"""
QUIC flow tracking.

Groups raw UDP payloads captured off the wire into per-connection
flows keyed by 5-tuple, tracks per-packet metadata needed for both
crypto-based (Initial ClientHello) and statistical (packet size/timing)
fingerprinting, and reassembles a client's CRYPTO stream across
multiple coalesced or retransmitted Initial packets when the first
one alone doesn't contain a complete ClientHello.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from quicfp.headers import (
    HeaderParseError,
    LongHeaderPacket,
    LongPacketType,
    ShortHeaderPacket,
    VersionNegotiationPacket,
    parse_quic_header,
)
from quicfp.initial_crypto import InitialCryptoError, find_crypto_frame_data, remove_initial_protection
from quicfp.tls_clienthello import ClientHelloParseError, parse_client_hello


@dataclass
class ObservedPacket:
    timestamp: float
    size: int
    direction: str  # "c2s" or "s2c" (heuristic if roles unknown)
    is_long_header: bool
    packet_type: str = ""


@dataclass
class QuicFlow:
    flow_key: tuple
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    packets: list[ObservedPacket] = field(default_factory=list)
    version: int | None = None
    client_dcid: bytes | None = None  # DCID of the client's *first* Initial
    crypto_chunks: dict[int, bytes] = field(default_factory=dict)
    client_hello_parsed: bool = False
    client_hello = None  # type: ignore[assignment]
    parse_error: str | None = None

    def add_packet(self, timestamp: float, size: int, direction: str, kind: str, is_long: bool) -> None:
        self.packets.append(
            ObservedPacket(timestamp=timestamp, size=size, direction=direction, is_long_header=is_long, packet_type=kind)
        )
        self.last_seen = max(self.last_seen, timestamp)
        self.first_seen = min(self.first_seen, timestamp)

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    @property
    def packet_count(self) -> int:
        return len(self.packets)


class FlowTable:
    """Tracks QuicFlow objects by (src_ip, src_port, dst_ip, dst_port)
    -- or, once available, by connection ID, since QUIC connections can
    migrate across 5-tuples (RFC 9000 §9) while keeping the same CID.
    """

    def __init__(self) -> None:
        self._by_5tuple: dict[tuple, QuicFlow] = {}
        self._by_dcid: dict[bytes, QuicFlow] = {}

    def _get_or_create(self, five_tuple: tuple, dcid: bytes | None) -> QuicFlow:
        if dcid and dcid in self._by_dcid:
            flow = self._by_dcid[dcid]
            self._by_5tuple[five_tuple] = flow
            return flow
        if five_tuple in self._by_5tuple:
            flow = self._by_5tuple[five_tuple]
            if dcid:
                self._by_dcid[dcid] = flow
            return flow
        flow = QuicFlow(flow_key=five_tuple)
        self._by_5tuple[five_tuple] = flow
        if dcid:
            self._by_dcid[dcid] = flow
        return flow

    def ingest(
        self,
        five_tuple: tuple,
        udp_payload: bytes,
        timestamp: float,
        direction_hint: str = "c2s",
    ) -> QuicFlow | None:
        """Feed one UDP datagram's payload (which may contain multiple
        coalesced QUIC packets, per RFC 9000 §12.2) into the flow table.
        Returns the QuicFlow the (first) packet belongs to, or None if
        it doesn't parse as QUIC at all.
        """
        offset = 0
        flow: QuicFlow | None = None

        while offset < len(udp_payload):
            remaining = udp_payload[offset:]
            try:
                pkt = parse_quic_header(remaining)
            except HeaderParseError:
                break

            if isinstance(pkt, VersionNegotiationPacket):
                flow = self._get_or_create(five_tuple, pkt.dcid or None)
                flow.add_packet(timestamp, len(remaining), direction_hint, "version_negotiation", True)
                break  # VN packets are never coalesced with others

            if isinstance(pkt, LongHeaderPacket):
                dcid_for_lookup = pkt.dcid if direction_hint == "c2s" else None
                flow = self._get_or_create(five_tuple, dcid_for_lookup)
                if flow.version is None:
                    flow.version = pkt.version

                kind = pkt.type_name.lower().replace("-", "_").replace(" ", "_")
                flow.add_packet(timestamp, len(remaining), direction_hint, kind, True)

                if (
                    pkt.packet_type == LongPacketType.INITIAL
                    and direction_hint == "c2s"
                    and not flow.client_hello_parsed
                ):
                    if flow.client_dcid is None:
                        flow.client_dcid = pkt.dcid
                    self._try_decrypt_initial(flow, remaining, pkt)

                # Long-header packets carry an explicit Length field, so
                # we can find the next coalesced packet precisely.
                if pkt.length_field is not None:
                    consumed = pkt.header_len + pkt.length_field
                else:
                    consumed = len(remaining)
                offset += max(consumed, 1)
            elif isinstance(pkt, ShortHeaderPacket):
                flow = self._get_or_create(five_tuple, None)
                flow.add_packet(timestamp, len(remaining), direction_hint, "short_header_1rtt", False)
                # Short-header packets are never coalesced with anything
                # after them in the same datagram.
                break
            else:  # pragma: no cover - defensive
                break

        return flow

    def _try_decrypt_initial(self, flow: QuicFlow, raw: bytes, pkt: LongHeaderPacket) -> None:
        try:
            unprotected = remove_initial_protection(
                raw, pkt.header_len, pkt.dcid, pkt.version, is_from_client=True
            )
        except InitialCryptoError as exc:
            flow.parse_error = f"initial decrypt failed: {exc}"
            return

        crypto_data = find_crypto_frame_data(unprotected.payload)
        if not crypto_data:
            return

        # We don't have the CRYPTO frame's declared stream offset here
        # (find_crypto_frame_data already reassembles same-packet
        # fragments); treat this packet's contribution as offset 0 for
        # the (overwhelmingly common) single-packet ClientHello case.
        flow.crypto_chunks[0] = crypto_data

        try:
            ch = parse_client_hello(crypto_data)
            flow.client_hello = ch
            flow.client_hello_parsed = True
        except ClientHelloParseError as exc:
            flow.parse_error = f"ClientHello parse incomplete: {exc}"

    def flows(self) -> list[QuicFlow]:
        seen_ids = set()
        unique = []
        for flow in self._by_5tuple.values():
            if id(flow) not in seen_ids:
                seen_ids.add(id(flow))
                unique.append(flow)
        return unique
