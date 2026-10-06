"""
Packet capture sources: offline pcap/pcapng files and live interfaces.

Offline reading uses :mod:`dpkt` for speed on large files. Live capture
uses :mod:`scapy`, which is more portable across platforms for
grabbing raw sockets/npcap. Both paths funnel into the same
:class:`quicfp.flow.FlowTable`.

QUIC almost always rides on UDP/443, but this module doesn't hardcode
that -- it inspects every UDP datagram and lets the QUIC header parser
itself decide whether the payload looks like QUIC (a QUIC long header
starts with the fixed bit pattern ``1x1x xxxx`` and a recognizable/
plausible version field; short headers are only attributed to a flow
that a prior long header already established as QUIC, to avoid
misclassifying arbitrary UDP traffic).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from quicfp.flow import FlowTable


@dataclass
class RawUdpPacket:
    timestamp: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    payload: bytes


def iter_udp_packets_pcap(path: str) -> Iterator[RawUdpPacket]:
    """Yield every UDP datagram found in a pcap/pcapng file."""
    import dpkt

    with open(path, "rb") as fh:
        try:
            reader = dpkt.pcapng.Reader(fh)
        except (ValueError, dpkt.dpkt.NeedData):
            fh.seek(0)
            reader = dpkt.pcap.Reader(fh)

        for timestamp, buf in reader:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
            except Exception:
                try:
                    ip = dpkt.ip.IP(buf)
                except Exception:
                    continue

            if isinstance(ip, dpkt.ip6.IP6):
                proto_is_udp = isinstance(ip.data, dpkt.udp.UDP)
            elif isinstance(ip, dpkt.ip.IP):
                proto_is_udp = isinstance(ip.data, dpkt.udp.UDP)
            else:
                continue

            if not proto_is_udp:
                continue

            udp = ip.data
            try:
                src_ip = str(ipaddress.ip_address(ip.src))
                dst_ip = str(ipaddress.ip_address(ip.dst))
            except ValueError:
                continue

            yield RawUdpPacket(
                timestamp=float(timestamp),
                src_ip=src_ip,
                src_port=udp.sport,
                dst_ip=dst_ip,
                dst_port=udp.dport,
                payload=bytes(udp.data),
            )


def analyze_pcap(
    path: str,
    client_ports: set[int] | None = None,
    progress_cb: Callable[[int], None] | None = None,
) -> FlowTable:
    """Read a pcap file and build a FlowTable from every UDP datagram
    found. ``client_ports`` lets you hint which side is the client
    (e.g. {443} means "port 443 is the server") -- if omitted, the
    lower port number is heuristically treated as the server.
    """
    table = FlowTable()
    count = 0
    for pkt in iter_udp_packets_pcap(path):
        direction = _guess_direction(pkt, client_ports)
        five_tuple = _canonical_five_tuple(pkt)
        table.ingest(five_tuple, pkt.payload, pkt.timestamp, direction_hint=direction)
        count += 1
        if progress_cb and count % 500 == 0:
            progress_cb(count)
    if progress_cb:
        progress_cb(count)
    return table


def _guess_direction(pkt: RawUdpPacket, client_ports: set[int] | None) -> str:
    if client_ports:
        if pkt.dst_port in client_ports:
            return "s2c"
        if pkt.src_port in client_ports:
            return "c2s"
    # Heuristic: QUIC servers overwhelmingly listen on 443; whichever
    # side is NOT 443 is treated as the client.
    if pkt.dst_port == 443:
        return "c2s"
    if pkt.src_port == 443:
        return "s2c"
    # Fallback: lower port number is usually the well-known server port.
    return "c2s" if pkt.dst_port < pkt.src_port else "s2c"


def _canonical_five_tuple(pkt: RawUdpPacket) -> tuple:
    """A direction-independent flow key so both directions of a
    connection land in the same QuicFlow.
    """
    a = (pkt.src_ip, pkt.src_port)
    b = (pkt.dst_ip, pkt.dst_port)
    return tuple(sorted([a, b]))


def live_capture(
    interface: str,
    bpf_filter: str = "udp",
    packet_limit: int = 0,
    duration_s: float | None = None,
) -> FlowTable:
    """Capture live traffic using scapy and build a FlowTable.

    Requires appropriate OS privileges (root/CAP_NET_RAW on Linux, or
    running as Administrator with Npcap on Windows).
    """
    from scapy.all import IP, UDP, IPv6, sniff

    table = FlowTable()

    def _handle(scapy_pkt):
        if UDP not in scapy_pkt:
            return
        if IP in scapy_pkt:
            src_ip, dst_ip = scapy_pkt[IP].src, scapy_pkt[IP].dst
        elif IPv6 in scapy_pkt:
            src_ip, dst_ip = scapy_pkt[IPv6].src, scapy_pkt[IPv6].dst
        else:
            return

        udp = scapy_pkt[UDP]
        payload = bytes(udp.payload)
        if not payload:
            return

        raw = RawUdpPacket(
            timestamp=float(scapy_pkt.time),
            src_ip=src_ip,
            src_port=udp.sport,
            dst_ip=dst_ip,
            dst_port=udp.dport,
            payload=payload,
        )
        direction = _guess_direction(raw, None)
        five_tuple = _canonical_five_tuple(raw)
        table.ingest(five_tuple, raw.payload, raw.timestamp, direction_hint=direction)

    sniff(
        iface=interface,
        filter=bpf_filter,
        prn=_handle,
        count=packet_limit or 0,
        timeout=duration_s,
        store=False,
    )
    return table
