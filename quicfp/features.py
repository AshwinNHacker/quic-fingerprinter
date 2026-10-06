"""
Statistical flow-level features for QUIC traffic.

Once a connection moves past its Initial/Handshake packets into 1-RTT
(short-header) packets, everything is genuinely, strongly encrypted --
there is no equivalent of the Initial salt trick for these packets,
and there shouldn't be (this is QUIC's real security boundary working
as intended). Most of a QUIC connection's *lifetime*, and therefore
most of the bytes an observer sees, falls into this bucket.

This is the actual "blind spot" the project is named for. The
mitigation used here is the same one traffic-analysis research has
applied to encrypted TCP/TLS and to Tor for years: side-channel
statistics of packet sizes, timing, and direction survive encryption
because encryption (by design) does not hide *when* or *how big* a
packet is, only its content. These features feed
:mod:`quicfp.ml.classifier` for coarse application/client-family
classification when no ClientHello is observable -- e.g. for 0-RTT
resumed connections, mid-stream capture starts, or connections using
Encrypted Client Hello (ECH) where even the SNI is hidden.

This is explicitly probabilistic, coarse-grained triage -- not packet
content recovery.
"""

from __future__ import annotations

import math
import statistics as stats
from dataclasses import dataclass

from quicfp.flow import QuicFlow


@dataclass
class FlowFeatures:
    packet_count: int
    duration_s: float
    bytes_total: int
    bytes_c2s: int
    bytes_s2c: int
    mean_packet_size: float
    stdev_packet_size: float
    min_packet_size: int
    max_packet_size: int
    mean_iat_s: float  # inter-arrival time
    stdev_iat_s: float
    c2s_s2c_ratio: float
    long_header_fraction: float
    packets_per_second: float
    size_entropy_bits: float  # Shannon entropy over a coarse size histogram

    def as_vector(self) -> list[float]:
        """Fixed-order numeric vector for feeding a scikit-learn model."""
        return [
            self.packet_count,
            self.duration_s,
            self.bytes_total,
            self.bytes_c2s,
            self.bytes_s2c,
            self.mean_packet_size,
            self.stdev_packet_size,
            self.min_packet_size,
            self.max_packet_size,
            self.mean_iat_s,
            self.stdev_iat_s,
            self.c2s_s2c_ratio,
            self.long_header_fraction,
            self.packets_per_second,
            self.size_entropy_bits,
        ]

    @staticmethod
    def feature_names() -> list[str]:
        return [
            "packet_count",
            "duration_s",
            "bytes_total",
            "bytes_c2s",
            "bytes_s2c",
            "mean_packet_size",
            "stdev_packet_size",
            "min_packet_size",
            "max_packet_size",
            "mean_iat_s",
            "stdev_iat_s",
            "c2s_s2c_ratio",
            "long_header_fraction",
            "packets_per_second",
            "size_entropy_bits",
        ]


def _shannon_entropy_bits(sizes: list[int], bucket_width: int = 32) -> float:
    if not sizes:
        return 0.0
    buckets: dict[int, int] = {}
    for s in sizes:
        b = s // bucket_width
        buckets[b] = buckets.get(b, 0) + 1
    total = len(sizes)
    entropy = 0.0
    for count in buckets.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def extract_features(flow: QuicFlow) -> FlowFeatures | None:
    if flow.packet_count < 2:
        return None

    sizes = [p.size for p in flow.packets]
    timestamps = sorted(p.timestamp for p in flow.packets)
    c2s_bytes = sum(p.size for p in flow.packets if p.direction == "c2s")
    s2c_bytes = sum(p.size for p in flow.packets if p.direction == "s2c")
    long_header_count = sum(1 for p in flow.packets if p.is_long_header)

    iats = [t2 - t1 for t1, t2 in zip(timestamps, timestamps[1:], strict=False) if t2 >= t1]

    duration = max(flow.duration, 1e-6)

    return FlowFeatures(
        packet_count=flow.packet_count,
        duration_s=flow.duration,
        bytes_total=sum(sizes),
        bytes_c2s=c2s_bytes,
        bytes_s2c=s2c_bytes,
        mean_packet_size=stats.fmean(sizes),
        stdev_packet_size=stats.pstdev(sizes) if len(sizes) > 1 else 0.0,
        min_packet_size=min(sizes),
        max_packet_size=max(sizes),
        mean_iat_s=stats.fmean(iats) if iats else 0.0,
        stdev_iat_s=stats.pstdev(iats) if len(iats) > 1 else 0.0,
        c2s_s2c_ratio=(c2s_bytes + 1) / (s2c_bytes + 1),
        long_header_fraction=long_header_count / flow.packet_count,
        packets_per_second=flow.packet_count / duration,
        size_entropy_bits=_shannon_entropy_bits(sizes),
    )
