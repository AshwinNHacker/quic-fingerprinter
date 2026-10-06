from quicfp.features import extract_features
from quicfp.flow import QuicFlow


def _flow_with_packets(sizes_and_times, direction="c2s", is_long=True):
    flow = QuicFlow(flow_key=(("1.2.3.4", 1234), ("5.6.7.8", 443)))
    for size, t in sizes_and_times:
        flow.add_packet(timestamp=t, size=size, direction=direction, kind="short_header_1rtt", is_long=is_long)
    return flow


def test_extract_features_returns_none_for_single_packet_flow():
    flow = _flow_with_packets([(100, 0.0)])
    assert extract_features(flow) is None


def test_extract_features_basic_stats():
    packets = [(1200, 0.0), (1200, 0.1), (60, 0.2), (1200, 0.3)]
    flow = _flow_with_packets(packets)
    feats = extract_features(flow)

    assert feats.packet_count == 4
    assert feats.bytes_total == 1200 + 1200 + 60 + 1200
    assert feats.min_packet_size == 60
    assert feats.max_packet_size == 1200
    assert feats.duration_s > 0
    assert feats.mean_packet_size == (1200 + 1200 + 60 + 1200) / 4


def test_extract_features_direction_split():
    flow = QuicFlow(flow_key=(("a", 1), ("b", 2)))
    flow.add_packet(0.0, 1000, "c2s", "initial", True)
    flow.add_packet(0.1, 500, "s2c", "initial", True)
    flow.add_packet(0.2, 1000, "c2s", "short_header_1rtt", False)
    feats = extract_features(flow)
    assert feats.bytes_c2s == 2000
    assert feats.bytes_s2c == 500
    assert feats.long_header_fraction == 2 / 3


def test_feature_vector_matches_names_length():
    flow = _flow_with_packets([(100, 0.0), (200, 0.1), (150, 0.2)])
    feats = extract_features(flow)
    assert len(feats.as_vector()) == len(feats.feature_names())


def test_entropy_zero_for_uniform_sizes():
    flow = _flow_with_packets([(1200, 0.0), (1200, 0.1), (1200, 0.2)])
    feats = extract_features(flow)
    assert feats.size_entropy_bits == 0.0


def test_entropy_positive_for_varied_sizes():
    flow = _flow_with_packets([(60, 0.0), (600, 0.1), (1200, 0.2), (1400, 0.3)])
    feats = extract_features(flow)
    assert feats.size_entropy_bits > 0.0
