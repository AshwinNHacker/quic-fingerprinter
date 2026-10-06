from quicfp.fingerprint import compute_fingerprint
from quicfp.tls_clienthello import ClientHello


def _make_ch(cipher_suites, extension_order, alpn=None, sni="example.com", grease=False):
    return ClientHello(
        legacy_version=0x0303,
        cipher_suites=cipher_suites,
        extension_order=extension_order,
        extensions={e: b"" for e in extension_order},
        alpn=alpn or ["h3"],
        sni=sni,
        supported_versions=[0x0304],
        quic_transport_parameters=b"\x01\x02",
        is_grease_present=grease,
    )


def test_fingerprint_deterministic():
    ch = _make_ch([0x1301, 0x1302], [0, 16, 43, 57])
    fp1 = compute_fingerprint(ch)
    fp2 = compute_fingerprint(ch)
    assert fp1.sorted_fingerprint == fp2.sorted_fingerprint
    assert fp1.raw_order_fingerprint == fp2.raw_order_fingerprint


def test_raw_order_fingerprint_sensitive_to_extension_order():
    ch_a = _make_ch([0x1301, 0x1302], [0, 16, 43, 57])
    ch_b = _make_ch([0x1301, 0x1302], [57, 43, 16, 0])
    fp_a = compute_fingerprint(ch_a)
    fp_b = compute_fingerprint(ch_b)
    assert fp_a.raw_order_fingerprint != fp_b.raw_order_fingerprint


def test_sorted_fingerprint_stable_across_extension_order():
    ch_a = _make_ch([0x1301, 0x1302], [0, 16, 43, 57])
    ch_b = _make_ch([0x1301, 0x1302], [57, 43, 16, 0])
    fp_a = compute_fingerprint(ch_a)
    fp_b = compute_fingerprint(ch_b)
    assert fp_a.sorted_fingerprint == fp_b.sorted_fingerprint


def test_different_cipher_suites_change_fingerprint():
    ch_a = _make_ch([0x1301], [0, 16])
    ch_b = _make_ch([0x1301, 0x1302, 0x1303], [0, 16])
    assert compute_fingerprint(ch_a).sorted_fingerprint != compute_fingerprint(ch_b).sorted_fingerprint


def test_v1_v2_produce_different_fingerprints_for_identical_hello():
    ch = _make_ch([0x1301, 0x1302], [0, 16, 43, 57])
    fp_v1 = compute_fingerprint(ch, quic_version_is_v2=False)
    fp_v2 = compute_fingerprint(ch, quic_version_is_v2=True)
    assert fp_v1.sorted_fingerprint != fp_v2.sorted_fingerprint
    assert fp_v1.protocol == "quic"
    assert fp_v2.protocol == "quicv2"


def test_short_tag_format():
    ch = _make_ch([0x1301, 0x1302], [0, 16, 43, 57], alpn=["h3"])
    fp = compute_fingerprint(ch)
    tag = fp.short()
    assert tag.startswith("q13")
    assert "h3" in tag
