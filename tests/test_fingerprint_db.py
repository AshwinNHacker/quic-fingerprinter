import json

from quicfp.fingerprint import compute_fingerprint
from quicfp.fingerprint_db import FingerprintStore, heuristic_guess
from quicfp.tls_clienthello import ClientHello


def _make_ch(**overrides):
    base = dict(
        legacy_version=0x0303,
        cipher_suites=[0x1301, 0x1302],
        extension_order=[0, 16, 43, 51, 57, 65037],
        extensions={e: b"" for e in [0, 16, 43, 51, 57, 65037]},
        alpn=["h3"],
        sni="example.com",
        supported_versions=[0x0304],
        quic_transport_parameters=b"\x01\x02",
        is_grease_present=True,
    )
    base.update(overrides)
    return ClientHello(**base)


def test_learn_and_lookup_round_trip(tmp_path):
    db_path = tmp_path / "fp.json"
    store = FingerprintStore(path=db_path)

    ch = _make_ch()
    fp = compute_fingerprint(ch)
    store.learn(fp, "Test Client 1.0")
    store.save()

    assert db_path.exists()
    reloaded = FingerprintStore.load(db_path)
    match = reloaded.lookup(fp)
    assert match is not None
    assert match.label == "Test Client 1.0"
    assert match.confidence == "exact"


def test_lookup_miss_returns_none(tmp_path):
    store = FingerprintStore(path=tmp_path / "empty.json")
    ch = _make_ch()
    fp = compute_fingerprint(ch)
    assert store.lookup(fp) is None


def test_store_persists_valid_json(tmp_path):
    db_path = tmp_path / "fp.json"
    store = FingerprintStore(path=db_path)
    ch = _make_ch()
    store.learn(compute_fingerprint(ch), "X")
    store.save()
    data = json.loads(db_path.read_text())
    assert isinstance(data, dict)
    assert "X" in data.values()


def test_load_missing_file_returns_empty_store(tmp_path):
    store = FingerprintStore.load(tmp_path / "does_not_exist.json")
    assert store.entries == {}


def test_heuristic_guess_missing_qtp_flagged():
    ch = _make_ch(extension_order=[0, 16], extensions={0: b"", 16: b""}, quic_transport_parameters=None)
    result = heuristic_guess(ch)
    assert result.confidence == "heuristic"
    assert "quic_transport_parameters" in result.detail


def test_heuristic_guess_chromium_like():
    ch = _make_ch(
        extension_order=[0, 16, 51, 57, 65037],
        extensions={e: b"" for e in [0, 16, 51, 57, 65037]},
        alpn=["h3"],
        is_grease_present=True,
    )
    result = heuristic_guess(ch)
    assert "Chromium" in result.label
    assert result.confidence == "heuristic"


def test_heuristic_guess_doq():
    ch = _make_ch(alpn=["doq"])
    result = heuristic_guess(ch)
    assert "DNS-over-QUIC" in result.label


def test_heuristic_guess_no_grease_firefox_like():
    ch = _make_ch(alpn=["h3"], is_grease_present=False)
    result = heuristic_guess(ch)
    assert "Firefox" in result.label or "unknown" in result.label
