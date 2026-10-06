import json
import subprocess
import sys
from pathlib import Path

PCAP_PATH = Path(__file__).parent / "data" / "rfc9369_client_initial.pcap"


def _run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "quicfp.cli", *args],
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).parent.parent),
    )


def test_cli_version():
    result = _run_cli("--version")
    assert result.returncode == 0
    assert "quicfp" in result.stdout


def test_cli_analyze_json_output():
    result = _run_cli("analyze", str(PCAP_PATH), "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["quic_flows"] == 1
    flow = data["flows"][0]
    assert flow["client_hello"]["sni"] == "example.com"


def test_cli_analyze_human_output():
    result = _run_cli("analyze", str(PCAP_PATH))
    assert result.returncode == 0
    assert "example.com" in result.stdout
    assert "fingerprint" in result.stdout.lower()


def test_cli_learn_creates_db(tmp_path):
    db_path = tmp_path / "learned.json"
    result = _run_cli("learn", str(PCAP_PATH), "--label", "Test Vector Client", "--db", str(db_path))
    assert result.returncode == 0
    assert db_path.exists()
    data = json.loads(db_path.read_text())
    assert "Test Vector Client" in data.values()


def test_cli_analyze_after_learn_shows_exact_match(tmp_path):
    db_path = tmp_path / "learned.json"
    _run_cli("learn", str(PCAP_PATH), "--label", "Test Vector Client", "--db", str(db_path))
    result = _run_cli("analyze", str(PCAP_PATH), "--db", str(db_path), "--json")
    data = json.loads(result.stdout)
    match = data["flows"][0]["client_match"]
    assert match["label"] == "Test Vector Client"
    assert match["confidence"] == "exact"


def test_cli_missing_pcap_fails_gracefully():
    result = _run_cli("analyze", "/nonexistent/path/does_not_exist.pcap")
    assert result.returncode != 0
