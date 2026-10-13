import tempfile
from pathlib import Path
from netsentry.config import Config
from netsentry.core.detector import ThreatDetector
from netsentry.core.threat_intel import ThreatIntel


def test_detector_clean_traffic():
    with tempfile.TemporaryDirectory() as tmpdir:
        intel = ThreatIntel(cache_file=Path(tmpdir) / "intel.json")
        cfg = Config()
        detector = ThreatDetector(cfg, intel)

        # Standard benign traffic
        threat = detector.analyze_connection(
            remote_ip="142.250.180.206",  # Google
            remote_port=443,
            process_name="firefox",
            pid=5000,
            exe_path="/usr/bin/firefox",
        )
        assert threat is None


def test_detector_reverse_shell():
    with tempfile.TemporaryDirectory() as tmpdir:
        intel = ThreatIntel(cache_file=Path(tmpdir) / "intel.json")
        cfg = Config()
        detector = ThreatDetector(cfg, intel)

        # Bash socket connected to remote port 4444
        threat = detector.analyze_connection(
            remote_ip="203.0.113.5",
            remote_port=4444,
            process_name="bash",
            pid=8888,
            exe_path="/usr/bin/bash",
        )
        assert threat is not None
        assert threat.severity in ("HIGH", "CRITICAL")
        assert "REVERSE_SHELL" in threat.rule_name or "SUSPICIOUS_PORT" in threat.rule_name


def test_detector_malicious_ip():
    with tempfile.TemporaryDirectory() as tmpdir:
        intel = ThreatIntel(cache_file=Path(tmpdir) / "intel.json")
        cfg = Config()
        detector = ThreatDetector(cfg, intel)

        # Pre-seeded test malicious IP
        threat = detector.analyze_connection(
            remote_ip="198.51.100.66",
            remote_port=80,
            process_name="curl",
            pid=9999,
            exe_path="/usr/bin/curl",
        )
        assert threat is not None
        assert threat.severity in ("HIGH", "CRITICAL")
        assert threat.rule_name == "THREAT_INTEL_MATCH"


def test_detector_untrusted_tmp_binary():
    with tempfile.TemporaryDirectory() as tmpdir:
        intel = ThreatIntel(cache_file=Path(tmpdir) / "intel.json")
        cfg = Config()
        detector = ThreatDetector(cfg, intel)

        # Binary executed out of /tmp
        threat = detector.analyze_connection(
            remote_ip="93.184.216.34",
            remote_port=8080,
            process_name="xmrig_miner",
            pid=4444,
            exe_path="/tmp/xmrig_miner",
        )
        assert threat is not None
        assert threat.severity in ("HIGH", "CRITICAL")
        assert threat.rule_name == "UNTRUSTED_BINARY_PATH"
