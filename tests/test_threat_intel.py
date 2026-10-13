import tempfile
from pathlib import Path
from netsentry.core.threat_intel import ThreatIntel


def test_threat_intel_seed():
    with tempfile.TemporaryDirectory() as tmpdir:
        cache_file = Path(tmpdir) / "intel.json"
        intel = ThreatIntel(cache_file=cache_file)

        # Check local/private address returns None
        assert intel.check_ip("127.0.0.1") is None
        assert intel.check_ip("192.168.1.100") is None
        assert intel.check_ip("10.0.0.1") is None

        # Check pre-seeded test malicious IP
        res = intel.check_ip("198.51.100.66")
        assert res is not None
        assert res["confidence"] == 100

        # Add custom bad IP
        intel.add_bad_ip("198.51.100.99", category="Test Threat")
        res2 = intel.check_ip("198.51.100.99")
        assert res2 is not None
        assert res2["category"] == "Test Threat"
