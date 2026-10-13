"""Tests for IP resolver and caching engine."""

from pathlib import Path
from netsentry.core.database import Database
from netsentry.core.resolver import IPResolver, IPInfo


def test_resolver_private_ips(tmp_path: Path):
    db = Database(tmp_path / "test.db")
    resolver = IPResolver(db=db)

    info_local = resolver.resolve("127.0.0.1", fetch_geo=False)
    assert info_local.is_private is True
    assert info_local.badge == "[LAN]"

    info_lan = resolver.resolve("192.168.1.10", fetch_geo=False)
    assert info_lan.is_private is True
    assert info_lan.badge == "[LAN]"


def test_resolver_db_cache(tmp_path: Path):
    db = Database(tmp_path / "test.db")
    db.cache_ip_info(
        ip="8.8.8.8",
        hostname="dns.google",
        country_code="US",
        country_name="United States",
        city="Mountain View",
        org="Google LLC",
    )

    resolver = IPResolver(db=db)
    # Should resolve straight from database cache without network call
    info = resolver.resolve("8.8.8.8", fetch_geo=False)
    assert info.hostname == "dns.google"
    assert info.country_code == "US"
    assert info.city == "Mountain View"
