"""Reverse DNS and GeoIP resolution engine with local caching."""

from __future__ import annotations

import ipaddress
import logging
import socket
from dataclasses import dataclass
from typing import Dict, Optional

import requests

logger = logging.getLogger(__name__)


@dataclass
class IPInfo:
    ip: str
    hostname: Optional[str] = None
    country_code: Optional[str] = None
    country_name: Optional[str] = None
    city: Optional[str] = None
    org: Optional[str] = None
    asn: Optional[str] = None
    is_private: bool = False

    @property
    def badge(self) -> str:
        """Return a short badge like '[PL]' or '[LAN]'."""
        if self.is_private:
            return "[LAN]"
        return f"[{self.country_code}]" if self.country_code else ""

    def summary(self) -> str:
        """Formatted string summary of the IP."""
        parts = [self.ip]
        if self.country_code:
            parts.append(f"[{self.country_code}]")
        if self.hostname and self.hostname != self.ip:
            parts.append(f"({self.hostname})")
        return " ".join(parts)


class IPResolver:
    """Thread-safe IP address metadata resolver with in-memory & SQLite cache."""

    def __init__(self, db=None, timeout: float = 2.0):
        self.db = db
        self.timeout = timeout
        self._cache: Dict[str, IPInfo] = {}

    def _is_private(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private or addr.is_loopback or addr.is_unspecified or addr.is_link_local
        except ValueError:
            return False

    def resolve(self, ip: str, fetch_geo: bool = True) -> IPInfo:
        """Resolve reverse DNS and GeoIP info for a given IP."""
        if not ip:
            return IPInfo(ip="")

        # 1. Check in-memory cache
        if ip in self._cache:
            return self._cache[ip]

        # 2. Check if private or local
        if self._is_private(ip):
            info = IPInfo(
                ip=ip,
                hostname="localhost" if ip in ("127.0.0.1", "::1") else "local-network",
                country_code="LAN",
                country_name="Local Network",
                city="Local",
                org="Private Network",
                is_private=True,
            )
            self._cache[ip] = info
            return info

        # 3. Check SQLite database cache if DB is attached
        if self.db:
            cached = self.db.get_cached_ip_info(ip)
            if cached:
                info = IPInfo(
                    ip=ip,
                    hostname=cached.get("hostname"),
                    country_code=cached.get("country_code"),
                    country_name=cached.get("country_name"),
                    city=cached.get("city"),
                    org=cached.get("org"),
                    asn=cached.get("asn"),
                    is_private=False,
                )
                self._cache[ip] = info
                return info

        # 4. Perform Reverse DNS
        hostname = None
        try:
            prev_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(1.0)
            try:
                host, _, _ = socket.gethostbyaddr(ip)
                hostname = host
            finally:
                socket.setdefaulttimeout(prev_timeout)
        except Exception:
            hostname = None

        country_code = None
        country_name = None
        city = None
        org = None
        asn = None

        # 5. Perform GeoIP lookup if enabled
        if fetch_geo:
            try:
                url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,isp,org,as"
                resp = requests.get(
                    url,
                    timeout=self.timeout,
                    headers={"User-Agent": "NetSentry-Monitor/0.1.0"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") == "success":
                        country_code = data.get("countryCode")
                        country_name = data.get("country")
                        city = data.get("city")
                        org = data.get("org") or data.get("isp")
                        asn = data.get("as")
            except Exception as e:
                logger.debug("GeoIP query error for %s: %s", ip, e)

        info = IPInfo(
            ip=ip,
            hostname=hostname,
            country_code=country_code,
            country_name=country_name,
            city=city,
            org=org,
            asn=asn,
            is_private=False,
        )

        # Store in memory cache
        self._cache[ip] = info

        # Store in SQLite cache if DB attached
        if self.db:
            try:
                self.db.cache_ip_info(
                    ip=ip,
                    hostname=hostname,
                    country_code=country_code,
                    country_name=country_name,
                    city=city,
                    org=org,
                    asn=asn,
                )
            except Exception as e:
                logger.debug("Failed to write to DB IP cache: %s", e)

        return info

    def get_display_name(self, ip: str) -> str:
        """Short formatted representation of IP with country or hostname."""
        info = self.resolve(ip, fetch_geo=False)
        return info.summary()
