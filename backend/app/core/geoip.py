"""
Fast GeoIP & ASN Resolution and Country-Level Geo-Fencing Engine.

Provides IP geolocation enrichment and policy-based country blocking
to suppress automated foreign botnets and scanning campaigns before exploit evaluation.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import urllib.request

logger = logging.getLogger("ids.geoip")

# In-memory LRU-like cache: ip -> dict
_geoip_cache: dict[str, dict[str, str]] = {}
MAX_CACHE_SIZE = 10000


def get_ip_geoinfo(ip_str: str) -> dict[str, str]:
    """Resolves IP to country code, country name, and ASN with caching."""
    if not ip_str or ip_str in ("127.0.0.1", "::1", "localhost"):
        return {"country_code": "LOCAL", "country_name": "Localhost / Loopback", "asn": "AS0 Internal"}

    if ip_str in _geoip_cache:
        return _geoip_cache[ip_str]

    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
            res = {"country_code": "LOCAL", "country_name": "Private Network", "asn": "AS0 RFC1918"}
            _geoip_cache[ip_str] = res
            return res
    except ValueError:
        return {"country_code": "UNKNOWN", "country_name": "Unknown", "asn": "AS0"}

    # Online fast lookup with 1-second timeout
    try:
        url = f"http://ip-api.com/json/{ip_str}?fields=status,country,countryCode,as,org"
        req = urllib.request.Request(url, headers={"User-Agent": "ApexSentinel-GeoIP/1.0"})
        with urllib.request.urlopen(req, timeout=1.2) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("status") == "success":
                    info = {
                        "country_code": data.get("countryCode", "UNKNOWN").upper(),
                        "country_name": data.get("country", "Unknown"),
                        "asn": data.get("as", data.get("org", "AS0")),
                    }
                    if len(_geoip_cache) > MAX_CACHE_SIZE:
                        _geoip_cache.clear()
                    _geoip_cache[ip_str] = info
                    return info
    except Exception as exc:
        logger.debug("GeoIP lookup notice for %s: %s", ip_str, exc)

    fallback = {"country_code": "UNKNOWN", "country_name": "Unknown", "asn": "AS0"}
    _geoip_cache[ip_str] = fallback
    return fallback


def check_country_geofence(ip_str: str) -> tuple[bool, str]:
    """Evaluates whether an IP address is blocked by country-level geo-fencing policies.

    Controlled by:
      - IPS_BLOCKED_COUNTRIES: comma-separated list of country ISO codes (e.g. 'RU,CN,KP,IR')
      - IPS_ALLOWED_COUNTRIES: optional strict allowlist of country ISO codes (e.g. 'US,CA,GB,IN')
    """
    blocked_env = os.getenv("IPS_BLOCKED_COUNTRIES", "").strip()
    allowed_env = os.getenv("IPS_ALLOWED_COUNTRIES", "").strip()

    if not blocked_env and not allowed_env:
        return False, ""

    geo = get_ip_geoinfo(ip_str)
    country = geo.get("country_code", "UNKNOWN")

    # Local infrastructure is never geo-blocked
    if country in ("LOCAL", "UNKNOWN"):
        return False, ""

    # 1. Deny list policy
    if blocked_env:
        blocked_set = {c.strip().upper() for c in blocked_env.split(",") if c.strip()}
        if country in blocked_set:
            return True, country

    # 2. Strict allow list policy
    if allowed_env:
        allowed_set = {c.strip().upper() for c in allowed_env.split(",") if c.strip()}
        if country not in allowed_set:
            return True, country

    return False, ""
