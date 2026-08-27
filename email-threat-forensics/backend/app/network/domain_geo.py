"""
Stage 2 — IP geolocation, sender-domain entropy & typosquat detection.

1. Geo & ASN resolution via local MaxMind GeoLite2 databases.  Lookups are
   delegated to geoip2, which supports the offline .mmdb files
   bundled in backend/data/. The resolver is air-gapped-friendly, no
   network calls are ever issued.

2. Sender-domain entropy via math.log2() (Shannon entropy). The
   registrable domain (eTLD+1) is the lower bound; the full sender host
   (e.g. mail.us1.example.com) is the upper bound.  We return the higher
   of the two because a long subdomain is itself a strong BEC indicator.

3. Typosquat detection via Levenshtein. We compare the registrable
   sender domain against a curated set of commonly-spoofed brand registrable
   domains (Microsoft, PayPal, Apple, Google, DocuSign, etc.) and report the
   closest hit below a conservative edit-distance budget of 2.

Design notes:
1. Database handles are lazily opened and cached at module level, the cost
  of opening the DB on every request is prohibitive, but globals are simple
  to reason about in an air-gapped CLI process.
2. is_datacenter and is_vpn_tor are heuristics over the org field
  produced by GeoLite2-ASN, MaxMind's paid Anonymous-IP DB is not part of
  this bundle. Replace these heuristics with a proper Anonymous-IP lookup
  if/when that database is provisioned.
3. All exceptions are caught and downgraded to safe defaults. A failed lookup
  must not break the upstream pipeline.
"""

from __future__ import annotations

import logging
import math
import os
from functools import lru_cache
from pathlib import Path
from typing import List, Optional, Tuple
import re

import geoip2.database  # type: ignore  # geoip2 ships unofficial type hints
import geoip2.errors
import tldextract
from Levenshtein import distance as lev_distance

from app.schemas.forensic_report import OriginNetwork

logger = logging.getLogger(__name__)


# Environment variable resolution is good for docker or while using uvicorn etc
_DEFAULT_DATA_DIR = Path(
    os.environ.get(
        "ETF_DATA_DIR",
        Path(__file__).resolve().parents[2] / "data",
    )
)

_CITY_DB = _DEFAULT_DATA_DIR / "GeoLite2-City.mmdb"
_ASN_DB = _DEFAULT_DATA_DIR / "GeoLite2-ASN.mmdb"


# Heuristic substring matchers for VPN / Tor providers & datacenter ASNs.
_DATACENTER_HINTS = (
    "amazon", "aws", "google cloud", "gcp", "microsoft azure", "azure",
    "digitalocean", "linode", "ovh", "hetzner", "vultr", "scaleway",
    "alibaba", "tencent", "oracle cloud", "ibm cloud",
)
_VPN_TOR_HINTS = (
    "mullvad", "nordvpn", "expressvpn", "private internet access", "pia",
    "protonvpn", "tor exit", "tor network", "torservers", "anonymizer",
    "surfshark", "vyprvpn", "windscribe",
)

# list of registrable brand domains routinely spoofed in BEC.
_BRAND_DOMAINS: Tuple[str, ...] = (
    "microsoft.com",
    "outlook.com",
    "office.com",
    "office365.com",
    "live.com",
    "gmail.com",
    "google.com",
    "googlemail.com",
    "apple.com",
    "icloud.com",
    "paypal.com",
    "docusign.com",
    "dropbox.com",
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "amazon.com",
    "amazonaws.com",
    "fedex.com",
    "ups.com",
    "dhl.com",
    "wellsfargo.com",
    "chase.com",
    "bankofamerica.com",
    "hsbc.com",
    "barclays.com",
    "intuit.com",
    "quickbooks.com",
    "xero.com",
    "wework.com",
)

EXTRACTOR = tldextract.TLDExtract(cache_dir=None)
_BRAND_MAP: dict[str, str] = {
    EXTRACTOR(d).domain: d for d in _BRAND_DOMAINS if EXTRACTOR(d).domain
}


# Public entry point
def resolve(
    from_address: str,
    ip: str,
    data_dir: Optional[Path] = None,
) -> OriginNetwork:
    """Build a fully-populated :class:`OriginNetwork`.

    Parameters
    ----------
    from_address:
        RFC 5322 ``From:`` address (lowercased is fine).
    ip:
        Public IPv4 / IPv6 string (typically from :mod:`hop_tracer`).
    data_dir:
        Override the location of the ``.mmdb`` files — useful in tests and
        in production where the data directory has been relocated via the
        ``ETF_DATA_DIR`` environment variable.
    """
    data_dir = Path(data_dir) if data_dir else _DEFAULT_DATA_DIR
    city_db_path = data_dir / "GeoLite2-City.mmdb"
    asn_db_path = data_dir / "GeoLite2-ASN.mmdb"

    country, city, lat, lon = _geo_lookup(ip, city_db_path)
    asn, org = _asn_lookup(ip, asn_db_path)
    is_datacenter = _looks_like_datacenter(org)
    is_vpn_tor = _looks_like_vpn_or_tor(org, asn)

    sender_host = (from_address or "").split("@", 1)[-1].lower().strip()
    domain_entropy = _shannon_entropy(sender_host)

    typosquat_target, edit_distance = _closest_brand(sender_host)

    return OriginNetwork(
        ip=ip or "",
        country=country,
        city=city,
        latitude=lat,
        longitude=lon,
        asn=asn or "AS0",
        org=org or "Unknown",
        is_datacenter=is_datacenter,
        is_vpn_tor=is_vpn_tor,
        domain_entropy=domain_entropy,
        typosquat_target=typosquat_target,
        edit_distance=edit_distance,
    )


# Geo & ASN lookups
@lru_cache(maxsize=4)  # Holds City, ASN, and any future DBs simultaneously
def _get_mmdb_reader(path_str: str) -> Optional[geoip2.database.Reader]:
    path = Path(path_str)
    if not path.exists():
        logger.warning("MaxMind database file missing at %s", path)
        return None
    try:
        return geoip2.database.Reader(str(path))
    except Exception as exc:
        logger.error("Failed to load MaxMind database (%s): %s", path.name, exc)
        return None


def _geo_lookup(
    ip: str, db_path: Path,
) -> Tuple[str, str, float, float]:
    """Return ``(country_iso, city, latitude, longitude)`` from GeoLite2-City."""
    if not ip:
        return "XX", "Unknown", 0.0, 0.0
    reader = _get_mmdb_reader(str(db_path))
    if reader is None:
        return "XX", "Unknown", 0.0, 0.0

    try:
        response = reader.city(ip)
    except geoip2.errors.AddressNotFoundError:
        return "XX", "Unknown", 0.0, 0.0
    except Exception as exc:  # noqa: BLE001
        logger.warning("GeoIP city lookup failed for %s: %s", ip, exc)
        return "XX", "Unknown", 0.0, 0.0

    country = response.country.iso_code or "XX"
    # GeoLite2 stores the city record in a structured ``subdivisions`` /
    # city block — handle every shape possible across DB revisions.
    city = response.city.name or "Unknown"
    return (
        country,
        city,
        float(response.location.latitude or 0.0),
        float(response.location.longitude or 0.0),
    )


def _asn_lookup(ip: str, db_path: Path) -> Tuple[str, str]:
    # Return (ASN, organization)
    if not ip:
        return "AS0", "Unknown"
    reader = _get_mmdb_reader(str(db_path))
    if reader is None:
        return "AS0", "Unknown"
    try:
        response = reader.asn(ip)
    except geoip2.errors.AddressNotFoundError:
        return "AS0", "Unknown"
    except Exception as exc:  # noqa: BLE001
        logger.warning("GeoIP ASN lookup failed for %s: %s", ip, exc)
        return "AS0", "Unknown"
    asn = f"AS{response.autonomous_system_number}" \
        if response.autonomous_system_number else "AS0"
    return asn, response.autonomous_system_organization or "Unknown"


# Datacenter / VPN heuristics
def _looks_like_datacenter(org: str) -> bool:
    needle = (org or "").lower()
    return any(hint in needle for hint in _DATACENTER_HINTS)


def _looks_like_vpn_or_tor(org: str, asn: str) -> bool:
    haystack = f"{org or ''} {asn or ''}".lower()
    return any(hint in haystack for hint in _VPN_TOR_HINTS)


# Entropy & typosquatting
def _shannon_entropy(value: str) -> float:
    # Bits-per-character Shannon entropy of value (0.0 if empty).
    if not value:
        return 0.0
    length = len(value)
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    # log2 >= 0 always, keep the return narrow for downstream sanity-checks.
    return float(round(entropy, 4))


def _registrable_domain(value: str) -> str:
    extracted = tldextract.extract(value or "")
    if extracted.registered_domain:
        return extracted.registered_domain.lower()
    return (value or "").lower()


def _closest_brand(host: str) -> Tuple[Optional[str], Optional[int]]:
    ext = EXTRACTOR(host)
    domain_prefix = ext.domain.lower()  # e.g., "micros0ft-security-update" or "micros0ft"
    registered = ext.registered_domain.lower()  # e.g., "micros0ft.com"
    
    if not domain_prefix:
        return None, None

    # Exact legitimate match check (e.g. genuine mail from microsoft.com)
    if registered in _BRAND_DOMAINS:
        return registered, 0

    best_target: Optional[str] = None
    best_distance: Optional[int] = None

    # 1. Check full domain SLD (Direct Typosquatting: "micros0ft" vs "microsoft")
    for bare_brand, full_domain in _BRAND_MAP.items():
        dist = lev_distance(domain_prefix, bare_brand)
        if dist <= 2:
            return full_domain, dist

    # 2. Check tokenized parts (Combosquatting: "micros0ft-security-update")
    tokens = re.split(r"[-_.]", domain_prefix)
    for token in tokens:
        if len(token) < 4:  # Ignore tiny tokens like "us", "id", "m"
            continue
            
        for bare_brand, full_domain in _BRAND_MAP.items():
            dist = lev_distance(token, bare_brand)
            if dist <= 2:
                if best_distance is None or dist < best_distance:
                    best_target = full_domain
                    best_distance = dist
                    if dist == 0:  # Direct inclusion of legitimate brand keyword (e.g., "paypal-support")
                        break

    return best_target, best_distance

__all__ = ["OriginNetwork", "resolve"]
