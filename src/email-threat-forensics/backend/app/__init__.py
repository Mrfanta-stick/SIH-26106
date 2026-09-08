"""Email Threat Forensics — backend package.

Stage 1 & 2 module surface:

* ``app.schemas.forensic_report`` — immutable Pydantic V2 master contract.
* ``app.network.ingest``        — RFC 5322 (``.eml``) / MAPI (``.msg``) parsing + SHA-256.
* ``app.network.hop_tracer``    — chronological ``Received:`` parsing & earliest public IP.
* ``app.network.auth_verifier`` — SPF / DKIM / DMARC & relaxed domain alignment.
* ``app.network.domain_geo``    — MaxMind GeoLite2 / GeoLite2-ASN resolution + entropy + Levenshtein.

Group 3 modules (``intent``, ``attribution``, ``custody``) and the Group 1 Next.js
frontend are intentionally excluded from this build phase.
"""

__all__ = ["schemas", "network"]
