"""
DFIR Forensic PDF Dossier Generator using WeasyPrint.
Renders court-admissible forensic documentation adhering to ISO/IEC 27037 integrity.
"""

from __future__ import annotations

from typing import List
from weasyprint import HTML

from ..schemas.forensic_report import (
    AttachmentReport,
    ChainOfCustodyEntry,
    MasterForensicReport,
    SuspiciousURL,
)


def _truncate_hash(hash_str: str, length: int = 5) -> str:
    """Return a clean monospace-shortened hash (e.g. 24c33…da237)."""
    if not hash_str or len(hash_str) <= length * 2:
        return hash_str or "—"
    return f"{hash_str[:length]}…{hash_str[-length:]}"


def _format_timestamp(ts: str) -> str:
    """Format ISO timestamps to clean, human-readable UTC."""
    if not ts:
        return "—"
    return ts.replace("T", " ").split(".")[0] + " UTC"


def _html_escape(text: str) -> str:
    return (
        str(text or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _badge(val: str, mode: str = "neutral") -> str:
    """Render small forensic indicator pills."""
    val_upper = str(val).upper()
    cls = "badge-neutral"
    if val_upper in ("PASS", "BENIGN", "LOW", "NO"):
        cls = "badge-pass"
    elif val_upper in ("FAIL", "SUSPICIOUS", "MALICIOUS", "CRITICAL", "YES"):
        cls = "badge-fail"
    elif val_upper in ("NONE", "UNKNOWN"):
        cls = "badge-warning"
    return f"<span class='badge {cls}'>{_html_escape(val)}</span>"


def generate_forensic_pdf(report: MasterForensicReport) -> bytes:
    """Render a MasterForensicReport into an official forensic incident dossier."""
    ev = report.evidence
    pf = report.protocol_forensics
    on = report.origin_network
    ti = report.threat_intent

    evidence_html = f"""
    <div class='section-card'>
        <div class='section-title'>1. Evidentiary Identification & Baseline Hash</div>
        <table class='kv-table'>
            <tr>
                <td class='k'>Case UUID</td>
                <td class='v mono'>{_html_escape(report.case_id)}</td>
            </tr>
            <tr>
                <td class='k'>Original Filename</td>
                <td class='v'><strong>{_html_escape(ev.filename)}</strong></td>
            </tr>
            <tr>
                <td class='k'>SHA-256 Ingestion Fingerprint</td>
                <td class='v mono break-all'>{_html_escape(ev.sha256)}</td>
            </tr>
            <tr>
                <td class='k'>Acquisition Timestamp</td>
                <td class='v'>{_format_timestamp(ev.ingestion_timestamp)}</td>
            </tr>
        </table>
    </div>
    """

    verdict_html = f"""
    <div class='section-card'>
        <div class='section-title'>2. Threat Severity & Protocol Forensics</div>
        <div class='verdict-grid'>
            <div class='verdict-box'>
                <div class='v-label'>Overall Verdict</div>
                <div class='v-val'>{_badge(ti.primary_intent)}</div>
            </div>
            <div class='verdict-box'>
                <div class='v-label'>Risk Score</div>
                <div class='v-val risk-number'>{ti.risk_score}<span class='denom'>/100</span></div>
            </div>
            <div class='verdict-box'>
                <div class='v-label'>SPF Auth</div>
                <div class='v-val'>{_badge(pf.spf)}</div>
            </div>
            <div class='verdict-box'>
                <div class='v-label'>DKIM Signature</div>
                <div class='v-val'>{_badge(pf.dkim)}</div>
            </div>
            <div class='verdict-box'>
                <div class='v-label'>DMARC Policy</div>
                <div class='v-val'>{_badge(pf.dmarc)}</div>
            </div>
            <div class='verdict-box'>
                <div class='v-label'>Domain Alignment</div>
                <div class='v-val'>{'Aligned' if pf.domain_alignment.is_aligned else _badge('UNALIGNED', 'fail')}</div>
            </div>
        </div>
    </div>
    """

    origin_html = f"""
    <div class='section-card'>
        <div class='section-title'>3. Origin Infrastructure & Attribution</div>
        <table class='kv-table'>
            <tr>
                <td class='k'>Origin Public IP</td>
                <td class='v mono'><strong>{_html_escape(on.ip)}</strong></td>
            </tr>
            <tr>
                <td class='k'>Geolocation</td>
                <td class='v'>{_html_escape(on.city or 'Unknown')}, {_html_escape(on.country or 'Unknown')} ({on.latitude}, {on.longitude})</td>
            </tr>
            <tr>
                <td class='k'>Autonomous System (ASN)</td>
                <td class='v'>{_html_escape(on.asn)} — {_html_escape(on.org)}</td>
            </tr>
            <tr>
                <td class='k'>Deception & Threat Flags</td>
                <td class='v'>
                    Datacenter: {_badge('Yes' if on.is_datacenter else 'No')} | 
                    VPN/Tor: {_badge('Yes' if on.is_vpn_tor else 'No')} | 
                    Typosquatting: {f'Imitating {_html_escape(on.typosquat_target)} (Dist: {on.edit_distance})' if on.typosquat_target else 'None'}
                </td>
            </tr>
        </table>
    </div>
    """

    urls: List[SuspiciousURL] = ti.suspicious_urls
    if urls:
        url_rows = "".join(
            f"<tr>"
            f"<td class='mono break-all'>{_html_escape(u.anchor_text)}</td>"
            f"<td class='mono break-all'>{_html_escape(u.destination)}</td>"
            f"<td style='text-align:center;'>{_badge('YES', 'fail') if u.is_mismatch else _badge('No', 'pass')}</td>"
            f"</tr>"
            for u in urls
        )
        url_html = f"""
        <div class='section-card'>
            <div class='section-title'>4. Link Deception & Suspicious Destinations</div>
            <table class='grid-table'>
                <thead>
                    <tr>
                        <th style='width: 44%;'>Visible Anchor Text</th>
                        <th style='width: 44%;'>Destination Target</th>
                        <th style='width: 12%; text-align:center;'>Mismatch</th>
                    </tr>
                </thead>
                <tbody>{url_rows}</tbody>
            </table>
        </div>
        """
    else:
        url_html = ""

    atts: List[AttachmentReport] = report.attachment_forensics
    if atts:
        att_rows = "".join(
            f"<tr>"
            f"<td><strong>{_html_escape(a.filename)}</strong></td>"
            f"<td>{_html_escape(a.detected_magic)}</td>"
            f"<td style='text-align:center;'>{_badge(a.risk)}</td>"
            f"<td style='text-align:center;'>{a.size_bytes if a.size_bytes is not None else '—'} B</td>"
            f"<td class='mono-hash'>{_truncate_hash(a.sha256, 5)}</td>"
            f"</tr>"
            for a in atts
        )
        att_html = f"""
        <div class='section-card'>
            <div class='section-title'>5. Static Attachment Triage</div>
            <table class='grid-table'>
                <thead>
                    <tr>
                        <th style='width: 20%;'>Filename</th>
                        <th style='width: 25%;'>Magic Byte Signature</th>
                        <th style='width: 18%; text-align:center;'>Verdict</th>
                        <th style='width: 10%; text-align:center;'>Size</th>
                        <th style='width: 10%; text-align:center;'>SHA-256</th>
                    </tr>
                </thead>
                <tbody>{att_rows}</tbody>
            </table>
        </div>
        """
    else:
        att_html = ""

    entries: List[ChainOfCustodyEntry] = report.chain_of_custody
    custody_rows = "".join(
        f"<tr>"
        f"<td style='text-align:center;' class='mono'>{e.sequence}</td>"
        f"<td>{_format_timestamp(e.timestamp)}</td>"
        f"<td>{_html_escape(e.action)}</td>"
        f"<td class='mono'>{_html_escape(e.actor)}</td>"
        f"<td class='mono-hash'>{_truncate_hash(e.prev_hash, 5)}</td>"
        f"<td class='mono-hash'><strong>{_truncate_hash(e.entry_hash, 5)}</strong></td>"
        f"</tr>"
        for e in entries
    )
    custody_html = f"""
    <div class='section-card'>
        <div class='section-title'>6. Cryptographic Chain of Custody (ISO/IEC 27037)</div>
        <table class='grid-table'>
            <thead>
                <tr>
                    <th style='width: 5%; text-align:center;'>#</th>
                    <th style='width: 19%; text-align:center;'>Timestamp</th>
                    <th style='width: 25%; text-align:center;'>Action / Event</th>
                    <th style='width: 12%; text-align:center;'>Actor</th>
                    <th style='width: 10%; text-align:center; text-align:center;'>Prev Hash</th>
                    <th style='width: 15%; text-align:center;'>Block Hash</th>
                </tr>
            </thead>
            <tbody>{custody_rows}</tbody>
        </table>
    </div>
    """

    html = f"""
    <!DOCTYPE html>
    <html lang='en'>
    <head>
        <meta charset='utf-8'>
        <title>DFIR Dossier — {_html_escape(report.case_id)}</title>
        <style>
            @page {{
                size: A4;
                margin: 0.6in 0.5in 0.7in 0.5in;
                @top-left {{
                    content: "CONFIDENTIAL // LAW ENFORCEMENT & SOC FORENSIC REPORT";
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                    font-size: 7pt;
                    font-weight: bold;
                    color: #718096;
                }}
                @top-right {{
                    content: "CASE: {_html_escape(report.case_id[:8])}";
                    font-family: monospace;
                    font-size: 7pt;
                    color: #718096;
                }}
                @bottom-left {{
                    content: "DFIR Evidentiary Forensic Dossier";
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                    font-size: 7pt;
                    color: #a0aec0;
                }}
                @bottom-right {{
                    content: "Page " counter(page) " of " counter(pages);
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                    font-size: 7pt;
                    font-weight: bold;
                    color: #4a5568;
                }}
            }}

            body {{
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                color: #1a202c;
                line-height: 1.35;
                font-size: 8.5pt;
                margin: 0;
            }}

            .header-banner {{
                border-bottom: 2px solid #2b6cb0;
                padding-bottom: 6px;
                margin-bottom: 12px;
            }}
            .header-title {{
                font-size: 15pt;
                font-weight: 800;
                color: #2b6cb0;
                letter-spacing: -0.5px;
                margin: 0;
            }}
            .header-sub {{
                font-size: 7.5pt;
                color: #4a5568;
                margin-top: 2px;
            }}

            .section-card {{
                margin-bottom: 13px;
            }}
            .section-title {{
                font-size: 9pt;
                font-weight: 700;
                color: #2d3748;
                border-bottom: 1px solid #e2e8f0;
                padding-bottom: 3px;
                margin-bottom: 5px;
                text-transform: uppercase;
                letter-spacing: 0.3px;
                break-after: avoid;
                page-break-after: avoid;
            }}

            table {{
                width: 100%;
                border-collapse: collapse;
                table-layout: fixed;
            }}
            thead {{
                display: table-header-group;
            }}
            tr {{
                break-inside: avoid;
                page-break-inside: avoid;
            }}

            .kv-table td {{
                padding: 4px 6px;
                border: 1px solid #e2e8f0;
                font-size: 8pt;
            }}
            .kv-table .k {{
                width: 28%;
                background: #f7fafc;
                font-weight: 600;
                color: #4a5568;
            }}
            .kv-table .v {{
                width: 72%;
            }}

            .grid-table th, .grid-table td {{
                border: 1px solid #e2e8f0;
                padding: 4px 6px;
                font-size: 7.5pt;
                vertical-align: middle;
            }}
            .grid-table th {{
                background: #edf2f7;
                font-weight: 700;
                color: #2d3748;
                text-align: left;
            }}
            .grid-table tbody tr:nth-child(even) {{
                background: #f7fafc;
            }}

            .verdict-grid {{
                display: flex;
                gap: 6px;
                margin-top: 4px;
            }}
            .verdict-box {{
                flex: 1;
                background: #f7fafc;
                border: 1px solid #e2e8f0;
                border-radius: 3px;
                padding: 5px 3px;
                text-align: center;
            }}
            .v-label {{
                font-size: 6.2pt;
                text-transform: uppercase;
                color: #718096;
                font-weight: 700;
                margin-bottom: 3px;
            }}
            .v-val {{
                font-size: 8.8pt;
                font-weight: 700;
            }}
            .risk-number {{
                font-size: 10.5pt;
                color: #c53030;
            }}
            .denom {{
                font-size: 6.8pt;
                color: #a0aec0;
            }}

            .badge {{
                display: inline-block;
                padding: 1px 4px;
                border-radius: 3px;
                font-size: 6.5pt;
                font-weight: 700;
                text-transform: uppercase;
            }}
            .badge-pass {{ background: #c6f6d5; color: #22543d; border: 1px solid #9ae6b4; }}
            .badge-fail {{ background: #fed7d7; color: #742a2a; border: 1px solid #feb2b2; }}
            .badge-warning {{ background: #feebc8; color: #7b341e; border: 1px solid #fbd38d; }}
            .badge-neutral {{ background: #edf2f7; color: #4a5568; border: 1px solid #cbd5e0; }}

            .mono {{ font-family: "Courier New", Courier, monospace; font-size: 7pt; }}
            .mono-hash {{
                font-family: "Courier New", Courier, monospace;
                font-size: 6.8pt;
                text-align: center;
                white-space: nowrap;
            }}
            .break-all {{ word-break: break-all; overflow-wrap: anywhere; }}
        </style>
    </head>
    <body>
        <div class='header-banner'>
            <div class='header-title'>Digital Forensics Incident Report</div>
            <div class='header-sub'>Automated Evidentiary Extraction & Threat Analysis Pipeline</div>
        </div>

        {evidence_html}
        {verdict_html}
        {origin_html}
        {url_html}
        {att_html}
        {custody_html}
    </body>
    </html>
    """

    return HTML(string=html).write_pdf()
