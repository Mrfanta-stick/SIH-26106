"""
The :func:`generate_forensic_pdf` function consumes a fully populated
:class:`~app.schemas.forensic_report.MasterForensicReport` instance and returns a
byte string containing a PDF document.  The implementation relies on
`WeasyPrint <https://weasyprint.org/>`_ to render a self‑contained HTML/CSS
template.
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


def _truncate_hash(hash_str: str, length: int = 8) -> str:
    """Return a shortened representation of a SHA‑256 hash.

    Example: ``a3b1...9f2c`` where ``length`` characters are taken from the
    start and the end of the full 64‑character hex string.
    """

    if not hash_str or len(hash_str) < length * 2:
        return hash_str or ""
    return f"{hash_str[:length]}…{hash_str[-length:]}"


def _html_escape(text: str) -> str:
    """Very small HTML escape helper – we rely on the data being safe.
    """
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def generate_forensic_pdf(report: MasterForensicReport) -> bytes:
    """Render the report as a PDF.

    The function builds a single HTML document with embedded CSS that captures
    the required forensic sections.  All optional/nullable fields are rendered
    as an empty string when missing – this prevents Jinja‑style template errors.
    The final PDF bytes are returned for downstream storage or HTTP response.
    """

    # turning model objects into HTML fragments.
    
    def evidence_block() -> str:
        ev = report.evidence
        return f"""
        <h2>Evidence Block</h2>
        <table class='kv'>
            <tr><th>Case UUID</th><td>{_html_escape(report.case_id)}</td></tr>
            <tr><th>Evidence Filename</th><td>{_html_escape(ev.filename)}</td></tr>
            <tr><th>SHA‑256 Hash</th><td>{_html_escape(ev.sha256)}</td></tr>
            <tr><th>Ingestion Timestamp</th><td>{_html_escape(ev.ingestion_timestamp)}</td></tr>
        </table>
        """

    def verdict_card() -> str:
        ti = report.threat_intent
        pf = report.protocol_forensics
        return f"""
        <h2>Verdict Card</h2>
        <table class='kv'>
            <tr><th>Primary Intent</th><td>{_html_escape(ti.primary_intent)}</td></tr>
            <tr><th>Risk Score</th><td>{ti.risk_score}</td></tr>
            <tr><th>SPF</th><td>{_html_escape(pf.spf)}</td></tr>
            <tr><th>DKIM</th><td>{_html_escape(pf.dkim)}</td></tr>
            <tr><th>DMARC</th><td>{_html_escape(pf.dmarc)}</td></tr>
        </table>
        """

    def origin_network() -> str:
        on = report.origin_network
        return f"""
        <h2>Origin Network</h2>
        <table class='kv'>
            <tr><th>IP</th><td>{_html_escape(on.ip)}</td></tr>
            <tr><th>City / Country</th><td>{_html_escape(on.city)} / {_html_escape(on.country)}</td></tr>
            <tr><th>ASN / Org</th><td>{_html_escape(on.asn)} / {_html_escape(on.org)}</td></tr>
            <tr><th>Datacenter</th><td>{'Yes' if on.is_datacenter else 'No'}</td></tr>
            <tr><th>VPN / Tor</th><td>{'Yes' if on.is_vpn_tor else 'No'}</td></tr>
        </table>
        """

    def suspicious_urls() -> str:
        urls: List[SuspiciousURL] = report.threat_intent.suspicious_urls
        if not urls:
            return "<p>No suspicious URLs detected.</p>"
        rows = "".join(
            f"<tr><td>{_html_escape(u.anchor_text)}</td><td>{_html_escape(u.destination)}</td><td>{'Yes' if u.is_mismatch else 'No'}</td></tr>"
            for u in urls
        )
        return f"""
        <h2>Suspicious URLs</h2>
        <table class='grid'>
            <thead><tr><th>Anchor Text</th><th>Destination</th><th>Mismatch</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>
        """

    def attachments() -> str:
        atts: List[AttachmentReport] = report.attachment_forensics
        if not atts:
            return "<p>No attachments.</p>"
        rows = "".join(
            f"<tr>"
            f"<td>{_html_escape(a.filename)}</td>"
            f"<td>{_html_escape(a.detected_magic)}</td>"
            f"<td>{_html_escape(a.risk)}</td>"
            f"<td>{a.size_bytes if a.size_bytes is not None else ''}</td>"
            f"<td>{_html_escape(a.sha256 or '')}</td>"
            f"</tr>"
            for a in atts
        )
        return f"""
        <h2>Attachments</h2>
        <table class='grid'>
            <thead>
                <tr>
                    <th>Filename</th><th>Magic</th><th>Risk</th><th>Size (bytes)</th><th>SHA‑256</th>
                </tr>
            </thead>
            <tbody>{rows}</tbody>
        </table>
        """

    def custody_table() -> str:
        entries: List[ChainOfCustodyEntry] = report.chain_of_custody
        if not entries:
            return "<p>Chain of custody is empty.</p>"
        rows = "".join(
            f"<tr>"
            f"<td>{e.sequence}</td>"
            f"<td>{_html_escape(e.timestamp)}</td>"
            f"<td>{_html_escape(e.action)}</td>"
            f"<td>{_html_escape(e.actor)}</td>"
            f"<td>{_truncate_hash(e.prev_hash)}</td>"
            f"<td>{_truncate_hash(e.entry_hash)}</td>"
            f"</tr>"
            for e in entries
        )
        return f"""
        <h2>Chain of Custody</h2>
        <table class='grid'>
            <thead>
                <tr>
                    <th>Seq</th><th>Timestamp</th><th>Action</th><th>Actor</th><th>Prev Hash</th><th>Entry Hash</th>
                </tr>
            </thead>
            <tbody>{rows}</tbody>
        </table>
        """

    # Assemble final HTML document.

    html = f"""
    <!DOCTYPE html>
    <html lang='en'>
    <head>
        <meta charset='utf-8'>
        <title>Forensic Report – {_html_escape(report.case_id)}</title>
        <style>
            @page {{
                size: A4;
                margin: 1in;
                @bottom-center {{
                    content: "Page " counter(page) " of " counter(pages);
                    font-size: 0.8rem;
                    color: #555;
                }}
                @top-center {{
                    content: "DFIR Forensic Report";
                    font-weight: bold;
                    font-size: 1rem;
                }}
            }}
            body {{ font-family: system-ui, sans-serif; line-height: 1.4; color: #212529; }}
            h1, h2 {{ margin-top: 1.5rem; margin-bottom: 0.5rem; color: #0d6efd; }}
            h1 {{ text-align: center; font-size: 1.8rem; }}
            table {{ width: 100%; border-collapse: collapse; margin-bottom: 1rem; }}
            th, td {{ border: 1px solid #dee2e6; padding: 0.4rem 0.6rem; text-align: left; font-size: 0.9rem; }}
            th {{ background: #f8f9fa; font-weight: 600; }}
            .kv th {{ width: 30%; }}
            .grid tbody tr:nth-child(even) {{ background: #f1f3f5; }}
        </style>
    </head>
    <body>
        <h1>Digital Forensics Incident Response Report</h1>
        {evidence_block()}
        {verdict_card()}
        {origin_network()}
        {suspicious_urls()}
        {attachments()}
        {custody_table()}
    </body>
    </html>
    """

    # Render using WeasyPrint – the function returns raw PDF bytes.
    pdf_bytes = HTML(string=html).write_pdf()
    return pdf_bytes

