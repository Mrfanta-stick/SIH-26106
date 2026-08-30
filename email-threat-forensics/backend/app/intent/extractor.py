"""
purpose:
    extract bytes from base64 or text from Quoted-printable
    extract anchor and link from html (check if they are mis-matched)
    find and extract hidden text
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from bs4 import BeautifulSoup, Tag
from urllib.parse import urlparse, urljoin

__all__ = [
    "KNOWN_REDIRECTORS",
    "detect_zero_font_obfuscation",
    "extract_and_analyze_urls",
]

# constants

KNOWN_REDIRECTORS: frozenset[str] = frozenset({
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly",
    "buff.ly", "is.gd", "shorte.st", "lnkd.in", "cutt.ly",
    "t.ly", "rb.gy", "short.io",
})

_HiddenStylePatterns = [
    r"font-size\s*:\s*0(?:px|pt|em|rem|%)",
    r"display\s*:\s*none",
    r"visibility\s*:\s*hidden",
    r"color\s*:\s*transparent",
    r"opacity\s*:\s*0(?:\.0*)?",
    r"width\s*:\s*0(?:px)?\s*;\s*overflow\s*:\s*hidden",
    r"height\s*:\s*0(?:px)?\s*;\s*overflow\s*:\s*hidden",
    r"left\s*:\s*-?\d{4,}px",          # off-screen
    r"top\s*:\s*-?\d{4,}px",
    r"clip\s*:\s*rect\s*\(\s*0\s*,\s*0\s*,\s*0\s*,\s*0\s*\)",
]

_CSS_BLOCK_RE = re.compile(
    r"\.([a-zA-Z0-9_-]+)\s*\{[^}]*?(?:display\s*:\s*none|font-size\s*:\s*0)[^}]*\}"
    r"|"
    r"#([a-zA-Z0-9_-]+)\s*\{[^}]*?(?:display\s*:\s*none|font-size\s*:\s*0)[^}]*\}",
    re.IGNORECASE,
)


# hidden-text detection

def detect_zero_font_obfuscation(html_content: str) -> Tuple[str, List[str]]:
    """
    Scans HTML inline styles for hidden text tricks used by attackers to bypass
    email filters (e.g. zero-font).  Strips them and returns the visible text.

    Returns:
    (visible_text, list_of_hidden_strings)
    """
    if not html_content:
        return "", []

    soup = BeautifulSoup(html_content, "html.parser")
    extracted: List[str] = []

    def record_and_clear(tag: Tag) -> None:
        text = tag.get_text(" ", strip=True)
        if text:
            extracted.append(text)
        try:
            tag.clear()
        except Exception:
            pass  # leave the (empty) tag in place; safer than replace_with for table cells

    # Capture <style> block CSS before any clearing
    style_texts: List[str] = []
    for style_tag in soup.find_all("style"):
        if style_tag.string:
            style_texts.append(style_tag.string)
    combined_style = " ".join(style_texts)

    # Inline style attributes 
    for tag in soup.find_all(style=True):
        style_val = str(tag.get("style") or "")
        if any(re.search(pat, style_val.lower()) for pat in _HiddenStylePatterns):
            record_and_clear(tag)

    # hidden / aria-hidden attributes
    for tag in soup.find_all(hidden=True):
        record_and_clear(tag)
    
    for tag in soup.select('[aria-hidden="true"], [aria-hidden="1"]'):
        record_and_clear(tag)

    # Hidden inputs
    for tag in soup.find_all("input", attrs={"type": "hidden"}):
        record_and_clear(tag)

    # Scripts / noscripts (not user-facing)
    for tag in soup.find_all(["script", "noscript"]):
        record_and_clear(tag)

    # Now that we've captured the CSS, clear style tags so their text
    # doesn't pollute visible text.
    for tag in soup.find_all("style"):
        tag.clear()

    # Class / id selectors from <style> blocks
    for match in _CSS_BLOCK_RE.finditer(combined_style):
        cls, idv = match.group(1), match.group(2)
        selector = f".{cls}" if cls else (f"#{idv}" if idv else None)
        if not selector:
            continue
        try:
            for tag in soup.select(selector):
                record_and_clear(tag)
        except Exception:
            pass  # invalid selector – skip gracefully

    # Visible text
    visible = re.sub(r"\s+", " ", soup.get_text(separator=" ", strip=True))
    return visible, extracted


# URL / anchor analysis

_OBFUSCATED_DOT_RE = re.compile(
    r"\[\s*\.?\s*\]"          # [.]  [ . ]
    r"|\(\s*dot\s*\)"         # (dot)
    r"|\s+dot\s+"             # dot  (word-boundary safe)
    r"|\s\.\s",              # .  (spaced dot, NOT bare dots inside a domain)
    re.IGNORECASE,
)


def _deobfuscate_anchor_text(text: str) -> str:
    """
    Normalise common domain-obfuscation tokens in visible anchor text:
      example[.]com, example(dot)com, example . com  ->  example.com
    Conservative: only collapses spaced dots and bracket/paren tokens.
    """
    if not text:
        return text

    s = text.strip()
    s = _OBFUSCATED_DOT_RE.sub(".", s)
    s = re.sub(r"[«»\"'`<>]", "", s)   # strip decorative quotes / angle brackets
    s = re.sub(r"\s+", " ", s).strip()
    return s


def extract_and_analyze_urls(html_content: str) -> List[Dict[str, Any]]:
    # Extract <a> tags, compare visible text to href, and flag suspicious links.

    if not html_content:
        return []

    soup = BeautifulSoup(html_content, "html.parser")
    results: List[Dict[str, Any]] = []

    base_href: Optional[str] = None
    base_tag = soup.find("base")

    if base_tag is not None:
        base_href_val = base_tag.get("href")
        if base_href_val:
            base_href = str(base_href_val).strip()

    for a_tag in soup.find_all("a", href=True):
        raw_href = str(a_tag.get("href") or "").strip()
        destination = urljoin(base_href, raw_href) if base_href else raw_href

        anchor_text = re.sub(r"\s+", " ", a_tag.get_text(" ", strip=True))
        deobfuscated = _deobfuscate_anchor_text(anchor_text)

        # parse destination
        try:
            dest_parsed = urlparse(destination)
        except Exception:
            dest_parsed = None

        scheme = (dest_parsed.scheme or "").lower() if dest_parsed else ""
        dest_domain = ((dest_parsed.hostname or "").lower().removeprefix("www.")
                       if dest_parsed else "")

        dest_has_userinfo = False
        if dest_parsed is not None:
            dest_has_userinfo = bool(
            dest_parsed.username or "@" in (dest_parsed.netloc or "")
        )

        # classify visible text
        visible_is_url_like = False
        anchor_domain = ""

        if re.match(r"^https?://", deobfuscated, re.IGNORECASE):
            visible_is_url_like = True
            parsed = urlparse(deobfuscated)
            anchor_domain = (parsed.hostname or "").lower().removeprefix("www.")
        elif re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$", deobfuscated):
            visible_is_url_like = True
            anchor_domain = deobfuscated.lower().removeprefix("www.")
        elif re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", deobfuscated):
            visible_is_url_like = True
            anchor_domain = deobfuscated.split("@", 1)[-1].lower().removeprefix("www.")

        # flags
        anchor_has_userinfo = "@" in anchor_text
        is_mismatch = bool(
            visible_is_url_like
            and anchor_domain
            and dest_domain
            and anchor_domain != dest_domain
        )
        # visible text looks like a domain but dest has none (javascript:, data:, …)
        if visible_is_url_like and anchor_domain and not dest_domain \
           and scheme not in {"mailto", "tel"}:
            is_mismatch = True

        results.append({
            "anchor_text": anchor_text,
            "deobfuscated_anchor_text": deobfuscated,
            "raw_href": raw_href,
            "destination": destination,
            "scheme": scheme,
            "anchor_domain": anchor_domain,
            "dest_domain": dest_domain,
            "is_mismatch": is_mismatch,
            "has_userinfo": anchor_has_userinfo or dest_has_userinfo,
            "is_mailto": scheme == "mailto",
            "is_tel": scheme == "tel",
            "is_javascript": scheme == "javascript",
            "is_data": scheme == "data",
            "is_redirector": dest_domain in KNOWN_REDIRECTORS,
        })

    return results
