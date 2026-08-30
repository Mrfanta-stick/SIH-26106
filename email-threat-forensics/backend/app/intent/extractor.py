"""
purpose:
    extract bytes from base64 or text from Quoted-printable
    extract anchor and link from html (check if they are mis-matched)
    find and extract hidden text
"""

import re
from typing import Any, Dict, List, Tuple, Optional
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

# simple list of common redirector/shortener hosts we might want to flag
KNOWN_REDIRECTORS = {
    "bit.ly",
    "t.co",
    "tinyurl.com",
    "goo.gl",
    "ow.ly",
    "buff.ly",
    "is.gd",
    "shorte.st",
}


def detect_zero_font_obfuscation(html_content: str) -> Tuple[str, List[str]]:
    """
    Scans HTML inline styles for hidden text tricks used by attackers to bypass
    email filters (e.g., zero-font). Strips them and returns the visible text.

    RETURN VALUE:
                (visible_text, list of non-visible strings)

    Improvements:
    1) Avoids removing parent content by clearing hidden nodes rather than decomposing them.
    2) Detects inline style obfuscation (font-size:0, display:none, visibility:hidden, color:transparent, opacity:0).
    3) Detects elements with hidden/aria-hidden attributes and input type="hidden".
    4) Parses <style> blocks for simple class/id selectors that hide content and clears matching elements.
    """
    if not html_content:
        return "", []

    soup = BeautifulSoup(html_content, "html.parser")
    extracted_hidden_cues: List[str] = []

    # CSS properties commonly used to hide text from users while exposing it to scanners
    hidden_style_patterns = [
        r"font-size\s*:\s*0(?:px|pt|em|rem)?",
        r"display\s*:\s*none",
        r"visibility\s*:\s*hidden",
        r"color\s*:\s*transparent",
        r"opacity\s*:\s*0(?:\.0*)?",
    ]

    def record_and_clear(tag):
        hidden_text = tag.get_text(" ", strip=True)
        if hidden_text:
            extracted_hidden_cues.append(hidden_text)
        # Remove child nodes / text but keep the tag structure to avoid taking out sibling content
        try:
            tag.clear()
        except Exception:
            # Fallback to replace_with empty string if clear fails
            try:
                tag.replace_with("")
            except Exception:
                pass

    # 1) Inline style attributes
    for tag in soup.find_all(style=True):
        style_attr = (tag.get("style") or "").lower()
        if any(re.search(pattern, style_attr) for pattern in hidden_style_patterns):
            record_and_clear(tag)

    # 2) Elements explicitly marked hidden or aria-hidden
    for tag in soup.find_all(attrs={"hidden": True}):
        record_and_clear(tag)
    for tag in soup.find_all(attrs={"aria-hidden": True}):
        # aria-hidden can be 'true' or other, check truthiness
        if str(tag.attrs.get("aria-hidden")).lower() in {"true", "1"}:
            record_and_clear(tag)

    # 3) Inputs and form elements that are not visible
    for tag in soup.find_all("input", {"type": "hidden"}):
        record_and_clear(tag)

    # 4) Remove script and noscript contents from visible text (they are not user-facing)
    for tag in soup.find_all(["script", "noscript", "style"]):
        # If style block contains hiding CSS, we'll parse it below; don't double-add
        if tag.name == "style":
            # leave style tag for selector analysis but remove its text so it doesn't pollute visible text
            tag.string = ""
        else:
            record_and_clear(tag)

    # 5) Inspect <style> blocks for simple class/id selectors that hide content.
    # This is conservative: we only look for simple selectors like ".classname { display: none }" or "#id { display: none }"
    style_texts = []
    for style_tag in soup.find_all("style"):
        if style_tag.string:
            style_texts.append(style_tag.string)

    combined_style = " ".join(style_texts)
    # find class selectors: .foo { ... display: none ... }
    class_matches = re.findall(r"\.([a-zA-Z0-9_-]+)\s*\{[^}]*?(?:display\s*:\s*none|font-size\s*:\s*0)[^}]*\}", combined_style, flags=re.IGNORECASE)
    id_matches = re.findall(r"#([a-zA-Z0-9_-]+)\s*\{[^}]*?(?:display\s*:\s*none|font-size\s*:\s*0)[^}]*\}", combined_style, flags=re.IGNORECASE)

    for cls in set(class_matches):
        for tag in soup.select(f".{cls}"):
            record_and_clear(tag)
    for idv in set(id_matches):
        for tag in soup.select(f"#{idv}"):
            record_and_clear(tag)

    # After clearing hidden bits, extract the visible text
    visible_text_only = soup.get_text(separator=" ", strip=True)
    visible_text_only = re.sub(r"\s+", " ", visible_text_only)

    return visible_text_only, extracted_hidden_cues


def _deobfuscate_anchor_text(text: str) -> str:
    """
    Try to normalize common obfuscations used in visible text:
    - example[.]com, example(dot)com, example . com, example (dot) com -> example.com
    - remove surrounding punctuation and whitespace
    This is heuristic and conservative.
    """
    if not text:
        return text
    s = text.strip()

    # Replace common obfuscation tokens with a dot
    s = re.sub(r"\[\.?]\s*|[(]\s*dot\s*[)]|(?:\s+dot\s+)|\s*\.\s*", ".", s, flags=re.IGNORECASE)
    # remove spaces around dots that might remain
    s = re.sub(r"\s*\.\s*", ".", s)
    # remove extraneous characters often used to break scanners
    s = re.sub(r"[«»\"'`<>()]", "", s)
    # collapsed spaces
    s = re.sub(r"\s+", " ", s)
    return s


def extract_and_analyze_urls(html_content: str) -> List[Dict[str, Any]]:
    """
    Extracts <a> tags and compares visible anchor text against
    the actual href destination.

    Enhancements implemented:
    - Honor <base href="..."> and resolve relative links via urljoin.
    - Detect mailto:, tel:, javascript:, data: schemes and surface them.
    - Normalize obfuscated visible text (example[.]com -> example.com) before comparison.
    - Flag mismatches when the anchor-looking visible text contains a domain but href points elsewhere.
    - Flag presence of userinfo (username@host) in either anchor text or destination.
    - Mark known redirector/shortener hosts as potentially suspicious.
    """
    if not html_content:
        return []

    soup = BeautifulSoup(html_content, "html.parser")
    suspicious_urls: List[Dict[str, Any]] = []

    # If a <base> tag exists, use it to resolve relative hrefs
    base_tag = soup.find("base", href=True)
    base_href: Optional[str] = base_tag["href"].strip() if base_tag else None

    for a_tag in soup.find_all("a", href=True):
        raw_href = (a_tag["href"] or "").strip()
        # Resolve relative links using base_href if present
        destination = urljoin(base_href, raw_href) if base_href else raw_href
        anchor_text = a_tag.get_text(" ", strip=True)
        anchor_text = re.sub(r"\s+", " ", anchor_text)

        is_mismatch = False
        anchor_has_userinfo = "@" in anchor_text

        dest_has_userinfo = False
        dest_parsed = None
        try:
            dest_parsed = urlparse(destination)
            dest_has_userinfo = bool(dest_parsed.username or ("@" in (dest_parsed.netloc or "")))
        except Exception:
            # malformed destination; mark it as having userinfo if '@' present
            dest_has_userinfo = "@" in destination

        # Basic classification of scheme (mailto, tel, javascript, data, http(s))
        scheme = (dest_parsed.scheme if dest_parsed else "").lower() if dest_parsed else ""
        is_mailto = scheme == "mailto"
        is_tel = scheme == "tel"
        is_javascript = scheme == "javascript"
        is_data = scheme == "data"

        # If the visible text looks like a URL/domain/email, attempt to compare
        visible_is_url_like = False
        anchor_domain = ""
        dest_domain = ""
        try:
            # deobfuscate common patterns like example[.]com
            normalized_visible = _deobfuscate_anchor_text(anchor_text)

            # Consider it URL-like if it starts with http(s) or contains a dot and domain-like characters
            if re.match(r"^https?://", normalized_visible, re.IGNORECASE) or re.match(r"^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}", normalized_visible):
                visible_is_url_like = True
                normalized_anchor = normalized_visible if "://" in normalized_visible else f"http://{normalized_visible}"
                anchor_parsed = urlparse(normalized_anchor)
                anchor_domain = (anchor_parsed.hostname or "").lower()
            elif re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", normalized_visible):
                # visible text is an email address
                anchor_domain = normalized_visible.split("@", 1)[-1].lower()
                visible_is_url_like = True
        except Exception:
            pass

        if dest_parsed:
            dest_domain = (dest_parsed.hostname or "").lower()

        # Normalize common www prefix
        if anchor_domain.startswith("www."):
            anchor_domain = anchor_domain.removeprefix("www.")
        if dest_domain.startswith("www."):
            dest_domain = dest_domain.removeprefix("www.")

        # If visible text indicated a domain and both domains are present, compare
        if visible_is_url_like and anchor_domain and dest_domain:
            if anchor_domain != dest_domain:
                is_mismatch = True

        # If visible looks like domain but destination has no domain (e.g., javascript:, data:), that's suspicious
        if visible_is_url_like and not dest_domain and not is_mailto and not is_tel:
            is_mismatch = True

        # If the destination netloc contains a userinfo pattern or explicit username, flag it
        has_userinfo = anchor_has_userinfo or dest_has_userinfo

        # Flag redirector shorteners
        is_redirector = dest_domain in KNOWN_REDIRECTORS if dest_domain else False

        suspicious_urls.append(
            {
                "anchor_text": anchor_text,
                "deobfuscated_anchor_text": _deobfuscate_anchor_text(anchor_text),
                "raw_href": raw_href,
                "destination": destination,
                "scheme": scheme,
                "is_mismatch": is_mismatch,
                "has_userinfo": has_userinfo,
                "is_mailto": is_mailto,
                "is_tel": is_tel,
                "is_javascript": is_javascript,
                "is_data": is_data,
                "is_redirector": is_redirector,
                "anchor_domain": anchor_domain,
                "dest_domain": dest_domain,
            }
        )

    return suspicious_urls
