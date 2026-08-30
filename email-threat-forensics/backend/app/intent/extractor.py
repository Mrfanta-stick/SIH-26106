"""
purpose:
    extract bytes from base64 or text from Quoted-printable
    extract anchor and link from html (check if they are mis-matched)
    find and extract hidden text
"""

import re
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse
from bs4 import BeautifulSoup


def detect_zero_font_obfuscation(html_content: str) -> Tuple[str, List[str]]:
    """
    Scans HTML inline styles for hidden text tricks used by attackers to bypass
    email filters (e.g., zero-font). Strips them and returns the visible text.

    >> RETURN VALUE:
                 (Visible_text, list of non-visible strings)

    (TODO):
    1) tag.decompose will cause problems with nested tags
    """
    if not html_content:
        return "", []

    soup = BeautifulSoup(html_content, 'html.parser')
    extracted_hidden_cues: List[str] = []

    # CSS properties commonly used to hide text from users while exposing it to scanners
    hidden_style_patterns = [
    r'font-size\s*:\s*0(?:px|pt|em|rem)?',
    r'display\s*:\s*none',
    r'visibility\s*:\s*hidden',
    r'color\s*:\s*transparent',
    r'opacity\s*:\s*0(?:\.0*)?',
    ]

    # Find and evaluate all tags containing a 'style' attribute
    for tag in soup.find_all(style=True):
        style_attr = tag['style'].lower()

        # Check if the inline style matches any obfuscation pattern
        if any(re.search(pattern, style_attr) for pattern in hidden_style_patterns):
            hidden_text = tag.get_text(strip=True)
            if hidden_text:
                extracted_hidden_cues.append(hidden_text)

            # Decompose removes the tag and its contents from the soup entirely
            tag.decompose()

    # Extract the remaining visible text, using spaces to separate block elements
    visible_text_only = soup.get_text(separator=' ', strip=True)
    visible_text_only = re.sub(r'\s+', ' ', visible_text_only)

    return visible_text_only, extracted_hidden_cues



def extract_and_analyze_urls(html_content: str) -> List[Dict[str, Any]]:
    """
    Extracts <a> tags and compares visible anchor text against
    the actual href destination.

    (TODO):
    1) tags to parse:
           -> <a></a>
           -> <base></base>
    2) detect if the link is legitimate, i.e., it should take where the email is saying to
    """

    if not html_content:
        return []

    soup = BeautifulSoup(html_content, "html.parser")
    suspicious_urls = []

    for a_tag in soup.find_all("a", href=True):

        destination = a_tag["href"].strip()
        anchor_text = a_tag.get_text(" ", strip=True)
        is_mismatch = False
        anchor_has_userinfo = "@" in anchor_text

        dest_has_userinfo = False
        try:
            dest_parsed = urlparse(destination)
            dest_has_userinfo = bool(dest_parsed.username or "@" in (dest_parsed.netloc or ""))
        except ValueError:
            dest_has_userinfo = "@" in destination

        # Only perform mismatch analysis if the visible text
        # looks like a URL/domain.
        if (
            re.match(r"^https?://", anchor_text, re.IGNORECASE)
            or re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", anchor_text)
        ):

            normalized_anchor = (anchor_text if "://" in anchor_text else f"http://{anchor_text}")

            try:
                anchor_parsed = urlparse(normalized_anchor)
                anchor_has_userinfo = bool(anchor_parsed.username or "@" in (anchor_parsed.netloc or ""))

                anchor_domain = (anchor_parsed.hostname or "").lower()
                dest_domain = (dest_parsed.hostname or "").lower()

                anchor_domain = anchor_domain.removeprefix("www.")
                dest_domain = dest_domain.removeprefix("www.")

                if anchor_domain and dest_domain:
                    if anchor_domain != dest_domain:
                        is_mismatch = True
            except ValueError:
                pass

        suspicious_urls.append({
            "anchor_text": anchor_text,
            "destination": destination,
            "is_mismatch": is_mismatch,
            "has_userinfo": anchor_has_userinfo or dest_has_userinfo
        })

    return suspicious_urls
