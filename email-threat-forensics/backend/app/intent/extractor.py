""""
purpose:
    extract bytes from base64 or text from Quoted-printable
    extract anchor and link from html (check if they are mis-matched)
    find and extract hidden text
"""

import json
import html
import re
import base64
import binascii
import quopri
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse
from bs4 import BeautifulSoup



def detect_zero_font_obfuscation(html_content: str) -> Tuple[str, List[str]]:
    """
    Scans HTML inline styles for hidden text tricks used by attackers to bypass
    email filters (e.g., zero-font). Strips them and returns the visible text.

    >> RETURN VALUE:
                 (Visible_text, list of non-visible strings)
    """
    if not html_content:
        return "", []

    soup = BeautifulSoup(html_content, 'html.parser')
    extracted_hidden_cues: List[str] = []

    # CSS properties commonly used to hide text from users while exposing it to scanners
    hidden_style_patterns = [
        'font-size: 0', 'font-size:0',
        'display: none', 'display:none',
        'visibility: hidden', 'visibility:hidden',
        'color: transparent', 'color:transparent',
        'opacity: 0', 'opacity:0'
    ]

    # Find and evaluate all tags containing a 'style' attribute
    for tag in soup.find_all(style=True):
        style_attr = tag['style'].lower()

        # Check if the inline style matches any obfuscation pattern
        if any(pattern in style_attr for pattern in hidden_style_patterns):
            hidden_text = tag.get_text(strip=True)
            if hidden_text:
                extracted_hidden_cues.append(hidden_text)

            # Decompose removes the tag and its contents from the soup entirely
            tag.decompose()

    # Extract the remaining visible text, using spaces to separate block elements
    visible_text_only = soup.get_text(separator=' ', strip=True)

    # Clean up excessive whitespace created by extraction
    visible_text_only = re.sub(r'\s+', ' ', visible_text_only)

    return visible_text_only, extracted_hidden_cues



def extract_and_analyze_urls(html_content: str) -> str:
    """
    Extracts <a> tags and compares visible anchor text against
    the actual href destination.

    Returns:
    [
        {
            "anchor_text": "...",
            "destination": "...",
            "is_mismatch": True
        }
    ]
    tags to parse:
        -> <a></a>
        -> <base></base> (TODO)

    (TODO : detect them as well)
    links might do something like this:
            https://google.com@example.com : this will take you to example.com instead of google.com
    """

    if not html_content:
        return []

    soup = BeautifulSoup(html_content, "html.parser")
    return_string = "\"suspicious_urls\": ["

    for a_tag in soup.find_all("a", href=True):

        destination = a_tag["href"].strip()
        anchor_text = a_tag.get_text(" ", strip=True)
        is_mismatch = False

        # Only perform mismatch analysis if the visible text
        # looks like a URL/domain.
        if (
            re.match(r"^https?://", anchor_text, re.IGNORECASE)
            or re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", anchor_text)
        ):
            normalized_anchor = (
                anchor_text
                if "://" in anchor_text
                else f"http://{anchor_text}"
            )

            try:
                anchor_domain = urlparse(normalized_anchor).netloc.lower()
                dest_domain = urlparse(destination).netloc.lower()

                # Remove www.
                anchor_domain = anchor_domain.removeprefix("www.")
                dest_domain = dest_domain.removeprefix("www.")

                if anchor_domain and dest_domain:
                    if anchor_domain != dest_domain:
                        is_mismatch = True
            except ValueError:
                pass

            is_mismatch_string = "true" if is_mismatch else "false"
            return_string += f"{{\"anchor_text\": \"{anchor_text}\", \"destination\": \"{destination}\", \"is_mismatch\": {is_mismatch_string}}},"

    return_string += "]"
    return return_string




#--------------------------- testing code -------------------------------

def test_url_extractor():
    html = """
    <html>
        <body>

            <p>Normal link:</p>
            <a href="https://google.com/login">
                https://google.com/login
            </a>

            <p>Phishing mismatch:</p>
            <a href="http://194.26.29.112/auth.php">
                https://microsoft.com/login
            </a>

            <p>Another mismatch:</p>
            <a href="https://evil.com/steal">
                https://google.com
            </a>

            <p>Non-URL anchor text:</p>
            <a href="https://example.com/login">
                Click here to login
            </a>

        </body>
    </html>
    """

    result = extract_and_analyze_urls(html)

    print(result)


if __name__ == "__main__":
    test_url_extractor()