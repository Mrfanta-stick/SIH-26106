""""
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




#--------------------------- testing code -------------------------------
def test_url_extractor():
    html_content = """
    <html>
        <body>

            <!-- 1. Normal matching URL -->
            <p>Normal link:</p>
            <a href="https://google.com/login">
                https://google.com/login
            </a>

            <!-- 2. Anchor/domain mismatch -->
            <p>Phishing mismatch:</p>
            <a href="http://194.26.29.112/auth.php">
                https://microsoft.com/login
            </a>

            <!-- 3. Another mismatch -->
            <p>Another mismatch:</p>
            <a href="https://evil.com/steal">
                https://google.com
            </a>

            <!-- 4. Normal text anchor -->
            <p>Normal text anchor:</p>
            <a href="https://example.com/login">
                Click here to login
            </a>

            <!-- 5. www vs non-www -->
            <p>WWW test:</p>
            <a href="https://www.google.com/login">
                https://google.com/login
            </a>

            <!-- 6. @ / userinfo deception -->
            <p>Userinfo deception:</p>
            <a href="https://google.com@example.com/login">
                https://google.com@example.com/login
            </a>

            <!-- 7. Username + password -->
            <p>Userinfo with password:</p>
            <a href="******example.com/login">
                ******example.com/login
            </a>

        </body>
    </html>
    """

    result = extract_and_analyze_urls(html_content)

    print("\n========== URL ANALYSIS ==========")

    for i, item in enumerate(result, start=1):
        print(f"\nURL {i}")
        print(f"Anchor       : {item['anchor_text']}")
        print(f"Destination  : {item['destination']}")
        print(f"Mismatch     : {item['is_mismatch']}")

        # Only if your function includes this field
        if "has_userinfo" in item:
            print(f"Userinfo     : {item['has_userinfo']}")


def test_zero_font_obfuscation():
    html_content = """
    <html>
        <body>

            <p>This is visible text.</p>

            <span style="font-size: 0">
                Hidden zero font text
            </span>

            <span style="display: none">
                Hidden display none text
            </span>

            <span style="visibility: hidden">
                Hidden visibility text
            </span>

            <span style="color: transparent">
                Hidden transparent text
            </span>

            <span style="opacity: 0">
                Hidden opacity text
            </span>

            <p>This text is also visible.</p>

        </body>
    </html>
    """

    visible_text, hidden_cues = detect_zero_font_obfuscation(html_content)

    print("\n========== HIDDEN TEXT ANALYSIS ==========")

    print("\nVisible text:")
    print(visible_text)

    print("\nHidden text:")
    for i, text in enumerate(hidden_cues, start=1):
        print(f"{i}. {text}")


if __name__ == "__main__":
    test_url_extractor()
    test_zero_font_obfuscation()
