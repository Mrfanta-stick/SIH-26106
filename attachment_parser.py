import email
from email import policy
import hashlib
import json
import urllib.request
import urllib.error

""" VirusTotal is Google's Virus database. 
Hashes are compared by 67 engines, comparing attachments to already flagged attachments.
Higher the malicious count, higher the threat."""

# noinspection PyBroadException
def check_virustotal(sha256_hash, api_key):
    if not api_key or api_key == "NOT_FOUND":
        return {"malicious": 54, "undetected": 16, "status": "Mocked (No API Key)"}

    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {"x-apikey": api_key}

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read())
            stats = data['data']['attributes']['last_analysis_stats']
            return {
                "malicious": stats.get('malicious', 0),
                "undetected": stats.get('undetected', 0),
                "status": "Found in VT"
            }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"malicious": 0, "undetected": 0, "status": "File never seen by VT"}
        return {"error": f"HTTP {e.code}"}
    except Exception as e:
        return {"error": "VT Connection Failed"}


def analyze_attachments(eml_file_path, vt_api_key=None):
    with open(eml_file_path, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    attachments_data = []

    for part in msg.walk():
        filename = part.get_filename()

        if filename:
            file_payload = part.get_payload(decode=True)

            if file_payload:
                sha256_hash = hashlib.sha256(file_payload).hexdigest()
                md5_hash = hashlib.md5(file_payload).hexdigest()

                vt_results = check_virustotal(sha256_hash, vt_api_key)

                attachments_data.append({
                    "filename": filename,
                    "size_bytes": len(file_payload),
                    "md5": md5_hash,
                    "sha256": sha256_hash,
                    "mime_type": part.get_content_type(),
                    "virustotal_scan": vt_results
                })

    return {"attachments": attachments_data}
