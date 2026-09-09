import email
from email import policy
import hashlib
import json
import urllib.request
import urllib.error
import redis
import os
try:
    import magic
except ImportError:
    magic = None
from dotenv import load_dotenv
from pathlib import Path
from typing import Iterable

env_path = Path(__file__).resolve().parents[0] / ".env"
load_dotenv(dotenv_path=env_path)

REDIS_URL = os.getenv("REDIS_URL", "NOT_FOUND")
cache_db = None

if REDIS_URL and REDIS_URL != "NOT_FOUND":
    try:
        cache_db = redis.Redis.from_url(
            REDIS_URL,
            decode_responses=True,
            socket_timeout=5,
        )
        cache_db.ping()
    except redis.RedisError as e:
        print("Redis connection error: ", e)
        cache_db = None

def get_cached_intel(sha256_hash):
    if not cache_db:
        return None
    try:
        cached_intel = cache_db.get(f"vt:{sha256_hash}")
        if cached_intel:
            return json.loads(cached_intel)
    except Exception:
        pass
    return None

def set_cached_intel(sha256_hash, data, ttl_seconds=604800):
    if not cache_db:
        return
    try:
        cache_db.setex(f"vt:{sha256_hash}", ttl_seconds, json.dumps(data))
    except Exception:
        pass

def check_virustotal(sha256_hash, api_key):
    cached = get_cached_intel(sha256_hash)
    if cached:
        return cached

    if not api_key or api_key == "NOT_FOUND":
        return {"status": "Mocked (No API Key)"}

    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {"x-apikey": api_key}

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read())
            stats = data['data']['attributes']['last_analysis_stats']
            result = {
                "malicious": stats.get('malicious', 0),
                "undetected": stats.get('undetected', 0),
                "status": "Found in VT"
            }
            set_cached_intel(sha256_hash, result)
            return result
    except urllib.error.HTTPError as e:
        if e.code == 404:
            result = {"malicious": 0, "undetected": 0, "status": "File never seen by VT"}
            set_cached_intel(sha256_hash, result, ttl_seconds=3600)
            return result
        return {"error": f"HTTP {e.code}"}
    except Exception as e:
        return {"error": "VT Connection Failed"}

def evaluate_magic_bytes(filename, data):
    if not data:
        return {"magic_type": "Empty File", "risk": "None"}

    if magic is None:
        return {"magic_type": "Unavailable (libmagic not installed)", "risk": "Unknown"}

    magic_type = magic.from_buffer(data[:2048])
    risk = "Low"

    if "ISO 9660" in magic_type or filename.lower().endswith(('.iso', '.vhd', '.img')):
        risk = "High (Container Smuggling / MotW Bypass)"
    elif "PE32" in magic_type or "executable" in magic_type.lower():
        risk = "Critical (Executable Payload)"
    elif "script" in magic_type.lower() or filename.lower().endswith(('.vbs', '.js', '.wsf', '.ps1')):
        risk = "High (Script Payload)"
    elif "Microsoft Word" in magic_type or "Excel" in magic_type or filename.lower().endswith(('.docm', '.xlsm', '.xlsb')):
        risk = "High (Macro-Enabled Document)"
    elif "Zip archive" in magic_type or "RAR archive" in magic_type:
        risk = "Medium (Archive Extraction Required)"

    return {"magic_type": magic_type, "risk": risk}

def analyze_attachment_parts(parts: Iterable[tuple[str, str, bytes]], vt_api_key=None):
    attachments_data = []

    for filename, mime_type, file_payload in parts:
        payload = bytes(file_payload)
        sha256_hash = hashlib.sha256(payload).hexdigest()
        md5_hash = hashlib.md5(payload).hexdigest()
        vt_results = check_virustotal(sha256_hash, vt_api_key)
        magic_verdict = evaluate_magic_bytes(filename, payload)

        attachments_data.append({
            "filename": filename,
            "size_bytes": len(payload),
            "md5": md5_hash,
            "sha256": sha256_hash,
            "mime_type": mime_type,
            "magic_type": magic_verdict["magic_type"],
            "risk": magic_verdict["risk"],
            "virustotal_scan": vt_results
        })

    return {"attachments": attachments_data}
