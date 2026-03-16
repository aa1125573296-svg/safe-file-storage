import hashlib
import requests

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def calculate_vt_risk(vt_status: str, stats: dict | None) -> str:
    if vt_status == "ok":
        malicious = int(stats.get("malicious", 0)) if stats else 0
        suspicious = int(stats.get("suspicious", 0)) if stats else 0

        if malicious > 0:
            return "HIGH"
        if suspicious > 0:
            return "MEDIUM"
        return "LOW"

    if vt_status == "not_found":
        return "UNKNOWN"

    
    return "UNKNOWN"


def yara_scan_stub(data: bytes) -> bool:
    suspicious_keywords = [
        b"powershell",
        b"cmd.exe",
        b"base64",
        b"wget",
        b"curl",
        b"invoke-expression"
    ]

    lowered = data.lower()
    for keyword in suspicious_keywords:
        if keyword in lowered:
            return True

    return False


def vt_check_hash(sha256: str, api_key: str) -> dict:
    """
    Returns:
      status: skipped | not_found | ok | error
      stats: {malicious, suspicious, harmless, undetected}
    """
    if not api_key:
        return {"status": "skipped", "stats": None, "timeout": False}

    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": api_key}

    try:
        r = requests.get(url, headers=headers, timeout=15)
    except requests.Timeout:
        return {"status": "error", "stats": None, "timeout": True}
    except requests.RequestException:
        return {"status": "error", "stats": None, "timeout": False}

    if r.status_code == 404:
        return {"status": "not_found", "stats": None, "timeout": False}

    if not r.ok:
        return {"status": "error", "stats": None, "timeout": False}

    data = r.json()
    stats = data["data"]["attributes"]["last_analysis_stats"]
    return {"status": "ok", "stats": stats, "timeout": False}


def yara_stub_scan(_data: bytes) -> dict:
    return {"status": "disabled", "matches": []}
