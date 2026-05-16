import os
import requests
import json
import urllib.parse

# -------------------------------------------------------------------
# EXTERNAL THREAT INTELLIGENCE CONFIGURATION
# -------------------------------------------------------------------
# Pulls API keys securely from Environment Variables (e.g. Render Dashboard).
# If not deployed, falls back to the placeholders.
GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get("GOOGLE_API_KEY", "PLACEHOLDER_KEY_GOOGLE")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "PLACEHOLDER_KEY_VIRUSTOTAL")
# -------------------------------------------------------------------

def check_google_safe_browsing(url):
    """
    Checks the URL against Google Safe Browsing API.
    """
    if GOOGLE_SAFE_BROWSING_API_KEY == "PLACEHOLDER_KEY_GOOGLE":
        return {"status": "skipped", "message": "Google API key not configured."}
        
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
    payload = {
        "client": {
            "clientId": "phishguard-ai",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }
    
    try:
        response = requests.post(endpoint, json=payload, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data and 'matches' in data:
                return {"status": "danger", "message": "Google Safe Browsing: URL is flagged as malicious."}
            return {"status": "safe", "message": "Google Safe Browsing: No threats found."}
    except Exception as e:
        return {"status": "error", "message": f"API Error: {str(e)}"}
        
    return {"status": "error", "message": "Invalid response from API."}

def check_virustotal(url):
    """
    Checks the URL against VirusTotal API v3.
    """
    if VIRUSTOTAL_API_KEY == "PLACEHOLDER_KEY_VIRUSTOTAL":
        return {"status": "skipped", "message": "VirusTotal API key not configured."}
        
    url_id = urllib.parse.quote_plus(url).replace('%', '') # Simplistic URL to ID conversion for VT v3
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    
    try:
        response = requests.get(endpoint, headers=headers, timeout=5)
        if response.status_code == 200:
            stats = response.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            
            if malicious > 0 or suspicious > 0:
                return {"status": "danger", "message": f"VirusTotal: Flagged by {malicious} security vendors."}
            return {"status": "safe", "message": "VirusTotal: Clean."}
    except Exception as e:
        return {"status": "error", "message": f"API Error: {str(e)}"}
        
    return {"status": "error", "message": "Invalid response from API."}

def run_external_checks(url):
    """
    Runs all configured external threat checks and returns an aggregate intelligence report.
    """
    results = {
        "google": check_google_safe_browsing(url),
        "virustotal": check_virustotal(url)
    }
    
    # Calculate aggregate verdict
    is_danger = any(res['status'] == 'danger' for res in results.values())
    is_safe = all(res['status'] == 'safe' or res['status'] == 'skipped' for res in results.values())
    
    if is_danger:
        aggregate_verdict = "MALICIOUS"
    elif is_safe and not all(res['status'] == 'skipped' for res in results.values()):
        aggregate_verdict = "CLEAN"
    else:
        aggregate_verdict = "PENDING_API_CONFIG"
        
    return {
        "aggregate_verdict": aggregate_verdict,
        "details": results
    }
