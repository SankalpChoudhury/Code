import socket
import re
from urllib.parse import urlparse
import whois
import ssl
from datetime import datetime
import os

def extract_features(url):
    try:
        parsed_url = urlparse(url)
        host = parsed_url.netloc.lower().replace("www.", "")
        if is_trusted_domain(host):
            # Return a perfectly safe profile for known mega-trusted domains
            return [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1]
    except:
        pass

    features = []
    
    # 1. Using IP Address (ip)
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        if not domain:
            domain = url.split('/')[0]
        socket.inet_aton(domain)
        ip = 1
    except:
        ip = 2

    # 2. Long URL (ul)
    if len(url) < 54:
        ul = 1
    elif len(url) >= 54 and len(url) <= 75:
        ul = 0
    else:
        ul = 2

    # 3. Shortening Service (at)
    if "@" in url or "bit.ly" in url or "goo.gl" in url or "tinyurl.com" in url:
        at = 2
    else:
        at = 1

    # 4. Prefix/Suffix (ps)
    if "-" in domain:
        ps = 2
    else:
        ps = 1

    # 5. Sub-domain Count (sd)
    dot_count = domain.count('.')
    if dot_count <= 2:
        sd = 1
    elif dot_count == 3:
        sd = 0
    else:
        sd = 2

    # 6. HTTPS Token (ht)
    if "https" in domain:
        ht = 2
    else:
        ht = 1

    # 7. Request URL (ru)
    ru = 1

    # 8. URL Anchor (ua)
    ua = 1

    # 9. SFH (sfh)
    sfh = 1

    # 10. Abnormal URL (ab)
    # 11. Redirect (re_redir)
    # 12. On Mouseover (mo)
    # 13. Pop Up Window (po)
    # 14. Age of Domain (ad)
    # 15. DNS Record (dns)
    # 16. Web Traffic (wt)
    
    ab, re_redir, mo, po, ad, dns, wt = 1, 0, 1, 1, 1, 1, 1

    try:
        w = whois.whois(domain)
        if not w.domain_name:
            ab = 2
        else:
            ab = 1
        
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            age = (datetime.now() - creation_date).days
            ad = 1 if age > 180 else 2
        else:
            ad = 2
            
        dns = 1
    except:
        # If WHOIS fails, we mark as 'Suspicious' (0) instead of 'Phishing' (2)
        # This prevents safe sites from being blocked just because of a WHOIS timeout
        ab = 0
        ad = 0
        dns = 0

    wt = 1 if dns == 1 else 0

    return [ip, ul, at, ps, sd, ht, ru, ua, sfh, ab, re_redir, mo, po, ad, dns, wt]

def get_ssl_details(url):
    """
    Check SSL certificate validity and issuer.
    Returns: (is_valid, issuer, days_to_expiry)
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                # Extract expiry
                not_after = cert['notAfter']
                expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                days_to_expiry = (expiry_date - datetime.now()).days
                
                # Extract issuer
                issuer = dict(x[0] for x in cert['issuer'])
                common_name = issuer.get('commonName', 'Unknown')
                
                return True, common_name, days_to_expiry
    except Exception:
        return False, "None", 0


def is_trusted_domain(host):
    """
    Check if the host is a known major trusted domain.
    """
    trusted_domains = [
        "flipkart.com", "snapdeal.com", "amazon.in", "amazon.com", "paytm.com",
        "myntra.com", "google.com", "microsoft.com", "apple.com", "facebook.com",
        "instagram.com", "twitter.com", "linkedin.com", "netflix.com", "github.com",
        "flipkart.in", "snapdeal.in", "youtube.com", "youtube.co.in", "gmail.com",
        "drive.google.com", "outlook.com", "live.com", "yahoo.com", "hot.mail", "icloud.com"
    ]
    return any(host == td or host.endswith("." + td) for td in trusted_domains)


def is_official_tld(host):
    """
    Check if the host ends in an official bank or gov TLD.
    """
    official_tlds = (".bank.in", ".bank", ".sbi", ".gov.in", ".gov")
    return any(host.endswith(tld) for tld in official_tlds)


def is_high_risk_phishing_pattern(url):
    """
    Rule-based safety net for obvious phishing patterns and impersonation.
    """
    normalized = (url or "").strip().lower()
    if not normalized:
        return False

    if not normalized.startswith(("http://", "https://")):
        normalized = "http://" + normalized

    try:
        parsed = urlparse(normalized)
    except Exception:
        return True

    host = parsed.netloc.lower().replace("www.", "")
    path = parsed.path.lower()
    full = f"{host}{path}"

    if is_trusted_domain(host) or is_official_tld(host):
        return False

    # Target Keywords for impersonation detection
    brand_keywords = [
        "sbi", "sbicard", "bank", "login", "verify", "account", "secure", 
        "update", "kyc", "card", "payment", "support", "signin",
        "yojna", "yojana", "scheme", "seva", "portal", "registration", "samiti"
    ]
    
    generic_hosts = [
        "wixsite.com", "blogspot.com", "wordpress.com", "github.io", 
        "000webhostapp.com", "firebaseapp.com", "weebly.com"
    ]

    is_generic_host = any(gh in host for gh in generic_hosts)
    if is_generic_host and any(bk in host for bk in brand_keywords):
        return True

    lure_keywords = [
        "free", "scholarship", "tablet", "register", "yojna", "yojana", 
        "apply", "form", "gov", "shree", "pm-", "seva", "samiti", "portal"
    ]
    lure_score = sum(1 for kw in lure_keywords if kw in full)

    risky_tlds = (".online", ".xyz", ".top", ".site", ".club", ".link", ".click")
    has_risky_tld = any(host.endswith(tld) for tld in risky_tlds)
    is_org_in = host.endswith(".org.in")

    looks_official = any(kw in host for kw in ["yojna", "yojana", "pm-", "gov", "seva"])
    
    if looks_official:
        if lure_score >= 1:
            return True
    
    if (has_risky_tld or is_org_in) and lure_score >= 1:
        return True
        
    if host.count("-") >= 2 and lure_score >= 1:
        return True

    return False


def is_high_risk_feature_profile(features, url=None):
    """
    Catch likely phishing based on combined risk signals.
    """
    if not features or len(features) < 16:
        return False

    if url:
        parsed = urlparse(url)
        host = parsed.netloc.lower().replace("www.", "")
        if is_trusted_domain(host) or is_official_tld(host):
            return False

    ab, ad, dns, wt = features[9], features[13], features[14], features[15]

    if ab == 2 and dns == 2 and wt == 2 and ad == 2:
        return True

    return False
