import os
import requests
import traceback
import ssl
import socket
from collections import Counter
import math

from flask import (
    Flask,
    request,
    render_template,
    redirect,
    url_for,
    jsonify
)
import numpy as np
import pickle
from urllib.parse import urlparse
import webbrowser
from threading import Timer
import ipaddress
import tldextract
import re
from cachetools import TTLCache, cached
import whois
from datetime import datetime, timezone
import csv
import logging
from difflib import SequenceMatcher

from feature import FeatureExtraction

app = Flask(__name__)

# Config (tunable via environment variables)
REDIRECT_HOP_THRESHOLD = int(os.getenv("REDIRECT_HOP_THRESHOLD", "4"))
ENTROPY_THRESHOLD = float(os.getenv("ENTROPY_THRESHOLD", "5.5"))
SSL_AGE_DAYS_THRESHOLD = int(os.getenv("SSL_AGE_DAYS_THRESHOLD", "30"))
VERY_OLD_DOMAIN_YEARS = int(os.getenv("VERY_OLD_DOMAIN_YEARS", "5"))
FALLBACK_TRUST_YEARS = int(os.getenv("FALLBACK_TRUST_YEARS", "3"))
WHOIS_IP_YOUNG_DAYS = int(os.getenv("WHOIS_IP_YOUNG_DAYS", "180"))
WHOIS_IP_SIMILARITY_THRESHOLD = float(os.getenv("WHOIS_IP_SIMILARITY_THRESHOLD", "0.45"))
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "5"))
COUNT_REDIRECTS_MAX_HOPS = int(os.getenv("COUNT_REDIRECTS_MAX_HOPS", "20"))

# Trust / ML thresholds (tunable)
TRUSTED_ISSUERS = os.getenv("TRUSTED_ISSUERS", "Let's Encrypt,Amazon,Cloudflare,Google").split(",")
TRUSTED_ISSUERS = [t.strip().lower() for t in TRUSTED_ISSUERS if t.strip()]

ML_PHISH_CONF_THRESHOLD = float(os.getenv("ML_PHISH_CONF_THRESHOLD", "0.70"))
ML_CONFIDENCE_GAP = float(os.getenv("ML_CONFIDENCE_GAP", "0.10"))

# Final-fallback tunables 
SAFE_AUTO_TRUST_THRESHOLD = float(os.getenv("SAFE_AUTO_TRUST_THRESHOLD", "0.65"))
SAFE_AUTO_TRUST_GAP = float(os.getenv("SAFE_AUTO_TRUST_GAP", "0.10"))
DEFAULT_FALLBACK_SCORE = float(os.getenv("DEFAULT_FALLBACK_SCORE", "0.30"))

# Configure logging
logging.basicConfig(level=os.getenv("APP_LOG_LEVEL", "INFO"), format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# Load your trained ML model (pickle) 
with open('pickle/model.pkl', 'rb') as f:
    model = pickle.load(f)

# Diagnostic log of model classes
try:
    logger.debug("Model classes_: %s", getattr(model, "classes_", None))
except Exception:
    logger.debug("Model classes_ not available")

# WHOIS TTL CACHE (24h) 
whois_cache = TTLCache(maxsize=1000, ttl=86400)

@cached(whois_cache)
def fetch_creation_date(domain: str):
    try:
        w = whois.whois(domain)
        cd = w.creation_date
        if isinstance(cd, list):
            cd = cd[0]
        return cd
    except Exception as e:
        logger.debug("fetch_creation_date(%s) failed: %s", domain, e)
        return None

#  Utilities 
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((cnt/length) * math.log2(cnt/length) for cnt in counts.values())

def normalized_string(s: str) -> str:
    if not s:
        return ""
    s = s.lower()
    s = re.sub(r"[^a-z0-9\s]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s

def similarity_score(a: str, b: str) -> float:
    try:
        a_n = normalized_string(a)
        b_n = normalized_string(b)
        if not a_n or not b_n:
            return 0.0
        return SequenceMatcher(None, a_n, b_n).ratio()
    except Exception as e:
        logger.debug("similarity_score error: %s", e)
        return 0.0

# Networking helpers 
def resolve_hostname_ips(hostname: str) -> list:
    try:
        infos = socket.getaddrinfo(hostname, None)
        ips = []
        for info in infos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
        return ips
    except Exception as e:
        logger.debug("resolve_hostname_ips(%s) error: %s", hostname, e)
        return []

def get_ip_owner(ip: str) -> str:
    try:
        url = f"https://rdap.org/ip/{ip}"
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            return ""
        j = resp.json()
        owner = ""
        network = j.get("network") or {}
        owner = network.get("name") or ""
        if not owner:
            ents = j.get("entities", []) or []
            for e in ents:
                v = e.get("vcardArray")
                if v and isinstance(v, list) and len(v) > 1:
                    for entry in v[1]:
                        if len(entry) >= 4 and entry[0].lower() in ("org", "fn", "n"):
                            owner = entry[3]
                            break
                if owner:
                    break
        return (owner or "").strip().lower()
    except Exception as e:
        logger.debug("get_ip_owner(%s) error: %s", ip, e)
        return ""

def whois_registrar_org(domain: str) -> str:
    try:
        w = whois.whois(domain)
        candidates = []
        if isinstance(w, dict):
            candidates.extend([w.get("org"), w.get("registrar"), w.get("name")])
        else:
            for attr in ("org", "registrar", "name", "owner"):
                val = getattr(w, attr, None)
                if val:
                    candidates.append(val)
        for c in candidates:
            if not c:
                continue
            if isinstance(c, list):
                c = c[0]
            if c:
                return str(c).strip().lower()
        return ""
    except Exception as e:
        logger.debug("whois_registrar_org(%s) error: %s", domain, e)
        return ""

# Robust redirect hop counter 
def count_redirects(url: str, max_hops: int = COUNT_REDIRECTS_MAX_HOPS) -> int:
    
    import time
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/116.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })
    INITIAL_TIMEOUT = max(3, REQUEST_TIMEOUT)
    MAX_RETRIES = 3
    BACKOFF_FACTOR = 1.5

    try:
        for method in ("HEAD", "GET"):
            hops = 0
            visited = set()
            current = url
            while hops < max_hops:
                timeout = INITIAL_TIMEOUT
                resp = None
                last_exc = None
                for attempt in range(1, MAX_RETRIES + 1):
                    try:
                        resp = session.request(method, current, allow_redirects=False, timeout=timeout)
                        last_exc = None
                        break
                    except requests.exceptions.ReadTimeout as e:
                        last_exc = e
                        time.sleep(timeout * (BACKOFF_FACTOR ** (attempt - 1)))
                        timeout = min(timeout * BACKOFF_FACTOR, 30)
                        continue
                    except Exception as e:
                        last_exc = e
                        break
                if resp is None:
                    if last_exc is not None:
                        logger.debug("count_redirects: %s no response for %s: %s", method, current, last_exc)
                    break
                status = resp.status_code
                if 500 <= status < 600 and method == "HEAD":
                    try:
                        resp2 = session.get(current, allow_redirects=False, timeout=min(20, INITIAL_TIMEOUT * 2))
                        logger.debug("count_redirects: HEAD retry GET status %s for %s", resp2.status_code, current)
                        resp = resp2
                        status = resp.status_code
                    except Exception as e:
                        logger.debug("count_redirects: HEAD->GET retry failed for %s: %s", current, e)
                        break
                if 300 <= status < 400:
                    loc = resp.headers.get("location")
                    logger.debug("count_redirects: %s saw %s -> %s (current=%s)", method, status, loc, current)
                    if not loc:
                        break
                    next_url = requests.compat.urljoin(current, loc)
                    if next_url in visited:
                        logger.debug("count_redirects: loop detected at %s", next_url)
                        break
                    visited.add(next_url)
                    hops += 1
                    current = next_url
                    continue
                logger.debug("count_redirects: %s got non-3xx status=%s for %s", method, status, current)
                break
            if hops > 0:
                logger.debug("count_redirects: url=%s method=%s hops=%s", url, method, hops)
                return hops
        try:
            resp = session.get(url, allow_redirects=True, timeout=30)
            hist = len(resp.history)
            logger.debug("count_redirects: fallback allow_redirects=True history=%s final_status=%s", hist, resp.status_code)
            return hist
        except Exception as e:
            logger.debug("count_redirects: fallback GET error for %s: %s", url, e)
            return 0
    except Exception as e:
        logger.debug("count_redirects unexpected error for %s: %s", url, e)
        return 0

# Fetch certificate info (age + issuer + expiry) 
def fetch_cert_info(domain: str, port: int = 443) -> tuple:
    
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=domain) as sock:
            sock.settimeout(REQUEST_TIMEOUT)
            sock.connect((domain, port))
            cert = sock.getpeercert()
        not_before = cert.get("notBefore")
        not_after = cert.get("notAfter")
        if not not_before:
            age = -1
        else:
            try:
                dt_obj = datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')
                age = (datetime.now(timezone.utc).replace(tzinfo=None) - dt_obj.replace(tzinfo=None)).days
            except Exception:
                age = -1
        is_expired = False
        if not_after:
            try:
                dt_after = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                is_expired = datetime.now(timezone.utc).replace(tzinfo=None) > dt_after.replace(tzinfo=None)
            except Exception:
                is_expired = False
        issuer = ""
        raw_issuer = cert.get("issuer")
        try:
            parts = []
            if raw_issuer and isinstance(raw_issuer, (list, tuple)):
                for r in raw_issuer:
                    if isinstance(r, (list, tuple)):
                        for item in r:
                            if isinstance(item, (list, tuple)) and len(item) >= 2:
                                parts.append(item[1])
                            elif isinstance(item, str):
                                parts.append(item)
            issuer = " ".join([p for p in parts if p])
        except Exception:
            issuer = ""
        issuer = (issuer or "").strip().lower()
        return int(age), issuer, bool(is_expired)
    except Exception as e:
        logger.debug("fetch_cert_info error for %s: %s", domain, e)
        return -1, "fetch_failed_or_untrusted", False

# Feedback CSV setup 
FEEDBACK_FILE = 'feedback.csv'
if not os.path.exists(FEEDBACK_FILE):
    with open(FEEDBACK_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['timestamp','url','model_score','user_feedback'])

# /feedback endpoint 
@app.route('/feedback', methods=['POST'])
def feedback():
    """Capture user feedback and redirect back with a flag."""
    try:
        url = request.form['url']
        score = request.form['score']
        user_fb = request.form['feedback']
        ts = datetime.now().isoformat()
        with open(FEEDBACK_FILE, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([ts, url, score, user_fb])
        return redirect(url_for('index', feedback=user_fb))
    except Exception:
        return render_template(
            'index.html',
            url=None,
            xx=-1,
            alert_message="Could not record feedback. Please try again.",
            alert_class='alert-error'
        )

# /cache/whois endpoint
@app.route('/cache/whois', methods=['GET'])
def view_whois_cache():
    """Return cached WHOIS creation dates (read-only)."""
    output = {}
    for key, cd in whois_cache.items():
        if isinstance(key, str):
            domain = key
        elif hasattr(key, 'args') and key.args:
            domain = key.args[0]
        else:
            domain = str(key)
        output[domain] = cd.isoformat() if isinstance(cd, datetime) else None
    return jsonify(output)

LAST_EXPLAIN = {}

# Core analysis pipeline
def run_definitive_analysis(url):
    """
    Main pipeline:
    - Returns numeric score in same way as original contract.
    - Populates LAST_EXPLAIN with heuristic and supporting details for UI explainability.
    """
    global LAST_EXPLAIN
    LAST_EXPLAIN = {"url": url, "heuristic": None, "details": {}}

    # Parse URL and components
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname or ""
        ext = tldextract.extract(url)
        reg_dom = getattr(ext, 'top_domain_under_public_suffix', getattr(ext, 'registered_domain', '')).lower()
        domain = ext.domain.lower()
    except Exception as e:
        LAST_EXPLAIN["heuristic"] = "malformed"
        LAST_EXPLAIN["details"] = {"error": str(e)}
        return 0.0  # malformed => unsafe
    
    # --- VIP FAST LANE START ---
    c_age, c_iss, c_exp = fetch_cert_info(hostname)
    if not c_exp and c_iss and c_iss != "fetch_failed_or_untrusted":
        # Dictionary tying the issuer to their official domains
        trusted_brands = {
            "amazon": ["amazon.com", "amazon.in", "aws.amazon.com"],
            "google": ["google.com", "google.co.in", "youtube.com"],
            "microsoft": ["microsoft.com", "live.com", "office.com"],
            "apple": ["apple.com", "icloud.com"]
        }
        
        for brand, official_domains in trusted_brands.items():
            # If the brand issued the cert AND the domain is officially theirs
            if brand in c_iss and reg_dom in official_domains:
                LAST_EXPLAIN.update({"heuristic": "vip_allowlist", "details": {"cert_issuer": c_iss, "note": "Verified Enterprise Domain & Cert"}})
                return 0.99  # 99% Safe bypass!
    # --- VIP FAST LANE END ---

    # 0) Basic quick fails
    if parsed.username or parsed.password:
        LAST_EXPLAIN["heuristic"] = "embedded_credentials"
        return 0.01
    if scheme != "https":
        LAST_EXPLAIN["heuristic"] = "non_https"
        return 0.01

    # 1) Trusted TLD
    if ext.suffix in {"gov", "edu", "mil", "int"}:
        LAST_EXPLAIN["heuristic"] = "trusted_tld"
        return 0.98

    # 2) Suspicious TLDs / free hosts
    suspicious_tlds = {"xyz","ml","cf","ga","gq","tk","vu","top","fun","shop","info","biz"}
    free_hosts = {
        "000webhostapp.com","wcomhost.com","godaddysites.com",
        "weebly.com","workers.dev","repl.co","pages.dev",
        "atwebpages.com","myshopify.com","125mb.com"
    }
    if ext.suffix in suspicious_tlds or any(hostname.endswith(fh) for fh in free_hosts):
        LAST_EXPLAIN["heuristic"] = "suspicious_tld_or_free_host"
        LAST_EXPLAIN["details"]["tld"] = ext.suffix
        return 0.09

    # 3) Very-old-domain branch 
    cd = fetch_creation_date(reg_dom)
    if cd:
        age_days = (datetime.now() - cd.replace(tzinfo=None)).days
        if age_days > VERY_OLD_DOMAIN_YEARS * 365:
            # a) Redirect-chain check
            hops_inner = count_redirects(url, max_hops=COUNT_REDIRECTS_MAX_HOPS)
            if hops_inner >= REDIRECT_HOP_THRESHOLD:
                LAST_EXPLAIN["heuristic"] = "very_old_redirects"
                LAST_EXPLAIN["details"]["hops"] = hops_inner
                return 0.14
            # b) Path entropy check
            ent_inner = shannon_entropy(parsed.path or "")
            if ent_inner > ENTROPY_THRESHOLD:
                LAST_EXPLAIN["heuristic"] = "very_old_path_entropy"
                LAST_EXPLAIN["details"]["path_entropy"] = ent_inner
                return 0.13
            # c) SSL certificate info (age, issuer, expiry)
            cert_age, cert_issuer, cert_is_expired = fetch_cert_info(hostname)
            LAST_EXPLAIN["details"]["cert_age_days"] = cert_age
            LAST_EXPLAIN["details"]["cert_issuer"] = cert_issuer
            LAST_EXPLAIN["details"]["cert_is_expired"] = cert_is_expired

            if cert_is_expired:
                LAST_EXPLAIN["heuristic"] = "very_old_ssl_expired"
                LAST_EXPLAIN["details"]["cert_age_days"] = cert_age
                LAST_EXPLAIN["details"]["cert_issuer"] = cert_issuer
                return 0.15

            issuer_trusted = False
            if cert_issuer:
                for t in TRUSTED_ISSUERS:
                    if t and t in cert_issuer:
                        issuer_trusted = True
                        break

            domain_age_days = age_days
            flag_ssl_age = False
            
            if cert_age >= 0 and cert_age < SSL_AGE_DAYS_THRESHOLD: 
                if not issuer_trusted: 
                    flag_ssl_age = True 
            if flag_ssl_age:
                LAST_EXPLAIN["heuristic"] = "very_old_ssl_age_fail"
                LAST_EXPLAIN["details"]["cert_age_days"] = cert_age
                LAST_EXPLAIN["details"]["cert_issuer"] = cert_issuer
                LAST_EXPLAIN["details"]["note"] = "New cert from untrusted issuer on an old domain."
                return 0.15

            try:
                ml_obj = FeatureExtraction(url)
                ml_feats = np.array(ml_obj.get_features_list()).reshape(1, -1)
                ml_probs = model.predict_proba(ml_feats)[0]
                ml_classes = getattr(model, "classes_", None)
                phish_idx = None
                safe_idx = None
                if ml_classes is not None:
                    for i, lab in enumerate(ml_classes):
                        s = str(lab).lower()
                        if s in ("phish", "phishing", "malicious", "1"):
                            phish_idx = i
                        if s in ("safe", "benign", "legit", "0"):
                            safe_idx = i
                if phish_idx is None:
                    phish_idx = 0
                if safe_idx is None:
                    safe_idx = 1 if len(ml_probs) > 1 else 0
                phish_p = float(ml_probs[phish_idx])
                safe_p = float(ml_probs[safe_idx]) if safe_idx < len(ml_probs) else 1.0 - phish_p

                LAST_EXPLAIN["details"]["model_phish_prob"] = phish_p
                LAST_EXPLAIN["details"]["model_safe_prob"] = safe_p

                if (
                    safe_p >= SAFE_AUTO_TRUST_THRESHOLD
                    and (safe_p - phish_p) >= SAFE_AUTO_TRUST_GAP
                    and cert_age is not None
                    and isinstance(cert_age, int)
                    and cert_age >= 0
                    and not cert_is_expired
                    and cert_issuer != "fetch_failed_or_untrusted"
                ):
                    LAST_EXPLAIN["heuristic"] = "very_old_trust"
                    LAST_EXPLAIN["details"]["domain_age_days"] = age_days
                    LAST_EXPLAIN["details"]["model_safe_prob"] = safe_p
                    LAST_EXPLAIN["details"]["model_phish_prob"] = phish_p
                    return 0.95
                else:
                    LAST_EXPLAIN["details"]["note"] = "ml_disagrees_or_cert_untrusted; skipping auto-trust"
                    
            except Exception as e:
                LAST_EXPLAIN["details"]["note"] = f"ml_check_failed: {e}"

    # 4) Instant-fail heuristics and brand checks
    try:
        ipaddress.ip_address(hostname)
        LAST_EXPLAIN["heuristic"] = "raw_ip_hostname"
        return 0.02
    except ValueError:
        pass

    if "xn--" in hostname:
        LAST_EXPLAIN["heuristic"] = "punycode"
        return 0.03

    major_brands = [
        "google","microsoft","apple","facebook","amazon",
        "paypal","netflix","chase","bankofamerica","walmart",
        "yahoo","coinbase"
    ]
    for brand in major_brands:
        if brand in reg_dom:
            if not (
                reg_dom == f"{brand}.com"
                or reg_dom == f"{brand}.{ext.suffix}"
                or reg_dom.endswith(f".{brand}.com")
            ):
                LAST_EXPLAIN["heuristic"] = "brand_impersonation_regdom"
                LAST_EXPLAIN["details"]["brand"] = brand
                return 0.04

    sub = ext.subdomain.lower()
    for brand in major_brands:
        if brand in sub and brand not in reg_dom:
            LAST_EXPLAIN["heuristic"] = "brand_in_subdomain"
            LAST_EXPLAIN["details"]["brand"] = brand
            return 0.05

    if domain and domain[0].isdigit():
        LAST_EXPLAIN["heuristic"] = "digit_start_domain"
        return 0.06

    if hostname:
        digit_ratio = sum(c.isdigit() for c in hostname) / len(hostname)
        if digit_ratio > 0.4:
            LAST_EXPLAIN["heuristic"] = "digit_heavy_hostname"
            LAST_EXPLAIN["details"]["digit_ratio"] = digit_ratio
            return 0.07

    if re.search(r"(.)\1{5,}", hostname):
        LAST_EXPLAIN["heuristic"] = "repeated_chars"
        return 0.08

    # 5) Path entropy and brand-in-path checks
    def _filter_query_and_segments(parsed):
        TRACKING_KEYS = {"utm_source","utm_medium","utm_campaign","utm_term","utm_content","ref","fbclid","gclid","_ga"}
        path_only = parsed.path or ""
        q = parsed.query or ""
        if q:
            try:
                from urllib.parse import parse_qsl, urlencode
                pairs = [(k, v) for k, v in parse_qsl(q, keep_blank_values=True) if k not in TRACKING_KEYS]
                cleaned_q = urlencode(pairs)
            except Exception:
                cleaned_q = ""
        else:
            cleaned_q = ""
        combined = path_only
        if cleaned_q:
            combined = path_only + "?" + cleaned_q
        return combined, path_only

    combined_path, path_only = _filter_query_and_segments(parsed)

    segments = [seg for seg in (path_only.split("/") if path_only else []) if seg]
    if not segments:
        ent = shannon_entropy(combined_path)
        if ent > ENTROPY_THRESHOLD:
            LAST_EXPLAIN["heuristic"] = "path_entropy"
            LAST_EXPLAIN["details"]["path_entropy"] = ent
            return 0.13
    else:
        high_segment = None
        for seg in segments:
            seg_ent = shannon_entropy(seg)
            norm = seg_ent / max(1, len(seg))
            if seg_ent > ENTROPY_THRESHOLD or norm > 0.5:
                high_segment = (seg, seg_ent, norm)
                break
        if high_segment:
            LAST_EXPLAIN["heuristic"] = "path_entropy"
            LAST_EXPLAIN["details"]["path_entropy"] = high_segment[1]
            LAST_EXPLAIN["details"]["path_entropy_segment"] = high_segment[0]
            LAST_EXPLAIN["details"]["path_entropy_normalized"] = high_segment[2]
            return 0.13

    path_q = (parsed.path + " " + parsed.query).lower()
    for brand in major_brands:
        if brand in path_q and brand not in reg_dom:
            LAST_EXPLAIN["heuristic"] = "brand_in_path_query"
            LAST_EXPLAIN["details"]["brand"] = brand
            return 0.10

    # 5b) Open Redirector Check
    if parsed.query:
        try:
            from urllib.parse import parse_qs, unquote
            q_params = parse_qs(parsed.query)
            for key, values in q_params.items():
                for val in values:
                    unquoted_val = unquote(val).lower()
                    if unquoted_val.startswith("http://") or unquoted_val.startswith("https://"):
                        LAST_EXPLAIN["heuristic"] = "open_redirector"
                        LAST_EXPLAIN["details"]["key"] = key
                        LAST_EXPLAIN["details"]["value"] = unquoted_val
                        return 0.11 # Return a new unsafe score
        except Exception as e:
            logger.debug("Open redirector check failed: %s", e)

    # 6) Redirect-chain general check
    hops = count_redirects(url, max_hops=COUNT_REDIRECTS_MAX_HOPS)
    if hops >= REDIRECT_HOP_THRESHOLD:
        LAST_EXPLAIN["heuristic"] = "redirect_chain"
        LAST_EXPLAIN["details"]["hops"] = hops
        return 0.14

    # 7) General SSL check (age, issuer, expiry)
    cert_age, cert_issuer, cert_is_expired = fetch_cert_info(hostname)
    LAST_EXPLAIN["details"]["cert_age_days"] = cert_age
    LAST_EXPLAIN["details"]["cert_issuer"] = cert_issuer
    LAST_EXPLAIN["details"]["cert_is_expired"] = cert_is_expired

    if cert_is_expired or cert_issuer == "fetch_failed_or_untrusted" or cert_age < 0:
        LAST_EXPLAIN["heuristic"] = "ssl_expired"
        LAST_EXPLAIN["details"]["cert_age_days"] = cert_age
        LAST_EXPLAIN["details"]["cert_issuer"] = cert_issuer
        LAST_EXPLAIN["details"]["cert_is_expired"] = True
        return 0.15

    issuer_trusted = False
    if cert_issuer:
        for t in TRUSTED_ISSUERS:
            if t and t in cert_issuer:
                issuer_trusted = True
                break

    domain_age_days = None
    if 'cd' in locals() and cd:
        domain_age_days = (datetime.now() - cd.replace(tzinfo=None)).days

    
    flag_ssl_age = False
    if cert_age >= 0 and cert_age < SSL_AGE_DAYS_THRESHOLD:
        if domain_age_days is None or domain_age_days < (VERY_OLD_DOMAIN_YEARS * 365):
            flag_ssl_age = True

    if flag_ssl_age:
        LAST_EXPLAIN["heuristic"] = "ssl_age"
        LAST_EXPLAIN["details"]["cert_age_days"] = cert_age
        LAST_EXPLAIN["details"]["cert_issuer"] = cert_issuer
        LAST_EXPLAIN["details"]["domain_age_days"] = domain_age_days
        LAST_EXPLAIN["details"]["note"] = "New certificate on a domain that is not long-established."
        return 0.15

    # 8) WHOIS vs IP-owner mismatch (young domains)
    try:
        domain_cd = cd if 'cd' in locals() else fetch_creation_date(reg_dom)
        domain_age_days = None
        if domain_cd:
            domain_age_days = (datetime.now() - domain_cd).days

        consider = domain_age_days is None or domain_age_days <= WHOIS_IP_YOUNG_DAYS

        if consider:
            registrar_org = whois_registrar_org(reg_dom)
            ips = resolve_hostname_ips(hostname)
            ip_owners = []
            for ip in ips:
                owner = get_ip_owner(ip)
                if owner:
                    ip_owners.append(owner)

            if registrar_org and ip_owners:
                match_found = False
                for owner in ip_owners:
                    sim = similarity_score(registrar_org, owner)
                    logger.debug("whois-ip compare: registrar='%s' owner='%s' sim=%.2f", registrar_org, owner, sim)
                    if sim >= WHOIS_IP_SIMILARITY_THRESHOLD:
                        match_found = True
                        break

                if not match_found:
                    LAST_EXPLAIN["heuristic"] = "whois_ip_mismatch"
                    LAST_EXPLAIN["details"]["registrar_org"] = registrar_org
                    LAST_EXPLAIN["details"]["ip_owners"] = ip_owners
                    LAST_EXPLAIN["details"]["domain_age_days"] = domain_age_days
                    return 0.16
    except Exception as e:
        logger.debug("whois-ip heuristic error: %s", e)

    obj = FeatureExtraction(url)
    feats = np.array(obj.get_features_list()).reshape(1, -1)
    try:
        probs = model.predict_proba(feats)[0]
        classes = getattr(model, "classes_", [0, 1]) 

        phish_idx = 0
        safe_idx = 1
        
        if len(classes) > 1 and str(classes[0]) == "1":
            phish_idx = 1
            safe_idx = 0
        
        phish_p = float(probs[phish_idx])
        safe_p = float(probs[safe_idx])

        LAST_EXPLAIN["details"]["model_phish_prob"] = phish_p
        LAST_EXPLAIN["details"]["model_safe_prob"] = safe_p
        
        if phish_p > ML_PHISH_CONF_THRESHOLD and (phish_p - safe_p) >= ML_CONFIDENCE_GAP:
            LAST_EXPLAIN["heuristic"] = "ml_phish_confident"
            return 0.12
    except Exception as e:
        logger.debug("model predict_proba fallback: %s", e)
        try:
            pred = model.predict(feats)[0]
            LAST_EXPLAIN["details"]["model_pred"] = int(pred)
            
            if int(pred) == 0: 
                LAST_EXPLAIN["heuristic"] = "ml_predict_phish"
                return 0.12
        except Exception as ee:
            logger.debug("model predict fallback error: %s", ee)
    try:
        s = requests.Session()
        s.headers.update({"User-Agent": "Mozilla/5.0 (compatible)"})
        resp = s.get(url, allow_redirects=True, timeout=min(10, REQUEST_TIMEOUT * 2))
        final_url = resp.url if resp is not None else None
        if final_url and final_url != url:
            final_ext = tldextract.extract(final_url)
            final_reg = final_ext.registered_domain.lower() if final_ext.registered_domain else ""
            if final_reg and final_reg != reg_dom:
                LAST_EXPLAIN["heuristic"] = "redirect_to_different_regdom"
                LAST_EXPLAIN["details"]["original_regdom"] = reg_dom
                LAST_EXPLAIN["details"]["final_url"] = final_url
                LAST_EXPLAIN["details"]["final_regdom"] = final_reg
                return 0.14
    except Exception as e:
        logger.debug("final-redirect check failed: %s", e)

    if (
        "model_safe_prob" in LAST_EXPLAIN["details"]
        and "model_phish_prob" in LAST_EXPLAIN["details"]
    ):
        safe_p = LAST_EXPLAIN["details"]["model_safe_prob"]
        phish_p = LAST_EXPLAIN["details"]["model_phish_prob"]
        if (
            safe_p >= SAFE_AUTO_TRUST_THRESHOLD
            and (safe_p - phish_p) >= SAFE_AUTO_TRUST_GAP
        ):
            LAST_EXPLAIN["heuristic"] = "ml_safe_fallback"
            LAST_EXPLAIN["details"]["note"] = "No unsafe signals; trusting ML prediction."
            return 0.85 

    LAST_EXPLAIN["heuristic"] = "default_fallback"
    LAST_EXPLAIN["details"]["note"] = "no_strong_signals; conservative fallback"
    return DEFAULT_FALLBACK_SCORE

@app.route("/", methods=["GET", "POST"])
def index():
    """
    Main route:
    - GET: show welcome banner
    - POST: run analysis and render index.html with url, xx (score), and explain
    """
    fb = request.args.get('feedback')
    if fb == 'safe':
        alert_message = 'Reported Safe'
        alert_class = 'alert-safe'
    elif fb == 'phish':
        alert_message = 'Reported Phishing'
        alert_class = 'alert-phish'
    else:
        if request.method == 'GET':
            alert_message = 'Welcome to Phishing Detector'
            alert_class = 'alert-welcome'
        else:
            alert_message = None
            alert_class = None

    url = None
    score = -1
    if request.method == "POST":
        url = request.form.get("url")
        score = run_definitive_analysis(url)

    return render_template(
        "index.html",
        url=url,
        xx=score,
        alert_message=alert_message,
        alert_class=alert_class,
        explain=LAST_EXPLAIN
    )

@app.route("/explain/last", methods=["GET"])
def explain_last():
    """Return LAST_EXPLAIN for the most recent analysis (useful for UI/console)."""
    return jsonify(LAST_EXPLAIN)

@app.errorhandler(404)
def handle_404(e):
    return render_template(
        "index.html",
        url=None,
        xx=-1,
        alert_message="Page not found.",
        alert_class='alert-error'
    ), 404

@app.errorhandler(Exception)
def handle_exception(e):
    traceback.print_exc() 
    
    logger.error("Unhandled exception: %s", e) 
    
    return render_template(
        "index.html",
        url=None,
        xx=-1,
        alert_message="An unexpected error occurred.",
        alert_class='alert-error'
    ), 500

def open_browser():
    webbrowser.open_new("http://127.0.0.1:5000/")

if __name__ == "__main__":
    if not os.environ.get("WERKZEUG_RUN_MAIN"):
        Timer(1, open_browser).start()
    app.run(debug=True)