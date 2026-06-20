"""
osint.py — OSINT IP Enrichment
Fast parallel enrichment using ThreadPoolExecutor.
Private IPs are always skipped.
"""

import requests
import concurrent.futures
from filters import is_private_ip


# ── Geolocation — ip-api.com (free) ──────────────────────────
def get_ip_geo_intel(ip: str, timeout: int = 4) -> dict:
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,countryCode,regionName,city,isp,org,as,hosting"},
            timeout=timeout,
        )
        data = resp.json()
        if data.get("status") == "success":
            return {
                "country":      data.get("country", "Unknown"),
                "country_code": data.get("countryCode", ""),
                "region":       data.get("regionName", ""),
                "city":         data.get("city", ""),
                "isp":          data.get("isp", ""),
                "org":          data.get("org", ""),
                "asn":          data.get("as", ""),
                "hosting":      data.get("hosting", False),
            }
    except Exception:
        pass
    return {"country": "Unknown", "city": "", "isp": "", "asn": "", "hosting": False}


# ── AbuseIPDB ─────────────────────────────────────────────────
def _fetch_abuseipdb(ip: str, api_key: str, timeout: int = 4) -> dict:
    if not api_key:
        return {}
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=timeout,
        )
        data = resp.json().get("data", {})
        return {
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "reports":     data.get("totalReports", 0),
            "usage_type":  data.get("usageType", ""),
        }
    except Exception:
        return {}


# ── VirusTotal ────────────────────────────────────────────────
def _fetch_virustotal_ip(ip: str, api_key: str, timeout: int = 4) -> dict:
    if not api_key:
        return {}
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": api_key},
            timeout=timeout,
        )
        data      = resp.json().get("data", {}).get("attributes", {})
        stats     = data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        return {
            "vt_reputation": data.get("reputation", 0),
            "vt_malicious":  malicious,
            "abuse_score":   min(100, malicious * 10),   # convert to 0-100 scale
        }
    except Exception:
        return {}


# ── Enrich ONE IP (all sources) ───────────────────────────────
def _enrich_single(ip: str, abuseipdb_key: str, vt_key: str, timeout: int) -> dict:
    """Enrich a single public IP with geo + reputation. Runs in thread."""
    entry = {"ip": ip}

    # Geolocation always
    geo = get_ip_geo_intel(ip, timeout=timeout)
    entry.update(geo)

    # AbuseIPDB first, VT as fallback
    if abuseipdb_key:
        abuse = _fetch_abuseipdb(ip, abuseipdb_key, timeout=timeout)
        if abuse:
            entry.update(abuse)

    if vt_key and entry.get("abuse_score") is None:
        vt = _fetch_virustotal_ip(ip, vt_key, timeout=timeout)
        if vt:
            entry.update(vt)

    # Malicious flag
    score = entry.get("abuse_score") or 0
    vt_m  = entry.get("vt_malicious") or 0
    entry["is_malicious_ip"] = (score >= 50 or vt_m >= 3)

    return entry


# ── MAIN: parallel enrichment ─────────────────────────────────
def enrich_ip_list(
    ip_list:       list,
    abuseipdb_key: str = "",
    vt_key:        str = "",
    timeout:       int = 4,
) -> list:
    """
    Enrich a list of IPs in PARALLEL using threads.
    Skips private IPs. Returns enriched list.

    Old approach: serial → 15 IPs × 3 calls × 4s = up to 180s
    New approach: parallel → all IPs at once → ~4-6s total
    """
    # Filter: only public IPs, deduplicated, capped at 10
    seen = set()
    public = []
    for ip in ip_list:
        ip = ip.strip()
        if ip and ip not in seen and not is_private_ip(ip):
            seen.add(ip)
            public.append(ip)
        if len(public) >= 10:
            break

    if not public:
        return []

    results = []

    # Run all enrichments in parallel — max 10 threads
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(public), 10)) as executor:
        futures = {
            executor.submit(_enrich_single, ip, abuseipdb_key, vt_key, timeout): ip
            for ip in public
        }
        for future in concurrent.futures.as_completed(futures, timeout=timeout + 2):
            try:
                results.append(future.result())
            except Exception:
                ip = futures[future]
                results.append({
                    "ip": ip, "country": "Unknown", "city": "",
                    "isp": "", "asn": "", "hosting": False,
                    "abuse_score": 0, "is_malicious_ip": False,
                })

    # Sort by original order
    order = {ip: i for i, ip in enumerate(public)}
    results.sort(key=lambda x: order.get(x.get("ip", ""), 99))

    return results
