"""
verdict.py — Risk & Confidence Scoring Engine
Two-score system: Risk (capability) + Confidence (intent) → Final Verdict
"""


def calculate_verdict(result: dict) -> dict:
    """
    Calculate final malware verdict using Risk vs. Confidence Matrix.

    RISK SCORE  (0-100): What CAN this app do?
    CONFIDENCE  (0-100): Does it INTEND to be malicious?
    """
    risk = 0
    confidence = 50   # neutral start
    fired_rules = []

    perms      = result.get("permissions", {})
    apis       = result.get("suspicious_apis", [])
    network    = result.get("network_indicators", {})
    strings    = result.get("string_intelligence", {})
    cert       = result.get("certificate", {})
    obfuscation = result.get("obfuscation", {})
    behaviors  = result.get("behaviors", [])
    ips        = result.get("enriched_ips", [])

    critical_perms = perms.get("critical_count", 0)
    high_perms     = perms.get("high_count", 0)
    critical_apis  = sum(1 for a in apis if a.get("risk") == "CRITICAL")
    high_apis      = sum(1 for a in apis if a.get("risk") == "HIGH")

    # ── RISK SCORE RULES ──────────────────────────────────────

    # R1: Critical API calls detected
    if critical_apis >= 1:
        pts = min(30, critical_apis * 10)
        risk += pts
        fired_rules.append({"rule": "R1", "label": f"Critical API calls ({critical_apis})", "impact": f"+{pts}", "type": "risk"})

    # R2: Critical permissions
    if critical_perms >= 1:
        pts = min(25, critical_perms * 8)
        risk += pts
        fired_rules.append({"rule": "R2", "label": f"Critical permissions ({critical_perms})", "impact": f"+{pts}", "type": "risk"})

    # R3: Multiple HIGH risk permissions
    if high_perms >= 3:
        risk += 15
        fired_rules.append({"rule": "R3", "label": f"Multiple HIGH permissions ({high_perms})", "impact": "+15", "type": "risk"})
    elif high_apis >= 2:
        risk += 10
        fired_rules.append({"rule": "R3b", "label": f"Multiple HIGH APIs ({high_apis})", "impact": "+10", "type": "risk"})

    # R4: Hardcoded C2 infrastructure
    hard_ips  = len(network.get("hardcoded_ips", []))
    hard_urls = len(network.get("hardcoded_urls", []))
    if hard_ips >= 1 or hard_urls >= 1:
        risk += 10
        fired_rules.append({"rule": "R4", "label": f"Hardcoded network infra (IPs:{hard_ips}, URLs:{hard_urls})", "impact": "+10", "type": "risk"})

    # R5: Code obfuscation
    if obfuscation.get("likely_obfuscated"):
        risk += 10
        fired_rules.append({"rule": "R5", "label": "Code obfuscation detected", "impact": "+10", "type": "risk"})

    # R6: Dynamic code loading
    dex_loader = any("DexClassLoader" in str(a.get("api","")) for a in apis)
    if dex_loader:
        risk += 10
        fired_rules.append({"rule": "R6", "label": "Dynamic code loading (DexClassLoader)", "impact": "+10", "type": "risk"})

    # R7: Phone numbers (bulk SMS attack potential)
    phones = network.get("phone_numbers", [])
    if len(phones) >= 1:
        risk += 5
        fired_rules.append({"rule": "R7", "label": f"Hardcoded phone numbers ({len(phones)})", "impact": "+5", "type": "risk"})

    # ── CONFIDENCE SCORE RULES ────────────────────────────────

    # C1: Telegram / Discord bot token found (C2 channel)
    tg_tokens = strings.get("telegram_tokens", [])
    if tg_tokens:
        confidence += 30
        fired_rules.append({"rule": "C1", "label": f"Telegram bot token found ({len(tg_tokens)})", "impact": "+30 conf", "type": "confidence"})

    # C2: Suspicious TLDs in URLs
    susp_urls = [u for u in network.get("hardcoded_urls", []) if u.get("suspicious_tld")]
    if susp_urls:
        confidence += 20
        fired_rules.append({"rule": "C2", "label": f"Suspicious TLD URLs found ({len(susp_urls)})", "impact": "+20 conf", "type": "confidence"})

    # C3: Debug certificate
    if cert.get("is_debug"):
        confidence += 20
        fired_rules.append({"rule": "C3", "label": "Debug certificate (not production)", "impact": "+20 conf", "type": "confidence"})

    # C4: Self-signed certificate
    if cert.get("is_self_signed") and not cert.get("is_debug"):
        confidence += 10
        fired_rules.append({"rule": "C4", "label": "Self-signed certificate", "impact": "+10 conf", "type": "confidence"})

    # C5: Known malicious IP (high AbuseIPDB score)
    mal_ips = [ip for ip in ips if ip.get("is_malicious_ip")]
    if mal_ips:
        confidence += 20
        fired_rules.append({"rule": "C5", "label": f"Known malicious IPs ({len(mal_ips)})", "impact": "+20 conf", "type": "confidence"})

    # C6: Hardcoded credentials / API keys
    creds = strings.get("hardcoded_credentials", [])
    if creds:
        confidence += 15
        fired_rules.append({"rule": "C6", "label": f"Hardcoded credentials ({len(creds)})", "impact": "+15 conf", "type": "confidence"})

    # C7: No suspicious network infrastructure → reduce confidence
    if hard_ips == 0 and hard_urls == 0:
        confidence -= 15
        fired_rules.append({"rule": "C7", "label": "No suspicious network infrastructure", "impact": "-15 conf", "type": "confidence_reduce"})

    # C8: Correlated attack behaviors
    if len(behaviors) >= 2:
        confidence += 15
        fired_rules.append({"rule": "C8", "label": f"Multiple correlated attack behaviors ({len(behaviors)})", "impact": "+15 conf", "type": "confidence"})

    # ── CLAMP SCORES ──────────────────────────────────────────
    risk       = max(0, min(100, risk))
    confidence = max(0, min(100, confidence))

    # ── VERDICT LOGIC ─────────────────────────────────────────
    if risk >= 70 and confidence >= 70:
        verdict       = "HIGH RISK — Likely Malicious"
        verdict_short = "MALICIOUS"
        verdict_color = "red"
        verdict_icon  = "🔴"
    elif risk >= 70 and confidence < 70:
        verdict       = "SUSPICIOUS — High Capability, Unclear Intent"
        verdict_short = "SUSPICIOUS"
        verdict_color = "orange"
        verdict_icon  = "🟠"
    elif risk < 70 and confidence >= 70:
        verdict       = "SUSPICIOUS — Low Capability, Suspicious Intent"
        verdict_short = "SUSPICIOUS"
        verdict_color = "orange"
        verdict_icon  = "🟠"
    elif risk >= 40 or confidence >= 60:
        verdict       = "POTENTIALLY UNWANTED — Manual Review Recommended"
        verdict_short = "PUA"
        verdict_color = "yellow"
        verdict_icon  = "🟡"
    else:
        verdict       = "LOW RISK — No Significant Threats Detected"
        verdict_short = "SAFE"
        verdict_color = "green"
        verdict_icon  = "🟢"

    return {
        "risk_score":     risk,
        "confidence":     confidence,
        "verdict":        verdict,
        "verdict_short":  verdict_short,
        "verdict_color":  verdict_color,
        "verdict_icon":   verdict_icon,
        "fired_rules":    fired_rules,
    }


def safe_calculate_verdict(result: dict) -> dict:
    """Wrapper with error handling — returns safe default if calculation fails."""
    try:
        return calculate_verdict(result)
    except Exception as e:
        return {
            "risk_score":    0,
            "confidence":    0,
            "verdict":       "ANALYSIS ERROR",
            "verdict_short": "ERROR",
            "verdict_color": "grey",
            "verdict_icon":  "⚪",
            "fired_rules":   [],
            "error":         str(e),
        }
