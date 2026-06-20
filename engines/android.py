"""
engines/android.py — Android APK Deep Static Analysis Engine

SPEED APPROACH:
  - APK()  for manifest/cert/permissions (fast - no DEX parsing)
  - Raw DEX bytes read directly (no Androguard DEX parsing at all)
  - Strings extracted using DEX binary format spec (10-50x faster)
  - API detection via raw bytecode pattern matching (instant)
  - No call graph, no DalvikVMFormat, no AnalyzeAPK
  Expected: 5-20 seconds on any APK size
"""

import re
import os
import hashlib
import zipfile
import struct

from filters import (
    is_framework_string, is_private_ip, is_valid_network_url,
    has_suspicious_tld, is_java_constant,
)

# ══════════════════════════════════════════════════════════════
# MITRE ATT&CK MAPPING
# ══════════════════════════════════════════════════════════════
MITRE_MAP = {
    "android.permission.READ_SMS":                   ("T1636.004", "SMS Messages"),
    "android.permission.RECEIVE_SMS":                ("T1636.004", "SMS Messages"),
    "android.permission.SEND_SMS":                   ("T1582",     "SMS Control"),
    "android.permission.RECORD_AUDIO":               ("T1429",     "Capture Audio"),
    "android.permission.CAMERA":                     ("T1512",     "Video Capture"),
    "android.permission.READ_CONTACTS":              ("T1636.003", "Contact List"),
    "android.permission.ACCESS_FINE_LOCATION":       ("T1430",     "Location Tracking"),
    "android.permission.ACCESS_BACKGROUND_LOCATION": ("T1430",     "Background Location"),
    "android.permission.READ_CALL_LOG":              ("T1636.002", "Call Log"),
    "android.permission.BIND_DEVICE_ADMIN":          ("T1629.003", "Impair Defenses"),
    "android.permission.REQUEST_INSTALL_PACKAGES":   ("T1474",     "Supply Chain Compromise"),
    "android.permission.RECEIVE_BOOT_COMPLETED":     ("T1624",     "Boot Persistence"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": ("T1417",     "Input Capture"),
    "android.permission.SYSTEM_ALERT_WINDOW":        ("T1418",     "Screen Overlay"),
    "android.permission.READ_PHONE_STATE":           ("T1426",     "System Info Discovery"),
}

# ══════════════════════════════════════════════════════════════
# DANGEROUS PERMISSIONS
# ══════════════════════════════════════════════════════════════
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS":                   {"risk": "CRITICAL", "explanation": "Read all SMS including bank OTPs and 2FA codes"},
    "android.permission.RECEIVE_SMS":                {"risk": "CRITICAL", "explanation": "Intercept incoming SMS messages in real-time"},
    "android.permission.SEND_SMS":                   {"risk": "CRITICAL", "explanation": "Send SMS without user knowledge — premium fraud risk"},
    "android.permission.RECORD_AUDIO":               {"risk": "CRITICAL", "explanation": "Record microphone/ambient audio silently in background"},
    "android.permission.PROCESS_OUTGOING_CALLS":     {"risk": "CRITICAL", "explanation": "Intercept and redirect outgoing phone calls"},
    "android.permission.READ_CALL_LOG":              {"risk": "CRITICAL", "explanation": "Access full call history"},
    "android.permission.BIND_DEVICE_ADMIN":          {"risk": "CRITICAL", "explanation": "Full device admin — can lock/wipe device (ransomware)"},
    "android.permission.REQUEST_INSTALL_PACKAGES":   {"risk": "CRITICAL", "explanation": "Install additional APKs silently (dropper)"},
    "android.permission.RECEIVE_BOOT_COMPLETED":     {"risk": "CRITICAL", "explanation": "Auto-start on every device boot — persistence"},
    "android.permission.BIND_ACCESSIBILITY_SERVICE": {"risk": "CRITICAL", "explanation": "Read screen content and simulate taps — banking trojan"},
    "android.permission.SYSTEM_ALERT_WINDOW":        {"risk": "CRITICAL", "explanation": "Draw overlay over any app — fake login screens"},
    "android.permission.READ_PHONE_STATE":           {"risk": "CRITICAL", "explanation": "Read IMEI, phone number, SIM info — fingerprinting"},
    "android.permission.WRITE_SETTINGS":             {"risk": "CRITICAL", "explanation": "Modify system settings without user knowledge"},
    "android.permission.DISABLE_KEYGUARD":           {"risk": "CRITICAL", "explanation": "Disable the device lock screen"},
    "android.permission.INSTALL_PACKAGES":           {"risk": "CRITICAL", "explanation": "Install apps silently — dropper capability"},
    "android.permission.DELETE_PACKAGES":            {"risk": "CRITICAL", "explanation": "Uninstall apps silently"},
    "android.permission.WRITE_SECURE_SETTINGS":      {"risk": "CRITICAL", "explanation": "Modify protected system settings"},
    "android.permission.CHANGE_NETWORK_STATE":       {"risk": "CRITICAL", "explanation": "Modify network connectivity"},
    "android.permission.REBOOT":                     {"risk": "CRITICAL", "explanation": "Forcefully reboot the device"},
    "android.permission.CAMERA":                     {"risk": "HIGH",     "explanation": "Access camera for photo/video surveillance"},
    "android.permission.ACCESS_FINE_LOCATION":       {"risk": "HIGH",     "explanation": "Precise GPS location tracking"},
    "android.permission.ACCESS_COARSE_LOCATION":     {"risk": "HIGH",     "explanation": "Approximate location via network/WiFi"},
    "android.permission.ACCESS_BACKGROUND_LOCATION": {"risk": "HIGH",     "explanation": "Track location even when app is in background"},
    "android.permission.READ_CONTACTS":              {"risk": "HIGH",     "explanation": "Read entire contact list"},
    "android.permission.WRITE_CONTACTS":             {"risk": "HIGH",     "explanation": "Modify or delete contacts"},
    "android.permission.GET_ACCOUNTS":               {"risk": "HIGH",     "explanation": "List all Google/email/banking accounts"},
    "android.permission.USE_CREDENTIALS":            {"risk": "HIGH",     "explanation": "Use stored account credentials"},
    "android.permission.READ_EXTERNAL_STORAGE":      {"risk": "HIGH",     "explanation": "Read all files from shared storage"},
    "android.permission.WRITE_EXTERNAL_STORAGE":     {"risk": "HIGH",     "explanation": "Write files to shared storage"},
    "android.permission.MANAGE_EXTERNAL_STORAGE":    {"risk": "HIGH",     "explanation": "Full access to all files on device"},
    "android.permission.FOREGROUND_SERVICE":         {"risk": "HIGH",     "explanation": "Run persistent foreground service"},
    "android.permission.WAKE_LOCK":                  {"risk": "HIGH",     "explanation": "Prevent CPU sleep — keeps malware running"},
    "android.permission.RECEIVE_WAP_PUSH":           {"risk": "HIGH",     "explanation": "Intercept WAP push messages"},
    "android.permission.READ_CALENDAR":              {"risk": "HIGH",     "explanation": "Read all calendar events"},
    "android.permission.WRITE_CALL_LOG":             {"risk": "HIGH",     "explanation": "Modify call log entries"},
    "android.permission.INTERNET":                   {"risk": "MEDIUM",   "explanation": "Full internet access — required for data exfiltration"},
    "android.permission.ACCESS_WIFI_STATE":          {"risk": "MEDIUM",   "explanation": "Read WiFi network names and MAC addresses"},
    "android.permission.CHANGE_WIFI_STATE":          {"risk": "MEDIUM",   "explanation": "Connect/disconnect from WiFi networks"},
    "android.permission.BLUETOOTH":                  {"risk": "MEDIUM",   "explanation": "Bluetooth device access"},
    "android.permission.NFC":                        {"risk": "MEDIUM",   "explanation": "NFC chip access — payment interception risk"},
    "android.permission.USE_BIOMETRIC":              {"risk": "MEDIUM",   "explanation": "Access biometric authentication"},
    "android.permission.USE_FINGERPRINT":            {"risk": "MEDIUM",   "explanation": "Access fingerprint authentication"},
    "android.permission.VIBRATE":                    {"risk": "LOW",      "explanation": "Control device vibration"},
}

# ══════════════════════════════════════════════════════════════
# SUSPICIOUS API BYTE PATTERNS
# These are searched in raw DEX bytes — instant, no parsing
# ══════════════════════════════════════════════════════════════
SUSPICIOUS_API_SIGNATURES = [
    ("android/telephony/SmsManager",       "sendTextMessage",          "CRITICAL", "Send SMS without user knowledge"),
    ("android/telephony/SmsManager",       "sendMultipartTextMessage", "CRITICAL", "Send bulk SMS silently"),
    ("android/media/MediaRecorder",        "start",                    "CRITICAL", "Start audio/video recording silently"),
    ("dalvik/system/DexClassLoader",       "<init>",                   "CRITICAL", "Load DEX code at runtime — dropper/loader"),
    ("dalvik/system/PathClassLoader",      "<init>",                   "HIGH",     "Dynamic class loading"),
    ("java/lang/Runtime",                  "exec",                     "CRITICAL", "Execute shell commands on device"),
    ("java/lang/ProcessBuilder",           "start",                    "CRITICAL", "Start arbitrary system process"),
    ("java/lang/reflect/Method",           "invoke",                   "HIGH",     "Reflective invocation — evasion technique"),
    ("android/app/admin/DevicePolicyManager", "lockNow",               "CRITICAL", "Lock device — ransomware behavior"),
    ("android/app/admin/DevicePolicyManager", "wipeData",              "CRITICAL", "Wipe all device data — destructive"),
    ("android/app/admin/DevicePolicyManager", "resetPassword",         "CRITICAL", "Reset device password — locks out owner"),
    ("android/accessibilityservice/AccessibilityService", "onAccessibilityEvent", "CRITICAL", "Monitor all UI events — banking trojan"),
    ("android/view/accessibility/AccessibilityNodeInfo", "getText",    "HIGH",     "Read UI text — credential theft"),
    ("android/view/WindowManager",         "addView",                  "HIGH",     "Draw overlay over other apps"),
    ("android/content/ClipboardManager",   "getPrimaryClip",           "HIGH",     "Read clipboard — crypto wallet theft"),
    ("javax/crypto/Cipher",                "getInstance",              "HIGH",     "Cryptographic cipher — possible ransomware"),
    ("android/location/LocationManager",   "requestLocationUpdates",   "HIGH",     "Continuously track GPS location"),
    ("android/telephony/TelephonyManager", "getDeviceId",              "HIGH",     "Read IMEI — device fingerprinting"),
    ("android/telephony/TelephonyManager", "getSubscriberId",          "HIGH",     "Read IMSI — SIM fingerprinting"),
    ("android/telephony/TelephonyManager", "getLine1Number",           "HIGH",     "Read phone number programmatically"),
    ("android/hardware/camera2/CameraManager", "openCamera",           "HIGH",     "Open camera for covert surveillance"),
    ("android/content/pm/PackageInstaller","createSession",            "CRITICAL", "Install packages programmatically"),
    ("android/content/pm/PackageManager",  "getInstalledPackages",     "MEDIUM",   "List all installed apps — recon"),
    ("java/net/HttpURLConnection",         "getOutputStream",          "MEDIUM",   "Upload data via HTTP"),
    ("android/content/ContentResolver",    "query",                    "HIGH",     "Query SMS/Contacts database"),
]


# ══════════════════════════════════════════════════════════════
# FAST DEX STRING EXTRACTOR
# Reads string table directly from raw DEX bytes
# NO androguard DEX parsing needed — 10-50x faster
# ══════════════════════════════════════════════════════════════
def _extract_dex_strings_fast(dex_bytes: bytes) -> list:
    """
    Extract all strings from DEX binary format directly.
    DEX header layout (bytes):
      0-7:   magic "dex\n035\0" or "dex\n036\0"
      8-11:  checksum
      12-31: SHA-1 signature
      32-35: file size
      36-39: header size
      40-43: endian tag
      44-47: link size
      48-51: link offset
      52-55: map offset
      56-59: string_ids_size  ← number of strings
      60-63: string_ids_off   ← offset to string ID list
    """
    strings = []
    try:
        if len(dex_bytes) < 112:
            return strings

        # Validate DEX magic
        magic = dex_bytes[:4]
        if magic != b'dex\n':
            return strings

        # Read string table info
        string_ids_size = struct.unpack_from('<I', dex_bytes, 56)[0]
        string_ids_off  = struct.unpack_from('<I', dex_bytes, 60)[0]

        # Sanity check
        if string_ids_size > 2_000_000 or string_ids_off > len(dex_bytes):
            return strings

        # Read each string
        for i in range(string_ids_size):
            try:
                # Each string ID entry is 4 bytes = offset to string data
                id_offset  = string_ids_off + i * 4
                str_offset = struct.unpack_from('<I', dex_bytes, id_offset)[0]

                if str_offset >= len(dex_bytes):
                    continue

                # String data starts with ULEB128 encoded length, then UTF-16 length
                # Then the actual MUTF-8 bytes follow
                pos = str_offset
                # Read ULEB128 (variable length encoding)
                length = 0
                shift  = 0
                while pos < len(dex_bytes):
                    b = dex_bytes[pos]
                    pos += 1
                    length |= (b & 0x7F) << shift
                    if not (b & 0x80):
                        break
                    shift += 7
                    if shift > 28:
                        break

                # Read the actual string bytes (null terminated MUTF-8)
                end = dex_bytes.index(b'\x00', pos) if b'\x00' in dex_bytes[pos:pos+length+10] else pos+length
                raw = dex_bytes[pos:end]
                s   = raw.decode('utf-8', errors='ignore').strip()
                if s:
                    strings.append(s)
            except Exception:
                continue

    except Exception:
        pass

    return strings


# ══════════════════════════════════════════════════════════════
# MAIN ANALYSIS
# ══════════════════════════════════════════════════════════════
def analyze_apk(filepath: str) -> dict:
    """
    Ultra-fast APK analysis:
    1. APK()  = manifest/cert/permissions (androguard - fast)
    2. Raw DEX bytes = string extraction without any parsing
    3. Pattern matching on raw bytes = API detection instantly
    Expected time: 5-20 seconds regardless of APK size
    """
    result = {
        "file_type":           "APK",
        "filename":            os.path.basename(filepath),
        "sha256":              _hash_file(filepath),
        "file_size_mb":        round(os.path.getsize(filepath) / (1024 * 1024), 2),
        "app_info":            {},
        "certificate":         {},
        "permissions":         {
            "dangerous":      {"CRITICAL":[],"HIGH":[],"MEDIUM":[],"LOW":[],"NORMAL":[]},
            "all_permissions": [],
            "critical_count":  0,
            "high_count":      0,
            "medium_count":    0,
            "total_count":     0,
        },
        "suspicious_apis":     [],
        "network_indicators":  {"hardcoded_ips":[],"private_ips":[],"hardcoded_urls":[],"domains":[],"phone_numbers":[]},
        "manifest_components": {"activities":[],"services":[],"receivers":[],"providers":[]},
        "string_intelligence": {"telegram_tokens":[],"discord_tokens":[],"firebase_configs":[],"hardcoded_credentials":[]},
        "obfuscation":         {"likely_obfuscated":False,"flags":[],"short_method_ratio":0},
        "frameworks":          [],
        "behaviors":           [],
        "errors":              [],
    }

    # ── Step 1: APK manifest parse (fast - no DEX) ──
    apk = None
    try:
        from androguard.core.bytecodes.apk import APK
        apk = APK(filepath)
    except Exception as e:
        result["errors"].append(f"APK parse: {e}")

    # ── Step 2: Read ALL DEX files as raw bytes (no parsing) ──
    all_dex_bytes  = b""   # combined raw bytes for pattern matching
    all_dex_strings = []   # strings extracted via DEX format reader

    try:
        with zipfile.ZipFile(filepath, "r") as zf:
            dex_names = sorted([n for n in zf.namelist() if re.match(r'classes\d*\.dex$', n)])
            for dex_name in dex_names:
                try:
                    raw = zf.read(dex_name)
                    all_dex_bytes += raw
                    # Fast string extraction from raw bytes
                    strings = _extract_dex_strings_fast(raw)
                    all_dex_strings.extend(strings)
                except Exception as de:
                    result["errors"].append(f"DEX read {dex_name}: {de}")
    except Exception as e:
        result["errors"].append(f"ZIP read: {e}")

    # ── Step 3: Also scan resource/asset text files ──
    resource_text = []
    TEXT_EXTS = (".json",".xml",".txt",".js",".html",".htm",
                 ".properties",".cfg",".ini",".yaml",".yml",".gradle",".config")
    try:
        with zipfile.ZipFile(filepath, "r") as zf:
            for name in zf.namelist():
                if any(name.lower().endswith(e) for e in TEXT_EXTS):
                    try:
                        content = zf.read(name).decode("utf-8", errors="ignore")
                        resource_text.append(content)
                    except Exception:
                        pass
    except Exception:
        pass

    # ── Step 4: Run all extractors ──
    if apk:
        _run(result, "app_info",           lambda: _extract_app_info(apk))
        _run(result, "certificate",        lambda: _extract_certificate(apk))
        _run(result, "permissions",        lambda: _extract_permissions(apk))
        _run(result, "manifest_components",lambda: _extract_manifest_components(apk))

    _run(result, "suspicious_apis",    lambda: _detect_apis_fast(all_dex_bytes, all_dex_strings))
    _run(result, "network_indicators", lambda: _extract_network_indicators(filepath, apk, all_dex_strings, resource_text))
    _run(result, "string_intelligence",lambda: _extract_string_intelligence(all_dex_strings, resource_text))
    _run(result, "obfuscation",        lambda: _detect_obfuscation_fast(all_dex_bytes, all_dex_strings))
    _run(result, "frameworks",         lambda: _detect_frameworks_fast(all_dex_bytes, all_dex_strings))
    _run(result, "behaviors",          lambda: _correlate_behaviors(result))

    return result


def _run(result: dict, key: str, fn):
    try:
        result[key] = fn()
    except Exception as e:
        result["errors"].append(f"{key}: {type(e).__name__}: {e}")


# ══════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════
def _hash_file(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def _safe(val) -> str:
    if val is None: return "Unknown"
    try:
        s = str(val).strip().replace('\x00','')
        return s if s and s != 'None' else "Unknown"
    except: return "Unknown"

def _to_str(data) -> str:
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="ignore")
    return str(data) if data is not None else ""


# ══════════════════════════════════════════════════════════════
# EXTRACTORS
# ══════════════════════════════════════════════════════════════
def _extract_app_info(apk) -> dict:
    info = {"package_name":"Unknown","app_name":"Unknown","version_name":"Unknown",
            "version_code":"Unknown","min_sdk":"Unknown","target_sdk":"Unknown","main_activity":"Unknown"}
    try: info["package_name"]  = _safe(apk.get_package())
    except: pass
    try:
        n = apk.get_app_name()
        info["app_name"] = _safe(n) if _safe(n) != "Unknown" else info["package_name"].split(".")[-1].capitalize()
    except: info["app_name"] = info["package_name"].split(".")[-1].capitalize()
    try: info["version_name"]  = _safe(apk.get_androidversion_name())
    except: pass
    try: info["version_code"]  = _safe(apk.get_androidversion_code())
    except: pass
    try: info["min_sdk"]       = _safe(apk.get_min_sdk_version())
    except: pass
    try: info["target_sdk"]    = _safe(apk.get_target_sdk_version())
    except: pass
    try: info["main_activity"] = _safe(apk.get_main_activity())
    except: pass
    return info


def _extract_certificate(apk) -> dict:
    res = {"issuer":"Unknown","subject":"Unknown","is_debug":False,"is_self_signed":False,"sha1":"","notice":""}
    try:
        certs = apk.get_certificates()
        if not certs:
            res["notice"] = "No certificate found"
            return res
        cert = certs[0]
        try:    res["issuer"]  = str(cert.issuer.human_friendly)
        except: res["issuer"]  = str(cert.issuer)
        try:    res["subject"] = str(cert.subject.human_friendly)
        except: res["subject"] = str(cert.subject)
        il = res["issuer"].lower()
        sl = res["subject"].lower()
        res["is_debug"]       = "android debug" in il or "android debug" in sl
        res["is_self_signed"] = il.strip() == sl.strip()
        try:    res["sha1"]   = cert.sha1_fingerprint.replace(" ","").lower()
        except:
            try:
                res["sha1"] = hashlib.sha1(cert.dump()).hexdigest()
            except: pass
        if res["is_debug"]:         res["notice"] = "APK signed with developer/debug certificate."
        elif res["is_self_signed"]: res["notice"] = "APK is self-signed. No trusted CA verification."
        else:                       res["notice"] = "Production certificate detected."
    except Exception as e:
        res["notice"] = f"Certificate error: {e}"
    return res


def _extract_permissions(apk) -> dict:
    try:    declared  = [_safe(p) for p in (apk.get_declared_permissions() or [])]
    except: declared  = []
    try:    requested = [_safe(p) for p in (apk.get_permissions() or [])]
    except: requested = []

    all_perms   = list({p for p in declared + requested if p and p != "Unknown"})
    categorized = {"CRITICAL":[],"HIGH":[],"MEDIUM":[],"LOW":[],"NORMAL":[]}

    for perm in all_perms:
        if perm in DANGEROUS_PERMISSIONS:
            info  = DANGEROUS_PERMISSIONS[perm]
            mitre = MITRE_MAP.get(perm, ("",""))
            categorized[info["risk"]].append({
                "permission": perm, "short": perm.split(".")[-1],
                "risk": info["risk"], "explanation": info["explanation"],
                "mitre_id": mitre[0], "mitre_name": mitre[1],
            })
        else:
            pl   = perm.lower()
            risk = "NORMAL"
            exp  = ""
            if any(k in pl for k in ["sms","mms","message"]):              risk,exp = "HIGH",   "SMS/messaging permission"
            elif any(k in pl for k in ["camera","audio","record","mic"]):  risk,exp = "HIGH",   "Media capture permission"
            elif any(k in pl for k in ["location","gps"]):                 risk,exp = "HIGH",   "Location access permission"
            elif any(k in pl for k in ["contact","phone","call"]):         risk,exp = "MEDIUM", "Contact/call permission"
            elif any(k in pl for k in ["storage","file","external"]):      risk,exp = "MEDIUM", "Storage access permission"

            categorized[risk].append({
                "permission": perm, "short": perm.split(".")[-1],
                "risk": risk, "explanation": exp, "mitre_id":"","mitre_name":"",
            })

    return {
        "all_permissions": all_perms,
        "dangerous":       categorized,
        "critical_count":  len(categorized["CRITICAL"]),
        "high_count":      len(categorized["HIGH"]),
        "medium_count":    len(categorized["MEDIUM"]),
        "total_count":     len(all_perms),
    }


def _detect_apis_fast(raw_dex_bytes: bytes, all_dex_strings: list) -> list:
    """
    Detect suspicious APIs by searching raw DEX bytes for class+method strings.
    Instant — no call graph, no DEX parsing.
    """
    found      = []
    string_set = set(all_dex_strings)

    for (cls, method, risk, explanation) in SUSPICIOUS_API_SIGNATURES:
        # Search raw bytes directly — fastest possible check
        cls_b    = cls.encode("utf-8")
        method_b = method.encode("utf-8")
        cls_found    = cls_b in raw_dex_bytes    or cls    in string_set
        method_found = method_b in raw_dex_bytes or method in string_set

        if cls_found and method_found:
            short = cls.split("/")[-1]
            found.append({
                "api":         f"{short}.{method}",
                "full_class":  cls,
                "method":      method,
                "risk":        risk,
                "explanation": explanation,
                "callers":     [],
                "mitre_id":    "",
                "mitre_name":  "",
            })

    return found


def _extract_network_indicators(filepath: str, apk, all_dex_strings: list, resource_text: list) -> dict:
    """Extract IPs, URLs, domains, phone numbers from all text sources."""
    ips, urls, domains, phones = set(), set(), set(), set()

    re_ip      = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
    re_url     = re.compile(r'https?://[^\s\'"<>{}\[\]\\]{6,200}')
    re_domain  = re.compile(
        r'\b(?:[a-zA-Z0-9\-]{2,63}\.)+(?:com|net|org|io|xyz|ru|top|tk|ml|ga|cf|pw|cc|su|biz|info|link|click|loan|win|download|in|co|me|app|dev|cloud|online|site|store|tech)\b'
    )
    re_ph_in   = re.compile(r'(?:\+91[\s\-]?)?[6-9]\d{9}')
    re_ph_intl = re.compile(r'\+[1-9]\d{7,14}')

    BAD = {'example.com','schema.org','w3.org','mozilla.org','android.com',
           'google.com','gstatic.com','googleapis.com','ietf.org','openjdk.org',
           'apache.org','github.com','stackoverflow.com'}

    def _scan(text: str):
        if not text or len(text) < 4: return
        for ip in re_ip.findall(text):
            parts = ip.split(".")
            try:
                if all(0 <= int(p) <= 255 for p in parts) and ip not in ("0.0.0.0","255.255.255.255"):
                    ips.add(ip)
            except: pass
        for url in re_url.findall(text):
            url = url.rstrip(".,;)'\"\\")
            if is_valid_network_url(url) and not is_framework_string(url) and len(url) < 300:
                urls.add(url)
        for dom in re_domain.findall(text):
            if not is_framework_string(dom) and 5 < len(dom) < 100 and dom.lower() not in BAD:
                domains.add(dom)
        for ph in re_ph_in.findall(text):
            d = re.sub(r'\D','',ph)
            if len(d) >= 10 and not is_java_constant(d): phones.add(ph.strip())
        for ph in re_ph_intl.findall(text):
            d = re.sub(r'\D','',ph)
            if 10 <= len(d) <= 15 and not is_java_constant(d): phones.add(ph.strip())

    # Scan DEX strings
    for s in all_dex_strings:
        _scan(s)

    # Scan manifest
    if apk:
        try: _scan(_to_str(apk.get_android_manifest_xml()))
        except: pass

    # Scan resource files (already loaded)
    for content in resource_text:
        _scan(content)

    public_ips  = sorted([ip for ip in ips if not is_private_ip(ip)])
    private_ips = sorted([ip for ip in ips if is_private_ip(ip)])

    url_list, seen_u = [], set()
    for url in sorted(urls):
        if url not in seen_u:
            seen_u.add(url)
            url_list.append({"url": url, "suspicious_tld": has_suspicious_tld(url)})

    return {
        "hardcoded_ips":  public_ips,
        "private_ips":    private_ips,
        "hardcoded_urls": url_list,
        "domains":        sorted(list(domains))[:50],
        "phone_numbers":  sorted(list(phones)),
    }


def _extract_manifest_components(apk) -> dict:
    activities,services,receivers,providers = [],[],[],[]
    for getter,lst in [('get_activities',activities),('get_services',services),
                        ('get_receivers',receivers),('get_providers',providers)]:
        try:
            for item in (getattr(apk,getter)() or []):
                lst.append({"name": _safe(item)})
        except: pass
    return {"activities":activities,"services":services,"receivers":receivers,"providers":providers}


def _extract_string_intelligence(all_dex_strings: list, resource_text: list) -> dict:
    """Scan strings for tokens, credentials, C2 configs."""
    telegram_tokens,firebase_configs,credentials,discord_tokens = [],[],[],[]

    re_tg     = re.compile(r'\b(\d{8,12}:[A-Za-z0-9_-]{35,})\b')
    re_tg_url = re.compile(r'api\.telegram\.org/bot([0-9]+:[A-Za-z0-9_-]{35,})')
    re_dc     = re.compile(r'[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}')
    re_fb     = re.compile(r'https://[a-z0-9\-]+\.firebaseio\.com')
    re_gapi   = re.compile(r'AIza[0-9A-Za-z\-_]{35}')
    re_aws    = re.compile(r'AKIA[0-9A-Z]{16}')
    re_cred   = re.compile(
        r'(?i)(?:password|passwd|pwd|secret|api_key|apikey|token|auth_token|access_token|bearer|access_key|private_key)\s*[=:]\s*["\']?([A-Za-z0-9!@#$%^&*()\-_+]{6,80})["\']?'
    )

    all_texts = list(all_dex_strings) + resource_text
    seen_tg,seen_dc,seen_fb,seen_creds = set(),set(),set(),set()

    SKIP_VALS = {'null','none','undefined','false','true','example','test','placeholder','your_key','changeme'}

    for text in all_texts:
        for m in re_tg.findall(text):
            if m not in seen_tg: seen_tg.add(m); telegram_tokens.append(m)
        for m in re_tg_url.findall(text):
            if m not in seen_tg: seen_tg.add(m); telegram_tokens.append(m)
        for m in re_dc.findall(text):
            if m not in seen_dc: seen_dc.add(m); discord_tokens.append(m)
        for m in re_fb.findall(text):
            if m not in seen_fb: seen_fb.add(m); firebase_configs.append(m)
        for m in re_gapi.findall(text):
            k = f"g:{m}"
            if k not in seen_creds: seen_creds.add(k); credentials.append({"key":"Google API Key","value":m})
        for m in re_aws.findall(text):
            k = f"a:{m}"
            if k not in seen_creds: seen_creds.add(k); credentials.append({"key":"AWS Access Key","value":m})
        for match in re_cred.finditer(text):
            val = match.group(1).strip().strip('"\'')
            if (len(val) >= 6 and val not in seen_creds and
                    not is_java_constant(val) and val.lower() not in SKIP_VALS):
                seen_creds.add(val)
                key_m = re.search(r'(?i)(password|passwd|pwd|secret|api_key|apikey|token|auth_token|bearer|access_key|private_key)', match.group(0))
                credentials.append({
                    "key":   key_m.group(1) if key_m else "credential",
                    "value": (val[:40]+"...") if len(val)>40 else val,
                })

    return {
        "telegram_tokens":       telegram_tokens[:10],
        "discord_tokens":        discord_tokens[:5],
        "firebase_configs":      firebase_configs[:10],
        "hardcoded_credentials": credentials[:20],
    }


def _detect_obfuscation_fast(raw_dex_bytes: bytes, all_dex_strings: list) -> dict:
    """Fast obfuscation detection from raw bytes — no parsing needed."""
    flags = []

    short = sum(1 for s in all_dex_strings
                if len(s) <= 2 and s.isalpha()
                and s not in {"is","do","on","go","ok","id","of","at","to","in","if","or","as"})
    total = max(len(all_dex_strings), 1)
    ratio = short / total

    if ratio > 0.04:
        flags.append(f"Short identifier ratio {ratio:.1%} ({short}/{total}) — obfuscator detected")
    if b"DexClassLoader" in raw_dex_bytes:
        flags.append("DexClassLoader — loads additional code at runtime")
    if b"java/lang/reflect/Method" in raw_dex_bytes:
        flags.append("Heavy reflection — common in obfuscated/evasive malware")

    return {
        "likely_obfuscated":  len(flags) > 0,
        "flags":              flags,
        "short_method_ratio": round(ratio * 100, 1),
    }


def _detect_frameworks_fast(raw_dex_bytes: bytes, all_dex_strings: list) -> list:
    """Detect frameworks from raw bytes — instant."""
    found      = []
    string_set = set(all_dex_strings)

    FINGERPRINTS = {
        "React Native": [b"libreactnativejni", b"index.android.bundle", b"com.facebook.react"],
        "Flutter":      [b"libflutter",        b"kernel_blob.bin",      b"io.flutter"],
        "Unity":        [b"libunity",          b"UnityPlayer",          b"com.unity3d"],
        "Kotlin":       [b"kotlin/Metadata",   b"kotlin.jvm"],
        "Xamarin":      [b"libmono",           b"Xamarin"],
        "Cordova":      [b"cordova.js",        b"org.apache.cordova"],
    }
    for framework, patterns in FINGERPRINTS.items():
        for p in patterns:
            if p in raw_dex_bytes or p.decode("utf-8","ignore") in string_set:
                found.append(framework)
                break
    return list(set(found))


def _correlate_behaviors(result: dict) -> list:
    behaviors = []

    all_dangerous = result.get("permissions", {}).get("dangerous", {})
    perms = set()
    for level_list in all_dangerous.values():
        if isinstance(level_list, list):
            for p in level_list:
                if isinstance(p, dict): perms.add(p.get("permission",""))

    api_names = {a.get("api","") for a in result.get("suspicious_apis",[])}
    strings   = result.get("string_intelligence", {})

    def hp(*p): return any(x in perms for x in p)
    def ha(*a): return any(x in api_names for x in a)

    if hp("android.permission.READ_SMS","android.permission.RECEIVE_SMS") and hp("android.permission.INTERNET"):
        behaviors.append({"name":"OTP / SMS Exfiltration","description":"Intercepts all SMS (OTPs, bank codes) and exfiltrates via internet.","severity":"CRITICAL","mitre":"T1636.004","indicators":["READ_SMS","INTERNET"]})
    if hp("android.permission.BIND_ACCESSIBILITY_SERVICE") and hp("android.permission.SYSTEM_ALERT_WINDOW"):
        behaviors.append({"name":"Banking Trojan Pattern","description":"Reads banking screens via Accessibility + overlays fake login forms.","severity":"CRITICAL","mitre":"T1417","indicators":["BIND_ACCESSIBILITY_SERVICE","SYSTEM_ALERT_WINDOW"]})
    if hp("android.permission.RECORD_AUDIO") and hp("android.permission.INTERNET"):
        behaviors.append({"name":"Audio Surveillance / Spyware","description":"Records ambient audio/calls and uploads to remote server.","severity":"CRITICAL","mitre":"T1429","indicators":["RECORD_AUDIO","INTERNET"]})
    if hp("android.permission.ACCESS_FINE_LOCATION","android.permission.ACCESS_BACKGROUND_LOCATION") and hp("android.permission.INTERNET"):
        behaviors.append({"name":"GPS Location Tracker","description":"Tracks precise GPS location in background and reports to attacker.","severity":"HIGH","mitre":"T1430","indicators":["ACCESS_FINE_LOCATION","INTERNET"]})
    if hp("android.permission.REQUEST_INSTALL_PACKAGES") or ha("PackageInstaller.createSession","DexClassLoader.<init>"):
        behaviors.append({"name":"Dropper / Malware Loader","description":"Downloads and silently installs additional APKs or loads code at runtime.","severity":"CRITICAL","mitre":"T1407","indicators":["REQUEST_INSTALL_PACKAGES","DexClassLoader"]})
    if hp("android.permission.BIND_DEVICE_ADMIN") and ha("DevicePolicyManager.lockNow","DevicePolicyManager.wipeData"):
        behaviors.append({"name":"Ransomware Pattern","description":"Device admin + lock/wipe = holds device hostage.","severity":"CRITICAL","mitre":"T1629.003","indicators":["BIND_DEVICE_ADMIN","lockNow/wipeData"]})
    if hp("android.permission.CAMERA") and hp("android.permission.INTERNET"):
        behaviors.append({"name":"Camera Surveillance","description":"Silently captures photos/video and uploads to attacker server.","severity":"HIGH","mitre":"T1512","indicators":["CAMERA","INTERNET"]})
    if hp("android.permission.RECEIVE_BOOT_COMPLETED"):
        behaviors.append({"name":"Boot Persistence","description":"Auto-starts on every reboot — malware survives restarts.","severity":"HIGH","mitre":"T1624","indicators":["RECEIVE_BOOT_COMPLETED"]})
    if strings.get("telegram_tokens"):
        behaviors.append({"name":"Telegram C2 Channel","description":"Hardcoded Telegram bot token — attacker controls via Telegram.","severity":"CRITICAL","mitre":"T1437","indicators":[f"Token: {strings['telegram_tokens'][0][:25]}..."]})
    if hp("android.permission.READ_CONTACTS") and hp("android.permission.INTERNET"):
        behaviors.append({"name":"Contact List Harvesting","description":"Steals entire contact list and exfiltrates via internet.","severity":"HIGH","mitre":"T1636.003","indicators":["READ_CONTACTS","INTERNET"]})
    if hp("android.permission.SEND_SMS"):
        behaviors.append({"name":"Premium SMS Fraud","description":"Sends SMS to premium-rate numbers without user knowledge.","severity":"HIGH","mitre":"T1582","indicators":["SEND_SMS"]})
    if ha("ClipboardManager.getPrimaryClip"):
        behaviors.append({"name":"Clipboard Hijacking","description":"Reads clipboard — targets crypto wallet addresses and passwords.","severity":"HIGH","mitre":"T1414","indicators":["ClipboardManager.getPrimaryClip"]})
    if ha("Runtime.exec","ProcessBuilder.start"):
        behaviors.append({"name":"Shell Command Execution","description":"Executes arbitrary shell commands — may attempt root access.","severity":"CRITICAL","mitre":"T1059","indicators":["Runtime.exec / ProcessBuilder.start"]})

    return behaviors
