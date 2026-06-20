"""
filters.py — Noise filtering utilities
Removes framework strings, Java constants, and false positives
"""

# ──────────────────────────────────────────────────────────────
# FRAMEWORK STRING BLOCKLIST
# Strings that belong to standard libraries / SDKs — not app logic
# ──────────────────────────────────────────────────────────────
FRAMEWORK_STRING_BLOCKLIST = [
    "react native", "flutter", "unity", "androidx", "com.google",
    "com.facebook", "okhttp", "retrofit", "glide", "picasso",
    "proguard", "kotlin", "dalvik", "java.lang", "java.util",
    "java.io", "android.os", "android.app", "android.content",
    "android.view", "android.widget", "android.graphics",
    "com.squareup", "io.reactivex", "org.apache", "org.json",
    "javax.net", "sun.security", "libcore", "com.android",
    "android.support", "com.crashlytics", "com.appsflyer",
    "io.flutter", "libreactnativejni", "libunity",
    "firebase.google.com",   # allow firebase detection separately
    "gms.common", "play.services",
]

# ──────────────────────────────────────────────────────────────
# JAVA NUMERIC CONSTANTS (not real phone numbers / IPs)
# ──────────────────────────────────────────────────────────────
JAVA_CONSTANTS = {
    "9223372036854775807",  # Long.MAX_VALUE
    "2147483647",           # Integer.MAX_VALUE
    "0000000000",
    "1111111111",
    "1234567890",
    "9876543210",
    "1000000000",
    "2000000000",
}

# ──────────────────────────────────────────────────────────────
# PRIVATE / RESERVED IP RANGES (not C2)
# ──────────────────────────────────────────────────────────────
PRIVATE_IP_PREFIXES = [
    "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "127.", "0.0.0.", "255.255.", "169.254.",
]

# ──────────────────────────────────────────────────────────────
# FRAMEWORK FINGERPRINTS — detect which framework an APK uses
# ──────────────────────────────────────────────────────────────
FRAMEWORK_FINGERPRINTS = {
    "React Native": ["libreactnativejni.so", "index.android.bundle", "com.facebook.react"],
    "Flutter":      ["libflutter.so", "kernel_blob.bin", "io.flutter.embedding"],
    "Unity":        ["libunity.so", "UnityPlayer", "com.unity3d"],
    "Kotlin":       ["kotlin.Metadata", "kotlin/jvm"],
    "Xamarin":      ["libmono", "Xamarin", "mono-android"],
    "Cordova":      ["cordova.js", "org.apache.cordova"],
}

# ──────────────────────────────────────────────────────────────
# SUSPICIOUS TLDs
# ──────────────────────────────────────────────────────────────
SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".ru", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".pw", ".cc", ".su", ".biz", ".info", ".link", ".click",
    ".loan", ".win", ".download", ".zip", ".review",
]

# ──────────────────────────────────────────────────────────────
# HELPER FUNCTIONS
# ──────────────────────────────────────────────────────────────

def is_framework_string(s: str) -> bool:
    """Return True if string belongs to a known framework/SDK (should be ignored)."""
    sl = s.lower()
    return any(fw in sl for fw in FRAMEWORK_STRING_BLOCKLIST)


def is_java_constant(number_str: str) -> bool:
    """Return True if the number string is a known Java constant."""
    return number_str.strip() in JAVA_CONSTANTS


def is_private_ip(ip: str) -> bool:
    """Return True if IP is in a private/reserved range."""
    return any(ip.startswith(prefix) for prefix in PRIVATE_IP_PREFIXES)


def is_valid_network_url(url: str) -> bool:
    """Basic URL validity check."""
    if not url.startswith(("http://", "https://")):
        return False
    if len(url) < 12:
        return False
    if url.count(".") == 0:
        return False
    return True


def has_suspicious_tld(url_or_domain: str) -> bool:
    """Return True if URL/domain uses a suspicious TLD."""
    lower = url_or_domain.lower()
    return any(lower.endswith(tld) or (tld + "/") in lower for tld in SUSPICIOUS_TLDS)


def detect_frameworks(filepath: str, dex_list: list) -> list:
    """
    Detect which frameworks/libraries are used in the APK.
    Returns list of framework names found.
    """
    found = []
    try:
        # Read raw APK bytes for fingerprinting
        with open(filepath, "rb") as f:
            raw = f.read().decode("latin-1", errors="ignore").lower()

        # Check DEX string pools
        dex_strings = set()
        for dex in dex_list:
            for s in dex.get_strings():
                dex_strings.add(str(s).lower())

        for framework, fingerprints in FRAMEWORK_FINGERPRINTS.items():
            for fp in fingerprints:
                fp_lower = fp.lower()
                if fp_lower in raw or any(fp_lower in ds for ds in dex_strings):
                    found.append(framework)
                    break
    except Exception:
        pass
    return list(set(found))
