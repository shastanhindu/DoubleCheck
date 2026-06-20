"""
engines/windows.py — Windows PE File Static Analysis Engine
Analyzes EXE, DLL files for malicious indicators.
"""

import os
import re
import hashlib
import math
import struct

# ══════════════════════════════════════════════════════════════
# MALICIOUS WINDOWS API SIGNATURES
# ══════════════════════════════════════════════════════════════
MALICIOUS_IMPORTS = {
    # Process Injection
    "CreateRemoteThread":       {"risk": "CRITICAL", "explanation": "Inject code into another process"},
    "WriteProcessMemory":       {"risk": "CRITICAL", "explanation": "Write to another process's memory"},
    "VirtualAllocEx":           {"risk": "CRITICAL", "explanation": "Allocate memory in another process (shellcode injection)"},
    "NtCreateThreadEx":         {"risk": "CRITICAL", "explanation": "Create thread in remote process (stealthy injection)"},
    "QueueUserAPC":             {"risk": "CRITICAL", "explanation": "APC injection technique"},
    "SetThreadContext":         {"risk": "CRITICAL", "explanation": "Hijack thread context (process hollowing)"},
    "ResumeThread":             {"risk": "HIGH",     "explanation": "Resume suspended thread (process hollowing)"},

    # Keylogging / Input capture
    "SetWindowsHookEx":         {"risk": "CRITICAL", "explanation": "Hook keyboard/mouse — keylogger"},
    "GetAsyncKeyState":         {"risk": "HIGH",     "explanation": "Capture key presses asynchronously"},
    "GetForegroundWindow":      {"risk": "HIGH",     "explanation": "Monitor active window (surveillance)"},

    # Network
    "InternetOpenUrl":          {"risk": "HIGH",     "explanation": "Open internet URL (download/C2)"},
    "HttpSendRequest":          {"risk": "HIGH",     "explanation": "Send HTTP request (data exfiltration)"},
    "WSAStartup":               {"risk": "MEDIUM",   "explanation": "Initialize network (Winsock)"},
    "connect":                  {"risk": "MEDIUM",   "explanation": "TCP/UDP connection"},
    "send":                     {"risk": "MEDIUM",   "explanation": "Send data over network"},
    "recv":                     {"risk": "MEDIUM",   "explanation": "Receive data from network"},

    # File / Persistence
    "RegSetValueEx":            {"risk": "HIGH",     "explanation": "Write registry key (persistence)"},
    "RegCreateKeyEx":           {"risk": "HIGH",     "explanation": "Create registry key (persistence)"},
    "CreateService":            {"risk": "HIGH",     "explanation": "Create Windows service (persistence)"},
    "OpenSCManager":            {"risk": "HIGH",     "explanation": "Access service control manager"},
    "SHFileOperation":          {"risk": "MEDIUM",   "explanation": "File operation (copy, delete, move)"},
    "DeleteFile":               {"risk": "MEDIUM",   "explanation": "Delete files (cover tracks)"},

    # Privilege / UAC bypass
    "AdjustTokenPrivileges":    {"risk": "CRITICAL", "explanation": "Elevate process privileges"},
    "OpenProcessToken":         {"risk": "HIGH",     "explanation": "Access process token (privilege escalation)"},
    "ImpersonateLoggedOnUser":  {"risk": "CRITICAL", "explanation": "Impersonate another user's session"},

    # Anti-analysis / Evasion
    "IsDebuggerPresent":        {"risk": "HIGH",     "explanation": "Anti-debugging check — evades analysis"},
    "CheckRemoteDebuggerPresent":{"risk":"HIGH",     "explanation": "Anti-debugging check"},
    "GetTickCount":             {"risk": "MEDIUM",   "explanation": "Timing check — detect sandbox (fast clock)"},
    "NtQueryInformationProcess":{"risk": "HIGH",     "explanation": "Anti-VM / anti-debug detection"},
    "OutputDebugString":        {"risk": "MEDIUM",   "explanation": "Debug string — evasion technique"},

    # Execution
    "ShellExecute":             {"risk": "HIGH",     "explanation": "Execute external command"},
    "ShellExecuteEx":           {"risk": "HIGH",     "explanation": "Execute external command (extended)"},
    "WinExec":                  {"risk": "CRITICAL", "explanation": "Execute command line"},
    "CreateProcess":            {"risk": "HIGH",     "explanation": "Create new process"},
    "LoadLibrary":              {"risk": "HIGH",     "explanation": "Load DLL at runtime (evasion)"},
    "GetProcAddress":           {"risk": "HIGH",     "explanation": "Resolve API address at runtime (evasion)"},

    # Crypto / Ransomware
    "CryptEncrypt":             {"risk": "CRITICAL", "explanation": "Encrypt data (ransomware)"},
    "CryptGenKey":              {"risk": "HIGH",     "explanation": "Generate encryption key (ransomware)"},
    "CryptAcquireContext":      {"risk": "HIGH",     "explanation": "Access cryptographic context"},

    # Screenshot
    "BitBlt":                   {"risk": "HIGH",     "explanation": "Screen capture / screenshot"},
    "GetDC":                    {"risk": "MEDIUM",   "explanation": "Get device context (screen capture)"},
}


# ══════════════════════════════════════════════════════════════
# MAIN WINDOWS PE ANALYSIS
# ══════════════════════════════════════════════════════════════
def analyze_windows(filepath: str) -> dict:
    result = {
        "file_type":          "PE",
        "filename":           os.path.basename(filepath),
        "sha256":             _hash_file(filepath),
        "file_size_mb":       round(os.path.getsize(filepath) / (1024 * 1024), 2),
        "file_info":          {},
        "pdb_path":           None,
        "imports":            [],
        "sections":           [],
        "strings_of_interest": [],
        "suspicious_indicators": [],
        "is_packed":          False,
        "errors":             [],
    }

    try:
        import pefile
        pe = pefile.PE(filepath)
    except Exception as e:
        result["errors"].append(f"PE parsing failed: {e}")
        return result

    # File info
    try:
        result["file_info"] = {
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "image_base":  hex(pe.OPTIONAL_HEADER.ImageBase),
            "timestamp":   pe.FILE_HEADER.TimeDateStamp,
            "machine":     hex(pe.FILE_HEADER.Machine),
            "arch":        "x64" if pe.FILE_HEADER.Machine == 0x8664 else "x86",
            "is_dll":      bool(pe.FILE_HEADER.Characteristics & 0x2000),
            "subsystem":   pe.OPTIONAL_HEADER.Subsystem,
        }
    except Exception as e:
        result["errors"].append(f"file_info: {e}")

    # PDB path
    try:
        if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
            for entry in pe.DIRECTORY_ENTRY_DEBUG:
                raw = entry.struct
                if hasattr(entry, 'entry') and hasattr(entry.entry, 'PdbFileName'):
                    pdb = entry.entry.PdbFileName.decode("utf-8", errors="ignore").rstrip("\x00")
                    if pdb:
                        result["pdb_path"] = pdb
    except Exception:
        pass

    # Import table
    try:
        suspicious = []
        all_imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for lib in pe.DIRECTORY_ENTRY_IMPORT:
                lib_name = lib.dll.decode("utf-8", errors="ignore")
                for imp in lib.imports:
                    if imp.name:
                        fn_name = imp.name.decode("utf-8", errors="ignore")
                        all_imports.append({"dll": lib_name, "function": fn_name})
                        if fn_name in MALICIOUS_IMPORTS:
                            info = MALICIOUS_IMPORTS[fn_name]
                            suspicious.append({
                                "dll":         lib_name,
                                "function":    fn_name,
                                "risk":        info["risk"],
                                "explanation": info["explanation"],
                            })
        result["imports"]  = suspicious
        result["all_imports_count"] = len(all_imports)
    except Exception as e:
        result["errors"].append(f"imports: {e}")

    # Section analysis + entropy (packing detection)
    try:
        sections = []
        packed_sections = 0
        for section in pe.sections:
            name = section.Name.decode("utf-8", errors="ignore").rstrip("\x00")
            data = section.get_data()
            entropy = _calc_entropy(data)
            is_packed = entropy > 7.0
            if is_packed:
                packed_sections += 1
            sections.append({
                "name":      name,
                "virtual_address": hex(section.VirtualAddress),
                "raw_size":  section.SizeOfRawData,
                "entropy":   round(entropy, 2),
                "is_packed": is_packed,
            })
        result["sections"] = sections
        result["is_packed"] = packed_sections >= 1
    except Exception as e:
        result["errors"].append(f"sections: {e}")

    # Interesting strings (IPs, URLs, etc.)
    try:
        result["strings_of_interest"] = _extract_strings(filepath)
    except Exception as e:
        result["errors"].append(f"strings: {e}")

    # Overall suspicious indicator summary
    crit = sum(1 for i in result["imports"] if i["risk"] == "CRITICAL")
    high = sum(1 for i in result["imports"] if i["risk"] == "HIGH")
    if crit >= 1:
        result["suspicious_indicators"].append(f"{crit} CRITICAL Windows API calls detected")
    if high >= 2:
        result["suspicious_indicators"].append(f"{high} HIGH risk Windows API calls detected")
    if result["is_packed"]:
        result["suspicious_indicators"].append("File is packed/encrypted (high entropy sections)")
    if result["pdb_path"]:
        result["suspicious_indicators"].append(f"PDB path leaked: {result['pdb_path']}")

    # Calculate verdict data
    result["verdict_data"] = {
        "permissions":    {"critical_count": crit, "high_count": high},
        "suspicious_apis": result["imports"],
        "network_indicators": {"hardcoded_ips": [], "hardcoded_urls": [], "phone_numbers": []},
        "string_intelligence": {},
        "certificate":    {},
        "obfuscation":    {"likely_obfuscated": result["is_packed"]},
        "behaviors":      result["suspicious_indicators"],
        "enriched_ips":   [],
    }

    return result


def _hash_file(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _calc_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    n = len(data)
    for count in freq.values():
        p = count / n
        entropy -= p * math.log2(p)
    return entropy


def _extract_strings(filepath: str) -> list:
    """Extract printable strings of interest (IPs, URLs, paths) from binary."""
    results = []
    re_url  = re.compile(rb'https?://[^\x00-\x1f\x7f-\xff ]{6,200}')
    re_ip   = re.compile(rb'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')

    try:
        with open(filepath, "rb") as f:
            data = f.read()

        for url in re_url.findall(data):
            results.append({"type": "URL", "value": url.decode("utf-8", errors="ignore")})

        for ip in re_ip.findall(data):
            ip_str = ip.decode()
            parts  = ip_str.split(".")
            if all(0 <= int(p) <= 255 for p in parts):
                if not ip_str.startswith(("10.", "127.", "192.168.", "0.0.")):
                    results.append({"type": "IP", "value": ip_str})

    except Exception:
        pass

    return results[:30]
