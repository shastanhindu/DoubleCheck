# 🛡️ Intel Platform v2.1 — Digital Forensics & Threat Intelligence Engine

## What It Does
Analyzes **APK, EXE, and DLL** files to extract EVERY risky indicator:

| Category | What is Extracted |
|---|---|
| 📦 App Info | Package name, app name, version, SDK levels |
| 🔏 Certificate | Issuer, subject, debug cert detection, self-signed |
| 🔐 Permissions | 45+ dangerous Android permissions with risk levels |
| ⚙️ API Calls | 40+ malicious API calls from DEX bytecode & PE imports |
| 🌐 IPs | Hardcoded IP addresses (with OSINT geolocation + AbuseIPDB score) |
| 🔗 URLs | Hardcoded URLs with suspicious TLD detection |
| 🌍 Domains | All extracted domains |
| 📞 Phone Numbers | Hardcoded phone numbers (Indian + International) |
| 🔑 Credentials | Telegram tokens, Firebase configs, API keys, passwords |
| ⚡ Behaviors | OTP theft, banking trojans, spyware, ransomware patterns |
| 🎭 Obfuscation | Code hiding/encryption detection |
| 🧰 Frameworks | Flutter, React Native, Unity, Kotlin, Xamarin detection |
| 📊 MITRE ATT&CK | Every finding mapped to MITRE technique |
| 🏆 Verdict | Risk score + Confidence score → MALICIOUS / SUSPICIOUS / SAFE |

---

## Quick Setup

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Add API keys
Copy `.env.example` to `.env` and fill in your API keys:
```bash
cp .env.example .env
```
Edit `.env`:
```
ABUSEIPDB_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
```

Get free API keys from:
- AbuseIPDB: https://www.abuseipdb.com/api
- VirusTotal: https://www.virustotal.com/gui/my-apikey

### 3. Run the app
```bash
python app.py
```

### 4. Open in browser
```
http://localhost:5000
```

---

## Project Structure

```
DoubleCheck/
├── app.py                  ← Flask web server (main entry point)
├── verdict.py              ← Risk + Confidence scoring engine
├── osint.py                ← IP geolocation + AbuseIPDB + VirusTotal
├── filters.py              ← Noise filtering (framework strings, etc.)
├── pdf_export.py           ← Professional PDF report generator
├── engines/
│   ├── android.py          ← APK deep static analysis
│   └── windows.py          ← Windows PE analysis
├── templates/
│   ├── index.html          ← Upload page
│   ├── report.html         ← Analysis results
│   └── error.html          ← Error display
├── static/css/
│   └── style.css           ← Professional styling
├── uploads/                ← Temp folder (auto-created, auto-deleted)
├── requirements.txt
└── .env.example
```

---

## Supported File Types
- **APK** — Android application packages
- **EXE** — Windows executables
- **DLL** — Windows dynamic link libraries

---

## Verdict Logic (Risk vs. Confidence Matrix)

| Risk Score | Confidence Score | Verdict |
|---|---|---|
| ≥ 70 | ≥ 70 | 🔴 MALICIOUS |
| ≥ 70 | < 70 | 🟠 SUSPICIOUS |
| < 70 | ≥ 70 | 🟠 SUSPICIOUS |
| ≥ 40 | any | 🟡 PUA |
| < 40 | < 60 | 🟢 SAFE |

---
*For authorized forensic use only.*
