"""
pdf_export.py — Professional PDF Report Generator
Fully fixed: handles missing/empty data gracefully, no crashes.
"""

import datetime
import io

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

# ── Colour palette ──────────────────────────────────────────
C_RED     = colors.HexColor("#E53E3E")
C_ORANGE  = colors.HexColor("#DD6B20")
C_YELLOW  = colors.HexColor("#D69E2E")
C_GREEN   = colors.HexColor("#38A169")
C_BLUE    = colors.HexColor("#2B6CB0")
C_DARK    = colors.HexColor("#1A202C")
C_MID     = colors.HexColor("#4A5568")
C_GREY    = colors.HexColor("#718096")
C_LIGHT   = colors.HexColor("#F7FAFC")
C_BORDER  = colors.HexColor("#CBD5E0")
C_WHITE   = colors.white

RISK_BG = {
    "CRITICAL": C_RED,
    "HIGH":     C_ORANGE,
    "MEDIUM":   C_YELLOW,
    "LOW":      C_GREEN,
}
VERDICT_BG = {
    "red":    C_RED,
    "orange": C_ORANGE,
    "yellow": C_YELLOW,
    "green":  C_GREEN,
    "grey":   C_GREY,
}

# ── Styles ───────────────────────────────────────────────────
def _styles():
    base = {
        "title":   ParagraphStyle("title",  fontSize=18, textColor=C_DARK,
                                  alignment=TA_CENTER, fontName="Helvetica-Bold",
                                  spaceAfter=4),
        "sub":     ParagraphStyle("sub",    fontSize=9,  textColor=C_GREY,
                                  alignment=TA_CENTER, spaceAfter=10),
        "h2":      ParagraphStyle("h2",     fontSize=12, textColor=C_DARK,
                                  fontName="Helvetica-Bold",
                                  spaceBefore=12, spaceAfter=5),
        "h3":      ParagraphStyle("h3",     fontSize=10, textColor=C_MID,
                                  fontName="Helvetica-Bold",
                                  spaceBefore=8, spaceAfter=4),
        "body":    ParagraphStyle("body",   fontSize=9,  textColor=C_DARK,
                                  leading=13),
        "mono":    ParagraphStyle("mono",   fontSize=8,  fontName="Courier",
                                  textColor=C_DARK, leading=12),
        "small":   ParagraphStyle("small",  fontSize=8,  textColor=C_GREY,
                                  leading=11),
        "none":    ParagraphStyle("none",   fontSize=8,  textColor=C_GREY,
                                  leading=11, leftIndent=8),
        "footer":  ParagraphStyle("footer", fontSize=7,  textColor=C_GREY,
                                  alignment=TA_CENTER),
        "vtitle":  ParagraphStyle("vtitle", fontSize=13, textColor=C_WHITE,
                                  fontName="Helvetica-Bold", alignment=TA_CENTER),
        "vscore":  ParagraphStyle("vscore", fontSize=9,  textColor=C_WHITE,
                                  alignment=TA_CENTER),
    }
    return base


# ── Safe helpers ─────────────────────────────────────────────
def _safe(val, fallback="—"):
    """Return a safe string — never None, never crashes."""
    if val is None:
        return fallback
    s = str(val).strip()
    return s if s and s.lower() not in ("none", "null", "unknown") else fallback


def _p(text, style):
    """Paragraph — strip special chars that break ReportLab."""
    safe_text = _safe(text, "")
    safe_text = safe_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    # Remove emoji (ReportLab default fonts don't support them)
    safe_text = safe_text.encode("ascii", errors="ignore").decode("ascii")
    return Paragraph(safe_text or " ", style)


def _na(style):
    """Standard 'not found' paragraph."""
    return Paragraph("Nothing found.", style)


# ── Table builders ───────────────────────────────────────────
_TBL_BASE = [
    ("FONTSIZE",       (0, 0), (-1, -1), 8),
    ("FONTNAME",       (0, 0), (-1,  0), "Helvetica-Bold"),
    ("BACKGROUND",     (0, 0), (-1,  0), colors.HexColor("#EBF4FF")),
    ("TEXTCOLOR",      (0, 0), (-1,  0), C_DARK),
    ("GRID",           (0, 0), (-1, -1), 0.4, C_BORDER),
    ("PADDING",        (0, 0), (-1, -1), 5),
    ("VALIGN",         (0, 0), (-1, -1), "TOP"),
    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, C_LIGHT]),
]


def _tbl(rows, col_widths=None):
    t = Table(rows, colWidths=col_widths, repeatRows=1, hAlign="LEFT")
    t.setStyle(TableStyle(_TBL_BASE))
    return t


def _tbl_risk(rows, risk_col=1, col_widths=None):
    """Table with colour-coded risk column."""
    t = _tbl(rows, col_widths)
    for i, row in enumerate(rows[1:], start=1):
        val = row[risk_col] if risk_col < len(row) else ""
        bg  = RISK_BG.get(val)
        if bg:
            t.setStyle(TableStyle([
                ("BACKGROUND", (risk_col, i), (risk_col, i), bg),
                ("TEXTCOLOR",  (risk_col, i), (risk_col, i), C_WHITE),
                ("FONTNAME",   (risk_col, i), (risk_col, i), "Helvetica-Bold"),
            ]))
    return t


# ══════════════════════════════════════════════════════════════
# MAIN PDF GENERATOR
# ══════════════════════════════════════════════════════════════
def generate_pdf(result: dict) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=1.5*cm, rightMargin=1.5*cm,
        topMargin=1.5*cm,  bottomMargin=1.5*cm,
    )
    S  = _styles()
    st = []   # story elements

    # ── HEADER ────────────────────────────────────────────────
    st.append(_p("DoubleCheck Intel Platform v2.1  Forensic Report", S["title"]))
    st.append(_p(
        f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}  |  "
        f"File: {_safe(result.get('filename'))}  |  "
        f"Type: {_safe(result.get('file_type'))}  |  "
        f"Size: {_safe(result.get('file_size_mb'))} MB",
        S["sub"]
    ))
    st.append(HRFlowable(width="100%", thickness=2, color=C_BLUE))
    st.append(Spacer(1, 8))

    # ── VERDICT BANNER ────────────────────────────────────────
    vi     = result.get("verdict_info") or {}
    v_bg   = VERDICT_BG.get(vi.get("verdict_color", "grey"), C_GREY)
    v_icon = vi.get("verdict_icon", "")
    v_text = _safe(vi.get("verdict"), "UNKNOWN")
    risk_s = vi.get("risk_score", 0)
    conf_s = vi.get("confidence",  0)

    vt = Table([[
        _p(f"{v_text}", S["vtitle"]),
        _p(f"Risk: {risk_s}/100  |  Confidence: {conf_s}/100", S["vscore"]),
    ]], colWidths=["60%", "40%"])
    vt.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), v_bg),
        ("PADDING",    (0,0), (-1,-1), 10),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
    ]))
    st.append(vt)
    st.append(Spacer(1, 10))

    # ── SECTION: APP / FILE INFO ──────────────────────────────
    st.append(_p("Application Information", S["h2"]))
    app_info = result.get("app_info") or result.get("file_info") or {}
    rows = [["Field", "Value"],
            ["File",        _safe(result.get("filename"))],
            ["SHA-256",     _safe(result.get("sha256"))],
            ["Size",        f"{_safe(result.get('file_size_mb'))} MB"],
            ["File Type",   _safe(result.get("file_type"))]]
    for k, v in app_info.items():
        rows.append([k.replace("_", " ").title(), _safe(v)])
    st.append(_tbl(rows))
    st.append(Spacer(1, 8))

    # ── SECTION: CERTIFICATE ──────────────────────────────────
    cert = result.get("certificate") or {}
    st.append(_p("Certificate", S["h2"]))
    if cert and not cert.get("error"):
        rows = [
            ["Field", "Value"],
            ["Issuer",      _safe(cert.get("issuer"))],
            ["Subject",     _safe(cert.get("subject"))],
            ["Debug Cert",  "YES — Suspicious" if cert.get("is_debug") else "No"],
            ["Self-Signed", "YES"              if cert.get("is_self_signed") else "No"],
            ["SHA1",        _safe(cert.get("sha1"))],
            ["Notice",      _safe(cert.get("notice"))],
        ]
        st.append(_tbl(rows))
    else:
        st.append(_na(S["none"]))
    st.append(Spacer(1, 8))

    # ── SECTION: PERMISSIONS ──────────────────────────────────
    st.append(_p("Dangerous Permissions", S["h2"]))
    perms    = result.get("permissions") or {}
    dangerous= perms.get("dangerous") or {}
    prows    = [["Permission", "Risk", "Explanation"]]
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        for p in (dangerous.get(level) or []):
            prows.append([
                _safe(p.get("short") or p.get("permission", "").split(".")[-1]),
                level,
                _safe(p.get("explanation")),
            ])
    if len(prows) > 1:
        st.append(_tbl_risk(prows, risk_col=1))
    else:
        st.append(_na(S["none"]))
    st.append(Spacer(1, 8))

    # ── SECTION: SUSPICIOUS APIs ──────────────────────────────
    st.append(_p("Suspicious API Calls", S["h2"]))
    apis = result.get("suspicious_apis") or result.get("imports") or []
    if apis:
        arows = [["API / Function", "Risk", "Explanation"]]
        for a in apis[:30]:
            arows.append([
                _safe(a.get("api") or a.get("function")),
                _safe(a.get("risk")),
                _safe(a.get("explanation")),
            ])
        st.append(_tbl_risk(arows, risk_col=1))
    else:
        st.append(_na(S["none"]))
    st.append(Spacer(1, 8))

    # ── SECTION: BEHAVIORS ────────────────────────────────────
    st.append(_p("Correlated Attack Behaviors", S["h2"]))
    behaviors = result.get("behaviors") or []
    if behaviors:
        brows = [["Behavior", "Severity", "MITRE", "Indicators"]]
        for b in behaviors:
            brows.append([
                _safe(b.get("name")),
                _safe(b.get("severity")),
                _safe(b.get("mitre")),
                _safe(", ".join(b.get("indicators") or [])),
            ])
        st.append(_tbl_risk(brows, risk_col=1))
    else:
        st.append(_na(S["none"]))
    st.append(Spacer(1, 8))

    # ── SECTION: NETWORK INDICATORS ───────────────────────────
    st.append(_p("Network Indicators", S["h2"]))
    net = result.get("network_indicators") or {}

    # Public IPs
    st.append(_p("Public IP Addresses (OSINT)", S["h3"]))
    enr = result.get("enriched_ips") or []
    pub_ips = net.get("hardcoded_ips") or []
    if enr:
        irows = [["IP", "Country", "City", "ISP", "Abuse Score", "Verdict"]]
        for ip in enr:
            score = ip.get("abuse_score") or 0
            irows.append([
                _safe(ip.get("ip")),
                _safe(ip.get("country")),
                _safe(ip.get("city")),
                _safe(ip.get("isp")),
                f"{score}/100",
                "MALICIOUS" if ip.get("is_malicious_ip") else "Clean",
            ])
        st.append(_tbl(irows))
    elif pub_ips:
        st.append(_p(", ".join(pub_ips), S["mono"]))
    else:
        st.append(_na(S["none"]))
    st.append(Spacer(1, 5))

    # Private IPs
    priv = net.get("private_ips") or []
    st.append(_p("Private / Internal IPs", S["h3"]))
    if priv:
        st.append(_p(", ".join(priv), S["mono"]))
    else:
        st.append(_na(S["none"]))
    st.append(Spacer(1, 5))

    # URLs
    st.append(_p("Hardcoded URLs", S["h3"]))
    urls = net.get("hardcoded_urls") or []
    if urls:
        urows = [["URL", "Suspicious TLD"]]
        for u in urls[:20]:
            urows.append([
                _safe(u.get("url"))[:90],
                "YES" if u.get("suspicious_tld") else "No",
            ])
        st.append(_tbl(urows))
    else:
        st.append(_na(S["none"]))
    st.append(Spacer(1, 5))

    # Domains
    st.append(_p("Extracted Domains", S["h3"]))
    domains = net.get("domains") or []
    if domains:
        st.append(_p(", ".join(domains[:30]), S["mono"]))
    else:
        st.append(_na(S["none"]))
    st.append(Spacer(1, 5))

    # Phone numbers
    st.append(_p("Hardcoded Phone Numbers", S["h3"]))
    phones = net.get("phone_numbers") or []
    if phones:
        st.append(_p(", ".join(phones[:20]), S["mono"]))
    else:
        st.append(_na(S["none"]))
    st.append(Spacer(1, 8))

    # ── SECTION: STRING INTELLIGENCE ─────────────────────────
    st.append(_p("String Intelligence", S["h2"]))
    strings = result.get("string_intelligence") or {}

    st.append(_p("Telegram Bot Tokens", S["h3"]))
    tg = strings.get("telegram_tokens") or []
    if tg:
        for t in tg:
            st.append(_p(f"  {_safe(t)}", S["mono"]))
    else:
        st.append(_na(S["none"]))

    st.append(_p("Firebase Configs", S["h3"]))
    fb = strings.get("firebase_configs") or []
    if fb:
        for f in fb:
            st.append(_p(f"  {_safe(f)}", S["mono"]))
    else:
        st.append(_na(S["none"]))

    st.append(_p("Hardcoded Credentials", S["h3"]))
    creds = strings.get("hardcoded_credentials") or []
    if creds:
        crows = [["Key", "Value (Partial)"]]
        for c in creds:
            crows.append([_safe(c.get("key")), _safe(c.get("value"))])
        st.append(_tbl(crows))
    else:
        st.append(_na(S["none"]))
    st.append(Spacer(1, 8))

    # ── SECTION: OBFUSCATION ──────────────────────────────────
    obf = result.get("obfuscation") or {}
    if obf:
        st.append(_p("Obfuscation Analysis", S["h2"]))
        flags = obf.get("flags") or []
        if flags:
            for fl in flags:
                st.append(_p(f"  {_safe(fl)}", S["body"]))
        else:
            st.append(_na(S["none"]))
        st.append(Spacer(1, 8))

    # ── SECTION: SCORING RULES ────────────────────────────────
    st.append(_p("Verdict Scoring Rules", S["h2"]))
    fired = vi.get("fired_rules") or []
    if fired:
        rrows = [["Rule", "Description", "Impact", "Type"]]
        for r in fired:
            rrows.append([
                _safe(r.get("rule")),
                _safe(r.get("label")),
                _safe(r.get("impact")),
                _safe(r.get("type")),
            ])
        st.append(_tbl(rrows))
    else:
        st.append(_na(S["none"]))
    st.append(Spacer(1, 8))

    # ── SECTION: PE (Windows only) ────────────────────────────
    if result.get("sections") or result.get("pdb_path"):
        st.append(_p("PE Analysis (Windows)", S["h2"]))
        if result.get("pdb_path"):
            st.append(_p(f"PDB Path: {_safe(result.get('pdb_path'))}", S["mono"]))
        sections = result.get("sections") or []
        if sections:
            srows = [["Section", "Virtual Address", "Size", "Entropy", "Packed?"]]
            for sec in sections:
                srows.append([
                    _safe(sec.get("name")),
                    _safe(sec.get("virtual_address")),
                    _safe(sec.get("raw_size")),
                    _safe(sec.get("entropy")),
                    "YES" if sec.get("is_packed") else "No",
                ])
            st.append(_tbl(srows))
        st.append(Spacer(1, 8))

    # ── FOOTER ────────────────────────────────────────────────
    st.append(Spacer(1, 16))
    st.append(HRFlowable(width="100%", thickness=1, color=C_BORDER))
    st.append(_p(
        "DoubleCheck Intel Platform v2.1 — For authorized forensic use only.",
        S["footer"]
    ))

    doc.build(st)
    return buf.getvalue()
