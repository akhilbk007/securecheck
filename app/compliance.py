"""Maps each check to the controls it relates to in common security frameworks.

The mapping is indicative. A passive web scan can show evidence for or
against part of a control, but it never demonstrates compliance on its own:
every control here also covers people, processes and systems a scan cannot see.
"""
from __future__ import annotations

FRAMEWORKS: dict[str, dict[str, str]] = {
    "ISO 27001:2022": {
        "A.5.14": "Information transfer",
        "A.5.21": "Managing information security in the ICT supply chain",
        "A.6.8": "Information security event reporting",
        "A.8.5": "Secure authentication",
        "A.8.8": "Management of technical vulnerabilities",
        "A.8.9": "Configuration management",
        "A.8.12": "Data leakage prevention",
        "A.8.20": "Networks security",
        "A.8.24": "Use of cryptography",
        "A.8.26": "Application security requirements",
        "A.8.28": "Secure coding",
    },
    "SOC 2": {
        "CC2.3": "Communication with external parties",
        "CC6.1": "Logical access security",
        "CC6.6": "Protection against threats from outside the system boundary",
        "CC6.7": "Protection of information during transmission",
        "CC6.8": "Prevention and detection of unauthorised or malicious software",
        "CC7.1": "Detection of vulnerabilities and configuration changes",
        "CC9.2": "Vendor and business partner risk management",
    },
    "PCI DSS v4.0": {
        "2.2": "System components are configured and managed securely",
        "4.2.1": "Strong cryptography protects data sent over open, public networks",
        "5.4.1": "Mechanisms detect and protect personnel against phishing",
        "6.2.4": "Software is engineered to prevent common attacks",
        "6.3.1": "Security vulnerabilities are identified and managed",
        "6.3.3": "Components are protected from known vulnerabilities by patching",
        "6.4.3": "Scripts loaded in the browser are authorised and their integrity assured",
    },
    "OWASP Top 10 (2021)": {
        "A01": "Broken Access Control",
        "A02": "Cryptographic Failures",
        "A03": "Injection",
        "A05": "Security Misconfiguration",
        "A06": "Vulnerable and Outdated Components",
        "A07": "Identification and Authentication Failures",
        "A08": "Software and Data Integrity Failures",
    },
}

ISO, SOC, PCI, OWASP = FRAMEWORKS.keys()

_TRANSPORT = {ISO: ["A.8.24", "A.5.14"], SOC: ["CC6.7"], PCI: ["4.2.1"], OWASP: ["A02"]}
_HARDENING = {ISO: ["A.8.9", "A.8.26"], SOC: ["CC6.6", "CC7.1"], PCI: ["2.2"], OWASP: ["A05"]}

MAPPING: dict[str, dict[str, list[str]]] = {
    # Encryption
    "tls-available": _TRANSPORT,
    "cert-trusted": _TRANSPORT,
    "cert-expiry": _TRANSPORT,
    "cert-strength": _TRANSPORT,
    "tls-legacy": _TRANSPORT,
    "tls-13": _TRANSPORT,
    "tls-fs": _TRANSPORT,
    "http-redirect": _TRANSPORT,
    "hsts": {ISO: ["A.8.24", "A.8.9"], SOC: ["CC6.7"], PCI: ["4.2.1"], OWASP: ["A02", "A05"]},
    "mixed-content": _TRANSPORT,
    # Browser protections
    "csp": {ISO: ["A.8.26", "A.8.28"], SOC: ["CC6.6", "CC6.8"], PCI: ["6.2.4", "6.4.3"], OWASP: ["A03", "A05"]},
    "framing": {ISO: ["A.8.26"], SOC: ["CC6.6"], PCI: ["6.2.4"], OWASP: ["A05"]},
    "nosniff": _HARDENING,
    "permissions": _HARDENING,
    "coop": _HARDENING,
    "deprecated-headers": _HARDENING,
    "disclosure": {ISO: ["A.8.9"], SOC: ["CC7.1"], PCI: ["2.2"], OWASP: ["A05"]},
    "referrer": {ISO: ["A.8.12", "A.8.9"], SOC: ["CC6.6"], PCI: ["2.2"], OWASP: ["A05"]},
    "cors": {ISO: ["A.8.26"], SOC: ["CC6.1", "CC6.6"], PCI: ["6.2.4"], OWASP: ["A01", "A05"]},
    # Cookies
    "cookie-secure": {ISO: ["A.8.5", "A.8.24"], SOC: ["CC6.1", "CC6.7"], PCI: ["6.2.4"], OWASP: ["A02", "A07"]},
    "cookie-httponly": {ISO: ["A.8.5", "A.8.26"], SOC: ["CC6.1"], PCI: ["6.2.4"], OWASP: ["A07"]},
    "cookie-samesite": {ISO: ["A.8.5", "A.8.26"], SOC: ["CC6.1"], PCI: ["6.2.4"], OWASP: ["A01"]},
    # Page content
    "sri": {ISO: ["A.5.21", "A.8.26"], SOC: ["CC9.2", "CC6.8"], PCI: ["6.4.3"], OWASP: ["A08"]},
    "third-party": {ISO: ["A.5.21"], SOC: ["CC9.2"], PCI: ["6.4.3"], OWASP: ["A08"]},
    "js-libraries": {ISO: ["A.8.8"], SOC: ["CC7.1"], PCI: ["6.3.3"], OWASP: ["A06"]},
    # Domain and email
    "spf": {ISO: ["A.5.14"], SOC: ["CC6.6"], PCI: ["5.4.1"]},
    "dmarc": {ISO: ["A.5.14"], SOC: ["CC6.6"], PCI: ["5.4.1"]},
    "mta-sts": {ISO: ["A.5.14", "A.8.24"], SOC: ["CC6.7"]},
    "caa": {ISO: ["A.8.24"], SOC: ["CC6.1"]},
    "dnssec": {ISO: ["A.8.20"], SOC: ["CC6.6"]},
    "security-txt": {ISO: ["A.6.8", "A.8.8"], SOC: ["CC2.3"], PCI: ["6.3.1"]},
}

_RANK = {"fail": 0, "warn": 1, "pass": 2}


def controls_for(finding_id: str) -> list[dict]:
    """Controls related to one check, as [{framework, id, name}]."""
    out = []
    for framework, ids in MAPPING.get(finding_id, {}).items():
        for cid in ids:
            out.append({"framework": framework, "id": cid, "name": FRAMEWORKS[framework][cid]})
    return out


def summarise(findings: list[dict]) -> list[dict]:
    """Per framework: each control touched by this scan and its worst result."""
    summary = []
    for framework, names in FRAMEWORKS.items():
        controls = []
        for cid, name in names.items():
            related = [f for f in findings
                       if cid in MAPPING.get(f["id"], {}).get(framework, [])
                       and f["status"] in _RANK]
            if not related:
                continue
            worst = min(related, key=lambda f: _RANK[f["status"]])["status"]
            related.sort(key=lambda f: _RANK[f["status"]])
            controls.append({
                "id": cid, "name": name, "status": worst,
                "checks": [{"title": f["title"], "status": f["status"]} for f in related],
            })
        counts = {s: sum(1 for c in controls if c["status"] == s) for s in ("fail", "warn", "pass")}
        summary.append({"framework": framework, "controls": controls, "counts": counts})
    return summary
