"""TLS protocol and certificate checks."""
from __future__ import annotations

import socket
import ssl
import warnings
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from ..models import FAIL, INFO, PASS, WARN, Finding

CAT = "Encryption"
TIMEOUT = 6.0

_VERSIONS = [
    ("TLS 1.0", ssl.TLSVersion.TLSv1),
    ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
    ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
    ("TLS 1.3", ssl.TLSVersion.TLSv1_3),
]


def _probe(ip: str, port: int, host: str, version: ssl.TLSVersion) -> bool | None:
    """True if the server completes a handshake at exactly this version.

    None means the local OpenSSL build cannot offer that version, so the
    result is unknown rather than "not supported".
    """
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            if version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
                # Legacy protocols need the legacy cipher set to be offered at all.
                ctx.set_ciphers("ALL:@SECLEVEL=0")
            ctx.minimum_version = version
            ctx.maximum_version = version
    except (ssl.SSLError, ValueError):
        return None
    try:
        with socket.create_connection((ip, port), TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except ssl.SSLError as exc:
        text = str(exc).upper()
        if "NO_PROTOCOLS_AVAILABLE" in text or "NO_CIPHERS_AVAILABLE" in text:
            return None
        return False
    except OSError:
        return False


def _handshake(ip: str, port: int, host: str, verify: bool):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((ip, port), TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return tls.version(), tls.cipher(), tls.getpeercert(binary_form=True)


def _cert_problem(exc: ssl.SSLCertVerificationError) -> str:
    msg = (exc.verify_message or str(exc)).lower()
    if "expired" in msg:
        return "The certificate has expired."
    if "self-signed" in msg or "self signed" in msg:
        return "The certificate is self-signed, so browsers will not trust it."
    if "hostname mismatch" in msg or "doesn't match" in msg or "ip address mismatch" in msg:
        return "The certificate was issued for a different domain name."
    if "unable to get local issuer" in msg:
        return "The certificate chain is incomplete or issued by an untrusted authority."
    return "Browsers will not trust this certificate."


def check_tls(host: str, ip: str, port: int = 443) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    summary: dict = {"available": False}

    # 1. Can we connect at all, and is the certificate trusted?
    trusted, problem = True, ""
    try:
        version, cipher, der = _handshake(ip, port, host, verify=True)
    except ssl.SSLCertVerificationError as exc:
        trusted, problem = False, _cert_problem(exc)
        try:
            version, cipher, der = _handshake(ip, port, host, verify=False)
        except (OSError, ssl.SSLError):
            version = cipher = der = None
    except (OSError, ssl.SSLError):
        version = cipher = der = None

    if version is None:
        findings.append(Finding(
            "tls-available", CAT, "HTTPS is available", FAIL,
            "The site did not accept a secure (HTTPS) connection on port 443. "
            "Everything visitors send or receive can be read or changed in transit.",
            penalty=40, severity="high",
            fix="Install a TLS certificate (Let's Encrypt is free) and serve the site over HTTPS.",
            reference="https://letsencrypt.org/getting-started/",
        ))
        return findings, summary

    summary.update(available=True, negotiated=version, cipher=cipher[0] if cipher else "")
    findings.append(Finding(
        "tls-available", CAT, "HTTPS is available", PASS,
        f"The site accepts secure connections. This scan negotiated {version.replace('v', ' ')} "
        f"with the cipher {cipher[0]}.",
        evidence=f"{version} / {cipher[0]}",
    ))

    # 2. Certificate trust and details
    if trusted:
        findings.append(Finding(
            "cert-trusted", CAT, "Certificate is trusted", PASS,
            "The certificate is valid for this domain and chains to a trusted authority.",
        ))
    else:
        findings.append(Finding(
            "cert-trusted", CAT, "Certificate is trusted", FAIL,
            problem + " Visitors see a full-page browser warning.",
            penalty=30, severity="high",
            fix="Renew or reissue the certificate for the exact domain name, and serve the full chain "
                "(leaf plus intermediates).",
        ))
    summary["cert_trusted"] = trusted

    if der:
        try:
            findings.extend(_certificate_findings(der, summary))
        except Exception:  # a malformed certificate must not break the scan
            pass

    # 3. Which protocol versions does the server accept?
    supported: dict[str, bool | None] = {}
    for label, ver in _VERSIONS:
        supported[label] = _probe(ip, port, host, ver)
    summary["protocols"] = supported

    legacy = [v for v in ("TLS 1.0", "TLS 1.1") if supported[v]]
    untested = [v for v in ("TLS 1.0", "TLS 1.1") if supported[v] is None]
    if legacy:
        findings.append(Finding(
            "tls-legacy", CAT, "Old TLS versions are switched off", FAIL,
            f"The server still accepts {' and '.join(legacy)}. These versions were formally "
            "deprecated in 2021 (RFC 8996) and fail PCI DSS requirements.",
            penalty=10, severity="medium",
            fix="Set the minimum TLS version to 1.2. nginx: ssl_protocols TLSv1.2 TLSv1.3; "
                "Cloudflare: SSL/TLS > Edge Certificates > Minimum TLS Version.",
            evidence=", ".join(legacy),
            reference="https://datatracker.ietf.org/doc/html/rfc8996",
        ))
    elif untested:
        findings.append(Finding(
            "tls-legacy", CAT, "Old TLS versions are switched off", INFO,
            f"{' and '.join(untested)} could not be tested from this scanner's environment.",
        ))
    else:
        findings.append(Finding(
            "tls-legacy", CAT, "Old TLS versions are switched off", PASS,
            "The server refuses TLS 1.0 and TLS 1.1.",
        ))

    if supported["TLS 1.3"]:
        findings.append(Finding(
            "tls-13", CAT, "TLS 1.3 is supported", PASS,
            "The server supports TLS 1.3, the fastest and most secure version.",
        ))
    elif supported["TLS 1.3"] is False:
        findings.append(Finding(
            "tls-13", CAT, "TLS 1.3 is supported", WARN,
            "The server does not offer TLS 1.3. TLS 1.2 is still acceptable, but 1.3 removes "
            "weak ciphers entirely and connects faster.",
            penalty=6, severity="low",
            fix="Enable TLS 1.3 on the web server or CDN.",
        ))

    name = cipher[0] if cipher else ""
    forward_secret = version == "TLSv1.3" or "ECDHE" in name or "DHE" in name
    if not forward_secret:
        findings.append(Finding(
            "tls-fs", CAT, "Forward secrecy", WARN,
            "The negotiated cipher does not provide forward secrecy, so recorded traffic could be "
            "decrypted later if the server key leaks.",
            penalty=8, severity="medium",
            fix="Prefer ECDHE cipher suites and disable static RSA key exchange.",
            evidence=name,
        ))
    return findings, summary


def _certificate_findings(der: bytes, summary: dict) -> list[Finding]:
    out: list[Finding] = []
    cert = x509.load_der_x509_certificate(der)
    not_after = cert.not_valid_after_utc
    days_left = (not_after - datetime.now(timezone.utc)).days

    def _name(n: x509.Name, oid) -> str:
        attrs = n.get_attributes_for_oid(oid)
        return str(attrs[0].value) if attrs else ""

    issuer = _name(cert.issuer, x509.NameOID.ORGANIZATION_NAME) or _name(cert.issuer, x509.NameOID.COMMON_NAME)
    subject = _name(cert.subject, x509.NameOID.COMMON_NAME)
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_desc, weak_key = f"RSA {key.key_size}-bit", key.key_size < 2048
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_desc, weak_key = f"ECDSA {key.curve.name}", key.key_size < 224
    else:
        key_desc, weak_key = type(key).__name__.replace("PublicKey", ""), False
    sig_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else ""

    summary["certificate"] = {
        "subject": subject, "issuer": issuer,
        "expires": not_after.date().isoformat(), "days_left": days_left,
        "key": key_desc, "signature": sig_hash,
    }

    if days_left < 0:
        pass  # already reported by the trust check
    elif days_left < 14:
        out.append(Finding(
            "cert-expiry", CAT, "Certificate is not about to expire", WARN,
            f"The certificate expires in {days_left} days ({not_after.date().isoformat()}).",
            penalty=10, severity="medium",
            fix="Renew now and automate renewal (certbot, ACME, or a managed certificate).",
        ))
    else:
        out.append(Finding(
            "cert-expiry", CAT, "Certificate is not about to expire", PASS,
            f"Issued by {issuer or 'an unknown authority'}; valid for another {days_left} days "
            f"(until {not_after.date().isoformat()}).",
        ))

    if weak_key or sig_hash in ("sha1", "md5"):
        out.append(Finding(
            "cert-strength", CAT, "Certificate uses strong cryptography", FAIL,
            f"The certificate uses {key_desc} with a {sig_hash.upper()} signature, which is below "
            "current minimums.",
            penalty=10, severity="medium",
            fix="Reissue with RSA 2048-bit or ECDSA P-256 and a SHA-256 signature.",
            evidence=f"{key_desc}, {sig_hash}",
        ))
    else:
        out.append(Finding(
            "cert-strength", CAT, "Certificate uses strong cryptography", PASS,
            f"Key: {key_desc}. Signature: {sig_hash.upper()}.",
        ))
    return out
