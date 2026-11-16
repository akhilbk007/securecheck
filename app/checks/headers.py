"""HTTP response header and cookie checks.

Every function here is pure: it takes header values and returns findings,
which keeps the logic easy to unit test.
"""
from __future__ import annotations

import re

from ..models import FAIL, INFO, PASS, WARN, Finding

CAT = "Browser protections"
CAT_COOKIES = "Cookies"
OWASP = "https://owasp.org/www-project-secure-headers/"
SIX_MONTHS = 15552000


def check_hsts(value: str | None) -> Finding:
    title = "HTTPS is enforced on return visits (HSTS)"
    if not value:
        return Finding(
            "hsts", CAT, title, FAIL,
            "No Strict-Transport-Security header. An attacker on the same network can downgrade "
            "a visitor to plain HTTP and intercept the session.",
            penalty=10, severity="medium",
            fix="Send: Strict-Transport-Security: max-age=31536000; includeSubDomains",
            reference=OWASP,
        )
    m = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.I)
    max_age = int(m.group(1)) if m else 0
    if max_age < SIX_MONTHS:
        return Finding(
            "hsts", CAT, title, WARN,
            f"HSTS is set but only for {max_age // 86400} days. Short lifetimes leave gaps in "
            "which a downgrade is possible.",
            penalty=8, severity="low",
            fix="Raise max-age to at least 31536000 (one year).",
            evidence=value, reference=OWASP,
        )
    extras = []
    if "includesubdomains" in value.lower():
        extras.append("covers subdomains")
    if "preload" in value.lower():
        extras.append("preload requested")
    return Finding(
        "hsts", CAT, title, PASS,
        f"Browsers will insist on HTTPS for {max_age // 86400} days"
        + (f" ({', '.join(extras)})." if extras else "."),
        evidence=value,
    )


def parse_csp(value: str) -> dict[str, list[str]]:
    policy: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if tokens:
            policy.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return policy


def check_csp(value: str | None, report_only: str | None = None) -> Finding:
    title = "Content Security Policy limits injected scripts"
    if not value:
        detail = ("No Content-Security-Policy header. If an attacker manages to inject script "
                  "into a page (XSS), nothing stops it from running.")
        if report_only:
            detail = ("A policy is present in report-only mode, so violations are logged but "
                      "nothing is blocked yet.")
        return Finding(
            "csp", CAT, title, WARN if report_only else FAIL, detail,
            penalty=10, severity="medium",
            fix="Start with: Content-Security-Policy: default-src 'self'; object-src 'none'; "
                "base-uri 'self'; frame-ancestors 'none' and loosen only where needed.",
            evidence=report_only or "", reference="https://developer.mozilla.org/docs/Web/HTTP/CSP",
        )
    policy = parse_csp(value)
    script = policy.get("script-src", policy.get("default-src"))
    problems = []
    if script is None:
        problems.append("there is no script-src or default-src, so scripts are unrestricted")
    else:
        has_nonce = any(s.startswith("'nonce-") or s.startswith("'sha") for s in script)
        if "'unsafe-inline'" in script and not has_nonce:
            problems.append("'unsafe-inline' allows injected inline scripts to run")
        if "'unsafe-eval'" in script:
            problems.append("'unsafe-eval' allows strings to be executed as code")
        if any(s in ("*", "http:", "https:", "data:") for s in script):
            problems.append("scripts may load from any origin")
    if problems:
        return Finding(
            "csp", CAT, title, WARN,
            "A policy is present, but " + "; ".join(problems) + ".",
            penalty=10, severity="low",
            fix="Replace 'unsafe-inline' with nonces or hashes, and list script origins explicitly.",
            evidence=value, reference="https://csp-evaluator.withgoogle.com/",
        )
    return Finding("csp", CAT, title, PASS,
                   "A policy is present and restricts where scripts can come from.", evidence=value)


def check_framing(xfo: str | None, csp: str | None) -> Finding:
    title = "Page cannot be embedded by other sites (clickjacking)"
    ancestors = parse_csp(csp).get("frame-ancestors") if csp else None
    if ancestors is not None and "*" not in ancestors:
        return Finding("framing", CAT, title, PASS,
                       "The CSP frame-ancestors directive controls who may embed this page.",
                       evidence="frame-ancestors " + " ".join(ancestors))
    if xfo and xfo.strip().lower().split(",")[0].strip() in ("deny", "sameorigin"):
        return Finding("framing", CAT, title, PASS,
                       "X-Frame-Options stops other sites from embedding this page.", evidence=xfo)
    return Finding(
        "framing", CAT, title, FAIL,
        "Any website can load this page inside an invisible frame and trick visitors into "
        "clicking on it.",
        penalty=6, severity="medium",
        fix="Send: Content-Security-Policy: frame-ancestors 'self' (or X-Frame-Options: DENY).",
        evidence=xfo or "", reference=OWASP,
    )


def check_nosniff(value: str | None) -> Finding:
    title = "Browser does not guess file types"
    if value and value.strip().lower() == "nosniff":
        return Finding("nosniff", CAT, title, PASS, "X-Content-Type-Options: nosniff is set.")
    return Finding(
        "nosniff", CAT, title, FAIL,
        "Without X-Content-Type-Options, a browser may treat an uploaded file as script.",
        penalty=4, severity="low", fix="Send: X-Content-Type-Options: nosniff", reference=OWASP,
    )


_GOOD_REFERRER = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin",
                  "origin", "origin-when-cross-origin", "no-referrer-when-downgrade"}
_LEAKY_REFERRER = {"unsafe-url", "no-referrer-when-downgrade", "origin-when-cross-origin"}


def check_referrer(value: str | None) -> Finding:
    title = "Full page addresses are not leaked to other sites"
    if not value:
        return Finding(
            "referrer", CAT, title, WARN,
            "No Referrer-Policy header. Modern browsers fall back to a reasonable default, but "
            "older ones send the full address of the page to every site linked from it.",
            penalty=4, severity="low",
            fix="Send: Referrer-Policy: strict-origin-when-cross-origin", reference=OWASP,
        )
    tokens = [t.strip().lower() for t in value.split(",") if t.strip()]
    effective = next((t for t in reversed(tokens) if t in _GOOD_REFERRER | {"unsafe-url"}), "")
    if effective in _LEAKY_REFERRER:
        return Finding(
            "referrer", CAT, title, WARN,
            f"The policy '{effective}' can send full page addresses, including query strings, "
            "to other sites.",
            penalty=4, severity="low",
            fix="Use strict-origin-when-cross-origin or stricter.", evidence=value,
        )
    return Finding("referrer", CAT, title, PASS, f"Referrer-Policy is {effective or value}.",
                   evidence=value)


def check_permissions(value: str | None) -> Finding:
    title = "Access to camera, microphone and location is restricted"
    if value:
        return Finding("permissions", CAT, title, PASS,
                       "A Permissions-Policy header limits which browser features pages may use.",
                       evidence=value)
    return Finding(
        "permissions", CAT, title, WARN,
        "No Permissions-Policy header. Embedded third-party content can request powerful "
        "browser features.",
        penalty=4, severity="low",
        fix="Send: Permissions-Policy: camera=(), microphone=(), geolocation=()", reference=OWASP,
    )


_VERSION = re.compile(r"\d+\.\d+")


def check_disclosure(server: str | None, powered_by: str | None) -> Finding:
    title = "Server software versions are hidden"
    leaks = []
    if server and _VERSION.search(server):
        leaks.append(f"Server: {server}")
    if powered_by:
        leaks.append(f"X-Powered-By: {powered_by}")
    if leaks:
        return Finding(
            "disclosure", CAT, title, WARN,
            "Response headers reveal the software in use, which helps an attacker match the "
            "site against known vulnerabilities.",
            penalty=4, severity="low",
            fix="Remove X-Powered-By and hide version numbers (nginx: server_tokens off).",
            evidence="; ".join(leaks),
        )
    return Finding("disclosure", CAT, title, PASS,
                   "No software version numbers are exposed in the response headers.",
                   evidence=f"Server: {server}" if server else "")


def check_cors(acao: str | None, acac: str | None, probe_origin: str) -> Finding | None:
    """We sent a made-up Origin. Reflecting it with credentials is dangerous."""
    title = "Other sites cannot read signed-in data (CORS)"
    if not acao:
        return None
    creds = (acac or "").strip().lower() == "true"
    if acao.strip() == probe_origin and creds:
        return Finding(
            "cors", CAT, title, FAIL,
            "The server echoes back any Origin and allows credentials. Any website a signed-in "
            "user visits can read their data from this site.",
            penalty=12, severity="high",
            fix="Check the Origin against an allow-list before echoing it, and never combine "
                "credentials with a reflected origin.",
            evidence=f"Access-Control-Allow-Origin: {acao}; Access-Control-Allow-Credentials: {acac}",
            reference="https://portswigger.net/web-security/cors",
        )
    if acao.strip() == probe_origin:
        return Finding(
            "cors", CAT, title, WARN,
            "The server echoes back any Origin. Without credentials this exposes only public "
            "content, but it is rarely intended.",
            penalty=4, severity="low",
            fix="Return a fixed list of allowed origins.",
            evidence=f"Access-Control-Allow-Origin: {acao}",
        )
    if acao.strip() == "*":
        return Finding("cors", CAT, title, INFO,
                       "This page is readable from any origin (Access-Control-Allow-Origin: *). "
                       "That is fine for public content.", evidence="Access-Control-Allow-Origin: *")
    return Finding("cors", CAT, title, PASS, "Cross-origin access is limited to named origins.",
                   evidence=f"Access-Control-Allow-Origin: {acao}")


def parse_cookie(header: str) -> tuple[str, set[str], str]:
    parts = [p.strip() for p in header.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    flags, samesite = set(), ""
    for p in parts[1:]:
        key, _, val = p.partition("=")
        key = key.strip().lower()
        flags.add(key)
        if key == "samesite":
            samesite = val.strip().lower()
    return name, flags, samesite


def check_cookies(set_cookie: list[str]) -> list[Finding]:
    if not set_cookie:
        return [Finding("cookies", CAT_COOKIES, "Cookies are protected", INFO,
                        "The page set no cookies, so there was nothing to check.")]
    no_secure, no_httponly, no_samesite = [], [], []
    for header in set_cookie[:30]:
        name, flags, samesite = parse_cookie(header)
        if not name:
            continue
        if "secure" not in flags:
            no_secure.append(name)
        if "httponly" not in flags:
            no_httponly.append(name)
        if not samesite or (samesite == "none"):
            no_samesite.append(name)

    out = []

    def names(ns):
        return ", ".join(ns[:6]) + (" and others" if len(ns) > 6 else "")

    if no_secure:
        out.append(Finding(
            "cookie-secure", CAT_COOKIES, "Cookies are only sent over HTTPS", FAIL,
            f"{len(no_secure)} cookie(s) lack the Secure flag and can travel over plain HTTP.",
            penalty=6, severity="medium", fix="Add the Secure attribute to every cookie.",
            evidence=names(no_secure),
        ))
    else:
        out.append(Finding("cookie-secure", CAT_COOKIES, "Cookies are only sent over HTTPS", PASS,
                           "Every cookie has the Secure flag."))
    if no_httponly:
        out.append(Finding(
            "cookie-httponly", CAT_COOKIES, "Cookies are hidden from page scripts", WARN,
            f"{len(no_httponly)} cookie(s) lack HttpOnly. If any of them identifies a session, "
            "an injected script could steal it.",
            penalty=6, severity="low",
            fix="Add HttpOnly to session and authentication cookies.", evidence=names(no_httponly),
        ))
    else:
        out.append(Finding("cookie-httponly", CAT_COOKIES, "Cookies are hidden from page scripts",
                           PASS, "Every cookie has the HttpOnly flag."))
    if no_samesite:
        out.append(Finding(
            "cookie-samesite", CAT_COOKIES, "Cookies are not sent with cross-site requests", WARN,
            f"{len(no_samesite)} cookie(s) have no SameSite restriction, which weakens protection "
            "against cross-site request forgery.",
            penalty=4, severity="low",
            fix="Set SameSite=Lax (or Strict) unless the cookie is needed cross-site.",
            evidence=names(no_samesite),
        ))
    else:
        out.append(Finding("cookie-samesite", CAT_COOKIES,
                           "Cookies are not sent with cross-site requests", PASS,
                           "Every cookie sets SameSite to Lax or Strict."))
    return out
