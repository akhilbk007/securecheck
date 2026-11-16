"""Runs every check against a target and produces a graded report."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from .checks import headers as H
from .checks.content import analyse_page
from .checks.dns import check_dns
from .checks.tls import check_tls
from .compliance import controls_for, summarise
from .fetch import FetchError, Response, fetch, fetch_once
from .models import FAIL, INFO, PASS, WARN, Finding
from .netguard import Target, TargetError, parse_target, resolve_public

PROBE_ORIGIN = "https://cors-probe.securecheck.invalid"
CATEGORY_ORDER = ["Encryption", "Browser protections", "Cookies", "Page content", "Domain and email"]
GRADES = [(95, "A+"), (85, "A"), (70, "B"), (55, "C"), (40, "D"), (0, "F")]


def grade_for(score: int) -> str:
    return next(g for floor, g in GRADES if score >= floor)


def score_findings(findings: list[Finding]) -> int:
    score = 100
    for f in findings:
        if f.status == FAIL:
            score -= f.penalty
        elif f.status == WARN:
            score -= f.penalty // 2
    score = max(score, 0)
    # Broken transport security outweighs everything else on the page.
    by_id = {f.id: f for f in findings}
    if by_id.get("tls-available") and by_id["tls-available"].status == FAIL:
        score = min(score, 30)
    if by_id.get("cert-trusted") and by_id["cert-trusted"].status == FAIL:
        score = min(score, 45)
    return score


def _redirect_finding(host: str) -> Finding:
    title = "Plain HTTP redirects to HTTPS"
    cat = "Encryption"
    try:
        resp = fetch_once(Target("http", host, 80, "/"))
    except TargetError:
        raise
    except FetchError:
        return Finding("http-redirect", cat, title, PASS,
                       "The site does not answer on plain HTTP at all, so nothing can be sent "
                       "unencrypted.")
    location = (resp.header("Location") or "")
    if resp.status in (301, 302, 303, 307, 308) and location.lower().startswith("https://"):
        return Finding("http-redirect", cat, title, PASS,
                       f"Requests to http://{host} are redirected to HTTPS ({resp.status}).",
                       evidence=location)
    return Finding(
        "http-redirect", cat, title, FAIL,
        f"http://{host} serves content without redirecting to HTTPS, so visitors who type the "
        "address without https:// stay on an unencrypted connection.",
        penalty=10, severity="medium",
        fix="Redirect all HTTP requests to HTTPS with a 301. nginx: return 301 https://$host$request_uri;",
        evidence=f"HTTP {resp.status}",
    )


def _security_txt_finding(host: str, port: int) -> Finding:
    title = "Researchers know how to report a vulnerability (security.txt)"
    cat = "Domain and email"
    try:
        resp = fetch(Target("https", host, port, "/.well-known/security.txt").url)
        found = resp.status == 200 and b"contact:" in resp.body.lower()
    except (FetchError, TargetError):
        found = False
    if found:
        return Finding("security-txt", cat, title, PASS,
                       "A security.txt file with contact details is published.")
    return Finding(
        "security-txt", cat, title, WARN,
        "No /.well-known/security.txt file. People who find a flaw have no official way to "
        "tell the owner.",
        penalty=2, severity="low",
        fix="Publish /.well-known/security.txt with at least Contact: and Expires: lines.",
        reference="https://securitytxt.org/",
    )


def _header_findings(resp: Response) -> list[Finding]:
    content, meta_csp = analyse_page(resp.body, resp.url, resp.header("Content-Type"))
    header_csp = resp.header("Content-Security-Policy")
    csp = header_csp or meta_csp
    out = [
        H.check_hsts(resp.header("Strict-Transport-Security")),
        H.check_csp(csp, resp.header("Content-Security-Policy-Report-Only"),
                    from_meta=bool(meta_csp and not header_csp)),
        # frame-ancestors is ignored in a <meta> policy, so only the header counts here
        H.check_framing(resp.header("X-Frame-Options"), header_csp),
        H.check_nosniff(resp.header("X-Content-Type-Options")),
        H.check_referrer(resp.header("Referrer-Policy")),
        H.check_permissions(resp.header("Permissions-Policy")),
        H.check_coop(resp.header("Cross-Origin-Opener-Policy")),
        H.check_disclosure(resp.header("Server"), resp.header("X-Powered-By")),
    ]
    deprecated = H.check_deprecated(resp.header("X-XSS-Protection"))
    if deprecated:
        out.append(deprecated)
    cors = H.check_cors(resp.header("Access-Control-Allow-Origin"),
                        resp.header("Access-Control-Allow-Credentials"), PROBE_ORIGIN)
    if cors:
        out.append(cors)
    out.extend(H.check_cookies(resp.header_all("Set-Cookie")))
    out.extend(content)
    return out


def scan(raw_url: str) -> dict:
    """Scan one site. Raises TargetError for input we refuse to scan."""
    started = time.monotonic()
    target = parse_target(raw_url)
    host = target.host
    tls_port = target.port if target.scheme == "https" else 443
    ip = resolve_public(host, tls_port)  # raises TargetError for internal addresses

    page_url = Target("https", host, tls_port, target.path).url
    probe = {"Origin": PROBE_ORIGIN}

    with ThreadPoolExecutor(max_workers=5) as pool:
        f_tls = pool.submit(check_tls, host, ip, tls_port)
        f_page = pool.submit(fetch, page_url, probe)
        f_redirect = pool.submit(_redirect_finding, host)
        f_dns = pool.submit(check_dns, host)
        f_sectxt = pool.submit(_security_txt_finding, host, tls_port)

        findings, tls_summary = f_tls.result()

        page: Response | None = None
        page_error = ""
        try:
            page = f_page.result()
        except (FetchError, TargetError) as exc:
            page_error = str(exc)
            if not tls_summary.get("available"):
                try:  # no HTTPS at all: read the headers over HTTP instead
                    page = fetch(Target("http", host, 80, target.path).url, probe)
                    page_error = ""
                except (FetchError, TargetError) as exc2:
                    page_error = str(exc2)

        try:
            findings.append(f_redirect.result())
        except TargetError:
            pass
        if page is not None:
            findings.extend(_header_findings(page))
        else:
            findings.append(Finding(
                "page", "Browser protections", "Page could be loaded", INFO,
                f"The page itself could not be fetched, so header checks were skipped. {page_error}",
            ))
        findings.extend(f_dns.result())
        findings.append(f_sectxt.result())

    if page is None and not tls_summary.get("available"):
        raise TargetError(f"{host} could not be reached over HTTP or HTTPS.")

    findings.sort(key=lambda f: CATEGORY_ORDER.index(f.category))
    score = score_findings(findings)
    counts = {s: sum(1 for f in findings if f.status == s) for s in (PASS, WARN, FAIL, INFO)}

    finding_dicts = []
    for f in findings:
        d = f.to_dict()
        d["controls"] = controls_for(f.id)
        finding_dicts.append(d)

    return {
        "host": host,
        "ip": ip,
        "final_url": page.url if page else page_url,
        "http_status": page.status if page else None,
        "redirects": page.redirects if page else [],
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "duration_ms": int((time.monotonic() - started) * 1000),
        "score": score,
        "grade": grade_for(score),
        "counts": counts,
        "tls": tls_summary,
        "categories": CATEGORY_ORDER,
        "findings": finding_dicts,
        "compliance": summarise(finding_dicts),
    }
