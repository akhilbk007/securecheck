"""Checks on the HTML of the page itself.

The page is parsed with the standard library's HTMLParser and nothing in it
is ever executed. Only tags and attributes are read.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from ..models import FAIL, INFO, PASS, WARN, Finding

CAT = "Page content"
MAX_TAGS = 5000


class _Collector(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.scripts: list[tuple[str, bool]] = []      # (src, has integrity)
        self.styles: list[tuple[str, bool]] = []
        self.active: list[str] = []                    # iframes
        self.passive: list[str] = []                   # images, media
        self.forms: list[str] = []
        self.meta_csp: str | None = None
        self._count = 0

    def handle_starttag(self, tag, attrs):
        self._count += 1
        if self._count > MAX_TAGS:
            return
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "script" and a.get("src"):
            self.scripts.append((a["src"].strip(), bool(a.get("integrity"))))
        elif tag == "link" and "stylesheet" in a.get("rel", "").lower() and a.get("href"):
            self.styles.append((a["href"].strip(), bool(a.get("integrity"))))
        elif tag == "iframe" and a.get("src"):
            self.active.append(a["src"].strip())
        elif tag in ("img", "audio", "video", "source") and a.get("src"):
            self.passive.append(a["src"].strip())
        elif tag == "form" and a.get("action"):
            self.forms.append(a["action"].strip())
        elif (tag == "meta" and a.get("http-equiv", "").lower() == "content-security-policy"
              and a.get("content") and self.meta_csp is None):
            self.meta_csp = a["content"]


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _same_site(host: str, page_host: str) -> bool:
    base = page_host[4:] if page_host.startswith("www.") else page_host
    return host == page_host or host == base or host.endswith("." + base)


def _short(items: list[str], limit: int = 6) -> str:
    unique = list(dict.fromkeys(items))
    return ", ".join(unique[:limit]) + (f" and {len(unique) - limit} more" if len(unique) > limit else "")


_LIB = re.compile(r"(jquery|bootstrap|angular(?:\.js|js)?)(?:@|[/.-])v?(\d+)\.(\d+)(?:\.(\d+))?", re.I)


def _vulnerable(name: str, v: tuple[int, int, int]) -> str | None:
    name = name.lower()
    if name == "jquery" and v < (3, 5, 0):
        return "jQuery before 3.5.0 allows cross-site scripting through HTML it processes (CVE-2020-11022)"
    if name == "bootstrap" and (v < (3, 4, 1) or (4, 0, 0) <= v < (4, 3, 1)):
        return "Bootstrap before 3.4.1 / 4.3.1 allows cross-site scripting in tooltips (CVE-2019-8331)"
    if name.startswith("angular") and v[0] == 1:
        return "AngularJS 1.x reached end of life in 2022 and no longer receives security fixes"
    return None


def analyse_page(body: bytes, page_url: str, content_type: str | None) -> tuple[list[Finding], str | None]:
    """Return findings for the page HTML, plus any CSP set by a <meta> tag."""
    if "html" not in (content_type or "").lower():
        return [], None
    parser = _Collector()
    try:
        parser.feed(body.decode("utf-8", "replace"))
    except Exception:  # hostile or broken markup must not break the scan
        return [], None

    page_host = _host(page_url)
    https = page_url.lower().startswith("https://")
    full = lambda u: urljoin(page_url, u)  # noqa: E731

    scripts = [(full(u), sri) for u, sri in parser.scripts]
    styles = [(full(u), sri) for u, sri in parser.styles]
    findings: list[Finding] = []

    # 1. Third-party code without Subresource Integrity
    external = [(u, sri) for u, sri in scripts + styles
                if _host(u) and not _same_site(_host(u), page_host)]
    unpinned = [_host(u) for u, sri in external if not sri]
    title = "Third-party code is pinned to a known version (SRI)"
    if not external:
        findings.append(Finding("sri", CAT, title, PASS,
                                "The page loads no scripts or stylesheets from other sites."))
    elif unpinned:
        findings.append(Finding(
            "sri", CAT, title, WARN,
            f"{len(unpinned)} script(s) or stylesheet(s) from other sites load without an integrity "
            "hash. If one of those hosts is compromised, its code runs on this site unchecked.",
            penalty=4, severity="low",
            fix='Add integrity="sha384-..." and crossorigin="anonymous" to tags that load fixed '
                "versions from a CDN, or host the files yourself.",
            evidence=_short(unpinned),
            reference="https://developer.mozilla.org/docs/Web/Security/Subresource_Integrity",
        ))
    else:
        findings.append(Finding("sri", CAT, title, PASS,
                                "Every script and stylesheet from another site carries an integrity hash."))

    # 2. Mixed content
    title = "Everything on the page loads over HTTPS"
    if https:
        is_http = lambda u: u.lower().startswith("http://")  # noqa: E731
        active = [u for u, _ in scripts + styles if is_http(u)]
        active += [full(u) for u in parser.active if is_http(full(u))]
        forms = [full(u) for u in parser.forms if is_http(full(u))]
        passive = [full(u) for u in parser.passive if is_http(full(u))]
        if active or forms:
            what = []
            if active:
                what.append(f"{len(active)} script, stylesheet or frame address(es)")
            if forms:
                what.append(f"{len(forms)} form(s) that submit")
            findings.append(Finding(
                "mixed-content", CAT, title, FAIL,
                "The page is served securely but references " + " and ".join(what) +
                " over plain HTTP. Browsers block the resources, and form data would travel unencrypted.",
                penalty=8, severity="medium",
                fix="Change every http:// address in the page to https://.",
                evidence=_short(active + forms, 4),
            ))
        elif passive:
            findings.append(Finding(
                "mixed-content", CAT, title, WARN,
                f"{len(passive)} image or media file(s) are referenced over plain HTTP.",
                penalty=4, severity="low", fix="Change the addresses to https://.",
                evidence=_short(passive, 4),
            ))
        else:
            findings.append(Finding("mixed-content", CAT, title, PASS,
                                    "No resources or forms on the page use plain HTTP."))

    # 3. Known-vulnerable JavaScript libraries, identified from file addresses only
    title = "JavaScript libraries are up to date"
    problems, seen = [], []
    for url, _ in scripts:
        for m in _LIB.finditer(urlsplit(url).path):
            version = (int(m.group(2)), int(m.group(3)), int(m.group(4) or 0))
            label = f"{m.group(1)} {'.'.join(str(n) for n in version)}"
            seen.append(label)
            reason = _vulnerable(m.group(1), version)
            if reason:
                problems.append(f"{label}: {reason}")
    if problems:
        findings.append(Finding(
            "js-libraries", CAT, title, FAIL,
            "The page loads library versions with published security flaws.",
            penalty=8, severity="medium",
            fix="Upgrade to the current release of each library.",
            evidence="; ".join(dict.fromkeys(problems)),
        ))
    else:
        detail = ("Versions seen: " + _short(seen) + "." if seen else
                  "No versioned jQuery, Bootstrap or AngularJS files were found in script addresses.")
        findings.append(Finding("js-libraries", CAT, title, PASS,
                                detail + " This check reads file names only, so bundled copies are not detected."))

    # 4. Inventory of third-party script hosts
    hosts = list(dict.fromkeys(_host(u) for u, _ in scripts
                               if _host(u) and not _same_site(_host(u), page_host)))
    if hosts:
        findings.append(Finding(
            "third-party", CAT, "Other sites that run code on this page", INFO,
            f"Scripts load from {len(hosts)} other host(s). Each one can read and change anything on the page.",
            evidence=_short(hosts, 10),
        ))
    return findings, parser.meta_csp
