from app.checks import headers as H
from app.checks.content import analyse_page
from app.models import FAIL, INFO, PASS, WARN
from app.report import build_pdf

HTML = "text/html; charset=utf-8"


def by_id(html, url="https://example.com/"):
    findings, meta = analyse_page(html.encode(), url, HTML)
    return {f.id: f for f in findings}, meta


def test_clean_page_passes():
    f, meta = by_id('<script src="/app.js"></script><link rel="stylesheet" href="style.css"><img src="/a.png">')
    assert f["sri"].status == PASS
    assert f["mixed-content"].status == PASS
    assert f["js-libraries"].status == PASS
    assert "third-party" not in f and meta is None


def test_third_party_script_without_integrity():
    f, _ = by_id('<script src="https://cdn.example.net/lib.js"></script>')
    assert f["sri"].status == WARN and "cdn.example.net" in f["sri"].evidence
    assert f["third-party"].status == INFO
    pinned, _ = by_id('<script src="https://cdn.example.net/lib.js" integrity="sha384-abc"></script>')
    assert pinned["sri"].status == PASS
    # a subdomain of the same site is not third party
    own, _ = by_id('<script src="https://static.example.com/lib.js"></script>', "https://www.example.com/")
    assert own["sri"].status == PASS


def test_mixed_content():
    active, _ = by_id('<script src="http://example.com/a.js"></script>')
    assert active["mixed-content"].status == FAIL
    form, _ = by_id('<form action="http://example.com/login"></form>')
    assert form["mixed-content"].status == FAIL
    passive, _ = by_id('<img src="http://example.com/a.png">')
    assert passive["mixed-content"].status == WARN


def test_outdated_libraries():
    for src in ["/js/jquery-1.12.4.min.js", "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.3.1/jquery.min.js",
                "https://cdn.jsdelivr.net/npm/bootstrap@4.1.3/dist/js/bootstrap.min.js",
                "https://ajax.googleapis.com/ajax/libs/angularjs/1.6.9/angular.min.js"]:
        f, _ = by_id(f'<script src="{src}"></script>')
        assert f["js-libraries"].status == FAIL, src
    for src in ["/js/jquery-3.7.1.min.js", "https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.min.js",
                "/js/jquery-ui-1.12.1.js", "/js/jquery.min.js"]:
        f, _ = by_id(f'<script src="{src}"></script>')
        assert f["js-libraries"].status == PASS, src


def test_meta_csp_and_non_html():
    _, meta = by_id('<meta http-equiv="Content-Security-Policy" content="default-src \'self\'">')
    assert meta == "default-src 'self'"
    assert H.check_csp(meta, from_meta=True).status == PASS
    assert analyse_page(b"{}", "https://example.com/", "application/json") == ([], None)


def test_hostile_markup_does_not_break_parsing():
    junk = "<script src=" + "<" * 5000 + "><<<!-- <img src='http://x/" + "a" * 10000
    findings, _ = analyse_page(junk.encode(), "https://example.com/", HTML)
    assert isinstance(findings, list)


def test_coop_and_deprecated_headers():
    assert H.check_coop("same-origin").status == PASS
    assert H.check_coop(None).status == WARN
    assert H.check_coop("unsafe-none").status == WARN
    assert H.check_deprecated(None) is None
    assert H.check_deprecated("0") is None
    assert H.check_deprecated("1; mode=block").status == WARN


def test_pdf_report_survives_hostile_values():
    result = {
        "host": "example.com", "ip": "93.184.216.34", "final_url": "https://example.com/",
        "scanned_at": "2026-11-16T12:00:00+00:00", "score": 61, "grade": "C",
        "counts": {"pass": 1, "warn": 1, "fail": 1, "info": 0},
        "tls": {"negotiated": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
                "protocols": {"TLS 1.2": True, "TLS 1.3": True},
                "certificate": {"issuer": "<b>Evil & Co</b>", "expires": "2027-01-01", "days_left": 40,
                                "key": "RSA 2048-bit", "signature": "sha256"}},
        "categories": ["Encryption", "Browser protections"],
        "findings": [
            {"id": "a", "category": "Browser protections", "title": "T <script>", "status": "fail",
             "severity": "high", "penalty": 10, "detail": "d & </para><b>",
             "evidence": "x" * 500 + " 中文 <font color='red'>\x00\x07", "fix": "<i>fix", "reference": "https://example.com/?a=1&b=2"},
            {"id": "b", "category": "Encryption", "title": "ok", "status": "pass", "severity": "low",
             "penalty": 0, "detail": "fine", "evidence": "", "fix": "", "reference": ""},
        ],
    }
    pdf = build_pdf(result)
    assert pdf.startswith(b"%PDF") and len(pdf) > 2000


def test_compliance_mapping_is_consistent():
    from app.compliance import FRAMEWORKS, MAPPING, controls_for, summarise

    # every mapped control exists in its framework
    for finding_id, frameworks in MAPPING.items():
        for framework, ids in frameworks.items():
            for cid in ids:
                assert cid in FRAMEWORKS[framework], (finding_id, framework, cid)
    assert {c["id"] for c in controls_for("tls-legacy")} >= {"A.8.24", "CC6.7", "4.2.1", "A02"}
    assert controls_for("no-such-check") == []

    findings = [
        {"id": "hsts", "title": "HSTS", "status": "fail"},
        {"id": "tls-13", "title": "TLS 1.3", "status": "pass"},
        {"id": "dmarc", "title": "DMARC", "status": "warn"},
        {"id": "cookies", "title": "Cookies", "status": "info"},
    ]
    summary = {fw["framework"]: fw for fw in summarise(findings)}
    iso = {c["id"]: c for c in summary["ISO 27001:2022"]["controls"]}
    assert iso["A.8.24"]["status"] == "fail"          # worst result wins
    assert iso["A.5.14"]["status"] == "warn"
    assert iso["A.8.24"]["checks"][0]["status"] == "fail"
    pci = {c["id"]: c["status"] for c in summary["PCI DSS v4.0"]["controls"]}
    assert pci == {"4.2.1": "fail", "5.4.1": "warn"}
