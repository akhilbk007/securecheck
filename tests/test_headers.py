from app.checks import headers as H
from app.checks.dns import check_dmarc, check_spf
from app.models import FAIL, INFO, PASS, WARN, Finding
from app.scanner import grade_for, score_findings


def test_hsts():
    assert H.check_hsts(None).status == FAIL
    assert H.check_hsts("max-age=300").status == WARN
    assert H.check_hsts("max-age=31536000; includeSubDomains; preload").status == PASS


def test_csp():
    assert H.check_csp(None).status == FAIL
    assert H.check_csp(None, "default-src 'self'").status == WARN
    assert H.check_csp("default-src 'self'; script-src 'self' 'unsafe-inline'").status == WARN
    assert H.check_csp("script-src *").status == WARN
    assert H.check_csp("img-src 'self'").status == WARN
    assert H.check_csp("default-src 'self'; object-src 'none'").status == PASS
    # a nonce makes 'unsafe-inline' ignored by modern browsers
    assert H.check_csp("script-src 'nonce-abc' 'unsafe-inline'").status == PASS


def test_framing():
    assert H.check_framing(None, None).status == FAIL
    assert H.check_framing("DENY", None).status == PASS
    assert H.check_framing("ALLOWALL", None).status == FAIL
    assert H.check_framing(None, "frame-ancestors 'none'").status == PASS
    assert H.check_framing(None, "frame-ancestors *").status == FAIL


def test_simple_headers():
    assert H.check_nosniff("nosniff").status == PASS
    assert H.check_nosniff(None).status == FAIL
    assert H.check_referrer("strict-origin-when-cross-origin").status == PASS
    assert H.check_referrer("unsafe-url").status == WARN
    assert H.check_referrer(None).status == WARN
    assert H.check_permissions("camera=()").status == PASS
    assert H.check_disclosure("nginx/1.18.0", None).status == WARN
    assert H.check_disclosure("cloudflare", None).status == PASS
    assert H.check_disclosure(None, "PHP/8.1").status == WARN


def test_cors():
    probe = "https://probe.invalid"
    assert H.check_cors(None, None, probe) is None
    assert H.check_cors(probe, "true", probe).status == FAIL
    assert H.check_cors(probe, None, probe).status == WARN
    assert H.check_cors("*", None, probe).status == INFO
    assert H.check_cors("https://app.example.com", "true", probe).status == PASS


def test_cookies():
    assert H.check_cookies([])[0].status == INFO
    good = H.check_cookies(["sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax"])
    assert [f.status for f in good] == [PASS, PASS, PASS]
    bad = {f.id: f for f in H.check_cookies(["sid=abc; Path=/", "t=1; Secure; SameSite=None"])}
    assert bad["cookie-secure"].status == FAIL
    assert bad["cookie-secure"].evidence == "sid"
    assert bad["cookie-httponly"].status == WARN
    assert bad["cookie-samesite"].status == WARN


def test_spf_and_dmarc():
    assert check_spf([], "example.com").status == WARN
    assert check_spf(None, "example.com").status == INFO
    assert check_spf(["v=spf1 +all"], "example.com").status == FAIL
    assert check_spf(["v=spf1 include:_spf.google.com ~all"], "example.com").status == PASS
    assert check_spf(["v=spf1 -all", "v=spf1 ~all"], "example.com").status == WARN
    assert check_dmarc([], "example.com").status == WARN
    assert check_dmarc(["v=DMARC1; p=none"], "example.com").status == WARN
    assert check_dmarc(["v=DMARC1; p=reject; rua=mailto:a@example.com"], "example.com").status == PASS


def test_scoring_and_grades():
    assert grade_for(100) == "A+" and grade_for(85) == "A" and grade_for(39) == "F"
    ok = Finding("x", "Encryption", "t", PASS, "d", penalty=10)
    assert score_findings([ok]) == 100
    fail = Finding("x", "Encryption", "t", FAIL, "d", penalty=10)
    warn = Finding("y", "Encryption", "t", WARN, "d", penalty=10)
    assert score_findings([fail, warn]) == 85
    # an untrusted certificate caps the score however good the headers are
    cert = Finding("cert-trusted", "Encryption", "t", FAIL, "d", penalty=30)
    assert score_findings([cert]) == 45
    no_tls = Finding("tls-available", "Encryption", "t", FAIL, "d", penalty=40)
    assert score_findings([no_tls]) == 30
