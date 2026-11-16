"""DNS-based checks: email spoofing protection (SPF, DMARC) and CAA."""
from __future__ import annotations

import dns.exception
import dns.resolver

from ..models import FAIL, INFO, PASS, WARN, Finding

CAT = "Domain and email"


def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.timeout = 3.0
    r.lifetime = 5.0
    return r


def _txt(resolver, name: str) -> list[str] | None:
    """TXT strings for name; [] if none exist; None if DNS itself failed."""
    try:
        answer = resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.exception.DNSException, OSError):
        return None
    return [b"".join(r.strings).decode("utf-8", "replace") for r in answer]


def _parents(host: str) -> list[str]:
    """host and its parent domains, stopping before the top-level domain."""
    labels = host.split(".")
    return [".".join(labels[i:]) for i in range(0, max(1, len(labels) - 1))]


def check_spf(records: list[str] | None, domain: str) -> Finding:
    title = "Email senders are restricted (SPF)"
    if records is None:
        return Finding("spf", CAT, title, INFO, "DNS could not be queried for this check.")
    spf = [r for r in records if r.lower().startswith("v=spf1")]
    if not spf:
        return Finding(
            "spf", CAT, title, WARN,
            f"No SPF record on {domain}. Anyone can send email that claims to come from this domain.",
            penalty=4, severity="low",
            fix=f'Publish a TXT record on {domain}, for example: "v=spf1 include:_spf.google.com -all" '
                'or "v=spf1 -all" if the domain never sends email.',
        )
    record = spf[0]
    if len(spf) > 1:
        return Finding("spf", CAT, title, WARN,
                       "More than one SPF record is published, which makes SPF fail for all mail.",
                       penalty=4, severity="low", fix="Merge them into a single record.",
                       evidence=" | ".join(spf))
    if "+all" in record.lower() or record.lower().rstrip().endswith(" all"):
        return Finding("spf", CAT, title, FAIL,
                       "The SPF record ends in +all, which authorises every server on the internet.",
                       penalty=4, severity="medium", fix="End the record with -all or ~all.",
                       evidence=record)
    return Finding("spf", CAT, title, PASS, "An SPF record lists who may send email for this domain.",
                   evidence=record)


def check_dmarc(records: list[str] | None, domain: str) -> Finding:
    title = "Forged email is rejected (DMARC)"
    if records is None:
        return Finding("dmarc", CAT, title, INFO, "DNS could not be queried for this check.")
    dmarc = [r for r in records if r.lower().startswith("v=dmarc1")]
    if not dmarc:
        return Finding(
            "dmarc", CAT, title, WARN,
            f"No DMARC record for {domain}. Receiving mail servers get no instruction to reject "
            "phishing email that forges this domain.",
            penalty=6, severity="medium",
            fix=f'Publish a TXT record at _dmarc.{domain}: "v=DMARC1; p=quarantine; rua=mailto:you@{domain}"',
            reference="https://dmarc.org/overview/",
        )
    record = dmarc[0]
    tags = dict(
        (k.strip().lower(), v.strip().lower())
        for k, _, v in (part.partition("=") for part in record.split(";")) if k.strip()
    )
    policy = tags.get("p", "")
    if policy == "none":
        return Finding("dmarc", CAT, title, WARN,
                       "DMARC is in monitoring mode (p=none), so forged email is still delivered.",
                       penalty=3, severity="low",
                       fix="Move to p=quarantine, then p=reject once reports look clean.",
                       evidence=record)
    return Finding("dmarc", CAT, title, PASS, f"DMARC policy is p={policy}.", evidence=record)


def check_dns(host: str) -> list[Finding]:
    resolver = _resolver()
    candidates = _parents(host)

    # SPF and DMARC live on the organisational domain; walk up until found.
    spf_records, spf_domain = None, candidates[-1]
    for name in candidates:
        records = _txt(resolver, name)
        spf_records = records
        if records and any(r.lower().startswith("v=spf1") for r in records):
            spf_domain = name
            break

    dmarc_records, dmarc_domain = None, candidates[-1]
    for name in candidates:
        records = _txt(resolver, "_dmarc." + name)
        dmarc_records = records
        if records and any(r.lower().startswith("v=dmarc1") for r in records):
            dmarc_domain = name
            break

    findings = [check_spf(spf_records, spf_domain), check_dmarc(dmarc_records, dmarc_domain)]

    # CAA: which certificate authorities may issue for this domain.
    caa, failed = [], False
    for name in candidates:
        try:
            answer = resolver.resolve(name, "CAA")
            caa = [r.to_text() for r in answer]
            break
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except (dns.exception.DNSException, OSError):
            failed = True
            break
    title = "Certificate issuance is restricted (CAA)"
    if failed:
        findings.append(Finding("caa", CAT, title, INFO, "DNS could not be queried for this check."))
    elif caa:
        findings.append(Finding("caa", CAT, title, PASS,
                                "CAA records name the certificate authorities allowed to issue "
                                "certificates for this domain.", evidence="; ".join(caa)))
    else:
        findings.append(Finding(
            "caa", CAT, title, WARN,
            "No CAA record. Any certificate authority may issue a certificate for this domain.",
            penalty=2, severity="low",
            fix='Publish a CAA record naming your authority, for example: 0 issue "letsencrypt.org"',
        ))

    # DNSSEC: a DS record at the parent zone means the domain's answers are signed.
    signed, failed = False, False
    for name in candidates:
        try:
            resolver.resolve(name, "DS")
            signed = True
            break
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except (dns.exception.DNSException, OSError):
            failed = True
            break
    title = "DNS answers are signed (DNSSEC)"
    if failed:
        findings.append(Finding("dnssec", CAT, title, INFO, "DNS could not be queried for this check."))
    elif signed:
        findings.append(Finding("dnssec", CAT, title, PASS,
                                "The domain is signed with DNSSEC, so forged DNS answers can be detected."))
    else:
        findings.append(Finding(
            "dnssec", CAT, title, WARN,
            "The domain is not signed with DNSSEC, so a forged DNS answer could send visitors to "
            "another server without detection.",
            penalty=2, severity="low",
            fix="Enable DNSSEC at your DNS provider and add the DS record at your registrar.",
        ))

    # MTA-STS only matters for domains that receive email.
    mail_domain = spf_domain if spf_domain == dmarc_domain else candidates[-1]
    try:
        has_mx = any(str(r.exchange) != "." for r in resolver.resolve(mail_domain, "MX"))
    except (dns.exception.DNSException, OSError):
        has_mx = False
    if has_mx:
        records = _txt(resolver, "_mta-sts." + mail_domain)
        title = "Incoming email must be encrypted (MTA-STS)"
        if records is None:
            pass
        elif any(r.lower().startswith("v=stsv1") for r in records):
            findings.append(Finding("mta-sts", CAT, title, PASS,
                                    "An MTA-STS policy tells sending servers to require TLS."))
        else:
            findings.append(Finding(
                "mta-sts", CAT, title, WARN,
                "No MTA-STS policy. An attacker on the network path can strip encryption from email "
                "being delivered to this domain.",
                penalty=2, severity="low",
                fix=f"Publish a TXT record at _mta-sts.{mail_domain} and a policy file at "
                    f"https://mta-sts.{mail_domain}/.well-known/mta-sts.txt",
                reference="https://datatracker.ietf.org/doc/html/rfc8461",
            ))
    return findings
