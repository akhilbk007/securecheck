import pytest

from app.netguard import TargetError, is_public_ip, parse_target, resolve_public


@pytest.mark.parametrize("raw,expected", [
    ("example.com", "https://example.com/"),
    ("  Example.COM/path?q=1 ", "https://example.com/path?q=1"),
    ("http://example.com", "http://example.com/"),
    ("https://example.com:443/", "https://example.com/"),
    ("bücher.example", "https://xn--bcher-kva.example/"),
])
def test_parse_accepts_normal_addresses(raw, expected):
    assert parse_target(raw).url == expected


@pytest.mark.parametrize("raw", [
    "",
    "ftp://example.com",
    "file:///etc/passwd",
    "gopher://example.com",
    "javascript:alert(1)",
    "https://user:pass@example.com",
    "https://example.com:8080",
    "https://example.com:22",
    "http://127.0.0.1",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/",
    "http://2130706433/",       # decimal form of 127.0.0.1
    "http://0x7f.0.0.1/",       # hex form
    "http://127.1/",            # short form
    "http://localhost",
    "https://exa mple.com",
    "https://example.com\r\nHost: evil",
    "https://-bad-.example.com",
    "x" * 3000,
])
def test_parse_rejects_dangerous_input(raw):
    with pytest.raises(TargetError):
        parse_target(raw)


@pytest.mark.parametrize("ip", [
    "127.0.0.1", "10.0.0.5", "172.16.3.4", "192.168.1.1",
    "169.254.169.254",          # cloud metadata service
    "100.64.0.1",               # carrier-grade NAT
    "0.0.0.0", "224.0.0.1", "255.255.255.255",
    "::1", "fe80::1", "fc00::1",
    "::ffff:10.0.0.1",          # IPv4-mapped IPv6
    "::ffff:169.254.169.254",
    "2002:7f00:0001::",         # 6to4 wrapping 127.0.0.1
    "not-an-ip",
])
def test_non_public_addresses_are_blocked(ip):
    assert is_public_ip(ip) is False


@pytest.mark.parametrize("ip", ["93.184.216.34", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_addresses_are_allowed(ip):
    assert is_public_ip(ip) is True


def _fake_dns(monkeypatch, addresses):
    def fake(host, port, type=0):
        return [(2, 1, 6, "", (a, port)) for a in addresses]
    monkeypatch.setattr("app.netguard.socket.getaddrinfo", fake)


def test_resolve_blocks_domain_pointing_at_internal_ip(monkeypatch):
    _fake_dns(monkeypatch, ["10.0.0.7"])
    with pytest.raises(TargetError):
        resolve_public("internal.attacker.example", 443)


def test_resolve_blocks_mixed_public_and_internal_records(monkeypatch):
    _fake_dns(monkeypatch, ["93.184.216.34", "169.254.169.254"])
    with pytest.raises(TargetError):
        resolve_public("rebind.attacker.example", 443)


def test_resolve_returns_public_ip(monkeypatch):
    _fake_dns(monkeypatch, ["93.184.216.34"])
    assert resolve_public("example.com", 443) == "93.184.216.34"
