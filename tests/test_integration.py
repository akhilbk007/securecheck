"""End-to-end: scan a real local HTTPS server with a self-signed certificate."""
import datetime
import http.server
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "Apache/2.4.1")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Set-Cookie", "session=abc; Path=/")
        origin = self.headers.get("Origin")
        if origin:  # deliberately vulnerable CORS
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()
        self.wfile.write(b'<h1>hello</h1><script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>'
                         b'<img src="http://localhost/logo.png">')

    def log_message(self, *args):
        pass


@pytest.fixture()
def tls_server(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
            .sign(key, hashes.SHA256()))
    cert_file, key_file = tmp_path / "c.pem", tmp_path / "k.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.TraditionalOpenSSL,
                                           serialization.NoEncryption()))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_file, key_file)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()


def test_full_scan_against_local_server(tls_server, monkeypatch):
    monkeypatch.setenv("SECURECHECK_ALLOW_PRIVATE", "1")
    monkeypatch.setattr("app.scanner.check_dns", lambda host: [])
    from app.scanner import scan

    report = scan(f"https://localhost:{tls_server}/")
    by_id = {f["id"]: f for f in report["findings"]}

    assert report["tls"]["available"] is True
    assert report["tls"]["protocols"]["TLS 1.3"] is True
    assert report["tls"]["certificate"]["key"] == "RSA 2048-bit"
    assert by_id["cert-trusted"]["status"] == "fail"      # self-signed
    assert by_id["hsts"]["status"] == "fail"
    assert by_id["csp"]["status"] == "fail"
    assert by_id["nosniff"]["status"] == "pass"
    assert by_id["disclosure"]["status"] == "warn"
    assert by_id["cors"]["status"] == "fail"              # reflected origin + credentials
    assert by_id["cookie-secure"]["status"] == "fail"
    assert by_id["js-libraries"]["status"] == "fail"      # jQuery 1.12.4
    assert by_id["sri"]["status"] == "warn"
    assert by_id["mixed-content"]["status"] == "warn"
    assert by_id["coop"]["status"] == "warn"
    assert {c["id"] for c in by_id["hsts"]["controls"]} >= {"A.8.24", "CC6.7", "4.2.1"}
    frameworks = {fw["framework"]: fw for fw in report["compliance"]}
    assert set(frameworks) == {"ISO 27001:2022", "SOC 2", "PCI DSS v4.0", "OWASP Top 10 (2021)"}
    assert frameworks["OWASP Top 10 (2021)"]["counts"]["fail"] >= 1
    assert report["tls"]["certificate"]["expires_text"]
    assert report["score"] <= 45 and report["grade"] in ("D", "F")


def test_pdf_report_endpoint(tls_server, monkeypatch):
    monkeypatch.setenv("SECURECHECK_ALLOW_PRIVATE", "1")
    monkeypatch.setattr("app.scanner.check_dns", lambda host: [])
    from app.main import create_app
    client = TestClient(create_app())

    url = f"https://localhost:{tls_server}/"
    assert client.post("/api/scan", json={"url": url}).status_code == 200
    res = client.post("/api/report", json={"url": url})
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"
    assert "attachment" in res.headers["content-disposition"]
    assert res.content.startswith(b"%PDF")


def test_report_endpoint_refuses_blocked_targets():
    from app.main import create_app
    client = TestClient(create_app())
    for url in ["http://169.254.169.254/", "http://localhost/", "file:///etc/passwd"]:
        assert client.post("/api/report", json={"url": url}).status_code == 400, url


def test_api_blocks_internal_targets_and_sets_own_headers():
    from app.main import create_app
    client = TestClient(create_app())

    for url in ["http://169.254.169.254/latest/meta-data/", "http://localhost/", "file:///etc/passwd"]:
        res = client.post("/api/scan", json={"url": url})
        assert res.status_code == 400, url

    page = client.get("/")
    assert page.status_code == 200
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    assert page.headers["x-content-type-options"] == "nosniff"
    assert page.headers["cache-control"] == "no-cache"
    assert client.get("/app.js").headers["cache-control"] == "no-cache"
    # every asset the page references is versioned and exists
    import re
    for ref in re.findall(r'(?:href|src)="([a-z.]+\.(?:css|js))\?v=\d+"', page.text):
        assert client.get("/" + ref).status_code == 200, ref


def test_api_rate_limit(monkeypatch):
    monkeypatch.setattr("app.main.PER_IP_LIMIT", 3)
    from app.main import create_app
    client = TestClient(create_app())
    codes = [client.post("/api/scan", json={"url": "ftp://x"}).status_code for _ in range(5)]
    assert codes == [400, 400, 400, 429, 429]
