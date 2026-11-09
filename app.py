from __future__ import annotations

import http.client
import ipaddress
import json
import re
import socket
import ssl
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).parent
ASSETS = {
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
}
PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP alternate",
    8443: "HTTPS alternate",
}
SOCKET_TIMEOUT = 0.35


class ScanInputError(ValueError):
    pass


def resolve_target(value: str) -> tuple[str, str, int, list[str]]:
    raw = value.strip()
    if not raw:
        raise ScanInputError("Enter a hostname or private IP address.")
    try:
        parsed = urlsplit(raw if "://" in raw else f"http://{raw}")
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise ScanInputError("The target URL or port is malformed.") from exc
    if parsed.scheme not in {"http", "https"} or not host:
        raise ScanInputError("Use a hostname or an http(s) URL, such as http://192.168.1.10.")
    if parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ScanInputError("Enter only the host and optional port; paths and credentials are not scanned.")
    try:
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise ScanInputError("The hostname could not be resolved.") from exc
    addresses = list(dict.fromkeys(record[4][0] for record in records))
    if not addresses:
        raise ScanInputError("The hostname did not resolve to an address.")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not (ip.is_private or ip.is_loopback or ip.is_link_local) or ip.is_multicast or ip.is_unspecified:
            raise ScanInputError("For safety, this demo only scans localhost and private or link-local network addresses.")
    return host, parsed.scheme, port, addresses[:4]


def port_scan(address: str, custom_port: int) -> list[dict[str, int | str]]:
    ports = dict(PORTS)
    if custom_port not in ports:
        ports[custom_port] = "Target web port"
    open_ports = []
    for port, service in ports.items():
        try:
            with socket.create_connection((address, port), timeout=SOCKET_TIMEOUT):
                open_ports.append({"port": port, "service": service})
        except (OSError, TimeoutError):
            continue
    return open_ports


def read_web_headers(host: str, address: str, scheme: str, port: int) -> dict:
    raw_socket = socket.create_connection((address, port), timeout=2)
    connection = raw_socket
    try:
        if scheme == "https":
            context = ssl.create_default_context()
            connection = context.wrap_socket(raw_socket, server_hostname=host)
        display_host = f"[{host}]" if ":" in host else host
        default_port = 443 if scheme == "https" else 80
        host_header = display_host if port == default_port else f"{display_host}:{port}"
        connection.settimeout(3)
        connection.sendall(
            f"HEAD / HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: UMO/1.0\r\nConnection: close\r\n\r\n".encode("ascii")
        )
        response = http.client.HTTPResponse(connection)
        response.begin()
        headers = {key.lower(): value.strip() for key, value in response.getheaders()}
        return {"status": response.status, "headers": headers}
    finally:
        connection.close()


def legacy_version_hint(server_value: str, powered_by: str) -> str | None:
    combined = f"{server_value} {powered_by}"
    rules = [
        (r"Apache/(\d+)\.(\d+)", lambda v: v[0] < 2 or (v[0] == 2 and v[1] < 4), "Apache 2.2 and earlier are legacy branches"),
        (r"nginx/(\d+)\.(\d+)", lambda v: v[0] == 0 or (v[0] == 1 and v[1] < 20), "nginx versions before 1.20 are legacy branches"),
        (r"PHP/(\d+)\.(\d+)", lambda v: v[0] < 8 or (v[0] == 8 and v[1] == 0), "PHP versions before 8.1 are legacy branches"),
        (r"OpenSSH[_/ ](\d+)\.(\d+)", lambda v: v[0] < 8, "OpenSSH versions before 8 are legacy branches"),
        (r"IIS/(\d+)\.(\d+)", lambda v: v[0] < 10, "IIS versions before 10 are legacy branches"),
    ]
    for pattern, is_legacy, message in rules:
        match = re.search(pattern, combined, re.IGNORECASE)
        if match and is_legacy((int(match.group(1)), int(match.group(2)))):
            return message
    return None


def build_findings(web: dict | None, open_ports: list[dict], scheme: str, web_error: str | None) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if web_error:
        findings.append({"severity": "info", "title": "Web check unavailable", "detail": web_error})
    elif web:
        headers = web["headers"]
        required = [
            ("content-security-policy", "Content Security Policy"),
            ("x-content-type-options", "X-Content-Type-Options"),
            ("referrer-policy", "Referrer Policy"),
        ]
        for header, label in required:
            if header not in headers:
                findings.append({"severity": "medium", "title": f"Missing {label}", "detail": f"The root response does not set {label}. Review whether this header fits the application."})
        if "x-frame-options" not in headers and "content-security-policy" not in headers:
            findings.append({"severity": "medium", "title": "Clickjacking protection not observed", "detail": "No X-Frame-Options or Content Security Policy header was returned."})
        if scheme == "https" and "strict-transport-security" not in headers:
            findings.append({"severity": "low", "title": "HSTS not observed", "detail": "The HTTPS response does not set Strict-Transport-Security."})
        server = headers.get("server", "")
        powered_by = headers.get("x-powered-by", "")
        disclosed = ", ".join(value for value in (server, powered_by) if value)
        if disclosed:
            findings.append({"severity": "low", "title": "Technology details disclosed", "detail": f"Response headers identify: {disclosed}"})
            legacy = legacy_version_hint(server, powered_by)
            if legacy:
                findings.append({"severity": "high", "title": "Possible legacy software branch", "detail": f"{legacy}. This is a heuristic; verify the installed version and vendor support status."})
    risky = {21, 23, 139, 445, 3306, 3389, 5900, 6379}
    for entry in open_ports:
        port = int(entry["port"])
        findings.append({
            "severity": "medium" if port in risky else "info",
            "title": f"Port {port} open: {entry['service']}",
            "detail": "Confirm this service is needed and restricted to trusted networks. An open port alone does not confirm a vulnerability.",
        })
    if not findings:
        findings.append({"severity": "low", "title": "No common issues observed", "detail": "The limited checks did not identify a finding. This is not a full security assessment."})
    return findings


def scan(value: str) -> dict:
    host, scheme, web_port, addresses = resolve_target(value)
    open_ports = []
    seen_ports = set()
    for address in addresses:
        for item in port_scan(address, web_port):
            if item["port"] not in seen_ports:
                open_ports.append(item)
                seen_ports.add(item["port"])
    web = None
    web_error = None
    try:
        web = read_web_headers(host, addresses[0], scheme, web_port)
    except ssl.SSLCertVerificationError:
        web_error = "TLS certificate verification failed; review the certificate and hostname."
    except (OSError, ssl.SSLError, http.client.HTTPException, UnicodeError):
        web_error = "Could not complete a read-only HEAD request on the selected web port."
    findings = build_findings(web, open_ports, scheme, web_error)
    counts = {level: sum(item["severity"] == level for item in findings) for level in ("high", "medium", "low", "info")}
    return {
        "target": value.strip(),
        "host": host,
        "resolved_addresses": addresses,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "web": web,
        "open_ports": open_ports,
        "findings": findings,
        "counts": counts,
        "scope": "Single host; common TCP ports and a read-only HTTP HEAD check.",
    }


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/api/health":
            self.send_json(200, {"ok": True})
            return
        if self.path == "/":
            path, content_type = "index.html", "text/html; charset=utf-8"
        elif self.path in ASSETS:
            path, content_type = ASSETS[self.path]
        else:
            self.send_error(404)
            return
        page = (ROOT / path).read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(page)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(page)

    def do_POST(self) -> None:
        if self.path != "/api/scan":
            self.send_error(404)
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size < 1 or size > 4096:
                raise ScanInputError("Invalid request size.")
            payload = json.loads(self.rfile.read(size))
            if not isinstance(payload, dict) or not isinstance(payload.get("target"), str):
                raise ScanInputError("Provide a target hostname or address.")
            self.send_json(200, scan(payload["target"]))
        except ScanInputError as exc:
            self.send_json(400, {"error": str(exc)})
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.send_json(400, {"error": "Request body must be valid JSON."})

    def send_json(self, status: int, value: dict) -> None:
        body = json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        print(f"[{self.log_date_time_string()}] {format % args}")


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 8765), Handler)
    print("UMO is running at http://127.0.0.1:8765")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping UMO.")
        server.server_close()