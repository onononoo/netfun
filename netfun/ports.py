"""TCP port checks and service banner grabbing."""

import re
import socket
import ssl

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 554,
                631, 993, 1883, 3306, 3389, 5000, 5353, 5432, 5900, 8008,
                8009, 8080, 8443, 9100, 32400, 62078]

HTTP_PORTS = {80, 5000, 8000, 8008, 8080, 8888, 32400}
HTTPS_PORTS = {443, 8443}

EXTRA_NAMES = {8009: "castv2", 32400: "plex", 62078: "iphone-sync", 1883: "mqtt",
               8008: "http-alt", 9100: "jetdirect", 8443: "https-alt", 631: "ipp",
               5353: "mdns", 554: "rtsp", 5900: "vnc", 3389: "rdp"}

# Ports whose exposure is worth a second look on a home network.
RISKY_PORTS = {
    21: "FTP sends credentials in plain text",
    23: "Telnet sends everything in plain text",
    445: "SMB file sharing; keep it off untrusted networks",
    1883: "MQTT is often unauthenticated",
    3389: "Remote Desktop is a frequent attack target",
    5900: "VNC is often weakly protected",
    3306: "Database exposed on the network",
    5432: "Database exposed on the network",
}


def parse_ports(spec):
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = map(int, part.split("-"))
            ports.update(range(a, b + 1))
        elif part:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


def port_open(ip, port, timeout=0.5):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((ip, port)) == 0


def service_name(port):
    if port in EXTRA_NAMES:
        return EXTRA_NAMES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "?"


def _tls_wrap(sock, ip):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx.wrap_socket(sock, server_hostname=ip)


def grab_banner(ip, port, timeout=2.0):
    """Return a short one-line description of what's listening on a port."""
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return ""
    is_http = port in HTTP_PORTS or port in HTTPS_PORTS
    data = b""
    try:
        sock.settimeout(timeout)
        if port in HTTPS_PORTS:
            sock = _tls_wrap(sock, ip)
        if is_http:
            sock.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: netfun\r\n\r\n".encode())
        while len(data) < 8192:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if not is_http:
                break
    except (OSError, ssl.SSLError):
        pass
    finally:
        sock.close()
    return summarize_banner(data.decode("utf-8", "replace"))


def summarize_banner(text):
    if text.startswith("HTTP/"):
        server = re.search(r"^server:\s*(.+)$", text, re.I | re.M)
        title = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        parts = [p for p in (server and server.group(1).strip(),
                             title and " ".join(title.group(1).split())) if p]
        return " | ".join(parts)[:60] or text.split("\r\n", 1)[0][:60]
    line = text.strip().splitlines()[0] if text.strip() else ""
    return "".join(c for c in line if c.isprintable())[:60]
