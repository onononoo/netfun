"""netmap - a small, dependency-free network mapper for your local network.

Discovers live hosts on a subnet (ping sweep + ARP table), resolves hostnames,
looks up MAC vendors, guesses the OS from ping TTL, checks common TCP ports,
grabs service banners, and makes a best-effort guess at each device's type.

Only scan networks you own or are authorized to test.

Usage:
    python netmap.py --update-oui         # one-time: download IEEE vendor list
    python netmap.py                      # auto-detect local /24 subnet
    python netmap.py 192.168.1.0/24       # explicit subnet
    python netmap.py 10.0.0.0/24 -p 22,80,443,8000-8100 --json out.json
"""

import argparse
import concurrent.futures as cf
import csv
import ipaddress
import json
import os
import platform
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.request

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 554,
                631, 993, 1883, 3306, 3389, 5000, 5353, 5432, 5900, 8008,
                8009, 8080, 8443, 9100, 32400, 62078]

HTTP_PORTS = {80, 5000, 8008, 8080, 32400}
HTTPS_PORTS = {443, 8443}

IS_WINDOWS = platform.system() == "Windows"

OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"
OUI_CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "oui.csv")


# --------------------------------------------------------------------------
# MAC vendor lookup
# --------------------------------------------------------------------------

def update_oui():
    print(f"[*] Downloading {OUI_URL} ...", file=sys.stderr)
    req = urllib.request.Request(OUI_URL, headers={"User-Agent": "netmap/1.0"})
    with urllib.request.urlopen(req, timeout=60) as r, open(OUI_CACHE, "wb") as f:
        f.write(r.read())
    print(f"[*] Saved {len(load_oui())} vendor prefixes to {OUI_CACHE}", file=sys.stderr)


def load_oui():
    """Return {'AABBCC': 'Vendor Name'} from the cached IEEE CSV, or {}."""
    if not os.path.exists(OUI_CACHE):
        return {}
    table = {}
    with open(OUI_CACHE, encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            prefix = (row.get("Assignment") or "").strip().upper()
            if len(prefix) == 6:
                table[prefix] = (row.get("Organization Name") or "").strip()
    return table


def mac_vendor(mac, oui):
    if not mac:
        return ""
    first = int(mac[:2], 16)
    if first & 0x02:  # locally administered bit: randomized/private MAC
        return "(private/random MAC)"
    return oui.get(mac.replace(":", "")[:6].upper(), "")


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------

def local_ip():
    """Return the IP of the interface used for outbound traffic."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # no packets are sent for UDP connect
        return s.getsockname()[0]
    finally:
        s.close()


def default_subnet():
    return ipaddress.ip_network(f"{local_ip()}/24", strict=False)


def ping(ip, timeout_ms):
    """Return (alive, ttl, rtt_ms)."""
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           timeout=timeout_ms / 1000 + 2, text=True)
    except subprocess.TimeoutExpired:
        return False, None, None
    out = r.stdout.lower()
    # Windows ping returns 0 on "Destination host unreachable"; check for TTL.
    ttl = re.search(r"ttl=(\d+)", out)
    if r.returncode != 0 or not ttl:
        return False, None, None
    rtt = re.search(r"time[=<]([\d.]+)", out)
    return True, int(ttl.group(1)), float(rtt.group(1)) if rtt else None


def os_from_ttl(ttl):
    if ttl is None:
        return ""
    if ttl <= 64:
        return "Linux/Unix/macOS/iOS/Android"
    if ttl <= 128:
        return "Windows"
    return "Network device (router/switch)"


def arp_table():
    """Parse the OS ARP cache into {ip: mac}."""
    try:
        out = subprocess.run(["arp", "-a"], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, text=True).stdout
    except FileNotFoundError:
        return {}
    table = {}
    pat = re.compile(r"(\d+\.\d+\.\d+\.\d+)\D+?([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})")
    for ip, mac in pat.findall(out):
        mac = ":".join(b.zfill(2) for b in re.split("[:-]", mac.lower()))
        if mac != "ff:ff:ff:ff:ff:ff" and not mac.startswith("01:00:5e"):
            table[ip] = mac
    return table


def default_gateway():
    try:
        if IS_WINDOWS:
            out = subprocess.run(["route", "print", "0.0.0.0"], stdout=subprocess.PIPE,
                                 text=True).stdout
            m = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", out)
        else:
            out = subprocess.run(["ip", "route"], stdout=subprocess.PIPE, text=True).stdout
            m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
        return m.group(1) if m else ""
    except (FileNotFoundError, OSError):
        return ""


def hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def netbios_name(ip, timeout=1.0):
    """Query NetBIOS name service (UDP 137) for a Windows/Samba machine name."""
    query = (b"\x13\x37\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
             b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        try:
            s.sendto(query, (ip, 137))
            data = s.recv(1024)
        except OSError:
            return ""
    try:
        count = data[56]
        for i in range(count):
            entry = data[57 + i * 18: 57 + i * 18 + 18]
            name, flags = entry[:15].decode("ascii", "replace").strip(), entry[16]
            if entry[15] == 0x00 and not flags & 0x80:  # unique workstation name
                return name
    except IndexError:
        pass
    return ""


# --------------------------------------------------------------------------
# Ports and banners
# --------------------------------------------------------------------------

def port_open(ip, port, timeout):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((ip, port)) == 0


def service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return {8009: "castv2", 32400: "plex", 62078: "iphone-sync",
                1883: "mqtt", 8008: "http-alt", 9100: "jetdirect"}.get(port, "?")


def grab_banner(ip, port, timeout):
    """Return a short one-line description of what's listening on a port."""
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return ""
    try:
        raw.settimeout(timeout)
        if port in HTTPS_PORTS:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = ctx.wrap_socket(raw, server_hostname=ip)
        if port in HTTP_PORTS or port in HTTPS_PORTS:
            raw.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: netmap\r\n\r\n".encode())
        data = b""
        while len(data) < 8192:
            chunk = raw.recv(4096)
            if not chunk:
                break
            data += chunk
            if port not in HTTP_PORTS and port not in HTTPS_PORTS:
                break
    except (OSError, ssl.SSLError):
        data = b""
    finally:
        raw.close()

    text = data.decode("utf-8", "replace")
    if text.startswith("HTTP/"):
        server = re.search(r"^server:\s*(.+)$", text, re.I | re.M)
        title = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        parts = [p for p in (server and server.group(1).strip(),
                             title and " ".join(title.group(1).split())) if p]
        return " | ".join(parts)[:60] or text.split("\r\n", 1)[0][:60]
    line = text.strip().splitlines()[0] if text.strip() else ""
    return "".join(c for c in line if c.isprintable())[:60]


# --------------------------------------------------------------------------
# Device classification
# --------------------------------------------------------------------------

VENDOR_HINTS = [
    (r"apple", "Apple device"),
    (r"samsung", "Samsung device"),
    (r"google|nest", "Google/Nest device"),
    (r"amazon", "Amazon device (Echo/Fire/Ring)"),
    (r"sonos", "Sonos speaker"),
    (r"roku", "Roku streamer"),
    (r"espressif|tuya|shelly|wiz|lifx|signify|philips lighting", "IoT / smart home"),
    (r"raspberry", "Raspberry Pi"),
    (r"hewlett|hp inc|brother|canon|epson|xerox|lexmark", "Printer"),
    (r"synology|qnap|western digital", "NAS"),
    (r"netgear|tp-link|asus|ubiquiti|cisco|linksys|arris|eero|mikrotik|d-link", "Network gear"),
    (r"intel|realtek|dell|lenovo|micro-star|gigabyte|asrock", "PC / laptop"),
    (r"nintendo|sony interactive|microsoft", "Console / PC"),
]


def classify(host, gateway):
    ports, vendor = set(host["ports"]), host["vendor"].lower()
    if host["ip"] == gateway:
        return "Router / gateway"
    if 9100 in ports or 631 in ports:
        return "Printer"
    if 62078 in ports:
        return "iPhone / iPad"
    if 8009 in ports or 8008 in ports:
        return "Chromecast / Google speaker"
    if 32400 in ports:
        return "Plex server"
    if 3389 in ports or {135, 445} <= ports:
        return "Windows PC"
    if 554 in ports:
        return "Camera / NVR"
    if 1883 in ports:
        return "MQTT / home automation"
    for pat, label in VENDOR_HINTS:
        if re.search(pat, vendor):
            return label
    if 22 in ports:
        return "Linux / server"
    if vendor == "(private/random mac)":
        return "Phone / laptop (private MAC)"
    return ""


# --------------------------------------------------------------------------
# Scan orchestration
# --------------------------------------------------------------------------

def scan(network, ports, workers, ping_timeout, port_timeout, banners=True, progress=True):
    hosts = [str(h) for h in network.hosts()]
    ping_info = {}

    def log(msg):
        if progress:
            print(msg, file=sys.stderr, flush=True)

    log(f"[*] Ping sweep of {network} ({len(hosts)} addresses)...")
    with cf.ThreadPoolExecutor(workers) as ex:
        for ip, (up, ttl, rtt) in zip(hosts, ex.map(lambda h: ping(h, ping_timeout), hosts)):
            if up:
                ping_info[ip] = (ttl, rtt)

    # Hosts that block ICMP often still show up in the ARP cache after the sweep.
    arp = arp_table()
    alive = set(ping_info)
    alive.update(ip for ip in arp if ipaddress.ip_address(ip) in network)
    me = local_ip()
    if ipaddress.ip_address(me) in network:
        alive.add(me)
    gateway = default_gateway()
    oui = load_oui()
    if not oui:
        log("[!] No vendor database; run with --update-oui for MAC vendor names.")
    log(f"[*] {len(alive)} live hosts. Resolving names and scanning {len(ports)} ports...")

    results = {}
    for ip in alive:
        ttl, rtt = ping_info.get(ip, (None, None))
        mac = arp.get(ip, "")
        results[ip] = {"ip": ip, "mac": mac, "vendor": mac_vendor(mac, oui),
                       "hostname": "", "ttl": ttl, "rtt_ms": rtt,
                       "os_guess": os_from_ttl(ttl), "ports": [], "services": {},
                       "self": ip == me, "gateway": ip == gateway}

    def resolve(ip):
        return hostname(ip) or netbios_name(ip)

    with cf.ThreadPoolExecutor(workers) as ex:
        name_futs = {ex.submit(resolve, ip): ip for ip in alive}
        port_futs = {ex.submit(port_open, ip, p, port_timeout): (ip, p)
                     for ip in alive for p in ports}
        for f in cf.as_completed(name_futs):
            results[name_futs[f]]["hostname"] = f.result()
        for f in cf.as_completed(port_futs):
            if f.result():
                ip, p = port_futs[f]
                results[ip]["ports"].append(p)

        if banners:
            open_pairs = [(ip, p) for ip in alive for p in results[ip]["ports"]]
            if open_pairs:
                log(f"[*] Grabbing banners from {len(open_pairs)} open ports...")
            banner_futs = {ex.submit(grab_banner, ip, p, max(port_timeout, 2.0)): (ip, p)
                           for ip, p in open_pairs}
            for f in cf.as_completed(banner_futs):
                ip, p = banner_futs[f]
                results[ip]["services"][str(p)] = f.result()

    out = sorted(results.values(), key=lambda r: ipaddress.ip_address(r["ip"]))
    for r in out:
        r["ports"].sort()
        r["device"] = classify(r, gateway)
    return out


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def print_table(results):
    print(f"\n{'IP':<16} {'MAC':<18} {'VENDOR':<26} {'HOSTNAME':<22} {'DEVICE / OS GUESS':<30}")
    print("-" * 116)
    for r in results:
        tag = "*" if r["self"] else ("G" if r["gateway"] else "")
        guess = r["device"] or r["os_guess"] or "-"
        print(f"{r['ip'] + tag:<16} {r['mac'] or '-':<18} {(r['vendor'] or '-')[:25]:<26} "
              f"{(r['hostname'] or '-')[:21]:<22} {guess[:30]}")
        for p in r["ports"]:
            banner = r["services"].get(str(p), "")
            print(f"{'':<16}   {p:>5}/tcp  {service_name(p):<14} {banner}")
    print(f"\n{len(results)} hosts found. (* = this machine, G = gateway)")


def main():
    ap = argparse.ArgumentParser(description="Map hosts and open ports on a local network.")
    ap.add_argument("network", nargs="?", help="CIDR to scan (default: your /24)")
    ap.add_argument("-p", "--ports", help="ports, e.g. 22,80,8000-8100 (default: common ports)")
    ap.add_argument("-w", "--workers", type=int, default=128)
    ap.add_argument("--ping-timeout", type=int, default=800, help="ms")
    ap.add_argument("--port-timeout", type=float, default=0.5, help="seconds")
    ap.add_argument("--no-banners", action="store_true", help="skip service banner grabbing")
    ap.add_argument("--json", metavar="FILE", help="also write results as JSON")
    ap.add_argument("--update-oui", action="store_true",
                    help="download the IEEE MAC vendor list and exit")
    args = ap.parse_args()

    if args.update_oui:
        update_oui()
        return

    network = ipaddress.ip_network(args.network, strict=False) if args.network else default_subnet()
    if network.num_addresses > 4096:
        sys.exit(f"{network} is large ({network.num_addresses} addresses); use a /20 or smaller.")
    ports = parse_ports(args.ports) if args.ports else COMMON_PORTS

    start = time.time()
    results = scan(network, ports, args.workers, args.ping_timeout, args.port_timeout,
                   banners=not args.no_banners)
    print_table(results)
    print(f"Done in {time.time() - start:.1f}s.")

    if args.json:
        with open(args.json, "w") as f:
            json.dump({"network": str(network), "ports": ports, "hosts": results}, f, indent=2)
        print(f"Wrote {args.json}")


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


if __name__ == "__main__":
    main()
