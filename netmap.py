"""netmap - a small, dependency-free network mapper for your local network.

Discovers live hosts on a subnet (ping sweep + ARP table), resolves hostnames,
looks up MAC addresses, and checks a set of common TCP ports.

Only scan networks you own or are authorized to test.

Usage:
    python netmap.py                      # auto-detect local /24 subnet
    python netmap.py 192.168.1.0/24       # explicit subnet
    python netmap.py 10.0.0.0/24 -p 22,80,443,8000-8100 --json out.json
"""

import argparse
import concurrent.futures as cf
import ipaddress
import json
import platform
import re
import socket
import subprocess
import sys
import time

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 554,
                631, 993, 1883, 3306, 3389, 5000, 5353, 5432, 5900, 8008,
                8080, 8443, 9100, 32400]

IS_WINDOWS = platform.system() == "Windows"


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
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           timeout=timeout_ms / 1000 + 2, text=True)
    except subprocess.TimeoutExpired:
        return False
    # Windows ping returns 0 on "Destination host unreachable"; check for TTL.
    return r.returncode == 0 and "ttl=" in r.stdout.lower()


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
        mac = mac.replace("-", ":").lower()
        if mac not in ("ff:ff:ff:ff:ff:ff",):
            table[ip] = mac
    return table


def hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def port_open(ip, port, timeout):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((ip, port)) == 0


def service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "?"


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


def scan(network, ports, workers, ping_timeout, port_timeout, progress=True):
    hosts = [str(h) for h in network.hosts()]
    alive = set()

    def log(msg):
        if progress:
            print(msg, file=sys.stderr, flush=True)

    log(f"[*] Ping sweep of {network} ({len(hosts)} addresses)...")
    with cf.ThreadPoolExecutor(workers) as ex:
        for ip, up in zip(hosts, ex.map(lambda h: ping(h, ping_timeout), hosts)):
            if up:
                alive.add(ip)

    # Hosts that block ICMP often still show up in the ARP cache after the sweep.
    arp = arp_table()
    alive.update(ip for ip in arp if ipaddress.ip_address(ip) in network)
    me = local_ip()
    if ipaddress.ip_address(me) in network:
        alive.add(me)
    log(f"[*] {len(alive)} live hosts. Resolving names and scanning {len(ports)} ports...")

    results = {ip: {"ip": ip, "mac": arp.get(ip, ""), "hostname": "",
                    "ports": [], "self": ip == me} for ip in alive}

    with cf.ThreadPoolExecutor(workers) as ex:
        name_futs = {ex.submit(hostname, ip): ip for ip in alive}
        port_futs = {ex.submit(port_open, ip, p, port_timeout): (ip, p)
                     for ip in alive for p in ports}
        for f in cf.as_completed(name_futs):
            results[name_futs[f]]["hostname"] = f.result()
        for f in cf.as_completed(port_futs):
            if f.result():
                ip, p = port_futs[f]
                results[ip]["ports"].append(p)

    out = sorted(results.values(), key=lambda r: ipaddress.ip_address(r["ip"]))
    for r in out:
        r["ports"].sort()
    return out


def print_table(results):
    print(f"\n{'IP':<16} {'MAC':<18} {'HOSTNAME':<32} OPEN PORTS")
    print("-" * 100)
    for r in results:
        ip = r["ip"] + ("*" if r["self"] else "")
        ports = ", ".join(f"{p}/{service_name(p)}" for p in r["ports"]) or "-"
        print(f"{ip:<16} {r['mac'] or '-':<18} {(r['hostname'] or '-')[:31]:<32} {ports}")
    print(f"\n{len(results)} hosts found. (* = this machine)")


def main():
    ap = argparse.ArgumentParser(description="Map hosts and open ports on a local network.")
    ap.add_argument("network", nargs="?", help="CIDR to scan (default: your /24)")
    ap.add_argument("-p", "--ports", help="ports, e.g. 22,80,8000-8100 (default: common ports)")
    ap.add_argument("-w", "--workers", type=int, default=128)
    ap.add_argument("--ping-timeout", type=int, default=800, help="ms")
    ap.add_argument("--port-timeout", type=float, default=0.5, help="seconds")
    ap.add_argument("--json", metavar="FILE", help="also write results as JSON")
    args = ap.parse_args()

    network = ipaddress.ip_network(args.network, strict=False) if args.network else default_subnet()
    if network.num_addresses > 4096:
        sys.exit(f"{network} is large ({network.num_addresses} addresses); use a /20 or smaller.")
    ports = parse_ports(args.ports) if args.ports else COMMON_PORTS

    start = time.time()
    results = scan(network, ports, args.workers, args.ping_timeout, args.port_timeout)
    print_table(results)
    print(f"Done in {time.time() - start:.1f}s.")

    if args.json:
        with open(args.json, "w") as f:
            json.dump({"network": str(network), "ports": ports, "hosts": results}, f, indent=2)
        print(f"Wrote {args.json}")


if __name__ == "__main__":
    main()
