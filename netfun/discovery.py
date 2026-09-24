"""host discovery."""

import ipaddress
import platform
import re
import socket
import struct
import subprocess

IS_WINDOWS = platform.system() == "Windows"
_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0


def _run(cmd, timeout=None):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          text=True, timeout=timeout, creationflags=_NO_WINDOW)


def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


def default_subnet():
    return ipaddress.ip_network(f"{local_ip()}/24", strict=False)


def ping(ip, timeout_ms=800):
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        r = _run(cmd, timeout=timeout_ms / 1000 + 2)
    except subprocess.TimeoutExpired:
        return False, None, None
    out = r.stdout.lower()
    # windows returns 0 on unreachable
    ttl = re.search(r"ttl=(\d+)", out)
    if r.returncode != 0 or not ttl:
        return False, None, None
    rtt = re.search(r"time[=<]([\d.]+)", out)
    return True, int(ttl.group(1)), float(rtt.group(1)) if rtt else None


def os_from_ttl(ttl):
    if ttl is None:
        return ""
    if ttl <= 64:
        return "unix-like"
    if ttl <= 128:
        return "windows"
    return "network"


_ARP_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+)\D+?([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})")


def normalize_mac(mac):
    return ":".join(b.zfill(2) for b in re.split("[:-]", mac.lower()))


def parse_arp(text):
    table = {}
    for ip, mac in _ARP_RE.findall(text):
        mac = normalize_mac(mac)
        if mac != "ff:ff:ff:ff:ff:ff" and not mac.startswith("01:00:5e"):
            table[ip] = mac
    return table


def arp_table():
    try:
        return parse_arp(_run(["arp", "-a"]).stdout)
    except (FileNotFoundError, OSError):
        return {}


def default_gateway():
    try:
        if IS_WINDOWS:
            out = _run(["route", "print", "0.0.0.0"]).stdout
            m = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", out)
        else:
            out = _run(["ip", "route"]).stdout
            m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
        return m.group(1) if m else ""
    except (FileNotFoundError, OSError):
        return ""


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def netbios_name(ip, timeout=1.0):
    # netbios, udp 137
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
        for i in range(data[56]):
            entry = data[57 + i * 18: 57 + i * 18 + 18]
            if entry[15] == 0x00 and not entry[16] & 0x80:
                return entry[:15].decode("ascii", "replace").strip()
    except IndexError:
        pass
    return ""


def mdns_name(ip, timeout=1.0):
    # unicast mdns ptr, udp 5353
    rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    qname = b"".join(bytes([len(p)]) + p.encode() for p in rev.split(".")) + b"\x00"
    packet = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0) + qname + struct.pack(">HH", 12, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        try:
            s.sendto(packet, (ip, 5353))
            data = s.recv(2048)
        except OSError:
            return ""
    try:
        return _parse_ptr_answer(data)
    except (IndexError, struct.error, UnicodeDecodeError):
        return ""


def _read_name(data, off):
    labels, jumped, end = [], False, off
    for _ in range(64):
        ln = data[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            ptr = struct.unpack(">H", data[off:off + 2])[0] & 0x3FFF
            if not jumped:
                end = off + 2
            jumped, off = True, ptr
            continue
        labels.append(data[off + 1: off + 1 + ln].decode())
        off += 1 + ln
    return ".".join(labels), (end if jumped else off)


def _parse_ptr_answer(data):
    qd, an = struct.unpack(">HH", data[4:8])
    off = 12
    for _ in range(qd):
        _, off = _read_name(data, off)
        off += 4
    for _ in range(an):
        _, off = _read_name(data, off)
        rtype, _, _, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        if rtype == 12:
            return _read_name(data, off)[0].rstrip(".")
        off += rdlen
    return ""


def resolve_name(ip):
    return reverse_dns(ip) or mdns_name(ip) or netbios_name(ip)
