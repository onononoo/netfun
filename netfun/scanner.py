"""scan."""

import concurrent.futures as cf
import datetime
import ipaddress
import sys
import time

from . import classify, discovery, oui, ports as portmod, store


def scan(network, ports=None, workers=128, ping_timeout=800, port_timeout=0.5,
         banners=True, quiet=False):
    ports = ports if ports is not None else portmod.COMMON_PORTS
    started = time.time()

    def log(msg):
        if not quiet:
            print(msg, file=sys.stderr, flush=True)

    addrs = [str(h) for h in network.hosts()]
    ping_info = {}
    log(f"scanning {network}")
    with cf.ThreadPoolExecutor(workers) as ex:
        for ip, (up, ttl, rtt) in zip(addrs, ex.map(lambda a: discovery.ping(a, ping_timeout), addrs)):
            if up:
                ping_info[ip] = (ttl, rtt)

    # arp catches hosts that drop ping
    arp = discovery.arp_table()
    alive = set(ping_info) | {ip for ip in arp if ipaddress.ip_address(ip) in network}
    me = discovery.local_ip()
    if ipaddress.ip_address(me) in network:
        alive.add(me)
    gateway = discovery.default_gateway()
    table = oui.load()
    if not table:
        log("no vendor db, run: netfun update-oui")
    labels = store.load_labels()
    log(f"{len(alive)} hosts, checking {len(ports)} ports")

    hosts = {}
    for ip in alive:
        ttl, rtt = ping_info.get(ip, (None, None))
        mac = arp.get(ip, "")
        hosts[ip] = {
            "ip": ip, "mac": mac, "vendor": oui.vendor(mac, table),
            "hostname": "", "label": labels.get(mac) or labels.get(ip, ""),
            "ttl": ttl, "rtt_ms": rtt, "os_guess": discovery.os_from_ttl(ttl),
            "ports": [], "services": {}, "self": ip == me, "gateway": ip == gateway,
        }

    with cf.ThreadPoolExecutor(workers) as ex:
        name_futs = {ex.submit(discovery.resolve_name, ip): ip for ip in alive}
        port_futs = {ex.submit(portmod.port_open, ip, p, port_timeout): (ip, p)
                     for ip in alive for p in ports}
        for f in cf.as_completed(name_futs):
            hosts[name_futs[f]]["hostname"] = f.result()
        for f in cf.as_completed(port_futs):
            if f.result():
                ip, p = port_futs[f]
                hosts[ip]["ports"].append(p)

        if banners:
            pairs = [(ip, p) for ip in alive for p in hosts[ip]["ports"]]
            if pairs:
                log(f"banners: {len(pairs)}")
            bfuts = {ex.submit(portmod.grab_banner, ip, p, max(port_timeout, 2.0)): (ip, p)
                     for ip, p in pairs}
            for f in cf.as_completed(bfuts):
                ip, p = bfuts[f]
                hosts[ip]["services"][str(p)] = f.result()

    out = sorted(hosts.values(), key=lambda h: ipaddress.ip_address(h["ip"]))
    for h in out:
        h["ports"].sort()
        h["device"] = classify.classify(h)
        h["warnings"] = [f"{p}: {portmod.RISKY_PORTS[p]}" for p in h["ports"]
                         if p in portmod.RISKY_PORTS and not h["self"]]

    return {
        "network": str(network),
        "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
        "duration_s": round(time.time() - started, 1),
        "local_ip": me,
        "gateway": gateway,
        "ports_scanned": ports,
        "hosts": out,
    }
