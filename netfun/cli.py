"""cli."""

import argparse
import concurrent.futures as cf
import datetime
import ipaddress
import os
import statistics
import subprocess
import sys
import time

from . import __version__, diff, discovery, inventory, oui, report, serve, ssdp, store, wol
from .ports import COMMON_PORTS, grab_banner, parse_ports, port_open, service_name
from .scanner import scan

MAX_ADDRESSES = 4096


class _Fmt(argparse.HelpFormatter):
    # lowercase default metavars
    def _get_default_metavar_for_optional(self, action):
        return action.dest.lower()

    def _get_default_metavar_for_positional(self, action):
        return action.dest.lower()


def _network(arg):
    net = ipaddress.ip_network(arg, strict=False) if arg else discovery.default_subnet()
    if net.num_addresses > MAX_ADDRESSES:
        sys.exit(f"too large: {net}, max /20")
    return net


def _add_scan_opts(p):
    p.add_argument("network", nargs="?", help="cidr, default local /24")
    p.add_argument("-p", "--ports", help="e.g. 22,80,8000-8100")
    p.add_argument("-w", "--workers", type=int, default=128)
    p.add_argument("--ping-timeout", type=int, default=800, help="ms")
    p.add_argument("--port-timeout", type=float, default=0.5, help="seconds")
    p.add_argument("--no-banners", action="store_true")
    p.add_argument("--no-upnp", action="store_true")


def _do_scan(args, quiet=False):
    return scan(_network(args.network),
                ports=parse_ports(args.ports) if args.ports else COMMON_PORTS,
                workers=args.workers, ping_timeout=args.ping_timeout,
                port_timeout=args.port_timeout, banners=not args.no_banners,
                upnp=not args.no_upnp, quiet=quiet)


def cmd_scan(args):
    result = _do_scan(args)
    report.print_table(result)
    if not args.no_save:
        prev = store.list_scans()
        print(f"saved {store.save_scan(result)}")
        inventory.update(result)
        if prev:
            old = store.load_scan(prev[-1])
            if old["network"] == result["network"]:
                for line in diff.format_changes(diff.compare(old, result)):
                    print(line)
    for path, write in ((args.json, report.write_json), (args.csv, report.write_csv),
                        (args.html, report.write_html)):
        if path:
            write(result, path)
            print(f"wrote {path}")


def cmd_report(args):
    result = store.load_scan(args.scan)
    out = args.output or f"netfun-report.{args.format}"
    {"html": report.write_html, "csv": report.write_csv, "json": report.write_json}[args.format](result, out)
    print(f"wrote {out}")


def cmd_show(args):
    report.print_table(store.load_scan(args.scan), show_ports=not args.brief)


def cmd_diff(args):
    old, new = store.load_scan(args.old), store.load_scan(args.new)
    for line in diff.format_changes(diff.compare(old, new)):
        print(line)


def cmd_history(args):
    scans = store.list_scans()
    if not scans:
        print("no scans")
        return
    n = len(scans)
    for i, path in enumerate(scans[-args.limit:], start=max(0, n - args.limit)):
        s = store.load_scan(path)
        print(f"{i - n:>4}  {s['timestamp']}  {s['network']:<18} {len(s['hosts']):>3}")


def cmd_watch(args):
    scans = store.list_scans()
    last = store.load_scan(scans[-1]) if scans else None
    try:
        while True:
            result = _do_scan(args, quiet=True)
            now = datetime.datetime.now().strftime("%H:%M:%S")
            if last and last["network"] == result["network"]:
                changes = diff.compare(last, result)
                if args.new_only:
                    changes = {**changes, "gone": [], "moved": [], "ports": []}
                lines = diff.format_changes(changes)
                for line in lines:
                    print(f"{now} {line}", flush=True)
                if not diff.is_empty(changes):
                    if args.beep:
                        print("\a", end="", flush=True)
                    if args.exec:
                        env = {**os.environ, "NETFUN_CHANGES": "\n".join(lines)}
                        subprocess.run(args.exec, shell=True, env=env)
            else:
                print(f"{now} {len(result['hosts'])} hosts", flush=True)
            store.save_scan(result)
            inventory.update(result)
            last = result
            time.sleep(args.interval)
    except KeyboardInterrupt:
        pass


def cmd_ports(args):
    ports = parse_ports(args.ports)
    with cf.ThreadPoolExecutor(args.workers) as ex:
        opened = [p for p, ok in zip(ports, ex.map(lambda p: port_open(args.host, p, args.timeout), ports)) if ok]
        banners = dict(zip(opened, ex.map(lambda p: grab_banner(args.host, p), opened)))
    for p in opened:
        print(f"{p:>5}/tcp {service_name(p):<14} {banners[p]}")
    print(f"{len(opened)}/{len(ports)} open")


def cmd_devices(args):
    inv = inventory.load()
    scans = store.list_scans()
    latest = store.load_scan(scans[-1])["timestamp"] if scans else ""
    rows = sorted(inv.items(), key=lambda kv: kv[1].get("last_seen", ""), reverse=True)
    print(f"{'ip':<16}{'':<4}{'mac':<18} {'vendor':<22} {'name':<22} {'type':<14} {'first':<11} seen")
    for key, d in rows:
        up = d.get("last_seen") == latest
        if args.offline and up:
            continue
        name = d.get("upnp_name") or d.get("hostname") or "-"
        print(f"{d.get('ip', ''):<16}{'up' if up else '':<4}{d.get('mac') or '-':<18} "
              f"{d.get('vendor', '-')[:21]:<22} {name[:21]:<22} {d.get('device', '-')[:13]:<14} "
              f"{d.get('first_seen', '')[:10]:<11} {d.get('seen', 0)}")
    print(f"{len(rows)} known")


def cmd_mon(args):
    rtts, sent = [], 0
    try:
        while args.count == 0 or sent < args.count:
            sent += 1
            up, ttl, rtt = discovery.ping(args.host, args.timeout)
            now = datetime.datetime.now().strftime("%H:%M:%S")
            if up:
                rtts.append(rtt or 0.0)
                print(f"{now} {args.host} {rtt}ms ttl={ttl}", flush=True)
            else:
                print(f"{now} {args.host} timeout", flush=True)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        pass
    loss = 100 * (sent - len(rtts)) / max(sent, 1)
    print(f"sent {sent}, lost {sent - len(rtts)} ({loss:.0f}%)")
    if rtts:
        jitter = statistics.pstdev(rtts)
        print(f"min {min(rtts)}ms, avg {statistics.mean(rtts):.1f}ms, max {max(rtts)}ms, jitter {jitter:.1f}ms")


def cmd_upnp(args):
    found = ssdp.discover(args.timeout, discovery.local_ip())
    for ip in sorted(found, key=ipaddress.ip_address):
        d = found[ip]
        model = " ".join(x for x in (d.get("manufacturer"), d.get("model_name")) if x)
        print(f"{ip:<16} {d.get('friendly_name', '-')[:30]:<31} {model[:40]}")
        if args.verbose:
            for k in ("device_type", "server", "location"):
                if d.get(k):
                    print(f"{'':<16} {k}: {d[k]}")
    print(f"{len(found)} devices")


def cmd_serve(args):
    rescan = None
    if args.interval:
        net = _network(args.network)
        rescan = lambda: scan(net, quiet=True)
    serve.run(args.host, args.port, rescan, args.interval)


def cmd_label(args):
    if args.key is None:
        for k, v in sorted(store.load_labels().items()):
            print(f"{k:<20} {v}")
        return
    store.set_label(args.key, args.name)
    print(f"{'set' if args.name else 'removed'} {args.key}")


def cmd_vendor(args):
    for mac in args.mac:
        print(f"{mac:<20} {oui.vendor(discovery.normalize_mac(mac)) or '-'}")


def cmd_wake(args):
    mac = args.target
    if ":" not in mac and "-" not in mac:
        labels = {v.lower(): k for k, v in store.load_labels().items()}
        mac = labels.get(mac.lower(), mac)
    wol.wake(mac, args.broadcast)
    print(f"sent {mac}")


def cmd_info(args):
    print(f"version: {__version__}")
    print(f"ip: {discovery.local_ip()}")
    print(f"gateway: {discovery.default_gateway() or '-'}")
    print(f"subnet: {discovery.default_subnet()}")
    print(f"vendors: {len(oui.load())}")
    print(f"scans: {len(store.list_scans())}")
    print(f"labels: {len(store.load_labels())}")


def build_parser():
    ap = argparse.ArgumentParser(prog="netfun", description="network scanner", formatter_class=_Fmt)
    ap.add_argument("--version", action="version", version=f"netfun {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True, metavar="command")

    def add(name, help, func):
        p = sub.add_parser(name, help=help, description=help, formatter_class=_Fmt)
        p.set_defaults(func=func)
        return p

    p = add("scan", "scan and save", cmd_scan)
    _add_scan_opts(p)
    p.add_argument("--json", metavar="file")
    p.add_argument("--csv", metavar="file")
    p.add_argument("--html", metavar="file")
    p.add_argument("--no-save", action="store_true")

    p = add("watch", "rescan on an interval, print changes", cmd_watch)
    _add_scan_opts(p)
    p.add_argument("-i", "--interval", type=int, default=300, help="seconds")
    p.add_argument("--beep", action="store_true")
    p.add_argument("--new-only", action="store_true", help="only report new devices")
    p.add_argument("--exec", metavar="cmd", help="run on change, changes in $NETFUN_CHANGES")

    p = add("show", "print a saved scan", cmd_show)
    p.add_argument("scan", nargs="?", default="-1", help="index or file, default -1")
    p.add_argument("--brief", action="store_true", help="no ports")

    p = add("history", "list saved scans", cmd_history)
    p.add_argument("-n", "--limit", type=int, default=20)

    p = add("diff", "compare two scans", cmd_diff)
    p.add_argument("old", nargs="?", default="-2")
    p.add_argument("new", nargs="?", default="-1")

    p = add("report", "export a saved scan", cmd_report)
    p.add_argument("scan", nargs="?", default="-1")
    p.add_argument("-f", "--format", choices=["html", "csv", "json"], default="html")
    p.add_argument("-o", "--output")

    p = add("ports", "port scan one host", cmd_ports)
    p.add_argument("host")
    p.add_argument("-p", "--ports", default="1-1024")
    p.add_argument("-w", "--workers", type=int, default=256)
    p.add_argument("-t", "--timeout", type=float, default=0.5)

    p = add("devices", "every device ever seen", cmd_devices)
    p.add_argument("--offline", action="store_true", help="only devices missing from latest scan")

    p = add("mon", "continuous ping with loss and jitter", cmd_mon)
    p.add_argument("host")
    p.add_argument("-i", "--interval", type=float, default=1.0, help="seconds")
    p.add_argument("-c", "--count", type=int, default=0, help="0 = forever")
    p.add_argument("-t", "--timeout", type=int, default=1000, help="ms")

    p = add("upnp", "list upnp/ssdp devices", cmd_upnp)
    p.add_argument("-t", "--timeout", type=float, default=3.0, help="seconds")
    p.add_argument("-v", "--verbose", action="store_true")

    p = add("serve", "local web view", cmd_serve)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("-i", "--interval", type=int, default=0, help="rescan seconds, 0 = off")
    p.add_argument("network", nargs="?", help="cidr for rescans")

    p = add("label", "name a device by mac or ip, no args lists", cmd_label)
    p.add_argument("key", nargs="?")
    p.add_argument("name", nargs="?", default="", help="omit to remove")

    p = add("vendor", "mac vendor lookup", cmd_vendor)
    p.add_argument("mac", nargs="+")

    p = add("wake", "wake-on-lan by mac or label", cmd_wake)
    p.add_argument("target")
    p.add_argument("--broadcast", default="255.255.255.255")

    add("update-oui", "download vendor db", lambda a: oui.update())
    add("info", "local network info", cmd_info)
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
