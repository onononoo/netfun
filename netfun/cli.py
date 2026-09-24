"""cli."""

import argparse
import concurrent.futures as cf
import datetime
import ipaddress
import sys
import time

from . import __version__, diff, discovery, oui, report, store, wol
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


def _do_scan(args, quiet=False):
    return scan(_network(args.network),
                ports=parse_ports(args.ports) if args.ports else COMMON_PORTS,
                workers=args.workers, ping_timeout=args.ping_timeout,
                port_timeout=args.port_timeout, banners=not args.no_banners, quiet=quiet)


def cmd_scan(args):
    result = _do_scan(args)
    report.print_table(result)
    if not args.no_save:
        prev = store.list_scans()
        print(f"saved {store.save_scan(result)}")
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
                for line in diff.format_changes(changes):
                    print(f"{now} {line}", flush=True)
                if args.beep and not diff.is_empty(changes):
                    print("\a", end="", flush=True)
            else:
                print(f"{now} {len(result['hosts'])} hosts", flush=True)
            store.save_scan(result)
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
