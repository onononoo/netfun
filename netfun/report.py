"""output: table, csv, json, html."""

import csv
import html
import json
import math

from .ports import RISKY_PORTS, service_name


def display_name(h):
    return h.get("label") or h.get("upnp", {}).get("friendly_name") or h.get("hostname") or ""


def _tag(h):
    return "self" if h["self"] else ("gw" if h["gateway"] else "")


def print_table(result, show_ports=True):
    hosts = result["hosts"]
    print(f"{'ip':<16}{'':<5}{'mac':<18} {'vendor':<26} {'name':<22} type")
    for h in hosts:
        kind = h["device"] or h["os_guess"] or "-"
        print(f"{h['ip']:<16}{_tag(h):<5}{h['mac'] or '-':<18} {(h['vendor'] or '-')[:25]:<26} "
              f"{(display_name(h) or '-')[:21]:<22} {kind}")
        if show_ports:
            for p in h["ports"]:
                banner = h["services"].get(str(p), "")
                print(f"{'':<21}{p:>5}/tcp {service_name(p):<14} {banner}")
    print(f"{len(hosts)} hosts, {result['duration_s']}s")
    warnings = [(h, w) for h in hosts for w in h.get("warnings", [])]
    if warnings:
        print("warnings:")
        for h, w in warnings:
            print(f"  {h['ip']:<15} {w}")


def write_json(result, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)


def write_csv(result, path):
    fields = ["ip", "mac", "vendor", "hostname", "label", "device", "os_guess",
              "ttl", "rtt_ms", "ports"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for h in result["hosts"]:
            w.writerow({**h, "ports": " ".join(map(str, h["ports"]))})


def _topology_svg(result):
    # gateway in the center, hosts on a ring
    hosts = [h for h in result["hosts"] if not h["gateway"]]
    gw = next((h for h in result["hosts"] if h["gateway"]), None)
    n = max(len(hosts), 1)
    size, cx, cy, r = 720, 360, 360, 270
    parts = [f'<svg viewBox="0 0 {size} {size}" role="img" aria-label="map">']
    pos = []
    for i, h in enumerate(hosts):
        a = 2 * math.pi * i / n - math.pi / 2
        x, y = cx + r * math.cos(a), cy + r * math.sin(a)
        pos.append((h, x, y))
        parts.append(f'<line x1="{cx}" y1="{cy}" x2="{x:.1f}" y2="{y:.1f}" class="edge"/>')
    parts.append(f'<circle cx="{cx}" cy="{cy}" r="30" class="node gw"/>')
    parts.append(f'<text x="{cx}" y="{cy + 4}" class="lbl">'
                 f'{html.escape(gw["ip"] if gw else "gateway")}</text>')
    for h, x, y in pos:
        name = display_name(h) or h["device"] or ""
        tip = html.escape(f"{h['ip']} {name} {h['mac']}")
        parts.append(f'<g><title>{tip}</title>'
                     f'<circle cx="{x:.1f}" cy="{y:.1f}" r="12" class="node"/>'
                     f'<text x="{x:.1f}" y="{y + 28:.1f}" class="lbl">{html.escape(h["ip"].split(".")[-1])}'
                     f'</text><text x="{x:.1f}" y="{y + 41:.1f}" class="lbl dim">'
                     f'{html.escape(name[:18])}</text></g>')
    parts.append("</svg>")
    return "".join(parts)


_CSS = """
:root{--bg:#fff;--fg:#222;--dim:#888;--line:#ddd}
@media (prefers-color-scheme:dark){:root{--bg:#141414;--fg:#ddd;--dim:#888;--line:#333}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 ui-monospace,Consolas,monospace}
main{max-width:1000px;margin:0 auto;padding:24px 16px}
h1{margin:0;font-size:16px;font-weight:600}.meta{color:var(--dim);margin-bottom:24px}
svg{width:100%;max-width:560px;display:block;margin:0 auto 24px}
.edge{stroke:var(--line)}.node{fill:var(--bg);stroke:var(--fg)}.node.gw{fill:var(--line)}
.lbl{fill:var(--fg);font-size:11px;text-anchor:middle}.lbl.dim{fill:var(--dim);font-size:10px}
.tw{overflow-x:auto}table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--dim);font-weight:400}.dim{color:var(--dim)}.risk{text-decoration:underline}
input{width:100%;padding:6px 8px;border:1px solid var(--line);background:var(--bg);color:var(--fg);
margin-bottom:12px;font:inherit}
"""


def render_html(result):
    rows = []
    for h in result["hosts"]:
        ports = " ".join(
            f'<span class="{"risk" if p in RISKY_PORTS and not h["self"] else ""}" '
            f'title="{html.escape(h["services"].get(str(p), ""))}">{p}/{service_name(p)}</span>'
            for p in h["ports"]) or '<span class="dim">-</span>'
        rows.append(
            f"<tr><td>{h['ip']} <span class='dim'>{_tag(h)}</span></td>"
            f"<td>{h['mac'] or '-'}<br><span class='dim'>{html.escape(h['vendor'] or '')}</span></td>"
            f"<td>{html.escape(display_name(h) or '-')}</td>"
            f"<td>{html.escape(h['device'] or h['os_guess'] or '-')}</td>"
            f"<td>{ports}</td></tr>")
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>netfun</title><style>{_CSS}</style></head><body><main>
<h1>netfun</h1>
<div class="meta">{html.escape(result['network'])}, {html.escape(result['timestamp'])},
 {len(result['hosts'])} hosts</div>
{_topology_svg(result)}
<input id="q" placeholder="filter">
<div class="tw"><table id="t"><thead><tr><th>ip</th><th>mac</th><th>name</th>
<th>type</th><th>ports</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>
</main><script>
document.getElementById('q').addEventListener('input',e=>{{const q=e.target.value.toLowerCase();
for(const r of document.querySelectorAll('#t tbody tr'))r.style.display=r.textContent.toLowerCase().includes(q)?'':'none'}});
</script></body></html>"""
    return doc


def write_html(result, path):
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_html(result))
