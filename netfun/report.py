"""Output formats: terminal table, CSV, and a self-contained HTML report."""

import csv
import html
import json
import math

from .ports import service_name


def display_name(h):
    return h.get("label") or h.get("hostname") or ""


def print_table(result, show_ports=True):
    hosts = result["hosts"]
    print(f"\n{'IP':<16} {'MAC':<18} {'VENDOR':<26} {'NAME':<22} {'DEVICE / OS GUESS':<30}")
    print("-" * 116)
    for h in hosts:
        tag = "*" if h["self"] else ("G" if h["gateway"] else "")
        guess = h["device"] or h["os_guess"] or "-"
        print(f"{h['ip'] + tag:<16} {h['mac'] or '-':<18} {(h['vendor'] or '-')[:25]:<26} "
              f"{(display_name(h) or '-')[:21]:<22} {guess[:30]}")
        if show_ports:
            for p in h["ports"]:
                banner = h["services"].get(str(p), "")
                print(f"{'':<16}   {p:>5}/tcp  {service_name(p):<14} {banner}")
    warnings = [(h, w) for h in hosts for w in h.get("warnings", [])]
    print(f"\n{len(hosts)} hosts found in {result['duration_s']}s. (* = this machine, G = gateway)")
    if warnings:
        print("\nWorth a look:")
        for h, w in warnings:
            print(f"  ! {h['ip']:<15} port {w}")


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


# --------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------

def _topology_svg(result):
    """A star diagram: gateway in the middle, every other host around it."""
    hosts = [h for h in result["hosts"] if not h["gateway"]]
    gw = next((h for h in result["hosts"] if h["gateway"]), None)
    n = max(len(hosts), 1)
    size, cx, cy = 720, 360, 360
    r = 270
    parts = [f'<svg viewBox="0 0 {size} {size}" role="img" aria-label="Network map">']
    pos = []
    for i, h in enumerate(hosts):
        a = 2 * math.pi * i / n - math.pi / 2
        x, y = cx + r * math.cos(a), cy + r * math.sin(a)
        pos.append((h, x, y))
        parts.append(f'<line x1="{cx}" y1="{cy}" x2="{x:.1f}" y2="{y:.1f}" class="edge"/>')
    parts.append(f'<circle cx="{cx}" cy="{cy}" r="34" class="node gw"/>')
    parts.append(f'<text x="{cx}" y="{cy + 4}" class="lbl strong">'
                 f'{html.escape(gw["ip"] if gw else "gateway")}</text>')
    for h, x, y in pos:
        cls = "self" if h["self"] else ("warn" if h.get("warnings") else "")
        name = display_name(h) or h["device"] or h["vendor"] or ""
        tip = html.escape(f"{h['ip']} {name} {h['mac']}")
        parts.append(f'<g><title>{tip}</title>'
                     f'<circle cx="{x:.1f}" cy="{y:.1f}" r="16" class="node {cls}"/>'
                     f'<text x="{x:.1f}" y="{y + 32:.1f}" class="lbl">{html.escape(h["ip"].split(".")[-1])}'
                     f'</text><text x="{x:.1f}" y="{y + 46:.1f}" class="lbl dim">'
                     f'{html.escape(name[:18])}</text></g>')
    parts.append("</svg>")
    return "".join(parts)


_CSS = """
:root{--bg:#f7f7f5;--fg:#1d1d1b;--dim:#6b6b66;--card:#fff;--line:#d9d8d2;--accent:#2f6fde;
--warn:#c2410c;--self:#15803d}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--fg:#ecebe6;--dim:#9a9993;--card:#21211f;
--line:#3a3a36;--accent:#6b9cf0;--warn:#f59e5b;--self:#4ade80}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px}
h1{margin:0 0 4px;font-size:26px}.meta{color:var(--dim);margin-bottom:24px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:24px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.stat b{display:block;font-size:24px}.stat span{color:var(--dim);font-size:13px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:24px}
svg{width:100%;max-width:640px;display:block;margin:0 auto}
.edge{stroke:var(--line);stroke-width:1.5}.node{fill:var(--card);stroke:var(--accent);stroke-width:2.5}
.node.gw{fill:var(--accent)}.node.self{stroke:var(--self)}.node.warn{stroke:var(--warn)}
.lbl{fill:var(--fg);font-size:12px;text-anchor:middle}.lbl.dim{fill:var(--dim);font-size:10.5px}
.lbl.strong{fill:#fff;font-weight:600}
.tw{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:14px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--dim);font-weight:500;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
code{font-family:ui-monospace,Consolas,monospace;font-size:13px}
.port{display:inline-block;background:var(--bg);border:1px solid var(--line);border-radius:5px;
padding:0 6px;margin:0 4px 4px 0;font-size:12px}.port.risk{border-color:var(--warn);color:var(--warn)}
.dim{color:var(--dim)}input{width:100%;padding:8px 10px;border-radius:8px;border:1px solid var(--line);
background:var(--card);color:var(--fg);margin-bottom:12px;font:inherit}
"""


def write_html(result, path):
    from .ports import RISKY_PORTS

    hosts = result["hosts"]
    open_ports = sum(len(h["ports"]) for h in hosts)
    warns = sum(len(h.get("warnings", [])) for h in hosts)
    known = sum(1 for h in hosts if h["vendor"] and not h["vendor"].startswith("("))
    rows = []
    for h in hosts:
        tags = []
        if h["self"]:
            tags.append("this machine")
        if h["gateway"]:
            tags.append("gateway")
        ports = "".join(
            f'<span class="port{" risk" if p in RISKY_PORTS and not h["self"] else ""}" '
            f'title="{html.escape(h["services"].get(str(p), ""))}">{p}/{service_name(p)}</span>'
            for p in h["ports"]) or '<span class="dim">none</span>'
        rows.append(
            f"<tr><td><code>{h['ip']}</code><br><span class='dim'>{', '.join(tags)}</span></td>"
            f"<td><code>{h['mac'] or '-'}</code><br><span class='dim'>{html.escape(h['vendor'] or '')}</span></td>"
            f"<td>{html.escape(display_name(h) or '-')}</td>"
            f"<td>{html.escape(h['device'] or '-')}<br><span class='dim'>{html.escape(h['os_guess'])}</span></td>"
            f"<td>{ports}</td></tr>")
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>netfun report</title><style>{_CSS}</style></head><body><main>
<h1>netfun network report</h1>
<div class="meta">{html.escape(result['network'])} · scanned {html.escape(result['timestamp'])}
 · {result['duration_s']}s</div>
<div class="stats">
<div class="stat"><b>{len(hosts)}</b><span>devices</span></div>
<div class="stat"><b>{known}</b><span>known vendors</span></div>
<div class="stat"><b>{open_ports}</b><span>open ports</span></div>
<div class="stat"><b>{warns}</b><span>worth a look</span></div></div>
<div class="card">{_topology_svg(result)}</div>
<div class="card"><input id="q" placeholder="Filter by IP, vendor, name, port...">
<div class="tw"><table id="t"><thead><tr><th>IP</th><th>MAC / vendor</th><th>Name</th>
<th>Device guess</th><th>Open ports</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div></div>
</main><script>
document.getElementById('q').addEventListener('input',e=>{{const q=e.target.value.toLowerCase();
for(const r of document.querySelectorAll('#t tbody tr'))r.style.display=r.textContent.toLowerCase().includes(q)?'':'none'}});
</script></body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)
