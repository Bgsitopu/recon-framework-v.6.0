"""
Reporting system v9.0
P3: Interactive Attack Surface Graph (vis.js network)
P10: Professional HTML dashboard
"""
from __future__ import annotations
import json
import os
from datetime import datetime
from core.logger import get_logger

log = get_logger("reporter")
SEV_COLOR = {
    "critical": "#ff4444", "high": "#ff8800",
    "medium": "#ffcc00", "low": "#44aaff", "info": "#888",
}


def _badge(sev: str) -> str:
    c = SEV_COLOR.get(sev, "#888")
    return f'<span class="badge" style="background:{c}">{sev.upper()}</span>'


# ── JSON / TXT ────────────────────────────────────────────────────────────────

def save_json(results: dict, out_dir: str, target: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    slug = target.replace("https://", "").replace("http://", "").replace("/", "_")
    path = os.path.join(out_dir, f"{slug}_report.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str)
    log.info(f"[reporter] JSON: {path}")
    return path


def save_txt(results: dict, out_dir: str, target: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    slug = target.replace("https://", "").replace("http://", "").replace("/", "_")
    path = os.path.join(out_dir, f"{slug}_report.txt")

    ai       = results.get("ai_analysis") or {}
    ssl      = results.get("ssl_check") or {}
    em       = results.get("email_harvest") or {}
    vuln     = results.get("vuln_scan") or {}
    sub_data = results.get("subdomain") or {}
    cloud    = results.get("cloud_discovery") or {}
    params   = results.get("parameter_discovery") or {}

    lines = [
        f"RECON REPORT v9.0 — {target}",
        f"Generated : {datetime.now().isoformat()}",
        f"Profile   : {results.get('profile', 'balanced')}",
        "=" * 70,
        f"\nRISK SCORE : {ai.get('risk_score','N/A')}/100  [{ai.get('risk_level','?')}]",
        f"SUMMARY    : {ai.get('summary','')}",
        f"\nSECURITY POSTURE : {vuln.get('posture_score',0)}/100",
        f"CSP SCORE        : {vuln.get('csp_score',0)}/100",
        f"HSTS SCORE       : {vuln.get('hsts_score',0)}/100",
        "\n[TOP ATTACK PATHS]",
    ]
    for p in ai.get("top_attack_paths", []):
        lines.append(f"  → {p}")

    lines += ["\n[CRITICAL ASSETS]"]
    for a in ai.get("critical_assets", []):
        lines.append(f"  • {a}")

    lines += ["\n[RISK BREAKDOWN]"]
    for sev in ("critical", "high", "medium", "low"):
        items = ai.get("risk_breakdown", {}).get(sev, [])
        if items:
            lines.append(f"  {sev.upper():8}: {', '.join(items)}")

    lines += ["\n[MISCONFIGURATIONS]"]
    for m in ai.get("misconfigurations", []):
        lines.append(f"  [{m['severity'].upper()}] {m['issue']}  (w:{m.get('weight',0)} cat:{m.get('category','')})")
        lines.append(f"    → {m.get('remediation','')}")

    lines += [f"\n[SUBDOMAINS — {sub_data.get('total_validated',0)} validated / "
              f"{sub_data.get('total_discovered',0)} discovered / "
              f"{sub_data.get('wildcard_filtered_count',0)} wildcard-filtered]"]
    if sub_data.get("wildcard_dns"):
        lines.append(f"  ⚠ Wildcard DNS detected! IPs: {sub_data.get('wildcard_ips',[])} ")
    for e in sub_data.get("entries", []):
        lines.append(f"  {e['subdomain']:45} {e['ip']:16} [{', '.join(e['sources'])}]")

    ports = (results.get("port_scan") or {}).get("open_ports", [])
    lines += [f"\n[OPEN PORTS — {len(ports)} open]"]
    for p in ports:
        proto = p.get("protocol", "tcp")
        method = p.get("detection_method", "")
        conf = p.get("confidence", "?")
        fp = p.get("fingerprint", "")
        lines.append(f"  {p['port']:6}/{proto:<8} {p['service']:<16} conf={conf}% method={method}")
        if fp:
            lines.append(f"    Banner: {fp}")

    # P5: SSL with cert_type, expiry_date, remaining days
    days_disp = ssl.get("days_until_expiry")
    expiry_date = ssl.get("expiry_date") or ssl.get("not_after", "?")
    if days_disp is None:
        days_str = f"unknown ({ssl.get('expiry_parse_error','parse error')})"
        status_str = "Unknown"
    elif days_disp < 0:
        days_str = f"{abs(days_disp)} days ago (EXPIRED)"
        status_str = "Expired"
    else:
        days_str = f"{days_disp} days remaining"
        status_str = "Valid" if days_disp > 30 else "Expiring Soon"
    lines += [
        "\n[SSL/TLS]",
        f"  Subject    : {ssl.get('subject_cn','')}",
        f"  Issuer     : {ssl.get('issuer_cn','')}",
        f"  Cert Type  : {ssl.get('cert_type','unknown')}",
        f"  Protocol   : {ssl.get('protocol','')}  Cipher: {ssl.get('cipher','')}",
        f"  Expires    : {expiry_date}",
        f"  Remaining  : {days_str}",
        f"  Status     : {status_str}",
        f"  Chain      : {'VALID' if ssl.get('chain_valid') else 'INVALID'}",
        f"  HSTS       : {ssl.get('hsts_status','missing').upper()}",
    ]

    lines += [f"\n[SECURITY HEADERS — posture {vuln.get('posture_score',0)}/100]"]
    for h in vuln.get("missing_headers", []):
        lines.append(f"  MISSING [{h['severity'].upper()}] {h['header']}")
        lines.append(f"    → {h.get('remediation','')}")

    lines += [f"\n[CVE PATHS — {len(vuln.get('cve_paths',[]))} found]"]
    for c in vuln.get("cve_paths", []):
        tag = "CONFIRMED" if c.get("confirmed") else "unconfirmed"
        cve = f" [{c['cve_id']}]" if c.get("cve_id") else ""
        lines.append(f"  [{c['severity'].upper()}] {c['url']}  [{c['status']}]  {tag}{cve}")
        if c.get("evidence"):
            lines.append(f"    Evidence: {c['evidence'][:100]}")

    lines += [f"\n[EMAILS — {em.get('total',0)}]"]
    for e in em.get("on_domain", []):
        lines.append(f"  {e}  [on-domain]")

    # P5: Wayback with source info
    wb = results.get("wayback") or {}
    wb_src = wb.get("source_used", "wayback")
    wb_fb  = ", ".join(wb.get("fallback_sources", [])) or "none"
    lines += [f"\n[WAYBACK — {wb.get('total',0)} URLs | source={wb_src} | fallbacks={wb_fb}]"]
    if wb.get("error_reason"):
        lines.append(f"  Error: {wb['error_reason']}")

    # P5: WAF with confidence + evidence
    tech = results.get("tech_detect") or {}
    lines += [f"\n[WAF DETECTION]"]
    for wf in tech.get("waf_findings", []):
        lines.append(f"  {wf['name']} — confidence={wf['confidence']}% "
                     f"status={wf.get('validation_status','?')}")
        for ev in wf.get("evidence", [])[:3]:
            lines.append(f"    Evidence: {ev}")
    if not tech.get("waf_findings"):
        waf_dbg = tech.get("waf_debug", {})
        sigs = waf_dbg.get("signatures_checked", "?")
        lines.append(f"  No WAF detected  (signatures_checked={sigs}, matches=0)")

    lines += [f"\n[PARAMETERS — {params.get('total_params',0)} total]"]
    for risk in ("critical", "high", "medium"):
        ps = (params.get("by_risk") or {}).get(risk, [])
        if ps:
            lines.append(f"  {risk.upper()}: {', '.join(ps)}")

    lines += [f"\n[CLOUD ASSETS — {cloud.get('total',0)}]"]
    for a in cloud.get("assets", []):
        lines.append(f"  [{a['risk'].upper()}] {a['provider']:20} {a['url']}")

    # P5: Dir discovery stats
    dir_data = results.get("dir_discovery") or {}
    dir_stats = dir_data.get("stats", {})
    lines += [f"\n[DIR DISCOVERY — {len(dir_data.get('found',[]))} found]"]
    if dir_stats:
        lines.append(f"  Requests: {dir_stats.get('requests',0)} | "
                     f"Delays: {dir_stats.get('delays_applied',0)} | "
                     f"Rate-limit events: {dir_stats.get('rate_limit_events',0)}")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    log.info(f"[reporter] TXT: {path}")
    return path


# ── CSS ───────────────────────────────────────────────────────────────────────

HTML_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;color:#c9d1d9;font-family:'Segoe UI',monospace;padding:20px;font-size:14px}
h1{color:#58a6ff;font-size:1.6em;margin-bottom:4px}
h2{color:#79c0ff;font-size:.9em;margin:22px 0 8px;border-bottom:1px solid #30363d;
   padding-bottom:4px;text-transform:uppercase;letter-spacing:.06em}
.meta{color:#8b949e;font-size:.8em;margin-bottom:16px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:20px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px;text-align:center}
.card .num{font-size:1.8em;font-weight:bold;color:#58a6ff}
.card .lbl{font-size:.72em;color:#8b949e;margin-top:4px}
table{width:100%;border-collapse:collapse;font-size:.82em;margin-bottom:12px}
th{background:#161b22;color:#8b949e;padding:7px;text-align:left;border-bottom:1px solid #30363d}
td{padding:5px 7px;border-bottom:1px solid #21262d;word-break:break-all}
tr:hover td{background:#161b2288}
.badge{display:inline-block;padding:1px 7px;border-radius:3px;font-size:.72em;font-weight:bold;color:#000}
.tag{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.75em;font-weight:bold;margin:2px}
.tech{background:#1f6feb;color:#fff}.waf{background:#388bfd22;color:#79c0ff;border:1px solid #388bfd}
pre{background:#161b22;padding:10px;border-radius:6px;overflow-x:auto;font-size:.78em;
    color:#a5d6ff;max-height:280px;white-space:pre-wrap}
.summary{background:#161b22;border-left:4px solid #58a6ff;padding:10px 14px;
         border-radius:0 6px 6px 0;margin-bottom:14px;line-height:1.6;font-size:.88em}
details summary{cursor:pointer;color:#79c0ff;padding:4px 0}
.remed-card{background:#161b22;border:1px solid #30363d;border-radius:6px;margin-bottom:8px;overflow:hidden}
.remed-header{padding:8px 12px;background:#21262d;display:flex;align-items:center;gap:8px}
.remed-body{padding:8px 12px;color:#8b949e;font-size:.85em;line-height:1.5}
.heatmap{display:flex;flex-wrap:wrap;gap:4px;margin-bottom:12px}
.hm-cell{padding:3px 8px;border-radius:3px;font-size:.72em;cursor:default;white-space:nowrap}
.ep-group{margin-bottom:14px}
.ep-group h3{color:#58a6ff;font-size:.85em;margin-bottom:6px;text-transform:uppercase}
.charts-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px;margin-bottom:20px}
.chart-box{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px}
.chart-box h3{color:#79c0ff;font-size:.82em;margin-bottom:10px;text-transform:uppercase}
canvas{max-width:100%}
.exec-box{background:#161b22;border:1px solid #388bfd;border-radius:8px;padding:16px;margin-bottom:16px}
.exec-box h3{color:#58a6ff;margin-bottom:8px}
.exec-box p{color:#c9d1d9;line-height:1.7;font-size:.9em}
.score-bar{height:8px;border-radius:4px;background:#30363d;margin:4px 0}
.score-fill{height:8px;border-radius:4px}
#graph-container{background:#161b22;border:1px solid #30363d;border-radius:8px;
                 height:520px;position:relative;margin-bottom:16px}
.graph-controls{display:flex;gap:8px;margin-bottom:8px;flex-wrap:wrap}
.graph-controls button{background:#21262d;border:1px solid #30363d;color:#c9d1d9;
                        padding:4px 12px;border-radius:4px;cursor:pointer;font-size:.8em}
.graph-controls button:hover{background:#30363d}
.graph-legend{display:flex;gap:12px;flex-wrap:wrap;font-size:.75em;margin-bottom:8px}
.legend-item{display:flex;align-items:center;gap:4px}
.legend-dot{width:10px;height:10px;border-radius:50%}
.gallery-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px;margin-bottom:16px}
.gallery-card{background:#161b22;border:1px solid #30363d;border-radius:8px;overflow:hidden}
.gallery-card img{width:100%;height:140px;object-fit:cover;background:#0d1117}
.gallery-card .gc-info{padding:8px 10px}
.gallery-card .gc-title{font-size:.8em;color:#c9d1d9;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.gallery-card .gc-url{font-size:.72em;color:#8b949e;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.gallery-card .gc-cat{font-size:.68em;font-weight:bold;margin-top:2px}
.path-item{background:#161b22;border-left:3px solid #ff4444;padding:6px 10px;
           margin-bottom:6px;border-radius:0 4px 4px 0;font-size:.85em}
.asset-item{background:#161b22;border-left:3px solid #58a6ff;padding:6px 10px;
            margin-bottom:6px;border-radius:0 4px 4px 0;font-size:.85em}
"""


def _gauge_svg(score: int) -> str:
    import math
    color = "#ff4444" if score >= 70 else "#ff8800" if score >= 40 else "#44cc44"
    rad = math.radians(180 - score * 1.8)
    x = 100 + 80 * math.cos(rad)
    y = 100 - 80 * math.sin(rad)
    level = ("CRITICAL" if score >= 80 else "HIGH" if score >= 60
             else "MEDIUM" if score >= 35 else "LOW" if score >= 15 else "MINIMAL")
    return (f'<svg viewBox="0 0 200 110" width="200" height="110">'
            f'<path d="M20,100 A80,80 0 0,1 180,100" fill="none" stroke="#30363d" stroke-width="16" stroke-linecap="round"/>'
            f'<path d="M20,100 A80,80 0 0,1 {x:.1f},{y:.1f}" fill="none" stroke="{color}" stroke-width="16" stroke-linecap="round"/>'
            f'<text x="100" y="90" text-anchor="middle" fill="{color}" font-size="28" font-weight="bold">{score}</text>'
            f'<text x="100" y="108" text-anchor="middle" fill="#8b949e" font-size="11">{level}</text>'
            f'</svg>')


def _score_bar(score: int, color: str = "#58a6ff") -> str:
    return (f'<div class="score-bar"><div class="score-fill" '
            f'style="width:{score}%;background:{color}"></div></div>'
            f'<span style="font-size:.75em;color:#8b949e">{score}/100</span>')


def _tech_donut_js(techs: list) -> str:
    if not techs:
        return "<p style='color:#8b949e;font-size:.8em'>No technologies detected.</p>"
    labels = json.dumps(techs[:12])
    data   = json.dumps([1] * min(len(techs), 12))
    colors = json.dumps(["#58a6ff","#ff8800","#44cc44","#ff4444","#ffcc00",
                         "#79c0ff","#ff6b6b","#51cf66","#ffd43b","#74c0fc",
                         "#f783ac","#a9e34b"][:len(techs)])
    return (f'<canvas id="techChart" height="180"></canvas>'
            f'<script>new Chart(document.getElementById("techChart"),{{'
            f'type:"doughnut",'
            f'data:{{labels:{labels},datasets:[{{data:{data},backgroundColor:{colors},borderWidth:0}}]}},'
            f'options:{{plugins:{{legend:{{position:"right",labels:{{color:"#c9d1d9",font:{{size:11}},boxWidth:12}}}}}},cutout:"60%"}}'
            f'}});</script>')


def _radar_js(atk: dict) -> str:
    ep   = min(len(atk.get("entry_points", [])), 10)
    svc  = min(len(atk.get("exposed_services", [])), 10)
    subs = min(atk.get("subdomain_count", 0), 10)
    tech = min(len(atk.get("tech_stack", [])), 10)
    waf  = 0 if atk.get("waf") else 8
    cld  = min(atk.get("cloud_assets", 0), 10)
    return (f'<canvas id="radarChart" height="220"></canvas>'
            f'<script>new Chart(document.getElementById("radarChart"),{{'
            f'type:"radar",'
            f'data:{{labels:["Entry Points","Services","Subdomains","Tech Stack","No WAF","Cloud"],'
            f'datasets:[{{label:"Attack Surface",data:[{ep},{svc},{subs},{tech},{waf},{cld}],'
            f'backgroundColor:"rgba(88,166,255,0.15)",borderColor:"#58a6ff",pointBackgroundColor:"#58a6ff"}}]}},'
            f'options:{{scales:{{r:{{beginAtZero:true,max:10,'
            f'grid:{{color:"#30363d"}},pointLabels:{{color:"#c9d1d9",font:{{size:11}}}},'
            f'ticks:{{color:"#8b949e",backdropColor:"transparent"}}}}}},'
            f'plugins:{{legend:{{labels:{{color:"#c9d1d9"}}}}}}}}'
            f'}});</script>')


def _bar_js(by_category: dict) -> str:
    cats   = list(by_category.keys())
    counts = [len(v) for v in by_category.values()]
    colors = ["#ff4444","#ff8800","#ffcc00","#44aaff","#888","#79c0ff","#51cf66","#f783ac"]
    return (f'<canvas id="catChart" height="180"></canvas>'
            f'<script>new Chart(document.getElementById("catChart"),{{'
            f'type:"bar",'
            f'data:{{labels:{json.dumps(cats)},'
            f'datasets:[{{label:"Issues",data:{json.dumps(counts)},'
            f'backgroundColor:{json.dumps(colors[:len(cats)])},borderRadius:4}}]}},'
            f'options:{{plugins:{{legend:{{display:false}}}},'
            f'scales:{{x:{{ticks:{{color:"#8b949e"}},grid:{{color:"#30363d"}}}},'
            f'y:{{ticks:{{color:"#8b949e"}},grid:{{color:"#30363d"}},beginAtZero:true}}}}}}'
            f'}});</script>')


def _endpoint_heatmap(ep_groups: dict) -> str:
    colors = {"admin":"#ff4444","api":"#ff8800","login":"#ffcc00","asset":"#44aaff","other":"#555"}
    parts = []
    for group, urls in ep_groups.items():
        if not urls:
            continue
        c = colors.get(group, "#555")
        parts.append(f'<div class="ep-group"><h3 style="color:{c}">{group} ({len(urls)})</h3>'
                     f'<div class="heatmap">')
        for url in urls[:50]:
            path = url.split("?")[0][-45:]
            parts.append(f'<div class="hm-cell" style="background:{c}22;border:1px solid {c}44" '
                         f'title="{url}">{path}</div>')
        if len(urls) > 50:
            parts.append(f'<div class="hm-cell" style="background:#333;color:#8b949e">+{len(urls)-50} more</div>')
        parts.append("</div></div>")
    return "".join(parts) or "<p style='color:#8b949e'>No endpoints.</p>"


def _param_heatmap(by_risk: dict) -> str:
    colors = {"critical":"#ff4444","high":"#ff8800","medium":"#ffcc00","low":"#44aaff","info":"#555"}
    parts = []
    for risk in ("critical","high","medium","low","info"):
        params = by_risk.get(risk, [])
        if not params:
            continue
        c = colors[risk]
        parts.append(f'<div style="margin-bottom:8px"><span style="color:{c};font-weight:bold;'
                     f'font-size:.8em">{risk.upper()} ({len(params)})</span><br>'
                     f'<div class="heatmap">')
        for p in params[:40]:
            parts.append(f'<div class="hm-cell" style="background:{c}22;border:1px solid {c}44">{p}</div>')
        parts.append("</div></div>")
    return "".join(parts) or "<p style='color:#8b949e'>No parameters found.</p>"


def _subdomain_tree(entries: list, domain: str) -> str:
    if not entries:
        return "<p style='color:#8b949e'>No subdomains found.</p>"
    groups: dict[str, list] = {}
    for e in entries:
        prefix = e["subdomain"].replace(f".{domain}", "").split(".")[-1]
        groups.setdefault(prefix, []).append(e)
    lines = [f'<div style="font-family:monospace;font-size:.82em;line-height:1.8;color:#79c0ff">'
             f'<strong style="color:#58a6ff">🌐 {domain}</strong><br>']
    for prefix, items in sorted(groups.items()):
        lines.append(f'├── <span style="color:#79c0ff">{prefix}</span><br>')
        for i, e in enumerate(items):
            conn = "└──" if i == len(items)-1 else "├──"
            srcs = " ".join(
                f'<span class="badge" style="background:#1f6feb;color:#fff;font-size:.6em">{s}</span>'
                for s in e.get("sources", [])
            )
            lines.append(f'│&nbsp;&nbsp;&nbsp;{conn} {e["subdomain"]} '
                         f'<span style="color:#8b949e">{e["ip"]}</span> {srcs}<br>')
    lines.append("</div>")
    return "".join(lines)


# ── P3: Interactive Attack Surface Graph ──────────────────────────────────────

def _build_graph_data(results: dict) -> dict:
    """Build vis.js nodes/edges for the attack surface graph."""
    nodes = []
    edges = []
    nid   = 0

    def add_node(label: str, group: str, title: str = "", size: int = 20) -> int:
        nonlocal nid
        nid += 1
        nodes.append({"id": nid, "label": label[:30], "group": group,
                      "title": title or label, "size": size})
        return nid

    ai       = results.get("ai_analysis") or {}
    sub_data = results.get("subdomain") or {}
    techs    = (results.get("tech_detect") or {}).get("technologies", [])
    ports    = (results.get("port_scan") or {}).get("open_ports", [])
    panels   = (results.get("login_finder") or {}).get("panels", [])
    cve_paths= (results.get("vuln_scan") or {}).get("cve_paths", [])
    cloud    = (results.get("cloud_discovery") or {}).get("assets", [])
    corr     = ai.get("correlation") or {}

    domain = sub_data.get("domain", results.get("target", "target"))

    # Root domain node
    root_id = add_node(domain, "root", f"Root domain: {domain}", 35)

    # Subdomains
    sub_ids: dict[str, int] = {}
    for e in sub_data.get("entries", [])[:20]:
        sid = add_node(e["subdomain"], "subdomain",
                       f"IP: {e['ip']}\nSources: {', '.join(e['sources'])}")
        sub_ids[e["subdomain"]] = sid
        edges.append({"from": root_id, "to": sid})

    # Technologies
    tech_ids: dict[str, int] = {}
    for t in techs[:10]:
        tid = add_node(t, "tech", f"Technology: {t}", 15)
        tech_ids[t] = tid
        edges.append({"from": root_id, "to": tid})

    # Open ports
    for p in ports[:10]:
        pid = add_node(f":{p['port']}", "port",
                       f"Port {p['port']} — {p['service']}\n{p.get('fingerprint','')}", 14)
        edges.append({"from": root_id, "to": pid})

    # Login panels
    for panel in panels[:8]:
        short = panel["url"].split("/")[-1] or "login"
        lid = add_node(short, "login",
                       f"Login panel\n{panel['url']}\nTech: {panel.get('technology','?')}", 18)
        edges.append({"from": root_id, "to": lid})

    # Vulnerabilities (confirmed CVEs)
    for cve in cve_paths:
        if cve.get("confirmed"):
            vid = add_node(cve["description"][:25], "vuln",
                           f"{cve['severity'].upper()}: {cve['description']}\n{cve['url']}", 22)
            edges.append({"from": root_id, "to": vid})

    # Cloud assets
    for asset in cloud[:6]:
        cid = add_node(asset.get("provider", "cloud"), "cloud",
                       f"Cloud: {asset['url']}\nListable: {asset.get('listable', False)}", 16)
        edges.append({"from": root_id, "to": cid})

    # Tech → vuln correlations
    for tech, vulns in (corr.get("tech_to_vulns") or {}).items():
        if tech in tech_ids:
            for v in vulns[:2]:
                vid = add_node(v[:25], "vuln", f"CVE via {tech}: {v}", 16)
                edges.append({"from": tech_ids[tech], "to": vid})

    return {"nodes": nodes, "edges": edges}


def _graph_html(graph_data: dict) -> str:
    nodes_json = json.dumps(graph_data["nodes"])
    edges_json = json.dumps(graph_data["edges"])
    return f"""
<div class="graph-controls">
  <button onclick="network.fit()">⊞ Fit</button>
  <button onclick="network.setOptions({{physics:{{enabled:true}}}})">▶ Physics</button>
  <button onclick="network.setOptions({{physics:{{enabled:false}}}})">⏸ Freeze</button>
  <input id="graphSearch" placeholder="🔍 Search node..." style="background:#21262d;border:1px solid #30363d;
    color:#c9d1d9;padding:4px 8px;border-radius:4px;font-size:.8em" oninput="searchGraph(this.value)">
</div>
<div class="graph-legend">
  <div class="legend-item"><div class="legend-dot" style="background:#58a6ff"></div>Root</div>
  <div class="legend-item"><div class="legend-dot" style="background:#79c0ff"></div>Subdomain</div>
  <div class="legend-item"><div class="legend-dot" style="background:#1f6feb"></div>Technology</div>
  <div class="legend-item"><div class="legend-dot" style="background:#ff8800"></div>Port</div>
  <div class="legend-item"><div class="legend-dot" style="background:#ffcc00"></div>Login</div>
  <div class="legend-item"><div class="legend-dot" style="background:#ff4444"></div>Vuln</div>
  <div class="legend-item"><div class="legend-dot" style="background:#44cc44"></div>Cloud</div>
</div>
<div id="graph-container"></div>
<script src="https://unpkg.com/vis-network@9/standalone/umd/vis-network.min.js"></script>
<script>
(function(){{
  var nodes = new vis.DataSet({nodes_json});
  var edges = new vis.DataSet({edges_json});
  var groups = {{
    root:      {{color:{{background:"#58a6ff",border:"#388bfd"}},font:{{color:"#fff",size:14}}}},
    subdomain: {{color:{{background:"#1a3a5c",border:"#79c0ff"}},font:{{color:"#79c0ff"}}}},
    tech:      {{color:{{background:"#1f3a6e",border:"#1f6feb"}},font:{{color:"#79c0ff"}}}},
    port:      {{color:{{background:"#3a2000",border:"#ff8800"}},font:{{color:"#ff8800"}}}},
    login:     {{color:{{background:"#3a3000",border:"#ffcc00"}},font:{{color:"#ffcc00"}}}},
    vuln:      {{color:{{background:"#3a0000",border:"#ff4444"}},font:{{color:"#ff4444"}}}},
    cloud:     {{color:{{background:"#003a00",border:"#44cc44"}},font:{{color:"#44cc44"}}}},
  }};
  var container = document.getElementById("graph-container");
  var network = new vis.Network(container, {{nodes:nodes,edges:edges}}, {{
    groups: groups,
    edges: {{color:{{color:"#30363d",highlight:"#58a6ff"}},smooth:{{type:"dynamic"}}}},
    physics: {{stabilization:{{iterations:150}},barnesHut:{{gravitationalConstant:-3000}}}},
    interaction: {{hover:true,tooltipDelay:100,navigationButtons:false}},
  }});
  window.network = network;
  window.searchGraph = function(q) {{
    if (!q) {{ nodes.forEach(function(n){{ nodes.update({{id:n.id,hidden:false}}); }}); return; }}
    nodes.forEach(function(n) {{
      nodes.update({{id:n.id, hidden: !n.label.toLowerCase().includes(q.toLowerCase())}});
    }});
  }};
}})();
</script>"""


# ── Screenshot Gallery ────────────────────────────────────────────────────────

def _screenshot_gallery(screenshot_data: dict) -> str:
    gallery = screenshot_data.get("gallery", {})
    if not gallery:
        return "<p style='color:#8b949e'>No screenshots captured.</p>"

    cat_colors = {"homepage":"#58a6ff","login":"#ffcc00","admin":"#ff4444",
                  "endpoint":"#ff8800","custom":"#44cc44"}
    parts = []
    for cat, items in gallery.items():
        if not items:
            continue
        c = cat_colors.get(cat, "#888")
        parts.append(f'<h3 style="color:{c};font-size:.85em;margin:10px 0 6px">'
                     f'{cat.upper()} ({len(items)})</h3>'
                     f'<div class="gallery-grid">')
        for item in items:
            if item.get("error"):
                continue
            thumb = item.get("thumb") or item.get("path", "")
            title = item.get("title", "")[:40] or "No title"
            url   = item.get("url", "")
            status= item.get("status", "")
            img_src = f'file://{thumb}' if thumb else ""
            parts.append(
                f'<div class="gallery-card">'
                f'{"<img src=" + repr(img_src) + " loading=lazy>" if img_src else "<div style=height:140px;background:#21262d;display:flex;align-items:center;justify-content:center;color:#8b949e>No preview</div>"}'
                f'<div class="gc-info">'
                f'<div class="gc-title" title="{title}">{title}</div>'
                f'<div class="gc-url" title="{url}">{url}</div>'
                f'<div class="gc-cat" style="color:{c}">{cat} · HTTP {status}</div>'
                f'</div></div>'
            )
        parts.append("</div>")
    return "".join(parts)


# ── save_html ─────────────────────────────────────────────────────────────────

def save_html(results: dict, out_dir: str, target: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    slug = target.replace("https://", "").replace("http://", "").replace("/", "_")
    path = os.path.join(out_dir, f"{slug}_dashboard.html")

    ai       = results.get("ai_analysis") or {}
    risk     = ai.get("risk_score", 0) or 0
    rlevel   = ai.get("risk_level", "?") or "?"
    rc       = "#ff4444" if risk >= 70 else "#ff8800" if risk >= 40 else "#44cc44"
    misconf  = ai.get("misconfigurations") or []
    ssl      = results.get("ssl_check") or {}
    emails   = results.get("email_harvest") or {}
    vuln     = results.get("vuln_scan") or {}
    sub_data = results.get("subdomain") or {}
    subs     = sub_data.get("subdomains", []) or []
    sub_ent  = sub_data.get("entries", []) or []
    domain   = sub_data.get("domain", target) or target
    techs    = (results.get("tech_detect") or {}).get("technologies", []) or []
    tech_findings = (results.get("tech_detect") or {}).get("tech_findings", []) or []
    wafs     = (results.get("tech_detect") or {}).get("waf", []) or []
    ports    = (results.get("port_scan") or {}).get("open_ports", []) or []
    panels   = (results.get("login_finder") or {}).get("panels", []) or []
    js_finds = (results.get("js_analysis") or {}).get("findings", []) or []
    dirs     = ((results.get("dir_discovery") or {}).get("found", []) or [])[:100]
    eps      = ((results.get("endpoint") or {}).get("endpoints", []) or [])[:100]
    ep_grps  = ai.get("endpoint_groups") or {}
    atk      = ai.get("attack_surface") or {}
    by_cat   = ai.get("by_category") or {}
    cloud    = results.get("cloud_discovery") or {}
    params   = results.get("parameter_discovery") or {}
    corr     = ai.get("correlation") or {}
    shots    = results.get("screenshot") or {}

    ssl_days  = ssl.get("days_until_expiry", "N/A")
    ssl_color = ("#ff4444" if isinstance(ssl_days, int) and ssl_days < 0
                 else "#ff8800" if isinstance(ssl_days, int) and ssl_days <= 30
                 else "#44cc44")

    confirmed_cves = sum(1 for c in vuln.get("cve_paths", []) if c.get("confirmed"))
    port_scanned   = (results.get("port_scan") or {}).get("scanned", 0)
    params_by_risk = params.get("by_risk") or {}
    posture        = vuln.get("posture_score", 0)
    csp_score      = vuln.get("csp_score", 0)
    hsts_score     = vuln.get("hsts_score", 0)

    # Graph
    graph_data = _build_graph_data(results)
    graph_html = _graph_html(graph_data)

    # Remediation cards
    remed_html = "".join(
        f'<div class="remed-card"><div class="remed-header">'
        f'{_badge(m["severity"])} <strong>{m["issue"]}</strong>'
        f'<span style="margin-left:auto;color:#8b949e;font-size:.75em">[{m.get("category","")}] w:{m.get("weight",0)}</span>'
        f'</div><div class="remed-body">🔧 {m.get("remediation","")}</div></div>'
        for m in misconf
    ) or "<p style='color:#8b949e'>No issues found.</p>"

    # Missing headers table
    missing_hdrs = "".join(
        f"<tr><td>{_badge(h['severity'])}</td><td><strong>{h['header']}</strong></td>"
        f"<td style='color:#8b949e;font-size:.8em'>{h.get('explanation','')}</td>"
        f"<td style='color:#79c0ff;font-size:.78em'>{h.get('remediation','')}</td>"
        f"<td style='color:#8b949e;font-size:.75em'>{h.get('evidence','')}</td>"
        f"<td><span class='badge' style='background:#1f6feb'>{h.get('confidence','')}{'%' if h.get('confidence') else ''}</span></td>"
        f"<td style='color:#8b949e;font-size:.75em'>{h.get('validation_status','')}</td></tr>"
        for h in vuln.get("missing_headers", [])
    ) or "<tr><td colspan=7 style='color:#8b949e'>All headers present ✅</td></tr>"

    # CVE table
    cve_html = "".join(
        f"<tr><td>{_badge(c['severity'])}</td>"
        f"<td>{'<span style=\"color:#44cc44\">✅</span>' if c.get('confirmed') else '<span style=\"color:#ff8800\">⚠</span>'}</td>"
        f"<td>{c['url']}</td><td>{c.get('title', c.get('description',''))}</td>"
        f"<td>{c.get('cve_id','')}</td><td>{c['status']}</td>"
        f"<td style='font-size:.75em;color:#8b949e'>{c.get('evidence','')[:80]}</td></tr>"
        for c in vuln.get("cve_paths", [])
    ) or "<tr><td colspan=7 style='color:#8b949e'>None found</td></tr>"

    # Cloud table
    cloud_html = "".join(
        f"<tr><td>{_badge(a['risk'])}</td><td>{a['provider']}</td><td>{a['url']}</td>"
        f"<td>{'<span style=\"color:#ff4444\">YES</span>' if a.get('listable') else 'no'}</td>"
        f"<td>{a['status']}</td></tr>"
        for a in cloud.get("assets", [])
    ) or "<tr><td colspan=5 style='color:#8b949e'>No cloud assets found</td></tr>"

    # Tech table with version + outdated
    tech_table = "".join(
        f"<tr><td>{tf['name']}</td>"
        f"<td>{tf.get('version') or '<span style=\"color:#8b949e\">unknown</span>'}</td>"
        f"<td>{tf.get('confidence',0)}%</td>"
        f"<td>{tf.get('detection_method','')}</td>"
        f"<td>{'<span style=\"color:#ff4444\">⚠ OUTDATED</span>' if tf.get('outdated') else '✅'}</td>"
        f"<td style='font-size:.75em;color:#ff8800'>{', '.join(tf.get('cves',[])[:2])}</td></tr>"
        for tf in tech_findings
    ) or "<tr><td colspan=6 style='color:#8b949e'>None detected</td></tr>"

    # Correlation table
    tech_vulns = corr.get("tech_to_vulns", {})
    corr_html = "".join(
        f"<tr><td style='color:#79c0ff'>{tech}</td><td style='color:#ff8800'>{', '.join(vulns)}</td></tr>"
        for tech, vulns in tech_vulns.items()
    ) or "<tr><td colspan=2 style='color:#8b949e'>No correlations found</td></tr>"

    # Top attack paths
    paths_html = "".join(
        f'<div class="path-item">→ {p}</div>'
        for p in ai.get("top_attack_paths", [])
    ) or "<p style='color:#8b949e'>No attack paths identified.</p>"

    # Critical assets
    assets_html = "".join(
        f'<div class="asset-item">• {a}</div>'
        for a in ai.get("critical_assets", [])
    ) or "<p style='color:#8b949e'>No critical assets identified.</p>"

    # Wildcard DNS notice
    wildcard_notice = ""
    if sub_data.get("wildcard_dns"):
        wildcard_notice = (
            f'<div style="background:#3a2000;border:1px solid #ff8800;border-radius:6px;'
            f'padding:8px 12px;margin-bottom:8px;font-size:.85em">'
            f'⚠ <strong>Wildcard DNS detected</strong> — IPs: {sub_data.get("wildcard_ips",[])} — '
            f'{sub_data.get("wildcard_filtered_count",0)} false positives filtered</div>'
        )

    breakdown_html = "".join(
        f"<tr><td>{_badge(sev)}</td><td>{'<br>'.join(items)}</td></tr>"
        for sev, items in ai.get("risk_breakdown", {}).items() if items
    ) or "<tr><td colspan=2>No issues</td></tr>"

    src_tags = " ".join(
        f'<span class="tag" style="background:#1f6feb22;color:#79c0ff;border:1px solid #1f6feb">'
        f'{s}: {n}</span>'
        for s, n in sub_data.get("sources", {}).items()
    )

    cors_html  = (f"<p>{_badge(vuln['cors']['severity'])} {vuln['cors']['title']}</p>"
                  if vuln.get("cors") else "")
    click_html = (f"<p>{_badge(vuln['clickjacking']['severity'])} {vuln['clickjacking']['title']}</p>"
                  if vuln.get("clickjacking") else "")

    # P7: WAF evidence section
    waf_findings = (results.get("tech_detect") or {}).get("waf_findings", [])
    waf_debug    = (results.get("tech_detect") or {}).get("waf_debug", {})
    if waf_findings:
        waf_section = "".join(
            f'<div class="remed-card"><div class="remed-header">'
            f'<span class="badge" style="background:#388bfd">WAF</span> '
            f'<strong>{w["name"]}</strong>'
            f'<span style="margin-left:auto">'
            f'<span class="badge" style="background:{"#44cc44" if w["confidence"]>=85 else "#ff8800"}">'
            f'{w["confidence"]}%</span> '
            f'<span style="color:#8b949e;font-size:.75em">{w.get("validation_status","")}</span>'
            f'</span></div>'
            f'<div class="remed-body">Methods: {", ".join(w.get("detection_methods",[]))}<br>'
            f'{"<br>".join(f"<code style=color:#79c0ff>{e}</code>" for e in w.get("evidence",[])[:5])}'
            f'</div></div>'
            for w in waf_findings
        )
    else:
        sigs = waf_debug.get("signatures_checked", "?")
        waf_section = (
            f'<div style="background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px">'
            f'<span style="color:#ff8800">⚠ No WAF detected</span>'
            f'<span style="color:#8b949e;font-size:.8em;margin-left:12px">'
            f'Signatures checked: {sigs} &nbsp;|&nbsp; Matches: 0</span></div>'
        )

    # P7: SSL certificate section
    ssl_days_str = f"{ssl_days} days" if isinstance(ssl_days, int) else "unknown"
    ssl_status_icon = "✅" if ssl.get("chain_valid") else "❌"
    ssl_cert_section = f"""
<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;margin-bottom:12px">
  <div class="card">
    <div class="num" style="font-size:1em;color:#79c0ff">{ssl.get('subject_cn','N/A')}</div>
    <div class="lbl">Subject CN</div>
  </div>
  <div class="card">
    <div class="num" style="font-size:1em;color:#8b949e">{ssl.get('issuer_cn','N/A')}</div>
    <div class="lbl">Issuer</div>
  </div>
  <div class="card">
    <div class="num" style="color:{ssl_color}">{ssl_days_str}</div>
    <div class="lbl">Expires {ssl.get('not_after','')}</div>
  </div>
  <div class="card">
    <div class="num">{ssl_status_icon} {ssl.get('cert_type','unknown')}</div>
    <div class="lbl">Chain / Cert Type</div>
  </div>
  <div class="card">
    <div class="num" style="color:{'#44cc44' if ssl.get('hsts') else '#ff4444'}">
      {'✅ ' + str(ssl.get('hsts_max_age','')) + 's' if ssl.get('hsts') else '❌ Missing'}
    </div>
    <div class="lbl">HSTS</div>
  </div>
  <div class="card">
    <div class="num" style="font-size:.9em">{ssl.get('protocol','?')} / {ssl.get('cipher_bits','?')}b</div>
    <div class="lbl">Protocol / Key Size</div>
  </div>
</div>
{"".join(f'<p style="color:#ff8800;font-size:.82em">⚠ {f["issue"]} — {f.get("evidence","")[:80]}</p>' for f in ssl.get("findings",[]))}
"""

    # P7: Port service cards
    port_cards = "".join(
        f'<div class="card" style="text-align:left;padding:10px">'
        f'<div style="font-size:1.1em;font-weight:bold;color:{"#ff4444" if p["port"] in (6379,27017,9200,2375,2376) else "#58a6ff"}">'
        f'{p["port"]}<span style="color:#8b949e;font-size:.7em">/{p.get("protocol","tcp")}</span></div>'
        f'<div style="color:#79c0ff;font-size:.8em">{p["service"]}</div>'
        f'<div style="color:#8b949e;font-size:.72em;margin-top:2px">{p.get("fingerprint","") or p.get("title","") or "—"}</div>'
        f'<div style="margin-top:4px">'
        f'<span class="badge" style="background:{"#44cc44" if p.get("confidence",0)>=90 else "#ff8800"};font-size:.65em">'
        f'{p.get("confidence","?")}%</span> '
        f'<span style="color:#8b949e;font-size:.65em">{p.get("detection_method","")}</span>'
        f'</div></div>'
        for p in ports
    ) or "<p style='color:#8b949e'>No open ports found.</p>"

    # P7: Confidence badges for executive summary
    vstats = ai.get("validation_stats", {})
    scan_conf = vstats.get("scan_confidence", 85)
    ev_cov    = vstats.get("evidence_coverage", 0)
    val_cov   = vstats.get("validation_coverage", 0)
    conf_color = "#44cc44" if scan_conf >= 90 else "#ff8800" if scan_conf >= 70 else "#ff4444"
    exec_stats_html = f"""
<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-top:10px">
  <div class="card">
    <div class="num" style="color:{conf_color}">{scan_conf}%</div>
    <div class="lbl">Scan Confidence</div>{_score_bar(scan_conf, conf_color)}
  </div>
  <div class="card">
    <div class="num" style="color:#44cc44">{vstats.get('modules_succeeded',0)}</div>
    <div class="lbl">Modules OK</div>
  </div>
  <div class="card">
    <div class="num" style="color:{'#ff4444' if vstats.get('modules_failed',0) else '#44cc44'}">{vstats.get('modules_failed',0)}</div>
    <div class="lbl">Modules Failed</div>
  </div>
  <div class="card">
    <div class="num" style="color:#ff8800">{vstats.get('fallbacks_used',0)}</div>
    <div class="lbl">Fallbacks Used</div>
  </div>
  <div class="card">
    <div class="num">{ev_cov}%</div>
    <div class="lbl">Evidence Coverage</div>{_score_bar(ev_cov)}
  </div>
  <div class="card">
    <div class="num">{val_cov}%</div>
    <div class="lbl">Validation Coverage</div>{_score_bar(val_cov)}
  </div>
</div>
"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Recon v10.0 — {target}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<style>{HTML_CSS}
.risk-score{{font-size:2.6em;font-weight:bold;color:{rc}}}
.ssl-days{{font-size:1.4em;font-weight:bold;color:{ssl_color}}}
@media(max-width:600px){{.grid{{grid-template-columns:repeat(2,1fr)}}.charts-row{{grid-template-columns:1fr}}}}
</style>
</head>
<body>
<h1>🔍 Recon Framework v10.0</h1>
<div class="meta">Target: <strong>{target}</strong> &nbsp;|&nbsp;
Profile: <strong>{results.get('profile','balanced')}</strong> &nbsp;|&nbsp;
{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>

<div class="grid">
  <div class="card"><div class="risk-score">{risk}</div><div class="lbl">Risk Score /100<br><strong style="color:{rc}">{rlevel}</strong></div></div>
  <div class="card"><div class="num">{sub_data.get('total_validated',len(subs))}</div><div class="lbl">Subdomains<br><span style="color:#8b949e;font-size:.85em">{sub_data.get('wildcard_filtered_count',0)} filtered</span></div></div>
  <div class="card"><div class="num">{len(ports)}</div><div class="lbl">Open Ports</div></div>
  <div class="card"><div class="num">{len(panels)}</div><div class="lbl">Login Panels</div></div>
  <div class="card"><div class="num">{len(js_finds)}</div><div class="lbl">JS Secrets</div></div>
  <div class="card"><div class="num">{emails.get('total',0)}</div><div class="lbl">Emails</div></div>
  <div class="card"><div class="num">{params.get('total_params',0)}</div><div class="lbl">Parameters</div></div>
  <div class="card"><div class="num">{cloud.get('total',0)}</div><div class="lbl">Cloud Assets</div></div>
  <div class="card"><div class="num">{confirmed_cves}</div><div class="lbl">CVEs Confirmed</div></div>
  <div class="card"><div class="num">{len(misconf)}</div><div class="lbl">Misconfigs</div></div>
  <div class="card"><div class="ssl-days">{ssl_days if isinstance(ssl_days,int) else '?'}d</div><div class="lbl">SSL Expiry</div></div>
  <div class="card"><div class="num" style="color:{'#44cc44' if posture>=70 else '#ff8800' if posture>=40 else '#ff4444'}">{posture}</div><div class="lbl">Header Posture</div></div>
</div>

<h2>📋 Executive Summary</h2>
<div class="exec-box">
  <h3>🎯 Risk Assessment — {rlevel}</h3>
  <p>{ai.get('summary','N/A')}</p>
</div>
{exec_stats_html}

<h2>🎯 Top Attack Paths</h2>
{paths_html}

<h2>🏆 Critical Assets</h2>
{assets_html}

<h2>📊 Risk Breakdown</h2>
<table><tr><th>Severity</th><th>Issues</th></tr>{breakdown_html}</table>

<h2>📈 Visualizations</h2>
<div class="charts-row">
  <div class="chart-box"><h3>🗺 Attack Surface Radar</h3>{_radar_js(atk)}</div>
  <div class="chart-box"><h3>🛠 Issues by Category</h3>{_bar_js(by_cat)}</div>
  <div class="chart-box"><h3>🔧 Technology Distribution</h3>{_tech_donut_js(techs)}</div>
  <div class="chart-box"><h3>⚠️ Risk Gauge</h3>{_gauge_svg(risk)}</div>
</div>

<h2>🕸 Interactive Attack Surface Graph</h2>
{graph_html}

<h2>🛠 Remediation Plan</h2>
{remed_html}

<h2>🔒 Security Header Scorecard</h2>
<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:12px">
  <div class="card"><div class="num" style="color:{'#44cc44' if posture>=70 else '#ff8800' if posture>=40 else '#ff4444'}">{posture}</div><div class="lbl">Overall Posture</div>{_score_bar(posture)}</div>
  <div class="card"><div class="num" style="color:{'#44cc44' if csp_score>=70 else '#ff8800' if csp_score>=40 else '#ff4444'}">{csp_score}</div><div class="lbl">CSP Score</div>{_score_bar(csp_score)}</div>
  <div class="card"><div class="num" style="color:{'#44cc44' if hsts_score>=70 else '#ff8800' if hsts_score>=40 else '#ff4444'}">{hsts_score}</div><div class="lbl">HSTS Score</div>{_score_bar(hsts_score)}</div>
</div>
{"".join(f'<p style="color:#ff8800;font-size:.82em">⚠ {i}</p>' for i in vuln.get('csp_issues',[]) + vuln.get('hsts_issues',[]) + vuln.get('referrer_policy_issues',[]) + vuln.get('permissions_policy_issues',[]))}
<table><tr><th>Sev</th><th>Missing Header</th><th>Explanation</th><th>Remediation</th><th>Evidence</th><th>Conf</th><th>Status</th></tr>{missing_hdrs}</table>

<h2>🛡 WAF Detection</h2>
{waf_section}

<h2>🔒 SSL/TLS Certificate</h2>
{ssl_cert_section}

<h2>🔍 Vulnerability Scan</h2>
{cors_html}{click_html}
<table><tr><th>Sev</th><th>✓</th><th>URL</th><th>Title</th><th>CVE</th><th>Status</th><th>Evidence</th></tr>{cve_html}</table>

<h2>🔧 Technology Fingerprinting</h2>
<table><tr><th>Technology</th><th>Version</th><th>Confidence</th><th>Method</th><th>Status</th><th>CVEs</th></tr>
{tech_table}</table>

<h2>🔗 Intelligence Correlation (Tech → Vulns)</h2>
<table><tr><th>Technology</th><th>Related Vulnerabilities</th></tr>{corr_html}</table>

<h2>🔌 Open Port Service Cards ({len(ports)} / {port_scanned} scanned)</h2>
<div class="grid" style="grid-template-columns:repeat(auto-fill,minmax(150px,1fr))">
{port_cards}
</div>

<h2>🔎 Parameter Analysis ({params.get('total_params',0)} params)</h2>
{_param_heatmap(params_by_risk)}

<h2>🔗 Endpoint Heatmap</h2>
{_endpoint_heatmap(ep_grps)}

<h2>🌐 Subdomain Tree ({sub_data.get('total_validated',len(subs))}) &nbsp; {src_tags}</h2>
{wildcard_notice}
{_subdomain_tree(sub_ent, domain)}

<h2>☁️ Cloud Asset Summary ({cloud.get('total',0)})</h2>
<table><tr><th>Risk</th><th>Provider</th><th>URL</th><th>Listable</th><th>Status</th></tr>{cloud_html}</table>

<h2>📸 Screenshot Gallery</h2>
{_screenshot_gallery(shots)}

<h2>📧 Emails ({emails.get('total',0)})</h2>
<pre>{chr(10).join(emails.get('on_domain',[]) + emails.get('off_domain',[])) or 'None found'}</pre>

<h2>🔑 Login Panels</h2>
<table><tr><th>URL</th><th>Status</th><th>Technology</th><th>Login Form</th><th>Verified</th></tr>
{"".join(f'<tr><td>{p["url"]}</td><td>{p["status"]}</td><td>{p.get("technology","")}</td><td>{"✅" if p.get("has_login_form") else "—"}</td><td>{"✅" if p.get("verified") else "—"}</td></tr>' for p in panels) or '<tr><td colspan=5>None</td></tr>'}
</table>

<h2>🔐 JS Secrets</h2>
{"".join(f'<details><summary>{f["file"]}</summary><pre>{json.dumps(f["findings"],indent=2)}</pre></details>' for f in js_finds) or '<p style="color:#8b949e">None found</p>'}

<h2>📁 Directory Discovery ({len(dirs)})</h2>
<table><tr><th>URL</th><th>Status</th><th>Severity</th></tr>
{"".join(f'<tr><td>{d["url"]}</td><td>{d["status"]}</td><td>{_badge(d.get("severity","info"))}</td></tr>' for d in dirs) or '<tr><td colspan=3>None</td></tr>'}
</table>

<h2>⏱ Module Execution Times</h2>
{_module_times_html(results.get("_diagnostics") or {})}
</body></html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    log.info(f"[reporter] HTML: {path}")
    return path


# ── Module execution times ────────────────────────────────────────────────────

def _module_times_html(diag: dict) -> str:
    modules = diag.get("modules", {})
    if not modules:
        return "<p style='color:#8b949e'>No diagnostics available.</p>"
    rows = []
    for name, m in sorted(modules.items(), key=lambda x: -x[1].get("runtime_s", 0)):
        status = m.get("status", "?")
        color = {"success": "#44cc44", "error": "#ff4444", "warning": "#ff8800",
                 "skipped": "#8b949e"}.get(status, "#c9d1d9")
        rt = m.get("runtime_s", 0)
        bar_w = min(int(rt / max(m.get("runtime_s", 1) for m in modules.values()) * 200), 200) if rt else 0
        rows.append(
            f"<tr><td style='color:#79c0ff'>{name}</td>"
            f"<td><span style='color:{color}'>{status}</span></td>"
            f"<td>{rt:.2f}s "
            f"<div style='display:inline-block;width:{bar_w}px;height:6px;"
            f"background:{color};border-radius:3px;vertical-align:middle'></div></td>"
            f"<td style='color:#8b949e'>{m.get('findings_count',0)}</td>"
            f"<td style='color:#ff8800'>{m.get('retries',0)}</td>"
            f"<td style='color:#ff4444'>{m.get('timeout_count',0)}</td>"
            f"<td style='color:#8b949e;font-size:.75em'>{m.get('failure_reason','')[:60]}</td></tr>"
        )
    total = diag.get("total_runtime_s", 0)
    return (
        f"<table><tr><th>Module</th><th>Status</th><th>Runtime</th>"
        f"<th>Findings</th><th>Retries</th><th>Timeouts</th><th>Error</th></tr>"
        f"{''.join(rows)}</table>"
        f"<p style='color:#8b949e;font-size:.8em'>Total scan time: {total:.2f}s</p>"
    )


# ── CSV export ────────────────────────────────────────────────────────────────

def save_csv(results: dict, out_dir: str, target: str) -> str:
    import csv
    os.makedirs(out_dir, exist_ok=True)
    slug = target.replace("https://", "").replace("http://", "").replace("/", "_")
    path = os.path.join(out_dir, f"{slug}_findings.csv")

    ai   = results.get("ai_analysis") or {}
    vuln = results.get("vuln_scan") or {}
    rows: list[dict] = []

    # Misconfigurations
    for m in ai.get("misconfigurations", []):
        rows.append({"type": "misconfiguration", "severity": m["severity"],
                     "title": m["issue"], "confidence": m.get("confidence", ""),
                     "evidence": "", "url": target,
                     "remediation": m.get("remediation", ""),
                     "validation_status": m.get("validation_status", "")})

    # CVE paths
    for c in vuln.get("cve_paths", []):
        rows.append({"type": "cve_path", "severity": c["severity"],
                     "title": c.get("title", c.get("description", "")),
                     "confidence": "confirmed" if c.get("confirmed") else "suspected",
                     "evidence": c.get("evidence", "")[:200], "url": c.get("url", ""),
                     "remediation": f"Restrict access to {c['url']}",
                     "validation_status": c.get("verification_status", "")})

    # Missing headers
    for h in vuln.get("missing_headers", []):
        rows.append({"type": "missing_header", "severity": h["severity"],
                     "title": f"Missing {h['header']}", "confidence": h.get("confidence", 99),
                     "evidence": h.get("evidence", ""), "url": target,
                     "remediation": h.get("remediation", ""),
                     "validation_status": h.get("validation_status", "confirmed")})

    if not rows:
        rows.append({"type": "", "severity": "", "title": "No findings", "confidence": "",
                     "evidence": "", "url": target, "remediation": "", "validation_status": ""})

    fieldnames = ["type", "severity", "title", "confidence", "evidence",
                  "url", "remediation", "validation_status"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    log.info(f"[reporter] CSV: {path} ({len(rows)} rows)")
    return path


# ── Entry point ───────────────────────────────────────────────────────────────

def generate_all(results: dict, out_dir: str, target: str) -> dict:
    return {
        "json": save_json(results, out_dir, target),
        "txt":  save_txt(results, out_dir, target),
        "html": save_html(results, out_dir, target),
        "csv":  save_csv(results, out_dir, target),
    }
