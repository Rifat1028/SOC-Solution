# file: custom_report.py
"""Reports scoped to one or more incidents, or to any time range."""
import html
import statistics
from collections import Counter
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from db import get_db

UTC = timezone.utc
SAMPLE_SECONDS = 30      # node_metrics are sampled every 30 s


def _ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _parse(v: str) -> datetime:
    v = (v or "").strip().replace("T", " ").replace("Z", "")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(v, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    raise ValueError(f"Invalid date: {v!r}")


def custom_report(tenant_id: str, incident_ids: Optional[List[str]] = None, start: Optional[str] = None,
                  end: Optional[str] = None, include_steps: bool = False, domain: Optional[str] = None) -> dict:
    now = datetime.now(UTC)
    ids = [i for i in (incident_ids or []) if i]
    with closing(get_db()) as conn:
        tenant = conn.execute("SELECT name FROM tenants WHERE id=?", (tenant_id,)).fetchone()
        if ids:
            q = ",".join("?" * len(ids))
            incs = [dict(r) for r in conn.execute(f"SELECT * FROM incidents WHERE tenant_id=? AND id IN ({q})" + (" AND COALESCE(domain,'cyber')=?" if domain else ""), [tenant_id, *ids] + ([domain] if domain else [])).fetchall()]
            if not incs:
                return {}
            t0 = min(_parse(i["created_at"]) for i in incs)
            t1 = max(_parse(i["updated_at"]) for i in incs)
            scope = f"{len(incs)} selected incident(s)"
        else:
            t1 = _parse(end) if end else now
            t0 = _parse(start) if start else t1 - timedelta(days=7)
            if t0 > t1:
                raise ValueError("Start must be before end")
            if (t1 - t0).days > 366:
                raise ValueError("Range is limited to 366 days")
            incs = [dict(r) for r in conn.execute("SELECT * FROM incidents WHERE tenant_id=? AND created_at<=? AND updated_at>=?" + (" AND COALESCE(domain,'cyber')=?" if domain else "") + " ORDER BY risk_score DESC",
                                                  (tenant_id, _ts(t1), _ts(t0)) + ((domain,) if domain else ())).fetchall()]
            scope = "Time range"
        s0, s1 = _ts(t0), _ts(t1)
        inc_ids = [i["id"] for i in incs]
        if domain in ("it", "ai"):
            alerts = []
        elif ids:
            q = ",".join("?" * len(inc_ids))
            alerts = [dict(r) for r in conn.execute(f"SELECT * FROM alert_records WHERE tenant_id=? AND incident IN ({q})", [tenant_id, *inc_ids]).fetchall()]
        else:
            alerts = [dict(r) for r in conn.execute("SELECT * FROM alert_records WHERE tenant_id=? AND created_at>=? AND created_at<=?", (tenant_id, s0, s1)).fetchall()]
        steps: List[dict] = []
        if inc_ids:
            q = ",".join("?" * len(inc_ids))
            steps = [dict(r) for r in conn.execute(f"SELECT * FROM incident_steps WHERE tenant_id=? AND incident_id IN ({q}) ORDER BY stage_order", [tenant_id, *inc_ids]).fetchall()]
        samples = 0 if domain in ("it", "ai") else conn.execute("SELECT COALESCE(SUM(eps),0) s FROM node_metrics WHERE tenant_id=? AND ts>=? AND ts<=?", (tenant_id, s0, s1)).fetchone()["s"]
        ai_n = conn.execute("SELECT COUNT(*) n, COALESCE(SUM(CASE WHEN verdict='block' THEN 1 ELSE 0 END),0) b, COALESCE(SUM(CASE WHEN verdict='flag' THEN 1 ELSE 0 END),0) f "
                            "FROM ai_events WHERE tenant_id=? AND created_at>=? AND created_at<=?", (tenant_id, s0, s1)).fetchone() if domain in (None, "ai") else None
        audit_n = conn.execute("SELECT COUNT(*) c FROM audit_logs WHERE tenant_id=? AND created_at>=? AND created_at<=?", (tenant_id, s0, s1)).fetchone()["c"]

    contained = [i for i in incs if i["status"] in ("contained", "closed")]
    mttr = round(statistics.mean((_parse(i["updated_at"]) - _parse(i["created_at"])).total_seconds() / 60 for i in contained), 1) if contained else None
    disp = Counter(a["disposition"] for a in alerts)
    judged = disp.get("false_positive", 0) + disp.get("true_positive", 0)
    by_inc = Counter(s["incident_id"] for s in steps)
    out_inc = []
    for i in incs:
        mine = [s for s in steps if s["incident_id"] == i["id"]]
        row = {"id": i["id"], "title": i["title"], "severity": i["severity"], "status": i["status"], "risk": i["risk_score"],
               "assigned_to": i.get("assigned_to") or "Unassigned", "created_at": i["created_at"], "updated_at": i["updated_at"],
               "entity": i["primary_entity"], "steps": by_inc.get(i["id"], 0), "story": i["ai_story"], "action": i["recommended_action"],
               "tactics": sorted({s["tactic"] for s in mine})}
        if include_steps:
            row["timeline"] = [{k: s[k] for k in ("event_time", "tactic", "technique_id", "title", "source", "entity", "severity", "raw_log")} for s in mine]
        out_inc.append(row)
    return {
        "tenant": tenant["name"] if tenant else tenant_id, "scope": scope + (f" ({domain} pillar)" if domain else ""), "start": s0, "end": s1, "generated_at": _ts(now) + " UTC",
        "totals": {
            "logs_estimated": int(samples * SAMPLE_SECONDS),
            "alerts": len(alerts), "alerts_by_severity": dict(Counter((a["severity"] or "unknown") for a in alerts)),
            "true_positive": disp.get("true_positive", 0), "false_positive": disp.get("false_positive", 0),
            "fp_rate": round(100 * disp.get("false_positive", 0) / judged) if judged else None,
            "incidents": len(incs), "open": sum(1 for i in incs if i["status"] not in ("contained", "closed")), "contained": len(contained),
            "by_severity": dict(Counter(i["severity"] for i in incs)), "by_verdict": dict(Counter(i["verdict"] for i in incs if i.get("verdict"))), "mttr_minutes": mttr,
            "ai_events": ai_n["n"] if ai_n else None, "ai_blocked": ai_n["b"] if ai_n else None, "ai_flagged": ai_n["f"] if ai_n else None,
            "signals": len(steps), "tactics": dict(Counter(s["tactic"] for s in steps)), "audit_events": audit_n,
        },
        "top_entities": [{"entity": e, "count": c} for e, c in Counter(a["entity"] for a in alerts if a["entity"]).most_common(5)],
        "top_rules": [{"rule": r, "count": c} for r, c in Counter(a["rule"] for a in alerts if a["rule"]).most_common(5)],
        "incidents": out_inc,
    }


def render_custom_html(r: dict) -> str:
    e = lambda v: html.escape(str(v if v is not None else "n/a"))
    t = r["totals"]
    card = lambda n, l: f'<div class="card"><b>{e(n)}</b><span>{e(l)}</span></div>'
    cards = "".join([card(f"{t['logs_estimated']:,}", "Log events (est.)"), card(t["alerts"], "Alerts"), card(t["incidents"], "Incidents"),
                     card(t["signals"], "Attack-chain signals"), card(t["open"], "Open"), card(t["contained"], "Contained"),
                     card(f"{t['mttr_minutes']} min" if t["mttr_minutes"] is not None else "n/a", "Mean time to resolve"),
                     card(f"{t['fp_rate']}%" if t["fp_rate"] is not None else "n/a", "False-positive rate")]
                    + ([card(t["ai_events"], "AI events inspected"), card(t["ai_blocked"], "AI events blocked"), card(t["ai_flagged"], "AI events flagged")] if t.get("ai_events") is not None else []))
    kv = lambda d: "".join(f"<tr><td>{e(k)}</td><td>{e(v)}</td></tr>" for k, v in sorted(d.items(), key=lambda x: -x[1])) or "<tr><td colspan=2>None</td></tr>"
    inc_rows = "".join(f"<tr><td>{e(i['id'])}</td><td>{e(i['title'])}</td><td>{e(i['severity'])}</td><td>{e(i['status'])}</td><td>{e(i['risk'])}</td>"
                       f"<td>{e(i['assigned_to'])}</td><td>{e(i['steps'])}</td><td>{e(', '.join(i['tactics']))}</td></tr>" for i in r["incidents"]) or "<tr><td colspan=8>No incidents in scope</td></tr>"
    detail = ""
    for i in r["incidents"]:
        tl = "".join(f"<tr><td>{e(s['event_time'])}</td><td>{e(s['tactic'])} ({e(s['technique_id'])})</td><td>{e(s['title'])}</td><td>{e(s['source'])}</td><td>{e(s['entity'])}</td><td>{e(s['severity'])}</td></tr>"
                     for s in i.get("timeline", []))
        detail += (f"<h2>{e(i['id'])}: {e(i['title'])}</h2><p>{e(i['story'])}</p><p><b>Response:</b> {e(i['action'])}</p>"
                   + (f"<table><tr><th>Time</th><th>Tactic</th><th>Step</th><th>Source</th><th>Entity</th><th>Severity</th></tr>{tl}</table>" if tl else ""))
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Security Report - {e(r['tenant'])}</title>
<style>
body{{font-family:Calibri,Segoe UI,Arial,sans-serif;color:#2b2b2e;margin:0;background:#fff}}.page{{max-width:900px;margin:0 auto;padding:36px 40px}}
h1{{font-size:28px;margin:0 0 4px}}h2{{font-size:18px;border-bottom:2px solid #d31c5b;padding-bottom:4px;margin-top:26px}}.sub{{color:#777;margin-bottom:18px}}
.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}}.card{{background:#f7f5f6;border-radius:10px;padding:12px 14px}}.card b{{display:block;font-size:22px;color:#d31c5b}}.card span{{font-size:12px;color:#666}}
table{{width:100%;border-collapse:collapse;font-size:13px;margin-top:8px}}th,td{{text-align:left;padding:6px 8px;border-bottom:1px solid #eee}}th{{color:#d31c5b;font-size:12px}}.two{{display:grid;grid-template-columns:1fr 1fr;gap:20px}}
.foot{{margin-top:30px;color:#888;font-size:11.5px}}@media print{{.page{{padding:0}}.noprint{{display:none}}}}
</style></head><body><div class="page"><div class="noprint" style="text-align:right"><button onclick="window.print()">Print / Save as PDF</button></div>
<h1>Security Operations Report</h1><div class="sub">{e(r['tenant'])} &middot; {e(r['scope'])} &middot; {e(r['start'])} to {e(r['end'])} UTC &middot; generated {e(r['generated_at'])}</div>
<div class="grid">{cards}</div>
<div class="two"><div><h2>Alerts by severity</h2><table>{kv(t['alerts_by_severity'])}</table></div><div><h2>Incidents by severity</h2><table>{kv(t['by_severity'])}</table></div></div>
<div class="two"><div><h2>Top alerting entities</h2><table>{''.join(f"<tr><td>{e(x['entity'])}</td><td>{e(x['count'])}</td></tr>" for x in r['top_entities']) or '<tr><td>None</td></tr>'}</table></div>
<div><h2>Top rules</h2><table>{''.join(f"<tr><td>{e(x['rule'])}</td><td>{e(x['count'])}</td></tr>" for x in r['top_rules']) or '<tr><td>None</td></tr>'}</table></div></div>
<h2>MITRE tactics observed</h2><table>{kv(t['tactics'])}</table>
<h2>Incidents</h2><table><tr><th>ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Risk</th><th>Assigned</th><th>Signals</th><th>Tactics</th></tr>{inc_rows}</table>
{detail}<div class="foot">Log events are estimated from node throughput samples over the period. {e(t['audit_events'])} audited platform actions occurred in the same window.</div>
</div></body></html>"""
