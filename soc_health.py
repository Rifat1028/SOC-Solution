# file: soc_health.py
"""SOC health & quality features. Depends only on db.get_db (and httpx for the optional feed refresh).

  1. Silent log sources / blind spots     -> node_health()
  2. Rule health + expiring suppressions  -> rule_health(), suppression_health()
  4. Vulnerability prioritization         -> vuln_priorities(), refresh_vuln_intel()
  6. Incident quality                     -> similar_incidents(), checklist_for(), draft_summary()
  7. Executive reporting                  -> weekly_report(), render_report_html()
 10. Evidence export (Ed25519-signed zip) -> build_evidence_zip(), verify_evidence_zip()
"""
import asyncio
import hashlib
import hmac
import html
import io
import json
import math
import random
import re
import statistics
import uuid
import zipfile
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from db import MASTER_KEY, get_db

DEMO_TENANT = "tenant-trustaira"
SUPPRESSION_DAYS = 90
EXPIRING_SOON_DAYS = 14
SAMPLE_EVERY_SEC = 30
_outage_until: Dict[str, datetime] = {}      # demo-only: node_id -> end of simulated outage


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ts(dt: Optional[datetime] = None) -> str:
    return (dt or _now()).strftime("%Y-%m-%d %H:%M:%S")


def _parse(ts: str) -> datetime:
    return datetime.strptime(ts[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)


# =====================================================================
# SCHEMA + DEMO SEED
# =====================================================================
DDL = """
CREATE TABLE IF NOT EXISTS node_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, node_id TEXT NOT NULL, ts TEXT NOT NULL, eps REAL NOT NULL);
CREATE INDEX IF NOT EXISTS idx_node_metrics ON node_metrics(node_id, ts);
CREATE TABLE IF NOT EXISTS alert_records (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, created_at TEXT NOT NULL, rule TEXT NOT NULL, segment TEXT,
    severity TEXT, entity TEXT, source TEXT, incident TEXT DEFAULT 'Standalone',
    disposition TEXT DEFAULT 'open', simulated INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS idx_alert_records ON alert_records(tenant_id, rule, created_at);
CREATE TABLE IF NOT EXISTS vuln_intel (
    cve TEXT PRIMARY KEY, kev INTEGER DEFAULT 0, kev_added TEXT, ransomware INTEGER DEFAULT 0,
    epss REAL, percentile REAL, updated_at TEXT);
CREATE TABLE IF NOT EXISTS intel_meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS checklist_state (
    incident_id TEXT NOT NULL, tenant_id TEXT NOT NULL, item_key TEXT NOT NULL, done INTEGER DEFAULT 0,
    by_user TEXT, at TEXT, PRIMARY KEY (incident_id, tenant_id, item_key));
"""

# (id, segment, rule, source, entity, severity, incident, ai_suggested_fp)  - copied from the dashboard's demo alerts
DEMO_ALERTS = (
(
"ALT-901",
"System",
"Volume Shadow Copy Deletion (vssadmin.exe)",
"Wazuh EDR",
"SRV-DC-01",
"critical",
"INC-2043",
False
),
(
"ALT-902",
"System",
"Mass File Modification (.lockbit extension)",
"Elastic SIEM",
"SRV-FILE-01",
"critical",
"INC-2043",
False
),
(
"ALT-905",
"System",
"Systemd Service Binary Modified in /usr/local/bin",
"Elastic Agent",
"LNX-PROD-DB01",
"medium",
"Standalone",
True
),
(
"ALT-906",
"System",
"High CPU & Disk Read Burst via tar/gzip",
"Wazuh Host",
"SRV-BACKUP-01",
"low",
"Standalone",
True
),
(
"ALT-801",
"Network",
"2.3 GB Outbound Data Spike to Rare External IP",
"Perimeter Firewall",
"SRV-FILE-02 → 185.220.101.42",
"high",
"INC-2041",
False
),
(
"ALT-802",
"Network",
"Lateral SMB Enumeration Spike (Port 445 to 6 Hosts)",
"Perimeter Firewall",
"192.168.1.52 (SRV-FILE-02)",
"medium",
"INC-2041",
False
),
(
"ALT-804",
"Network",
"Internal Port Sweep Across VLAN 20",
"Perimeter Firewall",
"192.168.1.200 (Qualys-Scanner)",
"medium",
"Standalone",
True
),
(
"ALT-701",
"Endpoint / XDR",
"Office Macro Spawned Hidden Encoded PowerShell",
"Trend Vision One",
"WS-RAHMAN-01 (a.rahman)",
"high",
"INC-2041",
False
),
(
"ALT-702",
"Endpoint / XDR",
"LSASS Process Memory Dump via rundll32.exe",
"Trend Vision One",
"WS-RAHMAN-01 (a.rahman)",
"high",
"INC-2041",
False
),
(
"ALT-703",
"Endpoint / XDR",
"Unsigned DLL Loaded from Chrome Updater Temp Path",
"Trend Vision One",
"WS-HR-02",
"low",
"Standalone",
True
),
(
"ALT-601",
"Identity & AD",
"14 Failed NTLM Logins Followed by Success (Brute Force)",
"AD via Wazuh",
"a.rahman",
"medium",
"INC-2041",
False
),
(
"ALT-602",
"Identity & AD",
"UEBA: First-Time RDP Session to File Server",
"Wazuh UEBA",
"a.rahman → SRV-FILE-02",
"high",
"INC-2041",
False
),
(
"ALT-603",
"Identity & AD",
"PAM Vault Privileged Checkout Outside Shift Window",
"Trustaira PAM",
"svc-sql-backup",
"medium",
"Standalone",
True
),
(
"ALT-501",
"Email Gateway",
"Spoofed Payroll Attachment (Salary_Q3.xlsm) SPF Fail",
"Email Gateway",
"a.rahman@client.com",
"medium",
"INC-2041",
False
),
(
"ALT-401",
"Cloud & Threat Intel",
"AWS AssumeRole API Call from Tor Exit Node (Moldova)",
"AWS CloudTrail",
"dev-pipeline-role",
"high",
"INC-2042",
False
),
(
"ALT-402",
"Cloud & Threat Intel",
"Unauthorized Launch of 45 GPU EC2 Instances (eu-west-3)",
"AWS GuardDuty",
"eu-west-3",
"high",
"INC-2042",
False
),
(
"ALT-403",
"Cloud & Threat Intel",
"Outbound Connection to Known C2 Exfiltration Node",
"Shodan / OTX / VT",
"185.220.101.42",
"high",
"INC-2041",
False
)
)


def init_health_db() -> None:
    with closing(get_db()) as conn:
        conn.executescript(DDL)
        for sql in ("ALTER TABLE fp_rules ADD COLUMN expires_at TEXT",
                    "ALTER TABLE fp_rules ADD COLUMN last_reviewed TEXT",
                    "ALTER TABLE fp_rules ADD COLUMN reviewed_by TEXT"):
            try:
                conn.execute(sql)
            except Exception:
                pass
        conn.execute(f"UPDATE fp_rules SET expires_at = datetime(created_at, '+{SUPPRESSION_DAYS} days') WHERE expires_at IS NULL")
        if conn.execute("SELECT COUNT(*) c FROM alert_records WHERE tenant_id=?", (DEMO_TENANT,)).fetchone()["c"] == 0:
            _seed_alerts(conn)
        if conn.execute("SELECT COUNT(*) c FROM node_metrics WHERE tenant_id=?", (DEMO_TENANT,)).fetchone()["c"] == 0:
            _seed_metrics(conn)
        conn.commit()


def _seed_alerts(conn) -> None:
    """Demo history so the rule-health page has something real-shaped to analyse. Flagged simulated=1."""
    rnd = random.Random(42)
    now = _now()
    for (aid, seg, rule, src, ent, sev, inc, ai_fp) in DEMO_ALERTS:
        conn.execute("INSERT OR IGNORE INTO alert_records (id, tenant_id, created_at, rule, segment, severity, entity, source, incident, disposition, simulated) "
                     "VALUES (?,?,?,?,?,?,?,?,?,?,1)",
                     (aid, DEMO_TENANT, _ts(now - timedelta(hours=rnd.randint(1, 20))), rule, seg, sev, ent, src, inc,
                      "true_positive" if inc.startswith("INC-") else "open"))
        # history of the same rule on the same entity over ~5 weeks
        if ai_fp:
            n, fp_share = rnd.randint(8, 16), 0.93
        elif inc.startswith("INC-"):
            n, fp_share = rnd.randint(0, 2), 0.1
        else:
            n, fp_share = rnd.randint(2, 6), 0.45
        for i in range(n):
            when = now - timedelta(days=rnd.randint(1, 34), hours=rnd.randint(0, 23))
            disp = "false_positive" if rnd.random() < fp_share else "true_positive"
            conn.execute("INSERT INTO alert_records (id, tenant_id, created_at, rule, segment, severity, entity, source, incident, disposition, simulated) "
                         "VALUES (?,?,?,?,?,?,?,?,?,?,1)",
                         (f"H-{uuid.uuid4().hex[:8]}", DEMO_TENANT, _ts(when), rule, seg, sev, ent, src, "Standalone", disp))
    # one rule that used to fire and went silent (dead log source or broken rule)
    conn.execute("INSERT INTO alert_records (id, tenant_id, created_at, rule, segment, severity, entity, source, incident, disposition, simulated) VALUES (?,?,?,?,?,?,?,?,?,?,1)",
                 (f"H-{uuid.uuid4().hex[:8]}", DEMO_TENANT, _ts(now - timedelta(days=44)), "AD Golden Ticket Anomaly (Kerberos TGT lifetime)",
                  "Identity & AD", "high", "SRV-DC-01", "Wazuh UEBA", "Standalone", "true_positive"))


def _seed_metrics(conn) -> None:
    rnd = random.Random(7)
    nodes = conn.execute("SELECT id, eps FROM node_status WHERE tenant_id=?", (DEMO_TENANT,)).fetchall()
    now = _now()
    for n in nodes:
        base = float(n["eps"] or 0)
        for i in range(60, 0, -1):
            conn.execute("INSERT INTO node_metrics (tenant_id, node_id, ts, eps) VALUES (?,?,?,?)",
                         (DEMO_TENANT, n["id"], _ts(now - timedelta(seconds=i * SAMPLE_EVERY_SEC)), max(0.0, base * rnd.uniform(0.92, 1.08))))


# =====================================================================
# 1. SILENT LOG SOURCES
# =====================================================================
def record_heartbeat(tenant_id: str, node_id: str, eps: float) -> None:
    with closing(get_db()) as conn:
        if not conn.execute("SELECT 1 FROM node_status WHERE id=? AND tenant_id=?", (node_id, tenant_id)).fetchone():
            raise KeyError("unknown node")
        conn.execute("INSERT INTO node_metrics (tenant_id, node_id, ts, eps) VALUES (?,?,?,?)", (tenant_id, node_id, _ts(), max(0.0, float(eps))))
        conn.execute("UPDATE node_status SET eps=?, last_seen=datetime('now') WHERE id=?", (int(eps), node_id))
        conn.execute("DELETE FROM node_metrics WHERE node_id=? AND id NOT IN (SELECT id FROM node_metrics WHERE node_id=? ORDER BY id DESC LIMIT 2000)", (node_id, node_id))
        conn.commit()


def classify_source(samples: List[tuple], now: datetime) -> dict:
    """samples: [(datetime, eps)] oldest -> newest. Pure function (unit-tested)."""
    if len(samples) < 12:
        return {"state": "learning", "message": f"Learning normal volume ({len(samples)}/12 samples)", "baseline": None, "current": None}
    ts_list = [t for t, _ in samples]
    gaps = [(b - a).total_seconds() for a, b in zip(ts_list, ts_list[1:]) if (b - a).total_seconds() > 0]
    typical_gap = statistics.median(gaps) if gaps else SAMPLE_EVERY_SEC
    age = (now - ts_list[-1]).total_seconds()
    vals = [v for _, v in samples]
    baseline = statistics.median(vals[:-3])
    current = sum(vals[-3:]) / 3
    silent_after = max(90.0, 3.5 * typical_gap)
    pct = (100 * current / baseline) if baseline > 0 else None
    base = {"baseline": round(baseline, 1), "current": round(current, 1), "pct": round(pct) if pct is not None else None,
            "age_sec": int(age)}
    if age > silent_after:
        mins = int(age // 60)
        # the last samples are stale, so do not present them as the current rate
        return {**base, "current": None, "pct": None, "last_reported": base["current"], "state": "silent",
                "message": f"No data for {mins} min (normally every {int(typical_gap)}s)" if mins else f"No data for {int(age)}s"}
    if baseline >= 5 and current <= 0.05 * baseline:
        return {**base, "state": "silent", "message": f"Still connected but sending ~0 events (normally ~{round(baseline)}/s)"}
    if baseline >= 5 and current < 0.4 * baseline:
        return {**base, "state": "degraded", "message": f"Volume dropped to {round(pct)}% of normal"}
    if baseline >= 5 and current > 3 * baseline:
        return {**base, "state": "surging", "message": f"Volume is {round(current / baseline, 1)}x normal: possible log flood or attack"}
    return {**base, "state": "healthy", "message": "Within normal range"}


def node_health(tenant_id: str) -> dict:
    now = _now()
    out = []
    with closing(get_db()) as conn:
        nodes = [dict(r) for r in conn.execute("SELECT id, node_name, node_type, ip_address, eps FROM node_status WHERE tenant_id=? ORDER BY id", (tenant_id,)).fetchall()]
        for n in nodes:
            rows = conn.execute("SELECT ts, eps FROM node_metrics WHERE node_id=? ORDER BY id DESC LIMIT 60", (n["id"],)).fetchall()
            samples = [(_parse(r["ts"]), r["eps"]) for r in reversed(rows)]
            res = classify_source(samples, now)
            res.update({"node_id": n["id"], "name": n["node_name"], "type": n["node_type"], "ip": n["ip_address"],
                        "spark": [round(v, 1) for _, v in samples[-30:]]})
            out.append(res)
    counts = {k: sum(1 for o in out if o["state"] == k) for k in ("healthy", "degraded", "silent", "surging", "learning")}
    return {"nodes": out, "summary": counts, "needs_attention": counts["degraded"] + counts["silent"] + counts["surging"]}


def simulate_outage(node_id: str, minutes: int = 3) -> None:
    _outage_until[node_id] = _now() + timedelta(minutes=max(1, min(minutes, 30)))


def _sample_tick() -> None:
    rnd = random.Random()
    now = _now()
    with closing(get_db()) as conn:
        for n in conn.execute("SELECT id, eps FROM node_status WHERE tenant_id=?", (DEMO_TENANT,)).fetchall():
            until = _outage_until.get(n["id"])
            if until and until > now:
                continue                               # a silent source sends nothing at all
            conn.execute("INSERT INTO node_metrics (tenant_id, node_id, ts, eps) VALUES (?,?,?,?)",
                         (DEMO_TENANT, n["id"], _ts(now), max(0.0, float(n["eps"] or 0) * rnd.uniform(0.92, 1.08))))
            conn.execute("DELETE FROM node_metrics WHERE node_id=? AND id NOT IN (SELECT id FROM node_metrics WHERE node_id=? ORDER BY id DESC LIMIT 2000)", (n["id"], n["id"]))
        conn.commit()


async def _sampler_loop() -> None:
    while True:
        try:
            await asyncio.to_thread(_sample_tick)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            print(f"[health-sampler] {e}")
        await asyncio.sleep(SAMPLE_EVERY_SEC)


def start_health_sampler():
    """Demo only: feeds fake EPS samples. In production, connectors call POST /health/heartbeat instead."""
    import os
    if os.getenv("SOC_DEMO_HEALTH", "1") == "0":
        return None
    return asyncio.create_task(_sampler_loop())


# =====================================================================
# 2. RULE HEALTH + SUPPRESSION EXPIRY
# =====================================================================
def mark_disposition(tenant_id: str, alert_id: str, disposition: str) -> None:
    if disposition not in ("false_positive", "true_positive", "open"):
        return
    with closing(get_db()) as conn:
        conn.execute("UPDATE alert_records SET disposition=? WHERE id=? AND tenant_id=?", (disposition, alert_id, tenant_id))
        conn.commit()


def rule_health(tenant_id: str, window_days: int = 30) -> dict:
    now = _now()
    since = _ts(now - timedelta(days=window_days))
    with closing(get_db()) as conn:
        rows = conn.execute("SELECT rule, MAX(segment) segment, MAX(created_at) last_fired, COUNT(*) total_all FROM alert_records WHERE tenant_id=? GROUP BY rule", (tenant_id,)).fetchall()
        recent = conn.execute("SELECT rule, entity, disposition FROM alert_records WHERE tenant_id=? AND created_at>=?", (tenant_id, since)).fetchall()
        simulated = conn.execute("SELECT COUNT(*) c FROM alert_records WHERE tenant_id=? AND simulated=1", (tenant_id,)).fetchone()["c"]
    by_rule: Dict[str, List[dict]] = {}
    for r in recent:
        by_rule.setdefault(r["rule"], []).append(dict(r))
    out = []
    for r in rows:
        items = by_rule.get(r["rule"], [])
        total = len(items)
        fp = sum(1 for i in items if i["disposition"] == "false_positive")
        tp = sum(1 for i in items if i["disposition"] == "true_positive")
        judged = fp + tp
        fp_rate = round(100 * fp / judged) if judged else None
        fp_ents: Dict[str, int] = {}
        for i in items:
            if i["disposition"] == "false_positive":
                fp_ents[i["entity"]] = fp_ents.get(i["entity"], 0) + 1
        top_ent, top_n = (max(fp_ents.items(), key=lambda kv: kv[1]) if fp_ents else (None, 0))
        days_silent = (now - _parse(r["last_fired"])).days
        grade, suggestion = "ok", "No action needed."
        if total == 0:
            grade = "silent"
            suggestion = (f"Has not fired for {days_silent} days. Check that its log source is still flowing "
                          f"(see Source Health) and run an Atomic test to confirm the rule still works.")
        elif fp_rate is not None and fp_rate >= 80 and judged >= 5:
            grade = "noisy"
            if top_ent and top_n / max(fp, 1) >= 0.6:
                suggestion = f"Add an exclusion for '{top_ent}': {top_n} of {fp} false positives come from it. Give the exclusion a {SUPPRESSION_DAYS}-day review date."
            else:
                suggestion = "Tighten the rule (higher threshold or extra context conditions): false positives are spread across many entities."
        elif total >= 5 and judged / total < 0.3:
            grade = "unreviewed"
            suggestion = "Most alerts from this rule have no analyst verdict yet. Mark them true/false positive so quality can be measured."
        elif tp > 0 and (fp_rate is None or fp_rate < 50):
            grade = "healthy"
            suggestion = "Producing mostly real detections."
        out.append({"rule": r["rule"], "segment": r["segment"], "alerts_30d": total, "per_week": round(total / (window_days / 7), 1),
                    "false_positives": fp, "true_positives": tp, "fp_rate": fp_rate, "last_fired": r["last_fired"],
                    "days_since_fired": days_silent, "top_fp_entity": top_ent, "grade": grade, "suggestion": suggestion})
    order = {"noisy": 0, "silent": 1, "unreviewed": 2, "ok": 3, "healthy": 4}
    out.sort(key=lambda x: (order[x["grade"]], -x["alerts_30d"]))
    summary = {g: sum(1 for o in out if o["grade"] == g) for g in order}
    return {"rules": out, "summary": summary, "window_days": window_days, "demo_data": simulated > 0}


def suppression_health(tenant_id: str) -> dict:
    now = _now()
    with closing(get_db()) as conn:
        rules = [dict(r) for r in conn.execute("SELECT * FROM fp_rules WHERE tenant_id=? ORDER BY expires_at ASC", (tenant_id,)).fetchall()]
        hits = {(r["rule"], r["entity"]): r["c"] for r in conn.execute(
            "SELECT rule, entity, COUNT(*) c FROM alert_records WHERE tenant_id=? AND created_at>=? GROUP BY rule, entity",
            (tenant_id, _ts(now - timedelta(days=30)))).fetchall()}
    out = []
    for r in rules:
        exp = _parse(r["expires_at"]) if r.get("expires_at") else None
        days_left = (exp - now).days if exp else None
        state = "no_expiry" if exp is None else ("expired" if exp < now else ("expiring" if days_left <= EXPIRING_SOON_DAYS else "active"))
        matched = sum(c for (rule, ent), c in hits.items()
                      if r["rule_name"].lower() in rule.lower() and (r["entity_pattern"].lower() in (ent or "").lower()))
        out.append({"id": r["id"], "rule_name": r["rule_name"], "entity_pattern": r["entity_pattern"], "suppressed_by": r["suppressed_by"],
                    "reason": r["reason"], "created_at": r["created_at"], "expires_at": r.get("expires_at"), "days_left": days_left,
                    "state": state, "last_reviewed": r.get("last_reviewed"), "reviewed_by": r.get("reviewed_by"), "alerts_hidden_30d": matched})
    summary = {s: sum(1 for o in out if o["state"] == s) for s in ("active", "expiring", "expired", "no_expiry")}
    return {"suppressions": out, "summary": summary, "review_policy_days": SUPPRESSION_DAYS}


def renew_suppression(tenant_id: str, fp_id: str, reviewer: str) -> bool:
    with closing(get_db()) as conn:
        cur = conn.execute("UPDATE fp_rules SET expires_at=?, last_reviewed=?, reviewed_by=? WHERE id=? AND tenant_id=?",
                           (_ts(_now() + timedelta(days=SUPPRESSION_DAYS)), _ts(), reviewer, fp_id, tenant_id))
        conn.commit()
        return cur.rowcount > 0


def revoke_suppression(tenant_id: str, fp_id: str) -> Optional[dict]:
    with closing(get_db()) as conn:
        row = conn.execute("SELECT * FROM fp_rules WHERE id=? AND tenant_id=?", (fp_id, tenant_id)).fetchone()
        if not row:
            return None
        conn.execute("DELETE FROM fp_rules WHERE id=? AND tenant_id=?", (fp_id, tenant_id))
        conn.commit()
        return dict(row)


# =====================================================================
# 4. VULNERABILITY PRIORITIZATION  (CISA KEV + EPSS + CVSS + asset criticality + active incidents)
# =====================================================================
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
CVSS_RE = re.compile(r"CVSS\s*([0-9]+(?:\.[0-9])?)", re.I)
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"


def parse_kev(payload: dict) -> List[dict]:
    out = []
    for v in payload.get("vulnerabilities", []):
        cve = (v.get("cveID") or "").upper()
        if cve:
            out.append({"cve": cve, "kev_added": v.get("dateAdded"), "ransomware": 1 if str(v.get("knownRansomwareCampaignUse", "")).lower() == "known" else 0})
    return out


def parse_epss(payload: dict) -> List[dict]:
    out = []
    for d in payload.get("data", []):
        try:
            out.append({"cve": d["cve"].upper(), "epss": float(d["epss"]), "percentile": float(d.get("percentile", 0))})
        except (KeyError, ValueError, TypeError):
            continue
    return out


def tracked_cves(tenant_id: str) -> List[str]:
    with closing(get_db()) as conn:
        rows = conn.execute("SELECT cves FROM entity_profiles WHERE tenant_id=?", (tenant_id,)).fetchall()
    found = set()
    for r in rows:
        for item in json.loads(r["cves"] or "[]"):
            found.update(c.upper() for c in CVE_RE.findall(item))
    return sorted(found)


async def refresh_vuln_intel(tenant_id: str) -> dict:
    import httpx
    errors, kev_n, epss_n = [], 0, 0
    cves = tracked_cves(tenant_id)
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        kev, epss = [], []
        try:
            r = await client.get(KEV_URL)
            r.raise_for_status()
            kev = parse_kev(r.json())
        except Exception as e:
            errors.append(f"CISA KEV feed: {type(e).__name__}")
        for i in range(0, len(cves), 50):
            try:
                r = await client.get(EPSS_URL, params={"cve": ",".join(cves[i:i + 50])})
                r.raise_for_status()
                epss += parse_epss(r.json())
            except Exception as e:
                errors.append(f"EPSS feed: {type(e).__name__}")
                break
    now = _ts()
    with closing(get_db()) as conn:
        for k in kev:
            conn.execute("INSERT INTO vuln_intel (cve, kev, kev_added, ransomware, updated_at) VALUES (?,1,?,?,?) "
                         "ON CONFLICT(cve) DO UPDATE SET kev=1, kev_added=excluded.kev_added, ransomware=excluded.ransomware, updated_at=excluded.updated_at",
                         (k["cve"], k["kev_added"], k["ransomware"], now))
        for e in epss:
            conn.execute("INSERT INTO vuln_intel (cve, epss, percentile, updated_at) VALUES (?,?,?,?) "
                         "ON CONFLICT(cve) DO UPDATE SET epss=excluded.epss, percentile=excluded.percentile, updated_at=excluded.updated_at",
                         (e["cve"], e["epss"], e["percentile"], now))
        if kev or epss:
            conn.execute("INSERT OR REPLACE INTO intel_meta (key, value) VALUES ('vuln_intel_refreshed', ?)", (now,))
        conn.commit()
    return {"kev_loaded": len(kev), "epss_loaded": len(epss), "errors": errors, "tracked_cves": len(cves)}


def score_vuln(cvss: Optional[float], intel: Optional[dict], criticality: str, in_incident: bool) -> dict:
    """Explainable 0-100 score. Each factor is returned so the analyst can see why."""
    factors = []
    c = cvss if cvss is not None else 5.0
    factors.append({"name": "CVSS severity", "points": round(c / 10 * 30), "max": 30,
                    "why": f"CVSS {c}" + ("" if cvss is not None else " (unknown, assumed 5.0)")})
    kev = bool(intel and intel.get("kev"))
    factors.append({"name": "Known exploited (CISA KEV)", "points": (30 + (5 if intel and intel.get("ransomware") else 0)) if kev else 0, "max": 35,
                    "why": ("Listed in CISA KEV" + (", used in ransomware campaigns" if intel and intel.get("ransomware") else "")) if kev
                           else ("Not in CISA KEV" if intel else "Feed not loaded yet")})
    ep = intel.get("epss") if intel else None
    factors.append({"name": "Exploit likelihood (EPSS)", "points": round((ep or 0) * 20), "max": 20,
                    "why": f"{round(ep * 100, 1)}% chance of exploitation in 30 days" if ep is not None else "Feed not loaded yet"})
    crit = (criticality or "")
    pts = 12 if ("Tier-0" in crit or "Crown" in crit) else 8 if "Tier-1" in crit else 5 if "High" in crit else 2
    factors.append({"name": "Asset criticality", "points": pts, "max": 12, "why": crit or "Unclassified"})
    factors.append({"name": "Active incident on this asset", "points": 10 if in_incident else 0, "max": 10,
                    "why": "Host is part of an open incident" if in_incident else "No open incident"})
    total = min(100, sum(f["points"] for f in factors))
    band = "P1 - Patch now" if total >= 75 else "P2 - This week" if total >= 55 else "P3 - This month" if total >= 35 else "P4 - Monitor"
    return {"score": total, "band": band, "factors": factors}


def vuln_priorities(tenant_id: str) -> dict:
    with closing(get_db()) as conn:
        ents = [dict(r) for r in conn.execute("SELECT entity_id, entity_type, criticality, cves FROM entity_profiles WHERE tenant_id=?", (tenant_id,)).fetchall()]
        intel = {r["cve"]: dict(r) for r in conn.execute("SELECT * FROM vuln_intel").fetchall()}
        open_inc = [dict(r) for r in conn.execute("SELECT id, primary_entity FROM incidents WHERE tenant_id=? AND status NOT IN ('contained','closed')", (tenant_id,)).fetchall()]
        step_ents = [(r["incident_id"], r["entity"]) for r in conn.execute(
            "SELECT s.incident_id, s.entity FROM incident_steps s JOIN incidents i ON i.id=s.incident_id WHERE s.tenant_id=? AND i.status NOT IN ('contained','closed')", (tenant_id,)).fetchall()]
        refreshed = conn.execute("SELECT value FROM intel_meta WHERE key='vuln_intel_refreshed'").fetchone()
    rows = []
    for e in ents:
        eid = e["entity_id"]
        inc_ids = sorted({i["id"] for i in open_inc if i["primary_entity"] == eid} | {iid for iid, ent in step_ents if eid and eid in (ent or "")})
        for item in json.loads(e["cves"] or "[]"):
            m = CVE_RE.search(item)
            if not m:
                continue
            cve = m.group(0).upper()
            cv = CVSS_RE.search(item)
            sc = score_vuln(float(cv.group(1)) if cv else None, intel.get(cve), e["criticality"], bool(inc_ids))
            rows.append({"entity": eid, "entity_type": e["entity_type"], "criticality": e["criticality"], "cve": cve, "incidents": inc_ids,
                         "kev": bool(intel.get(cve, {}).get("kev")), "epss": intel.get(cve, {}).get("epss"), **sc})
    rows.sort(key=lambda r: -r["score"])
    bands = {b: sum(1 for r in rows if r["band"].startswith(b)) for b in ("P1", "P2", "P3", "P4")}
    return {"rows": rows, "bands": bands, "kev_count": sum(1 for r in rows if r["kev"]),
            "intel_loaded": bool(intel), "intel_refreshed_at": refreshed["value"] if refreshed else None}


# =====================================================================
# 6. INCIDENT QUALITY: similar incidents, checklist, summary draft
# =====================================================================
CHECKLISTS = {
    "Initial access": [("ia_headers", "Verify email headers (SPF/DKIM/DMARC) and sender reputation"),
                       ("ia_attach", "Hash-check or detonate attachments and URLs"),
                       ("ia_recipients", "Find every other recipient of the same message")],
    "Execution": [("ex_script", "Review PowerShell script-block logs (4104) and decode any encoded commands"),
                  ("ex_parent", "Check the parent-child process tree of the executing process")],
    "Persistence": [("pe_tasks", "Check scheduled tasks, services and Run keys created in the window"),
                    ("pe_accts", "Look for new local or domain accounts")],
    "Privilege escalation": [("pr_admin", "Review local/domain admin group changes"), ("pr_patch", "Check the host for exploited, unpatched CVEs")],
    "Defense evasion": [("de_logs", "Confirm logs were forwarded off-host before any clearing"), ("de_tools", "Check security-tool tamper or disable events")],
    "Credential access": [("ca_lsass", "Confirm LSASS access and identify the tool used"),
                          ("ca_rotate", "Rotate credentials for affected accounts (PAM vault and AD)"),
                          ("ca_scope", "List other systems the account logged in to")],
    "Discovery": [("di_cmds", "Collect the discovery commands run and the account used")],
    "Lateral movement": [("lm_paths", "Map source to destination hosts and protocols (RDP/SMB/WinRM)"),
                         ("lm_isolate", "Isolate source and destination hosts if confirmed")],
    "Collection": [("co_files", "Identify which files and shares were read or archived")],
    "Command and control": [("c2_block", "Block C2 destinations and search retroactively for other hits")],
    "Exfiltration": [("ex2_dest", "Block the destination IP/domain and hunt for earlier connections"),
                     ("ex2_volume", "Estimate data volume and sensitivity of what left"),
                     ("ex2_notify", "Decide whether customer or regulator notification is required")],
    "Impact": [("im_backup", "Verify backups are intact and offline copies are unaffected"),
               ("im_contain", "Contain affected hosts before encryption spreads")],
}
GENERIC_CHECKS = [("gen_scope", "Confirm the full scope of affected users and hosts"),
                  ("gen_ticket", "Update the ITSM ticket and notify the customer contact"),
                  ("gen_lessons", "Record lessons learned and any detection tuning needed")]


def checklist_for(tenant_id: str, incident_id: str) -> List[dict]:
    with closing(get_db()) as conn:
        tactics = [r["tactic"] for r in conn.execute("SELECT DISTINCT tactic FROM incident_steps WHERE incident_id=? AND tenant_id=? ORDER BY stage_order", (incident_id, tenant_id)).fetchall()]
        state = {r["item_key"]: dict(r) for r in conn.execute("SELECT * FROM checklist_state WHERE incident_id=? AND tenant_id=?", (incident_id, tenant_id)).fetchall()}
    items, seen = [], set()
    for t in tactics:
        for key, text in CHECKLISTS.get(t, []):
            if key not in seen:
                seen.add(key)
                items.append((key, text, t))
    items += [(k, t, "General") for k, t in GENERIC_CHECKS]
    return [{"key": k, "text": t, "stage": st, "done": bool(state.get(k, {}).get("done")),
             "by": state.get(k, {}).get("by_user"), "at": state.get(k, {}).get("at")} for k, t, st in items]


def set_check(tenant_id: str, incident_id: str, key: str, done: bool, user: str) -> bool:
    valid = {k for lst in CHECKLISTS.values() for k, _ in lst} | {k for k, _ in GENERIC_CHECKS}
    if key not in valid:
        return False
    with closing(get_db()) as conn:
        if not conn.execute("SELECT 1 FROM incidents WHERE id=? AND tenant_id=?", (incident_id, tenant_id)).fetchone():
            return False
        conn.execute("INSERT INTO checklist_state (incident_id, tenant_id, item_key, done, by_user, at) VALUES (?,?,?,?,?,?) "
                     "ON CONFLICT(incident_id, tenant_id, item_key) DO UPDATE SET done=excluded.done, by_user=excluded.by_user, at=excluded.at",
                     (incident_id, tenant_id, key, 1 if done else 0, user, _ts()))
        conn.commit()
    return True


_STOP = {"the", "and", "for", "with", "from", "that", "this", "was", "are", "has", "have", "via", "its", "into", "not", "all", "any", "can"}


def _tokens(text: str) -> List[str]:
    return [t for t in re.findall(r"[a-z0-9][a-z0-9\.\-]{2,}", (text or "").lower()) if t not in _STOP]


def similar_incidents(tenant_id: str, incident_id: str, top: int = 3) -> List[dict]:
    with closing(get_db()) as conn:
        incs = {r["id"]: dict(r) for r in conn.execute("SELECT * FROM incidents WHERE tenant_id=?", (tenant_id,)).fetchall()}
        steps: Dict[str, List[dict]] = {}
        for r in conn.execute("SELECT incident_id, title, tactic, technique_id, entity, source FROM incident_steps WHERE tenant_id=?", (tenant_id,)).fetchall():
            steps.setdefault(r["incident_id"], []).append(dict(r))
    if incident_id not in incs or len(incs) < 2:
        return []
    docs = {}
    for iid, inc in incs.items():
        parts = [inc["title"], inc["ai_story"], inc["recommended_action"]]
        for s in steps.get(iid, []):
            parts += [s["title"], s["tactic"], s["technique_id"], s["source"]]
        docs[iid] = _tokens(" ".join(p or "" for p in parts))
    n = len(docs)
    df: Dict[str, int] = {}
    for toks in docs.values():
        for t in set(toks):
            df[t] = df.get(t, 0) + 1
    idf = {t: math.log((n + 1) / (c + 1)) + 1 for t, c in df.items()}

    def vec(toks):
        tf: Dict[str, float] = {}
        for t in toks:
            tf[t] = tf.get(t, 0) + 1
        return {t: c * idf[t] for t, c in tf.items()}

    def cos(a, b):
        dot = sum(a[t] * b.get(t, 0) for t in a)
        na, nb = math.sqrt(sum(v * v for v in a.values())), math.sqrt(sum(v * v for v in b.values()))
        return dot / (na * nb) if na and nb else 0.0

    base = vec(docs[incident_id])
    my_tactics = {s["tactic"] for s in steps.get(incident_id, [])}
    out = []
    for iid, toks in docs.items():
        if iid == incident_id:
            continue
        sim = cos(base, vec(toks))
        if sim >= 0.05:
            out.append({"id": iid, "title": incs[iid]["title"], "status": incs[iid]["status"], "risk_score": incs[iid]["risk_score"],
                        "similarity_pct": round(sim * 100), "shared_tactics": sorted(my_tactics & {s["tactic"] for s in steps.get(iid, [])}),
                        "what_was_done": incs[iid]["recommended_action"]})
    out.sort(key=lambda x: -x["similarity_pct"])
    return out[:top]


def draft_summary(tenant_id: str, incident_id: str) -> Optional[str]:
    with closing(get_db()) as conn:
        inc = conn.execute("SELECT * FROM incidents WHERE id=? AND tenant_id=?", (incident_id, tenant_id)).fetchone()
        if not inc:
            return None
        inc = dict(inc)
        steps = [dict(r) for r in conn.execute("SELECT tactic, title, event_time, entity FROM incident_steps WHERE incident_id=? AND tenant_id=? ORDER BY stage_order, event_time", (incident_id, tenant_id)).fetchall()]
        pb = [dict(r) for r in conn.execute("SELECT status FROM soar_playbook_steps WHERE incident_id=? AND tenant_id=?", (incident_id, tenant_id)).fetchall()]
    tactics = []
    for s in steps:
        if s["tactic"] not in tactics:
            tactics.append(s["tactic"])
    done = sum(1 for p in pb if p["status"] in ("executed", "auto_executed"))
    lines = [f"Incident {incident_id}: {inc['title']}",
             f"Severity {inc['severity']}, risk score {inc['risk_score']}/100, status {inc['status']}, owner {inc.get('assigned_to') or 'Unassigned'}.",
             f"Primary entity: {inc['primary_entity']}. {len(steps)} correlated signals across {len(tactics)} ATT&CK stage(s): {' > '.join(tactics) or 'none yet'}."]
    if steps:
        lines.append(f"Timeline: first signal '{steps[0]['title']}' at {steps[0]['event_time']}; latest '{steps[-1]['title']}' at {steps[-1]['event_time']}.")
    lines.append(f"Response: {done} of {len(pb)} playbook step(s) completed. Recommended next action: {inc['recommended_action']}")
    return "\n".join(lines)


# =====================================================================
# 7. EXECUTIVE / CUSTOMER REPORT
# =====================================================================
def weekly_report(tenant_id: str, days: int = 7) -> dict:
    now = _now()
    since = _ts(now - timedelta(days=days))
    with closing(get_db()) as conn:
        tenant = dict(conn.execute("SELECT * FROM tenants WHERE id=?", (tenant_id,)).fetchone())
        incs = [dict(r) for r in conn.execute("SELECT * FROM incidents WHERE tenant_id=?", (tenant_id,)).fetchall()]
        ents = [dict(r) for r in conn.execute("SELECT entity_id, criticality, risk_score FROM entity_profiles WHERE tenant_id=? ORDER BY risk_score DESC LIMIT 5", (tenant_id,)).fetchall()]
        alerts = conn.execute("SELECT disposition, COUNT(*) c FROM alert_records WHERE tenant_id=? AND created_at>=? GROUP BY disposition", (tenant_id, since)).fetchall()
        pb = conn.execute("SELECT COUNT(*) c FROM soar_playbook_steps WHERE tenant_id=? AND status IN ('executed','auto_executed')", (tenant_id,)).fetchone()["c"]
    contained = [i for i in incs if i["status"] in ("contained", "closed") and i["updated_at"] >= since]
    mttr = round(statistics.mean((_parse(i["updated_at"]) - _parse(i["created_at"])).total_seconds() / 60 for i in contained), 1) if contained else None
    sev: Dict[str, int] = {}
    for i in incs:
        sev[i["severity"]] = sev.get(i["severity"], 0) + 1
    disp = {r["disposition"]: r["c"] for r in alerts}
    judged = disp.get("false_positive", 0) + disp.get("true_positive", 0)
    health, rules, sups = node_health(tenant_id), rule_health(tenant_id), suppression_health(tenant_id)
    return {"tenant": tenant["name"], "period_days": days, "generated_at": _ts(now) + " UTC",
            "incidents": {"total": len(incs), "open": sum(1 for i in incs if i["status"] not in ("contained", "closed")), "contained": len(contained),
                          "by_severity": sev, "mttr_minutes": mttr,
                          "open_list": [{"id": i["id"], "title": i["title"], "severity": i["severity"], "risk": i["risk_score"], "status": i["status"],
                                         "age_hours": round((now - _parse(i["created_at"])).total_seconds() / 3600, 1)} for i in incs if i["status"] != "contained"]},
            "alerts": {"total": sum(disp.values()), "false_positive": disp.get("false_positive", 0), "true_positive": disp.get("true_positive", 0),
                       "fp_rate": round(100 * disp.get("false_positive", 0) / judged) if judged else None},
            "top_risky_assets": ents, "playbook_actions": pb,
            "source_health": health["summary"], "noisy_rules": rules["summary"]["noisy"], "silent_rules": rules["summary"]["silent"],
            "suppressions": sups["summary"], "posture_score": tenant.get("posture_score"), "demo_data": rules["demo_data"]}


def render_report_html(r: dict) -> str:
    e = lambda v: html.escape(str(v if v is not None else "n/a"))
    inc, al = r["incidents"], r["alerts"]
    sev_rows = "".join(f"<tr><td>{e(k)}</td><td>{e(v)}</td></tr>" for k, v in sorted(inc["by_severity"].items()))
    open_rows = "".join(f"<tr><td>{e(i['id'])}</td><td>{e(i['title'])}</td><td>{e(i['severity'])}</td><td>{e(i['risk'])}</td><td>{e(i['status'])}</td><td>{e(i['age_hours'])} h</td></tr>" for i in inc["open_list"]) or "<tr><td colspan=6>No open incidents</td></tr>"
    asset_rows = "".join(f"<tr><td>{e(a['entity_id'])}</td><td>{e(a['criticality'])}</td><td>{e(a['risk_score'])}</td></tr>" for a in r["top_risky_assets"])
    sh = r["source_health"]
    demo = "<p class='demo'>Includes demo data: alert history is simulated until real alert ingestion is connected.</p>" if r["demo_data"] else ""
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Security Report - {e(r['tenant'])}</title>
<style>
body{{font-family:Calibri,Segoe UI,Arial,sans-serif;color:#2b2b2e;margin:0;background:#fff}}
.page{{max-width:860px;margin:0 auto;padding:36px 40px}}
h1{{font-family:Cambria,Georgia,serif;font-size:28px;margin:0 0 4px}} h2{{font-family:Cambria,Georgia,serif;font-size:18px;border-bottom:2px solid #d31c5b;padding-bottom:4px;margin-top:26px}}
.sub{{color:#777;margin-bottom:18px}} .grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}}
.card{{background:#f7f5f6;border-radius:10px;padding:12px 14px}} .card b{{display:block;font-size:24px;color:#d31c5b}} .card span{{font-size:12px;color:#666}}
table{{width:100%;border-collapse:collapse;font-size:13px;margin-top:8px}} th,td{{text-align:left;padding:6px 8px;border-bottom:1px solid #eee}} th{{color:#d31c5b;font-size:11px;letter-spacing:.05em;text-transform:uppercase}}
.demo{{background:#fff4d6;border:1px solid #f0d28a;padding:8px 12px;border-radius:8px;font-size:12.5px}} .foot{{margin-top:30px;color:#888;font-size:11.5px}}
@media print{{.page{{padding:0}} .noprint{{display:none}}}}
</style></head><body><div class="page">
<div class="noprint" style="text-align:right"><button onclick="window.print()">Print / Save as PDF</button></div>
<h1>Security Operations Report</h1><div class="sub">{e(r['tenant'])} &middot; last {e(r['period_days'])} days &middot; generated {e(r['generated_at'])}</div>{demo}
<div class="grid">
<div class="card"><b>{e(inc['open'])}</b><span>Open incidents</span></div>
<div class="card"><b>{e(inc['contained'])}</b><span>Contained this period</span></div>
<div class="card"><b>{e(str(inc['mttr_minutes']) + ' min' if inc['mttr_minutes'] is not None else 'n/a')}</b><span>Mean time to resolve</span></div>
<div class="card"><b>{e(str(al['fp_rate']) + '%' if al['fp_rate'] is not None else 'n/a')}</b><span>False-positive rate</span></div></div>
<h2>Incidents</h2><table><tr><th>Severity</th><th>Count</th></tr>{sev_rows}</table>
<h2>Open incidents</h2><table><tr><th>ID</th><th>Title</th><th>Severity</th><th>Risk</th><th>Status</th><th>Age</th></tr>{open_rows}</table>
<h2>Alert quality</h2><p>{e(al['total'])} alerts in the period: {e(al['true_positive'])} confirmed real, {e(al['false_positive'])} false positives. {e(r['noisy_rules'])} noisy rule(s) and {e(r['silent_rules'])} silent rule(s) need attention.</p>
<h2>Highest-risk assets</h2><table><tr><th>Asset</th><th>Criticality</th><th>Risk score</th></tr>{asset_rows}</table>
<h2>Platform health</h2><p>Log sources: {e(sh['healthy'])} healthy, {e(sh['degraded'])} degraded, {e(sh['silent'])} silent, {e(sh['surging'])} surging. Suppression rules: {e(r['suppressions']['active'])} active, {e(r['suppressions']['expiring'])} expiring soon, {e(r['suppressions']['expired'])} expired and awaiting review. Playbook actions completed: {e(r['playbook_actions'])}.</p>
<div class="foot">MTTD and SLA compliance are not shown: detection and first-response timestamps are not captured yet.</div>
</div></body></html>"""


# =====================================================================
# 10. EVIDENCE EXPORT (Ed25519-signed zip, verifiable with the public key only)
# =====================================================================
def _signing_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hmac.new(MASTER_KEY, b"evidence-signing-v1", hashlib.sha256).digest())


def public_key_hex() -> str:
    return _signing_key().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def _canon(o) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_evidence_zip(tenant_id: str, incident_id: str, generated_by: str) -> Optional[bytes]:
    with closing(get_db()) as conn:
        inc = conn.execute("SELECT * FROM incidents WHERE id=? AND tenant_id=?", (incident_id, tenant_id)).fetchone()
        if not inc:
            return None
        inc = dict(inc)
        q = lambda sql, *p: [dict(r) for r in conn.execute(sql, p).fetchall()]
        files = {
            "incident.json": inc,
            "steps.json": q("SELECT * FROM incident_steps WHERE incident_id=? AND tenant_id=? ORDER BY stage_order, event_time", incident_id, tenant_id),
            "playbook.json": q("SELECT * FROM soar_playbook_steps WHERE incident_id=? AND tenant_id=? ORDER BY step_order", incident_id, tenant_id),
            "case_notes.json": q("SELECT * FROM case_notes WHERE incident_id=? AND tenant_id=? ORDER BY created_at", incident_id, tenant_id),
            "entity_profile.json": q("SELECT * FROM entity_profiles WHERE entity_id=? AND tenant_id=?", inc["primary_entity"], tenant_id),
            "audit_extract.json": q("SELECT * FROM audit_logs WHERE tenant_id=? AND (target LIKE ? OR details LIKE ?) ORDER BY rowid LIMIT 1000",
                                    tenant_id, f"%{incident_id}%", f"%{incident_id}%"),
        }
    blobs = {name: json.dumps(data, indent=2, default=str).encode("utf-8") for name, data in files.items()}
    manifest = {"incident_id": incident_id, "tenant_id": tenant_id, "generated_at": _ts() + " UTC", "generated_by": generated_by,
                "files": {name: hashlib.sha256(b).hexdigest() for name, b in blobs.items()}}
    sig = {"algorithm": "Ed25519", "public_key": public_key_hex(), "signature": _signing_key().sign(_canon(manifest)).hex()}
    readme = (f"Evidence package for {incident_id}\n\nmanifest.json lists the SHA-256 of every file. signature.json is an Ed25519 signature over manifest.json "
              "(canonical JSON, sorted keys, no spaces).\nVerify with:  python verify_evidence.py <this.zip> [--trusted-public-key <hex>]\n"
              "To prove it came from this platform, compare the public key with the one published by the platform operator.\n")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, b in blobs.items():
            z.writestr(name, b)
        z.writestr("manifest.json", json.dumps(manifest, indent=2))
        z.writestr("signature.json", json.dumps(sig, indent=2))
        z.writestr("README.txt", readme)
    return buf.getvalue()


def verify_evidence_zip(data: bytes, trusted_public_key: Optional[str] = None) -> dict:
    problems = []
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        manifest = json.loads(z.read("manifest.json"))
        sig = json.loads(z.read("signature.json"))
    except Exception as e:
        return {"ok": False, "problems": [f"unreadable package: {type(e).__name__}"]}
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(sig["public_key"])).verify(bytes.fromhex(sig["signature"]), _canon(manifest))
    except (InvalidSignature, ValueError, KeyError):
        problems.append("manifest signature is invalid")
    for name, digest in manifest.get("files", {}).items():
        try:
            if hashlib.sha256(z.read(name)).hexdigest() != digest:
                problems.append(f"{name}: content does not match manifest")
        except KeyError:
            problems.append(f"{name}: missing from package")
    if trusted_public_key and trusted_public_key.lower() != sig.get("public_key", "").lower():
        problems.append("signed by a different key than the trusted one")
    return {"ok": not problems, "problems": problems, "incident_id": manifest.get("incident_id"), "generated_at": manifest.get("generated_at")}
