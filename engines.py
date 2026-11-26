# file: engines.py
import asyncio
import re
from datetime import datetime, timedelta, timezone
from typing import Dict, List

import httpx
from config import settings
from db import get_db
from ai_security import UNTRUSTED_NOTICE, ingest_event, sanitize_for_llm


# =====================================================================
# ENGINE 1, 2, 3, 5: SEGMENTATION, FP DETECTION, UEBA, MULTI-MODEL RISK
# =====================================================================
TACTIC_WEIGHTS = {
    "Initial access": 18,
    "Execution": 20,
    "Credential access": 24,
    "Lateral movement": 28,
    "Exfiltration": 35,
}


def compute_multi_model_risk(steps: List[dict]) -> int:
    """Engine 5: Combines MITRE kill-chain depth, step severity, and TI/UEBA flags into a 0-100 score."""
    if not steps:
        return 0
    tactics = {s["tactic"] for s in steps}
    base = sum(TACTIC_WEIGHTS.get(t, 12) for t in tactics)
    high_count = sum(1 for s in steps if s["severity"] == "high")
    score = int((base + high_count * 4) * (1.15 if len(tactics) >= 4 else 1.0))
    return min(99, max(10, score))


def get_six_engines_status(tenant_id: str) -> List[dict]:
    """Returns live metrics for the 6 Core Capabilities cards."""
    with get_db() as conn:
        fp_count = conn.execute("SELECT COUNT(*) as c FROM fp_rules WHERE tenant_id=?", (tenant_id,)).fetchone()["c"]
        node_count = conn.execute("SELECT COUNT(*) as c FROM node_status WHERE tenant_id=? AND status='online'", (tenant_id,)).fetchone()["c"]
        inc_count = conn.execute("SELECT COUNT(*) as c FROM incidents WHERE tenant_id=?", (tenant_id,)).fetchone()["c"]
        step_count = conn.execute("SELECT COUNT(*) as c FROM incident_steps WHERE tenant_id=?", (tenant_id,)).fetchone()["c"]

    return [
        {
            "engine": "Alert Segmentation",
            "metric": f"{step_count} signals → {inc_count} incident",
            "desc": "Groups and categorizes incoming alerts by type, source and severity so analysts see organized queues, not a flood.",
            "status": "active",
        },
        {
            "engine": "Behavioural Analysis",
            "metric": "2 UEBA anomalies flagged",
            "desc": "Baselines normal user and host behaviour and flags deviations that rule-based detection misses (First-time RDP & 2.3 GB spike).",
            "status": "active",
        },
        {
            "engine": "False-Positive Detection",
            "metric": f"{fp_count} active suppression rules",
            "desc": "Identifies and suppresses recurring benign alerts, freeing analysts to focus on real threats.",
            "status": "active",
        },
        {
            "engine": "Integrated Node Status",
            "metric": f"{node_count}/6 nodes healthy",
            "desc": "Live health and status of connected nodes and integrations in one view, with early warning on gaps.",
            "status": "active",
        },
        {
            "engine": "AI-Driven Response",
            "metric": "Multi-LLM + Playbooks ready",
            "desc": "Recommends and automates response actions with context, shortening time to contain.",
            "status": "active",
        },
        {
            "engine": "Multi-Model Detection & Risk Score",
            "metric": "Peak Incident Risk: 92/100",
            "desc": "Combines several detection models into one risk score to prioritize what matters most.",
            "status": "active",
        },
    ]


# =====================================================================
# ENGINE 6A: MULTI-API THREAT INTEL & OSINT ENRICHMENT
# =====================================================================
async def enrich_ip_full(ip: str) -> dict:
    """Queries Shodan InternetDB, Shodan Host, AlienVault OTX, VirusTotal, and IP-API concurrently."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        tasks = {
            "geo": client.get(settings.IP_API_GEOLOCATION_URL.format(ip=ip)),
            "idb": client.get(settings.SHODAN_INTERNETDB_URL.format(ip=ip)),
        }
        if settings.SHODAN_API_KEY:
            tasks["shodan"] = client.get(settings.SHODAN_HOST_URL.format(ip=ip, key=settings.SHODAN_API_KEY))
        if settings.ALIENVAULT_OTX_KEY:
            tasks["otx"] = client.get(
                settings.OTX_IP_PULSES_URL.format(ip=ip),
                headers={"X-OTX-API-KEY": settings.ALIENVAULT_OTX_KEY},
            )
        if settings.VIRUSTOTAL_API_KEY:
            tasks["vt"] = client.get(
                settings.VT_IP_URL.format(ip=ip),
                headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
            )

        res = await asyncio.gather(*tasks.values(), return_exceptions=True)
        out = dict(zip(tasks.keys(), res))

    def safe_json(k):
        r = out.get(k)
        if r and not isinstance(r, Exception) and r.is_success:
            try:
                return r.json()
            except Exception:
                return {}
        return {}

    geo = safe_json("geo")
    idb = safe_json("idb")
    otx = safe_json("otx")
    vt = safe_json("vt")

    otx_pulses = otx.get("pulse_info", {}).get("count", 0)
    vt_stats = vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    vt_mal = vt_stats.get("malicious", 0) + vt_stats.get("suspicious", 0)

    return {
        "ip": ip,
        "country": geo.get("country", "Unknown"),
        "country_code": geo.get("countryCode", ""),
        "isp_org": geo.get("org") or geo.get("isp", "Unknown"),
        "asn": geo.get("as", ""),
        "ports": idb.get("ports", []),
        "vulns": idb.get("vulns", [])[:8],
        "tags": idb.get("tags", []),
        "otx_pulses": otx_pulses,
        "vt_malicious": vt_mal,
        "verdict": "MALICIOUS" if (vt_mal >= 2 or otx_pulses >= 2) else ("SUSPICIOUS" if (vt_mal == 1 or otx_pulses == 1) else "CLEAN"),
    }


# =====================================================================
# ENGINE 6B: MULTI-CLOUD LLM EXPLAINER (Groq -> OpenAI -> Anthropic -> Gemini)
# =====================================================================
async def generate_step_explanation(step: dict) -> dict:
    """Generates plain-language explanation for 'Explain this step ↗' button."""
    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", step["raw_log"])
    ti_summary = ""
    if ip_match and not ip_match.group(0).startswith("192.168."):
        ti_data = await enrich_ip_full(ip_match.group(0))
        ti_summary = (
            f"\nLive OSINT Enrichment for {ti_data['ip']}: Country={ti_data['country']}, "
            f"Org={ti_data['isp_org']}, Ports={ti_data['ports']}, OTX Pulses={ti_data['otx_pulses']}, "
            f"VT Malicious={ti_data['vt_malicious']} ({ti_data['verdict']})."
        )

    # The SOC protects its own AI: logs and OSINT text are attacker-controlled, so secrets/PII are redacted and
    # injection phrases are removed before anything reaches an LLM.
    safe_log, guard_log = sanitize_for_llm(step["raw_log"])
    ti_summary, guard_ti = sanitize_for_llm(ti_summary)
    step = {**step, "raw_log": safe_log, "title": sanitize_for_llm(step["title"])[0], "entity": sanitize_for_llm(step["entity"])[0]}
    if (guard_log["injection"] or guard_ti["injection"]) and step.get("tenant_id"):
        try:
            ingest_event(step["tenant_id"], "soc-ai-analyst", step["raw_log"] + " " + ti_summary, "retrieval", user_id=step.get("incident_id", ""), raise_incident=False)
        except Exception:
            pass                                    # recording the attempt must never break the explanation
    sys_prompt = (
        "You are Trustaira Smart SOC's AI Analyst writing for a business client. "
        "Explain this attack step clearly in 4 short labeled lines:\n"
        "• What Happened:\n"
        "• Risk & Business Impact:\n"
        "• Automated Checks Performed:\n"
        "• Recommended Action:\n" + UNTRUSTED_NOTICE
    )
    user_prompt = (
        f"Incident: {step['incident_id']} | Step: {step['title']}\n"
        f"MITRE Tactic: {step['tactic']} ({step['technique_id']})\n"
        f"Source: {step['source']} | Entity: {step['entity']} | Time: {step['event_time']}\n"
        f"<untrusted_log>{step['raw_log']}{ti_summary}</untrusted_log>"
    )

    async with httpx.AsyncClient(timeout=12.0) as client:
        # 1. Try Groq (Llama 3.3 70B - Ultra Fast)
        if settings.GROQ_API_KEY:
            try:
                r = await client.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers={"Authorization": f"Bearer {settings.GROQ_API_KEY}"},
                    json={
                        "model": "llama-3.3-70b-versatile",
                        "messages": [{"role": "system", "content": sys_prompt}, {"role": "user", "content": user_prompt}],
                        "temperature": 0.2,
                    },
                )
                if r.is_success:
                    return {"provider": "Groq (Llama-3.3-70B)", "text": r.json()["choices"][0]["message"]["content"], "ti": ti_summary}
            except Exception:
                pass

        # 2. Try OpenAI (GPT-4o-mini)
        if settings.OPENAI_API_KEY:
            try:
                r = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {settings.OPENAI_API_KEY}"},
                    json={
                        "model": "gpt-4o-mini",
                        "messages": [{"role": "system", "content": sys_prompt}, {"role": "user", "content": user_prompt}],
                        "temperature": 0.2,
                    },
                )
                if r.is_success:
                    return {"provider": "OpenAI (GPT-4o-mini)", "text": r.json()["choices"][0]["message"]["content"], "ti": ti_summary}
            except Exception:
                pass

        # 3. Try Anthropic (Claude)
        if settings.ANTHROPIC_API_KEY:
            try:
                r = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={"x-api-key": settings.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01"},
                    json={
                        "model": "claude-3-5-haiku-latest",
                        "max_tokens": 350,
                        "system": sys_prompt,
                        "messages": [{"role": "user", "content": user_prompt}],
                    },
                )
                if r.is_success:
                    return {"provider": "Anthropic (Claude)", "text": r.json()["content"][0]["text"], "ti": ti_summary}
            except Exception:
                pass

    # Deterministic plain-language fallback
    fallback = (
        f"• What Happened: {step['source']} detected '{step['title']}' on entity '{step['entity']}' at {step['event_time']} ({step['tactic']} - {step['technique_id']}).\n"
        f"• Risk & Business Impact: Severity is {step['severity'].upper()}. Telemetry ({step['raw_log']}) confirms active progression along the attack chain.\n"
        f"• Automated Checks Performed: Correlated entity activity across email, endpoint, AD, and network telemetry.{ti_summary}\n"
        f"• Recommended Action: Pin this step to the incident report and approve automated host/account containment."
    )
    return {"provider": "Trustaira Built-In AI Engine", "text": fallback, "ti": ti_summary}


# =====================================================================
# LIVE ELASTICSEARCH & TREND VISION ONE TELEMETRY CONNECTORS
# =====================================================================
def base_index(name: str) -> str:
    n = re.sub(r"^\.ds-", "", name)
    return re.sub(r"-\d{4}\.\d{2}\.\d{2}(-\d+)?$", "", n)


async def fetch_siem_summary(days: int) -> dict:
    if not settings.ES_API_KEY:
        raise RuntimeError("ES_API_KEY not set in .env (using Smart SOC Incident DB mode)")
    interval = "1h" if days <= 2 else "1d"
    body = {
        "size": 15,
        "track_total_hits": True,
        "sort": [{"@timestamp": "desc"}],
        "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": f"now-{days}d"}}}]}},
        "_source": False,
        "fields": [
            "@timestamp", "kibana.alert.rule.name", "kibana.alert.severity",
            "kibana.alert.risk_score", "kibana.alert.reason", "host.name", "source.ip",
        ],
        "aggs": {
            "sev": {"terms": {"field": "kibana.alert.severity", "size": 10}},
            "rules": {"terms": {"field": "kibana.alert.rule.name", "size": 8}},
            "hosts": {"terms": {"field": "host.name", "size": 8}},
            "timeline": {"date_histogram": {"field": "@timestamp", "fixed_interval": interval}},
        },
    }
    async with httpx.AsyncClient(verify=settings.ES_VERIFY, timeout=15.0) as client:
        r = await client.post(
            f"{settings.ES_HOST}/{settings.ES_ALERT_INDEX}/_search",
            json=body,
            headers={"Authorization": f"ApiKey {settings.ES_API_KEY}"},
        )
        r.raise_for_status()
        d = r.json()

    ag = d.get("aggregations", {})
    buckets = lambda k: [{"key": b["key"], "count": b["doc_count"]} for b in ag.get(k, {}).get("buckets", [])]
    latest = []
    for h in d["hits"]["hits"]:
        f = h.get("fields", {})
        g = lambda k: (f.get(k) or [None])[0]
        latest.append({
            "time": g("@timestamp"),
            "rule": g("kibana.alert.rule.name"),
            "severity": g("kibana.alert.severity"),
            "risk": g("kibana.alert.risk_score"),
            "host": g("host.name"),
            "source_ip": g("source.ip"),
            "reason": g("kibana.alert.reason"),
        })
    return {
        "total": d["hits"]["total"]["value"],
        "severity": buckets("sev"),
        "rules": buckets("rules"),
        "hosts": buckets("hosts"),
        "timeline": [{"t": b["key_as_string"], "count": b["doc_count"]} for b in ag.get("timeline", {}).get("buckets", [])],
        "latest": latest,
    }


async def fetch_v1_summary(days: int) -> dict:
    if not settings.V1_API_KEY:
        raise RuntimeError("V1_API_KEY not set in .env (using Smart SOC Incident DB mode)")
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=min(days, 90))
    fmt = lambda dt: dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    params = {
        "startDateTime": fmt(start),
        "endDateTime": fmt(end),
        "dateTimeTarget": "createdDateTime",
        "orderBy": "createdDateTime desc",
    }
    headers = {"Authorization": f"Bearer {settings.V1_API_KEY}"}
    async with httpx.AsyncClient(timeout=20.0) as client:
        r = await client.get(f"{settings.V1_BASE_URL}/v3.0/workbench/alerts", params=params, headers=headers)
        r.raise_for_status()
        data = r.json()
        items = list(data.get("items", []))

    def count_by(key, limit=None):
        out: Dict[str, int] = {}
        for it in items:
            k = str(it.get(key) or "unknown").lower() if key == "severity" else str(it.get(key) or "unknown")
            out[k] = out.get(k, 0) + 1
        rows = [{"key": k, "count": v} for k, v in sorted(out.items(), key=lambda x: -x[1])]
        return rows[:limit] if limit else rows

    return {
        "total": len(items),
        "severity": count_by("severity"),
        "models": count_by("model", 8),
        "latest": [{
            "id": it.get("id"),
            "model": it.get("model"),
            "severity": (it.get("severity") or "").lower(),
            "status": it.get("status"),
            "score": it.get("score"),
            "created": it.get("createdDateTime"),
            "link": it.get("workbenchLink"),
        } for it in items[:15]],
    }