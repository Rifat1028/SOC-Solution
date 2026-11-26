# file: ai_cloud.py
"""AI Security, second layer:
* AI discovery and shadow-AI monitoring (CASB-style): which AI services are people using, who, how much data goes out.
* AI-SPM: posture checks over the AI inventory with a score, framework mapping and accepted-risk handling.
* AI gateway: an inline, policy-driven proxy in front of the model with the same guardrail engine.
Depends on ai_security.py and db.py only."""
import json
import re
import time
import uuid
import zlib
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

import httpx

import ai_security as ai
from config import settings
from db import get_db

UTC = timezone.utc


def _now() -> datetime:
    return datetime.now(UTC)


def _ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


# =====================================================================
# 1. DISCOVERY / SHADOW AI (CASB)
# =====================================================================
# Classified by category, not by a vendor audit: the risk text describes what can go wrong with that kind of service.
CATEGORY = {
    "chat":         ("medium", "Staff may paste confidential text into prompts."),
    "code":         ("high",   "Source code and secrets may leave the company."),
    "api_platform": ("high",   "Programmatic access can move data out in bulk."),
    "image_video":  ("low",    "Brand and product material may be uploaded."),
    "model_hub":    ("medium", "Models and datasets may be downloaded or uploaded outside review."),
    "search":       ("medium", "Queries can reveal strategy and customer names."),
    "meeting":      ("high",   "Meeting audio and transcripts leave the company."),
    "unknown":      ("medium", "Looks like an AI service but is not in the catalogue. Needs review."),
}
# (id, name, vendor, category, domains)
CATALOG = [
    ("openai-chatgpt", "ChatGPT", "OpenAI", "chat", ["chatgpt.com", "chat.openai.com"]),
    ("openai-api", "OpenAI API", "OpenAI", "api_platform", ["api.openai.com", "platform.openai.com"]),
    ("anthropic-claude", "Claude", "Anthropic", "chat", ["claude.ai"]),
    ("anthropic-api", "Anthropic API", "Anthropic", "api_platform", ["api.anthropic.com", "console.anthropic.com"]),
    ("google-gemini", "Gemini", "Google", "chat", ["gemini.google.com"]),
    ("google-ai-studio", "Google AI Studio / Gemini API", "Google", "api_platform", ["aistudio.google.com", "generativelanguage.googleapis.com"]),
    ("microsoft-copilot", "Microsoft Copilot", "Microsoft", "chat", ["copilot.microsoft.com"]),
    ("github-copilot", "GitHub Copilot", "GitHub", "code", ["copilot.github.com", "api.githubcopilot.com"]),
    ("cursor", "Cursor", "Anysphere", "code", ["cursor.com", "cursor.sh"]),
    ("perplexity", "Perplexity", "Perplexity", "search", ["perplexity.ai"]),
    ("deepseek", "DeepSeek", "DeepSeek", "chat", ["deepseek.com", "chat.deepseek.com"]),
    ("mistral", "Mistral", "Mistral AI", "chat", ["chat.mistral.ai", "mistral.ai"]),
    ("mistral-api", "Mistral API", "Mistral AI", "api_platform", ["api.mistral.ai"]),
    ("xai-grok", "Grok", "xAI", "chat", ["grok.com", "x.ai"]),
    ("groq", "Groq", "Groq", "api_platform", ["groq.com", "api.groq.com"]),
    ("huggingface", "Hugging Face", "Hugging Face", "model_hub", ["huggingface.co"]),
    ("replicate", "Replicate", "Replicate", "api_platform", ["replicate.com"]),
    ("together", "Together AI", "Together", "api_platform", ["together.ai", "api.together.xyz"]),
    ("cohere", "Cohere", "Cohere", "api_platform", ["cohere.com", "api.cohere.com"]),
    ("openrouter", "OpenRouter", "OpenRouter", "api_platform", ["openrouter.ai"]),
    ("midjourney", "Midjourney", "Midjourney", "image_video", ["midjourney.com"]),
    ("runway", "Runway", "Runway", "image_video", ["runwayml.com"]),
    ("stability", "Stability AI", "Stability AI", "image_video", ["stability.ai"]),
    ("elevenlabs", "ElevenLabs", "ElevenLabs", "image_video", ["elevenlabs.io"]),
    ("character-ai", "Character.AI", "Character.AI", "chat", ["character.ai"]),
    ("poe", "Poe", "Quora", "chat", ["poe.com"]),
    ("otter", "Otter.ai", "Otter.ai", "meeting", ["otter.ai"]),
    ("fireflies", "Fireflies.ai", "Fireflies", "meeting", ["fireflies.ai"]),
]
_BY_ID = {c[0]: c for c in CATALOG}
_HEURISTIC = re.compile(r"(?:^|[.\-_])(?:gpt|llm|chatbot|genai|aigen|copilot|openai)(?:[.\-_0-9]|$)", re.IGNORECASE)   # a whole word in the name, not a substring
STATUSES = ("sanctioned", "tolerated", "unsanctioned", "blocked")
DECISION = {"sanctioned": "allow", "tolerated": "warn", "unsanctioned": "warn", "blocked": "block", "unreviewed": "warn"}


def classify_host(host: str) -> Optional[dict]:
    host = (host or "").strip().lower().rstrip(".")
    host = re.sub(r"^[a-z]+://", "", host).split("/")[0].split(":")[0]
    if not host:
        return None
    for sid, name, vendor, cat, domains in CATALOG:
        for d in domains:
            if host == d or host.endswith("." + d):
                return {"service_id": sid, "name": name, "vendor": vendor, "category": cat, "host": host, "known": True}
    if _HEURISTIC.search(host):
        return {"service_id": "unknown:" + host, "name": host, "vendor": "Unknown", "category": "unknown", "host": host, "known": False}
    return None


def init_cloud_db() -> None:
    with closing(get_db()) as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS ai_service_policy (tenant_id TEXT NOT NULL, service_id TEXT NOT NULL, status TEXT NOT NULL, note TEXT,
            updated_by TEXT, updated_at TEXT NOT NULL, PRIMARY KEY (tenant_id, service_id));
        CREATE TABLE IF NOT EXISTS ai_discovery_events (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, created_at TEXT NOT NULL,
            user_id TEXT, device TEXT, host TEXT, service_id TEXT NOT NULL, service_name TEXT, category TEXT, decision TEXT, bytes_out INTEGER DEFAULT 0,
            dlp_verdict TEXT, incident_id TEXT, is_demo INTEGER DEFAULT 0);
        CREATE INDEX IF NOT EXISTS idx_ai_disc ON ai_discovery_events(tenant_id, created_at);
        CREATE TABLE IF NOT EXISTS ai_posture_exceptions (tenant_id TEXT NOT NULL, finding_key TEXT NOT NULL, reason TEXT NOT NULL,
            accepted_by TEXT NOT NULL, accepted_at TEXT NOT NULL, PRIMARY KEY (tenant_id, finding_key));
        CREATE TABLE IF NOT EXISTS ai_posture_history (tenant_id TEXT NOT NULL, day TEXT NOT NULL, score INTEGER NOT NULL, PRIMARY KEY (tenant_id, day));
        CREATE TABLE IF NOT EXISTS ai_gateway_policies (tenant_id TEXT NOT NULL, app TEXT NOT NULL, mode TEXT NOT NULL DEFAULT 'redact',
            block_threshold INTEGER NOT NULL DEFAULT 75, max_chars INTEGER NOT NULL DEFAULT 12000, rate_per_min INTEGER NOT NULL DEFAULT 30,
            allowed_models TEXT DEFAULT '', updated_by TEXT, updated_at TEXT NOT NULL, PRIMARY KEY (tenant_id, app));
        CREATE TABLE IF NOT EXISTS ai_gateway_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, created_at TEXT NOT NULL, app TEXT NOT NULL,
            user_id TEXT, model TEXT, mode TEXT, verdict TEXT, blocked INTEGER DEFAULT 0, redactions INTEGER DEFAULT 0, latency_ms INTEGER DEFAULT 0,
            forwarded INTEGER DEFAULT 0, prompt_chars INTEGER DEFAULT 0, reason TEXT);
        CREATE INDEX IF NOT EXISTS idx_ai_gw ON ai_gateway_requests(tenant_id, app, user_id, created_at);
        """)
        conn.commit()


def _status_map(conn, tenant_id: str) -> Dict[str, dict]:
    return {r["service_id"]: dict(r) for r in conn.execute("SELECT service_id, status, note, updated_by, updated_at FROM ai_service_policy WHERE tenant_id=?", (tenant_id,)).fetchall()}


def record_discovery(tenant_id: str, user_id: str, device: str, host: str, bytes_out: int = 0, text: str = "",
                     created: Optional[datetime] = None, is_demo: bool = False) -> dict:
    """One proxy / DNS / SaaS-log record. Returns the policy decision a proxy can enforce."""
    svc = classify_host(host)
    if not svc:
        return {"ai_service": False, "decision": "allow"}
    created = created or _now()
    bytes_out = max(0, min(int(bytes_out or 0), 10**12))
    with closing(get_db()) as conn:
        pol = _status_map(conn, tenant_id).get(svc["service_id"])
        status = pol["status"] if pol else "unreviewed"
        decision = DECISION[status]
        dlp, incident_id = "none", None
        if text:
            res = ai.inspect_text(text, "prompt", ai.list_terms(tenant_id))
            dlp = res["verdict"]
            leaked = res["verdict"] == "block" or any(f["owasp"] == "LLM02" and f["severity"] in ("high", "critical") for f in res["findings"])
            if leaked:
                dlp = "block"
            if status != "sanctioned" and leaked:
                incident_id = ai._raise_incident(conn, tenant_id, {"app": svc["name"], "user_id": (user_id or "")[:80]}, res, created)
                decision = "block"
        first = not conn.execute("SELECT 1 FROM ai_discovery_events WHERE tenant_id=? AND service_id=? LIMIT 1", (tenant_id, svc["service_id"])).fetchone()
        conn.execute("INSERT INTO ai_discovery_events (tenant_id, created_at, user_id, device, host, service_id, service_name, category, decision, bytes_out, dlp_verdict, incident_id, is_demo) "
                     "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", (tenant_id, _ts(created), (user_id or "")[:80], (device or "")[:80], svc["host"][:120], svc["service_id"], svc["name"],
                                                           svc["category"], decision, bytes_out, dlp, incident_id, 1 if is_demo else 0))
        conn.commit()
    return {"ai_service": True, "service_id": svc["service_id"], "service": svc["name"], "category": svc["category"], "status": status, "decision": decision,
            "first_seen": first, "dlp": dlp, "incident_id": incident_id}


def discovery_summary(tenant_id: str, days: int = 30) -> dict:
    since = _ts(_now() - timedelta(days=max(1, min(days, 365))))
    with closing(get_db()) as conn:
        pol = _status_map(conn, tenant_id)
        rows = conn.execute("SELECT service_id, MAX(service_name) name, MAX(category) category, COUNT(*) events, COUNT(DISTINCT user_id) users, COALESCE(SUM(bytes_out),0) bytes_out, "
                            "MIN(created_at) first_seen, MAX(created_at) last_seen, SUM(CASE WHEN dlp_verdict IN ('block','flag') THEN 1 ELSE 0 END) dlp_hits "
                            "FROM ai_discovery_events WHERE tenant_id=? AND created_at>=? GROUP BY service_id ORDER BY bytes_out DESC", (tenant_id, since)).fetchall()
        top_users = conn.execute("SELECT user_id, COUNT(DISTINCT service_id) services, COALESCE(SUM(bytes_out),0) bytes_out FROM ai_discovery_events WHERE tenant_id=? AND created_at>=? GROUP BY user_id ORDER BY bytes_out DESC LIMIT 8", (tenant_id, since)).fetchall()
        sample = conn.execute("SELECT COUNT(*) c FROM ai_discovery_events WHERE tenant_id=? AND is_demo=1", (tenant_id,)).fetchone()["c"]
    services = []
    for r in rows:
        status = (pol.get(r["service_id"]) or {}).get("status", "unreviewed")
        base = CATEGORY[r["category"]]
        risk = base[0]
        if status in ("unsanctioned", "unreviewed", "blocked") and (r["dlp_hits"] or r["bytes_out"] > 50_000_000):
            risk = "critical" if r["dlp_hits"] else "high"
        services.append({"service_id": r["service_id"], "name": r["name"], "category": r["category"], "status": status, "risk": risk, "risk_reason": base[1],
                         "events": r["events"], "users": r["users"], "bytes_out": r["bytes_out"], "first_seen": r["first_seen"], "last_seen": r["last_seen"],
                         "dlp_hits": r["dlp_hits"], "note": (pol.get(r["service_id"]) or {}).get("note")})
    shadow = [s for s in services if s["status"] in ("unreviewed", "unsanctioned")]
    return {"services": services, "top_users": [dict(u) for u in top_users], "has_sample_data": bool(sample),
            "totals": {"services": len(services), "shadow": len(shadow), "blocked": sum(1 for s in services if s["status"] == "blocked"), "sanctioned": sum(1 for s in services if s["status"] == "sanctioned"),
                       "users": len({u["user_id"] for u in top_users}) if top_users else 0, "bytes_out": sum(s["bytes_out"] for s in services), "dlp_hits": sum(s["dlp_hits"] for s in services)}}


def service_detail(tenant_id: str, service_id: str, days: int = 30) -> dict:
    since = _ts(_now() - timedelta(days=days))
    with closing(get_db()) as conn:
        users = [dict(r) for r in conn.execute("SELECT user_id, COUNT(*) events, COALESCE(SUM(bytes_out),0) bytes_out, MAX(created_at) last_seen FROM ai_discovery_events WHERE tenant_id=? AND service_id=? AND created_at>=? GROUP BY user_id ORDER BY bytes_out DESC LIMIT 25", (tenant_id, service_id, since)).fetchall()]
    return {"service_id": service_id, "users": users}


def set_service_status(tenant_id: str, service_id: str, status: str, note: str, actor: str) -> dict:
    if status not in STATUSES:
        raise ai.AIError(400, f"status must be one of: {', '.join(STATUSES)}")
    with closing(get_db()) as conn:
        if not conn.execute("SELECT 1 FROM ai_discovery_events WHERE tenant_id=? AND service_id=? LIMIT 1", (tenant_id, service_id)).fetchone() and service_id not in _BY_ID:
            raise ai.AIError(404, "Unknown AI service")
        conn.execute("INSERT OR REPLACE INTO ai_service_policy (tenant_id, service_id, status, note, updated_by, updated_at) VALUES (?,?,?,?,?,?)",
                     (tenant_id, service_id, status, (note or "")[:200], actor, _ts(_now())))
        conn.commit()
    return {"service_id": service_id, "status": status}


# =====================================================================
# 2. AI-SPM: posture
# =====================================================================
SEV_POINTS = {"critical": 12, "high": 7, "medium": 3, "low": 1}
GUARDED = ("model", "agent", "app")


def _days_since(date_str: Optional[str]) -> Optional[int]:
    if not date_str:
        return None
    try:
        return (_now() - datetime.strptime(date_str[:10], "%Y-%m-%d").replace(tzinfo=UTC)).days
    except ValueError:
        return None


# (check id, title, severity, NIST AI RMF function, remediation, test(asset) -> bool)
CHECKS = [
    ("shadow_ai", "Unapproved AI asset (shadow AI)", "high", "GOVERN", "Review it, then approve it into the inventory or remove it.", lambda a: not a["approved"]),
    ("no_owner", "No named owner", "medium", "GOVERN", "Assign an accountable owner.", lambda a: not (a.get("owner") or "").strip()),
    ("exposed_no_guardrail", "Internet-facing without a guardrail", "critical", "MANAGE", "Route it through the AI gateway with block mode.", lambda a: a["asset_type"] in GUARDED and a["internet_exposed"] and not a["guardrail"]),
    ("vector_db_exposed", "Vector store reachable from the internet", "critical", "MANAGE", "Move it to a private network and require authentication.", lambda a: a["asset_type"] == "vector_db" and a["internet_exposed"]),
    ("agent_no_approval", "Tool-using agent without human approval", "high", "MANAGE", "Require approval for destructive or external actions.", lambda a: (a["asset_type"] in ("agent", "mcp_server") or a["tool_access"]) and not a["human_approval"]),
    ("sensitive_no_guardrail", "Sensitive data without a guardrail", "high", "MANAGE", "Enable the guardrail and redaction for this asset.", lambda a: a["asset_type"] in GUARDED and (a["handles_pii"] or a["data_classification"] in ("confidential", "restricted")) and not a["guardrail"]),
    ("unsafe_format", "Model stored in an unsafe format (pickle)", "high", "MAP", "Convert to safetensors and scan before loading.", lambda a: a["model_format"] == "pickle"),
    ("no_logging_prod", "Production asset without logging", "medium", "MEASURE", "Turn on request logging so activity can be investigated.", lambda a: a["environment"] == "prod" and a["asset_type"] in GUARDED + ("mcp_server",) and not a["logging_enabled"]),
    ("stale_review", "Not reviewed in the last 180 days", "low", "GOVERN", "Re-review the asset and record the date.", lambda a: (_days_since(a.get("last_reviewed")) is None) or _days_since(a.get("last_reviewed")) > 180),
]


def posture(tenant_id: str, record_history: bool = True) -> dict:
    assets = ai.list_assets(tenant_id)
    findings: List[dict] = []
    for a in assets:
        for cid, title, sev, fn, fix, test in CHECKS:
            try:
                hit = bool(test(a))
            except Exception:
                hit = False
            if hit:
                findings.append({"key": f"{a['id']}:{cid}", "check": cid, "title": title, "severity": sev, "function": fn, "remediation": fix,
                                 "asset_id": a["id"], "asset_name": a["name"], "asset_type": a["asset_type"]})
    since = _ts(_now() - timedelta(days=30))
    with closing(get_db()) as conn:
        leaks = {r["app"].lower(): r["n"] for r in conn.execute("SELECT app, COUNT(*) n FROM ai_events WHERE tenant_id=? AND created_at>=? AND verdict='block' AND categories LIKE '%LLM02%' GROUP BY app", (tenant_id, since)).fetchall()}
        shadow_svc = conn.execute("SELECT COUNT(DISTINCT e.service_id) c FROM ai_discovery_events e LEFT JOIN ai_service_policy p ON p.tenant_id=e.tenant_id AND p.service_id=e.service_id "
                                  "WHERE e.tenant_id=? AND e.created_at>=? AND COALESCE(p.status,'unreviewed') IN ('unreviewed','unsanctioned')", (tenant_id, since)).fetchone()["c"]
        exc = {r["finding_key"]: dict(r) for r in conn.execute("SELECT finding_key, reason, accepted_by, accepted_at FROM ai_posture_exceptions WHERE tenant_id=?", (tenant_id,)).fetchall()}
    for a in assets:
        n = leaks.get(a["name"].lower(), 0)
        if n:
            findings.append({"key": f"{a['id']}:secrets_in_traffic", "check": "secrets_in_traffic", "title": f"Secrets or personal data seen in its traffic ({n} blocked in 30 days)", "severity": "high",
                             "function": "MEASURE", "remediation": "Rotate what was exposed and enforce redaction at the gateway.", "asset_id": a["id"], "asset_name": a["name"], "asset_type": a["asset_type"]})
    if shadow_svc:
        findings.append({"key": "tenant:shadow_services", "check": "shadow_services", "title": f"{shadow_svc} unreviewed or unsanctioned AI service(s) in use", "severity": "high" if shadow_svc >= 3 else "medium",
                         "function": "GOVERN", "remediation": "Review them under AI Discovery: sanction, tolerate or block.", "asset_id": None, "asset_name": "Organisation", "asset_type": "tenant"})
    rt = ai.latest_redteam(tenant_id)
    if not rt or rt["detection_rate"] < 90:
        findings.append({"key": "tenant:guardrail_efficacy", "check": "guardrail_efficacy", "title": "Guardrail not validated" if not rt else f"Guardrail detection rate is {rt['detection_rate']}%",
                         "severity": "medium", "function": "MEASURE", "remediation": "Run the red-team suite and close the gaps it reports.", "asset_id": None, "asset_name": "Organisation", "asset_type": "tenant"})
    for f in findings:
        f["status"] = "accepted" if f["key"] in exc else "open"
        f["exception"] = exc.get(f["key"])
    open_f = [f for f in findings if f["status"] == "open"]
    score = max(0, 100 - sum(SEV_POINTS[f["severity"]] for f in open_f))
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 55 else "D" if score >= 35 else "F"
    by_fn = {k: sum(1 for f in open_f if f["function"] == k) for k in ("GOVERN", "MAP", "MEASURE", "MANAGE")}
    today = _now().strftime("%Y-%m-%d")
    with closing(get_db()) as conn:
        if record_history:
            conn.execute("INSERT OR REPLACE INTO ai_posture_history (tenant_id, day, score) VALUES (?,?,?)", (tenant_id, today, score))
            conn.commit()
        hist = [dict(r) for r in conn.execute("SELECT day, score FROM ai_posture_history WHERE tenant_id=? ORDER BY day DESC LIMIT 30", (tenant_id,)).fetchall()][::-1]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (f["status"] != "open", order[f["severity"]], f["asset_name"]))
    return {"score": score, "grade": grade, "findings": findings, "by_function": by_fn, "history": hist, "assets": len(assets),
            "counts": {s: sum(1 for f in open_f if f["severity"] == s) for s in ("critical", "high", "medium", "low")}, "accepted": sum(1 for f in findings if f["status"] == "accepted")}


def accept_risk(tenant_id: str, key: str, reason: str, actor: str) -> dict:
    reason = (reason or "").strip()
    if len(reason) < 10:
        raise ai.AIError(400, "Explain why the risk is accepted (at least 10 characters)")
    if key not in {f["key"] for f in posture(tenant_id, record_history=False)["findings"]}:
        raise ai.AIError(404, "Finding not found")
    with closing(get_db()) as conn:
        conn.execute("INSERT OR REPLACE INTO ai_posture_exceptions (tenant_id, finding_key, reason, accepted_by, accepted_at) VALUES (?,?,?,?,?)", (tenant_id, key, reason[:300], actor, _ts(_now())))
        conn.commit()
    return {"key": key}


def revoke_acceptance(tenant_id: str, key: str) -> None:
    with closing(get_db()) as conn:
        cur = conn.execute("DELETE FROM ai_posture_exceptions WHERE tenant_id=? AND finding_key=?", (tenant_id, key))
        conn.commit()
        if cur.rowcount != 1:
            raise ai.AIError(404, "No accepted risk with that key")


def aibom(tenant_id: str) -> dict:
    """AI bill of materials in a CycloneDX-style layout (components of type machine-learning-model / application / data)."""
    ctype = {"model": "machine-learning-model", "agent": "application", "app": "application", "mcp_server": "application", "vector_db": "data", "dataset": "data", "api_key": "data"}
    comps = []
    for a in ai.list_assets(tenant_id):
        if a["asset_type"] == "api_key":
            continue                                           # credentials are never exported
        comps.append({"type": ctype[a["asset_type"]], "bom-ref": a["id"], "name": a["name"], "supplier": {"name": a["provider"] or "unknown"},
                      "properties": [{"name": f"trustaira:{k}", "value": str(v)} for k, v in (("asset_type", a["asset_type"]), ("environment", a["environment"]), ("data_classification", a["data_classification"]),
                                                                                              ("model_format", a["model_format"]), ("approved", bool(a["approved"])), ("risk_score", a["risk"]["score"]), ("owner", a["owner"] or "none"))]})
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
            "metadata": {"timestamp": _ts(_now()).replace(" ", "T") + "Z", "tools": [{"name": "TrustAira AI-SPM"}]}, "components": comps}


# =====================================================================
# 3. AI GATEWAY
# =====================================================================
MODES = ("monitor", "redact", "block")
DEFAULT_POLICY = {"mode": "redact", "block_threshold": 75, "max_chars": 12000, "rate_per_min": 30, "allowed_models": ""}


def get_policy(tenant_id: str, app: str) -> dict:
    with closing(get_db()) as conn:
        row = conn.execute("SELECT * FROM ai_gateway_policies WHERE tenant_id=? AND app=?", (tenant_id, app)).fetchone() or \
              conn.execute("SELECT * FROM ai_gateway_policies WHERE tenant_id=? AND app='*'", (tenant_id,)).fetchone()
    p = dict(row) if row else {**DEFAULT_POLICY, "app": "*"}
    p["allowed_models"] = [m.strip() for m in (p.get("allowed_models") or "").split(",") if m.strip()]
    return p


def list_policies(tenant_id: str) -> List[dict]:
    with closing(get_db()) as conn:
        rows = [dict(r) for r in conn.execute("SELECT * FROM ai_gateway_policies WHERE tenant_id=? ORDER BY app", (tenant_id,)).fetchall()]
    if not any(r["app"] == "*" for r in rows):
        rows.insert(0, {"tenant_id": tenant_id, "app": "*", **DEFAULT_POLICY, "updated_by": "default", "updated_at": None})
    for r in rows:
        r["allowed_models"] = [m.strip() for m in (r.get("allowed_models") or "").split(",") if m.strip()]
    return rows


def set_policy(tenant_id: str, app: str, data: dict, actor: str) -> dict:
    app = (app or "").strip()
    if not (app == "*" or 2 <= len(app) <= 80):
        raise ai.AIError(400, "app must be '*' or 2 to 80 characters")
    mode = data.get("mode", "redact")
    if mode not in MODES:
        raise ai.AIError(400, f"mode must be one of: {', '.join(MODES)}")
    thr, mx, rate = int(data.get("block_threshold", 75)), int(data.get("max_chars", 12000)), int(data.get("rate_per_min", 30))
    if not (20 <= thr <= 100 and 100 <= mx <= 200000 and 1 <= rate <= 10000):
        raise ai.AIError(400, "block_threshold 20-100, max_chars 100-200000, rate_per_min 1-10000")
    models = ",".join(m.strip() for m in (data.get("allowed_models") or []) if m.strip())[:400]
    with closing(get_db()) as conn:
        conn.execute("INSERT OR REPLACE INTO ai_gateway_policies (tenant_id, app, mode, block_threshold, max_chars, rate_per_min, allowed_models, updated_by, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                     (tenant_id, app, mode, thr, mx, rate, models, actor, _ts(_now())))
        conn.commit()
    return {"app": app, "mode": mode}


def delete_policy(tenant_id: str, app: str) -> None:
    if app == "*":
        raise ai.AIError(400, "The default policy cannot be removed")
    with closing(get_db()) as conn:
        cur = conn.execute("DELETE FROM ai_gateway_policies WHERE tenant_id=? AND app=?", (tenant_id, app))
        conn.commit()
        if cur.rowcount != 1:
            raise ai.AIError(404, "Policy not found")


async def _forward(model: str, messages: List[dict], max_tokens: int) -> Optional[dict]:
    """Calls the configured upstream LLM (OpenAI-compatible or Anthropic). None when no provider is configured."""
    async with httpx.AsyncClient(timeout=30.0) as client:
        if settings.OPENAI_API_KEY:
            r = await client.post("https://api.openai.com/v1/chat/completions", headers={"Authorization": f"Bearer {settings.OPENAI_API_KEY}"},
                                  json={"model": model or "gpt-4o-mini", "messages": messages, "max_tokens": max_tokens})
            r.raise_for_status()
            return {"text": r.json()["choices"][0]["message"]["content"], "model": model or "gpt-4o-mini"}
        if settings.GROQ_API_KEY:
            r = await client.post("https://api.groq.com/openai/v1/chat/completions", headers={"Authorization": f"Bearer {settings.GROQ_API_KEY}"},
                                  json={"model": model or "llama-3.3-70b-versatile", "messages": messages, "max_tokens": max_tokens})
            r.raise_for_status()
            return {"text": r.json()["choices"][0]["message"]["content"], "model": model or "llama-3.3-70b-versatile"}
        if settings.ANTHROPIC_API_KEY:
            sys_txt = " ".join(m["content"] for m in messages if m["role"] == "system")
            r = await client.post("https://api.anthropic.com/v1/messages", headers={"x-api-key": settings.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01"},
                                  json={"model": model or "claude-3-5-haiku-latest", "max_tokens": max_tokens, "system": sys_txt, "messages": [m for m in messages if m["role"] != "system"]})
            r.raise_for_status()
            return {"text": r.json()["content"][0]["text"], "model": model or "claude-3-5-haiku-latest"}
    return None


async def gateway_chat(tenant_id: str, app: str, user_id: str, model: str, messages: List[dict], max_tokens: int = 512, forward=None) -> dict:
    t0 = time.time()
    forward = forward or _forward
    pol = get_policy(tenant_id, app)
    terms = ai.list_terms(tenant_id)
    now = _now()
    msgs = [{"role": m.get("role", "user") if m.get("role") in ("system", "user", "assistant", "tool") else "user", "content": str(m.get("content", ""))} for m in messages][:50]
    prompt_text = "\n".join(m["content"] for m in msgs if m["role"] in ("user", "tool"))
    out = {"app": app, "mode": pol["mode"], "blocked": False, "forwarded": False, "redactions": 0, "response": None, "reason": None, "model": model}

    def finish(verdict="allow", risk=0, cats=None, incident_id=None, reason=None, blocked=False, forwarded=False, redactions=0):
        ms = int((time.time() - t0) * 1000)
        with closing(get_db()) as conn:
            conn.execute("INSERT INTO ai_gateway_requests (tenant_id, created_at, app, user_id, model, mode, verdict, blocked, redactions, latency_ms, forwarded, prompt_chars, reason) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                         (tenant_id, _ts(now), app, (user_id or "")[:80], (model or "")[:80], pol["mode"], verdict, 1 if blocked else 0, redactions, ms, 1 if forwarded else 0, len(prompt_text), reason))
            conn.commit()
        out.update(blocked=blocked, forwarded=forwarded, redactions=redactions, reason=reason, verdict=verdict, risk=risk, categories=cats or [], incident_id=incident_id, latency_ms=ms, allowed=not blocked)
        return out

    # hard limits first: they are cheap and do not need inspection
    if pol["allowed_models"] and model not in pol["allowed_models"]:
        return finish("block", 100, [], reason=f"Model '{model}' is not on this application's allow-list", blocked=True)
    if len(prompt_text) > pol["max_chars"]:
        return finish("block", 60, ["LLM10"], reason=f"Prompt is longer than the {pol['max_chars']} character limit", blocked=True)
    with closing(get_db()) as conn:
        recent = conn.execute("SELECT COUNT(*) c FROM ai_gateway_requests WHERE tenant_id=? AND app=? AND user_id=? AND created_at>=?", (tenant_id, app, (user_id or "")[:80], _ts(now - timedelta(seconds=60)))).fetchone()["c"]
    if recent >= pol["rate_per_min"]:
        return finish("block", 50, ["LLM10"], reason=f"Rate limit of {pol['rate_per_min']} requests per minute reached", blocked=True)

    res = ai.inspect_text(prompt_text, "prompt", terms)
    over = res["verdict"] == "block" or res["risk"] >= pol["block_threshold"]
    ev = ai.ingest_event(tenant_id, app, prompt_text, "prompt", user_id, model, raise_incident=(pol["mode"] == "block" and over))
    if pol["mode"] == "block" and over:
        return finish(res["verdict"], res["risk"], res["categories"], ev.get("incident_id"), reason="Blocked by the prompt guardrail: " + ", ".join(f["name"] for f in res["findings"][:3]), blocked=True)

    n_red = 0
    send = msgs
    if pol["mode"] in ("redact", "block"):
        send = []
        for m in msgs:
            c = m["content"]
            red = ai.redact_terms(ai.redact(c), terms) if m["role"] in ("user", "tool") else c
            n_red += len(re.findall(r"\[REDACTED:", red)) - len(re.findall(r"\[REDACTED:", c))
            send.append({**m, "content": red})
    try:
        up = await forward(model, send, max_tokens)
    except Exception as exc:                                    # an upstream failure must not look like a guardrail decision
        return finish(res["verdict"], res["risk"], res["categories"], ev.get("incident_id"), reason=f"Upstream error: {type(exc).__name__}", redactions=n_red)
    if up is None:
        out["note"] = "No upstream model is configured. The request was inspected and logged only."
        return finish(res["verdict"], res["risk"], res["categories"], ev.get("incident_id"), redactions=n_red)
    out["model"], text = up.get("model", model), up["text"]
    rres = ai.inspect_text(text, "response", terms)
    ai.ingest_event(tenant_id, app, text, "response", user_id, out["model"], raise_incident=(pol["mode"] == "block" and rres["verdict"] == "block"))
    if pol["mode"] == "block" and (rres["verdict"] == "block" or rres["risk"] >= pol["block_threshold"]):
        return finish("block", max(res["risk"], rres["risk"]), sorted(set(res["categories"]) | set(rres["categories"])), reason="The model's answer was withheld by the response guardrail: " + ", ".join(f["name"] for f in rres["findings"][:3]),
                      blocked=True, forwarded=True, redactions=n_red)
    if pol["mode"] in ("redact", "block"):
        clean = ai.redact_terms(ai.redact(text), terms)
        n_red += len(re.findall(r"\[REDACTED:", clean)) - len(re.findall(r"\[REDACTED:", text))
        text = clean
    out["response"] = text
    return finish(res["verdict"] if res["verdict"] != "allow" else rres["verdict"], max(res["risk"], rres["risk"]), sorted(set(res["categories"]) | set(rres["categories"])), ev.get("incident_id"), forwarded=True, redactions=n_red)


def gateway_stats(tenant_id: str, hours: int = 24) -> dict:
    since = _ts(_now() - timedelta(hours=max(1, min(hours, 720))))
    with closing(get_db()) as conn:
        t = conn.execute("SELECT COUNT(*) n, COALESCE(SUM(blocked),0) blocked, COALESCE(SUM(CASE WHEN redactions>0 THEN 1 ELSE 0 END),0) redacted, COALESCE(AVG(latency_ms),0) lat FROM ai_gateway_requests WHERE tenant_id=? AND created_at>=?", (tenant_id, since)).fetchone()
        apps = [dict(r) for r in conn.execute("SELECT app, COUNT(*) requests, SUM(blocked) blocked, SUM(CASE WHEN redactions>0 THEN 1 ELSE 0 END) redacted, ROUND(AVG(latency_ms)) avg_ms FROM ai_gateway_requests WHERE tenant_id=? AND created_at>=? GROUP BY app ORDER BY requests DESC LIMIT 20", (tenant_id, since)).fetchall()]
    return {"requests": t["n"], "blocked": t["blocked"], "redacted": t["redacted"], "avg_latency_ms": round(t["lat"]), "apps": apps}


# ---------- demo sample data ----------
def seed_demo_cloud(tenant_id: str) -> None:
    with closing(get_db()) as conn:
        if conn.execute("SELECT 1 FROM ai_discovery_events WHERE tenant_id=? LIMIT 1", (tenant_id,)).fetchone():
            return
    plan = [("chatgpt.com", "j.silva", "LAPTOP-114", 4_200_000, 20, ""), ("chatgpt.com", "m.khan", "LAPTOP-207", 18_000_000, 30, ""), ("chatgpt.com", "t.ahmed", "LAPTOP-031", 61_000_000, 8, ""),
            ("claude.ai", "j.silva", "LAPTOP-114", 900_000, 12, ""), ("claude.ai", "r.das", "LAPTOP-099", 2_300_000, 40, ""),
            ("api.openai.com", "svc-reporting", "SRV-APP-02", 95_000_000, 6, ""), ("huggingface.co", "dev-12", "LAPTOP-310", 340_000_000, 48, ""),
            ("github.com", "dev-12", "LAPTOP-310", 1_000, 5, ""), ("deepseek.com", "m.khan", "LAPTOP-207", 7_500_000, 3, ""),
            ("otter.ai", "s.ali", "LAPTOP-052", 220_000_000, 26, ""), ("midjourney.com", "mkt-03", "LAPTOP-441", 12_000_000, 60, ""),
            ("perplexity.ai", "r.das", "LAPTOP-099", 400_000, 2, ""), ("my-genai-notes.example.net", "s.ali", "LAPTOP-052", 3_000_000, 9, ""),
            ("chatgpt.com", "t.ahmed", "LAPTOP-031", 2_000_000, 2, "Here is the prod config: aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY and password=Prod-DB-2026!")]
    for host, user, dev, nbytes, hours, text in plan:
        record_discovery(tenant_id, user, dev, host, nbytes, text, created=_now() - timedelta(hours=hours, minutes=zlib.crc32((user + host).encode()) % 50), is_demo=True)
    set_service_status(tenant_id, "anthropic-claude", "sanctioned", "Approved enterprise plan (sample)", "system")
    set_service_status(tenant_id, "microsoft-copilot", "sanctioned", "Sample", "system")
    set_service_status(tenant_id, "deepseek", "blocked", "Sample policy: blocked", "system")
    set_service_status(tenant_id, "openai-chatgpt", "tolerated", "Sample policy: allowed with warning", "system")
