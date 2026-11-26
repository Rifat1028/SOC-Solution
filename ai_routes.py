# file: ai_routes.py
"""HTTP layer for ai_security.py. Wired into main.py with one include_router() call."""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

import ai_appsec as ax
import ai_cloud as cloud
import ai_security as ai
from notifications import notify


class AssetRequest(BaseModel):
    name: str
    asset_type: str
    provider: str = ""
    owner: str = ""
    environment: str = "prod"
    data_classification: str = "internal"
    model_format: str = "api"
    internet_exposed: bool = False
    tool_access: bool = False
    handles_pii: bool = False
    guardrail: bool = False
    approved: bool = True
    notes: str = ""


class InspectRequest(BaseModel):
    text: str = Field(max_length=60000)
    direction: str = "prompt"


class DiscoveryEvent(BaseModel):
    user_id: str = Field(default="", max_length=80)
    device: str = Field(default="", max_length=80)
    host: str = Field(min_length=3, max_length=255)
    bytes_out: int = Field(default=0, ge=0)
    text: str = Field(default="", max_length=20000)


class DiscoveryBatch(BaseModel):
    events: list[DiscoveryEvent] = Field(min_length=1, max_length=500)


class ServicePolicy(BaseModel):
    status: str
    note: str = Field(default="", max_length=200)


class AcceptRisk(BaseModel):
    key: str = Field(min_length=3, max_length=120)
    reason: str = Field(min_length=10, max_length=300)


class GatewayMessage(BaseModel):
    role: str = "user"
    content: str = Field(max_length=200000)


class GatewayChat(BaseModel):
    app: str = Field(min_length=2, max_length=80)
    user_id: str = Field(default="", max_length=80)
    model: str = Field(default="", max_length=80)
    messages: list[GatewayMessage] = Field(min_length=1, max_length=50)
    max_tokens: int = Field(default=512, ge=1, le=4096)


class GatewayPolicy(BaseModel):
    mode: str = "redact"
    block_threshold: int = 75
    max_chars: int = 12000
    rate_per_min: int = 30
    allowed_models: list[str] = []


class TermRequest(BaseModel):
    term: str = Field(min_length=3, max_length=80)
    severity: str = "high"
    note: str = Field(default="", max_length=200)


class EventRequest(BaseModel):
    app: str = Field(min_length=1, max_length=80)
    text: str = Field(max_length=60000)
    direction: str = "prompt"
    user_id: str = Field(default="", max_length=80)
    model: str = Field(default="", max_length=80)
    session_id: str = Field(default="", max_length=80)


def build_ai_router(get_current_user, require_roles, write_audit, client_ip) -> APIRouter:
    router = APIRouter(prefix="/api/v1/ai")
    analyst = require_roles("admin", "analyst")
    admin = require_roles("admin")

    def audit(user, request, action, target, details):
        write_audit(user["tenant_id"], user["username"], action, target, details, actor_role=user["role"], ip_address=client_ip(request))

    def guard(fn, *a, **k):
        try:
            return fn(*a, **k)
        except (ai.AIError, ax.AIAppSecError) as exc:
            raise HTTPException(status_code=exc.status, detail=exc.message)

    @router.get("/overview")
    def overview(user: dict = Depends(get_current_user)):
        return ai.overview(user["tenant_id"])

    @router.get("/coverage")
    def coverage(user: dict = Depends(get_current_user)):
        return ai.coverage(user["tenant_id"])

    @router.get("/events")
    def events(limit: int = Query(100, ge=1, le=500), verdict: str = "", user: dict = Depends(analyst)):
        return {"events": ai.list_events(user["tenant_id"], limit, verdict)}

    @router.post("/inspect")
    def inspect(req: InspectRequest, user: dict = Depends(analyst)):
        return ai.inspect_text(req.text, req.direction, ai.list_terms(user["tenant_id"]))

    @router.post("/events")
    def ingest(req: EventRequest, request: Request, user: dict = Depends(analyst)):
        res = guard(ai.ingest_event, user["tenant_id"], req.app, req.text, req.direction, req.user_id, req.model, req.session_id)
        if res["verdict"] == "block" and res["incident_id"]:
            top = res["findings"][0]
            notify(user["tenant_id"], res["severity"] if res["severity"] in ("critical", "high") else "high", "active_attack",
                   f"AI attack blocked on {req.app}: {top['name']}", f"{top['owasp']} {top['owasp_name']}; user {req.user_id or 'anonymous'}; risk {res['risk']}/100.",
                   res["incident_id"], f"{req.app}:{req.user_id or 'anonymous'}", f"ai:{res['incident_id']}:{top['owasp']}")
            audit(user, request, "AI_EVENT_BLOCKED", res["incident_id"], f"AI guardrail blocked {top['name']} on '{req.app}' (risk {res['risk']})")
        return res

    @router.get("/assets")
    def assets(user: dict = Depends(analyst)):
        return {"assets": ai.list_assets(user["tenant_id"])}

    @router.post("/assets")
    def create_asset(req: AssetRequest, request: Request, user: dict = Depends(analyst)):
        guard(ax.enforce_gate, user["tenant_id"], req.model_dump())          # no-op unless SOC_AI_GATE_ENFORCE=1
        a = guard(ai.create_asset, user["tenant_id"], req.model_dump())
        audit(user, request, "AI_ASSET_CREATE", a["id"], f"'{user['username']}' registered AI asset '{a['name']}' ({a['asset_type']})")
        return a

    @router.put("/assets/{asset_id}")
    def update_asset(asset_id: str, req: AssetRequest, request: Request, user: dict = Depends(analyst)):
        guard(ax.enforce_gate, user["tenant_id"], req.model_dump(), asset_id)  # no-op unless SOC_AI_GATE_ENFORCE=1
        a = guard(ai.update_asset, user["tenant_id"], asset_id, req.model_dump())
        audit(user, request, "AI_ASSET_UPDATE", asset_id, f"'{user['username']}' updated AI asset '{a['name']}'")
        return a

    @router.delete("/assets/{asset_id}")
    def delete_asset(asset_id: str, request: Request, user: dict = Depends(admin)):
        name = guard(ai.delete_asset, user["tenant_id"], asset_id)
        audit(user, request, "AI_ASSET_DELETE", asset_id, f"Admin '{user['username']}' removed AI asset '{name}'")
        return {"status": "deleted", "id": asset_id}

    @router.post("/redteam/run")
    def redteam_run(request: Request, user: dict = Depends(analyst)):
        res = ai.run_redteam(user["tenant_id"], user["username"])
        audit(user, request, "AI_REDTEAM_RUN", res["id"], f"'{user['username']}' ran the AI red-team suite: {res['attacks_detected']}/{res['attacks_total']} attacks detected, {res['benign_flagged']} false positive(s)")
        return res

    @router.get("/redteam/latest")
    def redteam_latest(user: dict = Depends(analyst)):
        return ai.latest_redteam(user["tenant_id"]) or {}

    # ---------- discovery / shadow AI (CASB) ----------
    @router.post("/discovery/events")
    def discovery_ingest(req: DiscoveryBatch, request: Request, user: dict = Depends(analyst)):
        out = []
        for e in req.events:
            res = cloud.record_discovery(user["tenant_id"], e.user_id, e.device, e.host, e.bytes_out, e.text)
            out.append(res)
            if res.get("incident_id"):
                notify(user["tenant_id"], "critical", "active_attack", f"Sensitive data sent to an unsanctioned AI service: {res['service']}", f"User {e.user_id or 'unknown'} on {e.device or 'unknown device'}.",
                       res["incident_id"], f"{res['service']}:{e.user_id or 'unknown'}", f"disc:{res['incident_id']}")
                audit(user, request, "AI_EVENT_BLOCKED", res["incident_id"], f"Sensitive data to unsanctioned AI service '{res['service']}' by '{e.user_id}'")
        return {"results": out, "ai_services": sum(1 for o in out if o.get("ai_service"))}

    @router.get("/discovery/summary")
    def discovery_summary(days: int = Query(30, ge=1, le=365), user: dict = Depends(analyst)):
        return cloud.discovery_summary(user["tenant_id"], days)

    @router.get("/discovery/services/{service_id}")
    def discovery_service(service_id: str, user: dict = Depends(analyst)):
        return cloud.service_detail(user["tenant_id"], service_id)

    @router.put("/discovery/policy/{service_id}")
    def discovery_policy(service_id: str, req: ServicePolicy, request: Request, user: dict = Depends(admin)):
        res = guard(cloud.set_service_status, user["tenant_id"], service_id, req.status, req.note, user["username"])
        audit(user, request, "AI_POLICY_SET", service_id, f"Admin '{user['username']}' set AI service '{service_id}' to {req.status}")
        return res

    # ---------- AI-SPM ----------
    @router.get("/posture")
    def posture(user: dict = Depends(analyst)):
        return cloud.posture(user["tenant_id"])

    @router.post("/posture/accept")
    def posture_accept(req: AcceptRisk, request: Request, user: dict = Depends(admin)):
        res = guard(cloud.accept_risk, user["tenant_id"], req.key, req.reason, user["username"])
        audit(user, request, "AI_RISK_ACCEPTED", req.key, f"Admin '{user['username']}' accepted AI posture risk {req.key}: {req.reason[:120]}")
        return res

    @router.delete("/posture/accept")
    def posture_revoke(key: str, request: Request, user: dict = Depends(admin)):
        guard(cloud.revoke_acceptance, user["tenant_id"], key)
        audit(user, request, "AI_RISK_ACCEPTED", key, f"Admin '{user['username']}' withdrew the accepted risk {key}")
        return {"status": "revoked"}

    @router.get("/aibom")
    def aibom(user: dict = Depends(analyst)):
        return cloud.aibom(user["tenant_id"])

    # ---------- gateway ----------
    @router.post("/gateway/chat")
    async def gateway_chat(req: GatewayChat, request: Request, user: dict = Depends(analyst)):
        res = await cloud.gateway_chat(user["tenant_id"], req.app, req.user_id, req.model, [m.model_dump() for m in req.messages], req.max_tokens)
        if res.get("blocked") and res.get("incident_id"):
            notify(user["tenant_id"], "high", "active_attack", f"AI gateway blocked a request to {req.app}", res.get("reason") or "", res["incident_id"], f"{req.app}:{req.user_id or 'anonymous'}", f"gw:{res['incident_id']}")
        return res

    @router.get("/gateway/stats")
    def gateway_stats(hours: int = Query(24, ge=1, le=720), user: dict = Depends(analyst)):
        return cloud.gateway_stats(user["tenant_id"], hours)

    @router.get("/gateway/policies")
    def gateway_policies(user: dict = Depends(analyst)):
        return {"policies": cloud.list_policies(user["tenant_id"])}

    @router.put("/gateway/policies/{app}")
    def gateway_policy_set(app: str, req: GatewayPolicy, request: Request, user: dict = Depends(admin)):
        res = guard(cloud.set_policy, user["tenant_id"], app, req.model_dump(), user["username"])
        audit(user, request, "AI_GATEWAY_POLICY", app, f"Admin '{user['username']}' set gateway policy for '{app}': mode {req.mode}, threshold {req.block_threshold}")
        return res

    @router.delete("/gateway/policies/{app}")
    def gateway_policy_delete(app: str, request: Request, user: dict = Depends(admin)):
        guard(cloud.delete_policy, user["tenant_id"], app)
        audit(user, request, "AI_GATEWAY_POLICY", app, f"Admin '{user['username']}' removed the gateway policy for '{app}'")
        return {"status": "deleted"}

    @router.get("/terms")
    def terms(user: dict = Depends(analyst)):
        return {"terms": ai.list_terms(user["tenant_id"])}

    @router.post("/terms")
    def term_add(req: TermRequest, request: Request, user: dict = Depends(admin)):
        res = guard(ai.add_term, user["tenant_id"], req.term, req.severity, req.note, user["username"])
        audit(user, request, "AI_TERM_ADD", res["id"], f"Admin '{user['username']}' protected a term in AI prompts (severity {req.severity})")
        return res

    @router.delete("/terms/{term_id}")
    def term_delete(term_id: str, request: Request, user: dict = Depends(admin)):
        guard(ai.delete_term, user["tenant_id"], term_id)
        audit(user, request, "AI_TERM_ADD", term_id, f"Admin '{user['username']}' removed a protected term")
        return {"status": "deleted"}

    return router
