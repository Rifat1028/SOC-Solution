# file: health_routes.py
"""HTTP layer for soc_health.py. Wired into main.py with one include_router() call."""
import re

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field

import soc_health as h

SAFE_ID = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")


class HeartbeatRequest(BaseModel):
    node_id: str
    eps: float = Field(ge=0, le=10_000_000)


class OutageRequest(BaseModel):
    minutes: int = Field(default=3, ge=1, le=30)


class CheckRequest(BaseModel):
    done: bool


def _safe(value: str, what: str) -> str:
    if not SAFE_ID.match(value or ""):
        raise HTTPException(status_code=400, detail=f"Invalid {what}")
    return value


def build_health_router(get_current_user, require_roles, write_audit, client_ip) -> APIRouter:
    router = APIRouter(prefix="/api/v1")
    analyst = require_roles("admin", "analyst")
    admin = require_roles("admin")

    def audit(user, request, action, target, details):
        write_audit(user["tenant_id"], user["username"], action, target, details,
                    actor_role=user["role"], ip_address=client_ip(request))

    # ---------- 1. silent sources ----------
    @router.get("/health/sources")
    def sources(user: dict = Depends(analyst)):
        return h.node_health(user["tenant_id"])

    @router.post("/health/heartbeat")
    def heartbeat(req: HeartbeatRequest, user: dict = Depends(analyst)):
        try:
            h.record_heartbeat(user["tenant_id"], _safe(req.node_id, "node id"), req.eps)
        except KeyError:
            raise HTTPException(status_code=404, detail="Unknown node")
        return {"status": "recorded"}

    @router.post("/health/sources/{node_id}/simulate-outage")
    def outage(node_id: str, req: OutageRequest, request: Request, user: dict = Depends(admin)):
        known = {n["node_id"] for n in h.node_health(user["tenant_id"])["nodes"]}
        if node_id not in known:
            raise HTTPException(status_code=404, detail="Unknown node")
        h.simulate_outage(node_id, req.minutes)
        audit(user, request, "SIMULATE_SOURCE_OUTAGE", node_id, f"Admin '{user['username']}' simulated a {req.minutes}-minute outage on {node_id} to test silent-source detection")
        return {"status": "outage_started", "node_id": node_id, "minutes": req.minutes}

    # ---------- 2. rules + suppressions ----------
    @router.get("/health/rules")
    def rules(days: int = Query(30, ge=7, le=90), user: dict = Depends(analyst)):
        return h.rule_health(user["tenant_id"], days)

    @router.get("/health/suppressions")
    def suppressions(user: dict = Depends(analyst)):
        return h.suppression_health(user["tenant_id"])

    @router.post("/health/suppressions/{fp_id}/renew")
    def renew(fp_id: str, request: Request, user: dict = Depends(analyst)):
        if not h.renew_suppression(user["tenant_id"], _safe(fp_id, "suppression id"), user["username"]):
            raise HTTPException(status_code=404, detail="Suppression rule not found")
        audit(user, request, "SUPPRESSION_RENEW", fp_id, f"'{user['username']}' reviewed suppression {fp_id} and extended it by {h.SUPPRESSION_DAYS} days")
        return {"status": "renewed", "id": fp_id}

    @router.delete("/health/suppressions/{fp_id}")
    def revoke(fp_id: str, request: Request, user: dict = Depends(admin)):
        row = h.revoke_suppression(user["tenant_id"], _safe(fp_id, "suppression id"))
        if not row:
            raise HTTPException(status_code=404, detail="Suppression rule not found")
        audit(user, request, "SUPPRESSION_REVOKE", fp_id, f"Admin '{user['username']}' revoked suppression {fp_id} ('{row['rule_name']}' on '{row['entity_pattern']}')")
        return {"status": "revoked", "id": fp_id}

    # ---------- 4. vulnerabilities ----------
    @router.get("/exposure/priorities")
    def priorities(user: dict = Depends(get_current_user)):
        return h.vuln_priorities(user["tenant_id"])

    @router.post("/exposure/refresh-intel")
    async def refresh_intel(request: Request, user: dict = Depends(analyst)):
        res = await h.refresh_vuln_intel(user["tenant_id"])
        audit(user, request, "VULN_INTEL_REFRESH", "CISA-KEV+EPSS", f"'{user['username']}' refreshed vulnerability intel: {res['kev_loaded']} KEV, {res['epss_loaded']} EPSS, {len(res['errors'])} error(s)")
        return res

    # ---------- 6. incident quality ----------
    @router.get("/incidents/{incident_id}/quality")
    def quality(incident_id: str, user: dict = Depends(analyst)):
        tid = user["tenant_id"]
        summary = h.draft_summary(tid, _safe(incident_id, "incident id"))
        if summary is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        return {"similar": h.similar_incidents(tid, incident_id), "checklist": h.checklist_for(tid, incident_id), "summary_draft": summary}

    @router.post("/incidents/{incident_id}/checklist/{item_key}")
    def toggle_check(incident_id: str, item_key: str, req: CheckRequest, user: dict = Depends(analyst)):
        if not h.set_check(user["tenant_id"], _safe(incident_id, "incident id"), _safe(item_key, "item key"), req.done, user["username"]):
            raise HTTPException(status_code=404, detail="Checklist item or incident not found")
        return {"status": "saved", "key": item_key, "done": req.done}

    # ---------- 7. reports ----------
    @router.get("/reports/weekly")
    def report_json(days: int = Query(7, ge=1, le=90), user: dict = Depends(get_current_user)):
        return h.weekly_report(user["tenant_id"], days)

    @router.get("/reports/weekly.html", response_class=HTMLResponse)
    def report_html(request: Request, days: int = Query(7, ge=1, le=90), user: dict = Depends(get_current_user)):
        audit(user, request, "REPORT_GENERATED", f"weekly-{days}d", f"'{user['username']}' generated the {days}-day security report")
        return HTMLResponse(h.render_report_html(h.weekly_report(user["tenant_id"], days)))

    # ---------- 10. evidence ----------
    @router.get("/incidents/{incident_id}/evidence")
    def evidence(incident_id: str, request: Request, user: dict = Depends(analyst)):
        data = h.build_evidence_zip(user["tenant_id"], _safe(incident_id, "incident id"), user["username"])
        if data is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        audit(user, request, "EVIDENCE_EXPORT", incident_id, f"'{user['username']}' exported a signed evidence package for {incident_id}")
        return Response(content=data, media_type="application/zip",
                        headers={"Content-Disposition": f'attachment; filename="evidence_{incident_id}.zip"'})

    @router.get("/evidence/public-key")
    def evidence_key(user: dict = Depends(get_current_user)):
        return {"algorithm": "Ed25519", "public_key": h.public_key_hex()}

    return router
