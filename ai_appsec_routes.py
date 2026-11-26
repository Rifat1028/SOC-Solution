# file: ai_appsec_routes.py
"""HTTP routes for AI AppSec (contract audit, allow-list policy, AI code scan, approval gate).

Wired in main.py as:
    app.include_router(build_ai_appsec_router(get_current_user, require_roles, write_audit, client_ip))

Every endpoint needs the admin or analyst role, the same rule ai_routes.py uses for AI assets.
"""
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

import ai_appsec as appsec
from ai_appsec import AIAppSecError


class AuditRequest(BaseModel):
    name: str
    kind: str                      # "openapi" or "tools"
    content: str
    asset_id: Optional[str] = None


class PolicyRequest(BaseModel):
    content: str


class CheckCallRequest(BaseModel):
    policy: Any
    call: Any


class CodeFile(BaseModel):
    path: str
    content: str


class CodeScanRequest(BaseModel):
    name: str
    files: List[CodeFile]


class RegisterRequest(BaseModel):
    providers: Optional[List[str]] = None


def _run(fn, *args, **kwargs):
    """Call a service function and turn its errors into proper HTTP errors."""
    try:
        return fn(*args, **kwargs)
    except AIAppSecError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.message)
    except RecursionError:
        raise HTTPException(status_code=400, detail="The document is nested too deeply")


def build_ai_appsec_router(get_current_user, require_roles, write_audit, client_ip) -> APIRouter:
    router = APIRouter(prefix="/api/v1/ai", tags=["ai-appsec"])
    writer = require_roles("admin", "analyst")   # same access rule as ai_routes.py

    def audit(user: dict, request: Request, action: str, target: str, detail: str) -> None:
        write_audit(user["tenant_id"], user["username"], action, target, detail,
                    actor_role=user["role"], ip_address=client_ip(request))

    # ---------------- contract audit ----------------
    @router.get("/contracts")
    def contracts_list(limit: int = Query(50, ge=1, le=200), user: dict = Depends(writer)):
        return {"audits": appsec.list_audits(user["tenant_id"], limit)}

    @router.post("/contracts/audit")
    def contracts_audit(req: AuditRequest, request: Request, user: dict = Depends(writer)):
        res = _run(appsec.run_contract_audit, user["tenant_id"], req.name, req.kind, req.content, req.asset_id or None, user["username"])
        audit(user, request, "AI_CONTRACT_AUDIT", res["name"],
              f"Audited {req.kind} contract '{res['name']}': score {res['score']} ({res['grade']}), {res['counts']['critical']} critical, {res['counts']['high']} high")
        return res

    @router.post("/contracts/policy")
    def contracts_policy(req: PolicyRequest, user: dict = Depends(writer)):
        return _run(lambda: appsec.generate_policy(appsec.parse_document(req.content)))

    @router.post("/contracts/check-call")
    def contracts_check_call(req: CheckCallRequest, user: dict = Depends(writer)):
        return _run(appsec.enforce, req.policy, req.call)

    @router.get("/contracts/{audit_id}")
    def contracts_get(audit_id: str, user: dict = Depends(writer)):
        return _run(appsec.get_audit, user["tenant_id"], audit_id)

    # ---------------- AI-in-code scanner ----------------
    @router.post("/code-scan")
    def code_scan(req: CodeScanRequest, request: Request, user: dict = Depends(writer)):
        res = _run(appsec.run_code_scan, user["tenant_id"], req.name, [f.model_dump() if hasattr(f, "model_dump") else f.dict() for f in req.files], user["username"])
        audit(user, request, "AI_CODE_SCAN", res["name"],
              f"Scanned {res['files']} file(s) for AI risks: score {res['score']} ({res['grade']}), {len(res['findings'])} finding(s)")
        return res

    @router.get("/code-scans")
    def code_scans_list(limit: int = Query(50, ge=1, le=200), user: dict = Depends(writer)):
        return {"scans": appsec.list_scans(user["tenant_id"], limit)}

    @router.get("/code-scans/{scan_id}")
    def code_scans_get(scan_id: str, user: dict = Depends(writer)):
        return _run(appsec.get_scan, user["tenant_id"], scan_id)

    @router.post("/code-scans/{scan_id}/register-assets")
    def code_scans_register(scan_id: str, req: RegisterRequest, request: Request, user: dict = Depends(writer)):
        res = _run(appsec.register_components, user["tenant_id"], scan_id, req.providers)
        audit(user, request, "AI_ASSETS_REGISTERED", scan_id,
              f"Registered {len(res['created'])} AI component(s) from scan {scan_id} as unapproved assets")
        return res

    # ---------------- approval gate ----------------
    @router.get("/assets/{asset_id}/gate")
    def asset_gate(asset_id: str, user: dict = Depends(writer)):
        return _run(appsec.asset_gate, user["tenant_id"], asset_id)

    return router
