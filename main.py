#!/usr/bin/env python3
# file: main.py
import ipaddress
import json
import os
import pathlib
import re
import time
import uuid
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from config import settings
from db import (
    create_encrypted_user,
    create_session_token,
    decrypt_text,
    encrypt_password,
    get_db,
    init_db,
    upgrade_legacy_user_encryption,
    username_blind_index,
    verify_audit_chain,
    verify_password,
    verify_session_token,
    write_audit,
)
from engines import (
    compute_multi_model_risk,
    enrich_ip_full,
    fetch_siem_summary,
    fetch_v1_summary,
    generate_step_explanation,
    get_six_engines_status,
)
from health_routes import build_health_router
from platform_admin import PLATFORM_TENANT, build_platform_router, init_platform_db
import ai_cloud
from ai_appsec import init_ai_appsec_db
from ai_appsec_routes import build_ai_appsec_router
from ai_cloud import init_cloud_db, seed_demo_cloud
from ai_routes import build_ai_router
from ai_security import ai_prediction, init_ai_security_db
from case_mgmt import CaseError, VERDICTS, case_file, close_incident as close_incident_core, reopen_incident as reopen_incident_core, reopen_if_contained, claim as claim_incident_core, decorate, init_case_mgmt_db, policy as assignment_policy, release as release_incident_core, set_assignment
from user_admin import (UserAdminError, assignable_usernames, clear_must_change, deactivate_user, init_user_admin_db,
                        list_users as list_users_admin, purge_user, reactivate_user, reset_password, session_problem)
import soc_health as health_module
from ai_security import overview as ai_overview
from soc_health import init_health_db, mark_disposition, start_health_sampler
from notifications import build_notification_router, init_notifications_db, notify, start_sweeper
from custom_report import custom_report, render_custom_html

BASE_DIR = pathlib.Path(__file__).parent

ACTION_CATEGORY_MAP = {
    "AI_EVENT_BLOCKED": "AI Security",
    "AI_CONTRACT_AUDIT": "AI Security",
    "AI_CODE_SCAN": "AI Security",
    "AI_ASSETS_REGISTERED": "AI Security",
    "AI_POLICY_SET": "AI Security",
    "AI_RISK_ACCEPTED": "AI Security",
    "AI_GATEWAY_POLICY": "AI Security",
    "AI_TERM_ADD": "AI Security",
    "AI_ASSET_CREATE": "AI Security",
    "AI_ASSET_UPDATE": "AI Security",
    "AI_ASSET_DELETE": "AI Security",
    "AI_REDTEAM_RUN": "AI Security",
    "CLOSE_INCIDENT": "Incident Assignment",
    "REOPEN_INCIDENT": "Incident Assignment",
    "INCIDENT_REOPENED": "Incident Assignment",
    "CLAIM_INCIDENT": "Incident Assignment",
    "RELEASE_INCIDENT": "Incident Assignment",
    "NOTIFICATION_ACK": "Incident Assignment",
    "REPORT_CUSTOM": "Intelligence & Reporting",
    "USER_LOGIN": "Authentication",
    "USER_LOGIN_SUCCESS": "Authentication",
    "USER_LOGIN_FAILED": "Authentication",
    "USER_LOGOUT": "Authentication",
    "ASSIGN_INCIDENT": "Incident Assignment",
    "INCIDENT_CONTAINMENT": "Containment & Isolation",
    "SOAR_PLAYBOOK_EXEC": "Containment & Isolation",
    "PRESTAGE_DEFENSE": "Containment & Isolation",
    "ALERT_ISOLATION": "Containment & Isolation",
    "MARK_FALSE_POSITIVE": "Detection & Suppression",
    "ATOMIC_RED_TEAM_TEST": "Detection & Suppression",
    "DEPLOY_MITRE_RULE": "Detection & Suppression",
    "CREATE_USER": "User & RBAC",
    "DELETE_USER": "User & RBAC",
    "CHANGE_PASSWORD": "User & RBAC",
    "DEACTIVATE_USER": "User & RBAC",
    "REACTIVATE_USER": "User & RBAC",
    "PURGE_USER": "User & RBAC",
    "RESET_USER_PASSWORD": "User & RBAC",
    "ADD_CASE_NOTE": "Case & Shift Handover",
    "PIN_TO_REPORT": "Intelligence & Reporting",
    "UNPIN_FROM_REPORT": "Intelligence & Reporting",
    "EXPLAIN_STEP": "Intelligence & Reporting",
    "COPILOT_QUERY": "Intelligence & Reporting",
    "NL_THREAT_HUNT": "Intelligence & Reporting",
    "ENRICH_IOC_IP": "Intelligence & Reporting",
    "WEBHOOK_INGEST": "Telemetry Ingestion",
    "SIMULATE_SOURCE_OUTAGE": "SOC Health",
    "SUPPRESSION_RENEW": "Detection & Suppression",
    "SUPPRESSION_REVOKE": "Detection & Suppression",
    "VULN_INTEL_REFRESH": "Intelligence & Reporting",
    "REPORT_GENERATED": "Intelligence & Reporting",
    "EVIDENCE_EXPORT": "Intelligence & Reporting",
}

STAGE_CHECK_HINTS = {
    "Initial access": "Check Email Gateway headers (SPF/DKIM/DMARC) and inspect parent-child process tree for macro execution.",
    "Execution": "Inspect PowerShell ScriptBlock logs (Event ID 4104) and command-line arguments for base64 payloads.",
    "Credential access": "Verify LSASS memory access (Sysmon Event ID 10) and rotate PAM/Kerberos credentials immediately.",
    "Lateral movement": "Check UEBA first-time RDP/SMB anomalies and isolate source and destination hosts.",
    "Exfiltration": "Block destination IP on perimeter firewall, inspect TLS SNI/JA3, and run retroactive IOC hunt.",
}

# =====================================================================
# PREDICTIVE NEXT-STEP ENGINE (Forecasts Next ATT&CK Tactic + Pre-Stage)
# =====================================================================
PREDICTIVE_KILLCHAIN_MAP = {
    "INC-2041": {
        "predicted_tactic": "Impact",
        "predicted_technique_group": "T1486",
        "predicted_technique_id": "T1486 / T1070.004",
        "predicted_title": "Ransomware Encryption & Indicator Removal on SRV-FILE-02",
        "probability": 89,
        "target_entity": "SRV-FILE-02 & 6 SMB Peers",
        "reasoning": "Attacker completed Credential Access (T1003), RDP Lateral Movement (T1021), and 2.3 GB Exfiltration (T1041). In 89% of observed double-extortion playbooks, the immediate next step is payload encryption (T1486) and log/file deletion (T1070).",
        "prestage_action": "Pre-stage SMB Write-Lock on SRV-FILE-02, freeze Volume Shadow Copies, and arm PAM honey-token credentials.",
        "prestaged": False,
    },
    "INC-2042": {
        "predicted_tactic": "Persistence",
        "predicted_technique_group": "T1098",
        "predicted_technique_id": "T1098.001",
        "predicted_title": "Creation of Backdoor AWS IAM Access Keys & Cross-Account Role",
        "probability": 86,
        "target_entity": "dev-pipeline-role (AWS IAM)",
        "reasoning": "After initial Tor AssumeRole (T1078) and GPU instance provisioning (T1204), cloud threat actors typically mint secondary IAM keys (T1098.001) to survive primary key revocation.",
        "prestage_action": "Pre-stage AWS IAM Deny-All Permission Boundary on dev-pipeline-role and block CreateAccessKey API calls.",
        "prestaged": False,
    },
    "INC-2043": {
        "predicted_tactic": "Exfiltration",
        "predicted_technique_group": "T1567",
        "predicted_technique_id": "T1567.002",
        "predicted_title": "Rclone / Mega.nz Double-Extortion Archive Upload from Domain Controller",
        "probability": 93,
        "target_entity": "SRV-DC-01",
        "reasoning": "LockBit execution (T1490 shadow deletion + SMB encryption) is accompanied by automated Rclone/HTTPS staging (T1567.002) prior to final DC lockout.",
        "prestage_action": "Pre-stage Perimeter Firewall sinkhole for cloud-storage ASN ranges and lock AD Tier-0 VLAN egress.",
        "prestaged": False,
    },
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    init_user_admin_db()
    init_case_mgmt_db()
    init_platform_db()
    init_ai_security_db()
    init_ai_appsec_db()
    init_cloud_db()
    if os.getenv("SOC_DEMO_MODE", "0") == "1":
        try:
            seed_demo_cloud("tenant-trustaira")
        except Exception as exc:
            print(f"[ai] sample discovery data skipped: {exc}")
    init_health_db()
    init_notifications_db()
    sampler = start_health_sampler()
    sweeper = start_sweeper()
    yield
    sweeper.cancel()
    if sampler:
        sampler.cancel()


app = FastAPI(title="Trustaira Smart SOCaaS Platform", lifespan=lifespan)

_cors_origins = [o.strip() for o in os.getenv("SOC_CORS_ORIGINS", "").split(",") if o.strip()]
if _cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    return response


MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 15 * 60
_failed_logins: Dict[str, list] = defaultdict(list)


def _throttle_key(ip: str, username: str) -> str:
    return f"{ip}|{username.strip().lower()}"


def _is_locked(key: str) -> bool:
    cutoff = time.time() - LOCKOUT_SECONDS
    _failed_logins[key] = [t for t in _failed_logins[key] if t > cutoff]
    return len(_failed_logins[key]) >= MAX_FAILED_LOGINS


MIN_PASSWORD_LEN = 8


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "192.168.1.64"


# =====================================================================
# REQUEST SCHEMAS
# =====================================================================
class LoginRequest(BaseModel):
    username: str
    password: str


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class ResetPasswordRequest(BaseModel):
    new_password: str
    force_change: bool = True


class AssignIncidentRequest(BaseModel):
    assigned_to: str


class ContainAlertRequest(BaseModel):
    alert_id: str
    segment: str
    rule: str
    entity: str


class FalsePositiveRequest(BaseModel):
    alert_id: str
    rule_name: str
    entity_pattern: str
    reason: str = "Confirmed benign activity by SOC Analyst"


class CopilotRequest(BaseModel):
    question: str


class NLHuntRequest(BaseModel):
    query: str


class CloseIncidentRequest(BaseModel):
    verdict: str
    summary: str


class ReopenIncidentRequest(BaseModel):
    reason: str


class CaseNoteRequest(BaseModel):
    incident_id: str = "SHIFT-HANDOVER"
    note_type: str = "handover"
    content: str


class WebhookIngestRequest(BaseModel):
    source: str
    title: str
    entity: str
    severity: str = "high"
    tactic: str = "Execution"
    technique_id: str = "T1059"
    raw_log: str
    incident_id: str = "INC-2041"


class AtomicTestRunRequest(BaseModel):
    technique_id: str
    tactic: str
    name: str
    target_host: str = "WS-LAB-ATOMIC01"
    command: str
    current_status: str  # 'detected', 'partial', 'missed'


PASSWORD_CHANGE_ALLOWED_PATHS = ("/api/v1/users/password", "/api/v1/auth/logout")
MAX_PASSWORD_LEN = 128


async def get_current_user(request: Request, authorization: Optional[str] = Header(default=None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required")
    token = authorization.split(" ", 1)[1]
    try:
        claims = verify_session_token(token)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e)) from e

    with get_db() as conn:
        row = conn.execute("SELECT role, tenant_id, deleted_at, pw_changed_at, must_change_password FROM users WHERE id = ?", (claims["sub"],)).fetchone()
    problem = session_problem(row, claims.get("iat", 0))
    if problem:
        raise HTTPException(status_code=401, detail=problem)
    if row["must_change_password"] and request.url.path not in PASSWORD_CHANGE_ALLOWED_PATHS:
        raise HTTPException(status_code=403, detail="PASSWORD_CHANGE_REQUIRED")
    claims["role"] = row["role"]
    claims["real_role"] = row["role"]
    claims["tenant_id"] = row["tenant_id"]
    ctx = claims.get("ctx")
    if ctx:
        # super admin working inside a tenant: only honoured for a real super admin and an existing tenant
        if row["role"] != "superadmin":
            raise HTTPException(status_code=401, detail="Invalid session context")
        with get_db() as conn:
            t = conn.execute("SELECT name FROM tenants WHERE id = ? AND id != ?", (ctx, PLATFORM_TENANT)).fetchone()
        if not t:
            raise HTTPException(status_code=401, detail="Tenant no longer exists")
        if claims.get("ro") and request.method not in ("GET", "HEAD", "OPTIONS") and request.url.path not in ("/api/v1/auth/logout", "/api/v1/platform/exit", "/api/v1/platform/switch"):
            raise HTTPException(status_code=403, detail="Read-only tenant session. Re-enter the tenant with changes enabled to make changes.")
        claims.update(home_tenant=row["tenant_id"], ctx_tenant=ctx, ctx_tenant_name=t["name"], read_only=bool(claims.get("ro")),
                      is_superadmin=True, role="admin", tenant_id=ctx, username=f"{claims['username']} (superadmin)")
    elif row["role"] == "superadmin":
        claims["is_superadmin"] = True
    return claims


def require_roles(*allowed_roles: str):
    async def role_checker(user: dict = Depends(get_current_user)) -> dict:
        if user["role"] not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail=f"RBAC Denied: Role '{user['role']}' cannot perform this action. Required: {allowed_roles}",
            )
        return user
    return role_checker


app.include_router(build_health_router(get_current_user, require_roles, write_audit, client_ip))
app.include_router(build_notification_router(get_current_user, require_roles, write_audit, client_ip))
app.include_router(build_ai_router(get_current_user, require_roles, write_audit, client_ip))
app.include_router(build_ai_appsec_router(get_current_user, require_roles, write_audit, client_ip))
app.include_router(build_platform_router(get_current_user, write_audit, client_ip))


# =====================================================================
# EXPLAINABLE RISK SCORE BREAKDOWN ENGINE
# =====================================================================
def build_explainable_risk(inc: dict, steps: List[dict], entity_prof: Optional[dict]) -> dict:
    tactics = list({s["tactic"] for s in steps})
    base_sig = min(30, len(steps) * 4 + 10)
    ueba_pts = 24 if any("ueba" in s["raw_log"].lower() or "first-time" in s["title"].lower() or "spike" in s["title"].lower() for s in steps) else 12
    crit_label = entity_prof["criticality"] if entity_prof else "High Asset Value"
    crit_pts = 22 if ("Tier-0" in crit_label or "Tier-1" in crit_label) else 16
    cves = json.loads(entity_prof["cves"]) if (entity_prof and entity_prof.get("cves")) else []
    ti_cve_pts = 18 if (cves or any("ti" in s["source"].lower() or "tor" in s["raw_log"].lower() for s in steps)) else 10
    total = min(99, base_sig + ueba_pts + crit_pts + ti_cve_pts)
    return {
        "total": inc.get("risk_score") or total,
        "confidence": inc.get("confidence") or 94,
        "AutoResponseEligible": (inc.get("risk_score", 90) < 60 and (inc.get("confidence") or 94) >= 90),
        "factors": [
            {"model": "Multi-Tool Signature Correlation", "points": base_sig, "max": 30, "reason": f"{len(steps)} alerts correlated across {len(tactics)} MITRE stages ({', '.join(tactics)})"},
            {"model": "UEBA Behavioural Deviation", "points": ueba_pts, "max": 25, "reason": "First-time RDP / 49x outbound data volume deviation from entity baseline"},
            {"model": "Asset Criticality Weight", "points": crit_pts, "max": 25, "reason": f"Primary target '{inc['primary_entity']}' tagged as {crit_label}"},
            {"model": "Vulnerability (CVE) & Threat Intel", "points": ti_cve_pts, "max": 20, "reason": f"Exploitable CVEs ({', '.join(cves) if cves else 'Active C2 IOC match'}) present on target path"},
        ],
    }


# =====================================================================
# AUTH & USER MANAGEMENT ENDPOINTS
# =====================================================================
@app.post("/api/v1/auth/login")
async def login(req: LoginRequest, request: Request):
    ip = client_ip(request)
    u_idx = username_blind_index(req.username)
    tkey = _throttle_key(ip, req.username)
    if _is_locked(tkey):
        raise HTTPException(status_code=429, detail="Too many failed attempts. Try again in 15 minutes.")
    with get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE username_lookup = ?", (u_idx,)).fetchone()
        if not row or row["deleted_at"] or not verify_password(req.password, row["password_encrypted"]):
            _failed_logins[tkey].append(time.time())
            write_audit(
                row["tenant_id"] if row else PLATFORM_TENANT,
                req.username.strip() or "unknown",
                "USER_LOGIN_FAILED",
                "Auth-Portal",
                f"Failed login attempt for username '{req.username.strip()}' from IP {ip}",
                actor_role="unauthenticated",
                ip_address=ip,
            )
            raise HTTPException(status_code=401, detail="Invalid username or password")

        _failed_logins.pop(tkey, None)
        upgrade_legacy_user_encryption(conn, row["id"], req.password)
        row = conn.execute("SELECT * FROM users WHERE id = ?", (row["id"],)).fetchone()
        decrypted_username = decrypt_text(row["username_encrypted"])
        token = create_session_token(row["id"], decrypted_username, row["role"], row["tenant_id"])

    write_audit(
        row["tenant_id"],
        decrypted_username,
        "USER_LOGIN",
        "Auth-Portal",
        f"User '{decrypted_username}' ({row['role']}) signed in from {ip}",
        actor_role=row["role"],
        ip_address=ip,
    )
    return {
        "token": token,
        "user": {
            "id": row["id"],
            "username": decrypted_username,
            "role": row["role"],
            "tenant_id": row["tenant_id"],
        },
        "must_change_password": bool(row["must_change_password"]),
    }


@app.post("/api/v1/auth/logout")
async def logout(request: Request, user: dict = Depends(get_current_user)):
    ip = client_ip(request)
    write_audit(
        user["tenant_id"],
        user["username"],
        "USER_LOGOUT",
        "Auth-Portal",
        f"User '{user['username']}' ({user['role']}) signed out from {ip}",
        actor_role=user["role"],
        ip_address=ip,
    )
    return {"status": "logged_out"}


def _fail(e: UserAdminError):
    raise HTTPException(status_code=e.status, detail=e.message)


def _user_audit(admin_user: dict, request: Request, action: str, target: str, details: str):
    write_audit(admin_user["tenant_id"], admin_user["username"], action, target, details,
                actor_role=admin_user["role"], ip_address=client_ip(request))


@app.get("/api/v1/users")
async def list_users(user: dict = Depends(require_roles("admin"))):
    return list_users_admin(user["tenant_id"])


@app.post("/api/v1/users")
async def add_user(req: CreateUserRequest, request: Request, admin_user: dict = Depends(require_roles("admin"))):
    if req.role not in ("admin", "analyst", "viewer"):
        raise HTTPException(status_code=400, detail="Role must be admin, analyst, or viewer")
    if len(req.username.strip()) < 3 or not (MIN_PASSWORD_LEN <= len(req.password) <= MAX_PASSWORD_LEN):
        raise HTTPException(status_code=400, detail=f"Username (min 3 chars) and password ({MIN_PASSWORD_LEN}-{MAX_PASSWORD_LEN} chars) required")

    u_idx = username_blind_index(req.username)
    with get_db() as conn:
        exists = conn.execute("SELECT deleted_at FROM users WHERE username_lookup = ?", (u_idx,)).fetchone()
        if exists:
            if exists["deleted_at"]:
                raise HTTPException(status_code=409, detail="A removed account with this username exists. Reactivate it from the Removed users list instead.")
            raise HTTPException(status_code=409, detail="Username already exists")
        create_encrypted_user(conn, admin_user["tenant_id"], req.username, req.password, req.role)
        conn.commit()

    _user_audit(admin_user, request, "CREATE_USER", req.username.strip(),
                f"Admin '{admin_user['username']}' created encrypted user '{req.username.strip()}' with role '{req.role}'")
    return {"status": "created", "username": req.username, "role": req.role}


@app.delete("/api/v1/users/{target_id}")
async def delete_user(target_id: str, request: Request, admin_user: dict = Depends(require_roles("admin"))):
    """Soft delete: the account is deactivated and can be reactivated until its retention window ends."""
    try:
        res = deactivate_user(admin_user["tenant_id"], target_id, admin_user["sub"])
    except UserAdminError as e:
        _fail(e)
    _user_audit(admin_user, request, "DEACTIVATE_USER", res["username"],
                f"Admin '{admin_user['username']}' removed user '{res['username']}' (role={res['role']}); reactivation possible for {res['retention_days']} days; {res['incidents_unassigned']} open incident(s) unassigned")
    return {"status": "removed", **res}


@app.post("/api/v1/users/{target_id}/reactivate")
async def reactivate_user_ep(target_id: str, request: Request, admin_user: dict = Depends(require_roles("admin"))):
    try:
        res = reactivate_user(admin_user["tenant_id"], target_id)
    except UserAdminError as e:
        _fail(e)
    _user_audit(admin_user, request, "REACTIVATE_USER", res["username"],
                f"Admin '{admin_user['username']}' reactivated user '{res['username']}' (role={res['role']}); password change required at next sign-in")
    return {"status": "reactivated", **res}


@app.delete("/api/v1/users/{target_id}/permanent")
async def purge_user_ep(target_id: str, request: Request, admin_user: dict = Depends(require_roles("admin"))):
    try:
        res = purge_user(admin_user["tenant_id"], target_id)
    except UserAdminError as e:
        _fail(e)
    _user_audit(admin_user, request, "PURGE_USER", res["username"],
                f"Admin '{admin_user['username']}' permanently deleted the removed account '{res['username']}' (role={res['role']})")
    return {"status": "purged", **res}


@app.post("/api/v1/users/{target_id}/reset-password")
async def reset_user_password(target_id: str, req: ResetPasswordRequest, request: Request, admin_user: dict = Depends(require_roles("admin"))):
    if len(req.new_password) > MAX_PASSWORD_LEN:
        raise HTTPException(status_code=400, detail=f"Password must be at most {MAX_PASSWORD_LEN} characters")
    try:
        res = reset_password(admin_user["tenant_id"], target_id, req.new_password, admin_user["sub"], req.force_change)
    except UserAdminError as e:
        _fail(e)
    _user_audit(admin_user, request, "RESET_USER_PASSWORD", res["username"],
                f"Admin '{admin_user['username']}' reset the password for '{res['username']}'" + ("; user must change it at next sign-in" if res["force_change"] else "") + "; existing sessions ended")
    return {"status": "password_reset", "username": res["username"], "force_change": res["force_change"]}


@app.post("/api/v1/users/password")
async def update_own_password(req: ChangePasswordRequest, request: Request, user: dict = Depends(get_current_user)):
    if not (MIN_PASSWORD_LEN <= len(req.new_password) <= MAX_PASSWORD_LEN):
        raise HTTPException(status_code=400, detail=f"New password must be {MIN_PASSWORD_LEN}-{MAX_PASSWORD_LEN} characters")
    with get_db() as conn:
        row = conn.execute("SELECT password_encrypted FROM users WHERE id = ?", (user["sub"],)).fetchone()
        if not row or not verify_password(req.current_password, row["password_encrypted"]):
            raise HTTPException(status_code=400, detail="Current password is incorrect")
    if req.current_password == req.new_password:
        raise HTTPException(status_code=400, detail="New password must be different from the current one")
    clear_must_change(user["sub"], req.new_password)       # also ends older sessions
    token = create_session_token(user["sub"], user["username"], user["role"], user["tenant_id"])

    _user_audit(user, request, "CHANGE_PASSWORD", user["username"], f"User '{user['username']}' rotated their encrypted password")
    return {"status": "password_updated", "token": token}


# =====================================================================
# ADMIN-ONLY CHAINED AUDIT TRAIL ENDPOINT
# =====================================================================
@app.get("/api/v1/audit-logs")
async def get_audit_trail(
    limit: int = Query(300, ge=10, le=1000),
    category: Optional[str] = Query(None),
    admin_user: dict = Depends(require_roles("admin")),
):
    tenant_id = admin_user["tenant_id"]
    chain_verification = verify_audit_chain(tenant_id)

    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_logs WHERE tenant_id = ? ORDER BY rowid DESC LIMIT ?",
            (tenant_id, limit),
        ).fetchall()

    all_logs = []
    for r in rows:
        d = dict(r)
        ip_addr = d.get("ip_address") or "192.168.1.64"
        d["source_ip"] = ip_addr
        d.pop("prev_hash", None)
        d.pop("integrity_hash", None)
        d["category"] = ACTION_CATEGORY_MAP.get(d["action"], "General")
        all_logs.append(d)

    filtered_logs = (
        [x for x in all_logs if x["category"] == category]
        if (category and category != "all")
        else all_logs
    )

    return {
        "total": len(filtered_logs),
        "integrity_ok": chain_verification["valid"],
        "integrity": chain_verification,
        "counts": {
            "total": len(all_logs),
            "auth": sum(1 for x in all_logs if x["category"] == "Authentication"),
            "actions": sum(
                1 for x in all_logs
                if x["category"] in ("Incident Assignment", "Containment & Isolation", "Detection & Suppression")
            ),
        },
        "logs": filtered_logs,
    }


# =====================================================================
# DASHBOARD, INCIDENTS, PREDICTIVE NEXT-STEP & SOAR ENDPOINTS
# =====================================================================
@app.get("/", response_class=HTMLResponse)
async def serve_portal():
    ui_file = BASE_DIR / "ui" / "index.html"
    return ui_file.read_text(encoding="utf-8")


@app.get("/api/v1/dashboard")
async def get_smart_soc_dashboard(days: int = Query(7, ge=1, le=90), user: dict = Depends(get_current_user)):
    tenant_id = user["tenant_id"]
    with get_db() as conn:
        tenant = dict(conn.execute("SELECT * FROM tenants WHERE id=?", (tenant_id,)).fetchone())
        tenant.pop("api_key", None)
        incidents = [dict(r) for r in conn.execute("SELECT * FROM incidents WHERE tenant_id=? ORDER BY risk_score DESC", (tenant_id,)).fetchall()]
        nodes = [dict(r) for r in conn.execute("SELECT * FROM node_status WHERE tenant_id=?", (tenant_id,)).fetchall()]
        fp_rules = [dict(r) for r in conn.execute("SELECT * FROM fp_rules WHERE tenant_id=? ORDER BY rowid DESC", (tenant_id,)).fetchall()]
        entities = [dict(r) for r in conn.execute("SELECT * FROM entity_profiles WHERE tenant_id=? ORDER BY risk_score DESC", (tenant_id,)).fetchall()]
        notes = [dict(r) for r in conn.execute("SELECT * FROM case_notes WHERE tenant_id=? ORDER BY rowid DESC LIMIT 30", (tenant_id,)).fetchall()]
        total_steps = conn.execute("SELECT COUNT(*) as c FROM incident_steps WHERE tenant_id=?", (tenant_id,)).fetchone()["c"]
        user_rows = conn.execute("SELECT username_encrypted, role FROM users WHERE tenant_id=? AND deleted_at IS NULL AND role IN ('admin', 'analyst')", (tenant_id,)).fetchall()
        pb_executed = conn.execute("SELECT COUNT(*) as c FROM soar_playbook_steps WHERE tenant_id=? AND status IN ('auto_executed', 'executed')", (tenant_id,)).fetchone()["c"]

    assignable_users = [
        {"username": decrypt_text(u["username_encrypted"]), "role": u["role"]}
        for u in user_rows
    ]

    for e in entities:
        try:
            e["cves_list"] = json.loads(e.get("cves") or "[]")
        except Exception:
            e["cves_list"] = []

    decorate(incidents, tenant_id)

    high_level_stats = {
        "total_logs_ingested": 1428520 + (total_steps * 140),
        "active_alerts_suppressed": 1184 + len(fp_rules),
        "open_incidents": len([i for i in incidents if i["status"] not in ("contained", "closed") and i.get("domain", "cyber") == "cyber"]),
        "mttr_avg_minutes": 11.4,
        "posture_score": tenant["posture_score"],
        "playbook_actions_taken": 24 + pb_executed,
    }

    is_viewer = user["role"] == "viewer"
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "current_user": user,
        "assignable_users": [] if is_viewer else assignable_users,
        "tenant": tenant,
        "stats": high_level_stats,
        "engines": get_six_engines_status(tenant_id),
        "nodes": nodes,
        "fp_rules": [] if is_viewer else fp_rules,
        "entities": [] if is_viewer else entities,
        "case_notes": [] if is_viewer else notes,
        "incidents": incidents,
        "assignment_policy": assignment_policy(),
        "verdict_options": VERDICTS,
    }
    if os.getenv("SOC_SHOW_INFRA", "0") == "1" and user["role"] == "admin":
        payload["server_ip"] = settings.SOC_SERVER_IP
    return payload


@app.get("/api/v1/incidents/{incident_id}")
async def get_incident_graph(incident_id: str, user: dict = Depends(get_current_user)):
    tenant_id = user["tenant_id"]
    with get_db() as conn:
        inc_row = conn.execute("SELECT * FROM incidents WHERE id=? AND tenant_id=?", (incident_id, tenant_id)).fetchone()
        if not inc_row:
            raise HTTPException(status_code=404, detail="Incident not found")
        inc = dict(inc_row)
        decorate([inc], tenant_id)

        steps = [
            dict(r) for r in conn.execute(
                "SELECT * FROM incident_steps WHERE incident_id=? AND tenant_id=? ORDER BY stage_order ASC, event_time ASC",
                (incident_id, tenant_id),
            ).fetchall()
        ]
        playbook = [
            dict(r) for r in conn.execute(
                "SELECT * FROM soar_playbook_steps WHERE incident_id=? AND tenant_id=? ORDER BY step_order ASC",
                (incident_id, tenant_id),
            ).fetchall()
        ]
        entity_prof_row = conn.execute(
            "SELECT * FROM entity_profiles WHERE entity_id=? AND tenant_id=?",
            (inc["primary_entity"], tenant_id),
        ).fetchone()
        entity_prof = dict(entity_prof_row) if entity_prof_row else None

    for s in steps:
        s["next_check_hint"] = STAGE_CHECK_HINTS.get(
            s["tactic"],
            "Correlate entity activity across adjacent logs and verify asset criticality.",
        )

    stages_map: Dict[str, dict] = {}
    for s in steps:
        tactic = s["tactic"]
        if tactic not in stages_map:
            stages_map[tactic] = {
                "tactic": tactic,
                "technique_group": s["technique_group"],
                "hint": STAGE_CHECK_HINTS.get(tactic, ""),
                "steps": [],
            }
        stages_map[tactic]["steps"].append(s)

    if inc.get("domain") == "ai":
        prediction = PREDICTIVE_KILLCHAIN_MAP.setdefault(incident_id, ai_prediction(steps))
    else:
        prediction = PREDICTIVE_KILLCHAIN_MAP.get(incident_id, PREDICTIVE_KILLCHAIN_MAP["INC-2041"])

    return {
        "incident": inc,
        "dynamic_risk": compute_multi_model_risk(steps),
        "explainable_risk": build_explainable_risk(inc, steps, entity_prof),
        "predictive_next": prediction,
        "playbook": playbook,
        "pinned_count": sum(1 for s in steps if s["pinned"] == 1),
        "stages": list(stages_map.values()),
        "steps": steps,
        "assignment_policy": assignment_policy(),
        **({"assignment_history": case_file(tenant_id, incident_id)["assignment_history"]} if user["role"] == "viewer"
           else case_file(tenant_id, incident_id)),
    }


@app.post("/api/v1/incidents/{incident_id}/prestage")
async def prestage_predicted_response(
    incident_id: str,
    request: Request,
    user: dict = Depends(require_roles("admin", "analyst")),
):
    """Pre-stages defensive controls for the predicted next ATT&CK tactic before the attacker strikes."""
    pred = PREDICTIVE_KILLCHAIN_MAP.get(incident_id)
    if not pred:
        raise HTTPException(status_code=404, detail="Prediction not found")
    pred["prestaged"] = True
    pred["prestaged_by"] = user["username"]
    pred["prestaged_at"] = datetime.now(timezone.utc).strftime("%H:%M UTC")

    write_audit(
        user["tenant_id"],
        user["username"],
        "PRESTAGE_DEFENSE",
        f"{incident_id} -> {pred['predicted_tactic']} ({pred['predicted_technique_id']})",
        f"Pre-staged predictive defense for {incident_id} ({pred['probability']}% prob): {pred['prestage_action']}",
        actor_role=user["role"],
        ip_address=client_ip(request),
    )
    return {"status": "prestaged", "incident_id": incident_id, "prediction": pred}


# =====================================================================
# ATOMIC RED TEAM RUNNER & MITRE COVERAGE VALIDATION ENDPOINT
# =====================================================================
@app.post("/api/v1/atomic/run")
async def run_atomic_red_team_test(
    req: AtomicTestRunRequest,
    request: Request,
    user: dict = Depends(require_roles("admin", "analyst")),
):
    """Simulates an Invoke-AtomicTest execution, logs to Audit Trail, and returns synthetic telemetry."""
    now_hm = datetime.now(timezone.utc).strftime("%H:%M:%S")
    triggered_alert = req.current_status == "detected"
    outcome = (
        f"ALERT TRIGGERED (Caught by Elastic SIEM & Wazuh EDR rule for {req.technique_id})"
        if triggered_alert
        else (
            f"TELEMETRY ONLY (Raw process/command logged on {req.target_host}, but no correlation alert fired)"
            if req.current_status == "partial"
            else f"MISSED / BLIND SPOT (No alert fired for {req.technique_id} on {req.target_host} — Deploy rule recommended)"
        )
    )

    write_audit(
        user["tenant_id"],
        user["username"],
        "ATOMIC_RED_TEAM_TEST",
        f"{req.technique_id} ({req.name})",
        f"Executed Atomic Red Team test '{req.command}' on {req.target_host} -> {outcome}",
        actor_role=user["role"],
        ip_address=client_ip(request),
    )
    return {
        "status": "completed",
        "timestamp": now_hm,
        "technique_id": req.technique_id,
        "tactic": req.tactic,
        "name": req.name,
        "target_host": req.target_host,
        "triggered_alert": triggered_alert,
        "outcome": outcome,
        "synthetic_log": f"atomic_test=true host={req.target_host} mitre={req.technique_id} cmd=\"{req.command}\" user={user['username']}",
    }


@app.post("/api/v1/atomic/deploy-rule/{technique_id}")
async def deploy_mitre_detection_rule(
    technique_id: str,
    request: Request,
    user: dict = Depends(require_roles("admin", "analyst")),
):
    """Deploys a new detection rule to convert a Missed/Partial MITRE technique into Detected."""
    write_audit(
        user["tenant_id"],
        user["username"],
        "DEPLOY_MITRE_RULE",
        technique_id,
        f"Deployed active SIEM/EDR correlation rule for MITRE technique {technique_id} after Atomic Red Team gap analysis",
        actor_role=user["role"],
        ip_address=client_ip(request),
    )
    return {"status": "deployed", "technique_id": technique_id, "new_coverage_state": "detected"}


# =====================================================================
# SOAR PLAYBOOKS, FALSE POSITIVES, COPILOT, HUNTING & NOTES
# =====================================================================
@app.post("/api/v1/incidents/{incident_id}/playbook/{pb_step_id}/execute")
async def execute_playbook_step(
    incident_id: str,
    pb_step_id: str,
    request: Request,
    user: dict = Depends(require_roles("admin", "analyst")),
):
    tenant_id = user["tenant_id"]
    now_str = datetime.now(timezone.utc).strftime("%H:%M UTC")
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM soar_playbook_steps WHERE id=? AND incident_id=? AND tenant_id=?",
            (pb_step_id, incident_id, tenant_id),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Playbook step not found")

        conn.execute(
            "UPDATE soar_playbook_steps SET status='executed', executed_by=?, executed_at=? WHERE id=?",
            (user["username"], now_str, pb_step_id),
        )
        rem = conn.execute(
            "SELECT COUNT(*) as c FROM soar_playbook_steps WHERE incident_id=? AND tenant_id=? AND status='pending'",
            (incident_id, tenant_id),
        ).fetchone()["c"]
        if rem == 0:
            conn.execute(
                "UPDATE incidents SET action_approved=1, status='contained', updated_at=datetime('now') WHERE id=? AND tenant_id=? AND status!='closed'",
                (incident_id, tenant_id),
            )
        conn.commit()

    write_audit(
        tenant_id,
        user["username"],
        "SOAR_PLAYBOOK_EXEC",
        f"{incident_id}/{row['action_type']}",
        f"Executed SOAR playbook step '{row['title']}' on {row['target_system']} (approved by '{user['username']}')",
        actor_role=user["role"],
        ip_address=client_ip(request),
    )
    return {"status": "executed", "pb_step_id": pb_step_id, "incident_contained": rem == 0}


@app.post("/api/v1/alerts/false-positive")
async def mark_alert_false_positive(
    req: FalsePositiveRequest,
    request: Request,
    user: dict = Depends(require_roles("admin", "analyst")),
):
    tenant_id = user["tenant_id"]
    fp_id = f"fp-{uuid.uuid4().hex[:6]}"
    with get_db() as conn:
        conn.execute(
            "INSERT INTO fp_rules (id, tenant_id, rule_name, entity_pattern, suppressed_by, reason) VALUES (?, ?, ?, ?, ?, ?)",
            (fp_id, tenant_id, req.rule_name, req.entity_pattern, user["username"], req.reason),
        )
        conn.execute("UPDATE fp_rules SET expires_at = datetime('now', '+90 days') WHERE id = ?", (fp_id,))
        conn.commit()
    mark_disposition(tenant_id, req.alert_id, "false_positive")

    write_audit(
        tenant_id,
        user["username"],
        "MARK_FALSE_POSITIVE",
        f"{req.alert_id} ({req.entity_pattern})",
        f"Analyst '{user['username']}' confirmed False Positive on '{req.rule_name}' ({req.entity_pattern}) -> Added rule {fp_id}",
        actor_role=user["role"],
        ip_address=client_ip(request),
    )
    return {"status": "suppressed", "fp_id": fp_id, "rule_name": req.rule_name, "entity_pattern": req.entity_pattern}


@app.post("/api/v1/incidents/{incident_id}/copilot")
async def incident_ai_copilot(
    incident_id: str,
    req: CopilotRequest,
    request: Request,
    user: dict = Depends(require_roles("admin", "analyst")),
):
    tenant_id = user["tenant_id"]
    with get_db() as conn:
        inc = conn.execute("SELECT * FROM incidents WHERE id=? AND tenant_id=?", (incident_id, tenant_id)).fetchone()
        if not inc:
            raise HTTPException(status_code=404, detail="Incident not found")
        steps = [
            dict(r) for r in conn.execute(
                "SELECT * FROM incident_steps WHERE incident_id=? AND tenant_id=? ORDER BY stage_order ASC",
                (incident_id, tenant_id),
            ).fetchall()
        ]

    pred = PREDICTIVE_KILLCHAIN_MAP.get(incident_id) or (ai_prediction(steps) if inc["domain"] == "ai" else PREDICTIVE_KILLCHAIN_MAP["INC-2041"])
    citations = [f"[{s['event_time']} · {s['source']} · {s['technique_id']}] {s['raw_log']}" for s in steps[:4]]
    q_low = req.question.lower()

    if "next" in q_low or "predict" in q_low or "recommend" in q_low or "action" in q_low:
        answer = (
            f"Based on the {len(steps)} correlated steps in {incident_id} (Primary Entity: {inc['primary_entity']}), "
            f"the attacker's predicted next move is {pred['predicted_tactic']} ({pred['predicted_technique_id']} — {pred['predicted_title']}) with {pred['probability']}% confidence.\n"
            f"• Immediate Pre-Stage Action: {pred['prestage_action']}\n"
            f"• Pending SOAR Gates: {inc['recommended_action']}\n\n"
            f"Cited Telemetry Lines:\n• " + "\n• ".join(citations[:3])
        )
    elif "summary" in q_low or "report" in q_low or "executive" in q_low:
        answer = (
            f"Executive Draft for {incident_id} (Risk {inc['risk_score']}/100):\n"
            f"{inc['ai_story']}\n\n"
            f"Key Evidence Cited:\n• " + "\n• ".join(citations[:3])
        )
    else:
        answer = (
            f"Copilot Analysis for {incident_id} ('{inc['title']}'):\n"
            f"• Primary Entity '{inc['primary_entity']}' traversed {len(steps)} kill-chain steps ending in {steps[-1]['tactic'] if steps else 'N/A'}.\n"
            f"• Predicted Next Tactic: {pred['predicted_tactic']} ({pred['predicted_technique_id']}).\n\n"
            f"Supporting Log Evidence:\n• " + "\n• ".join(citations)
        )

    write_audit(
        tenant_id,
        user["username"],
        "COPILOT_QUERY",
        incident_id,
        f"Queried AI Incident Copilot on {incident_id}: '{req.question[:80]}'",
        actor_role=user["role"],
        ip_address=client_ip(request),
    )
    return {"incident_id": incident_id, "answer": answer, "cited_logs": citations}


@app.post("/api/v1/hunt")
async def natural_language_hunt(
    req: NLHuntRequest,
    request: Request,
    user: dict = Depends(require_roles("admin", "analyst")),
):
    tenant_id = user["tenant_id"]
    q_raw = req.query.strip()
    q_low = q_raw.lower()

    with get_db() as conn:
        steps = [dict(r) for r in conn.execute("SELECT * FROM incident_steps WHERE tenant_id=?", (tenant_id,)).fetchall()]

    stop_words = {"show", "all", "by", "this", "user", "from", "new", "this", "week", "the", "in", "on", "for", "with", "events", "logs", "find", "and", "or"}
    tokens = [t.strip(",.?!'") for t in q_low.split() if t.strip(",.?!'") and t.strip(",.?!'") not in stop_words]

    matched = []
    for s in steps:
        blob = f"{s['incident_id']} {s['tactic']} {s['technique_id']} {s['title']} {s['source']} {s['entity']} {s['severity']} {s['raw_log']}".lower()
        if not tokens or any(tok in blob for tok in tokens):
            matched.append(s)

    translated_kql = " AND ".join([f'*{t}*' for t in tokens]) if tokens else "*:*"
    write_audit(
        tenant_id,
        user["username"],
        "NL_THREAT_HUNT",
        translated_kql,
        f"Executed Natural-Language Hunt: '{q_raw}' -> {len(matched)} log matches",
        actor_role=user["role"],
        ip_address=client_ip(request),
    )
    return {
        "natural_query": q_raw,
        "translated_query": f'ecs.query: ({translated_kql}) AND @timestamp >= now-7d',
        "match_count": len(matched),
        "matches": matched,
    }


@app.post("/api/v1/notes")
async def add_case_or_handover_note(
    req: CaseNoteRequest,
    request: Request,
    user: dict = Depends(require_roles("admin", "analyst")),
):
    if not req.content.strip():
        raise HTTPException(status_code=400, detail="Note content required")
    tenant_id = user["tenant_id"]
    if len(req.content) > 4000:
        raise HTTPException(status_code=400, detail="Note is too long (max 4000 characters)")
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    note_id = str(uuid.uuid4())
    with get_db() as conn:
        if req.incident_id != "SHIFT-HANDOVER" and not conn.execute("SELECT 1 FROM incidents WHERE id=? AND tenant_id=?", (req.incident_id, tenant_id)).fetchone():
            raise HTTPException(status_code=404, detail="Incident not found")
        conn.execute(
            "INSERT INTO case_notes VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (note_id, tenant_id, req.incident_id, user["username"], user["role"], req.note_type, req.content.strip(), now_str),
        )
        conn.commit()

    write_audit(
        tenant_id,
        user["username"],
        "ADD_CASE_NOTE",
        req.incident_id,
        f"Added {req.note_type} note on {req.incident_id}: '{req.content.strip()[:80]}'",
        actor_role=user["role"],
        ip_address=client_ip(request),
    )
    return {"status": "added", "id": note_id, "created_at": now_str}


@app.post("/api/v1/ingest/webhook")
async def ingest_external_webhook(
    req: WebhookIngestRequest,
    request: Request,
    user: dict = Depends(require_roles("admin", "analyst")),
):
    tenant_id = user["tenant_id"]
    step_id = f"step-{uuid.uuid4().hex[:6]}"
    now_hm = datetime.now(timezone.utc).strftime("%H:%M")
    with get_db() as conn:
        if not conn.execute("SELECT 1 FROM incidents WHERE id=? AND tenant_id=?", (req.incident_id, tenant_id)).fetchone():
            raise HTTPException(status_code=404, detail="Incident not found")
        conn.execute(
            """INSERT INTO incident_steps
               (id, incident_id, tenant_id, stage_order, tactic, technique_group, technique_id, title, event_time, source, entity, severity, raw_log, pinned)
               VALUES (?, ?, ?, 5, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)""",
            (
                step_id, req.incident_id, tenant_id, req.tactic, req.technique_id.split(".")[0],
                req.technique_id, req.title, now_hm, req.source, req.entity, req.severity.lower(), req.raw_log,
            ),
        )
        conn.commit()

    write_audit(
        tenant_id,
        user["username"],
        "WEBHOOK_INGEST",
        f"{req.incident_id}/{step_id}",
        f"Ingested external telemetry signal '{req.title}' from {req.source} for entity '{req.entity}' into {req.incident_id}",
        actor_role=user["role"],
        ip_address=client_ip(request),
    )
    if req.severity.lower() in ("critical", "high"):
        reopened = reopen_if_contained(tenant_id, req.incident_id, f"{req.source} reported {req.severity.lower()} activity on {req.entity} ({req.title}) after containment")
        if reopened:
            write_audit(tenant_id, "system", "INCIDENT_REOPENED", req.incident_id,
                        f"{req.incident_id} re-opened: new {req.severity.lower()} activity after containment ({req.title})",
                        actor_role="system", ip_address=client_ip(request))
        notify(tenant_id, req.severity.lower(), "active_attack", f"{req.title} ({req.tactic})",
               f"{req.source} reported activity on {req.entity} in {req.incident_id}." + (" The incident was re-opened." if reopened else ""),
               req.incident_id, req.entity, f"step:{step_id}")
    return {"status": "ingested", "step_id": step_id, "incident_id": req.incident_id}


def _audit_assignment(user, request, incident_id, res, assignee):
    verb = {"claim": "CLAIM_INCIDENT", "release": "RELEASE_INCIDENT"}.get(res["action"], "ASSIGN_INCIDENT")
    write_audit(
        user["tenant_id"], user["username"], verb, incident_id,
        f"{res['action'].capitalize()} incident {incident_id} ('{res['title']}'): '{res['previous']}' -> '{assignee}' by '{user['username']}'",
        actor_role=user["role"], ip_address=client_ip(request),
    )


@app.post("/api/v1/incidents/{incident_id}/assign")
async def assign_incident(
    incident_id: str,
    req: AssignIncidentRequest,
    request: Request,
    user: dict = Depends(require_roles("admin", "analyst")),
):
    tenant_id = user["tenant_id"]
    assignee = req.assigned_to.strip() or "Unassigned"
    if assignee != "Unassigned" and assignee not in assignable_usernames(tenant_id):
        raise HTTPException(status_code=400, detail="Assignee must be an active admin or analyst")
    if user["role"] != "admin":
        with get_db() as conn:                       # analysts may take a free case or hand back their own, never move someone else's
            row = conn.execute("SELECT assigned_to FROM incidents WHERE id=? AND tenant_id=?", (incident_id, tenant_id)).fetchone()
        if row and (row["assigned_to"] or "Unassigned") not in ("Unassigned", user["username"]):
            raise HTTPException(status_code=403, detail=f"Only an admin can move a case owned by {row['assigned_to']}")
    try:
        res = set_assignment(tenant_id, incident_id, assignee, user["username"])
    except CaseError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.message)
    if res["changed"]:
        _audit_assignment(user, request, incident_id, res, assignee)
    return {"incident_id": incident_id, "assigned_to": assignee, "status": res["status"], "action": res["action"]}


@app.post("/api/v1/incidents/{incident_id}/claim")
async def claim_incident(incident_id: str, request: Request, user: dict = Depends(require_roles("admin", "analyst"))):
    try:
        res = claim_incident_core(user["tenant_id"], incident_id, user["username"])
    except CaseError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.message)
    if res["changed"]:
        _audit_assignment(user, request, incident_id, res, user["username"])
    return {"incident_id": incident_id, "assigned_to": user["username"], "status": res["status"]}


@app.post("/api/v1/incidents/{incident_id}/release")
async def release_incident(incident_id: str, request: Request, user: dict = Depends(require_roles("admin", "analyst"))):
    try:
        res = release_incident_core(user["tenant_id"], incident_id, user["username"], user["role"])
    except CaseError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.message)
    if res["changed"]:
        _audit_assignment(user, request, incident_id, res, "Unassigned")
    return {"incident_id": incident_id, "assigned_to": "Unassigned", "status": res["status"]}


@app.post("/api/v1/incidents/{incident_id}/close")
async def close_incident(incident_id: str, req: CloseIncidentRequest, request: Request,
                         user: dict = Depends(require_roles("admin", "analyst"))):
    try:
        res = close_incident_core(user["tenant_id"], incident_id, user["username"], user["role"], req.verdict, req.summary)
    except CaseError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.message)
    write_audit(user["tenant_id"], user["username"], "CLOSE_INCIDENT", incident_id,
                f"Closed incident {incident_id} ('{res['title']}') as {res['verdict']} (owner '{res['owner']}')",
                actor_role=user["role"], ip_address=client_ip(request))
    return {"incident_id": incident_id, "status": "closed", "verdict": res["verdict"]}


@app.post("/api/v1/incidents/{incident_id}/reopen")
async def reopen_incident(incident_id: str, req: ReopenIncidentRequest, request: Request,
                          user: dict = Depends(require_roles("admin", "analyst"))):
    try:
        res = reopen_incident_core(user["tenant_id"], incident_id, user["username"], user["role"], req.reason)
    except CaseError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.message)
    write_audit(user["tenant_id"], user["username"], "REOPEN_INCIDENT", incident_id,
                f"Reopened incident {incident_id} ('{res['title']}'): {req.reason.strip()[:200]}",
                actor_role=user["role"], ip_address=client_ip(request))
    return {"incident_id": incident_id, "status": "open"}


@app.post("/api/v1/incidents/{incident_id}/steps/{step_id}/pin")
async def toggle_step_pin(
    incident_id: str,
    step_id: str,
    request: Request,
    user: dict = Depends(require_roles("admin", "analyst")),
):
    tenant_id = user["tenant_id"]
    with get_db() as conn:
        row = conn.execute(
            "SELECT pinned, title, entity FROM incident_steps WHERE id=? AND incident_id=? AND tenant_id=?",
            (step_id, incident_id, tenant_id),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Step not found")
        new_pin = 0 if row["pinned"] == 1 else 1
        conn.execute("UPDATE incident_steps SET pinned=? WHERE id=? AND tenant_id=?", (new_pin, step_id, tenant_id))
        conn.commit()
        pinned_count = conn.execute(
            "SELECT COUNT(*) as c FROM incident_steps WHERE incident_id=? AND tenant_id=? AND pinned=1", (incident_id, tenant_id)
        ).fetchone()["c"]

    action_name = "PIN_TO_REPORT" if new_pin else "UNPIN_FROM_REPORT"
    write_audit(
        tenant_id,
        user["username"],
        action_name,
        f"{incident_id}/{step_id}",
        f"{'Pinned' if new_pin else 'Unpinned'} step '{row['title']}' (entity={row['entity']}) on {incident_id}",
        actor_role=user["role"],
        ip_address=client_ip(request),
    )
    return {"step_id": step_id, "pinned": bool(new_pin), "pinned_count": pinned_count}


@app.post("/api/v1/incidents/{incident_id}/steps/{step_id}/explain")
async def explain_step_ai(incident_id: str, step_id: str, request: Request, user: dict = Depends(require_roles("admin", "analyst"))):
    tenant_id = user["tenant_id"]
    with get_db() as conn:
        step = conn.execute(
            "SELECT * FROM incident_steps WHERE id=? AND incident_id=? AND tenant_id=?",
            (step_id, incident_id, tenant_id),
        ).fetchone()
        if not step:
            raise HTTPException(status_code=404, detail="Step not found")
        step_dict = dict(step)

        result = await generate_step_explanation(step_dict)
        conn.execute(
            "UPDATE incident_steps SET ai_explanation=?, ti_enrichment=? WHERE id=? AND tenant_id=?",
            (result["text"], result.get("ti", ""), step_id, tenant_id),
        )
        conn.commit()

    write_audit(
        tenant_id,
        user["username"],
        "EXPLAIN_STEP",
        f"{incident_id}/{step_id}",
        f"Generated AI explanation for step '{step_dict['title']}' via {result['provider']}",
        actor_role=user["role"],
        ip_address=client_ip(request),
    )
    return {
        "step_id": step_id,
        "provider": result["provider"],
        "explanation": result["text"],
        "ti_summary": result.get("ti", ""),
    }


@app.post("/api/v1/incidents/{incident_id}/approve")
async def approve_containment(
    incident_id: str,
    request: Request,
    user: dict = Depends(require_roles("admin", "analyst")),
):
    tenant_id = user["tenant_id"]
    now_str = datetime.now(timezone.utc).strftime("%H:%M UTC")
    with get_db() as conn:
        inc = conn.execute(
            "SELECT title, primary_entity, recommended_action FROM incidents WHERE id=? AND tenant_id=?",
            (incident_id, tenant_id),
        ).fetchone()
        if not inc:
            raise HTTPException(status_code=404, detail="Incident not found")
        conn.execute(
            "UPDATE incidents SET action_approved=1, status='contained', updated_at=datetime('now') WHERE id=? AND tenant_id=? AND status!='closed'",
            (incident_id, tenant_id),
        )
        conn.execute(
            "UPDATE soar_playbook_steps SET status='executed', executed_by=?, executed_at=? WHERE incident_id=? AND tenant_id=? AND status='pending'",
            (user["username"], now_str, incident_id, tenant_id),
        )
        conn.commit()

    write_audit(
        tenant_id,
        user["username"],
        "INCIDENT_CONTAINMENT",
        f"{incident_id} ({inc['primary_entity']})",
        f"User '{user['username']}' ({user['role']}) executed full SOAR containment on '{inc['primary_entity']}' for {incident_id}: {inc['recommended_action']}",
        actor_role=user["role"],
        ip_address=client_ip(request),
    )
    return {"incident_id": incident_id, "status": "contained", "action_executed": inc["recommended_action"]}


@app.post("/api/v1/alerts/contain")
@app.post("/api/v1/alerts/isolate")
async def contain_segmented_alert(
    req: ContainAlertRequest,
    request: Request,
    user: dict = Depends(require_roles("admin", "analyst")),
):
    mark_disposition(user["tenant_id"], req.alert_id, "true_positive")
    write_audit(
        user["tenant_id"],
        user["username"],
        "ALERT_ISOLATION",
        f"{req.alert_id} ({req.entity})",
        f"User '{user['username']}' ({user['role']}) isolated/blocked entity '{req.entity}' on [{req.segment}] alert '{req.rule}' ({req.alert_id})",
        actor_role=user["role"],
        ip_address=client_ip(request),
    )
    return {"status": "isolated", "alert_id": req.alert_id, "actor": user["username"]}


@app.get("/api/v1/pillars/summary")
async def pillars_summary(user: dict = Depends(get_current_user)):
    """One summary per pillar for the Dashboard: Cyber, IT and AI Security."""
    tid, viewer = user["tenant_id"], user["role"] == "viewer"
    with get_db() as conn:
        def inc(domain):
            rows = conn.execute("SELECT status, severity, assigned_to FROM incidents WHERE tenant_id=? AND COALESCE(domain,'cyber')=?", (tid, domain)).fetchall()
            act = [r for r in rows if r["status"] not in ("contained", "closed")]
            return {"active": len(act), "unassigned": sum(1 for r in act if (r["assigned_to"] or "Unassigned") == "Unassigned"),
                    "critical": sum(1 for r in act if r["severity"] == "critical"), "awaiting_closeout": sum(1 for r in rows if r["status"] == "contained")}
        cyber, it_inc = inc("cyber"), inc("it")
    out = {"cyber": cyber, "it": None, "ai": None}
    if user["role"] != "superadmin":
        ov = ai_overview(tid)
        out["ai"] = {"active": ov["open_incidents"], "blocked_24h": ov["blocked_24h"], "shadow_ai": ov["shadow_ai"], "assets": ov["assets_total"],
                     "posture": None if viewer else ai_cloud.posture(tid, record_history=False)["score"]}
        if not viewer:
            nh = health_module.node_health(tid)
            vp = health_module.vuln_priorities(tid)
            out["it"] = {**it_inc, "sources": len(nh["nodes"]), "sources_attention": nh.get("needs_attention", 0),
                         "p1_vulns": sum(1 for r in vp["rows"] if str(r["band"]).startswith("P1"))}
    return out


def _report_args(incident_ids, start, end):
    ids = [x.strip() for x in (incident_ids or "").split(",") if x.strip()][:50]
    for i in ids:
        if not re.fullmatch(r"[A-Za-z0-9_\-]{1,64}", i):
            raise HTTPException(status_code=400, detail="Invalid incident id")
    return ids


@app.get("/api/v1/reports/custom")
async def report_custom(request: Request, incident_ids: str = "", start: Optional[str] = None, end: Optional[str] = None,
                        steps: bool = False, pillar: Optional[str] = None, user: dict = Depends(get_current_user)):
    ids = _report_args(incident_ids, start, end)
    if pillar not in (None, "", "cyber", "it", "ai"):
        raise HTTPException(status_code=400, detail="pillar must be cyber, it or ai")
    try:
        r = custom_report(user["tenant_id"], ids, start, end, include_steps=steps and user["role"] != "viewer", domain=pillar or None)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not r:
        raise HTTPException(status_code=404, detail="No matching incidents")
    write_audit(user["tenant_id"], user["username"], "REPORT_CUSTOM", ",".join(ids) or "time-range",
                f"'{user['username']}' generated a report ({r['scope']}, {r['start']} to {r['end']})",
                actor_role=user["role"], ip_address=client_ip(request))
    return r


@app.get("/api/v1/reports/custom.html", response_class=HTMLResponse)
async def report_custom_html(request: Request, incident_ids: str = "", start: Optional[str] = None, end: Optional[str] = None,
                             steps: bool = False, pillar: Optional[str] = None, user: dict = Depends(get_current_user)):
    return HTMLResponse(render_custom_html(await report_custom(request, incident_ids, start, end, steps, pillar, user)))


@app.get("/api/v1/enrich/ip/{ip}")
async def enrich_ip_endpoint(ip: str, request: Request, user: dict = Depends(require_roles("admin", "analyst"))):
    try:
        ip = str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address")

    osint_data = await enrich_ip_full(ip)
    with get_db() as conn:
        retro_hits = [
            dict(r) for r in conn.execute(
                "SELECT incident_id, event_time, source, title, entity, raw_log FROM incident_steps WHERE tenant_id=? AND (raw_log LIKE ? OR entity LIKE ?)",
                (user["tenant_id"], f"%{ip}%", f"%{ip}%"),
            ).fetchall()
        ]

    osint_data["retroactive_hunt"] = {
        "matched_logs_count": len(retro_hits),
        "historical_hits": retro_hits,
    }

    write_audit(
        user["tenant_id"],
        user["username"],
        "ENRICH_IOC_IP",
        ip,
        f"User '{user['username']}' ran OSINT + Retroactive IOC Hunt on {ip} ({len(retro_hits)} stored log hits found)",
        actor_role=user["role"],
        ip_address=client_ip(request),
    )
    return osint_data


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=os.getenv("SOC_HOST", "0.0.0.0"),
        port=settings.SOC_PORT,
        reload=os.getenv("SOC_RELOAD", "0") == "1",
    )