# file: platform_admin.py
"""Platform layer for the multi-tenant SOC: the super admin portal.

* A tenant admin only ever sees their own tenant.
* A super admin belongs to the internal platform tenant, can list every tenant and switch into one.
  The switch issues a separate, signed token that carries the tenant context; it is read-only unless the
  super admin asks for changes, and every entry, exit and action is audited inside the tenant that was visited.
"""
import os
import re
import secrets
import time
import uuid
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from db import create_encrypted_user, create_session_token, encrypt_password, get_db, username_blind_index

PLATFORM_TENANT = "tenant-platform"
SUPERADMIN = "superadmin"
UTC = timezone.utc


def _ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def ensure_superadmin(username: str, password: str, reset: bool = False) -> str:
    """Creates the super admin in the platform tenant. Returns 'created', 'reset' or 'exists'.
    An existing account keeps its password unless reset=True."""
    username = (username or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.@\-]{3,64}", username):
        raise ValueError("Username may use letters, digits and _ . @ - (3 to 64 characters)")
    if len(password or "") < 8:
        raise ValueError("Password must be at least 8 characters")
    with closing(get_db()) as conn:
        if not conn.execute("SELECT 1 FROM tenants WHERE id=?", (PLATFORM_TENANT,)).fetchone():
            conn.execute("INSERT INTO tenants (id, name, api_key, posture_score) VALUES (?,?,?,0)", (PLATFORM_TENANT, "Platform Operations", secrets.token_urlsafe(24)))
        row = conn.execute("SELECT id, role, tenant_id FROM users WHERE username_lookup=?", (username_blind_index(username),)).fetchone()
        if row and (row["role"] != SUPERADMIN or row["tenant_id"] != PLATFORM_TENANT):
            raise ValueError("That username belongs to a tenant user. Choose a different name for the super admin.")
        if row and not reset:
            conn.commit()
            return "exists"
        if row:
            conn.execute("UPDATE users SET password_encrypted=?, must_change_password=0, deleted_at=NULL, pw_changed_at=? WHERE id=?",
                         (encrypt_password(password), int(time.time()), row["id"]))      # also ends any session the old password had
            conn.commit()
            return "reset"
        create_encrypted_user(conn, PLATFORM_TENANT, username, password, SUPERADMIN)
        conn.commit()
        return "created"


def init_platform_db() -> None:
    """Creates the internal platform tenant and, if configured, the first super admin."""
    with closing(get_db()) as conn:
        if not conn.execute("SELECT 1 FROM tenants WHERE id=?", (PLATFORM_TENANT,)).fetchone():
            conn.execute("INSERT INTO tenants (id, name, api_key, posture_score) VALUES (?,?,?,0)",
                         (PLATFORM_TENANT, "Platform Operations", secrets.token_urlsafe(24)))
        conn.commit()
    name = os.getenv("SOC_SUPERADMIN_USERNAME", "").strip()
    pw = os.getenv("SOC_SUPERADMIN_PASSWORD", "")
    if not name and os.getenv("SOC_DEMO_MODE", "0") == "1":
        name, pw = "superadmin", "Super@123"
        print(f"[SECURITY] Demo super admin '{name}' password: {pw}  (demo mode only; set SOC_SUPERADMIN_USERNAME / SOC_SUPERADMIN_PASSWORD in production)")
    if name and pw:
        try:
            ensure_superadmin(name, pw)
        except ValueError as exc:
            print(f"[SECURITY] Super admin not created: {exc}")
    with closing(get_db()) as conn:
        have = conn.execute("SELECT 1 FROM users WHERE tenant_id=? AND role=? AND deleted_at IS NULL", (PLATFORM_TENANT, SUPERADMIN)).fetchone()
    if not have:
        print("[SECURITY] No super admin account exists, so the Tenants portal cannot be used. Create one with:  python create_superadmin.py <username>   "
              "(or set SOC_SUPERADMIN_USERNAME and SOC_SUPERADMIN_PASSWORD and restart).")


def tenant_stats() -> list:
    now = _now()
    since24 = _ts(now - timedelta(hours=24))
    out = []
    with closing(get_db()) as conn:
        for t in conn.execute("SELECT id, name, created_at, posture_score FROM tenants WHERE id != ? ORDER BY name COLLATE NOCASE", (PLATFORM_TENANT,)).fetchall():
            tid = t["id"]
            one = lambda q, *a: conn.execute(q, a).fetchone()[0]
            out.append({
                "id": tid, "name": t["name"], "created_at": t["created_at"],
                "users": one("SELECT COUNT(*) FROM users WHERE tenant_id=? AND deleted_at IS NULL", tid),
                "active_incidents": one("SELECT COUNT(*) FROM incidents WHERE tenant_id=? AND status NOT IN ('contained','closed')", tid),
                "unassigned_incidents": one("SELECT COUNT(*) FROM incidents WHERE tenant_id=? AND status NOT IN ('contained','closed') AND (assigned_to IS NULL OR assigned_to='Unassigned')", tid),
                "critical_active": one("SELECT COUNT(*) FROM incidents WHERE tenant_id=? AND status NOT IN ('contained','closed') AND severity='critical'", tid),
                "open_alarms": one("SELECT COUNT(*) FROM notifications WHERE tenant_id=? AND acked_at IS NULL AND severity='critical' AND created_at>=?", tid, _ts(now - timedelta(hours=12))),
                "last_activity": conn.execute("SELECT MAX(created_at) FROM audit_logs WHERE tenant_id=?", (tid,)).fetchone()[0],
                "ai_blocked_24h": one("SELECT COUNT(*) FROM ai_events WHERE tenant_id=? AND verdict='block' AND created_at>=?", tid, since24),
            })
    return out


def _now() -> datetime:
    return datetime.now(UTC)


def _slug(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return s[:24] or "tenant"


class NewTenant(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    admin_username: str = Field(min_length=3, max_length=64)


class SwitchRequest(BaseModel):
    tenant_id: str
    read_only: bool = True


def create_tenant(name: str, admin_username: str) -> dict:
    name, admin_username = name.strip(), admin_username.strip()
    if not re.fullmatch(r"[A-Za-z0-9_.@\-]{3,64}", admin_username):
        raise HTTPException(status_code=400, detail="Admin username may use letters, digits and _ . @ - only")
    with closing(get_db()) as conn:
        if conn.execute("SELECT 1 FROM tenants WHERE lower(name)=lower(?)", (name,)).fetchone():
            raise HTTPException(status_code=409, detail="A tenant with this name already exists")
        if conn.execute("SELECT 1 FROM users WHERE username_lookup=?", (username_blind_index(admin_username),)).fetchone():
            raise HTTPException(status_code=409, detail="That username is already taken (usernames are unique across the platform)")
        tid = f"tenant-{_slug(name)}-{uuid.uuid4().hex[:4]}"
        pw = secrets.token_urlsafe(12)
        conn.execute("INSERT INTO tenants (id, name, api_key) VALUES (?,?,?)", (tid, name, secrets.token_urlsafe(24)))
        create_encrypted_user(conn, tid, admin_username, pw, "admin")
        conn.execute("UPDATE users SET must_change_password=1 WHERE username_lookup=?", (username_blind_index(admin_username),))
        conn.commit()
    return {"tenant_id": tid, "name": name, "admin_username": admin_username, "temporary_password": pw}


def build_platform_router(get_current_user, write_audit, client_ip) -> APIRouter:
    router = APIRouter(prefix="/api/v1/platform")

    async def superadmin(user: dict = Depends(get_current_user)) -> dict:
        if user.get("real_role") != SUPERADMIN:
            raise HTTPException(status_code=403, detail="Platform administration is restricted to the super admin")
        return user

    def audit(tenant_id, user, request, action, target, details):
        write_audit(tenant_id, user["username"].replace(" (superadmin)", ""), action, target, details, actor_role=SUPERADMIN, ip_address=client_ip(request))

    @router.get("/tenants")
    async def tenants(user: dict = Depends(superadmin)):
        return {"tenants": tenant_stats(), "home_tenant": user.get("home_tenant") or user["tenant_id"]}

    @router.post("/tenants")
    async def new_tenant(req: NewTenant, request: Request, user: dict = Depends(superadmin)):
        res = create_tenant(req.name, req.admin_username)
        audit(PLATFORM_TENANT, user, request, "PLATFORM_TENANT_CREATE", res["tenant_id"], f"Super admin created tenant '{res['name']}' with admin '{res['admin_username']}'")
        audit(res["tenant_id"], user, request, "PLATFORM_TENANT_CREATE", res["tenant_id"], "Tenant provisioned by the platform super admin")
        return res

    @router.post("/switch")
    async def switch(req: SwitchRequest, request: Request, user: dict = Depends(superadmin)):
        with closing(get_db()) as conn:
            t = conn.execute("SELECT id, name FROM tenants WHERE id=? AND id!=?", (req.tenant_id, PLATFORM_TENANT)).fetchone()
        if not t:
            raise HTTPException(status_code=404, detail="Tenant not found")
        token = create_session_token(user["sub"], user["username"].replace(" (superadmin)", ""), SUPERADMIN, user.get("home_tenant") or user["tenant_id"],
                                     extra={"ctx": t["id"], "ro": bool(req.read_only)})
        mode = "read-only" if req.read_only else "full access"
        audit(t["id"], user, request, "PLATFORM_TENANT_ENTER", t["id"], f"Platform super admin '{user['username'].replace(' (superadmin)', '')}' entered this tenant ({mode})")
        return {"token": token, "tenant_id": t["id"], "tenant_name": t["name"], "read_only": bool(req.read_only)}

    @router.post("/exit")
    async def exit_tenant(request: Request, user: dict = Depends(superadmin)):
        if user.get("ctx_tenant"):
            audit(user["ctx_tenant"], user, request, "PLATFORM_TENANT_EXIT", user["ctx_tenant"], "Platform super admin left this tenant")
        home = user.get("home_tenant") or user["tenant_id"]
        token = create_session_token(user["sub"], user["username"].replace(" (superadmin)", ""), SUPERADMIN, home)
        return {"token": token}

    return router
