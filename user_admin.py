# file: user_admin.py
"""User lifecycle: deactivate (soft delete) -> reactivate / purge, admin password reset.
Only depends on db.py, so it can be unit-tested without the web layer."""
import os
import time
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from db import decrypt_text, encrypt_password, get_db

RETENTION_DAYS = int(os.getenv("SOC_USER_RETENTION_DAYS", "30"))
MIN_PASSWORD_LEN = 8


class UserAdminError(Exception):
    """Carries an HTTP-friendly status code and a message that is safe to show to the admin."""
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def init_user_admin_db() -> None:
    with closing(get_db()) as conn:
        for sql in ("ALTER TABLE users ADD COLUMN deleted_at TEXT",
                    "ALTER TABLE users ADD COLUMN deleted_by TEXT",
                    "ALTER TABLE users ADD COLUMN purge_after TEXT",
                    "ALTER TABLE users ADD COLUMN pw_changed_at INTEGER DEFAULT 0",
                    "ALTER TABLE users ADD COLUMN must_change_password INTEGER DEFAULT 0"):
            try:
                conn.execute(sql)
            except Exception:
                pass                                   # column already exists
        conn.commit()
    purge_expired()


def purge_expired() -> int:
    """Permanently remove deactivated accounts whose reactivation window has passed."""
    with closing(get_db()) as conn:
        cur = conn.execute("DELETE FROM users WHERE deleted_at IS NOT NULL AND purge_after IS NOT NULL AND purge_after < ?", (_ts(_now()),))
        conn.commit()
        return cur.rowcount


def _get(conn, tenant_id: str, user_id: str):
    row = conn.execute("SELECT * FROM users WHERE id=? AND tenant_id=?", (user_id, tenant_id)).fetchone()
    if not row:
        raise UserAdminError(404, "User not found")
    return row


def _active_admins(conn, tenant_id: str, excluding: str = "") -> int:
    return conn.execute("SELECT COUNT(*) c FROM users WHERE tenant_id=? AND role='admin' AND deleted_at IS NULL AND id!=?",
                        (tenant_id, excluding)).fetchone()["c"]


def list_users(tenant_id: str) -> dict:
    purge_expired()
    now = _now()
    active, deactivated = [], []
    with closing(get_db()) as conn:
        for r in conn.execute("SELECT * FROM users WHERE tenant_id=? ORDER BY created_at ASC", (tenant_id,)).fetchall():
            item = {"id": r["id"], "username": decrypt_text(r["username_encrypted"]), "role": r["role"], "created_at": r["created_at"],
                    "must_change_password": bool(r["must_change_password"])}
            if r["deleted_at"]:
                left = (datetime.strptime(r["purge_after"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc) - now) if r["purge_after"] else None
                item.update({"deleted_at": r["deleted_at"], "deleted_by": r["deleted_by"], "purge_after": r["purge_after"],
                             "days_left": max(0, left.days) if left is not None else None})
                deactivated.append(item)
            else:
                active.append(item)
    return {"users": active, "deactivated": deactivated, "retention_days": RETENTION_DAYS}


def deactivate_user(tenant_id: str, target_id: str, actor_id: str) -> dict:
    with closing(get_db()) as conn:
        row = _get(conn, tenant_id, target_id)
        if target_id == actor_id:
            raise UserAdminError(400, "You cannot remove your own account")
        if row["deleted_at"]:
            raise UserAdminError(409, "This user is already removed")
        if row["role"] == "admin" and _active_admins(conn, tenant_id, excluding=target_id) < 1:
            raise UserAdminError(400, "Cannot remove the last active admin")
        name = decrypt_text(row["username_encrypted"])
        actor = conn.execute("SELECT username_encrypted FROM users WHERE id=?", (actor_id,)).fetchone()
        now = _now()
        conn.execute("UPDATE users SET deleted_at=?, deleted_by=?, purge_after=?, pw_changed_at=? WHERE id=?",
                     (_ts(now), decrypt_text(actor["username_encrypted"]) if actor else "admin",
                      _ts(now + timedelta(days=RETENTION_DAYS)), int(time.time()), target_id))
        # their open work must not sit with someone who can no longer log in
        moved = conn.execute("UPDATE incidents SET assigned_to='Unassigned', updated_at=datetime('now') WHERE tenant_id=? AND assigned_to=? AND status!='contained'",
                             (tenant_id, name)).rowcount
        conn.commit()
    return {"username": name, "role": row["role"], "incidents_unassigned": moved, "retention_days": RETENTION_DAYS}


def reactivate_user(tenant_id: str, target_id: str) -> dict:
    with closing(get_db()) as conn:
        row = _get(conn, tenant_id, target_id)
        if not row["deleted_at"]:
            raise UserAdminError(409, "This user is not removed")
        conn.execute("UPDATE users SET deleted_at=NULL, deleted_by=NULL, purge_after=NULL, must_change_password=1, pw_changed_at=? WHERE id=?",
                     (int(time.time()), target_id))
        conn.commit()
        return {"username": decrypt_text(row["username_encrypted"]), "role": row["role"]}


def purge_user(tenant_id: str, target_id: str) -> dict:
    """Permanent delete. Only allowed for users that were already removed (two-step by design)."""
    with closing(get_db()) as conn:
        row = _get(conn, tenant_id, target_id)
        if not row["deleted_at"]:
            raise UserAdminError(409, "Remove the user first, then delete permanently")
        conn.execute("DELETE FROM users WHERE id=?", (target_id,))
        conn.commit()
        return {"username": decrypt_text(row["username_encrypted"]), "role": row["role"]}


def reset_password(tenant_id: str, target_id: str, new_password: str, actor_id: str, force_change: bool = True) -> dict:
    if len(new_password or "") < MIN_PASSWORD_LEN:
        raise UserAdminError(400, f"Password must be at least {MIN_PASSWORD_LEN} characters")
    with closing(get_db()) as conn:
        row = _get(conn, tenant_id, target_id)
        if target_id == actor_id:
            raise UserAdminError(400, "Use 'Update My Password' for your own account")
        if row["deleted_at"]:
            raise UserAdminError(409, "Reactivate this user before resetting the password")
        conn.execute("UPDATE users SET password_encrypted=?, pw_changed_at=?, must_change_password=? WHERE id=?",
                     (encrypt_password(new_password), int(time.time()), 1 if force_change else 0, target_id))
        conn.commit()
        return {"username": decrypt_text(row["username_encrypted"]), "role": row["role"], "force_change": force_change}


def clear_must_change(user_id: str, new_password: str) -> None:
    """Called when a user sets their own password: also invalidates their older sessions."""
    with closing(get_db()) as conn:
        conn.execute("UPDATE users SET password_encrypted=?, must_change_password=0, pw_changed_at=? WHERE id=?",
                     (encrypt_password(new_password), int(time.time()), user_id))
        conn.commit()


def session_problem(user_row, token_iat: int) -> Optional[str]:
    """Why a still-signed token must be refused, or None if it is fine."""
    if user_row is None:
        return "Account no longer exists"
    if user_row["deleted_at"]:
        return "Account has been removed"
    if int(token_iat or 0) < int(user_row["pw_changed_at"] or 0):
        return "Session expired after a password change. Please sign in again."
    return None


def assignable_usernames(tenant_id: str) -> List[str]:
    """Only active admins/analysts can own incidents (never viewers or removed users)."""
    with closing(get_db()) as conn:
        return [decrypt_text(r["username_encrypted"]) for r in conn.execute(
            "SELECT username_encrypted FROM users WHERE tenant_id=? AND deleted_at IS NULL AND role IN ('admin','analyst')", (tenant_id,)).fetchall()]
