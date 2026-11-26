# file: notifications.py
"""Real-time critical-alert / active-attack notifications (Server-Sent Events).

Notifications live in SQLite so every worker sees them and nothing is lost on restart.
Producers call notify(); the browser tails /api/v1/notifications/stream.
"""
import asyncio
import json
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse

from db import get_db

UTC = timezone.utc
STARTED_AT = datetime.now(UTC)
SCHEMA = """
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, severity TEXT NOT NULL, kind TEXT NOT NULL,
    title TEXT NOT NULL, detail TEXT, incident_id TEXT, entity TEXT, dedupe_key TEXT,
    created_at TEXT NOT NULL, acked_by TEXT, acked_at TEXT);
CREATE UNIQUE INDEX IF NOT EXISTS idx_notif_dedupe ON notifications(tenant_id, dedupe_key);
CREATE INDEX IF NOT EXISTS idx_notif_tenant ON notifications(tenant_id, id);
"""


def _ts(dt: Optional[datetime] = None) -> str:
    return (dt or datetime.now(UTC)).strftime("%Y-%m-%d %H:%M:%S")


def init_notifications_db() -> None:
    with closing(get_db()) as conn:
        conn.executescript(SCHEMA)
        conn.commit()


def notify(tenant_id: str, severity: str, kind: str, title: str, detail: str = "",
           incident_id: str = "", entity: str = "", dedupe_key: Optional[str] = None) -> Optional[int]:
    """Store one notification. A repeated dedupe_key is ignored, which is what stops alert storms."""
    key = dedupe_key or f"{kind}:{incident_id}:{entity}:{title}:{_ts()[:16]}"
    with closing(get_db()) as conn:
        cur = conn.execute(
            "INSERT OR IGNORE INTO notifications (tenant_id, severity, kind, title, detail, incident_id, entity, dedupe_key, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?)", (tenant_id, severity, kind, title, detail, incident_id, entity, key, _ts()))
        conn.commit()
        return cur.lastrowid if cur.rowcount else None


def _public(row, role: str) -> dict:
    d = {"id": row["id"], "severity": row["severity"], "kind": row["kind"], "title": row["title"],
         "created_at": row["created_at"], "acked_by": row["acked_by"]}
    if role == "viewer":          # viewers get the headline only, never entities or detail
        d.update(detail="", incident_id="", entity="")
    else:
        d.update(detail=row["detail"], incident_id=row["incident_id"], entity=row["entity"])
    return d


def _replay(tenant_id: str, role: str, hours: int = 12, limit: int = 10):
    """Unacknowledged alerts to re-show after a page reload or reconnect (oldest first)."""
    with closing(get_db()) as conn:
        rows = conn.execute("SELECT * FROM notifications WHERE tenant_id=? AND acked_at IS NULL AND created_at>=? ORDER BY id DESC LIMIT ?",
                            (tenant_id, _ts(datetime.now(UTC) - timedelta(hours=hours)), limit)).fetchall()
    return [_public(r, role) for r in reversed(rows)]


def _new_acks(tenant_id: str, already: set):
    """Acknowledgements made by anyone in the last 15 minutes, so every screen can stop its alarm."""
    with closing(get_db()) as conn:
        rows = conn.execute("SELECT id, acked_by FROM notifications WHERE tenant_id=? AND acked_at IS NOT NULL AND acked_at>=?",
                            (tenant_id, _ts(datetime.now(UTC) - timedelta(minutes=15)))).fetchall()
    return [{"type": "ack", "id": r["id"], "acked_by": r["acked_by"]} for r in rows if r["id"] not in already]


def _fetch(tenant_id: str, after_id: int, role: str, limit: int = 20, recent_minutes: Optional[int] = None):
    sql, args = "SELECT * FROM notifications WHERE tenant_id=? AND id>?", [tenant_id, after_id]
    if recent_minutes:
        sql += " AND created_at>=? AND acked_at IS NULL"
        args.append(_ts(datetime.now(UTC) - timedelta(minutes=recent_minutes)))
    sql += " ORDER BY id ASC LIMIT ?"
    args.append(limit)
    with closing(get_db()) as conn:
        return [_public(r, role) for r in conn.execute(sql, args).fetchall()]


# ---------- background detector: critical alerts and incidents that are still moving ----------
def sweep_once() -> int:
    created = 0
    since = _ts(max(STARTED_AT, datetime.now(UTC) - timedelta(minutes=15)))
    with closing(get_db()) as conn:
        incs = conn.execute("SELECT id, tenant_id, title, severity, risk_score, primary_entity, updated_at FROM incidents "
                            "WHERE status NOT IN ('contained','closed') AND updated_at>=? AND (severity IN ('critical','high') OR risk_score>=85)", (since,)).fetchall()
        try:
            alerts = conn.execute("SELECT id, tenant_id, rule, entity, incident FROM alert_records "
                                  "WHERE severity='critical' AND disposition='open' AND created_at>=?", (since,)).fetchall()
        except Exception:
            alerts = []
    for i in incs:
        if notify(i["tenant_id"], "critical" if (i["severity"] == "critical" or i["risk_score"] >= 90) else "high", "active_attack",
                  f"Attack in progress: {i['title']}", f"{i['id']} is still active (risk {i['risk_score']}/100).",
                  i["id"], i["primary_entity"] or "", f"attack:{i['id']}"):
            created += 1
    for a in alerts:
        if notify(a["tenant_id"], "critical", "critical_alert", f"Critical alert: {a['rule']}", f"Entity {a['entity']}.",
                  a["incident"] if a["incident"] != "Standalone" else "", a["entity"] or "", f"alert:{a['id']}"):
            created += 1
    return created


async def run_sweeper(interval: int = 15):
    while True:
        try:
            await asyncio.to_thread(sweep_once)
        except Exception as exc:  # never let the detector die
            print(f"[notifications] sweep failed: {exc}")
        await asyncio.sleep(interval)


def start_sweeper():
    return asyncio.create_task(run_sweeper())


def build_notification_router(get_current_user, require_roles, write_audit, client_ip) -> APIRouter:
    router = APIRouter(prefix="/api/v1/notifications")
    analyst, admin = require_roles("admin", "analyst"), require_roles("admin")

    @router.get("")
    def recent(after: int = 0, user: dict = Depends(get_current_user)):
        return {"items": _fetch(user["tenant_id"], max(after, 0), user["role"], 50)}

    @router.get("/stream")
    async def stream(request: Request, user: dict = Depends(get_current_user)):
        tid, role = user["tenant_id"], user["role"]

        async def gen():
            with closing(get_db()) as conn:                            # live events start AFTER everything that exists now
                last = conn.execute("SELECT COALESCE(MAX(id),0) m FROM notifications WHERE tenant_id=?", (tid,)).fetchone()["m"]
            for n in await asyncio.to_thread(_replay, tid, role):      # unacknowledged ones are re-shown after a reload or reconnect
                yield f"data: {json.dumps(n)}\n\n"
            idle, acked_sent = 0, set()
            while not await request.is_disconnected():
                items = await asyncio.to_thread(_fetch, tid, last, role, 20)
                for n in items:
                    last = max(last, n["id"])
                    yield f"data: {json.dumps(n)}\n\n"
                acks = await asyncio.to_thread(_new_acks, tid, acked_sent)
                for a in acks:
                    acked_sent.add(a["id"])
                    yield f"data: {json.dumps(a)}\n\n"
                idle = 0 if (items or acks) else idle + 1
                if idle >= 7:
                    yield ": keepalive\n\n"
                    idle = 0
                await asyncio.sleep(2)

        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @router.post("/{notif_id}/ack")
    def ack(notif_id: int, request: Request, user: dict = Depends(analyst)):
        with closing(get_db()) as conn:
            cur = conn.execute("UPDATE notifications SET acked_by=?, acked_at=? WHERE id=? AND tenant_id=? AND acked_at IS NULL",
                               (user["username"], _ts(), notif_id, user["tenant_id"]))
            conn.commit()
            row = conn.execute("SELECT title FROM notifications WHERE id=? AND tenant_id=?", (notif_id, user["tenant_id"])).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Notification not found")
        if cur.rowcount:
            write_audit(user["tenant_id"], user["username"], "NOTIFICATION_ACK", str(notif_id),
                        f"'{user['username']}' acknowledged: {row['title']}", actor_role=user["role"], ip_address=client_ip(request))
        return {"status": "acknowledged", "id": notif_id}

    @router.post("/test")
    def test(request: Request, user: dict = Depends(admin)):
        nid = notify(user["tenant_id"], "critical", "test", "Test notification: critical alert pipeline",
                     f"Sent by {user['username']} to verify live notifications.", dedupe_key=f"test:{_ts()}:{user['username']}")
        return {"status": "sent", "id": nid}

    return router
