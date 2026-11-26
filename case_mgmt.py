# file: case_mgmt.py
"""Case ownership: who has an incident, since when, claim/release, and the case-file timeline.
Depends only on db.py so it can be unit-tested without the web layer."""
import os
import uuid
from contextlib import closing
from datetime import datetime, timezone
from typing import Dict, List, Optional

from db import get_db

WARN_HOURS = int(os.getenv("SOC_ASSIGN_WARN_HOURS", "72"))      # still open this long after assignment: amber
LATE_HOURS = int(os.getenv("SOC_ASSIGN_LATE_HOURS", "168"))     # ... red
UNASSIGNED = "Unassigned"
RESOLVED = ("contained", "closed")          # the threat is no longer active
VERDICTS = {
    "true_positive": "True positive: confirmed malicious activity",
    "false_positive": "False positive: no malicious activity",
    "benign_true_positive": "Benign true positive: real activity, authorized or expected",
    "inconclusive": "Inconclusive: not enough evidence to decide",
    "duplicate": "Duplicate of another incident",
}
MIN_SUMMARY = 15


class CaseError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def parse_ts(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    v = value.replace(" UTC", "").replace("T", " ").replace("Z", "").strip()[:19]
    try:
        return datetime.strptime(v, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def init_case_mgmt_db() -> None:
    with closing(get_db()) as conn:
        for sql in ("ALTER TABLE incidents ADD COLUMN assigned_at TEXT", "ALTER TABLE incidents ADD COLUMN assigned_by TEXT",
                    "ALTER TABLE incidents ADD COLUMN verdict TEXT", "ALTER TABLE incidents ADD COLUMN closed_by TEXT",
                    "ALTER TABLE incidents ADD COLUMN closed_at TEXT", "ALTER TABLE incidents ADD COLUMN closure_summary TEXT",
                    "ALTER TABLE incidents ADD COLUMN domain TEXT DEFAULT 'cyber'",
                    ):
            try:
                conn.execute(sql)
            except Exception:
                pass                                           # column already exists
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS incident_assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            incident_id TEXT NOT NULL,
            assignee TEXT NOT NULL,
            assigned_by TEXT NOT NULL,
            action TEXT NOT NULL,              -- assign, claim, reassign, release
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_assign_incident ON incident_assignments(tenant_id, incident_id, id);
        """)
        # incidents assigned before this feature existed: best available time is the last update
        try:
            conn.execute("ALTER TABLE incident_assignments ADD COLUMN detail TEXT")
        except Exception:
            pass
        conn.execute("UPDATE incidents SET domain='cyber' WHERE domain IS NULL")
        conn.execute("UPDATE incidents SET assigned_at = updated_at, assigned_by = 'system' "
                     "WHERE assigned_to IS NOT NULL AND assigned_to != 'Unassigned' AND assigned_at IS NULL")
        conn.commit()


def stale_level(status: str, assigned_at: Optional[str], now: Optional[datetime] = None) -> str:
    """'' | 'warn' | 'late': assigned a long time ago and the case is still not contained."""
    t = parse_ts(assigned_at)
    if not t or status in RESOLVED:
        return ""
    hours = ((now or _now()) - t).total_seconds() / 3600
    return "late" if hours >= LATE_HOURS else ("warn" if hours >= WARN_HOURS else "")


def decorate(incidents: List[dict], tenant_id: str) -> List[dict]:
    """Adds assignment age, staleness and comment counts to incident dicts."""
    now = _now()
    with closing(get_db()) as conn:
        counts = {r["incident_id"]: (r["n"], r["last"]) for r in conn.execute(
            "SELECT incident_id, COUNT(*) n, MAX(created_at) last FROM case_notes WHERE tenant_id=? GROUP BY incident_id", (tenant_id,)).fetchall()}
    for inc in incidents:
        if not inc.get("assigned_to"):
            inc["assigned_to"] = UNASSIGNED
        at = parse_ts(inc.get("assigned_at")) if inc["assigned_to"] != UNASSIGNED else None
        created = parse_ts(inc.get("created_at"))
        inc["assigned_age_seconds"] = int((now - at).total_seconds()) if at else None
        inc["age_seconds"] = int((now - created).total_seconds()) if created else None
        inc["stale"] = stale_level(inc.get("status", ""), inc.get("assigned_at"), now) if at else ""
        n, last = counts.get(inc["id"], (0, None))
        inc["comment_count"], inc["last_comment_at"] = n, last
        inc["domain"] = inc.get("domain") or "cyber"
        inc["verdict_label"] = VERDICTS.get(inc.get("verdict") or "", "")
    return incidents


def policy() -> dict:
    return {"warn_hours": WARN_HOURS, "late_hours": LATE_HOURS}


def _log(conn, tenant_id, incident_id, assignee, actor, action, detail=None):
    conn.execute("INSERT INTO incident_assignments (tenant_id, incident_id, assignee, assigned_by, action, created_at, detail) VALUES (?,?,?,?,?,?,?)",
                 (tenant_id, incident_id, assignee, actor, action, _ts(_now()), detail))


def set_assignment(tenant_id: str, incident_id: str, assignee: str, actor: str) -> dict:
    """Assign, reassign or release. Re-assigning to the same person keeps the original assignment time.
    updated_at is deliberately left alone: it marks attack activity (it drives the live alarm and MTTR), not bookkeeping."""
    with closing(get_db()) as conn:
        row = conn.execute("SELECT title, status, assigned_to FROM incidents WHERE id=? AND tenant_id=?", (incident_id, tenant_id)).fetchone()
        if not row:
            raise CaseError(404, "Incident not found")
        prev = row["assigned_to"] or UNASSIGNED
        if row["status"] == "closed":
            raise CaseError(409, "This incident is closed. Reopen it first.")
        if assignee == prev:
            return {"changed": False, "title": row["title"], "previous": prev, "status": row["status"], "action": "none"}
        if assignee == UNASSIGNED:
            action = "release"
        elif prev == UNASSIGNED:
            action = "claim" if assignee == actor else "assign"
        else:
            action = "reassign"
        status = row["status"]
        if assignee != UNASSIGNED and status in ("open", "awaiting_approval"):
            status = "investigating"
        elif assignee == UNASSIGNED and status == "investigating":
            status = "open"
        now = _ts(_now())
        conn.execute("UPDATE incidents SET assigned_to=?, assigned_at=?, assigned_by=?, status=? WHERE id=? AND tenant_id=?",
                     (assignee, None if assignee == UNASSIGNED else now, None if assignee == UNASSIGNED else actor, status, incident_id, tenant_id))
        _log(conn, tenant_id, incident_id, assignee, actor, action)
        conn.commit()
    return {"changed": True, "title": row["title"], "previous": prev, "status": status, "action": action}


def claim(tenant_id: str, incident_id: str, username: str) -> dict:
    """Take an unassigned incident. Atomic, so two analysts clicking at once cannot both win."""
    with closing(get_db()) as conn:
        row = conn.execute("SELECT title, status, assigned_to FROM incidents WHERE id=? AND tenant_id=?", (incident_id, tenant_id)).fetchone()
        if not row:
            raise CaseError(404, "Incident not found")
        owner = row["assigned_to"] or UNASSIGNED
        if row["status"] == "closed":
            raise CaseError(409, "This incident is closed. Reopen it first.")
        if owner == username:
            return {"changed": False, "title": row["title"], "status": row["status"], "action": "none", "previous": owner}
        if owner != UNASSIGNED:
            raise CaseError(409, f"Already assigned to {owner}. Ask an admin to reassign it.")
        status = "investigating" if row["status"] in ("open", "awaiting_approval") else row["status"]
        now = _ts(_now())
        cur = conn.execute("UPDATE incidents SET assigned_to=?, assigned_at=?, assigned_by=?, status=? "
                           "WHERE id=? AND tenant_id=? AND (assigned_to IS NULL OR assigned_to='Unassigned')",
                           (username, now, username, status, incident_id, tenant_id))
        if cur.rowcount != 1:
            raise CaseError(409, "Someone else just claimed this incident")
        _log(conn, tenant_id, incident_id, username, username, "claim")
        conn.commit()
    return {"changed": True, "title": row["title"], "status": status, "action": "claim", "previous": UNASSIGNED}


def release(tenant_id: str, incident_id: str, actor: str, actor_role: str) -> dict:
    with closing(get_db()) as conn:
        row = conn.execute("SELECT assigned_to FROM incidents WHERE id=? AND tenant_id=?", (incident_id, tenant_id)).fetchone()
        if not row:
            raise CaseError(404, "Incident not found")
        owner = row["assigned_to"] or UNASSIGNED
        if owner == UNASSIGNED:
            raise CaseError(409, "This incident is not assigned")
        if owner != actor and actor_role != "admin":
            raise CaseError(403, f"Only {owner} or an admin can release this incident")
    return set_assignment(tenant_id, incident_id, UNASSIGNED, actor)


def close_incident(tenant_id: str, incident_id: str, actor: str, actor_role: str, verdict: str, summary: str) -> dict:
    """Final close-out by the owning analyst (or an admin). A verdict and findings are mandatory."""
    verdict, summary = (verdict or "").strip(), (summary or "").strip()
    if verdict not in VERDICTS:
        raise CaseError(400, "Choose a final verdict")
    if len(summary) < MIN_SUMMARY:
        raise CaseError(400, f"Write the findings (at least {MIN_SUMMARY} characters)")
    if len(summary) > 2000:
        raise CaseError(400, "Findings are too long (max 2000 characters)")
    with closing(get_db()) as conn:
        row = conn.execute("SELECT title, status, assigned_to FROM incidents WHERE id=? AND tenant_id=?", (incident_id, tenant_id)).fetchone()
        if not row:
            raise CaseError(404, "Incident not found")
        owner = row["assigned_to"] or UNASSIGNED
        if row["status"] == "closed":
            raise CaseError(409, "This incident is already closed")
        if actor_role != "admin":
            if owner == UNASSIGNED:
                raise CaseError(409, "Claim the incident before closing it")
            if owner != actor:
                raise CaseError(403, f"Only {owner} or an admin can close this incident")
        now = _ts(_now())
        cur = conn.execute("UPDATE incidents SET status='closed', verdict=?, closed_by=?, closed_at=?, closure_summary=?, updated_at=? "
                           "WHERE id=? AND tenant_id=? AND status!='closed'", (verdict, actor, now, summary, now, incident_id, tenant_id))
        if cur.rowcount != 1:
            raise CaseError(409, "This incident is already closed")
        _log(conn, tenant_id, incident_id, owner, actor, "close", f"{verdict}: {summary}")
        conn.execute("INSERT INTO case_notes (id, tenant_id, incident_id, author, author_role, note_type, content, created_at) VALUES (?,?,?,?,?,?,?,?)",
                     (str(uuid.uuid4()), tenant_id, incident_id, actor, actor_role, "closure", f"Closed as {VERDICTS[verdict].split(':')[0]}. {summary}", now + " UTC"))
        conn.commit()
    return {"title": row["title"], "previous_status": row["status"], "owner": owner, "verdict": verdict}


def reopen_incident(tenant_id: str, incident_id: str, actor: str, actor_role: str, reason: str) -> dict:
    reason = (reason or "").strip()
    if len(reason) < 10:
        raise CaseError(400, "Explain why it is being reopened (at least 10 characters)")
    with closing(get_db()) as conn:
        row = conn.execute("SELECT title, status, closed_by FROM incidents WHERE id=? AND tenant_id=?", (incident_id, tenant_id)).fetchone()
        if not row:
            raise CaseError(404, "Incident not found")
        if row["status"] != "closed":
            raise CaseError(409, "Only a closed incident can be reopened")
        if actor_role != "admin" and row["closed_by"] != actor:
            raise CaseError(403, f"Only {row['closed_by']} or an admin can reopen this incident")
        now = _ts(_now())
        conn.execute("UPDATE incidents SET status='open', action_approved=0, assigned_to='Unassigned', assigned_at=NULL, assigned_by=NULL, "
                     "verdict=NULL, closed_by=NULL, closed_at=NULL, closure_summary=NULL, updated_at=? WHERE id=? AND tenant_id=?", (now, incident_id, tenant_id))
        _log(conn, tenant_id, incident_id, UNASSIGNED, actor, "reopen", reason)
        conn.execute("INSERT INTO case_notes (id, tenant_id, incident_id, author, author_role, note_type, content, created_at) VALUES (?,?,?,?,?,?,?,?)",
                     (str(uuid.uuid4()), tenant_id, incident_id, actor, actor_role, "case_comment", f"Reopened: {reason}", now + " UTC"))
        conn.commit()
    return {"title": row["title"]}


def ownership_chain(inc: dict, history: List[dict], now: Optional[datetime] = None) -> dict:
    """Who held the incident, in order, and for how long: Unassigned -> ana (3 d) -> bob (1 d) -> closed."""
    now = now or _now()
    created = parse_ts(inc.get("created_at"))
    closed_at = parse_ts(inc.get("closed_at")) if inc.get("status") == "closed" else None
    events = [h for h in history if h["action"] in ("assign", "claim", "reassign", "release", "reopen", "close")]
    if not any(e["action"] in ("assign", "claim", "reassign") for e in events) and inc.get("assigned_to") not in (None, UNASSIGNED):
        events.insert(0, {"action": "assign", "assignee": inc["assigned_to"], "assigned_by": inc.get("assigned_by") or "system",
                          "created_at": inc.get("assigned_at") or inc.get("updated_at")})   # assigned before history existed
    segs: List[dict] = []
    cur = {"owner": UNASSIGNED, "start": created, "by": None, "how": "created"}
    final = None
    for e in events:
        at = parse_ts(e["created_at"])
        if e["action"] == "close":
            final = e
            continue
        new_owner = UNASSIGNED if e["action"] in ("release", "reopen") else e["assignee"]
        if cur["start"] is not None and at is not None:
            cur["end"] = at
            segs.append(cur)
        cur = {"owner": new_owner, "start": at, "by": e.get("assigned_by"), "how": e["action"]}
    cur["end"] = closed_at
    segs.append(cur)
    out = []
    for s in segs:
        start, end = s["start"], s.get("end")
        stop = end or now
        out.append({"owner": s["owner"], "start": _ts(start) if start else None, "end": _ts(end) if end else None,
                    "seconds": max(0, int((stop - start).total_seconds())) if start else None, "by": s["by"], "how": s["how"],
                    "current": end is None and not closed_at})
    result = {"segments": out}
    if closed_at:
        result["final"] = {"verdict": inc.get("verdict"), "verdict_label": VERDICTS.get(inc.get("verdict") or "", ""), "closed_by": inc.get("closed_by"),
                           "closed_at": _ts(closed_at), "summary": inc.get("closure_summary"),
                           "total_seconds": int((closed_at - created).total_seconds()) if created else None}
    return result


def case_file(tenant_id: str, incident_id: str) -> dict:
    with closing(get_db()) as conn:
        comments = [dict(r) for r in conn.execute(
            "SELECT id, author, author_role, note_type, content, created_at FROM case_notes WHERE tenant_id=? AND incident_id=? ORDER BY created_at ASC, rowid ASC",
            (tenant_id, incident_id)).fetchall()]
        history = [dict(r) for r in conn.execute(
            "SELECT assignee, assigned_by, action, created_at, detail FROM incident_assignments WHERE tenant_id=? AND incident_id=? ORDER BY id ASC",
            (tenant_id, incident_id)).fetchall()]
        inc = conn.execute("SELECT * FROM incidents WHERE id=? AND tenant_id=?", (incident_id, tenant_id)).fetchone()
    return {"comments": comments, "assignment_history": history, "ownership": ownership_chain(dict(inc), history) if inc else {"segments": []}}


def reopen_if_contained(tenant_id: str, incident_id: str, reason: str) -> bool:
    """New high/critical activity on a contained or closed incident means it did not hold:
    put it back in the queue (unassigned, open) and leave a note in the case file."""
    now = _ts(_now())
    with closing(get_db()) as conn:
        cur = conn.execute("UPDATE incidents SET status='open', action_approved=0, assigned_to='Unassigned', assigned_at=NULL, assigned_by=NULL, updated_at=? "
                           "WHERE id=? AND tenant_id=? AND status IN ('contained','closed')", (now, incident_id, tenant_id))
        if cur.rowcount != 1:
            return False
        conn.execute("UPDATE incidents SET verdict=NULL, closed_by=NULL, closed_at=NULL, closure_summary=NULL WHERE id=? AND tenant_id=?", (incident_id, tenant_id))
        _log(conn, tenant_id, incident_id, UNASSIGNED, "system", "reopen", reason)
        conn.execute("INSERT INTO case_notes (id, tenant_id, incident_id, author, author_role, note_type, content, created_at) VALUES (?,?,?,?,?,?,?,?)",
                     (str(uuid.uuid4()), tenant_id, incident_id, "system", "system", "case_comment", f"Re-opened automatically: {reason}", now + " UTC"))
        conn.commit()
    return True
