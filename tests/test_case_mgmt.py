"""Run from the project root:  python -m unittest discover -s tests -v
Uses a throw-away database; your real data is never touched."""
import os
import pathlib
import sqlite3
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
_TMP = tempfile.mkdtemp()
DBFILE = os.path.join(_TMP, "case_test.db")
os.environ["SOC_DB_PATH"] = DBFILE
os.environ["SOC_MASTER_KEY"] = "unit-test-master-key-unit-test-master-key"
os.environ["SOC_DEMO_MODE"] = "1"

import db            # noqa: E402
import case_mgmt as cm   # noqa: E402

T, PW = "tenant-trustaira", "Passw0rd!x"
UTC = timezone.utc
ts = lambda d: d.strftime("%Y-%m-%d %H:%M:%S")
cl = None


def _sql(q, args=()):
    c = sqlite3.connect(DBFILE); c.row_factory = sqlite3.Row
    r = c.execute(q, args).fetchall(); c.commit(); c.close()
    return r


def setUpModule():
    global cl
    db.init_db()
    now = datetime.now(UTC)
    c = sqlite3.connect(DBFILE)
    c.execute("INSERT OR IGNORE INTO tenants (id, name, api_key, posture_score) VALUES (?, 'Acme', 'k', 70)", (T,))
    for iid, status, assigned in (("C-1", "open", None), ("C-2", "open", None), ("C-3", "open", None), ("C-LEGACY", "open", "olduser")):
        c.execute("INSERT OR REPLACE INTO incidents (id,tenant_id,title,risk_score,severity,status,primary_entity,ai_story,recommended_action,created_at,updated_at,assigned_to) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                  (iid, T, "Case " + iid, 80, "high", status, "WS-1", "story", "act", ts(now - timedelta(days=30)), ts(now - timedelta(days=20)), assigned))
    c.commit(); c.close()
    with db.get_db() as conn:
        for u, r in (("boss", "admin"), ("ana", "analyst"), ("bob", "analyst"), ("vic", "viewer")):
            db.create_encrypted_user(conn, T, u, PW, r)
        conn.commit()
    from fastapi.testclient import TestClient
    import main
    cl = TestClient(main.app)
    cl.__enter__()


def tearDownModule():
    if cl:
        cl.__exit__(None, None, None)


def H(u):
    r = cl.post("/api/v1/auth/login", json={"username": u, "password": PW})
    return {"Authorization": "Bearer " + r.json()["token"]}


class Ownership(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.h = {u: H(u) for u in ("boss", "ana", "bob", "vic")}

    def post(self, u, p, **k): return cl.post(p, headers=self.h[u], **k)
    def get(self, u, p, **k): return cl.get(p, headers=self.h[u], **k)
    def inc(self, iid): return [i for i in self.get("boss", "/api/v1/dashboard").json()["incidents"] if i["id"] == iid][0]

    def test_legacy_assignments_are_backfilled(self):
        i = self.inc("C-LEGACY")
        self.assertEqual(i["assigned_to"], "olduser")
        self.assertIsNotNone(i["assigned_at"])
        self.assertGreater(i["assigned_age_seconds"], 19 * 86400)
        self.assertEqual(i["stale"], "late")                  # 20 days is past the 7-day "late" threshold

    def test_claim_release_flow(self):
        r = self.post("ana", "/api/v1/incidents/C-1/claim")
        self.assertEqual(r.status_code, 200, r.text)
        i = self.inc("C-1")
        self.assertEqual((i["assigned_to"], i["assigned_by"], i["status"]), ("ana", "ana", "investigating"))
        self.assertIsNotNone(i["assigned_at"])
        self.assertEqual(self.post("bob", "/api/v1/incidents/C-1/claim").status_code, 409)       # already owned
        self.assertEqual(self.post("ana", "/api/v1/incidents/C-1/claim").status_code, 200)       # idempotent for the owner
        self.assertEqual(self.post("bob", "/api/v1/incidents/C-1/release").status_code, 403)     # not yours
        self.assertEqual(self.post("vic", "/api/v1/incidents/C-1/claim").status_code, 403)       # viewers cannot
        self.assertEqual(self.post("ana", "/api/v1/incidents/C-1/release").status_code, 200)
        i = self.inc("C-1")
        self.assertEqual((i["assigned_to"], i["status"]), ("Unassigned", "open"))
        self.assertIsNone(i["assigned_at"]); self.assertIsNone(i["assigned_age_seconds"])
        self.assertEqual(self.post("ana", "/api/v1/incidents/C-1/release").status_code, 409)     # nothing to release
        self.assertEqual(self.post("ana", "/api/v1/incidents/NOPE/claim").status_code, 404)

    def test_assignment_time_is_kept_when_reassigning_same_person(self):
        self.post("boss", "/api/v1/incidents/C-2/assign", json={"assigned_to": "ana"})
        first = self.inc("C-2")["assigned_at"]
        _sql("UPDATE incidents SET assigned_at=? WHERE id='C-2'", (ts(datetime.now(UTC) - timedelta(days=5)),))
        before = self.inc("C-2")["assigned_at"]
        self.post("boss", "/api/v1/incidents/C-2/assign", json={"assigned_to": "ana"})       # same person again
        self.assertEqual(self.inc("C-2")["assigned_at"], before)
        self.post("boss", "/api/v1/incidents/C-2/assign", json={"assigned_to": "bob"})       # real change resets the clock
        self.assertNotEqual(self.inc("C-2")["assigned_at"], before)
        self.assertEqual(self.inc("C-2")["assigned_by"], "boss")

    def test_analyst_cannot_move_someone_elses_case(self):
        self.post("ana", "/api/v1/incidents/C-3/claim")
        r = self.post("bob", "/api/v1/incidents/C-3/assign", json={"assigned_to": "bob"})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.post("boss", "/api/v1/incidents/C-3/assign", json={"assigned_to": "bob"}).status_code, 200)   # admin can
        self.assertEqual(self.post("boss", "/api/v1/incidents/C-3/assign", json={"assigned_to": "vic"}).status_code, 400)   # viewers cannot own cases
        self.post("boss", "/api/v1/incidents/C-3/assign", json={"assigned_to": "Unassigned"})

    def test_staleness_levels(self):
        now = datetime.now(UTC)
        for days, expect in ((1, ""), (4, "warn"), (9, "late")):
            _sql("UPDATE incidents SET assigned_to='ana', assigned_at=?, status='investigating' WHERE id='C-2'", (ts(now - timedelta(days=days)),))
            self.assertEqual(self.inc("C-2")["stale"], expect, days)
        _sql("UPDATE incidents SET status='contained' WHERE id='C-2'")
        self.assertEqual(self.inc("C-2")["stale"], "")                                       # closed cases are never stale

    def test_case_file_shows_everyones_comments_and_history(self):
        self.post("ana", "/api/v1/incidents/C-1/claim")
        self.post("ana", "/api/v1/notes", json={"incident_id": "C-1", "note_type": "case_comment", "content": "Isolated WS-1"})
        self.post("bob", "/api/v1/notes", json={"incident_id": "C-1", "note_type": "case_comment", "content": "Seeing the same hash on WS-9"})
        d = self.get("bob", "/api/v1/incidents/C-1").json()
        self.assertEqual([c["author"] for c in d["comments"]], ["ana", "bob"])               # bob sees ana's comment and vice versa
        self.assertEqual(d["assignment_history"][-1]["action"], "claim")
        self.assertEqual(d["incident"]["comment_count"], 2)
        v = self.get("vic", "/api/v1/incidents/C-1").json()
        self.assertNotIn("comments", v)                                                      # viewers never see analyst notes
        self.assertEqual(v["incident"]["assigned_to"], "ana")
        self.assertIn("assignment_history", v)
        self.assertEqual(self.post("vic", "/api/v1/notes", json={"incident_id": "C-1", "note_type": "case_comment", "content": "x"}).status_code, 403)
        self.assertEqual(self.post("ana", "/api/v1/notes", json={"incident_id": "NOPE", "note_type": "case_comment", "content": "x"}).status_code, 404)
        self.assertEqual(self.post("ana", "/api/v1/notes", json={"incident_id": "C-1", "note_type": "case_comment", "content": "x" * 5000}).status_code, 400)
        self.post("ana", "/api/v1/incidents/C-1/release")

    def test_assignments_are_audited(self):
        self.post("ana", "/api/v1/incidents/C-3/claim")
        logs = self.get("boss", "/api/v1/audit-logs").json()["logs"]
        self.assertTrue(any(l["action"] == "CLAIM_INCIDENT" and l["target"] == "C-3" for l in logs))
        self.post("ana", "/api/v1/incidents/C-3/release")

    def test_claiming_does_not_trigger_an_attack_alarm(self):
        import notifications
        _sql("UPDATE incidents SET severity='critical', risk_score=95, status='open', assigned_to='Unassigned', assigned_at=NULL, updated_at=? WHERE id='C-3'",
             (ts(datetime.now(UTC) - timedelta(days=3)),))
        notifications.sweep_once()
        before = len(_sql("SELECT id FROM notifications"))
        self.post("ana", "/api/v1/incidents/C-3/claim")
        notifications.sweep_once()
        self.assertEqual(len(_sql("SELECT id FROM notifications")), before)        # ownership changes are not attack activity
        self.post("ana", "/api/v1/incidents/C-3/release")

    def test_new_activity_reopens_a_contained_incident(self):
        _sql("INSERT OR REPLACE INTO incidents (id,tenant_id,title,risk_score,severity,status,primary_entity,ai_story,recommended_action,created_at,updated_at,assigned_to,assigned_at) "
             "VALUES ('C-RE',?,'Contained one',80,'high','contained','WS-1','s','a',?,?,'ana',?)", (T, ts(datetime.now(UTC) - timedelta(days=3)), ts(datetime.now(UTC) - timedelta(days=2)), ts(datetime.now(UTC) - timedelta(days=3))))
        hook = {"incident_id": "C-RE", "title": "PAM checkout blocked", "tactic": "Credential access", "technique_id": "T1078", "source": "PAM", "entity": "VAULT-1", "severity": "high", "raw_log": "x"}
        r = self.post("ana", "/api/v1/ingest/webhook", json=hook)
        self.assertEqual(r.status_code, 200, r.text)
        i = self.inc("C-RE")
        self.assertEqual((i["status"], i["assigned_to"]), ("open", "Unassigned"))             # back in the queue, so the cards show it
        self.assertTrue(any("Re-opened" in c["content"] for c in self.get("ana", "/api/v1/incidents/C-RE").json()["comments"]))
        self.assertTrue(any("re-opened" in n["detail"] for n in self.get("ana", "/api/v1/notifications").json()["items"] if n["incident_id"] == "C-RE"))
        self.assertEqual(self.post("ana", "/api/v1/ingest/webhook", json={**hook, "incident_id": "NOPE"}).status_code, 404)   # no orphan alerts
        low = {**hook, "severity": "low"}
        _sql("UPDATE incidents SET status='contained' WHERE id='C-RE'")
        self.post("ana", "/api/v1/ingest/webhook", json=low)
        self.assertEqual(self.inc("C-RE")["status"], "contained")                              # low noise does not reopen

    # ---------------- close-out with a final verdict + ownership timeline ----------------
    def _fresh(self, iid, **cols):
        now = datetime.now(UTC)
        _sql("DELETE FROM incident_assignments WHERE incident_id=?", (iid,))
        _sql("DELETE FROM case_notes WHERE incident_id=?", (iid,))
        _sql("INSERT OR REPLACE INTO incidents (id,tenant_id,title,risk_score,severity,status,primary_entity,ai_story,recommended_action,created_at,updated_at,assigned_to) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
             (iid, T, "Case " + iid, 80, "high", cols.get("status", "open"), "WS-1", "story", "act", ts(now - timedelta(days=10)), ts(now - timedelta(days=9)), "Unassigned"))

    def test_close_needs_owner_verdict_and_findings(self):
        self._fresh("K-1")
        ok = {"verdict": "true_positive", "summary": "Credential dump confirmed on WS-1; host isolated and password reset."}
        self.assertEqual(self.post("ana", "/api/v1/incidents/K-1/close", json=ok).status_code, 409)            # not claimed yet
        self.post("ana", "/api/v1/incidents/K-1/claim")
        self.assertEqual(self.post("bob", "/api/v1/incidents/K-1/close", json=ok).status_code, 403)           # someone else's case
        self.assertEqual(self.post("vic", "/api/v1/incidents/K-1/close", json=ok).status_code, 403)
        self.assertEqual(self.post("ana", "/api/v1/incidents/K-1/close", json={**ok, "verdict": "maybe"}).status_code, 400)
        self.assertEqual(self.post("ana", "/api/v1/incidents/K-1/close", json={**ok, "summary": "done"}).status_code, 400)
        r = self.post("ana", "/api/v1/incidents/K-1/close", json=ok)
        self.assertEqual(r.status_code, 200, r.text)
        i = self.inc("K-1")
        self.assertEqual((i["status"], i["verdict"], i["closed_by"]), ("closed", "true_positive", "ana"))
        self.assertIsNotNone(i["closed_at"]); self.assertEqual(i["stale"], "")
        self.assertEqual(self.post("ana", "/api/v1/incidents/K-1/close", json=ok).status_code, 409)           # already closed
        self.assertEqual(self.post("bob", "/api/v1/incidents/K-1/claim").status_code, 409)                    # closed cases are frozen
        self.assertEqual(self.post("boss", "/api/v1/incidents/K-1/assign", json={"assigned_to": "bob"}).status_code, 409)
        logs = self.get("boss", "/api/v1/audit-logs").json()["logs"]
        self.assertTrue(any(l["action"] == "CLOSE_INCIDENT" and l["target"] == "K-1" for l in logs))
        d = self.get("bob", "/api/v1/incidents/K-1").json()
        self.assertTrue(any(c["note_type"] == "closure" for c in d["comments"]))                              # the findings are in the case file
        self.assertEqual(d["ownership"]["final"]["verdict"], "true_positive")

    def test_admin_can_close_any_case_and_dashboard_stops_counting_it(self):
        self._fresh("K-2")
        before = self.get("boss", "/api/v1/dashboard").json()["stats"]["open_incidents"]
        r = self.post("boss", "/api/v1/incidents/K-2/close", json={"verdict": "false_positive", "summary": "Scheduled backup job, verified with the owner."})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self.get("boss", "/api/v1/dashboard").json()["stats"]["open_incidents"], before - 1)
        self.assertIn("False positive", self.inc("K-2")["verdict_label"])

    def test_reopen_rules(self):
        self._fresh("K-3")
        self.post("ana", "/api/v1/incidents/K-3/claim")
        self.post("ana", "/api/v1/incidents/K-3/close", json={"verdict": "inconclusive", "summary": "Not enough telemetry to decide either way."})
        self.assertEqual(self.post("bob", "/api/v1/incidents/K-3/reopen", json={"reason": "I want to look again"}).status_code, 403)
        self.assertEqual(self.post("ana", "/api/v1/incidents/K-3/reopen", json={"reason": "short"}).status_code, 400)
        self.assertEqual(self.post("ana", "/api/v1/incidents/K-3/reopen", json={"reason": "New logs arrived from the EDR"}).status_code, 200)
        i = self.inc("K-3")
        self.assertEqual((i["status"], i["assigned_to"], i["verdict"]), ("open", "Unassigned", None))
        self.assertEqual(self.post("ana", "/api/v1/incidents/K-3/reopen", json={"reason": "Not closed any more"}).status_code, 409)

    def test_activity_after_closure_reopens(self):
        self._fresh("K-4")
        self.post("boss", "/api/v1/incidents/K-4/close", json={"verdict": "true_positive", "summary": "Contained and cleaned up by the IR team."})
        hook = {"incident_id": "K-4", "title": "Beacon again", "tactic": "Command and control", "technique_id": "T1071", "source": "NDR", "entity": "WS-1", "severity": "high", "raw_log": "x"}
        self.assertEqual(self.post("ana", "/api/v1/ingest/webhook", json=hook).status_code, 200)
        i = self.inc("K-4")
        self.assertEqual((i["status"], i["verdict"]), ("open", None))

    def test_ownership_timeline_shows_who_held_it_and_for_how_long(self):
        self._fresh("K-5")
        self.post("ana", "/api/v1/incidents/K-5/claim")
        self.post("boss", "/api/v1/incidents/K-5/assign", json={"assigned_to": "bob"})
        base = datetime.now(UTC)
        rows = _sql("SELECT id FROM incident_assignments WHERE incident_id='K-5' ORDER BY id")
        for r, days in zip(rows, (8, 4)):
            _sql("UPDATE incident_assignments SET created_at=? WHERE id=?", (ts(base - timedelta(days=days)), r["id"]))
        self.post("bob", "/api/v1/incidents/K-5/close", json={"verdict": "benign_true_positive", "summary": "Authorized penetration test by the red team."})
        _sql("UPDATE incident_assignments SET created_at=? WHERE incident_id='K-5' AND action='close'", (ts(base - timedelta(days=1)),))
        _sql("UPDATE incidents SET closed_at=? WHERE id='K-5'", (ts(base - timedelta(days=1)),))
        o = self.get("boss", "/api/v1/incidents/K-5").json()["ownership"]
        self.assertEqual([s["owner"] for s in o["segments"]], ["Unassigned", "ana", "bob"])
        self.assertEqual([s["how"] for s in o["segments"]], ["created", "claim", "reassign"])
        self.assertEqual(o["segments"][2]["by"], "boss")
        self.assertAlmostEqual(o["segments"][0]["seconds"], 2 * 86400, delta=5)        # waited 2 days for an owner
        self.assertAlmostEqual(o["segments"][1]["seconds"], 4 * 86400, delta=5)        # ana held it 4 days
        self.assertAlmostEqual(o["segments"][2]["seconds"], 3 * 86400, delta=5)        # bob held it 3 days until closure
        self.assertFalse(any(s["current"] for s in o["segments"]))
        self.assertEqual((o["final"]["verdict"], o["final"]["closed_by"]), ("benign_true_positive", "bob"))

    def test_timeline_for_legacy_assignment_without_history(self):
        o = self.get("boss", "/api/v1/incidents/C-LEGACY").json()["ownership"]
        self.assertEqual([s["owner"] for s in o["segments"]], ["Unassigned", "olduser"])
        self.assertTrue(o["segments"][-1]["current"])

    def test_concurrent_claim_has_one_winner(self):
        import threading
        _sql("UPDATE incidents SET assigned_to='Unassigned', assigned_at=NULL, status='open' WHERE id='C-1'")
        res = []
        def go(u): res.append(cm.claim.__call__(T, "C-1", u) if False else self.post(u, "/api/v1/incidents/C-1/claim").status_code)
        ts_ = [threading.Thread(target=go, args=(u,)) for u in ("ana", "bob")]
        [t.start() for t in ts_]; [t.join() for t in ts_]
        self.assertEqual(sorted(res), [200, 409])
        self.post("boss", "/api/v1/incidents/C-1/assign", json={"assigned_to": "Unassigned"})


if __name__ == "__main__":
    unittest.main()
