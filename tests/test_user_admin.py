"""Run from the project root:  python -m unittest discover -s tests -v
Uses a throw-away database; your real data is never touched."""
import os
import pathlib
import sqlite3
import sys
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
_TMP = tempfile.mkdtemp()
os.environ["SOC_DB_PATH"] = os.path.join(_TMP, "users_test.db")
os.environ["SOC_MASTER_KEY"] = "unit-test-master-key-unit-test-master-key"
os.environ["SOC_DEMO_MODE"] = "1"

import db            # noqa: E402
import user_admin as ua   # noqa: E402

T = "tenant-trustaira"


def _conn():
    c = sqlite3.connect(os.environ["SOC_DB_PATH"])
    c.row_factory = sqlite3.Row
    return c


def _uid(name):
    with _conn() as c:
        return c.execute("SELECT id FROM users WHERE username_lookup=?", (db.username_blind_index(name),)).fetchone()["id"]


def _row(name):
    with _conn() as c:
        return c.execute("SELECT * FROM users WHERE username_lookup=?", (db.username_blind_index(name),)).fetchone()


def _mk(name, role="analyst", pw="Password-123"):
    with _conn() as c:
        db.create_encrypted_user(c, T, name, pw, role)
        c.commit()
    return _uid(name)


def setUpModule():
    db.init_db()
    ua.init_user_admin_db()


class SeedingRegression(unittest.TestCase):
    def test_init_never_wipes_existing_users(self):
        """Old bug: changing the admin password then restarting deleted ALL users and reset defaults."""
        extra = _mk("keepme", "analyst")
        with _conn() as c:
            c.execute("UPDATE users SET password_encrypted=? WHERE username_lookup=?", (db.encrypt_password("A-brand-new-pass-1"), db.username_blind_index("admin")))
            c.commit()
            before = c.execute("SELECT COUNT(*) n FROM users").fetchone()["n"]
        db.init_db()                       # simulates a server restart
        db.init_db()
        with _conn() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) n FROM users").fetchone()["n"], before)
        self.assertTrue(db.verify_password("A-brand-new-pass-1", _row("admin")["password_encrypted"]))
        self.assertFalse(db.verify_password("Admin@123", _row("admin")["password_encrypted"]))
        self.assertEqual(_uid("keepme"), extra)

    def test_first_run_uses_random_passwords_outside_demo_mode(self):
        with _conn() as c:
            saved = c.execute("SELECT * FROM users").fetchall()
            c.execute("DELETE FROM users"); c.commit()
        old = os.environ["SOC_DEMO_MODE"]
        os.environ["SOC_DEMO_MODE"] = "0"
        try:
            db.init_db()
            self.assertFalse(db.verify_password("Admin@123", _row("admin")["password_encrypted"]))
        finally:
            os.environ["SOC_DEMO_MODE"] = old
            with _conn() as c:
                c.execute("DELETE FROM users")
                for r in saved:
                    c.execute("INSERT INTO users (id, tenant_id, username_lookup, username_encrypted, password_encrypted, role, created_at) VALUES (?,?,?,?,?,?,?)",
                              (r["id"], r["tenant_id"], r["username_lookup"], r["username_encrypted"], r["password_encrypted"], r["role"], r["created_at"]))
                c.commit()
            ua.init_user_admin_db()


class Deactivate(unittest.TestCase):
    def test_removed_user_is_flagged_and_tokens_refused(self):
        uid = _mk("leaver1")
        admin = _uid("admin")
        res = ua.deactivate_user(T, uid, admin)
        self.assertEqual(res["username"], "leaver1")
        r = _row("leaver1")
        self.assertIsNotNone(r["deleted_at"])
        self.assertIn("removed", ua.session_problem(r, int(time.time()) + 5).lower())

    def test_open_incidents_are_unassigned_but_closed_ones_kept(self):
        uid = _mk("owner1")
        with _conn() as c:
            c.execute("UPDATE incidents SET assigned_to='owner1' WHERE id='INC-2041'")
            c.execute("UPDATE incidents SET assigned_to='owner1' WHERE id='INC-2043'")
            c.execute("UPDATE incidents SET status='contained' WHERE id='INC-2043'")
            c.commit()
        res = ua.deactivate_user(T, uid, _uid("admin"))
        self.assertEqual(res["incidents_unassigned"], 1)
        with _conn() as c:
            self.assertEqual(c.execute("SELECT assigned_to FROM incidents WHERE id='INC-2041'").fetchone()[0], "Unassigned")
            self.assertEqual(c.execute("SELECT assigned_to FROM incidents WHERE id='INC-2043'").fetchone()[0], "owner1")

    def test_guards(self):
        admin = _uid("admin")
        with self.assertRaises(ua.UserAdminError) as e:
            ua.deactivate_user(T, admin, admin)
        self.assertEqual(e.exception.status, 400)                      # cannot remove yourself
        uid = _mk("twice1")
        ua.deactivate_user(T, uid, admin)
        with self.assertRaises(ua.UserAdminError) as e:
            ua.deactivate_user(T, uid, admin)
        self.assertEqual(e.exception.status, 409)                      # already removed
        with self.assertRaises(ua.UserAdminError) as e:
            ua.deactivate_user("other-tenant", uid, admin)
        self.assertEqual(e.exception.status, 404)                      # other tenants cannot touch it

    def test_last_active_admin_is_protected(self):
        with _conn() as c:
            admins = [r["id"] for r in c.execute("SELECT id FROM users WHERE role='admin' AND deleted_at IS NULL").fetchall()]
        keeper, others = admins[0], admins[1:]
        for other in others:
            ua.deactivate_user(T, other, keeper)
        helper = _mk("helper_analyst", "analyst")           # any other actor
        try:
            with self.assertRaises(ua.UserAdminError) as e:
                ua.deactivate_user(T, keeper, helper)       # keeper is now the only active admin
            self.assertEqual(e.exception.status, 400)
            self.assertIn("last", e.exception.message.lower())
        finally:
            for a in others:
                ua.reactivate_user(T, a)


class Reactivate(unittest.TestCase):
    def test_reactivate_restores_login_and_forces_password_change(self):
        uid = _mk("comeback1")
        ua.deactivate_user(T, uid, _uid("admin"))
        res = ua.reactivate_user(T, uid)
        r = _row("comeback1")
        self.assertIsNone(r["deleted_at"])
        self.assertEqual(r["must_change_password"], 1)
        self.assertEqual(res["username"], "comeback1")
        self.assertTrue(db.verify_password("Password-123", r["password_encrypted"]))
        self.assertIn("password change", ua.session_problem(r, int(time.time()) - 3600).lower())   # pre-removal tokens stay dead
        with self.assertRaises(ua.UserAdminError):
            ua.reactivate_user(T, uid)                   # not removed any more


class Purge(unittest.TestCase):
    def test_purge_requires_removal_first(self):
        uid = _mk("purge1")
        with self.assertRaises(ua.UserAdminError) as e:
            ua.purge_user(T, uid)
        self.assertEqual(e.exception.status, 409)
        ua.deactivate_user(T, uid, _uid("admin"))
        ua.purge_user(T, uid)
        self.assertIsNone(_row("purge1"))

    def test_expired_window_is_purged_automatically(self):
        uid = _mk("expired1")
        ua.deactivate_user(T, uid, _uid("admin"))
        with _conn() as c:
            c.execute("UPDATE users SET purge_after='2000-01-01 00:00:00' WHERE id=?", (uid,)); c.commit()
        keep = _mk("stillthere1"); ua.deactivate_user(T, keep, _uid("admin"))
        self.assertGreaterEqual(ua.purge_expired(), 1)
        self.assertIsNone(_row("expired1"))
        self.assertIsNotNone(_row("stillthere1"))        # still inside its window

    def test_list_shows_removed_with_days_left(self):
        uid = _mk("listme1")
        ua.deactivate_user(T, uid, _uid("admin"))
        d = ua.list_users(T)
        names = [u["username"] for u in d["deactivated"]]
        self.assertIn("listme1", names)
        self.assertNotIn("listme1", [u["username"] for u in d["users"]])
        item = [u for u in d["deactivated"] if u["username"] == "listme1"][0]
        self.assertGreaterEqual(item["days_left"], ua.RETENTION_DAYS - 1)
        self.assertEqual(item["deleted_by"], "admin")


class PasswordReset(unittest.TestCase):
    def test_reset_changes_password_forces_change_and_ends_sessions(self):
        uid = _mk("resetme1", pw="Old-Password-1")
        admin = _uid("admin")
        token_iat = int(time.time()) - 2                  # a token issued before the reset
        ua.reset_password(T, uid, "Temp-Password-9", admin, True)
        r = _row("resetme1")
        self.assertTrue(db.verify_password("Temp-Password-9", r["password_encrypted"]))
        self.assertFalse(db.verify_password("Old-Password-1", r["password_encrypted"]))
        self.assertEqual(r["must_change_password"], 1)
        self.assertIn("password change", ua.session_problem(r, token_iat).lower())
        self.assertIsNone(ua.session_problem(r, int(time.time()) + 1))   # a fresh login works

    def test_force_change_can_be_turned_off(self):
        uid = _mk("resetme2")
        ua.reset_password(T, uid, "Another-Pass-1", _uid("admin"), False)
        self.assertEqual(_row("resetme2")["must_change_password"], 0)

    def test_rules(self):
        admin, uid = _uid("admin"), _mk("resetme3")
        for bad in ("short", "", None):
            with self.assertRaises(ua.UserAdminError) as e:
                ua.reset_password(T, uid, bad, admin)
            self.assertEqual(e.exception.status, 400)
        with self.assertRaises(ua.UserAdminError) as e:
            ua.reset_password(T, admin, "Valid-Password-1", admin)        # own account
        self.assertEqual(e.exception.status, 400)
        with self.assertRaises(ua.UserAdminError) as e:
            ua.reset_password("other-tenant", uid, "Valid-Password-1", admin)
        self.assertEqual(e.exception.status, 404)
        ua.deactivate_user(T, uid, admin)
        with self.assertRaises(ua.UserAdminError) as e:
            ua.reset_password(T, uid, "Valid-Password-1", admin)           # removed user
        self.assertEqual(e.exception.status, 409)

    def test_user_sets_own_password_clears_flag(self):
        uid = _mk("resetme4")
        ua.reset_password(T, uid, "Temp-Password-9", _uid("admin"), True)
        ua.clear_must_change(uid, "My-Own-Password-1")
        r = _row("resetme4")
        self.assertEqual(r["must_change_password"], 0)
        self.assertTrue(db.verify_password("My-Own-Password-1", r["password_encrypted"]))


class Assignees(unittest.TestCase):
    def test_only_active_admins_and_analysts_can_own_incidents(self):
        _mk("an1", "analyst"); _mk("vw1", "viewer"); gone = _mk("an2", "analyst")
        ua.deactivate_user(T, gone, _uid("admin"))
        names = ua.assignable_usernames(T)
        self.assertIn("an1", names)
        self.assertNotIn("vw1", names)
        self.assertNotIn("an2", names)


class SessionRules(unittest.TestCase):
    def test_missing_user(self):
        self.assertIn("no longer exists", ua.session_problem(None, 1))

    def test_normal_session_ok(self):
        r = _row("admin")
        self.assertIsNone(ua.session_problem(r, int(time.time())))


if __name__ == "__main__":
    unittest.main()
