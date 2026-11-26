"""Run from the project root:  python -m unittest discover -s tests -v
Uses a throw-away database; your real data is never touched."""
import json
import os
import pathlib
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
_TMP = tempfile.mkdtemp()
os.environ["SOC_DB_PATH"] = os.path.join(_TMP, "test.db")
os.environ["SOC_MASTER_KEY"] = "unit-test-master-key-unit-test-master-key"
os.environ["SOC_DEMO_MODE"] = "1"

import db            # noqa: E402
import soc_health as h   # noqa: E402

T = "tenant-trustaira"
UTC = timezone.utc


def _ts(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def setUpModule():
    conn = sqlite3.connect(os.environ["SOC_DB_PATH"])
    conn.executescript((ROOT / "sql" / "schema.sql").read_text(encoding="utf-8"))
    conn.execute("INSERT OR IGNORE INTO tenants (id, name, api_key) VALUES (?, 'Test Tenant <b>', 'k')", (T,))
    conn.execute("UPDATE tenants SET name='Test Tenant <b>' WHERE id=?", (T,))
    now = datetime.now(UTC)
    inc = [("INC-T1", "Macro phishing leads to credential theft", "Phishing email with macro, PowerShell and LSASS credential dump", "high", "open", "WS-A", now - timedelta(hours=5), now),
           ("INC-T2", "Macro phishing then credential dump on finance host", "Phishing email with macro, PowerShell and LSASS credential dump", "high", "contained", "WS-B", now - timedelta(hours=3), now - timedelta(hours=1)),
           ("INC-T3", "Crypto mining on cloud instances", "GPU instances launched for coin mining", "medium", "open", "aws-role", now - timedelta(hours=2), now)]
    for iid, title, story, sev, status, ent, c, u in inc:
        conn.execute("INSERT OR REPLACE INTO incidents (id, tenant_id, title, risk_score, severity, status, primary_entity, ai_story, recommended_action, created_at, updated_at) "
                     "VALUES (?,?,?,?,?,?,?,?,?,?,?)", (iid, T, title, 80, sev, status, ent, story, "Isolate host and rotate credentials", _ts(c), _ts(u)))
    for iid, tactic, ttl in (("INC-T1", "Initial access", "Phishing macro opened"), ("INC-T1", "Execution", "PowerShell encoded"), ("INC-T1", "Credential access", "LSASS dump"),
                             ("INC-T2", "Initial access", "Phishing macro opened"), ("INC-T2", "Credential access", "LSASS dump"), ("INC-T3", "Impact", "GPU mining")):
        conn.execute("INSERT INTO incident_steps (id, incident_id, tenant_id, stage_order, tactic, technique_group, technique_id, title, event_time, source, entity, severity, raw_log) "
                     "VALUES (?,?,?,1,?,?,?,?,?,?,?,?,?)", (f"s-{iid}-{tactic}", iid, T, tactic, "T0", "T0000", ttl, "09:00", "EDR", "WS-A", "high", "raw"))
    conn.commit()
    conn.close()
    db.init_db()
    h.init_health_db()


def _samples(values, step=30, end_age=0):
    end = datetime.now(UTC) - timedelta(seconds=end_age)
    return [(end - timedelta(seconds=step * (len(values) - 1 - i)), v) for i, v in enumerate(values)]


class SilentSources(unittest.TestCase):
    now = datetime.now(UTC)

    def test_healthy(self):
        self.assertEqual(h.classify_source(_samples([100] * 20), self.now)["state"], "healthy")

    def test_learning_when_few_samples(self):
        self.assertEqual(h.classify_source(_samples([100] * 5), self.now)["state"], "learning")

    def test_silent_when_no_recent_data(self):
        r = h.classify_source(_samples([100] * 20, end_age=600), self.now)
        self.assertEqual(r["state"], "silent")
        self.assertIn("No data for", r["message"])
        self.assertIsNone(r["current"])                 # stale samples must not be shown as "current"
        self.assertEqual(r["last_reported"], 100.0)

    def test_silent_when_zero_volume(self):
        self.assertEqual(h.classify_source(_samples([100] * 17 + [0, 0, 0]), self.now)["state"], "silent")

    def test_degraded_on_sharp_drop(self):
        r = h.classify_source(_samples([100] * 17 + [20, 25, 22]), self.now)
        self.assertEqual(r["state"], "degraded")
        self.assertLess(r["pct"], 40)

    def test_surging(self):
        self.assertEqual(h.classify_source(_samples([100] * 17 + [500, 520, 480]), self.now)["state"], "surging")

    def test_low_volume_source_is_not_flagged(self):
        self.assertEqual(h.classify_source(_samples([1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0]), self.now)["state"], "healthy")

    def test_heartbeat_unknown_node(self):
        with self.assertRaises(KeyError):
            h.record_heartbeat(T, "node-does-not-exist", 5)

    def test_outage_shows_up_end_to_end(self):
        node = sqlite3.connect(os.environ["SOC_DB_PATH"]).execute("SELECT id FROM node_status WHERE tenant_id=? LIMIT 1", (T,)).fetchone()
        if not node:
            self.skipTest("no demo nodes in the seed data")
        conn = sqlite3.connect(os.environ["SOC_DB_PATH"])
        conn.execute("DELETE FROM node_metrics WHERE node_id=?", (node[0],))
        old = datetime.now(UTC) - timedelta(minutes=20)
        for i in range(30):
            conn.execute("INSERT INTO node_metrics (tenant_id, node_id, ts, eps) VALUES (?,?,?,?)", (T, node[0], _ts(old + timedelta(seconds=30 * i)), 100))
        conn.commit(); conn.close()
        states = {n["node_id"]: n["state"] for n in h.node_health(T)["nodes"]}
        self.assertEqual(states[node[0]], "silent")


class RulesAndSuppressions(unittest.TestCase):
    def test_noisy_rule_gets_entity_exclusion_suggestion(self):
        r = h.rule_health(T)
        noisy = [x for x in r["rules"] if x["grade"] == "noisy"]
        self.assertTrue(noisy, "demo data should contain a noisy rule")
        self.assertIn("exclusion", noisy[0]["suggestion"])
        self.assertIsNotNone(noisy[0]["top_fp_entity"])

    def test_silent_rule_detected(self):
        silent = [x for x in h.rule_health(T)["rules"] if x["grade"] == "silent"]
        self.assertTrue(any("Golden Ticket" in x["rule"] for x in silent))

    def test_disposition_updates_stats(self):
        aid = h.DEMO_ALERTS[0][0]
        conn = sqlite3.connect(os.environ["SOC_DB_PATH"])
        h.mark_disposition(T, aid, "false_positive")
        self.assertEqual(conn.execute("SELECT disposition FROM alert_records WHERE id=?", (aid,)).fetchone()[0], "false_positive")
        h.mark_disposition(T, aid, "garbage")                 # invalid values are ignored
        self.assertEqual(conn.execute("SELECT disposition FROM alert_records WHERE id=?", (aid,)).fetchone()[0], "false_positive")
        h.mark_disposition("other-tenant", aid, "true_positive")   # other tenants cannot change it
        self.assertEqual(conn.execute("SELECT disposition FROM alert_records WHERE id=?", (aid,)).fetchone()[0], "false_positive")

    def test_suppression_expiry_lifecycle(self):
        conn = sqlite3.connect(os.environ["SOC_DB_PATH"])
        old = _ts(datetime.now(UTC) - timedelta(days=100))
        conn.execute("INSERT OR REPLACE INTO fp_rules (id, tenant_id, rule_name, entity_pattern, suppressed_by, reason, created_at, expires_at) VALUES ('fp-old', ?, 'Some Rule', 'HOST-1', 'analyst', 'x', ?, ?)",
                     (T, old, _ts(datetime.now(UTC) - timedelta(days=10))))
        conn.execute("INSERT OR REPLACE INTO fp_rules (id, tenant_id, rule_name, entity_pattern, suppressed_by, reason, created_at, expires_at) VALUES ('fp-soon', ?, 'Other Rule', 'HOST-2', 'analyst', 'x', ?, ?)",
                     (T, old, _ts(datetime.now(UTC) + timedelta(days=5))))
        conn.commit(); conn.close()
        states = {s["id"]: s["state"] for s in h.suppression_health(T)["suppressions"]}
        self.assertEqual(states["fp-old"], "expired")
        self.assertEqual(states["fp-soon"], "expiring")
        self.assertTrue(h.renew_suppression(T, "fp-old", "admin"))
        states = {s["id"]: s for s in h.suppression_health(T)["suppressions"]}
        self.assertEqual(states["fp-old"]["state"], "active")
        self.assertEqual(states["fp-old"]["reviewed_by"], "admin")
        self.assertIsNotNone(h.revoke_suppression(T, "fp-old"))
        self.assertIsNone(h.revoke_suppression(T, "fp-old"))
        self.assertFalse(h.renew_suppression(T, "fp-old", "admin"))

    def test_other_tenant_cannot_touch_suppression(self):
        conn = sqlite3.connect(os.environ["SOC_DB_PATH"])
        soon = _ts(datetime.now(UTC) + timedelta(days=3))
        conn.execute("INSERT OR REPLACE INTO fp_rules (id, tenant_id, rule_name, entity_pattern, suppressed_by, reason, expires_at) VALUES ('fp-iso', ?, 'Iso Rule', 'HOST-9', 'analyst', 'x', ?)", (T, soon))
        conn.commit()
        self.assertFalse(h.renew_suppression("some-other-tenant", "fp-iso", "attacker"))
        self.assertIsNone(h.revoke_suppression("some-other-tenant", "fp-iso"))
        row = conn.execute("SELECT expires_at, reviewed_by FROM fp_rules WHERE id='fp-iso'").fetchone()
        self.assertEqual(row[0], soon)                      # untouched
        self.assertIsNone(row[1])
        self.assertTrue(h.renew_suppression(T, "fp-iso", "admin"))   # the owning tenant can
        conn.execute("DELETE FROM fp_rules WHERE id='fp-iso'"); conn.commit(); conn.close()


class Vulnerabilities(unittest.TestCase):
    def test_kev_raises_priority(self):
        plain = h.score_vuln(9.8, {"kev": 0, "epss": 0.01}, "Tier-1 Critical Asset", False)
        kev = h.score_vuln(9.8, {"kev": 1, "epss": 0.9, "ransomware": 1}, "Tier-1 Critical Asset", True)
        self.assertGreater(kev["score"], plain["score"])
        self.assertTrue(kev["band"].startswith("P1"))
        self.assertLessEqual(kev["score"], 100)

    def test_missing_intel_is_explained_not_hidden(self):
        r = h.score_vuln(None, None, "", False)
        why = " ".join(f["why"] for f in r["factors"])
        self.assertIn("unknown", why)
        self.assertIn("not loaded", why)

    def test_parsers(self):
        kev = h.parse_kev({"vulnerabilities": [{"cveID": "cve-2023-44487", "dateAdded": "2023-10-10", "knownRansomwareCampaignUse": "Known"}, {"nope": 1}]})
        self.assertEqual(kev, [{"cve": "CVE-2023-44487", "kev_added": "2023-10-10", "ransomware": 1}])
        epss = h.parse_epss({"data": [{"cve": "CVE-2023-44487", "epss": "0.5", "percentile": "0.97"}, {"cve": "bad"}]})
        self.assertEqual(len(epss), 1)
        self.assertAlmostEqual(epss[0]["epss"], 0.5)

    def test_priorities_use_loaded_intel(self):
        conn = sqlite3.connect(os.environ["SOC_DB_PATH"])
        cves = h.tracked_cves(T)
        if not cves:
            self.skipTest("no CVEs in demo entity profiles")
        before = {r["cve"]: r["score"] for r in h.vuln_priorities(T)["rows"]}
        conn.execute("INSERT OR REPLACE INTO vuln_intel (cve, kev, ransomware, epss, updated_at) VALUES (?,1,1,0.9,'now')", (cves[0],))
        conn.commit(); conn.close()
        after = h.vuln_priorities(T)
        self.assertTrue(after["intel_loaded"])
        self.assertGreater(max(r["score"] for r in after["rows"] if r["cve"] == cves[0]), before[cves[0]])


class IncidentQuality(unittest.TestCase):
    def test_similar_incident_found_and_ranked(self):
        sim = h.similar_incidents(T, "INC-T1")
        self.assertEqual(sim[0]["id"], "INC-T2")
        self.assertGreater(sim[0]["similarity_pct"], sim[-1]["similarity_pct"] - 1)
        self.assertIn("Credential access", sim[0]["shared_tactics"])

    def test_checklist_follows_incident_tactics(self):
        keys = [c["key"] for c in h.checklist_for(T, "INC-T1")]
        self.assertIn("ca_lsass", keys)
        self.assertIn("gen_scope", keys)
        self.assertNotIn("im_backup", keys)

    def test_checklist_toggle_persists_and_validates(self):
        self.assertTrue(h.set_check(T, "INC-T1", "ca_lsass", True, "analyst"))
        item = [c for c in h.checklist_for(T, "INC-T1") if c["key"] == "ca_lsass"][0]
        self.assertTrue(item["done"])
        self.assertEqual(item["by"], "analyst")
        self.assertFalse(h.set_check(T, "INC-T1", "not-a-real-key", True, "analyst"))
        self.assertFalse(h.set_check(T, "INC-NOPE", "ca_lsass", True, "analyst"))
        self.assertFalse(h.set_check("other-tenant", "INC-T1", "ca_lsass", True, "analyst"))

    def test_summary_draft(self):
        s = h.draft_summary(T, "INC-T1")
        self.assertIn("INC-T1", s)
        self.assertIn("Initial access > Execution > Credential access", s)
        self.assertIsNone(h.draft_summary(T, "INC-NOPE"))


class Reporting(unittest.TestCase):
    def test_report_numbers_and_html_escaping(self):
        r = h.weekly_report(T)
        self.assertGreaterEqual(r["incidents"]["total"], 3)
        self.assertIsNotNone(r["incidents"]["mttr_minutes"])            # INC-T2 is contained
        page = h.render_report_html(r)
        self.assertIn("Test Tenant &lt;b&gt;", page)                     # tenant name is escaped
        self.assertNotIn("Test Tenant <b>", page)


class Evidence(unittest.TestCase):
    def test_package_verifies(self):
        z = h.build_evidence_zip(T, "INC-T1", "analyst")
        res = h.verify_evidence_zip(z, h.public_key_hex())
        self.assertTrue(res["ok"], res)

    def test_tampering_is_detected(self):
        import io, zipfile
        z = h.build_evidence_zip(T, "INC-T1", "analyst")
        src = zipfile.ZipFile(io.BytesIO(z))
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w") as dst:
            for n in src.namelist():
                data = src.read(n)
                if n == "incident.json":
                    data = data.replace(b"INC-T1", b"INC-XX")
                dst.writestr(n, data)
        res = h.verify_evidence_zip(out.getvalue())
        self.assertFalse(res["ok"])
        self.assertTrue(any("incident.json" in p for p in res["problems"]))

    def test_forged_manifest_is_detected(self):
        import io, zipfile
        z = h.build_evidence_zip(T, "INC-T1", "analyst")
        src = zipfile.ZipFile(io.BytesIO(z))
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w") as dst:
            for n in src.namelist():
                data = src.read(n)
                if n == "manifest.json":
                    m = json.loads(data); m["generated_by"] = "attacker"; data = json.dumps(m).encode()
                dst.writestr(n, data)
        self.assertIn("manifest signature is invalid", h.verify_evidence_zip(out.getvalue())["problems"])

    def test_wrong_trusted_key_is_rejected(self):
        z = h.build_evidence_zip(T, "INC-T1", "analyst")
        self.assertFalse(h.verify_evidence_zip(z, "00" * 32)["ok"])

    def test_unknown_incident_and_garbage_input(self):
        self.assertIsNone(h.build_evidence_zip(T, "INC-NOPE", "x"))
        self.assertFalse(h.verify_evidence_zip(b"not a zip")["ok"])
        self.assertIsNone(h.build_evidence_zip("other-tenant", "INC-T1", "x"))


if __name__ == "__main__":
    unittest.main()
