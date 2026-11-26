"""Run from the project root:  python -m unittest discover -s tests -v
HTTP-level and hardening tests for the AI AppSec module. Uses a throw-away database."""
import json
import os
import pathlib
import sqlite3
import sys
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
_TMP = tempfile.mkdtemp()
DBFILE = os.path.join(_TMP, "appsec_api_test.db")
DBFILE = os.environ.setdefault("SOC_DB_PATH", DBFILE)          # one shared test database when run together
os.environ["SOC_MASTER_KEY"] = "unit-test-master-key-unit-test-master-key"
os.environ["SOC_DEMO_MODE"] = "1"
os.environ.pop("SOC_AI_GATE_ENFORCE", None)

import db                       # noqa: E402
import ai_appsec as x           # noqa: E402

T, PW = "tenant-trustaira", "Passw0rd!x"
cl = None
SPEC = json.dumps({"openapi": "3.0.0", "info": {"title": "Chat API"}, "servers": [{"url": "http://api.example.com"}],
                   "paths": {"/v1/chat": {"post": {"requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"prompt": {"type": "string"}}}}}},
                                                   "responses": {"200": {"description": "ok"}}}}}})
TOOLS = json.dumps({"tools": [{"name": "get_weather", "description": "Current weather", "annotations": {"readOnlyHint": True},
                               "inputSchema": {"type": "object", "additionalProperties": False, "required": ["city"],
                                               "properties": {"city": {"type": "string", "maxLength": 60, "pattern": "^[A-Za-z ]+$"}}}}]})
SECRET = "sk-ant-abcdefghijklmnopqrstuvwxyz012345"


def _sql(q, args=()):
    c = sqlite3.connect(DBFILE); c.row_factory = sqlite3.Row
    r = c.execute(q, args).fetchall(); c.commit(); c.close()
    return r


def setUpModule():
    global cl
    db.init_db()
    c = sqlite3.connect(DBFILE)
    c.execute("INSERT OR IGNORE INTO tenants (id, name, api_key, posture_score) VALUES (?, 'Acme', 'k', 70)", (T,))
    c.commit(); c.close()
    with db.get_db() as conn:
        for u, r in (("boss", "admin"), ("ana", "analyst"), ("vic", "viewer")):
            None if conn.execute("SELECT 1 FROM users WHERE username_lookup=?", (db.username_blind_index(u),)).fetchone() else db.create_encrypted_user(conn, T, u, PW, r)
        conn.commit()
    from fastapi.testclient import TestClient
    import main
    cl = TestClient(main.app)
    cl.__enter__()


def tearDownModule():
    if cl:
        cl.__exit__(None, None, None)


class Hardening(unittest.TestCase):
    def test_dangerous_patterns_are_refused_without_running_them(self):
        for p in (r"(a+)+$", r"(a|aa)+$", r"(.*)*", r"(a*)*b", r"(\w+\s?)+$", r"(a)\1", r".*.*.*.*.*x"):
            self.assertEqual(x.pattern_problem(p), "complex", p)
        self.assertEqual(x.pattern_problem("("), "unusable")
        for ok in (r"^[a-z0-9_\-]{1,64}$", r"^[A-Za-z ]+$", r"^\d{4}-\d{2}-\d{2}$", r"^(ab){1,3}$", r"^(GET|POST)$", r"^https://[a-z.]+/v1/.*$"):
            self.assertIsNone(x.pattern_problem(ok), ok)

    def test_catastrophic_pattern_cannot_hang_the_checker(self):
        pol = {"default": "deny", "tools": {"t": {"requires_approval": False, "args": {"v": {"type": "string", "required": True, "maxLength": 2000, "pattern": r"(a+)+$"}}}}}
        t0 = time.time()
        res = x.enforce(pol, {"tool": "t", "args": {"v": "a" * 40 + "!"}})
        self.assertLess(time.time() - t0, 1.0)
        self.assertEqual(res["decision"], "deny"); self.assertIn("too complex", " ".join(res["reasons"]))

    def test_normal_patterns_still_enforce(self):
        pol = x.generate_policy(x.parse_document(TOOLS))
        self.assertEqual(x.enforce(pol, {"tool": "get_weather", "args": {"city": "Dhaka"}})["decision"], "allow")
        self.assertEqual(x.enforce(pol, {"tool": "get_weather", "args": {"city": "Dhaka; rm -rf /"}})["decision"], "deny")

    def test_long_values_are_not_matched_against_patterns(self):
        pol = {"default": "deny", "tools": {"t": {"requires_approval": False, "args": {"v": {"type": "string", "required": True, "maxLength": 2000, "pattern": "^[a-z]+$"}}}}}
        r = x.enforce(pol, {"tool": "t", "args": {"v": "a" * 500}})
        self.assertEqual(r["decision"], "deny"); self.assertIn("too long to check", " ".join(r["reasons"]))

    def test_yaml_aliases_are_refused_but_plain_yaml_works(self):
        bomb = "a: &a [x,x,x]\nb: [*a,*a,*a]\nopenapi: 3.0.0\n"
        with self.assertRaises(x.AIAppSecError) as e: x.parse_document(bomb)
        self.assertIn("anchors", e.exception.message)
        self.assertEqual(x.parse_document("openapi: 3.0.0\ninfo:\n  title: T\n")["openapi"], "3.0.0")
        self.assertEqual(x.parse_document('{"a": 1}')["a"], 1)

    def test_deeply_nested_documents_fail_cleanly(self):
        r = cl.post("/api/v1/auth/login", json={"username": "ana", "password": PW}); h = {"Authorization": "Bearer " + r.json()["token"]}
        deep = '{"openapi":"3.0.0","x":' + "[" * 4000 + "]" * 4000 + "}"
        resp = cl.post("/api/v1/ai/contracts/audit", headers=h, json={"name": "deep", "kind": "openapi", "content": deep})
        self.assertIn(resp.status_code, (200, 400), resp.text)                   # never a 500

    def test_secrets_never_reach_stored_evidence(self):
        code = f'r = subprocess.run(["curl", "-H", "x: {SECRET}"]); print(response)\npassword = "Hunter2Hunter2"; send(user_input, prompt)\n'
        res = x.run_code_scan(T, "leaky-repo", [{"path": "a.py", "content": code}], "ana")
        stored = json.dumps([dict(r) for r in _sql("SELECT * FROM ai_code_scans")]) + json.dumps(x.get_scan(T, res["id"]))
        self.assertNotIn(SECRET, stored); self.assertNotIn("Hunter2Hunter2", stored)
        self.assertTrue(any(f["rule"] == "exposed_ai_key" for f in res["findings"]))


class Api(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        def H(u):
            r = cl.post("/api/v1/auth/login", json={"username": u, "password": PW}); return {"Authorization": "Bearer " + r.json()["token"]}
        cls.h = {u: H(u) for u in ("boss", "ana", "vic")}

    def get(self, u, p, **k): return cl.get(p, headers=self.h[u], **k)
    def post(self, u, p, **k): return cl.post(p, headers=self.h[u], **k)

    def test_viewers_cannot_use_any_appsec_endpoint(self):
        for m, p, body in (("post", "/api/v1/ai/contracts/audit", {"name": "x1", "kind": "openapi", "content": SPEC}), ("get", "/api/v1/ai/contracts", None),
                           ("post", "/api/v1/ai/contracts/policy", {"content": TOOLS}), ("post", "/api/v1/ai/contracts/check-call", {"policy": {}, "call": {}}),
                           ("post", "/api/v1/ai/code-scan", {"name": "x1", "files": []}), ("get", "/api/v1/ai/code-scans", None), ("get", "/api/v1/ai/assets/ai-x/gate", None)):
            r = getattr(cl, m)(p, headers=self.h["vic"], **({"json": body} if body is not None else {}))
            self.assertEqual(r.status_code, 403, p)

    def test_contract_audit_is_stored_audited_and_tenant_scoped(self):
        r = self.post("ana", "/api/v1/ai/contracts/audit", json={"name": "chat-api", "kind": "openapi", "content": SPEC})
        self.assertEqual(r.status_code, 200, r.text); a = r.json()
        self.assertLess(a["score"], 100); self.assertTrue(a["findings"])
        self.assertTrue(any(x_["id"] == a["id"] for x_ in self.get("ana", "/api/v1/ai/contracts").json()["audits"]))
        self.assertEqual(self.get("ana", f"/api/v1/ai/contracts/{a['id']}").status_code, 200)
        stored = json.dumps([dict(r_) for r_ in _sql("SELECT * FROM ai_contract_audits WHERE id=?", (a["id"],))])
        self.assertNotIn("Chat API", stored)                                                                  # the document itself is never stored (only findings and its hash)
        import hashlib
        self.assertIn(hashlib.sha256(SPEC.encode()).hexdigest(), stored)
        _sql("UPDATE ai_contract_audits SET tenant_id='tenant-other' WHERE id=?", (a["id"],))
        self.assertEqual(self.get("ana", f"/api/v1/ai/contracts/{a['id']}").status_code, 404)                  # another tenant's audit is invisible
        self.assertEqual(self.get("ana", "/api/v1/ai/contracts/not%20an%20id").status_code, 400)
        self.assertTrue(any(l["action"] == "AI_CONTRACT_AUDIT" for l in self.get("boss", "/api/v1/audit-logs").json()["logs"]))

    def test_policy_generation_and_call_check(self):
        pol = self.post("ana", "/api/v1/ai/contracts/policy", json={"content": TOOLS}).json()
        ok = self.post("ana", "/api/v1/ai/contracts/check-call", json={"policy": pol, "call": {"tool": "get_weather", "args": {"city": "Dhaka"}}}).json()
        no = self.post("ana", "/api/v1/ai/contracts/check-call", json={"policy": pol, "call": {"tool": "get_weather", "args": {"city": "x; DROP TABLE a"}}}).json()
        self.assertEqual((ok["decision"], no["decision"]), ("allow", "deny"))
        self.assertEqual(self.post("ana", "/api/v1/ai/contracts/check-call", json={"policy": {"tools": {}, "pad": "x" * 1_100_000}, "call": {"tool": "a", "args": {}}}).status_code, 400)

    def test_code_scan_finds_shadow_ai_and_registers_it_as_unapproved(self):
        code = "import openai\nclient = openai.OpenAI(api_key=\"%s\")\nanswer = client.chat.completions.create(model='gpt-4o', messages=[])\neval(answer)\n" % SECRET
        r = self.post("ana", "/api/v1/ai/code-scan", json={"name": "billing-service", "files": [{"path": "app/ai.py", "content": code}]})
        self.assertEqual(r.status_code, 200, r.text); s = r.json()
        self.assertGreaterEqual(s["shadow_ai"], 1); self.assertNotIn(SECRET, json.dumps(s))
        self.assertTrue({"exposed_ai_key", "exec_model_output"} <= {f["rule"] for f in s["findings"]}, {f["rule"] for f in s["findings"]})
        self.assertEqual(self.get("ana", f"/api/v1/ai/code-scans/{s['id']}").status_code, 200)
        reg = self.post("ana", f"/api/v1/ai/code-scans/{s['id']}/register-assets", json={})
        self.assertEqual(reg.status_code, 200, reg.text); self.assertTrue(reg.json()["created"])
        assets = self.get("ana", "/api/v1/ai/assets").json()["assets"]
        self.assertTrue(all(not a["approved"] for a in assets if a["name"] in reg.json()["created"]))
        again = self.post("ana", f"/api/v1/ai/code-scans/{s['id']}/register-assets", json={})
        self.assertEqual(again.json()["created"], [])                                                          # idempotent
        logs = self.get("boss", "/api/v1/audit-logs").json()["logs"]
        self.assertTrue(any(l["action"] == "AI_CODE_SCAN" for l in logs) and any(l["action"] == "AI_ASSETS_REGISTERED" for l in logs))
        self.assertEqual(self.post("ana", "/api/v1/ai/code-scan", json={"name": "x1", "files": [{"path": "a.py", "content": "x" * 400_000}]}).status_code, 422)

    def test_approval_gate_reports_and_can_enforce(self):
        a = self.post("ana", "/api/v1/ai/assets", json={"name": "gate-app", "asset_type": "app", "internet_exposed": True, "approved": False, "owner": "team"}).json()
        g = self.get("ana", f"/api/v1/ai/assets/{a['id']}/gate").json()
        self.assertFalse(g["passed"]); self.assertTrue(g["criteria"])
        self.assertEqual(self.get("ana", "/api/v1/ai/assets/ai-nope/gate").status_code, 404)
        self.assertEqual(self.post("ana", "/api/v1/ai/assets", json={"name": "ungated", "asset_type": "app", "internet_exposed": True, "approved": True}).status_code, 200)   # informs only by default
        os.environ["SOC_AI_GATE_ENFORCE"] = "1"
        try:
            blocked = self.post("ana", "/api/v1/ai/assets", json={"name": "gated", "asset_type": "app", "internet_exposed": True, "approved": True})
            self.assertEqual(blocked.status_code, 409); self.assertIn("Cannot approve yet", blocked.json()["detail"])
            self.assertEqual(self.post("ana", "/api/v1/ai/assets", json={"name": "gated-ok", "asset_type": "app", "internet_exposed": True, "approved": False}).status_code, 200)
            put = cl.put(f"/api/v1/ai/assets/{a['id']}", headers=self.h["ana"], json={"name": "gate-app", "asset_type": "app", "internet_exposed": True, "approved": True, "owner": "team"})
            self.assertEqual(put.status_code, 409)
        finally:
            os.environ.pop("SOC_AI_GATE_ENFORCE", None)

    def test_existing_ai_routes_still_work_next_to_the_new_ones(self):
        for p in ("/api/v1/ai/overview", "/api/v1/ai/posture", "/api/v1/ai/discovery/summary", "/api/v1/ai/gateway/policies", "/api/v1/ai/coverage"):
            self.assertEqual(self.get("ana", p).status_code, 200, p)


if __name__ == "__main__":
    unittest.main()
