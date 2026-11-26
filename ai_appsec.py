# file: ai_appsec.py
"""AI application security, built in-house (standard library only; PyYAML is optional for YAML input).

  1. Contract audit      : scores an OpenAPI document or an AI tool / MCP schema and explains every weakness.
  2. Allow-list policy   : turns a tool contract into a deny-by-default policy and checks tool calls against it.
  3. AI-in-code scanner  : finds AI components (shadow AI), exposed AI keys, unsafe model loading and
                           unsafe handling of model output in source code. Secrets are masked, code is never stored.
  4. Quality gates       : rules an AI asset must meet before it may be marked approved.

Depends only on db.py (and ai_security for the asset inventory and the prompt inspector).
"""
import hashlib
import json
import os
import re
import uuid
from contextlib import closing
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional

from db import get_db

UTC = timezone.utc
MAX_DOC_CHARS = 1_000_000
MAX_FILES, MAX_FILE_CHARS, MAX_TOTAL_CHARS = 200, 300_000, 3_000_000
KEEP_PER_TENANT = 200

SEV_POINTS = {"critical": 25, "high": 15, "medium": 8, "low": 3}
SEV_ORDER = ["critical", "high", "medium", "low"]
API10 = {"API2": "API2:2023 Broken Authentication", "API3": "API3:2023 Broken Object Property Level Authorization",
         "API4": "API4:2023 Unrestricted Resource Consumption", "API7": "API7:2023 Server Side Request Forgery",
         "API8": "API8:2023 Security Misconfiguration", "API9": "API9:2023 Improper Inventory Management"}
LLM10 = {"LLM01": "LLM01 Prompt Injection", "LLM02": "LLM02 Sensitive Information Disclosure", "LLM03": "LLM03 Supply Chain",
         "LLM05": "LLM05 Improper Output Handling", "LLM06": "LLM06 Excessive Agency", "LLM10": "LLM10 Unbounded Consumption"}


class AIAppSecError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def _now() -> datetime:
    return datetime.now(UTC)


def _ts(dt: Optional[datetime] = None) -> str:
    return (dt or _now()).strftime("%Y-%m-%d %H:%M:%S")


# =====================================================================
# SHARED: findings, scoring
# =====================================================================
def _f(rule: str, severity: str, where: str, message: str, fix: str, refs: Iterable[str] = ()) -> dict:
    return {"rule": rule, "severity": severity, "where": where, "message": message, "fix": fix, "refs": list(refs)}


def score_findings(findings: List[dict]) -> dict:
    """100 minus penalties. A rule can cost at most twice its base points, so one noisy rule cannot zero the score."""
    spent: Dict[str, int] = {}
    for f in findings:
        base = SEV_POINTS[f["severity"]]
        spent[f["rule"]] = min(spent.get(f["rule"], 0) + base, base * 2)
    score = max(0, 100 - sum(spent.values()))
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_ORDER}
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 65 else "D" if score >= 50 else "F"
    if counts["critical"] and grade in ("A", "B", "C"):
        grade = "D"                                      # a critical issue always caps the grade
    return {"score": score, "grade": grade, "counts": counts}


def _sorted(findings: List[dict]) -> List[dict]:
    return sorted(findings, key=lambda f: SEV_ORDER.index(f["severity"]))


# =====================================================================
# 1a. CONTRACT AUDIT: OpenAPI
# =====================================================================
def parse_document(text: str):
    if not isinstance(text, str) or not text.strip():
        raise AIAppSecError(400, "The document is empty")
    if len(text) > MAX_DOC_CHARS:
        raise AIAppSecError(400, f"The document is larger than {MAX_DOC_CHARS // 1000} KB")
    try:
        return json.loads(text)
    except ValueError:
        pass
    except RecursionError:
        raise AIAppSecError(400, "The document is nested too deeply")
    try:
        import yaml                                      # optional dependency
    except ImportError:
        raise AIAppSecError(400, "This is not valid JSON. To audit YAML, install PyYAML (pip install pyyaml) or paste JSON.")
    try:
        if any(isinstance(ev, yaml.events.AliasEvent) for ev in yaml.parse(text)):
            raise AIAppSecError(400, "YAML anchors and aliases are not supported. Remove them or paste JSON.")
        return yaml.safe_load(text)
    except AIAppSecError:
        raise
    except Exception:
        raise AIAppSecError(400, "The document is neither valid JSON nor valid YAML")


def _deref(spec: dict, node, depth: int = 0):
    """Resolve local $ref pointers only (never fetches anything)."""
    seen = 0
    while isinstance(node, dict) and "$ref" in node and seen < 10:
        ref = node["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/"):
            return {}
        cur = spec
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            cur = cur.get(part) if isinstance(cur, dict) else None
            if cur is None:
                return {}
        node, seen = cur, seen + 1
    return node if isinstance(node, dict) else {}


def _walk_schema(spec: dict, schema, path: str, depth: int = 0, visiting: Optional[set] = None):
    """Yield (name_path, schema_dict) for the schema and every property / item beneath it."""
    visiting = visiting or set()
    if depth > 5 or not isinstance(schema, dict):
        return
    key = id(schema)
    s = _deref(spec, schema)
    if key in visiting:
        return
    visiting = visiting | {key}
    yield path, s
    for name, sub in (s.get("properties") or {}).items():
        yield from _walk_schema(spec, sub, f"{path}.{name}" if path else name, depth + 1, visiting)
    if isinstance(s.get("items"), dict):
        yield from _walk_schema(spec, s["items"], f"{path}[]", depth + 1, visiting)
    for combo in ("allOf", "oneOf", "anyOf"):
        for sub in (s.get(combo) or []):
            yield from _walk_schema(spec, sub, path, depth + 1, visiting)


METHODS = ("get", "put", "post", "delete", "patch", "options", "head")
WRITE = ("post", "put", "patch", "delete")
LLM_PATH = re.compile(r"(chat|completion|generate|prompt|assistant|agent|inference|embed|llm|ask)", re.I)
SENSITIVE_QUERY = re.compile(r"^(password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?token|ssn|card|cvv|authorization)$", re.I)
SSRF_NAME = re.compile(r"^(url|uri|callback|callback_url|webhook|webhook_url|endpoint|redirect|redirect_url|target)$", re.I)
PROMPT_NAME = re.compile(r"^(prompt|message|messages|input|query|question|text|content|instruction)s?$", re.I)
BOUNDED_FORMATS = {"date", "date-time", "uuid", "time", "int32", "int64", "byte", "binary", "uri-reference"}


def _string_unbounded(s: dict) -> bool:
    return s.get("type") == "string" and not any(k in s for k in ("maxLength", "enum", "pattern", "const")) and s.get("format") not in BOUNDED_FORMATS


def audit_openapi(spec) -> dict:
    if not isinstance(spec, dict) or not (spec.get("openapi") or spec.get("swagger")):
        raise AIAppSecError(400, "This does not look like an OpenAPI/Swagger document (missing 'openapi' or 'swagger')")
    paths = spec.get("paths") if isinstance(spec.get("paths"), dict) else {}
    findings: List[dict] = []
    oas3 = bool(spec.get("openapi"))
    schemes = (spec.get("components", {}) or {}).get("securitySchemes") if oas3 else spec.get("securityDefinitions")
    schemes = schemes if isinstance(schemes, dict) else {}
    global_sec = spec.get("security")
    info = spec.get("info") if isinstance(spec.get("info"), dict) else {}

    # ---- authentication model ----
    if not schemes:
        findings.append(_f("no_security_scheme", "critical", "document", "No authentication scheme is defined, so every endpoint is open.",
                           "Define a securityScheme (OAuth2, OIDC or API key in a header) and apply it globally.", [API10["API2"]]))
    for name, sch in schemes.items():
        sch = _deref(spec, sch)
        t, where = (sch.get("type") or "").lower(), f"securityScheme {name}"
        if t == "apikey" and (sch.get("in") or "").lower() == "query":
            findings.append(_f("apikey_in_query", "high", where, "The API key travels in the URL, where it ends up in logs, browser history and proxies.",
                               "Send the key in a header instead.", [API10["API2"]]))
        if (t == "http" and (sch.get("scheme") or "").lower() == "basic") or t == "basic":
            findings.append(_f("basic_auth", "medium", where, "HTTP Basic sends a reusable password with every request.",
                               "Use short-lived tokens (OAuth2/OIDC) instead.", [API10["API2"]]))

    # ---- transport ----
    urls = [str(s.get("url", "")) for s in (spec.get("servers") or []) if isinstance(s, dict)]
    if not oas3 and spec.get("schemes"):
        urls += [f"{sc}://{spec.get('host', 'host')}" for sc in spec["schemes"]]
    for u in urls:
        if u.lower().startswith(("http://", "ws://")) and not re.match(r"^(http|ws)://(localhost|127\.0\.0\.1|\[::1\])", u.lower()):
            findings.append(_f("plain_http", "high", f"server {u}", "Traffic is not encrypted.", "Serve the API over HTTPS only.", [API10["API8"]]))
    if not info.get("version"):
        findings.append(_f("no_version", "low", "info", "The API has no version, which makes inventory and retirement hard.", "Set info.version and keep an API inventory.", [API10["API9"]]))

    # ---- per operation ----
    any_429, any_rate_header = False, False
    for p, item in paths.items():
        item = _deref(spec, item)
        shared = [_deref(spec, x) for x in (item.get("parameters") or [])]
        for m in METHODS:
            op = item.get(m)
            if not isinstance(op, dict):
                continue
            tag = f"{m.upper()} {p}"
            is_llm = bool(LLM_PATH.search(p) or LLM_PATH.search(str(op.get("operationId", ""))))
            eff = op["security"] if "security" in op else global_sec
            if schemes and (eff is None or eff == []):
                sev = "high" if (m in WRITE or is_llm) else "medium"
                findings.append(_f("operation_unprotected", sev, tag, "This operation requires no authentication.",
                                   "Require authentication, or document why it is public.", [API10["API2"]]))
            responses = op.get("responses") if isinstance(op.get("responses"), dict) else {}
            codes = {str(c) for c in responses}
            if "429" in codes:
                any_429 = True
            for r in responses.values():
                hdrs = _deref(spec, r).get("headers") or {}
                if any(str(h).lower().startswith(("x-ratelimit", "ratelimit", "retry-after")) for h in hdrs):
                    any_rate_header = True
            if codes and not any(c.startswith("4") or c == "default" for c in codes):
                findings.append(_f("no_error_responses", "low", tag, "No client-error responses are documented.", "Document 400/401/403/404/429 responses.", [API10["API8"]]))

            params = shared + [_deref(spec, x) for x in (op.get("parameters") or [])]
            for prm in params:
                pname, loc = str(prm.get("name", "")), prm.get("in", "")
                sch = _deref(spec, prm.get("schema")) if oas3 else prm
                where = f"{tag} -> {loc} param '{pname}'"
                if loc == "query" and SENSITIVE_QUERY.match(pname):
                    findings.append(_f("sensitive_in_query", "high", where, "A sensitive value is sent in the URL.", "Move it to a header or the request body.", [API10["API2"]]))
                if SSRF_NAME.match(pname) and _string_unbounded(sch):
                    findings.append(_f("ssrf_param", "medium", where, "The server may fetch a caller-supplied address (SSRF).", "Allow-list destinations and block internal ranges.", [API10["API7"]]))
                if sch.get("type") in ("integer", "number") and re.match(r"^(limit|page_?size|per_?page|size|count|top)$", pname, re.I) and "maximum" not in sch:
                    findings.append(_f("unbounded_page_size", "medium", where, "Callers can request unlimited results.", "Set a maximum (for example 100).", [API10["API4"]]))
                elif _string_unbounded(sch):
                    findings.append(_f("unbounded_string", "low", where, "No length limit or pattern on this input.", "Add maxLength and a pattern or enum.", [API10["API4"]]))

            bodies: List[tuple] = []
            if oas3:
                content = _deref(spec, op.get("requestBody")).get("content") or {}
                bodies = [(mime, c.get("schema")) for mime, c in content.items() if isinstance(c, dict) and "json" in mime]
            else:
                bodies = [("json", prm.get("schema")) for prm in params if prm.get("in") == "body"]
            prompt_bounded = False
            has_prompt_field = False
            for _mime, bschema in bodies:
                for fname, s in _walk_schema(spec, bschema, "body"):
                    leaf = fname.split(".")[-1].replace("[]", "")
                    where = f"{tag} -> {fname}"
                    if s.get("type") == "object" and s.get("properties") and s.get("additionalProperties") is not False and fname == "body":
                        findings.append(_f("mass_assignment", "low", where, "Extra fields are accepted, which can let callers set properties they should not.",
                                           "Set additionalProperties: false.", [API10["API3"]]))
                    if s.get("type") == "array" and "maxItems" not in s:
                        findings.append(_f("unbounded_array", "low", where, "No limit on the number of items.", "Add maxItems.", [API10["API4"]]))
                    if s.get("type") in ("integer", "number") and not any(k in s for k in ("maximum", "exclusiveMaximum", "enum")):
                        findings.append(_f("unbounded_number", "low", where, "No upper bound on this number.", "Add minimum and maximum.", [API10["API4"]]))
                    if SSRF_NAME.match(leaf) and _string_unbounded(s):
                        findings.append(_f("ssrf_param", "medium", where, "The server may fetch a caller-supplied address (SSRF).", "Allow-list destinations and block internal ranges.", [API10["API7"]]))
                    if s.get("type") == "string":
                        if PROMPT_NAME.match(leaf):
                            has_prompt_field = True
                            prompt_bounded = prompt_bounded or "maxLength" in s
                        if _string_unbounded(s) and not PROMPT_NAME.match(leaf):
                            findings.append(_f("unbounded_string", "low", where, "No length limit or pattern on this input.", "Add maxLength and a pattern or enum.", [API10["API4"]]))
            if is_llm and m in WRITE:
                if not prompt_bounded:
                    findings.append(_f("llm_unbounded_prompt", "high", tag, "An AI endpoint accepts prompts of any size, which allows cost abuse and denial of service."
                                       if has_prompt_field else "An AI endpoint was found but no bounded prompt field is defined.",
                                       "Set maxLength on the prompt/message field and cap tokens server-side.", [LLM10["LLM10"], API10["API4"]]))
                if "429" not in codes:
                    findings.append(_f("llm_no_rate_limit", "high", tag, "An AI endpoint documents no rate limiting (no 429 response).",
                                       "Add per-user rate and spend limits, and document the 429 response.", [LLM10["LLM10"], API10["API4"]]))

    if paths and not (any_429 or any_rate_header):
        findings.append(_f("no_rate_limit", "medium", "document", "Nothing in the contract mentions rate limiting.", "Rate limit every endpoint and document 429 responses.", [API10["API4"]]))
    findings = _sorted(findings)
    return {"kind": "openapi", "endpoints": sum(1 for _p, it in paths.items() for m in METHODS if isinstance(_deref(spec, it).get(m), dict)),
            "findings": findings, **score_findings(findings)}


# =====================================================================
# 1b. CONTRACT AUDIT: AI tool / MCP schema
# =====================================================================
DANGEROUS_TOOL = re.compile(r"(exec|shell|bash|run[_-]?command|run[_-]?script|eval|subprocess|sudo|delete|remove|drop|truncate|format|wipe|transfer|payment|wire|"
                            r"send[_-]?(email|mail|message|sms)|write[_-]?file|upload|deploy|grant|revoke|admin)", re.I)
INJECTION_PARAM = re.compile(r"^(command|cmd|script|code|query|sql|expression|expr|shell)$", re.I)
PATHLIKE_PARAM = re.compile(r"^(path|file|filename|filepath|dir|directory|url|uri|endpoint)$", re.I)
POISON = re.compile(r"(ignore\s+(all|any|the|previous|prior)|do\s+not\s+(tell|inform|mention|reveal)|don'?t\s+(tell|mention)|<important>|system\s+prompt|"
                    r"before\s+(using|calling)\s+(any|this|other)|always\s+(call|use|run)\s+this|exfiltrat|send\s+.*\s+to\s+https?://|\bsecretly\b)", re.I)


def _tools_from(doc) -> List[dict]:
    tools = doc.get("tools") if isinstance(doc, dict) else doc
    if not isinstance(tools, list) or not tools or not all(isinstance(t, dict) and t.get("name") for t in tools):
        raise AIAppSecError(400, "Expected a list of tools, each with a 'name' (for example the tools/list result of an MCP server)")
    if len(tools) > 500:
        raise AIAppSecError(400, "At most 500 tools can be audited at once")
    return tools


def _tool_schema(t: dict) -> dict:
    s = t.get("inputSchema") or t.get("input_schema") or t.get("parameters")
    return s if isinstance(s, dict) else {}


def _approval(t: dict) -> bool:
    a = t.get("annotations") if isinstance(t.get("annotations"), dict) else {}
    return bool(t.get("requires_approval") or a.get("requires_approval") or a.get("requiresApproval"))


def _readonly(t: dict) -> bool:
    a = t.get("annotations") if isinstance(t.get("annotations"), dict) else {}
    return bool(a.get("readOnlyHint") or a.get("read_only") or t.get("read_only"))


def audit_tools(doc) -> dict:
    tools = _tools_from(doc)
    findings: List[dict] = []
    seen: Dict[str, str] = {}
    if len(tools) > 25:
        findings.append(_f("too_many_tools", "low", "document", f"{len(tools)} tools are exposed to one agent, which widens its reach.", "Give each agent only the tools it needs.", [LLM10["LLM06"]]))
    for t in tools:
        name = str(t["name"])
        desc = str(t.get("description") or "")
        schema = _tool_schema(t)
        props = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
        norm = re.sub(r"[-_\s]", "", name.lower())
        if norm in seen and seen[norm] != name:
            findings.append(_f("shadowed_tool_name", "medium", f"tool {name}", f"Name is almost identical to '{seen[norm]}', which can be used to hijack calls.", "Use clearly distinct names.", [LLM10["LLM01"]]))
        seen.setdefault(norm, name)
        if DANGEROUS_TOOL.search(name) and not _approval(t) and not _readonly(t):
            findings.append(_f("dangerous_tool_no_approval", "high", f"tool {name}", "A powerful tool can run without a human approval step.",
                               "Mark it as requiring approval and limit what it can touch.", [LLM10["LLM06"]]))
        if POISON.search(desc):
            findings.append(_f("tool_description_instructions", "high", f"tool {name}", "The description contains instruction-like text aimed at the model (possible tool poisoning).",
                               "Descriptions should only describe the tool. Review where this text came from.", [LLM10["LLM01"]]))
        elif len(desc) > 1500:
            findings.append(_f("tool_description_long", "medium", f"tool {name}", "A very long description can hide instructions.", "Keep descriptions short and review them.", [LLM10["LLM01"]]))
        if not schema:
            findings.append(_f("tool_no_schema", "medium", f"tool {name}", "No input schema, so arguments cannot be validated.", "Define an inputSchema with types and limits.", [LLM10["LLM06"]]))
        elif schema.get("additionalProperties") is not False:
            findings.append(_f("tool_extra_args", "low", f"tool {name}", "Unknown arguments are accepted.", "Set additionalProperties: false.", [LLM10["LLM06"]]))
        for pname, ps in props.items():
            ps = ps if isinstance(ps, dict) else {}
            where = f"tool {name} -> {pname}"
            free = ps.get("type") == "string" and not any(k in ps for k in ("enum", "pattern", "const"))
            if INJECTION_PARAM.match(pname) and free:
                findings.append(_f("tool_injection_param", "high", where, "Free text is passed into a command, query or code argument.",
                                   "Restrict it to an enum or pattern, or use parameterised calls.", [LLM10["LLM05"], LLM10["LLM06"]]))
            elif PATHLIKE_PARAM.match(pname) and free:
                findings.append(_f("tool_path_param", "medium", where, "Free text path or URL can reach files or internal services.", "Allow-list directories/hosts and reject '..'.", [LLM10["LLM06"]]))
            elif free and "maxLength" not in ps:
                findings.append(_f("tool_unbounded_string", "low", where, "No length limit on this argument.", "Add maxLength.", [LLM10["LLM10"]]))
    findings = _sorted(findings)
    return {"kind": "tools", "endpoints": len(tools), "findings": findings, **score_findings(findings)}


# =====================================================================
# 2. ALLOW-LIST POLICY FROM A CONTRACT
# =====================================================================
def generate_policy(doc) -> dict:
    tools = _tools_from(doc)
    policy: Dict[str, dict] = {}
    for t in tools:
        schema = _tool_schema(t)
        required = set(schema.get("required") or [])
        args = {}
        for pname, ps in (schema.get("properties") or {}).items():
            ps = ps if isinstance(ps, dict) else {}
            a = {"type": ps.get("type", "string"), "required": pname in required}
            if a["type"] == "string":
                a["maxLength"] = int(ps.get("maxLength", 2000))
                for k in ("enum", "pattern"):
                    if k in ps:
                        a[k] = ps[k]
            elif a["type"] in ("integer", "number"):
                for k in ("minimum", "maximum"):
                    if k in ps:
                        a[k] = ps[k]
            elif a["type"] == "array":
                a["maxItems"] = int(ps.get("maxItems", 50))
            args[pname] = a
        policy[str(t["name"])] = {"requires_approval": _approval(t) or bool(DANGEROUS_TOOL.search(str(t["name"])) and not _readonly(t)), "args": args}
    return {"default": "deny", "tools": policy}


try:                                                   # Python 3.11+ keeps the regex parser in re._parser
    import re._parser as _sre_parse
    from re import _constants as _sre_const
except ImportError:                                    # older Pythons
    import sre_parse as _sre_parse
    import sre_constants as _sre_const

PATTERN_INPUT_MAX = 256          # values longer than this are not matched against a contract pattern
_REPEATS = tuple(getattr(_sre_const, n) for n in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT") if hasattr(_sre_const, n))


def _walk_sre(node):
    """Yield every (op, args) in a parsed regex, however deeply nested."""
    items = getattr(node, "data", None)
    if items is None:
        if isinstance(node, (list, tuple)):
            for x in node:
                yield from _walk_sre(x)
        return
    for op, av in items:
        yield op, av
        yield from _walk_sre(av)


def pattern_problem(pattern: str) -> Optional[str]:
    """Why a contract-supplied regex is not safe to run, or None.
    Python's regex engine can backtrack without limit and cannot be interrupted, so only simple shapes are allowed:
    no repeat inside a repeat, no alternation inside a repeat, no back-references, at most 3 open-ended repeats."""
    if not isinstance(pattern, str) or len(pattern) > 200:
        return "too long"
    try:
        parsed = _sre_parse.parse(pattern)
    except Exception:
        return "unusable"
    open_ended = 0
    for op, av in _walk_sre(parsed):
        if op == _sre_const.GROUPREF:
            return "complex"
        if op in _REPEATS:
            mn, mx, sub = av
            if mx > 100:
                open_ended += 1
            if mx > 1 and any(o in _REPEATS and a2[1] > 1 or o == _sre_const.BRANCH for o, a2 in _walk_sre(sub)):
                return "complex"
    return "complex" if open_ended > 3 else None


_TYPES = {"string": str, "integer": int, "number": (int, float), "boolean": bool, "array": list, "object": dict}


def enforce(policy: dict, call: dict) -> dict:
    """Check one tool call against a generated policy. Deny by default."""
    reasons: List[str] = []
    if not isinstance(policy, dict) or not isinstance(policy.get("tools"), dict):
        raise AIAppSecError(400, "Invalid policy")
    try:
        if len(json.dumps(policy, default=str)) > MAX_DOC_CHARS or len(json.dumps(call, default=str)) > 200_000:
            raise AIAppSecError(400, "The policy or the call is too large")
    except (TypeError, ValueError, RecursionError):
        raise AIAppSecError(400, "The policy or the call is not valid JSON data")
    tool = str((call or {}).get("tool", ""))
    args = (call or {}).get("args")
    args = args if isinstance(args, dict) else {}
    spec = policy["tools"].get(tool)
    if spec is None:
        return {"decision": "deny", "reasons": [f"Tool '{tool}' is not in the contract"]}
    allowed = spec.get("args", {})
    for k in args:
        if k not in allowed:
            reasons.append(f"Unexpected argument '{k}'")
    for k, a in allowed.items():
        if a.get("required") and k not in args:
            reasons.append(f"Missing required argument '{k}'")
    for k, v in args.items():
        a = allowed.get(k)
        if not a:
            continue
        want = _TYPES.get(a.get("type", "string"), str)
        if isinstance(v, bool) and a.get("type") in ("integer", "number"):
            reasons.append(f"'{k}' must be a {a['type']}")
            continue
        if not isinstance(v, want):
            reasons.append(f"'{k}' must be a {a.get('type', 'string')}")
            continue
        if isinstance(v, str):
            if len(v) > int(a.get("maxLength", 2000)):
                reasons.append(f"'{k}' is longer than {a.get('maxLength', 2000)} characters")
                continue
            if "enum" in a and v not in a["enum"]:
                reasons.append(f"'{k}' is not one of the allowed values")
            if a.get("pattern"):
                problem = pattern_problem(str(a["pattern"]))
                if problem == "unusable":
                    reasons.append(f"'{k}' has an unusable pattern in the contract")
                elif problem:
                    reasons.append(f"'{k}' has a pattern that is too complex to check safely")
                elif len(v) > PATTERN_INPUT_MAX:
                    reasons.append(f"'{k}' is too long to check against its pattern (over {PATTERN_INPUT_MAX} characters)")
                elif not re.search(str(a["pattern"]), v):
                    reasons.append(f"'{k}' does not match the required pattern")
            if PATHLIKE_PARAM.match(k) and (".." in v.replace("\\", "/").split("/") or v.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", v)):
                reasons.append(f"'{k}' looks like a path traversal or absolute path")
            try:                                          # reuse the platform's prompt/secret inspector on every text argument
                from ai_security import inspect_text
                res = inspect_text(v, "tool_call")
                if res.get("verdict") == "block":
                    reasons.append(f"'{k}' was blocked by the guardrail ({res['findings'][0]['name']})")
            except Exception:
                pass
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            if "minimum" in a and v < a["minimum"]:
                reasons.append(f"'{k}' is below {a['minimum']}")
            if "maximum" in a and v > a["maximum"]:
                reasons.append(f"'{k}' is above {a['maximum']}")
        if isinstance(v, list) and len(v) > int(a.get("maxItems", 50)):
            reasons.append(f"'{k}' has more than {a.get('maxItems', 50)} items")
    if reasons:
        return {"decision": "deny", "reasons": reasons}
    if spec.get("requires_approval"):
        return {"decision": "needs_approval", "reasons": ["This tool requires a human approval"]}
    return {"decision": "allow", "reasons": []}


# =====================================================================
# 3. AI-IN-CODE SCANNER
# =====================================================================
# (provider, kind, patterns).  kind -> asset type: api->model, local->model, framework->app, vector->vector_db, mcp->mcp_server
PROVIDERS = [
    ("OpenAI", "api", r"(\bimport\s+openai\b|from\s+openai\s+import|require\(['\"]openai['\"]\)|from\s+['\"]openai['\"]|\"openai\"\s*:|^openai\s*[=<>~!]|api\.openai\.com)"),
    ("Azure OpenAI", "api", r"(openai\.azure\.com|AzureOpenAI)"),
    ("Anthropic", "api", r"(\bimport\s+anthropic\b|from\s+anthropic\s+import|@anthropic-ai/sdk|require\(['\"]anthropic['\"]\)|from\s+['\"]anthropic['\"]|^anthropic\s*[=<>~!]|api\.anthropic\.com)"),
    ("Google Gemini", "api", r"(google\.generativeai|google-generativeai|from\s+google\s+import\s+genai|@google/generative-ai|generativelanguage\.googleapis\.com)"),
    ("Groq", "api", r"(\bimport\s+groq\b|from\s+groq\s+import|groq-sdk|api\.groq\.com|^groq\s*[=<>~!])"),
    ("Mistral", "api", r"(mistralai|api\.mistral\.ai)"),
    ("Cohere", "api", r"(\bimport\s+cohere\b|cohere-ai|api\.cohere\.(com|ai)|^cohere\s*[=<>~!])"),
    ("OpenRouter", "api", r"openrouter\.ai"),
    ("AWS Bedrock", "api", r"(bedrock-runtime|bedrock_runtime|invoke_model\()"),
    ("Hugging Face", "local", r"(\bfrom\s+transformers\s+import|\bimport\s+transformers\b|huggingface_hub|api-inference\.huggingface\.co|AutoModelFor)"),
    ("Ollama", "local", r"(\bimport\s+ollama\b|localhost:11434|127\.0\.0\.1:11434)"),
    ("vLLM", "local", r"(\bimport\s+vllm\b|from\s+vllm\s+import)"),
    ("LangChain", "framework", r"(\blangchain\b|\blanggraph\b)"),
    ("LlamaIndex", "framework", r"(llama_index|llama-index)"),
    ("Vector database", "vector", r"(chromadb|pinecone|weaviate|qdrant_client|\bfaiss\b|pgvector|lancedb)"),
    ("MCP", "mcp", r"(from\s+mcp\b|import\s+mcp\b|@modelcontextprotocol|modelcontextprotocol)"),
]
PROVIDERS_RE = [(n, k, re.compile(p, re.I | re.M)) for n, k, p in PROVIDERS]
KIND_TO_ASSET = {"api": "model", "local": "model", "framework": "app", "vector": "vector_db", "mcp": "mcp_server"}

KEY_PATTERNS = [
    ("OpenAI API key", re.compile(r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}")),
    ("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("Groq API key", re.compile(r"gsk_[A-Za-z0-9]{20,}")),
    ("Hugging Face token", re.compile(r"hf_[A-Za-z0-9]{30,}")),
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
]
GENERIC_KEY = re.compile(r"(openai|anthropic|gemini|groq|mistral|cohere|llm|ai)[_-]?(api)?[_-]?key\s*[=:]\s*['\"]([^'\"\s]{16,})['\"]", re.I)
PLACEHOLDER = re.compile(r"(x{4,}|your[_-]|<|>|\*{3,}|example|changeme|placeholder|dummy|fake|test|\.\.\.|\$\{|%s)", re.I)
LLMISH = r"(response|completion|completions|choices|message\.content|llm|model_output|generated|answer|output_text|ai_reply|reply)"

CODE_RULES = [
    ("unsafe_deserialization", "high", re.compile(r"\b(pickle\.loads?|dill\.loads?|cloudpickle\.loads?|joblib\.load)\s*\("), None,
     "Loading a pickle can run attacker code, and model files are a common carrier.", "Use safetensors or another safe format and verify file hashes.", ["LLM03"]),
    ("torch_load_unsafe", "high", re.compile(r"\btorch\.load\s*\((?![^)]*weights_only\s*=\s*True)"), None,
     "torch.load can execute code from a model file.", "Pass weights_only=True or use safetensors.", ["LLM03"]),
    ("trust_remote_code", "high", re.compile(r"trust_remote_code\s*=\s*True"), None,
     "Downloaded model code will be executed on your machine.", "Leave it off unless the exact revision was reviewed and pinned.", ["LLM03"]),
    ("exec_model_output", "critical", re.compile(r"\b(eval|exec)\s*\("), re.compile(LLMISH, re.I),
     "Model output is executed as code, so a prompt injection becomes remote code execution.", "Never execute model output. Parse it as data and validate it.", ["LLM05"]),
    ("shell_model_output", "critical", re.compile(r"(subprocess\.(run|Popen|call|check_output)|os\.system|child_process\.(exec|spawn))"), re.compile(LLMISH, re.I),
     "Model output reaches a shell command.", "Use fixed commands with an allow-listed argument set and human approval.", ["LLM05", "LLM06"]),
    ("html_model_output", "high", re.compile(r"(innerHTML\s*=|dangerouslySetInnerHTML|\.html\()"), re.compile(LLMISH, re.I),
     "Model output is written into the page as HTML (cross-site scripting).", "Render it as text or sanitise it first.", ["LLM05"]),
    ("sql_model_output", "high", re.compile(r"\.execute\(\s*f?['\"].*(\{|\+|%s)"), re.compile(LLMISH, re.I),
     "A SQL statement appears to be built from model output.", "Use parameterised queries and a read-only account.", ["LLM05"]),
    ("dangerous_agent_tool", "high", re.compile(r"(ShellTool|PythonREPLTool|PythonAstREPLTool|BashProcess|allow_dangerous_code\s*=\s*True|allow_dangerous_requests\s*=\s*True)"), None,
     "An agent is given a tool that can run arbitrary code or commands.", "Remove it, or sandbox it and require human approval.", ["LLM06"]),
    ("prompt_from_user_input", "medium", re.compile(r"f['\"][^'\"\n]*\{(user|request|req|input|query|message|question|prompt)[\w\.\[\]'\"]*\}[^'\"\n]*['\"]"),
     re.compile(r"(prompt|system|messages|content)", re.I),
     "User input is pasted straight into a prompt (heuristic).", "Keep user text in a separate message role and treat it as untrusted.", ["LLM01"]),
    ("prompt_in_logs", "low", re.compile(r"(logger|logging|console)\.(debug|info|log|warn|warning)\s*\("), re.compile(r"(prompt|messages|completion|conversation)", re.I),
     "Prompts or answers may be written to logs, which can leak personal data.", "Redact before logging and limit retention.", ["LLM02"]),
    ("tls_verify_off", "medium", re.compile(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false"), None,
     "TLS certificate checking is switched off.", "Leave certificate verification on.", []),
]


def _scrub(line: str) -> str:
    """Remove every credential-looking value from a code line before it is shown or stored."""
    for _label, krx in KEY_PATTERNS:
        line = krx.sub("[REDACTED]", line)
    line = GENERIC_KEY.sub(lambda m: m.group(0).replace(m.group(3), "[REDACTED]"), line)
    try:
        from ai_security import redact
        line = redact(line)
    except Exception:
        pass
    return line


def _mask(s: str) -> str:
    return f"{s[:4]}…({len(s)} chars)"


def _is_placeholder(s: str) -> bool:
    return bool(PLACEHOLDER.search(s))


def scan_code(files: List[dict], registered: Optional[List[dict]] = None, scan_name: str = "code") -> dict:
    if not isinstance(files, list) or not files:
        raise AIAppSecError(400, "No files to scan")
    if len(files) > MAX_FILES:
        raise AIAppSecError(400, f"At most {MAX_FILES} files per scan")
    total = sum(len(str(f.get("content", ""))) for f in files if isinstance(f, dict))
    if total > MAX_TOTAL_CHARS:
        raise AIAppSecError(400, f"The files are larger than {MAX_TOTAL_CHARS // 1_000_000} MB in total")
    findings: List[dict] = []
    comps: Dict[str, dict] = {}
    n_lines = n_files = 0
    for f in files:
        if not isinstance(f, dict):
            continue
        path, content = str(f.get("path", "file"))[:200], str(f.get("content", ""))[:MAX_FILE_CHARS]
        n_files += 1
        for ln, line in enumerate(content.splitlines(), 1):
            n_lines += 1
            line = line[:2000]
            stripped = line.strip()
            for prov, kind, rx in PROVIDERS_RE:
                if rx.search(line):
                    c = comps.setdefault(prov, {"provider": prov, "kind": kind, "files": [], "mentions": 0})
                    c["mentions"] += 1
                    if path not in c["files"] and len(c["files"]) < 10:
                        c["files"].append(path)
            for label, krx in KEY_PATTERNS:
                for m in krx.finditer(line):
                    if not _is_placeholder(m.group(0)):
                        findings.append({**_f("exposed_ai_key", "critical", f"{path}:{ln}", f"{label} is written in the code.", "Revoke the key now, move it to a secret store or environment variable, and clean it from Git history.", ["LLM02"]),
                                         "file": path, "line": ln, "evidence": _mask(m.group(0))})
            gm = GENERIC_KEY.search(line)
            if gm and not _is_placeholder(gm.group(3)) and not any(x["file"] == path and x["line"] == ln for x in findings):
                findings.append({**_f("exposed_ai_key", "critical", f"{path}:{ln}", "An AI credential is assigned in plain text.", "Revoke it, store it in a secret manager and read it from the environment.", ["LLM02"]),
                                 "file": path, "line": ln, "evidence": _mask(gm.group(3))})
            if stripped.startswith(("#", "//", "*", "/*")):
                continue
            for rid, sev, rx, ctx, msg, fix, refs in CODE_RULES:
                if rx.search(line) and (ctx is None or ctx.search(line)):
                    findings.append({**_f(rid, sev, f"{path}:{ln}", msg, fix, [LLM10[r] for r in refs]), "file": path, "line": ln, "evidence": _scrub(stripped)[:120]})
    reg = registered or []
    reg_names = {str(a.get("name", "")).lower() for a in reg}
    reg_providers = " ".join(str(a.get("provider", "")).lower() for a in reg)
    components = []
    for prov, c in sorted(comps.items()):
        base = scan_name.strip()[:40] or "code"
        suggested_name = f"{prov} (code: {base})"[:80]
        # "registered" means THIS service's use of the provider is in the inventory (matched by name).
        # A provider that merely appears elsewhere in the inventory does not make this code approved.
        components.append({**c, "registered": suggested_name.lower() in reg_names, "provider_in_inventory": prov.lower() in reg_providers, "suggested_asset": {
            "name": suggested_name, "asset_type": KIND_TO_ASSET[c["kind"]], "provider": prov if c["kind"] in ("api", "local") else "",
            "environment": "dev", "model_format": "api" if c["kind"] == "api" else "n/a", "approved": False,
            "notes": f"Found in code scan '{base}' ({c['mentions']} mention(s) in {len(c['files'])} file(s))."}})
    findings = _sorted(findings)
    sc = score_findings(findings)
    return {"files": n_files, "lines": n_lines, "findings": findings, "components": components,
            "shadow_ai": sum(1 for c in components if not c["registered"]), **sc}


# =====================================================================
# STORAGE
# =====================================================================
DDL = """
CREATE TABLE IF NOT EXISTS ai_contract_audits (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, asset_id TEXT, kind TEXT NOT NULL, name TEXT NOT NULL, doc_hash TEXT,
    score INTEGER, grade TEXT, critical INTEGER DEFAULT 0, high INTEGER DEFAULT 0, endpoints INTEGER DEFAULT 0,
    findings TEXT, created_by TEXT, created_at TEXT);
CREATE INDEX IF NOT EXISTS idx_aica_tenant ON ai_contract_audits(tenant_id, created_at);
CREATE TABLE IF NOT EXISTS ai_code_scans (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL, files_count INTEGER, lines INTEGER, score INTEGER, grade TEXT,
    findings TEXT, components TEXT, created_by TEXT, created_at TEXT);
CREATE INDEX IF NOT EXISTS idx_aics_tenant ON ai_code_scans(tenant_id, created_at);
"""


def init_ai_appsec_db() -> None:
    with closing(get_db()) as conn:
        conn.executescript(DDL)
        conn.commit()


def _trim(conn, table: str, tenant_id: str) -> None:
    conn.execute(f"DELETE FROM {table} WHERE tenant_id=? AND id NOT IN (SELECT id FROM {table} WHERE tenant_id=? ORDER BY created_at DESC, rowid DESC LIMIT ?)",
                 (tenant_id, tenant_id, KEEP_PER_TENANT))


def run_contract_audit(tenant_id: str, name: str, kind: str, content: str, asset_id: Optional[str], actor: str) -> dict:
    name = (name or "").strip()
    if not 2 <= len(name) <= 80:
        raise AIAppSecError(400, "Name must be 2 to 80 characters")
    if kind not in ("openapi", "tools"):
        raise AIAppSecError(400, "Kind must be 'openapi' or 'tools'")
    doc = parse_document(content)
    try:
        res = audit_openapi(doc) if kind == "openapi" else audit_tools(doc)
    except RecursionError:
        raise AIAppSecError(400, "The document is nested too deeply")
    if asset_id:
        with closing(get_db()) as conn:
            if not conn.execute("SELECT 1 FROM ai_assets WHERE id=? AND tenant_id=?", (asset_id, tenant_id)).fetchone():
                raise AIAppSecError(404, "AI asset not found")
    aid = "aud-" + uuid.uuid4().hex[:8]
    with closing(get_db()) as conn:
        conn.execute("INSERT INTO ai_contract_audits (id, tenant_id, asset_id, kind, name, doc_hash, score, grade, critical, high, endpoints, findings, created_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     (aid, tenant_id, asset_id, kind, name, hashlib.sha256(content.encode("utf-8", "ignore")).hexdigest(), res["score"], res["grade"],
                      res["counts"]["critical"], res["counts"]["high"], res["endpoints"], json.dumps(res["findings"]), actor, _ts()))
        _trim(conn, "ai_contract_audits", tenant_id)
        conn.commit()
    return {"id": aid, "name": name, "asset_id": asset_id, "created_by": actor, "created_at": _ts(), **res}


def list_audits(tenant_id: str, limit: int = 50) -> List[dict]:
    with closing(get_db()) as conn:
        rows = conn.execute("SELECT id, asset_id, kind, name, score, grade, critical, high, endpoints, created_by, created_at FROM ai_contract_audits WHERE tenant_id=? ORDER BY created_at DESC, rowid DESC LIMIT ?",
                            (tenant_id, max(1, min(limit, 200)))).fetchall()
    return [dict(r) for r in rows]


def get_audit(tenant_id: str, audit_id: str) -> dict:
    with closing(get_db()) as conn:
        r = conn.execute("SELECT * FROM ai_contract_audits WHERE id=? AND tenant_id=?", (audit_id, tenant_id)).fetchone()
    if not r:
        raise AIAppSecError(404, "Audit not found")
    d = dict(r)
    d["findings"] = json.loads(d["findings"] or "[]")
    d["counts"] = {s: sum(1 for f in d["findings"] if f["severity"] == s) for s in SEV_ORDER}
    return d


def run_code_scan(tenant_id: str, name: str, files: List[dict], actor: str) -> dict:
    name = (name or "").strip()
    if not 2 <= len(name) <= 80:
        raise AIAppSecError(400, "Name must be 2 to 80 characters")
    try:
        from ai_security import list_assets
        registered = list_assets(tenant_id)
    except Exception:
        registered = []
    res = scan_code(files, registered, name)
    sid = "scn-" + uuid.uuid4().hex[:8]
    with closing(get_db()) as conn:
        conn.execute("INSERT INTO ai_code_scans (id, tenant_id, name, files_count, lines, score, grade, findings, components, created_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                     (sid, tenant_id, name, res["files"], res["lines"], res["score"], res["grade"], json.dumps(res["findings"]), json.dumps(res["components"]), actor, _ts()))
        _trim(conn, "ai_code_scans", tenant_id)
        conn.commit()
    return {"id": sid, "name": name, "created_by": actor, "created_at": _ts(), **res}


def list_scans(tenant_id: str, limit: int = 50) -> List[dict]:
    with closing(get_db()) as conn:
        rows = conn.execute("SELECT id, name, files_count, lines, score, grade, created_by, created_at, findings, components FROM ai_code_scans WHERE tenant_id=? ORDER BY created_at DESC, rowid DESC LIMIT ?",
                            (tenant_id, max(1, min(limit, 200)))).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["findings_count"] = len(json.loads(d.pop("findings") or "[]"))
        d["components_count"] = len(json.loads(d.pop("components") or "[]"))
        out.append(d)
    return out


def get_scan(tenant_id: str, scan_id: str) -> dict:
    with closing(get_db()) as conn:
        r = conn.execute("SELECT * FROM ai_code_scans WHERE id=? AND tenant_id=?", (scan_id, tenant_id)).fetchone()
    if not r:
        raise AIAppSecError(404, "Scan not found")
    d = dict(r)
    d["findings"], d["components"] = json.loads(d["findings"] or "[]"), json.loads(d["components"] or "[]")
    d["counts"] = {s: sum(1 for f in d["findings"] if f["severity"] == s) for s in SEV_ORDER}
    return d


def register_components(tenant_id: str, scan_id: str, providers: Optional[List[str]] = None) -> dict:
    """Add the AI components a scan found to the AI asset inventory as unapproved (shadow AI) assets."""
    from ai_security import AIError, create_asset
    scan = get_scan(tenant_id, scan_id)
    wanted = {p.lower() for p in providers} if providers else None
    created, skipped = [], []
    for c in scan["components"]:
        if c["registered"] or (wanted is not None and c["provider"].lower() not in wanted):
            continue
        try:
            created.append(create_asset(tenant_id, c["suggested_asset"])["name"])
        except AIError as exc:
            if exc.status == 409:
                skipped.append(c["suggested_asset"]["name"])
            else:
                raise AIAppSecError(exc.status, exc.message)
    return {"created": created, "already_existed": skipped}


# =====================================================================
# 4. QUALITY GATES
# =====================================================================
MIN_AUDIT_SCORE = int(os.getenv("SOC_AI_GATE_MIN_SCORE", "70"))


def latest_audit_for_asset(tenant_id: str, asset_id: str) -> Optional[dict]:
    with closing(get_db()) as conn:
        r = conn.execute("SELECT id, name, score, grade, critical, high, created_at FROM ai_contract_audits WHERE tenant_id=? AND asset_id=? ORDER BY created_at DESC, rowid DESC LIMIT 1",
                         (tenant_id, asset_id)).fetchone()
    return dict(r) if r else None


def evaluate_gate(asset: dict, audit: Optional[dict]) -> dict:
    """Which conditions must hold before this asset may be approved. Pure function."""
    crit: List[dict] = []
    def add(cid, label, required, passed, detail):
        crit.append({"id": cid, "label": label, "required": required, "passed": bool(passed), "detail": detail})
    typed = asset.get("asset_type") in ("model", "agent", "app")
    live = asset.get("environment") in ("prod", "staging")
    add("owner", "Has a named owner", True, (asset.get("owner") or "").strip(), "Every AI asset needs someone accountable.")
    add("guardrail", "Runtime guardrail enabled", typed and live, asset.get("guardrail"), "Models, agents and apps that are live should be protected at runtime.")
    add("format", "Model file format is safe", True, asset.get("model_format") != "pickle", "Pickle files can run code when loaded.")
    needs_contract = bool(asset.get("tool_access") or asset.get("internet_exposed"))
    if needs_contract:
        ok = bool(audit) and audit["score"] >= MIN_AUDIT_SCORE and not audit["critical"]
        detail = ("No contract audit yet" if not audit else
                  f"Latest audit scored {audit['score']} ({audit['grade']}) with {audit['critical']} critical and {audit['high']} high finding(s); needs {MIN_AUDIT_SCORE}+ and no critical findings")
        add("contract", "Contract audit passed", True, ok, detail)
    if asset.get("handles_pii") or asset.get("data_classification") in ("confidential", "restricted"):
        add("sensitive", "Sensitive data is protected by a guardrail", True, asset.get("guardrail"), "Personal or confidential data needs output and secret filtering.")
    blockers = [c for c in crit if c["required"] and not c["passed"]]
    return {"passed": not blockers, "blockers": len(blockers), "criteria": crit}


def asset_gate(tenant_id: str, asset_id: str) -> dict:
    from ai_security import list_assets
    asset = next((a for a in list_assets(tenant_id) if a["id"] == asset_id), None)
    if not asset:
        raise AIAppSecError(404, "AI asset not found")
    return {"asset_id": asset_id, "name": asset["name"], "approved": bool(asset.get("approved")), **evaluate_gate(asset, latest_audit_for_asset(tenant_id, asset_id))}


def enforce_gate(tenant_id: str, data: dict, asset_id: Optional[str] = None) -> None:
    """Optional hard stop: with SOC_AI_GATE_ENFORCE=1, an asset cannot be saved as approved while the gate fails."""
    if os.getenv("SOC_AI_GATE_ENFORCE", "0") != "1" or not data.get("approved"):
        return
    res = evaluate_gate(data, latest_audit_for_asset(tenant_id, asset_id) if asset_id else None)
    if not res["passed"]:
        failed = "; ".join(f"{c['label']}: {c['detail']}" for c in res["criteria"] if c["required"] and not c["passed"])
        raise AIAppSecError(409, f"Cannot approve yet. {failed}")
