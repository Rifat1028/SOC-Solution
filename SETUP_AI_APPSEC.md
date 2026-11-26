# AI AppSec drop (in-house, no third-party tools)

New files (project root): `ai_appsec.py`, `ai_appsec_routes.py`, `tests/test_ai_appsec.py`
Changed files: `main.py` (2 imports, 1 startup call, 1 include_router, 3 audit labels), `ai_routes.py` (approval gate hook),
`ui/index.html` (2 new AI tabs, Contract Audit and AI Code Scan, + a Gate button on AI Assets).

**Use the `ai_routes.py` and `main.py` from this folder.** An older copy of `ai_routes.py` lacks the AI Discovery, AI Posture, AI Gateway and protected-terms routes and would remove them.
New dependency: none. YAML input needs PyYAML (`pip install pyyaml`); JSON works without it.

Run the tests (own temp database, your data is untouched):

    python -m unittest discover -s tests -v

Settings (all optional):
- `SOC_AI_GATE_ENFORCE=1`    block saving an AI asset as "approved" while its gate fails (default off: the gate only informs)
- `SOC_AI_GATE_MIN_SCORE=70` minimum contract-audit score for assets with tools or internet access

What it does
- Contract audit: scores an OpenAPI document or an AI tool / MCP schema and explains each weakness (mapped to OWASP API and LLM lists).
- Allow-list policy: turns a tool contract into a deny-by-default policy and checks individual tool calls against it.
- AI code scan: finds AI services in code (shadow AI), exposed AI keys, unsafe model loading, unsafe use of model output.
  Secrets are masked in results; source code and audited documents are never stored (only findings and a document hash).
- Approval gate: owner, runtime guardrail, safe model format, and a passing contract audit for assets with tools or internet exposure.

Limits to know
- The code scanner is pattern-based (fast, no dependencies). It misses indirect flows and can flag false positives.
  Treat "prompt_from_user_input" in particular as a hint, not a verdict.
- Contract audit checks the document, not the live API. It cannot prove the running service matches the contract.
- The policy tester shows decisions; wiring enforce() in front of a real agent's tool calls is a separate step.

## Review notes (hardening applied to `ai_appsec.py`)

1. **Contract patterns could hang the server.** `check-call` runs a regex taken from the contract. Python's regex engine can backtrack without limit and cannot be interrupted, so a pattern such as `(a+)+$` pinned a worker thread forever.
   Patterns are now screened first: no repeat inside a repeat, no alternation inside a repeat, no back-references, at most 3 open-ended repeats, and values over 256 characters are not matched. Refused patterns produce a clear "too complex to check safely" reason. Ordinary patterns (`^[a-z0-9_\-]{1,64}$`, `^(GET|POST)$`) are unaffected.
2. **YAML anchors and aliases are refused.** They let a small document expand into a huge structure and multiply the auditor's work. Plain YAML and JSON still work.
3. **Secrets can no longer reach stored evidence.** A code line that matched a key rule and another rule had its full text saved as evidence. Every evidence line is now scrubbed of key-like values before it is shown or stored.
4. **Size limits** on the policy and call bodies of `check-call` (1 MB and 200 KB), and very deeply nested documents now return a clean 400 instead of an error.

Tests: `tests/test_ai_appsec_api.py` (13 tests: the four fixes, role limits, tenant scoping, audit entries, the gate with `SOC_AI_GATE_ENFORCE`, registration is idempotent, existing AI routes still work).
The other suites were changed to share one test database, so `python -m unittest discover -s tests -v` now runs all 129 tests in one go.
