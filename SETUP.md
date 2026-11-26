# What changed in this drop

Copy over your project (same names): `main.py`, `db.py`, `ui/index.html` (the file called index.html here).
New files in the project root: `soc_health.py`, `health_routes.py`, `verify_evidence.py`. New folder: `tests/`.
No new dependencies (uses `cryptography`, already required by db.py, and `httpx`, already used by engines.py).

Run the tests (own temp database, your data is untouched):

    python -m unittest discover -s tests -v

Settings (all optional):
- `SOC_DEMO_HEALTH=0`  stop the demo EPS sampler once real connectors call `POST /api/v1/health/heartbeat`
- The Sources & Rules page shows a "Demo data" chip while alert history is simulated.

## Still demo / not real yet
- Alert history behind Rule Health is seeded demo data. It becomes real when alerts are stored server-side;
  until then only new Mark-False-Positive / Isolate clicks add real verdicts.
- Source health samples are simulated until connectors send heartbeats.
- KEV / EPSS values only appear after you click "Refresh free feeds" (server needs internet access).
- MTTD and SLA compliance are not in the report: detection / first-response timestamps are not stored yet.
