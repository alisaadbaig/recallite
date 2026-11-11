"""
recallite.uat — User Acceptance Test runner against a REAL model.

The benchmark (recallite bench) proves retrieval math; UAT proves the whole
product: real backend, real prompts, expected answers.

    recallite uat --backend openai --model openai/gpt-oss-20b \
                 --url http://localhost:8000/v1 --report uat_report.json

- Prompts ship with each release in uat_prompts.json (override: --prompts FILE).
- Each case runs in its own fresh database: zero cross-contamination.
- Secure-mode cases use a dedicated test password read from --password-file
  (default ~/.recallite_uat_pass, chmod 600 recommended) — never hard-coded.
- The report (text to stdout, JSON via --report) records pass/fail per
  prompt, latency, which model answered, and the recallite version.
- Exit code 0 only if every case passes, so it drops into CI or cron:

    # nightly at 02:00
    0 2 * * * recallite uat --backend openai --model openai/gpt-oss-20b \
        --url http://localhost:8000/v1 \
        --report ~/uat-reports/uat-$(date +\\%F).json >> ~/uat-reports/uat.log 2>&1

Case format (JSON list):
    {
      "name": "recall-age",
      "secure": false,              # create the store in secure mode
      "setup": ["/enable ...", "/save age ..."],   # commands run first
      "prompt": "How old am I?",    # sent to the model (or a /command)
      "expect": {
        "contains_all": ["36"],     # every string must appear (case-insens.)
        "contains_any": [...],      # at least one must appear
        "not_contains": [...],      # none may appear
        "regex": "...",             # re.search, case-insensitive
        "memory_count": 1           # active memories after the case
      }
    }
In setup commands and prompts, the token {PASSWORD} is replaced by the
UAT password, so prompt files never contain a real secret.
"""

from __future__ import annotations

import json
import re
import statistics
import tempfile
import time
from pathlib import Path

DEFAULT_PASSWORD_FILE = "~/.recallite_uat_pass"


# ---------------------------------------------------------------------------
# case evaluation
# ---------------------------------------------------------------------------

def _check(expect: dict, reply: str, store) -> list[str]:
    """Return a list of failure reasons (empty = pass)."""
    fails = []
    low = reply.lower()
    for s in expect.get("contains_all", []):
        if s.lower() not in low:
            fails.append(f'missing required text: "{s}"')
    any_list = expect.get("contains_any", [])
    if any_list and not any(s.lower() in low for s in any_list):
        fails.append(f"none of the expected texts present: {any_list}")
    for s in expect.get("not_contains", []):
        if s.lower() in low:
            fails.append(f'forbidden text present: "{s}"')
    rx = expect.get("regex")
    if rx and not re.search(rx, reply, re.IGNORECASE):
        fails.append(f"regex did not match: {rx}")
    if "memory_count" in expect:
        try:
            n = store.count()
        except PermissionError:
            n = "locked"
        if n != expect["memory_count"]:
            fails.append(f"memory_count {n} != expected {expect['memory_count']}")
    return fails


def run_case(case: dict, backend, password: str, tmp: Path) -> dict:
    from .store import MemoryStore
    from .agent import MemoryAgent
    from .guardrails import Guardrails

    name = case.get("name", "unnamed")
    db = tmp / f"{re.sub(r'[^a-z0-9_-]', '_', name.lower())}.db"
    store = MemoryStore(str(db), user_id="uat",
                        secure=bool(case.get("secure")),
                        guardrails=Guardrails(
                            pii_mode=case.get("pii_mode", "redact")))
    agent = MemoryAgent(store, backend)

    def fill(s: str) -> str:
        s = s.replace("{PASSWORD}", password)
        if "{LAST_ID}" in s:          # id of the most recent /save
            s = s.replace("{LAST_ID}", agent._last_saved_id or "none")
        return s

    t0 = time.perf_counter()
    try:
        for cmd in case.get("setup", []):
            r = agent.ask(fill(cmd))
            if any(bad in r for bad in ("Usage:", "Unknown command",
                                        "Wrong password",
                                        "similar memory exists")):
                raise RuntimeError(f"setup command failed: {cmd!r} -> {r!r}")
        reply = agent.ask(fill(case["prompt"]))
        fails = _check(case.get("expect", {}), reply, store)
    except Exception as e:  # backend down, setup broken, etc.
        reply = f"<error: {e}>"
        fails = [str(e)]
    ms = (time.perf_counter() - t0) * 1000
    store.close()
    return {"name": name, "passed": not fails, "latency_ms": round(ms, 1),
            "failures": fails,
            "reply_excerpt": reply[:300]}


# ---------------------------------------------------------------------------
# runner
# ---------------------------------------------------------------------------

def default_prompts_path() -> Path:
    return Path(__file__).parent / "uat_prompts.json"


def load_password(password_file: str | None) -> str:
    """UAT password lives in a file only the operator writes — never in
    prompt files or the repo. Created with a random value on first run."""
    import os
    import secrets
    path = Path(password_file or DEFAULT_PASSWORD_FILE).expanduser()
    if path.exists():
        pw = path.read_text(encoding="utf-8").strip()
        if len(pw) >= 4:
            return pw
    pw = secrets.token_urlsafe(12)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(pw + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    print(f"[uat] created new UAT password file: {path}")
    return pw


def run_uat(backend, backend_desc: dict, cases: list[dict],
            password: str) -> dict:
    results = []
    with tempfile.TemporaryDirectory() as tmp:
        for case in cases:
            results.append(run_case(case, backend, password, Path(tmp)))
    lat = [r["latency_ms"] for r in results]
    try:
        from . import __version__ as ver
    except Exception:
        ver = "?"
    return {
        "recallite_version": ver,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "backend": backend_desc,
        "total": len(results),
        "passed": sum(r["passed"] for r in results),
        "median_latency_ms": round(statistics.median(lat), 1) if lat else 0,
        "results": results,
        "ok": all(r["passed"] for r in results),
    }


def render(report: dict) -> str:
    b = report["backend"]
    lines = [f"recallite UAT — v{report['recallite_version']} — "
             f"{report['timestamp']}",
             f"model: {b.get('model')}  backend: {b.get('kind')}"
             + (f"  url: {b['url']}" if b.get("url") else ""),
             "-" * 62]
    for r in report["results"]:
        mark = "PASS" if r["passed"] else "FAIL"
        lines.append(f"{mark}  {r['name']:32s} {r['latency_ms']:>8.1f} ms")
        for f in r["failures"]:
            lines.append(f"      - {f}")
            lines.append(f"      reply: {r['reply_excerpt'][:160]!r}")
    lines += ["-" * 62,
              f"RESULT: {report['passed']}/{report['total']} passed   "
              f"median latency {report['median_latency_ms']} ms",
              f"OVERALL: {'PASS' if report['ok'] else 'FAIL'}"]
    return "\n".join(lines)


def main(argv=None) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="recallite uat")
    p.add_argument("--backend", choices=["ollama", "openai"],
                   default="ollama")
    p.add_argument("--model", default="llama3.2")
    p.add_argument("--url", default=None)
    p.add_argument("--prompts", metavar="FILE",
                   help="UAT case file (default: the one shipped with "
                        "this release)")
    p.add_argument("--password-file", metavar="FILE",
                   default=DEFAULT_PASSWORD_FILE)
    p.add_argument("--report", metavar="FILE",
                   help="also write the JSON report here")
    a = p.parse_args(argv)

    from .adapters import OllamaBackend, OpenAICompatBackend
    if a.backend == "ollama":
        backend = OllamaBackend(a.model,
                                host=a.url or "http://localhost:11434")
        desc = {"kind": "ollama", "model": a.model, "url": a.url}
    else:
        backend = OpenAICompatBackend(
            a.model, base_url=a.url or "http://localhost:8000/v1")
        desc = {"kind": "openai-compatible", "model": a.model, "url": a.url}

    cases = json.loads(Path(a.prompts or default_prompts_path())
                       .read_text(encoding="utf-8"))
    password = load_password(a.password_file)

    report = run_uat(backend, desc, cases, password)
    print(render(report))
    if a.report:
        out = Path(a.report).expanduser()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nJSON report written to {out}")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
