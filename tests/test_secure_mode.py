"""
test_secure_mode.py — Attack secure mode from every angle. All checks must PASS.

Run:  python3 test_secure_mode.py
"""

import os
from recallite import MemoryStore, MemoryAgent

def main():
    DB = "secure_check.db"
    for f in (DB, DB + "-wal", DB + "-shm"):
        if os.path.exists(f):
            os.remove(f)

    def check(name, ok):
        print(("PASS  " if ok else "FAIL  ") + name)
        return ok

    results = []

    # ---- 1. fresh secure store starts LOCKED ---------------------------------
    agent = MemoryAgent(MemoryStore(DB, user_id="ali", secure=True))
    r = agent.ask("/save age Ali is 36")
    results.append(check("starts locked: /save refused", "locked" in r.lower()))
    results.append(check("starts locked: /memories refused",
                         "locked" in agent.ask("/memories").lower()))

    # ---- 2. locked = ZERO leakage into the model prompt ----------------------
    ctx = agent.store.build_context("age name Ali")
    results.append(check("locked: no memory injected into prompt", ctx == ""))

    # ---- 3. first /enable sets the password, unlocks -------------------------
    r = agent.ask("/enable mypass123")
    results.append(check("first /enable sets password", "Password set" in r))
    results.append(check("unlocked: /save works",
                         "Saved" in agent.ask("/save age Ali is 36 years old")))

    # ---- 4. /lock relocks; wrong password rejected ---------------------------
    agent.ask("/lock")
    results.append(check("/lock relocks",
                         "locked" in agent.ask("/memories").lower()))
    results.append(check("wrong password rejected",
                         "Wrong password" in agent.ask("/enable hackerguess")))
    results.append(check("correct password unlocks",
                         "Correct password" in agent.ask("/enable mypass123")))

    # ---- 5. restart: lock resets, password persists --------------------------
    agent.store.close()
    agent2 = MemoryAgent(MemoryStore(DB, user_id="ali", secure=True))
    results.append(check("after restart: locked again",
                         "locked" in agent2.ask("/memories").lower()))
    results.append(check("after restart: old password still works",
                         "Correct password" in agent2.ask("/enable mypass123")))
    results.append(check("after restart: memories intact",
                         "Ali is 36" in agent2.ask("/memories")))

    # ---- 6. attacker with the .db file cannot read the password --------------
    import sqlite3
    raw = sqlite3.connect(DB)
    row = raw.execute("SELECT salt, pw_hash FROM settings").fetchone()
    raw_bytes = open(DB, "rb").read()
    results.append(check("password NOT stored in plain text",
                         b"mypass123" not in raw_bytes and row is not None))
    raw.close()

    # ---- 7. Python API cannot bypass the lock --------------------------------
    agent2.ask("/lock")
    try:
        agent2.store.save("bypass attempt", keyword="x")
        results.append(check("direct store.save() blocked while locked", False))
    except PermissionError:
        results.append(check("direct store.save() blocked while locked", True))

    # ---- 8. every memory command respects the lock ---------------------------
    locked_cmds = ["/save x y", "/save! x y", "/replace abc x y", "/undo",
                   "/search age", "/memories", "/forget abc", "/clear",
                   "/stats", "/export x.json", "/import x.json",
                   "/block term", "/blocked", "/history age"]
    all_locked = all("locked" in agent2.ask(c).lower() for c in locked_cmds)
    results.append(check(f"all {len(locked_cmds)} memory commands locked", all_locked))

    # ---- 9. profiles: each secure profile has its own lock -------------------
    agent2.ask("/enable mypass123")
    agent2.ask("/profile work")            # new profile -> fresh lock state
    r = agent2.ask("/save job engineer at startup")
    results.append(check("switching profile does not inherit unlock",
                         "locked" in r.lower()))

    # --------------------------------------------------------------------------
    for f in (DB, DB + "-wal", DB + "-shm"):
        if os.path.exists(f):
            os.remove(f)

    print("-" * 50)
    n = sum(results)
    print(f"RESULT: {n}/{len(results)} secure-mode checks passed")
    raise SystemExit(0 if n == len(results) else 1)

def test_secure_mode_suite():
    """pytest entry: the suite must pass end to end."""
    try:
        main()
    except SystemExit as e:
        assert e.code == 0


if __name__ == "__main__":
    main()
