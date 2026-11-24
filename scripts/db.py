#!/usr/bin/env python3
"""Database helper for the RLS cookbook. Standard library only.

    python scripts/db.py up      start a throwaway Postgres with pgTAP
    python scripts/db.py test    rebuild the test database and run tests/*.sql
    python scripts/db.py demo    rebuild the demo database and run demo/demo.sql
    python scripts/db.py audit   run queries/grant_audit.sql on the demo database
    python scripts/db.py down    remove the throwaway container

Two ways to reach Postgres:

  docker mode (default)  A container named by RLS_COOKBOOK_CONTAINER is
                         started from the postgres:16 image. psql runs inside
                         it through "docker exec". No port is published.
  psql mode              Used when PGHOST is set (this is what CI does). psql
                         from PATH connects with the usual PG* variables. The
                         server must already have the pgTAP extension files.

Each run drops and recreates its database, so migrations always apply to an
empty database. Roles are cluster wide and the role migration is re-runnable.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONTAINER = os.environ.get("RLS_COOKBOOK_CONTAINER", "rls-cookbook-pg")
IMAGE = os.environ.get("RLS_COOKBOOK_IMAGE", "postgres:16")
PG_MAJOR = os.environ.get("RLS_COOKBOOK_PG_MAJOR", "16")
TEST_DB = "rls_cookbook_test"
DEMO_DB = "rls_cookbook_demo"
PSQL_MODE = bool(os.environ.get("PGHOST"))


class DbError(RuntimeError):
    pass


def run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if check and proc.returncode != 0:
        raise DbError(f"command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stdout}")
    return proc


def database_available() -> bool:
    """True when this machine can reach a Postgres one way or the other."""
    if PSQL_MODE:
        return shutil.which("psql") is not None
    if shutil.which("docker") is None:
        return False
    return run(["docker", "info"], check=False).returncode == 0


def sql_path(rel: str) -> str:
    """Path to a repo file as the psql process sees it."""
    if PSQL_MODE:
        return str(ROOT / rel)
    return "/repo/" + rel.replace("\\", "/")


def psql(db: str, args: list[str], check: bool = True, stop_on_error: bool = True):
    base = ["psql", "-X", "-d", db]
    if stop_on_error:
        base += ["-v", "ON_ERROR_STOP=1"]
    if PSQL_MODE:
        cmd = base + args
    else:
        cmd = ["docker", "exec", "-u", "postgres", CONTAINER] + base + args
    return run(cmd, check=check)


def container_running() -> bool:
    proc = run(
        ["docker", "ps", "--filter", f"name=^{CONTAINER}$", "--format", "{{.Names}}"],
        check=False,
    )
    return CONTAINER in proc.stdout.split()


def up() -> None:
    if PSQL_MODE:
        psql("postgres", ["-qAt", "-c", "select 1"])
        print(f"psql mode: using the server at {os.environ['PGHOST']}")
        return
    if not database_available():
        raise DbError("docker is not available. Set PGHOST to use an existing server.")
    if not container_running():
        run(["docker", "rm", "-f", CONTAINER], check=False)
        run([
            "docker", "run", "-d", "--name", CONTAINER,
            "-e", "POSTGRES_PASSWORD=postgres",
            "-v", f"{ROOT}:/repo:ro",
            IMAGE,
        ])
        print(f"started container {CONTAINER} from {IMAGE}")
    # The image starts a temporary server on the unix socket while it
    # initialises. Probing over TCP only succeeds on the real one.
    for _ in range(60):
        ready = run(
            ["docker", "exec", CONTAINER, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"],
            check=False,
        )
        if ready.returncode == 0:
            break
        time.sleep(1)
    else:
        raise DbError("postgres did not become ready in 60 seconds")
    have = psql(
        "postgres",
        ["-qAt", "-c", "select count(*) from pg_available_extensions where name = 'pgtap'"],
    )
    if have.stdout.strip() != "1":
        print("installing pgTAP into the container (needs network once) ...")
        run([
            "docker", "exec", CONTAINER, "bash", "-c",
            "apt-get update -qq && apt-get install -y -qq "
            f"postgresql-{PG_MAJOR}-pgtap >/dev/null",
        ])
    print("postgres is ready")


def down() -> None:
    if PSQL_MODE:
        print("psql mode: nothing to remove")
        return
    run(["docker", "rm", "-f", CONTAINER], check=False)
    print(f"removed container {CONTAINER}")


def migration_files() -> list[str]:
    return sorted(p.name for p in (ROOT / "migrations").glob("*.sql"))


def rebuild(db: str, with_pgtap: bool = False) -> None:
    """Drop and recreate a database, then apply every migration in order."""
    up()
    psql("postgres", ["-q", "-c", f"drop database if exists {db} with (force)"])
    psql("postgres", ["-q", "-c", f"create database {db}"])
    for name in migration_files():
        psql(db, ["-q", "-1", "-f", sql_path(f"migrations/{name}")])
    if with_pgtap:
        psql(db, ["-q", "-c", "create extension if not exists pgtap"])


TAP_OK = re.compile(r"^ok \d+")
TAP_NOT_OK = re.compile(r"^not ok \d+")
TAP_PLAN = re.compile(r"^1\.\.(\d+)$")


def parse_tap(output: str) -> tuple[int, int, int | None, list[str]]:
    """Return (passed, failed, planned, lines worth showing on failure)."""
    passed = failed = 0
    planned = None
    notes: list[str] = []
    for line in output.splitlines():
        line = line.strip()
        plan = TAP_PLAN.match(line)
        if plan:
            planned = int(plan.group(1))
        elif TAP_OK.match(line):
            passed += 1
        elif TAP_NOT_OK.match(line):
            failed += 1
            notes.append(line)
        elif line.startswith("#") or "ERROR" in line:
            notes.append(line)
    return passed, failed, planned, notes


def test() -> int:
    rebuild(TEST_DB, with_pgtap=True)
    files = sorted(p.name for p in (ROOT / "tests").glob("*.sql"))
    total_pass = total_fail = 0
    bad_files = 0
    for name in files:
        proc = psql(TEST_DB, ["-qAt", "-f", sql_path(f"tests/{name}")], check=False)
        passed, failed, planned, notes = parse_tap(proc.stdout)
        ok = (
            proc.returncode == 0
            and failed == 0
            and planned is not None
            and passed == planned
        )
        total_pass += passed
        total_fail += failed
        status = "ok" if ok else "FAILED"
        print(f"tests/{name:<34} {passed:>3}/{planned if planned is not None else '?':<3} {status}")
        if not ok:
            bad_files += 1
            for note in notes:
                print(f"    {note}")
            if proc.returncode != 0:
                print(f"    psql exited with {proc.returncode}")
    print(f"\n{len(files)} files, {total_pass} passed, {total_fail} failed")
    if bad_files or not files:
        print("RESULT: FAIL")
        return 1
    print("RESULT: PASS")
    return 0


def demo() -> str:
    """Rebuild the demo database, seed it, run the walkthrough, return its output."""
    rebuild(DEMO_DB)
    psql(DEMO_DB, ["-q", "-1", "-f", sql_path("seed/seed.sql")])
    proc = psql(DEMO_DB, ["-q", "-f", sql_path("demo/demo.sql")])
    return proc.stdout


def audit() -> str:
    rebuild(DEMO_DB)
    return psql(DEMO_DB, ["-q", "-f", sql_path("queries/grant_audit.sql")]).stdout


def main(argv: list[str]) -> int:
    commands = {"up", "down", "test", "demo", "audit"}
    if len(argv) != 2 or argv[1] not in commands:
        print(__doc__)
        return 2
    try:
        if argv[1] == "up":
            up()
        elif argv[1] == "down":
            down()
        elif argv[1] == "test":
            return test()
        elif argv[1] == "demo":
            print(demo())
        elif argv[1] == "audit":
            print(audit())
    except DbError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
