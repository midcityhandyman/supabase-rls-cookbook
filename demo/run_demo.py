#!/usr/bin/env python3
"""Run the walkthrough and save what it printed to demo/output.txt.

With Docker (or PGHOST set) this rebuilds the demo database, seeds it with
synthetic data and runs demo/demo.sql as each role in turn.

With no database available it falls back to the static report: the same
migrations, parsed in Python, printed as a table of tables, policies and
grants. Nothing is executed in that mode and the output says so.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "static_checks"))

import db  # noqa: E402
import sqlscan  # noqa: E402


def main() -> int:
    force_static = "--static" in sys.argv
    if not force_static and db.database_available():
        try:
            body = db.demo()
        except db.DbError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        header = "RLS cookbook demo: live run against Postgres (demo/demo.sql)\n"
    else:
        body = sqlscan.report(ROOT / "migrations")
        header = (
            "RLS cookbook demo: STATIC report. No database was available (or\n"
            "--static was given), so nothing below was executed. It is parsed\n"
            "from the migration files.\n"
        )
    text = header + body.rstrip() + "\n"
    out = ROOT / "demo" / ("output.txt" if not force_static else "output_static.txt")
    out.write_text(text, encoding="utf-8", newline="\n")
    print(text)
    print(f"saved to {out.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
