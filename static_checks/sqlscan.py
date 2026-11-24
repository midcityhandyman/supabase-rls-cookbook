#!/usr/bin/env python3
"""A small reader for the migration files. Standard library only.

It is not a SQL parser. It understands just enough of the statements this
repository uses (create table, enable/force RLS, create policy, create
function, grant, revoke, alter ... owner) to let the static checks reason
about them without a database, and to print a report.

    python static_checks/sqlscan.py        print the static report
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

DOLLAR_TAG = re.compile(r"\$[A-Za-z_]*\$")


def split_statements(sql: str) -> list[str]:
    """Drop comments and split on semicolons outside strings and dollar quotes."""
    out: list[str] = []
    buf: list[str] = []
    i, n = 0, len(sql)
    while i < n:
        ch = sql[i]
        if sql.startswith("--", i):
            end = sql.find("\n", i)
            i = n if end == -1 else end
        elif sql.startswith("/*", i):
            end = sql.find("*/", i + 2)
            i = n if end == -1 else end + 2
        elif ch == "'":
            j = i + 1
            while j < n:
                if sql[j] == "'" and sql[j + 1 : j + 2] == "'":
                    j += 2
                elif sql[j] == "'":
                    break
                else:
                    j += 1
            buf.append(sql[i : j + 1])
            i = j + 1
        elif ch == "$" and DOLLAR_TAG.match(sql, i):
            tag = DOLLAR_TAG.match(sql, i).group(0)
            end = sql.find(tag, i + len(tag))
            end = n if end == -1 else end + len(tag)
            buf.append(sql[i:end])
            i = end
        elif ch == ";":
            out.append("".join(buf))
            buf = []
            i += 1
        else:
            buf.append(ch)
            i += 1
    out.append("".join(buf))
    return [" ".join(s.split()) for s in out if s.strip()]


def split_top_level(text: str) -> list[str]:
    """Split on commas that are not inside parentheses."""
    parts, depth, cur = [], 0, []
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur).strip())
    return [p for p in parts if p]


@dataclass
class Policy:
    name: str
    table: str
    command: str
    roles: list[str]
    restrictive: bool
    has_using: bool
    has_check: bool
    source: str


@dataclass
class Function:
    name: str  # schema qualified, no argument list
    definer: bool
    search_path: str | None
    body: str
    source: str


@dataclass
class Grant:
    privileges: list[str]
    kind: str  # table, schema, function, role
    objects: list[str]
    grantees: list[str]
    source: str


@dataclass
class Model:
    statements: list[tuple[str, str]] = field(default_factory=list)
    tables: list[str] = field(default_factory=list)
    rls_enabled: set[str] = field(default_factory=set)
    rls_forced: set[str] = field(default_factory=set)
    policies: list[Policy] = field(default_factory=list)
    functions: list[Function] = field(default_factory=list)
    grants: list[Grant] = field(default_factory=list)
    public_execute_revoked: set[str] = field(default_factory=set)
    owners: dict[str, str] = field(default_factory=dict)


POLICY = re.compile(
    r"^create policy (?P<name>\w+) on (?P<table>[\w.]+)"
    r"(?: as (?P<kind>permissive|restrictive))?"
    r"(?: for (?P<cmd>all|select|insert|update|delete))?"
    r"(?: to (?P<roles>[\w, ]+?))?"
    r"(?= using| with check|$)(?P<rest>.*)$",
    re.I,
)
FUNCTION = re.compile(r"^create (?:or replace )?function (?P<name>[\w.]+)\s*\(", re.I)
SEARCH_PATH = re.compile(r"set search_path (?:=|to) (?P<value>''|[\w, \"$]+?)(?= as | security | language |$)", re.I)
GRANT_ON = re.compile(
    r"^grant (?P<privs>.+?) on (?P<kind>table |schema |function |all functions in schema )?"
    r"(?P<objects>.+?) to (?P<grantees>.+)$",
    re.I,
)
GRANT_ROLE = re.compile(r"^grant (?P<roles>[\w, ]+) to (?P<grantees>[\w, ]+)$", re.I)
REVOKE_FN = re.compile(r"^revoke execute on function (?P<name>[\w.]+)\s*\(.*\) from public$", re.I)
OWNER = re.compile(r"^alter (?:table|function) (?P<name>[\w.]+)(?:\s*\(.*\))? owner to (?P<owner>\w+)$", re.I)


def load(migrations_dir: Path) -> Model:
    model = Model()
    for path in sorted(Path(migrations_dir).glob("*.sql")):
        for stmt in split_statements(path.read_text(encoding="utf-8")):
            model.statements.append((path.name, stmt))
            _classify(model, path.name, stmt)
    return model


def _classify(model: Model, source: str, stmt: str) -> None:
    low = stmt.lower()
    m = re.match(r"^create table ([\w.]+)", low)
    if m:
        model.tables.append(m.group(1))
        return
    m = re.match(r"^alter table ([\w.]+) (enable|force) row level security$", low)
    if m:
        (model.rls_enabled if m.group(2) == "enable" else model.rls_forced).add(m.group(1))
        return
    m = POLICY.match(stmt)
    if m:
        rest = m.group("rest").lower()
        model.policies.append(Policy(
            name=m.group("name"),
            table=m.group("table").lower(),
            command=(m.group("cmd") or "all").lower(),
            roles=[r.strip().lower() for r in (m.group("roles") or "").split(",") if r.strip()],
            restrictive=(m.group("kind") or "").lower() == "restrictive",
            has_using=" using (" in rest or rest.startswith("using ("),
            has_check="with check (" in rest,
            source=source,
        ))
        return
    m = FUNCTION.match(stmt)
    if m:
        body_at = DOLLAR_TAG.search(stmt)
        head = stmt[: body_at.start()] if body_at else stmt
        sp = SEARCH_PATH.search(head)
        model.functions.append(Function(
            name=m.group("name").lower(),
            definer=" security definer" in head.lower(),
            search_path=sp.group("value").strip() if sp else None,
            body=stmt[body_at.start():] if body_at else "",
            source=source,
        ))
        return
    m = REVOKE_FN.match(stmt)
    if m:
        model.public_execute_revoked.add(m.group("name").lower())
        return
    m = OWNER.match(stmt)
    if m:
        model.owners[m.group("name").lower()] = m.group("owner").lower()
        return
    m = GRANT_ON.match(stmt)
    if m:
        kind = (m.group("kind") or "table ").strip().lower()
        objects = [re.sub(r"\s*\(.*\)$", "", o).lower() for o in split_top_level(m.group("objects"))]
        model.grants.append(Grant(
            privileges=[p.lower() for p in split_top_level(m.group("privs"))],
            kind="function" if "function" in kind else kind,
            objects=objects,
            grantees=[g.strip().lower() for g in m.group("grantees").split(",")],
            source=source,
        ))
        return
    m = GRANT_ROLE.match(stmt)
    if m:
        model.grants.append(Grant(
            privileges=["member"],
            kind="role",
            objects=[r.strip().lower() for r in m.group("roles").split(",")],
            grantees=[g.strip().lower() for g in m.group("grantees").split(",")],
            source=source,
        ))


def table_grants(model: Model, table: str) -> dict[str, list[str]]:
    """Privileges per grantee for one table, as written in the migrations."""
    out: dict[str, list[str]] = {}
    for g in model.grants:
        if g.kind == "table" and table in g.objects:
            for grantee in g.grantees:
                out.setdefault(grantee, []).extend(g.privileges)
    return {k: sorted(set(v)) for k, v in sorted(out.items())}


def report(migrations_dir: Path) -> str:
    model = load(migrations_dir)
    lines = [f"{len(model.statements)} statements in {len({s for s, _ in model.statements})} migration files", ""]
    for table in model.tables:
        flags = []
        flags.append("RLS enabled" if table in model.rls_enabled else "RLS OFF")
        flags.append("forced" if table in model.rls_forced else "NOT forced")
        owner = model.owners.get(table, "(migration role)")
        lines.append(f"{table}   [{', '.join(flags)}]   owner {owner}")
        lines.append("  policies")
        for p in (p for p in model.policies if p.table == table):
            kind = "restrictive" if p.restrictive else "permissive"
            roles = ", ".join(p.roles) or "PUBLIC"
            lines.append(f"    {p.name:<30} {p.command:<7} {kind:<11} to {roles}")
        lines.append("  grants")
        for grantee, privs in table_grants(model, table).items():
            lines.append(f"    {grantee:<30} {', '.join(privs)}")
        lines.append("")
    lines.append("functions")
    for f in model.functions:
        mode = "SECURITY DEFINER" if f.definer else "invoker"
        sp = "search_path " + (f.search_path if f.search_path is not None else "NOT SET")
        owner = model.owners.get(f.name, "(migration role)")
        public = "PUBLIC revoked" if f.name in model.public_execute_revoked else "PUBLIC CAN EXECUTE"
        lines.append(f"  {f.name:<30} {mode:<17} {sp:<16} owner {owner:<12} {public}")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    sys.stdout.write(report(Path(__file__).resolve().parent.parent / "migrations"))
