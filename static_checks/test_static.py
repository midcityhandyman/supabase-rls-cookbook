"""Static checks. They read the files and never touch a database.

    python -m unittest discover -s static_checks -v

These do not replace the pgTAP tests: they cannot tell whether a policy is
correct, only whether the rules of the cookbook were followed when it was
written. They exist so that a machine with no Postgres still gets a signal,
and so that a careless migration fails fast in CI before the database job.
"""

from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "static_checks"))
sys.path.insert(0, str(ROOT / "scripts"))

import db  # noqa: E402
import sqlscan  # noqa: E402

MIGRATIONS = ROOT / "migrations"
WRITE_PRIVS = ("insert", "update", "delete", "truncate", "all")
TEXT_SUFFIXES = {".sql", ".py", ".md", ".yml", ".yaml", ".txt", ".example", ".gitignore"}


def repo_text_files() -> list[Path]:
    skip = {".git", ".venv", "venv", "node_modules", "__pycache__"}
    files = []
    for path in ROOT.rglob("*"):
        if path.is_file() and not (set(path.relative_to(ROOT).parts) & skip):
            if path.suffix in TEXT_SUFFIXES or path.name in {".gitignore", ".env.example"}:
                files.append(path)
    return files


class MigrationRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = sqlscan.load(MIGRATIONS)
        cls.app_tables = [t for t in cls.model.tables if t.startswith("app.")]

    def test_migrations_are_numbered_without_gaps(self):
        names = sorted(p.name for p in MIGRATIONS.glob("*.sql"))
        numbers = [int(re.match(r"(\d{4})_[a-z0-9_]+\.sql$", n).group(1)) for n in names]
        self.assertEqual(numbers, list(range(1, len(names) + 1)))

    def test_expected_tables_exist(self):
        self.assertEqual(len(self.app_tables), 7)

    def test_every_table_enables_and_forces_rls(self):
        for table in self.app_tables:
            self.assertIn(table, self.model.rls_enabled, f"{table}: RLS not enabled")
            self.assertIn(table, self.model.rls_forced, f"{table}: RLS not forced")

    def test_every_table_has_a_policy_and_an_owner(self):
        covered = {p.table for p in self.model.policies}
        for table in self.app_tables:
            self.assertIn(table, covered, f"{table}: no policy")
            self.assertEqual(self.model.owners.get(table), "app_owner", table)

    def test_every_policy_names_its_roles(self):
        for p in self.model.policies:
            self.assertTrue(p.roles, f"{p.name}: no TO clause, applies to PUBLIC")
            self.assertNotIn("public", p.roles, p.name)
            self.assertNotIn("anon", p.roles, p.name)

    def test_policies_are_on_known_tables_with_unique_names(self):
        names = [p.name for p in self.model.policies]
        self.assertEqual(len(names), len(set(names)))
        for p in self.model.policies:
            self.assertIn(p.table, self.app_tables, p.name)
            self.assertTrue(p.name.startswith(p.table.split(".")[1] + "_"), p.name)

    def test_update_policies_have_using_and_with_check(self):
        updates = [p for p in self.model.policies if p.command == "update"]
        self.assertTrue(updates)
        for p in updates:
            self.assertTrue(p.has_using and p.has_check, p.name)

    def test_insert_policies_have_with_check(self):
        for p in (p for p in self.model.policies if p.command == "insert"):
            self.assertTrue(p.has_check, p.name)

    def test_every_function_pins_an_empty_search_path(self):
        self.assertTrue(self.model.functions)
        for f in self.model.functions:
            self.assertEqual(f.search_path, "''", f"{f.name}: search_path is {f.search_path}")

    def test_every_function_revokes_public_execute(self):
        for f in self.model.functions:
            self.assertIn(f.name, self.model.public_execute_revoked, f.name)

    def test_definer_functions_follow_the_checklist(self):
        definers = [f for f in self.model.functions if f.definer]
        self.assertEqual(sorted(f.name for f in definers),
                         ["app.job_has_unpaid_invoice", "app.log_event"])
        for f in definers:
            self.assertEqual(self.model.owners.get(f.name), "app_definer", f.name)
            body = f.body.lower()
            self.assertNotRegex(body, r"\bexecute\b", f"{f.name}: dynamic SQL")
            self.assertNotIn("current_user", body, f"{f.name}: current_user is the owner here")
            self.assertIn("app.caller_role()", body, f"{f.name}: does not identify the caller")
            for ref in re.findall(r"\b(?:from|join|into)\s+([a-z_][\w.]*)", body):
                self.assertIn(".", ref, f"{f.name}: unqualified reference {ref}")
            execute = [g for g in self.model.grants if g.kind == "function" and f.name in g.objects]
            self.assertTrue(execute, f"{f.name}: nobody may execute it")
            for g in execute:
                self.assertFalse({"public", "anon", "authenticated"} & set(g.grantees), f.name)

    def test_nothing_is_granted_to_public_or_anon(self):
        for g in self.model.grants:
            self.assertFalse({"public", "anon"} & set(g.grantees), g)

    def test_no_grant_all(self):
        for g in self.model.grants:
            for priv in g.privileges:
                self.assertFalse(priv.startswith("all"), g)

    def test_readonly_group_only_gets_select(self):
        seen = False
        for g in self.model.grants:
            if g.kind == "table" and "app_readonly" in g.grantees:
                seen = True
                self.assertEqual(g.privileges, ["select"], g)
        self.assertTrue(seen)
        members = {m for g in self.model.grants if g.kind == "role" and "app_readonly" in g.objects
                   for m in g.grantees}
        self.assertEqual(members, {"agent_reporter"})
        for g in self.model.grants:
            if g.kind == "table" and members & set(g.grantees):
                self.assertFalse([p for p in g.privileges if p.startswith(WRITE_PRIVS)], g)

    def test_audit_log_is_append_only(self):
        for g in self.model.grants:
            if g.kind == "table" and "app.audit_log" in g.objects:
                for priv in g.privileges:
                    self.assertIn(priv, ("select", "insert"), g)
                if "insert" in g.privileges:
                    self.assertEqual(g.grantees, ["app_definer"])
        for p in self.model.policies:
            if p.table == "app.audit_log" and not p.restrictive:
                self.assertIn(p.command, ("select", "insert"), p.name)

    def test_no_role_is_created_privileged(self):
        text = "\n".join(p.read_text(encoding="utf-8") for p in MIGRATIONS.glob("*.sql"))
        code = "\n".join(line.split("--")[0] for line in text.splitlines()).lower()
        role_statements = re.findall(r"(?:create|alter) role [^;]*", code)
        self.assertGreaterEqual(len(role_statements), 3)
        for stmt in role_statements:
            for attribute in ("superuser", "bypassrls", "createrole", "createdb", "login"):
                self.assertNotRegex(stmt, rf"(?<!no){attribute}\b", stmt)
            self.assertNotIn("password", stmt)
        self.assertNotIn("disable row level security", code)
        self.assertNotIn("no force row level security", code)

    def test_every_agent_is_in_the_agent_group(self):
        members = {m for g in self.model.grants if g.kind == "role" and "app_agent" in g.objects
                   for m in g.grantees}
        self.assertEqual(members, {"agent_intake", "agent_scheduler", "agent_billing", "agent_reporter"})


class ScannerCatchesMistakes(unittest.TestCase):
    """The rules above are only worth something if the reader sees mistakes."""

    def scan(self, sql: str) -> sqlscan.Model:
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "0001_bad.sql").write_text(sql, encoding="utf-8")
            return sqlscan.load(Path(tmp))

    def test_sees_missing_force_and_public_policy(self):
        m = self.scan("""
            create table app.t (id int); -- a comment; with a semicolon
            alter table app.t enable row level security;
            create policy t_all on app.t using (true);
        """)
        self.assertEqual(m.tables, ["app.t"])
        self.assertIn("app.t", m.rls_enabled)
        self.assertNotIn("app.t", m.rls_forced)
        self.assertEqual(m.policies[0].roles, [])
        self.assertEqual(m.policies[0].command, "all")

    def test_sees_definer_without_search_path(self):
        m = self.scan("""
            create function app.f() returns int language sql security definer
              as $$ select 1; -- semicolon inside the body $$;
            grant execute on function app.f() to public;
        """)
        self.assertTrue(m.functions[0].definer)
        self.assertIsNone(m.functions[0].search_path)
        self.assertNotIn("app.f", m.public_execute_revoked)
        self.assertEqual(m.grants[0].grantees, ["public"])
        self.assertEqual(m.grants[0].kind, "function")

    def test_parses_column_grants_and_update_policy_halves(self):
        m = self.scan("""
            grant select, update (a, b) on app.t, app.u to r1, r2;
            create policy t_upd on app.t for update to r1 using (a = 'x;y');
        """)
        self.assertEqual(m.grants[0].privileges, ["select", "update (a, b)"])
        self.assertEqual(m.grants[0].objects, ["app.t", "app.u"])
        self.assertEqual(m.grants[0].grantees, ["r1", "r2"])
        self.assertTrue(m.policies[0].has_using)
        self.assertFalse(m.policies[0].has_check)


class RepositoryHygiene(unittest.TestCase):
    def test_files_are_plain_ascii_with_no_long_dashes(self):
        for path in repo_text_files():
            data = path.read_bytes()
            bad = [b for b in data if b > 127]
            self.assertFalse(bad, f"{path.relative_to(ROOT)} has non ASCII bytes")

    def test_seed_data_is_obviously_synthetic(self):
        seed = (ROOT / "seed" / "seed.sql").read_text(encoding="utf-8")
        emails = re.findall(r"[\w.+-]+@[\w.-]+", seed)
        self.assertTrue(emails)
        for email in emails:
            self.assertTrue(email.endswith("@example.com"), email)
        phones = re.findall(r"'(\d{3}-\d{4})'", seed)
        self.assertTrue(phones)
        for phone in phones:
            self.assertRegex(phone, r"^555-01\d\d$")

    def test_pgtap_files_are_well_formed(self):
        files = sorted((ROOT / "tests").glob("*.sql"))
        self.assertGreaterEqual(len(files), 6)
        assertion = re.compile(
            r"^select (?:\* from )?(?:ok|is|isnt|is_empty|results_eq|throws_ok|lives_ok|has_\w+|"
            r"tables_are|policies_are|is_member_of|is_definer|function_owner_is|fk_ok)\s*\(",
        )
        for path in files:
            text = path.read_text(encoding="utf-8")
            stmts = [s.lower() for s in sqlscan.split_statements(text)]
            self.assertEqual(stmts[0], "begin", path.name)
            self.assertEqual(stmts[-1], "rollback", path.name)
            self.assertIn("select * from finish()", stmts, path.name)
            plan = [int(m.group(1)) for s in stmts if (m := re.match(r"select plan\((\d+)\)$", s))]
            self.assertEqual(len(plan), 1, path.name)
            counted = 0
            for s in stmts:
                s = re.sub(r"^\\ir \S+ ", "", s)
                s = re.sub(r"^with \w+ as \(.*?returning 1 \) ", "", s)
                if assertion.match(s):
                    counted += 1
            self.assertEqual(counted, plan[0], f"{path.name}: plan does not match assertions")

    def test_ci_runs_both_suites(self):
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("python scripts/db.py test", ci)
        self.assertIn("unittest discover -s static_checks", ci)
        self.assertIn("postgres:16", ci)

    def test_required_files_exist(self):
        for rel in ("README.md", ".gitignore", ".env.example", "demo/output.txt",
                    "demo/demo.sql", "queries/grant_audit.sql", "seed/seed.sql"):
            self.assertTrue((ROOT / rel).is_file(), rel)
        self.assertTrue((ROOT / "LICENSE").is_file())


class TapParser(unittest.TestCase):
    def test_counts_and_plan(self):
        out = "1..3\nok 1 - a\nnot ok 2 - b\n# Failed test 2\nok 3 - c\n"
        passed, failed, planned, notes = db.parse_tap(out)
        self.assertEqual((passed, failed, planned), (2, 1, 3))
        self.assertIn("not ok 2 - b", notes)

    def test_missing_plan_is_reported(self):
        self.assertIsNone(db.parse_tap("ok 1 - a\n")[2])

    def test_psql_errors_are_kept(self):
        notes = db.parse_tap("1..1\npsql:x.sql:3: ERROR:  boom\n")[3]
        self.assertEqual(len(notes), 1)


if __name__ == "__main__":
    unittest.main()
