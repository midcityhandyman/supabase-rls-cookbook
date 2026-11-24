-- 060_grant_audit.sql
-- The audit views report a clean install as clean, and catch each kind of
-- mistake when one is planted. Everything planted here rolls back.
begin;
select plan(16);

select is_empty(
  'select * from rls_audit.findings',
  'a fresh install has no findings'
);
select is(
  (select count(*) from rls_audit.rls_status where rls_enabled and rls_forced),
  7::bigint,
  'all seven tables report RLS enabled and forced'
);
select is(
  (select privileges from rls_audit.role_matrix
   where table_name = 'jobs' and grantee = 'agent_scheduler'),
  'UPDATE(scheduled_for), UPDATE(status)',
  'column level grants show up in the matrix'
);
select is(
  (select privileges from rls_audit.role_matrix
   where table_name = 'invoices' and grantee = 'agent_billing'),
  'INSERT, SELECT, UPDATE(status)',
  'billing matrix row is exactly what 0005 grants'
);
select is_empty(
  $$ select * from rls_audit.table_privileges where grantee in ('PUBLIC', 'anon') $$,
  'nothing is granted to PUBLIC or anon'
);
select results_eq(
  'select function_signature from rls_audit.definer_functions order by 1',
  array['app.job_has_unpaid_invoice(uuid)', 'app.log_event(uuid,text,jsonb)'],
  'the definer inventory lists both functions'
);

-- Plant mistakes.
create table app.leaky (id int, tenant_id uuid);
grant select on app.leaky to public;

create table app.half_done (id int, tenant_id uuid);
alter table app.half_done enable row level security;
create policy half_done_all on app.half_done using (true);

create table app.locked_out (id int);
alter table app.locked_out enable row level security;
alter table app.locked_out force row level security;

create function app.sloppy() returns int
  language sql security definer as 'select 1';

grant update (full_name) on app.customers to app_readonly;
alter role agent_intake bypassrls;

select ok(
  exists (select 1 from rls_audit.findings
          where check_name = 'rls_disabled' and object_name = 'app.leaky'),
  'finds a table without RLS'
);
select ok(
  exists (select 1 from rls_audit.findings
          where check_name = 'public_table_grant' and object_name = 'app.leaky'),
  'finds a grant to PUBLIC'
);
select ok(
  exists (select 1 from rls_audit.findings
          where check_name = 'rls_not_forced' and object_name = 'app.half_done'),
  'finds RLS that is enabled but not forced'
);
select ok(
  exists (select 1 from rls_audit.findings
          where check_name = 'policy_for_public' and object_name = 'app.half_done'),
  'finds a policy with no TO clause'
);
select ok(
  exists (select 1 from rls_audit.findings
          where check_name = 'rls_no_policies' and object_name = 'app.locked_out'),
  'finds a table with RLS and no policies'
);
select ok(
  exists (select 1 from rls_audit.findings
          where check_name = 'definer_no_search_path' and object_name = 'app.sloppy()'),
  'finds a definer function without a search_path'
);
select ok(
  exists (select 1 from rls_audit.findings
          where check_name = 'definer_public_execute' and object_name = 'app.sloppy()'),
  'finds a definer function open to PUBLIC'
);
select ok(
  exists (select 1 from rls_audit.findings
          where check_name = 'definer_privileged_owner' and object_name = 'app.sloppy()'),
  'finds a definer function owned by a superuser'
);
select ok(
  exists (select 1 from rls_audit.findings
          where check_name = 'readonly_role_can_write' and object_name = 'app.customers'
            and detail like 'agent_reporter %'),
  'finds a write privilege reaching a read only role'
);
select ok(
  exists (select 1 from rls_audit.findings
          where check_name = 'agent_is_privileged' and object_name = 'agent_intake'),
  'finds an agent role with BYPASSRLS'
);

select * from finish();
rollback;
