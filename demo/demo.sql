-- demo.sql
-- A guided walkthrough against the seeded demo database. Run it with
--   python demo/run_demo.py
-- Everything is synthetic. The demo database is rebuilt on every run.

\pset footer off
\pset null '(null)'

-- Demo helpers. They run as the caller (SECURITY INVOKER), so they show
-- exactly what the current role is allowed to do. demo.try runs arbitrary SQL
-- text, which is fine for a walkthrough and wrong for anything else.
create schema demo;
create function demo.peek(p_table text) returns text
  language plpgsql set search_path = '' as $$
declare v bigint;
begin
  execute format('select count(*) from app.%I', p_table) into v;
  return v || ' rows';
exception when insufficient_privilege then
  return 'denied';
end $$;
create function demo.try(p_sql text) returns text
  language plpgsql set search_path = '' as $$
declare n bigint;
begin
  execute p_sql;
  get diagnostics n = row_count;
  return 'ok (' || n || ' row' || case when n = 1 then '' else 's' end || ')';
exception when others then
  return 'refused: ' || sqlerrm;
end $$;
create function demo.summary() returns table (
  acting_as text, tenants text, customers text, jobs text, invoices text, audit_log text
) language sql set search_path = '' as $$
  select current_user::text,
         coalesce((select string_agg(t.slug, ', ' order by t.slug) from app.tenants t), 'none'),
         demo.peek('customers'), demo.peek('jobs'), demo.peek('invoices'), demo.peek('audit_log')
$$;
grant usage on schema demo to authenticated, app_agent;
grant execute on all functions in schema demo to authenticated, app_agent;

\echo
\echo ==========================================================================
\echo 1. Same tables, different role, different rows
\echo ==========================================================================
\echo The database holds 3 tenants, 5 customers, 5 jobs, 4 invoices.
\echo Each agent connects as its own database role.
\echo

set role agent_intake;
select * from demo.summary();
set role agent_scheduler;
select * from demo.summary();
set role agent_billing;
select * from demo.summary();
set role agent_reporter;
select * from demo.summary();
reset role;

\echo
\echo A signed in human: the owner of north-sample, then a user with no membership.
\echo

set role authenticated;
set request.jwt.claims = '{"sub":"20000000-0000-4000-a000-000000000001"}';
select * from demo.summary();
set request.jwt.claims = '{"sub":"20000000-0000-4000-a000-000000000004"}';
select * from demo.summary();
reset request.jwt.claims;
reset role;

\echo
\echo ==========================================================================
\echo 2. Grants pick the command, policies pick the rows, column grants pick
\echo    the columns
\echo ==========================================================================
\echo

set role agent_intake;
select 'intake: add customer to assigned tenant' as attempt, demo.try($$
  insert into app.customers (id, tenant_id, full_name, email, phone)
  values ('30000000-0000-4000-a000-000000000099', '10000000-0000-4000-a000-000000000001',
          'Avery Invented', 'avery.invented@example.com', '555-0120') $$) as result
union all
select 'intake: add customer to unassigned tenant', demo.try($$
  insert into app.customers (tenant_id, full_name)
  values ('10000000-0000-4000-a000-000000000003', 'Not My Tenant') $$)
union all
select 'intake: job pointing at another tenant''s customer', demo.try($$
  insert into app.jobs (tenant_id, customer_id, title)
  values ('10000000-0000-4000-a000-000000000001', '30000000-0000-4000-a000-000000000021', 'Cross tenant') $$)
union all
select 'intake: delete customers', demo.try('delete from app.customers');

set role agent_scheduler;
select 'scheduler: set status and date on own tenant' as attempt, demo.try($$
  update app.jobs set status = 'scheduled', scheduled_for = '2030-02-01'
  where id = '40000000-0000-4000-a000-000000000011' $$) as result
union all
select 'scheduler: rename a job', demo.try($$
  update app.jobs set title = 'renamed' where id = '40000000-0000-4000-a000-000000000011' $$)
union all
select 'scheduler: update a job in another tenant', demo.try($$
  update app.jobs set status = 'cancelled' where id = '40000000-0000-4000-a000-000000000021' $$);

set role agent_billing;
select 'billing: mark own invoice paid' as attempt, demo.try($$
  update app.invoices set status = 'paid' where id = '50000000-0000-4000-a000-000000000021' $$) as result
union all
select 'billing: change an invoice amount', demo.try($$
  update app.invoices set amount_cents = 1 where id = '50000000-0000-4000-a000-000000000021' $$)
union all
select 'billing: invoice for another tenant', demo.try($$
  insert into app.invoices (tenant_id, job_id, amount_cents)
  values ('10000000-0000-4000-a000-000000000001', '40000000-0000-4000-a000-000000000011', 5000) $$);
reset role;

\echo
\echo ==========================================================================
\echo 3. Tenant pin: a multi tenant agent narrows itself to one tenant
\echo ==========================================================================
\echo

begin;
set local role agent_intake;
select 'no pin' as pin, demo.peek('customers') as customers_visible;
set local app.tenant_id = '10000000-0000-4000-a000-000000000002';
select 'south-example' as pin, demo.peek('customers') as customers_visible;
select 'pinned to south, write to north' as attempt, demo.try($$
  insert into app.customers (tenant_id, full_name)
  values ('10000000-0000-4000-a000-000000000001', 'Wrong Pin') $$) as result;
commit;

\echo
\echo ==========================================================================
\echo 4. The read only agent
\echo ==========================================================================
\echo

set role agent_reporter;
select t.slug as tenant, count(*) as invoices, sum(i.amount_cents) as total_cents
from app.invoices i join app.tenants t on t.id = i.tenant_id
group by t.slug order by t.slug;
select 'reporter: insert' as attempt, demo.try($$
  insert into app.customers (tenant_id, full_name)
  values ('10000000-0000-4000-a000-000000000001', 'x') $$) as result
union all
select 'reporter: update', demo.try($$ update app.jobs set status = 'done' $$)
union all
select 'reporter: delete', demo.try('delete from app.invoices')
union all
select 'reporter: write via audit function', demo.try($$
  select app.log_event('10000000-0000-4000-a000-000000000001', 'report.run') $$);
reset role;

\echo
\echo ==========================================================================
\echo 5. SECURITY DEFINER, done safely
\echo ==========================================================================
\echo

set role agent_intake;
select 'intake: insert into audit_log directly' as attempt, demo.try($$
  insert into app.audit_log (tenant_id, actor, action)
  values ('10000000-0000-4000-a000-000000000001', 'agent_billing', 'forged') $$) as result
union all
select 'intake: app.log_event for assigned tenant', demo.try($$
  select app.log_event('10000000-0000-4000-a000-000000000001', 'customer.created', '{"source":"demo"}') $$)
union all
select 'intake: app.log_event for unassigned tenant', demo.try($$
  select app.log_event('10000000-0000-4000-a000-000000000003', 'customer.created') $$);
reset role;

\echo
\echo The row was written by the function owner, but the actor is the real caller:
\echo

select t.slug as tenant, a.actor, a.action, a.detail
from app.audit_log a join app.tenants t on t.id = a.tenant_id
where a.actor <> 'seed';

\echo
\echo The scheduler cannot read invoices, but may ask one yes or no question:
\echo

set role agent_scheduler;
select 'north job with a sent invoice' as job,
       app.job_has_unpaid_invoice('40000000-0000-4000-a000-000000000011') as has_unpaid
union all
select 'north job with a paid invoice',
       app.job_has_unpaid_invoice('40000000-0000-4000-a000-000000000012')
union all
select 'west job with a sent invoice (not my tenant)',
       app.job_has_unpaid_invoice('40000000-0000-4000-a000-000000000031');
select 'scheduler: read invoices directly' as attempt,
       demo.try('select * from app.invoices') as result;
reset role;

\echo
\echo ==========================================================================
\echo 6. Grant audit
\echo ==========================================================================
\echo Who can do what (rls_audit.role_matrix):
\echo

select table_name, grantee, privileges
from rls_audit.role_matrix
order by table_name, grantee;

\echo
\echo SECURITY DEFINER inventory (rls_audit.definer_functions):
\echo

select function_signature, function_owner, owner_is_privileged,
       search_path_is_set, public_can_execute
from rls_audit.definer_functions
order by 1;

\echo
\echo Findings on this install (rls_audit.findings):
\echo

select count(*) as findings from rls_audit.findings;

\echo
\echo Now plant four common mistakes inside a transaction and audit again:
\echo   a new table with no RLS that is granted to PUBLIC,
\echo   a SECURITY DEFINER function with defaults,
\echo   a write grant on the read only group,
\echo   BYPASSRLS on an agent.
\echo

begin;
create table app.leaky (id int, tenant_id uuid);
grant select on app.leaky to public;
create function app.sloppy() returns int language sql security definer as 'select 1';
grant update (full_name) on app.customers to app_readonly;
alter role agent_intake bypassrls;
select severity, check_name, object_name, detail
from rls_audit.findings
order by check_name, object_name;
rollback;

\echo
\echo Rolled back. Findings after rollback:
\echo

select count(*) as findings from rls_audit.findings;
