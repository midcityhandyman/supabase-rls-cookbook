-- 050_security_definer.sql
-- The two SECURITY DEFINER functions and the checklist they follow.
begin;
select plan(26);
\ir ../seed/seed.sql

-- ------------------------------------------------------------- checklist
select is_definer('app', 'log_event', array['uuid', 'text', 'jsonb']);
select is_definer('app', 'job_has_unpaid_invoice', array['uuid']);
select function_owner_is('app', 'log_event', array['uuid', 'text', 'jsonb'], 'app_definer');
select function_owner_is('app', 'job_has_unpaid_invoice', array['uuid'], 'app_definer');
select is_empty(
  $$ select p.proname from pg_proc p
     join pg_namespace n on n.oid = p.pronamespace
     where n.nspname = 'app' and p.prosecdef
       and not coalesce(p.proconfig @> array['search_path=""'], false) $$,
  'every definer function pins an empty search_path'
);
select is_empty(
  $$ select p.proname from pg_proc p
     join pg_namespace n on n.oid = p.pronamespace
     where n.nspname = 'app' and p.prosecdef
       and has_function_privilege('public', p.oid, 'execute') $$,
  'no definer function is executable by PUBLIC'
);
select is_empty(
  $$ select rolname from pg_roles
     where rolname = 'app_definer' and (rolsuper or rolbypassrls or rolcanlogin) $$,
  'the definer role is not privileged and cannot log in'
);
select is(
  (select count(*) from pg_proc p join pg_namespace n on n.oid = p.pronamespace
   where n.nspname = 'app' and p.prosecdef),
  2::bigint,
  'exactly two definer functions exist, so a new one has to be added here on purpose'
);

-- ------------------------------------------------------- recipe A: log_event
set local role agent_intake;
select throws_ok(
  $$ insert into app.audit_log (tenant_id, actor, action)
     values ('10000000-0000-4000-a000-000000000001', 'agent_billing', 'forged') $$,
  '42501', 'permission denied for table audit_log',
  'an agent cannot insert into the audit log directly'
);
select lives_ok(
  $$ select app.log_event('10000000-0000-4000-a000-000000000001', 'customer.created', '{"source":"test"}') $$,
  'an agent can log an event for an assigned tenant'
);
select throws_ok(
  $$ select app.log_event('10000000-0000-4000-a000-000000000003', 'customer.created') $$,
  '42501', null,
  'an agent cannot log an event for an unassigned tenant'
);
select throws_ok(
  $$ select app.log_event('10000000-0000-4000-a000-000000000001', null) $$,
  '22004', null,
  'null action is rejected'
);
select throws_ok(
  $$ select app.log_event('10000000-0000-4000-a000-000000000001', repeat('x', 81)) $$,
  '23514', null,
  'table constraints still apply inside the function'
);
set local app.tenant_id = '10000000-0000-4000-a000-000000000001';
select throws_ok(
  $$ select app.log_event('10000000-0000-4000-a000-000000000002', 'customer.created') $$,
  '42501', null,
  'the tenant pin is honoured inside the function'
);
set local app.tenant_id = '';
-- A hostile search_path must not matter: every reference is schema qualified.
set local search_path = pg_temp, public;
select lives_ok(
  $$ select app.log_event('10000000-0000-4000-a000-000000000002', 'job.created') $$,
  'the function is not affected by the caller''s search_path'
);
set local search_path = "$user", public;
select throws_ok(
  'select app.caller_role()', '42501', 'permission denied for function caller_role',
  'the identity helper is not callable by agents'
);
reset role;

select results_eq(
  $$ select action from app.audit_log
     where actor = 'agent_intake' order by action $$,
  array['customer.created', 'job.created'],
  'the function stamps the real caller as actor, not the function owner'
);

set local role authenticated;
set local request.jwt.claims = '{"sub":"20000000-0000-4000-a000-000000000001"}';
select throws_ok(
  $$ select app.log_event('10000000-0000-4000-a000-000000000001', 'x') $$,
  '42501', 'permission denied for function log_event',
  'humans cannot call the agent audit function'
);
reset role;

-- ------------------------------------------- recipe B: job_has_unpaid_invoice
set local role agent_scheduler;
select is(
  app.job_has_unpaid_invoice('40000000-0000-4000-a000-000000000011'), true,
  'scheduler learns that a job in its tenant has an unpaid invoice'
);
select is(
  app.job_has_unpaid_invoice('40000000-0000-4000-a000-000000000012'), false,
  'a job with a paid invoice answers false'
);
select is(
  app.job_has_unpaid_invoice('40000000-0000-4000-a000-000000000021'), false,
  'a job in another tenant answers false even though it has an unpaid invoice'
);
select is(
  app.job_has_unpaid_invoice(null), false,
  'null job answers false'
);
select throws_ok(
  'select count(*) from app.invoices', '42501',
  'permission denied for table invoices',
  'the function did not widen the scheduler''s own access'
);
reset role;

-- The function runs as its owner, which the restrictive pin policies do not
-- cover, so it has to honour the pin itself. Give the scheduler a second
-- tenant, then pin the first one.
insert into app.agent_tenants (agent_role, tenant_id)
values ('agent_scheduler', '10000000-0000-4000-a000-000000000002');
set local role agent_scheduler;
select is(
  app.job_has_unpaid_invoice('40000000-0000-4000-a000-000000000021'), true,
  'with no pin, a job in a second assigned tenant is answered'
);
set local app.tenant_id = '10000000-0000-4000-a000-000000000001';
select is(
  app.job_has_unpaid_invoice('40000000-0000-4000-a000-000000000021'), false,
  'with a pin, a job in the other assigned tenant answers false'
);
set local app.tenant_id = '';
reset role;

set local role agent_intake;
select throws_ok(
  $$ select app.job_has_unpaid_invoice('40000000-0000-4000-a000-000000000011') $$,
  '42501', 'permission denied for function job_has_unpaid_invoice',
  'only the scheduler may ask'
);
reset role;

select * from finish();
rollback;
