-- 030_agent_roles.sql
-- One database role per agent. Grants pick the tables and commands,
-- policies pick the rows, column grants pick the columns.
begin;
select plan(30);
\ir ../seed/seed.sql

-- ---------------------------------------------------------------- intake
-- Assigned to north-sample and south-example.
set local role agent_intake;
select results_eq(
  'select slug from app.tenants order by slug',
  array['north-sample', 'south-example'],
  'intake sees its two tenants and not the third'
);
select is((select count(*) from app.customers), 4::bigint, 'intake sees customers of both tenants');
select is(
  (select count(*) from app.agent_tenants where agent_role <> current_user),
  0::bigint,
  'an agent sees only its own assignment rows'
);
select lives_ok(
  $$ insert into app.customers (id, tenant_id, full_name, email, phone)
     values ('30000000-0000-4000-a000-000000000099', '10000000-0000-4000-a000-000000000001',
             'Avery Invented', 'avery.invented@example.com', '555-0120') $$,
  'intake can create a customer in an assigned tenant'
);
select lives_ok(
  $$ insert into app.jobs (tenant_id, customer_id, title)
     values ('10000000-0000-4000-a000-000000000001', '30000000-0000-4000-a000-000000000099', 'Hang a door') $$,
  'intake can create a job in an assigned tenant'
);
select throws_ok(
  $$ insert into app.customers (tenant_id, full_name)
     values ('10000000-0000-4000-a000-000000000003', 'Not My Tenant') $$,
  '42501', 'new row violates row-level security policy for table "customers"',
  'intake cannot create a customer in an unassigned tenant'
);
select throws_ok(
  $$ insert into app.jobs (tenant_id, customer_id, title)
     values ('10000000-0000-4000-a000-000000000001', '30000000-0000-4000-a000-000000000021', 'Cross tenant job') $$,
  '23503', null,
  'composite foreign key rejects a job that points at another tenant''s customer'
);
select throws_ok(
  'select count(*) from app.invoices', '42501',
  'permission denied for table invoices',
  'intake cannot read invoices'
);
select throws_ok(
  $$ update app.jobs set status = 'done' $$, '42501',
  'permission denied for table jobs',
  'intake cannot update jobs'
);
select throws_ok(
  'delete from app.customers', '42501',
  'permission denied for table customers',
  'intake cannot delete customers'
);
-- SET ROLE is checked against the login role, which in this test is the
-- superuser, so membership is asserted directly instead of by trying it.
select ok(
  not pg_has_role('agent_intake', 'agent_billing', 'member'),
  'an agent is not a member of another agent role'
);
select ok(
  not pg_has_role('agent_intake', 'app_definer', 'member')
    and not pg_has_role('agent_intake', 'app_owner', 'member'),
  'an agent is not a member of the owner or definer roles'
);

-- Tenant pin: narrow a multi tenant agent to one tenant for the transaction.
set local app.tenant_id = '10000000-0000-4000-a000-000000000001';
select is((select count(*) from app.customers), 3::bigint, 'pinned: only the pinned tenant is visible');
select throws_ok(
  $$ insert into app.customers (tenant_id, full_name)
     values ('10000000-0000-4000-a000-000000000002', 'Wrong Pin') $$,
  '42501', 'new row violates row-level security policy "customers_agent_pin" for table "customers"',
  'pinned: cannot write to another assigned tenant'
);
set local app.tenant_id = '10000000-0000-4000-a000-000000000003';
select is((select count(*) from app.customers), 0::bigint, 'pinning an unassigned tenant shows nothing');
set local app.tenant_id = 'not-a-uuid';
select throws_ok('select count(*) from app.customers', '22P02', null, 'a malformed pin fails closed');
set local app.tenant_id = '';
select is((select count(*) from app.customers), 5::bigint, 'pin cleared: both tenants again');
reset role;

-- ------------------------------------------------------------- scheduler
-- Assigned to north-sample only.
set local role agent_scheduler;
select is((select count(*) from app.jobs), 3::bigint, 'scheduler sees jobs of its one tenant');
select lives_ok(
  $$ update app.jobs set status = 'scheduled', scheduled_for = '2030-02-01'
     where id = '40000000-0000-4000-a000-000000000011' $$,
  'scheduler can set status and date'
);
select is(
  (select status from app.jobs where id = '40000000-0000-4000-a000-000000000011'),
  'scheduled',
  'the update took effect'
);
select throws_ok(
  $$ update app.jobs set title = 'renamed' where id = '40000000-0000-4000-a000-000000000011' $$,
  '42501', 'permission denied for table jobs',
  'scheduler cannot change other columns'
);
with changed as (
  update app.jobs set status = 'cancelled'
  where id = '40000000-0000-4000-a000-000000000021'
  returning 1
)
select is((select count(*) from changed), 0::bigint, 'scheduler update on another tenant touches 0 rows');
select throws_ok(
  $$ insert into app.jobs (tenant_id, customer_id, title)
     values ('10000000-0000-4000-a000-000000000001', '30000000-0000-4000-a000-000000000011', 'x') $$,
  '42501', 'permission denied for table jobs',
  'scheduler cannot create jobs'
);
select throws_ok(
  'select count(*) from app.invoices', '42501',
  'permission denied for table invoices',
  'scheduler cannot read invoices'
);
reset role;

-- --------------------------------------------------------------- billing
-- Assigned to south-example only.
set local role agent_billing;
select is((select count(*) from app.invoices), 1::bigint, 'billing sees invoices of its one tenant');
select lives_ok(
  $$ insert into app.invoices (tenant_id, job_id, amount_cents)
     values ('10000000-0000-4000-a000-000000000002', '40000000-0000-4000-a000-000000000022', 12000) $$,
  'billing can create an invoice in its tenant'
);
select throws_ok(
  $$ insert into app.invoices (tenant_id, job_id, amount_cents)
     values ('10000000-0000-4000-a000-000000000001', '40000000-0000-4000-a000-000000000011', 12000) $$,
  '42501', 'new row violates row-level security policy for table "invoices"',
  'billing cannot create an invoice in another tenant'
);
select lives_ok(
  $$ update app.invoices set status = 'paid'
     where id = '50000000-0000-4000-a000-000000000021' $$,
  'billing can change invoice status'
);
select throws_ok(
  $$ update app.invoices set amount_cents = 1
     where id = '50000000-0000-4000-a000-000000000021' $$,
  '42501', 'permission denied for table invoices',
  'billing cannot change the amount'
);
select throws_ok(
  $$ insert into app.customers (tenant_id, full_name)
     values ('10000000-0000-4000-a000-000000000002', 'x') $$,
  '42501', 'permission denied for table customers',
  'billing cannot create customers'
);
reset role;

select * from finish();
rollback;
