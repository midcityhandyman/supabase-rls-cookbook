-- 020_tenant_isolation_users.sql
-- Signed in humans: the "authenticated" role plus a JWT subject.
begin;
select plan(24);
\ir ../seed/seed.sql

-- anon holds nothing at all.
set local role anon;
select throws_ok(
  'select count(*) from app.customers', '42501',
  'permission denied for schema app',
  'anon cannot reach the app schema'
);
reset role;

-- authenticated with no JWT subject sees nothing.
set local role authenticated;
select is((select count(*) from app.tenants), 0::bigint, 'no subject: no tenants');
select is((select count(*) from app.customers), 0::bigint, 'no subject: no customers');
reset role;

-- Owner of north-sample.
set local role authenticated;
set local request.jwt.claims = '{"sub":"20000000-0000-4000-a000-000000000001"}';
select results_eq(
  'select slug from app.tenants order by slug',
  array['north-sample'],
  'owner sees only their tenant'
);
select is((select count(*) from app.customers), 2::bigint, 'owner sees 2 customers');
select is((select count(*) from app.jobs), 2::bigint, 'owner sees 2 jobs');
select is((select count(*) from app.invoices), 2::bigint, 'owner sees 2 invoices');
select is((select count(*) from app.audit_log), 1::bigint, 'owner sees their audit rows');
select is((select count(*) from app.memberships), 1::bigint, 'a user sees only their own membership row');
select is(
  (select count(*) from app.customers where tenant_id = '10000000-0000-4000-a000-000000000002'),
  0::bigint,
  'asking for another tenant by id returns nothing'
);
select lives_ok(
  $$ insert into app.customers (tenant_id, full_name, email, phone)
     values ('10000000-0000-4000-a000-000000000001', 'Casey Madeup', 'casey.madeup@example.com', '555-0110') $$,
  'owner can add a customer to their tenant'
);
select throws_ok(
  $$ insert into app.customers (tenant_id, full_name)
     values ('10000000-0000-4000-a000-000000000002', 'Wrong Tenant') $$,
  '42501', 'new row violates row-level security policy for table "customers"',
  'owner cannot add a customer to another tenant'
);
select throws_ok(
  $$ update app.customers set tenant_id = '10000000-0000-4000-a000-000000000002'
     where id = '30000000-0000-4000-a000-000000000011' $$,
  '23514', null,
  'tenant_id cannot be changed'
);
with changed as (
  update app.jobs set title = 'hijacked'
  where tenant_id = '10000000-0000-4000-a000-000000000002'
  returning 1
)
select is((select count(*) from changed), 0::bigint, 'update aimed at another tenant touches 0 rows');
with gone as (
  delete from app.customers where full_name = 'Casey Madeup' returning 1
)
select is((select count(*) from gone), 1::bigint, 'owner can delete a customer');
select throws_ok(
  $$ insert into app.audit_log (tenant_id, actor, action)
     values ('10000000-0000-4000-a000-000000000001', 'me', 'forged') $$,
  '42501', 'permission denied for table audit_log',
  'humans cannot write the audit log'
);
select throws_ok(
  $$ update app.invoices set amount_cents = 1 $$,
  '42501', 'permission denied for table invoices',
  'humans cannot edit invoices'
);
reset role;

-- Viewer of north-sample: reads, never writes.
set local role authenticated;
set local request.jwt.claims = '{"sub":"20000000-0000-4000-a000-000000000003"}';
select is((select count(*) from app.customers), 2::bigint, 'viewer sees 2 customers');
select is((select count(*) from app.audit_log), 0::bigint, 'viewer cannot read the audit log');
select throws_ok(
  $$ insert into app.customers (tenant_id, full_name)
     values ('10000000-0000-4000-a000-000000000001', 'Viewer Attempt') $$,
  '42501', 'new row violates row-level security policy for table "customers"',
  'viewer cannot insert'
);
with changed as (
  update app.customers set full_name = 'changed' returning 1
)
select is((select count(*) from changed), 0::bigint, 'viewer update touches 0 rows');
with gone as (
  delete from app.customers returning 1
)
select is((select count(*) from gone), 0::bigint, 'viewer delete touches 0 rows');
reset role;

-- Member of south-example.
set local role authenticated;
set local request.jwt.claims = '{"sub":"20000000-0000-4000-a000-000000000002"}';
select results_eq(
  'select full_name from app.customers order by full_name',
  array['Morgan Example', 'Taylor Fictional'],
  'member of the other tenant sees only that tenant'
);
reset role;

-- Signed in, member of nothing.
set local role authenticated;
set local request.jwt.claims = '{"sub":"20000000-0000-4000-a000-000000000004"}';
select is(
  (select count(*) from app.customers) + (select count(*) from app.jobs)
    + (select count(*) from app.invoices) + (select count(*) from app.tenants),
  0::bigint,
  'a user with no membership sees nothing'
);
reset role;

select * from finish();
rollback;
