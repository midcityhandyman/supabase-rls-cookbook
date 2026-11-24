-- 040_read_only.sql
-- The read only agent: reads across its tenants, writes nowhere.
begin;
select plan(17);
\ir ../seed/seed.sql

set local role agent_reporter;
select results_eq(
  'select slug from app.tenants order by slug',
  array['north-sample', 'south-example'],
  'reporter sees its two tenants'
);
select is((select count(*) from app.customers), 4::bigint, 'reporter reads customers');
select is((select count(*) from app.jobs), 4::bigint, 'reporter reads jobs');
select is((select count(*) from app.invoices), 3::bigint, 'reporter reads invoices');
select is((select count(*) from app.audit_log), 2::bigint, 'reporter reads the audit log');
select is(
  (select coalesce(sum(amount_cents), 0) from app.invoices
   where tenant_id = '10000000-0000-4000-a000-000000000003'),
  0::bigint,
  'reporter gets nothing for a tenant it is not assigned to'
);

select throws_ok(
  $$ insert into app.customers (tenant_id, full_name)
     values ('10000000-0000-4000-a000-000000000001', 'x') $$,
  '42501', 'permission denied for table customers', 'reporter cannot insert'
);
select throws_ok(
  $$ update app.customers set full_name = 'x' $$,
  '42501', 'permission denied for table customers', 'reporter cannot update'
);
select throws_ok(
  'delete from app.customers',
  '42501', 'permission denied for table customers', 'reporter cannot delete'
);
select throws_ok(
  'truncate app.audit_log',
  '42501', 'permission denied for table audit_log', 'reporter cannot truncate'
);
select throws_ok(
  $$ update app.jobs set status = 'done' $$,
  '42501', 'permission denied for table jobs', 'reporter cannot update jobs'
);
select throws_ok(
  $$ update app.invoices set status = 'void' $$,
  '42501', 'permission denied for table invoices', 'reporter cannot update invoices'
);
select throws_ok(
  $$ select app.log_event('10000000-0000-4000-a000-000000000001', 'report.run') $$,
  '42501', 'permission denied for function log_event',
  'reporter cannot write through the audit function either'
);
select throws_ok(
  'create table app.scratch (id int)',
  '42501', 'permission denied for schema app', 'reporter cannot create objects'
);
reset role;

select is_empty(
  $$ select c.relname from pg_class c
     join pg_namespace n on n.oid = c.relnamespace
     where n.nspname = 'app' and c.relkind = 'r'
       and (has_table_privilege('agent_reporter', c.oid, 'INSERT, UPDATE, DELETE, TRUNCATE')
            or has_any_column_privilege('agent_reporter', c.oid, 'INSERT, UPDATE')) $$,
  'reporter holds no write privilege on any app table, directly or inherited'
);
select is_empty(
  $$ select table_name, privilege_type from rls_audit.table_privileges
     where grantee = 'app_readonly' and privilege_type <> 'SELECT' $$,
  'the read only group is granted SELECT and nothing else'
);
select ok(
  (select 'default_transaction_read_only=on' = any (rolconfig)
   from pg_roles where rolname = 'agent_reporter'),
  'reporter sessions default to read only transactions'
);

select * from finish();
rollback;
