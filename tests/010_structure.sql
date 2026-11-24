-- 010_structure.sql
-- The shape of the install: schemas, tables, roles, ownership, RLS flags.
begin;
select plan(28);

select has_schema('app');
select has_schema('rls_audit');

select tables_are('app', array[
  'tenants', 'memberships', 'agent_tenants', 'customers', 'jobs', 'invoices', 'audit_log'
]);

select has_role('app_owner');
select has_role('app_definer');
select has_role('app_agent');
select has_role('app_readonly');
select has_role('agent_intake');
select has_role('agent_scheduler');
select has_role('agent_billing');
select has_role('agent_reporter');

select is_member_of('app_agent', array[
  'agent_intake', 'agent_scheduler', 'agent_billing', 'agent_reporter'
]);
select is_member_of('app_readonly', array['agent_reporter']);

select is_empty(
  $$ select rolname from pg_roles
     where (rolname like 'app\_%' or rolname like 'agent\_%')
       and (rolsuper or rolbypassrls or rolcreaterole or rolcreatedb or rolcanlogin) $$,
  'no cookbook role is privileged or able to log in out of the box'
);

select is_empty(
  $$ select c.relname from pg_class c
     join pg_namespace n on n.oid = c.relnamespace
     where n.nspname = 'app' and c.relkind = 'r'
       and pg_get_userbyid(c.relowner) <> 'app_owner' $$,
  'every app table is owned by app_owner'
);

select is_empty(
  $$ select c.relname from pg_class c
     join pg_namespace n on n.oid = c.relnamespace
     where n.nspname = 'app' and c.relkind = 'r'
       and not (c.relrowsecurity and c.relforcerowsecurity) $$,
  'every app table has row level security enabled and forced'
);

select is_empty(
  $$ select c.relname from pg_class c
     join pg_namespace n on n.oid = c.relnamespace
     where n.nspname = 'app' and c.relkind = 'r'
       and not exists (select 1 from pg_policy p where p.polrelid = c.oid) $$,
  'every app table has at least one policy'
);

select is_empty(
  $$ select p.polname from pg_policy p
     join pg_class c on c.oid = p.polrelid
     join pg_namespace n on n.oid = c.relnamespace
     where n.nspname = 'app' and p.polroles = '{0}'::oid[] $$,
  'no policy applies to PUBLIC'
);

select is_empty(
  $$ select p.polname from pg_policy p
     join pg_class c on c.oid = p.polrelid
     join pg_namespace n on n.oid = c.relnamespace
     where n.nspname = 'app' and p.polcmd = 'w'
       and (p.polqual is null or p.polwithcheck is null) $$,
  'every UPDATE policy has both USING and WITH CHECK'
);

select policies_are('app', 'memberships', array['memberships_select_own']);
select policies_are('app', 'agent_tenants', array[
  'agent_tenants_select_own', 'agent_tenants_select_definer'
]);
select policies_are('app', 'audit_log', array[
  'audit_log_select_owner', 'audit_log_select_readonly',
  'audit_log_insert_definer', 'audit_log_agent_pin'
]);

select has_trigger('app'::name, 'customers'::name, 'customers_tenant_immutable'::name);
select has_trigger('app'::name, 'jobs'::name, 'jobs_tenant_immutable'::name);
select has_trigger('app'::name, 'invoices'::name, 'invoices_tenant_immutable'::name);

select fk_ok('app', 'jobs', array['tenant_id', 'customer_id'],
             'app', 'customers', array['tenant_id', 'id']);
select fk_ok('app', 'invoices', array['tenant_id', 'job_id'],
             'app', 'jobs', array['tenant_id', 'id']);

select is_empty(
  $$ select p.proname from pg_proc p
     join pg_namespace n on n.oid = p.pronamespace
     where n.nspname = 'app'
       and has_function_privilege('public', p.oid, 'execute') $$,
  'no function in app is executable by PUBLIC'
);

select * from finish();
rollback;
