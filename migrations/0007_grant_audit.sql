-- 0007_grant_audit.sql
-- Grant audit views. Policies drift: someone adds a table and forgets RLS, or
-- a quick fix grants too much. These views turn "who can do what" into rows
-- you can read, diff, and assert on in a test.
--
--   rls_audit.table_privileges   one row per grant (table and column level)
--   rls_audit.role_matrix        one row per table and role
--   rls_audit.rls_status         RLS flags and policy count per table
--   rls_audit.definer_functions  every SECURITY DEFINER function and its risks
--   rls_audit.findings           problems only. Empty means clean.
--
-- By default the views look at schema "app". To audit other schemas:
--   set rls_audit.schemas = 'app,billing';
--
-- queries/grant_audit.sql is a standalone version of the matrix that needs
-- nothing installed.

create schema rls_audit;
revoke all on schema rls_audit from public;

create function rls_audit.audited_schemas() returns name[]
  language sql stable
  set search_path = ''
  as $$
    select string_to_array(
      coalesce(nullif(current_setting('rls_audit.schemas', true), ''), 'app'),
      ','
    )::name[]
  $$;
revoke execute on function rls_audit.audited_schemas() from public;

create view rls_audit.table_privileges as
select
  n.nspname::text as schema_name,
  c.relname::text as table_name,
  case when a.grantee = 0 then 'PUBLIC' else pg_get_userbyid(a.grantee)::text end as grantee,
  a.privilege_type::text as privilege_type,
  null::text as column_name
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
cross join lateral aclexplode(c.relacl) a
where c.relkind in ('r', 'p', 'v', 'm')
  and n.nspname = any (rls_audit.audited_schemas())
  and a.grantee <> c.relowner
union all
select
  n.nspname::text,
  c.relname::text,
  case when a.grantee = 0 then 'PUBLIC' else pg_get_userbyid(a.grantee)::text end,
  a.privilege_type::text,
  att.attname::text
from pg_attribute att
join pg_class c on c.oid = att.attrelid
join pg_namespace n on n.oid = c.relnamespace
cross join lateral aclexplode(att.attacl) a
where c.relkind in ('r', 'p', 'v', 'm')
  and att.attnum > 0
  and not att.attisdropped
  and n.nspname = any (rls_audit.audited_schemas())
  and a.grantee <> c.relowner;

create view rls_audit.role_matrix as
select
  p.schema_name,
  p.table_name,
  p.grantee,
  string_agg(p.priv, ', ' order by p.priv) as privileges
from (
  select distinct
    schema_name,
    table_name,
    grantee,
    case
      when column_name is null then privilege_type
      else privilege_type || '(' || column_name || ')'
    end as priv
  from rls_audit.table_privileges
) p
group by p.schema_name, p.table_name, p.grantee;

create view rls_audit.rls_status as
select
  n.nspname::text as schema_name,
  c.relname::text as table_name,
  pg_get_userbyid(c.relowner)::text as table_owner,
  c.relrowsecurity as rls_enabled,
  c.relforcerowsecurity as rls_forced,
  (select count(*) from pg_policy pol where pol.polrelid = c.oid) as policy_count
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('r', 'p')
  and n.nspname = any (rls_audit.audited_schemas());

create view rls_audit.definer_functions as
select
  n.nspname::text as schema_name,
  p.oid::regprocedure::text as function_signature,
  o.rolname::text as function_owner,
  (o.rolsuper or o.rolbypassrls) as owner_is_privileged,
  exists (
    select 1 from unnest(p.proconfig) cfg where cfg like 'search_path=%'
  ) as search_path_is_set,
  has_function_privilege('public', p.oid, 'execute') as public_can_execute
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
join pg_roles o on o.oid = p.proowner
where p.prosecdef
  and n.nspname = any (rls_audit.audited_schemas());

create view rls_audit.findings as
select 'high'::text as severity, 'rls_disabled'::text as check_name,
       schema_name || '.' || table_name as object_name,
       'row level security is not enabled'::text as detail
from rls_audit.rls_status
where not rls_enabled
union all
select 'medium', 'rls_not_forced', schema_name || '.' || table_name,
       'owner ' || table_owner || ' is exempt from the policies'
from rls_audit.rls_status
where rls_enabled and not rls_forced
union all
select 'low', 'rls_no_policies', schema_name || '.' || table_name,
       'enabled with no policies: every non owner query returns nothing'
from rls_audit.rls_status
where rls_enabled and policy_count = 0
union all
select 'high', 'public_table_grant', schema_name || '.' || table_name,
       grantee || ' holds ' || privilege_type
from rls_audit.table_privileges
where grantee in ('PUBLIC', 'anon')
union all
select 'medium', 'policy_for_public', n.nspname || '.' || c.relname,
       'policy ' || pol.polname || ' has no TO clause and applies to every role'
from pg_policy pol
join pg_class c on c.oid = pol.polrelid
join pg_namespace n on n.oid = c.relnamespace
where pol.polroles = '{0}'::oid[]
  and n.nspname = any (rls_audit.audited_schemas())
union all
select 'high', 'definer_no_search_path', function_signature,
       'SECURITY DEFINER without a fixed search_path'
from rls_audit.definer_functions
where not search_path_is_set
union all
select 'high', 'definer_public_execute', function_signature,
       'SECURITY DEFINER function executable by PUBLIC'
from rls_audit.definer_functions
where public_can_execute
union all
select 'high', 'definer_privileged_owner', function_signature,
       'owner ' || function_owner || ' is a superuser or has BYPASSRLS'
from rls_audit.definer_functions
where owner_is_privileged
union all
select 'high', 'readonly_role_can_write', s.schema_name || '.' || s.table_name,
       r.rolname || ' is read only (app_readonly) but holds a write privilege'
from rls_audit.rls_status s
join pg_roles r on r.rolname !~ '^pg_'
where exists (select 1 from pg_roles g where g.rolname = 'app_readonly')
  and not r.rolsuper
  and pg_has_role(r.oid, 'app_readonly', 'member')
  and (
    has_table_privilege(
      r.oid, format('%I.%I', s.schema_name, s.table_name),
      'INSERT, UPDATE, DELETE, TRUNCATE')
    or has_any_column_privilege(
      r.oid, format('%I.%I', s.schema_name, s.table_name),
      'INSERT, UPDATE')
  )
union all
select 'high', 'agent_is_privileged', r.rolname::text,
       'agent role is a superuser, has BYPASSRLS, or can create roles'
from pg_roles r
join pg_auth_members m on m.member = r.oid
join pg_roles g on g.oid = m.roleid and g.rolname = 'app_agent'
where r.rolsuper or r.rolbypassrls or r.rolcreaterole;
