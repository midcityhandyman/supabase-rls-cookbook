-- grant_audit.sql
-- Standalone grant audit. Needs nothing installed: paste it into psql or the
-- Supabase SQL editor. One row per table and role, with the role's table and
-- column privileges and the table's RLS state side by side.
--
-- Change the schema list in the first CTE to audit other schemas.
--
-- How to read it
--   rls = 'forced'   policies apply to everyone, including the table owner
--   rls = 'enabled'  policies apply, but the owner is exempt
--   rls = 'OFF'      every grant below is a grant on all rows
--   grantee PUBLIC or anon on a business table is almost always a mistake

with audited as (
  select unnest(array['app'])::name as schema_name
),
grants as (
  select c.oid as table_oid, a.grantee, a.privilege_type::text as priv
  from pg_class c
  cross join lateral aclexplode(c.relacl) a
  where a.grantee <> c.relowner
  union
  select att.attrelid, a.grantee, a.privilege_type || '(' || att.attname || ')'
  from pg_attribute att
  join pg_class c on c.oid = att.attrelid
  cross join lateral aclexplode(att.attacl) a
  where att.attnum > 0
    and not att.attisdropped
    and a.grantee <> c.relowner
)
select
  n.nspname as schema_name,
  c.relname as table_name,
  case
    when c.relrowsecurity and c.relforcerowsecurity then 'forced'
    when c.relrowsecurity then 'enabled'
    else 'OFF'
  end as rls,
  (select count(*) from pg_policy p where p.polrelid = c.oid) as policies,
  case when g.grantee = 0 then 'PUBLIC' else pg_get_userbyid(g.grantee)::text end as grantee,
  string_agg(g.priv, ', ' order by g.priv) as privileges
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
join audited a on a.schema_name = n.nspname
join grants g on g.table_oid = c.oid
where c.relkind in ('r', 'p', 'v', 'm')
group by n.nspname, c.relname, c.relrowsecurity, c.relforcerowsecurity, c.oid, g.grantee
order by schema_name, table_name, grantee;
