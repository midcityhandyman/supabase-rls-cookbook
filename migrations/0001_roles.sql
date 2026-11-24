-- 0001_roles.sql
-- Recipe: one database role per agent, plus group roles that carry shared grants.
--
-- Roles are cluster wide, so every create is guarded and this file is safe to
-- run again. No role here can log in and no passwords live in this repository.
-- Enable login out of band, for example:
--   alter role agent_intake login password '<from your secret manager>';
--
-- Role map
--   app_owner       owns the tables. Never used to connect.
--   app_definer     owns SECURITY DEFINER functions. Holds only the narrow
--                   grants those functions need. Never used to connect.
--   app_agent       group role. Every agent is a member. Shared read grants.
--   app_readonly    group role. SELECT only, on everything it is given.
--   agent_intake    creates customers and jobs.
--   agent_scheduler moves jobs through their status and sets dates.
--   agent_billing   creates invoices and updates their status.
--   agent_reporter  read only. Member of app_readonly.
--
-- Why not service_role for agents: on Supabase that role bypasses row level
-- security entirely. An agent holding it can read every tenant.

do $$
declare
  r text;
begin
  -- Supabase ships these. Create them only on plain Postgres so the same
  -- policies can be tested without a Supabase stack.
  foreach r in array array['anon', 'authenticated'] loop
    if not exists (select 1 from pg_roles where rolname = r) then
      execute format('create role %I nologin', r);
    end if;
  end loop;

  foreach r in array array[
    'app_owner', 'app_definer', 'app_agent', 'app_readonly',
    'agent_intake', 'agent_scheduler', 'agent_billing', 'agent_reporter'
  ] loop
    if not exists (select 1 from pg_roles where rolname = r) then
      execute format(
        'create role %I nologin nosuperuser nocreatedb nocreaterole noreplication nobypassrls',
        r
      );
    end if;
  end loop;

  -- A managed platform runs migrations as a role that is not a superuser.
  -- That role must be a member of the owner roles to hand objects to them.
  if not (select rolsuper from pg_roles where rolname = current_user) then
    execute format('grant app_owner, app_definer to %I', current_user);
  end if;
end
$$;

-- Group membership. Policies written "to app_agent" apply to every member.
grant app_agent to agent_intake, agent_scheduler, agent_billing, agent_reporter;
grant app_readonly to agent_reporter;

-- Belt and braces for the read only agent. This is only a session default
-- that applies at login (not after SET ROLE) and the role could change it
-- for itself, so the real control is the absence of write grants in 0005.
alter role agent_reporter set default_transaction_read_only = on;

-- Functions grant EXECUTE to PUBLIC by default. Turn that off for anything
-- the owner roles create from now on. This has to be the global form:
-- a per schema ALTER DEFAULT PRIVILEGES cannot take away a global default.
alter default privileges for role app_owner revoke execute on functions from public;
alter default privileges for role app_definer revoke execute on functions from public;
