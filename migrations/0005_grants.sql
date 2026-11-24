-- 0005_grants.sql
-- Grants decide which tables and commands a role may use at all.
-- Policies (0004) decide which rows. A role needs both.
--
-- Recipes in this file
--   1. No GRANT ALL and nothing granted to PUBLIC or anon.
--   2. Shared reads go to a group role. Writes go to one named agent each.
--   3. Column level UPDATE grants keep an agent to the columns it owns.
--   4. The read only group gets SELECT and nothing else.

grant usage on schema app to authenticated, app_agent, app_readonly, app_definer;

-- Humans. Row level rules live in the policies.
grant select on app.tenants, app.memberships, app.customers, app.jobs,
  app.invoices, app.audit_log to authenticated;
grant insert, update, delete on app.customers to authenticated;
grant insert, update on app.jobs to authenticated;

-- Every agent: read its tenants, its own assignment rows, customers, jobs.
grant select on app.tenants, app.agent_tenants, app.customers, app.jobs to app_agent;

-- agent_intake creates customers and jobs. It cannot change or remove them.
grant insert on app.customers, app.jobs to agent_intake;

-- agent_scheduler changes two columns of a job and nothing else.
grant update (status, scheduled_for) on app.jobs to agent_scheduler;

-- agent_billing owns invoices. It may change the status but never the amount.
grant select, insert on app.invoices to agent_billing;
grant update (status) on app.invoices to agent_billing;

-- Read only group: SELECT on the tables the shared agent grant leaves out.
grant select on app.invoices, app.audit_log to app_readonly;

-- The definer role: exactly what the functions in 0006 need.
grant select on app.agent_tenants, app.jobs, app.invoices to app_definer;
grant insert on app.audit_log to app_definer;
