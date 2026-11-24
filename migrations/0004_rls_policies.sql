-- 0004_rls_policies.sql
-- Tenant isolation.
--
-- Recipes in this file
--   1. ENABLE and FORCE row level security on every table. FORCE makes the
--      policies apply to the table owner as well.
--   2. Small SECURITY INVOKER helper functions answer "which tenants may the
--      caller touch". They read lookup tables whose own policies refer to no
--      other table, so there is no policy recursion and no need for a
--      SECURITY DEFINER helper.
--   3. Every policy names its command and its roles. Nothing applies to
--      PUBLIC. Humans (authenticated) and agents (app_agent) get separate
--      policies, so agents never depend on the auth schema.
--   4. Helpers that take no row argument are wrapped as
--      "in (select helper())" so the planner evaluates them once per
--      statement. app.user_has_role(tenant_id, ...) takes the row's tenant
--      and the pin check is called bare, so those run per row.
--   5. Every UPDATE policy has USING and WITH CHECK.
--   6. A RESTRICTIVE policy lets an agent that serves several tenants pin
--      one tenant for the current transaction:
--        set local app.tenant_id = '<tenant uuid>';

alter table app.tenants enable row level security;
alter table app.tenants force row level security;
alter table app.memberships enable row level security;
alter table app.memberships force row level security;
alter table app.agent_tenants enable row level security;
alter table app.agent_tenants force row level security;
alter table app.customers enable row level security;
alter table app.customers force row level security;
alter table app.jobs enable row level security;
alter table app.jobs force row level security;
alter table app.invoices enable row level security;
alter table app.invoices force row level security;
alter table app.audit_log enable row level security;
alter table app.audit_log force row level security;

-- ---------------------------------------------------------------------------
-- Helpers (SECURITY INVOKER: they run as the caller, under the caller's RLS)
-- ---------------------------------------------------------------------------

-- Tenants the signed in human belongs to.
create function app.user_tenant_ids() returns setof uuid
  language sql stable
  set search_path = ''
  as $$
    select m.tenant_id
    from app.memberships m
    where m.user_id = (select auth.uid())
  $$;

-- True when the signed in human holds one of the given roles in the tenant.
create function app.user_has_role(p_tenant_id uuid, p_roles text[]) returns boolean
  language sql stable
  set search_path = ''
  as $$
    select exists (
      select 1
      from app.memberships m
      where m.tenant_id = p_tenant_id
        and m.user_id = (select auth.uid())
        and m.member_role = any (p_roles)
    )
  $$;

-- Tenants the current agent role is assigned to.
create function app.agent_tenant_ids() returns setof uuid
  language sql stable
  set search_path = ''
  as $$
    select a.tenant_id
    from app.agent_tenants a
    where a.agent_role = current_user
  $$;

-- The tenant pinned for this transaction, or null. A value that is not a
-- uuid raises an error, so a bad pin fails closed.
create function app.pinned_tenant_id() returns uuid
  language sql stable
  set search_path = ''
  as $$
    select nullif(current_setting('app.tenant_id', true), '')::uuid
  $$;

alter function app.user_tenant_ids() owner to app_owner;
alter function app.user_has_role(uuid, text[]) owner to app_owner;
alter function app.agent_tenant_ids() owner to app_owner;
alter function app.pinned_tenant_id() owner to app_owner;

revoke execute on function app.user_tenant_ids() from public;
revoke execute on function app.user_has_role(uuid, text[]) from public;
revoke execute on function app.agent_tenant_ids() from public;
revoke execute on function app.pinned_tenant_id() from public;

grant execute on function app.user_tenant_ids() to authenticated;
grant execute on function app.user_has_role(uuid, text[]) to authenticated;
grant execute on function app.agent_tenant_ids() to app_agent;
grant execute on function app.pinned_tenant_id() to app_agent, app_definer;

-- ---------------------------------------------------------------------------
-- Lookup tables. Their policies refer to no other table.
-- ---------------------------------------------------------------------------

create policy memberships_select_own on app.memberships
  for select to authenticated
  using (user_id = (select auth.uid()));

create policy agent_tenants_select_own on app.agent_tenants
  for select to app_agent
  using (agent_role = current_user);

create policy agent_tenants_select_definer on app.agent_tenants
  for select to app_definer
  using (true);

-- ---------------------------------------------------------------------------
-- tenants
-- ---------------------------------------------------------------------------

create policy tenants_select_user on app.tenants
  for select to authenticated
  using (id in (select app.user_tenant_ids()));

create policy tenants_select_agent on app.tenants
  for select to app_agent
  using (id in (select app.agent_tenant_ids()));

-- ---------------------------------------------------------------------------
-- customers
-- ---------------------------------------------------------------------------

create policy customers_select_user on app.customers
  for select to authenticated
  using (tenant_id in (select app.user_tenant_ids()));

create policy customers_insert_user on app.customers
  for insert to authenticated
  with check (app.user_has_role(tenant_id, array['owner', 'member']));

create policy customers_update_user on app.customers
  for update to authenticated
  using (app.user_has_role(tenant_id, array['owner', 'member']))
  with check (app.user_has_role(tenant_id, array['owner', 'member']));

create policy customers_delete_owner on app.customers
  for delete to authenticated
  using (app.user_has_role(tenant_id, array['owner']));

create policy customers_select_agent on app.customers
  for select to app_agent
  using (tenant_id in (select app.agent_tenant_ids()));

create policy customers_insert_intake on app.customers
  for insert to agent_intake
  with check (tenant_id in (select app.agent_tenant_ids()));

create policy customers_agent_pin on app.customers
  as restrictive for all to app_agent
  using (app.pinned_tenant_id() is null or tenant_id = app.pinned_tenant_id());

-- ---------------------------------------------------------------------------
-- jobs
-- ---------------------------------------------------------------------------

create policy jobs_select_user on app.jobs
  for select to authenticated
  using (tenant_id in (select app.user_tenant_ids()));

create policy jobs_insert_user on app.jobs
  for insert to authenticated
  with check (app.user_has_role(tenant_id, array['owner', 'member']));

create policy jobs_update_user on app.jobs
  for update to authenticated
  using (app.user_has_role(tenant_id, array['owner', 'member']))
  with check (app.user_has_role(tenant_id, array['owner', 'member']));

create policy jobs_select_agent on app.jobs
  for select to app_agent
  using (tenant_id in (select app.agent_tenant_ids()));

create policy jobs_insert_intake on app.jobs
  for insert to agent_intake
  with check (tenant_id in (select app.agent_tenant_ids()));

create policy jobs_update_scheduler on app.jobs
  for update to agent_scheduler
  using (tenant_id in (select app.agent_tenant_ids()))
  with check (tenant_id in (select app.agent_tenant_ids()));

create policy jobs_agent_pin on app.jobs
  as restrictive for all to app_agent
  using (app.pinned_tenant_id() is null or tenant_id = app.pinned_tenant_id());

-- ---------------------------------------------------------------------------
-- invoices. Only the billing agent and read only roles hold grants here
-- (see 0005), so the agent policies name those roles and no others.
-- ---------------------------------------------------------------------------

create policy invoices_select_user on app.invoices
  for select to authenticated
  using (tenant_id in (select app.user_tenant_ids()));

create policy invoices_select_agent on app.invoices
  for select to agent_billing, app_readonly
  using (tenant_id in (select app.agent_tenant_ids()));

create policy invoices_insert_billing on app.invoices
  for insert to agent_billing
  with check (tenant_id in (select app.agent_tenant_ids()));

create policy invoices_update_billing on app.invoices
  for update to agent_billing
  using (tenant_id in (select app.agent_tenant_ids()))
  with check (tenant_id in (select app.agent_tenant_ids()));

create policy invoices_select_definer on app.invoices
  for select to app_definer
  using (true);

create policy invoices_agent_pin on app.invoices
  as restrictive for all to app_agent
  using (app.pinned_tenant_id() is null or tenant_id = app.pinned_tenant_id());

-- jobs are also read by the definer role (0006).
create policy jobs_select_definer on app.jobs
  for select to app_definer
  using (true);

-- ---------------------------------------------------------------------------
-- audit_log. Readable by tenant owners and read only roles. Writable only
-- through app.log_event() in 0006. No UPDATE or DELETE policy exists, so the
-- table is append only even for a role that somehow gained the grant.
-- ---------------------------------------------------------------------------

create policy audit_log_select_owner on app.audit_log
  for select to authenticated
  using (app.user_has_role(tenant_id, array['owner']));

create policy audit_log_select_readonly on app.audit_log
  for select to app_readonly
  using (tenant_id in (select app.agent_tenant_ids()));

create policy audit_log_insert_definer on app.audit_log
  for insert to app_definer
  with check (true);

create policy audit_log_agent_pin on app.audit_log
  as restrictive for all to app_agent
  using (app.pinned_tenant_id() is null or tenant_id = app.pinned_tenant_id());
