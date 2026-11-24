-- 0006_security_definer.sql
-- SECURITY DEFINER functions, done safely.
--
-- A definer function runs with its owner's privileges, so each one is a
-- small, deliberate hole in the wall. The checklist every function here
-- follows (static_checks and tests/050 enforce it):
--
--   1. Owned by app_definer: not a superuser, no BYPASSRLS, cannot log in,
--      and holding only the grants and policies the function bodies need.
--   2. set search_path = '' and every object schema qualified, so a caller
--      cannot swap in its own table or operator.
--   3. EXECUTE revoked from PUBLIC, then granted to named roles only.
--   4. The function re-checks who is calling and what they may touch.
--      It never trusts an argument for identity.
--   5. No dynamic SQL. Arguments are only ever used as values.
--   6. It returns the least it can: void, or one boolean.
--
-- Who is calling? Inside a definer function current_user is the owner, so it
-- is useless for this. app.caller_role() reads the role setting instead,
-- which SET ROLE (and the Supabase API layer) sets and which a definer
-- function does not change. With a direct login and no SET ROLE that setting
-- is 'none' and session_user is the caller.

create function app.caller_role() returns name
  language sql stable
  set search_path = ''
  as $$
    select case
      when coalesce(current_setting('role', true), 'none') in ('none', '')
        then session_user
      else current_setting('role', true)::name
    end
  $$;

-- Recipe A: write through a function to a table the caller cannot write.
-- Agents hold no INSERT on app.audit_log. This is the only way in, and it
-- stamps the actor itself.
create function app.log_event(
  p_tenant_id uuid,
  p_action    text,
  p_detail    jsonb default '{}'::jsonb
) returns void
  language plpgsql volatile
  security definer
  set search_path = ''
  as $$
declare
  v_caller name := app.caller_role();
  v_pin    uuid := app.pinned_tenant_id();
begin
  if p_tenant_id is null or p_action is null then
    raise exception 'tenant and action are required'
      using errcode = '22004';
  end if;

  if not exists (
    select 1
    from app.agent_tenants a
    where a.agent_role = v_caller
      and a.tenant_id = p_tenant_id
  ) then
    raise exception 'role % may not log events for tenant %', v_caller, p_tenant_id
      using errcode = '42501';
  end if;

  if v_pin is not null and v_pin <> p_tenant_id then
    raise exception 'tenant % is not the pinned tenant', p_tenant_id
      using errcode = '42501';
  end if;

  insert into app.audit_log (tenant_id, actor, action, detail)
  values (p_tenant_id, v_caller, p_action, coalesce(p_detail, '{}'::jsonb));
end
$$;

-- Recipe B: expose one narrow fact across a privilege boundary.
-- The scheduler cannot read invoices, but it should not book more work on a
-- job with an unpaid invoice. It gets a single boolean. A job outside the
-- caller's tenants answers false, the same as a job with nothing owing, so
-- the function does not reveal whether such a job exists.
create function app.job_has_unpaid_invoice(p_job_id uuid) returns boolean
  language sql stable
  security definer
  set search_path = ''
  as $$
    select exists (
      select 1
      from app.jobs j
      join app.invoices i
        on i.tenant_id = j.tenant_id
       and i.job_id = j.id
      where j.id = p_job_id
        and i.status = 'sent'
        and j.tenant_id in (
          select a.tenant_id
          from app.agent_tenants a
          where a.agent_role = app.caller_role()
        )
    )
  $$;

alter function app.caller_role() owner to app_definer;
alter function app.log_event(uuid, text, jsonb) owner to app_definer;
alter function app.job_has_unpaid_invoice(uuid) owner to app_definer;

revoke execute on function app.caller_role() from public;
revoke execute on function app.log_event(uuid, text, jsonb) from public;
revoke execute on function app.job_has_unpaid_invoice(uuid) from public;

-- The read only agent is left out on purpose: writing an audit row is a write.
grant execute on function app.log_event(uuid, text, jsonb)
  to agent_intake, agent_scheduler, agent_billing;
grant execute on function app.job_has_unpaid_invoice(uuid) to agent_scheduler;
