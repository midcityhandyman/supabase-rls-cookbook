-- 0003_schema.sql
-- A small multi tenant schema for a service business: tenants, the people and
-- agents allowed into each tenant, and three business tables.
--
-- Recipes in this file
--   1. Every tenant owned row carries tenant_id. No exceptions.
--   2. Composite foreign keys (tenant_id, id) so a child row can never point
--      at a parent in another tenant, whatever the policies say.
--   3. tenant_id is immutable after insert (trigger).
--   4. Tables are owned by a role that cannot log in.

create schema app authorization app_owner;
revoke all on schema app from public;

create table app.tenants (
  id         uuid primary key default gen_random_uuid(),
  slug       text not null unique check (slug ~ '^[a-z0-9-]{3,40}$'),
  name       text not null,
  created_at timestamptz not null default now()
);

-- Human users, keyed by the JWT subject (auth.uid()).
create table app.memberships (
  tenant_id   uuid not null references app.tenants (id) on delete cascade,
  user_id     uuid not null,
  member_role text not null check (member_role in ('owner', 'member', 'viewer')),
  primary key (tenant_id, user_id)
);
create index memberships_user_idx on app.memberships (user_id);

-- Agents, keyed by database role name. An agent acts only for the tenants
-- listed here. Rows are managed by an administrator, never by the agents.
create table app.agent_tenants (
  agent_role name not null,
  tenant_id  uuid not null references app.tenants (id) on delete cascade,
  primary key (agent_role, tenant_id)
);

create table app.customers (
  id         uuid primary key default gen_random_uuid(),
  tenant_id  uuid not null references app.tenants (id),
  full_name  text not null,
  email      text,
  phone      text,
  created_at timestamptz not null default now(),
  unique (tenant_id, id)
);
create index customers_tenant_idx on app.customers (tenant_id);

create table app.jobs (
  id            uuid primary key default gen_random_uuid(),
  tenant_id     uuid not null references app.tenants (id),
  customer_id   uuid not null,
  title         text not null,
  status        text not null default 'new'
                check (status in ('new', 'scheduled', 'done', 'cancelled')),
  scheduled_for date,
  created_at    timestamptz not null default now(),
  unique (tenant_id, id),
  foreign key (tenant_id, customer_id) references app.customers (tenant_id, id)
);
create index jobs_tenant_idx on app.jobs (tenant_id);

create table app.invoices (
  id           uuid primary key default gen_random_uuid(),
  tenant_id    uuid not null references app.tenants (id),
  job_id       uuid not null,
  amount_cents integer not null check (amount_cents >= 0),
  status       text not null default 'draft'
               check (status in ('draft', 'sent', 'paid', 'void')),
  issued_at    timestamptz not null default now(),
  unique (tenant_id, id),
  foreign key (tenant_id, job_id) references app.jobs (tenant_id, id)
);
create index invoices_tenant_idx on app.invoices (tenant_id);

-- Append only. Nobody gets INSERT here except the definer role in 0006,
-- and nobody at all gets UPDATE or DELETE.
create table app.audit_log (
  id        bigint generated always as identity primary key,
  tenant_id uuid not null references app.tenants (id),
  actor     name not null,
  action    text not null check (length(action) between 1 and 80),
  detail    jsonb not null default '{}'::jsonb,
  logged_at timestamptz not null default now()
);
create index audit_log_tenant_idx on app.audit_log (tenant_id);

-- Recipe 3: a row never changes tenant. The WITH CHECK half of an update
-- policy only proves the new tenant is one the writer may use, which still
-- lets a writer with two tenants move a row between them.
create function app.forbid_tenant_change() returns trigger
  language plpgsql
  set search_path = ''
  as $$
begin
  if new.tenant_id is distinct from old.tenant_id then
    raise exception 'tenant_id is immutable on %.%', tg_table_schema, tg_table_name
      using errcode = '23514';
  end if;
  return new;
end
$$;
revoke execute on function app.forbid_tenant_change() from public;

create trigger customers_tenant_immutable before update on app.customers
  for each row execute function app.forbid_tenant_change();
create trigger jobs_tenant_immutable before update on app.jobs
  for each row execute function app.forbid_tenant_change();
create trigger invoices_tenant_immutable before update on app.invoices
  for each row execute function app.forbid_tenant_change();

-- Recipe 4: hand everything to the owner role.
alter table app.tenants owner to app_owner;
alter table app.memberships owner to app_owner;
alter table app.agent_tenants owner to app_owner;
alter table app.customers owner to app_owner;
alter table app.jobs owner to app_owner;
alter table app.invoices owner to app_owner;
alter table app.audit_log owner to app_owner;
alter function app.forbid_tenant_change() owner to app_owner;
