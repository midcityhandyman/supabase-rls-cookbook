-- seed.sql
-- Synthetic data only. Every name, email and phone number here is invented:
-- emails use example.com and phone numbers use the reserved 555-01xx range.
-- Run as the migration role (it bypasses row level security).
-- Used by the pgTAP tests (inside a transaction that rolls back) and the demo.

insert into app.tenants (id, slug, name) values
  ('10000000-0000-4000-a000-000000000001', 'north-sample',  'North Sample Co'),
  ('10000000-0000-4000-a000-000000000002', 'south-example', 'South Example Co'),
  ('10000000-0000-4000-a000-000000000003', 'west-demo',     'West Demo Co');

-- Human users (JWT subjects).
--   ...0001 owner of north-sample
--   ...0002 member of south-example
--   ...0003 viewer of north-sample
--   ...0004 signed in, member of nothing
insert into app.memberships (tenant_id, user_id, member_role) values
  ('10000000-0000-4000-a000-000000000001', '20000000-0000-4000-a000-000000000001', 'owner'),
  ('10000000-0000-4000-a000-000000000002', '20000000-0000-4000-a000-000000000002', 'member'),
  ('10000000-0000-4000-a000-000000000001', '20000000-0000-4000-a000-000000000003', 'viewer');

-- Agents. Nobody is assigned to west-demo.
insert into app.agent_tenants (agent_role, tenant_id) values
  ('agent_intake',    '10000000-0000-4000-a000-000000000001'),
  ('agent_intake',    '10000000-0000-4000-a000-000000000002'),
  ('agent_scheduler', '10000000-0000-4000-a000-000000000001'),
  ('agent_billing',   '10000000-0000-4000-a000-000000000002'),
  ('agent_reporter',  '10000000-0000-4000-a000-000000000001'),
  ('agent_reporter',  '10000000-0000-4000-a000-000000000002');

insert into app.customers (id, tenant_id, full_name, email, phone) values
  ('30000000-0000-4000-a000-000000000011', '10000000-0000-4000-a000-000000000001', 'Jordan Sample',      'jordan.sample@example.com',      '555-0101'),
  ('30000000-0000-4000-a000-000000000012', '10000000-0000-4000-a000-000000000001', 'Riley Placeholder',  'riley.placeholder@example.com',  '555-0102'),
  ('30000000-0000-4000-a000-000000000021', '10000000-0000-4000-a000-000000000002', 'Morgan Example',     'morgan.example@example.com',     '555-0103'),
  ('30000000-0000-4000-a000-000000000022', '10000000-0000-4000-a000-000000000002', 'Taylor Fictional',   'taylor.fictional@example.com',   '555-0104'),
  ('30000000-0000-4000-a000-000000000031', '10000000-0000-4000-a000-000000000003', 'Quinn Demo',         'quinn.demo@example.com',         '555-0105');

insert into app.jobs (id, tenant_id, customer_id, title, status, scheduled_for) values
  ('40000000-0000-4000-a000-000000000011', '10000000-0000-4000-a000-000000000001', '30000000-0000-4000-a000-000000000011', 'Replace kitchen faucet', 'new',       null),
  ('40000000-0000-4000-a000-000000000012', '10000000-0000-4000-a000-000000000001', '30000000-0000-4000-a000-000000000012', 'Patch hallway drywall',  'scheduled', '2030-01-15'),
  ('40000000-0000-4000-a000-000000000021', '10000000-0000-4000-a000-000000000002', '30000000-0000-4000-a000-000000000021', 'Deep clean office',      'new',       null),
  ('40000000-0000-4000-a000-000000000022', '10000000-0000-4000-a000-000000000002', '30000000-0000-4000-a000-000000000022', 'Wash front windows',     'done',      '2030-01-10'),
  ('40000000-0000-4000-a000-000000000031', '10000000-0000-4000-a000-000000000003', '30000000-0000-4000-a000-000000000031', 'Repair garden fence',    'new',       null);

insert into app.invoices (id, tenant_id, job_id, amount_cents, status) values
  ('50000000-0000-4000-a000-000000000011', '10000000-0000-4000-a000-000000000001', '40000000-0000-4000-a000-000000000011', 18000, 'sent'),
  ('50000000-0000-4000-a000-000000000012', '10000000-0000-4000-a000-000000000001', '40000000-0000-4000-a000-000000000012',  9500, 'paid'),
  ('50000000-0000-4000-a000-000000000021', '10000000-0000-4000-a000-000000000002', '40000000-0000-4000-a000-000000000021', 22000, 'sent'),
  ('50000000-0000-4000-a000-000000000031', '10000000-0000-4000-a000-000000000003', '40000000-0000-4000-a000-000000000031', 31000, 'sent');

insert into app.audit_log (tenant_id, actor, action) values
  ('10000000-0000-4000-a000-000000000001', 'seed', 'seed.loaded'),
  ('10000000-0000-4000-a000-000000000002', 'seed', 'seed.loaded'),
  ('10000000-0000-4000-a000-000000000003', 'seed', 'seed.loaded');
