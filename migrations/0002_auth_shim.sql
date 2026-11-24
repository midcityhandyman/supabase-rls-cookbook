-- 0002_auth_shim.sql
-- Plain Postgres only. Supabase already has an auth schema, in which case
-- this file does nothing.
--
-- The shim reads the same setting that the Supabase API layer sets for each
-- request (request.jwt.claims), so policies written against auth.uid() behave
-- the same way in a bare Postgres container and in CI.

do $$
begin
  if not exists (select 1 from pg_namespace where nspname = 'auth') then
    create schema auth;

    create function auth.jwt() returns jsonb
      language sql stable
      set search_path = ''
      as $f$
        select coalesce(
          nullif(current_setting('request.jwt.claims', true), ''),
          '{}'
        )::jsonb
      $f$;

    create function auth.uid() returns uuid
      language sql stable
      set search_path = ''
      as $f$
        select nullif(auth.jwt() ->> 'sub', '')::uuid
      $f$;

    revoke all on schema auth from public;
    revoke execute on function auth.jwt() from public;
    revoke execute on function auth.uid() from public;
    grant usage on schema auth to authenticated;
    grant execute on function auth.jwt() to authenticated;
    grant execute on function auth.uid() to authenticated;
  end if;
end
$$;
