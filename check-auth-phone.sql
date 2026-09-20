create or replace function public.check_auth_phone(phone_input text)
returns jsonb
language sql
security definer
set search_path = auth, public, pg_temp
as $$
  select jsonb_build_object(
    'id', u.id,
    'phone', u.phone,
    'email', u.email,
    'role', u.role,
    'created_at', u.created_at
  )
  from auth.users as u
  where regexp_replace(coalesce(u.phone, ''), '[^0-9]', '', 'g') = regexp_replace(coalesce(phone_input, ''), '[^0-9]', '', 'g')
  limit 1;
$$;

revoke all on function public.check_auth_phone(text) from public;
grant execute on function public.check_auth_phone(text) to service_role;
