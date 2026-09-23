create or replace function public.check_auth_phone(phone_input text)
returns jsonb
language sql
security definer
set search_path = auth, public, pg_temp
as $$
  with normalized_input as (
    select case
      when regexp_replace(coalesce(phone_input, ''), '[^0-9]', '', 'g') ~ '^8[0-9]{10}$'
        then '7' || substring(regexp_replace(phone_input, '[^0-9]', '', 'g') from 2)
      when regexp_replace(coalesce(phone_input, ''), '[^0-9]', '', 'g') ~ '^[0-9]{10}$'
        then '7' || regexp_replace(phone_input, '[^0-9]', '', 'g')
      else regexp_replace(coalesce(phone_input, ''), '[^0-9]', '', 'g')
    end as phone
  ), normalized_users as (
    select
      u.*,
      case
        when regexp_replace(coalesce(u.phone, ''), '[^0-9]', '', 'g') ~ '^8[0-9]{10}$'
          then '7' || substring(regexp_replace(u.phone, '[^0-9]', '', 'g') from 2)
        when regexp_replace(coalesce(u.phone, ''), '[^0-9]', '', 'g') ~ '^[0-9]{10}$'
          then '7' || regexp_replace(u.phone, '[^0-9]', '', 'g')
        else regexp_replace(coalesce(u.phone, ''), '[^0-9]', '', 'g')
      end as normalized_phone
    from auth.users as u
  )
  select jsonb_build_object(
    'id', u.id,
    'phone', u.phone,
    'email', u.email,
    'role', u.role,
    'created_at', u.created_at
  )
  from normalized_users as u, normalized_input as i
  where u.normalized_phone = i.phone
  limit 1;
$$;

revoke all on function public.check_auth_phone(text) from public;
grant execute on function public.check_auth_phone(text) to service_role;
