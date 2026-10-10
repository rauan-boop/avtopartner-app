create table if not exists public.webauthn_credentials (
  credential_id text primary key,
  user_id uuid not null references public.profiles(id) on delete cascade,
  public_key text not null,
  counter bigint not null default 0,
  transports text[] not null default '{}',
  created_at timestamptz not null default now()
);

create index if not exists webauthn_credentials_user_id_idx
  on public.webauthn_credentials(user_id);

alter table public.webauthn_credentials enable row level security;
