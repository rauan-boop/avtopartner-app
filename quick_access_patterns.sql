create table if not exists public.quick_access_patterns (
  user_id uuid primary key references public.profiles(id) on delete cascade,
  pattern_salt text not null,
  pattern_hash text not null,
  updated_at timestamptz not null default now()
);

alter table public.quick_access_patterns enable row level security;
