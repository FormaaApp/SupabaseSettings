-- supabase/migrations/20260915222100_test_migration.sql

create table public.test_items (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  created_at timestamptz not null default now()
);

alter table public.test_items enable row level security;

create policy "Users can read test items"
on public.test_items
for select
to authenticated
using (true);

insert into public.test_items (name)
values ('Test item');
