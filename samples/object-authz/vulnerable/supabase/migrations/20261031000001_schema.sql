-- Shared schema of the object-level authorization sample (identical in all versions).

create table public.tenants (
  id uuid primary key,
  name text not null
);

create table public.memberships (
  tenant_id uuid not null references public.tenants (id),
  user_id uuid not null references auth.users (id),
  role text not null check (role in ('member', 'admin')),
  primary key (tenant_id, user_id)
);

create table public.documents (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id),
  owner_id uuid not null references auth.users (id),
  title text not null,
  body text not null,
  shared boolean not null default false
);

alter table public.tenants enable row level security;
alter table public.memberships enable row level security;
alter table public.documents enable row level security;

grant select on public.tenants, public.memberships to authenticated;
grant select, insert, update, delete on public.documents to authenticated;

create policy "members read their tenants" on public.tenants
  for select to authenticated
  using (id in (select tenant_id from public.memberships where user_id = auth.uid()));

create policy "users read their memberships" on public.memberships
  for select to authenticated
  using (user_id = auth.uid());

-- Public data: announcements are readable by anyone, signed in or not. USING (true) is the
-- legitimate read policy here (TK-DYN-004), not a vulnerability.
create table public.announcements (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  body text not null
);

alter table public.announcements enable row level security;
grant select on public.announcements to anon, authenticated;

create policy "anyone reads announcements" on public.announcements
  for select to anon, authenticated
  using (true);
