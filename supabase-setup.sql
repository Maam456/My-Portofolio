-- My Portofolio: secure project editing and publicly readable project images.
-- Create an admin user in Supabase Authentication before running the final
-- INSERT statement at the bottom. Disable public sign-ups in Auth settings.

create table if not exists public.portfolio_admins (
  user_id uuid primary key references auth.users (id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.portfolio_projects (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users (id) on delete cascade,
  title text not null check (char_length(title) between 1 and 60),
  description text not null check (char_length(description) between 1 and 180),
  icon text not null default '✨',
  url text,
  image_path text,
  created_at timestamptz not null default now()
);

create table if not exists public.portfolio_profile (
  id integer primary key check (id = 1),
  owner_id uuid not null references auth.users (id) on delete cascade,
  full_name text not null check (char_length(full_name) between 1 and 80),
  profession text not null check (char_length(profession) between 1 and 100),
  bio text not null check (char_length(bio) between 1 and 240),
  email text,
  phone text,
  instagram_url text,
  linkedin_url text,
  github_url text,
  website_url text,
  updated_at timestamptz not null default now()
);

alter table public.portfolio_admins enable row level security;
alter table public.portfolio_projects enable row level security;
alter table public.portfolio_profile enable row level security;

revoke all on public.portfolio_admins from anon, authenticated;
grant select on public.portfolio_projects to anon, authenticated;
grant insert, update, delete on public.portfolio_projects to authenticated;
grant select on public.portfolio_profile to anon, authenticated;
grant insert, update on public.portfolio_profile to authenticated;

create or replace function public.is_portfolio_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.portfolio_admins
    where user_id = (select auth.uid())
  );
$$;

revoke all on function public.is_portfolio_admin() from public, anon;
grant execute on function public.is_portfolio_admin() to authenticated;

drop policy if exists "Anyone can view portfolio projects" on public.portfolio_projects;
create policy "Anyone can view portfolio projects"
  on public.portfolio_projects for select
  to anon, authenticated
  using (true);

drop policy if exists "Portfolio admin can add own projects" on public.portfolio_projects;
create policy "Portfolio admin can add own projects"
  on public.portfolio_projects for insert
  to authenticated
  with check (public.is_portfolio_admin() and owner_id = (select auth.uid()));

drop policy if exists "Portfolio admin can update own projects" on public.portfolio_projects;
create policy "Portfolio admin can update own projects"
  on public.portfolio_projects for update
  to authenticated
  using (public.is_portfolio_admin() and owner_id = (select auth.uid()))
  with check (public.is_portfolio_admin() and owner_id = (select auth.uid()));

drop policy if exists "Portfolio admin can delete own projects" on public.portfolio_projects;
create policy "Portfolio admin can delete own projects"
  on public.portfolio_projects for delete
  to authenticated
  using (public.is_portfolio_admin() and owner_id = (select auth.uid()));

drop policy if exists "Anyone can view portfolio profile" on public.portfolio_profile;
create policy "Anyone can view portfolio profile"
  on public.portfolio_profile for select
  to anon, authenticated
  using (true);

drop policy if exists "Portfolio admin can add profile" on public.portfolio_profile;
create policy "Portfolio admin can add profile"
  on public.portfolio_profile for insert
  to authenticated
  with check (public.is_portfolio_admin() and owner_id = (select auth.uid()));

drop policy if exists "Portfolio admin can update profile" on public.portfolio_profile;
create policy "Portfolio admin can update profile"
  on public.portfolio_profile for update
  to authenticated
  using (public.is_portfolio_admin() and owner_id = (select auth.uid()))
  with check (public.is_portfolio_admin() and owner_id = (select auth.uid()));

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('project-images', 'project-images', true, 15728640, array['image/jpeg'])
on conflict (id) do update
  set public = true,
      file_size_limit = 15728640,
      allowed_mime_types = array['image/jpeg'];

drop policy if exists "Anyone can view project images" on storage.objects;
create policy "Anyone can view project images"
  on storage.objects for select
  to anon, authenticated
  using (bucket_id = 'project-images');

drop policy if exists "Portfolio admin can upload own project images" on storage.objects;
create policy "Portfolio admin can upload own project images"
  on storage.objects for insert
  to authenticated
  with check (
    bucket_id = 'project-images'
    and public.is_portfolio_admin()
    and (storage.foldername(name))[1] = (select auth.uid())::text
  );

drop policy if exists "Portfolio admin can update own project images" on storage.objects;
create policy "Portfolio admin can update own project images"
  on storage.objects for update
  to authenticated
  using (
    bucket_id = 'project-images'
    and public.is_portfolio_admin()
    and (storage.foldername(name))[1] = (select auth.uid())::text
  )
  with check (
    bucket_id = 'project-images'
    and public.is_portfolio_admin()
    and (storage.foldername(name))[1] = (select auth.uid())::text
  );

drop policy if exists "Portfolio admin can delete own project images" on storage.objects;
create policy "Portfolio admin can delete own project images"
  on storage.objects for delete
  to authenticated
  using (
    bucket_id = 'project-images'
    and public.is_portfolio_admin()
    and (storage.foldername(name))[1] = (select auth.uid())::text
  );

-- After creating your admin user, replace the address, then run this statement.
insert into public.portfolio_admins (user_id)
select id from auth.users where email = 'VOTRE_EMAIL_ADMIN'
on conflict (user_id) do nothing;
