-- Run in Supabase SQL Editor. Enable Anonymous Sign-ins in Authentication > Providers.
create extension if not exists pgcrypto;
create table if not exists public.policies (
 id uuid primary key default gen_random_uuid(), title text not null check (char_length(title) between 3 and 160),
 category text not null, summary text not null check(char_length(summary) between 5 and 3000),
 source_url text not null check (source_url ~ '^https://'), source_date date,
 status text not null default 'published' check(status in ('published','hidden')),
 created_at timestamptz not null default now()
);
create table if not exists public.comments (
 id uuid primary key default gen_random_uuid(), policy_id uuid references public.policies(id) on delete cascade,
 proposal_id uuid, user_id uuid not null default auth.uid(), body text not null check(char_length(body) between 2 and 1000)),
 created_at timestamptz not null default now(), hidden boolean not null default false,
 constraint comment_target check ((policy_id is not null) <> (proposal_id is not null))
);
create table if not exists public.proposals (
 id uuid primary key default gen_random_uuid(), user_id uuid not null default auth.uid(),
 title text not null check(char_length(title) between 3 and 120),
 body text not null check(char_length(body) between 10 and 3000),
 hidden boolean not null default false, created_at timestamptz not null default now()
);
alter table public.comments add constraint comments_proposal_fk foreign key(proposal_id) references public.proposals(id) on delete cascade;
create table if not exists public.votes (
 user_id uuid not null default auth.uid(), policy_id uuid not null references public.policies(id) on delete cascade,
 value smallint not null check(value in (-1,1)), created_at timestamptz not null default now(),
 primary key(user_id,policy_id)
);
create table if not exists public.reports (
 id uuid primary key default gen_random_uuid(), reporter_id uuid not null default auth.uid(),
 comment_id uuid references public.comments(id) on delete cascade,
 proposal_id uuid references public.proposals(id) on delete cascade,
 reason text not null check(char_length(reason) between 5 and 500),
 created_at timestamptz not null default now(),
 constraint report_target check ((comment_id is not null) <> (proposal_id is not null))
);
create table if not exists public.admins (user_id uuid primary key);
-- Only service role (SQL editor) may appoint admins.
create or replace function public.is_admin() returns boolean language sql stable security definer set search_path = '' as $$
 select exists(select 1 from public.admins where user_id = (select auth.uid()));
$$;
revoke all on function public.is_admin() from public;
grant execute on function public.is_admin() to authenticated;
create or replace function public.check_post_rate() returns trigger language plpgsql security definer set search_path = '' as $$
begin
 if TG_TABLE_NAME = 'comments' and exists(select 1 from public.comments where user_id=NEW.user_id and created_at > now()-interval '30 seconds') then
  raise exception '댓글은 30초 간격으로 작성할 수 있습니다';
 elsif TG_TABLE_NAME = 'proposals' and exists(select 1 from public.proposals where user_id=NEW.user_id and created_at > now()-interval '60 seconds') then
  raise exception '제안은 60초 간격으로 작성할 수 있습니다';
 end if;
 return NEW;
end $$;
create trigger comments_rate before insert on public.comments for each row execute function public.check_post_rate();
create trigger proposals_rate before insert on public.proposals for each row execute function public.check_post_rate();
create or replace function public.prevent_identity_spoof() returns trigger language plpgsql set search_path = '' as $$
begin
 if NEW.user_id is distinct from (select auth.uid()) then raise exception '작성자 정보가 올바르지 않습니다'; end if;
 return NEW;
end $$;
create trigger comments_identity before insert on public.comments for each row execute function public.prevent_identity_spoof();
create trigger proposals_identity before insert on public.proposals for each row execute function public.prevent_identity_spoof();
create trigger votes_identity before insert or update on public.votes for each row execute function public.prevent_identity_spoof();
create trigger reports_identity before insert on public.reports for each row execute function public.prevent_identity_spoof();
alter table public.policies enable row level security;
alter table public.comments enable row level security;
alter table public.proposals enable row level security;
alter table public.votes enable row level security;
alter table public.reports enable row level security;
alter table public.admins enable row level security;
create policy policies_read on public.policies for select to anon,authenticated using(status='published' or public.is_admin());
create policy policies_admin_insert on public.policies for insert to authenticated with check(public.is_admin());
create policy policies_admin_update on public.policies for update to authenticated using(public.is_admin()) with check(public.is_admin());
create policy comments_read on public.comments for select to authenticated using(not hidden or public.is_admin());
create policy comments_insert on public.comments for insert to authenticated with check(user_id=(select auth.uid()) and hidden=false and ((policy_id is not null and exists(select 1 from public.policies p where p.id=policy_id and p.status='published')) or (proposal_id is not null and exists(select 1 from public.proposals p where p.id=proposal_id and not p.hidden))));
create policy comments_moderate on public.comments for update to authenticated using(public.is_admin()) with check(public.is_admin());
create policy proposals_read on public.proposals for select to authenticated using(not hidden or public.is_admin());
create policy proposals_insert on public.proposals for insert to authenticated with check(user_id=(select auth.uid()) and hidden=false);
create policy proposals_moderate on public.proposals for update to authenticated using(public.is_admin()) with check(public.is_admin());
create policy votes_read on public.votes for select to authenticated using(true);
create policy votes_insert on public.votes for insert to authenticated with check(user_id=(select auth.uid()) and exists(select 1 from public.policies p where p.id=policy_id and p.status='published'));
create policy votes_update on public.votes for update to authenticated using(user_id=(select auth.uid())) with check(user_id=(select auth.uid()));
create policy votes_delete on public.votes for delete to authenticated using(user_id=(select auth.uid()));
create policy reports_insert on public.reports for insert to authenticated with check(reporter_id=(select auth.uid()));
create policy reports_admin_read on public.reports for select to authenticated using(public.is_admin());
create policy admins_self_read on public.admins for select to authenticated using(user_id=(select auth.uid()));
create index if not exists comments_policy_idx on public.comments(policy_id,created_at desc);
create index if not exists comments_proposal_idx on public.comments(proposal_id,created_at desc);
create index if not exists proposals_created_idx on public.proposals(created_at desc);
create index if not exists reports_created_idx on public.reports(created_at desc);
-- Appoint administrator only after signing in and obtaining the auth.users UUID:
-- insert into public.admins(user_id) values ('YOUR-USER-UUID');
-- Add verified official source records via admin UI, not invented policy descriptions.
