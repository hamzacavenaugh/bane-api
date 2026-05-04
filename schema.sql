-- =========================================================
-- BANE PERFORMANCE PEPTIDES — Supabase / Postgres schema
-- Run once in Supabase Dashboard → SQL Editor → New Query → Paste → Run.
-- Idempotent — safe to re-run.
-- =========================================================

create table if not exists admin_users (
  id            text primary key,
  email         text unique not null,
  password_hash text not null,
  created_at    timestamptz default now()
);

create table if not exists admin_sessions (
  token      text primary key,
  user_id    text references admin_users(id) on delete cascade,
  created_at timestamptz default now()
);
create index if not exists admin_sessions_created_idx on admin_sessions(created_at desc);

create table if not exists orders (
  id               text primary key,
  customer_name    text,
  customer_email   text,
  customer_phone   text,
  customer_address text,
  customer_zip     text,
  notes            text,
  items            jsonb default '[]'::jsonb,
  coupon_code      text,
  subtotal         numeric(10,2),
  discount         numeric(10,2),
  shipping         numeric(10,2),
  total            numeric(10,2),
  status           text default 'pending',
  created_at       timestamptz default now(),
  updated_at       timestamptz
);
create index if not exists orders_created_idx on orders(created_at desc);
create index if not exists orders_status_idx  on orders(status);

create table if not exists reviews (
  id          text primary key,
  name        text,
  location    text,
  rating      int,
  content     text,
  status      text default 'pending',
  visibility  text default 'public',
  created_at  timestamptz default now(),
  approved_at timestamptz
);
create index if not exists reviews_created_idx on reviews(created_at desc);
create index if not exists reviews_status_idx  on reviews(status);

create table if not exists coupons (
  id            text primary key,
  code          text unique not null,
  type          text not null check (type in ('percent','fixed')),
  value         numeric(10,2) not null,
  label         text,
  expires_at    timestamptz,
  max_uses      int,
  current_uses  int default 0,
  active        boolean default true,
  created_at    timestamptz default now()
);
create index if not exists coupons_code_idx on coupons(code);

create table if not exists product_overrides (
  id          text primary key,
  product_id  text unique not null,
  name        text,
  dose        text,
  price       numeric(10,2),
  image_url   text,
  active      boolean default true,
  updated_at  timestamptz default now()
);

create table if not exists custom_products (
  id           text primary key,
  name         text not null,
  dose         text,
  price        numeric(10,2),
  category     text default 'Other',
  description  text,
  image        text,
  custom       boolean default true,
  created_at   timestamptz default now()
);

create table if not exists analytics_events (
  id          bigserial primary key,
  event_type  text,
  page        text,
  product_id  text,
  user_agent  text,
  created_at  timestamptz default now()
);
create index if not exists analytics_created_idx on analytics_events(created_at desc);
create index if not exists analytics_type_idx    on analytics_events(event_type);

-- Defense in depth: enable RLS on every table. The Render backend uses the
-- Service Role key, which bypasses RLS by design. Any other key (anon,
-- authenticated) will be denied — there are no permissive policies.
alter table admin_users        enable row level security;
alter table admin_sessions     enable row level security;
alter table orders             enable row level security;
alter table reviews            enable row level security;
alter table coupons            enable row level security;
alter table product_overrides  enable row level security;
alter table custom_products    enable row level security;
alter table analytics_events   enable row level security;
