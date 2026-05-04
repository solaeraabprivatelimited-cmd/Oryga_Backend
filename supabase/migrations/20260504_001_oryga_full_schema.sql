-- Oryga full Supabase schema
-- Run this single migration in Supabase before deploying the Edge Function.

create extension if not exists pgcrypto;

create table if not exists public.kv_store_44966e3b (
  key text primary key,
  value jsonb not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  role text not null default 'patient',
  full_name text,
  email text,
  phone text,
  avatar_url text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.patient_profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  name text,
  email text,
  phone text,
  age integer,
  gender text,
  blood_group text,
  address text,
  emergency_contact jsonb,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.hospital_profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  name text not null default 'Hospital',
  registered_name text,
  email text,
  type text,
  description text,
  tagline text,
  address text,
  city text,
  state text,
  phone text,
  support_email text,
  website text,
  license_number text,
  gstin text,
  facilities text[] not null default '{}',
  image text,
  verification_status text not null default 'pending_verification',
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.doctor_profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  hospital_id uuid references public.hospital_profiles(id) on delete set null,
  name text not null default 'Doctor',
  email text,
  phone text,
  specialty text,
  qualification text,
  experience text,
  registration_number text,
  registration_year text,
  state_medical_council text,
  bio text,
  languages text[],
  consultation_fee numeric(10,2),
  location text,
  image text,
  verification_status text not null default 'pending_verification',
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.appointments (
  id uuid primary key default gen_random_uuid(),
  patient_id uuid references auth.users(id) on delete set null,
  doctor_id uuid references public.doctor_profiles(id) on delete set null,
  hospital_id uuid references public.hospital_profiles(id) on delete set null,
  patient_name text,
  doctor_name text,
  hospital_name text,
  date date,
  time text,
  type text,
  reason text,
  symptoms text,
  status text not null default 'scheduled',
  payment_status text,
  amount numeric(10,2),
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.doctor_schedules (
  id uuid primary key default gen_random_uuid(),
  doctor_id uuid not null references public.doctor_profiles(id) on delete cascade,
  day text not null,
  start_time time not null,
  end_time time not null,
  slot_duration integer not null default 30,
  max_bookings integer not null default 1,
  enabled boolean not null default true,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.appointment_slots (
  id uuid primary key default gen_random_uuid(),
  schedule_id uuid references public.doctor_schedules(id) on delete cascade,
  doctor_id uuid references public.doctor_profiles(id) on delete cascade,
  hospital_id uuid references public.hospital_profiles(id) on delete cascade,
  date date,
  day text,
  slot_time time,
  start_time time,
  end_time time,
  status text not null default 'available',
  current_bookings integer not null default 0,
  max_bookings integer not null default 1,
  is_emergency boolean not null default false,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.vitals (
  id uuid primary key default gen_random_uuid(),
  patient_id uuid references auth.users(id) on delete cascade,
  recorded_by uuid references auth.users(id) on delete set null,
  blood_pressure text,
  heart_rate integer,
  temperature numeric(5,2),
  oxygen_saturation integer,
  weight numeric(6,2),
  notes text,
  metadata jsonb not null default '{}'::jsonb,
  recorded_at timestamptz not null default now(),
  created_at timestamptz not null default now()
);

create table if not exists public.health_records (
  id uuid primary key default gen_random_uuid(),
  patient_id uuid references auth.users(id) on delete cascade,
  doctor_id uuid references public.doctor_profiles(id) on delete set null,
  hospital_id uuid references public.hospital_profiles(id) on delete set null,
  record_type text not null,
  title text,
  notes text,
  file_url text,
  test_name text,
  details jsonb not null default '{}'::jsonb,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.transactions (
  id uuid primary key default gen_random_uuid(),
  doctor_id uuid references public.doctor_profiles(id) on delete set null,
  patient_id uuid references auth.users(id) on delete set null,
  appointment_id uuid references public.appointments(id) on delete set null,
  order_id text,
  payment_id text,
  amount numeric(10,2) not null default 0,
  transaction_type text not null default 'consultation',
  status text not null default 'pending',
  description text,
  metadata jsonb not null default '{}'::jsonb,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.contact_messages (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  email text not null,
  subject text not null,
  message text not null,
  status text not null default 'unread',
  notes text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.jobs (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  description text not null,
  position text not null,
  salary text,
  location text,
  hospital text,
  posted_by uuid references auth.users(id) on delete set null,
  status text not null default 'active',
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.job_applications (
  id uuid primary key default gen_random_uuid(),
  job_id uuid references public.jobs(id) on delete cascade,
  applicant_id uuid references auth.users(id) on delete cascade,
  resume_url text,
  cover_letter text,
  status text not null default 'submitted',
  notes text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.doctor_blogs (
  id uuid primary key default gen_random_uuid(),
  author_id uuid references public.doctor_profiles(id) on delete cascade,
  title text not null,
  slug text unique,
  content text,
  short_description text,
  category text,
  tags text[] not null default '{}',
  cover_image_url text,
  status text not null default 'draft',
  published_at timestamptz,
  published_by uuid references auth.users(id) on delete set null,
  review_notes text,
  rejection_reason text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.verification_requests (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade,
  verification_type text not null,
  registration_number text,
  qualifications text,
  license_url text,
  status text not null default 'pending',
  reason text,
  metadata jsonb not null default '{}'::jsonb,
  submitted_at timestamptz not null default now(),
  approved_at timestamptz,
  approved_by uuid references auth.users(id) on delete set null,
  updated_at timestamptz not null default now()
);

create table if not exists public.staff_members (
  id uuid primary key default gen_random_uuid(),
  hospital_id uuid references public.hospital_profiles(id) on delete cascade,
  user_id uuid references auth.users(id) on delete set null,
  name text not null,
  email text,
  phone text,
  role text not null default 'receptionist',
  permissions jsonb not null default '{}'::jsonb,
  status text not null default 'active',
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.doctor_credentials (
  id uuid primary key default gen_random_uuid(),
  doctor_id uuid references public.doctor_profiles(id) on delete cascade,
  type text,
  label text,
  file_url text,
  status text not null default 'pending',
  metadata jsonb not null default '{}'::jsonb,
  uploaded_at timestamptz not null default now()
);

create table if not exists public.otp_codes (
  mobile_number text primary key,
  otp_code text not null,
  expires_at timestamptz not null,
  is_used boolean not null default false,
  attempts integer not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.activity_logs (
  id uuid primary key default gen_random_uuid(),
  actor_id text,
  role text,
  action text not null,
  target_id text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists public.notifications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade,
  type text,
  title text,
  message text,
  data jsonb not null default '{}'::jsonb,
  read boolean not null default false,
  created_at timestamptz not null default now()
);

create index if not exists idx_kv_store_prefix on public.kv_store_44966e3b (key text_pattern_ops);
create index if not exists idx_appointments_patient on public.appointments(patient_id);
create index if not exists idx_appointments_doctor on public.appointments(doctor_id);
create index if not exists idx_appointments_hospital_date on public.appointments(hospital_id, date);
create index if not exists idx_slots_doctor_date on public.appointment_slots(doctor_id, date);
create index if not exists idx_vitals_patient_time on public.vitals(patient_id, recorded_at desc);
create index if not exists idx_health_records_patient_time on public.health_records(patient_id, created_at desc);
create index if not exists idx_transactions_doctor_time on public.transactions(doctor_id, created_at desc);
create index if not exists idx_jobs_status on public.jobs(status);
create index if not exists idx_blogs_status_time on public.doctor_blogs(status, published_at desc);

create or replace function public.touch_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

do $$
declare
  t text;
begin
  foreach t in array array[
    'kv_store_44966e3b','profiles','patient_profiles','hospital_profiles','doctor_profiles',
    'appointments','doctor_schedules','appointment_slots','health_records','transactions',
    'contact_messages','jobs','job_applications','doctor_blogs','verification_requests',
    'staff_members','otp_codes'
  ]
  loop
    execute format('drop trigger if exists touch_%I_updated_at on public.%I', t, t);
    execute format('create trigger touch_%I_updated_at before update on public.%I for each row execute function public.touch_updated_at()', t, t);
  end loop;
end $$;

create or replace function public.handle_new_auth_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, role, full_name, email, phone, metadata)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'role', 'patient'),
    coalesce(new.raw_user_meta_data->>'full_name', new.raw_user_meta_data->>'name'),
    new.email,
    new.phone,
    coalesce(new.raw_user_meta_data, '{}'::jsonb)
  )
  on conflict (id) do update set
    role = excluded.role,
    full_name = coalesce(excluded.full_name, public.profiles.full_name),
    email = coalesce(excluded.email, public.profiles.email),
    phone = coalesce(excluded.phone, public.profiles.phone),
    metadata = public.profiles.metadata || excluded.metadata,
    updated_at = now();

  if coalesce(new.raw_user_meta_data->>'role', 'patient') = 'doctor' then
    insert into public.doctor_profiles (
      id, name, email, phone, specialty, qualification, registration_number,
      registration_year, state_medical_council, verification_status, metadata
    )
    values (
      new.id,
      coalesce(new.raw_user_meta_data->>'full_name', 'Doctor'),
      new.email,
      new.phone,
      new.raw_user_meta_data->>'specialty',
      new.raw_user_meta_data->>'qualification',
      new.raw_user_meta_data->>'registration_number',
      new.raw_user_meta_data->>'registration_year',
      new.raw_user_meta_data->>'state_medical_council',
      coalesce(new.raw_user_meta_data->>'verification_status', 'pending_verification'),
      coalesce(new.raw_user_meta_data, '{}'::jsonb)
    )
    on conflict (id) do nothing;
  elsif coalesce(new.raw_user_meta_data->>'role', 'patient') = 'hospital' then
    insert into public.hospital_profiles (
      id, name, registered_name, email, phone, license_number, gstin, type,
      verification_status, metadata
    )
    values (
      new.id,
      coalesce(new.raw_user_meta_data->>'hospital_name', new.raw_user_meta_data->>'full_name', 'Hospital'),
      new.raw_user_meta_data->>'hospital_name',
      new.email,
      new.phone,
      new.raw_user_meta_data->>'license_number',
      new.raw_user_meta_data->>'gstin',
      new.raw_user_meta_data->>'facility_type',
      coalesce(new.raw_user_meta_data->>'verification_status', 'pending_verification'),
      coalesce(new.raw_user_meta_data, '{}'::jsonb)
    )
    on conflict (id) do nothing;
  else
    insert into public.patient_profiles (id, name, email, phone, metadata)
    values (
      new.id,
      coalesce(new.raw_user_meta_data->>'full_name', 'Patient'),
      new.email,
      new.phone,
      coalesce(new.raw_user_meta_data, '{}'::jsonb)
    )
    on conflict (id) do nothing;
  end if;

  return new;
end;
$$;

drop trigger if exists on_auth_user_created_oryga on auth.users;
create trigger on_auth_user_created_oryga
after insert or update on auth.users
for each row execute function public.handle_new_auth_user();

alter table public.kv_store_44966e3b enable row level security;
alter table public.profiles enable row level security;
alter table public.patient_profiles enable row level security;
alter table public.hospital_profiles enable row level security;
alter table public.doctor_profiles enable row level security;
alter table public.appointments enable row level security;
alter table public.doctor_schedules enable row level security;
alter table public.appointment_slots enable row level security;
alter table public.vitals enable row level security;
alter table public.health_records enable row level security;
alter table public.transactions enable row level security;
alter table public.contact_messages enable row level security;
alter table public.jobs enable row level security;
alter table public.job_applications enable row level security;
alter table public.doctor_blogs enable row level security;
alter table public.verification_requests enable row level security;
alter table public.staff_members enable row level security;
alter table public.doctor_credentials enable row level security;
alter table public.otp_codes enable row level security;
alter table public.activity_logs enable row level security;
alter table public.notifications enable row level security;

do $$
declare
  t text;
begin
  foreach t in array array[
    'kv_store_44966e3b','profiles','patient_profiles','hospital_profiles','doctor_profiles',
    'appointments','doctor_schedules','appointment_slots','vitals','health_records','transactions',
    'contact_messages','jobs','job_applications','doctor_blogs','verification_requests',
    'staff_members','doctor_credentials','otp_codes','activity_logs','notifications'
  ]
  loop
    execute format('drop policy if exists service_role_all on public.%I', t);
    execute format('create policy service_role_all on public.%I for all to service_role using (true) with check (true)', t);
  end loop;
end $$;

drop policy if exists public_read_doctors on public.doctor_profiles;
create policy public_read_doctors on public.doctor_profiles for select to anon, authenticated using (true);

drop policy if exists public_read_hospitals on public.hospital_profiles;
create policy public_read_hospitals on public.hospital_profiles for select to anon, authenticated using (true);

drop policy if exists public_read_jobs on public.jobs;
create policy public_read_jobs on public.jobs for select to anon, authenticated using (status = 'active');

drop policy if exists public_read_blogs on public.doctor_blogs;
create policy public_read_blogs on public.doctor_blogs for select to anon, authenticated using (status = 'published');

drop policy if exists contact_insert_public on public.contact_messages;
create policy contact_insert_public on public.contact_messages for insert to anon, authenticated with check (true);

drop policy if exists own_profile_read on public.profiles;
create policy own_profile_read on public.profiles for select to authenticated using (auth.uid() = id);

drop policy if exists own_patient_profile on public.patient_profiles;
create policy own_patient_profile on public.patient_profiles for all to authenticated using (auth.uid() = id) with check (auth.uid() = id);

drop policy if exists own_doctor_profile_write on public.doctor_profiles;
create policy own_doctor_profile_write on public.doctor_profiles for all to authenticated using (auth.uid() = id) with check (auth.uid() = id);

drop policy if exists own_hospital_profile_write on public.hospital_profiles;
create policy own_hospital_profile_write on public.hospital_profiles for all to authenticated using (auth.uid() = id) with check (auth.uid() = id);

insert into storage.buckets (id, name, public)
values
  ('avatars', 'avatars', true),
  ('credentials', 'credentials', false),
  ('health-records', 'health-records', false),
  ('resumes', 'resumes', false),
  ('blog-images', 'blog-images', true),
  ('document-proofs', 'document-proofs', false)
on conflict (id) do nothing;
