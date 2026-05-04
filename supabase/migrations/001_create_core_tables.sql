-- Core Tables for Oryga Platform
-- Created: 2026-04-18
-- Purpose: Establish primary data structures for all features

-- 1. VITALS TRACKING TABLE
CREATE TABLE IF NOT EXISTS vitals (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  patient_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  recorded_by UUID NOT NULL REFERENCES auth.users(id),
  blood_pressure VARCHAR(10),
  heart_rate INT,
  temperature FLOAT,
  oxygen_saturation INT,
  weight FLOAT,
  notes TEXT,
  recorded_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_vitals_patient_id ON vitals(patient_id);
CREATE INDEX idx_vitals_recorded_at ON vitals(recorded_at DESC);

-- 2. DOCTOR SCHEDULES TABLE
CREATE TABLE IF NOT EXISTS doctor_schedules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  doctor_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  day VARCHAR(20) NOT NULL,
  start_time TIME NOT NULL,
  end_time TIME NOT NULL,
  slot_duration INT NOT NULL DEFAULT 30,
  max_bookings INT NOT NULL DEFAULT 1,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_schedules_doctor_id ON doctor_schedules(doctor_id);
CREATE INDEX idx_schedules_doctor_day ON doctor_schedules(doctor_id, day);

-- 3. APPOINTMENT SLOTS TABLE
CREATE TABLE IF NOT EXISTS appointment_slots (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  schedule_id UUID NOT NULL REFERENCES doctor_schedules(id) ON DELETE CASCADE,
  doctor_id UUID NOT NULL REFERENCES auth.users(id),
  day VARCHAR(20) NOT NULL,
  slot_time TIME NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'available',
  current_bookings INT NOT NULL DEFAULT 0,
  max_bookings INT NOT NULL DEFAULT 1,
  is_emergency BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_slots_doctor_id ON appointment_slots(doctor_id);
CREATE INDEX idx_slots_status ON appointment_slots(status);
CREATE INDEX idx_slots_doctor_day_time ON appointment_slots(doctor_id, day, slot_time);

-- 4. HEALTH RECORDS TABLE
CREATE TABLE IF NOT EXISTS health_records (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  patient_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  doctor_id UUID NOT NULL REFERENCES auth.users(id),
  record_type VARCHAR(50) NOT NULL,
  notes TEXT,
  file_url TEXT,
  test_name VARCHAR(255),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  created_by UUID NOT NULL REFERENCES auth.users(id)
);

CREATE INDEX idx_health_records_patient_id ON health_records(patient_id);
CREATE INDEX idx_health_records_created_at ON health_records(created_at DESC);
CREATE INDEX idx_health_records_type ON health_records(record_type);

-- 5. TRANSACTIONS TABLE
CREATE TABLE IF NOT EXISTS transactions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  doctor_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  amount DECIMAL(10, 2) NOT NULL,
  transaction_type VARCHAR(50) NOT NULL,
  status VARCHAR(50) NOT NULL DEFAULT 'pending',
  appointment_id UUID,
  description TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  created_by UUID NOT NULL REFERENCES auth.users(id)
);

CREATE INDEX idx_transactions_doctor_id ON transactions(doctor_id);
CREATE INDEX idx_transactions_status ON transactions(status);
CREATE INDEX idx_transactions_created_at ON transactions(created_at DESC);

-- 6. CONTACT MESSAGES TABLE
CREATE TABLE IF NOT EXISTS contact_messages (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL,
  email VARCHAR(255) NOT NULL,
  subject VARCHAR(255) NOT NULL,
  message TEXT NOT NULL,
  status VARCHAR(50) NOT NULL DEFAULT 'unread',
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_contact_messages_status ON contact_messages(status);
CREATE INDEX idx_contact_messages_created_at ON contact_messages(created_at DESC);

-- 7. EMERGENCY SLOTS TABLE
CREATE TABLE IF NOT EXISTS emergency_slots (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  doctor_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  date DATE NOT NULL,
  slot_time TIME NOT NULL,
  duration INT NOT NULL DEFAULT 30,
  is_emergency BOOLEAN NOT NULL DEFAULT TRUE,
  status VARCHAR(20) NOT NULL DEFAULT 'available',
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_emergency_slots_doctor_id ON emergency_slots(doctor_id);
CREATE INDEX idx_emergency_slots_date ON emergency_slots(date);

-- 8. JOB POSTINGS TABLE
CREATE TABLE IF NOT EXISTS jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title VARCHAR(255) NOT NULL,
  description TEXT NOT NULL,
  position VARCHAR(255) NOT NULL,
  salary VARCHAR(100),
  location VARCHAR(255) NOT NULL,
  hospital VARCHAR(255) NOT NULL,
  posted_by UUID NOT NULL REFERENCES auth.users(id),
  status VARCHAR(20) NOT NULL DEFAULT 'active',
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_jobs_posted_by ON jobs(posted_by);
CREATE INDEX idx_jobs_status ON jobs(status);
CREATE INDEX idx_jobs_position ON jobs(position);

-- 9. JOB APPLICATIONS TABLE
CREATE TABLE IF NOT EXISTS job_applications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  job_id UUID NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  applicant_id UUID NOT NULL REFERENCES auth.users(id),
  resume_url TEXT,
  cover_letter TEXT,
  status VARCHAR(50) NOT NULL DEFAULT 'submitted',
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_job_applications_job_id ON job_applications(job_id);
CREATE INDEX idx_job_applications_applicant_id ON job_applications(applicant_id);

-- 10. DOCTOR BLOGS TABLE
CREATE TABLE IF NOT EXISTS doctor_blogs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  author_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  title VARCHAR(255) NOT NULL,
  slug VARCHAR(255) UNIQUE,
  content TEXT,
  short_description TEXT,
  category VARCHAR(100),
  cover_image_url TEXT,
  status VARCHAR(50) NOT NULL DEFAULT 'draft',
  published_at TIMESTAMP WITH TIME ZONE,
  published_by UUID REFERENCES auth.users(id),
  review_notes TEXT,
  rejection_reason TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_doctor_blogs_author_id ON doctor_blogs(author_id);
CREATE INDEX idx_doctor_blogs_status ON doctor_blogs(status);
CREATE INDEX idx_doctor_blogs_published_at ON doctor_blogs(published_at DESC);

-- 11. VERIFICATION REQUESTS TABLE
CREATE TABLE IF NOT EXISTS verification_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  verification_type VARCHAR(50) NOT NULL,
  registration_number VARCHAR(100),
  qualifications TEXT,
  license_url TEXT,
  status VARCHAR(50) NOT NULL DEFAULT 'pending',
  submitted_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  approved_at TIMESTAMP WITH TIME ZONE,
  approved_by UUID REFERENCES auth.users(id)
);

CREATE INDEX idx_verification_user_id ON verification_requests(user_id);
CREATE INDEX idx_verification_status ON verification_requests(status);

-- ENABLE ROW LEVEL SECURITY
ALTER TABLE vitals ENABLE ROW LEVEL SECURITY;
ALTER TABLE doctor_schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE appointment_slots ENABLE ROW LEVEL SECURITY;
ALTER TABLE health_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE contact_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE emergency_slots ENABLE ROW LEVEL SECURITY;
ALTER TABLE jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE job_applications ENABLE ROW LEVEL SECURITY;
ALTER TABLE doctor_blogs ENABLE ROW LEVEL SECURITY;
ALTER TABLE verification_requests ENABLE ROW LEVEL SECURITY;

-- RLS POLICIES

-- Vitals: Patients can view own vitals, doctors can view patient vitals they recorded
CREATE POLICY "vitals_read_own" ON vitals FOR SELECT
  USING (auth.uid() = patient_id);

CREATE POLICY "vitals_read_doctor" ON vitals FOR SELECT
  USING (auth.uid() = recorded_by);

CREATE POLICY "vitals_insert" ON vitals FOR INSERT
  WITH CHECK (auth.uid() = recorded_by);

-- Doctor Schedules: Doctors can manage own schedules
CREATE POLICY "schedules_read" ON doctor_schedules FOR SELECT
  USING (auth.uid() = doctor_id OR true);

CREATE POLICY "schedules_manage" ON doctor_schedules FOR INSERT
  WITH CHECK (auth.uid() = doctor_id);

CREATE POLICY "schedules_update" ON doctor_schedules FOR UPDATE
  USING (auth.uid() = doctor_id);

-- Health Records: Patients can view own records
CREATE POLICY "health_records_read_own" ON health_records FOR SELECT
  USING (auth.uid() = patient_id);

CREATE POLICY "health_records_read_doctor" ON health_records FOR SELECT
  USING (auth.uid() = doctor_id);

CREATE POLICY "health_records_insert" ON health_records FOR INSERT
  WITH CHECK (auth.uid() = created_by);

-- Transactions: Doctors can view own transactions
CREATE POLICY "transactions_read" ON transactions FOR SELECT
  USING (auth.uid() = doctor_id);

CREATE POLICY "transactions_insert" ON transactions FOR INSERT
  WITH CHECK (true);

-- Contact Messages: Public can insert, admins can read
CREATE POLICY "contact_messages_insert" ON contact_messages FOR INSERT
  WITH CHECK (true);

-- Emergency Slots: Doctors manage own
CREATE POLICY "emergency_slots_manage" ON emergency_slots FOR INSERT
  WITH CHECK (auth.uid() = doctor_id);

-- Jobs: Anyone can view, hospitals can manage
CREATE POLICY "jobs_read" ON jobs FOR SELECT
  USING (true);

CREATE POLICY "jobs_manage" ON jobs FOR INSERT
  WITH CHECK (auth.uid() = posted_by);

-- Job Applications: Users can apply, hospitals can view applications
CREATE POLICY "job_applications_insert" ON job_applications FOR INSERT
  WITH CHECK (auth.uid() = applicant_id);

-- Doctor Blogs: Authors manage, public can view published
CREATE POLICY "doctor_blogs_read_published" ON doctor_blogs FOR SELECT
  USING (status = 'published' OR auth.uid() = author_id);

CREATE POLICY "doctor_blogs_insert" ON doctor_blogs FOR INSERT
  WITH CHECK (auth.uid() = author_id);

-- Verification: Users can submit, admins can review
CREATE POLICY "verification_submit" ON verification_requests FOR INSERT
  WITH CHECK (auth.uid() = user_id);
