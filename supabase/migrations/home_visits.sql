-- ── Home Visit Tables ────────────────────────────────────────────────────────
-- Run this in your Supabase SQL editor (Dashboard → SQL Editor → New Query)

-- Doctor-level home visit settings
CREATE TABLE IF NOT EXISTS home_visit_settings (
  doctor_id   UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  is_enabled  BOOLEAN     NOT NULL DEFAULT false,
  default_fee INTEGER     NOT NULL DEFAULT 500,
  areas       TEXT[]      NOT NULL DEFAULT '{}',
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Available time slots created by the doctor
CREATE TABLE IF NOT EXISTS home_visit_slots (
  id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  doctor_id    UUID        NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  date         DATE        NOT NULL,
  time         TEXT        NOT NULL,
  area         TEXT        NOT NULL,
  fee          INTEGER     NOT NULL,
  is_available BOOLEAN     NOT NULL DEFAULT true,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Patient bookings against a slot
CREATE TABLE IF NOT EXISTS home_visit_bookings (
  id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  slot_id         UUID        NOT NULL REFERENCES home_visit_slots(id) ON DELETE CASCADE,
  patient_id      UUID        NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  patient_name    TEXT        NOT NULL,
  patient_address TEXT        NOT NULL,
  patient_phone   TEXT        NOT NULL,
  status          TEXT        NOT NULL DEFAULT 'pending'
                              CHECK (status IN ('pending','confirmed','completed','cancelled')),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── RLS ──────────────────────────────────────────────────────────────────────

ALTER TABLE home_visit_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE home_visit_slots    ENABLE ROW LEVEL SECURITY;
ALTER TABLE home_visit_bookings ENABLE ROW LEVEL SECURITY;

-- home_visit_settings
CREATE POLICY "doctor_own_settings"
  ON home_visit_settings FOR ALL
  USING (auth.uid() = doctor_id);

CREATE POLICY "public_read_enabled_settings"
  ON home_visit_settings FOR SELECT
  USING (is_enabled = true);

-- home_visit_slots
CREATE POLICY "doctor_own_slots"
  ON home_visit_slots FOR ALL
  USING (auth.uid() = doctor_id);

CREATE POLICY "public_read_available_slots"
  ON home_visit_slots FOR SELECT
  USING (is_available = true);

-- home_visit_bookings
CREATE POLICY "patient_own_bookings"
  ON home_visit_bookings FOR ALL
  USING (auth.uid() = patient_id);

CREATE POLICY "doctor_read_bookings"
  ON home_visit_bookings FOR SELECT
  USING (
    slot_id IN (
      SELECT id FROM home_visit_slots WHERE doctor_id = auth.uid()
    )
  );

CREATE POLICY "doctor_update_booking_status"
  ON home_visit_bookings FOR UPDATE
  USING (
    slot_id IN (
      SELECT id FROM home_visit_slots WHERE doctor_id = auth.uid()
    )
  );
