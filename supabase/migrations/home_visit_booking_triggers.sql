-- ── Home Visit Booking Triggers ──────────────────────────────────────────────
-- Run in: Supabase dashboard → SQL Editor (project alwqgsubuzjqwtjleqmv)
--
-- Why: Patients cannot UPDATE home_visit_slots (RLS restricts that to doctors).
-- These SECURITY DEFINER triggers run as the table owner (postgres) and handle
-- slot availability atomically, preventing double-booking at the DB level.

-- 1. Prevent two bookings for the same slot
ALTER TABLE home_visit_bookings
  ADD CONSTRAINT IF NOT EXISTS home_visit_bookings_slot_id_key UNIQUE (slot_id);

-- 2. Mark slot unavailable when a booking is created
CREATE OR REPLACE FUNCTION fn_mark_slot_unavailable()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  UPDATE home_visit_slots
  SET is_available = false
  WHERE id = NEW.slot_id;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_mark_slot_unavailable ON home_visit_bookings;
CREATE TRIGGER trg_mark_slot_unavailable
  AFTER INSERT ON home_visit_bookings
  FOR EACH ROW
  EXECUTE FUNCTION fn_mark_slot_unavailable();

-- 3. Restore slot availability when a booking is cancelled
CREATE OR REPLACE FUNCTION fn_restore_slot_on_cancel()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF NEW.status = 'cancelled' AND OLD.status <> 'cancelled' THEN
    UPDATE home_visit_slots
    SET is_available = true
    WHERE id = NEW.slot_id;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_restore_slot_on_cancel ON home_visit_bookings;
CREATE TRIGGER trg_restore_slot_on_cancel
  AFTER UPDATE ON home_visit_bookings
  FOR EACH ROW
  EXECUTE FUNCTION fn_restore_slot_on_cancel();
