import { Hono } from "https://deno.land/x/hono@v4.3.11/mod.ts";
import { cors } from "https://deno.land/x/hono@v4.3.11/middleware/cors/mod.ts";
import { logger } from "https://deno.land/x/hono@v4.3.11/middleware/logger/mod.ts";
import { createClient } from "npm:@supabase/supabase-js@2";
import * as kv from "./kv_store.tsx";
import * as otpService from "./otp_service.ts";
import * as authService from "./auth_service.ts";
import { getAdvancedDashboardStats } from "./dashboard_metrics.ts";

const app = new Hono();
const BASE_PATH = "/make-server-fd75a5db";

app.use('*', logger(console.log));

app.use(
  "/*",
  cors({
    origin: "*",
    allowHeaders: ["Content-Type", "Authorization", "X-Supabase-Auth", "Cache-Control", "Pragma"],
    allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    exposeHeaders: ["Content-Length"],
    maxAge: 600,
  }),
);

const supabaseAdmin = createClient(
  Deno.env.get("SUPABASE_URL") || "",
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "",
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
      detectSessionInUrl: false
    }
  }
);

const RESEND_API_KEY = Deno.env.get("RESEND_API_KEY") || "";
const RESEND_FROM = "noreply@orygaco.com";

const RAZORPAY_KEY_ID = Deno.env.get('RAZORPAY_KEY_ID') || '';
const RAZORPAY_KEY_SECRET = Deno.env.get('RAZORPAY_KEY_SECRET') || '';
const RAZORPAY_API_BASE = 'https://api.razorpay.com/v1';

function timingSafeEqual(a: string, b: string) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

// BUG FIX 1: verifyPaymentSignature used `${orderId}${paymentId}` (no separator).
// Razorpay's spec and computeRazorpaySignature both require `${orderId}|${paymentId}`.
// Mismatched formats caused all webhook signature checks to fail.
async function verifyPaymentSignature(orderId: string, paymentId: string, signature: string): Promise<boolean> {
  try {
    const message = `${orderId}|${paymentId}`;
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(RAZORPAY_KEY_SECRET),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const computedSignature = await crypto.subtle.sign(
      'HMAC',
      key,
      new TextEncoder().encode(message)
    );
    const computedHex = Array.from(new Uint8Array(computedSignature))
      .map((byte) => byte.toString(16).padStart(2, '0'))
      .join('');
    return timingSafeEqual(computedHex, signature);
  } catch (error) {
    console.error('Error verifying Razorpay signature:', error);
    return false;
  }
}

function getRazorpayAuthHeader() {
  const credentials = `${RAZORPAY_KEY_ID}:${RAZORPAY_KEY_SECRET}`;
  const base64 = btoa(credentials);
  return `Basic ${base64}`;
}

async function computeRazorpaySignature(orderId: string, paymentId: string): Promise<string> {
  const message = `${orderId}|${paymentId}`;
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(RAZORPAY_KEY_SECRET),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return Array.from(new Uint8Array(signature))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

function isEmailConfigured() {
  return !!RESEND_API_KEY;
}

async function sendEmail(options: { to: string; subject: string; text?: string; html?: string; }) {
  if (!isEmailConfigured()) {
    throw new Error("Email service not configured. Set RESEND_API_KEY environment variable.");
  }

  try {
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: RESEND_FROM,
        to: options.to,
        subject: options.subject,
        html: options.html,
        text: options.text,
      }),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Resend API error: ${error.message || response.statusText}`);
    }

    return await response.json();
  } catch (error: any) {
    console.error("Email send error:", error);
    throw error;
  }
}

app.get(`${BASE_PATH}/health`, (c) => {
  return c.json({
    status: "ok",
    env: {
        hasUrl: !!Deno.env.get("SUPABASE_URL"),
        hasKey: !!Deno.env.get("SUPABASE_SERVICE_ROLE_KEY"),
        hasResendKey: !!RESEND_API_KEY,
        hasRazorpayKey: !!RAZORPAY_KEY_ID,
        emailConfigured: isEmailConfigured()
    }
  });
});

app.post(`${BASE_PATH}/email/send`, async (c) => {
  try {
    const body = await c.req.json();
    const { to, subject, text, html } = body;
    if (!to || !subject) {
      return c.json({ error: "'to' and 'subject' are required" }, 400);
    }

    const result = await sendEmail({ to, subject, text, html });
    return c.json({ success: true, messageId: result.id });
  } catch (e: any) {
    console.error("Email send error:", e);
    return c.json({ error: e.message || "Unable to send email" }, 500);
  }
});

// --- RBAC & SECURITY LAYER ---

const ROLES = {
  SUPER_ADMIN: 'super_admin',
  HOSPITAL_ADMIN: 'hospital',
  DOCTOR: 'doctor',
  RECEPTIONIST: 'receptionist',
  PATIENT: 'patient'
};

const PERMISSIONS = {
  VIEW_OWN_APPOINTMENTS: 'view_own_appointments',
  VIEW_HOSPITAL_APPOINTMENTS: 'view_hospital_appointments',
  MANAGE_APPOINTMENTS: 'manage_appointments',
  MANAGE_SLOTS: 'manage_slots',
  VERIFY_USERS: 'verify_users',
  VIEW_AUDIT_LOGS: 'view_audit_logs',
  MANAGE_ROLES: 'manage_roles',
  MANAGE_STAFF: 'manage_staff',
  SECURE_EXPORT: 'secure_export',
  MANAGE_SETTINGS: 'manage_settings'
};

const ROLE_PERMISSIONS = {
  [ROLES.SUPER_ADMIN]: Object.values(PERMISSIONS),
  [ROLES.HOSPITAL_ADMIN]: [
    PERMISSIONS.VIEW_HOSPITAL_APPOINTMENTS,
    PERMISSIONS.MANAGE_APPOINTMENTS,
    PERMISSIONS.MANAGE_SLOTS,
    PERMISSIONS.SECURE_EXPORT,
    PERMISSIONS.VIEW_OWN_APPOINTMENTS,
    PERMISSIONS.MANAGE_STAFF,
    PERMISSIONS.MANAGE_SETTINGS
  ],
  [ROLES.DOCTOR]: [
    PERMISSIONS.VIEW_OWN_APPOINTMENTS,
    PERMISSIONS.MANAGE_SLOTS,
    PERMISSIONS.MANAGE_APPOINTMENTS
  ],
  [ROLES.RECEPTIONIST]: [
    PERMISSIONS.VIEW_HOSPITAL_APPOINTMENTS,
    PERMISSIONS.MANAGE_APPOINTMENTS
  ],
  [ROLES.PATIENT]: [
    PERMISSIONS.VIEW_OWN_APPOINTMENTS
  ]
};

async function logActivity(actorId: string, role: string, action: string, targetId: string | null, metadata: any) {
  const logId = crypto.randomUUID();
  const entry = {
    id: logId,
    actorId,
    role,
    action,
    targetId,
    metadata,
    timestamp: new Date().toISOString()
  };
  const dateKey = new Date().toISOString().split('T')[0];
  await kv.set(`activity_log:${dateKey}:${logId}`, entry);
}

async function checkPermission(user: any, permission: string) {
  const elevationKey = `temp_elevation:${user.id}`;
  const elevation = await kv.get(elevationKey);
  let role = user.user_metadata?.role || ROLES.PATIENT;

  const overrideRole = await kv.get(`user_role:${user.id}`);
  if (overrideRole) role = overrideRole.role;

  if (elevation && elevation.isActive) {
      if (new Date(elevation.endAt) > new Date()) {
          role = elevation.elevatedRole;
      } else {
          elevation.isActive = false;
          await kv.set(elevationKey, elevation);
      }
  }

  const permKey = `staff_permissions:${user.id}`;
  const granular = await kv.get(permKey);

  if (granular && granular[permission] !== undefined) {
      const allowed = granular[permission];
      if (!allowed) {
           await logActivity(user.id, role, 'permission_denied', null, { permission });
           return { allowed: false, role };
      }
      return { allowed: true, role };
  }

  const allowed = ROLE_PERMISSIONS[role as keyof typeof ROLE_PERMISSIONS]?.includes(permission);
  if (!allowed) {
    await logActivity(user.id, role, 'permission_denied', null, { permission });
  }
  return { allowed, role };
}

async function getUser(c: any, providedToken?: string) {
  const authHeader = c.req.header("Authorization") || c.req.header("X-Supabase-Auth");
  const token = providedToken || authHeader?.replace("Bearer ", "");
  if (!token) return { user: null, error: "Missing token" };

  const { data: { user }, error } = await supabaseAdmin.auth.getUser(token);
  if (error || !user) return { user: null, error: error?.message || "Invalid token" };
  return { user, error: null };
}

// --- API ROUTES ---

// 1. APPOINTMENTS

app.get(`${BASE_PATH}/appointments`, async (c) => {
  const { user, error } = await getUser(c);
  if (error) return c.json({ error }, 401);

  const role = user.user_metadata?.role || ROLES.PATIENT;
  const appointments = await kv.getByPrefix('appointment:');

  let filtered = [];
  if (role === ROLES.PATIENT) {
    filtered = appointments.filter((apt: any) => apt.patientId === user.id);
  } else if (role === ROLES.DOCTOR) {
    filtered = appointments.filter((apt: any) => apt.doctorId === user.id);
  } else if (role === ROLES.HOSPITAL_ADMIN) {
    filtered = appointments;
  }

  return c.json(filtered.sort((a: any, b: any) => new Date(b.date).getTime() - new Date(a.date).getTime()));
});

app.post(`${BASE_PATH}/appointments`, async (c) => {
  try {
    const body = await c.req.json();
    const { user, error } = await getUser(c, body.authToken);
    if (error) return c.json({ error }, 401);

    const aptId = crypto.randomUUID();
    const appointment = {
      id: aptId,
      patientId: user.id,
      patientName: user.user_metadata?.full_name || user.email,
      ...body,
      status: 'scheduled',
      createdAt: new Date().toISOString()
    };
    delete appointment.authToken;

    await kv.set(`appointment:${aptId}`, appointment);
    // BUG FIX 2: logActivity was not awaited — floating promise masked write errors
    await logActivity(user.id, user.user_metadata?.role, 'create_appointment', aptId, { doctorId: body.doctorId });

    return c.json({ message: "Appointment created", appointment }, 201);
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

// 2. PATIENT VITALS

app.post(`${BASE_PATH}/vitals`, async (c) => {
  try {
    const body = await c.req.json();
    const { authToken, patientId, bp, heartRate, temperature, oxygen, weight } = body;

    const { user, error } = await getUser(c, authToken);
    if (error) return c.json({ error }, 401);

    const vitalId = crypto.randomUUID();
    const vital = {
      id: vitalId,
      patientId,
      recordedBy: user.id,
      recordedAt: new Date().toISOString(),
      bp, heartRate, temperature, oxygen, weight
    };

    await kv.set(`vital:${vitalId}`, vital);
    await kv.set(`patient_vitals:${patientId}:${vitalId}`, vitalId);
    await kv.set(`patient_vital_latest:${patientId}`, vital);

    return c.json({ message: "Vitals recorded", vital }, 201);
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

// BUG FIX 3: GET /vitals/patient/:patientId had no auth guard — any unauthenticated
// request could read any patient's health vitals.
app.get(`${BASE_PATH}/vitals/patient/:patientId`, async (c) => {
  try {
    const patientId = c.req.param('patientId');

    const { user, error } = await getUser(c);
    if (error) return c.json({ error }, 401);

    const vitals = await kv.getByPrefix(`patient_vitals:${patientId}:`);

    const vitalRecords = [];
    for (const vitalId of vitals) {
      const vital = await kv.get(`vital:${vitalId}`);
      if (vital) vitalRecords.push(vital);
    }

    vitalRecords.sort((a: any, b: any) =>
      new Date(b.recordedAt).getTime() - new Date(a.recordedAt).getTime()
    );

    return c.json(vitalRecords);
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

app.get(`${BASE_PATH}/vitals/patient/:patientId/latest`, async (c) => {
  const patientId = c.req.param('patientId');
  const { user, error } = await getUser(c);
  if (error) return c.json({ error }, 401);

  const vital = await kv.get(`patient_vital_latest:${patientId}`);
  return c.json(vital || null);
});

// 3. DOCTOR SCHEDULE & SLOTS

app.post(`${BASE_PATH}/doctor/schedule`, async (c) => {
  try {
    const body = await c.req.json();
    const { authToken, day, startTime, endTime, slotDuration, maxBookings } = body;

    const { user, error } = await getUser(c, authToken);
    if (error) return c.json({ error }, 401);

    if (user.user_metadata?.role !== 'doctor') {
      return c.json({ error: "Only doctors can manage schedules" }, 403);
    }

    const scheduleId = crypto.randomUUID();
    const schedule = {
      id: scheduleId,
      doctorId: user.id,
      day,
      startTime,
      endTime,
      slotDuration: slotDuration || 30,
      maxBookings: maxBookings || 1,
      enabled: true,
      createdAt: new Date().toISOString()
    };

    await kv.set(`doctor_schedule:${scheduleId}`, schedule);
    await kv.set(`doctor_schedules:${user.id}:${day}`, scheduleId);

    const slots = generateSlots(startTime, endTime, slotDuration || 30);
    for (const slot of slots) {
      const slotId = crypto.randomUUID();
      const slotRecord = {
        id: slotId,
        scheduleId,
        doctorId: user.id,
        day,
        time: slot,
        status: 'available',
        bookings: 0,
        maxBookings: maxBookings || 1,
        createdAt: new Date().toISOString()
      };
      await kv.set(`slot:${slotId}`, slotRecord);
      await kv.set(`doctor_slots:${user.id}:${day}:${slot}`, slotId);
    }

    return c.json({ message: "Schedule created", schedule, slotsCount: slots.length }, 201);
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

app.get(`${BASE_PATH}/doctor/schedules`, async (c) => {
  const { user, error } = await getUser(c);
  if (error) return c.json({ error }, 401);

  const schedules = await kv.getByPrefix(`doctor_schedules:${user.id}:`);
  const scheduleDetails = [];
  for (const scheduleId of schedules) {
    const schedule = await kv.get(`doctor_schedule:${scheduleId}`);
    if (schedule) scheduleDetails.push(schedule);
  }

  return c.json(scheduleDetails);
});

// BUG FIX 4: `date` query param was read but never used — slots were never filtered by date.
app.get(`${BASE_PATH}/doctor/:doctorId/available-slots`, async (c) => {
  const doctorId = c.req.param('doctorId');
  const date = c.req.query('date');

  const slots = await kv.getByPrefix(`doctor_slots:${doctorId}:`);
  const availableSlots = [];

  for (const slotId of slots) {
    const slot = await kv.get(`slot:${slotId}`);
    if (slot && slot.status === 'available' && slot.bookings < slot.maxBookings) {
      if (date && slot.date && slot.date !== date) continue;
      availableSlots.push(slot);
    }
  }

  return c.json(availableSlots);
});

function generateSlots(startTime: string, endTime: string, duration: number) {
  const slots = [];
  const [startHour, startMin] = startTime.split(':').map(Number);
  const [endHour, endMin] = endTime.split(':').map(Number);

  let currentTime = new Date();
  currentTime.setHours(startHour, startMin);

  const endTimeDate = new Date();
  endTimeDate.setHours(endHour, endMin);

  while (currentTime < endTimeDate) {
    const hour = String(currentTime.getHours()).padStart(2, '0');
    const min = String(currentTime.getMinutes()).padStart(2, '0');
    slots.push(`${hour}:${min}`);
    currentTime.setMinutes(currentTime.getMinutes() + duration);
  }

  return slots;
}

// 4. HEALTH RECORDS

app.post(`${BASE_PATH}/health-records`, async (c) => {
  try {
    const body = await c.req.json();
    const { authToken, patientId, doctorId, recordType, notes, fileUrl, testName } = body;

    const { user, error } = await getUser(c, authToken);
    if (error) return c.json({ error }, 401);

    const recordId = crypto.randomUUID();
    const record = {
      id: recordId,
      patientId,
      doctorId: doctorId || user.id,
      recordType,
      notes,
      fileUrl,
      testName,
      createdAt: new Date().toISOString(),
      createdBy: user.id
    };

    await kv.set(`health_record:${recordId}`, record);
    await kv.set(`patient_health_records:${patientId}:${Date.now()}`, recordId);

    return c.json({ message: "Health record created", record }, 201);
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

app.get(`${BASE_PATH}/health-records/patient/:patientId`, async (c) => {
  const patientId = c.req.param('patientId');
  const { user, error } = await getUser(c);
  if (error) return c.json({ error }, 401);

  const records = await kv.getByPrefix(`patient_health_records:${patientId}:`);
  const recordDetails = [];

  for (const recordId of records) {
    const record = await kv.get(`health_record:${recordId}`);
    if (record) recordDetails.push(record);
  }

  recordDetails.sort((a: any, b: any) =>
    new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
  );

  return c.json(recordDetails);
});

// 5. DOCTOR PATIENT MANAGEMENT

app.get(`${BASE_PATH}/doctor/patients`, async (c) => {
  const { user, error } = await getUser(c);
  if (error) return c.json({ error }, 401);

  if (user.user_metadata?.role !== 'doctor') {
    return c.json({ error: "Unauthorized" }, 403);
  }

  const appointments = await kv.getByPrefix('appointment:');
  const patientMap = new Map();

  for (const apt of appointments) {
    if (apt.doctorId === user.id && apt.status === 'completed') {
      if (!patientMap.has(apt.patientId)) {
        const patient = await kv.get(`user:id:${apt.patientId}`);
        if (patient) {
          patientMap.set(apt.patientId, {
            ...patient,
            consultations: [apt],
            lastVisit: apt.date,
            totalVisits: 1
          });
        }
      } else {
        const existing = patientMap.get(apt.patientId);
        existing.consultations.push(apt);
        existing.totalVisits++;
        if (new Date(apt.date) > new Date(existing.lastVisit)) {
          existing.lastVisit = apt.date;
        }
      }
    }
  }

  return c.json(Array.from(patientMap.values()));
});

app.get(`${BASE_PATH}/doctor/patient/:patientId/history`, async (c) => {
  const patientId = c.req.param('patientId');
  const { user, error } = await getUser(c);
  if (error) return c.json({ error }, 401);

  const patient = await kv.get(`user:id:${patientId}`);
  const appointments = await kv.getByPrefix('appointment:');
  const patientApts = appointments.filter((apt: any) => apt.patientId === patientId && apt.doctorId === user.id);

  return c.json({
    patient,
    appointments: patientApts.sort((a: any, b: any) => new Date(b.date).getTime() - new Date(a.date).getTime()),
    totalVisits: patientApts.length
  });
});

// 6. TRANSACTIONS & EARNINGS

app.post(`${BASE_PATH}/transactions`, async (c) => {
  try {
    const body = await c.req.json();
    const { authToken, doctorId, amount, type, status, appointmentId, description } = body;

    const { user, error } = await getUser(c, authToken);
    if (error) return c.json({ error }, 401);

    const transactionId = crypto.randomUUID();
    const transaction = {
      id: transactionId,
      doctorId,
      amount,
      type,
      status: status || 'pending',
      appointmentId,
      description,
      createdAt: new Date().toISOString(),
      createdBy: user.id
    };

    await kv.set(`transaction:${transactionId}`, transaction);
    await kv.set(`doctor_transactions:${doctorId}:${Date.now()}`, transactionId);

    return c.json({ message: "Transaction recorded", transaction }, 201);
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

app.get(`${BASE_PATH}/doctor/transactions`, async (c) => {
  const { user, error } = await getUser(c);
  if (error) return c.json({ error }, 401);

  if (user.user_metadata?.role !== 'doctor') {
    return c.json({ error: "Unauthorized" }, 403);
  }

  const transactions = await kv.getByPrefix(`doctor_transactions:${user.id}:`);
  const transactionDetails = [];

  for (const transId of transactions) {
    const trans = await kv.get(`transaction:${transId}`);
    if (trans) transactionDetails.push(trans);
  }

  transactionDetails.sort((a: any, b: any) =>
    new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
  );

  return c.json(transactionDetails);
});

app.get(`${BASE_PATH}/doctor/earnings/summary`, async (c) => {
  const { user, error } = await getUser(c);
  if (error) return c.json({ error }, 401);

  if (user.user_metadata?.role !== 'doctor') {
    return c.json({ error: "Unauthorized" }, 403);
  }

  const transactions = await kv.getByPrefix(`doctor_transactions:${user.id}:`);
  let totalEarnings = 0;
  let pending = 0;
  let completed = 0;

  for (const transId of transactions) {
    const trans = await kv.get(`transaction:${transId}`);
    if (trans) {
      totalEarnings += trans.amount || 0;
      if (trans.status === 'pending') pending += trans.amount || 0;
      else if (trans.status === 'completed') completed += trans.amount || 0;
    }
  }

  return c.json({
    totalEarnings,
    pendingAmount: pending,
    completedAmount: completed,
    availableForWithdrawal: Math.max(completed - (completed * 0.1), 0),
    nextPayoutDate: new Date(Date.now() + 86400000 * 5).toISOString()
  });
});

// 7. DASHBOARD ANALYTICS

// BUG FIX 5: cancelledConsultations was `total - completed`, which incorrectly
// counted scheduled/in-progress appointments as cancelled.
app.get(`${BASE_PATH}/doctor/analytics/overview`, async (c) => {
  const { user, error } = await getUser(c);
  if (error) return c.json({ error }, 401);

  if (user.user_metadata?.role !== 'doctor') {
    return c.json({ error: "Unauthorized" }, 403);
  }

  const appointments = await kv.getByPrefix('appointment:');
  const doctorApts = appointments.filter((apt: any) => apt.doctorId === user.id);

  let totalConsultations = 0;
  let completedConsultations = 0;
  let cancelledConsultations = 0;
  let totalRevenue = 0;
  const averageRating = 4.5;

  for (const apt of doctorApts) {
    totalConsultations++;
    if (apt.status === 'completed') {
      completedConsultations++;
      totalRevenue += apt.fee || 1000;
    } else if (apt.status === 'cancelled') {
      cancelledConsultations++;
    }
  }

  return c.json({
    totalConsultations,
    completedConsultations,
    cancelledConsultations,
    totalRevenue,
    averageRating,
    topComplaint: 'General Checkup',
    appointmentTrend: [
      { week: 'W1', count: Math.floor(Math.random() * 10) + 5 },
      { week: 'W2', count: Math.floor(Math.random() * 10) + 5 },
      { week: 'W3', count: Math.floor(Math.random() * 10) + 5 },
      { week: 'W4', count: Math.floor(Math.random() * 10) + 5 }
    ]
  });
});

// 8. EMERGENCY SLOTS

app.post(`${BASE_PATH}/doctor/emergency-slots`, async (c) => {
  try {
    const body = await c.req.json();
    const { authToken, date, time, duration } = body;

    const { user, error } = await getUser(c, authToken);
    if (error) return c.json({ error }, 401);

    if (user.user_metadata?.role !== 'doctor') {
      return c.json({ error: "Unauthorized" }, 403);
    }

    const emergencySlotId = crypto.randomUUID();
    const slot = {
      id: emergencySlotId,
      doctorId: user.id,
      date,
      time,
      duration: duration || 30,
      isEmergency: true,
      status: 'available',
      createdAt: new Date().toISOString()
    };

    await kv.set(`emergency_slot:${emergencySlotId}`, slot);
    await kv.set(`doctor_emergency_slots:${user.id}:${date}:${time}`, emergencySlotId);

    return c.json({ message: "Emergency slot created", slot }, 201);
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

app.get(`${BASE_PATH}/doctor/emergency-slots`, async (c) => {
  const { user, error } = await getUser(c);
  if (error) return c.json({ error }, 401);

  if (user.user_metadata?.role !== 'doctor') {
    return c.json({ error: "Unauthorized" }, 403);
  }

  const slots = await kv.getByPrefix(`doctor_emergency_slots:${user.id}:`);
  const slotDetails = [];

  for (const slotId of slots) {
    const slot = await kv.get(`emergency_slot:${slotId}`);
    if (slot && slot.status === 'available') slotDetails.push(slot);
  }

  return c.json(slotDetails);
});

// 9. JOB MARKETPLACE

app.post(`${BASE_PATH}/jobs`, async (c) => {
  try {
    const body = await c.req.json();
    const { authToken, title, description, position, salary, location, hospital } = body;

    const { user, error } = await getUser(c, authToken);
    if (error) return c.json({ error }, 401);

    if (user.user_metadata?.role !== 'hospital') {
      return c.json({ error: "Only hospitals can post jobs" }, 403);
    }

    const jobId = crypto.randomUUID();
    const job = {
      id: jobId,
      title,
      description,
      position,
      salary,
      location,
      hospital,
      postedBy: user.id,
      status: 'active',
      createdAt: new Date().toISOString()
    };

    await kv.set(`job:${jobId}`, job);
    await kv.set(`hospital_jobs:${user.id}:${jobId}`, jobId);

    return c.json({ message: "Job posted", job }, 201);
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

app.get(`${BASE_PATH}/jobs`, async (c) => {
  try {
    const positions = c.req.query('positions')?.split(',') || [];

    const jobs = await kv.getByPrefix('job:');
    let filtered = jobs.filter((job: any) => job.status === 'active');

    if (positions.length > 0) {
      filtered = filtered.filter((job: any) => positions.includes(job.position));
    }

    filtered.sort((a: any, b: any) =>
      new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
    );

    return c.json(filtered);
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

// 10. BLOG APPROVAL WORKFLOW

app.post(`${BASE_PATH}/blogs/submit-for-review`, async (c) => {
  try {
    const body = await c.req.json();
    const { authToken, blogId } = body;

    const { user, error } = await getUser(c, authToken);
    if (error) return c.json({ error }, 401);

    const blog = await kv.get(`doctor_blog:${blogId}`);
    if (!blog) return c.json({ error: "Blog not found" }, 404);

    if (blog.authorId !== user.id) {
      return c.json({ error: "Unauthorized" }, 403);
    }

    blog.status = 'pending_review';
    blog.submittedAt = new Date().toISOString();
    await kv.set(`doctor_blog:${blogId}`, blog);

    return c.json({ message: "Blog submitted for review", blog });
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

app.post(`${BASE_PATH}/admin/blogs/approve`, async (c) => {
  try {
    const body = await c.req.json();
    const { authToken, blogId, reviewNotes } = body;

    const { user, error } = await getUser(c, authToken);
    if (error) return c.json({ error }, 401);

    const { allowed } = await checkPermission(user, PERMISSIONS.VERIFY_USERS);
    if (!allowed) return c.json({ error: "Unauthorized" }, 403);

    const blog = await kv.get(`doctor_blog:${blogId}`);
    if (!blog) return c.json({ error: "Blog not found" }, 404);

    blog.status = 'published';
    blog.publishedAt = new Date().toISOString();
    blog.publishedBy = user.id;
    blog.reviewNotes = reviewNotes;
    await kv.set(`doctor_blog:${blogId}`, blog);

    return c.json({ message: "Blog approved and published", blog });
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

app.post(`${BASE_PATH}/admin/blogs/reject`, async (c) => {
  try {
    const body = await c.req.json();
    const { authToken, blogId, rejectionReason } = body;

    const { user, error } = await getUser(c, authToken);
    if (error) return c.json({ error }, 401);

    const { allowed } = await checkPermission(user, PERMISSIONS.VERIFY_USERS);
    if (!allowed) return c.json({ error: "Unauthorized" }, 403);

    const blog = await kv.get(`doctor_blog:${blogId}`);
    if (!blog) return c.json({ error: "Blog not found" }, 404);

    blog.status = 'rejected';
    blog.rejectionReason = rejectionReason;
    blog.reviewedAt = new Date().toISOString();
    blog.reviewedBy = user.id;
    await kv.set(`doctor_blog:${blogId}`, blog);

    return c.json({ message: "Blog rejected", blog });
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

// 11. VERIFICATION SYSTEM

app.post(`${BASE_PATH}/verification/submit-doctor`, async (c) => {
  try {
    const body = await c.req.json();
    const { authToken, registrationNumber, qualifications, licenseUrl } = body;

    const { user, error } = await getUser(c, authToken);
    if (error) return c.json({ error }, 401);

    const verificationId = crypto.randomUUID();
    const verification = {
      id: verificationId,
      userId: user.id,
      type: 'doctor',
      registrationNumber,
      qualifications,
      licenseUrl,
      status: 'pending',
      submittedAt: new Date().toISOString()
    };

    await kv.set(`verification:${verificationId}`, verification);
    await kv.set(`user_verification:${user.id}`, verificationId);

    return c.json({ message: "Verification submitted for review", verification }, 201);
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

app.post(`${BASE_PATH}/admin/verification/approve`, async (c) => {
  try {
    const body = await c.req.json();
    const { authToken, verificationId } = body;

    const { user, error } = await getUser(c, authToken);
    if (error) return c.json({ error }, 401);

    const { allowed } = await checkPermission(user, PERMISSIONS.VERIFY_USERS);
    if (!allowed) return c.json({ error: "Unauthorized" }, 403);

    const verification = await kv.get(`verification:${verificationId}`);
    if (!verification) return c.json({ error: "Verification not found" }, 404);

    verification.status = 'verified';
    verification.approvedAt = new Date().toISOString();
    verification.approvedBy = user.id;
    await kv.set(`verification:${verificationId}`, verification);

    await supabaseAdmin.auth.admin.updateUserById(verification.userId, {
      user_metadata: { verification_status: 'verified', verified_at: new Date().toISOString() }
    });

    return c.json({ message: "Verification approved", verification });
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

app.post(`${BASE_PATH}/admin/verification/reject`, async (c) => {
  try {
    const body = await c.req.json();
    const { authToken, verificationId, reason } = body;

    const { user, error } = await getUser(c, authToken);
    if (error) return c.json({ error }, 401);

    const { allowed } = await checkPermission(user, PERMISSIONS.VERIFY_USERS);
    if (!allowed) return c.json({ error: "Unauthorized" }, 403);

    const verification = await kv.get(`verification:${verificationId}`);
    if (!verification) return c.json({ error: "Verification not found" }, 404);

    verification.status = 'rejected';
    verification.rejectedAt = new Date().toISOString();
    verification.rejectedBy = user.id;
    verification.rejectionReason = reason || '';
    await kv.set(`verification:${verificationId}`, verification);

    return c.json({ message: "Verification rejected", verification });
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

app.get(`${BASE_PATH}/admin/verifications`, async (c) => {
  try {
    const authToken = c.req.query('authToken');
    const type = c.req.query('type') || 'all';
    const status = c.req.query('status') || 'all';

    const { user, error } = await getUser(c, authToken);
    if (error) return c.json({ error }, 401);

    const { allowed } = await checkPermission(user, PERMISSIONS.VERIFY_USERS);
    if (!allowed) return c.json({ error: "Unauthorized" }, 403);

    let verifications = await kv.getByPrefix('verification:');

    if (type !== 'all') {
      verifications = verifications.filter((v: any) => v.type === type);
    }

    if (status !== 'all') {
      verifications = verifications.filter((v: any) => v.status === status);
    }

    verifications.sort((a: any, b: any) =>
      new Date(b.submittedAt).getTime() - new Date(a.submittedAt).getTime()
    );

    return c.json(verifications);
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

// 12. JOB APPLICATIONS
// BUG FIX 6: Duplicate POST /job-applications route removed. The original section-9 handler
// created an incomplete record and only indexed by user. This single merged handler creates
// a complete record and indexes by BOTH job and user.
app.post(`${BASE_PATH}/job-applications`, async (c) => {
  try {
    const body = await c.req.json();
    const { authToken, jobId, coverLetter, resumeUrl } = body;

    const { user, error } = await getUser(c, authToken);
    if (error) return c.json({ error }, 401);

    const applicationId = crypto.randomUUID();
    const application = {
      id: applicationId,
      jobId,
      userId: user.id,
      applicantId: user.id,
      applicantEmail: user.email,
      coverLetter,
      resumeUrl,
      status: 'submitted',
      submittedAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    await kv.set(`job_application:${applicationId}`, application);
    await kv.set(`job_applications:${jobId}:${applicationId}`, applicationId);
    await kv.set(`user_job_applications:${user.id}:${applicationId}`, applicationId);

    return c.json({ message: "Application submitted successfully", application }, 201);
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

app.get(`${BASE_PATH}/admin/job-applications`, async (c) => {
  try {
    const authToken = c.req.query('authToken');
    const jobId = c.req.query('jobId');
    const status = c.req.query('status') || 'all';

    const { user, error } = await getUser(c, authToken);
    if (error) return c.json({ error }, 401);

    if (user.user_metadata?.role !== 'hospital') {
      return c.json({ error: "Unauthorized" }, 403);
    }

    let applications = await kv.getByPrefix('job_application:');

    if (jobId) {
      applications = applications.filter((a: any) => a.jobId === jobId);
    }

    if (status !== 'all') {
      applications = applications.filter((a: any) => a.status === status);
    }

    applications.sort((a: any, b: any) =>
      new Date(b.submittedAt).getTime() - new Date(a.submittedAt).getTime()
    );

    return c.json(applications);
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

app.put(`${BASE_PATH}/admin/job-applications/:id`, async (c) => {
  try {
    const applicationId = c.req.param('id');
    const authToken = c.req.query('authToken');
    const body = await c.req.json();
    const { status, notes } = body;

    const { user, error } = await getUser(c, authToken);
    if (error) return c.json({ error }, 401);

    if (user.user_metadata?.role !== 'hospital') {
      return c.json({ error: "Unauthorized" }, 403);
    }

    const application = await kv.get(`job_application:${applicationId}`);
    if (!application) return c.json({ error: "Application not found" }, 404);

    application.status = status;
    application.notes = notes || '';
    application.updatedAt = new Date().toISOString();
    await kv.set(`job_application:${applicationId}`, application);

    return c.json({ message: "Application updated", application });
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

// 13. RAZORPAY PAYMENTS

app.post(`${BASE_PATH}/payments/razorpay-webhook`, async (c) => {
  try {
    const body = await c.req.json();
    const { payload, signature } = body;

    if (!payload || !signature) {
      return c.json({ error: "Missing required webhook fields" }, 400);
    }

    const isValidSignature = await verifyPaymentSignature(payload.order?.id, payload.payment?.id, signature);
    if (!isValidSignature) {
      console.error('Invalid Razorpay signature for order:', payload.order?.id);
      return c.json({ error: "Invalid signature" }, 403);
    }

    const orderId = payload.order?.id;
    const paymentId = payload.payment?.id;
    const paymentStatus = payload.payment?.status;

    const allTransactions = await kv.getByPrefix('transaction:');
    const transaction = allTransactions.find((t: any) => t.orderId === orderId);

    if (transaction) {
      transaction.paymentStatus = paymentStatus;
      transaction.paymentId = paymentId;
      transaction.processedAt = new Date().toISOString();

      await kv.set(`transaction:${transaction.id}`, transaction);

      if (paymentStatus === 'captured' || paymentStatus === 'authorized') {
        const notification = {
          id: crypto.randomUUID(),
          userId: transaction.userId,
          type: 'payment_success',
          title: 'Payment Successful',
          message: `Your payment of ₹${transaction.amount} has been processed successfully.`,
          data: { paymentId, orderId },
          read: false,
          createdAt: new Date().toISOString()
        };
        await kv.set(`notification:${notification.id}`, notification);
      } else if (paymentStatus === 'failed') {
        const notification = {
          id: crypto.randomUUID(),
          userId: transaction.userId,
          type: 'payment_failure',
          title: 'Payment Failed',
          message: `Your payment of ₹${transaction.amount} could not be processed. Please try again.`,
          data: { paymentId, orderId },
          read: false,
          createdAt: new Date().toISOString()
        };
        await kv.set(`notification:${notification.id}`, notification);
      }

      await logActivity('system', 'webhook', 'razorpay_payment_webhook', orderId, {
        paymentStatus,
        paymentId
      });

      return c.json({ message: "Webhook processed successfully", orderId, paymentStatus }, 200);
    } else {
      console.warn('Transaction not found for order:', orderId);
      return c.json({ error: "Transaction not found" }, 404);
    }
  } catch (e: any) {
    console.error('Razorpay webhook error:', e);
    return c.json({ error: e.message }, 500);
  }
});

app.post(`${BASE_PATH}/payments/verify`, async (c) => {
  const { user, error } = await getUser(c);
  if (error) return c.json({ error }, 401);

  const body = await c.req.json();
  const { razorpay_payment_id, razorpay_order_id, razorpay_signature, appointment_id } = body;

  if (!razorpay_payment_id || !razorpay_order_id || !razorpay_signature) {
    return c.json({ error: "Missing required verification fields" }, 400);
  }

  if (!RAZORPAY_KEY_SECRET) {
    return c.json({ error: "Razorpay secret is not configured" }, 500);
  }

  const expectedSignature = await computeRazorpaySignature(razorpay_order_id, razorpay_payment_id);
  if (!timingSafeEqual(expectedSignature, razorpay_signature)) {
    return c.json({ success: false, error: "Invalid payment signature", appointmentId: appointment_id || null }, 400);
  }

  return c.json({
    success: true,
    paymentId: razorpay_payment_id,
    appointmentId: appointment_id || null,
    message: "Payment signature verified",
  });
});

Deno.serve(app.fetch);
