import * as kv from "./kv_store.tsx";

const OTP_EXPIRY_MINUTES = 5;
const MAX_OTP_ATTEMPTS_PER_HOUR = 5;

export function generateOTP(): string {
  const array = new Uint32Array(1);
  crypto.getRandomValues(array);
  return String((array[0] % 900000) + 100000);
}

export async function createOTP(mobileNumber: string) {
  const hourBucket = new Date().toISOString().slice(0, 13); // "YYYY-MM-DDTHH"
  const rateLimitKey = `otp_rate:${mobileNumber}:${hourBucket}`;
  const rateData = (await kv.get(rateLimitKey)) || { count: 0 };
  if (rateData.count >= MAX_OTP_ATTEMPTS_PER_HOUR) {
    return { success: false, error: 'Too many OTP requests. Please try again later.' };
  }

  rateData.count++;
  await kv.set(rateLimitKey, rateData);

  const otp = generateOTP();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + OTP_EXPIRY_MINUTES * 60 * 1000);

  const otpRecord = {
    mobile_number: mobileNumber,
    otp_code: otp, // TODO: hash before storing in production
    expires_at: expiresAt.toISOString(),
    is_used: false,
    created_at: now.toISOString(),
    attempts: 0,
  };

  await kv.set(`otp:${mobileNumber}`, otpRecord);
  // TODO: send OTP via SMS provider (Twilio, MSG91, etc.) — do NOT return it in the response
  return { success: true };
}

export async function verifyOTPCode(mobileNumber: string, otp: string) {
  const otpRecord = await kv.get(`otp:${mobileNumber}`);

  if (!otpRecord || otpRecord.is_used) return { success: false, error: 'Invalid or used OTP' };
  if (new Date() > new Date(otpRecord.expires_at)) return { success: false, error: 'Expired' };
  if (otpRecord.otp_code !== otp) return { success: false, error: 'Invalid code' };

  otpRecord.is_used = true;
  await kv.set(`otp:${mobileNumber}`, otpRecord);

  const user = await kv.get(`user:mobile:${mobileNumber}`);
  return { success: true, isNewUser: !user };
}
