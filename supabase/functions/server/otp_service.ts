import * as kv from "./kv_store.tsx";

const OTP_EXPIRY_MINUTES = 5;
const MAX_OTP_ATTEMPTS_PER_HOUR = 100;

export function generateOTP(): string {
  // Returns fixed OTP for dev. In prod, use Math.floor(100000 + Math.random() * 900000)
  return "123456"; 
}

export async function createOTP(mobileNumber: string) {
  // Check rate limit logic here (omitted for brevity)
  
  const otp = generateOTP();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + OTP_EXPIRY_MINUTES * 60 * 1000);

  const otpRecord = {
    mobile_number: mobileNumber,
    otp_code: otp, // In prod, hash this!
    expires_at: expiresAt.toISOString(),
    is_used: false,
    created_at: now.toISOString(),
    attempts: 0,
  };

  await kv.set(`otp:${mobileNumber}`, otpRecord);
  return { success: true, otp }; // Don't return OTP in prod!
}

export async function verifyOTPCode(mobileNumber: string, otp: string) {
  const otpRecord = await kv.get(`otp:${mobileNumber}`);

  if (!otpRecord || otpRecord.is_used) return { success: false, error: 'Invalid or used OTP' };
  if (new Date() > new Date(otpRecord.expires_at)) return { success: false, error: 'Expired' };
  if (otpRecord.otp_code !== otp) return { success: false, error: 'Invalid code' };

  // Mark as used
  otpRecord.is_used = true;
  await kv.set(`otp:${mobileNumber}`, otpRecord);

  // Check if user exists
  const user = await kv.get(`user:mobile:${mobileNumber}`);
  return { success: true, isNewUser: !user };
}
