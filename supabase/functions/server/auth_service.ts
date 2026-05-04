import * as kv from "./kv_store.tsx";

export async function createUser(mobileNumber: string, role = 'patient') {
  const userId = mobileNumber; // Simple ID strategy
  const user = {
    id: userId,
    mobile_number: mobileNumber,
    role,
    created_at: new Date().toISOString(),
  };

  // Index by both mobile and ID
  await kv.set(`user:mobile:${mobileNumber}`, user);
  await kv.set(`user:id:${userId}`, user);
  return user;
}

export async function createAuthTokens(user: any) {
  const accessToken = `access_${user.id}_${Date.now()}_${Math.random().toString(36).substr(2)}`;
  
  // Store token session
  await kv.set(`auth:token:${accessToken}`, {
    user_id: user.id,
    expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString() // 24 hours
  });

  return { access_token: accessToken };
}
