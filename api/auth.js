// /api/auth
//
// Telegram Login Widget supports two modes:
//   - Callback mode  (data-onauth):    POST { …payload } → JSON { token, user }
//   - Redirect mode  (data-auth-url):  GET ?…payload     → 302 /?token=…&user=…
//
// This handler implements BOTH. The front-end uses redirect mode (works
// reliably with phone-number login that opens a popup the parent can't
// reach), and POST is retained for testing / future flows.
//
// Required env vars:
//   TELEGRAM_BOT_TOKEN    — bot token from BotFather
//   SUPABASE_URL          — Supabase project URL
//   SUPABASE_SERVICE_KEY  — service_role key (NEVER expose to the browser)
//   JWT_SECRET            — random string used to sign session tokens

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const BOT_TOKEN            = process.env.TELEGRAM_BOT_TOKEN;
const SUPABASE_URL         = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const JWT_SECRET           = process.env.JWT_SECRET;

const TOKEN_TTL          = '30d';
const MAX_AUTH_DATE_AGE  = 86400; // seconds (24h) — reject stale auth payloads

/**
 * Telegram Login Widget hash verification.
 * https://core.telegram.org/widgets/login#checking-authorization
 *   1. Remove `hash` from the payload.
 *   2. Sort remaining fields alphabetically, format as "key=value", join with "\n".
 *   3. secret_key = SHA256(bot_token).
 *   4. computed_hash = HMAC_SHA256(data_check_string, secret_key) in hex.
 *   5. Compare to the supplied hash with a constant-time comparison.
 */
function verifyTelegramHash(payload) {
  if (!payload || typeof payload !== 'object') return false;
  if (!payload.hash || !BOT_TOKEN) return false;

  const { hash, ...data } = payload;
  const dataCheckString = Object.keys(data)
    .filter(k => data[k] !== undefined && data[k] !== null && data[k] !== '')
    .sort()
    .map(k => `${k}=${data[k]}`)
    .join('\n');

  const secretKey = crypto.createHash('sha256').update(BOT_TOKEN).digest();
  const computed  = crypto
    .createHmac('sha256', secretKey)
    .update(dataCheckString)
    .digest('hex');

  if (computed.length !== hash.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(computed), Buffer.from(hash));
  } catch (e) {
    return false;
  }
}

// Shared verification + JWT issuance. Returns:
//   { ok: true,  token, user }                        on success
//   { ok: false, status, errorCode, errorMessage }    on failure
async function performAuth(payload) {
  console.log('=== AUTH DEBUG ===');
  console.log('BOT_TOKEN exists:', !!BOT_TOKEN);
  console.log('BOT_TOKEN length:', BOT_TOKEN ? BOT_TOKEN.length : 0);
  console.log('payload:', JSON.stringify(payload));
  console.log('verifyHash result:', verifyTelegramHash(payload));
  const age = Date.now() / 1000 - parseInt(payload.auth_date, 10);
  console.log('auth_date age seconds:', age);

  if (!BOT_TOKEN || !SUPABASE_URL || !SUPABASE_SERVICE_KEY || !JWT_SECRET) {
    return { ok: false, status: 500, errorCode: 'server', errorMessage: 'Server not configured: missing env vars' };
  }
  if (!verifyTelegramHash(payload)) {
    return { ok: false, status: 401, errorCode: 'invalid', errorMessage: 'Invalid Telegram signature' };
  }
  const authDate = parseInt(payload.auth_date, 10);
  if (isNaN(authDate) || (Date.now() / 1000 - authDate) > MAX_AUTH_DATE_AGE) {
    return { ok: false, status: 401, errorCode: 'stale', errorMessage: 'Auth data is stale' };
  }
  const userId = Number(payload.id);
  if (!userId) {
    return { ok: false, status: 400, errorCode: 'invalid', errorMessage: 'Missing user id' };
  }
  try {
    const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
      auth: { autoRefreshToken: false, persistSession: false },
    });
    const { error } = await supabase.from('users').upsert({
      id: userId,
      username: payload.username || null,
      first_name: payload.first_name || null,
    });
    if (error) {
      console.error('Supabase upsert(users) error:', error);
      return { ok: false, status: 500, errorCode: 'server', errorMessage: 'Database error' };
    }
  } catch (e) {
    console.error('auth handler error:', e);
    return { ok: false, status: 500, errorCode: 'server', errorMessage: 'Server error' };
  }
  const token = jwt.sign({ user_id: userId }, JWT_SECRET, { expiresIn: TOKEN_TTL });
  return {
    ok: true,
    token,
    user: {
      id: userId,
      first_name: payload.first_name || null,
      username:   payload.username   || null,
      photo_url:  payload.photo_url  || null,
    },
  };
}

function redirectTo(res, location) {
  res.statusCode = 302;
  res.setHeader('Location', location);
  res.setHeader('Cache-Control', 'no-store');
  res.end();
}

module.exports = async (req, res) => {
  // ----- Redirect mode (Telegram Login Widget with data-auth-url) -----
  if (req.method === 'GET') {
    const result = await performAuth(req.query || {});
    if (!result.ok) {
      return redirectTo(res, '/?auth_error=' + encodeURIComponent(result.errorCode || 'invalid'));
    }
    // Pack token + user info into a single redirect so the front-end has
    // everything it needs without an extra round-trip.
    const userB64 = Buffer.from(JSON.stringify(result.user))
      .toString('base64')
      .replace(/=+$/, '');
    const qs = new URLSearchParams();
    qs.set('token', result.token);
    qs.set('user',  userB64);
    return redirectTo(res, '/?' + qs.toString());
  }

  // ----- Callback mode (kept for testing / future use) -----
  if (req.method === 'POST') {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const result = await performAuth(body);
    if (!result.ok) {
      return res.status(result.status || 500).json({ error: result.errorMessage });
    }
    return res.status(200).json({ token: result.token, user: result.user });
  }

  res.setHeader('Allow', 'GET, POST');
  return res.status(405).json({ error: 'Method not allowed' });
};
