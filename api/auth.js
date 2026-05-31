// POST /api/auth
// Verifies a Telegram Login Widget payload server-side using the bot token,
// upserts the user into Supabase, and returns a JWT session token.
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
 * Algorithm (https://core.telegram.org/widgets/login#checking-authorization):
 *   1. Remove `hash` from the payload.
 *   2. Sort remaining fields alphabetically, format as "key=value", join with "\n".
 *   3. Compute secret_key = SHA256(bot_token).
 *   4. Compute computed_hash = HMAC_SHA256(data_check_string, secret_key) in hex.
 *   5. Compare computed_hash to the supplied hash with a constant-time comparison.
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

  // Constant-time comparison (lengths must match for timingSafeEqual)
  if (computed.length !== hash.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(computed), Buffer.from(hash));
  } catch (e) {
    return false;
  }
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  if (!BOT_TOKEN || !SUPABASE_URL || !SUPABASE_SERVICE_KEY || !JWT_SECRET) {
    return res.status(500).json({ error: 'Server not configured: missing env vars' });
  }

  const payload = req.body && typeof req.body === 'object' ? req.body : {};

  if (!verifyTelegramHash(payload)) {
    return res.status(401).json({ error: 'Invalid Telegram signature' });
  }

  // Freshness check — reject payloads older than MAX_AUTH_DATE_AGE seconds
  const authDate = parseInt(payload.auth_date, 10);
  if (isNaN(authDate) || (Date.now() / 1000 - authDate) > MAX_AUTH_DATE_AGE) {
    return res.status(401).json({ error: 'Auth data is stale' });
  }

  const userId = Number(payload.id);
  if (!userId) return res.status(400).json({ error: 'Missing user id' });

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
      return res.status(500).json({ error: 'Database error', detail: error.message });
    }
  } catch (e) {
    console.error('auth handler error:', e);
    return res.status(500).json({ error: 'Server error', detail: String(e.message || e) });
  }

  const token = jwt.sign({ user_id: userId }, JWT_SECRET, { expiresIn: TOKEN_TTL });

  return res.status(200).json({
    token,
    user: {
      id: userId,
      first_name: payload.first_name || null,
      username:   payload.username   || null,
      photo_url:  payload.photo_url  || null,
    },
  });
};
