// POST /api/register
// Body: { username, password }
// Creates a new user, returns { token, user: { id, username } }.
//
// Required env vars:
//   SUPABASE_URL, SUPABASE_SERVICE_KEY, JWT_SECRET

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).end();
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (username.length < 3)    return res.status(400).json({ error: 'Username must be at least 3 characters' });
  if (password.length < 6)    return res.status(400).json({ error: 'Password must be at least 6 characters' });

  const sb = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY, {
    auth: { autoRefreshToken: false, persistSession: false },
  });
  const { data: existing } = await sb.from('users').select('id').eq('username', username).maybeSingle();
  if (existing) return res.status(409).json({ error: 'Username already taken' });

  const password_hash = await bcrypt.hash(password, 10);
  const id = Date.now();
  const { error } = await sb.from('users').insert({ id, username, password_hash });
  if (error) {
    console.error('register insert error:', error);
    return res.status(500).json({ error: 'Database error' });
  }

  const token = jwt.sign({ user_id: id }, process.env.JWT_SECRET, { expiresIn: '30d' });
  return res.status(200).json({ token, user: { id, username } });
};
