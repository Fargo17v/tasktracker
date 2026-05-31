// POST /api/login
// Body: { username, password }
// Returns { token, user: { id, username } } if credentials are correct.
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

  const sb = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY, {
    auth: { autoRefreshToken: false, persistSession: false },
  });
  const { data: user } = await sb.from('users')
    .select('id, username, password_hash')
    .eq('username', username)
    .maybeSingle();
  if (!user || !user.password_hash) return res.status(401).json({ error: 'Invalid username or password' });

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid username or password' });

  const token = jwt.sign({ user_id: user.id }, process.env.JWT_SECRET, { expiresIn: '30d' });
  return res.status(200).json({ token, user: { id: user.id, username: user.username } });
};
