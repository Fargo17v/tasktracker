// /api/categories — CRUD for the authenticated user's categories.
//
// Auth: Authorization: Bearer <jwt>  (issued by /api/auth)
// Methods:
//   GET    /api/categories             → list all categories for user
//   POST   /api/categories             → upsert single category OR array
//   PUT    /api/categories?key=<key>   → patch one category (label, color_id)
//   DELETE /api/categories?key=<key>   → delete one category AND its tasks (cascade)
//   DELETE /api/categories             → delete ALL of user's categories AND tasks

const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL         = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const JWT_SECRET           = process.env.JWT_SECRET;

function getUserIdFromAuth(req) {
  const header = req.headers && (req.headers.authorization || req.headers.Authorization);
  if (!header) return null;
  const m = String(header).match(/^Bearer\s+(.+)$/i);
  if (!m) return null;
  try {
    const payload = jwt.verify(m[1], JWT_SECRET);
    return payload && payload.user_id ? payload.user_id : null;
  } catch (e) { return null; }
}

async function upsertOne(supabase, userId, body) {
  if (!body.key || !body.label) {
    return { error: { message: 'Missing key/label' }, status: 400 };
  }
  // Find existing row by (user_id, key) so we can preserve the id
  const { data: existing } = await supabase
    .from('categories').select('id')
    .eq('user_id', userId).eq('key', body.key).maybeSingle();
  const row = {
    user_id: userId,
    key: body.key,
    label: body.label,
    color_id: body.color_id || 'blue',
  };
  if (existing && existing.id) row.id = existing.id;
  const { data, error } = await supabase
    .from('categories').upsert(row).select().single();
  if (error) return { error, status: 500 };
  return { data };
}

module.exports = async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY || !JWT_SECRET) {
    return res.status(500).json({ error: 'Server not configured: missing env vars' });
  }
  const userId = getUserIdFromAuth(req);
  if (!userId) return res.status(401).json({ error: 'Unauthorized' });

  const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  try {
    if (req.method === 'GET') {
      const { data, error } = await supabase
        .from('categories').select('*').eq('user_id', userId);
      if (error) throw error;
      return res.status(200).json(data || []);
    }

    if (req.method === 'POST') {
      const body = req.body;
      if (!body) return res.status(400).json({ error: 'Missing body' });
      const arr = Array.isArray(body) ? body : [body];
      if (!arr.length) return res.status(200).json([]);
      const results = [];
      for (const b of arr) {
        const r = await upsertOne(supabase, userId, b);
        if (r.error) {
          console.error('upsertOne error:', r.error);
          return res.status(r.status || 500).json({ error: r.error.message || 'upsert failed' });
        }
        results.push(r.data);
      }
      return res.status(201).json(Array.isArray(body) ? results : results[0]);
    }

    if (req.method === 'PUT') {
      const key = req.query && req.query.key;
      if (!key) return res.status(400).json({ error: 'Missing key' });
      const body = req.body || {};
      const patch = {};
      if ('label'    in body) patch.label    = body.label;
      if ('color_id' in body) patch.color_id = body.color_id;
      const { data, error } = await supabase.from('categories')
        .update(patch).eq('user_id', userId).eq('key', key).select().single();
      if (error) throw error;
      return res.status(200).json(data);
    }

    if (req.method === 'DELETE') {
      const key = req.query && req.query.key;
      if (key) {
        // Delete tasks tagged with this category first (cascade)
        await supabase.from('tasks').delete()
          .eq('user_id', userId).eq('tag', key);
        const { error } = await supabase.from('categories')
          .delete().eq('user_id', userId).eq('key', key);
        if (error) throw error;
      } else {
        // Wipe all user data (used by resetAll)
        await supabase.from('tasks').delete().eq('user_id', userId);
        const { error } = await supabase.from('categories')
          .delete().eq('user_id', userId);
        if (error) throw error;
      }
      return res.status(200).json({ ok: true });
    }

    res.setHeader('Allow', 'GET, POST, PUT, DELETE');
    return res.status(405).json({ error: 'Method not allowed' });
  } catch (e) {
    console.error('categories handler error:', e);
    return res.status(500).json({ error: 'Server error', detail: String(e.message || e) });
  }
};
