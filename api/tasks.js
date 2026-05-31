// /api/tasks — CRUD for the authenticated user's tasks.
//
// Auth: Authorization: Bearer <jwt>  (issued by /api/auth)
// Methods:
//   GET    /api/tasks                  → list all tasks for user
//   POST   /api/tasks                  → upsert single task OR array of tasks
//   PUT    /api/tasks?id=<uuid>        → patch one task (partial fields)
//   PUT    /api/tasks                  → patch ALL of user's tasks (used for resetProgress)
//   DELETE /api/tasks?id=<uuid>        → delete one task
//   DELETE /api/tasks                  → delete ALL of user's tasks (used for resetAll)

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

function buildTaskRow(userId, b) {
  const row = {
    user_id:       userId,
    text:          b.text,
    tag:           b.tag,
    deadline:      b.deadline      != null ? b.deadline      : null,
    deadline_date: b.deadline_date != null ? b.deadline_date : null,
    month:         b.month         != null ? b.month         : null,
    urgent:        !!b.urgent,
    done:          !!b.done,
    updated_at:    new Date().toISOString(),
  };
  if (b.id) row.id = b.id;
  return row;
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
        .from('tasks').select('*').eq('user_id', userId);
      if (error) throw error;
      return res.status(200).json(data || []);
    }

    if (req.method === 'POST') {
      const body = req.body;
      if (!body) return res.status(400).json({ error: 'Missing body' });
      const arr = Array.isArray(body) ? body : [body];
      if (!arr.length) return res.status(200).json([]);
      const rows = arr.map(b => buildTaskRow(userId, b));
      const { data, error } = await supabase
        .from('tasks').upsert(rows).select();
      if (error) throw error;
      return res.status(201).json(Array.isArray(body) ? (data || []) : (data && data[0]) || null);
    }

    if (req.method === 'PUT') {
      const id   = req.query && req.query.id;
      const body = req.body || {};
      const patch = { updated_at: new Date().toISOString() };
      if ('text'          in body) patch.text          = body.text;
      if ('tag'           in body) patch.tag           = body.tag;
      if ('deadline'      in body) patch.deadline      = body.deadline;
      if ('deadline_date' in body) patch.deadline_date = body.deadline_date;
      if ('month'         in body) patch.month         = body.month;
      if ('urgent'        in body) patch.urgent        = !!body.urgent;
      if ('done'          in body) patch.done          = !!body.done;

      if (id) {
        const { data, error } = await supabase.from('tasks')
          .update(patch).eq('id', id).eq('user_id', userId).select().single();
        if (error) throw error;
        return res.status(200).json(data);
      } else {
        // Bulk update across all of user's tasks (used by resetProgress)
        const { error } = await supabase.from('tasks')
          .update(patch).eq('user_id', userId);
        if (error) throw error;
        return res.status(200).json({ ok: true });
      }
    }

    if (req.method === 'DELETE') {
      const id = req.query && req.query.id;
      let q = supabase.from('tasks').delete().eq('user_id', userId);
      if (id) q = q.eq('id', id);
      const { error } = await q;
      if (error) throw error;
      return res.status(200).json({ ok: true });
    }

    res.setHeader('Allow', 'GET, POST, PUT, DELETE');
    return res.status(405).json({ error: 'Method not allowed' });
  } catch (e) {
    console.error('tasks handler error:', e);
    return res.status(500).json({ error: 'Server error', detail: String(e.message || e) });
  }
};
