/* =========================================================
   BANE PERFORMANCE PEPTIDES — backend
   Express + Supabase Postgres. Runs on Render, called cross-origin
   from the SiteGround static site.

   Auth: token-based (Authorization: Bearer <token>) for cross-origin
   support; session cookie kept as fallback for same-origin localhost.

   Storage: Supabase Postgres via @supabase/supabase-js using the
   service role key. RLS is enabled on every table; service role
   bypasses by design.
   ========================================================= */

const express = require('express');
const session = require('express-session');
const bcrypt  = require('bcryptjs');
const crypto  = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const PORT     = process.env.PORT || 3000;
const IS_PROD  = process.env.NODE_ENV === 'production';

// ---------- Supabase ----------
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;
if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error('Missing SUPABASE_URL or SUPABASE_KEY. Set env vars and restart.');
  process.exit(1);
}
const sb = createClient(SUPABASE_URL, SUPABASE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
});

// ---------- Defaults / seed ----------
const DEFAULT_ADMIN_EMAIL = (process.env.ADMIN_EMAIL || 'support@baneperformance.com').toLowerCase();
const DEFAULT_ADMIN_PASS  = process.env.ADMIN_PASSWORD || 'BanePerf!2026';
const TOKEN_TTL_MS = 1000 * 60 * 60 * 8; // 8 hours

function uid() { return crypto.randomBytes(8).toString('hex'); }

async function ensureSeedAdmin() {
  const { data, error } = await sb.from('admin_users').select('id').limit(1);
  if (error) { console.error('seed check failed:', error.message); return; }
  if (data && data.length > 0) return;
  const { error: e2 } = await sb.from('admin_users').insert({
    id: uid(),
    email: DEFAULT_ADMIN_EMAIL,
    password_hash: bcrypt.hashSync(DEFAULT_ADMIN_PASS, 10),
  });
  if (e2) console.error('seed insert failed:', e2.message);
  else console.log(`[seed] Created default admin: ${DEFAULT_ADMIN_EMAIL}`);
}

// ---------- App ----------
const app = express();
if (IS_PROD) app.set('trust proxy', 1);

app.use(express.json({ limit: '12mb' }));

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS ||
  'http://localhost:3000,https://cavenaughm20.sg-host.com'
).split(',').map(s => s.trim()).filter(Boolean);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,DELETE,PATCH,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Accept,Authorization');
  }
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

if (!IS_PROD) {
  app.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    next();
  });
}

app.use(session({
  name: 'bane.sid',
  secret: process.env.SESSION_SECRET || 'bane-localhost-' + crypto.randomBytes(8).toString('hex'),
  resave: false,
  saveUninitialized: false,
  proxy: IS_PROD,
  cookie: {
    httpOnly: true,
    sameSite: IS_PROD ? 'none' : 'lax',
    secure:   IS_PROD,
    maxAge: TOKEN_TTL_MS,
  },
}));

// ---------- Auth helpers ----------
function tokenFromRequest(req) {
  const h = req.headers.authorization || '';
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return m ? m[1].trim() : null;
}

async function userFromToken(token) {
  if (!token) return null;
  const cutoff = new Date(Date.now() - TOKEN_TTL_MS).toISOString();
  const { data: sess } = await sb
    .from('admin_sessions')
    .select('user_id, created_at')
    .eq('token', token)
    .gte('created_at', cutoff)
    .maybeSingle();
  if (!sess) return null;
  const { data: user } = await sb
    .from('admin_users')
    .select('id, email')
    .eq('id', sess.user_id)
    .maybeSingle();
  return user || null;
}

async function requireAdmin(req, res, next) {
  const token = tokenFromRequest(req);
  if (token) {
    const user = await userFromToken(token);
    if (user) { req.admin = user; return next(); }
  }
  if (req.session && req.session.adminId) {
    req.admin = { id: req.session.adminId, email: req.session.adminEmail };
    return next();
  }
  return res.status(401).json({ error: 'unauthorized' });
}

// ---------- Public APIs ----------
app.post('/api/orders', async (req, res) => {
  const { customer = {}, items = [], coupon_code, subtotal, discount, shipping, total } = req.body || {};
  if (!Array.isArray(items) || items.length === 0) return res.status(400).json({ error: 'no items' });
  const order = {
    id: uid(),
    customer_name: customer.name || '',
    customer_email: customer.email || '',
    customer_phone: customer.phone || '',
    customer_address: customer.address || '',
    customer_zip: customer.zip || '',
    notes: customer.notes || '',
    items, coupon_code: coupon_code || null,
    subtotal: Number(subtotal) || 0,
    discount: Number(discount) || 0,
    shipping: Number(shipping) || 0,
    total: Number(total) || 0,
    status: 'pending',
  };
  const { error } = await sb.from('orders').insert(order);
  if (error) return res.status(500).json({ error: 'db', details: error.message });
  res.json({ ok: true, id: order.id });
});

app.post('/api/track', async (req, res) => {
  const { event_type, page, product_id } = req.body || {};
  await sb.from('analytics_events').insert({
    event_type: event_type || 'view',
    page: page || '/',
    product_id: product_id || null,
    user_agent: (req.headers['user-agent'] || '').slice(0, 240),
  });
  res.json({ ok: true });
});

app.post('/api/reviews', async (req, res) => {
  const { name, location, rating, content } = req.body || {};
  if (!name || !content) return res.status(400).json({ error: 'name and review required' });
  const r = parseInt(rating, 10);
  const { error } = await sb.from('reviews').insert({
    id: uid(),
    name: String(name).slice(0, 80),
    location: String(location || '').slice(0, 80),
    rating: (r >= 1 && r <= 5) ? r : 5,
    content: String(content).slice(0, 2000),
    status: 'pending',
    visibility: 'public',
  });
  if (error) return res.status(500).json({ error: 'db' });
  res.json({ ok: true });
});

app.get('/api/reviews', async (req, res) => {
  const { data, error } = await sb
    .from('reviews')
    .select('id, name, location, rating, content, created_at')
    .eq('status', 'approved')
    .eq('visibility', 'public')
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json([]);
  res.json(data || []);
});

app.post('/api/coupons/validate', async (req, res) => {
  const code = String((req.body && req.body.code) || '').trim().toUpperCase();
  if (!code) return res.status(400).json({ error: 'no code' });
  const { data: coupon } = await sb.from('coupons')
    .select('*').eq('code', code).eq('active', true).maybeSingle();
  if (!coupon) return res.status(404).json({ error: 'invalid' });
  if (coupon.expires_at && new Date(coupon.expires_at) < new Date()) return res.status(410).json({ error: 'expired' });
  if (coupon.max_uses && coupon.current_uses >= coupon.max_uses) return res.status(410).json({ error: 'maxed' });
  res.json({ code: coupon.code, type: coupon.type, value: Number(coupon.value), label: coupon.label || '' });
});

app.get('/api/catalog', async (req, res) => {
  const [over, custom] = await Promise.all([
    sb.from('product_overrides').select('*'),
    sb.from('custom_products').select('*'),
  ]);
  res.json({
    overrides: over.data || [],
    custom: custom.data || [],
  });
});

// ---------- Admin auth ----------
app.post('/api/admin/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'missing' });
  const { data: user } = await sb.from('admin_users')
    .select('id, email, password_hash')
    .eq('email', String(email).toLowerCase())
    .maybeSingle();
  if (!user) return res.status(401).json({ error: 'invalid' });
  if (!bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({ error: 'invalid' });

  const token = crypto.randomBytes(32).toString('hex');
  await sb.from('admin_sessions').insert({ token, user_id: user.id });
  // best-effort prune of expired tokens
  const cutoff = new Date(Date.now() - TOKEN_TTL_MS).toISOString();
  await sb.from('admin_sessions').delete().lt('created_at', cutoff);

  if (req.session) { req.session.adminId = user.id; req.session.adminEmail = user.email; }
  res.json({ ok: true, email: user.email, token });
});

app.post('/api/admin/logout', async (req, res) => {
  const token = tokenFromRequest(req);
  if (token) await sb.from('admin_sessions').delete().eq('token', token);
  if (req.session) req.session.destroy(() => res.json({ ok: true }));
  else res.json({ ok: true });
});

app.get('/api/admin/me', async (req, res) => {
  const token = tokenFromRequest(req);
  if (token) {
    const user = await userFromToken(token);
    if (user) return res.json({ email: user.email });
  }
  if (req.session && req.session.adminId) return res.json({ email: req.session.adminEmail });
  return res.status(401).json({ error: 'unauthorized' });
});

// ---------- Admin: orders ----------
app.get('/api/admin/orders', requireAdmin, async (req, res) => {
  const { data } = await sb.from('orders').select('*').order('created_at', { ascending: false });
  res.json(data || []);
});

app.post('/api/admin/orders/:id/status', requireAdmin, async (req, res) => {
  const next = String((req.body && req.body.status) || '').toLowerCase();
  if (!['pending', 'paid', 'shipped', 'cancelled'].includes(next)) return res.status(400).json({ error: 'bad status' });
  const { data, error } = await sb.from('orders')
    .update({ status: next, updated_at: new Date().toISOString() })
    .eq('id', req.params.id)
    .select('*').maybeSingle();
  if (error || !data) return res.status(404).json({ error: 'not found' });
  res.json({ ok: true, order: data });
});

app.delete('/api/admin/orders/:id', requireAdmin, async (req, res) => {
  await sb.from('orders').delete().eq('id', req.params.id);
  res.json({ ok: true });
});

// ---------- Admin: coupons ----------
app.get('/api/admin/coupons', requireAdmin, async (req, res) => {
  const { data } = await sb.from('coupons').select('*').order('created_at', { ascending: false });
  res.json(data || []);
});

app.post('/api/admin/coupons', requireAdmin, async (req, res) => {
  const { code, type, value, expires_at, max_uses, label } = req.body || {};
  if (!code || !type || value == null) return res.status(400).json({ error: 'missing fields' });
  if (!['percent', 'fixed'].includes(type)) return res.status(400).json({ error: 'bad type' });
  const upper = String(code).trim().toUpperCase();
  const row = {
    id: uid(),
    code: upper,
    type,
    value: Number(value),
    label: String(label || ''),
    expires_at: expires_at || null,
    max_uses: max_uses ? Number(max_uses) : null,
    current_uses: 0,
    active: true,
  };
  const { data, error } = await sb.from('coupons').insert(row).select('*').maybeSingle();
  if (error) {
    if (String(error.message).toLowerCase().includes('duplicate')) return res.status(409).json({ error: 'code exists' });
    return res.status(500).json({ error: 'db' });
  }
  res.json({ ok: true, coupon: data });
});

app.delete('/api/admin/coupons/:id', requireAdmin, async (req, res) => {
  await sb.from('coupons').delete().eq('id', req.params.id);
  res.json({ ok: true });
});

// ---------- Admin: reviews ----------
app.get('/api/admin/reviews', requireAdmin, async (req, res) => {
  const { data } = await sb.from('reviews').select('*').order('created_at', { ascending: false });
  res.json(data || []);
});

app.post('/api/admin/reviews/:id/status', requireAdmin, async (req, res) => {
  const next = String((req.body && req.body.status) || '').toLowerCase();
  if (!['pending', 'approved', 'rejected'].includes(next)) return res.status(400).json({ error: 'bad status' });
  const update = { status: next };
  if (next === 'approved') update.approved_at = new Date().toISOString();
  const { data, error } = await sb.from('reviews').update(update).eq('id', req.params.id).select('*').maybeSingle();
  if (error || !data) return res.status(404).json({ error: 'not found' });
  res.json({ ok: true, review: data });
});

app.post('/api/admin/reviews/:id/visibility', requireAdmin, async (req, res) => {
  const v = String((req.body && req.body.visibility) || 'public');
  const visibility = (v === 'private') ? 'private' : 'public';
  const { data, error } = await sb.from('reviews').update({ visibility }).eq('id', req.params.id).select('*').maybeSingle();
  if (error || !data) return res.status(404).json({ error: 'not found' });
  res.json({ ok: true, review: data });
});

app.delete('/api/admin/reviews/:id', requireAdmin, async (req, res) => {
  await sb.from('reviews').delete().eq('id', req.params.id);
  res.json({ ok: true });
});

// ---------- Admin: product overrides ----------
app.get('/api/admin/products', requireAdmin, async (req, res) => {
  const { data } = await sb.from('product_overrides').select('*');
  res.json(data || []);
});

app.post('/api/admin/products/:id', requireAdmin, async (req, res) => {
  const product_id = req.params.id;
  const { name, dose, price, image_url, active } = req.body || {};
  // upsert: select existing, then insert or update
  const { data: existing } = await sb.from('product_overrides').select('id').eq('product_id', product_id).maybeSingle();
  const fields = { product_id, updated_at: new Date().toISOString() };
  if (name      != null) fields.name = String(name);
  if (dose      != null) fields.dose = String(dose);
  if (price     != null) fields.price = Number(price);
  if (image_url != null) fields.image_url = String(image_url);
  if (active    != null) fields.active = !!active;
  if (existing) {
    const { data } = await sb.from('product_overrides').update(fields).eq('product_id', product_id).select('*').maybeSingle();
    return res.json({ ok: true, override: data });
  }
  fields.id = uid();
  if (fields.active === undefined) fields.active = true;
  const { data, error } = await sb.from('product_overrides').insert(fields).select('*').maybeSingle();
  if (error) return res.status(500).json({ error: 'db' });
  res.json({ ok: true, override: data });
});

app.delete('/api/admin/products/:id', requireAdmin, async (req, res) => {
  await sb.from('product_overrides').delete().eq('product_id', req.params.id);
  res.json({ ok: true });
});

// ---------- Admin: custom products ----------
app.get('/api/admin/custom-products', requireAdmin, async (req, res) => {
  const { data } = await sb.from('custom_products').select('*').order('created_at', { ascending: false });
  res.json(data || []);
});

app.post('/api/admin/custom-products', requireAdmin, async (req, res) => {
  const { name, dose, price, category, description, image } = req.body || {};
  if (!name || price == null) return res.status(400).json({ error: 'missing fields' });
  const slugBase = String(name).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 24) || 'custom';
  // ensure unique id
  let id = slugBase, n = 2;
  while (true) {
    const { data: clash } = await sb.from('custom_products').select('id').eq('id', id).maybeSingle();
    if (!clash) break;
    id = `${slugBase}-${n++}`;
    if (n > 50) { id = `${slugBase}-${uid()}`; break; }
  }
  const product = {
    id,
    name: String(name),
    dose: String(dose || ''),
    price: Number(price),
    category: String(category || 'Other'),
    description: String(description || ''),
    image: String(image || ''),
    custom: true,
  };
  const { data, error } = await sb.from('custom_products').insert(product).select('*').maybeSingle();
  if (error) return res.status(500).json({ error: 'db' });
  res.json({ ok: true, product: data });
});

app.delete('/api/admin/custom-products/:id', requireAdmin, async (req, res) => {
  await sb.from('custom_products').delete().eq('id', req.params.id);
  await sb.from('product_overrides').delete().eq('product_id', req.params.id);
  res.json({ ok: true });
});

// ---------- Admin: image picker / upload ----------
// NOTE: uploads endpoint disabled in cloud mode — Render filesystem is ephemeral.
// For now the picker only lists images already deployed to the static site.
// Migrate to Supabase Storage later when needed.
app.get('/api/admin/images', requireAdmin, (req, res) => {
  res.json({ disabled: true, message: 'Image picker is local-dev only. Set image_url manually for now.' });
});

app.post('/api/admin/upload', requireAdmin, (req, res) => {
  res.status(501).json({ error: 'Image upload not supported in cloud mode. Use SFTP for now.' });
});

// ---------- Admin: analytics ----------
app.get('/api/admin/analytics', requireAdmin, async (req, res) => {
  const since = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
  const [{ data: events }, { data: orders }] = await Promise.all([
    sb.from('analytics_events').select('event_type, page, product_id, created_at').gte('created_at', since).limit(5000),
    sb.from('orders').select('total, status, created_at').gte('created_at', since),
  ]);
  const recent = events || [];
  const ord = orders || [];

  const by = (key) => recent.reduce((m, e) => {
    const k = e[key]; if (!k) return m;
    m[k] = (m[k] || 0) + 1; return m;
  }, {});

  const events_by_type = by('event_type');
  const top_products = Object.entries(by('product_id'))
    .sort((a, b) => b[1] - a[1]).slice(0, 12)
    .map(([product_id, count]) => ({ product_id, count }));
  const top_pages = Object.entries(by('page'))
    .sort((a, b) => b[1] - a[1]).slice(0, 10)
    .map(([page, count]) => ({ page, count }));

  const order_revenue = ord.filter(o => o.status === 'paid').reduce((s, o) => s + Number(o.total || 0), 0);

  res.json({
    last_30_days: {
      events: recent.length,
      events_by_type, top_products, top_pages,
      orders_count: ord.length,
      orders_paid: ord.filter(o => o.status === 'paid').length,
      orders_pending: ord.filter(o => o.status === 'pending').length,
      order_revenue,
    },
  });
});

// ---------- Health check ----------
app.get('/healthz', (req, res) => res.json({ ok: true }));

// ---------- Start ----------
ensureSeedAdmin().finally(() => {
  app.listen(PORT, () => {
    console.log(`Bane API up on :${PORT} (${IS_PROD ? 'production' : 'dev'})`);
  });
});
