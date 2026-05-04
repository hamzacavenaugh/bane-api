/* =========================================================
   BANE PERFORMANCE PEPTIDES — local server
   Express + JSON-file storage. No native deps.
   - Serves static site from project root
   - Public APIs:    /api/orders, /api/track, /api/reviews, /api/coupons/validate
   - Admin auth:     /api/admin/login|logout|me
   - Admin APIs:     /api/admin/orders, /coupons, /reviews, /products, /analytics
   - Admin pages:    /admin → login.html or dashboard.html (auth-gated server-side)
   ========================================================= */

const express = require('express');
const session = require('express-session');
const bcrypt  = require('bcryptjs');
const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');

const PORT     = process.env.PORT || 3000;
const ROOT     = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const DB_FILE  = path.join(DATA_DIR, 'bane.json');

// ---------- Default admin (override via env on production) ----------
const DEFAULT_ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'support@baneperformance.com';
const DEFAULT_ADMIN_PASS  = process.env.ADMIN_PASSWORD || 'BanePerf!2026';

// ---------- Tiny JSON-file DB ----------
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

let db = {
  orders: [], reviews: [], coupons: [],
  product_overrides: [], custom_products: [],
  analytics: [], admin_users: [],
  admin_sessions: [], // token-based auth (works cross-origin without 3rd-party cookies)
};

function load() {
  try {
    if (fs.existsSync(DB_FILE)) {
      db = { ...db, ...JSON.parse(fs.readFileSync(DB_FILE, 'utf8')) };
    }
  } catch (e) {
    console.error('DB load failed, starting fresh:', e.message);
  }
}
function save() {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}
function uid() { return crypto.randomBytes(8).toString('hex'); }
function now() { return new Date().toISOString(); }

load();

// Seed admin if missing
if (db.admin_users.length === 0) {
  db.admin_users.push({
    id: uid(),
    email: DEFAULT_ADMIN_EMAIL.toLowerCase(),
    password_hash: bcrypt.hashSync(DEFAULT_ADMIN_PASS, 10),
    created_at: now(),
  });
  save();
  console.log(`\n[seed] Created default admin: ${DEFAULT_ADMIN_EMAIL}\n`);
}

// ---------- App ----------
const app = express();
const IS_PROD = process.env.NODE_ENV === 'production';

// Trust the first proxy in front (Render's load balancer) so secure cookies
// work and req.ip / proto come from X-Forwarded-* headers.
if (IS_PROD) app.set('trust proxy', 1);

app.use(express.json({ limit: '12mb' })); // allow base64-encoded image uploads

// CORS — allow the static-site origins to call the API with credentials.
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

// Dev server: never cache HTML/JS/CSS so iterative changes show on refresh.
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
    // Cross-origin (static site on SG, API on Render) needs SameSite=None + Secure.
    sameSite: IS_PROD ? 'none' : 'lax',
    secure:   IS_PROD,
    maxAge: 1000 * 60 * 60 * 8,
  },
}));

// ---------- Token auth helpers ----------
// Cross-origin browsers (Safari, Firefox strict, Brave, incognito) block 3rd-party
// cookies by default, which breaks session-based auth when the API is on a
// different origin from the static site. Tokens in Authorization headers don't
// have that problem.
const TOKEN_TTL_MS = 1000 * 60 * 60 * 8; // 8 hours

function pruneSessions() {
  const cutoff = Date.now() - TOKEN_TTL_MS;
  const before = db.admin_sessions.length;
  db.admin_sessions = db.admin_sessions.filter(s => new Date(s.created_at).getTime() > cutoff);
  return db.admin_sessions.length !== before;
}

function tokenFromRequest(req) {
  const h = req.headers.authorization || '';
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return m ? m[1].trim() : null;
}

function requireAdmin(req, res, next) {
  // 1) Token (preferred — works cross-origin)
  const token = tokenFromRequest(req);
  if (token) {
    const sess = db.admin_sessions.find(s => s.token === token);
    if (sess && (Date.now() - new Date(sess.created_at).getTime()) < TOKEN_TTL_MS) {
      const user = db.admin_users.find(u => u.id === sess.user_id);
      if (user) {
        req.admin = { id: user.id, email: user.email };
        return next();
      }
    }
  }
  // 2) Session cookie (still works on localhost / same-origin)
  if (req.session && req.session.adminId) {
    req.admin = { id: req.session.adminId, email: req.session.adminEmail };
    return next();
  }
  return res.status(401).json({ error: 'unauthorized' });
}

// ---------- Public APIs ----------
app.post('/api/orders', (req, res) => {
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
    created_at: now(),
  };
  db.orders.unshift(order);
  save();
  res.json({ ok: true, id: order.id });
});

app.post('/api/track', (req, res) => {
  const { event_type, page, product_id } = req.body || {};
  db.analytics.unshift({
    id: uid(),
    event_type: event_type || 'view',
    page: page || '/',
    product_id: product_id || null,
    user_agent: (req.headers['user-agent'] || '').slice(0, 240),
    created_at: now(),
  });
  // cap analytics rows
  if (db.analytics.length > 5000) db.analytics.length = 5000;
  save();
  res.json({ ok: true });
});

app.post('/api/reviews', (req, res) => {
  const { name, location, rating, content } = req.body || {};
  if (!name || !content) return res.status(400).json({ error: 'name and review required' });
  const r = parseInt(rating, 10);
  db.reviews.unshift({
    id: uid(),
    name: String(name).slice(0, 80),
    location: String(location || '').slice(0, 80),
    rating: (r >= 1 && r <= 5) ? r : 5,
    content: String(content).slice(0, 2000),
    status: 'pending',
    visibility: 'public', // can be flipped to private by admin
    created_at: now(),
    approved_at: null,
  });
  save();
  res.json({ ok: true });
});

app.get('/api/reviews', (req, res) => {
  const list = db.reviews
    .filter(r => r.status === 'approved' && r.visibility === 'public')
    .map(({ id, name, location, rating, content, created_at }) => ({ id, name, location, rating, content, created_at }));
  res.json(list);
});

app.post('/api/coupons/validate', (req, res) => {
  const code = String((req.body && req.body.code) || '').trim().toUpperCase();
  if (!code) return res.status(400).json({ error: 'no code' });
  const coupon = db.coupons.find(c => c.code === code && c.active);
  if (!coupon) return res.status(404).json({ error: 'invalid' });
  if (coupon.expires_at && new Date(coupon.expires_at) < new Date()) return res.status(410).json({ error: 'expired' });
  if (coupon.max_uses && coupon.current_uses >= coupon.max_uses) return res.status(410).json({ error: 'maxed' });
  res.json({ code: coupon.code, type: coupon.type, value: coupon.value, label: coupon.label || '' });
});

// ---------- Admin auth ----------
app.post('/api/admin/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'missing' });
  const user = db.admin_users.find(u => u.email === String(email).toLowerCase());
  if (!user) return res.status(401).json({ error: 'invalid' });
  if (!bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({ error: 'invalid' });

  // Mint a token (cross-origin friendly) AND set the session cookie (same-origin friendly).
  const token = crypto.randomBytes(32).toString('hex');
  db.admin_sessions.push({ token, user_id: user.id, created_at: now() });
  if (pruneSessions()) save(); else save();

  req.session.adminId = user.id;
  req.session.adminEmail = user.email;

  res.json({ ok: true, email: user.email, token });
});

app.post('/api/admin/logout', (req, res) => {
  const token = tokenFromRequest(req);
  if (token) {
    db.admin_sessions = db.admin_sessions.filter(s => s.token !== token);
    save();
  }
  if (req.session) req.session.destroy(() => res.json({ ok: true }));
  else res.json({ ok: true });
});

app.get('/api/admin/me', (req, res) => {
  // Token first (cross-origin)
  const token = tokenFromRequest(req);
  if (token) {
    const sess = db.admin_sessions.find(s => s.token === token);
    if (sess && (Date.now() - new Date(sess.created_at).getTime()) < TOKEN_TTL_MS) {
      const user = db.admin_users.find(u => u.id === sess.user_id);
      if (user) return res.json({ email: user.email });
    }
  }
  // Session fallback
  if (req.session && req.session.adminId) return res.json({ email: req.session.adminEmail });
  return res.status(401).json({ error: 'unauthorized' });
});

// ---------- Admin APIs ----------
app.get('/api/admin/orders', requireAdmin, (req, res) => {
  res.json(db.orders);
});

app.post('/api/admin/orders/:id/status', requireAdmin, (req, res) => {
  const order = db.orders.find(o => o.id === req.params.id);
  if (!order) return res.status(404).json({ error: 'not found' });
  const next = String((req.body && req.body.status) || '').toLowerCase();
  if (!['pending', 'paid', 'shipped', 'cancelled'].includes(next)) return res.status(400).json({ error: 'bad status' });
  order.status = next;
  order.updated_at = now();
  save();
  res.json({ ok: true, order });
});

app.delete('/api/admin/orders/:id', requireAdmin, (req, res) => {
  const before = db.orders.length;
  db.orders = db.orders.filter(o => o.id !== req.params.id);
  save();
  res.json({ ok: true, removed: before - db.orders.length });
});

app.get('/api/admin/coupons', requireAdmin, (req, res) => res.json(db.coupons));

app.post('/api/admin/coupons', requireAdmin, (req, res) => {
  const { code, type, value, expires_at, max_uses, label } = req.body || {};
  if (!code || !type || value == null) return res.status(400).json({ error: 'missing fields' });
  if (!['percent', 'fixed'].includes(type)) return res.status(400).json({ error: 'bad type' });
  const upper = String(code).trim().toUpperCase();
  if (db.coupons.find(c => c.code === upper)) return res.status(409).json({ error: 'code exists' });
  const c = {
    id: uid(),
    code: upper,
    type,
    value: Number(value),
    label: String(label || ''),
    expires_at: expires_at || null,
    max_uses: max_uses ? Number(max_uses) : null,
    current_uses: 0,
    active: true,
    created_at: now(),
  };
  db.coupons.unshift(c);
  save();
  res.json({ ok: true, coupon: c });
});

app.delete('/api/admin/coupons/:id', requireAdmin, (req, res) => {
  db.coupons = db.coupons.filter(c => c.id !== req.params.id);
  save();
  res.json({ ok: true });
});

app.get('/api/admin/reviews', requireAdmin, (req, res) => res.json(db.reviews));

app.post('/api/admin/reviews/:id/status', requireAdmin, (req, res) => {
  const review = db.reviews.find(r => r.id === req.params.id);
  if (!review) return res.status(404).json({ error: 'not found' });
  const next = String((req.body && req.body.status) || '').toLowerCase();
  if (!['pending', 'approved', 'rejected'].includes(next)) return res.status(400).json({ error: 'bad status' });
  review.status = next;
  if (next === 'approved') review.approved_at = now();
  save();
  res.json({ ok: true, review });
});

app.post('/api/admin/reviews/:id/visibility', requireAdmin, (req, res) => {
  const review = db.reviews.find(r => r.id === req.params.id);
  if (!review) return res.status(404).json({ error: 'not found' });
  const v = String((req.body && req.body.visibility) || 'public');
  review.visibility = (v === 'private') ? 'private' : 'public';
  save();
  res.json({ ok: true, review });
});

app.delete('/api/admin/reviews/:id', requireAdmin, (req, res) => {
  db.reviews = db.reviews.filter(r => r.id !== req.params.id);
  save();
  res.json({ ok: true });
});

app.get('/api/admin/products', requireAdmin, (req, res) => res.json(db.product_overrides));

app.post('/api/admin/products/:id', requireAdmin, (req, res) => {
  const id = req.params.id;
  const { name, dose, price, image_url, active } = req.body || {};
  let entry = db.product_overrides.find(p => p.product_id === id);
  if (!entry) {
    entry = { id: uid(), product_id: id, active: true };
    db.product_overrides.push(entry);
  }
  if (name      != null) entry.name = String(name);
  if (dose      != null) entry.dose = String(dose);
  if (price     != null) entry.price = Number(price);
  if (image_url != null) entry.image_url = String(image_url);
  if (active    != null) entry.active = !!active;
  entry.updated_at = now();
  save();
  res.json({ ok: true, override: entry });
});

app.delete('/api/admin/products/:id', requireAdmin, (req, res) => {
  db.product_overrides = db.product_overrides.filter(p => p.product_id !== req.params.id);
  save();
  res.json({ ok: true });
});

app.get('/api/admin/analytics', requireAdmin, (req, res) => {
  const events = db.analytics;
  const now30 = Date.now() - 30 * 24 * 60 * 60 * 1000;
  const recent = events.filter(e => new Date(e.created_at).getTime() >= now30);

  const by = (key) => recent.reduce((m, e) => {
    const k = e[key]; if (!k) return m;
    m[k] = (m[k] || 0) + 1; return m;
  }, {});

  const events_by_type = by('event_type');
  const top_products = Object.entries(by('product_id'))
    .sort((a, b) => b[1] - a[1]).slice(0, 12)
    .map(([product_id, count]) => ({ product_id, count }));
  const pages = Object.entries(by('page'))
    .sort((a, b) => b[1] - a[1]).slice(0, 10)
    .map(([page, count]) => ({ page, count }));

  // Order summary
  const orders30 = db.orders.filter(o => new Date(o.created_at).getTime() >= now30);
  const order_revenue = orders30.filter(o => o.status === 'paid').reduce((s, o) => s + o.total, 0);

  res.json({
    last_30_days: {
      events: recent.length,
      events_by_type, top_products, top_pages: pages,
      orders_count: orders30.length,
      orders_paid: orders30.filter(o => o.status === 'paid').length,
      orders_pending: orders30.filter(o => o.status === 'pending').length,
      order_revenue,
    },
  });
});

// ---------- Public catalog (overrides + custom products) ----------
app.get('/api/catalog', (req, res) => {
  res.json({
    overrides: db.product_overrides,
    custom: db.custom_products,
  });
});

// ---------- Admin: list images in /assets/images/ for image picker ----------
app.get('/api/admin/images', requireAdmin, (req, res) => {
  const dir = path.join(ROOT, 'assets', 'images');
  try {
    const files = fs.readdirSync(dir)
      .filter(f => /\.(png|jpg|jpeg|webp|gif)$/i.test(f))
      .sort()
      .map(f => ({ name: f, url: `assets/images/${f}` }));
    res.json(files);
  } catch (e) {
    res.json([]);
  }
});

// ---------- Admin: upload an image (base64 -> /assets/images/uploads/) ----------
app.post('/api/admin/upload', requireAdmin, (req, res) => {
  const { filename, data_url } = req.body || {};
  if (!filename || !data_url) return res.status(400).json({ error: 'missing' });
  const m = String(data_url).match(/^data:image\/(png|jpe?g|webp|gif);base64,(.+)$/i);
  if (!m) return res.status(400).json({ error: 'bad data url' });
  const ext = m[1].toLowerCase().replace('jpeg', 'jpg');
  const buffer = Buffer.from(m[2], 'base64');
  if (buffer.length > 10 * 1024 * 1024) return res.status(413).json({ error: 'too large' });

  const safe = String(filename).replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 80);
  const stem = safe.replace(/\.[^.]+$/, '');
  const uploadsDir = path.join(ROOT, 'assets', 'images', 'uploads');
  if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
  const finalName = `${Date.now()}-${stem}.${ext}`;
  fs.writeFileSync(path.join(uploadsDir, finalName), buffer);
  res.json({ ok: true, url: `assets/images/uploads/${finalName}` });
});

// ---------- Admin: custom products CRUD ----------
app.post('/api/admin/custom-products', requireAdmin, (req, res) => {
  const { name, dose, price, category, description, image } = req.body || {};
  if (!name || price == null) return res.status(400).json({ error: 'missing fields' });
  const slugBase = String(name).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 24) || 'custom';
  let id = slugBase, n = 2;
  while (db.custom_products.find(p => p.id === id)) { id = `${slugBase}-${n++}`; }
  const product = {
    id,
    name: String(name),
    dose: String(dose || ''),
    price: Number(price),
    category: String(category || 'Other'),
    description: String(description || ''),
    image: String(image || ''),
    created_at: now(),
    custom: true,
  };
  db.custom_products.unshift(product);
  save();
  res.json({ ok: true, product });
});

app.delete('/api/admin/custom-products/:id', requireAdmin, (req, res) => {
  db.custom_products = db.custom_products.filter(p => p.id !== req.params.id);
  // Also drop any override for this id
  db.product_overrides = db.product_overrides.filter(o => o.product_id !== req.params.id);
  save();
  res.json({ ok: true });
});

app.get('/api/admin/custom-products', requireAdmin, (req, res) => {
  res.json(db.custom_products);
});

// ---------- Admin page server-side gate ----------
app.get(['/admin', '/admin/'], (req, res) => {
  if (req.session && req.session.adminId) {
    return res.sendFile(path.join(ROOT, 'admin', 'index.html'));
  }
  return res.sendFile(path.join(ROOT, 'admin', 'login.html'));
});

// ---------- Static files ----------
app.use(express.static(ROOT, { extensions: ['html'] }));

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`\n  Bane Performance Peptides — running\n  http://localhost:${PORT}\n  http://localhost:${PORT}/admin\n`);
});
