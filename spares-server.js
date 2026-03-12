// ═══════════════════════════════════════════════════════
// FORCAP SPARES TRACKER — server.js
// ═══════════════════════════════════════════════════════
const express  = require('express');
const cors     = require('cors');
const path     = require('path');
const fs       = require('fs');
const crypto   = require('crypto');
const nodemailer = require('nodemailer');

const app  = express();
const PORT = process.env.PORT || 3001;

// ── Data directory ─────────────────────────────────────
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const DB = {
  read:  (f) => { try { return JSON.parse(fs.readFileSync(path.join(DATA_DIR, f), 'utf8')); } catch { return []; } },
  write: (f, d) => fs.writeFileSync(path.join(DATA_DIR, f), JSON.stringify(d, null, 2)),
};

// ── Email (Nodemailer) ─────────────────────────────────
const mailer = nodemailer.createTransport({
  host:   process.env.SMTP_HOST   || 'smtp.gmail.com',
  port:   parseInt(process.env.SMTP_PORT || '587'),
  secure: false,
  auth: {
    user: process.env.SMTP_USER || '',
    pass: process.env.SMTP_PASS || '',
  },
});

async function sendEmail(to, subject, html) {
  if (!process.env.SMTP_USER) { console.log('[email skip]', to, subject); return; }
  try {
    await mailer.sendMail({
      from: `"FORCAP Spares" <${process.env.SMTP_USER}>`,
      to, subject, html
    });
    console.log('[email sent]', to, subject);
  } catch(e) { console.error('[email error]', e.message); }
}

const APP_URL = process.env.APP_URL || 'https://spares.forcap.io';

function emailHtml(title, body, btnText, btnUrl) {
  return `
  <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#0a0d14;color:#b8c8e0;padding:32px;border-radius:8px;">
    <div style="font-size:22px;font-weight:900;color:#f5a623;margin-bottom:4px;">FORCAP SPARES</div>
    <div style="font-size:11px;color:#5a6e90;letter-spacing:2px;margin-bottom:24px;">SUPPLY CHAIN TRACKER</div>
    <div style="font-size:16px;font-weight:700;color:#e8f0ff;margin-bottom:16px;">${title}</div>
    <div style="font-size:14px;line-height:1.8;margin-bottom:24px;">${body}</div>
    ${btnText && btnUrl ? `<a href="${btnUrl}" style="display:inline-block;background:#f5a623;color:#000;font-weight:700;padding:12px 28px;border-radius:6px;text-decoration:none;font-size:14px;">${btnText}</a>` : ''}
    <div style="margin-top:32px;font-size:11px;color:#5a6e90;">This is an automated notification from FORCAP Spares Tracker.</div>
  </div>`;
}

// ── CORS ───────────────────────────────────────────────
app.use(cors({
  origin: [
    'https://spares.forcap.io',
    'https://forcap.io',
    'https://maride.onrender.com',
    /\.forcap\.io$/,
    /\.onrender\.com$/,
    'http://localhost:3000',
    'http://localhost:3001',
  ],
  credentials: true,
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

// ── Auth middleware ────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'spares-secret-2026';

function generateToken(user) {
  const payload = Buffer.from(JSON.stringify({
    id: user.id, email: user.email, name: user.name,
    role: user.role, iat: Date.now()
  })).toString('base64');
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(payload).digest('hex');
  return `${payload}.${sig}`;
}

function verifyToken(token) {
  try {
    const [payload, sig] = token.split('.');
    const expected = crypto.createHmac('sha256', JWT_SECRET).update(payload).digest('hex');
    if (sig !== expected) return null;
    return JSON.parse(Buffer.from(payload, 'base64').toString('utf8'));
  } catch { return null; }
}

function requireAuth(req, res, next) {
  const token = req.headers['x-auth-token'] || req.query.token;
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  const user = verifyToken(token);
  if (!user) return res.status(401).json({ error: 'Invalid token' });
  req.user = user;
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Insufficient permissions' });
    next();
  };
}

// ── Seed admin user ────────────────────────────────────
function seedAdmin() {
  const users = DB.read('spares_users.json');
  if (!users.find(u => u.role === 'admin')) {
    const admin = {
      id: 'user_admin',
      email: process.env.ADMIN_EMAIL || 'admin@forcap.io',
      password: process.env.ADMIN_PASSWORD || 'admin123',
      name: 'System Administrator',
      role: 'admin',
      created_at: new Date().toISOString(),
    };
    users.push(admin);
    DB.write('spares_users.json', users);
    console.log('[seed] Admin user created:', admin.email);
  }
}
seedAdmin();

// ═══════════════════════════════════════════════════════
// AUTH ROUTES
// ═══════════════════════════════════════════════════════

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const users = DB.read('spares_users.json');
  const user = users.find(u => u.email?.toLowerCase() === email?.toLowerCase() && u.password === password);
  if (!user) return res.status(401).json({ error: 'Invalid email or password' });
  const token = generateToken(user);
  res.json({ token, user: { id: user.id, email: user.email, name: user.name, role: user.role, vessel: user.vessel } });
});

// Magic link login for external parties (supplier/agent)
app.post('/api/auth/magic-request', async (req, res) => {
  const { email, indent_id } = req.body;
  const users = DB.read('spares_users.json');
  const user = users.find(u => u.email?.toLowerCase() === email?.toLowerCase());
  if (!user) return res.status(404).json({ error: 'Email not registered' });

  const token = generateToken({ ...user, magic: true });
  const link = `${APP_URL}?magic=${encodeURIComponent(token)}&indent=${indent_id || ''}`;

  await sendEmail(user.email, 'Your FORCAP Spares login link',
    emailHtml('Login to FORCAP Spares', `Click the button below to access your orders. This link is valid for 24 hours.`, 'ACCESS MY ORDERS', link)
  );
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════
// USER MANAGEMENT
// ═══════════════════════════════════════════════════════

app.get('/api/users', requireAuth, (req, res) => {
  const users = DB.read('spares_users.json');
  res.json(users.map(u => ({ id: u.id, email: u.email, name: u.name, role: u.role, vessel: u.vessel, company: u.company })));
});

app.post('/api/users', requireAuth, requireRole('admin', 'superintendent'), (req, res) => {
  const users = DB.read('spares_users.json');
  const { email, name, role, vessel, company, password } = req.body;
  if (users.find(u => u.email?.toLowerCase() === email?.toLowerCase())) {
    return res.status(400).json({ error: 'Email already exists' });
  }
  const user = {
    id: 'user_' + Date.now().toString(36),
    email, name, role, vessel: vessel || '', company: company || '',
    password: password || crypto.randomBytes(6).toString('hex'),
    created_at: new Date().toISOString(),
  };
  users.push(user);
  DB.write('spares_users.json', users);
  res.json(user);
});

app.put('/api/users/:id', requireAuth, requireRole('admin', 'superintendent'), (req, res) => {
  const users = DB.read('spares_users.json');
  const idx = users.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'User not found' });
  users[idx] = { ...users[idx], ...req.body, id: users[idx].id };
  DB.write('spares_users.json', users);
  res.json(users[idx]);
});

app.delete('/api/users/:id', requireAuth, requireRole('admin'), (req, res) => {
  const users = DB.read('spares_users.json');
  const filtered = users.filter(u => u.id !== req.params.id);
  DB.write('spares_users.json', filtered);
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════
// VESSELS
// ═══════════════════════════════════════════════════════

app.get('/api/vessels', requireAuth, (req, res) => {
  let vessels = DB.read('spares_vessels.json');
  if (!vessels.length) {
    vessels = [
      { id: 'v1', name: 'Alfred Temile', imo: '9859882', type: 'LPG' },
      { id: 'v2', name: 'LNG Port Harcourt 2', imo: '', type: 'LNG' },
    ];
    DB.write('spares_vessels.json', vessels);
  }
  res.json(vessels);
});

app.post('/api/vessels', requireAuth, requireRole('admin', 'superintendent'), (req, res) => {
  const vessels = DB.read('spares_vessels.json');
  const vessel = { id: 'v_' + Date.now().toString(36), ...req.body, created_at: new Date().toISOString() };
  vessels.push(vessel);
  DB.write('spares_vessels.json', vessels);
  res.json(vessel);
});

// ═══════════════════════════════════════════════════════
// INDENTS
// ═══════════════════════════════════════════════════════

const STATUSES = [
  'indent_raised',    // vessel
  'approved',         // superintendent
  'po_issued',        // C&P
  'acknowledged',     // supplier
  'ets_set',          // supplier (estimated time of shipment)
  'shipped',          // supplier
  'picked_up',        // agent
  'in_transit',       // agent
  'under_clearance',  // agent
  'at_warehouse',     // agent
  'delivered',        // agent
  'received',         // vessel
];

const STATUS_LABELS = {
  indent_raised:   'Indent Raised',
  approved:        'Approved',
  po_issued:       'PO Issued',
  acknowledged:    'Acknowledged by Supplier',
  ets_set:         'ETS Confirmed',
  shipped:         'Shipped',
  picked_up:       'Picked Up',
  in_transit:      'In Transit',
  under_clearance: 'Under Customs Clearance',
  at_warehouse:    'At Local Warehouse',
  delivered:       'Delivered to Vessel',
  received:        'Received & Closed',
};

const STATUS_ROLE = {
  approved:        ['superintendent', 'admin'],
  po_issued:       ['procurement', 'admin'],
  acknowledged:    ['supplier', 'admin'],
  ets_set:         ['supplier', 'admin'],
  shipped:         ['supplier', 'admin'],
  picked_up:       ['agent', 'admin'],
  in_transit:      ['agent', 'admin'],
  under_clearance: ['agent', 'admin'],
  at_warehouse:    ['agent', 'admin'],
  delivered:       ['agent', 'admin'],
  received:        ['vessel', 'admin', 'superintendent'],
};

// Email notifications per status transition
async function notifyStatusChange(indent, newStatus, actor, note) {
  const users = DB.read('spares_users.json');
  const vessels = DB.read('spares_vessels.json');
  const vessel = vessels.find(v => v.id === indent.vessel_id);
  const vName = vessel?.name || indent.vessel_name || 'Vessel';
  const label = STATUS_LABELS[newStatus] || newStatus;

  const baseInfo = `
    <strong>Indent:</strong> ${indent.indent_number}<br>
    <strong>Vessel:</strong> ${vName}<br>
    <strong>Description:</strong> ${indent.description}<br>
    <strong>Status:</strong> ${label}<br>
    ${note ? `<strong>Note:</strong> ${note}<br>` : ''}
    <strong>Updated by:</strong> ${actor}<br>
  `;

  const indentUrl = `${APP_URL}?indent=${indent.id}`;

  const notify = async (email, subject, extraInfo) => {
    if (!email) return;
    await sendEmail(email, subject,
      emailHtml(subject, baseInfo + (extraInfo || ''), 'VIEW ORDER', indentUrl)
    );
  };

  // Find supers and C&P
  const supers = users.filter(u => ['superintendent', 'admin'].includes(u.role)).map(u => u.email).filter(Boolean);
  const cp     = users.filter(u => u.role === 'procurement').map(u => u.email).filter(Boolean);

  switch(newStatus) {
    case 'approved':
      for (const e of cp) await notify(e, `PO Required — ${indent.indent_number}`, '<br>Please issue PO for this approved indent.');
      break;
    case 'po_issued':
      if (indent.supplier_email) await notify(indent.supplier_email, `New Purchase Order — ${indent.po_number || indent.indent_number}`,
        `<br><strong>PO Number:</strong> ${indent.po_number || '—'}<br>Please acknowledge receipt of this order.`);
      break;
    case 'shipped':
      if (indent.agent_email) await notify(indent.agent_email, `Shipment Dispatched — ${indent.indent_number}`,
        `<br><strong>AWB/BL:</strong> ${indent.awb_number || '—'}<br><strong>ETA:</strong> ${indent.eta || '—'}<br>Please update status when shipment arrives.`);
      for (const e of supers) await notify(e, `Shipped — ${indent.indent_number}`, '');
      break;
    case 'delivered':
      const vesselUsers = users.filter(u => u.role === 'vessel' && u.vessel === indent.vessel_id).map(u => u.email).filter(Boolean);
      for (const e of vesselUsers) await notify(e, `Spares Delivered — ${indent.indent_number}`, '<br>Please confirm receipt of spares.');
      for (const e of supers) await notify(e, `Delivered — ${indent.indent_number}`, '');
      break;
    case 'received':
      for (const e of supers) await notify(e, `Received & Closed — ${indent.indent_number}`, '');
      break;
    default:
      for (const e of supers) await notify(e, `${label} — ${indent.indent_number}`, '');
  }
}

// GET all indents
app.get('/api/indents', requireAuth, (req, res) => {
  let indents = DB.read('spares_indents.json');
  const u = req.user;

  // Filter by role
  if (u.role === 'vessel') indents = indents.filter(i => i.vessel_id === u.vessel || i.created_by === u.id);
  if (u.role === 'supplier') indents = indents.filter(i => i.supplier_email?.toLowerCase() === u.email?.toLowerCase());
  if (u.role === 'agent') indents = indents.filter(i => i.agent_email?.toLowerCase() === u.email?.toLowerCase());

  // Filter by vessel
  if (req.query.vessel_id) indents = indents.filter(i => i.vessel_id === req.query.vessel_id);
  if (req.query.status) indents = indents.filter(i => i.status === req.query.status);

  // Sort newest first
  indents.sort((a,b) => new Date(b.created_at) - new Date(a.created_at));
  res.json(indents);
});

// GET single indent
app.get('/api/indents/:id', requireAuth, (req, res) => {
  const indents = DB.read('spares_indents.json');
  const indent = indents.find(i => i.id === req.params.id);
  if (!indent) return res.status(404).json({ error: 'Not found' });
  res.json(indent);
});

// POST create indent (vessel)
app.post('/api/indents', requireAuth, async (req, res) => {
  const indents = DB.read('spares_indents.json');
  const indent = {
    id: 'ind_' + Date.now().toString(36),
    indent_number: req.body.indent_number || ('IND-' + Date.now().toString().slice(-6)),
    vessel_id: req.body.vessel_id,
    vessel_name: req.body.vessel_name || '',
    description: req.body.description || '',
    items: req.body.items || [],
    priority: req.body.priority || 'normal',
    required_by: req.body.required_by || '',
    remarks: req.body.remarks || '',
    status: 'indent_raised',
    po_number: '',
    supplier_name: req.body.supplier_name || '',
    supplier_email: req.body.supplier_email || '',
    agent_name: req.body.agent_name || '',
    agent_email: req.body.agent_email || '',
    awb_number: '',
    etd: '', eta: '',
    tracking_url: '',
    documents: [],
    timeline: [{
      status: 'indent_raised',
      label: STATUS_LABELS['indent_raised'],
      by: req.user.name || req.user.email,
      at: new Date().toISOString(),
      note: req.body.remarks || '',
    }],
    created_by: req.user.id,
    created_by_name: req.user.name || req.user.email,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };
  indents.push(indent);
  DB.write('spares_indents.json', indents);

  // Notify superintendents
  const users = DB.read('spares_users.json');
  const supers = users.filter(u => ['superintendent','admin'].includes(u.role)).map(u => u.email).filter(Boolean);
  for (const e of supers) {
    await sendEmail(e, `New Indent — ${indent.indent_number}`,
      emailHtml(`New Indent Raised — ${indent.indent_number}`,
        `<strong>Vessel:</strong> ${indent.vessel_name}<br><strong>Description:</strong> ${indent.description}<br><strong>Priority:</strong> ${indent.priority}<br><strong>Raised by:</strong> ${indent.created_by_name}`,
        'REVIEW & APPROVE', `${APP_URL}?indent=${indent.id}`
      )
    );
  }
  res.json(indent);
});

// PATCH update indent status
app.patch('/api/indents/:id/status', requireAuth, async (req, res) => {
  const indents = DB.read('spares_indents.json');
  const idx = indents.findIndex(i => i.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });

  const { status, note, ...extraFields } = req.body;
  const allowed = STATUS_ROLE[status];
  if (allowed && !allowed.includes(req.user.role)) {
    return res.status(403).json({ error: `Only ${allowed.join('/')} can set status to ${status}` });
  }

  const indent = indents[idx];
  Object.assign(indent, extraFields);
  indent.status = status;
  indent.updated_at = new Date().toISOString();
  indent.timeline = indent.timeline || [];
  indent.timeline.push({
    status, label: STATUS_LABELS[status] || status,
    by: req.user.name || req.user.email,
    at: new Date().toISOString(),
    note: note || '',
    ...Object.keys(extraFields).length ? { fields: extraFields } : {},
  });

  DB.write('spares_indents.json', indents);
  await notifyStatusChange(indent, status, req.user.name || req.user.email, note);
  res.json(indent);
});

// PATCH update indent fields (supplier/agent details, etc.)
app.patch('/api/indents/:id', requireAuth, (req, res) => {
  const indents = DB.read('spares_indents.json');
  const idx = indents.findIndex(i => i.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  Object.assign(indents[idx], req.body, { updated_at: new Date().toISOString() });
  DB.write('spares_indents.json', indents);
  res.json(indents[idx]);
});

// DELETE indent (admin only)
app.delete('/api/indents/:id', requireAuth, requireRole('admin'), (req, res) => {
  const indents = DB.read('spares_indents.json');
  DB.write('spares_indents.json', indents.filter(i => i.id !== req.params.id));
  res.json({ ok: true });
});

// ── Document upload (base64) ───────────────────────────
app.post('/api/indents/:id/documents', requireAuth, (req, res) => {
  const indents = DB.read('spares_indents.json');
  const idx = indents.findIndex(i => i.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  const doc = {
    id: 'doc_' + Date.now().toString(36),
    name: req.body.name,
    type: req.body.type, // invoice, awb, packing_list, delivery_note, other
    data: req.body.data, // base64
    uploaded_by: req.user.name || req.user.email,
    uploaded_at: new Date().toISOString(),
  };
  indents[idx].documents = indents[idx].documents || [];
  indents[idx].documents.push(doc);
  indents[idx].updated_at = new Date().toISOString();
  DB.write('spares_indents.json', indents);
  res.json(doc);
});

// ── Stats / dashboard ──────────────────────────────────
app.get('/api/stats', requireAuth, (req, res) => {
  const indents = DB.read('spares_indents.json');
  const byStatus = {};
  STATUSES.forEach(s => byStatus[s] = 0);
  indents.forEach(i => { if (byStatus[i.status] !== undefined) byStatus[i.status]++; });
  res.json({
    total: indents.length,
    open: indents.filter(i => i.status !== 'received').length,
    closed: indents.filter(i => i.status === 'received').length,
    byStatus,
    overdue: indents.filter(i => i.required_by && new Date(i.required_by) < new Date() && i.status !== 'received').length,
  });
});

app.listen(PORT, () => console.log(`FORCAP Spares running on port ${PORT}`));
