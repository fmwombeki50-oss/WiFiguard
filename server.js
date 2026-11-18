const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public'))); // weka index.html kwenye folda ya "public"

const ADMIN_PIN = process.env.ADMIN_PIN || '1234';
const SECRET = process.env.SECRET || 'badilisha-hii';
const WEBHOOK_KEY = process.env.WEBHOOK_KEY || 'badilisha-hii-pia';
const DB_FILE = path.join(__dirname, 'db.json');

const PACKAGES = [
  { id: 'h1', name: 'Saa 1', seconds: 3600, price: 500 },
  { id: 'h6', name: 'Saa 6', seconds: 21600, price: 1500 },
  { id: 'd1', name: 'Siku 1', seconds: 86400, price: 2500 },
  { id: 'w1', name: 'Wiki 1', seconds: 604800, price: 12000 },
];

// ---------- Database (faili la JSON) ----------
let db = { nextId: 1, customers: [] };
try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (e) {}
const save = () => { try { fs.writeFileSync(DB_FILE, JSON.stringify(db)); } catch (e) {} };
const find = (id) => db.customers.find((c) => c.id === Number(id));

// ---------- Admin token (iliyosainiwa) ----------
const sign = (p) => crypto.createHmac('sha256', SECRET).update(p).digest('hex');
const makeToken = () => { const exp = Date.now() + 12 * 3600e3; return exp + '.' + sign(String(exp)); };
const validToken = (t = '') => {
  const [exp, sig] = t.split('.');
  return exp && sig && Number(exp) > Date.now() && sign(exp) === sig;
};
const adminOnly = (req, res, next) =>
  validToken((req.headers.authorization || '').replace('Bearer ', ''))
    ? next() : res.status(401).json({ error: 'Hairuhusiwi' });

// ---------- Kudhibiti mtandao (router) ----------
// Hapa ndipo unaunganisha router yako. Mfano: MikroTik API au captive portal.
// action: 'allow' | 'deny'
function enforce(customer, action) {
  console.log(`[ENFORCE] ${action} -> ${customer.phone} (${customer.deviceIds.join(',')})`);
  // TODO: tuma amri kwa router, mfano allow/deny kwa MAC address ya kifaa
}

// ---------- Njia za mteja ----------
app.get('/api/packages', (req, res) => res.json(PACKAGES));

app.post('/api/pay', (req, res) => {
  const { phone, packageId, method, deviceId } = req.body;
  const pk = PACKAGES.find((p) => p.id === packageId);
  if (!pk || !phone || String(phone).length < 9) return res.status(400).json({ error: 'Taarifa si sahihi' });
  const c = {
    id: db.nextId++, phone, package: pk.name, seconds: pk.seconds, price: pk.price,
    method: method || 'cash', status: 'pending', left: pk.seconds,
    deviceIds: deviceId ? [deviceId] : [], theft: false, createdAt: Date.now(),
  };
  db.customers.push(c); save();
  res.json({ id: c.id, status: c.status }); // malipo ya simu yakithibitishwa kupitia webhook, cash kupitia admin
});

app.get('/api/status/:id', (req, res) => {
  const c = find(req.params.id);
  if (!c) return res.status(404).json({ error: 'Hajapatikana' });
  // Password ya WiFi HAITUMWI kamwe kwa mteja
  res.json({ id: c.id, package: c.package, status: c.status, left: c.left });
});

// Simu ya mteja hutuma kila dakika: inatambua vifaa vingi (hotspot sharing)
app.post('/api/heartbeat', (req, res) => {
  const c = find(req.body.id);
  if (!c) return res.status(404).json({ error: 'Hajapatikana' });
  const dev = req.body.deviceId;
  if (dev && !c.deviceIds.includes(dev)) c.deviceIds.push(dev);
  if (c.status === 'active' && c.deviceIds.length > 1) {
    c.theft = true; c.status = 'blocked'; enforce(c, 'deny');
  }
  save();
  res.json({ status: c.status, left: c.left });
});

// ---------- Webhook ya malipo ya simu (M-Pesa/Airtel/Tigo via Selcom, AzamPay n.k.) ----------
app.post('/api/webhook/payment', (req, res) => {
  if (req.headers['x-webhook-key'] !== WEBHOOK_KEY) return res.status(401).end();
  const c = find(req.body.customerId);
  if (c && req.body.status === 'success' && c.status === 'pending') {
    c.status = 'active'; enforce(c, 'allow'); save();
  }
  res.json({ ok: true });
});

// ---------- Njia za admin ----------
app.post('/api/admin/login', (req, res) =>
  req.body.pin === ADMIN_PIN ? res.json({ token: makeToken() }) : res.status(401).json({ error: 'PIN si sahihi' }));

app.get('/api/admin/stats', adminOnly, (req, res) => {
  const cs = db.customers;
  res.json({
    active: cs.filter((c) => c.status === 'active').length,
    thieves: cs.filter((c) => c.theft).length,
    revenue: cs.filter((c) => c.status !== 'pending').reduce((s, c) => s + c.price, 0),
    total: cs.length,
  });
});

app.get('/api/admin/customers', adminOnly, (req, res) => res.json(db.customers.slice().reverse()));

app.post('/api/admin/approve/:id', adminOnly, (req, res) => {
  const c = find(req.params.id); if (!c) return res.status(404).end();
  c.status = 'active'; enforce(c, 'allow'); save(); res.json(c);
});
app.post('/api/admin/block/:id', adminOnly, (req, res) => {
  const c = find(req.params.id); if (!c) return res.status(404).end();
  c.status = 'blocked'; enforce(c, 'deny'); save(); res.json(c);
});
app.post('/api/admin/unblock/:id', adminOnly, (req, res) => {
  const c = find(req.params.id); if (!c) return res.status(404).end();
  c.theft = false; c.deviceIds = c.deviceIds.slice(0, 1);
  c.status = c.left > 0 ? 'active' : 'expired';
  if (c.status === 'active') enforce(c, 'allow');
  save(); res.json(c);
});
app.post('/api/admin/scan', adminOnly, (req, res) => {
  let n = 0;
  db.customers.forEach((c) => {
    if (c.status === 'active' && c.deviceIds.length > 1) { c.status = 'blocked'; c.theft = true; enforce(c, 'deny'); n++; }
  });
  save(); res.json({ blocked: n });
});

// ---------- Kuhesabu muda na kuzuia kiotomatiki ----------
setInterval(() => {
  let changed = false;
  db.customers.forEach((c) => {
    if (c.status === 'active') {
      c.left -= 5;
      if (c.left <= 0) { c.left = 0; c.status = 'expired'; enforce(c, 'deny'); }
      changed = true;
    }
  });
  if (changed) save();
}, 5000);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Kimali server inafanya kazi port ' + PORT));
