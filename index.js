'use strict';

const express  = require('express');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const https    = require('https');
const cors     = require('cors');
const path     = require('path');
const fs       = require('fs');

require('dotenv').config();

// ─────────────────────────────────────────
// CONSTANTS  (declared first — nothing references them before this)
// ─────────────────────────────────────────
const JWT_SECRET         = process.env.JWT_SECRET         || 'toolyvans_jwt_2024_change_me';
const PAYSTACK_SECRET    = process.env.PAYSTACK_SECRET_KEY || '';
const SUPPORT_SITE_PRICE = 3;   // $ per day
const RECEIPT_PRICE      = 2;   // $ per day

const PLATFORM_NAMES = {
  binance:'Binance', bybit:'Bybit', coinbase:'Coinbase',
  metamask:'MetaMask', trustwallet:'Trust Wallet', robinhood:'Robinhood',
  phantom:'Phantom', kraken:'Kraken', kucoin:'KuCoin', okx:'OKX'
};

// ─────────────────────────────────────────
// HTML FILES
// On Vercel: process.cwd() = /var/task (project root)
// Locally:   process.cwd() = wherever you ran `node`
// vercel.json includeFiles bundles public/** into the function
// ─────────────────────────────────────────
function readHtml(filename) {
  // Try multiple path strategies so it works both locally and on Vercel
  const candidates = [
    path.join(process.cwd(), 'public', filename),
    path.join(__dirname, '..', 'public', filename),
    path.join(__dirname, 'public', filename),
  ];
  for (const p of candidates) {
    try {
      if (fs.existsSync(p)) return fs.readFileSync(p, 'utf8');
    } catch (_) {}
  }
  return `<h1>500 — Could not load ${filename}</h1><p>Path candidates: ${candidates.join(', ')}</p>`;
}

// ─────────────────────────────────────────
// DATABASE  (/tmp persists across warm invocations on Vercel)
// ─────────────────────────────────────────
const DB_PATH = '/tmp/toolyvans_db.json';

function readDB() {
  try {
    if (fs.existsSync(DB_PATH))
      return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  } catch (_) {}
  return { users: [], transactions: [], generatedSites: [], generatedReceipts: [] };
}

function writeDB(db) {
  try { fs.writeFileSync(DB_PATH, JSON.stringify(db)); }
  catch (e) { console.error('DB write:', e.message); }
}

// ─────────────────────────────────────────
// PAYSTACK  (native https — no axios)
// ─────────────────────────────────────────
function paystackReq(method, apiPath, body) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : '';
    const req = https.request(
      {
        hostname: 'api.paystack.co',
        path: apiPath,
        method,
        headers: {
          'Content-Type':   'application/json',
          'Content-Length': Buffer.byteLength(payload),
          'Authorization':  `Bearer ${PAYSTACK_SECRET}`
        }
      },
      res => {
        let raw = '';
        res.on('data', c => (raw += c));
        res.on('end', () => {
          try { resolve({ status: res.statusCode, data: JSON.parse(raw) }); }
          catch (e) { reject(new Error('Paystack: non-JSON response')); }
        });
      }
    );
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

// ─────────────────────────────────────────
// EXPRESS
// ─────────────────────────────────────────
const app = express();

app.use(cors({ origin: '*', methods: ['GET','POST','OPTIONS'] }));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

// ─────────────────────────────────────────
// AUTH MIDDLEWARE
// ─────────────────────────────────────────
function auth(req, res, next) {
  const raw   = (req.headers.authorization || '');
  const token = raw.startsWith('Bearer ') ? raw.slice(7) : raw;
  if (!token) return res.status(401).json({ error: 'Unauthorized — no token' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch (_) { res.status(401).json({ error: 'Unauthorized — invalid or expired token' }); }
}

// ═══════════════════════════════════════════════════════
// AUTH
// ═══════════════════════════════════════════════════════

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name?.trim() || !email?.trim() || !password)
      return res.status(400).json({ error: 'Name, email and password are required' });
    if (password.length < 6)
      return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const db  = readDB();
    const low = email.toLowerCase().trim();
    if (db.users.find(u => u.email === low))
      return res.status(400).json({ error: 'Email already registered' });

    const user = {
      id: uuidv4(), name: name.trim(), email: low,
      password: await bcrypt.hash(password, 12),
      balance: 0, createdAt: new Date().toISOString()
    };
    db.users.push(user);
    writeDB(db);

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '14d' });
    res.status(201).json({ token, user: { id: user.id, name: user.name, email: user.email, balance: 0 } });
  } catch (e) { console.error('register:', e); res.status(500).json({ error: 'Registration failed' }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password)
      return res.status(400).json({ error: 'Email and password required' });

    const db   = readDB();
    const user = db.users.find(u => u.email === email.toLowerCase().trim());
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ error: 'Invalid email or password' });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '14d' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, balance: user.balance } });
  } catch (e) { console.error('login:', e); res.status(500).json({ error: 'Login failed' }); }
});

app.get('/api/auth/me', auth, (req, res) => {
  const db   = readDB();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ id: user.id, name: user.name, email: user.email, balance: user.balance });
});

// ═══════════════════════════════════════════════════════
// DASHBOARD
// ═══════════════════════════════════════════════════════

app.get('/api/dashboard', auth, (req, res) => {
  const db   = readDB();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const txs = db.transactions
    .filter(t => t.userId === req.user.id)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .slice(0, 50);

  const sites    = db.generatedSites.filter(s    => s.userId === req.user.id);
  const receipts = db.generatedReceipts.filter(r => r.userId === req.user.id);
  const spent    = txs.filter(t => t.amount < 0).reduce((s, t) => s + Math.abs(t.amount), 0);

  res.json({
    balance:      user.balance,
    transactions: txs,
    stats:        { sites: sites.length, receipts: receipts.length, totalSpent: +spent.toFixed(2) }
  });
});

// ═══════════════════════════════════════════════════════
// PAYSTACK
// ═══════════════════════════════════════════════════════

app.post('/api/payment/initialize', auth, async (req, res) => {
  try {
    const amount = parseFloat(req.body?.amount);
    if (!amount || amount < 5) return res.status(400).json({ error: 'Minimum deposit is $5' });

    const db   = readDB();
    const user = db.users.find(u => u.id === req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const r = await paystackReq('POST', '/transaction/initialize', {
      email:        user.email,
      amount:       Math.round(amount * 100),
      currency:     'NGN',
      reference:    'TV-' + Date.now() + '-' + uuidv4().split('-')[0],
      callback_url: process.env.APP_URL || 'https://toolyvans.vercel.app',
      metadata: { userId: user.id, depositAmountUSD: amount }
    });

    if (!r.data?.data) return res.status(500).json({ error: r.data?.message || 'Paystack init failed' });
    res.json({ authorizationUrl: r.data.data.authorization_url, reference: r.data.data.reference });
  } catch (e) { console.error('pay init:', e); res.status(500).json({ error: 'Payment init failed' }); }
});

app.post('/api/payment/verify', auth, async (req, res) => {
  try {
    const { reference } = req.body || {};
    if (!reference) return res.status(400).json({ error: 'Reference required' });

    const db   = readDB();
    const user = db.users.find(u => u.id === req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Prevent double-credit
    const dup = db.transactions.find(t => t.reference === reference && t.type === 'deposit');
    if (dup) return res.json({ success: true, balance: user.balance, amount: dup.amount, alreadyProcessed: true });

    const r = await paystackReq('GET', `/transaction/verify/${reference}`, null);
    const pd = r.data?.data;
    if (!pd || pd.status !== 'success')
      return res.status(400).json({ error: `Payment not confirmed (${pd?.status || 'unknown'})` });

    const amountUSD  = +( pd.amount / 100 ).toFixed(2);
    user.balance     = +( user.balance + amountUSD ).toFixed(2);

    const tx = {
      id: uuidv4(), userId: user.id, type: 'deposit',
      description: 'Paystack Deposit', amount: amountUSD,
      reference, status: 'success', icon: 'add_task',
      createdAt: new Date().toISOString()
    };
    db.transactions.push(tx);
    writeDB(db);
    res.json({ success: true, balance: user.balance, amount: amountUSD, transaction: tx });
  } catch (e) { console.error('pay verify:', e); res.status(500).json({ error: 'Verification failed' }); }
});

// ═══════════════════════════════════════════════════════
// TOOL 1 — SUPPORT SITE GENERATOR
// ═══════════════════════════════════════════════════════

app.post('/api/tools/support-site/generate', auth, async (req, res) => {
  try {
    const { platform, contactMethod, contactValue, chatbotCode, days } = req.body || {};

    if (!platform)      return res.status(400).json({ error: 'Platform is required' });
    if (!contactMethod) return res.status(400).json({ error: 'Contact method is required' });
    if (contactMethod !== 'chatbot' && !contactValue?.trim())
      return res.status(400).json({ error: 'Contact value is required' });
    if (contactMethod === 'chatbot' && !chatbotCode?.trim())
      return res.status(400).json({ error: 'Chatbot embed code is required' });

    const daysInt = parseInt(days, 10);
    if (!daysInt || daysInt < 1 || daysInt > 30)
      return res.status(400).json({ error: 'Duration must be 1–30 days' });

    const db   = readDB();
    const user = db.users.find(u => u.id === req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const cost = +(daysInt * SUPPORT_SITE_PRICE).toFixed(2);
    if (user.balance < cost)
      return res.status(400).json({ error: `Insufficient balance. Need $${cost}, have $${user.balance.toFixed(2)}` });

    user.balance = +(user.balance - cost).toFixed(2);

    const id  = uuidv4().replace(/-/g,'').slice(0,10);
    const plt = platform.toLowerCase();
    const slug = `${plt}-support-${id}`;

    const site = {
      id, userId: user.id, type: 'support-site', platform: plt,
      contactMethod, contactValue: contactValue?.trim() || '',
      chatbotCode: chatbotCode?.trim() || '',
      days: daysInt, totalCost: cost, slug,
      expiresAt: new Date(Date.now() + daysInt * 86400000).toISOString(),
      createdAt: new Date().toISOString(), active: true
    };
    db.generatedSites.push(site);
    db.transactions.push({
      id: uuidv4(), userId: user.id, type: 'billing',
      description: `Support Site — ${PLATFORM_NAMES[plt]||platform} (${daysInt}d)`,
      amount: -cost, reference: `SITE-${id}`,
      status: 'success', icon: 'support_agent',
      createdAt: new Date().toISOString()
    });
    writeDB(db);

    res.json({ success:true, siteId:id, slug, viewUrl:`/view/${slug}`, expiresAt:site.expiresAt, newBalance:user.balance, cost });
  } catch (e) { console.error('ss gen:', e); res.status(500).json({ error: 'Generation failed' }); }
});

app.get('/api/tools/support-site/list', auth, (req, res) => {
  const db = readDB();
  res.json({ sites: db.generatedSites.filter(s => s.userId === req.user.id)
    .sort((a,b) => new Date(b.createdAt)-new Date(a.createdAt)) });
});

// ═══════════════════════════════════════════════════════
// TOOL 2 — RECEIPT GENERATOR
// ═══════════════════════════════════════════════════════

app.post('/api/tools/receipt/generate', auth, async (req, res) => {
  try {
    const { platform, tradeType, asset, amount, price, totalValue, date, txId, walletAddress, fee, days } = req.body || {};

    if (!platform)                            return res.status(400).json({ error: 'Platform required' });
    if (!asset?.trim())                       return res.status(400).json({ error: 'Asset required' });
    if (!amount || isNaN(+amount))            return res.status(400).json({ error: 'Valid amount required' });
    if (!price  || isNaN(+price))             return res.status(400).json({ error: 'Valid price required' });
    if (!date)                                return res.status(400).json({ error: 'Trade date required' });
    if (!txId?.trim())                        return res.status(400).json({ error: 'Transaction ID required' });

    const daysInt = parseInt(days, 10);
    if (!daysInt || daysInt < 1 || daysInt > 30)
      return res.status(400).json({ error: 'Duration must be 1–30 days' });

    const db   = readDB();
    const user = db.users.find(u => u.id === req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const cost = +(daysInt * RECEIPT_PRICE).toFixed(2);
    if (user.balance < cost)
      return res.status(400).json({ error: `Insufficient balance. Need $${cost}, have $${user.balance.toFixed(2)}` });

    user.balance = +(user.balance - cost).toFixed(2);

    const id  = uuidv4().replace(/-/g,'').slice(0,10);
    const plt = platform.toLowerCase();
    const slug = `${plt}-receipt-${id}`;

    const receipt = {
      id, userId: user.id, type: 'receipt', platform: plt,
      tradeType: (tradeType||'BUY').toUpperCase(),
      asset: asset.trim().toUpperCase(),
      amount: +(+amount).toFixed(8),
      price:  +(+price).toFixed(2),
      totalValue: +(totalValue || (+amount * +price)).toFixed(2),
      date, txId: txId.trim(),
      walletAddress: walletAddress?.trim()||'',
      fee: +(+(fee||0)).toFixed(2),
      days: daysInt, totalCost: cost, slug,
      expiresAt: new Date(Date.now() + daysInt*86400000).toISOString(),
      createdAt: new Date().toISOString(), active: true
    };
    db.generatedReceipts.push(receipt);
    db.transactions.push({
      id: uuidv4(), userId: user.id, type: 'billing',
      description: `Receipt — ${PLATFORM_NAMES[plt]||platform} ${receipt.tradeType} ${receipt.asset} (${daysInt}d)`,
      amount: -cost, reference: `RCPT-${id}`,
      status: 'success', icon: 'receipt_long',
      createdAt: new Date().toISOString()
    });
    writeDB(db);

    res.json({ success:true, receiptId:id, slug, viewUrl:`/view/${slug}`, expiresAt:receipt.expiresAt, newBalance:user.balance, cost });
  } catch (e) { console.error('rg gen:', e); res.status(500).json({ error: 'Generation failed' }); }
});

app.get('/api/tools/receipt/list', auth, (req, res) => {
  const db = readDB();
  res.json({ receipts: db.generatedReceipts.filter(r => r.userId === req.user.id)
    .sort((a,b) => new Date(b.createdAt)-new Date(a.createdAt)) });
});

// ═══════════════════════════════════════════════════════
// PUBLIC VIEW  (no auth — called by view.html)
// ═══════════════════════════════════════════════════════

app.get('/api/view/:slug', (req, res) => {
  const db   = readDB();
  const slug = req.params.slug;

  const site = db.generatedSites.find(s => s.slug === slug);
  if (site) {
    if (new Date() > new Date(site.expiresAt))
      return res.status(410).json({ error:'expired', message:'This support site has expired.' });
    const { userId:_u, ...pub } = site;
    return res.json({ type:'support-site', data:pub });
  }

  const receipt = db.generatedReceipts.find(r => r.slug === slug);
  if (receipt) {
    if (new Date() > new Date(receipt.expiresAt))
      return res.status(410).json({ error:'expired', message:'This receipt has expired.' });
    const { userId:_u, ...pub } = receipt;
    return res.json({ type:'receipt', data:pub });
  }

  res.status(404).json({ error:'not_found', message:'Link not found or removed.' });
});

// ═══════════════════════════════════════════════════════
// SPA HTML ROUTES  — must be LAST
// ═══════════════════════════════════════════════════════

// /view/* → view.html
app.get('/view/*', (_req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(readHtml('view.html'));
});

// Anything else → index.html
app.get('*', (_req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(readHtml('index.html'));
});

// ═══════════════════════════════════════════════════════
// START  (only when running locally, not on Vercel)
// ═══════════════════════════════════════════════════════
if (!process.env.VERCEL) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`🚀  http://localhost:${PORT}`));
}

module.exports = app;
