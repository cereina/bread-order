/*
 * Simple Node.js server for the Bread Order App with Auth and Railway support.
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const BASE_DIR = __dirname; // ✅ BASE_DIR defined first

// ===== Writable FS helpers for Railway (ephemeral FS) =====
let MEMORY_FILES = {};

function safeReadJSON(p, fallback) {
  try {
    if (MEMORY_FILES[p]) return JSON.parse(MEMORY_FILES[p]);
    if (fs.existsSync(p)) return JSON.parse(fs.readFileSync(p, 'utf-8'));
  } catch (e) {
    console.warn('Read JSON failed', p, e.message);
  }
  return fallback;
}
function safeWriteJSON(p, obj) {
  try {
    fs.writeFileSync(p, JSON.stringify(obj, null, 2));
    MEMORY_FILES[p] = null;
  } catch (e) {
    if (e && (e.code === 'EROFS' || e.code === 'EACCES')) {
      console.warn('FS not writable; storing in memory:', p);
      MEMORY_FILES[p] = JSON.stringify(obj);
    } else {
      throw e;
    }
  }
}

// ===== File paths =====
const ordersFile = path.join(BASE_DIR, 'orders.json');
const itemsFile = path.join(BASE_DIR, 'items.json');
const usersFile = path.join(BASE_DIR, 'users.json');

// ===== Auth helpers =====
const sessions = new Map();

function readUsers() {
  if (!fs.existsSync(usersFile)) {
    safeWriteJSON(usersFile, { users: [] });
  }
  const data = safeReadJSON(usersFile, { users: [] });
  data.users = data.users || [];
  return data;
}
function writeUsers(data) {
  safeWriteJSON(usersFile, data);
}
function hashPassword(password, saltHex, iter) {
  const iterations = iter || 200000;
  const salt = saltHex ? Buffer.from(saltHex, 'hex') : crypto.randomBytes(16);
  const hash = crypto.pbkdf2Sync(password, salt, iterations, 32, 'sha256');
  return { algo: 'pbkdf2_sha256', iter: iterations, salt: salt.toString('hex'), hash: hash.toString('hex') };
}
function verifyPassword(password, ph) {
  if (!ph || ph.algo !== 'pbkdf2_sha256') return false;
  const check = hashPassword(password, ph.salt, ph.iter);
  return crypto.timingSafeEqual(Buffer.from(check.hash, 'hex'), Buffer.from(ph.hash, 'hex'));
}
function parseCookies(req) {
  const header = req.headers.cookie || '';
  const cookies = {};
  header.split(';').forEach(pair => {
    const [k, v] = pair.trim().split('=');
    if (k) cookies[k] = decodeURIComponent(v || '');
  });
  return cookies;
}
function setCookie(res, name, value, opts = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  if (opts.httpOnly !== false) parts.push('HttpOnly');
  if (opts.path) parts.push(`Path=${opts.path}`); else parts.push('Path=/');
  if (opts.maxAge) parts.push(`Max-Age=${opts.maxAge}`);
  if (opts.sameSite) parts.push(`SameSite=${opts.sameSite}`); else parts.push('SameSite=Lax');
  if (opts.secure) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}
function currentUser(req) {
  const cookies = parseCookies(req);
  const tok = cookies['session'];
  if (!tok) return null;
  return sessions.get(tok) || null;
}
function requireAuth(req, res) {
  const user = currentUser(req);
  if (!user) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Unauthorized' }));
    return null;
  }
  return user;
}
function requireAdmin(req, res) {
  const user = requireAuth(req, res);
  if (!user) return null;
  if (user.role !== 'admin') {
    res.writeHead(403, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Forbidden' }));
    return null;
  }
  return user;
}
function parseBody(req, cb) {
  let body = '';
  req.on('data', chunk => body += chunk.toString());
  req.on('end', () => {
    try { cb(null, JSON.parse(body || '{}')); }
    catch { cb(new Error('Invalid JSON')); }
  });
}

// ===== Ensure default files =====
if (!fs.existsSync(ordersFile)) safeWriteJSON(ordersFile, []);
if (!fs.existsSync(itemsFile)) safeWriteJSON(itemsFile, ['Baguette', 'Whole Wheat', 'Rye', 'Sourdough']);
if (!fs.existsSync(usersFile)) {
  const pw = hashPassword('admin123');
  safeWriteJSON(usersFile, { users: [{ username: 'admin', role: 'admin', password: pw }] });
}

// ===== HTTP server =====
const server = http.createServer((req, res) => {
  const method = req.method;
  let url = req.url.split('?')[0];

  // CORS
  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    });
    res.end();
    return;
  }

  // === Auth & User management endpoints ===
  if (url === '/api/login' && method === 'POST') {
    parseBody(req, (err, body) => {
      if (err) return res.writeHead(400).end();
      const { username, password } = body;
      const data = readUsers();
      const u = data.users.find(us => us.username === username);
      if (!u || !verifyPassword(password, u.password)) {
        return res.writeHead(401, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: 'Invalid credentials' }));
      }
      const token = crypto.randomBytes(24).toString('hex');
      sessions.set(token, { username: u.username, role: u.role });
      setCookie(res, 'session', token, { httpOnly: true, path: '/' });
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ ok: true, user: { username: u.username, role: u.role } }));
    });
    return;
  }
  if (url === '/api/logout' && method === 'POST') {
    const tok = parseCookies(req)['session'];
    if (tok) sessions.delete(tok);
    setCookie(res, 'session', '', { httpOnly: true, path: '/', maxAge: 0 });
    return res.writeHead(200).end(JSON.stringify({ ok: true }));
  }
  if (url === '/api/me' && method === 'GET') {
    return res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ user: currentUser(req) }));
  }
  if (url === '/api/users' && method === 'GET') {
    if (!requireAdmin(req, res)) return;
    const list = readUsers().users.map(u => ({ username: u.username, role: u.role }));
    return res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify(list));
  }
  if (url === '/api/users' && method === 'POST') {
    if (!requireAdmin(req, res)) return;
    parseBody(req, (err, body) => {
      if (err) return res.writeHead(400).end();
      const { username, password, role } = body;
      const data = readUsers();
      if (data.users.find(u => u.username === username)) {
        return res.writeHead(409).end(JSON.stringify({ error: 'User exists' }));
      }
      data.users.push({ username, role: role === 'admin' ? 'admin' : 'user', password: hashPassword(password) });
      writeUsers(data);
      res.writeHead(201).end(JSON.stringify({ ok: true }));
    });
    return;
  }
  if (url.startsWith('/api/users/') && method === 'PUT') {
    if (!requireAdmin(req, res)) return;
    const uname = decodeURIComponent(url.split('/').pop());
    parseBody(req, (err, body) => {
      if (err) return res.writeHead(400).end();
      const data = readUsers();
      const u = data.users.find(x => x.username === uname);
      if (!u) return res.writeHead(404).end();
      if (body.password) u.password = hashPassword(body.password);
      if (body.role) u.role = body.role;
      writeUsers(data);
      res.writeHead(200).end(JSON.stringify({ ok: true }));
    });
    return;
  }
  if (url.startsWith('/api/users/') && method === 'DELETE') {
    if (!requireAdmin(req, res)) return;
    const uname = decodeURIComponent(url.split('/').pop());
    const data = readUsers();
    const idx = data.users.findIndex(x => x.username === uname);
    if (idx === -1) return res.writeHead(404).end();
    data.users.splice(idx, 1);
    writeUsers(data);
    res.writeHead(200).end(JSON.stringify({ ok: true }));
    return;
  }

  // === Orders API ===
  if (url === '/api/orders' && method === 'GET') {
    return res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify(safeReadJSON(ordersFile, [])));
  }
  if (url === '/api/orders' && method === 'POST') {
    if (!requireAuth(req, res)) return;
    parseBody(req, (err, body) => {
      if (err) return res.writeHead(400).end();
      const orders = safeReadJSON(ordersFile, []);
      orders.push({ item: body.item, qty: body.qty });
      safeWriteJSON(ordersFile, orders);
      res.writeHead(201).end(JSON.stringify(orders));
    });
    return;
  }
  if (url.startsWith('/api/orders/') && method === 'DELETE') {
    if (!requireAuth(req, res)) return;
    const idx = parseInt(url.split('/').pop());
    const orders = safeReadJSON(ordersFile, []);
    if (idx < 0 || idx >= orders.length) return res.writeHead(404).end();
    orders.splice(idx, 1);
    safeWriteJSON(ordersFile, orders);
    res.writeHead(200).end(JSON.stringify({ ok: true }));
    return;
  }

  // === Items API ===
  if (url === '/api/items' && method === 'GET') {
    return res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify(safeReadJSON(itemsFile, [])));
  }
  if (url === '/api/items' && method === 'POST') {
    if (!requireAdmin(req, res)) return;
    parseBody(req, (err, body) => {
      if (err) return res.writeHead(400).end();
      const items = safeReadJSON(itemsFile, []);
      items.push(body.name);
      safeWriteJSON(itemsFile, items);
      res.writeHead(201).end(JSON.stringify(items));
    });
    return;
  }

  // === Static files ===
  if (method === 'GET') {
    let filePath = (url === '/' ? 'index.html' : url.replace(/^\//, ''));
    filePath = path.join(BASE_DIR, filePath);
    if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
      filePath = path.join(BASE_DIR, 'index.html');
    }
    const ext = path.extname(filePath).toLowerCase();
    const types = { '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript', '.json': 'application/json' };
    res.writeHead(200, { 'Content-Type': types[ext] || 'application/octet-stream' });
    res.end(fs.readFileSync(filePath));
    return;
  }

  res.writeHead(404).end('Not Found');
});

server.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
