/*
 * Simple Node.js server for the Bread Order App — with Auth & Railway helpers.
 * Place this file next to: index.html, styles.css, items.json, orders.json, users.json
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const BASE_DIR = __dirname; // Define before use

// ===== Writable FS helpers for Railway (ephemeral / read-only at times) =====
let MEMORY_FILES = {}; // path -> stringified JSON (fallback if FS isn't writable)

function safeReadJSON(p, fallback) {
  try {
    if (MEMORY_FILES[p]) return JSON.parse(MEMORY_FILES[p]);
    if (fs.existsSync(p)) return JSON.parse(fs.readFileSync(p, 'utf-8'));
  } catch (e) {
    console.warn('Read JSON failed:', p, e.message);
  }
  return fallback;
}
function safeWriteJSON(p, obj) {
  try {
    fs.writeFileSync(p, JSON.stringify(obj, null, 2));
    MEMORY_FILES[p] = null; // clear memory copy on success
  } catch (e) {
    if (e && (e.code === 'EROFS' || e.code === 'EACCES')) {
      console.warn('FS not writable; keeping in memory for this session:', p, e.code);
      MEMORY_FILES[p] = JSON.stringify(obj);
    } else {
      console.warn('Write JSON failed:', p, e.message);
      throw e;
    }
  }
}

// ===== File paths =====
const ordersFile = path.join(BASE_DIR, 'orders.json');
const itemsFile  = path.join(BASE_DIR, 'items.json');
const usersFile  = path.join(BASE_DIR, 'users.json');

// ===== Basic JSON response helper =====
function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
  });
  res.end(body);
}

// ===== Static file helper =====
function serveStatic(filePath, res) {
  const ext = path.extname(filePath).toLowerCase();
  const map = {
    '.html': 'text/html',
    '.css': 'text/css',
    '.js': 'application/javascript',
    '.json': 'application/json',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon'
  };
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404);
      res.end('Not Found');
    } else {
      res.writeHead(200, { 'Content-Type': map[ext] || 'application/octet-stream' });
      res.end(data);
    }
  });
}
function redirect(res, location) {
  res.writeHead(302, { Location: location });
  res.end();
}

// ===== Auth helpers =====
const sessions = new Map(); // token -> { username, role }

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
  parts.push(`Path=${opts.path || '/'}`);
  if (opts.maxAge != null) parts.push(`Max-Age=${opts.maxAge}`);
  parts.push(`SameSite=${opts.sameSite || 'Lax'}`);
  if (opts.secure) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}
function currentUser(req) {
  const tok = parseCookies(req)['session'];
  if (!tok) return null;
  return sessions.get(tok) || null;
}
function requireAuth(req, res) {
  const me = currentUser(req);
  if (!me) {
    sendJson(res, 401, { error: 'Unauthorized' });
    return null;
  }
  return me;
}
function requireAdmin(req, res) {
  const me = requireAuth(req, res);
  if (!me) return null;
  if (me.role !== 'admin') {
    sendJson(res, 403, { error: 'Forbidden' });
    return null;
  }
  return me;
}
function parseBody(req, cb) {
  let body = '';
  req.on('data', chunk => body += chunk);
  req.on('end', () => {
    try { cb(null, JSON.parse(body || '{}')); }
    catch (e) { cb(e); }
  });
}

// ===== Ensure default data files =====
if (!fs.existsSync(ordersFile)) safeWriteJSON(ordersFile, []);
if (!fs.existsSync(itemsFile))  safeWriteJSON(itemsFile, ['Baguette', 'Whole Wheat', 'Rye', 'Sourdough']);
if (!fs.existsSync(usersFile)) {
  // Create a default admin so you can log in immediately
  const pw = hashPassword('admin123');
  safeWriteJSON(usersFile, { users: [{ username: 'admin', role: 'admin', password: pw }] });
}

// ===== HTTP server =====
const server = http.createServer((req, res) => {
  const method = req.method;
  let url = req.url;
  const q = url.indexOf('?');
  if (q !== -1) url = url.slice(0, q);

  // CORS preflight
  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    });
    res.end();
    return;
  }

  // ===== Auth & user management endpoints =====
  if (url === '/api/login' && method === 'POST') {
    return parseBody(req, (err, data) => {
      if (err) return sendJson(res, 400, { error: 'Invalid JSON' });
      const { username, password } = data || {};
      const users = readUsers().users;
      const u = users.find(x => x.username === username);
      if (!u || !verifyPassword(password, u.password)) {
        return sendJson(res, 401, { error: 'Invalid credentials' });
      }
      const token = crypto.randomBytes(24).toString('hex');
      sessions.set(token, { username: u.username, role: u.role });
      setCookie(res, 'session', token, { httpOnly: true, path: '/', sameSite: 'Lax' });
      return sendJson(res, 200, { ok: true, user: { username: u.username, role: u.role } });
    });
  }

  if (url === '/api/logout' && method === 'POST') {
    const tok = parseCookies(req)['session'];
    if (tok) sessions.delete(tok);
    setCookie(res, 'session', '', { httpOnly: true, path: '/', maxAge: 0, sameSite: 'Lax' });
    return sendJson(res, 200, { ok: true });
  }

  if (url === '/api/me' && method === 'GET') {
    return sendJson(res, 200, { user: currentUser(req) });
  }

  if (url === '/api/users' && method === 'GET') {
    if (!requireAdmin(req, res)) return;
    const list = readUsers().users.map(u => ({ username: u.username, role: u.role }));
    return sendJson(res, 200, list);
  }

  if (url === '/api/users' && method === 'POST') {
    if (!requireAdmin(req, res)) return;
    return parseBody(req, (err, body) => {
      if (err) return sendJson(res, 400, { error: 'Invalid JSON' });
      const { username, password, role } = body || {};
      if (!username || !password) return sendJson(res, 400, { error: 'username and password required' });
      const data = readUsers();
      if (data.users.find(u => u.username === username)) {
        return sendJson(res, 409, { error: 'User exists' });
      }
      data.users.push({ username, role: role === 'admin' ? 'admin' : 'user', password: hashPassword(password) });
      writeUsers(data);
      return sendJson(res, 201, { ok: true });
    });
  }

  if (url.startsWith('/api/users/') && method === 'PUT') {
    if (!requireAdmin(req, res)) return;
    const uname = decodeURIComponent(url.split('/').pop());
    return parseBody(req, (err, body) => {
      if (err) return sendJson(res, 400, { error: 'Invalid JSON' });
      const data = readUsers();
      const u = data.users.find(x => x.username === uname);
      if (!u) return sendJson(res, 404, { error: 'Not found' });
      if (body.password) u.password = hashPassword(body.password);
      if (body.role)     u.role     = body.role === 'admin' ? 'admin' : 'user';
      writeUsers(data);
      return sendJson(res, 200, { ok: true });
    });
  }

  if (url.startsWith('/api/users/') && method === 'DELETE') {
    if (!requireAdmin(req, res)) return;
    const uname = decodeURIComponent(url.split('/').pop());
    const data = readUsers();
    const idx = data.users.findIndex(x => x.username === uname);
    if (idx === -1) return sendJson(res, 404, { error: 'Not found' });
    data.users.splice(idx, 1);
    writeUsers(data);
    return sendJson(res, 200, { ok: true });
  }

  // ===== Orders API =====
  if (url === '/api/orders' && method === 'GET') {
    return sendJson(res, 200, safeReadJSON(ordersFile, []));
  }
  if (url === '/api/orders' && method === 'POST') {
    if (!requireAuth(req, res)) return;
    return parseBody(req, (err, body) => {
      if (err) return sendJson(res, 400, { error: 'Invalid JSON' });
      if (!body || typeof body.item !== 'string' || typeof body.qty !== 'number') {
        return sendJson(res, 400, { error: 'Invalid order format' });
      }
      const orders = safeReadJSON(ordersFile, []);
      orders.push({ item: body.item, qty: body.qty });
      safeWriteJSON(ordersFile, orders);
      return sendJson(res, 201, orders);
    });
  }
  if (url.startsWith('/api/orders/') && (method === 'PUT' || method === 'DELETE')) {
    if (!requireAuth(req, res)) return;
    const index = parseInt(url.split('/')[3], 10);
    const orders = safeReadJSON(ordersFile, []);
    if (!Number.isFinite(index) || index < 0 || index >= orders.length) {
      return sendJson(res, 404, { error: 'Order not found' });
    }
    if (method === 'DELETE') {
      orders.splice(index, 1);
      safeWriteJSON(ordersFile, orders);
      return sendJson(res, 200, { ok: true });
    }
    // PUT: update order
    return parseBody(req, (err, body) => {
      if (err) return sendJson(res, 400, { error: 'Invalid JSON' });
      if (!body || typeof body.item !== 'string' || typeof body.qty !== 'number') {
        return sendJson(res, 400, { error: 'Invalid order format' });
      }
      orders[index] = { item: body.item, qty: body.qty };
      safeWriteJSON(ordersFile, orders);
      return sendJson(res, 200, orders);
    });
  }

  // ===== Items API =====
  if (url === '/api/items' && method === 'GET') {
    return sendJson(res, 200, safeReadJSON(itemsFile, []));
  }
  if (url === '/api/items' && method === 'POST') {
    if (!requireAdmin(req, res)) return;
    return parseBody(req, (err, body) => {
      if (err) return sendJson(res, 400, { error: 'Invalid JSON' });
      if (!body || typeof body.name !== 'string') {
        return sendJson(res, 400, { error: 'Invalid item format' });
      }
      const items = safeReadJSON(itemsFile, []);
      const trimmed = body.name.trim();
      if (!trimmed || items.includes(trimmed)) {
        return sendJson(res, 400, { error: 'Item name invalid or already exists' });
      }
      items.push(trimmed);
      safeWriteJSON(itemsFile, items);
      return sendJson(res, 201, items);
    });
  }
  if (url.startsWith('/api/items/') && method === 'PUT') {
    if (!requireAdmin(req, res)) return;
    const index = parseInt(url.split('/')[3], 10);
    const items = safeReadJSON(itemsFile, []);
    if (!Number.isFinite(index) || index < 0 || index >= items.length) {
      return sendJson(res, 404, { error: 'Item not found' });
    }
    return parseBody(req, (err, body) => {
      if (err) return sendJson(res, 400, { error: 'Invalid JSON' });
      if (!body || typeof body.name !== 'string') {
        return sendJson(res, 400, { error: 'Invalid item format' });
      }
      const trimmed = body.name.trim();
      if (!trimmed) return sendJson(res, 400, { error: 'Name cannot be empty' });
      const oldName = items[index];
      if (trimmed !== oldName && items.includes(trimmed)) {
        return sendJson(res, 400, { error: 'Name already exists' });
      }
      items[index] = trimmed;
      safeWriteJSON(itemsFile, items);
      // Update orders that referenced the old item name
      if (trimmed !== oldName) {
        const orders = safeReadJSON(ordersFile, []);
        const updated = orders.map(o => o.item === oldName ? { item: trimmed, qty: o.qty } : o);
        safeWriteJSON(ordersFile, updated);
      }
      return sendJson(res, 200, items);
    });
  }

  // ===== Static files with auth gates =====
  if (method === 'GET') {
    let reqPath = url === '/' ? '/index.html' : url;
    const ext = path.extname(reqPath).toLowerCase();
    const isHTML = ext === '.html' || reqPath === '/';
    const me = currentUser(req);

    if (isHTML) {
      if (reqPath === '/login.html' && me) {
        return redirect(res, '/');
      }
      if (reqPath === '/users.html') {
        if (!me) return redirect(res, '/login.html');
        if (me.role !== 'admin') return redirect(res, '/');
      }
      if (reqPath !== '/login.html' && !me) {
        return redirect(res, '/login.html');
      }
    }

    let filePath = path.join(BASE_DIR, reqPath.replace(/^\//, ''));
    if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
      filePath = path.join(BASE_DIR, 'index.html');
    }
    serveStatic(filePath, res);
    return;
  }

  // Fallback
  res.writeHead(404);
  res.end('Not Found');
});

server.listen(PORT, () => {
  console.log(`Bread Order App server is running at http://localhost:${PORT}`);
});
