/*
 * Simple Node.js server for the Bread Order App.
 *
 * This server serves the static files that make up the Progressive Web App
 * (HTML, CSS, JS, manifest and icons) and exposes a tiny REST API for
 * managing orders and available bread items. Orders and items are
 * persisted to JSON files so that multiple users sharing the same
 * application instance can see a shared list of orders.
 *
 * Endpoints:
 *   GET  /api/orders           → returns the array of current orders
 *   POST /api/orders           → expects { item: string, qty: number }; adds a new order
 *   PUT  /api/orders/:index    → expects { item: string, qty: number }; updates order at index
 *   DELETE /api/orders/:index  → deletes the order at index
 *
 *   GET  /api/items            → returns the array of available bread items
 *   POST /api/items            → expects { name: string }; adds a new item
 *   PUT  /api/items/:index     → expects { name: string }; renames the item at index and updates
 *                                any orders that reference the old name
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const BASE_DIR = __dirname; // bread_order_app directory

const ordersFile = path.join(BASE_DIR, 'orders.json');
const itemsFile = path.join(BASE_DIR, 'items.json');

/**
 * Read JSON data from a file. If the file doesn't exist, return the
 * provided default value. If parsing fails, an empty array or
 * defaultValue is returned.
 *
 * @param {string} filename
 * @param {any} defaultValue
 * @returns {any}
 */
function readJson(filename, defaultValue) {
  try {
    if (fs.existsSync(filename)) {
      const data = fs.readFileSync(filename, 'utf8');
      return JSON.parse(data);
    }
  } catch (err) {
    console.error(`Error reading ${filename}:`, err);
  }
  return defaultValue;
}

/**
 * Write JSON data to a file. If writing fails, logs the error.
 *
 * @param {string} filename
 * @param {any} data
 */
function writeJson(filename, data) {
  try {
    fs.writeFileSync(filename, JSON.stringify(data, null, 2), 'utf8');
  } catch (err) {
    console.error(`Error writing ${filename}:`, err);
  }
}

/**
 * Ensure that the JSON files exist with sensible defaults on server start.
 */
function ensureDataFiles() {
  if (!fs.existsSync(ordersFile)) {
    writeJson(ordersFile, []);
  }
  if (!fs.existsSync(itemsFile)) {
    writeJson(itemsFile, ['Baguette', 'Whole Wheat', 'Rye', 'Sourdough']);
  }
}

ensureDataFiles();

/**
 * Send a JSON response with the given status code and object.
 * @param {http.ServerResponse} res
 * @param {number} status
 * @param {any} obj
 */
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

/**
 * Serve a static file from the app directory. Sets a basic content type
 * based on the file extension. If the file is not found, returns 404.
 *
 * @param {string} filePath
 * @param {http.ServerResponse} res
 */
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
      const contentType = map[ext] || 'application/octet-stream';
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(data);
    }
  });
}

const server = http.createServer((req, res) => {
  const method = req.method;
  let url = req.url;
  // Strip query string if present
  const queryIndex = url.indexOf('?');
  if (queryIndex !== -1) {
    url = url.slice(0, queryIndex);
  }

  // Handle preflight CORS request
  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    });
    res.end();
    return;
  }

  // API routes
  if (url === '/api/orders') {
    if (method === 'GET') {
      const orders = readJson(ordersFile, []);
      sendJson(res, 200, orders);
      return;
    } else if (method === 'POST') {
      let body = '';
      req.on('data', chunk => {
        body += chunk.toString();
      });
      req.on('end', () => {
        try {
          const data = JSON.parse(body);
          if (!data || typeof data.item !== 'string' || typeof data.qty !== 'number') {
            sendJson(res, 400, { error: 'Invalid order format' });
            return;
          }
          const orders = readJson(ordersFile, []);
          orders.push({ item: data.item, qty: data.qty });
          writeJson(ordersFile, orders);
          sendJson(res, 201, orders);
        } catch (err) {
          sendJson(res, 400, { error: 'Invalid JSON' });
        }
      });
      return;
    }
  }
  if (url.startsWith('/api/orders/') && ['PUT', 'DELETE'].includes(method)) {
    const parts = url.split('/');
    const index = parseInt(parts[3], 10);
    if (isNaN(index)) {
      sendJson(res, 400, { error: 'Invalid index' });
      return;
    }
    const orders = readJson(ordersFile, []);
    if (index < 0 || index >= orders.length) {
      sendJson(res, 404, { error: 'Order not found' });
      return;
    }
    if (method === 'DELETE') {
      orders.splice(index, 1);
      writeJson(ordersFile, orders);
      sendJson(res, 200, { success: true });
      return;
    }
    // PUT: update order
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        if (!data || typeof data.item !== 'string' || typeof data.qty !== 'number') {
          sendJson(res, 400, { error: 'Invalid order format' });
          return;
        }
        orders[index] = { item: data.item, qty: data.qty };
        writeJson(ordersFile, orders);
        sendJson(res, 200, orders);
      } catch (err) {
        sendJson(res, 400, { error: 'Invalid JSON' });
      }
    });
    return;
  }
  // API routes for items
  if (url === '/api/items') {
    if (method === 'GET') {
      const items = readJson(itemsFile, []);
      sendJson(res, 200, items);
      return;
    } else if (method === 'POST') {
      let body = '';
      req.on('data', chunk => {
        body += chunk.toString();
      });
      req.on('end', () => {
        try {
          const data = JSON.parse(body);
          if (!data || typeof data.name !== 'string') {
            sendJson(res, 400, { error: 'Invalid item format' });
            return;
          }
          const items = readJson(itemsFile, []);
          const trimmed = data.name.trim();
          if (!trimmed || items.includes(trimmed)) {
            sendJson(res, 400, { error: 'Item name invalid or already exists' });
            return;
          }
          items.push(trimmed);
          writeJson(itemsFile, items);
          sendJson(res, 201, items);
        } catch (err) {
          sendJson(res, 400, { error: 'Invalid JSON' });
        }
      });
      return;
    }
  }
  if (url.startsWith('/api/items/') && method === 'PUT') {
    const parts = url.split('/');
    const index = parseInt(parts[3], 10);
    if (isNaN(index)) {
      sendJson(res, 400, { error: 'Invalid index' });
      return;
    }
    const items = readJson(itemsFile, []);
    if (index < 0 || index >= items.length) {
      sendJson(res, 404, { error: 'Item not found' });
      return;
    }
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        if (!data || typeof data.name !== 'string') {
          sendJson(res, 400, { error: 'Invalid item format' });
          return;
        }
        const trimmed = data.name.trim();
        if (!trimmed) {
          sendJson(res, 400, { error: 'Name cannot be empty' });
          return;
        }
        // Check if name already exists (except when same as old)
        const oldName = items[index];
        if (trimmed !== oldName && items.includes(trimmed)) {
          sendJson(res, 400, { error: 'Name already exists' });
          return;
        }
        items[index] = trimmed;
        writeJson(itemsFile, items);
        // If changed, update orders referencing old name
        if (trimmed !== oldName) {
          const orders = readJson(ordersFile, []);
          const updated = orders.map(order => order.item === oldName ? { item: trimmed, qty: order.qty } : order);
          writeJson(ordersFile, updated);
        }
        sendJson(res, 200, items);
      } catch (err) {
        sendJson(res, 400, { error: 'Invalid JSON' });
      }
    });
    return;
  }
  // Static files: default to index.html for root or unknown paths
  // For root or path without extension, serve index.html for SPA routing
  if (method === 'GET') {
    // Determine file to serve
    let filePath = '';
    if (url === '/' || url === '') {
      filePath = path.join(BASE_DIR, 'index.html');
    } else {
      // Remove leading slash
      const relativePath = url.replace(/^\//, '');
      filePath = path.join(BASE_DIR, relativePath);
    }
    // If the file exists and is within our directory, serve it; otherwise serve index.html
    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      serveStatic(filePath, res);
    } else {
      serveStatic(path.join(BASE_DIR, 'index.html'), res);
    }
    return;
  }
  // If none of the above matched, return 404
  res.writeHead(404);
  res.end('Not Found');
});

server.listen(PORT, () => {
  console.log(`Bread Order App server is running at http://localhost:${PORT}`);
});