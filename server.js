
// server.js with authentication system
const express = require('express');
const fs = require('fs');
const cors = require('cors');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

const ORDERS_FILE = 'orders.json';
const ITEMS_FILE = 'items.json';
const USERS_FILE = 'users.json';

// Load users from file
function loadUsers() {
  return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
}

function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function findUser(username) {
  const users = loadUsers();
  return users.find(u => u.username === username);
}

// --- AUTHENTICATION ---
app.post('/api/signup', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).send('Missing credentials');
  const users = loadUsers();
  if (users.find(u => u.username === username)) {
    return res.status(400).send('User already exists');
  }
  const hashed = await bcrypt.hash(password, 12);
  users.push({ username, password: hashed, role: 'user' });
  saveUsers(users);
  res.status(201).send('User created');
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = findUser(username);
  if (!user) return res.status(401).send('Invalid user');
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).send('Invalid password');
  res.json({ username: user.username, role: user.role });
});

// --- ORDER AND ITEM API ---
app.get('/api/orders', (req, res) => {
  const orders = fs.existsSync(ORDERS_FILE) ? JSON.parse(fs.readFileSync(ORDERS_FILE)) : [];
  res.json(orders);
});

app.post('/api/orders', (req, res) => {
  const orders = fs.existsSync(ORDERS_FILE) ? JSON.parse(fs.readFileSync(ORDERS_FILE)) : [];
  orders.push(req.body);
  fs.writeFileSync(ORDERS_FILE, JSON.stringify(orders, null, 2));
  res.status(201).send('Order saved');
});

app.get('/api/items', (req, res) => {
  const items = fs.existsSync(ITEMS_FILE) ? JSON.parse(fs.readFileSync(ITEMS_FILE)) : [];
  res.json(items);
});

app.post('/api/items', (req, res) => {
  const { user, item } = req.body;
  if (!user || user.role !== 'admin') return res.status(403).send('Forbidden');
  const items = fs.existsSync(ITEMS_FILE) ? JSON.parse(fs.readFileSync(ITEMS_FILE)) : [];
  items.push(item);
  fs.writeFileSync(ITEMS_FILE, JSON.stringify(items, null, 2));
  res.status(201).send('Item added');
});

app.put('/api/items', (req, res) => {
  const { user, items } = req.body;
  if (!user || user.role !== 'admin') return res.status(403).send('Forbidden');
  fs.writeFileSync(ITEMS_FILE, JSON.stringify(items, null, 2));
  res.status(200).send('Items updated');
});

app.listen(PORT, () => {
  console.log(`Bread Order App server is running at http://localhost:${PORT}`);
});
