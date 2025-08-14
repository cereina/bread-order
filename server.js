
const express = require('express');
const fs = require('fs');
const bcrypt = require('bcrypt');
const path = require('path');
const bodyParser = require('body-parser');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.json());
app.use(express.static('public'));

let orders = [];
let items = ['Pain Libanais', 'Manakish Zaatar', 'Pain complet'];

function readUsers() {
  try {
    const data = fs.readFileSync('users.json', 'utf8');
    return JSON.parse(data);
  } catch (err) {
    return [];
  }
}

function saveUsers(users) {
  fs.writeFileSync('users.json', JSON.stringify(users, null, 2));
}

app.post('/signup', async (req, res) => {
  const { username, password } = req.body;
  const users = readUsers();
  if (users.find(user => user.username === username)) {
    return res.json({ success: false, message: 'User already exists' });
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, password: hashedPassword, role: 'user' });
  saveUsers(users);
  res.json({ success: true, message: 'User created' });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const users = readUsers();
  const user = users.find(u => u.username === username);
  if (!user) return res.json({ success: false, message: 'User not found' });
  const valid = await bcrypt.compare(password, user.password);
  if (valid) {
    res.json({ success: true, role: user.role });
  } else {
    res.json({ success: false, message: 'Invalid credentials' });
  }
});

app.get('/items', (req, res) => res.json(items));

app.post('/add-item', (req, res) => {
  const { item } = req.body;
  items.push(item);
  res.json({ success: true });
});

app.delete('/delete-item/:index', (req, res) => {
  const index = parseInt(req.params.index);
  items.splice(index, 1);
  res.json({ success: true });
});

app.post('/add-order', (req, res) => {
  const { item, quantity } = req.body;
  orders.push({ item, quantity });
  res.json({ success: true });
});

app.get('/orders', (req, res) => res.json(orders));

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
