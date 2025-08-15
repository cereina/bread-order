const express = require("express");
const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = path.join(__dirname, "bread.db");

app.use(express.json());
app.use(express.static("public"));

// Initialize SQLite database
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) return console.error("DB Error:", err.message);
  console.log("Connected to SQLite database.");
});

// Create tables if they don't exist
db.serialize(() => {
  db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT)");
  db.run("CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, name TEXT)");
  db.run("CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY, item TEXT, quantity INTEGER)");
});

// Signup endpoint
app.post("/signup", async (req, res) => {
  const { username, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  const role = username === "admin" ? "admin" : "user";

  db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", [username, hash, role], (err) => {
    if (err) return res.json({ success: false, message: "User already exists" });
    res.json({ success: true, message: "Signup successful" });
  });
});

// Login endpoint
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
    if (err || !user) return res.json({ success: false, message: "User not found" });
    const match = await bcrypt.compare(password, user.password);
    if (match) {
      res.json({ success: true, role: user.role });
    } else {
      res.json({ success: false, message: "Invalid password" });
    }
  });
});

// Get all users
app.get("/users", (req, res) => {
  db.all("SELECT username, role FROM users", (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Items management
app.get("/items", (req, res) => {
  db.all("SELECT name FROM items", (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows.map(r => r.name));
  });
});

app.post("/add-item", (req, res) => {
  const { item } = req.body;
  db.run("INSERT INTO items (name) VALUES (?)", [item], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

app.delete("/delete-item/:index", (req, res) => {
  const idx = parseInt(req.params.index);
  db.get("SELECT id FROM items LIMIT 1 OFFSET ?", [idx], (err, row) => {
    if (row) {
      db.run("DELETE FROM items WHERE id = ?", [row.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
      });
    } else {
      res.status(404).json({ error: "Item not found" });
    }
  });
});

// Orders
app.post("/add-order", (req, res) => {
  const { item, quantity } = req.body;
  db.run("INSERT INTO orders (item, quantity) VALUES (?, ?)", [item, quantity], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

app.get("/orders", (req, res) => {
  db.all("SELECT item, quantity FROM orders", (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});