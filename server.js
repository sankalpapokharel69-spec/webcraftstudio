const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');
const { OAuth2Client } = require('google-auth-library');

const app = express();
const PORT = process.env.PORT || 3000;

/* ================= CONFIG ================= */
const ADMIN_PASSWORD = '1325354430';                    // Admin / Owner password
const GOOGLE_CLIENT_ID = 'YOUR_GOOGLE_CLIENT_ID_HERE';  // <-- paste your Google Client ID
const SESSION_SECRET = 'change-this-to-a-random-string';

const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

/* ================= DATABASE ================= */
const db = new Database('webcraft.db'); // auto-created on first run

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT,
    provider TEXT DEFAULT 'local',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    image_url TEXT DEFAULT '',
    link TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    subject TEXT DEFAULT '',
    message TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

/* ================= MIDDLEWARE ================= */
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 }
}));

/* ================= HELPERS ================= */
function uniqueUsername(base) {
  let username = (base || 'user').replace(/[^a-zA-Z0-9_]/g, '').toLowerCase() || 'user';
  let final = username, i = 1;
  while (db.prepare('SELECT id FROM users WHERE username = ?').get(final)) {
    final = username + i++;
  }
  return final;
}

/* ================= AUTH ROUTES ================= */

// Real-time username availability (used on register page)
app.get('/api/check-username/:username', (req, res) => {
  const taken = db.prepare('SELECT id FROM users WHERE username = ?').get(req.params.username);
  res.json({ available: !taken });
});

// Register — username uniqueness enforced by UNIQUE constraint + this check
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password)
      return res.status(400).json({ error: 'All fields are required' });
    if (username.length < 3 || username.length > 20)
      return res.status(400).json({ error: 'Username must be 3-20 characters' });
    if (!/^[a-zA-Z0-9_]+$/.test(username))
      return res.status(400).json({ error: 'Username can only contain letters, numbers and _' });
    if (password.length < 6)
      return res.status(400).json({ error: 'Password must be at least 6 characters' });

    if (db.prepare('SELECT id FROM users WHERE username = ?').get(username))
      return res.status(409).json({ error: 'Username already taken' });
    if (db.prepare('SELECT id FROM users WHERE email = ?').get(email))
      return res.status(409).json({ error: 'Email already registered' });

    const hash = await bcrypt.hash(password, 10);
    db.prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)').run(username, email, hash);
    res.json({ success: true, message: 'Account created! You can log in now.' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ? OR email = ?').get(username, username);
  if (!user || !user.password)
    return res.status(401).json({ error: 'Invalid username or password' });
  const match = await bcrypt.compare(password, user.password);
  if (!match)
    return res.status(401).json({ error: 'Invalid username or password' });
  req.session.user = { id: user.id, username: user.username };
  res.json({ success: true });
});

// Google Sign-In
app.post('/api/google-auth', async (req, res) => {
  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: req.body.credential,
      audience: GOOGLE_CLIENT_ID
    });
    const { email, name } = ticket.getPayload();
    let user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) {
      const username = uniqueUsername(name || email.split('@')[0]);
      db.prepare('INSERT INTO users (username, email, provider) VALUES (?, ?, ?)').run(username, email, 'google');
      user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    }
    req.session.user = { id: user.id, username: user.username };
    res.json({ success: true });
  } catch (err) {
    res.status(401).json({ error: 'Google sign-in failed' });
  }
});

// Current user (for navbar)
app.get('/api/me', (req, res) => {
  if (req.session.user) res.json({ loggedIn: true, username: req.session.user.username });
  else res.json({ loggedIn: false });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

/* ================= ADMIN / OWNER ROUTES ================= */

app.post('/api/admin/login', (req, res) => {
  if (req.body.password === ADMIN_PASSWORD) {
    req.session.isAdmin = true;
    res.json({ success: true });
  } else {
    res.status(401).json({ error: 'Wrong password' });
  }
});

app.get('/api/admin/status', (req, res) => {
  res.json({ isAdmin: !!req.session.isAdmin });
});

app.post('/api/admin/logout', (req, res) => {
  req.session.isAdmin = false;
  res.json({ success: true });
});

/* ================= PROJECTS ================= */

// PUBLIC — everyone sees projects (stored in database)
app.get('/api/projects', (req, res) => {
  res.json(db.prepare('SELECT * FROM projects ORDER BY id DESC').all());
});

// ADMIN ONLY — add project
app.post('/api/projects', (req, res) => {
  if (!req.session.isAdmin) return res.status(403).json({ error: 'Admin access only' });
  const { title, description, image_url, link } = req.body;
  if (!title || !description)
    return res.status(400).json({ error: 'Title and description are required' });
  db.prepare('INSERT INTO projects (title, description, image_url, link) VALUES (?, ?, ?, ?)')
    .run(title, description, image_url || '', link || '');
  res.json({ success: true, message: 'Project added!' });
});

// ADMIN ONLY — delete project
app.delete('/api/projects/:id', (req, res) => {
  if (!req.session.isAdmin) return res.status(403).json({ error: 'Admin access only' });
  db.prepare('DELETE FROM projects WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

/* ================= INBOX (OWNER ONLY) ================= */

// PUBLIC — anyone can send a message (goes to owner's inbox)
app.post('/api/contact', (req, res) => {
  const { name, email, subject, message } = req.body;
  if (!name || !email || !message)
    return res.status(400).json({ error: 'Name, email and message are required' });
  db.prepare('INSERT INTO messages (name, email, subject, message) VALUES (?, ?, ?, ?)')
    .run(name, email, subject || '', message);
  res.json({ success: true, message: 'Message sent to owner inbox!' });
});

// OWNER ONLY — view inbox
app.get('/api/inbox', (req, res) => {
  if (!req.session.isAdmin) return res.status(403).json({ error: 'Owner access only' });
  res.json(db.prepare('SELECT * FROM messages ORDER BY id DESC').all());
});

// OWNER ONLY — delete message
app.delete('/api/inbox/:id', (req, res) => {
  if (!req.session.isAdmin) return res.status(403).json({ error: 'Owner access only' });
  db.prepare('DELETE FROM messages WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

/* ================= START ================= */
app.listen(PORT, () => {
  console.log(`✅ Web Craft Studio running at http://localhost:${PORT}`);
});