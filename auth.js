const crypto = require('crypto');
const express = require('express');
const bcrypt = require('bcrypt');
const db = require('./db');

const BCRYPT_ROUNDS = 12;
const SESSION_DAYS = 30;
const COOKIE_NAME = 'lq_session';

/* ---------- prepared statements ---------- */

const stmt = {
  insertUser: db.prepare(
    `INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)`
  ),
  userByLogin: db.prepare(
    `SELECT * FROM users WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE`
  ),
  insertSession: db.prepare(
    `INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)`
  ),
  sessionUser: db.prepare(
    `SELECT u.id, u.username, u.email, u.created_at, s.expires_at
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token = ?`
  ),
  deleteSession: db.prepare(`DELETE FROM sessions WHERE token = ?`),
  purgeExpired: db.prepare(`DELETE FROM sessions WHERE expires_at <= datetime('now')`),
};

/* ---------- validation ---------- */

const USERNAME_RE = /^[a-zA-Z0-9_]{3,30}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function validateRegistration({ username, email, password }) {
  if (typeof username !== 'string' || !USERNAME_RE.test(username)) {
    return 'Username must be 3–30 characters: letters, numbers, or underscores.';
  }
  if (typeof email !== 'string' || email.length > 254 || !EMAIL_RE.test(email)) {
    return 'Please enter a valid email address.';
  }
  if (typeof password !== 'string' || password.length < 8 || password.length > 200) {
    return 'Password must be at least 8 characters.';
  }
  return null;
}

/* ---------- session helpers ---------- */

function createSession(res, userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + SESSION_DAYS * 864e5);
  // SQLite datetime('now') is UTC; store the same way for correct comparison.
  const expiresSql = expires.toISOString().slice(0, 19).replace('T', ' ');
  stmt.insertSession.run(token, userId, expiresSql);

  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: SESSION_DAYS * 864e5,
    path: '/',
  });
  return token;
}

function clearSessionCookie(res) {
  res.clearCookie(COOKIE_NAME, { path: '/' });
}

// Populates req.user (or null) from the session cookie. Never throws.
function attachUser(req, res, next) {
  req.user = null;
  const token = req.cookies && req.cookies[COOKIE_NAME];
  if (token) {
    const row = stmt.sessionUser.get(token);
    if (row) {
      if (new Date(row.expires_at + 'Z') > new Date()) {
        req.user = { id: row.id, username: row.username, email: row.email, created_at: row.created_at };
        req.sessionToken = token;
      } else {
        stmt.deleteSession.run(token); // expired — clean up
        clearSessionCookie(res);
      }
    } else {
      clearSessionCookie(res); // stale cookie, no matching session
    }
  }
  next();
}

function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Not authenticated.' });
  next();
}

/* ---------- router ---------- */

const router = express.Router();

router.post('/register', (req, res) => {
  const body = req.body || {};
  const username = typeof body.username === 'string' ? body.username.trim() : body.username;
  const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : body.email;
  const password = body.password;

  const error = validateRegistration({ username, email, password });
  if (error) return res.status(400).json({ error });

  const hash = bcrypt.hashSync(password, BCRYPT_ROUNDS);
  let info;
  try {
    info = stmt.insertUser.run(username, email, hash);
  } catch (e) {
    if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ error: 'That username or email is already taken.' });
    }
    throw e;
  }

  createSession(res, info.lastInsertRowid);
  res.status(201).json({ user: { id: info.lastInsertRowid, username, email } });
});

router.post('/login', (req, res) => {
  const body = req.body || {};
  const identifier = typeof body.identifier === 'string' ? body.identifier.trim() : '';
  const password = typeof body.password === 'string' ? body.password : '';

  if (!identifier || !password) {
    return res.status(400).json({ error: 'Enter your username/email and password.' });
  }

  const user = stmt.userByLogin.get(identifier, identifier);
  // Always run a compare to keep timing consistent whether or not the user exists.
  const hash = user ? user.password_hash : '$2b$12$0000000000000000000000000000000000000000000000000000';
  const ok = bcrypt.compareSync(password, hash);

  if (!user || !ok) {
    return res.status(401).json({ error: 'Incorrect username/email or password.' });
  }

  createSession(res, user.id);
  res.json({ user: { id: user.id, username: user.username, email: user.email } });
});

router.post('/logout', (req, res) => {
  if (req.sessionToken) stmt.deleteSession.run(req.sessionToken);
  clearSessionCookie(res);
  res.json({ ok: true });
});

router.get('/me', (req, res) => {
  res.json({ user: req.user });
});

/* Best-effort cleanup of expired sessions on startup and daily. */
function purgeExpiredSessions() {
  try { stmt.purgeExpired.run(); } catch { /* non-fatal */ }
}
purgeExpiredSessions();
setInterval(purgeExpiredSessions, 24 * 3600 * 1000).unref();

module.exports = { router, attachUser, requireAuth };
