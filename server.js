'use strict';
require('dotenv').config();

const express      = require('express');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const fs           = require('fs');
const path         = require('path');

// ── Validation de la configuration ──────────────────────────────────────────

if (!process.env.JWT_SECRET) {
  console.error('[ERREUR] Variable JWT_SECRET manquante. Arrêt du serveur.');
  process.exit(1);
}

const app  = express();
const PORT = process.env.PORT || 3000;
const isProd = process.env.NODE_ENV === 'production';

const DATA_FILE  = path.join(__dirname, 'data', 'content.json');
const ADMIN_FILE = path.join(__dirname, 'data', 'admin.json');
const ALLOWED    = new Set(['news', 'services', 'gallery', 'temoignages', 'drive', 'settings']);

// ── Middleware globaux ───────────────────────────────────────────────────────

app.use(express.json({ limit: '256kb' }));
app.use(cookieParser());
app.use(express.static(__dirname, { index: 'index.html' }));

// ── Helpers fichiers ─────────────────────────────────────────────────────────

function readJSON(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
}

function writeJSON(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8');
}

function getAdminHash() {
  const local = readJSON(ADMIN_FILE, {});
  return local.hash || process.env.ADMIN_PASSWORD_HASH || null;
}

// ── Middleware d'authentification ────────────────────────────────────────────

function requireAuth(req, res, next) {
  const token = req.cookies.jey_token;
  if (!token) {
    return res.status(401).json({ error: 'Non autorisé' });
  }
  try {
    req.admin = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.clearCookie('jey_token');
    return res.status(401).json({ error: 'Session expirée' });
  }
}

// ── Routes publiques ─────────────────────────────────────────────────────────

app.get('/api/content', (req, res) => {
  res.json(readJSON(DATA_FILE, {}));
});

app.post('/api/login', async (req, res) => {
  const { password } = req.body || {};

  if (!password || typeof password !== 'string' || password.length > 128) {
    return res.status(400).json({ error: 'Identifiants invalides' });
  }

  const hash = getAdminHash();
  if (!hash) {
    return res.status(500).json({ error: 'Compte admin non configuré' });
  }

  const valid = await bcrypt.compare(password, hash);
  if (!valid) {
    return res.status(401).json({ error: 'Identifiants incorrects' });
  }

  const token = jwt.sign({ role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '8h' });

  res.cookie('jey_token', token, {
    httpOnly: true,
    secure: isProd,
    sameSite: 'strict',
    maxAge: 8 * 60 * 60 * 1000,
  });

  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('jey_token');
  res.json({ ok: true });
});

// ── Routes protégées ─────────────────────────────────────────────────────────

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ ok: true });
});

app.post('/api/save', requireAuth, (req, res) => {
  const { key, data } = req.body || {};

  if (!key || !ALLOWED.has(key)) {
    return res.status(400).json({ error: 'Clé invalide' });
  }

  const content = readJSON(DATA_FILE, {});
  content[key]  = data;
  writeJSON(DATA_FILE, content);

  res.json({ ok: true });
});

app.post('/api/change-password', requireAuth, async (req, res) => {
  const { newPassword } = req.body || {};

  if (!newPassword || typeof newPassword !== 'string' || newPassword.length < 8 || newPassword.length > 128) {
    return res.status(400).json({ error: 'Mot de passe trop court (8 caractères minimum)' });
  }

  const hash = await bcrypt.hash(newPassword, 12);
  writeJSON(ADMIN_FILE, { hash });

  // Invalider le cookie actuel pour forcer une reconnexion
  res.clearCookie('jey_token');
  res.json({ ok: true, relogin: true });
});

// ── Démarrage ────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`Jamondeyra démarré sur le port ${PORT} [${isProd ? 'production' : 'développement'}]`);
});
