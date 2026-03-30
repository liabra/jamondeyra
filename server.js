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

const app    = express();
const PORT   = process.env.PORT || 3000;
const isProd = process.env.NODE_ENV === 'production';

const DATA_FILE  = path.join(__dirname, 'data', 'content.json');
const USERS_FILE = path.join(__dirname, 'data', 'users.json');

// Clés de contenu autorisées
const CONTENT_KEYS   = new Set(['news', 'services', 'gallery', 'temoignages', 'drive']);
const SETTINGS_KEYS  = new Set(['settings']);
const ALL_KEYS       = new Set([...CONTENT_KEYS, ...SETTINGS_KEYS]);

// ── Middleware globaux ───────────────────────────────────────────────────────

app.use(express.json({ limit: '256kb' }));
app.use(cookieParser());
app.use(express.static(__dirname, { index: 'index.html' }));

// ── Helpers fichiers ─────────────────────────────────────────────────────────

function readJSON(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { return fallback; }
}

function writeJSON(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8');
}

// ── Gestion des utilisateurs ─────────────────────────────────────────────────

// Le super_admin "admin" est toujours bootstrapé depuis les variables d'env.
// Les comptes supplémentaires sont dans data/users.json.

function getEnvAdmin() {
  const hash = process.env.ADMIN_PASSWORD_HASH || null;
  if (!hash) return null;
  return { username: 'admin', role: 'super_admin', hash };
}

function getUsers() {
  return readJSON(USERS_FILE, []);
}

function saveUsers(users) {
  writeJSON(USERS_FILE, users);
}

function findUser(username) {
  if (!username) return null;
  const envAdmin = getEnvAdmin();
  if (envAdmin && username === 'admin') return envAdmin;
  return getUsers().find(u => u.username === username) || null;
}

// ── Middlewares d'authentification et de rôle ────────────────────────────────

function requireAuth(req, res, next) {
  const token = req.cookies.jey_token;
  if (!token) return res.status(401).json({ error: 'Non autorisé' });
  try {
    req.admin = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.clearCookie('jey_token');
    return res.status(401).json({ error: 'Session expirée' });
  }
}

function requireSuperAdmin(req, res, next) {
  if (req.admin?.role !== 'super_admin') {
    return res.status(403).json({ error: 'Accès réservé au super administrateur' });
  }
  next();
}

// ── Routes publiques ─────────────────────────────────────────────────────────

app.get('/api/content', (req, res) => {
  res.json(readJSON(DATA_FILE, {}));
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};

  if (!username || typeof username !== 'string' || username.length > 64
   || !password || typeof password !== 'string' || password.length > 128) {
    return res.status(400).json({ error: 'Identifiants invalides' });
  }

  const user = findUser(username.trim());
  if (!user) {
    // Délai constant pour éviter l'énumération de comptes
    await bcrypt.compare(password, '$2b$12$invalidhashplaceholderXXXXXXXXXXXXXXXXXXXXXXXXX');
    return res.status(401).json({ error: 'Identifiants incorrects' });
  }

  if (!process.env.ADMIN_PASSWORD_HASH && user.username === 'admin') {
    return res.status(500).json({ error: 'Compte admin non configuré' });
  }

  const valid = await bcrypt.compare(password, user.hash);
  if (!valid) return res.status(401).json({ error: 'Identifiants incorrects' });

  const token = jwt.sign(
    { username: user.username, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '8h' }
  );

  res.cookie('jey_token', token, {
    httpOnly: true,
    secure: isProd,
    sameSite: 'strict',
    maxAge: 8 * 60 * 60 * 1000,
  });

  res.json({ ok: true, username: user.username, role: user.role });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('jey_token');
  res.json({ ok: true });
});

// ── Routes protégées — tout utilisateur authentifié ───────────────────────────

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ ok: true, username: req.admin.username, role: req.admin.role });
});

app.post('/api/save', requireAuth, (req, res) => {
  const { key, data } = req.body || {};

  if (!key || !ALL_KEYS.has(key)) {
    return res.status(400).json({ error: 'Clé invalide' });
  }

  // Les paramètres sont réservés au super_admin
  if (SETTINGS_KEYS.has(key) && req.admin.role !== 'super_admin') {
    return res.status(403).json({ error: 'Accès refusé' });
  }

  const content = readJSON(DATA_FILE, {});
  content[key]  = data;
  writeJSON(DATA_FILE, content);

  res.json({ ok: true });
});

// Changement de son propre mot de passe (tout utilisateur authentifié)
app.post('/api/change-password', requireAuth, async (req, res) => {
  const { newPassword } = req.body || {};

  if (!newPassword || typeof newPassword !== 'string'
   || newPassword.length < 8 || newPassword.length > 128) {
    return res.status(400).json({ error: 'Mot de passe trop court (8 caractères minimum)' });
  }

  const hash = await bcrypt.hash(newPassword, 12);

  if (req.admin.username === 'admin') {
    // Le compte admin env-based ne peut pas être changé via le panel
    return res.status(403).json({ error: 'Utilisez la variable d\'environnement ADMIN_PASSWORD_HASH pour ce compte' });
  }

  const users = getUsers();
  const user  = users.find(u => u.username === req.admin.username);
  if (!user) return res.status(404).json({ error: 'Compte introuvable' });

  user.hash = hash;
  saveUsers(users);

  res.clearCookie('jey_token');
  res.json({ ok: true, relogin: true });
});

// ── Routes protégées — super_admin uniquement ────────────────────────────────

// Lister les comptes
app.get('/api/users', requireAuth, requireSuperAdmin, (req, res) => {
  const envAdmin = getEnvAdmin();
  const local    = getUsers();
  const list = [
    ...(envAdmin ? [{ username: 'admin', role: 'super_admin', builtin: true }] : []),
    ...local.map(u => ({ username: u.username, role: u.role, builtin: false })),
  ];
  res.json(list);
});

// Créer un compte
app.post('/api/users', requireAuth, requireSuperAdmin, async (req, res) => {
  const { username, password, role } = req.body || {};

  if (!username || typeof username !== 'string' || !/^[a-zA-Z0-9_-]{2,32}$/.test(username)) {
    return res.status(400).json({ error: 'Identifiant invalide (2–32 caractères alphanumériques)' });
  }
  if (!password || typeof password !== 'string' || password.length < 8 || password.length > 128) {
    return res.status(400).json({ error: 'Mot de passe trop court (8 caractères minimum)' });
  }
  if (!['super_admin', 'editor'].includes(role)) {
    return res.status(400).json({ error: 'Rôle invalide' });
  }
  if (username === 'admin') {
    return res.status(400).json({ error: 'Identifiant réservé' });
  }

  const users = getUsers();
  if (users.find(u => u.username === username)) {
    return res.status(409).json({ error: 'Identifiant déjà utilisé' });
  }

  const hash = await bcrypt.hash(password, 12);
  users.push({ username, role, hash });
  saveUsers(users);

  res.status(201).json({ ok: true });
});

// Supprimer un compte
app.delete('/api/users/:username', requireAuth, requireSuperAdmin, (req, res) => {
  const { username } = req.params;

  if (username === 'admin') {
    return res.status(403).json({ error: 'Compte admin non supprimable' });
  }
  if (username === req.admin.username) {
    return res.status(400).json({ error: 'Impossible de supprimer son propre compte' });
  }

  const users    = getUsers();
  const filtered = users.filter(u => u.username !== username);

  if (filtered.length === users.length) {
    return res.status(404).json({ error: 'Compte introuvable' });
  }

  saveUsers(filtered);
  res.json({ ok: true });
});

// Changer le mot de passe d'un autre compte (super_admin seulement)
app.post('/api/users/:username/password', requireAuth, requireSuperAdmin, async (req, res) => {
  const { username } = req.params;
  const { newPassword } = req.body || {};

  if (username === 'admin') {
    return res.status(403).json({ error: 'Utilisez la variable d\'environnement ADMIN_PASSWORD_HASH pour ce compte' });
  }
  if (!newPassword || typeof newPassword !== 'string'
   || newPassword.length < 8 || newPassword.length > 128) {
    return res.status(400).json({ error: 'Mot de passe trop court (8 caractères minimum)' });
  }

  const users = getUsers();
  const user  = users.find(u => u.username === username);
  if (!user) return res.status(404).json({ error: 'Compte introuvable' });

  user.hash = await bcrypt.hash(newPassword, 12);
  saveUsers(users);

  res.json({ ok: true });
});

// ── Démarrage ────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`Jamondeyra démarré sur le port ${PORT} [${isProd ? 'production' : 'développement'}]`);
});
