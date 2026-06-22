'use strict';
require('dotenv').config();

const express      = require('express');
const helmet       = require('helmet');
const rateLimit    = require('express-rate-limit');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const fs           = require('fs');
const path         = require('path');

// ── Validation de la configuration ──────────────────────────────────────────

if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  console.error('[ERREUR] JWT_SECRET manquant ou trop court (32 caractères min). Arrêt.');
  process.exit(1);
}

const app    = express();
const PORT   = process.env.PORT || 3000;
const isProd = process.env.NODE_ENV === 'production';

const DATA_DIR   = process.env.DATA_DIR || path.join(__dirname, 'data');
const DATA_FILE  = path.join(DATA_DIR, 'content.json');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

// Initialisation du dossier de données (volume persistant Railway le cas échéant)
fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DATA_FILE)) {
  fs.writeFileSync(DATA_FILE, '{}');
}

const CONTENT_KEYS  = new Set(['news', 'services', 'gallery', 'temoignages', 'drive']);
const SETTINGS_KEYS = new Set(['settings']);
const ALL_KEYS      = new Set([...CONTENT_KEYS, ...SETTINGS_KEYS]);

// ── Journalisation ────────────────────────────────────────────────────────────

function log(level, event, details = {}) {
  const entry = {
    ts: new Date().toISOString(),
    level,
    event,
    ...details,
  };
  // Stdout uniquement — Railway capture les logs process
  console.log(JSON.stringify(entry));
}

// ── Middlewares globaux ───────────────────────────────────────────────────────

// 1. Helmet — headers de sécurité
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'", "'unsafe-inline'"],   // inline scripts du HTML existant
      scriptSrcAttr: ["'unsafe-inline'"],          // gestionnaires d'événements en ligne (onclick…)
      styleSrc:   ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc:    ["'self'", 'https://fonts.gstatic.com'],
      imgSrc:     ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      frameSrc:   ["'none'"],
      objectSrc:  ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false, // Évite de casser les fonts Google
}));

// Masquer Express
app.disable('x-powered-by');

// 2. CORS — en production : même origine uniquement (cookie sameSite:strict suffisant)
//    En développement : permissif pour faciliter les tests locaux
if (isProd) {
  app.use((req, res, next) => {
    const origin = req.headers.origin;
    // Pas de header Origin (cas fréquent en GET same-origin) — on laisse passer
    if (!origin) return next();
    // Les navigateurs envoient un header Origin sur les requêtes POST/PUT/DELETE
    // même en same-origin. On compare donc l'origine à l'hôte de la requête et
    // on ne bloque que les requêtes réellement cross-origin vers les API.
    const host = req.headers.host;
    const sameOrigin = origin === `https://${host}` || origin === `http://${host}`;
    if (!sameOrigin && req.path.startsWith('/api/')) {
      return res.status(403).json({ error: 'Accès refusé' });
    }
    next();
  });
}

// 3. Rate limiting sur le login — 5 tentatives / 15 min par IP
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true, // Ne compte pas les connexions réussies
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    log('warn', 'login_rate_limited', { ip: req.ip });
    res.status(429).json({ error: 'Trop de tentatives. Réessayez dans 15 minutes.' });
  },
});

// Rate limiting général API — 120 req / min (protection contre abus)
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    log('warn', 'api_rate_limited', { ip: req.ip, path: req.path });
    res.status(429).json({ error: 'Trop de requêtes.' });
  },
});

app.use(express.json({ limit: '128kb' })); // Réduit de 256kb à 128kb
app.use(cookieParser());
app.use('/api/', apiLimiter);

// 4. Bloquer l'accès direct aux fichiers data/ via static
app.use('/data', (req, res) => res.status(404).end());

app.use(express.static(__dirname, {
  index: 'index.html',
  // Exclure explicitement les fichiers sensibles
  setHeaders: (res, filePath) => {
    if (filePath.startsWith(DATA_DIR)) {
      res.status(404).end();
    }
  },
}));

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

function getEnvAdmin() {
  const hash = process.env.ADMIN_PASSWORD_HASH || null;
  if (!hash) return null;
  return { username: 'admin', role: 'super_admin', hash };
}

function getUsers() { return readJSON(USERS_FILE, []); }
function saveUsers(users) { writeJSON(USERS_FILE, users); }

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
    return res.status(403).json({ error: 'Accès refusé' });
  }
  next();
}

// ── Validation du contenu /api/save ──────────────────────────────────────────

const SAVE_VALIDATORS = {
  news:        d => Array.isArray(d) && d.length <= 50,
  services:    d => Array.isArray(d) && d.length <= 20,
  gallery:     d => Array.isArray(d) && d.length <= 100,
  temoignages: d => Array.isArray(d) && d.length <= 50,
  drive:       d => d !== null && typeof d === 'object' && !Array.isArray(d),
  settings:    d => d !== null && typeof d === 'object' && !Array.isArray(d),
};

// ── Routes publiques ─────────────────────────────────────────────────────────

app.get('/api/content', (req, res) => {
  const content = readJSON(DATA_FILE, {});
  // Ne pas exposer les settings complets publiquement (email admin, etc.)
  // On expose uniquement les clés de contenu
  const pub = {};
  for (const key of CONTENT_KEYS) {
    if (content[key] !== undefined) pub[key] = content[key];
  }
  // Settings exposés partiellement (affichage contact/footer uniquement)
  if (content.settings) {
    const { name, address1, address2, zip, city, phone, email, hours, infos, mapsUrl, fb, ig } = content.settings;
    pub.settings = { name, address1, address2, zip, city, phone, email, hours, infos, mapsUrl, fb, ig };
  }
  res.json(pub);
});

app.post('/api/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  const ip = req.ip;

  if (!username || typeof username !== 'string' || username.length > 64
   || !password || typeof password !== 'string' || password.length > 128) {
    log('warn', 'login_invalid_input', { ip });
    return res.status(400).json({ error: 'Identifiants invalides' });
  }

  const user = findUser(username.trim());
  if (!user) {
    await bcrypt.compare(password, '$2b$12$invalidhashplaceholderXXXXXXXXXXXXXXXXXXXXXXXXX');
    log('warn', 'login_unknown_user', { ip, username: username.trim() });
    return res.status(401).json({ error: 'Identifiants incorrects' });
  }

  if (!process.env.ADMIN_PASSWORD_HASH && user.username === 'admin') {
    return res.status(500).json({ error: 'Compte admin non configuré' });
  }

  const valid = await bcrypt.compare(password, user.hash);
  if (!valid) {
    log('warn', 'login_failed', { ip, username: user.username });
    return res.status(401).json({ error: 'Identifiants incorrects' });
  }

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
    path: '/',
  });

  log('info', 'login_success', { ip, username: user.username, role: user.role });
  res.json({ ok: true, username: user.username, role: user.role });
});

app.post('/api/logout', (req, res) => {
  const token = req.cookies.jey_token;
  if (token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      log('info', 'logout', { username: decoded.username });
    } catch {}
  }
  res.clearCookie('jey_token', { path: '/' });
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

  if (SETTINGS_KEYS.has(key) && req.admin.role !== 'super_admin') {
    return res.status(403).json({ error: 'Accès refusé' });
  }

  const validator = SAVE_VALIDATORS[key];
  if (!validator || !validator(data)) {
    log('warn', 'save_invalid_data', { username: req.admin.username, key });
    return res.status(400).json({ error: 'Données invalides' });
  }

  const content = readJSON(DATA_FILE, {});
  content[key]  = data;
  writeJSON(DATA_FILE, content);

  log('info', 'content_saved', { username: req.admin.username, key });
  res.json({ ok: true });
});

app.post('/api/change-password', requireAuth, async (req, res) => {
  const { newPassword } = req.body || {};

  if (!newPassword || typeof newPassword !== 'string'
   || newPassword.length < 8 || newPassword.length > 128) {
    return res.status(400).json({ error: 'Mot de passe trop court (8 caractères minimum)' });
  }

  if (req.admin.username === 'admin') {
    return res.status(403).json({ error: 'Utilisez la variable d\'environnement ADMIN_PASSWORD_HASH pour ce compte' });
  }

  const hash  = await bcrypt.hash(newPassword, 12);
  const users = getUsers();
  const user  = users.find(u => u.username === req.admin.username);
  if (!user) return res.status(404).json({ error: 'Compte introuvable' });

  user.hash = hash;
  saveUsers(users);

  log('info', 'password_changed', { username: req.admin.username });
  res.clearCookie('jey_token', { path: '/' });
  res.json({ ok: true, relogin: true });
});

// ── Routes protégées — super_admin uniquement ────────────────────────────────

app.get('/api/users', requireAuth, requireSuperAdmin, (req, res) => {
  const envAdmin = getEnvAdmin();
  const local    = getUsers();
  const list = [
    ...(envAdmin ? [{ username: 'admin', role: 'super_admin', builtin: true }] : []),
    ...local.map(u => ({ username: u.username, role: u.role, builtin: false })),
  ];
  res.json(list);
});

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

  log('info', 'user_created', { by: req.admin.username, username, role });
  res.status(201).json({ ok: true });
});

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
  log('info', 'user_deleted', { by: req.admin.username, username });
  res.json({ ok: true });
});

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

  log('info', 'password_reset', { by: req.admin.username, username });
  res.json({ ok: true });
});

// ── Erreurs non gérées ────────────────────────────────────────────────────────

// Réponse sobre pour toute route inconnue sous /api/
app.use('/api/*', (req, res) => {
  res.status(404).json({ error: 'Route introuvable' });
});

// Handler d'erreur global — évite les stack traces en réponse
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  log('error', 'unhandled_error', { path: req.path, message: err.message });
  res.status(500).json({ error: 'Erreur interne' });
});

// ── Démarrage ────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  log('info', 'server_started', { port: PORT, env: isProd ? 'production' : 'development' });
});
