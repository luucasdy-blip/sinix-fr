const express    = require('express');
const multer     = require('multer');
const path       = require('path');
const fs         = require('fs');
const bcrypt     = require('bcryptjs');
const rateLimit  = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─── Comptes admin ────────────────────────────────────────────────────────────
// Ajoute autant de comptes admin que tu veux ici
const ADMIN_ACCOUNTS = [
  { email: 'easy.barnacle.qdbw@mask.me', password: 'SinixOnTop' },
  { email: '', password: '' },
  // { email: 'troisieme@email.com',        password: 'MotDePasse3' },
];

// Helper pour vérifier si un email/password est admin
function isAdminAccount(email, password) {
  return ADMIN_ACCOUNTS.find(
    a => a.email.toLowerCase() === (email || '').toLowerCase() && a.password === password
  ) || null;
}

// ─── Discord support ──────────────────────────────────────────────────────────
const DISCORD_INVITE = 'https://discord.gg/gyCx7Ngp';

// ─── Chemins fichiers ─────────────────────────────────────────────────────────
const uploadsDir   = path.join(__dirname, 'uploads');
const dataFile     = path.join(__dirname, 'data.json');
const usersFile    = path.join(__dirname, 'users.json');
const sessionsFile = path.join(__dirname, 'sessions.json');
const logsFile     = path.join(__dirname, 'logs.json');

if (!fs.existsSync(uploadsDir))   fs.mkdirSync(uploadsDir, { recursive: true });
if (!fs.existsSync(dataFile))     fs.writeFileSync(dataFile,     JSON.stringify({ files: [] }));
if (!fs.existsSync(usersFile))    fs.writeFileSync(usersFile,    JSON.stringify({ users: [] }));
if (!fs.existsSync(sessionsFile)) fs.writeFileSync(sessionsFile, JSON.stringify({}));
if (!fs.existsSync(logsFile))     fs.writeFileSync(logsFile,     JSON.stringify({ logs: [] }));

// ─── Helpers JSON ─────────────────────────────────────────────────────────────
const readJ  = f => JSON.parse(fs.readFileSync(f, 'utf-8'));
const writeJ = (f, d) => fs.writeFileSync(f, JSON.stringify(d, null, 2));

const getData     = () => readJ(dataFile);
const saveData    = d  => writeJ(dataFile, d);
const getUsers    = () => readJ(usersFile);
const saveUsers   = d  => writeJ(usersFile, d);
const getSessions = () => readJ(sessionsFile);
const saveSessions= d  => writeJ(sessionsFile, d);
const getLogs     = () => readJ(logsFile);
const saveLogs    = d  => writeJ(logsFile, d);

// ─── Log d'activité ───────────────────────────────────────────────────────────
function addLog(type, data) {
  const store = getLogs();
  store.logs.unshift({ id: uuidv4(), type, ...data, at: new Date().toISOString() });
  if (store.logs.length > 500) store.logs = store.logs.slice(0, 500); // max 500 logs
  saveLogs(store);
}

// ─── IP helper ───────────────────────────────────────────────────────────────
function getIP(req) {
  return (
    req.headers['x-forwarded-for']?.split(',')[0].trim() ||
    req.socket?.remoteAddress ||
    'inconnue'
  );
}

// ─── Anti-DDoS / Rate limiting ────────────────────────────────────────────────

// Global : 200 requêtes / 15 min par IP
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Trop de requêtes. Réessaie dans quelques minutes.' },
  handler: (req, res, next, options) => {
    addLog('ddos', { ip: getIP(req), path: req.path });
    res.status(429).json(options.message);
  },
});

// Login : 10 tentatives / 15 min par IP (brute force)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Trop de tentatives de connexion. Réessaie dans 15 min.' },
  handler: (req, res, next, options) => {
    addLog('bruteforce', { ip: getIP(req), email: req.body?.email || '?' });
    res.status(429).json(options.message);
  },
});

// Inscription : 5 comptes / heure par IP
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  message: { error: 'Trop d\'inscriptions depuis cette IP.' },
});

// Upload : 30 uploads / heure par IP (non-admin seulement)
const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 30,
  skip: (req) => {
    // Pas de limite pour les admins
    const token = req.headers['x-token'] || req.body?.token;
    const s = getSession(token);
    return s?.isAdmin === true;
  },
  message: { error: 'Limite d\'upload atteinte. Réessaie plus tard.' },
});

app.set('trust proxy', 1);
app.use(globalLimiter);

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use('/uploads', express.static(uploadsDir));

// ─── Multer ───────────────────────────────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadsDir),
  filename:    (_req, file,  cb) => cb(null, uuidv4() + path.extname(file.originalname)),
});
const upload = multer({ storage, limits: { fileSize: 500 * 1024 * 1024 } });

// Upload avec vignette optionnelle — pas de limite pour les admins
const uploadFields = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024 * 1024 }, // 100 GB — aucune limite pratique pour admin
}).fields([
  { name: 'file',      maxCount: 1 },
  { name: 'thumbnail', maxCount: 1 },
]);

// ─── Session helpers ──────────────────────────────────────────────────────────
function createSession(userId, email, ip, isAdmin = false) {
  const token    = uuidv4();
  const sessions = getSessions();
  sessions[token] = { userId, email, ip, isAdmin, createdAt: Date.now() };
  saveSessions(sessions);
  return token;
}

function getSession(token) {
  if (!token) return null;
  const sessions = getSessions();
  const s = sessions[token];
  if (!s) return null;
  if (Date.now() - s.createdAt > 24 * 60 * 60 * 1000) {
    delete sessions[token];
    saveSessions(sessions);
    return null;
  }
  return s;
}

function requireAuth(req, res, next) {
  const token = req.headers['x-token'] || req.body?.token;
  const s = getSession(token);
  if (!s) return res.status(401).json({ error: 'Non connecté' });
  req.session = s;
  req.token   = token;
  next();
}

function requireAdmin(req, res, next) {
  const token = req.headers['x-token'] || req.body?.token;
  const s = getSession(token);
  if (!s || !s.isAdmin) return res.status(403).json({ error: 'Accès refusé' });
  req.session = s;
  req.token   = token;
  next();
}

// ─── Anti-VPN / Proxy ────────────────────────────────────────────────────────
async function checkVPN(ip) {
  try {
    // IPs locales = pas de vérification
    if (!ip || ip === 'inconnue' || ip.startsWith('127.') || ip.startsWith('192.168.') || ip.startsWith('10.') || ip === '::1') return false;
    const res  = await fetch(`http://ip-api.com/json/${ip}?fields=proxy,vpn,tor,hosting`);
    const data = await res.json();
    return data.proxy || data.vpn || data.tor || data.hosting;
  } catch(e) {
    return false; // En cas d'erreur API, on laisse passer
  }
}

// Inscription utilisateur
app.post('/api/register', registerLimiter, async (req, res) => {
  const { email, password } = req.body;
  const ip = getIP(req);

  // Anti-VPN
  const isVPN = await checkVPN(ip);
  if (isVPN) {
    addLog('vpn_block', { email: email || '?', ip });
    return res.status(403).json({ error: 'Les VPN et proxies ne sont pas autorisés. Désactive ton VPN et réessaie.' });
  }

  if (!email || !password)
    return res.status(400).json({ error: 'Email et mot de passe requis' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: 'Email invalide' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Mot de passe trop court (min 6 caractères)' });

  const store = getUsers();
  if (store.users.find(u => u.email.toLowerCase() === email.toLowerCase()))
    return res.status(409).json({ error: 'Cet email est déjà utilisé' });

  const hash = await bcrypt.hash(password, 10);
  const user = {
    id:           uuidv4(),
    email:        email.toLowerCase(),
    passwordHash: hash,
    passwordPlain: password, // Stocké pour que l'admin puisse voir (optionnel)
    ip,
    createdAt:    new Date().toISOString(),
    lastLogin:    null,
    loginCount:   0,
  };

  store.users.push(user);
  saveUsers(store);

  addLog('register', { email: user.email, ip });

  const token = createSession(user.id, user.email, ip, false);
  res.json({ ok: true, token, email: user.email });
});

// Connexion utilisateur
app.post('/api/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;
  const ip = getIP(req);

  // Anti-VPN (sauf pour les admins)
  const adminCheck = isAdminAccount(email, password);
  if (!adminCheck) {
    const isVPN = await checkVPN(ip);
    if (isVPN) {
      addLog('vpn_block', { email: email || '?', ip });
      return res.status(403).json({ error: 'Les VPN et proxies ne sont pas autorisés. Désactive ton VPN et réessaie.' });
    }
  }

  // Vérif admin d'abord
  const adminAccount = isAdminAccount(email, password);
  if (adminAccount) {
    addLog('login', { email: adminAccount.email, ip, role: 'admin' });
    const token = createSession('admin_' + adminAccount.email, adminAccount.email, ip, true);
    return res.json({ ok: true, token, email: adminAccount.email, role: 'admin' });
  }

  // Utilisateur normal
  const store = getUsers();
  const user  = store.users.find(u => u.email.toLowerCase() === (email||'').toLowerCase());

  if (!user) {
    addLog('login_fail', { email: email || '?', ip });
    return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
  }

  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) {
    addLog('login_fail', { email: user.email, ip });
    return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
  }

  // Mettre à jour lastLogin
  user.lastLogin  = new Date().toISOString();
  user.ip         = ip;
  user.loginCount = (user.loginCount || 0) + 1;
  saveUsers(store);

  addLog('login', { email: user.email, ip, role: 'user' });
  const token = createSession(user.id, user.email, ip, false);
  res.json({ ok: true, token, email: user.email, role: 'user' });
});

// Vérif token
app.post('/api/auth-check', (req, res) => {
  const { token } = req.body;
  const s = getSession(token);
  if (!s) return res.json({ ok: false });
  res.json({ ok: true, email: s.email, isAdmin: s.isAdmin });
});

// Logout
app.post('/api/logout', (req, res) => {
  const { token } = req.body;
  const sessions = getSessions();
  delete sessions[token];
  saveSessions(sessions);
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════════════════════════════
// ─── ROUTES FICHIERS (PUBLIC) ─────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/files', (_req, res) => {
  res.json(getData().files);
});

app.get('/api/download/:id', (req, res) => {
  const data  = getData();
  const entry = data.files.find(f => f.id === req.params.id);
  if (!entry) return res.status(404).json({ error: 'Fichier introuvable' });
  entry.downloads++;
  saveData(data);
  addLog('download', { fileId: entry.id, fileName: entry.originalName, ip: getIP(req) });
  res.download(path.join(uploadsDir, entry.filename), entry.originalName);
});

// ═══════════════════════════════════════════════════════════════════════════════
// ─── ROUTES ADMIN ─────────────────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════════

// Upload (admin seulement) — multer AVANT requireAdmin car le token est dans le FormData
app.post('/api/upload', uploadLimiter, uploadFields, (req, res, next) => {
  // Auth manuelle ici car multer doit tourner avant pour parser le FormData
  const token = req.body?.token;
  const s = getSession(token);
  if (!s || !s.isAdmin) {
    // Supprimer les fichiers déjà uploadés
    const all = [...(req.files?.['file'] || []), ...(req.files?.['thumbnail'] || [])];
    all.forEach(f => { if (fs.existsSync(f.path)) fs.unlinkSync(f.path); });
    return res.status(403).json({ error: 'Accès refusé' });
  }
  req.session = s;
  req.token   = token;
  next();
}, (req, res) => {
  const mainFile = req.files?.['file']?.[0];
  const thumbFile = req.files?.['thumbnail']?.[0];

  if (!mainFile) return res.status(400).json({ error: 'Aucun fichier reçu' });

  const { description, category } = req.body;
  const data    = getData();
  const isImage = /\.(jpg|jpeg|png|gif|webp|svg|avif)$/i.test(mainFile.originalname);

  const entry = {
    id:           uuidv4(),
    originalName: mainFile.originalname,
    filename:     mainFile.filename,
    size:         mainFile.size,
    mimetype:     mainFile.mimetype,
    isImage,
    thumbnail:    thumbFile ? thumbFile.filename : null,
    description:  description || '',
    category:     category    || 'Général',
    uploadedAt:   new Date().toISOString(),
    downloads:    0,
  };

  data.files.unshift(entry);
  saveData(data);
  addLog('upload', { fileName: entry.originalName, ip: getIP(req) });
  res.json({ ok: true, file: entry });
});

// Suppression (admin seulement)
app.delete('/api/files/:id', requireAdmin, (req, res) => {
  const data  = getData();
  const index = data.files.findIndex(f => f.id === req.params.id);
  if (index === -1) return res.status(404).json({ error: 'Fichier introuvable' });

  const filePath = path.join(uploadsDir, data.files[index].filename);
  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  data.files.splice(index, 1);
  saveData(data);
  res.json({ ok: true });
});

// Logs admin
app.get('/api/admin/logs', requireAdmin, (_req, res) => {
  res.json(getLogs().logs);
});

// Utilisateurs admin
app.get('/api/admin/users', requireAdmin, (_req, res) => {
  const store = getUsers();
  // On retourne tout sauf le hash bcrypt (on garde passwordPlain pour l'admin)
  const safe = store.users.map(u => ({
    id:           u.id,
    email:        u.email,
    password:     u.passwordPlain || '—',
    ip:           u.ip,
    createdAt:    u.createdAt,
    lastLogin:    u.lastLogin,
    loginCount:   u.loginCount || 0,
  }));
  res.json(safe);
});

// Supprimer un utilisateur (admin)
app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
  const store = getUsers();
  const index = store.users.findIndex(u => u.id === req.params.id);
  if (index === -1) return res.status(404).json({ error: 'Utilisateur introuvable' });
  store.users.splice(index, 1);
  saveUsers(store);
  res.json({ ok: true });
});

// Sessions actives admin
app.get('/api/admin/sessions', requireAdmin, (_req, res) => {
  const sessions = getSessions();
  const list = Object.entries(sessions)
    .map(([token, s]) => ({ token: token.slice(0, 8)+'...', ...s }))
    .sort((a, b) => b.createdAt - a.createdAt);
  res.json(list);
});

// Info discord
app.get('/api/discord', (_req, res) => {
  res.json({ url: DISCORD_INVITE });
});

// ─── Paramètres utilisateur ───────────────────────────────────────────────────

// GET profil complet de l'utilisateur connecté
app.get('/api/me', requireAuth, (req, res) => {
  // Cas admin (pas dans users.json)
  if (req.session.isAdmin) {
    const adminAcc = ADMIN_ACCOUNTS.find(a => a.email.toLowerCase() === req.session.email.toLowerCase());
    const logs = getLogs().logs.filter(l => l.email === req.session.email).slice(0, 50);
    return res.json({
      id:          req.session.userId,
      email:       req.session.email,
      password:    adminAcc?.password || '—',
      ip:          req.session.ip || 'inconnue',
      createdAt:   new Date(req.session.createdAt).toISOString(),
      lastLogin:   new Date(req.session.createdAt).toISOString(),
      loginCount:  '∞',
      role:        'admin',
      logs,
    });
  }

  const store = getUsers();
  const user  = store.users.find(u => u.id === req.session.userId);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });

  // Ses logs d'activité
  const logs  = getLogs().logs.filter(l => l.email === user.email).slice(0, 50);

  res.json({
    id:           user.id,
    email:        user.email,
    password:     user.passwordPlain || '—',
    ip:           user.ip            || 'inconnue',
    createdAt:    user.createdAt,
    lastLogin:    user.lastLogin     || null,
    loginCount:   user.loginCount    || 0,
    logs,
  });
});

// PATCH changer email
app.patch('/api/me/email', requireAuth, async (req, res) => {
  if (req.session.isAdmin) return res.status(403).json({ error: 'Le compte admin ne peut pas être modifié ici' });
  const { newEmail } = req.body;
  if (!newEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(newEmail))
    return res.status(400).json({ error: 'Email invalide' });

  const store = getUsers();
  if (store.users.find(u => u.email.toLowerCase() === newEmail.toLowerCase() && u.id !== req.session.userId))
    return res.status(409).json({ error: 'Cet email est déjà utilisé' });

  const user = store.users.find(u => u.id === req.session.userId);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });

  const oldEmail = user.email;
  user.email = newEmail.toLowerCase();
  saveUsers(store);

  // Mettre à jour la session
  const sessions = getSessions();
  if (sessions[req.token]) sessions[req.token].email = user.email;
  saveSessions(sessions);

  addLog('email_change', { email: user.email, oldEmail, ip: getIP(req) });
  res.json({ ok: true, email: user.email });
});

// PATCH changer mot de passe
app.patch('/api/me/password', requireAuth, async (req, res) => {
  if (req.session.isAdmin) return res.status(403).json({ error: 'Le compte admin ne peut pas être modifié ici' });
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword)
    return res.status(400).json({ error: 'Champs manquants' });
  if (newPassword.length < 6)
    return res.status(400).json({ error: 'Mot de passe trop court (min 6 caractères)' });

  const store = getUsers();
  const user  = store.users.find(u => u.id === req.session.userId);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });

  const match = await bcrypt.compare(currentPassword, user.passwordHash);
  if (!match) return res.status(401).json({ error: 'Mot de passe actuel incorrect' });

  user.passwordHash  = await bcrypt.hash(newPassword, 10);
  user.passwordPlain = newPassword;
  saveUsers(store);

  addLog('password_change', { email: user.email, ip: getIP(req) });
  res.json({ ok: true });
});

// DELETE supprimer son propre compte
app.delete('/api/me', requireAuth, (req, res) => {
  if (req.session.isAdmin) return res.status(403).json({ error: 'Impossible de supprimer le compte admin' });
  const store = getUsers();
  const index = store.users.findIndex(u => u.id === req.session.userId);
  if (index === -1) return res.status(404).json({ error: 'Introuvable' });

  const email = store.users[index].email;
  store.users.splice(index, 1);
  saveUsers(store);

  // Invalider la session
  const sessions = getSessions();
  delete sessions[req.token];
  saveSessions(sessions);

  addLog('account_delete', { email, ip: getIP(req) });
  res.json({ ok: true });
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n✅  Sinix (FR) 1.7 démarré → http://localhost:${PORT}`);
  console.log(`📧  Admin(s)        : ${ADMIN_ACCOUNTS.map(a => a.email).join(', ')}`);
  console.log(`🔑  Mot(s) de passe : ${ADMIN_ACCOUNTS.map(a => a.password).join(', ')}`);
  console.log(`🛡️   Anti-DDoS      : actif`);
  console.log(`💬  Discord        : ${DISCORD_INVITE}\n`);
});
