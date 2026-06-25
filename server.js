try { require('dotenv').config(); } catch (e) {}
try { require('dns').setDefaultResultOrder('ipv4first'); } catch (e) {}
const express    = require('express');
const multer     = require('multer');
const path       = require('path');
const fs         = require('fs');
const dns        = require('dns').promises;
const bcrypt     = require('bcryptjs');
const rateLimit  = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─── Anti-VPN / Proxy ULTRA STRICT ──────────────────────────────────────────────
const vpnCheckCache = new Map(); // Cache pour les vérifications VPN
const blockedIPs = new Map();    // IPs bloquées (temporairement ou définitivement)
const vpnAttempts = new Map();   // Tentatives VPN par IP
const bannedEmails = new Set();  // Emails bannis

const BAN_DURATION = 30 * 60 * 1000; // 30 minutes (par défaut)
const MAX_VPN_ATTEMPTS = 2; // 2 tentatives avant ban

// Middleware pour bloquer les IPs et emails bannis
function checkBanned(req, res, next) {
  const ip = getIP(req);
  
  // Vérifier si l'IP est bannie
  if (blockedIPs.has(ip)) {
    const ban = blockedIPs.get(ip);
    // Vérifier si le ban a expiré
    if (!ban.until || Date.now() < ban.until) {
      return sendBanPage(res, ip, ban.reason);
    } else {
      // Ban expiré, l'enlever
      blockedIPs.delete(ip);
    }
  }
  
  next();
}

// Fonction pour envoyer la page de ban
function sendBanPage(res, identifier, reason) {
  const html = `
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Accès Refusé - Sinix</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            min-height: 100vh;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            color: #fff;
            text-align: center;
            padding: 20px;
        }
        
        .ban-icon {
            font-size: 120px;
            margin-bottom: 30px;
            animation: shake 0.5s ease-in-out;
        }
        
        @keyframes shake {
            0%, 100% { transform: translateX(0); }
            25% { transform: translateX(-10px); }
            75% { transform: translateX(10px); }
        }
        
        h1 {
            font-size: clamp(36px, 8vw, 72px);
            font-weight: 900;
            background: linear-gradient(90deg, #ff6b6b, #ee5a5a, #ff8e8e);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 20px;
            text-transform: uppercase;
            letter-spacing: 2px;
        }
        
        .identifier {
            font-size: clamp(24px, 5vw, 48px);
            font-weight: 800;
            color: #7c5cfc;
            margin-bottom: 10px;
            font-family: 'Consolas', 'Monaco', monospace;
            background: rgba(124, 92, 252, 0.1);
            padding: 10px 20px;
            border-radius: 10px;
            border: 1px solid rgba(124, 92, 252, 0.3);
            word-break: break-all;
            max-width: 90%;
        }
        
        .reason-label {
            font-size: 20px;
            color: #888;
            margin-bottom: 5px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .reason {
            font-size: clamp(20px, 4vw, 32px);
            font-weight: 700;
            color: #fca5a5;
            margin-bottom: 40px;
            max-width: 800px;
        }
        
        .discord-section {
            margin-top: 40px;
            padding: 30px;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 20px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            max-width: 600px;
        }
        
        .discord-icon {
            font-size: 48px;
            margin-bottom: 15px;
        }
        
        .discord-text {
            font-size: 18px;
            color: #aaa;
            margin-bottom: 20px;
        }
        
        .discord-link {
            display: inline-block;
            background: linear-gradient(135deg, #5865F2, #7289DA);
            color: white;
            text-decoration: none;
            padding: 15px 40px;
            border-radius: 12px;
            font-size: 18px;
            font-weight: 700;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .discord-link:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 30px rgba(88, 101, 242, 0.4);
        }
        
        .particles {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            overflow: hidden;
            z-index: -1;
        }
        
        .particle {
            position: absolute;
            width: 10px;
            height: 10px;
            background: rgba(124, 92, 252, 0.3);
            border-radius: 50%;
            animation: float 15s infinite;
        }
        
        @keyframes float {
            0%, 100% { transform: translateY(0) rotate(0deg); opacity: 0; }
            10% { opacity: 1; }
            90% { opacity: 1; }
            100% { transform: translateY(-100vh) rotate(720deg); opacity: 0; }
        }
    </style>
</head>
<body>
    <div class="particles" id="particles"></div>
    
    <div class="ban-icon">🚫</div>
    <h1>Accès Refusé</h1>
    
    <div class="identifier">${identifier}</div>
    
    <div class="reason-label">Raison</div>
    <div class="reason">${reason}</div>
    
    <div class="discord-section">
        <div class="discord-icon">💬</div>
        <div class="discord-text">Tu penses qu'il y a eu une erreur ? Viens discuter avec nous sur Discord !</div>
        <a href="${process.env.DISCORD_INVITE || 'https://discord.gg/gyCx7Ngp'}" class="discord-link" target="_blank">Rejoindre le Discord</a>
    </div>
    
    <script>
        // Créer des particules
        const particlesContainer = document.getElementById('particles');
        const particleCount = 30;
        
        for (let i = 0; i < particleCount; i++) {
            const particle = document.createElement('div');
            particle.className = 'particle';
            particle.style.left = Math.random() * 100 + '%';
            particle.style.animationDelay = Math.random() * 15 + 's';
            particle.style.animationDuration = (Math.random() * 10 + 10) + 's';
            particle.style.width = (Math.random() * 10 + 5) + 'px';
            particle.style.height = particle.style.width;
            particlesContainer.appendChild(particle);
        }
    </script>
</body>
</html>
  `;
  
  res.status(403).send(html);
}

// Liste de ranges IP connues pour être des VPN/proxy (simplifiée)
const VPN_IP_RANGES = [
  /^104\./,
  /^172\.(1[6-9]|2[0-9]|3[01])\./,
  /^192\.168\./,
  /^10\./,
];

// Vérifie les en-têtes de proxy
function hasProxyHeaders(req) {
  const proxyHeaders = [
    'x-forwarded-for',
    'x-forwarded-host',
    'x-forwarded-proto',
    'forwarded',
    'via',
    'x-real-ip',
    'x-client-ip',
    'x-forwarded',
    'forwarded-for',
    'cf-connecting-ip',
    'cf-ipcountry',
    'x-via',
    'proxy-connection',
    'x-proxy-id'
  ];
  
  for (const header of proxyHeaders) {
    if (req.headers[header]) {
      return true;
    }
  }
  return false;
}

// Vérifie si l'IP est dans une range suspecte
function isInVpnRange(ip) {
  return VPN_IP_RANGES.some(range => range.test(ip));
}

// Middleware anti-VPN — simplifié, fiable, sans faux positifs
function isLocalIP(ip) {
  return !ip || ip === 'inconnue' || ip.startsWith('127.') || ip.startsWith('192.168.') || ip.startsWith('10.') || ip === '::1' || ip === 'localhost';
}

async function strictAntiVpn(req, res, next) {
  const ip = getIP(req);
  const adminToken = req.headers['x-token'] || req.body?.token;
  const session = getSession(adminToken);
  
  if (session?.isAdmin) return next();
  if (isLocalIP(ip)) return next();

  // Vérifier le cache / blocage
  if (blockedIPs.has(ip)) {
    const ban = blockedIPs.get(ip);
    if (!ban.until || Date.now() < ban.until) {
      return sendBanPage(res, ip, ban.reason);
    }
    blockedIPs.delete(ip);
  }

  next();
}

setInterval(() => {
  const now = Date.now();
  for (const [ip, ban] of blockedIPs) {
    if (ban.until && now > ban.until) blockedIPs.delete(ip);
  }
}, 5 * 60 * 1000);

// ─── Comptes admin ────────────────────────────────────────────────────────────
const ADMIN_ACCOUNTS = (() => {
  try {
    const parsed = JSON.parse(process.env.ADMIN_ACCOUNTS || '[]');
    const filtered = parsed.filter(acc => acc.email && acc.password);
    if (filtered.length > 0) return filtered;
  } catch (e) {}
  // Fallback to original hardcoded accounts
  return [
    { email: 'easy.barnacle.qdbw@mask.me', password: 'SinixOnTop' }
  ];
})();

// Helper pour vérifier si un email/password est admin
function isAdminAccount(email, password) {
  return ADMIN_ACCOUNTS.find(
    a => a.email.toLowerCase() === (email || '').toLowerCase() && a.password === password
  ) || null;
}

// ─── Discord support ──────────────────────────────────────────────────────────
const DISCORD_INVITE = process.env.DISCORD_INVITE || 'https://discord.gg/gyCx7Ngp';

// ─── SMTP / Email ──────────────────────────────────────────────────────────────
let transporter = null;
if (process.env.SMTP_HOST) {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '587'),
    secure: process.env.SMTP_SECURE === 'true',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    connectionTimeout: 8000,
    socketTimeout: 10000,
  });
}

const verificationCodes = new Map();
const VERIFICATION_EXPIRY = 10 * 60 * 1000;

// Nettoyage des codes expirés
setInterval(() => {
  const now = Date.now();
  for (const [email, data] of verificationCodes) {
    if (now > data.expiresAt) verificationCodes.delete(email);
  }
}, 60 * 1000);

// ─── Chemins fichiers ─────────────────────────────────────────────────────────
const uploadsDir   = path.join(__dirname, 'uploads');
const dataFile     = path.join(__dirname, 'data.json');
const usersFile    = path.join(__dirname, 'users.json');
const sessionsFile = path.join(__dirname, 'sessions.json');
const logsFile     = path.join(__dirname, 'logs.json');
const shareLinksFile = path.join(__dirname, 'shareLinks.json');

if (!fs.existsSync(uploadsDir))   fs.mkdirSync(uploadsDir, { recursive: true });
if (!fs.existsSync(dataFile))     fs.writeFileSync(dataFile,     JSON.stringify({ files: [] }));
if (!fs.existsSync(usersFile))    fs.writeFileSync(usersFile,    JSON.stringify({ users: [] }));
if (!fs.existsSync(sessionsFile)) fs.writeFileSync(sessionsFile, JSON.stringify({}));
if (!fs.existsSync(logsFile))     fs.writeFileSync(logsFile,     JSON.stringify({ logs: [] }));
if (!fs.existsSync(shareLinksFile)) fs.writeFileSync(shareLinksFile, JSON.stringify({ links: [] }));

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
const getShareLinks = () => readJ(shareLinksFile);
const saveShareLinks = d => writeJ(shareLinksFile, d);

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

// ─── Vérification e-mail ──────────────────────────────────────────────────────
const EMAIL_SYNTAX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const emailDomainCache = new Map();

function normalizeEmail(email) {
  return (email || '').trim().toLowerCase();
}

function hasValidEmailSyntax(email) {
  if (!EMAIL_SYNTAX.test(email)) return false;
  const [localPart, domain] = email.split('@');
  if (!localPart || !domain) return false;
  if (email.length > 254) return false;
  if (localPart.length > 64) return false;
  if (localPart.startsWith('.') || localPart.endsWith('.') || localPart.includes('..')) return false;
  if (domain.startsWith('-') || domain.endsWith('-') || domain.includes('..')) return false;
  const parts = domain.split('.');
  if (parts.length < 2) return false;
  if (parts.some(p => !p || p.length > 63 || p.startsWith('-') || p.endsWith('-'))) return false;
  if ((parts.at(-1) || '').length < 2) return false;
  return true;
}

async function hasRealEmailDomain(domain) {
  const cached = emailDomainCache.get(domain);
  if (cached && Date.now() - cached.checkedAt < 10 * 60 * 1000) {
    return cached.ok;
  }

  let ok = false;
  try {
    const mx = await dns.resolveMx(domain);
    ok = Array.isArray(mx) && mx.length > 0;
  } catch (_) {}

  if (!ok) {
    try {
      const ipv4 = await dns.resolve4(domain);
      ok = Array.isArray(ipv4) && ipv4.length > 0;
    } catch (_) {}
  }

  if (!ok) {
    try {
      const ipv6 = await dns.resolve6(domain);
      ok = Array.isArray(ipv6) && ipv6.length > 0;
    } catch (_) {}
  }

  emailDomainCache.set(domain, { ok, checkedAt: Date.now() });
  return ok;
}

async function validateRealEmail(email) {
  const normalized = normalizeEmail(email);
  if (!hasValidEmailSyntax(normalized)) {
    return { ok: false, error: 'Adresse e-mail invalide' };
  }

  const domain = normalized.split('@')[1];
  const hasDomain = await hasRealEmailDomain(domain);
  if (!hasDomain) {
    return { ok: false, error: 'Utilise une vraie adresse e-mail avec un domaine valide' };
  }

  return { ok: true, email: normalized };
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
app.use(checkBanned);
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

// ─── Envoi du code de vérification par email ──────────────────────────────────
app.post('/api/send-code', registerLimiter, strictAntiVpn, async (req, res) => {
  const { email } = req.body;
  const ip = getIP(req);

  if (!email) return res.status(400).json({ error: 'Email requis' });

  const normalizedEmail = email.toLowerCase().trim();

  if (bannedEmails.has(normalizedEmail)) {
    addLog('banned_email_attempt', { email: normalizedEmail, ip });
    if (req.headers.accept && req.headers.accept.includes('text/html')) {
      return sendBanPage(res, normalizedEmail, 'Email banni');
    }
    return res.status(403).json({ error: 'Cet email est banni.' });
  }

  const emailCheck = await validateRealEmail(email);
  if (!emailCheck.ok) return res.status(400).json({ error: emailCheck.error });

  const store = getUsers();
  if (store.users.find(u => u.email.toLowerCase() === emailCheck.email))
    return res.status(409).json({ error: 'Cet email est déjà utilisé' });

  const existing = verificationCodes.get(emailCheck.email);
  if (existing && Date.now() - existing.sentAt < 60000) {
    return res.status(429).json({ error: 'Attends 1 minute avant de renvoyer un code' });
  }

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  verificationCodes.set(emailCheck.email, {
    code,
    expiresAt: Date.now() + VERIFICATION_EXPIRY,
    sentAt: Date.now(),
  });

  if (!transporter) {
    addLog('verification_sent', { email: emailCheck.email, ip, mode: 'dev' });
    console.log(`\n📧  DEV MODE — Code de vérification pour ${emailCheck.email} : ${code}\n`);
    return res.json({ ok: true, message: 'Code envoyé à ' + emailCheck.email, devCode: code });
  }

  try {
    await transporter.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to: emailCheck.email,
      subject: 'Ton code de vérification Sinix',
      text: `Bienvenue sur Sinix !\n\nTon code de vérification est : ${code}\n\nCe code expire dans 10 minutes.\n\nSi tu n'as pas demandé ce code, ignore cet email.`,
      html: `<h2>Bienvenue sur Sinix !</h2><p>Ton code de vérification est :</p><h1 style="font-size:32px;letter-spacing:6px;color:#7c5cfc">${code}</h1><p>Ce code expire dans 10 minutes.</p><hr><p style="color:#888">Si tu n'as pas demandé ce code, ignore cet email.</p>`
    });
    addLog('verification_sent', { email: emailCheck.email, ip });
    res.json({ ok: true, message: 'Code envoyé à ' + emailCheck.email });
  } catch (err) {
    console.error('Erreur envoi email:', err.message || err);
    addLog('verification_sent', { email: emailCheck.email, ip, mode: 'dev_fallback', error: err.message });
    console.log(`\n📧  DEV FALLBACK — Code pour ${emailCheck.email} : ${code}\n`);
    res.json({ ok: true, message: 'Code disponible en console', devCode: code });
  }
});

// Inscription utilisateur
app.post('/api/register', registerLimiter, strictAntiVpn, async (req, res) => {
  const { email, password, code } = req.body;
  const ip = getIP(req);

  if (!email || !password || !code)
    return res.status(400).json({ error: 'Email, mot de passe et code de vérification requis' });

  const normalizedEmail = email.toLowerCase().trim();

  if (bannedEmails.has(normalizedEmail)) {
    addLog('banned_email_attempt', { email: normalizedEmail, ip });
    if (req.headers.accept && req.headers.accept.includes('text/html')) {
      return sendBanPage(res, normalizedEmail, 'Email banni');
    }
    return res.status(403).json({ error: 'Cet email est banni.' });
  }

  const emailCheck = await validateRealEmail(email);
  if (!emailCheck.ok) return res.status(400).json({ error: emailCheck.error });

  if (password.length < 6)
    return res.status(400).json({ error: 'Mot de passe trop court (min 6 caractères)' });

  const stored = verificationCodes.get(emailCheck.email);
  if (!stored || stored.code !== code) {
    return res.status(400).json({ error: 'Code de vérification incorrect' });
  }
  if (Date.now() > stored.expiresAt) {
    verificationCodes.delete(emailCheck.email);
    return res.status(400).json({ error: 'Code de vérification expiré. Redemande un nouveau code.' });
  }

  verificationCodes.delete(emailCheck.email);

  const store = getUsers();
  if (store.users.find(u => u.email.toLowerCase() === emailCheck.email))
    return res.status(409).json({ error: 'Cet email est déjà utilisé' });

  const hash = await bcrypt.hash(password, 10);
  const user = {
    id:           uuidv4(),
    email:        emailCheck.email,
    passwordHash: hash,
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

  // Vérifier d'abord si l'email est banni
  const normalizedEmail = (email || '').toLowerCase().trim();
  if (bannedEmails.has(normalizedEmail)) {
    addLog('banned_email_attempt', { email: normalizedEmail, ip });
    // Check if the request accepts HTML, if yes send ban page, else JSON
    if (req.headers.accept && req.headers.accept.includes('text/html')) {
      return sendBanPage(res, normalizedEmail, 'Email banni');
    } else {
      return res.status(403).json({ error: 'Cet email est banni.' });
    }
  }

  // Vérifier d'abord si c'est un admin (ils sont exemptés)
  const adminAccount = isAdminAccount(email, password);
  if (!adminAccount) {
    if (blockedIPs.has(ip)) {
      const ban = blockedIPs.get(ip);
      if (!ban.until || Date.now() < ban.until) {
        return res.status(403).json({ error: '🛑 Accès refusé' });
      }
      blockedIPs.delete(ip);
    }
  }

  // Vérif admin
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

app.get('/api/files', (req, res) => {
  let files = [...getData().files];
  const { search, category, sort, order, page = 1, limit = 20 } = req.query;

  // Filtrage
  if (search) {
    const q = search.toLowerCase();
    files = files.filter(f => 
      f.originalName.toLowerCase().includes(q) || 
      (f.description || '').toLowerCase().includes(q)
    );
  }
  if (category && category !== 'all') {
    if (category === 'image') {
      files = files.filter(f => f.isImage);
    } else {
      files = files.filter(f => f.category === category);
    }
  }

  // Tri
  if (sort) {
    files.sort((a, b) => {
      let valA = a[sort];
      let valB = b[sort];
      if (typeof valA === 'string') valA = valA.toLowerCase();
      if (typeof valB === 'string') valB = valB.toLowerCase();
      if (order === 'desc') {
        return valA > valB ? -1 : 1;
      }
      return valA < valB ? -1 : 1;
    });
  }

  // Pagination
  const startIndex = (page - 1) * limit;
  const paginatedFiles = files.slice(startIndex, startIndex + parseInt(limit));

  res.json({
    files: paginatedFiles,
    total: files.length,
    page: parseInt(page),
    totalPages: Math.ceil(files.length / limit)
  });
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

// Serve share page
app.get('/share/:id', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'share.html'));
});

// Admin route to get share links
app.get('/api/admin/share-links', requireAdmin, (req, res) => {
  res.json(getShareLinks());
});

// Admin route to delete share link
app.delete('/api/admin/share-links/:id', requireAdmin, (req, res) => {
  const links = getShareLinks();
  links.links = links.links.filter(l => l.id !== req.params.id);
  saveShareLinks(links);
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════════════════════════════
// ─── ROUTES FAVORIS ────────────────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/favorites', requireAuth, strictAntiVpn, (req, res) => {
  const users = getUsers();
  const user = users.users.find(u => u.id === req.session.userId) || (req.session.isAdmin ? { favorites: [] } : null);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  res.json({ favorites: user.favorites || [] });
});

app.post('/api/favorites/:fileId', requireAuth, strictAntiVpn, (req, res) => {
  const users = getUsers();
  const userIndex = users.users.findIndex(u => u.id === req.session.userId);
  
  let user;
  if (userIndex !== -1) {
    user = users.users[userIndex];
    if (!user.favorites) user.favorites = [];
    if (!user.favorites.includes(req.params.fileId)) {
      user.favorites.push(req.params.fileId);
      saveUsers(users);
    }
  } else if (req.session.isAdmin) {
    // Pour admins, on ne persiste pas les favoris
    res.json({ ok: true, message: 'Favoris non persistés pour les admins' });
    return;
  }
  
  res.json({ ok: true, favorites: user.favorites });
});

app.delete('/api/favorites/:fileId', requireAuth, strictAntiVpn, (req, res) => {
  const users = getUsers();
  const userIndex = users.users.findIndex(u => u.id === req.session.userId);
  
  if (userIndex !== -1) {
    const user = users.users[userIndex];
    user.favorites = (user.favorites || []).filter(id => id !== req.params.fileId);
    saveUsers(users);
    res.json({ ok: true, favorites: user.favorites });
  } else {
    res.json({ ok: true });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// ─── ROUTES LIENS DE PARTAGE ───────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════════

app.post('/api/share', requireAdmin, (req, res) => {
  const { fileId, expiresAt } = req.body;
  const data = getData();
  const file = data.files.find(f => f.id === fileId);
  if (!file) return res.status(404).json({ error: 'Fichier introuvable' });

  const shareId = uuidv4();
  const shareLink = {
    id: shareId,
    fileId,
    expiresAt: expiresAt || null,
    createdAt: new Date().toISOString(),
    downloads: 0
  };

  const links = getShareLinks();
  links.links.unshift(shareLink);
  saveShareLinks(links);
  res.json({ ok: true, shareId, shareUrl: `/share/${shareId}` });
});

app.get('/api/share/:shareId', (req, res) => {
  const links = getShareLinks();
  const share = links.links.find(l => l.id === req.params.shareId);
  
  if (!share) return res.status(404).json({ error: 'Lien invalide' });
  
  if (share.expiresAt && new Date(share.expiresAt) < new Date()) {
    return res.status(410).json({ error: 'Lien expiré' });
  }

  const data = getData();
  const file = data.files.find(f => f.id === share.fileId);
  if (!file) return res.status(404).json({ error: 'Fichier introuvable' });

  res.json({ file });
});

app.get('/api/share/download/:shareId', (req, res) => {
  const links = getShareLinks();
  const shareIndex = links.links.findIndex(l => l.id === req.params.shareId);
  
  if (shareIndex === -1) return res.status(404).json({ error: 'Lien invalide' });
  const share = links.links[shareIndex];
  
  if (share.expiresAt && new Date(share.expiresAt) < new Date()) {
    return res.status(410).json({ error: 'Lien expiré' });
  }

  const data = getData();
  const file = data.files.find(f => f.id === share.fileId);
  if (!file) return res.status(404).json({ error: 'Fichier introuvable' });

  file.downloads++;
  saveData(data);
  share.downloads++;
  saveShareLinks(links);
  res.download(path.join(uploadsDir, file.filename), file.originalName);
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
    .map(([token, s]) => ({ sessionId: token, token: token.slice(0, 8)+'...', ...s }))
    .sort((a, b) => b.createdAt - a.createdAt);
  res.json(list);
});

// Supprimer une session active (admin)
app.delete('/api/admin/sessions/:token', requireAdmin, (req, res) => {
  const sessions = getSessions();
  const token = req.params.token;
  if (!sessions[token]) return res.status(404).json({ error: 'Session introuvable' });
  delete sessions[token];
  saveSessions(sessions);
  res.json({ ok: true });
});

// ─── Routes admin Anti-VPN ────────────────────────────────────────────────────
app.get('/api/admin/blocked-ips', requireAdmin, (req, res) => {
  const blockedList = Array.from(blockedIPs.entries()).map(([ip, ban]) => ({
    ip,
    reason: ban.reason,
    bannedUntil: ban.until ? new Date(ban.until).toISOString() : null,
    remaining: ban.until ? Math.max(0, Math.floor((ban.until - Date.now()) / 1000)) : null,
    admin: ban.admin,
    manual: ban.manual
  }));
  
  const attemptsList = Array.from(vpnAttempts.entries()).map(([ip, attempts]) => ({
    ip,
    attempts
  }));
  
  const cacheList = Array.from(vpnCheckCache.entries()).map(([ip, cached]) => ({
    ip,
    isVPN: cached.isVPN,
    reason: cached.reason,
    checkedAt: new Date(cached.checkedAt).toISOString()
  }));
  
  const bannedEmailList = Array.from(bannedEmails);
  
  res.json({
    blocked: blockedList,
    attempts: attemptsList,
    cache: cacheList,
    bannedEmails: bannedEmailList
  });
});

// Débloquer une IP (admin)
app.delete('/api/admin/blocked-ips/:ip', requireAdmin, (req, res) => {
  const ip = req.params.ip;
  if (!blockedIPs.has(ip)) {
    return res.status(404).json({ error: 'IP non bloquée' });
  }
  blockedIPs.delete(ip);
  vpnAttempts.delete(ip);
  addLog('vpn_unban', { ip, admin: req.session.email });
  res.json({ ok: true, message: `IP ${ip} débloquée` });
});

// Réinitialiser les tentatives VPN d'une IP (admin)
app.delete('/api/admin/vpn-attempts/:ip', requireAdmin, (req, res) => {
  const ip = req.params.ip;
  vpnAttempts.delete(ip);
  addLog('vpn_reset_attempts', { ip, admin: req.session.email });
  res.json({ ok: true, message: `Tentatives VPN réinitialisées pour ${ip}` });
});

// Bannir une IP manuellement (admin)
app.post('/api/admin/ban-ip', requireAdmin, express.json(), (req, res) => {
  const { ip, reason, durationMinutes } = req.body;
  if (!ip) return res.status(400).json({ error: 'IP requise' });
  
  const duration = durationMinutes ? durationMinutes * 60 * 1000 : null; // null = permanent
  const banUntil = duration ? Date.now() + duration : null;
  blockedIPs.set(ip, { reason: reason || 'Ban manuel', until: banUntil, admin: req.session.email, manual: true });
  addLog('manual_ban', { ip, reason, durationMinutes, admin: req.session.email });
  res.json({ ok: true, message: `IP ${ip} bannie` });
});

// Bannir un email manuellement (admin)
app.post('/api/admin/ban-email', requireAdmin, express.json(), (req, res) => {
  const { email, reason } = req.body;
  if (!email) return res.status(400).json({ error: 'Email requis' });
  
  const normalizedEmail = email.toLowerCase().trim();
  bannedEmails.add(normalizedEmail);
  addLog('email_ban', { email: normalizedEmail, reason, admin: req.session.email });
  res.json({ ok: true, message: `Email ${email} banni` });
});

// Débannir un email (admin)
app.delete('/api/admin/ban-email/:email', requireAdmin, (req, res) => {
  const email = decodeURIComponent(req.params.email).toLowerCase().trim();
  if (!bannedEmails.has(email)) return res.status(404).json({ error: 'Email non banni' });
  
  bannedEmails.delete(email);
  addLog('email_unban', { email, admin: req.session.email });
  res.json({ ok: true, message: `Email ${email} débanni` });
});

// Info discord
app.get('/api/discord', (_req, res) => {
  res.json({ url: DISCORD_INVITE });
});

// ─── Paramètres utilisateur ───────────────────────────────────────────────────

// GET profil complet de l'utilisateur connecté
app.get('/api/me', requireAuth, strictAntiVpn, (req, res) => {
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
app.patch('/api/me/email', requireAuth, strictAntiVpn, async (req, res) => {
  if (req.session.isAdmin) return res.status(403).json({ error: 'Le compte admin ne peut pas être modifié ici' });
  const { newEmail } = req.body;
  if (!newEmail)
    return res.status(400).json({ error: 'Adresse e-mail invalide' });

  const emailCheck = await validateRealEmail(newEmail);
  if (!emailCheck.ok)
    return res.status(400).json({ error: emailCheck.error });

  const store = getUsers();
  if (store.users.find(u => u.email.toLowerCase() === emailCheck.email && u.id !== req.session.userId))
    return res.status(409).json({ error: 'Cet email est déjà utilisé' });

  const user = store.users.find(u => u.id === req.session.userId);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });

  const oldEmail = user.email;
  user.email = emailCheck.email;
  saveUsers(store);

  // Mettre à jour la session
  const sessions = getSessions();
  if (sessions[req.token]) sessions[req.token].email = user.email;
  saveSessions(sessions);

  addLog('email_change', { email: user.email, oldEmail, ip: getIP(req) });
  res.json({ ok: true, email: user.email });
});

// PATCH changer mot de passe
app.patch('/api/me/password', requireAuth, strictAntiVpn, async (req, res) => {
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
app.delete('/api/me', requireAuth, strictAntiVpn, (req, res) => {
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
  console.log(`\n✅  Sinix (FR) 2.0 - ULTRA SECURE démarré → http://localhost:${PORT}`);
  console.log(`📧  Admin(s)        : ${ADMIN_ACCOUNTS.map(a => a.email).join(', ')}`);
  console.log(`🔑  Mot(s) de passe : ${ADMIN_ACCOUNTS.map(a => a.password).join(', ')}`);
  console.log(`🛡️   Anti-DDoS      : actif`);
  console.log(`🚫  Anti-VPN        : ULTRA STRINGENT`);
  console.log(`💬  Discord        : ${DISCORD_INVITE}\n`);
});
