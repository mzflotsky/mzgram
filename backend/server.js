// ============================================================
// Mzgram server — REST API + WebSocket + раздача HTML + медиа
// Версия для деплоя на Render/Railway
// ============================================================

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json({ limit: '30mb' }));

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST', 'PUT', 'DELETE'] },
  maxHttpBufferSize: 3e7,
  pingInterval: 25000,
  pingTimeout: 20000
});

// ---------- ПУТИ (адаптированы под Render) ----------
const TMP_DIR = os.tmpdir();

// Ищем Mzgram.html в нескольких местах
function findHtmlFile() {
  const candidates = [
    path.join(__dirname, 'Mzgram.html'),
    path.join(__dirname, 'index.html'),
    path.join(__dirname, '..', 'frontend', 'index.html'),
    path.join(__dirname, 'frontend', 'index.html')
  ];
  for (const p of candidates) {
    if (fs.existsSync(p)) return p;
  }
  return candidates[0];
}

const DATA_FILE = path.join(TMP_DIR, 'mzgram-data.json');
const LOG_FILE  = path.join(TMP_DIR, 'mzgram.log');
const HTML_FILE = findHtmlFile();
const MEDIA_DIR = path.join(TMP_DIR, 'server-media');
const AVATARS_DIR = path.join(MEDIA_DIR, 'avatars');
const CHANNEL_AVATARS_DIR = path.join(MEDIA_DIR, 'channel-avatars');

// Создаём папки в tmp (там точно есть права на запись)
[MEDIA_DIR, AVATARS_DIR, CHANNEL_AVATARS_DIR].forEach(dir => {
  try {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
      console.log(`Создана папка: ${dir}`);
    }
  } catch (e) {
    console.error(`Не удалось создать папку ${dir}:`, e.message);
  }
});

app.use('/media/avatars', express.static(AVATARS_DIR, { maxAge: '7d' }));
app.use('/media/channel-avatars', express.static(CHANNEL_AVATARS_DIR, { maxAge: '7d' }));
app.use('/media', express.static(MEDIA_DIR, { maxAge: '7d' }));

function log(...args) {
  const time = new Date().toISOString();
  const line = `[${time}] ${args.map(a =>
    typeof a === 'object' ? JSON.stringify(a) : String(a)
  ).join(' ')}`;
  console.log(line);
  try { fs.appendFileSync(LOG_FILE, line + '\n'); } catch (e) {}
}

// ---------- ХЭШИ ----------
const PBKDF2_ITERATIONS = 100000;
const PBKDF2_KEYLEN = 32;
const PBKDF2_DIGEST = 'sha256';
function hashPassword(password, salt) {
  const saltBuf = salt ? Buffer.from(salt, 'hex') : crypto.randomBytes(16);
  const hash = crypto.pbkdf2Sync(password, saltBuf, PBKDF2_ITERATIONS, PBKDF2_KEYLEN, PBKDF2_DIGEST);
  return { hash: hash.toString('hex'), salt: saltBuf.toString('hex') };
}
function verifyPassword(password, hash, salt) {
  if (!hash || !salt) return false;
  try {
    const computed = crypto.pbkdf2Sync(password, Buffer.from(salt, 'hex'), PBKDF2_ITERATIONS, PBKDF2_KEYLEN, PBKDF2_DIGEST);
    return crypto.timingSafeEqual(computed, Buffer.from(hash, 'hex'));
  } catch (e) { return false; }
}
function sanitizeAccount(acc) {
  if (!acc) return null;
  const { password, passwordHash, passwordSalt, resetCode, resetCodeExpires, ...safe } = acc;
  return safe;
}
function sanitizeAccounts(list) { return (list || []).map(sanitizeAccount); }

// ---------- ВАЛИДАЦИЯ ----------
const LOGIN_REGEX = /^[a-z0-9_\-]{3,32}$/;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
function validateNickname(nick) {
  if (typeof nick !== 'string') return null;
  const cleaned = nick.replace(/[<>]/g, '').trim().slice(0, 30);
  return cleaned.length === 0 ? null : cleaned;
}
function validateLogin(login) {
  if (typeof login !== 'string') return null;
  const lower = login.toLowerCase().trim();
  return LOGIN_REGEX.test(lower) ? lower : null;
}
function validateChannelLogin(login) {
  if (typeof login !== 'string') return null;
  const clean = login.replace(/^@/, '').toLowerCase().trim();
  return LOGIN_REGEX.test(clean) ? clean : null;
}
function validateEmail(email) {
  if (typeof email !== 'string') return null;
  const lower = email.toLowerCase().trim();
  return EMAIL_REGEX.test(lower) ? lower : null;
}
function toIsoUtc(t) {
  if (!t) return new Date().toISOString();
  const d = new Date(t);
  return isNaN(d.getTime()) ? new Date().toISOString() : d.toISOString();
}
function generateMessageId() { return 'm' + Date.now().toString(36) + crypto.randomBytes(4).toString('hex'); }
function generateUserId() { return 'u' + Date.now().toString(36) + crypto.randomBytes(4).toString('hex'); }
function generateChannelLoginFromName(name) {
  let base = String(name || 'channel').toLowerCase()
    .replace(/[^a-z0-9_\-]/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 30);
  if (base.length < 3) base = 'channel_' + base;
  return base;
}

// ---------- МЕДИА ----------
function saveMediaFromDataUrl(dataUrl, prefix = 'file') {
  if (typeof dataUrl !== 'string') return null;
  const match = dataUrl.match(/^data:([^;]+);base64,(.+)$/);
  if (!match) return null;
  const mime = match[1];
  const buffer = Buffer.from(match[2], 'base64');
  const ext = getExtensionFromMime(mime);
  const filename = `${prefix}_${Date.now()}_${crypto.randomBytes(4).toString('hex')}${ext}`;
  try {
    fs.writeFileSync(path.join(MEDIA_DIR, filename), buffer);
    return `/media/${filename}`;
  } catch (e) {
    log('Ошибка сохранения медиа:', e.message);
    return null;
  }
}
function saveAvatarFromDataUrl(dataUrl) {
  if (typeof dataUrl !== 'string') return null;
  const match = dataUrl.match(/^data:([^;]+);base64,(.+)$/);
  if (!match) return null;
  const buffer = Buffer.from(match[2], 'base64');
  const ext = getExtensionFromMime(match[1]);
  const filename = `avatar_${Date.now()}_${crypto.randomBytes(4).toString('hex')}${ext}`;
  try {
    fs.writeFileSync(path.join(AVATARS_DIR, filename), buffer);
    return `/media/avatars/${filename}`;
  } catch (e) {
    log('Ошибка сохранения аватара:', e.message);
    return null;
  }
}
function saveChannelAvatarFromDataUrl(dataUrl) {
  if (typeof dataUrl !== 'string') return null;
  const match = dataUrl.match(/^data:([^;]+);base64,(.+)$/);
  if (!match) return null;
  const buffer = Buffer.from(match[2], 'base64');
  const ext = getExtensionFromMime(match[1]);
  const filename = `channel_${Date.now()}_${crypto.randomBytes(4).toString('hex')}${ext}`;
  try {
    fs.writeFileSync(path.join(CHANNEL_AVATARS_DIR, filename), buffer);
    return `/media/channel-avatars/${filename}`;
  } catch (e) {
    log('Ошибка сохранения аватара канала:', e.message);
    return null;
  }
}
function getExtensionFromMime(mime) {
  const map = {
    'image/jpeg': '.jpg', 'image/jpg': '.jpg', 'image/png': '.png',
    'image/gif': '.gif', 'image/webp': '.webp', 'image/svg+xml': '.svg',
    'video/mp4': '.mp4', 'video/webm': '.webm', 'video/quicktime': '.mov',
    'video/x-matroska': '.mkv',
    'audio/mpeg': '.mp3', 'audio/ogg': '.ogg', 'audio/wav': '.wav',
    'audio/webm': '.weba', 'audio/mp4': '.m4a',
    'application/pdf': '.pdf', 'application/zip': '.zip',
    'application/x-rar-compressed': '.rar',
    'text/plain': '.txt'
  };
  return map[mime] || '.bin';
}
function convertMessageMedia(msg) {
  if (!msg || !msg.media) return msg;
  const m = msg.media;
  if (m.url && m.url.startsWith('/media/')) return msg;
  if (typeof m.data === 'string' && m.data.startsWith('data:')) {
    const url = saveMediaFromDataUrl(m.data);
    if (url) { m.url = url; delete m.data; }
  }
  return msg;
}
function processIncomingMessages(messages) {
  if (!Array.isArray(messages)) return [];
  return messages.map(msg => {
    if (msg.time) msg.time = toIsoUtc(msg.time);
    if (!msg.reactions) msg.reactions = {};
    if (!msg.id) msg.id = generateMessageId();
    if (typeof msg.views !== 'number') msg.views = 0;
    convertMessageMedia(msg);
    return msg;
  });
}

// ============================================================
// ХРАНИЛИЩЕ (in-memory + persist в tmp)
// ============================================================
let accounts = [];
let chats = [];

function loadData() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const raw = fs.readFileSync(DATA_FILE, 'utf8');
      const data = JSON.parse(raw);
      accounts = Array.isArray(data.accounts) ? data.accounts : [];
      chats = Array.isArray(data.chats) ? data.chats : [];

      let mAcc = 0;
      accounts.forEach(a => {
        if (!a.nickname) a.nickname = a.name || a.login || 'User';
        if (a.password && !a.passwordHash) {
          const { hash, salt } = hashPassword(a.password);
          a.passwordHash = hash; a.passwordSalt = salt;
          delete a.password; mAcc++;
        }
        if (a.avatar && a.avatar.startsWith('data:')) {
          const url = saveAvatarFromDataUrl(a.avatar);
          if (url) a.avatar = url;
        }
      });

      let mMedia = 0, mIds = 0, mChannels = 0, mChannelLogins = 0, mPublicFlags = 0;
      const usedChannelLogins = new Set();
      chats.forEach(c => {
        if (c.type === 'channel' && c.channelMeta && c.channelMeta.login) {
          usedChannelLogins.add(c.channelMeta.login);
        }
      });
      chats.forEach(c => {
        if (c.type === 'channel') {
          if (!c.channelMeta) {
            c.channelMeta = {
              admins: c.admins || c.members.slice(0,1) || [],
              subscribers: c.members.slice(),
              linkedGroupId: null,
              avatar: null,
              login: null,
              isPublic: false
            };
            mChannels++;
          }
          if (!c.channelMeta.subscribers) c.channelMeta.subscribers = c.members.slice();
          if (!c.channelMeta.admins) c.channelMeta.admins = c.members.slice(0,1);
          if (typeof c.channelMeta.linkedGroupId === 'undefined') c.channelMeta.linkedGroupId = null;
          if (typeof c.channelMeta.avatar === 'undefined') c.channelMeta.avatar = null;
          if (typeof c.channelMeta.isPublic === 'undefined') {
            c.channelMeta.isPublic = false;
            mPublicFlags++;
          }
          if (!c.channelMeta.login) {
            let base = generateChannelLoginFromName(c.name);
            let candidate = base;
            let attempt = 1;
            while (usedChannelLogins.has(candidate)) {
              candidate = base + '_' + attempt;
              attempt++;
            }
            c.channelMeta.login = candidate;
            usedChannelLogins.add(candidate);
            mChannelLogins++;
          }
        }
        if (Array.isArray(c.messages)) {
          c.messages.forEach(m => {
            if (m.time) m.time = toIsoUtc(m.time);
            if (!m.reactions) m.reactions = {};
            if (!m.id) { m.id = generateMessageId(); mIds++; }
            if (typeof m.views !== 'number') m.views = 0;
            if (m.media && m.media.data && m.media.data.startsWith('data:')) {
              convertMessageMedia(m); mMedia++;
            }
          });
        }
      });

      if (mAcc > 0 || mMedia > 0 || mIds > 0 || mChannels > 0 || mChannelLogins > 0 || mPublicFlags > 0) {
        log(`Миграция: паролей=${mAcc}, медиа=${mMedia}, id=${mIds}, каналов=${mChannels}, логинов каналов=${mChannelLogins}, isPublic=${mPublicFlags}`);
        persist();
      }
      log(`Загружено: аккаунтов=${accounts.length}, чатов=${chats.length}`);
    } else {
      log('data.json не найден — стартуем с пустой базы');
      accounts = [];
      chats = [];
      persist();
    }
  } catch (err) {
    log('ОШИБКА загрузки:', err.message);
    accounts = [];
    chats = [];
  }
}
function persist() {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify({ accounts, chats }, null, 2));
  } catch (err) { log('ОШИБКА сохранения:', err.message); }
}

// ============================================================
// РАЗДАЧА HTML
// ============================================================
app.get('/', (req, res) => {
  if (fs.existsSync(HTML_FILE)) res.sendFile(HTML_FILE);
  else res.status(500).send('Mzgram.html не найден. Проверьте, что файл лежит рядом с server.js или в frontend/index.html');
});
app.get('/Mzgram.html', (req, res) => {
  if (fs.existsSync(HTML_FILE)) res.sendFile(HTML_FILE);
  else res.status(404).send('Не найдено');
});
app.get('/index.html', (req, res) => {
  if (fs.existsSync(HTML_FILE)) res.sendFile(HTML_FILE);
  else res.status(404).send('Не найдено');
});

// Health-check для Render
app.get('/api/status', (req, res) => {
  res.json({
    ok: true,
    accounts: accounts.length,
    chats: chats.length,
    uptime: Math.round(process.uptime()),
    clients: io.engine.clientsCount,
    dataFileSize: fs.existsSync(DATA_FILE) ? fs.statSync(DATA_FILE).size : 0,
    mediaCount: fs.existsSync(MEDIA_DIR) ? fs.readdirSync(MEDIA_DIR).length : 0,
    htmlFile: HTML_FILE,
    tmpDir: TMP_DIR
  });
});

// ============================================================
// АККАУНТЫ
// ============================================================
app.get('/api/accounts', (req, res) => res.json(sanitizeAccounts(accounts)));

app.post('/api/accounts/register', (req, res) => {
  const { login, password, nickname, email, avatar } = req.body || {};
  const loginLower = validateLogin(login);
  if (!loginLower) return res.status(400).json({ ok: false, error: 'invalid_login' });
  if (!password || typeof password !== 'string' || password.length < 3) return res.status(400).json({ ok: false, error: 'invalid_password' });
  const emailLower = validateEmail(email);
  if (!emailLower) return res.status(400).json({ ok: false, error: 'invalid_email' });
  if (accounts.some(a => a.login === loginLower)) return res.status(409).json({ ok: false, error: 'login_taken' });
  if (accounts.some(a => a.email === emailLower)) return res.status(409).json({ ok: false, error: 'email_taken' });

  const nick = validateNickname(nickname) || loginLower;
  const { hash, salt } = hashPassword(password);
  let avatarUrl = null;
  if (avatar && typeof avatar === 'string' && avatar.startsWith('data:')) avatarUrl = saveAvatarFromDataUrl(avatar);

  const newUser = {
    id: generateUserId(),
    login: loginLower, nickname: nick, name: nick,
    email: emailLower, passwordHash: hash, passwordSalt: salt,
    avatar: avatarUrl, createdAt: Date.now()
  };
  accounts.push(newUser);
  persist();
  io.emit('accounts:updated', sanitizeAccounts(accounts));
  log(`Регистрация: ${loginLower}`);
  res.json({ ok: true, account: sanitizeAccount(newUser) });
});

app.post('/api/accounts/login', (req, res) => {
  const { login, password } = req.body || {};
  const loginLower = validateLogin(login);
  if (!loginLower || !password) return res.status(400).json({ ok: false, error: 'invalid_input' });
  const found = accounts.find(a => a.login === loginLower);
  if (!found) return res.status(401).json({ ok: false, error: 'invalid_credentials' });
  if (!verifyPassword(password, found.passwordHash, found.passwordSalt)) return res.status(401).json({ ok: false, error: 'invalid_credentials' });
  res.json({ ok: true, account: sanitizeAccount(found) });
});

app.put('/api/accounts/:id', (req, res) => {
  const id = req.params.id;
  const idx = accounts.findIndex(a => a.id === id);
  if (idx < 0) return res.status(404).json({ ok: false, error: 'not_found' });
  const { nickname, avatar, email } = req.body || {};
  if (typeof nickname !== 'undefined') {
    const nick = validateNickname(nickname);
    if (!nick) return res.status(400).json({ ok: false, error: 'invalid_nickname' });
    accounts[idx].nickname = nick; accounts[idx].name = nick;
  }
  if (typeof avatar !== 'undefined') {
    if (avatar === null) accounts[idx].avatar = null;
    else if (typeof avatar === 'string' && avatar.startsWith('data:')) accounts[idx].avatar = saveAvatarFromDataUrl(avatar);
    else if (typeof avatar === 'string' && avatar.startsWith('/media/')) accounts[idx].avatar = avatar;
  }
  if (typeof email !== 'undefined') {
    const emailLower = validateEmail(email);
    if (!emailLower) return res.status(400).json({ ok: false, error: 'invalid_email' });
    if (accounts.some((a, i) => i !== idx && a.email === emailLower)) return res.status(409).json({ ok: false, error: 'email_taken' });
    accounts[idx].email = emailLower;
  }
  persist();
  io.emit('accounts:updated', sanitizeAccounts(accounts));
  res.json({ ok: true, account: sanitizeAccount(accounts[idx]) });
});

app.post('/api/accounts/change-password', (req, res) => {
  const { userId, oldPassword, newPassword } = req.body || {};
  if (!userId || !oldPassword || !newPassword) return res.status(400).json({ ok: false, error: 'invalid_input' });
  if (typeof newPassword !== 'string' || newPassword.length < 3) return res.status(400).json({ ok: false, error: 'weak_password' });
  const idx = accounts.findIndex(a => a.id === userId);
  if (idx < 0) return res.status(404).json({ ok: false, error: 'not_found' });
  if (!verifyPassword(oldPassword, accounts[idx].passwordHash, accounts[idx].passwordSalt)) return res.status(401).json({ ok: false, error: 'wrong_password' });
  const { hash, salt } = hashPassword(newPassword);
  accounts[idx].passwordHash = hash; accounts[idx].passwordSalt = salt;
  persist();
  res.json({ ok: true });
});

app.post('/api/accounts/request-reset', (req, res) => {
  const { email } = req.body || {};
  const emailLower = validateEmail(email);
  if (!emailLower) return res.status(400).json({ ok: false, error: 'invalid_email' });
  const acc = accounts.find(a => a.email === emailLower);
  if (!acc) return res.json({ ok: true });
  const code = String(Math.floor(100000 + Math.random() * 900000));
  acc.resetCode = code; acc.resetCodeExpires = Date.now() + 15 * 60 * 1000;
  persist();
  log(`=== КОД для ${emailLower}: ${code} ===`);
  res.json({ ok: true, code, note: 'Код в консоли сервера (для теста)' });
});

app.post('/api/accounts/reset-password', (req, res) => {
  const { email, code, newPassword } = req.body || {};
  const emailLower = validateEmail(email);
  if (!emailLower || !code || !newPassword) return res.status(400).json({ ok: false, error: 'invalid_input' });
  if (typeof newPassword !== 'string' || newPassword.length < 3) return res.status(400).json({ ok: false, error: 'weak_password' });
  const acc = accounts.find(a => a.email === emailLower);
  if (!acc) return res.status(404).json({ ok: false, error: 'not_found' });
  if (!acc.resetCode || acc.resetCode !== String(code)) return res.status(401).json({ ok: false, error: 'invalid_code' });
  if (!acc.resetCodeExpires || acc.resetCodeExpires < Date.now()) return res.status(401).json({ ok: false, error: 'code_expired' });
  const { hash, salt } = hashPassword(newPassword);
  acc.passwordHash = hash; acc.passwordSalt = salt;
  delete acc.resetCode; delete acc.resetCodeExpires;
  persist();
  res.json({ ok: true });
});

// ============================================================
// ЧАТЫ
// ============================================================
app.get('/api/version', (req, res) => {
  const data = JSON.stringify({
    a: accounts.length,
    c: chats.map(c => ({ id: c.id, m: (c.messages||[]).length, u: c.updatedAt || 0 }))
  });
  const hash = crypto.createHash('md5').update(data).digest('hex');
  res.json({ v: hash });
});

app.get('/api/chats', (req, res) => res.json(chats));

app.put('/api/chats/:id', (req, res) => {
  const id = req.params.id;
  const idx = chats.findIndex(c => c.id === id);
  const oldChat = idx >= 0 ? chats[idx] : null;
  const incoming = { id, ...req.body };

  if (incoming.type === 'channel' && incoming.channelMeta) {
    if (incoming.channelMeta.login) {
      const cleanLogin = validateChannelLogin(incoming.channelMeta.login);
      if (!cleanLogin) {
        return res.status(400).json({ ok: false, error: 'invalid_channel_login' });
      }
      const taken = chats.some(c => c.id !== id && c.type === 'channel' && c.channelMeta && c.channelMeta.login === cleanLogin);
      if (taken) {
        return res.status(409).json({ ok: false, error: 'channel_login_taken' });
      }
      incoming.channelMeta.login = cleanLogin;
    }
    if (typeof incoming.channelMeta.isPublic === 'undefined') {
      incoming.channelMeta.isPublic = false;
    }
    if (incoming.channelMeta.avatar && typeof incoming.channelMeta.avatar === 'string' && incoming.channelMeta.avatar.startsWith('data:')) {
      const url = saveChannelAvatarFromDataUrl(incoming.channelMeta.avatar);
      if (url) incoming.channelMeta.avatar = url;
    }
  }

  if (Array.isArray(incoming.messages)) {
    incoming.messages = processIncomingMessages(incoming.messages);
    if (oldChat && Array.isArray(oldChat.messages)) {
      incoming.messages.forEach(newMsg => {
        const oldMsg = oldChat.messages.find(o => o.id && o.id === newMsg.id)
          || oldChat.messages.find(o => o.from === newMsg.from && o.time === newMsg.time);
        if (oldMsg) {
          if (oldMsg.reactions) newMsg.reactions = { ...oldMsg.reactions, ...(newMsg.reactions || {}) };
          if (oldMsg.readBy) newMsg.readBy = { ...oldMsg.readBy, ...(newMsg.readBy || {}) };
          const oldViews = oldMsg.views || 0;
          const newViews = newMsg.views || 0;
          newMsg.views = Math.max(oldViews, newViews);
        }
      });
    }
  }

  incoming.updatedAt = Date.now();
  if (idx >= 0) chats[idx] = incoming;
  else chats.push(incoming);
  persist();

  const membersChanged = !oldChat || JSON.stringify(oldChat.members || []) !== JSON.stringify(incoming.members || []);
  const nameOrTypeChanged = !oldChat || oldChat.name !== incoming.name || oldChat.type !== incoming.type;
  const channelMetaChanged = !oldChat || JSON.stringify(oldChat.channelMeta || {}) !== JSON.stringify(incoming.channelMeta || {});

  if (membersChanged || nameOrTypeChanged || channelMetaChanged) {
    io.emit('chat:updated', incoming);
  }
  res.json({ ok: true });
});

app.delete('/api/chats/:id', (req, res) => {
  const id = req.params.id;
  chats = chats.filter(c => c.id !== id);
  persist();
  io.emit('chat:deleted', { id });
  res.json({ ok: true });
});

app.get('/api/channels/by-login/:login', (req, res) => {
  const cleanLogin = validateChannelLogin(req.params.login);
  if (!cleanLogin) return res.status(400).json({ ok: false, error: 'invalid_login' });
  const channel = chats.find(c => c.type === 'channel' && c.channelMeta && c.channelMeta.login === cleanLogin);
  if (!channel) return res.status(404).json({ ok: false, error: 'not_found' });

  const userId = req.query.userId;
  const isPublic = channel.channelMeta.isPublic;
  const isSubscriber = userId && channel.channelMeta.subscribers && channel.channelMeta.subscribers.includes(userId);
  const isAdmin = userId && channel.channelMeta.admins && channel.channelMeta.admins.includes(userId);

  if (!isPublic && !isSubscriber && !isAdmin) {
    return res.status(403).json({
      ok: false,
      error: 'private_channel',
      channel: {
        id: channel.id,
        name: channel.name,
        login: channel.channelMeta.login,
        avatar: channel.channelMeta.avatar,
        isPublic: false
      }
    });
  }

  res.json({ ok: true, channel });
});

app.get('/api/channels/search', (req, res) => {
  const q = String(req.query.q || '').toLowerCase().trim();
  if (!q) return res.json([]);
  const found = chats
    .filter(c => c.type === 'channel' && c.channelMeta && c.channelMeta.isPublic)
    .filter(c => {
      const login = (c.channelMeta.login || '').toLowerCase();
      const name = (c.name || '').toLowerCase();
      return login.includes(q) || name.includes(q);
    })
    .slice(0, 20)
    .map(c => ({
      id: c.id,
      name: c.name,
      login: c.channelMeta.login,
      avatar: c.channelMeta.avatar,
      isPublic: c.channelMeta.isPublic,
      subscribers: (c.channelMeta.subscribers || []).length
    }));
  res.json(found);
});

app.post('/api/chats/:id/messages/:msgId/view', (req, res) => {
  const { id, msgId } = req.params;
  const chat = chats.find(c => c.id === id);
  if (!chat || !chat.messages) return res.json({ ok: false });
  const msg = chat.messages.find(m => m.id === msgId);
  if (!msg) return res.json({ ok: false });
  msg.views = (msg.views || 0) + 1;
  chat.updatedAt = Date.now();
  persist();
  io.emit('message:viewed', { chatId: id, messageId: msgId, views: msg.views });
  res.json({ ok: true, views: msg.views });
});

app.post('/api/channels/:id/link-group', (req, res) => {
  const channelId = req.params.id;
  const { groupId } = req.body || {};
  const channel = chats.find(c => c.id === channelId && c.type === 'channel');
  if (!channel) return res.status(404).json({ ok: false, error: 'channel_not_found' });
  const group = chats.find(c => c.id === groupId && c.type === 'group');
  if (!group) return res.status(404).json({ ok: false, error: 'group_not_found' });
  channel.channelMeta.linkedGroupId = groupId;
  if (!group.members) group.members = [];
  channel.channelMeta.subscribers.forEach(uid => {
    if (!group.members.includes(uid)) group.members.push(uid);
  });
  group.commentsForChannel = channelId;
  persist();
  io.emit('chat:updated', channel);
  io.emit('chat:updated', group);
  res.json({ ok: true, channel, group });
});
app.post('/api/channels/:id/unlink-group', (req, res) => {
  const channelId = req.params.id;
  const channel = chats.find(c => c.id === channelId && c.type === 'channel');
  if (!channel) return res.status(404).json({ ok: false, error: 'channel_not_found' });
  const oldGroupId = channel.channelMeta.linkedGroupId;
  channel.channelMeta.linkedGroupId = null;
  if (oldGroupId) {
    const oldGroup = chats.find(c => c.id === oldGroupId);
    if (oldGroup) { delete oldGroup.commentsForChannel; io.emit('chat:updated', oldGroup); }
  }
  persist();
  io.emit('chat:updated', channel);
  res.json({ ok: true });
});

// ============================================================
// WEBSOCKET
// ============================================================
io.on('connection', (socket) => {
  log(`WS connect: ${socket.id} (всего: ${io.engine.clientsCount})`);
  socket.on('chat:join', ({ chatId }) => { if (chatId) socket.join(chatId); });
  socket.on('chat:leave', ({ chatId }) => { if (chatId) socket.leave(chatId); });

  socket.on('message:send', ({ chatId, message }) => {
    if (!chatId || !message) return;
    if (message.time) message.time = toIsoUtc(message.time);
    if (!message.reactions) message.reactions = {};
    if (!message.id) message.id = generateMessageId();
    if (typeof message.views !== 'number') message.views = 0;
    convertMessageMedia(message);
    const chat = chats.find(c => c.id === chatId);
    if (chat) {
      if (!chat.messages) chat.messages = [];
      const exists = chat.messages.some(m => m.id === message.id);
      if (!exists) {
        chat.messages.push(message);
        chat.updatedAt = Date.now();
        if (chat.type === 'channel' && chat.channelMeta && chat.channelMeta.linkedGroupId) {
          const group = chats.find(c => c.id === chat.channelMeta.linkedGroupId);
          if (group) {
            if (!group.messages) group.messages = [];
            const fwd = {
              id: generateMessageId(),
              from: message.from, text: message.text || '',
              time: new Date().toISOString(), reactions: {},
              media: message.media ? { ...message.media } : undefined,
              forwarded: true, forwardedFrom: chat.name,
              channelPostId: message.id, channelId: chat.id
            };
            group.messages.push(fwd);
            group.updatedAt = Date.now();
            io.to(group.id).emit('message:new', { chatId: group.id, message: fwd });
          }
        }
        persist();
      }
    }
    socket.to(chatId).emit('message:new', { chatId, message });
  });

  socket.on('message:react', ({ chatId, messageId, emoji, userId, action }) => {
    if (!chatId || !messageId || !emoji || !userId) return;
    const chat = chats.find(c => c.id === chatId);
    if (chat && Array.isArray(chat.messages)) {
      const msg = chat.messages.find(m => m.id === messageId);
      if (msg) {
        if (!msg.reactions) msg.reactions = {};
        if (action === 'remove') delete msg.reactions[userId];
        else msg.reactions[userId] = emoji;
        chat.updatedAt = Date.now();
        persist();
      }
    }
    socket.to(chatId).emit('message:reacted', { chatId, messageId, emoji, userId, action });
  });

  socket.on('message:read', ({ chatId, messageId, userId }) => {
    if (!chatId || !messageId || !userId) return;
    const chat = chats.find(c => c.id === chatId);
    if (chat && Array.isArray(chat.messages)) {
      const msg = chat.messages.find(m => m.id === messageId);
      if (msg) {
        if (!msg.readBy) msg.readBy = {};
        msg.readBy[userId] = Date.now();
        persist();
      }
    }
    socket.to(chatId).emit('message:read', { chatId, messageId, userId, time: Date.now() });
  });

  socket.on('message:viewed', ({ chatId, messageId }) => {
    if (!chatId || !messageId) return;
    const chat = chats.find(c => c.id === chatId);
    if (chat && chat.type === 'channel' && chat.messages) {
      const msg = chat.messages.find(m => m.id === messageId);
      if (msg) {
        msg.views = (msg.views || 0) + 1;
        chat.updatedAt = Date.now();
        persist();
        socket.to(chatId).emit('message:viewed', { chatId, messageId, views: msg.views });
      }
    }
  });

  socket.on('channel:subscribe', ({ channelId, userId }) => {
    if (!channelId || !userId) return;
    const channel = chats.find(c => c.id === channelId && c.type === 'channel');
    if (!channel) return;
    if (!channel.channelMeta) channel.channelMeta = { admins: [], subscribers: [], linkedGroupId: null, avatar: null, login: null, isPublic: false };
    if (!channel.channelMeta.subscribers.includes(userId)) {
      channel.channelMeta.subscribers.push(userId);
      if (!channel.members.includes(userId)) channel.members.push(userId);
      persist();
      io.emit('chat:updated', channel);
    }
  });
  socket.on('channel:unsubscribe', ({ channelId, userId }) => {
    if (!channelId || !userId) return;
    const channel = chats.find(c => c.id === channelId && c.type === 'channel');
    if (!channel) return;
    if (channel.channelMeta && channel.channelMeta.subscribers) {
      channel.channelMeta.subscribers = channel.channelMeta.subscribers.filter(u => u !== userId);
      channel.members = channel.members.filter(u => u !== userId);
      persist();
      io.emit('chat:updated', channel);
    }
  });

  socket.on('user:online', ({ userId }) => {
    socket.broadcast.emit('user:online', { userId });
    socket.broadcast.emit('user:heartbeat', { userId });
  });
  socket.on('user:offline', ({ userId }) => { socket.broadcast.emit('user:offline', { userId }); });
  socket.on('disconnect', (reason) => { log(`WS disconnect: ${socket.id} (${reason})`); });
});

// ============================================================
// ЗАПУСК
// ============================================================
loadData();

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
  log('========================================');
  log(`  Mzgram server запущен на порту ${PORT}`);
  log(`  HTML: ${HTML_FILE}`);
  log(`  Данные: ${DATA_FILE}`);
  log(`  Медиа: ${MEDIA_DIR}`);
  log('========================================');
});

process.on('SIGINT', () => { persist(); process.exit(0); });
process.on('SIGTERM', () => { persist(); process.exit(0); });
