import { createServer } from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { randomBytes, createHash, createHmac, scryptSync, timingSafeEqual } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

const here = path.dirname(fileURLToPath(import.meta.url));
const htmlPath = process.env.NEXORA_HTML || path.join(here, 'index.html');
const dbPath = process.env.NEXORA_DB || path.join(here, 'nexora.sqlite');
const port = Number(process.env.PORT || 8787);
const host = process.env.HOST || '127.0.0.1';
const adminEmail = String(process.env.NEXORA_ADMIN_EMAIL || '').trim().toLowerCase();
const adminPassword = String(process.env.NEXORA_ADMIN_PASSWORD || '');
const isProduction = process.env.NODE_ENV === 'production';
const cryptoPayToken = String(process.env.CRYPTO_PAY_API_TOKEN || '').trim();
const cryptoPayApi = 'https://pay.crypt.bot/api';

if (!adminEmail || adminPassword.length < 14) {
  console.error('Set NEXORA_ADMIN_EMAIL and a unique NEXORA_ADMIN_PASSWORD (14+ characters) before starting.');
  process.exit(1);
}
if (!existsSync(htmlPath)) {
  console.error(`Site file not found: ${htmlPath}. Place index.html next to this server or set NEXORA_HTML.`);
  process.exit(1);
}

const db = new DatabaseSync(dbPath);
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','admin')),
    created_at TEXT NOT NULL,
    last_login_at TEXT
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS threads (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    updated_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY,
    thread_id INTEGER NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
    sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    text TEXT NOT NULL CHECK (length(text) BETWEEN 1 AND 2000),
    created_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS messages_thread_id_id ON messages(thread_id,id);
  CREATE INDEX IF NOT EXISTS threads_updated_at ON threads(updated_at DESC);
  CREATE TABLE IF NOT EXISTS orders (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    product_id TEXT NOT NULL,
    product_name TEXT NOT NULL,
    amount_rub INTEGER NOT NULL,
    invoice_id TEXT UNIQUE,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','paid','expired','cancelled')),
    pay_url TEXT,
    created_at TEXT NOT NULL,
    paid_at TEXT
  );
  CREATE INDEX IF NOT EXISTS orders_user_created ON orders(user_id, created_at DESC);
  CREATE TABLE IF NOT EXISTS subscriptions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    product_id TEXT NOT NULL,
    product_name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active','expired','revoked')),
    source_type TEXT NOT NULL CHECK (source_type IN ('payment','test')),
    source_order_id TEXT UNIQUE,
    started_at TEXT NOT NULL,
    expires_at TEXT
  );
  CREATE INDEX IF NOT EXISTS subscriptions_user ON subscriptions(user_id, started_at DESC);
  CREATE TABLE IF NOT EXISTS test_subscription_claims (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    claimed_at TEXT NOT NULL
  );
`);

if (!db.prepare('PRAGMA table_info(users)').all().some(column => column.name === 'last_login_at')) {
  db.exec('ALTER TABLE users ADD COLUMN last_login_at TEXT');
}
db.exec('UPDATE users SET last_login_at=created_at WHERE last_login_at IS NULL');

const products = Object.freeze({
  client_1165: { name: 'NEXORA 1.16.5', amount: 449 },
  client_12111: { name: 'NEXORA 1.21.11', amount: 449 },
  bundle: { name: 'Всё в одном', amount: 1499 },
  premium: { name: 'Premium 1.16.5', amount: 299 },
  hwid_reset: { name: 'Сброс HWID', amount: 299 }
});

const digest = value => createHash('sha256').update(value).digest('hex');
function passwordHash(password, salt = randomBytes(16).toString('hex')) {
  return { salt, hash: scryptSync(password, salt, 64).toString('hex') };
}
function passwordMatches(password, salt, expected) {
  const actual = Buffer.from(passwordHash(password, salt).hash, 'hex');
  const stored = Buffer.from(expected, 'hex');
  return actual.length === stored.length && timingSafeEqual(actual, stored);
}
const adminCred = passwordHash(adminPassword);
db.prepare("UPDATE users SET role='user' WHERE role='admin' AND email<>?").run(adminEmail);
db.prepare(`INSERT INTO users(username,email,password_salt,password_hash,role,created_at)
  VALUES('Администратор',?,?,?,?,?)
  ON CONFLICT(email) DO UPDATE SET password_salt=excluded.password_salt,
  password_hash=excluded.password_hash,role='admin'`).run(
  adminEmail, adminCred.salt, adminCred.hash, 'admin', new Date().toISOString()
);

const windows = new Map();
const registrationWindows = new Map();
function allowRegistration(req) {
  const key = req.socket.remoteAddress || 'unknown', now = Date.now();
  let state = registrationWindows.get(key);
  if (!state || now - state.start > 60 * 60_000) state = { start: now, count: 0 };
  state.count++;
  registrationWindows.set(key, state);
  return state.count <= 8;
}
function allowRequest(req, limit = 120) {
  const key = req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  let state = windows.get(key);
  if (!state || now - state.start > 60_000) state = { start: now, count: 0 };
  state.count++;
  windows.set(key, state);
  return state.count <= limit;
}
function send(res, status, data, headers = {}) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'same-origin',
    ...headers
  });
  res.end(JSON.stringify(data));
}
function cookies(req) {
  return Object.fromEntries(String(req.headers.cookie || '').split(';').map(x => x.trim()).filter(Boolean).map(x => {
    const i = x.indexOf('='); return [x.slice(0, i), decodeURIComponent(x.slice(i + 1))];
  }));
}
function currentUser(req) {
  const token = cookies(req).nexora_session;
  if (!token) return null;
  return db.prepare(`SELECT u.id,u.username,u.email,u.role FROM sessions s JOIN users u ON u.id=s.user_id
    WHERE s.token_hash=? AND s.expires_at>?`).get(digest(token), Date.now()) || null;
}
function createSession(userId, res) {
  const token = randomBytes(32).toString('base64url');
  const expiry = Date.now() + 30 * 24 * 60 * 60 * 1000;
  db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').run(digest(token), userId, expiry);
  const secure = isProduction ? '; Secure' : '';
  res.setHeader('Set-Cookie', `nexora_session=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=2592000${secure}`);
}
async function body(req) {
  let raw = '';
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > 64_000) throw Object.assign(new Error('Request too large'), { status: 413 });
  }
  if (!raw) return {};
  try { return JSON.parse(raw); }
  catch { throw Object.assign(new Error('Invalid JSON'), { status: 400 }); }
}
async function rawBody(req, limit = 64_000) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) throw Object.assign(new Error('Request too large'), { status: 413 });
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}
function safeEqualHex(a, b) {
  if (!/^[a-f0-9]{64}$/i.test(a) || !/^[a-f0-9]{64}$/i.test(b)) return false;
  const left = Buffer.from(a, 'hex'), right = Buffer.from(b, 'hex');
  return left.length === right.length && timingSafeEqual(left, right);
}
async function cryptoPay(method, payload) {
  const response = await fetch(`${cryptoPayApi}/${method}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Crypto-Pay-API-Token': cryptoPayToken },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(12_000)
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.ok) throw new Error('Crypto Pay не смог создать счёт. Проверьте API-токен приложения.');
  return data.result;
}
function requireUser(user) {
  if (!user) throw Object.assign(new Error('Войдите в аккаунт'), { status: 401 });
}
function requireAdmin(user) {
  requireUser(user);
  if (user.role !== 'admin') throw Object.assign(new Error('Доступ только для администратора'), { status: 403 });
}
function getUserThread(userId) {
  return db.prepare('SELECT id FROM threads WHERE user_id=?').get(userId) || null;
}
function apiMessageRows(threadId) {
  return db.prepare(`SELECT m.id,m.thread_id,m.sender_id,u.username,m.text,m.created_at
    FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.thread_id=? ORDER BY m.id`).all(threadId);
}
const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    if (url.pathname.startsWith('/api/') && !allowRequest(req, 180)) return send(res, 429, { error: 'Слишком много запросов. Попробуйте позже.' });
    if (url.pathname === '/' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
      return res.end(readFileSync(htmlPath));
    }
    if (!url.pathname.startsWith('/api/')) return send(res, 404, { error: 'Not found' });

    if (url.pathname === '/api/payments/config' && req.method === 'GET') {
      return send(res, 200, { available: !!cryptoPayToken });
    }
    if (url.pathname === '/api/payments/crypto/webhook' && req.method === 'POST') {
      if (!cryptoPayToken) return send(res, 503, { error: 'Payments are not configured' });
      const raw = await rawBody(req);
      const expected = createHash('sha256').update(cryptoPayToken).digest();
      const supplied = String(req.headers['crypto-pay-api-signature'] || '');
      const actual = createHmac('sha256', expected).update(raw).digest('hex');
      if (!safeEqualHex(supplied, actual)) return send(res, 401, { error: 'Invalid signature' });
      let update;
      try { update = JSON.parse(raw.toString('utf8')); } catch { return send(res, 400, { error: 'Invalid JSON' }); }
      if (update?.update_type !== 'invoice_paid' || update?.payload?.status !== 'paid') return send(res, 200, { ok: true });
      const invoice = update.payload;
      const orderId = String(invoice.payload || '');
      const order = db.prepare('SELECT * FROM orders WHERE id=? AND invoice_id=?').get(orderId, String(invoice.invoice_id));
      if (!order) return send(res, 200, { ok: true });
      if (invoice.currency_type !== 'fiat' || invoice.fiat !== 'RUB' || Number(invoice.amount) !== order.amount_rub) {
        return send(res, 400, { error: 'Invoice amount mismatch' });
      }
      if (order.status !== 'paid') {
        const now = new Date().toISOString();
        db.prepare("UPDATE orders SET status='paid',paid_at=? WHERE id=? AND status='pending'").run(now, order.id);
        if (order.product_id !== 'hwid_reset') {
          db.prepare(`INSERT OR IGNORE INTO subscriptions(id,user_id,product_id,product_name,status,source_type,source_order_id,started_at,expires_at)
            VALUES(?,?,?,?,'active','payment',?,?,NULL)`)
            .run(randomBytes(18).toString('base64url'), order.user_id, order.product_id, order.product_name, order.id, now);
        }
        db.prepare('INSERT OR IGNORE INTO threads(user_id,updated_at) VALUES(?,?)').run(order.user_id, now);
        const thread = getUserThread(order.user_id);
        const admin = db.prepare("SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1").get();
        if (thread && admin) db.prepare('INSERT INTO messages(thread_id,sender_id,text,created_at) VALUES(?,?,?,?)')
          .run(thread.id, admin.id, order.product_id === 'hwid_reset'
            ? `Оплата подтверждена: услуга «${order.product_name}» (${order.amount_rub} ₽). Обращение передано поддержке.`
            : `Оплата подтверждена: ${order.product_name} (${order.amount_rub} ₽). Подписка активирована в аккаунте.`, now);
      }
      return send(res, 200, { ok: true });
    }
    const user = currentUser(req);

    if (url.pathname === '/api/me' && req.method === 'GET') return send(res, 200, { user });
    if (url.pathname === '/api/profile' && req.method === 'GET') {
      requireUser(user);
      const account = db.prepare('SELECT id,username,email,role,created_at,last_login_at FROM users WHERE id=?').get(user.id);
      const subscriptions = db.prepare(`SELECT id,product_id,product_name,status,source_type,started_at,expires_at
        FROM subscriptions WHERE user_id=? ORDER BY started_at DESC`).all(user.id);
      const orders = db.prepare(`SELECT id,product_name,amount_rub,status,created_at,paid_at
        FROM orders WHERE user_id=? ORDER BY created_at DESC LIMIT 10`).all(user.id);
      return send(res, 200, {
        account: { ...account, email: account.email.endsWith('.nexora.invalid') ? '' : account.email, hwid: null },
        subscriptions: subscriptions.map(item => ({ ...item, status: item.expires_at && Date.parse(item.expires_at) <= Date.now() && item.status === 'active' ? 'expired' : item.status })),
        orders,
        testSubscriptionClaimed: !!db.prepare('SELECT 1 FROM test_subscription_claims WHERE user_id=?').get(user.id)
      });
    }
    if (url.pathname === '/api/purchases/free-test' && req.method === 'POST') {
      requireUser(user);
      const now = new Date().toISOString();
      const expires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
      const orderId = randomBytes(18).toString('base64url');
      const subscriptionId = randomBytes(18).toString('base64url');
      db.exec('BEGIN IMMEDIATE');
      try {
        const claimed = db.prepare('INSERT OR IGNORE INTO test_subscription_claims(user_id,claimed_at) VALUES(?,?)').run(user.id, now);
        if (!claimed.changes) {
          db.exec('ROLLBACK');
          return send(res, 409, { error: 'Тестовую подписку можно оформить только один раз на аккаунт.' });
        }
        db.prepare(`INSERT INTO orders(id,user_id,product_id,product_name,amount_rub,status,created_at,paid_at)
          VALUES(?,?,'test_access','Тестовая подписка',0,'paid',?,?)`).run(orderId, user.id, now, now);
        db.prepare(`INSERT INTO subscriptions(id,user_id,product_id,product_name,status,source_type,source_order_id,started_at,expires_at)
          VALUES(?,?,'test_access','Тестовая подписка','active','test',?,?,?)`)
          .run(subscriptionId, user.id, orderId, now, expires);
        db.exec('COMMIT');
      } catch (error) {
        db.exec('ROLLBACK');
        throw error;
      }
      return send(res, 201, {
        order: { id: orderId, product_name: 'Тестовая подписка', amount_rub: 0, status: 'paid', created_at: now, paid_at: now },
        subscription: { id: subscriptionId, product_id: 'test_access', product_name: 'Тестовая подписка', status: 'active', source_type: 'test', started_at: now, expires_at: expires }
      });
    }
    if (url.pathname === '/api/payments/crypto/create' && req.method === 'POST') {
      requireUser(user);
      if (!cryptoPayToken) return send(res, 503, { error: 'Оплата пока не настроена. Нужен API-токен приложения Crypto Pay.' });
      const data = await body(req), product = products[String(data.productId || '')];
      if (!product) return send(res, 400, { error: 'Товар не найден.' });
      const orderId = randomBytes(18).toString('base64url');
      const now = new Date().toISOString();
      db.prepare('INSERT INTO orders(id,user_id,product_id,product_name,amount_rub,created_at) VALUES(?,?,?,?,?,?)')
        .run(orderId, user.id, String(data.productId), product.name, product.amount, now);
      try {
        const invoice = await cryptoPay('createInvoice', {
          currency_type: 'fiat', fiat: 'RUB', amount: String(product.amount), accepted_assets: 'USDT,TON,BTC,ETH',
          description: `${product.name} — заказ ${orderId.slice(0, 8)}`, payload: orderId,
          expires_in: 1800, allow_comments: false, allow_anonymous: false
        });
        if (!invoice?.invoice_id || !invoice?.bot_invoice_url) throw new Error('Провайдер не вернул ссылку на оплату.');
        db.prepare('UPDATE orders SET invoice_id=?,pay_url=? WHERE id=?').run(String(invoice.invoice_id), invoice.bot_invoice_url, orderId);
        return send(res, 201, { orderId, payUrl: invoice.bot_invoice_url, product: product.name, amount: product.amount });
      } catch (error) {
        db.prepare("UPDATE orders SET status='cancelled' WHERE id=?").run(orderId);
        throw error;
      }
    }
    if (url.pathname === '/api/payments/order' && req.method === 'GET') {
      requireUser(user);
      const order = db.prepare('SELECT id,product_name,amount_rub,status,created_at,paid_at FROM orders WHERE id=? AND user_id=?')
        .get(String(url.searchParams.get('id') || ''), user.id);
      if (!order) return send(res, 404, { error: 'Заказ не найден.' });
      return send(res, 200, { order });
    }
    if (url.pathname === '/api/register' && req.method === 'POST') {
      if (!allowRegistration(req)) return send(res, 429, { error: 'Слишком много регистраций с этого адреса. Попробуйте позже.' });
      const data = await body(req);
      const username = String(data.username || '').trim().normalize('NFKC');
      const email = String(data.email || '').trim().toLowerCase();
      const password = String(data.password || '');
      if (!/^[\p{L}\p{N}_-]{2,32}$/u.test(username)) return send(res, 400, { error: 'Ник должен быть длиной от 2 до 32 символов: буквы, цифры, _ или -.' });
      if (email && (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254)) return send(res, 400, { error: 'Проверьте формат email или оставьте поле пустым.' });
      if (password.length < 10 || password.length > 128) return send(res, 400, { error: 'Пароль должен содержать от 10 до 128 символов.' });
      const usernameKey = username.toLocaleLowerCase('ru-RU');
      if (db.prepare('SELECT username FROM users').all().some(row => row.username.normalize('NFKC').toLocaleLowerCase('ru-RU') === usernameKey)) return send(res, 409, { error: 'Этот ник уже занят.' });
      if (email && db.prepare('SELECT id FROM users WHERE email=?').get(email)) return send(res, 409, { error: 'Этот email уже привязан к аккаунту.' });
      const cred = passwordHash(password);
      const storedEmail = email || `local-${randomBytes(16).toString('hex')}@nexora.invalid`;
      let info;
      const createdAt = new Date().toISOString();
      try { info = db.prepare(`INSERT INTO users(username,email,password_salt,password_hash,role,created_at,last_login_at)
        VALUES(?,?,?,?,'user',?,?)`).run(username, storedEmail, cred.salt, cred.hash, createdAt, createdAt); }
      catch (e) { if (String(e.message).includes('UNIQUE')) return send(res, 409, { error: 'Ник или email уже используется.' }); throw e; }
      createSession(Number(info.lastInsertRowid), res);
      const created = db.prepare('SELECT id,username,email,role FROM users WHERE id=?').get(Number(info.lastInsertRowid));
      return send(res, 201, { user: created });
    }
    if (url.pathname === '/api/login' && req.method === 'POST') {
      if (!allowRequest(req, 30)) return send(res, 429, { error: 'Слишком много попыток входа. Попробуйте позже.' });
      const data = await body(req), identifier = String(data.username || '').trim().normalize('NFKC'), password = String(data.password || '');
      const identifierKey = identifier.toLocaleLowerCase('ru-RU');
      const row = db.prepare('SELECT id,username,email,role,password_salt,password_hash FROM users').all()
        .find(account => account.username.normalize('NFKC').toLocaleLowerCase('ru-RU') === identifierKey || account.email.toLowerCase() === identifier.toLowerCase());
      if (!row || !passwordMatches(password, row.password_salt, row.password_hash)) return send(res, 401, { error: 'Неверный ник/email или пароль.' });
      db.prepare('UPDATE users SET last_login_at=? WHERE id=?').run(new Date().toISOString(), row.id);
      createSession(row.id, res);
      return send(res, 200, { user: { id: row.id, username: row.username, email: row.email, role: row.role } });
    }
    if (url.pathname === '/api/logout' && req.method === 'POST') {
      const token = cookies(req).nexora_session;
      if (token) db.prepare('DELETE FROM sessions WHERE token_hash=?').run(digest(token));
      res.setHeader('Set-Cookie', 'nexora_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0');
      return send(res, 200, { ok: true });
    }
    if (url.pathname === '/api/chat/threads' && req.method === 'GET') {
      requireAdmin(user);
      const threads = db.prepare(`SELECT t.id,t.user_id,u.username,
        (SELECT text FROM messages WHERE thread_id=t.id ORDER BY id DESC LIMIT 1) AS last_message,
        t.updated_at FROM threads t JOIN users u ON u.id=t.user_id ORDER BY t.updated_at DESC`).all();
      return send(res, 200, { threads });
    }
    if (url.pathname === '/api/chat/messages' && req.method === 'GET') {
      requireUser(user);
      if (user.role === 'admin') {
        const threadId = Number(url.searchParams.get('threadId'));
        if (!Number.isInteger(threadId) || threadId < 1) return send(res, 400, { error: 'Выберите обращение.' });
        if (!db.prepare('SELECT id FROM threads WHERE id=?').get(threadId)) return send(res, 404, { error: 'Обращение не найдено.' });
        return send(res, 200, { messages: apiMessageRows(threadId) });
      }
      const thread = getUserThread(user.id);
      return send(res, 200, { messages: thread ? apiMessageRows(thread.id) : [] });
    }
    if (url.pathname === '/api/chat/messages' && req.method === 'POST') {
      requireUser(user);
      const data = await body(req), text = String(data.text || '').trim();
      if (!text || text.length > 2000) return send(res, 400, { error: 'Сообщение должно содержать от 1 до 2000 символов.' });
      let thread;
      if (user.role === 'admin') {
        const id = Number(data.threadId);
        thread = Number.isInteger(id) ? db.prepare('SELECT id,user_id FROM threads WHERE id=?').get(id) : null;
        if (!thread) return send(res, 400, { error: 'Выберите пользователя, которому отвечаете.' });
      } else {
        thread = getUserThread(user.id);
        if (!thread) {
          db.prepare('INSERT OR IGNORE INTO threads(user_id,updated_at) VALUES(?,?)').run(user.id, new Date().toISOString());
          thread = getUserThread(user.id);
        }
      }
      const now = new Date().toISOString();
      const result = db.prepare('INSERT INTO messages(thread_id,sender_id,text,created_at) VALUES(?,?,?,?)').run(thread.id, user.id, text, now);
      db.prepare('UPDATE threads SET updated_at=? WHERE id=?').run(now, thread.id);
      const message = db.prepare(`SELECT m.id,m.thread_id,m.sender_id,u.username,m.text,m.created_at
        FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.id=?`).get(Number(result.lastInsertRowid));
      return send(res, 201, { message });
    }
    return send(res, 404, { error: 'Not found' });
  } catch (error) {
    const status = error.status || 500;
    if (status === 500) console.error(error);
    return send(res, status, { error: status === 500 ? 'Внутренняя ошибка сервера.' : error.message });
  }
});

server.listen(port, host, () => console.log(`NEXORA server listening at http://${host}:${port}`));
