'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const { DatabaseSync } = require('node:sqlite');
try { process.loadEnvFile(path.join(__dirname, '.env')); } catch (error) { if (error.code !== 'ENOENT') throw error; }
const dns = require('node:dns/promises');
const net = require('node:net');

const scrypt = promisify(crypto.scrypt);
const ROOT = __dirname;
const DATA_DIR = process.env.DATA_DIR || path.join(ROOT, '.data');
const PORT = Number(process.env.PORT || 3000);
const NODE_ENV = process.env.NODE_ENV || 'development';
const SESSION_COOKIE = 'vigia_session';
const SESSION_DAYS = 30;
const MAX_BODY_BYTES = 32 * 1024;
const USER_AGENT = process.env.CRAWLER_USER_AGENT || 'VigiaPriceMonitor/1.0';
const ALLOWED_HOSTS = (process.env.STORE_ALLOWLIST || '').split(',').map(host => host.trim().toLowerCase()).filter(Boolean);
const configuredHostDelay = Number(process.env.MIN_STORE_DELAY_SECONDS || 60);
const HOST_DELAY_MS = Math.max(60_000, (Number.isFinite(configuredHostDelay) ? configuredHostDelay : 60) * 1000);
const hostLastRequest = new Map();
const productChecks = new Set();
let monitorRunning = false;
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new DatabaseSync(path.join(DATA_DIR, 'vigia.sqlite'), { timeout: 5000 });
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
  PRAGMA busy_timeout = 5000;
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL, created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS products (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL, url TEXT NOT NULL, store TEXT NOT NULL, target_price REAL,
    current_price REAL, availability TEXT, enabled INTEGER NOT NULL DEFAULT 1,
    interval_minutes INTEGER NOT NULL DEFAULT 30, change_pct REAL, last_checked_at TEXT,
    next_check_at TEXT NOT NULL, last_error TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    UNIQUE(user_id, url)
  );
  CREATE INDEX IF NOT EXISTS products_due_idx ON products(enabled, next_check_at);
  CREATE INDEX IF NOT EXISTS products_user_idx ON products(user_id, created_at DESC);
  CREATE TABLE IF NOT EXISTS price_history (
    id TEXT PRIMARY KEY, product_id TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    price REAL NOT NULL, captured_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS price_history_product_idx ON price_history(product_id, captured_at);
  CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    product_id TEXT REFERENCES products(id) ON DELETE SET NULL, type TEXT NOT NULL,
    title TEXT NOT NULL, detail TEXT NOT NULL, value TEXT NOT NULL, created_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS alerts_user_idx ON alerts(user_id, created_at DESC);
  CREATE TABLE IF NOT EXISTS password_resets (
    token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS settings (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    price_alerts INTEGER NOT NULL DEFAULT 1, stock_alerts INTEGER NOT NULL DEFAULT 1,
    interval_minutes INTEGER NOT NULL DEFAULT 30, monitor_enabled INTEGER NOT NULL DEFAULT 1,
    telegram_chat_id TEXT
  );
`);
const statements = {
  userByEmail: db.prepare('SELECT * FROM users WHERE email = ?'),
  userById: db.prepare('SELECT id, name, email, created_at FROM users WHERE id = ?'),
  userCount: db.prepare('SELECT COUNT(*) AS count FROM users'),
  createUser: db.prepare('INSERT INTO users (id,name,email,password_hash,created_at) VALUES (?,?,?,?,?)'),
  createSettings: db.prepare('INSERT INTO settings (user_id) VALUES (?)'),
  saveSession: db.prepare('INSERT INTO sessions (token_hash,user_id,expires_at) VALUES (?,?,?)'),
  sessionUser: db.prepare('SELECT users.id,users.name,users.email FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash=? AND sessions.expires_at>?'),
  deleteSession: db.prepare('DELETE FROM sessions WHERE token_hash=?'),
};
const rateBuckets = new Map();
function uuid() { return crypto.randomUUID(); }
function nowIso() { return new Date().toISOString(); }
function json(res, status, payload, extraHeaders = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'Content-Length': Buffer.byteLength(body), ...extraHeaders });
  res.end(body);
}
function setSecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
}
function parseCookies(req) {
  const out = {};
  for (const part of (req.headers.cookie || '').split(';')) {
    const index = part.indexOf('='); if (index < 0) continue;
    out[part.slice(0, index).trim()] = decodeURIComponent(part.slice(index + 1).trim());
  }
  return out;
}
function issueSession(res, userId) {
  const token = crypto.randomBytes(32).toString('base64url');
  const expires = new Date(Date.now() + SESSION_DAYS * 864e5).toISOString();
  statements.saveSession.run(crypto.createHash('sha256').update(token).digest('hex'), userId, expires);
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}${NODE_ENV === 'production' ? '; Secure' : ''}`);
}
function clearSession(res) {
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${NODE_ENV === 'production' ? '; Secure' : ''}`);
}
function getSessionUser(req) {
  const token = parseCookies(req)[SESSION_COOKIE];
  if (!token) return null;
  return statements.sessionUser.get(crypto.createHash('sha256').update(token).digest('hex'), nowIso()) || null;
}
function checkRateLimit(req, res) {
  const key = `${req.socket.remoteAddress || 'unknown'}:${req.url.split('?')[0]}`;
  const now = Date.now(), bucket = rateBuckets.get(key) || { count: 0, resetAt: now + 15 * 60_000 };
  if (now > bucket.resetAt) { bucket.count = 0; bucket.resetAt = now + 15 * 60_000; }
  bucket.count++;
  rateBuckets.set(key, bucket);
  if (bucket.count <= 12) return true;
  json(res, 429, { error: 'Demasiadas tentativas. Aguarda alguns minutos.' }, { 'Retry-After': String(Math.ceil((bucket.resetAt - now) / 1000)) });
  return false;
}
async function readJson(req) {
  const chunks = []; let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw Object.assign(new Error('Pedido demasiado grande.'), { status: 413 });
    chunks.push(chunk);
  }
  if (!size) return {};
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { throw Object.assign(new Error('JSON inválido.'), { status: 400 }); }
}
function originAllowed(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  try {
    const expected = process.env.PUBLIC_ORIGIN ? new URL(process.env.PUBLIC_ORIGIN).host : req.headers.host;
    return new URL(origin).host === expected;
  } catch { return false; }
}
function requireUser(req, res) {
  const user = getSessionUser(req);
  if (!user) { json(res, 401, { error: 'Inicia sessão para continuar.' }); return null; }
  return user;
}
function parseProduct(row) {
  const interval = row.interval_minutes === 360 ? '6 horas' : row.interval_minutes === 60 ? '1 hora' : `${row.interval_minutes} minutos`;
  return {
    id: row.id, name: row.name, url: row.url, store: row.store,
    target: row.target_price, price: row.current_price, availability: row.availability,
    paused: !row.enabled, interval,
    change: row.change_pct === null ? '—' : `${row.change_pct < 0 ? '↓' : '↑'} ${Math.abs(row.change_pct).toFixed(1).replace('.', ',')}%`,
    changeType: row.change_pct === null ? 'neutral' : row.change_pct <= 0 ? 'down' : 'up',
    last: row.last_checked_at ? new Date(row.last_checked_at).toLocaleString('pt-PT') : 'A aguardar',
    lastError: row.last_error,
    status: row.current_price !== null && row.target_price !== null && row.current_price <= row.target_price ? 'drop' : row.availability === 'in_stock' ? 'stock' : 'watching',
    icon: '◉', thumb: 'thumb-watch'
  };
}
function isPublicAddress(address) {
  const version = net.isIP(address);
  if (version === 4) {
    const octets = address.split('.').map(Number), [a,b] = octets;
    return !(a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 192 && b === 0) || (a === 198 && (b === 18 || b === 19)) || a >= 224);
  }
  if (version === 6) {
    const lower = address.toLowerCase();
    if (lower.startsWith('::ffff:')) return isPublicAddress(lower.slice(7));
    return !(lower === '::' || lower === '::1' || lower.startsWith('fc') || lower.startsWith('fd') || lower.startsWith('fe8') || lower.startsWith('fe9') || lower.startsWith('fea') || lower.startsWith('feb') || lower.startsWith('ff'));
  }
  return false;
}
function hostAllowed(hostname) {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  return ALLOWED_HOSTS.some(root => host === root || host.endsWith(`.${root}`));
}
async function validateRemoteUrl(input) {
  const url = new URL(input);
  if (url.protocol !== 'https:' || url.username || url.password || !hostAllowed(url.hostname)) throw new Error('Loja não autorizada. Adiciona o domínio a STORE_ALLOWLIST no ficheiro .env.');
  if (net.isIP(url.hostname)) throw new Error('Endereços IP diretos não são aceites.');
  const records = await dns.lookup(url.hostname, { all: true, verbatim: true });
  if (!records.length || records.some(record => !isPublicAddress(record.address))) throw new Error('O domínio não resolve para um endereço público permitido.');
  return url;
}
const robotsCache = new Map();
async function allowedByRobots(url) {
  const host = url.hostname.toLowerCase(); let rules = robotsCache.get(host);
  if (!rules || Date.now() - rules.loadedAt > 60 * 60_000) {
    const robotsUrl = new URL('/robots.txt', url.origin);
    const response = await fetch(robotsUrl, { signal: AbortSignal.timeout(6000), redirect: 'error', headers: { 'User-Agent': USER_AGENT } });
    rules = { loadedAt: Date.now(), lines: [] };
    if (response.ok) {
      const text = await response.text();
      if (text.length > 250_000) throw new Error('robots.txt ultrapassa o limite de leitura.');
      rules.lines = text.split(/\r?\n/).map(line => line.split('#')[0].trim()).filter(Boolean);
    } else if (response.status !== 404 && response.status !== 410) throw new Error(`robots.txt respondeu com HTTP ${response.status}.`);
    robotsCache.set(host, rules);
  }
  let groupMatches = false, groupHasRules = false; const directives = [];
  for (const line of rules.lines) {
    const match = line.match(/^([^:]+):\s*(.*)$/); if (!match) continue;
    const key = match[1].toLowerCase(), value = match[2].trim();
    if (key === 'user-agent') {
      if (groupHasRules) { groupMatches = false; groupHasRules = false; }
      if (value === '*' || USER_AGENT.toLowerCase().includes(value.toLowerCase())) groupMatches = true;
    } else if ((key === 'allow' || key === 'disallow') && groupMatches) {
      groupHasRules = true; if (value) directives.push({ key, value });
    }
  }
  const pathName = `${url.pathname}${url.search}`;
  const applicable = directives.filter(rule => pathName.startsWith(rule.value)).sort((a,b) => b.value.length - a.value.length);
  return !applicable.length || applicable[0].key === 'allow';
}
async function fetchHtml(url) {
  let current = await validateRemoteUrl(url);
  if (!await allowedByRobots(current)) throw new Error('robots.txt da loja não permite esta página.');
  for (let redirectCount = 0; redirectCount <= 3; redirectCount++) {
    const previous = hostLastRequest.get(current.hostname) || 0;
    const wait = HOST_DELAY_MS - (Date.now() - previous);
    if (wait > 0) await new Promise(resolve => setTimeout(resolve, wait));
    hostLastRequest.set(current.hostname, Date.now());
    const response = await fetch(current, { method: 'GET', redirect: 'manual', signal: AbortSignal.timeout(12_000), headers: { 'User-Agent': USER_AGENT, 'Accept': 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.5' } });
    if ([301,302,303,307,308].includes(response.status)) {
      const location = response.headers.get('location'); if (!location || redirectCount === 3) throw new Error('Demasiados redirecionamentos.');
      current = await validateRemoteUrl(new URL(location, current).href); continue;
    }
    if (!response.ok) throw new Error(`A loja respondeu com HTTP ${response.status}.`);
    const size = Number(response.headers.get('content-length') || 0); if (size > 2_000_000) throw new Error('A página excede o limite de 2 MB.');
    const reader = response.body.getReader(), chunks = []; let total = 0;
    while (true) { const { done, value } = await reader.read(); if (done) break; total += value.length; if (total > 2_000_000) { await reader.cancel(); throw new Error('A página excede o limite de 2 MB.'); } chunks.push(Buffer.from(value)); }
    return { html: Buffer.concat(chunks).toString('utf8'), finalUrl: current };
  }
  throw new Error('Não foi possível abrir esta página.');
}
function normalizePrice(value) {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  const text = String(value || '').trim().replace(/[^\d,.-]/g, '');
  if (!text) return null;
  const normalized = text.includes(',') ? text.replace(/\.(?=\d{3}(?:,|$))/g, '').replace(',', '.') : text;
  const number = Number(normalized); return Number.isFinite(number) && number > 0 ? number : null;
}
function collectProducts(value, out = []) {
  if (!value) return out;
  if (Array.isArray(value)) { for (const item of value) collectProducts(item, out); return out; }
  if (typeof value !== 'object') return out;
  const type = value['@type'];
  if ((Array.isArray(type) ? type : [type]).includes('Product')) out.push(value);
  if (value['@graph']) collectProducts(value['@graph'], out);
  return out;
}
function priceFromHtml(html) {
  const scripts = html.matchAll(/<script\b[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script\s*>/gi);
  for (const match of scripts) {
    try {
      const products = collectProducts(JSON.parse(match[1].replace(/&quot;/g, '"').trim()));
      for (const product of products) {
        const offers = Array.isArray(product.offers) ? product.offers : [product.offers];
        for (const offer of offers) {
          if (!offer) continue;
          const price = normalizePrice(offer.price ?? offer.lowPrice ?? offer.priceSpecification?.price);
          if (price) return { price, availability: /OutOfStock|SoldOut/i.test(offer.availability || '') ? 'out_of_stock' : /InStock|LimitedAvailability/i.test(offer.availability || '') ? 'in_stock' : 'unknown' };
        }
      }
    } catch { /* Ignore malformed structured data and try standard metadata. */ }
  }
  const tags = html.match(/<meta\b[^>]*>/gi) || [];
  for (const tag of tags) {
    const prop = (tag.match(/(?:property|itemprop|name)=["']([^"']+)["']/i) || [])[1]?.toLowerCase();
    if (!['product:price:amount','og:price:amount','price','price:amount'].includes(prop)) continue;
    const raw = (tag.match(/content=["']([^"']+)["']/i) || [])[1]; const price = normalizePrice(raw);
    if (price) return { price, availability: 'unknown' };
  }
  return null;
}
function userSettings(userId) {
  return db.prepare('SELECT * FROM settings WHERE user_id=?').get(userId) || { price_alerts: 1, stock_alerts: 1, interval_minutes: 30, monitor_enabled: 1, telegram_chat_id: null };
}
function saveAlert(userId, product, type, title, value) {
  const detail = product.name, createdAt = nowIso();
  db.prepare('INSERT INTO alerts (id,user_id,product_id,type,title,detail,value,created_at) VALUES (?,?,?,?,?,?,?,?)').run(uuid(), userId, product.id, type, title, detail, String(value), createdAt);
  const settings = userSettings(userId);
  if ((type === 'price_drop' && settings.price_alerts) || (type === 'stock' && settings.stock_alerts)) {
    void sendNotifications(userId, `${title}: ${detail} — ${value}`);
  }
}
async function sendNotifications(userId, message) {
  const settings = userSettings(userId), tasks = [];
  if (process.env.TELEGRAM_BOT_TOKEN && settings.telegram_chat_id) tasks.push(sendTelegramNotification(settings.telegram_chat_id, message));
  if (process.env.DISCORD_WEBHOOK_URL) tasks.push(sendDiscordNotification(message));
  const results = await Promise.allSettled(tasks);
  for (const result of results) if (result.status === 'rejected') console.error('Falha ao enviar alerta:', result.reason?.message || 'erro externo');
}
async function sendTelegramNotification(chatId, message) {
  const response = await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ chat_id: chatId, text: message }), signal: AbortSignal.timeout(8000) });
  const result = await response.json().catch(() => ({ ok: false }));
  if (!response.ok || !result.ok) throw new Error('Telegram recusou a mensagem.');
}
async function sendDiscordNotification(message) {
  const webhook = new URL(process.env.DISCORD_WEBHOOK_URL || '');
  if (webhook.protocol !== 'https:' || !['discord.com','discordapp.com'].includes(webhook.hostname) || !webhook.pathname.startsWith('/api/webhooks/')) throw new Error('DISCORD_WEBHOOK_URL não é um webhook válido do Discord.');
  const response = await fetch(webhook, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ content: message.slice(0, 1900) }), signal: AbortSignal.timeout(8000) });
  if (!response.ok) throw new Error(`Discord respondeu com HTTP ${response.status}.`);
}
async function checkProduct(product) {
  if (productChecks.has(product.id)) return { ok: false, error: 'Esta monitorização já está a ser verificada.' };
  productChecks.add(product.id);
  const checkedAt = nowIso();
  try {
    const { html } = await fetchHtml(product.url), extracted = priceFromHtml(html);
    if (!extracted) throw new Error('Não encontrei preço estruturado nesta página. Esta loja pode precisar de um adaptador por API.');
    const previous = product.current_price, price = extracted.price, change = previous === null ? null : ((price - previous) / previous) * 100;
    const statusChange = (change !== null && change < -0.01) || (product.target_price !== null && previous !== null && previous > product.target_price && price <= product.target_price);
    const stockChange = extracted.availability === 'in_stock' && product.availability === 'out_of_stock';
    db.prepare('UPDATE products SET current_price=?, availability=?, change_pct=?, last_checked_at=?, next_check_at=?, last_error=NULL, updated_at=? WHERE id=?').run(price, extracted.availability, change, checkedAt, new Date(Date.now() + product.interval_minutes * 60_000).toISOString(), checkedAt, product.id);
    db.prepare('INSERT INTO price_history (id,product_id,price,captured_at) VALUES (?,?,?,?)').run(uuid(), product.id, price, checkedAt);
    if (statusChange) saveAlert(product.user_id, product, 'price_drop', 'Queda de preço detetada', `€${price.toFixed(2)}`);
    if (stockChange) saveAlert(product.user_id, product, 'stock', 'Produto novamente em stock', `€${price.toFixed(2)}`);
    return { ok: true, price, availability: extracted.availability };
  } catch (error) {
    db.prepare('UPDATE products SET last_checked_at=?, next_check_at=?, last_error=?, updated_at=? WHERE id=?').run(checkedAt, new Date(Date.now() + product.interval_minutes * 60_000).toISOString(), String(error.message || 'Falha na verificação').slice(0, 350), checkedAt, product.id);
    return { ok: false, error: String(error.message || 'Falha na verificação') };
  } finally { productChecks.delete(product.id); }
}
async function runMonitor() {
  if (monitorRunning) return; monitorRunning = true;
  try {
    const due = db.prepare(`SELECT p.* FROM products p JOIN settings s ON s.user_id=p.user_id WHERE p.enabled=1 AND s.monitor_enabled=1 AND p.next_check_at<=? ORDER BY p.next_check_at LIMIT 8`).all(nowIso());
    for (const product of due) await checkProduct(product);
  } catch (error) { console.error('Ciclo de monitorização falhou:', error.message); }
  finally { monitorRunning = false; }
}

function intervalMinutes(value) {
  const text=String(value??'').toLowerCase();
  if(text.includes('6 horas'))return 360;
  if(text.includes('1 hora'))return 60;
  if(text.includes('15'))return 15;
  if(text.includes('30'))return 30;
  const number=Number(value);
  return [15,30,60,360].includes(number)?number:30;
}
function cleanText(value, max, label) {
  const text = String(value || '').trim();
  if (!text || text.length > max) throw Object.assign(new Error(`${label} é obrigatório e deve ter até ${max} caracteres.`), { status: 400 });
  return text;
}
function productOwned(userId, productId) {
  return db.prepare('SELECT * FROM products WHERE id=? AND user_id=?').get(productId, userId);
}
async function sendRecoveryEmail(user, token) {
  if (!process.env.RESEND_API_KEY || !process.env.MAIL_FROM || !process.env.PUBLIC_ORIGIN) throw Object.assign(new Error('A recuperação por email precisa de RESEND_API_KEY, MAIL_FROM e PUBLIC_ORIGIN.'), { status: 503 });
  const link = `${process.env.PUBLIC_ORIGIN.replace(/\/$/, '')}/?reset=${encodeURIComponent(token)}`;
  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST', signal: AbortSignal.timeout(10_000),
    headers: { 'Authorization': `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: process.env.MAIL_FROM, to: [user.email], subject: 'Recuperar acesso ao Vigia', html: `<p>Recebemos um pedido para alterar a palavra-passe da tua conta Vigia.</p><p><a href="${link}">Definir uma palavra-passe nova</a></p><p>O link expira dentro de uma hora. Se não pediste esta alteração, ignora esta mensagem.</p>` })
  });
  if (!response.ok) throw new Error(`O serviço de email respondeu com HTTP ${response.status}.`);
}
async function handleApi(req, res, url) {
  const pathname = url.pathname, method = req.method;
  if (pathname === '/api/health' && method === 'GET') return json(res, 200, { ok: true, service: 'vigia', now: nowIso() });
  if (['POST','PUT','PATCH','DELETE'].includes(method) && !originAllowed(req)) return json(res, 403, { error: 'Origem do pedido não autorizada.' });
  if (pathname === '/api/auth/register' && method === 'POST') {
    if (!checkRateLimit(req, res)) return;
    const body = await readJson(req), name = cleanText(body.name, 80, 'Nome'), email = cleanText(body.email, 254, 'Email').toLowerCase(), password = String(body.password || '');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json(res, 400, { error: 'Introduz um email válido.' });
    if (password.length < 12 || password.length > 200) return json(res, 400, { error: 'A palavra-passe precisa de pelo menos 12 caracteres.' });
    if (statements.userCount.get().count > 0 && process.env.ALLOW_SIGNUPS !== 'true') return json(res, 403, { error: 'O registo público está fechado. Usa a conta existente ou ativa ALLOW_SIGNUPS.' });
    const salt = crypto.randomBytes(16), hash = await scrypt(password, salt, 64, { N: 32768, r: 8, p: 1, maxmem: 80 * 1024 * 1024 });
    const id = uuid();
    db.exec('BEGIN IMMEDIATE');
    try {
      if (statements.userCount.get().count > 0 && process.env.ALLOW_SIGNUPS !== 'true') { db.exec('ROLLBACK'); return json(res, 403, { error: 'A primeira conta já foi criada e o registo público está fechado.' }); }
      statements.createUser.run(id, name, email, `scrypt$32768$8$1$${salt.toString('base64url')}$${Buffer.from(hash).toString('base64url')}`, nowIso());
      statements.createSettings.run(id);
      db.exec('COMMIT');
    } catch (error) { db.exec('ROLLBACK'); if (String(error.message).includes('UNIQUE')) return json(res, 409, { error: 'Este email já tem uma conta.' }); throw error; }
    issueSession(res, id); return json(res, 201, { user: statements.userById.get(id) });
  }
  if (pathname === '/api/auth/login' && method === 'POST') {
    if (!checkRateLimit(req, res)) return;
    const body = await readJson(req), email = String(body.email || '').trim().toLowerCase(), password = String(body.password || '');
    if (password.length > 200 || !email) return json(res, 400, { error: 'Email ou palavra-passe inválidos.' });
    const user = statements.userByEmail.get(email);
    let matches = false;
    if (user) {
      const parts = user.password_hash.split('$');
      if (parts.length === 6 && parts[0] === 'scrypt') {
        const candidate = await scrypt(password, Buffer.from(parts[4], 'base64url'), 64, { N: Number(parts[1]), r: Number(parts[2]), p: Number(parts[3]), maxmem: 80 * 1024 * 1024 });
        matches = crypto.timingSafeEqual(Buffer.from(candidate), Buffer.from(parts[5], 'base64url'));
      }
    }
    if (!matches) return json(res, 401, { error: 'Email ou palavra-passe inválidos.' });
    issueSession(res, user.id); return json(res, 200, { user: statements.userById.get(user.id) });
  }
  if (pathname === '/api/auth/logout' && method === 'POST') {
    const token = parseCookies(req)[SESSION_COOKIE];
    if (token) statements.deleteSession.run(crypto.createHash('sha256').update(token).digest('hex'));
    clearSession(res); return json(res, 200, { ok: true });
  }
  if (pathname === '/api/auth/me' && method === 'GET') {
    const user = getSessionUser(req); return user ? json(res, 200, { user }) : json(res, 401, { error: 'Sessão terminada.' });
  }
  if (pathname === '/api/auth/config' && method === 'GET') {
    return json(res, 200, { registrationAvailable: statements.userCount.get().count === 0 || process.env.ALLOW_SIGNUPS === 'true' });
  }
  if (pathname === '/api/auth/forgot-password' && method === 'POST') {
    if (!checkRateLimit(req, res)) return;
    const body = await readJson(req), email = String(body.email || '').trim().toLowerCase(), user = statements.userByEmail.get(email);
    if (user) {
      const token = crypto.randomBytes(32).toString('base64url'), digest = crypto.createHash('sha256').update(token).digest('hex'), expires = new Date(Date.now() + 60 * 60_000).toISOString();
      db.prepare('INSERT INTO password_resets (token_hash,user_id,expires_at,used) VALUES (?,?,?,0)').run(digest, user.id, expires);
      try { await sendRecoveryEmail(user, token); } catch (error) { console.error('Email de recuperação falhou:', error.message); }
    }
    return json(res, 200, { message: 'Se o email estiver registado e o serviço de email configurado, receberás um link de recuperação.' });
  }
  if (pathname === '/api/auth/reset' && method === 'POST') {
    if (!checkRateLimit(req, res)) return;
    const body = await readJson(req), token = String(body.token || ''), password = String(body.password || '');
    if (password.length < 12 || password.length > 200) return json(res, 400, { error: 'A nova palavra-passe precisa de pelo menos 12 caracteres.' });
    const digest = crypto.createHash('sha256').update(token).digest('hex'), reset = db.prepare('SELECT * FROM password_resets WHERE token_hash=? AND used=0 AND expires_at>?').get(digest, nowIso());
    if (!reset) return json(res, 400, { error: 'Este link expirou ou já foi utilizado.' });
    const salt = crypto.randomBytes(16), hash = await scrypt(password, salt, 64, { N: 32768, r: 8, p: 1, maxmem: 80 * 1024 * 1024 });
    db.exec('BEGIN IMMEDIATE');
    try {
      db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(`scrypt$32768$8$1$${salt.toString('base64url')}$${Buffer.from(hash).toString('base64url')}`, reset.user_id);
      db.prepare('UPDATE password_resets SET used=1 WHERE token_hash=?').run(digest);
      db.prepare('DELETE FROM sessions WHERE user_id=?').run(reset.user_id);
      db.exec('COMMIT');
    } catch (error) { db.exec('ROLLBACK'); throw error; }
    return json(res, 200, { ok: true, message: 'Palavra-passe alterada. Inicia sessão com a palavra-passe nova.' });
  }

  const user = requireUser(req, res); if (!user) return;
  if (pathname === '/api/products' && method === 'GET') {
    const rows = db.prepare('SELECT * FROM products WHERE user_id=? ORDER BY created_at DESC').all(user.id);
    return json(res, 200, { products: rows.map(parseProduct) });
  }
  if (pathname === '/api/products' && method === 'POST') {
    const body = await readJson(req), name = cleanText(body.name, 160, 'Nome'); let url;
    try { url = new URL(String(body.url || '')); } catch { return json(res, 400, { error: 'O endereço do produto não é válido.' }); }
    if (url.protocol !== 'https:' || !hostAllowed(url.hostname)) return json(res, 400, { error: 'Esta loja ainda não está autorizada. Configura STORE_ALLOWLIST no .env.' });
    const target = body.target === null || body.target === '' ? null : Number(body.target);
    if (target !== null && (!Number.isFinite(target) || target < 0 || target > 10_000_000)) return json(res, 400, { error: 'O preço-alvo não é válido.' });
    const interval = intervalMinutes(body.intervalMinutes ?? body.interval);
    const id = uuid(), created = nowIso();
    try {
      db.prepare('INSERT INTO products (id,user_id,name,url,store,target_price,interval_minutes,next_check_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)').run(id,user.id,name,url.href,url.hostname,target,interval,created,created,created);
    } catch (error) { if (String(error.message).includes('UNIQUE')) return json(res, 409, { error: 'Este endereço já está na tua lista.' }); throw error; }
    const row = productOwned(user.id,id);
    return json(res, 201, { product: parseProduct(row) });
  }
  const historyMatch = pathname.match(/^\/api\/products\/([\w-]+)\/history$/);
  if (historyMatch && method === 'GET') {
    const product = productOwned(user.id, historyMatch[1]);
    if (!product) return json(res, 404, { error: 'Produto não encontrado.' });
    const days = Math.min(90, Math.max(1, Number.parseInt(url.searchParams.get('days') || '30', 10) || 30));
    const since = new Date(Date.now() - days * 86_400_000).toISOString();
    const rows = db.prepare('SELECT price,captured_at FROM price_history WHERE product_id=? AND captured_at>=? ORDER BY captured_at DESC LIMIT 500').all(product.id, since).reverse();
    return json(res, 200, { history: rows.map(row => ({ price: row.price, time: row.captured_at })) });
  }
  const productMatch = pathname.match(/^\/api\/products\/([\w-]+)(?:\/(check))?$/);
  if (productMatch) {
    const [, id, action] = productMatch, product = productOwned(user.id,id);
    if (!product) return json(res, 404, { error: 'Produto não encontrado.' });
    if (action === 'check' && method === 'POST') {
      const result = await checkProduct(product), updated = productOwned(user.id,id);
      return json(res, result.ok ? 200 : 422, { ...result, product: parseProduct(updated) });
    }
    if (!action && method === 'PUT') {
      const body = await readJson(req), name = cleanText(body.name, 160, 'Nome'); let url;
      try { url = new URL(String(body.url || '')); } catch { return json(res, 400, { error: 'O endereço do produto não é válido.' }); }
      if (url.protocol !== 'https:' || !hostAllowed(url.hostname)) return json(res, 400, { error: 'Esta loja ainda não está autorizada. Configura STORE_ALLOWLIST no .env.' });
      const target = body.target === null || body.target === '' ? null : Number(body.target);
      if (target !== null && (!Number.isFinite(target) || target < 0)) return json(res, 400, { error: 'O preço-alvo não é válido.' });
      db.prepare('UPDATE products SET name=?,url=?,store=?,target_price=?,interval_minutes=?,next_check_at=?,updated_at=? WHERE id=? AND user_id=?').run(name,url.href,url.hostname,target,intervalMinutes(body.intervalMinutes ?? body.interval),nowIso(),nowIso(),id,user.id);
      return json(res, 200, { product: parseProduct(productOwned(user.id,id)) });
    }
    if (!action && method === 'PATCH') {
      const body = await readJson(req); if (typeof body.enabled !== 'boolean') return json(res,400,{error:'Indica se a monitorização deve ficar ativa.'});
      db.prepare('UPDATE products SET enabled=?,updated_at=? WHERE id=? AND user_id=?').run(body.enabled?1:0,nowIso(),id,user.id);
      return json(res,200,{product:parseProduct(productOwned(user.id,id))});
    }
    if (!action && method === 'DELETE') {
      db.prepare('DELETE FROM products WHERE id=? AND user_id=?').run(id,user.id);return json(res,200,{ok:true});
    }
  }
  if (pathname === '/api/alerts' && method === 'GET') {
    const rows = db.prepare('SELECT * FROM alerts WHERE user_id=? ORDER BY created_at DESC LIMIT 60').all(user.id);
    const total = db.prepare('SELECT COUNT(*) AS count FROM alerts WHERE user_id=?').get(user.id).count;
    return json(res,200,{total,alerts:rows.map(row=>({id:row.id,type:row.type==='stock'?'stock':'drop',title:row.title,detail:row.detail,value:row.value,time:row.created_at}))});
  }
  if (pathname === '/api/settings' && method === 'GET') {
    const row=userSettings(user.id);return json(res,200,{settings:{priceAlerts:!!row.price_alerts,stockAlerts:!!row.stock_alerts,intervalMinutes:row.interval_minutes,enabled:!!row.monitor_enabled,telegramConnected:!!row.telegram_chat_id,discordConfigured:!!process.env.DISCORD_WEBHOOK_URL}});
  }
  if (pathname === '/api/settings' && method === 'PUT') {
    const body=await readJson(req),interval=intervalMinutes(body.intervalMinutes ?? body.interval);
    db.prepare(`INSERT INTO settings (user_id,price_alerts,stock_alerts,interval_minutes,monitor_enabled) VALUES (?,?,?,?,?)
      ON CONFLICT(user_id) DO UPDATE SET price_alerts=excluded.price_alerts,stock_alerts=excluded.stock_alerts,interval_minutes=excluded.interval_minutes,monitor_enabled=excluded.monitor_enabled`)
      .run(user.id,body.priceAlerts===false?0:1,body.stockAlerts===false?0:1,interval,body.enabled===false?0:1);
    return json(res,200,{settings:{priceAlerts:body.priceAlerts!==false,stockAlerts:body.stockAlerts!==false,intervalMinutes:interval,enabled:body.enabled!==false}});
  }
  if (pathname === '/api/integrations' && method === 'GET') {
    const settings=userSettings(user.id);return json(res,200,{telegram:{available:!!process.env.TELEGRAM_BOT_TOKEN,connected:!!settings.telegram_chat_id},discord:{configured:!!process.env.DISCORD_WEBHOOK_URL},email:{configured:!!(process.env.RESEND_API_KEY&&process.env.MAIL_FROM&&process.env.PUBLIC_ORIGIN)}});
  }
  if (pathname === '/api/integrations/telegram/connect' && method === 'POST') {
    if (!process.env.TELEGRAM_BOT_TOKEN) return json(res,503,{error:'Define TELEGRAM_BOT_TOKEN no ambiente do servidor.'});
    const response=await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/getUpdates?limit=25&allowed_updates=%5B%22message%22%5D`,{signal:AbortSignal.timeout(10_000)}),result=await response.json();
    if(!response.ok||!result.ok)return json(res,502,{error:'Telegram não devolveu atualizações. Envia /start ao bot e tenta novamente.'});
    const update=[...result.result].reverse().find(item=>item.message?.chat?.type==='private'&&/^\/start(?:\s|$)/.test(item.message?.text||''));
    if(!update)return json(res,404,{error:'Abre o bot no Telegram, envia /start e tenta novamente.'});
    db.prepare('INSERT INTO settings (user_id,telegram_chat_id) VALUES (?,?) ON CONFLICT(user_id) DO UPDATE SET telegram_chat_id=excluded.telegram_chat_id').run(user.id,String(update.message.chat.id));
    return json(res,200,{connected:true,message:'Telegram ligado a esta conta.'});
  }
  if (pathname === '/api/integrations/telegram' && method === 'DELETE') {
    db.prepare('INSERT INTO settings (user_id,telegram_chat_id) VALUES (?,NULL) ON CONFLICT(user_id) DO UPDATE SET telegram_chat_id=NULL').run(user.id);return json(res,200,{connected:false});
  }
  if (pathname === '/api/integrations/test' && method === 'POST') {
    const settings=userSettings(user.id),body=await readJson(req),channel=body.channel;
    if(channel==='telegram'){
      if(!process.env.TELEGRAM_BOT_TOKEN||!settings.telegram_chat_id)return json(res,400,{error:'Configura e liga primeiro o Telegram.'});
      try{await sendTelegramNotification(settings.telegram_chat_id,'Vigia ligado. Vais receber aqui os alertas de preço.');return json(res,200,{ok:true})}catch{return json(res,502,{error:'Telegram recusou a mensagem de teste.'})}
    }
    if(channel==='discord'){
      if(!process.env.DISCORD_WEBHOOK_URL)return json(res,400,{error:'Define DISCORD_WEBHOOK_URL no ambiente do servidor.'});
      try{await sendDiscordNotification('Vigia ligado. Vais receber aqui os alertas de preço.');return json(res,200,{ok:true})}catch(error){return json(res,502,{error:error.message})}
    }
    return json(res,400,{error:'Canal de integração desconhecido.'});
  }
  return json(res,404,{error:'Endpoint não encontrado.'});
}
const mimeTypes={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.svg':'image/svg+xml','.png':'image/png','.ico':'image/x-icon'};
async function handleRequest(req,res){
  setSecurityHeaders(res);
  let url;try{url=new URL(req.url,`http://${req.headers.host||'localhost'}`)}catch{return json(res,400,{error:'Endereço do pedido inválido.'})}
  if(url.pathname.startsWith('/api/')){
    try{return await handleApi(req,res,url)}catch(error){console.error('API error:',error.stack||error);if(!res.headersSent)return json(res,error.status||500,{error:error.status?error.message:'O servidor encontrou um erro.'});res.destroy();return}
  }
  if(req.method!=='GET'&&req.method!=='HEAD')return json(res,405,{error:'Método não permitido.'});
  const route=url.pathname==='/'?'/index.html':url.pathname;
  if(!['/index.html','/app.js','/integration.js','/styles.css'].includes(route))return json(res,404,{error:'Página não encontrada.'});
  try{const data=await fs.promises.readFile(path.join(ROOT,route.slice(1)));res.writeHead(200,{'Content-Type':mimeTypes[path.extname(route)],'Cache-Control':route==='/index.html'?'no-cache':'public, max-age=3600'});res.end(req.method==='HEAD'?undefined:data)}catch{json(res,404,{error:'Ficheiro não encontrado.'})}
}
const server=http.createServer((req,res)=>void handleRequest(req,res));
server.listen(PORT,'0.0.0.0',()=>console.log(`Vigia online em http://localhost:${PORT} (${NODE_ENV})`));
setInterval(()=>void runMonitor(),15_000).unref();
setInterval(()=>{const cutoff=nowIso();db.prepare('DELETE FROM sessions WHERE expires_at<=?').run(cutoff);db.prepare('DELETE FROM password_resets WHERE expires_at<=? OR used=1').run(cutoff)},60*60_000).unref();
process.on('SIGTERM',()=>{server.close(()=>{db.close();process.exit(0)})});
process.on('SIGINT',()=>{server.close(()=>{db.close();process.exit(0)})});



