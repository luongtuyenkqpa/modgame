/**
 * ======================================================
 *  GOD MODE v4.0 — BACKEND SERVER (NÂNG CẤP BẢO MẬT)
 *  - BỎ chữ ký HMAC request (X-Ts/X-Nonce/X-Sign) theo yêu cầu
 *  - ẨN TOÀN BỘ link API: prefix = 12 ký tự hex derived từ SECRET
 *    (client tự tính ra cùng giá trị → người ngoài quét không tìm thấy)
 *  - SESSION KHÔNG TRẠNG THÁI (HMAC-signed token) → sống qua mọi lần
 *    Vercel khởi động lại / cold start (không phụ thuộc Map trong bộ nhớ)
 *  - BAN VĨNH VIỄN IP + THIẾT BỊ khi phát hiện: máy ảo/emulator,
 *    proxy/VPN/datacenter, trình duyệt giả/webdriver/headless.
 *    Chỉ admin mở khoá thì dùng lại được.
 *    → Lưu ban vào Vercel KV (Upstash) nếu có env KV_REST_API_URL/TOKEN
 *      để tồn tại vĩnh viễn qua restart; nếu không có thì in-memory
 *      (mất khi cold start) + seed từ env BANNED_LIST.
 *  - Chỉ chấp nhận: máy Android/iOS THẬT + trình duyệt THẬT + mạng THẬT.
 *  - Admin: đổi mật khẩu (hash scrypt), bật/tắt auto-ban & mobile-only,
 *    quản lý danh sách ban (unban/ban thủ công), log hiển thị TÊN MÁY,
 *    xem danh sách thiết bị đã kết nối.
 *  - Anti-dump/hook: đáp án mã hóa AES-256-GCM bằng key derive từ
 *    session token, token xoay sau mỗi request, phiên ràng buộc
 *    key+hwid+ip+fp, thời gian sống ngắn (5 phút).
 * ======================================================
 *  Cài: npm install express@^4 cheerio cors
 *  Chạy local: node server.js
 *  Vercel: index.js require('./server.js') → export app
 * ======================================================
 */
'use strict';
const express  = require('express');
const cheerio  = require('cheerio');
const cors     = require('cors');
const https    = require('https');
const crypto   = require('crypto');
const app      = express();
const PORT     = process.env.PORT || 3000;

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.disable('x-powered-by');
app.set('trust proxy', 1);

// Security headers
app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cache-Control', 'no-store');
    next();
});

// CORS: chỉ cho OLM + no-origin (GM_xmlhttpRequest)
app.use(cors({
    origin: (origin, cb) => {
        const allowed = ['https://olm.vn', 'https://www.olm.vn', 'http://localhost', undefined];
        if (!origin || allowed.some(o => origin === o || (o && origin.endsWith('.olm.vn')))) cb(null, true);
        else cb(null, false);
    },
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'X-Session', 'X-Fp-Hash', 'X-Seq', 'X-HWID']
}));
app.options(/.*/, cors());

// ══════════════════════════════════════════════════════════════════════════════
//  SECRET & ẨN API PREFIX
// ══════════════════════════════════════════════════════════════════════════════
// Client (connector) dùng CÙNG giá trị mặc định này → tự tính ra cùng prefix.
// Để tăng bảo mật: đặt env GODMODE_SECRET (64 hex) trên Vercel + cập nhật
// API_SECRET trong connector cho khớp.
const DEFAULT_SECRET = 'a7f3c9e1b2d48506fae1c7d3b9f0e2a4c6d8f1a3b5e7c9d0f2a4c6e8b1d3f5a7';
let SECRET = process.env.GODMODE_SECRET || DEFAULT_SECRET;
function hmacHex(s) { return crypto.createHmac('sha256', SECRET).update(s).digest('hex'); }
function computeApiPrefix(sec) { return '/' + crypto.createHmac('sha256', sec).update('godmode:api:prefix:v4').digest('hex').slice(0, 12); }
let API_PREFIX = computeApiPrefix(SECRET);
console.log('[SECURITY] Ẩn API prefix: ' + API_PREFIX + ' (client tự tính từ SECRET)');

// Đường dẫn admin (có thể đổi qua env để ẩn)
const ADMIN_PATH = process.env.ADMIN_PATH || '/admin';

// ══════════════════════════════════════════════════════════════════════════════
//  STATELESS SESSION (chống Vercel restart — không lưu Map trên server)
//  Token = base64url(payload_json) + '.' + hmacSha256(SECRET, 'sess:' + body)
// ══════════════════════════════════════════════════════════════════════════════
function b64url(buf) { return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function b64urlDecode(s) { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; return Buffer.from(s, 'base64'); }
function signSession(payload) {
    const body = b64url(JSON.stringify(payload));
    const sig  = b64url(crypto.createHmac('sha256', SECRET).update('sess:' + body).digest());
    return body + '.' + sig;
}
function verifySession(token) {
    if (!token || typeof token !== 'string' || !token.includes('.')) return null;
    const [body, sig] = token.split('.');
    const expected = b64url(crypto.createHmac('sha256', SECRET).update('sess:' + body).digest());
    try {
        if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
        const p = JSON.parse(b64urlDecode(body).toString());
        if (!p.exp || p.exp < Date.now()) return null;
        return p;
    } catch (_) { return null; }
}
const SESSION_TTL = 5 * 60 * 1000; // 5 phút

// ══════════════════════════════════════════════════════════════════════════════
//  BAN STORE — ban vĩnh viễn IP + thiết bị (HWID)
//  Lưu: in-memory Map + (tùy chọn) Vercel KV để tồn tại qua restart.
// ══════════════════════════════════════════════════════════════════════════════
const banned = new Map(); // 'ip:x.x.x.x' hoặc 'dev:HWID' -> {reason, device, t, by}
const devices = new Map(); // hwid -> {name, model, os, ip, lastSeen}
let AUTO_BAN   = process.env.AUTO_BAN !== 'false';      // auto-ban khi phát hiện bất hợp lệ (mặc định BẬT)
let MOBILE_ONLY = process.env.MOBILE_ONLY !== 'false';  // chỉ chấp nhận Android/iOS thật (mặc định BẬT)
let BAN_DESKTOP = process.env.BAN_DESKTOP === 'true';   // ban cả desktop (mặc định TẮT — chỉ từ chối)

// Seed ban từ env (BANNED_LIST=ip1,ip2 hoặc dev:HW1,...)
try {
    (process.env.BANNED_LIST || '').split(',').map(s => s.trim()).filter(Boolean).forEach(k => {
        const key = k.includes(':') ? k : 'ip:' + k;
        banned.set(key, { reason: 'seed-env', device: '', t: Date.now(), by: 'env' });
    });
} catch (_) {}

// ── Vercel KV / Upstash REST (tùy chọn) ──
const KV_URL = process.env.KV_REST_API_URL;
const KV_TOKEN = process.env.KV_REST_API_TOKEN;
const KV_ENABLED = !!(KV_URL && KV_TOKEN);
const KV_KEY = 'godmode_v4_state';
function kvRequest(path) {
    return new Promise((resolve) => {
        if (!KV_ENABLED) return resolve(null);
        const url = KV_URL.replace(/\/$/, '') + path;
        const u = new URL(url);
        const req = https.get({
            hostname: u.hostname, path: u.pathname + u.search,
            headers: { Authorization: 'Bearer ' + KV_TOKEN }, timeout: 4000
        }, (r) => {
            let raw = ''; r.on('data', c => raw += c); r.on('end', () => {
                try { resolve(JSON.parse(raw)); } catch (_) { resolve(null); }
            });
        });
        req.on('error', () => resolve(null));
        req.on('timeout', () => { req.destroy(); resolve(null); });
    });
}
async function kvLoadState() {
    if (!KV_ENABLED) return;
    try {
        const r = await kvRequest('/get/' + KV_KEY);
        if (r && r.result) {
            const st = JSON.parse(Buffer.from(r.result, 'base64').toString());
            if (st && st.bans) for (const [k, v] of Object.entries(st.bans)) banned.set(k, v);
            if (st && st.devices) for (const [k, v] of Object.entries(st.devices)) devices.set(k, v);
            if (st && typeof st.autoBan === 'boolean') AUTO_BAN = st.autoBan;
            if (st && typeof st.mobileOnly === 'boolean') MOBILE_ONLY = st.mobileOnly;
            if (st && typeof st.banDesktop === 'boolean') BAN_DESKTOP = st.banDesktop;
            if (st && st.adminHash) ADMIN_HASH = st.adminHash;
            if (st && st.adminUser) ADMIN_USER = st.adminUser;
            if (st && st.secret) { SECRET = st.secret; API_PREFIX = computeApiPrefix(SECRET); }
        }
    } catch (_) {}
}
async function kvSaveState() {
    if (!KV_ENABLED) return;
    try {
        const st = {
            bans: Object.fromEntries(banned),
            devices: Object.fromEntries(devices),
            autoBan: AUTO_BAN, mobileOnly: MOBILE_ONLY, banDesktop: BAN_DESKTOP,
            adminHash: ADMIN_HASH, adminUser: ADMIN_USER, secret: SECRET, t: Date.now()
        };
        const val = Buffer.from(JSON.stringify(st)).toString('base64');
        await kvRequest('/set/' + KV_KEY + '/' + encodeURIComponent(val));
    } catch (_) {}
}
let kvLoaded = false;
let kvLoadPromise = null;
function ensureKvLoaded() {
    if (!KV_ENABLED) return Promise.resolve();
    if (kvLoaded) return Promise.resolve();
    if (!kvLoadPromise) { kvLoadPromise = kvLoadState().then(() => { kvLoaded = true; }); }
    return kvLoadPromise;
}
ensureKvLoaded();

function isBanned(ip, hwid) {
    if (banned.has('ip:' + ip)) return banned.get('ip:' + ip);
    if (hwid && banned.has('dev:' + hwid)) return banned.get('dev:' + hwid);
    return null;
}
function addBan(ip, hwid, reason, deviceName) {
    if (ip) banned.set('ip:' + ip, { reason, device: deviceName || '', t: Date.now(), by: 'auto' });
    if (hwid) banned.set('dev:' + hwid, { reason, device: deviceName || '', t: Date.now(), by: 'auto', ip });
    kvSaveState();
    adminLog('ban', { ip, hwid, reason, device: deviceName || '' });
}
function removeBan(key) { banned.delete(key); kvSaveState(); }

// ══════════════════════════════════════════════════════════════════════════════
//  ADMIN — tài khoản/mật khẩu hash (scrypt), đổi được trong dashboard
// ══════════════════════════════════════════════════════════════════════════════
function hashPass(pw, salt) {
    salt = salt || crypto.randomBytes(16).toString('hex');
    const h = crypto.scryptSync(String(pw), salt, 64).toString('hex');
    return salt + ':' + h;
}
function verifyPass(pw, stored) {
    try {
        const [salt, h] = String(stored).split(':');
        const chk = crypto.scryptSync(String(pw), salt, 64);
        return crypto.timingSafeEqual(Buffer.from(h, 'hex'), chk);
    } catch (_) { return false; }
}
let ADMIN_USER = process.env.ADMIN_USER || 'Adminn';
let ADMIN_HASH = process.env.ADMIN_PASS_HASH || hashPass(process.env.ADMIN_PASS || '120510@');
const adminLogins = new Map();
const adminSessions = new Map();
setInterval(() => { const now = Date.now(); for (const [t, s] of adminSessions) if (s.exp < now) adminSessions.delete(t); }, 60000).unref();

// ── Log (ring buffer) ──
const ADMIN_LOG = [];
const ADMIN_LOG_MAX = 500;
function adminLog(type, data) {
    try {
        const entry = Object.assign({ t: new Date().toISOString(), type }, data || {});
        ADMIN_LOG.unshift(entry);
        if (ADMIN_LOG.length > ADMIN_LOG_MAX) ADMIN_LOG.length = ADMIN_LOG_MAX;
    } catch (_) {}
}
function maskKey(k) { if (!k) return ''; const s = String(k); return s.length <= 4 ? '****' : s.slice(0, 3) + '***' + s.slice(-2); }
function deviceNameOf(hwid) { const d = hwid && devices.get(hwid); return d ? d.name : ''; }

// ── Helpers ──
function getClientIp(req) {
    const fwd = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    return fwd || req.ip || (req.socket && req.socket.remoteAddress) || '';
}
function isLoopbackIp(ip) { return ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1'; }
const rateBuckets = new Map();
function rateLimit(key, max, windowMs) {
    const now = Date.now();
    const arr = (rateBuckets.get(key) || []).filter(t => now - t < windowMs);
    if (arr.length >= max) { rateBuckets.set(key, arr); return false; }
    arr.push(now); rateBuckets.set(key, arr); return true;
}
setInterval(() => {
    const now = Date.now();
    for (const [k, arr] of rateBuckets) {
        const f = arr.filter(t => now - t < 120000);
        if (f.length === 0) rateBuckets.delete(k); else rateBuckets.set(k, f);
    }
}, 60000).unref();

// ══════════════════════════════════════════════════════════════════════════════
//  HONEYPOT + BAN MIDDLEWARE — quét đường dẫn cũ / /api/* → ban vĩnh viễn
// ══════════════════════════════════════════════════════════════════════════════
const HONEYPOT_PATHS = ['/api', '/.env', '/wp-admin', '/phpmyadmin', '/.git', '/config', '/server.js',
    '/backup', '/source', '/install', '/console', '/debug', '/shell', '/etc', '/admin/login.php',
    '/xmlrpc.php', '/.htaccess', '/wp-login.php'];
app.use(async (req, res, next) => {
    await ensureKvLoaded();
    const ip = getClientIp(req);
    const isLoopback = ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';
    // Đã bị ban → trả 404 trơn (không tiết lộ)
    if (isBanned(ip, req.headers['x-hwid'])) return res.status(404).json({ error: 'Not found' });
    const p = req.path;
    // Honeypot: /api/* (prefix cũ) và các đường dẫn quét phổ biến → BAN VĨNH VIỄN
    if (HONEYPOT_PATHS.some(h => p === h || p.startsWith(h + '/'))) {
        if (!isLoopback && AUTO_BAN) addBan(ip, null, 'honeypot-scan:' + p, '');
        return res.status(404).json({ error: 'Not found' });
    }
    next();
});

// ══════════════════════════════════════════════════════════════════════════════
//  PHÁT HIỆN MẠNG (proxy/VPN/datacenter) — cache 1h, fail-open an toàn
// ══════════════════════════════════════════════════════════════════════════════
const ipCache = new Map();
const DC_KEYWORDS = ['amazon', 'google cloud', 'microsoft azure', 'digitalocean', 'ovh', 'hetzner', 'linode',
    'vultr', 'choopa', 'leaseweb', 'colocrossing', 'data center', 'datacenter', 'hosting', 'proxy', 'vpn',
    'shadowsocks', 'contabo', 'buyvm', 'greencloud', 'alibaba', 'tencent cloud', 'oracle cloud', 'ibm cloud',
    'scaleway', 'online.net', 'dedibox', 'cloudflare', 'fastly'];
const ALLOW_LIST = (process.env.PROXY_ALLOW_LIST || '').split(',').map(x => x.trim()).filter(Boolean);
function checkProxyIp(ip) {
    return new Promise((resolve) => {
        if (!ip || ALLOW_LIST.includes(ip)) return resolve({ risk: 'low' });
        const hit = ipCache.get(ip);
        if (hit && hit.expire > Date.now()) return resolve(hit.info);
        const done = (info) => { ipCache.set(ip, { info, expire: Date.now() + 3600000 }); resolve(info); };
        const req = https.get(`https://api.ipapi.is/?q=${encodeURIComponent(ip)}`, { timeout: 4000 }, (r) => {
            let raw = ''; r.on('data', c => raw += c); r.on('end', () => {
                try {
                    const j = JSON.parse(raw);
                    const org = ((j.asn && j.asn.org) || (j.company && j.company.name) || '').toLowerCase();
                    const isDC = !!(j.is_datacenter || (j.company && j.company.type === 'hosting'));
                    const isVPN = !!(j.is_vpn || j.is_proxy || j.is_tor || j.is_abuser);
                    const kw = DC_KEYWORDS.some(k => org.includes(k));
                    done({ risk: (isDC || isVPN || kw) ? 'high' : 'low', isDC, isVPN, country: (j.location && j.location.country_code) || '', org });
                } catch (_) { done({ risk: 'low', note: 'lookup-fail' }); }
            });
        });
        req.on('error', () => done({ risk: 'low', note: 'lookup-error' }));
        req.on('timeout', () => { req.destroy(); done({ risk: 'low', note: 'lookup-timeout' }); });
    });
}

// ══════════════════════════════════════════════════════════════════════════════
//  PHÁT HIỆN THIẾT BỊ THẬT (Android/iOS) — máy ảo/emulator/trình duyệt giả → BAN
//  Trả về: { ok, ban (bool), reason, deviceName }
// ══════════════════════════════════════════════════════════════════════════════
const EMU_MARKERS = ['emulator', 'sdk built for', 'genymotion', 'bluestacks', 'nox', 'ldplayer', 'memu',
    'andy', 'droid4x', 'ipadian', 'windroy', 'youwave', 'leapdroid', 'koplayer', 'remix os', 'phoenixos',
    'primeos', 'virtualbox', 'vmware', 'qemu', 'android_x86', 'x86_64; rv', 'sm-n976n', 'sm-g977n'];
const BAD_UA = ['headlesschrome', 'phantom', 'puppeteer', 'selenium', 'webdriver', 'playwright', 'electron',
    'cef', 'wkhtml', 'chrome-lighthouse', 'bot', 'crawl', 'spider', 'scrapy', 'curl', 'wget',
    'python-requests', 'axios', 'okhttp', 'java/', 'go-http-client', 'libwww', 'httpclient', 'postman', 'insomnia'];
function validateDevice(fp, device, uaHeader) {
    const ua = String((fp && fp.ua) || uaHeader || '').toLowerCase();
    const dev = device || {};
    // 1. Trình duyệt giả / bot / webdriver → BAN
    if (BAD_UA.some(k => ua.includes(k))) return { ok: false, ban: true, reason: 'trình duyệt giả/bot (UA)', deviceName: '' };
    if (fp && fp.webdriver === true) return { ok: false, ban: true, reason: 'webdriver/automation', deviceName: '' };
    if (!ua || ua.length < 20) return { ok: false, ban: true, reason: 'UA không hợp lệ', deviceName: '' };
    // 2. Máy ảo / emulator → BAN
    if (EMU_MARKERS.some(k => ua.includes(k))) return { ok: false, ban: true, reason: 'máy ảo/emulator (UA)', deviceName: '' };
    // 3. Xác định mobile thật
    const isAndroid = /android/i.test(ua);
    const isIOS = /iphone|ipad|ipod/i.test(ua);
    // Tên máy (hiển thị trong log admin)
    let deviceName = '';
    if (isAndroid) {
        const m = ua.match(/;\s*([^;)]+?)\s+build\//i) || ua.match(/android\s+[^;)]+;\s*([^;)]+)/i);
        deviceName = m ? m[1].trim() : (dev.model || 'Android Device');
    } else if (isIOS) {
        deviceName = /ipad/i.test(ua) ? 'iPad' : /ipod/i.test(ua) ? 'iPod' : 'iPhone';
        if (dev.model) deviceName += ' ' + dev.model;
    } else {
        deviceName = dev.model || navigator_platform_fallback(fp);
    }
    // 4. Chỉ chấp nhận Android/iOS thật (nếu MOBILE_ONLY)
    if (MOBILE_ONLY && !isAndroid && !isIOS) {
        return { ok: false, ban: BAN_DESKTOP, reason: 'không phải máy Android/iOS thật', deviceName };
    }
    // 5. Cảm ứng: mobile thật phải có touch
    const touch = dev.touchPoints != null ? dev.touchPoints : (fp && fp.maxTouchPoints);
    if ((isAndroid || isIOS) && (touch == null || touch < 1)) return { ok: false, ban: true, reason: 'thiếu cảm ứng (emulator)', deviceName };
    // 6. Số nhân CPU: <2 → giả lập
    const cores = dev.cores || (fp && fp.hardwareConcurrency) || 0;
    if (cores && cores < 2) return { ok: false, ban: true, reason: 'CPU bất thường (<2 nhân)', deviceName };
    // 7. Màn hình: quá nhỏ → giả
    const scr = dev.screen || (fp && fp.screen) || '';
    const sm = String(scr).match(/(\d+)x(\d+)/);
    const w = sm ? parseInt(sm[1], 10) : 0;
    if (w && w < 320) return { ok: false, ban: true, reason: 'màn hình bất thường', deviceName };
    if ((isAndroid || isIOS) && w > 1400) return { ok: false, ban: true, reason: 'màn hình desktop giả mobile', deviceName };
    // 8. RAM: nếu browser có expose và <1 → nghi
    const mem = dev.memory || (fp && fp.deviceMemory) || 0;
    if (mem && mem < 1) return { ok: false, ban: true, reason: 'RAM bất thường', deviceName };
    return { ok: true, ban: false, reason: '', deviceName };
}
function navigator_platform_fallback(fp) { return (fp && fp.platform) || 'Unknown'; }

// ══════════════════════════════════════════════════════════════════════════════
//  MÃ HÓA ĐÁP ÁN AES-256-GCM (anti-dump) — key derive từ session token
// ══════════════════════════════════════════════════════════════════════════════
function deriveKey(sessionToken) { return crypto.pbkdf2Sync(sessionToken + '|' + SECRET, 'godmode-v4-salt', 1000, 32, 'sha256'); }
function encryptAnswers(questions, sessionToken) {
    const key = deriveKey(sessionToken);
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', key, iv);
    let enc = c.update(JSON.stringify(questions), 'utf8', 'base64');
    enc += c.final('base64');
    return { iv: iv.toString('base64'), tag: c.getAuthTag().toString('base64'), data: enc };
}
function fpHash(fp) { return crypto.createHmac('sha256', SECRET).update(JSON.stringify(fp || {}).slice(0, 800)).digest('hex').slice(0, 16); }

// Kiểm tra session stateless cho endpoint nhạy cảm (process/fire)
function requireSession(req, res) {
    const token = req.headers['x-session'];
    const sess = verifySession(token);
    if (!sess) { res.status(403).json({ success: false, message: 'Phiên không hợp lệ hoặc hết hạn' }); return false; }
    const { key, hwid } = req.body || {};
    if (sess.k !== key) { res.status(403).json({ success: false, message: 'Phiên không khớp key' }); return false; }
    if (sess.h !== (hwid || '')) { res.status(403).json({ success: false, message: 'Phiên không khớp thiết bị' }); return false; }
    if (sess.ip && sess.ip !== getClientIp(req)) { res.status(403).json({ success: false, message: 'IP thay đổi trong phiên' }); return false; }
    const fph = req.headers['x-fp-hash'];
    if (fph && sess.fp && fph !== sess.fp) { res.status(403).json({ success: false, message: 'Dấu vân tay thay đổi' }); return false; }
    req._sess = sess; req._token = token;
    return true;
}
// Xoay session token sau mỗi request thành công (token bị hook sẽ hết hạn sau 5 phút)
function rotateSession(req, payload) {
    if (!req._sess) return payload;
    const old = req._sess;
    const newTok = signSession(Object.assign({}, old, { exp: Date.now() + SESSION_TTL, seq: (old.seq || 1) + 1 }));
    payload.next_session = newTok;
    return payload;
}

// ══════════════════════════════════════════════════════════════════════════════
//  CORE LOGIC (giữ nguyên từ bản gốc — chạy trên Node.js)
// ══════════════════════════════════════════════════════════════════════════════
const SECRET_KEY = process.env.OLM_SECRET_KEY || '1047823200';
const APP_ID = process.env.APP_ID || 'tiep_god_mode_v3';

function decryptOLM(base64Str) {
    if (!base64Str) return null;
    try {
        const rawBuf = Buffer.from(base64Str, 'base64');
        const rawStr = rawBuf.toString('latin1');
        let decrypted = '';
        for (let i = 0; i < rawStr.length; i++) {
            decrypted += String.fromCharCode(rawStr.charCodeAt(i) ^ SECRET_KEY.charCodeAt(i % SECRET_KEY.length));
        }
        return Buffer.from(Uint8Array.from(decrypted, c => c.charCodeAt(0))).toString('utf-8');
    } catch (e) { console.error('[decryptOLM]', e.message); return null; }
}
function extractAnswers(htmlContent) {
    const $ = cheerio.load(htmlContent);
    let answers = [];
    const correctNodes = $('.correctAnswer');
    if (correctNodes.length > 0) { correctNodes.each((_, el) => answers.push($(el).text().replace('||', '').trim())); return answers; }
    const fillInNodes = $('input[data-accept]');
    if (fillInNodes.length > 0) { fillInNodes.each((_, el) => answers.push($(el).attr('data-accept'))); return answers; }
    let isMatching = false;
    $('li').each((_, li) => {
        const text = $(li).text().trim();
        if (text.includes('||')) { isMatching = true; answers.push(text.split('||').map(s => s.trim()).filter(s => s).join(' ➔ ')); }
    });
    if (isMatching) return answers;
    return ['Không tự động trích xuất được.'];
}
function buildParams(sq) {
    const count = sq.count || 4;
    if (sq.type === 6) { const orderArr = Array.from(Array(Math.max(count, 15)), (_, k) => k); return { js: '', order_l: orderArr, order_r: orderArr }; }
    return { js: '', order: Array.from(Array(count), (_, k) => k) };
}
function findCorrectInfo(node) {
    const results = [];
    function traverse(n) {
        if (!n) return;
        const subQ_ID = n.id || n._id || (n.props ? n.props.id : null);
        if ((n.type === 'fillme-input' && n.content) || (typeof n.content === 'string' && n.content.includes('data-accept='))) {
            if (n.content.includes('data-accept=')) {
                const regex = /data-accept="([^"]+)"/g; let match;
                while ((match = regex.exec(n.content)) !== null)
                    results.push({ type: 4, ans: [match[1]], count: 1, skill: n.id_skill, subId: subQ_ID || ('raw_' + Math.random()), isText: true });
            } else {
                results.push({ type: 4, ans: [n.content], count: 1, skill: n.id_skill, subId: subQ_ID, isText: true });
            }
            return;
        }
        if (n.type === 'olm-list' || (Array.isArray(n.children) && n.children.length > 0)) {
            const options = n.children;
            if (n.name === 'true-false' || n.listType === 'true-false') {
                results.push({ type: 13, ans: options.map(o => (o.correct == true || o.correct === 'true' || o.correct == 1) ? '1' : '0'), count: options.length, skill: n.id_skill, subId: subQ_ID });
                return;
            }
            if (n.name === 'link-list' || n.listType === 'matching') {
                results.push({ type: 6, ans: options.map((_, idx) => idx.toString()), count: options.length, skill: n.id_skill, subId: subQ_ID });
                return;
            }
            if (options.some(c => c.correct !== undefined)) {
                const trueIndex = options.findIndex(o => o.correct == true || o.correct === 'true' || o.correct == 1);
                results.push({ type: 1, ans: [(trueIndex === -1 ? 0 : trueIndex).toString()], count: options.length, skill: n.id_skill, subId: subQ_ID });
                return;
            }
        }
        if (Array.isArray(n.children)) n.children.forEach(traverse);
        else if (Array.isArray(n.questions)) n.questions.forEach(traverse);
        else if (Array.isArray(n.items)) n.items.forEach(traverse);
        else if (Array.isArray(n.list)) n.list.forEach(traverse);
        else if (n.root) traverse(n.root);
    }
    let contentToParse = node.json_content || node.content;
    if (typeof contentToParse === 'string' && !contentToParse.trim().startsWith('{') && !contentToParse.trim().startsWith('[')) {
        const decoded = decryptOLM(contentToParse);
        if (decoded) contentToParse = decoded;
    }
    try { traverse(typeof contentToParse === 'string' ? JSON.parse(contentToParse) : contentToParse); }
    catch (_) { traverse(node); }
    if (results.length === 0) results.push({ type: 1, ans: ['0'], count: 4, skill: null, subId: null });
    return results;
}
function buildFirePayload({ raw_questions, meta, video_length }, mode, timeStr, grade) {
    const timeParts = (timeStr || '10.00').split('.');
    const userMins = parseInt(timeParts[0]) || 0;
    let userSecsStr = timeParts[1] || '0';
    if (userSecsStr.length === 1) userSecsStr += '0';
    const userSecs = parseInt(userSecsStr.substring(0, 2));
    let calcSeconds = (userMins * 60) + userSecs;
    if (calcSeconds < 30) calcSeconds = 120;
    const totalPackages = raw_questions.length;
    const isExam = mode === 'exam', isVideo = mode === 'video';
    const now = Math.floor(Date.now() / 1000);
    let totalSeconds, timeInit;
    if (isVideo || isExam) { totalSeconds = calcSeconds; timeInit = now - totalSeconds; }
    else { totalSeconds = totalPackages * 15; timeInit = now - totalSeconds; }
    const params = new URLSearchParams();
    const fakeLog = [];
    let max_tn_score = 0, tn_score_calc = 0, tl_max_calc = 0;
    raw_questions.forEach((q, i) => {
        const subQuestions = findCorrectInfo(q);
        const sub_count = subQuestions.length;
        const is_tl = (q.q_type == 18 || q.type == 18 || q.q_type == 11);
        let final_score = sub_count;
        if (q.score !== undefined && q.score !== null && q.score !== '') final_score = parseFloat(q.score);
        else if (q.point !== undefined && q.point !== null && q.point !== '') final_score = parseFloat(q.point);
        if (!isVideo) {
            params.append('quiz_list[]', q.id || q._id);
            params.append(`score_list[${q.id || q._id}]`, final_score);
        }
        let skillIDs = [...new Set(subQuestions.map(sq => sq.skill).filter(s => s != null))];
        if (!isVideo) skillIDs.forEach(s => params.append('correct_skill[]', s));
        if (isVideo || isExam) {
            if (is_tl && isExam) {
                tl_max_calc += final_score;
                fakeLog.push({ answer: JSON.stringify(['Học sinh đã làm phần tự luận trên máy.']), label: [''], params: '{"js":"","order":[0]}', correct_skill: [], wrong_skill: [], type: [18], result: [0], idq: parseInt(q.id || q._id), score: final_score, chk: 0 });
            } else {
                max_tn_score += final_score; tn_score_calc += final_score;
                const ans_list = [], type_list = [], prs_list = [], resArr = [], mresult = [], listIdq = [], lbl_list = [];
                for (let j = 0; j < sub_count; j++) {
                    const sq = subQuestions[j];
                    if (sq.type === 4 || sq.type === 13 || sq.type === 6) ans_list.push(JSON.stringify(sq.ans));
                    else ans_list.push(JSON.stringify(sq.ans[0] || '0'));
                    type_list.push(sq.type || 1);
                    prs_list.push(JSON.stringify(buildParams(sq)));
                    resArr.push(1); mresult.push([1]);
                    listIdq.push(sq.subId && sq.subId.toString().length > 5 ? sq.subId : `q${j}`);
                    let lbl = '';
                    if (sq.ans.length === 1 && !isNaN(sq.ans[0]) && sq.type !== 4 && sq.type !== 13)
                        lbl = ['A', 'B', 'C', 'D', 'E'][parseInt(sq.ans[0])] || '';
                    lbl_list.push(lbl);
                }
                const logItem = {
                    answer: JSON.stringify(ans_list), label: sub_count === 1 ? lbl_list : [], labels: lbl_list,
                    params: sub_count === 1 ? prs_list[0] : JSON.stringify({ js: '', prs: prs_list, order: Array.from(Array(sub_count).keys()) }),
                    correct_skill: skillIDs, wrong_skill: [], type: type_list, result: resArr, mresult, idq: parseInt(q.id || q._id), score: final_score
                };
                if (isExam) { logItem.chk = 1; if (sub_count > 1) logItem.list_idq = listIdq; }
                if (isVideo) { logItem.marker = q.marker || (i + 1); logItem.id = (q.id || q._id).toString(); }
                fakeLog.push(logItem);
            }
        } else {
            const q_params_arr = [], a_params_arr = [];
            subQuestions.forEach(sq => { q_params_arr.push(JSON.stringify(buildParams(sq))); a_params_arr.push(JSON.stringify(sq.ans)); });
            fakeLog.push({ q_params: JSON.stringify(q_params_arr), a_params: JSON.stringify(a_params_arr), result: 1, correct: 1, wrong: 0, a_index: i, time_spent: Math.floor(Math.random() * 15) + 10 });
        }
    });
    params.append('id_cate', meta.id_cate);
    params.append('id_courseware', meta.id_courseware || meta.id_cate);
    params.append('id_user', meta.id_user);
    params.append('id_grade', grade || meta.id_grade || '10');
    if (meta.id_school) params.append('id_school', meta.id_school);
    if (meta.id_group) params.append('id_group', meta.id_group);
    params.append('type_vip', '530'); params.append('time_stored', '0'); params.append('date_end', now);
    params.append('data_log', JSON.stringify(fakeLog));
    if (isVideo) {
        const vl = video_length || 900;
        params.append('type', '5'); params.append('type_exam', '0'); params.append('total_time', vl); params.append('current_time', vl);
        params.append('time_spent', totalSeconds + 2); params.append('score_10', '10'); params.append('totalq', totalPackages);
        params.append('score', tn_score_calc); params.append('max_score', max_tn_score); params.append('answered', totalPackages);
        params.append('correct', totalPackages); params.append('count_problems', totalPackages); params.append('percent', '100');
        params.append('pscore', '10'); params.append('score_status', '10');
        const vLog = { [timeInit]: 'start', [timeInit + 1]: 'start', [timeInit + 10]: 'reload' };
        params.append('log', JSON.stringify(vLog));
    } else if (isExam) {
        params.append('time_init', timeInit); params.append('time_spent', totalSeconds); params.append('score', tn_score_calc);
        params.append('max_score', max_tn_score + tl_max_calc); params.append('tn_score', tn_score_calc); params.append('type_exam', '1');
        params.append('correct', tn_score_calc); params.append('wrong', 0); params.append('name_user', ''); params.append('tl_score', '0');
        params.append('times', '0'); params.append('iframe', 'false');
        let curT = timeInit + Math.floor(totalSeconds * 0.1);
        const totalQs = raw_questions.length;
        const usableTime = Math.max(10, totalSeconds - Math.floor(totalSeconds * 0.1) - 10);
        const baseInterval = usableTime / (totalQs || 1);
        for (let c = 0; c < totalQs; c++) {
            curT += Math.floor(baseInterval * (0.7 + Math.random() * 0.6));
            if (curT >= timeInit + totalSeconds) curT = timeInit + totalSeconds - 2;
            params.append(`choose_log[${c}][ind]`, c);
            params.append(`choose_log[${c}][t]`, Math.floor(curT));
            params.append(`choose_log[${c}][l]`, c + 1);
        }
    } else {
        params.append('time_init', timeInit); params.append('time_spent', totalSeconds); params.append('time_elapsed', totalSeconds);
        params.append('score', '100'); params.append('score_10', '10'); params.append('star', '20'); params.append('theta', '0');
        params.append('max_score', '100'); params.append('answered', totalPackages); params.append('correct', totalPackages);
        params.append('wrong', '0'); params.append('missed', '0'); params.append('count_problems', totalPackages);
        params.append('type', '3'); params.append('type_exam', '0');
        const pLog = { [timeInit]: 'start', [timeInit + 1]: 'start' };
        params.append('log', JSON.stringify(pLog));
    }
    params.append('count_redo', '0'); params.append('ended', '1'); params.append('save_star', '1');
    return params.toString();
}

// ══════════════════════════════════════════════════════════════════════════════
//  KEY VALIDATION — proxy tới keyvault-vn.onrender.com
// ══════════════════════════════════════════════════════════════════════════════
function proxyVerify(key, hwid, olmUser) {
    return new Promise((resolve) => {
        const postData = JSON.stringify({ key, app: APP_ID, device: hwid || 'unknown', olm_user: olmUser || '' });
        const opts = {
            hostname: 'keyvault-vn.onrender.com', port: 443, path: '/api/verify', method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(postData) }, timeout: 15000
        };
        const req = https.request(opts, (res) => {
            let raw = '';
            res.on('data', c => raw += c);
            res.on('end', () => {
                if (res.statusCode !== 200) return resolve({ success: false, message: `KeyVault lỗi HTTP ${res.statusCode}: ${raw.slice(0, 120) || 'không phản hồi'}` });
                try {
                    const kv = JSON.parse(raw);
                    resolve({
                        success: kv.success !== undefined ? !!kv.success : !!kv.valid,
                        message: kv.message || kv.reason || (kv.valid === false ? 'Key không hợp lệ (KeyVault từ chối)' : ''),
                        type: kv.type || kv.plan || kv.level || '',
                        expires_at: kv.expires_at || kv.exp || kv.expire || ''
                    });
                } catch (_) { resolve({ success: false, message: `KeyVault trả về không phải JSON (có thể đang khởi động): ${raw.slice(0, 80)}` }); }
            });
        });
        req.on('error', e => resolve({ success: false, message: 'Lỗi kết nối KeyVault: ' + e.message }));
        req.on('timeout', () => { req.destroy(); resolve({ success: false, message: 'KeyVault timeout (server đang ngủ — thử lại)' }); });
        req.write(postData); req.end();
    });
}

// ══════════════════════════════════════════════════════════════════════════════
//  ROUTES (API ẩn tại API_PREFIX)
// ══════════════════════════════════════════════════════════════════════════════
// Root — tối thiểu, không tiết lộ endpoint
app.get('/', (_req, res) => res.json({ ok: true, t: Date.now() }));

// Ping (ẩn) — client kiểm tra kết nối
app.get(API_PREFIX + '/ping', (_req, res) => res.json({ ok: true, t: Date.now() }));

// Verify key
app.post(API_PREFIX + '/verify', async (req, res) => {
    const ip = getClientIp(req);
    if (isBanned(ip, req.body && req.body.hwid)) return res.status(404).json({ error: 'Not found' });
    if (!rateLimit('verify:' + ip, 20, 60000)) return res.status(429).json({ success: false, message: 'Quá nhiều yêu cầu' });
    const { key, hwid, olm_user } = req.body || {};
    if (!key) return res.status(400).json({ success: false, message: 'Missing key' });
    const result = await proxyVerify(key, hwid, olm_user);
    adminLog('verify', { key: maskKey(key), hwid, device: deviceNameOf(hwid), olm_user, ip, success: !!result.success, type: result.type || '', message: result.message || '' });
    res.json(result);
});

// Attestation — client gửi fp + device info, server kiểm tra máy thật + mạng thật, cấp session
app.post(API_PREFIX + '/attest', async (req, res) => {
    const ip = getClientIp(req);
    const { key, hwid, fp, device } = req.body || {};
    if (isBanned(ip, hwid)) return res.status(404).json({ error: 'Not found' });
    if (!key) return res.status(400).json({ success: false, message: 'Thiếu key' });
    if (!rateLimit('attest:' + ip, 10, 60000)) return res.status(429).json({ success: false, message: 'Quá nhiều lần xác thực' });

    // 1. Kiểm tra thiết bị thật (Android/iOS, không máy ảo, không trình duyệt giả)
    const v = validateDevice(fp, device, req.headers['user-agent']);
    if (!v.ok) {
        if (v.ban && AUTO_BAN && !isLoopbackIp(ip)) addBan(ip, hwid, v.reason, v.deviceName);
        adminLog('reject', { ip, hwid, device: v.deviceName, reason: v.reason, banned: !!(v.ban && AUTO_BAN) });
        return res.status(403).json({ success: false, message: v.ban ? 'Thiết bị/mạng không hợp lệ — đã bị khoá vĩnh viễn, liên hệ admin' : 'Chỉ hỗ trợ trên máy Android/iOS thật với trình duyệt thật' });
    }
    // 2. Kiểm tra mạng thật (không proxy/VPN/datacenter)
    const p = await checkProxyIp(ip);
    if (p.risk === 'high') {
        if (AUTO_BAN && !isLoopbackIp(ip)) addBan(ip, hwid, 'proxy/VPN/datacenter', v.deviceName);
        adminLog('reject', { ip, hwid, device: v.deviceName, reason: 'proxy/VPN/datacenter', banned: AUTO_BAN });
        return res.status(403).json({ success: false, message: 'Phát hiện proxy/VPN/datacenter — mạng không hợp lệ' + (AUTO_BAN ? ', đã bị khoá vĩnh viễn' : '') });
    }
    // 3. Key phải hợp lệ
    const kv = await proxyVerify(key, hwid);
    if (!kv.success) return res.status(401).json({ success: false, message: kv.message || 'Key không hợp lệ' });
    // 4. Đăng ký thiết bị vào registry (hiển thị tên máy trong log admin)
    devices.set(hwid || 'unknown', {
        name: v.deviceName, model: (device && device.model) || '', os: (device && device.os) || '',
        ip, lastSeen: Date.now()
    });
    kvSaveState();
    // 5. Cấp session stateless (5 phút)
    const fph = fpHash(fp);
    const token = signSession({ k: key, h: hwid || '', ip, fp: fph, dev: v.deviceName, exp: Date.now() + SESSION_TTL, seq: 1 });
    adminLog('attest', { key: maskKey(key), hwid, device: v.deviceName, ip, success: true });
    res.json({ success: true, session: token, expiresIn: 300, fpHash: fph, device: v.deviceName, message: 'Thiết bị & mạng hợp lệ — phiên đã cấp' });
});

// Process — giải mã đáp án (cần session)
app.post(API_PREFIX + '/process', async (req, res) => {
    const ip = getClientIp(req);
    if (isBanned(ip, req.body && req.body.hwid)) return res.status(404).json({ error: 'Not found' });
    if (!requireSession(req, res)) return;
    if (!rateLimit('ip:' + ip, 30, 60000)) return res.status(429).json({ success: false, message: 'Quá nhiều yêu cầu (IP)' });
    const { key, hwid, questions } = req.body || {};
    if (!key) return res.status(401).json({ success: false, message: 'Missing key' });
    if (!Array.isArray(questions) || questions.length === 0) return res.status(400).json({ success: false, message: 'No questions' });
    const kv = await proxyVerify(key, hwid);
    if (!kv.success) return res.status(401).json({ success: false, message: kv.message || 'Invalid key' });
    adminLog('process', { key: maskKey(key), hwid, device: deviceNameOf(hwid), ip, questions: questions.length, type: kv.type || '' });
    const processed = questions.map((item, index) => {
        const rawContent = item.content || item.json_content;
        const htmlDecrypted = decryptOLM(rawContent);
        const answers = htmlDecrypted ? extractAnswers(htmlDecrypted) : ['Lỗi giải mã'];
        return { index: index + 1, id: item.id, title: item.title || `Câu ${index + 1}`, answers };
    });
    // Mã hóa đáp án AES-256-GCM (anti-dump) + xoay session
    const payload = { success: true, encrypted: true, count: processed.length, payload: encryptAnswers(processed, req.headers['x-session']) };
    res.json(rotateSession(req, payload));
});

// Fire — build payload nộp bài (cần session, key VIP)
app.post(API_PREFIX + '/fire', async (req, res) => {
    const ip = getClientIp(req);
    if (isBanned(ip, req.body && req.body.hwid)) return res.status(404).json({ error: 'Not found' });
    if (!requireSession(req, res)) return;
    const { key, hwid, session, mode, time_str, grade } = req.body || {};
    if (!key) return res.status(401).json({ success: false, message: 'Missing key' });
    if (!session) return res.status(400).json({ success: false, message: 'Missing session' });
    const kv = await proxyVerify(key, hwid);
    if (!kv.success) return res.status(401).json({ success: false, message: kv.message || 'Invalid key' });
    adminLog('fire', { key: maskKey(key), hwid, device: deviceNameOf(hwid), ip, mode: mode || '', type: kv.type || '' });
    const keyType = (kv.type || '').toUpperCase();
    if (!['PREMIUM', 'VIP', 'UNLIMITED'].includes(keyType))
        return res.status(403).json({ success: false, message: 'Chức năng này yêu cầu key PREMIUM/VIP!' });
    if (!Array.isArray(session.raw_questions) || session.raw_questions.length === 0)
        return res.status(400).json({ success: false, message: 'raw_questions rỗng!' });
    if (!session.meta || !session.meta.id_user || !session.meta.id_cate)
        return res.status(400).json({ success: false, message: 'Thiếu meta (id_user / id_cate)' });
    try {
        const paramsStr = buildFirePayload(session, mode || 'practice', time_str || '10.00', grade);
        res.json(rotateSession(req, { success: true, params_str: paramsStr, endpoint: '/course/teacher-static' }));
    } catch (err) {
        console.error('[/fire]', err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// ══════════════════════════════════════════════════════════════════════════════
//  WEB ADMIN v4.0 — đăng nhập, dashboard, đổi mật khẩu, quản lý ban, log
// ══════════════════════════════════════════════════════════════════════════════
function _parseCookies(req) {
    const out = {};
    (req.headers.cookie || '').split(';').forEach(p => { const [k, ...v] = p.split('='); if (k) out[k.trim()] = decodeURIComponent(v.join('=')); });
    return out;
}
function isAdmin(req) {
    const tok = _parseCookies(req)['god_admin'];
    const sess = tok && adminSessions.get(tok);
    return !!(sess && sess.exp >= Date.now());
}
function requireAdmin(req, res) { if (!isAdmin(req)) { res.redirect(ADMIN_PATH); return false; } return true; }
function _esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }

function adminLoginPage(msg) {
    return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin — GOD MODE v4</title><style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0d1117;font-family:'Segoe UI',system-ui,sans-serif;color:#c9d1d9}
.box{width:340px;background:#161b22;border:1px solid #30363d;border-radius:14px;padding:28px;box-shadow:0 0 40px rgba(0,0,0,.6)}
h1{font-size:18px;margin:0 0 4px;background:linear-gradient(90deg,#00f2fe,#4facfe);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.sub{font-size:11px;color:#8b949e;margin-bottom:20px;font-family:monospace}
label{font-size:11px;color:#8b949e;display:block;margin:10px 0 4px;text-transform:uppercase;letter-spacing:.5px}
input{width:100%;padding:11px;background:#0d1117;border:1px solid #30363d;border-radius:8px;color:#00f2fe;font-family:monospace;font-size:14px;outline:none}
input:focus{border-color:#00f2fe;box-shadow:0 0 12px rgba(0,242,254,.3)}
button{width:100%;margin-top:18px;padding:12px;border:none;border-radius:8px;background:linear-gradient(135deg,#00b09b,#96c93d);color:#fff;font-weight:700;cursor:pointer;font-size:13px;letter-spacing:1px}
button:hover{filter:brightness(1.1)}
.err{background:rgba(239,35,60,.12);border:1px solid rgba(239,35,60,.4);color:#ef233c;padding:8px;border-radius:6px;font-size:12px;margin-top:12px;text-align:center}
</style></head><body><div class="box">
<h1>🚀 GOD MODE v4 — ADMIN</h1><div class="sub">// server control panel</div>
<form method="POST" action="${ADMIN_PATH}/login">
<label>Tài khoản</label><input name="username" autocomplete="username" autofocus>
<label>Mật khẩu</label><input type="password" name="password" autocomplete="current-password">
<button>🔓 ĐĂNG NHẬP</button>
${msg ? `<div class="err">${_esc(msg)}</div>` : ''}
</form></div></body></html>`;
}

app.get(ADMIN_PATH, (req, res) => { if (isAdmin(req)) return res.redirect(ADMIN_PATH + '/dashboard'); res.send(adminLoginPage('')); });

app.post(ADMIN_PATH + '/login', (req, res) => {
    const ip = getClientIp(req);
    const now = Date.now();
    const arr = (adminLogins.get(ip) || []).filter(t => now - t < 10 * 60000);
    if (arr.length >= 5) {
        // Quá 5 lần sai → ban IP vĩnh viễn (chống brute-force mật khẩu admin)
        if (AUTO_BAN && !isLoopbackIp(ip)) addBan(ip, null, 'brute-force admin login', '');
        return res.status(429).send(adminLoginPage('Quá nhiều lần thử sai — IP đã bị khoá.'));
    }
    arr.push(now); adminLogins.set(ip, arr);
    const { username, password } = req.body || {};
    if (username === ADMIN_USER && verifyPass(password, ADMIN_HASH)) {
        adminLogins.delete(ip);
        const tok = crypto.randomBytes(16).toString('hex');
        adminSessions.set(tok, { exp: Date.now() + 12 * 3600 * 1000 });
        res.setHeader('Set-Cookie', `god_admin=${tok}; Path=/; HttpOnly; Max-Age=43200; SameSite=Lax`);
        adminLog('admin', { action: 'login', ip });
        return res.redirect(ADMIN_PATH + '/dashboard');
    }
    res.status(401).send(adminLoginPage('Sai tài khoản hoặc mật khẩu!'));
});

app.get(ADMIN_PATH + '/logout', (req, res) => {
    const tok = _parseCookies(req)['god_admin'];
    if (tok) adminSessions.delete(tok);
    res.setHeader('Set-Cookie', 'god_admin=; Path=/; Max-Age=0');
    res.redirect(ADMIN_PATH);
});

function adminDashboardPage(msg) {
    const upt = Math.floor(process.uptime());
    const uptStr = Math.floor(upt / 3600) + 'h ' + Math.floor((upt % 3600) / 60) + 'm ' + (upt % 60) + 's';
    const logRows = ADMIN_LOG.slice(0, 80).map(e => `<tr>
<td style="font-family:monospace;font-size:10px;color:#8b949e">${_esc(new Date(e.t).toLocaleString('vi-VN'))}</td>
<td><span style="color:${e.type === 'verify' ? '#4facfe' : e.type === 'process' ? '#00e676' : e.type === 'ban' || e.type === 'reject' ? '#ef233c' : '#ffc107'}">${_esc(e.type)}</span></td>
<td style="font-family:monospace">${_esc(e.device || '')}</td>
<td style="font-family:monospace;font-size:10px">${_esc(e.hwid || '')}</td>
<td style="font-size:10px">${_esc(e.ip || '')}</td>
<td>${e.success === undefined ? '—' : (e.success ? '<span style="color:#00e676">✅</span>' : '<span style="color:#ef233c">❌</span>')}</td>
<td style="font-size:10px;max-width:180px;overflow:hidden;text-overflow:ellipsis">${_esc(e.message || (e.questions ? e.questions + ' câu' : '') || e.reason || '')}</td>
</tr>`).join('');
    const banRows = [...banned.entries()].slice(0, 50).map(([k, v]) => `<tr>
<td style="font-family:monospace;font-size:11px">${_esc(k)}</td>
<td style="font-size:11px">${_esc(v.device || '')}</td>
<td style="font-size:11px;color:#ef233c">${_esc(v.reason || '')}</td>
<td style="font-size:10px;color:#8b949e">${_esc(new Date(v.t || 0).toLocaleString('vi-VN'))}</td>
<td><form method="POST" action="${ADMIN_PATH}/unban" style="display:inline"><input type="hidden" name="key" value="${_esc(k)}"><button style="padding:4px 10px;font-size:10px;margin:0" class="danger">MỞ KHOÁ</button></form></td>
</tr>`).join('');
    const devRows = [...devices.entries()].slice(0, 50).map(([hwid, d]) => `<tr>
<td style="font-family:monospace;font-size:11px">${_esc(hwid)}</td>
<td style="font-size:11px;color:#00f2fe">${_esc(d.name || '')}</td>
<td style="font-size:10px">${_esc(d.os || '')} ${_esc(d.model || '')}</td>
<td style="font-size:10px">${_esc(d.ip || '')}</td>
<td style="font-size:10px;color:#8b949e">${_esc(new Date(d.lastSeen || 0).toLocaleString('vi-VN'))}</td>
</tr>`).join('');
    return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dashboard — GOD MODE Admin v4</title><style>
*{box-sizing:border-box}body{margin:0;background:#0d1117;font-family:'Segoe UI',system-ui,sans-serif;color:#c9d1d9;padding:20px}
.wrap{max-width:1150px;margin:0 auto}
.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:8px}
h1{font-size:20px;margin:0;background:linear-gradient(90deg,#00f2fe,#4facfe);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
a.logout{color:#ef233c;text-decoration:none;font-size:12px;border:1px solid rgba(239,35,60,.4);padding:6px 12px;border-radius:6px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:16px}
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:14px}
.card .lbl{font-size:10px;color:#8b949e;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px}
.card .val{font-size:14px;font-weight:700;font-family:monospace;color:#00f2fe;word-break:break-all}
.card .val.ok{color:#00e676}.card .val.bad{color:#ef233c}
.panel{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;margin-bottom:16px}
.panel h2{font-size:13px;margin:0 0 12px;color:#4facfe;text-transform:uppercase;letter-spacing:1px}
form.inline{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
input{padding:9px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#00f2fe;font-family:monospace;font-size:12px;outline:none;min-width:160px}
button{padding:9px 16px;border:none;border-radius:6px;background:linear-gradient(135deg,#00b09b,#96c93d);color:#fff;font-weight:700;cursor:pointer;font-size:12px}
button.danger{background:linear-gradient(135deg,#d90429,#ef233c)}
button.warn{background:linear-gradient(135deg,#f59e0b,#ef4444)}
.msg{padding:8px 12px;border-radius:6px;font-size:12px;margin-bottom:12px}
.msg.ok{background:rgba(0,230,118,.1);border:1px solid rgba(0,230,118,.3);color:#00e676}
.msg.warn{background:rgba(255,193,7,.1);border:1px solid rgba(255,193,7,.3);color:#ffc107}
table{width:100%;border-collapse:collapse;font-size:11px}
th,td{padding:6px 8px;text-align:left;border-bottom:1px solid #21262d;vertical-align:top}
th{color:#8b949e;font-size:10px;text-transform:uppercase;letter-spacing:.5px}
.hint{font-size:10px;color:#8b949e;margin-top:8px;line-height:1.6}
.toggle-row{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:10px}
.toggle{display:flex;align-items:center;gap:8px;font-size:12px;background:#0d1117;border:1px solid #30363d;padding:8px 12px;border-radius:8px}
.toggle .st{font-weight:700}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:800px){.grid2{grid-template-columns:1fr}}
</style></head><body><div class="wrap">
<div class="top"><h1>⚙️ GOD MODE v4 — ADMIN DASHBOARD</h1><a class="logout" href="${ADMIN_PATH}/logout">🚪 Đăng xuất</a></div>
${msg ? `<div class="msg ${msg.includes('thành công') || msg.includes('OK') || msg.includes('✅') ? 'ok' : 'warn'}">${_esc(msg)}</div>` : ''}
<div class="cards">
<div class="card"><div class="lbl">Trạng thái server</div><div class="val ok">● ĐANG CHẠY</div></div>
<div class="card"><div class="lbl">Uptime</div><div class="val">${uptStr}</div></div>
<div class="card"><div class="lbl">Ẩn API Prefix</div><div class="val">${_esc(API_PREFIX)}</div></div>
<div class="card"><div class="lbl">Auto-ban</div><div class="val ${AUTO_BAN ? 'ok' : 'bad'}">${AUTO_BAN ? 'BẬT' : 'TẮT'}</div></div>
<div class="card"><div class="lbl">Chỉ Android/iOS</div><div class="val ${MOBILE_ONLY ? 'ok' : 'bad'}">${MOBILE_ONLY ? 'BẬT' : 'TẮT'}</div></div>
<div class="card"><div class="lbl">Đang bị khoá</div><div class="val bad">${banned.size} IP/thiết bị</div></div>
<div class="card"><div class="lbl">Thiết bị đã kết nối</div><div class="val">${devices.size}</div></div>
<div class="card"><div class="lbl">Lưu trữ ban vĩnh viễn</div><div class="val ${KV_ENABLED ? 'ok' : 'bad'}">${KV_ENABLED ? 'KV (bền vững)' : 'CHỈ bộ nhớ (mất khi restart)'}</div></div>
</div>

<div class="panel">
<h2>🎛 BẬT / TẮT BẢO MẬT</h2>
<div class="toggle-row">
<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="autoBan"><button class="${AUTO_BAN ? 'warn' : ''}">${AUTO_BAN ? '⛔ TẮT auto-ban' : '✅ BẬT auto-ban'}</button></form>
<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="mobileOnly"><button class="${MOBILE_ONLY ? 'warn' : ''}">${MOBILE_ONLY ? '📴 TẮT chỉ-mobile' : '📱 BẬT chỉ-mobile'}</button></form>
<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="banDesktop"><button class="${BAN_DESKTOP ? 'warn' : ''}">${BAN_DESKTOP ? '💻 TẮT ban desktop' : '💻 BẬT ban desktop'}</button></form>
</div>
<div class="hint">Auto-ban: khoá vĩnh viễn IP+thiết bị khi phát hiện máy ảo/proxy/VPN/trình duyệt giả. Chỉ-mobile: chỉ chấp nhận Android/iOS thật. Ban desktop: khoá cả máy tính (mặc định tắt — chỉ từ chối).</div>
</div>

<div class="grid2">
<div class="panel">
<h2>🔑 ĐỔI MẬT KHẨU ADMIN</h2>
<form method="POST" action="${ADMIN_PATH}/change-password" class="inline" style="flex-direction:column;align-items:stretch">
<input type="password" name="old" placeholder="Mật khẩu hiện tại" required>
<input type="password" name="new" placeholder="Mật khẩu mới (tối thiểu 6 ký tự)" required>
<input type="password" name="confirm" placeholder="Xác nhận mật khẩu mới" required>
<button>💾 ĐỔI MẬT KHẨU</button>
</form>
<div class="hint">Mật khẩu được lưu dạng hash scrypt (không bao giờ lưu plaintext). Sau khi đổi, mọi phiên đăng nhập khác sẽ bị đăng xuất.${KV_ENABLED ? ' Đã lưu vào KV — tồn tại qua restart.' : ' ⚠️ Chưa có KV — đổi mật khẩu sẽ mất khi server restart (đặt env KV_REST_API_URL + KV_REST_API_TOKEN để bền vững).'}</div>
</div>
<div class="panel">
<h2>🛡 ĐỔI SECRET (ẩn API + ký phiên)</h2>
<form method="POST" action="${ADMIN_PATH}/set-secret" class="inline" style="flex-direction:column;align-items:stretch">
<input name="secret" placeholder="64 ký tự hex (hoặc để trống = random)" value="">
<button class="warn">⚠️ ĐỔI SECRET (sẽ đổi API prefix)</button>
</form>
<div class="hint">⚠️ Khi đổi SECRET, API prefix thay đổi → PHẢI cập nhật API_SECRET trong connector userscript cho khớp, nếu không script sẽ không kết nối được.${KV_ENABLED ? ' Đã lưu vào KV.' : ' ⚠️ Mất khi restart nếu không có KV.'}</div>
</div>
</div>

<div class="panel">
<h2>🚫 DANH SÁCH BỊ KHOÁ VĨNH VIỄN (IP + THIẾT BỊ)</h2>
${banned.size === 0 ? '<div style="font-size:12px;color:#8b949e;padding:8px">Chưa có thiết bị/IP nào bị khoá.</div>' : `<table><thead><tr><th>Đối tượng</th><th>Tên máy</th><th>Lý do</th><th>Thời gian</th><th></th></tr></thead><tbody>${banRows}</tbody></table>`}
<h2 style="margin-top:16px">➕ KHOÁ THỦ CÔNG</h2>
<form method="POST" action="${ADMIN_PATH}/ban" class="inline">
<input name="target" placeholder="IP hoặc HWID (vd: 1.2.3.4 hoặc HW1234ABCD)" required>
<input name="reason" placeholder="Lý do" value="manual">
<button class="danger">🚫 KHOÁ</button>
</form>
</div>

<div class="panel">
<h2>📱 THIẾT BỊ ĐÃ KẾT NỐI (tên máy)</h2>
${devices.size === 0 ? '<div style="font-size:12px;color:#8b949e;padding:8px">Chưa có thiết bị nào xác thực thành công.</div>' : `<table><thead><tr><th>HWID</th><th>Tên máy</th><th>Hệ điều hành</th><th>IP cuối</th><th>Lần cuối</th></tr></thead><tbody>${devRows}</tbody></table>`}
</div>

<div class="panel">
<h2>📜 LOG GẦN NHẤT (có tên máy gửi lên server)</h2>
<table><thead><tr><th>Thời gian</th><th>Loại</th><th>Tên máy</th><th>HWID</th><th>IP</th><th>OK</th><th>Chi tiết</th></tr></thead>
<tbody>${logRows || '<tr><td colspan="7" style="text-align:center;color:#8b949e">Chưa có request nào.</td></tr>'}</tbody></table>
<div class="hint">verify = nhập key • attest = xác thực thiết bị/mạng • process = giải mã đáp án • fire = nộp bài • ban/reject = bị khoá/từ chối</div>
</div>
</div></body></html>`;
}

app.get(ADMIN_PATH + '/dashboard', (req, res) => { if (!requireAdmin(req, res)) return; res.send(adminDashboardPage(req.query.msg || '')); });

// Đổi mật khẩu admin
app.post(ADMIN_PATH + '/change-password', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const { old, new: npass, confirm } = req.body || {};
    if (!verifyPass(old, ADMIN_HASH)) return res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent('❌ Sai mật khẩu hiện tại!'));
    if (!npass || npass.length < 6) return res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent('❌ Mật khẩu mới tối thiểu 6 ký tự!'));
    if (npass !== confirm) return res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent('❌ Xác nhận mật khẩu không khớp!'));
    ADMIN_HASH = hashPass(npass);
    adminSessions.clear(); // đăng xuất mọi phiên khác
    kvSaveState();
    adminLog('admin', { action: 'change-password', ip: getClientIp(req) });
    // Phiên hiện tại cũng bị xoá → yêu cầu đăng nhập lại
    res.setHeader('Set-Cookie', 'god_admin=; Path=/; Max-Age=0');
    res.redirect(ADMIN_PATH + '?msg=' + encodeURIComponent('✅ Đổi mật khẩu thành công! Đăng nhập lại bằng mật khẩu mới.'));
});

// Bật/tắt cờ bảo mật
app.post(ADMIN_PATH + '/toggle', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const flag = (req.body && req.body.flag) || '';
    let msg = '✅ Đã cập nhật.';
    if (flag === 'autoBan') { AUTO_BAN = !AUTO_BAN; msg = AUTO_BAN ? '✅ Đã BẬT auto-ban.' : '⚠️ Đã TẮT auto-ban.'; }
    else if (flag === 'mobileOnly') { MOBILE_ONLY = !MOBILE_ONLY; msg = MOBILE_ONLY ? '✅ Đã BẬT chỉ chấp nhận Android/iOS.' : '⚠️ Đã TẮT chỉ-mobile (cho phép desktop).'; }
    else if (flag === 'banDesktop') { BAN_DESKTOP = !BAN_DESKTOP; msg = BAN_DESKTOP ? '✅ Đã BẬT ban desktop.' : '⚠️ Đã TẮT ban desktop (desktop chỉ bị từ chối, không khoá).'; }
    kvSaveState();
    adminLog('admin', { action: 'toggle:' + flag, value: flag === 'autoBan' ? AUTO_BAN : flag === 'mobileOnly' ? MOBILE_ONLY : BAN_DESKTOP, ip: getClientIp(req) });
    res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent(msg));
});

// Mở khoá (unban)
app.post(ADMIN_PATH + '/unban', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const key = String((req.body && req.body.key) || '').trim();
    if (key) { removeBan(key); adminLog('admin', { action: 'unban', target: key, ip: getClientIp(req) }); }
    res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent('✅ Đã mở khoá: ' + key));
});

// Khoá thủ công
app.post(ADMIN_PATH + '/ban', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const target = String((req.body && req.body.target) || '').trim();
    const reason = String((req.body && req.body.reason) || 'manual').trim();
    if (!target) return res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent('❌ Thiếu đối tượng khoá!'));
    const key = /^\d+\.\d+\.\d+\.\d+$/.test(target) || target.includes(':') ? (target.includes(':') ? target : 'ip:' + target) : 'dev:' + target;
    banned.set(key, { reason, device: '', t: Date.now(), by: 'admin' });
    kvSaveState();
    adminLog('admin', { action: 'ban', target: key, reason, ip: getClientIp(req) });
    res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent('✅ Đã khoá: ' + key));
});

// Đổi SECRET (ẩn API prefix + ký session)
app.post(ADMIN_PATH + '/set-secret', (req, res) => {
    if (!requireAdmin(req, res)) return;
    let secret = String((req.body && req.body.secret) || '').trim();
    if (!secret) secret = crypto.randomBytes(32).toString('hex');
    if (secret.length < 8) return res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent('❌ SECRET quá ngắn!'));
    SECRET = secret;
    API_PREFIX = computeApiPrefix(SECRET);
    kvSaveState();
    adminLog('admin', { action: 'set-secret', newLength: secret.length, ip: getClientIp(req) });
    res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent('✅ Đã đổi SECRET. API prefix mới: ' + API_PREFIX + ' — CẬP NHẬT API_SECRET trong connector!'));
});

app.get(ADMIN_PATH + '/logs.json', (req, res) => { if (!requireAdmin(req, res)) return; res.json({ logs: ADMIN_LOG.slice(0, 100), count: ADMIN_LOG.length }); });

// 404 fallback — không tiết lộ thông tin
app.use((_req, res) => res.status(404).json({ error: 'Not found' }));
// Error handler
app.use((err, _req, res, _next) => { console.error('[server-error]', err && err.message ? err.message : err); res.status(500).json({ success: false, error: 'Internal server error' }); });

// ─── Start / Export ──────────────────────────────────────────────────────────
if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`\n🚀 GOD MODE Server v4.0 (Bảo mật nâng cao) running → http://localhost:${PORT}`);
        console.log(`   Ẩn API prefix: ${API_PREFIX}`);
        console.log(`   Admin: ${ADMIN_PATH} (${ADMIN_USER})`);
        console.log(`   Lưu trữ bền vững (KV): ${KV_ENABLED ? 'CÓ' : 'KHÔNG — đặt env KV_REST_API_URL + KV_REST_API_TOKEN để ban/mật khẩu tồn tại qua restart'}`);
    });
}
module.exports = app;
