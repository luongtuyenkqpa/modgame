/**
 * ======================================================
 *  GOD MODE v3.2 — BACKEND SERVER
 *  Chứa toàn bộ logic xử lý. File này KHÔNG BAO GIỜ
 *  được gửi xuống client — chỉ expose REST API.
 * ======================================================
 *  Cài dependencies: npm install express@^4 cheerio cors   # hoặc express@^5 (đã tương thích)
 *  Chạy: node server.js   hoặc   PORT=8080 node server.js
 * ======================================================
 */

'use strict';

const express  = require('express');
const cheerio  = require('cheerio');
const cors     = require('cors');
const https    = require('https');
const app      = express();
const PORT     = process.env.PORT || 3000;

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Chỉ cho phép request từ OLM (và localhost khi dev)
app.use(cors({
    origin: (origin, cb) => {
        const allowed = [
            'https://olm.vn',
            'https://www.olm.vn',
            'http://localhost',
            undefined  // allow no-origin (VM GM_xmlhttpRequest)
        ];
        if (!origin || allowed.some(o => origin === o || (o && origin.endsWith('.olm.vn')))) {
            cb(null, true);
        } else {
            cb(null, false);  // origin không hợp lệ: không gắn CORS header, browser tự chặn
        }
    },
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'X-Key', 'X-HWID', 'X-App', 'X-Ts', 'X-Nonce', 'X-Sign', 'X-Session', 'X-Fp-Hash', 'X-Seq']
}));
app.options(/.*/, cors());

// ══════════════════════════════════════════════════════════════════════════════
//  SECURITY LAYER v3.3 — anti-dump / anti-proxy-VPN / anti-VM / browser attestation
//  Master switch: env GODMODE_SECURITY=off để tạm TẮT toàn bộ (tương thích ngược).
//  Các env tinh chỉnh (khi bật master):
//    GODMODE_SIGN_SECRET    — secret ký request (BẮT BUỘC client dùng cùng giá trị)
//    GODMODE_SESSION_SECRET — secret mã hóa phiên (để mặc định random cũng được)
//    REQUIRE_ATTEST=false   — tắt yêu cầu trình duyệt thật (KHÔNG khuyến nghị)
//    BLOCK_PROXY=false      — tắt chặn proxy/vpn/datacenter/VM
//    ENCRYPT_ANSWERS=false  — tắt mã hóa đáp án
//    PROXY_ALLOW_LIST=ip1,ip2 — whitelist IP
// ══════════════════════════════════════════════════════════════════════════════
const crypto = require('crypto');
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cache-Control', 'no-store');
    next();
});

const SEC_ON = true; // BẮT BUỘC bật — không thể tắt bằng env
// FIX v3.5: Mặc định khớp HARDCODE với client (SIGN_SECRET trong connector).
// Trước đây: nếu env GODMODE_SIGN_SECRET chưa đặt → server tạo NGẪU NHIÊN mỗi lần khởi động
// → client ký bằng secret khác → chữ ký sai + API_PREFIX sai → 404 → báo "Key không hợp lệ" dù key đúng.
// Giữ env để tùy chỉnh, nhưng fallback mặc định = giá trị client đã hardcode → chạy được ngay.
const DEFAULT_SIGN_SECRET = '481dba5c0d1c1ca6f9865a3246e030e86782bdd3b4c68b9884f1171ec708eae5';
const _signSecret = process.env.GODMODE_SIGN_SECRET || DEFAULT_SIGN_SECRET;
if (!process.env.GODMODE_SIGN_SECRET) {
    console.warn('[SECURITY] GODMODE_SIGN_SECRET chưa đặt — dùng MẶC ĐỊNH khớp client (vẫn hoạt động).');
}
// FIX v3.5: BỎ prefix API ẩn (derived từ secret). Nó KHÔNG tăng bảo mật (cùng secret với chữ ký)
// mà chỉ gây lỗi routing 404 khi deploy sai / secret lệch. Dùng đường dẫn chuẩn /api/*.
const API_PREFIX = '/api';
console.log('[SECURITY] Endpoint API tại prefix: ' + API_PREFIX);
console.log('[SECURITY] SIGN_SECRET khớp client: ' + (_signSecret === DEFAULT_SIGN_SECRET ? 'CÓ (mặc định)' : 'CÓ (env)'));
const SEC = {
    signSecret:     _signSecret,
    sessionSecret:  process.env.GODMODE_SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
    requireAttest:  process.env.REQUIRE_ATTEST !== 'false',
    blockProxy:     process.env.BLOCK_PROXY !== 'false',
    encryptAnswers: process.env.ENCRYPT_ANSWERS !== 'false',
    allowList:      (process.env.PROXY_ALLOW_LIST || '').split(',').map(x => x.trim()).filter(Boolean)
};

// In-memory stores
const nonceCache  = new Map();  // nonce|ip -> expire
const ipCache     = new Map();  // ip -> {info, expire}
const rateBuckets = new Map();  // key -> [timestamps]
const sessions    = new Map();  // token -> {key,hwid,ip,fpHash,exp}

// GC định kỳ (chạy nền, không chặn request)
setInterval(() => {
    const now = Date.now();
    for (const [k, v] of nonceCache) if (v < now) nonceCache.delete(k);
    for (const [k, v] of ipCache)    if (v.expire < now) ipCache.delete(k);
    for (const [k, v] of sessions)   if (v.exp < now) sessions.delete(k);
    for (const [k, v] of bannedIps)  if (v < now) bannedIps.delete(k);
    for (const [k, arr] of rateBuckets) {
        const f = arr.filter(t => now - t < 120000);
        if (f.length === 0) rateBuckets.delete(k); else rateBuckets.set(k, f);
    }
}, 60000).unref();

function hmacHex(secret, s) { return crypto.createHmac('sha256', secret).update(s).digest('hex'); }
function getClientIp(req) {
    const fwd = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    return fwd || req.ip || (req.socket && req.socket.remoteAddress) || '';
}
function rateLimit(key, max, windowMs) {
    const now = Date.now();
    const arr = (rateBuckets.get(key) || []).filter(t => now - t < windowMs);
    if (arr.length >= max) { rateBuckets.set(key, arr); return false; }
    arr.push(now); rateBuckets.set(key, arr); return true;
}

// ── 0. Ban IP + honeypot (dò quét / vào đường dẫn cũ → cấm 1h) ──
const bannedIps = new Map();
const BAN_PATHS  = ['/.env','/admin','/wp-admin','/phpmyadmin','/.git','/config','/server.js','/backup','/source','/install','/console','/debug','/api/admin','/shell','/etc'];
// FIX v3.5: Bỏ danh sách OLD_404 chặn /api/* — vì giờ chúng ta DÙNG thật các đường dẫn /api/verify, /api/process...
// Trước đây chặn để ẩn API cũ, giờ prefix chuẩn là /api nên không được chặn nữa (nếu chặn → mọi request verify đều 404).
const OLD_404    = [];
app.use((req, res, next) => {
    const ip = getClientIp(req);
    const isLoopback = ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';
    const ban = bannedIps.get(ip);
    if (ban && ban > Date.now()) return res.status(404).json({ error: 'Not found' });
    const p = req.path;
    if (BAN_PATHS.some(h => p === h || p.startsWith(h + '/'))) {
        if (!isLoopback) bannedIps.set(ip, Date.now() + 3600000);
        return res.status(404).json({ error: 'Not found' });
    }
    if (OLD_404.some(h => p === h || p.startsWith(h + '/'))) {
        return res.status(404).json({ error: 'Not found' });
    }
    next();
});

// ── 1. Chữ ký request (chống curl / replay / dump thô API) ──
function requireSignature(req, res) {
    if (!SEC_ON) return true;
    const ts    = req.headers['x-ts'];
    const nonce = req.headers['x-nonce'];
    const sign  = req.headers['x-sign'];
    if (!ts || !nonce || !sign) { res.status(401).json({ success: false, message: 'Thiếu chữ ký bảo mật (X-Ts/X-Nonce/X-Sign)' }); return false; }
    const tsNum = parseInt(ts, 10);
    if (isNaN(tsNum) || Math.abs(Date.now() - tsNum) > 30000) { res.status(401).json({ success: false, message: 'Chữ ký hết hiệu lực (sai giờ)' }); return false; }
    const nk = nonce + '|' + getClientIp(req);
    if (nonceCache.has(nk)) { res.status(401).json({ success: false, message: 'Phát hiện tấn công replay (trùng nonce)' }); return false; }
    nonceCache.set(nk, Date.now() + 60000);
    if (nonceCache.size > 10000) { const old = [...nonceCache.keys()].slice(0, 4000); old.forEach(k => nonceCache.delete(k)); }
    const expected = hmacHex(SEC.signSecret, `${req.method}|${req.path}|${ts}|${nonce}`);
    if (String(sign).toLowerCase() !== expected.toLowerCase()) { res.status(401).json({ success: false, message: 'Chữ ký không hợp lệ' }); return false; }
    return true;
}

// ── 2. Phát hiện proxy / VPN / datacenter / VM theo IP (cache 1h, fail-open an toàn) ──
const DC_KEYWORDS = ['amazon', 'google cloud', 'microsoft azure', 'digitalocean', 'ovh', 'hetzner', 'linode', 'vultr', 'choopa', 'leaseweb', 'colocrossing', 'data center', 'datacenter', 'hosting', 'proxy', 'vpn', 'shadowsocks', 'contabo', 'buyvm', 'greencloud', 'alibaba', 'tencent cloud', 'oracle cloud', 'ibm cloud', 'scaleway', 'online.net', 'dedibox', 'cloudflare', 'fastly'];
function checkProxyIp(ip) {
    return new Promise((resolve) => {
        if (!SEC_ON || !ip || SEC.allowList.includes(ip)) return resolve({ risk: 'low' });
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
                    const risk = (isDC || isVPN || kw) ? 'high' : 'low';
                    done({ risk, isDC, isVPN, country: (j.location && j.location.country_code) || '', org });
                } catch (e) { done({ risk: 'low', note: 'lookup-fail' }); }
            });
        });
        req.on('error', () => done({ risk: 'low', note: 'lookup-error' }));
        req.on('timeout', () => { req.destroy(); done({ risk: 'low', note: 'lookup-timeout' }); });
    });
}

// ── 3. Attestation — kiểm tra trình duyệt thật (Android/iOS thật vẫn PASS) ──
const BAD_UA = ['headlesschrome', 'phantom', 'puppeteer', 'selenium', 'webdriver', 'playwright', 'electron', 'cef', 'wkhtml', 'chrome-lighthouse', 'bot', 'crawl', 'spider', 'scrapy', 'curl', 'wget', 'python-requests', 'axios', 'okhttp', 'java/', 'go-http-client', 'libwww', 'httpclient', 'postman', 'insomnia'];
function isRealBrowserUA(ua) {
    if (!ua || ua.length < 20) return false;
    const u = ua.toLowerCase();
    if (BAD_UA.some(k => u.includes(k))) return false;
    const hasEngine  = /(chrome|safari|firefox|edg|opera|crios|fxios)/.test(u);
    const hasPlatform = /(mobile|android|iphone|ipad|ipod|windows|macintosh|linux)/.test(u);
    return hasEngine && hasPlatform;
}
function fpHash(fp) { return hmacHex(SEC.sessionSecret, JSON.stringify(fp || {}).slice(0, 800)).slice(0, 16); }

function requireSession(req, res) {
    if (!SEC_ON || !SEC.requireAttest) return true;
    // FIX v3.5: Trên Vercel / Render serverless, Map sessions KHÔNG tồn tại giữa các lần gọi (cold start).
    // Nếu SERVERLESS=1 → bỏ kiểm tra session (vẫn còn chữ ký HMAC + verify key = đủ bảo mật cho mục đích này).
    if (process.env.SERVERLESS === '1' || process.env.VERCEL === '1') return true;
    const token = req.headers['x-session'];
    const sess = token && sessions.get(token);
    if (!sess) { res.status(403).json({ success: false, message: 'Phiên chưa xác thực' }); return false; }
    if (sess.exp < Date.now()) { sessions.delete(token); res.status(403).json({ success: false, message: 'Phiên hết hạn' }); return false; }
    const { key, hwid } = req.body || {};
    if (sess.key !== key || sess.hwid !== (hwid || '')) { res.status(403).json({ success: false, message: 'Phiên không khớp key/hwid' }); return false; }
    if (sess.ip && sess.ip !== getClientIp(req)) { res.status(403).json({ success: false, message: 'IP thay đổi' }); return false; }
    const fph = req.headers['x-fp-hash'];
    if (fph && sess.fpHash && fph !== sess.fpHash) { res.status(403).json({ success: false, message: 'Dấu vân tay thay đổi' }); return false; }
    const seqH = parseInt(req.headers['x-seq'], 10);
    if (isNaN(seqH) || seqH !== sess.seq) { res.status(403).json({ success: false, message: 'Sai thứ tự yêu cầu' }); return false; }
    req._secToken = token; req._secSession = sess;
    return true;
}
// Xoay session token sau mỗi request thành công (chống hook/steal token)
function finalizeSec(req, payload) {
    if (!req._secToken) return payload;
    const old = sessions.get(req._secToken);
    if (old) {
        sessions.delete(req._secToken);
        const newTok = crypto.randomBytes(24).toString('hex');
        sessions.set(newTok, Object.assign({}, old, { seq: (old.seq || 1) + 1 }));
        payload.next_session = newTok;
    }
    return payload;
}

// ── 4. Mã hóa đáp án AES-256-GCM (anti-dump) — chỉ client có session token mới giải mã ──
function deriveKey(sessionToken) { return crypto.pbkdf2Sync(sessionToken + '|' + SEC.signSecret, 'godmode-v3-salt', 1000, 32, 'sha256'); }
function encryptAnswers(questions, sessionToken) {
    const key = deriveKey(sessionToken);
    const iv  = crypto.randomBytes(12);
    const c   = crypto.createCipheriv('aes-256-gcm', key, iv);
    let enc   = c.update(JSON.stringify(questions), 'utf8', 'base64');
    enc += c.final('base64');
    return { iv: iv.toString('base64'), tag: c.getAuthTag().toString('base64'), data: enc };
}

// ── Cổng bảo mật tổng hợp cho endpoint nhạy cảm (process/fire) ──
async function secureGate(req, res, opts = {}) {
    if (!SEC_ON) return true;
    if (!requireSignature(req, res)) return false;
    const ip = getClientIp(req);
    const { key } = req.body || {};
    if (!rateLimit('ip:' + ip, 30, 60000))   { res.status(429).json({ success: false, message: 'Quá nhiều yêu cầu (IP)' }); return false; }
    if (key && !rateLimit('key:' + key, 80, 60000)) { res.status(429).json({ success: false, message: 'Quá nhiều yêu cầu (key)' }); return false; }
    if (SEC.blockProxy) {
        const p = await checkProxyIp(ip);
        if (p.risk === 'high') { res.status(403).json({ success: false, message: 'Phát hiện proxy/VPN/datacenter/VM — chức năng bị khóa' }); return false; }
    }
    if (opts.needSession && !requireSession(req, res)) return false;
    return true;
}

// ─── Không bao giờ serve static JS gốc ───────────────────────────────────────
// (Không dùng express.static — script gốc nằm ngoài www-root)


// ══════════════════════════════════════════════════════════════════════════════
//  CORE LOGIC (adapted từ userscript gốc — chạy trên Node.js)
// ══════════════════════════════════════════════════════════════════════════════

const SECRET_KEY = process.env.OLM_SECRET_KEY || '1047823200';   // OLM XOR key — ẩn hoàn toàn trong server
const APP_ID     = process.env.APP_ID || 'tiep_god_mode_v3';

// ── 1. Giải mã OLM (thay atob bằng Buffer) ───────────────────────────────────
function decryptOLM(base64Str) {
    if (!base64Str) return null;
    try {
        const rawBuf  = Buffer.from(base64Str, 'base64');
        const rawStr  = rawBuf.toString('latin1');   // binary equivalent of atob
        let decrypted = '';
        for (let i = 0; i < rawStr.length; i++) {
            decrypted += String.fromCharCode(
                rawStr.charCodeAt(i) ^ SECRET_KEY.charCodeAt(i % SECRET_KEY.length)
            );
        }
        return Buffer.from(Uint8Array.from(decrypted, c => c.charCodeAt(0))).toString('utf-8');
    } catch (e) {
        console.error('[decryptOLM]', e.message);
        return null;
    }
}

// ── 2. Trích xuất đáp án từ HTML (thay DOMParser bằng cheerio) ───────────────
function extractAnswers(htmlContent) {
    const $ = cheerio.load(htmlContent);
    let answers = [];

    // Trắc nghiệm — .correctAnswer
    const correctNodes = $('.correctAnswer');
    if (correctNodes.length > 0) {
        correctNodes.each((_, el) => answers.push($(el).text().replace('||', '').trim()));
        return answers;
    }

    // Điền từ — input[data-accept]
    const fillInNodes = $('input[data-accept]');
    if (fillInNodes.length > 0) {
        fillInNodes.each((_, el) => answers.push($(el).attr('data-accept')));
        return answers;
    }

    // Nối chéo — li có ||
    let isMatching = false;
    $('li').each((_, li) => {
        const text = $(li).text().trim();
        if (text.includes('||')) {
            isMatching = true;
            answers.push(text.split('||').map(s => s.trim()).filter(s => s).join(' ➔ '));
        }
    });
    if (isMatching) return answers;

    return ['Không tự động trích xuất được.'];
}

// ── 3. buildParams (giữ nguyên — pure JS) ────────────────────────────────────
function buildParams(sq) {
    const count = sq.count || 4;
    if (sq.type === 6) {
        const orderArr = Array.from(Array(Math.max(count, 15)), (_, k) => k);
        return { js: '', order_l: orderArr, order_r: orderArr };
    }
    return { js: '', order: Array.from(Array(count), (_, k) => k) };
}

// ── 4. findCorrectInfo (giữ nguyên — pure JS) ─────────────────────────────────
function findCorrectInfo(node) {
    const results = [];
    function traverse(n) {
        if (!n) return;
        const subQ_ID = n.id || n._id || (n.props ? n.props.id : null);

        if ((n.type === 'fillme-input' && n.content) ||
            (typeof n.content === 'string' && n.content.includes('data-accept='))) {
            if (n.content.includes('data-accept=')) {
                const regex = /data-accept="([^"]+)"/g;
                let match;
                while ((match = regex.exec(n.content)) !== null) {
                    results.push({ type: 4, ans: [match[1]], count: 1,
                        skill: n.id_skill, subId: subQ_ID || ('raw_' + Math.random()), isText: true });
                }
            } else {
                results.push({ type: 4, ans: [n.content], count: 1,
                    skill: n.id_skill, subId: subQ_ID, isText: true });
            }
            return;
        }

        if (n.type === 'olm-list' || (Array.isArray(n.children) && n.children.length > 0)) {
            const options = n.children;
            if (n.name === 'true-false' || n.listType === 'true-false') {
                results.push({ type: 13,
                    ans: options.map(o => (o.correct == true || o.correct === 'true' || o.correct == 1) ? '1' : '0'),
                    count: options.length, skill: n.id_skill, subId: subQ_ID });
                return;
            }
            if (n.name === 'link-list' || n.listType === 'matching') {
                results.push({ type: 6,
                    ans: options.map((_, idx) => idx.toString()),
                    count: options.length, skill: n.id_skill, subId: subQ_ID });
                return;
            }
            if (options.some(c => c.correct !== undefined)) {
                const trueIndex = options.findIndex(o => o.correct == true || o.correct === 'true' || o.correct == 1);
                results.push({ type: 1,
                    ans: [(trueIndex === -1 ? 0 : trueIndex).toString()],
                    count: options.length, skill: n.id_skill, subId: subQ_ID });
                return;
            }
        }

        if (Array.isArray(n.children))   n.children.forEach(traverse);
        else if (Array.isArray(n.questions)) n.questions.forEach(traverse);
        else if (Array.isArray(n.items))  n.items.forEach(traverse);
        else if (Array.isArray(n.list))   n.list.forEach(traverse);
        else if (n.root) traverse(n.root);
    }

    let contentToParse = node.json_content || node.content;
    if (typeof contentToParse === 'string' &&
        !contentToParse.trim().startsWith('{') &&
        !contentToParse.trim().startsWith('[')) {
        const decoded = decryptOLM(contentToParse);
        if (decoded) contentToParse = decoded;
    }
    try {
        traverse(typeof contentToParse === 'string' ? JSON.parse(contentToParse) : contentToParse);
    } catch (_) {
        traverse(node);
    }

    if (results.length === 0) results.push({ type: 1, ans: ['0'], count: 4, skill: null, subId: null });
    return results;
}

// ── 5. buildFirePayload (tiepFirePayload adapted cho server-side) ─────────────
function buildFirePayload({ raw_questions, meta, video_length }, mode, timeStr, grade) {
    const timeParts   = (timeStr || '10.00').split('.');
    const userMins    = parseInt(timeParts[0]) || 0;
    let   userSecsStr = timeParts[1] || '0';
    if (userSecsStr.length === 1) userSecsStr += '0';
    const userSecs    = parseInt(userSecsStr.substring(0, 2));
    let   calcSeconds = (userMins * 60) + userSecs;
    if (calcSeconds < 30) calcSeconds = 120;

    const totalPackages = raw_questions.length;
    const isExam  = mode === 'exam';
    const isVideo = mode === 'video';
    const now     = Math.floor(Date.now() / 1000);

    let totalSeconds, timeInit;
    if (isVideo || isExam) {
        totalSeconds = calcSeconds;
        timeInit     = now - totalSeconds;
    } else {
        totalSeconds = totalPackages * 15;
        timeInit     = now - totalSeconds;
    }

    const params  = new URLSearchParams();
    const fakeLog = [];
    let   max_tn_score = 0, tn_score_calc = 0, tl_max_calc = 0;

    raw_questions.forEach((q, i) => {
        const subQuestions = findCorrectInfo(q);
        const sub_count    = subQuestions.length;
        const is_tl        = (q.q_type == 18 || q.type == 18 || q.q_type == 11);

        let final_score = sub_count;
        if (q.score !== undefined && q.score !== null && q.score !== '')
            final_score = parseFloat(q.score);
        else if (q.point !== undefined && q.point !== null && q.point !== '')
            final_score = parseFloat(q.point);

        if (!isVideo) {
            params.append('quiz_list[]', q.id || q._id);
            params.append(`score_list[${q.id || q._id}]`, final_score);
        }

        let skillIDs = [...new Set(subQuestions.map(sq => sq.skill).filter(s => s != null))];
        if (!isVideo) skillIDs.forEach(s => params.append('correct_skill[]', s));

        if (isVideo || isExam) {
            if (is_tl && isExam) {
                tl_max_calc += final_score;
                fakeLog.push({
                    answer:        JSON.stringify(['Học sinh đã làm phần tự luận trên máy.']),
                    label:         [''],
                    params:        '{"js":"","order":[0]}',
                    correct_skill: [],
                    wrong_skill:   [],
                    type:          [18],
                    result:        [0],
                    idq:           parseInt(q.id || q._id),
                    score:         final_score,
                    chk:           0
                });
            } else {
                max_tn_score   += final_score;
                tn_score_calc  += final_score;

                const ans_list = [], type_list = [], prs_list = [];
                const resArr   = [], mresult    = [], listIdq  = [], lbl_list = [];

                for (let j = 0; j < sub_count; j++) {
                    const sq = subQuestions[j];
                    if (sq.type === 4 || sq.type === 13 || sq.type === 6)
                        ans_list.push(JSON.stringify(sq.ans));
                    else
                        ans_list.push(JSON.stringify(sq.ans[0] || '0'));

                    type_list.push(sq.type || 1);
                    prs_list.push(JSON.stringify(buildParams(sq)));
                    resArr.push(1);
                    mresult.push([1]);
                    listIdq.push(sq.subId && sq.subId.toString().length > 5 ? sq.subId : `q${j}`);

                    let lbl = '';
                    if (sq.ans.length === 1 && !isNaN(sq.ans[0]) && sq.type !== 4 && sq.type !== 13)
                        lbl = ['A','B','C','D','E'][parseInt(sq.ans[0])] || '';
                    lbl_list.push(lbl);
                }

                const logItem = {
                    answer:        JSON.stringify(ans_list),
                    label:         sub_count === 1 ? lbl_list : [],
                    labels:        lbl_list,
                    params:        sub_count === 1 ? prs_list[0] : JSON.stringify({ js: '', prs: prs_list, order: Array.from(Array(sub_count).keys()) }),
                    correct_skill: skillIDs,
                    wrong_skill:   [],
                    type:          type_list,
                    result:        resArr,
                    mresult,
                    idq:           parseInt(q.id || q._id),
                    score:         final_score
                };
                if (isExam) {
                    logItem.chk = 1;
                    if (sub_count > 1) logItem.list_idq = listIdq;
                }
                if (isVideo) {
                    logItem.marker = q.marker || (i + 1);
                    logItem.id     = (q.id || q._id).toString();
                }
                fakeLog.push(logItem);
            }
        } else {
            const q_params_arr = [], a_params_arr = [];
            subQuestions.forEach(sq => {
                q_params_arr.push(JSON.stringify(buildParams(sq)));
                a_params_arr.push(JSON.stringify(sq.ans));
            });
            fakeLog.push({
                q_params:   JSON.stringify(q_params_arr),
                a_params:   JSON.stringify(a_params_arr),
                result:     1,
                correct:    1,
                wrong:      0,
                a_index:    i,
                time_spent: Math.floor(Math.random() * 15) + 10
            });
        }
    });

    // Common params
    params.append('id_cate',       meta.id_cate);
    params.append('id_courseware', meta.id_courseware || meta.id_cate);
    params.append('id_user',       meta.id_user);
    params.append('id_grade',      grade || meta.id_grade || '10');
    if (meta.id_school) params.append('id_school', meta.id_school);
    if (meta.id_group)  params.append('id_group',  meta.id_group);
    params.append('type_vip',    '530');
    params.append('time_stored', '0');
    params.append('date_end',    now);
    params.append('data_log',    JSON.stringify(fakeLog));

    if (isVideo) {
        const vl = video_length || 900;
        params.append('type',           '5');
        params.append('type_exam',      '0');
        params.append('total_time',     vl);
        params.append('current_time',   vl);
        params.append('time_spent',     totalSeconds + 2);
        params.append('score_10',       '10');
        params.append('totalq',         totalPackages);
        params.append('score',          tn_score_calc);
        params.append('max_score',      max_tn_score);
        params.append('answered',       totalPackages);
        params.append('correct',        totalPackages);
        params.append('count_problems', totalPackages);
        params.append('percent',        '100');
        params.append('pscore',         '10');
        params.append('score_status',   '10');
        const vLog = { [timeInit]: 'start', [timeInit + 1]: 'start', [timeInit + 10]: 'reload' };
        params.append('log', JSON.stringify(vLog));

    } else if (isExam) {
        params.append('time_init',    timeInit);
        params.append('time_spent',   totalSeconds);
        params.append('score',        tn_score_calc);
        params.append('max_score',    max_tn_score + tl_max_calc);
        params.append('tn_score',     tn_score_calc);
        params.append('type_exam',    '1');
        params.append('correct',      tn_score_calc);
        params.append('wrong',        0);
        params.append('name_user',    '');
        params.append('tl_score',     '0');
        params.append('times',        '0');
        params.append('iframe',       'false');

        let curT          = timeInit + Math.floor(totalSeconds * 0.1);
        const totalQs     = raw_questions.length;
        const usableTime  = Math.max(10, totalSeconds - Math.floor(totalSeconds * 0.1) - 10);
        const baseInterval = usableTime / (totalQs || 1);
        for (let c = 0; c < totalQs; c++) {
            const step = Math.floor(baseInterval * (0.7 + Math.random() * 0.6));
            curT += step;
            if (curT >= timeInit + totalSeconds) curT = timeInit + totalSeconds - 2;
            params.append(`choose_log[${c}][ind]`, c);
            params.append(`choose_log[${c}][t]`,   Math.floor(curT));
            params.append(`choose_log[${c}][l]`,   c + 1);
        }
    } else {
        params.append('time_init',      timeInit);
        params.append('time_spent',     totalSeconds);
        params.append('time_elapsed',   totalSeconds);
        params.append('score',          '100');
        params.append('score_10',       '10');
        params.append('star',           '20');
        params.append('theta',          '0');
        params.append('max_score',      '100');
        params.append('answered',       totalPackages);
        params.append('correct',        totalPackages);
        params.append('wrong',          '0');
        params.append('missed',         '0');
        params.append('count_problems', totalPackages);
        params.append('type',           '3');
        params.append('type_exam',      '0');
        const pLog = { [timeInit]: 'start', [timeInit + 1]: 'start' };
        params.append('log', JSON.stringify(pLog));
    }

    params.append('count_redo', '0');
    params.append('ended',      '1');
    params.append('save_star',  '1');

    return params.toString();
}


// ══════════════════════════════════════════════════════════════════════════════
//  KEY VALIDATION — proxy tới keyvault-vn.onrender.com
// ══════════════════════════════════════════════════════════════════════════════

function proxyVerify(key, hwid, olmUser) {
    return new Promise((resolve) => {
        const postData = JSON.stringify({ key, app: APP_ID, device: hwid || 'unknown', olm_user: olmUser || '' });
        const opts = {
            hostname: 'keyvault-vn.onrender.com',
            port:     443,
            path:     '/api/verify',
            method:   'POST',
            headers:  { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(postData) },
            timeout:  15000  // FIX v3.5: tăng từ 10s → 15s (onrender free tier hay cold-start chậm)
        };
        const req = https.request(opts, (res) => {
            let raw = '';
            res.on('data', c => raw += c);
            res.on('end', () => {
                // FIX v3.5: log raw response để debug (không log key đầy đủ)
                console.log(`[keyvault] HTTP ${res.statusCode} | key=${String(key).slice(0,3)}*** | app=${APP_ID} | raw=${raw.slice(0,300)}`);
                if (res.statusCode !== 200) {
                    return resolve({ success: false, message: `KeyVault lỗi HTTP ${res.statusCode}: ${raw.slice(0,120) || 'không phản hồi'}` });
                }
                try {
                    const kv = JSON.parse(raw);
                    // Chuẩn hóa: keyvault có thể trả {valid, reason} hoặc {success, message}
                    resolve({
                        success:    kv.success !== undefined ? !!kv.success : !!kv.valid,
                        message:    kv.message || kv.reason || (kv.valid === false ? 'Key không hợp lệ (KeyVault từ chối)' : ''),
                        type:       kv.type || kv.plan || kv.level || '',
                        expires_at: kv.expires_at || kv.exp || kv.expire || '',
                        // FIX v3.5: trả thêm debug để client hiển thị chính xác nguyên nhân
                        _kv_raw:    { status: res.statusCode, valid: kv.valid, success: kv.success, reason: kv.reason || '', message: kv.message || '' }
                    });
                } catch (e) {
                    // onrender free tier đôi khi trả HTML 502 khi cold start → không parse được JSON
                    resolve({ success: false, message: `KeyVault trả về không phải JSON (có thể đang khởi động): ${raw.slice(0,80)}` });
                }
            });
        });
        req.on('error', e => resolve({ success: false, message: 'Lỗi kết nối KeyVault: ' + e.message }));
        req.on('timeout', ()  => { req.destroy(); resolve({ success: false, message: 'KeyVault timeout (server đang ngủ — thử lại)' }); });
        req.write(postData);
        req.end();
    });
}


// ══════════════════════════════════════════════════════════════════════════════
//  ROUTES
// ══════════════════════════════════════════════════════════════════════════════

/** Ping / health check — FIX v3.5: trả thông tin debug để chẩn đoán lỗi routing/secret */
// Trang chủ — kiểm tra deploy thành công
app.get('/', (_req, res) => {
    res.json({
        ok: true,
        server: 'GOD MODE v3.5',
        time: Date.now(),
        api_prefix: API_PREFIX,
        sign_secret_set: !!process.env.GODMODE_SIGN_SECRET,
        sec_on: SEC_ON,
        endpoints: {
            verify:  'POST ' + API_PREFIX + '/verify',
            process: 'POST ' + API_PREFIX + '/process',
            fire:    'POST ' + API_PREFIX + '/fire',
            attest:  'POST ' + API_PREFIX + '/attest',
            ping:    'GET  ' + API_PREFIX + '/ping'
        }
    });
});
/** Ping công khai — KHÔNG cần chữ ký, để client kiểm tra kết nối trước khi verify */
app.get(API_PREFIX + '/ping', (_req, res) => {
    res.json({ ok: true, time: Date.now(), server: 'GOD MODE v3.5', api_prefix: API_PREFIX });
});

/** Key verification (proxy) */
app.post(API_PREFIX + '/verify', async (req, res) => {
    if (!requireSignature(req, res)) return;
    if (!rateLimit('verify:' + getClientIp(req), 20, 60000))
        return res.status(429).json({ success: false, message: 'Quá nhiều yêu cầu' });
    const { key, hwid, olm_user } = req.body;
    if (!key) return res.status(400).json({ success: false, message: 'Missing key' });
    // FIX v3.5: log để biết request có tới server không + key dạng gì (có bị uppercase không)
    console.log(`[/verify] nhận key="${key}" (len=${key.length}) hwid=${hwid} olm_user=${olm_user}`);
    const result = await proxyVerify(key, hwid, olm_user);
    console.log(`[/verify] → success=${result.success} message=${result.message}`);
    res.json(result);
});

/**
 * Process raw question list → trả về đáp án đã giải mã
 * Body: { key, hwid, questions: [...] }
 */
app.post(API_PREFIX + '/process', async (req, res) => {
    if (!(await secureGate(req, res, { needSession: true }))) return;
    const { key, hwid, questions } = req.body;
    if (!key)                   return res.status(401).json({ success: false, message: 'Missing key' });
    if (!Array.isArray(questions) || questions.length === 0)
        return res.status(400).json({ success: false, message: 'No questions' });

    // Validate key
    const kv = await proxyVerify(key, hwid);
    if (!kv.success) return res.status(401).json({ success: false, message: kv.message || 'Invalid key' });

    const processed = questions.map((item, index) => {
        const rawContent    = item.content || item.json_content;
        const htmlDecrypted = decryptOLM(rawContent);
        const answers       = htmlDecrypted ? extractAnswers(htmlDecrypted) : ['Lỗi giải mã'];
        return { index: index + 1, id: item.id, title: item.title || `Câu ${index + 1}`, answers };
    });

    if (SEC_ON && SEC.encryptAnswers && req.headers['x-session']) {
        res.json(finalizeSec(req, { success: true, encrypted: true, count: processed.length,
                   payload: encryptAnswers(processed, req.headers['x-session']) }));
    } else {
        res.json(finalizeSec(req, { success: true, questions: processed, count: processed.length }));
    }
});

/**
 * Build & return fire payload (server-side)
 * Body: { key, hwid, session: { raw_questions, meta, video_length }, mode, time_str, grade }
 * Response: { success, params_str, endpoint }
 */
app.post(API_PREFIX + '/fire', async (req, res) => {
    if (!(await secureGate(req, res, { needSession: true }))) return;
    const { key, hwid, session, mode, time_str, grade } = req.body;
    if (!key)     return res.status(401).json({ success: false, message: 'Missing key' });
    if (!session) return res.status(400).json({ success: false, message: 'Missing session' });

    // Key must be VIP/UNLIMITED for fire
    const kv = await proxyVerify(key, hwid);
    if (!kv.success) return res.status(401).json({ success: false, message: kv.message || 'Invalid key' });

    // Chỉ key PREMIUM/VIP/UNLIMITED mới dùng được fire
    const keyType = (kv.type || '').toUpperCase();
    const isPremium = ['PREMIUM','VIP','UNLIMITED'].includes(keyType);
    if (!isPremium) {
        return res.status(403).json({ success: false, message: 'Chức năng này yêu cầu key PREMIUM/VIP!' });
    }

    if (!Array.isArray(session.raw_questions) || session.raw_questions.length === 0) {
        return res.status(400).json({ success: false, message: 'raw_questions rỗng!' });
    }
    if (!session.meta || !session.meta.id_user || !session.meta.id_cate) {
        return res.status(400).json({ success: false, message: 'Thiếu meta (id_user / id_cate)' });
    }

    try {
        const paramsStr = buildFirePayload(session, mode || 'practice', time_str || '10.00', grade);
        res.json(finalizeSec(req, { success: true, params_str: paramsStr, endpoint: '/course/teacher-static' }));
    } catch (err) {
        console.error('[/api/fire]', err);
        res.status(500).json({ success: false, message: 'Server error: ' + err.message });
    }
});


/**
 * Attestation — client gửi dấu vân tay trình duyệt, server kiểm tra trình duyệt thật
 * rồi cấp session token ngắn hạn (10 phút) BẮT BUỘC khi lấy đáp án / nộp bài.
 * Body: { key, hwid, fp: { ua, platform, language, timezone, webdriver, hardwareConcurrency, deviceMemory, screen } }
 */
app.post(API_PREFIX + '/attest', async (req, res) => {
    if (!requireSignature(req, res)) return;
    const { key, hwid, fp } = req.body || {};
    if (!key) return res.status(400).json({ success: false, message: 'Thiếu key' });
    const ip = getClientIp(req);
    if (!rateLimit('attest:' + ip, 10, 60000))
        return res.status(429).json({ success: false, message: 'Quá nhiều lần xác thực' });
    // Key phải hợp lệ
    const kv = await proxyVerify(key, hwid);
    if (!kv.success) return res.status(401).json({ success: false, message: kv.message || 'Key không hợp lệ' });
    // Chặn proxy/VPN/VM
    if (SEC_ON && SEC.blockProxy) {
        const p = await checkProxyIp(ip);
        if (p.risk === 'high') return res.status(403).json({ success: false, message: 'Proxy/VPN/VM không được cấp phiên' });
    }
    // Kiểm tra trình duyệt thật (Android/iOS thật vẫn pass)
    const ua = (fp && fp.ua) || req.headers['user-agent'] || '';
    if (!isRealBrowserUA(ua)) return res.status(403).json({ success: false, message: 'Không phát hiện trình duyệt thật' });
    if (fp && fp.webdriver === true) return res.status(403).json({ success: false, message: 'Trình duyệt tự động (webdriver) bị từ chối' });
    if (fp && fp.screen && /^(0|1|2|3|4)x/.test(String(fp.screen))) return res.status(403).json({ success: false, message: 'Màn hình không hợp lệ' });
    const fph = fpHash(fp);
    // Cấp phiên 10 phút, ràng buộc key+hwid+ip+fp
    const token = crypto.randomBytes(24).toString('hex');
    for (const [t, ss] of sessions) if (ss.key === key && ss.hwid === (hwid || '')) sessions.delete(t);
    sessions.set(token, { key, hwid: hwid || '', ip, fpHash: fph, exp: Date.now() + 10 * 60 * 1000, seq: 1 });
    res.json({ success: true, session: token, expiresIn: 600, fpHash: fph, message: 'Trình duyệt thật — phiên đã cấp' });
});

// 404 fallback — không tiết lộ bất cứ thông tin nào
app.use((_req, res) => res.status(404).json({ error: 'Not found' }));



// ─── Error handler — bắt mọi lỗi chưa xử lý, trả JSON thay vì HTML ───────────────
app.use((err, _req, res, _next) => {
    console.error('[server-error]', err && err.message ? err.message : err);
    res.status(500).json({ success: false, error: 'Internal server error' });
});

// ─── Start ────────────────────────────────────────────────────────────────────
// Chỉ listen khi chạy trực tiếp (local); trên Vercel export app
if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`\n🚀 GOD MODE Server v3.5 (FIXED) running → http://localhost:${PORT}`);
        console.log(`   GET  /              — health check + debug info`);
        console.log(`   GET  ${API_PREFIX}/ping    — connectivity check (no signature)`);
        console.log(`   POST ${API_PREFIX}/verify  — xác thực key`);
        console.log(`   POST ${API_PREFIX}/process — giải mã đáp án`);
        console.log(`   POST ${API_PREFIX}/fire    — tạo payload nộp bài`);
        console.log(`   POST ${API_PREFIX}/attest  — cấp phiên (chỉ khi SERVERLESS≠1)\n`);
    });
}
module.exports = app;
