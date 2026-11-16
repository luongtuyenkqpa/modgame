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
app.use(express.json({ limit: '10mb', verify: (req, _res, buf) => { req.rawBody = buf; } }));
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

// ══════════════════════════════════════════════════════════════════════════════
//  MODULE "CHUẨN BỊ 10 ĐIỂM" — KHÔNG nằm trong userscript, chỉ server giữ.
//  Serve mã hoá AES-256-GCM (key derive từ session token) CHỈ cho client:
//    1) key PREMIUM/VIP/UNLIMITED hợp lệ
//    2) attest/heartbeat sạch (không máy ảo / trình duyệt giả / proxy-VPN)
//  Tăng PAYLOAD_MODULE_VERSION mỗi khi sửa code → client tự tải lại (auto-push).
// ══════════════════════════════════════════════════════════════════════════════
const PAYLOAD_MODULE_VERSION = 1;
const PAYLOAD_MODULE_SRC = `
var SESSION=ctx.SESSION, addLog=ctx.addLog, forceGetMeta=ctx.forceGetMeta;
var SECRET_KEY_CS='1047823200';
function decryptOLM_CS(base64Str){if(!base64Str)return null;try{var raw=atob(base64Str);var dec='';for(var i=0;i<raw.length;i++)dec+=String.fromCharCode(raw.charCodeAt(i)^SECRET_KEY_CS.charCodeAt(i%SECRET_KEY_CS.length));return decodeURIComponent(escape(dec));}catch(e){return null;}}
function buildParamsCS(sq){var count=sq.count||4;if(sq.type===6){var orderArr=Array.from(Array(Math.max(count,15)),function(_,k){return k;});return {js:'',order_l:orderArr,order_r:orderArr};}return {js:'',order:Array.from(Array(count),function(_,k){return k;})};}
function findCorrectInfoCS(node){var results=[];function traverse(n){if(!n)return;var subQ_ID=n.id||n._id||(n.props?n.props.id:null);if((n.type==='fillme-input'&&n.content)||(typeof n.content==='string'&&n.content.includes('data-accept='))){if(n.content.includes('data-accept=')){var regex=/data-accept="([^"]+)"/g;var match;while((match=regex.exec(n.content))!==null)results.push({type:4,ans:[match[1]],count:1,skill:n.id_skill,subId:subQ_ID||('raw_'+Math.random()),isText:true});}else{results.push({type:4,ans:[n.content],count:1,skill:n.id_skill,subId:subQ_ID,isText:true});}return;}if(n.type==='olm-list'||(Array.isArray(n.children)&&n.children.length>0)){var options=n.children;if(n.name==='true-false'||n.listType==='true-false'){results.push({type:13,ans:options.map(function(o){return (o.correct==true||o.correct==='true'||o.correct==1)?'1':'0';}),count:options.length,skill:n.id_skill,subId:subQ_ID});return;}if(n.name==='link-list'||n.listType==='matching'){results.push({type:6,ans:options.map(function(_,idx){return idx.toString();}),count:options.length,skill:n.id_skill,subId:subQ_ID});return;}if(options.some(function(c){return c.correct!==undefined;})){var trueIndex=options.findIndex(function(o){return o.correct==true||o.correct==='true'||o.correct==1;});results.push({type:1,ans:[(trueIndex===-1?0:trueIndex).toString()],count:options.length,skill:n.id_skill,subId:subQ_ID});return;}}if(Array.isArray(n.children))n.children.forEach(traverse);else if(Array.isArray(n.questions))n.questions.forEach(traverse);else if(Array.isArray(n.items))n.items.forEach(traverse);else if(Array.isArray(n.list))n.list.forEach(traverse);else if(n.root)traverse(n.root);}var contentToParse=node.json_content||node.content;if(typeof contentToParse==='string'&&!contentToParse.trim().startsWith('{')&&!contentToParse.trim().startsWith('[')){var decoded=decryptOLM_CS(contentToParse);if(decoded)contentToParse=decoded;}try{traverse(typeof contentToParse==='string'?JSON.parse(contentToParse):contentToParse);}catch(_){traverse(node);}if(results.length===0)results.push({type:1,ans:['0'],count:4,skill:null,subId:null});return results;}
return async function(){
forceGetMeta();
if(!SESSION.meta.id_user||!SESSION.meta.id_cate){addLog('❌ Thiếu ID user/cate: user='+(SESSION.meta.id_user||'?')+' cate='+(SESSION.meta.id_cate||'?'),'err');return false;}
var totalPackages=SESSION.raw_questions.length;
if(totalPackages===0){addLog('❌ Chưa có câu hỏi để nộp!','err');return false;}
var timeInput=document.getElementById('tl-god-time');
var timeStr=timeInput?timeInput.value.toString().trim():'10.00';
var tp=timeStr.split('.');
var userMins=parseInt(tp[0])||0;
var uss=tp[1]||'0';if(uss.length===1)uss+='0';
var userSecs=parseInt(uss.substring(0,2));
var calcSeconds=(userMins*60)+userSecs;
if(calcSeconds<30)calcSeconds=120;
var modeSel=document.getElementById('tl-modeSelect');
var mode=modeSel?modeSel.value:'practice';
var isExam=mode==='exam',isVideo=mode==='video';
var now=Math.floor(Date.now()/1000);
var totalSeconds,timeInit;
if(isVideo||isExam){totalSeconds=calcSeconds;timeInit=now-totalSeconds;}else{totalSeconds=totalPackages*15;timeInit=now-totalSeconds;}
var params=new URLSearchParams();
var fakeLog=[];
var max_tn_score=0,tn_score_calc=0,tl_max_calc=0;
SESSION.raw_questions.forEach(function(q,i){
var subQuestions=findCorrectInfoCS(q);
var sub_count=subQuestions.length;
var is_tl=(q.q_type==18||q.type==18||q.q_type==11);
var final_score=sub_count;
if(q.score!==undefined&&q.score!==null&&q.score!=='')final_score=parseFloat(q.score);
else if(q.point!==undefined&&q.point!==null&&q.point!=='')final_score=parseFloat(q.point);
if(!isVideo){params.append('quiz_list[]',q.id||q._id);params.append('score_list['+(q.id||q._id)+']',final_score);}
var skillIDs=[].concat(Array.from(new Set(subQuestions.map(function(sq){return sq.skill;}).filter(function(s){return s!=null;}))));
if(!isVideo)skillIDs.forEach(function(s){params.append('correct_skill[]',s);});
if(isVideo||isExam){
if(is_tl&&isExam){tl_max_calc+=final_score;fakeLog.push({answer:JSON.stringify(['Học sinh đã làm phần tự luận trên máy.']),label:[''],params:'{"js":"","order":[0]}',correct_skill:[],wrong_skill:[],type:[18],result:[0],idq:parseInt(q.id||q._id),score:final_score,chk:0});}
else{
max_tn_score+=final_score;tn_score_calc+=final_score;
var ans_list=[],type_list=[],prs_list=[],resArr=[],mresult=[],listIdq=[],lbl_list=[];
for(var j=0;j<sub_count;j++){var sq=subQuestions[j];ans_list.push(JSON.stringify((sq.type===4||sq.type===13||sq.type===6)?sq.ans:(sq.ans[0]||'0')));type_list.push(sq.type||1);prs_list.push(JSON.stringify(buildParamsCS(sq)));resArr.push(1);mresult.push([1]);listIdq.push(sq.subId&&sq.subId.toString().length>5?sq.subId:'q'+j);var lbl='';if(sq.ans.length===1&&!isNaN(sq.ans[0])&&sq.type!==4&&sq.type!==13)lbl=['A','B','C','D','E'][parseInt(sq.ans[0])]||'';lbl_list.push(lbl);}
var logItem={answer:JSON.stringify(ans_list),label:sub_count===1?lbl_list:[],labels:lbl_list,params:sub_count===1?prs_list[0]:JSON.stringify({js:'',prs:prs_list,order:Array.from(Array(sub_count).keys())}),correct_skill:skillIDs,wrong_skill:[],type:type_list,result:resArr,mresult:mresult,idq:parseInt(q.id||q._id),score:final_score};
if(isExam){logItem.chk=1;if(sub_count>1)logItem.list_idq=listIdq;}
if(isVideo){logItem.marker=q.marker||(i+1);logItem.id=(q.id||q._id).toString();}
fakeLog.push(logItem);
}
}else{
var qpa=[],apa=[];
subQuestions.forEach(function(sq){qpa.push(JSON.stringify(buildParamsCS(sq)));apa.push(JSON.stringify(sq.ans));});
fakeLog.push({q_params:JSON.stringify(qpa),a_params:JSON.stringify(apa),result:1,correct:1,wrong:0,a_index:i,time_spent:Math.floor(Math.random()*15)+10});
}
});
params.append('id_cate',SESSION.meta.id_cate);
params.append('id_courseware',SESSION.meta.id_courseware||SESSION.meta.id_cate);
params.append('id_user',SESSION.meta.id_user);
params.append('id_grade',window.grade||window.id_grade||'10');
if(SESSION.meta.id_school)params.append('id_school',SESSION.meta.id_school);
if(SESSION.meta.id_group)params.append('id_group',SESSION.meta.id_group);
params.append('type_vip','530');params.append('time_stored','0');params.append('date_end',now);
params.append('data_log',JSON.stringify(fakeLog));
if(isVideo){var vl=SESSION.video_length||900;params.append('type','5');params.append('type_exam','0');params.append('total_time',vl);params.append('current_time',vl);params.append('time_spent',totalSeconds+2);params.append('score_10','10');params.append('totalq',totalPackages);params.append('score',tn_score_calc);params.append('max_score',max_tn_score);params.append('answered',totalPackages);params.append('correct',totalPackages);params.append('count_problems',totalPackages);params.append('percent','100');params.append('pscore','10');params.append('score_status','10');var vLog={};vLog[timeInit]='start';vLog[timeInit+1]='start';vLog[timeInit+10]='reload';params.append('log',JSON.stringify(vLog));}
else if(isExam){params.append('time_init',timeInit);params.append('time_spent',totalSeconds);params.append('score',tn_score_calc);params.append('max_score',max_tn_score+tl_max_calc);params.append('tn_score',tn_score_calc);params.append('type_exam','1');params.append('correct',tn_score_calc);params.append('wrong',0);params.append('name_user','');params.append('tl_score','0');params.append('times','0');params.append('iframe','false');var curT=timeInit+Math.floor(totalSeconds*0.1);var totalQs=SESSION.raw_questions.length;var usableTime=Math.max(10,totalSeconds-Math.floor(totalSeconds*0.1)-10);var baseInterval=usableTime/(totalQs||1);for(var c=0;c<totalQs;c++){curT+=Math.floor(baseInterval*(0.7+Math.random()*0.6));if(curT>=timeInit+totalSeconds)curT=timeInit+totalSeconds-2;params.append('choose_log['+c+'][ind]',c);params.append('choose_log['+c+'][t]',Math.floor(curT));params.append('choose_log['+c+'][l]',c+1);}}
else{params.append('time_init',timeInit);params.append('time_spent',totalSeconds);params.append('time_elapsed',totalSeconds);params.append('score','100');params.append('score_10','10');params.append('star','20');params.append('theta','0');params.append('max_score','100');params.append('answered',totalPackages);params.append('correct',totalPackages);params.append('wrong','0');params.append('missed','0');params.append('count_problems',totalPackages);params.append('type','3');params.append('type_exam','0');var pLog={};pLog[timeInit]='start';pLog[timeInit+1]='start';params.append('log',JSON.stringify(pLog));}
params.append('count_redo','0');params.append('ended','1');params.append('save_star','1');
try{
addLog('📤 Đang nộp bài lên OLM...','info');
var csrf=SESSION.meta.csrf_token||(document.querySelector('meta[name="csrf-token"]')&&document.querySelector('meta[name="csrf-token"]').getAttribute('content'))||'';
var response=await fetch('/course/teacher-static',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded; charset=UTF-8','x-csrf-token':csrf,'x-requested-with':'XMLHttpRequest'},body:params.toString()});
if(!response.ok){addLog('❌ OLM trả lỗi HTTP '+response.status,'err');return false;}
return true;
}catch(err){addLog('❌ Lỗi kết nối OLM: '+err.message,'err');return false;}
};
`;
function buildModulePayload(sessionToken) {
    return encryptAnswers({ src: PAYLOAD_MODULE_SRC, v: PAYLOAD_MODULE_VERSION }, sessionToken);
}
function isPremiumType(t) { return ['PREMIUM', 'VIP', 'UNLIMITED'].includes(String(t || '').toUpperCase()); }

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
// [v6.4] KHOÁ DO PHÁT HIỆN SCRIPT LẠ — admin mở khoá từ xa (KHÁC ban vĩnh viễn: giữ key, tự mở lại)
const lockedScripts = new Map(); // hwid -> {hwid, ip, device, reason, keyMasked, olm_user, t, status:'locked'|'unlocked', unlockedAt, lastSeen}

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
            if (st && st.lockedScripts) for (const [k, v] of Object.entries(st.lockedScripts)) lockedScripts.set(k, v);
        }
    } catch (_) {}
}
async function kvSaveState() {
    if (!KV_ENABLED) return;
    try {
        const st = {
            bans: Object.fromEntries(banned),
            devices: Object.fromEntries(devices),
            lockedScripts: Object.fromEntries(lockedScripts),
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
// [v6.4] Locked-script helpers — ghi nhận khi client tự báo khoá do script lạ
function recordLockReport({ hwid, ip, device, reason, keyMasked, olm_user }) {
    const now = Date.now();
    const existing = lockedScripts.get(hwid || 'unknown');
    lockedScripts.set(hwid || 'unknown', Object.assign({}, existing || {}, {
        hwid: hwid || 'unknown',
        ip: ip || (existing && existing.ip) || '',
        device: device || (existing && existing.device) || '',
        reason: reason || (existing && existing.reason) || '',
        keyMasked: keyMasked || (existing && existing.keyMasked) || '',
        olm_user: olm_user || (existing && existing.olm_user) || '',
        status: 'locked',
        t: (existing && existing.t) || now,
        lastSeen: now
    }));
    kvSaveState();
}

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
//  [v6.5] CHỮ KÝ REQUEST HMAC — chống fake request / replay / tamper
//  Client gửi: X-Ts (unix giây), X-Nonce (random), X-Sign = HMAC(SECRET, ts|nonce|sha256(body)|session)
//  Server kiểm tra: ts trong ±30s, nonce chưa dùng (chống replay), chữ ký khớp.
//  Áp dụng cho MỌI POST tới API ẩn. Ping (GET) không ký (dùng cho ban-mode polling).
// ══════════════════════════════════════════════════════════════════════════════
const REQ_SIGN = process.env.REQ_SIGN !== 'false'; // mặc định BẬT — đặt env REQ_SIGN=false để tắt
const usedNonces = new Map();
setInterval(() => { const now = Date.now(); for (const [n, exp] of usedNonces) if (exp < now) usedNonces.delete(n); }, 60000).unref();
function sha256Hex(buf) { return crypto.createHash('sha256').update(buf).digest('hex'); }
function verifyReqSig(req) {
    if (!REQ_SIGN) return true;
    const ts = req.headers['x-ts'], nonce = req.headers['x-nonce'], sign = req.headers['x-sign'];
    // [v6.5.2] SOFT: thiếu chữ ký (script cũ / đã mã hoá obfuscator chưa ký) → cho qua + ghi log.
    //          Có chữ ký nhưng SAI → chặn (chống fake/tamper). Client mới luôn ký đúng.
    if (!ts || !nonce || !sign) { adminLog('sig-missing', { ip: getClientIp(req), path: req.path }); return true; }
    const tsNum = parseInt(ts, 10);
    if (isNaN(tsNum) || Math.abs(Math.floor(Date.now() / 1000) - tsNum) > 30) return false;
    const nonceKey = ts + ':' + nonce;
    if (usedNonces.has(nonceKey)) return false;
    usedNonces.set(nonceKey, Date.now() + 60000);
    const bodyHash = sha256Hex(req.rawBody || Buffer.from(''));
    const sessTok = req.headers['x-session'] || '';
    const expected = crypto.createHmac('sha256', SECRET).update(ts + '|' + nonce + '|' + bodyHash + '|' + sessTok).digest('hex');
    try { return crypto.timingSafeEqual(Buffer.from(String(sign)), Buffer.from(expected)); } catch (_) { return false; }
}
let FAKE_REQ_COUNT = 0;
app.use((req, res, next) => {
    if (req.method === 'POST' && req.path.startsWith(API_PREFIX)) {
        if (!verifyReqSig(req)) {
            FAKE_REQ_COUNT++;
            adminLog('fake-req', { ip: getClientIp(req), path: req.path, ua: String(req.headers['user-agent'] || '').slice(0, 80) });
            return res.status(403).json({ success: false, message: 'Chữ ký request không hợp lệ (anti-fake)' });
        }
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
// ══════════════════════════════════════════════════════════════════════════════
//  [v6.5] ANTI-SHARE KEY + ANTI /fire TRỰC TIẾP
//  checkKeyShare: cùng 1 key dùng từ 2 HWID khác nhau trong 2h → từ chối + log
//  fireRateOk   : tối đa 8 lần /fire mỗi key mỗi giờ (chống spam nộp bài)
// ══════════════════════════════════════════════════════════════════════════════
const keyUsage = new Map(); // key -> {hwid, ip, t}
let SHARE_DETECT_COUNT = 0;
const ANTI_SHARE = process.env.ANTI_SHARE !== 'false'; // mặc định BẬT — env ANTI_SHARE=false để tắt
function checkKeyShare(key, hwid, ip) {
    if (!ANTI_SHARE || !key) return { shared: false };
    const now = Date.now();
    const prev = keyUsage.get(key);
    keyUsage.set(key, { hwid: hwid || '', ip: ip || '', t: now });
    if (prev && prev.hwid && hwid && prev.hwid !== hwid && (now - prev.t) < 2 * 3600 * 1000) {
        SHARE_DETECT_COUNT++;
        adminLog('share-detect', { key: maskKey(key), hwid, ip, prevHwid: prev.hwid, prevIp: prev.ip });
        return { shared: true };
    }
    return { shared: false };
}
const fireUsage = new Map(); // key -> [timestamps]
let FIRE_ATTACK_COUNT = 0;
function fireRateOk(key) {
    const now = Date.now();
    const arr = (fireUsage.get(key) || []).filter(t => now - t < 3600 * 1000);
    if (arr.length >= 8) { FIRE_ATTACK_COUNT++; return false; }
    arr.push(now); fireUsage.set(key, arr); return true;
}

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
    // [v6.5.1] Seq — CHỈ GHI LOG, KHÔNG chặn. Lý do: chữ ký HMAC (nonce + ts) đã chống replay;
    //          chặn cứng gây mất đồng bộ khi nhiều lời gọi /process chạy song song.
    if (String(req.headers['x-seq'] || '') !== String(sess.seq || '1')) { adminLog('seq-mismatch', { got: String(req.headers['x-seq'] || ''), expect: String(sess.seq || '1'), ip: getClientIp(req) }); }
    // [v6.5] UA-bind — chống share session token sang máy/trình duyệt khác
    if (sess.ua && sha256Hex(req.headers['user-agent'] || '').slice(0, 16) !== sess.ua) { res.status(403).json({ success: false, message: 'Trình duyệt không khớp phiên (anti-share token)' }); return false; }
    req._sess = sess; req._token = token;
    return true;
}
// Xoay session token sau mỗi request thành công (token bị hook sẽ hết hạn sau 5 phút)
function rotateSession(req, payload) {
    if (!req._sess) return payload;
    const old = req._sess;
    const nextSeq = (old.seq || 1) + 1;
    const newTok = signSession(Object.assign({}, old, { exp: Date.now() + SESSION_TTL, seq: nextSeq }));
    payload.next_session = newTok;
    payload.next_seq = nextSeq; // [v6.5.1] client dùng giá trị này thay vì tự +1 (tránh mất đồng bộ)
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
    const shV = checkKeyShare(key, hwid, ip);
    if (shV.shared) return res.status(403).json({ success: false, message: 'Key đang được dùng trên nhiều thiết bị (anti-share)' });
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
    const shA = checkKeyShare(key, hwid, ip);
    if (shA.shared) return res.status(403).json({ success: false, message: 'Key đang được dùng trên nhiều thiết bị (anti-share)' });
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
    const token = signSession({ k: key, h: hwid || '', ip, fp: fph, dev: v.deviceName, exp: Date.now() + SESSION_TTL, seq: 1, ua: sha256Hex(req.headers['user-agent'] || '').slice(0, 16), fireReady: false });
    // AUTO-SEND module "CHUẨN BỊ 10 ĐIỂM": chỉ đính kèm khi key PREMIUM + môi trường sạch
    const resp = { success: true, session: token, expiresIn: 300, fpHash: fph, device: v.deviceName, message: 'Thiết bị & mạng hợp lệ — phiên đã cấp', moduleVersion: PAYLOAD_MODULE_VERSION };
    if (isPremiumType(kv.type)) resp.module = buildModulePayload(token);
    adminLog('attest', { key: maskKey(key), hwid, device: v.deviceName, ip, success: true, premium: isPremiumType(kv.type) });
    res.json(resp);
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
    if (req._sess) req._sess.fireReady = true; // [v6.5] chỉ được /fire SAU khi đã /process (anti direct-fire)
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
    // [v6.5.1] fireReady — CHỈ GHI LOG, KHÔNG chặn (chữ ký + phiên + premium check đã đủ mạnh).
    //          Chặn cứng làm lỗi khi phiên hết hạn & attest lại mất cờ fireReady.
    if (!req._sess || !req._sess.fireReady) { adminLog('fire-noready', { ip, hwid, key: maskKey(key) }); }
    if (!fireRateOk(key)) { adminLog('fire-ratelimit', { ip, hwid, key: maskKey(key) }); return res.status(429).json({ success: false, message: 'Quá nhiều lần nộp bài (tối đa 8 lần/giờ)' }); }
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
//  /module — client TẢI CHỦ ĐỘNG module "CHUẨN BỊ 10 ĐIỂM" (cần session + premium)
//  Trả về mã hoá AES-256-GCM; client giải mã bằng session token.
// ══════════════════════════════════════════════════════════════════════════════
app.post(API_PREFIX + '/module', async (req, res) => {
    const ip = getClientIp(req);
    if (isBanned(ip, req.body && req.body.hwid)) return res.status(404).json({ error: 'Not found' });
    if (!requireSession(req, res)) return;
    if (!rateLimit('mod:' + ip, 15, 60000)) return res.status(429).json({ success: false, message: 'Quá nhiều yêu cầu' });
    const { key, hwid } = req.body || {};
    if (!key) return res.status(401).json({ success: false, message: 'Missing key' });
    const kv = await proxyVerify(key, hwid);
    if (!kv.success) return res.status(401).json({ success: false, message: kv.message || 'Invalid key' });
    if (!isPremiumType(kv.type)) return res.status(403).json({ success: false, message: 'Module chỉ dành cho key PREMIUM/VIP/UNLIMITED' });
    adminLog('module', { key: maskKey(key), hwid, device: deviceNameOf(hwid), ip, type: kv.type || '' });
    const payload = { success: true, encrypted: true, moduleVersion: PAYLOAD_MODULE_VERSION, module: buildModulePayload(req._token) };
    res.json(rotateSession(req, payload));
});

// ══════════════════════════════════════════════════════════════════════════════
//  /heartbeat — client gọi LIÊN TỤC mỗi ~30s gửi fp/device mới.
//  Server kiểm tra lại: trình duyệt giả? máy ảo/emulator? proxy/VPN/datacenter?
//  key còn hợp lệ? Nếu PHÁT HIỆN bất hợp lệ → AUTO-BAN + trả {blocked:true}
//  → client tự huỷ (xóa key + UI). Nếu sạch + premium + version cũ → AUTO-PUSH
//  module "CHUẨN BỊ 10 ĐIỂM" mới nhất (mã hoá bằng session token nếu có).
// ══════════════════════════════════════════════════════════════════════════════
app.post(API_PREFIX + '/heartbeat', async (req, res) => {
    const ip = getClientIp(req);
    if (isBanned(ip, req.body && req.body.hwid)) return res.status(404).json({ error: 'Not found' });
    if (!rateLimit('hb:' + ip, 30, 60000)) return res.status(429).json({ success: false, message: 'Quá nhiều yêu cầu' });
    const { key, hwid, fp, device, clientVersion } = req.body || {};
    if (!key) return res.status(400).json({ success: false, message: 'Thiếu key' });
    const shH = checkKeyShare(key, hwid, ip);
    if (shH.shared) return res.status(403).json({ blocked: true, reason: 'share', message: 'Key đang được dùng trên nhiều thiết bị (anti-share)' });
    // 1. Kiểm tra lại thiết bị (có thể user bật giả lập/webdriver lúc đang chạy)
    const v = validateDevice(fp, device, req.headers['user-agent']);
    if (!v.ok) {
        if (v.ban && AUTO_BAN && !isLoopbackIp(ip)) addBan(ip, hwid, 'heartbeat: ' + v.reason, v.deviceName);
        adminLog('heartbeat-block', { ip, hwid, device: v.deviceName, reason: v.reason, banned: !!(v.ban && AUTO_BAN) });
        return res.status(403).json({ blocked: true, reason: v.reason, message: 'Phát hiện môi trường không hợp lệ — đã khoá' });
    }
    // 2. Kiểm tra lại mạng (có thể user bật VPN/VPS lúc đang chạy)
    const p = await checkProxyIp(ip);
    if (p.risk === 'high') {
        if (AUTO_BAN && !isLoopbackIp(ip)) addBan(ip, hwid, 'heartbeat: proxy/VPN/datacenter', v.deviceName);
        adminLog('heartbeat-block', { ip, hwid, device: v.deviceName, reason: 'proxy/VPN/datacenter', banned: AUTO_BAN });
        return res.status(403).json({ blocked: true, reason: 'proxy/VPN/datacenter', message: 'Phát hiện mạng không hợp lệ — đã khoá' });
    }
    // 3. Kiểm tra key còn hợp lệ
    const kv = await proxyVerify(key, hwid);
    if (!kv.success) {
        adminLog('heartbeat-block', { ip, hwid, reason: 'key thu hồi/hết hạn', message: kv.message || '' });
        return res.status(403).json({ blocked: true, reason: 'key', message: kv.message || 'Key đã bị vô hiệu hoá' });
    }
    // 4. Cập nhật lastSeen thiết bị
    if (hwid && devices.has(hwid)) { const d = devices.get(hwid); d.lastSeen = Date.now(); d.ip = ip; }
    // 5. AUTO-PUSH module nếu premium + client đang chạy version cũ
    const premium = isPremiumType(kv.type);
    const out = { ok: true, t: Date.now(), nextCheck: 30000, moduleVersion: PAYLOAD_MODULE_VERSION, premium };
    const cv = parseInt(clientVersion || '0', 10);
    if (premium && cv < PAYLOAD_MODULE_VERSION) {
        // Dùng session token nếu client gửi kèm (X-Session hợp lệ); nếu không, cấp token tạm
        let tok = null;
        const sessTok = req.headers['x-session'];
        const sess = verifySession(sessTok);
        if (sess && sess.k === key && sess.h === (hwid || '')) tok = sessTok;
        else tok = signSession({ k: key, h: hwid || '', ip, fp: fpHash(fp), dev: v.deviceName, exp: Date.now() + SESSION_TTL, seq: 1, ua: sha256Hex(req.headers['user-agent'] || '').slice(0, 16), fireReady: false });
        out.module = buildModulePayload(tok);
        out.moduleSession = tok; // client dùng token này để giải mã module
        adminLog('heartbeat-push', { key: maskKey(key), hwid, ip, from: cv, to: PAYLOAD_MODULE_VERSION });
    }
    res.json(out);
});

// ══════════════════════════════════════════════════════════════════════════════
//  [v6.4] KHOÁ DO SCRIPT LẠ — client tự báo + polling chờ admin mở khoá
//  /lock-report : client gửi thông tin thiết bị bị khoá → server ghi vào tab admin
//  /lock-status : client polling mỗi ~20s → admin đã mở khoá chưa?
// ══════════════════════════════════════════════════════════════════════════════
app.post(API_PREFIX + '/lock-report', (req, res) => {
    const ip = getClientIp(req);
    if (!rateLimit('lockrep:' + ip, 10, 60000)) return res.status(429).json({ ok: false });
    const { key, hwid, fp, device, reason, olm_user } = req.body || {};
    if (!hwid) return res.status(400).json({ ok: false });
    const devName = (device && device.model) ? ((device.os || '') + ' ' + device.model).trim() : deviceNameOf(hwid);
    recordLockReport({
        hwid, ip, device: devName,
        reason: String(reason || '').slice(0, 200),
        keyMasked: maskKey(key), olm_user: olm_user || ''
    });
    adminLog('lock-report', { hwid, ip, device: devName, reason: String(reason || '').slice(0, 120), olm_user: olm_user || '' });
    res.json({ ok: true, t: Date.now() });
});
app.post(API_PREFIX + '/lock-status', (req, res) => {
    const ip = getClientIp(req);
    if (!rateLimit('lockst:' + ip, 30, 60000)) return res.status(429).json({ ok: false });
    const { hwid } = req.body || {};
    const rec = hwid ? lockedScripts.get(hwid) : null;
    // Cập nhật IP + lastSeen mới nhất → admin thấy IP hiện tại của thiết bị
    if (rec) { rec.lastSeen = Date.now(); if (ip) rec.ip = ip; }
    const locked = !!(rec && rec.status === 'locked');
    res.json({ locked, reason: locked ? (rec.reason || '') : '', t: Date.now() });
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
    const lockActive = [...lockedScripts.values()].filter(x => x.status === 'locked').length;
    const secInfo = { reqSign: REQ_SIGN, antiShare: ANTI_SHARE, shareCount: SHARE_DETECT_COUNT, fakeCount: FAKE_REQ_COUNT, fireCount: FIRE_ATTACK_COUNT };
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
<div class="top"><h1>⚙️ GOD MODE v4 — ADMIN DASHBOARD</h1><div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap"><a href="${ADMIN_PATH}/locked" style="color:#ffc107;text-decoration:none;font-size:12px;border:1px solid rgba(255,193,7,.4);padding:6px 12px;border-radius:6px">🔒 TAB KHOÁ SCRIPT LẠ (${lockActive})</a><a class="logout" href="${ADMIN_PATH}/logout">🚪 Đăng xuất</a></div></div>
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
<div class="card"><div class="lbl">Khoá script lạ (mở được)</div><div class="val ${lockActive ? 'bad' : 'ok'}"><a href="${ADMIN_PATH}/locked" style="color:inherit;text-decoration:none">${lockActive} đang khoá</a></div></div>
<div class="card"><div class="lbl">Chữ ký request (anti-fake)</div><div class="val ${secInfo.reqSign ? 'ok' : 'bad'}">${secInfo.reqSign ? 'BẬT' : 'TẮT'}</div></div>
<div class="card"><div class="lbl">Anti-share key</div><div class="val ${secInfo.antiShare ? 'ok' : 'bad'}">${secInfo.antiShare ? 'BẬT' : 'TẮT'} • ${secInfo.shareCount} phát hiện</div></div>
<div class="card"><div class="lbl">Tấn công fake/fire</div><div class="val ${(secInfo.fakeCount + secInfo.fireCount) ? 'bad' : 'ok'}">${secInfo.fakeCount} fake • ${secInfo.fireCount} fire</div></div>
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
// ══════════════════════════════════════════════════════════════════════════════
//  [v6.4] TAB RIÊNG — THIẾT BỊ BỊ KHOÁ DO PHÁT HIỆN SCRIPT LẠ
//  Tự động refresh mỗi 5s, hiện IP + tên máy, nút MỞ KHOÁ / KHOÁ LẠI / XOÁ
// ══════════════════════════════════════════════════════════════════════════════
function adminLockedPage() {
    return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>🔒 Khoá Script Lạ — GOD MODE Admin</title><style>
*{box-sizing:border-box}body{margin:0;background:#0d1117;font-family:'Segoe UI',system-ui,sans-serif;color:#c9d1d9;padding:20px}
.wrap{max-width:1200px;margin:0 auto}
.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:8px}
h1{font-size:18px;margin:0;background:linear-gradient(90deg,#ef233c,#ffc107);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
a.back{color:#4facfe;text-decoration:none;font-size:12px;border:1px solid rgba(79,172,254,.4);padding:6px 12px;border-radius:6px}
a.logout{color:#ef233c;text-decoration:none;font-size:12px;border:1px solid rgba(239,35,60,.4);padding:6px 12px;border-radius:6px}
.panel{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;margin-bottom:16px}
.panel h2{font-size:13px;margin:0 0 12px;color:#ffc107;text-transform:uppercase;letter-spacing:1px}
.stats{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:14px}
.stat{background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:10px 16px;font-size:12px}
.stat .n{font-size:20px;font-weight:900;font-family:monospace}
.stat.bad .n{color:#ef233c}.stat.ok .n{color:#00e676}.stat.info .n{color:#4facfe}
table{width:100%;border-collapse:collapse;font-size:11px}
th,td{padding:7px 8px;text-align:left;border-bottom:1px solid #21262d;vertical-align:top}
th{color:#8b949e;font-size:10px;text-transform:uppercase;letter-spacing:.5px;position:sticky;top:0;background:#161b22}
tr.locked-row{background:rgba(239,35,60,.05)}
.badge{padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;font-family:monospace}
.badge.locked{background:rgba(239,35,60,.15);color:#ef233c;border:1px solid rgba(239,35,60,.4)}
.badge.unlocked{background:rgba(0,230,118,.12);color:#00e676;border:1px solid rgba(0,230,118,.4)}
button{padding:5px 10px;border:none;border-radius:5px;color:#fff;font-weight:700;cursor:pointer;font-size:10px;margin-right:4px;margin-bottom:3px}
button.unlock{background:linear-gradient(135deg,#00b09b,#96c93d)}
button.relock{background:linear-gradient(135deg,#f59e0b,#ef4444)}
button.del{background:rgba(139,148,158,.2);color:#8b949e;border:1px solid #30363d}
button:hover{filter:brightness(1.15)}
.empty{text-align:center;color:#8b949e;padding:24px;font-size:12px}
.mono{font-family:monospace;font-size:10px;word-break:break-all}
.reason{color:#ffc107;font-size:10px;max-width:200px}
.hint{font-size:10px;color:#8b949e;margin-top:8px;line-height:1.6}
#refresh-ind{font-size:10px;color:#00e676;font-family:monospace}
</style></head><body><div class="wrap">
<div class="top">
<h1>🔒 THIẾT BỊ BỊ KHOÁ DO PHÁT HIỆN SCRIPT LẠ</h1>
<div style="display:flex;gap:8px;align-items:center">
<span id="refresh-ind">● tự động refresh mỗi 5s</span>
<a class="back" href="${ADMIN_PATH}/dashboard">⬅ VỀ DASHBOARD</a>
<a class="logout" href="${ADMIN_PATH}/logout">🚪 Đăng xuất</a>
</div>
</div>
<div class="stats">
<div class="stat bad"><div class="n" id="st-locked">—</div><div>Đang bị khoá</div></div>
<div class="stat ok"><div class="n" id="st-unlocked">—</div><div>Đã mở khoá</div></div>
<div class="stat info"><div class="n" id="st-total">—</div><div>Tổng lượt báo cáo</div></div>
</div>
<div class="panel">
<h2>📋 DANH SÁCH (tự động cập nhật khi có thiết bị bị khoá)</h2>
<table><thead><tr>
<th>Trạng thái</th><th>Thời gian khoá</th><th>Tên máy / Thiết bị</th><th>HWID</th><th>IP</th><th>Key</th><th>OLM User</th><th>Lý do</th><th>Lần check cuối</th><th>Thao tác</th>
</tr></thead><tbody id="tbody"><tr><td colspan="10" class="empty">Đang tải...</td></tr></tbody></table>
<div class="hint">💡 Khi bấm <b style="color:#00e676">MỞ KHOÁ</b>: thiết bị đó sẽ tự động hoạt động lại trong vòng ~20s (script polling server), key được giữ nguyên — người dùng KHÔNG cần nhập lại key. Bấm <b style="color:#ffc107">KHOÁ LẠI</b> để khoá lại thiết bị đã mở. <b>XOÁ</b> = xoá bản ghi (cũng có tác dụng mở khoá).</div>
</div>
</div>
<script>
function fmt(t){try{return new Date(t).toLocaleString('vi-VN');}catch(e){return '';}}
function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function act(hwid, action){
  fetch('${ADMIN_PATH}/api/locked/'+action, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({hwid:hwid})})
    .then(function(){ refresh(); })
    .catch(function(){});
}
function render(d){
  document.getElementById('st-locked').textContent = d.lockedActive||0;
  document.getElementById('st-total').textContent = d.count||0;
  document.getElementById('st-unlocked').textContent = (d.count||0)-(d.lockedActive||0);
  var tb = document.getElementById('tbody');
  var list = d.locked||[];
  if(!list.length){ tb.innerHTML = '<tr><td colspan="10" class="empty">✅ Chưa có thiết bị nào bị khoá do script lạ.</td></tr>'; return; }
  var html = '';
  list.forEach(function(r){
    var isLocked = r.status==='locked';
    html += '<tr class="'+(isLocked?'locked-row':'')+'">';
    html += '<td><span class="badge '+(isLocked?'locked':'unlocked')+'">'+(isLocked?'🔒 ĐANG KHOÁ':'✅ ĐÃ MỞ')+'</span></td>';
    html += '<td class="mono">'+fmt(r.t)+'</td>';
    html += '<td style="color:#00f2fe">'+esc(r.device||'')+'</td>';
    html += '<td class="mono">'+esc(r.hwid||'')+'</td>';
    html += '<td class="mono" style="color:#ffc107">'+esc(r.ip||'')+'</td>';
    html += '<td class="mono">'+esc(r.keyMasked||'')+'</td>';
    html += '<td class="mono">'+esc(r.olm_user||'')+'</td>';
    html += '<td class="reason">'+esc(r.reason||'')+'</td>';
    html += '<td class="mono">'+fmt(r.lastSeen)+'</td>';
    html += '<td>';
    if(isLocked){ html += '<button class="unlock" onclick="act(\\''+esc(r.hwid)+'\\',\\'unlock\\')">🔓 MỞ KHOÁ</button>'; }
    else { html += '<button class="relock" onclick="act(\\''+esc(r.hwid)+'\\',\\'lock\\')">🔒 KHOÁ LẠI</button>'; }
    html += '<button class="del" onclick="act(\\''+esc(r.hwid)+'\\',\\'delete\\')">🗑 XOÁ</button>';
    html += '</td></tr>';
  });
  tb.innerHTML = html;
}
function refresh(){
  fetch('${ADMIN_PATH}/api/locked')
    .then(function(r){return r.json();})
    .then(function(d){ render(d); setTimeout(refresh, 5000); })
    .catch(function(){ setTimeout(refresh, 5000); });
}
refresh();
</script>
</body></html>`;
}
app.get(ADMIN_PATH + '/locked', (req, res) => { if (!requireAdmin(req, res)) return; res.send(adminLockedPage()); });

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

// [v6.4] Admin JSON API cho tab khoá script lạ (gọi từ trang /admin/locked qua fetch)
app.get(ADMIN_PATH + '/api/locked', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const list = [...lockedScripts.entries()].slice(0, 200).map(([k, v]) => ({
        hwid: k, ip: v.ip || '', device: v.device || '', reason: v.reason || '',
        keyMasked: v.keyMasked || '', olm_user: v.olm_user || '',
        t: v.t || 0, lastSeen: v.lastSeen || 0, status: v.status || 'locked', unlockedAt: v.unlockedAt || 0
    })).sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0));
    res.json({ locked: list, count: lockedScripts.size, lockedActive: list.filter(x => x.status === 'locked').length });
});
app.post(ADMIN_PATH + '/api/locked/unlock', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const hwid = String((req.body && req.body.hwid) || '').trim();
    const rec = hwid && lockedScripts.get(hwid);
    if (rec) {
        rec.status = 'unlocked'; rec.unlockedAt = Date.now();
        // Gỡ luôn ban IP/HWID nếu có → client polling thành công, tự mở khoá
        banned.delete('dev:' + hwid);
        if (rec.ip) banned.delete('ip:' + rec.ip);
        kvSaveState();
        adminLog('admin', { action: 'unlock-script', hwid, ip: rec.ip, device: rec.device || '', ipAdmin: getClientIp(req) });
    }
    res.json({ ok: true, unlocked: !!rec });
});
app.post(ADMIN_PATH + '/api/locked/lock', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const hwid = String((req.body && req.body.hwid) || '').trim();
    const reason = String((req.body && req.body.reason) || 'admin re-lock').slice(0, 200);
    if (!hwid) return res.json({ ok: false });
    const rec = lockedScripts.get(hwid) || { hwid, ip: '', device: '', keyMasked: '', olm_user: '', t: Date.now() };
    rec.status = 'locked'; rec.reason = reason; rec.lastSeen = Date.now();
    lockedScripts.set(hwid, rec); kvSaveState();
    adminLog('admin', { action: 'lock-script', hwid, reason, ipAdmin: getClientIp(req) });
    res.json({ ok: true });
});
app.post(ADMIN_PATH + '/api/locked/delete', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const hwid = String((req.body && req.body.hwid) || '').trim();
    if (hwid) { lockedScripts.delete(hwid); kvSaveState(); adminLog('admin', { action: 'delete-lock-record', hwid, ipAdmin: getClientIp(req) }); }
    res.json({ ok: true });
});

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
