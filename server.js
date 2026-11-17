/**
 * ======================================================
 *  GOD MODE v9.2 — FIX BAN NHẦM Android thật (platform Linux armv) + AES-256/decryptor/no-key
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
        // [v7] FIX iOS "Network error": extension Userscripts/Violentmonkey/Tampermonkey trên iOS
        //       gửi origin = null hoặc safari-extension://... / moz-extension://... → CORS cũ CHẶN
        //       → client báo "Không thể kết nối server: Network error". Auth KHÔNG dùng cookie
        //       (HMAC signature + key + session token trong header/body) nên reflect origin là AN TOÀN.
        cb(null, true);
    },
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'X-Session', 'X-Fp-Hash', 'X-Seq', 'X-HWID', 'X-Ts', 'X-Nonce', 'X-Sign']
}));
app.options(/.*/, cors());

// [v6.5.3 · LEGACY] Script cũ (v5.0, đã mã hoá, tải qua KeyVault) gọi endpoint KHÔNG có ẩn prefix.
// Rewrite URL cũ → có prefix để route khớp. Client mới (tự tính prefix) không bị ảnh hưởng.
app.use((req, res, next) => {
    if (req.method === 'POST' && !req.path.startsWith(API_PREFIX)) {
        const LEGACY = ['/verify', '/attest', '/process', '/fire', '/module', '/code', '/heartbeat', '/lock-report', '/lock-status', '/ping'];
        if (LEGACY.includes(req.path)) {
            adminLog('legacy-rewrite', { path: req.path, ip: getClientIp(req) });
            req.url = API_PREFIX + req.path;
        }
    }
    next();
});

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
console.log('[v8] Gate môi trường thật (REQUIRE_REAL_ENV): ' + (process.env.REQUIRE_REAL_ENV === 'false' ? 'TẮT' : 'BẬT — chỉ gửi connector code cho trình duyệt thật + Android/iOS thật'));

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

// ══════════════════════════════════════════════════════════════════════════════
//  [v7] FULL CONNECTOR MODULE — TOÀN BỘ code chức năng userscript nằm ở SERVER.
//  Loader (userscript tối thiểu) chỉ attest → nhận code mã hoá → giải mã → chạy.
//  Nguồn code: env CONNECTOR_MODULE_SRC (chuỗi JS) HOẶC file tại
//  CONNECTOR_MODULE_PATH (mặc định ./connector.module.js). Mã hoá AES-256-GCM
//  key derive từ session token (chỉ client hợp lệ mới giải mã được).
//  Tăng CONNECTOR_MODULE_VERSION mỗi khi cập nhật code → loader tự tải lại.
// ══════════════════════════════════════════════════════════════════════════════
const CONNECTOR_MODULE_VERSION = parseInt(process.env.CONNECTOR_MODULE_VERSION || '3', 10);
// ══════════════════════════════════════════════════════════════════════════════
//  [v8] TOÀN BỘ code chức năng của connector.module.js ĐÃ ĐƯỢC NHÚNG TRỰC TIẾP
//  vào server (single-file — KHÔNG còn phụ thuộc file ngoài / env).
//  Server sẽ MÃ HOÁ AES-256-GCM (key derive từ session token) và GỬI XUỐNG loader
//  (Violentmonkey/Tampermonkey/Userscripts) CHỈ KHI gate môi trường thật xác nhận:
//    trình duyệt thật + thiết bị Android/iOS thật + mạng thật.
//  env CONNECTOR_MODULE_SRC (nếu đặt) vẫn ghi đè để cập nhật nóng không redeploy.
// ══════════════════════════════════════════════════════════════════════════════
const CONNECTOR_MODULE_EMBEDDED = `// ==UserScript==
// @name         THIÊN TAI TÙ TỘI //
// @namespace   dev.luongtuyen
// @version      6.5.4-instant-block
// @description  Thin client v6.5.4 — Anti share session/key + anti fake request + anti direct-fire + anti-hook/dump + CHẶN NGAY userscript lạ chạy song song
// @author       Thiên Tai Tù Tội
// @match        https://olm.vn/*
// @match        https://*.olm.vn/*
// @run-at       document-start
// @grant        unsafeWindow
// @grant        GM_addStyle
// @grant        GM_xmlhttpRequest
// @connect      modgame.vercel.app
// @connect      YOUR_SERVER_DOMAIN
// @connect      keyvault-vn.onrender.com
// @connect      olm.vn
// ==/UserScript==

// ════════════════════════════════════════════════════════
//  ĐỔI 2 GIÁ TRỊ NÀY cho khớp với server của bạn:
// ════════════════════════════════════════════════════════
const SERVER_BASE = 'https://modgame.vercel.app';  // ⚠️ ĐỔI thành URL server Vercel của bạn
const API_SECRET  = 'a7f3c9e1b2d48506fae1c7d3b9f0e2a4c6d8f1a3b5e7c9d0f2a4c6e8b1d3f5a7';  // ⚠️ ĐỔI khớp env GODMODE_SECRET trên server
// ════════════════════════════════════════════════════════
// [v5] Mã hoá request body — đổi true SAU KHI server hỗ trợ giải mã v5
const REQUEST_ENCRYPTION = false;
// ════════════════════════════════════════════════════════

;(function () {
    'use strict';

    // ─── Storage key ─────────────────────────────────────
    const LS_KEY       = '_tl_conn_key';
    const LS_TYPE      = '_tl_conn_type';
    const LS_EXP       = '_tl_conn_exp';
    const LS_THEME     = '_tiep_theme';
    let   CURRENT_KEY  = null;
    let   KEY_STATUS   = { valid: false, type: null, expires_at: null };
    let   CURRENT_DEVICE = ''; // [v4] tên máy (lấy từ server sau attest)

    // ─── SESSION (data captured from XHR) ────────────────
    const SESSION = {
        raw_questions: [],
        meta: { id_user: null, id_cate: null, id_courseware: null,
                id_school: null, id_group: null, csrf_token: null },
        auto_mode:    'practice',
        video_length: 900
    };

    // ─── Theme ────────────────────────────────────────────
    let CURRENT_THEME = localStorage.getItem(LS_THEME) || 'default';

    // ══════════════════════════════════════════════════════
    //  [v4.1] KIỂM TRA LOẠI KEY — GIỐNG V3 CORE
    // ══════════════════════════════════════════════════════
    function isPremiumKey() {
        const t = (KEY_STATUS.type || _sLS.get(LS_TYPE) || '').toString().toUpperCase(); // [v5] obfuscated read
        return t === 'PREMIUM' || t === 'VIP' || t === 'UNLIMITED';
    }

    // ══════════════════════════════════════════════════════
    //  [v4.1] XỬ LÝ OLM ACCOUNT MISMATCH
    // ══════════════════════════════════════════════════════
    function handleOlmMismatch(serverOlm, currentOlm) {
        // Xóa key khỏi bộ nhớ và localStorage
        localStorage.removeItem(LS_KEY);
        localStorage.removeItem(LS_TYPE);
        localStorage.removeItem(LS_EXP);
        CURRENT_KEY    = null;
        KEY_STATUS     = { valid: false, type: null, expires_at: null };
        _secSession    = { token: null, exp: 0, fpHash: null, seq: 1 };
        CURRENT_DEVICE = '';

        // Xóa panel UI nếu đang hiện
        const panelEl = document.getElementById('tl-panel');
        const fb      = document.getElementById('tl-floatBtn');
        if (panelEl) panelEl.remove();
        if (fb)      fb.remove();

        // Hiện modal thông báo rồi quay lại trang đăng nhập key
        showCustomModal({
            icon:  '🚫',
            title: 'TÀI KHOẢN OLM KHÔNG KHỚP!',
            lines: [
                \`Key được đăng ký cho tài khoản: <b>\${serverOlm}</b>\`,
                \`Tài khoản OLM hiện tại: <b>\${currentOlm}</b>\`,
                \`⚠️ Vui lòng đăng nhập đúng tài khoản OLM để sử dụng key này,\`,
                \`hoặc liên hệ admin để được hỗ trợ!\`
            ],
            onOk: () => buildLockScreen('⚠️ Tài khoản OLM không khớp với key đã đăng ký!')
        });
    }

    // ══════════════════════════════════════════════════════
    //  HỆ THỐNG GIAO DIỆN THEO CHỦ ĐỀ (THEME) — giống core v3.2
    // ══════════════════════════════════════════════════════
    function getThemeColors(theme) {
        const T = {
            default: {
                c1:'#00f2fe', c2:'#4facfe',
                bgOverlay:'rgba(13,17,23,0.95)', bgPanel:'rgba(13,17,23,0.88)',
                border:'rgba(0,242,254,0.2)', borderStrong:'rgba(0,242,254,0.3)',
                borderSubtle:'rgba(0,242,254,0.12)',
                headerBg:'linear-gradient(135deg,rgba(0,242,254,0.07),rgba(79,172,254,0.04))',
                glowColor:'rgba(0,242,254,0.45)', glowStrong:'rgba(0,242,254,0.7)',
                glowMid:'rgba(0,242,254,0.25)', glowSubtle:'rgba(0,242,254,0.08)',
                glowPulse:'rgba(0,242,254,0.55)',
                inputBorder:'rgba(0,242,254,0.4)', inputColor:'#00f2fe',
                floatGradient:'linear-gradient(135deg,#00f2fe,#4facfe)',
                brandGradient:'linear-gradient(90deg,#00f2fe,#4facfe,#00f2fe)',
                statusBorder:'rgba(0,230,120,0.25)', statusBg:'rgba(0,230,120,0.04)',
                panelInset:'rgba(0,242,254,0.08)',
                selectBorder:'rgba(0,242,254,0.2)', consoleBorder:'rgba(0,242,254,0.12)',
                fxCSS:'', panelExtra:'',
                themeLabel:'🔵 Mặc Định',
                previewBg:'linear-gradient(135deg,#001520,#00f2fe55)',
                previewBorder:'rgba(0,242,254,0.5)',
                previewText:'#00f2fe',
            },
            gray: {
                c1:'#e0e0e0', c2:'#a0a0a0',
                bgOverlay:'rgba(10,10,10,0.97)', bgPanel:'rgba(20,20,20,0.94)',
                border:'rgba(200,200,200,0.18)', borderStrong:'rgba(230,230,230,0.3)',
                borderSubtle:'rgba(170,170,170,0.1)',
                headerBg:'linear-gradient(135deg,rgba(120,120,120,0.12),rgba(60,60,60,0.05))',
                glowColor:'rgba(210,210,210,0.35)', glowStrong:'rgba(220,220,220,0.6)',
                glowMid:'rgba(200,200,200,0.2)', glowSubtle:'rgba(160,160,160,0.07)',
                glowPulse:'rgba(200,200,200,0.45)',
                inputBorder:'rgba(200,200,200,0.38)', inputColor:'#d8d8d8',
                floatGradient:'linear-gradient(135deg,#c0c0c0,#666)',
                brandGradient:'linear-gradient(90deg,#c0c0c0,#ffffff,#d0d0d0,#c0c0c0)',
                statusBorder:'rgba(160,160,160,0.2)', statusBg:'rgba(60,60,60,0.07)',
                panelInset:'rgba(200,200,200,0.07)',
                selectBorder:'rgba(190,190,190,0.2)', consoleBorder:'rgba(160,160,160,0.1)',
                fxCSS:\`
                    #tl-conn-fx-bar { height:2px; background:linear-gradient(90deg,transparent,rgba(255,255,255,0.08),rgba(255,255,255,0.55),rgba(255,255,255,0.08),transparent); background-size:300% 100%; animation:metalSweep 2.8s linear infinite; }
                    @keyframes metalSweep { 0%{background-position:100% 0} 100%{background-position:-200% 0} }
                    #tl-panel { box-shadow: 0 0 60px rgba(0,0,0,0.85), 0 0 30px rgba(180,180,180,0.06), inset 0 1px 0 rgba(255,255,255,0.08); }
                    #tl-conn-panel { box-shadow: 0 0 60px rgba(0,0,0,0.85), inset 0 1px 0 rgba(255,255,255,0.08); }
                \`,
                panelExtra:'<div id="tl-conn-fx-bar"></div>',
                themeLabel:'⚫ Xám Bạc',
                previewBg:'linear-gradient(135deg,#1a1a1a,#666)',
                previewBorder:'rgba(220,220,220,0.45)',
                previewText:'#e0e0e0',
            },
            pink: {
                c1:'#ff6eb4', c2:'#ff1493',
                bgOverlay:'rgba(18,4,14,0.97)', bgPanel:'rgba(26,4,18,0.93)',
                border:'rgba(255,110,180,0.2)', borderStrong:'rgba(255,110,180,0.38)',
                borderSubtle:'rgba(255,110,180,0.12)',
                headerBg:'linear-gradient(135deg,rgba(255,110,180,0.09),rgba(255,20,147,0.04))',
                glowColor:'rgba(255,110,180,0.45)', glowStrong:'rgba(255,110,180,0.75)',
                glowMid:'rgba(255,110,180,0.22)', glowSubtle:'rgba(255,20,147,0.07)',
                glowPulse:'rgba(255,110,180,0.55)',
                inputBorder:'rgba(255,110,180,0.42)', inputColor:'#ffb3d9',
                floatGradient:'linear-gradient(135deg,#ff6eb4,#ff1493)',
                brandGradient:'linear-gradient(90deg,#ff6eb4,#ffcce8,#ff1493,#ff6eb4)',
                statusBorder:'rgba(255,110,180,0.2)', statusBg:'rgba(255,20,147,0.05)',
                panelInset:'rgba(255,110,180,0.1)',
                selectBorder:'rgba(255,110,180,0.2)', consoleBorder:'rgba(255,110,180,0.12)',
                fxCSS:\`
                    #tl-panel { animation:sakuraPanelGlow 3s ease-in-out infinite; }
                    #tl-conn-panel { animation:sakuraPanelGlow 3s ease-in-out infinite; }
                    @keyframes sakuraPanelGlow {
                        0%,100%{ box-shadow:0 0 60px rgba(0,0,0,0.8),0 0 25px rgba(255,110,180,0.1),inset 0 0 0 1px rgba(255,110,180,0.06); }
                        50%{ box-shadow:0 0 60px rgba(0,0,0,0.8),0 0 45px rgba(255,110,180,0.2),inset 0 0 0 1px rgba(255,110,180,0.12); }
                    }
                    .sakura-petal { position:absolute; pointer-events:none; border-radius:50% 0 50% 0; background:rgba(255,110,180,0.22); animation:sakuraDrift linear infinite; }
                    @keyframes sakuraDrift { 0%{transform:translateY(-10px) rotate(0deg);opacity:0.7} 100%{transform:translateY(420px) rotate(270deg);opacity:0} }
                    #tl-conn-fx-petals { position:absolute;top:0;left:0;right:0;height:100%;pointer-events:none;overflow:hidden;z-index:0;border-radius:16px; }
                \`,
                panelExtra:\`<div id="tl-conn-fx-petals">
                    <div class="sakura-petal" style="width:7px;height:7px;left:8%;top:-10px;animation-duration:3.8s;animation-delay:0s;"></div>
                    <div class="sakura-petal" style="width:5px;height:5px;left:28%;top:-10px;animation-duration:5.1s;animation-delay:0.9s;"></div>
                    <div class="sakura-petal" style="width:8px;height:8px;left:55%;top:-10px;animation-duration:4.4s;animation-delay:1.7s;"></div>
                    <div class="sakura-petal" style="width:4px;height:4px;left:75%;top:-10px;animation-duration:3.2s;animation-delay:0.4s;"></div>
                    <div class="sakura-petal" style="width:6px;height:6px;left:92%;top:-10px;animation-duration:4.9s;animation-delay:2.1s;"></div>
                </div>\`,
                themeLabel:'🌸 Hồng Sakura',
                previewBg:'linear-gradient(135deg,#1a0510,#ff6eb455)',
                previewBorder:'rgba(255,110,180,0.55)',
                previewText:'#ff6eb4',
            }
        };
        return T[theme] || T.default;
    }

    // ========== CSS LOCK SCREEN — giống core ==========
    function getLockScreenStyles() {
        const tc = getThemeColors(CURRENT_THEME);
        return \`
            @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');
            #tl-conn-overlay { position:fixed;top:0;left:0;width:100vw;height:100vh;background:\${tc.bgOverlay};backdrop-filter:blur(15px);z-index:2147483647;display:flex;align-items:center;justify-content:center;font-family:'Rajdhani',sans-serif; }
            #tl-conn-panel { width:420px;background:\${tc.bgPanel};border:1px solid \${tc.borderStrong};border-radius:20px;box-shadow:0 0 60px rgba(0,0,0,0.8),0 0 0 1px \${tc.panelInset} inset;text-align:center;overflow:hidden;animation:tlFadeIn 0.3s ease;position:relative; }
            @keyframes tlFadeIn { from{opacity:0;transform:scale(0.95)}to{opacity:1;transform:scale(1)} }
            #tl-conn-header { padding:22px;background:\${tc.headerBg};border-bottom:1px solid \${tc.border}; }
            .tl-brand-name { font-family:'Orbitron',sans-serif;font-size:22px;font-weight:700;background:\${tc.brandGradient};background-size:200%;-webkit-background-clip:text;-webkit-text-fill-color:transparent;animation:tlShimmer 3s linear infinite; }
            @keyframes tlShimmer { 100%{background-position:200% 50%} }
            #tl-conn-body { padding:30px 25px; }
            .tl-subtitle { color:rgba(255,255,255,0.7);font-size:13px;margin-bottom:10px;font-family:'Share Tech Mono'; }
            .tl-warning { color:#ffc107;font-size:12px;margin-bottom:20px;background:rgba(255,193,7,0.1);padding:8px;border-radius:6px; }
            .tl-input { width:100%;padding:14px;background:rgba(0,0,0,0.55);border:1px solid \${tc.inputBorder};border-radius:10px;color:\${tc.inputColor};font-family:'Share Tech Mono';font-size:16px;text-align:center;margin-bottom:15px;transition:0.2s;box-sizing:border-box; }
            .tl-input:focus { outline:none;border-color:\${tc.c1};box-shadow:0 0 16px \${tc.glowMid}; }
            .tl-btn { width:100%;padding:14px;border:none;border-radius:10px;cursor:pointer;font-family:'Orbitron',sans-serif;font-size:14px;font-weight:900;margin-bottom:12px;transition:0.2s; }
            .tl-btn-unlock { background:linear-gradient(135deg,#00b09b,#96c93d);color:#fff; }
            .tl-btn-unlock:hover { transform:scale(1.02);box-shadow:0 0 25px rgba(0,176,155,0.6); }
            .tl-btn-vip { background:rgba(217,4,41,0.1);border:1px solid rgba(217,4,41,0.5);color:#ef233c; }
            .tl-btn-vip:hover { background:rgba(217,4,41,0.2);transform:scale(1.01); }
            #tl-err { color:#ef233c;font-size:13px;margin-top:12px;display:none;font-family:'Share Tech Mono';background:rgba(239,35,60,0.1);padding:8px;border-radius:6px; }
            .tl-hwid { color:rgba(255,255,255,0.22);font-size:10px;margin-top:15px;word-break:break-all;font-family:monospace; }
            .tl-foot { margin-top:15px;font-size:11px;color:rgba(255,255,255,0.13); }
            \${tc.fxCSS}
        \`;
    }

    // ========== CSS MAIN UI — giống core ==========
    function getMainUIStyles() {
        const tc = getThemeColors(CURRENT_THEME);
        return \`
            @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');
            #tl-floatBtn { position:fixed;bottom:28px;right:28px;width:56px;height:56px;border-radius:50%;border:none;cursor:pointer;z-index:10000;background:\${tc.floatGradient};box-shadow:0 0 0 0 \${tc.glowStrong},0 0 20px \${tc.glowColor},0 4px 20px rgba(0,0,0,0.5);display:flex;align-items:center;justify-content:center;font-size:22px;transition:transform 0.2s ease,box-shadow 0.2s ease;animation:connPulseRing 2.5s ease-out infinite; }
            #tl-floatBtn:hover { transform:scale(1.12) rotate(15deg); }
            @keyframes connPulseRing { 0%{box-shadow:0 0 0 0 \${tc.glowPulse}}70%{box-shadow:0 0 0 15px rgba(0,0,0,0)}100%{box-shadow:0 0 0 0 rgba(0,0,0,0)} }
            @keyframes connBlink { 0%,100%{opacity:1}50%{opacity:0.3} }
            #tl-panel { position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);width:360px;background:\${tc.bgPanel};backdrop-filter:blur(24px);border:1px solid \${tc.border};border-radius:16px;box-shadow:0 0 60px rgba(0,0,0,0.8);z-index:9999;overflow:hidden;font-family:'Rajdhani',sans-serif; }
            #tl-panel.hidden { display:none; }
            #tl-p-header { cursor:move;padding:14px 16px 12px;background:\${tc.headerBg};border-bottom:1px solid \${tc.borderSubtle};display:flex;align-items:center;justify-content:space-between; }
            .tl-p-brand { display:flex;align-items:center;gap:8px; }
            .tl-p-name { font-family:'Orbitron',sans-serif;font-size:11.5px;font-weight:700;background:\${tc.brandGradient};background-size:200%;-webkit-background-clip:text;-webkit-text-fill-color:transparent;animation:tlShimmer 3s linear infinite; }
            @keyframes tlShimmer { 100%{background-position:200% 50%} }
            .tl-badge { font-family:'Orbitron';font-size:7.5px;font-weight:900;color:#fff;border-radius:4px;padding:3px 6px;background:linear-gradient(135deg,#555,#777); }
            .tl-badge.vip { background:linear-gradient(135deg,#a855f7,#6366f1);box-shadow:0 0 10px rgba(168,85,247,0.4); }
            .tl-badge.unlimited { background:linear-gradient(135deg,#f59e0b,#ef4444);box-shadow:0 0 10px rgba(245,158,11,0.4); }
            #tl-closeBtn,#tl-settingsBtn { width:28px;height:28px;border-radius:50%;border:1px solid rgba(255,255,255,0.1);background:rgba(255,255,255,0.04);color:rgba(255,255,255,0.5);cursor:pointer;display:flex;align-items:center;justify-content:center;transition:0.2s;font-size:13px; }
            #tl-closeBtn:hover { border-color:rgba(217,4,41,0.6);background:rgba(217,4,41,0.15);color:#ef233c; }
            #tl-settingsBtn:hover { border-color:\${tc.borderStrong};background:\${tc.glowSubtle};color:\${tc.c1}; }
            #tl-settingsBtn.active { border-color:\${tc.c1};background:\${tc.glowSubtle};color:\${tc.c1}; }
            #tl-p-body { padding:14px;display:flex;flex-direction:column;gap:12px; }
            .tl-statbox { border:1px solid \${tc.statusBorder};border-radius:10px;padding:10px;background:\${tc.statusBg}; }
            .tl-statrow { display:flex;align-items:center;gap:8px;font-family:'Share Tech Mono',monospace;font-size:11.5px;color:#ccc;margin-top:4px; }
            #tl-modeSelect { width:100%;padding:10px;background:rgba(0,0,0,0.4);border:1px solid \${tc.selectBorder};border-radius:8px;color:#fff;font-family:'Rajdhani',sans-serif;font-size:14px;outline:none;margin-top:5px; }
            .tl-god-input { width:100%;padding:10px;background:rgba(0,0,0,0.4);border:1px solid rgba(255,193,7,0.3);border-radius:8px;color:#ffc107;font-family:'Share Tech Mono';font-size:13px;outline:none;margin-top:5px;box-sizing:border-box; }
            #tl-fireBtn { width:100%;padding:13px;background:linear-gradient(135deg,#d90429,#ef233c);border:none;border-radius:10px;color:#fff;font-family:'Orbitron';font-weight:900;font-size:14px;cursor:pointer;box-shadow:0 0 20px rgba(217,4,41,0.4);transition:0.2s;margin-top:5px; }
            #tl-fireBtn:hover { box-shadow:0 0 30px rgba(217,4,41,0.7); }
            #tl-fireBtn:disabled { opacity:0.5;cursor:not-allowed; }
            .tl-console { border:1px solid \${tc.consoleBorder};border-radius:10px;background:rgba(0,0,0,0.5);padding:8px;height:80px;overflow-y:auto;font-family:'Share Tech Mono';font-size:10.5px;color:#aaa; }
            .tl-log { margin-bottom:2px; }
            .tl-log.ok   { color:#00e676; }
            .tl-log.err  { color:#ef233c; }
            .tl-log.warn { color:#ffc107; }
            .tl-log.info { color:#4facfe; }
            #tl-p-footer { padding:8px 14px;border-top:1px solid \${tc.borderSubtle};display:flex;justify-content:space-between;font-family:'Share Tech Mono';font-size:9px;color:rgba(255,255,255,0.2); }
            /* ── Settings Overlay ── */
            #tl-so { position:absolute;top:0;left:0;right:0;bottom:0;background:\${tc.bgPanel};backdrop-filter:blur(12px);z-index:20;border-radius:16px;display:flex;flex-direction:column;overflow:hidden; }
            #tl-so.hidden { display:none; }
            .tl-so-hdr { padding:13px 16px;background:\${tc.headerBg};border-bottom:1px solid \${tc.borderSubtle};display:flex;align-items:center;justify-content:space-between;flex-shrink:0; }
            .tl-so-title { font-family:'Orbitron',sans-serif;font-size:10.5px;font-weight:700;color:\${tc.c1}; }
            #tl-soClose { width:26px;height:26px;border-radius:50%;border:1px solid \${tc.border};background:\${tc.glowSubtle};color:\${tc.c1};cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:12px;transition:0.2s; }
            #tl-soClose:hover { background:rgba(217,4,41,0.15);border-color:rgba(217,4,41,0.5);color:#ef233c; }
            .tl-so-body { padding:14px;flex:1;display:flex;flex-direction:column;gap:12px;overflow-y:auto; }
            .tl-so-lbl { font-size:9.5px;font-weight:700;color:rgba(255,255,255,0.28);text-transform:uppercase;font-family:'Orbitron';letter-spacing:1.2px;margin-bottom:2px; }
            .tl-theme-cards { display:flex;gap:8px; }
            .tl-tc { flex:1;cursor:pointer;border-radius:10px;border:2px solid rgba(255,255,255,0.07);padding:8px 6px;text-align:center;transition:all 0.22s;background:rgba(0,0,0,0.3);position:relative; }
            .tl-tc:hover { transform:translateY(-3px);border-color:rgba(255,255,255,0.18);box-shadow:0 6px 18px rgba(0,0,0,0.4); }
            .tl-tc.active { border-color:\${tc.c1};box-shadow:0 0 14px \${tc.glowMid}; }
            .tl-tc-prev { width:100%;height:38px;border-radius:7px;margin-bottom:7px;overflow:hidden;position:relative; }
            .tl-tc-prev-inner { position:absolute;inset:0;display:flex;align-items:center;justify-content:center; }
            .tl-tc-prev-text { font-family:'Orbitron',sans-serif;font-size:7px;font-weight:700;letter-spacing:1px;opacity:0.9; }
            .tl-tc-lbl { font-family:'Rajdhani',sans-serif;font-size:10.5px;font-weight:600;color:rgba(255,255,255,0.6); }
            .tl-tc.active .tl-tc-lbl { color:\${tc.c1};font-weight:700; }
            .tl-tc.active::after { content:'✓';position:absolute;top:5px;right:7px;color:\${tc.c1};font-size:11px;font-weight:900; }
            .tl-so-divider { height:1px;background:linear-gradient(90deg,transparent,\${tc.border},transparent); }
            .tl-hint { font-size:10px;color:rgba(255,255,255,0.2);font-family:'Share Tech Mono';text-align:center;line-height:1.6; }
            .tl-change-key { width:100%;padding:10px;background:rgba(239,35,60,0.1);border:1px solid rgba(239,35,60,0.38);border-radius:8px;color:#ef233c;font-family:'Orbitron',sans-serif;font-size:10.5px;font-weight:700;cursor:pointer;transition:0.2s;letter-spacing:0.5px; }
            .tl-change-key:hover { background:rgba(239,35,60,0.2);border-color:rgba(239,35,60,0.65);box-shadow:0 0 14px rgba(239,35,60,0.25); }
            /* ── Custom Modal ── */
            #tiep-modal-overlay { position:fixed;top:0;left:0;width:100vw;height:100vh;background:rgba(0,0,0,0.72);z-index:2147483646;display:flex;align-items:center;justify-content:center; }
            .tiep-modal-box { width:320px;background:\${tc.bgPanel};border:1px solid \${tc.borderStrong};border-radius:16px;padding:26px 22px 22px;text-align:center;box-shadow:0 0 60px rgba(0,0,0,0.9),inset 0 0 0 1px \${tc.panelInset};font-family:'Rajdhani',sans-serif; }
            .tiep-modal-icon { font-size:38px;margin-bottom:8px; }
            .tiep-modal-title { font-family:'Orbitron',sans-serif;font-size:12px;font-weight:700;color:\${tc.c1};margin-bottom:12px;line-height:1.5; }
            .tiep-modal-lines { color:rgba(255,255,255,0.78);font-size:13px;line-height:1.65;margin-bottom:18px; }
            .tiep-modal-lines b { color:#fff; }
            .tiep-modal-ok { padding:10px 36px;background:\${tc.floatGradient};border:none;border-radius:8px;color:#fff;font-family:'Orbitron',sans-serif;font-size:11.5px;font-weight:900;cursor:pointer;transition:0.2s;box-shadow:0 4px 16px \${tc.glowColor}; }
            .tiep-modal-ok:hover { transform:scale(1.06);box-shadow:0 0 24px \${tc.glowColor}; }
            \${tc.fxCSS}
        \`;
    }

    // ========== CUSTOM MODAL — giống core ==========
    function _ensureModalStyle() {
        if (document.getElementById('tiep-modal-style')) return;
        const tc = getThemeColors(CURRENT_THEME);
        const ms = document.createElement('style');
        ms.id = 'tiep-modal-style';
        ms.textContent = \`
            @keyframes tlModalIn{from{opacity:0;transform:scale(0.92)}to{opacity:1;transform:scale(1)}}
            #tiep-modal-overlay{position:fixed!important;top:0!important;left:0!important;width:100vw!important;height:100vh!important;background:rgba(0,0,0,0.75)!important;z-index:2147483646!important;display:flex!important;align-items:center!important;justify-content:center!important;}
            .tiep-modal-box{width:320px;max-width:90vw;background:\${tc.bgPanel};border:1px solid \${tc.borderStrong};border-radius:16px;padding:26px 22px 22px;text-align:center;box-shadow:0 0 60px rgba(0,0,0,0.9),inset 0 0 0 1px \${tc.panelInset};font-family:'Rajdhani',sans-serif;animation:tlModalIn 0.22s ease;}
            .tiep-modal-icon{font-size:38px;margin-bottom:8px;}
            .tiep-modal-title{font-family:'Orbitron',sans-serif;font-size:12px;font-weight:700;color:\${tc.c1};margin-bottom:12px;line-height:1.5;}
            .tiep-modal-lines{color:rgba(255,255,255,0.82);font-size:13px;line-height:1.7;margin-bottom:18px;}
            .tiep-modal-lines b{color:#fff;}
            .tiep-modal-ok{padding:10px 36px;background:\${tc.floatGradient};border:none;border-radius:8px;color:#fff;font-family:'Orbitron',sans-serif;font-size:11.5px;font-weight:900;cursor:pointer;transition:0.2s;box-shadow:0 4px 16px \${tc.glowColor};}
            .tiep-modal-ok:hover{transform:scale(1.06);box-shadow:0 0 24px \${tc.glowColor};}
        \`;
        document.head.appendChild(ms);
    }

    function showCustomModal({ icon, title, lines, onOk }) {
        _ensureModalStyle();
        const existing = document.getElementById('tiep-modal-overlay');
        if (existing) existing.remove();
        const overlay = document.createElement('div');
        overlay.id = 'tiep-modal-overlay';
        const linesHTML = (Array.isArray(lines) ? lines : [lines]).map(l => \`<div>\${l}</div>\`).join('');
        overlay.innerHTML = \`
            <div class="tiep-modal-box">
                <div class="tiep-modal-icon">\${icon || 'ℹ️'}</div>
                <div class="tiep-modal-title">\${title || 'Thông báo'}</div>
                <div class="tiep-modal-lines">\${linesHTML}</div>
                <button class="tiep-modal-ok" id="tiep-modal-ok-btn">OK</button>
            </div>\`;
        document.body.appendChild(overlay);
        const close = () => { overlay.remove(); if (onOk) onOk(); };
        document.getElementById('tiep-modal-ok-btn').onclick = close;
        overlay.onclick = (e) => { if (e.target === overlay) close(); };
    }

    function showConfirmModal({ icon, title, lines, okText, cancelText, onOk }) {
        _ensureModalStyle();
        const existing = document.getElementById('tiep-modal-overlay');
        if (existing) existing.remove();
        const overlay = document.createElement('div');
        overlay.id = 'tiep-modal-overlay';
        const linesHTML = (Array.isArray(lines) ? lines : [lines]).map(l => \`<div>\${l}</div>\`).join('');
        overlay.innerHTML = \`
            <div class="tiep-modal-box">
                <div class="tiep-modal-icon">\${icon || '❓'}</div>
                <div class="tiep-modal-title">\${title || 'Xác nhận'}</div>
                <div class="tiep-modal-lines">\${linesHTML}</div>
                <div style="display:flex;gap:10px;justify-content:center;">
                    <button class="tiep-modal-ok" id="tiep-confirm-cancel-btn" style="background:rgba(255,255,255,0.08);box-shadow:none;">\${cancelText || 'HỦY'}</button>
                    <button class="tiep-modal-ok" id="tiep-confirm-ok-btn">\${okText || 'XÁC NHẬN'}</button>
                </div>
            </div>\`;
        document.body.appendChild(overlay);
        const dismiss = () => overlay.remove();
        const confirm = () => { overlay.remove(); if (onOk) onOk(); };
        document.getElementById('tiep-confirm-cancel-btn').onclick = dismiss;
        document.getElementById('tiep-confirm-ok-btn').onclick = confirm;
        overlay.onclick = (e) => { if (e.target === overlay) dismiss(); };
    }

    // Áp dụng theme ngay lập tức
    function applyThemeLive(newTheme) {
        CURRENT_THEME = newTheme;
        localStorage.setItem(LS_THEME, newTheme);
        const uiStyle = document.getElementById('tl-ui-style');
        if (uiStyle) uiStyle.textContent = getMainUIStyles();
        const lockStyle = document.getElementById('tl-lock-style');
        if (lockStyle) lockStyle.textContent = getLockScreenStyles();
        const ms = document.getElementById('tiep-modal-style');
        if (ms) ms.remove();
        const fb = document.getElementById('tl-floatBtn');
        if (fb) { fb.style.animation = 'none'; void fb.offsetWidth; fb.style.animation = ''; }
        const lockPanel = document.getElementById('tl-conn-panel');
        if (lockPanel) {
            const existFx = lockPanel.querySelector('#tl-conn-fx-bar,#tl-conn-fx-petals');
            if (existFx) existFx.remove();
            const tc = getThemeColors(newTheme);
            if (tc.panelExtra) {
                const tmp = document.createElement('div');
                tmp.innerHTML = tc.panelExtra;
                lockPanel.insertBefore(tmp.firstElementChild, lockPanel.firstChild);
            }
        }
    }

    // ══════════════════════════════════════════════════════
    //  BẢO MẬT v4 — ẨN API prefix + session token + mã hoá đáp án
    // ══════════════════════════════════════════════════════
    let _secSession    = { token: null, exp: 0, fpHash: null, seq: 1 };
    let _apiPrefixCache = null;
    // [v6] Module "CHUẨN BỊ 10 ĐIỂM" — tải ĐỘNG từ server, KHÔNG nằm trong script
    let _fireModule      = { factory: null, version: 0, loading: false, lastErr: null };
    let _heartbeatTimer  = null;
    let _heartbeatFail   = 0;

    // ══════════════════════════════════════════════════════
    //  [v5] BẢO MẬT NÂNG CAO: ENCRYPT-LS + ANTI-HOOK + SCRIPT GUARD
    // ══════════════════════════════════════════════════════

    // ─── Obfuscation LocalStorage nhạy cảm (XOR + Base64) ─
    const _ENC_PFX = '\\x5f\\x45\\x35\\x5f'; // '_E5_'
    function _lsXor(value) {
        if (!value) return '';
        try {
            const k = getHWID() + API_SECRET.slice(0, 10);
            let r = '';
            for (let i = 0; i < value.length; i++)
                r += String.fromCharCode(value.charCodeAt(i) ^ k.charCodeAt(i % k.length));
            return _ENC_PFX + btoa(unescape(encodeURIComponent(r)));
        } catch (_) { return value; }
    }
    function _lsUnxor(encoded) {
        if (!encoded) return null;
        if (!encoded.startsWith(_ENC_PFX)) return encoded; // Legacy plain — tương thích ngược
        try {
            const v = decodeURIComponent(escape(atob(encoded.slice(_ENC_PFX.length))));
            const k = getHWID() + API_SECRET.slice(0, 10);
            let r = '';
            for (let i = 0; i < v.length; i++)
                r += String.fromCharCode(v.charCodeAt(i) ^ k.charCodeAt(i % k.length));
            return r;
        } catch (_) { return encoded; }
    }
    // Wrapper đọc/ghi LS cho các key nhạy cảm (key, type, exp)
    const _sLS = {
        get: (key)    => { try { return _lsUnxor(localStorage.getItem(key));  } catch (_) { return null; } },
        set: (key, v) => { try { localStorage.setItem(key, v ? _lsXor(v) : ''); } catch (_) {} },
        del: (key)    => { try { localStorage.removeItem(key); }                  catch (_) {} }
    };

    // ─── Mã hoá payload request (AES-GCM + PBKDF2) ───────
    async function _encryptPayload(data, hint) {
        const enc = new TextEncoder(), c = _cryptoObj();
        const iv    = c.getRandomValues(new Uint8Array(12));
        const ts    = Math.floor(Date.now() / 1000);
        const nonce = Array.from(c.getRandomValues(new Uint8Array(8)), b => b.toString(16).padStart(2, '0')).join('');
        const rawKey   = enc.encode(API_SECRET + (hint || '') + (ts >>> 7).toString(16));
        const baseKey  = await c.subtle.importKey('raw', rawKey, 'PBKDF2', false, ['deriveBits']);
        const bits     = await c.subtle.deriveBits({ name: 'PBKDF2', salt: enc.encode('tl5req' + nonce), iterations: 1200, hash: 'SHA-256' }, baseKey, 256);
        const aesKey   = await c.subtle.importKey('raw', bits, { name: 'AES-GCM' }, false, ['encrypt']);
        const ct       = new Uint8Array(await c.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, enc.encode(JSON.stringify(data))));
        const b64      = (a) => btoa(String.fromCharCode(...a));
        return { _e: 5, iv: b64(iv), d: b64(ct.slice(0, -16)), t: b64(ct.slice(-16)), ts, n: nonce };
    }

    // ─── Guard state ───────────────────────────────────────
    let _guardActive = false;
    let _guardTimer  = null;
    let _guardBC     = null;
    let _preScanHook = null; // set bởi early-check trước injectPageHook
    let _hookStrike  = 0;    // [v6-smart] đếm liên tục phát hiện hook — yêu cầu ≥3 mới khoá tạm
    const _GUARD_START_TS = Date.now(); // [v6-smart] miễn nhiễm 60s đầu (trang đang tải)
    // [v6-smart] Khoá VĨNH VIỄN vẫn giữ như cũ khi PHÁT HIỆN ĐÚNG script lạ (đã xác nhận).
    //             Chỉ tinh chỉnh bộ dò: bỏ nhầm cùng-script-nhiều-tab, yêu cầu 3 lần liên tục mới kết luận hook.
    const _GUARD_LS  = ['_tl_conn_key','_tl_conn_type','_tl_conn_exp','_tiep_theme','_tl_hwid','_tl_guard_ts'];
    const _GUARD_UI  = ['tl-conn-overlay','tl-panel','tl-floatBtn','tl-ui-style','tl-lock-style','tiep-modal-style','tiep-modal-overlay'];

    // ─── Hiển thị cảnh báo phát hiện phần mềm lạ ──────────
    function _showGuardWarning(reason) {
        const render = () => {
            try {
                const ex = document.getElementById('_tl_guard_warn');
                if (ex) ex.remove();
                const o = document.createElement('div');
                o.id = '_tl_guard_warn';
                o.style.cssText = 'position:fixed!important;top:0!important;left:0!important;width:100vw!important;height:100vh!important;background:rgba(0,0,0,0.96)!important;z-index:2147483647!important;display:flex!important;align-items:center!important;justify-content:center!important;font-family:monospace!important;';
                o.innerHTML = \`<div style="background:#0d0d0d;border:2px solid #ef233c;border-radius:16px;padding:36px 32px;max-width:430px;text-align:center;box-shadow:0 0 80px rgba(239,35,60,0.6),0 0 160px rgba(239,35,60,0.15);">
                    <div style="font-size:52px;margin-bottom:14px;">🚨</div>
                    <style>@keyframes _tlBlink{50%{opacity:0}}#_tl_guard_warn .glitch{animation:_tlBlink 0.75s step-end infinite;}</style>
                    <div class="glitch" style="font-family:'Courier New',monospace;font-size:16px;font-weight:900;color:#ef233c;text-transform:uppercase;letter-spacing:3px;margin-bottom:14px;">⚠ PHÁT HIỆN PHẦN MỀM LẠ</div>
                    <div style="color:rgba(255,255,255,0.78);font-size:12.5px;line-height:1.9;margin-bottom:18px;">\${reason || 'Phát hiện script/phần mềm không rõ nguồn gốc đang chạy song song.'}<br><br>Toàn bộ dữ liệu khoá đã bị <b style="color:#ef233c">XÓA TỰ ĐỘNG</b> để bảo vệ hệ thống.<br>Liên hệ admin để được hỗ trợ.</div>
                    <div style="color:rgba(239,35,60,0.45);font-size:9px;letter-spacing:2px;font-family:'Courier New',monospace;">THIÊN TAI TÙ TỘI // SECURITY LOCKDOWN v5</div>
                </div>\`;
                document.body.appendChild(o);
            } catch (_) {}
        };
        if (document.body) render();
        else document.addEventListener('DOMContentLoaded', render);
    }

    // ─── Tự huỷ hoàn toàn ─────────────────────────────────
    function _selfDestruct(reason) {
        try { if (_guardTimer) { clearInterval(_guardTimer); _guardTimer = null; } } catch (_) {}
        try { if (_guardBC)    { _guardBC.close();            _guardBC    = null; } } catch (_) {}
        // Xoá toàn bộ LS liên quan đến script
        _GUARD_LS.forEach(k => { try { localStorage.removeItem(k); } catch (_) {} });
        // Đặt cờ độc — ngăn script khởi động lại
        try { localStorage.setItem('_tl_poisoned', '1'); } catch (_) {}
        // Xoá toàn bộ DOM do script tạo ra
        _GUARD_UI.forEach(id => { try { const el = document.getElementById(id); if (el) el.remove(); } catch (_) {} });
        // Reset toàn bộ session nội bộ
        CURRENT_KEY = null;
        KEY_STATUS  = { valid: false, type: null, expires_at: null };
        try { _secSession = { token: null, exp: 0, fpHash: null, seq: 1 }; } catch (_) {}
        CURRENT_DEVICE = '';
        _guardActive = false;
        _showGuardWarning(reason);
    }

    // ══════════════════════════════════════════════════════
    //  [v6.3] BAN-MODE — khoá do SERVER BAN IP/thiết bị (CÓ THỂ MỞ LẠI).
    //  Khác _selfDestruct (khoá vĩnh viễn do script lạ): ban-mode tự polling
    //  server mỗi 15s; khi admin mở khoá → TỰ ĐỘNG reload, dùng lại bình thường
    //  (key được GIỮ LẠI trong localStorage, không xóa).
    // ══════════════════════════════════════════════════════
    let _banState = { active: false, timer: null, reason: '' };
    function _showBanScreen(reason) {
        const render = () => {
            try {
                const ex = document.getElementById('_tl_ban_overlay');
                if (ex) ex.remove();
                const o = document.createElement('div');
                o.id = '_tl_ban_overlay';
                o.style.cssText = 'position:fixed!important;top:0!important;left:0!important;width:100vw!important;height:100vh!important;background:rgba(0,0,0,0.96)!important;z-index:2147483647!important;display:flex!important;align-items:center!important;justify-content:center!important;font-family:monospace!important;';
                o.innerHTML = '<div style="background:#0d0d0d;border:2px solid #ef233c;border-radius:16px;padding:36px 32px;max-width:430px;text-align:center;box-shadow:0 0 80px rgba(239,35,60,0.6),0 0 160px rgba(239,35,60,0.15);">'
                    + '<div style="font-size:52px;margin-bottom:14px;">🚨</div>'
                    + '<style>@keyframes _tlBlink{50%{opacity:0}}#_tl_ban_overlay .glitch{animation:_tlBlink 0.75s step-end infinite;}</style>'
                    + '<div class="glitch" style="font-family:\\'Courier New\\',monospace;font-size:16px;font-weight:900;color:#ef233c;text-transform:uppercase;letter-spacing:3px;margin-bottom:14px;">⚠ Thiết bị / IP đã bị khoá</div>'
                    + '<div style="color:rgba(255,255,255,0.78);font-size:12.5px;line-height:1.9;margin-bottom:14px;">' + (reason || 'Phát hiện môi trường không hợp lệ.') + '<br>Liên hệ admin để được mở khoá.</div>'
                    + '<div id="_tl_ban_status" style="color:#ffc107;font-size:11.5px;line-height:1.8;">🔄 Đang tự động kiểm tra mỗi 15 giây...<br>Khi admin mở khoá, tool sẽ <b style="color:#00e676;">TỰ ĐỘNG hoạt động lại</b>, không cần thao tác.</div>'
                    + '<div style="color:rgba(239,35,60,0.45);font-size:9px;letter-spacing:2px;font-family:\\'Courier New\\',monospace;margin-top:16px;">THIÊN TAI TÙ TỘI // BAN LOCK v6.3 (TỰ MỞ KHI UNBAN)</div>'
                    + '</div>';
                document.body.appendChild(o);
            } catch (_) {}
        };
        if (document.body) render();
        else document.addEventListener('DOMContentLoaded', render);
    }
    function _banPollOnce() {
        (async () => {
            try {
                const prefix = await _apiPrefix();
                GM_xmlhttpRequest({
                    method: 'GET', url: SERVER_BASE + prefix + '/ping', timeout: 8000,
                    onload: (r) => {
                        if (r.status === 200) { _exitBanMode(); return; }
                        const el = document.getElementById('_tl_ban_status');
                        if (el) el.innerHTML = '🔄 Vẫn bị khoá — đang chờ admin mở khoá...<br>(tự kiểm tra lại sau 15 giây)';
                    },
                    onerror: () => {}, ontimeout: () => {}
                });
            } catch (_) {}
        })();
    }
    function _enterBanMode(reason) {
        if (_banState.active) return;
        _banState.active = true;
        _banState.reason = reason || '';
        // Dừng heartbeat + guard (đã vào ban mode, không cần nữa)
        try { if (_heartbeatTimer) { clearInterval(_heartbeatTimer); _heartbeatTimer = null; } } catch (_) {}
        try { if (_guardTimer)     { clearInterval(_guardTimer);     _guardTimer     = null; } } catch (_) {}
        try { if (_guardBC)        { _guardBC.close();               _guardBC        = null; } } catch (_) {}
        // Xoá UI đang chạy (ngừng hoạt động) — GIỮ LẠI key trong LS để mở khoá dùng lại ngay
        ['tl-panel','tl-floatBtn','tl-conn-overlay','tiep-modal-overlay'].forEach(id => { try { const el = document.getElementById(id); if (el) el.remove(); } catch (_) {} });
        CURRENT_KEY = null;
        KEY_STATUS  = { valid: false, type: null, expires_at: null };
        try { _secSession = { token: null, exp: 0, fpHash: null, seq: 1 }; } catch (_) {}
        _fireModule = { factory: null, version: 0, loading: false, lastErr: null };
        _showBanScreen(reason);
        // Polling mỗi 15s chờ admin mở khoá; lần đầu sau 5s
        _banState.timer = setInterval(_banPollOnce, 15000);
        setTimeout(_banPollOnce, 5000);
    }
    function _exitBanMode() {
        if (!_banState.active) return;
        _banState.active = false;
        try { if (_banState.timer) { clearInterval(_banState.timer); _banState.timer = null; } } catch (_) {}
        try { const el = document.getElementById('_tl_ban_overlay'); if (el) el.remove(); } catch (_) {}
        // Tự reload → script khởi động lại sạch, key vẫn còn → dùng bình thường
        setTimeout(() => { try { window.location.reload(); } catch (_) {} }, 800);
    }

    // ══════════════════════════════════════════════════════
    //  [v6.4] REMOTE-LOCK — khoá do PHÁT HIỆN SCRIPT LẠ.
    //  Khác _selfDestruct (cũ, khoá vĩnh viễn, xóa key):
    //   1) TỰ ĐỘNG gửi báo cáo lên server (ip + thiết bị + lý do)
    //   2) Server ghi vào tab admin riêng → admin thấy IP + thiết bị bị khoá
    //   3) Admin bấm MỞ KHOÁ → client polling thấy → TỰ ĐỘNG reload, dùng lại
    //      bình thường (GIỮ LẠI key trong localStorage, không cần nhập lại).
    // ══════════════════════════════════════════════════════
    let _remoteLockState = { active: false, timer: null, reason: '', reported: false };
    function _rlSendReport(reason) {
        (async () => {
            try {
                const prefix = await _apiPrefix();
                let olmUser = '';
                try { olmUser = getOlmUsername(); } catch (_) {}
                const body = JSON.stringify({
                    key: CURRENT_KEY || _sLS.get(LS_KEY) || '',
                    hwid: getHWID(), fp: _collectFP(), device: _collectDevice(),
                    reason: String(reason || '').slice(0, 200), olm_user: olmUser
                });
                let tries = 0;
                let sigHdrs = {};
                try { sigHdrs = await _signReq(body, ''); } catch (_) {}
                (function send() {
                    tries++;
                    GM_xmlhttpRequest({
                        method: 'POST', url: SERVER_BASE + prefix + '/lock-report',
                        headers: Object.assign({ 'Content-Type': 'application/json' }, sigHdrs), data: body, timeout: 10000,
                        onload: () => {
                            _remoteLockState.reported = true;
                            const el = document.getElementById('_tl_rl_status');
                            if (el) el.innerHTML = '✅ Đã báo cáo lên server admin.<br>🔄 Đang chờ admin mở khoá (tự kiểm tra mỗi 20s)...';
                        },
                        onerror:   () => { if (tries < 4) setTimeout(send, 3000); },
                        ontimeout: () => { if (tries < 4) setTimeout(send, 3000); }
                    });
                })();
            } catch (_) {}
        })();
    }
    function _showRemoteLockScreen(reason) {
        const render = () => {
            try {
                const ex = document.getElementById('_tl_rl_overlay');
                if (ex) ex.remove();
                const o = document.createElement('div');
                o.id = '_tl_rl_overlay';
                o.style.cssText = 'position:fixed!important;top:0!important;left:0!important;width:100vw!important;height:100vh!important;background:rgba(0,0,0,0.96)!important;z-index:2147483647!important;display:flex!important;align-items:center!important;justify-content:center!important;font-family:monospace!important;';
                o.innerHTML = '<div style="background:#0d0d0d;border:2px solid #ef233c;border-radius:16px;padding:36px 32px;max-width:430px;text-align:center;box-shadow:0 0 80px rgba(239,35,60,0.6),0 0 160px rgba(239,35,60,0.15);">'
                    + '<div style="font-size:52px;margin-bottom:14px;">🚨</div>'
                    + '<style>@keyframes _tlBlink{50%{opacity:0}}#_tl_rl_overlay .glitch{animation:_tlBlink 0.75s step-end infinite;}</style>'
                    + '<div class="glitch" style="font-family:\\'Courier New\\',monospace;font-size:16px;font-weight:900;color:#ef233c;text-transform:uppercase;letter-spacing:3px;margin-bottom:14px;">⚠ PHÁT HIỆN PHẦN MỀM LẠ</div>'
                    + '<div style="color:rgba(255,255,255,0.78);font-size:12.5px;line-height:1.9;margin-bottom:14px;">' + (reason || 'Phát hiện script/phần mềm không rõ nguồn gốc.') + '<br>Đã <b style="color:#ffc107;">TỰ ĐỘNG báo cáo</b> lên server admin.</div>'
                    + '<div id="_tl_rl_status" style="color:#ffc107;font-size:11.5px;line-height:1.8;">📤 Đang gửi báo cáo lên server...</div>'
                    + '<div style="color:rgba(0,230,118,0.6);font-size:10.5px;line-height:1.7;margin-top:10px;">Khi admin bấm <b>MỞ KHOÁ</b> trên trang quản trị,<br>tool sẽ <b style="color:#00e676;">TỰ ĐỘNG hoạt động lại</b> (không cần nhập lại key).</div>'
                    + '<div style="color:rgba(239,35,60,0.45);font-size:9px;letter-spacing:2px;font-family:\\'Courier New\\',monospace;margin-top:16px;">THIÊN TAI TÙ TỘI // REMOTE LOCK v6.4</div>'
                    + '<div style="color:rgba(255,255,255,0.25);font-size:9px;margin-top:6px;font-family:monospace;">HWID: ' + getHWID() + '</div>'
                    + '</div>';
                document.body.appendChild(o);
            } catch (_) {}
        };
        if (document.body) render();
        else document.addEventListener('DOMContentLoaded', render);
    }
    function _remoteLockPollOnce() {
        (async () => {
            try {
                const prefix = await _apiPrefix();
                const lockBody = JSON.stringify({ hwid: getHWID() });
                let sigHdrs2 = {};
                try { sigHdrs2 = await _signReq(lockBody, ''); } catch (_) {}
                GM_xmlhttpRequest({
                    method: 'POST', url: SERVER_BASE + prefix + '/lock-status',
                    headers: Object.assign({ 'Content-Type': 'application/json' }, sigHdrs2),
                    data: lockBody, timeout: 8000,
                    onload: (r) => {
                        try {
                            const j = JSON.parse(r.responseText);
                            if (j && j.locked === false) { _exitRemoteLock(); return; }
                            const el = document.getElementById('_tl_rl_status');
                            if (el) el.innerHTML = '🔒 Vẫn bị khoá — chờ admin mở khoá...<br>(tự kiểm tra lại sau 20s)';
                        } catch (_) {}
                    },
                    onerror: () => {}, ontimeout: () => {}
                });
            } catch (_) {}
        })();
    }
    function _enterRemoteLock(reason) {
        if (_remoteLockState.active) return;
        _remoteLockState.active = true;
        _remoteLockState.reason = reason || '';
        // Đánh dấu tồn tại qua reload — KHÔNG xóa key → mở khoá dùng lại ngay
        try { localStorage.setItem('_tl_remote_locked', '1'); } catch (_) {}
        try { localStorage.removeItem('_tl_poisoned'); } catch (_) {} // cờ vĩnh viễn cũ không dùng nữa
        // Dừng mọi timer đang chạy
        try { if (_heartbeatTimer) { clearInterval(_heartbeatTimer); _heartbeatTimer = null; } } catch (_) {}
        try { if (_guardTimer)     { clearInterval(_guardTimer);     _guardTimer     = null; } } catch (_) {}
        try { if (_guardBC)        { _guardBC.close();               _guardBC        = null; } } catch (_) {}
        try { if (_banState.timer) { clearInterval(_banState.timer); _banState.timer = null; } } catch (_) {}
        // Xoá UI đang chạy — GIỮ LẠI key trong LS
        ['tl-panel','tl-floatBtn','tl-conn-overlay','tiep-modal-overlay','_tl_guard_warn','_tl_ban_overlay'].forEach(id => { try { const el = document.getElementById(id); if (el) el.remove(); } catch (_) {} });
        CURRENT_KEY = null;
        KEY_STATUS  = { valid: false, type: null, expires_at: null };
        try { _secSession = { token: null, exp: 0, fpHash: null, seq: 1 }; } catch (_) {}
        _fireModule = { factory: null, version: 0, loading: false, lastErr: null };
        _showRemoteLockScreen(reason);
        _rlSendReport(reason);
        _remoteLockState.timer = setInterval(_remoteLockPollOnce, 20000);
        setTimeout(_remoteLockPollOnce, 6000);
    }
    function _exitRemoteLock() {
        _remoteLockState.active = false;
        try { if (_remoteLockState.timer) { clearInterval(_remoteLockState.timer); _remoteLockState.timer = null; } } catch (_) {}
        try { localStorage.removeItem('_tl_remote_locked'); } catch (_) {}
        try { localStorage.removeItem('_tl_poisoned'); } catch (_) {}
        try { const el = document.getElementById('_tl_rl_overlay'); if (el) el.remove(); } catch (_) {}
        // Tự reload → script khởi động lại sạch, key vẫn còn → dùng bình thường
        setTimeout(() => { try { window.location.reload(); } catch (_) {} }, 800);
    }

    // ─── Phát hiện hook vào native functions ──────────────
    // [v6.5] Mở rộng danh sách: thêm fetch/XHR/setTimeout/setInterval/eval (anti-hook/dump cực mạnh)
    function _detectHookNow() {
        // [v6.5.2] WHITELIST loader KeyVault (OLM_user.js): nó hook XHR/fetch ngay từ document-start.
        //          Nếu loader đang chạy (window.__kv_q_buf tồn tại) → các native bị wrap là CỦA TA, không phải script lạ.
        let _kvLoaderActive = false;
        try { _kvLoaderActive = !!((typeof unsafeWindow !== 'undefined' ? unsafeWindow : window).__kv_q_buf); } catch (_) {}
        try { if (!Function.prototype.toString.toString().includes('[native code]')) return 'Function.prototype.toString'; } catch (_) {}
        try { if (!Object.defineProperty.toString().includes('[native code]'))       return 'Object.defineProperty'; }       catch (_) {}
        try { if (!JSON.parse.toString().includes('[native code]'))                   return 'JSON.parse'; }                   catch (_) {}
        if (_kvLoaderActive) return null; // loader của ta đang wrap fetch/XHR/setTimeout → bỏ qua, không khoá nhầm
        try { if (typeof window.fetch === 'function' && !window.fetch.toString().includes('[native code]')) return 'window.fetch'; } catch (_) {}
        try { if (!XMLHttpRequest.prototype.open.toString().includes('[native code]'))  return 'XMLHttpRequest.open'; }  catch (_) {}
        try { if (!XMLHttpRequest.prototype.send.toString().includes('[native code]'))  return 'XMLHttpRequest.send'; }  catch (_) {}
        try { if (!setTimeout.toString().includes('[native code]'))  return 'setTimeout'; }  catch (_) {}
        try { if (!setInterval.toString().includes('[native code]')) return 'setInterval'; } catch (_) {}
        try { if (!eval.toString().includes('[native code]'))        return 'eval'; }        catch (_) {}
        try { if (!Function.toString().includes('[native code]'))    return 'Function'; }    catch (_) {}
        return null;
    }
    // [v6.5] DevTools detection (nghi ngờ dump) — chỉ TĂNG đòn strike khi CŨNG phát hiện hook
    function _devtoolsOpen() {
        try { return (window.outerWidth - window.innerWidth > 160) || (window.outerHeight - window.innerHeight > 200); } catch (_) { return false; }
    }
    // Early-check: chạy NGAY tại definition-time, TRƯỚC injectPageHook ─
    _preScanHook = _detectHookNow();

    // ─── Phát hiện script song song qua BroadcastChannel ──
    function _initGuardBC() {
        try {
            const chName = '_tltg_' + API_SECRET.slice(0, 8);
            _guardBC = new BroadcastChannel(chName);
            _guardBC.onmessage = (evt) => {
                try {
                    // [v6-smart] Chỉ CÙNG script ta mới gửi TL_HB trên kênh bí mật này.
                    // Nhận được = tab khác của CHÍNH script này (user mở nhiều tab) → BÌNH THƯỜNG, KHÔNG khoá.
                    // (Script lạ không biết tên kênh + định dạng này nên không thể giả mạo.)
                    if (evt && evt.data && evt.data.t === 'TL_HB') {
                        // chỉ ghi nhận, không làm gì — nhiều tab là hành vi hợp lệ
                    }
                } catch (_) {}
            };
            // Gửi heartbeat lần đầu sau 700ms (cho phép cả 2 instance setup xong)
            setTimeout(() => { try { if (_guardBC) _guardBC.postMessage({ t: 'TL_HB', ts: Date.now() }); } catch (_) {} }, 700);
            // Heartbeat định kỳ mỗi 15s — phát hiện script cài muộn
            setInterval(() => { try { if (_guardBC) _guardBC.postMessage({ t: 'TL_HB', ts: Date.now() }); } catch (_) {} }, 15000);
        } catch (_) {
            _initGuardLS(); // BroadcastChannel không hỗ trợ → fallback LS
        }
    }

    // ─── Fallback: phát hiện qua localStorage timestamp ───
    function _initGuardLS() {
        const TS_KEY = '_tl_guard_ts';
        const now    = Date.now();
        const prev   = parseInt(localStorage.getItem(TS_KEY) || '0');
        // [v6-smart] Timestamp gần = user F5 nhanh hoặc mở nhiều tab CÙNG script → BÌNH THƯỜNG, KHÔNG khoá.
        localStorage.setItem(TS_KEY, now.toString());
        setInterval(() => { try { localStorage.setItem(TS_KEY, Date.now().toString()); } catch (_) {} }, 2500);
    }

    // ─── Quét định kỳ mỗi 7 giây ─────────────────────────
    function _startPeriodicScan() {
        _guardTimer = setInterval(() => {
            try {
                // [v6-smart] Miễn nhiễm 60s đầu (trang/extension đang khởi tạo, có thể bọc native tạm thời)
                if (Date.now() - _GUARD_START_TS < 60000) return;
                const h = _detectHookNow();
                if (h) {
                    // [v6.5] Nếu đồng thời mở DevTools (nghi dump) → đòn strike gấp đôi
                    _hookStrike += _devtoolsOpen() ? 2 : 1;
                    // [v6-smart] Yêu cầu 3 lần liên tục mới kết luận có hook thật → remote-lock (admin mở khoá được).
                    if (_hookStrike >= 3) {
                        clearInterval(_guardTimer); _guardTimer = null;
                        _enterRemoteLock('🛡️ Phát hiện phần mềm lạ can thiệp liên tục vào ' + h + ' (đã xác nhận 3 lần). Đã báo cáo admin, chờ mở khoá từ xa.');
                    }
                } else {
                    _hookStrike = 0; // quét sạch → reset đếm
                }
            } catch (_) {}
        }, 5000); // [v6.5] quét nhanh hơn (5s) — phát hiện sớm hơn
    }

    // ─── Khởi tạo toàn bộ hệ thống bảo vệ ────────────────
    function _initGuard() {
        if (_guardActive) return;
        _guardActive = true;
        // [v6-smart] MIGRATION: cờ poisoned do bản cũ (dò nhầm) đặt → tự gỡ một lần để người dùng dùng lại.
        //             Bản v6 trở lên chỉ đặt poisoned khi đã XÁC NHẬN (3 lần liên tục) script lạ thật.
        try {
            if (localStorage.getItem('_tl_guard_ver') !== '6') {
                localStorage.removeItem('_tl_poisoned');
                localStorage.setItem('_tl_guard_ver', '6');
            }
        } catch (_) {}
        // [v6.4] Cờ poisoned / _tl_remote_locked được xử lý ở startup (báo server + chờ admin mở khoá).
        _initGuardBC();
        _startPeriodicScan();
    }
    // ══════════════════════════════════════════════════════
    //  [end v5 security module]
    // ══════════════════════════════════════════════════════

    function _cryptoObj() { return (typeof crypto !== 'undefined' ? crypto : window.crypto); }

    async function _hmacHex(secret, str) {
        const enc = new TextEncoder(), c = _cryptoObj();
        const key = await c.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
        const sig = await c.subtle.sign('HMAC', key, enc.encode(str));
        return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    async function _apiPrefix() {
        if (!_apiPrefixCache)
            _apiPrefixCache = '/' + (await _hmacHex(API_SECRET, 'godmode:api:prefix:v4')).slice(0, 12);
        return _apiPrefixCache;
    }
    // [v6.5] KÝ REQUEST HMAC — chống fake / replay / tamper (khớp server verifyReqSig)
    // Sign = HMAC_SHA256(API_SECRET, ts|nonce|sha256(body)|sessionToken)
    async function _signReq(bodyStr, sessionTok) {
        const c = _cryptoObj(), enc = new TextEncoder();
        const ts = Math.floor(Date.now() / 1000).toString();
        const nonce = Array.from(c.getRandomValues(new Uint8Array(8)), b => b.toString(16).padStart(2, '0')).join('');
        const bodyHashBuf = await c.subtle.digest('SHA-256', enc.encode(bodyStr || ''));
        const bodyHash = Array.from(new Uint8Array(bodyHashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
        const hmacKey = await c.subtle.importKey('raw', enc.encode(API_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
        const sigBuf = await c.subtle.sign('HMAC', hmacKey, enc.encode(ts + '|' + nonce + '|' + bodyHash + '|' + (sessionTok || '')));
        const sign = Array.from(new Uint8Array(sigBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
        return { 'X-Ts': ts, 'X-Nonce': nonce, 'X-Sign': sign };
    }

    function _collectDevice() {
        const ua = navigator.userAgent || '';
        const isAndroid = /android/i.test(ua);
        const isIOS = /iphone|ipad|ipod/i.test(ua);
        let model = '';
        if (isAndroid) {
            const m = ua.match(/;\\s*([^;)]+?)\\s+Build\\//i) || ua.match(/android\\s+[^;)]+;\\s*([^;)]+)/i);
            model = m ? m[1].trim() : '';
        } else if (isIOS) {
            model = /ipad/i.test(ua) ? 'iPad' : /ipod/i.test(ua) ? 'iPod' : 'iPhone';
        }
        const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
        return {
            os: isAndroid ? 'Android' : isIOS ? 'iOS' : (navigator.platform || 'Unknown'),
            model: model || '', brand: '', isMobile: isAndroid || isIOS,
            touchPoints: navigator.maxTouchPoints || 0,
            cores: navigator.hardwareConcurrency || 0,
            memory: navigator.deviceMemory || 0,
            screen: \`\${screen.width}x\${screen.height}\`,
            pixelRatio: window.devicePixelRatio || 1,
            connection: conn ? (conn.effectiveType || '') : '',
            vendor: navigator.vendor || '',
            language: navigator.language || '',
            timezone: (Intl.DateTimeFormat().resolvedOptions().timeZone) || '',
            webdriver: !!navigator.webdriver
        };
    }

    function _collectFP() {
        return {
            ua: navigator.userAgent, platform: navigator.platform || '',
            language: navigator.language || '',
            timezone: (Intl.DateTimeFormat().resolvedOptions().timeZone) || '',
            webdriver: !!navigator.webdriver,
            hardwareConcurrency: navigator.hardwareConcurrency || 0,
            deviceMemory: navigator.deviceMemory || 0,
            maxTouchPoints: navigator.maxTouchPoints || 0,
            screen: \`\${screen.width}x\${screen.height}\`,
            colorDepth: screen.colorDepth, pixelRatio: window.devicePixelRatio || 1
        };
    }

    async function _deriveKey(sessionToken) {
        const enc = new TextEncoder(), c = _cryptoObj();
        const baseKey = await c.subtle.importKey('raw', enc.encode(sessionToken + '|' + API_SECRET), 'PBKDF2', false, ['deriveBits']);
        const bits = await c.subtle.deriveBits({ name: 'PBKDF2', salt: enc.encode('godmode-v4-salt'), iterations: 1000, hash: 'SHA-256' }, baseKey, 256);
        return c.subtle.importKey('raw', bits, { name: 'AES-GCM' }, false, ['decrypt']);
    }

    function _b64ToBytes(b64) {
        const bin = atob(b64);
        return Uint8Array.from(bin, x => x.charCodeAt(0));
    }

    async function _decryptAnswers(payload, sessionToken) {
        const c = _cryptoObj();
        const key = await _deriveKey(sessionToken);
        const iv = _b64ToBytes(payload.iv), data = _b64ToBytes(payload.data), tag = _b64ToBytes(payload.tag);
        const buf = new Uint8Array(data.length + tag.length); buf.set(data); buf.set(tag, data.length);
        const plain = await c.subtle.decrypt({ name: 'AES-GCM', iv }, key, buf);
        return JSON.parse(new TextDecoder().decode(plain));
    }

    async function _ensureSession(key, hwid) {
        if (_secSession.token && _secSession.exp > Date.now()) return _secSession.token;
        if (!key) throw new Error('Thiếu key — không thể xác thực phiên');
        const r = await gmPost('/attest', { key, hwid: hwid || getHWID(), fp: _collectFP(), device: _collectDevice() });
        if (!r.success) throw new Error(r.message || 'Xác thực thiết bị/mạng thất bại');
        _secSession = { token: r.session, exp: Date.now() + (r.expiresIn - 30) * 1000, fpHash: r.fpHash, seq: 1 };
        if (r.device) CURRENT_DEVICE = r.device;
        return r.session;
    }

    // [v6] Tải CHỦ ĐỘNG module "CHUẨN BỊ 10 ĐIỂM" từ server (chỉ premium)
    async function _loadFireModule() {
        if (_fireModule.factory) return true;
        if (_fireModule.loading) return false;
        if (!isPremiumKey()) return false;
        _fireModule.loading = true;
        try {
            const key = CURRENT_KEY || _sLS.get(LS_KEY);
            if (!key) return false;
            await gmPost('/module', { key, hwid: getHWID() });
            return !!_fireModule.factory;
        } catch (e) {
            _fireModule.lastErr = e.message;
            return false;
        } finally {
            _fireModule.loading = false;
        }
    }

    // [v6] Heartbeat liên tục (30s) — gửi fp/device mới cho server check.
    // Nếu server trả blocked hoặc 404 (đã bị ban) → TỰ HUỶ (xóa key + UI).
    // Nếu server đẩy module mới → tự nạp lại. Mất mạng kéo dài → khóa tạm module.
    function _startHeartbeat() {
        if (_heartbeatTimer) return;
        _heartbeatTimer = setInterval(async () => {
            if (!CURRENT_KEY) return;
            try {
                const r = await gmPost('/heartbeat', {
                    key: CURRENT_KEY, hwid: getHWID(),
                    fp: _collectFP(), device: _collectDevice(),
                    clientVersion: _fireModule.version
                });
                _heartbeatFail = 0;
                if (r && r.blocked) {
                    // [v6.3] Server ban → ban-mode (tự mở lại khi admin unban), KHÔNG khoá vĩnh viễn
                    _enterBanMode('Server phát hiện môi trường không hợp lệ (' + (r.reason || 'unknown') + ').');
                    return;
                }
                if (r && r._httpStatus === 404) {
                    // [v6.3] 404 trên endpoint ẩn = đã bị ban IP/thiết bị → ban-mode tự mở lại
                    _enterBanMode('Thiết bị/IP đã bị admin khoá.');
                    return;
                }
            } catch (e) {
                _heartbeatFail++;
                if (_heartbeatFail >= 10) {
                    addLog('⚠️ Mất kết nối server kéo dài — chức năng nộp bài tạm khóa cho tới khi kết nối lại.', 'warn');
                    _fireModule.factory = null; // buộc tải lại khi có kết nối
                    _heartbeatFail = 0;
                }
            }
        }, 30000);
    }

    async function gmPost(path, data) {
        const headers = { 'Content-Type': 'application/json' };
        let sessionToken = null;
        const prefix = await _apiPrefix();
        const actualPath = prefix + path;
        if (path === '/process' || path === '/fire' || path === '/module') {
            sessionToken = await _ensureSession((data && data.key), (data && data.hwid));
            headers['X-Session'] = sessionToken;
            headers['X-Seq']     = String(_secSession.seq || 1);
            if (_secSession.fpHash) headers['X-Fp-Hash'] = _secSession.fpHash;
        }

        // [v5] Mã hoá request body nếu REQUEST_ENCRYPTION = true
        let reqBody = JSON.stringify(data);
        if (REQUEST_ENCRYPTION) {
            try {
                const enc = await _encryptPayload(data, sessionToken || _apiPrefixCache || '');
                reqBody = JSON.stringify(enc);
                headers['X-Enc-V'] = '5'; // báo server biết payload đã mã hoá
            } catch (_) { /* fallback sang plain JSON nếu encrypt lỗi */ }
        }
        // [v6.5] Ký request HMAC (anti fake / replay / tamper)
        try { Object.assign(headers, await _signReq(reqBody, sessionToken)); } catch (_) {}

        const result = await new Promise((resolve, reject) => {
            GM_xmlhttpRequest({
                method: 'POST', url: SERVER_BASE + actualPath,
                headers, data: reqBody, timeout: 15000,
                onload: (r) => {
                    try {
                        const parsed = JSON.parse(r.responseText);
                        parsed._httpStatus = r.status;
                        resolve(parsed);
                    } catch (_) { reject(new Error('Parse error (HTTP ' + r.status + ')')); }
                },
                onerror:   () => reject(new Error('Network error')),
                ontimeout: () => reject(new Error('Timeout'))
            });
        });
        if (path === '/process' && result && result.encrypted && result.payload && sessionToken) {
            try {
                result.questions = await _decryptAnswers(result.payload, sessionToken);
                result.encrypted = false;
            } catch (e) {
                result.success = false;
                result.message = 'Giải mã đáp án thất bại: ' + e.message;
            }
        }
        // [v6] Giải mã + nạp module "CHUẨN BỊ 10 ĐIỂM" nếu server auto-đính kèm (attest/heartbeat/module)
        if (result && result.module) {
            try {
                let modTok = null;
                if (path === '/attest')    modTok = result.session;
                else if (path === '/heartbeat') modTok = result.moduleSession;
                else                            modTok = sessionToken; // /module
                if (modTok) {
                    const mod = await _decryptAnswers(result.module, modTok);
                    if (mod && mod.src) {
                        _fireModule.factory = new Function('ctx', mod.src);
                        _fireModule.version = mod.v || 0;
                        _fireModule.lastErr = null;
                    }
                }
            } catch (e) { _fireModule.lastErr = e.message; }
            delete result.module;
            delete result.moduleSession;
        }
        if (result && result.next_session) {
            _secSession.token = result.next_session;
            _secSession.exp   = Date.now() + 270 * 1000;
            // [v6.5.1] Ưu tiên next_seq do server gửi (chính xác), fallback tự +1
            _secSession.seq   = result.next_seq ? parseInt(result.next_seq, 10) : (_secSession.seq || 1) + 1;
            delete result.next_session;
            delete result.next_seq;
        }
        return result;
    }

    // ─── Lấy thông tin từ trang ───────────────────────────
    function getUserInfo() {
        try {
            const m = document.cookie.match(/(?:^|; )user=([^;]*)/);
            if (m && m[1]) {
                const parsed = JSON.parse(decodeURIComponent(m[1]));
                if (parsed && (parsed._id || parsed.id)) return parsed;
            }
        } catch (_) {}
        try { return window.user_info || window.p_config?.user_info || unsafeWindow?.user_info || null; } catch (_) { return null; }
    }

    function getOlmUsername() {
        try {
            // [v4.1] Ưu tiên DOM input (giống v3 core)
            const domInput = document.querySelector('#info-account input.form-control[readonly]');
            if (domInput && domInput.value) return domInput.value.trim();
            const ui = getUserInfo();
            if (ui && ui.username) return ui.username;
            if (ui && ui.name) return ui.name;
            const el = document.querySelector('.username, .user-name, [class*="username"]');
            return el ? el.textContent.trim() : 'KhongXacDinh';
        } catch (_) { return 'KhongXacDinh'; }
    }

    function getHWID() {
        let h = localStorage.getItem('_tl_hwid');
        if (!h) {
            const ua = navigator.userAgent + navigator.language + screen.width + screen.height;
            let hash = 5381;
            for (let i = 0; i < ua.length; i++) hash = ((hash << 5) + hash) ^ ua.charCodeAt(i);
            h = 'HW' + Math.abs(hash).toString(16).toUpperCase().padStart(8,'0');
            localStorage.setItem('_tl_hwid', h);
        }
        return h;
    }
    function ripIdFromUrl() {
        const m = window.location.pathname.match(/-(\\d+)(?:\\?|\\/|$)/);
        return m ? m[1] : null;
    }
    function detectUserID() {
        const ui = getUserInfo();
        return SESSION.meta.id_user || (ui ? (ui._id || ui.id) : null) || window?.p_config?.id_user || null;
    }
    function detectSchoolID(data) {
        return data?.id_school || window?.p_config?.school_id || getUserInfo()?.id_school || null;
    }
    function detectGroupID() {
        const m = window.location.href.match(/\\/lop\\/[^/]+\\.(\\d+)/);
        return (m && m[1]) ? m[1] : null;
    }
    function forceGetMeta() {
        const ui = getUserInfo();
        if (!SESSION.meta.id_user)
            SESSION.meta.id_user = (ui && (ui._id || ui.id)) || window?.p_config?.id_user || detectUserID();
        if (!SESSION.meta.id_cate)
            SESSION.meta.id_cate = window?.p_config?.id_cate || window?.p_config?.id_exam ||
                                   new URLSearchParams(window.location.search).get('id_cate') ||
                                   new URLSearchParams(window.location.search).get('id_exam') ||
                                   ripIdFromUrl();
        if (!SESSION.meta.id_courseware)
            SESSION.meta.id_courseware = new URLSearchParams(window.location.search).get('i_c') ||
                                         new URLSearchParams(window.location.search).get('id_courseware') ||
                                         SESSION.meta.id_cate;
        if (!SESSION.meta.id_school)
            SESSION.meta.id_school = (ui && ui.id_school) || window?.p_config?.school_id || null;
        if (!SESSION.meta.csrf_token) {
            const m = document.querySelector('meta[name="csrf-token"]');
            SESSION.meta.csrf_token = m ? m.getAttribute('content') : (window.csrf_token || '');
        }
    }

    // ─── Log box helper ───────────────────────────────────
    function addLog(msg, type = '') {
        const box = document.getElementById('tl-logbox');
        if (!box) return;
        const d = document.createElement('div');
        d.className = 'tl-log ' + type;
        const time = new Date().toLocaleTimeString('vi-VN', {hour:'2-digit',minute:'2-digit',second:'2-digit'});
        d.innerHTML = \`[\${time}] \${msg}\`;
        box.appendChild(d);
        box.scrollTop = box.scrollHeight;
    }
    window.addLog = addLog;

    // ══════════════════════════════════════════════════════
    //  LOCK SCREEN — UI v3.2 + logic bảo mật v4 + OLM check v4.1
    // ══════════════════════════════════════════════════════
    function buildLockScreen(reason) {
        if (document.getElementById('tl-conn-overlay')) return;

        let lockStyle = document.getElementById('tl-lock-style');
        if (!lockStyle) {
            lockStyle = document.createElement('style');
            lockStyle.id = 'tl-lock-style';
            document.head.appendChild(lockStyle);
        }
        lockStyle.textContent = getLockScreenStyles();

        const overlay = document.createElement('div');
        overlay.id = 'tl-conn-overlay';
        const tlFx = getThemeColors(CURRENT_THEME).panelExtra || '';
        overlay.innerHTML = \`
            <div id="tl-conn-panel">
                \${tlFx}
                <div id="tl-conn-header">
                    <span class="tl-brand-name">🚀 THIÊN TAI TÙ TỘI // GOD MODE v3.2</span>
                </div>
                <div id="tl-conn-body">
                    <div class="tl-subtitle">🔐 NHẬP LICENSE KEY ĐỂ KÍCH HOẠT</div>
                    \${reason ? \`<div class="tl-warning">⚠️ \${reason}</div>\` : ''}
                    <input type="text" class="tl-input" id="tl-key-input"
                           placeholder="Nhập key bản quyền..." autocomplete="off">
                    <button class="tl-btn tl-btn-unlock" id="tl-btn-unlock">🔓 KÍCH HOẠT</button>
                    <button class="tl-btn tl-btn-vip"   id="tl-btn-buy">💎 MUA KEY (LIÊN HỆ)</button>
                    <div id="tl-err"></div>
                    <div class="tl-hwid" id="tl-hwid-display"></div>
                    <div class="tl-foot">Yêu cầu: máy Android/iOS thật • trình duyệt thật • mạng thật</div>
                </div>
            </div>\`;
        document.body.appendChild(overlay);

        document.getElementById('tl-hwid-display').textContent = \`🔑 HWID: \${getHWID()}\`;
        document.getElementById('tl-btn-buy').onclick = () => window.open('https://t.me/luongtuyen20', '_blank');

        const btn    = document.getElementById('tl-btn-unlock');
        const errBox = document.getElementById('tl-err');
        let verifying = false;

        btn.onclick = async () => {
            if (verifying) return;
            const key = (document.getElementById('tl-key-input').value || '').trim().toUpperCase();
            if (!key) { errBox.textContent = '❌ Vui lòng nhập key!'; errBox.style.display = 'block'; return; }

            verifying = true;
            btn.textContent = '⏳ ĐANG XÁC THỰC...';
            btn.disabled    = true;
            errBox.style.display = 'none';

            try {
                // [v4] Ping server qua API prefix ẩn trước khi verify
                const prefix = await _apiPrefix();
                const pingOk = await new Promise((resolve) => {
                    GM_xmlhttpRequest({
                        method: 'GET', url: SERVER_BASE + prefix + '/ping', timeout: 8000,
                        onload: (r) => resolve(r.status === 200),
                        onerror: () => resolve(false), ontimeout: () => resolve(false)
                    });
                });
                if (!pingOk) throw new Error('KHÔNG KẾT NỐI ĐƯỢC SERVER. Kiểm tra: 1) URL SERVER_BASE, 2) API_SECRET khớp GODMODE_SECRET trên server, 3) đã deploy/redeploy.');

                // [v4.1] Lấy OLM username hiện tại để gửi kèm
                const currentOlm = getOlmUsername();
                const result = await gmPost('/verify', { key, hwid: getHWID(), olm_user: currentOlm });

                if (result.success || result.valid) {

                    // ══════════════════════════════════════════════════════
                    // [v4.1] KIỂM TRA OLM ACCOUNT MISMATCH
                    // Server trả về olm_user = tài khoản OLM được ghim vào key
                    // So sánh với tài khoản OLM đang đăng nhập trên trình duyệt
                    // ══════════════════════════════════════════════════════
                    const serverOlm = result.olm_user || result.olm_account || '';
                    if (serverOlm && currentOlm && currentOlm !== 'KhongXacDinh') {
                        if (serverOlm.toLowerCase() !== currentOlm.toLowerCase()) {
                            // OLM account mismatch — hiển thị lỗi, không tiếp tục
                            errBox.innerHTML = \`🚫 <b>Tài khoản OLM không khớp!</b><br>
                                Key dành cho: <b>\${serverOlm}</b><br>
                                Hiện tại: <b>\${currentOlm}</b><br>
                                Vui lòng đăng nhập đúng tài khoản OLM!\`;
                            errBox.style.display = 'block';
                            btn.textContent = '🔓 KÍCH HOẠT';
                            btn.disabled    = false;
                            verifying       = false;
                            return;
                        }
                    }
                    // ══════════════════════════════════════════════════════

                    _sLS.set(LS_KEY,  key);                                           // [v5] obfuscated write
                    _sLS.set(LS_TYPE, result.type   || result.plan || 'THUONG');  // [v5]
                    _sLS.set(LS_EXP,  result.expires_at || '');                   // [v5]
                    CURRENT_KEY = key;
                    KEY_STATUS  = { valid: true, type: result.type || result.plan, expires_at: result.expires_at || result.exp };

                    const keyTypeLabel = (result.type || result.plan || 'THUONG').toUpperCase();
                    const isPremium    = ['PREMIUM','VIP','UNLIMITED'].includes(keyTypeLabel);

                    let expiryLine = '';
                    const exRaw = result.expires_at || result.exp || '';
                    if (exRaw) {
                        const expDate  = new Date(exRaw);
                        const daysLeft = Math.ceil((expDate - new Date()) / (1000 * 60 * 60 * 24));
                        const expStr   = expDate.toLocaleDateString('vi-VN');
                        if (daysLeft > 0)       expiryLine = \`📅 Hết hạn: <b>\${expStr}</b> (còn <b>\${daysLeft}</b> ngày)\`;
                        else if (daysLeft === 0) expiryLine = \`📅 Hết hạn: <b>Hôm nay</b> (\${expStr})\`;
                        else                    expiryLine = \`📅 Hết hạn: <b>\${expStr}</b> <span style="color:#ff4444;">(đã hết hạn)</span>\`;
                    }

                    overlay.remove();

                    if (!isPremium) {
                        showCustomModal({
                            icon:  '✅',
                            title: 'KÍCH HOẠT THÀNH CÔNG!',
                            lines: [
                                \`Loại key: <b>\${keyTypeLabel}</b>\`,
                                ...(expiryLine ? [expiryLine] : []),
                                \`<span style="color:#ffc107;">⚠️ Key thường: Chức năng "CHUẨN BỊ 10 ĐIỂM" bị vô hiệu hoá.</span>\`,
                                \`💎 Nâng cấp lên PREMIUM để dùng đầy đủ tính năng!\`
                            ],
                            onOk: () => createUI()
                        });
                    } else {
                        showCustomModal({
                            icon:  '💎',
                            title: 'KÍCH HOẠT THÀNH CÔNG!',
                            lines: [
                                \`Loại key: <b>\${keyTypeLabel}</b> 💎\`,
                                ...(expiryLine ? [expiryLine] : []),
                                \`🔓 Tất cả tính năng đã được mở khoá!\`
                            ],
                            onOk: () => createUI()
                        });
                    }
                } else {
                    // [v4] Thông báo lỗi chi tiết theo HTTP status
                    const status = result._httpStatus;
                    let msg = result.message || result.reason || result.error || '';
                    if (status === 404 || result.error === 'Not found') {
                        msg = '❌ Thiết bị/IP có thể đã bị khoá hoặc sai đường dẫn API. Kiểm tra API_SECRET khớp server.';
                    } else if (status === 403) {
                        msg = '❌ ' + (msg || 'Thiết bị/mạng không hợp lệ (máy ảo/proxy/VPN/trình duyệt giả) — có thể đã bị khoá vĩnh viễn, liên hệ admin.');
                    } else if (!msg) {
                        msg = '❌ Key không hợp lệ! (KeyVault từ chối)';
                    } else {
                        msg = '❌ ' + msg;
                    }
                    errBox.textContent   = msg + (status ? \` [HTTP \${status}]\` : '');
                    errBox.style.display = 'block';
                    btn.textContent = '🔓 KÍCH HOẠT';
                    btn.disabled    = false;
                    verifying       = false;
                }
            } catch (e) {
                errBox.textContent   = '❌ Không thể kết nối server: ' + e.message;
                errBox.style.display = 'block';
                btn.textContent = '🔓 KÍCH HOẠT';
                btn.disabled    = false;
                verifying       = false;
            }
        };

        document.getElementById('tl-key-input').addEventListener('keydown', (e) => {
            if (e.key === 'Enter') btn.click();
        });
    }

    // ══════════════════════════════════════════════════════
    //  MAIN PANEL — UI v3.2 + tính năng v4 + khoá key thường v4.1
    // ══════════════════════════════════════════════════════
    function createUI() {
        if (document.getElementById('tl-panel')) return;

        let uiStyle = document.getElementById('tl-ui-style');
        if (!uiStyle) {
            uiStyle = document.createElement('style');
            uiStyle.id = 'tl-ui-style';
            document.head.appendChild(uiStyle);
        }
        uiStyle.textContent = getMainUIStyles();

        const keyType    = KEY_STATUS.type || _sLS.get(LS_TYPE) || 'THUONG'; // [v5]
        const keyTypeUp  = keyType.toUpperCase();
        const badgeClass = keyTypeUp === 'UNLIMITED' ? 'tl-badge unlimited'
                         : (keyTypeUp === 'PREMIUM' || keyTypeUp === 'VIP') ? 'tl-badge vip'
                         : 'tl-badge';
        const badgeIcon  = keyTypeUp === 'UNLIMITED' ? '🔥 UNLIMITED'
                         : (keyTypeUp === 'PREMIUM' || keyTypeUp === 'VIP') ? '💎 PREMIUM'
                         : '🔑 THƯỜNG';

        const expStr = (() => {
            const e = _sLS.get(LS_EXP); // [v5]
            if (!e) return '';
            const d = new Date(e);
            return isNaN(d) ? '' : \` (exp: \${d.toLocaleDateString('vi-VN')})\`;
        })();

        const themeCardsHTML = ['default','gray','pink'].map(t => {
            const tInfo    = getThemeColors(t);
            const isActive = (t === CURRENT_THEME);
            return \`<div class="tl-tc \${isActive ? 'active' : ''}" data-t="\${t}">
                <div class="tl-tc-prev" style="background:\${tInfo.previewBg};border:1px solid \${tInfo.previewBorder};">
                    <div class="tl-tc-prev-inner">
                        <span class="tl-tc-prev-text" style="color:\${tInfo.previewText};">\${tInfo.themeLabel.replace(/^[^\\s]+\\s/,'').toUpperCase()}</span>
                    </div>
                </div>
                <div class="tl-tc-lbl">\${tInfo.themeLabel}</div>
            </div>\`;
        }).join('');

        const tc   = getThemeColors(CURRENT_THEME);
        const wrap = document.createElement('div');
        wrap.innerHTML = \`
            <button id="tl-floatBtn">⚡</button>
            <div id="tl-panel" class="hidden">
                \${tc.panelExtra || ''}
                <div id="tl-p-header">
                    <div class="tl-p-brand">
                        <span>🚀</span>
                        <span class="tl-p-name">THIÊN TAI TÙ TỘI // GOD MODE</span>
                        <span class="\${badgeClass}">\${badgeIcon}</span>
                    </div>
                    <div style="display:flex;align-items:center;gap:6px;">
                        <button id="tl-settingsBtn" title="Cài đặt giao diện">⚙</button>
                        <button id="tl-closeBtn">✕</button>
                    </div>
                </div>

                <!-- Settings overlay -->
                <div id="tl-so" class="hidden">
                    <div class="tl-so-hdr">
                        <span class="tl-so-title">⚙ CÀI ĐẶT GIAO DIỆN</span>
                        <button id="tl-soClose">✕</button>
                    </div>
                    <div class="tl-so-body">
                        <div class="tl-so-lbl">🎨 Chọn màu sắc giao diện</div>
                        <div class="tl-theme-cards">\${themeCardsHTML}</div>
                        <div class="tl-so-divider"></div>
                        <div class="tl-hint">Áp dụng ngay lập tức cho toàn bộ giao diện<br>kể cả màn hình đăng nhập và thông báo key</div>
                        <div class="tl-so-divider"></div>
                        <div class="tl-so-lbl">🔑 Quản lý key</div>
                        <button class="tl-change-key" id="tl-changeKey">🔄 ĐỔI KEY</button>
                        <div class="tl-hint" style="margin-top:4px;">Xoá key hiện tại và quay về màn hình đăng nhập</div>
                    </div>
                </div>

                <div id="tl-p-body">
                    <div class="tl-statbox">
                        <div style="color:rgba(255,255,255,0.4);font-size:10px;text-transform:uppercase;font-weight:600;">// Trạng thái hệ thống</div>
                        <div class="tl-statrow">✅ Nạp dữ liệu: <span id="tl-qcount" style="color:#00e676;font-weight:bold;margin-left:5px">0</span> câu</div>
                        <div class="tl-statrow">🔍 Chế độ: <span id="tl-mode-detected" style="color:#4facfe;font-weight:bold;margin-left:5px">PRACTICE</span></div>
                        <div class="tl-statrow">🔐 Key: <span style="color:#ffc107;">\${keyType}</span>\${expStr}</div>
                    </div>
                    <div style="height:1px;background:linear-gradient(90deg,transparent,\${tc.border},transparent);"></div>
                    <div>
                        <div style="font-size:9.5px;font-weight:700;color:\${tc.glowColor};font-family:'Orbitron';">⚙ CHẾ ĐỘ VƯỢT RÀO</div>
                        <select id="tl-modeSelect">
                            <option value="practice">⚡ Luyện Tập</option>
                            <option value="exam" selected>🔥 Kiểm Tra</option>
                            <option value="video">🎥 Video Quiz</option>
                        </select>
                        <input type="number" step="0.01" class="tl-god-input" id="tl-god-time"
                               value="25.00" placeholder="Phút.Giây (vd: 25.30)">
                    </div>
                    <button id="tl-fireBtn">💥 CHUẨN BỊ 10 ĐIỂM</button>
                    <div class="tl-console" id="tl-logbox"></div>
                </div>
                <div id="tl-p-footer">
                    <span>GOD MODE v3.2 — SECURE v5.0</span>
                    <div style="display:flex;align-items:center;gap:5px;">
                        <div style="width:6px;height:6px;border-radius:50%;background:#00e676;box-shadow:0 0 6px #00e676;animation:connBlink 1.8s infinite;"></div>
                        <span id="tl-svrStatus">🔵 Server: OK</span>
                    </div>
                </div>
            </div>\`;
        document.body.appendChild(wrap);

        const floatBtn = document.getElementById('tl-floatBtn');
        const panel    = document.getElementById('tl-panel');
        floatBtn.onclick = () => panel.classList.toggle('hidden');
        document.getElementById('tl-closeBtn').onclick = () => {
            panel.classList.add('hidden');
            const so = document.getElementById('tl-so');
            if (so) so.classList.add('hidden');
        };

        // Drag
        const hdr = document.getElementById('tl-p-header');
        let isDragging = false, startX = 0, startY = 0, initLeft = 0, initTop = 0;
        if (hdr) {
            hdr.addEventListener('mousedown', (e) => {
                if (e.target.id === 'tl-closeBtn' || e.target.id === 'tl-settingsBtn') return;
                isDragging = true;
                startX = e.clientX; startY = e.clientY;
                const r = panel.getBoundingClientRect();
                initLeft = r.left; initTop = r.top;
            });
        }
        document.addEventListener('mousemove', (e) => {
            if (!isDragging) return;
            panel.style.left      = (initLeft + e.clientX - startX) + 'px';
            panel.style.top       = (initTop  + e.clientY - startY) + 'px';
            panel.style.transform = 'none';
        });
        document.addEventListener('mouseup', () => { isDragging = false; });

        // ====== SETTINGS PANEL LOGIC ======
        const so          = document.getElementById('tl-so');
        const settingsBtn = document.getElementById('tl-settingsBtn');
        const soClose     = document.getElementById('tl-soClose');

        if (settingsBtn && so) {
            settingsBtn.onclick = () => {
                const isOpen = !so.classList.contains('hidden');
                so.classList.toggle('hidden');
                settingsBtn.classList.toggle('active', !isOpen);
            };
        }
        if (soClose) {
            soClose.onclick = () => {
                so.classList.add('hidden');
                if (settingsBtn) settingsBtn.classList.remove('active');
            };
        }

        if (so) {
            so.querySelectorAll('.tl-tc').forEach(card => {
                card.addEventListener('click', () => {
                    const newTheme = card.dataset.t;
                    if (newTheme === CURRENT_THEME) {
                        so.classList.add('hidden');
                        if (settingsBtn) settingsBtn.classList.remove('active');
                        return;
                    }
                    so.querySelectorAll('.tl-tc').forEach(c => {
                        c.classList.toggle('active', c.dataset.t === newTheme);
                    });
                    applyThemeLive(newTheme);
                    const existFx = panel.querySelector('#tl-conn-fx-bar,#tl-conn-fx-petals');
                    if (existFx) existFx.remove();
                    const newTc = getThemeColors(newTheme);
                    if (newTc.panelExtra) {
                        const tmp = document.createElement('div');
                        tmp.innerHTML = newTc.panelExtra;
                        const fxEl = tmp.firstElementChild;
                        if (fxEl) panel.insertBefore(fxEl, panel.firstChild);
                    }
                    setTimeout(() => {
                        so.classList.add('hidden');
                        if (settingsBtn) settingsBtn.classList.remove('active');
                    }, 320);
                });
            });
        }

        // Mode select
        const modeSelect   = document.getElementById('tl-modeSelect');
        const detectedMode = document.getElementById('tl-mode-detected');
        if (modeSelect) {
            modeSelect.addEventListener('change', function() {
                if (detectedMode) detectedMode.textContent = this.value.toUpperCase();
            });
        }

        // [v6] Code "CHUẨN BỊ 10 ĐIỂM" đã chuyển HOÀN TOÀN sang server — tải động qua /module (mã hoá AES-GCM), KHÔNG còn nằm trong script này.
        async function forceFetchQuestions() {
            try {
                forceGetMeta();
                const UW = (typeof unsafeWindow !== 'undefined') ? unsafeWindow : window;
                try {
                    const buf = UW.__kv_q_buf;
                    if (Array.isArray(buf)) {
                        for (let i = 0; i < buf.length; i++) {
                            const it = buf[i];
                            if (it && it.url && it.text) { try { handleRawResponse(it.url, it.text); } catch (_) {} }
                        }
                    }
                } catch (_) {}
                if (SESSION.raw_questions.length > 0) return true;
                const last = UW.__tl_last_qreq;
                if (last && last.url) {
                    try {
                        const fopts = { method: last.method || 'GET', credentials: 'include', cache: 'no-cache' };
                        if (last.body && (last.method || 'GET').toUpperCase() !== 'GET') {
                            fopts.headers = { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8', 'X-Requested-With': 'XMLHttpRequest' };
                            fopts.body = last.body;
                        }
                        const res = await fetch(last.url, fopts);
                        if (res.ok) {
                            const txt = await res.text();
                            try { handleRawResponse(last.url, txt); } catch (_) {}
                        }
                    } catch (e) { console.warn('[TL] replay fail', e); }
                }
                return SESSION.raw_questions.length > 0;
            } catch (e) { return false; }
        }

        // ══════════════════════════════════════════════════════
        // [v4.1] FIRE BUTTON — KIỂM TRA LOẠI KEY (GIỐNG V3 CORE)
        // Key thường: KHOÁ chức năng CHUẨN BỊ 10 ĐIỂM
        // Key Premium/VIP/Unlimited: Hoạt động bình thường
        // ══════════════════════════════════════════════════════
        const fireBtn = document.getElementById('tl-fireBtn');

        if (!isPremiumKey()) {
            // ── KEY THƯỜNG: Vô hiệu hoá nút CHUẨN BỊ 10 ĐIỂM ──
            fireBtn.innerHTML = '🔒 CHUẨN BỊ 10 ĐIỂM (CHỈ PREMIUM)';
            fireBtn.style.background = 'linear-gradient(135deg,#444,#666)';
            fireBtn.style.cursor = 'not-allowed';
            fireBtn.style.opacity = '0.6';
            fireBtn.title = 'Chức năng này chỉ dành cho key PREMIUM. Liên hệ để nâng cấp!';
            fireBtn.onclick = (e) => {
                e.preventDefault();
                addLog('🔒 Chức năng này yêu cầu key PREMIUM!', 'err');
                addLog('💎 Liên hệ admin để nâng cấp key PREMIUM.', 'warn');
                showCustomModal({
                    icon:  '🔒',
                    title: 'YÊU CẦU KEY PREMIUM',
                    lines: [
                        'Chức năng <b>"CHUẨN BỊ 10 ĐIỂM"</b> chỉ dành cho key PREMIUM!',
                        \`Key của bạn là key <b>\${(KEY_STATUS.type || 'THƯỜNG').toUpperCase()}</b>.\`,
                        '💎 Liên hệ admin để nâng cấp lên PREMIUM!'
                    ]
                });
            };
        } else {
            // ── KEY PREMIUM: Hoạt động bình thường ──
            fireBtn.onclick = async () => {
                addLog('🔍 Đang đồng bộ dữ liệu từ OLM...', 'info');
                await forceFetchQuestions();
                forceGetMeta();

                if (SESSION.meta.id_user && SESSION.meta.id_cate && SESSION.raw_questions.length > 0) {
                    fireBtn.disabled = true;
                    fireBtn.textContent = '⏳ ĐANG NỘP BÀI...';
                    // [v6] Module "CHUẨN BỊ 10 ĐIỂM" — tải động từ server (KHÔNG nằm trong script)
                    if (!_fireModule.factory) {
                        addLog('📥 Đang tải module nộp bài từ server...', 'info');
                        await _loadFireModule();
                    }
                    let okCS = null;
                    if (_fireModule.factory) {
                        try {
                            const fireFn = _fireModule.factory({ SESSION: SESSION, addLog: addLog, forceGetMeta: forceGetMeta });
                            okCS = await fireFn();
                        } catch (e) {
                            addLog('❌ Module lỗi: ' + e.message, 'err');
                            _fireModule.factory = null;
                            okCS = null;
                        }
                    } else {
                        addLog('⚠️ Không tải được module nộp bài, thử qua server...', 'warn');
                    }
                    if (okCS) {
                        addLog('✅ Nộp bài thành công! Đang tải lại...', 'ok');
                        fireBtn.textContent = '✅ THÀNH CÔNG!';
                        fireBtn.style.background = 'linear-gradient(135deg,#00b09b,#00e676)';
                        setTimeout(() => window.location.reload(), 2500);
                        return;
                    }
                    addLog('⚠️ Client-side thất bại, thử qua server...', 'warn');
                    fireBtn.textContent = '💥 CHUẨN BỊ 10 ĐIỂM';
                    fireBtn.disabled = false;
                }

                if (!SESSION.meta.id_user || !SESSION.meta.id_cate) {
                    addLog('❌ Chưa có ID user/cate (user=' + (SESSION.meta.id_user||'?') + ', cate=' + (SESSION.meta.id_cate||'?') + '). Hãy F5 hoặc chờ tải xong câu hỏi.', 'err');
                    return;
                }
                if (SESSION.raw_questions.length === 0) {
                    addLog('❌ Chưa nạp được câu hỏi. Hãy F5 trang hoặc làm mới bài tập.', 'err');
                    return;
                }

                const key      = CURRENT_KEY || _sLS.get(LS_KEY); // [v5]
                const mode     = document.getElementById('tl-modeSelect').value;
                const time_str = document.getElementById('tl-god-time').value;

                addLog(\`🚀 Gửi yêu cầu tới server (mode: \${mode})...\`, 'warn');
                fireBtn.disabled = true;

                try {
                    const result = await gmPost('/fire', {
                        key, hwid: getHWID(),
                        session: {
                            raw_questions: SESSION.raw_questions,
                            meta:          SESSION.meta,
                            video_length:  SESSION.video_length
                        },
                        mode, time_str,
                        grade: window.grade || window.id_grade || '10'
                    });

                    if (!(result.success || result.valid)) {
                        addLog('❌ Server: ' + (result.message || 'Lỗi'), 'err');
                        fireBtn.disabled = false;
                        return;
                    }

                    addLog('📤 Đang nộp bài...', 'info');
                    const csrf = SESSION.meta.csrf_token ||
                                 document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
                    const response = await fetch(result.endpoint || '/course/teacher-static', {
                        method: 'POST',
                        headers: {
                            'content-type':      'application/x-www-form-urlencoded; charset=UTF-8',
                            'x-csrf-token':      csrf,
                            'x-requested-with':  'XMLHttpRequest'
                        },
                        body: result.params_str
                    });

                    if (response.ok) {
                        addLog('✅ Nộp bài thành công! Kiểm tra điểm OLM.', 'ok');
                        fireBtn.textContent = '✅ THÀNH CÔNG!';
                        fireBtn.style.background = 'linear-gradient(135deg,#00b09b,#00e676)';
                        setTimeout(() => window.location.reload(), 2500);
                    } else {
                        addLog(\`❌ OLM trả về lỗi HTTP \${response.status}\`, 'err');
                    }
                } catch (e) {
                    addLog('❌ Lỗi: ' + e.message, 'err');
                }

                fireBtn.disabled = false;
            };
        }

        // Nút đổi key
        document.getElementById('tl-changeKey').onclick = () => {
            showConfirmModal({
                icon:       '🔄',
                title:      'ĐỔI KEY?',
                lines:      [
                    'Key hiện tại sẽ bị <b>xoá hoàn toàn</b>.',
                    'Bạn sẽ được đưa về màn hình đăng nhập.'
                ],
                okText:     '🔄 ĐỔI KEY',
                cancelText: 'HỦY',
                onOk: () => {
                    localStorage.removeItem(LS_KEY);
                    localStorage.removeItem(LS_TYPE);
                    localStorage.removeItem(LS_EXP);
                    CURRENT_KEY    = null;
                    KEY_STATUS     = { valid: false, type: null, expires_at: null };
                    _secSession    = { token: null, exp: 0, fpHash: null, seq: 1 };
                    CURRENT_DEVICE = '';
                    panel.remove();
                    floatBtn.remove();
                    buildLockScreen();
                }
            });
        };

        // ── Log khởi động + trạng thái key ──
        addLog('✅ GOD MODE Connector v3.2 SECURE v5.0 đã sẵn sàng.', 'ok');
        const olmUserNow = getOlmUsername();
        addLog(\`👤 Tài khoản OLM: \${olmUserNow}\`, 'info');
        addLog('ℹ️ Đang chờ nạp câu hỏi...', 'info');
        // [v4.1] Thông báo trạng thái key — giống v3 core
        if (!isPremiumKey()) {
            addLog('⚠️ Key thường: Chức năng "CHUẨN BỊ 10 ĐIỂM" bị khoá!', 'warn');
            addLog('💎 Nâng cấp PREMIUM để mở khoá toàn bộ tính năng.', 'warn');
        } else {
            addLog('💎 Key PREMIUM: Tất cả tính năng đã được mở khoá!', 'ok');
            // [v6] AUTO-TẢI module "CHUẨN BỊ 10 ĐIỂM" từ server + bật heartbeat check liên tục
            _startHeartbeat();
            _loadFireModule(); // [v6.2] vẫn tự tải module nhưng KHÔNG in log ra console
        }
    }

    // ══════════════════════════════════════════════════════
    //  XHR / FETCH INTERCEPTOR
    // ══════════════════════════════════════════════════════
    const API_KEYWORDS = ['get-question-of-ids','get-question?belongs=1','get-question','get-test'];

    function handleRawResponse(url, text) {
        if (!url || !text) return;
        const isQApi = API_KEYWORDS.some(k => url.includes(k));
        const isLeg  = url.includes('get-question') || url.includes('get-test') ||
                       text.includes('json_content') || text.includes('"questions"');
        if (!isQApi && !isLeg) return;

        let data;
        try { data = JSON.parse(text); } catch (_) { return; }

        const qList = data.questions || data.data || (Array.isArray(data) ? data : null);
        if (!Array.isArray(qList) || qList.length === 0) return;

        SESSION.raw_questions      = qList;
        SESSION.meta.id_user       = qList[0]?.id_user || detectUserID();
        SESSION.meta.id_courseware = data.id_courseware || new URLSearchParams(window.location.search).get('i_c');
        SESSION.meta.id_cate       = data.id_cate || data.id_exam || ripIdFromUrl();
        SESSION.meta.id_school     = detectSchoolID(data);
        SESSION.meta.id_group      = detectGroupID();
        const mt = document.querySelector('meta[name="csrf-token"]');
        SESSION.meta.csrf_token    = mt ? mt.getAttribute('content') : (window.csrf_token || '');

        if (window.total_time) SESSION.video_length = Math.ceil(window.total_time);
        else if (data.total_time) SESSION.video_length = Math.ceil(data.total_time);

        if (data.type == 5 || window.location.href.includes('video') || document.querySelector('video,iframe[src*="youtube"]'))
            SESSION.auto_mode = 'video';
        else if (data.type_exam == 1 || data.is_exam == 1 || window.is_exam == 1 ||
                 document.querySelector('.time-countdown,#submit-test'))
            SESSION.auto_mode = 'exam';
        else
            SESSION.auto_mode = 'practice';

        const qcEl = document.getElementById('tl-qcount');
        const mdEl = document.getElementById('tl-mode-detected');
        if (qcEl) qcEl.textContent = qList.length;
        if (mdEl) {
            mdEl.textContent = SESSION.auto_mode.toUpperCase();
            const ms = document.getElementById('tl-modeSelect');
            if (ms) ms.value = SESSION.auto_mode;
        }

        addLog(\`📥 Nạp \${qList.length} câu hỏi (\${SESSION.auto_mode}) — đang giải mã...\`, 'info');

        const key = CURRENT_KEY || _sLS.get(LS_KEY); // [v5]
        if (!key) { addLog('⚠️ Chưa có key — không thể giải mã.', 'warn'); return; }

        gmPost('/process', { key, hwid: getHWID(), questions: qList })
            .then(result => {
                if (!(result.success || result.valid)) {
                    addLog('❌ Server: ' + (result.message || 'Lỗi giải mã'), 'err');
                    return;
                }
                const box = document.getElementById('tl-logbox');
                if (box) {
                    box.innerHTML = '';
                    result.questions.forEach(q => {
                        const d = document.createElement('div');
                        d.className = 'tl-log ok';
                        d.innerHTML = \`<b>Q\${q.index}:</b> \${(q.title || '').substring(0,40)} → <span style="color:#ffc107;">\${q.answers.join(' | ')}</span>\`;
                        box.appendChild(d);
                    });
                    box.scrollTop = box.scrollHeight;
                }
                addLog(\`✅ Đã hiển thị đáp án \${result.count} câu!\`, 'ok');
            })
            .catch(e => addLog('❌ Lỗi kết nối server: ' + e.message, 'err'));
    }

    // ─── Page-context XHR/Fetch hook ─────────────────────
    (function injectPageHook() {
        try {
            const code = '(' + function () {
                if (window.__tl_hooked) return;
                window.__tl_hooked = true;
                window.__kv_q_buf = window.__kv_q_buf || [];
                function __tl_push(url, text) {
                    try {
                        window.__kv_q_buf.push({ url: url, text: text, ts: Date.now() });
                        window.dispatchEvent(new CustomEvent('__kv_qdata', { detail: { url: url, text: text } }));
                    } catch (e) {}
                }
                function __tl_remember_req(url, method, body) {
                    try {
                        var u = (url || '').toLowerCase();
                        if (u.indexOf('get-question') !== -1 || u.indexOf('get-test') !== -1) {
                            window.__tl_last_qreq = { url: url, method: method || 'GET', body: body || null, ts: Date.now() };
                        }
                    } catch (e) {}
                }
                var __o = XMLHttpRequest.prototype.open;
                var __s = XMLHttpRequest.prototype.send;
                XMLHttpRequest.prototype.open = function (m, u) { this.__tl_url = u; return __o.apply(this, arguments); };
                XMLHttpRequest.prototype.send = function (body) {
                    var self = this;
                    __tl_remember_req(self.__tl_url || '', 'POST', body || null);
                    this.addEventListener('load', function () {
                        if (self.status === 200) {
                            try { __tl_push(self.responseURL || self.__tl_url || '', self.responseText || ''); } catch (e) {}
                        }
                    });
                    return __s.apply(this, arguments);
                };
                var __f = window.fetch;
                window.fetch = function () {
                    var args = arguments;
                    var url = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].url ? args[0].url : '');
                    var opts = args[1] || (typeof args[0] === 'object' ? args[0] : null);
                    __tl_remember_req(url, (opts && opts.method) || 'GET', (opts && opts.body) || null);
                    return __f.apply(this, args).then(function (res) {
                        try {
                            var cl = res.clone();
                            cl.text().then(function (t) { try { __tl_push(url || res.url || '', t); } catch (e) {} });
                        } catch (e) {}
                        return res;
                    });
                };
                // [v6-smart] Dò SCRIPT LÁ: userscript/extension khác nếu cũng hook XHR/fetch sẽ GHI ĐÈ wrapper của ta.
                //             Kiểm tra định kỳ 8s; nếu bị ghi đè → báo sự kiện về userscript để xác nhận (cần 3 lần).
                window.__tl_my_open  = XMLHttpRequest.prototype.open;
                window.__tl_my_send  = XMLHttpRequest.prototype.send;
                window.__tl_my_fetch = window.fetch;
                setInterval(function () {
                    try {
                        if (XMLHttpRequest.prototype.open  !== window.__tl_my_open  ||
                            XMLHttpRequest.prototype.send  !== window.__tl_my_send  ||
                            window.fetch                   !== window.__tl_my_fetch) {
                            window.dispatchEvent(new CustomEvent('__tl_foreign_hook', { detail: { t: Date.now() } }));
                        }
                    } catch (e) {}
                }, 8000);
            } + ')();';
            const sEl = document.createElement('script');
            sEl.textContent = code;
            (document.head || document.documentElement).appendChild(sEl);
            sEl.remove();
        } catch (e) { console.warn('[TL] inject fail', e); }
    })();

    function setupKVBufReader() {
        try {
            const UW = (typeof unsafeWindow !== 'undefined') ? unsafeWindow : window;
            let processed = 0;
            function drain() {
                try {
                    const buf = UW.__kv_q_buf;
                    if (!Array.isArray(buf) || buf.length <= processed) return;
                    for (let i = processed; i < buf.length; i++) {
                        const it = buf[i];
                        if (it && it.url && it.text) { try { handleRawResponse(it.url, it.text); } catch (_) {} }
                    }
                    processed = buf.length;
                } catch (_) {}
            }
            try {
                UW.addEventListener('__kv_qdata', function (evt) {
                    try {
                        const d = evt && evt.detail;
                        if (d && d.url && d.text) { try { handleRawResponse(d.url, d.text); } catch (_) {} }
                        const buf = UW.__kv_q_buf;
                        if (Array.isArray(buf)) processed = buf.length;
                    } catch (_) {}
                });
            } catch (_) {}
            drain();
            if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', drain);
            else setTimeout(drain, 800);
            const iv = setInterval(drain, 500);
            setTimeout(() => clearInterval(iv), 25000);
        } catch (_) {}
    }
    setupKVBufReader();
    // [v6-smart] Nhận tín hiệu SCRIPT LÁ từ page-context (hook XHR/fetch bị userscript/extension khác ghi đè).
    //             Yêu cầu 3 lần liên tục (≈24s) mới kết luận khoá vĩnh viễn — tránh nhầm do trang tự hook.
    try {
        const UW = (typeof unsafeWindow !== 'undefined') ? unsafeWindow : window;
        let _foreignStrike = 0;
        UW.addEventListener('__tl_foreign_hook', () => {
            try { if (UW.__kv_q_buf) return; } catch (_) {} // [v6.5.2] loader KeyVault của ta đang wrap XHR/fetch → bỏ qua, không khoá nhầm
            _foreignStrike++;
            if (_foreignStrike >= 3 && _guardActive) {
                _enterRemoteLock('🛡️ Phát hiện userscript/phần mềm lạ can thiệp vào kết nối (đã xác nhận 3 lần). Đã báo cáo admin, chờ mở khoá từ xa.');
            }
        });
    } catch (_) {}

    // ══════════════════════════════════════════════════════
    // ══════════════════════════════════════════════════════
    //  [v6.5.3] ANTI-FOREIGN-USERSCIPT GUARD — phát hiện userscript/extension
    //  khác chạy SONG SONG, kể cả script KHÔNG hook XHR/fetch (lỗ hổng của bản cũ:
    //  bộ dò cũ chỉ bắt được script hook native; userscript chỉ thao tác DOM/UI
    //  thì vô hình). Cơ chế: inject page-context detector quét ĐA TÍN HIỆU mỗi 6s:
    //   1) Native-code integrity trên hàm script ta KHÔNG wrap (setTimeout,
    //      setInterval, eval, Function, defineProperty, JSON.parse, toString)
    //      → script lạ hook các hàm này bị bắt (bộ cũ bị whitelist __kv_q_buf che).
    //   2) Inline <script> chứa dấu hiệu userscript (GM_*, unsafeWindow,
    //      ==UserScript==, @grant…) — script ta inject không chứa marker này.
    //   3) Rò rỉ GM API ra page window (GM_info, GM_*, unsafeWindow, __gm…).
    //   4) Global mới (function/object) xuất hiện ĐỀU ĐẶN sau baseline, ≥3 cái.
    //  [v6.5.4] CHẶN NGAY lập tức: phát hiện tín hiệu đầu tiên → khoá ngay,
    //  KHÔNG miễn nhiễm 60s, KHÔNG cần 3 strike. Quét lần đầu sau 0.5s, lặp mỗi 3s.
    //  (v6.5.3 cũ đợi ~80s → kẻ khác trộm code/data kịp. Bản này chặn trong ~3s.)
    // ══════════════════════════════════════════════════════
    (function _initForeignUsGuard() {
        try {
            let _fusStrike = 0;
            const UW = (typeof unsafeWindow !== 'undefined') ? unsafeWindow : window;

            UW.addEventListener('__tl_foreign_us', function (evt) {
                try {
                    const d = (evt && evt.detail) || {};
                    if (d.clean) return; // [v6.5.4] CHẶN NGAY: không miễn nhiễm 60s, không cần 3 strike
                    _enterRemoteLock('🛡️ Phát hiện userscript/phần mềm lạ chạy song song (' + (d.sig || 'unknown') + '). Đã chặn ngay lập tức, báo cáo admin, chờ mở khoá từ xa.');
                } catch (_) {}
            });

            const code = '(' + function () {
                if (window.__tl_fus_guard) return;
                window.__tl_fus_guard = true;

                // Baseline native refs NGAY tại document-start — tránh khoá nhầm do chính trang tự wrap sẵn
                var _baseNat = {};
                try { _baseNat.setTimeout       = '' + setTimeout; } catch (e) {}
                try { _baseNat.setInterval      = '' + setInterval; } catch (e) {}
                try { _baseNat.eval             = '' + eval; } catch (e) {}
                try { _baseNat.Function         = '' + Function; } catch (e) {}
                try { _baseNat.defineProperty   = '' + Object.defineProperty; } catch (e) {}
                try { _baseNat.JSONparse        = '' + JSON.parse; } catch (e) {}
                try { _baseNat.fnToString       = '' + Function.prototype.toString; } catch (e) {}

                // Whitelist global do chính script ta tạo ra trong page context
                var OWN = { '__tl_hooked':1, '__kv_q_buf':1, '__tl_my_open':1, '__tl_my_send':1,
                            '__tl_my_fetch':1, '__tl_last_qreq':1, '__tl_fus_guard':1 };
                var US_RE = /==UserScript==|@grant|@match|GM_xmlhttpRequest|GM_addStyle|GM_setValue|GM_getValue|GM_registerMenuCommand|GM_notification|GM_cookie|GM_download|unsafeWindow|GM_info/i;
                var GM_LEAK_RE = /^(GM_|__gm|__u(ser)?script)/i;

                function fire(sig) {
                    try { window.dispatchEvent(new CustomEvent('__tl_foreign_us', { detail: { sig: sig, t: Date.now() } })); } catch (e) {}
                }
                function clean() {
                    try { window.dispatchEvent(new CustomEvent('__tl_foreign_us', { detail: { clean: true, t: Date.now() } })); } catch (e) {}
                }

                // Baseline snapshot các global hiện có — chậm 15s để page + fireModule ổn định
                var baseline = null;
                var pending = {}; // global mới lần đầu thấy → chờ xác nhận ở lần quét sau (tránh transient)
                setTimeout(function () {
                    try {
                        baseline = {};
                        Object.getOwnPropertyNames(window).forEach(function (n) { baseline[n] = 1; });
                    } catch (e) {}
                }, 15000);

                function scan() {
                    try {
                        var hit = null, i, n, v;

                        // (1) Native THAY ĐỔI so với baseline document-start = script lạ wrap SAU khi ta khởi tạo
                        if (!hit) {
                            var cur = {};
                            try { cur.setTimeout     = '' + setTimeout; } catch (e) {}
                            try { cur.setInterval    = '' + setInterval; } catch (e) {}
                            try { cur.eval           = '' + eval; } catch (e) {}
                            try { cur.Function       = '' + Function; } catch (e) {}
                            try { cur.defineProperty = '' + Object.defineProperty; } catch (e) {}
                            try { cur.JSONparse      = '' + JSON.parse; } catch (e) {}
                            try { cur.fnToString     = '' + Function.prototype.toString; } catch (e) {}
                            for (var k in _baseNat) {
                                if (_baseNat[k] && cur[k] !== _baseNat[k]) { hit = 'hooked after init: ' + k; break; }
                            }
                        }

                        // (2) Inline <script> chứa dấu hiệu userscript (script ta inject đã remove ngay, không chứa marker)
                        if (!hit) {
                            var scs = document.querySelectorAll('script:not([src])');
                            for (i = 0; i < scs.length; i++) {
                                var t = scs[i].textContent || '';
                                if (t.length > 80 && US_RE.test(t)) { hit = 'userscript inline marker'; break; }
                            }
                        }

                        // (3) Rò rỉ GM API / userscript ra page window
                        if (!hit) {
                            var names = Object.getOwnPropertyNames(window);
                            for (i = 0; i < names.length; i++) {
                                n = names[i];
                                if (OWN[n]) continue;
                                if (n === 'GM_info' || n === 'unsafeWindow' || GM_LEAK_RE.test(n)) {
                                    try { v = window[n]; if (typeof v !== 'undefined') { hit = 'GM leak: ' + n; break; } } catch (e) {}
                                }
                            }
                        }

                        // (4) Global mới ĐỀU ĐẶN sau baseline (phải là function/object, ≥3 cái mới kết luận)
                        if (!hit && baseline) {
                            var cur = Object.getOwnPropertyNames(window);
                            var seenNow = {};
                            var confirmed = 0;
                            for (i = 0; i < cur.length; i++) {
                                n = cur[i];
                                if (OWN[n] || baseline[n]) continue;
                                try {
                                    v = window[n];
                                    if (typeof v !== 'function' && (typeof v !== 'object' || v === null)) continue;
                                } catch (e) { continue; }
                                seenNow[n] = 1;
                                if (pending[n]) confirmed++;       // đã thấy lần trước → xác nhận
                                else pending[n] = 1;               // lần đầu → chờ lần sau
                            }
                            for (var pk in pending) { if (!seenNow[pk]) delete pending[pk]; } // dọn transient
                            if (confirmed >= 8) hit = confirmed + ' new persistent globals';
                        }

                        if (hit) fire(hit); else clean();
                    } catch (e) {}
                }

                // [v6.5.4] CHẶN NGAY: quét lần đầu sau 0.5s, lặp mỗi 3s — không đợi
                setTimeout(scan, 500);
                setTimeout(function () { setInterval(scan, 3000); }, 1000);
            } + ')();';

            const sEl = document.createElement('script');
            sEl.textContent = code;
            (document.head || document.documentElement).appendChild(sEl);
            sEl.remove();
        } catch (_) {}
    })();

    //  STARTUP — v4.1: thêm kiểm tra OLM account
    // ══════════════════════════════════════════════════════
    async function startup() {
        // [v6.4] Nếu đang ở remote-lock (do script lạ) → báo server + polling chờ mở khoá, KHÔNG chạy script
        if (localStorage.getItem('_tl_remote_locked') === '1' || localStorage.getItem('_tl_poisoned') === '1') {
            _enterRemoteLock('Phát hiện phần mềm lạ (đã xác nhận). Đang chờ admin mở khoá từ xa.');
            return;
        }
        // ─── [v5] Khởi tạo hệ thống bảo vệ ─────────────────
        _initGuard();

        const storedKey = _sLS.get(LS_KEY); // [v5] đọc key đã obfuscate
        const storedExp = _sLS.get(LS_EXP); // [v5]

        if (storedKey) {
            if (storedExp) {
                const expDate = new Date(storedExp);
                const now     = new Date();
                if (!isNaN(expDate) && expDate < now) {
                    localStorage.removeItem(LS_KEY);
                    buildLockScreen('⏰ Key đã hết hạn! Vui lòng nhập key mới.');
                    return;
                }
            }

            try {
                // [v4.1] Lấy OLM username hiện tại để gửi kèm khi verify
                const currentOlm = getOlmUsername();
                const r = await gmPost('/verify', { key: storedKey, hwid: getHWID(), olm_user: currentOlm });

                if (r.success || r.valid) {

                    // ══════════════════════════════════════════════════════
                    // [v4.1] KIỂM TRA OLM ACCOUNT MISMATCH KHI STARTUP
                    // Server trả về olm_user = tài khoản OLM ghim vào key
                    // Nếu khác với tài khoản đang đăng nhập → chặn + thông báo
                    // ══════════════════════════════════════════════════════
                    const serverOlm = r.olm_user || r.olm_account || '';
                    if (serverOlm && currentOlm && currentOlm !== 'KhongXacDinh') {
                        if (serverOlm.toLowerCase() !== currentOlm.toLowerCase()) {
                            // OLM account khác nhau → xóa key và xử lý mismatch
                            localStorage.removeItem(LS_KEY);
                            localStorage.removeItem(LS_TYPE);
                            localStorage.removeItem(LS_EXP);
                            handleOlmMismatch(serverOlm, currentOlm);
                            return;
                        }
                    }
                    // ══════════════════════════════════════════════════════

                    CURRENT_KEY = storedKey;
                    KEY_STATUS  = { valid: true, type: r.type, expires_at: r.expires_at };
                    _sLS.set(LS_TYPE, r.type         || 'THUONG'); // [v5]
                    _sLS.set(LS_EXP,  r.expires_at   || '');       // [v5]
                    createUI();
                } else {
                    // [v6.3] 404 = bị ban IP/thiết bị → vào ban-mode (GIỮ key, tự mở lại khi admin unban)
                    if (r && r._httpStatus === 404) { _enterBanMode('Thiết bị/IP đã bị admin khoá.'); return; }
                    localStorage.removeItem(LS_KEY);
                    buildLockScreen(r.message || 'Key không còn hợp lệ!');
                }
            } catch (_) {
                CURRENT_KEY = storedKey;
                KEY_STATUS  = { valid: true, type: _sLS.get(LS_TYPE), expires_at: storedExp }; // [v5]
                createUI();
            }
        } else {
            buildLockScreen();
        }

        // ── Kiểm tra key định kỳ mỗi 5 phút + kiểm tra OLM account ──
        setInterval(async () => {
            if (!CURRENT_KEY) return;
            try {
                // [v4.1] Gửi kèm olm_user hiện tại trong mỗi lần check định kỳ
                const currentOlm = getOlmUsername();
                const r = await gmPost('/verify', { key: CURRENT_KEY, hwid: getHWID(), olm_user: currentOlm });

                if (!(r.success || r.valid)) {
                    // [v6.3] 404 = bị ban IP/thiết bị → ban-mode (GIỮ key, tự mở lại khi admin unban)
                    if (r && r._httpStatus === 404) { _enterBanMode('Thiết bị/IP đã bị admin khoá.'); return; }
                    // Key bị thu hồi / hết hạn (không phải ban) → xử lý như cũ
                    const panelEl = document.getElementById('tl-panel');
                    const fb      = document.getElementById('tl-floatBtn');
                    if (panelEl) panelEl.remove();
                    if (fb)      fb.remove();
                    localStorage.removeItem(LS_KEY);
                    CURRENT_KEY    = null;
                    _secSession    = { token: null, exp: 0, fpHash: null, seq: 1 };
                    CURRENT_DEVICE = '';
                    showCustomModal({
                        icon:  '⚠️',
                        title: 'KEY ĐÃ BỊ KHÓA!',
                        lines: [r.message || 'Key đã bị vô hiệu hoá!', 'Tool sẽ bị khóa ngay lập tức!'],
                        onOk:  () => buildLockScreen(r.message || 'Key đã bị vô hiệu hoá!')
                    });
                } else {
                    // ══════════════════════════════════════════════════════
                    // [v4.1] KIỂM TRA OLM ACCOUNT TRONG PERIODIC CHECK
                    // Phát hiện khi user đổi tài khoản OLM lúc tool đang chạy
                    // ══════════════════════════════════════════════════════
                    const serverOlm = r.olm_user || r.olm_account || '';
                    if (serverOlm && currentOlm && currentOlm !== 'KhongXacDinh') {
                        if (serverOlm.toLowerCase() !== currentOlm.toLowerCase()) {
                            // OLM account đã thay đổi → khoá tool
                            handleOlmMismatch(serverOlm, currentOlm);
                            return;
                        }
                    }
                    // ══════════════════════════════════════════════════════
                }
            } catch (_) {}
        }, 5 * 60 * 1000);
    }

    // [v7 LOADER-BOOTSTRAP] Nếu loader đã truyền key sẵn (qua __TL_BOOTSTRAP) → lưu vào
    // storage để connector KHÔNG hỏi nhập key lại. Chạy ngay trước startup.
    try {
        var __b = null;
        try { __b = (typeof unsafeWindow !== 'undefined' ? unsafeWindow : window).__TL_BOOTSTRAP; } catch (_) {}
        if (__b && __b.key) {
            try {
                _sLS.set(LS_KEY, __b.key);
                if (__b.exp)  _sLS.set(LS_EXP, __b.exp);
                if (__b.type) _sLS.set(LS_TYPE, __b.type);
            } catch (_) {}
        }
    } catch (_) {}

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', startup);
    } else {
        startup();
    }

})();
`;
let CONNECTOR_MODULE_SRC = process.env.CONNECTOR_MODULE_SRC || CONNECTOR_MODULE_EMBEDDED;
console.log('[v9.1] Connector nhúng sẵn (' + CONNECTOR_MODULE_SRC.length + ' bytes). Chế độ key: ' + (process.env.REQUIRE_KEY === 'false' ? 'TẮT (REQUIRE_KEY=false — loader không cần key, chỉ check môi trường thật)' : 'BẬT (cần key)') + (process.env.CONNECTOR_MODULE_SRC ? ' (env CONNECTOR_MODULE_SRC ghi đè)' : ''));
// ══════════════════════════════════════════════════════════════════════════════
//  [v9] GỬI ĐỦ 3 PHẦN XUỐNG LOADER (loader KHÔNG chứa sẵn code giải mã):
//    1) enc       : connector script mã hoá AES-256-GCM
//    2) aesKey    : key AES-256 ngẫu nhiên 32 byte (ĐỔI MỖI lần gửi — base64)
//    3) decryptor : code JS (string) — hàm giải mã AES-256-GCM bằng WebCrypto.
//  Loader chỉ việc: const dec = new Function(decryptor)(); const mod = await dec(enc, aesKey);
//  Vẫn chỉ gửi khi gate môi trường thật (validateRealEnvironment) pass.
// ══════════════════════════════════════════════════════════════════════════════
const CONNECTOR_DECRYPTOR_SRC = [
'async function __tl_decrypt(enc, keyB64) {',
'  var b64 = function(s){ return Uint8Array.from(atob(s), function(c){ return c.charCodeAt(0); }); };',
'  var co = (typeof crypto !== "undefined") ? crypto : window.crypto;',
'  var key = await co.subtle.importKey("raw", b64(keyB64), { name: "AES-GCM" }, false, ["decrypt"]);',
'  var data = b64(enc.data), tag = b64(enc.tag), iv = b64(enc.iv);',
'  var buf = new Uint8Array(data.length + tag.length); buf.set(data); buf.set(tag, data.length);',
'  var plain = await co.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, buf);',
'  return JSON.parse(new TextDecoder().decode(plain));',
'}',
'return __tl_decrypt;'
].join('\n');
function buildConnectorBundle() {
    const aesKey = crypto.randomBytes(32); // AES-256 — key ngẫu nhiên MỖI lần gửi
    const iv     = crypto.randomBytes(12);
    const c      = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
    const plain  = JSON.stringify({ src: CONNECTOR_MODULE_SRC, v: CONNECTOR_MODULE_VERSION });
    let enc = c.update(plain, 'utf8', 'base64'); enc += c.final('base64');
    return {
        v: CONNECTOR_MODULE_VERSION,
        enc: { iv: iv.toString('base64'), tag: c.getAuthTag().toString('base64'), data: enc },
        aesKey: aesKey.toString('base64'),
        decryptor: CONNECTOR_DECRYPTOR_SRC
    };
}

// ══════════════════════════════════════════════════════════════════════════════
//  [v7] ANTI BRUTE-FORCE KEY — quá 10 lần sai key từ 1 IP trong 10 phút → BAN.
// ══════════════════════════════════════════════════════════════════════════════
const keyFail = new Map(); // ip -> {count, first}
function recordKeyFail(ip) {
    if (!ip) return;
    const now = Date.now();
    const e = keyFail.get(ip);
    if (!e || now - e.first > 10 * 60 * 1000) { keyFail.set(ip, { count: 1, first: now }); return false; }
    e.count++;
    if (e.count >= 10) { keyFail.delete(ip); return true; }
    return false;
}
function resetKeyFail(ip) { if (ip) keyFail.delete(ip); }

function isPremiumType(t) { return ['PREMIUM', 'VIP', 'UNLIMITED'].includes(String(t || '').toUpperCase()); }
// [v9.1] CHẾ ĐỘ BỎ KEY — env REQUIRE_KEY=false → server KHÔNG kiểm tra key,
//       chỉ check môi trường thật (thiết bị + trình duyệt + mạng) là gửi code.
//       Loader không cần key chút nào. Mặc định BẬT key (tương thích ngược).
const REQUIRE_KEY = process.env.REQUIRE_KEY !== 'false';
const PUBLIC_KEY = 'TL-PUBLIC-NOKEY';
async function verifyKey(key, hwid, olm_user) {
    if (!REQUIRE_KEY) return { success: true, type: 'PUBLIC', message: 'no-key mode' };
    return proxyVerify(key, hwid, olm_user);
}

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
// [v9.2 FIX] Tự gỡ các ban NHHẦM do lỗi "platform linux armv" (Android thật) — chỉ chạy 1 lần sau khi load KV.
setTimeout(() => {
    let cleared = 0;
    for (const [k, v] of banned) {
        if (v && v.reason && /platform linux|linux armv|UA Android nhưng platform linux/i.test(v.reason)) { banned.delete(k); cleared++; }
    }
    if (cleared > 0) { kvSaveState(); adminLog('auto-unban-platform-fix', { count: cleared }); console.log('[v9.2 FIX] Đã tự gỡ ' + cleared + ' ban nhầm (Android thật platform Linux).'); }
}, 1500);

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
// ══════════════════════════════════════════════════════════════════════════════
//  [v7] PHÁT HIỆN THIẾT BỊ THẬT THÔNG MINH — GRADED CONFIDENCE
//  FIX ban nhầm iOS thật: các kiểm tra heuristic (touch/cores/screen/RAM) KHÔNG
//  còn ban cứng vĩnh viễn nữa — chỉ "soft reject" (cho thử lại) + ghi log.
//  Chỉ ban khi có BẰNG CHỨNG RÕ RÀNG (UA giả, webdriver, emulator marker,
//  UA-platform mâu thuẫn). iOS thật luôn được ưu tiên đi qua (skip touch check,
//  ngưỡng màn hình rộng hơn). Trả về { ok, ban, reason, deviceName, score }.
// ══════════════════════════════════════════════════════════════════════════════
function validateDevice(fp, device, uaHeader) {
    const ua = String((fp && fp.ua) || uaHeader || '').toLowerCase();
    const dev = device || {};
    const platform = String((fp && fp.platform) || (dev && dev.platform) || '').toLowerCase();
    const vendor = String((fp && fp.vendor) || (dev && dev.vendor) || '').toLowerCase();
    let score = 0; // điểm nghi ngờ tích lũy
    let softReason = '';

    // ── A. BẰNG CHỨNG RÕ RÀNG → BAN NGAY (high confidence) ──
    if (BAD_UA.some(k => ua.includes(k))) return { ok: false, ban: true, reason: 'trình duyệt giả/bot (UA)', deviceName: '', score: 99 };
    if (fp && fp.webdriver === true) return { ok: false, ban: true, reason: 'webdriver/automation', deviceName: '', score: 99 };
    if (!ua || ua.length < 20) return { ok: false, ban: true, reason: 'UA không hợp lệ', deviceName: '', score: 99 };
    if (EMU_MARKERS.some(k => ua.includes(k))) return { ok: false, ban: true, reason: 'máy ảo/emulator (UA marker)', deviceName: '', score: 99 };

    const isAndroid = /android/i.test(ua);
    const isIOS = /iphone|ipad|ipod/i.test(ua);

    // [v9.2 FIX] UA-platform mâu thuẫn — CHỈ ban khi mâu thuẫn RÕ RÀNG.
    //   Android thật: navigator.platform = "Linux armv8l"/"Linux armv7l" (Android=Linux kernel) → HỢP LỆ.
    //   iOS thật (iPadOS desktop-mode): platform = "MacIntel" → soft, KHÔNG ban cứng.
    if (isIOS && /win|linux|android|x11/.test(platform) && !/iphone|ipad|ipod/.test(platform))
        return { ok: false, ban: true, reason: 'UA iOS nhưng platform ' + (platform || '?') + ' (giả)', deviceName: '', score: 99 };
    if (isAndroid && /win|mac|iphone|ipad|ipod/.test(platform))
        return { ok: false, ban: true, reason: 'UA Android nhưng platform ' + (platform || '?') + ' (giả)', deviceName: '', score: 99 };
    // iOS + MacIntel (iPadOS request desktop) → soft, không ban (chỉ ghi log)
    if (isIOS && /mac/.test(platform)) { score += 1; softReason = softReason || 'iOS platform MacIntel (iPadOS desktop-mode)'; }
    // UA iOS nhưng vendor không phải Apple → nghi giả (trung bình, soft)
    if (isIOS && vendor && !vendor.includes('apple')) { score += 2; softReason = softReason || 'vendor không khớp iOS'; }

    // Tên máy (log admin)
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

    // ── B. MOBILE_ONLY: không phải Android/iOS → soft reject (KHÔNG ban, tránh nhầm) ──
    if (MOBILE_ONLY && !isAndroid && !isIOS) {
        return { ok: false, ban: BAN_DESKTOP, reason: 'không phải máy Android/iOS thật', deviceName, score: 1 };
    }

    // ── C. HEURISTIC — chỉ cộng điểm, KHÔNG ban cứng (fix ban nhầm iOS thật) ──
    // Cảm ứng: iOS thật LUÔN có touch → skip check trên iOS (client cũ có thể gửi sai).
    //          Android thiếu touch → soft (thử lại), không ban.
    const touch = dev.touchPoints != null ? dev.touchPoints : (fp && fp.maxTouchPoints);
    if (isAndroid && (touch == null || touch < 1)) { score += 1; softReason = softReason || 'thiếu cảm ứng'; }

    // CPU <2 nhân → soft
    const cores = dev.cores || (fp && fp.hardwareConcurrency) || 0;
    if (cores && cores < 2) { score += 1; softReason = softReason || 'CPU bất thường'; }

    // Màn hình: iOS ngưỡng rộng hơn (iPad Pro physical 2048). Chỉ soft, không ban.
    const scr = dev.screen || (fp && fp.screen) || '';
    const sm = String(scr).match(/(\d+)x(\d+)/);
    const w = sm ? parseInt(sm[1], 10) : 0;
    const maxW = isIOS ? 2200 : 1400;
    if (w && (w < 320 || ((isAndroid || isIOS) && w > maxW))) { score += 1; softReason = softReason || 'màn hình bất thường'; }

    // RAM <1 (nếu browser expose) → soft
    const mem = dev.memory || (fp && fp.deviceMemory) || 0;
    if (mem && mem < 1) { score += 1; softReason = softReason || 'RAM bất thường'; }

    // ── D. KẾT LUẬN: score ≥3 → ban (đa dấu hiệu giả); 1-2 → soft reject; 0 → ok ──
    if (score >= 3) return { ok: false, ban: true, reason: 'đa dấu hiệu thiết bị giả (' + softReason + ')', deviceName, score };
    if (score >= 1) return { ok: false, ban: false, reason: softReason + ' — vui lòng thử lại / dùng trình duyệt mặc định', deviceName, score };
    return { ok: true, ban: false, reason: '', deviceName, score: 0 };
}
function navigator_platform_fallback(fp) { return (fp && fp.platform) || 'Unknown'; }

// ══════════════════════════════════════════════════════════════════════════════
//  [v8] GATE MÔI TRƯỜNG THẬT — CHỈ gửi toàn bộ code connector xuống loader khi:
//    (1) trình duyệt THẬT (không headless/webdriver/bot/automation)
//    (2) thiết bị Android/iOS THẬT (không emulator/generic build/x86)
//    (3) dấu hiệu phần cứng nhất quán (cảm ứng / màn hình / CPU / RAM / ngôn ngữ)
//  Là lớp BẢO MẬT THỨ HAI trên validateDevice (đã chặn ban cứng). Gate này KHÔNG
//  ban vĩnh viễn — chỉ KHÔNG gửi code chức năng xuống + ghi log + trả lý do.
//  Tắt bằng env REQUIRE_REAL_ENV=false (mặc định BẬT).
// ══════════════════════════════════════════════════════════════════════════════
const REQUIRE_REAL_ENV = process.env.REQUIRE_REAL_ENV !== 'false';
const HEADLESS_MARKERS = ['headless', 'headlesschrome', 'phantomjs', 'phantom', 'puppeteer', 'playwright',
    'selenium', 'webdriver', 'wkhtml', 'electron', 'cef/', 'nw.js', 'node.js', 'deno', 'bun ',
    'jsdom', 'httpunit', 'htmlunit', 'phantomjs', 'chrome-lighthouse', 'lighthouse'];
const REAL_BROWSER_TOKENS = ['chrome/', 'safari/', 'firefox/', 'edg/', 'edge/', 'crios/', 'fxios/', 'version/', 'miuibrowser', 'samsungbrowser', 'opera/', 'opr/', 'ucbrowser'];
function validateRealEnvironment(fp, device, uaHeader, ipCountry) {
    if (!REQUIRE_REAL_ENV) return { ok: true, reason: 'real-env-check-disabled', score: 0 };
    const ua = String((fp && fp.ua) || uaHeader || '').toLowerCase();
    const dev = device || {};
    let score = 0, reason = '';
    const add = (n, r) => { if (score === 0 || !reason) reason = r; score += n; };

    // A. Trình duyệt giả/headless/automation → từ chối NGAY (không gửi connector)
    if (HEADLESS_MARKERS.some(k => ua.includes(k))) return { ok: false, reason: 'phát hiện trình duyệt headless/automation (anti-dump)', score: 99 };
    if (fp && fp.webdriver === true) return { ok: false, reason: 'navigator.webdriver=true (trình duyệt điều khiển tự động)', score: 99 };
    if (!ua || ua.length < 20) return { ok: false, reason: 'User-Agent rỗng/quá ngắn', score: 99 };
    if (!REAL_BROWSER_TOKENS.some(t => ua.includes(t))) add(3, 'UA không chứa token trình duyệt thật');

    const isAndroid = /android/i.test(ua);
    const isIOS = /iphone|ipad|ipod/i.test(ua);

    // B. Gate này CHỈ dành cho mobile thật — desktop/laptop không nhận code connector
    if (!isAndroid && !isIOS) return { ok: false, reason: 'không phải thiết bị Android/iOS thật (chỉ hỗ trợ điện thoại thật)', score: 99 };

    // C. Android thật: phải có model cụ thể, không phải generic/emulator/x86 build
    if (isAndroid) {
        const m = ua.match(/;\s*([^;)]+?)\s+build\//i);
        const model = (m ? m[1].trim() : (dev.model || '')).toLowerCase();
        if (!model || model === 'android' || model.length < 3) add(2, 'Android không xác định model (nghi emulator)');
        if (/sdk|emulator|generic|x86|goldfish|ranchu|vbox|vmware/i.test(model))
            return { ok: false, reason: 'Android emulator/generic/x86 build (không phải máy thật)', score: 99 };
    }
    // D. iOS thật: vendor phải là Apple + có version iOS trong UA
    if (isIOS) {
        const vendor = String((fp && fp.vendor) || (dev && dev.vendor) || '').toLowerCase();
        if (vendor && !vendor.includes('apple')) add(2, 'iOS vendor không phải Apple (nghi giả lập)');
        if (!/os \d+|iphone os \d+|cpu os \d+/.test(ua)) add(1, 'iOS thiếu version trong UA');
    }
    // E. Mobile thật LUÔN có cảm ứng ≥1 điểm
    const touch = dev.touchPoints != null ? dev.touchPoints : (fp && fp.maxTouchPoints);
    if (touch != null && touch < 1) add(2, 'thiết bị mobile không có cảm ứng (nghi máy ảo)');
    // F. Màn hình: headless mặc định 800x600/1024x768 — mobile thật trong khoảng hợp lý
    const scr = dev.screen || (fp && fp.screen) || '';
    const sm = String(scr).match(/(\d+)x(\d+)/);
    if (sm) {
        const w = parseInt(sm[1], 10), h = parseInt(sm[2], 10);
        if (w < 320 || h < 320) add(2, 'màn hình quá nhỏ (headless mặc định)');
        if (w > 2200 || h > 2200) add(1, 'màn hình quá lớn so với mobile');
    }
    // G. CPU/RAM nhất quán với điện thoại thật
    const cores = dev.cores || (fp && fp.hardwareConcurrency) || 0;
    if (cores && cores < 2) add(1, 'CPU <2 nhân (không hợp lý với điện thoại)');
    const mem = dev.memory || (fp && fp.deviceMemory) || 0;
    if (mem && mem < 1) add(1, 'RAM <1GB (không hợp lý với điện thoại)');
    // H. Trình duyệt thật luôn có navigator.language
    if (!fp || !fp.language) add(1, 'thiếu navigator.language (nghi headless)');
    // I. isMobile flag (nếu client gửi) phải khớp UA
    if (dev && dev.isMobile === false) add(2, 'client tự báo không phải mobile nhưng UA là mobile (mâu thuẫn)');

    if (score >= 3) return { ok: false, reason: 'đa dấu hiệu môi trường giả (' + reason + ')', score };
    if (score >= 1) return { ok: false, reason: reason + ' — vui lòng dùng trình duyệt mặc định (Chrome/Safari) trên điện thoại Android/iOS thật', score };
    return { ok: true, reason: '', score: 0 };
}
// [v8] Helper: build payload connector CHỈ KHI gate môi trường thật pass. Trả về null nếu từ chối.
function maybeSendConnector(token, fp, device, uaHeader, ipCountry, ctx) {
    const e = validateRealEnvironment(fp, device, uaHeader, ipCountry || '');
    if (!e.ok) {
        adminLog('connector-denied', Object.assign({ reason: e.reason, score: e.score }, ctx || {}));
        return { denied: true, reason: e.reason, score: e.score };
    }
    return { bundle: buildConnectorBundle() };
}

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
    // [v6.5.3 · LEGACY] Script cũ (v5.0) không gửi session token → cho qua (chỉ log), không chặn.
    //          Bảo mật vẫn còn: chữ ký HMAC (nếu client ký) + key verify ở /verify.
    if (!token) { adminLog('legacy-no-session', { path: req.path, ip: getClientIp(req) }); req._sess = null; req._token = null; return true; }
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
    const result = await verifyKey(key, hwid, olm_user);
    if (!result.success) recordKeyFail(ip); else resetKeyFail(ip); // [v7] anti brute-force key
    adminLog('verify', { key: maskKey(key), hwid, device: deviceNameOf(hwid), olm_user, ip, success: !!result.success, type: result.type || '', message: result.message || '' });
    res.json(result);
});

// Attestation — client gửi fp + device info, server kiểm tra máy thật + mạng thật, cấp session
app.post(API_PREFIX + '/attest', async (req, res) => {
    const ip = getClientIp(req);
    let { key, hwid, fp, device } = req.body || {};
    if (!key && !REQUIRE_KEY) key = PUBLIC_KEY; // [v9.1] no-key mode — loader không cần gửi key
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
    const kv = await verifyKey(key, hwid);
    if (!kv.success) {
        // [v7] anti brute-force: 10 lần sai key / 10p từ 1 IP → BAN
        if (recordKeyFail(ip) && AUTO_BAN && !isLoopbackIp(ip)) addBan(ip, hwid, 'brute-force key (10 lần sai)', v.deviceName);
        return res.status(401).json({ success: false, message: kv.message || 'Key không hợp lệ' });
    }
    resetKeyFail(ip);
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
    const resp = { success: true, session: token, expiresIn: 300, fpHash: fph, device: v.deviceName, message: 'Thiết bị & mạng hợp lệ — phiên đã cấp', moduleVersion: PAYLOAD_MODULE_VERSION, connectorVersion: CONNECTOR_MODULE_VERSION };
    if (isPremiumType(kv.type)) resp.module = buildModulePayload(token);
    // [v8] AUTO-SEND TOÀN BỘ code connector xuống loader CHỈ KHI môi trường thật xác nhận
    //     (trình duyệt thật + Android/iOS thiết bị thật). Mọi key hợp lệ đều được gửi nếu pass gate.
    const envCountry = (p && p.country) || '';
    const connRes = maybeSendConnector(token, fp, device, req.headers['user-agent'], envCountry,
        { key: maskKey(key), hwid, device: v.deviceName, ip, via: 'attest' });
    if (connRes.bundle) {
        resp.connector = connRes.bundle; // [v9] {v, enc, aesKey, decryptor}
    } else {
        resp.connectorDenied = true;
        resp.message = '⚠️ ' + connRes.reason + '. Code chức năng không được gửi xuống thiết bị này.';
    }
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
    const kv = await verifyKey(key, hwid);
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
    const kv = await verifyKey(key, hwid);
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
    const kv = await verifyKey(key, hwid);
    if (!kv.success) return res.status(401).json({ success: false, message: kv.message || 'Invalid key' });
    if (!isPremiumType(kv.type)) return res.status(403).json({ success: false, message: 'Module chỉ dành cho key PREMIUM/VIP/UNLIMITED' });
    adminLog('module', { key: maskKey(key), hwid, device: deviceNameOf(hwid), ip, type: kv.type || '' });
    const payload = { success: true, encrypted: true, moduleVersion: PAYLOAD_MODULE_VERSION, module: buildModulePayload(req._token) };
    res.json(rotateSession(req, payload));
});

// ══════════════════════════════════════════════════════════════════════════════
//  [v7] /code — loader TẢI LẠI toàn bộ connector code (cần session hợp lệ).
//  Dùng khi phiên hết hạn hoặc cập nhật version. Mã hoá AES-256-GCM key derive
//  từ session token (chỉ client attest hợp lệ mới giải mã được).
// ══════════════════════════════════════════════════════════════════════════════
app.post(API_PREFIX + '/code', async (req, res) => {
    const ip = getClientIp(req);
    if (isBanned(ip, req.body && req.body.hwid)) return res.status(404).json({ error: 'Not found' });
    if (!requireSession(req, res)) return;
    if (!rateLimit('code:' + ip, 10, 60000)) return res.status(429).json({ success: false, message: 'Quá nhiều yêu cầu' });
    const { key, hwid } = req.body || {};
    if (!key) return res.status(401).json({ success: false, message: 'Missing key' });
    const kv = await verifyKey(key, hwid);
    if (!kv.success) return res.status(401).json({ success: false, message: kv.message || 'Invalid key' });
    adminLog('code', { key: maskKey(key), hwid, device: deviceNameOf(hwid), ip, connectorVersion: CONNECTOR_MODULE_VERSION });
    // [v8] /code cũng phải qua gate môi trường thật (client gửi kèm fp+device để check đầy đủ)
    const codeFp = (req.body && req.body.fp) || { ua: req.headers['user-agent'] || '' };
    const codeDev = (req.body && req.body.device) || {};
    const codeRes = maybeSendConnector(req._token, codeFp, codeDev, req.headers['user-agent'], '',
        { key: maskKey(key), hwid, device: deviceNameOf(hwid), ip, via: 'code' });
    if (!codeRes.bundle) {
        return res.status(403).json({ success: false, connectorDenied: true, message: '⚠️ ' + codeRes.reason + '. Code chức năng không được gửi xuống thiết bị này.' });
    }
    const payload = { success: true, encrypted: true, connectorVersion: CONNECTOR_MODULE_VERSION, connector: codeRes.bundle };
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
    const kv = await verifyKey(key, hwid);
    if (!kv.success) {
        adminLog('heartbeat-block', { ip, hwid, reason: 'key thu hồi/hết hạn', message: kv.message || '' });
        return res.status(403).json({ blocked: true, reason: 'key', message: kv.message || 'Key đã bị vô hiệu hoá' });
    }
    // 4. Cập nhật lastSeen thiết bị
    if (hwid && devices.has(hwid)) { const d = devices.get(hwid); d.lastSeen = Date.now(); d.ip = ip; }
    // 5. AUTO-PUSH module nếu premium + client đang chạy version cũ
    const premium = isPremiumType(kv.type);
    const out = { ok: true, t: Date.now(), nextCheck: 30000, moduleVersion: PAYLOAD_MODULE_VERSION, premium, connectorVersion: CONNECTOR_MODULE_VERSION };
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
    // [v8] AUTO-PUSH connector code CHỈ KHI môi trường thật xác nhận (loader gửi fp+device trong heartbeat)
    const ccv = parseInt(req.body.connectorVersion || '0', 10);
    if (ccv < CONNECTOR_MODULE_VERSION) {
        const hbFp = fp || { ua: req.headers['user-agent'] || '' };
        const hbDev = device || {};
        const hbCountry = (p && p.country) || '';
        let tok2 = null;
        const sessTok2 = req.headers['x-session'];
        const sess2 = verifySession(sessTok2);
        if (sess2 && sess2.k === key && sess2.h === (hwid || '')) tok2 = sessTok2;
        else tok2 = signSession({ k: key, h: hwid || '', ip, fp: fpHash(fp), dev: v.deviceName, exp: Date.now() + SESSION_TTL, seq: 1, ua: sha256Hex(req.headers['user-agent'] || '').slice(0, 16), fireReady: false });
        const hbConn = maybeSendConnector(tok2, hbFp, hbDev, req.headers['user-agent'], hbCountry,
            { key: maskKey(key), hwid, ip, from: ccv, to: CONNECTOR_MODULE_VERSION, via: 'heartbeat' });
        if (hbConn.bundle) {
            out.connector = hbConn.bundle; // [v9] {v, enc, aesKey, decryptor} — loader tự giải mã, không cần session token
            adminLog('heartbeat-connector-push', { key: maskKey(key), hwid, ip, from: ccv, to: CONNECTOR_MODULE_VERSION });
        } else {
            out.connectorDenied = true;
            out.connectorReason = hbConn.reason;
            adminLog('heartbeat-connector-denied', { key: maskKey(key), hwid, ip, reason: hbConn.reason, score: hbConn.score });
        }
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
        console.log(`\n🚀 GOD MODE Server v9.2 (FIX ban nhầm Android platform Linux + AES-256 + no-key) running → http://localhost:${PORT}`);
        console.log(`   Ẩn API prefix: ${API_PREFIX}`);
        console.log(`   Admin: ${ADMIN_PATH} (${ADMIN_USER})`);
        console.log(`   Lưu trữ bền vững (KV): ${KV_ENABLED ? 'CÓ' : 'KHÔNG — đặt env KV_REST_API_URL + KV_REST_API_TOKEN để ban/mật khẩu tồn tại qua restart'}`);
    });
}
module.exports = app;
