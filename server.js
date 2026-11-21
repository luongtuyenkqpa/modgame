/**
 * ======================================================
 *  GOD MODE v18.0 — SLIM ARCHITECTURE (server-authoritative)
 *  - Connector Violentmonkey còn 3 nhóm: GIAO DIỆN + ANTI + THÔNG BÁO.
 *  - Toàn bộ logic giải đáp / dựng payload nộp bài chạy ở server (/process, /fire);
 *    client chỉ gửi dữ liệu thô (raw_questions + meta), nhận params_str + summary.
 *  - /fire trả thêm summary danh sách đáp án để client hiển thị log/thông báo.
 *  - Client KHÔNG tải/exec module nộp bài trong trình duyệt; module cũ giữ tương thích ngược.
 *  - anti-ban / KeyVault proxy / admin panel / KV giữ nguyên từ v17.
 * ======================================================
 * ======================================================
 *  GOD MODE v17.0 — BACKEND SERVER (KeyVault-compatible, NO GM-leak) (SELF-CONTAINED LOADER)
 *  - [v17] FIX LỖI TRÊN MÁY THẬT: Android/iOS thật + IP nhà mạng thật KHÔNG còn bị 404 "Not found"
 *          thầm lặng (client báo "Xác thực thiết bị/mạng thất bại" không rõ lý do).
 *          (1) guardBanned: thiết bị mobile thật tự gỡ khoá IP/HWID rồi đi tiếp, không trả 404;
 *          (2) mọi lỗi từ chối đều kèm message tiếng Việt (không còn body {error} trống);
 *          (3) key bị thu hồi trên máy thật -> 401 có thông báo, KHÔNG âm thầm 404;
 *          (4) getClientIp lấy client IP thật (req.ip / XFF đầu) thay vì IP edge/proxy cuối chuỗi;
 *          (5) validateDevice: mobile thật miễn các dấu hiệu mềm (BAD_UA marker, UA ngắn, EMU marker
 *              không rõ ràng), chỉ chặn automation rõ ràng (webdriver/headless/puppeteer...);
 *          (6) HARD_DC_BAN không bao giờ chặn IP của UA mobile thật, kể cả khi SMART_BAN tắt;
 *          (7) checkProxyIp nhận diện nhà mạng di động (Viettel/Vinaphone/Mobifone/FPT...) -> risk=low;
 *          (8) requireSession: lệch UA trên mobile (Userscripts/iOS) chỉ ghi log, không 403;
 *          (9) dumper-guard trên máy thật chỉ ghi log, không thu hồi key;
 *          (10) nâng rate-limit attest 10 -> 30 lần/phút cho IP+HWID;
 *          (11) anti-share mềm: cùng 1 key trên Android + iPhone thật của chủ chỉ ghi log, không 403.
 *  - [v16] AUDIT-FIX cho may THAT Android/iOS: (1) session khong con chan khi IP quay số (CGNAT/Wi-Fi-4G),
 *         chi ghi log; (2) guard ban nhận UA mới nhất của IP (chặn ban nhầm trước khi kịp attest);
 *         (3) validateDevice: mobile thiếu fingerprint KHÔNG bị tính ban cứng; (4) attest/heartbeat proxy
 *         cho mobile thật bỏ qua khi HARD_DC_BAN bật; (5) rate-limit gắn theo IP+HWID, nâng trần global
 *         120→300/phút để không trúng 429 khi nhiều máy dùng chung IP nhà mạng (CGNAT).
 *  - [v15] AUTO_UNLOCK_REAL_IP: IP THẬT của máy Android/iOS TỰ ĐỘNG MỞ KHOÁ NGAY khi có request
 *         (middleware + mọi API route), không cần admin bấm thủ công. Ghi nhận IP thật (realIps),
 *         tự xoá cache proxy nhận nhầm, không bao giờ ban lại IP thật.
 *  - [v14] SMART_BAN mặc định BẬT: ban THÔNG MINH — CHỈ ban máy ảo/emulator/webdriver/bot + IP
 *         datacenter+proxy/VPN đã XÁC NHẬN. Máy thật Android/iOS (UA mobile + attest thành công)
 *         KHÔNG BAO GIỜ bị ban; nếu bị khoá nhầm sẽ TỰ ĐỘNG MỞ BAN ngay (khi có request tiếp theo).
 *         Quét định kỳ 5 phút cũng tự gỡ ban của thiết bị thật. Ghi nhận realDevices vào KV.
 *  - [v13] SAFE_MODE (CHẾ ĐỘ AN TOÀN) mặc định BẬT: auto-ban IP/HWID bị khoá MỀM — chỉ log + từ chối (403),
 *         KHÔNG khoá vĩnh viễn nữa. Chỉ admin khoá thủ công mới có hiệu lực. Khắc phục triệt để lỗi ban nhầm
 *         IP thật của nhà mạng di động (CGNAT) / thiết bị Android/iOS thật. Tắt bằng env SAFE_MODE=false hoặc panel.
 *  - [v13] HARD_DC_BAN mặc định TẮT (kill-switch) — admin chủ động bật trong panel khi cần.
 *  - [v13] checkProxyIp: nếu ip-api báo mobile=true (nhà mạng di động) → force risk=low, KHÔNG bao giờ chặn/ban.
 *         Chỉ coi risk=high khi CẢ isDC lẫn isVPN/proxy (tránh nhận nhầm carrier IP thành datacenter).
 *  - [v13] Nút "MỞ KHOÁ TẤT CẢ" trong admin panel: gỡ toàn bộ ban IP/HWID + xóa cache IP → reset thiết bị bị khoá.
 *  - [v13] DUMPER_GUARD: ngưỡng lấy module 2→10 lần/giờ; vượt ngưỡng chỉ trả 429, KHÔNG ban key.
 *  - [v13] Bỏ ban vĩnh viễn khi brute-force key (chỉ trả 401, tránh ban nhầm IP dùng chung CGNAT).
 *  - [v12] SMART_VM_BLOCK: toggle "Chặn kèo script VM" giờ CHỈ chặn VM/proxy/datacenter/desktop UA.
 *         Android/iOS thật (UA mobile + IP nhà mạng) vẫn kéo code bình thường khi toggle BẬT.
 *         Bỏ blanket 404 ở /module & /code (đã bắt buộc session = thiết bị thật qua /attest).
 *  - [v11] VÁ LỖ HỔNG: /kv-payload.js & /loader.user.js giờ có HARD_DC_BAN + chặn UA bot/curl/emulator
 *         (trước đây 2 endpoint này KHÔNG có check nào → IP datacenter kéo được raw connector).
 *  - [v11] /bootstrap.js chặn UA bot/curl/emulator (trước chỉ chặn IP datacenter).
 *  - [v11] /module defense-in-depth: kiểm tra lại IP datacenter (dù session đã ràng buộc IP).
 *  - [v11] checkProxyIp: fallback ip-api.com khi ipapi.is lỗi; cache lỗi chỉ 60s (thử lại sớm).
 *  - [v11] Global rate-limit 120 req/phút/IP chống scan/dumper.
 *  - [v11] Cảnh báo khởi động nếu BLOCK_VM_SCRIPT đang TẮT.
 *  - [v10.1] SỬA: BLOCK_VM_SCRIPT (chặn kèo script VM) mặc định TẮT (kill-switch) — admin chủ động BẬT trong panel.
 *  - [v10] MẶC ĐỊNH: chặn module 10đ (admin vẫn TẮT được trong panel).
 *  - [v10] HARD_DC_BAN: IP datacenter/proxy/VPN gọi bất kỳ API nào (kể cả bootstrap.js) → BAN NGAY.
 *  - [v10] DUMPER_GUARD: phát hiện hành vi dumper (gọi /module trực tiếp không qua process/fire,
 *         attest→module <10s, lấy module ≥2 lần, heartbeat clientVersion=0 liên tục) → BAN key+hwid+ip.
 *  - [v10] MODULE_WATERMARK: dấu vết duy nhất mỗi key+hwid nhúng vào module → leak dump là truy ra người mua.
 *  - [v10] BANNED_KEYS: revoke key bị rò rỉ/dump (env BANNED_KEYS=KEY1,KEY2 hoặc khoá trong admin).
 *  - [v10] Siết chữ ký HMAC: cửa sổ ts 30s→15s; /module & /code BẮT BUỘC có chữ ký + session hợp lệ.
 *  - [v10] Cảnh báo khẩn nếu vẫn dùng SECRET mặc định ĐÃ RÒ RỈ (trong tất cả file dumper).
 *  - [v8] TOÀN BỘ code connector (chức năng userscript) được NHÚNG sẵn
 *    trong server (CONNECTOR_MODULE_EMBEDDED_B64) → không cần file ngoài.
 *  - [v8] Endpoint ẩn GET <API_PREFIX>/bootstrap.js trả connector mã hoá
 *  - [v8.1] Endpoint ẩn GET <API_PREFIX>/kv-payload.js trả RAW JS tương thích KeyVault
 *  - [v8.2] FIX GM-LEAK: bridge GM_xmlhttpRequest/GM_addStyle là biến CỤC BỘ, tuyệt đối không gán
 *         vào window → không còn kích hoạt anti-cheat "PHÁT HIỆN PHẦN MỀM LẠ (GM leak: GM_addStyle)".
 *         (index.js): tự cài bridge GM_xmlhttpRequest qua fetch + chạy connector ngay,
 *         không loader trung gian, không cache, KHÔNG đệ quy. Upload file này lên KeyVault.
 *    AES-256-GCM (key PBKDF2 từ SECRET) cho loader.user.js tải & chạy.
 *  - [v8] Server tự inject SERVER_BASE (origin request) + API_SECRET
 *    (SECRET hiện tại) vào code connector khi phục vụ → luôn khớp.
 *  - Giữ nguyên /code, /attest, /heartbeat auto-push (tương thích v7).
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
const http     = require('http'); // [v11] fallback ip-api.com (free tier chi ho tro http)
const crypto   = require('crypto');
const app      = express();
const PORT     = process.env.PORT || 3000;

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(express.json({ limit: '5mb', verify: (req, _res, buf) => { req.rawBody = buf; } })); // [v9] 5mb chong DoS
app.use(express.urlencoded({ extended: true, limit: '5mb' })); // [v9] 5mb chong DoS
app.disable('x-powered-by');
app.set('trust proxy', 1);

// Security headers
app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cache-Control', 'no-store');
    // [v9] them headers bao mat
    res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
    res.setHeader('X-DNS-Prefetch-Control', 'off');
    res.removeHeader('X-Powered-By');
    res.setHeader('Server', 'cloudflare'); // [v9] gia ma, khong tiet lo Express/Node
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
if (SECRET === DEFAULT_SECRET) {
    console.error('\x1b[31m[SECURITY CRITICAL — v10] BAN DANG DUNG SECRET MAC DINH DA ROI ROI (co trong tat ca file dumper)! Dat env GODMODE_SECRET (64 hex ngau nhien) tren Vercel NGAY, va cap nhat API_SECRET trong loader Payload_v9.js cho khop.\x1b[0m');
    console.error('\x1b[31m[SECURITY] Key OLM-UPJO-GXYC-USLC-ER2O va HWID HW2334B90D da xuat hien trong dumper — xem xet revokle key do bang env BANNED_KEYS hoac admin panel.\x1b[0m');
}

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
function buildModulePayload(sessionToken, key, hwid) {
    return encryptAnswers({ src: watermarkSrc(PAYLOAD_MODULE_SRC, key, hwid), v: PAYLOAD_MODULE_VERSION }, sessionToken);
}

// ══════════════════════════════════════════════════════════════════════════════
//  [v7] FULL CONNECTOR MODULE — TOÀN BỘ code chức năng userscript nằm ở SERVER.
//  Loader (userscript tối thiểu) chỉ attest → nhận code mã hoá → giải mã → chạy.
//  Nguồn code: env CONNECTOR_MODULE_SRC (chuỗi JS) HOẶC file tại
//  CONNECTOR_MODULE_PATH (mặc định ./connector.module.js). Mã hoá AES-256-GCM
//  key derive từ session token (chỉ client hợp lệ mới giải mã được).
//  Tăng CONNECTOR_MODULE_VERSION mỗi khi cập nhật code → loader tự tải lại.
// ══════════════════════════════════════════════════════════════════════════════
// [v8] CONNECTOR NHÚNG SẴN trong server (base64) → self-contained, không cần file ngoài.
// Vẫn ưu tiên: env CONNECTOR_MODULE_SRC > file ./connector.module.js > embedded.
const CONNECTOR_MODULE_EMBEDDED_B64 = 'Ly8g4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQCi8vICBDT05ORUNUT1IgTU9EVUxFIFNMSU0gdjE4IChwaOG7pWMgduG7pSB04burIFNFUlZFUikKLy8gIEtJ4bq+TiBUUsOaQzogY2xpZW50IGNo4buJIGdp4buvIDMgbmjDs20gdmnhu4djIOKAlAovLyAgICAxKSBHSUFPIERJ4buGTjogbG9jayBzY3JlZW4sIHBhbmVsLCB0aGVtZSwgbsO6dCBi4bqlbSwgw7QgbG9nLCBtb2RhbAovLyAgICAyKSBBTlRJOiBkw7IgaG9vay9zY3JpcHQgbOG6oSwgdGh1IHRo4bqtcCBIV0lEL0ZQL2RldmljZSwgYmFuLW1vZGUgJgovLyAgICAgICByZW1vdGUtbG9jaywgYnJpZGdlIG3huqFuZyBj4bulYyBi4buZIChLSMOUTkcgbGVhayBHTV8qIHJhIHdpbmRvdykKLy8gICAgMykgVEjDlE5HIELDgU86IGxvZyB0cuG7sWMgcXVhbiwgbW9kYWwgdGjDoG5oIGPDtG5nL2zhu5dpLCBtw6BuIGjDrG5oIGtob8OhCi8vICBN4buMSSBsb2dpYyBuZ2hp4buHcCB24bulIChnaeG6o2kgxJHDoXAsIGThu7FuZyBwYXlsb2FkIG7hu5lwIGLDoGksIHZhbGlkYXRlKSBkbwovLyAgU0VSVkVSIHjhu60gbMO9OyBjbGllbnQgY2jhu4kgZ+G7rWkgROG7riBMSeG7hlUgVEjDlCAoY8OidSBo4buPaSB0aMO0ICsgbWV0YSksIG5o4bqtbgovLyAga+G6v3QgcXXhuqMgKHBhcmFtc19zdHIgKyBzdW1tYXJ5KSDEkeG7gyBoaeG7g24gdGjhu4sgdsOgIHBow6F0IGzhuqFpIHJlcXVlc3QgbuG7mXAgYsOgaQovLyAgYuG6sW5nIHBoacOqbiDEkcSDbmcgbmjhuq1wIE9MTSBj4bulYyBi4buZIChjb29raWUvQ1NSRiBu4bqxbSB0cm9uZyB0csOsbmggZHV54buHdCkuCi8vICBTZXJ2ZXIgdOG7sSBpbmplY3QgU0VSVkVSX0JBU0UgKyBBUElfU0VDUkVUIGtoaSBwaOG7pWMgduG7pSAvYm9vdHN0cmFwLmpzLgovLyDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZAKCi8vIOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkAovLyAgxJDhu5RJIDIgR0nDgSBUUuG7iiBOw4BZIGNobyBraOG7m3AgduG7m2kgc2VydmVyIGPhu6dhIGLhuqFuOgovLyDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZAKY29uc3QgU0VSVkVSX0JBU0UgPSAnaHR0cHM6Ly9tb2RnYW1lLnZlcmNlbC5hcHAnOyAgLy8g4pqg77iPIMSQ4buUSSB0aMOgbmggVVJMIHNlcnZlciBWZXJjZWwgY+G7p2EgYuG6oW4KY29uc3QgQVBJX1NFQ1JFVCAgPSAnYTdmM2M5ZTFiMmQ0ODUwNmZhZTFjN2QzYjlmMGUyYTRjNmQ4ZjFhM2I1ZTdjOWQwZjJhNGM2ZThiMWQzZjVhNyc7ICAvLyDimqDvuI8gxJDhu5RJIGto4bubcCBlbnYgR09ETU9ERV9TRUNSRVQgdHLDqm4gc2VydmVyCi8vIOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkAovLyBbdjVdIE3DoyBob8OhIHJlcXVlc3QgYm9keSDigJQgxJHhu5VpIHRydWUgU0FVIEtISSBzZXJ2ZXIgaOG7lyB0cuG7oyBnaeG6o2kgbcOjIHY1CmNvbnN0IFJFUVVFU1RfRU5DUllQVElPTiA9IGZhbHNlOwovLyDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZAKCjsoZnVuY3Rpb24gKCkgewogICAgJ3VzZSBzdHJpY3QnOwoKICAgIC8vIOKUgOKUgOKUgCBTdG9yYWdlIGtleSDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIAKICAgIGNvbnN0IExTX0tFWSAgICAgICA9ICdfdGxfY29ubl9rZXknOwogICAgY29uc3QgTFNfVFlQRSAgICAgID0gJ190bF9jb25uX3R5cGUnOwogICAgY29uc3QgTFNfRVhQICAgICAgID0gJ190bF9jb25uX2V4cCc7CiAgICBjb25zdCBMU19USEVNRSAgICAgPSAnX3RpZXBfdGhlbWUnOwogICAgbGV0ICAgQ1VSUkVOVF9LRVkgID0gbnVsbDsKICAgIGxldCAgIEtFWV9TVEFUVVMgICA9IHsgdmFsaWQ6IGZhbHNlLCB0eXBlOiBudWxsLCBleHBpcmVzX2F0OiBudWxsIH07CiAgICBsZXQgICBDVVJSRU5UX0RFVklDRSA9ICcnOyAvLyBbdjRdIHTDqm4gbcOheSAobOG6pXkgdOG7qyBzZXJ2ZXIgc2F1IGF0dGVzdCkKCiAgICAvLyDilIDilIDilIAgU0VTU0lPTiAoZGF0YSBjYXB0dXJlZCBmcm9tIFhIUikg4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSACiAgICBjb25zdCBTRVNTSU9OID0gewogICAgICAgIHJhd19xdWVzdGlvbnM6IFtdLAogICAgICAgIG1ldGE6IHsgaWRfdXNlcjogbnVsbCwgaWRfY2F0ZTogbnVsbCwgaWRfY291cnNld2FyZTogbnVsbCwKICAgICAgICAgICAgICAgIGlkX3NjaG9vbDogbnVsbCwgaWRfZ3JvdXA6IG51bGwsIGNzcmZfdG9rZW46IG51bGwgfSwKICAgICAgICBhdXRvX21vZGU6ICAgICdwcmFjdGljZScsCiAgICAgICAgdmlkZW9fbGVuZ3RoOiA5MDAKICAgIH07CgogICAgLy8g4pSA4pSA4pSAIFRoZW1lIOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgAogICAgbGV0IENVUlJFTlRfVEhFTUUgPSBsb2NhbFN0b3JhZ2UuZ2V0SXRlbShMU19USEVNRSkgfHwgJ2RlZmF1bHQnOwoKICAgIC8vIOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkAogICAgLy8gIFt2NC4xXSBLSeG7gk0gVFJBIExP4bqgSSBLRVkg4oCUIEdJ4buQTkcgVjMgQ09SRQogICAgLy8g4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQCiAgICBmdW5jdGlvbiBpc1ByZW1pdW1LZXkoKSB7CiAgICAgICAgY29uc3QgdCA9IChLRVlfU1RBVFVTLnR5cGUgfHwgX3NMUy5nZXQoTFNfVFlQRSkgfHwgJycpLnRvU3RyaW5nKCkudG9VcHBlckNhc2UoKTsgLy8gW3Y1XSBvYmZ1c2NhdGVkIHJlYWQKICAgICAgICByZXR1cm4gdCA9PT0gJ1BSRU1JVU0nIHx8IHQgPT09ICdWSVAnIHx8IHQgPT09ICdVTkxJTUlURUQnOwogICAgfQoKICAgIC8vIOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkAogICAgLy8gIFt2NC4xXSBY4busIEzDnSBPTE0gQUNDT1VOVCBNSVNNQVRDSAogICAgLy8g4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQCiAgICBmdW5jdGlvbiBoYW5kbGVPbG1NaXNtYXRjaChzZXJ2ZXJPbG0sIGN1cnJlbnRPbG0pIHsKICAgICAgICAvLyBYw7NhIGtleSBraOG7j2kgYuG7mSBuaOG7myB2w6AgbG9jYWxTdG9yYWdlCiAgICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oTFNfS0VZKTsKICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShMU19UWVBFKTsKICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShMU19FWFApOwogICAgICAgIENVUlJFTlRfS0VZICAgID0gbnVsbDsKICAgICAgICBLRVlfU1RBVFVTICAgICA9IHsgdmFsaWQ6IGZhbHNlLCB0eXBlOiBudWxsLCBleHBpcmVzX2F0OiBudWxsIH07CiAgICAgICAgX3NlY1Nlc3Npb24gICAgPSB7IHRva2VuOiBudWxsLCBleHA6IDAsIGZwSGFzaDogbnVsbCwgc2VxOiAxIH07CiAgICAgICAgQ1VSUkVOVF9ERVZJQ0UgPSAnJzsKCiAgICAgICAgLy8gWMOzYSBwYW5lbCBVSSBu4bq/dSDEkWFuZyBoaeG7h24KICAgICAgICBjb25zdCBwYW5lbEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLXBhbmVsJyk7CiAgICAgICAgY29uc3QgZmIgICAgICA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1mbG9hdEJ0bicpOwogICAgICAgIGlmIChwYW5lbEVsKSBwYW5lbEVsLnJlbW92ZSgpOwogICAgICAgIGlmIChmYikgICAgICBmYi5yZW1vdmUoKTsKCiAgICAgICAgLy8gSGnhu4duIG1vZGFsIHRow7RuZyBiw6FvIHLhu5NpIHF1YXkgbOG6oWkgdHJhbmcgxJHEg25nIG5o4bqtcCBrZXkKICAgICAgICBzaG93Q3VzdG9tTW9kYWwoewogICAgICAgICAgICBpY29uOiAgJ/CfmqsnLAogICAgICAgICAgICB0aXRsZTogJ1TDgEkgS0hP4bqiTiBPTE0gS0jDlE5HIEtI4buaUCEnLAogICAgICAgICAgICBsaW5lczogWwogICAgICAgICAgICAgICAgYEtleSDEkcaw4bujYyDEkcSDbmcga8O9IGNobyB0w6BpIGtob+G6o246IDxiPiR7c2VydmVyT2xtfTwvYj5gLAogICAgICAgICAgICAgICAgYFTDoGkga2hv4bqjbiBPTE0gaGnhu4duIHThuqFpOiA8Yj4ke2N1cnJlbnRPbG19PC9iPmAsCiAgICAgICAgICAgICAgICBg4pqg77iPIFZ1aSBsw7JuZyDEkcSDbmcgbmjhuq1wIMSRw7puZyB0w6BpIGtob+G6o24gT0xNIMSR4buDIHPhu60gZOG7pW5nIGtleSBuw6B5LGAsCiAgICAgICAgICAgICAgICBgaG/hurdjIGxpw6puIGjhu4cgYWRtaW4gxJHhu4MgxJHGsOG7o2MgaOG7lyB0cuG7oyFgCiAgICAgICAgICAgIF0sCiAgICAgICAgICAgIG9uT2s6ICgpID0+IGJ1aWxkTG9ja1NjcmVlbign4pqg77iPIFTDoGkga2hv4bqjbiBPTE0ga2jDtG5nIGto4bubcCB24bubaSBrZXkgxJHDoyDEkcSDbmcga8O9IScpCiAgICAgICAgfSk7CiAgICB9CgogICAgLy8g4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQCiAgICAvLyAgSOG7hiBUSOG7kE5HIEdJQU8gREnhu4ZOIFRIRU8gQ0jhu6YgxJDhu4AgKFRIRU1FKSDigJQgZ2nhu5FuZyBjb3JlIHYzLjIKICAgIC8vIOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkAogICAgZnVuY3Rpb24gZ2V0VGhlbWVDb2xvcnModGhlbWUpIHsKICAgICAgICBjb25zdCBUID0gewogICAgICAgICAgICBkZWZhdWx0OiB7CiAgICAgICAgICAgICAgICBjMTonIzAwZjJmZScsIGMyOicjNGZhY2ZlJywKICAgICAgICAgICAgICAgIGJnT3ZlcmxheToncmdiYSgxMywxNywyMywwLjk1KScsIGJnUGFuZWw6J3JnYmEoMTMsMTcsMjMsMC44OCknLAogICAgICAgICAgICAgICAgYm9yZGVyOidyZ2JhKDAsMjQyLDI1NCwwLjIpJywgYm9yZGVyU3Ryb25nOidyZ2JhKDAsMjQyLDI1NCwwLjMpJywKICAgICAgICAgICAgICAgIGJvcmRlclN1YnRsZToncmdiYSgwLDI0MiwyNTQsMC4xMiknLAogICAgICAgICAgICAgICAgaGVhZGVyQmc6J2xpbmVhci1ncmFkaWVudCgxMzVkZWcscmdiYSgwLDI0MiwyNTQsMC4wNykscmdiYSg3OSwxNzIsMjU0LDAuMDQpKScsCiAgICAgICAgICAgICAgICBnbG93Q29sb3I6J3JnYmEoMCwyNDIsMjU0LDAuNDUpJywgZ2xvd1N0cm9uZzoncmdiYSgwLDI0MiwyNTQsMC43KScsCiAgICAgICAgICAgICAgICBnbG93TWlkOidyZ2JhKDAsMjQyLDI1NCwwLjI1KScsIGdsb3dTdWJ0bGU6J3JnYmEoMCwyNDIsMjU0LDAuMDgpJywKICAgICAgICAgICAgICAgIGdsb3dQdWxzZToncmdiYSgwLDI0MiwyNTQsMC41NSknLAogICAgICAgICAgICAgICAgaW5wdXRCb3JkZXI6J3JnYmEoMCwyNDIsMjU0LDAuNCknLCBpbnB1dENvbG9yOicjMDBmMmZlJywKICAgICAgICAgICAgICAgIGZsb2F0R3JhZGllbnQ6J2xpbmVhci1ncmFkaWVudCgxMzVkZWcsIzAwZjJmZSwjNGZhY2ZlKScsCiAgICAgICAgICAgICAgICBicmFuZEdyYWRpZW50OidsaW5lYXItZ3JhZGllbnQoOTBkZWcsIzAwZjJmZSwjNGZhY2ZlLCMwMGYyZmUpJywKICAgICAgICAgICAgICAgIHN0YXR1c0JvcmRlcjoncmdiYSgwLDIzMCwxMjAsMC4yNSknLCBzdGF0dXNCZzoncmdiYSgwLDIzMCwxMjAsMC4wNCknLAogICAgICAgICAgICAgICAgcGFuZWxJbnNldDoncmdiYSgwLDI0MiwyNTQsMC4wOCknLAogICAgICAgICAgICAgICAgc2VsZWN0Qm9yZGVyOidyZ2JhKDAsMjQyLDI1NCwwLjIpJywgY29uc29sZUJvcmRlcjoncmdiYSgwLDI0MiwyNTQsMC4xMiknLAogICAgICAgICAgICAgICAgZnhDU1M6JycsIHBhbmVsRXh0cmE6JycsCiAgICAgICAgICAgICAgICB0aGVtZUxhYmVsOifwn5S1IE3hurdjIMSQ4buLbmgnLAogICAgICAgICAgICAgICAgcHJldmlld0JnOidsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLCMwMDE1MjAsIzAwZjJmZTU1KScsCiAgICAgICAgICAgICAgICBwcmV2aWV3Qm9yZGVyOidyZ2JhKDAsMjQyLDI1NCwwLjUpJywKICAgICAgICAgICAgICAgIHByZXZpZXdUZXh0OicjMDBmMmZlJywKICAgICAgICAgICAgfSwKICAgICAgICAgICAgZ3JheTogewogICAgICAgICAgICAgICAgYzE6JyNlMGUwZTAnLCBjMjonI2EwYTBhMCcsCiAgICAgICAgICAgICAgICBiZ092ZXJsYXk6J3JnYmEoMTAsMTAsMTAsMC45NyknLCBiZ1BhbmVsOidyZ2JhKDIwLDIwLDIwLDAuOTQpJywKICAgICAgICAgICAgICAgIGJvcmRlcjoncmdiYSgyMDAsMjAwLDIwMCwwLjE4KScsIGJvcmRlclN0cm9uZzoncmdiYSgyMzAsMjMwLDIzMCwwLjMpJywKICAgICAgICAgICAgICAgIGJvcmRlclN1YnRsZToncmdiYSgxNzAsMTcwLDE3MCwwLjEpJywKICAgICAgICAgICAgICAgIGhlYWRlckJnOidsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLHJnYmEoMTIwLDEyMCwxMjAsMC4xMikscmdiYSg2MCw2MCw2MCwwLjA1KSknLAogICAgICAgICAgICAgICAgZ2xvd0NvbG9yOidyZ2JhKDIxMCwyMTAsMjEwLDAuMzUpJywgZ2xvd1N0cm9uZzoncmdiYSgyMjAsMjIwLDIyMCwwLjYpJywKICAgICAgICAgICAgICAgIGdsb3dNaWQ6J3JnYmEoMjAwLDIwMCwyMDAsMC4yKScsIGdsb3dTdWJ0bGU6J3JnYmEoMTYwLDE2MCwxNjAsMC4wNyknLAogICAgICAgICAgICAgICAgZ2xvd1B1bHNlOidyZ2JhKDIwMCwyMDAsMjAwLDAuNDUpJywKICAgICAgICAgICAgICAgIGlucHV0Qm9yZGVyOidyZ2JhKDIwMCwyMDAsMjAwLDAuMzgpJywgaW5wdXRDb2xvcjonI2Q4ZDhkOCcsCiAgICAgICAgICAgICAgICBmbG9hdEdyYWRpZW50OidsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLCNjMGMwYzAsIzY2NiknLAogICAgICAgICAgICAgICAgYnJhbmRHcmFkaWVudDonbGluZWFyLWdyYWRpZW50KDkwZGVnLCNjMGMwYzAsI2ZmZmZmZiwjZDBkMGQwLCNjMGMwYzApJywKICAgICAgICAgICAgICAgIHN0YXR1c0JvcmRlcjoncmdiYSgxNjAsMTYwLDE2MCwwLjIpJywgc3RhdHVzQmc6J3JnYmEoNjAsNjAsNjAsMC4wNyknLAogICAgICAgICAgICAgICAgcGFuZWxJbnNldDoncmdiYSgyMDAsMjAwLDIwMCwwLjA3KScsCiAgICAgICAgICAgICAgICBzZWxlY3RCb3JkZXI6J3JnYmEoMTkwLDE5MCwxOTAsMC4yKScsIGNvbnNvbGVCb3JkZXI6J3JnYmEoMTYwLDE2MCwxNjAsMC4xKScsCiAgICAgICAgICAgICAgICBmeENTUzpgCiAgICAgICAgICAgICAgICAgICAgI3RsLWNvbm4tZngtYmFyIHsgaGVpZ2h0OjJweDsgYmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoOTBkZWcsdHJhbnNwYXJlbnQscmdiYSgyNTUsMjU1LDI1NSwwLjA4KSxyZ2JhKDI1NSwyNTUsMjU1LDAuNTUpLHJnYmEoMjU1LDI1NSwyNTUsMC4wOCksdHJhbnNwYXJlbnQpOyBiYWNrZ3JvdW5kLXNpemU6MzAwJSAxMDAlOyBhbmltYXRpb246bWV0YWxTd2VlcCAyLjhzIGxpbmVhciBpbmZpbml0ZTsgfQogICAgICAgICAgICAgICAgICAgIEBrZXlmcmFtZXMgbWV0YWxTd2VlcCB7IDAle2JhY2tncm91bmQtcG9zaXRpb246MTAwJSAwfSAxMDAle2JhY2tncm91bmQtcG9zaXRpb246LTIwMCUgMH0gfQogICAgICAgICAgICAgICAgICAgICN0bC1wYW5lbCB7IGJveC1zaGFkb3c6IDAgMCA2MHB4IHJnYmEoMCwwLDAsMC44NSksIDAgMCAzMHB4IHJnYmEoMTgwLDE4MCwxODAsMC4wNiksIGluc2V0IDAgMXB4IDAgcmdiYSgyNTUsMjU1LDI1NSwwLjA4KTsgfQogICAgICAgICAgICAgICAgICAgICN0bC1jb25uLXBhbmVsIHsgYm94LXNoYWRvdzogMCAwIDYwcHggcmdiYSgwLDAsMCwwLjg1KSwgaW5zZXQgMCAxcHggMCByZ2JhKDI1NSwyNTUsMjU1LDAuMDgpOyB9CiAgICAgICAgICAgICAgICBgLAogICAgICAgICAgICAgICAgcGFuZWxFeHRyYTonPGRpdiBpZD0idGwtY29ubi1meC1iYXIiPjwvZGl2PicsCiAgICAgICAgICAgICAgICB0aGVtZUxhYmVsOifimqsgWMOhbSBC4bqhYycsCiAgICAgICAgICAgICAgICBwcmV2aWV3Qmc6J2xpbmVhci1ncmFkaWVudCgxMzVkZWcsIzFhMWExYSwjNjY2KScsCiAgICAgICAgICAgICAgICBwcmV2aWV3Qm9yZGVyOidyZ2JhKDIyMCwyMjAsMjIwLDAuNDUpJywKICAgICAgICAgICAgICAgIHByZXZpZXdUZXh0OicjZTBlMGUwJywKICAgICAgICAgICAgfSwKICAgICAgICAgICAgcGluazogewogICAgICAgICAgICAgICAgYzE6JyNmZjZlYjQnLCBjMjonI2ZmMTQ5MycsCiAgICAgICAgICAgICAgICBiZ092ZXJsYXk6J3JnYmEoMTgsNCwxNCwwLjk3KScsIGJnUGFuZWw6J3JnYmEoMjYsNCwxOCwwLjkzKScsCiAgICAgICAgICAgICAgICBib3JkZXI6J3JnYmEoMjU1LDExMCwxODAsMC4yKScsIGJvcmRlclN0cm9uZzoncmdiYSgyNTUsMTEwLDE4MCwwLjM4KScsCiAgICAgICAgICAgICAgICBib3JkZXJTdWJ0bGU6J3JnYmEoMjU1LDExMCwxODAsMC4xMiknLAogICAgICAgICAgICAgICAgaGVhZGVyQmc6J2xpbmVhci1ncmFkaWVudCgxMzVkZWcscmdiYSgyNTUsMTEwLDE4MCwwLjA5KSxyZ2JhKDI1NSwyMCwxNDcsMC4wNCkpJywKICAgICAgICAgICAgICAgIGdsb3dDb2xvcjoncmdiYSgyNTUsMTEwLDE4MCwwLjQ1KScsIGdsb3dTdHJvbmc6J3JnYmEoMjU1LDExMCwxODAsMC43NSknLAogICAgICAgICAgICAgICAgZ2xvd01pZDoncmdiYSgyNTUsMTEwLDE4MCwwLjIyKScsIGdsb3dTdWJ0bGU6J3JnYmEoMjU1LDIwLDE0NywwLjA3KScsCiAgICAgICAgICAgICAgICBnbG93UHVsc2U6J3JnYmEoMjU1LDExMCwxODAsMC41NSknLAogICAgICAgICAgICAgICAgaW5wdXRCb3JkZXI6J3JnYmEoMjU1LDExMCwxODAsMC40MiknLCBpbnB1dENvbG9yOicjZmZiM2Q5JywKICAgICAgICAgICAgICAgIGZsb2F0R3JhZGllbnQ6J2xpbmVhci1ncmFkaWVudCgxMzVkZWcsI2ZmNmViNCwjZmYxNDkzKScsCiAgICAgICAgICAgICAgICBicmFuZEdyYWRpZW50OidsaW5lYXItZ3JhZGllbnQoOTBkZWcsI2ZmNmViNCwjZmZjY2U4LCNmZjE0OTMsI2ZmNmViNCknLAogICAgICAgICAgICAgICAgc3RhdHVzQm9yZGVyOidyZ2JhKDI1NSwxMTAsMTgwLDAuMiknLCBzdGF0dXNCZzoncmdiYSgyNTUsMjAsMTQ3LDAuMDUpJywKICAgICAgICAgICAgICAgIHBhbmVsSW5zZXQ6J3JnYmEoMjU1LDExMCwxODAsMC4xKScsCiAgICAgICAgICAgICAgICBzZWxlY3RCb3JkZXI6J3JnYmEoMjU1LDExMCwxODAsMC4yKScsIGNvbnNvbGVCb3JkZXI6J3JnYmEoMjU1LDExMCwxODAsMC4xMiknLAogICAgICAgICAgICAgICAgZnhDU1M6YAogICAgICAgICAgICAgICAgICAgICN0bC1wYW5lbCB7IGFuaW1hdGlvbjpzYWt1cmFQYW5lbEdsb3cgM3MgZWFzZS1pbi1vdXQgaW5maW5pdGU7IH0KICAgICAgICAgICAgICAgICAgICAjdGwtY29ubi1wYW5lbCB7IGFuaW1hdGlvbjpzYWt1cmFQYW5lbEdsb3cgM3MgZWFzZS1pbi1vdXQgaW5maW5pdGU7IH0KICAgICAgICAgICAgICAgICAgICBAa2V5ZnJhbWVzIHNha3VyYVBhbmVsR2xvdyB7CiAgICAgICAgICAgICAgICAgICAgICAgIDAlLDEwMCV7IGJveC1zaGFkb3c6MCAwIDYwcHggcmdiYSgwLDAsMCwwLjgpLDAgMCAyNXB4IHJnYmEoMjU1LDExMCwxODAsMC4xKSxpbnNldCAwIDAgMCAxcHggcmdiYSgyNTUsMTEwLDE4MCwwLjA2KTsgfQogICAgICAgICAgICAgICAgICAgICAgICA1MCV7IGJveC1zaGFkb3c6MCAwIDYwcHggcmdiYSgwLDAsMCwwLjgpLDAgMCA0NXB4IHJnYmEoMjU1LDExMCwxODAsMC4yKSxpbnNldCAwIDAgMCAxcHggcmdiYSgyNTUsMTEwLDE4MCwwLjEyKTsgfQogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAuc2FrdXJhLXBldGFsIHsgcG9zaXRpb246YWJzb2x1dGU7IHBvaW50ZXItZXZlbnRzOm5vbmU7IGJvcmRlci1yYWRpdXM6NTAlIDAgNTAlIDA7IGJhY2tncm91bmQ6cmdiYSgyNTUsMTEwLDE4MCwwLjIyKTsgYW5pbWF0aW9uOnNha3VyYURyaWZ0IGxpbmVhciBpbmZpbml0ZTsgfQogICAgICAgICAgICAgICAgICAgIEBrZXlmcmFtZXMgc2FrdXJhRHJpZnQgeyAwJXt0cmFuc2Zvcm06dHJhbnNsYXRlWSgtMTBweCkgcm90YXRlKDBkZWcpO29wYWNpdHk6MC43fSAxMDAle3RyYW5zZm9ybTp0cmFuc2xhdGVZKDQyMHB4KSByb3RhdGUoMjcwZGVnKTtvcGFjaXR5OjB9IH0KICAgICAgICAgICAgICAgICAgICAjdGwtY29ubi1meC1wZXRhbHMgeyBwb3NpdGlvbjphYnNvbHV0ZTt0b3A6MDtsZWZ0OjA7cmlnaHQ6MDtoZWlnaHQ6MTAwJTtwb2ludGVyLWV2ZW50czpub25lO292ZXJmbG93OmhpZGRlbjt6LWluZGV4OjA7Ym9yZGVyLXJhZGl1czoxNnB4OyB9CiAgICAgICAgICAgICAgICBgLAogICAgICAgICAgICAgICAgcGFuZWxFeHRyYTpgPGRpdiBpZD0idGwtY29ubi1meC1wZXRhbHMiPgogICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InNha3VyYS1wZXRhbCIgc3R5bGU9IndpZHRoOjdweDtoZWlnaHQ6N3B4O2xlZnQ6OCU7dG9wOi0xMHB4O2FuaW1hdGlvbi1kdXJhdGlvbjozLjhzO2FuaW1hdGlvbi1kZWxheTowczsiPjwvZGl2PgogICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InNha3VyYS1wZXRhbCIgc3R5bGU9IndpZHRoOjVweDtoZWlnaHQ6NXB4O2xlZnQ6MjglO3RvcDotMTBweDthbmltYXRpb24tZHVyYXRpb246NS4xczthbmltYXRpb24tZGVsYXk6MC45czsiPjwvZGl2PgogICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InNha3VyYS1wZXRhbCIgc3R5bGU9IndpZHRoOjhweDtoZWlnaHQ6OHB4O2xlZnQ6NTUlO3RvcDotMTBweDthbmltYXRpb24tZHVyYXRpb246NC40czthbmltYXRpb24tZGVsYXk6MS43czsiPjwvZGl2PgogICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InNha3VyYS1wZXRhbCIgc3R5bGU9IndpZHRoOjRweDtoZWlnaHQ6NHB4O2xlZnQ6NzUlO3RvcDotMTBweDthbmltYXRpb24tZHVyYXRpb246My4yczthbmltYXRpb24tZGVsYXk6MC40czsiPjwvZGl2PgogICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InNha3VyYS1wZXRhbCIgc3R5bGU9IndpZHRoOjZweDtoZWlnaHQ6NnB4O2xlZnQ6OTIlO3RvcDotMTBweDthbmltYXRpb24tZHVyYXRpb246NC45czthbmltYXRpb24tZGVsYXk6Mi4xczsiPjwvZGl2PgogICAgICAgICAgICAgICAgPC9kaXY+YCwKICAgICAgICAgICAgICAgIHRoZW1lTGFiZWw6J/CfjLggSOG7k25nIFNha3VyYScsCiAgICAgICAgICAgICAgICBwcmV2aWV3Qmc6J2xpbmVhci1ncmFkaWVudCgxMzVkZWcsIzFhMDUxMCwjZmY2ZWI0NTUpJywKICAgICAgICAgICAgICAgIHByZXZpZXdCb3JkZXI6J3JnYmEoMjU1LDExMCwxODAsMC41NSknLAogICAgICAgICAgICAgICAgcHJldmlld1RleHQ6JyNmZjZlYjQnLAogICAgICAgICAgICB9CiAgICAgICAgfTsKICAgICAgICByZXR1cm4gVFt0aGVtZV0gfHwgVC5kZWZhdWx0OwogICAgfQoKICAgIC8vID09PT09PT09PT0gQ1NTIExPQ0sgU0NSRUVOIOKAlCBnaeG7kW5nIGNvcmUgPT09PT09PT09PQogICAgZnVuY3Rpb24gZ2V0TG9ja1NjcmVlblN0eWxlcygpIHsKICAgICAgICBjb25zdCB0YyA9IGdldFRoZW1lQ29sb3JzKENVUlJFTlRfVEhFTUUpOwogICAgICAgIHJldHVybiBgCiAgICAgICAgICAgIEBpbXBvcnQgdXJsKCdodHRwczovL2ZvbnRzLmdvb2dsZWFwaXMuY29tL2NzczI/ZmFtaWx5PU9yYml0cm9uOndnaHRANDAwOzcwMDs5MDAmZmFtaWx5PVNoYXJlK1RlY2grTW9ubyZmYW1pbHk9UmFqZGhhbmk6d2dodEA0MDA7NjAwOzcwMCZkaXNwbGF5PXN3YXAnKTsKICAgICAgICAgICAgI3RsLWNvbm4tb3ZlcmxheSB7IHBvc2l0aW9uOmZpeGVkO3RvcDowO2xlZnQ6MDt3aWR0aDoxMDB2dztoZWlnaHQ6MTAwdmg7YmFja2dyb3VuZDoke3RjLmJnT3ZlcmxheX07YmFja2Ryb3AtZmlsdGVyOmJsdXIoMTVweCk7ei1pbmRleDoyMTQ3NDgzNjQ3O2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OmNlbnRlcjtmb250LWZhbWlseTonUmFqZGhhbmknLHNhbnMtc2VyaWY7IH0KICAgICAgICAgICAgI3RsLWNvbm4tcGFuZWwgeyB3aWR0aDo0MjBweDtiYWNrZ3JvdW5kOiR7dGMuYmdQYW5lbH07Ym9yZGVyOjFweCBzb2xpZCAke3RjLmJvcmRlclN0cm9uZ307Ym9yZGVyLXJhZGl1czoyMHB4O2JveC1zaGFkb3c6MCAwIDYwcHggcmdiYSgwLDAsMCwwLjgpLDAgMCAwIDFweCAke3RjLnBhbmVsSW5zZXR9IGluc2V0O3RleHQtYWxpZ246Y2VudGVyO292ZXJmbG93OmhpZGRlbjthbmltYXRpb246dGxGYWRlSW4gMC4zcyBlYXNlO3Bvc2l0aW9uOnJlbGF0aXZlOyB9CiAgICAgICAgICAgIEBrZXlmcmFtZXMgdGxGYWRlSW4geyBmcm9te29wYWNpdHk6MDt0cmFuc2Zvcm06c2NhbGUoMC45NSl9dG97b3BhY2l0eToxO3RyYW5zZm9ybTpzY2FsZSgxKX0gfQogICAgICAgICAgICAjdGwtY29ubi1oZWFkZXIgeyBwYWRkaW5nOjIycHg7YmFja2dyb3VuZDoke3RjLmhlYWRlckJnfTtib3JkZXItYm90dG9tOjFweCBzb2xpZCAke3RjLmJvcmRlcn07IH0KICAgICAgICAgICAgLnRsLWJyYW5kLW5hbWUgeyBmb250LWZhbWlseTonT3JiaXRyb24nLHNhbnMtc2VyaWY7Zm9udC1zaXplOjIycHg7Zm9udC13ZWlnaHQ6NzAwO2JhY2tncm91bmQ6JHt0Yy5icmFuZEdyYWRpZW50fTtiYWNrZ3JvdW5kLXNpemU6MjAwJTstd2Via2l0LWJhY2tncm91bmQtY2xpcDp0ZXh0Oy13ZWJraXQtdGV4dC1maWxsLWNvbG9yOnRyYW5zcGFyZW50O2FuaW1hdGlvbjp0bFNoaW1tZXIgM3MgbGluZWFyIGluZmluaXRlOyB9CiAgICAgICAgICAgIEBrZXlmcmFtZXMgdGxTaGltbWVyIHsgMTAwJXtiYWNrZ3JvdW5kLXBvc2l0aW9uOjIwMCUgNTAlfSB9CiAgICAgICAgICAgICN0bC1jb25uLWJvZHkgeyBwYWRkaW5nOjMwcHggMjVweDsgfQogICAgICAgICAgICAudGwtc3VidGl0bGUgeyBjb2xvcjpyZ2JhKDI1NSwyNTUsMjU1LDAuNyk7Zm9udC1zaXplOjEzcHg7bWFyZ2luLWJvdHRvbToxMHB4O2ZvbnQtZmFtaWx5OidTaGFyZSBUZWNoIE1vbm8nOyB9CiAgICAgICAgICAgIC50bC13YXJuaW5nIHsgY29sb3I6I2ZmYzEwNztmb250LXNpemU6MTJweDttYXJnaW4tYm90dG9tOjIwcHg7YmFja2dyb3VuZDpyZ2JhKDI1NSwxOTMsNywwLjEpO3BhZGRpbmc6OHB4O2JvcmRlci1yYWRpdXM6NnB4OyB9CiAgICAgICAgICAgIC50bC1pbnB1dCB7IHdpZHRoOjEwMCU7cGFkZGluZzoxNHB4O2JhY2tncm91bmQ6cmdiYSgwLDAsMCwwLjU1KTtib3JkZXI6MXB4IHNvbGlkICR7dGMuaW5wdXRCb3JkZXJ9O2JvcmRlci1yYWRpdXM6MTBweDtjb2xvcjoke3RjLmlucHV0Q29sb3J9O2ZvbnQtZmFtaWx5OidTaGFyZSBUZWNoIE1vbm8nO2ZvbnQtc2l6ZToxNnB4O3RleHQtYWxpZ246Y2VudGVyO21hcmdpbi1ib3R0b206MTVweDt0cmFuc2l0aW9uOjAuMnM7Ym94LXNpemluZzpib3JkZXItYm94OyB9CiAgICAgICAgICAgIC50bC1pbnB1dDpmb2N1cyB7IG91dGxpbmU6bm9uZTtib3JkZXItY29sb3I6JHt0Yy5jMX07Ym94LXNoYWRvdzowIDAgMTZweCAke3RjLmdsb3dNaWR9OyB9CiAgICAgICAgICAgIC50bC1idG4geyB3aWR0aDoxMDAlO3BhZGRpbmc6MTRweDtib3JkZXI6bm9uZTtib3JkZXItcmFkaXVzOjEwcHg7Y3Vyc29yOnBvaW50ZXI7Zm9udC1mYW1pbHk6J09yYml0cm9uJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZToxNHB4O2ZvbnQtd2VpZ2h0OjkwMDttYXJnaW4tYm90dG9tOjEycHg7dHJhbnNpdGlvbjowLjJzOyB9CiAgICAgICAgICAgIC50bC1idG4tdW5sb2NrIHsgYmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLCMwMGIwOWIsIzk2YzkzZCk7Y29sb3I6I2ZmZjsgfQogICAgICAgICAgICAudGwtYnRuLXVubG9jazpob3ZlciB7IHRyYW5zZm9ybTpzY2FsZSgxLjAyKTtib3gtc2hhZG93OjAgMCAyNXB4IHJnYmEoMCwxNzYsMTU1LDAuNik7IH0KICAgICAgICAgICAgLnRsLWJ0bi12aXAgeyBiYWNrZ3JvdW5kOnJnYmEoMjE3LDQsNDEsMC4xKTtib3JkZXI6MXB4IHNvbGlkIHJnYmEoMjE3LDQsNDEsMC41KTtjb2xvcjojZWYyMzNjOyB9CiAgICAgICAgICAgIC50bC1idG4tdmlwOmhvdmVyIHsgYmFja2dyb3VuZDpyZ2JhKDIxNyw0LDQxLDAuMik7dHJhbnNmb3JtOnNjYWxlKDEuMDEpOyB9CiAgICAgICAgICAgICN0bC1lcnIgeyBjb2xvcjojZWYyMzNjO2ZvbnQtc2l6ZToxM3B4O21hcmdpbi10b3A6MTJweDtkaXNwbGF5Om5vbmU7Zm9udC1mYW1pbHk6J1NoYXJlIFRlY2ggTW9ubyc7YmFja2dyb3VuZDpyZ2JhKDIzOSwzNSw2MCwwLjEpO3BhZGRpbmc6OHB4O2JvcmRlci1yYWRpdXM6NnB4OyB9CiAgICAgICAgICAgIC50bC1od2lkIHsgY29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjIyKTtmb250LXNpemU6MTBweDttYXJnaW4tdG9wOjE1cHg7d29yZC1icmVhazpicmVhay1hbGw7Zm9udC1mYW1pbHk6bW9ub3NwYWNlOyB9CiAgICAgICAgICAgIC50bC1mb290IHsgbWFyZ2luLXRvcDoxNXB4O2ZvbnQtc2l6ZToxMXB4O2NvbG9yOnJnYmEoMjU1LDI1NSwyNTUsMC4xMyk7IH0KICAgICAgICAgICAgJHt0Yy5meENTU30KICAgICAgICBgOwogICAgfQoKICAgIC8vID09PT09PT09PT0gQ1NTIE1BSU4gVUkg4oCUIGdp4buRbmcgY29yZSA9PT09PT09PT09CiAgICBmdW5jdGlvbiBnZXRNYWluVUlTdHlsZXMoKSB7CiAgICAgICAgY29uc3QgdGMgPSBnZXRUaGVtZUNvbG9ycyhDVVJSRU5UX1RIRU1FKTsKICAgICAgICByZXR1cm4gYAogICAgICAgICAgICBAaW1wb3J0IHVybCgnaHR0cHM6Ly9mb250cy5nb29nbGVhcGlzLmNvbS9jc3MyP2ZhbWlseT1PcmJpdHJvbjp3Z2h0QDQwMDs3MDA7OTAwJmZhbWlseT1TaGFyZStUZWNoK01vbm8mZmFtaWx5PVJhamRoYW5pOndnaHRANDAwOzYwMDs3MDAmZGlzcGxheT1zd2FwJyk7CiAgICAgICAgICAgICN0bC1mbG9hdEJ0biB7IHBvc2l0aW9uOmZpeGVkO2JvdHRvbToyOHB4O3JpZ2h0OjI4cHg7d2lkdGg6NTZweDtoZWlnaHQ6NTZweDtib3JkZXItcmFkaXVzOjUwJTtib3JkZXI6bm9uZTtjdXJzb3I6cG9pbnRlcjt6LWluZGV4OjEwMDAwO2JhY2tncm91bmQ6JHt0Yy5mbG9hdEdyYWRpZW50fTtib3gtc2hhZG93OjAgMCAwIDAgJHt0Yy5nbG93U3Ryb25nfSwwIDAgMjBweCAke3RjLmdsb3dDb2xvcn0sMCA0cHggMjBweCByZ2JhKDAsMCwwLDAuNSk7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyO2ZvbnQtc2l6ZToyMnB4O3RyYW5zaXRpb246dHJhbnNmb3JtIDAuMnMgZWFzZSxib3gtc2hhZG93IDAuMnMgZWFzZTthbmltYXRpb246Y29ublB1bHNlUmluZyAyLjVzIGVhc2Utb3V0IGluZmluaXRlOyB9CiAgICAgICAgICAgICN0bC1mbG9hdEJ0bjpob3ZlciB7IHRyYW5zZm9ybTpzY2FsZSgxLjEyKSByb3RhdGUoMTVkZWcpOyB9CiAgICAgICAgICAgIEBrZXlmcmFtZXMgY29ublB1bHNlUmluZyB7IDAle2JveC1zaGFkb3c6MCAwIDAgMCAke3RjLmdsb3dQdWxzZX19NzAle2JveC1zaGFkb3c6MCAwIDAgMTVweCByZ2JhKDAsMCwwLDApfTEwMCV7Ym94LXNoYWRvdzowIDAgMCAwIHJnYmEoMCwwLDAsMCl9IH0KICAgICAgICAgICAgQGtleWZyYW1lcyBjb25uQmxpbmsgeyAwJSwxMDAle29wYWNpdHk6MX01MCV7b3BhY2l0eTowLjN9IH0KICAgICAgICAgICAgI3RsLXBhbmVsIHsgcG9zaXRpb246Zml4ZWQ7dG9wOjUwJTtsZWZ0OjUwJTt0cmFuc2Zvcm06dHJhbnNsYXRlKC01MCUsLTUwJSk7d2lkdGg6MzYwcHg7YmFja2dyb3VuZDoke3RjLmJnUGFuZWx9O2JhY2tkcm9wLWZpbHRlcjpibHVyKDI0cHgpO2JvcmRlcjoxcHggc29saWQgJHt0Yy5ib3JkZXJ9O2JvcmRlci1yYWRpdXM6MTZweDtib3gtc2hhZG93OjAgMCA2MHB4IHJnYmEoMCwwLDAsMC44KTt6LWluZGV4Ojk5OTk7b3ZlcmZsb3c6aGlkZGVuO2ZvbnQtZmFtaWx5OidSYWpkaGFuaScsc2Fucy1zZXJpZjsgfQogICAgICAgICAgICAjdGwtcGFuZWwuaGlkZGVuIHsgZGlzcGxheTpub25lOyB9CiAgICAgICAgICAgICN0bC1wLWhlYWRlciB7IGN1cnNvcjptb3ZlO3BhZGRpbmc6MTRweCAxNnB4IDEycHg7YmFja2dyb3VuZDoke3RjLmhlYWRlckJnfTtib3JkZXItYm90dG9tOjFweCBzb2xpZCAke3RjLmJvcmRlclN1YnRsZX07ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2VlbjsgfQogICAgICAgICAgICAudGwtcC1icmFuZCB7IGRpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjhweDsgfQogICAgICAgICAgICAudGwtcC1uYW1lIHsgZm9udC1mYW1pbHk6J09yYml0cm9uJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZToxMS41cHg7Zm9udC13ZWlnaHQ6NzAwO2JhY2tncm91bmQ6JHt0Yy5icmFuZEdyYWRpZW50fTtiYWNrZ3JvdW5kLXNpemU6MjAwJTstd2Via2l0LWJhY2tncm91bmQtY2xpcDp0ZXh0Oy13ZWJraXQtdGV4dC1maWxsLWNvbG9yOnRyYW5zcGFyZW50O2FuaW1hdGlvbjp0bFNoaW1tZXIgM3MgbGluZWFyIGluZmluaXRlOyB9CiAgICAgICAgICAgIEBrZXlmcmFtZXMgdGxTaGltbWVyIHsgMTAwJXtiYWNrZ3JvdW5kLXBvc2l0aW9uOjIwMCUgNTAlfSB9CiAgICAgICAgICAgIC50bC1iYWRnZSB7IGZvbnQtZmFtaWx5OidPcmJpdHJvbic7Zm9udC1zaXplOjcuNXB4O2ZvbnQtd2VpZ2h0OjkwMDtjb2xvcjojZmZmO2JvcmRlci1yYWRpdXM6NHB4O3BhZGRpbmc6M3B4IDZweDtiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCgxMzVkZWcsIzU1NSwjNzc3KTsgfQogICAgICAgICAgICAudGwtYmFkZ2UudmlwIHsgYmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLCNhODU1ZjcsIzYzNjZmMSk7Ym94LXNoYWRvdzowIDAgMTBweCByZ2JhKDE2OCw4NSwyNDcsMC40KTsgfQogICAgICAgICAgICAudGwtYmFkZ2UudW5saW1pdGVkIHsgYmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLCNmNTllMGIsI2VmNDQ0NCk7Ym94LXNoYWRvdzowIDAgMTBweCByZ2JhKDI0NSwxNTgsMTEsMC40KTsgfQogICAgICAgICAgICAjdGwtY2xvc2VCdG4sI3RsLXNldHRpbmdzQnRuIHsgd2lkdGg6MjhweDtoZWlnaHQ6MjhweDtib3JkZXItcmFkaXVzOjUwJTtib3JkZXI6MXB4IHNvbGlkIHJnYmEoMjU1LDI1NSwyNTUsMC4xKTtiYWNrZ3JvdW5kOnJnYmEoMjU1LDI1NSwyNTUsMC4wNCk7Y29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjUpO2N1cnNvcjpwb2ludGVyO2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OmNlbnRlcjt0cmFuc2l0aW9uOjAuMnM7Zm9udC1zaXplOjEzcHg7IH0KICAgICAgICAgICAgI3RsLWNsb3NlQnRuOmhvdmVyIHsgYm9yZGVyLWNvbG9yOnJnYmEoMjE3LDQsNDEsMC42KTtiYWNrZ3JvdW5kOnJnYmEoMjE3LDQsNDEsMC4xNSk7Y29sb3I6I2VmMjMzYzsgfQogICAgICAgICAgICAjdGwtc2V0dGluZ3NCdG46aG92ZXIgeyBib3JkZXItY29sb3I6JHt0Yy5ib3JkZXJTdHJvbmd9O2JhY2tncm91bmQ6JHt0Yy5nbG93U3VidGxlfTtjb2xvcjoke3RjLmMxfTsgfQogICAgICAgICAgICAjdGwtc2V0dGluZ3NCdG4uYWN0aXZlIHsgYm9yZGVyLWNvbG9yOiR7dGMuYzF9O2JhY2tncm91bmQ6JHt0Yy5nbG93U3VidGxlfTtjb2xvcjoke3RjLmMxfTsgfQogICAgICAgICAgICAjdGwtcC1ib2R5IHsgcGFkZGluZzoxNHB4O2Rpc3BsYXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47Z2FwOjEycHg7IH0KICAgICAgICAgICAgLnRsLXN0YXRib3ggeyBib3JkZXI6MXB4IHNvbGlkICR7dGMuc3RhdHVzQm9yZGVyfTtib3JkZXItcmFkaXVzOjEwcHg7cGFkZGluZzoxMHB4O2JhY2tncm91bmQ6JHt0Yy5zdGF0dXNCZ307IH0KICAgICAgICAgICAgLnRsLXN0YXRyb3cgeyBkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDo4cHg7Zm9udC1mYW1pbHk6J1NoYXJlIFRlY2ggTW9ubycsbW9ub3NwYWNlO2ZvbnQtc2l6ZToxMS41cHg7Y29sb3I6I2NjYzttYXJnaW4tdG9wOjRweDsgfQogICAgICAgICAgICAjdGwtbW9kZVNlbGVjdCB7IHdpZHRoOjEwMCU7cGFkZGluZzoxMHB4O2JhY2tncm91bmQ6cmdiYSgwLDAsMCwwLjQpO2JvcmRlcjoxcHggc29saWQgJHt0Yy5zZWxlY3RCb3JkZXJ9O2JvcmRlci1yYWRpdXM6OHB4O2NvbG9yOiNmZmY7Zm9udC1mYW1pbHk6J1JhamRoYW5pJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZToxNHB4O291dGxpbmU6bm9uZTttYXJnaW4tdG9wOjVweDsgfQogICAgICAgICAgICAudGwtZ29kLWlucHV0IHsgd2lkdGg6MTAwJTtwYWRkaW5nOjEwcHg7YmFja2dyb3VuZDpyZ2JhKDAsMCwwLDAuNCk7Ym9yZGVyOjFweCBzb2xpZCByZ2JhKDI1NSwxOTMsNywwLjMpO2JvcmRlci1yYWRpdXM6OHB4O2NvbG9yOiNmZmMxMDc7Zm9udC1mYW1pbHk6J1NoYXJlIFRlY2ggTW9ubyc7Zm9udC1zaXplOjEzcHg7b3V0bGluZTpub25lO21hcmdpbi10b3A6NXB4O2JveC1zaXppbmc6Ym9yZGVyLWJveDsgfQogICAgICAgICAgICAjdGwtZmlyZUJ0biB7IHdpZHRoOjEwMCU7cGFkZGluZzoxM3B4O2JhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDEzNWRlZywjZDkwNDI5LCNlZjIzM2MpO2JvcmRlcjpub25lO2JvcmRlci1yYWRpdXM6MTBweDtjb2xvcjojZmZmO2ZvbnQtZmFtaWx5OidPcmJpdHJvbic7Zm9udC13ZWlnaHQ6OTAwO2ZvbnQtc2l6ZToxNHB4O2N1cnNvcjpwb2ludGVyO2JveC1zaGFkb3c6MCAwIDIwcHggcmdiYSgyMTcsNCw0MSwwLjQpO3RyYW5zaXRpb246MC4yczttYXJnaW4tdG9wOjVweDsgfQogICAgICAgICAgICAjdGwtZmlyZUJ0bjpob3ZlciB7IGJveC1zaGFkb3c6MCAwIDMwcHggcmdiYSgyMTcsNCw0MSwwLjcpOyB9CiAgICAgICAgICAgICN0bC1maXJlQnRuOmRpc2FibGVkIHsgb3BhY2l0eTowLjU7Y3Vyc29yOm5vdC1hbGxvd2VkOyB9CiAgICAgICAgICAgIC50bC1jb25zb2xlIHsgYm9yZGVyOjFweCBzb2xpZCAke3RjLmNvbnNvbGVCb3JkZXJ9O2JvcmRlci1yYWRpdXM6MTBweDtiYWNrZ3JvdW5kOnJnYmEoMCwwLDAsMC41KTtwYWRkaW5nOjhweDtoZWlnaHQ6ODBweDtvdmVyZmxvdy15OmF1dG87Zm9udC1mYW1pbHk6J1NoYXJlIFRlY2ggTW9ubyc7Zm9udC1zaXplOjEwLjVweDtjb2xvcjojYWFhOyB9CiAgICAgICAgICAgIC50bC1sb2cgeyBtYXJnaW4tYm90dG9tOjJweDsgfQogICAgICAgICAgICAudGwtbG9nLm9rICAgeyBjb2xvcjojMDBlNjc2OyB9CiAgICAgICAgICAgIC50bC1sb2cuZXJyICB7IGNvbG9yOiNlZjIzM2M7IH0KICAgICAgICAgICAgLnRsLWxvZy53YXJuIHsgY29sb3I6I2ZmYzEwNzsgfQogICAgICAgICAgICAudGwtbG9nLmluZm8geyBjb2xvcjojNGZhY2ZlOyB9CiAgICAgICAgICAgICN0bC1wLWZvb3RlciB7IHBhZGRpbmc6OHB4IDE0cHg7Ym9yZGVyLXRvcDoxcHggc29saWQgJHt0Yy5ib3JkZXJTdWJ0bGV9O2Rpc3BsYXk6ZmxleDtqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2Vlbjtmb250LWZhbWlseTonU2hhcmUgVGVjaCBNb25vJztmb250LXNpemU6OXB4O2NvbG9yOnJnYmEoMjU1LDI1NSwyNTUsMC4yKTsgfQogICAgICAgICAgICAvKiDilIDilIAgU2V0dGluZ3MgT3ZlcmxheSDilIDilIAgKi8KICAgICAgICAgICAgI3RsLXNvIHsgcG9zaXRpb246YWJzb2x1dGU7dG9wOjA7bGVmdDowO3JpZ2h0OjA7Ym90dG9tOjA7YmFja2dyb3VuZDoke3RjLmJnUGFuZWx9O2JhY2tkcm9wLWZpbHRlcjpibHVyKDEycHgpO3otaW5kZXg6MjA7Ym9yZGVyLXJhZGl1czoxNnB4O2Rpc3BsYXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47b3ZlcmZsb3c6aGlkZGVuOyB9CiAgICAgICAgICAgICN0bC1zby5oaWRkZW4geyBkaXNwbGF5Om5vbmU7IH0KICAgICAgICAgICAgLnRsLXNvLWhkciB7IHBhZGRpbmc6MTNweCAxNnB4O2JhY2tncm91bmQ6JHt0Yy5oZWFkZXJCZ307Ym9yZGVyLWJvdHRvbToxcHggc29saWQgJHt0Yy5ib3JkZXJTdWJ0bGV9O2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47ZmxleC1zaHJpbms6MDsgfQogICAgICAgICAgICAudGwtc28tdGl0bGUgeyBmb250LWZhbWlseTonT3JiaXRyb24nLHNhbnMtc2VyaWY7Zm9udC1zaXplOjEwLjVweDtmb250LXdlaWdodDo3MDA7Y29sb3I6JHt0Yy5jMX07IH0KICAgICAgICAgICAgI3RsLXNvQ2xvc2UgeyB3aWR0aDoyNnB4O2hlaWdodDoyNnB4O2JvcmRlci1yYWRpdXM6NTAlO2JvcmRlcjoxcHggc29saWQgJHt0Yy5ib3JkZXJ9O2JhY2tncm91bmQ6JHt0Yy5nbG93U3VidGxlfTtjb2xvcjoke3RjLmMxfTtjdXJzb3I6cG9pbnRlcjtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpjZW50ZXI7Zm9udC1zaXplOjEycHg7dHJhbnNpdGlvbjowLjJzOyB9CiAgICAgICAgICAgICN0bC1zb0Nsb3NlOmhvdmVyIHsgYmFja2dyb3VuZDpyZ2JhKDIxNyw0LDQxLDAuMTUpO2JvcmRlci1jb2xvcjpyZ2JhKDIxNyw0LDQxLDAuNSk7Y29sb3I6I2VmMjMzYzsgfQogICAgICAgICAgICAudGwtc28tYm9keSB7IHBhZGRpbmc6MTRweDtmbGV4OjE7ZGlzcGxheTpmbGV4O2ZsZXgtZGlyZWN0aW9uOmNvbHVtbjtnYXA6MTJweDtvdmVyZmxvdy15OmF1dG87IH0KICAgICAgICAgICAgLnRsLXNvLWxibCB7IGZvbnQtc2l6ZTo5LjVweDtmb250LXdlaWdodDo3MDA7Y29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjI4KTt0ZXh0LXRyYW5zZm9ybTp1cHBlcmNhc2U7Zm9udC1mYW1pbHk6J09yYml0cm9uJztsZXR0ZXItc3BhY2luZzoxLjJweDttYXJnaW4tYm90dG9tOjJweDsgfQogICAgICAgICAgICAudGwtdGhlbWUtY2FyZHMgeyBkaXNwbGF5OmZsZXg7Z2FwOjhweDsgfQogICAgICAgICAgICAudGwtdGMgeyBmbGV4OjE7Y3Vyc29yOnBvaW50ZXI7Ym9yZGVyLXJhZGl1czoxMHB4O2JvcmRlcjoycHggc29saWQgcmdiYSgyNTUsMjU1LDI1NSwwLjA3KTtwYWRkaW5nOjhweCA2cHg7dGV4dC1hbGlnbjpjZW50ZXI7dHJhbnNpdGlvbjphbGwgMC4yMnM7YmFja2dyb3VuZDpyZ2JhKDAsMCwwLDAuMyk7cG9zaXRpb246cmVsYXRpdmU7IH0KICAgICAgICAgICAgLnRsLXRjOmhvdmVyIHsgdHJhbnNmb3JtOnRyYW5zbGF0ZVkoLTNweCk7Ym9yZGVyLWNvbG9yOnJnYmEoMjU1LDI1NSwyNTUsMC4xOCk7Ym94LXNoYWRvdzowIDZweCAxOHB4IHJnYmEoMCwwLDAsMC40KTsgfQogICAgICAgICAgICAudGwtdGMuYWN0aXZlIHsgYm9yZGVyLWNvbG9yOiR7dGMuYzF9O2JveC1zaGFkb3c6MCAwIDE0cHggJHt0Yy5nbG93TWlkfTsgfQogICAgICAgICAgICAudGwtdGMtcHJldiB7IHdpZHRoOjEwMCU7aGVpZ2h0OjM4cHg7Ym9yZGVyLXJhZGl1czo3cHg7bWFyZ2luLWJvdHRvbTo3cHg7b3ZlcmZsb3c6aGlkZGVuO3Bvc2l0aW9uOnJlbGF0aXZlOyB9CiAgICAgICAgICAgIC50bC10Yy1wcmV2LWlubmVyIHsgcG9zaXRpb246YWJzb2x1dGU7aW5zZXQ6MDtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpjZW50ZXI7IH0KICAgICAgICAgICAgLnRsLXRjLXByZXYtdGV4dCB7IGZvbnQtZmFtaWx5OidPcmJpdHJvbicsc2Fucy1zZXJpZjtmb250LXNpemU6N3B4O2ZvbnQtd2VpZ2h0OjcwMDtsZXR0ZXItc3BhY2luZzoxcHg7b3BhY2l0eTowLjk7IH0KICAgICAgICAgICAgLnRsLXRjLWxibCB7IGZvbnQtZmFtaWx5OidSYWpkaGFuaScsc2Fucy1zZXJpZjtmb250LXNpemU6MTAuNXB4O2ZvbnQtd2VpZ2h0OjYwMDtjb2xvcjpyZ2JhKDI1NSwyNTUsMjU1LDAuNik7IH0KICAgICAgICAgICAgLnRsLXRjLmFjdGl2ZSAudGwtdGMtbGJsIHsgY29sb3I6JHt0Yy5jMX07Zm9udC13ZWlnaHQ6NzAwOyB9CiAgICAgICAgICAgIC50bC10Yy5hY3RpdmU6OmFmdGVyIHsgY29udGVudDon4pyTJztwb3NpdGlvbjphYnNvbHV0ZTt0b3A6NXB4O3JpZ2h0OjdweDtjb2xvcjoke3RjLmMxfTtmb250LXNpemU6MTFweDtmb250LXdlaWdodDo5MDA7IH0KICAgICAgICAgICAgLnRsLXNvLWRpdmlkZXIgeyBoZWlnaHQ6MXB4O2JhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDkwZGVnLHRyYW5zcGFyZW50LCR7dGMuYm9yZGVyfSx0cmFuc3BhcmVudCk7IH0KICAgICAgICAgICAgLnRsLWhpbnQgeyBmb250LXNpemU6MTBweDtjb2xvcjpyZ2JhKDI1NSwyNTUsMjU1LDAuMik7Zm9udC1mYW1pbHk6J1NoYXJlIFRlY2ggTW9ubyc7dGV4dC1hbGlnbjpjZW50ZXI7bGluZS1oZWlnaHQ6MS42OyB9CiAgICAgICAgICAgIC50bC1jaGFuZ2Uta2V5IHsgd2lkdGg6MTAwJTtwYWRkaW5nOjEwcHg7YmFja2dyb3VuZDpyZ2JhKDIzOSwzNSw2MCwwLjEpO2JvcmRlcjoxcHggc29saWQgcmdiYSgyMzksMzUsNjAsMC4zOCk7Ym9yZGVyLXJhZGl1czo4cHg7Y29sb3I6I2VmMjMzYztmb250LWZhbWlseTonT3JiaXRyb24nLHNhbnMtc2VyaWY7Zm9udC1zaXplOjEwLjVweDtmb250LXdlaWdodDo3MDA7Y3Vyc29yOnBvaW50ZXI7dHJhbnNpdGlvbjowLjJzO2xldHRlci1zcGFjaW5nOjAuNXB4OyB9CiAgICAgICAgICAgIC50bC1jaGFuZ2Uta2V5OmhvdmVyIHsgYmFja2dyb3VuZDpyZ2JhKDIzOSwzNSw2MCwwLjIpO2JvcmRlci1jb2xvcjpyZ2JhKDIzOSwzNSw2MCwwLjY1KTtib3gtc2hhZG93OjAgMCAxNHB4IHJnYmEoMjM5LDM1LDYwLDAuMjUpOyB9CiAgICAgICAgICAgIC8qIOKUgOKUgCBDdXN0b20gTW9kYWwg4pSA4pSAICovCiAgICAgICAgICAgICN0aWVwLW1vZGFsLW92ZXJsYXkgeyBwb3NpdGlvbjpmaXhlZDt0b3A6MDtsZWZ0OjA7d2lkdGg6MTAwdnc7aGVpZ2h0OjEwMHZoO2JhY2tncm91bmQ6cmdiYSgwLDAsMCwwLjcyKTt6LWluZGV4OjIxNDc0ODM2NDY7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyOyB9CiAgICAgICAgICAgIC50aWVwLW1vZGFsLWJveCB7IHdpZHRoOjMyMHB4O2JhY2tncm91bmQ6JHt0Yy5iZ1BhbmVsfTtib3JkZXI6MXB4IHNvbGlkICR7dGMuYm9yZGVyU3Ryb25nfTtib3JkZXItcmFkaXVzOjE2cHg7cGFkZGluZzoyNnB4IDIycHggMjJweDt0ZXh0LWFsaWduOmNlbnRlcjtib3gtc2hhZG93OjAgMCA2MHB4IHJnYmEoMCwwLDAsMC45KSxpbnNldCAwIDAgMCAxcHggJHt0Yy5wYW5lbEluc2V0fTtmb250LWZhbWlseTonUmFqZGhhbmknLHNhbnMtc2VyaWY7IH0KICAgICAgICAgICAgLnRpZXAtbW9kYWwtaWNvbiB7IGZvbnQtc2l6ZTozOHB4O21hcmdpbi1ib3R0b206OHB4OyB9CiAgICAgICAgICAgIC50aWVwLW1vZGFsLXRpdGxlIHsgZm9udC1mYW1pbHk6J09yYml0cm9uJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZToxMnB4O2ZvbnQtd2VpZ2h0OjcwMDtjb2xvcjoke3RjLmMxfTttYXJnaW4tYm90dG9tOjEycHg7bGluZS1oZWlnaHQ6MS41OyB9CiAgICAgICAgICAgIC50aWVwLW1vZGFsLWxpbmVzIHsgY29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjc4KTtmb250LXNpemU6MTNweDtsaW5lLWhlaWdodDoxLjY1O21hcmdpbi1ib3R0b206MThweDsgfQogICAgICAgICAgICAudGllcC1tb2RhbC1saW5lcyBiIHsgY29sb3I6I2ZmZjsgfQogICAgICAgICAgICAudGllcC1tb2RhbC1vayB7IHBhZGRpbmc6MTBweCAzNnB4O2JhY2tncm91bmQ6JHt0Yy5mbG9hdEdyYWRpZW50fTtib3JkZXI6bm9uZTtib3JkZXItcmFkaXVzOjhweDtjb2xvcjojZmZmO2ZvbnQtZmFtaWx5OidPcmJpdHJvbicsc2Fucy1zZXJpZjtmb250LXNpemU6MTEuNXB4O2ZvbnQtd2VpZ2h0OjkwMDtjdXJzb3I6cG9pbnRlcjt0cmFuc2l0aW9uOjAuMnM7Ym94LXNoYWRvdzowIDRweCAxNnB4ICR7dGMuZ2xvd0NvbG9yfTsgfQogICAgICAgICAgICAudGllcC1tb2RhbC1vazpob3ZlciB7IHRyYW5zZm9ybTpzY2FsZSgxLjA2KTtib3gtc2hhZG93OjAgMCAyNHB4ICR7dGMuZ2xvd0NvbG9yfTsgfQogICAgICAgICAgICAke3RjLmZ4Q1NTfQogICAgICAgIGA7CiAgICB9CgogICAgLy8gPT09PT09PT09PSBDVVNUT00gTU9EQUwg4oCUIGdp4buRbmcgY29yZSA9PT09PT09PT09CiAgICBmdW5jdGlvbiBfZW5zdXJlTW9kYWxTdHlsZSgpIHsKICAgICAgICBpZiAoZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RpZXAtbW9kYWwtc3R5bGUnKSkgcmV0dXJuOwogICAgICAgIGNvbnN0IHRjID0gZ2V0VGhlbWVDb2xvcnMoQ1VSUkVOVF9USEVNRSk7CiAgICAgICAgY29uc3QgbXMgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdzdHlsZScpOwogICAgICAgIG1zLmlkID0gJ3RpZXAtbW9kYWwtc3R5bGUnOwogICAgICAgIG1zLnRleHRDb250ZW50ID0gYAogICAgICAgICAgICBAa2V5ZnJhbWVzIHRsTW9kYWxJbntmcm9te29wYWNpdHk6MDt0cmFuc2Zvcm06c2NhbGUoMC45Mil9dG97b3BhY2l0eToxO3RyYW5zZm9ybTpzY2FsZSgxKX19CiAgICAgICAgICAgICN0aWVwLW1vZGFsLW92ZXJsYXl7cG9zaXRpb246Zml4ZWQhaW1wb3J0YW50O3RvcDowIWltcG9ydGFudDtsZWZ0OjAhaW1wb3J0YW50O3dpZHRoOjEwMHZ3IWltcG9ydGFudDtoZWlnaHQ6MTAwdmghaW1wb3J0YW50O2JhY2tncm91bmQ6cmdiYSgwLDAsMCwwLjc1KSFpbXBvcnRhbnQ7ei1pbmRleDoyMTQ3NDgzNjQ2IWltcG9ydGFudDtkaXNwbGF5OmZsZXghaW1wb3J0YW50O2FsaWduLWl0ZW1zOmNlbnRlciFpbXBvcnRhbnQ7anVzdGlmeS1jb250ZW50OmNlbnRlciFpbXBvcnRhbnQ7fQogICAgICAgICAgICAudGllcC1tb2RhbC1ib3h7d2lkdGg6MzIwcHg7bWF4LXdpZHRoOjkwdnc7YmFja2dyb3VuZDoke3RjLmJnUGFuZWx9O2JvcmRlcjoxcHggc29saWQgJHt0Yy5ib3JkZXJTdHJvbmd9O2JvcmRlci1yYWRpdXM6MTZweDtwYWRkaW5nOjI2cHggMjJweCAyMnB4O3RleHQtYWxpZ246Y2VudGVyO2JveC1zaGFkb3c6MCAwIDYwcHggcmdiYSgwLDAsMCwwLjkpLGluc2V0IDAgMCAwIDFweCAke3RjLnBhbmVsSW5zZXR9O2ZvbnQtZmFtaWx5OidSYWpkaGFuaScsc2Fucy1zZXJpZjthbmltYXRpb246dGxNb2RhbEluIDAuMjJzIGVhc2U7fQogICAgICAgICAgICAudGllcC1tb2RhbC1pY29ue2ZvbnQtc2l6ZTozOHB4O21hcmdpbi1ib3R0b206OHB4O30KICAgICAgICAgICAgLnRpZXAtbW9kYWwtdGl0bGV7Zm9udC1mYW1pbHk6J09yYml0cm9uJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZToxMnB4O2ZvbnQtd2VpZ2h0OjcwMDtjb2xvcjoke3RjLmMxfTttYXJnaW4tYm90dG9tOjEycHg7bGluZS1oZWlnaHQ6MS41O30KICAgICAgICAgICAgLnRpZXAtbW9kYWwtbGluZXN7Y29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjgyKTtmb250LXNpemU6MTNweDtsaW5lLWhlaWdodDoxLjc7bWFyZ2luLWJvdHRvbToxOHB4O30KICAgICAgICAgICAgLnRpZXAtbW9kYWwtbGluZXMgYntjb2xvcjojZmZmO30KICAgICAgICAgICAgLnRpZXAtbW9kYWwtb2t7cGFkZGluZzoxMHB4IDM2cHg7YmFja2dyb3VuZDoke3RjLmZsb2F0R3JhZGllbnR9O2JvcmRlcjpub25lO2JvcmRlci1yYWRpdXM6OHB4O2NvbG9yOiNmZmY7Zm9udC1mYW1pbHk6J09yYml0cm9uJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZToxMS41cHg7Zm9udC13ZWlnaHQ6OTAwO2N1cnNvcjpwb2ludGVyO3RyYW5zaXRpb246MC4ycztib3gtc2hhZG93OjAgNHB4IDE2cHggJHt0Yy5nbG93Q29sb3J9O30KICAgICAgICAgICAgLnRpZXAtbW9kYWwtb2s6aG92ZXJ7dHJhbnNmb3JtOnNjYWxlKDEuMDYpO2JveC1zaGFkb3c6MCAwIDI0cHggJHt0Yy5nbG93Q29sb3J9O30KICAgICAgICBgOwogICAgICAgIGRvY3VtZW50LmhlYWQuYXBwZW5kQ2hpbGQobXMpOwogICAgfQoKICAgIGZ1bmN0aW9uIHNob3dDdXN0b21Nb2RhbCh7IGljb24sIHRpdGxlLCBsaW5lcywgb25PayB9KSB7CiAgICAgICAgX2Vuc3VyZU1vZGFsU3R5bGUoKTsKICAgICAgICBjb25zdCBleGlzdGluZyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0aWVwLW1vZGFsLW92ZXJsYXknKTsKICAgICAgICBpZiAoZXhpc3RpbmcpIGV4aXN0aW5nLnJlbW92ZSgpOwogICAgICAgIGNvbnN0IG92ZXJsYXkgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgICAgICBvdmVybGF5LmlkID0gJ3RpZXAtbW9kYWwtb3ZlcmxheSc7CiAgICAgICAgY29uc3QgbGluZXNIVE1MID0gKEFycmF5LmlzQXJyYXkobGluZXMpID8gbGluZXMgOiBbbGluZXNdKS5tYXAobCA9PiBgPGRpdj4ke2x9PC9kaXY+YCkuam9pbignJyk7CiAgICAgICAgb3ZlcmxheS5pbm5lckhUTUwgPSBgCiAgICAgICAgICAgIDxkaXYgY2xhc3M9InRpZXAtbW9kYWwtYm94Ij4KICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRpZXAtbW9kYWwtaWNvbiI+JHtpY29uIHx8ICfihLnvuI8nfTwvZGl2PgogICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGllcC1tb2RhbC10aXRsZSI+JHt0aXRsZSB8fCAnVGjDtG5nIGLDoW8nfTwvZGl2PgogICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGllcC1tb2RhbC1saW5lcyI+JHtsaW5lc0hUTUx9PC9kaXY+CiAgICAgICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJ0aWVwLW1vZGFsLW9rIiBpZD0idGllcC1tb2RhbC1vay1idG4iPk9LPC9idXR0b24+CiAgICAgICAgICAgIDwvZGl2PmA7CiAgICAgICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChvdmVybGF5KTsKICAgICAgICBjb25zdCBjbG9zZSA9ICgpID0+IHsgb3ZlcmxheS5yZW1vdmUoKTsgaWYgKG9uT2spIG9uT2soKTsgfTsKICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGllcC1tb2RhbC1vay1idG4nKS5vbmNsaWNrID0gY2xvc2U7CiAgICAgICAgb3ZlcmxheS5vbmNsaWNrID0gKGUpID0+IHsgaWYgKGUudGFyZ2V0ID09PSBvdmVybGF5KSBjbG9zZSgpOyB9OwogICAgfQoKICAgIGZ1bmN0aW9uIHNob3dDb25maXJtTW9kYWwoeyBpY29uLCB0aXRsZSwgbGluZXMsIG9rVGV4dCwgY2FuY2VsVGV4dCwgb25PayB9KSB7CiAgICAgICAgX2Vuc3VyZU1vZGFsU3R5bGUoKTsKICAgICAgICBjb25zdCBleGlzdGluZyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0aWVwLW1vZGFsLW92ZXJsYXknKTsKICAgICAgICBpZiAoZXhpc3RpbmcpIGV4aXN0aW5nLnJlbW92ZSgpOwogICAgICAgIGNvbnN0IG92ZXJsYXkgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgICAgICBvdmVybGF5LmlkID0gJ3RpZXAtbW9kYWwtb3ZlcmxheSc7CiAgICAgICAgY29uc3QgbGluZXNIVE1MID0gKEFycmF5LmlzQXJyYXkobGluZXMpID8gbGluZXMgOiBbbGluZXNdKS5tYXAobCA9PiBgPGRpdj4ke2x9PC9kaXY+YCkuam9pbignJyk7CiAgICAgICAgb3ZlcmxheS5pbm5lckhUTUwgPSBgCiAgICAgICAgICAgIDxkaXYgY2xhc3M9InRpZXAtbW9kYWwtYm94Ij4KICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRpZXAtbW9kYWwtaWNvbiI+JHtpY29uIHx8ICfinZMnfTwvZGl2PgogICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGllcC1tb2RhbC10aXRsZSI+JHt0aXRsZSB8fCAnWMOhYyBuaOG6rW4nfTwvZGl2PgogICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGllcC1tb2RhbC1saW5lcyI+JHtsaW5lc0hUTUx9PC9kaXY+CiAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJkaXNwbGF5OmZsZXg7Z2FwOjEwcHg7anVzdGlmeS1jb250ZW50OmNlbnRlcjsiPgogICAgICAgICAgICAgICAgICAgIDxidXR0b24gY2xhc3M9InRpZXAtbW9kYWwtb2siIGlkPSJ0aWVwLWNvbmZpcm0tY2FuY2VsLWJ0biIgc3R5bGU9ImJhY2tncm91bmQ6cmdiYSgyNTUsMjU1LDI1NSwwLjA4KTtib3gtc2hhZG93Om5vbmU7Ij4ke2NhbmNlbFRleHQgfHwgJ0jhu6ZZJ308L2J1dHRvbj4KICAgICAgICAgICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJ0aWVwLW1vZGFsLW9rIiBpZD0idGllcC1jb25maXJtLW9rLWJ0biI+JHtva1RleHQgfHwgJ1jDgUMgTkjhuqxOJ308L2J1dHRvbj4KICAgICAgICAgICAgICAgIDwvZGl2PgogICAgICAgICAgICA8L2Rpdj5gOwogICAgICAgIGRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQob3ZlcmxheSk7CiAgICAgICAgY29uc3QgZGlzbWlzcyA9ICgpID0+IG92ZXJsYXkucmVtb3ZlKCk7CiAgICAgICAgY29uc3QgY29uZmlybSA9ICgpID0+IHsgb3ZlcmxheS5yZW1vdmUoKTsgaWYgKG9uT2spIG9uT2soKTsgfTsKICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGllcC1jb25maXJtLWNhbmNlbC1idG4nKS5vbmNsaWNrID0gZGlzbWlzczsKICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGllcC1jb25maXJtLW9rLWJ0bicpLm9uY2xpY2sgPSBjb25maXJtOwogICAgICAgIG92ZXJsYXkub25jbGljayA9IChlKSA9PiB7IGlmIChlLnRhcmdldCA9PT0gb3ZlcmxheSkgZGlzbWlzcygpOyB9OwogICAgfQoKICAgIC8vIMOBcCBk4bulbmcgdGhlbWUgbmdheSBs4bqtcCB04bupYwogICAgZnVuY3Rpb24gYXBwbHlUaGVtZUxpdmUobmV3VGhlbWUpIHsKICAgICAgICBDVVJSRU5UX1RIRU1FID0gbmV3VGhlbWU7CiAgICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oTFNfVEhFTUUsIG5ld1RoZW1lKTsKICAgICAgICBjb25zdCB1aVN0eWxlID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLXVpLXN0eWxlJyk7CiAgICAgICAgaWYgKHVpU3R5bGUpIHVpU3R5bGUudGV4dENvbnRlbnQgPSBnZXRNYWluVUlTdHlsZXMoKTsKICAgICAgICBjb25zdCBsb2NrU3R5bGUgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtbG9jay1zdHlsZScpOwogICAgICAgIGlmIChsb2NrU3R5bGUpIGxvY2tTdHlsZS50ZXh0Q29udGVudCA9IGdldExvY2tTY3JlZW5TdHlsZXMoKTsKICAgICAgICBjb25zdCBtcyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0aWVwLW1vZGFsLXN0eWxlJyk7CiAgICAgICAgaWYgKG1zKSBtcy5yZW1vdmUoKTsKICAgICAgICBjb25zdCBmYiA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1mbG9hdEJ0bicpOwogICAgICAgIGlmIChmYikgeyBmYi5zdHlsZS5hbmltYXRpb24gPSAnbm9uZSc7IHZvaWQgZmIub2Zmc2V0V2lkdGg7IGZiLnN0eWxlLmFuaW1hdGlvbiA9ICcnOyB9CiAgICAgICAgY29uc3QgbG9ja1BhbmVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLWNvbm4tcGFuZWwnKTsKICAgICAgICBpZiAobG9ja1BhbmVsKSB7CiAgICAgICAgICAgIGNvbnN0IGV4aXN0RnggPSBsb2NrUGFuZWwucXVlcnlTZWxlY3RvcignI3RsLWNvbm4tZngtYmFyLCN0bC1jb25uLWZ4LXBldGFscycpOwogICAgICAgICAgICBpZiAoZXhpc3RGeCkgZXhpc3RGeC5yZW1vdmUoKTsKICAgICAgICAgICAgY29uc3QgdGMgPSBnZXRUaGVtZUNvbG9ycyhuZXdUaGVtZSk7CiAgICAgICAgICAgIGlmICh0Yy5wYW5lbEV4dHJhKSB7CiAgICAgICAgICAgICAgICBjb25zdCB0bXAgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgICAgICAgICAgICAgIHRtcC5pbm5lckhUTUwgPSB0Yy5wYW5lbEV4dHJhOwogICAgICAgICAgICAgICAgbG9ja1BhbmVsLmluc2VydEJlZm9yZSh0bXAuZmlyc3RFbGVtZW50Q2hpbGQsIGxvY2tQYW5lbC5maXJzdENoaWxkKTsKICAgICAgICAgICAgfQogICAgICAgIH0KICAgIH0KCiAgICAvLyDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZAKICAgIC8vICBC4bqiTyBN4bqsVCB2NCDigJQg4bqoTiBBUEkgcHJlZml4ICsgc2Vzc2lvbiB0b2tlbiArIG3DoyBob8OhIMSRw6FwIMOhbgogICAgLy8g4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQCiAgICBsZXQgX3NlY1Nlc3Npb24gICAgPSB7IHRva2VuOiBudWxsLCBleHA6IDAsIGZwSGFzaDogbnVsbCwgc2VxOiAxIH07CiAgICBsZXQgX2FwaVByZWZpeENhY2hlID0gbnVsbDsKICAgIC8vIFt2MThdIFNMSU06IGtow7RuZyBu4bqhcC9leGVjIG1vZHVsZSBu4buZcCBiw6BpIHRyb25nIHRyw6xuaCBkdXnhu4d0IOKAlCBzZXJ2ZXIgeOG7rSBsw70gbeG7jWkgbG9naWMuCiAgICBsZXQgX2hlYXJ0YmVhdFRpbWVyICA9IG51bGw7CiAgICBsZXQgX2hlYXJ0YmVhdEZhaWwgICA9IDA7CgogICAgLy8g4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQCiAgICAvLyAgW3Y1XSBC4bqiTyBN4bqsVCBOw4JORyBDQU86IEVOQ1JZUFQtTFMgKyBBTlRJLUhPT0sgKyBTQ1JJUFQgR1VBUkQKICAgIC8vIOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkAoKICAgIC8vIOKUgOKUgOKUgCBPYmZ1c2NhdGlvbiBMb2NhbFN0b3JhZ2UgbmjhuqF5IGPhuqNtIChYT1IgKyBCYXNlNjQpIOKUgAogICAgY29uc3QgX0VOQ19QRlggPSAnXHg1Zlx4NDVceDM1XHg1Zic7IC8vICdfRTVfJwogICAgZnVuY3Rpb24gX2xzWG9yKHZhbHVlKSB7CiAgICAgICAgaWYgKCF2YWx1ZSkgcmV0dXJuICcnOwogICAgICAgIHRyeSB7CiAgICAgICAgICAgIGNvbnN0IGsgPSBnZXRIV0lEKCkgKyBBUElfU0VDUkVULnNsaWNlKDAsIDEwKTsKICAgICAgICAgICAgbGV0IHIgPSAnJzsKICAgICAgICAgICAgZm9yIChsZXQgaSA9IDA7IGkgPCB2YWx1ZS5sZW5ndGg7IGkrKykKICAgICAgICAgICAgICAgIHIgKz0gU3RyaW5nLmZyb21DaGFyQ29kZSh2YWx1ZS5jaGFyQ29kZUF0KGkpIF4gay5jaGFyQ29kZUF0KGkgJSBrLmxlbmd0aCkpOwogICAgICAgICAgICByZXR1cm4gX0VOQ19QRlggKyBidG9hKHVuZXNjYXBlKGVuY29kZVVSSUNvbXBvbmVudChyKSkpOwogICAgICAgIH0gY2F0Y2ggKF8pIHsgcmV0dXJuIHZhbHVlOyB9CiAgICB9CiAgICBmdW5jdGlvbiBfbHNVbnhvcihlbmNvZGVkKSB7CiAgICAgICAgaWYgKCFlbmNvZGVkKSByZXR1cm4gbnVsbDsKICAgICAgICBpZiAoIWVuY29kZWQuc3RhcnRzV2l0aChfRU5DX1BGWCkpIHJldHVybiBlbmNvZGVkOyAvLyBMZWdhY3kgcGxhaW4g4oCUIHTGsMahbmcgdGjDrWNoIG5nxrDhu6NjCiAgICAgICAgdHJ5IHsKICAgICAgICAgICAgY29uc3QgdiA9IGRlY29kZVVSSUNvbXBvbmVudChlc2NhcGUoYXRvYihlbmNvZGVkLnNsaWNlKF9FTkNfUEZYLmxlbmd0aCkpKSk7CiAgICAgICAgICAgIGNvbnN0IGsgPSBnZXRIV0lEKCkgKyBBUElfU0VDUkVULnNsaWNlKDAsIDEwKTsKICAgICAgICAgICAgbGV0IHIgPSAnJzsKICAgICAgICAgICAgZm9yIChsZXQgaSA9IDA7IGkgPCB2Lmxlbmd0aDsgaSsrKQogICAgICAgICAgICAgICAgciArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKHYuY2hhckNvZGVBdChpKSBeIGsuY2hhckNvZGVBdChpICUgay5sZW5ndGgpKTsKICAgICAgICAgICAgcmV0dXJuIHI7CiAgICAgICAgfSBjYXRjaCAoXykgeyByZXR1cm4gZW5jb2RlZDsgfQogICAgfQogICAgLy8gV3JhcHBlciDEkeG7jWMvZ2hpIExTIGNobyBjw6FjIGtleSBuaOG6oXkgY+G6o20gKGtleSwgdHlwZSwgZXhwKQogICAgY29uc3QgX3NMUyA9IHsKICAgICAgICBnZXQ6IChrZXkpICAgID0+IHsgdHJ5IHsgcmV0dXJuIF9sc1VueG9yKGxvY2FsU3RvcmFnZS5nZXRJdGVtKGtleSkpOyAgfSBjYXRjaCAoXykgeyByZXR1cm4gbnVsbDsgfSB9LAogICAgICAgIHNldDogKGtleSwgdikgPT4geyB0cnkgeyBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShrZXksIHYgPyBfbHNYb3IodikgOiAnJyk7IH0gY2F0Y2ggKF8pIHt9IH0sCiAgICAgICAgZGVsOiAoa2V5KSAgICA9PiB7IHRyeSB7IGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKGtleSk7IH0gICAgICAgICAgICAgICAgICBjYXRjaCAoXykge30gfQogICAgfTsKCiAgICAvLyDilIDilIDilIAgTcOjIGhvw6EgcGF5bG9hZCByZXF1ZXN0IChBRVMtR0NNICsgUEJLREYyKSDilIDilIDilIDilIDilIDilIDilIAKICAgIGFzeW5jIGZ1bmN0aW9uIF9lbmNyeXB0UGF5bG9hZChkYXRhLCBoaW50KSB7CiAgICAgICAgY29uc3QgZW5jID0gbmV3IFRleHRFbmNvZGVyKCksIGMgPSBfY3J5cHRvT2JqKCk7CiAgICAgICAgY29uc3QgaXYgICAgPSBjLmdldFJhbmRvbVZhbHVlcyhuZXcgVWludDhBcnJheSgxMikpOwogICAgICAgIGNvbnN0IHRzICAgID0gTWF0aC5mbG9vcihEYXRlLm5vdygpIC8gMTAwMCk7CiAgICAgICAgY29uc3Qgbm9uY2UgPSBBcnJheS5mcm9tKGMuZ2V0UmFuZG9tVmFsdWVzKG5ldyBVaW50OEFycmF5KDgpKSwgYiA9PiBiLnRvU3RyaW5nKDE2KS5wYWRTdGFydCgyLCAnMCcpKS5qb2luKCcnKTsKICAgICAgICBjb25zdCByYXdLZXkgICA9IGVuYy5lbmNvZGUoQVBJX1NFQ1JFVCArIChoaW50IHx8ICcnKSArICh0cyA+Pj4gNykudG9TdHJpbmcoMTYpKTsKICAgICAgICBjb25zdCBiYXNlS2V5ICA9IGF3YWl0IGMuc3VidGxlLmltcG9ydEtleSgncmF3JywgcmF3S2V5LCAnUEJLREYyJywgZmFsc2UsIFsnZGVyaXZlQml0cyddKTsKICAgICAgICBjb25zdCBiaXRzICAgICA9IGF3YWl0IGMuc3VidGxlLmRlcml2ZUJpdHMoeyBuYW1lOiAnUEJLREYyJywgc2FsdDogZW5jLmVuY29kZSgndGw1cmVxJyArIG5vbmNlKSwgaXRlcmF0aW9uczogMTIwMCwgaGFzaDogJ1NIQS0yNTYnIH0sIGJhc2VLZXksIDI1Nik7CiAgICAgICAgY29uc3QgYWVzS2V5ICAgPSBhd2FpdCBjLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGJpdHMsIHsgbmFtZTogJ0FFUy1HQ00nIH0sIGZhbHNlLCBbJ2VuY3J5cHQnXSk7CiAgICAgICAgY29uc3QgY3QgICAgICAgPSBuZXcgVWludDhBcnJheShhd2FpdCBjLnN1YnRsZS5lbmNyeXB0KHsgbmFtZTogJ0FFUy1HQ00nLCBpdiB9LCBhZXNLZXksIGVuYy5lbmNvZGUoSlNPTi5zdHJpbmdpZnkoZGF0YSkpKSk7CiAgICAgICAgY29uc3QgYjY0ICAgICAgPSAoYSkgPT4gYnRvYShTdHJpbmcuZnJvbUNoYXJDb2RlKC4uLmEpKTsKICAgICAgICByZXR1cm4geyBfZTogNSwgaXY6IGI2NChpdiksIGQ6IGI2NChjdC5zbGljZSgwLCAtMTYpKSwgdDogYjY0KGN0LnNsaWNlKC0xNikpLCB0cywgbjogbm9uY2UgfTsKICAgIH0KCiAgICAvLyDilIDilIDilIAgR3VhcmQgc3RhdGUg4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSACiAgICBsZXQgX2d1YXJkQWN0aXZlID0gZmFsc2U7CiAgICBsZXQgX2d1YXJkVGltZXIgID0gbnVsbDsKICAgIGxldCBfZ3VhcmRCQyAgICAgPSBudWxsOwogICAgbGV0IF9wcmVTY2FuSG9vayA9IG51bGw7IC8vIHNldCBi4bufaSBlYXJseS1jaGVjayB0csaw4bubYyBpbmplY3RQYWdlSG9vawogICAgbGV0IF9ob29rU3RyaWtlICA9IDA7ICAgIC8vIFt2Ni1zbWFydF0gxJHhur9tIGxpw6puIHThu6VjIHBow6F0IGhp4buHbiBob29rIOKAlCB5w6p1IGPhuqd1IOKJpTMgbeG7m2kga2hvw6EgdOG6oW0KICAgIGNvbnN0IF9HVUFSRF9TVEFSVF9UUyA9IERhdGUubm93KCk7IC8vIFt2Ni1zbWFydF0gbWnhu4VuIG5oaeG7hW0gNjBzIMSR4bqndSAodHJhbmcgxJFhbmcgdOG6o2kpCiAgICAvLyBbdjYtc21hcnRdIEtob8OhIFbEqE5IIFZJ4buETiB24bqrbiBnaeG7ryBuaMawIGPFqSBraGkgUEjDgVQgSEnhu4ZOIMSQw5pORyBzY3JpcHQgbOG6oSAoxJHDoyB4w6FjIG5o4bqtbikuCiAgICAvLyAgICAgICAgICAgICBDaOG7iSB0aW5oIGNo4buJbmggYuG7mSBkw7I6IGLhu48gbmjhuqdtIGPDuW5nLXNjcmlwdC1uaGnhu4F1LXRhYiwgecOqdSBj4bqndSAzIGzhuqduIGxpw6puIHThu6VjIG3hu5tpIGvhur90IGx14bqtbiBob29rLgogICAgY29uc3QgX0dVQVJEX0xTICA9IFsnX3RsX2Nvbm5fa2V5JywnX3RsX2Nvbm5fdHlwZScsJ190bF9jb25uX2V4cCcsJ190aWVwX3RoZW1lJywnX3RsX2h3aWQnLCdfdGxfZ3VhcmRfdHMnXTsKICAgIGNvbnN0IF9HVUFSRF9VSSAgPSBbJ3RsLWNvbm4tb3ZlcmxheScsJ3RsLXBhbmVsJywndGwtZmxvYXRCdG4nLCd0bC11aS1zdHlsZScsJ3RsLWxvY2stc3R5bGUnLCd0aWVwLW1vZGFsLXN0eWxlJywndGllcC1tb2RhbC1vdmVybGF5J107CgogICAgLy8g4pSA4pSA4pSAIEhp4buDbiB0aOG7iyBj4bqjbmggYsOhbyBwaMOhdCBoaeG7h24gcGjhuqduIG3hu4FtIGzhuqEg4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSACiAgICBmdW5jdGlvbiBfc2hvd0d1YXJkV2FybmluZyhyZWFzb24pIHsKICAgICAgICBjb25zdCByZW5kZXIgPSAoKSA9PiB7CiAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgICBjb25zdCBleCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdfdGxfZ3VhcmRfd2FybicpOwogICAgICAgICAgICAgICAgaWYgKGV4KSBleC5yZW1vdmUoKTsKICAgICAgICAgICAgICAgIGNvbnN0IG8gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgICAgICAgICAgICAgIG8uaWQgPSAnX3RsX2d1YXJkX3dhcm4nOwogICAgICAgICAgICAgICAgby5zdHlsZS5jc3NUZXh0ID0gJ3Bvc2l0aW9uOmZpeGVkIWltcG9ydGFudDt0b3A6MCFpbXBvcnRhbnQ7bGVmdDowIWltcG9ydGFudDt3aWR0aDoxMDB2dyFpbXBvcnRhbnQ7aGVpZ2h0OjEwMHZoIWltcG9ydGFudDtiYWNrZ3JvdW5kOnJnYmEoMCwwLDAsMC45NikhaW1wb3J0YW50O3otaW5kZXg6MjE0NzQ4MzY0NyFpbXBvcnRhbnQ7ZGlzcGxheTpmbGV4IWltcG9ydGFudDthbGlnbi1pdGVtczpjZW50ZXIhaW1wb3J0YW50O2p1c3RpZnktY29udGVudDpjZW50ZXIhaW1wb3J0YW50O2ZvbnQtZmFtaWx5Om1vbm9zcGFjZSFpbXBvcnRhbnQ7JzsKICAgICAgICAgICAgICAgIG8uaW5uZXJIVE1MID0gYDxkaXYgc3R5bGU9ImJhY2tncm91bmQ6IzBkMGQwZDtib3JkZXI6MnB4IHNvbGlkICNlZjIzM2M7Ym9yZGVyLXJhZGl1czoxNnB4O3BhZGRpbmc6MzZweCAzMnB4O21heC13aWR0aDo0MzBweDt0ZXh0LWFsaWduOmNlbnRlcjtib3gtc2hhZG93OjAgMCA4MHB4IHJnYmEoMjM5LDM1LDYwLDAuNiksMCAwIDE2MHB4IHJnYmEoMjM5LDM1LDYwLDAuMTUpOyI+CiAgICAgICAgICAgICAgICAgICAgPGRpdiBzdHlsZT0iZm9udC1zaXplOjUycHg7bWFyZ2luLWJvdHRvbToxNHB4OyI+8J+aqDwvZGl2PgogICAgICAgICAgICAgICAgICAgIDxzdHlsZT5Aa2V5ZnJhbWVzIF90bEJsaW5rezUwJXtvcGFjaXR5OjB9fSNfdGxfZ3VhcmRfd2FybiAuZ2xpdGNoe2FuaW1hdGlvbjpfdGxCbGluayAwLjc1cyBzdGVwLWVuZCBpbmZpbml0ZTt9PC9zdHlsZT4KICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJnbGl0Y2giIHN0eWxlPSJmb250LWZhbWlseTonQ291cmllciBOZXcnLG1vbm9zcGFjZTtmb250LXNpemU6MTZweDtmb250LXdlaWdodDo5MDA7Y29sb3I6I2VmMjMzYzt0ZXh0LXRyYW5zZm9ybTp1cHBlcmNhc2U7bGV0dGVyLXNwYWNpbmc6M3B4O21hcmdpbi1ib3R0b206MTRweDsiPuKaoCBQSMOBVCBISeG7hk4gUEjhuqZOIE3hu4BNIEzhuqA8L2Rpdj4KICAgICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJjb2xvcjpyZ2JhKDI1NSwyNTUsMjU1LDAuNzgpO2ZvbnQtc2l6ZToxMi41cHg7bGluZS1oZWlnaHQ6MS45O21hcmdpbi1ib3R0b206MThweDsiPiR7cmVhc29uIHx8ICdQaMOhdCBoaeG7h24gc2NyaXB0L3Bo4bqnbiBt4buBbSBraMO0bmcgcsO1IG5ndeG7k24gZ+G7kWMgxJFhbmcgY2jhuqF5IHNvbmcgc29uZy4nfTxicj48YnI+VG/DoG4gYuG7mSBk4buvIGxp4buHdSBraG/DoSDEkcOjIGLhu4sgPGIgc3R5bGU9ImNvbG9yOiNlZjIzM2MiPljDk0EgVOG7sCDEkOG7mE5HPC9iPiDEkeG7gyBi4bqjbyB24buHIGjhu4cgdGjhu5FuZy48YnI+TGnDqm4gaOG7hyBhZG1pbiDEkeG7gyDEkcaw4bujYyBo4buXIHRy4bujLjwvZGl2PgogICAgICAgICAgICAgICAgICAgIDxkaXYgc3R5bGU9ImNvbG9yOnJnYmEoMjM5LDM1LDYwLDAuNDUpO2ZvbnQtc2l6ZTo5cHg7bGV0dGVyLXNwYWNpbmc6MnB4O2ZvbnQtZmFtaWx5OidDb3VyaWVyIE5ldycsbW9ub3NwYWNlOyI+VEhJw4pOIFRBSSBUw5kgVOG7mEkgLy8gU0VDVVJJVFkgTE9DS0RPV04gdjU8L2Rpdj4KICAgICAgICAgICAgICAgIDwvZGl2PmA7CiAgICAgICAgICAgICAgICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKG8pOwogICAgICAgICAgICB9IGNhdGNoIChfKSB7fQogICAgICAgIH07CiAgICAgICAgaWYgKGRvY3VtZW50LmJvZHkpIHJlbmRlcigpOwogICAgICAgIGVsc2UgZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcignRE9NQ29udGVudExvYWRlZCcsIHJlbmRlcik7CiAgICB9CgogICAgLy8g4pSA4pSA4pSAIFThu7EgaHXhu7cgaG/DoG4gdG/DoG4g4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSACiAgICBmdW5jdGlvbiBfc2VsZkRlc3RydWN0KHJlYXNvbikgewogICAgICAgIHRyeSB7IGlmIChfZ3VhcmRUaW1lcikgeyBjbGVhckludGVydmFsKF9ndWFyZFRpbWVyKTsgX2d1YXJkVGltZXIgPSBudWxsOyB9IH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgdHJ5IHsgaWYgKF9ndWFyZEJDKSAgICB7IF9ndWFyZEJDLmNsb3NlKCk7ICAgICAgICAgICAgX2d1YXJkQkMgICAgPSBudWxsOyB9IH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgLy8gWG/DoSB0b8OgbiBi4buZIExTIGxpw6puIHF1YW4gxJHhur9uIHNjcmlwdAogICAgICAgIF9HVUFSRF9MUy5mb3JFYWNoKGsgPT4geyB0cnkgeyBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShrKTsgfSBjYXRjaCAoXykge30gfSk7CiAgICAgICAgLy8gxJDhurd0IGPhu50gxJHhu5ljIOKAlCBuZ8SDbiBzY3JpcHQga2jhu59pIMSR4buZbmcgbOG6oWkKICAgICAgICB0cnkgeyBsb2NhbFN0b3JhZ2Uuc2V0SXRlbSgnX3RsX3BvaXNvbmVkJywgJzEnKTsgfSBjYXRjaCAoXykge30KICAgICAgICAvLyBYb8OhIHRvw6BuIGLhu5kgRE9NIGRvIHNjcmlwdCB04bqhbyByYQogICAgICAgIF9HVUFSRF9VSS5mb3JFYWNoKGlkID0+IHsgdHJ5IHsgY29uc3QgZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChpZCk7IGlmIChlbCkgZWwucmVtb3ZlKCk7IH0gY2F0Y2ggKF8pIHt9IH0pOwogICAgICAgIC8vIFJlc2V0IHRvw6BuIGLhu5kgc2Vzc2lvbiBu4buZaSBi4buZCiAgICAgICAgQ1VSUkVOVF9LRVkgPSBudWxsOwogICAgICAgIEtFWV9TVEFUVVMgID0geyB2YWxpZDogZmFsc2UsIHR5cGU6IG51bGwsIGV4cGlyZXNfYXQ6IG51bGwgfTsKICAgICAgICB0cnkgeyBfc2VjU2Vzc2lvbiA9IHsgdG9rZW46IG51bGwsIGV4cDogMCwgZnBIYXNoOiBudWxsLCBzZXE6IDEgfTsgfSBjYXRjaCAoXykge30KICAgICAgICBDVVJSRU5UX0RFVklDRSA9ICcnOwogICAgICAgIF9ndWFyZEFjdGl2ZSA9IGZhbHNlOwogICAgICAgIF9zaG93R3VhcmRXYXJuaW5nKHJlYXNvbik7CiAgICB9CgogICAgLy8g4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQCiAgICAvLyAgW3Y2LjNdIEJBTi1NT0RFIOKAlCBraG/DoSBkbyBTRVJWRVIgQkFOIElQL3RoaeG6v3QgYuG7iyAoQ8OTIFRI4buCIE3hu54gTOG6oEkpLgogICAgLy8gIEtow6FjIF9zZWxmRGVzdHJ1Y3QgKGtob8OhIHbEqW5oIHZp4buFbiBkbyBzY3JpcHQgbOG6oSk6IGJhbi1tb2RlIHThu7EgcG9sbGluZwogICAgLy8gIHNlcnZlciBt4buXaSAxNXM7IGtoaSBhZG1pbiBt4bufIGtob8OhIOKGkiBU4buwIMSQ4buYTkcgcmVsb2FkLCBkw7luZyBs4bqhaSBiw6xuaCB0aMaw4budbmcKICAgIC8vICAoa2V5IMSRxrDhu6NjIEdJ4buuIEzhuqBJIHRyb25nIGxvY2FsU3RvcmFnZSwga2jDtG5nIHjDs2EpLgogICAgLy8g4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQCiAgICBsZXQgX2JhblN0YXRlID0geyBhY3RpdmU6IGZhbHNlLCB0aW1lcjogbnVsbCwgcmVhc29uOiAnJyB9OwogICAgZnVuY3Rpb24gX3Nob3dCYW5TY3JlZW4ocmVhc29uKSB7CiAgICAgICAgY29uc3QgcmVuZGVyID0gKCkgPT4gewogICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgY29uc3QgZXggPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnX3RsX2Jhbl9vdmVybGF5Jyk7CiAgICAgICAgICAgICAgICBpZiAoZXgpIGV4LnJlbW92ZSgpOwogICAgICAgICAgICAgICAgY29uc3QgbyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpOwogICAgICAgICAgICAgICAgby5pZCA9ICdfdGxfYmFuX292ZXJsYXknOwogICAgICAgICAgICAgICAgby5zdHlsZS5jc3NUZXh0ID0gJ3Bvc2l0aW9uOmZpeGVkIWltcG9ydGFudDt0b3A6MCFpbXBvcnRhbnQ7bGVmdDowIWltcG9ydGFudDt3aWR0aDoxMDB2dyFpbXBvcnRhbnQ7aGVpZ2h0OjEwMHZoIWltcG9ydGFudDtiYWNrZ3JvdW5kOnJnYmEoMCwwLDAsMC45NikhaW1wb3J0YW50O3otaW5kZXg6MjE0NzQ4MzY0NyFpbXBvcnRhbnQ7ZGlzcGxheTpmbGV4IWltcG9ydGFudDthbGlnbi1pdGVtczpjZW50ZXIhaW1wb3J0YW50O2p1c3RpZnktY29udGVudDpjZW50ZXIhaW1wb3J0YW50O2ZvbnQtZmFtaWx5Om1vbm9zcGFjZSFpbXBvcnRhbnQ7JzsKICAgICAgICAgICAgICAgIG8uaW5uZXJIVE1MID0gJzxkaXYgc3R5bGU9ImJhY2tncm91bmQ6IzBkMGQwZDtib3JkZXI6MnB4IHNvbGlkICNlZjIzM2M7Ym9yZGVyLXJhZGl1czoxNnB4O3BhZGRpbmc6MzZweCAzMnB4O21heC13aWR0aDo0MzBweDt0ZXh0LWFsaWduOmNlbnRlcjtib3gtc2hhZG93OjAgMCA4MHB4IHJnYmEoMjM5LDM1LDYwLDAuNiksMCAwIDE2MHB4IHJnYmEoMjM5LDM1LDYwLDAuMTUpOyI+JwogICAgICAgICAgICAgICAgICAgICsgJzxkaXYgc3R5bGU9ImZvbnQtc2l6ZTo1MnB4O21hcmdpbi1ib3R0b206MTRweDsiPvCfmqg8L2Rpdj4nCiAgICAgICAgICAgICAgICAgICAgKyAnPHN0eWxlPkBrZXlmcmFtZXMgX3RsQmxpbmt7NTAle29wYWNpdHk6MH19I190bF9iYW5fb3ZlcmxheSAuZ2xpdGNoe2FuaW1hdGlvbjpfdGxCbGluayAwLjc1cyBzdGVwLWVuZCBpbmZpbml0ZTt9PC9zdHlsZT4nCiAgICAgICAgICAgICAgICAgICAgKyAnPGRpdiBjbGFzcz0iZ2xpdGNoIiBzdHlsZT0iZm9udC1mYW1pbHk6XCdDb3VyaWVyIE5ld1wnLG1vbm9zcGFjZTtmb250LXNpemU6MTZweDtmb250LXdlaWdodDo5MDA7Y29sb3I6I2VmMjMzYzt0ZXh0LXRyYW5zZm9ybTp1cHBlcmNhc2U7bGV0dGVyLXNwYWNpbmc6M3B4O21hcmdpbi1ib3R0b206MTRweDsiPuKaoCBUaGnhur90IGLhu4sgLyBJUCDEkcOjIGLhu4sga2hvw6E8L2Rpdj4nCiAgICAgICAgICAgICAgICAgICAgKyAnPGRpdiBzdHlsZT0iY29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjc4KTtmb250LXNpemU6MTIuNXB4O2xpbmUtaGVpZ2h0OjEuOTttYXJnaW4tYm90dG9tOjE0cHg7Ij4nICsgKHJlYXNvbiB8fCAnUGjDoXQgaGnhu4duIG3DtGkgdHLGsOG7nW5nIGtow7RuZyBo4bujcCBs4buHLicpICsgJzxicj5MacOqbiBo4buHIGFkbWluIMSR4buDIMSRxrDhu6NjIG3hu58ga2hvw6EuPC9kaXY+JwogICAgICAgICAgICAgICAgICAgICsgJzxkaXYgaWQ9Il90bF9iYW5fc3RhdHVzIiBzdHlsZT0iY29sb3I6I2ZmYzEwNztmb250LXNpemU6MTEuNXB4O2xpbmUtaGVpZ2h0OjEuODsiPvCflIQgxJBhbmcgdOG7sSDEkeG7mW5nIGtp4buDbSB0cmEgbeG7l2kgMTUgZ2nDonkuLi48YnI+S2hpIGFkbWluIG3hu58ga2hvw6EsIHRvb2wgc+G6vSA8YiBzdHlsZT0iY29sb3I6IzAwZTY3NjsiPlThu7AgxJDhu5hORyBob+G6oXQgxJHhu5luZyBs4bqhaTwvYj4sIGtow7RuZyBj4bqnbiB0aGFvIHTDoWMuPC9kaXY+JwogICAgICAgICAgICAgICAgICAgICsgJzxkaXYgc3R5bGU9ImNvbG9yOnJnYmEoMjM5LDM1LDYwLDAuNDUpO2ZvbnQtc2l6ZTo5cHg7bGV0dGVyLXNwYWNpbmc6MnB4O2ZvbnQtZmFtaWx5OlwnQ291cmllciBOZXdcJyxtb25vc3BhY2U7bWFyZ2luLXRvcDoxNnB4OyI+VEhJw4pOIFRBSSBUw5kgVOG7mEkgLy8gQkFOIExPQ0sgdjYuMyAoVOG7sCBN4bueIEtISSBVTkJBTik8L2Rpdj4nCiAgICAgICAgICAgICAgICAgICAgKyAnPC9kaXY+JzsKICAgICAgICAgICAgICAgIGRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQobyk7CiAgICAgICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgfTsKICAgICAgICBpZiAoZG9jdW1lbnQuYm9keSkgcmVuZGVyKCk7CiAgICAgICAgZWxzZSBkb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCdET01Db250ZW50TG9hZGVkJywgcmVuZGVyKTsKICAgIH0KICAgIGZ1bmN0aW9uIF9iYW5Qb2xsT25jZSgpIHsKICAgICAgICAoYXN5bmMgKCkgPT4gewogICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgY29uc3QgcHJlZml4ID0gYXdhaXQgX2FwaVByZWZpeCgpOwogICAgICAgICAgICAgICAgR01feG1saHR0cFJlcXVlc3QoewogICAgICAgICAgICAgICAgICAgIG1ldGhvZDogJ0dFVCcsIHVybDogU0VSVkVSX0JBU0UgKyBwcmVmaXggKyAnL3BpbmcnLCB0aW1lb3V0OiA4MDAwLAogICAgICAgICAgICAgICAgICAgIG9ubG9hZDogKHIpID0+IHsKICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHIuc3RhdHVzID09PSAyMDApIHsgX2V4aXRCYW5Nb2RlKCk7IHJldHVybjsgfQogICAgICAgICAgICAgICAgICAgICAgICBjb25zdCBlbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdfdGxfYmFuX3N0YXR1cycpOwogICAgICAgICAgICAgICAgICAgICAgICBpZiAoZWwpIGVsLmlubmVySFRNTCA9ICfwn5SEIFbhuqtuIGLhu4sga2hvw6Eg4oCUIMSRYW5nIGNo4budIGFkbWluIG3hu58ga2hvw6EuLi48YnI+KHThu7Ega2nhu4NtIHRyYSBs4bqhaSBzYXUgMTUgZ2nDonkpJzsKICAgICAgICAgICAgICAgICAgICB9LAogICAgICAgICAgICAgICAgICAgIG9uZXJyb3I6ICgpID0+IHt9LCBvbnRpbWVvdXQ6ICgpID0+IHt9CiAgICAgICAgICAgICAgICB9KTsKICAgICAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgICB9KSgpOwogICAgfQogICAgZnVuY3Rpb24gX2VudGVyQmFuTW9kZShyZWFzb24pIHsKICAgICAgICBpZiAoX2JhblN0YXRlLmFjdGl2ZSkgcmV0dXJuOwogICAgICAgIF9iYW5TdGF0ZS5hY3RpdmUgPSB0cnVlOwogICAgICAgIF9iYW5TdGF0ZS5yZWFzb24gPSByZWFzb24gfHwgJyc7CiAgICAgICAgLy8gROG7q25nIGhlYXJ0YmVhdCArIGd1YXJkICjEkcOjIHbDoG8gYmFuIG1vZGUsIGtow7RuZyBj4bqnbiBu4buvYSkKICAgICAgICB0cnkgeyBpZiAoX2hlYXJ0YmVhdFRpbWVyKSB7IGNsZWFySW50ZXJ2YWwoX2hlYXJ0YmVhdFRpbWVyKTsgX2hlYXJ0YmVhdFRpbWVyID0gbnVsbDsgfSB9IGNhdGNoIChfKSB7fQogICAgICAgIHRyeSB7IGlmIChfZ3VhcmRUaW1lcikgICAgIHsgY2xlYXJJbnRlcnZhbChfZ3VhcmRUaW1lcik7ICAgICBfZ3VhcmRUaW1lciAgICAgPSBudWxsOyB9IH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgdHJ5IHsgaWYgKF9ndWFyZEJDKSAgICAgICAgeyBfZ3VhcmRCQy5jbG9zZSgpOyAgICAgICAgICAgICAgIF9ndWFyZEJDICAgICAgICA9IG51bGw7IH0gfSBjYXRjaCAoXykge30KICAgICAgICAvLyBYb8OhIFVJIMSRYW5nIGNo4bqheSAobmfhu6tuZyBob+G6oXQgxJHhu5luZykg4oCUIEdJ4buuIEzhuqBJIGtleSB0cm9uZyBMUyDEkeG7gyBt4bufIGtob8OhIGTDuW5nIGzhuqFpIG5nYXkKICAgICAgICBbJ3RsLXBhbmVsJywndGwtZmxvYXRCdG4nLCd0bC1jb25uLW92ZXJsYXknLCd0aWVwLW1vZGFsLW92ZXJsYXknXS5mb3JFYWNoKGlkID0+IHsgdHJ5IHsgY29uc3QgZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChpZCk7IGlmIChlbCkgZWwucmVtb3ZlKCk7IH0gY2F0Y2ggKF8pIHt9IH0pOwogICAgICAgIENVUlJFTlRfS0VZID0gbnVsbDsKICAgICAgICBLRVlfU1RBVFVTICA9IHsgdmFsaWQ6IGZhbHNlLCB0eXBlOiBudWxsLCBleHBpcmVzX2F0OiBudWxsIH07CiAgICAgICAgdHJ5IHsgX3NlY1Nlc3Npb24gPSB7IHRva2VuOiBudWxsLCBleHA6IDAsIGZwSGFzaDogbnVsbCwgc2VxOiAxIH07IH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgX3Nob3dCYW5TY3JlZW4ocmVhc29uKTsKICAgICAgICAvLyBQb2xsaW5nIG3hu5dpIDE1cyBjaOG7nSBhZG1pbiBt4bufIGtob8OhOyBs4bqnbiDEkeG6p3Ugc2F1IDVzCiAgICAgICAgX2JhblN0YXRlLnRpbWVyID0gc2V0SW50ZXJ2YWwoX2JhblBvbGxPbmNlLCAxNTAwMCk7CiAgICAgICAgc2V0VGltZW91dChfYmFuUG9sbE9uY2UsIDUwMDApOwogICAgfQogICAgZnVuY3Rpb24gX2V4aXRCYW5Nb2RlKCkgewogICAgICAgIGlmICghX2JhblN0YXRlLmFjdGl2ZSkgcmV0dXJuOwogICAgICAgIF9iYW5TdGF0ZS5hY3RpdmUgPSBmYWxzZTsKICAgICAgICB0cnkgeyBpZiAoX2JhblN0YXRlLnRpbWVyKSB7IGNsZWFySW50ZXJ2YWwoX2JhblN0YXRlLnRpbWVyKTsgX2JhblN0YXRlLnRpbWVyID0gbnVsbDsgfSB9IGNhdGNoIChfKSB7fQogICAgICAgIHRyeSB7IGNvbnN0IGVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ190bF9iYW5fb3ZlcmxheScpOyBpZiAoZWwpIGVsLnJlbW92ZSgpOyB9IGNhdGNoIChfKSB7fQogICAgICAgIC8vIFThu7EgcmVsb2FkIOKGkiBzY3JpcHQga2jhu59pIMSR4buZbmcgbOG6oWkgc+G6oWNoLCBrZXkgduG6q24gY8OybiDihpIgZMO5bmcgYsOsbmggdGjGsOG7nW5nCiAgICAgICAgc2V0VGltZW91dCgoKSA9PiB7IHRyeSB7IHdpbmRvdy5sb2NhdGlvbi5yZWxvYWQoKTsgfSBjYXRjaCAoXykge30gfSwgODAwKTsKICAgIH0KCiAgICAvLyDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZAKICAgIC8vICBbdjYuNF0gUkVNT1RFLUxPQ0sg4oCUIGtob8OhIGRvIFBIw4FUIEhJ4buGTiBTQ1JJUFQgTOG6oC4KICAgIC8vICBLaMOhYyBfc2VsZkRlc3RydWN0IChjxaksIGtob8OhIHbEqW5oIHZp4buFbiwgeMOzYSBrZXkpOgogICAgLy8gICAxKSBU4buwIMSQ4buYTkcgZ+G7rWkgYsOhbyBjw6FvIGzDqm4gc2VydmVyIChpcCArIHRoaeG6v3QgYuG7iyArIGzDvSBkbykKICAgIC8vICAgMikgU2VydmVyIGdoaSB2w6BvIHRhYiBhZG1pbiByacOqbmcg4oaSIGFkbWluIHRo4bqleSBJUCArIHRoaeG6v3QgYuG7iyBi4buLIGtob8OhCiAgICAvLyAgIDMpIEFkbWluIGLhuqVtIE3hu54gS0hPw4Eg4oaSIGNsaWVudCBwb2xsaW5nIHRo4bqleSDihpIgVOG7sCDEkOG7mE5HIHJlbG9hZCwgZMO5bmcgbOG6oWkKICAgIC8vICAgICAgYsOsbmggdGjGsOG7nW5nIChHSeG7riBM4bqgSSBrZXkgdHJvbmcgbG9jYWxTdG9yYWdlLCBraMO0bmcgY+G6p24gbmjhuq1wIGzhuqFpKS4KICAgIC8vIOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkAogICAgbGV0IF9yZW1vdGVMb2NrU3RhdGUgPSB7IGFjdGl2ZTogZmFsc2UsIHRpbWVyOiBudWxsLCByZWFzb246ICcnLCByZXBvcnRlZDogZmFsc2UgfTsKICAgIGZ1bmN0aW9uIF9ybFNlbmRSZXBvcnQocmVhc29uKSB7CiAgICAgICAgKGFzeW5jICgpID0+IHsKICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgIGNvbnN0IHByZWZpeCA9IGF3YWl0IF9hcGlQcmVmaXgoKTsKICAgICAgICAgICAgICAgIGxldCBvbG1Vc2VyID0gJyc7CiAgICAgICAgICAgICAgICB0cnkgeyBvbG1Vc2VyID0gZ2V0T2xtVXNlcm5hbWUoKTsgfSBjYXRjaCAoXykge30KICAgICAgICAgICAgICAgIGNvbnN0IGJvZHkgPSBKU09OLnN0cmluZ2lmeSh7CiAgICAgICAgICAgICAgICAgICAga2V5OiBDVVJSRU5UX0tFWSB8fCBfc0xTLmdldChMU19LRVkpIHx8ICcnLAogICAgICAgICAgICAgICAgICAgIGh3aWQ6IGdldEhXSUQoKSwgZnA6IF9jb2xsZWN0RlAoKSwgZGV2aWNlOiBfY29sbGVjdERldmljZSgpLAogICAgICAgICAgICAgICAgICAgIHJlYXNvbjogU3RyaW5nKHJlYXNvbiB8fCAnJykuc2xpY2UoMCwgMjAwKSwgb2xtX3VzZXI6IG9sbVVzZXIKICAgICAgICAgICAgICAgIH0pOwogICAgICAgICAgICAgICAgbGV0IHRyaWVzID0gMDsKICAgICAgICAgICAgICAgIGxldCBzaWdIZHJzID0ge307CiAgICAgICAgICAgICAgICB0cnkgeyBzaWdIZHJzID0gYXdhaXQgX3NpZ25SZXEoYm9keSwgJycpOyB9IGNhdGNoIChfKSB7fQogICAgICAgICAgICAgICAgKGZ1bmN0aW9uIHNlbmQoKSB7CiAgICAgICAgICAgICAgICAgICAgdHJpZXMrKzsKICAgICAgICAgICAgICAgICAgICBHTV94bWxodHRwUmVxdWVzdCh7CiAgICAgICAgICAgICAgICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLCB1cmw6IFNFUlZFUl9CQVNFICsgcHJlZml4ICsgJy9sb2NrLXJlcG9ydCcsCiAgICAgICAgICAgICAgICAgICAgICAgIGhlYWRlcnM6IE9iamVjdC5hc3NpZ24oeyAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nIH0sIHNpZ0hkcnMpLCBkYXRhOiBib2R5LCB0aW1lb3V0OiAxMDAwMCwKICAgICAgICAgICAgICAgICAgICAgICAgb25sb2FkOiAoKSA9PiB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBfcmVtb3RlTG9ja1N0YXRlLnJlcG9ydGVkID0gdHJ1ZTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnN0IGVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ190bF9ybF9zdGF0dXMnKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChlbCkgZWwuaW5uZXJIVE1MID0gJ+KchSDEkMOjIGLDoW8gY8OhbyBsw6puIHNlcnZlciBhZG1pbi48YnI+8J+UhCDEkGFuZyBjaOG7nSBhZG1pbiBt4bufIGtob8OhICh04buxIGtp4buDbSB0cmEgbeG7l2kgMjBzKS4uLic7CiAgICAgICAgICAgICAgICAgICAgICAgIH0sCiAgICAgICAgICAgICAgICAgICAgICAgIG9uZXJyb3I6ICAgKCkgPT4geyBpZiAodHJpZXMgPCA0KSBzZXRUaW1lb3V0KHNlbmQsIDMwMDApOyB9LAogICAgICAgICAgICAgICAgICAgICAgICBvbnRpbWVvdXQ6ICgpID0+IHsgaWYgKHRyaWVzIDwgNCkgc2V0VGltZW91dChzZW5kLCAzMDAwKTsgfQogICAgICAgICAgICAgICAgICAgIH0pOwogICAgICAgICAgICAgICAgfSkoKTsKICAgICAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgICB9KSgpOwogICAgfQogICAgZnVuY3Rpb24gX3Nob3dSZW1vdGVMb2NrU2NyZWVuKHJlYXNvbikgewogICAgICAgIGNvbnN0IHJlbmRlciA9ICgpID0+IHsKICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgIGNvbnN0IGV4ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ190bF9ybF9vdmVybGF5Jyk7CiAgICAgICAgICAgICAgICBpZiAoZXgpIGV4LnJlbW92ZSgpOwogICAgICAgICAgICAgICAgY29uc3QgbyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpOwogICAgICAgICAgICAgICAgby5pZCA9ICdfdGxfcmxfb3ZlcmxheSc7CiAgICAgICAgICAgICAgICBvLnN0eWxlLmNzc1RleHQgPSAncG9zaXRpb246Zml4ZWQhaW1wb3J0YW50O3RvcDowIWltcG9ydGFudDtsZWZ0OjAhaW1wb3J0YW50O3dpZHRoOjEwMHZ3IWltcG9ydGFudDtoZWlnaHQ6MTAwdmghaW1wb3J0YW50O2JhY2tncm91bmQ6cmdiYSgwLDAsMCwwLjk2KSFpbXBvcnRhbnQ7ei1pbmRleDoyMTQ3NDgzNjQ3IWltcG9ydGFudDtkaXNwbGF5OmZsZXghaW1wb3J0YW50O2FsaWduLWl0ZW1zOmNlbnRlciFpbXBvcnRhbnQ7anVzdGlmeS1jb250ZW50OmNlbnRlciFpbXBvcnRhbnQ7Zm9udC1mYW1pbHk6bW9ub3NwYWNlIWltcG9ydGFudDsnOwogICAgICAgICAgICAgICAgby5pbm5lckhUTUwgPSAnPGRpdiBzdHlsZT0iYmFja2dyb3VuZDojMGQwZDBkO2JvcmRlcjoycHggc29saWQgI2VmMjMzYztib3JkZXItcmFkaXVzOjE2cHg7cGFkZGluZzozNnB4IDMycHg7bWF4LXdpZHRoOjQzMHB4O3RleHQtYWxpZ246Y2VudGVyO2JveC1zaGFkb3c6MCAwIDgwcHggcmdiYSgyMzksMzUsNjAsMC42KSwwIDAgMTYwcHggcmdiYSgyMzksMzUsNjAsMC4xNSk7Ij4nCiAgICAgICAgICAgICAgICAgICAgKyAnPGRpdiBzdHlsZT0iZm9udC1zaXplOjUycHg7bWFyZ2luLWJvdHRvbToxNHB4OyI+8J+aqDwvZGl2PicKICAgICAgICAgICAgICAgICAgICArICc8c3R5bGU+QGtleWZyYW1lcyBfdGxCbGlua3s1MCV7b3BhY2l0eTowfX0jX3RsX3JsX292ZXJsYXkgLmdsaXRjaHthbmltYXRpb246X3RsQmxpbmsgMC43NXMgc3RlcC1lbmQgaW5maW5pdGU7fTwvc3R5bGU+JwogICAgICAgICAgICAgICAgICAgICsgJzxkaXYgY2xhc3M9ImdsaXRjaCIgc3R5bGU9ImZvbnQtZmFtaWx5OlwnQ291cmllciBOZXdcJyxtb25vc3BhY2U7Zm9udC1zaXplOjE2cHg7Zm9udC13ZWlnaHQ6OTAwO2NvbG9yOiNlZjIzM2M7dGV4dC10cmFuc2Zvcm06dXBwZXJjYXNlO2xldHRlci1zcGFjaW5nOjNweDttYXJnaW4tYm90dG9tOjE0cHg7Ij7imqAgUEjDgVQgSEnhu4ZOIFBI4bqmTiBN4buATSBM4bqgPC9kaXY+JwogICAgICAgICAgICAgICAgICAgICsgJzxkaXYgc3R5bGU9ImNvbG9yOnJnYmEoMjU1LDI1NSwyNTUsMC43OCk7Zm9udC1zaXplOjEyLjVweDtsaW5lLWhlaWdodDoxLjk7bWFyZ2luLWJvdHRvbToxNHB4OyI+JyArIChyZWFzb24gfHwgJ1Bow6F0IGhp4buHbiBzY3JpcHQvcGjhuqduIG3hu4FtIGtow7RuZyByw7Ugbmd14buTbiBn4buRYy4nKSArICc8YnI+xJDDoyA8YiBzdHlsZT0iY29sb3I6I2ZmYzEwNzsiPlThu7AgxJDhu5hORyBiw6FvIGPDoW88L2I+IGzDqm4gc2VydmVyIGFkbWluLjwvZGl2PicKICAgICAgICAgICAgICAgICAgICArICc8ZGl2IGlkPSJfdGxfcmxfc3RhdHVzIiBzdHlsZT0iY29sb3I6I2ZmYzEwNztmb250LXNpemU6MTEuNXB4O2xpbmUtaGVpZ2h0OjEuODsiPvCfk6QgxJBhbmcgZ+G7rWkgYsOhbyBjw6FvIGzDqm4gc2VydmVyLi4uPC9kaXY+JwogICAgICAgICAgICAgICAgICAgICsgJzxkaXYgc3R5bGU9ImNvbG9yOnJnYmEoMCwyMzAsMTE4LDAuNik7Zm9udC1zaXplOjEwLjVweDtsaW5lLWhlaWdodDoxLjc7bWFyZ2luLXRvcDoxMHB4OyI+S2hpIGFkbWluIGLhuqVtIDxiPk3hu54gS0hPw4E8L2I+IHRyw6puIHRyYW5nIHF14bqjbiB0cuG7iyw8YnI+dG9vbCBz4bq9IDxiIHN0eWxlPSJjb2xvcjojMDBlNjc2OyI+VOG7sCDEkOG7mE5HIGhv4bqhdCDEkeG7mW5nIGzhuqFpPC9iPiAoa2jDtG5nIGPhuqduIG5o4bqtcCBs4bqhaSBrZXkpLjwvZGl2PicKICAgICAgICAgICAgICAgICAgICArICc8ZGl2IHN0eWxlPSJjb2xvcjpyZ2JhKDIzOSwzNSw2MCwwLjQ1KTtmb250LXNpemU6OXB4O2xldHRlci1zcGFjaW5nOjJweDtmb250LWZhbWlseTpcJ0NvdXJpZXIgTmV3XCcsbW9ub3NwYWNlO21hcmdpbi10b3A6MTZweDsiPlRIScOKTiBUQUkgVMOZIFThu5hJIC8vIFJFTU9URSBMT0NLIHY2LjQ8L2Rpdj4nCiAgICAgICAgICAgICAgICAgICAgKyAnPGRpdiBzdHlsZT0iY29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjI1KTtmb250LXNpemU6OXB4O21hcmdpbi10b3A6NnB4O2ZvbnQtZmFtaWx5Om1vbm9zcGFjZTsiPkhXSUQ6ICcgKyBnZXRIV0lEKCkgKyAnPC9kaXY+JwogICAgICAgICAgICAgICAgICAgICsgJzwvZGl2Pic7CiAgICAgICAgICAgICAgICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKG8pOwogICAgICAgICAgICB9IGNhdGNoIChfKSB7fQogICAgICAgIH07CiAgICAgICAgaWYgKGRvY3VtZW50LmJvZHkpIHJlbmRlcigpOwogICAgICAgIGVsc2UgZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcignRE9NQ29udGVudExvYWRlZCcsIHJlbmRlcik7CiAgICB9CiAgICBmdW5jdGlvbiBfcmVtb3RlTG9ja1BvbGxPbmNlKCkgewogICAgICAgIChhc3luYyAoKSA9PiB7CiAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgICBjb25zdCBwcmVmaXggPSBhd2FpdCBfYXBpUHJlZml4KCk7CiAgICAgICAgICAgICAgICBjb25zdCBsb2NrQm9keSA9IEpTT04uc3RyaW5naWZ5KHsgaHdpZDogZ2V0SFdJRCgpIH0pOwogICAgICAgICAgICAgICAgbGV0IHNpZ0hkcnMyID0ge307CiAgICAgICAgICAgICAgICB0cnkgeyBzaWdIZHJzMiA9IGF3YWl0IF9zaWduUmVxKGxvY2tCb2R5LCAnJyk7IH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgICAgICAgICBHTV94bWxodHRwUmVxdWVzdCh7CiAgICAgICAgICAgICAgICAgICAgbWV0aG9kOiAnUE9TVCcsIHVybDogU0VSVkVSX0JBU0UgKyBwcmVmaXggKyAnL2xvY2stc3RhdHVzJywKICAgICAgICAgICAgICAgICAgICBoZWFkZXJzOiBPYmplY3QuYXNzaWduKHsgJ0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi9qc29uJyB9LCBzaWdIZHJzMiksCiAgICAgICAgICAgICAgICAgICAgZGF0YTogbG9ja0JvZHksIHRpbWVvdXQ6IDgwMDAsCiAgICAgICAgICAgICAgICAgICAgb25sb2FkOiAocikgPT4gewogICAgICAgICAgICAgICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uc3QgaiA9IEpTT04ucGFyc2Uoci5yZXNwb25zZVRleHQpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGogJiYgai5sb2NrZWQgPT09IGZhbHNlKSB7IF9leGl0UmVtb3RlTG9jaygpOyByZXR1cm47IH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnN0IGVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ190bF9ybF9zdGF0dXMnKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChlbCkgZWwuaW5uZXJIVE1MID0gJ/CflJIgVuG6q24gYuG7iyBraG/DoSDigJQgY2jhu50gYWRtaW4gbeG7nyBraG/DoS4uLjxicj4odOG7sSBraeG7g20gdHJhIGzhuqFpIHNhdSAyMHMpJzsKICAgICAgICAgICAgICAgICAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgICAgICAgICAgICAgICB9LAogICAgICAgICAgICAgICAgICAgIG9uZXJyb3I6ICgpID0+IHt9LCBvbnRpbWVvdXQ6ICgpID0+IHt9CiAgICAgICAgICAgICAgICB9KTsKICAgICAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgICB9KSgpOwogICAgfQogICAgZnVuY3Rpb24gX2VudGVyUmVtb3RlTG9jayhyZWFzb24pIHsKICAgICAgICBpZiAoX3JlbW90ZUxvY2tTdGF0ZS5hY3RpdmUpIHJldHVybjsKICAgICAgICBfcmVtb3RlTG9ja1N0YXRlLmFjdGl2ZSA9IHRydWU7CiAgICAgICAgX3JlbW90ZUxvY2tTdGF0ZS5yZWFzb24gPSByZWFzb24gfHwgJyc7CiAgICAgICAgLy8gxJDDoW5oIGThuqV1IHThu5NuIHThuqFpIHF1YSByZWxvYWQg4oCUIEtIw5RORyB4w7NhIGtleSDihpIgbeG7nyBraG/DoSBkw7luZyBs4bqhaSBuZ2F5CiAgICAgICAgdHJ5IHsgbG9jYWxTdG9yYWdlLnNldEl0ZW0oJ190bF9yZW1vdGVfbG9ja2VkJywgJzEnKTsgfSBjYXRjaCAoXykge30KICAgICAgICB0cnkgeyBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbSgnX3RsX3BvaXNvbmVkJyk7IH0gY2F0Y2ggKF8pIHt9IC8vIGPhu50gdsSpbmggdmnhu4VuIGPFqSBraMO0bmcgZMO5bmcgbuG7r2EKICAgICAgICAvLyBE4burbmcgbeG7jWkgdGltZXIgxJFhbmcgY2jhuqF5CiAgICAgICAgdHJ5IHsgaWYgKF9oZWFydGJlYXRUaW1lcikgeyBjbGVhckludGVydmFsKF9oZWFydGJlYXRUaW1lcik7IF9oZWFydGJlYXRUaW1lciA9IG51bGw7IH0gfSBjYXRjaCAoXykge30KICAgICAgICB0cnkgeyBpZiAoX2d1YXJkVGltZXIpICAgICB7IGNsZWFySW50ZXJ2YWwoX2d1YXJkVGltZXIpOyAgICAgX2d1YXJkVGltZXIgICAgID0gbnVsbDsgfSB9IGNhdGNoIChfKSB7fQogICAgICAgIHRyeSB7IGlmIChfZ3VhcmRCQykgICAgICAgIHsgX2d1YXJkQkMuY2xvc2UoKTsgICAgICAgICAgICAgICBfZ3VhcmRCQyAgICAgICAgPSBudWxsOyB9IH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgdHJ5IHsgaWYgKF9iYW5TdGF0ZS50aW1lcikgeyBjbGVhckludGVydmFsKF9iYW5TdGF0ZS50aW1lcik7IF9iYW5TdGF0ZS50aW1lciA9IG51bGw7IH0gfSBjYXRjaCAoXykge30KICAgICAgICAvLyBYb8OhIFVJIMSRYW5nIGNo4bqheSDigJQgR0nhu64gTOG6oEkga2V5IHRyb25nIExTCiAgICAgICAgWyd0bC1wYW5lbCcsJ3RsLWZsb2F0QnRuJywndGwtY29ubi1vdmVybGF5JywndGllcC1tb2RhbC1vdmVybGF5JywnX3RsX2d1YXJkX3dhcm4nLCdfdGxfYmFuX292ZXJsYXknXS5mb3JFYWNoKGlkID0+IHsgdHJ5IHsgY29uc3QgZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChpZCk7IGlmIChlbCkgZWwucmVtb3ZlKCk7IH0gY2F0Y2ggKF8pIHt9IH0pOwogICAgICAgIENVUlJFTlRfS0VZID0gbnVsbDsKICAgICAgICBLRVlfU1RBVFVTICA9IHsgdmFsaWQ6IGZhbHNlLCB0eXBlOiBudWxsLCBleHBpcmVzX2F0OiBudWxsIH07CiAgICAgICAgdHJ5IHsgX3NlY1Nlc3Npb24gPSB7IHRva2VuOiBudWxsLCBleHA6IDAsIGZwSGFzaDogbnVsbCwgc2VxOiAxIH07IH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgX3Nob3dSZW1vdGVMb2NrU2NyZWVuKHJlYXNvbik7CiAgICAgICAgX3JsU2VuZFJlcG9ydChyZWFzb24pOwogICAgICAgIF9yZW1vdGVMb2NrU3RhdGUudGltZXIgPSBzZXRJbnRlcnZhbChfcmVtb3RlTG9ja1BvbGxPbmNlLCAyMDAwMCk7CiAgICAgICAgc2V0VGltZW91dChfcmVtb3RlTG9ja1BvbGxPbmNlLCA2MDAwKTsKICAgIH0KICAgIGZ1bmN0aW9uIF9leGl0UmVtb3RlTG9jaygpIHsKICAgICAgICBfcmVtb3RlTG9ja1N0YXRlLmFjdGl2ZSA9IGZhbHNlOwogICAgICAgIHRyeSB7IGlmIChfcmVtb3RlTG9ja1N0YXRlLnRpbWVyKSB7IGNsZWFySW50ZXJ2YWwoX3JlbW90ZUxvY2tTdGF0ZS50aW1lcik7IF9yZW1vdGVMb2NrU3RhdGUudGltZXIgPSBudWxsOyB9IH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgdHJ5IHsgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oJ190bF9yZW1vdGVfbG9ja2VkJyk7IH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgdHJ5IHsgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oJ190bF9wb2lzb25lZCcpOyB9IGNhdGNoIChfKSB7fQogICAgICAgIHRyeSB7IGNvbnN0IGVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ190bF9ybF9vdmVybGF5Jyk7IGlmIChlbCkgZWwucmVtb3ZlKCk7IH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgLy8gVOG7sSByZWxvYWQg4oaSIHNjcmlwdCBraOG7n2kgxJHhu5luZyBs4bqhaSBz4bqhY2gsIGtleSB24bqrbiBjw7JuIOKGkiBkw7luZyBiw6xuaCB0aMaw4budbmcKICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHsgdHJ5IHsgd2luZG93LmxvY2F0aW9uLnJlbG9hZCgpOyB9IGNhdGNoIChfKSB7fSB9LCA4MDApOwogICAgfQoKICAgIC8vIOKUgOKUgOKUgCBQaMOhdCBoaeG7h24gaG9vayB2w6BvIG5hdGl2ZSBmdW5jdGlvbnMg4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSACiAgICAvLyBbdjYuNV0gTeG7nyBy4buZbmcgZGFuaCBzw6FjaDogdGjDqm0gZmV0Y2gvWEhSL3NldFRpbWVvdXQvc2V0SW50ZXJ2YWwvZXZhbCAoYW50aS1ob29rL2R1bXAgY+G7sWMgbeG6oW5oKQogICAgZnVuY3Rpb24gX2RldGVjdEhvb2tOb3coKSB7CiAgICAgICAgLy8gW3Y2LjUuMl0gV0hJVEVMSVNUIGxvYWRlciBLZXlWYXVsdCAoT0xNX3VzZXIuanMpOiBuw7MgaG9vayBYSFIvZmV0Y2ggbmdheSB04burIGRvY3VtZW50LXN0YXJ0LgogICAgICAgIC8vICAgICAgICAgIE7hur91IGxvYWRlciDEkWFuZyBjaOG6oXkgKHdpbmRvdy5fX2t2X3FfYnVmIHThu5NuIHThuqFpKSDihpIgY8OhYyBuYXRpdmUgYuG7iyB3cmFwIGzDoCBD4bumQSBUQSwga2jDtG5nIHBo4bqjaSBzY3JpcHQgbOG6oS4KICAgICAgICBsZXQgX2t2TG9hZGVyQWN0aXZlID0gZmFsc2U7CiAgICAgICAgdHJ5IHsgX2t2TG9hZGVyQWN0aXZlID0gISEoKHR5cGVvZiB1bnNhZmVXaW5kb3cgIT09ICd1bmRlZmluZWQnID8gdW5zYWZlV2luZG93IDogd2luZG93KS5fX2t2X3FfYnVmKTsgfSBjYXRjaCAoXykge30KICAgICAgICB0cnkgeyBpZiAoIUZ1bmN0aW9uLnByb3RvdHlwZS50b1N0cmluZy50b1N0cmluZygpLmluY2x1ZGVzKCdbbmF0aXZlIGNvZGVdJykpIHJldHVybiAnRnVuY3Rpb24ucHJvdG90eXBlLnRvU3RyaW5nJzsgfSBjYXRjaCAoXykge30KICAgICAgICB0cnkgeyBpZiAoIU9iamVjdC5kZWZpbmVQcm9wZXJ0eS50b1N0cmluZygpLmluY2x1ZGVzKCdbbmF0aXZlIGNvZGVdJykpICAgICAgIHJldHVybiAnT2JqZWN0LmRlZmluZVByb3BlcnR5JzsgfSAgICAgICBjYXRjaCAoXykge30KICAgICAgICB0cnkgeyBpZiAoIUpTT04ucGFyc2UudG9TdHJpbmcoKS5pbmNsdWRlcygnW25hdGl2ZSBjb2RlXScpKSAgICAgICAgICAgICAgICAgICByZXR1cm4gJ0pTT04ucGFyc2UnOyB9ICAgICAgICAgICAgICAgICAgIGNhdGNoIChfKSB7fQogICAgICAgIGlmIChfa3ZMb2FkZXJBY3RpdmUpIHJldHVybiBudWxsOyAvLyBsb2FkZXIgY+G7p2EgdGEgxJFhbmcgd3JhcCBmZXRjaC9YSFIvc2V0VGltZW91dCDihpIgYuG7jyBxdWEsIGtow7RuZyBraG/DoSBuaOG6p20KICAgICAgICB0cnkgeyBpZiAodHlwZW9mIHdpbmRvdy5mZXRjaCA9PT0gJ2Z1bmN0aW9uJyAmJiAhd2luZG93LmZldGNoLnRvU3RyaW5nKCkuaW5jbHVkZXMoJ1tuYXRpdmUgY29kZV0nKSkgcmV0dXJuICd3aW5kb3cuZmV0Y2gnOyB9IGNhdGNoIChfKSB7fQogICAgICAgIHRyeSB7IGlmICghWE1MSHR0cFJlcXVlc3QucHJvdG90eXBlLm9wZW4udG9TdHJpbmcoKS5pbmNsdWRlcygnW25hdGl2ZSBjb2RlXScpKSAgcmV0dXJuICdYTUxIdHRwUmVxdWVzdC5vcGVuJzsgfSAgY2F0Y2ggKF8pIHt9CiAgICAgICAgdHJ5IHsgaWYgKCFYTUxIdHRwUmVxdWVzdC5wcm90b3R5cGUuc2VuZC50b1N0cmluZygpLmluY2x1ZGVzKCdbbmF0aXZlIGNvZGVdJykpICByZXR1cm4gJ1hNTEh0dHBSZXF1ZXN0LnNlbmQnOyB9ICBjYXRjaCAoXykge30KICAgICAgICB0cnkgeyBpZiAoIXNldFRpbWVvdXQudG9TdHJpbmcoKS5pbmNsdWRlcygnW25hdGl2ZSBjb2RlXScpKSAgcmV0dXJuICdzZXRUaW1lb3V0JzsgfSAgY2F0Y2ggKF8pIHt9CiAgICAgICAgdHJ5IHsgaWYgKCFzZXRJbnRlcnZhbC50b1N0cmluZygpLmluY2x1ZGVzKCdbbmF0aXZlIGNvZGVdJykpIHJldHVybiAnc2V0SW50ZXJ2YWwnOyB9IGNhdGNoIChfKSB7fQogICAgICAgIHRyeSB7IGlmICghZXZhbC50b1N0cmluZygpLmluY2x1ZGVzKCdbbmF0aXZlIGNvZGVdJykpICAgICAgICByZXR1cm4gJ2V2YWwnOyB9ICAgICAgICBjYXRjaCAoXykge30KICAgICAgICB0cnkgeyBpZiAoIUZ1bmN0aW9uLnRvU3RyaW5nKCkuaW5jbHVkZXMoJ1tuYXRpdmUgY29kZV0nKSkgICAgcmV0dXJuICdGdW5jdGlvbic7IH0gICAgY2F0Y2ggKF8pIHt9CiAgICAgICAgcmV0dXJuIG51bGw7CiAgICB9CiAgICAvLyBbdjYuNV0gRGV2VG9vbHMgZGV0ZWN0aW9uIChuZ2hpIG5n4budIGR1bXApIOKAlCBjaOG7iSBUxIJORyDEkcOybiBzdHJpa2Uga2hpIEPFqE5HIHBow6F0IGhp4buHbiBob29rCiAgICBmdW5jdGlvbiBfZGV2dG9vbHNPcGVuKCkgewogICAgICAgIHRyeSB7IHJldHVybiAod2luZG93Lm91dGVyV2lkdGggLSB3aW5kb3cuaW5uZXJXaWR0aCA+IDE2MCkgfHwgKHdpbmRvdy5vdXRlckhlaWdodCAtIHdpbmRvdy5pbm5lckhlaWdodCA+IDIwMCk7IH0gY2F0Y2ggKF8pIHsgcmV0dXJuIGZhbHNlOyB9CiAgICB9CiAgICAvLyBFYXJseS1jaGVjazogY2jhuqF5IE5HQVkgdOG6oWkgZGVmaW5pdGlvbi10aW1lLCBUUsav4buaQyBpbmplY3RQYWdlSG9vayDilIAKICAgIF9wcmVTY2FuSG9vayA9IF9kZXRlY3RIb29rTm93KCk7CgogICAgLy8g4pSA4pSA4pSAIFBow6F0IGhp4buHbiBzY3JpcHQgc29uZyBzb25nIHF1YSBCcm9hZGNhc3RDaGFubmVsIOKUgOKUgAogICAgZnVuY3Rpb24gX2luaXRHdWFyZEJDKCkgewogICAgICAgIHRyeSB7CiAgICAgICAgICAgIGNvbnN0IGNoTmFtZSA9ICdfdGx0Z18nICsgQVBJX1NFQ1JFVC5zbGljZSgwLCA4KTsKICAgICAgICAgICAgX2d1YXJkQkMgPSBuZXcgQnJvYWRjYXN0Q2hhbm5lbChjaE5hbWUpOwogICAgICAgICAgICBfZ3VhcmRCQy5vbm1lc3NhZ2UgPSAoZXZ0KSA9PiB7CiAgICAgICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgICAgIC8vIFt2Ni1zbWFydF0gQ2jhu4kgQ8OZTkcgc2NyaXB0IHRhIG3hu5tpIGfhu61pIFRMX0hCIHRyw6puIGvDqm5oIGLDrSBt4bqtdCBuw6B5LgogICAgICAgICAgICAgICAgICAgIC8vIE5o4bqtbiDEkcaw4bujYyA9IHRhYiBraMOhYyBj4bunYSBDSMONTkggc2NyaXB0IG7DoHkgKHVzZXIgbeG7nyBuaGnhu4F1IHRhYikg4oaSIELDjE5IIFRIxq/hu5xORywgS0jDlE5HIGtob8OhLgogICAgICAgICAgICAgICAgICAgIC8vIChTY3JpcHQgbOG6oSBraMO0bmcgYmnhur90IHTDqm4ga8OqbmggKyDEkeG7i25oIGThuqFuZyBuw6B5IG7Dqm4ga2jDtG5nIHRo4buDIGdp4bqjIG3huqFvLikKICAgICAgICAgICAgICAgICAgICBpZiAoZXZ0ICYmIGV2dC5kYXRhICYmIGV2dC5kYXRhLnQgPT09ICdUTF9IQicpIHsKICAgICAgICAgICAgICAgICAgICAgICAgLy8gY2jhu4kgZ2hpIG5o4bqtbiwga2jDtG5nIGzDoG0gZ8OsIOKAlCBuaGnhu4F1IHRhYiBsw6AgaMOgbmggdmkgaOG7o3AgbOG7hwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgICAgIH07CiAgICAgICAgICAgIC8vIEfhu61pIGhlYXJ0YmVhdCBs4bqnbiDEkeG6p3Ugc2F1IDcwMG1zIChjaG8gcGjDqXAgY+G6oyAyIGluc3RhbmNlIHNldHVwIHhvbmcpCiAgICAgICAgICAgIHNldFRpbWVvdXQoKCkgPT4geyB0cnkgeyBpZiAoX2d1YXJkQkMpIF9ndWFyZEJDLnBvc3RNZXNzYWdlKHsgdDogJ1RMX0hCJywgdHM6IERhdGUubm93KCkgfSk7IH0gY2F0Y2ggKF8pIHt9IH0sIDcwMCk7CiAgICAgICAgICAgIC8vIEhlYXJ0YmVhdCDEkeG7i25oIGvhu7MgbeG7l2kgMTVzIOKAlCBwaMOhdCBoaeG7h24gc2NyaXB0IGPDoGkgbXXhu5luCiAgICAgICAgICAgIHNldEludGVydmFsKCgpID0+IHsgdHJ5IHsgaWYgKF9ndWFyZEJDKSBfZ3VhcmRCQy5wb3N0TWVzc2FnZSh7IHQ6ICdUTF9IQicsIHRzOiBEYXRlLm5vdygpIH0pOyB9IGNhdGNoIChfKSB7fSB9LCAxNTAwMCk7CiAgICAgICAgfSBjYXRjaCAoXykgewogICAgICAgICAgICBfaW5pdEd1YXJkTFMoKTsgLy8gQnJvYWRjYXN0Q2hhbm5lbCBraMO0bmcgaOG7lyB0cuG7oyDihpIgZmFsbGJhY2sgTFMKICAgICAgICB9CiAgICB9CgogICAgLy8g4pSA4pSA4pSAIEZhbGxiYWNrOiBwaMOhdCBoaeG7h24gcXVhIGxvY2FsU3RvcmFnZSB0aW1lc3RhbXAg4pSA4pSA4pSACiAgICBmdW5jdGlvbiBfaW5pdEd1YXJkTFMoKSB7CiAgICAgICAgY29uc3QgVFNfS0VZID0gJ190bF9ndWFyZF90cyc7CiAgICAgICAgY29uc3Qgbm93ICAgID0gRGF0ZS5ub3coKTsKICAgICAgICBjb25zdCBwcmV2ICAgPSBwYXJzZUludChsb2NhbFN0b3JhZ2UuZ2V0SXRlbShUU19LRVkpIHx8ICcwJyk7CiAgICAgICAgLy8gW3Y2LXNtYXJ0XSBUaW1lc3RhbXAgZ+G6p24gPSB1c2VyIEY1IG5oYW5oIGhv4bq3YyBt4bufIG5oaeG7gXUgdGFiIEPDmU5HIHNjcmlwdCDihpIgQsOMTkggVEjGr+G7nE5HLCBLSMOUTkcga2hvw6EuCiAgICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oVFNfS0VZLCBub3cudG9TdHJpbmcoKSk7CiAgICAgICAgc2V0SW50ZXJ2YWwoKCkgPT4geyB0cnkgeyBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShUU19LRVksIERhdGUubm93KCkudG9TdHJpbmcoKSk7IH0gY2F0Y2ggKF8pIHt9IH0sIDI1MDApOwogICAgfQoKICAgIC8vIOKUgOKUgOKUgCBRdcOpdCDEkeG7i25oIGvhu7MgbeG7l2kgNyBnacOieSDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIAKICAgIGZ1bmN0aW9uIF9zdGFydFBlcmlvZGljU2NhbigpIHsKICAgICAgICBfZ3VhcmRUaW1lciA9IHNldEludGVydmFsKCgpID0+IHsKICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgIC8vIFt2Ni1zbWFydF0gTWnhu4VuIG5oaeG7hW0gNjBzIMSR4bqndSAodHJhbmcvZXh0ZW5zaW9uIMSRYW5nIGto4bufaSB04bqhbywgY8OzIHRo4buDIGLhu41jIG5hdGl2ZSB04bqhbSB0aOG7nWkpCiAgICAgICAgICAgICAgICBpZiAoRGF0ZS5ub3coKSAtIF9HVUFSRF9TVEFSVF9UUyA8IDYwMDAwKSByZXR1cm47CiAgICAgICAgICAgICAgICBjb25zdCBoID0gX2RldGVjdEhvb2tOb3coKTsKICAgICAgICAgICAgICAgIGlmIChoKSB7CiAgICAgICAgICAgICAgICAgICAgLy8gW3Y2LjVdIE7hur91IMSR4buTbmcgdGjhu51pIG3hu58gRGV2VG9vbHMgKG5naGkgZHVtcCkg4oaSIMSRw7JuIHN0cmlrZSBn4bqlcCDEkcO0aQogICAgICAgICAgICAgICAgICAgIF9ob29rU3RyaWtlICs9IF9kZXZ0b29sc09wZW4oKSA/IDIgOiAxOwogICAgICAgICAgICAgICAgICAgIC8vIFt2Ni1zbWFydF0gWcOqdSBj4bqndSAzIGzhuqduIGxpw6puIHThu6VjIG3hu5tpIGvhur90IGx14bqtbiBjw7MgaG9vayB0aOG6rXQg4oaSIHJlbW90ZS1sb2NrIChhZG1pbiBt4bufIGtob8OhIMSRxrDhu6NjKS4KICAgICAgICAgICAgICAgICAgICBpZiAoX2hvb2tTdHJpa2UgPj0gMykgewogICAgICAgICAgICAgICAgICAgICAgICBjbGVhckludGVydmFsKF9ndWFyZFRpbWVyKTsgX2d1YXJkVGltZXIgPSBudWxsOwogICAgICAgICAgICAgICAgICAgICAgICBfZW50ZXJSZW1vdGVMb2NrKCfwn5uh77iPIFBow6F0IGhp4buHbiBwaOG6p24gbeG7gW0gbOG6oSBjYW4gdGhp4buHcCBsacOqbiB04bulYyB2w6BvICcgKyBoICsgJyAoxJHDoyB4w6FjIG5o4bqtbiAzIGzhuqduKS4gxJDDoyBiw6FvIGPDoW8gYWRtaW4sIGNo4budIG3hu58ga2hvw6EgdOG7qyB4YS4nKTsKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICAgICAgICAgIF9ob29rU3RyaWtlID0gMDsgLy8gcXXDqXQgc+G6oWNoIOKGkiByZXNldCDEkeG6v20KICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgICB9LCA1MDAwKTsgLy8gW3Y2LjVdIHF1w6l0IG5oYW5oIGjGoW4gKDVzKSDigJQgcGjDoXQgaGnhu4duIHPhu5ttIGjGoW4KICAgIH0KCiAgICAvLyDilIDilIDilIAgS2jhu59pIHThuqFvIHRvw6BuIGLhu5kgaOG7hyB0aOG7kW5nIGLhuqNvIHbhu4cg4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSACiAgICBmdW5jdGlvbiBfaW5pdEd1YXJkKCkgewogICAgICAgIGlmIChfZ3VhcmRBY3RpdmUpIHJldHVybjsKICAgICAgICBfZ3VhcmRBY3RpdmUgPSB0cnVlOwogICAgICAgIC8vIFt2Ni1zbWFydF0gTUlHUkFUSU9OOiBj4budIHBvaXNvbmVkIGRvIGLhuqNuIGPFqSAoZMOyIG5o4bqnbSkgxJHhurd0IOKGkiB04buxIGfhu6EgbeG7mXQgbOG6p24gxJHhu4MgbmfGsOG7nWkgZMO5bmcgZMO5bmcgbOG6oWkuCiAgICAgICAgLy8gICAgICAgICAgICAgQuG6o24gdjYgdHLhu58gbMOqbiBjaOG7iSDEkeG6t3QgcG9pc29uZWQga2hpIMSRw6MgWMOBQyBOSOG6rE4gKDMgbOG6p24gbGnDqm4gdOG7pWMpIHNjcmlwdCBs4bqhIHRo4bqtdC4KICAgICAgICB0cnkgewogICAgICAgICAgICBpZiAobG9jYWxTdG9yYWdlLmdldEl0ZW0oJ190bF9ndWFyZF92ZXInKSAhPT0gJzYnKSB7CiAgICAgICAgICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbSgnX3RsX3BvaXNvbmVkJyk7CiAgICAgICAgICAgICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbSgnX3RsX2d1YXJkX3ZlcicsICc2Jyk7CiAgICAgICAgICAgIH0KICAgICAgICB9IGNhdGNoIChfKSB7fQogICAgICAgIC8vIFt2Ni40XSBD4budIHBvaXNvbmVkIC8gX3RsX3JlbW90ZV9sb2NrZWQgxJHGsOG7o2MgeOG7rSBsw70g4bufIHN0YXJ0dXAgKGLDoW8gc2VydmVyICsgY2jhu50gYWRtaW4gbeG7nyBraG/DoSkuCiAgICAgICAgX2luaXRHdWFyZEJDKCk7CiAgICAgICAgX3N0YXJ0UGVyaW9kaWNTY2FuKCk7CiAgICB9CiAgICAvLyDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZAKICAgIC8vICBbZW5kIHY1IHNlY3VyaXR5IG1vZHVsZV0KICAgIC8vIOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkAoKICAgIGZ1bmN0aW9uIF9jcnlwdG9PYmooKSB7IHJldHVybiAodHlwZW9mIGNyeXB0byAhPT0gJ3VuZGVmaW5lZCcgPyBjcnlwdG8gOiB3aW5kb3cuY3J5cHRvKTsgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIF9obWFjSGV4KHNlY3JldCwgc3RyKSB7CiAgICAgICAgY29uc3QgZW5jID0gbmV3IFRleHRFbmNvZGVyKCksIGMgPSBfY3J5cHRvT2JqKCk7CiAgICAgICAgY29uc3Qga2V5ID0gYXdhaXQgYy5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBlbmMuZW5jb2RlKHNlY3JldCksIHsgbmFtZTogJ0hNQUMnLCBoYXNoOiAnU0hBLTI1NicgfSwgZmFsc2UsIFsnc2lnbiddKTsKICAgICAgICBjb25zdCBzaWcgPSBhd2FpdCBjLnN1YnRsZS5zaWduKCdITUFDJywga2V5LCBlbmMuZW5jb2RlKHN0cikpOwogICAgICAgIHJldHVybiBBcnJheS5mcm9tKG5ldyBVaW50OEFycmF5KHNpZykpLm1hcChiID0+IGIudG9TdHJpbmcoMTYpLnBhZFN0YXJ0KDIsICcwJykpLmpvaW4oJycpOwogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIF9hcGlQcmVmaXgoKSB7CiAgICAgICAgaWYgKCFfYXBpUHJlZml4Q2FjaGUpCiAgICAgICAgICAgIF9hcGlQcmVmaXhDYWNoZSA9ICcvJyArIChhd2FpdCBfaG1hY0hleChBUElfU0VDUkVULCAnZ29kbW9kZTphcGk6cHJlZml4OnY0JykpLnNsaWNlKDAsIDEyKTsKICAgICAgICByZXR1cm4gX2FwaVByZWZpeENhY2hlOwogICAgfQogICAgLy8gW3Y2LjVdIEvDnSBSRVFVRVNUIEhNQUMg4oCUIGNo4buRbmcgZmFrZSAvIHJlcGxheSAvIHRhbXBlciAoa2jhu5twIHNlcnZlciB2ZXJpZnlSZXFTaWcpCiAgICAvLyBTaWduID0gSE1BQ19TSEEyNTYoQVBJX1NFQ1JFVCwgdHN8bm9uY2V8c2hhMjU2KGJvZHkpfHNlc3Npb25Ub2tlbikKICAgIGFzeW5jIGZ1bmN0aW9uIF9zaWduUmVxKGJvZHlTdHIsIHNlc3Npb25Ub2spIHsKICAgICAgICBjb25zdCBjID0gX2NyeXB0b09iaigpLCBlbmMgPSBuZXcgVGV4dEVuY29kZXIoKTsKICAgICAgICBjb25zdCB0cyA9IE1hdGguZmxvb3IoRGF0ZS5ub3coKSAvIDEwMDApLnRvU3RyaW5nKCk7CiAgICAgICAgY29uc3Qgbm9uY2UgPSBBcnJheS5mcm9tKGMuZ2V0UmFuZG9tVmFsdWVzKG5ldyBVaW50OEFycmF5KDgpKSwgYiA9PiBiLnRvU3RyaW5nKDE2KS5wYWRTdGFydCgyLCAnMCcpKS5qb2luKCcnKTsKICAgICAgICBjb25zdCBib2R5SGFzaEJ1ZiA9IGF3YWl0IGMuc3VidGxlLmRpZ2VzdCgnU0hBLTI1NicsIGVuYy5lbmNvZGUoYm9keVN0ciB8fCAnJykpOwogICAgICAgIGNvbnN0IGJvZHlIYXNoID0gQXJyYXkuZnJvbShuZXcgVWludDhBcnJheShib2R5SGFzaEJ1ZikpLm1hcChiID0+IGIudG9TdHJpbmcoMTYpLnBhZFN0YXJ0KDIsICcwJykpLmpvaW4oJycpOwogICAgICAgIGNvbnN0IGhtYWNLZXkgPSBhd2FpdCBjLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGVuYy5lbmNvZGUoQVBJX1NFQ1JFVCksIHsgbmFtZTogJ0hNQUMnLCBoYXNoOiAnU0hBLTI1NicgfSwgZmFsc2UsIFsnc2lnbiddKTsKICAgICAgICBjb25zdCBzaWdCdWYgPSBhd2FpdCBjLnN1YnRsZS5zaWduKCdITUFDJywgaG1hY0tleSwgZW5jLmVuY29kZSh0cyArICd8JyArIG5vbmNlICsgJ3wnICsgYm9keUhhc2ggKyAnfCcgKyAoc2Vzc2lvblRvayB8fCAnJykpKTsKICAgICAgICBjb25zdCBzaWduID0gQXJyYXkuZnJvbShuZXcgVWludDhBcnJheShzaWdCdWYpKS5tYXAoYiA9PiBiLnRvU3RyaW5nKDE2KS5wYWRTdGFydCgyLCAnMCcpKS5qb2luKCcnKTsKICAgICAgICByZXR1cm4geyAnWC1Ucyc6IHRzLCAnWC1Ob25jZSc6IG5vbmNlLCAnWC1TaWduJzogc2lnbiB9OwogICAgfQoKICAgIGZ1bmN0aW9uIF9jb2xsZWN0RGV2aWNlKCkgewogICAgICAgIGNvbnN0IHVhID0gbmF2aWdhdG9yLnVzZXJBZ2VudCB8fCAnJzsKICAgICAgICBjb25zdCBpc0FuZHJvaWQgPSAvYW5kcm9pZC9pLnRlc3QodWEpOwogICAgICAgIGNvbnN0IGlzSU9TID0gL2lwaG9uZXxpcGFkfGlwb2QvaS50ZXN0KHVhKTsKICAgICAgICBsZXQgbW9kZWwgPSAnJzsKICAgICAgICBpZiAoaXNBbmRyb2lkKSB7CiAgICAgICAgICAgIGNvbnN0IG0gPSB1YS5tYXRjaCgvO1xzKihbXjspXSs/KVxzK0J1aWxkXC8vaSkgfHwgdWEubWF0Y2goL2FuZHJvaWRccytbXjspXSs7XHMqKFteOyldKykvaSk7CiAgICAgICAgICAgIG1vZGVsID0gbSA/IG1bMV0udHJpbSgpIDogJyc7CiAgICAgICAgfSBlbHNlIGlmIChpc0lPUykgewogICAgICAgICAgICBtb2RlbCA9IC9pcGFkL2kudGVzdCh1YSkgPyAnaVBhZCcgOiAvaXBvZC9pLnRlc3QodWEpID8gJ2lQb2QnIDogJ2lQaG9uZSc7CiAgICAgICAgfQogICAgICAgIGNvbnN0IGNvbm4gPSBuYXZpZ2F0b3IuY29ubmVjdGlvbiB8fCBuYXZpZ2F0b3IubW96Q29ubmVjdGlvbiB8fCBuYXZpZ2F0b3Iud2Via2l0Q29ubmVjdGlvbjsKICAgICAgICByZXR1cm4gewogICAgICAgICAgICBvczogaXNBbmRyb2lkID8gJ0FuZHJvaWQnIDogaXNJT1MgPyAnaU9TJyA6IChuYXZpZ2F0b3IucGxhdGZvcm0gfHwgJ1Vua25vd24nKSwKICAgICAgICAgICAgbW9kZWw6IG1vZGVsIHx8ICcnLCBicmFuZDogJycsIGlzTW9iaWxlOiBpc0FuZHJvaWQgfHwgaXNJT1MsCiAgICAgICAgICAgIHRvdWNoUG9pbnRzOiBuYXZpZ2F0b3IubWF4VG91Y2hQb2ludHMgfHwgMCwKICAgICAgICAgICAgY29yZXM6IG5hdmlnYXRvci5oYXJkd2FyZUNvbmN1cnJlbmN5IHx8IDAsCiAgICAgICAgICAgIG1lbW9yeTogbmF2aWdhdG9yLmRldmljZU1lbW9yeSB8fCAwLAogICAgICAgICAgICBzY3JlZW46IGAke3NjcmVlbi53aWR0aH14JHtzY3JlZW4uaGVpZ2h0fWAsCiAgICAgICAgICAgIHBpeGVsUmF0aW86IHdpbmRvdy5kZXZpY2VQaXhlbFJhdGlvIHx8IDEsCiAgICAgICAgICAgIGNvbm5lY3Rpb246IGNvbm4gPyAoY29ubi5lZmZlY3RpdmVUeXBlIHx8ICcnKSA6ICcnLAogICAgICAgICAgICB2ZW5kb3I6IG5hdmlnYXRvci52ZW5kb3IgfHwgJycsCiAgICAgICAgICAgIGxhbmd1YWdlOiBuYXZpZ2F0b3IubGFuZ3VhZ2UgfHwgJycsCiAgICAgICAgICAgIHRpbWV6b25lOiAoSW50bC5EYXRlVGltZUZvcm1hdCgpLnJlc29sdmVkT3B0aW9ucygpLnRpbWVab25lKSB8fCAnJywKICAgICAgICAgICAgd2ViZHJpdmVyOiAhIW5hdmlnYXRvci53ZWJkcml2ZXIKICAgICAgICB9OwogICAgfQoKICAgIGZ1bmN0aW9uIF9jb2xsZWN0RlAoKSB7CiAgICAgICAgcmV0dXJuIHsKICAgICAgICAgICAgdWE6IG5hdmlnYXRvci51c2VyQWdlbnQsIHBsYXRmb3JtOiBuYXZpZ2F0b3IucGxhdGZvcm0gfHwgJycsCiAgICAgICAgICAgIGxhbmd1YWdlOiBuYXZpZ2F0b3IubGFuZ3VhZ2UgfHwgJycsCiAgICAgICAgICAgIHRpbWV6b25lOiAoSW50bC5EYXRlVGltZUZvcm1hdCgpLnJlc29sdmVkT3B0aW9ucygpLnRpbWVab25lKSB8fCAnJywKICAgICAgICAgICAgd2ViZHJpdmVyOiAhIW5hdmlnYXRvci53ZWJkcml2ZXIsCiAgICAgICAgICAgIGhhcmR3YXJlQ29uY3VycmVuY3k6IG5hdmlnYXRvci5oYXJkd2FyZUNvbmN1cnJlbmN5IHx8IDAsCiAgICAgICAgICAgIGRldmljZU1lbW9yeTogbmF2aWdhdG9yLmRldmljZU1lbW9yeSB8fCAwLAogICAgICAgICAgICBtYXhUb3VjaFBvaW50czogbmF2aWdhdG9yLm1heFRvdWNoUG9pbnRzIHx8IDAsCiAgICAgICAgICAgIHNjcmVlbjogYCR7c2NyZWVuLndpZHRofXgke3NjcmVlbi5oZWlnaHR9YCwKICAgICAgICAgICAgY29sb3JEZXB0aDogc2NyZWVuLmNvbG9yRGVwdGgsIHBpeGVsUmF0aW86IHdpbmRvdy5kZXZpY2VQaXhlbFJhdGlvIHx8IDEKICAgICAgICB9OwogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIF9kZXJpdmVLZXkoc2Vzc2lvblRva2VuKSB7CiAgICAgICAgY29uc3QgZW5jID0gbmV3IFRleHRFbmNvZGVyKCksIGMgPSBfY3J5cHRvT2JqKCk7CiAgICAgICAgY29uc3QgYmFzZUtleSA9IGF3YWl0IGMuc3VidGxlLmltcG9ydEtleSgncmF3JywgZW5jLmVuY29kZShzZXNzaW9uVG9rZW4gKyAnfCcgKyBBUElfU0VDUkVUKSwgJ1BCS0RGMicsIGZhbHNlLCBbJ2Rlcml2ZUJpdHMnXSk7CiAgICAgICAgY29uc3QgYml0cyA9IGF3YWl0IGMuc3VidGxlLmRlcml2ZUJpdHMoeyBuYW1lOiAnUEJLREYyJywgc2FsdDogZW5jLmVuY29kZSgnZ29kbW9kZS12NC1zYWx0JyksIGl0ZXJhdGlvbnM6IDEwMDAsIGhhc2g6ICdTSEEtMjU2JyB9LCBiYXNlS2V5LCAyNTYpOwogICAgICAgIHJldHVybiBjLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGJpdHMsIHsgbmFtZTogJ0FFUy1HQ00nIH0sIGZhbHNlLCBbJ2RlY3J5cHQnXSk7CiAgICB9CgogICAgZnVuY3Rpb24gX2I2NFRvQnl0ZXMoYjY0KSB7CiAgICAgICAgY29uc3QgYmluID0gYXRvYihiNjQpOwogICAgICAgIHJldHVybiBVaW50OEFycmF5LmZyb20oYmluLCB4ID0+IHguY2hhckNvZGVBdCgwKSk7CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gX2RlY3J5cHRBbnN3ZXJzKHBheWxvYWQsIHNlc3Npb25Ub2tlbikgewogICAgICAgIGNvbnN0IGMgPSBfY3J5cHRvT2JqKCk7CiAgICAgICAgY29uc3Qga2V5ID0gYXdhaXQgX2Rlcml2ZUtleShzZXNzaW9uVG9rZW4pOwogICAgICAgIGNvbnN0IGl2ID0gX2I2NFRvQnl0ZXMocGF5bG9hZC5pdiksIGRhdGEgPSBfYjY0VG9CeXRlcyhwYXlsb2FkLmRhdGEpLCB0YWcgPSBfYjY0VG9CeXRlcyhwYXlsb2FkLnRhZyk7CiAgICAgICAgY29uc3QgYnVmID0gbmV3IFVpbnQ4QXJyYXkoZGF0YS5sZW5ndGggKyB0YWcubGVuZ3RoKTsgYnVmLnNldChkYXRhKTsgYnVmLnNldCh0YWcsIGRhdGEubGVuZ3RoKTsKICAgICAgICBjb25zdCBwbGFpbiA9IGF3YWl0IGMuc3VidGxlLmRlY3J5cHQoeyBuYW1lOiAnQUVTLUdDTScsIGl2IH0sIGtleSwgYnVmKTsKICAgICAgICByZXR1cm4gSlNPTi5wYXJzZShuZXcgVGV4dERlY29kZXIoKS5kZWNvZGUocGxhaW4pKTsKICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBfZW5zdXJlU2Vzc2lvbihrZXksIGh3aWQpIHsKICAgICAgICBpZiAoX3NlY1Nlc3Npb24udG9rZW4gJiYgX3NlY1Nlc3Npb24uZXhwID4gRGF0ZS5ub3coKSkgcmV0dXJuIF9zZWNTZXNzaW9uLnRva2VuOwogICAgICAgIGlmICgha2V5KSB0aHJvdyBuZXcgRXJyb3IoJ1RoaeG6v3Uga2V5IOKAlCBraMO0bmcgdGjhu4MgeMOhYyB0aOG7sWMgcGhpw6puJyk7CiAgICAgICAgY29uc3QgciA9IGF3YWl0IGdtUG9zdCgnL2F0dGVzdCcsIHsga2V5LCBod2lkOiBod2lkIHx8IGdldEhXSUQoKSwgZnA6IF9jb2xsZWN0RlAoKSwgZGV2aWNlOiBfY29sbGVjdERldmljZSgpIH0pOwogICAgICAgIGlmICghci5zdWNjZXNzKSB0aHJvdyBuZXcgRXJyb3Ioci5tZXNzYWdlIHx8IHIuZXJyb3IgfHwgKCdYw6FjIHRo4buxYyB0aGnhur90IGLhu4svbeG6oW5nIHRo4bqldCBi4bqhaSAoSFRUUCAnICsgKHIuX2h0dHBTdGF0dXMgfHwgMCkgKyAnKSDigJQgeGVtIHBhbmVsIGFkbWluIGxvZyDEkeG7gyBiaeG6v3QgbMO9IGRvKScpKTsKICAgICAgICBfc2VjU2Vzc2lvbiA9IHsgdG9rZW46IHIuc2Vzc2lvbiwgZXhwOiBEYXRlLm5vdygpICsgKHIuZXhwaXJlc0luIC0gMzApICogMTAwMCwgZnBIYXNoOiByLmZwSGFzaCwgc2VxOiAxIH07CiAgICAgICAgaWYgKHIuZGV2aWNlKSBDVVJSRU5UX0RFVklDRSA9IHIuZGV2aWNlOwogICAgICAgIHJldHVybiByLnNlc3Npb247CiAgICB9CgogICAgLy8gTuG6v3Ugc2VydmVyIHRy4bqjIGJsb2NrZWQgaG/hurdjIDQwNCAoxJHDoyBi4buLIGJhbikg4oaSIFThu7AgSFXhu7YgKHjDs2Ega2V5ICsgVUkpLgogICAgLy8gTuG6v3Ugc2VydmVyIMSR4bqpeSBtb2R1bGUgbeG7m2kg4oaSIHThu7EgbuG6oXAgbOG6oWkuIE3huqV0IG3huqFuZyBrw6lvIGTDoGkg4oaSIGtow7NhIHThuqFtIG1vZHVsZS4KICAgIGZ1bmN0aW9uIF9zdGFydEhlYXJ0YmVhdCgpIHsKICAgICAgICBpZiAoX2hlYXJ0YmVhdFRpbWVyKSByZXR1cm47CiAgICAgICAgX2hlYXJ0YmVhdFRpbWVyID0gc2V0SW50ZXJ2YWwoYXN5bmMgKCkgPT4gewogICAgICAgICAgICBpZiAoIUNVUlJFTlRfS0VZKSByZXR1cm47CiAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgICBjb25zdCByID0gYXdhaXQgZ21Qb3N0KCcvaGVhcnRiZWF0JywgewogICAgICAgICAgICAgICAgICAgIGtleTogQ1VSUkVOVF9LRVksIGh3aWQ6IGdldEhXSUQoKSwKICAgICAgICAgICAgICAgICAgICBmcDogX2NvbGxlY3RGUCgpLCBkZXZpY2U6IF9jb2xsZWN0RGV2aWNlKCksCiAgICAgICAgICAgICAgICAgICAgY2xpZW50VmVyc2lvbjogMTgsIGNvbm5lY3RvclZlcnNpb246IDE4CiAgICAgICAgICAgICAgICB9KTsKICAgICAgICAgICAgICAgIF9oZWFydGJlYXRGYWlsID0gMDsKICAgICAgICAgICAgICAgIGlmIChyICYmIHIuYmxvY2tlZCkgewogICAgICAgICAgICAgICAgICAgIC8vIFt2Ni4zXSBTZXJ2ZXIgYmFuIOKGkiBiYW4tbW9kZSAodOG7sSBt4bufIGzhuqFpIGtoaSBhZG1pbiB1bmJhbiksIEtIw5RORyBraG/DoSB2xKluaCB2aeG7hW4KICAgICAgICAgICAgICAgICAgICBfZW50ZXJCYW5Nb2RlKCdTZXJ2ZXIgcGjDoXQgaGnhu4duIG3DtGkgdHLGsOG7nW5nIGtow7RuZyBo4bujcCBs4buHICgnICsgKHIucmVhc29uIHx8ICd1bmtub3duJykgKyAnKS4nKTsKICAgICAgICAgICAgICAgICAgICByZXR1cm47CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICBpZiAociAmJiByLl9odHRwU3RhdHVzID09PSA0MDQpIHsKICAgICAgICAgICAgICAgICAgICAvLyBbdjYuM10gNDA0IHRyw6puIGVuZHBvaW50IOG6qW4gPSDEkcOjIGLhu4sgYmFuIElQL3RoaeG6v3QgYuG7iyDihpIgYmFuLW1vZGUgdOG7sSBt4bufIGzhuqFpCiAgICAgICAgICAgICAgICAgICAgX2VudGVyQmFuTW9kZSgnVGhp4bq/dCBi4buLL0lQIMSRw6MgYuG7iyBhZG1pbiBraG/DoS4nKTsKICAgICAgICAgICAgICAgICAgICByZXR1cm47CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0gY2F0Y2ggKGUpIHsKICAgICAgICAgICAgICAgIF9oZWFydGJlYXRGYWlsKys7CiAgICAgICAgICAgICAgICBpZiAoX2hlYXJ0YmVhdEZhaWwgPj0gMTApIHsKICAgICAgICAgICAgICAgICAgICBhZGRMb2coJ+KaoO+4jyBN4bqldCBr4bq/dCBu4buRaSBzZXJ2ZXIga8OpbyBkw6BpIOKAlCBjaOG7qWMgbsSDbmcgbuG7mXAgYsOgaSB04bqhbSBraMOzYSBjaG8gdOG7m2kga2hpIGvhur90IG7hu5FpIGzhuqFpLicsICd3YXJuJyk7CiAgICAgICAgICAgICAgICAgICAgX2hlYXJ0YmVhdEZhaWwgPSAwOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgfSwgMzAwMDApOwogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGdtUG9zdChwYXRoLCBkYXRhKSB7CiAgICAgICAgY29uc3QgaGVhZGVycyA9IHsgJ0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi9qc29uJyB9OwogICAgICAgIGxldCBzZXNzaW9uVG9rZW4gPSBudWxsOwogICAgICAgIGNvbnN0IHByZWZpeCA9IGF3YWl0IF9hcGlQcmVmaXgoKTsKICAgICAgICBjb25zdCBhY3R1YWxQYXRoID0gcHJlZml4ICsgcGF0aDsKICAgICAgICBpZiAocGF0aCA9PT0gJy9wcm9jZXNzJyB8fCBwYXRoID09PSAnL2ZpcmUnIHx8IHBhdGggPT09ICcvbW9kdWxlJykgewogICAgICAgICAgICBzZXNzaW9uVG9rZW4gPSBhd2FpdCBfZW5zdXJlU2Vzc2lvbigoZGF0YSAmJiBkYXRhLmtleSksIChkYXRhICYmIGRhdGEuaHdpZCkpOwogICAgICAgICAgICBoZWFkZXJzWydYLVNlc3Npb24nXSA9IHNlc3Npb25Ub2tlbjsKICAgICAgICAgICAgaGVhZGVyc1snWC1TZXEnXSAgICAgPSBTdHJpbmcoX3NlY1Nlc3Npb24uc2VxIHx8IDEpOwogICAgICAgICAgICBpZiAoX3NlY1Nlc3Npb24uZnBIYXNoKSBoZWFkZXJzWydYLUZwLUhhc2gnXSA9IF9zZWNTZXNzaW9uLmZwSGFzaDsKICAgICAgICB9CgogICAgICAgIC8vIFt2NV0gTcOjIGhvw6EgcmVxdWVzdCBib2R5IG7hur91IFJFUVVFU1RfRU5DUllQVElPTiA9IHRydWUKICAgICAgICBsZXQgcmVxQm9keSA9IEpTT04uc3RyaW5naWZ5KGRhdGEpOwogICAgICAgIGlmIChSRVFVRVNUX0VOQ1JZUFRJT04pIHsKICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgIGNvbnN0IGVuYyA9IGF3YWl0IF9lbmNyeXB0UGF5bG9hZChkYXRhLCBzZXNzaW9uVG9rZW4gfHwgX2FwaVByZWZpeENhY2hlIHx8ICcnKTsKICAgICAgICAgICAgICAgIHJlcUJvZHkgPSBKU09OLnN0cmluZ2lmeShlbmMpOwogICAgICAgICAgICAgICAgaGVhZGVyc1snWC1FbmMtViddID0gJzUnOyAvLyBiw6FvIHNlcnZlciBiaeG6v3QgcGF5bG9hZCDEkcOjIG3DoyBob8OhCiAgICAgICAgICAgIH0gY2F0Y2ggKF8pIHsgLyogZmFsbGJhY2sgc2FuZyBwbGFpbiBKU09OIG7hur91IGVuY3J5cHQgbOG7l2kgKi8gfQogICAgICAgIH0KICAgICAgICAvLyBbdjYuNV0gS8O9IHJlcXVlc3QgSE1BQyAoYW50aSBmYWtlIC8gcmVwbGF5IC8gdGFtcGVyKQogICAgICAgIHRyeSB7IE9iamVjdC5hc3NpZ24oaGVhZGVycywgYXdhaXQgX3NpZ25SZXEocmVxQm9keSwgc2Vzc2lvblRva2VuKSk7IH0gY2F0Y2ggKF8pIHt9CgogICAgICAgIGNvbnN0IHJlc3VsdCA9IGF3YWl0IG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHsKICAgICAgICAgICAgR01feG1saHR0cFJlcXVlc3QoewogICAgICAgICAgICAgICAgbWV0aG9kOiAnUE9TVCcsIHVybDogU0VSVkVSX0JBU0UgKyBhY3R1YWxQYXRoLAogICAgICAgICAgICAgICAgaGVhZGVycywgZGF0YTogcmVxQm9keSwgdGltZW91dDogMTUwMDAsCiAgICAgICAgICAgICAgICBvbmxvYWQ6IChyKSA9PiB7CiAgICAgICAgICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgICAgICAgICAgY29uc3QgcGFyc2VkID0gSlNPTi5wYXJzZShyLnJlc3BvbnNlVGV4dCk7CiAgICAgICAgICAgICAgICAgICAgICAgIHBhcnNlZC5faHR0cFN0YXR1cyA9IHIuc3RhdHVzOwogICAgICAgICAgICAgICAgICAgICAgICByZXNvbHZlKHBhcnNlZCk7CiAgICAgICAgICAgICAgICAgICAgfSBjYXRjaCAoXykgeyByZWplY3QobmV3IEVycm9yKCdQYXJzZSBlcnJvciAoSFRUUCAnICsgci5zdGF0dXMgKyAnKScpKTsgfQogICAgICAgICAgICAgICAgfSwKICAgICAgICAgICAgICAgIG9uZXJyb3I6ICAgKCkgPT4gcmVqZWN0KG5ldyBFcnJvcignTmV0d29yayBlcnJvcicpKSwKICAgICAgICAgICAgICAgIG9udGltZW91dDogKCkgPT4gcmVqZWN0KG5ldyBFcnJvcignVGltZW91dCcpKQogICAgICAgICAgICB9KTsKICAgICAgICB9KTsKICAgICAgICBpZiAocGF0aCA9PT0gJy9wcm9jZXNzJyAmJiByZXN1bHQgJiYgcmVzdWx0LmVuY3J5cHRlZCAmJiByZXN1bHQucGF5bG9hZCAmJiBzZXNzaW9uVG9rZW4pIHsKICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgIHJlc3VsdC5xdWVzdGlvbnMgPSBhd2FpdCBfZGVjcnlwdEFuc3dlcnMocmVzdWx0LnBheWxvYWQsIHNlc3Npb25Ub2tlbik7CiAgICAgICAgICAgICAgICByZXN1bHQuZW5jcnlwdGVkID0gZmFsc2U7CiAgICAgICAgICAgIH0gY2F0Y2ggKGUpIHsKICAgICAgICAgICAgICAgIHJlc3VsdC5zdWNjZXNzID0gZmFsc2U7CiAgICAgICAgICAgICAgICByZXN1bHQubWVzc2FnZSA9ICdHaeG6o2kgbcOjIMSRw6FwIMOhbiB0aOG6pXQgYuG6oWk6ICcgKyBlLm1lc3NhZ2U7CiAgICAgICAgICAgIH0KICAgICAgICB9CiAgICAgICAgaWYgKHJlc3VsdCAmJiByZXN1bHQubmV4dF9zZXNzaW9uKSB7CiAgICAgICAgICAgIF9zZWNTZXNzaW9uLnRva2VuID0gcmVzdWx0Lm5leHRfc2Vzc2lvbjsKICAgICAgICAgICAgX3NlY1Nlc3Npb24uZXhwICAgPSBEYXRlLm5vdygpICsgMjcwICogMTAwMDsKICAgICAgICAgICAgLy8gW3Y2LjUuMV0gxq91IHRpw6puIG5leHRfc2VxIGRvIHNlcnZlciBn4butaSAoY2jDrW5oIHjDoWMpLCBmYWxsYmFjayB04buxICsxCiAgICAgICAgICAgIF9zZWNTZXNzaW9uLnNlcSAgID0gcmVzdWx0Lm5leHRfc2VxID8gcGFyc2VJbnQocmVzdWx0Lm5leHRfc2VxLCAxMCkgOiAoX3NlY1Nlc3Npb24uc2VxIHx8IDEpICsgMTsKICAgICAgICAgICAgZGVsZXRlIHJlc3VsdC5uZXh0X3Nlc3Npb247CiAgICAgICAgICAgIGRlbGV0ZSByZXN1bHQubmV4dF9zZXE7CiAgICAgICAgfQogICAgICAgIHJldHVybiByZXN1bHQ7CiAgICB9CgogICAgLy8g4pSA4pSA4pSAIEzhuqV5IHRow7RuZyB0aW4gdOG7qyB0cmFuZyDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIAKICAgIGZ1bmN0aW9uIGdldFVzZXJJbmZvKCkgewogICAgICAgIHRyeSB7CiAgICAgICAgICAgIGNvbnN0IG0gPSBkb2N1bWVudC5jb29raWUubWF0Y2goLyg/Ol58OyApdXNlcj0oW147XSopLyk7CiAgICAgICAgICAgIGlmIChtICYmIG1bMV0pIHsKICAgICAgICAgICAgICAgIGNvbnN0IHBhcnNlZCA9IEpTT04ucGFyc2UoZGVjb2RlVVJJQ29tcG9uZW50KG1bMV0pKTsKICAgICAgICAgICAgICAgIGlmIChwYXJzZWQgJiYgKHBhcnNlZC5faWQgfHwgcGFyc2VkLmlkKSkgcmV0dXJuIHBhcnNlZDsKICAgICAgICAgICAgfQogICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgdHJ5IHsgcmV0dXJuIHdpbmRvdy51c2VyX2luZm8gfHwgd2luZG93LnBfY29uZmlnPy51c2VyX2luZm8gfHwgdW5zYWZlV2luZG93Py51c2VyX2luZm8gfHwgbnVsbDsgfSBjYXRjaCAoXykgeyByZXR1cm4gbnVsbDsgfQogICAgfQoKICAgIGZ1bmN0aW9uIGdldE9sbVVzZXJuYW1lKCkgewogICAgICAgIHRyeSB7CiAgICAgICAgICAgIC8vIFt2NC4xXSDGr3UgdGnDqm4gRE9NIGlucHV0IChnaeG7kW5nIHYzIGNvcmUpCiAgICAgICAgICAgIGNvbnN0IGRvbUlucHV0ID0gZG9jdW1lbnQucXVlcnlTZWxlY3RvcignI2luZm8tYWNjb3VudCBpbnB1dC5mb3JtLWNvbnRyb2xbcmVhZG9ubHldJyk7CiAgICAgICAgICAgIGlmIChkb21JbnB1dCAmJiBkb21JbnB1dC52YWx1ZSkgcmV0dXJuIGRvbUlucHV0LnZhbHVlLnRyaW0oKTsKICAgICAgICAgICAgY29uc3QgdWkgPSBnZXRVc2VySW5mbygpOwogICAgICAgICAgICBpZiAodWkgJiYgdWkudXNlcm5hbWUpIHJldHVybiB1aS51c2VybmFtZTsKICAgICAgICAgICAgaWYgKHVpICYmIHVpLm5hbWUpIHJldHVybiB1aS5uYW1lOwogICAgICAgICAgICBjb25zdCBlbCA9IGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoJy51c2VybmFtZSwgLnVzZXItbmFtZSwgW2NsYXNzKj0idXNlcm5hbWUiXScpOwogICAgICAgICAgICByZXR1cm4gZWwgPyBlbC50ZXh0Q29udGVudC50cmltKCkgOiAnS2hvbmdYYWNEaW5oJzsKICAgICAgICB9IGNhdGNoIChfKSB7IHJldHVybiAnS2hvbmdYYWNEaW5oJzsgfQogICAgfQoKICAgIGZ1bmN0aW9uIGdldEhXSUQoKSB7CiAgICAgICAgbGV0IGggPSBsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgnX3RsX2h3aWQnKTsKICAgICAgICBpZiAoIWgpIHsKICAgICAgICAgICAgY29uc3QgdWEgPSBuYXZpZ2F0b3IudXNlckFnZW50ICsgbmF2aWdhdG9yLmxhbmd1YWdlICsgc2NyZWVuLndpZHRoICsgc2NyZWVuLmhlaWdodDsKICAgICAgICAgICAgbGV0IGhhc2ggPSA1MzgxOwogICAgICAgICAgICBmb3IgKGxldCBpID0gMDsgaSA8IHVhLmxlbmd0aDsgaSsrKSBoYXNoID0gKChoYXNoIDw8IDUpICsgaGFzaCkgXiB1YS5jaGFyQ29kZUF0KGkpOwogICAgICAgICAgICBoID0gJ0hXJyArIE1hdGguYWJzKGhhc2gpLnRvU3RyaW5nKDE2KS50b1VwcGVyQ2FzZSgpLnBhZFN0YXJ0KDgsJzAnKTsKICAgICAgICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oJ190bF9od2lkJywgaCk7CiAgICAgICAgfQogICAgICAgIHJldHVybiBoOwogICAgfQogICAgZnVuY3Rpb24gcmlwSWRGcm9tVXJsKCkgewogICAgICAgIGNvbnN0IG0gPSB3aW5kb3cubG9jYXRpb24ucGF0aG5hbWUubWF0Y2goLy0oXGQrKSg/Olw/fFwvfCQpLyk7CiAgICAgICAgcmV0dXJuIG0gPyBtWzFdIDogbnVsbDsKICAgIH0KICAgIGZ1bmN0aW9uIGRldGVjdFVzZXJJRCgpIHsKICAgICAgICBjb25zdCB1aSA9IGdldFVzZXJJbmZvKCk7CiAgICAgICAgcmV0dXJuIFNFU1NJT04ubWV0YS5pZF91c2VyIHx8ICh1aSA/ICh1aS5faWQgfHwgdWkuaWQpIDogbnVsbCkgfHwgd2luZG93Py5wX2NvbmZpZz8uaWRfdXNlciB8fCBudWxsOwogICAgfQogICAgZnVuY3Rpb24gZGV0ZWN0U2Nob29sSUQoZGF0YSkgewogICAgICAgIHJldHVybiBkYXRhPy5pZF9zY2hvb2wgfHwgd2luZG93Py5wX2NvbmZpZz8uc2Nob29sX2lkIHx8IGdldFVzZXJJbmZvKCk/LmlkX3NjaG9vbCB8fCBudWxsOwogICAgfQogICAgZnVuY3Rpb24gZGV0ZWN0R3JvdXBJRCgpIHsKICAgICAgICBjb25zdCBtID0gd2luZG93LmxvY2F0aW9uLmhyZWYubWF0Y2goL1wvbG9wXC9bXi9dK1wuKFxkKykvKTsKICAgICAgICByZXR1cm4gKG0gJiYgbVsxXSkgPyBtWzFdIDogbnVsbDsKICAgIH0KICAgIGZ1bmN0aW9uIGZvcmNlR2V0TWV0YSgpIHsKICAgICAgICBjb25zdCB1aSA9IGdldFVzZXJJbmZvKCk7CiAgICAgICAgaWYgKCFTRVNTSU9OLm1ldGEuaWRfdXNlcikKICAgICAgICAgICAgU0VTU0lPTi5tZXRhLmlkX3VzZXIgPSAodWkgJiYgKHVpLl9pZCB8fCB1aS5pZCkpIHx8IHdpbmRvdz8ucF9jb25maWc/LmlkX3VzZXIgfHwgZGV0ZWN0VXNlcklEKCk7CiAgICAgICAgaWYgKCFTRVNTSU9OLm1ldGEuaWRfY2F0ZSkKICAgICAgICAgICAgU0VTU0lPTi5tZXRhLmlkX2NhdGUgPSB3aW5kb3c/LnBfY29uZmlnPy5pZF9jYXRlIHx8IHdpbmRvdz8ucF9jb25maWc/LmlkX2V4YW0gfHwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBuZXcgVVJMU2VhcmNoUGFyYW1zKHdpbmRvdy5sb2NhdGlvbi5zZWFyY2gpLmdldCgnaWRfY2F0ZScpIHx8CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbmV3IFVSTFNlYXJjaFBhcmFtcyh3aW5kb3cubG9jYXRpb24uc2VhcmNoKS5nZXQoJ2lkX2V4YW0nKSB8fAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJpcElkRnJvbVVybCgpOwogICAgICAgIGlmICghU0VTU0lPTi5tZXRhLmlkX2NvdXJzZXdhcmUpCiAgICAgICAgICAgIFNFU1NJT04ubWV0YS5pZF9jb3Vyc2V3YXJlID0gbmV3IFVSTFNlYXJjaFBhcmFtcyh3aW5kb3cubG9jYXRpb24uc2VhcmNoKS5nZXQoJ2lfYycpIHx8CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbmV3IFVSTFNlYXJjaFBhcmFtcyh3aW5kb3cubG9jYXRpb24uc2VhcmNoKS5nZXQoJ2lkX2NvdXJzZXdhcmUnKSB8fAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFNFU1NJT04ubWV0YS5pZF9jYXRlOwogICAgICAgIGlmICghU0VTU0lPTi5tZXRhLmlkX3NjaG9vbCkKICAgICAgICAgICAgU0VTU0lPTi5tZXRhLmlkX3NjaG9vbCA9ICh1aSAmJiB1aS5pZF9zY2hvb2wpIHx8IHdpbmRvdz8ucF9jb25maWc/LnNjaG9vbF9pZCB8fCBudWxsOwogICAgICAgIGlmICghU0VTU0lPTi5tZXRhLmNzcmZfdG9rZW4pIHsKICAgICAgICAgICAgY29uc3QgbSA9IGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoJ21ldGFbbmFtZT0iY3NyZi10b2tlbiJdJyk7CiAgICAgICAgICAgIFNFU1NJT04ubWV0YS5jc3JmX3Rva2VuID0gbSA/IG0uZ2V0QXR0cmlidXRlKCdjb250ZW50JykgOiAod2luZG93LmNzcmZfdG9rZW4gfHwgJycpOwogICAgICAgIH0KICAgIH0KCiAgICAvLyDilIDilIDilIAgTG9nIGJveCBoZWxwZXIg4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSACiAgICBmdW5jdGlvbiBhZGRMb2cobXNnLCB0eXBlID0gJycpIHsKICAgICAgICBjb25zdCBib3ggPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtbG9nYm94Jyk7CiAgICAgICAgaWYgKCFib3gpIHJldHVybjsKICAgICAgICBjb25zdCBkID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICAgICAgZC5jbGFzc05hbWUgPSAndGwtbG9nICcgKyB0eXBlOwogICAgICAgIGNvbnN0IHRpbWUgPSBuZXcgRGF0ZSgpLnRvTG9jYWxlVGltZVN0cmluZygndmktVk4nLCB7aG91cjonMi1kaWdpdCcsbWludXRlOicyLWRpZ2l0JyxzZWNvbmQ6JzItZGlnaXQnfSk7CiAgICAgICAgZC5pbm5lckhUTUwgPSBgWyR7dGltZX1dICR7bXNnfWA7CiAgICAgICAgYm94LmFwcGVuZENoaWxkKGQpOwogICAgICAgIGJveC5zY3JvbGxUb3AgPSBib3guc2Nyb2xsSGVpZ2h0OwogICAgfQogICAgd2luZG93LmFkZExvZyA9IGFkZExvZzsKCiAgICAvLyDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZAKICAgIC8vICBMT0NLIFNDUkVFTiDigJQgVUkgdjMuMiArIGxvZ2ljIGLhuqNvIG3huq10IHY0ICsgT0xNIGNoZWNrIHY0LjEKICAgIC8vIOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkAogICAgZnVuY3Rpb24gYnVpbGRMb2NrU2NyZWVuKHJlYXNvbikgewogICAgICAgIGlmIChkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtY29ubi1vdmVybGF5JykpIHJldHVybjsKCiAgICAgICAgbGV0IGxvY2tTdHlsZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1sb2NrLXN0eWxlJyk7CiAgICAgICAgaWYgKCFsb2NrU3R5bGUpIHsKICAgICAgICAgICAgbG9ja1N0eWxlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc3R5bGUnKTsKICAgICAgICAgICAgbG9ja1N0eWxlLmlkID0gJ3RsLWxvY2stc3R5bGUnOwogICAgICAgICAgICBkb2N1bWVudC5oZWFkLmFwcGVuZENoaWxkKGxvY2tTdHlsZSk7CiAgICAgICAgfQogICAgICAgIGxvY2tTdHlsZS50ZXh0Q29udGVudCA9IGdldExvY2tTY3JlZW5TdHlsZXMoKTsKCiAgICAgICAgY29uc3Qgb3ZlcmxheSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpOwogICAgICAgIG92ZXJsYXkuaWQgPSAndGwtY29ubi1vdmVybGF5JzsKICAgICAgICBjb25zdCB0bEZ4ID0gZ2V0VGhlbWVDb2xvcnMoQ1VSUkVOVF9USEVNRSkucGFuZWxFeHRyYSB8fCAnJzsKICAgICAgICBvdmVybGF5LmlubmVySFRNTCA9IGAKICAgICAgICAgICAgPGRpdiBpZD0idGwtY29ubi1wYW5lbCI+CiAgICAgICAgICAgICAgICAke3RsRnh9CiAgICAgICAgICAgICAgICA8ZGl2IGlkPSJ0bC1jb25uLWhlYWRlciI+CiAgICAgICAgICAgICAgICAgICAgPHNwYW4gY2xhc3M9InRsLWJyYW5kLW5hbWUiPvCfmoAgVEhJw4pOIFRBSSBUw5kgVOG7mEkgLy8gR09EIE1PREUgdjMuMjwvc3Bhbj4KICAgICAgICAgICAgICAgIDwvZGl2PgogICAgICAgICAgICAgICAgPGRpdiBpZD0idGwtY29ubi1ib2R5Ij4KICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC1zdWJ0aXRsZSI+8J+UkCBOSOG6rFAgTElDRU5TRSBLRVkgxJDhu4IgS8ONQ0ggSE/huqBUPC9kaXY+CiAgICAgICAgICAgICAgICAgICAgJHtyZWFzb24gPyBgPGRpdiBjbGFzcz0idGwtd2FybmluZyI+4pqg77iPICR7cmVhc29ufTwvZGl2PmAgOiAnJ30KICAgICAgICAgICAgICAgICAgICA8aW5wdXQgdHlwZT0idGV4dCIgY2xhc3M9InRsLWlucHV0IiBpZD0idGwta2V5LWlucHV0IgogICAgICAgICAgICAgICAgICAgICAgICAgICBwbGFjZWhvbGRlcj0iTmjhuq1wIGtleSBi4bqjbiBxdXnhu4FuLi4uIiBhdXRvY29tcGxldGU9Im9mZiI+CiAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0idGwtYnRuIHRsLWJ0bi11bmxvY2siIGlkPSJ0bC1idG4tdW5sb2NrIj7wn5STIEvDjUNIIEhP4bqgVDwvYnV0dG9uPgogICAgICAgICAgICAgICAgICAgIDxidXR0b24gY2xhc3M9InRsLWJ0biB0bC1idG4tdmlwIiAgIGlkPSJ0bC1idG4tYnV5Ij7wn5KOIE1VQSBLRVkgKExJw4pOIEjhu4YpPC9idXR0b24+CiAgICAgICAgICAgICAgICAgICAgPGRpdiBpZD0idGwtZXJyIj48L2Rpdj4KICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC1od2lkIiBpZD0idGwtaHdpZC1kaXNwbGF5Ij48L2Rpdj4KICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC1mb290Ij5Zw6p1IGPhuqd1OiBtw6F5IEFuZHJvaWQvaU9TIHRo4bqtdCDigKIgdHLDrG5oIGR1eeG7h3QgdGjhuq10IOKAoiBt4bqhbmcgdGjhuq10PC9kaXY+CiAgICAgICAgICAgICAgICA8L2Rpdj4KICAgICAgICAgICAgPC9kaXY+YDsKICAgICAgICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKG92ZXJsYXkpOwoKICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtaHdpZC1kaXNwbGF5JykudGV4dENvbnRlbnQgPSBg8J+UkSBIV0lEOiAke2dldEhXSUQoKX1gOwogICAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1idG4tYnV5Jykub25jbGljayA9ICgpID0+IHdpbmRvdy5vcGVuKCdodHRwczovL3QubWUvbHVvbmd0dXllbjIwJywgJ19ibGFuaycpOwoKICAgICAgICBjb25zdCBidG4gICAgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtYnRuLXVubG9jaycpOwogICAgICAgIGNvbnN0IGVyckJveCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1lcnInKTsKICAgICAgICBsZXQgdmVyaWZ5aW5nID0gZmFsc2U7CgogICAgICAgIGJ0bi5vbmNsaWNrID0gYXN5bmMgKCkgPT4gewogICAgICAgICAgICBpZiAodmVyaWZ5aW5nKSByZXR1cm47CiAgICAgICAgICAgIGNvbnN0IGtleSA9IChkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwta2V5LWlucHV0JykudmFsdWUgfHwgJycpLnRyaW0oKS50b1VwcGVyQ2FzZSgpOwogICAgICAgICAgICBpZiAoIWtleSkgeyBlcnJCb3gudGV4dENvbnRlbnQgPSAn4p2MIFZ1aSBsw7JuZyBuaOG6rXAga2V5ISc7IGVyckJveC5zdHlsZS5kaXNwbGF5ID0gJ2Jsb2NrJzsgcmV0dXJuOyB9CgogICAgICAgICAgICB2ZXJpZnlpbmcgPSB0cnVlOwogICAgICAgICAgICBidG4udGV4dENvbnRlbnQgPSAn4o+zIMSQQU5HIFjDgUMgVEjhu7BDLi4uJzsKICAgICAgICAgICAgYnRuLmRpc2FibGVkICAgID0gdHJ1ZTsKICAgICAgICAgICAgZXJyQm94LnN0eWxlLmRpc3BsYXkgPSAnbm9uZSc7CgogICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgLy8gW3Y0XSBQaW5nIHNlcnZlciBxdWEgQVBJIHByZWZpeCDhuqluIHRyxrDhu5tjIGtoaSB2ZXJpZnkKICAgICAgICAgICAgICAgIGNvbnN0IHByZWZpeCA9IGF3YWl0IF9hcGlQcmVmaXgoKTsKICAgICAgICAgICAgICAgIGNvbnN0IHBpbmdPayA9IGF3YWl0IG5ldyBQcm9taXNlKChyZXNvbHZlKSA9PiB7CiAgICAgICAgICAgICAgICAgICAgR01feG1saHR0cFJlcXVlc3QoewogICAgICAgICAgICAgICAgICAgICAgICBtZXRob2Q6ICdHRVQnLCB1cmw6IFNFUlZFUl9CQVNFICsgcHJlZml4ICsgJy9waW5nJywgdGltZW91dDogODAwMCwKICAgICAgICAgICAgICAgICAgICAgICAgb25sb2FkOiAocikgPT4gcmVzb2x2ZShyLnN0YXR1cyA9PT0gMjAwKSwKICAgICAgICAgICAgICAgICAgICAgICAgb25lcnJvcjogKCkgPT4gcmVzb2x2ZShmYWxzZSksIG9udGltZW91dDogKCkgPT4gcmVzb2x2ZShmYWxzZSkKICAgICAgICAgICAgICAgICAgICB9KTsKICAgICAgICAgICAgICAgIH0pOwogICAgICAgICAgICAgICAgaWYgKCFwaW5nT2spIHRocm93IG5ldyBFcnJvcignS0jDlE5HIEvhur5UIE7hu5BJIMSQxq/hu6JDIFNFUlZFUi4gS2nhu4NtIHRyYTogMSkgVVJMIFNFUlZFUl9CQVNFLCAyKSBBUElfU0VDUkVUIGto4bubcCBHT0RNT0RFX1NFQ1JFVCB0csOqbiBzZXJ2ZXIsIDMpIMSRw6MgZGVwbG95L3JlZGVwbG95LicpOwoKICAgICAgICAgICAgICAgIC8vIFt2NC4xXSBM4bqleSBPTE0gdXNlcm5hbWUgaGnhu4duIHThuqFpIMSR4buDIGfhu61pIGvDqG0KICAgICAgICAgICAgICAgIGNvbnN0IGN1cnJlbnRPbG0gPSBnZXRPbG1Vc2VybmFtZSgpOwogICAgICAgICAgICAgICAgY29uc3QgcmVzdWx0ID0gYXdhaXQgZ21Qb3N0KCcvdmVyaWZ5JywgeyBrZXksIGh3aWQ6IGdldEhXSUQoKSwgb2xtX3VzZXI6IGN1cnJlbnRPbG0gfSk7CgogICAgICAgICAgICAgICAgaWYgKHJlc3VsdC5zdWNjZXNzIHx8IHJlc3VsdC52YWxpZCkgewoKICAgICAgICAgICAgICAgICAgICAvLyDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZAKICAgICAgICAgICAgICAgICAgICAvLyBbdjQuMV0gS0nhu4JNIFRSQSBPTE0gQUNDT1VOVCBNSVNNQVRDSAogICAgICAgICAgICAgICAgICAgIC8vIFNlcnZlciB0cuG6oyB24buBIG9sbV91c2VyID0gdMOgaSBraG/huqNuIE9MTSDEkcaw4bujYyBnaGltIHbDoG8ga2V5CiAgICAgICAgICAgICAgICAgICAgLy8gU28gc8OhbmggduG7m2kgdMOgaSBraG/huqNuIE9MTSDEkWFuZyDEkcSDbmcgbmjhuq1wIHRyw6puIHRyw6xuaCBkdXnhu4d0CiAgICAgICAgICAgICAgICAgICAgLy8g4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQCiAgICAgICAgICAgICAgICAgICAgY29uc3Qgc2VydmVyT2xtID0gcmVzdWx0Lm9sbV91c2VyIHx8IHJlc3VsdC5vbG1fYWNjb3VudCB8fCAnJzsKICAgICAgICAgICAgICAgICAgICBpZiAoc2VydmVyT2xtICYmIGN1cnJlbnRPbG0gJiYgY3VycmVudE9sbSAhPT0gJ0tob25nWGFjRGluaCcpIHsKICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHNlcnZlck9sbS50b0xvd2VyQ2FzZSgpICE9PSBjdXJyZW50T2xtLnRvTG93ZXJDYXNlKCkpIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8vIE9MTSBhY2NvdW50IG1pc21hdGNoIOKAlCBoaeG7g24gdGjhu4sgbOG7l2ksIGtow7RuZyB0aeG6v3AgdOG7pWMKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVyckJveC5pbm5lckhUTUwgPSBg8J+aqyA8Yj5Uw6BpIGtob+G6o24gT0xNIGtow7RuZyBraOG7m3AhPC9iPjxicj4KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBLZXkgZMOgbmggY2hvOiA8Yj4ke3NlcnZlck9sbX08L2I+PGJyPgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEhp4buHbiB04bqhaTogPGI+JHtjdXJyZW50T2xtfTwvYj48YnI+CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgVnVpIGzDsm5nIMSRxINuZyBuaOG6rXAgxJHDum5nIHTDoGkga2hv4bqjbiBPTE0hYDsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVyckJveC5zdHlsZS5kaXNwbGF5ID0gJ2Jsb2NrJzsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJ0bi50ZXh0Q29udGVudCA9ICfwn5STIEvDjUNIIEhP4bqgVCc7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBidG4uZGlzYWJsZWQgICAgPSBmYWxzZTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZlcmlmeWluZyAgICAgICA9IGZhbHNlOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuOwogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIC8vIOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkAoKICAgICAgICAgICAgICAgICAgICBfc0xTLnNldChMU19LRVksICBrZXkpOyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAvLyBbdjVdIG9iZnVzY2F0ZWQgd3JpdGUKICAgICAgICAgICAgICAgICAgICBfc0xTLnNldChMU19UWVBFLCByZXN1bHQudHlwZSAgIHx8IHJlc3VsdC5wbGFuIHx8ICdUSFVPTkcnKTsgIC8vIFt2NV0KICAgICAgICAgICAgICAgICAgICBfc0xTLnNldChMU19FWFAsICByZXN1bHQuZXhwaXJlc19hdCB8fCAnJyk7ICAgICAgICAgICAgICAgICAgIC8vIFt2NV0KICAgICAgICAgICAgICAgICAgICBDVVJSRU5UX0tFWSA9IGtleTsKICAgICAgICAgICAgICAgICAgICBLRVlfU1RBVFVTICA9IHsgdmFsaWQ6IHRydWUsIHR5cGU6IHJlc3VsdC50eXBlIHx8IHJlc3VsdC5wbGFuLCBleHBpcmVzX2F0OiByZXN1bHQuZXhwaXJlc19hdCB8fCByZXN1bHQuZXhwIH07CgogICAgICAgICAgICAgICAgICAgIGNvbnN0IGtleVR5cGVMYWJlbCA9IChyZXN1bHQudHlwZSB8fCByZXN1bHQucGxhbiB8fCAnVEhVT05HJykudG9VcHBlckNhc2UoKTsKICAgICAgICAgICAgICAgICAgICBjb25zdCBpc1ByZW1pdW0gICAgPSBbJ1BSRU1JVU0nLCdWSVAnLCdVTkxJTUlURUQnXS5pbmNsdWRlcyhrZXlUeXBlTGFiZWwpOwoKICAgICAgICAgICAgICAgICAgICBsZXQgZXhwaXJ5TGluZSA9ICcnOwogICAgICAgICAgICAgICAgICAgIGNvbnN0IGV4UmF3ID0gcmVzdWx0LmV4cGlyZXNfYXQgfHwgcmVzdWx0LmV4cCB8fCAnJzsKICAgICAgICAgICAgICAgICAgICBpZiAoZXhSYXcpIHsKICAgICAgICAgICAgICAgICAgICAgICAgY29uc3QgZXhwRGF0ZSAgPSBuZXcgRGF0ZShleFJhdyk7CiAgICAgICAgICAgICAgICAgICAgICAgIGNvbnN0IGRheXNMZWZ0ID0gTWF0aC5jZWlsKChleHBEYXRlIC0gbmV3IERhdGUoKSkgLyAoMTAwMCAqIDYwICogNjAgKiAyNCkpOwogICAgICAgICAgICAgICAgICAgICAgICBjb25zdCBleHBTdHIgICA9IGV4cERhdGUudG9Mb2NhbGVEYXRlU3RyaW5nKCd2aS1WTicpOwogICAgICAgICAgICAgICAgICAgICAgICBpZiAoZGF5c0xlZnQgPiAwKSAgICAgICBleHBpcnlMaW5lID0gYPCfk4UgSOG6v3QgaOG6oW46IDxiPiR7ZXhwU3RyfTwvYj4gKGPDsm4gPGI+JHtkYXlzTGVmdH08L2I+IG5nw6B5KWA7CiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UgaWYgKGRheXNMZWZ0ID09PSAwKSBleHBpcnlMaW5lID0gYPCfk4UgSOG6v3QgaOG6oW46IDxiPkjDtG0gbmF5PC9iPiAoJHtleHBTdHJ9KWA7CiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UgICAgICAgICAgICAgICAgICAgIGV4cGlyeUxpbmUgPSBg8J+ThSBI4bq/dCBo4bqhbjogPGI+JHtleHBTdHJ9PC9iPiA8c3BhbiBzdHlsZT0iY29sb3I6I2ZmNDQ0NDsiPijEkcOjIGjhur90IGjhuqFuKTwvc3Bhbj5gOwogICAgICAgICAgICAgICAgICAgIH0KCiAgICAgICAgICAgICAgICAgICAgb3ZlcmxheS5yZW1vdmUoKTsKCiAgICAgICAgICAgICAgICAgICAgaWYgKCFpc1ByZW1pdW0pIHsKICAgICAgICAgICAgICAgICAgICAgICAgc2hvd0N1c3RvbU1vZGFsKHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGljb246ICAn4pyFJywKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRpdGxlOiAnS8ONQ0ggSE/huqBUIFRIw4BOSCBDw5RORyEnLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgbGluZXM6IFsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBgTG/huqFpIGtleTogPGI+JHtrZXlUeXBlTGFiZWx9PC9iPmAsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLi4uKGV4cGlyeUxpbmUgPyBbZXhwaXJ5TGluZV0gOiBbXSksCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYDxzcGFuIHN0eWxlPSJjb2xvcjojZmZjMTA3OyI+4pqg77iPIEtleSB0aMaw4budbmc6IENo4bupYyBuxINuZyAiQ0hV4bqoTiBC4buKIDEwIMSQSeG7gk0iIGLhu4sgdsO0IGhp4buHdSBob8OhLjwvc3Bhbj5gLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGDwn5KOIE7Dom5nIGPhuqVwIGzDqm4gUFJFTUlVTSDEkeG7gyBkw7luZyDEkeG6p3kgxJHhu6cgdMOtbmggbsSDbmchYAogICAgICAgICAgICAgICAgICAgICAgICAgICAgXSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9uT2s6ICgpID0+IGNyZWF0ZVVJKCkKICAgICAgICAgICAgICAgICAgICAgICAgfSk7CiAgICAgICAgICAgICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgICAgICAgICAgICAgc2hvd0N1c3RvbU1vZGFsKHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGljb246ICAn8J+SjicsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aXRsZTogJ0vDjUNIIEhP4bqgVCBUSMOATkggQ8OUTkchJywKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGxpbmVzOiBbCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYExv4bqhaSBrZXk6IDxiPiR7a2V5VHlwZUxhYmVsfTwvYj4g8J+SjmAsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLi4uKGV4cGlyeUxpbmUgPyBbZXhwaXJ5TGluZV0gOiBbXSksCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYPCflJMgVOG6pXQgY+G6oyB0w61uaCBuxINuZyDEkcOjIMSRxrDhu6NjIG3hu58ga2hvw6EhYAogICAgICAgICAgICAgICAgICAgICAgICAgICAgXSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9uT2s6ICgpID0+IGNyZWF0ZVVJKCkKICAgICAgICAgICAgICAgICAgICAgICAgfSk7CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgICAgICAgICAvLyBbdjRdIFRow7RuZyBiw6FvIGzhu5dpIGNoaSB0aeG6v3QgdGhlbyBIVFRQIHN0YXR1cwogICAgICAgICAgICAgICAgICAgIGNvbnN0IHN0YXR1cyA9IHJlc3VsdC5faHR0cFN0YXR1czsKICAgICAgICAgICAgICAgICAgICBsZXQgbXNnID0gcmVzdWx0Lm1lc3NhZ2UgfHwgcmVzdWx0LnJlYXNvbiB8fCByZXN1bHQuZXJyb3IgfHwgJyc7CiAgICAgICAgICAgICAgICAgICAgaWYgKHN0YXR1cyA9PT0gNDA0IHx8IHJlc3VsdC5lcnJvciA9PT0gJ05vdCBmb3VuZCcpIHsKICAgICAgICAgICAgICAgICAgICAgICAgbXNnID0gJ+KdjCBUaGnhur90IGLhu4svSVAgY8OzIHRo4buDIMSRw6MgYuG7iyBraG/DoSBob+G6t2Mgc2FpIMSRxrDhu51uZyBk4bqrbiBBUEkuIEtp4buDbSB0cmEgQVBJX1NFQ1JFVCBraOG7m3Agc2VydmVyLic7CiAgICAgICAgICAgICAgICAgICAgfSBlbHNlIGlmIChzdGF0dXMgPT09IDQwMykgewogICAgICAgICAgICAgICAgICAgICAgICBtc2cgPSAn4p2MICcgKyAobXNnIHx8ICdUaGnhur90IGLhu4svbeG6oW5nIGtow7RuZyBo4bujcCBs4buHIChtw6F5IOG6o28vcHJveHkvVlBOL3Ryw6xuaCBkdXnhu4d0IGdp4bqjKSDigJQgY8OzIHRo4buDIMSRw6MgYuG7iyBraG/DoSB2xKluaCB2aeG7hW4sIGxpw6puIGjhu4cgYWRtaW4uJyk7CiAgICAgICAgICAgICAgICAgICAgfSBlbHNlIGlmICghbXNnKSB7CiAgICAgICAgICAgICAgICAgICAgICAgIG1zZyA9ICfinYwgS2V5IGtow7RuZyBo4bujcCBs4buHISAoS2V5VmF1bHQgdOG7qyBjaOG7kWkpJzsKICAgICAgICAgICAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICAgICAgICAgICAgICBtc2cgPSAn4p2MICcgKyBtc2c7CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIGVyckJveC50ZXh0Q29udGVudCAgID0gbXNnICsgKHN0YXR1cyA/IGAgW0hUVFAgJHtzdGF0dXN9XWAgOiAnJyk7CiAgICAgICAgICAgICAgICAgICAgZXJyQm94LnN0eWxlLmRpc3BsYXkgPSAnYmxvY2snOwogICAgICAgICAgICAgICAgICAgIGJ0bi50ZXh0Q29udGVudCA9ICfwn5STIEvDjUNIIEhP4bqgVCc7CiAgICAgICAgICAgICAgICAgICAgYnRuLmRpc2FibGVkICAgID0gZmFsc2U7CiAgICAgICAgICAgICAgICAgICAgdmVyaWZ5aW5nICAgICAgID0gZmFsc2U7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0gY2F0Y2ggKGUpIHsKICAgICAgICAgICAgICAgIGVyckJveC50ZXh0Q29udGVudCAgID0gJ+KdjCBLaMO0bmcgdGjhu4Mga+G6v3QgbuG7kWkgc2VydmVyOiAnICsgZS5tZXNzYWdlOwogICAgICAgICAgICAgICAgZXJyQm94LnN0eWxlLmRpc3BsYXkgPSAnYmxvY2snOwogICAgICAgICAgICAgICAgYnRuLnRleHRDb250ZW50ID0gJ/CflJMgS8ONQ0ggSE/huqBUJzsKICAgICAgICAgICAgICAgIGJ0bi5kaXNhYmxlZCAgICA9IGZhbHNlOwogICAgICAgICAgICAgICAgdmVyaWZ5aW5nICAgICAgID0gZmFsc2U7CiAgICAgICAgICAgIH0KICAgICAgICB9OwoKICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwta2V5LWlucHV0JykuYWRkRXZlbnRMaXN0ZW5lcigna2V5ZG93bicsIChlKSA9PiB7CiAgICAgICAgICAgIGlmIChlLmtleSA9PT0gJ0VudGVyJykgYnRuLmNsaWNrKCk7CiAgICAgICAgfSk7CiAgICB9CgogICAgLy8g4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQCiAgICAvLyAgTUFJTiBQQU5FTCDigJQgVUkgdjMuMiArIHTDrW5oIG7Eg25nIHY0ICsga2hvw6Ega2V5IHRoxrDhu51uZyB2NC4xCiAgICAvLyDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZAKICAgIGZ1bmN0aW9uIGNyZWF0ZVVJKCkgewogICAgICAgIGlmIChkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtcGFuZWwnKSkgcmV0dXJuOwoKICAgICAgICBsZXQgdWlTdHlsZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC11aS1zdHlsZScpOwogICAgICAgIGlmICghdWlTdHlsZSkgewogICAgICAgICAgICB1aVN0eWxlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc3R5bGUnKTsKICAgICAgICAgICAgdWlTdHlsZS5pZCA9ICd0bC11aS1zdHlsZSc7CiAgICAgICAgICAgIGRvY3VtZW50LmhlYWQuYXBwZW5kQ2hpbGQodWlTdHlsZSk7CiAgICAgICAgfQogICAgICAgIHVpU3R5bGUudGV4dENvbnRlbnQgPSBnZXRNYWluVUlTdHlsZXMoKTsKCiAgICAgICAgY29uc3Qga2V5VHlwZSAgICA9IEtFWV9TVEFUVVMudHlwZSB8fCBfc0xTLmdldChMU19UWVBFKSB8fCAnVEhVT05HJzsgLy8gW3Y1XQogICAgICAgIGNvbnN0IGtleVR5cGVVcCAgPSBrZXlUeXBlLnRvVXBwZXJDYXNlKCk7CiAgICAgICAgY29uc3QgYmFkZ2VDbGFzcyA9IGtleVR5cGVVcCA9PT0gJ1VOTElNSVRFRCcgPyAndGwtYmFkZ2UgdW5saW1pdGVkJwogICAgICAgICAgICAgICAgICAgICAgICAgOiAoa2V5VHlwZVVwID09PSAnUFJFTUlVTScgfHwga2V5VHlwZVVwID09PSAnVklQJykgPyAndGwtYmFkZ2UgdmlwJwogICAgICAgICAgICAgICAgICAgICAgICAgOiAndGwtYmFkZ2UnOwogICAgICAgIGNvbnN0IGJhZGdlSWNvbiAgPSBrZXlUeXBlVXAgPT09ICdVTkxJTUlURUQnID8gJ/CflKUgVU5MSU1JVEVEJwogICAgICAgICAgICAgICAgICAgICAgICAgOiAoa2V5VHlwZVVwID09PSAnUFJFTUlVTScgfHwga2V5VHlwZVVwID09PSAnVklQJykgPyAn8J+SjiBQUkVNSVVNJwogICAgICAgICAgICAgICAgICAgICAgICAgOiAn8J+UkSBUSMav4bucTkcnOwoKICAgICAgICBjb25zdCBleHBTdHIgPSAoKCkgPT4gewogICAgICAgICAgICBjb25zdCBlID0gX3NMUy5nZXQoTFNfRVhQKTsgLy8gW3Y1XQogICAgICAgICAgICBpZiAoIWUpIHJldHVybiAnJzsKICAgICAgICAgICAgY29uc3QgZCA9IG5ldyBEYXRlKGUpOwogICAgICAgICAgICByZXR1cm4gaXNOYU4oZCkgPyAnJyA6IGAgKGV4cDogJHtkLnRvTG9jYWxlRGF0ZVN0cmluZygndmktVk4nKX0pYDsKICAgICAgICB9KSgpOwoKICAgICAgICBjb25zdCB0aGVtZUNhcmRzSFRNTCA9IFsnZGVmYXVsdCcsJ2dyYXknLCdwaW5rJ10ubWFwKHQgPT4gewogICAgICAgICAgICBjb25zdCB0SW5mbyAgICA9IGdldFRoZW1lQ29sb3JzKHQpOwogICAgICAgICAgICBjb25zdCBpc0FjdGl2ZSA9ICh0ID09PSBDVVJSRU5UX1RIRU1FKTsKICAgICAgICAgICAgcmV0dXJuIGA8ZGl2IGNsYXNzPSJ0bC10YyAke2lzQWN0aXZlID8gJ2FjdGl2ZScgOiAnJ30iIGRhdGEtdD0iJHt0fSI+CiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC10Yy1wcmV2IiBzdHlsZT0iYmFja2dyb3VuZDoke3RJbmZvLnByZXZpZXdCZ307Ym9yZGVyOjFweCBzb2xpZCAke3RJbmZvLnByZXZpZXdCb3JkZXJ9OyI+CiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtdGMtcHJldi1pbm5lciI+CiAgICAgICAgICAgICAgICAgICAgICAgIDxzcGFuIGNsYXNzPSJ0bC10Yy1wcmV2LXRleHQiIHN0eWxlPSJjb2xvcjoke3RJbmZvLnByZXZpZXdUZXh0fTsiPiR7dEluZm8udGhlbWVMYWJlbC5yZXBsYWNlKC9eW15cc10rXHMvLCcnKS50b1VwcGVyQ2FzZSgpfTwvc3Bhbj4KICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KICAgICAgICAgICAgICAgIDwvZGl2PgogICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtdGMtbGJsIj4ke3RJbmZvLnRoZW1lTGFiZWx9PC9kaXY+CiAgICAgICAgICAgIDwvZGl2PmA7CiAgICAgICAgfSkuam9pbignJyk7CgogICAgICAgIGNvbnN0IHRjICAgPSBnZXRUaGVtZUNvbG9ycyhDVVJSRU5UX1RIRU1FKTsKICAgICAgICBjb25zdCB3cmFwID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICAgICAgd3JhcC5pbm5lckhUTUwgPSBgCiAgICAgICAgICAgIDxidXR0b24gaWQ9InRsLWZsb2F0QnRuIj7imqE8L2J1dHRvbj4KICAgICAgICAgICAgPGRpdiBpZD0idGwtcGFuZWwiIGNsYXNzPSJoaWRkZW4iPgogICAgICAgICAgICAgICAgJHt0Yy5wYW5lbEV4dHJhIHx8ICcnfQogICAgICAgICAgICAgICAgPGRpdiBpZD0idGwtcC1oZWFkZXIiPgogICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLXAtYnJhbmQiPgogICAgICAgICAgICAgICAgICAgICAgICA8c3Bhbj7wn5qAPC9zcGFuPgogICAgICAgICAgICAgICAgICAgICAgICA8c3BhbiBjbGFzcz0idGwtcC1uYW1lIj5USEnDik4gVEFJIFTDmSBU4buYSSAvLyBHT0QgTU9ERTwvc3Bhbj4KICAgICAgICAgICAgICAgICAgICAgICAgPHNwYW4gY2xhc3M9IiR7YmFkZ2VDbGFzc30iPiR7YmFkZ2VJY29ufTwvc3Bhbj4KICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KICAgICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDo2cHg7Ij4KICAgICAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBpZD0idGwtc2V0dGluZ3NCdG4iIHRpdGxlPSJDw6BpIMSR4bq3dCBnaWFvIGRp4buHbiI+4pqZPC9idXR0b24+CiAgICAgICAgICAgICAgICAgICAgICAgIDxidXR0b24gaWQ9InRsLWNsb3NlQnRuIj7inJU8L2J1dHRvbj4KICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KICAgICAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgICAgICAgIDwhLS0gU2V0dGluZ3Mgb3ZlcmxheSAtLT4KICAgICAgICAgICAgICAgIDxkaXYgaWQ9InRsLXNvIiBjbGFzcz0iaGlkZGVuIj4KICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC1zby1oZHIiPgogICAgICAgICAgICAgICAgICAgICAgICA8c3BhbiBjbGFzcz0idGwtc28tdGl0bGUiPuKamSBDw4BJIMSQ4bq2VCBHSUFPIERJ4buGTjwvc3Bhbj4KICAgICAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBpZD0idGwtc29DbG9zZSI+4pyVPC9idXR0b24+CiAgICAgICAgICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtc28tYm9keSI+CiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLXNvLWxibCI+8J+OqCBDaOG7jW4gbcOgdSBz4bqvYyBnaWFvIGRp4buHbjwvZGl2PgogICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC10aGVtZS1jYXJkcyI+JHt0aGVtZUNhcmRzSFRNTH08L2Rpdj4KICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtc28tZGl2aWRlciI+PC9kaXY+CiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLWhpbnQiPsOBcCBk4bulbmcgbmdheSBs4bqtcCB04bupYyBjaG8gdG/DoG4gYuG7mSBnaWFvIGRp4buHbjxicj5r4buDIGPhuqMgbcOgbiBow6xuaCDEkcSDbmcgbmjhuq1wIHbDoCB0aMO0bmcgYsOhbyBrZXk8L2Rpdj4KICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtc28tZGl2aWRlciI+PC9kaXY+CiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLXNvLWxibCI+8J+UkSBRdeG6o24gbMO9IGtleTwvZGl2PgogICAgICAgICAgICAgICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJ0bC1jaGFuZ2Uta2V5IiBpZD0idGwtY2hhbmdlS2V5Ij7wn5SEIMSQ4buUSSBLRVk8L2J1dHRvbj4KICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtaGludCIgc3R5bGU9Im1hcmdpbi10b3A6NHB4OyI+WG/DoSBrZXkgaGnhu4duIHThuqFpIHbDoCBxdWF5IHbhu4EgbcOgbiBow6xuaCDEkcSDbmcgbmjhuq1wPC9kaXY+CiAgICAgICAgICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgICAgICA8ZGl2IGlkPSJ0bC1wLWJvZHkiPgogICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLXN0YXRib3giPgogICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJjb2xvcjpyZ2JhKDI1NSwyNTUsMjU1LDAuNCk7Zm9udC1zaXplOjEwcHg7dGV4dC10cmFuc2Zvcm06dXBwZXJjYXNlO2ZvbnQtd2VpZ2h0OjYwMDsiPi8vIFRy4bqhbmcgdGjDoWkgaOG7hyB0aOG7kW5nPC9kaXY+CiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLXN0YXRyb3ciPuKchSBO4bqhcCBk4buvIGxp4buHdTogPHNwYW4gaWQ9InRsLXFjb3VudCIgc3R5bGU9ImNvbG9yOiMwMGU2NzY7Zm9udC13ZWlnaHQ6Ym9sZDttYXJnaW4tbGVmdDo1cHgiPjA8L3NwYW4+IGPDonU8L2Rpdj4KICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtc3RhdHJvdyI+8J+UjSBDaOG6vyDEkeG7mTogPHNwYW4gaWQ9InRsLW1vZGUtZGV0ZWN0ZWQiIHN0eWxlPSJjb2xvcjojNGZhY2ZlO2ZvbnQtd2VpZ2h0OmJvbGQ7bWFyZ2luLWxlZnQ6NXB4Ij5QUkFDVElDRTwvc3Bhbj48L2Rpdj4KICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtc3RhdHJvdyI+8J+UkCBLZXk6IDxzcGFuIHN0eWxlPSJjb2xvcjojZmZjMTA3OyI+JHtrZXlUeXBlfTwvc3Bhbj4ke2V4cFN0cn08L2Rpdj4KICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KICAgICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJoZWlnaHQ6MXB4O2JhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDkwZGVnLHRyYW5zcGFyZW50LCR7dGMuYm9yZGVyfSx0cmFuc3BhcmVudCk7Ij48L2Rpdj4KICAgICAgICAgICAgICAgICAgICA8ZGl2PgogICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJmb250LXNpemU6OS41cHg7Zm9udC13ZWlnaHQ6NzAwO2NvbG9yOiR7dGMuZ2xvd0NvbG9yfTtmb250LWZhbWlseTonT3JiaXRyb24nOyI+4pqZIENI4bq+IMSQ4buYIFbGr+G7olQgUsOATzwvZGl2PgogICAgICAgICAgICAgICAgICAgICAgICA8c2VsZWN0IGlkPSJ0bC1tb2RlU2VsZWN0Ij4KICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxvcHRpb24gdmFsdWU9InByYWN0aWNlIj7imqEgTHV54buHbiBU4bqtcDwvb3B0aW9uPgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0iZXhhbSIgc2VsZWN0ZWQ+8J+UpSBLaeG7g20gVHJhPC9vcHRpb24+CiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSJ2aWRlbyI+8J+OpSBWaWRlbyBRdWl6PC9vcHRpb24+CiAgICAgICAgICAgICAgICAgICAgICAgIDwvc2VsZWN0PgogICAgICAgICAgICAgICAgICAgICAgICA8aW5wdXQgdHlwZT0ibnVtYmVyIiBzdGVwPSIwLjAxIiBjbGFzcz0idGwtZ29kLWlucHV0IiBpZD0idGwtZ29kLXRpbWUiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YWx1ZT0iMjUuMDAiIHBsYWNlaG9sZGVyPSJQaMO6dC5HacOieSAodmQ6IDI1LjMwKSI+CiAgICAgICAgICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBpZD0idGwtZmlyZUJ0biI+8J+SpSBDSFXhuqhOIELhu4ogMTAgxJBJ4buCTTwvYnV0dG9uPgogICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLWNvbnNvbGUiIGlkPSJ0bC1sb2dib3giPjwvZGl2PgogICAgICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICAgICAgICA8ZGl2IGlkPSJ0bC1wLWZvb3RlciI+CiAgICAgICAgICAgICAgICAgICAgPHNwYW4+R09EIE1PREUgdjMuMiDigJQgU0VDVVJFIHY1LjEgKHYxNyBhbnRpLWJhbik8L3NwYW4+CiAgICAgICAgICAgICAgICAgICAgPGRpdiBzdHlsZT0iZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6NXB4OyI+CiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgc3R5bGU9IndpZHRoOjZweDtoZWlnaHQ6NnB4O2JvcmRlci1yYWRpdXM6NTAlO2JhY2tncm91bmQ6IzAwZTY3Njtib3gtc2hhZG93OjAgMCA2cHggIzAwZTY3NjthbmltYXRpb246Y29ubkJsaW5rIDEuOHMgaW5maW5pdGU7Ij48L2Rpdj4KICAgICAgICAgICAgICAgICAgICAgICAgPHNwYW4gaWQ9InRsLXN2clN0YXR1cyI+8J+UtSBTZXJ2ZXI6IE9LPC9zcGFuPgogICAgICAgICAgICAgICAgICAgIDwvZGl2PgogICAgICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICAgIDwvZGl2PmA7CiAgICAgICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZCh3cmFwKTsKCiAgICAgICAgY29uc3QgZmxvYXRCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtZmxvYXRCdG4nKTsKICAgICAgICBjb25zdCBwYW5lbCAgICA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1wYW5lbCcpOwogICAgICAgIGZsb2F0QnRuLm9uY2xpY2sgPSAoKSA9PiBwYW5lbC5jbGFzc0xpc3QudG9nZ2xlKCdoaWRkZW4nKTsKICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtY2xvc2VCdG4nKS5vbmNsaWNrID0gKCkgPT4gewogICAgICAgICAgICBwYW5lbC5jbGFzc0xpc3QuYWRkKCdoaWRkZW4nKTsKICAgICAgICAgICAgY29uc3Qgc28gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtc28nKTsKICAgICAgICAgICAgaWYgKHNvKSBzby5jbGFzc0xpc3QuYWRkKCdoaWRkZW4nKTsKICAgICAgICB9OwoKICAgICAgICAvLyBEcmFnCiAgICAgICAgY29uc3QgaGRyID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLXAtaGVhZGVyJyk7CiAgICAgICAgbGV0IGlzRHJhZ2dpbmcgPSBmYWxzZSwgc3RhcnRYID0gMCwgc3RhcnRZID0gMCwgaW5pdExlZnQgPSAwLCBpbml0VG9wID0gMDsKICAgICAgICBpZiAoaGRyKSB7CiAgICAgICAgICAgIGhkci5hZGRFdmVudExpc3RlbmVyKCdtb3VzZWRvd24nLCAoZSkgPT4gewogICAgICAgICAgICAgICAgaWYgKGUudGFyZ2V0LmlkID09PSAndGwtY2xvc2VCdG4nIHx8IGUudGFyZ2V0LmlkID09PSAndGwtc2V0dGluZ3NCdG4nKSByZXR1cm47CiAgICAgICAgICAgICAgICBpc0RyYWdnaW5nID0gdHJ1ZTsKICAgICAgICAgICAgICAgIHN0YXJ0WCA9IGUuY2xpZW50WDsgc3RhcnRZID0gZS5jbGllbnRZOwogICAgICAgICAgICAgICAgY29uc3QgciA9IHBhbmVsLmdldEJvdW5kaW5nQ2xpZW50UmVjdCgpOwogICAgICAgICAgICAgICAgaW5pdExlZnQgPSByLmxlZnQ7IGluaXRUb3AgPSByLnRvcDsKICAgICAgICAgICAgfSk7CiAgICAgICAgfQogICAgICAgIGRvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXIoJ21vdXNlbW92ZScsIChlKSA9PiB7CiAgICAgICAgICAgIGlmICghaXNEcmFnZ2luZykgcmV0dXJuOwogICAgICAgICAgICBwYW5lbC5zdHlsZS5sZWZ0ICAgICAgPSAoaW5pdExlZnQgKyBlLmNsaWVudFggLSBzdGFydFgpICsgJ3B4JzsKICAgICAgICAgICAgcGFuZWwuc3R5bGUudG9wICAgICAgID0gKGluaXRUb3AgICsgZS5jbGllbnRZIC0gc3RhcnRZKSArICdweCc7CiAgICAgICAgICAgIHBhbmVsLnN0eWxlLnRyYW5zZm9ybSA9ICdub25lJzsKICAgICAgICB9KTsKICAgICAgICBkb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCdtb3VzZXVwJywgKCkgPT4geyBpc0RyYWdnaW5nID0gZmFsc2U7IH0pOwoKICAgICAgICAvLyA9PT09PT0gU0VUVElOR1MgUEFORUwgTE9HSUMgPT09PT09CiAgICAgICAgY29uc3Qgc28gICAgICAgICAgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtc28nKTsKICAgICAgICBjb25zdCBzZXR0aW5nc0J0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1zZXR0aW5nc0J0bicpOwogICAgICAgIGNvbnN0IHNvQ2xvc2UgICAgID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLXNvQ2xvc2UnKTsKCiAgICAgICAgaWYgKHNldHRpbmdzQnRuICYmIHNvKSB7CiAgICAgICAgICAgIHNldHRpbmdzQnRuLm9uY2xpY2sgPSAoKSA9PiB7CiAgICAgICAgICAgICAgICBjb25zdCBpc09wZW4gPSAhc28uY2xhc3NMaXN0LmNvbnRhaW5zKCdoaWRkZW4nKTsKICAgICAgICAgICAgICAgIHNvLmNsYXNzTGlzdC50b2dnbGUoJ2hpZGRlbicpOwogICAgICAgICAgICAgICAgc2V0dGluZ3NCdG4uY2xhc3NMaXN0LnRvZ2dsZSgnYWN0aXZlJywgIWlzT3Blbik7CiAgICAgICAgICAgIH07CiAgICAgICAgfQogICAgICAgIGlmIChzb0Nsb3NlKSB7CiAgICAgICAgICAgIHNvQ2xvc2Uub25jbGljayA9ICgpID0+IHsKICAgICAgICAgICAgICAgIHNvLmNsYXNzTGlzdC5hZGQoJ2hpZGRlbicpOwogICAgICAgICAgICAgICAgaWYgKHNldHRpbmdzQnRuKSBzZXR0aW5nc0J0bi5jbGFzc0xpc3QucmVtb3ZlKCdhY3RpdmUnKTsKICAgICAgICAgICAgfTsKICAgICAgICB9CgogICAgICAgIGlmIChzbykgewogICAgICAgICAgICBzby5xdWVyeVNlbGVjdG9yQWxsKCcudGwtdGMnKS5mb3JFYWNoKGNhcmQgPT4gewogICAgICAgICAgICAgICAgY2FyZC5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHsKICAgICAgICAgICAgICAgICAgICBjb25zdCBuZXdUaGVtZSA9IGNhcmQuZGF0YXNldC50OwogICAgICAgICAgICAgICAgICAgIGlmIChuZXdUaGVtZSA9PT0gQ1VSUkVOVF9USEVNRSkgewogICAgICAgICAgICAgICAgICAgICAgICBzby5jbGFzc0xpc3QuYWRkKCdoaWRkZW4nKTsKICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHNldHRpbmdzQnRuKSBzZXR0aW5nc0J0bi5jbGFzc0xpc3QucmVtb3ZlKCdhY3RpdmUnKTsKICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICBzby5xdWVyeVNlbGVjdG9yQWxsKCcudGwtdGMnKS5mb3JFYWNoKGMgPT4gewogICAgICAgICAgICAgICAgICAgICAgICBjLmNsYXNzTGlzdC50b2dnbGUoJ2FjdGl2ZScsIGMuZGF0YXNldC50ID09PSBuZXdUaGVtZSk7CiAgICAgICAgICAgICAgICAgICAgfSk7CiAgICAgICAgICAgICAgICAgICAgYXBwbHlUaGVtZUxpdmUobmV3VGhlbWUpOwogICAgICAgICAgICAgICAgICAgIGNvbnN0IGV4aXN0RnggPSBwYW5lbC5xdWVyeVNlbGVjdG9yKCcjdGwtY29ubi1meC1iYXIsI3RsLWNvbm4tZngtcGV0YWxzJyk7CiAgICAgICAgICAgICAgICAgICAgaWYgKGV4aXN0RngpIGV4aXN0RngucmVtb3ZlKCk7CiAgICAgICAgICAgICAgICAgICAgY29uc3QgbmV3VGMgPSBnZXRUaGVtZUNvbG9ycyhuZXdUaGVtZSk7CiAgICAgICAgICAgICAgICAgICAgaWYgKG5ld1RjLnBhbmVsRXh0cmEpIHsKICAgICAgICAgICAgICAgICAgICAgICAgY29uc3QgdG1wID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICAgICAgICAgICAgICAgICAgICAgIHRtcC5pbm5lckhUTUwgPSBuZXdUYy5wYW5lbEV4dHJhOwogICAgICAgICAgICAgICAgICAgICAgICBjb25zdCBmeEVsID0gdG1wLmZpcnN0RWxlbWVudENoaWxkOwogICAgICAgICAgICAgICAgICAgICAgICBpZiAoZnhFbCkgcGFuZWwuaW5zZXJ0QmVmb3JlKGZ4RWwsIHBhbmVsLmZpcnN0Q2hpbGQpOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHsKICAgICAgICAgICAgICAgICAgICAgICAgc28uY2xhc3NMaXN0LmFkZCgnaGlkZGVuJyk7CiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChzZXR0aW5nc0J0bikgc2V0dGluZ3NCdG4uY2xhc3NMaXN0LnJlbW92ZSgnYWN0aXZlJyk7CiAgICAgICAgICAgICAgICAgICAgfSwgMzIwKTsKICAgICAgICAgICAgICAgIH0pOwogICAgICAgICAgICB9KTsKICAgICAgICB9CgogICAgICAgIC8vIE1vZGUgc2VsZWN0CiAgICAgICAgY29uc3QgbW9kZVNlbGVjdCAgID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLW1vZGVTZWxlY3QnKTsKICAgICAgICBjb25zdCBkZXRlY3RlZE1vZGUgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtbW9kZS1kZXRlY3RlZCcpOwogICAgICAgIGlmIChtb2RlU2VsZWN0KSB7CiAgICAgICAgICAgIG1vZGVTZWxlY3QuYWRkRXZlbnRMaXN0ZW5lcignY2hhbmdlJywgZnVuY3Rpb24oKSB7CiAgICAgICAgICAgICAgICBpZiAoZGV0ZWN0ZWRNb2RlKSBkZXRlY3RlZE1vZGUudGV4dENvbnRlbnQgPSB0aGlzLnZhbHVlLnRvVXBwZXJDYXNlKCk7CiAgICAgICAgICAgIH0pOwogICAgICAgIH0KCiAgICAgICAgLy8gW3Y2XSBDb2RlICJDSFXhuqhOIELhu4ogMTAgxJBJ4buCTSIgxJHDoyBjaHV54buDbiBIT8OATiBUT8OATiBzYW5nIHNlcnZlciDigJQgdOG6o2kgxJHhu5luZyBxdWEgL21vZHVsZSAobcOjIGhvw6EgQUVTLUdDTSksIEtIw5RORyBjw7JuIG7hurFtIHRyb25nIHNjcmlwdCBuw6B5LgogICAgICAgIGFzeW5jIGZ1bmN0aW9uIGZvcmNlRmV0Y2hRdWVzdGlvbnMoKSB7CiAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgICBmb3JjZUdldE1ldGEoKTsKICAgICAgICAgICAgICAgIGNvbnN0IFVXID0gKHR5cGVvZiB1bnNhZmVXaW5kb3cgIT09ICd1bmRlZmluZWQnKSA/IHVuc2FmZVdpbmRvdyA6IHdpbmRvdzsKICAgICAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgICAgICAgY29uc3QgYnVmID0gVVcuX19rdl9xX2J1ZjsKICAgICAgICAgICAgICAgICAgICBpZiAoQXJyYXkuaXNBcnJheShidWYpKSB7CiAgICAgICAgICAgICAgICAgICAgICAgIGZvciAobGV0IGkgPSAwOyBpIDwgYnVmLmxlbmd0aDsgaSsrKSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zdCBpdCA9IGJ1ZltpXTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChpdCAmJiBpdC51cmwgJiYgaXQudGV4dCkgeyB0cnkgeyBoYW5kbGVSYXdSZXNwb25zZShpdC51cmwsIGl0LnRleHQpOyB9IGNhdGNoIChfKSB7fSB9CiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICB9IGNhdGNoIChfKSB7fQogICAgICAgICAgICAgICAgaWYgKFNFU1NJT04ucmF3X3F1ZXN0aW9ucy5sZW5ndGggPiAwKSByZXR1cm4gdHJ1ZTsKICAgICAgICAgICAgICAgIGNvbnN0IGxhc3QgPSBVVy5fX3RsX2xhc3RfcXJlcTsKICAgICAgICAgICAgICAgIGlmIChsYXN0ICYmIGxhc3QudXJsKSB7CiAgICAgICAgICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgICAgICAgICAgY29uc3QgZm9wdHMgPSB7IG1ldGhvZDogbGFzdC5tZXRob2QgfHwgJ0dFVCcsIGNyZWRlbnRpYWxzOiAnaW5jbHVkZScsIGNhY2hlOiAnbm8tY2FjaGUnIH07CiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChsYXN0LmJvZHkgJiYgKGxhc3QubWV0aG9kIHx8ICdHRVQnKS50b1VwcGVyQ2FzZSgpICE9PSAnR0VUJykgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9wdHMuaGVhZGVycyA9IHsgJ0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQ7IGNoYXJzZXQ9VVRGLTgnLCAnWC1SZXF1ZXN0ZWQtV2l0aCc6ICdYTUxIdHRwUmVxdWVzdCcgfTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvcHRzLmJvZHkgPSBsYXN0LmJvZHk7CiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2gobGFzdC51cmwsIGZvcHRzKTsKICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHJlcy5vaykgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uc3QgdHh0ID0gYXdhaXQgcmVzLnRleHQoKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRyeSB7IGhhbmRsZVJhd1Jlc3BvbnNlKGxhc3QudXJsLCB0eHQpOyB9IGNhdGNoIChfKSB7fQogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgfSBjYXRjaCAoZSkgeyBjb25zb2xlLndhcm4oJ1tUTF0gcmVwbGF5IGZhaWwnLCBlKTsgfQogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgcmV0dXJuIFNFU1NJT04ucmF3X3F1ZXN0aW9ucy5sZW5ndGggPiAwOwogICAgICAgICAgICB9IGNhdGNoIChlKSB7IHJldHVybiBmYWxzZTsgfQogICAgICAgIH0KCiAgICAgICAgLy8g4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQCiAgICAgICAgLy8gW3Y0LjFdIEZJUkUgQlVUVE9OIOKAlCBLSeG7gk0gVFJBIExP4bqgSSBLRVkgKEdJ4buQTkcgVjMgQ09SRSkKICAgICAgICAvLyBLZXkgdGjGsOG7nW5nOiBLSE/DgSBjaOG7qWMgbsSDbmcgQ0hV4bqoTiBC4buKIDEwIMSQSeG7gk0KICAgICAgICAvLyBLZXkgUHJlbWl1bS9WSVAvVW5saW1pdGVkOiBIb+G6oXQgxJHhu5luZyBiw6xuaCB0aMaw4budbmcKICAgICAgICAvLyDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZAKICAgICAgICBjb25zdCBmaXJlQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLWZpcmVCdG4nKTsKCiAgICAgICAgaWYgKCFpc1ByZW1pdW1LZXkoKSkgewogICAgICAgICAgICAvLyDilIDilIAgS0VZIFRIxq/hu5xORzogVsO0IGhp4buHdSBob8OhIG7DunQgQ0hV4bqoTiBC4buKIDEwIMSQSeG7gk0g4pSA4pSACiAgICAgICAgICAgIGZpcmVCdG4uaW5uZXJIVE1MID0gJ/CflJIgQ0hV4bqoTiBC4buKIDEwIMSQSeG7gk0gKENI4buIIFBSRU1JVU0pJzsKICAgICAgICAgICAgZmlyZUJ0bi5zdHlsZS5iYWNrZ3JvdW5kID0gJ2xpbmVhci1ncmFkaWVudCgxMzVkZWcsIzQ0NCwjNjY2KSc7CiAgICAgICAgICAgIGZpcmVCdG4uc3R5bGUuY3Vyc29yID0gJ25vdC1hbGxvd2VkJzsKICAgICAgICAgICAgZmlyZUJ0bi5zdHlsZS5vcGFjaXR5ID0gJzAuNic7CiAgICAgICAgICAgIGZpcmVCdG4udGl0bGUgPSAnQ2jhu6ljIG7Eg25nIG7DoHkgY2jhu4kgZMOgbmggY2hvIGtleSBQUkVNSVVNLiBMacOqbiBo4buHIMSR4buDIG7Dom5nIGPhuqVwISc7CiAgICAgICAgICAgIGZpcmVCdG4ub25jbGljayA9IChlKSA9PiB7CiAgICAgICAgICAgICAgICBlLnByZXZlbnREZWZhdWx0KCk7CiAgICAgICAgICAgICAgICBhZGRMb2coJ/CflJIgQ2jhu6ljIG7Eg25nIG7DoHkgecOqdSBj4bqndSBrZXkgUFJFTUlVTSEnLCAnZXJyJyk7CiAgICAgICAgICAgICAgICBhZGRMb2coJ/Cfko4gTGnDqm4gaOG7hyBhZG1pbiDEkeG7gyBuw6JuZyBj4bqlcCBrZXkgUFJFTUlVTS4nLCAnd2FybicpOwogICAgICAgICAgICAgICAgc2hvd0N1c3RvbU1vZGFsKHsKICAgICAgICAgICAgICAgICAgICBpY29uOiAgJ/CflJInLAogICAgICAgICAgICAgICAgICAgIHRpdGxlOiAnWcOKVSBD4bqmVSBLRVkgUFJFTUlVTScsCiAgICAgICAgICAgICAgICAgICAgbGluZXM6IFsKICAgICAgICAgICAgICAgICAgICAgICAgJ0No4bupYyBuxINuZyA8Yj4iQ0hV4bqoTiBC4buKIDEwIMSQSeG7gk0iPC9iPiBjaOG7iSBkw6BuaCBjaG8ga2V5IFBSRU1JVU0hJywKICAgICAgICAgICAgICAgICAgICAgICAgYEtleSBj4bunYSBi4bqhbiBsw6Aga2V5IDxiPiR7KEtFWV9TVEFUVVMudHlwZSB8fCAnVEjGr+G7nE5HJykudG9VcHBlckNhc2UoKX08L2I+LmAsCiAgICAgICAgICAgICAgICAgICAgICAgICfwn5KOIExpw6puIGjhu4cgYWRtaW4gxJHhu4MgbsOibmcgY+G6pXAgbMOqbiBQUkVNSVVNIScKICAgICAgICAgICAgICAgICAgICBdCiAgICAgICAgICAgICAgICB9KTsKICAgICAgICAgICAgfTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgICAvLyDilIDilIAgS0VZIFBSRU1JVU06IFNFUlZFUiB44butIGzDvSBsb2dpYzsgY2xpZW50IGNo4buJIMSRaeG7gXUgcGjhu5FpICsgaGnhu4NuIHRo4buLIOKUgOKUgAogICAgICAgICAgICBmaXJlQnRuLm9uY2xpY2sgPSBhc3luYyAoKSA9PiB7CiAgICAgICAgICAgICAgICBhZGRMb2coJ/CflI0gxJDhu5NuZyBi4buZIGThu68gbGnhu4d1IHRow7QgdOG7qyBPTE0uLi4nLCAnaW5mbycpOwogICAgICAgICAgICAgICAgYXdhaXQgZm9yY2VGZXRjaFF1ZXN0aW9ucygpOwogICAgICAgICAgICAgICAgZm9yY2VHZXRNZXRhKCk7CgogICAgICAgICAgICAgICAgaWYgKCFTRVNTSU9OLm1ldGEuaWRfdXNlciB8fCAhU0VTU0lPTi5tZXRhLmlkX2NhdGUpIHsKICAgICAgICAgICAgICAgICAgICBhZGRMb2coJ+KdjCBDaMawYSBjw7MgSUQgdXNlci9jYXRlICh1c2VyPScgKyAoU0VTU0lPTi5tZXRhLmlkX3VzZXJ8fCc/JykgKyAnLCBjYXRlPScgKyAoU0VTU0lPTi5tZXRhLmlkX2NhdGV8fCc/JykgKyAnKS4gSMOjeSBGNSBob+G6t2MgY2jhu50gdOG6o2kgeG9uZyBjw6J1IGjhu49pLicsICdlcnInKTsKICAgICAgICAgICAgICAgICAgICBzaG93Q3VzdG9tTW9kYWwoewogICAgICAgICAgICAgICAgICAgICAgICBpY29uOiAgJ+KaoO+4jycsCiAgICAgICAgICAgICAgICAgICAgICAgIHRpdGxlOiAnVEhJ4bq+VSBE4buuIExJ4buGVScsCiAgICAgICAgICAgICAgICAgICAgICAgIGxpbmVzOiBbJ0NoxrBhIG5o4bqtbiDEkcaw4bujYyBJRCB0w6BpIGtob+G6o24gLyBiw6BpIHThuq1wIHThu6sgdHJhbmcgT0xNLjxicj5WdWkgbMOybmcgRjUgdHJhbmcsIMSR4bujaSBkYW5oIHPDoWNoIGPDonUgaOG7j2kgbuG6oXAgeG9uZyBy4buTaSBi4bqlbSBs4bqhaS4nXQogICAgICAgICAgICAgICAgICAgIH0pOwogICAgICAgICAgICAgICAgICAgIHJldHVybjsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIGlmIChTRVNTSU9OLnJhd19xdWVzdGlvbnMubGVuZ3RoID09PSAwKSB7CiAgICAgICAgICAgICAgICAgICAgYWRkTG9nKCfinYwgQ2jGsGEgbuG6oXAgxJHGsOG7o2MgY8OidSBo4buPaS4gSMOjeSBGNSB0cmFuZyBob+G6t2MgbMOgbSBt4bubaSBiw6BpIHThuq1wLicsICdlcnInKTsKICAgICAgICAgICAgICAgICAgICBzaG93Q3VzdG9tTW9kYWwoewogICAgICAgICAgICAgICAgICAgICAgICBpY29uOiAgJ/Cfk60nLAogICAgICAgICAgICAgICAgICAgICAgICB0aXRsZTogJ0NIxq9BIEPDkyBDw4JVIEjhu45JJywKICAgICAgICAgICAgICAgICAgICAgICAgbGluZXM6IFsnRGFuaCBzw6FjaCBjw6J1IGjhu49pIMSRYW5nIHRy4buRbmcuIEY1IHRyYW5nIGLDoGkgdOG6rXAgcuG7k2kgYuG6pW0gbOG6oWkuJ10KICAgICAgICAgICAgICAgICAgICB9KTsKICAgICAgICAgICAgICAgICAgICByZXR1cm47CiAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgY29uc3Qga2V5ICAgICAgPSBDVVJSRU5UX0tFWSB8fCBfc0xTLmdldChMU19LRVkpOwogICAgICAgICAgICAgICAgY29uc3QgbW9kZSAgICAgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtbW9kZVNlbGVjdCcpLnZhbHVlOwogICAgICAgICAgICAgICAgY29uc3QgdGltZV9zdHIgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtZ29kLXRpbWUnKS52YWx1ZTsKCiAgICAgICAgICAgICAgICBmaXJlQnRuLmRpc2FibGVkID0gdHJ1ZTsKICAgICAgICAgICAgICAgIGZpcmVCdG4udGV4dENvbnRlbnQgPSAn4o+zIMSQQU5HIFjhu6wgTMOdIFRSw4pOIFNFUlZFUi4uLic7CiAgICAgICAgICAgICAgICBhZGRMb2coJ/CfmoAgR+G7rWkgZOG7ryBsaeG7h3UgdGjDtCBsw6puIHNlcnZlciAobW9kZTogJyArIG1vZGUgKyAnKS4uLicsICd3YXJuJyk7CiAgICAgICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgICAgIC8vIFt2MThdIFNlcnZlciBnaeG6o2kgxJHDoXAgKyBk4buxbmcgc+G6tW4gcGFyYW1zIG7hu5lwIGLDoGk7IGNsaWVudCBraMO0bmcgeOG7rSBsw70gbmdoaeG7h3AgduG7pS4KICAgICAgICAgICAgICAgICAgICBjb25zdCByZXN1bHQgPSBhd2FpdCBnbVBvc3QoJy9maXJlJywgewogICAgICAgICAgICAgICAgICAgICAgICBrZXksIGh3aWQ6IGdldEhXSUQoKSwKICAgICAgICAgICAgICAgICAgICAgICAgc2Vzc2lvbjogewogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmF3X3F1ZXN0aW9uczogU0VTU0lPTi5yYXdfcXVlc3Rpb25zLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgbWV0YTogICAgICAgICAgU0VTU0lPTi5tZXRhLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgdmlkZW9fbGVuZ3RoOiAgU0VTU0lPTi52aWRlb19sZW5ndGgKICAgICAgICAgICAgICAgICAgICAgICAgfSwKICAgICAgICAgICAgICAgICAgICAgICAgbW9kZSwgdGltZV9zdHIsCiAgICAgICAgICAgICAgICAgICAgICAgIGdyYWRlOiB3aW5kb3cuZ3JhZGUgfHwgd2luZG93LmlkX2dyYWRlIHx8ICcxMCcKICAgICAgICAgICAgICAgICAgICB9KTsKCiAgICAgICAgICAgICAgICAgICAgaWYgKCEocmVzdWx0LnN1Y2Nlc3MgfHwgcmVzdWx0LnZhbGlkKSkgewogICAgICAgICAgICAgICAgICAgICAgICBjb25zdCBzdCAgPSByZXN1bHQuX2h0dHBTdGF0dXM7CiAgICAgICAgICAgICAgICAgICAgICAgIGNvbnN0IG1zZyA9IHJlc3VsdC5tZXNzYWdlIHx8ICdM4buXaSBraMO0bmcgeMOhYyDEkeG7i25oIHThu6sgc2VydmVyJzsKICAgICAgICAgICAgICAgICAgICAgICAgYWRkTG9nKCfinYwgU2VydmVyIHThu6sgY2jhu5FpOiAnICsgbXNnLCAnZXJyJyk7CiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChzdCA9PT0gNDAxKSAgICAgIHNob3dDdXN0b21Nb2RhbCh7IGljb246J/CflJInLCB0aXRsZTonS0VZIEtIw5RORyBI4buiUCBM4buGJywgICAgICBsaW5lczpbbXNnLCAnVnVpIGzDsm5nIG5o4bqtcCBrZXkgaOG7o3AgbOG7hyBob+G6t2MgbGnDqm4gaOG7hyBhZG1pbi4nXSB9KTsKICAgICAgICAgICAgICAgICAgICAgICAgZWxzZSBpZiAoc3QgPT09IDQwMykgc2hvd0N1c3RvbU1vZGFsKHsgaWNvbjon8J+SjicsIHRpdGxlOidD4bqmTiBLRVkgUFJFTUlVTScsICAgICBsaW5lczpbbXNnXSB9KTsKICAgICAgICAgICAgICAgICAgICAgICAgZWxzZSBpZiAoc3QgPT09IDQyOSkgc2hvd0N1c3RvbU1vZGFsKHsgaWNvbjon4o+zJywgdGl0bGU6J1FVw4EgVOG6pk4gU1XhuqRUJywgICAgICAgIGxpbmVzOlttc2csICdWdWkgbMOybmcgY2jhu50gdsOgaSBwaMO6dCBy4buTaSB0aOG7rSBs4bqhaS4nXSB9KTsKICAgICAgICAgICAgICAgICAgICAgICAgZWxzZSAgICAgICAgICAgICAgICAgc2hvd0N1c3RvbU1vZGFsKHsgaWNvbjon4pqg77iPJywgdGl0bGU6J0tIw5RORyBO4buYUCDEkMav4buiQycsIGxpbmVzOlttc2ddIH0pOwogICAgICAgICAgICAgICAgICAgICAgICBmaXJlQnRuLmRpc2FibGVkID0gZmFsc2U7CiAgICAgICAgICAgICAgICAgICAgICAgIGZpcmVCdG4udGV4dENvbnRlbnQgPSAn8J+SpSBDSFXhuqhOIELhu4ogMTAgxJBJ4buCTSc7CiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjsKICAgICAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgICAgIC8vIFt2MThdIFBow6F0IGzhuqFpIHJlcXVlc3QgbuG7mXAgYsOgaSBi4bqxbmcgcGhpw6puIE9MTSBj4bulYyBi4buZIChjb29raWUgKyBDU1JGIHRyw6puIHRyw6xuaCBkdXnhu4d0KS4KICAgICAgICAgICAgICAgICAgICBhZGRMb2coJ/Cfk6QgU2VydmVyIMSRw6MgZOG7sW5nIHhvbmcgYsOgaSDigJQgxJFhbmcgZ+G7rWkgbMOqbiBPTE0uLi4nLCAnaW5mbycpOwogICAgICAgICAgICAgICAgICAgIGlmIChyZXN1bHQuc3VtbWFyeSAmJiBBcnJheS5pc0FycmF5KHJlc3VsdC5zdW1tYXJ5Lml0ZW1zKSAmJiByZXN1bHQuc3VtbWFyeS5pdGVtcy5sZW5ndGgpIHsKICAgICAgICAgICAgICAgICAgICAgICAgYWRkTG9nKCfwn6euIFNlcnZlciDEkcOjIGdp4bqjaSAnICsgKHJlc3VsdC5zdW1tYXJ5LmNvdW50IHx8IHJlc3VsdC5zdW1tYXJ5Lml0ZW1zLmxlbmd0aCkgKyAnIGPDonUgKG1vZGU6ICcgKyAocmVzdWx0LnN1bW1hcnkubW9kZSB8fCBtb2RlKSArICcpLicsICdpbmZvJyk7CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIGNvbnN0IGNzcmYgPSBTRVNTSU9OLm1ldGEuY3NyZl90b2tlbiB8fAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkb2N1bWVudC5xdWVyeVNlbGVjdG9yKCdtZXRhW25hbWU9ImNzcmYtdG9rZW4iXScpPy5nZXRBdHRyaWJ1dGUoJ2NvbnRlbnQnKSB8fCAnJzsKICAgICAgICAgICAgICAgICAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGZldGNoKHJlc3VsdC5lbmRwb2ludCB8fCAnL2NvdXJzZS90ZWFjaGVyLXN0YXRpYycsIHsKICAgICAgICAgICAgICAgICAgICAgICAgbWV0aG9kOiAnUE9TVCcsCiAgICAgICAgICAgICAgICAgICAgICAgIGNyZWRlbnRpYWxzOiAnaW5jbHVkZScsCiAgICAgICAgICAgICAgICAgICAgICAgIGhlYWRlcnM6IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICdjb250ZW50LXR5cGUnOiAgICAgJ2FwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZDsgY2hhcnNldD1VVEYtOCcsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAneC1jc3JmLXRva2VuJzogICAgIGNzcmYsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAneC1yZXF1ZXN0ZWQtd2l0aCc6ICdYTUxIdHRwUmVxdWVzdCcKICAgICAgICAgICAgICAgICAgICAgICAgfSwKICAgICAgICAgICAgICAgICAgICAgICAgYm9keTogcmVzdWx0LnBhcmFtc19zdHIKICAgICAgICAgICAgICAgICAgICB9KTsKCiAgICAgICAgICAgICAgICAgICAgaWYgKHJlc3BvbnNlLm9rKSB7CiAgICAgICAgICAgICAgICAgICAgICAgIGFkZExvZygn4pyFIE7hu5lwIGLDoGkgdGjDoG5oIGPDtG5nISBLaeG7g20gdHJhIMSRaeG7g20gT0xNLicsICdvaycpOwogICAgICAgICAgICAgICAgICAgICAgICBmaXJlQnRuLnRleHRDb250ZW50ID0gJ+KchSBUSMOATkggQ8OUTkchJzsKICAgICAgICAgICAgICAgICAgICAgICAgZmlyZUJ0bi5zdHlsZS5iYWNrZ3JvdW5kID0gJ2xpbmVhci1ncmFkaWVudCgxMzVkZWcsIzAwYjA5YiwjMDBlNjc2KSc7CiAgICAgICAgICAgICAgICAgICAgICAgIHNob3dDdXN0b21Nb2RhbCh7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpY29uOiAgJ+KchScsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aXRsZTogJ07hu5hQIELDgEkgVEjDgE5IIEPDlE5HJywKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGxpbmVzOiBbCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJ1NlcnZlciDEkcOjIHjhu60gbMO9IDxiPicgKyAocmVzdWx0LnN1bW1hcnkgPyAocmVzdWx0LnN1bW1hcnkuY291bnQgfHwgMCkgOiBTRVNTSU9OLnJhd19xdWVzdGlvbnMubGVuZ3RoKSArICc8L2I+IGPDonUgdsOgIGfhu61pIGzDqm4gT0xNLicsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJ1RyYW5nIHPhur0gdOG7sSB04bqjaSBs4bqhaSBzYXUgdsOgaSBnacOieS4nCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBdCiAgICAgICAgICAgICAgICAgICAgICAgIH0pOwogICAgICAgICAgICAgICAgICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHdpbmRvdy5sb2NhdGlvbi5yZWxvYWQoKSwgMjUwMCk7CiAgICAgICAgICAgICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgICAgICAgICAgICAgYWRkTG9nKCfinYwgT0xNIHRy4bqjIHbhu4EgbOG7l2kgSFRUUCAnICsgcmVzcG9uc2Uuc3RhdHVzLCAnZXJyJyk7CiAgICAgICAgICAgICAgICAgICAgICAgIHNob3dDdXN0b21Nb2RhbCh7IGljb246J+KdjCcsIHRpdGxlOidO4buYUCBCw4BJIFRI4bqkVCBC4bqgSScsIGxpbmVzOlsnTcOheSBjaOG7pyBPTE0gdHLhuqMgbOG7l2kgSFRUUCAnICsgcmVzcG9uc2Uuc3RhdHVzICsgJy48YnI+VGjhu60gRjUgdHJhbmcgcuG7k2kgYuG6pW0gbOG6oWkuJ10gfSk7CiAgICAgICAgICAgICAgICAgICAgICAgIGZpcmVCdG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgICAgICAgICAgICAgICAgICAgZmlyZUJ0bi50ZXh0Q29udGVudCA9ICfwn5KlIENIVeG6qE4gQuG7iiAxMCDEkEnhu4JNJzsKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICB9IGNhdGNoIChlKSB7CiAgICAgICAgICAgICAgICAgICAgYWRkTG9nKCfinYwgTOG7l2k6ICcgKyBlLm1lc3NhZ2UsICdlcnInKTsKICAgICAgICAgICAgICAgICAgICBzaG93Q3VzdG9tTW9kYWwoeyBpY29uOifwn4yQJywgdGl0bGU6J0zhu5ZJIEvhur5UIE7hu5BJJywgbGluZXM6WydLaMO0bmcga+G6v3QgbuG7kWkgxJHGsOG7o2Mgc2VydmVyL09MTTogPGI+JyArIChlLm1lc3NhZ2UgfHwgJycpICsgJzwvYj4nXSB9KTsKICAgICAgICAgICAgICAgICAgICBmaXJlQnRuLmRpc2FibGVkID0gZmFsc2U7CiAgICAgICAgICAgICAgICAgICAgZmlyZUJ0bi50ZXh0Q29udGVudCA9ICfwn5KlIENIVeG6qE4gQuG7iiAxMCDEkEnhu4JNJzsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfTsKICAgICAgICB9CgogICAgICAgIC8vIE7DunQgxJHhu5VpIGtleQogICAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1jaGFuZ2VLZXknKS5vbmNsaWNrID0gKCkgPT4gewogICAgICAgICAgICBzaG93Q29uZmlybU1vZGFsKHsKICAgICAgICAgICAgICAgIGljb246ICAgICAgICfwn5SEJywKICAgICAgICAgICAgICAgIHRpdGxlOiAgICAgICfEkOG7lEkgS0VZPycsCiAgICAgICAgICAgICAgICBsaW5lczogICAgICBbCiAgICAgICAgICAgICAgICAgICAgJ0tleSBoaeG7h24gdOG6oWkgc+G6vSBi4buLIDxiPnhvw6EgaG/DoG4gdG/DoG48L2I+LicsCiAgICAgICAgICAgICAgICAgICAgJ0LhuqFuIHPhur0gxJHGsOG7o2MgxJHGsGEgduG7gSBtw6BuIGjDrG5oIMSRxINuZyBuaOG6rXAuJwogICAgICAgICAgICAgICAgXSwKICAgICAgICAgICAgICAgIG9rVGV4dDogICAgICfwn5SEIMSQ4buUSSBLRVknLAogICAgICAgICAgICAgICAgY2FuY2VsVGV4dDogJ0jhu6ZZJywKICAgICAgICAgICAgICAgIG9uT2s6ICgpID0+IHsKICAgICAgICAgICAgICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShMU19LRVkpOwogICAgICAgICAgICAgICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKExTX1RZUEUpOwogICAgICAgICAgICAgICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKExTX0VYUCk7CiAgICAgICAgICAgICAgICAgICAgQ1VSUkVOVF9LRVkgICAgPSBudWxsOwogICAgICAgICAgICAgICAgICAgIEtFWV9TVEFUVVMgICAgID0geyB2YWxpZDogZmFsc2UsIHR5cGU6IG51bGwsIGV4cGlyZXNfYXQ6IG51bGwgfTsKICAgICAgICAgICAgICAgICAgICBfc2VjU2Vzc2lvbiAgICA9IHsgdG9rZW46IG51bGwsIGV4cDogMCwgZnBIYXNoOiBudWxsLCBzZXE6IDEgfTsKICAgICAgICAgICAgICAgICAgICBDVVJSRU5UX0RFVklDRSA9ICcnOwogICAgICAgICAgICAgICAgICAgIHBhbmVsLnJlbW92ZSgpOwogICAgICAgICAgICAgICAgICAgIGZsb2F0QnRuLnJlbW92ZSgpOwogICAgICAgICAgICAgICAgICAgIGJ1aWxkTG9ja1NjcmVlbigpOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9KTsKICAgICAgICB9OwoKICAgICAgICAvLyDilIDilIAgTG9nIGto4bufaSDEkeG7mW5nICsgdHLhuqFuZyB0aMOhaSBrZXkg4pSA4pSACiAgICAgICAgYWRkTG9nKCfinIUgR09EIE1PREUgQ29ubmVjdG9yIHYxOCAoc2xpbTogZ2lhbyBkaeG7h24gKyBhbnRpICsgdGjDtG5nIGLDoW8pIMSRw6Mgc+G6tW4gc8OgbmcuJywgJ29rJyk7CiAgICAgICAgY29uc3Qgb2xtVXNlck5vdyA9IGdldE9sbVVzZXJuYW1lKCk7CiAgICAgICAgYWRkTG9nKGDwn5GkIFTDoGkga2hv4bqjbiBPTE06ICR7b2xtVXNlck5vd31gLCAnaW5mbycpOwogICAgICAgIGFkZExvZygn4oS577iPIMSQYW5nIGNo4budIG7huqFwIGPDonUgaOG7j2kuLi4nLCAnaW5mbycpOwogICAgICAgIC8vIFt2NC4xXSBUaMO0bmcgYsOhbyB0cuG6oW5nIHRow6FpIGtleSDigJQgZ2nhu5FuZyB2MyBjb3JlCiAgICAgICAgaWYgKCFpc1ByZW1pdW1LZXkoKSkgewogICAgICAgICAgICBhZGRMb2coJ+KaoO+4jyBLZXkgdGjGsOG7nW5nOiBDaOG7qWMgbsSDbmcgIkNIVeG6qE4gQuG7iiAxMCDEkEnhu4JNIiBi4buLIGtob8OhIScsICd3YXJuJyk7CiAgICAgICAgICAgIGFkZExvZygn8J+SjiBOw6JuZyBj4bqlcCBQUkVNSVVNIMSR4buDIG3hu58ga2hvw6EgdG/DoG4gYuG7mSB0w61uaCBuxINuZy4nLCAnd2FybicpOwogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgIGFkZExvZygn8J+SjiBLZXkgUFJFTUlVTTogVOG6pXQgY+G6oyB0w61uaCBuxINuZyDEkcOjIMSRxrDhu6NjIG3hu58ga2hvw6EhJywgJ29rJyk7CiAgICAgICAgICAgIC8vIFt2Nl0gQVVUTy1U4bqiSSBtb2R1bGUgIkNIVeG6qE4gQuG7iiAxMCDEkEnhu4JNIiB04burIHNlcnZlciArIGLhuq10IGhlYXJ0YmVhdCBjaGVjayBsacOqbiB04bulYwogICAgICAgICAgICBfc3RhcnRIZWFydGJlYXQoKTsKICAgICAgICB9CiAgICB9CgogICAgLy8g4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQCiAgICAvLyAgWEhSIC8gRkVUQ0ggSU5URVJDRVBUT1IKICAgIC8vIOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkAogICAgY29uc3QgQVBJX0tFWVdPUkRTID0gWydnZXQtcXVlc3Rpb24tb2YtaWRzJywnZ2V0LXF1ZXN0aW9uP2JlbG9uZ3M9MScsJ2dldC1xdWVzdGlvbicsJ2dldC10ZXN0J107CgogICAgZnVuY3Rpb24gaGFuZGxlUmF3UmVzcG9uc2UodXJsLCB0ZXh0KSB7CiAgICAgICAgaWYgKCF1cmwgfHwgIXRleHQpIHJldHVybjsKICAgICAgICBjb25zdCBpc1FBcGkgPSBBUElfS0VZV09SRFMuc29tZShrID0+IHVybC5pbmNsdWRlcyhrKSk7CiAgICAgICAgY29uc3QgaXNMZWcgID0gdXJsLmluY2x1ZGVzKCdnZXQtcXVlc3Rpb24nKSB8fCB1cmwuaW5jbHVkZXMoJ2dldC10ZXN0JykgfHwKICAgICAgICAgICAgICAgICAgICAgICB0ZXh0LmluY2x1ZGVzKCdqc29uX2NvbnRlbnQnKSB8fCB0ZXh0LmluY2x1ZGVzKCcicXVlc3Rpb25zIicpOwogICAgICAgIGlmICghaXNRQXBpICYmICFpc0xlZykgcmV0dXJuOwoKICAgICAgICBsZXQgZGF0YTsKICAgICAgICB0cnkgeyBkYXRhID0gSlNPTi5wYXJzZSh0ZXh0KTsgfSBjYXRjaCAoXykgeyByZXR1cm47IH0KCiAgICAgICAgY29uc3QgcUxpc3QgPSBkYXRhLnF1ZXN0aW9ucyB8fCBkYXRhLmRhdGEgfHwgKEFycmF5LmlzQXJyYXkoZGF0YSkgPyBkYXRhIDogbnVsbCk7CiAgICAgICAgaWYgKCFBcnJheS5pc0FycmF5KHFMaXN0KSB8fCBxTGlzdC5sZW5ndGggPT09IDApIHJldHVybjsKCiAgICAgICAgU0VTU0lPTi5yYXdfcXVlc3Rpb25zICAgICAgPSBxTGlzdDsKICAgICAgICBTRVNTSU9OLm1ldGEuaWRfdXNlciAgICAgICA9IHFMaXN0WzBdPy5pZF91c2VyIHx8IGRldGVjdFVzZXJJRCgpOwogICAgICAgIFNFU1NJT04ubWV0YS5pZF9jb3Vyc2V3YXJlID0gZGF0YS5pZF9jb3Vyc2V3YXJlIHx8IG5ldyBVUkxTZWFyY2hQYXJhbXMod2luZG93LmxvY2F0aW9uLnNlYXJjaCkuZ2V0KCdpX2MnKTsKICAgICAgICBTRVNTSU9OLm1ldGEuaWRfY2F0ZSAgICAgICA9IGRhdGEuaWRfY2F0ZSB8fCBkYXRhLmlkX2V4YW0gfHwgcmlwSWRGcm9tVXJsKCk7CiAgICAgICAgU0VTU0lPTi5tZXRhLmlkX3NjaG9vbCAgICAgPSBkZXRlY3RTY2hvb2xJRChkYXRhKTsKICAgICAgICBTRVNTSU9OLm1ldGEuaWRfZ3JvdXAgICAgICA9IGRldGVjdEdyb3VwSUQoKTsKICAgICAgICBjb25zdCBtdCA9IGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoJ21ldGFbbmFtZT0iY3NyZi10b2tlbiJdJyk7CiAgICAgICAgU0VTU0lPTi5tZXRhLmNzcmZfdG9rZW4gICAgPSBtdCA/IG10LmdldEF0dHJpYnV0ZSgnY29udGVudCcpIDogKHdpbmRvdy5jc3JmX3Rva2VuIHx8ICcnKTsKCiAgICAgICAgaWYgKHdpbmRvdy50b3RhbF90aW1lKSBTRVNTSU9OLnZpZGVvX2xlbmd0aCA9IE1hdGguY2VpbCh3aW5kb3cudG90YWxfdGltZSk7CiAgICAgICAgZWxzZSBpZiAoZGF0YS50b3RhbF90aW1lKSBTRVNTSU9OLnZpZGVvX2xlbmd0aCA9IE1hdGguY2VpbChkYXRhLnRvdGFsX3RpbWUpOwoKICAgICAgICBpZiAoZGF0YS50eXBlID09IDUgfHwgd2luZG93LmxvY2F0aW9uLmhyZWYuaW5jbHVkZXMoJ3ZpZGVvJykgfHwgZG9jdW1lbnQucXVlcnlTZWxlY3RvcigndmlkZW8saWZyYW1lW3NyYyo9InlvdXR1YmUiXScpKQogICAgICAgICAgICBTRVNTSU9OLmF1dG9fbW9kZSA9ICd2aWRlbyc7CiAgICAgICAgZWxzZSBpZiAoZGF0YS50eXBlX2V4YW0gPT0gMSB8fCBkYXRhLmlzX2V4YW0gPT0gMSB8fCB3aW5kb3cuaXNfZXhhbSA9PSAxIHx8CiAgICAgICAgICAgICAgICAgZG9jdW1lbnQucXVlcnlTZWxlY3RvcignLnRpbWUtY291bnRkb3duLCNzdWJtaXQtdGVzdCcpKQogICAgICAgICAgICBTRVNTSU9OLmF1dG9fbW9kZSA9ICdleGFtJzsKICAgICAgICBlbHNlCiAgICAgICAgICAgIFNFU1NJT04uYXV0b19tb2RlID0gJ3ByYWN0aWNlJzsKCiAgICAgICAgY29uc3QgcWNFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1xY291bnQnKTsKICAgICAgICBjb25zdCBtZEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLW1vZGUtZGV0ZWN0ZWQnKTsKICAgICAgICBpZiAocWNFbCkgcWNFbC50ZXh0Q29udGVudCA9IHFMaXN0Lmxlbmd0aDsKICAgICAgICBpZiAobWRFbCkgewogICAgICAgICAgICBtZEVsLnRleHRDb250ZW50ID0gU0VTU0lPTi5hdXRvX21vZGUudG9VcHBlckNhc2UoKTsKICAgICAgICAgICAgY29uc3QgbXMgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtbW9kZVNlbGVjdCcpOwogICAgICAgICAgICBpZiAobXMpIG1zLnZhbHVlID0gU0VTU0lPTi5hdXRvX21vZGU7CiAgICAgICAgfQoKICAgICAgICBhZGRMb2coYPCfk6UgTuG6oXAgJHtxTGlzdC5sZW5ndGh9IGPDonUgaOG7j2kgKCR7U0VTU0lPTi5hdXRvX21vZGV9KSDigJQgxJFhbmcgZ2nhuqNpIG3Doy4uLmAsICdpbmZvJyk7CgogICAgICAgIGNvbnN0IGtleSA9IENVUlJFTlRfS0VZIHx8IF9zTFMuZ2V0KExTX0tFWSk7IC8vIFt2NV0KICAgICAgICBpZiAoIWtleSkgeyBhZGRMb2coJ+KaoO+4jyBDaMawYSBjw7Mga2V5IOKAlCBraMO0bmcgdGjhu4MgZ2nhuqNpIG3Doy4nLCAnd2FybicpOyByZXR1cm47IH0KCiAgICAgICAgZ21Qb3N0KCcvcHJvY2VzcycsIHsga2V5LCBod2lkOiBnZXRIV0lEKCksIHF1ZXN0aW9uczogcUxpc3QgfSkKICAgICAgICAgICAgLnRoZW4ocmVzdWx0ID0+IHsKICAgICAgICAgICAgICAgIGlmICghKHJlc3VsdC5zdWNjZXNzIHx8IHJlc3VsdC52YWxpZCkpIHsKICAgICAgICAgICAgICAgICAgICBhZGRMb2coJ+KdjCBTZXJ2ZXI6ICcgKyAocmVzdWx0Lm1lc3NhZ2UgfHwgJ0zhu5dpIGdp4bqjaSBtw6MnKSwgJ2VycicpOwogICAgICAgICAgICAgICAgICAgIHJldHVybjsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIGNvbnN0IGJveCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1sb2dib3gnKTsKICAgICAgICAgICAgICAgIGlmIChib3gpIHsKICAgICAgICAgICAgICAgICAgICBib3guaW5uZXJIVE1MID0gJyc7CiAgICAgICAgICAgICAgICAgICAgcmVzdWx0LnF1ZXN0aW9ucy5mb3JFYWNoKHEgPT4gewogICAgICAgICAgICAgICAgICAgICAgICBjb25zdCBkID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICAgICAgICAgICAgICAgICAgICAgIGQuY2xhc3NOYW1lID0gJ3RsLWxvZyBvayc7CiAgICAgICAgICAgICAgICAgICAgICAgIGQuaW5uZXJIVE1MID0gYDxiPlEke3EuaW5kZXh9OjwvYj4gJHsocS50aXRsZSB8fCAnJykuc3Vic3RyaW5nKDAsNDApfSDihpIgPHNwYW4gc3R5bGU9ImNvbG9yOiNmZmMxMDc7Ij4ke3EuYW5zd2Vycy5qb2luKCcgfCAnKX08L3NwYW4+YDsKICAgICAgICAgICAgICAgICAgICAgICAgYm94LmFwcGVuZENoaWxkKGQpOwogICAgICAgICAgICAgICAgICAgIH0pOwogICAgICAgICAgICAgICAgICAgIGJveC5zY3JvbGxUb3AgPSBib3guc2Nyb2xsSGVpZ2h0OwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgYWRkTG9nKGDinIUgxJDDoyBoaeG7g24gdGjhu4sgxJHDoXAgw6FuICR7cmVzdWx0LmNvdW50fSBjw6J1IWAsICdvaycpOwogICAgICAgICAgICB9KQogICAgICAgICAgICAuY2F0Y2goZSA9PiBhZGRMb2coJ+KdjCBM4buXaSBr4bq/dCBu4buRaSBzZXJ2ZXI6ICcgKyBlLm1lc3NhZ2UsICdlcnInKSk7CiAgICB9CgogICAgLy8g4pSA4pSA4pSAIFBhZ2UtY29udGV4dCBYSFIvRmV0Y2ggaG9vayDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIAKICAgIChmdW5jdGlvbiBpbmplY3RQYWdlSG9vaygpIHsKICAgICAgICB0cnkgewogICAgICAgICAgICBjb25zdCBjb2RlID0gJygnICsgZnVuY3Rpb24gKCkgewogICAgICAgICAgICAgICAgaWYgKHdpbmRvdy5fX3RsX2hvb2tlZCkgcmV0dXJuOwogICAgICAgICAgICAgICAgd2luZG93Ll9fdGxfaG9va2VkID0gdHJ1ZTsKICAgICAgICAgICAgICAgIHdpbmRvdy5fX2t2X3FfYnVmID0gd2luZG93Ll9fa3ZfcV9idWYgfHwgW107CiAgICAgICAgICAgICAgICBmdW5jdGlvbiBfX3RsX3B1c2godXJsLCB0ZXh0KSB7CiAgICAgICAgICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgICAgICAgICAgd2luZG93Ll9fa3ZfcV9idWYucHVzaCh7IHVybDogdXJsLCB0ZXh0OiB0ZXh0LCB0czogRGF0ZS5ub3coKSB9KTsKICAgICAgICAgICAgICAgICAgICAgICAgd2luZG93LmRpc3BhdGNoRXZlbnQobmV3IEN1c3RvbUV2ZW50KCdfX2t2X3FkYXRhJywgeyBkZXRhaWw6IHsgdXJsOiB1cmwsIHRleHQ6IHRleHQgfSB9KSk7CiAgICAgICAgICAgICAgICAgICAgfSBjYXRjaCAoZSkge30KICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIGZ1bmN0aW9uIF9fdGxfcmVtZW1iZXJfcmVxKHVybCwgbWV0aG9kLCBib2R5KSB7CiAgICAgICAgICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHUgPSAodXJsIHx8ICcnKS50b0xvd2VyQ2FzZSgpOwogICAgICAgICAgICAgICAgICAgICAgICBpZiAodS5pbmRleE9mKCdnZXQtcXVlc3Rpb24nKSAhPT0gLTEgfHwgdS5pbmRleE9mKCdnZXQtdGVzdCcpICE9PSAtMSkgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgd2luZG93Ll9fdGxfbGFzdF9xcmVxID0geyB1cmw6IHVybCwgbWV0aG9kOiBtZXRob2QgfHwgJ0dFVCcsIGJvZHk6IGJvZHkgfHwgbnVsbCwgdHM6IERhdGUubm93KCkgfTsKICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIH0gY2F0Y2ggKGUpIHt9CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICB2YXIgX19vID0gWE1MSHR0cFJlcXVlc3QucHJvdG90eXBlLm9wZW47CiAgICAgICAgICAgICAgICB2YXIgX19zID0gWE1MSHR0cFJlcXVlc3QucHJvdG90eXBlLnNlbmQ7CiAgICAgICAgICAgICAgICBYTUxIdHRwUmVxdWVzdC5wcm90b3R5cGUub3BlbiA9IGZ1bmN0aW9uIChtLCB1KSB7IHRoaXMuX190bF91cmwgPSB1OyByZXR1cm4gX19vLmFwcGx5KHRoaXMsIGFyZ3VtZW50cyk7IH07CiAgICAgICAgICAgICAgICBYTUxIdHRwUmVxdWVzdC5wcm90b3R5cGUuc2VuZCA9IGZ1bmN0aW9uIChib2R5KSB7CiAgICAgICAgICAgICAgICAgICAgdmFyIHNlbGYgPSB0aGlzOwogICAgICAgICAgICAgICAgICAgIF9fdGxfcmVtZW1iZXJfcmVxKHNlbGYuX190bF91cmwgfHwgJycsICdQT1NUJywgYm9keSB8fCBudWxsKTsKICAgICAgICAgICAgICAgICAgICB0aGlzLmFkZEV2ZW50TGlzdGVuZXIoJ2xvYWQnLCBmdW5jdGlvbiAoKSB7CiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChzZWxmLnN0YXR1cyA9PT0gMjAwKSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0cnkgeyBfX3RsX3B1c2goc2VsZi5yZXNwb25zZVVSTCB8fCBzZWxmLl9fdGxfdXJsIHx8ICcnLCBzZWxmLnJlc3BvbnNlVGV4dCB8fCAnJyk7IH0gY2F0Y2ggKGUpIHt9CiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICB9KTsKICAgICAgICAgICAgICAgICAgICByZXR1cm4gX19zLmFwcGx5KHRoaXMsIGFyZ3VtZW50cyk7CiAgICAgICAgICAgICAgICB9OwogICAgICAgICAgICAgICAgdmFyIF9fZiA9IHdpbmRvdy5mZXRjaDsKICAgICAgICAgICAgICAgIHdpbmRvdy5mZXRjaCA9IGZ1bmN0aW9uICgpIHsKICAgICAgICAgICAgICAgICAgICB2YXIgYXJncyA9IGFyZ3VtZW50czsKICAgICAgICAgICAgICAgICAgICB2YXIgdXJsID0gdHlwZW9mIGFyZ3NbMF0gPT09ICdzdHJpbmcnID8gYXJnc1swXSA6IChhcmdzWzBdICYmIGFyZ3NbMF0udXJsID8gYXJnc1swXS51cmwgOiAnJyk7CiAgICAgICAgICAgICAgICAgICAgdmFyIG9wdHMgPSBhcmdzWzFdIHx8ICh0eXBlb2YgYXJnc1swXSA9PT0gJ29iamVjdCcgPyBhcmdzWzBdIDogbnVsbCk7CiAgICAgICAgICAgICAgICAgICAgX190bF9yZW1lbWJlcl9yZXEodXJsLCAob3B0cyAmJiBvcHRzLm1ldGhvZCkgfHwgJ0dFVCcsIChvcHRzICYmIG9wdHMuYm9keSkgfHwgbnVsbCk7CiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIF9fZi5hcHBseSh0aGlzLCBhcmdzKS50aGVuKGZ1bmN0aW9uIChyZXMpIHsKICAgICAgICAgICAgICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBjbCA9IHJlcy5jbG9uZSgpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2wudGV4dCgpLnRoZW4oZnVuY3Rpb24gKHQpIHsgdHJ5IHsgX190bF9wdXNoKHVybCB8fCByZXMudXJsIHx8ICcnLCB0KTsgfSBjYXRjaCAoZSkge30gfSk7CiAgICAgICAgICAgICAgICAgICAgICAgIH0gY2F0Y2ggKGUpIHt9CiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiByZXM7CiAgICAgICAgICAgICAgICAgICAgfSk7CiAgICAgICAgICAgICAgICB9OwogICAgICAgICAgICAgICAgLy8gW3Y2LXNtYXJ0XSBEw7IgU0NSSVBUIEzDgTogdXNlcnNjcmlwdC9leHRlbnNpb24ga2jDoWMgbuG6v3UgY8WpbmcgaG9vayBYSFIvZmV0Y2ggc+G6vSBHSEkgxJDDiCB3cmFwcGVyIGPhu6dhIHRhLgogICAgICAgICAgICAgICAgLy8gICAgICAgICAgICAgS2nhu4NtIHRyYSDEkeG7i25oIGvhu7MgOHM7IG7hur91IGLhu4sgZ2hpIMSRw6gg4oaSIGLDoW8gc+G7sSBraeG7h24gduG7gSB1c2Vyc2NyaXB0IMSR4buDIHjDoWMgbmjhuq1uIChj4bqnbiAzIGzhuqduKS4KICAgICAgICAgICAgICAgIHdpbmRvdy5fX3RsX215X29wZW4gID0gWE1MSHR0cFJlcXVlc3QucHJvdG90eXBlLm9wZW47CiAgICAgICAgICAgICAgICB3aW5kb3cuX190bF9teV9zZW5kICA9IFhNTEh0dHBSZXF1ZXN0LnByb3RvdHlwZS5zZW5kOwogICAgICAgICAgICAgICAgd2luZG93Ll9fdGxfbXlfZmV0Y2ggPSB3aW5kb3cuZmV0Y2g7CiAgICAgICAgICAgICAgICBzZXRJbnRlcnZhbChmdW5jdGlvbiAoKSB7CiAgICAgICAgICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgICAgICAgICAgaWYgKFhNTEh0dHBSZXF1ZXN0LnByb3RvdHlwZS5vcGVuICAhPT0gd2luZG93Ll9fdGxfbXlfb3BlbiAgfHwKICAgICAgICAgICAgICAgICAgICAgICAgICAgIFhNTEh0dHBSZXF1ZXN0LnByb3RvdHlwZS5zZW5kICAhPT0gd2luZG93Ll9fdGxfbXlfc2VuZCAgfHwKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdpbmRvdy5mZXRjaCAgICAgICAgICAgICAgICAgICAhPT0gd2luZG93Ll9fdGxfbXlfZmV0Y2gpIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdpbmRvdy5kaXNwYXRjaEV2ZW50KG5ldyBDdXN0b21FdmVudCgnX190bF9mb3JlaWduX2hvb2snLCB7IGRldGFpbDogeyB0OiBEYXRlLm5vdygpIH0gfSkpOwogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgfSBjYXRjaCAoZSkge30KICAgICAgICAgICAgICAgIH0sIDgwMDApOwogICAgICAgICAgICB9ICsgJykoKTsnOwogICAgICAgICAgICBjb25zdCBzRWwgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdzY3JpcHQnKTsKICAgICAgICAgICAgc0VsLnRleHRDb250ZW50ID0gY29kZTsKICAgICAgICAgICAgKGRvY3VtZW50LmhlYWQgfHwgZG9jdW1lbnQuZG9jdW1lbnRFbGVtZW50KS5hcHBlbmRDaGlsZChzRWwpOwogICAgICAgICAgICBzRWwucmVtb3ZlKCk7CiAgICAgICAgfSBjYXRjaCAoZSkgeyBjb25zb2xlLndhcm4oJ1tUTF0gaW5qZWN0IGZhaWwnLCBlKTsgfQogICAgfSkoKTsKCiAgICBmdW5jdGlvbiBzZXR1cEtWQnVmUmVhZGVyKCkgewogICAgICAgIHRyeSB7CiAgICAgICAgICAgIGNvbnN0IFVXID0gKHR5cGVvZiB1bnNhZmVXaW5kb3cgIT09ICd1bmRlZmluZWQnKSA/IHVuc2FmZVdpbmRvdyA6IHdpbmRvdzsKICAgICAgICAgICAgbGV0IHByb2Nlc3NlZCA9IDA7CiAgICAgICAgICAgIGZ1bmN0aW9uIGRyYWluKCkgewogICAgICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgICAgICBjb25zdCBidWYgPSBVVy5fX2t2X3FfYnVmOwogICAgICAgICAgICAgICAgICAgIGlmICghQXJyYXkuaXNBcnJheShidWYpIHx8IGJ1Zi5sZW5ndGggPD0gcHJvY2Vzc2VkKSByZXR1cm47CiAgICAgICAgICAgICAgICAgICAgZm9yIChsZXQgaSA9IHByb2Nlc3NlZDsgaSA8IGJ1Zi5sZW5ndGg7IGkrKykgewogICAgICAgICAgICAgICAgICAgICAgICBjb25zdCBpdCA9IGJ1ZltpXTsKICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGl0ICYmIGl0LnVybCAmJiBpdC50ZXh0KSB7IHRyeSB7IGhhbmRsZVJhd1Jlc3BvbnNlKGl0LnVybCwgaXQudGV4dCk7IH0gY2F0Y2ggKF8pIHt9IH0KICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgcHJvY2Vzc2VkID0gYnVmLmxlbmd0aDsKICAgICAgICAgICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgICAgIH0KICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgIFVXLmFkZEV2ZW50TGlzdGVuZXIoJ19fa3ZfcWRhdGEnLCBmdW5jdGlvbiAoZXZ0KSB7CiAgICAgICAgICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgICAgICAgICAgY29uc3QgZCA9IGV2dCAmJiBldnQuZGV0YWlsOwogICAgICAgICAgICAgICAgICAgICAgICBpZiAoZCAmJiBkLnVybCAmJiBkLnRleHQpIHsgdHJ5IHsgaGFuZGxlUmF3UmVzcG9uc2UoZC51cmwsIGQudGV4dCk7IH0gY2F0Y2ggKF8pIHt9IH0KICAgICAgICAgICAgICAgICAgICAgICAgY29uc3QgYnVmID0gVVcuX19rdl9xX2J1ZjsKICAgICAgICAgICAgICAgICAgICAgICAgaWYgKEFycmF5LmlzQXJyYXkoYnVmKSkgcHJvY2Vzc2VkID0gYnVmLmxlbmd0aDsKICAgICAgICAgICAgICAgICAgICB9IGNhdGNoIChfKSB7fQogICAgICAgICAgICAgICAgfSk7CiAgICAgICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgICAgIGRyYWluKCk7CiAgICAgICAgICAgIGlmIChkb2N1bWVudC5yZWFkeVN0YXRlID09PSAnbG9hZGluZycpIGRvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXIoJ0RPTUNvbnRlbnRMb2FkZWQnLCBkcmFpbik7CiAgICAgICAgICAgIGVsc2Ugc2V0VGltZW91dChkcmFpbiwgODAwKTsKICAgICAgICAgICAgY29uc3QgaXYgPSBzZXRJbnRlcnZhbChkcmFpbiwgNTAwKTsKICAgICAgICAgICAgc2V0VGltZW91dCgoKSA9PiBjbGVhckludGVydmFsKGl2KSwgMjUwMDApOwogICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICB9CiAgICBzZXR1cEtWQnVmUmVhZGVyKCk7CiAgICAvLyBbdjYtc21hcnRdIE5o4bqtbiB0w61uIGhp4buHdSBTQ1JJUFQgTMOBIHThu6sgcGFnZS1jb250ZXh0IChob29rIFhIUi9mZXRjaCBi4buLIHVzZXJzY3JpcHQvZXh0ZW5zaW9uIGtow6FjIGdoaSDEkcOoKS4KICAgIC8vICAgICAgICAgICAgIFnDqnUgY+G6p3UgMyBs4bqnbiBsacOqbiB04bulYyAo4omIMjRzKSBt4bubaSBr4bq/dCBsdeG6rW4ga2hvw6EgdsSpbmggdmnhu4VuIOKAlCB0csOhbmggbmjhuqdtIGRvIHRyYW5nIHThu7EgaG9vay4KICAgIHRyeSB7CiAgICAgICAgY29uc3QgVVcgPSAodHlwZW9mIHVuc2FmZVdpbmRvdyAhPT0gJ3VuZGVmaW5lZCcpID8gdW5zYWZlV2luZG93IDogd2luZG93OwogICAgICAgIGxldCBfZm9yZWlnblN0cmlrZSA9IDA7CiAgICAgICAgVVcuYWRkRXZlbnRMaXN0ZW5lcignX190bF9mb3JlaWduX2hvb2snLCAoKSA9PiB7CiAgICAgICAgICAgIHRyeSB7IGlmIChVVy5fX2t2X3FfYnVmKSByZXR1cm47IH0gY2F0Y2ggKF8pIHt9IC8vIFt2Ni41LjJdIGxvYWRlciBLZXlWYXVsdCBj4bunYSB0YSDEkWFuZyB3cmFwIFhIUi9mZXRjaCDihpIgYuG7jyBxdWEsIGtow7RuZyBraG/DoSBuaOG6p20KICAgICAgICAgICAgX2ZvcmVpZ25TdHJpa2UrKzsKICAgICAgICAgICAgaWYgKF9mb3JlaWduU3RyaWtlID49IDMgJiYgX2d1YXJkQWN0aXZlKSB7CiAgICAgICAgICAgICAgICBfZW50ZXJSZW1vdGVMb2NrKCfwn5uh77iPIFBow6F0IGhp4buHbiB1c2Vyc2NyaXB0L3Bo4bqnbiBt4buBbSBs4bqhIGNhbiB0aGnhu4dwIHbDoG8ga+G6v3QgbuG7kWkgKMSRw6MgeMOhYyBuaOG6rW4gMyBs4bqnbikuIMSQw6MgYsOhbyBjw6FvIGFkbWluLCBjaOG7nSBt4bufIGtob8OhIHThu6sgeGEuJyk7CiAgICAgICAgICAgIH0KICAgICAgICB9KTsKICAgIH0gY2F0Y2ggKF8pIHt9CgogICAgLy8g4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQCiAgICAvLyDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZAKICAgIC8vICBbdjYuNS4zXSBBTlRJLUZPUkVJR04tVVNFUlNDSVBUIEdVQVJEIOKAlCBwaMOhdCBoaeG7h24gdXNlcnNjcmlwdC9leHRlbnNpb24KICAgIC8vICBraMOhYyBjaOG6oXkgU09ORyBTT05HLCBr4buDIGPhuqMgc2NyaXB0IEtIw5RORyBob29rIFhIUi9mZXRjaCAobOG7lyBo4buVbmcgY+G7p2EgYuG6o24gY8WpOgogICAgLy8gIGLhu5kgZMOyIGPFqSBjaOG7iSBi4bqvdCDEkcaw4bujYyBzY3JpcHQgaG9vayBuYXRpdmU7IHVzZXJzY3JpcHQgY2jhu4kgdGhhbyB0w6FjIERPTS9VSQogICAgLy8gIHRow6wgdsO0IGjDrG5oKS4gQ8ahIGNo4bq/OiBpbmplY3QgcGFnZS1jb250ZXh0IGRldGVjdG9yIHF1w6l0IMSQQSBUw41OIEhJ4buGVSBt4buXaSA2czoKICAgIC8vICAgMSkgTmF0aXZlLWNvZGUgaW50ZWdyaXR5IHRyw6puIGjDoG0gc2NyaXB0IHRhIEtIw5RORyB3cmFwIChzZXRUaW1lb3V0LAogICAgLy8gICAgICBzZXRJbnRlcnZhbCwgZXZhbCwgRnVuY3Rpb24sIGRlZmluZVByb3BlcnR5LCBKU09OLnBhcnNlLCB0b1N0cmluZykKICAgIC8vICAgICAg4oaSIHNjcmlwdCBs4bqhIGhvb2sgY8OhYyBow6BtIG7DoHkgYuG7iyBi4bqvdCAoYuG7mSBjxakgYuG7iyB3aGl0ZWxpc3QgX19rdl9xX2J1ZiBjaGUpLgogICAgLy8gICAyKSBJbmxpbmUgPHNjcmlwdD4gY2jhu6lhIGThuqV1IGhp4buHdSB1c2Vyc2NyaXB0IChHTV8qLCB1bnNhZmVXaW5kb3csCiAgICAvLyAgICAgID09VXNlclNjcmlwdD09LCBAZ3JhbnTigKYpIOKAlCBzY3JpcHQgdGEgaW5qZWN0IGtow7RuZyBjaOG7qWEgbWFya2VyIG7DoHkuCiAgICAvLyAgIDMpIFLDsiBy4buJIEdNIEFQSSByYSBwYWdlIHdpbmRvdyAoR01faW5mbywgR01fKiwgdW5zYWZlV2luZG93LCBfX2dt4oCmKS4KICAgIC8vICAgNCkgR2xvYmFsIG3hu5tpIChmdW5jdGlvbi9vYmplY3QpIHh14bqldCBoaeG7h24gxJDhu4BVIMSQ4bq2TiBzYXUgYmFzZWxpbmUsIOKJpTMgY8OhaS4KICAgIC8vICBbdjYuNS40XSBDSOG6tk4gTkdBWSBs4bqtcCB04bupYzogcGjDoXQgaGnhu4duIHTDrW4gaGnhu4d1IMSR4bqndSB0acOqbiDihpIga2hvw6EgbmdheSwKICAgIC8vICBLSMOUTkcgbWnhu4VuIG5oaeG7hW0gNjBzLCBLSMOUTkcgY+G6p24gMyBzdHJpa2UuIFF1w6l0IGzhuqduIMSR4bqndSBzYXUgMC41cywgbOG6t3AgbeG7l2kgM3MuCiAgICAvLyAgKHY2LjUuMyBjxakgxJHhu6NpIH44MHMg4oaSIGvhursga2jDoWMgdHLhu5ltIGNvZGUvZGF0YSBr4buLcC4gQuG6o24gbsOgeSBjaOG6t24gdHJvbmcgfjNzLikKICAgIC8vIOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkAogICAgKGZ1bmN0aW9uIF9pbml0Rm9yZWlnblVzR3VhcmQoKSB7CiAgICAgICAgdHJ5IHsKICAgICAgICAgICAgbGV0IF9mdXNTdHJpa2UgPSAwOwogICAgICAgICAgICBjb25zdCBVVyA9ICh0eXBlb2YgdW5zYWZlV2luZG93ICE9PSAndW5kZWZpbmVkJykgPyB1bnNhZmVXaW5kb3cgOiB3aW5kb3c7CgogICAgICAgICAgICBVVy5hZGRFdmVudExpc3RlbmVyKCdfX3RsX2ZvcmVpZ25fdXMnLCBmdW5jdGlvbiAoZXZ0KSB7CiAgICAgICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgICAgIGNvbnN0IGQgPSAoZXZ0ICYmIGV2dC5kZXRhaWwpIHx8IHt9OwogICAgICAgICAgICAgICAgICAgIGlmIChkLmNsZWFuKSByZXR1cm47IC8vIFt2Ni41LjRdIENI4bq2TiBOR0FZOiBraMO0bmcgbWnhu4VuIG5oaeG7hW0gNjBzLCBraMO0bmcgY+G6p24gMyBzdHJpa2UKICAgICAgICAgICAgICAgICAgICBfZW50ZXJSZW1vdGVMb2NrKCfwn5uh77iPIFBow6F0IGhp4buHbiB1c2Vyc2NyaXB0L3Bo4bqnbiBt4buBbSBs4bqhIGNo4bqheSBzb25nIHNvbmcgKCcgKyAoZC5zaWcgfHwgJ3Vua25vd24nKSArICcpLiDEkMOjIGNo4bq3biBuZ2F5IGzhuq1wIHThu6ljLCBiw6FvIGPDoW8gYWRtaW4sIGNo4budIG3hu58ga2hvw6EgdOG7qyB4YS4nKTsKICAgICAgICAgICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgICAgIH0pOwoKICAgICAgICAgICAgY29uc3QgY29kZSA9ICcoJyArIGZ1bmN0aW9uICgpIHsKICAgICAgICAgICAgICAgIGlmICh3aW5kb3cuX190bF9mdXNfZ3VhcmQpIHJldHVybjsKICAgICAgICAgICAgICAgIHdpbmRvdy5fX3RsX2Z1c19ndWFyZCA9IHRydWU7CgogICAgICAgICAgICAgICAgLy8gQmFzZWxpbmUgbmF0aXZlIHJlZnMgTkdBWSB04bqhaSBkb2N1bWVudC1zdGFydCDigJQgdHLDoW5oIGtob8OhIG5o4bqnbSBkbyBjaMOtbmggdHJhbmcgdOG7sSB3cmFwIHPhurVuCiAgICAgICAgICAgICAgICB2YXIgX2Jhc2VOYXQgPSB7fTsKICAgICAgICAgICAgICAgIHRyeSB7IF9iYXNlTmF0LnNldFRpbWVvdXQgICAgICAgPSAnJyArIHNldFRpbWVvdXQ7IH0gY2F0Y2ggKGUpIHt9CiAgICAgICAgICAgICAgICB0cnkgeyBfYmFzZU5hdC5zZXRJbnRlcnZhbCAgICAgID0gJycgKyBzZXRJbnRlcnZhbDsgfSBjYXRjaCAoZSkge30KICAgICAgICAgICAgICAgIHRyeSB7IF9iYXNlTmF0LmV2YWwgICAgICAgICAgICAgPSAnJyArIGV2YWw7IH0gY2F0Y2ggKGUpIHt9CiAgICAgICAgICAgICAgICB0cnkgeyBfYmFzZU5hdC5GdW5jdGlvbiAgICAgICAgID0gJycgKyBGdW5jdGlvbjsgfSBjYXRjaCAoZSkge30KICAgICAgICAgICAgICAgIHRyeSB7IF9iYXNlTmF0LmRlZmluZVByb3BlcnR5ICAgPSAnJyArIE9iamVjdC5kZWZpbmVQcm9wZXJ0eTsgfSBjYXRjaCAoZSkge30KICAgICAgICAgICAgICAgIHRyeSB7IF9iYXNlTmF0LkpTT05wYXJzZSAgICAgICAgPSAnJyArIEpTT04ucGFyc2U7IH0gY2F0Y2ggKGUpIHt9CiAgICAgICAgICAgICAgICB0cnkgeyBfYmFzZU5hdC5mblRvU3RyaW5nICAgICAgID0gJycgKyBGdW5jdGlvbi5wcm90b3R5cGUudG9TdHJpbmc7IH0gY2F0Y2ggKGUpIHt9CgogICAgICAgICAgICAgICAgLy8gV2hpdGVsaXN0IGdsb2JhbCBkbyBjaMOtbmggc2NyaXB0IHRhIHThuqFvIHJhIHRyb25nIHBhZ2UgY29udGV4dAogICAgICAgICAgICAgICAgdmFyIE9XTiA9IHsgJ19fdGxfaG9va2VkJzoxLCAnX19rdl9xX2J1Zic6MSwgJ19fdGxfbXlfb3Blbic6MSwgJ19fdGxfbXlfc2VuZCc6MSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICdfX3RsX215X2ZldGNoJzoxLCAnX190bF9sYXN0X3FyZXEnOjEsICdfX3RsX2Z1c19ndWFyZCc6MSB9OwogICAgICAgICAgICAgICAgdmFyIFVTX1JFID0gLz09VXNlclNjcmlwdD09fEBncmFudHxAbWF0Y2h8R01feG1saHR0cFJlcXVlc3R8R01fYWRkU3R5bGV8R01fc2V0VmFsdWV8R01fZ2V0VmFsdWV8R01fcmVnaXN0ZXJNZW51Q29tbWFuZHxHTV9ub3RpZmljYXRpb258R01fY29va2llfEdNX2Rvd25sb2FkfHVuc2FmZVdpbmRvd3xHTV9pbmZvL2k7CiAgICAgICAgICAgICAgICB2YXIgR01fTEVBS19SRSA9IC9eKEdNX3xfX2dtfF9fdShzZXIpP3NjcmlwdCkvaTsKCiAgICAgICAgICAgICAgICBmdW5jdGlvbiBmaXJlKHNpZykgewogICAgICAgICAgICAgICAgICAgIHRyeSB7IHdpbmRvdy5kaXNwYXRjaEV2ZW50KG5ldyBDdXN0b21FdmVudCgnX190bF9mb3JlaWduX3VzJywgeyBkZXRhaWw6IHsgc2lnOiBzaWcsIHQ6IERhdGUubm93KCkgfSB9KSk7IH0gY2F0Y2ggKGUpIHt9CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICBmdW5jdGlvbiBjbGVhbigpIHsKICAgICAgICAgICAgICAgICAgICB0cnkgeyB3aW5kb3cuZGlzcGF0Y2hFdmVudChuZXcgQ3VzdG9tRXZlbnQoJ19fdGxfZm9yZWlnbl91cycsIHsgZGV0YWlsOiB7IGNsZWFuOiB0cnVlLCB0OiBEYXRlLm5vdygpIH0gfSkpOyB9IGNhdGNoIChlKSB7fQogICAgICAgICAgICAgICAgfQoKICAgICAgICAgICAgICAgIC8vIEJhc2VsaW5lIHNuYXBzaG90IGPDoWMgZ2xvYmFsIGhp4buHbiBjw7Mg4oCUIGNo4bqtbSAxNXMgxJHhu4MgcGFnZSArIGZpcmVNb2R1bGUg4buVbiDEkeG7i25oCiAgICAgICAgICAgICAgICB2YXIgYmFzZWxpbmUgPSBudWxsOwogICAgICAgICAgICAgICAgdmFyIHBlbmRpbmcgPSB7fTsgLy8gZ2xvYmFsIG3hu5tpIGzhuqduIMSR4bqndSB0aOG6pXkg4oaSIGNo4budIHjDoWMgbmjhuq1uIOG7nyBs4bqnbiBxdcOpdCBzYXUgKHRyw6FuaCB0cmFuc2llbnQpCiAgICAgICAgICAgICAgICBzZXRUaW1lb3V0KGZ1bmN0aW9uICgpIHsKICAgICAgICAgICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgICAgICAgICBiYXNlbGluZSA9IHt9OwogICAgICAgICAgICAgICAgICAgICAgICBPYmplY3QuZ2V0T3duUHJvcGVydHlOYW1lcyh3aW5kb3cpLmZvckVhY2goZnVuY3Rpb24gKG4pIHsgYmFzZWxpbmVbbl0gPSAxOyB9KTsKICAgICAgICAgICAgICAgICAgICB9IGNhdGNoIChlKSB7fQogICAgICAgICAgICAgICAgfSwgMTUwMDApOwoKICAgICAgICAgICAgICAgIGZ1bmN0aW9uIHNjYW4oKSB7CiAgICAgICAgICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGhpdCA9IG51bGwsIGksIG4sIHY7CgogICAgICAgICAgICAgICAgICAgICAgICAvLyAoMSkgTmF0aXZlIFRIQVkgxJDhu5RJIHNvIHbhu5tpIGJhc2VsaW5lIGRvY3VtZW50LXN0YXJ0ID0gc2NyaXB0IGzhuqEgd3JhcCBTQVUga2hpIHRhIGto4bufaSB04bqhbwogICAgICAgICAgICAgICAgICAgICAgICBpZiAoIWhpdCkgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGN1ciA9IHt9OwogICAgICAgICAgICAgICAgICAgICAgICAgICAgdHJ5IHsgY3VyLnNldFRpbWVvdXQgICAgID0gJycgKyBzZXRUaW1lb3V0OyB9IGNhdGNoIChlKSB7fQogICAgICAgICAgICAgICAgICAgICAgICAgICAgdHJ5IHsgY3VyLnNldEludGVydmFsICAgID0gJycgKyBzZXRJbnRlcnZhbDsgfSBjYXRjaCAoZSkge30KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRyeSB7IGN1ci5ldmFsICAgICAgICAgICA9ICcnICsgZXZhbDsgfSBjYXRjaCAoZSkge30KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRyeSB7IGN1ci5GdW5jdGlvbiAgICAgICA9ICcnICsgRnVuY3Rpb247IH0gY2F0Y2ggKGUpIHt9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0cnkgeyBjdXIuZGVmaW5lUHJvcGVydHkgPSAnJyArIE9iamVjdC5kZWZpbmVQcm9wZXJ0eTsgfSBjYXRjaCAoZSkge30KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRyeSB7IGN1ci5KU09OcGFyc2UgICAgICA9ICcnICsgSlNPTi5wYXJzZTsgfSBjYXRjaCAoZSkge30KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRyeSB7IGN1ci5mblRvU3RyaW5nICAgICA9ICcnICsgRnVuY3Rpb24ucHJvdG90eXBlLnRvU3RyaW5nOyB9IGNhdGNoIChlKSB7fQogICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9yICh2YXIgayBpbiBfYmFzZU5hdCkgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChfYmFzZU5hdFtrXSAmJiBjdXJba10gIT09IF9iYXNlTmF0W2tdKSB7IGhpdCA9ICdob29rZWQgYWZ0ZXIgaW5pdDogJyArIGs7IGJyZWFrOyB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIH0KCiAgICAgICAgICAgICAgICAgICAgICAgIC8vICgyKSBJbmxpbmUgPHNjcmlwdD4gY2jhu6lhIGThuqV1IGhp4buHdSB1c2Vyc2NyaXB0IChzY3JpcHQgdGEgaW5qZWN0IMSRw6MgcmVtb3ZlIG5nYXksIGtow7RuZyBjaOG7qWEgbWFya2VyKQogICAgICAgICAgICAgICAgICAgICAgICBpZiAoIWhpdCkgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHNjcyA9IGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJ3NjcmlwdDpub3QoW3NyY10pJyk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb3IgKGkgPSAwOyBpIDwgc2NzLmxlbmd0aDsgaSsrKSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHQgPSBzY3NbaV0udGV4dENvbnRlbnQgfHwgJyc7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHQubGVuZ3RoID4gODAgJiYgVVNfUkUudGVzdCh0KSkgeyBoaXQgPSAndXNlcnNjcmlwdCBpbmxpbmUgbWFya2VyJzsgYnJlYWs7IH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgfQoKICAgICAgICAgICAgICAgICAgICAgICAgLy8gKDMpIFLDsiBy4buJIEdNIEFQSSAvIHVzZXJzY3JpcHQgcmEgcGFnZSB3aW5kb3cKICAgICAgICAgICAgICAgICAgICAgICAgaWYgKCFoaXQpIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBuYW1lcyA9IE9iamVjdC5nZXRPd25Qcm9wZXJ0eU5hbWVzKHdpbmRvdyk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb3IgKGkgPSAwOyBpIDwgbmFtZXMubGVuZ3RoOyBpKyspIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBuID0gbmFtZXNbaV07CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKE9XTltuXSkgY29udGludWU7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKG4gPT09ICdHTV9pbmZvJyB8fCBuID09PSAndW5zYWZlV2luZG93JyB8fCBHTV9MRUFLX1JFLnRlc3QobikpIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdHJ5IHsgdiA9IHdpbmRvd1tuXTsgaWYgKHR5cGVvZiB2ICE9PSAndW5kZWZpbmVkJykgeyBoaXQgPSAnR00gbGVhazogJyArIG47IGJyZWFrOyB9IH0gY2F0Y2ggKGUpIHt9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgICAgICAgICAvLyAoNCkgR2xvYmFsIG3hu5tpIMSQ4buAVSDEkOG6tk4gc2F1IGJhc2VsaW5lIChwaOG6o2kgbMOgIGZ1bmN0aW9uL29iamVjdCwg4omlMyBjw6FpIG3hu5tpIGvhur90IGx14bqtbikKICAgICAgICAgICAgICAgICAgICAgICAgaWYgKCFoaXQgJiYgYmFzZWxpbmUpIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBjdXIgPSBPYmplY3QuZ2V0T3duUHJvcGVydHlOYW1lcyh3aW5kb3cpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHNlZW5Ob3cgPSB7fTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBjb25maXJtZWQgPSAwOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9yIChpID0gMDsgaSA8IGN1ci5sZW5ndGg7IGkrKykgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG4gPSBjdXJbaV07CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKE9XTltuXSB8fCBiYXNlbGluZVtuXSkgY29udGludWU7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdiA9IHdpbmRvd1tuXTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHR5cGVvZiB2ICE9PSAnZnVuY3Rpb24nICYmICh0eXBlb2YgdiAhPT0gJ29iamVjdCcgfHwgdiA9PT0gbnVsbCkpIGNvbnRpbnVlOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0gY2F0Y2ggKGUpIHsgY29udGludWU7IH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzZWVuTm93W25dID0gMTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAocGVuZGluZ1tuXSkgY29uZmlybWVkKys7ICAgICAgIC8vIMSRw6MgdGjhuqV5IGzhuqduIHRyxrDhu5tjIOKGkiB4w6FjIG5o4bqtbgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UgcGVuZGluZ1tuXSA9IDE7ICAgICAgICAgICAgICAgLy8gbOG6p24gxJHhuqd1IOKGkiBjaOG7nSBs4bqnbiBzYXUKICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvciAodmFyIHBrIGluIHBlbmRpbmcpIHsgaWYgKCFzZWVuTm93W3BrXSkgZGVsZXRlIHBlbmRpbmdbcGtdOyB9IC8vIGThu41uIHRyYW5zaWVudAogICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGNvbmZpcm1lZCA+PSA4KSBoaXQgPSBjb25maXJtZWQgKyAnIG5ldyBwZXJzaXN0ZW50IGdsb2JhbHMnOwogICAgICAgICAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgICAgICAgICBpZiAoaGl0KSBmaXJlKGhpdCk7IGVsc2UgY2xlYW4oKTsKICAgICAgICAgICAgICAgICAgICB9IGNhdGNoIChlKSB7fQogICAgICAgICAgICAgICAgfQoKICAgICAgICAgICAgICAgIC8vIFt2Ni41LjRdIENI4bq2TiBOR0FZOiBxdcOpdCBs4bqnbiDEkeG6p3Ugc2F1IDAuNXMsIGzhurdwIG3hu5dpIDNzIOKAlCBraMO0bmcgxJHhu6NpCiAgICAgICAgICAgICAgICBzZXRUaW1lb3V0KHNjYW4sIDUwMCk7CiAgICAgICAgICAgICAgICBzZXRUaW1lb3V0KGZ1bmN0aW9uICgpIHsgc2V0SW50ZXJ2YWwoc2NhbiwgMzAwMCk7IH0sIDEwMDApOwogICAgICAgICAgICB9ICsgJykoKTsnOwoKICAgICAgICAgICAgY29uc3Qgc0VsID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc2NyaXB0Jyk7CiAgICAgICAgICAgIHNFbC50ZXh0Q29udGVudCA9IGNvZGU7CiAgICAgICAgICAgIChkb2N1bWVudC5oZWFkIHx8IGRvY3VtZW50LmRvY3VtZW50RWxlbWVudCkuYXBwZW5kQ2hpbGQoc0VsKTsKICAgICAgICAgICAgc0VsLnJlbW92ZSgpOwogICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICB9KSgpOwoKICAgIC8vICBTVEFSVFVQIOKAlCB2NC4xOiB0aMOqbSBraeG7g20gdHJhIE9MTSBhY2NvdW50CiAgICAvLyDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZAKICAgIGFzeW5jIGZ1bmN0aW9uIHN0YXJ0dXAoKSB7CiAgICAgICAgLy8gW3Y2LjRdIE7hur91IMSRYW5nIOG7nyByZW1vdGUtbG9jayAoZG8gc2NyaXB0IGzhuqEpIOKGkiBiw6FvIHNlcnZlciArIHBvbGxpbmcgY2jhu50gbeG7nyBraG/DoSwgS0jDlE5HIGNo4bqheSBzY3JpcHQKICAgICAgICBpZiAobG9jYWxTdG9yYWdlLmdldEl0ZW0oJ190bF9yZW1vdGVfbG9ja2VkJykgPT09ICcxJyB8fCBsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgnX3RsX3BvaXNvbmVkJykgPT09ICcxJykgewogICAgICAgICAgICBfZW50ZXJSZW1vdGVMb2NrKCdQaMOhdCBoaeG7h24gcGjhuqduIG3hu4FtIGzhuqEgKMSRw6MgeMOhYyBuaOG6rW4pLiDEkGFuZyBjaOG7nSBhZG1pbiBt4bufIGtob8OhIHThu6sgeGEuJyk7CiAgICAgICAgICAgIHJldHVybjsKICAgICAgICB9CiAgICAgICAgLy8g4pSA4pSA4pSAIFt2NV0gS2jhu59pIHThuqFvIGjhu4cgdGjhu5FuZyBi4bqjbyB24buHIOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgAogICAgICAgIF9pbml0R3VhcmQoKTsKCiAgICAgICAgY29uc3Qgc3RvcmVkS2V5ID0gX3NMUy5nZXQoTFNfS0VZKTsgLy8gW3Y1XSDEkeG7jWMga2V5IMSRw6Mgb2JmdXNjYXRlCiAgICAgICAgY29uc3Qgc3RvcmVkRXhwID0gX3NMUy5nZXQoTFNfRVhQKTsgLy8gW3Y1XQoKICAgICAgICBpZiAoc3RvcmVkS2V5KSB7CiAgICAgICAgICAgIGlmIChzdG9yZWRFeHApIHsKICAgICAgICAgICAgICAgIGNvbnN0IGV4cERhdGUgPSBuZXcgRGF0ZShzdG9yZWRFeHApOwogICAgICAgICAgICAgICAgY29uc3Qgbm93ICAgICA9IG5ldyBEYXRlKCk7CiAgICAgICAgICAgICAgICBpZiAoIWlzTmFOKGV4cERhdGUpICYmIGV4cERhdGUgPCBub3cpIHsKICAgICAgICAgICAgICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShMU19LRVkpOwogICAgICAgICAgICAgICAgICAgIGJ1aWxkTG9ja1NjcmVlbign4o+wIEtleSDEkcOjIGjhur90IGjhuqFuISBWdWkgbMOybmcgbmjhuq1wIGtleSBt4bubaS4nKTsKICAgICAgICAgICAgICAgICAgICByZXR1cm47CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KCiAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgICAvLyBbdjQuMV0gTOG6pXkgT0xNIHVzZXJuYW1lIGhp4buHbiB04bqhaSDEkeG7gyBn4butaSBrw6htIGtoaSB2ZXJpZnkKICAgICAgICAgICAgICAgIGNvbnN0IGN1cnJlbnRPbG0gPSBnZXRPbG1Vc2VybmFtZSgpOwogICAgICAgICAgICAgICAgY29uc3QgciA9IGF3YWl0IGdtUG9zdCgnL3ZlcmlmeScsIHsga2V5OiBzdG9yZWRLZXksIGh3aWQ6IGdldEhXSUQoKSwgb2xtX3VzZXI6IGN1cnJlbnRPbG0gfSk7CgogICAgICAgICAgICAgICAgaWYgKHIuc3VjY2VzcyB8fCByLnZhbGlkKSB7CgogICAgICAgICAgICAgICAgICAgIC8vIOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkAogICAgICAgICAgICAgICAgICAgIC8vIFt2NC4xXSBLSeG7gk0gVFJBIE9MTSBBQ0NPVU5UIE1JU01BVENIIEtISSBTVEFSVFVQCiAgICAgICAgICAgICAgICAgICAgLy8gU2VydmVyIHRy4bqjIHbhu4Egb2xtX3VzZXIgPSB0w6BpIGtob+G6o24gT0xNIGdoaW0gdsOgbyBrZXkKICAgICAgICAgICAgICAgICAgICAvLyBO4bq/dSBraMOhYyB24bubaSB0w6BpIGtob+G6o24gxJFhbmcgxJHEg25nIG5o4bqtcCDihpIgY2jhurduICsgdGjDtG5nIGLDoW8KICAgICAgICAgICAgICAgICAgICAvLyDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZAKICAgICAgICAgICAgICAgICAgICBjb25zdCBzZXJ2ZXJPbG0gPSByLm9sbV91c2VyIHx8IHIub2xtX2FjY291bnQgfHwgJyc7CiAgICAgICAgICAgICAgICAgICAgaWYgKHNlcnZlck9sbSAmJiBjdXJyZW50T2xtICYmIGN1cnJlbnRPbG0gIT09ICdLaG9uZ1hhY0RpbmgnKSB7CiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChzZXJ2ZXJPbG0udG9Mb3dlckNhc2UoKSAhPT0gY3VycmVudE9sbS50b0xvd2VyQ2FzZSgpKSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAvLyBPTE0gYWNjb3VudCBraMOhYyBuaGF1IOKGkiB4w7NhIGtleSB2w6AgeOG7rSBsw70gbWlzbWF0Y2gKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKExTX0tFWSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShMU19UWVBFKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKExTX0VYUCk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBoYW5kbGVPbG1NaXNtYXRjaChzZXJ2ZXJPbG0sIGN1cnJlbnRPbG0pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuOwogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIC8vIOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkAoKICAgICAgICAgICAgICAgICAgICBDVVJSRU5UX0tFWSA9IHN0b3JlZEtleTsKICAgICAgICAgICAgICAgICAgICBLRVlfU1RBVFVTICA9IHsgdmFsaWQ6IHRydWUsIHR5cGU6IHIudHlwZSwgZXhwaXJlc19hdDogci5leHBpcmVzX2F0IH07CiAgICAgICAgICAgICAgICAgICAgX3NMUy5zZXQoTFNfVFlQRSwgci50eXBlICAgICAgICAgfHwgJ1RIVU9ORycpOyAvLyBbdjVdCiAgICAgICAgICAgICAgICAgICAgX3NMUy5zZXQoTFNfRVhQLCAgci5leHBpcmVzX2F0ICAgfHwgJycpOyAgICAgICAvLyBbdjVdCiAgICAgICAgICAgICAgICAgICAgY3JlYXRlVUkoKTsKICAgICAgICAgICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgICAgICAgICAgLy8gW3Y2LjNdIDQwNCA9IGLhu4sgYmFuIElQL3RoaeG6v3QgYuG7iyDihpIgdsOgbyBiYW4tbW9kZSAoR0nhu64ga2V5LCB04buxIG3hu58gbOG6oWkga2hpIGFkbWluIHVuYmFuKQogICAgICAgICAgICAgICAgICAgIGlmIChyICYmIHIuX2h0dHBTdGF0dXMgPT09IDQwNCkgeyBfZW50ZXJCYW5Nb2RlKCdUaGnhur90IGLhu4svSVAgxJHDoyBi4buLIGFkbWluIGtob8OhLicpOyByZXR1cm47IH0KICAgICAgICAgICAgICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShMU19LRVkpOwogICAgICAgICAgICAgICAgICAgIGJ1aWxkTG9ja1NjcmVlbihyLm1lc3NhZ2UgfHwgJ0tleSBraMO0bmcgY8OybiBo4bujcCBs4buHIScpOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9IGNhdGNoIChfKSB7CiAgICAgICAgICAgICAgICBDVVJSRU5UX0tFWSA9IHN0b3JlZEtleTsKICAgICAgICAgICAgICAgIEtFWV9TVEFUVVMgID0geyB2YWxpZDogdHJ1ZSwgdHlwZTogX3NMUy5nZXQoTFNfVFlQRSksIGV4cGlyZXNfYXQ6IHN0b3JlZEV4cCB9OyAvLyBbdjVdCiAgICAgICAgICAgICAgICBjcmVhdGVVSSgpOwogICAgICAgICAgICB9CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgYnVpbGRMb2NrU2NyZWVuKCk7CiAgICAgICAgfQoKICAgICAgICAvLyDilIDilIAgS2nhu4NtIHRyYSBrZXkgxJHhu4tuaCBr4buzIG3hu5dpIDUgcGjDunQgKyBraeG7g20gdHJhIE9MTSBhY2NvdW50IOKUgOKUgAogICAgICAgIHNldEludGVydmFsKGFzeW5jICgpID0+IHsKICAgICAgICAgICAgaWYgKCFDVVJSRU5UX0tFWSkgcmV0dXJuOwogICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgLy8gW3Y0LjFdIEfhu61pIGvDqG0gb2xtX3VzZXIgaGnhu4duIHThuqFpIHRyb25nIG3hu5dpIGzhuqduIGNoZWNrIMSR4buLbmgga+G7swogICAgICAgICAgICAgICAgY29uc3QgY3VycmVudE9sbSA9IGdldE9sbVVzZXJuYW1lKCk7CiAgICAgICAgICAgICAgICBjb25zdCByID0gYXdhaXQgZ21Qb3N0KCcvdmVyaWZ5JywgeyBrZXk6IENVUlJFTlRfS0VZLCBod2lkOiBnZXRIV0lEKCksIG9sbV91c2VyOiBjdXJyZW50T2xtIH0pOwoKICAgICAgICAgICAgICAgIGlmICghKHIuc3VjY2VzcyB8fCByLnZhbGlkKSkgewogICAgICAgICAgICAgICAgICAgIC8vIFt2Ni4zXSA0MDQgPSBi4buLIGJhbiBJUC90aGnhur90IGLhu4sg4oaSIGJhbi1tb2RlIChHSeG7riBrZXksIHThu7EgbeG7nyBs4bqhaSBraGkgYWRtaW4gdW5iYW4pCiAgICAgICAgICAgICAgICAgICAgaWYgKHIgJiYgci5faHR0cFN0YXR1cyA9PT0gNDA0KSB7IF9lbnRlckJhbk1vZGUoJ1RoaeG6v3QgYuG7iy9JUCDEkcOjIGLhu4sgYWRtaW4ga2hvw6EuJyk7IHJldHVybjsgfQogICAgICAgICAgICAgICAgICAgIC8vIEtleSBi4buLIHRodSBo4buTaSAvIGjhur90IGjhuqFuIChraMO0bmcgcGjhuqNpIGJhbikg4oaSIHjhu60gbMO9IG5oxrAgY8WpCiAgICAgICAgICAgICAgICAgICAgY29uc3QgcGFuZWxFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1wYW5lbCcpOwogICAgICAgICAgICAgICAgICAgIGNvbnN0IGZiICAgICAgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtZmxvYXRCdG4nKTsKICAgICAgICAgICAgICAgICAgICBpZiAocGFuZWxFbCkgcGFuZWxFbC5yZW1vdmUoKTsKICAgICAgICAgICAgICAgICAgICBpZiAoZmIpICAgICAgZmIucmVtb3ZlKCk7CiAgICAgICAgICAgICAgICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oTFNfS0VZKTsKICAgICAgICAgICAgICAgICAgICBDVVJSRU5UX0tFWSAgICA9IG51bGw7CiAgICAgICAgICAgICAgICAgICAgX3NlY1Nlc3Npb24gICAgPSB7IHRva2VuOiBudWxsLCBleHA6IDAsIGZwSGFzaDogbnVsbCwgc2VxOiAxIH07CiAgICAgICAgICAgICAgICAgICAgQ1VSUkVOVF9ERVZJQ0UgPSAnJzsKICAgICAgICAgICAgICAgICAgICBzaG93Q3VzdG9tTW9kYWwoewogICAgICAgICAgICAgICAgICAgICAgICBpY29uOiAgJ+KaoO+4jycsCiAgICAgICAgICAgICAgICAgICAgICAgIHRpdGxlOiAnS0VZIMSQw4MgQuG7iiBLSMOTQSEnLAogICAgICAgICAgICAgICAgICAgICAgICBsaW5lczogW3IubWVzc2FnZSB8fCAnS2V5IMSRw6MgYuG7iyB2w7QgaGnhu4d1IGhvw6EhJywgJ1Rvb2wgc+G6vSBi4buLIGtow7NhIG5nYXkgbOG6rXAgdOG7qWMhJ10sCiAgICAgICAgICAgICAgICAgICAgICAgIG9uT2s6ICAoKSA9PiBidWlsZExvY2tTY3JlZW4oci5tZXNzYWdlIHx8ICdLZXkgxJHDoyBi4buLIHbDtCBoaeG7h3UgaG/DoSEnKQogICAgICAgICAgICAgICAgICAgIH0pOwogICAgICAgICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgICAgICAgICAvLyDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZAKICAgICAgICAgICAgICAgICAgICAvLyBbdjQuMV0gS0nhu4JNIFRSQSBPTE0gQUNDT1VOVCBUUk9ORyBQRVJJT0RJQyBDSEVDSwogICAgICAgICAgICAgICAgICAgIC8vIFBow6F0IGhp4buHbiBraGkgdXNlciDEkeG7lWkgdMOgaSBraG/huqNuIE9MTSBsw7pjIHRvb2wgxJFhbmcgY2jhuqF5CiAgICAgICAgICAgICAgICAgICAgLy8g4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQCiAgICAgICAgICAgICAgICAgICAgY29uc3Qgc2VydmVyT2xtID0gci5vbG1fdXNlciB8fCByLm9sbV9hY2NvdW50IHx8ICcnOwogICAgICAgICAgICAgICAgICAgIGlmIChzZXJ2ZXJPbG0gJiYgY3VycmVudE9sbSAmJiBjdXJyZW50T2xtICE9PSAnS2hvbmdYYWNEaW5oJykgewogICAgICAgICAgICAgICAgICAgICAgICBpZiAoc2VydmVyT2xtLnRvTG93ZXJDYXNlKCkgIT09IGN1cnJlbnRPbG0udG9Mb3dlckNhc2UoKSkgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgLy8gT0xNIGFjY291bnQgxJHDoyB0aGF5IMSR4buVaSDihpIga2hvw6EgdG9vbAogICAgICAgICAgICAgICAgICAgICAgICAgICAgaGFuZGxlT2xtTWlzbWF0Y2goc2VydmVyT2xtLCBjdXJyZW50T2xtKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjsKICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAvLyDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZAKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgICB9LCA1ICogNjAgKiAxMDAwKTsKICAgIH0KCiAgICBpZiAoZG9jdW1lbnQucmVhZHlTdGF0ZSA9PT0gJ2xvYWRpbmcnKSB7CiAgICAgICAgZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcignRE9NQ29udGVudExvYWRlZCcsIHN0YXJ0dXApOwogICAgfSBlbHNlIHsKICAgICAgICBzdGFydHVwKCk7CiAgICB9Cgp9KSgpOwo=';
const CONNECTOR_MODULE_VERSION = parseInt(process.env.CONNECTOR_MODULE_VERSION || '4', 10);
let CONNECTOR_MODULE_SRC = process.env.CONNECTOR_MODULE_SRC || '';
if (!CONNECTOR_MODULE_SRC) {
    try {
        const fs = require('fs');
        const p = process.env.CONNECTOR_MODULE_PATH || './connector.module.js';
        CONNECTOR_MODULE_SRC = fs.readFileSync(p, 'utf8');
        console.log('[v8] Đã nạp connector module từ file ' + p + ' (' + CONNECTOR_MODULE_SRC.length + ' bytes)');
    } catch (e) {
        try {
            CONNECTOR_MODULE_SRC = Buffer.from(CONNECTOR_MODULE_EMBEDDED_B64, 'base64').toString('utf8');
            console.log('[v8] Đã nạp connector module từ EMBEDDED base64 (' + CONNECTOR_MODULE_SRC.length + ' bytes) — self-contained.');
        } catch (e2) {
            console.warn('[v8] Lỗi giải mã embedded connector. Loader sẽ nhận code rỗng.');
            CONNECTOR_MODULE_SRC = 'console.warn("[loader] Connector module lỗi trên server.");';
        }
    }
}
function buildConnectorPayload(sessionToken) {
    return encryptAnswers({ src: GM_LEAK_SANITIZER + CONNECTOR_MODULE_SRC, v: CONNECTOR_MODULE_VERSION }, sessionToken);
}
// ══════════════════════════════════════════════════════════════════════════════
//  [v8] STATIC ENCRYPT cho /bootstrap.js — key PBKDF2 từ SECRET (loader tự
//  derive cùng key từ API_SECRET). KHÔNG cần session/key → loader tối thiểu.
//  Định dạng payload: { iv: base64(12B), data: base64(ciphertext + 16B tag) }
//  Loader giải mã bằng WebCrypto AES-GCM (tag nằm ở cuối data).
// ══════════════════════════════════════════════════════════════════════════════
const BOOTSTRAP_SALT = 'tl-bootstrap-v8-salt';
const BOOTSTRAP_ITER = 1000;
function bootstrapDeriveKey() {
    return crypto.pbkdf2Sync(SECRET, BOOTSTRAP_SALT, BOOTSTRAP_ITER, 32, 'sha256');
}
function bootstrapEncrypt(plaintext) {
    const key = bootstrapDeriveKey();
    const iv  = crypto.randomBytes(12);
    const c   = crypto.createCipheriv('aes-256-gcm', key, iv);
    const enc = Buffer.concat([c.update(plaintext, 'utf8'), c.final(), c.getAuthTag()]);
    return { iv: iv.toString('base64'), data: enc.toString('base64') };
}
// [v8] Inject SERVER_BASE = origin của request + API_SECRET = SECRET hiện tại
//      vào code connector → bản phục vụ LUÔN khớp với server (kể cả khi admin
//      đã đổi SECRET qua dashboard).
// [v8.3] GM-LEAK SANITIZER — prepend vao dau connector de xoa GM_* tren window
// do loader cu (Payload_fixed.js) gan vao, truoc khi anti-cheat quet & khoa "PHÁT HIỆN PHẦN MỀM LẠ".
// Connector dung GM_* qua tham so cuc bo (khong qua window) → xoa an toan, giu nguyen chuc nang.
const GM_LEAK_SANITIZER = ";(function(){try{var _wn=Object.getOwnPropertyNames(window);for(var _i=0;_i<_wn.length;_i++){var _n=_wn[_i];if(_n===\"GM_info\"||_n===\"unsafeWindow\"||/^(GM_|__gm|__u(ser)?script)/i.test(_n)){try{delete window[_n];}catch(_){try{window[_n]=undefined;}catch(_){}}}}}catch(_){}})();\n";

// [v9] iOS SHIM: dinh nghia window.__GMFunc__ nhu Proxy tra ve ham no-op -> KHONG bao loi
//      "undefined is not an object (evaluating 'window.__GMFunc__[uuid]')" tren iOS (Userscripts/Safari).
//      Mang that su di qua GM_xmlhttpRequest (fetch bridge) duoc truyen tham so — shim nay chi tranh crash.
const IOS_GMFUNC_SHIM = ";try{if(typeof window!=='undefined'&&!window.__GMFunc__){window.__GMFunc__=new Proxy({},{get:function(t,k){if(k in t)return t[k];return function(){};},set:function(t,k,v){t[k]=v;return true;}});}}catch(_){}\n";
// [v9] OLM BAN POLLING snippet: chen vao cuoi connector — tu dong kiem tra tai khoan OLM dang nhap co bi ban khong,
//      neu co -> hien thi thong bao full-screen manh. Server inject origin + API_PREFIX.
function buildOlmBanSnippet(origin, apiPrefix) {
    var O = JSON.stringify(origin), P = JSON.stringify(apiPrefix);
    var parts = [
        ";try{(function(){",
        "var _o=", O, ",_p=", P, ";",
        "function _olmu(){var u='';var w;try{w=(typeof unsafeWindow!=='undefined')?unsafeWindow:window;}catch(e){w=window;}try{u=w.SESSION&&w.SESSION.meta&&(w.SESSION.meta.id_user||w.SESSION.meta.username||w.SESSION.meta.name)||'';}catch(e){}if(!u){try{u=localStorage.getItem('id_user')||localStorage.getItem('user_id')||localStorage.getItem('olm_user')||localStorage.getItem('username')||'';}catch(e){}}if(!u){try{var el=document.querySelector('.user-name,.username,.account-name,[class*=user-name],[class*=username]');if(el)u=(el.textContent||'').trim();}catch(e){}}return u;}",
        "function _show(m){try{if(document.getElementById('_olmbn_ov'))return;var d=document.createElement('div');d.id='_olmbn_ov';d.style.cssText='position:fixed;inset:0;z-index:2147483647;background:rgba(127,29,29,.97);color:#fff;display:flex;align-items:center;justify-content:center;padding:24px;font-family:system-ui,sans-serif;';var c=document.createElement('div');c.style.cssText='max-width:420px;text-align:center;background:#7f1d1d;border:2px solid #ef4444;border-radius:14px;padding:28px;box-shadow:0 10px 40px rgba(0,0,0,.5);';var t1=document.createElement('div');t1.textContent='🚫';t1.style.cssText='font-size:42px;margin-bottom:12px';var t2=document.createElement('div');t2.textContent='TÀI KHOẢN OLM ĐÃ BỊ CẤM';t2.style.cssText='font-size:18px;font-weight:800;margin-bottom:10px;color:#fca5a5';var t3=document.createElement('div');t3.textContent=String(m||'');t3.style.cssText='font-size:13px;line-height:1.7;color:#fecaca';c.appendChild(t1);c.appendChild(t2);c.appendChild(t3);d.appendChild(c);(document.documentElement||document.body).appendChild(d);}catch(e){}}",
        "function _chk(){var u=_olmu();if(!u)return;try{fetch(_o+_p+'/olm-check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({olm_user:u})}).then(function(r){return r.json();}).then(function(j){if(j&&j.banned){_show(j.message||('Tai khoan OLM bi ban'+(j.permanent?' vinh vien':'')+'. Ly do: '+(j.reason||'')));}}).catch(function(){});}catch(e){}}",
        "setInterval(_chk,30000);setTimeout(_chk,4000);",
        "})();}catch(e){}\n"
    ];
    return parts.join('');
}
function renderConnectorSrc(req) {
    const origin = req.protocol + '://' + req.get('host');
    let src = CONNECTOR_MODULE_SRC;
    src = src.replace(/const SERVER_BASE\s*=\s*'[^']*';/, 'const SERVER_BASE = ' + JSON.stringify(origin) + ';');
    src = src.replace(/const API_SECRET\s*=\s*'[^']*';/,  'const API_SECRET  = ' + JSON.stringify(SECRET) + ';');
    // [v9] them iOS shim (tranh crash __GMFunc__) + OLM ban polling snippet
    return IOS_GMFUNC_SHIM + GM_LEAK_SANITIZER + src + buildOlmBanSnippet(origin, API_PREFIX);
}

// [v8.2] wrapConnectorWithBridge giữ lại để tương thích nhưng KHÔNG làm gì (tránh GM leak).
// Bridge (nếu cần) được truyền làm THAM SỐ cục bộ qua new Function trong buildKvPayloadSrc — không bao giờ gán vào window.
function wrapConnectorWithBridge(src) { return src; }
// [v9] iOS-FIX LOADER: serve loader.user.js tu server — hoan toan fetch-based (KHONG dung
//      window.__GMFunc__ / GM_xmlhttpRequest native) -> chay duoc tren iOS (Userscripts/Safari),
//      fix loi "undefined is not an object (evaluating 'window.__GMFunc__[uuid]')".
//      Flow: keo bootstrap.js -> PBKDF2+AES-GCM giai ma -> chay connector voi GM bridge cuc bo.
function buildLoaderSrc(req) {
    const origin = req.protocol + '://' + req.get('host');
    const SEC = SECRET, AP = API_PREFIX;
    return `// ==UserScript==
// @name         GOD MODE v9 Loader (iOS-FIX, fetch-based)
// @namespace    godmode.v9
// @version      9.0
// @description  Fix loi dang nhap key tren iOS: khong dung window.__GMFunc__ — mang qua fetch (CORS da bat).
// @match        *://*.olm.vn/*
// @match        *://olm.vn/*
// @run-at       document-end
// @grant        none
// ==/UserScript==
;(function(){
  var SERVER_BASE = ${JSON.stringify(origin)};
  var API_PREFIX = ${JSON.stringify(AP)};
  var API_SECRET = ${JSON.stringify(SEC)};
  function _err(m){ try{ var d=document.createElement('div'); d.style.cssText='position:fixed;top:10px;left:10px;z-index:2147483647;background:#7f1d1d;color:#fff;padding:10px 14px;border-radius:8px;font:12px/1.5 monospace;max-width:85%'; d.textContent='GOD MODE: '+(m||''); (document.documentElement||document.body).appendChild(d); setTimeout(function(){try{d.remove();}catch(_){}},8000); }catch(_){} }
  function _b64dec(b64){ var bin=atob(b64); var bytes=new Uint8Array(bin.length); for(var i=0;i<bin.length;i++) bytes[i]=bin.charCodeAt(i); return bytes.buffer; }
  function _gmXhr(d){ d=d||{}; try{ var ctrl=(typeof AbortController!=='undefined')?new AbortController():null; var tmo=setTimeout(function(){if(ctrl)try{ctrl.abort();}catch(_){}}, d.timeout||20000); var opts={method:d.method||'GET',headers:d.headers||{}}; if(ctrl)opts.signal=ctrl.signal; if(d.data!==undefined&&d.data!==null)opts.body=d.data; fetch(d.url,opts).then(function(r){clearTimeout(tmo);return r.text().then(function(t){return{s:r.status,t:t};});}).then(function(o){if(d.onload)d.onload({status:o.s,responseText:o.t,response:o.t,readyState:4});}).catch(function(e){clearTimeout(tmo);if(d.onerror)d.onerror({error:String(e&&e.message||e)});}); }catch(e){ if(d.onerror)d.onerror({error:String(e&&e.message||e)}); } }
  function _gmStyle(css){ try{ var st=document.createElement('style'); st.textContent=css; (document.head||document.documentElement).appendChild(st); }catch(_){} }
  try{ if(typeof window!=='undefined'&&!window.__GMFunc__){ window.__GMFunc__=new Proxy({},{get:function(t,k){if(k in t)return t[k];return function(){};},set:function(t,k,v){t[k]=v;return true;}}); } }catch(_){}
  function _runConnector(src){ try{ (new Function('GM_xmlhttpRequest','GM_addStyle','unsafeWindow', src)).call(window, _gmXhr, _gmStyle, window); }catch(e){ _err('Connector loi: '+(e&&e.message||e)); } }
  async function _boot(){
    try{
      var r = await fetch(SERVER_BASE + API_PREFIX + '/bootstrap.js', {cache:'no-store'});
      if(!r.ok){ if(r.status===404){ _err('Server dang bao tri / script tam khoa (admin da chan keo script).'); } else { _err('Khong keo duoc bootstrap (HTTP '+r.status+')'); } return; }
      var j = await r.json();
      if(!j||!j.ok||!j.payload){ _err('Bootstrap khong hop le.'); return; }
      var enc = new TextEncoder();
      var keyMat = await crypto.subtle.importKey('raw', enc.encode(API_SECRET), 'PBKDF2', false, ['deriveKey']);
      var aesKey = await crypto.subtle.deriveKey({name:'PBKDF2', salt: enc.encode('tl-bootstrap-v8-salt'), iterations: 1000, hash:'SHA-256'}, keyMat, {name:'AES-GCM', length:256}, false, ['decrypt']);
      var iv = _b64dec(j.payload.iv);
      var data = _b64dec(j.payload.data);
      var plain = await crypto.subtle.decrypt({name:'AES-GCM', iv: iv}, aesKey, data);
      var src = new TextDecoder('utf-8').decode(plain);
      _runConnector(src);
    }catch(e){ _err('Loi giai ma bootstrap: '+(e&&e.message||e)); }
  }
  if(document.readyState==='loading'){ document.addEventListener('DOMContentLoaded', _boot); } else { _boot(); }
})();
`;
}

// [v8.2] Tao RAW JS payload de upload len KeyVault (index.js).
// FIX v8.2: bridge GM_xmlhttpRequest/GM_addStyle la BIEN CUC BO trong IIFE,
// tuyet doi KHONG gan vao window (tranh GM leak trigger anti-cheat "PHÁT HIỆN PHẦN MỀM LẠ").
function buildKvPayloadSrc(req) {
    const origin = req.protocol + '://' + req.get('host');
    const connSrc = renderConnectorSrc(req); // da inject SERVER_BASE+API_SECRET, KHONG co bridge
    const connB64 = Buffer.from(connSrc, 'utf8').toString('base64');
    return `/* ============================================================
   GOD MODE v8.2 — KEYVAULT-COMPATIBLE PAYLOAD (cho server index.js)
   Upload noi dung JS nay len KeyVault (trang "Nap file code").
   [v8.2] FIX: bridge GM_* la bien cuc bo, KHONG leak ra window ->
   khong con bi anti-cheat "PHÁT HIỆN PHẦN MỀM LẠ (GM leak: GM_addStyle)" khoa.
   Server goc: ${origin}
   ============================================================ */
;(function(){
  if (window.__tl_kv_payload_v82) return;
  window.__tl_kv_payload_v82 = 1;
  function __tlFail(msg){
    console.error('[TL-KV]', msg);
    try {
      var d=document.createElement('div');
      d.style.cssText='position:fixed;top:8px;left:8px;z-index:2147483647;background:#7f1d1d;color:#fff;padding:8px 12px;border-radius:8px;font:12px/1.4 monospace;max-width:85%;box-shadow:0 4px 12px rgba(0,0,0,.4)';
      d.textContent='Tool loi: '+(msg||'');
      (document.documentElement||document.body).appendChild(d);
      setTimeout(function(){ try{d.remove();}catch(_){} }, 7000);
    } catch(_){}
  }
  try {
    /* [v8.2] BRIDGE CUC BO — KHONG gan vao window (tranh GM leak).
       Neu chay trong userscript sandbox that, GM_xmlhttpRequest/GM_addStyle co san.
       Neu chay trong page context (KeyVault), dung ban thay the qua fetch (server da bat CORS). */
    var __uw = (typeof unsafeWindow !== 'undefined') ? unsafeWindow : window;
    var __gmStyle = (typeof GM_addStyle !== 'undefined') ? GM_addStyle : function(css){ try { var s=document.createElement('style'); s.textContent=css; (document.head||document.documentElement).appendChild(s); } catch(_){} };
    var __gmXhr = (typeof GM_xmlhttpRequest !== 'undefined') ? GM_xmlhttpRequest : function(d){
      d = d || {};
      try {
        var ctrl = (typeof AbortController !== 'undefined') ? new AbortController() : null;
        var tmo = setTimeout(function(){ if (ctrl) try{ ctrl.abort(); }catch(_){} }, d.timeout || 20000);
        var opts = { method: d.method || 'GET', headers: d.headers || {} };
        if (ctrl) opts.signal = ctrl.signal;
        if (d.data !== undefined && d.data !== null) opts.body = d.data;
        fetch(d.url, opts).then(function(r){
          clearTimeout(tmo);
          return r.text().then(function(t){ return { s: r.status, t: t }; });
        }).then(function(o){
          if (d.onload) d.onload({ status: o.s, responseText: o.t, response: o.t, readyState: 4 });
        }).catch(function(e){
          clearTimeout(tmo);
          if (d.onerror) d.onerror({ error: String(e && e.message || e) });
        });
      } catch(e){ if (d.onerror) d.onerror({ error: String(e && e.message || e) }); }
    };
    var __b64 = "${connB64}";
    var bin = atob(__b64);
    var bytes = new Uint8Array(bin.length);
    for (var i=0;i<bin.length;i++) bytes[i]=bin.charCodeAt(i);
    var __src = new TextDecoder('utf-8').decode(bytes);
    /* Truyen GM_* lam THAM SO cuc bo — KHONG leak ra window. Anti-cheat khong phat hien. */
    (new Function('GM_xmlhttpRequest','GM_addStyle','unsafeWindow', __src)).call(window, __gmXhr, __gmStyle, __uw);
  } catch(e) {
    __tlFail(e && e.message ? e.message : String(e));
  }
})();
`;
}


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
// [v10] ===== DUMPER_GUARD helpers =====
function keyAct(key){ if(!key) return {processCount:0,fireCount:0,moduleFetchCount:0,hbZeroCount:0,dumpScore:0,firstAttestAt:0,lastModuleAt:0}; let r=keyActivity.get(key); if(!r){r={firstAttestAt:0,lastModuleAt:0,moduleFetchCount:0,processCount:0,fireCount:0,hbZeroCount:0,dumpScore:0}; keyActivity.set(key,r);} return r; }
function isKeyBanned(key){ return key ? BANNED_KEYS.has(String(key).trim().toUpperCase()) : false; }
function addKeyBan(key, reason, ip, hwid, deviceName){ if(!key) return false; const k=String(key).trim().toUpperCase(); if(BANNED_KEYS.has(k)) return false; if(SMART_BAN && isRealMobileDevice(ip, hwid, recentUaByIp.get(ip) || '')){ adminLog('key-ban-blocked-real',{ key: maskKey(key), reason, ip, hwid, device: deviceName||'', note:'SMART_BAN: thiet bi di dong that, khong revokle key' }); return false; } if(!SMART_BAN && SAFE_MODE){ adminLog('key-ban-soft',{ key: maskKey(key), reason, ip, hwid, device: deviceName||'', note:'SAFE_MODE: khong revokle key, chi log' }); return false; } BANNED_KEYS.add(k); kvSaveState(); addBan(ip, hwid, reason + ' — key bi revokle', deviceName); adminLog('key-ban', { key: maskKey(key), reason, ip, hwid, device: deviceName || '' }); return true; }
// Ghi su kien va tra ve ly do ban (null = hop le). event: attest|process|fire|heartbeat-zero|module
function dumperJudge(key, hwid, ip, deviceName, event){
    if(!DUMPER_GUARD || !key) return null;
    const r = keyAct(key);
    const now = Date.now();
    if(event==='attest'){ if(!r.firstAttestAt) r.firstAttestAt=now; return null; }
    if(event==='process'){ r.processCount++; if(r.dumpScore>0) r.dumpScore=Math.max(0,r.dumpScore-2); return null; }
    if(event==='fire'){ r.fireCount++; r.dumpScore=0; return null; } // co hoat dong thuc -> reset nghi ngo
    if(event==='heartbeat-zero'){ if(r.processCount===0 && r.fireCount===0){ r.hbZeroCount++; r.dumpScore+=1; if(r.hbZeroCount>=5) return 'heartbeat zero-version >=5 lan va KHONG co hoat dong process/fire — chi co dumper'; } return null; }
    if(event==='module'){
        r.moduleFetchCount++; r.lastModuleAt=now;
        if(r.moduleFetchCount>=2) return 'lay module truc tiep >=2 lan — nghi dump file';
        if(r.processCount===0 && r.fireCount===0) return 'goi /module nhung chua tung process/fire lan nao — dumper khong co hoat dong thuc';
        if(r.firstAttestAt && (now - r.firstAttestAt) < 10000) return 'attest -> lay module trong vong <10s, khong co hoat dong thuc — dumper';
        return null;
    }
    return null;
}
// [v10] Watermark: dam trace duy nhat moi key+hwid -> leak dump la tim duoc nguoi mua
function watermarkSrc(src, key, hwid){
    if(!MODULE_WATERMARK || !key) return src;
    const wm = hmacHex('wm:' + String(key).trim().toUpperCase() + ':' + (hwid||'')).slice(0, 16);
    return 'var _tlwm="' + wm + '";\n' + src;
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
// [v10.1] CHAN KEO SCRIPT VIOLENTMONKEY: MAC DINH TAT (kill-switch) — admin chu dong BAT trong panel de chan hoan toan viec keo code
let BLOCK_VM_SCRIPT = process.env.BLOCK_VM_SCRIPT === 'true'; // [v10.1] mac dinh TAT — day la kill-switch, admin chu dong BAT khi can chan tong keo code
// [v10] CHAN MODULE "CHUAN BI 10 DIEM": MAC DINH BAT (theo yeu cau) — admin co the TAT trong panel
let BLOCK_MODULE_10 = process.env.BLOCK_MODULE_10 !== 'false';
// [v10] HARD_DC_BAN: IP datacenter/proxy/VPN goi bat ky API nao -> BAN NGAY (mac dinh BAT)
let HARD_DC_BAN = process.env.HARD_DC_BAN === 'true'; // [v13] mac dinh TAT (kill-switch) — admin chu dong BAT trong panel
// [v13] SAFE_MODE: mac dinh BAT — auto-ban chi ghi log + tu choi (403), KHONG khoa vinh vien.
//       Chi admin ban thu cong (set truc tiep vao `banned`) moi co hieu luc. Tat = env SAFE_MODE=false.
let SAFE_MODE = process.env.SAFE_MODE !== 'false';
// [v14] SMART_BAN: mac dinh BAT — chi ban may ao/server/proxy ao xac nhan; may that Android/iOS khong bao gio ban + tu mo ban.
let SMART_BAN = process.env.SMART_BAN !== 'false';
const realDevices = new Map(); // hwid -> {ip, deviceName, firstSeen, lastSeen} — thiet bi di dong that da xac thuc (KHONG bao gio bi ban)
let autoUnbanCount = 0; // [v14] dem so lan tu mo ban thiet bi that
const realIps = new Set(); // [v15] IP cua thiet bi di dong that (khong can hwid) — tu mo ban + khong ban lai
const recentUaByIp = new Map(); // [v16] ip -> UA gan nhat; giup guard ban nhan dien mobile that ca truoc khi attest
// [v10] DUMPER_GUARD: phat hien hanh vi dumper -> BAN key+hwid+ip (mac dinh BAT)
let DUMPER_GUARD = process.env.DUMPER_GUARD !== 'false';
// [v10] MODULE_WATERMARK: dam trace duy nhat moi key+hwid vao module (mac dinh BAT)
let MODULE_WATERMARK = process.env.MODULE_WATERMARK !== 'false';
// [v10] BANNED_KEYS: key bi ro ri/dump -> revokle vinh vien. env BANNED_KEYS=K1,K2 hoac admin khoa.
const BANNED_KEYS = new Set((process.env.BANNED_KEYS || '').split(',').map(s => String(s).trim().toUpperCase()).filter(Boolean));
// [v10] keyActivity: theo doi hoat dong moi key de phat hien dumper (in-memory, du cho viec phat hien theo phien)
const keyActivity = new Map();
// [v10] TRACK HOAT DONG thiet bi: hwid -> {olm_user, id_cate, mode, id_user, device, ip, lastSeen}
const deviceActivity = new Map();
function trackDevice(hwid, data){ if(!hwid) return; const ex = deviceActivity.get(hwid) || {}; deviceActivity.set(hwid, Object.assign(ex, data, { lastSeen: Date.now() })); } // mac dinh TAT (keo binh thuong)
// [v9] BAN TAI KHOAN OLM: key=olm_user lowercase -> {reason, until:null=vinh vien|timestamp_ms, t, by}
const olmBans = new Map();
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
            if (st && typeof st.blockVmScript === 'boolean') BLOCK_VM_SCRIPT = st.blockVmScript;
            if (st && typeof st.blockModule10 === 'boolean') BLOCK_MODULE_10 = st.blockModule10;
            if (st && typeof st.hardDcBan === 'boolean') HARD_DC_BAN = st.hardDcBan;
            if (st && typeof st.safeMode === 'boolean') SAFE_MODE = st.safeMode;
            if (st && typeof st.smartBan === 'boolean') SMART_BAN = st.smartBan;
            if (st && st.realDevices) for (const [_k, _v] of Object.entries(st.realDevices)) realDevices.set(_k, _v);
            if (st && Array.isArray(st.realIps)) st.realIps.forEach(x => realIps.add(x));
            if (st && typeof st.dumperGuard === 'boolean') DUMPER_GUARD = st.dumperGuard;
            if (st && typeof st.moduleWatermark === 'boolean') MODULE_WATERMARK = st.moduleWatermark;
            if (st && Array.isArray(st.bannedKeys)) st.bannedKeys.forEach(k => BANNED_KEYS.add(String(k).toUpperCase()));
            if (st && st.olmBans) for (const [k, v] of Object.entries(st.olmBans)) olmBans.set(String(k).toLowerCase(), v);
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
            autoBan: AUTO_BAN, mobileOnly: MOBILE_ONLY, banDesktop: BAN_DESKTOP, blockVmScript: BLOCK_VM_SCRIPT, blockModule10: BLOCK_MODULE_10,
            hardDcBan: HARD_DC_BAN, dumperGuard: DUMPER_GUARD, moduleWatermark: MODULE_WATERMARK, safeMode: SAFE_MODE, smartBan: SMART_BAN, realDevices: Object.fromEntries(realDevices), realIps: Array.from(realIps), bannedKeys: Array.from(BANNED_KEYS),
            olmBans: Object.fromEntries(olmBans),
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
// [v14] SMART_BAN helpers — may that Android/iOS KHONG bao gio bi ban
function isRealMobileDevice(ip, hwid, uaHeader){
    if (!SMART_BAN) return false;
    const ua = String(uaHeader || '').toLowerCase();
    // UA mobile (Android/iOS that) -> coi la that, khong bao gio ban (uu tien nhat theo yeu cau)
    if (/android|iphone|ipad|ipod/.test(ua)) return true;
    // HWID da tung attest thanh cong -> chac chan that
    if (hwid && realDevices.has(String(hwid))) return true;
    // [v15] IP da nhan dien la thiet bi that (da gap truoc, ke ca IP chua co hwid) -> that
    if (ip && realIps.has(ip)) return true;
    // IP trung voi IP cua thiet bi that da biet (CGNAT chung IP) -> that
    if (ip) { for (const v of realDevices.values()) if (v.ip === ip) return true; }
    return false;
}
function autoUnbanIfReal(ip, hwid, uaHeader, reason){
    if (!SMART_BAN) return false;
    if (!isRealMobileDevice(ip, hwid, uaHeader)) return false;
    // [v15] Ghi nhan IP that (ke ca khi chua co hwid) de request sau tu nhan dien; luon xoa cache IP nham
    if (ip) { realIps.add(ip); if (ipCache.has(ip)) ipCache.delete(ip); }
    let removed = 0;
    if (ip && banned.has('ip:' + ip)) { banned.delete('ip:' + ip); removed++; }
    if (hwid && banned.has('dev:' + String(hwid))) { banned.delete('dev:' + String(hwid)); removed++; }
    if (removed > 0) {
        autoUnbanCount += removed;
        kvSaveState();
        adminLog('auto-unban', { ip, hwid, reason, removed, total: autoUnbanCount });
    }
    return removed > 0;
}
// [v15] Goi o dau moi route: thiet bi that tu mo ban IP/HWID ngay, khong can admin thao tac
function unlockReal(req, ip, hwid, source){
    if (!SMART_BAN) return;
    autoUnbanIfReal(ip, hwid, req.headers && req.headers['user-agent'], source);
    softUnbanReal(req, ip, hwid, 'unlock:' + source);
}
// [v17] UA co dau hieu Android/iOS that (khong phu thuoc Map da hoc) -> coi la thiet bi that
function uaIsMobile(uaHeader) {
    return /android|iphone|ipad|ipod|harmonyos|crios|fxios|mobile safari/i.test(String(uaHeader || '').toLowerCase());
}
// [v17] Thiet bi that: UA mobile, hoac HWID/IP da nam trong s registry that
function realMobileReq(req, hwid) {
    const ua = req && req.headers ? req.headers['user-agent'] : '';
    if (uaIsMobile(ua)) return true;
    if (hwid && realDevices.has(String(hwid))) return true;
    const ip = req ? getClientIp(req) : '';
    if (ip && realIps.has(ip)) return true;
    return false;
}
// [v17] Go ban thong minh cho may that: luu IP that, xoa cache IP nham, golo ip/dev ban
function softUnbanReal(req, ip, hwid, reason) {
    if (!SMART_BAN) return false;
    if (!realMobileReq(req, hwid)) return false;
    if (ip) { realIps.add(ip); if (ipCache.has(ip)) ipCache.delete(ip); }
    let removed = 0;
    if (ip && banned.has('ip:' + ip)) { banned.delete('ip:' + ip); removed++; }
    if (hwid && banned.has('dev:' + String(hwid))) { banned.delete('dev:' + String(hwid)); removed++; }
    if (removed > 0) {
        autoUnbanCount += removed;
        kvSaveState();
        adminLog('auto-unban-v17', { ip, hwid, reason, removed });
    }
    return true;
}
// [v17] Guard thay cho 404 "Not found" tren moi route API: may that tu mo khoa; con lai tra 403 co message
function guardBanned(req, res, ip, hwid, label) {
    if (softUnbanReal(req, ip, hwid, 'guard:' + label)) return false;
    const b = isBanned(ip, hwid);
    if (!b) return false;
    res.status(403).json({ success: false, blocked: true, message: 'Thiết bị/IP đang bị khoá (' + (b.reason || label) + ') — thiết bị thật Android/iOS sẽ tự mở khoá ở request kế tiếp.', reason: b.reason || '' });
    return true;
}
// [v17] Key bi thu hoi: may that tra 401 co thong bao; may gia moi ban + 404
function keyBlocked(req, res, key, ip, hwid, deviceName, label) {
    if (!isKeyBanned(key)) return false;
    if (realMobileReq(req, hwid)) {
        adminLog('key-blocked-real-soft', { key: maskKey(key), ip, hwid, label });
        res.status(401).json({ success: false, message: 'Key đã bị thu hồi (dump/rò rỉ) — liên hệ admin để cấp key mới.', reason: 'key_revoked' });
        return true;
    }
    addBan(ip, hwid, 'key revokle (' + label + ')', deviceName || '');
    res.status(404).json({ error: 'Not found' });
    return true;
}
function addBan(ip, hwid, reason, deviceName) {
    // [v14] SMART_BAN: neu la thiet bi di dong that -> TU CHOI ban + tu mo ban neu dang bi khoa
    if (SMART_BAN && isRealMobileDevice(ip, hwid, recentUaByIp.get(ip) || '')) {
        autoUnbanIfReal(ip, hwid, '', 'addBan-attempt-on-real-device');
        adminLog('ban-blocked-real', { ip, hwid, reason, device: deviceName || '', note: 'SMART_BAN: thiet bi di dong that, KHONG ban' });
        return;
    }
    // [v13] SAFE_MODE: chi ap dung khi SMART_BAN dang TAT (SMART_BAN on thi ban binh thuong voi may ao/proxy xac nhan)
    if (!SMART_BAN && SAFE_MODE) { adminLog('ban-soft', { ip, hwid, reason, device: deviceName || '', note: 'SAFE_MODE: khong ban cung, chi tu choi' }); return; }
    if (ip) banned.set('ip:' + ip, { reason, device: deviceName || '', t: Date.now(), by: 'auto' });
    if (hwid) banned.set('dev:' + hwid, { reason, device: deviceName || '', t: Date.now(), by: 'auto', ip });
    kvSaveState();
    adminLog('ban', { ip, hwid, reason, device: deviceName || '' });
}
function removeBan(key) { banned.delete(key); kvSaveState(); }
// [v9] ===== OLM ACCOUNT BAN helpers =====
function normOlm(u){ return String(u || '').trim().toLowerCase(); }
function addOlmBan(olm, minutes, reason, by){
    const k = normOlm(olm); if (!k) return false;
    const mins = Number(minutes);
    const until = (minutes === -1 || minutes === '-1' || minutes === 'permanent' || isNaN(mins) || mins <= 0) ? null : Date.now() + Math.floor(mins) * 60 * 1000;
    olmBans.set(k, { reason: String(reason || 'vi pham').slice(0, 200), until, t: Date.now(), by: by || 'admin' });
    kvSaveState(); return true;
}
function removeOlmBan(olm){ const k = normOlm(olm); const had = olmBans.has(k); olmBans.delete(k); if (had) kvSaveState(); return had; }
function checkOlmBan(olm){
    const k = normOlm(olm); if (!k) return null;
    const b = olmBans.get(k); if (!b) return null;
    if (b.until && b.until < Date.now()) { olmBans.delete(k); kvSaveState(); return null; } // het han -> tu go
    let remain = '';
    if (b.until) {
        const ms = Math.max(0, b.until - Date.now());
        const d = Math.floor(ms / 86400000), h = Math.floor((ms % 86400000) / 3600000), m = Math.max(0, Math.floor((ms % 3600000) / 60000));
        remain = (d ? d + ' ngay ' : '') + (h ? h + 'h ' : '') + m + 'p';
    }
    return { banned: true, reason: b.reason, until: b.until, permanent: !b.until, remain, t: b.t, by: b.by };
}
function fmtOlmRemain(b){ if (!b) return ''; return b.permanent ? 'VINH VIEN' : (b.remain || 'con hieu luc'); }
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
// [v9] FIX chong fake IP: lay IP CUOI CUNG trong X-Forwarded-For (proxy tin cay them vao),
//      validate dinh dang de tranh inject. Client co the them entry dau tien nhung khong bao gio
//      thay duoc entry cuoi -> ban/rate-limit khong the ne.
function getClientIp(req) {
    const fwdAll = (req.headers['x-forwarded-for'] || '').split(',').map(x => x.trim()).filter(Boolean);
    let ip = '';
    if (req.ip && req.ip !== '::' && req.ip !== '::ffff:0.0.0.0') ip = req.ip;
    else if (fwdAll.length) ip = fwdAll[0];
    else ip = (req.socket && req.socket.remoteAddress) || '';
    ip = String(ip).replace(/^::ffff:/, '');
    if (!/^[0-9a-fA-F:.]{3,45}$/.test(ip)) ip = '';
    return ip;
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
    if (ip && req.headers['user-agent']) recentUaByIp.set(ip, String(req.headers['user-agent'])); // [v16]
    const isLoopback = ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';
    // Đã bị ban → trả 404 trơn (không tiết lộ). [v14] Nhưng nếu là thiết bị di động thật → TỰ ĐỘNG MỞ BAN ngay.
    if (isBanned(ip, req.headers['x-hwid'])) {
        if (!autoUnbanIfReal(ip, req.headers['x-hwid'], req.headers['user-agent'], 'middleware-banned-real-device')
            && !softUnbanReal(req, ip, req.headers['x-hwid'], 'middleware-banned-real-device-v17')) {
            return res.status(403).json({ success: false, error: 'Not found', message: 'Thiết bị/IP đang bị khoá — thiết bị thật sẽ tự mở khoá ở request kế tiếp.' });
        }
    }
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
// [v14] SMART_BAN: quet dinh ky 5 phut — tu go ban cua moi IP/HWID thuoc thiet bi di dong that
setInterval(() => {
    if (!SMART_BAN) return;
    const realIps = new Set();
    for (const v of realDevices.values()) realIps.add(v.ip);
    let removed = 0;
    for (const k of [...banned.keys()]) {
        let isReal = false;
        if (k.startsWith('ip:')) { const ip = k.slice(3); if (realIps.has(ip)) { isReal = true; ipCache.delete(ip); } }
        else if (k.startsWith('dev:')) { if (realDevices.has(k.slice(4))) isReal = true; }
        if (isReal) { banned.delete(k); removed++; }
    }
    if (removed > 0) { autoUnbanCount += removed; kvSaveState(); adminLog('auto-unban-sweep', { removed, total: autoUnbanCount, realDevices: realDevices.size }); }
}, 5 * 60 * 1000).unref();
function sha256Hex(buf) { return crypto.createHash('sha256').update(buf).digest('hex'); }
function verifyReqSig(req) {
    if (!REQ_SIGN) return true;
    const ts = req.headers['x-ts'], nonce = req.headers['x-nonce'], sign = req.headers['x-sign'];
    // [v6.5.2] SOFT: thiếu chữ ký (script cũ / đã mã hoá obfuscator chưa ký) → cho qua + ghi log.
    //          Có chữ ký nhưng SAI → chặn (chống fake/tamper). Client mới luôn ký đúng.
    if (!ts || !nonce || !sign) { if (/\/module$/.test(req.path)) { adminLog('sig-missing-hard', { ip: getClientIp(req), path: req.path }); return false; } adminLog('sig-missing', { ip: getClientIp(req), path: req.path }); return true; }
    const tsNum = parseInt(ts, 10);
    if (isNaN(tsNum) || Math.abs(Math.floor(Date.now() / 1000) - tsNum) > 15) return false; // [v10] 30s->15s chong replay
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
// [v11] Global rate-limit per-IP chong scan/dumper (120 req/phut — connector that <30)
app.use((req, res, next) => {
    const ip = getClientIp(req);
    if (isLoopbackIp(ip) || ALLOW_LIST.includes(ip)) return next();
    if (!rateLimit('g:' + ip, 300, 60000)) { adminLog('ratelimit-global', { ip, path: req.path, ua: String(req.headers['user-agent'] || '').slice(0, 50) }); return res.status(429).json({ error: 'Too many requests' }); }
    next();
});
// [v10] HARD_DC_BAN: IP datacenter/proxy ĐÃ BIẾT (cache) gọi bất kỳ API nào → BAN NGAY, không xử lý tiếp
app.use(async (req, res, next) => {
    if (!HARD_DC_BAN || !req.path.startsWith(API_PREFIX)) return next();
    const ip = getClientIp(req);
    if (isLoopbackIp(ip) || ALLOW_LIST.includes(ip)) return next();
    const hit = ipCache.get(ip);
    if (hit && hit.expire > Date.now() && hit.info && hit.info.risk === 'high' && hit.info.isDC && hit.info.isVPN) {
        // [v17] UA mobile that (Android/iOS) LUON bo qua, ke ca khi SMART_BAN tat hoac cache nham
        if (uaIsMobile(req.headers['user-agent']) || (SMART_BAN && isRealMobileDevice(ip, null, req.headers['user-agent']))) {
            autoUnbanIfReal(ip, null, req.headers['user-agent'], 'dc-cache-real-mobile');
            softUnbanReal(req, ip, null, 'dc-cache-real-mobile-v17');
            adminLog('dc-skip-real', { ip, org: hit.info.org || '' });
            return next();
        }
        addBan(ip, null, 'IP datacenter/proxy goi API (HARD_DC_BAN) — ' + (hit.info.org || ''), '');
        adminLog('dc-ban', { ip, org: hit.info.org || '', country: hit.info.country || '' });
        return res.status(403).json({ success: false, error: 'Not found', message: 'Mạng datacenter/proxy bị chặn.' });
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
// [v11] checkProxyIp v2: ipapi.is chinh + fallback ip-api.com; that bai -> cache 60s (thu lai som), co co 'degraded'
function checkProxyIp(ip) {
    return new Promise((resolve) => {
        if (!ip || ALLOW_LIST.includes(ip)) return resolve({ risk: 'low' });
        const hit = ipCache.get(ip);
        if (hit && hit.expire > Date.now()) return resolve(hit.info);
        const done = (info, ttlMs) => { ipCache.set(ip, { info, expire: Date.now() + (ttlMs || 3600000) }); resolve(info); };
        // fail-open an toan (tranh ban nham nha mang di dong CGNAT) nhung cache 60s de thu lai som
        const finishFail = (note) => done({ risk: 'low', degraded: true, note }, 60000);
        const parseIpApiIs = (raw) => {
            try {
                const j = JSON.parse(raw);
                const org = String((j.asn && j.asn.org) || (j.company && j.company.name) || '').toLowerCase();
                const isDC = !!(j.is_datacenter || (j.company && j.company.type === 'hosting'));
                const isVPN = !!(j.is_vpn || j.is_proxy || j.is_tor || j.is_abuser);
                const kw = DC_KEYWORDS.some(k => org.includes(k));
                // [v17] Nha mang di dong that (Viettel/Vinaphone/Mobifone/FPT/Gtel...) -> luon low, khong chan/ban
                const CARRIER_RE = /viettel|vinaphone|mobifone|fpt|vietnamobile|gtel|vietnam postal|hanoi telecom|sai gon|carrier|cellular|mobile network|telecom/i;
                if (CARRIER_RE.test(org)) {
                    return { risk: 'low', carrier: true, isMobile: true, isDC, isVPN, country: (j.location && j.location.country_code) || '', org };
                }
                // [v13] Chi risk=high khi CA datacenter LAN co proxy/VPN/keyword.
                return { risk: (isDC && (isVPN || kw)) ? 'high' : 'low', isDC, isVPN, country: (j.location && j.location.country_code) || '', org };
            } catch (_) { return null; }
        };
        const fallback = () => {
            const r2 = http.get(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,country,org,isp,proxy,hosting,mobile`, { timeout: 3000 }, (resp) => {
                let raw = ''; resp.on('data', c => raw += c); resp.on('end', () => {
                    try {
                        const j = JSON.parse(raw);
                        if (j && j.status === 'success') {
                            const org = String(j.isp || j.org || '').toLowerCase();
                            const isDC = !!j.hosting;
                            const isVPN = !!j.proxy;
                            const isMobile = !!j.mobile; // [v13] ip-api tra mobile=true voi nha mang di dong
                            const kw = DC_KEYWORDS.some(k => org.includes(k));
                            const CARRIER_RE2 = /viettel|vinaphone|mobifone|fpt|vietnamobile|gtel|vietnam postal|hanoi telecom|sai gon|carrier|cellular|mobile|telecom/i;
                            // [v13] Neu la mobile carrier (nha mang di dong that) -> force risk=low, KHONG bao gio ban/chan.
                            if (isMobile || CARRIER_RE2.test(org)) { done({ risk: 'low', isMobile: true, carrier: true, isDC, isVPN, country: j.country || '', org }); return; }
                            // [v13] Chi risk=high khi CA datacenter LAN co proxy/VPN/keyword (tranh nham carrier IP).
                            done({ risk: (isDC && (isVPN || kw)) ? 'high' : 'low', isDC, isVPN, country: j.country || '', org });
                        } else { finishFail('fallback-fail'); }
                    } catch (_) { finishFail('fallback-parse'); }
                });
            });
            r2.on('error', () => finishFail('fallback-error'));
            r2.on('timeout', () => { r2.destroy(); finishFail('fallback-timeout'); });
        };
        const req = https.get(`https://api.ipapi.is/?q=${encodeURIComponent(ip)}`, { timeout: 4000 }, (r) => {
            let raw = ''; r.on('data', c => raw += c); r.on('end', () => {
                const info = parseIpApiIs(raw);
                if (info) done(info); else fallback();
            });
        });
        req.on('error', () => fallback());
        req.on('timeout', () => { req.destroy(); fallback(); });
    });
}

// ══════════════════════════════════════════════════════════════════════════════
//  PHÁT HIỆN THIẾT BỊ THẬT (Android/iOS) — máy ảo/emulator/trình duyệt giả → BAN
//  Trả về: { ok, ban (bool), reason, deviceName }
// ══════════════════════════════════════════════════════════════════════════════
// [FIX v8.1] Bỏ sm-n976n / sm-g977n — đây là máy Samsung Galaxy THẬT (Note10+ 5G / S10 5G),
//            trước đây bị nhầm là emulator marker → ban nhầm người dùng thật.
const EMU_MARKERS = ['emulator', 'sdk built for', 'genymotion', 'bluestacks', 'nox', 'ldplayer', 'memu',
    'andy', 'droid4x', 'ipadian', 'windroy', 'youwave', 'leapdroid', 'koplayer', 'remix os', 'phoenixos',
    'primeos', 'virtualbox', 'vmware', 'qemu', 'android_x86', 'x86_64; rv', 'android sdk', 'google_sdk',
    'sdk_gphone', 'emulator64', 'vbox86', 'andvm', 'duos', 'appplayer', 'microvirt', 'titandx',
    'browserless', 'phantomjs', 'slimerjs', 'nightmare', 'cypress', 'testcafe', 'headless'];
const BAD_UA = ['headlesschrome', 'phantom', 'puppeteer', 'selenium', 'webdriver', 'playwright', 'electron',
    'cef', 'wkhtml', 'chrome-lighthouse', 'bot', 'crawl', 'spider', 'scrapy', 'curl', 'wget',
    'python-requests', 'axios', 'okhttp', 'java/', 'go-http-client', 'libwww', 'httpclient', 'postman', 'insomnia',
    'libcurl', 'node-fetch', 'undici', 'deno', 'bun/', 'httpie', 'python-urllib', 'python-httpx', 'aiohttp',
    'guzzle', 'reqwest', 'rust', 'php/', 'ruby/', 'k6', 'jmeter', 'loadrunner', 'headless'];

// [v11] Helper: tra true neu UA la bot/curl/emulator/headless/webdriver (dung cho ca GET endpoint, khong chi /attest)
function isBadUA(uaHeader){
    const ua = String(uaHeader || '').toLowerCase();
    if(!ua || ua.length < 20) return true;
    if(BAD_UA.some(k => ua.includes(k))) return true;
    if(EMU_MARKERS.some(k => ua.includes(k))) return true;
    return false;
}
// [v12] Chi Android/iOS that (UA mobile) moi duoc phep keo code khi SMART_VM_BLOCK bat
function isMobileUA(uaHeader){
    const ua = String(uaHeader || '').toLowerCase();
    return /android|iphone|ipad|ipod/.test(ua);
}
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
    // [v10] không gửi fingerprint / device → nghi dumper/curl giả
    if (!fp || typeof fp !== 'object') { score += 3; softReason = softReason || 'khong gui fingerprint'; }
    if (!device || typeof device !== 'object') { score += 2; softReason = softReason || 'khong gui thong tin thiet bi'; }

    // ── A. BẰNG CHỨNG RÕ RÀNG → BAN NGAY (high confidence) ──
    // [v17] Mobile thật (Android/iOS) miễn các dấu hiệu mềm; chỉ automation rõ ràng mới chặn.
    const uaMobile = /android|iphone|ipad|ipod|harmonyos/i.test(ua);
    const HARD_AUTO_RE = /webdriver|headlesschrome|puppeteer|playwright|selenium|phantomjs|electron/i;
    if (BAD_UA.some(k => ua.includes(k))) {
        if (!(uaMobile && !HARD_AUTO_RE.test(ua))) return { ok: false, ban: true, reason: 'trình duyệt giả/bot (UA)', deviceName: '', score: 99 };
        score += 1; softReason = softReason || 'dau hieu UA soft tren mobile (v17 mien ban)';
    }
    if (fp && fp.webdriver === true) return { ok: false, ban: true, reason: 'webdriver/automation', deviceName: '', score: 99 };
    if (!ua || ua.length < 20) {
        if (!uaMobile) return { ok: false, ban: true, reason: 'UA không hợp lệ', deviceName: '', score: 99 };
        softReason = softReason || 'thieu UA header tren mobile (v17 soft)';
    }
    if (EMU_MARKERS.some(k => ua.includes(k))) {
        const STRONG_EMU_RE = /sdk_gphone|emulator|genymotion|bluestacks|nox|ldplayer|memu|vbox|qemu|virtualbox|vmware/i;
        if (!(uaMobile && !STRONG_EMU_RE.test(ua))) return { ok: false, ban: true, reason: 'máy ảo/emulator (UA marker)', deviceName: '', score: 99 };
        score += 1; softReason = softReason || 'emu marker soft tren mobile (v17)';
    }

    const isAndroid = /android/i.test(ua);
    const isIOS = /iphone|ipad|ipod/i.test(ua);

    // [FIX v8.1] UA-platform mâu thuẫn → KHÔNG ban cứng nữa. navigator.platform KHÔNG đáng tin
    //            trên di động: Android Chrome báo "Linux armv8l" (khớp /linux/), iPad desktop-mode
    //            báo "MacIntel" (khớp /mac/) → trước đây BAN NHẦM thiết bị thật. Chỉ cộng điểm nhẹ.
    if (isIOS && /win|mac|linux|x11/.test(platform) && !/iphone|ipad|ipod/.test(platform))
        { score += 1; softReason = softReason || 'platform không khớp iOS (thường là iPad desktop-mode)'; }
    if (isAndroid && /win|mac|linux/.test(platform) && !/android/.test(platform))
        { score += 1; softReason = softReason || 'platform không khớp Android (thường là Linux armv8l)'; }
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

    // [v10] C.2 KIỂM TRA NHẤT QUÁN (CPU/RAM/touch/screen/vendor) — cộng điểm
    const coresC = dev.cores || (fp && fp.hardwareConcurrency) || 0;
    const memC = dev.memory || (fp && fp.deviceMemory) || 0;
    if (coresC && memC && coresC > 8 && memC < 2) { score += 2; softReason = softReason || 'CPU/RAM mau thuan (cores>8 nhung RAM<2)'; }
    const touchC = dev.touchPoints != null ? dev.touchPoints : (fp && fp.maxTouchPoints);
    if (touchC && touchC >= 5 && w && w < 320) { score += 2; softReason = softReason || 'touch nhieu nhung man hinh qua nho'; }
    if (isAndroid && vendor && !/google/.test(vendor)) { score += 1; softReason = softReason || 'vendor Android khong phai Google'; }
    // [v10] suspicious = score>=2 → kết hợp với tín hiệu proxy/datacenter để BAN (tránh ban nhầm nhà mạng di động)
    const suspicious = score >= 2;
    // ── D. KẾT LUẬN: ban cứng chỉ khi ≥5 điểm; suspicious ghi cờ cho HARD_DC_BAN
    if (score >= 5 && !isAndroid && !isIOS) return { ok: false, ban: true, reason: 'đa dấu hiệu thiết bị giả (' + softReason + ')', deviceName, score, suspicious: true };
    // [v16] Mobile that diem heuristic cao (thieu fp cu, thieu touch...) -> KHONG chan, chi danh dau nghi ngo
    if (score >= 5) return { ok: true, ban: false, reason: '', deviceName, score, suspicious: true, softScore: true };
    return { ok: true, ban: false, reason: '', deviceName, score, suspicious };
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
    // [v6.5.3 · LEGACY] Script cũ (v5.0) không gửi session token → cho qua (chỉ log), không chặn.
    //          Bảo mật vẫn còn: chữ ký HMAC (nếu client ký) + key verify ở /verify.
    if (!token) { adminLog('legacy-no-session', { path: req.path, ip: getClientIp(req) }); req._sess = null; req._token = null; return true; }
    const sess = verifySession(token);
    if (!sess) { res.status(403).json({ success: false, message: 'Phiên không hợp lệ hoặc hết hạn' }); return false; }
    const { key, hwid } = req.body || {};
    if (sess.k !== key) { res.status(403).json({ success: false, message: 'Phiên không khớp key' }); return false; }
    if (sess.h !== (hwid || '')) { res.status(403).json({ success: false, message: 'Phiên không khớp thiết bị' }); return false; }
    // [v16] IP quay số (CGNAT / chuyển Wi-Fi<->4G) tren di dong la binh thuong -> CHI GHI LOG, khong chan
    if (sess.ip && sess.ip !== getClientIp(req)) { adminLog('ip-rotated-soft', { oldIp: sess.ip, newIp: getClientIp(req), path: req.path }); }
    const fph = req.headers['x-fp-hash'];
    if (fph && sess.fp && fph !== sess.fp) { adminLog('fp-changed-soft', { path: req.path, ip: getClientIp(req) }); }
    // [v6.5.1] Seq — CHỈ GHI LOG, KHÔNG chặn. Lý do: chữ ký HMAC (nonce + ts) đã chống replay;
    //          chặn cứng gây mất đồng bộ khi nhiều lời gọi /process chạy song song.
    if (String(req.headers['x-seq'] || '') !== String(sess.seq || '1')) { adminLog('seq-mismatch', { got: String(req.headers['x-seq'] || ''), expect: String(sess.seq || '1'), ip: getClientIp(req) }); }
    // [v6.5] UA-bind — chống share session token sang máy/trình duyệt khác
    if (sess.ua && sha256Hex(req.headers['user-agent'] || '').slice(0, 16) !== sess.ua) {
        if (uaIsMobile(req.headers['user-agent'])) { adminLog('ua-soft-mobile', { path: req.path, ip: getClientIp(req) }); }
        else { res.status(403).json({ success: false, message: 'Trình duyệt không khớp phiên (anti-share token)' }); return false; }
    }
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

// [v18] Tóm tắt đáp án do SERVER giải (client chỉ hiển thị log/thông báo, không tự giải).
function buildFireSummary(rawQuestions, mode) {
    const items = (rawQuestions || []).map((q, i) => {
        let answers = [];
        try {
            const subs = findCorrectInfo(q);
            answers = subs.flatMap(sq => {
                if (sq.type === 1) {
                    const lbl = ['A', 'B', 'C', 'D', 'E'][parseInt(sq.ans && sq.ans[0], 10)];
                    return lbl ? [lbl] : [];
                }
                return (sq.ans || []).map(String);
            });
        } catch (_) {}
        return { i: i + 1, id: q.id || q._id || null, answers };
    });
    return { count: (rawQuestions || []).length, mode: mode || 'practice', items };
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
// ══════════════════════════════════════════════════════════════════════════════
//  [v8] /bootstrap.js — loader.user.js TẢI toàn bộ connector code (chỉ GET,
//  ẩn sau API_PREFIX + mã hoá AES-GCM key derive từ SECRET). Không cần key,
//  không cần session → loader chỉ có đúng 1 chức năng: kéo code về chạy.
// ══════════════════════════════════════════════════════════════════════════════
app.get(API_PREFIX + '/bootstrap.js', async (req, res) => {
    const ip = getClientIp(req);
    unlockReal(req, ip, null, 'bootstrap.js');
    if (guardBanned(req, res, ip, null, 'bootstrap.js')) return;
    if (!rateLimit('boot:' + ip, 60, 60000)) return res.status(429).json({ error: 'Too many requests' });
    // [v12] SMART_VM_BLOCK: blanket block da thay bang smart check (xem duoi) — khong chan user mobile that
    // [v11] chan UA bot/curl/emulator (truoc bootstrap chi check IP datacenter)
    if (isBadUA(req.headers['user-agent'])) { adminLog('badua-block', { ip, path: 'bootstrap.js', ua: String(req.headers['user-agent'] || '').slice(0, 60) }); return res.status(404).json({ error: 'Not found' }); }
    // [v10] HARD_DC_BAN: máy ảo/VPS/proxy kéo bootstrap.js → BAN NGAY (chặn trước khi lấy được code)
    const pBoot = await checkProxyIp(ip);
    if (HARD_DC_BAN && pBoot.risk === 'high' && pBoot.isDC && pBoot.isVPN && !(uaIsMobile(req.headers['user-agent']) || (SMART_BAN && isRealMobileDevice(ip, null, req.headers['user-agent'])))) { addBan(ip, null, 'IP datacenter/proxy keo bootstrap.js (HARD_DC_BAN v11) — ' + (pBoot.org || ''), ''); adminLog('dc-ban', { ip, path: 'bootstrap.js', org: pBoot.org || '' }); return res.status(404).json({ error: 'Not found' }); }
    // [v12] SMART_VM_BLOCK: khi admin BAT toggle, chi Android/iOS that (UA mobile) + IP khong phai datacenter moi keo duoc code.
    //       VM/proxy/desktop/bot -> 404. Khi TAT -> cho moi nguoi (HARD_DC_BAN van tu chan datacenter).
    if (BLOCK_VM_SCRIPT && (!isMobileUA(req.headers['user-agent']) || pBoot.isDC)) { adminLog('vm-smart-block', { ip, path: 'bootstrap.js', ua: String(req.headers['user-agent'] || '').slice(0, 60), isDC: !!pBoot.isDC }); return res.status(404).json({ error: 'Not found' }); }
    try {
        const src     = renderConnectorSrc(req);
        const payload = bootstrapEncrypt(src);
        adminLog('bootstrap', { ip, ua: String(req.headers['user-agent'] || '').slice(0, 80), bytes: src.length });
        res.json({ ok: true, v: CONNECTOR_MODULE_VERSION, payload });
    } catch (err) {
        console.error('[/bootstrap.js]', err);
        res.status(500).json({ ok: false, error: 'Server error' });
    }
});

// ══════════════════════════════════════════════════════════════════════════════
//  [v8.1] /kv-payload.js — PAYLOAD TƯƠNG THÍCH KEYVAULT (server index.js)
//  Trả RAW JS (không mã hoá): tự cài bridge mạng + chạy connector ngay.
//  Cách dùng: mở URL này trong trình duyệt → copy toàn bộ nội dung JS →
//  upload lên KeyVault (trang "📤 Nạp file code") → loader OLM_user.js
//  của KeyVault sẽ kéo về chạy. Không cần loader Payload.js nữa.
// ══════════════════════════════════════════════════════════════════════════════
app.get(API_PREFIX + '/kv-payload.js', async (req, res) => {
    const ip = getClientIp(req);
    unlockReal(req, ip, null, 'kv-payload.js');
    if (guardBanned(req, res, ip, null, 'kv-payload.js')) return;
    if (!rateLimit('kvp:' + ip, 40, 60000)) return res.status(429).send('/* too many requests */');
    // [v12] SMART_VM_BLOCK: blanket block da thay bang smart check (xem duoi)
    // [v11] chan UA bot/curl/emulator + IP datacenter (truoc day endpoint nay KHONG co check nao -> lo hong)
    if (isBadUA(req.headers['user-agent'])) { adminLog('badua-block', { ip, path: 'kv-payload.js', ua: String(req.headers['user-agent'] || '').slice(0, 60) }); return res.status(404).send('/* not found */'); }
    const pKvp = await checkProxyIp(ip);
    if (HARD_DC_BAN && pKvp.risk === 'high' && pKvp.isDC && pKvp.isVPN && !(uaIsMobile(req.headers['user-agent']) || (SMART_BAN && isRealMobileDevice(ip, null, req.headers['user-agent'])))) { addBan(ip, null, 'IP datacenter/proxy keo kv-payload.js (HARD_DC_BAN v11) — ' + (pKvp.org || ''), ''); adminLog('dc-ban', { ip, path: 'kv-payload.js', org: pKvp.org || '' }); return res.status(404).send('/* not found */'); }
    // [v12] SMART_VM_BLOCK: chi Android/iOS that moi keo duoc raw connector khi toggle BAT
    if (BLOCK_VM_SCRIPT && (!isMobileUA(req.headers['user-agent']) || pKvp.isDC)) { adminLog('vm-smart-block', { ip, path: 'kv-payload.js', ua: String(req.headers['user-agent'] || '').slice(0, 60), isDC: !!pKvp.isDC }); return res.status(404).send('/* not found */'); }
    try {
        const src = buildKvPayloadSrc(req);
        adminLog('kv-payload', { ip, ua: String(req.headers['user-agent'] || '').slice(0, 80), bytes: src.length });
        res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
        res.setHeader('Cache-Control', 'no-store');
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.send(src);
    } catch (err) {
        console.error('[/kv-payload.js]', err);
        res.status(500).send('/* server error */');
    }
});

// [v9] iOS-FIX: loader.user.js tu server — cai thay the tren iOS de fix loi __GMFunc__
app.get(API_PREFIX + '/loader.user.js', async (req, res) => {
    const ip = getClientIp(req);
    unlockReal(req, ip, null, 'loader.user.js');
    if (guardBanned(req, res, ip, null, 'loader.user.js')) return;
    if (!rateLimit('ldr:' + ip, 30, 60000)) return res.status(429).send('// too many requests');
    // [v12] SMART_VM_BLOCK: blanket block da thay bang smart check (xem duoi)
    // [v11] chan UA bot/curl/emulator + IP datacenter (truoc day endpoint nay KHONG co check nao -> lo hong)
    if (isBadUA(req.headers['user-agent'])) { adminLog('badua-block', { ip, path: 'loader.user.js', ua: String(req.headers['user-agent'] || '').slice(0, 60) }); return res.status(404).send('// not found'); }
    const pLdr = await checkProxyIp(ip);
    if (HARD_DC_BAN && pLdr.risk === 'high' && pLdr.isDC && pLdr.isVPN && !(uaIsMobile(req.headers['user-agent']) || (SMART_BAN && isRealMobileDevice(ip, null, req.headers['user-agent'])))) { addBan(ip, null, 'IP datacenter/proxy keo loader.user.js (HARD_DC_BAN v11) — ' + (pLdr.org || ''), ''); adminLog('dc-ban', { ip, path: 'loader.user.js', org: pLdr.org || '' }); return res.status(404).send('// not found'); }
    // [v12] SMART_VM_BLOCK: chi Android/iOS that moi keo duoc loader khi toggle BAT
    if (BLOCK_VM_SCRIPT && (!isMobileUA(req.headers['user-agent']) || pLdr.isDC)) { adminLog('vm-smart-block', { ip, path: 'loader.user.js', ua: String(req.headers['user-agent'] || '').slice(0, 60), isDC: !!pLdr.isDC }); return res.status(404).send('// not found'); }
    try {
        adminLog('loader-served', { ip, ua: String(req.headers['user-agent'] || '').slice(0, 60) });
        res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
        res.setHeader('Cache-Control', 'no-store');
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.send(buildLoaderSrc(req));
    } catch (err) { console.error('[/loader.user.js]', err); res.status(500).send('// server error'); }
});
// [v9] OLM BAN CHECK endpoint: connector poll de biet tai khoan OLM hien tai co bi ban khong
app.post(API_PREFIX + '/olm-check', (req, res) => {
    const ip = getClientIp(req);
    if (!rateLimit('olmc:' + ip, 30, 60000)) return res.status(429).json({ banned: false });
    const olm_user = (req.body && req.body.olm_user) || '';
    const ob = checkOlmBan(olm_user);
    if (ob) {
        adminLog('olm-ban-check', { olm_user: normOlm(olm_user), ip, reason: ob.reason });
        return res.json({ banned: true, permanent: ob.permanent, remain: ob.remain || '', reason: ob.reason,
            message: 'Tai khoan OLM ' + String(olm_user || '') + ' da bi BAN' + (ob.permanent ? ' VINH VIEN' : ' (con ' + ob.remain + ')') + '. Ly do: ' + ob.reason });
    }
    res.json({ banned: false });
});
// Verify key
app.post(API_PREFIX + '/verify'
, async (req, res) => {
    const ip = getClientIp(req);
    unlockReal(req, ip, (req.body && req.body.hwid) || null, 'route');
    if (guardBanned(req, res, ip, (req.body && req.body.hwid) || null, 'api')) return;
    if (!rateLimit('verify:' + ip + '|' + ((req.body && req.body.hwid) || ''), 20, 60000)) return res.status(429).json({ success: false, message: 'Quá nhiều yêu cầu' });
    const { key, hwid, olm_user } = req.body || {};
    if (!key) return res.status(400).json({ success: false, message: 'Missing key' });
    // [v9] Kiem tra ban tai khoan OLM NGAY tai verify (chan dang nhap)
    const _obV = checkOlmBan(olm_user);
    if (_obV) {
        adminLog('olm-ban-verify', { olm_user: normOlm(olm_user), hwid, ip, reason: _obV.reason, permanent: _obV.permanent });
        return res.status(403).json({ success: false, olmBanned: true, permanent: _obV.permanent, remain: _obV.remain || '',
            message: 'Tai khoan OLM ' + String(olm_user || '') + ' da bi BAN' + (_obV.permanent ? ' VINH VIEN' : ' (con ' + _obV.remain + ')') + '. Ly do: ' + _obV.reason });
    }
    const shV = checkKeyShare(key, hwid, ip);
    if (shV.shared) {
        if (SMART_BAN && realMobileReq(req, hwid)) adminLog('share-soft-mobile', { key: maskKey(key), hwid, ip, route: 'verify' });
        else return res.status(403).json({ success: false, message: 'Key đang được dùng trên nhiều thiết bị (anti-share)' });
    }
    const result = await proxyVerify(key, hwid, olm_user);
    if (!result.success) { if (recordKeyFail(ip) && AUTO_BAN && !isLoopbackIp(ip)) addBan(ip, null, 'brute-force key (>=10 sai/10 phut)', ''); } else resetKeyFail(ip); // [v7] anti brute-force key [v9] ban that khi vuot nguong
    adminLog('verify', { key: maskKey(key), hwid, device: deviceNameOf(hwid), olm_user, ip, success: !!result.success, type: result.type || '', message: result.message || '' });
    trackDevice(hwid, { olm_user: normOlm(olm_user), ip });
    res.json(result);
});

// Attestation — client gửi fp + device info, server kiểm tra máy thật + mạng thật, cấp session
app.post(API_PREFIX + '/attest', async (req, res) => {
    const ip = getClientIp(req);
    const { key, hwid, fp, device } = req.body || {};
    unlockReal(req, ip, hwid, 'attest');
    if (guardBanned(req, res, ip, hwid, 'attest')) return;
    if (!key) return res.status(400).json({ success: false, message: 'Thiếu key' });
    const shA = checkKeyShare(key, hwid, ip);
    if (shA.shared) {
        if (SMART_BAN && realMobileReq(req, hwid)) adminLog('share-soft-mobile', { key: maskKey(key), hwid, ip, route: 'attest' });
        else return res.status(403).json({ success: false, message: 'Key đang được dùng trên nhiều thiết bị (anti-share)' });
    }
    if (!rateLimit('attest:' + ip + '|' + (hwid || ''), 30, 60000)) return res.status(429).json({ success: false, message: 'Quá nhiều lần xác thực' });

    // 1. Kiểm tra thiết bị thật (Android/iOS, không máy ảo, không trình duyệt giả)
    const v = validateDevice(fp, device, req.headers['user-agent']);
    if (!v.ok) {
        if (v.ban && AUTO_BAN && !isLoopbackIp(ip)) addBan(ip, hwid, v.reason, v.deviceName);
        adminLog('reject', { ip, hwid, device: v.deviceName, reason: v.reason, banned: !!(v.ban && AUTO_BAN) });
        return res.status(403).json({ success: false, message: v.ban ? 'Thiết bị/mạng không hợp lệ — đã bị khoá vĩnh viễn, liên hệ admin' : 'Chỉ hỗ trợ trên máy Android/iOS thật với trình duyệt thật' });
    }
    // [v14] SMART_BAN: danh dau thiet bi di dong that da xac thuc -> KHONG bao gio bi ban + tu mo ban neu co
    if (SMART_BAN && /android|iphone|ipad|ipod/i.test(String(req.headers['user-agent'] || ''))) {
        const _rd = realDevices.get(hwid) || {};
        realDevices.set(hwid, { ip, deviceName: v.deviceName, firstSeen: _rd.firstSeen || Date.now(), lastSeen: Date.now() });
        autoUnbanIfReal(ip, hwid, req.headers['user-agent'], 'attest-real-mobile');
    }
    // 2. Kiểm tra mạng thật (không proxy/VPN/datacenter)
    // [FIX v8.1] KHÔNG ban vĩnh viễn IP & KHÔNG chặn khi nghi proxy/VPN. Lý do: IP nhà mạng
    //            di động (Viettel/Vinaphone/Mobifone) thường bị ipapi.is nhận NHẦM thành
    //            datacenter/proxy (carrier-grade NAT) → ban nhầm thiết bị thật + thật trình duyệt.
    //            Đã qua bước 1 validateDevice (chỉ thiết bị Android/iOS thật mới tới đây) → nếu
    //            thiết bị thật mà IP bị nghi proxy, khả năng cao là nhận nhầm. Chỉ log cảnh báo.
    const p = await checkProxyIp(ip);
    if (p.risk === 'high') {
        // [v10] HARD_DC_BAN: IP datacenter HOẶC (proxy + thiết bị nghi ngờ) → BAN NGAY.
        //       Chỉ soft khi IP nghi proxy nhưng KHÔNG phải datacenter và thiết bị sạch (tránh ban nhầm nhà mạng di động CGNAT).
        if (HARD_DC_BAN && p.isDC && p.isVPN && !(uaIsMobile(req.headers['user-agent']) || (SMART_BAN && isRealMobileDevice(ip, hwid, req.headers['user-agent'])))) {
            addBan(ip, hwid, 'proxy/VPN/datacenter + IP datacenter (HARD_DC_BAN)', v.deviceName);
            adminLog('proxy-ban', { ip, hwid, device: v.deviceName, org: p.org || '', country: p.country || '', isDC: !!p.isDC, suspicious: !!v.suspicious });
            return res.status(403).json({ success: false, message: 'Mạng không hợp lệ (proxy/VPN/datacenter) — đã khoá vĩnh viễn, liên hệ admin' });
        }
        adminLog('proxy-warn', { ip, hwid, device: v.deviceName, reason: 'proxy/VPN (soft, co the la nha mang di dong CGNAT)', org: p.org || '', country: p.country || '' });
    }
    // [v10] Key bị revokle (dump/rò rỉ) → 404 + ban thiết bị
    if (keyBlocked(req, res, key, ip, hwid, v.deviceName, 'attest')) return;
    // [v10] DUMPER_GUARD: ghi nhận attest
    dumperJudge(key, hwid, ip, v.deviceName, 'attest');
    // 3. Key phải hợp lệ
    const kv = await proxyVerify(key, hwid);
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
        if (isPremiumType(kv.type) && !BLOCK_MODULE_10) { keyAct(key).moduleFetchCount++; resp.module = buildModulePayload(token, key, hwid); }
    trackDevice(hwid, { device: v.deviceName, ip });
    // [v7] AUTO-SEND TOÀN BỘ code connector xuống loader — mọi key hợp lệ (không chỉ premium)
    resp.connector = buildConnectorPayload(token);
    adminLog('attest', { key: maskKey(key), hwid, device: v.deviceName, ip, success: true, premium: isPremiumType(kv.type) });
    res.json(resp);
});

// Process — giải mã đáp án (cần session)
app.post(API_PREFIX + '/process', async (req, res) => {
    const ip = getClientIp(req);
    unlockReal(req, ip, (req.body && req.body.hwid) || null, 'route');
    if (guardBanned(req, res, ip, (req.body && req.body.hwid) || null, 'api')) return;
    if (!requireSession(req, res)) return;
    if (!rateLimit('ip:' + ip + '|' + ((req.body && req.body.hwid) || ''), 30, 60000)) return res.status(429).json({ success: false, message: 'Quá nhiều yêu cầu (IP)' });
    const { key, hwid, questions } = req.body || {};
    if (!key) return res.status(401).json({ success: false, message: 'Missing key' });
    if (!Array.isArray(questions) || questions.length === 0) return res.status(400).json({ success: false, message: 'No questions' });
    const kv = await proxyVerify(key, hwid);
    if (!kv.success) return res.status(401).json({ success: false, message: kv.message || 'Invalid key' });
    dumperJudge(key, hwid, ip, deviceNameOf(hwid), 'process'); // [v10] đánh dấu hoạt động thật → giảm nghi ngờ dump
    if (keyBlocked(req, res, key, ip, hwid, deviceNameOf(hwid), 'core')) return;
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
    unlockReal(req, ip, (req.body && req.body.hwid) || null, 'route');
    if (guardBanned(req, res, ip, (req.body && req.body.hwid) || null, 'api')) return;
    if (!requireSession(req, res)) return;
    const { key, hwid, session, mode, time_str, grade } = req.body || {};
    if (!key) return res.status(401).json({ success: false, message: 'Missing key' });
    // [v6.5.1] fireReady — CHỈ GHI LOG, KHÔNG chặn (chữ ký + phiên + premium check đã đủ mạnh).
    //          Chặn cứng làm lỗi khi phiên hết hạn & attest lại mất cờ fireReady.
    if (!req._sess || !req._sess.fireReady) { adminLog('fire-noready', { ip, hwid, key: maskKey(key) }); }
    dumperJudge(key, hwid, ip, deviceNameOf(hwid), 'fire'); // [v10] đánh dấu hoạt động thật (nộp bài) → reset nghi ngờ dump
    if (keyBlocked(req, res, key, ip, hwid, deviceNameOf(hwid), 'core')) return;
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
    trackDevice(hwid, { id_cate: session.meta.id_cate, id_user: session.meta.id_user, mode: mode || '', ip });
    try {
        const paramsStr = buildFirePayload(session, mode || 'practice', time_str || '10.00', grade);
        const summary = buildFireSummary(session.raw_questions, mode || 'practice');
        res.json(rotateSession(req, { success: true, params_str: paramsStr, endpoint: '/course/teacher-static', summary }));
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
    unlockReal(req, ip, (req.body && req.body.hwid) || null, 'route');
    if (guardBanned(req, res, ip, (req.body && req.body.hwid) || null, 'api')) return;
    // [v10] /module BẮT BUỘC có session hợp lệ (không còn legacy bypass — dumper luôn cố gắng endpoint này)
    if (!req.headers['x-session']) {
        adminLog('module-no-session', { ip, hwid: req.body && req.body.hwid, ua: String(req.headers['user-agent'] || '').slice(0, 60) });
        if (DUMPER_GUARD && (req.body && req.body.key) && !realMobileReq(req, req.body.hwid)) addKeyBan(req.body.key, 'goi /module khong co session — dumper', ip, req.body.hwid, '');
        else if (DUMPER_GUARD && (req.body && req.body.key)) adminLog('module-nosession-soft-mobile', { ip, hwid: req.body && req.body.hwid });
        return res.status(403).json({ success: false, message: 'Phiên không hợp lệ' });
    }
    if (!requireSession(req, res)) return;
    // [v11] defense-in-depth: IP datacenter dung session cu lay module -> ban (session da rang buoc IP, them lop)
    const pMod = await checkProxyIp(ip);
    if (HARD_DC_BAN && pMod.risk === 'high' && pMod.isDC && pMod.isVPN && !(uaIsMobile(req.headers['user-agent']) || (SMART_BAN && isRealMobileDevice(ip, req.body && req.body.hwid, req.headers['user-agent'])))) { addBan(ip, req.body && req.body.hwid, 'IP datacenter goi /module (HARD_DC_BAN v11) — ' + (pMod.org || ''), deviceNameOf(req.body && req.body.hwid)); adminLog('dc-ban', { ip, hwid: req.body && req.body.hwid, path: 'module', org: pMod.org || '' }); return res.status(404).json({ error: 'Not found' }); }
    const { key, hwid } = req.body || {};
    if (keyBlocked(req, res, key, ip, hwid, deviceNameOf(hwid), 'core')) return;
    // [v10] Rate limit nghiêm ngặt: 2 lần/giờ/key (connector thật không bao giờ gọi /module — module đẩy tự động qua attest/heartbeat)
    if (!rateLimit('mod:' + String(key || ip), 10, 3600000)) { adminLog('mod-ratelimit', { key: maskKey(key||''), hwid, ip, note: '[v13] vuot nguong 10 lan/gio — chi 429, khong ban' }); return res.status(429).json({ success: false, message: 'Quá nhiều yêu cầu' }); } // [v13] nguong 2->10, khong ban key
    // [v12] SMART_VM_BLOCK: /module da BAT BUOC session (chi thiet bi that qua /attest moi co) -> khong can chan blanket nua; DUMPER_GUARD + rate-limit + watermark phong dump.
    if (BLOCK_MODULE_10) { adminLog('module10-block', { ip, hwid }); return res.status(403).json({ success: false, message: 'Module chuan bi 10 diem da bi admin chan' }); }
    if (!key) return res.status(401).json({ success: false, message: 'Missing key' });
    // [v10] DUMPER_GUARD: phát hiện hành vi dump → BAN key+hwid+ip vĩnh viễn
    const djMod = dumperJudge(key, hwid, ip, deviceNameOf(hwid), 'module');
    if (djMod) {
        if (realMobileReq(req, hwid)) { adminLog('dumper-soft-mobile', { key: maskKey(key), ip, hwid, reason: djMod }); }
        else { addKeyBan(key, djMod, ip, hwid, deviceNameOf(hwid)); return res.status(403).json({ success: false, message: 'Phát hiện hành vi dump — key & thiết bị đã bị khoá vĩnh viễn' }); }
    }
    const kv = await proxyVerify(key, hwid);
    if (!kv.success) return res.status(401).json({ success: false, message: kv.message || 'Invalid key' });
    if (!isPremiumType(kv.type)) return res.status(403).json({ success: false, message: 'Module chỉ dành cho key PREMIUM/VIP/UNLIMITED' });
    adminLog('module', { key: maskKey(key), hwid, device: deviceNameOf(hwid), ip, type: kv.type || '' });
    const payload = { success: true, encrypted: true, moduleVersion: PAYLOAD_MODULE_VERSION, module: buildModulePayload(req._token, key, hwid) };
    res.json(rotateSession(req, payload));
});

// ══════════════════════════════════════════════════════════════════════════════
//  [v7] /code — loader TẢI LẠI toàn bộ connector code (cần session hợp lệ).
//  Dùng khi phiên hết hạn hoặc cập nhật version. Mã hoá AES-256-GCM key derive
//  từ session token (chỉ client attest hợp lệ mới giải mã được).
// ══════════════════════════════════════════════════════════════════════════════
app.post(API_PREFIX + '/code', async (req, res) => {
    const ip = getClientIp(req);
    unlockReal(req, ip, (req.body && req.body.hwid) || null, 'route');
    if (guardBanned(req, res, ip, (req.body && req.body.hwid) || null, 'api')) return;
    if (!requireSession(req, res)) return;
    if (!rateLimit('code:' + ip + '|' + ((req.body && req.body.hwid) || ''), 10, 60000)) return res.status(429).json({ success: false, message: 'Quá nhiều yêu cầu' });
    // [v12] SMART_VM_BLOCK: /code da BAT BUOC session -> khong can chan blanket nua.
    const { key, hwid } = req.body || {};
    if (!key) return res.status(401).json({ success: false, message: 'Missing key' });
    const kv = await proxyVerify(key, hwid);
    if (!kv.success) return res.status(401).json({ success: false, message: kv.message || 'Invalid key' });
    adminLog('code', { key: maskKey(key), hwid, device: deviceNameOf(hwid), ip, connectorVersion: CONNECTOR_MODULE_VERSION });
    const payload = { success: true, encrypted: true, connectorVersion: CONNECTOR_MODULE_VERSION, connector: buildConnectorPayload(req._token) };
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
    unlockReal(req, ip, (req.body && req.body.hwid) || null, 'route');
    if (guardBanned(req, res, ip, (req.body && req.body.hwid) || null, 'api')) return;
    if (!rateLimit('hb:' + ip + '|' + ((req.body && req.body.hwid) || ''), 30, 60000)) return res.status(429).json({ success: false, message: 'Quá nhiều yêu cầu' });
    const { key, hwid, fp, device, clientVersion } = req.body || {};
    if (!key) return res.status(400).json({ success: false, message: 'Thiếu key' });
    const shH = checkKeyShare(key, hwid, ip);
    if (shH.shared) {
        if (SMART_BAN && realMobileReq(req, hwid)) adminLog('share-soft-mobile', { key: maskKey(key), hwid, ip, route: 'heartbeat' });
        else return res.status(403).json({ blocked: true, reason: 'share', message: 'Key đang được dùng trên nhiều thiết bị (anti-share)' });
    }
    // 1. Kiểm tra lại thiết bị (có thể user bật giả lập/webdriver lúc đang chạy)
    const v = validateDevice(fp, device, req.headers['user-agent']);
    if (!v.ok) {
        if (v.ban && AUTO_BAN && !isLoopbackIp(ip)) addBan(ip, hwid, 'heartbeat: ' + v.reason, v.deviceName);
        adminLog('heartbeat-block', { ip, hwid, device: v.deviceName, reason: v.reason, banned: !!(v.ban && AUTO_BAN) });
        return res.status(403).json({ blocked: true, reason: v.reason, message: 'Phát hiện môi trường không hợp lệ — đã khoá' });
    }
    // [v14] SMART_BAN: cap nhat real device + tu mo ban neu co
    if (SMART_BAN && /android|iphone|ipad|ipod/i.test(String(req.headers['user-agent'] || ''))) {
        const _rdh = realDevices.get(hwid) || {};
        realDevices.set(hwid, { ip, deviceName: v.deviceName, firstSeen: _rdh.firstSeen || Date.now(), lastSeen: Date.now() });
        autoUnbanIfReal(ip, hwid, req.headers['user-agent'], 'heartbeat-real-mobile');
    }
    // 2. Kiểm tra lại mạng (có thể user bật VPN/VPS lúc đang chạy)
    const p = await checkProxyIp(ip);
    if (p.risk === 'high') {
        // [v10] HARD_DC_BAN: IP datacenter HOẶC (proxy + thiết bị nghi ngờ) → BAN NGAY
        if (HARD_DC_BAN && p.isDC && p.isVPN && !(uaIsMobile(req.headers['user-agent']) || (SMART_BAN && isRealMobileDevice(ip, hwid, req.headers['user-agent'])))) {
            addBan(ip, hwid, 'heartbeat: proxy/VPN/datacenter + IP datacenter (HARD_DC_BAN)', v.deviceName);
            adminLog('proxy-ban', { ip, hwid, device: v.deviceName, org: p.org || '', isDC: !!p.isDC });
            return res.status(403).json({ blocked: true, reason: 'proxy', message: 'Mạng không hợp lệ — đã khoá vĩnh viễn' });
        }
        adminLog('heartbeat-warn', { ip, hwid, device: v.deviceName, reason: 'proxy/VPN (soft, co the la nha mang di dong)', org: p.org || '' });
    }
    // [v10] Key bị revokle → khoá
    if (keyBlocked(req, res, key, ip, hwid, v.deviceName, 'heartbeat')) return;
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
    const out = { ok: true, t: Date.now(), nextCheck: 30000, moduleVersion: PAYLOAD_MODULE_VERSION, premium, connectorVersion: CONNECTOR_MODULE_VERSION };
    const cv = parseInt(clientVersion || '0', 10);
    // [v10] DUMPER_GUARD: dumper v2/v3 luôn gửi clientVersion=0 & connectorVersion=0 để ép server đẩy module/connector
    if (cv === 0 && parseInt(req.body.connectorVersion || '0', 10) === 0) {
        const dj0 = dumperJudge(key, hwid, ip, v.deviceName, 'heartbeat-zero');
        if (dj0) {
            if (realMobileReq(req, hwid)) { adminLog('dumper-zero-soft-mobile', { key: maskKey(key), ip, hwid, reason: dj0 }); }
            else { addKeyBan(key, dj0, ip, hwid, v.deviceName); return res.status(403).json({ blocked: true, reason: 'dumper', message: 'Phát hiện dumper — key & thiết bị đã bị khoá vĩnh viễn' }); }
        }
    }
        if (premium && cv < PAYLOAD_MODULE_VERSION && !BLOCK_MODULE_10) {
        // Dùng session token nếu client gửi kèm (X-Session hợp lệ); nếu không, cấp token tạm
        let tok = null;
        const sessTok = req.headers['x-session'];
        const sess = verifySession(sessTok);
        if (sess && sess.k === key && sess.h === (hwid || '')) tok = sessTok;
        else tok = signSession({ k: key, h: hwid || '', ip, fp: fpHash(fp), dev: v.deviceName, exp: Date.now() + SESSION_TTL, seq: 1, ua: sha256Hex(req.headers['user-agent'] || '').slice(0, 16), fireReady: false });
        out.module = buildModulePayload(tok, key, hwid);
        out.moduleSession = tok; // client dùng token này để giải mã module
        adminLog('heartbeat-push', { key: maskKey(key), hwid, ip, from: cv, to: PAYLOAD_MODULE_VERSION });
    }
    // [v7] AUTO-PUSH connector code nếu loader đang chạy version cũ (mọi key hợp lệ)
    const ccv = parseInt(req.body.connectorVersion || '0', 10);
    if (ccv < CONNECTOR_MODULE_VERSION) {
        let tok2 = null;
        const sessTok2 = req.headers['x-session'];
        const sess2 = verifySession(sessTok2);
        if (sess2 && sess2.k === key && sess2.h === (hwid || '')) tok2 = sessTok2;
        else tok2 = signSession({ k: key, h: hwid || '', ip, fp: fpHash(fp), dev: v.deviceName, exp: Date.now() + SESSION_TTL, seq: 1, ua: sha256Hex(req.headers['user-agent'] || '').slice(0, 16), fireReady: false });
        out.connector = buildConnectorPayload(tok2);
        out.connectorSession = tok2; // loader dùng token này giải mã connector
        adminLog('heartbeat-connector-push', { key: maskKey(key), hwid, ip, from: ccv, to: CONNECTOR_MODULE_VERSION });
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

// [v9] CSRF protection cho admin POST: kiem tra Origin/Referer khop host (SameSite=Strict cookie da bao ve 1 lop)
app.use((req, res, next) => {
    if (req.method === 'POST' && req.path.startsWith(ADMIN_PATH + '/')) {
        const origin = String(req.headers['origin'] || '').replace(/^https?:\/\//, '').split('/')[0];
        const referer = String(req.headers['referer'] || '').replace(/^https?:\/\//, '').split('/')[0];
        const host = req.get('host') || '';
        const ok = (!origin && !referer) || (origin && origin === host) || (!origin && referer && (referer === host || referer.endsWith('.' + host)));
        if (!ok) { adminLog('csrf-block', { ip: getClientIp(req), path: req.path, origin, referer, host }); return res.status(403).send('CSRF check failed'); }
    }
    // Admin pages gui Referer (de CSRF check hoat dong) — ghi de no-referrer global
    if (req.path.startsWith(ADMIN_PATH)) res.setHeader('Referrer-Policy', 'same-origin');
    next();
});
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
        const _secFlag = (req.protocol === 'https' || req.headers['x-forwarded-proto'] === 'https') ? '; Secure' : '';
        res.setHeader('Set-Cookie', `god_admin=${tok}; Path=/; HttpOnly; Max-Age=43200; SameSite=Strict${_secFlag}`); // [v9] Strict + Secure chong CSRF
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
<td style="font-family:monospace;font-size:10px">${_esc(e.olm_user || '')}</td>
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
<div class="card"><div class="lbl">Chặn kèo script VM (chỉ VM/proxy/desktop)</div><div class="val ${BLOCK_VM_SCRIPT ? 'warn' : 'ok'}">${BLOCK_VM_SCRIPT ? '🛑 Chặn VM/proxy (mobile vẫn OK)' : '✅ Bình thường'}</div></div>
<div class="card"><div class="lbl">Tài khoản OLM bị ban</div><div class="val" style="color:#ef4444">${olmBans.size}</div></div>
<div class="card"><div class="lbl">Module 10 điểm</div><div class="val ${BLOCK_MODULE_10 ? 'bad' : 'ok'}">${BLOCK_MODULE_10 ? '🛑 ĐANG CHẶN' : '✅ Đang gửi'}</div></div>
<div class="card"><div class="lbl">HARD_DC_BAN (proxy/VM gọi API→ban)</div><div class="val ${HARD_DC_BAN ? 'ok' : 'bad'}">${HARD_DC_BAN ? 'BẬT' : 'TẮT'}</div></div>
<div class="card"><div class="lbl">SAFE_MODE (chống ban nhầm — auto-ban chỉ log)</div><div class="val ${SAFE_MODE ? 'ok' : 'bad'}">${SAFE_MODE ? 'BẬT (an toàn)' : 'TẮT (nguy cơ ban nhầm)'}</div></div>
<div class="card"><div class="lbl">SMART_BAN (chỉ ban máy ảo/proxy, máy thật tự mở ban)</div><div class="val ${SMART_BAN ? 'ok' : 'bad'}">${SMART_BAN ? 'BẬT (thông minh)' : 'TẮT'}</div></div>
<div class="card"><div class="lbl">Đã tự mở ban cho thiết bị thật</div><div class="val" style="color:#00e676">${autoUnbanCount} lần</div></div>
<div class="card"><div class="lbl">Thiết bị thật đã nhận diện</div><div class="val" style="color:#4facfe">${realDevices.size} máy</div></div>
<div class="card"><div class="lbl">DUMPER_GUARD (phát hiện dump→ban key)</div><div class="val ${DUMPER_GUARD ? 'ok' : 'bad'}">${DUMPER_GUARD ? 'BẬT' : 'TẮT'}</div></div>
<div class="card"><div class="lbl">Watermark truy vết module</div><div class="val ${MODULE_WATERMARK ? 'ok' : 'bad'}">${MODULE_WATERMARK ? 'BẬT' : 'TẮT'}</div></div>
<div class="card"><div class="lbl">Key đã khoá (revoke)</div><div class="val bad">${BANNED_KEYS.size} key</div></div>
${SECRET === DEFAULT_SECRET ? '<div class="card" style="grid-column:1/-1;border-color:#ef4444"><div class="lbl" style="color:#ef4444">⚠️ SECRET MẶC ĐỊNH ĐÃ RÒ RỈ — đặt env GODMODE_SECRET NGAY</div></div>' : ''}
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
<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="blockVmScript"><button class="${BLOCK_VM_SCRIPT ? 'warn' : ''}" style="${BLOCK_VM_SCRIPT ? 'background:linear-gradient(135deg,#f59e0b,#eab308)' : ''}">${BLOCK_VM_SCRIPT ? '🛑 ĐANG chặn VM/proxy (Android/iOS vẫn OK) — bấm để TẮT' : '🔓 BẬT chặn kèo script VM (chỉ chặn VM/proxy/desktop)'}</button></form>
<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="blockModule10"><button class="${BLOCK_MODULE_10 ? 'warn' : ''}" style="${BLOCK_MODULE_10 ? 'background:linear-gradient(135deg,#f59e0b,#ef4444)' : ''}">${BLOCK_MODULE_10 ? '🛑 ĐANG CHẶN module 10đ (bấm TẮT)' : '🔟 BẬT chặn module chuẩn bị 10đ'}</button></form>
<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="hardDcBan"><button class="${HARD_DC_BAN ? 'warn' : ''}">${HARD_DC_BAN ? '🌐 TẮT HARD_DC_BAN' : '🌐 BẬT HARD_DC_BAN (proxy/VM→ban)'}</button></form>
<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="safeMode"><button class="${SAFE_MODE ? '' : 'warn'}">${SAFE_MODE ? '🛡️ TẮT SAFE_MODE (cho phép ban cứng)' : '🛡️ BẬT SAFE_MODE (chống ban nhầm)'}</button></form>
<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="smartBan"><button class="${SMART_BAN ? '' : 'warn'}">${SMART_BAN ? '🧠 TẮT SMART_BAN' : '🧠 BẬT SMART_BAN (chỉ ban máy ảo/proxy)'}</button></form>
<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="dumperGuard"><button class="${DUMPER_GUARD ? 'warn' : ''}">${DUMPER_GUARD ? '🕵️ TẮT DUMPER_GUARD' : '🕵️ BẬT DUMPER_GUARD (dump→ban key)'}</button></form>
<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="moduleWatermark"><button class="${MODULE_WATERMARK ? 'warn' : ''}">${MODULE_WATERMARK ? '💧 TẮT watermark' : '💧 BẬT watermark truy vết'}</button></form>
<form method="POST" action="${ADMIN_PATH}/toggle" class="inline" style="display:flex;gap:4px"><input type="hidden" name="flag" value="bankey"><input name="key" placeholder="KEY cần khoá (revoke)" style="padding:8px;border-radius:6px;border:1px solid #30363d;background:#0d1117;color:#e6edf3;min-width:180px"><button style="background:linear-gradient(135deg,#ef4444,#b91c1c)">🔨 Khoá key</button></form>
<form method="POST" action="${ADMIN_PATH}/toggle" class="inline" style="display:flex;gap:4px"><input type="hidden" name="flag" value="unbankey"><input name="key" placeholder="KEY cần mở khoá" style="padding:8px;border-radius:6px;border:1px solid #30363d;background:#0d1117;color:#e6edf3;min-width:180px"><button style="background:linear-gradient(135deg,#22c55e,#15803d)">🔓 Mở khoá key</button></form>
<div class="panel" style="margin-top:16px;border-color:rgba(239,68,68,.4)">
<h2 style="color:#ef4444">🚫 BAN TÀI KHOẢN OLM (phút / ngày / tháng / vĩnh viễn)</h2>
<form method="POST" action="${ADMIN_PATH}/olm-ban" style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end;margin-bottom:14px">
<div><label style="display:block;font-size:10px;color:#8b949e;margin-bottom:4px">Tài khoản OLM (email/username)</label>
<input name="olm_user" required placeholder="vd: user@olm.vn" style="padding:7px 10px;border-radius:5px;border:1px solid #30363d;background:#0d1117;color:#c9d1d9;width:200px;font-size:12px"></div>
<div><label style="display:block;font-size:10px;color:#8b949e;margin-bottom:4px">Thời gian</label>
<input name="value" type="number" min="1" value="1" style="width:70px;padding:7px 10px;border-radius:5px;border:1px solid #30363d;background:#0d1117;color:#c9d1d9;font-size:12px"></div>
<div><label style="display:block;font-size:10px;color:#8b949e;margin-bottom:4px">Đơn vị</label>
<select name="unit" style="padding:7px 8px;border-radius:5px;border:1px solid #30363d;background:#0d1117;color:#c9d1d9;font-size:12px">
<option value="minute">Phút</option>
<option value="day" selected>Ngày</option>
<option value="month">Tháng</option>
<option value="permanent">Vĩnh viễn</option>
</select></div>
<div><label style="display:block;font-size:10px;color:#8b949e;margin-bottom:4px">Lý do</label>
<input name="reason" placeholder="Vi phạm điều khoản" style="padding:7px 10px;border-radius:5px;border:1px solid #30363d;background:#0d1117;color:#c9d1d9;width:180px;font-size:12px"></div>
<button type="submit" style="background:linear-gradient(135deg,#ef4444,#b91c1c);padding:8px 18px">🚫 BAN</button>
</form>
<div style="font-size:10px;color:#8b949e;margin-bottom:8px">💡 Khi BAN: script trên server tự check — người dùng đăng nhập tài khoản OLM bị ban sẽ thấy thông báo <b style="color:#fca5a5">TÀI KHOẢN OLM ĐÃ BỊ CẤM</b> full-screen. Ban hết hạn tự gỡ. Chọn "Vĩnh viễn" = không hết hạn.</div>
<table><thead><tr><th>Tài khoản OLM</th><th>Thời gian còn lại</th><th>Lý do</th><th>Thời gian ban</th><th>Thao tác</th></tr></thead>
<tbody id="olm-ban-tbody"><tr><td colspan="5" class="empty">Đang tải...</td></tr></tbody></table>
</div>
<script>
function _escOl(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function _unbanOl(olm){
  var fd=new FormData(); fd.append('olm_user', olm);
  fetch('${ADMIN_PATH}/olm-unban',{method:'POST',body:fd}).then(function(){ _refreshOl(); }).catch(function(){});
}
function _renderOl(d){
  var tb=document.getElementById('olm-ban-tbody');
  var list=(d&&d.list)||[];
  if(!list.length){ tb.innerHTML='<tr><td colspan="5" style="text-align:center;color:#00e676;padding:16px;font-size:12px">✅ Chưa có tài khoản OLM nào bị ban.</td></tr>'; return; }
  var html='';
  list.forEach(function(r){
    html+='<tr style="background:rgba(239,68,68,.05)">';
    html+='<td style="font-family:monospace;font-size:11px;color:#fca5a5">'+_escOl(r.olm)+'</td>';
    html+='<td style="font-size:11px;color:#ef4444;font-weight:700">'+(r.permanent?'♾️ VĨNH VIÊN':('⏳ '+_escOl(r.remain)))+'</td>';
    html+='<td style="font-size:10px;color:#ffc107;max-width:180px">'+_escOl(r.reason||'')+'</td>';
    html+='<td style="font-size:10px;color:#8b949e;font-family:monospace">'+(r.t?new Date(r.t).toLocaleString('vi-VN'):'')+'</td>';
    html+='<td><button onclick="_unbanOl(\\''+_escOl(r.olm)+'\\')" style="background:linear-gradient(135deg,#00b09b,#96c93d)">🔓 UNBAN</button></td>';
    html+='</tr>';
  });
  tb.innerHTML=html;
}
function _refreshOl(){ fetch('${ADMIN_PATH}/olm-bans.json').then(function(r){return r.json();}).then(function(d){_renderOl(d);setTimeout(_refreshOl,5000);}).catch(function(){setTimeout(_refreshOl,5000);}); }
_refreshOl();
</script>
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
<form method="POST" action="${ADMIN_PATH}/unban-all" style="margin-bottom:10px" onsubmit="return confirm('Mở khoá TẤT CẢ IP/thiết bị bị khoá + xóa cache IP? Các thiết bị bị khoá nhầm sẽ hoạt động lại ngay.')"><button type="submit" style="background:linear-gradient(135deg,#00b09b,#96c93d);padding:10px 20px;font-size:13px;font-weight:bold">🔓 MỞ KHOÁ TẤT CẢ (reset thiết bị bị khoá)</button></form>
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
 <a href="${ADMIN_PATH}/devices" style="color:#4facfe;text-decoration:none;font-size:11px;border:1px solid rgba(79,172,254,.4);padding:4px 10px;border-radius:6px;margin-left:10px">📱 Xem tab Thiết bị & OLM & Môn →</a>
${devices.size === 0 ? '<div style="font-size:12px;color:#8b949e;padding:8px">Chưa có thiết bị nào xác thực thành công.</div>' : `<table><thead><tr><th>HWID</th><th>Tên máy</th><th>Hệ điều hành</th><th>IP cuối</th><th>Lần cuối</th></tr></thead><tbody>${devRows}</tbody></table>`}
</div>

<div class="panel">
<h2>📜 LOG GẦN NHẤT (có tên máy gửi lên server)</h2>
<table><thead><tr><th>Thời gian</th><th>Loại</th><th>Tên máy</th><th>HWID</th><th>IP</th><th>OK</th><th>OLM User</th><th>Chi tiết</th></tr></thead>
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
// [v10] ===== TAB THIẾT BỊ + TÀI KHOẢN OLM + MÔN ĐANG LÀM =====
function adminDevicesPage() {
    return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>📱 Thiết bị & OLM — GOD MODE Admin</title><style>
*{box-sizing:border-box}body{margin:0;background:#0d1117;font-family:'Segoe UI',system-ui,sans-serif;color:#c9d1d9;padding:20px}
.wrap{max-width:1200px;margin:0 auto}
.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:8px}
h1{font-size:18px;margin:0;background:linear-gradient(90deg,#00f2fe,#4facfe);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
a.back{color:#4facfe;text-decoration:none;font-size:12px;border:1px solid rgba(79,172,254,.4);padding:6px 12px;border-radius:6px}
a.logout{color:#ef233c;text-decoration:none;font-size:12px;border:1px solid rgba(239,35,60,.4);padding:6px 12px;border-radius:6px}
.panel{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;margin-bottom:16px}
.panel h2{font-size:13px;margin:0 0 12px;color:#00f2fe;text-transform:uppercase;letter-spacing:1px}
.stats{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:14px}
.stat{background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:10px 16px;font-size:12px}
.stat .n{font-size:20px;font-weight:900;font-family:monospace}
.stat.info .n{color:#4facfe}.stat.ok .n{color:#00e676}
table{width:100%;border-collapse:collapse;font-size:11px}
th,td{padding:7px 8px;text-align:left;border-bottom:1px solid #21262d;vertical-align:top}
th{color:#8b949e;font-size:10px;text-transform:uppercase;letter-spacing:.5px;position:sticky;top:0;background:#161b22}
.mono{font-family:monospace;font-size:10px;word-break:break-all}
.empty{text-align:center;color:#8b949e;padding:24px;font-size:12px}
.hint{font-size:10px;color:#8b949e;margin-top:8px;line-height:1.6}
#refresh-ind{font-size:10px;color:#00e676;font-family:monospace}
.badge{padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;font-family:monospace;background:rgba(79,172,254,.15);color:#4facfe;border:1px solid rgba(79,172,254,.4)}
</style></head><body><div class="wrap">
<div class="top">
<h1>📱 THIẾT BỊ & TÀI KHOẢN OLM & MÔN ĐANG LÀM</h1>
<div style="display:flex;gap:8px;align-items:center">
<span id="refresh-ind">● tự động refresh mỗi 5s</span>
<a class="back" href="${ADMIN_PATH}/dashboard">⬅ VỀ DASHBOARD</a>
<a class="logout" href="${ADMIN_PATH}/logout">🚪 Đăng xuất</a>
</div>
</div>
<div class="stats">
<div class="stat info"><div class="n" id="st-dev">—</div><div>Thiết bị hoạt động</div></div>
<div class="stat ok"><div class="n" id="st-olm">—</div><div>Có tài khoản OLM</div></div>
</div>
<div class="panel">
<h2>📋 DANH SÁCH (tự động cập nhật)</h2>
<table><thead><tr>
<th>Tên máy</th><th>HWID</th><th>IP</th><th>Tài khoản OLM</th><th>Môn (id_cate)</th><th>Chế độ làm bài</th><th>Lần hoạt động cuối</th>
</tr></thead><tbody id="tbody"><tr><td colspan="7" class="empty">Đang tải...</td></tr></tbody></table>
<div class="hint">💡 Cột <b>Tài khoản OLM</b> được ghi nhận khi user đăng nhập key (gửi kèm olm_user). Cột <b>Môn (id_cate)</b> + <b>Chế độ</b> được ghi nhận khi user nộp bài (/fire) — id_cate là mã môn của OLM. Thiết bị không hoạt động quá 24h tự biến mất.</div>
</div>
</div>
<script>
function fmt(t){try{return new Date(t).toLocaleString('vi-VN');}catch(e){return '';}}
function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function modeLabel(m){ if(!m) return '—'; if(m==='exam') return '📝 Kiểm tra (exam)'; if(m==='video') return '🎬 Video'; return '✏️ Luyện tập (practice)'; }
function render(d){
  document.getElementById('st-dev').textContent = d.count||0;
  document.getElementById('st-olm').textContent = d.withOlm||0;
  var tb = document.getElementById('tbody');
  var list = d.list||[];
  if(!list.length){ tb.innerHTML = '<tr><td colspan="7" class="empty">✅ Chưa có thiết bị nào hoạt động. Khi user đăng nhập key & nộp bài sẽ hiện ở đây.</td></tr>'; return; }
  var html = '';
  list.forEach(function(r){
    html += '<tr>';
    html += '<td style="color:#00f2fe">'+esc(r.device||'')+'</td>';
    html += '<td class="mono">'+esc(r.hwid||'')+'</td>';
    html += '<td class="mono" style="color:#ffc107">'+esc(r.ip||'')+'</td>';
    html += '<td class="mono" style="color:#fca5a5;font-weight:700">'+(r.olm_user?esc(r.olm_user):'<span style="color:#8b949e">— chưa gửi</span>')+'</td>';
    html += '<td class="mono">'+(r.id_cate?('<span class="badge">'+esc(r.id_cate)+'</span>'):'<span style="color:#8b949e">—</span>')+'</td>';
    html += '<td style="font-size:10px">'+modeLabel(r.mode)+'</td>';
    html += '<td class="mono">'+fmt(r.lastSeen)+'</td>';
    html += '</tr>';
  });
  tb.innerHTML = html;
}
function refresh(){
  fetch('${ADMIN_PATH}/api/devices')
    .then(function(r){return r.json();})
    .then(function(d){ render(d); setTimeout(refresh, 5000); })
    .catch(function(){ setTimeout(refresh, 5000); });
}
refresh();
</script>
</body></html>`;
}
app.get(ADMIN_PATH + '/devices', (req, res) => { if (!requireAdmin(req, res)) return; res.send(adminDevicesPage()); });
app.get(ADMIN_PATH + '/api/devices', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const now = Date.now();
    const DAY = 24 * 3600 * 1000;
    const list = [];
    let withOlm = 0;
    // gop deviceActivity + devices map
    const all = new Set();
    deviceActivity.forEach((v, k) => all.add(k));
    devices.forEach((v, k) => all.add(k));
    all.forEach(hwid => {
        const act = deviceActivity.get(hwid) || {};
        const dev = devices.get(hwid) || {};
        const lastSeen = act.lastSeen || dev.lastSeen || 0;
        if (lastSeen && now - lastSeen > DAY) return; // qua 24h -> bo qua
        if (act.olm_user) withOlm++;
        list.push({ hwid, device: act.device || dev.name || '', ip: act.ip || dev.ip || '', olm_user: act.olm_user || '', id_cate: act.id_cate || '', mode: act.mode || '', id_user: act.id_user || '', lastSeen });
    });
    list.sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0));
    res.json({ list: list.slice(0, 200), count: list.length, withOlm });
});
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
    else if (flag === 'blockVmScript') { BLOCK_VM_SCRIPT = !BLOCK_VM_SCRIPT; msg = BLOCK_VM_SCRIPT ? '✅ Đã BẬT SMART_VM_BLOCK: chỉ chặn VM/proxy/datacenter/desktop; Android/iOS thật vẫn kéo code bình thường.' : '⚠️ Đã TẮT chặn (mọi người đều kéo code được, HARD_DC_BAN vẫn tự chặn datacenter).'; }

    else if (flag === 'blockModule10') { BLOCK_MODULE_10 = !BLOCK_MODULE_10; msg = BLOCK_MODULE_10 ? '✅ Đã BẬT chặn module chuẩn bị 10 điểm (KHÔNG gửi xuống script).' : '⚠️ Đã TẮT chặn (module 10 điểm gửi xuống bình thường).'; }
    else if (flag === 'hardDcBan') { HARD_DC_BAN = !HARD_DC_BAN; msg = HARD_DC_BAN ? '✅ Đã BẬT HARD_DC_BAN (IP datacenter/proxy gọi API → BAN NGAY).' : '⚠️ Đã TẮT HARD_DC_BAN.'; }
    else if (flag === 'safeMode') { SAFE_MODE = !SAFE_MODE; msg = SAFE_MODE ? '✅ Đã BẬT SAFE_MODE: auto-ban chỉ log + từ chối, KHÔNG khoá vĩnh viễn (an toàn, tránh ban nhầm).' : '⚠️ Đã TẮT SAFE_MODE — auto-ban sẽ khoá vĩnh viễn IP/thiết bị (dễ ban nhầm nhà mạng CGNAT).'; }
    else if (flag === 'smartBan') { SMART_BAN = !SMART_BAN; msg = SMART_BAN ? '✅ Đã BẬT SMART_BAN: chỉ ban máy ảo/proxy ảo xác nhận; máy thật Android/iOS KHÔNG bao giờ bị ban + tự mở ban.' : '⚠️ Đã TẮT SMART_BAN — dùng quy tắc ban cũ (dễ ban nhầm).'; }
    else if (flag === 'dumperGuard') { DUMPER_GUARD = !DUMPER_GUARD; msg = DUMPER_GUARD ? '✅ Đã BẬT DUMPER_GUARD (phát hiện dump → ban key+hwid+ip).' : '⚠️ Đã TẮT DUMPER_GUARD.'; }
    else if (flag === 'moduleWatermark') { MODULE_WATERMARK = !MODULE_WATERMARK; msg = MODULE_WATERMARK ? '✅ Đã BẬT watermark truy vết module.' : '⚠️ Đã TẮT watermark.'; }
    else if (flag === 'bankey') { const kk = String(req.body.key || '').trim().toUpperCase(); if (kk) { BANNED_KEYS.add(kk); kvSaveState(); msg = '🔨 Đã KHOÁ key ' + maskKey(kk) + ' — mọi thiết bị dùng key này bị 404.'; } else msg = 'Thiếu key để khoá.'; }
    else if (flag === 'unbankey') { const uk = String(req.body.key || '').trim().toUpperCase(); if (uk && BANNED_KEYS.delete(uk)) { kvSaveState(); msg = '🔓 Đã MỞ KHOÁ key ' + maskKey(uk) + '.'; } else msg = 'Không tìm thấy key để mở khoá.'; }
    kvSaveState();
    adminLog('admin', { action: 'toggle:' + flag, value: flag === 'autoBan' ? AUTO_BAN : flag === 'mobileOnly' ? MOBILE_ONLY : flag === 'banDesktop' ? BAN_DESKTOP : flag === 'blockVmScript' ? BLOCK_VM_SCRIPT : flag === 'blockModule10' ? BLOCK_MODULE_10 : flag === 'hardDcBan' ? HARD_DC_BAN : flag === 'safeMode' ? SAFE_MODE : flag === 'smartBan' ? SMART_BAN : flag === 'dumperGuard' ? DUMPER_GUARD : flag === 'moduleWatermark' ? MODULE_WATERMARK : (req.body.key || ''), ip: getClientIp(req) });
    res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent(msg));
});

// Mở khoá (unban)
app.post(ADMIN_PATH + '/unban', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const key = String((req.body && req.body.key) || '').trim();
    if (key) { removeBan(key); adminLog('admin', { action: 'unban', target: key, ip: getClientIp(req) }); }
    res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent('✅ Đã mở khoá: ' + key));
});

// [v13] MỞ KHOÁ TẤT CẢ — reset toàn bộ IP/thiết bị bị khoá (gỡ ban nhầm) + xóa cache IP
app.post(ADMIN_PATH + '/unban-all', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const n = banned.size;
    banned.clear();            // gỡ toàn bộ ban IP + HWID
    ipCache.clear();           // xóa cache IP → check lại từ đầu, không dùng kết quả nhận nhầm cũ
    keyActivity.clear();       // reset theo dõi dumper (trạng thái cũ có thể do nhận nhầm)
    lockedScripts.clear();     // [v13] mở khoá luôn các script bị khoá do phát hiện nhầm
    // Giữ nguyên BANNED_KEYS (key admin revokle chủ động) và olmBans (ban tài khoản OLM có chủ đích)
    kvSaveState();
    adminLog('admin', { action: 'unban-all', cleared: n, ip: getClientIp(req) });
    res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent('✅ Đã MỞ KHOÁ TẤT CẢ (' + n + ' IP/thiết bị). Cache IP đã xóa — mọi thiết bị bị khoá nhầm đã hoạt động lại.'));
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

// [v9] ===== ADMIN: BAN / UNBAN TAI KHOAN OLM =====
app.post(ADMIN_PATH + '/olm-ban', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const olm = String((req.body && req.body.olm_user) || '').trim();
    const unit = String((req.body && req.body.unit) || 'day'); // minute|day|month|permanent
    const val = parseFloat((req.body && req.body.value) || '1');
    const reason = String((req.body && req.body.reason) || 'vi pham dieu khoan').trim();
    if (!olm) return res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent('❌ Thiếu tài khoản OLM!'));
    let minutes;
    if (unit === 'permanent') minutes = -1;
    else if (unit === 'minute') minutes = Math.max(1, val);
    else if (unit === 'month') minutes = Math.max(1, val) * 30 * 24 * 60;
    else minutes = Math.max(1, val) * 24 * 60; // day (mac dinh)
    addOlmBan(olm, minutes, reason, 'admin');
    const unitLabel = unit === 'permanent' ? 'vinh vien' : (unit === 'minute' ? 'phut' : unit === 'month' ? 'thang' : 'ngay');
    adminLog('admin', { action: 'olm-ban', olm: normOlm(olm), unit, value: val, minutes, reason, ip: getClientIp(req) });
    res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent('✅ Đã BAN tài khoản OLM: ' + olm + ' (' + (unit === 'permanent' ? 'VĨNH VIỄN' : (val + ' ' + unitLabel)) + ')'));
});
app.post(ADMIN_PATH + '/olm-unban', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const olm = String((req.body && req.body.olm_user) || '').trim();
    if (!olm) return res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent('❌ Thiếu tài khoản OLM!'));
    const had = removeOlmBan(olm);
    adminLog('admin', { action: 'olm-unban', olm: normOlm(olm), had, ip: getClientIp(req) });
    res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent(had ? '✅ Đã UNBAN tài khoản OLM: ' + olm : '⚠️ Không tìm thấy tài khoản: ' + olm));
});
app.get(ADMIN_PATH + '/olm-bans.json', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const list = [...olmBans.entries()].map(([k, v]) => {
        const ob = checkOlmBan(k); // tu go ban het han
        return { olm: k, reason: v.reason, until: v.until, permanent: !v.until, t: v.t, by: v.by, remain: ob ? ob.remain : 'đã hết hạn' };
    }).filter(x => x.remain !== 'đã hết hạn');
    res.json({ list, count: list.length });
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
app.use((_req, res) => res.status(404).json({ success: false, error: 'Not found', message: 'Endpoint không tồn tại hoặc yêu cầu bị từ chối.' }));
// Error handler
app.use((err, _req, res, _next) => { console.error('[server-error]', err && err.message ? err.message : err); res.status(500).json({ success: false, error: 'Internal server error' }); });

// ─── Start / Export ──────────────────────────────────────────────────────────
if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`\n🚀 GOD MODE Server v18.0 (server-authoritative slim) running → http://localhost:${PORT}`);
        console.log(`   Ẩn API prefix: ${API_PREFIX}`);
        console.log(`   Admin: ${ADMIN_PATH} (${ADMIN_USER})`);
        console.log(`   Lưu trữ bền vững (KV): ${KV_ENABLED ? 'CÓ' : 'KHÔNG — đặt env KV_REST_API_URL + KV_REST_API_TOKEN để ban/mật khẩu tồn tại qua restart'}`);
        // [v13] Cảnh báo SAFE_MODE / HARD_DC_BAN trạng thái
        if (SAFE_MODE) console.log('\x1b[32m[v13 SAFE_MODE ĐANG BẬT] Auto-ban chỉ log + từ chối, KHÔNG khoá vĩnh viễn — không còn ban nhầm IP thật. Tắt: env SAFE_MODE=false hoặc panel admin.\x1b[0m');
        else console.log('\x1b[33m[v13] CẢNH BÁO: SAFE_MODE đang TẮT — auto-ban sẽ khoá vĩnh viễn, dễ ban nhầm IP nhà mạng di động (CGNAT).\x1b[0m');
        if (!HARD_DC_BAN) console.log('\x1b[33m[v13] HARD_DC_BAN đang TẮT (kill-switch). Bật trong panel admin nếu muốn chặn cứng IP datacenter.\x1b[0m');
        if (SMART_BAN) console.log('\x1b[32m[v14 SMART_BAN ĐANG BẬT] Chi ban may ao/emulator/proxy xac nhan; may that Android/iOS KHONG bao gio bi ban + tu mo ban tu dong.\x1b[0m');
        else console.log('\x1b[33m[v14] SMART_BAN dang TAT — de ban thong minh, bat lai trong panel admin.\x1b[0m');
        if (SMART_BAN) console.log('\x1b[36m[v15] AUTO_UNLOCK_REAL_IP: IP that cua Android/iOS tu dong mo khoa ngay khi ket noi — khong can admin thao tac.\x1b[0m');
        if (!BLOCK_VM_SCRIPT) console.warn('\x1b[33m   [SECURITY v12] SMART_VM_BLOCK dang TAT — vao admin panel BAT de chi cho Android/iOS that keo code (chan VM/proxy/desktop, KHONG anh huong user that).\x1b[0m');
        if (BLOCK_VM_SCRIPT) console.log('\x1b[32m   [SECURITY v12] SMART_VM_BLOCK dang BAT: chi chan VM/proxy/datacenter/desktop, Android/iOS that van hoat dong binh thuong.\x1b[0m');
        if (SECRET === DEFAULT_SECRET) console.warn('\x1b[31m   [SECURITY] SECRET MAC DINH DA ROI ROI — dat env GODMODE_SECRET (64 hex) NGAY.\x1b[0m');
    });
}
module.exports = app;
