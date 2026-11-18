/**
 * ======================================================
 *  GOD MODE v8.0 — BACKEND SERVER (SELF-CONTAINED LOADER)
 *  - [v8] TOÀN BỘ code connector (chức năng userscript) được NHÚNG sẵn
 *    trong server (CONNECTOR_MODULE_EMBEDDED_B64) → không cần file ngoài.
 *  - [v8] Endpoint ẩn GET <API_PREFIX>/bootstrap.js trả connector mã hoá
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
// [v8] CONNECTOR NHÚNG SẴN trong server (base64) → self-contained, không cần file ngoài.
// Vẫn ưu tiên: env CONNECTOR_MODULE_SRC > file ./connector.module.js > embedded.
const CONNECTOR_MODULE_EMBEDDED_B64 = 'Ly8g4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQCi8vICBDT05ORUNUT1IgTU9EVUxFIChwaOG7pWMgduG7pSB04burIFNFUlZFUikg4oCUIGLhuqNuIHY2LjUuNC1mdWxsCi8vICBUb8OgbiBi4buZIGNo4bupYyBuxINuZyB1c2Vyc2NyaXB0IG7hurFtIOG7nyDEkcOieS4gU2VydmVyIHThu7EgaW5qZWN0Ci8vICBTRVJWRVJfQkFTRSArIEFQSV9TRUNSRVQga2hpIHBo4bulYyB24bulIC9ib290c3RyYXAuanMuCi8vICBMb2FkZXIgKGxvYWRlci51c2VyLmpzKSBjaOG7iSB2aeG7h2MgdOG6o2kg4oaSIGdp4bqjaSBtw6Mg4oaSIGNo4bqheS4KLy8g4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQCgovLyDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZAKLy8gIMSQ4buUSSAyIEdJw4EgVFLhu4ogTsOAWSBjaG8ga2jhu5twIHbhu5tpIHNlcnZlciBj4bunYSBi4bqhbjoKLy8g4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQCmNvbnN0IFNFUlZFUl9CQVNFID0gJ2h0dHBzOi8vbW9kZ2FtZS52ZXJjZWwuYXBwJzsgIC8vIOKaoO+4jyDEkOG7lEkgdGjDoG5oIFVSTCBzZXJ2ZXIgVmVyY2VsIGPhu6dhIGLhuqFuCmNvbnN0IEFQSV9TRUNSRVQgID0gJ2E3ZjNjOWUxYjJkNDg1MDZmYWUxYzdkM2I5ZjBlMmE0YzZkOGYxYTNiNWU3YzlkMGYyYTRjNmU4YjFkM2Y1YTcnOyAgLy8g4pqg77iPIMSQ4buUSSBraOG7m3AgZW52IEdPRE1PREVfU0VDUkVUIHRyw6puIHNlcnZlcgovLyDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZAKLy8gW3Y1XSBNw6MgaG/DoSByZXF1ZXN0IGJvZHkg4oCUIMSR4buVaSB0cnVlIFNBVSBLSEkgc2VydmVyIGjhu5cgdHLhu6MgZ2nhuqNpIG3DoyB2NQpjb25zdCBSRVFVRVNUX0VOQ1JZUFRJT04gPSBmYWxzZTsKLy8g4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQCgo7KGZ1bmN0aW9uICgpIHsKICAgICd1c2Ugc3RyaWN0JzsKCiAgICAvLyDilIDilIDilIAgU3RvcmFnZSBrZXkg4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSACiAgICBjb25zdCBMU19LRVkgICAgICAgPSAnX3RsX2Nvbm5fa2V5JzsKICAgIGNvbnN0IExTX1RZUEUgICAgICA9ICdfdGxfY29ubl90eXBlJzsKICAgIGNvbnN0IExTX0VYUCAgICAgICA9ICdfdGxfY29ubl9leHAnOwogICAgY29uc3QgTFNfVEhFTUUgICAgID0gJ190aWVwX3RoZW1lJzsKICAgIGxldCAgIENVUlJFTlRfS0VZICA9IG51bGw7CiAgICBsZXQgICBLRVlfU1RBVFVTICAgPSB7IHZhbGlkOiBmYWxzZSwgdHlwZTogbnVsbCwgZXhwaXJlc19hdDogbnVsbCB9OwogICAgbGV0ICAgQ1VSUkVOVF9ERVZJQ0UgPSAnJzsgLy8gW3Y0XSB0w6puIG3DoXkgKGzhuqV5IHThu6sgc2VydmVyIHNhdSBhdHRlc3QpCgogICAgLy8g4pSA4pSA4pSAIFNFU1NJT04gKGRhdGEgY2FwdHVyZWQgZnJvbSBYSFIpIOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgAogICAgY29uc3QgU0VTU0lPTiA9IHsKICAgICAgICByYXdfcXVlc3Rpb25zOiBbXSwKICAgICAgICBtZXRhOiB7IGlkX3VzZXI6IG51bGwsIGlkX2NhdGU6IG51bGwsIGlkX2NvdXJzZXdhcmU6IG51bGwsCiAgICAgICAgICAgICAgICBpZF9zY2hvb2w6IG51bGwsIGlkX2dyb3VwOiBudWxsLCBjc3JmX3Rva2VuOiBudWxsIH0sCiAgICAgICAgYXV0b19tb2RlOiAgICAncHJhY3RpY2UnLAogICAgICAgIHZpZGVvX2xlbmd0aDogOTAwCiAgICB9OwoKICAgIC8vIOKUgOKUgOKUgCBUaGVtZSDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIAKICAgIGxldCBDVVJSRU5UX1RIRU1FID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oTFNfVEhFTUUpIHx8ICdkZWZhdWx0JzsKCiAgICAvLyDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZAKICAgIC8vICBbdjQuMV0gS0nhu4JNIFRSQSBMT+G6oEkgS0VZIOKAlCBHSeG7kE5HIFYzIENPUkUKICAgIC8vIOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkAogICAgZnVuY3Rpb24gaXNQcmVtaXVtS2V5KCkgewogICAgICAgIGNvbnN0IHQgPSAoS0VZX1NUQVRVUy50eXBlIHx8IF9zTFMuZ2V0KExTX1RZUEUpIHx8ICcnKS50b1N0cmluZygpLnRvVXBwZXJDYXNlKCk7IC8vIFt2NV0gb2JmdXNjYXRlZCByZWFkCiAgICAgICAgcmV0dXJuIHQgPT09ICdQUkVNSVVNJyB8fCB0ID09PSAnVklQJyB8fCB0ID09PSAnVU5MSU1JVEVEJzsKICAgIH0KCiAgICAvLyDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZAKICAgIC8vICBbdjQuMV0gWOG7rCBMw50gT0xNIEFDQ09VTlQgTUlTTUFUQ0gKICAgIC8vIOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkAogICAgZnVuY3Rpb24gaGFuZGxlT2xtTWlzbWF0Y2goc2VydmVyT2xtLCBjdXJyZW50T2xtKSB7CiAgICAgICAgLy8gWMOzYSBrZXkga2jhu49pIGLhu5kgbmjhu5sgdsOgIGxvY2FsU3RvcmFnZQogICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKExTX0tFWSk7CiAgICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oTFNfVFlQRSk7CiAgICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oTFNfRVhQKTsKICAgICAgICBDVVJSRU5UX0tFWSAgICA9IG51bGw7CiAgICAgICAgS0VZX1NUQVRVUyAgICAgPSB7IHZhbGlkOiBmYWxzZSwgdHlwZTogbnVsbCwgZXhwaXJlc19hdDogbnVsbCB9OwogICAgICAgIF9zZWNTZXNzaW9uICAgID0geyB0b2tlbjogbnVsbCwgZXhwOiAwLCBmcEhhc2g6IG51bGwsIHNlcTogMSB9OwogICAgICAgIENVUlJFTlRfREVWSUNFID0gJyc7CgogICAgICAgIC8vIFjDs2EgcGFuZWwgVUkgbuG6v3UgxJFhbmcgaGnhu4duCiAgICAgICAgY29uc3QgcGFuZWxFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1wYW5lbCcpOwogICAgICAgIGNvbnN0IGZiICAgICAgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtZmxvYXRCdG4nKTsKICAgICAgICBpZiAocGFuZWxFbCkgcGFuZWxFbC5yZW1vdmUoKTsKICAgICAgICBpZiAoZmIpICAgICAgZmIucmVtb3ZlKCk7CgogICAgICAgIC8vIEhp4buHbiBtb2RhbCB0aMO0bmcgYsOhbyBy4buTaSBxdWF5IGzhuqFpIHRyYW5nIMSRxINuZyBuaOG6rXAga2V5CiAgICAgICAgc2hvd0N1c3RvbU1vZGFsKHsKICAgICAgICAgICAgaWNvbjogICfwn5qrJywKICAgICAgICAgICAgdGl0bGU6ICdUw4BJIEtIT+G6ok4gT0xNIEtIw5RORyBLSOG7mlAhJywKICAgICAgICAgICAgbGluZXM6IFsKICAgICAgICAgICAgICAgIGBLZXkgxJHGsOG7o2MgxJHEg25nIGvDvSBjaG8gdMOgaSBraG/huqNuOiA8Yj4ke3NlcnZlck9sbX08L2I+YCwKICAgICAgICAgICAgICAgIGBUw6BpIGtob+G6o24gT0xNIGhp4buHbiB04bqhaTogPGI+JHtjdXJyZW50T2xtfTwvYj5gLAogICAgICAgICAgICAgICAgYOKaoO+4jyBWdWkgbMOybmcgxJHEg25nIG5o4bqtcCDEkcO6bmcgdMOgaSBraG/huqNuIE9MTSDEkeG7gyBz4butIGThu6VuZyBrZXkgbsOgeSxgLAogICAgICAgICAgICAgICAgYGhv4bq3YyBsacOqbiBo4buHIGFkbWluIMSR4buDIMSRxrDhu6NjIGjhu5cgdHLhu6MhYAogICAgICAgICAgICBdLAogICAgICAgICAgICBvbk9rOiAoKSA9PiBidWlsZExvY2tTY3JlZW4oJ+KaoO+4jyBUw6BpIGtob+G6o24gT0xNIGtow7RuZyBraOG7m3AgduG7m2kga2V5IMSRw6MgxJHEg25nIGvDvSEnKQogICAgICAgIH0pOwogICAgfQoKICAgIC8vIOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkAogICAgLy8gIEjhu4YgVEjhu5BORyBHSUFPIERJ4buGTiBUSEVPIENI4bumIMSQ4buAIChUSEVNRSkg4oCUIGdp4buRbmcgY29yZSB2My4yCiAgICAvLyDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZAKICAgIGZ1bmN0aW9uIGdldFRoZW1lQ29sb3JzKHRoZW1lKSB7CiAgICAgICAgY29uc3QgVCA9IHsKICAgICAgICAgICAgZGVmYXVsdDogewogICAgICAgICAgICAgICAgYzE6JyMwMGYyZmUnLCBjMjonIzRmYWNmZScsCiAgICAgICAgICAgICAgICBiZ092ZXJsYXk6J3JnYmEoMTMsMTcsMjMsMC45NSknLCBiZ1BhbmVsOidyZ2JhKDEzLDE3LDIzLDAuODgpJywKICAgICAgICAgICAgICAgIGJvcmRlcjoncmdiYSgwLDI0MiwyNTQsMC4yKScsIGJvcmRlclN0cm9uZzoncmdiYSgwLDI0MiwyNTQsMC4zKScsCiAgICAgICAgICAgICAgICBib3JkZXJTdWJ0bGU6J3JnYmEoMCwyNDIsMjU0LDAuMTIpJywKICAgICAgICAgICAgICAgIGhlYWRlckJnOidsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLHJnYmEoMCwyNDIsMjU0LDAuMDcpLHJnYmEoNzksMTcyLDI1NCwwLjA0KSknLAogICAgICAgICAgICAgICAgZ2xvd0NvbG9yOidyZ2JhKDAsMjQyLDI1NCwwLjQ1KScsIGdsb3dTdHJvbmc6J3JnYmEoMCwyNDIsMjU0LDAuNyknLAogICAgICAgICAgICAgICAgZ2xvd01pZDoncmdiYSgwLDI0MiwyNTQsMC4yNSknLCBnbG93U3VidGxlOidyZ2JhKDAsMjQyLDI1NCwwLjA4KScsCiAgICAgICAgICAgICAgICBnbG93UHVsc2U6J3JnYmEoMCwyNDIsMjU0LDAuNTUpJywKICAgICAgICAgICAgICAgIGlucHV0Qm9yZGVyOidyZ2JhKDAsMjQyLDI1NCwwLjQpJywgaW5wdXRDb2xvcjonIzAwZjJmZScsCiAgICAgICAgICAgICAgICBmbG9hdEdyYWRpZW50OidsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLCMwMGYyZmUsIzRmYWNmZSknLAogICAgICAgICAgICAgICAgYnJhbmRHcmFkaWVudDonbGluZWFyLWdyYWRpZW50KDkwZGVnLCMwMGYyZmUsIzRmYWNmZSwjMDBmMmZlKScsCiAgICAgICAgICAgICAgICBzdGF0dXNCb3JkZXI6J3JnYmEoMCwyMzAsMTIwLDAuMjUpJywgc3RhdHVzQmc6J3JnYmEoMCwyMzAsMTIwLDAuMDQpJywKICAgICAgICAgICAgICAgIHBhbmVsSW5zZXQ6J3JnYmEoMCwyNDIsMjU0LDAuMDgpJywKICAgICAgICAgICAgICAgIHNlbGVjdEJvcmRlcjoncmdiYSgwLDI0MiwyNTQsMC4yKScsIGNvbnNvbGVCb3JkZXI6J3JnYmEoMCwyNDIsMjU0LDAuMTIpJywKICAgICAgICAgICAgICAgIGZ4Q1NTOicnLCBwYW5lbEV4dHJhOicnLAogICAgICAgICAgICAgICAgdGhlbWVMYWJlbDon8J+UtSBN4bq3YyDEkOG7i25oJywKICAgICAgICAgICAgICAgIHByZXZpZXdCZzonbGluZWFyLWdyYWRpZW50KDEzNWRlZywjMDAxNTIwLCMwMGYyZmU1NSknLAogICAgICAgICAgICAgICAgcHJldmlld0JvcmRlcjoncmdiYSgwLDI0MiwyNTQsMC41KScsCiAgICAgICAgICAgICAgICBwcmV2aWV3VGV4dDonIzAwZjJmZScsCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIGdyYXk6IHsKICAgICAgICAgICAgICAgIGMxOicjZTBlMGUwJywgYzI6JyNhMGEwYTAnLAogICAgICAgICAgICAgICAgYmdPdmVybGF5OidyZ2JhKDEwLDEwLDEwLDAuOTcpJywgYmdQYW5lbDoncmdiYSgyMCwyMCwyMCwwLjk0KScsCiAgICAgICAgICAgICAgICBib3JkZXI6J3JnYmEoMjAwLDIwMCwyMDAsMC4xOCknLCBib3JkZXJTdHJvbmc6J3JnYmEoMjMwLDIzMCwyMzAsMC4zKScsCiAgICAgICAgICAgICAgICBib3JkZXJTdWJ0bGU6J3JnYmEoMTcwLDE3MCwxNzAsMC4xKScsCiAgICAgICAgICAgICAgICBoZWFkZXJCZzonbGluZWFyLWdyYWRpZW50KDEzNWRlZyxyZ2JhKDEyMCwxMjAsMTIwLDAuMTIpLHJnYmEoNjAsNjAsNjAsMC4wNSkpJywKICAgICAgICAgICAgICAgIGdsb3dDb2xvcjoncmdiYSgyMTAsMjEwLDIxMCwwLjM1KScsIGdsb3dTdHJvbmc6J3JnYmEoMjIwLDIyMCwyMjAsMC42KScsCiAgICAgICAgICAgICAgICBnbG93TWlkOidyZ2JhKDIwMCwyMDAsMjAwLDAuMiknLCBnbG93U3VidGxlOidyZ2JhKDE2MCwxNjAsMTYwLDAuMDcpJywKICAgICAgICAgICAgICAgIGdsb3dQdWxzZToncmdiYSgyMDAsMjAwLDIwMCwwLjQ1KScsCiAgICAgICAgICAgICAgICBpbnB1dEJvcmRlcjoncmdiYSgyMDAsMjAwLDIwMCwwLjM4KScsIGlucHV0Q29sb3I6JyNkOGQ4ZDgnLAogICAgICAgICAgICAgICAgZmxvYXRHcmFkaWVudDonbGluZWFyLWdyYWRpZW50KDEzNWRlZywjYzBjMGMwLCM2NjYpJywKICAgICAgICAgICAgICAgIGJyYW5kR3JhZGllbnQ6J2xpbmVhci1ncmFkaWVudCg5MGRlZywjYzBjMGMwLCNmZmZmZmYsI2QwZDBkMCwjYzBjMGMwKScsCiAgICAgICAgICAgICAgICBzdGF0dXNCb3JkZXI6J3JnYmEoMTYwLDE2MCwxNjAsMC4yKScsIHN0YXR1c0JnOidyZ2JhKDYwLDYwLDYwLDAuMDcpJywKICAgICAgICAgICAgICAgIHBhbmVsSW5zZXQ6J3JnYmEoMjAwLDIwMCwyMDAsMC4wNyknLAogICAgICAgICAgICAgICAgc2VsZWN0Qm9yZGVyOidyZ2JhKDE5MCwxOTAsMTkwLDAuMiknLCBjb25zb2xlQm9yZGVyOidyZ2JhKDE2MCwxNjAsMTYwLDAuMSknLAogICAgICAgICAgICAgICAgZnhDU1M6YAogICAgICAgICAgICAgICAgICAgICN0bC1jb25uLWZ4LWJhciB7IGhlaWdodDoycHg7IGJhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDkwZGVnLHRyYW5zcGFyZW50LHJnYmEoMjU1LDI1NSwyNTUsMC4wOCkscmdiYSgyNTUsMjU1LDI1NSwwLjU1KSxyZ2JhKDI1NSwyNTUsMjU1LDAuMDgpLHRyYW5zcGFyZW50KTsgYmFja2dyb3VuZC1zaXplOjMwMCUgMTAwJTsgYW5pbWF0aW9uOm1ldGFsU3dlZXAgMi44cyBsaW5lYXIgaW5maW5pdGU7IH0KICAgICAgICAgICAgICAgICAgICBAa2V5ZnJhbWVzIG1ldGFsU3dlZXAgeyAwJXtiYWNrZ3JvdW5kLXBvc2l0aW9uOjEwMCUgMH0gMTAwJXtiYWNrZ3JvdW5kLXBvc2l0aW9uOi0yMDAlIDB9IH0KICAgICAgICAgICAgICAgICAgICAjdGwtcGFuZWwgeyBib3gtc2hhZG93OiAwIDAgNjBweCByZ2JhKDAsMCwwLDAuODUpLCAwIDAgMzBweCByZ2JhKDE4MCwxODAsMTgwLDAuMDYpLCBpbnNldCAwIDFweCAwIHJnYmEoMjU1LDI1NSwyNTUsMC4wOCk7IH0KICAgICAgICAgICAgICAgICAgICAjdGwtY29ubi1wYW5lbCB7IGJveC1zaGFkb3c6IDAgMCA2MHB4IHJnYmEoMCwwLDAsMC44NSksIGluc2V0IDAgMXB4IDAgcmdiYSgyNTUsMjU1LDI1NSwwLjA4KTsgfQogICAgICAgICAgICAgICAgYCwKICAgICAgICAgICAgICAgIHBhbmVsRXh0cmE6JzxkaXYgaWQ9InRsLWNvbm4tZngtYmFyIj48L2Rpdj4nLAogICAgICAgICAgICAgICAgdGhlbWVMYWJlbDon4pqrIFjDoW0gQuG6oWMnLAogICAgICAgICAgICAgICAgcHJldmlld0JnOidsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLCMxYTFhMWEsIzY2NiknLAogICAgICAgICAgICAgICAgcHJldmlld0JvcmRlcjoncmdiYSgyMjAsMjIwLDIyMCwwLjQ1KScsCiAgICAgICAgICAgICAgICBwcmV2aWV3VGV4dDonI2UwZTBlMCcsCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHBpbms6IHsKICAgICAgICAgICAgICAgIGMxOicjZmY2ZWI0JywgYzI6JyNmZjE0OTMnLAogICAgICAgICAgICAgICAgYmdPdmVybGF5OidyZ2JhKDE4LDQsMTQsMC45NyknLCBiZ1BhbmVsOidyZ2JhKDI2LDQsMTgsMC45MyknLAogICAgICAgICAgICAgICAgYm9yZGVyOidyZ2JhKDI1NSwxMTAsMTgwLDAuMiknLCBib3JkZXJTdHJvbmc6J3JnYmEoMjU1LDExMCwxODAsMC4zOCknLAogICAgICAgICAgICAgICAgYm9yZGVyU3VidGxlOidyZ2JhKDI1NSwxMTAsMTgwLDAuMTIpJywKICAgICAgICAgICAgICAgIGhlYWRlckJnOidsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLHJnYmEoMjU1LDExMCwxODAsMC4wOSkscmdiYSgyNTUsMjAsMTQ3LDAuMDQpKScsCiAgICAgICAgICAgICAgICBnbG93Q29sb3I6J3JnYmEoMjU1LDExMCwxODAsMC40NSknLCBnbG93U3Ryb25nOidyZ2JhKDI1NSwxMTAsMTgwLDAuNzUpJywKICAgICAgICAgICAgICAgIGdsb3dNaWQ6J3JnYmEoMjU1LDExMCwxODAsMC4yMiknLCBnbG93U3VidGxlOidyZ2JhKDI1NSwyMCwxNDcsMC4wNyknLAogICAgICAgICAgICAgICAgZ2xvd1B1bHNlOidyZ2JhKDI1NSwxMTAsMTgwLDAuNTUpJywKICAgICAgICAgICAgICAgIGlucHV0Qm9yZGVyOidyZ2JhKDI1NSwxMTAsMTgwLDAuNDIpJywgaW5wdXRDb2xvcjonI2ZmYjNkOScsCiAgICAgICAgICAgICAgICBmbG9hdEdyYWRpZW50OidsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLCNmZjZlYjQsI2ZmMTQ5MyknLAogICAgICAgICAgICAgICAgYnJhbmRHcmFkaWVudDonbGluZWFyLWdyYWRpZW50KDkwZGVnLCNmZjZlYjQsI2ZmY2NlOCwjZmYxNDkzLCNmZjZlYjQpJywKICAgICAgICAgICAgICAgIHN0YXR1c0JvcmRlcjoncmdiYSgyNTUsMTEwLDE4MCwwLjIpJywgc3RhdHVzQmc6J3JnYmEoMjU1LDIwLDE0NywwLjA1KScsCiAgICAgICAgICAgICAgICBwYW5lbEluc2V0OidyZ2JhKDI1NSwxMTAsMTgwLDAuMSknLAogICAgICAgICAgICAgICAgc2VsZWN0Qm9yZGVyOidyZ2JhKDI1NSwxMTAsMTgwLDAuMiknLCBjb25zb2xlQm9yZGVyOidyZ2JhKDI1NSwxMTAsMTgwLDAuMTIpJywKICAgICAgICAgICAgICAgIGZ4Q1NTOmAKICAgICAgICAgICAgICAgICAgICAjdGwtcGFuZWwgeyBhbmltYXRpb246c2FrdXJhUGFuZWxHbG93IDNzIGVhc2UtaW4tb3V0IGluZmluaXRlOyB9CiAgICAgICAgICAgICAgICAgICAgI3RsLWNvbm4tcGFuZWwgeyBhbmltYXRpb246c2FrdXJhUGFuZWxHbG93IDNzIGVhc2UtaW4tb3V0IGluZmluaXRlOyB9CiAgICAgICAgICAgICAgICAgICAgQGtleWZyYW1lcyBzYWt1cmFQYW5lbEdsb3cgewogICAgICAgICAgICAgICAgICAgICAgICAwJSwxMDAleyBib3gtc2hhZG93OjAgMCA2MHB4IHJnYmEoMCwwLDAsMC44KSwwIDAgMjVweCByZ2JhKDI1NSwxMTAsMTgwLDAuMSksaW5zZXQgMCAwIDAgMXB4IHJnYmEoMjU1LDExMCwxODAsMC4wNik7IH0KICAgICAgICAgICAgICAgICAgICAgICAgNTAleyBib3gtc2hhZG93OjAgMCA2MHB4IHJnYmEoMCwwLDAsMC44KSwwIDAgNDVweCByZ2JhKDI1NSwxMTAsMTgwLDAuMiksaW5zZXQgMCAwIDAgMXB4IHJnYmEoMjU1LDExMCwxODAsMC4xMik7IH0KICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgLnNha3VyYS1wZXRhbCB7IHBvc2l0aW9uOmFic29sdXRlOyBwb2ludGVyLWV2ZW50czpub25lOyBib3JkZXItcmFkaXVzOjUwJSAwIDUwJSAwOyBiYWNrZ3JvdW5kOnJnYmEoMjU1LDExMCwxODAsMC4yMik7IGFuaW1hdGlvbjpzYWt1cmFEcmlmdCBsaW5lYXIgaW5maW5pdGU7IH0KICAgICAgICAgICAgICAgICAgICBAa2V5ZnJhbWVzIHNha3VyYURyaWZ0IHsgMCV7dHJhbnNmb3JtOnRyYW5zbGF0ZVkoLTEwcHgpIHJvdGF0ZSgwZGVnKTtvcGFjaXR5OjAuN30gMTAwJXt0cmFuc2Zvcm06dHJhbnNsYXRlWSg0MjBweCkgcm90YXRlKDI3MGRlZyk7b3BhY2l0eTowfSB9CiAgICAgICAgICAgICAgICAgICAgI3RsLWNvbm4tZngtcGV0YWxzIHsgcG9zaXRpb246YWJzb2x1dGU7dG9wOjA7bGVmdDowO3JpZ2h0OjA7aGVpZ2h0OjEwMCU7cG9pbnRlci1ldmVudHM6bm9uZTtvdmVyZmxvdzpoaWRkZW47ei1pbmRleDowO2JvcmRlci1yYWRpdXM6MTZweDsgfQogICAgICAgICAgICAgICAgYCwKICAgICAgICAgICAgICAgIHBhbmVsRXh0cmE6YDxkaXYgaWQ9InRsLWNvbm4tZngtcGV0YWxzIj4KICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJzYWt1cmEtcGV0YWwiIHN0eWxlPSJ3aWR0aDo3cHg7aGVpZ2h0OjdweDtsZWZ0OjglO3RvcDotMTBweDthbmltYXRpb24tZHVyYXRpb246My44czthbmltYXRpb24tZGVsYXk6MHM7Ij48L2Rpdj4KICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJzYWt1cmEtcGV0YWwiIHN0eWxlPSJ3aWR0aDo1cHg7aGVpZ2h0OjVweDtsZWZ0OjI4JTt0b3A6LTEwcHg7YW5pbWF0aW9uLWR1cmF0aW9uOjUuMXM7YW5pbWF0aW9uLWRlbGF5OjAuOXM7Ij48L2Rpdj4KICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJzYWt1cmEtcGV0YWwiIHN0eWxlPSJ3aWR0aDo4cHg7aGVpZ2h0OjhweDtsZWZ0OjU1JTt0b3A6LTEwcHg7YW5pbWF0aW9uLWR1cmF0aW9uOjQuNHM7YW5pbWF0aW9uLWRlbGF5OjEuN3M7Ij48L2Rpdj4KICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJzYWt1cmEtcGV0YWwiIHN0eWxlPSJ3aWR0aDo0cHg7aGVpZ2h0OjRweDtsZWZ0Ojc1JTt0b3A6LTEwcHg7YW5pbWF0aW9uLWR1cmF0aW9uOjMuMnM7YW5pbWF0aW9uLWRlbGF5OjAuNHM7Ij48L2Rpdj4KICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJzYWt1cmEtcGV0YWwiIHN0eWxlPSJ3aWR0aDo2cHg7aGVpZ2h0OjZweDtsZWZ0OjkyJTt0b3A6LTEwcHg7YW5pbWF0aW9uLWR1cmF0aW9uOjQuOXM7YW5pbWF0aW9uLWRlbGF5OjIuMXM7Ij48L2Rpdj4KICAgICAgICAgICAgICAgIDwvZGl2PmAsCiAgICAgICAgICAgICAgICB0aGVtZUxhYmVsOifwn4y4IEjhu5NuZyBTYWt1cmEnLAogICAgICAgICAgICAgICAgcHJldmlld0JnOidsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLCMxYTA1MTAsI2ZmNmViNDU1KScsCiAgICAgICAgICAgICAgICBwcmV2aWV3Qm9yZGVyOidyZ2JhKDI1NSwxMTAsMTgwLDAuNTUpJywKICAgICAgICAgICAgICAgIHByZXZpZXdUZXh0OicjZmY2ZWI0JywKICAgICAgICAgICAgfQogICAgICAgIH07CiAgICAgICAgcmV0dXJuIFRbdGhlbWVdIHx8IFQuZGVmYXVsdDsKICAgIH0KCiAgICAvLyA9PT09PT09PT09IENTUyBMT0NLIFNDUkVFTiDigJQgZ2nhu5FuZyBjb3JlID09PT09PT09PT0KICAgIGZ1bmN0aW9uIGdldExvY2tTY3JlZW5TdHlsZXMoKSB7CiAgICAgICAgY29uc3QgdGMgPSBnZXRUaGVtZUNvbG9ycyhDVVJSRU5UX1RIRU1FKTsKICAgICAgICByZXR1cm4gYAogICAgICAgICAgICBAaW1wb3J0IHVybCgnaHR0cHM6Ly9mb250cy5nb29nbGVhcGlzLmNvbS9jc3MyP2ZhbWlseT1PcmJpdHJvbjp3Z2h0QDQwMDs3MDA7OTAwJmZhbWlseT1TaGFyZStUZWNoK01vbm8mZmFtaWx5PVJhamRoYW5pOndnaHRANDAwOzYwMDs3MDAmZGlzcGxheT1zd2FwJyk7CiAgICAgICAgICAgICN0bC1jb25uLW92ZXJsYXkgeyBwb3NpdGlvbjpmaXhlZDt0b3A6MDtsZWZ0OjA7d2lkdGg6MTAwdnc7aGVpZ2h0OjEwMHZoO2JhY2tncm91bmQ6JHt0Yy5iZ092ZXJsYXl9O2JhY2tkcm9wLWZpbHRlcjpibHVyKDE1cHgpO3otaW5kZXg6MjE0NzQ4MzY0NztkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpjZW50ZXI7Zm9udC1mYW1pbHk6J1JhamRoYW5pJyxzYW5zLXNlcmlmOyB9CiAgICAgICAgICAgICN0bC1jb25uLXBhbmVsIHsgd2lkdGg6NDIwcHg7YmFja2dyb3VuZDoke3RjLmJnUGFuZWx9O2JvcmRlcjoxcHggc29saWQgJHt0Yy5ib3JkZXJTdHJvbmd9O2JvcmRlci1yYWRpdXM6MjBweDtib3gtc2hhZG93OjAgMCA2MHB4IHJnYmEoMCwwLDAsMC44KSwwIDAgMCAxcHggJHt0Yy5wYW5lbEluc2V0fSBpbnNldDt0ZXh0LWFsaWduOmNlbnRlcjtvdmVyZmxvdzpoaWRkZW47YW5pbWF0aW9uOnRsRmFkZUluIDAuM3MgZWFzZTtwb3NpdGlvbjpyZWxhdGl2ZTsgfQogICAgICAgICAgICBAa2V5ZnJhbWVzIHRsRmFkZUluIHsgZnJvbXtvcGFjaXR5OjA7dHJhbnNmb3JtOnNjYWxlKDAuOTUpfXRve29wYWNpdHk6MTt0cmFuc2Zvcm06c2NhbGUoMSl9IH0KICAgICAgICAgICAgI3RsLWNvbm4taGVhZGVyIHsgcGFkZGluZzoyMnB4O2JhY2tncm91bmQ6JHt0Yy5oZWFkZXJCZ307Ym9yZGVyLWJvdHRvbToxcHggc29saWQgJHt0Yy5ib3JkZXJ9OyB9CiAgICAgICAgICAgIC50bC1icmFuZC1uYW1lIHsgZm9udC1mYW1pbHk6J09yYml0cm9uJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZToyMnB4O2ZvbnQtd2VpZ2h0OjcwMDtiYWNrZ3JvdW5kOiR7dGMuYnJhbmRHcmFkaWVudH07YmFja2dyb3VuZC1zaXplOjIwMCU7LXdlYmtpdC1iYWNrZ3JvdW5kLWNsaXA6dGV4dDstd2Via2l0LXRleHQtZmlsbC1jb2xvcjp0cmFuc3BhcmVudDthbmltYXRpb246dGxTaGltbWVyIDNzIGxpbmVhciBpbmZpbml0ZTsgfQogICAgICAgICAgICBAa2V5ZnJhbWVzIHRsU2hpbW1lciB7IDEwMCV7YmFja2dyb3VuZC1wb3NpdGlvbjoyMDAlIDUwJX0gfQogICAgICAgICAgICAjdGwtY29ubi1ib2R5IHsgcGFkZGluZzozMHB4IDI1cHg7IH0KICAgICAgICAgICAgLnRsLXN1YnRpdGxlIHsgY29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjcpO2ZvbnQtc2l6ZToxM3B4O21hcmdpbi1ib3R0b206MTBweDtmb250LWZhbWlseTonU2hhcmUgVGVjaCBNb25vJzsgfQogICAgICAgICAgICAudGwtd2FybmluZyB7IGNvbG9yOiNmZmMxMDc7Zm9udC1zaXplOjEycHg7bWFyZ2luLWJvdHRvbToyMHB4O2JhY2tncm91bmQ6cmdiYSgyNTUsMTkzLDcsMC4xKTtwYWRkaW5nOjhweDtib3JkZXItcmFkaXVzOjZweDsgfQogICAgICAgICAgICAudGwtaW5wdXQgeyB3aWR0aDoxMDAlO3BhZGRpbmc6MTRweDtiYWNrZ3JvdW5kOnJnYmEoMCwwLDAsMC41NSk7Ym9yZGVyOjFweCBzb2xpZCAke3RjLmlucHV0Qm9yZGVyfTtib3JkZXItcmFkaXVzOjEwcHg7Y29sb3I6JHt0Yy5pbnB1dENvbG9yfTtmb250LWZhbWlseTonU2hhcmUgVGVjaCBNb25vJztmb250LXNpemU6MTZweDt0ZXh0LWFsaWduOmNlbnRlcjttYXJnaW4tYm90dG9tOjE1cHg7dHJhbnNpdGlvbjowLjJzO2JveC1zaXppbmc6Ym9yZGVyLWJveDsgfQogICAgICAgICAgICAudGwtaW5wdXQ6Zm9jdXMgeyBvdXRsaW5lOm5vbmU7Ym9yZGVyLWNvbG9yOiR7dGMuYzF9O2JveC1zaGFkb3c6MCAwIDE2cHggJHt0Yy5nbG93TWlkfTsgfQogICAgICAgICAgICAudGwtYnRuIHsgd2lkdGg6MTAwJTtwYWRkaW5nOjE0cHg7Ym9yZGVyOm5vbmU7Ym9yZGVyLXJhZGl1czoxMHB4O2N1cnNvcjpwb2ludGVyO2ZvbnQtZmFtaWx5OidPcmJpdHJvbicsc2Fucy1zZXJpZjtmb250LXNpemU6MTRweDtmb250LXdlaWdodDo5MDA7bWFyZ2luLWJvdHRvbToxMnB4O3RyYW5zaXRpb246MC4yczsgfQogICAgICAgICAgICAudGwtYnRuLXVubG9jayB7IGJhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDEzNWRlZywjMDBiMDliLCM5NmM5M2QpO2NvbG9yOiNmZmY7IH0KICAgICAgICAgICAgLnRsLWJ0bi11bmxvY2s6aG92ZXIgeyB0cmFuc2Zvcm06c2NhbGUoMS4wMik7Ym94LXNoYWRvdzowIDAgMjVweCByZ2JhKDAsMTc2LDE1NSwwLjYpOyB9CiAgICAgICAgICAgIC50bC1idG4tdmlwIHsgYmFja2dyb3VuZDpyZ2JhKDIxNyw0LDQxLDAuMSk7Ym9yZGVyOjFweCBzb2xpZCByZ2JhKDIxNyw0LDQxLDAuNSk7Y29sb3I6I2VmMjMzYzsgfQogICAgICAgICAgICAudGwtYnRuLXZpcDpob3ZlciB7IGJhY2tncm91bmQ6cmdiYSgyMTcsNCw0MSwwLjIpO3RyYW5zZm9ybTpzY2FsZSgxLjAxKTsgfQogICAgICAgICAgICAjdGwtZXJyIHsgY29sb3I6I2VmMjMzYztmb250LXNpemU6MTNweDttYXJnaW4tdG9wOjEycHg7ZGlzcGxheTpub25lO2ZvbnQtZmFtaWx5OidTaGFyZSBUZWNoIE1vbm8nO2JhY2tncm91bmQ6cmdiYSgyMzksMzUsNjAsMC4xKTtwYWRkaW5nOjhweDtib3JkZXItcmFkaXVzOjZweDsgfQogICAgICAgICAgICAudGwtaHdpZCB7IGNvbG9yOnJnYmEoMjU1LDI1NSwyNTUsMC4yMik7Zm9udC1zaXplOjEwcHg7bWFyZ2luLXRvcDoxNXB4O3dvcmQtYnJlYWs6YnJlYWstYWxsO2ZvbnQtZmFtaWx5Om1vbm9zcGFjZTsgfQogICAgICAgICAgICAudGwtZm9vdCB7IG1hcmdpbi10b3A6MTVweDtmb250LXNpemU6MTFweDtjb2xvcjpyZ2JhKDI1NSwyNTUsMjU1LDAuMTMpOyB9CiAgICAgICAgICAgICR7dGMuZnhDU1N9CiAgICAgICAgYDsKICAgIH0KCiAgICAvLyA9PT09PT09PT09IENTUyBNQUlOIFVJIOKAlCBnaeG7kW5nIGNvcmUgPT09PT09PT09PQogICAgZnVuY3Rpb24gZ2V0TWFpblVJU3R5bGVzKCkgewogICAgICAgIGNvbnN0IHRjID0gZ2V0VGhlbWVDb2xvcnMoQ1VSUkVOVF9USEVNRSk7CiAgICAgICAgcmV0dXJuIGAKICAgICAgICAgICAgQGltcG9ydCB1cmwoJ2h0dHBzOi8vZm9udHMuZ29vZ2xlYXBpcy5jb20vY3NzMj9mYW1pbHk9T3JiaXRyb246d2dodEA0MDA7NzAwOzkwMCZmYW1pbHk9U2hhcmUrVGVjaCtNb25vJmZhbWlseT1SYWpkaGFuaTp3Z2h0QDQwMDs2MDA7NzAwJmRpc3BsYXk9c3dhcCcpOwogICAgICAgICAgICAjdGwtZmxvYXRCdG4geyBwb3NpdGlvbjpmaXhlZDtib3R0b206MjhweDtyaWdodDoyOHB4O3dpZHRoOjU2cHg7aGVpZ2h0OjU2cHg7Ym9yZGVyLXJhZGl1czo1MCU7Ym9yZGVyOm5vbmU7Y3Vyc29yOnBvaW50ZXI7ei1pbmRleDoxMDAwMDtiYWNrZ3JvdW5kOiR7dGMuZmxvYXRHcmFkaWVudH07Ym94LXNoYWRvdzowIDAgMCAwICR7dGMuZ2xvd1N0cm9uZ30sMCAwIDIwcHggJHt0Yy5nbG93Q29sb3J9LDAgNHB4IDIwcHggcmdiYSgwLDAsMCwwLjUpO2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OmNlbnRlcjtmb250LXNpemU6MjJweDt0cmFuc2l0aW9uOnRyYW5zZm9ybSAwLjJzIGVhc2UsYm94LXNoYWRvdyAwLjJzIGVhc2U7YW5pbWF0aW9uOmNvbm5QdWxzZVJpbmcgMi41cyBlYXNlLW91dCBpbmZpbml0ZTsgfQogICAgICAgICAgICAjdGwtZmxvYXRCdG46aG92ZXIgeyB0cmFuc2Zvcm06c2NhbGUoMS4xMikgcm90YXRlKDE1ZGVnKTsgfQogICAgICAgICAgICBAa2V5ZnJhbWVzIGNvbm5QdWxzZVJpbmcgeyAwJXtib3gtc2hhZG93OjAgMCAwIDAgJHt0Yy5nbG93UHVsc2V9fTcwJXtib3gtc2hhZG93OjAgMCAwIDE1cHggcmdiYSgwLDAsMCwwKX0xMDAle2JveC1zaGFkb3c6MCAwIDAgMCByZ2JhKDAsMCwwLDApfSB9CiAgICAgICAgICAgIEBrZXlmcmFtZXMgY29ubkJsaW5rIHsgMCUsMTAwJXtvcGFjaXR5OjF9NTAle29wYWNpdHk6MC4zfSB9CiAgICAgICAgICAgICN0bC1wYW5lbCB7IHBvc2l0aW9uOmZpeGVkO3RvcDo1MCU7bGVmdDo1MCU7dHJhbnNmb3JtOnRyYW5zbGF0ZSgtNTAlLC01MCUpO3dpZHRoOjM2MHB4O2JhY2tncm91bmQ6JHt0Yy5iZ1BhbmVsfTtiYWNrZHJvcC1maWx0ZXI6Ymx1cigyNHB4KTtib3JkZXI6MXB4IHNvbGlkICR7dGMuYm9yZGVyfTtib3JkZXItcmFkaXVzOjE2cHg7Ym94LXNoYWRvdzowIDAgNjBweCByZ2JhKDAsMCwwLDAuOCk7ei1pbmRleDo5OTk5O292ZXJmbG93OmhpZGRlbjtmb250LWZhbWlseTonUmFqZGhhbmknLHNhbnMtc2VyaWY7IH0KICAgICAgICAgICAgI3RsLXBhbmVsLmhpZGRlbiB7IGRpc3BsYXk6bm9uZTsgfQogICAgICAgICAgICAjdGwtcC1oZWFkZXIgeyBjdXJzb3I6bW92ZTtwYWRkaW5nOjE0cHggMTZweCAxMnB4O2JhY2tncm91bmQ6JHt0Yy5oZWFkZXJCZ307Ym9yZGVyLWJvdHRvbToxcHggc29saWQgJHt0Yy5ib3JkZXJTdWJ0bGV9O2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47IH0KICAgICAgICAgICAgLnRsLXAtYnJhbmQgeyBkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDo4cHg7IH0KICAgICAgICAgICAgLnRsLXAtbmFtZSB7IGZvbnQtZmFtaWx5OidPcmJpdHJvbicsc2Fucy1zZXJpZjtmb250LXNpemU6MTEuNXB4O2ZvbnQtd2VpZ2h0OjcwMDtiYWNrZ3JvdW5kOiR7dGMuYnJhbmRHcmFkaWVudH07YmFja2dyb3VuZC1zaXplOjIwMCU7LXdlYmtpdC1iYWNrZ3JvdW5kLWNsaXA6dGV4dDstd2Via2l0LXRleHQtZmlsbC1jb2xvcjp0cmFuc3BhcmVudDthbmltYXRpb246dGxTaGltbWVyIDNzIGxpbmVhciBpbmZpbml0ZTsgfQogICAgICAgICAgICBAa2V5ZnJhbWVzIHRsU2hpbW1lciB7IDEwMCV7YmFja2dyb3VuZC1wb3NpdGlvbjoyMDAlIDUwJX0gfQogICAgICAgICAgICAudGwtYmFkZ2UgeyBmb250LWZhbWlseTonT3JiaXRyb24nO2ZvbnQtc2l6ZTo3LjVweDtmb250LXdlaWdodDo5MDA7Y29sb3I6I2ZmZjtib3JkZXItcmFkaXVzOjRweDtwYWRkaW5nOjNweCA2cHg7YmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLCM1NTUsIzc3Nyk7IH0KICAgICAgICAgICAgLnRsLWJhZGdlLnZpcCB7IGJhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDEzNWRlZywjYTg1NWY3LCM2MzY2ZjEpO2JveC1zaGFkb3c6MCAwIDEwcHggcmdiYSgxNjgsODUsMjQ3LDAuNCk7IH0KICAgICAgICAgICAgLnRsLWJhZGdlLnVubGltaXRlZCB7IGJhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDEzNWRlZywjZjU5ZTBiLCNlZjQ0NDQpO2JveC1zaGFkb3c6MCAwIDEwcHggcmdiYSgyNDUsMTU4LDExLDAuNCk7IH0KICAgICAgICAgICAgI3RsLWNsb3NlQnRuLCN0bC1zZXR0aW5nc0J0biB7IHdpZHRoOjI4cHg7aGVpZ2h0OjI4cHg7Ym9yZGVyLXJhZGl1czo1MCU7Ym9yZGVyOjFweCBzb2xpZCByZ2JhKDI1NSwyNTUsMjU1LDAuMSk7YmFja2dyb3VuZDpyZ2JhKDI1NSwyNTUsMjU1LDAuMDQpO2NvbG9yOnJnYmEoMjU1LDI1NSwyNTUsMC41KTtjdXJzb3I6cG9pbnRlcjtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpjZW50ZXI7dHJhbnNpdGlvbjowLjJzO2ZvbnQtc2l6ZToxM3B4OyB9CiAgICAgICAgICAgICN0bC1jbG9zZUJ0bjpob3ZlciB7IGJvcmRlci1jb2xvcjpyZ2JhKDIxNyw0LDQxLDAuNik7YmFja2dyb3VuZDpyZ2JhKDIxNyw0LDQxLDAuMTUpO2NvbG9yOiNlZjIzM2M7IH0KICAgICAgICAgICAgI3RsLXNldHRpbmdzQnRuOmhvdmVyIHsgYm9yZGVyLWNvbG9yOiR7dGMuYm9yZGVyU3Ryb25nfTtiYWNrZ3JvdW5kOiR7dGMuZ2xvd1N1YnRsZX07Y29sb3I6JHt0Yy5jMX07IH0KICAgICAgICAgICAgI3RsLXNldHRpbmdzQnRuLmFjdGl2ZSB7IGJvcmRlci1jb2xvcjoke3RjLmMxfTtiYWNrZ3JvdW5kOiR7dGMuZ2xvd1N1YnRsZX07Y29sb3I6JHt0Yy5jMX07IH0KICAgICAgICAgICAgI3RsLXAtYm9keSB7IHBhZGRpbmc6MTRweDtkaXNwbGF5OmZsZXg7ZmxleC1kaXJlY3Rpb246Y29sdW1uO2dhcDoxMnB4OyB9CiAgICAgICAgICAgIC50bC1zdGF0Ym94IHsgYm9yZGVyOjFweCBzb2xpZCAke3RjLnN0YXR1c0JvcmRlcn07Ym9yZGVyLXJhZGl1czoxMHB4O3BhZGRpbmc6MTBweDtiYWNrZ3JvdW5kOiR7dGMuc3RhdHVzQmd9OyB9CiAgICAgICAgICAgIC50bC1zdGF0cm93IHsgZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6OHB4O2ZvbnQtZmFtaWx5OidTaGFyZSBUZWNoIE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6MTEuNXB4O2NvbG9yOiNjY2M7bWFyZ2luLXRvcDo0cHg7IH0KICAgICAgICAgICAgI3RsLW1vZGVTZWxlY3QgeyB3aWR0aDoxMDAlO3BhZGRpbmc6MTBweDtiYWNrZ3JvdW5kOnJnYmEoMCwwLDAsMC40KTtib3JkZXI6MXB4IHNvbGlkICR7dGMuc2VsZWN0Qm9yZGVyfTtib3JkZXItcmFkaXVzOjhweDtjb2xvcjojZmZmO2ZvbnQtZmFtaWx5OidSYWpkaGFuaScsc2Fucy1zZXJpZjtmb250LXNpemU6MTRweDtvdXRsaW5lOm5vbmU7bWFyZ2luLXRvcDo1cHg7IH0KICAgICAgICAgICAgLnRsLWdvZC1pbnB1dCB7IHdpZHRoOjEwMCU7cGFkZGluZzoxMHB4O2JhY2tncm91bmQ6cmdiYSgwLDAsMCwwLjQpO2JvcmRlcjoxcHggc29saWQgcmdiYSgyNTUsMTkzLDcsMC4zKTtib3JkZXItcmFkaXVzOjhweDtjb2xvcjojZmZjMTA3O2ZvbnQtZmFtaWx5OidTaGFyZSBUZWNoIE1vbm8nO2ZvbnQtc2l6ZToxM3B4O291dGxpbmU6bm9uZTttYXJnaW4tdG9wOjVweDtib3gtc2l6aW5nOmJvcmRlci1ib3g7IH0KICAgICAgICAgICAgI3RsLWZpcmVCdG4geyB3aWR0aDoxMDAlO3BhZGRpbmc6MTNweDtiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCgxMzVkZWcsI2Q5MDQyOSwjZWYyMzNjKTtib3JkZXI6bm9uZTtib3JkZXItcmFkaXVzOjEwcHg7Y29sb3I6I2ZmZjtmb250LWZhbWlseTonT3JiaXRyb24nO2ZvbnQtd2VpZ2h0OjkwMDtmb250LXNpemU6MTRweDtjdXJzb3I6cG9pbnRlcjtib3gtc2hhZG93OjAgMCAyMHB4IHJnYmEoMjE3LDQsNDEsMC40KTt0cmFuc2l0aW9uOjAuMnM7bWFyZ2luLXRvcDo1cHg7IH0KICAgICAgICAgICAgI3RsLWZpcmVCdG46aG92ZXIgeyBib3gtc2hhZG93OjAgMCAzMHB4IHJnYmEoMjE3LDQsNDEsMC43KTsgfQogICAgICAgICAgICAjdGwtZmlyZUJ0bjpkaXNhYmxlZCB7IG9wYWNpdHk6MC41O2N1cnNvcjpub3QtYWxsb3dlZDsgfQogICAgICAgICAgICAudGwtY29uc29sZSB7IGJvcmRlcjoxcHggc29saWQgJHt0Yy5jb25zb2xlQm9yZGVyfTtib3JkZXItcmFkaXVzOjEwcHg7YmFja2dyb3VuZDpyZ2JhKDAsMCwwLDAuNSk7cGFkZGluZzo4cHg7aGVpZ2h0OjgwcHg7b3ZlcmZsb3cteTphdXRvO2ZvbnQtZmFtaWx5OidTaGFyZSBUZWNoIE1vbm8nO2ZvbnQtc2l6ZToxMC41cHg7Y29sb3I6I2FhYTsgfQogICAgICAgICAgICAudGwtbG9nIHsgbWFyZ2luLWJvdHRvbToycHg7IH0KICAgICAgICAgICAgLnRsLWxvZy5vayAgIHsgY29sb3I6IzAwZTY3NjsgfQogICAgICAgICAgICAudGwtbG9nLmVyciAgeyBjb2xvcjojZWYyMzNjOyB9CiAgICAgICAgICAgIC50bC1sb2cud2FybiB7IGNvbG9yOiNmZmMxMDc7IH0KICAgICAgICAgICAgLnRsLWxvZy5pbmZvIHsgY29sb3I6IzRmYWNmZTsgfQogICAgICAgICAgICAjdGwtcC1mb290ZXIgeyBwYWRkaW5nOjhweCAxNHB4O2JvcmRlci10b3A6MXB4IHNvbGlkICR7dGMuYm9yZGVyU3VidGxlfTtkaXNwbGF5OmZsZXg7anVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47Zm9udC1mYW1pbHk6J1NoYXJlIFRlY2ggTW9ubyc7Zm9udC1zaXplOjlweDtjb2xvcjpyZ2JhKDI1NSwyNTUsMjU1LDAuMik7IH0KICAgICAgICAgICAgLyog4pSA4pSAIFNldHRpbmdzIE92ZXJsYXkg4pSA4pSAICovCiAgICAgICAgICAgICN0bC1zbyB7IHBvc2l0aW9uOmFic29sdXRlO3RvcDowO2xlZnQ6MDtyaWdodDowO2JvdHRvbTowO2JhY2tncm91bmQ6JHt0Yy5iZ1BhbmVsfTtiYWNrZHJvcC1maWx0ZXI6Ymx1cigxMnB4KTt6LWluZGV4OjIwO2JvcmRlci1yYWRpdXM6MTZweDtkaXNwbGF5OmZsZXg7ZmxleC1kaXJlY3Rpb246Y29sdW1uO292ZXJmbG93OmhpZGRlbjsgfQogICAgICAgICAgICAjdGwtc28uaGlkZGVuIHsgZGlzcGxheTpub25lOyB9CiAgICAgICAgICAgIC50bC1zby1oZHIgeyBwYWRkaW5nOjEzcHggMTZweDtiYWNrZ3JvdW5kOiR7dGMuaGVhZGVyQmd9O2JvcmRlci1ib3R0b206MXB4IHNvbGlkICR7dGMuYm9yZGVyU3VidGxlfTtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpzcGFjZS1iZXR3ZWVuO2ZsZXgtc2hyaW5rOjA7IH0KICAgICAgICAgICAgLnRsLXNvLXRpdGxlIHsgZm9udC1mYW1pbHk6J09yYml0cm9uJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZToxMC41cHg7Zm9udC13ZWlnaHQ6NzAwO2NvbG9yOiR7dGMuYzF9OyB9CiAgICAgICAgICAgICN0bC1zb0Nsb3NlIHsgd2lkdGg6MjZweDtoZWlnaHQ6MjZweDtib3JkZXItcmFkaXVzOjUwJTtib3JkZXI6MXB4IHNvbGlkICR7dGMuYm9yZGVyfTtiYWNrZ3JvdW5kOiR7dGMuZ2xvd1N1YnRsZX07Y29sb3I6JHt0Yy5jMX07Y3Vyc29yOnBvaW50ZXI7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyO2ZvbnQtc2l6ZToxMnB4O3RyYW5zaXRpb246MC4yczsgfQogICAgICAgICAgICAjdGwtc29DbG9zZTpob3ZlciB7IGJhY2tncm91bmQ6cmdiYSgyMTcsNCw0MSwwLjE1KTtib3JkZXItY29sb3I6cmdiYSgyMTcsNCw0MSwwLjUpO2NvbG9yOiNlZjIzM2M7IH0KICAgICAgICAgICAgLnRsLXNvLWJvZHkgeyBwYWRkaW5nOjE0cHg7ZmxleDoxO2Rpc3BsYXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47Z2FwOjEycHg7b3ZlcmZsb3cteTphdXRvOyB9CiAgICAgICAgICAgIC50bC1zby1sYmwgeyBmb250LXNpemU6OS41cHg7Zm9udC13ZWlnaHQ6NzAwO2NvbG9yOnJnYmEoMjU1LDI1NSwyNTUsMC4yOCk7dGV4dC10cmFuc2Zvcm06dXBwZXJjYXNlO2ZvbnQtZmFtaWx5OidPcmJpdHJvbic7bGV0dGVyLXNwYWNpbmc6MS4ycHg7bWFyZ2luLWJvdHRvbToycHg7IH0KICAgICAgICAgICAgLnRsLXRoZW1lLWNhcmRzIHsgZGlzcGxheTpmbGV4O2dhcDo4cHg7IH0KICAgICAgICAgICAgLnRsLXRjIHsgZmxleDoxO2N1cnNvcjpwb2ludGVyO2JvcmRlci1yYWRpdXM6MTBweDtib3JkZXI6MnB4IHNvbGlkIHJnYmEoMjU1LDI1NSwyNTUsMC4wNyk7cGFkZGluZzo4cHggNnB4O3RleHQtYWxpZ246Y2VudGVyO3RyYW5zaXRpb246YWxsIDAuMjJzO2JhY2tncm91bmQ6cmdiYSgwLDAsMCwwLjMpO3Bvc2l0aW9uOnJlbGF0aXZlOyB9CiAgICAgICAgICAgIC50bC10Yzpob3ZlciB7IHRyYW5zZm9ybTp0cmFuc2xhdGVZKC0zcHgpO2JvcmRlci1jb2xvcjpyZ2JhKDI1NSwyNTUsMjU1LDAuMTgpO2JveC1zaGFkb3c6MCA2cHggMThweCByZ2JhKDAsMCwwLDAuNCk7IH0KICAgICAgICAgICAgLnRsLXRjLmFjdGl2ZSB7IGJvcmRlci1jb2xvcjoke3RjLmMxfTtib3gtc2hhZG93OjAgMCAxNHB4ICR7dGMuZ2xvd01pZH07IH0KICAgICAgICAgICAgLnRsLXRjLXByZXYgeyB3aWR0aDoxMDAlO2hlaWdodDozOHB4O2JvcmRlci1yYWRpdXM6N3B4O21hcmdpbi1ib3R0b206N3B4O292ZXJmbG93OmhpZGRlbjtwb3NpdGlvbjpyZWxhdGl2ZTsgfQogICAgICAgICAgICAudGwtdGMtcHJldi1pbm5lciB7IHBvc2l0aW9uOmFic29sdXRlO2luc2V0OjA7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyOyB9CiAgICAgICAgICAgIC50bC10Yy1wcmV2LXRleHQgeyBmb250LWZhbWlseTonT3JiaXRyb24nLHNhbnMtc2VyaWY7Zm9udC1zaXplOjdweDtmb250LXdlaWdodDo3MDA7bGV0dGVyLXNwYWNpbmc6MXB4O29wYWNpdHk6MC45OyB9CiAgICAgICAgICAgIC50bC10Yy1sYmwgeyBmb250LWZhbWlseTonUmFqZGhhbmknLHNhbnMtc2VyaWY7Zm9udC1zaXplOjEwLjVweDtmb250LXdlaWdodDo2MDA7Y29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjYpOyB9CiAgICAgICAgICAgIC50bC10Yy5hY3RpdmUgLnRsLXRjLWxibCB7IGNvbG9yOiR7dGMuYzF9O2ZvbnQtd2VpZ2h0OjcwMDsgfQogICAgICAgICAgICAudGwtdGMuYWN0aXZlOjphZnRlciB7IGNvbnRlbnQ6J+Kckyc7cG9zaXRpb246YWJzb2x1dGU7dG9wOjVweDtyaWdodDo3cHg7Y29sb3I6JHt0Yy5jMX07Zm9udC1zaXplOjExcHg7Zm9udC13ZWlnaHQ6OTAwOyB9CiAgICAgICAgICAgIC50bC1zby1kaXZpZGVyIHsgaGVpZ2h0OjFweDtiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCg5MGRlZyx0cmFuc3BhcmVudCwke3RjLmJvcmRlcn0sdHJhbnNwYXJlbnQpOyB9CiAgICAgICAgICAgIC50bC1oaW50IHsgZm9udC1zaXplOjEwcHg7Y29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjIpO2ZvbnQtZmFtaWx5OidTaGFyZSBUZWNoIE1vbm8nO3RleHQtYWxpZ246Y2VudGVyO2xpbmUtaGVpZ2h0OjEuNjsgfQogICAgICAgICAgICAudGwtY2hhbmdlLWtleSB7IHdpZHRoOjEwMCU7cGFkZGluZzoxMHB4O2JhY2tncm91bmQ6cmdiYSgyMzksMzUsNjAsMC4xKTtib3JkZXI6MXB4IHNvbGlkIHJnYmEoMjM5LDM1LDYwLDAuMzgpO2JvcmRlci1yYWRpdXM6OHB4O2NvbG9yOiNlZjIzM2M7Zm9udC1mYW1pbHk6J09yYml0cm9uJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZToxMC41cHg7Zm9udC13ZWlnaHQ6NzAwO2N1cnNvcjpwb2ludGVyO3RyYW5zaXRpb246MC4ycztsZXR0ZXItc3BhY2luZzowLjVweDsgfQogICAgICAgICAgICAudGwtY2hhbmdlLWtleTpob3ZlciB7IGJhY2tncm91bmQ6cmdiYSgyMzksMzUsNjAsMC4yKTtib3JkZXItY29sb3I6cmdiYSgyMzksMzUsNjAsMC42NSk7Ym94LXNoYWRvdzowIDAgMTRweCByZ2JhKDIzOSwzNSw2MCwwLjI1KTsgfQogICAgICAgICAgICAvKiDilIDilIAgQ3VzdG9tIE1vZGFsIOKUgOKUgCAqLwogICAgICAgICAgICAjdGllcC1tb2RhbC1vdmVybGF5IHsgcG9zaXRpb246Zml4ZWQ7dG9wOjA7bGVmdDowO3dpZHRoOjEwMHZ3O2hlaWdodDoxMDB2aDtiYWNrZ3JvdW5kOnJnYmEoMCwwLDAsMC43Mik7ei1pbmRleDoyMTQ3NDgzNjQ2O2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OmNlbnRlcjsgfQogICAgICAgICAgICAudGllcC1tb2RhbC1ib3ggeyB3aWR0aDozMjBweDtiYWNrZ3JvdW5kOiR7dGMuYmdQYW5lbH07Ym9yZGVyOjFweCBzb2xpZCAke3RjLmJvcmRlclN0cm9uZ307Ym9yZGVyLXJhZGl1czoxNnB4O3BhZGRpbmc6MjZweCAyMnB4IDIycHg7dGV4dC1hbGlnbjpjZW50ZXI7Ym94LXNoYWRvdzowIDAgNjBweCByZ2JhKDAsMCwwLDAuOSksaW5zZXQgMCAwIDAgMXB4ICR7dGMucGFuZWxJbnNldH07Zm9udC1mYW1pbHk6J1JhamRoYW5pJyxzYW5zLXNlcmlmOyB9CiAgICAgICAgICAgIC50aWVwLW1vZGFsLWljb24geyBmb250LXNpemU6MzhweDttYXJnaW4tYm90dG9tOjhweDsgfQogICAgICAgICAgICAudGllcC1tb2RhbC10aXRsZSB7IGZvbnQtZmFtaWx5OidPcmJpdHJvbicsc2Fucy1zZXJpZjtmb250LXNpemU6MTJweDtmb250LXdlaWdodDo3MDA7Y29sb3I6JHt0Yy5jMX07bWFyZ2luLWJvdHRvbToxMnB4O2xpbmUtaGVpZ2h0OjEuNTsgfQogICAgICAgICAgICAudGllcC1tb2RhbC1saW5lcyB7IGNvbG9yOnJnYmEoMjU1LDI1NSwyNTUsMC43OCk7Zm9udC1zaXplOjEzcHg7bGluZS1oZWlnaHQ6MS42NTttYXJnaW4tYm90dG9tOjE4cHg7IH0KICAgICAgICAgICAgLnRpZXAtbW9kYWwtbGluZXMgYiB7IGNvbG9yOiNmZmY7IH0KICAgICAgICAgICAgLnRpZXAtbW9kYWwtb2sgeyBwYWRkaW5nOjEwcHggMzZweDtiYWNrZ3JvdW5kOiR7dGMuZmxvYXRHcmFkaWVudH07Ym9yZGVyOm5vbmU7Ym9yZGVyLXJhZGl1czo4cHg7Y29sb3I6I2ZmZjtmb250LWZhbWlseTonT3JiaXRyb24nLHNhbnMtc2VyaWY7Zm9udC1zaXplOjExLjVweDtmb250LXdlaWdodDo5MDA7Y3Vyc29yOnBvaW50ZXI7dHJhbnNpdGlvbjowLjJzO2JveC1zaGFkb3c6MCA0cHggMTZweCAke3RjLmdsb3dDb2xvcn07IH0KICAgICAgICAgICAgLnRpZXAtbW9kYWwtb2s6aG92ZXIgeyB0cmFuc2Zvcm06c2NhbGUoMS4wNik7Ym94LXNoYWRvdzowIDAgMjRweCAke3RjLmdsb3dDb2xvcn07IH0KICAgICAgICAgICAgJHt0Yy5meENTU30KICAgICAgICBgOwogICAgfQoKICAgIC8vID09PT09PT09PT0gQ1VTVE9NIE1PREFMIOKAlCBnaeG7kW5nIGNvcmUgPT09PT09PT09PQogICAgZnVuY3Rpb24gX2Vuc3VyZU1vZGFsU3R5bGUoKSB7CiAgICAgICAgaWYgKGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0aWVwLW1vZGFsLXN0eWxlJykpIHJldHVybjsKICAgICAgICBjb25zdCB0YyA9IGdldFRoZW1lQ29sb3JzKENVUlJFTlRfVEhFTUUpOwogICAgICAgIGNvbnN0IG1zID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc3R5bGUnKTsKICAgICAgICBtcy5pZCA9ICd0aWVwLW1vZGFsLXN0eWxlJzsKICAgICAgICBtcy50ZXh0Q29udGVudCA9IGAKICAgICAgICAgICAgQGtleWZyYW1lcyB0bE1vZGFsSW57ZnJvbXtvcGFjaXR5OjA7dHJhbnNmb3JtOnNjYWxlKDAuOTIpfXRve29wYWNpdHk6MTt0cmFuc2Zvcm06c2NhbGUoMSl9fQogICAgICAgICAgICAjdGllcC1tb2RhbC1vdmVybGF5e3Bvc2l0aW9uOmZpeGVkIWltcG9ydGFudDt0b3A6MCFpbXBvcnRhbnQ7bGVmdDowIWltcG9ydGFudDt3aWR0aDoxMDB2dyFpbXBvcnRhbnQ7aGVpZ2h0OjEwMHZoIWltcG9ydGFudDtiYWNrZ3JvdW5kOnJnYmEoMCwwLDAsMC43NSkhaW1wb3J0YW50O3otaW5kZXg6MjE0NzQ4MzY0NiFpbXBvcnRhbnQ7ZGlzcGxheTpmbGV4IWltcG9ydGFudDthbGlnbi1pdGVtczpjZW50ZXIhaW1wb3J0YW50O2p1c3RpZnktY29udGVudDpjZW50ZXIhaW1wb3J0YW50O30KICAgICAgICAgICAgLnRpZXAtbW9kYWwtYm94e3dpZHRoOjMyMHB4O21heC13aWR0aDo5MHZ3O2JhY2tncm91bmQ6JHt0Yy5iZ1BhbmVsfTtib3JkZXI6MXB4IHNvbGlkICR7dGMuYm9yZGVyU3Ryb25nfTtib3JkZXItcmFkaXVzOjE2cHg7cGFkZGluZzoyNnB4IDIycHggMjJweDt0ZXh0LWFsaWduOmNlbnRlcjtib3gtc2hhZG93OjAgMCA2MHB4IHJnYmEoMCwwLDAsMC45KSxpbnNldCAwIDAgMCAxcHggJHt0Yy5wYW5lbEluc2V0fTtmb250LWZhbWlseTonUmFqZGhhbmknLHNhbnMtc2VyaWY7YW5pbWF0aW9uOnRsTW9kYWxJbiAwLjIycyBlYXNlO30KICAgICAgICAgICAgLnRpZXAtbW9kYWwtaWNvbntmb250LXNpemU6MzhweDttYXJnaW4tYm90dG9tOjhweDt9CiAgICAgICAgICAgIC50aWVwLW1vZGFsLXRpdGxle2ZvbnQtZmFtaWx5OidPcmJpdHJvbicsc2Fucy1zZXJpZjtmb250LXNpemU6MTJweDtmb250LXdlaWdodDo3MDA7Y29sb3I6JHt0Yy5jMX07bWFyZ2luLWJvdHRvbToxMnB4O2xpbmUtaGVpZ2h0OjEuNTt9CiAgICAgICAgICAgIC50aWVwLW1vZGFsLWxpbmVze2NvbG9yOnJnYmEoMjU1LDI1NSwyNTUsMC44Mik7Zm9udC1zaXplOjEzcHg7bGluZS1oZWlnaHQ6MS43O21hcmdpbi1ib3R0b206MThweDt9CiAgICAgICAgICAgIC50aWVwLW1vZGFsLWxpbmVzIGJ7Y29sb3I6I2ZmZjt9CiAgICAgICAgICAgIC50aWVwLW1vZGFsLW9re3BhZGRpbmc6MTBweCAzNnB4O2JhY2tncm91bmQ6JHt0Yy5mbG9hdEdyYWRpZW50fTtib3JkZXI6bm9uZTtib3JkZXItcmFkaXVzOjhweDtjb2xvcjojZmZmO2ZvbnQtZmFtaWx5OidPcmJpdHJvbicsc2Fucy1zZXJpZjtmb250LXNpemU6MTEuNXB4O2ZvbnQtd2VpZ2h0OjkwMDtjdXJzb3I6cG9pbnRlcjt0cmFuc2l0aW9uOjAuMnM7Ym94LXNoYWRvdzowIDRweCAxNnB4ICR7dGMuZ2xvd0NvbG9yfTt9CiAgICAgICAgICAgIC50aWVwLW1vZGFsLW9rOmhvdmVye3RyYW5zZm9ybTpzY2FsZSgxLjA2KTtib3gtc2hhZG93OjAgMCAyNHB4ICR7dGMuZ2xvd0NvbG9yfTt9CiAgICAgICAgYDsKICAgICAgICBkb2N1bWVudC5oZWFkLmFwcGVuZENoaWxkKG1zKTsKICAgIH0KCiAgICBmdW5jdGlvbiBzaG93Q3VzdG9tTW9kYWwoeyBpY29uLCB0aXRsZSwgbGluZXMsIG9uT2sgfSkgewogICAgICAgIF9lbnN1cmVNb2RhbFN0eWxlKCk7CiAgICAgICAgY29uc3QgZXhpc3RpbmcgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGllcC1tb2RhbC1vdmVybGF5Jyk7CiAgICAgICAgaWYgKGV4aXN0aW5nKSBleGlzdGluZy5yZW1vdmUoKTsKICAgICAgICBjb25zdCBvdmVybGF5ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICAgICAgb3ZlcmxheS5pZCA9ICd0aWVwLW1vZGFsLW92ZXJsYXknOwogICAgICAgIGNvbnN0IGxpbmVzSFRNTCA9IChBcnJheS5pc0FycmF5KGxpbmVzKSA/IGxpbmVzIDogW2xpbmVzXSkubWFwKGwgPT4gYDxkaXY+JHtsfTwvZGl2PmApLmpvaW4oJycpOwogICAgICAgIG92ZXJsYXkuaW5uZXJIVE1MID0gYAogICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0aWVwLW1vZGFsLWJveCI+CiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0aWVwLW1vZGFsLWljb24iPiR7aWNvbiB8fCAn4oS577iPJ308L2Rpdj4KICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRpZXAtbW9kYWwtdGl0bGUiPiR7dGl0bGUgfHwgJ1Row7RuZyBiw6FvJ308L2Rpdj4KICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRpZXAtbW9kYWwtbGluZXMiPiR7bGluZXNIVE1MfTwvZGl2PgogICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0idGllcC1tb2RhbC1vayIgaWQ9InRpZXAtbW9kYWwtb2stYnRuIj5PSzwvYnV0dG9uPgogICAgICAgICAgICA8L2Rpdj5gOwogICAgICAgIGRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQob3ZlcmxheSk7CiAgICAgICAgY29uc3QgY2xvc2UgPSAoKSA9PiB7IG92ZXJsYXkucmVtb3ZlKCk7IGlmIChvbk9rKSBvbk9rKCk7IH07CiAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RpZXAtbW9kYWwtb2stYnRuJykub25jbGljayA9IGNsb3NlOwogICAgICAgIG92ZXJsYXkub25jbGljayA9IChlKSA9PiB7IGlmIChlLnRhcmdldCA9PT0gb3ZlcmxheSkgY2xvc2UoKTsgfTsKICAgIH0KCiAgICBmdW5jdGlvbiBzaG93Q29uZmlybU1vZGFsKHsgaWNvbiwgdGl0bGUsIGxpbmVzLCBva1RleHQsIGNhbmNlbFRleHQsIG9uT2sgfSkgewogICAgICAgIF9lbnN1cmVNb2RhbFN0eWxlKCk7CiAgICAgICAgY29uc3QgZXhpc3RpbmcgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGllcC1tb2RhbC1vdmVybGF5Jyk7CiAgICAgICAgaWYgKGV4aXN0aW5nKSBleGlzdGluZy5yZW1vdmUoKTsKICAgICAgICBjb25zdCBvdmVybGF5ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICAgICAgb3ZlcmxheS5pZCA9ICd0aWVwLW1vZGFsLW92ZXJsYXknOwogICAgICAgIGNvbnN0IGxpbmVzSFRNTCA9IChBcnJheS5pc0FycmF5KGxpbmVzKSA/IGxpbmVzIDogW2xpbmVzXSkubWFwKGwgPT4gYDxkaXY+JHtsfTwvZGl2PmApLmpvaW4oJycpOwogICAgICAgIG92ZXJsYXkuaW5uZXJIVE1MID0gYAogICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0aWVwLW1vZGFsLWJveCI+CiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0aWVwLW1vZGFsLWljb24iPiR7aWNvbiB8fCAn4p2TJ308L2Rpdj4KICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRpZXAtbW9kYWwtdGl0bGUiPiR7dGl0bGUgfHwgJ1jDoWMgbmjhuq1uJ308L2Rpdj4KICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRpZXAtbW9kYWwtbGluZXMiPiR7bGluZXNIVE1MfTwvZGl2PgogICAgICAgICAgICAgICAgPGRpdiBzdHlsZT0iZGlzcGxheTpmbGV4O2dhcDoxMHB4O2p1c3RpZnktY29udGVudDpjZW50ZXI7Ij4KICAgICAgICAgICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJ0aWVwLW1vZGFsLW9rIiBpZD0idGllcC1jb25maXJtLWNhbmNlbC1idG4iIHN0eWxlPSJiYWNrZ3JvdW5kOnJnYmEoMjU1LDI1NSwyNTUsMC4wOCk7Ym94LXNoYWRvdzpub25lOyI+JHtjYW5jZWxUZXh0IHx8ICdI4bumWSd9PC9idXR0b24+CiAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0idGllcC1tb2RhbC1vayIgaWQ9InRpZXAtY29uZmlybS1vay1idG4iPiR7b2tUZXh0IHx8ICdYw4FDIE5I4bqsTid9PC9idXR0b24+CiAgICAgICAgICAgICAgICA8L2Rpdj4KICAgICAgICAgICAgPC9kaXY+YDsKICAgICAgICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKG92ZXJsYXkpOwogICAgICAgIGNvbnN0IGRpc21pc3MgPSAoKSA9PiBvdmVybGF5LnJlbW92ZSgpOwogICAgICAgIGNvbnN0IGNvbmZpcm0gPSAoKSA9PiB7IG92ZXJsYXkucmVtb3ZlKCk7IGlmIChvbk9rKSBvbk9rKCk7IH07CiAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RpZXAtY29uZmlybS1jYW5jZWwtYnRuJykub25jbGljayA9IGRpc21pc3M7CiAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RpZXAtY29uZmlybS1vay1idG4nKS5vbmNsaWNrID0gY29uZmlybTsKICAgICAgICBvdmVybGF5Lm9uY2xpY2sgPSAoZSkgPT4geyBpZiAoZS50YXJnZXQgPT09IG92ZXJsYXkpIGRpc21pc3MoKTsgfTsKICAgIH0KCiAgICAvLyDDgXAgZOG7pW5nIHRoZW1lIG5nYXkgbOG6rXAgdOG7qWMKICAgIGZ1bmN0aW9uIGFwcGx5VGhlbWVMaXZlKG5ld1RoZW1lKSB7CiAgICAgICAgQ1VSUkVOVF9USEVNRSA9IG5ld1RoZW1lOwogICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKExTX1RIRU1FLCBuZXdUaGVtZSk7CiAgICAgICAgY29uc3QgdWlTdHlsZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC11aS1zdHlsZScpOwogICAgICAgIGlmICh1aVN0eWxlKSB1aVN0eWxlLnRleHRDb250ZW50ID0gZ2V0TWFpblVJU3R5bGVzKCk7CiAgICAgICAgY29uc3QgbG9ja1N0eWxlID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLWxvY2stc3R5bGUnKTsKICAgICAgICBpZiAobG9ja1N0eWxlKSBsb2NrU3R5bGUudGV4dENvbnRlbnQgPSBnZXRMb2NrU2NyZWVuU3R5bGVzKCk7CiAgICAgICAgY29uc3QgbXMgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGllcC1tb2RhbC1zdHlsZScpOwogICAgICAgIGlmIChtcykgbXMucmVtb3ZlKCk7CiAgICAgICAgY29uc3QgZmIgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtZmxvYXRCdG4nKTsKICAgICAgICBpZiAoZmIpIHsgZmIuc3R5bGUuYW5pbWF0aW9uID0gJ25vbmUnOyB2b2lkIGZiLm9mZnNldFdpZHRoOyBmYi5zdHlsZS5hbmltYXRpb24gPSAnJzsgfQogICAgICAgIGNvbnN0IGxvY2tQYW5lbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1jb25uLXBhbmVsJyk7CiAgICAgICAgaWYgKGxvY2tQYW5lbCkgewogICAgICAgICAgICBjb25zdCBleGlzdEZ4ID0gbG9ja1BhbmVsLnF1ZXJ5U2VsZWN0b3IoJyN0bC1jb25uLWZ4LWJhciwjdGwtY29ubi1meC1wZXRhbHMnKTsKICAgICAgICAgICAgaWYgKGV4aXN0RngpIGV4aXN0RngucmVtb3ZlKCk7CiAgICAgICAgICAgIGNvbnN0IHRjID0gZ2V0VGhlbWVDb2xvcnMobmV3VGhlbWUpOwogICAgICAgICAgICBpZiAodGMucGFuZWxFeHRyYSkgewogICAgICAgICAgICAgICAgY29uc3QgdG1wID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICAgICAgICAgICAgICB0bXAuaW5uZXJIVE1MID0gdGMucGFuZWxFeHRyYTsKICAgICAgICAgICAgICAgIGxvY2tQYW5lbC5pbnNlcnRCZWZvcmUodG1wLmZpcnN0RWxlbWVudENoaWxkLCBsb2NrUGFuZWwuZmlyc3RDaGlsZCk7CiAgICAgICAgICAgIH0KICAgICAgICB9CiAgICB9CgogICAgLy8g4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQCiAgICAvLyAgQuG6ok8gTeG6rFQgdjQg4oCUIOG6qE4gQVBJIHByZWZpeCArIHNlc3Npb24gdG9rZW4gKyBtw6MgaG/DoSDEkcOhcCDDoW4KICAgIC8vIOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkAogICAgbGV0IF9zZWNTZXNzaW9uICAgID0geyB0b2tlbjogbnVsbCwgZXhwOiAwLCBmcEhhc2g6IG51bGwsIHNlcTogMSB9OwogICAgbGV0IF9hcGlQcmVmaXhDYWNoZSA9IG51bGw7CiAgICAvLyBbdjZdIE1vZHVsZSAiQ0hV4bqoTiBC4buKIDEwIMSQSeG7gk0iIOKAlCB04bqjaSDEkOG7mE5HIHThu6sgc2VydmVyLCBLSMOUTkcgbuG6sW0gdHJvbmcgc2NyaXB0CiAgICBsZXQgX2ZpcmVNb2R1bGUgICAgICA9IHsgZmFjdG9yeTogbnVsbCwgdmVyc2lvbjogMCwgbG9hZGluZzogZmFsc2UsIGxhc3RFcnI6IG51bGwgfTsKICAgIGxldCBfaGVhcnRiZWF0VGltZXIgID0gbnVsbDsKICAgIGxldCBfaGVhcnRiZWF0RmFpbCAgID0gMDsKCiAgICAvLyDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZAKICAgIC8vICBbdjVdIELhuqJPIE3huqxUIE7Dgk5HIENBTzogRU5DUllQVC1MUyArIEFOVEktSE9PSyArIFNDUklQVCBHVUFSRAogICAgLy8g4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQCgogICAgLy8g4pSA4pSA4pSAIE9iZnVzY2F0aW9uIExvY2FsU3RvcmFnZSBuaOG6oXkgY+G6o20gKFhPUiArIEJhc2U2NCkg4pSACiAgICBjb25zdCBfRU5DX1BGWCA9ICdceDVmXHg0NVx4MzVceDVmJzsgLy8gJ19FNV8nCiAgICBmdW5jdGlvbiBfbHNYb3IodmFsdWUpIHsKICAgICAgICBpZiAoIXZhbHVlKSByZXR1cm4gJyc7CiAgICAgICAgdHJ5IHsKICAgICAgICAgICAgY29uc3QgayA9IGdldEhXSUQoKSArIEFQSV9TRUNSRVQuc2xpY2UoMCwgMTApOwogICAgICAgICAgICBsZXQgciA9ICcnOwogICAgICAgICAgICBmb3IgKGxldCBpID0gMDsgaSA8IHZhbHVlLmxlbmd0aDsgaSsrKQogICAgICAgICAgICAgICAgciArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKHZhbHVlLmNoYXJDb2RlQXQoaSkgXiBrLmNoYXJDb2RlQXQoaSAlIGsubGVuZ3RoKSk7CiAgICAgICAgICAgIHJldHVybiBfRU5DX1BGWCArIGJ0b2EodW5lc2NhcGUoZW5jb2RlVVJJQ29tcG9uZW50KHIpKSk7CiAgICAgICAgfSBjYXRjaCAoXykgeyByZXR1cm4gdmFsdWU7IH0KICAgIH0KICAgIGZ1bmN0aW9uIF9sc1VueG9yKGVuY29kZWQpIHsKICAgICAgICBpZiAoIWVuY29kZWQpIHJldHVybiBudWxsOwogICAgICAgIGlmICghZW5jb2RlZC5zdGFydHNXaXRoKF9FTkNfUEZYKSkgcmV0dXJuIGVuY29kZWQ7IC8vIExlZ2FjeSBwbGFpbiDigJQgdMawxqFuZyB0aMOtY2ggbmfGsOG7o2MKICAgICAgICB0cnkgewogICAgICAgICAgICBjb25zdCB2ID0gZGVjb2RlVVJJQ29tcG9uZW50KGVzY2FwZShhdG9iKGVuY29kZWQuc2xpY2UoX0VOQ19QRlgubGVuZ3RoKSkpKTsKICAgICAgICAgICAgY29uc3QgayA9IGdldEhXSUQoKSArIEFQSV9TRUNSRVQuc2xpY2UoMCwgMTApOwogICAgICAgICAgICBsZXQgciA9ICcnOwogICAgICAgICAgICBmb3IgKGxldCBpID0gMDsgaSA8IHYubGVuZ3RoOyBpKyspCiAgICAgICAgICAgICAgICByICs9IFN0cmluZy5mcm9tQ2hhckNvZGUodi5jaGFyQ29kZUF0KGkpIF4gay5jaGFyQ29kZUF0KGkgJSBrLmxlbmd0aCkpOwogICAgICAgICAgICByZXR1cm4gcjsKICAgICAgICB9IGNhdGNoIChfKSB7IHJldHVybiBlbmNvZGVkOyB9CiAgICB9CiAgICAvLyBXcmFwcGVyIMSR4buNYy9naGkgTFMgY2hvIGPDoWMga2V5IG5o4bqheSBj4bqjbSAoa2V5LCB0eXBlLCBleHApCiAgICBjb25zdCBfc0xTID0gewogICAgICAgIGdldDogKGtleSkgICAgPT4geyB0cnkgeyByZXR1cm4gX2xzVW54b3IobG9jYWxTdG9yYWdlLmdldEl0ZW0oa2V5KSk7ICB9IGNhdGNoIChfKSB7IHJldHVybiBudWxsOyB9IH0sCiAgICAgICAgc2V0OiAoa2V5LCB2KSA9PiB7IHRyeSB7IGxvY2FsU3RvcmFnZS5zZXRJdGVtKGtleSwgdiA/IF9sc1hvcih2KSA6ICcnKTsgfSBjYXRjaCAoXykge30gfSwKICAgICAgICBkZWw6IChrZXkpICAgID0+IHsgdHJ5IHsgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oa2V5KTsgfSAgICAgICAgICAgICAgICAgIGNhdGNoIChfKSB7fSB9CiAgICB9OwoKICAgIC8vIOKUgOKUgOKUgCBNw6MgaG/DoSBwYXlsb2FkIHJlcXVlc3QgKEFFUy1HQ00gKyBQQktERjIpIOKUgOKUgOKUgOKUgOKUgOKUgOKUgAogICAgYXN5bmMgZnVuY3Rpb24gX2VuY3J5cHRQYXlsb2FkKGRhdGEsIGhpbnQpIHsKICAgICAgICBjb25zdCBlbmMgPSBuZXcgVGV4dEVuY29kZXIoKSwgYyA9IF9jcnlwdG9PYmooKTsKICAgICAgICBjb25zdCBpdiAgICA9IGMuZ2V0UmFuZG9tVmFsdWVzKG5ldyBVaW50OEFycmF5KDEyKSk7CiAgICAgICAgY29uc3QgdHMgICAgPSBNYXRoLmZsb29yKERhdGUubm93KCkgLyAxMDAwKTsKICAgICAgICBjb25zdCBub25jZSA9IEFycmF5LmZyb20oYy5nZXRSYW5kb21WYWx1ZXMobmV3IFVpbnQ4QXJyYXkoOCkpLCBiID0+IGIudG9TdHJpbmcoMTYpLnBhZFN0YXJ0KDIsICcwJykpLmpvaW4oJycpOwogICAgICAgIGNvbnN0IHJhd0tleSAgID0gZW5jLmVuY29kZShBUElfU0VDUkVUICsgKGhpbnQgfHwgJycpICsgKHRzID4+PiA3KS50b1N0cmluZygxNikpOwogICAgICAgIGNvbnN0IGJhc2VLZXkgID0gYXdhaXQgYy5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCByYXdLZXksICdQQktERjInLCBmYWxzZSwgWydkZXJpdmVCaXRzJ10pOwogICAgICAgIGNvbnN0IGJpdHMgICAgID0gYXdhaXQgYy5zdWJ0bGUuZGVyaXZlQml0cyh7IG5hbWU6ICdQQktERjInLCBzYWx0OiBlbmMuZW5jb2RlKCd0bDVyZXEnICsgbm9uY2UpLCBpdGVyYXRpb25zOiAxMjAwLCBoYXNoOiAnU0hBLTI1NicgfSwgYmFzZUtleSwgMjU2KTsKICAgICAgICBjb25zdCBhZXNLZXkgICA9IGF3YWl0IGMuc3VidGxlLmltcG9ydEtleSgncmF3JywgYml0cywgeyBuYW1lOiAnQUVTLUdDTScgfSwgZmFsc2UsIFsnZW5jcnlwdCddKTsKICAgICAgICBjb25zdCBjdCAgICAgICA9IG5ldyBVaW50OEFycmF5KGF3YWl0IGMuc3VidGxlLmVuY3J5cHQoeyBuYW1lOiAnQUVTLUdDTScsIGl2IH0sIGFlc0tleSwgZW5jLmVuY29kZShKU09OLnN0cmluZ2lmeShkYXRhKSkpKTsKICAgICAgICBjb25zdCBiNjQgICAgICA9IChhKSA9PiBidG9hKFN0cmluZy5mcm9tQ2hhckNvZGUoLi4uYSkpOwogICAgICAgIHJldHVybiB7IF9lOiA1LCBpdjogYjY0KGl2KSwgZDogYjY0KGN0LnNsaWNlKDAsIC0xNikpLCB0OiBiNjQoY3Quc2xpY2UoLTE2KSksIHRzLCBuOiBub25jZSB9OwogICAgfQoKICAgIC8vIOKUgOKUgOKUgCBHdWFyZCBzdGF0ZSDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIAKICAgIGxldCBfZ3VhcmRBY3RpdmUgPSBmYWxzZTsKICAgIGxldCBfZ3VhcmRUaW1lciAgPSBudWxsOwogICAgbGV0IF9ndWFyZEJDICAgICA9IG51bGw7CiAgICBsZXQgX3ByZVNjYW5Ib29rID0gbnVsbDsgLy8gc2V0IGLhu59pIGVhcmx5LWNoZWNrIHRyxrDhu5tjIGluamVjdFBhZ2VIb29rCiAgICBsZXQgX2hvb2tTdHJpa2UgID0gMDsgICAgLy8gW3Y2LXNtYXJ0XSDEkeG6v20gbGnDqm4gdOG7pWMgcGjDoXQgaGnhu4duIGhvb2sg4oCUIHnDqnUgY+G6p3Ug4omlMyBt4bubaSBraG/DoSB04bqhbQogICAgY29uc3QgX0dVQVJEX1NUQVJUX1RTID0gRGF0ZS5ub3coKTsgLy8gW3Y2LXNtYXJ0XSBtaeG7hW4gbmhp4buFbSA2MHMgxJHhuqd1ICh0cmFuZyDEkWFuZyB04bqjaSkKICAgIC8vIFt2Ni1zbWFydF0gS2hvw6EgVsSoTkggVknhu4ROIHbhuqtuIGdp4buvIG5oxrAgY8WpIGtoaSBQSMOBVCBISeG7hk4gxJDDmk5HIHNjcmlwdCBs4bqhICjEkcOjIHjDoWMgbmjhuq1uKS4KICAgIC8vICAgICAgICAgICAgIENo4buJIHRpbmggY2jhu4luaCBi4buZIGTDsjogYuG7jyBuaOG6p20gY8O5bmctc2NyaXB0LW5oaeG7gXUtdGFiLCB5w6p1IGPhuqd1IDMgbOG6p24gbGnDqm4gdOG7pWMgbeG7m2kga+G6v3QgbHXhuq1uIGhvb2suCiAgICBjb25zdCBfR1VBUkRfTFMgID0gWydfdGxfY29ubl9rZXknLCdfdGxfY29ubl90eXBlJywnX3RsX2Nvbm5fZXhwJywnX3RpZXBfdGhlbWUnLCdfdGxfaHdpZCcsJ190bF9ndWFyZF90cyddOwogICAgY29uc3QgX0dVQVJEX1VJICA9IFsndGwtY29ubi1vdmVybGF5JywndGwtcGFuZWwnLCd0bC1mbG9hdEJ0bicsJ3RsLXVpLXN0eWxlJywndGwtbG9jay1zdHlsZScsJ3RpZXAtbW9kYWwtc3R5bGUnLCd0aWVwLW1vZGFsLW92ZXJsYXknXTsKCiAgICAvLyDilIDilIDilIAgSGnhu4NuIHRo4buLIGPhuqNuaCBiw6FvIHBow6F0IGhp4buHbiBwaOG6p24gbeG7gW0gbOG6oSDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIAKICAgIGZ1bmN0aW9uIF9zaG93R3VhcmRXYXJuaW5nKHJlYXNvbikgewogICAgICAgIGNvbnN0IHJlbmRlciA9ICgpID0+IHsKICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgIGNvbnN0IGV4ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ190bF9ndWFyZF93YXJuJyk7CiAgICAgICAgICAgICAgICBpZiAoZXgpIGV4LnJlbW92ZSgpOwogICAgICAgICAgICAgICAgY29uc3QgbyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpOwogICAgICAgICAgICAgICAgby5pZCA9ICdfdGxfZ3VhcmRfd2Fybic7CiAgICAgICAgICAgICAgICBvLnN0eWxlLmNzc1RleHQgPSAncG9zaXRpb246Zml4ZWQhaW1wb3J0YW50O3RvcDowIWltcG9ydGFudDtsZWZ0OjAhaW1wb3J0YW50O3dpZHRoOjEwMHZ3IWltcG9ydGFudDtoZWlnaHQ6MTAwdmghaW1wb3J0YW50O2JhY2tncm91bmQ6cmdiYSgwLDAsMCwwLjk2KSFpbXBvcnRhbnQ7ei1pbmRleDoyMTQ3NDgzNjQ3IWltcG9ydGFudDtkaXNwbGF5OmZsZXghaW1wb3J0YW50O2FsaWduLWl0ZW1zOmNlbnRlciFpbXBvcnRhbnQ7anVzdGlmeS1jb250ZW50OmNlbnRlciFpbXBvcnRhbnQ7Zm9udC1mYW1pbHk6bW9ub3NwYWNlIWltcG9ydGFudDsnOwogICAgICAgICAgICAgICAgby5pbm5lckhUTUwgPSBgPGRpdiBzdHlsZT0iYmFja2dyb3VuZDojMGQwZDBkO2JvcmRlcjoycHggc29saWQgI2VmMjMzYztib3JkZXItcmFkaXVzOjE2cHg7cGFkZGluZzozNnB4IDMycHg7bWF4LXdpZHRoOjQzMHB4O3RleHQtYWxpZ246Y2VudGVyO2JveC1zaGFkb3c6MCAwIDgwcHggcmdiYSgyMzksMzUsNjAsMC42KSwwIDAgMTYwcHggcmdiYSgyMzksMzUsNjAsMC4xNSk7Ij4KICAgICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJmb250LXNpemU6NTJweDttYXJnaW4tYm90dG9tOjE0cHg7Ij7wn5qoPC9kaXY+CiAgICAgICAgICAgICAgICAgICAgPHN0eWxlPkBrZXlmcmFtZXMgX3RsQmxpbmt7NTAle29wYWNpdHk6MH19I190bF9ndWFyZF93YXJuIC5nbGl0Y2h7YW5pbWF0aW9uOl90bEJsaW5rIDAuNzVzIHN0ZXAtZW5kIGluZmluaXRlO308L3N0eWxlPgogICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9ImdsaXRjaCIgc3R5bGU9ImZvbnQtZmFtaWx5OidDb3VyaWVyIE5ldycsbW9ub3NwYWNlO2ZvbnQtc2l6ZToxNnB4O2ZvbnQtd2VpZ2h0OjkwMDtjb2xvcjojZWYyMzNjO3RleHQtdHJhbnNmb3JtOnVwcGVyY2FzZTtsZXR0ZXItc3BhY2luZzozcHg7bWFyZ2luLWJvdHRvbToxNHB4OyI+4pqgIFBIw4FUIEhJ4buGTiBQSOG6pk4gTeG7gE0gTOG6oDwvZGl2PgogICAgICAgICAgICAgICAgICAgIDxkaXYgc3R5bGU9ImNvbG9yOnJnYmEoMjU1LDI1NSwyNTUsMC43OCk7Zm9udC1zaXplOjEyLjVweDtsaW5lLWhlaWdodDoxLjk7bWFyZ2luLWJvdHRvbToxOHB4OyI+JHtyZWFzb24gfHwgJ1Bow6F0IGhp4buHbiBzY3JpcHQvcGjhuqduIG3hu4FtIGtow7RuZyByw7Ugbmd14buTbiBn4buRYyDEkWFuZyBjaOG6oXkgc29uZyBzb25nLid9PGJyPjxicj5Ub8OgbiBi4buZIGThu68gbGnhu4d1IGtob8OhIMSRw6MgYuG7iyA8YiBzdHlsZT0iY29sb3I6I2VmMjMzYyI+WMOTQSBU4buwIMSQ4buYTkc8L2I+IMSR4buDIGLhuqNvIHbhu4cgaOG7hyB0aOG7kW5nLjxicj5MacOqbiBo4buHIGFkbWluIMSR4buDIMSRxrDhu6NjIGjhu5cgdHLhu6MuPC9kaXY+CiAgICAgICAgICAgICAgICAgICAgPGRpdiBzdHlsZT0iY29sb3I6cmdiYSgyMzksMzUsNjAsMC40NSk7Zm9udC1zaXplOjlweDtsZXR0ZXItc3BhY2luZzoycHg7Zm9udC1mYW1pbHk6J0NvdXJpZXIgTmV3Jyxtb25vc3BhY2U7Ij5USEnDik4gVEFJIFTDmSBU4buYSSAvLyBTRUNVUklUWSBMT0NLRE9XTiB2NTwvZGl2PgogICAgICAgICAgICAgICAgPC9kaXY+YDsKICAgICAgICAgICAgICAgIGRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQobyk7CiAgICAgICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgfTsKICAgICAgICBpZiAoZG9jdW1lbnQuYm9keSkgcmVuZGVyKCk7CiAgICAgICAgZWxzZSBkb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCdET01Db250ZW50TG9hZGVkJywgcmVuZGVyKTsKICAgIH0KCiAgICAvLyDilIDilIDilIAgVOG7sSBodeG7tyBob8OgbiB0b8OgbiDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIAKICAgIGZ1bmN0aW9uIF9zZWxmRGVzdHJ1Y3QocmVhc29uKSB7CiAgICAgICAgdHJ5IHsgaWYgKF9ndWFyZFRpbWVyKSB7IGNsZWFySW50ZXJ2YWwoX2d1YXJkVGltZXIpOyBfZ3VhcmRUaW1lciA9IG51bGw7IH0gfSBjYXRjaCAoXykge30KICAgICAgICB0cnkgeyBpZiAoX2d1YXJkQkMpICAgIHsgX2d1YXJkQkMuY2xvc2UoKTsgICAgICAgICAgICBfZ3VhcmRCQyAgICA9IG51bGw7IH0gfSBjYXRjaCAoXykge30KICAgICAgICAvLyBYb8OhIHRvw6BuIGLhu5kgTFMgbGnDqm4gcXVhbiDEkeG6v24gc2NyaXB0CiAgICAgICAgX0dVQVJEX0xTLmZvckVhY2goayA9PiB7IHRyeSB7IGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKGspOyB9IGNhdGNoIChfKSB7fSB9KTsKICAgICAgICAvLyDEkOG6t3QgY+G7nSDEkeG7mWMg4oCUIG5nxINuIHNjcmlwdCBraOG7n2kgxJHhu5luZyBs4bqhaQogICAgICAgIHRyeSB7IGxvY2FsU3RvcmFnZS5zZXRJdGVtKCdfdGxfcG9pc29uZWQnLCAnMScpOyB9IGNhdGNoIChfKSB7fQogICAgICAgIC8vIFhvw6EgdG/DoG4gYuG7mSBET00gZG8gc2NyaXB0IHThuqFvIHJhCiAgICAgICAgX0dVQVJEX1VJLmZvckVhY2goaWQgPT4geyB0cnkgeyBjb25zdCBlbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKGlkKTsgaWYgKGVsKSBlbC5yZW1vdmUoKTsgfSBjYXRjaCAoXykge30gfSk7CiAgICAgICAgLy8gUmVzZXQgdG/DoG4gYuG7mSBzZXNzaW9uIG7hu5lpIGLhu5kKICAgICAgICBDVVJSRU5UX0tFWSA9IG51bGw7CiAgICAgICAgS0VZX1NUQVRVUyAgPSB7IHZhbGlkOiBmYWxzZSwgdHlwZTogbnVsbCwgZXhwaXJlc19hdDogbnVsbCB9OwogICAgICAgIHRyeSB7IF9zZWNTZXNzaW9uID0geyB0b2tlbjogbnVsbCwgZXhwOiAwLCBmcEhhc2g6IG51bGwsIHNlcTogMSB9OyB9IGNhdGNoIChfKSB7fQogICAgICAgIENVUlJFTlRfREVWSUNFID0gJyc7CiAgICAgICAgX2d1YXJkQWN0aXZlID0gZmFsc2U7CiAgICAgICAgX3Nob3dHdWFyZFdhcm5pbmcocmVhc29uKTsKICAgIH0KCiAgICAvLyDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZAKICAgIC8vICBbdjYuM10gQkFOLU1PREUg4oCUIGtob8OhIGRvIFNFUlZFUiBCQU4gSVAvdGhp4bq/dCBi4buLIChDw5MgVEjhu4IgTeG7niBM4bqgSSkuCiAgICAvLyAgS2jDoWMgX3NlbGZEZXN0cnVjdCAoa2hvw6EgdsSpbmggdmnhu4VuIGRvIHNjcmlwdCBs4bqhKTogYmFuLW1vZGUgdOG7sSBwb2xsaW5nCiAgICAvLyAgc2VydmVyIG3hu5dpIDE1czsga2hpIGFkbWluIG3hu58ga2hvw6Eg4oaSIFThu7AgxJDhu5hORyByZWxvYWQsIGTDuW5nIGzhuqFpIGLDrG5oIHRoxrDhu51uZwogICAgLy8gIChrZXkgxJHGsOG7o2MgR0nhu64gTOG6oEkgdHJvbmcgbG9jYWxTdG9yYWdlLCBraMO0bmcgeMOzYSkuCiAgICAvLyDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZAKICAgIGxldCBfYmFuU3RhdGUgPSB7IGFjdGl2ZTogZmFsc2UsIHRpbWVyOiBudWxsLCByZWFzb246ICcnIH07CiAgICBmdW5jdGlvbiBfc2hvd0JhblNjcmVlbihyZWFzb24pIHsKICAgICAgICBjb25zdCByZW5kZXIgPSAoKSA9PiB7CiAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgICBjb25zdCBleCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdfdGxfYmFuX292ZXJsYXknKTsKICAgICAgICAgICAgICAgIGlmIChleCkgZXgucmVtb3ZlKCk7CiAgICAgICAgICAgICAgICBjb25zdCBvID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICAgICAgICAgICAgICBvLmlkID0gJ190bF9iYW5fb3ZlcmxheSc7CiAgICAgICAgICAgICAgICBvLnN0eWxlLmNzc1RleHQgPSAncG9zaXRpb246Zml4ZWQhaW1wb3J0YW50O3RvcDowIWltcG9ydGFudDtsZWZ0OjAhaW1wb3J0YW50O3dpZHRoOjEwMHZ3IWltcG9ydGFudDtoZWlnaHQ6MTAwdmghaW1wb3J0YW50O2JhY2tncm91bmQ6cmdiYSgwLDAsMCwwLjk2KSFpbXBvcnRhbnQ7ei1pbmRleDoyMTQ3NDgzNjQ3IWltcG9ydGFudDtkaXNwbGF5OmZsZXghaW1wb3J0YW50O2FsaWduLWl0ZW1zOmNlbnRlciFpbXBvcnRhbnQ7anVzdGlmeS1jb250ZW50OmNlbnRlciFpbXBvcnRhbnQ7Zm9udC1mYW1pbHk6bW9ub3NwYWNlIWltcG9ydGFudDsnOwogICAgICAgICAgICAgICAgby5pbm5lckhUTUwgPSAnPGRpdiBzdHlsZT0iYmFja2dyb3VuZDojMGQwZDBkO2JvcmRlcjoycHggc29saWQgI2VmMjMzYztib3JkZXItcmFkaXVzOjE2cHg7cGFkZGluZzozNnB4IDMycHg7bWF4LXdpZHRoOjQzMHB4O3RleHQtYWxpZ246Y2VudGVyO2JveC1zaGFkb3c6MCAwIDgwcHggcmdiYSgyMzksMzUsNjAsMC42KSwwIDAgMTYwcHggcmdiYSgyMzksMzUsNjAsMC4xNSk7Ij4nCiAgICAgICAgICAgICAgICAgICAgKyAnPGRpdiBzdHlsZT0iZm9udC1zaXplOjUycHg7bWFyZ2luLWJvdHRvbToxNHB4OyI+8J+aqDwvZGl2PicKICAgICAgICAgICAgICAgICAgICArICc8c3R5bGU+QGtleWZyYW1lcyBfdGxCbGlua3s1MCV7b3BhY2l0eTowfX0jX3RsX2Jhbl9vdmVybGF5IC5nbGl0Y2h7YW5pbWF0aW9uOl90bEJsaW5rIDAuNzVzIHN0ZXAtZW5kIGluZmluaXRlO308L3N0eWxlPicKICAgICAgICAgICAgICAgICAgICArICc8ZGl2IGNsYXNzPSJnbGl0Y2giIHN0eWxlPSJmb250LWZhbWlseTpcJ0NvdXJpZXIgTmV3XCcsbW9ub3NwYWNlO2ZvbnQtc2l6ZToxNnB4O2ZvbnQtd2VpZ2h0OjkwMDtjb2xvcjojZWYyMzNjO3RleHQtdHJhbnNmb3JtOnVwcGVyY2FzZTtsZXR0ZXItc3BhY2luZzozcHg7bWFyZ2luLWJvdHRvbToxNHB4OyI+4pqgIFRoaeG6v3QgYuG7iyAvIElQIMSRw6MgYuG7iyBraG/DoTwvZGl2PicKICAgICAgICAgICAgICAgICAgICArICc8ZGl2IHN0eWxlPSJjb2xvcjpyZ2JhKDI1NSwyNTUsMjU1LDAuNzgpO2ZvbnQtc2l6ZToxMi41cHg7bGluZS1oZWlnaHQ6MS45O21hcmdpbi1ib3R0b206MTRweDsiPicgKyAocmVhc29uIHx8ICdQaMOhdCBoaeG7h24gbcO0aSB0csaw4budbmcga2jDtG5nIGjhu6NwIGzhu4cuJykgKyAnPGJyPkxpw6puIGjhu4cgYWRtaW4gxJHhu4MgxJHGsOG7o2MgbeG7nyBraG/DoS48L2Rpdj4nCiAgICAgICAgICAgICAgICAgICAgKyAnPGRpdiBpZD0iX3RsX2Jhbl9zdGF0dXMiIHN0eWxlPSJjb2xvcjojZmZjMTA3O2ZvbnQtc2l6ZToxMS41cHg7bGluZS1oZWlnaHQ6MS44OyI+8J+UhCDEkGFuZyB04buxIMSR4buZbmcga2nhu4NtIHRyYSBt4buXaSAxNSBnacOieS4uLjxicj5LaGkgYWRtaW4gbeG7nyBraG/DoSwgdG9vbCBz4bq9IDxiIHN0eWxlPSJjb2xvcjojMDBlNjc2OyI+VOG7sCDEkOG7mE5HIGhv4bqhdCDEkeG7mW5nIGzhuqFpPC9iPiwga2jDtG5nIGPhuqduIHRoYW8gdMOhYy48L2Rpdj4nCiAgICAgICAgICAgICAgICAgICAgKyAnPGRpdiBzdHlsZT0iY29sb3I6cmdiYSgyMzksMzUsNjAsMC40NSk7Zm9udC1zaXplOjlweDtsZXR0ZXItc3BhY2luZzoycHg7Zm9udC1mYW1pbHk6XCdDb3VyaWVyIE5ld1wnLG1vbm9zcGFjZTttYXJnaW4tdG9wOjE2cHg7Ij5USEnDik4gVEFJIFTDmSBU4buYSSAvLyBCQU4gTE9DSyB2Ni4zIChU4buwIE3hu54gS0hJIFVOQkFOKTwvZGl2PicKICAgICAgICAgICAgICAgICAgICArICc8L2Rpdj4nOwogICAgICAgICAgICAgICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChvKTsKICAgICAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgICB9OwogICAgICAgIGlmIChkb2N1bWVudC5ib2R5KSByZW5kZXIoKTsKICAgICAgICBlbHNlIGRvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXIoJ0RPTUNvbnRlbnRMb2FkZWQnLCByZW5kZXIpOwogICAgfQogICAgZnVuY3Rpb24gX2JhblBvbGxPbmNlKCkgewogICAgICAgIChhc3luYyAoKSA9PiB7CiAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgICBjb25zdCBwcmVmaXggPSBhd2FpdCBfYXBpUHJlZml4KCk7CiAgICAgICAgICAgICAgICBHTV94bWxodHRwUmVxdWVzdCh7CiAgICAgICAgICAgICAgICAgICAgbWV0aG9kOiAnR0VUJywgdXJsOiBTRVJWRVJfQkFTRSArIHByZWZpeCArICcvcGluZycsIHRpbWVvdXQ6IDgwMDAsCiAgICAgICAgICAgICAgICAgICAgb25sb2FkOiAocikgPT4gewogICAgICAgICAgICAgICAgICAgICAgICBpZiAoci5zdGF0dXMgPT09IDIwMCkgeyBfZXhpdEJhbk1vZGUoKTsgcmV0dXJuOyB9CiAgICAgICAgICAgICAgICAgICAgICAgIGNvbnN0IGVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ190bF9iYW5fc3RhdHVzJyk7CiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChlbCkgZWwuaW5uZXJIVE1MID0gJ/CflIQgVuG6q24gYuG7iyBraG/DoSDigJQgxJFhbmcgY2jhu50gYWRtaW4gbeG7nyBraG/DoS4uLjxicj4odOG7sSBraeG7g20gdHJhIGzhuqFpIHNhdSAxNSBnacOieSknOwogICAgICAgICAgICAgICAgICAgIH0sCiAgICAgICAgICAgICAgICAgICAgb25lcnJvcjogKCkgPT4ge30sIG9udGltZW91dDogKCkgPT4ge30KICAgICAgICAgICAgICAgIH0pOwogICAgICAgICAgICB9IGNhdGNoIChfKSB7fQogICAgICAgIH0pKCk7CiAgICB9CiAgICBmdW5jdGlvbiBfZW50ZXJCYW5Nb2RlKHJlYXNvbikgewogICAgICAgIGlmIChfYmFuU3RhdGUuYWN0aXZlKSByZXR1cm47CiAgICAgICAgX2JhblN0YXRlLmFjdGl2ZSA9IHRydWU7CiAgICAgICAgX2JhblN0YXRlLnJlYXNvbiA9IHJlYXNvbiB8fCAnJzsKICAgICAgICAvLyBE4burbmcgaGVhcnRiZWF0ICsgZ3VhcmQgKMSRw6MgdsOgbyBiYW4gbW9kZSwga2jDtG5nIGPhuqduIG7hu69hKQogICAgICAgIHRyeSB7IGlmIChfaGVhcnRiZWF0VGltZXIpIHsgY2xlYXJJbnRlcnZhbChfaGVhcnRiZWF0VGltZXIpOyBfaGVhcnRiZWF0VGltZXIgPSBudWxsOyB9IH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgdHJ5IHsgaWYgKF9ndWFyZFRpbWVyKSAgICAgeyBjbGVhckludGVydmFsKF9ndWFyZFRpbWVyKTsgICAgIF9ndWFyZFRpbWVyICAgICA9IG51bGw7IH0gfSBjYXRjaCAoXykge30KICAgICAgICB0cnkgeyBpZiAoX2d1YXJkQkMpICAgICAgICB7IF9ndWFyZEJDLmNsb3NlKCk7ICAgICAgICAgICAgICAgX2d1YXJkQkMgICAgICAgID0gbnVsbDsgfSB9IGNhdGNoIChfKSB7fQogICAgICAgIC8vIFhvw6EgVUkgxJFhbmcgY2jhuqF5IChuZ+G7q25nIGhv4bqhdCDEkeG7mW5nKSDigJQgR0nhu64gTOG6oEkga2V5IHRyb25nIExTIMSR4buDIG3hu58ga2hvw6EgZMO5bmcgbOG6oWkgbmdheQogICAgICAgIFsndGwtcGFuZWwnLCd0bC1mbG9hdEJ0bicsJ3RsLWNvbm4tb3ZlcmxheScsJ3RpZXAtbW9kYWwtb3ZlcmxheSddLmZvckVhY2goaWQgPT4geyB0cnkgeyBjb25zdCBlbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKGlkKTsgaWYgKGVsKSBlbC5yZW1vdmUoKTsgfSBjYXRjaCAoXykge30gfSk7CiAgICAgICAgQ1VSUkVOVF9LRVkgPSBudWxsOwogICAgICAgIEtFWV9TVEFUVVMgID0geyB2YWxpZDogZmFsc2UsIHR5cGU6IG51bGwsIGV4cGlyZXNfYXQ6IG51bGwgfTsKICAgICAgICB0cnkgeyBfc2VjU2Vzc2lvbiA9IHsgdG9rZW46IG51bGwsIGV4cDogMCwgZnBIYXNoOiBudWxsLCBzZXE6IDEgfTsgfSBjYXRjaCAoXykge30KICAgICAgICBfZmlyZU1vZHVsZSA9IHsgZmFjdG9yeTogbnVsbCwgdmVyc2lvbjogMCwgbG9hZGluZzogZmFsc2UsIGxhc3RFcnI6IG51bGwgfTsKICAgICAgICBfc2hvd0JhblNjcmVlbihyZWFzb24pOwogICAgICAgIC8vIFBvbGxpbmcgbeG7l2kgMTVzIGNo4budIGFkbWluIG3hu58ga2hvw6E7IGzhuqduIMSR4bqndSBzYXUgNXMKICAgICAgICBfYmFuU3RhdGUudGltZXIgPSBzZXRJbnRlcnZhbChfYmFuUG9sbE9uY2UsIDE1MDAwKTsKICAgICAgICBzZXRUaW1lb3V0KF9iYW5Qb2xsT25jZSwgNTAwMCk7CiAgICB9CiAgICBmdW5jdGlvbiBfZXhpdEJhbk1vZGUoKSB7CiAgICAgICAgaWYgKCFfYmFuU3RhdGUuYWN0aXZlKSByZXR1cm47CiAgICAgICAgX2JhblN0YXRlLmFjdGl2ZSA9IGZhbHNlOwogICAgICAgIHRyeSB7IGlmIChfYmFuU3RhdGUudGltZXIpIHsgY2xlYXJJbnRlcnZhbChfYmFuU3RhdGUudGltZXIpOyBfYmFuU3RhdGUudGltZXIgPSBudWxsOyB9IH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgdHJ5IHsgY29uc3QgZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnX3RsX2Jhbl9vdmVybGF5Jyk7IGlmIChlbCkgZWwucmVtb3ZlKCk7IH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgLy8gVOG7sSByZWxvYWQg4oaSIHNjcmlwdCBraOG7n2kgxJHhu5luZyBs4bqhaSBz4bqhY2gsIGtleSB24bqrbiBjw7JuIOKGkiBkw7luZyBiw6xuaCB0aMaw4budbmcKICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHsgdHJ5IHsgd2luZG93LmxvY2F0aW9uLnJlbG9hZCgpOyB9IGNhdGNoIChfKSB7fSB9LCA4MDApOwogICAgfQoKICAgIC8vIOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkAogICAgLy8gIFt2Ni40XSBSRU1PVEUtTE9DSyDigJQga2hvw6EgZG8gUEjDgVQgSEnhu4ZOIFNDUklQVCBM4bqgLgogICAgLy8gIEtow6FjIF9zZWxmRGVzdHJ1Y3QgKGPFqSwga2hvw6EgdsSpbmggdmnhu4VuLCB4w7NhIGtleSk6CiAgICAvLyAgIDEpIFThu7AgxJDhu5hORyBn4butaSBiw6FvIGPDoW8gbMOqbiBzZXJ2ZXIgKGlwICsgdGhp4bq/dCBi4buLICsgbMO9IGRvKQogICAgLy8gICAyKSBTZXJ2ZXIgZ2hpIHbDoG8gdGFiIGFkbWluIHJpw6puZyDihpIgYWRtaW4gdGjhuqV5IElQICsgdGhp4bq/dCBi4buLIGLhu4sga2hvw6EKICAgIC8vICAgMykgQWRtaW4gYuG6pW0gTeG7niBLSE/DgSDihpIgY2xpZW50IHBvbGxpbmcgdGjhuqV5IOKGkiBU4buwIMSQ4buYTkcgcmVsb2FkLCBkw7luZyBs4bqhaQogICAgLy8gICAgICBiw6xuaCB0aMaw4budbmcgKEdJ4buuIEzhuqBJIGtleSB0cm9uZyBsb2NhbFN0b3JhZ2UsIGtow7RuZyBj4bqnbiBuaOG6rXAgbOG6oWkpLgogICAgLy8g4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQCiAgICBsZXQgX3JlbW90ZUxvY2tTdGF0ZSA9IHsgYWN0aXZlOiBmYWxzZSwgdGltZXI6IG51bGwsIHJlYXNvbjogJycsIHJlcG9ydGVkOiBmYWxzZSB9OwogICAgZnVuY3Rpb24gX3JsU2VuZFJlcG9ydChyZWFzb24pIHsKICAgICAgICAoYXN5bmMgKCkgPT4gewogICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgY29uc3QgcHJlZml4ID0gYXdhaXQgX2FwaVByZWZpeCgpOwogICAgICAgICAgICAgICAgbGV0IG9sbVVzZXIgPSAnJzsKICAgICAgICAgICAgICAgIHRyeSB7IG9sbVVzZXIgPSBnZXRPbG1Vc2VybmFtZSgpOyB9IGNhdGNoIChfKSB7fQogICAgICAgICAgICAgICAgY29uc3QgYm9keSA9IEpTT04uc3RyaW5naWZ5KHsKICAgICAgICAgICAgICAgICAgICBrZXk6IENVUlJFTlRfS0VZIHx8IF9zTFMuZ2V0KExTX0tFWSkgfHwgJycsCiAgICAgICAgICAgICAgICAgICAgaHdpZDogZ2V0SFdJRCgpLCBmcDogX2NvbGxlY3RGUCgpLCBkZXZpY2U6IF9jb2xsZWN0RGV2aWNlKCksCiAgICAgICAgICAgICAgICAgICAgcmVhc29uOiBTdHJpbmcocmVhc29uIHx8ICcnKS5zbGljZSgwLCAyMDApLCBvbG1fdXNlcjogb2xtVXNlcgogICAgICAgICAgICAgICAgfSk7CiAgICAgICAgICAgICAgICBsZXQgdHJpZXMgPSAwOwogICAgICAgICAgICAgICAgbGV0IHNpZ0hkcnMgPSB7fTsKICAgICAgICAgICAgICAgIHRyeSB7IHNpZ0hkcnMgPSBhd2FpdCBfc2lnblJlcShib2R5LCAnJyk7IH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgICAgICAgICAoZnVuY3Rpb24gc2VuZCgpIHsKICAgICAgICAgICAgICAgICAgICB0cmllcysrOwogICAgICAgICAgICAgICAgICAgIEdNX3htbGh0dHBSZXF1ZXN0KHsKICAgICAgICAgICAgICAgICAgICAgICAgbWV0aG9kOiAnUE9TVCcsIHVybDogU0VSVkVSX0JBU0UgKyBwcmVmaXggKyAnL2xvY2stcmVwb3J0JywKICAgICAgICAgICAgICAgICAgICAgICAgaGVhZGVyczogT2JqZWN0LmFzc2lnbih7ICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbicgfSwgc2lnSGRycyksIGRhdGE6IGJvZHksIHRpbWVvdXQ6IDEwMDAwLAogICAgICAgICAgICAgICAgICAgICAgICBvbmxvYWQ6ICgpID0+IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIF9yZW1vdGVMb2NrU3RhdGUucmVwb3J0ZWQgPSB0cnVlOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uc3QgZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnX3RsX3JsX3N0YXR1cycpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGVsKSBlbC5pbm5lckhUTUwgPSAn4pyFIMSQw6MgYsOhbyBjw6FvIGzDqm4gc2VydmVyIGFkbWluLjxicj7wn5SEIMSQYW5nIGNo4budIGFkbWluIG3hu58ga2hvw6EgKHThu7Ega2nhu4NtIHRyYSBt4buXaSAyMHMpLi4uJzsKICAgICAgICAgICAgICAgICAgICAgICAgfSwKICAgICAgICAgICAgICAgICAgICAgICAgb25lcnJvcjogICAoKSA9PiB7IGlmICh0cmllcyA8IDQpIHNldFRpbWVvdXQoc2VuZCwgMzAwMCk7IH0sCiAgICAgICAgICAgICAgICAgICAgICAgIG9udGltZW91dDogKCkgPT4geyBpZiAodHJpZXMgPCA0KSBzZXRUaW1lb3V0KHNlbmQsIDMwMDApOyB9CiAgICAgICAgICAgICAgICAgICAgfSk7CiAgICAgICAgICAgICAgICB9KSgpOwogICAgICAgICAgICB9IGNhdGNoIChfKSB7fQogICAgICAgIH0pKCk7CiAgICB9CiAgICBmdW5jdGlvbiBfc2hvd1JlbW90ZUxvY2tTY3JlZW4ocmVhc29uKSB7CiAgICAgICAgY29uc3QgcmVuZGVyID0gKCkgPT4gewogICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgY29uc3QgZXggPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnX3RsX3JsX292ZXJsYXknKTsKICAgICAgICAgICAgICAgIGlmIChleCkgZXgucmVtb3ZlKCk7CiAgICAgICAgICAgICAgICBjb25zdCBvID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICAgICAgICAgICAgICBvLmlkID0gJ190bF9ybF9vdmVybGF5JzsKICAgICAgICAgICAgICAgIG8uc3R5bGUuY3NzVGV4dCA9ICdwb3NpdGlvbjpmaXhlZCFpbXBvcnRhbnQ7dG9wOjAhaW1wb3J0YW50O2xlZnQ6MCFpbXBvcnRhbnQ7d2lkdGg6MTAwdnchaW1wb3J0YW50O2hlaWdodDoxMDB2aCFpbXBvcnRhbnQ7YmFja2dyb3VuZDpyZ2JhKDAsMCwwLDAuOTYpIWltcG9ydGFudDt6LWluZGV4OjIxNDc0ODM2NDchaW1wb3J0YW50O2Rpc3BsYXk6ZmxleCFpbXBvcnRhbnQ7YWxpZ24taXRlbXM6Y2VudGVyIWltcG9ydGFudDtqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyIWltcG9ydGFudDtmb250LWZhbWlseTptb25vc3BhY2UhaW1wb3J0YW50Oyc7CiAgICAgICAgICAgICAgICBvLmlubmVySFRNTCA9ICc8ZGl2IHN0eWxlPSJiYWNrZ3JvdW5kOiMwZDBkMGQ7Ym9yZGVyOjJweCBzb2xpZCAjZWYyMzNjO2JvcmRlci1yYWRpdXM6MTZweDtwYWRkaW5nOjM2cHggMzJweDttYXgtd2lkdGg6NDMwcHg7dGV4dC1hbGlnbjpjZW50ZXI7Ym94LXNoYWRvdzowIDAgODBweCByZ2JhKDIzOSwzNSw2MCwwLjYpLDAgMCAxNjBweCByZ2JhKDIzOSwzNSw2MCwwLjE1KTsiPicKICAgICAgICAgICAgICAgICAgICArICc8ZGl2IHN0eWxlPSJmb250LXNpemU6NTJweDttYXJnaW4tYm90dG9tOjE0cHg7Ij7wn5qoPC9kaXY+JwogICAgICAgICAgICAgICAgICAgICsgJzxzdHlsZT5Aa2V5ZnJhbWVzIF90bEJsaW5rezUwJXtvcGFjaXR5OjB9fSNfdGxfcmxfb3ZlcmxheSAuZ2xpdGNoe2FuaW1hdGlvbjpfdGxCbGluayAwLjc1cyBzdGVwLWVuZCBpbmZpbml0ZTt9PC9zdHlsZT4nCiAgICAgICAgICAgICAgICAgICAgKyAnPGRpdiBjbGFzcz0iZ2xpdGNoIiBzdHlsZT0iZm9udC1mYW1pbHk6XCdDb3VyaWVyIE5ld1wnLG1vbm9zcGFjZTtmb250LXNpemU6MTZweDtmb250LXdlaWdodDo5MDA7Y29sb3I6I2VmMjMzYzt0ZXh0LXRyYW5zZm9ybTp1cHBlcmNhc2U7bGV0dGVyLXNwYWNpbmc6M3B4O21hcmdpbi1ib3R0b206MTRweDsiPuKaoCBQSMOBVCBISeG7hk4gUEjhuqZOIE3hu4BNIEzhuqA8L2Rpdj4nCiAgICAgICAgICAgICAgICAgICAgKyAnPGRpdiBzdHlsZT0iY29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjc4KTtmb250LXNpemU6MTIuNXB4O2xpbmUtaGVpZ2h0OjEuOTttYXJnaW4tYm90dG9tOjE0cHg7Ij4nICsgKHJlYXNvbiB8fCAnUGjDoXQgaGnhu4duIHNjcmlwdC9waOG6p24gbeG7gW0ga2jDtG5nIHLDtSBuZ3Xhu5NuIGfhu5FjLicpICsgJzxicj7EkMOjIDxiIHN0eWxlPSJjb2xvcjojZmZjMTA3OyI+VOG7sCDEkOG7mE5HIGLDoW8gY8OhbzwvYj4gbMOqbiBzZXJ2ZXIgYWRtaW4uPC9kaXY+JwogICAgICAgICAgICAgICAgICAgICsgJzxkaXYgaWQ9Il90bF9ybF9zdGF0dXMiIHN0eWxlPSJjb2xvcjojZmZjMTA3O2ZvbnQtc2l6ZToxMS41cHg7bGluZS1oZWlnaHQ6MS44OyI+8J+TpCDEkGFuZyBn4butaSBiw6FvIGPDoW8gbMOqbiBzZXJ2ZXIuLi48L2Rpdj4nCiAgICAgICAgICAgICAgICAgICAgKyAnPGRpdiBzdHlsZT0iY29sb3I6cmdiYSgwLDIzMCwxMTgsMC42KTtmb250LXNpemU6MTAuNXB4O2xpbmUtaGVpZ2h0OjEuNzttYXJnaW4tdG9wOjEwcHg7Ij5LaGkgYWRtaW4gYuG6pW0gPGI+TeG7niBLSE/DgTwvYj4gdHLDqm4gdHJhbmcgcXXhuqNuIHRy4buLLDxicj50b29sIHPhur0gPGIgc3R5bGU9ImNvbG9yOiMwMGU2NzY7Ij5U4buwIMSQ4buYTkcgaG/huqF0IMSR4buZbmcgbOG6oWk8L2I+IChraMO0bmcgY+G6p24gbmjhuq1wIGzhuqFpIGtleSkuPC9kaXY+JwogICAgICAgICAgICAgICAgICAgICsgJzxkaXYgc3R5bGU9ImNvbG9yOnJnYmEoMjM5LDM1LDYwLDAuNDUpO2ZvbnQtc2l6ZTo5cHg7bGV0dGVyLXNwYWNpbmc6MnB4O2ZvbnQtZmFtaWx5OlwnQ291cmllciBOZXdcJyxtb25vc3BhY2U7bWFyZ2luLXRvcDoxNnB4OyI+VEhJw4pOIFRBSSBUw5kgVOG7mEkgLy8gUkVNT1RFIExPQ0sgdjYuNDwvZGl2PicKICAgICAgICAgICAgICAgICAgICArICc8ZGl2IHN0eWxlPSJjb2xvcjpyZ2JhKDI1NSwyNTUsMjU1LDAuMjUpO2ZvbnQtc2l6ZTo5cHg7bWFyZ2luLXRvcDo2cHg7Zm9udC1mYW1pbHk6bW9ub3NwYWNlOyI+SFdJRDogJyArIGdldEhXSUQoKSArICc8L2Rpdj4nCiAgICAgICAgICAgICAgICAgICAgKyAnPC9kaXY+JzsKICAgICAgICAgICAgICAgIGRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQobyk7CiAgICAgICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgfTsKICAgICAgICBpZiAoZG9jdW1lbnQuYm9keSkgcmVuZGVyKCk7CiAgICAgICAgZWxzZSBkb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCdET01Db250ZW50TG9hZGVkJywgcmVuZGVyKTsKICAgIH0KICAgIGZ1bmN0aW9uIF9yZW1vdGVMb2NrUG9sbE9uY2UoKSB7CiAgICAgICAgKGFzeW5jICgpID0+IHsKICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgIGNvbnN0IHByZWZpeCA9IGF3YWl0IF9hcGlQcmVmaXgoKTsKICAgICAgICAgICAgICAgIGNvbnN0IGxvY2tCb2R5ID0gSlNPTi5zdHJpbmdpZnkoeyBod2lkOiBnZXRIV0lEKCkgfSk7CiAgICAgICAgICAgICAgICBsZXQgc2lnSGRyczIgPSB7fTsKICAgICAgICAgICAgICAgIHRyeSB7IHNpZ0hkcnMyID0gYXdhaXQgX3NpZ25SZXEobG9ja0JvZHksICcnKTsgfSBjYXRjaCAoXykge30KICAgICAgICAgICAgICAgIEdNX3htbGh0dHBSZXF1ZXN0KHsKICAgICAgICAgICAgICAgICAgICBtZXRob2Q6ICdQT1NUJywgdXJsOiBTRVJWRVJfQkFTRSArIHByZWZpeCArICcvbG9jay1zdGF0dXMnLAogICAgICAgICAgICAgICAgICAgIGhlYWRlcnM6IE9iamVjdC5hc3NpZ24oeyAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nIH0sIHNpZ0hkcnMyKSwKICAgICAgICAgICAgICAgICAgICBkYXRhOiBsb2NrQm9keSwgdGltZW91dDogODAwMCwKICAgICAgICAgICAgICAgICAgICBvbmxvYWQ6IChyKSA9PiB7CiAgICAgICAgICAgICAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zdCBqID0gSlNPTi5wYXJzZShyLnJlc3BvbnNlVGV4dCk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAoaiAmJiBqLmxvY2tlZCA9PT0gZmFsc2UpIHsgX2V4aXRSZW1vdGVMb2NrKCk7IHJldHVybjsgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uc3QgZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnX3RsX3JsX3N0YXR1cycpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGVsKSBlbC5pbm5lckhUTUwgPSAn8J+UkiBW4bqrbiBi4buLIGtob8OhIOKAlCBjaOG7nSBhZG1pbiBt4bufIGtob8OhLi4uPGJyPih04buxIGtp4buDbSB0cmEgbOG6oWkgc2F1IDIwcyknOwogICAgICAgICAgICAgICAgICAgICAgICB9IGNhdGNoIChfKSB7fQogICAgICAgICAgICAgICAgICAgIH0sCiAgICAgICAgICAgICAgICAgICAgb25lcnJvcjogKCkgPT4ge30sIG9udGltZW91dDogKCkgPT4ge30KICAgICAgICAgICAgICAgIH0pOwogICAgICAgICAgICB9IGNhdGNoIChfKSB7fQogICAgICAgIH0pKCk7CiAgICB9CiAgICBmdW5jdGlvbiBfZW50ZXJSZW1vdGVMb2NrKHJlYXNvbikgewogICAgICAgIGlmIChfcmVtb3RlTG9ja1N0YXRlLmFjdGl2ZSkgcmV0dXJuOwogICAgICAgIF9yZW1vdGVMb2NrU3RhdGUuYWN0aXZlID0gdHJ1ZTsKICAgICAgICBfcmVtb3RlTG9ja1N0YXRlLnJlYXNvbiA9IHJlYXNvbiB8fCAnJzsKICAgICAgICAvLyDEkMOhbmggZOG6pXUgdOG7k24gdOG6oWkgcXVhIHJlbG9hZCDigJQgS0jDlE5HIHjDs2Ega2V5IOKGkiBt4bufIGtob8OhIGTDuW5nIGzhuqFpIG5nYXkKICAgICAgICB0cnkgeyBsb2NhbFN0b3JhZ2Uuc2V0SXRlbSgnX3RsX3JlbW90ZV9sb2NrZWQnLCAnMScpOyB9IGNhdGNoIChfKSB7fQogICAgICAgIHRyeSB7IGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKCdfdGxfcG9pc29uZWQnKTsgfSBjYXRjaCAoXykge30gLy8gY+G7nSB2xKluaCB2aeG7hW4gY8WpIGtow7RuZyBkw7luZyBu4buvYQogICAgICAgIC8vIEThu6tuZyBt4buNaSB0aW1lciDEkWFuZyBjaOG6oXkKICAgICAgICB0cnkgeyBpZiAoX2hlYXJ0YmVhdFRpbWVyKSB7IGNsZWFySW50ZXJ2YWwoX2hlYXJ0YmVhdFRpbWVyKTsgX2hlYXJ0YmVhdFRpbWVyID0gbnVsbDsgfSB9IGNhdGNoIChfKSB7fQogICAgICAgIHRyeSB7IGlmIChfZ3VhcmRUaW1lcikgICAgIHsgY2xlYXJJbnRlcnZhbChfZ3VhcmRUaW1lcik7ICAgICBfZ3VhcmRUaW1lciAgICAgPSBudWxsOyB9IH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgdHJ5IHsgaWYgKF9ndWFyZEJDKSAgICAgICAgeyBfZ3VhcmRCQy5jbG9zZSgpOyAgICAgICAgICAgICAgIF9ndWFyZEJDICAgICAgICA9IG51bGw7IH0gfSBjYXRjaCAoXykge30KICAgICAgICB0cnkgeyBpZiAoX2JhblN0YXRlLnRpbWVyKSB7IGNsZWFySW50ZXJ2YWwoX2JhblN0YXRlLnRpbWVyKTsgX2JhblN0YXRlLnRpbWVyID0gbnVsbDsgfSB9IGNhdGNoIChfKSB7fQogICAgICAgIC8vIFhvw6EgVUkgxJFhbmcgY2jhuqF5IOKAlCBHSeG7riBM4bqgSSBrZXkgdHJvbmcgTFMKICAgICAgICBbJ3RsLXBhbmVsJywndGwtZmxvYXRCdG4nLCd0bC1jb25uLW92ZXJsYXknLCd0aWVwLW1vZGFsLW92ZXJsYXknLCdfdGxfZ3VhcmRfd2FybicsJ190bF9iYW5fb3ZlcmxheSddLmZvckVhY2goaWQgPT4geyB0cnkgeyBjb25zdCBlbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKGlkKTsgaWYgKGVsKSBlbC5yZW1vdmUoKTsgfSBjYXRjaCAoXykge30gfSk7CiAgICAgICAgQ1VSUkVOVF9LRVkgPSBudWxsOwogICAgICAgIEtFWV9TVEFUVVMgID0geyB2YWxpZDogZmFsc2UsIHR5cGU6IG51bGwsIGV4cGlyZXNfYXQ6IG51bGwgfTsKICAgICAgICB0cnkgeyBfc2VjU2Vzc2lvbiA9IHsgdG9rZW46IG51bGwsIGV4cDogMCwgZnBIYXNoOiBudWxsLCBzZXE6IDEgfTsgfSBjYXRjaCAoXykge30KICAgICAgICBfZmlyZU1vZHVsZSA9IHsgZmFjdG9yeTogbnVsbCwgdmVyc2lvbjogMCwgbG9hZGluZzogZmFsc2UsIGxhc3RFcnI6IG51bGwgfTsKICAgICAgICBfc2hvd1JlbW90ZUxvY2tTY3JlZW4ocmVhc29uKTsKICAgICAgICBfcmxTZW5kUmVwb3J0KHJlYXNvbik7CiAgICAgICAgX3JlbW90ZUxvY2tTdGF0ZS50aW1lciA9IHNldEludGVydmFsKF9yZW1vdGVMb2NrUG9sbE9uY2UsIDIwMDAwKTsKICAgICAgICBzZXRUaW1lb3V0KF9yZW1vdGVMb2NrUG9sbE9uY2UsIDYwMDApOwogICAgfQogICAgZnVuY3Rpb24gX2V4aXRSZW1vdGVMb2NrKCkgewogICAgICAgIF9yZW1vdGVMb2NrU3RhdGUuYWN0aXZlID0gZmFsc2U7CiAgICAgICAgdHJ5IHsgaWYgKF9yZW1vdGVMb2NrU3RhdGUudGltZXIpIHsgY2xlYXJJbnRlcnZhbChfcmVtb3RlTG9ja1N0YXRlLnRpbWVyKTsgX3JlbW90ZUxvY2tTdGF0ZS50aW1lciA9IG51bGw7IH0gfSBjYXRjaCAoXykge30KICAgICAgICB0cnkgeyBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbSgnX3RsX3JlbW90ZV9sb2NrZWQnKTsgfSBjYXRjaCAoXykge30KICAgICAgICB0cnkgeyBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbSgnX3RsX3BvaXNvbmVkJyk7IH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgdHJ5IHsgY29uc3QgZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnX3RsX3JsX292ZXJsYXknKTsgaWYgKGVsKSBlbC5yZW1vdmUoKTsgfSBjYXRjaCAoXykge30KICAgICAgICAvLyBU4buxIHJlbG9hZCDihpIgc2NyaXB0IGto4bufaSDEkeG7mW5nIGzhuqFpIHPhuqFjaCwga2V5IHbhuqtuIGPDsm4g4oaSIGTDuW5nIGLDrG5oIHRoxrDhu51uZwogICAgICAgIHNldFRpbWVvdXQoKCkgPT4geyB0cnkgeyB3aW5kb3cubG9jYXRpb24ucmVsb2FkKCk7IH0gY2F0Y2ggKF8pIHt9IH0sIDgwMCk7CiAgICB9CgogICAgLy8g4pSA4pSA4pSAIFBow6F0IGhp4buHbiBob29rIHbDoG8gbmF0aXZlIGZ1bmN0aW9ucyDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIAKICAgIC8vIFt2Ni41XSBN4bufIHLhu5luZyBkYW5oIHPDoWNoOiB0aMOqbSBmZXRjaC9YSFIvc2V0VGltZW91dC9zZXRJbnRlcnZhbC9ldmFsIChhbnRpLWhvb2svZHVtcCBj4buxYyBt4bqhbmgpCiAgICBmdW5jdGlvbiBfZGV0ZWN0SG9va05vdygpIHsKICAgICAgICAvLyBbdjYuNS4yXSBXSElURUxJU1QgbG9hZGVyIEtleVZhdWx0IChPTE1fdXNlci5qcyk6IG7DsyBob29rIFhIUi9mZXRjaCBuZ2F5IHThu6sgZG9jdW1lbnQtc3RhcnQuCiAgICAgICAgLy8gICAgICAgICAgTuG6v3UgbG9hZGVyIMSRYW5nIGNo4bqheSAod2luZG93Ll9fa3ZfcV9idWYgdOG7k24gdOG6oWkpIOKGkiBjw6FjIG5hdGl2ZSBi4buLIHdyYXAgbMOgIEPhu6ZBIFRBLCBraMO0bmcgcGjhuqNpIHNjcmlwdCBs4bqhLgogICAgICAgIGxldCBfa3ZMb2FkZXJBY3RpdmUgPSBmYWxzZTsKICAgICAgICB0cnkgeyBfa3ZMb2FkZXJBY3RpdmUgPSAhISgodHlwZW9mIHVuc2FmZVdpbmRvdyAhPT0gJ3VuZGVmaW5lZCcgPyB1bnNhZmVXaW5kb3cgOiB3aW5kb3cpLl9fa3ZfcV9idWYpOyB9IGNhdGNoIChfKSB7fQogICAgICAgIHRyeSB7IGlmICghRnVuY3Rpb24ucHJvdG90eXBlLnRvU3RyaW5nLnRvU3RyaW5nKCkuaW5jbHVkZXMoJ1tuYXRpdmUgY29kZV0nKSkgcmV0dXJuICdGdW5jdGlvbi5wcm90b3R5cGUudG9TdHJpbmcnOyB9IGNhdGNoIChfKSB7fQogICAgICAgIHRyeSB7IGlmICghT2JqZWN0LmRlZmluZVByb3BlcnR5LnRvU3RyaW5nKCkuaW5jbHVkZXMoJ1tuYXRpdmUgY29kZV0nKSkgICAgICAgcmV0dXJuICdPYmplY3QuZGVmaW5lUHJvcGVydHknOyB9ICAgICAgIGNhdGNoIChfKSB7fQogICAgICAgIHRyeSB7IGlmICghSlNPTi5wYXJzZS50b1N0cmluZygpLmluY2x1ZGVzKCdbbmF0aXZlIGNvZGVdJykpICAgICAgICAgICAgICAgICAgIHJldHVybiAnSlNPTi5wYXJzZSc7IH0gICAgICAgICAgICAgICAgICAgY2F0Y2ggKF8pIHt9CiAgICAgICAgaWYgKF9rdkxvYWRlckFjdGl2ZSkgcmV0dXJuIG51bGw7IC8vIGxvYWRlciBj4bunYSB0YSDEkWFuZyB3cmFwIGZldGNoL1hIUi9zZXRUaW1lb3V0IOKGkiBi4buPIHF1YSwga2jDtG5nIGtob8OhIG5o4bqnbQogICAgICAgIHRyeSB7IGlmICh0eXBlb2Ygd2luZG93LmZldGNoID09PSAnZnVuY3Rpb24nICYmICF3aW5kb3cuZmV0Y2gudG9TdHJpbmcoKS5pbmNsdWRlcygnW25hdGl2ZSBjb2RlXScpKSByZXR1cm4gJ3dpbmRvdy5mZXRjaCc7IH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgdHJ5IHsgaWYgKCFYTUxIdHRwUmVxdWVzdC5wcm90b3R5cGUub3Blbi50b1N0cmluZygpLmluY2x1ZGVzKCdbbmF0aXZlIGNvZGVdJykpICByZXR1cm4gJ1hNTEh0dHBSZXF1ZXN0Lm9wZW4nOyB9ICBjYXRjaCAoXykge30KICAgICAgICB0cnkgeyBpZiAoIVhNTEh0dHBSZXF1ZXN0LnByb3RvdHlwZS5zZW5kLnRvU3RyaW5nKCkuaW5jbHVkZXMoJ1tuYXRpdmUgY29kZV0nKSkgIHJldHVybiAnWE1MSHR0cFJlcXVlc3Quc2VuZCc7IH0gIGNhdGNoIChfKSB7fQogICAgICAgIHRyeSB7IGlmICghc2V0VGltZW91dC50b1N0cmluZygpLmluY2x1ZGVzKCdbbmF0aXZlIGNvZGVdJykpICByZXR1cm4gJ3NldFRpbWVvdXQnOyB9ICBjYXRjaCAoXykge30KICAgICAgICB0cnkgeyBpZiAoIXNldEludGVydmFsLnRvU3RyaW5nKCkuaW5jbHVkZXMoJ1tuYXRpdmUgY29kZV0nKSkgcmV0dXJuICdzZXRJbnRlcnZhbCc7IH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgdHJ5IHsgaWYgKCFldmFsLnRvU3RyaW5nKCkuaW5jbHVkZXMoJ1tuYXRpdmUgY29kZV0nKSkgICAgICAgIHJldHVybiAnZXZhbCc7IH0gICAgICAgIGNhdGNoIChfKSB7fQogICAgICAgIHRyeSB7IGlmICghRnVuY3Rpb24udG9TdHJpbmcoKS5pbmNsdWRlcygnW25hdGl2ZSBjb2RlXScpKSAgICByZXR1cm4gJ0Z1bmN0aW9uJzsgfSAgICBjYXRjaCAoXykge30KICAgICAgICByZXR1cm4gbnVsbDsKICAgIH0KICAgIC8vIFt2Ni41XSBEZXZUb29scyBkZXRlY3Rpb24gKG5naGkgbmfhu50gZHVtcCkg4oCUIGNo4buJIFTEgk5HIMSRw7JuIHN0cmlrZSBraGkgQ8WoTkcgcGjDoXQgaGnhu4duIGhvb2sKICAgIGZ1bmN0aW9uIF9kZXZ0b29sc09wZW4oKSB7CiAgICAgICAgdHJ5IHsgcmV0dXJuICh3aW5kb3cub3V0ZXJXaWR0aCAtIHdpbmRvdy5pbm5lcldpZHRoID4gMTYwKSB8fCAod2luZG93Lm91dGVySGVpZ2h0IC0gd2luZG93LmlubmVySGVpZ2h0ID4gMjAwKTsgfSBjYXRjaCAoXykgeyByZXR1cm4gZmFsc2U7IH0KICAgIH0KICAgIC8vIEVhcmx5LWNoZWNrOiBjaOG6oXkgTkdBWSB04bqhaSBkZWZpbml0aW9uLXRpbWUsIFRSxq/hu5pDIGluamVjdFBhZ2VIb29rIOKUgAogICAgX3ByZVNjYW5Ib29rID0gX2RldGVjdEhvb2tOb3coKTsKCiAgICAvLyDilIDilIDilIAgUGjDoXQgaGnhu4duIHNjcmlwdCBzb25nIHNvbmcgcXVhIEJyb2FkY2FzdENoYW5uZWwg4pSA4pSACiAgICBmdW5jdGlvbiBfaW5pdEd1YXJkQkMoKSB7CiAgICAgICAgdHJ5IHsKICAgICAgICAgICAgY29uc3QgY2hOYW1lID0gJ190bHRnXycgKyBBUElfU0VDUkVULnNsaWNlKDAsIDgpOwogICAgICAgICAgICBfZ3VhcmRCQyA9IG5ldyBCcm9hZGNhc3RDaGFubmVsKGNoTmFtZSk7CiAgICAgICAgICAgIF9ndWFyZEJDLm9ubWVzc2FnZSA9IChldnQpID0+IHsKICAgICAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgICAgICAgLy8gW3Y2LXNtYXJ0XSBDaOG7iSBDw5lORyBzY3JpcHQgdGEgbeG7m2kgZ+G7rWkgVExfSEIgdHLDqm4ga8OqbmggYsOtIG3huq10IG7DoHkuCiAgICAgICAgICAgICAgICAgICAgLy8gTmjhuq1uIMSRxrDhu6NjID0gdGFiIGtow6FjIGPhu6dhIENIw41OSCBzY3JpcHQgbsOgeSAodXNlciBt4bufIG5oaeG7gXUgdGFiKSDihpIgQsOMTkggVEjGr+G7nE5HLCBLSMOUTkcga2hvw6EuCiAgICAgICAgICAgICAgICAgICAgLy8gKFNjcmlwdCBs4bqhIGtow7RuZyBiaeG6v3QgdMOqbiBrw6puaCArIMSR4buLbmggZOG6oW5nIG7DoHkgbsOqbiBraMO0bmcgdGjhu4MgZ2nhuqMgbeG6oW8uKQogICAgICAgICAgICAgICAgICAgIGlmIChldnQgJiYgZXZ0LmRhdGEgJiYgZXZ0LmRhdGEudCA9PT0gJ1RMX0hCJykgewogICAgICAgICAgICAgICAgICAgICAgICAvLyBjaOG7iSBnaGkgbmjhuq1uLCBraMO0bmcgbMOgbSBnw6wg4oCUIG5oaeG7gXUgdGFiIGzDoCBow6BuaCB2aSBo4bujcCBs4buHCiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgICAgICAgfTsKICAgICAgICAgICAgLy8gR+G7rWkgaGVhcnRiZWF0IGzhuqduIMSR4bqndSBzYXUgNzAwbXMgKGNobyBwaMOpcCBj4bqjIDIgaW5zdGFuY2Ugc2V0dXAgeG9uZykKICAgICAgICAgICAgc2V0VGltZW91dCgoKSA9PiB7IHRyeSB7IGlmIChfZ3VhcmRCQykgX2d1YXJkQkMucG9zdE1lc3NhZ2UoeyB0OiAnVExfSEInLCB0czogRGF0ZS5ub3coKSB9KTsgfSBjYXRjaCAoXykge30gfSwgNzAwKTsKICAgICAgICAgICAgLy8gSGVhcnRiZWF0IMSR4buLbmgga+G7syBt4buXaSAxNXMg4oCUIHBow6F0IGhp4buHbiBzY3JpcHQgY8OgaSBtdeG7mW4KICAgICAgICAgICAgc2V0SW50ZXJ2YWwoKCkgPT4geyB0cnkgeyBpZiAoX2d1YXJkQkMpIF9ndWFyZEJDLnBvc3RNZXNzYWdlKHsgdDogJ1RMX0hCJywgdHM6IERhdGUubm93KCkgfSk7IH0gY2F0Y2ggKF8pIHt9IH0sIDE1MDAwKTsKICAgICAgICB9IGNhdGNoIChfKSB7CiAgICAgICAgICAgIF9pbml0R3VhcmRMUygpOyAvLyBCcm9hZGNhc3RDaGFubmVsIGtow7RuZyBo4buXIHRy4bujIOKGkiBmYWxsYmFjayBMUwogICAgICAgIH0KICAgIH0KCiAgICAvLyDilIDilIDilIAgRmFsbGJhY2s6IHBow6F0IGhp4buHbiBxdWEgbG9jYWxTdG9yYWdlIHRpbWVzdGFtcCDilIDilIDilIAKICAgIGZ1bmN0aW9uIF9pbml0R3VhcmRMUygpIHsKICAgICAgICBjb25zdCBUU19LRVkgPSAnX3RsX2d1YXJkX3RzJzsKICAgICAgICBjb25zdCBub3cgICAgPSBEYXRlLm5vdygpOwogICAgICAgIGNvbnN0IHByZXYgICA9IHBhcnNlSW50KGxvY2FsU3RvcmFnZS5nZXRJdGVtKFRTX0tFWSkgfHwgJzAnKTsKICAgICAgICAvLyBbdjYtc21hcnRdIFRpbWVzdGFtcCBn4bqnbiA9IHVzZXIgRjUgbmhhbmggaG/hurdjIG3hu58gbmhp4buBdSB0YWIgQ8OZTkcgc2NyaXB0IOKGkiBCw4xOSCBUSMav4bucTkcsIEtIw5RORyBraG/DoS4KICAgICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShUU19LRVksIG5vdy50b1N0cmluZygpKTsKICAgICAgICBzZXRJbnRlcnZhbCgoKSA9PiB7IHRyeSB7IGxvY2FsU3RvcmFnZS5zZXRJdGVtKFRTX0tFWSwgRGF0ZS5ub3coKS50b1N0cmluZygpKTsgfSBjYXRjaCAoXykge30gfSwgMjUwMCk7CiAgICB9CgogICAgLy8g4pSA4pSA4pSAIFF1w6l0IMSR4buLbmgga+G7syBt4buXaSA3IGdpw6J5IOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgAogICAgZnVuY3Rpb24gX3N0YXJ0UGVyaW9kaWNTY2FuKCkgewogICAgICAgIF9ndWFyZFRpbWVyID0gc2V0SW50ZXJ2YWwoKCkgPT4gewogICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgLy8gW3Y2LXNtYXJ0XSBNaeG7hW4gbmhp4buFbSA2MHMgxJHhuqd1ICh0cmFuZy9leHRlbnNpb24gxJFhbmcga2jhu59pIHThuqFvLCBjw7MgdGjhu4MgYuG7jWMgbmF0aXZlIHThuqFtIHRo4budaSkKICAgICAgICAgICAgICAgIGlmIChEYXRlLm5vdygpIC0gX0dVQVJEX1NUQVJUX1RTIDwgNjAwMDApIHJldHVybjsKICAgICAgICAgICAgICAgIGNvbnN0IGggPSBfZGV0ZWN0SG9va05vdygpOwogICAgICAgICAgICAgICAgaWYgKGgpIHsKICAgICAgICAgICAgICAgICAgICAvLyBbdjYuNV0gTuG6v3UgxJHhu5NuZyB0aOG7nWkgbeG7nyBEZXZUb29scyAobmdoaSBkdW1wKSDihpIgxJHDsm4gc3RyaWtlIGfhuqVwIMSRw7RpCiAgICAgICAgICAgICAgICAgICAgX2hvb2tTdHJpa2UgKz0gX2RldnRvb2xzT3BlbigpID8gMiA6IDE7CiAgICAgICAgICAgICAgICAgICAgLy8gW3Y2LXNtYXJ0XSBZw6p1IGPhuqd1IDMgbOG6p24gbGnDqm4gdOG7pWMgbeG7m2kga+G6v3QgbHXhuq1uIGPDsyBob29rIHRo4bqtdCDihpIgcmVtb3RlLWxvY2sgKGFkbWluIG3hu58ga2hvw6EgxJHGsOG7o2MpLgogICAgICAgICAgICAgICAgICAgIGlmIChfaG9va1N0cmlrZSA+PSAzKSB7CiAgICAgICAgICAgICAgICAgICAgICAgIGNsZWFySW50ZXJ2YWwoX2d1YXJkVGltZXIpOyBfZ3VhcmRUaW1lciA9IG51bGw7CiAgICAgICAgICAgICAgICAgICAgICAgIF9lbnRlclJlbW90ZUxvY2soJ/Cfm6HvuI8gUGjDoXQgaGnhu4duIHBo4bqnbiBt4buBbSBs4bqhIGNhbiB0aGnhu4dwIGxpw6puIHThu6VjIHbDoG8gJyArIGggKyAnICjEkcOjIHjDoWMgbmjhuq1uIDMgbOG6p24pLiDEkMOjIGLDoW8gY8OhbyBhZG1pbiwgY2jhu50gbeG7nyBraG/DoSB04burIHhhLicpOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgICAgICAgICAgX2hvb2tTdHJpa2UgPSAwOyAvLyBxdcOpdCBz4bqhY2gg4oaSIHJlc2V0IMSR4bq/bQogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9IGNhdGNoIChfKSB7fQogICAgICAgIH0sIDUwMDApOyAvLyBbdjYuNV0gcXXDqXQgbmhhbmggaMahbiAoNXMpIOKAlCBwaMOhdCBoaeG7h24gc+G7m20gaMahbgogICAgfQoKICAgIC8vIOKUgOKUgOKUgCBLaOG7n2kgdOG6oW8gdG/DoG4gYuG7mSBo4buHIHRo4buRbmcgYuG6o28gduG7hyDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIAKICAgIGZ1bmN0aW9uIF9pbml0R3VhcmQoKSB7CiAgICAgICAgaWYgKF9ndWFyZEFjdGl2ZSkgcmV0dXJuOwogICAgICAgIF9ndWFyZEFjdGl2ZSA9IHRydWU7CiAgICAgICAgLy8gW3Y2LXNtYXJ0XSBNSUdSQVRJT046IGPhu50gcG9pc29uZWQgZG8gYuG6o24gY8WpIChkw7IgbmjhuqdtKSDEkeG6t3Qg4oaSIHThu7EgZ+G7oSBt4buZdCBs4bqnbiDEkeG7gyBuZ8aw4budaSBkw7luZyBkw7luZyBs4bqhaS4KICAgICAgICAvLyAgICAgICAgICAgICBC4bqjbiB2NiB0cuG7nyBsw6puIGNo4buJIMSR4bq3dCBwb2lzb25lZCBraGkgxJHDoyBYw4FDIE5I4bqsTiAoMyBs4bqnbiBsacOqbiB04bulYykgc2NyaXB0IGzhuqEgdGjhuq10LgogICAgICAgIHRyeSB7CiAgICAgICAgICAgIGlmIChsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgnX3RsX2d1YXJkX3ZlcicpICE9PSAnNicpIHsKICAgICAgICAgICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKCdfdGxfcG9pc29uZWQnKTsKICAgICAgICAgICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKCdfdGxfZ3VhcmRfdmVyJywgJzYnKTsKICAgICAgICAgICAgfQogICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgLy8gW3Y2LjRdIEPhu50gcG9pc29uZWQgLyBfdGxfcmVtb3RlX2xvY2tlZCDEkcaw4bujYyB44butIGzDvSDhu58gc3RhcnR1cCAoYsOhbyBzZXJ2ZXIgKyBjaOG7nSBhZG1pbiBt4bufIGtob8OhKS4KICAgICAgICBfaW5pdEd1YXJkQkMoKTsKICAgICAgICBfc3RhcnRQZXJpb2RpY1NjYW4oKTsKICAgIH0KICAgIC8vIOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkAogICAgLy8gIFtlbmQgdjUgc2VjdXJpdHkgbW9kdWxlXQogICAgLy8g4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQCgogICAgZnVuY3Rpb24gX2NyeXB0b09iaigpIHsgcmV0dXJuICh0eXBlb2YgY3J5cHRvICE9PSAndW5kZWZpbmVkJyA/IGNyeXB0byA6IHdpbmRvdy5jcnlwdG8pOyB9CgogICAgYXN5bmMgZnVuY3Rpb24gX2htYWNIZXgoc2VjcmV0LCBzdHIpIHsKICAgICAgICBjb25zdCBlbmMgPSBuZXcgVGV4dEVuY29kZXIoKSwgYyA9IF9jcnlwdG9PYmooKTsKICAgICAgICBjb25zdCBrZXkgPSBhd2FpdCBjLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGVuYy5lbmNvZGUoc2VjcmV0KSwgeyBuYW1lOiAnSE1BQycsIGhhc2g6ICdTSEEtMjU2JyB9LCBmYWxzZSwgWydzaWduJ10pOwogICAgICAgIGNvbnN0IHNpZyA9IGF3YWl0IGMuc3VidGxlLnNpZ24oJ0hNQUMnLCBrZXksIGVuYy5lbmNvZGUoc3RyKSk7CiAgICAgICAgcmV0dXJuIEFycmF5LmZyb20obmV3IFVpbnQ4QXJyYXkoc2lnKSkubWFwKGIgPT4gYi50b1N0cmluZygxNikucGFkU3RhcnQoMiwgJzAnKSkuam9pbignJyk7CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gX2FwaVByZWZpeCgpIHsKICAgICAgICBpZiAoIV9hcGlQcmVmaXhDYWNoZSkKICAgICAgICAgICAgX2FwaVByZWZpeENhY2hlID0gJy8nICsgKGF3YWl0IF9obWFjSGV4KEFQSV9TRUNSRVQsICdnb2Rtb2RlOmFwaTpwcmVmaXg6djQnKSkuc2xpY2UoMCwgMTIpOwogICAgICAgIHJldHVybiBfYXBpUHJlZml4Q2FjaGU7CiAgICB9CiAgICAvLyBbdjYuNV0gS8OdIFJFUVVFU1QgSE1BQyDigJQgY2jhu5FuZyBmYWtlIC8gcmVwbGF5IC8gdGFtcGVyIChraOG7m3Agc2VydmVyIHZlcmlmeVJlcVNpZykKICAgIC8vIFNpZ24gPSBITUFDX1NIQTI1NihBUElfU0VDUkVULCB0c3xub25jZXxzaGEyNTYoYm9keSl8c2Vzc2lvblRva2VuKQogICAgYXN5bmMgZnVuY3Rpb24gX3NpZ25SZXEoYm9keVN0ciwgc2Vzc2lvblRvaykgewogICAgICAgIGNvbnN0IGMgPSBfY3J5cHRvT2JqKCksIGVuYyA9IG5ldyBUZXh0RW5jb2RlcigpOwogICAgICAgIGNvbnN0IHRzID0gTWF0aC5mbG9vcihEYXRlLm5vdygpIC8gMTAwMCkudG9TdHJpbmcoKTsKICAgICAgICBjb25zdCBub25jZSA9IEFycmF5LmZyb20oYy5nZXRSYW5kb21WYWx1ZXMobmV3IFVpbnQ4QXJyYXkoOCkpLCBiID0+IGIudG9TdHJpbmcoMTYpLnBhZFN0YXJ0KDIsICcwJykpLmpvaW4oJycpOwogICAgICAgIGNvbnN0IGJvZHlIYXNoQnVmID0gYXdhaXQgYy5zdWJ0bGUuZGlnZXN0KCdTSEEtMjU2JywgZW5jLmVuY29kZShib2R5U3RyIHx8ICcnKSk7CiAgICAgICAgY29uc3QgYm9keUhhc2ggPSBBcnJheS5mcm9tKG5ldyBVaW50OEFycmF5KGJvZHlIYXNoQnVmKSkubWFwKGIgPT4gYi50b1N0cmluZygxNikucGFkU3RhcnQoMiwgJzAnKSkuam9pbignJyk7CiAgICAgICAgY29uc3QgaG1hY0tleSA9IGF3YWl0IGMuc3VidGxlLmltcG9ydEtleSgncmF3JywgZW5jLmVuY29kZShBUElfU0VDUkVUKSwgeyBuYW1lOiAnSE1BQycsIGhhc2g6ICdTSEEtMjU2JyB9LCBmYWxzZSwgWydzaWduJ10pOwogICAgICAgIGNvbnN0IHNpZ0J1ZiA9IGF3YWl0IGMuc3VidGxlLnNpZ24oJ0hNQUMnLCBobWFjS2V5LCBlbmMuZW5jb2RlKHRzICsgJ3wnICsgbm9uY2UgKyAnfCcgKyBib2R5SGFzaCArICd8JyArIChzZXNzaW9uVG9rIHx8ICcnKSkpOwogICAgICAgIGNvbnN0IHNpZ24gPSBBcnJheS5mcm9tKG5ldyBVaW50OEFycmF5KHNpZ0J1ZikpLm1hcChiID0+IGIudG9TdHJpbmcoMTYpLnBhZFN0YXJ0KDIsICcwJykpLmpvaW4oJycpOwogICAgICAgIHJldHVybiB7ICdYLVRzJzogdHMsICdYLU5vbmNlJzogbm9uY2UsICdYLVNpZ24nOiBzaWduIH07CiAgICB9CgogICAgZnVuY3Rpb24gX2NvbGxlY3REZXZpY2UoKSB7CiAgICAgICAgY29uc3QgdWEgPSBuYXZpZ2F0b3IudXNlckFnZW50IHx8ICcnOwogICAgICAgIGNvbnN0IGlzQW5kcm9pZCA9IC9hbmRyb2lkL2kudGVzdCh1YSk7CiAgICAgICAgY29uc3QgaXNJT1MgPSAvaXBob25lfGlwYWR8aXBvZC9pLnRlc3QodWEpOwogICAgICAgIGxldCBtb2RlbCA9ICcnOwogICAgICAgIGlmIChpc0FuZHJvaWQpIHsKICAgICAgICAgICAgY29uc3QgbSA9IHVhLm1hdGNoKC87XHMqKFteOyldKz8pXHMrQnVpbGRcLy9pKSB8fCB1YS5tYXRjaCgvYW5kcm9pZFxzK1teOyldKztccyooW147KV0rKS9pKTsKICAgICAgICAgICAgbW9kZWwgPSBtID8gbVsxXS50cmltKCkgOiAnJzsKICAgICAgICB9IGVsc2UgaWYgKGlzSU9TKSB7CiAgICAgICAgICAgIG1vZGVsID0gL2lwYWQvaS50ZXN0KHVhKSA/ICdpUGFkJyA6IC9pcG9kL2kudGVzdCh1YSkgPyAnaVBvZCcgOiAnaVBob25lJzsKICAgICAgICB9CiAgICAgICAgY29uc3QgY29ubiA9IG5hdmlnYXRvci5jb25uZWN0aW9uIHx8IG5hdmlnYXRvci5tb3pDb25uZWN0aW9uIHx8IG5hdmlnYXRvci53ZWJraXRDb25uZWN0aW9uOwogICAgICAgIHJldHVybiB7CiAgICAgICAgICAgIG9zOiBpc0FuZHJvaWQgPyAnQW5kcm9pZCcgOiBpc0lPUyA/ICdpT1MnIDogKG5hdmlnYXRvci5wbGF0Zm9ybSB8fCAnVW5rbm93bicpLAogICAgICAgICAgICBtb2RlbDogbW9kZWwgfHwgJycsIGJyYW5kOiAnJywgaXNNb2JpbGU6IGlzQW5kcm9pZCB8fCBpc0lPUywKICAgICAgICAgICAgdG91Y2hQb2ludHM6IG5hdmlnYXRvci5tYXhUb3VjaFBvaW50cyB8fCAwLAogICAgICAgICAgICBjb3JlczogbmF2aWdhdG9yLmhhcmR3YXJlQ29uY3VycmVuY3kgfHwgMCwKICAgICAgICAgICAgbWVtb3J5OiBuYXZpZ2F0b3IuZGV2aWNlTWVtb3J5IHx8IDAsCiAgICAgICAgICAgIHNjcmVlbjogYCR7c2NyZWVuLndpZHRofXgke3NjcmVlbi5oZWlnaHR9YCwKICAgICAgICAgICAgcGl4ZWxSYXRpbzogd2luZG93LmRldmljZVBpeGVsUmF0aW8gfHwgMSwKICAgICAgICAgICAgY29ubmVjdGlvbjogY29ubiA/IChjb25uLmVmZmVjdGl2ZVR5cGUgfHwgJycpIDogJycsCiAgICAgICAgICAgIHZlbmRvcjogbmF2aWdhdG9yLnZlbmRvciB8fCAnJywKICAgICAgICAgICAgbGFuZ3VhZ2U6IG5hdmlnYXRvci5sYW5ndWFnZSB8fCAnJywKICAgICAgICAgICAgdGltZXpvbmU6IChJbnRsLkRhdGVUaW1lRm9ybWF0KCkucmVzb2x2ZWRPcHRpb25zKCkudGltZVpvbmUpIHx8ICcnLAogICAgICAgICAgICB3ZWJkcml2ZXI6ICEhbmF2aWdhdG9yLndlYmRyaXZlcgogICAgICAgIH07CiAgICB9CgogICAgZnVuY3Rpb24gX2NvbGxlY3RGUCgpIHsKICAgICAgICByZXR1cm4gewogICAgICAgICAgICB1YTogbmF2aWdhdG9yLnVzZXJBZ2VudCwgcGxhdGZvcm06IG5hdmlnYXRvci5wbGF0Zm9ybSB8fCAnJywKICAgICAgICAgICAgbGFuZ3VhZ2U6IG5hdmlnYXRvci5sYW5ndWFnZSB8fCAnJywKICAgICAgICAgICAgdGltZXpvbmU6IChJbnRsLkRhdGVUaW1lRm9ybWF0KCkucmVzb2x2ZWRPcHRpb25zKCkudGltZVpvbmUpIHx8ICcnLAogICAgICAgICAgICB3ZWJkcml2ZXI6ICEhbmF2aWdhdG9yLndlYmRyaXZlciwKICAgICAgICAgICAgaGFyZHdhcmVDb25jdXJyZW5jeTogbmF2aWdhdG9yLmhhcmR3YXJlQ29uY3VycmVuY3kgfHwgMCwKICAgICAgICAgICAgZGV2aWNlTWVtb3J5OiBuYXZpZ2F0b3IuZGV2aWNlTWVtb3J5IHx8IDAsCiAgICAgICAgICAgIG1heFRvdWNoUG9pbnRzOiBuYXZpZ2F0b3IubWF4VG91Y2hQb2ludHMgfHwgMCwKICAgICAgICAgICAgc2NyZWVuOiBgJHtzY3JlZW4ud2lkdGh9eCR7c2NyZWVuLmhlaWdodH1gLAogICAgICAgICAgICBjb2xvckRlcHRoOiBzY3JlZW4uY29sb3JEZXB0aCwgcGl4ZWxSYXRpbzogd2luZG93LmRldmljZVBpeGVsUmF0aW8gfHwgMQogICAgICAgIH07CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gX2Rlcml2ZUtleShzZXNzaW9uVG9rZW4pIHsKICAgICAgICBjb25zdCBlbmMgPSBuZXcgVGV4dEVuY29kZXIoKSwgYyA9IF9jcnlwdG9PYmooKTsKICAgICAgICBjb25zdCBiYXNlS2V5ID0gYXdhaXQgYy5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBlbmMuZW5jb2RlKHNlc3Npb25Ub2tlbiArICd8JyArIEFQSV9TRUNSRVQpLCAnUEJLREYyJywgZmFsc2UsIFsnZGVyaXZlQml0cyddKTsKICAgICAgICBjb25zdCBiaXRzID0gYXdhaXQgYy5zdWJ0bGUuZGVyaXZlQml0cyh7IG5hbWU6ICdQQktERjInLCBzYWx0OiBlbmMuZW5jb2RlKCdnb2Rtb2RlLXY0LXNhbHQnKSwgaXRlcmF0aW9uczogMTAwMCwgaGFzaDogJ1NIQS0yNTYnIH0sIGJhc2VLZXksIDI1Nik7CiAgICAgICAgcmV0dXJuIGMuc3VidGxlLmltcG9ydEtleSgncmF3JywgYml0cywgeyBuYW1lOiAnQUVTLUdDTScgfSwgZmFsc2UsIFsnZGVjcnlwdCddKTsKICAgIH0KCiAgICBmdW5jdGlvbiBfYjY0VG9CeXRlcyhiNjQpIHsKICAgICAgICBjb25zdCBiaW4gPSBhdG9iKGI2NCk7CiAgICAgICAgcmV0dXJuIFVpbnQ4QXJyYXkuZnJvbShiaW4sIHggPT4geC5jaGFyQ29kZUF0KDApKTsKICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBfZGVjcnlwdEFuc3dlcnMocGF5bG9hZCwgc2Vzc2lvblRva2VuKSB7CiAgICAgICAgY29uc3QgYyA9IF9jcnlwdG9PYmooKTsKICAgICAgICBjb25zdCBrZXkgPSBhd2FpdCBfZGVyaXZlS2V5KHNlc3Npb25Ub2tlbik7CiAgICAgICAgY29uc3QgaXYgPSBfYjY0VG9CeXRlcyhwYXlsb2FkLml2KSwgZGF0YSA9IF9iNjRUb0J5dGVzKHBheWxvYWQuZGF0YSksIHRhZyA9IF9iNjRUb0J5dGVzKHBheWxvYWQudGFnKTsKICAgICAgICBjb25zdCBidWYgPSBuZXcgVWludDhBcnJheShkYXRhLmxlbmd0aCArIHRhZy5sZW5ndGgpOyBidWYuc2V0KGRhdGEpOyBidWYuc2V0KHRhZywgZGF0YS5sZW5ndGgpOwogICAgICAgIGNvbnN0IHBsYWluID0gYXdhaXQgYy5zdWJ0bGUuZGVjcnlwdCh7IG5hbWU6ICdBRVMtR0NNJywgaXYgfSwga2V5LCBidWYpOwogICAgICAgIHJldHVybiBKU09OLnBhcnNlKG5ldyBUZXh0RGVjb2RlcigpLmRlY29kZShwbGFpbikpOwogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIF9lbnN1cmVTZXNzaW9uKGtleSwgaHdpZCkgewogICAgICAgIGlmIChfc2VjU2Vzc2lvbi50b2tlbiAmJiBfc2VjU2Vzc2lvbi5leHAgPiBEYXRlLm5vdygpKSByZXR1cm4gX3NlY1Nlc3Npb24udG9rZW47CiAgICAgICAgaWYgKCFrZXkpIHRocm93IG5ldyBFcnJvcignVGhp4bq/dSBrZXkg4oCUIGtow7RuZyB0aOG7gyB4w6FjIHRo4buxYyBwaGnDqm4nKTsKICAgICAgICBjb25zdCByID0gYXdhaXQgZ21Qb3N0KCcvYXR0ZXN0JywgeyBrZXksIGh3aWQ6IGh3aWQgfHwgZ2V0SFdJRCgpLCBmcDogX2NvbGxlY3RGUCgpLCBkZXZpY2U6IF9jb2xsZWN0RGV2aWNlKCkgfSk7CiAgICAgICAgaWYgKCFyLnN1Y2Nlc3MpIHRocm93IG5ldyBFcnJvcihyLm1lc3NhZ2UgfHwgJ1jDoWMgdGjhu7FjIHRoaeG6v3QgYuG7iy9t4bqhbmcgdGjhuqV0IGLhuqFpJyk7CiAgICAgICAgX3NlY1Nlc3Npb24gPSB7IHRva2VuOiByLnNlc3Npb24sIGV4cDogRGF0ZS5ub3coKSArIChyLmV4cGlyZXNJbiAtIDMwKSAqIDEwMDAsIGZwSGFzaDogci5mcEhhc2gsIHNlcTogMSB9OwogICAgICAgIGlmIChyLmRldmljZSkgQ1VSUkVOVF9ERVZJQ0UgPSByLmRldmljZTsKICAgICAgICByZXR1cm4gci5zZXNzaW9uOwogICAgfQoKICAgIC8vIFt2Nl0gVOG6o2kgQ0jhu6YgxJDhu5hORyBtb2R1bGUgIkNIVeG6qE4gQuG7iiAxMCDEkEnhu4JNIiB04burIHNlcnZlciAoY2jhu4kgcHJlbWl1bSkKICAgIGFzeW5jIGZ1bmN0aW9uIF9sb2FkRmlyZU1vZHVsZSgpIHsKICAgICAgICBpZiAoX2ZpcmVNb2R1bGUuZmFjdG9yeSkgcmV0dXJuIHRydWU7CiAgICAgICAgaWYgKF9maXJlTW9kdWxlLmxvYWRpbmcpIHJldHVybiBmYWxzZTsKICAgICAgICBpZiAoIWlzUHJlbWl1bUtleSgpKSByZXR1cm4gZmFsc2U7CiAgICAgICAgX2ZpcmVNb2R1bGUubG9hZGluZyA9IHRydWU7CiAgICAgICAgdHJ5IHsKICAgICAgICAgICAgY29uc3Qga2V5ID0gQ1VSUkVOVF9LRVkgfHwgX3NMUy5nZXQoTFNfS0VZKTsKICAgICAgICAgICAgaWYgKCFrZXkpIHJldHVybiBmYWxzZTsKICAgICAgICAgICAgYXdhaXQgZ21Qb3N0KCcvbW9kdWxlJywgeyBrZXksIGh3aWQ6IGdldEhXSUQoKSB9KTsKICAgICAgICAgICAgcmV0dXJuICEhX2ZpcmVNb2R1bGUuZmFjdG9yeTsKICAgICAgICB9IGNhdGNoIChlKSB7CiAgICAgICAgICAgIF9maXJlTW9kdWxlLmxhc3RFcnIgPSBlLm1lc3NhZ2U7CiAgICAgICAgICAgIHJldHVybiBmYWxzZTsKICAgICAgICB9IGZpbmFsbHkgewogICAgICAgICAgICBfZmlyZU1vZHVsZS5sb2FkaW5nID0gZmFsc2U7CiAgICAgICAgfQogICAgfQoKICAgIC8vIFt2Nl0gSGVhcnRiZWF0IGxpw6puIHThu6VjICgzMHMpIOKAlCBn4butaSBmcC9kZXZpY2UgbeG7m2kgY2hvIHNlcnZlciBjaGVjay4KICAgIC8vIE7hur91IHNlcnZlciB0cuG6oyBibG9ja2VkIGhv4bq3YyA0MDQgKMSRw6MgYuG7iyBiYW4pIOKGkiBU4buwIEhV4bu2ICh4w7NhIGtleSArIFVJKS4KICAgIC8vIE7hur91IHNlcnZlciDEkeG6qXkgbW9kdWxlIG3hu5tpIOKGkiB04buxIG7huqFwIGzhuqFpLiBN4bqldCBt4bqhbmcga8OpbyBkw6BpIOKGkiBraMOzYSB04bqhbSBtb2R1bGUuCiAgICBmdW5jdGlvbiBfc3RhcnRIZWFydGJlYXQoKSB7CiAgICAgICAgaWYgKF9oZWFydGJlYXRUaW1lcikgcmV0dXJuOwogICAgICAgIF9oZWFydGJlYXRUaW1lciA9IHNldEludGVydmFsKGFzeW5jICgpID0+IHsKICAgICAgICAgICAgaWYgKCFDVVJSRU5UX0tFWSkgcmV0dXJuOwogICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgY29uc3QgciA9IGF3YWl0IGdtUG9zdCgnL2hlYXJ0YmVhdCcsIHsKICAgICAgICAgICAgICAgICAgICBrZXk6IENVUlJFTlRfS0VZLCBod2lkOiBnZXRIV0lEKCksCiAgICAgICAgICAgICAgICAgICAgZnA6IF9jb2xsZWN0RlAoKSwgZGV2aWNlOiBfY29sbGVjdERldmljZSgpLAogICAgICAgICAgICAgICAgICAgIGNsaWVudFZlcnNpb246IF9maXJlTW9kdWxlLnZlcnNpb24KICAgICAgICAgICAgICAgIH0pOwogICAgICAgICAgICAgICAgX2hlYXJ0YmVhdEZhaWwgPSAwOwogICAgICAgICAgICAgICAgaWYgKHIgJiYgci5ibG9ja2VkKSB7CiAgICAgICAgICAgICAgICAgICAgLy8gW3Y2LjNdIFNlcnZlciBiYW4g4oaSIGJhbi1tb2RlICh04buxIG3hu58gbOG6oWkga2hpIGFkbWluIHVuYmFuKSwgS0jDlE5HIGtob8OhIHbEqW5oIHZp4buFbgogICAgICAgICAgICAgICAgICAgIF9lbnRlckJhbk1vZGUoJ1NlcnZlciBwaMOhdCBoaeG7h24gbcO0aSB0csaw4budbmcga2jDtG5nIGjhu6NwIGzhu4cgKCcgKyAoci5yZWFzb24gfHwgJ3Vua25vd24nKSArICcpLicpOwogICAgICAgICAgICAgICAgICAgIHJldHVybjsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIGlmIChyICYmIHIuX2h0dHBTdGF0dXMgPT09IDQwNCkgewogICAgICAgICAgICAgICAgICAgIC8vIFt2Ni4zXSA0MDQgdHLDqm4gZW5kcG9pbnQg4bqpbiA9IMSRw6MgYuG7iyBiYW4gSVAvdGhp4bq/dCBi4buLIOKGkiBiYW4tbW9kZSB04buxIG3hu58gbOG6oWkKICAgICAgICAgICAgICAgICAgICBfZW50ZXJCYW5Nb2RlKCdUaGnhur90IGLhu4svSVAgxJHDoyBi4buLIGFkbWluIGtob8OhLicpOwogICAgICAgICAgICAgICAgICAgIHJldHVybjsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfSBjYXRjaCAoZSkgewogICAgICAgICAgICAgICAgX2hlYXJ0YmVhdEZhaWwrKzsKICAgICAgICAgICAgICAgIGlmIChfaGVhcnRiZWF0RmFpbCA+PSAxMCkgewogICAgICAgICAgICAgICAgICAgIGFkZExvZygn4pqg77iPIE3huqV0IGvhur90IG7hu5FpIHNlcnZlciBrw6lvIGTDoGkg4oCUIGNo4bupYyBuxINuZyBu4buZcCBiw6BpIHThuqFtIGtow7NhIGNobyB04bubaSBraGkga+G6v3QgbuG7kWkgbOG6oWkuJywgJ3dhcm4nKTsKICAgICAgICAgICAgICAgICAgICBfZmlyZU1vZHVsZS5mYWN0b3J5ID0gbnVsbDsgLy8gYnXhu5ljIHThuqNpIGzhuqFpIGtoaSBjw7Mga+G6v3QgbuG7kWkKICAgICAgICAgICAgICAgICAgICBfaGVhcnRiZWF0RmFpbCA9IDA7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KICAgICAgICB9LCAzMDAwMCk7CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gZ21Qb3N0KHBhdGgsIGRhdGEpIHsKICAgICAgICBjb25zdCBoZWFkZXJzID0geyAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nIH07CiAgICAgICAgbGV0IHNlc3Npb25Ub2tlbiA9IG51bGw7CiAgICAgICAgY29uc3QgcHJlZml4ID0gYXdhaXQgX2FwaVByZWZpeCgpOwogICAgICAgIGNvbnN0IGFjdHVhbFBhdGggPSBwcmVmaXggKyBwYXRoOwogICAgICAgIGlmIChwYXRoID09PSAnL3Byb2Nlc3MnIHx8IHBhdGggPT09ICcvZmlyZScgfHwgcGF0aCA9PT0gJy9tb2R1bGUnKSB7CiAgICAgICAgICAgIHNlc3Npb25Ub2tlbiA9IGF3YWl0IF9lbnN1cmVTZXNzaW9uKChkYXRhICYmIGRhdGEua2V5KSwgKGRhdGEgJiYgZGF0YS5od2lkKSk7CiAgICAgICAgICAgIGhlYWRlcnNbJ1gtU2Vzc2lvbiddID0gc2Vzc2lvblRva2VuOwogICAgICAgICAgICBoZWFkZXJzWydYLVNlcSddICAgICA9IFN0cmluZyhfc2VjU2Vzc2lvbi5zZXEgfHwgMSk7CiAgICAgICAgICAgIGlmIChfc2VjU2Vzc2lvbi5mcEhhc2gpIGhlYWRlcnNbJ1gtRnAtSGFzaCddID0gX3NlY1Nlc3Npb24uZnBIYXNoOwogICAgICAgIH0KCiAgICAgICAgLy8gW3Y1XSBNw6MgaG/DoSByZXF1ZXN0IGJvZHkgbuG6v3UgUkVRVUVTVF9FTkNSWVBUSU9OID0gdHJ1ZQogICAgICAgIGxldCByZXFCb2R5ID0gSlNPTi5zdHJpbmdpZnkoZGF0YSk7CiAgICAgICAgaWYgKFJFUVVFU1RfRU5DUllQVElPTikgewogICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgY29uc3QgZW5jID0gYXdhaXQgX2VuY3J5cHRQYXlsb2FkKGRhdGEsIHNlc3Npb25Ub2tlbiB8fCBfYXBpUHJlZml4Q2FjaGUgfHwgJycpOwogICAgICAgICAgICAgICAgcmVxQm9keSA9IEpTT04uc3RyaW5naWZ5KGVuYyk7CiAgICAgICAgICAgICAgICBoZWFkZXJzWydYLUVuYy1WJ10gPSAnNSc7IC8vIGLDoW8gc2VydmVyIGJp4bq/dCBwYXlsb2FkIMSRw6MgbcOjIGhvw6EKICAgICAgICAgICAgfSBjYXRjaCAoXykgeyAvKiBmYWxsYmFjayBzYW5nIHBsYWluIEpTT04gbuG6v3UgZW5jcnlwdCBs4buXaSAqLyB9CiAgICAgICAgfQogICAgICAgIC8vIFt2Ni41XSBLw70gcmVxdWVzdCBITUFDIChhbnRpIGZha2UgLyByZXBsYXkgLyB0YW1wZXIpCiAgICAgICAgdHJ5IHsgT2JqZWN0LmFzc2lnbihoZWFkZXJzLCBhd2FpdCBfc2lnblJlcShyZXFCb2R5LCBzZXNzaW9uVG9rZW4pKTsgfSBjYXRjaCAoXykge30KCiAgICAgICAgY29uc3QgcmVzdWx0ID0gYXdhaXQgbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4gewogICAgICAgICAgICBHTV94bWxodHRwUmVxdWVzdCh7CiAgICAgICAgICAgICAgICBtZXRob2Q6ICdQT1NUJywgdXJsOiBTRVJWRVJfQkFTRSArIGFjdHVhbFBhdGgsCiAgICAgICAgICAgICAgICBoZWFkZXJzLCBkYXRhOiByZXFCb2R5LCB0aW1lb3V0OiAxNTAwMCwKICAgICAgICAgICAgICAgIG9ubG9hZDogKHIpID0+IHsKICAgICAgICAgICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgICAgICAgICBjb25zdCBwYXJzZWQgPSBKU09OLnBhcnNlKHIucmVzcG9uc2VUZXh0KTsKICAgICAgICAgICAgICAgICAgICAgICAgcGFyc2VkLl9odHRwU3RhdHVzID0gci5zdGF0dXM7CiAgICAgICAgICAgICAgICAgICAgICAgIHJlc29sdmUocGFyc2VkKTsKICAgICAgICAgICAgICAgICAgICB9IGNhdGNoIChfKSB7IHJlamVjdChuZXcgRXJyb3IoJ1BhcnNlIGVycm9yIChIVFRQICcgKyByLnN0YXR1cyArICcpJykpOyB9CiAgICAgICAgICAgICAgICB9LAogICAgICAgICAgICAgICAgb25lcnJvcjogICAoKSA9PiByZWplY3QobmV3IEVycm9yKCdOZXR3b3JrIGVycm9yJykpLAogICAgICAgICAgICAgICAgb250aW1lb3V0OiAoKSA9PiByZWplY3QobmV3IEVycm9yKCdUaW1lb3V0JykpCiAgICAgICAgICAgIH0pOwogICAgICAgIH0pOwogICAgICAgIGlmIChwYXRoID09PSAnL3Byb2Nlc3MnICYmIHJlc3VsdCAmJiByZXN1bHQuZW5jcnlwdGVkICYmIHJlc3VsdC5wYXlsb2FkICYmIHNlc3Npb25Ub2tlbikgewogICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgcmVzdWx0LnF1ZXN0aW9ucyA9IGF3YWl0IF9kZWNyeXB0QW5zd2VycyhyZXN1bHQucGF5bG9hZCwgc2Vzc2lvblRva2VuKTsKICAgICAgICAgICAgICAgIHJlc3VsdC5lbmNyeXB0ZWQgPSBmYWxzZTsKICAgICAgICAgICAgfSBjYXRjaCAoZSkgewogICAgICAgICAgICAgICAgcmVzdWx0LnN1Y2Nlc3MgPSBmYWxzZTsKICAgICAgICAgICAgICAgIHJlc3VsdC5tZXNzYWdlID0gJ0dp4bqjaSBtw6MgxJHDoXAgw6FuIHRo4bqldCBi4bqhaTogJyArIGUubWVzc2FnZTsKICAgICAgICAgICAgfQogICAgICAgIH0KICAgICAgICAvLyBbdjZdIEdp4bqjaSBtw6MgKyBu4bqhcCBtb2R1bGUgIkNIVeG6qE4gQuG7iiAxMCDEkEnhu4JNIiBu4bq/dSBzZXJ2ZXIgYXV0by3EkcOtbmgga8OobSAoYXR0ZXN0L2hlYXJ0YmVhdC9tb2R1bGUpCiAgICAgICAgaWYgKHJlc3VsdCAmJiByZXN1bHQubW9kdWxlKSB7CiAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgICBsZXQgbW9kVG9rID0gbnVsbDsKICAgICAgICAgICAgICAgIGlmIChwYXRoID09PSAnL2F0dGVzdCcpICAgIG1vZFRvayA9IHJlc3VsdC5zZXNzaW9uOwogICAgICAgICAgICAgICAgZWxzZSBpZiAocGF0aCA9PT0gJy9oZWFydGJlYXQnKSBtb2RUb2sgPSByZXN1bHQubW9kdWxlU2Vzc2lvbjsKICAgICAgICAgICAgICAgIGVsc2UgICAgICAgICAgICAgICAgICAgICAgICAgICAgbW9kVG9rID0gc2Vzc2lvblRva2VuOyAvLyAvbW9kdWxlCiAgICAgICAgICAgICAgICBpZiAobW9kVG9rKSB7CiAgICAgICAgICAgICAgICAgICAgY29uc3QgbW9kID0gYXdhaXQgX2RlY3J5cHRBbnN3ZXJzKHJlc3VsdC5tb2R1bGUsIG1vZFRvayk7CiAgICAgICAgICAgICAgICAgICAgaWYgKG1vZCAmJiBtb2Quc3JjKSB7CiAgICAgICAgICAgICAgICAgICAgICAgIF9maXJlTW9kdWxlLmZhY3RvcnkgPSBuZXcgRnVuY3Rpb24oJ2N0eCcsIG1vZC5zcmMpOwogICAgICAgICAgICAgICAgICAgICAgICBfZmlyZU1vZHVsZS52ZXJzaW9uID0gbW9kLnYgfHwgMDsKICAgICAgICAgICAgICAgICAgICAgICAgX2ZpcmVNb2R1bGUubGFzdEVyciA9IG51bGw7CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9IGNhdGNoIChlKSB7IF9maXJlTW9kdWxlLmxhc3RFcnIgPSBlLm1lc3NhZ2U7IH0KICAgICAgICAgICAgZGVsZXRlIHJlc3VsdC5tb2R1bGU7CiAgICAgICAgICAgIGRlbGV0ZSByZXN1bHQubW9kdWxlU2Vzc2lvbjsKICAgICAgICB9CiAgICAgICAgaWYgKHJlc3VsdCAmJiByZXN1bHQubmV4dF9zZXNzaW9uKSB7CiAgICAgICAgICAgIF9zZWNTZXNzaW9uLnRva2VuID0gcmVzdWx0Lm5leHRfc2Vzc2lvbjsKICAgICAgICAgICAgX3NlY1Nlc3Npb24uZXhwICAgPSBEYXRlLm5vdygpICsgMjcwICogMTAwMDsKICAgICAgICAgICAgLy8gW3Y2LjUuMV0gxq91IHRpw6puIG5leHRfc2VxIGRvIHNlcnZlciBn4butaSAoY2jDrW5oIHjDoWMpLCBmYWxsYmFjayB04buxICsxCiAgICAgICAgICAgIF9zZWNTZXNzaW9uLnNlcSAgID0gcmVzdWx0Lm5leHRfc2VxID8gcGFyc2VJbnQocmVzdWx0Lm5leHRfc2VxLCAxMCkgOiAoX3NlY1Nlc3Npb24uc2VxIHx8IDEpICsgMTsKICAgICAgICAgICAgZGVsZXRlIHJlc3VsdC5uZXh0X3Nlc3Npb247CiAgICAgICAgICAgIGRlbGV0ZSByZXN1bHQubmV4dF9zZXE7CiAgICAgICAgfQogICAgICAgIHJldHVybiByZXN1bHQ7CiAgICB9CgogICAgLy8g4pSA4pSA4pSAIEzhuqV5IHRow7RuZyB0aW4gdOG7qyB0cmFuZyDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIAKICAgIGZ1bmN0aW9uIGdldFVzZXJJbmZvKCkgewogICAgICAgIHRyeSB7CiAgICAgICAgICAgIGNvbnN0IG0gPSBkb2N1bWVudC5jb29raWUubWF0Y2goLyg/Ol58OyApdXNlcj0oW147XSopLyk7CiAgICAgICAgICAgIGlmIChtICYmIG1bMV0pIHsKICAgICAgICAgICAgICAgIGNvbnN0IHBhcnNlZCA9IEpTT04ucGFyc2UoZGVjb2RlVVJJQ29tcG9uZW50KG1bMV0pKTsKICAgICAgICAgICAgICAgIGlmIChwYXJzZWQgJiYgKHBhcnNlZC5faWQgfHwgcGFyc2VkLmlkKSkgcmV0dXJuIHBhcnNlZDsKICAgICAgICAgICAgfQogICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgdHJ5IHsgcmV0dXJuIHdpbmRvdy51c2VyX2luZm8gfHwgd2luZG93LnBfY29uZmlnPy51c2VyX2luZm8gfHwgdW5zYWZlV2luZG93Py51c2VyX2luZm8gfHwgbnVsbDsgfSBjYXRjaCAoXykgeyByZXR1cm4gbnVsbDsgfQogICAgfQoKICAgIGZ1bmN0aW9uIGdldE9sbVVzZXJuYW1lKCkgewogICAgICAgIHRyeSB7CiAgICAgICAgICAgIC8vIFt2NC4xXSDGr3UgdGnDqm4gRE9NIGlucHV0IChnaeG7kW5nIHYzIGNvcmUpCiAgICAgICAgICAgIGNvbnN0IGRvbUlucHV0ID0gZG9jdW1lbnQucXVlcnlTZWxlY3RvcignI2luZm8tYWNjb3VudCBpbnB1dC5mb3JtLWNvbnRyb2xbcmVhZG9ubHldJyk7CiAgICAgICAgICAgIGlmIChkb21JbnB1dCAmJiBkb21JbnB1dC52YWx1ZSkgcmV0dXJuIGRvbUlucHV0LnZhbHVlLnRyaW0oKTsKICAgICAgICAgICAgY29uc3QgdWkgPSBnZXRVc2VySW5mbygpOwogICAgICAgICAgICBpZiAodWkgJiYgdWkudXNlcm5hbWUpIHJldHVybiB1aS51c2VybmFtZTsKICAgICAgICAgICAgaWYgKHVpICYmIHVpLm5hbWUpIHJldHVybiB1aS5uYW1lOwogICAgICAgICAgICBjb25zdCBlbCA9IGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoJy51c2VybmFtZSwgLnVzZXItbmFtZSwgW2NsYXNzKj0idXNlcm5hbWUiXScpOwogICAgICAgICAgICByZXR1cm4gZWwgPyBlbC50ZXh0Q29udGVudC50cmltKCkgOiAnS2hvbmdYYWNEaW5oJzsKICAgICAgICB9IGNhdGNoIChfKSB7IHJldHVybiAnS2hvbmdYYWNEaW5oJzsgfQogICAgfQoKICAgIGZ1bmN0aW9uIGdldEhXSUQoKSB7CiAgICAgICAgbGV0IGggPSBsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgnX3RsX2h3aWQnKTsKICAgICAgICBpZiAoIWgpIHsKICAgICAgICAgICAgY29uc3QgdWEgPSBuYXZpZ2F0b3IudXNlckFnZW50ICsgbmF2aWdhdG9yLmxhbmd1YWdlICsgc2NyZWVuLndpZHRoICsgc2NyZWVuLmhlaWdodDsKICAgICAgICAgICAgbGV0IGhhc2ggPSA1MzgxOwogICAgICAgICAgICBmb3IgKGxldCBpID0gMDsgaSA8IHVhLmxlbmd0aDsgaSsrKSBoYXNoID0gKChoYXNoIDw8IDUpICsgaGFzaCkgXiB1YS5jaGFyQ29kZUF0KGkpOwogICAgICAgICAgICBoID0gJ0hXJyArIE1hdGguYWJzKGhhc2gpLnRvU3RyaW5nKDE2KS50b1VwcGVyQ2FzZSgpLnBhZFN0YXJ0KDgsJzAnKTsKICAgICAgICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oJ190bF9od2lkJywgaCk7CiAgICAgICAgfQogICAgICAgIHJldHVybiBoOwogICAgfQogICAgZnVuY3Rpb24gcmlwSWRGcm9tVXJsKCkgewogICAgICAgIGNvbnN0IG0gPSB3aW5kb3cubG9jYXRpb24ucGF0aG5hbWUubWF0Y2goLy0oXGQrKSg/Olw/fFwvfCQpLyk7CiAgICAgICAgcmV0dXJuIG0gPyBtWzFdIDogbnVsbDsKICAgIH0KICAgIGZ1bmN0aW9uIGRldGVjdFVzZXJJRCgpIHsKICAgICAgICBjb25zdCB1aSA9IGdldFVzZXJJbmZvKCk7CiAgICAgICAgcmV0dXJuIFNFU1NJT04ubWV0YS5pZF91c2VyIHx8ICh1aSA/ICh1aS5faWQgfHwgdWkuaWQpIDogbnVsbCkgfHwgd2luZG93Py5wX2NvbmZpZz8uaWRfdXNlciB8fCBudWxsOwogICAgfQogICAgZnVuY3Rpb24gZGV0ZWN0U2Nob29sSUQoZGF0YSkgewogICAgICAgIHJldHVybiBkYXRhPy5pZF9zY2hvb2wgfHwgd2luZG93Py5wX2NvbmZpZz8uc2Nob29sX2lkIHx8IGdldFVzZXJJbmZvKCk/LmlkX3NjaG9vbCB8fCBudWxsOwogICAgfQogICAgZnVuY3Rpb24gZGV0ZWN0R3JvdXBJRCgpIHsKICAgICAgICBjb25zdCBtID0gd2luZG93LmxvY2F0aW9uLmhyZWYubWF0Y2goL1wvbG9wXC9bXi9dK1wuKFxkKykvKTsKICAgICAgICByZXR1cm4gKG0gJiYgbVsxXSkgPyBtWzFdIDogbnVsbDsKICAgIH0KICAgIGZ1bmN0aW9uIGZvcmNlR2V0TWV0YSgpIHsKICAgICAgICBjb25zdCB1aSA9IGdldFVzZXJJbmZvKCk7CiAgICAgICAgaWYgKCFTRVNTSU9OLm1ldGEuaWRfdXNlcikKICAgICAgICAgICAgU0VTU0lPTi5tZXRhLmlkX3VzZXIgPSAodWkgJiYgKHVpLl9pZCB8fCB1aS5pZCkpIHx8IHdpbmRvdz8ucF9jb25maWc/LmlkX3VzZXIgfHwgZGV0ZWN0VXNlcklEKCk7CiAgICAgICAgaWYgKCFTRVNTSU9OLm1ldGEuaWRfY2F0ZSkKICAgICAgICAgICAgU0VTU0lPTi5tZXRhLmlkX2NhdGUgPSB3aW5kb3c/LnBfY29uZmlnPy5pZF9jYXRlIHx8IHdpbmRvdz8ucF9jb25maWc/LmlkX2V4YW0gfHwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBuZXcgVVJMU2VhcmNoUGFyYW1zKHdpbmRvdy5sb2NhdGlvbi5zZWFyY2gpLmdldCgnaWRfY2F0ZScpIHx8CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbmV3IFVSTFNlYXJjaFBhcmFtcyh3aW5kb3cubG9jYXRpb24uc2VhcmNoKS5nZXQoJ2lkX2V4YW0nKSB8fAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJpcElkRnJvbVVybCgpOwogICAgICAgIGlmICghU0VTU0lPTi5tZXRhLmlkX2NvdXJzZXdhcmUpCiAgICAgICAgICAgIFNFU1NJT04ubWV0YS5pZF9jb3Vyc2V3YXJlID0gbmV3IFVSTFNlYXJjaFBhcmFtcyh3aW5kb3cubG9jYXRpb24uc2VhcmNoKS5nZXQoJ2lfYycpIHx8CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbmV3IFVSTFNlYXJjaFBhcmFtcyh3aW5kb3cubG9jYXRpb24uc2VhcmNoKS5nZXQoJ2lkX2NvdXJzZXdhcmUnKSB8fAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFNFU1NJT04ubWV0YS5pZF9jYXRlOwogICAgICAgIGlmICghU0VTU0lPTi5tZXRhLmlkX3NjaG9vbCkKICAgICAgICAgICAgU0VTU0lPTi5tZXRhLmlkX3NjaG9vbCA9ICh1aSAmJiB1aS5pZF9zY2hvb2wpIHx8IHdpbmRvdz8ucF9jb25maWc/LnNjaG9vbF9pZCB8fCBudWxsOwogICAgICAgIGlmICghU0VTU0lPTi5tZXRhLmNzcmZfdG9rZW4pIHsKICAgICAgICAgICAgY29uc3QgbSA9IGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoJ21ldGFbbmFtZT0iY3NyZi10b2tlbiJdJyk7CiAgICAgICAgICAgIFNFU1NJT04ubWV0YS5jc3JmX3Rva2VuID0gbSA/IG0uZ2V0QXR0cmlidXRlKCdjb250ZW50JykgOiAod2luZG93LmNzcmZfdG9rZW4gfHwgJycpOwogICAgICAgIH0KICAgIH0KCiAgICAvLyDilIDilIDilIAgTG9nIGJveCBoZWxwZXIg4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSACiAgICBmdW5jdGlvbiBhZGRMb2cobXNnLCB0eXBlID0gJycpIHsKICAgICAgICBjb25zdCBib3ggPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtbG9nYm94Jyk7CiAgICAgICAgaWYgKCFib3gpIHJldHVybjsKICAgICAgICBjb25zdCBkID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICAgICAgZC5jbGFzc05hbWUgPSAndGwtbG9nICcgKyB0eXBlOwogICAgICAgIGNvbnN0IHRpbWUgPSBuZXcgRGF0ZSgpLnRvTG9jYWxlVGltZVN0cmluZygndmktVk4nLCB7aG91cjonMi1kaWdpdCcsbWludXRlOicyLWRpZ2l0JyxzZWNvbmQ6JzItZGlnaXQnfSk7CiAgICAgICAgZC5pbm5lckhUTUwgPSBgWyR7dGltZX1dICR7bXNnfWA7CiAgICAgICAgYm94LmFwcGVuZENoaWxkKGQpOwogICAgICAgIGJveC5zY3JvbGxUb3AgPSBib3guc2Nyb2xsSGVpZ2h0OwogICAgfQogICAgd2luZG93LmFkZExvZyA9IGFkZExvZzsKCiAgICAvLyDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZAKICAgIC8vICBMT0NLIFNDUkVFTiDigJQgVUkgdjMuMiArIGxvZ2ljIGLhuqNvIG3huq10IHY0ICsgT0xNIGNoZWNrIHY0LjEKICAgIC8vIOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkAogICAgZnVuY3Rpb24gYnVpbGRMb2NrU2NyZWVuKHJlYXNvbikgewogICAgICAgIGlmIChkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtY29ubi1vdmVybGF5JykpIHJldHVybjsKCiAgICAgICAgbGV0IGxvY2tTdHlsZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1sb2NrLXN0eWxlJyk7CiAgICAgICAgaWYgKCFsb2NrU3R5bGUpIHsKICAgICAgICAgICAgbG9ja1N0eWxlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc3R5bGUnKTsKICAgICAgICAgICAgbG9ja1N0eWxlLmlkID0gJ3RsLWxvY2stc3R5bGUnOwogICAgICAgICAgICBkb2N1bWVudC5oZWFkLmFwcGVuZENoaWxkKGxvY2tTdHlsZSk7CiAgICAgICAgfQogICAgICAgIGxvY2tTdHlsZS50ZXh0Q29udGVudCA9IGdldExvY2tTY3JlZW5TdHlsZXMoKTsKCiAgICAgICAgY29uc3Qgb3ZlcmxheSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpOwogICAgICAgIG92ZXJsYXkuaWQgPSAndGwtY29ubi1vdmVybGF5JzsKICAgICAgICBjb25zdCB0bEZ4ID0gZ2V0VGhlbWVDb2xvcnMoQ1VSUkVOVF9USEVNRSkucGFuZWxFeHRyYSB8fCAnJzsKICAgICAgICBvdmVybGF5LmlubmVySFRNTCA9IGAKICAgICAgICAgICAgPGRpdiBpZD0idGwtY29ubi1wYW5lbCI+CiAgICAgICAgICAgICAgICAke3RsRnh9CiAgICAgICAgICAgICAgICA8ZGl2IGlkPSJ0bC1jb25uLWhlYWRlciI+CiAgICAgICAgICAgICAgICAgICAgPHNwYW4gY2xhc3M9InRsLWJyYW5kLW5hbWUiPvCfmoAgVEhJw4pOIFRBSSBUw5kgVOG7mEkgLy8gR09EIE1PREUgdjMuMjwvc3Bhbj4KICAgICAgICAgICAgICAgIDwvZGl2PgogICAgICAgICAgICAgICAgPGRpdiBpZD0idGwtY29ubi1ib2R5Ij4KICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC1zdWJ0aXRsZSI+8J+UkCBOSOG6rFAgTElDRU5TRSBLRVkgxJDhu4IgS8ONQ0ggSE/huqBUPC9kaXY+CiAgICAgICAgICAgICAgICAgICAgJHtyZWFzb24gPyBgPGRpdiBjbGFzcz0idGwtd2FybmluZyI+4pqg77iPICR7cmVhc29ufTwvZGl2PmAgOiAnJ30KICAgICAgICAgICAgICAgICAgICA8aW5wdXQgdHlwZT0idGV4dCIgY2xhc3M9InRsLWlucHV0IiBpZD0idGwta2V5LWlucHV0IgogICAgICAgICAgICAgICAgICAgICAgICAgICBwbGFjZWhvbGRlcj0iTmjhuq1wIGtleSBi4bqjbiBxdXnhu4FuLi4uIiBhdXRvY29tcGxldGU9Im9mZiI+CiAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0idGwtYnRuIHRsLWJ0bi11bmxvY2siIGlkPSJ0bC1idG4tdW5sb2NrIj7wn5STIEvDjUNIIEhP4bqgVDwvYnV0dG9uPgogICAgICAgICAgICAgICAgICAgIDxidXR0b24gY2xhc3M9InRsLWJ0biB0bC1idG4tdmlwIiAgIGlkPSJ0bC1idG4tYnV5Ij7wn5KOIE1VQSBLRVkgKExJw4pOIEjhu4YpPC9idXR0b24+CiAgICAgICAgICAgICAgICAgICAgPGRpdiBpZD0idGwtZXJyIj48L2Rpdj4KICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC1od2lkIiBpZD0idGwtaHdpZC1kaXNwbGF5Ij48L2Rpdj4KICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC1mb290Ij5Zw6p1IGPhuqd1OiBtw6F5IEFuZHJvaWQvaU9TIHRo4bqtdCDigKIgdHLDrG5oIGR1eeG7h3QgdGjhuq10IOKAoiBt4bqhbmcgdGjhuq10PC9kaXY+CiAgICAgICAgICAgICAgICA8L2Rpdj4KICAgICAgICAgICAgPC9kaXY+YDsKICAgICAgICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKG92ZXJsYXkpOwoKICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtaHdpZC1kaXNwbGF5JykudGV4dENvbnRlbnQgPSBg8J+UkSBIV0lEOiAke2dldEhXSUQoKX1gOwogICAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1idG4tYnV5Jykub25jbGljayA9ICgpID0+IHdpbmRvdy5vcGVuKCdodHRwczovL3QubWUvbHVvbmd0dXllbjIwJywgJ19ibGFuaycpOwoKICAgICAgICBjb25zdCBidG4gICAgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtYnRuLXVubG9jaycpOwogICAgICAgIGNvbnN0IGVyckJveCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1lcnInKTsKICAgICAgICBsZXQgdmVyaWZ5aW5nID0gZmFsc2U7CgogICAgICAgIGJ0bi5vbmNsaWNrID0gYXN5bmMgKCkgPT4gewogICAgICAgICAgICBpZiAodmVyaWZ5aW5nKSByZXR1cm47CiAgICAgICAgICAgIGNvbnN0IGtleSA9IChkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwta2V5LWlucHV0JykudmFsdWUgfHwgJycpLnRyaW0oKS50b1VwcGVyQ2FzZSgpOwogICAgICAgICAgICBpZiAoIWtleSkgeyBlcnJCb3gudGV4dENvbnRlbnQgPSAn4p2MIFZ1aSBsw7JuZyBuaOG6rXAga2V5ISc7IGVyckJveC5zdHlsZS5kaXNwbGF5ID0gJ2Jsb2NrJzsgcmV0dXJuOyB9CgogICAgICAgICAgICB2ZXJpZnlpbmcgPSB0cnVlOwogICAgICAgICAgICBidG4udGV4dENvbnRlbnQgPSAn4o+zIMSQQU5HIFjDgUMgVEjhu7BDLi4uJzsKICAgICAgICAgICAgYnRuLmRpc2FibGVkICAgID0gdHJ1ZTsKICAgICAgICAgICAgZXJyQm94LnN0eWxlLmRpc3BsYXkgPSAnbm9uZSc7CgogICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgLy8gW3Y0XSBQaW5nIHNlcnZlciBxdWEgQVBJIHByZWZpeCDhuqluIHRyxrDhu5tjIGtoaSB2ZXJpZnkKICAgICAgICAgICAgICAgIGNvbnN0IHByZWZpeCA9IGF3YWl0IF9hcGlQcmVmaXgoKTsKICAgICAgICAgICAgICAgIGNvbnN0IHBpbmdPayA9IGF3YWl0IG5ldyBQcm9taXNlKChyZXNvbHZlKSA9PiB7CiAgICAgICAgICAgICAgICAgICAgR01feG1saHR0cFJlcXVlc3QoewogICAgICAgICAgICAgICAgICAgICAgICBtZXRob2Q6ICdHRVQnLCB1cmw6IFNFUlZFUl9CQVNFICsgcHJlZml4ICsgJy9waW5nJywgdGltZW91dDogODAwMCwKICAgICAgICAgICAgICAgICAgICAgICAgb25sb2FkOiAocikgPT4gcmVzb2x2ZShyLnN0YXR1cyA9PT0gMjAwKSwKICAgICAgICAgICAgICAgICAgICAgICAgb25lcnJvcjogKCkgPT4gcmVzb2x2ZShmYWxzZSksIG9udGltZW91dDogKCkgPT4gcmVzb2x2ZShmYWxzZSkKICAgICAgICAgICAgICAgICAgICB9KTsKICAgICAgICAgICAgICAgIH0pOwogICAgICAgICAgICAgICAgaWYgKCFwaW5nT2spIHRocm93IG5ldyBFcnJvcignS0jDlE5HIEvhur5UIE7hu5BJIMSQxq/hu6JDIFNFUlZFUi4gS2nhu4NtIHRyYTogMSkgVVJMIFNFUlZFUl9CQVNFLCAyKSBBUElfU0VDUkVUIGto4bubcCBHT0RNT0RFX1NFQ1JFVCB0csOqbiBzZXJ2ZXIsIDMpIMSRw6MgZGVwbG95L3JlZGVwbG95LicpOwoKICAgICAgICAgICAgICAgIC8vIFt2NC4xXSBM4bqleSBPTE0gdXNlcm5hbWUgaGnhu4duIHThuqFpIMSR4buDIGfhu61pIGvDqG0KICAgICAgICAgICAgICAgIGNvbnN0IGN1cnJlbnRPbG0gPSBnZXRPbG1Vc2VybmFtZSgpOwogICAgICAgICAgICAgICAgY29uc3QgcmVzdWx0ID0gYXdhaXQgZ21Qb3N0KCcvdmVyaWZ5JywgeyBrZXksIGh3aWQ6IGdldEhXSUQoKSwgb2xtX3VzZXI6IGN1cnJlbnRPbG0gfSk7CgogICAgICAgICAgICAgICAgaWYgKHJlc3VsdC5zdWNjZXNzIHx8IHJlc3VsdC52YWxpZCkgewoKICAgICAgICAgICAgICAgICAgICAvLyDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZAKICAgICAgICAgICAgICAgICAgICAvLyBbdjQuMV0gS0nhu4JNIFRSQSBPTE0gQUNDT1VOVCBNSVNNQVRDSAogICAgICAgICAgICAgICAgICAgIC8vIFNlcnZlciB0cuG6oyB24buBIG9sbV91c2VyID0gdMOgaSBraG/huqNuIE9MTSDEkcaw4bujYyBnaGltIHbDoG8ga2V5CiAgICAgICAgICAgICAgICAgICAgLy8gU28gc8OhbmggduG7m2kgdMOgaSBraG/huqNuIE9MTSDEkWFuZyDEkcSDbmcgbmjhuq1wIHRyw6puIHRyw6xuaCBkdXnhu4d0CiAgICAgICAgICAgICAgICAgICAgLy8g4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQCiAgICAgICAgICAgICAgICAgICAgY29uc3Qgc2VydmVyT2xtID0gcmVzdWx0Lm9sbV91c2VyIHx8IHJlc3VsdC5vbG1fYWNjb3VudCB8fCAnJzsKICAgICAgICAgICAgICAgICAgICBpZiAoc2VydmVyT2xtICYmIGN1cnJlbnRPbG0gJiYgY3VycmVudE9sbSAhPT0gJ0tob25nWGFjRGluaCcpIHsKICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHNlcnZlck9sbS50b0xvd2VyQ2FzZSgpICE9PSBjdXJyZW50T2xtLnRvTG93ZXJDYXNlKCkpIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8vIE9MTSBhY2NvdW50IG1pc21hdGNoIOKAlCBoaeG7g24gdGjhu4sgbOG7l2ksIGtow7RuZyB0aeG6v3AgdOG7pWMKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVyckJveC5pbm5lckhUTUwgPSBg8J+aqyA8Yj5Uw6BpIGtob+G6o24gT0xNIGtow7RuZyBraOG7m3AhPC9iPjxicj4KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBLZXkgZMOgbmggY2hvOiA8Yj4ke3NlcnZlck9sbX08L2I+PGJyPgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEhp4buHbiB04bqhaTogPGI+JHtjdXJyZW50T2xtfTwvYj48YnI+CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgVnVpIGzDsm5nIMSRxINuZyBuaOG6rXAgxJHDum5nIHTDoGkga2hv4bqjbiBPTE0hYDsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVyckJveC5zdHlsZS5kaXNwbGF5ID0gJ2Jsb2NrJzsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJ0bi50ZXh0Q29udGVudCA9ICfwn5STIEvDjUNIIEhP4bqgVCc7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBidG4uZGlzYWJsZWQgICAgPSBmYWxzZTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZlcmlmeWluZyAgICAgICA9IGZhbHNlOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuOwogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIC8vIOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkAoKICAgICAgICAgICAgICAgICAgICBfc0xTLnNldChMU19LRVksICBrZXkpOyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAvLyBbdjVdIG9iZnVzY2F0ZWQgd3JpdGUKICAgICAgICAgICAgICAgICAgICBfc0xTLnNldChMU19UWVBFLCByZXN1bHQudHlwZSAgIHx8IHJlc3VsdC5wbGFuIHx8ICdUSFVPTkcnKTsgIC8vIFt2NV0KICAgICAgICAgICAgICAgICAgICBfc0xTLnNldChMU19FWFAsICByZXN1bHQuZXhwaXJlc19hdCB8fCAnJyk7ICAgICAgICAgICAgICAgICAgIC8vIFt2NV0KICAgICAgICAgICAgICAgICAgICBDVVJSRU5UX0tFWSA9IGtleTsKICAgICAgICAgICAgICAgICAgICBLRVlfU1RBVFVTICA9IHsgdmFsaWQ6IHRydWUsIHR5cGU6IHJlc3VsdC50eXBlIHx8IHJlc3VsdC5wbGFuLCBleHBpcmVzX2F0OiByZXN1bHQuZXhwaXJlc19hdCB8fCByZXN1bHQuZXhwIH07CgogICAgICAgICAgICAgICAgICAgIGNvbnN0IGtleVR5cGVMYWJlbCA9IChyZXN1bHQudHlwZSB8fCByZXN1bHQucGxhbiB8fCAnVEhVT05HJykudG9VcHBlckNhc2UoKTsKICAgICAgICAgICAgICAgICAgICBjb25zdCBpc1ByZW1pdW0gICAgPSBbJ1BSRU1JVU0nLCdWSVAnLCdVTkxJTUlURUQnXS5pbmNsdWRlcyhrZXlUeXBlTGFiZWwpOwoKICAgICAgICAgICAgICAgICAgICBsZXQgZXhwaXJ5TGluZSA9ICcnOwogICAgICAgICAgICAgICAgICAgIGNvbnN0IGV4UmF3ID0gcmVzdWx0LmV4cGlyZXNfYXQgfHwgcmVzdWx0LmV4cCB8fCAnJzsKICAgICAgICAgICAgICAgICAgICBpZiAoZXhSYXcpIHsKICAgICAgICAgICAgICAgICAgICAgICAgY29uc3QgZXhwRGF0ZSAgPSBuZXcgRGF0ZShleFJhdyk7CiAgICAgICAgICAgICAgICAgICAgICAgIGNvbnN0IGRheXNMZWZ0ID0gTWF0aC5jZWlsKChleHBEYXRlIC0gbmV3IERhdGUoKSkgLyAoMTAwMCAqIDYwICogNjAgKiAyNCkpOwogICAgICAgICAgICAgICAgICAgICAgICBjb25zdCBleHBTdHIgICA9IGV4cERhdGUudG9Mb2NhbGVEYXRlU3RyaW5nKCd2aS1WTicpOwogICAgICAgICAgICAgICAgICAgICAgICBpZiAoZGF5c0xlZnQgPiAwKSAgICAgICBleHBpcnlMaW5lID0gYPCfk4UgSOG6v3QgaOG6oW46IDxiPiR7ZXhwU3RyfTwvYj4gKGPDsm4gPGI+JHtkYXlzTGVmdH08L2I+IG5nw6B5KWA7CiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UgaWYgKGRheXNMZWZ0ID09PSAwKSBleHBpcnlMaW5lID0gYPCfk4UgSOG6v3QgaOG6oW46IDxiPkjDtG0gbmF5PC9iPiAoJHtleHBTdHJ9KWA7CiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UgICAgICAgICAgICAgICAgICAgIGV4cGlyeUxpbmUgPSBg8J+ThSBI4bq/dCBo4bqhbjogPGI+JHtleHBTdHJ9PC9iPiA8c3BhbiBzdHlsZT0iY29sb3I6I2ZmNDQ0NDsiPijEkcOjIGjhur90IGjhuqFuKTwvc3Bhbj5gOwogICAgICAgICAgICAgICAgICAgIH0KCiAgICAgICAgICAgICAgICAgICAgb3ZlcmxheS5yZW1vdmUoKTsKCiAgICAgICAgICAgICAgICAgICAgaWYgKCFpc1ByZW1pdW0pIHsKICAgICAgICAgICAgICAgICAgICAgICAgc2hvd0N1c3RvbU1vZGFsKHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGljb246ICAn4pyFJywKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRpdGxlOiAnS8ONQ0ggSE/huqBUIFRIw4BOSCBDw5RORyEnLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgbGluZXM6IFsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBgTG/huqFpIGtleTogPGI+JHtrZXlUeXBlTGFiZWx9PC9iPmAsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLi4uKGV4cGlyeUxpbmUgPyBbZXhwaXJ5TGluZV0gOiBbXSksCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYDxzcGFuIHN0eWxlPSJjb2xvcjojZmZjMTA3OyI+4pqg77iPIEtleSB0aMaw4budbmc6IENo4bupYyBuxINuZyAiQ0hV4bqoTiBC4buKIDEwIMSQSeG7gk0iIGLhu4sgdsO0IGhp4buHdSBob8OhLjwvc3Bhbj5gLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGDwn5KOIE7Dom5nIGPhuqVwIGzDqm4gUFJFTUlVTSDEkeG7gyBkw7luZyDEkeG6p3kgxJHhu6cgdMOtbmggbsSDbmchYAogICAgICAgICAgICAgICAgICAgICAgICAgICAgXSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9uT2s6ICgpID0+IGNyZWF0ZVVJKCkKICAgICAgICAgICAgICAgICAgICAgICAgfSk7CiAgICAgICAgICAgICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgICAgICAgICAgICAgc2hvd0N1c3RvbU1vZGFsKHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGljb246ICAn8J+SjicsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aXRsZTogJ0vDjUNIIEhP4bqgVCBUSMOATkggQ8OUTkchJywKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGxpbmVzOiBbCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYExv4bqhaSBrZXk6IDxiPiR7a2V5VHlwZUxhYmVsfTwvYj4g8J+SjmAsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLi4uKGV4cGlyeUxpbmUgPyBbZXhwaXJ5TGluZV0gOiBbXSksCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYPCflJMgVOG6pXQgY+G6oyB0w61uaCBuxINuZyDEkcOjIMSRxrDhu6NjIG3hu58ga2hvw6EhYAogICAgICAgICAgICAgICAgICAgICAgICAgICAgXSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9uT2s6ICgpID0+IGNyZWF0ZVVJKCkKICAgICAgICAgICAgICAgICAgICAgICAgfSk7CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgICAgICAgICAvLyBbdjRdIFRow7RuZyBiw6FvIGzhu5dpIGNoaSB0aeG6v3QgdGhlbyBIVFRQIHN0YXR1cwogICAgICAgICAgICAgICAgICAgIGNvbnN0IHN0YXR1cyA9IHJlc3VsdC5faHR0cFN0YXR1czsKICAgICAgICAgICAgICAgICAgICBsZXQgbXNnID0gcmVzdWx0Lm1lc3NhZ2UgfHwgcmVzdWx0LnJlYXNvbiB8fCByZXN1bHQuZXJyb3IgfHwgJyc7CiAgICAgICAgICAgICAgICAgICAgaWYgKHN0YXR1cyA9PT0gNDA0IHx8IHJlc3VsdC5lcnJvciA9PT0gJ05vdCBmb3VuZCcpIHsKICAgICAgICAgICAgICAgICAgICAgICAgbXNnID0gJ+KdjCBUaGnhur90IGLhu4svSVAgY8OzIHRo4buDIMSRw6MgYuG7iyBraG/DoSBob+G6t2Mgc2FpIMSRxrDhu51uZyBk4bqrbiBBUEkuIEtp4buDbSB0cmEgQVBJX1NFQ1JFVCBraOG7m3Agc2VydmVyLic7CiAgICAgICAgICAgICAgICAgICAgfSBlbHNlIGlmIChzdGF0dXMgPT09IDQwMykgewogICAgICAgICAgICAgICAgICAgICAgICBtc2cgPSAn4p2MICcgKyAobXNnIHx8ICdUaGnhur90IGLhu4svbeG6oW5nIGtow7RuZyBo4bujcCBs4buHIChtw6F5IOG6o28vcHJveHkvVlBOL3Ryw6xuaCBkdXnhu4d0IGdp4bqjKSDigJQgY8OzIHRo4buDIMSRw6MgYuG7iyBraG/DoSB2xKluaCB2aeG7hW4sIGxpw6puIGjhu4cgYWRtaW4uJyk7CiAgICAgICAgICAgICAgICAgICAgfSBlbHNlIGlmICghbXNnKSB7CiAgICAgICAgICAgICAgICAgICAgICAgIG1zZyA9ICfinYwgS2V5IGtow7RuZyBo4bujcCBs4buHISAoS2V5VmF1bHQgdOG7qyBjaOG7kWkpJzsKICAgICAgICAgICAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICAgICAgICAgICAgICBtc2cgPSAn4p2MICcgKyBtc2c7CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIGVyckJveC50ZXh0Q29udGVudCAgID0gbXNnICsgKHN0YXR1cyA/IGAgW0hUVFAgJHtzdGF0dXN9XWAgOiAnJyk7CiAgICAgICAgICAgICAgICAgICAgZXJyQm94LnN0eWxlLmRpc3BsYXkgPSAnYmxvY2snOwogICAgICAgICAgICAgICAgICAgIGJ0bi50ZXh0Q29udGVudCA9ICfwn5STIEvDjUNIIEhP4bqgVCc7CiAgICAgICAgICAgICAgICAgICAgYnRuLmRpc2FibGVkICAgID0gZmFsc2U7CiAgICAgICAgICAgICAgICAgICAgdmVyaWZ5aW5nICAgICAgID0gZmFsc2U7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0gY2F0Y2ggKGUpIHsKICAgICAgICAgICAgICAgIGVyckJveC50ZXh0Q29udGVudCAgID0gJ+KdjCBLaMO0bmcgdGjhu4Mga+G6v3QgbuG7kWkgc2VydmVyOiAnICsgZS5tZXNzYWdlOwogICAgICAgICAgICAgICAgZXJyQm94LnN0eWxlLmRpc3BsYXkgPSAnYmxvY2snOwogICAgICAgICAgICAgICAgYnRuLnRleHRDb250ZW50ID0gJ/CflJMgS8ONQ0ggSE/huqBUJzsKICAgICAgICAgICAgICAgIGJ0bi5kaXNhYmxlZCAgICA9IGZhbHNlOwogICAgICAgICAgICAgICAgdmVyaWZ5aW5nICAgICAgID0gZmFsc2U7CiAgICAgICAgICAgIH0KICAgICAgICB9OwoKICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwta2V5LWlucHV0JykuYWRkRXZlbnRMaXN0ZW5lcigna2V5ZG93bicsIChlKSA9PiB7CiAgICAgICAgICAgIGlmIChlLmtleSA9PT0gJ0VudGVyJykgYnRuLmNsaWNrKCk7CiAgICAgICAgfSk7CiAgICB9CgogICAgLy8g4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQCiAgICAvLyAgTUFJTiBQQU5FTCDigJQgVUkgdjMuMiArIHTDrW5oIG7Eg25nIHY0ICsga2hvw6Ega2V5IHRoxrDhu51uZyB2NC4xCiAgICAvLyDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZAKICAgIGZ1bmN0aW9uIGNyZWF0ZVVJKCkgewogICAgICAgIGlmIChkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtcGFuZWwnKSkgcmV0dXJuOwoKICAgICAgICBsZXQgdWlTdHlsZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC11aS1zdHlsZScpOwogICAgICAgIGlmICghdWlTdHlsZSkgewogICAgICAgICAgICB1aVN0eWxlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc3R5bGUnKTsKICAgICAgICAgICAgdWlTdHlsZS5pZCA9ICd0bC11aS1zdHlsZSc7CiAgICAgICAgICAgIGRvY3VtZW50LmhlYWQuYXBwZW5kQ2hpbGQodWlTdHlsZSk7CiAgICAgICAgfQogICAgICAgIHVpU3R5bGUudGV4dENvbnRlbnQgPSBnZXRNYWluVUlTdHlsZXMoKTsKCiAgICAgICAgY29uc3Qga2V5VHlwZSAgICA9IEtFWV9TVEFUVVMudHlwZSB8fCBfc0xTLmdldChMU19UWVBFKSB8fCAnVEhVT05HJzsgLy8gW3Y1XQogICAgICAgIGNvbnN0IGtleVR5cGVVcCAgPSBrZXlUeXBlLnRvVXBwZXJDYXNlKCk7CiAgICAgICAgY29uc3QgYmFkZ2VDbGFzcyA9IGtleVR5cGVVcCA9PT0gJ1VOTElNSVRFRCcgPyAndGwtYmFkZ2UgdW5saW1pdGVkJwogICAgICAgICAgICAgICAgICAgICAgICAgOiAoa2V5VHlwZVVwID09PSAnUFJFTUlVTScgfHwga2V5VHlwZVVwID09PSAnVklQJykgPyAndGwtYmFkZ2UgdmlwJwogICAgICAgICAgICAgICAgICAgICAgICAgOiAndGwtYmFkZ2UnOwogICAgICAgIGNvbnN0IGJhZGdlSWNvbiAgPSBrZXlUeXBlVXAgPT09ICdVTkxJTUlURUQnID8gJ/CflKUgVU5MSU1JVEVEJwogICAgICAgICAgICAgICAgICAgICAgICAgOiAoa2V5VHlwZVVwID09PSAnUFJFTUlVTScgfHwga2V5VHlwZVVwID09PSAnVklQJykgPyAn8J+SjiBQUkVNSVVNJwogICAgICAgICAgICAgICAgICAgICAgICAgOiAn8J+UkSBUSMav4bucTkcnOwoKICAgICAgICBjb25zdCBleHBTdHIgPSAoKCkgPT4gewogICAgICAgICAgICBjb25zdCBlID0gX3NMUy5nZXQoTFNfRVhQKTsgLy8gW3Y1XQogICAgICAgICAgICBpZiAoIWUpIHJldHVybiAnJzsKICAgICAgICAgICAgY29uc3QgZCA9IG5ldyBEYXRlKGUpOwogICAgICAgICAgICByZXR1cm4gaXNOYU4oZCkgPyAnJyA6IGAgKGV4cDogJHtkLnRvTG9jYWxlRGF0ZVN0cmluZygndmktVk4nKX0pYDsKICAgICAgICB9KSgpOwoKICAgICAgICBjb25zdCB0aGVtZUNhcmRzSFRNTCA9IFsnZGVmYXVsdCcsJ2dyYXknLCdwaW5rJ10ubWFwKHQgPT4gewogICAgICAgICAgICBjb25zdCB0SW5mbyAgICA9IGdldFRoZW1lQ29sb3JzKHQpOwogICAgICAgICAgICBjb25zdCBpc0FjdGl2ZSA9ICh0ID09PSBDVVJSRU5UX1RIRU1FKTsKICAgICAgICAgICAgcmV0dXJuIGA8ZGl2IGNsYXNzPSJ0bC10YyAke2lzQWN0aXZlID8gJ2FjdGl2ZScgOiAnJ30iIGRhdGEtdD0iJHt0fSI+CiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC10Yy1wcmV2IiBzdHlsZT0iYmFja2dyb3VuZDoke3RJbmZvLnByZXZpZXdCZ307Ym9yZGVyOjFweCBzb2xpZCAke3RJbmZvLnByZXZpZXdCb3JkZXJ9OyI+CiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtdGMtcHJldi1pbm5lciI+CiAgICAgICAgICAgICAgICAgICAgICAgIDxzcGFuIGNsYXNzPSJ0bC10Yy1wcmV2LXRleHQiIHN0eWxlPSJjb2xvcjoke3RJbmZvLnByZXZpZXdUZXh0fTsiPiR7dEluZm8udGhlbWVMYWJlbC5yZXBsYWNlKC9eW15cc10rXHMvLCcnKS50b1VwcGVyQ2FzZSgpfTwvc3Bhbj4KICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KICAgICAgICAgICAgICAgIDwvZGl2PgogICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtdGMtbGJsIj4ke3RJbmZvLnRoZW1lTGFiZWx9PC9kaXY+CiAgICAgICAgICAgIDwvZGl2PmA7CiAgICAgICAgfSkuam9pbignJyk7CgogICAgICAgIGNvbnN0IHRjICAgPSBnZXRUaGVtZUNvbG9ycyhDVVJSRU5UX1RIRU1FKTsKICAgICAgICBjb25zdCB3cmFwID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICAgICAgd3JhcC5pbm5lckhUTUwgPSBgCiAgICAgICAgICAgIDxidXR0b24gaWQ9InRsLWZsb2F0QnRuIj7imqE8L2J1dHRvbj4KICAgICAgICAgICAgPGRpdiBpZD0idGwtcGFuZWwiIGNsYXNzPSJoaWRkZW4iPgogICAgICAgICAgICAgICAgJHt0Yy5wYW5lbEV4dHJhIHx8ICcnfQogICAgICAgICAgICAgICAgPGRpdiBpZD0idGwtcC1oZWFkZXIiPgogICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLXAtYnJhbmQiPgogICAgICAgICAgICAgICAgICAgICAgICA8c3Bhbj7wn5qAPC9zcGFuPgogICAgICAgICAgICAgICAgICAgICAgICA8c3BhbiBjbGFzcz0idGwtcC1uYW1lIj5USEnDik4gVEFJIFTDmSBU4buYSSAvLyBHT0QgTU9ERTwvc3Bhbj4KICAgICAgICAgICAgICAgICAgICAgICAgPHNwYW4gY2xhc3M9IiR7YmFkZ2VDbGFzc30iPiR7YmFkZ2VJY29ufTwvc3Bhbj4KICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KICAgICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDo2cHg7Ij4KICAgICAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBpZD0idGwtc2V0dGluZ3NCdG4iIHRpdGxlPSJDw6BpIMSR4bq3dCBnaWFvIGRp4buHbiI+4pqZPC9idXR0b24+CiAgICAgICAgICAgICAgICAgICAgICAgIDxidXR0b24gaWQ9InRsLWNsb3NlQnRuIj7inJU8L2J1dHRvbj4KICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KICAgICAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgICAgICAgIDwhLS0gU2V0dGluZ3Mgb3ZlcmxheSAtLT4KICAgICAgICAgICAgICAgIDxkaXYgaWQ9InRsLXNvIiBjbGFzcz0iaGlkZGVuIj4KICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC1zby1oZHIiPgogICAgICAgICAgICAgICAgICAgICAgICA8c3BhbiBjbGFzcz0idGwtc28tdGl0bGUiPuKamSBDw4BJIMSQ4bq2VCBHSUFPIERJ4buGTjwvc3Bhbj4KICAgICAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBpZD0idGwtc29DbG9zZSI+4pyVPC9idXR0b24+CiAgICAgICAgICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtc28tYm9keSI+CiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLXNvLWxibCI+8J+OqCBDaOG7jW4gbcOgdSBz4bqvYyBnaWFvIGRp4buHbjwvZGl2PgogICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC10aGVtZS1jYXJkcyI+JHt0aGVtZUNhcmRzSFRNTH08L2Rpdj4KICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtc28tZGl2aWRlciI+PC9kaXY+CiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLWhpbnQiPsOBcCBk4bulbmcgbmdheSBs4bqtcCB04bupYyBjaG8gdG/DoG4gYuG7mSBnaWFvIGRp4buHbjxicj5r4buDIGPhuqMgbcOgbiBow6xuaCDEkcSDbmcgbmjhuq1wIHbDoCB0aMO0bmcgYsOhbyBrZXk8L2Rpdj4KICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtc28tZGl2aWRlciI+PC9kaXY+CiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLXNvLWxibCI+8J+UkSBRdeG6o24gbMO9IGtleTwvZGl2PgogICAgICAgICAgICAgICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJ0bC1jaGFuZ2Uta2V5IiBpZD0idGwtY2hhbmdlS2V5Ij7wn5SEIMSQ4buUSSBLRVk8L2J1dHRvbj4KICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtaGludCIgc3R5bGU9Im1hcmdpbi10b3A6NHB4OyI+WG/DoSBrZXkgaGnhu4duIHThuqFpIHbDoCBxdWF5IHbhu4EgbcOgbiBow6xuaCDEkcSDbmcgbmjhuq1wPC9kaXY+CiAgICAgICAgICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgICAgICA8ZGl2IGlkPSJ0bC1wLWJvZHkiPgogICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLXN0YXRib3giPgogICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJjb2xvcjpyZ2JhKDI1NSwyNTUsMjU1LDAuNCk7Zm9udC1zaXplOjEwcHg7dGV4dC10cmFuc2Zvcm06dXBwZXJjYXNlO2ZvbnQtd2VpZ2h0OjYwMDsiPi8vIFRy4bqhbmcgdGjDoWkgaOG7hyB0aOG7kW5nPC9kaXY+CiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLXN0YXRyb3ciPuKchSBO4bqhcCBk4buvIGxp4buHdTogPHNwYW4gaWQ9InRsLXFjb3VudCIgc3R5bGU9ImNvbG9yOiMwMGU2NzY7Zm9udC13ZWlnaHQ6Ym9sZDttYXJnaW4tbGVmdDo1cHgiPjA8L3NwYW4+IGPDonU8L2Rpdj4KICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtc3RhdHJvdyI+8J+UjSBDaOG6vyDEkeG7mTogPHNwYW4gaWQ9InRsLW1vZGUtZGV0ZWN0ZWQiIHN0eWxlPSJjb2xvcjojNGZhY2ZlO2ZvbnQtd2VpZ2h0OmJvbGQ7bWFyZ2luLWxlZnQ6NXB4Ij5QUkFDVElDRTwvc3Bhbj48L2Rpdj4KICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtc3RhdHJvdyI+8J+UkCBLZXk6IDxzcGFuIHN0eWxlPSJjb2xvcjojZmZjMTA3OyI+JHtrZXlUeXBlfTwvc3Bhbj4ke2V4cFN0cn08L2Rpdj4KICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KICAgICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJoZWlnaHQ6MXB4O2JhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDkwZGVnLHRyYW5zcGFyZW50LCR7dGMuYm9yZGVyfSx0cmFuc3BhcmVudCk7Ij48L2Rpdj4KICAgICAgICAgICAgICAgICAgICA8ZGl2PgogICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJmb250LXNpemU6OS41cHg7Zm9udC13ZWlnaHQ6NzAwO2NvbG9yOiR7dGMuZ2xvd0NvbG9yfTtmb250LWZhbWlseTonT3JiaXRyb24nOyI+4pqZIENI4bq+IMSQ4buYIFbGr+G7olQgUsOATzwvZGl2PgogICAgICAgICAgICAgICAgICAgICAgICA8c2VsZWN0IGlkPSJ0bC1tb2RlU2VsZWN0Ij4KICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxvcHRpb24gdmFsdWU9InByYWN0aWNlIj7imqEgTHV54buHbiBU4bqtcDwvb3B0aW9uPgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0iZXhhbSIgc2VsZWN0ZWQ+8J+UpSBLaeG7g20gVHJhPC9vcHRpb24+CiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSJ2aWRlbyI+8J+OpSBWaWRlbyBRdWl6PC9vcHRpb24+CiAgICAgICAgICAgICAgICAgICAgICAgIDwvc2VsZWN0PgogICAgICAgICAgICAgICAgICAgICAgICA8aW5wdXQgdHlwZT0ibnVtYmVyIiBzdGVwPSIwLjAxIiBjbGFzcz0idGwtZ29kLWlucHV0IiBpZD0idGwtZ29kLXRpbWUiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YWx1ZT0iMjUuMDAiIHBsYWNlaG9sZGVyPSJQaMO6dC5HacOieSAodmQ6IDI1LjMwKSI+CiAgICAgICAgICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBpZD0idGwtZmlyZUJ0biI+8J+SpSBDSFXhuqhOIELhu4ogMTAgxJBJ4buCTTwvYnV0dG9uPgogICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLWNvbnNvbGUiIGlkPSJ0bC1sb2dib3giPjwvZGl2PgogICAgICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICAgICAgICA8ZGl2IGlkPSJ0bC1wLWZvb3RlciI+CiAgICAgICAgICAgICAgICAgICAgPHNwYW4+R09EIE1PREUgdjMuMiDigJQgU0VDVVJFIHY1LjA8L3NwYW4+CiAgICAgICAgICAgICAgICAgICAgPGRpdiBzdHlsZT0iZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6NXB4OyI+CiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgc3R5bGU9IndpZHRoOjZweDtoZWlnaHQ6NnB4O2JvcmRlci1yYWRpdXM6NTAlO2JhY2tncm91bmQ6IzAwZTY3Njtib3gtc2hhZG93OjAgMCA2cHggIzAwZTY3NjthbmltYXRpb246Y29ubkJsaW5rIDEuOHMgaW5maW5pdGU7Ij48L2Rpdj4KICAgICAgICAgICAgICAgICAgICAgICAgPHNwYW4gaWQ9InRsLXN2clN0YXR1cyI+8J+UtSBTZXJ2ZXI6IE9LPC9zcGFuPgogICAgICAgICAgICAgICAgICAgIDwvZGl2PgogICAgICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICAgIDwvZGl2PmA7CiAgICAgICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZCh3cmFwKTsKCiAgICAgICAgY29uc3QgZmxvYXRCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtZmxvYXRCdG4nKTsKICAgICAgICBjb25zdCBwYW5lbCAgICA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1wYW5lbCcpOwogICAgICAgIGZsb2F0QnRuLm9uY2xpY2sgPSAoKSA9PiBwYW5lbC5jbGFzc0xpc3QudG9nZ2xlKCdoaWRkZW4nKTsKICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtY2xvc2VCdG4nKS5vbmNsaWNrID0gKCkgPT4gewogICAgICAgICAgICBwYW5lbC5jbGFzc0xpc3QuYWRkKCdoaWRkZW4nKTsKICAgICAgICAgICAgY29uc3Qgc28gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtc28nKTsKICAgICAgICAgICAgaWYgKHNvKSBzby5jbGFzc0xpc3QuYWRkKCdoaWRkZW4nKTsKICAgICAgICB9OwoKICAgICAgICAvLyBEcmFnCiAgICAgICAgY29uc3QgaGRyID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLXAtaGVhZGVyJyk7CiAgICAgICAgbGV0IGlzRHJhZ2dpbmcgPSBmYWxzZSwgc3RhcnRYID0gMCwgc3RhcnRZID0gMCwgaW5pdExlZnQgPSAwLCBpbml0VG9wID0gMDsKICAgICAgICBpZiAoaGRyKSB7CiAgICAgICAgICAgIGhkci5hZGRFdmVudExpc3RlbmVyKCdtb3VzZWRvd24nLCAoZSkgPT4gewogICAgICAgICAgICAgICAgaWYgKGUudGFyZ2V0LmlkID09PSAndGwtY2xvc2VCdG4nIHx8IGUudGFyZ2V0LmlkID09PSAndGwtc2V0dGluZ3NCdG4nKSByZXR1cm47CiAgICAgICAgICAgICAgICBpc0RyYWdnaW5nID0gdHJ1ZTsKICAgICAgICAgICAgICAgIHN0YXJ0WCA9IGUuY2xpZW50WDsgc3RhcnRZID0gZS5jbGllbnRZOwogICAgICAgICAgICAgICAgY29uc3QgciA9IHBhbmVsLmdldEJvdW5kaW5nQ2xpZW50UmVjdCgpOwogICAgICAgICAgICAgICAgaW5pdExlZnQgPSByLmxlZnQ7IGluaXRUb3AgPSByLnRvcDsKICAgICAgICAgICAgfSk7CiAgICAgICAgfQogICAgICAgIGRvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXIoJ21vdXNlbW92ZScsIChlKSA9PiB7CiAgICAgICAgICAgIGlmICghaXNEcmFnZ2luZykgcmV0dXJuOwogICAgICAgICAgICBwYW5lbC5zdHlsZS5sZWZ0ICAgICAgPSAoaW5pdExlZnQgKyBlLmNsaWVudFggLSBzdGFydFgpICsgJ3B4JzsKICAgICAgICAgICAgcGFuZWwuc3R5bGUudG9wICAgICAgID0gKGluaXRUb3AgICsgZS5jbGllbnRZIC0gc3RhcnRZKSArICdweCc7CiAgICAgICAgICAgIHBhbmVsLnN0eWxlLnRyYW5zZm9ybSA9ICdub25lJzsKICAgICAgICB9KTsKICAgICAgICBkb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCdtb3VzZXVwJywgKCkgPT4geyBpc0RyYWdnaW5nID0gZmFsc2U7IH0pOwoKICAgICAgICAvLyA9PT09PT0gU0VUVElOR1MgUEFORUwgTE9HSUMgPT09PT09CiAgICAgICAgY29uc3Qgc28gICAgICAgICAgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtc28nKTsKICAgICAgICBjb25zdCBzZXR0aW5nc0J0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1zZXR0aW5nc0J0bicpOwogICAgICAgIGNvbnN0IHNvQ2xvc2UgICAgID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLXNvQ2xvc2UnKTsKCiAgICAgICAgaWYgKHNldHRpbmdzQnRuICYmIHNvKSB7CiAgICAgICAgICAgIHNldHRpbmdzQnRuLm9uY2xpY2sgPSAoKSA9PiB7CiAgICAgICAgICAgICAgICBjb25zdCBpc09wZW4gPSAhc28uY2xhc3NMaXN0LmNvbnRhaW5zKCdoaWRkZW4nKTsKICAgICAgICAgICAgICAgIHNvLmNsYXNzTGlzdC50b2dnbGUoJ2hpZGRlbicpOwogICAgICAgICAgICAgICAgc2V0dGluZ3NCdG4uY2xhc3NMaXN0LnRvZ2dsZSgnYWN0aXZlJywgIWlzT3Blbik7CiAgICAgICAgICAgIH07CiAgICAgICAgfQogICAgICAgIGlmIChzb0Nsb3NlKSB7CiAgICAgICAgICAgIHNvQ2xvc2Uub25jbGljayA9ICgpID0+IHsKICAgICAgICAgICAgICAgIHNvLmNsYXNzTGlzdC5hZGQoJ2hpZGRlbicpOwogICAgICAgICAgICAgICAgaWYgKHNldHRpbmdzQnRuKSBzZXR0aW5nc0J0bi5jbGFzc0xpc3QucmVtb3ZlKCdhY3RpdmUnKTsKICAgICAgICAgICAgfTsKICAgICAgICB9CgogICAgICAgIGlmIChzbykgewogICAgICAgICAgICBzby5xdWVyeVNlbGVjdG9yQWxsKCcudGwtdGMnKS5mb3JFYWNoKGNhcmQgPT4gewogICAgICAgICAgICAgICAgY2FyZC5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHsKICAgICAgICAgICAgICAgICAgICBjb25zdCBuZXdUaGVtZSA9IGNhcmQuZGF0YXNldC50OwogICAgICAgICAgICAgICAgICAgIGlmIChuZXdUaGVtZSA9PT0gQ1VSUkVOVF9USEVNRSkgewogICAgICAgICAgICAgICAgICAgICAgICBzby5jbGFzc0xpc3QuYWRkKCdoaWRkZW4nKTsKICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHNldHRpbmdzQnRuKSBzZXR0aW5nc0J0bi5jbGFzc0xpc3QucmVtb3ZlKCdhY3RpdmUnKTsKICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICBzby5xdWVyeVNlbGVjdG9yQWxsKCcudGwtdGMnKS5mb3JFYWNoKGMgPT4gewogICAgICAgICAgICAgICAgICAgICAgICBjLmNsYXNzTGlzdC50b2dnbGUoJ2FjdGl2ZScsIGMuZGF0YXNldC50ID09PSBuZXdUaGVtZSk7CiAgICAgICAgICAgICAgICAgICAgfSk7CiAgICAgICAgICAgICAgICAgICAgYXBwbHlUaGVtZUxpdmUobmV3VGhlbWUpOwogICAgICAgICAgICAgICAgICAgIGNvbnN0IGV4aXN0RnggPSBwYW5lbC5xdWVyeVNlbGVjdG9yKCcjdGwtY29ubi1meC1iYXIsI3RsLWNvbm4tZngtcGV0YWxzJyk7CiAgICAgICAgICAgICAgICAgICAgaWYgKGV4aXN0RngpIGV4aXN0RngucmVtb3ZlKCk7CiAgICAgICAgICAgICAgICAgICAgY29uc3QgbmV3VGMgPSBnZXRUaGVtZUNvbG9ycyhuZXdUaGVtZSk7CiAgICAgICAgICAgICAgICAgICAgaWYgKG5ld1RjLnBhbmVsRXh0cmEpIHsKICAgICAgICAgICAgICAgICAgICAgICAgY29uc3QgdG1wID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICAgICAgICAgICAgICAgICAgICAgIHRtcC5pbm5lckhUTUwgPSBuZXdUYy5wYW5lbEV4dHJhOwogICAgICAgICAgICAgICAgICAgICAgICBjb25zdCBmeEVsID0gdG1wLmZpcnN0RWxlbWVudENoaWxkOwogICAgICAgICAgICAgICAgICAgICAgICBpZiAoZnhFbCkgcGFuZWwuaW5zZXJ0QmVmb3JlKGZ4RWwsIHBhbmVsLmZpcnN0Q2hpbGQpOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHsKICAgICAgICAgICAgICAgICAgICAgICAgc28uY2xhc3NMaXN0LmFkZCgnaGlkZGVuJyk7CiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChzZXR0aW5nc0J0bikgc2V0dGluZ3NCdG4uY2xhc3NMaXN0LnJlbW92ZSgnYWN0aXZlJyk7CiAgICAgICAgICAgICAgICAgICAgfSwgMzIwKTsKICAgICAgICAgICAgICAgIH0pOwogICAgICAgICAgICB9KTsKICAgICAgICB9CgogICAgICAgIC8vIE1vZGUgc2VsZWN0CiAgICAgICAgY29uc3QgbW9kZVNlbGVjdCAgID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLW1vZGVTZWxlY3QnKTsKICAgICAgICBjb25zdCBkZXRlY3RlZE1vZGUgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtbW9kZS1kZXRlY3RlZCcpOwogICAgICAgIGlmIChtb2RlU2VsZWN0KSB7CiAgICAgICAgICAgIG1vZGVTZWxlY3QuYWRkRXZlbnRMaXN0ZW5lcignY2hhbmdlJywgZnVuY3Rpb24oKSB7CiAgICAgICAgICAgICAgICBpZiAoZGV0ZWN0ZWRNb2RlKSBkZXRlY3RlZE1vZGUudGV4dENvbnRlbnQgPSB0aGlzLnZhbHVlLnRvVXBwZXJDYXNlKCk7CiAgICAgICAgICAgIH0pOwogICAgICAgIH0KCiAgICAgICAgLy8gW3Y2XSBDb2RlICJDSFXhuqhOIELhu4ogMTAgxJBJ4buCTSIgxJHDoyBjaHV54buDbiBIT8OATiBUT8OATiBzYW5nIHNlcnZlciDigJQgdOG6o2kgxJHhu5luZyBxdWEgL21vZHVsZSAobcOjIGhvw6EgQUVTLUdDTSksIEtIw5RORyBjw7JuIG7hurFtIHRyb25nIHNjcmlwdCBuw6B5LgogICAgICAgIGFzeW5jIGZ1bmN0aW9uIGZvcmNlRmV0Y2hRdWVzdGlvbnMoKSB7CiAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgICBmb3JjZUdldE1ldGEoKTsKICAgICAgICAgICAgICAgIGNvbnN0IFVXID0gKHR5cGVvZiB1bnNhZmVXaW5kb3cgIT09ICd1bmRlZmluZWQnKSA/IHVuc2FmZVdpbmRvdyA6IHdpbmRvdzsKICAgICAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgICAgICAgY29uc3QgYnVmID0gVVcuX19rdl9xX2J1ZjsKICAgICAgICAgICAgICAgICAgICBpZiAoQXJyYXkuaXNBcnJheShidWYpKSB7CiAgICAgICAgICAgICAgICAgICAgICAgIGZvciAobGV0IGkgPSAwOyBpIDwgYnVmLmxlbmd0aDsgaSsrKSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zdCBpdCA9IGJ1ZltpXTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChpdCAmJiBpdC51cmwgJiYgaXQudGV4dCkgeyB0cnkgeyBoYW5kbGVSYXdSZXNwb25zZShpdC51cmwsIGl0LnRleHQpOyB9IGNhdGNoIChfKSB7fSB9CiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICB9IGNhdGNoIChfKSB7fQogICAgICAgICAgICAgICAgaWYgKFNFU1NJT04ucmF3X3F1ZXN0aW9ucy5sZW5ndGggPiAwKSByZXR1cm4gdHJ1ZTsKICAgICAgICAgICAgICAgIGNvbnN0IGxhc3QgPSBVVy5fX3RsX2xhc3RfcXJlcTsKICAgICAgICAgICAgICAgIGlmIChsYXN0ICYmIGxhc3QudXJsKSB7CiAgICAgICAgICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgICAgICAgICAgY29uc3QgZm9wdHMgPSB7IG1ldGhvZDogbGFzdC5tZXRob2QgfHwgJ0dFVCcsIGNyZWRlbnRpYWxzOiAnaW5jbHVkZScsIGNhY2hlOiAnbm8tY2FjaGUnIH07CiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChsYXN0LmJvZHkgJiYgKGxhc3QubWV0aG9kIHx8ICdHRVQnKS50b1VwcGVyQ2FzZSgpICE9PSAnR0VUJykgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9wdHMuaGVhZGVycyA9IHsgJ0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQ7IGNoYXJzZXQ9VVRGLTgnLCAnWC1SZXF1ZXN0ZWQtV2l0aCc6ICdYTUxIdHRwUmVxdWVzdCcgfTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvcHRzLmJvZHkgPSBsYXN0LmJvZHk7CiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2gobGFzdC51cmwsIGZvcHRzKTsKICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHJlcy5vaykgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uc3QgdHh0ID0gYXdhaXQgcmVzLnRleHQoKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRyeSB7IGhhbmRsZVJhd1Jlc3BvbnNlKGxhc3QudXJsLCB0eHQpOyB9IGNhdGNoIChfKSB7fQogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgfSBjYXRjaCAoZSkgeyBjb25zb2xlLndhcm4oJ1tUTF0gcmVwbGF5IGZhaWwnLCBlKTsgfQogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgcmV0dXJuIFNFU1NJT04ucmF3X3F1ZXN0aW9ucy5sZW5ndGggPiAwOwogICAgICAgICAgICB9IGNhdGNoIChlKSB7IHJldHVybiBmYWxzZTsgfQogICAgICAgIH0KCiAgICAgICAgLy8g4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQCiAgICAgICAgLy8gW3Y0LjFdIEZJUkUgQlVUVE9OIOKAlCBLSeG7gk0gVFJBIExP4bqgSSBLRVkgKEdJ4buQTkcgVjMgQ09SRSkKICAgICAgICAvLyBLZXkgdGjGsOG7nW5nOiBLSE/DgSBjaOG7qWMgbsSDbmcgQ0hV4bqoTiBC4buKIDEwIMSQSeG7gk0KICAgICAgICAvLyBLZXkgUHJlbWl1bS9WSVAvVW5saW1pdGVkOiBIb+G6oXQgxJHhu5luZyBiw6xuaCB0aMaw4budbmcKICAgICAgICAvLyDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZAKICAgICAgICBjb25zdCBmaXJlQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLWZpcmVCdG4nKTsKCiAgICAgICAgaWYgKCFpc1ByZW1pdW1LZXkoKSkgewogICAgICAgICAgICAvLyDilIDilIAgS0VZIFRIxq/hu5xORzogVsO0IGhp4buHdSBob8OhIG7DunQgQ0hV4bqoTiBC4buKIDEwIMSQSeG7gk0g4pSA4pSACiAgICAgICAgICAgIGZpcmVCdG4uaW5uZXJIVE1MID0gJ/CflJIgQ0hV4bqoTiBC4buKIDEwIMSQSeG7gk0gKENI4buIIFBSRU1JVU0pJzsKICAgICAgICAgICAgZmlyZUJ0bi5zdHlsZS5iYWNrZ3JvdW5kID0gJ2xpbmVhci1ncmFkaWVudCgxMzVkZWcsIzQ0NCwjNjY2KSc7CiAgICAgICAgICAgIGZpcmVCdG4uc3R5bGUuY3Vyc29yID0gJ25vdC1hbGxvd2VkJzsKICAgICAgICAgICAgZmlyZUJ0bi5zdHlsZS5vcGFjaXR5ID0gJzAuNic7CiAgICAgICAgICAgIGZpcmVCdG4udGl0bGUgPSAnQ2jhu6ljIG7Eg25nIG7DoHkgY2jhu4kgZMOgbmggY2hvIGtleSBQUkVNSVVNLiBMacOqbiBo4buHIMSR4buDIG7Dom5nIGPhuqVwISc7CiAgICAgICAgICAgIGZpcmVCdG4ub25jbGljayA9IChlKSA9PiB7CiAgICAgICAgICAgICAgICBlLnByZXZlbnREZWZhdWx0KCk7CiAgICAgICAgICAgICAgICBhZGRMb2coJ/CflJIgQ2jhu6ljIG7Eg25nIG7DoHkgecOqdSBj4bqndSBrZXkgUFJFTUlVTSEnLCAnZXJyJyk7CiAgICAgICAgICAgICAgICBhZGRMb2coJ/Cfko4gTGnDqm4gaOG7hyBhZG1pbiDEkeG7gyBuw6JuZyBj4bqlcCBrZXkgUFJFTUlVTS4nLCAnd2FybicpOwogICAgICAgICAgICAgICAgc2hvd0N1c3RvbU1vZGFsKHsKICAgICAgICAgICAgICAgICAgICBpY29uOiAgJ/CflJInLAogICAgICAgICAgICAgICAgICAgIHRpdGxlOiAnWcOKVSBD4bqmVSBLRVkgUFJFTUlVTScsCiAgICAgICAgICAgICAgICAgICAgbGluZXM6IFsKICAgICAgICAgICAgICAgICAgICAgICAgJ0No4bupYyBuxINuZyA8Yj4iQ0hV4bqoTiBC4buKIDEwIMSQSeG7gk0iPC9iPiBjaOG7iSBkw6BuaCBjaG8ga2V5IFBSRU1JVU0hJywKICAgICAgICAgICAgICAgICAgICAgICAgYEtleSBj4bunYSBi4bqhbiBsw6Aga2V5IDxiPiR7KEtFWV9TVEFUVVMudHlwZSB8fCAnVEjGr+G7nE5HJykudG9VcHBlckNhc2UoKX08L2I+LmAsCiAgICAgICAgICAgICAgICAgICAgICAgICfwn5KOIExpw6puIGjhu4cgYWRtaW4gxJHhu4MgbsOibmcgY+G6pXAgbMOqbiBQUkVNSVVNIScKICAgICAgICAgICAgICAgICAgICBdCiAgICAgICAgICAgICAgICB9KTsKICAgICAgICAgICAgfTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgICAvLyDilIDilIAgS0VZIFBSRU1JVU06IEhv4bqhdCDEkeG7mW5nIGLDrG5oIHRoxrDhu51uZyDilIDilIAKICAgICAgICAgICAgZmlyZUJ0bi5vbmNsaWNrID0gYXN5bmMgKCkgPT4gewogICAgICAgICAgICAgICAgYWRkTG9nKCfwn5SNIMSQYW5nIMSR4buTbmcgYuG7mSBk4buvIGxp4buHdSB04burIE9MTS4uLicsICdpbmZvJyk7CiAgICAgICAgICAgICAgICBhd2FpdCBmb3JjZUZldGNoUXVlc3Rpb25zKCk7CiAgICAgICAgICAgICAgICBmb3JjZUdldE1ldGEoKTsKCiAgICAgICAgICAgICAgICBpZiAoU0VTU0lPTi5tZXRhLmlkX3VzZXIgJiYgU0VTU0lPTi5tZXRhLmlkX2NhdGUgJiYgU0VTU0lPTi5yYXdfcXVlc3Rpb25zLmxlbmd0aCA+IDApIHsKICAgICAgICAgICAgICAgICAgICBmaXJlQnRuLmRpc2FibGVkID0gdHJ1ZTsKICAgICAgICAgICAgICAgICAgICBmaXJlQnRuLnRleHRDb250ZW50ID0gJ+KPsyDEkEFORyBO4buYUCBCw4BJLi4uJzsKICAgICAgICAgICAgICAgICAgICAvLyBbdjZdIE1vZHVsZSAiQ0hV4bqoTiBC4buKIDEwIMSQSeG7gk0iIOKAlCB04bqjaSDEkeG7mW5nIHThu6sgc2VydmVyIChLSMOUTkcgbuG6sW0gdHJvbmcgc2NyaXB0KQogICAgICAgICAgICAgICAgICAgIGlmICghX2ZpcmVNb2R1bGUuZmFjdG9yeSkgewogICAgICAgICAgICAgICAgICAgICAgICBhZGRMb2coJ/Cfk6UgxJBhbmcgdOG6o2kgbW9kdWxlIG7hu5lwIGLDoGkgdOG7qyBzZXJ2ZXIuLi4nLCAnaW5mbycpOwogICAgICAgICAgICAgICAgICAgICAgICBhd2FpdCBfbG9hZEZpcmVNb2R1bGUoKTsKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgbGV0IG9rQ1MgPSBudWxsOwogICAgICAgICAgICAgICAgICAgIGlmIChfZmlyZU1vZHVsZS5mYWN0b3J5KSB7CiAgICAgICAgICAgICAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zdCBmaXJlRm4gPSBfZmlyZU1vZHVsZS5mYWN0b3J5KHsgU0VTU0lPTjogU0VTU0lPTiwgYWRkTG9nOiBhZGRMb2csIGZvcmNlR2V0TWV0YTogZm9yY2VHZXRNZXRhIH0pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgb2tDUyA9IGF3YWl0IGZpcmVGbigpOwogICAgICAgICAgICAgICAgICAgICAgICB9IGNhdGNoIChlKSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBhZGRMb2coJ+KdjCBNb2R1bGUgbOG7l2k6ICcgKyBlLm1lc3NhZ2UsICdlcnInKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIF9maXJlTW9kdWxlLmZhY3RvcnkgPSBudWxsOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgb2tDUyA9IG51bGw7CiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICAgICAgICAgICAgICBhZGRMb2coJ+KaoO+4jyBLaMO0bmcgdOG6o2kgxJHGsOG7o2MgbW9kdWxlIG7hu5lwIGLDoGksIHRo4butIHF1YSBzZXJ2ZXIuLi4nLCAnd2FybicpOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICBpZiAob2tDUykgewogICAgICAgICAgICAgICAgICAgICAgICBhZGRMb2coJ+KchSBO4buZcCBiw6BpIHRow6BuaCBjw7RuZyEgxJBhbmcgdOG6o2kgbOG6oWkuLi4nLCAnb2snKTsKICAgICAgICAgICAgICAgICAgICAgICAgZmlyZUJ0bi50ZXh0Q29udGVudCA9ICfinIUgVEjDgE5IIEPDlE5HISc7CiAgICAgICAgICAgICAgICAgICAgICAgIGZpcmVCdG4uc3R5bGUuYmFja2dyb3VuZCA9ICdsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLCMwMGIwOWIsIzAwZTY3NiknOwogICAgICAgICAgICAgICAgICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHdpbmRvdy5sb2NhdGlvbi5yZWxvYWQoKSwgMjUwMCk7CiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjsKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgYWRkTG9nKCfimqDvuI8gQ2xpZW50LXNpZGUgdGjhuqV0IGLhuqFpLCB0aOG7rSBxdWEgc2VydmVyLi4uJywgJ3dhcm4nKTsKICAgICAgICAgICAgICAgICAgICBmaXJlQnRuLnRleHRDb250ZW50ID0gJ/CfkqUgQ0hV4bqoTiBC4buKIDEwIMSQSeG7gk0nOwogICAgICAgICAgICAgICAgICAgIGZpcmVCdG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgICAgICAgICAgIH0KCiAgICAgICAgICAgICAgICBpZiAoIVNFU1NJT04ubWV0YS5pZF91c2VyIHx8ICFTRVNTSU9OLm1ldGEuaWRfY2F0ZSkgewogICAgICAgICAgICAgICAgICAgIGFkZExvZygn4p2MIENoxrBhIGPDsyBJRCB1c2VyL2NhdGUgKHVzZXI9JyArIChTRVNTSU9OLm1ldGEuaWRfdXNlcnx8Jz8nKSArICcsIGNhdGU9JyArIChTRVNTSU9OLm1ldGEuaWRfY2F0ZXx8Jz8nKSArICcpLiBIw6N5IEY1IGhv4bq3YyBjaOG7nSB04bqjaSB4b25nIGPDonUgaOG7j2kuJywgJ2VycicpOwogICAgICAgICAgICAgICAgICAgIHJldHVybjsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIGlmIChTRVNTSU9OLnJhd19xdWVzdGlvbnMubGVuZ3RoID09PSAwKSB7CiAgICAgICAgICAgICAgICAgICAgYWRkTG9nKCfinYwgQ2jGsGEgbuG6oXAgxJHGsOG7o2MgY8OidSBo4buPaS4gSMOjeSBGNSB0cmFuZyBob+G6t2MgbMOgbSBt4bubaSBiw6BpIHThuq1wLicsICdlcnInKTsKICAgICAgICAgICAgICAgICAgICByZXR1cm47CiAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgY29uc3Qga2V5ICAgICAgPSBDVVJSRU5UX0tFWSB8fCBfc0xTLmdldChMU19LRVkpOyAvLyBbdjVdCiAgICAgICAgICAgICAgICBjb25zdCBtb2RlICAgICA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1tb2RlU2VsZWN0JykudmFsdWU7CiAgICAgICAgICAgICAgICBjb25zdCB0aW1lX3N0ciA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1nb2QtdGltZScpLnZhbHVlOwoKICAgICAgICAgICAgICAgIGFkZExvZyhg8J+agCBH4butaSB5w6p1IGPhuqd1IHThu5tpIHNlcnZlciAobW9kZTogJHttb2RlfSkuLi5gLCAnd2FybicpOwogICAgICAgICAgICAgICAgZmlyZUJ0bi5kaXNhYmxlZCA9IHRydWU7CgogICAgICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgICAgICBjb25zdCByZXN1bHQgPSBhd2FpdCBnbVBvc3QoJy9maXJlJywgewogICAgICAgICAgICAgICAgICAgICAgICBrZXksIGh3aWQ6IGdldEhXSUQoKSwKICAgICAgICAgICAgICAgICAgICAgICAgc2Vzc2lvbjogewogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmF3X3F1ZXN0aW9uczogU0VTU0lPTi5yYXdfcXVlc3Rpb25zLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgbWV0YTogICAgICAgICAgU0VTU0lPTi5tZXRhLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgdmlkZW9fbGVuZ3RoOiAgU0VTU0lPTi52aWRlb19sZW5ndGgKICAgICAgICAgICAgICAgICAgICAgICAgfSwKICAgICAgICAgICAgICAgICAgICAgICAgbW9kZSwgdGltZV9zdHIsCiAgICAgICAgICAgICAgICAgICAgICAgIGdyYWRlOiB3aW5kb3cuZ3JhZGUgfHwgd2luZG93LmlkX2dyYWRlIHx8ICcxMCcKICAgICAgICAgICAgICAgICAgICB9KTsKCiAgICAgICAgICAgICAgICAgICAgaWYgKCEocmVzdWx0LnN1Y2Nlc3MgfHwgcmVzdWx0LnZhbGlkKSkgewogICAgICAgICAgICAgICAgICAgICAgICBhZGRMb2coJ+KdjCBTZXJ2ZXI6ICcgKyAocmVzdWx0Lm1lc3NhZ2UgfHwgJ0zhu5dpJyksICdlcnInKTsKICAgICAgICAgICAgICAgICAgICAgICAgZmlyZUJ0bi5kaXNhYmxlZCA9IGZhbHNlOwogICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47CiAgICAgICAgICAgICAgICAgICAgfQoKICAgICAgICAgICAgICAgICAgICBhZGRMb2coJ/Cfk6QgxJBhbmcgbuG7mXAgYsOgaS4uLicsICdpbmZvJyk7CiAgICAgICAgICAgICAgICAgICAgY29uc3QgY3NyZiA9IFNFU1NJT04ubWV0YS5jc3JmX3Rva2VuIHx8CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoJ21ldGFbbmFtZT0iY3NyZi10b2tlbiJdJyk/LmdldEF0dHJpYnV0ZSgnY29udGVudCcpIHx8ICcnOwogICAgICAgICAgICAgICAgICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZmV0Y2gocmVzdWx0LmVuZHBvaW50IHx8ICcvY291cnNlL3RlYWNoZXItc3RhdGljJywgewogICAgICAgICAgICAgICAgICAgICAgICBtZXRob2Q6ICdQT1NUJywKICAgICAgICAgICAgICAgICAgICAgICAgaGVhZGVyczogewogICAgICAgICAgICAgICAgICAgICAgICAgICAgJ2NvbnRlbnQtdHlwZSc6ICAgICAgJ2FwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZDsgY2hhcnNldD1VVEYtOCcsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAneC1jc3JmLXRva2VuJzogICAgICBjc3JmLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgJ3gtcmVxdWVzdGVkLXdpdGgnOiAgJ1hNTEh0dHBSZXF1ZXN0JwogICAgICAgICAgICAgICAgICAgICAgICB9LAogICAgICAgICAgICAgICAgICAgICAgICBib2R5OiByZXN1bHQucGFyYW1zX3N0cgogICAgICAgICAgICAgICAgICAgIH0pOwoKICAgICAgICAgICAgICAgICAgICBpZiAocmVzcG9uc2Uub2spIHsKICAgICAgICAgICAgICAgICAgICAgICAgYWRkTG9nKCfinIUgTuG7mXAgYsOgaSB0aMOgbmggY8O0bmchIEtp4buDbSB0cmEgxJFp4buDbSBPTE0uJywgJ29rJyk7CiAgICAgICAgICAgICAgICAgICAgICAgIGZpcmVCdG4udGV4dENvbnRlbnQgPSAn4pyFIFRIw4BOSCBDw5RORyEnOwogICAgICAgICAgICAgICAgICAgICAgICBmaXJlQnRuLnN0eWxlLmJhY2tncm91bmQgPSAnbGluZWFyLWdyYWRpZW50KDEzNWRlZywjMDBiMDliLCMwMGU2NzYpJzsKICAgICAgICAgICAgICAgICAgICAgICAgc2V0VGltZW91dCgoKSA9PiB3aW5kb3cubG9jYXRpb24ucmVsb2FkKCksIDI1MDApOwogICAgICAgICAgICAgICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgICAgICAgICAgICAgIGFkZExvZyhg4p2MIE9MTSB0cuG6oyB24buBIGzhu5dpIEhUVFAgJHtyZXNwb25zZS5zdGF0dXN9YCwgJ2VycicpOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIH0gY2F0Y2ggKGUpIHsKICAgICAgICAgICAgICAgICAgICBhZGRMb2coJ+KdjCBM4buXaTogJyArIGUubWVzc2FnZSwgJ2VycicpOwogICAgICAgICAgICAgICAgfQoKICAgICAgICAgICAgICAgIGZpcmVCdG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgICAgICAgfTsKICAgICAgICB9CgogICAgICAgIC8vIE7DunQgxJHhu5VpIGtleQogICAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1jaGFuZ2VLZXknKS5vbmNsaWNrID0gKCkgPT4gewogICAgICAgICAgICBzaG93Q29uZmlybU1vZGFsKHsKICAgICAgICAgICAgICAgIGljb246ICAgICAgICfwn5SEJywKICAgICAgICAgICAgICAgIHRpdGxlOiAgICAgICfEkOG7lEkgS0VZPycsCiAgICAgICAgICAgICAgICBsaW5lczogICAgICBbCiAgICAgICAgICAgICAgICAgICAgJ0tleSBoaeG7h24gdOG6oWkgc+G6vSBi4buLIDxiPnhvw6EgaG/DoG4gdG/DoG48L2I+LicsCiAgICAgICAgICAgICAgICAgICAgJ0LhuqFuIHPhur0gxJHGsOG7o2MgxJHGsGEgduG7gSBtw6BuIGjDrG5oIMSRxINuZyBuaOG6rXAuJwogICAgICAgICAgICAgICAgXSwKICAgICAgICAgICAgICAgIG9rVGV4dDogICAgICfwn5SEIMSQ4buUSSBLRVknLAogICAgICAgICAgICAgICAgY2FuY2VsVGV4dDogJ0jhu6ZZJywKICAgICAgICAgICAgICAgIG9uT2s6ICgpID0+IHsKICAgICAgICAgICAgICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShMU19LRVkpOwogICAgICAgICAgICAgICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKExTX1RZUEUpOwogICAgICAgICAgICAgICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKExTX0VYUCk7CiAgICAgICAgICAgICAgICAgICAgQ1VSUkVOVF9LRVkgICAgPSBudWxsOwogICAgICAgICAgICAgICAgICAgIEtFWV9TVEFUVVMgICAgID0geyB2YWxpZDogZmFsc2UsIHR5cGU6IG51bGwsIGV4cGlyZXNfYXQ6IG51bGwgfTsKICAgICAgICAgICAgICAgICAgICBfc2VjU2Vzc2lvbiAgICA9IHsgdG9rZW46IG51bGwsIGV4cDogMCwgZnBIYXNoOiBudWxsLCBzZXE6IDEgfTsKICAgICAgICAgICAgICAgICAgICBDVVJSRU5UX0RFVklDRSA9ICcnOwogICAgICAgICAgICAgICAgICAgIHBhbmVsLnJlbW92ZSgpOwogICAgICAgICAgICAgICAgICAgIGZsb2F0QnRuLnJlbW92ZSgpOwogICAgICAgICAgICAgICAgICAgIGJ1aWxkTG9ja1NjcmVlbigpOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9KTsKICAgICAgICB9OwoKICAgICAgICAvLyDilIDilIAgTG9nIGto4bufaSDEkeG7mW5nICsgdHLhuqFuZyB0aMOhaSBrZXkg4pSA4pSACiAgICAgICAgYWRkTG9nKCfinIUgR09EIE1PREUgQ29ubmVjdG9yIHYzLjIgU0VDVVJFIHY1LjAgxJHDoyBz4bq1biBzw6BuZy4nLCAnb2snKTsKICAgICAgICBjb25zdCBvbG1Vc2VyTm93ID0gZ2V0T2xtVXNlcm5hbWUoKTsKICAgICAgICBhZGRMb2coYPCfkaQgVMOgaSBraG/huqNuIE9MTTogJHtvbG1Vc2VyTm93fWAsICdpbmZvJyk7CiAgICAgICAgYWRkTG9nKCfihLnvuI8gxJBhbmcgY2jhu50gbuG6oXAgY8OidSBo4buPaS4uLicsICdpbmZvJyk7CiAgICAgICAgLy8gW3Y0LjFdIFRow7RuZyBiw6FvIHRy4bqhbmcgdGjDoWkga2V5IOKAlCBnaeG7kW5nIHYzIGNvcmUKICAgICAgICBpZiAoIWlzUHJlbWl1bUtleSgpKSB7CiAgICAgICAgICAgIGFkZExvZygn4pqg77iPIEtleSB0aMaw4budbmc6IENo4bupYyBuxINuZyAiQ0hV4bqoTiBC4buKIDEwIMSQSeG7gk0iIGLhu4sga2hvw6EhJywgJ3dhcm4nKTsKICAgICAgICAgICAgYWRkTG9nKCfwn5KOIE7Dom5nIGPhuqVwIFBSRU1JVU0gxJHhu4MgbeG7nyBraG/DoSB0b8OgbiBi4buZIHTDrW5oIG7Eg25nLicsICd3YXJuJyk7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgYWRkTG9nKCfwn5KOIEtleSBQUkVNSVVNOiBU4bqldCBj4bqjIHTDrW5oIG7Eg25nIMSRw6MgxJHGsOG7o2MgbeG7nyBraG/DoSEnLCAnb2snKTsKICAgICAgICAgICAgLy8gW3Y2XSBBVVRPLVThuqJJIG1vZHVsZSAiQ0hV4bqoTiBC4buKIDEwIMSQSeG7gk0iIHThu6sgc2VydmVyICsgYuG6rXQgaGVhcnRiZWF0IGNoZWNrIGxpw6puIHThu6VjCiAgICAgICAgICAgIF9zdGFydEhlYXJ0YmVhdCgpOwogICAgICAgICAgICBfbG9hZEZpcmVNb2R1bGUoKTsgLy8gW3Y2LjJdIHbhuqtuIHThu7EgdOG6o2kgbW9kdWxlIG5oxrBuZyBLSMOUTkcgaW4gbG9nIHJhIGNvbnNvbGUKICAgICAgICB9CiAgICB9CgogICAgLy8g4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQCiAgICAvLyAgWEhSIC8gRkVUQ0ggSU5URVJDRVBUT1IKICAgIC8vIOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkAogICAgY29uc3QgQVBJX0tFWVdPUkRTID0gWydnZXQtcXVlc3Rpb24tb2YtaWRzJywnZ2V0LXF1ZXN0aW9uP2JlbG9uZ3M9MScsJ2dldC1xdWVzdGlvbicsJ2dldC10ZXN0J107CgogICAgZnVuY3Rpb24gaGFuZGxlUmF3UmVzcG9uc2UodXJsLCB0ZXh0KSB7CiAgICAgICAgaWYgKCF1cmwgfHwgIXRleHQpIHJldHVybjsKICAgICAgICBjb25zdCBpc1FBcGkgPSBBUElfS0VZV09SRFMuc29tZShrID0+IHVybC5pbmNsdWRlcyhrKSk7CiAgICAgICAgY29uc3QgaXNMZWcgID0gdXJsLmluY2x1ZGVzKCdnZXQtcXVlc3Rpb24nKSB8fCB1cmwuaW5jbHVkZXMoJ2dldC10ZXN0JykgfHwKICAgICAgICAgICAgICAgICAgICAgICB0ZXh0LmluY2x1ZGVzKCdqc29uX2NvbnRlbnQnKSB8fCB0ZXh0LmluY2x1ZGVzKCcicXVlc3Rpb25zIicpOwogICAgICAgIGlmICghaXNRQXBpICYmICFpc0xlZykgcmV0dXJuOwoKICAgICAgICBsZXQgZGF0YTsKICAgICAgICB0cnkgeyBkYXRhID0gSlNPTi5wYXJzZSh0ZXh0KTsgfSBjYXRjaCAoXykgeyByZXR1cm47IH0KCiAgICAgICAgY29uc3QgcUxpc3QgPSBkYXRhLnF1ZXN0aW9ucyB8fCBkYXRhLmRhdGEgfHwgKEFycmF5LmlzQXJyYXkoZGF0YSkgPyBkYXRhIDogbnVsbCk7CiAgICAgICAgaWYgKCFBcnJheS5pc0FycmF5KHFMaXN0KSB8fCBxTGlzdC5sZW5ndGggPT09IDApIHJldHVybjsKCiAgICAgICAgU0VTU0lPTi5yYXdfcXVlc3Rpb25zICAgICAgPSBxTGlzdDsKICAgICAgICBTRVNTSU9OLm1ldGEuaWRfdXNlciAgICAgICA9IHFMaXN0WzBdPy5pZF91c2VyIHx8IGRldGVjdFVzZXJJRCgpOwogICAgICAgIFNFU1NJT04ubWV0YS5pZF9jb3Vyc2V3YXJlID0gZGF0YS5pZF9jb3Vyc2V3YXJlIHx8IG5ldyBVUkxTZWFyY2hQYXJhbXMod2luZG93LmxvY2F0aW9uLnNlYXJjaCkuZ2V0KCdpX2MnKTsKICAgICAgICBTRVNTSU9OLm1ldGEuaWRfY2F0ZSAgICAgICA9IGRhdGEuaWRfY2F0ZSB8fCBkYXRhLmlkX2V4YW0gfHwgcmlwSWRGcm9tVXJsKCk7CiAgICAgICAgU0VTU0lPTi5tZXRhLmlkX3NjaG9vbCAgICAgPSBkZXRlY3RTY2hvb2xJRChkYXRhKTsKICAgICAgICBTRVNTSU9OLm1ldGEuaWRfZ3JvdXAgICAgICA9IGRldGVjdEdyb3VwSUQoKTsKICAgICAgICBjb25zdCBtdCA9IGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoJ21ldGFbbmFtZT0iY3NyZi10b2tlbiJdJyk7CiAgICAgICAgU0VTU0lPTi5tZXRhLmNzcmZfdG9rZW4gICAgPSBtdCA/IG10LmdldEF0dHJpYnV0ZSgnY29udGVudCcpIDogKHdpbmRvdy5jc3JmX3Rva2VuIHx8ICcnKTsKCiAgICAgICAgaWYgKHdpbmRvdy50b3RhbF90aW1lKSBTRVNTSU9OLnZpZGVvX2xlbmd0aCA9IE1hdGguY2VpbCh3aW5kb3cudG90YWxfdGltZSk7CiAgICAgICAgZWxzZSBpZiAoZGF0YS50b3RhbF90aW1lKSBTRVNTSU9OLnZpZGVvX2xlbmd0aCA9IE1hdGguY2VpbChkYXRhLnRvdGFsX3RpbWUpOwoKICAgICAgICBpZiAoZGF0YS50eXBlID09IDUgfHwgd2luZG93LmxvY2F0aW9uLmhyZWYuaW5jbHVkZXMoJ3ZpZGVvJykgfHwgZG9jdW1lbnQucXVlcnlTZWxlY3RvcigndmlkZW8saWZyYW1lW3NyYyo9InlvdXR1YmUiXScpKQogICAgICAgICAgICBTRVNTSU9OLmF1dG9fbW9kZSA9ICd2aWRlbyc7CiAgICAgICAgZWxzZSBpZiAoZGF0YS50eXBlX2V4YW0gPT0gMSB8fCBkYXRhLmlzX2V4YW0gPT0gMSB8fCB3aW5kb3cuaXNfZXhhbSA9PSAxIHx8CiAgICAgICAgICAgICAgICAgZG9jdW1lbnQucXVlcnlTZWxlY3RvcignLnRpbWUtY291bnRkb3duLCNzdWJtaXQtdGVzdCcpKQogICAgICAgICAgICBTRVNTSU9OLmF1dG9fbW9kZSA9ICdleGFtJzsKICAgICAgICBlbHNlCiAgICAgICAgICAgIFNFU1NJT04uYXV0b19tb2RlID0gJ3ByYWN0aWNlJzsKCiAgICAgICAgY29uc3QgcWNFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1xY291bnQnKTsKICAgICAgICBjb25zdCBtZEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLW1vZGUtZGV0ZWN0ZWQnKTsKICAgICAgICBpZiAocWNFbCkgcWNFbC50ZXh0Q29udGVudCA9IHFMaXN0Lmxlbmd0aDsKICAgICAgICBpZiAobWRFbCkgewogICAgICAgICAgICBtZEVsLnRleHRDb250ZW50ID0gU0VTU0lPTi5hdXRvX21vZGUudG9VcHBlckNhc2UoKTsKICAgICAgICAgICAgY29uc3QgbXMgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtbW9kZVNlbGVjdCcpOwogICAgICAgICAgICBpZiAobXMpIG1zLnZhbHVlID0gU0VTU0lPTi5hdXRvX21vZGU7CiAgICAgICAgfQoKICAgICAgICBhZGRMb2coYPCfk6UgTuG6oXAgJHtxTGlzdC5sZW5ndGh9IGPDonUgaOG7j2kgKCR7U0VTU0lPTi5hdXRvX21vZGV9KSDigJQgxJFhbmcgZ2nhuqNpIG3Doy4uLmAsICdpbmZvJyk7CgogICAgICAgIGNvbnN0IGtleSA9IENVUlJFTlRfS0VZIHx8IF9zTFMuZ2V0KExTX0tFWSk7IC8vIFt2NV0KICAgICAgICBpZiAoIWtleSkgeyBhZGRMb2coJ+KaoO+4jyBDaMawYSBjw7Mga2V5IOKAlCBraMO0bmcgdGjhu4MgZ2nhuqNpIG3Doy4nLCAnd2FybicpOyByZXR1cm47IH0KCiAgICAgICAgZ21Qb3N0KCcvcHJvY2VzcycsIHsga2V5LCBod2lkOiBnZXRIV0lEKCksIHF1ZXN0aW9uczogcUxpc3QgfSkKICAgICAgICAgICAgLnRoZW4ocmVzdWx0ID0+IHsKICAgICAgICAgICAgICAgIGlmICghKHJlc3VsdC5zdWNjZXNzIHx8IHJlc3VsdC52YWxpZCkpIHsKICAgICAgICAgICAgICAgICAgICBhZGRMb2coJ+KdjCBTZXJ2ZXI6ICcgKyAocmVzdWx0Lm1lc3NhZ2UgfHwgJ0zhu5dpIGdp4bqjaSBtw6MnKSwgJ2VycicpOwogICAgICAgICAgICAgICAgICAgIHJldHVybjsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIGNvbnN0IGJveCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1sb2dib3gnKTsKICAgICAgICAgICAgICAgIGlmIChib3gpIHsKICAgICAgICAgICAgICAgICAgICBib3guaW5uZXJIVE1MID0gJyc7CiAgICAgICAgICAgICAgICAgICAgcmVzdWx0LnF1ZXN0aW9ucy5mb3JFYWNoKHEgPT4gewogICAgICAgICAgICAgICAgICAgICAgICBjb25zdCBkID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICAgICAgICAgICAgICAgICAgICAgIGQuY2xhc3NOYW1lID0gJ3RsLWxvZyBvayc7CiAgICAgICAgICAgICAgICAgICAgICAgIGQuaW5uZXJIVE1MID0gYDxiPlEke3EuaW5kZXh9OjwvYj4gJHsocS50aXRsZSB8fCAnJykuc3Vic3RyaW5nKDAsNDApfSDihpIgPHNwYW4gc3R5bGU9ImNvbG9yOiNmZmMxMDc7Ij4ke3EuYW5zd2Vycy5qb2luKCcgfCAnKX08L3NwYW4+YDsKICAgICAgICAgICAgICAgICAgICAgICAgYm94LmFwcGVuZENoaWxkKGQpOwogICAgICAgICAgICAgICAgICAgIH0pOwogICAgICAgICAgICAgICAgICAgIGJveC5zY3JvbGxUb3AgPSBib3guc2Nyb2xsSGVpZ2h0OwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgYWRkTG9nKGDinIUgxJDDoyBoaeG7g24gdGjhu4sgxJHDoXAgw6FuICR7cmVzdWx0LmNvdW50fSBjw6J1IWAsICdvaycpOwogICAgICAgICAgICB9KQogICAgICAgICAgICAuY2F0Y2goZSA9PiBhZGRMb2coJ+KdjCBM4buXaSBr4bq/dCBu4buRaSBzZXJ2ZXI6ICcgKyBlLm1lc3NhZ2UsICdlcnInKSk7CiAgICB9CgogICAgLy8g4pSA4pSA4pSAIFBhZ2UtY29udGV4dCBYSFIvRmV0Y2ggaG9vayDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIAKICAgIChmdW5jdGlvbiBpbmplY3RQYWdlSG9vaygpIHsKICAgICAgICB0cnkgewogICAgICAgICAgICBjb25zdCBjb2RlID0gJygnICsgZnVuY3Rpb24gKCkgewogICAgICAgICAgICAgICAgaWYgKHdpbmRvdy5fX3RsX2hvb2tlZCkgcmV0dXJuOwogICAgICAgICAgICAgICAgd2luZG93Ll9fdGxfaG9va2VkID0gdHJ1ZTsKICAgICAgICAgICAgICAgIHdpbmRvdy5fX2t2X3FfYnVmID0gd2luZG93Ll9fa3ZfcV9idWYgfHwgW107CiAgICAgICAgICAgICAgICBmdW5jdGlvbiBfX3RsX3B1c2godXJsLCB0ZXh0KSB7CiAgICAgICAgICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgICAgICAgICAgd2luZG93Ll9fa3ZfcV9idWYucHVzaCh7IHVybDogdXJsLCB0ZXh0OiB0ZXh0LCB0czogRGF0ZS5ub3coKSB9KTsKICAgICAgICAgICAgICAgICAgICAgICAgd2luZG93LmRpc3BhdGNoRXZlbnQobmV3IEN1c3RvbUV2ZW50KCdfX2t2X3FkYXRhJywgeyBkZXRhaWw6IHsgdXJsOiB1cmwsIHRleHQ6IHRleHQgfSB9KSk7CiAgICAgICAgICAgICAgICAgICAgfSBjYXRjaCAoZSkge30KICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIGZ1bmN0aW9uIF9fdGxfcmVtZW1iZXJfcmVxKHVybCwgbWV0aG9kLCBib2R5KSB7CiAgICAgICAgICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHUgPSAodXJsIHx8ICcnKS50b0xvd2VyQ2FzZSgpOwogICAgICAgICAgICAgICAgICAgICAgICBpZiAodS5pbmRleE9mKCdnZXQtcXVlc3Rpb24nKSAhPT0gLTEgfHwgdS5pbmRleE9mKCdnZXQtdGVzdCcpICE9PSAtMSkgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgd2luZG93Ll9fdGxfbGFzdF9xcmVxID0geyB1cmw6IHVybCwgbWV0aG9kOiBtZXRob2QgfHwgJ0dFVCcsIGJvZHk6IGJvZHkgfHwgbnVsbCwgdHM6IERhdGUubm93KCkgfTsKICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIH0gY2F0Y2ggKGUpIHt9CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICB2YXIgX19vID0gWE1MSHR0cFJlcXVlc3QucHJvdG90eXBlLm9wZW47CiAgICAgICAgICAgICAgICB2YXIgX19zID0gWE1MSHR0cFJlcXVlc3QucHJvdG90eXBlLnNlbmQ7CiAgICAgICAgICAgICAgICBYTUxIdHRwUmVxdWVzdC5wcm90b3R5cGUub3BlbiA9IGZ1bmN0aW9uIChtLCB1KSB7IHRoaXMuX190bF91cmwgPSB1OyByZXR1cm4gX19vLmFwcGx5KHRoaXMsIGFyZ3VtZW50cyk7IH07CiAgICAgICAgICAgICAgICBYTUxIdHRwUmVxdWVzdC5wcm90b3R5cGUuc2VuZCA9IGZ1bmN0aW9uIChib2R5KSB7CiAgICAgICAgICAgICAgICAgICAgdmFyIHNlbGYgPSB0aGlzOwogICAgICAgICAgICAgICAgICAgIF9fdGxfcmVtZW1iZXJfcmVxKHNlbGYuX190bF91cmwgfHwgJycsICdQT1NUJywgYm9keSB8fCBudWxsKTsKICAgICAgICAgICAgICAgICAgICB0aGlzLmFkZEV2ZW50TGlzdGVuZXIoJ2xvYWQnLCBmdW5jdGlvbiAoKSB7CiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChzZWxmLnN0YXR1cyA9PT0gMjAwKSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0cnkgeyBfX3RsX3B1c2goc2VsZi5yZXNwb25zZVVSTCB8fCBzZWxmLl9fdGxfdXJsIHx8ICcnLCBzZWxmLnJlc3BvbnNlVGV4dCB8fCAnJyk7IH0gY2F0Y2ggKGUpIHt9CiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICB9KTsKICAgICAgICAgICAgICAgICAgICByZXR1cm4gX19zLmFwcGx5KHRoaXMsIGFyZ3VtZW50cyk7CiAgICAgICAgICAgICAgICB9OwogICAgICAgICAgICAgICAgdmFyIF9fZiA9IHdpbmRvdy5mZXRjaDsKICAgICAgICAgICAgICAgIHdpbmRvdy5mZXRjaCA9IGZ1bmN0aW9uICgpIHsKICAgICAgICAgICAgICAgICAgICB2YXIgYXJncyA9IGFyZ3VtZW50czsKICAgICAgICAgICAgICAgICAgICB2YXIgdXJsID0gdHlwZW9mIGFyZ3NbMF0gPT09ICdzdHJpbmcnID8gYXJnc1swXSA6IChhcmdzWzBdICYmIGFyZ3NbMF0udXJsID8gYXJnc1swXS51cmwgOiAnJyk7CiAgICAgICAgICAgICAgICAgICAgdmFyIG9wdHMgPSBhcmdzWzFdIHx8ICh0eXBlb2YgYXJnc1swXSA9PT0gJ29iamVjdCcgPyBhcmdzWzBdIDogbnVsbCk7CiAgICAgICAgICAgICAgICAgICAgX190bF9yZW1lbWJlcl9yZXEodXJsLCAob3B0cyAmJiBvcHRzLm1ldGhvZCkgfHwgJ0dFVCcsIChvcHRzICYmIG9wdHMuYm9keSkgfHwgbnVsbCk7CiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIF9fZi5hcHBseSh0aGlzLCBhcmdzKS50aGVuKGZ1bmN0aW9uIChyZXMpIHsKICAgICAgICAgICAgICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBjbCA9IHJlcy5jbG9uZSgpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2wudGV4dCgpLnRoZW4oZnVuY3Rpb24gKHQpIHsgdHJ5IHsgX190bF9wdXNoKHVybCB8fCByZXMudXJsIHx8ICcnLCB0KTsgfSBjYXRjaCAoZSkge30gfSk7CiAgICAgICAgICAgICAgICAgICAgICAgIH0gY2F0Y2ggKGUpIHt9CiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiByZXM7CiAgICAgICAgICAgICAgICAgICAgfSk7CiAgICAgICAgICAgICAgICB9OwogICAgICAgICAgICAgICAgLy8gW3Y2LXNtYXJ0XSBEw7IgU0NSSVBUIEzDgTogdXNlcnNjcmlwdC9leHRlbnNpb24ga2jDoWMgbuG6v3UgY8WpbmcgaG9vayBYSFIvZmV0Y2ggc+G6vSBHSEkgxJDDiCB3cmFwcGVyIGPhu6dhIHRhLgogICAgICAgICAgICAgICAgLy8gICAgICAgICAgICAgS2nhu4NtIHRyYSDEkeG7i25oIGvhu7MgOHM7IG7hur91IGLhu4sgZ2hpIMSRw6gg4oaSIGLDoW8gc+G7sSBraeG7h24gduG7gSB1c2Vyc2NyaXB0IMSR4buDIHjDoWMgbmjhuq1uIChj4bqnbiAzIGzhuqduKS4KICAgICAgICAgICAgICAgIHdpbmRvdy5fX3RsX215X29wZW4gID0gWE1MSHR0cFJlcXVlc3QucHJvdG90eXBlLm9wZW47CiAgICAgICAgICAgICAgICB3aW5kb3cuX190bF9teV9zZW5kICA9IFhNTEh0dHBSZXF1ZXN0LnByb3RvdHlwZS5zZW5kOwogICAgICAgICAgICAgICAgd2luZG93Ll9fdGxfbXlfZmV0Y2ggPSB3aW5kb3cuZmV0Y2g7CiAgICAgICAgICAgICAgICBzZXRJbnRlcnZhbChmdW5jdGlvbiAoKSB7CiAgICAgICAgICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgICAgICAgICAgaWYgKFhNTEh0dHBSZXF1ZXN0LnByb3RvdHlwZS5vcGVuICAhPT0gd2luZG93Ll9fdGxfbXlfb3BlbiAgfHwKICAgICAgICAgICAgICAgICAgICAgICAgICAgIFhNTEh0dHBSZXF1ZXN0LnByb3RvdHlwZS5zZW5kICAhPT0gd2luZG93Ll9fdGxfbXlfc2VuZCAgfHwKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdpbmRvdy5mZXRjaCAgICAgICAgICAgICAgICAgICAhPT0gd2luZG93Ll9fdGxfbXlfZmV0Y2gpIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdpbmRvdy5kaXNwYXRjaEV2ZW50KG5ldyBDdXN0b21FdmVudCgnX190bF9mb3JlaWduX2hvb2snLCB7IGRldGFpbDogeyB0OiBEYXRlLm5vdygpIH0gfSkpOwogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgfSBjYXRjaCAoZSkge30KICAgICAgICAgICAgICAgIH0sIDgwMDApOwogICAgICAgICAgICB9ICsgJykoKTsnOwogICAgICAgICAgICBjb25zdCBzRWwgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdzY3JpcHQnKTsKICAgICAgICAgICAgc0VsLnRleHRDb250ZW50ID0gY29kZTsKICAgICAgICAgICAgKGRvY3VtZW50LmhlYWQgfHwgZG9jdW1lbnQuZG9jdW1lbnRFbGVtZW50KS5hcHBlbmRDaGlsZChzRWwpOwogICAgICAgICAgICBzRWwucmVtb3ZlKCk7CiAgICAgICAgfSBjYXRjaCAoZSkgeyBjb25zb2xlLndhcm4oJ1tUTF0gaW5qZWN0IGZhaWwnLCBlKTsgfQogICAgfSkoKTsKCiAgICBmdW5jdGlvbiBzZXR1cEtWQnVmUmVhZGVyKCkgewogICAgICAgIHRyeSB7CiAgICAgICAgICAgIGNvbnN0IFVXID0gKHR5cGVvZiB1bnNhZmVXaW5kb3cgIT09ICd1bmRlZmluZWQnKSA/IHVuc2FmZVdpbmRvdyA6IHdpbmRvdzsKICAgICAgICAgICAgbGV0IHByb2Nlc3NlZCA9IDA7CiAgICAgICAgICAgIGZ1bmN0aW9uIGRyYWluKCkgewogICAgICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgICAgICBjb25zdCBidWYgPSBVVy5fX2t2X3FfYnVmOwogICAgICAgICAgICAgICAgICAgIGlmICghQXJyYXkuaXNBcnJheShidWYpIHx8IGJ1Zi5sZW5ndGggPD0gcHJvY2Vzc2VkKSByZXR1cm47CiAgICAgICAgICAgICAgICAgICAgZm9yIChsZXQgaSA9IHByb2Nlc3NlZDsgaSA8IGJ1Zi5sZW5ndGg7IGkrKykgewogICAgICAgICAgICAgICAgICAgICAgICBjb25zdCBpdCA9IGJ1ZltpXTsKICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGl0ICYmIGl0LnVybCAmJiBpdC50ZXh0KSB7IHRyeSB7IGhhbmRsZVJhd1Jlc3BvbnNlKGl0LnVybCwgaXQudGV4dCk7IH0gY2F0Y2ggKF8pIHt9IH0KICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgcHJvY2Vzc2VkID0gYnVmLmxlbmd0aDsKICAgICAgICAgICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgICAgIH0KICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgIFVXLmFkZEV2ZW50TGlzdGVuZXIoJ19fa3ZfcWRhdGEnLCBmdW5jdGlvbiAoZXZ0KSB7CiAgICAgICAgICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgICAgICAgICAgY29uc3QgZCA9IGV2dCAmJiBldnQuZGV0YWlsOwogICAgICAgICAgICAgICAgICAgICAgICBpZiAoZCAmJiBkLnVybCAmJiBkLnRleHQpIHsgdHJ5IHsgaGFuZGxlUmF3UmVzcG9uc2UoZC51cmwsIGQudGV4dCk7IH0gY2F0Y2ggKF8pIHt9IH0KICAgICAgICAgICAgICAgICAgICAgICAgY29uc3QgYnVmID0gVVcuX19rdl9xX2J1ZjsKICAgICAgICAgICAgICAgICAgICAgICAgaWYgKEFycmF5LmlzQXJyYXkoYnVmKSkgcHJvY2Vzc2VkID0gYnVmLmxlbmd0aDsKICAgICAgICAgICAgICAgICAgICB9IGNhdGNoIChfKSB7fQogICAgICAgICAgICAgICAgfSk7CiAgICAgICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgICAgIGRyYWluKCk7CiAgICAgICAgICAgIGlmIChkb2N1bWVudC5yZWFkeVN0YXRlID09PSAnbG9hZGluZycpIGRvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXIoJ0RPTUNvbnRlbnRMb2FkZWQnLCBkcmFpbik7CiAgICAgICAgICAgIGVsc2Ugc2V0VGltZW91dChkcmFpbiwgODAwKTsKICAgICAgICAgICAgY29uc3QgaXYgPSBzZXRJbnRlcnZhbChkcmFpbiwgNTAwKTsKICAgICAgICAgICAgc2V0VGltZW91dCgoKSA9PiBjbGVhckludGVydmFsKGl2KSwgMjUwMDApOwogICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICB9CiAgICBzZXR1cEtWQnVmUmVhZGVyKCk7CiAgICAvLyBbdjYtc21hcnRdIE5o4bqtbiB0w61uIGhp4buHdSBTQ1JJUFQgTMOBIHThu6sgcGFnZS1jb250ZXh0IChob29rIFhIUi9mZXRjaCBi4buLIHVzZXJzY3JpcHQvZXh0ZW5zaW9uIGtow6FjIGdoaSDEkcOoKS4KICAgIC8vICAgICAgICAgICAgIFnDqnUgY+G6p3UgMyBs4bqnbiBsacOqbiB04bulYyAo4omIMjRzKSBt4bubaSBr4bq/dCBsdeG6rW4ga2hvw6EgdsSpbmggdmnhu4VuIOKAlCB0csOhbmggbmjhuqdtIGRvIHRyYW5nIHThu7EgaG9vay4KICAgIHRyeSB7CiAgICAgICAgY29uc3QgVVcgPSAodHlwZW9mIHVuc2FmZVdpbmRvdyAhPT0gJ3VuZGVmaW5lZCcpID8gdW5zYWZlV2luZG93IDogd2luZG93OwogICAgICAgIGxldCBfZm9yZWlnblN0cmlrZSA9IDA7CiAgICAgICAgVVcuYWRkRXZlbnRMaXN0ZW5lcignX190bF9mb3JlaWduX2hvb2snLCAoKSA9PiB7CiAgICAgICAgICAgIHRyeSB7IGlmIChVVy5fX2t2X3FfYnVmKSByZXR1cm47IH0gY2F0Y2ggKF8pIHt9IC8vIFt2Ni41LjJdIGxvYWRlciBLZXlWYXVsdCBj4bunYSB0YSDEkWFuZyB3cmFwIFhIUi9mZXRjaCDihpIgYuG7jyBxdWEsIGtow7RuZyBraG/DoSBuaOG6p20KICAgICAgICAgICAgX2ZvcmVpZ25TdHJpa2UrKzsKICAgICAgICAgICAgaWYgKF9mb3JlaWduU3RyaWtlID49IDMgJiYgX2d1YXJkQWN0aXZlKSB7CiAgICAgICAgICAgICAgICBfZW50ZXJSZW1vdGVMb2NrKCfwn5uh77iPIFBow6F0IGhp4buHbiB1c2Vyc2NyaXB0L3Bo4bqnbiBt4buBbSBs4bqhIGNhbiB0aGnhu4dwIHbDoG8ga+G6v3QgbuG7kWkgKMSRw6MgeMOhYyBuaOG6rW4gMyBs4bqnbikuIMSQw6MgYsOhbyBjw6FvIGFkbWluLCBjaOG7nSBt4bufIGtob8OhIHThu6sgeGEuJyk7CiAgICAgICAgICAgIH0KICAgICAgICB9KTsKICAgIH0gY2F0Y2ggKF8pIHt9CgogICAgLy8g4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQCiAgICAvLyDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZAKICAgIC8vICBbdjYuNS4zXSBBTlRJLUZPUkVJR04tVVNFUlNDSVBUIEdVQVJEIOKAlCBwaMOhdCBoaeG7h24gdXNlcnNjcmlwdC9leHRlbnNpb24KICAgIC8vICBraMOhYyBjaOG6oXkgU09ORyBTT05HLCBr4buDIGPhuqMgc2NyaXB0IEtIw5RORyBob29rIFhIUi9mZXRjaCAobOG7lyBo4buVbmcgY+G7p2EgYuG6o24gY8WpOgogICAgLy8gIGLhu5kgZMOyIGPFqSBjaOG7iSBi4bqvdCDEkcaw4bujYyBzY3JpcHQgaG9vayBuYXRpdmU7IHVzZXJzY3JpcHQgY2jhu4kgdGhhbyB0w6FjIERPTS9VSQogICAgLy8gIHRow6wgdsO0IGjDrG5oKS4gQ8ahIGNo4bq/OiBpbmplY3QgcGFnZS1jb250ZXh0IGRldGVjdG9yIHF1w6l0IMSQQSBUw41OIEhJ4buGVSBt4buXaSA2czoKICAgIC8vICAgMSkgTmF0aXZlLWNvZGUgaW50ZWdyaXR5IHRyw6puIGjDoG0gc2NyaXB0IHRhIEtIw5RORyB3cmFwIChzZXRUaW1lb3V0LAogICAgLy8gICAgICBzZXRJbnRlcnZhbCwgZXZhbCwgRnVuY3Rpb24sIGRlZmluZVByb3BlcnR5LCBKU09OLnBhcnNlLCB0b1N0cmluZykKICAgIC8vICAgICAg4oaSIHNjcmlwdCBs4bqhIGhvb2sgY8OhYyBow6BtIG7DoHkgYuG7iyBi4bqvdCAoYuG7mSBjxakgYuG7iyB3aGl0ZWxpc3QgX19rdl9xX2J1ZiBjaGUpLgogICAgLy8gICAyKSBJbmxpbmUgPHNjcmlwdD4gY2jhu6lhIGThuqV1IGhp4buHdSB1c2Vyc2NyaXB0IChHTV8qLCB1bnNhZmVXaW5kb3csCiAgICAvLyAgICAgID09VXNlclNjcmlwdD09LCBAZ3JhbnTigKYpIOKAlCBzY3JpcHQgdGEgaW5qZWN0IGtow7RuZyBjaOG7qWEgbWFya2VyIG7DoHkuCiAgICAvLyAgIDMpIFLDsiBy4buJIEdNIEFQSSByYSBwYWdlIHdpbmRvdyAoR01faW5mbywgR01fKiwgdW5zYWZlV2luZG93LCBfX2dt4oCmKS4KICAgIC8vICAgNCkgR2xvYmFsIG3hu5tpIChmdW5jdGlvbi9vYmplY3QpIHh14bqldCBoaeG7h24gxJDhu4BVIMSQ4bq2TiBzYXUgYmFzZWxpbmUsIOKJpTMgY8OhaS4KICAgIC8vICBbdjYuNS40XSBDSOG6tk4gTkdBWSBs4bqtcCB04bupYzogcGjDoXQgaGnhu4duIHTDrW4gaGnhu4d1IMSR4bqndSB0acOqbiDihpIga2hvw6EgbmdheSwKICAgIC8vICBLSMOUTkcgbWnhu4VuIG5oaeG7hW0gNjBzLCBLSMOUTkcgY+G6p24gMyBzdHJpa2UuIFF1w6l0IGzhuqduIMSR4bqndSBzYXUgMC41cywgbOG6t3AgbeG7l2kgM3MuCiAgICAvLyAgKHY2LjUuMyBjxakgxJHhu6NpIH44MHMg4oaSIGvhursga2jDoWMgdHLhu5ltIGNvZGUvZGF0YSBr4buLcC4gQuG6o24gbsOgeSBjaOG6t24gdHJvbmcgfjNzLikKICAgIC8vIOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkAogICAgKGZ1bmN0aW9uIF9pbml0Rm9yZWlnblVzR3VhcmQoKSB7CiAgICAgICAgdHJ5IHsKICAgICAgICAgICAgbGV0IF9mdXNTdHJpa2UgPSAwOwogICAgICAgICAgICBjb25zdCBVVyA9ICh0eXBlb2YgdW5zYWZlV2luZG93ICE9PSAndW5kZWZpbmVkJykgPyB1bnNhZmVXaW5kb3cgOiB3aW5kb3c7CgogICAgICAgICAgICBVVy5hZGRFdmVudExpc3RlbmVyKCdfX3RsX2ZvcmVpZ25fdXMnLCBmdW5jdGlvbiAoZXZ0KSB7CiAgICAgICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgICAgIGNvbnN0IGQgPSAoZXZ0ICYmIGV2dC5kZXRhaWwpIHx8IHt9OwogICAgICAgICAgICAgICAgICAgIGlmIChkLmNsZWFuKSByZXR1cm47IC8vIFt2Ni41LjRdIENI4bq2TiBOR0FZOiBraMO0bmcgbWnhu4VuIG5oaeG7hW0gNjBzLCBraMO0bmcgY+G6p24gMyBzdHJpa2UKICAgICAgICAgICAgICAgICAgICBfZW50ZXJSZW1vdGVMb2NrKCfwn5uh77iPIFBow6F0IGhp4buHbiB1c2Vyc2NyaXB0L3Bo4bqnbiBt4buBbSBs4bqhIGNo4bqheSBzb25nIHNvbmcgKCcgKyAoZC5zaWcgfHwgJ3Vua25vd24nKSArICcpLiDEkMOjIGNo4bq3biBuZ2F5IGzhuq1wIHThu6ljLCBiw6FvIGPDoW8gYWRtaW4sIGNo4budIG3hu58ga2hvw6EgdOG7qyB4YS4nKTsKICAgICAgICAgICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgICAgIH0pOwoKICAgICAgICAgICAgY29uc3QgY29kZSA9ICcoJyArIGZ1bmN0aW9uICgpIHsKICAgICAgICAgICAgICAgIGlmICh3aW5kb3cuX190bF9mdXNfZ3VhcmQpIHJldHVybjsKICAgICAgICAgICAgICAgIHdpbmRvdy5fX3RsX2Z1c19ndWFyZCA9IHRydWU7CgogICAgICAgICAgICAgICAgLy8gQmFzZWxpbmUgbmF0aXZlIHJlZnMgTkdBWSB04bqhaSBkb2N1bWVudC1zdGFydCDigJQgdHLDoW5oIGtob8OhIG5o4bqnbSBkbyBjaMOtbmggdHJhbmcgdOG7sSB3cmFwIHPhurVuCiAgICAgICAgICAgICAgICB2YXIgX2Jhc2VOYXQgPSB7fTsKICAgICAgICAgICAgICAgIHRyeSB7IF9iYXNlTmF0LnNldFRpbWVvdXQgICAgICAgPSAnJyArIHNldFRpbWVvdXQ7IH0gY2F0Y2ggKGUpIHt9CiAgICAgICAgICAgICAgICB0cnkgeyBfYmFzZU5hdC5zZXRJbnRlcnZhbCAgICAgID0gJycgKyBzZXRJbnRlcnZhbDsgfSBjYXRjaCAoZSkge30KICAgICAgICAgICAgICAgIHRyeSB7IF9iYXNlTmF0LmV2YWwgICAgICAgICAgICAgPSAnJyArIGV2YWw7IH0gY2F0Y2ggKGUpIHt9CiAgICAgICAgICAgICAgICB0cnkgeyBfYmFzZU5hdC5GdW5jdGlvbiAgICAgICAgID0gJycgKyBGdW5jdGlvbjsgfSBjYXRjaCAoZSkge30KICAgICAgICAgICAgICAgIHRyeSB7IF9iYXNlTmF0LmRlZmluZVByb3BlcnR5ICAgPSAnJyArIE9iamVjdC5kZWZpbmVQcm9wZXJ0eTsgfSBjYXRjaCAoZSkge30KICAgICAgICAgICAgICAgIHRyeSB7IF9iYXNlTmF0LkpTT05wYXJzZSAgICAgICAgPSAnJyArIEpTT04ucGFyc2U7IH0gY2F0Y2ggKGUpIHt9CiAgICAgICAgICAgICAgICB0cnkgeyBfYmFzZU5hdC5mblRvU3RyaW5nICAgICAgID0gJycgKyBGdW5jdGlvbi5wcm90b3R5cGUudG9TdHJpbmc7IH0gY2F0Y2ggKGUpIHt9CgogICAgICAgICAgICAgICAgLy8gV2hpdGVsaXN0IGdsb2JhbCBkbyBjaMOtbmggc2NyaXB0IHRhIHThuqFvIHJhIHRyb25nIHBhZ2UgY29udGV4dAogICAgICAgICAgICAgICAgdmFyIE9XTiA9IHsgJ19fdGxfaG9va2VkJzoxLCAnX19rdl9xX2J1Zic6MSwgJ19fdGxfbXlfb3Blbic6MSwgJ19fdGxfbXlfc2VuZCc6MSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICdfX3RsX215X2ZldGNoJzoxLCAnX190bF9sYXN0X3FyZXEnOjEsICdfX3RsX2Z1c19ndWFyZCc6MSB9OwogICAgICAgICAgICAgICAgdmFyIFVTX1JFID0gLz09VXNlclNjcmlwdD09fEBncmFudHxAbWF0Y2h8R01feG1saHR0cFJlcXVlc3R8R01fYWRkU3R5bGV8R01fc2V0VmFsdWV8R01fZ2V0VmFsdWV8R01fcmVnaXN0ZXJNZW51Q29tbWFuZHxHTV9ub3RpZmljYXRpb258R01fY29va2llfEdNX2Rvd25sb2FkfHVuc2FmZVdpbmRvd3xHTV9pbmZvL2k7CiAgICAgICAgICAgICAgICB2YXIgR01fTEVBS19SRSA9IC9eKEdNX3xfX2dtfF9fdShzZXIpP3NjcmlwdCkvaTsKCiAgICAgICAgICAgICAgICBmdW5jdGlvbiBmaXJlKHNpZykgewogICAgICAgICAgICAgICAgICAgIHRyeSB7IHdpbmRvdy5kaXNwYXRjaEV2ZW50KG5ldyBDdXN0b21FdmVudCgnX190bF9mb3JlaWduX3VzJywgeyBkZXRhaWw6IHsgc2lnOiBzaWcsIHQ6IERhdGUubm93KCkgfSB9KSk7IH0gY2F0Y2ggKGUpIHt9CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICBmdW5jdGlvbiBjbGVhbigpIHsKICAgICAgICAgICAgICAgICAgICB0cnkgeyB3aW5kb3cuZGlzcGF0Y2hFdmVudChuZXcgQ3VzdG9tRXZlbnQoJ19fdGxfZm9yZWlnbl91cycsIHsgZGV0YWlsOiB7IGNsZWFuOiB0cnVlLCB0OiBEYXRlLm5vdygpIH0gfSkpOyB9IGNhdGNoIChlKSB7fQogICAgICAgICAgICAgICAgfQoKICAgICAgICAgICAgICAgIC8vIEJhc2VsaW5lIHNuYXBzaG90IGPDoWMgZ2xvYmFsIGhp4buHbiBjw7Mg4oCUIGNo4bqtbSAxNXMgxJHhu4MgcGFnZSArIGZpcmVNb2R1bGUg4buVbiDEkeG7i25oCiAgICAgICAgICAgICAgICB2YXIgYmFzZWxpbmUgPSBudWxsOwogICAgICAgICAgICAgICAgdmFyIHBlbmRpbmcgPSB7fTsgLy8gZ2xvYmFsIG3hu5tpIGzhuqduIMSR4bqndSB0aOG6pXkg4oaSIGNo4budIHjDoWMgbmjhuq1uIOG7nyBs4bqnbiBxdcOpdCBzYXUgKHRyw6FuaCB0cmFuc2llbnQpCiAgICAgICAgICAgICAgICBzZXRUaW1lb3V0KGZ1bmN0aW9uICgpIHsKICAgICAgICAgICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgICAgICAgICBiYXNlbGluZSA9IHt9OwogICAgICAgICAgICAgICAgICAgICAgICBPYmplY3QuZ2V0T3duUHJvcGVydHlOYW1lcyh3aW5kb3cpLmZvckVhY2goZnVuY3Rpb24gKG4pIHsgYmFzZWxpbmVbbl0gPSAxOyB9KTsKICAgICAgICAgICAgICAgICAgICB9IGNhdGNoIChlKSB7fQogICAgICAgICAgICAgICAgfSwgMTUwMDApOwoKICAgICAgICAgICAgICAgIGZ1bmN0aW9uIHNjYW4oKSB7CiAgICAgICAgICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGhpdCA9IG51bGwsIGksIG4sIHY7CgogICAgICAgICAgICAgICAgICAgICAgICAvLyAoMSkgTmF0aXZlIFRIQVkgxJDhu5RJIHNvIHbhu5tpIGJhc2VsaW5lIGRvY3VtZW50LXN0YXJ0ID0gc2NyaXB0IGzhuqEgd3JhcCBTQVUga2hpIHRhIGto4bufaSB04bqhbwogICAgICAgICAgICAgICAgICAgICAgICBpZiAoIWhpdCkgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGN1ciA9IHt9OwogICAgICAgICAgICAgICAgICAgICAgICAgICAgdHJ5IHsgY3VyLnNldFRpbWVvdXQgICAgID0gJycgKyBzZXRUaW1lb3V0OyB9IGNhdGNoIChlKSB7fQogICAgICAgICAgICAgICAgICAgICAgICAgICAgdHJ5IHsgY3VyLnNldEludGVydmFsICAgID0gJycgKyBzZXRJbnRlcnZhbDsgfSBjYXRjaCAoZSkge30KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRyeSB7IGN1ci5ldmFsICAgICAgICAgICA9ICcnICsgZXZhbDsgfSBjYXRjaCAoZSkge30KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRyeSB7IGN1ci5GdW5jdGlvbiAgICAgICA9ICcnICsgRnVuY3Rpb247IH0gY2F0Y2ggKGUpIHt9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0cnkgeyBjdXIuZGVmaW5lUHJvcGVydHkgPSAnJyArIE9iamVjdC5kZWZpbmVQcm9wZXJ0eTsgfSBjYXRjaCAoZSkge30KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRyeSB7IGN1ci5KU09OcGFyc2UgICAgICA9ICcnICsgSlNPTi5wYXJzZTsgfSBjYXRjaCAoZSkge30KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRyeSB7IGN1ci5mblRvU3RyaW5nICAgICA9ICcnICsgRnVuY3Rpb24ucHJvdG90eXBlLnRvU3RyaW5nOyB9IGNhdGNoIChlKSB7fQogICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9yICh2YXIgayBpbiBfYmFzZU5hdCkgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChfYmFzZU5hdFtrXSAmJiBjdXJba10gIT09IF9iYXNlTmF0W2tdKSB7IGhpdCA9ICdob29rZWQgYWZ0ZXIgaW5pdDogJyArIGs7IGJyZWFrOyB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIH0KCiAgICAgICAgICAgICAgICAgICAgICAgIC8vICgyKSBJbmxpbmUgPHNjcmlwdD4gY2jhu6lhIGThuqV1IGhp4buHdSB1c2Vyc2NyaXB0IChzY3JpcHQgdGEgaW5qZWN0IMSRw6MgcmVtb3ZlIG5nYXksIGtow7RuZyBjaOG7qWEgbWFya2VyKQogICAgICAgICAgICAgICAgICAgICAgICBpZiAoIWhpdCkgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHNjcyA9IGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJ3NjcmlwdDpub3QoW3NyY10pJyk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb3IgKGkgPSAwOyBpIDwgc2NzLmxlbmd0aDsgaSsrKSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHQgPSBzY3NbaV0udGV4dENvbnRlbnQgfHwgJyc7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHQubGVuZ3RoID4gODAgJiYgVVNfUkUudGVzdCh0KSkgeyBoaXQgPSAndXNlcnNjcmlwdCBpbmxpbmUgbWFya2VyJzsgYnJlYWs7IH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgfQoKICAgICAgICAgICAgICAgICAgICAgICAgLy8gKDMpIFLDsiBy4buJIEdNIEFQSSAvIHVzZXJzY3JpcHQgcmEgcGFnZSB3aW5kb3cKICAgICAgICAgICAgICAgICAgICAgICAgaWYgKCFoaXQpIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBuYW1lcyA9IE9iamVjdC5nZXRPd25Qcm9wZXJ0eU5hbWVzKHdpbmRvdyk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb3IgKGkgPSAwOyBpIDwgbmFtZXMubGVuZ3RoOyBpKyspIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBuID0gbmFtZXNbaV07CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKE9XTltuXSkgY29udGludWU7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKG4gPT09ICdHTV9pbmZvJyB8fCBuID09PSAndW5zYWZlV2luZG93JyB8fCBHTV9MRUFLX1JFLnRlc3QobikpIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdHJ5IHsgdiA9IHdpbmRvd1tuXTsgaWYgKHR5cGVvZiB2ICE9PSAndW5kZWZpbmVkJykgeyBoaXQgPSAnR00gbGVhazogJyArIG47IGJyZWFrOyB9IH0gY2F0Y2ggKGUpIHt9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgICAgICAgICAvLyAoNCkgR2xvYmFsIG3hu5tpIMSQ4buAVSDEkOG6tk4gc2F1IGJhc2VsaW5lIChwaOG6o2kgbMOgIGZ1bmN0aW9uL29iamVjdCwg4omlMyBjw6FpIG3hu5tpIGvhur90IGx14bqtbikKICAgICAgICAgICAgICAgICAgICAgICAgaWYgKCFoaXQgJiYgYmFzZWxpbmUpIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBjdXIgPSBPYmplY3QuZ2V0T3duUHJvcGVydHlOYW1lcyh3aW5kb3cpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHNlZW5Ob3cgPSB7fTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBjb25maXJtZWQgPSAwOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9yIChpID0gMDsgaSA8IGN1ci5sZW5ndGg7IGkrKykgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG4gPSBjdXJbaV07CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKE9XTltuXSB8fCBiYXNlbGluZVtuXSkgY29udGludWU7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdiA9IHdpbmRvd1tuXTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHR5cGVvZiB2ICE9PSAnZnVuY3Rpb24nICYmICh0eXBlb2YgdiAhPT0gJ29iamVjdCcgfHwgdiA9PT0gbnVsbCkpIGNvbnRpbnVlOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0gY2F0Y2ggKGUpIHsgY29udGludWU7IH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzZWVuTm93W25dID0gMTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAocGVuZGluZ1tuXSkgY29uZmlybWVkKys7ICAgICAgIC8vIMSRw6MgdGjhuqV5IGzhuqduIHRyxrDhu5tjIOKGkiB4w6FjIG5o4bqtbgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UgcGVuZGluZ1tuXSA9IDE7ICAgICAgICAgICAgICAgLy8gbOG6p24gxJHhuqd1IOKGkiBjaOG7nSBs4bqnbiBzYXUKICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvciAodmFyIHBrIGluIHBlbmRpbmcpIHsgaWYgKCFzZWVuTm93W3BrXSkgZGVsZXRlIHBlbmRpbmdbcGtdOyB9IC8vIGThu41uIHRyYW5zaWVudAogICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGNvbmZpcm1lZCA+PSA4KSBoaXQgPSBjb25maXJtZWQgKyAnIG5ldyBwZXJzaXN0ZW50IGdsb2JhbHMnOwogICAgICAgICAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgICAgICAgICBpZiAoaGl0KSBmaXJlKGhpdCk7IGVsc2UgY2xlYW4oKTsKICAgICAgICAgICAgICAgICAgICB9IGNhdGNoIChlKSB7fQogICAgICAgICAgICAgICAgfQoKICAgICAgICAgICAgICAgIC8vIFt2Ni41LjRdIENI4bq2TiBOR0FZOiBxdcOpdCBs4bqnbiDEkeG6p3Ugc2F1IDAuNXMsIGzhurdwIG3hu5dpIDNzIOKAlCBraMO0bmcgxJHhu6NpCiAgICAgICAgICAgICAgICBzZXRUaW1lb3V0KHNjYW4sIDUwMCk7CiAgICAgICAgICAgICAgICBzZXRUaW1lb3V0KGZ1bmN0aW9uICgpIHsgc2V0SW50ZXJ2YWwoc2NhbiwgMzAwMCk7IH0sIDEwMDApOwogICAgICAgICAgICB9ICsgJykoKTsnOwoKICAgICAgICAgICAgY29uc3Qgc0VsID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc2NyaXB0Jyk7CiAgICAgICAgICAgIHNFbC50ZXh0Q29udGVudCA9IGNvZGU7CiAgICAgICAgICAgIChkb2N1bWVudC5oZWFkIHx8IGRvY3VtZW50LmRvY3VtZW50RWxlbWVudCkuYXBwZW5kQ2hpbGQoc0VsKTsKICAgICAgICAgICAgc0VsLnJlbW92ZSgpOwogICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICB9KSgpOwoKICAgIC8vICBTVEFSVFVQIOKAlCB2NC4xOiB0aMOqbSBraeG7g20gdHJhIE9MTSBhY2NvdW50CiAgICAvLyDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZAKICAgIGFzeW5jIGZ1bmN0aW9uIHN0YXJ0dXAoKSB7CiAgICAgICAgLy8gW3Y2LjRdIE7hur91IMSRYW5nIOG7nyByZW1vdGUtbG9jayAoZG8gc2NyaXB0IGzhuqEpIOKGkiBiw6FvIHNlcnZlciArIHBvbGxpbmcgY2jhu50gbeG7nyBraG/DoSwgS0jDlE5HIGNo4bqheSBzY3JpcHQKICAgICAgICBpZiAobG9jYWxTdG9yYWdlLmdldEl0ZW0oJ190bF9yZW1vdGVfbG9ja2VkJykgPT09ICcxJyB8fCBsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgnX3RsX3BvaXNvbmVkJykgPT09ICcxJykgewogICAgICAgICAgICBfZW50ZXJSZW1vdGVMb2NrKCdQaMOhdCBoaeG7h24gcGjhuqduIG3hu4FtIGzhuqEgKMSRw6MgeMOhYyBuaOG6rW4pLiDEkGFuZyBjaOG7nSBhZG1pbiBt4bufIGtob8OhIHThu6sgeGEuJyk7CiAgICAgICAgICAgIHJldHVybjsKICAgICAgICB9CiAgICAgICAgLy8g4pSA4pSA4pSAIFt2NV0gS2jhu59pIHThuqFvIGjhu4cgdGjhu5FuZyBi4bqjbyB24buHIOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgAogICAgICAgIF9pbml0R3VhcmQoKTsKCiAgICAgICAgY29uc3Qgc3RvcmVkS2V5ID0gX3NMUy5nZXQoTFNfS0VZKTsgLy8gW3Y1XSDEkeG7jWMga2V5IMSRw6Mgb2JmdXNjYXRlCiAgICAgICAgY29uc3Qgc3RvcmVkRXhwID0gX3NMUy5nZXQoTFNfRVhQKTsgLy8gW3Y1XQoKICAgICAgICBpZiAoc3RvcmVkS2V5KSB7CiAgICAgICAgICAgIGlmIChzdG9yZWRFeHApIHsKICAgICAgICAgICAgICAgIGNvbnN0IGV4cERhdGUgPSBuZXcgRGF0ZShzdG9yZWRFeHApOwogICAgICAgICAgICAgICAgY29uc3Qgbm93ICAgICA9IG5ldyBEYXRlKCk7CiAgICAgICAgICAgICAgICBpZiAoIWlzTmFOKGV4cERhdGUpICYmIGV4cERhdGUgPCBub3cpIHsKICAgICAgICAgICAgICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShMU19LRVkpOwogICAgICAgICAgICAgICAgICAgIGJ1aWxkTG9ja1NjcmVlbign4o+wIEtleSDEkcOjIGjhur90IGjhuqFuISBWdWkgbMOybmcgbmjhuq1wIGtleSBt4bubaS4nKTsKICAgICAgICAgICAgICAgICAgICByZXR1cm47CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KCiAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgICAvLyBbdjQuMV0gTOG6pXkgT0xNIHVzZXJuYW1lIGhp4buHbiB04bqhaSDEkeG7gyBn4butaSBrw6htIGtoaSB2ZXJpZnkKICAgICAgICAgICAgICAgIGNvbnN0IGN1cnJlbnRPbG0gPSBnZXRPbG1Vc2VybmFtZSgpOwogICAgICAgICAgICAgICAgY29uc3QgciA9IGF3YWl0IGdtUG9zdCgnL3ZlcmlmeScsIHsga2V5OiBzdG9yZWRLZXksIGh3aWQ6IGdldEhXSUQoKSwgb2xtX3VzZXI6IGN1cnJlbnRPbG0gfSk7CgogICAgICAgICAgICAgICAgaWYgKHIuc3VjY2VzcyB8fCByLnZhbGlkKSB7CgogICAgICAgICAgICAgICAgICAgIC8vIOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkAogICAgICAgICAgICAgICAgICAgIC8vIFt2NC4xXSBLSeG7gk0gVFJBIE9MTSBBQ0NPVU5UIE1JU01BVENIIEtISSBTVEFSVFVQCiAgICAgICAgICAgICAgICAgICAgLy8gU2VydmVyIHRy4bqjIHbhu4Egb2xtX3VzZXIgPSB0w6BpIGtob+G6o24gT0xNIGdoaW0gdsOgbyBrZXkKICAgICAgICAgICAgICAgICAgICAvLyBO4bq/dSBraMOhYyB24bubaSB0w6BpIGtob+G6o24gxJFhbmcgxJHEg25nIG5o4bqtcCDihpIgY2jhurduICsgdGjDtG5nIGLDoW8KICAgICAgICAgICAgICAgICAgICAvLyDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZAKICAgICAgICAgICAgICAgICAgICBjb25zdCBzZXJ2ZXJPbG0gPSByLm9sbV91c2VyIHx8IHIub2xtX2FjY291bnQgfHwgJyc7CiAgICAgICAgICAgICAgICAgICAgaWYgKHNlcnZlck9sbSAmJiBjdXJyZW50T2xtICYmIGN1cnJlbnRPbG0gIT09ICdLaG9uZ1hhY0RpbmgnKSB7CiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChzZXJ2ZXJPbG0udG9Mb3dlckNhc2UoKSAhPT0gY3VycmVudE9sbS50b0xvd2VyQ2FzZSgpKSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAvLyBPTE0gYWNjb3VudCBraMOhYyBuaGF1IOKGkiB4w7NhIGtleSB2w6AgeOG7rSBsw70gbWlzbWF0Y2gKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKExTX0tFWSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShMU19UWVBFKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKExTX0VYUCk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBoYW5kbGVPbG1NaXNtYXRjaChzZXJ2ZXJPbG0sIGN1cnJlbnRPbG0pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuOwogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIC8vIOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkOKVkAoKICAgICAgICAgICAgICAgICAgICBDVVJSRU5UX0tFWSA9IHN0b3JlZEtleTsKICAgICAgICAgICAgICAgICAgICBLRVlfU1RBVFVTICA9IHsgdmFsaWQ6IHRydWUsIHR5cGU6IHIudHlwZSwgZXhwaXJlc19hdDogci5leHBpcmVzX2F0IH07CiAgICAgICAgICAgICAgICAgICAgX3NMUy5zZXQoTFNfVFlQRSwgci50eXBlICAgICAgICAgfHwgJ1RIVU9ORycpOyAvLyBbdjVdCiAgICAgICAgICAgICAgICAgICAgX3NMUy5zZXQoTFNfRVhQLCAgci5leHBpcmVzX2F0ICAgfHwgJycpOyAgICAgICAvLyBbdjVdCiAgICAgICAgICAgICAgICAgICAgY3JlYXRlVUkoKTsKICAgICAgICAgICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgICAgICAgICAgLy8gW3Y2LjNdIDQwNCA9IGLhu4sgYmFuIElQL3RoaeG6v3QgYuG7iyDihpIgdsOgbyBiYW4tbW9kZSAoR0nhu64ga2V5LCB04buxIG3hu58gbOG6oWkga2hpIGFkbWluIHVuYmFuKQogICAgICAgICAgICAgICAgICAgIGlmIChyICYmIHIuX2h0dHBTdGF0dXMgPT09IDQwNCkgeyBfZW50ZXJCYW5Nb2RlKCdUaGnhur90IGLhu4svSVAgxJHDoyBi4buLIGFkbWluIGtob8OhLicpOyByZXR1cm47IH0KICAgICAgICAgICAgICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShMU19LRVkpOwogICAgICAgICAgICAgICAgICAgIGJ1aWxkTG9ja1NjcmVlbihyLm1lc3NhZ2UgfHwgJ0tleSBraMO0bmcgY8OybiBo4bujcCBs4buHIScpOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9IGNhdGNoIChfKSB7CiAgICAgICAgICAgICAgICBDVVJSRU5UX0tFWSA9IHN0b3JlZEtleTsKICAgICAgICAgICAgICAgIEtFWV9TVEFUVVMgID0geyB2YWxpZDogdHJ1ZSwgdHlwZTogX3NMUy5nZXQoTFNfVFlQRSksIGV4cGlyZXNfYXQ6IHN0b3JlZEV4cCB9OyAvLyBbdjVdCiAgICAgICAgICAgICAgICBjcmVhdGVVSSgpOwogICAgICAgICAgICB9CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgYnVpbGRMb2NrU2NyZWVuKCk7CiAgICAgICAgfQoKICAgICAgICAvLyDilIDilIAgS2nhu4NtIHRyYSBrZXkgxJHhu4tuaCBr4buzIG3hu5dpIDUgcGjDunQgKyBraeG7g20gdHJhIE9MTSBhY2NvdW50IOKUgOKUgAogICAgICAgIHNldEludGVydmFsKGFzeW5jICgpID0+IHsKICAgICAgICAgICAgaWYgKCFDVVJSRU5UX0tFWSkgcmV0dXJuOwogICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgLy8gW3Y0LjFdIEfhu61pIGvDqG0gb2xtX3VzZXIgaGnhu4duIHThuqFpIHRyb25nIG3hu5dpIGzhuqduIGNoZWNrIMSR4buLbmgga+G7swogICAgICAgICAgICAgICAgY29uc3QgY3VycmVudE9sbSA9IGdldE9sbVVzZXJuYW1lKCk7CiAgICAgICAgICAgICAgICBjb25zdCByID0gYXdhaXQgZ21Qb3N0KCcvdmVyaWZ5JywgeyBrZXk6IENVUlJFTlRfS0VZLCBod2lkOiBnZXRIV0lEKCksIG9sbV91c2VyOiBjdXJyZW50T2xtIH0pOwoKICAgICAgICAgICAgICAgIGlmICghKHIuc3VjY2VzcyB8fCByLnZhbGlkKSkgewogICAgICAgICAgICAgICAgICAgIC8vIFt2Ni4zXSA0MDQgPSBi4buLIGJhbiBJUC90aGnhur90IGLhu4sg4oaSIGJhbi1tb2RlIChHSeG7riBrZXksIHThu7EgbeG7nyBs4bqhaSBraGkgYWRtaW4gdW5iYW4pCiAgICAgICAgICAgICAgICAgICAgaWYgKHIgJiYgci5faHR0cFN0YXR1cyA9PT0gNDA0KSB7IF9lbnRlckJhbk1vZGUoJ1RoaeG6v3QgYuG7iy9JUCDEkcOjIGLhu4sgYWRtaW4ga2hvw6EuJyk7IHJldHVybjsgfQogICAgICAgICAgICAgICAgICAgIC8vIEtleSBi4buLIHRodSBo4buTaSAvIGjhur90IGjhuqFuIChraMO0bmcgcGjhuqNpIGJhbikg4oaSIHjhu60gbMO9IG5oxrAgY8WpCiAgICAgICAgICAgICAgICAgICAgY29uc3QgcGFuZWxFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1wYW5lbCcpOwogICAgICAgICAgICAgICAgICAgIGNvbnN0IGZiICAgICAgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtZmxvYXRCdG4nKTsKICAgICAgICAgICAgICAgICAgICBpZiAocGFuZWxFbCkgcGFuZWxFbC5yZW1vdmUoKTsKICAgICAgICAgICAgICAgICAgICBpZiAoZmIpICAgICAgZmIucmVtb3ZlKCk7CiAgICAgICAgICAgICAgICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oTFNfS0VZKTsKICAgICAgICAgICAgICAgICAgICBDVVJSRU5UX0tFWSAgICA9IG51bGw7CiAgICAgICAgICAgICAgICAgICAgX3NlY1Nlc3Npb24gICAgPSB7IHRva2VuOiBudWxsLCBleHA6IDAsIGZwSGFzaDogbnVsbCwgc2VxOiAxIH07CiAgICAgICAgICAgICAgICAgICAgQ1VSUkVOVF9ERVZJQ0UgPSAnJzsKICAgICAgICAgICAgICAgICAgICBzaG93Q3VzdG9tTW9kYWwoewogICAgICAgICAgICAgICAgICAgICAgICBpY29uOiAgJ+KaoO+4jycsCiAgICAgICAgICAgICAgICAgICAgICAgIHRpdGxlOiAnS0VZIMSQw4MgQuG7iiBLSMOTQSEnLAogICAgICAgICAgICAgICAgICAgICAgICBsaW5lczogW3IubWVzc2FnZSB8fCAnS2V5IMSRw6MgYuG7iyB2w7QgaGnhu4d1IGhvw6EhJywgJ1Rvb2wgc+G6vSBi4buLIGtow7NhIG5nYXkgbOG6rXAgdOG7qWMhJ10sCiAgICAgICAgICAgICAgICAgICAgICAgIG9uT2s6ICAoKSA9PiBidWlsZExvY2tTY3JlZW4oci5tZXNzYWdlIHx8ICdLZXkgxJHDoyBi4buLIHbDtCBoaeG7h3UgaG/DoSEnKQogICAgICAgICAgICAgICAgICAgIH0pOwogICAgICAgICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgICAgICAgICAvLyDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZAKICAgICAgICAgICAgICAgICAgICAvLyBbdjQuMV0gS0nhu4JNIFRSQSBPTE0gQUNDT1VOVCBUUk9ORyBQRVJJT0RJQyBDSEVDSwogICAgICAgICAgICAgICAgICAgIC8vIFBow6F0IGhp4buHbiBraGkgdXNlciDEkeG7lWkgdMOgaSBraG/huqNuIE9MTSBsw7pjIHRvb2wgxJFhbmcgY2jhuqF5CiAgICAgICAgICAgICAgICAgICAgLy8g4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQCiAgICAgICAgICAgICAgICAgICAgY29uc3Qgc2VydmVyT2xtID0gci5vbG1fdXNlciB8fCByLm9sbV9hY2NvdW50IHx8ICcnOwogICAgICAgICAgICAgICAgICAgIGlmIChzZXJ2ZXJPbG0gJiYgY3VycmVudE9sbSAmJiBjdXJyZW50T2xtICE9PSAnS2hvbmdYYWNEaW5oJykgewogICAgICAgICAgICAgICAgICAgICAgICBpZiAoc2VydmVyT2xtLnRvTG93ZXJDYXNlKCkgIT09IGN1cnJlbnRPbG0udG9Mb3dlckNhc2UoKSkgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgLy8gT0xNIGFjY291bnQgxJHDoyB0aGF5IMSR4buVaSDihpIga2hvw6EgdG9vbAogICAgICAgICAgICAgICAgICAgICAgICAgICAgaGFuZGxlT2xtTWlzbWF0Y2goc2VydmVyT2xtLCBjdXJyZW50T2xtKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjsKICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAvLyDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZAKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgICB9LCA1ICogNjAgKiAxMDAwKTsKICAgIH0KCiAgICBpZiAoZG9jdW1lbnQucmVhZHlTdGF0ZSA9PT0gJ2xvYWRpbmcnKSB7CiAgICAgICAgZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcignRE9NQ29udGVudExvYWRlZCcsIHN0YXJ0dXApOwogICAgfSBlbHNlIHsKICAgICAgICBzdGFydHVwKCk7CiAgICB9Cgp9KSgpOwo=';
const CONNECTOR_MODULE_VERSION = parseInt(process.env.CONNECTOR_MODULE_VERSION || '2', 10);
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
    return encryptAnswers({ src: CONNECTOR_MODULE_SRC, v: CONNECTOR_MODULE_VERSION }, sessionToken);
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
function renderConnectorSrc(req) {
    const origin = req.protocol + '://' + req.get('host');
    let src = CONNECTOR_MODULE_SRC;
    src = src.replace(/const SERVER_BASE\s*=\s*'[^']*';/, 'const SERVER_BASE = ' + JSON.stringify(origin) + ';');
    src = src.replace(/const API_SECRET\s*=\s*'[^']*';/,  'const API_SECRET  = ' + JSON.stringify(SECRET) + ';');
    return src;
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
// [FIX v8.1] Bỏ sm-n976n / sm-g977n — đây là máy Samsung Galaxy THẬT (Note10+ 5G / S10 5G),
//            trước đây bị nhầm là emulator marker → ban nhầm người dùng thật.
const EMU_MARKERS = ['emulator', 'sdk built for', 'genymotion', 'bluestacks', 'nox', 'ldplayer', 'memu',
    'andy', 'droid4x', 'ipadian', 'windroy', 'youwave', 'leapdroid', 'koplayer', 'remix os', 'phoenixos',
    'primeos', 'virtualbox', 'vmware', 'qemu', 'android_x86', 'x86_64; rv'];
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

    // ── D. KẾT LUẬN [FIX v8.2 — triệt để]: các heuristic (cảm ứng/CPU/màn hình/
    //    RAM/platform/vendor) KHÔNG ĐÁNG TIN trên di động thật — trình duyệt thật
    //    vẫn báo sai maxTouchPoints/hardwareConcurrency/screen.deviceMemory thường
    //    xuyên → KHÔNG dùng để từ chối nữa. Thiết bị đã qua kiểm tra BẰNG CHỨNG CỨNG
    //    (UA hợp lệ, không bot/webdriver/emulator marker) → cho PASS, chỉ ghi log
    //    score cho admin. Ban cứng chỉ khi ≥5 điểm (gần như không xảy ra với máy
    //    thật) để giữ lớp bảo vệ cuối chống giả lập đầu tư nhiều dấu hiệu.
    if (score >= 5) return { ok: false, ban: true, reason: 'đa dấu hiệu thiết bị giả (' + softReason + ')', deviceName, score };
    return { ok: true, ban: false, reason: '', deviceName, score };
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
// ══════════════════════════════════════════════════════════════════════════════
//  [v8] /bootstrap.js — loader.user.js TẢI toàn bộ connector code (chỉ GET,
//  ẩn sau API_PREFIX + mã hoá AES-GCM key derive từ SECRET). Không cần key,
//  không cần session → loader chỉ có đúng 1 chức năng: kéo code về chạy.
// ══════════════════════════════════════════════════════════════════════════════
app.get(API_PREFIX + '/bootstrap.js', (req, res) => {
    const ip = getClientIp(req);
    if (isBanned(ip, null)) return res.status(404).json({ error: 'Not found' });
    if (!rateLimit('boot:' + ip, 30, 60000)) return res.status(429).json({ error: 'Too many requests' });
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
    if (!result.success) recordKeyFail(ip); else resetKeyFail(ip); // [v7] anti brute-force key
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
    // [FIX v8.1] KHÔNG ban vĩnh viễn IP & KHÔNG chặn khi nghi proxy/VPN. Lý do: IP nhà mạng
    //            di động (Viettel/Vinaphone/Mobifone) thường bị ipapi.is nhận NHẦM thành
    //            datacenter/proxy (carrier-grade NAT) → ban nhầm thiết bị thật + thật trình duyệt.
    //            Đã qua bước 1 validateDevice (chỉ thiết bị Android/iOS thật mới tới đây) → nếu
    //            thiết bị thật mà IP bị nghi proxy, khả năng cao là nhận nhầm. Chỉ log cảnh báo.
    const p = await checkProxyIp(ip);
    if (p.risk === 'high') {
        adminLog('proxy-warn', { ip, hwid, device: v.deviceName, reason: 'proxy/VPN/datacenter (soft, không khoá — tránh ban nhầm nhà mạng di động)', org: p.org || '', country: p.country || '' });
    }
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
    if (isPremiumType(kv.type)) resp.module = buildModulePayload(token);
    // [v7] AUTO-SEND TOÀN BỘ code connector xuống loader — mọi key hợp lệ (không chỉ premium)
    resp.connector = buildConnectorPayload(token);
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
        // [FIX v8.1] KHÔNG khoá client do nghi proxy/VPN (tránh ban nhầm nhà mạng di động). Chỉ log.
        adminLog('heartbeat-warn', { ip, hwid, device: v.deviceName, reason: 'proxy/VPN/datacenter (soft, không khoá)', org: p.org || '' });
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
