'use strict';
const express = require('express');
const cheerio = require('cheerio');
const cors = require('cors');
const https = require('https');
const http = require('http');
const crypto = require('crypto');
const vm = require('vm');
const fs = require('fs');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3e3;
app.use(express.json({
  limit: '1mb',
  verify: (req, _res, buf) => {
    req.rawBody = buf;
  }
}));
app.use(express.urlencoded({
  extended: true,
  limit: '64kb'
}));
app.disable('x-powered-by');
app.disable('etag');
app.set('trust proxy', parseInt(process.env.TRUST_PROXY || '1', 10) || 1);
app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  res.setHeader('X-DNS-Prefetch-Control', 'off');
  res.removeHeader('X-Powered-By');
  res.setHeader('Server', 'cloudflare');
  res.setHeader('Vary', 'Origin');
  if (_req.path && _req.path.startsWith(ADMIN_PATH)) {
    res.setHeader('Content-Security-Policy', 'default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data:; frame-ancestors \'none\'; base-uri \'none\'');
  }
  next();
});
const CORS_ALLOWED_HOSTS = (process.env.CORS_ALLOW || '').split(',').map(x => x.trim()).filter(Boolean);
app.use(cors({
  origin: (origin, cb) => cb(null, true),
  methods: [ 'GET', 'POST', 'OPTIONS' ],
  allowedHeaders: [ 'Content-Type', 'X-Session', 'X-Fp-Hash', 'X-Seq', 'X-HWID', 'X-Ts', 'X-Nonce', 'X-Sign', 'X-Enc-V' ],
  credentials: false
}));
app.options(/.*/, cors());
app.use((req, res, next) => {
  if (req.method === 'POST' && !req.path.startsWith(API_PREFIX)) {
    const LEGACY = [ '/verify', '/attest', '/process', '/fire', '/code', '/heartbeat', '/lock-report', '/lock-status', '/ping', '/ansfile/decode' ];
    if (LEGACY.includes(req.path)) {
      adminLog('legacy-rewrite', {
        path: req.path,
        ip: getClientIp(req)
      });
      req.url = API_PREFIX + req.path;
    }
  }
  next();
});
const DEFAULT_SECRET = 'a7f3c9e1b2d48506fae1c7d3b9f0e2a4c6d8f1a3b5e7c9d0f2a4c6e8b1d3f5a7';
let SECRET = process.env.GODMODE_SECRET || DEFAULT_SECRET;
const BOOTSTRAP_PUBLIC_KEY = process.env.BOOTSTRAP_KEY || 'b7f2c91a4e6d8f03c5b7a291e4d68c0af53b2d91c6e480a7f1d2c5b6a4e809137';
function hmacHex(s) {
  return crypto.createHmac('sha256', SECRET).update(s).digest('hex');
}
function computeApiPrefix(sec) {
  return '/' + crypto.createHmac('sha256', sec).update('godmode:api:prefix:v4').digest('hex').slice(0, 12);
}
let API_PREFIX = computeApiPrefix(SECRET);
console.log('[SECURITY] Ẩn API prefix: ' + API_PREFIX + ' (client tự tính từ SECRET)');
if (SECRET === DEFAULT_SECRET) {
  console.error('[31m[SECURITY CRITICAL — v10] BAN DANG DUNG SECRET MAC DINH DA ROI ROI (co trong tat ca file dumper)! Dat env GODMODE_SECRET (64 hex ngau nhien) tren Vercel NGAY, va cap nhat API_SECRET trong loader Payload_v9.js cho khop.[0m');
  console.error('[31m[SECURITY] Key OLM-UPJO-GXYC-USLC-ER2O va HWID HW2334B90D da xuat hien trong dumper — xem xet revokle key do bang env BANNED_KEYS hoac admin panel.[0m');
}
if (process.env.NODE_ENV === 'production' && process.env.ADMIN_REQUIRE_SECURE === '1') {
  const problems = [];
  if (SECRET === DEFAULT_SECRET) problems.push('GODMODE_SECRET (đang mặc định)');
  if (!process.env.ADMIN_PASS_HASH && !process.env.ADMIN_PASS) problems.push('ADMIN_PASS / ADMIN_PASS_HASH (đang mặc định 120510@)');
  if (problems.length) {
    console.error('[FATAL SECURITY] Production thiếu: ' + problems.join(', ') + '. Từ chối khởi động.');
    process.exit(1);
  }
} else if (SECRET === DEFAULT_SECRET || !process.env.ADMIN_PASS_HASH && !process.env.ADMIN_PASS) {
  console.warn('[33m[SECURITY][v38.1] Đang dùng cấu hình mặc định (secret/admin pass). Đặt GODMODE_SECRET, ADMIN_PASS trước khi public.[0m');
}
const PAYLOAD_MODULE_VERSION = 3;
const PAYLOAD_MODULE_SRC = `\nvar SESSION=ctx.SESSION, addLog=ctx.addLog, forceGetMeta=ctx.forceGetMeta;\nvar SECRET_KEY_CS='1047823200';\nfunction decryptOLM_CS(base64Str){if(!base64Str)return null;try{var raw=atob(base64Str);var dec='';for(var i=0;i<raw.length;i++)dec+=String.fromCharCode(raw.charCodeAt(i)^SECRET_KEY_CS.charCodeAt(i%SECRET_KEY_CS.length));return decodeURIComponent(escape(dec));}catch(e){return null;}}\nfunction buildParamsCS(sq){var count=sq.count||4;if(sq.type===6){var orderArr=Array.from(Array(Math.max(count,15)),function(_,k){return k;});return {js:'',order_l:orderArr,order_r:orderArr};}return {js:'',order:Array.from(Array(count),function(_,k){return k;})};}function _wrongAnsCS(sq){if(!sq)return[''];if(sq.type===4)return[''];if(sq.type===13)return(sq.ans||[]).map(function(a){return a==='1'?'0':'1';});if(sq.type===6){var n=Math.max(sq.count||(sq.ans||[]).length||2,2);return(sq.ans||[]).map(function(_,idx){return String((idx+1)%n);});}var c=parseInt(sq.ans&&sq.ans[0],10);var n2=Math.max(sq.count||4,2);return[String((isNaN(c)?0:c+1)%n2)];}\nfunction findCorrectInfoCS(node){var results=[];function traverse(n){if(!n)return;var subQ_ID=n.id||n._id||(n.props?n.props.id:null);if((n.type==='fillme-input'&&n.content)||(typeof n.content==='string'&&n.content.includes('data-accept='))){if(typeof n.content==='string'&&n.content.includes('data-accept=')){var regex=/data-accept="([^"]+)"/g;var match;while((match=regex.exec(n.content))!==null)results.push({type:4,ans:[match[1]],count:1,skill:n.id_skill,subId:subQ_ID||('raw_'+Math.random()),isText:true});}else if(typeof n.content==='string'){results.push({type:4,ans:[n.content],count:1,skill:n.id_skill,subId:subQ_ID,isText:true});}return;}if(n.type==='olm-list'||(Array.isArray(n.children)&&n.children.length>0)){var options=Array.isArray(n.children)?n.children:null;if(options&&(n.name==='true-false'||n.listType==='true-false')){results.push({type:13,ans:options.map(function(o){return (o.correct==true||o.correct==='true'||o.correct==1)?'1':'0';}),count:options.length,skill:n.id_skill,subId:subQ_ID});return;}if(options&&(n.name==='link-list'||n.listType==='matching')){results.push({type:6,ans:options.map(function(_,idx){return idx.toString();}),count:options.length,skill:n.id_skill,subId:subQ_ID});return;}if(options&&options.some(function(c){return c.correct!==undefined;})){var trueIndex=options.findIndex(function(o){return o.correct==true||o.correct==='true'||o.correct==1;});results.push({type:1,ans:[(trueIndex===-1?0:trueIndex).toString()],count:options.length,skill:n.id_skill,subId:subQ_ID});return;}}if(Array.isArray(n.children))n.children.forEach(traverse);else if(Array.isArray(n.questions))n.questions.forEach(traverse);else if(Array.isArray(n.items))n.items.forEach(traverse);else if(Array.isArray(n.list))n.list.forEach(traverse);else if(n.root)traverse(n.root);}var contentToParse=node.json_content||node.content;if(typeof contentToParse==='string'&&!contentToParse.trim().startsWith('{')&&!contentToParse.trim().startsWith('[')){var decoded=decryptOLM_CS(contentToParse);if(decoded)contentToParse=decoded;}try{traverse(typeof contentToParse==='string'?JSON.parse(contentToParse):contentToParse);}catch(_){traverse(node);}if(results.length===0)results.push({type:1,ans:['0'],count:4,skill:null,subId:null});return results;}\nreturn async function(){\nforceGetMeta();\nif(!SESSION.meta.id_user||!SESSION.meta.id_cate){addLog('❌ Thiếu ID user/cate: user='+(SESSION.meta.id_user||'?')+' cate='+(SESSION.meta.id_cate||'?'),'err');return false;}\nvar totalPackages=SESSION.raw_questions.length;\nif(totalPackages===0){addLog('❌ Chưa có câu hỏi để nộp!','err');return false;}\nvar timeInput=document.getElementById('tl-god-time');\nvar timeStr=timeInput?timeInput.value.toString().trim():'10.00';\nvar tp=timeStr.split('.');\nvar userMins=parseInt(tp[0])||0;\nvar uss=tp[1]||'0';if(uss.length===1)uss+='0';\nvar userSecs=parseInt(uss.substring(0,2));\nvar calcSeconds=(userMins*60)+userSecs;\nif(calcSeconds<30)calcSeconds=120;\nvar modeSel=document.getElementById('tl-modeSelect');\nvar mode=modeSel?modeSel.value:'practice';\nvar isExam=mode==='exam',isVideo=mode==='video';\nvar tgtScoreSel=document.getElementById('tl-god-target-score');\nvar tgtScore=tgtScoreSel?Math.min(10,Math.max(7,parseFloat(tgtScoreSel.value)||10)):10;\nvar tgtRatio=tgtScore/10;\nvar tgtCorrectCount=Math.round(totalPackages*tgtRatio);\nvar wrongSet=new Set();for(var wi=tgtCorrectCount;wi<totalPackages;wi++)wrongSet.add(wi);\nvar now=Math.floor(Date.now()/1000);\nvar totalSeconds,timeInit;\ntotalSeconds=calcSeconds;timeInit=now-totalSeconds;\nvar params=new URLSearchParams();\nvar fakeLog=[];\nvar max_tn_score=0,tn_score_calc=0,tl_max_calc=0;\nSESSION.raw_questions.forEach(function(q,i){\nvar subQuestions=findCorrectInfoCS(q);\nvar sub_count=subQuestions.length;\nvar is_tl=(q.q_type==18||q.type==18||q.q_type==11);\nvar final_score=sub_count;\nif(q.score!==undefined&&q.score!==null&&q.score!=='')final_score=parseFloat(q.score);\nelse if(q.point!==undefined&&q.point!==null&&q.point!=='')final_score=parseFloat(q.point);\nvar makeWrong=(tgtScore<10&&wrongSet.has(i));\nif(!isVideo){var _essayQ=(q.q_type==18||q.type==18||q.q_type==11);params.append('quiz_list[]',q.id||q._id);params.append('score_list['+(q.id||q._id)+']',(makeWrong&&!_essayQ)?0:final_score);}\nvar skillIDs=[].concat(Array.from(new Set(subQuestions.map(function(sq){return sq.skill;}).filter(function(s){return s!=null;}))));\nif(!isVideo)skillIDs.forEach(function(s){params.append('correct_skill[]',s);});\nif(isVideo||isExam){\nif(is_tl&&isExam){tl_max_calc+=final_score;fakeLog.push({answer:JSON.stringify(['Học sinh đã làm phần tự luận trên máy.']),label:[''],params:'{"js":"","order":[0]}',correct_skill:[],wrong_skill:[],type:[18],result:[0],idq:parseInt(q.id||q._id),score:final_score,chk:0});}\nelse{\nmax_tn_score+=final_score;if(!makeWrong)tn_score_calc+=final_score;\nvar ans_list=[],type_list=[],prs_list=[],resArr=[],mresult=[],listIdq=[],lbl_list=[];\nfor(var j=0;j<sub_count;j++){var sq=subQuestions[j];ans_list.push(JSON.stringify(makeWrong?_wrongAnsCS(sq):((sq.type===4||sq.type===13||sq.type===6)?sq.ans:(sq.ans[0]||'0'))));type_list.push(sq.type||1);prs_list.push(JSON.stringify(buildParamsCS(sq)));resArr.push(makeWrong?0:1);mresult.push([makeWrong?0:1]);listIdq.push(sq.subId&&sq.subId.toString().length>5?sq.subId:'q'+j);var lbl='';if(!makeWrong&&sq.ans.length===1&&!isNaN(sq.ans[0])&&sq.type!==4&&sq.type!==13)lbl=['A','B','C','D','E'][parseInt(sq.ans[0])]||'';lbl_list.push(lbl);}\nvar logItem={answer:JSON.stringify(ans_list),label:sub_count===1?lbl_list:[],labels:lbl_list,params:sub_count===1?prs_list[0]:JSON.stringify({js:'',prs:prs_list,order:Array.from(Array(sub_count).keys())}),correct_skill:makeWrong?[]:skillIDs,wrong_skill:makeWrong?skillIDs:[],type:type_list,result:resArr,mresult:mresult,idq:parseInt(q.id||q._id),score:makeWrong?0:final_score};\nif(isExam){if(!makeWrong)logItem.chk=1;if(sub_count>1)logItem.list_idq=listIdq;}\nif(isVideo){logItem.marker=q.marker||(i+1);logItem.id=(q.id||q._id).toString();}\nfakeLog.push(logItem);\n}\n}else{\nvar qpa=[],apa=[];\nsubQuestions.forEach(function(sq){qpa.push(JSON.stringify(buildParamsCS(sq)));apa.push(JSON.stringify(makeWrong?_wrongAnsCS(sq):sq.ans));});\nfakeLog.push({q_params:JSON.stringify(qpa),a_params:JSON.stringify(apa),result:makeWrong?0:1,correct:makeWrong?0:1,wrong:makeWrong?1:0,a_index:i,time_spent:Math.max(5,Math.round((totalSeconds/Math.max(1,totalPackages))*(0.55+Math.random()*0.8)))});\n}\n});\nparams.append('id_cate',SESSION.meta.id_cate);\nparams.append('id_courseware',SESSION.meta.id_courseware||SESSION.meta.id_cate);\nparams.append('id_user',SESSION.meta.id_user);\nparams.append('id_grade',window.grade||window.id_grade||'10');\nif(SESSION.meta.id_school)params.append('id_school',SESSION.meta.id_school);\nif(SESSION.meta.id_group)params.append('id_group',SESSION.meta.id_group);\nparams.append('type_vip','530');params.append('time_stored','0');params.append('date_end',now);\nparams.append('data_log',JSON.stringify(fakeLog));\nif(isVideo){var vl=SESSION.video_length||900;params.append('type','5');params.append('type_exam','0');params.append('total_time',vl);params.append('current_time',vl);params.append('time_spent',totalSeconds+2);params.append('score_10',tgtScore.toString());params.append('totalq',totalPackages);params.append('score',tn_score_calc);params.append('max_score',max_tn_score);params.append('answered',totalPackages);params.append('correct',tgtCorrectCount);params.append('count_problems',totalPackages);params.append('percent',Math.round(tgtScore*10).toString());params.append('pscore',tgtScore.toString());params.append('score_status',tgtScore.toString());var vLog={};vLog[timeInit]='start';vLog[timeInit+1]='start';vLog[timeInit+10]='reload';params.append('log',JSON.stringify(vLog));}\nelse if(isExam){params.append('time_init',timeInit);params.append('time_spent',totalSeconds);params.append('total_time',totalSeconds);params.append('current_time',totalSeconds);params.append('score',tn_score_calc);params.append('max_score',max_tn_score+tl_max_calc);params.append('tn_score',tn_score_calc);params.append('type_exam','1');params.append('correct',tn_score_calc);params.append('wrong',max_tn_score-tn_score_calc);params.append('name_user','');params.append('tl_score','0');params.append('times','0');params.append('iframe','false');var curT=timeInit+Math.floor(totalSeconds*0.1);var totalQs=SESSION.raw_questions.length;var usableTime=Math.max(10,totalSeconds-Math.floor(totalSeconds*0.1)-10);var baseInterval=usableTime/(totalQs||1);for(var c=0;c<totalQs;c++){curT+=Math.floor(baseInterval*(0.7+Math.random()*0.6));if(curT>=timeInit+totalSeconds)curT=timeInit+totalSeconds-2;params.append('choose_log['+c+'][ind]',c);params.append('choose_log['+c+'][t]',Math.floor(curT));params.append('choose_log['+c+'][l]',c+1);}}\nelse{params.append('time_init',timeInit);params.append('time_spent',totalSeconds);params.append('time_elapsed',totalSeconds);params.append('total_time',totalSeconds);params.append('current_time',totalSeconds);params.append('score',Math.round(tgtScore*10).toString());params.append('score_10',tgtScore.toString());params.append('star',Math.round(tgtScore*2).toString());params.append('theta','0');params.append('max_score','100');params.append('answered',totalPackages);params.append('correct',tgtCorrectCount);params.append('wrong',(totalPackages-tgtCorrectCount).toString());params.append('missed','0');params.append('count_problems',totalPackages);params.append('type','3');params.append('type_exam','0');var pLog={};pLog[timeInit]='start';pLog[timeInit+1]='start';params.append('log',JSON.stringify(pLog));}\nparams.append('count_redo','0');params.append('ended','1');params.append('save_star','1');\ntry{\naddLog('📤 Đang nộp bài lên OLM...','info');\nvar csrf=SESSION.meta.csrf_token||(document.querySelector('meta[name="csrf-token"]')&&document.querySelector('meta[name="csrf-token"]').getAttribute('content'))||'';\nvar response=await fetch('/course/teacher-static',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded; charset=UTF-8','x-csrf-token':csrf,'x-requested-with':'XMLHttpRequest'},body:params.toString()});\nif(!response.ok){addLog('❌ OLM trả lỗi HTTP '+response.status,'err');return false;}\nreturn true;\n}catch(err){addLog('❌ Lỗi kết nối OLM: '+err.message,'err');return false;}\n};\n`;
function buildModulePayload(sessionToken, key, hwid) {
  return encryptAnswers({
    src: watermarkSrc(PAYLOAD_MODULE_SRC, key, hwid),
    v: PAYLOAD_MODULE_VERSION
  }, sessionToken);
}
const CONNECTOR_MODULE_EMBEDDED_B64 = 'Y29uc3QgU0VSVkVSX0JBU0UgPSAnaHR0cHM6Ly9tb2RnYW1lLnZlcmNlbC5hcHAnOwpjb25zdCBBUElfU0VDUkVUID0gJ2E3ZjNjOWUxYjJkNDg1MDZmYWUxYzdkM2I5ZjBlMmE0YzZkOGYxYTNiNWU3YzlkMGYyYTRjNmU4YjFkM2Y1YTcnOwpjb25zdCBSRVFVRVNUX0VOQ1JZUFRJT04gPSBmYWxzZTsKKGZ1bmN0aW9uKCkgewogICd1c2Ugc3RyaWN0JzsKICBmdW5jdGlvbiBfbmF0aXZlWGhyKGQpIHsKICAgIHJldHVybiBuZXcgUHJvbWlzZShmdW5jdGlvbihyZXNvbHZlLCByZWplY3QpIHsKICAgICAgZCA9IGQgfHwge307CiAgICAgIHZhciBjdHJsID0gbnVsbCwgdG1vID0gbnVsbDsKICAgICAgdHJ5IHsKICAgICAgICBpZiAodHlwZW9mIEFib3J0Q29udHJvbGxlciAhPT0gJ3VuZGVmaW5lZCcpIGN0cmwgPSBuZXcgQWJvcnRDb250cm9sbGVyKCk7CiAgICAgICAgaWYgKGQudGltZW91dCkgdG1vID0gc2V0VGltZW91dChmdW5jdGlvbigpIHsKICAgICAgICAgIHRyeSB7IGlmIChjdHJsKSBjdHJsLmFib3J0KCk7IH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgICBpZiAodHlwZW9mIGQub250aW1lb3V0ID09PSAnZnVuY3Rpb24nKSB7IHRyeSB7IGQub250aW1lb3V0KHsgZXJyb3I6ICdUaW1lb3V0JyB9KTsgfSBjYXRjaCAoXykge30gfQogICAgICAgICAgcmVqZWN0KG5ldyBFcnJvcignVGltZW91dCcpKTsKICAgICAgICB9LCBkLnRpbWVvdXQpOwogICAgICAgIHZhciBvcHRzID0geyBtZXRob2Q6IGQubWV0aG9kIHx8ICdHRVQnLCBoZWFkZXJzOiBkLmhlYWRlcnMgfHwge30sIGNyZWRlbnRpYWxzOiAnb21pdCcsIGNhY2hlOiAnbm8tc3RvcmUnLCBtb2RlOiAnY29ycycgfTsKICAgICAgICBpZiAoY3RybCkgb3B0cy5zaWduYWwgPSBjdHJsLnNpZ25hbDsKICAgICAgICBpZiAoZC5kYXRhICE9PSB1bmRlZmluZWQgJiYgZC5kYXRhICE9PSBudWxsKSBvcHRzLmJvZHkgPSBkLmRhdGE7CiAgICAgICAgZmV0Y2goZC51cmwsIG9wdHMpLnRoZW4oZnVuY3Rpb24ocikgewogICAgICAgICAgaWYgKHRtbykgY2xlYXJUaW1lb3V0KHRtbyk7CiAgICAgICAgICByZXR1cm4gci50ZXh0KCkudGhlbihmdW5jdGlvbih0KSB7CiAgICAgICAgICAgIHZhciBvdXQgPSB7IHN0YXR1czogci5zdGF0dXMsIHJlc3BvbnNlVGV4dDogdCwgcmVzcG9uc2U6IHQsIHJlYWR5U3RhdGU6IDQsIGZpbmFsVXJsOiByLnVybCB9OwogICAgICAgICAgICBpZiAodHlwZW9mIGQub25sb2FkID09PSAnZnVuY3Rpb24nKSB7IHRyeSB7IGQub25sb2FkKG91dCk7IH0gY2F0Y2ggKF8pIHt9IH0KICAgICAgICAgICAgcmVzb2x2ZShvdXQpOwogICAgICAgICAgfSk7CiAgICAgICAgfSkuY2F0Y2goZnVuY3Rpb24oZXJyKSB7CiAgICAgICAgICBpZiAodG1vKSBjbGVhclRpbWVvdXQodG1vKTsKICAgICAgICAgIGNvbnN0IG1zZyA9IFN0cmluZyhlcnIgJiYgZXJyLm1lc3NhZ2UgfHwgZXJyKTsKICAgICAgICAgIGlmICh0eXBlb2YgZC5vbmVycm9yID09PSAnZnVuY3Rpb24nKSB7IHRyeSB7IGQub25lcnJvcih7IGVycm9yOiBtc2cgfSk7IH0gY2F0Y2ggKF8pIHt9IH0KICAgICAgICAgIHJlamVjdChuZXcgRXJyb3IobXNnKSk7CiAgICAgICAgfSk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIGlmICh0bW8pIGNsZWFyVGltZW91dCh0bW8pOwogICAgICAgIGNvbnN0IG1zZzIgPSBTdHJpbmcoZXJyICYmIGVyci5tZXNzYWdlIHx8IGVycik7CiAgICAgICAgaWYgKHR5cGVvZiBkLm9uZXJyb3IgPT09ICdmdW5jdGlvbicpIHsgdHJ5IHsgZC5vbmVycm9yKHsgZXJyb3I6IG1zZzIgfSk7IH0gY2F0Y2ggKF8pIHt9IH0KICAgICAgICByZWplY3QobmV3IEVycm9yKG1zZzIpKTsKICAgICAgfQogICAgfSk7CiAgfQogIGZ1bmN0aW9uIF9yZXNvbHZlWGhyKCkgewogICAgdHJ5IHsgaWYgKHR5cGVvZiBHTV94bWxodHRwUmVxdWVzdCA9PT0gJ2Z1bmN0aW9uJykgcmV0dXJuIEdNX3htbGh0dHBSZXF1ZXN0OyB9IGNhdGNoIChfKSB7fQogICAgdHJ5IHsgaWYgKHR5cGVvZiBHTSAhPT0gJ3VuZGVmaW5lZCcgJiYgR00gJiYgdHlwZW9mIEdNLnhtbEh0dHBSZXF1ZXN0ID09PSAnZnVuY3Rpb24nKSByZXR1cm4gZnVuY3Rpb24oZCkgeyByZXR1cm4gR00ueG1sSHR0cFJlcXVlc3QoZCk7IH07IH0gY2F0Y2ggKF8pIHt9CiAgICB0cnkgeyBpZiAodHlwZW9mIHdpbmRvdyAhPT0gJ3VuZGVmaW5lZCcgJiYgdHlwZW9mIHdpbmRvdy5fX3RsRmV0Y2hYaHIgPT09ICdmdW5jdGlvbicpIHJldHVybiB3aW5kb3cuX190bEZldGNoWGhyOyB9IGNhdGNoIChfKSB7fQogICAgcmV0dXJuIF9uYXRpdmVYaHI7CiAgfQogIHZhciBfeGhySW1wbCA9IF9yZXNvbHZlWGhyKCk7CiAgZnVuY3Rpb24gX3hockNhbGwob3B0cykgewogICAgdHJ5IHsgcmV0dXJuIF94aHJJbXBsKG9wdHMpOyB9IGNhdGNoIChfKSB7IHJldHVybiBfbmF0aXZlWGhyKG9wdHMpOyB9CiAgfQogIGNvbnN0IExTX0tFWSA9ICdfdGxfY29ubl9rZXknOwogIGNvbnN0IExTX1RZUEUgPSAnX3RsX2Nvbm5fdHlwZSc7CiAgY29uc3QgTFNfRVhQID0gJ190bF9jb25uX2V4cCc7CiAgY29uc3QgTFNfVEhFTUUgPSAnX3RpZXBfdGhlbWUnOwogIGxldCBDVVJSRU5UX0tFWSA9IG51bGw7CiAgbGV0IEtFWV9TVEFUVVMgPSB7CiAgICB2YWxpZDogZmFsc2UsCiAgICB0eXBlOiBudWxsLAogICAgZXhwaXJlc19hdDogbnVsbAogIH07CiAgbGV0IENVUlJFTlRfREVWSUNFID0gJyc7CiAgY29uc3QgU0VTU0lPTiA9IHsKICAgIHJhd19xdWVzdGlvbnM6IFtdLAogICAgbWV0YTogewogICAgICBpZF91c2VyOiBudWxsLAogICAgICBpZF9jYXRlOiBudWxsLAogICAgICBpZF9jb3Vyc2V3YXJlOiBudWxsLAogICAgICBpZF9zY2hvb2w6IG51bGwsCiAgICAgIGlkX2dyb3VwOiBudWxsLAogICAgICBjc3JmX3Rva2VuOiBudWxsLAogICAgICBzdWJqZWN0X25hbWU6IG51bGwsCiAgICAgIGV4ZXJjaXNlX3RpdGxlOiBudWxsLAogICAgICBzdWJqZWN0X2lkOiBudWxsCiAgICB9LAogICAgYXV0b19tb2RlOiAncHJhY3RpY2UnLAogICAgdmlkZW9fbGVuZ3RoOiA5MDAsCiAgICBiYW5rQW5zd2VyczogW10sCiAgICBhbnNGaWxlQW5zd2VyczogW10KICB9OwogIGxldCBfbGFzdE9sbVVzZXIgPSAnJzsKICBmdW5jdGlvbiBfc2V0UUNvdW50KG4pIHsKICAgIHRyeSB7CiAgICAgIGNvbnN0IGVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLXFjb3VudCcpOwogICAgICBpZiAoZWwpIGVsLnRleHRDb250ZW50ID0gU3RyaW5nKG4gfHwgMCk7CiAgICB9IGNhdGNoIChfKSB7fQogIH0KICBmdW5jdGlvbiBfcmVmcmVzaFFDb3VudCgpIHsKICAgIHRyeSB7CiAgICAgIGNvbnN0IHJhdyA9IChTRVNTSU9OLnJhd19xdWVzdGlvbnMgfHwgW10pLmxlbmd0aDsKICAgICAgY29uc3QgYmFuayA9IChTRVNTSU9OLmJhbmtBbnN3ZXJzIHx8IFtdKS5sZW5ndGg7CiAgICAgIGNvbnN0IGFuc2YgPSAoU0VTU0lPTi5hbnNGaWxlQW5zd2VycyB8fCBbXSkubGVuZ3RoOwogICAgICBfc2V0UUNvdW50KHJhdyB8fCBNYXRoLm1heChiYW5rLCBhbnNmKSB8fCAwKTsKICAgIH0gY2F0Y2ggKF8pIHt9CiAgfQogIHNldEludGVydmFsKF9yZWZyZXNoUUNvdW50LCAyNTAwKTsKICBsZXQgX2JhbmtGYWxsYmFja1RpbWVyID0gbnVsbDsKICBsZXQgX2JhbmtSZXRyeSA9IDA7CiAgbGV0IENVUlJFTlRfVEhFTUUgPSBsb2NhbFN0b3JhZ2UuZ2V0SXRlbShMU19USEVNRSkgfHwgJ2RlZmF1bHQnOwogIGZ1bmN0aW9uIGlzUHJlbWl1bUtleSgpIHsKICAgIGNvbnN0IHQgPSAoS0VZX1NUQVRVUy50eXBlIHx8IF9zTFMuZ2V0KExTX1RZUEUpIHx8ICcnKS50b1N0cmluZygpLnRvVXBwZXJDYXNlKCk7CiAgICByZXR1cm4gdCA9PT0gJ1BSRU1JVU0nIHx8IHQgPT09ICdWSVAnIHx8IHQgPT09ICdVTkxJTUlURUQnOwogIH0KICBmdW5jdGlvbiBoYW5kbGVPbG1NaXNtYXRjaChzZXJ2ZXJPbG0sIGN1cnJlbnRPbG0pIHsKICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKExTX0tFWSk7CiAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShMU19UWVBFKTsKICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKExTX0VYUCk7CiAgICBDVVJSRU5UX0tFWSA9IG51bGw7CiAgICBLRVlfU1RBVFVTID0gewogICAgICB2YWxpZDogZmFsc2UsCiAgICAgIHR5cGU6IG51bGwsCiAgICAgIGV4cGlyZXNfYXQ6IG51bGwKICAgIH07CiAgICBfc2VjU2Vzc2lvbiA9IHsKICAgICAgdG9rZW46IG51bGwsCiAgICAgIGV4cDogMCwKICAgICAgZnBIYXNoOiBudWxsLAogICAgICBzZXE6IDEKICAgIH07CiAgICBDVVJSRU5UX0RFVklDRSA9ICcnOwogICAgY29uc3QgcGFuZWxFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1wYW5lbCcpOwogICAgY29uc3QgZmIgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtZmxvYXRCdG4nKTsKICAgIGlmIChwYW5lbEVsKSBwYW5lbEVsLnJlbW92ZSgpOwogICAgaWYgKGZiKSBmYi5yZW1vdmUoKTsKICAgIHNob3dDdXN0b21Nb2RhbCh7CiAgICAgIGljb246ICfwn5qrJywKICAgICAgdGl0bGU6ICdUw4BJIEtIT+G6ok4gT0xNIEtIw5RORyBLSOG7mlAhJywKICAgICAgbGluZXM6IFsgYEtleSDEkcaw4bujYyDEkcSDbmcga8O9IGNobyB0w6BpIGtob+G6o246IDxiPiR7c2VydmVyT2xtfTwvYj5gLCBgVMOgaSBraG/huqNuIE9MTSBoaeG7h24gdOG6oWk6IDxiPiR7Y3VycmVudE9sbX08L2I+YCwgYOKaoO+4jyBWdWkgbMOybmcgxJHEg25nIG5o4bqtcCDEkcO6bmcgdMOgaSBraG/huqNuIE9MTSDEkeG7gyBz4butIGThu6VuZyBrZXkgbsOgeSxgLCBgaG/hurdjIGxpw6puIGjhu4cgYWRtaW4gxJHhu4MgxJHGsOG7o2MgaOG7lyB0cuG7oyFgIF0sCiAgICAgIG9uT2s6ICgpID0+IGJ1aWxkTG9ja1NjcmVlbign4pqg77iPIFTDoGkga2hv4bqjbiBPTE0ga2jDtG5nIGto4bubcCB24bubaSBrZXkgxJHDoyDEkcSDbmcga8O9IScpCiAgICB9KTsKICB9CiAgZnVuY3Rpb24gZ2V0VGhlbWVDb2xvcnModGhlbWUpIHsKICAgIGNvbnN0IFQgPSB7CiAgICAgIGRlZmF1bHQ6IHsKICAgICAgICBjMTogJyMwMGYyZmUnLAogICAgICAgIGMyOiAnIzRmYWNmZScsCiAgICAgICAgYmdPdmVybGF5OiAncmdiYSgxMywxNywyMywwLjk1KScsCiAgICAgICAgYmdQYW5lbDogJ3JnYmEoMTMsMTcsMjMsMC44OCknLAogICAgICAgIGJvcmRlcjogJ3JnYmEoMCwyNDIsMjU0LDAuMiknLAogICAgICAgIGJvcmRlclN0cm9uZzogJ3JnYmEoMCwyNDIsMjU0LDAuMyknLAogICAgICAgIGJvcmRlclN1YnRsZTogJ3JnYmEoMCwyNDIsMjU0LDAuMTIpJywKICAgICAgICBoZWFkZXJCZzogJ2xpbmVhci1ncmFkaWVudCgxMzVkZWcscmdiYSgwLDI0MiwyNTQsMC4wNykscmdiYSg3OSwxNzIsMjU0LDAuMDQpKScsCiAgICAgICAgZ2xvd0NvbG9yOiAncmdiYSgwLDI0MiwyNTQsMC40NSknLAogICAgICAgIGdsb3dTdHJvbmc6ICdyZ2JhKDAsMjQyLDI1NCwwLjcpJywKICAgICAgICBnbG93TWlkOiAncmdiYSgwLDI0MiwyNTQsMC4yNSknLAogICAgICAgIGdsb3dTdWJ0bGU6ICdyZ2JhKDAsMjQyLDI1NCwwLjA4KScsCiAgICAgICAgZ2xvd1B1bHNlOiAncmdiYSgwLDI0MiwyNTQsMC41NSknLAogICAgICAgIGlucHV0Qm9yZGVyOiAncmdiYSgwLDI0MiwyNTQsMC40KScsCiAgICAgICAgaW5wdXRDb2xvcjogJyMwMGYyZmUnLAogICAgICAgIGZsb2F0R3JhZGllbnQ6ICdsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLCMwMGYyZmUsIzRmYWNmZSknLAogICAgICAgIGJyYW5kR3JhZGllbnQ6ICdsaW5lYXItZ3JhZGllbnQoOTBkZWcsIzAwZjJmZSwjNGZhY2ZlLCMwMGYyZmUpJywKICAgICAgICBzdGF0dXNCb3JkZXI6ICdyZ2JhKDAsMjMwLDEyMCwwLjI1KScsCiAgICAgICAgc3RhdHVzQmc6ICdyZ2JhKDAsMjMwLDEyMCwwLjA0KScsCiAgICAgICAgcGFuZWxJbnNldDogJ3JnYmEoMCwyNDIsMjU0LDAuMDgpJywKICAgICAgICBzZWxlY3RCb3JkZXI6ICdyZ2JhKDAsMjQyLDI1NCwwLjIpJywKICAgICAgICBjb25zb2xlQm9yZGVyOiAncmdiYSgwLDI0MiwyNTQsMC4xMiknLAogICAgICAgIGZ4Q1NTOiAnJywKICAgICAgICBwYW5lbEV4dHJhOiAnJywKICAgICAgICB0aGVtZUxhYmVsOiAn8J+UtSBN4bq3YyDEkOG7i25oJywKICAgICAgICBwcmV2aWV3Qmc6ICdsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLCMwMDE1MjAsIzAwZjJmZTU1KScsCiAgICAgICAgcHJldmlld0JvcmRlcjogJ3JnYmEoMCwyNDIsMjU0LDAuNSknLAogICAgICAgIHByZXZpZXdUZXh0OiAnIzAwZjJmZScKICAgICAgfSwKICAgICAgZ3JheTogewogICAgICAgIGMxOiAnI2UwZTBlMCcsCiAgICAgICAgYzI6ICcjYTBhMGEwJywKICAgICAgICBiZ092ZXJsYXk6ICdyZ2JhKDEwLDEwLDEwLDAuOTcpJywKICAgICAgICBiZ1BhbmVsOiAncmdiYSgyMCwyMCwyMCwwLjk0KScsCiAgICAgICAgYm9yZGVyOiAncmdiYSgyMDAsMjAwLDIwMCwwLjE4KScsCiAgICAgICAgYm9yZGVyU3Ryb25nOiAncmdiYSgyMzAsMjMwLDIzMCwwLjMpJywKICAgICAgICBib3JkZXJTdWJ0bGU6ICdyZ2JhKDE3MCwxNzAsMTcwLDAuMSknLAogICAgICAgIGhlYWRlckJnOiAnbGluZWFyLWdyYWRpZW50KDEzNWRlZyxyZ2JhKDEyMCwxMjAsMTIwLDAuMTIpLHJnYmEoNjAsNjAsNjAsMC4wNSkpJywKICAgICAgICBnbG93Q29sb3I6ICdyZ2JhKDIxMCwyMTAsMjEwLDAuMzUpJywKICAgICAgICBnbG93U3Ryb25nOiAncmdiYSgyMjAsMjIwLDIyMCwwLjYpJywKICAgICAgICBnbG93TWlkOiAncmdiYSgyMDAsMjAwLDIwMCwwLjIpJywKICAgICAgICBnbG93U3VidGxlOiAncmdiYSgxNjAsMTYwLDE2MCwwLjA3KScsCiAgICAgICAgZ2xvd1B1bHNlOiAncmdiYSgyMDAsMjAwLDIwMCwwLjQ1KScsCiAgICAgICAgaW5wdXRCb3JkZXI6ICdyZ2JhKDIwMCwyMDAsMjAwLDAuMzgpJywKICAgICAgICBpbnB1dENvbG9yOiAnI2Q4ZDhkOCcsCiAgICAgICAgZmxvYXRHcmFkaWVudDogJ2xpbmVhci1ncmFkaWVudCgxMzVkZWcsI2MwYzBjMCwjNjY2KScsCiAgICAgICAgYnJhbmRHcmFkaWVudDogJ2xpbmVhci1ncmFkaWVudCg5MGRlZywjYzBjMGMwLCNmZmZmZmYsI2QwZDBkMCwjYzBjMGMwKScsCiAgICAgICAgc3RhdHVzQm9yZGVyOiAncmdiYSgxNjAsMTYwLDE2MCwwLjIpJywKICAgICAgICBzdGF0dXNCZzogJ3JnYmEoNjAsNjAsNjAsMC4wNyknLAogICAgICAgIHBhbmVsSW5zZXQ6ICdyZ2JhKDIwMCwyMDAsMjAwLDAuMDcpJywKICAgICAgICBzZWxlY3RCb3JkZXI6ICdyZ2JhKDE5MCwxOTAsMTkwLDAuMiknLAogICAgICAgIGNvbnNvbGVCb3JkZXI6ICdyZ2JhKDE2MCwxNjAsMTYwLDAuMSknLAogICAgICAgIGZ4Q1NTOiBgXG4gICAgICAgICAgICAgICAgICAgICN0bC1jb25uLWZ4LWJhciB7IGhlaWdodDoycHg7IGJhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDkwZGVnLHRyYW5zcGFyZW50LHJnYmEoMjU1LDI1NSwyNTUsMC4wOCkscmdiYSgyNTUsMjU1LDI1NSwwLjU1KSxyZ2JhKDI1NSwyNTUsMjU1LDAuMDgpLHRyYW5zcGFyZW50KTsgYmFja2dyb3VuZC1zaXplOjMwMCUgMTAwJTsgYW5pbWF0aW9uOm1ldGFsU3dlZXAgMi44cyBsaW5lYXIgaW5maW5pdGU7IH1cbiAgICAgICAgICAgICAgICAgICAgQGtleWZyYW1lcyBtZXRhbFN3ZWVwIHsgMCV7YmFja2dyb3VuZC1wb3NpdGlvbjoxMDAlIDB9IDEwMCV7YmFja2dyb3VuZC1wb3NpdGlvbjotMjAwJSAwfSB9XG4gICAgICAgICAgICAgICAgICAgICN0bC1wYW5lbCB7IGJveC1zaGFkb3c6IDAgMCA2MHB4IHJnYmEoMCwwLDAsMC44NSksIDAgMCAzMHB4IHJnYmEoMTgwLDE4MCwxODAsMC4wNiksIGluc2V0IDAgMXB4IDAgcmdiYSgyNTUsMjU1LDI1NSwwLjA4KTsgfVxuICAgICAgICAgICAgICAgICAgICAjdGwtY29ubi1wYW5lbCB7IGJveC1zaGFkb3c6IDAgMCA2MHB4IHJnYmEoMCwwLDAsMC44NSksIGluc2V0IDAgMXB4IDAgcmdiYSgyNTUsMjU1LDI1NSwwLjA4KTsgfVxuICAgICAgICAgICAgICAgIGAsCiAgICAgICAgcGFuZWxFeHRyYTogJzxkaXYgaWQ9InRsLWNvbm4tZngtYmFyIj48L2Rpdj4nLAogICAgICAgIHRoZW1lTGFiZWw6ICfimqsgWMOhbSBC4bqhYycsCiAgICAgICAgcHJldmlld0JnOiAnbGluZWFyLWdyYWRpZW50KDEzNWRlZywjMWExYTFhLCM2NjYpJywKICAgICAgICBwcmV2aWV3Qm9yZGVyOiAncmdiYSgyMjAsMjIwLDIyMCwwLjQ1KScsCiAgICAgICAgcHJldmlld1RleHQ6ICcjZTBlMGUwJwogICAgICB9LAogICAgICBwaW5rOiB7CiAgICAgICAgYzE6ICcjZmY2ZWI0JywKICAgICAgICBjMjogJyNmZjE0OTMnLAogICAgICAgIGJnT3ZlcmxheTogJ3JnYmEoMTgsNCwxNCwwLjk3KScsCiAgICAgICAgYmdQYW5lbDogJ3JnYmEoMjYsNCwxOCwwLjkzKScsCiAgICAgICAgYm9yZGVyOiAncmdiYSgyNTUsMTEwLDE4MCwwLjIpJywKICAgICAgICBib3JkZXJTdHJvbmc6ICdyZ2JhKDI1NSwxMTAsMTgwLDAuMzgpJywKICAgICAgICBib3JkZXJTdWJ0bGU6ICdyZ2JhKDI1NSwxMTAsMTgwLDAuMTIpJywKICAgICAgICBoZWFkZXJCZzogJ2xpbmVhci1ncmFkaWVudCgxMzVkZWcscmdiYSgyNTUsMTEwLDE4MCwwLjA5KSxyZ2JhKDI1NSwyMCwxNDcsMC4wNCkpJywKICAgICAgICBnbG93Q29sb3I6ICdyZ2JhKDI1NSwxMTAsMTgwLDAuNDUpJywKICAgICAgICBnbG93U3Ryb25nOiAncmdiYSgyNTUsMTEwLDE4MCwwLjc1KScsCiAgICAgICAgZ2xvd01pZDogJ3JnYmEoMjU1LDExMCwxODAsMC4yMiknLAogICAgICAgIGdsb3dTdWJ0bGU6ICdyZ2JhKDI1NSwyMCwxNDcsMC4wNyknLAogICAgICAgIGdsb3dQdWxzZTogJ3JnYmEoMjU1LDExMCwxODAsMC41NSknLAogICAgICAgIGlucHV0Qm9yZGVyOiAncmdiYSgyNTUsMTEwLDE4MCwwLjQyKScsCiAgICAgICAgaW5wdXRDb2xvcjogJyNmZmIzZDknLAogICAgICAgIGZsb2F0R3JhZGllbnQ6ICdsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLCNmZjZlYjQsI2ZmMTQ5MyknLAogICAgICAgIGJyYW5kR3JhZGllbnQ6ICdsaW5lYXItZ3JhZGllbnQoOTBkZWcsI2ZmNmViNCwjZmZjY2U4LCNmZjE0OTMsI2ZmNmViNCknLAogICAgICAgIHN0YXR1c0JvcmRlcjogJ3JnYmEoMjU1LDExMCwxODAsMC4yKScsCiAgICAgICAgc3RhdHVzQmc6ICdyZ2JhKDI1NSwyMCwxNDcsMC4wNSknLAogICAgICAgIHBhbmVsSW5zZXQ6ICdyZ2JhKDI1NSwxMTAsMTgwLDAuMSknLAogICAgICAgIHNlbGVjdEJvcmRlcjogJ3JnYmEoMjU1LDExMCwxODAsMC4yKScsCiAgICAgICAgY29uc29sZUJvcmRlcjogJ3JnYmEoMjU1LDExMCwxODAsMC4xMiknLAogICAgICAgIGZ4Q1NTOiBgXG4gICAgICAgICAgICAgICAgICAgICN0bC1wYW5lbCB7IGFuaW1hdGlvbjpzYWt1cmFQYW5lbEdsb3cgM3MgZWFzZS1pbi1vdXQgaW5maW5pdGU7IH1cbiAgICAgICAgICAgICAgICAgICAgI3RsLWNvbm4tcGFuZWwgeyBhbmltYXRpb246c2FrdXJhUGFuZWxHbG93IDNzIGVhc2UtaW4tb3V0IGluZmluaXRlOyB9XG4gICAgICAgICAgICAgICAgICAgIEBrZXlmcmFtZXMgc2FrdXJhUGFuZWxHbG93IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIDAlLDEwMCV7IGJveC1zaGFkb3c6MCAwIDYwcHggcmdiYSgwLDAsMCwwLjgpLDAgMCAyNXB4IHJnYmEoMjU1LDExMCwxODAsMC4xKSxpbnNldCAwIDAgMCAxcHggcmdiYSgyNTUsMTEwLDE4MCwwLjA2KTsgfVxuICAgICAgICAgICAgICAgICAgICAgICAgNTAleyBib3gtc2hhZG93OjAgMCA2MHB4IHJnYmEoMCwwLDAsMC44KSwwIDAgNDVweCByZ2JhKDI1NSwxMTAsMTgwLDAuMiksaW5zZXQgMCAwIDAgMXB4IHJnYmEoMjU1LDExMCwxODAsMC4xMik7IH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAuc2FrdXJhLXBldGFsIHsgcG9zaXRpb246YWJzb2x1dGU7IHBvaW50ZXItZXZlbnRzOm5vbmU7IGJvcmRlci1yYWRpdXM6NTAlIDAgNTAlIDA7IGJhY2tncm91bmQ6cmdiYSgyNTUsMTEwLDE4MCwwLjIyKTsgYW5pbWF0aW9uOnNha3VyYURyaWZ0IGxpbmVhciBpbmZpbml0ZTsgfVxuICAgICAgICAgICAgICAgICAgICBAa2V5ZnJhbWVzIHNha3VyYURyaWZ0IHsgMCV7dHJhbnNmb3JtOnRyYW5zbGF0ZVkoLTEwcHgpIHJvdGF0ZSgwZGVnKTtvcGFjaXR5OjAuN30gMTAwJXt0cmFuc2Zvcm06dHJhbnNsYXRlWSg0MjBweCkgcm90YXRlKDI3MGRlZyk7b3BhY2l0eTowfSB9XG4gICAgICAgICAgICAgICAgICAgICN0bC1jb25uLWZ4LXBldGFscyB7IHBvc2l0aW9uOmFic29sdXRlO3RvcDowO2xlZnQ6MDtyaWdodDowO2hlaWdodDoxMDAlO3BvaW50ZXItZXZlbnRzOm5vbmU7b3ZlcmZsb3c6aGlkZGVuO3otaW5kZXg6MDtib3JkZXItcmFkaXVzOjE2cHg7IH1cbiAgICAgICAgICAgICAgICBgLAogICAgICAgIHBhbmVsRXh0cmE6IGA8ZGl2IGlkPSJ0bC1jb25uLWZ4LXBldGFscyI+XG4gICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InNha3VyYS1wZXRhbCIgc3R5bGU9IndpZHRoOjdweDtoZWlnaHQ6N3B4O2xlZnQ6OCU7dG9wOi0xMHB4O2FuaW1hdGlvbi1kdXJhdGlvbjozLjhzO2FuaW1hdGlvbi1kZWxheTowczsiPjwvZGl2PlxuICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJzYWt1cmEtcGV0YWwiIHN0eWxlPSJ3aWR0aDo1cHg7aGVpZ2h0OjVweDtsZWZ0OjI4JTt0b3A6LTEwcHg7YW5pbWF0aW9uLWR1cmF0aW9uOjUuMXM7YW5pbWF0aW9uLWRlbGF5OjAuOXM7Ij48L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0ic2FrdXJhLXBldGFsIiBzdHlsZT0id2lkdGg6OHB4O2hlaWdodDo4cHg7bGVmdDo1NSU7dG9wOi0xMHB4O2FuaW1hdGlvbi1kdXJhdGlvbjo0LjRzO2FuaW1hdGlvbi1kZWxheToxLjdzOyI+PC9kaXY+XG4gICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InNha3VyYS1wZXRhbCIgc3R5bGU9IndpZHRoOjRweDtoZWlnaHQ6NHB4O2xlZnQ6NzUlO3RvcDotMTBweDthbmltYXRpb24tZHVyYXRpb246My4yczthbmltYXRpb24tZGVsYXk6MC40czsiPjwvZGl2PlxuICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJzYWt1cmEtcGV0YWwiIHN0eWxlPSJ3aWR0aDo2cHg7aGVpZ2h0OjZweDtsZWZ0OjkyJTt0b3A6LTEwcHg7YW5pbWF0aW9uLWR1cmF0aW9uOjQuOXM7YW5pbWF0aW9uLWRlbGF5OjIuMXM7Ij48L2Rpdj5cbiAgICAgICAgICAgICAgICA8L2Rpdj5gLAogICAgICAgIHRoZW1lTGFiZWw6ICfwn4y4IEjhu5NuZyBTYWt1cmEnLAogICAgICAgIHByZXZpZXdCZzogJ2xpbmVhci1ncmFkaWVudCgxMzVkZWcsIzFhMDUxMCwjZmY2ZWI0NTUpJywKICAgICAgICBwcmV2aWV3Qm9yZGVyOiAncmdiYSgyNTUsMTEwLDE4MCwwLjU1KScsCiAgICAgICAgcHJldmlld1RleHQ6ICcjZmY2ZWI0JwogICAgICB9CiAgICB9OwogICAgcmV0dXJuIFRbdGhlbWVdIHx8IFQuZGVmYXVsdDsKICB9CiAgZnVuY3Rpb24gZ2V0TG9ja1NjcmVlblN0eWxlcygpIHsKICAgIGNvbnN0IHRjID0gZ2V0VGhlbWVDb2xvcnMoQ1VSUkVOVF9USEVNRSk7CiAgICByZXR1cm4gYFxuICAgICAgICAgICAgQGltcG9ydCB1cmwoJ2h0dHBzOi8vZm9udHMuZ29vZ2xlYXBpcy5jb20vY3NzMj9mYW1pbHk9T3JiaXRyb246d2dodEA0MDA7NzAwOzkwMCZmYW1pbHk9U2hhcmUrVGVjaCtNb25vJmZhbWlseT1SYWpkaGFuaTp3Z2h0QDQwMDs2MDA7NzAwJmRpc3BsYXk9c3dhcCcpO1xuICAgICAgICAgICAgI3RsLWNvbm4tb3ZlcmxheSB7IHBvc2l0aW9uOmZpeGVkO3RvcDowO2xlZnQ6MDt3aWR0aDoxMDB2dztoZWlnaHQ6MTAwdmg7YmFja2dyb3VuZDoke3RjLmJnT3ZlcmxheX07YmFja2Ryb3AtZmlsdGVyOmJsdXIoMTVweCk7ei1pbmRleDoyMTQ3NDgzNjQ3O2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OmNlbnRlcjtmb250LWZhbWlseTonUmFqZGhhbmknLHNhbnMtc2VyaWY7IH1cbiAgICAgICAgICAgICN0bC1jb25uLXBhbmVsIHsgd2lkdGg6NDIwcHg7YmFja2dyb3VuZDoke3RjLmJnUGFuZWx9O2JvcmRlcjoxcHggc29saWQgJHt0Yy5ib3JkZXJTdHJvbmd9O2JvcmRlci1yYWRpdXM6MjBweDtib3gtc2hhZG93OjAgMCA2MHB4IHJnYmEoMCwwLDAsMC44KSwwIDAgMCAxcHggJHt0Yy5wYW5lbEluc2V0fSBpbnNldDt0ZXh0LWFsaWduOmNlbnRlcjtvdmVyZmxvdzpoaWRkZW47YW5pbWF0aW9uOnRsRmFkZUluIDAuM3MgZWFzZTtwb3NpdGlvbjpyZWxhdGl2ZTsgfVxuICAgICAgICAgICAgQGtleWZyYW1lcyB0bEZhZGVJbiB7IGZyb217b3BhY2l0eTowO3RyYW5zZm9ybTpzY2FsZSgwLjk1KX10b3tvcGFjaXR5OjE7dHJhbnNmb3JtOnNjYWxlKDEpfSB9XG4gICAgICAgICAgICAjdGwtY29ubi1oZWFkZXIgeyBwYWRkaW5nOjIycHg7YmFja2dyb3VuZDoke3RjLmhlYWRlckJnfTtib3JkZXItYm90dG9tOjFweCBzb2xpZCAke3RjLmJvcmRlcn07IH1cbiAgICAgICAgICAgIC50bC1icmFuZC1uYW1lIHsgZm9udC1mYW1pbHk6J09yYml0cm9uJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZToyMnB4O2ZvbnQtd2VpZ2h0OjcwMDtiYWNrZ3JvdW5kOiR7dGMuYnJhbmRHcmFkaWVudH07YmFja2dyb3VuZC1zaXplOjIwMCU7LXdlYmtpdC1iYWNrZ3JvdW5kLWNsaXA6dGV4dDstd2Via2l0LXRleHQtZmlsbC1jb2xvcjp0cmFuc3BhcmVudDthbmltYXRpb246dGxTaGltbWVyIDNzIGxpbmVhciBpbmZpbml0ZTsgfVxuICAgICAgICAgICAgQGtleWZyYW1lcyB0bFNoaW1tZXIgeyAxMDAle2JhY2tncm91bmQtcG9zaXRpb246MjAwJSA1MCV9IH1cbiAgICAgICAgICAgICN0bC1jb25uLWJvZHkgeyBwYWRkaW5nOjMwcHggMjVweDsgfVxuICAgICAgICAgICAgLnRsLXN1YnRpdGxlIHsgY29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjcpO2ZvbnQtc2l6ZToxM3B4O21hcmdpbi1ib3R0b206MTBweDtmb250LWZhbWlseTonU2hhcmUgVGVjaCBNb25vJzsgfVxuICAgICAgICAgICAgLnRsLXdhcm5pbmcgeyBjb2xvcjojZmZjMTA3O2ZvbnQtc2l6ZToxMnB4O21hcmdpbi1ib3R0b206MjBweDtiYWNrZ3JvdW5kOnJnYmEoMjU1LDE5Myw3LDAuMSk7cGFkZGluZzo4cHg7Ym9yZGVyLXJhZGl1czo2cHg7IH1cbiAgICAgICAgICAgIC50bC1pbnB1dCB7IHdpZHRoOjEwMCU7cGFkZGluZzoxNHB4O2JhY2tncm91bmQ6cmdiYSgwLDAsMCwwLjU1KTtib3JkZXI6MXB4IHNvbGlkICR7dGMuaW5wdXRCb3JkZXJ9O2JvcmRlci1yYWRpdXM6MTBweDtjb2xvcjoke3RjLmlucHV0Q29sb3J9O2ZvbnQtZmFtaWx5OidTaGFyZSBUZWNoIE1vbm8nO2ZvbnQtc2l6ZToxNnB4O3RleHQtYWxpZ246Y2VudGVyO21hcmdpbi1ib3R0b206MTVweDt0cmFuc2l0aW9uOjAuMnM7Ym94LXNpemluZzpib3JkZXItYm94OyB9XG4gICAgICAgICAgICAudGwtaW5wdXQ6Zm9jdXMgeyBvdXRsaW5lOm5vbmU7Ym9yZGVyLWNvbG9yOiR7dGMuYzF9O2JveC1zaGFkb3c6MCAwIDE2cHggJHt0Yy5nbG93TWlkfTsgfVxuICAgICAgICAgICAgLnRsLWJ0biB7IHdpZHRoOjEwMCU7cGFkZGluZzoxNHB4O2JvcmRlcjpub25lO2JvcmRlci1yYWRpdXM6MTBweDtjdXJzb3I6cG9pbnRlcjtmb250LWZhbWlseTonT3JiaXRyb24nLHNhbnMtc2VyaWY7Zm9udC1zaXplOjE0cHg7Zm9udC13ZWlnaHQ6OTAwO21hcmdpbi1ib3R0b206MTJweDt0cmFuc2l0aW9uOjAuMnM7IH1cbiAgICAgICAgICAgIC50bC1idG4tdW5sb2NrIHsgYmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLCMwMGIwOWIsIzk2YzkzZCk7Y29sb3I6I2ZmZjsgfVxuICAgICAgICAgICAgLnRsLWJ0bi11bmxvY2s6aG92ZXIgeyB0cmFuc2Zvcm06c2NhbGUoMS4wMik7Ym94LXNoYWRvdzowIDAgMjVweCByZ2JhKDAsMTc2LDE1NSwwLjYpOyB9XG4gICAgICAgICAgICAudGwtYnRuLXZpcCB7IGJhY2tncm91bmQ6cmdiYSgyMTcsNCw0MSwwLjEpO2JvcmRlcjoxcHggc29saWQgcmdiYSgyMTcsNCw0MSwwLjUpO2NvbG9yOiNlZjIzM2M7IH1cbiAgICAgICAgICAgIC50bC1idG4tdmlwOmhvdmVyIHsgYmFja2dyb3VuZDpyZ2JhKDIxNyw0LDQxLDAuMik7dHJhbnNmb3JtOnNjYWxlKDEuMDEpOyB9XG4gICAgICAgICAgICAjdGwtZXJyIHsgY29sb3I6I2VmMjMzYztmb250LXNpemU6MTNweDttYXJnaW4tdG9wOjEycHg7ZGlzcGxheTpub25lO2ZvbnQtZmFtaWx5OidTaGFyZSBUZWNoIE1vbm8nO2JhY2tncm91bmQ6cmdiYSgyMzksMzUsNjAsMC4xKTtwYWRkaW5nOjhweDtib3JkZXItcmFkaXVzOjZweDsgfVxuICAgICAgICAgICAgLnRsLWh3aWQgeyBjb2xvcjpyZ2JhKDI1NSwyNTUsMjU1LDAuMjIpO2ZvbnQtc2l6ZToxMHB4O21hcmdpbi10b3A6MTVweDt3b3JkLWJyZWFrOmJyZWFrLWFsbDtmb250LWZhbWlseTptb25vc3BhY2U7IH1cbiAgICAgICAgICAgIC50bC1mb290IHsgbWFyZ2luLXRvcDoxNXB4O2ZvbnQtc2l6ZToxMXB4O2NvbG9yOnJnYmEoMjU1LDI1NSwyNTUsMC4xMyk7IH1cbiAgICAgICAgICAgICR7dGMuZnhDU1N9XG4gICAgICAgIGA7CiAgfQogIGZ1bmN0aW9uIGdldE1haW5VSVN0eWxlcygpIHsKICAgIGNvbnN0IHRjID0gZ2V0VGhlbWVDb2xvcnMoQ1VSUkVOVF9USEVNRSk7CiAgICByZXR1cm4gYFxuICAgICAgICAgICAgQGltcG9ydCB1cmwoJ2h0dHBzOi8vZm9udHMuZ29vZ2xlYXBpcy5jb20vY3NzMj9mYW1pbHk9T3JiaXRyb246d2dodEA0MDA7NzAwOzkwMCZmYW1pbHk9U2hhcmUrVGVjaCtNb25vJmZhbWlseT1SYWpkaGFuaTp3Z2h0QDQwMDs2MDA7NzAwJmRpc3BsYXk9c3dhcCcpO1xuICAgICAgICAgICAgI3RsLWZsb2F0QnRuIHsgcG9zaXRpb246Zml4ZWQ7Ym90dG9tOjI4cHg7cmlnaHQ6MjhweDt3aWR0aDo1NnB4O2hlaWdodDo1NnB4O2JvcmRlci1yYWRpdXM6NTAlO2JvcmRlcjpub25lO2N1cnNvcjpwb2ludGVyO3otaW5kZXg6MTAwMDA7YmFja2dyb3VuZDoke3RjLmZsb2F0R3JhZGllbnR9O2JveC1zaGFkb3c6MCAwIDAgMCAke3RjLmdsb3dTdHJvbmd9LDAgMCAyMHB4ICR7dGMuZ2xvd0NvbG9yfSwwIDRweCAyMHB4IHJnYmEoMCwwLDAsMC41KTtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpjZW50ZXI7Zm9udC1zaXplOjIycHg7dHJhbnNpdGlvbjp0cmFuc2Zvcm0gMC4ycyBlYXNlLGJveC1zaGFkb3cgMC4ycyBlYXNlO2FuaW1hdGlvbjpjb25uUHVsc2VSaW5nIDIuNXMgZWFzZS1vdXQgaW5maW5pdGU7IH1cbiAgICAgICAgICAgICN0bC1mbG9hdEJ0bjpob3ZlciB7IHRyYW5zZm9ybTpzY2FsZSgxLjEyKSByb3RhdGUoMTVkZWcpOyB9XG4gICAgICAgICAgICBAa2V5ZnJhbWVzIGNvbm5QdWxzZVJpbmcgeyAwJXtib3gtc2hhZG93OjAgMCAwIDAgJHt0Yy5nbG93UHVsc2V9fTcwJXtib3gtc2hhZG93OjAgMCAwIDE1cHggcmdiYSgwLDAsMCwwKX0xMDAle2JveC1zaGFkb3c6MCAwIDAgMCByZ2JhKDAsMCwwLDApfSB9XG4gICAgICAgICAgICBAa2V5ZnJhbWVzIGNvbm5CbGluayB7IDAlLDEwMCV7b3BhY2l0eToxfTUwJXtvcGFjaXR5OjAuM30gfVxuICAgICAgICAgICAgI3RsLXBhbmVsIHsgcG9zaXRpb246Zml4ZWQ7dG9wOjUwJTtsZWZ0OjUwJTt0cmFuc2Zvcm06dHJhbnNsYXRlKC01MCUsLTUwJSk7d2lkdGg6MzYwcHg7YmFja2dyb3VuZDoke3RjLmJnUGFuZWx9O2JhY2tkcm9wLWZpbHRlcjpibHVyKDI0cHgpO2JvcmRlcjoxcHggc29saWQgJHt0Yy5ib3JkZXJ9O2JvcmRlci1yYWRpdXM6MTZweDtib3gtc2hhZG93OjAgMCA2MHB4IHJnYmEoMCwwLDAsMC44KTt6LWluZGV4Ojk5OTk7b3ZlcmZsb3c6aGlkZGVuO2ZvbnQtZmFtaWx5OidSYWpkaGFuaScsc2Fucy1zZXJpZjsgfVxuICAgICAgICAgICAgI3RsLXBhbmVsLmhpZGRlbiB7IGRpc3BsYXk6bm9uZTsgfVxuICAgICAgICAgICAgI3RsLXAtaGVhZGVyIHsgY3Vyc29yOm1vdmU7cGFkZGluZzoxNHB4IDE2cHggMTJweDtiYWNrZ3JvdW5kOiR7dGMuaGVhZGVyQmd9O2JvcmRlci1ib3R0b206MXB4IHNvbGlkICR7dGMuYm9yZGVyU3VidGxlfTtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpzcGFjZS1iZXR3ZWVuOyB9XG4gICAgICAgICAgICAudGwtcC1icmFuZCB7IGRpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjhweDsgfVxuICAgICAgICAgICAgLnRsLXAtbmFtZSB7IGZvbnQtZmFtaWx5OidPcmJpdHJvbicsc2Fucy1zZXJpZjtmb250LXNpemU6MTEuNXB4O2ZvbnQtd2VpZ2h0OjcwMDtiYWNrZ3JvdW5kOiR7dGMuYnJhbmRHcmFkaWVudH07YmFja2dyb3VuZC1zaXplOjIwMCU7LXdlYmtpdC1iYWNrZ3JvdW5kLWNsaXA6dGV4dDstd2Via2l0LXRleHQtZmlsbC1jb2xvcjp0cmFuc3BhcmVudDthbmltYXRpb246dGxTaGltbWVyIDNzIGxpbmVhciBpbmZpbml0ZTsgfVxuICAgICAgICAgICAgQGtleWZyYW1lcyB0bFNoaW1tZXIgeyAxMDAle2JhY2tncm91bmQtcG9zaXRpb246MjAwJSA1MCV9IH1cbiAgICAgICAgICAgIC50bC1iYWRnZSB7IGZvbnQtZmFtaWx5OidPcmJpdHJvbic7Zm9udC1zaXplOjcuNXB4O2ZvbnQtd2VpZ2h0OjkwMDtjb2xvcjojZmZmO2JvcmRlci1yYWRpdXM6NHB4O3BhZGRpbmc6M3B4IDZweDtiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCgxMzVkZWcsIzU1NSwjNzc3KTsgfVxuICAgICAgICAgICAgLnRsLWJhZGdlLnZpcCB7IGJhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDEzNWRlZywjYTg1NWY3LCM2MzY2ZjEpO2JveC1zaGFkb3c6MCAwIDEwcHggcmdiYSgxNjgsODUsMjQ3LDAuNCk7IH1cbiAgICAgICAgICAgIC50bC1iYWRnZS51bmxpbWl0ZWQgeyBiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCgxMzVkZWcsI2Y1OWUwYiwjZWY0NDQ0KTtib3gtc2hhZG93OjAgMCAxMHB4IHJnYmEoMjQ1LDE1OCwxMSwwLjQpOyB9XG4gICAgICAgICAgICAjdGwtY2xvc2VCdG4sI3RsLXNldHRpbmdzQnRuIHsgd2lkdGg6MjhweDtoZWlnaHQ6MjhweDtib3JkZXItcmFkaXVzOjUwJTtib3JkZXI6MXB4IHNvbGlkIHJnYmEoMjU1LDI1NSwyNTUsMC4xKTtiYWNrZ3JvdW5kOnJnYmEoMjU1LDI1NSwyNTUsMC4wNCk7Y29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjUpO2N1cnNvcjpwb2ludGVyO2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OmNlbnRlcjt0cmFuc2l0aW9uOjAuMnM7Zm9udC1zaXplOjEzcHg7IH1cbiAgICAgICAgICAgICN0bC1jbG9zZUJ0bjpob3ZlciB7IGJvcmRlci1jb2xvcjpyZ2JhKDIxNyw0LDQxLDAuNik7YmFja2dyb3VuZDpyZ2JhKDIxNyw0LDQxLDAuMTUpO2NvbG9yOiNlZjIzM2M7IH1cbiAgICAgICAgICAgICN0bC1zZXR0aW5nc0J0bjpob3ZlciB7IGJvcmRlci1jb2xvcjoke3RjLmJvcmRlclN0cm9uZ307YmFja2dyb3VuZDoke3RjLmdsb3dTdWJ0bGV9O2NvbG9yOiR7dGMuYzF9OyB9XG4gICAgICAgICAgICAjdGwtc2V0dGluZ3NCdG4uYWN0aXZlIHsgYm9yZGVyLWNvbG9yOiR7dGMuYzF9O2JhY2tncm91bmQ6JHt0Yy5nbG93U3VidGxlfTtjb2xvcjoke3RjLmMxfTsgfVxuICAgICAgICAgICAgI3RsLXAtYm9keSB7IHBhZGRpbmc6MTRweDtkaXNwbGF5OmZsZXg7ZmxleC1kaXJlY3Rpb246Y29sdW1uO2dhcDoxMnB4OyB9XG4gICAgICAgICAgICAudGwtc3RhdGJveCB7IGJvcmRlcjoxcHggc29saWQgJHt0Yy5zdGF0dXNCb3JkZXJ9O2JvcmRlci1yYWRpdXM6MTBweDtwYWRkaW5nOjEwcHg7YmFja2dyb3VuZDoke3RjLnN0YXR1c0JnfTsgfVxuICAgICAgICAgICAgLnRsLXN0YXRyb3cgeyBkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDo4cHg7Zm9udC1mYW1pbHk6J1NoYXJlIFRlY2ggTW9ubycsbW9ub3NwYWNlO2ZvbnQtc2l6ZToxMS41cHg7Y29sb3I6I2NjYzttYXJnaW4tdG9wOjRweDsgfVxuICAgICAgICAgICAgI3RsLW1vZGVTZWxlY3QgeyB3aWR0aDoxMDAlO3BhZGRpbmc6MTBweDtiYWNrZ3JvdW5kOnJnYmEoMCwwLDAsMC40KTtib3JkZXI6MXB4IHNvbGlkICR7dGMuc2VsZWN0Qm9yZGVyfTtib3JkZXItcmFkaXVzOjhweDtjb2xvcjojZmZmO2ZvbnQtZmFtaWx5OidSYWpkaGFuaScsc2Fucy1zZXJpZjtmb250LXNpemU6MTRweDtvdXRsaW5lOm5vbmU7bWFyZ2luLXRvcDo1cHg7IH0KICAgICAgICAgICAgI3RsLWdvZC10YXJnZXQtc2NvcmUgeyB3aWR0aDoxMDAlO3BhZGRpbmc6MTBweDtiYWNrZ3JvdW5kOnJnYmEoMCwwLDAsMC40KTtib3JkZXI6MXB4IHNvbGlkICR7dGMuc2VsZWN0Qm9yZGVyfTtib3JkZXItcmFkaXVzOjhweDtjb2xvcjojZmZjMTA3O2ZvbnQtZmFtaWx5OidSYWpkaGFuaScsc2Fucy1zZXJpZjtmb250LXNpemU6MTRweDtvdXRsaW5lOm5vbmU7bWFyZ2luLXRvcDo1cHg7IH1cbiAgICAgICAgICAgIC50bC1nb2QtaW5wdXQgeyB3aWR0aDoxMDAlO3BhZGRpbmc6MTBweDtiYWNrZ3JvdW5kOnJnYmEoMCwwLDAsMC40KTtib3JkZXI6MXB4IHNvbGlkIHJnYmEoMjU1LDE5Myw3LDAuMyk7Ym9yZGVyLXJhZGl1czo4cHg7Y29sb3I6I2ZmYzEwNztmb250LWZhbWlseTonU2hhcmUgVGVjaCBNb25vJztmb250LXNpemU6MTNweDtvdXRsaW5lOm5vbmU7bWFyZ2luLXRvcDo1cHg7Ym94LXNpemluZzpib3JkZXItYm94OyB9XG4gICAgICAgICAgICAjdGwtZmlyZUJ0biB7IHdpZHRoOjEwMCU7cGFkZGluZzoxM3B4O2JhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDEzNWRlZywjZDkwNDI5LCNlZjIzM2MpO2JvcmRlcjpub25lO2JvcmRlci1yYWRpdXM6MTBweDtjb2xvcjojZmZmO2ZvbnQtZmFtaWx5OidPcmJpdHJvbic7Zm9udC13ZWlnaHQ6OTAwO2ZvbnQtc2l6ZToxNHB4O2N1cnNvcjpwb2ludGVyO2JveC1zaGFkb3c6MCAwIDIwcHggcmdiYSgyMTcsNCw0MSwwLjQpO3RyYW5zaXRpb246MC4yczttYXJnaW4tdG9wOjVweDsgfVxuICAgICAgICAgICAgI3RsLWZpcmVCdG46aG92ZXIgeyBib3gtc2hhZG93OjAgMCAzMHB4IHJnYmEoMjE3LDQsNDEsMC43KTsgfVxuICAgICAgICAgICAgI3RsLWZpcmVCdG46ZGlzYWJsZWQgeyBvcGFjaXR5OjAuNTtjdXJzb3I6bm90LWFsbG93ZWQ7IH1cbiAgICAgICAgICAgIC50bC1jb25zb2xlIHsgYm9yZGVyOjFweCBzb2xpZCAke3RjLmNvbnNvbGVCb3JkZXJ9O2JvcmRlci1yYWRpdXM6MTBweDtiYWNrZ3JvdW5kOnJnYmEoMCwwLDAsMC44Mik7cGFkZGluZzo4cHg7aGVpZ2h0Ojk2cHg7b3ZlcmZsb3cteTphdXRvO2ZvbnQtZmFtaWx5OidTaGFyZSBUZWNoIE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6MTAuNXB4O2xpbmUtaGVpZ2h0OjEuNTtjb2xvcjojYWFhOyB9XG4gICAgICAgICAgICAudGwtbG9nIHsgbWFyZ2luLWJvdHRvbToycHg7cGFkZGluZzoxcHggM3B4O2xpbmUtaGVpZ2h0OjEuNTt3b3JkLWJyZWFrOmJyZWFrLXdvcmQ7d2hpdGUtc3BhY2U6bm9ybWFsOyB9XG4gICAgICAgICAgICAudGwtbG9nLm9rICAgeyBjb2xvcjojMDBlNjc2OyB9XG4gICAgICAgICAgICAudGwtbG9nLmVyciAgeyBjb2xvcjojZWYyMzNjOyB9XG4gICAgICAgICAgICAudGwtbG9nLndhcm4geyBjb2xvcjojZmZjMTA3OyB9XG4gICAgICAgICAgICAudGwtbG9nLmluZm8geyBjb2xvcjojNGZhY2ZlOyB9XG4gICAgICAgICAgICAjdGwtcC1mb290ZXIgeyBwYWRkaW5nOjhweCAxNHB4O2JvcmRlci10b3A6MXB4IHNvbGlkICR7dGMuYm9yZGVyU3VidGxlfTtkaXNwbGF5OmZsZXg7anVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47Zm9udC1mYW1pbHk6J1NoYXJlIFRlY2ggTW9ubyc7Zm9udC1zaXplOjlweDtjb2xvcjpyZ2JhKDI1NSwyNTUsMjU1LDAuMik7IH1cbiAgICAgICAgICAgIFxuICAgICAgICAgICAgI3RsLXNvIHsgcG9zaXRpb246YWJzb2x1dGU7dG9wOjA7bGVmdDowO3JpZ2h0OjA7Ym90dG9tOjA7YmFja2dyb3VuZDoke3RjLmJnUGFuZWx9O2JhY2tkcm9wLWZpbHRlcjpibHVyKDEycHgpO3otaW5kZXg6MjA7Ym9yZGVyLXJhZGl1czoxNnB4O2Rpc3BsYXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47b3ZlcmZsb3c6aGlkZGVuOyB9XG4gICAgICAgICAgICAjdGwtc28uaGlkZGVuIHsgZGlzcGxheTpub25lOyB9XG4gICAgICAgICAgICAudGwtc28taGRyIHsgcGFkZGluZzoxM3B4IDE2cHg7YmFja2dyb3VuZDoke3RjLmhlYWRlckJnfTtib3JkZXItYm90dG9tOjFweCBzb2xpZCAke3RjLmJvcmRlclN1YnRsZX07ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2VlbjtmbGV4LXNocmluazowOyB9XG4gICAgICAgICAgICAudGwtc28tdGl0bGUgeyBmb250LWZhbWlseTonT3JiaXRyb24nLHNhbnMtc2VyaWY7Zm9udC1zaXplOjEwLjVweDtmb250LXdlaWdodDo3MDA7Y29sb3I6JHt0Yy5jMX07IH1cbiAgICAgICAgICAgICN0bC1zb0Nsb3NlIHsgd2lkdGg6MjZweDtoZWlnaHQ6MjZweDtib3JkZXItcmFkaXVzOjUwJTtib3JkZXI6MXB4IHNvbGlkICR7dGMuYm9yZGVyfTtiYWNrZ3JvdW5kOiR7dGMuZ2xvd1N1YnRsZX07Y29sb3I6JHt0Yy5jMX07Y3Vyc29yOnBvaW50ZXI7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyO2ZvbnQtc2l6ZToxMnB4O3RyYW5zaXRpb246MC4yczsgfVxuICAgICAgICAgICAgI3RsLXNvQ2xvc2U6aG92ZXIgeyBiYWNrZ3JvdW5kOnJnYmEoMjE3LDQsNDEsMC4xNSk7Ym9yZGVyLWNvbG9yOnJnYmEoMjE3LDQsNDEsMC41KTtjb2xvcjojZWYyMzNjOyB9XG4gICAgICAgICAgICAudGwtc28tYm9keSB7IHBhZGRpbmc6MTRweDtmbGV4OjE7ZGlzcGxheTpmbGV4O2ZsZXgtZGlyZWN0aW9uOmNvbHVtbjtnYXA6MTJweDtvdmVyZmxvdy15OmF1dG87IH1cbiAgICAgICAgICAgIC50bC1zby1sYmwgeyBmb250LXNpemU6OS41cHg7Zm9udC13ZWlnaHQ6NzAwO2NvbG9yOnJnYmEoMjU1LDI1NSwyNTUsMC4yOCk7dGV4dC10cmFuc2Zvcm06dXBwZXJjYXNlO2ZvbnQtZmFtaWx5OidPcmJpdHJvbic7bGV0dGVyLXNwYWNpbmc6MS4ycHg7bWFyZ2luLWJvdHRvbToycHg7IH1cbiAgICAgICAgICAgIC50bC10aGVtZS1jYXJkcyB7IGRpc3BsYXk6ZmxleDtnYXA6OHB4OyB9XG4gICAgICAgICAgICAudGwtdGMgeyBmbGV4OjE7Y3Vyc29yOnBvaW50ZXI7Ym9yZGVyLXJhZGl1czoxMHB4O2JvcmRlcjoycHggc29saWQgcmdiYSgyNTUsMjU1LDI1NSwwLjA3KTtwYWRkaW5nOjhweCA2cHg7dGV4dC1hbGlnbjpjZW50ZXI7dHJhbnNpdGlvbjphbGwgMC4yMnM7YmFja2dyb3VuZDpyZ2JhKDAsMCwwLDAuMyk7cG9zaXRpb246cmVsYXRpdmU7IH1cbiAgICAgICAgICAgIC50bC10Yzpob3ZlciB7IHRyYW5zZm9ybTp0cmFuc2xhdGVZKC0zcHgpO2JvcmRlci1jb2xvcjpyZ2JhKDI1NSwyNTUsMjU1LDAuMTgpO2JveC1zaGFkb3c6MCA2cHggMThweCByZ2JhKDAsMCwwLDAuNCk7IH1cbiAgICAgICAgICAgIC50bC10Yy5hY3RpdmUgeyBib3JkZXItY29sb3I6JHt0Yy5jMX07Ym94LXNoYWRvdzowIDAgMTRweCAke3RjLmdsb3dNaWR9OyB9XG4gICAgICAgICAgICAudGwtdGMtcHJldiB7IHdpZHRoOjEwMCU7aGVpZ2h0OjM4cHg7Ym9yZGVyLXJhZGl1czo3cHg7bWFyZ2luLWJvdHRvbTo3cHg7b3ZlcmZsb3c6aGlkZGVuO3Bvc2l0aW9uOnJlbGF0aXZlOyB9XG4gICAgICAgICAgICAudGwtdGMtcHJldi1pbm5lciB7IHBvc2l0aW9uOmFic29sdXRlO2luc2V0OjA7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyOyB9XG4gICAgICAgICAgICAudGwtdGMtcHJldi10ZXh0IHsgZm9udC1mYW1pbHk6J09yYml0cm9uJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZTo3cHg7Zm9udC13ZWlnaHQ6NzAwO2xldHRlci1zcGFjaW5nOjFweDtvcGFjaXR5OjAuOTsgfVxuICAgICAgICAgICAgLnRsLXRjLWxibCB7IGZvbnQtZmFtaWx5OidSYWpkaGFuaScsc2Fucy1zZXJpZjtmb250LXNpemU6MTAuNXB4O2ZvbnQtd2VpZ2h0OjYwMDtjb2xvcjpyZ2JhKDI1NSwyNTUsMjU1LDAuNik7IH1cbiAgICAgICAgICAgIC50bC10Yy5hY3RpdmUgLnRsLXRjLWxibCB7IGNvbG9yOiR7dGMuYzF9O2ZvbnQtd2VpZ2h0OjcwMDsgfVxuICAgICAgICAgICAgLnRsLXRjLmFjdGl2ZTo6YWZ0ZXIgeyBjb250ZW50OifinJMnO3Bvc2l0aW9uOmFic29sdXRlO3RvcDo1cHg7cmlnaHQ6N3B4O2NvbG9yOiR7dGMuYzF9O2ZvbnQtc2l6ZToxMXB4O2ZvbnQtd2VpZ2h0OjkwMDsgfVxuICAgICAgICAgICAgLnRsLXNvLWRpdmlkZXIgeyBoZWlnaHQ6MXB4O2JhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDkwZGVnLHRyYW5zcGFyZW50LCR7dGMuYm9yZGVyfSx0cmFuc3BhcmVudCk7IH1cbiAgICAgICAgICAgIC50bC1oaW50IHsgZm9udC1zaXplOjEwcHg7Y29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjIpO2ZvbnQtZmFtaWx5OidTaGFyZSBUZWNoIE1vbm8nO3RleHQtYWxpZ246Y2VudGVyO2xpbmUtaGVpZ2h0OjEuNjsgfVxuICAgICAgICAgICAgLnRsLWNoYW5nZS1rZXkgeyB3aWR0aDoxMDAlO3BhZGRpbmc6MTBweDtiYWNrZ3JvdW5kOnJnYmEoMjM5LDM1LDYwLDAuMSk7Ym9yZGVyOjFweCBzb2xpZCByZ2JhKDIzOSwzNSw2MCwwLjM4KTtib3JkZXItcmFkaXVzOjhweDtjb2xvcjojZWYyMzNjO2ZvbnQtZmFtaWx5OidPcmJpdHJvbicsc2Fucy1zZXJpZjtmb250LXNpemU6MTAuNXB4O2ZvbnQtd2VpZ2h0OjcwMDtjdXJzb3I6cG9pbnRlcjt0cmFuc2l0aW9uOjAuMnM7bGV0dGVyLXNwYWNpbmc6MC41cHg7IH1cbiAgICAgICAgICAgIC50bC1jaGFuZ2Uta2V5OmhvdmVyIHsgYmFja2dyb3VuZDpyZ2JhKDIzOSwzNSw2MCwwLjIpO2JvcmRlci1jb2xvcjpyZ2JhKDIzOSwzNSw2MCwwLjY1KTtib3gtc2hhZG93OjAgMCAxNHB4IHJnYmEoMjM5LDM1LDYwLDAuMjUpOyB9XG4gICAgICAgICAgICBcbiAgICAgICAgICAgICN0aWVwLW1vZGFsLW92ZXJsYXkgeyBwb3NpdGlvbjpmaXhlZDt0b3A6MDtsZWZ0OjA7d2lkdGg6MTAwdnc7aGVpZ2h0OjEwMHZoO2JhY2tncm91bmQ6cmdiYSgwLDAsMCwwLjcyKTt6LWluZGV4OjIxNDc0ODM2NDY7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyOyB9XG4gICAgICAgICAgICAudGllcC1tb2RhbC1ib3ggeyB3aWR0aDozMjBweDtiYWNrZ3JvdW5kOiR7dGMuYmdQYW5lbH07Ym9yZGVyOjFweCBzb2xpZCAke3RjLmJvcmRlclN0cm9uZ307Ym9yZGVyLXJhZGl1czoxNnB4O3BhZGRpbmc6MjZweCAyMnB4IDIycHg7dGV4dC1hbGlnbjpjZW50ZXI7Ym94LXNoYWRvdzowIDAgNjBweCByZ2JhKDAsMCwwLDAuOSksaW5zZXQgMCAwIDAgMXB4ICR7dGMucGFuZWxJbnNldH07Zm9udC1mYW1pbHk6J1JhamRoYW5pJyxzYW5zLXNlcmlmOyB9XG4gICAgICAgICAgICAudGllcC1tb2RhbC1pY29uIHsgZm9udC1zaXplOjM4cHg7bWFyZ2luLWJvdHRvbTo4cHg7IH1cbiAgICAgICAgICAgIC50aWVwLW1vZGFsLXRpdGxlIHsgZm9udC1mYW1pbHk6J09yYml0cm9uJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZToxMnB4O2ZvbnQtd2VpZ2h0OjcwMDtjb2xvcjoke3RjLmMxfTttYXJnaW4tYm90dG9tOjEycHg7bGluZS1oZWlnaHQ6MS41OyB9XG4gICAgICAgICAgICAudGllcC1tb2RhbC1saW5lcyB7IGNvbG9yOnJnYmEoMjU1LDI1NSwyNTUsMC43OCk7Zm9udC1zaXplOjEzcHg7bGluZS1oZWlnaHQ6MS42NTttYXJnaW4tYm90dG9tOjE4cHg7IH1cbiAgICAgICAgICAgIC50aWVwLW1vZGFsLWxpbmVzIGIgeyBjb2xvcjojZmZmOyB9XG4gICAgICAgICAgICAudGllcC1tb2RhbC1vayB7IHBhZGRpbmc6MTBweCAzNnB4O2JhY2tncm91bmQ6JHt0Yy5mbG9hdEdyYWRpZW50fTtib3JkZXI6bm9uZTtib3JkZXItcmFkaXVzOjhweDtjb2xvcjojZmZmO2ZvbnQtZmFtaWx5OidPcmJpdHJvbicsc2Fucy1zZXJpZjtmb250LXNpemU6MTEuNXB4O2ZvbnQtd2VpZ2h0OjkwMDtjdXJzb3I6cG9pbnRlcjt0cmFuc2l0aW9uOjAuMnM7Ym94LXNoYWRvdzowIDRweCAxNnB4ICR7dGMuZ2xvd0NvbG9yfTsgfVxuICAgICAgICAgICAgLnRpZXAtbW9kYWwtb2s6aG92ZXIgeyB0cmFuc2Zvcm06c2NhbGUoMS4wNik7Ym94LXNoYWRvdzowIDAgMjRweCAke3RjLmdsb3dDb2xvcn07IH1cbiAgICAgICAgICAgICR7dGMuZnhDU1N9XG4gICAgICAgIGA7CiAgfQogIGZ1bmN0aW9uIF9lbnN1cmVNb2RhbFN0eWxlKCkgewogICAgaWYgKGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0aWVwLW1vZGFsLXN0eWxlJykpIHJldHVybjsKICAgIGNvbnN0IHRjID0gZ2V0VGhlbWVDb2xvcnMoQ1VSUkVOVF9USEVNRSk7CiAgICBjb25zdCBtcyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ3N0eWxlJyk7CiAgICBtcy5pZCA9ICd0aWVwLW1vZGFsLXN0eWxlJzsKICAgIG1zLnRleHRDb250ZW50ID0gYFxuICAgICAgICAgICAgQGtleWZyYW1lcyB0bE1vZGFsSW57ZnJvbXtvcGFjaXR5OjA7dHJhbnNmb3JtOnNjYWxlKDAuOTIpfXRve29wYWNpdHk6MTt0cmFuc2Zvcm06c2NhbGUoMSl9fVxuICAgICAgICAgICAgI3RpZXAtbW9kYWwtb3ZlcmxheXtwb3NpdGlvbjpmaXhlZCFpbXBvcnRhbnQ7dG9wOjAhaW1wb3J0YW50O2xlZnQ6MCFpbXBvcnRhbnQ7d2lkdGg6MTAwdnchaW1wb3J0YW50O2hlaWdodDoxMDB2aCFpbXBvcnRhbnQ7YmFja2dyb3VuZDpyZ2JhKDAsMCwwLDAuNzUpIWltcG9ydGFudDt6LWluZGV4OjIxNDc0ODM2NDYhaW1wb3J0YW50O2Rpc3BsYXk6ZmxleCFpbXBvcnRhbnQ7YWxpZ24taXRlbXM6Y2VudGVyIWltcG9ydGFudDtqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyIWltcG9ydGFudDt9XG4gICAgICAgICAgICAudGllcC1tb2RhbC1ib3h7d2lkdGg6MzIwcHg7bWF4LXdpZHRoOjkwdnc7YmFja2dyb3VuZDoke3RjLmJnUGFuZWx9O2JvcmRlcjoxcHggc29saWQgJHt0Yy5ib3JkZXJTdHJvbmd9O2JvcmRlci1yYWRpdXM6MTZweDtwYWRkaW5nOjI2cHggMjJweCAyMnB4O3RleHQtYWxpZ246Y2VudGVyO2JveC1zaGFkb3c6MCAwIDYwcHggcmdiYSgwLDAsMCwwLjkpLGluc2V0IDAgMCAwIDFweCAke3RjLnBhbmVsSW5zZXR9O2ZvbnQtZmFtaWx5OidSYWpkaGFuaScsc2Fucy1zZXJpZjthbmltYXRpb246dGxNb2RhbEluIDAuMjJzIGVhc2U7fVxuICAgICAgICAgICAgLnRpZXAtbW9kYWwtaWNvbntmb250LXNpemU6MzhweDttYXJnaW4tYm90dG9tOjhweDt9XG4gICAgICAgICAgICAudGllcC1tb2RhbC10aXRsZXtmb250LWZhbWlseTonT3JiaXRyb24nLHNhbnMtc2VyaWY7Zm9udC1zaXplOjEycHg7Zm9udC13ZWlnaHQ6NzAwO2NvbG9yOiR7dGMuYzF9O21hcmdpbi1ib3R0b206MTJweDtsaW5lLWhlaWdodDoxLjU7fVxuICAgICAgICAgICAgLnRpZXAtbW9kYWwtbGluZXN7Y29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjgyKTtmb250LXNpemU6MTNweDtsaW5lLWhlaWdodDoxLjc7bWFyZ2luLWJvdHRvbToxOHB4O31cbiAgICAgICAgICAgIC50aWVwLW1vZGFsLWxpbmVzIGJ7Y29sb3I6I2ZmZjt9XG4gICAgICAgICAgICAudGllcC1tb2RhbC1va3twYWRkaW5nOjEwcHggMzZweDtiYWNrZ3JvdW5kOiR7dGMuZmxvYXRHcmFkaWVudH07Ym9yZGVyOm5vbmU7Ym9yZGVyLXJhZGl1czo4cHg7Y29sb3I6I2ZmZjtmb250LWZhbWlseTonT3JiaXRyb24nLHNhbnMtc2VyaWY7Zm9udC1zaXplOjExLjVweDtmb250LXdlaWdodDo5MDA7Y3Vyc29yOnBvaW50ZXI7dHJhbnNpdGlvbjowLjJzO2JveC1zaGFkb3c6MCA0cHggMTZweCAke3RjLmdsb3dDb2xvcn07fVxuICAgICAgICAgICAgLnRpZXAtbW9kYWwtb2s6aG92ZXJ7dHJhbnNmb3JtOnNjYWxlKDEuMDYpO2JveC1zaGFkb3c6MCAwIDI0cHggJHt0Yy5nbG93Q29sb3J9O31cbiAgICAgICAgYDsKICAgIGRvY3VtZW50LmhlYWQuYXBwZW5kQ2hpbGQobXMpOwogIH0KICBmdW5jdGlvbiBzaG93Q3VzdG9tTW9kYWwoe2ljb246IGljb24sIHRpdGxlOiB0aXRsZSwgbGluZXM6IGxpbmVzLCBvbk9rOiBvbk9rfSkgewogICAgX2Vuc3VyZU1vZGFsU3R5bGUoKTsKICAgIGNvbnN0IGV4aXN0aW5nID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RpZXAtbW9kYWwtb3ZlcmxheScpOwogICAgaWYgKGV4aXN0aW5nKSBleGlzdGluZy5yZW1vdmUoKTsKICAgIGNvbnN0IG92ZXJsYXkgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgIG92ZXJsYXkuaWQgPSAndGllcC1tb2RhbC1vdmVybGF5JzsKICAgIGNvbnN0IGxpbmVzSFRNTCA9IChBcnJheS5pc0FycmF5KGxpbmVzKSA/IGxpbmVzIDogWyBsaW5lcyBdKS5tYXAobCA9PiBgPGRpdj4ke2x9PC9kaXY+YCkuam9pbignJyk7CiAgICBvdmVybGF5LmlubmVySFRNTCA9IGBcbiAgICAgICAgICAgIDxkaXYgY2xhc3M9InRpZXAtbW9kYWwtYm94Ij5cbiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0aWVwLW1vZGFsLWljb24iPiR7aWNvbiB8fCAn4oS577iPJ308L2Rpdj5cbiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0aWVwLW1vZGFsLXRpdGxlIj4ke3RpdGxlIHx8ICdUaMO0bmcgYsOhbyd9PC9kaXY+XG4gICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGllcC1tb2RhbC1saW5lcyI+JHtsaW5lc0hUTUx9PC9kaXY+XG4gICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0idGllcC1tb2RhbC1vayIgaWQ9InRpZXAtbW9kYWwtb2stYnRuIj5PSzwvYnV0dG9uPlxuICAgICAgICAgICAgPC9kaXY+YDsKICAgIGRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQob3ZlcmxheSk7CiAgICBjb25zdCBjbG9zZSA9ICgpID0+IHsKICAgICAgb3ZlcmxheS5yZW1vdmUoKTsKICAgICAgaWYgKG9uT2spIG9uT2soKTsKICAgIH07CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGllcC1tb2RhbC1vay1idG4nKS5vbmNsaWNrID0gY2xvc2U7CiAgICBvdmVybGF5Lm9uY2xpY2sgPSBlID0+IHsKICAgICAgaWYgKGUudGFyZ2V0ID09PSBvdmVybGF5KSBjbG9zZSgpOwogICAgfTsKICB9CiAgZnVuY3Rpb24gc2hvd0NvbmZpcm1Nb2RhbCh7aWNvbjogaWNvbiwgdGl0bGU6IHRpdGxlLCBsaW5lczogbGluZXMsIG9rVGV4dDogb2tUZXh0LCBjYW5jZWxUZXh0OiBjYW5jZWxUZXh0LCBvbk9rOiBvbk9rfSkgewogICAgX2Vuc3VyZU1vZGFsU3R5bGUoKTsKICAgIGNvbnN0IGV4aXN0aW5nID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RpZXAtbW9kYWwtb3ZlcmxheScpOwogICAgaWYgKGV4aXN0aW5nKSBleGlzdGluZy5yZW1vdmUoKTsKICAgIGNvbnN0IG92ZXJsYXkgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgIG92ZXJsYXkuaWQgPSAndGllcC1tb2RhbC1vdmVybGF5JzsKICAgIGNvbnN0IGxpbmVzSFRNTCA9IChBcnJheS5pc0FycmF5KGxpbmVzKSA/IGxpbmVzIDogWyBsaW5lcyBdKS5tYXAobCA9PiBgPGRpdj4ke2x9PC9kaXY+YCkuam9pbignJyk7CiAgICBvdmVybGF5LmlubmVySFRNTCA9IGBcbiAgICAgICAgICAgIDxkaXYgY2xhc3M9InRpZXAtbW9kYWwtYm94Ij5cbiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0aWVwLW1vZGFsLWljb24iPiR7aWNvbiB8fCAn4p2TJ308L2Rpdj5cbiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0aWVwLW1vZGFsLXRpdGxlIj4ke3RpdGxlIHx8ICdYw6FjIG5o4bqtbid9PC9kaXY+XG4gICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGllcC1tb2RhbC1saW5lcyI+JHtsaW5lc0hUTUx9PC9kaXY+XG4gICAgICAgICAgICAgICAgPGRpdiBzdHlsZT0iZGlzcGxheTpmbGV4O2dhcDoxMHB4O2p1c3RpZnktY29udGVudDpjZW50ZXI7Ij5cbiAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0idGllcC1tb2RhbC1vayIgaWQ9InRpZXAtY29uZmlybS1jYW5jZWwtYnRuIiBzdHlsZT0iYmFja2dyb3VuZDpyZ2JhKDI1NSwyNTUsMjU1LDAuMDgpO2JveC1zaGFkb3c6bm9uZTsiPiR7Y2FuY2VsVGV4dCB8fCAnSOG7plknfTwvYnV0dG9uPlxuICAgICAgICAgICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJ0aWVwLW1vZGFsLW9rIiBpZD0idGllcC1jb25maXJtLW9rLWJ0biI+JHtva1RleHQgfHwgJ1jDgUMgTkjhuqxOJ308L2J1dHRvbj5cbiAgICAgICAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICAgIDwvZGl2PmA7CiAgICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKG92ZXJsYXkpOwogICAgY29uc3QgZGlzbWlzcyA9ICgpID0+IG92ZXJsYXkucmVtb3ZlKCk7CiAgICBjb25zdCBjb25maXJtID0gKCkgPT4gewogICAgICBvdmVybGF5LnJlbW92ZSgpOwogICAgICBpZiAob25Paykgb25PaygpOwogICAgfTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0aWVwLWNvbmZpcm0tY2FuY2VsLWJ0bicpLm9uY2xpY2sgPSBkaXNtaXNzOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RpZXAtY29uZmlybS1vay1idG4nKS5vbmNsaWNrID0gY29uZmlybTsKICAgIG92ZXJsYXkub25jbGljayA9IGUgPT4gewogICAgICBpZiAoZS50YXJnZXQgPT09IG92ZXJsYXkpIGRpc21pc3MoKTsKICAgIH07CiAgfQogIGZ1bmN0aW9uIF9lbnN1cmVBbm5vdW5jZVN0eWxlKCkgewogICAgaWYgKGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdfdGwtYW5ub3VuY2Utc3R5bGUnKSkgcmV0dXJuOwogICAgY29uc3Qgc3QgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdzdHlsZScpOwogICAgc3QuaWQgPSAnX3RsLWFubm91bmNlLXN0eWxlJzsKICAgIHN0LnRleHRDb250ZW50ID0gWwogICAgICAiQGtleWZyYW1lcyB0bEFubklue2Zyb217b3BhY2l0eTowO3RyYW5zZm9ybTp0cmFuc2xhdGVZKDE4cHgpIHNjYWxlKC45Nil9dG97b3BhY2l0eToxO3RyYW5zZm9ybTp0cmFuc2xhdGVZKDApIHNjYWxlKDEpfX0iLAogICAgICAiI190bF9hbm5vdW5jZV9vdmVybGF5e3Bvc2l0aW9uOmZpeGVkO2luc2V0OjA7ei1pbmRleDoyMTQ3NDgzNjQ1O2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OmNlbnRlcjtwYWRkaW5nOjIycHg7YmFja2dyb3VuZDpyZ2JhKDYsMTAsMjAsLjcyKTtiYWNrZHJvcC1maWx0ZXI6Ymx1cigxMHB4KTstd2Via2l0LWJhY2tkcm9wLWZpbHRlcjpibHVyKDEwcHgpfSIsCiAgICAgICIudGwtYW5uLWNhcmR7d2lkdGg6MzgwcHg7bWF4LXdpZHRoOjk0dnc7Ym9yZGVyLXJhZGl1czoyMnB4O3BhZGRpbmc6MjZweCAyNHB4IDIycHg7Y29sb3I6I2ZmZjtib3gtc2hhZG93OjAgMjRweCA4MHB4IHJnYmEoMCwwLDAsLjYpO2FuaW1hdGlvbjp0bEFubkluIC4yOHMgZWFzZTtvdmVyZmxvdzpoaWRkZW47cG9zaXRpb246cmVsYXRpdmV9IiwKICAgICAgIi50bC1hbm4tY2FyZDo6YmVmb3Jle2NvbnRlbnQ6Jyc7cG9zaXRpb246YWJzb2x1dGU7aW5zZXQ6MDtiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCgxMzVkZWcscmdiYSgyNTUsMjU1LDI1NSwuMTYpLHRyYW5zcGFyZW50IDU1JSk7cG9pbnRlci1ldmVudHM6bm9uZX0iLAogICAgICAiLnRsLWFubi1pY29ue2ZvbnQtc2l6ZTo0MHB4O2xpbmUtaGVpZ2h0OjE7bWFyZ2luLWJvdHRvbToxMnB4O3RleHQtYWxpZ246Y2VudGVyfSIsCiAgICAgICIudGwtYW5uLXRpdGxle2ZvbnQtZmFtaWx5OidPcmJpdHJvbicsc2Fucy1zZXJpZjtmb250LXdlaWdodDo4MDA7Zm9udC1zaXplOjE1cHg7bGV0dGVyLXNwYWNpbmc6LjRweDt0ZXh0LWFsaWduOmNlbnRlcjttYXJnaW4tYm90dG9tOjEycHh9IiwKICAgICAgIi50bC1hbm4tbXNne2ZvbnQtc2l6ZToxMy41cHg7bGluZS1oZWlnaHQ6MS43O2NvbG9yOnJnYmEoMjU1LDI1NSwyNTUsLjkyKTt3aGl0ZS1zcGFjZTpwcmUtd3JhcDt3b3JkLWJyZWFrOmJyZWFrLXdvcmQ7dGV4dC1hbGlnbjpjZW50ZXI7bWF4LWhlaWdodDo0NnZoO292ZXJmbG93OmF1dG99IiwKICAgICAgIi50bC1hbm4tZm9vdHttYXJnaW4tdG9wOjE4cHg7ZGlzcGxheTpmbGV4O2p1c3RpZnktY29udGVudDpjZW50ZXJ9IiwKICAgICAgIi50bC1hbm4tYnRue2JvcmRlcjpub25lO2JvcmRlci1yYWRpdXM6MTJweDtwYWRkaW5nOjEwcHggMzBweDtmb250LWZhbWlseTonT3JiaXRyb24nLHNhbnMtc2VyaWY7Zm9udC13ZWlnaHQ6ODAwO2ZvbnQtc2l6ZToxMnB4O2NvbG9yOiMwYjEyMjA7Y3Vyc29yOnBvaW50ZXI7Ym94LXNoYWRvdzowIDhweCAyNHB4IHJnYmEoMCwwLDAsLjM1KX0iLAogICAgICAiLnRsLWFubi10YWd7cG9zaXRpb246YWJzb2x1dGU7dG9wOjEycHg7cmlnaHQ6MTRweDtmb250LXNpemU6OXB4O2xldHRlci1zcGFjaW5nOjEuNXB4O29wYWNpdHk6Ljc7dGV4dC10cmFuc2Zvcm06dXBwZXJjYXNlfSIKICAgIF0uam9pbignXG4nKTsKICAgIGRvY3VtZW50LmhlYWQuYXBwZW5kQ2hpbGQoc3QpOwogIH0KICBmdW5jdGlvbiBfc2hvd0Fubm91bmNlKGFubikgewogICAgdHJ5IHsKICAgICAgaWYgKCFhbm4gfHwgIWFubi5tZXNzYWdlKSB7CiAgICAgICAgdmFyIGdvbmUgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnX3RsX2Fubm91bmNlX292ZXJsYXknKTsKICAgICAgICBpZiAoZ29uZSkgZ29uZS5yZW1vdmUoKTsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgdmFyIF9hbm5LZXkgPSAnX3RsX2Fubl9zZWVuX3RzJzsKICAgICAgdmFyIF9zZWVuID0gMDsKICAgICAgdHJ5IHsgX3NlZW4gPSBwYXJzZUludChsb2NhbFN0b3JhZ2UuZ2V0SXRlbShfYW5uS2V5KSB8fCAnMCcsIDEwKSB8fCAwOyB9IGNhdGNoIChfZTApIHt9CiAgICAgIHZhciBfYW5uVHMgPSBhbm4udHMgfHwgMDsKICAgICAgaWYgKF9hbm5UcyAmJiBfYW5uVHMgPD0gX3NlZW4pIHJldHVybjsKICAgICAgX2Vuc3VyZUFubm91bmNlU3R5bGUoKTsKICAgICAgY29uc3Qgb2xkID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ190bF9hbm5vdW5jZV9vdmVybGF5Jyk7CiAgICAgIGlmIChvbGQpIG9sZC5yZW1vdmUoKTsKICAgICAgY29uc3QgbGV2ZWwgPSBhbm4ubGV2ZWwgfHwgJ2luZm8nOwogICAgICBjb25zdCBtZXRhID0gewogICAgICAgIGluZm86ICAgIHsgaWNvbjogJ+KEue+4jycsIHRpdGxlOiBhbm4udGl0bGUgfHwgJ1Row7RuZyBiw6FvJywgZ3JhZDogJ2xpbmVhci1ncmFkaWVudCgxMzVkZWcsIzRmYWNmZSAwJSwjMDBmMmZlIDEwMCUpJywgYnRuOiAnxJDDoyBoaeG7g3UnIH0sCiAgICAgICAgd2FybjogICAgeyBpY29uOiAn4pqg77iPJywgdGl0bGU6IGFubi50aXRsZSB8fCAnQ+G6o25oIGLDoW8nLCBncmFkOiAnbGluZWFyLWdyYWRpZW50KDEzNWRlZywjZjZkMzY1IDAlLCNmZGEwODUgMTAwJSknLCBidG46ICfEkMOjIGhp4buDdScgfSwKICAgICAgICBlcnJvcjogICB7IGljb246ICfim5QnLCB0aXRsZTogYW5uLnRpdGxlIHx8ICdUaMO0bmcgYsOhbyBo4buHIHRo4buRbmcnLCBncmFkOiAnbGluZWFyLWdyYWRpZW50KDEzNWRlZywjZjU1NzZjIDAlLCNmMDkzZmIgMTAwJSknLCBidG46ICfEkMOjIGhp4buDdScgfSwKICAgICAgICBibG9ja2VkOiB7IGljb246ICfwn5qrJywgdGl0bGU6IGFubi50aXRsZSB8fCAnVGjDtG5nIGLDoW8gY2jhurduJywgZ3JhZDogJ2xpbmVhci1ncmFkaWVudCgxMzVkZWcsIzJiMmQ0MiAwJSwjMTExMzFmIDEwMCUpJywgYnRuOiBudWxsIH0KICAgICAgfVtsZXZlbF0gfHwgeyBpY29uOiAn4oS577iPJywgdGl0bGU6IGFubi50aXRsZSB8fCAnVGjDtG5nIGLDoW8nLCBncmFkOiAnbGluZWFyLWdyYWRpZW50KDEzNWRlZywjNGZhY2ZlLCMwMGYyZmUpJywgYnRuOiAnxJDDoyBoaeG7g3UnIH07CiAgICAgIGNvbnN0IG92ZXJsYXkgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgICAgb3ZlcmxheS5pZCA9ICdfdGxfYW5ub3VuY2Vfb3ZlcmxheSc7CiAgICAgIGNvbnN0IGNhcmQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgICAgY2FyZC5jbGFzc05hbWUgPSAndGwtYW5uLWNhcmQnOwogICAgICBjYXJkLnN0eWxlLmJhY2tncm91bmQgPSBtZXRhLmdyYWQ7CiAgICAgIGNvbnN0IHRhZyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpOwogICAgICB0YWcuY2xhc3NOYW1lID0gJ3RsLWFubi10YWcnOwogICAgICB0YWcudGV4dENvbnRlbnQgPSAnU2VydmVyIHRow7RuZyBiw6FvJzsKICAgICAgY29uc3QgaWNvbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpOwogICAgICBpY29uLmNsYXNzTmFtZSA9ICd0bC1hbm4taWNvbic7CiAgICAgIGljb24udGV4dENvbnRlbnQgPSBtZXRhLmljb247CiAgICAgIGNvbnN0IHRpdGxlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICAgIHRpdGxlLmNsYXNzTmFtZSA9ICd0bC1hbm4tdGl0bGUnOwogICAgICB0aXRsZS50ZXh0Q29udGVudCA9IG1ldGEudGl0bGU7CiAgICAgIGNvbnN0IG1zZyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpOwogICAgICBtc2cuY2xhc3NOYW1lID0gJ3RsLWFubi1tc2cnOwogICAgICBtc2cudGV4dENvbnRlbnQgPSBTdHJpbmcoYW5uLm1lc3NhZ2UgfHwgJycpOwogICAgICBjYXJkLmFwcGVuZENoaWxkKHRhZyk7IGNhcmQuYXBwZW5kQ2hpbGQoaWNvbik7IGNhcmQuYXBwZW5kQ2hpbGQodGl0bGUpOyBjYXJkLmFwcGVuZENoaWxkKG1zZyk7CiAgICAgIGlmIChtZXRhLmJ0bikgewogICAgICAgIGNvbnN0IGZvb3QgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgICAgICBmb290LmNsYXNzTmFtZSA9ICd0bC1hbm4tZm9vdCc7CiAgICAgICAgY29uc3QgYnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnYnV0dG9uJyk7CiAgICAgICAgYnRuLmNsYXNzTmFtZSA9ICd0bC1hbm4tYnRuJzsKICAgICAgICBidG4udGV4dENvbnRlbnQgPSBtZXRhLmJ0bjsKICAgICAgICBidG4ub25jbGljayA9IGZ1bmN0aW9uICgpIHsgdHJ5IHsgbG9jYWxTdG9yYWdlLnNldEl0ZW0oX2FubktleSwgU3RyaW5nKF9hbm5UcyB8fCBEYXRlLm5vdygpKSk7IH0gY2F0Y2ggKF9lMSkge30gb3ZlcmxheS5yZW1vdmUoKTsgfTsKICAgICAgICBmb290LmFwcGVuZENoaWxkKGJ0bik7CiAgICAgICAgY2FyZC5hcHBlbmRDaGlsZChmb290KTsKICAgICAgICBvdmVybGF5LmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgZnVuY3Rpb24gKGUpIHsgaWYgKGUudGFyZ2V0ID09PSBvdmVybGF5KSB7IHRyeSB7IGxvY2FsU3RvcmFnZS5zZXRJdGVtKF9hbm5LZXksIFN0cmluZyhfYW5uVHMgfHwgRGF0ZS5ub3coKSkpOyB9IGNhdGNoIChfZTIpIHt9IG92ZXJsYXkucmVtb3ZlKCk7IH0gfSk7CiAgICAgIH0KICAgICAgb3ZlcmxheS5hcHBlbmRDaGlsZChjYXJkKTsKICAgICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChvdmVybGF5KTsKICAgIH0gY2F0Y2ggKF8pIHt9CiAgfQogIGZ1bmN0aW9uIGFwcGx5VGhlbWVMaXZlKG5ld1RoZW1lKSB7CiAgICBDVVJSRU5UX1RIRU1FID0gbmV3VGhlbWU7CiAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShMU19USEVNRSwgbmV3VGhlbWUpOwogICAgY29uc3QgdWlTdHlsZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC11aS1zdHlsZScpOwogICAgaWYgKHVpU3R5bGUpIHVpU3R5bGUudGV4dENvbnRlbnQgPSBnZXRNYWluVUlTdHlsZXMoKTsKICAgIGNvbnN0IGxvY2tTdHlsZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1sb2NrLXN0eWxlJyk7CiAgICBpZiAobG9ja1N0eWxlKSBsb2NrU3R5bGUudGV4dENvbnRlbnQgPSBnZXRMb2NrU2NyZWVuU3R5bGVzKCk7CiAgICBjb25zdCBtcyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0aWVwLW1vZGFsLXN0eWxlJyk7CiAgICBpZiAobXMpIG1zLnJlbW92ZSgpOwogICAgY29uc3QgZmIgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtZmxvYXRCdG4nKTsKICAgIGlmIChmYikgewogICAgICBmYi5zdHlsZS5hbmltYXRpb24gPSAnbm9uZSc7CiAgICAgIHZvaWQgZmIub2Zmc2V0V2lkdGg7CiAgICAgIGZiLnN0eWxlLmFuaW1hdGlvbiA9ICcnOwogICAgfQogICAgY29uc3QgbG9ja1BhbmVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLWNvbm4tcGFuZWwnKTsKICAgIGlmIChsb2NrUGFuZWwpIHsKICAgICAgY29uc3QgZXhpc3RGeCA9IGxvY2tQYW5lbC5xdWVyeVNlbGVjdG9yKCcjdGwtY29ubi1meC1iYXIsI3RsLWNvbm4tZngtcGV0YWxzJyk7CiAgICAgIGlmIChleGlzdEZ4KSBleGlzdEZ4LnJlbW92ZSgpOwogICAgICBjb25zdCB0YyA9IGdldFRoZW1lQ29sb3JzKG5ld1RoZW1lKTsKICAgICAgaWYgKHRjLnBhbmVsRXh0cmEpIHsKICAgICAgICBjb25zdCB0bXAgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgICAgICB0bXAuaW5uZXJIVE1MID0gdGMucGFuZWxFeHRyYTsKICAgICAgICBsb2NrUGFuZWwuaW5zZXJ0QmVmb3JlKHRtcC5maXJzdEVsZW1lbnRDaGlsZCwgbG9ja1BhbmVsLmZpcnN0Q2hpbGQpOwogICAgICB9CiAgICB9CiAgfQogIGxldCBfc2VjU2Vzc2lvbiA9IHsKICAgIHRva2VuOiBudWxsLAogICAgZXhwOiAwLAogICAgZnBIYXNoOiBudWxsLAogICAgc2VxOiAxCiAgfTsKICBsZXQgX2FwaVByZWZpeENhY2hlID0gbnVsbDsKICBsZXQgX2hlYXJ0YmVhdFRpbWVyID0gbnVsbDsKICBsZXQgX2hlYXJ0YmVhdEZhaWwgPSAwOwogIGNvbnN0IF9FTkNfUEZYID0gJ19FNV8nOwogIGZ1bmN0aW9uIF9sc1hvcih2YWx1ZSkgewogICAgaWYgKCF2YWx1ZSkgcmV0dXJuICcnOwogICAgdHJ5IHsKICAgICAgY29uc3QgayA9IGdldEhXSUQoKSArIEFQSV9TRUNSRVQuc2xpY2UoMCwgMTApOwogICAgICBsZXQgciA9ICcnOwogICAgICBmb3IgKGxldCBpID0gMDsgaSA8IHZhbHVlLmxlbmd0aDsgaSsrKSByICs9IFN0cmluZy5mcm9tQ2hhckNvZGUodmFsdWUuY2hhckNvZGVBdChpKSBeIGsuY2hhckNvZGVBdChpICUgay5sZW5ndGgpKTsKICAgICAgcmV0dXJuIF9FTkNfUEZYICsgYnRvYSh1bmVzY2FwZShlbmNvZGVVUklDb21wb25lbnQocikpKTsKICAgIH0gY2F0Y2ggKF8pIHsKICAgICAgcmV0dXJuIHZhbHVlOwogICAgfQogIH0KICBmdW5jdGlvbiBfbHNVbnhvcihlbmNvZGVkKSB7CiAgICBpZiAoIWVuY29kZWQpIHJldHVybiBudWxsOwogICAgaWYgKCFlbmNvZGVkLnN0YXJ0c1dpdGgoX0VOQ19QRlgpKSByZXR1cm4gZW5jb2RlZDsKICAgIHRyeSB7CiAgICAgIGNvbnN0IHYgPSBkZWNvZGVVUklDb21wb25lbnQoZXNjYXBlKGF0b2IoZW5jb2RlZC5zbGljZShfRU5DX1BGWC5sZW5ndGgpKSkpOwogICAgICBjb25zdCBrID0gZ2V0SFdJRCgpICsgQVBJX1NFQ1JFVC5zbGljZSgwLCAxMCk7CiAgICAgIGxldCByID0gJyc7CiAgICAgIGZvciAobGV0IGkgPSAwOyBpIDwgdi5sZW5ndGg7IGkrKykgciArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKHYuY2hhckNvZGVBdChpKSBeIGsuY2hhckNvZGVBdChpICUgay5sZW5ndGgpKTsKICAgICAgcmV0dXJuIHI7CiAgICB9IGNhdGNoIChfKSB7CiAgICAgIHJldHVybiBlbmNvZGVkOwogICAgfQogIH0KICBjb25zdCBfc0xTID0gewogICAgZ2V0OiBrZXkgPT4gewogICAgICB0cnkgewogICAgICAgIHJldHVybiBfbHNVbnhvcihsb2NhbFN0b3JhZ2UuZ2V0SXRlbShrZXkpKTsKICAgICAgfSBjYXRjaCAoXykgewogICAgICAgIHJldHVybiBudWxsOwogICAgICB9CiAgICB9LAogICAgc2V0OiAoa2V5LCB2KSA9PiB7CiAgICAgIHRyeSB7CiAgICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oa2V5LCB2ID8gX2xzWG9yKHYpIDogJycpOwogICAgICB9IGNhdGNoIChfKSB7fQogICAgfSwKICAgIGRlbDoga2V5ID0+IHsKICAgICAgdHJ5IHsKICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShrZXkpOwogICAgICB9IGNhdGNoIChfKSB7fQogICAgfQogIH07CiAgYXN5bmMgZnVuY3Rpb24gX2VuY3J5cHRQYXlsb2FkKGRhdGEsIGhpbnQpIHsKICAgIGNvbnN0IGVuYyA9IG5ldyBUZXh0RW5jb2RlciwgYyA9IF9jcnlwdG9PYmooKTsKICAgIGNvbnN0IGl2ID0gYy5nZXRSYW5kb21WYWx1ZXMobmV3IFVpbnQ4QXJyYXkoMTIpKTsKICAgIGNvbnN0IHRzID0gTWF0aC5mbG9vcihEYXRlLm5vdygpIC8gMWUzKTsKICAgIGNvbnN0IG5vbmNlID0gQXJyYXkuZnJvbShjLmdldFJhbmRvbVZhbHVlcyhuZXcgVWludDhBcnJheSg4KSksIGIgPT4gYi50b1N0cmluZygxNikucGFkU3RhcnQoMiwgJzAnKSkuam9pbignJyk7CiAgICBjb25zdCByYXdLZXkgPSBlbmMuZW5jb2RlKEFQSV9TRUNSRVQgKyAoaGludCB8fCAnJykgKyAodHMgPj4+IDcpLnRvU3RyaW5nKDE2KSk7CiAgICBjb25zdCBiYXNlS2V5ID0gYXdhaXQgYy5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCByYXdLZXksICdQQktERjInLCBmYWxzZSwgWyAnZGVyaXZlQml0cycgXSk7CiAgICBjb25zdCBiaXRzID0gYXdhaXQgYy5zdWJ0bGUuZGVyaXZlQml0cyh7CiAgICAgIG5hbWU6ICdQQktERjInLAogICAgICBzYWx0OiBlbmMuZW5jb2RlKCd0bDVyZXEnICsgbm9uY2UpLAogICAgICBpdGVyYXRpb25zOiAxMjAwLAogICAgICBoYXNoOiAnU0hBLTI1NicKICAgIH0sIGJhc2VLZXksIDI1Nik7CiAgICBjb25zdCBhZXNLZXkgPSBhd2FpdCBjLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGJpdHMsIHsKICAgICAgbmFtZTogJ0FFUy1HQ00nCiAgICB9LCBmYWxzZSwgWyAnZW5jcnlwdCcgXSk7CiAgICBjb25zdCBjdCA9IG5ldyBVaW50OEFycmF5KGF3YWl0IGMuc3VidGxlLmVuY3J5cHQoewogICAgICBuYW1lOiAnQUVTLUdDTScsCiAgICAgIGl2OiBpdgogICAgfSwgYWVzS2V5LCBlbmMuZW5jb2RlKEpTT04uc3RyaW5naWZ5KGRhdGEpKSkpOwogICAgY29uc3QgYjY0ID0gYSA9PiBidG9hKFN0cmluZy5mcm9tQ2hhckNvZGUoLi4uYSkpOwogICAgcmV0dXJuIHsKICAgICAgX2U6IDUsCiAgICAgIGl2OiBiNjQoaXYpLAogICAgICBkOiBiNjQoY3Quc2xpY2UoMCwgLTE2KSksCiAgICAgIHQ6IGI2NChjdC5zbGljZSgtMTYpKSwKICAgICAgdHM6IHRzLAogICAgICBuOiBub25jZQogICAgfTsKICB9CiAgbGV0IF9ndWFyZEFjdGl2ZSA9IGZhbHNlOwogIGxldCBfZ3VhcmRUaW1lciA9IG51bGw7CiAgbGV0IF9ndWFyZEJDID0gbnVsbDsKICBsZXQgX3ByZVNjYW5Ib29rID0gbnVsbDsKICBsZXQgX2hvb2tTdHJpa2UgPSAwOwogIGNvbnN0IF9HVUFSRF9TVEFSVF9UUyA9IERhdGUubm93KCk7CiAgY29uc3QgX0dVQVJEX0xTID0gWyAnX3RsX2Nvbm5fa2V5JywgJ190bF9jb25uX3R5cGUnLCAnX3RsX2Nvbm5fZXhwJywgJ190aWVwX3RoZW1lJywgJ190bF9od2lkJywgJ190bF9ndWFyZF90cycgXTsKICBjb25zdCBfR1VBUkRfVUkgPSBbICd0bC1jb25uLW92ZXJsYXknLCAndGwtcGFuZWwnLCAndGwtZmxvYXRCdG4nLCAndGwtdWktc3R5bGUnLCAndGwtbG9jay1zdHlsZScsICd0aWVwLW1vZGFsLXN0eWxlJywgJ3RpZXAtbW9kYWwtb3ZlcmxheScgXTsKICBmdW5jdGlvbiBfc2hvd0d1YXJkV2FybmluZyhyZWFzb24pIHsgICB9CiAgZnVuY3Rpb24gX3NlbGZEZXN0cnVjdChyZWFzb24pIHsgICB9CiAgbGV0IF9iYW5TdGF0ZSA9IHsKICAgIGFjdGl2ZTogZmFsc2UsCiAgICB0aW1lcjogbnVsbCwKICAgIHJlYXNvbjogJycKICB9OwogIGZ1bmN0aW9uIF9zaG93QmFuU2NyZWVuKHJlYXNvbikgewogICAgY29uc3QgcmVuZGVyID0gKCkgPT4gewogICAgICB0cnkgewogICAgICAgIGNvbnN0IGV4ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ190bF9iYW5fb3ZlcmxheScpOwogICAgICAgIGlmIChleCkgZXgucmVtb3ZlKCk7CiAgICAgICAgY29uc3QgbyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpOwogICAgICAgIG8uaWQgPSAnX3RsX2Jhbl9vdmVybGF5JzsKICAgICAgICBvLnN0eWxlLmNzc1RleHQgPSAncG9zaXRpb246Zml4ZWQhaW1wb3J0YW50O3RvcDowIWltcG9ydGFudDtsZWZ0OjAhaW1wb3J0YW50O3dpZHRoOjEwMHZ3IWltcG9ydGFudDtoZWlnaHQ6MTAwdmghaW1wb3J0YW50O2JhY2tncm91bmQ6cmdiYSgwLDAsMCwwLjk2KSFpbXBvcnRhbnQ7ei1pbmRleDoyMTQ3NDgzNjQ3IWltcG9ydGFudDtkaXNwbGF5OmZsZXghaW1wb3J0YW50O2FsaWduLWl0ZW1zOmNlbnRlciFpbXBvcnRhbnQ7anVzdGlmeS1jb250ZW50OmNlbnRlciFpbXBvcnRhbnQ7Zm9udC1mYW1pbHk6bW9ub3NwYWNlIWltcG9ydGFudDsnOwogICAgICAgIG8uaW5uZXJIVE1MID0gJzxkaXYgc3R5bGU9ImJhY2tncm91bmQ6IzBkMGQwZDtib3JkZXI6MnB4IHNvbGlkICNlZjIzM2M7Ym9yZGVyLXJhZGl1czoxNnB4O3BhZGRpbmc6MzZweCAzMnB4O21heC13aWR0aDo0MzBweDt0ZXh0LWFsaWduOmNlbnRlcjtib3gtc2hhZG93OjAgMCA4MHB4IHJnYmEoMjM5LDM1LDYwLDAuNiksMCAwIDE2MHB4IHJnYmEoMjM5LDM1LDYwLDAuMTUpOyI+JyArICc8ZGl2IHN0eWxlPSJmb250LXNpemU6NTJweDttYXJnaW4tYm90dG9tOjE0cHg7Ij7wn5qoPC9kaXY+JyArICc8c3R5bGU+QGtleWZyYW1lcyBfdGxCbGlua3s1MCV7b3BhY2l0eTowfX0jX3RsX2Jhbl9vdmVybGF5IC5nbGl0Y2h7YW5pbWF0aW9uOl90bEJsaW5rIDAuNzVzIHN0ZXAtZW5kIGluZmluaXRlO308L3N0eWxlPicgKyAnPGRpdiBjbGFzcz0iZ2xpdGNoIiBzdHlsZT0iZm9udC1mYW1pbHk6XCdDb3VyaWVyIE5ld1wnLG1vbm9zcGFjZTtmb250LXNpemU6MTZweDtmb250LXdlaWdodDo5MDA7Y29sb3I6I2VmMjMzYzt0ZXh0LXRyYW5zZm9ybTp1cHBlcmNhc2U7bGV0dGVyLXNwYWNpbmc6M3B4O21hcmdpbi1ib3R0b206MTRweDsiPuKaoCBUaGnhur90IGLhu4sgLyBJUCDEkcOjIGLhu4sga2hvw6E8L2Rpdj4nICsgJzxkaXYgc3R5bGU9ImNvbG9yOnJnYmEoMjU1LDI1NSwyNTUsMC43OCk7Zm9udC1zaXplOjEyLjVweDtsaW5lLWhlaWdodDoxLjk7bWFyZ2luLWJvdHRvbToxNHB4OyI+JyArIChyZWFzb24gfHwgJ1Bow6F0IGhp4buHbiBtw7RpIHRyxrDhu51uZyBraMO0bmcgaOG7o3AgbOG7hy4nKSArICc8YnI+TGnDqm4gaOG7hyBhZG1pbiDEkeG7gyDEkcaw4bujYyBt4bufIGtob8OhLjwvZGl2PicgKyAnPGRpdiBpZD0iX3RsX2Jhbl9zdGF0dXMiIHN0eWxlPSJjb2xvcjojZmZjMTA3O2ZvbnQtc2l6ZToxMS41cHg7bGluZS1oZWlnaHQ6MS44OyI+8J+UhCDEkGFuZyBraeG7g20gdHJhIG3hu5dpIDE1IGdpw6J5Li4uPGJyPkNo4buJIGtoaSA8YiBzdHlsZT0iY29sb3I6IzAwZTY3NjsiPmFkbWluIG3hu58ga2hvw6EgdHJvbmcgcGFuZWwgc2VydmVyPC9iPiBy4buTaSBGNSB0cmFuZyBt4bubaSBkw7luZyBs4bqhaSDEkcaw4bujYy48L2Rpdj4nICsgJzxkaXYgc3R5bGU9ImNvbG9yOnJnYmEoMjM5LDM1LDYwLDAuNDUpO2ZvbnQtc2l6ZTo5cHg7bGV0dGVyLXNwYWNpbmc6MnB4O2ZvbnQtZmFtaWx5OlwnQ291cmllciBOZXdcJyxtb25vc3BhY2U7bWFyZ2luLXRvcDoxNnB4OyI+VEhJw4pOIFRBSSBUw5kgVOG7mEkgLy8gQkFOIExPQ0sgdjcuMCAoQ0jhu4ggQURNSU4gTeG7nik8L2Rpdj4nICsgJzwvZGl2Pic7CiAgICAgICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChvKTsKICAgICAgfSBjYXRjaCAoXykge30KICAgIH07CiAgICBpZiAoZG9jdW1lbnQuYm9keSkgcmVuZGVyKCk7IGVsc2UgZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcignRE9NQ29udGVudExvYWRlZCcsIHJlbmRlcik7CiAgfQogIGZ1bmN0aW9uIF9wdXJnZUNsaWVudFN0YXRlKCkgewogICAgdHJ5IHsKICAgICAgY29uc3Qga2lsbCA9IFtdOwogICAgICBmb3IgKGxldCBpID0gMDsgaSA8IGxvY2FsU3RvcmFnZS5sZW5ndGg7IGkrKykgewogICAgICAgIGNvbnN0IGsgPSBsb2NhbFN0b3JhZ2Uua2V5KGkpOwogICAgICAgIGlmIChrICYmIChrLmluZGV4T2YoJ190bF8nKSA9PT0gMCB8fCBrLmluZGV4T2YoJ190aWVwXycpID09PSAwKSkga2lsbC5wdXNoKGspOwogICAgICB9CiAgICAgIGtpbGwuZm9yRWFjaChrID0+IHsgdHJ5IHsgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oayk7IH0gY2F0Y2ggKF8pIHt9IH0pOwogICAgfSBjYXRjaCAoXykge30KICAgIHRyeSB7CiAgICAgIFsgJ3RsLXBhbmVsJywgJ3RsLWZsb2F0QnRuJywgJ3RsLWNvbm4tb3ZlcmxheScsICd0bC11aS1zdHlsZScsICd0bC1sb2NrLXN0eWxlJywgJ190bF9iYW5fb3ZlcmxheScsICd0aWVwLW1vZGFsLW92ZXJsYXknLCAndGllcC1tb2RhbC1zdHlsZScgXS5mb3JFYWNoKGlkID0+IHsKICAgICAgICBjb25zdCBlbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKGlkKTsKICAgICAgICBpZiAoZWwpIGVsLnJlbW92ZSgpOwogICAgICB9KTsKICAgIH0gY2F0Y2ggKF8pIHt9CiAgICB0cnkgewogICAgICBDVVJSRU5UX0tFWSA9IG51bGw7CiAgICAgIEtFWV9TVEFUVVMgPSB7IHZhbGlkOiBmYWxzZSwgdHlwZTogbnVsbCwgZXhwaXJlc19hdDogbnVsbCB9OwogICAgICBfc2VjU2Vzc2lvbiA9IHsgdG9rZW46IG51bGwsIGV4cDogMCwgZnBIYXNoOiBudWxsLCBzZXE6IDEgfTsKICAgICAgQ1VSUkVOVF9ERVZJQ0UgPSAnJzsKICAgIH0gY2F0Y2ggKF8pIHt9CiAgfQogIGZ1bmN0aW9uIF9iYW5Qb2xsT25jZSgpIHsKICAgIChhc3luYyAoKSA9PiB7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgciA9IGF3YWl0IGdtUG9zdCgnL2xvY2stc3RhdHVzJywgeyBod2lkOiBnZXRIV0lEKCkgfSk7CiAgICAgICAgX3Nob3dBbm5vdW5jZShyICYmIHIuYW5ub3VuY2UpOwogICAgICAgIGlmIChyICYmIChyLnJldm9rZWQgfHwgci5iYW5uZWQpKSB7CiAgICAgICAgICBfcHVyZ2VDbGllbnRTdGF0ZSgpOwogICAgICAgICAgY29uc3QgZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnX3RsX2Jhbl9zdGF0dXMnKTsKICAgICAgICAgIGlmIChlbCkgZWwuaW5uZXJIVE1MID0gJ/CflIQgVGhp4bq/dCBi4buLL0lQIMSRYW5nIGLhu4sga2hvw6Eg4oCUIDxiPmNo4buJIGFkbWluIG3hu58ga2hvw6EgdHJvbmcgcGFuZWwgc2VydmVyPC9iPiBt4bubaSBkw7luZyBs4bqhaSDEkcaw4bujYy4nOwogICAgICAgICAgcmV0dXJuOwogICAgICAgIH0KICAgICAgICBpZiAociAmJiByLmxvY2tlZCA9PT0gZmFsc2UgJiYgIXIuYmFubmVkICYmICFyLnJldm9rZWQpIHsKICAgICAgICAgIF9leGl0QmFuTW9kZSgpOwogICAgICAgICAgcmV0dXJuOwogICAgICAgIH0KICAgICAgICBjb25zdCBlbDIgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnX3RsX2Jhbl9zdGF0dXMnKTsKICAgICAgICBpZiAoZWwyKSBlbDIuaW5uZXJIVE1MID0gJ/CflIQgVuG6q24gxJFhbmcgY2jhu50gYWRtaW4gbeG7nyBraG/DoS4uLiAodOG7sSBraeG7g20gdHJhIGzhuqFpIHNhdSAxNSBnacOieSknOwogICAgICB9IGNhdGNoIChfKSB7CiAgICAgIH0KICAgIH0pKCk7CiAgfQogIGZ1bmN0aW9uIF9lbnRlckJhbk1vZGUocmVhc29uKSB7CiAgICBpZiAoX2JhblN0YXRlLmFjdGl2ZSkgcmV0dXJuOwogICAgX2JhblN0YXRlLmFjdGl2ZSA9IHRydWU7CiAgICBfYmFuU3RhdGUucmVhc29uID0gcmVhc29uIHx8ICcnOwogICAgdHJ5IHsgX3B1cmdlQ2xpZW50U3RhdGUoKTsgfSBjYXRjaCAoXykge30KICAgIHRyeSB7CiAgICAgIGlmIChfaGVhcnRiZWF0VGltZXIpIHsKICAgICAgICBjbGVhckludGVydmFsKF9oZWFydGJlYXRUaW1lcik7CiAgICAgICAgX2hlYXJ0YmVhdFRpbWVyID0gbnVsbDsKICAgICAgfQogICAgfSBjYXRjaCAoXykge30KICAgIHRyeSB7CiAgICAgIGlmIChfZ3VhcmRUaW1lcikgewogICAgICAgIGNsZWFySW50ZXJ2YWwoX2d1YXJkVGltZXIpOwogICAgICAgIF9ndWFyZFRpbWVyID0gbnVsbDsKICAgICAgfQogICAgfSBjYXRjaCAoXykge30KICAgIHRyeSB7CiAgICAgIGlmIChfZ3VhcmRCQykgewogICAgICAgIF9ndWFyZEJDLmNsb3NlKCk7CiAgICAgICAgX2d1YXJkQkMgPSBudWxsOwogICAgICB9CiAgICB9IGNhdGNoIChfKSB7fQogICAgWyAndGwtcGFuZWwnLCAndGwtZmxvYXRCdG4nLCAndGwtY29ubi1vdmVybGF5JywgJ3RpZXAtbW9kYWwtb3ZlcmxheScgXS5mb3JFYWNoKGlkID0+IHsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCBlbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKGlkKTsKICAgICAgICBpZiAoZWwpIGVsLnJlbW92ZSgpOwogICAgICB9IGNhdGNoIChfKSB7fQogICAgfSk7CiAgICBDVVJSRU5UX0tFWSA9IG51bGw7CiAgICBLRVlfU1RBVFVTID0gewogICAgICB2YWxpZDogZmFsc2UsCiAgICAgIHR5cGU6IG51bGwsCiAgICAgIGV4cGlyZXNfYXQ6IG51bGwKICAgIH07CiAgICB0cnkgewogICAgICBfc2VjU2Vzc2lvbiA9IHsKICAgICAgICB0b2tlbjogbnVsbCwKICAgICAgICBleHA6IDAsCiAgICAgICAgZnBIYXNoOiBudWxsLAogICAgICAgIHNlcTogMQogICAgICB9OwogICAgfSBjYXRjaCAoXykge30KICAgIF9zaG93QmFuU2NyZWVuKHJlYXNvbik7CiAgICBfYmFuU3RhdGUudGltZXIgPSBzZXRJbnRlcnZhbChfYmFuUG9sbE9uY2UsIDE1ZTMpOwogICAgc2V0VGltZW91dChfYmFuUG9sbE9uY2UsIDVlMyk7CiAgfQogIGZ1bmN0aW9uIF9leGl0QmFuTW9kZSgpIHsKICAgIGlmICghX2JhblN0YXRlLmFjdGl2ZSkgcmV0dXJuOwogICAgX2JhblN0YXRlLmFjdGl2ZSA9IGZhbHNlOwogICAgdHJ5IHsKICAgICAgaWYgKF9iYW5TdGF0ZS50aW1lcikgewogICAgICAgIGNsZWFySW50ZXJ2YWwoX2JhblN0YXRlLnRpbWVyKTsKICAgICAgICBfYmFuU3RhdGUudGltZXIgPSBudWxsOwogICAgICB9CiAgICB9IGNhdGNoIChfKSB7fQogICAgdHJ5IHsKICAgICAgY29uc3QgZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnX3RsX2Jhbl9vdmVybGF5Jyk7CiAgICAgIGlmIChlbCkgZWwucmVtb3ZlKCk7CiAgICB9IGNhdGNoIChfKSB7fQogICAgc2V0VGltZW91dCgoKSA9PiB7CiAgICAgIHRyeSB7CiAgICAgICAgd2luZG93LmxvY2F0aW9uLnJlbG9hZCgpOwogICAgICB9IGNhdGNoIChfKSB7fQogICAgfSwgODAwKTsKICB9CiAgbGV0IF9yZW1vdGVMb2NrU3RhdGUgPSB7CiAgICBhY3RpdmU6IGZhbHNlLAogICAgdGltZXI6IG51bGwsCiAgICByZWFzb246ICcnLAogICAgcmVwb3J0ZWQ6IGZhbHNlCiAgfTsKICBmdW5jdGlvbiBfcmxTZW5kUmVwb3J0KHJlYXNvbikgeyAgIH0KICBmdW5jdGlvbiBfc2hvd1JlbW90ZUxvY2tTY3JlZW4ocmVhc29uKSB7ICAgfQogIGZ1bmN0aW9uIF9yZW1vdGVMb2NrUG9sbE9uY2UoKSB7ICAgfQogIGZ1bmN0aW9uIF9lbnRlclJlbW90ZUxvY2socmVhc29uKSB7ICAgfQogIGZ1bmN0aW9uIF9leGl0UmVtb3RlTG9jaygpIHsgICB9CiAgZnVuY3Rpb24gX2RldGVjdEhvb2tOb3coKSB7IHJldHVybiBudWxsOyAgIH0KICBmdW5jdGlvbiBfZGV2dG9vbHNPcGVuKCkgewogICAgdHJ5IHsKICAgICAgcmV0dXJuIHdpbmRvdy5vdXRlcldpZHRoIC0gd2luZG93LmlubmVyV2lkdGggPiAxNjAgfHwgd2luZG93Lm91dGVySGVpZ2h0IC0gd2luZG93LmlubmVySGVpZ2h0ID4gMjAwOwogICAgfSBjYXRjaCAoXykgewogICAgICByZXR1cm4gZmFsc2U7CiAgICB9CiAgfQogIF9wcmVTY2FuSG9vayA9IG51bGw7CiAgZnVuY3Rpb24gX2luaXRHdWFyZEJDKCkgewogICAgdHJ5IHsKICAgICAgY29uc3QgY2hOYW1lID0gJ190bHRnXycgKyBBUElfU0VDUkVULnNsaWNlKDAsIDgpOwogICAgICBfZ3VhcmRCQyA9IG5ldyBCcm9hZGNhc3RDaGFubmVsKGNoTmFtZSk7CiAgICAgIF9ndWFyZEJDLm9ubWVzc2FnZSA9IGV2dCA9PiB7CiAgICAgICAgdHJ5IHsKICAgICAgICAgIGlmIChldnQgJiYgZXZ0LmRhdGEgJiYgZXZ0LmRhdGEudCA9PT0gJ1RMX0hCJykge30KICAgICAgICB9IGNhdGNoIChfKSB7fQogICAgICB9OwogICAgICBzZXRUaW1lb3V0KCgpID0+IHsKICAgICAgICB0cnkgewogICAgICAgICAgaWYgKF9ndWFyZEJDKSBfZ3VhcmRCQy5wb3N0TWVzc2FnZSh7CiAgICAgICAgICAgIHQ6ICdUTF9IQicsCiAgICAgICAgICAgIHRzOiBEYXRlLm5vdygpCiAgICAgICAgICB9KTsKICAgICAgICB9IGNhdGNoIChfKSB7fQogICAgICB9LCA3MDApOwogICAgICBzZXRJbnRlcnZhbCgoKSA9PiB7CiAgICAgICAgdHJ5IHsKICAgICAgICAgIGlmIChfZ3VhcmRCQykgX2d1YXJkQkMucG9zdE1lc3NhZ2UoewogICAgICAgICAgICB0OiAnVExfSEInLAogICAgICAgICAgICB0czogRGF0ZS5ub3coKQogICAgICAgICAgfSk7CiAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgfSwgMTVlMyk7CiAgICB9IGNhdGNoIChfKSB7CiAgICAgIF9pbml0R3VhcmRMUygpOwogICAgfQogIH0KICBmdW5jdGlvbiBfaW5pdEd1YXJkTFMoKSB7CiAgICBjb25zdCBUU19LRVkgPSAnX3RsX2d1YXJkX3RzJzsKICAgIGNvbnN0IG5vdyA9IERhdGUubm93KCk7CiAgICBjb25zdCBwcmV2ID0gcGFyc2VJbnQobG9jYWxTdG9yYWdlLmdldEl0ZW0oVFNfS0VZKSB8fCAnMCcpOwogICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oVFNfS0VZLCBub3cudG9TdHJpbmcoKSk7CiAgICBzZXRJbnRlcnZhbCgoKSA9PiB7CiAgICAgIHRyeSB7CiAgICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oVFNfS0VZLCBEYXRlLm5vdygpLnRvU3RyaW5nKCkpOwogICAgICB9IGNhdGNoIChfKSB7fQogICAgfSwgMjUwMCk7CiAgfQogIGZ1bmN0aW9uIF9zdGFydFBlcmlvZGljU2NhbigpIHsgICB9CiAgZnVuY3Rpb24gX2luaXRHdWFyZCgpIHsgICB9CiAgZnVuY3Rpb24gX2NyeXB0b09iaigpIHsKICAgIHJldHVybiB0eXBlb2YgY3J5cHRvICE9PSAndW5kZWZpbmVkJyA/IGNyeXB0byA6IHdpbmRvdy5jcnlwdG87CiAgfQogIGZ1bmN0aW9uIF9qc1NoYTI1NkJ5dGVzKG1zZykgewogICAgZnVuY3Rpb24gcm90cihuLCB4KSB7IHJldHVybiAoeCA+Pj4gbikgfCAoeCA8PCAoMzIgLSBuKSk7IH0KICAgIHZhciBLID0gWzB4NDI4YTJmOTgsMHg3MTM3NDQ5MSwweGI1YzBmYmNmLDB4ZTliNWRiYTUsMHgzOTU2YzI1YiwweDU5ZjExMWYxLDB4OTIzZjgyYTQsMHhhYjFjNWVkNSwweGQ4MDdhYTk4LDB4MTI4MzViMDEsMHgyNDMxODViZSwweDU1MGM3ZGMzLDB4NzJiZTVkNzQsMHg4MGRlYjFmZSwweDliZGMwNmE3LDB4YzE5YmYxNzQsMHhlNDliNjljMSwweGVmYmU0Nzg2LDB4MGZjMTlkYzYsMHgyNDBjYTFjYywweDJkZTkyYzZmLDB4NGE3NDg0YWEsMHg1Y2IwYTlkYywweDc2Zjk4OGRhLDB4OTgzZTUxNTIsMHhhODMxYzY2ZCwweGIwMDMyN2M4LDB4YmY1OTdmYzcsMHhjNmUwMGJmMywweGQ1YTc5MTQ3LDB4MDZjYTYzNTEsMHgxNDI5Mjk2NywweDI3YjcwYTg1LDB4MmUxYjIxMzgsMHg0ZDJjNmRmYywweDUzMzgwZDEzLDB4NjUwYTczNTQsMHg3NjZhMGFiYiwweDgxYzJjOTJlLDB4OTI3MjJjODUsMHhhMmJmZThhMSwweGE4MWE2NjRiLDB4YzI0YjhiNzAsMHhjNzZjNTFhMywweGQxOTJlODE5LDB4ZDY5OTA2MjQsMHhmNDBlMzU4NSwweDEwNmFhMDcwLDB4MTlhNGMxMTYsMHgxZTM3NmMwOCwweDI3NDg3NzRjLDB4MzRiMGJjYjUsMHgzOTFjMGNiMywweDRlZDhhYTRhLDB4NWI5Y2NhNGYsMHg2ODJlNmZmMywweDc0OGY4MmVlLDB4NzhhNTYzNmYsMHg4NGM4NzgxNCwweDhjYzcwMjA4LDB4OTBiZWZmZmEsMHhhNDUwNmNlYiwweGJlZjlhM2Y3LDB4YzY3MTc4ZjJdOwogICAgdmFyIGJ5dGVzID0gQXJyYXkuZnJvbSh0eXBlb2YgbXNnID09PSAnc3RyaW5nJyA/IG5ldyBUZXh0RW5jb2RlcigpLmVuY29kZShtc2cpIDogKEFycmF5LmlzQXJyYXkobXNnKSA/IG1zZyA6IFtdKSk7CiAgICB2YXIgYml0TGVuID0gYnl0ZXMubGVuZ3RoICogODsKICAgIGJ5dGVzID0gYnl0ZXMuc2xpY2UoKTsKICAgIGJ5dGVzLnB1c2goMHg4MCk7CiAgICB3aGlsZSAoYnl0ZXMubGVuZ3RoICUgNjQgIT09IDU2KSBieXRlcy5wdXNoKDApOwogICAgZm9yICh2YXIgaSA9IDc7IGkgPj0gMDsgaS0tKSBieXRlcy5wdXNoKChiaXRMZW4gPj4+IChpICogOCkpICYgMHhmZik7CiAgICB2YXIgSCA9IFsweDZhMDllNjY3LDB4YmI2N2FlODUsMHgzYzZlZjM3MiwweGE1NGZmNTNhLDB4NTEwZTUyN2YsMHg5YjA1Njg4YywweDFmODNkOWFiLDB4NWJlMGNkMTldOwogICAgZm9yICh2YXIgYmxvY2sgPSAwOyBibG9jayA8IGJ5dGVzLmxlbmd0aDsgYmxvY2sgKz0gNjQpIHsKICAgICAgdmFyIFcgPSBbXTsKICAgICAgZm9yICh2YXIgdCA9IDA7IHQgPCAxNjsgdCsrKSBXW3RdID0gKChieXRlc1tibG9jayArIHQgKiA0XSA8PCAyNCkgfCAoYnl0ZXNbYmxvY2sgKyB0ICogNCArIDFdIDw8IDE2KSB8IChieXRlc1tibG9jayArIHQgKiA0ICsgMl0gPDwgOCkgfCBieXRlc1tibG9jayArIHQgKiA0ICsgM10pID4+PiAwOwogICAgICBmb3IgKHQgPSAxNjsgdCA8IDY0OyB0KyspIHsKICAgICAgICB2YXIgczAgPSByb3RyKDcsIFdbdCAtIDE1XSkgXiByb3RyKDE4LCBXW3QgLSAxNV0pIF4gKFdbdCAtIDE1XSA+Pj4gMyk7CiAgICAgICAgdmFyIHMxID0gcm90cigxNywgV1t0IC0gMl0pIF4gcm90cigxOSwgV1t0IC0gMl0pIF4gKFdbdCAtIDJdID4+PiAxMCk7CiAgICAgICAgV1t0XSA9IChXW3QgLSAxNl0gKyBzMCArIFdbdCAtIDddICsgczEpIHwgMDsKICAgICAgfQogICAgICB2YXIgYSA9IEhbMF0sIGIgPSBIWzFdLCBjID0gSFsyXSwgZCA9IEhbM10sIGUgPSBIWzRdLCBmID0gSFs1XSwgZyA9IEhbNl0sIGggPSBIWzddOwogICAgICBmb3IgKHQgPSAwOyB0IDwgNjQ7IHQrKykgewogICAgICAgIHZhciBTMSA9IHJvdHIoNiwgZSkgXiByb3RyKDExLCBlKSBeIHJvdHIoMjUsIGUpOwogICAgICAgIHZhciBjaCA9IChlICYgZikgXiAoKH5lKSAmIGcpOwogICAgICAgIHZhciB0MSA9IChoICsgUzEgKyBjaCArIEtbdF0gKyBXW3RdKSB8IDA7CiAgICAgICAgdmFyIFMwID0gcm90cigyLCBhKSBeIHJvdHIoMTMsIGEpIF4gcm90cigyMiwgYSk7CiAgICAgICAgdmFyIG1haiA9IChhICYgYikgXiAoYSAmIGMpIF4gKGIgJiBjKTsKICAgICAgICB2YXIgdDIgPSAoUzAgKyBtYWopIHwgMDsKICAgICAgICBoID0gZzsgZyA9IGY7IGYgPSBlOyBlID0gKGQgKyB0MSkgfCAwOyBkID0gYzsgYyA9IGI7IGIgPSBhOyBhID0gKHQxICsgdDIpIHwgMDsKICAgICAgfQogICAgICBIWzBdID0gKEhbMF0gKyBhKSB8IDA7IEhbMV0gPSAoSFsxXSArIGIpIHwgMDsgSFsyXSA9IChIWzJdICsgYykgfCAwOyBIWzNdID0gKEhbM10gKyBkKSB8IDA7CiAgICAgIEhbNF0gPSAoSFs0XSArIGUpIHwgMDsgSFs1XSA9IChIWzVdICsgZikgfCAwOyBIWzZdID0gKEhbNl0gKyBnKSB8IDA7IEhbN10gPSAoSFs3XSArIGgpIHwgMDsKICAgIH0KICAgIHJldHVybiBILm1hcChmdW5jdGlvbih4KSB7CiAgICAgIHZhciBzID0gJyc7CiAgICAgIGZvciAodmFyIGJiID0gMDsgYmIgPCA0OyBiYisrKSBzICs9ICgoeCA+Pj4gKDI0IC0gYmIgKiA4KSkgJiAweGZmKS50b1N0cmluZygxNikucGFkU3RhcnQoMiwgJzAnKTsKICAgICAgcmV0dXJuIHM7CiAgICB9KS5qb2luKCcnKTsKICB9CiAgZnVuY3Rpb24gX2pzSG1hY0hleChrZXlTdHIsIG1zZ1N0cikgewogICAgdmFyIGVuYyA9IG5ldyBUZXh0RW5jb2RlcigpOwogICAgdmFyIGtleSA9IEFycmF5LmZyb20oZW5jLmVuY29kZShTdHJpbmcoa2V5U3RyIHx8ICcnKSkpOwogICAgaWYgKGtleS5sZW5ndGggPiA2NCkgewogICAgICB2YXIgaCA9IF9qc1NoYTI1NkJ5dGVzKGtleSk7CiAgICAgIGtleSA9IFtdOwogICAgICBmb3IgKHZhciBpID0gMDsgaSA8IDMyOyBpKyspIGtleS5wdXNoKHBhcnNlSW50KGguc3Vic3RyKGkgKiAyLCAyKSwgMTYpKTsKICAgIH0KICAgIHdoaWxlIChrZXkubGVuZ3RoIDwgNjQpIGtleS5wdXNoKDApOwogICAgdmFyIGlwYWQgPSBrZXkubWFwKGZ1bmN0aW9uKGIpIHsgcmV0dXJuIGIgXiAweDM2OyB9KTsKICAgIHZhciBvcGFkID0ga2V5Lm1hcChmdW5jdGlvbihiKSB7IHJldHVybiBiIF4gMHg1YzsgfSk7CiAgICB2YXIgaW5uZXJIZXggPSBfanNTaGEyNTZCeXRlcyhpcGFkLmNvbmNhdChBcnJheS5mcm9tKGVuYy5lbmNvZGUoU3RyaW5nKG1zZ1N0ciB8fCAnJykpKSkpOwogICAgdmFyIGlubmVyQnl0ZXMgPSBbXTsKICAgIGZvciAodmFyIGogPSAwOyBqIDwgMzI7IGorKykgaW5uZXJCeXRlcy5wdXNoKHBhcnNlSW50KGlubmVySGV4LnN1YnN0cihqICogMiwgMiksIDE2KSk7CiAgICByZXR1cm4gX2pzU2hhMjU2Qnl0ZXMob3BhZC5jb25jYXQoaW5uZXJCeXRlcykpOwogIH0KICBhc3luYyBmdW5jdGlvbiBfaG1hY0hleChzZWNyZXQsIHN0cikgewogICAgY29uc3QgZW5jID0gbmV3IFRleHRFbmNvZGVyLCBjID0gX2NyeXB0b09iaigpOwogICAgdHJ5IHsKICAgICAgaWYgKGMgJiYgYy5zdWJ0bGUpIHsKICAgICAgICBjb25zdCBrZXkgPSBhd2FpdCBjLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGVuYy5lbmNvZGUoc2VjcmV0KSwgeyBuYW1lOiAnSE1BQycsIGhhc2g6ICdTSEEtMjU2JyB9LCBmYWxzZSwgWyAnc2lnbicgXSk7CiAgICAgICAgY29uc3Qgc2lnID0gYXdhaXQgYy5zdWJ0bGUuc2lnbignSE1BQycsIGtleSwgZW5jLmVuY29kZShzdHIpKTsKICAgICAgICByZXR1cm4gQXJyYXkuZnJvbShuZXcgVWludDhBcnJheShzaWcpKS5tYXAoYiA9PiBiLnRvU3RyaW5nKDE2KS5wYWRTdGFydCgyLCAnMCcpKS5qb2luKCcnKTsKICAgICAgfQogICAgfSBjYXRjaCAoXykge30KICAgIHJldHVybiBfanNIbWFjSGV4KHNlY3JldCwgc3RyKTsKICB9CiAgYXN5bmMgZnVuY3Rpb24gX2FwaVByZWZpeCgpIHsKICAgIGlmICghX2FwaVByZWZpeENhY2hlKSBfYXBpUHJlZml4Q2FjaGUgPSAnLycgKyAoYXdhaXQgX2htYWNIZXgoQVBJX1NFQ1JFVCwgJ2dvZG1vZGU6YXBpOnByZWZpeDp2NCcpKS5zbGljZSgwLCAxMik7CiAgICByZXR1cm4gX2FwaVByZWZpeENhY2hlOwogIH0KICBhc3luYyBmdW5jdGlvbiBfc2lnblJlcShib2R5U3RyLCBzZXNzaW9uVG9rKSB7CiAgICBjb25zdCBjID0gX2NyeXB0b09iaigpLCBlbmMgPSBuZXcgVGV4dEVuY29kZXI7CiAgICBjb25zdCB0cyA9IE1hdGguZmxvb3IoRGF0ZS5ub3coKSAvIDFlMykudG9TdHJpbmcoKTsKICAgIGxldCBub25jZSA9ICcnOwogICAgdHJ5IHsgbm9uY2UgPSBBcnJheS5mcm9tKGMuZ2V0UmFuZG9tVmFsdWVzKG5ldyBVaW50OEFycmF5KDgpKSwgYiA9PiBiLnRvU3RyaW5nKDE2KS5wYWRTdGFydCgyLCAnMCcpKS5qb2luKCcnKTsgfSBjYXRjaCAoXykgewogICAgICBub25jZSA9IEFycmF5LmZyb20obmV3IFVpbnQ4QXJyYXkoOCksIGZ1bmN0aW9uKCkgeyByZXR1cm4gTWF0aC5mbG9vcihNYXRoLnJhbmRvbSgpICogMjU2KS50b1N0cmluZygxNikucGFkU3RhcnQoMiwgJzAnKTsgfSkuam9pbignJyk7CiAgICB9CiAgICBsZXQgYm9keUhhc2ggPSAnJywgc2lnbiA9ICcnLCBzdWJ0bGVPayA9IGZhbHNlOwogICAgdHJ5IHsKICAgICAgaWYgKGMgJiYgYy5zdWJ0bGUpIHsKICAgICAgICBjb25zdCBib2R5SGFzaEJ1ZiA9IGF3YWl0IGMuc3VidGxlLmRpZ2VzdCgnU0hBLTI1NicsIGVuYy5lbmNvZGUoYm9keVN0ciB8fCAnJykpOwogICAgICAgIGJvZHlIYXNoID0gQXJyYXkuZnJvbShuZXcgVWludDhBcnJheShib2R5SGFzaEJ1ZikpLm1hcChiID0+IGIudG9TdHJpbmcoMTYpLnBhZFN0YXJ0KDIsICcwJykpLmpvaW4oJycpOwogICAgICAgIGNvbnN0IGhtYWNLZXkgPSBhd2FpdCBjLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGVuYy5lbmNvZGUoQVBJX1NFQ1JFVCksIHsgbmFtZTogJ0hNQUMnLCBoYXNoOiAnU0hBLTI1NicgfSwgZmFsc2UsIFsgJ3NpZ24nIF0pOwogICAgICAgIGNvbnN0IHNpZ0J1ZiA9IGF3YWl0IGMuc3VidGxlLnNpZ24oJ0hNQUMnLCBobWFjS2V5LCBlbmMuZW5jb2RlKHRzICsgJ3wnICsgbm9uY2UgKyAnfCcgKyBib2R5SGFzaCArICd8JyArIChzZXNzaW9uVG9rIHx8ICcnKSkpOwogICAgICAgIHNpZ24gPSBBcnJheS5mcm9tKG5ldyBVaW50OEFycmF5KHNpZ0J1ZikpLm1hcChiID0+IGIudG9TdHJpbmcoMTYpLnBhZFN0YXJ0KDIsICcwJykpLmpvaW4oJycpOwogICAgICAgIHN1YnRsZU9rID0gdHJ1ZTsKICAgICAgfQogICAgfSBjYXRjaCAoXykge30KICAgIGlmICghc3VidGxlT2spIHsKICAgICAgYm9keUhhc2ggPSBfanNTaGEyNTZCeXRlcyhib2R5U3RyIHx8ICcnKTsKICAgICAgc2lnbiA9IF9qc0htYWNIZXgoQVBJX1NFQ1JFVCwgdHMgKyAnfCcgKyBub25jZSArICd8JyArIGJvZHlIYXNoICsgJ3wnICsgKHNlc3Npb25Ub2sgfHwgJycpKTsKICAgIH0KICAgIHJldHVybiB7ICdYLVRzJzogdHMsICdYLU5vbmNlJzogbm9uY2UsICdYLVNpZ24nOiBzaWduIH07CiAgfQogIGZ1bmN0aW9uIF9jb2xsZWN0RGV2aWNlKCkgewogICAgY29uc3QgdWEgPSBuYXZpZ2F0b3IudXNlckFnZW50IHx8ICcnOwogICAgY29uc3QgaXNBbmRyb2lkID0gL2FuZHJvaWQvaS50ZXN0KHVhKTsKICAgIGNvbnN0IGlzSU9TID0gL2lwaG9uZXxpcGFkfGlwb2QvaS50ZXN0KHVhKTsKICAgIGxldCBtb2RlbCA9ICcnOwogICAgaWYgKGlzQW5kcm9pZCkgewogICAgICBjb25zdCBtID0gdWEubWF0Y2goLztccyooW147KV0rPylccytCdWlsZFwvL2kpIHx8IHVhLm1hdGNoKC9hbmRyb2lkXHMrW147KV0rO1xzKihbXjspXSspL2kpOwogICAgICBtb2RlbCA9IG0gPyBtWzFdLnRyaW0oKSA6ICcnOwogICAgfSBlbHNlIGlmIChpc0lPUykgewogICAgICBtb2RlbCA9IC9pcGFkL2kudGVzdCh1YSkgPyAnaVBhZCcgOiAvaXBvZC9pLnRlc3QodWEpID8gJ2lQb2QnIDogJ2lQaG9uZSc7CiAgICAgIGlmICgvZm9jdXMvaS50ZXN0KHVhKSkgbW9kZWwgKz0gJyAoRm9jdXMpJzsKICAgIH0KICAgIGNvbnN0IGNvbm4gPSBuYXZpZ2F0b3IuY29ubmVjdGlvbiB8fCBuYXZpZ2F0b3IubW96Q29ubmVjdGlvbiB8fCBuYXZpZ2F0b3Iud2Via2l0Q29ubmVjdGlvbjsKICAgIHJldHVybiB7CiAgICAgIG9zOiBpc0FuZHJvaWQgPyAnQW5kcm9pZCcgOiBpc0lPUyA/ICdpT1MnIDogbmF2aWdhdG9yLnBsYXRmb3JtIHx8ICdVbmtub3duJywKICAgICAgbW9kZWw6IG1vZGVsIHx8ICcnLAogICAgICBicmFuZDogJycsCiAgICAgIGlzTW9iaWxlOiBpc0FuZHJvaWQgfHwgaXNJT1MsCiAgICAgIHRvdWNoUG9pbnRzOiBuYXZpZ2F0b3IubWF4VG91Y2hQb2ludHMgfHwgMCwKICAgICAgY29yZXM6IG5hdmlnYXRvci5oYXJkd2FyZUNvbmN1cnJlbmN5IHx8IDAsCiAgICAgIG1lbW9yeTogbmF2aWdhdG9yLmRldmljZU1lbW9yeSB8fCAwLAogICAgICBzY3JlZW46IGAke3NjcmVlbi53aWR0aH14JHtzY3JlZW4uaGVpZ2h0fWAsCiAgICAgIHBpeGVsUmF0aW86IHdpbmRvdy5kZXZpY2VQaXhlbFJhdGlvIHx8IDEsCiAgICAgIGNvbm5lY3Rpb246IGNvbm4gPyBjb25uLmVmZmVjdGl2ZVR5cGUgfHwgJycgOiAnJywKICAgICAgdmVuZG9yOiBuYXZpZ2F0b3IudmVuZG9yIHx8ICcnLAogICAgICBsYW5ndWFnZTogbmF2aWdhdG9yLmxhbmd1YWdlIHx8ICcnLAogICAgICB0aW1lem9uZTogSW50bC5EYXRlVGltZUZvcm1hdCgpLnJlc29sdmVkT3B0aW9ucygpLnRpbWVab25lIHx8ICcnLAogICAgICB3ZWJkcml2ZXI6ICEhbmF2aWdhdG9yLndlYmRyaXZlcgogICAgfTsKICB9CiAgZnVuY3Rpb24gX2NvbGxlY3RGUCgpIHsKICAgIHJldHVybiB7CiAgICAgIHVhOiBuYXZpZ2F0b3IudXNlckFnZW50LAogICAgICBwbGF0Zm9ybTogbmF2aWdhdG9yLnBsYXRmb3JtIHx8ICcnLAogICAgICBsYW5ndWFnZTogbmF2aWdhdG9yLmxhbmd1YWdlIHx8ICcnLAogICAgICB0aW1lem9uZTogSW50bC5EYXRlVGltZUZvcm1hdCgpLnJlc29sdmVkT3B0aW9ucygpLnRpbWVab25lIHx8ICcnLAogICAgICB3ZWJkcml2ZXI6ICEhbmF2aWdhdG9yLndlYmRyaXZlciwKICAgICAgaGFyZHdhcmVDb25jdXJyZW5jeTogbmF2aWdhdG9yLmhhcmR3YXJlQ29uY3VycmVuY3kgfHwgMCwKICAgICAgZGV2aWNlTWVtb3J5OiBuYXZpZ2F0b3IuZGV2aWNlTWVtb3J5IHx8IDAsCiAgICAgIG1heFRvdWNoUG9pbnRzOiBuYXZpZ2F0b3IubWF4VG91Y2hQb2ludHMgfHwgMCwKICAgICAgc2NyZWVuOiBgJHtzY3JlZW4ud2lkdGh9eCR7c2NyZWVuLmhlaWdodH1gLAogICAgICBjb2xvckRlcHRoOiBzY3JlZW4uY29sb3JEZXB0aCwKICAgICAgcGl4ZWxSYXRpbzogd2luZG93LmRldmljZVBpeGVsUmF0aW8gfHwgMQogICAgfTsKICB9CiAgZnVuY3Rpb24gX2NvbGxlY3RFbnYoKSB7CiAgICBjb25zdCBlbnYgPSB7fTsKICAgIHRyeSB7CiAgICAgIGNvbnN0IG5hdGl2ZVNyYyA9IEZ1bmN0aW9uLnByb3RvdHlwZS50b1N0cmluZzsKICAgICAgZW52Lnhockhvb2tlZCA9IG5hdGl2ZVNyYy5jYWxsKFhNTEh0dHBSZXF1ZXN0LnByb3RvdHlwZS5vcGVuKS5pbmRleE9mKCdbbmF0aXZlIGNvZGVdJykgPT09IC0xCiAgICAgICAgfHwgbmF0aXZlU3JjLmNhbGwoWE1MSHR0cFJlcXVlc3QucHJvdG90eXBlLnNlbmQpLmluZGV4T2YoJ1tuYXRpdmUgY29kZV0nKSA9PT0gLTE7CiAgICAgIGVudi5mZXRjaEhvb2tlZCA9ICh0eXBlb2YgZmV0Y2ggPT09ICdmdW5jdGlvbicpICYmIG5hdGl2ZVNyYy5jYWxsKGZldGNoKS5pbmRleE9mKCdbbmF0aXZlIGNvZGVdJykgPT09IC0xOwogICAgICBlbnYuZ21MZWFrID0gT2JqZWN0LmdldE93blByb3BlcnR5TmFtZXMod2luZG93KS5zb21lKGZ1bmN0aW9uIChuKSB7IHJldHVybiAvXkdNX3xeZ21fLy50ZXN0KG4pOyB9KTsKICAgICAgZW52LmRldnRvb2xzID0gKHdpbmRvdy5vdXRlcldpZHRoICYmIHdpbmRvdy5pbm5lcldpZHRoICYmIE1hdGguYWJzKHdpbmRvdy5vdXRlcldpZHRoIC0gd2luZG93LmlubmVyV2lkdGgpID4gMTYwKQogICAgICAgIHx8ICh3aW5kb3cub3V0ZXJIZWlnaHQgJiYgd2luZG93LmlubmVySGVpZ2h0ICYmIE1hdGguYWJzKHdpbmRvdy5vdXRlckhlaWdodCAtIHdpbmRvdy5pbm5lckhlaWdodCkgPiAxNjApOwogICAgICB0cnkgewogICAgICAgIGNvbnN0IHQwID0gcGVyZm9ybWFuY2Uubm93KCk7CiAgICAgICAgZGVidWdnZXI7CiAgICAgICAgaWYgKHBlcmZvcm1hbmNlLm5vdygpIC0gdDAgPiA4MCkgZW52LmRldnRvb2xzID0gdHJ1ZTsKICAgICAgfSBjYXRjaCAoXykge30KICAgIH0gY2F0Y2ggKF8pIHt9CiAgICByZXR1cm4gZW52OwogIH0KICBhc3luYyBmdW5jdGlvbiBfZGVyaXZlS2V5KHNlc3Npb25Ub2tlbikgewogICAgY29uc3QgZW5jID0gbmV3IFRleHRFbmNvZGVyLCBjID0gX2NyeXB0b09iaigpOwogICAgY29uc3QgYmFzZUtleSA9IGF3YWl0IGMuc3VidGxlLmltcG9ydEtleSgncmF3JywgZW5jLmVuY29kZSgoc2Vzc2lvblRva2VuIHx8ICcnKSArICd8JyArIEFQSV9TRUNSRVQpLCAnUEJLREYyJywgZmFsc2UsIFsgJ2Rlcml2ZUJpdHMnIF0pOwogICAgY29uc3QgYml0cyA9IGF3YWl0IGMuc3VidGxlLmRlcml2ZUJpdHMoewogICAgICBuYW1lOiAnUEJLREYyJywKICAgICAgc2FsdDogZW5jLmVuY29kZSgnZ29kbW9kZS12NC1zYWx0JyksCiAgICAgIGl0ZXJhdGlvbnM6IDFlMywKICAgICAgaGFzaDogJ1NIQS0yNTYnCiAgICB9LCBiYXNlS2V5LCAyNTYpOwogICAgcmV0dXJuIGMuc3VidGxlLmltcG9ydEtleSgncmF3JywgYml0cywgewogICAgICBuYW1lOiAnQUVTLUdDTScKICAgIH0sIGZhbHNlLCBbICdkZWNyeXB0JyBdKTsKICB9CiAgZnVuY3Rpb24gX2I2NFRvQnl0ZXMoYjY0KSB7CiAgICBjb25zdCBiaW4gPSBhdG9iKGI2NCk7CiAgICByZXR1cm4gVWludDhBcnJheS5mcm9tKGJpbiwgeCA9PiB4LmNoYXJDb2RlQXQoMCkpOwogIH0KICBhc3luYyBmdW5jdGlvbiBfZGVjcnlwdEFuc3dlcnMocGF5bG9hZCwgc2Vzc2lvblRva2VuKSB7CiAgICBjb25zdCBjID0gX2NyeXB0b09iaigpOwogICAgY29uc3Qga2V5ID0gYXdhaXQgX2Rlcml2ZUtleShzZXNzaW9uVG9rZW4pOwogICAgY29uc3QgaXYgPSBfYjY0VG9CeXRlcyhwYXlsb2FkLml2KSwgZGF0YSA9IF9iNjRUb0J5dGVzKHBheWxvYWQuZGF0YSksIHRhZyA9IF9iNjRUb0J5dGVzKHBheWxvYWQudGFnKTsKICAgIGNvbnN0IGJ1ZiA9IG5ldyBVaW50OEFycmF5KGRhdGEubGVuZ3RoICsgdGFnLmxlbmd0aCk7CiAgICBidWYuc2V0KGRhdGEpOwogICAgYnVmLnNldCh0YWcsIGRhdGEubGVuZ3RoKTsKICAgIGNvbnN0IHBsYWluID0gYXdhaXQgYy5zdWJ0bGUuZGVjcnlwdCh7CiAgICAgIG5hbWU6ICdBRVMtR0NNJywKICAgICAgaXY6IGl2CiAgICB9LCBrZXksIGJ1Zik7CiAgICByZXR1cm4gSlNPTi5wYXJzZSgobmV3IFRleHREZWNvZGVyKS5kZWNvZGUocGxhaW4pKTsKICB9CiAgYXN5bmMgZnVuY3Rpb24gX2Vuc3VyZVNlc3Npb24oa2V5LCBod2lkKSB7CiAgICBpZiAoX3NlY1Nlc3Npb24udG9rZW4gJiYgX3NlY1Nlc3Npb24uZXhwID4gRGF0ZS5ub3coKSkgcmV0dXJuIF9zZWNTZXNzaW9uLnRva2VuOwogICAgaWYgKCFrZXkpIHRocm93IG5ldyBFcnJvcignVGhp4bq/dSBrZXkg4oCUIGtow7RuZyB0aOG7gyB4w6FjIHRo4buxYyBwaGnDqm4nKTsKICAgIGNvbnN0IHIgPSBhd2FpdCBnbVBvc3QoJy9hdHRlc3QnLCB7CiAgICAgIGtleToga2V5LAogICAgICBod2lkOiBod2lkIHx8IGdldEhXSUQoKSwKICAgICAgZnA6IF9jb2xsZWN0RlAoKSwKICAgICAgZGV2aWNlOiBfY29sbGVjdERldmljZSgpLAogICAgICBlbnY6IF9jb2xsZWN0RW52KCksCiAgICAgIGNsaWVudFZlcnNpb246IDM5LAogICAgICBjb25uZWN0b3JWZXJzaW9uOiAzOQogICAgfSk7CiAgICBpZiAoIXIuc3VjY2VzcykgdGhyb3cgbmV3IEVycm9yKHIubWVzc2FnZSB8fCByLmVycm9yIHx8ICdYw6FjIHRo4buxYyB0aGnhur90IGLhu4svbeG6oW5nIHRo4bqldCBi4bqhaSAoSFRUUCAnICsgKHIuX2h0dHBTdGF0dXMgfHwgMCkgKyAnKSDigJQgeGVtIHBhbmVsIGFkbWluIGxvZyDEkeG7gyBiaeG6v3QgbMO9IGRvKScpOwogICAgX3Nob3dBbm5vdW5jZShyICYmIHIuYW5ub3VuY2UpOwogICAgX3NlY1Nlc3Npb24gPSB7CiAgICAgIHRva2VuOiByLnNlc3Npb24sCiAgICAgIGV4cDogRGF0ZS5ub3coKSArIChyLmV4cGlyZXNJbiAtIDMwKSAqIDFlMywKICAgICAgZnBIYXNoOiByLmZwSGFzaCwKICAgICAgc2VxOiAxCiAgICB9OwogICAgaWYgKHIuZGV2aWNlKSBDVVJSRU5UX0RFVklDRSA9IHIuZGV2aWNlOwogICAgcmV0dXJuIHIuc2Vzc2lvbjsKICB9CiAgZnVuY3Rpb24gX3N0YXJ0SGVhcnRiZWF0KCkgewogICAgaWYgKF9oZWFydGJlYXRUaW1lcikgcmV0dXJuOwogICAgX2hlYXJ0YmVhdFRpbWVyID0gc2V0SW50ZXJ2YWwoYXN5bmMgKCkgPT4gewogICAgICBpZiAoIUNVUlJFTlRfS0VZKSByZXR1cm47CiAgICAgIGxldCByID0gbnVsbDsKICAgICAgdHJ5IHsKICAgICAgICByID0gYXdhaXQgZ21Qb3N0KCcvaGVhcnRiZWF0JywgewogICAgICAgICAga2V5OiBDVVJSRU5UX0tFWSwKICAgICAgICAgIGh3aWQ6IGdldEhXSUQoKSwKICAgICAgICAgIGZwOiBfY29sbGVjdEZQKCksCiAgICAgICAgICBkZXZpY2U6IF9jb2xsZWN0RGV2aWNlKCksCiAgICAgICAgICBlbnY6IF9jb2xsZWN0RW52KCksCiAgICAgICAgICBjbGllbnRWZXJzaW9uOiAzOSwKICAgICAgICAgIGNvbm5lY3RvclZlcnNpb246IDM5CiAgICAgICAgfSk7CiAgICAgIH0gY2F0Y2ggKGUpIHsKICAgICAgICBfaGVhcnRiZWF0RmFpbCsrOwogICAgICAgIGlmIChfaGVhcnRiZWF0RmFpbCA+PSAxMCkgewogICAgICAgICAgYWRkTG9nKCfimqDvuI8gTeG6oW5nIHnhur91L23huqV0IGvhur90IG7hu5FpIHNlcnZlciDigJQgZ2nhu68gbmd1ecOqbiBwaGnDqm4sIHThu7EgdGjhu60gbOG6oWkgbmjhu4twIHNhdSAoa2jDtG5nIHBo4bqjaSBiYW4sIGtow7RuZyB4b8OhIGtleSkuJywgJ3dhcm4nKTsKICAgICAgICAgIF9oZWFydGJlYXRGYWlsID0gMDsKICAgICAgICB9CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIGlmIChyICYmIHIucmV2b2tlZCkgewogICAgICAgIF9wdXJnZUNsaWVudFN0YXRlKCk7CiAgICAgICAgX2VudGVyQmFuTW9kZSgnU2VydmVyIHRodSBo4buTaSBxdXnhu4FuOiB0aGnhur90IGLhu4svSVAgxJHDoyBi4buLIGFkbWluIGtob8OhLicpOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBfaGVhcnRiZWF0RmFpbCA9IDA7CiAgICAgIGlmIChyICYmIHIuYmxvY2tlZCkgewogICAgICAgIF9wdXJnZUNsaWVudFN0YXRlKCk7CiAgICAgICAgX2VudGVyQmFuTW9kZSgnU2VydmVyIHBow6F0IGhp4buHbiBtw7RpIHRyxrDhu51uZyBraMO0bmcgaOG7o3AgbOG7hyAoJyArIChyLnJlYXNvbiB8fCAndW5rbm93bicpICsgJykuJyk7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIGlmIChyICYmIChyLl9odHRwU3RhdHVzID09PSA0MDQgfHwgci5faHR0cFN0YXR1cyA9PT0gNDAzICYmIHIucmV2b2tlZCkpIHsKICAgICAgICBfcHVyZ2VDbGllbnRTdGF0ZSgpOwogICAgICAgIF9lbnRlckJhbk1vZGUoJ1RoaeG6v3QgYuG7iy9JUCDEkcOjIGLhu4sgYWRtaW4ga2hvw6EuJyk7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIF9zaG93QW5ub3VuY2UociAmJiByLmFubm91bmNlKTsKICAgIH0sIDE1ZTMpOwogIH0KICBhc3luYyBmdW5jdGlvbiBnbVBvc3QocGF0aCwgZGF0YSkgewogICAgY29uc3QgaGVhZGVycyA9IHsKICAgICAgJ0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi9qc29uJwogICAgfTsKICAgIGxldCBzZXNzaW9uVG9rZW4gPSBudWxsOwogICAgY29uc3QgcHJlZml4ID0gYXdhaXQgX2FwaVByZWZpeCgpOwogICAgY29uc3QgYWN0dWFsUGF0aCA9IHByZWZpeCArIHBhdGg7CiAgICBpZiAocGF0aCA9PT0gJy9wcm9jZXNzJyB8fCBwYXRoID09PSAnL2ZpcmUnIHx8IHBhdGggPT09ICcvbW9kdWxlJyB8fCBwYXRoID09PSAnL2Fuc3dlcnMvbG9va3VwJyB8fCBwYXRoID09PSAnL2Fuc2ZpbGUvZGVjb2RlJykgewogICAgICB0cnkgewogICAgICAgIHNlc3Npb25Ub2tlbiA9IGF3YWl0IF9lbnN1cmVTZXNzaW9uKGRhdGEgJiYgZGF0YS5rZXksIGRhdGEgJiYgZGF0YS5od2lkKTsKICAgICAgICBoZWFkZXJzWydYLVNlc3Npb24nXSA9IHNlc3Npb25Ub2tlbjsKICAgICAgICBoZWFkZXJzWydYLVNlcSddID0gU3RyaW5nKF9zZWNTZXNzaW9uLnNlcSB8fCAxKTsKICAgICAgICBpZiAoX3NlY1Nlc3Npb24uZnBIYXNoKSBoZWFkZXJzWydYLUZwLUhhc2gnXSA9IF9zZWNTZXNzaW9uLmZwSGFzaDsKICAgICAgfSBjYXRjaCAoX3Nlc3NFcnIpIHsKICAgICAgICBpZiAocGF0aCAhPT0gJy9hbnN3ZXJzL2xvb2t1cCcpIHRocm93IF9zZXNzRXJyOwogICAgICAgIGRlbGV0ZSBoZWFkZXJzWydYLVNlc3Npb24nXTsKICAgICAgfQogICAgfQogICAgbGV0IHJlcUJvZHkgPSBKU09OLnN0cmluZ2lmeShkYXRhKTsKICAgIGlmIChSRVFVRVNUX0VOQ1JZUFRJT04pIHsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCBlbmMgPSBhd2FpdCBfZW5jcnlwdFBheWxvYWQoZGF0YSwgc2Vzc2lvblRva2VuIHx8IF9hcGlQcmVmaXhDYWNoZSB8fCAnJyk7CiAgICAgICAgcmVxQm9keSA9IEpTT04uc3RyaW5naWZ5KGVuYyk7CiAgICAgICAgaGVhZGVyc1snWC1FbmMtViddID0gJzUnOwogICAgICB9IGNhdGNoIChfKSB7fQogICAgfQogICAgdHJ5IHsKICAgICAgT2JqZWN0LmFzc2lnbihoZWFkZXJzLCBhd2FpdCBfc2lnblJlcShyZXFCb2R5LCBzZXNzaW9uVG9rZW4pKTsKICAgIH0gY2F0Y2ggKF8pIHt9CiAgICBjb25zdCBNQVhfUkVUUlkgPSBwYXRoID09PSAnL2hlYXJ0YmVhdCcgPyAzIDogMjsKICAgIGxldCByZXN1bHQgPSBudWxsOwogICAgZm9yIChsZXQgYXR0ZW1wdCA9IDA7IGF0dGVtcHQgPD0gTUFYX1JFVFJZOyBhdHRlbXB0KyspIHsKICAgICAgdHJ5IHsKICAgICAgICByZXN1bHQgPSBhd2FpdCBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7CiAgICAgICAgICBfeGhyQ2FsbCh7CiAgICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLAogICAgICAgICAgICB1cmw6IFNFUlZFUl9CQVNFICsgYWN0dWFsUGF0aCwKICAgICAgICAgICAgaGVhZGVyczogaGVhZGVycywKICAgICAgICAgICAgZGF0YTogcmVxQm9keSwKICAgICAgICAgICAgdGltZW91dDogYXR0ZW1wdCA9PT0gMCA/IDEyZTMgOiA4ZTMsCiAgICAgICAgICAgIG9ubG9hZDogciA9PiB7CiAgICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgIGNvbnN0IHBhcnNlZCA9IEpTT04ucGFyc2Uoci5yZXNwb25zZVRleHQpOwogICAgICAgICAgICAgICAgcGFyc2VkLl9odHRwU3RhdHVzID0gci5zdGF0dXM7CiAgICAgICAgICAgICAgICByZXNvbHZlKHBhcnNlZCk7CiAgICAgICAgICAgICAgfSBjYXRjaCAoXykgewogICAgICAgICAgICAgICAgcmVqZWN0KG5ldyBFcnJvcignUGFyc2UgZXJyb3IgKEhUVFAgJyArIHIuc3RhdHVzICsgJyknKSk7CiAgICAgICAgICAgICAgfQogICAgICAgICAgICB9LAogICAgICAgICAgICBvbmVycm9yOiAoKSA9PiByZWplY3QobmV3IEVycm9yKCdOZXR3b3JrIGVycm9yJykpLAogICAgICAgICAgICBvbnRpbWVvdXQ6ICgpID0+IHJlamVjdChuZXcgRXJyb3IoJ1RpbWVvdXQnKSkKICAgICAgICAgIH0pOwogICAgICAgIH0pOwogICAgICAgIGlmIChyZXN1bHQgJiYgcmVzdWx0Ll9odHRwU3RhdHVzID49IDUwMCAmJiByZXN1bHQuX2h0dHBTdGF0dXMgPCA2MDAgJiYgYXR0ZW1wdCA8IE1BWF9SRVRSWSkgewogICAgICAgICAgYXdhaXQgbmV3IFByb21pc2UocjIgPT4gc2V0VGltZW91dChyMiwgMTIwMCAqIChhdHRlbXB0ICsgMSkpKTsKICAgICAgICAgIGNvbnRpbnVlOwogICAgICAgIH0KICAgICAgICBicmVhazsKICAgICAgfSBjYXRjaCAoZSkgewogICAgICAgIGlmIChhdHRlbXB0IDwgTUFYX1JFVFJZKSB7CiAgICAgICAgICBhd2FpdCBuZXcgUHJvbWlzZShyMiA9PiBzZXRUaW1lb3V0KHIyLCAxMjAwICogKGF0dGVtcHQgKyAxKSkpOwogICAgICAgICAgY29udGludWU7CiAgICAgICAgfQogICAgICAgIHRocm93IGU7CiAgICAgIH0KICAgIH0KICAgIGlmIChwYXRoID09PSAnL3Byb2Nlc3MnICYmIHJlc3VsdCAmJiByZXN1bHQuZW5jcnlwdGVkICYmIHJlc3VsdC5wYXlsb2FkICYmIHNlc3Npb25Ub2tlbikgewogICAgICB0cnkgewogICAgICAgIHJlc3VsdC5xdWVzdGlvbnMgPSBhd2FpdCBfZGVjcnlwdEFuc3dlcnMocmVzdWx0LnBheWxvYWQsIHNlc3Npb25Ub2tlbik7CiAgICAgICAgcmVzdWx0LmVuY3J5cHRlZCA9IGZhbHNlOwogICAgICB9IGNhdGNoIChlKSB7CiAgICAgICAgcmVzdWx0LnN1Y2Nlc3MgPSBmYWxzZTsKICAgICAgICByZXN1bHQubWVzc2FnZSA9ICdHaeG6o2kgbcOjIMSRw6FwIMOhbiB0aOG6pXQgYuG6oWk6ICcgKyBlLm1lc3NhZ2U7CiAgICAgIH0KICAgIH0KICAgIGlmIChyZXN1bHQgJiYgcmVzdWx0Lm5leHRfc2Vzc2lvbikgewogICAgICBfc2VjU2Vzc2lvbi50b2tlbiA9IHJlc3VsdC5uZXh0X3Nlc3Npb247CiAgICAgIF9zZWNTZXNzaW9uLmV4cCA9IERhdGUubm93KCkgKyAyNzAgKiAxZTM7CiAgICAgIF9zZWNTZXNzaW9uLnNlcSA9IHJlc3VsdC5uZXh0X3NlcSA/IHBhcnNlSW50KHJlc3VsdC5uZXh0X3NlcSwgMTApIDogKF9zZWNTZXNzaW9uLnNlcSB8fCAxKSArIDE7CiAgICAgIGRlbGV0ZSByZXN1bHQubmV4dF9zZXNzaW9uOwogICAgICBkZWxldGUgcmVzdWx0Lm5leHRfc2VxOwogICAgfQogICAgcmV0dXJuIHJlc3VsdDsKICB9CiAgZnVuY3Rpb24gZ2V0VXNlckluZm8oKSB7CiAgICB0cnkgewogICAgICBjb25zdCBtID0gZG9jdW1lbnQuY29va2llLm1hdGNoKC8oPzpefDsgKXVzZXI9KFteO10qKS8pOwogICAgICBpZiAobSAmJiBtWzFdKSB7CiAgICAgICAgY29uc3QgcGFyc2VkID0gSlNPTi5wYXJzZShkZWNvZGVVUklDb21wb25lbnQobVsxXSkpOwogICAgICAgIGlmIChwYXJzZWQgJiYgKHBhcnNlZC5faWQgfHwgcGFyc2VkLmlkKSkgcmV0dXJuIHBhcnNlZDsKICAgICAgfQogICAgfSBjYXRjaCAoXykge30KICAgIHRyeSB7CiAgICAgIHJldHVybiB3aW5kb3cudXNlcl9pbmZvIHx8IHdpbmRvdy5wX2NvbmZpZz8udXNlcl9pbmZvIHx8IHVuc2FmZVdpbmRvdz8udXNlcl9pbmZvIHx8IG51bGw7CiAgICB9IGNhdGNoIChfKSB7CiAgICAgIHJldHVybiBudWxsOwogICAgfQogIH0KICBmdW5jdGlvbiBfbm9ybU9sbU5hbWUocykgewogICAgcmV0dXJuIFN0cmluZyhzID09IG51bGwgPyAnJyA6IHMpLnRyaW0oKS5yZXBsYWNlKC9zKy9nLCAnICcpOwogIH0KICBmdW5jdGlvbiBfcmVhZE9sbURvbSgpIHsKICAgIHRyeSB7CiAgICAgIGNvbnN0IHNlbHMgPSBbCiAgICAgICAgJyNpbmZvLWFjY291bnQgaW5wdXQuZm9ybS1jb250cm9sW3JlYWRvbmx5XScsCiAgICAgICAgJyNpbmZvLWFjY291bnQgaW5wdXQnLAogICAgICAgICcudXNlci1uYW1lIC5uYW1lJywgJy51c2VybmFtZSAubmFtZScsICcuYWNjb3VudC1uYW1lJywKICAgICAgICAnW2NsYXNzKj0idXNlck5hbWUiXScsICdbY2xhc3MqPSJVc2VyTmFtZSJdJywgJ1tjbGFzcyo9ImFjY291bnQtbmFtZSJdJywKICAgICAgICAnaGVhZGVyIC5hdmF0YXIgfiBzcGFuJywgJy5oZWFkZXItdXNlciAubmFtZScsICcudGJwLXVzZXItbmFtZScsICcudXNlci1pbmZvLW5hbWUnCiAgICAgIF07CiAgICAgIGZvciAobGV0IGsgPSAwOyBrIDwgc2Vscy5sZW5ndGg7IGsrKykgewogICAgICAgIGNvbnN0IGVsID0gZG9jdW1lbnQucXVlcnlTZWxlY3RvcihzZWxzW2tdKTsKICAgICAgICBpZiAoIWVsKSBjb250aW51ZTsKICAgICAgICBjb25zdCByYXcgPSBlbC52YWx1ZSAhPSBudWxsID8gZWwudmFsdWUgOiBlbC50ZXh0Q29udGVudDsKICAgICAgICBjb25zdCB2ID0gX25vcm1PbG1OYW1lKHJhdyk7CiAgICAgICAgaWYgKHYgJiYgdi5sZW5ndGggPj0gMiAmJiB2Lmxlbmd0aCA8PSA4MCAmJiAhL14oxJHEg25nIG5o4bqtcHzEkcSDbmcgbmjhuq1wcyokfGxvZ2luKSQvaS50ZXN0KHYpKSByZXR1cm4gdjsKICAgICAgfQogICAgfSBjYXRjaCAoXykge30KICAgIHJldHVybiAnJzsKICB9CiAgZnVuY3Rpb24gZ2V0T2xtVXNlcm5hbWUoKSB7CiAgICB0cnkgewogICAgICBjb25zdCBtID0gZG9jdW1lbnQuY29va2llLm1hdGNoKC8oPzpefDsgKXVzZXI9KFteO10qKS8pOwogICAgICBpZiAobSAmJiBtWzFdKSB7CiAgICAgICAgdHJ5IHsKICAgICAgICAgIGNvbnN0IHAgPSBKU09OLnBhcnNlKGRlY29kZVVSSUNvbXBvbmVudChtWzFdKSk7CiAgICAgICAgICBpZiAocCkgewogICAgICAgICAgICBjb25zdCB2ID0gcC51c2VybmFtZSB8fCBwLm5hbWUgfHwgcC5mdWxsX25hbWUgfHwgcC5lbWFpbCB8fCBwLm5pY2tuYW1lOwogICAgICAgICAgICBpZiAodikgcmV0dXJuIF9ub3JtT2xtTmFtZSh2KTsKICAgICAgICAgIH0KICAgICAgICB9IGNhdGNoIChfKSB7fQogICAgICB9CiAgICAgIGxldCB1aSA9IG51bGw7CiAgICAgIHRyeSB7IHVpID0gd2luZG93LnVzZXJfaW5mbyB8fCAod2luZG93LnBfY29uZmlnICYmIHdpbmRvdy5wX2NvbmZpZy51c2VyX2luZm8pIHx8ICh0eXBlb2YgdW5zYWZlV2luZG93ICE9PSAndW5kZWZpbmVkJyAmJiB1bnNhZmVXaW5kb3cudXNlcl9pbmZvKSB8fCBudWxsOyB9IGNhdGNoIChfKSB7fQogICAgICBpZiAodWkpIHsKICAgICAgICBjb25zdCB2ID0gdWkudXNlcm5hbWUgfHwgdWkubmFtZSB8fCB1aS5mdWxsX25hbWUgfHwgdWkuZW1haWwgfHwgdWkubmlja25hbWU7CiAgICAgICAgaWYgKHYpIHJldHVybiBfbm9ybU9sbU5hbWUodik7CiAgICAgIH0KICAgICAgdHJ5IHsKICAgICAgICBjb25zdCBwYyA9IHdpbmRvdy5wX2NvbmZpZyB8fCB7fTsKICAgICAgICBjb25zdCBwdiA9IHBjLnVzZXJuYW1lIHx8IHBjLm5hbWUgfHwgcGMuZnVsbF9uYW1lIHx8IHBjLmVtYWlsOwogICAgICAgIGlmIChwdikgcmV0dXJuIF9ub3JtT2xtTmFtZShwdik7CiAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgIGNvbnN0IGQgPSBfcmVhZE9sbURvbSgpOwogICAgICBpZiAoZCkgcmV0dXJuIGQ7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgdiA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdvbG1fdXNlcicpIHx8IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCd1c2VybmFtZScpIHx8IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCd1c2VyX25hbWUnKTsKICAgICAgICBpZiAodikgcmV0dXJuIF9ub3JtT2xtTmFtZSh2KTsKICAgICAgfSBjYXRjaCAoXykge30KICAgIH0gY2F0Y2ggKF8pIHt9CiAgICByZXR1cm4gJ0tob25nWGFjRGluaCc7CiAgfQogIGZ1bmN0aW9uIGdldEhXSUQoKSB7CiAgICBsZXQgaCA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdfdGxfaHdpZCcpOwogICAgaWYgKCFoKSB7CiAgICAgIGNvbnN0IHVhID0gbmF2aWdhdG9yLnVzZXJBZ2VudCArIG5hdmlnYXRvci5sYW5ndWFnZSArIHNjcmVlbi53aWR0aCArIHNjcmVlbi5oZWlnaHQ7CiAgICAgIGxldCBoYXNoID0gNTM4MTsKICAgICAgZm9yIChsZXQgaSA9IDA7IGkgPCB1YS5sZW5ndGg7IGkrKykgaGFzaCA9IChoYXNoIDw8IDUpICsgaGFzaCBeIHVhLmNoYXJDb2RlQXQoaSk7CiAgICAgIGggPSAnSFcnICsgTWF0aC5hYnMoaGFzaCkudG9TdHJpbmcoMTYpLnRvVXBwZXJDYXNlKCkucGFkU3RhcnQoOCwgJzAnKTsKICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oJ190bF9od2lkJywgaCk7CiAgICB9CiAgICByZXR1cm4gaDsKICB9CiAgZnVuY3Rpb24gcmlwSWRGcm9tVXJsKCkgewogICAgY29uc3QgbSA9IHdpbmRvdy5sb2NhdGlvbi5wYXRobmFtZS5tYXRjaCgvLShcZCspKD86XD98XC98JCkvKTsKICAgIHJldHVybiBtID8gbVsxXSA6IG51bGw7CiAgfQogIGZ1bmN0aW9uIGRldGVjdFVzZXJJRCgpIHsKICAgIGNvbnN0IHVpID0gZ2V0VXNlckluZm8oKTsKICAgIHJldHVybiBTRVNTSU9OLm1ldGEuaWRfdXNlciB8fCAodWkgPyB1aS5faWQgfHwgdWkuaWQgOiBudWxsKSB8fCB3aW5kb3c/LnBfY29uZmlnPy5pZF91c2VyIHx8IG51bGw7CiAgfQogIGZ1bmN0aW9uIGRldGVjdFNjaG9vbElEKGRhdGEpIHsKICAgIHJldHVybiBkYXRhPy5pZF9zY2hvb2wgfHwgd2luZG93Py5wX2NvbmZpZz8uc2Nob29sX2lkIHx8IGdldFVzZXJJbmZvKCk/LmlkX3NjaG9vbCB8fCBudWxsOwogIH0KICBmdW5jdGlvbiBkZXRlY3RHcm91cElEKCkgewogICAgY29uc3QgbSA9IHdpbmRvdy5sb2NhdGlvbi5ocmVmLm1hdGNoKC9cL2xvcFwvW14vXStcLihcZCspLyk7CiAgICByZXR1cm4gbSAmJiBtWzFdID8gbVsxXSA6IG51bGw7CiAgfQogIGZ1bmN0aW9uIGZvcmNlR2V0TWV0YSgpIHsKICAgIGNvbnN0IHVpID0gZ2V0VXNlckluZm8oKTsKICAgIGlmICghU0VTU0lPTi5tZXRhLmlkX3VzZXIpIFNFU1NJT04ubWV0YS5pZF91c2VyID0gdWkgJiYgKHVpLl9pZCB8fCB1aS5pZCkgfHwgd2luZG93Py5wX2NvbmZpZz8uaWRfdXNlciB8fCBkZXRlY3RVc2VySUQoKTsKICAgIGlmICghU0VTU0lPTi5tZXRhLmlkX2NhdGUpIFNFU1NJT04ubWV0YS5pZF9jYXRlID0gd2luZG93Py5wX2NvbmZpZz8uaWRfY2F0ZSB8fCB3aW5kb3c/LnBfY29uZmlnPy5pZF9leGFtIHx8IG5ldyBVUkxTZWFyY2hQYXJhbXMod2luZG93LmxvY2F0aW9uLnNlYXJjaCkuZ2V0KCdpZF9jYXRlJykgfHwgbmV3IFVSTFNlYXJjaFBhcmFtcyh3aW5kb3cubG9jYXRpb24uc2VhcmNoKS5nZXQoJ2lkX2V4YW0nKSB8fCByaXBJZEZyb21VcmwoKTsKICAgIGlmICghU0VTU0lPTi5tZXRhLmlkX2NvdXJzZXdhcmUpIFNFU1NJT04ubWV0YS5pZF9jb3Vyc2V3YXJlID0gbmV3IFVSTFNlYXJjaFBhcmFtcyh3aW5kb3cubG9jYXRpb24uc2VhcmNoKS5nZXQoJ2lfYycpIHx8IG5ldyBVUkxTZWFyY2hQYXJhbXMod2luZG93LmxvY2F0aW9uLnNlYXJjaCkuZ2V0KCdpZF9jb3Vyc2V3YXJlJykgfHwgU0VTU0lPTi5tZXRhLmlkX2NhdGU7CiAgICBpZiAoIVNFU1NJT04ubWV0YS5pZF9zY2hvb2wpIFNFU1NJT04ubWV0YS5pZF9zY2hvb2wgPSB1aSAmJiB1aS5pZF9zY2hvb2wgfHwgd2luZG93Py5wX2NvbmZpZz8uc2Nob29sX2lkIHx8IG51bGw7CiAgICBpZiAoIVNFU1NJT04ubWV0YS5jc3JmX3Rva2VuKSB7CiAgICAgIGNvbnN0IG0gPSBkb2N1bWVudC5xdWVyeVNlbGVjdG9yKCdtZXRhW25hbWU9ImNzcmYtdG9rZW4iXScpOwogICAgICBTRVNTSU9OLm1ldGEuY3NyZl90b2tlbiA9IG0gPyBtLmdldEF0dHJpYnV0ZSgnY29udGVudCcpIDogd2luZG93LmNzcmZfdG9rZW4gfHwgJyc7CiAgICB9CiAgICBpZiAoIVNFU1NJT04ubWV0YS5zdWJqZWN0X25hbWUpIFNFU1NJT04ubWV0YS5zdWJqZWN0X25hbWUgPSBkZXRlY3RTdWJqZWN0TmFtZSgpOwogICAgaWYgKCFTRVNTSU9OLm1ldGEuZXhlcmNpc2VfdGl0bGUpIFNFU1NJT04ubWV0YS5leGVyY2lzZV90aXRsZSA9IGRldGVjdEV4ZXJjaXNlVGl0bGUoKTsKICB9CiAgY29uc3QgS05PV05fU1VCSkVDVFMgPSBbCiAgICAnxJDhu4thIGzDrScsICfEkOG7i2EgbMO9JywgJ1Rp4bq/bmcgQW5oJywgJ1Rvw6FuJywgJ05n4buvIHbEg24nLCAnVsSDbicsICdW4bqtdCBsw60nLCAnVuG6rXQgbMO9JywKICAgICdIw7NhIGjhu41jJywgJ0hvw6EgaOG7jWMnLCAnU2luaCBo4buNYycsICdM4buLY2ggc+G7rScsICdHacOhbyBk4bulYyBjw7RuZyBkw6JuJywgJ0dEQ0QnLAogICAgJ1RpbiBo4buNYycsICdDw7RuZyBuZ2jhu4cnLCAnw4JtIG5o4bqhYycsICdN4bu5IHRodeG6rXQnLCAnVGjhu4MgZOG7pWMnLCAnS2hvYSBo4buNYyB04buxIG5oacOqbicsCiAgICAnVGnhur9uZyBWaeG7h3QnLCAnVOG7sSBuaGnDqm4gdsOgIHjDoyBo4buZaScsICdM4buLY2ggc+G7rSB2w6AgxJDhu4thIGzDrScsICfEkOG6oW8gxJHhu6ljJywKICAgICdQaMOybmcgdGjhu6cgdsOgIGFuIG5pbmggcXXhu5FjIHBow7JuZycKICBdOwogIGZ1bmN0aW9uIF9ub3JtVGV4dChzKSB7CiAgICByZXR1cm4gU3RyaW5nKHMgfHwgJycpLnRvTG93ZXJDYXNlKCkKICAgICAgLm5vcm1hbGl6ZSgnTkZEJykucmVwbGFjZSgvW1x1MDMwMC1cdTAzNmZdL2csICcnKQogICAgICAucmVwbGFjZSgvxJEvZywgJ2QnKS5yZXBsYWNlKC9bXmEtejAtOVxzXS9nLCAnICcpLnJlcGxhY2UoL1xzKy9nLCAnICcpLnRyaW0oKTsKICB9CiAgZnVuY3Rpb24gZGV0ZWN0U3ViamVjdE5hbWUoKSB7CiAgICB0cnkgewogICAgICBjb25zdCBwYyA9IHdpbmRvdy5wX2NvbmZpZyB8fCB7fTsKICAgICAgY29uc3QgY2FuZCA9IFtwYy5zdWJqZWN0X25hbWUsIHBjLnN1YmplY3QsIHBjLmNhdGVfbmFtZSwgcGMuY2F0ZV90aXRsZSwgcGMuc3ViamVjdF9jb2RlLCBwYy5uYW1lXTsKICAgICAgZm9yIChjb25zdCBjIG9mIGNhbmQpIHsKICAgICAgICBjb25zdCB2ID0gKGMgPT0gbnVsbCA/ICcnIDogU3RyaW5nKGMpKS50cmltKCk7CiAgICAgICAgaWYgKHYgJiYgdi5sZW5ndGggPD0gODApIHJldHVybiB2OwogICAgICB9CiAgICB9IGNhdGNoIChfKSB7fQogICAgdHJ5IHsKICAgICAgY29uc3Qgc2VsID0gWydbY2xhc3MqPSJzdWJqZWN0LW5hbWUiXScsICdbY2xhc3MqPSJzdWJqZWN0TmFtZSJdJywgJ1tjbGFzcyo9ImNhdGUtbmFtZSJdJywgJ1tjbGFzcyo9ImNhdGVOYW1lIl0nLCAnLmJhZGdlLXN1YmplY3QnLCAnLnRhZy1zdWJqZWN0JywgJ1tjbGFzcyo9ImJhZGdlLWNhdGUiXScsICdbY2xhc3MqPSJwaWxsLXN1YmplY3QiXScsICdbY2xhc3MqPSJ0YWctY2F0ZSJdJ107CiAgICAgIGZvciAoY29uc3QgcyBvZiBzZWwpIHsKICAgICAgICBjb25zdCBlbCA9IGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3Iocyk7CiAgICAgICAgaWYgKGVsKSB7CiAgICAgICAgICBjb25zdCB2ID0gKGVsLnRleHRDb250ZW50IHx8ICcnKS50cmltKCkucmVwbGFjZSgvXHMrL2csICcgJyk7CiAgICAgICAgICBpZiAodiAmJiB2Lmxlbmd0aCA8PSA2MCkgcmV0dXJuIHY7CiAgICAgICAgfQogICAgICB9CiAgICB9IGNhdGNoIChfKSB7fQogICAgdHJ5IHsKICAgICAgY29uc3Qgbm9kZXMgPSBkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCdoMSxoMixoMyxoNCwudGl0bGUsLmV4YW0tdGl0bGUsLnByYWN0aWNlLXRpdGxlLC5leGVyY2lzZS10aXRsZSwubGVzc29uLXRpdGxlLFtjbGFzcyo9ImJhZGdlIl0sW2NsYXNzKj0iY2hpcCJdLFtjbGFzcyo9InRhZyJdJyk7CiAgICAgIGNvbnN0IGhheSA9IFtdOwogICAgICBub2Rlcy5mb3JFYWNoKG4gPT4geyBjb25zdCB0ID0gKG4udGV4dENvbnRlbnQgfHwgJycpLnRyaW0oKTsgaWYgKHQgJiYgdC5sZW5ndGggPCAxMjApIGhheS5wdXNoKHQpOyB9KTsKICAgICAgaGF5LnB1c2goZG9jdW1lbnQudGl0bGUgfHwgJycpOwogICAgICBmb3IgKGNvbnN0IHN1Ymogb2YgS05PV05fU1VCSkVDVFMpIHsKICAgICAgICBjb25zdCBrID0gX25vcm1UZXh0KHN1YmopOwogICAgICAgIGlmICghaykgY29udGludWU7CiAgICAgICAgZm9yIChjb25zdCB0IG9mIGhheSkgeyBpZiAoX25vcm1UZXh0KHQpLmluY2x1ZGVzKGspKSByZXR1cm4gc3ViajsgfQogICAgICB9CiAgICB9IGNhdGNoIChfKSB7fQogICAgcmV0dXJuICcnOwogIH0KICBmdW5jdGlvbiBkZXRlY3RFeGVyY2lzZVRpdGxlKCkgewogICAgdHJ5IHsKICAgICAgY29uc3QgcGMgPSB3aW5kb3cucF9jb25maWcgfHwge307CiAgICAgIGNvbnN0IGNhbmQgPSBbcGMudGl0bGUsIHBjLmV4ZXJjaXNlX3RpdGxlLCBwYy5leGFtX25hbWUsIHBjLmV4ZXJjaXNlX25hbWUsIHBjLnRlc3RfdGl0bGUsIHBjLmNvdXJzZXdhcmVfdGl0bGUsIHBjLm5hbWVdOwogICAgICBmb3IgKGNvbnN0IGMgb2YgY2FuZCkgewogICAgICAgIGNvbnN0IHYgPSAoYyA9PSBudWxsID8gJycgOiBTdHJpbmcoYykpLnRyaW0oKTsKICAgICAgICBpZiAodiAmJiB2Lmxlbmd0aCA8PSAzMDApIHJldHVybiB2OwogICAgICB9CiAgICB9IGNhdGNoIChfKSB7fQogICAgdHJ5IHsKICAgICAgY29uc3Qgbm9kZXMgPSBkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCdoMSwuZXhhbS10aXRsZSwucHJhY3RpY2UtdGl0bGUsLmV4ZXJjaXNlLXRpdGxlLC5sZXNzb24tdGl0bGUsLmNhcmQtdGl0bGUsW2NsYXNzKj0idGl0bGUtbWFpbiJdLFtjbGFzcyo9Imxlc3Nvbi1uYW1lIl0nKTsKICAgICAgbGV0IGJlc3QgPSAnJzsKICAgICAgbm9kZXMuZm9yRWFjaChuID0+IHsgY29uc3QgdCA9IChuLnRleHRDb250ZW50IHx8ICcnKS50cmltKCkucmVwbGFjZSgvXHMrL2csICcgJyk7IGlmICh0ICYmIHQubGVuZ3RoID4gYmVzdC5sZW5ndGggJiYgdC5sZW5ndGggPD0gMzAwKSBiZXN0ID0gdDsgfSk7CiAgICAgIGlmIChiZXN0KSByZXR1cm4gYmVzdDsKICAgIH0gY2F0Y2ggKF8pIHt9CiAgICB0cnkgewogICAgICBsZXQgbGFzdCA9ICcnOwogICAgICBkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCdbY2xhc3MqPSJicmVhZGNydW1iIl0gYSxbY2xhc3MqPSJjcnVtYiJdIGEsLmJyZWFkY3J1bWIgYSxuYXYgYScpLmZvckVhY2goYSA9PiB7IGNvbnN0IHQgPSAoYS50ZXh0Q29udGVudCB8fCAnJykudHJpbSgpOyBpZiAodCkgbGFzdCA9IHQ7IH0pOwogICAgICBpZiAobGFzdCAmJiBsYXN0Lmxlbmd0aCA8PSAzMDApIHJldHVybiBsYXN0OwogICAgfSBjYXRjaCAoXykge30KICAgIHRyeSB7CiAgICAgIGxldCB0ID0gKGRvY3VtZW50LnRpdGxlIHx8ICcnKS5yZXBsYWNlKC9bLXzigJNdXHMqKE9MTXxvbG0pKFwuVk58XC52bik/LiokL2ksICcnKS5yZXBsYWNlKC9eXHMqxJDEg25nIG5o4bqtcC4qJC9pLCAnJykudHJpbSgpOwogICAgICBpZiAodCAmJiB0Lmxlbmd0aCA8PSAzMDApIHJldHVybiB0OwogICAgfSBjYXRjaCAoXykge30KICAgIHJldHVybiAnJzsKICB9CiAgZnVuY3Rpb24gaXNFeGVyY2lzZVBhZ2UoKSB7CiAgICB0cnkgewogICAgICBpZiAoU0VTU0lPTi5yYXdfcXVlc3Rpb25zICYmIFNFU1NJT04ucmF3X3F1ZXN0aW9ucy5sZW5ndGggPiAwKSByZXR1cm4gdHJ1ZTsKICAgICAgY29uc3QgcCA9IGxvY2F0aW9uLnBhdGhuYW1lIHx8ICcnOwogICAgICBjb25zdCBxID0gbG9jYXRpb24uc2VhcmNoIHx8ICcnOwogICAgICBpZiAoL2lkX2NhdGU9fGlkX2V4YW09fGlkX2NvdXJzZXdhcmU9fChefFs/Jl0paV9jPXxjYXRlX2lkPXxleGFtX2lkPS9pLnRlc3QocSkpIHJldHVybiB0cnVlOwogICAgICBpZiAoL1wvKGV4ZXJjaXNlfHByYWN0aWNlfGx1eWVuLXRhcHxleGFtfHRlc3R8a2llbS10cmF8YmFpLXRhcHxsZXNzb258cXVpenxjb3Vyc2V3YXJlKShcL3xcP3wkKS9pLnRlc3QocCkpIHJldHVybiB0cnVlOwogICAgICBpZiAoZG9jdW1lbnQucXVlcnlTZWxlY3RvcignLnF1ZXN0aW9uLWxpc3QsLnEtaXRlbSxbY2xhc3MqPSJxdWVzdGlvbi1pdGVtIl0sW2RhdGEtcXVlc3Rpb24taWRdLHRleHRhcmVhW2RhdGEtYWNjZXB0XSwudGltZS1jb3VudGRvd24sI3N1Ym1pdC10ZXN0LFtjbGFzcyo9ImV4YW0tYm9keSJdLFtjbGFzcyo9InF1ZXN0aW9uLWNvbnRlbnQiXScpKSByZXR1cm4gdHJ1ZTsKICAgICAgcmV0dXJuIGZhbHNlOwogICAgfSBjYXRjaCAoXykgeyByZXR1cm4gZmFsc2U7IH0KICB9CiAgZnVuY3Rpb24gcmVmcmVzaFN1YmplY3RUaXRsZVVJKCkgewogICAgdHJ5IHsKICAgICAgY29uc3Qgc2UgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtc3ViamVjdC1uYW1lJyk7CiAgICAgIGNvbnN0IHRlID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLWV4ZXJjaXNlLXRpdGxlJyk7CiAgICAgIGlmIChzZSkgc2UudGV4dENvbnRlbnQgPSBTRVNTSU9OLm1ldGEuc3ViamVjdF9uYW1lIHx8ICfigJQnOwogICAgICBpZiAodGUpIHRlLnRleHRDb250ZW50ID0gU0VTU0lPTi5tZXRhLmV4ZXJjaXNlX3RpdGxlIHx8ICfigJQnOwogICAgfSBjYXRjaCAoXykge30KICB9CiAgY29uc3QgX3RsTG9nU2VlbkFyciA9IFtdOwogIGNvbnN0IF90bExvZ1NlZW5TZXQgPSBuZXcgU2V0KCk7CiAgZnVuY3Rpb24gYWRkTG9nKG1zZywgdHlwZSA9ICcnKSB7CiAgICBjb25zdCBib3ggPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtbG9nYm94Jyk7CiAgICBpZiAoIWJveCkgcmV0dXJuOwogICAgdHJ5IHsKICAgICAgY29uc3QgX2xvZ0tleSA9ICh0eXBlIHx8ICcnKSArICd8JyArIFN0cmluZyhtc2cgPT0gbnVsbCA/ICcnIDogbXNnKTsKICAgICAgaWYgKF90bExvZ1NlZW5TZXQuaGFzKF9sb2dLZXkpKSByZXR1cm47CiAgICAgIF90bExvZ1NlZW5TZXQuYWRkKF9sb2dLZXkpOwogICAgICBfdGxMb2dTZWVuQXJyLnB1c2goX2xvZ0tleSk7CiAgICAgIGlmIChfdGxMb2dTZWVuQXJyLmxlbmd0aCA+IDMwMCkgX3RsTG9nU2VlblNldC5kZWxldGUoX3RsTG9nU2VlbkFyci5zaGlmdCgpKTsKICAgIH0gY2F0Y2ggKF8pIHt9CiAgICBjb25zdCBkID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICBkLmNsYXNzTmFtZSA9ICd0bC1sb2cgJyArIHR5cGU7CiAgICBjb25zdCB0aW1lID0gKG5ldyBEYXRlKS50b0xvY2FsZVRpbWVTdHJpbmcoJ3ZpLVZOJywgewogICAgICBob3VyOiAnMi1kaWdpdCcsCiAgICAgIG1pbnV0ZTogJzItZGlnaXQnLAogICAgICBzZWNvbmQ6ICcyLWRpZ2l0JwogICAgfSk7CiAgICBkLmlubmVySFRNTCA9IGBbJHt0aW1lfV0gJHttc2d9YDsKICAgIGJveC5hcHBlbmRDaGlsZChkKTsKICAgIGJveC5zY3JvbGxUb3AgPSBib3guc2Nyb2xsSGVpZ2h0OwogIH0KICB3aW5kb3cuYWRkTG9nID0gYWRkTG9nOwogIGZ1bmN0aW9uIF9pc0NsYXNzTGlzdFBhZ2UoKSB7CiAgICB0cnkgewogICAgICByZXR1cm4gU3RyaW5nKGxvY2F0aW9uLmhyZWYgfHwgJycpLmluZGV4T2YoJ2xvcC1ob2MtY3VhLXRvaScpICE9PSAtMTsKICAgIH0gY2F0Y2ggKF8pIHsgcmV0dXJuIGZhbHNlOyB9CiAgfQogIGZ1bmN0aW9uIF9pc0hvbWV3b3JrTGlzdFBhZ2UoKSB7CiAgICB0cnkgewogICAgICByZXR1cm4gU3RyaW5nKGxvY2F0aW9uLnBhdGhuYW1lIHx8ICcnKSA9PT0gJy9iYWktdGFwLWR1b2MtZ2lhbycgfHwKICAgICAgICAgICAgIFN0cmluZyhsb2NhdGlvbi5ocmVmIHx8ICcnKS5pbmRleE9mKCdiYWktdGFwLWR1b2MtZ2lhbycpICE9PSAtMTsKICAgIH0gY2F0Y2ggKF8pIHsgcmV0dXJuIGZhbHNlOyB9CiAgfQogIGZ1bmN0aW9uIF9hY2NvdW50UGFnZSgpIHsKICAgIHRyeSB7IHJldHVybiBfaXNDbGFzc0xpc3RQYWdlKCkgfHwgX2lzSG9tZXdvcmtMaXN0UGFnZSgpOyB9IGNhdGNoIChfKSB7IHJldHVybiBmYWxzZTsgfQogIH0KICBmdW5jdGlvbiBfcmVtb3ZlT2xtTG9nUm93cygpIHsKICAgIHRyeSB7CiAgICAgIGNvbnN0IGJveCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1sb2dib3gnKTsKICAgICAgaWYgKCFib3gpIHJldHVybjsKICAgICAgYm94LnF1ZXJ5U2VsZWN0b3JBbGwoJy50bC1sb2cnKS5mb3JFYWNoKG4gPT4gewogICAgICAgIGlmIChuLmdldEF0dHJpYnV0ZSAmJiBuLmdldEF0dHJpYnV0ZSgnZGF0YS1vbG0tcm93JykgPT09ICcxJykgeyBuLnJlbW92ZSgpOyByZXR1cm47IH0KICAgICAgICBpZiAoL1TDoGkga2hv4bqjbiBPTE0vaS50ZXN0KG4udGV4dENvbnRlbnQgfHwgJycpKSBuLnJlbW92ZSgpOwogICAgICB9KTsKICAgIH0gY2F0Y2ggKF8pIHt9CiAgfQogIGZ1bmN0aW9uIF9lbnN1cmVPbG1Mb2codSkgewogICAgdHJ5IHsKICAgICAgY29uc3QgYm94ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLWxvZ2JveCcpOwogICAgICBpZiAoIWJveCkgcmV0dXJuOwogICAgICBib3gucXVlcnlTZWxlY3RvckFsbCgnLnRsLWxvZ1tkYXRhLW9sbS1yb3c9IjEiXScpLmZvckVhY2gobiA9PiBuLnJlbW92ZSgpKTsKICAgICAgaWYgKCF1IHx8IHUgPT09ICdLaG9uZ1hhY0RpbmgnKSByZXR1cm47CiAgICAgIGNvbnN0IGQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgICAgZC5jbGFzc05hbWUgPSAndGwtbG9nIGluZm8nOwogICAgICBkLnNldEF0dHJpYnV0ZSgnZGF0YS1vbG0tcm93JywgJzEnKTsKICAgICAgY29uc3QgdGltZSA9IChuZXcgRGF0ZSkudG9Mb2NhbGVUaW1lU3RyaW5nKCd2aS1WTicsIHsgaG91cjogJzItZGlnaXQnLCBtaW51dGU6ICcyLWRpZ2l0Jywgc2Vjb25kOiAnMi1kaWdpdCcgfSk7CiAgICAgIGQuaW5uZXJIVE1MID0gYFske3RpbWV9XSDwn5GkIFTDoGkga2hv4bqjbiBPTE06ICR7dX1gOwogICAgICBib3guYXBwZW5kQ2hpbGQoZCk7CiAgICAgIGJveC5zY3JvbGxUb3AgPSBib3guc2Nyb2xsSGVpZ2h0OwogICAgfSBjYXRjaCAoXykge30KICB9CiAgZnVuY3Rpb24gX3JlZnJlc2hPbG1BY2NvdW50KGZvcmNlKSB7CiAgICB0cnkgewogICAgICBsZXQgdSA9IGdldE9sbVVzZXJuYW1lKCk7CiAgICAgIGlmICh1ID09PSAnS2hvbmdYYWNEaW5oJykgdSA9ICcnOwogICAgICBpZiAodSA9PT0gX2xhc3RPbG1Vc2VyICYmICFmb3JjZSkgcmV0dXJuOwogICAgICBfbGFzdE9sbVVzZXIgPSB1OwogICAgICBpZiAodSkgeyB0cnkgeyBTRVNTSU9OLm1ldGEudXNlcm5hbWUgPSB1OyB9IGNhdGNoIChfKSB7fSB9CiAgICAgIGlmIChfYWNjb3VudFBhZ2UoKSkgX2Vuc3VyZU9sbUxvZyh1KTsgZWxzZSBfcmVtb3ZlT2xtTG9nUm93cygpOwogICAgICBpZiAodSAmJiBDVVJSRU5UX0tFWSkgewogICAgICAgIGdtUG9zdCgnL3ZlcmlmeScsIHsga2V5OiBDVVJSRU5UX0tFWSwgaHdpZDogZ2V0SFdJRCgpLCBvbG1fdXNlcjogdSB9KS50aGVuKHIgPT4gewogICAgICAgICAgY29uc3Qgc2VydmVyT2xtID0gKHIgJiYgKHIub2xtX3VzZXIgfHwgci5vbG1fYWNjb3VudCkpIHx8ICcnOwogICAgICAgICAgaWYgKHNlcnZlck9sbSAmJiB1ICYmIFN0cmluZyhzZXJ2ZXJPbG0pLnRvTG93ZXJDYXNlKCkgIT09IFN0cmluZyh1KS50b0xvd2VyQ2FzZSgpKSBoYW5kbGVPbG1NaXNtYXRjaChzZXJ2ZXJPbG0sIHUpOwogICAgICAgIH0pLmNhdGNoKCgpID0+IHt9KTsKICAgICAgfQogICAgfSBjYXRjaCAoXykge30KICB9CiAgZnVuY3Rpb24gYnVpbGRMb2NrU2NyZWVuKHJlYXNvbikgewogICAgaWYgKGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1jb25uLW92ZXJsYXknKSkgcmV0dXJuOwogICAgbGV0IGxvY2tTdHlsZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1sb2NrLXN0eWxlJyk7CiAgICBpZiAoIWxvY2tTdHlsZSkgewogICAgICBsb2NrU3R5bGUgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdzdHlsZScpOwogICAgICBsb2NrU3R5bGUuaWQgPSAndGwtbG9jay1zdHlsZSc7CiAgICAgIGRvY3VtZW50LmhlYWQuYXBwZW5kQ2hpbGQobG9ja1N0eWxlKTsKICAgIH0KICAgIGxvY2tTdHlsZS50ZXh0Q29udGVudCA9IGdldExvY2tTY3JlZW5TdHlsZXMoKTsKICAgIGNvbnN0IG92ZXJsYXkgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgIG92ZXJsYXkuaWQgPSAndGwtY29ubi1vdmVybGF5JzsKICAgIGNvbnN0IHRsRnggPSBnZXRUaGVtZUNvbG9ycyhDVVJSRU5UX1RIRU1FKS5wYW5lbEV4dHJhIHx8ICcnOwogICAgb3ZlcmxheS5pbm5lckhUTUwgPSBgXG4gICAgICAgICAgICA8ZGl2IGlkPSJ0bC1jb25uLXBhbmVsIj5cbiAgICAgICAgICAgICAgICAke3RsRnh9XG4gICAgICAgICAgICAgICAgPGRpdiBpZD0idGwtY29ubi1oZWFkZXIiPlxuICAgICAgICAgICAgICAgICAgICA8c3BhbiBjbGFzcz0idGwtYnJhbmQtbmFtZSI+8J+agCBUSEnDik4gVEFJIFTDmSBU4buYSSAvLyBHT0QgTU9ERSB2My41PC9zcGFuPlxuICAgICAgICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgICAgICAgIDxkaXYgaWQ9InRsLWNvbm4tYm9keSI+XG4gICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLXN1YnRpdGxlIj7wn5SQIE5I4bqsUCBMSUNFTlNFIEtFWSDEkOG7giBLw41DSCBIT+G6oFQ8L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgJHtyZWFzb24gPyBgPGRpdiBjbGFzcz0idGwtd2FybmluZyI+4pqg77iPICR7cmVhc29ufTwvZGl2PmAgOiAnJ31cbiAgICAgICAgICAgICAgICAgICAgPGlucHV0IHR5cGU9InRleHQiIGNsYXNzPSJ0bC1pbnB1dCIgaWQ9InRsLWtleS1pbnB1dCJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgIHBsYWNlaG9sZGVyPSJOaOG6rXAga2V5IGLhuqNuIHF1eeG7gW4uLi4iIGF1dG9jb21wbGV0ZT0ib2ZmIj5cbiAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0idGwtYnRuIHRsLWJ0bi11bmxvY2siIGlkPSJ0bC1idG4tdW5sb2NrIj7wn5STIEvDjUNIIEhP4bqgVDwvYnV0dG9uPlxuICAgICAgICAgICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJ0bC1idG4gdGwtYnRuLXZpcCIgICBpZD0idGwtYnRuLWJ1eSI+8J+SjiBNVUEgS0VZIChMScOKTiBI4buGKTwvYnV0dG9uPlxuICAgICAgICAgICAgICAgICAgICA8ZGl2IGlkPSJ0bC1lcnIiPjwvZGl2PlxuICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC1od2lkIiBpZD0idGwtaHdpZC1kaXNwbGF5Ij48L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtZm9vdCI+WcOqdSBj4bqndTogbcOheSBBbmRyb2lkL2lPUyB0aOG6rXQg4oCiIHRyw6xuaCBkdXnhu4d0IHRo4bqtdCDigKIgbeG6oW5nIHRo4bqtdDwvZGl2PlxuICAgICAgICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgICAgPC9kaXY+YDsKICAgIGRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQob3ZlcmxheSk7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtaHdpZC1kaXNwbGF5JykudGV4dENvbnRlbnQgPSBg8J+UkSBIV0lEOiAke2dldEhXSUQoKX1gOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLWJ0bi1idXknKS5vbmNsaWNrID0gKCkgPT4gd2luZG93Lm9wZW4oJ2h0dHBzOi8vdC5tZS9sdW9uZ3R1eWVuMjAnLCAnX2JsYW5rJyk7CiAgICBjb25zdCBidG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtYnRuLXVubG9jaycpOwogICAgY29uc3QgZXJyQm94ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLWVycicpOwogICAgbGV0IHZlcmlmeWluZyA9IGZhbHNlOwogICAgYnRuLm9uY2xpY2sgPSBhc3luYyAoKSA9PiB7CiAgICAgIGlmICh2ZXJpZnlpbmcpIHJldHVybjsKICAgICAgY29uc3Qga2V5ID0gKGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1rZXktaW5wdXQnKS52YWx1ZSB8fCAnJykudHJpbSgpLnRvVXBwZXJDYXNlKCk7CiAgICAgIGlmICgha2V5KSB7CiAgICAgICAgZXJyQm94LnRleHRDb250ZW50ID0gJ+KdjCBWdWkgbMOybmcgbmjhuq1wIGtleSEnOwogICAgICAgIGVyckJveC5zdHlsZS5kaXNwbGF5ID0gJ2Jsb2NrJzsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgdmVyaWZ5aW5nID0gdHJ1ZTsKICAgICAgYnRuLnRleHRDb250ZW50ID0gJ+KPsyDEkEFORyBYw4FDIFRI4buwQy4uLic7CiAgICAgIGJ0bi5kaXNhYmxlZCA9IHRydWU7CiAgICAgIGVyckJveC5zdHlsZS5kaXNwbGF5ID0gJ25vbmUnOwogICAgICB0cnkgewogICAgICAgIGNvbnN0IHByZWZpeCA9IGF3YWl0IF9hcGlQcmVmaXgoKTsKICAgICAgICBjb25zdCBwaW5nT2sgPSBhd2FpdCBuZXcgUHJvbWlzZShyZXNvbHZlID0+IHsKICAgICAgICAgIF94aHJDYWxsKHsKICAgICAgICAgICAgbWV0aG9kOiAnR0VUJywKICAgICAgICAgICAgdXJsOiBTRVJWRVJfQkFTRSArIHByZWZpeCArICcvcGluZycsCiAgICAgICAgICAgIHRpbWVvdXQ6IDhlMywKICAgICAgICAgICAgb25sb2FkOiByID0+IHJlc29sdmUoci5zdGF0dXMgPT09IDIwMCksCiAgICAgICAgICAgIG9uZXJyb3I6ICgpID0+IHJlc29sdmUoZmFsc2UpLAogICAgICAgICAgICBvbnRpbWVvdXQ6ICgpID0+IHJlc29sdmUoZmFsc2UpCiAgICAgICAgICB9KTsKICAgICAgICB9KTsKICAgICAgICBpZiAoIXBpbmdPaykgdGhyb3cgbmV3IEVycm9yKCdLSMOUTkcgS+G6vlQgTuG7kEkgxJDGr+G7okMgU0VSVkVSLiBLaeG7g20gdHJhOiAxKSBVUkwgU0VSVkVSX0JBU0UsIDIpIEFQSV9TRUNSRVQga2jhu5twIEdPRE1PREVfU0VDUkVUIHRyw6puIHNlcnZlciwgMykgxJHDoyBkZXBsb3kvcmVkZXBsb3kuJyk7CiAgICAgICAgY29uc3QgY3VycmVudE9sbSA9IGdldE9sbVVzZXJuYW1lKCk7CiAgICAgICAgY29uc3QgcmVzdWx0ID0gYXdhaXQgZ21Qb3N0KCcvdmVyaWZ5JywgewogICAgICAgICAga2V5OiBrZXksCiAgICAgICAgICBod2lkOiBnZXRIV0lEKCksCiAgICAgICAgICBvbG1fdXNlcjogY3VycmVudE9sbQogICAgICAgIH0pOwogICAgICAgIGlmIChyZXN1bHQuc3VjY2VzcyB8fCByZXN1bHQudmFsaWQpIHsKICAgICAgICAgIGNvbnN0IHNlcnZlck9sbSA9IHJlc3VsdC5vbG1fdXNlciB8fCByZXN1bHQub2xtX2FjY291bnQgfHwgJyc7CiAgICAgICAgICBpZiAoc2VydmVyT2xtICYmIGN1cnJlbnRPbG0gJiYgY3VycmVudE9sbSAhPT0gJ0tob25nWGFjRGluaCcpIHsKICAgICAgICAgICAgaWYgKHNlcnZlck9sbS50b0xvd2VyQ2FzZSgpICE9PSBjdXJyZW50T2xtLnRvTG93ZXJDYXNlKCkpIHsKICAgICAgICAgICAgICBlcnJCb3guaW5uZXJIVE1MID0gYPCfmqsgPGI+VMOgaSBraG/huqNuIE9MTSBraMO0bmcga2jhu5twITwvYj48YnI+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEtleSBkw6BuaCBjaG86IDxiPiR7c2VydmVyT2xtfTwvYj48YnI+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEhp4buHbiB04bqhaTogPGI+JHtjdXJyZW50T2xtfTwvYj48YnI+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFZ1aSBsw7JuZyDEkcSDbmcgbmjhuq1wIMSRw7puZyB0w6BpIGtob+G6o24gT0xNIWA7CiAgICAgICAgICAgICAgZXJyQm94LnN0eWxlLmRpc3BsYXkgPSAnYmxvY2snOwogICAgICAgICAgICAgIGJ0bi50ZXh0Q29udGVudCA9ICfwn5STIEvDjUNIIEhP4bqgVCc7CiAgICAgICAgICAgICAgYnRuLmRpc2FibGVkID0gZmFsc2U7CiAgICAgICAgICAgICAgdmVyaWZ5aW5nID0gZmFsc2U7CiAgICAgICAgICAgICAgcmV0dXJuOwogICAgICAgICAgICB9CiAgICAgICAgICB9CiAgICAgICAgICBfc0xTLnNldChMU19LRVksIGtleSk7CiAgICAgICAgICBfc0xTLnNldChMU19UWVBFLCByZXN1bHQudHlwZSB8fCByZXN1bHQucGxhbiB8fCAnVEhVT05HJyk7CiAgICAgICAgICBfc0xTLnNldChMU19FWFAsIHJlc3VsdC5leHBpcmVzX2F0IHx8ICcnKTsKICAgICAgICAgIENVUlJFTlRfS0VZID0ga2V5OwogICAgICAgICAgS0VZX1NUQVRVUyA9IHsKICAgICAgICAgICAgdmFsaWQ6IHRydWUsCiAgICAgICAgICAgIHR5cGU6IHJlc3VsdC50eXBlIHx8IHJlc3VsdC5wbGFuLAogICAgICAgICAgICBleHBpcmVzX2F0OiByZXN1bHQuZXhwaXJlc19hdCB8fCByZXN1bHQuZXhwCiAgICAgICAgICB9OwogICAgICAgICAgY29uc3Qga2V5VHlwZUxhYmVsID0gKHJlc3VsdC50eXBlIHx8IHJlc3VsdC5wbGFuIHx8ICdUSFVPTkcnKS50b1VwcGVyQ2FzZSgpOwogICAgICAgICAgY29uc3QgaXNQcmVtaXVtID0gWyAnUFJFTUlVTScsICdWSVAnLCAnVU5MSU1JVEVEJyBdLmluY2x1ZGVzKGtleVR5cGVMYWJlbCk7CiAgICAgICAgICBsZXQgZXhwaXJ5TGluZSA9ICcnOwogICAgICAgICAgY29uc3QgZXhSYXcgPSByZXN1bHQuZXhwaXJlc19hdCB8fCByZXN1bHQuZXhwIHx8ICcnOwogICAgICAgICAgaWYgKGV4UmF3KSB7CiAgICAgICAgICAgIGNvbnN0IGV4cERhdGUgPSBuZXcgRGF0ZShleFJhdyk7CiAgICAgICAgICAgIGNvbnN0IGRheXNMZWZ0ID0gTWF0aC5jZWlsKChleHBEYXRlIC0gbmV3IERhdGUpIC8gKDFlMyAqIDYwICogNjAgKiAyNCkpOwogICAgICAgICAgICBjb25zdCBleHBTdHIgPSBleHBEYXRlLnRvTG9jYWxlRGF0ZVN0cmluZygndmktVk4nKTsKICAgICAgICAgICAgaWYgKGRheXNMZWZ0ID4gMCkgZXhwaXJ5TGluZSA9IGDwn5OFIEjhur90IGjhuqFuOiA8Yj4ke2V4cFN0cn08L2I+IChjw7JuIDxiPiR7ZGF5c0xlZnR9PC9iPiBuZ8OgeSlgOyBlbHNlIGlmIChkYXlzTGVmdCA9PT0gMCkgZXhwaXJ5TGluZSA9IGDwn5OFIEjhur90IGjhuqFuOiA8Yj5Iw7RtIG5heTwvYj4gKCR7ZXhwU3RyfSlgOyBlbHNlIGV4cGlyeUxpbmUgPSBg8J+ThSBI4bq/dCBo4bqhbjogPGI+JHtleHBTdHJ9PC9iPiA8c3BhbiBzdHlsZT0iY29sb3I6I2ZmNDQ0NDsiPijEkcOjIGjhur90IGjhuqFuKTwvc3Bhbj5gOwogICAgICAgICAgfQogICAgICAgICAgb3ZlcmxheS5yZW1vdmUoKTsKICAgICAgICAgIGlmICghaXNQcmVtaXVtKSB7CiAgICAgICAgICAgIHNob3dDdXN0b21Nb2RhbCh7CiAgICAgICAgICAgICAgaWNvbjogJ+KchScsCiAgICAgICAgICAgICAgdGl0bGU6ICdLw41DSCBIT+G6oFQgVEjDgE5IIEPDlE5HIScsCiAgICAgICAgICAgICAgbGluZXM6IFsgYExv4bqhaSBrZXk6IDxiPiR7a2V5VHlwZUxhYmVsfTwvYj5gLCAuLi5leHBpcnlMaW5lID8gWyBleHBpcnlMaW5lIF0gOiBbXSwgYDxzcGFuIHN0eWxlPSJjb2xvcjojZmZjMTA3OyI+4pqg77iPIEtleSB0aMaw4budbmc6IENo4bupYyBuxINuZyAiQ0hV4bqoTiBC4buKIDEwIMSQSeG7gk0iIGLhu4sgdsO0IGhp4buHdSBob8OhLjwvc3Bhbj5gLCBg8J+SjiBOw6JuZyBj4bqlcCBsw6puIFBSRU1JVU0gxJHhu4MgZMO5bmcgxJHhuqd5IMSR4bunIHTDrW5oIG7Eg25nIWAgXSwKICAgICAgICAgICAgICBvbk9rOiAoKSA9PiBjcmVhdGVVSSgpCiAgICAgICAgICAgIH0pOwogICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgc2hvd0N1c3RvbU1vZGFsKHsKICAgICAgICAgICAgICBpY29uOiAn8J+SjicsCiAgICAgICAgICAgICAgdGl0bGU6ICdLw41DSCBIT+G6oFQgVEjDgE5IIEPDlE5HIScsCiAgICAgICAgICAgICAgbGluZXM6IFsgYExv4bqhaSBrZXk6IDxiPiR7a2V5VHlwZUxhYmVsfTwvYj4g8J+SjmAsIC4uLmV4cGlyeUxpbmUgPyBbIGV4cGlyeUxpbmUgXSA6IFtdLCBg8J+UkyBU4bqldCBj4bqjIHTDrW5oIG7Eg25nIMSRw6MgxJHGsOG7o2MgbeG7nyBraG/DoSFgIF0sCiAgICAgICAgICAgICAgb25PazogKCkgPT4gY3JlYXRlVUkoKQogICAgICAgICAgICB9KTsKICAgICAgICAgIH0KICAgICAgICB9IGVsc2UgewogICAgICAgICAgY29uc3Qgc3RhdHVzID0gcmVzdWx0Ll9odHRwU3RhdHVzOwogICAgICAgICAgbGV0IG1zZyA9IHJlc3VsdC5tZXNzYWdlIHx8IHJlc3VsdC5yZWFzb24gfHwgcmVzdWx0LmVycm9yIHx8ICcnOwogICAgICAgICAgaWYgKHN0YXR1cyA9PT0gNDA0IHx8IHJlc3VsdC5lcnJvciA9PT0gJ05vdCBmb3VuZCcpIHsKICAgICAgICAgICAgbXNnID0gJ+KdjCBUaGnhur90IGLhu4svSVAgY8OzIHRo4buDIMSRw6MgYuG7iyBraG/DoSBob+G6t2Mgc2FpIMSRxrDhu51uZyBk4bqrbiBBUEkuIEtp4buDbSB0cmEgQVBJX1NFQ1JFVCBraOG7m3Agc2VydmVyLic7CiAgICAgICAgICB9IGVsc2UgaWYgKHN0YXR1cyA9PT0gNDAzKSB7CiAgICAgICAgICAgIG1zZyA9ICfinYwgJyArIChtc2cgfHwgJ1RoaeG6v3QgYuG7iy9t4bqhbmcga2jDtG5nIGjhu6NwIGzhu4cgKG3DoXkg4bqjby9wcm94eS9WUE4vdHLDrG5oIGR1eeG7h3QgZ2nhuqMpIOKAlCBjw7MgdGjhu4MgxJHDoyBi4buLIGtob8OhIHbEqW5oIHZp4buFbiwgbGnDqm4gaOG7hyBhZG1pbi4nKTsKICAgICAgICAgIH0gZWxzZSBpZiAoIW1zZykgewogICAgICAgICAgICBtc2cgPSAn4p2MIEtleSBraMO0bmcgaOG7o3AgbOG7hyEgKEtleVZhdWx0IHThu6sgY2jhu5FpKSc7CiAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICBtc2cgPSAn4p2MICcgKyBtc2c7CiAgICAgICAgICB9CiAgICAgICAgICBlcnJCb3gudGV4dENvbnRlbnQgPSBtc2cgKyAoc3RhdHVzID8gYCBbSFRUUCAke3N0YXR1c31dYCA6ICcnKTsKICAgICAgICAgIGVyckJveC5zdHlsZS5kaXNwbGF5ID0gJ2Jsb2NrJzsKICAgICAgICAgIGJ0bi50ZXh0Q29udGVudCA9ICfwn5STIEvDjUNIIEhP4bqgVCc7CiAgICAgICAgICBidG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgICAgIHZlcmlmeWluZyA9IGZhbHNlOwogICAgICAgIH0KICAgICAgfSBjYXRjaCAoZSkgewogICAgICAgIGVyckJveC50ZXh0Q29udGVudCA9ICfinYwgS2jDtG5nIHRo4buDIGvhur90IG7hu5FpIHNlcnZlcjogJyArIGUubWVzc2FnZTsKICAgICAgICBlcnJCb3guc3R5bGUuZGlzcGxheSA9ICdibG9jayc7CiAgICAgICAgYnRuLnRleHRDb250ZW50ID0gJ/CflJMgS8ONQ0ggSE/huqBUJzsKICAgICAgICBidG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgICB2ZXJpZnlpbmcgPSBmYWxzZTsKICAgICAgfQogICAgfTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1rZXktaW5wdXQnKS5hZGRFdmVudExpc3RlbmVyKCdrZXlkb3duJywgZSA9PiB7CiAgICAgIGlmIChlLmtleSA9PT0gJ0VudGVyJykgYnRuLmNsaWNrKCk7CiAgICB9KTsKICB9CiAgZnVuY3Rpb24gY3JlYXRlVUkoKSB7CiAgICBpZiAoZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLXBhbmVsJykpIHJldHVybjsKICAgIGxldCB1aVN0eWxlID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLXVpLXN0eWxlJyk7CiAgICBpZiAoIXVpU3R5bGUpIHsKICAgICAgdWlTdHlsZSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ3N0eWxlJyk7CiAgICAgIHVpU3R5bGUuaWQgPSAndGwtdWktc3R5bGUnOwogICAgICBkb2N1bWVudC5oZWFkLmFwcGVuZENoaWxkKHVpU3R5bGUpOwogICAgfQogICAgdWlTdHlsZS50ZXh0Q29udGVudCA9IGdldE1haW5VSVN0eWxlcygpOwogICAgY29uc3Qga2V5VHlwZSA9IEtFWV9TVEFUVVMudHlwZSB8fCBfc0xTLmdldChMU19UWVBFKSB8fCAnVEhVT05HJzsKICAgIGNvbnN0IGtleVR5cGVVcCA9IGtleVR5cGUudG9VcHBlckNhc2UoKTsKICAgIGNvbnN0IGJhZGdlQ2xhc3MgPSBrZXlUeXBlVXAgPT09ICdVTkxJTUlURUQnID8gJ3RsLWJhZGdlIHVubGltaXRlZCcgOiBrZXlUeXBlVXAgPT09ICdQUkVNSVVNJyB8fCBrZXlUeXBlVXAgPT09ICdWSVAnID8gJ3RsLWJhZGdlIHZpcCcgOiAndGwtYmFkZ2UnOwogICAgY29uc3QgYmFkZ2VJY29uID0ga2V5VHlwZVVwID09PSAnVU5MSU1JVEVEJyA/ICfwn5SlIFVOTElNSVRFRCcgOiBrZXlUeXBlVXAgPT09ICdQUkVNSVVNJyB8fCBrZXlUeXBlVXAgPT09ICdWSVAnID8gJ/Cfko4gUFJFTUlVTScgOiAn8J+UkSBUSMav4bucTkcnOwogICAgY29uc3QgZXhwU3RyID0gKCgpID0+IHsKICAgICAgY29uc3QgZSA9IF9zTFMuZ2V0KExTX0VYUCk7CiAgICAgIGlmICghZSkgcmV0dXJuICcnOwogICAgICBjb25zdCBkID0gbmV3IERhdGUoZSk7CiAgICAgIHJldHVybiBpc05hTihkKSA/ICcnIDogYCAoZXhwOiAke2QudG9Mb2NhbGVEYXRlU3RyaW5nKCd2aS1WTicpfSlgOwogICAgfSkoKTsKICAgIGNvbnN0IHRoZW1lQ2FyZHNIVE1MID0gWyAnZGVmYXVsdCcsICdncmF5JywgJ3BpbmsnIF0ubWFwKHQgPT4gewogICAgICBjb25zdCB0SW5mbyA9IGdldFRoZW1lQ29sb3JzKHQpOwogICAgICBjb25zdCBpc0FjdGl2ZSA9IHQgPT09IENVUlJFTlRfVEhFTUU7CiAgICAgIHJldHVybiBgPGRpdiBjbGFzcz0idGwtdGMgJHtpc0FjdGl2ZSA/ICdhY3RpdmUnIDogJyd9IiBkYXRhLXQ9IiR7dH0iPlxuICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLXRjLXByZXYiIHN0eWxlPSJiYWNrZ3JvdW5kOiR7dEluZm8ucHJldmlld0JnfTtib3JkZXI6MXB4IHNvbGlkICR7dEluZm8ucHJldmlld0JvcmRlcn07Ij5cbiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtdGMtcHJldi1pbm5lciI+XG4gICAgICAgICAgICAgICAgICAgICAgICA8c3BhbiBjbGFzcz0idGwtdGMtcHJldi10ZXh0IiBzdHlsZT0iY29sb3I6JHt0SW5mby5wcmV2aWV3VGV4dH07Ij4ke3RJbmZvLnRoZW1lTGFiZWwucmVwbGFjZSgvXlteXHNdK1xzLywgJycpLnRvVXBwZXJDYXNlKCl9PC9zcGFuPlxuICAgICAgICAgICAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC10Yy1sYmwiPiR7dEluZm8udGhlbWVMYWJlbH08L2Rpdj5cbiAgICAgICAgICAgIDwvZGl2PmA7CiAgICB9KS5qb2luKCcnKTsKICAgIGNvbnN0IHRjID0gZ2V0VGhlbWVDb2xvcnMoQ1VSUkVOVF9USEVNRSk7CiAgICBjb25zdCB3cmFwID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICB3cmFwLmlubmVySFRNTCA9IGBcbiAgICAgICAgICAgIDxidXR0b24gaWQ9InRsLWZsb2F0QnRuIj7imqE8L2J1dHRvbj5cbiAgICAgICAgICAgIDxkaXYgaWQ9InRsLXBhbmVsIiBjbGFzcz0iaGlkZGVuIj5cbiAgICAgICAgICAgICAgICAke3RjLnBhbmVsRXh0cmEgfHwgJyd9XG4gICAgICAgICAgICAgICAgPGRpdiBpZD0idGwtcC1oZWFkZXIiPlxuICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC1wLWJyYW5kIj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxzcGFuPvCfmoA8L3NwYW4+XG4gICAgICAgICAgICAgICAgICAgICAgICA8c3BhbiBjbGFzcz0idGwtcC1uYW1lIj5USEnDik4gVEFJIFTDmSBU4buYSSAvLyBHT0QgTU9ERTwvc3Bhbj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxzcGFuIGNsYXNzPSIke2JhZGdlQ2xhc3N9Ij4ke2JhZGdlSWNvbn08L3NwYW4+XG4gICAgICAgICAgICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDo2cHg7Ij5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxidXR0b24gaWQ9InRsLXNldHRpbmdzQnRuIiB0aXRsZT0iQ8OgaSDEkeG6t3QgZ2lhbyBkaeG7h24iPuKamTwvYnV0dG9uPlxuICAgICAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBpZD0idGwtY2xvc2VCdG4iPuKclTwvYnV0dG9uPlxuICAgICAgICAgICAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICAgICAgICA8L2Rpdj5cblxuICAgICAgICAgICAgICAgIFx4M2MhLS0gU2V0dGluZ3Mgb3ZlcmxheSAtLVx4M2VcbiAgICAgICAgICAgICAgICA8ZGl2IGlkPSJ0bC1zbyIgY2xhc3M9ImhpZGRlbiI+XG4gICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLXNvLWhkciI+XG4gICAgICAgICAgICAgICAgICAgICAgICA8c3BhbiBjbGFzcz0idGwtc28tdGl0bGUiPuKamSBDw4BJIMSQ4bq2VCBHSUFPIERJ4buGTjwvc3Bhbj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxidXR0b24gaWQ9InRsLXNvQ2xvc2UiPuKclTwvYnV0dG9uPlxuICAgICAgICAgICAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtc28tYm9keSI+XG4gICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC1zby1sYmwiPvCfjqggQ2jhu41uIG3DoHUgc+G6r2MgZ2lhbyBkaeG7h248L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLXRoZW1lLWNhcmRzIj4ke3RoZW1lQ2FyZHNIVE1MfTwvZGl2PlxuICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtc28tZGl2aWRlciI+PC9kaXY+XG4gICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC1oaW50Ij7DgXAgZOG7pW5nIG5nYXkgbOG6rXAgdOG7qWMgY2hvIHRvw6BuIGLhu5kgZ2lhbyBkaeG7h248YnI+a+G7gyBj4bqjIG3DoG4gaMOsbmggxJHEg25nIG5o4bqtcCB2w6AgdGjDtG5nIGLDoW8ga2V5PC9kaXY+XG4gICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC1zby1kaXZpZGVyIj48L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLXNvLWxibCI+8J+UkSBRdeG6o24gbMO9IGtleTwvZGl2PlxuICAgICAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0idGwtY2hhbmdlLWtleSIgaWQ9InRsLWNoYW5nZUtleSI+8J+UhCDEkOG7lEkgS0VZPC9idXR0b24+XG4gICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC1oaW50IiBzdHlsZT0ibWFyZ2luLXRvcDo0cHg7Ij5Yb8OhIGtleSBoaeG7h24gdOG6oWkgdsOgIHF1YXkgduG7gSBtw6BuIGjDrG5oIMSRxINuZyBuaOG6rXA8L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgPC9kaXY+XG4gICAgICAgICAgICAgICAgPC9kaXY+XG5cbiAgICAgICAgICAgICAgICA8ZGl2IGlkPSJ0bC1wLWJvZHkiPlxuICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC1zdGF0Ym94Ij5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgc3R5bGU9ImNvbG9yOnJnYmEoMjU1LDI1NSwyNTUsMC40KTtmb250LXNpemU6MTBweDt0ZXh0LXRyYW5zZm9ybTp1cHBlcmNhc2U7Zm9udC13ZWlnaHQ6NjAwOyI+Ly8gVHLhuqFuZyB0aMOhaSBo4buHIHRo4buRbmc8L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLXN0YXRyb3ciPuKchSBO4bqhcCBk4buvIGxp4buHdTogPHNwYW4gaWQ9InRsLXFjb3VudCIgc3R5bGU9ImNvbG9yOiMwMGU2NzY7Zm9udC13ZWlnaHQ6Ym9sZDttYXJnaW4tbGVmdDo1cHgiPjA8L3NwYW4+IGPDonU8L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLXN0YXRyb3ciPvCflI0gQ2jhur8gxJHhu5k6IDxzcGFuIGlkPSJ0bC1tb2RlLWRldGVjdGVkIiBzdHlsZT0iY29sb3I6IzRmYWNmZTtmb250LXdlaWdodDpib2xkO21hcmdpbi1sZWZ0OjVweCI+UFJBQ1RJQ0U8L3NwYW4+PC9kaXY+XG4gICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC1zdGF0cm93Ij7wn5SQIEtleTogPHNwYW4gc3R5bGU9ImNvbG9yOiNmZmMxMDc7Ij4ke2tleVR5cGV9PC9zcGFuPiR7ZXhwU3RyfTwvZGl2PlxuICAgICAgICAgICAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgPGRpdiBzdHlsZT0iaGVpZ2h0OjFweDtiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCg5MGRlZyx0cmFuc3BhcmVudCwke3RjLmJvcmRlcn0sdHJhbnNwYXJlbnQpOyI+PC9kaXY+XG4gICAgICAgICAgICAgICAgICAgIDxkaXY+XG4gICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJmb250LXNpemU6OS41cHg7Zm9udC13ZWlnaHQ6NzAwO2NvbG9yOiR7dGMuZ2xvd0NvbG9yfTtmb250LWZhbWlseTonT3JiaXRyb24nOyI+4pqZIENI4bq+IMSQ4buYIFbGr+G7olQgUsOATzwvZGl2PlxuICAgICAgICAgICAgICAgICAgICAgICAgPHNlbGVjdCBpZD0idGwtbW9kZVNlbGVjdCI+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0icHJhY3RpY2UiPuKaoSBMdXnhu4duIFThuq1wPC9vcHRpb24+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0iZXhhbSIgc2VsZWN0ZWQ+8J+UpSBLaeG7g20gVHJhPC9vcHRpb24+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0idmlkZW8iPvCfjqUgVmlkZW8gUXVpejwvb3B0aW9uPlxuICAgICAgICAgICAgICAgICAgICAgICAgPC9zZWxlY3Q+XG4gICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJmb250LXNpemU6OS41cHg7Zm9udC13ZWlnaHQ6NzAwO2NvbG9yOiR7dGMuZ2xvd0NvbG9yfTtmb250LWZhbWlseTonT3JiaXRyb24nO21hcmdpbi10b3A6NnB4OyI+4o+xIFRI4bucSSBHSUFOIEzDgE0gQsOASSAoUEjDmlQpPC9kaXY+XG4gICAgICAgICAgICAgICAgICAgICAgICA8aW5wdXQgdHlwZT0ibnVtYmVyIiBzdGVwPSIwLjAxIiBjbGFzcz0idGwtZ29kLWlucHV0IiBpZD0idGwtZ29kLXRpbWUiXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFsdWU9IjI1LjAwIiBwbGFjZWhvbGRlcj0iMjUgPSAyNSBwaMO6dCDCtyAyNS4zMCA9IDI1cDMwcyI+XG4gICAgICAgICAgICAgICAgICAgIDxkaXYgc3R5bGU9ImZvbnQtc2l6ZTo5LjVweDtmb250LXdlaWdodDo3MDA7Y29sb3I6JHt0Yy5nbG93Q29sb3J9O2ZvbnQtZmFtaWx5OidPcmJpdHJvbic7bWFyZ2luLXRvcDo2cHg7Ij7wn46vIMSQaeG7g20gbeG7pWMgdGnDqnU8L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgPHNlbGVjdCBpZD0idGwtZ29kLXRhcmdldC1zY29yZSI+XG4gICAgICAgICAgICAgICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSI3Ij43xJE8L29wdGlvbj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxvcHRpb24gdmFsdWU9IjgiPjjEkTwvb3B0aW9uPlxuICAgICAgICAgICAgICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0iOSI+OcSRPC9vcHRpb24+XG4gICAgICAgICAgICAgICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSIxMCIgc2VsZWN0ZWQ+MTDEkTwvb3B0aW9uPlxuICAgICAgICAgICAgICAgICAgICA8L3NlbGVjdD5cbiAgICAgICAgICAgICAgICAgICAgPC9kaXY+XG4gICAgICAgICAgICAgICAgICAgIDxidXR0b24gaWQ9InRsLWZpcmVCdG4iPvCfkqUgQ0hV4bqoTiBC4buKIDEwIMSQSeG7gk08L2J1dHRvbj5cbiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtY29uc29sZSIgaWQ9InRsLWxvZ2JveCI+PC9kaXY+XG4gICAgICAgICAgICAgICAgPC9kaXY+XG4gICAgICAgICAgICAgICAgPGRpdiBpZD0idGwtcC1mb290ZXIiPlxuICAgICAgICAgICAgICAgICAgICA8c3Bhbj5HT0QgTU9ERSB2My41IOKAlCBTRUNVUkUgdjUuMSAodjE3IGFudGktYmFuKTwvc3Bhbj5cbiAgICAgICAgICAgICAgICAgICAgPGRpdiBzdHlsZT0iZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6NXB4OyI+XG4gICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJ3aWR0aDo2cHg7aGVpZ2h0OjZweDtib3JkZXItcmFkaXVzOjUwJTtiYWNrZ3JvdW5kOiMwMGU2NzY7Ym94LXNoYWRvdzowIDAgNnB4ICMwMGU2NzY7YW5pbWF0aW9uOmNvbm5CbGluayAxLjhzIGluZmluaXRlOyI+PC9kaXY+XG4gICAgICAgICAgICAgICAgICAgICAgICA8c3BhbiBpZD0idGwtc3ZyU3RhdHVzIj7wn5S1IFNlcnZlcjogT0s8L3NwYW4+XG4gICAgICAgICAgICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgICAgPC9kaXY+YDsKICAgIGRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQod3JhcCk7CiAgICB0cnkgeyBfc2NoZWR1bGVBbnNGaWxlUmVzY3VlKCk7IH0gY2F0Y2ggKF8pIHt9CiAgICBjb25zdCBmbG9hdEJ0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1mbG9hdEJ0bicpOwogICAgY29uc3QgcGFuZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtcGFuZWwnKTsKICAgIGZsb2F0QnRuLm9uY2xpY2sgPSAoKSA9PiBwYW5lbC5jbGFzc0xpc3QudG9nZ2xlKCdoaWRkZW4nKTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1jbG9zZUJ0bicpLm9uY2xpY2sgPSAoKSA9PiB7CiAgICAgIHBhbmVsLmNsYXNzTGlzdC5hZGQoJ2hpZGRlbicpOwogICAgICBjb25zdCBzbyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1zbycpOwogICAgICBpZiAoc28pIHNvLmNsYXNzTGlzdC5hZGQoJ2hpZGRlbicpOwogICAgfTsKICAgIGNvbnN0IGhkciA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1wLWhlYWRlcicpOwogICAgbGV0IGlzRHJhZ2dpbmcgPSBmYWxzZSwgc3RhcnRYID0gMCwgc3RhcnRZID0gMCwgaW5pdExlZnQgPSAwLCBpbml0VG9wID0gMDsKICAgIGlmIChoZHIpIHsKICAgICAgaGRyLmFkZEV2ZW50TGlzdGVuZXIoJ21vdXNlZG93bicsIGUgPT4gewogICAgICAgIGlmIChlLnRhcmdldC5pZCA9PT0gJ3RsLWNsb3NlQnRuJyB8fCBlLnRhcmdldC5pZCA9PT0gJ3RsLXNldHRpbmdzQnRuJykgcmV0dXJuOwogICAgICAgIGlzRHJhZ2dpbmcgPSB0cnVlOwogICAgICAgIHN0YXJ0WCA9IGUuY2xpZW50WDsKICAgICAgICBzdGFydFkgPSBlLmNsaWVudFk7CiAgICAgICAgY29uc3QgciA9IHBhbmVsLmdldEJvdW5kaW5nQ2xpZW50UmVjdCgpOwogICAgICAgIGluaXRMZWZ0ID0gci5sZWZ0OwogICAgICAgIGluaXRUb3AgPSByLnRvcDsKICAgICAgfSk7CiAgICB9CiAgICBkb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCdtb3VzZW1vdmUnLCBlID0+IHsKICAgICAgaWYgKCFpc0RyYWdnaW5nKSByZXR1cm47CiAgICAgIHBhbmVsLnN0eWxlLmxlZnQgPSBpbml0TGVmdCArIGUuY2xpZW50WCAtIHN0YXJ0WCArICdweCc7CiAgICAgIHBhbmVsLnN0eWxlLnRvcCA9IGluaXRUb3AgKyBlLmNsaWVudFkgLSBzdGFydFkgKyAncHgnOwogICAgICBwYW5lbC5zdHlsZS50cmFuc2Zvcm0gPSAnbm9uZSc7CiAgICB9KTsKICAgIGRvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXIoJ21vdXNldXAnLCAoKSA9PiB7CiAgICAgIGlzRHJhZ2dpbmcgPSBmYWxzZTsKICAgIH0pOwogICAgY29uc3Qgc28gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtc28nKTsKICAgIGNvbnN0IHNldHRpbmdzQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLXNldHRpbmdzQnRuJyk7CiAgICBjb25zdCBzb0Nsb3NlID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLXNvQ2xvc2UnKTsKICAgIGlmIChzZXR0aW5nc0J0biAmJiBzbykgewogICAgICBzZXR0aW5nc0J0bi5vbmNsaWNrID0gKCkgPT4gewogICAgICAgIGNvbnN0IGlzT3BlbiA9ICFzby5jbGFzc0xpc3QuY29udGFpbnMoJ2hpZGRlbicpOwogICAgICAgIHNvLmNsYXNzTGlzdC50b2dnbGUoJ2hpZGRlbicpOwogICAgICAgIHNldHRpbmdzQnRuLmNsYXNzTGlzdC50b2dnbGUoJ2FjdGl2ZScsICFpc09wZW4pOwogICAgICB9OwogICAgfQogICAgaWYgKHNvQ2xvc2UpIHsKICAgICAgc29DbG9zZS5vbmNsaWNrID0gKCkgPT4gewogICAgICAgIHNvLmNsYXNzTGlzdC5hZGQoJ2hpZGRlbicpOwogICAgICAgIGlmIChzZXR0aW5nc0J0bikgc2V0dGluZ3NCdG4uY2xhc3NMaXN0LnJlbW92ZSgnYWN0aXZlJyk7CiAgICAgIH07CiAgICB9CiAgICBpZiAoc28pIHsKICAgICAgc28ucXVlcnlTZWxlY3RvckFsbCgnLnRsLXRjJykuZm9yRWFjaChjYXJkID0+IHsKICAgICAgICBjYXJkLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gewogICAgICAgICAgY29uc3QgbmV3VGhlbWUgPSBjYXJkLmRhdGFzZXQudDsKICAgICAgICAgIGlmIChuZXdUaGVtZSA9PT0gQ1VSUkVOVF9USEVNRSkgewogICAgICAgICAgICBzby5jbGFzc0xpc3QuYWRkKCdoaWRkZW4nKTsKICAgICAgICAgICAgaWYgKHNldHRpbmdzQnRuKSBzZXR0aW5nc0J0bi5jbGFzc0xpc3QucmVtb3ZlKCdhY3RpdmUnKTsKICAgICAgICAgICAgcmV0dXJuOwogICAgICAgICAgfQogICAgICAgICAgc28ucXVlcnlTZWxlY3RvckFsbCgnLnRsLXRjJykuZm9yRWFjaChjID0+IHsKICAgICAgICAgICAgYy5jbGFzc0xpc3QudG9nZ2xlKCdhY3RpdmUnLCBjLmRhdGFzZXQudCA9PT0gbmV3VGhlbWUpOwogICAgICAgICAgfSk7CiAgICAgICAgICBhcHBseVRoZW1lTGl2ZShuZXdUaGVtZSk7CiAgICAgICAgICBjb25zdCBleGlzdEZ4ID0gcGFuZWwucXVlcnlTZWxlY3RvcignI3RsLWNvbm4tZngtYmFyLCN0bC1jb25uLWZ4LXBldGFscycpOwogICAgICAgICAgaWYgKGV4aXN0RngpIGV4aXN0RngucmVtb3ZlKCk7CiAgICAgICAgICBjb25zdCBuZXdUYyA9IGdldFRoZW1lQ29sb3JzKG5ld1RoZW1lKTsKICAgICAgICAgIGlmIChuZXdUYy5wYW5lbEV4dHJhKSB7CiAgICAgICAgICAgIGNvbnN0IHRtcCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpOwogICAgICAgICAgICB0bXAuaW5uZXJIVE1MID0gbmV3VGMucGFuZWxFeHRyYTsKICAgICAgICAgICAgY29uc3QgZnhFbCA9IHRtcC5maXJzdEVsZW1lbnRDaGlsZDsKICAgICAgICAgICAgaWYgKGZ4RWwpIHBhbmVsLmluc2VydEJlZm9yZShmeEVsLCBwYW5lbC5maXJzdENoaWxkKTsKICAgICAgICAgIH0KICAgICAgICAgIHNldFRpbWVvdXQoKCkgPT4gewogICAgICAgICAgICBzby5jbGFzc0xpc3QuYWRkKCdoaWRkZW4nKTsKICAgICAgICAgICAgaWYgKHNldHRpbmdzQnRuKSBzZXR0aW5nc0J0bi5jbGFzc0xpc3QucmVtb3ZlKCdhY3RpdmUnKTsKICAgICAgICAgIH0sIDMyMCk7CiAgICAgICAgfSk7CiAgICAgIH0pOwogICAgfQogICAgY29uc3QgbW9kZVNlbGVjdCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1tb2RlU2VsZWN0Jyk7CiAgICBjb25zdCBkZXRlY3RlZE1vZGUgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtbW9kZS1kZXRlY3RlZCcpOwogICAgaWYgKG1vZGVTZWxlY3QpIHsKICAgICAgbW9kZVNlbGVjdC5hZGRFdmVudExpc3RlbmVyKCdjaGFuZ2UnLCBmdW5jdGlvbigpIHsKICAgICAgICBpZiAoZGV0ZWN0ZWRNb2RlKSBkZXRlY3RlZE1vZGUudGV4dENvbnRlbnQgPSB0aGlzLnZhbHVlLnRvVXBwZXJDYXNlKCk7CiAgICAgIH0pOwogICAgfQogICAgYXN5bmMgZnVuY3Rpb24gZm9yY2VGZXRjaFF1ZXN0aW9ucygpIHsKICAgICAgdHJ5IHsKICAgICAgICBmb3JjZUdldE1ldGEoKTsKICAgICAgICBjb25zdCBVVyA9IHR5cGVvZiB1bnNhZmVXaW5kb3cgIT09ICd1bmRlZmluZWQnID8gdW5zYWZlV2luZG93IDogd2luZG93OwogICAgICAgIHRyeSB7CiAgICAgICAgICBjb25zdCBidWYgPSBVVy5fX2t2X3FfYnVmOwogICAgICAgICAgaWYgKEFycmF5LmlzQXJyYXkoYnVmKSkgewogICAgICAgICAgICBmb3IgKGxldCBpID0gMDsgaSA8IGJ1Zi5sZW5ndGg7IGkrKykgewogICAgICAgICAgICAgIGNvbnN0IGl0ID0gYnVmW2ldOwogICAgICAgICAgICAgIGlmIChpdCAmJiBpdC51cmwgJiYgaXQudGV4dCkgewogICAgICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgICAgaGFuZGxlUmF3UmVzcG9uc2UoaXQudXJsLCBpdC50ZXh0KTsKICAgICAgICAgICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgICB9CiAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgICBpZiAoU0VTU0lPTi5yYXdfcXVlc3Rpb25zLmxlbmd0aCA+IDApIHsgdHJ5IHsgcmVzY3VlQW5zRmlsZVJlcXVlc3QoKTsgfSBjYXRjaCAoXykge30gcmV0dXJuIHRydWU7IH0KICAgICAgICB0cnkgewogICAgICAgICAgY29uc3QgcmVzTGlzdCA9ICh0eXBlb2YgcGVyZm9ybWFuY2UgIT09ICd1bmRlZmluZWQnICYmIHBlcmZvcm1hbmNlLmdldEVudHJpZXNCeVR5cGUpID8gcGVyZm9ybWFuY2UuZ2V0RW50cmllc0J5VHlwZSgncmVzb3VyY2UnKSA6IFtdOwogICAgICAgICAgZm9yIChsZXQgcmkgPSAwOyByaSA8IHJlc0xpc3QubGVuZ3RoOyByaSsrKSB7CiAgICAgICAgICAgIGNvbnN0IHUgPSByZXNMaXN0W3JpXS5uYW1lIHx8ICcnOwogICAgICAgICAgICBpZiAoIXUgfHwgdS5pbmRleE9mKFNFUlZFUl9CQVNFKSAhPT0gLTEpIGNvbnRpbnVlOwogICAgICAgICAgICBpZiAoISh1LmluZGV4T2YoJ2dldC1xdWVzdGlvbicpICE9PSAtMSB8fCB1LmluZGV4T2YoJ2dldC10ZXN0JykgIT09IC0xIHx8IEFQSV9LRVlXT1JEUy5zb21lKGsgPT4gdS5pbmRleE9mKGspICE9PSAtMSkpKSBjb250aW51ZTsKICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICBjb25zdCByMiA9IGF3YWl0IGZldGNoKHUsIHsgY3JlZGVudGlhbHM6ICdpbmNsdWRlJywgY2FjaGU6ICduby1jYWNoZScgfSk7CiAgICAgICAgICAgICAgaWYgKHIyICYmIHIyLm9rKSB7CiAgICAgICAgICAgICAgICBjb25zdCB0MiA9IGF3YWl0IHIyLnRleHQoKTsKICAgICAgICAgICAgICAgIHRyeSB7IGhhbmRsZVJhd1Jlc3BvbnNlKHUsIHQyKTsgfSBjYXRjaCAoXykge30KICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgICAgIGlmIChTRVNTSU9OLnJhd19xdWVzdGlvbnMubGVuZ3RoID4gMCkgeyB0cnkgeyByZXNjdWVBbnNGaWxlUmVxdWVzdCgpOyB9IGNhdGNoIChfKSB7fSByZXR1cm4gdHJ1ZTsgfQogICAgICAgICAgfQogICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgY29uc3QgbGFzdCA9IFVXLl9fdGxfbGFzdF9xcmVxOwogICAgICAgIGlmIChsYXN0ICYmIGxhc3QudXJsKSB7CiAgICAgICAgICB0cnkgewogICAgICAgICAgICBjb25zdCBmb3B0cyA9IHsKICAgICAgICAgICAgICBtZXRob2Q6IGxhc3QubWV0aG9kIHx8ICdHRVQnLAogICAgICAgICAgICAgIGNyZWRlbnRpYWxzOiAnaW5jbHVkZScsCiAgICAgICAgICAgICAgY2FjaGU6ICduby1jYWNoZScKICAgICAgICAgICAgfTsKICAgICAgICAgICAgaWYgKGxhc3QuYm9keSAmJiAobGFzdC5tZXRob2QgfHwgJ0dFVCcpLnRvVXBwZXJDYXNlKCkgIT09ICdHRVQnKSB7CiAgICAgICAgICAgICAgZm9wdHMuaGVhZGVycyA9IHsKICAgICAgICAgICAgICAgICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkOyBjaGFyc2V0PVVURi04JywKICAgICAgICAgICAgICAgICdYLVJlcXVlc3RlZC1XaXRoJzogJ1hNTEh0dHBSZXF1ZXN0JwogICAgICAgICAgICAgIH07CiAgICAgICAgICAgICAgZm9wdHMuYm9keSA9IGxhc3QuYm9keTsKICAgICAgICAgICAgfQogICAgICAgICAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChsYXN0LnVybCwgZm9wdHMpOwogICAgICAgICAgICBpZiAocmVzLm9rKSB7CiAgICAgICAgICAgICAgY29uc3QgdHh0ID0gYXdhaXQgcmVzLnRleHQoKTsKICAgICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgaGFuZGxlUmF3UmVzcG9uc2UobGFzdC51cmwsIHR4dCk7CiAgICAgICAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgICAgICAgfQogICAgICAgICAgfSBjYXRjaCAoZSkgewogICAgICAgICAgICBjb25zb2xlLndhcm4oJ1tUTF0gcmVwbGF5IGZhaWwnLCBlKTsKICAgICAgICAgIH0KICAgICAgICB9CiAgICAgICAgcmV0dXJuIFNFU1NJT04ucmF3X3F1ZXN0aW9ucy5sZW5ndGggPiAwOwogICAgICB9IGNhdGNoIChlKSB7CiAgICAgICAgcmV0dXJuIGZhbHNlOwogICAgICB9CiAgICB9CiAgICBmdW5jdGlvbiBfYXBwbHlFeGFtVGltZSgpIHsKICAgIHRyeSB7CiAgICAgIGNvbnN0IGlucCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0bC1nb2QtdGltZSIpOwogICAgICBpZiAoIWlucCkgcmV0dXJuOwogICAgICBjb25zdCBtb2RlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGwtbW9kZVNlbGVjdCIpOwogICAgICBjb25zdCBtb2RlID0gbW9kZUVsID8gbW9kZUVsLnZhbHVlIDogImV4YW0iOwogICAgICBjb25zdCBzID0gU3RyaW5nKGlucC52YWx1ZSB8fCAiIikudHJpbSgpIHx8ICIyNS4wMCI7CiAgICAgIGNvbnN0IHBhcnRzID0gcy5zcGxpdCgvWy46XS8pOwogICAgICBjb25zdCBtaW5zID0gcGFyc2VJbnQocGFydHNbMF0pIHx8IDA7CiAgICAgIGxldCBzZWNzID0gcGFyc2VJbnQocGFydHNbMV0gfHwgIjAiKTsgaWYgKGlzTmFOKHNlY3MpKSBzZWNzID0gMDsKICAgICAgY29uc3QgdG90YWwgPSBNYXRoLm1heCgzMCwgbWlucyAqIDYwICsgc2Vjcyk7CiAgICAgIHRyeSB7IHdpbmRvdy50b3RhbF90aW1lID0gdG90YWw7IH0gY2F0Y2ggKF8pIHt9CiAgICAgIGNvbnN0IG1tID0gU3RyaW5nKE1hdGguZmxvb3IodG90YWwgLyA2MCkpLnBhZFN0YXJ0KDIsICIwIik7CiAgICAgIGNvbnN0IHNzID0gU3RyaW5nKHRvdGFsICUgNjApLnBhZFN0YXJ0KDIsICIwIik7CiAgICAgIGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoIi50aW1lLWNvdW50ZG93bixbY2xhc3MqPWNvdW50ZG93bl0sW2lkKj1jb3VudGRvd25dLFtjbGFzcyo9dGltZXJdLCN0aW1lLWxlZnQsI2V4YW0tdGltZXIiKS5mb3JFYWNoKGZ1bmN0aW9uKGVsKSB7CiAgICAgICAgaWYgKGVsICYmIGVsLnRleHRDb250ZW50ICYmIC9cZHsxLDJ9OlxkezJ9Ly50ZXN0KGVsLnRleHRDb250ZW50KSkgZWwudGV4dENvbnRlbnQgPSBtbSArICI6IiArIHNzOwogICAgICB9KTsKICAgICAgYWRkTG9nKCLij7HvuI8gxJDhurd0IHRo4budaSBnaWFuIGzDoG0gYsOgaTogIiArIG1pbnMgKyAiIHBow7p0ICIgKyBzZWNzICsgIiBnacOieSAoIiArIG1tICsgIjoiICsgc3MgKyAiKS4iLCAiaW5mbyIpOwogICAgfSBjYXRjaCAoXykge30KICB9CiAgY29uc3QgZmlyZUJ0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1maXJlQnRuJyk7CiAgICBmdW5jdGlvbiBfdGd0U2NvcmVWYWwoKXsKICAgICAgdHJ5IHsKICAgICAgICB2YXIgX2VsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLWdvZC10YXJnZXQtc2NvcmUnKTsKICAgICAgICB2YXIgX3YgPSBfZWwgPyBwYXJzZUZsb2F0KF9lbC52YWx1ZSkgOiAxMDsKICAgICAgICBpZiAoIWlzRmluaXRlKF92KSkgX3YgPSAxMDsKICAgICAgICByZXR1cm4gTWF0aC5taW4oMTAsIE1hdGgubWF4KDcsIF92KSk7CiAgICAgIH0gY2F0Y2ggKF8pIHsgcmV0dXJuIDEwOyB9CiAgICB9CiAgICBmdW5jdGlvbiB1cGRhdGVGaXJlTGFiZWwoKXsKICAgICAgaWYgKCFmaXJlQnRuKSByZXR1cm47CiAgICAgIHZhciBfdiA9IF90Z3RTY29yZVZhbCgpOwogICAgICBpZiAoIWlzUHJlbWl1bUtleSgpKSB7CiAgICAgICAgZmlyZUJ0bi5pbm5lckhUTUwgPSAn8J+UkiBDSFXhuqhOIELhu4o4SSAnICsgX3YgKyAnIMSQSeG7gk0gKENI4buOIFBSRU1JVU0pJzsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgaWYgKCFmaXJlQnRuLmRpc2FibGVkKSBmaXJlQnRuLnRleHRDb250ZW50ID0gJ/CfkqUgQ0hV4bqoTiBC4buKOEkgJyArIF92ICsgJyDEkEnhu4JNJzsKICAgIH0KICAgIGlmICghaXNQcmVtaXVtS2V5KCkpIHsKICAgICAgdXBkYXRlRmlyZUxhYmVsKCk7CiAgICAgIGZpcmVCdG4uc3R5bGUuYmFja2dyb3VuZCA9ICdsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLCM0NDQsIzY2NiknOwogICAgICBmaXJlQnRuLnN0eWxlLmN1cnNvciA9ICdub3QtYWxsb3dlZCc7CiAgICAgIGZpcmVCdG4uc3R5bGUub3BhY2l0eSA9ICcwLjYnOwogICAgICBmaXJlQnRuLnRpdGxlID0gJ0No4bupYyBuxINuZyBuw6B5IGNo4buJIGTDoG5oIGNobyBrZXkgUFJFTUlVTS4gTGnDqm4gaOG7hyDEkeG7gyBuw6JuZyBj4bqlcCEnOwogICAgICBmaXJlQnRuLm9uY2xpY2sgPSBlID0+IHsKICAgICAgICBlLnByZXZlbnREZWZhdWx0KCk7CiAgICAgICAgYWRkTG9nKCfwn5SSIENo4bupYyBuxINuZyBuw6B5IHnDqnUgY+G6p3Uga2V5IFBSRU1JVU0hJywgJ2VycicpOwogICAgICAgIGFkZExvZygn8J+SjiBMacOqbiBo4buHIGFkbWluIMSR4buDIG7Dom5nIGPhuqVwIGtleSBQUkVNSVVNLicsICd3YXJuJyk7CiAgICAgICAgc2hvd0N1c3RvbU1vZGFsKHsKICAgICAgICAgIGljb246ICfwn5SSJywKICAgICAgICAgIHRpdGxlOiAnWcOKVSBD4bqmVSBLRVkgUFJFTUlVTScsCiAgICAgICAgICBsaW5lczogWyAnQ2jhu6ljIG7Eg25nIDxiPiJDSFXhuqhOIELhu4ogMTAgxJBJ4buCTSI8L2I+IGNo4buJIGTDoG5oIGNobyBrZXkgUFJFTUlVTSEnLCBgS2V5IGPhu6dhIGLhuqFuIGzDoCBrZXkgPGI+JHsoS0VZX1NUQVRVUy50eXBlIHx8ICdUSMav4bucTkcnKS50b1VwcGVyQ2FzZSgpfTwvYj4uYCwgJ/Cfko4gTGnDqm4gaOG7hyBhZG1pbiDEkeG7gyBuw6JuZyBj4bqlcCBsw6puIFBSRU1JVU0hJyBdCiAgICAgICAgfSk7CiAgICAgIH07CiAgICB9IGVsc2UgewogICAgICB1cGRhdGVGaXJlTGFiZWwoKTsKICAgICAgZmlyZUJ0bi5vbmNsaWNrID0gYXN5bmMgKCkgPT4gewogICAgICAgIGFkZExvZygn8J+UjSDEkOG7k25nIGLhu5kgZOG7ryBsaeG7h3UgdGjDtCB04burIE9MTS4uLicsICdpbmZvJyk7CiAgICAgICAgYXdhaXQgZm9yY2VGZXRjaFF1ZXN0aW9ucygpOwogICAgICAgIGZvcmNlR2V0TWV0YSgpOwogICAgICAgIGlmICghU0VTU0lPTi5tZXRhLmlkX3VzZXIgfHwgIVNFU1NJT04ubWV0YS5pZF9jYXRlKSB7CiAgICAgICAgICBhZGRMb2coJ+KdjCBDaMawYSBjw7MgSUQgdXNlci9jYXRlICh1c2VyPScgKyAoU0VTU0lPTi5tZXRhLmlkX3VzZXIgfHwgJz8nKSArICcsIGNhdGU9JyArIChTRVNTSU9OLm1ldGEuaWRfY2F0ZSB8fCAnPycpICsgJykuIEjDo3kgRjUgaG/hurdjIGNo4budIHThuqNpIHhvbmcgY8OidSBo4buPaS4nLCAnZXJyJyk7CiAgICAgICAgICBzaG93Q3VzdG9tTW9kYWwoewogICAgICAgICAgICBpY29uOiAn4pqg77iPJywKICAgICAgICAgICAgdGl0bGU6ICdUSEnhur5VIEThu64gTEnhu4ZVJywKICAgICAgICAgICAgbGluZXM6IFsgJ0NoxrBhIG5o4bqtbiDEkcaw4bujYyBJRCB0w6BpIGtob+G6o24gLyBiw6BpIHThuq1wIHThu6sgdHJhbmcgT0xNLjxicj5WdWkgbMOybmcgRjUgdHJhbmcsIMSR4bujaSBkYW5oIHPDoWNoIGPDonUgaOG7j2kgbuG6oXAgeG9uZyBy4buTaSBi4bqlbSBs4bqhaS4nIF0KICAgICAgICAgIH0pOwogICAgICAgICAgcmV0dXJuOwogICAgICAgIH0KICAgICAgICBpZiAoU0VTU0lPTi5yYXdfcXVlc3Rpb25zLmxlbmd0aCA9PT0gMCkgewogICAgICAgICAgaWYgKCFfc3ludGhlc2l6ZVF1ZXN0aW9uc0Zyb21BbnN3ZXJzKGZhbHNlKSkgewogICAgICAgICAgICBhZGRMb2coJ+KdjCBDaMawYSBu4bqhcCDEkcaw4bujYyBjw6J1IGjhu49pLiBIw6N5IEY1IHRyYW5nIGhv4bq3YyBsw6BtIG3hu5tpIGLDoGkgdOG6rXAuJywgJ2VycicpOwogICAgICAgICAgICBzaG93Q3VzdG9tTW9kYWwoewogICAgICAgICAgICAgIGljb246ICfwn5OtJywKICAgICAgICAgICAgICB0aXRsZTogJ0NIxq9BIEPDkyBDw4JVIEjhu45JJywKICAgICAgICAgICAgICBsaW5lczogWyAnRGFuaCBzw6FjaCBjw6J1IGjhu49pIMSRYW5nIHRy4buRbmcuIEY1IHRyYW5nIGLDoGkgdOG6rXAgcuG7k2kgYuG6pW0gbOG6oWkuJyBdCiAgICAgICAgICAgIH0pOwogICAgICAgICAgICByZXR1cm47CiAgICAgICAgICB9CiAgICAgICAgICBhZGRMb2coJ+KchSBEw7luZyAnICsgU0VTU0lPTi5yYXdfcXVlc3Rpb25zLmxlbmd0aCArICcgY8OidSBk4buxbmcgdOG7qyDEkcOhcCDDoW4ga2hvL3NlcnZlciDEkeG7gyBu4buZcC4nLCAnb2snKTsKICAgICAgICB9CiAgICAgICAgY29uc3Qga2V5ID0gQ1VSUkVOVF9LRVkgfHwgX3NMUy5nZXQoTFNfS0VZKTsKICAgICAgICBjb25zdCBtb2RlID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLW1vZGVTZWxlY3QnKS52YWx1ZTsKICAgICAgICBjb25zdCB0aW1lX3N0ciA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1nb2QtdGltZScpLnZhbHVlOwogICAgICAgIF9hcHBseUV4YW1UaW1lKCk7CiAgICAgICAgZmlyZUJ0bi5kaXNhYmxlZCA9IHRydWU7CiAgICAgICAgZmlyZUJ0bi50ZXh0Q29udGVudCA9ICfij7MgxJBBTkcgWOG7rCBMw50gVFLDik4gU0VSVkVSLi4uJzsKICAgICAgICBhZGRMb2coJ/CfmoAgR+G7rWkgZOG7ryBsaeG7h3UgdGjDtCBsw6puIHNlcnZlciAobW9kZTogJyArIG1vZGUgKyAnKS4uLicsICd3YXJuJyk7CiAgICAgICAgdHJ5IHsKICAgICAgICAgIGxldCByZXN1bHQgPSBudWxsOwogICAgICAgICAgZm9yIChsZXQgX2ZhID0gMDsgX2ZhIDwgMjsgX2ZhKyspIHsKICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICByZXN1bHQgPSBhd2FpdCBnbVBvc3QoJy9maXJlJywgewogICAgICAgICAgICAgICAga2V5OiBrZXksCiAgICAgICAgICAgICAgICBod2lkOiBnZXRIV0lEKCksCiAgICAgICAgICAgICAgICBzZXNzaW9uOiB7CiAgICAgICAgICAgICAgICAgIHJhd19xdWVzdGlvbnM6IFNFU1NJT04ucmF3X3F1ZXN0aW9ucywKICAgICAgICAgICAgICAgICAgYW5zd2VyczogW10uY29uY2F0KFNFU1NJT04uYW5zRmlsZUFuc3dlcnMgfHwgW10sIFNFU1NJT04uYmFua0Fuc3dlcnMgfHwgW10pLAogICAgICAgICAgICAgICAgICBtZXRhOiBTRVNTSU9OLm1ldGEsCiAgICAgICAgICAgICAgICAgIHZpZGVvX2xlbmd0aDogU0VTU0lPTi52aWRlb19sZW5ndGgKICAgICAgICAgICAgICAgIH0sCiAgICAgICAgICAgICAgICBtb2RlOiBtb2RlLAogICAgICAgICAgICAgICAgdGltZV9zdHI6IHRpbWVfc3RyLAogICAgICAgICAgICAgICAgZ3JhZGU6IHdpbmRvdy5ncmFkZSB8fCB3aW5kb3cuaWRfZ3JhZGUgfHwgJzEwJywKICAgICAgICAgICAgICAgIHRhcmdldF9zY29yZTogU3RyaW5nKF90Z3RTY29yZVZhbCgpKSwKICAgICAgICAgICAgICAgIG9sbV91c2VyOiAoZ2V0T2xtVXNlcm5hbWUoKSB8fCAnJykKICAgICAgICAgICAgICB9KTsKICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgfSBjYXRjaCAoX2ZlKSB7CiAgICAgICAgICAgICAgaWYgKF9mYSA9PT0gMCkgewogICAgICAgICAgICAgICAgYWRkTG9nKCfimqDvuI8gTeG6pXQgbeG6oW5nIGtoaSBn4butaSBzZXJ2ZXIg4oCUIHThu7EgdGjhu60gbOG6oWkgc2F1IDEuNXMuLi4nLCAnd2FybicpOwogICAgICAgICAgICAgICAgYXdhaXQgbmV3IFByb21pc2UociA9PiBzZXRUaW1lb3V0KHIsIDE1MDApKTsKICAgICAgICAgICAgICAgIGNvbnRpbnVlOwogICAgICAgICAgICAgIH0KICAgICAgICAgICAgICB0aHJvdyBfZmU7CiAgICAgICAgICAgIH0KICAgICAgICAgIH0KICAgICAgICAgIGlmIChyZXN1bHQgJiYgcmVzdWx0LnJldm9rZWQpIHsKICAgICAgICAgICAgX3B1cmdlQ2xpZW50U3RhdGUoKTsKICAgICAgICAgICAgX2VudGVyQmFuTW9kZSgnU2VydmVyIHRodSBo4buTaSBxdXnhu4FuOiB0aGnhur90IGLhu4svSVAgxJHDoyBi4buLIGFkbWluIGtob8OhLicpOwogICAgICAgICAgICByZXR1cm47CiAgICAgICAgICB9CiAgICAgICAgICBpZiAoIShyZXN1bHQuc3VjY2VzcyB8fCByZXN1bHQudmFsaWQpKSB7CiAgICAgICAgICAgIGNvbnN0IHN0ID0gcmVzdWx0Ll9odHRwU3RhdHVzOwogICAgICAgICAgICBjb25zdCBtc2cgPSByZXN1bHQubWVzc2FnZSB8fCAnTOG7l2kga2jDtG5nIHjDoWMgxJHhu4tuaCB04burIHNlcnZlcic7CiAgICAgICAgICAgIGFkZExvZygn4p2MIFNlcnZlciB04burIGNo4buRaTogJyArIG1zZywgJ2VycicpOwogICAgICAgICAgICBpZiAoc3QgPT09IDQwMSkgc2hvd0N1c3RvbU1vZGFsKHsKICAgICAgICAgICAgICBpY29uOiAn8J+UkicsCiAgICAgICAgICAgICAgdGl0bGU6ICdLRVkgS0jDlE5HIEjhu6JQIEzhu4YnLAogICAgICAgICAgICAgIGxpbmVzOiBbIG1zZywgJ1Z1aSBsw7JuZyBuaOG6rXAga2V5IGjhu6NwIGzhu4cgaG/hurdjIGxpw6puIGjhu4cgYWRtaW4uJyBdCiAgICAgICAgICAgIH0pOyBlbHNlIGlmIChzdCA9PT0gNDAzKSBzaG93Q3VzdG9tTW9kYWwoewogICAgICAgICAgICAgIGljb246ICfwn5KOJywKICAgICAgICAgICAgICB0aXRsZTogJ0PhuqZOIEtFWSBQUkVNSVVNJywKICAgICAgICAgICAgICBsaW5lczogWyBtc2cgXQogICAgICAgICAgICB9KTsgZWxzZSBpZiAoc3QgPT09IDQyOSkgc2hvd0N1c3RvbU1vZGFsKHsKICAgICAgICAgICAgICBpY29uOiAn4o+zJywKICAgICAgICAgICAgICB0aXRsZTogJ1FVw4EgVOG6pk4gU1XhuqRUJywKICAgICAgICAgICAgICBsaW5lczogWyBtc2csICdWdWkgbMOybmcgY2jhu50gdsOgaSBwaMO6dCBy4buTaSB0aOG7rSBs4bqhaS4nIF0KICAgICAgICAgICAgfSk7IGVsc2Ugc2hvd0N1c3RvbU1vZGFsKHsKICAgICAgICAgICAgICBpY29uOiAn4pqg77iPJywKICAgICAgICAgICAgICB0aXRsZTogJ0tIw5RORyBO4buYUCDEkMav4buiQycsCiAgICAgICAgICAgICAgbGluZXM6IFsgbXNnIF0KICAgICAgICAgICAgfSk7CiAgICAgICAgICAgIGZpcmVCdG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgICAgICAgdXBkYXRlRmlyZUxhYmVsKCk7CiAgICAgICAgICAgIHJldHVybjsKICAgICAgICAgIH0KICAgICAgICAgIGFkZExvZygn8J+TpCBTZXJ2ZXIgxJHDoyBk4buxbmcgeG9uZyBiw6BpIOKAlCDEkWFuZyBn4butaSBsw6puIE9MTS4uLicsICdpbmZvJyk7CiAgICAgICAgICBfYXBwbHlFeGFtVGltZSgpOwogICAgICAgICAgaWYgKHJlc3VsdC5zdW1tYXJ5ICYmIEFycmF5LmlzQXJyYXkocmVzdWx0LnN1bW1hcnkuaXRlbXMpICYmIHJlc3VsdC5zdW1tYXJ5Lml0ZW1zLmxlbmd0aCkgewogICAgICAgICAgICBhZGRMb2coJ/Cfp64gU2VydmVyIMSRw6MgZ2nhuqNpICcgKyAocmVzdWx0LnN1bW1hcnkuY291bnQgfHwgcmVzdWx0LnN1bW1hcnkuaXRlbXMubGVuZ3RoKSArICcgY8OidSAobW9kZTogJyArIChyZXN1bHQuc3VtbWFyeS5tb2RlIHx8IG1vZGUpICsgJykuJywgJ2luZm8nKTsKICAgICAgICAgIH0KICAgICAgICAgIGNvbnN0IGNzcmYgPSBTRVNTSU9OLm1ldGEuY3NyZl90b2tlbiB8fCBkb2N1bWVudC5xdWVyeVNlbGVjdG9yKCdtZXRhW25hbWU9ImNzcmYtdG9rZW4iXScpPy5nZXRBdHRyaWJ1dGUoJ2NvbnRlbnQnKSB8fCAnJzsKICAgICAgICAgIGxldCByZXNwb25zZSA9IG51bGw7CiAgICAgICAgICBmb3IgKGxldCBfc2EgPSAwOyBfc2EgPCAyOyBfc2ErKykgewogICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgIHJlc3BvbnNlID0gYXdhaXQgZmV0Y2gocmVzdWx0LmVuZHBvaW50IHx8ICcvY291cnNlL3RlYWNoZXItc3RhdGljJywgewogICAgICAgICAgICAgICAgbWV0aG9kOiAnUE9TVCcsCiAgICAgICAgICAgICAgICBjcmVkZW50aWFsczogJ2luY2x1ZGUnLAogICAgICAgICAgICAgICAgaGVhZGVyczogewogICAgICAgICAgICAgICAgICAnY29udGVudC10eXBlJzogJ2FwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZDsgY2hhcnNldD1VVEYtOCcsCiAgICAgICAgICAgICAgICAgICd4LWNzcmYtdG9rZW4nOiBjc3JmLAogICAgICAgICAgICAgICAgICAneC1yZXF1ZXN0ZWQtd2l0aCc6ICdYTUxIdHRwUmVxdWVzdCcKICAgICAgICAgICAgICAgIH0sCiAgICAgICAgICAgICAgICBib2R5OiByZXN1bHQucGFyYW1zX3N0cgogICAgICAgICAgICAgIH0pOwogICAgICAgICAgICAgIGlmIChyZXNwb25zZS5vayB8fCBfc2EgPT09IDEpIGJyZWFrOwogICAgICAgICAgICAgIGFkZExvZygn4pqg77iPIE9MTSB0cuG6oyBIVFRQICcgKyByZXNwb25zZS5zdGF0dXMgKyAnIOKAlCB0aOG7rSBs4bqhaSBzYXUgMS44cy4uLicsICd3YXJuJyk7CiAgICAgICAgICAgICAgYXdhaXQgbmV3IFByb21pc2UociA9PiBzZXRUaW1lb3V0KHIsIDE4MDApKTsKICAgICAgICAgICAgfSBjYXRjaCAoX3NlKSB7CiAgICAgICAgICAgICAgaWYgKF9zYSA9PT0gMCkgewogICAgICAgICAgICAgICAgYWRkTG9nKCfimqDvuI8gTeG6pXQgbeG6oW5nIGtoaSBu4buZcCBPTE0g4oCUIHRo4butIGzhuqFpIHNhdSAycy4uLicsICd3YXJuJyk7CiAgICAgICAgICAgICAgICBhd2FpdCBuZXcgUHJvbWlzZShyID0+IHNldFRpbWVvdXQociwgMjAwMCkpOwogICAgICAgICAgICAgICAgY29udGludWU7CiAgICAgICAgICAgICAgfQogICAgICAgICAgICAgIHRocm93IF9zZTsKICAgICAgICAgICAgfQogICAgICAgICAgfQogICAgICAgICAgaWYgKHJlc3BvbnNlLm9rKSB7CiAgICAgICAgICAgIGFkZExvZygn4pyFIE7hu5lwIGLDoGkgdGjDoG5oIGPDtG5nISBLaeG7g20gdHJhIMSRaeG7g20gT0xNLicsICdvaycpOwogICAgICAgICAgICBmaXJlQnRuLnRleHRDb250ZW50ID0gJ+KchSBUSMOATkggQ8OUTkchJzsKICAgICAgICAgICAgZmlyZUJ0bi5zdHlsZS5iYWNrZ3JvdW5kID0gJ2xpbmVhci1ncmFkaWVudCgxMzVkZWcsIzAwYjA5YiwjMDBlNjc2KSc7CiAgICAgICAgICAgIHNob3dDdXN0b21Nb2RhbCh7CiAgICAgICAgICAgICAgaWNvbjogJ+KchScsCiAgICAgICAgICAgICAgdGl0bGU6ICdO4buYUCBCw4BJIFRIw4BOSCBDw5RORycsCiAgICAgICAgICAgICAgbGluZXM6IFsgJ1NlcnZlciDEkcOjIHjhu60gbMO9IDxiPicgKyAocmVzdWx0LnN1bW1hcnkgPyByZXN1bHQuc3VtbWFyeS5jb3VudCB8fCAwIDogU0VTU0lPTi5yYXdfcXVlc3Rpb25zLmxlbmd0aCkgKyAnPC9iPiBjw6J1IHbDoCBn4butaSBsw6puIE9MTS4nLCAnVHJhbmcgc+G6vSB04buxIHThuqNpIGzhuqFpIHNhdSB2w6BpIGdpw6J5LicgXQogICAgICAgICAgICB9KTsKICAgICAgICAgICAgc2V0VGltZW91dCgoKSA9PiB3aW5kb3cubG9jYXRpb24ucmVsb2FkKCksIDI1MDApOwogICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgYWRkTG9nKCfinYwgT0xNIHRy4bqjIHbhu4EgbOG7l2kgSFRUUCAnICsgcmVzcG9uc2Uuc3RhdHVzLCAnZXJyJyk7CiAgICAgICAgICAgIHNob3dDdXN0b21Nb2RhbCh7CiAgICAgICAgICAgICAgaWNvbjogJ+KdjCcsCiAgICAgICAgICAgICAgdGl0bGU6ICdO4buYUCBCw4BJIFRI4bqkVCBC4bqgSScsCiAgICAgICAgICAgICAgbGluZXM6IFsgJ03DoXkgY2jhu6cgT0xNIHRy4bqjIGzhu5dpIEhUVFAgJyArIHJlc3BvbnNlLnN0YXR1cyArICcuPGJyPlRo4butIEY1IHRyYW5nIHLhu5NpIGLhuqVtIGzhuqFpLicgXQogICAgICAgICAgICB9KTsKICAgICAgICAgICAgZmlyZUJ0bi5kaXNhYmxlZCA9IGZhbHNlOwogICAgICAgICAgICB1cGRhdGVGaXJlTGFiZWwoKTsKICAgICAgICAgIH0KICAgICAgICB9IGNhdGNoIChlKSB7CiAgICAgICAgICBhZGRMb2coJ+KdjCBM4buXaTogJyArIGUubWVzc2FnZSwgJ2VycicpOwogICAgICAgICAgc2hvd0N1c3RvbU1vZGFsKHsKICAgICAgICAgICAgaWNvbjogJ/CfjJAnLAogICAgICAgICAgICB0aXRsZTogJ0zhu5ZJIEvhur5UIE7hu5BJJywKICAgICAgICAgICAgbGluZXM6IFsgJ0tow7RuZyBr4bq/dCBu4buRaSDEkcaw4bujYyBzZXJ2ZXIvT0xNOiA8Yj4nICsgKGUubWVzc2FnZSB8fCAnJykgKyAnPC9iPicgXQogICAgICAgICAgfSk7CiAgICAgICAgICBmaXJlQnRuLmRpc2FibGVkID0gZmFsc2U7CiAgICAgICAgICB1cGRhdGVGaXJlTGFiZWwoKTsKICAgICAgICB9CiAgICAgIH07CiAgICB9CiAgICB2YXIgX3RndFNlbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1nb2QtdGFyZ2V0LXNjb3JlJyk7CiAgICBpZiAoX3RndFNlbCkgewogICAgICBfdGd0U2VsLmFkZEV2ZW50TGlzdGVuZXIoJ2NoYW5nZScsIHVwZGF0ZUZpcmVMYWJlbCk7CiAgICAgIHVwZGF0ZUZpcmVMYWJlbCgpOwogICAgfQogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLWNoYW5nZUtleScpLm9uY2xpY2sgPSAoKSA9PiB7CiAgICAgIHNob3dDb25maXJtTW9kYWwoewogICAgICAgIGljb246ICfwn5SEJywKICAgICAgICB0aXRsZTogJ8SQ4buUSSBLRVk/JywKICAgICAgICBsaW5lczogWyAnS2V5IGhp4buHbiB04bqhaSBz4bq9IGLhu4sgPGI+eG/DoSBob8OgbiB0b8OgbjwvYj4uJywgJ0LhuqFuIHPhur0gxJHGsOG7o2MgxJHGsGEgduG7gSBtw6BuIGjDrG5oIMSRxINuZyBuaOG6rXAuJyBdLAogICAgICAgIG9rVGV4dDogJ/CflIQgxJDhu5RJIEtFWScsCiAgICAgICAgY2FuY2VsVGV4dDogJ0jhu6ZZJywKICAgICAgICBvbk9rOiAoKSA9PiB7CiAgICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShMU19LRVkpOwogICAgICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oTFNfVFlQRSk7CiAgICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShMU19FWFApOwogICAgICAgICAgQ1VSUkVOVF9LRVkgPSBudWxsOwogICAgICAgICAgS0VZX1NUQVRVUyA9IHsKICAgICAgICAgICAgdmFsaWQ6IGZhbHNlLAogICAgICAgICAgICB0eXBlOiBudWxsLAogICAgICAgICAgICBleHBpcmVzX2F0OiBudWxsCiAgICAgICAgICB9OwogICAgICAgICAgX3NlY1Nlc3Npb24gPSB7CiAgICAgICAgICAgIHRva2VuOiBudWxsLAogICAgICAgICAgICBleHA6IDAsCiAgICAgICAgICAgIGZwSGFzaDogbnVsbCwKICAgICAgICAgICAgc2VxOiAxCiAgICAgICAgICB9OwogICAgICAgICAgQ1VSUkVOVF9ERVZJQ0UgPSAnJzsKICAgICAgICAgIHBhbmVsLnJlbW92ZSgpOwogICAgICAgICAgZmxvYXRCdG4ucmVtb3ZlKCk7CiAgICAgICAgICBidWlsZExvY2tTY3JlZW4oKTsKICAgICAgICB9CiAgICAgIH0pOwogICAgfTsKICAgIGFkZExvZygn4pyFIEdPRCBNT0QgY29ubmVjdG9yIHN1Y2Nlc3MnLCAnb2snKTsKICAgIHRyeSB7CiAgICAgIGNvbnN0IF91MCA9IGdldE9sbVVzZXJuYW1lKCk7CiAgICAgIF9sYXN0T2xtVXNlciA9IChfdTAgJiYgX3UwICE9PSAnS2hvbmdYYWNEaW5oJykgPyBfdTAgOiAnJzsKICAgICAgaWYgKF9hY2NvdW50UGFnZSgpKSBfZW5zdXJlT2xtTG9nKF9sYXN0T2xtVXNlcik7CiAgICB9IGNhdGNoIChfKSB7fQogICAgc2V0SW50ZXJ2YWwoKCkgPT4gX3JlZnJlc2hPbG1BY2NvdW50KGZhbHNlKSwgMjAwMCk7CiAgICB0cnkgeyB3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcignZm9jdXMnLCAoKSA9PiBfcmVmcmVzaE9sbUFjY291bnQodHJ1ZSkpOyB9IGNhdGNoIChfKSB7fQogICAgdHJ5IHsgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoJ3BhZ2VzaG93JywgKCkgPT4gX3JlZnJlc2hPbG1BY2NvdW50KHRydWUpKTsgfSBjYXRjaCAoXykge30KICAgIHNldEludGVydmFsKCgpID0+IHsKICAgICAgdHJ5IHsKICAgICAgICBpZiAoX2FjY291bnRQYWdlKCkpIF9lbnN1cmVPbG1Mb2coX2xhc3RPbG1Vc2VyKTsKICAgICAgICBlbHNlIF9yZW1vdmVPbG1Mb2dSb3dzKCk7CiAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICB9LCA2MDAwKTsKICAgIGFkZExvZygn4oS577iPIMSQYW5nIGNo4budIG7huqFwIGPDonUgaOG7j2kuLi4nLCAnaW5mbycpOwogICAgaWYgKCFpc1ByZW1pdW1LZXkoKSkgewogICAgICBhZGRMb2coJ+KaoO+4jyBLZXkgdGjGsOG7nW5nOiBDaOG7qWMgbsSDbmcgIkNIVeG6qE4gQuG7iiAxMCDEkEnhu4JNIiBi4buLIGtob8OhIScsICd3YXJuJyk7CiAgICAgIGFkZExvZygn8J+SjiBOw6JuZyBj4bqlcCBQUkVNSVVNIMSR4buDIG3hu58ga2hvw6EgdG/DoG4gYuG7mSB0w61uaCBuxINuZy4nLCAnd2FybicpOwogICAgfSBlbHNlIHsKICAgICAgYWRkTG9nKCfwn5KOIEtleSBQUkVNSVVNOiBU4bqldCBj4bqjIHTDrW5oIG7Eg25nIMSRw6MgxJHGsOG7o2MgbeG7nyBraG/DoSEnLCAnb2snKTsKICAgICAgX3N0YXJ0SGVhcnRiZWF0KCk7CiAgICB9CiAgICBmb3JjZUdldE1ldGEoKTsKICAgIHJlZnJlc2hTdWJqZWN0VGl0bGVVSSgpOwogICAgX3NjaGVkdWxlQmFua0ZhbGxiYWNrKCk7CiAgfQogIGZ1bmN0aW9uIF9jYW5jZWxCYW5rRmFsbGJhY2soKSB7CiAgICBpZiAoX2JhbmtGYWxsYmFja1RpbWVyKSB7IGNsZWFyVGltZW91dChfYmFua0ZhbGxiYWNrVGltZXIpOyBfYmFua0ZhbGxiYWNrVGltZXIgPSBudWxsOyB9CiAgICBfYmFua1JldHJ5ID0gMDsKICB9CiAgbGV0IF9iYW5rTmF2VGltZXIgPSBudWxsOwogIGZ1bmN0aW9uIF9zY2hlZHVsZUJhbmtGYWxsYmFjaygpIHsKICAgIHRyeSB7CiAgICAgIGlmICghaXNFeGVyY2lzZVBhZ2UoKSkgewogICAgICAgIF9jYW5jZWxCYW5rRmFsbGJhY2soKTsKICAgICAgICBpZiAoIV9iYW5rTmF2VGltZXIpIHsKICAgICAgICAgIF9iYW5rTmF2VGltZXIgPSBzZXRJbnRlcnZhbCgoKSA9PiB7CiAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgaWYgKGlzRXhlcmNpc2VQYWdlKCkpIHsKICAgICAgICAgICAgICAgIGlmIChfYmFua05hdlRpbWVyKSB7IGNsZWFySW50ZXJ2YWwoX2JhbmtOYXZUaW1lcik7IF9iYW5rTmF2VGltZXIgPSBudWxsOyB9CiAgICAgICAgICAgICAgICBfc2NoZWR1bGVCYW5rRmFsbGJhY2soKTsKICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgICB9LCA0MDAwKTsKICAgICAgICB9CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIGlmIChfYmFua05hdlRpbWVyKSB7IGNsZWFySW50ZXJ2YWwoX2JhbmtOYXZUaW1lcik7IF9iYW5rTmF2VGltZXIgPSBudWxsOyB9CiAgICAgIF9jYW5jZWxCYW5rRmFsbGJhY2soKTsKICAgICAgX2JhbmtSZXRyeSA9IDA7CiAgICAgIF9iYW5rRmFsbGJhY2tUaW1lciA9IHNldFRpbWVvdXQoX2NoZWNrQW5zd2VyQmFua0ZhbGxiYWNrLCAyNTAwKTsKICAgICAgYWRkTG9nKCfij7MgVHJhbmcgYsOgaSB04bqtcDogc2F1IDIuNXMgbuG6v3UgY2jGsGEgbuG6oXAgY8OidSBo4buPaSBz4bq9IHThu7EgdHJhIGtobyDEkcOhcCDDoW4gc2VydmVyICh0aOG7rSBs4bqhaSBuaGFuaCA2cywgMTJzLCAyMHMsIDMwcywgNDVzKS4nLCAnaW5mbycpOwogICAgfSBjYXRjaCAoXykge30KICB9CiAgdHJ5IHsKICAgIHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKCdoYXNoY2hhbmdlJywgKCkgPT4gX3NjaGVkdWxlQmFua0ZhbGxiYWNrKCkpOwogICAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoJ3BvcHN0YXRlJywgKCkgPT4gX3NjaGVkdWxlQmFua0ZhbGxiYWNrKCkpOwogIH0gY2F0Y2ggKF8pIHt9CiAgZnVuY3Rpb24gX2VzY0JhbmsocykgewogICAgcmV0dXJuIFN0cmluZyhzID09IG51bGwgPyAnJyA6IHMpLnJlcGxhY2UoLyYvZywgJyZhbXA7JykucmVwbGFjZSgvPC9nLCAnJmx0OycpLnJlcGxhY2UoLz4vZywgJyZndDsnKTsKICB9CiAgYXN5bmMgZnVuY3Rpb24gX2NoZWNrQW5zd2VyQmFua0ZhbGxiYWNrKCkgewogICAgaWYgKCFpc0V4ZXJjaXNlUGFnZSgpKSByZXR1cm47CiAgICBpZiAoU0VTU0lPTi5yYXdfcXVlc3Rpb25zLmxlbmd0aCA+IDApIHJldHVybjsKICAgIGZvcmNlR2V0TWV0YSgpOwogICAgU0VTU0lPTi5tZXRhLnN1YmplY3RfbmFtZSA9IGRldGVjdFN1YmplY3ROYW1lKCkgfHwgU0VTU0lPTi5tZXRhLnN1YmplY3RfbmFtZSB8fCAnJzsKICAgIFNFU1NJT04ubWV0YS5leGVyY2lzZV90aXRsZSA9IGRldGVjdEV4ZXJjaXNlVGl0bGUoKSB8fCBTRVNTSU9OLm1ldGEuZXhlcmNpc2VfdGl0bGUgfHwgJyc7CiAgICBTRVNTSU9OLm1ldGEuaWRfY2F0ZSA9IFNFU1NJT04ubWV0YS5pZF9jYXRlIHx8IHJpcElkRnJvbVVybCgpOwogICAgcmVmcmVzaFN1YmplY3RUaXRsZVVJKCk7CiAgICBjb25zdCBjYXRlID0gU0VTU0lPTi5tZXRhLmlkX2NhdGU7CiAgICBpZiAoIWNhdGUgJiYgIVNFU1NJT04ubWV0YS5zdWJqZWN0X25hbWUpIHsgYWRkTG9nKCfihLnvuI8gQ2jGsGEgeMOhYyDEkeG7i25oIG3DoyBtw7RuIChpZF9jYXRlKSAvIHTDqm4gbcO0biDEkeG7gyB0cmEga2hvIMSRw6FwIMOhbi4nLCAnd2FybicpOyByZXR1cm47IH0KICAgIGFkZExvZygn8J+UjiBUcmEga2hvIMSRw6FwIMOhbiBzZXJ2ZXIgKGzhuqduIHRo4butICcgKyAoX2JhbmtSZXRyeSArIDEpICsgJyk6ICcgKyAoU0VTU0lPTi5tZXRhLnN1YmplY3RfbmFtZSA/ICdtw7RuICcgKyBTRVNTSU9OLm1ldGEuc3ViamVjdF9uYW1lIDogJ23DtG4gJyArIGNhdGUpICsgJy4uLicsICdpbmZvJyk7CiAgICB0cnkgewogICAgICBjb25zdCByID0gYXdhaXQgZ21Qb3N0KCcvYW5zd2Vycy9sb29rdXAnLCB7CiAgICAgICAga2V5OiBDVVJSRU5UX0tFWSB8fCBfc0xTLmdldChMU19LRVkpLAogICAgICAgIGh3aWQ6IGdldEhXSUQoKSwKICAgICAgICBjYXRlOiBjYXRlIHx8ICcnLAogICAgICAgIHN1YmplY3Q6IFNFU1NJT04ubWV0YS5zdWJqZWN0X25hbWUgfHwgJycsCiAgICAgICAgZXhlcmNpc2VfdGl0bGU6IFNFU1NJT04ubWV0YS5leGVyY2lzZV90aXRsZSB8fCAnJywKICAgICAgICBjb3Vyc2V3YXJlOiBTRVNTSU9OLm1ldGEuaWRfY291cnNld2FyZSB8fCAnJywKICAgICAgICBvbG1fdXNlcjogZ2V0T2xtVXNlcm5hbWUoKQogICAgICB9KTsKICAgICAgY29uc3QgaGFzSXRlbXMgPSByICYmIHIuZm91bmQgJiYgKEFycmF5LmlzQXJyYXkoci5pdGVtcykgJiYgci5pdGVtcy5sZW5ndGggfHwgQXJyYXkuaXNBcnJheShyLmV4ZXJjaXNlcykgJiYgci5leGVyY2lzZXMubGVuZ3RoKTsKICAgICAgaWYgKGhhc0l0ZW1zKSB7CiAgICAgICAgbGV0IHNjb3BlZCA9IFtdOwogICAgICAgIGxldCBtYXRjaGVkRXggPSBudWxsOwogICAgICAgIGlmIChyLm1hdGNoZWRfZXhlcmNpc2UgJiYgQXJyYXkuaXNBcnJheShyLmV4ZXJjaXNlcykgJiYgci5leGVyY2lzZXMubGVuZ3RoKSB7CiAgICAgICAgICBtYXRjaGVkRXggPSByLmV4ZXJjaXNlcy5maW5kKGV4ID0+IGV4LmtleSA9PT0gci5tYXRjaGVkX2V4ZXJjaXNlLmtleSkKICAgICAgICAgICAgfHwgci5leGVyY2lzZXMuZmluZChleCA9PiBleC50aXRsZSA9PT0gci5tYXRjaGVkX2V4ZXJjaXNlLnRpdGxlKQogICAgICAgICAgICB8fCBudWxsOwogICAgICAgIH0KICAgICAgICBpZiAobWF0Y2hlZEV4ICYmIChtYXRjaGVkRXguaXRlbXMgfHwgW10pLmxlbmd0aCkgc2NvcGVkID0gbWF0Y2hlZEV4Lml0ZW1zOwogICAgICAgIGVsc2UgaWYgKEFycmF5LmlzQXJyYXkoci5leGVyY2lzZXMpICYmIHIuZXhlcmNpc2VzLmxlbmd0aCA9PT0gMSAmJiAoci5leGVyY2lzZXNbMF0uaXRlbXMgfHwgW10pLmxlbmd0aCkgc2NvcGVkID0gci5leGVyY2lzZXNbMF0uaXRlbXM7CiAgICAgICAgZWxzZSBzY29wZWQgPSByLml0ZW1zIHx8IFtdOwogICAgICAgIFNFU1NJT04uYmFua0Fuc3dlcnMgPSBzY29wZWQ7CiAgICAgICAgX3JlZnJlc2hRQ291bnQoKTsKICAgICAgICBfc3ludGhlc2l6ZVF1ZXN0aW9uc0Zyb21BbnN3ZXJzKHRydWUpOwogICAgICAgIHJlbmRlckFuc3dlcnNCbG9jayhzY29wZWQsICLwn5OaIEtobyBzZXJ2ZXI6ICIgKyAoci5zdWJqZWN0IHx8ICJNw7RuIikgKyAobWF0Y2hlZEV4ID8gKCIgwrcgIiArIChtYXRjaGVkRXgudGl0bGUgfHwgIkLDoGkgdOG6rXAiKSkgOiAiIikgKyAiIOKAlCAiICsgc2NvcGVkLmxlbmd0aCArICIgY8OidSwgxJHhuql5IHh14buRbmcgbG9nISIpOwogICAgICAgIGFkZExvZygn4pyFIEtobyBzZXJ2ZXIgY8OzICcgKyBzY29wZWQubGVuZ3RoICsgJyDEkcOhcCDDoW4gY2hvIGLDoGkgdOG6rXAgxJFhbmcgbeG7nyDigJQgxJHDoyBoaeG7g24gdGjhu4sgeHXhu5FuZyBkxrDhu5tpIScsICdvaycpOwogICAgICB9IGVsc2UgewogICAgICAgIGFkZExvZygn4oS577iPIEtobyBzZXJ2ZXIgY2jGsGEgY8OzIMSRw6FwIMOhbiBjaG8gJyArIChTRVNTSU9OLm1ldGEuc3ViamVjdF9uYW1lIHx8ICgnbcO0biAnICsgKGNhdGUgfHwgJz8nKSkpICsgJyBiw6BpIHThuq1wIG7DoHkuJywgJ3dhcm4nKTsKICAgICAgICBfYmFua1JldHJ5Kys7CiAgICAgICAgaWYgKF9iYW5rUmV0cnkgPD0gNSkgewogICAgICAgICAgY29uc3Qgd2FpdE1zID0gWzYwMDAsIDEyMDAwLCAyMDAwMCwgMzAwMDAsIDQ1MDAwXVtfYmFua1JldHJ5IC0gMV0gfHwgNDUwMDA7CiAgICAgICAgICBfYmFua0ZhbGxiYWNrVGltZXIgPSBzZXRUaW1lb3V0KF9jaGVja0Fuc3dlckJhbmtGYWxsYmFjaywgd2FpdE1zKTsKICAgICAgICB9CiAgICAgIH0KICAgIH0gY2F0Y2ggKGUpIHsKICAgICAgYWRkTG9nKCfimqDvuI8gVHJhIGtobyDEkcOhcCDDoW4gbOG7l2k6ICcgKyAoKGUgJiYgZS5tZXNzYWdlKSB8fCBlKSwgJ2VycicpOwogICAgICBfYmFua1JldHJ5Kys7CiAgICAgIGlmIChfYmFua1JldHJ5IDw9IDUpIHsKICAgICAgICBjb25zdCB3YWl0TXMgPSBbNjAwMCwgMTIwMDAsIDIwMDAwLCAzMDAwMCwgNDUwMDBdW19iYW5rUmV0cnkgLSAxXSB8fCA0NTAwMDsKICAgICAgICBfYmFua0ZhbGxiYWNrVGltZXIgPSBzZXRUaW1lb3V0KF9jaGVja0Fuc3dlckJhbmtGYWxsYmFjaywgd2FpdE1zKTsKICAgICAgfQogICAgfQogIH0KICBsZXQgX2xhc3RBbnNGaWxlS2V5ID0gJyc7CiAgbGV0IF9wZW5kaW5nQW5zRmlsZSA9IG51bGw7CiAgbGV0IF9hbnNGaWxlUmVzY3VlZCA9IGZhbHNlOwogIGxldCBfcmVzY3VlU2NoZWR1bGVkID0gZmFsc2U7CiAgZnVuY3Rpb24gX2V4dHJhY3RBbnNGaWxlUmF3KHRleHQpIHsKICAgIGlmICh0ZXh0ID09IG51bGwpIHJldHVybiAnJzsKICAgIGNvbnN0IHQgPSBTdHJpbmcodGV4dCkudHJpbSgpOwogICAgaWYgKCF0KSByZXR1cm4gJyc7CiAgICB0cnkgewogICAgICBjb25zdCBqID0gSlNPTi5wYXJzZSh0KTsKICAgICAgaWYgKGogJiYgdHlwZW9mIGogPT09ICdvYmplY3QnKSB7CiAgICAgICAgaWYgKGouZmMgfHwgai5mZiB8fCBqLnRmIHx8IGouZGcgfHwgai5ucnEgfHwgai5ybnEpIHJldHVybiB0OwogICAgICAgIGZvciAoY29uc3QgayBvZiBbICdkYXRhJywgJ2NvbnRlbnQnLCAnYW5zd2VyX2ZpbGUnLCAnZmlsZScsICdwYXlsb2FkJywgJ2FucycsICdhbnN3ZXJzJywgJ3Jlc3VsdCcsICdib2R5JyBdKSB7CiAgICAgICAgICBpZiAodHlwZW9mIGpba10gPT09ICdzdHJpbmcnICYmIGpba10udHJpbSgpKSByZXR1cm4galtrXTsKICAgICAgICAgIGlmIChqW2tdICYmIHR5cGVvZiBqW2tdID09PSAnb2JqZWN0JykgcmV0dXJuIEpTT04uc3RyaW5naWZ5KGpba10pOwogICAgICAgIH0KICAgICAgfQogICAgfSBjYXRjaCAoXykge30KICAgIHRyeSB7CiAgICAgIGNvbnN0IG0gPSB0Lm1hdGNoKC9bQS1aYS16MC05Ky89Xy1dezQwLH0vZyk7CiAgICAgIGlmIChtICYmIG0ubGVuZ3RoKSByZXR1cm4gbS5zb3J0KChhLCBiKSA9PiBiLmxlbmd0aCAtIGEubGVuZ3RoKVswXTsKICAgIH0gY2F0Y2ggKF8pIHt9CiAgICByZXR1cm4gdDsKICB9CiAgZnVuY3Rpb24gX2Fuc1NpZyhyYXcpIHsKICAgIHJldHVybiByYXcubGVuZ3RoICsgJ3wnICsgcmF3LnNsaWNlKDAsIDEyMCkgKyAnfCcgKyByYXcuc2xpY2UoLTEyMCk7CiAgfQogIGFzeW5jIGZ1bmN0aW9uIF9zdWJtaXRBbnNGaWxlKHVybCwgcmF3LCBrZXlTaWcpIHsKICAgIGZvcmNlR2V0TWV0YSgpOwogICAgY29uc3Qga2V5ID0gQ1VSUkVOVF9LRVkgfHwgX3NMUy5nZXQoTFNfS0VZKTsKICAgIGlmICgha2V5KSByZXR1cm4gZmFsc2U7CiAgICBfbGFzdEFuc0ZpbGVLZXkgPSBrZXlTaWc7CiAgICBhZGRMb2coJ/Cfl53vuI8gUGjDoXQgaGnhu4duIGZpbGUgxJHDoXAgw6FuIGdldC1jcnQtYW5zLWZpbGUg4oCUIGfhu61pIHNlcnZlciBnaeG6o2kgbcOjLi4uJywgJ3dhcm4nKTsKICAgIGNvbnN0IHIgPSBhd2FpdCBnbVBvc3QoJy9hbnNmaWxlL2RlY29kZScsIHsKICAgICAga2V5OiBrZXksCiAgICAgIGh3aWQ6IGdldEhXSUQoKSwKICAgICAgcGF5bG9hZDogcmF3LAogICAgICB1cmw6IHVybCwKICAgICAgb2xtX3VzZXI6IGdldE9sbVVzZXJuYW1lKCksCiAgICAgIG1ldGE6IHsKICAgICAgICBpZF91c2VyOiBTRVNTSU9OLm1ldGEuaWRfdXNlciB8fCBkZXRlY3RVc2VySUQoKSwKICAgICAgICBpZF9jYXRlOiBTRVNTSU9OLm1ldGEuaWRfY2F0ZSwKICAgICAgICBpZF9jb3Vyc2V3YXJlOiBTRVNTSU9OLm1ldGEuaWRfY291cnNld2FyZSwKICAgICAgICBzdWJqZWN0X25hbWU6IFNFU1NJT04ubWV0YS5zdWJqZWN0X25hbWUgfHwgZGV0ZWN0U3ViamVjdE5hbWUoKSB8fCAnJywKICAgICAgICBleGVyY2lzZV90aXRsZTogU0VTU0lPTi5tZXRhLmV4ZXJjaXNlX3RpdGxlIHx8IGRldGVjdEV4ZXJjaXNlVGl0bGUoKSB8fCAnJywKICAgICAgICBzdWJqZWN0X2lkOiBTRVNTSU9OLm1ldGEuc3ViamVjdF9pZCB8fCBudWxsLAogICAgICAgIG9sbV91c2VyOiBnZXRPbG1Vc2VybmFtZSgpCiAgICAgIH0KICAgIH0pOwogICAgaWYgKCEoci5zdWNjZXNzIHx8IHIudmFsaWQpKSB7CiAgICAgIGFkZExvZygn4p2MIFNlcnZlciBnaeG6o2kgbcOjIGZpbGUgxJHDoXAgw6FuIGzhu5dpOiAnICsgKHIubWVzc2FnZSB8fCAna2jDtG5nIHLDtScpLCAnZXJyJyk7CiAgICAgIF9sYXN0QW5zRmlsZUtleSA9ICcnOwogICAgICByZXR1cm4gZmFsc2U7CiAgICB9CiAgICBjb25zdCBpdGVtcyA9IHIucXVlc3Rpb25zIHx8IHIuaXRlbXMgfHwgW107CiAgICBpZiAoIWl0ZW1zLmxlbmd0aCkgeyBhZGRMb2coJ+KEue+4jyBGaWxlIMSRw6FwIMOhbiBraMO0bmcgY8OzIGPDonUgaOG7o3AgbOG7hy4nLCAnd2FybicpOyByZXR1cm4gZmFsc2U7IH0KICAgIFNFU1NJT04uYW5zRmlsZUFuc3dlcnMgPSBpdGVtczsKICAgIHRyeSB7CiAgICAgIGNvbnN0IHNlZW4gPSBuZXcgU2V0KChTRVNTSU9OLmJhbmtBbnN3ZXJzIHx8IFtdKS5tYXAoYiA9PiBiICYmIGIucWlkKSk7CiAgICAgIChpdGVtcyB8fCBbXSkuZm9yRWFjaChpdCA9PiB7IGlmIChpdCAmJiBpdC5xaWQgJiYgIXNlZW4uaGFzKGl0LnFpZCkpIFNFU1NJT04uYmFua0Fuc3dlcnMucHVzaChpdCk7IH0pOwogICAgfSBjYXRjaCAoXykge30KICAgIGNvbnN0IHNlYyA9IHIuZGVjb2RlZF9zZWN0aW9ucyB8fCByLnNlY3Rpb25zIHx8IHt9OwogICAgY29uc3Qgc2VjTGFiZWwgPSBPYmplY3Qua2V5cyhzZWMpLmZpbHRlcihrID0+IHNlY1trXSkubWFwKGsgPT4gay50b1VwcGVyQ2FzZSgpICsgJz0nICsgc2VjW2tdKS5qb2luKCcgwrcgJyk7CiAgICByZW5kZXJBbnN3ZXJzQmxvY2soaXRlbXMsICfwn5eC77iPIGdldC1jcnQtYW5zLWZpbGU6ICcgKyBpdGVtcy5sZW5ndGggKyAnIMSRw6FwIMOhbicgKyAoc2VjTGFiZWwgPyAnICgnICsgc2VjTGFiZWwgKyAnKScgOiAnJykgKyAnIOKAlCBzZXJ2ZXIgZ2nhuqNpIG3DoyB4b25nLCBoaeG7g24gdGjhu4sgeHXhu5FuZyBkxrDhu5tpIScpOwogICAgYWRkTG9nKCfinIUgxJDDoyBuaOG6rW4gJyArIGl0ZW1zLmxlbmd0aCArICcgxJHDoXAgw6FuIHThu6sgZ2V0LWNydC1hbnMtZmlsZScgKyAoc2VjTGFiZWwgPyAnIFsnICsgc2VjTGFiZWwgKyAnXScgOiAnJykgKyAnLicsICdvaycpOwogICAgX3JlZnJlc2hRQ291bnQoKTsKICAgIF9zeW50aGVzaXplUXVlc3Rpb25zRnJvbUFuc3dlcnModHJ1ZSk7CiAgICByZXR1cm4gdHJ1ZTsKICB9CiAgYXN5bmMgZnVuY3Rpb24gaGFuZGxlQW5zRmlsZVJlc3BvbnNlKHVybCwgdGV4dCkgewogICAgdHJ5IHsKICAgICAgY29uc3QgcmF3ID0gX2V4dHJhY3RBbnNGaWxlUmF3KHRleHQpOwogICAgICBpZiAoIXJhdyB8fCByYXcubGVuZ3RoIDwgMTYpIHJldHVybjsKICAgICAgY29uc3Qga2V5U2lnID0gX2Fuc1NpZyhyYXcpOwogICAgICBpZiAoa2V5U2lnID09PSBfbGFzdEFuc0ZpbGVLZXkpIHJldHVybjsKICAgICAgY29uc3Qga2V5ID0gQ1VSUkVOVF9LRVkgfHwgX3NMUy5nZXQoTFNfS0VZKTsKICAgICAgaWYgKCFrZXkpIHsKICAgICAgICBfcGVuZGluZ0Fuc0ZpbGUgPSB7IHVybDogdXJsLCByYXc6IHJhdywgdHM6IERhdGUubm93KCkgfTsKICAgICAgICBhZGRMb2coJ+KPsyDEkMOjIGLhuq90IGZpbGUgxJHDoXAgw6FuIGdldC1jcnQtYW5zLWZpbGUgKGNoxrBhIGPDsyBrZXkpIOKAlCBz4bq9IGdp4bqjaSBtw6MgbmdheSBzYXUga2hpIGvDrWNoIGhv4bqhdC4nLCAnd2FybicpOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBhd2FpdCBfc3VibWl0QW5zRmlsZSh1cmwsIHJhdywga2V5U2lnKTsKICAgIH0gY2F0Y2ggKGUpIHsKICAgICAgYWRkTG9nKCfimqDvuI8gWOG7rSBsw70gZmlsZSDEkcOhcCDDoW4gbOG7l2k6ICcgKyAoZSAmJiBlLm1lc3NhZ2UgfHwgZSksICd3YXJuJyk7CiAgICB9CiAgfQogIGFzeW5jIGZ1bmN0aW9uIGZsdXNoUGVuZGluZ0Fuc0ZpbGUoKSB7CiAgICBpZiAoIV9wZW5kaW5nQW5zRmlsZSkgcmV0dXJuOwogICAgY29uc3QgcCA9IF9wZW5kaW5nQW5zRmlsZTsKICAgIGNvbnN0IHNpZyA9IF9hbnNTaWcocC5yYXcpOwogICAgaWYgKHNpZyA9PT0gX2xhc3RBbnNGaWxlS2V5KSB7IF9wZW5kaW5nQW5zRmlsZSA9IG51bGw7IHJldHVybjsgfQogICAgdHJ5IHsKICAgICAgaWYgKGF3YWl0IF9zdWJtaXRBbnNGaWxlKHAudXJsLCBwLnJhdywgc2lnKSkgX3BlbmRpbmdBbnNGaWxlID0gbnVsbDsKICAgIH0gY2F0Y2ggKF8pIHt9CiAgfQogIGFzeW5jIGZ1bmN0aW9uIHJlc2N1ZUFuc0ZpbGVSZXF1ZXN0KCkgewogICAgaWYgKF9hbnNGaWxlUmVzY3VlZCkgcmV0dXJuIHRydWU7CiAgICBjb25zdCBrZXkgPSBDVVJSRU5UX0tFWSB8fCBfc0xTLmdldChMU19LRVkpOwogICAgaWYgKCFrZXkpIHJldHVybiBmYWxzZTsKICAgIHRyeSB7CiAgICAgIGNvbnN0IHJlc0xpc3QgPSAodHlwZW9mIHBlcmZvcm1hbmNlICE9PSAndW5kZWZpbmVkJyAmJiBwZXJmb3JtYW5jZS5nZXRFbnRyaWVzQnlUeXBlKSA/IHBlcmZvcm1hbmNlLmdldEVudHJpZXNCeVR5cGUoJ3Jlc291cmNlJykgOiBbXTsKICAgICAgZm9yIChsZXQgcmkgPSAwOyByaSA8IHJlc0xpc3QubGVuZ3RoOyByaSsrKSB7CiAgICAgICAgY29uc3QgdSA9IHJlc0xpc3RbcmldLm5hbWUgfHwgJyc7CiAgICAgICAgaWYgKHUuaW5kZXhPZignZ2V0LWNydC1hbnMtZmlsZScpID09PSAtMSkgY29udGludWU7CiAgICAgICAgdHJ5IHsKICAgICAgICAgIGNvbnN0IHIyID0gYXdhaXQgZmV0Y2godSwgeyBjcmVkZW50aWFsczogJ2luY2x1ZGUnLCBjYWNoZTogJ25vLWNhY2hlJyB9KTsKICAgICAgICAgIGlmIChyMiAmJiByMi5vaykgewogICAgICAgICAgICBjb25zdCB0MiA9IGF3YWl0IHIyLnRleHQoKTsKICAgICAgICAgICAgY29uc3QgcmF3ID0gX2V4dHJhY3RBbnNGaWxlUmF3KHQyKTsKICAgICAgICAgICAgaWYgKHJhdyAmJiByYXcubGVuZ3RoID49IDE2KSB7CiAgICAgICAgICAgICAgaWYgKGF3YWl0IF9zdWJtaXRBbnNGaWxlKHUsIHJhdywgX2Fuc1NpZyhyYXcpKSkgeyBfYW5zRmlsZVJlc2N1ZWQgPSB0cnVlOyByZXR1cm4gdHJ1ZTsgfQogICAgICAgICAgICB9CiAgICAgICAgICB9CiAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgfQogICAgICBjb25zdCBVVyA9IHR5cGVvZiB1bnNhZmVXaW5kb3cgIT09ICd1bmRlZmluZWQnID8gdW5zYWZlV2luZG93IDogd2luZG93OwogICAgICBjb25zdCBsYXN0ID0gVVcuX190bF9sYXN0X2Fuc3JlcTsKICAgICAgaWYgKGxhc3QgJiYgbGFzdC51cmwpIHsKICAgICAgICB0cnkgewogICAgICAgICAgY29uc3QgZm9wdHMgPSB7IG1ldGhvZDogbGFzdC5tZXRob2QgfHwgJ0dFVCcsIGNyZWRlbnRpYWxzOiAnaW5jbHVkZScsIGNhY2hlOiAnbm8tY2FjaGUnIH07CiAgICAgICAgICBpZiAobGFzdC5ib2R5ICYmIChsYXN0Lm1ldGhvZCB8fCAnR0VUJykudG9VcHBlckNhc2UoKSAhPT0gJ0dFVCcpIHsKICAgICAgICAgICAgZm9wdHMuaGVhZGVycyA9IHsgJ0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQ7IGNoYXJzZXQ9VVRGLTgnLCAnWC1SZXF1ZXN0ZWQtV2l0aCc6ICdYTUxIdHRwUmVxdWVzdCcgfTsKICAgICAgICAgICAgZm9wdHMuYm9keSA9IGxhc3QuYm9keTsKICAgICAgICAgIH0KICAgICAgICAgIGNvbnN0IHIzID0gYXdhaXQgZmV0Y2gobGFzdC51cmwsIGZvcHRzKTsKICAgICAgICAgIGlmIChyMyAmJiByMy5vaykgewogICAgICAgICAgICBjb25zdCB0MyA9IGF3YWl0IHIzLnRleHQoKTsKICAgICAgICAgICAgY29uc3QgcmF3ID0gX2V4dHJhY3RBbnNGaWxlUmF3KHQzKTsKICAgICAgICAgICAgaWYgKHJhdyAmJiByYXcubGVuZ3RoID49IDE2KSB7CiAgICAgICAgICAgICAgaWYgKGF3YWl0IF9zdWJtaXRBbnNGaWxlKGxhc3QudXJsLCByYXcsIF9hbnNTaWcocmF3KSkpIHsgX2Fuc0ZpbGVSZXNjdWVkID0gdHJ1ZTsgcmV0dXJuIHRydWU7IH0KICAgICAgICAgICAgfQogICAgICAgICAgfQogICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgIH0KICAgIH0gY2F0Y2ggKF8pIHt9CiAgICByZXR1cm4gZmFsc2U7CiAgfQogIGZ1bmN0aW9uIF9zY2hlZHVsZUFuc0ZpbGVSZXNjdWUoKSB7CiAgICBpZiAoX3Jlc2N1ZVNjaGVkdWxlZCkgcmV0dXJuOwogICAgX3Jlc2N1ZVNjaGVkdWxlZCA9IHRydWU7CiAgICBjb25zdCB0aWNrID0gYXN5bmMgKCkgPT4gewogICAgICBhd2FpdCBmbHVzaFBlbmRpbmdBbnNGaWxlKCk7CiAgICAgIGF3YWl0IHJlc2N1ZUFuc0ZpbGVSZXF1ZXN0KCk7CiAgICB9OwogICAgdGljaygpOwogICAgbGV0IGxvb3BzID0gMDsKICAgIGNvbnN0IGl2ID0gc2V0SW50ZXJ2YWwoYXN5bmMgKCkgPT4gewogICAgICBpZiAoX2Fuc0ZpbGVSZXNjdWVkIHx8ICsrbG9vcHMgPiA5KSB7IGNsZWFySW50ZXJ2YWwoaXYpOyByZXR1cm47IH0KICAgICAgYXdhaXQgdGljaygpOwogICAgfSwgMjAwMDApOwogICAgY29uc3Qgb25Sb3V0ZSA9ICgpID0+IHsgX2Fuc0ZpbGVSZXNjdWVkID0gZmFsc2U7IHRpY2soKTsgfTsKICAgIHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKCdwb3BzdGF0ZScsIG9uUm91dGUpOwogICAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoJ2hhc2hjaGFuZ2UnLCBvblJvdXRlKTsKICB9CiAgZnVuY3Rpb24gX2NvbGxlY3REb21RdWVzdGlvbklkcygpIHsKICAgIGNvbnN0IGlkcyA9IFtdOwogICAgdHJ5IHsKICAgICAgZG9jdW1lbnQucXVlcnlTZWxlY3RvckFsbCgnW2RhdGEtcXVlc3Rpb24taWRdLFtkYXRhLXFpZF0sW2RhdGEtcXVlc3Rpb25dLFtkYXRhLWlkLXFdLFtpZF49InF1ZXN0aW9uLSJdLFtpZF49InFpZC0iXSwucXVlc3Rpb24taXRlbSxbY2xhc3MqPSJxdWVzdGlvbi1pdGVtIl0sW2NsYXNzKj0icS1pdGVtIl0nKS5mb3JFYWNoKGZ1bmN0aW9uIChlbCkgewogICAgICAgIGZvciAoY29uc3QgYSBvZiBbICdkYXRhLXF1ZXN0aW9uLWlkJywgJ2RhdGEtcWlkJywgJ2RhdGEtcXVlc3Rpb24nLCAnZGF0YS1pZC1xJyBdKSB7CiAgICAgICAgICBjb25zdCB2ID0gZWwuZ2V0QXR0cmlidXRlICYmIGVsLmdldEF0dHJpYnV0ZShhKTsKICAgICAgICAgIGlmICh2ICYmIC9eXGR7Myx9JC8udGVzdCh2KSkgeyBpZHMucHVzaCh2KTsgcmV0dXJuOyB9CiAgICAgICAgfQogICAgICAgIGNvbnN0IG0gPSAoZWwuaWQgfHwgJycpLm1hdGNoKC8oXGR7Myx9KS8pOwogICAgICAgIGlmIChtICYmIGlkcy5pbmRleE9mKG1bMV0pID09PSAtMSkgaWRzLnB1c2gobVsxXSk7CiAgICAgIH0pOwogICAgfSBjYXRjaCAoXykge30KICAgIHJldHVybiBpZHM7CiAgfQogIGZ1bmN0aW9uIF9iYW5rSXRlbVRvUmF3KGl0KSB7CiAgICBjb25zdCBhbnMgPSBBcnJheS5pc0FycmF5KGl0ICYmIGl0LmFuc3dlcnMpID8gaXQuYW5zd2Vycy5tYXAoU3RyaW5nKSA6IFtdOwogICAgaWYgKCFhbnMubGVuZ3RoKSByZXR1cm4gbnVsbDsKICAgIGNvbnN0IGxldHRlcnMgPSBhbnMubWFwKGEgPT4gYS50cmltKCkudG9VcHBlckNhc2UoKSkuZmlsdGVyKGEgPT4gL15bQS1HXSQvLnRlc3QoYSkpOwogICAgaWYgKGxldHRlcnMubGVuZ3RoICYmIGxldHRlcnMubGVuZ3RoID09PSBhbnMubGVuZ3RoKSB7CiAgICAgIHJldHVybiB7IHR5cGU6IDEsIGFuczogbGV0dGVycy5tYXAobCA9PiBTdHJpbmcoJ0FCQ0RFRkcnLmluZGV4T2YobCkpKSwgY291bnQ6IDQsIHNjb3JlOiAxIH07CiAgICB9CiAgICBjb25zdCB0ZiA9IGFucy5tYXAoYSA9PiAoL8SRw7puZy9pLnRlc3QoYSkgPyAnMScgOiAoL3NhaS9pLnRlc3QoYSkgPyAnMCcgOiBudWxsKSkpLmZpbHRlcih2ID0+IHYgIT09IG51bGwpOwogICAgaWYgKHRmLmxlbmd0aCAmJiB0Zi5sZW5ndGggPT09IGFucy5sZW5ndGgpIHJldHVybiB7IHR5cGU6IDEzLCBhbnM6IHRmLCBjb3VudDogdGYubGVuZ3RoLCBzY29yZTogMSB9OwogICAgcmV0dXJuIHsgdHlwZTogNCwgYW5zOiBhbnMsIGNvdW50OiBhbnMubGVuZ3RoLCBzY29yZTogMSwgaXNUZXh0OiB0cnVlIH07CiAgfQogIGZ1bmN0aW9uIF9zeW50aGVzaXplUXVlc3Rpb25zRnJvbUFuc3dlcnMoYXV0bykgewogICAgdHJ5IHsKICAgICAgaWYgKFNFU1NJT04ucmF3X3F1ZXN0aW9ucyAmJiBTRVNTSU9OLnJhd19xdWVzdGlvbnMubGVuZ3RoID4gMCkgcmV0dXJuIHRydWU7CiAgICAgIGNvbnN0IHNvdXJjZXMgPSBbXS5jb25jYXQoU0VTU0lPTi5hbnNGaWxlQW5zd2VycyB8fCBbXSwgU0VTU0lPTi5iYW5rQW5zd2VycyB8fCBbXSk7CiAgICAgIGlmICghc291cmNlcy5sZW5ndGgpIHJldHVybiBmYWxzZTsKICAgICAgY29uc3QgZG9tSWRzID0gX2NvbGxlY3REb21RdWVzdGlvbklkcygpOwogICAgICBjb25zdCBzeW50aCA9IFtdOwogICAgICBzb3VyY2VzLmZvckVhY2goZnVuY3Rpb24gKGl0LCBpZHgpIHsKICAgICAgICBjb25zdCByYXcgPSBpdC5yYXcgfHwgX2JhbmtJdGVtVG9SYXcoaXQpOwogICAgICAgIGlmICghcmF3KSByZXR1cm47CiAgICAgICAgY29uc3QgaWQgPSBkb21JZHNbaWR4XSB8fCBpdC5xaWQgfHwgaXQuaWQgfHwgKCdzeW5fJyArIChpZHggKyAxKSk7CiAgICAgICAgY29uc3Qgc2NvcmUgPSAodHlwZW9mIHJhdy5zY29yZSA9PT0gJ251bWJlcicpID8gcmF3LnNjb3JlIDogMTsKICAgICAgICBjb25zdCBxID0geyBpZDogU3RyaW5nKGlkKSwgc2NvcmU6IHNjb3JlIH07CiAgICAgICAgaWYgKHJhdy50eXBlID09PSAxMykgewogICAgICAgICAgcS5xX3R5cGUgPSAxMzsKICAgICAgICAgIHEuanNvbl9jb250ZW50ID0gSlNPTi5zdHJpbmdpZnkoeyB0eXBlOiAnb2xtLWxpc3QnLCBuYW1lOiAndHJ1ZS1mYWxzZScsIGNoaWxkcmVuOiAocmF3LmFucyB8fCBbXSkubWFwKHYgPT4gKHsgY29ycmVjdDogdiA9PT0gJzEnIHx8IHYgPT09IDEgfHwgdiA9PT0gdHJ1ZSB9KSkgfSk7CiAgICAgICAgfSBlbHNlIGlmIChyYXcudHlwZSA9PT0gNikgewogICAgICAgICAgY29uc3QgbiA9IE1hdGgubWF4KDIsIHJhdy5jb3VudCB8fCAocmF3LmFucyB8fCBbXSkubGVuZ3RoIHx8IDIpOwogICAgICAgICAgcS5xX3R5cGUgPSA2OwogICAgICAgICAgcS5qc29uX2NvbnRlbnQgPSBKU09OLnN0cmluZ2lmeSh7IHR5cGU6ICdvbG0tbGlzdCcsIG5hbWU6ICdsaW5rLWxpc3QnLCBsaXN0VHlwZTogJ21hdGNoaW5nJywgY2hpbGRyZW46IEFycmF5LmZyb20oeyBsZW5ndGg6IG4gfSwgZnVuY3Rpb24gKF8sIG9pKSB7IHJldHVybiB7IGlkeDogb2kgfTsgfSkgfSk7CiAgICAgICAgfSBlbHNlIGlmIChyYXcudHlwZSA9PT0gNCkgewogICAgICAgICAgcS5xX3R5cGUgPSAxMTsKICAgICAgICAgIHEudHlwZSA9ICdmaWxsbWUtaW5wdXQnOwogICAgICAgICAgcS5jb250ZW50ID0gU3RyaW5nKChyYXcuYW5zICYmIHJhdy5hbnNbMF0pIHx8ICcnKTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgY29uc3QgY291bnQgPSBNYXRoLm1heCg0LCByYXcuY291bnQgfHwgNCk7CiAgICAgICAgICBjb25zdCBjaG9zZW4gPSBuZXcgU2V0KChyYXcuYW5zIHx8IFtdKS5tYXAoYSA9PiBwYXJzZUludChhLCAxMCkpLmZpbHRlcihuID0+IE51bWJlci5pc0Zpbml0ZShuKSkpOwogICAgICAgICAgcS5xX3R5cGUgPSAxOwogICAgICAgICAgcS5qc29uX2NvbnRlbnQgPSBKU09OLnN0cmluZ2lmeSh7IHR5cGU6ICdvbG0tbGlzdCcsIG5hbWU6ICdjaG9pY2UnLCBjaGlsZHJlbjogQXJyYXkuZnJvbSh7IGxlbmd0aDogY291bnQgfSwgZnVuY3Rpb24gKF8sIG9pKSB7IHJldHVybiB7IGNvcnJlY3Q6IGNob3Nlbi5oYXMob2kpIH07IH0pIH0pOwogICAgICAgIH0KICAgICAgICBzeW50aC5wdXNoKHEpOwogICAgICB9KTsKICAgICAgaWYgKCFzeW50aC5sZW5ndGgpIHJldHVybiBmYWxzZTsKICAgICAgU0VTU0lPTi5yYXdfcXVlc3Rpb25zID0gc3ludGg7CiAgICAgIGlmICghYXV0bykgYWRkTG9nKCfwn6esIEThu7FuZyAnICsgc3ludGgubGVuZ3RoICsgJyBjw6J1IHThu6sgxJHDoXAgw6FuIGtoby9zZXJ2ZXIgxJHhu4Mgc+G6tW4gc8OgbmcgbuG7mXAuJywgJ29rJyk7CiAgICAgIF9yZWZyZXNoUUNvdW50KCk7CiAgICAgIHJldHVybiB0cnVlOwogICAgfSBjYXRjaCAoXykgeyByZXR1cm4gZmFsc2U7IH0KICB9CiAgY29uc3QgQVBJX0tFWVdPUkRTID0gWyAnZ2V0LXF1ZXN0aW9uLW9mLWlkcycsICdnZXQtcXVlc3Rpb24/YmVsb25ncz0xJywgJ2dldC1xdWVzdGlvbicsICdnZXQtdGVzdCcsICdnZXQtY3J0LWFucy1maWxlJyBdOwogIGZ1bmN0aW9uIHJlbmRlckFuc3dlcnNCbG9jayhsaXN0LCBoZWFkZXJNc2cpIHsKICAgIGNvbnN0IGJveCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0bC1sb2dib3giKTsKICAgIGlmICghYm94KSByZXR1cm47CiAgICBsZXQgYmxvY2sgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGwtYW5zLWJsb2NrIik7CiAgICBpZiAoIWJsb2NrKSB7CiAgICAgIGJsb2NrID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgIGJsb2NrLmlkID0gInRsLWFucy1ibG9jayI7CiAgICAgIGJsb2NrLnN0eWxlLmNzc1RleHQgPSAiYm9yZGVyLXRvcDoxcHggZGFzaGVkIHJnYmEoMjU1LDE5Myw3LC4zNSk7bWFyZ2luLXRvcDo0cHg7cGFkZGluZy10b3A6NHB4IjsKICAgICAgYm94LmFwcGVuZENoaWxkKGJsb2NrKTsKICAgIH0KICAgIGJsb2NrLmlubmVySFRNTCA9ICIiOwogICAgaWYgKGhlYWRlck1zZykgYWRkTG9nKGhlYWRlck1zZywgIm9rIik7CiAgICBjb25zdCBpdGVtcyA9IEFycmF5LmlzQXJyYXkobGlzdCkgPyBsaXN0IDogW107CiAgICBsZXQgaSA9IDA7CiAgICBmdW5jdGlvbiBjaHVuaygpIHsKICAgICAgY29uc3QgZnJhZyA9IGRvY3VtZW50LmNyZWF0ZURvY3VtZW50RnJhZ21lbnQoKTsKICAgICAgZm9yIChsZXQgbiA9IDA7IG4gPCAxMCAmJiBpIDwgaXRlbXMubGVuZ3RoOyBuKyssIGkrKykgewogICAgICAgIGNvbnN0IHEgPSBpdGVtc1tpXTsKICAgICAgICBjb25zdCBkID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgZC5jbGFzc05hbWUgPSAidGwtbG9nIG9rIjsKICAgICAgICBjb25zdCBhbnMgPSAocS5hbnN3ZXJzIHx8IFtdKS5qb2luKCIgfCAiKTsKICAgICAgICBkLmlubmVySFRNTCA9ICI8Yj5RIiArIChxLmluZGV4IHx8IChpICsgMSkpICsgIjo8L2I+ICIgKyBfZXNjQmFuayhTdHJpbmcocS50aXRsZSB8fCAiIikuc3Vic3RyaW5nKDAsIDYwKSkgKyAnIOKGkiA8c3BhbiBzdHlsZT0iY29sb3I6I2ZmYzEwNztmb250LXdlaWdodDo3MDA7Ij4nICsgX2VzY0JhbmsoYW5zKSArICI8L3NwYW4+IjsKICAgICAgICBmcmFnLmFwcGVuZENoaWxkKGQpOwogICAgICB9CiAgICAgIGJsb2NrLmFwcGVuZENoaWxkKGZyYWcpOwogICAgICBib3guc2Nyb2xsVG9wID0gYm94LnNjcm9sbEhlaWdodDsKICAgICAgaWYgKGkgPCBpdGVtcy5sZW5ndGgpIHNldFRpbWVvdXQoY2h1bmssIDI1KTsKICAgICAgZWxzZSBhZGRMb2coIuKchSDEkMOjIGhp4buDbiB0aOG7iyAiICsgaXRlbXMubGVuZ3RoICsgIiDEkcOhcCDDoW4iLCAib2siKTsKICAgIH0KICAgIGNodW5rKCk7CiAgfQogIGZ1bmN0aW9uIGhhbmRsZVJhd1Jlc3BvbnNlKHVybCwgdGV4dCkgewogICAgaWYgKCF1cmwgfHwgIXRleHQpIHJldHVybjsKICAgIGlmICh1cmwuaW5kZXhPZignZ2V0LWNydC1hbnMtZmlsZScpICE9PSAtMSkgeyB0cnkgeyBoYW5kbGVBbnNGaWxlUmVzcG9uc2UodXJsLCB0ZXh0KTsgfSBjYXRjaCAoXykge30gcmV0dXJuOyB9CiAgICBjb25zdCBpc1FBcGkgPSBBUElfS0VZV09SRFMuc29tZShrID0+IHVybC5pbmNsdWRlcyhrKSk7CiAgICBjb25zdCBpc0xlZyA9IHVybC5pbmNsdWRlcygnZ2V0LXF1ZXN0aW9uJykgfHwgdXJsLmluY2x1ZGVzKCdnZXQtdGVzdCcpIHx8IHRleHQuaW5jbHVkZXMoJ2pzb25fY29udGVudCcpIHx8IHRleHQuaW5jbHVkZXMoJyJxdWVzdGlvbnMiJyk7CiAgICBpZiAoIWlzUUFwaSAmJiAhaXNMZWcpIHJldHVybjsKICAgIGxldCBkYXRhOwogICAgdHJ5IHsKICAgICAgZGF0YSA9IEpTT04ucGFyc2UodGV4dCk7CiAgICB9IGNhdGNoIChfKSB7CiAgICAgIHJldHVybjsKICAgIH0KICAgIGNvbnN0IHFMaXN0ID0gZGF0YS5xdWVzdGlvbnMgfHwgZGF0YS5kYXRhIHx8IChBcnJheS5pc0FycmF5KGRhdGEpID8gZGF0YSA6IG51bGwpOwogICAgaWYgKCFBcnJheS5pc0FycmF5KHFMaXN0KSB8fCBxTGlzdC5sZW5ndGggPT09IDApIHJldHVybjsKICAgIFNFU1NJT04ucmF3X3F1ZXN0aW9ucyA9IHFMaXN0OwogICAgaWYgKF9iYW5rRmFsbGJhY2tUaW1lcikgeyBjbGVhclRpbWVvdXQoX2JhbmtGYWxsYmFja1RpbWVyKTsgX2JhbmtGYWxsYmFja1RpbWVyID0gbnVsbDsgfQogICAgX2JhbmtSZXRyeSA9IDA7CiAgICBTRVNTSU9OLm1ldGEuaWRfdXNlciA9IHFMaXN0WzBdPy5pZF91c2VyIHx8IGRldGVjdFVzZXJJRCgpOwogICAgU0VTU0lPTi5tZXRhLmlkX2NvdXJzZXdhcmUgPSBkYXRhLmlkX2NvdXJzZXdhcmUgfHwgbmV3IFVSTFNlYXJjaFBhcmFtcyh3aW5kb3cubG9jYXRpb24uc2VhcmNoKS5nZXQoJ2lfYycpOwogICAgU0VTU0lPTi5tZXRhLmlkX2NhdGUgPSBkYXRhLmlkX2NhdGUgfHwgZGF0YS5pZF9leGFtIHx8IHJpcElkRnJvbVVybCgpOwogICAgU0VTU0lPTi5tZXRhLnN1YmplY3RfbmFtZSA9IGRhdGEuc3ViamVjdF9uYW1lIHx8IGRhdGEuc3ViamVjdCB8fCBkYXRhLmNhdGVfbmFtZSB8fCBkZXRlY3RTdWJqZWN0TmFtZSgpIHx8IFNFU1NJT04ubWV0YS5zdWJqZWN0X25hbWUgfHwgJyc7CiAgICBTRVNTSU9OLm1ldGEuZXhlcmNpc2VfdGl0bGUgPSBkYXRhLnRpdGxlIHx8IGRhdGEubmFtZSB8fCBkYXRhLmV4ZXJjaXNlX3RpdGxlIHx8IGRldGVjdEV4ZXJjaXNlVGl0bGUoKSB8fCBTRVNTSU9OLm1ldGEuZXhlcmNpc2VfdGl0bGUgfHwgJyc7CiAgICBTRVNTSU9OLm1ldGEuc3ViamVjdF9pZCA9IGRhdGEuc3ViamVjdF9pZCB8fCBkYXRhLmNhdGVfaWQgfHwgU0VTU0lPTi5tZXRhLnN1YmplY3RfaWQgfHwgbnVsbDsKICAgIHJlZnJlc2hTdWJqZWN0VGl0bGVVSSgpOwogICAgU0VTU0lPTi5tZXRhLmlkX3NjaG9vbCA9IGRldGVjdFNjaG9vbElEKGRhdGEpOwogICAgU0VTU0lPTi5tZXRhLmlkX2dyb3VwID0gZGV0ZWN0R3JvdXBJRCgpOwogICAgY29uc3QgbXQgPSBkb2N1bWVudC5xdWVyeVNlbGVjdG9yKCdtZXRhW25hbWU9ImNzcmYtdG9rZW4iXScpOwogICAgU0VTU0lPTi5tZXRhLmNzcmZfdG9rZW4gPSBtdCA/IG10LmdldEF0dHJpYnV0ZSgnY29udGVudCcpIDogd2luZG93LmNzcmZfdG9rZW4gfHwgJyc7CiAgICBpZiAod2luZG93LnRvdGFsX3RpbWUpIFNFU1NJT04udmlkZW9fbGVuZ3RoID0gTWF0aC5jZWlsKHdpbmRvdy50b3RhbF90aW1lKTsgZWxzZSBpZiAoZGF0YS50b3RhbF90aW1lKSBTRVNTSU9OLnZpZGVvX2xlbmd0aCA9IE1hdGguY2VpbChkYXRhLnRvdGFsX3RpbWUpOwogICAgaWYgKGRhdGEudHlwZSA9PSA1IHx8IHdpbmRvdy5sb2NhdGlvbi5ocmVmLmluY2x1ZGVzKCd2aWRlbycpIHx8IGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoJ3ZpZGVvLGlmcmFtZVtzcmMqPSJ5b3V0dWJlIl0nKSkgU0VTU0lPTi5hdXRvX21vZGUgPSAndmlkZW8nOyBlbHNlIGlmIChkYXRhLnR5cGVfZXhhbSA9PSAxIHx8IGRhdGEuaXNfZXhhbSA9PSAxIHx8IHdpbmRvdy5pc19leGFtID09IDEgfHwgZG9jdW1lbnQucXVlcnlTZWxlY3RvcignLnRpbWUtY291bnRkb3duLCNzdWJtaXQtdGVzdCcpKSBTRVNTSU9OLmF1dG9fbW9kZSA9ICdleGFtJzsgZWxzZSBTRVNTSU9OLmF1dG9fbW9kZSA9ICdwcmFjdGljZSc7CiAgICBjb25zdCBxY0VsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLXFjb3VudCcpOwogICAgY29uc3QgbWRFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1tb2RlLWRldGVjdGVkJyk7CiAgICBpZiAocWNFbCkgcWNFbC50ZXh0Q29udGVudCA9IHFMaXN0Lmxlbmd0aDsKICAgIF9yZWZyZXNoUUNvdW50KCk7CiAgICBpZiAobWRFbCkgewogICAgICBtZEVsLnRleHRDb250ZW50ID0gU0VTU0lPTi5hdXRvX21vZGUudG9VcHBlckNhc2UoKTsKICAgICAgY29uc3QgbXMgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtbW9kZVNlbGVjdCcpOwogICAgICBpZiAobXMpIG1zLnZhbHVlID0gU0VTU0lPTi5hdXRvX21vZGU7CiAgICB9CiAgICBhZGRMb2coYPCfk6UgWyR7U0VTU0lPTi5tZXRhLnN1YmplY3RfbmFtZSB8fCAnbcO0biA/J31dJHtTRVNTSU9OLm1ldGEuZXhlcmNpc2VfdGl0bGUgPyAnIMK3ICcgKyBTRVNTSU9OLm1ldGEuZXhlcmNpc2VfdGl0bGUgOiAnJ30g4oCUIG7huqFwICR7cUxpc3QubGVuZ3RofSBjw6J1IGjhu49pICgke1NFU1NJT04uYXV0b19tb2RlfSkuLi5gLCAnaW5mbycpOwogICAgY29uc3Qga2V5ID0gQ1VSUkVOVF9LRVkgfHwgX3NMUy5nZXQoTFNfS0VZKTsKICAgIGlmICgha2V5KSB7CiAgICAgIGFkZExvZygn4pqg77iPIENoxrBhIGPDsyBrZXkg4oCUIGtow7RuZyB0aOG7gyBnaeG6o2kgbcOjLicsICd3YXJuJyk7CiAgICAgIHJldHVybjsKICAgIH0KICAgIGFkZExvZygn8J+UhCBTZXJ2ZXIgxJFhbmcgZ2nhuqNpICcgKyBxTGlzdC5sZW5ndGggKyAnIGPDonUuLi4nLCAnaW5mbycpOwogICAgZ21Qb3N0KCcvcHJvY2VzcycsIHsKICAgICAga2V5OiBrZXksCiAgICAgIGh3aWQ6IGdldEhXSUQoKSwKICAgICAgcXVlc3Rpb25zOiBxTGlzdCwKICAgICAgbWV0YTogewogICAgICAgIGlkX3VzZXI6IFNFU1NJT04ubWV0YS5pZF91c2VyIHx8IGRldGVjdFVzZXJJRCgpLAogICAgICAgIGlkX2NhdGU6IFNFU1NJT04ubWV0YS5pZF9jYXRlLAogICAgICAgIGlkX2NvdXJzZXdhcmU6IFNFU1NJT04ubWV0YS5pZF9jb3Vyc2V3YXJlLAogICAgICAgIHN1YmplY3RfbmFtZTogU0VTU0lPTi5tZXRhLnN1YmplY3RfbmFtZSB8fCAnJywKICAgICAgICBleGVyY2lzZV90aXRsZTogU0VTU0lPTi5tZXRhLmV4ZXJjaXNlX3RpdGxlIHx8ICcnLAogICAgICAgIHN1YmplY3RfaWQ6IFNFU1NJT04ubWV0YS5zdWJqZWN0X2lkIHx8IG51bGwsCiAgICAgICAgb2xtX3VzZXI6IGdldE9sbVVzZXJuYW1lKCkKICAgICAgfQogICAgfSkudGhlbihyZXN1bHQgPT4gewogICAgICBpZiAoIShyZXN1bHQuc3VjY2VzcyB8fCByZXN1bHQudmFsaWQpKSB7CiAgICAgICAgYWRkTG9nKCfinYwgU2VydmVyOiAnICsgKHJlc3VsdC5tZXNzYWdlIHx8ICdM4buXaSBnaeG6o2kgbcOjJyksICdlcnInKTsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgcmVuZGVyQW5zd2Vyc0Jsb2NrKHJlc3VsdC5xdWVzdGlvbnMsICIiKTsKICAgIH0pLmNhdGNoKGUgPT4gYWRkTG9nKCfinYwgTOG7l2kga+G6v3QgbuG7kWkgc2VydmVyOiAnICsgZS5tZXNzYWdlLCAnZXJyJykpOwogIH0KICAoZnVuY3Rpb24gaW5qZWN0UGFnZUhvb2soKSB7CiAgICB0cnkgewogICAgICBjb25zdCBjb2RlID0gJygnICsgZnVuY3Rpb24oKSB7CiAgICAgICAgaWYgKHdpbmRvdy5fX3RsX2hvb2tlZCkgcmV0dXJuOwogICAgICAgIHdpbmRvdy5fX3RsX2hvb2tlZCA9IHRydWU7CiAgICAgICAgd2luZG93Ll9fa3ZfcV9idWYgPSB3aW5kb3cuX19rdl9xX2J1ZiB8fCBbXTsKICAgICAgICBmdW5jdGlvbiBfX3RsX2JyaWRnZUVsKCkgewogICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgdmFyIGIgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnX190bF9xYnJpZGdlJyk7CiAgICAgICAgICAgIGlmICghYikgewogICAgICAgICAgICAgIGIgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgICAgICAgICAgICBiLmlkID0gJ19fdGxfcWJyaWRnZSc7CiAgICAgICAgICAgICAgYi5zdHlsZS5kaXNwbGF5ID0gJ25vbmUnOwogICAgICAgICAgICAgIChkb2N1bWVudC5ib2R5IHx8IGRvY3VtZW50LmRvY3VtZW50RWxlbWVudCkuYXBwZW5kQ2hpbGQoYik7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgcmV0dXJuIGI7CiAgICAgICAgICB9IGNhdGNoIChlKSB7IHJldHVybiBudWxsOyB9CiAgICAgICAgfQogICAgICAgIGZ1bmN0aW9uIF9fdGxfcHVzaCh1cmwsIHRleHQpIHsKICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgIHdpbmRvdy5fX2t2X3FfYnVmLnB1c2goewogICAgICAgICAgICAgIHVybDogdXJsLAogICAgICAgICAgICAgIHRleHQ6IHRleHQsCiAgICAgICAgICAgICAgdHM6IERhdGUubm93KCkKICAgICAgICAgICAgfSk7CiAgICAgICAgICAgIHRyeSB7IGlmICh3aW5kb3cucGFyZW50ICYmIHdpbmRvdy5wYXJlbnQgIT09IHdpbmRvdyAmJiBBcnJheS5pc0FycmF5KHdpbmRvdy5wYXJlbnQuX19rdl9xX2J1ZikpIHdpbmRvdy5wYXJlbnQuX19rdl9xX2J1Zi5wdXNoKHsgdXJsOiB1cmwsIHRleHQ6IHRleHQsIHRzOiBEYXRlLm5vdygpIH0pOyB9IGNhdGNoIChlKSB7fQogICAgICAgICAgICB2YXIgYiA9IF9fdGxfYnJpZGdlRWwoKTsKICAgICAgICAgICAgaWYgKGIpIHsKICAgICAgICAgICAgICB0cnkgeyBiLnNldEF0dHJpYnV0ZSgnZGF0YS1sYXRlc3QnLCBKU09OLnN0cmluZ2lmeSh7IHVybDogdXJsLCB0ZXh0OiB0ZXh0IH0pKTsgfSBjYXRjaCAoZSkge30KICAgICAgICAgICAgICB0cnkgeyBiLmRpc3BhdGNoRXZlbnQobmV3IEN1c3RvbUV2ZW50KCdfX3RsX3FicmlkZ2UnLCB7IGRldGFpbDogeyB1cmw6IHVybCwgdGV4dDogdGV4dCB9IH0pKTsgfSBjYXRjaCAoZSkge30KICAgICAgICAgICAgfQogICAgICAgICAgICB0cnkgeyBkb2N1bWVudC5kaXNwYXRjaEV2ZW50KG5ldyBDdXN0b21FdmVudCgnX19rdl9xZGF0YScsIHsgZGV0YWlsOiB7IHVybDogdXJsLCB0ZXh0OiB0ZXh0IH0gfSkpOyB9IGNhdGNoIChlKSB7fQogICAgICAgICAgICB3aW5kb3cuZGlzcGF0Y2hFdmVudChuZXcgQ3VzdG9tRXZlbnQoJ19fa3ZfcWRhdGEnLCB7CiAgICAgICAgICAgICAgZGV0YWlsOiB7CiAgICAgICAgICAgICAgICB1cmw6IHVybCwKICAgICAgICAgICAgICAgIHRleHQ6IHRleHQKICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0pKTsKICAgICAgICAgIH0gY2F0Y2ggKGUpIHt9CiAgICAgICAgfQogICAgICAgIGZ1bmN0aW9uIF9fdGxfcmVtZW1iZXJfcmVxKHVybCwgbWV0aG9kLCBib2R5KSB7CiAgICAgICAgICB0cnkgewogICAgICAgICAgICB2YXIgdSA9ICh1cmwgfHwgJycpLnRvTG93ZXJDYXNlKCk7CiAgICAgICAgICAgIGlmICh1LmluZGV4T2YoJ2dldC1jcnQtYW5zLWZpbGUnKSAhPT0gLTEpIHsKICAgICAgICAgICAgICB3aW5kb3cuX190bF9sYXN0X2Fuc3JlcSA9IHsgdXJsOiB1cmwsIG1ldGhvZDogbWV0aG9kIHx8ICdHRVQnLCBib2R5OiBib2R5IHx8IG51bGwsIHRzOiBEYXRlLm5vdygpIH07CiAgICAgICAgICAgIH0KICAgICAgICAgICAgaWYgKHUuaW5kZXhPZignZ2V0LXF1ZXN0aW9uJykgIT09IC0xIHx8IHUuaW5kZXhPZignZ2V0LXRlc3QnKSAhPT0gLTEpIHsKICAgICAgICAgICAgICB3aW5kb3cuX190bF9sYXN0X3FyZXEgPSB7CiAgICAgICAgICAgICAgICB1cmw6IHVybCwKICAgICAgICAgICAgICAgIG1ldGhvZDogbWV0aG9kIHx8ICdHRVQnLAogICAgICAgICAgICAgICAgYm9keTogYm9keSB8fCBudWxsLAogICAgICAgICAgICAgICAgdHM6IERhdGUubm93KCkKICAgICAgICAgICAgICB9OwogICAgICAgICAgICB9CiAgICAgICAgICB9IGNhdGNoIChlKSB7fQogICAgICAgIH0KICAgICAgICB2YXIgX19vID0gWE1MSHR0cFJlcXVlc3QucHJvdG90eXBlLm9wZW47CiAgICAgICAgdmFyIF9fcyA9IFhNTEh0dHBSZXF1ZXN0LnByb3RvdHlwZS5zZW5kOwogICAgICAgIFhNTEh0dHBSZXF1ZXN0LnByb3RvdHlwZS5vcGVuID0gZnVuY3Rpb24obSwgdSkgewogICAgICAgICAgdGhpcy5fX3RsX3VybCA9IHU7CiAgICAgICAgICByZXR1cm4gX19vLmFwcGx5KHRoaXMsIGFyZ3VtZW50cyk7CiAgICAgICAgfTsKICAgICAgICBYTUxIdHRwUmVxdWVzdC5wcm90b3R5cGUuc2VuZCA9IGZ1bmN0aW9uKGJvZHkpIHsKICAgICAgICAgIHZhciBzZWxmID0gdGhpczsKICAgICAgICAgIF9fdGxfcmVtZW1iZXJfcmVxKHNlbGYuX190bF91cmwgfHwgJycsICdQT1NUJywgYm9keSB8fCBudWxsKTsKICAgICAgICAgIHRoaXMuYWRkRXZlbnRMaXN0ZW5lcignbG9hZCcsIGZ1bmN0aW9uKCkgewogICAgICAgICAgICBpZiAoc2VsZi5zdGF0dXMgPT09IDIwMCkgewogICAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgICBfX3RsX3B1c2goc2VsZi5yZXNwb25zZVVSTCB8fCBzZWxmLl9fdGxfdXJsIHx8ICcnLCBzZWxmLnJlc3BvbnNlVGV4dCB8fCAnJyk7CiAgICAgICAgICAgICAgfSBjYXRjaCAoZSkge30KICAgICAgICAgICAgfQogICAgICAgICAgfSk7CiAgICAgICAgICByZXR1cm4gX19zLmFwcGx5KHRoaXMsIGFyZ3VtZW50cyk7CiAgICAgICAgfTsKICAgICAgICB2YXIgX19mID0gd2luZG93LmZldGNoOwogICAgICAgIHdpbmRvdy5mZXRjaCA9IGZ1bmN0aW9uKCkgewogICAgICAgICAgdmFyIGFyZ3MgPSBhcmd1bWVudHM7CiAgICAgICAgICB2YXIgdXJsID0gdHlwZW9mIGFyZ3NbMF0gPT09ICdzdHJpbmcnID8gYXJnc1swXSA6IGFyZ3NbMF0gJiYgYXJnc1swXS51cmwgPyBhcmdzWzBdLnVybCA6ICcnOwogICAgICAgICAgdmFyIG9wdHMgPSBhcmdzWzFdIHx8ICh0eXBlb2YgYXJnc1swXSA9PT0gJ29iamVjdCcgPyBhcmdzWzBdIDogbnVsbCk7CiAgICAgICAgICBfX3RsX3JlbWVtYmVyX3JlcSh1cmwsIG9wdHMgJiYgb3B0cy5tZXRob2QgfHwgJ0dFVCcsIG9wdHMgJiYgb3B0cy5ib2R5IHx8IG51bGwpOwogICAgICAgICAgcmV0dXJuIF9fZi5hcHBseSh0aGlzLCBhcmdzKS50aGVuKGZ1bmN0aW9uKHJlcykgewogICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgIHZhciBjbCA9IHJlcy5jbG9uZSgpOwogICAgICAgICAgICAgIGNsLnRleHQoKS50aGVuKGZ1bmN0aW9uKHQpIHsKICAgICAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgICAgIF9fdGxfcHVzaCh1cmwgfHwgcmVzLnVybCB8fCAnJywgdCk7CiAgICAgICAgICAgICAgICB9IGNhdGNoIChlKSB7fQogICAgICAgICAgICAgIH0pOwogICAgICAgICAgICB9IGNhdGNoIChlKSB7fQogICAgICAgICAgICByZXR1cm4gcmVzOwogICAgICAgICAgfSk7CiAgICAgICAgfTsKICAgICAgICBmdW5jdGlvbiBfX3RsX2hvb2tGcmFtZSh3KSB7CiAgICAgICAgICB0cnkgewogICAgICAgICAgICBpZiAoIXcgfHwgdy5fX3RsX2hvb2tlZF9mcmFtZSkgcmV0dXJuOwogICAgICAgICAgICB3Ll9fdGxfaG9va2VkX2ZyYW1lID0gdHJ1ZTsKICAgICAgICAgICAgdy5fX2t2X3FfYnVmID0gdy5fX2t2X3FfYnVmIHx8IFtdOwogICAgICAgICAgICB2YXIgb3ggPSB3LlhNTEh0dHBSZXF1ZXN0LnByb3RvdHlwZS5vcGVuOwogICAgICAgICAgICB2YXIgb3MgPSB3LlhNTEh0dHBSZXF1ZXN0LnByb3RvdHlwZS5zZW5kOwogICAgICAgICAgICB3LlhNTEh0dHBSZXF1ZXN0LnByb3RvdHlwZS5vcGVuID0gZnVuY3Rpb24obSwgdSkgeyB0aGlzLl9fdGxfdXJsID0gdTsgcmV0dXJuIG94LmFwcGx5KHRoaXMsIGFyZ3VtZW50cyk7IH07CiAgICAgICAgICAgIHcuWE1MSHR0cFJlcXVlc3QucHJvdG90eXBlLnNlbmQgPSBmdW5jdGlvbihib2R5KSB7CiAgICAgICAgICAgICAgdmFyIHNlbGYgPSB0aGlzOwogICAgICAgICAgICAgIF9fdGxfcmVtZW1iZXJfcmVxKHNlbGYuX190bF91cmwgfHwgJycsICdQT1NUJywgYm9keSB8fCBudWxsKTsKICAgICAgICAgICAgICBzZWxmLmFkZEV2ZW50TGlzdGVuZXIoJ2xvYWQnLCBmdW5jdGlvbigpIHsKICAgICAgICAgICAgICAgIGlmIChzZWxmLnN0YXR1cyA9PT0gMjAwKSB7IHRyeSB7IF9fdGxfcHVzaChzZWxmLnJlc3BvbnNlVVJMIHx8IHNlbGYuX190bF91cmwgfHwgJycsIHNlbGYucmVzcG9uc2VUZXh0IHx8ICcnKTsgfSBjYXRjaCAoZSkge30gfQogICAgICAgICAgICAgIH0pOwogICAgICAgICAgICAgIHJldHVybiBvcy5hcHBseSh0aGlzLCBhcmd1bWVudHMpOwogICAgICAgICAgICB9OwogICAgICAgICAgICB2YXIgb2YgPSB3LmZldGNoOwogICAgICAgICAgICB3LmZldGNoID0gZnVuY3Rpb24oKSB7CiAgICAgICAgICAgICAgdmFyIGFyZ3MgPSBhcmd1bWVudHM7CiAgICAgICAgICAgICAgdmFyIHVybCA9IHR5cGVvZiBhcmdzWzBdID09PSAnc3RyaW5nJyA/IGFyZ3NbMF0gOiAoYXJnc1swXSAmJiBhcmdzWzBdLnVybCkgfHwgJyc7CiAgICAgICAgICAgICAgdmFyIG9wdHMgPSBhcmdzWzFdIHx8ICh0eXBlb2YgYXJnc1swXSA9PT0gJ29iamVjdCcgPyBhcmdzWzBdIDogbnVsbCk7CiAgICAgICAgICAgICAgX190bF9yZW1lbWJlcl9yZXEodXJsLCAob3B0cyAmJiBvcHRzLm1ldGhvZCkgfHwgJ0dFVCcsIChvcHRzICYmIG9wdHMuYm9keSkgfHwgbnVsbCk7CiAgICAgICAgICAgICAgcmV0dXJuIG9mLmFwcGx5KHRoaXMsIGFyZ3MpLnRoZW4oZnVuY3Rpb24ocmVzKSB7CiAgICAgICAgICAgICAgICB0cnkgeyByZXMuY2xvbmUoKS50ZXh0KCkudGhlbihmdW5jdGlvbih0KSB7IF9fdGxfcHVzaCh1cmwgfHwgcmVzLnVybCB8fCAnJywgdCk7IH0pOyB9IGNhdGNoIChlKSB7fQogICAgICAgICAgICAgICAgcmV0dXJuIHJlczsKICAgICAgICAgICAgICB9KTsKICAgICAgICAgICAgfTsKICAgICAgICAgIH0gY2F0Y2ggKGUpIHt9CiAgICAgICAgfQogICAgICAgIGZ1bmN0aW9uIF9fdGxfaG9va0ZyYW1lcygpIHsKICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgIHZhciBmcmFtZXMgPSBkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCdpZnJhbWUsZnJhbWUnKTsKICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBmcmFtZXMubGVuZ3RoOyBpKyspIHsKICAgICAgICAgICAgICB0cnkgeyBfX3RsX2hvb2tGcmFtZShmcmFtZXNbaV0uY29udGVudFdpbmRvdyk7IH0gY2F0Y2ggKGUpIHt9CiAgICAgICAgICAgIH0KICAgICAgICAgIH0gY2F0Y2ggKGUpIHt9CiAgICAgICAgfQogICAgICAgIF9fdGxfaG9va0ZyYW1lcygpOwogICAgICAgIHZhciBfX2ZyYW1lSXYgPSBzZXRJbnRlcnZhbChfX3RsX2hvb2tGcmFtZXMsIDE1MDApOwogICAgICAgIHNldFRpbWVvdXQoZnVuY3Rpb24oKSB7IHRyeSB7IGNsZWFySW50ZXJ2YWwoX19mcmFtZUl2KTsgfSBjYXRjaCAoZSkge30gfSwgMTIwMDAwKTsKICAgICAgfSArICcpKCk7JzsKICAgICAgY29uc3Qgc0VsID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc2NyaXB0Jyk7CiAgICAgIHNFbC50ZXh0Q29udGVudCA9IGNvZGU7CiAgICAgIChkb2N1bWVudC5oZWFkIHx8IGRvY3VtZW50LmRvY3VtZW50RWxlbWVudCkuYXBwZW5kQ2hpbGQoc0VsKTsKICAgICAgc0VsLnJlbW92ZSgpOwogICAgfSBjYXRjaCAoZSkgewogICAgICBjb25zb2xlLndhcm4oJ1tUTF0gaW5qZWN0IGZhaWwnLCBlKTsKICAgIH0KICB9KSgpOwogIGZ1bmN0aW9uIHNldHVwS1ZCdWZSZWFkZXIoKSB7CiAgICB0cnkgewogICAgICBjb25zdCBVVyA9IHR5cGVvZiB1bnNhZmVXaW5kb3cgIT09ICd1bmRlZmluZWQnID8gdW5zYWZlV2luZG93IDogd2luZG93OwogICAgICBsZXQgcHJvY2Vzc2VkID0gMDsKICAgICAgZnVuY3Rpb24gZHJhaW4oKSB7CiAgICAgICAgdHJ5IHsKICAgICAgICAgIGNvbnN0IGJ1ZiA9IFVXLl9fa3ZfcV9idWY7CiAgICAgICAgICBpZiAoIUFycmF5LmlzQXJyYXkoYnVmKSB8fCBidWYubGVuZ3RoIDw9IHByb2Nlc3NlZCkgcmV0dXJuOwogICAgICAgICAgZm9yIChsZXQgaSA9IHByb2Nlc3NlZDsgaSA8IGJ1Zi5sZW5ndGg7IGkrKykgewogICAgICAgICAgICBjb25zdCBpdCA9IGJ1ZltpXTsKICAgICAgICAgICAgaWYgKGl0ICYmIGl0LnVybCAmJiBpdC50ZXh0KSB7CiAgICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgIGhhbmRsZVJhd1Jlc3BvbnNlKGl0LnVybCwgaXQudGV4dCk7CiAgICAgICAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgICAgICAgfQogICAgICAgICAgfQogICAgICAgICAgcHJvY2Vzc2VkID0gYnVmLmxlbmd0aDsKICAgICAgICB9IGNhdGNoIChfKSB7fQogICAgICB9CiAgICAgIHRyeSB7CiAgICAgICAgVVcuYWRkRXZlbnRMaXN0ZW5lcignX19rdl9xZGF0YScsIGZ1bmN0aW9uKGV2dCkgewogICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgY29uc3QgZCA9IGV2dCAmJiBldnQuZGV0YWlsOwogICAgICAgICAgICBpZiAoZCAmJiBkLnVybCAmJiBkLnRleHQpIHsKICAgICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgaGFuZGxlUmF3UmVzcG9uc2UoZC51cmwsIGQudGV4dCk7CiAgICAgICAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgICAgICAgfQogICAgICAgICAgICBjb25zdCBidWYgPSBVVy5fX2t2X3FfYnVmOwogICAgICAgICAgICBpZiAoQXJyYXkuaXNBcnJheShidWYpKSBwcm9jZXNzZWQgPSBidWYubGVuZ3RoOwogICAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgICB9KTsKICAgICAgICBkb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCdfX2t2X3FkYXRhJywgZnVuY3Rpb24oZXZ0KSB7CiAgICAgICAgICB0cnkgewogICAgICAgICAgICBjb25zdCBkID0gZXZ0ICYmIGV2dC5kZXRhaWw7CiAgICAgICAgICAgIGlmIChkICYmIGQudXJsICYmIGQudGV4dCkgewogICAgICAgICAgICAgIHRyeSB7IGhhbmRsZVJhd1Jlc3BvbnNlKGQudXJsLCBkLnRleHQpOyB9IGNhdGNoIChfKSB7fQogICAgICAgICAgICAgIGNvbnN0IGJ1ZiA9IFVXLl9fa3ZfcV9idWY7CiAgICAgICAgICAgICAgaWYgKEFycmF5LmlzQXJyYXkoYnVmKSkgcHJvY2Vzc2VkID0gYnVmLmxlbmd0aDsKICAgICAgICAgICAgfQogICAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgICB9KTsKICAgICAgICB2YXIgYnJpZGdlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnX190bF9xYnJpZGdlJyk7CiAgICAgICAgaWYgKGJyaWRnZUVsKSB7CiAgICAgICAgICBicmlkZ2VFbC5hZGRFdmVudExpc3RlbmVyKCdfX3RsX3FicmlkZ2UnLCBmdW5jdGlvbihldnQpIHsKICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICBjb25zdCBkID0gZXZ0ICYmIGV2dC5kZXRhaWw7CiAgICAgICAgICAgICAgaWYgKGQgJiYgZC51cmwgJiYgZC50ZXh0KSB7CiAgICAgICAgICAgICAgICB0cnkgeyBoYW5kbGVSYXdSZXNwb25zZShkLnVybCwgZC50ZXh0KTsgfSBjYXRjaCAoXykge30KICAgICAgICAgICAgICAgIGNvbnN0IGJ1ZiA9IFVXLl9fa3ZfcV9idWY7CiAgICAgICAgICAgICAgICBpZiAoQXJyYXkuaXNBcnJheShidWYpKSBwcm9jZXNzZWQgPSBidWYubGVuZ3RoOwogICAgICAgICAgICAgIH0KICAgICAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgICAgIH0pOwogICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgdmFyIGxhdGVzdCA9IGJyaWRnZUVsLmdldEF0dHJpYnV0ZSgnZGF0YS1sYXRlc3QnKTsKICAgICAgICAgICAgaWYgKGxhdGVzdCkgewogICAgICAgICAgICAgIHZhciBwID0gSlNPTi5wYXJzZShsYXRlc3QpOwogICAgICAgICAgICAgIGlmIChwICYmIHAudXJsICYmIHAudGV4dCkgaGFuZGxlUmF3UmVzcG9uc2UocC51cmwsIHAudGV4dCk7CiAgICAgICAgICAgIH0KICAgICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgfQogICAgICB9IGNhdGNoIChfKSB7fQogICAgICBkcmFpbigpOwogICAgICBpZiAoZG9jdW1lbnQucmVhZHlTdGF0ZSA9PT0gJ2xvYWRpbmcnKSBkb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCdET01Db250ZW50TG9hZGVkJywgZHJhaW4pOyBlbHNlIHNldFRpbWVvdXQoZHJhaW4sIDgwMCk7CiAgICAgIGNvbnN0IGl2ID0gc2V0SW50ZXJ2YWwoZHJhaW4sIDE1MCk7CiAgICAgIHNldFRpbWVvdXQoKCkgPT4gY2xlYXJJbnRlcnZhbChpdiksIDkwZTMpOwogICAgfSBjYXRjaCAoXykge30KICB9CiAgc2V0dXBLVkJ1ZlJlYWRlcigpOwogIGFzeW5jIGZ1bmN0aW9uIHN0YXJ0dXAoKSB7CiAgICB0cnkgeyBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbSgnX3RsX3JlbW90ZV9sb2NrZWQnKTsgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oJ190bF9wb2lzb25lZCcpOyB9IGNhdGNoIChfKSB7fQogICAgY29uc3Qgc3RvcmVkS2V5ID0gX3NMUy5nZXQoTFNfS0VZKTsKICAgIGNvbnN0IHN0b3JlZEV4cCA9IF9zTFMuZ2V0KExTX0VYUCk7CiAgICBpZiAoc3RvcmVkS2V5KSB7CiAgICAgIGlmIChzdG9yZWRFeHApIHsKICAgICAgICBjb25zdCBleHBEYXRlID0gbmV3IERhdGUoc3RvcmVkRXhwKTsKICAgICAgICBjb25zdCBub3cgPSBuZXcgRGF0ZTsKICAgICAgICBpZiAoIWlzTmFOKGV4cERhdGUpICYmIGV4cERhdGUgPCBub3cpIHsKICAgICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKExTX0tFWSk7CiAgICAgICAgICBidWlsZExvY2tTY3JlZW4oJ+KPsCBLZXkgxJHDoyBo4bq/dCBo4bqhbiEgVnVpIGzDsm5nIG5o4bqtcCBrZXkgbeG7m2kuJyk7CiAgICAgICAgICByZXR1cm47CiAgICAgICAgfQogICAgICB9CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgY3VycmVudE9sbSA9IGdldE9sbVVzZXJuYW1lKCk7CiAgICAgICAgY29uc3QgciA9IGF3YWl0IGdtUG9zdCgnL3ZlcmlmeScsIHsKICAgICAgICAgIGtleTogc3RvcmVkS2V5LAogICAgICAgICAgaHdpZDogZ2V0SFdJRCgpLAogICAgICAgICAgb2xtX3VzZXI6IGN1cnJlbnRPbG0KICAgICAgICB9KTsKICAgICAgICBpZiAoci5zdWNjZXNzIHx8IHIudmFsaWQpIHsKICAgICAgICAgIGNvbnN0IHNlcnZlck9sbSA9IHIub2xtX3VzZXIgfHwgci5vbG1fYWNjb3VudCB8fCAnJzsKICAgICAgICAgIGlmIChzZXJ2ZXJPbG0gJiYgY3VycmVudE9sbSAmJiBjdXJyZW50T2xtICE9PSAnS2hvbmdYYWNEaW5oJykgewogICAgICAgICAgICBpZiAoc2VydmVyT2xtLnRvTG93ZXJDYXNlKCkgIT09IGN1cnJlbnRPbG0udG9Mb3dlckNhc2UoKSkgewogICAgICAgICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKExTX0tFWSk7CiAgICAgICAgICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oTFNfVFlQRSk7CiAgICAgICAgICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oTFNfRVhQKTsKICAgICAgICAgICAgICBoYW5kbGVPbG1NaXNtYXRjaChzZXJ2ZXJPbG0sIGN1cnJlbnRPbG0pOwogICAgICAgICAgICAgIHJldHVybjsKICAgICAgICAgICAgfQogICAgICAgICAgfQogICAgICAgICAgQ1VSUkVOVF9LRVkgPSBzdG9yZWRLZXk7CiAgICAgICAgICBLRVlfU1RBVFVTID0gewogICAgICAgICAgICB2YWxpZDogdHJ1ZSwKICAgICAgICAgICAgdHlwZTogci50eXBlLAogICAgICAgICAgICBleHBpcmVzX2F0OiByLmV4cGlyZXNfYXQKICAgICAgICAgIH07CiAgICAgICAgICBfc0xTLnNldChMU19UWVBFLCByLnR5cGUgfHwgJ1RIVU9ORycpOwogICAgICAgICAgX3NMUy5zZXQoTFNfRVhQLCByLmV4cGlyZXNfYXQgfHwgJycpOwogICAgICAgICAgY3JlYXRlVUkoKTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgaWYgKHIgJiYgci5pbmZyYUVycm9yKSB7CiAgICAgICAgICAgIGJ1aWxkTG9ja1NjcmVlbign4pqg77iPIE3huqFuZyB54bq/dS9jaMawYSBr4bq/dCBu4buRaSDEkcaw4bujYyBzZXJ2ZXIgKEtleVZhdWx0IHThuqFtIGLhuq1uKSDigJQgZ2nhu68ga2V5LCDEkWFuZyB0aOG7rSBs4bqhaSBzYXUgOHMuIENo4buJIGTDuW5nIMSRxrDhu6NjIGtoaSBzZXJ2ZXIgeMOhYyB0aOG7sWMgaOG7o3AgbOG7hy4nKTsKICAgICAgICAgICAgc2V0VGltZW91dChzdGFydHVwLCA4ZTMpOwogICAgICAgICAgICByZXR1cm47CiAgICAgICAgICB9CiAgICAgICAgICBpZiAociAmJiByLl9odHRwU3RhdHVzID09PSA0MDQpIHsKICAgICAgICAgICAgX2VudGVyQmFuTW9kZSgnVGhp4bq/dCBi4buLL0lQIMSRw6MgYuG7iyBhZG1pbiBraG/DoS4nKTsKICAgICAgICAgICAgcmV0dXJuOwogICAgICAgICAgfQogICAgICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oTFNfS0VZKTsKICAgICAgICAgIGJ1aWxkTG9ja1NjcmVlbihyLm1lc3NhZ2UgfHwgJ0tleSBraMO0bmcgY8OybiBo4bujcCBs4buHIScpOwogICAgICAgIH0KICAgICAgfSBjYXRjaCAobmV0RXJyKSB7CiAgICAgICAgYWRkTG9nKCfimqDvuI8gQ2jGsGEga+G6v3QgbuG7kWkgxJHGsOG7o2Mgc2VydmVyICht4bqhbmcgeeG6v3UpIOKAlCDEkWFuZyB0aOG7rSBs4bqhaSwgY2jGsGEgY+G6pXAgY2jhu6ljIG7Eg25nLicsICd3YXJuJyk7CiAgICAgICAgYnVpbGRMb2NrU2NyZWVuKCfimqDvuI8gTeG6oW5nIHnhur91L2NoxrBhIGvhur90IG7hu5FpIMSRxrDhu6NjIHNlcnZlciDigJQgxJFhbmcgdOG7sSB0aOG7rSBs4bqhaS4gQ2jhu4kgaG/huqF0IMSR4buZbmcga2hpIHNlcnZlciB4w6FjIHRo4buxYyBrZXkgaOG7o3AgbOG7hy4nKTsKICAgICAgICBzZXRUaW1lb3V0KHN0YXJ0dXAsIDhlMyk7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICB9IGVsc2UgewogICAgICBidWlsZExvY2tTY3JlZW4oKTsKICAgIH0KICAgIHNldEludGVydmFsKGFzeW5jICgpID0+IHsKICAgICAgaWYgKCFDVVJSRU5UX0tFWSkgcmV0dXJuOwogICAgICB0cnkgewogICAgICAgIGNvbnN0IGN1cnJlbnRPbG0gPSBnZXRPbG1Vc2VybmFtZSgpOwogICAgICAgIGNvbnN0IHIgPSBhd2FpdCBnbVBvc3QoJy92ZXJpZnknLCB7CiAgICAgICAgICBrZXk6IENVUlJFTlRfS0VZLAogICAgICAgICAgaHdpZDogZ2V0SFdJRCgpLAogICAgICAgICAgb2xtX3VzZXI6IGN1cnJlbnRPbG0KICAgICAgICB9KTsKICAgICAgICBpZiAociAmJiByLnJldm9rZWQpIHsKICAgICAgICAgIF9wdXJnZUNsaWVudFN0YXRlKCk7CiAgICAgICAgICBfZW50ZXJCYW5Nb2RlKCdTZXJ2ZXIgdGh1IGjhu5NpIHF1eeG7gW46IHRoaeG6v3QgYuG7iy9JUCDEkcOjIGLhu4sgYWRtaW4ga2hvw6EuJyk7CiAgICAgICAgICByZXR1cm47CiAgICAgICAgfQogICAgICAgIGlmIChyICYmIHIuaW5mcmFFcnJvcikgcmV0dXJuOwogICAgICAgIGlmICghKHIuc3VjY2VzcyB8fCByLnZhbGlkKSkgewogICAgICAgICAgaWYgKHIgJiYgci5faHR0cFN0YXR1cyA9PT0gNDA0KSB7CiAgICAgICAgICAgIF9lbnRlckJhbk1vZGUoJ1RoaeG6v3QgYuG7iy9JUCDEkcOjIGLhu4sgYWRtaW4ga2hvw6EuJyk7CiAgICAgICAgICAgIHJldHVybjsKICAgICAgICAgIH0KICAgICAgICAgIGNvbnN0IHBhbmVsRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtcGFuZWwnKTsKICAgICAgICAgIGNvbnN0IGZiID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLWZsb2F0QnRuJyk7CiAgICAgICAgICBpZiAocGFuZWxFbCkgcGFuZWxFbC5yZW1vdmUoKTsKICAgICAgICAgIGlmIChmYikgZmIucmVtb3ZlKCk7CiAgICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShMU19LRVkpOwogICAgICAgICAgQ1VSUkVOVF9LRVkgPSBudWxsOwogICAgICAgICAgX3NlY1Nlc3Npb24gPSB7CiAgICAgICAgICAgIHRva2VuOiBudWxsLAogICAgICAgICAgICBleHA6IDAsCiAgICAgICAgICAgIGZwSGFzaDogbnVsbCwKICAgICAgICAgICAgc2VxOiAxCiAgICAgICAgICB9OwogICAgICAgICAgQ1VSUkVOVF9ERVZJQ0UgPSAnJzsKICAgICAgICAgIHNob3dDdXN0b21Nb2RhbCh7CiAgICAgICAgICAgIGljb246ICfimqDvuI8nLAogICAgICAgICAgICB0aXRsZTogJ0tFWSDEkMODIELhu4ogS0jDk0EhJywKICAgICAgICAgICAgbGluZXM6IFsgci5tZXNzYWdlIHx8ICdLZXkgxJHDoyBi4buLIHbDtCBoaeG7h3UgaG/DoSEnLCAnVG9vbCBz4bq9IGLhu4sga2jDs2EgbmdheSBs4bqtcCB04bupYyEnIF0sCiAgICAgICAgICAgIG9uT2s6ICgpID0+IGJ1aWxkTG9ja1NjcmVlbihyLm1lc3NhZ2UgfHwgJ0tleSDEkcOjIGLhu4sgdsO0IGhp4buHdSBob8OhIScpCiAgICAgICAgICB9KTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgY29uc3Qgc2VydmVyT2xtID0gci5vbG1fdXNlciB8fCByLm9sbV9hY2NvdW50IHx8ICcnOwogICAgICAgICAgaWYgKHNlcnZlck9sbSAmJiBjdXJyZW50T2xtICYmIGN1cnJlbnRPbG0gIT09ICdLaG9uZ1hhY0RpbmgnKSB7CiAgICAgICAgICAgIGlmIChzZXJ2ZXJPbG0udG9Mb3dlckNhc2UoKSAhPT0gY3VycmVudE9sbS50b0xvd2VyQ2FzZSgpKSB7CiAgICAgICAgICAgICAgaGFuZGxlT2xtTWlzbWF0Y2goc2VydmVyT2xtLCBjdXJyZW50T2xtKTsKICAgICAgICAgICAgICByZXR1cm47CiAgICAgICAgICAgIH0KICAgICAgICAgIH0KICAgICAgICB9CiAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICB9LCA1ICogNjAgKiAxZTMpOwogIH0KICBpZiAoZG9jdW1lbnQucmVhZHlTdGF0ZSA9PT0gJ2xvYWRpbmcnKSB7CiAgICBkb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCdET01Db250ZW50TG9hZGVkJywgc3RhcnR1cCk7CiAgfSBlbHNlIHsKICAgIHN0YXJ0dXAoKTsKICB9Cn0pKCk7Cg==';
const CONNECTOR_MODULE_VERSION = parseInt(process.env.CONNECTOR_MODULE_VERSION || '39', 10);
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
(function validateConnectorAtBoot() {
  try {
    const patched = patchConnectorSrc(CONNECTOR_MODULE_SRC);
    const chk = compileCheckJs(patched, 'connector-boot');
    if (chk.ok) {
      console.log('[HARDEN] Connector syntax OK (' + CONNECTOR_MODULE_SRC.length + ' bytes, patched ' + patched.length + ' bytes).');
      return;
    }
    console.error('[HARDEN] Connector module loi syntax: ' + chk.error);
    try {
      const embedded = Buffer.from(CONNECTOR_MODULE_EMBEDDED_B64, 'base64').toString('utf8');
      const embChk = compileCheckJs(patchConnectorSrc(embedded), 'connector-embedded-boot');
      if (embChk.ok) {
        CONNECTOR_MODULE_SRC = embedded;
        console.warn('[HARDEN] Rollback connector sang EMBEDDED base64 thanh cong.');
      }
    } catch (e2) {
      console.error('[HARDEN] Rollback embedded that bai: ' + (e2 && e2.message || e2));
    }
  } catch (_) {}
})();
function compileCheckJs(src, label) {
  try {
    new vm.Script(String(src == null ? '' : src), { filename: (label || 'payload') + '.js' });
    return { ok: true, error: null };
  } catch (e) {
    return { ok: false, error: (e && e.name ? e.name + ': ' : '') + (e && e.message ? e.message : String(e)) };
  }
}
const SAFE_MAINTENANCE_SRC = ';(function(){try{var d=document.createElement("div");d.style.cssText="position:fixed;inset:0;z-index:2147483647;background:#0d1117;color:#ff6b6b;display:flex;align-items:center;justify-content:center;font-family:monospace;font-size:14px;padding:20px;text-align:center;";d.textContent="[HARDEN] Loader: server dang cap nhat, vui long tai lai sau vai phut.";(document.documentElement||document.body).appendChild(d);}catch(_){}})();\n';
function safeJs(src, label) {
  const chk = compileCheckJs(src, label);
  if (chk.ok) return { src: src, ok: true, error: null };
  try { adminLog('js-syntax-invalid', { label: label, error: chk.error, bytes: String(src || '').length }); } catch (_) {}
  console.error('[HARDEN] Payload JS loi syntax (' + label + '): ' + chk.error + ' — dung payload bao tri.');
  return { src: SAFE_MAINTENANCE_SRC, ok: false, error: chk.error };
}
function patchConnectorSrc(src) {
  let out = String(src || '');
  try {
    if (out.includes("let h = localStorage.getItem('_tl_hwid');")) {
      out = out.replace(
        "let h = localStorage.getItem('_tl_hwid');",
        "let h=''; try{ h = localStorage.getItem('_tl_hwid') || ''; }catch(_){}"
      );
    }
    if (out.includes("localStorage.setItem('_tl_hwid', h);")) {
      out = out.replace(
        "localStorage.setItem('_tl_hwid', h);",
        "try{ localStorage.setItem('_tl_hwid', h); }catch(_){}"
      );
    }
    if (out.includes("let CURRENT_THEME = localStorage.getItem(LS_THEME) || 'default';")) {
      out = out.replace(
        "let CURRENT_THEME = localStorage.getItem(LS_THEME) || 'default';",
        "let CURRENT_THEME = (function(){try{return localStorage.getItem(LS_THEME)||'default';}catch(_){return 'default';}})();"
      );
    }
    if (out.includes('__tl_fus_guard: 1')) {
      out = out.replace(
        "__tl_fus_guard: 1",
        "__tl_fus_guard: 1,\n          GM_xmlhttpRequest: 1,\n          GM_xmlHttpRequest: 1,\n          GM_addStyle: 1,\n          __GMFunc__: 1,\n          GM_getValue: 1,\n          GM_setValue: 1,\n          GM_deleteValue: 1,\n          GM_listValues: 1,\n          GM_info: 1,\n          GM_notification: 1,\n          GM_openInTab: 1,\n          GM_registerMenuCommand: 1,\n          GM_cookie: 1,\n          GM_download: 1,\n          unsafeWindow: 1"
      );
    }
    if (out.includes('_preScanHook = _detectHookNow();')) {
      out = out.replace('_preScanHook = _detectHookNow();', '_preScanHook = null; // detection disabled');
    }
    if (out.includes('const h = _detectHookNow();')) {
      out = out.replace('const h = _detectHookNow();', 'const h = null; // detection disabled');
    }
    out = out.replace(
      /_foreignStrike\+\+;\n(\s*)if \(_foreignStrike >= 3 && _guardActive\) \{/,
      '_foreignStrike = 0; // disabled\n$1if (false && _foreignStrike >= 3 && _guardActive) {'
    );
    out = out.replace(
      /if \(d\.clean\) return;\n(\s*)_enterRemoteLock\('/g,
      "return; // detection disabled\n$1if (d.clean) return;\n$1_enterRemoteLock('"
    );
    out = out.replace(
      /salt:\s*enc\.encode\('godmode-v4-salt'\),\s*\n(\s*)iterations:\s*1e3,/,
      "salt: enc.encode('godmode-v4-salt'),\n$1iterations: 1e5,"
    );
    if (!out.includes('target_score:')) {
      out = out.replace(
        /(time_str:\s*time_str,\s*\n\s*grade:\s*window\.grade[^\n]*)/,
        "$1,\n            target_score: (function(){try{var el=document.getElementById('tl-god-target-score');var v=el?parseFloat(el.value):NaN;if(!isFinite(v))v=10;return String(Math.min(10,Math.max(7,v)));}catch(_){return '10';}})()"
      );
    }
    out = out.replace(
      "  function addLog(msg, type = '') {\n    const box = document.getElementById('tl-logbox');",
      "  function addLog(msg, type = '') {\n    if (type === 'info') return; // [v30] ẩn thông tin màu xanh nước biển; đáp án (ok) vẫn hiển thị\n    const box = document.getElementById('tl-logbox');"
    );
    out = out.replace('_bankFallbackTimer = setTimeout(_checkAnswerBankFallback, 6000);',
      '_bankFallbackTimer = setTimeout(_checkAnswerBankFallback, 60000); // [v30] tra kho sau 60s (1 phút)');
    out = out.replace("addLog('⏳ Trang bài tập: sau 6s nếu chưa nạp câu hỏi sẽ tự tra kho đáp án server (thử lại 20s, 45s).', 'info');",
      "addLog('⏳ Trang bài tập: sau 60s nếu chưa nạp câu hỏi sẽ tự tra kho đáp án server (thử lại mỗi 60s).', 'info');");
    const OLD_C7 = [
      '        _bankRetry++;',
      '        if (_bankRetry <= 2) {',
      '          const waitMs = _bankRetry === 1 ? 14000 : 25000;',
      '          _bankFallbackTimer = setTimeout(_checkAnswerBankFallback, waitMs);',
      '        }'
    ].join('\n');
    const NEW_C7 = [
      '        _bankRetry++;',
      '        if (_bankRetry <= 60) {',
      '          const waitMs = 60000; // [v30] chu kỳ tra kho 60s (1 phút)',
      '          _bankFallbackTimer = setTimeout(_checkAnswerBankFallback, waitMs);',
      '        }'
    ].join('\n');
    out = out.replace(OLD_C7, NEW_C7);
  } catch (_) {}
    try {
      out = out.replace(
        /function drain\(\) \{\s*try \{\s*const buf = UW\.__kv_q_buf;/,
        function () {
          return [
            'function drain() {',
            '        try {',
            '          try{var __be=document.getElementById("__tl_qbridge");if(__be){var __lt=__be.getAttribute("data-latest");if(__lt){try{var __lp=JSON.parse(__lt);if(__lp&&__lp.url&&__lp.text)handleRawResponse(__lp.url,__lp.text);}catch(_){}}}}catch(_){}',
            '          const buf = UW.__kv_q_buf;'
          ].join('\n');
        }
      );
      out = out.replace(
        /var bridgeEl = document\.getElementById\('__tl_qbridge'\);[\s\S]*?\n        \}\n(?=      \} catch \(_\) \{\})/,
        function () {
          return [
            '        function __tlAttachBridge(el){',
            '          if(!el || el.__tlAttached) return;',
            '          el.__tlAttached = 1;',
            '          el.addEventListener("__tl_qbridge", function(evt) {',
            '            try {',
            '              const d = evt && evt.detail;',
            '              if (d && d.url && d.text) {',
            '                try { handleRawResponse(d.url, d.text); } catch (_) {}',
            '                const buf = UW.__kv_q_buf;',
            '                if (Array.isArray(buf)) processed = buf.length;',
            '              }',
            '            } catch (_) {}',
            '          });',
            '          try {',
            '            var latest = el.getAttribute("data-latest");',
            '            if (latest) {',
            '              var p = JSON.parse(latest);',
            '              if (p && p.url && p.text) handleRawResponse(p.url, p.text);',
            '            }',
            '          } catch (_) {}',
            '        }',
            '        var bridgeEl = document.getElementById("__tl_qbridge");',
            '        __tlAttachBridge(bridgeEl);',
            '        var __bridgeTries = 0;',
            '        var __bridgeIv = setInterval(function(){',
            '          try {',
            '            var el2 = document.getElementById("__tl_qbridge");',
            '            if (el2) {',
            '              __tlAttachBridge(el2);',
            '              var latest2 = el2.getAttribute("data-latest");',
            '              if (latest2) { var p2 = JSON.parse(latest2); if (p2 && p2.url && p2.text) handleRawResponse(p2.url, p2.text); }',
            '            }',
            '          } catch (_) {}',
            '          if (++__bridgeTries > 80) clearInterval(__bridgeIv);',
            '        }, 250);'
          ].join('\n');
        }
      );
    } catch (_) {}
  try {
    // [v41] GATE FIX (KeyVault OLM_user.js / index.js): connector chạy TRẺ sau khi unlock key.
    // Tự replay các request tài nguyên câu hỏi; quét buffer parent/iframe; giữ drain 10 phút;
    // chấp nhận nhiều định dạng dữ liệu câu hỏi (data.data.questions / data.answers / data.items).
    if (out.includes('  setupKVBufReader();\n  async function startup() {')) {
      out = out.replace(
        '  setupKVBufReader();\n  async function startup() {',
        [
          '  setupKVBufReader();',
          '  (function __kvGateAutoReplay(){',
          '    try {',
          '      var __arTries = 0, __arDone = false;',
          '      function __arTick(){',
          '        try {',
          '          if (SESSION.raw_questions && SESSION.raw_questions.length) { __arDone = true; return; }',
          '          if (typeof forceFetchQuestions === "function") {',
          '            var __p = forceFetchQuestions();',
          '            if (__p && typeof __p.then === "function") __p.then(function(){}).catch(function(){});',
          '          }',
          '        } catch (_) {}',
          '        __arTries++;',
          '        if (!__arDone && __arTries < 24) setTimeout(__arTick, 2500);',
          '      }',
          '      setTimeout(__arTick, 1500);',
          '      function __arAgain(){ __arTries = 0; __arDone = false; setTimeout(__arTick, 1200); }',
          '      try { window.addEventListener("popstate", __arAgain); } catch (_) {}',
          '      try { window.addEventListener("hashchange", __arAgain); } catch (_) {}',
          '      try { document.addEventListener("__kv_qdata", function(){ setTimeout(function(){ try{ if (typeof forceFetchQuestions === "function") forceFetchQuestions(); }catch(_){} }, 300); }); } catch (_) {}',
          '    } catch (_) {}',
          '  })();',
          '  async function startup() {'
        ].join('\n')
      );
    }
    if (out.includes('const buf = UW.__kv_q_buf;\n          if (!Array.isArray(buf) || buf.length <= processed) return;')) {
      out = out.replace(
        'const buf = UW.__kv_q_buf;\n          if (!Array.isArray(buf) || buf.length <= processed) return;',
        [
          'const buf = UW.__kv_q_buf;',
          '          try {',
          '            var __kvSources = [];',
          '            try { if (UW.parent && UW.parent !== UW && Array.isArray(UW.parent.__kv_q_buf)) __kvSources.push(UW.parent.__kv_q_buf); } catch (_) {}',
          '            try { var __ifr = (document.querySelectorAll ? document.querySelectorAll("iframe,frame") : []); for (var fi = 0; fi < __ifr.length; fi++) { try { if (__ifr[fi].contentWindow && Array.isArray(__ifr[fi].contentWindow.__kv_q_buf)) __kvSources.push(__ifr[fi].contentWindow.__kv_q_buf); } catch (_) {} } } catch (_) {}',
          '            for (var si = 0; si < __kvSources.length; si++) {',
          '              var sb = __kvSources[si];',
          '              for (var sj = 0; sj < sb.length; sj++) { var sit = sb[sj]; if (sit && sit.url && sit.text) { try { handleRawResponse(sit.url, sit.text); } catch (_) {} } }',
          '            }',
          '          } catch (_) {}',
          '          if (!Array.isArray(buf) || buf.length <= processed) return;'
        ].join('\n')
      );
    }
    out = out.replace(
      'setTimeout(() => clearInterval(iv), 90e3);',
      'setTimeout(() => clearInterval(iv), 600e3); // [v41] gate: giữ drain buffer 10 phút thay vì 90s'
    );
    if (out.includes('const qList = data.questions || data.data || (Array.isArray(data) ? data : null);')) {
      out = out.replace(
        'const qList = data.questions || data.data || (Array.isArray(data) ? data : null);',
        [
          'let qList = data.questions || data.data || data.answers || (Array.isArray(data) ? data : null);',
          'if (!Array.isArray(qList) && qList && qList.questions) qList = qList.questions;',
          'if (!Array.isArray(qList) && data.data && Array.isArray(data.data.questions)) qList = data.data.questions;',
          'if (!Array.isArray(qList) && Array.isArray(data.items)) qList = data.items;'
        ].join('\n')
      );
    }
  } catch (_) {}
  const fallback = [
    ';(function(){try{',
    'if(typeof window!=="undefined"&&!window.__tlFetchXhr){',
    'Object.defineProperty(window,"__tlFetchXhr",{value:function(d){d=d||{};',
    'fetch(d.url,{method:d.method||"GET",headers:d.headers||{},body:(d.data!=null?d.data:undefined)})',
    '.then(function(r){return r.text().then(function(t){if(d.onload)d.onload({status:r.status,responseText:t,response:t,readyState:4});});})',
    '.catch(function(e){if(d.onerror)d.onerror({error:String(e&&e.message||e)});});',
    '},configurable:true,writable:false});}',
    '}catch(_){}})();',
    ''
  ].join('\n');
  return fallback + out;
}
function buildConnectorPayload(sessionToken) {
  const built = IOS_BRIDGE_SHIM + GM_LEAK_SANITIZER + patchConnectorSrc(CONNECTOR_MODULE_SRC);
  const safe = safeJs(built, 'connector-payload');
  return encryptAnswers({
    src: safe.src,
    v: CONNECTOR_MODULE_VERSION
  }, sessionToken);
}
const BOOTSTRAP_SALT = 'tl-bootstrap-v8-salt';
const BOOTSTRAP_ITER = 1e3;
function bootstrapDeriveKey() {
  return crypto.pbkdf2Sync(BOOTSTRAP_PUBLIC_KEY, BOOTSTRAP_SALT, BOOTSTRAP_ITER, 32, 'sha256');
}
function bootstrapEncrypt(plaintext) {
  const key = bootstrapDeriveKey();
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([ c.update(plaintext, 'utf8'), c.final(), c.getAuthTag() ]);
  return {
    iv: iv.toString('base64'),
    data: enc.toString('base64')
  };
}
const GM_LEAK_SANITIZER = ';(function(){try{var _wn=Object.getOwnPropertyNames(window);for(var _i=0;_i<_wn.length;_i++){var _n=_wn[_i];if(_n==="GM_info"||_n==="unsafeWindow"||/^(GM_|__gm|__u(ser)?script)/i.test(_n)){try{delete window[_n];}catch(_){try{window[_n]=undefined;}catch(_){}}}}}catch(_){}})();\n';
const IOS_BRIDGE_SHIM = `;try{
(function(){
  function __tlXhr(d){ d=d||{}; var done=false;
    function fin(ok,a){ if(done)return; done=true; try{ if(ok&&typeof d.onload==='function')d.onload(a); else if(!ok&&typeof d.onerror==='function')d.onerror(a); }catch(_){} }
    try{
      var ctrl=(typeof AbortController!=='undefined')?new AbortController():null;
      var tmo=setTimeout(function(){try{if(ctrl)ctrl.abort();}catch(_){} fin(false,{error:'Timeout'});}, d.timeout||20000);
      var opts={method:d.method||'GET',headers:d.headers||{}};
      if(ctrl)opts.signal=ctrl.signal;
      if(d.data!==undefined&&d.data!==null){ if(typeof d.data==='string'){opts.body=d.data;} else { try{opts.body=JSON.stringify(d.data);}catch(_){opts.body=String(d.data);} } }
      fetch(d.url,opts).then(function(r){clearTimeout(tmo);return r.text().then(function(t){fin(true,{status:r.status,responseText:t,response:t,readyState:4,finalUrl:r.url});});}).catch(function(e){clearTimeout(tmo);fin(false,{error:String(e&&e.message||e)});});
    }catch(e){fin(false,{error:String(e&&e.message||e)});}
  }
  function __tlStyle(css){ try{ var st=document.createElement('style'); st.textContent=css; (document.head||document.documentElement).appendChild(st); }catch(_){} }
  try{ if(typeof window!=='undefined' && !window.__tlFetchXhr){ Object.defineProperty(window,'__tlFetchXhr',{value:__tlXhr,configurable:true,writable:false}); } }catch(_){}
  try{ if(typeof window!=='undefined' && !window.__tlFetchStyle){ Object.defineProperty(window,'__tlFetchStyle',{value:__tlStyle,configurable:true,writable:false}); } }catch(_){}
})();
}catch(_){}
`;
function buildOlmBanSnippet(origin, apiPrefix) {
  var O = JSON.stringify(origin), P = JSON.stringify(apiPrefix);
  var parts = [ ';try{(function(){', 'var _o=', O, ',_p=', P, ';', 'function _olmu(){var u=\'\';var w;try{w=(typeof unsafeWindow!==\'undefined\')?unsafeWindow:window;}catch(e){w=window;}try{u=w.SESSION&&w.SESSION.meta&&(w.SESSION.meta.id_user||w.SESSION.meta.username||w.SESSION.meta.name)||\'\';}catch(e){}if(!u){try{u=localStorage.getItem(\'id_user\')||localStorage.getItem(\'user_id\')||localStorage.getItem(\'olm_user\')||localStorage.getItem(\'username\')||\'\';}catch(e){}}if(!u){try{var el=document.querySelector(\'.user-name,.username,.account-name,[class*=user-name],[class*=username]\');if(el)u=(el.textContent||\'\').trim();}catch(e){}}return u;}', 'function _show(m){try{if(document.getElementById(\'_olmbn_ov\'))return;var d=document.createElement(\'div\');d.id=\'_olmbn_ov\';d.style.cssText=\'position:fixed;inset:0;z-index:2147483647;background:rgba(127,29,29,.97);color:#fff;display:flex;align-items:center;justify-content:center;padding:24px;font-family:system-ui,sans-serif;\';var c=document.createElement(\'div\');c.style.cssText=\'max-width:420px;text-align:center;background:#7f1d1d;border:2px solid #ef4444;border-radius:14px;padding:28px;box-shadow:0 10px 40px rgba(0,0,0,.5);\';var t1=document.createElement(\'div\');t1.textContent=\'🚫\';t1.style.cssText=\'font-size:42px;margin-bottom:12px\';var t2=document.createElement(\'div\');t2.textContent=\'TÀI KHOẢN OLM ĐÃ BỊ CẤM\';t2.style.cssText=\'font-size:18px;font-weight:800;margin-bottom:10px;color:#fca5a5\';var t3=document.createElement(\'div\');t3.textContent=String(m||\'\');t3.style.cssText=\'font-size:13px;line-height:1.7;color:#fecaca\';c.appendChild(t1);c.appendChild(t2);c.appendChild(t3);d.appendChild(c);(document.documentElement||document.body).appendChild(d);}catch(e){}}', 'function _chk(){var u=_olmu();if(!u)return;try{fetch(_o+_p+\'/olm-check\',{method:\'POST\',headers:{\'Content-Type\':\'application/json\'},body:JSON.stringify({olm_user:u})}).then(function(r){return r.json();}).then(function(j){if(j&&j.banned){_show(j.message||(\'Tai khoan OLM bi ban\'+(j.permanent?\' vinh vien\':\'\')+\'. Ly do: \'+(j.reason||\'\')));}}).catch(function(){});}catch(e){}}', 'setInterval(_chk,30000);setTimeout(_chk,4000);', '})();}catch(e){}\n' ];
  return parts.join('');
}
function renderConnectorSrc(req) {
  const origin = req.protocol + '://' + req.get('host');
  let src = patchConnectorSrc(CONNECTOR_MODULE_SRC);
  src = src.replace(/const SERVER_BASE\s*=\s*'[^']*';/, 'const SERVER_BASE = ' + JSON.stringify(origin) + ';');
  src = src.replace(/const API_SECRET\s*=\s*'[^']*';/, 'const API_SECRET  = ' + JSON.stringify(SECRET) + ';');
  const full = IOS_BRIDGE_SHIM + GM_LEAK_SANITIZER + src + buildOlmBanSnippet(origin, API_PREFIX);
  const safe = safeJs(full, 'bootstrap-connector');
  return safe.src;
}
function wrapConnectorWithBridge(src) {
  return src;
}
const REVOKE_STUB_SRC = `;(function(){
  try{
    var KEYS=['_tl_conn_key','_tl_conn_type','_tl_conn_exp','_tl_hwid','_tiep_theme','_tl_poisoned','_tl_remote_locked','_tl_boot_cache_v10','__tl_last_ansreq','__tl_last_qreq'];
    for(var i=0;i<KEYS.length;i++){ try{localStorage.removeItem(KEYS[i]);}catch(_){} try{if(typeof GM_deleteValue==='function')GM_deleteValue(KEYS[i]);}catch(_){} }
    ['tl-panel','tl-floatBtn','tl-conn-overlay','tl-lock-style','tl-ui-style','_olmbn_ov'].forEach(function(id){ try{var e=document.getElementById(id); if(e)e.remove();}catch(_){} });
    try{ if(typeof unsafeWindow!=='undefined'){ unsafeWindow.__TL_REVOKED__=true; } window.__TL_REVOKED__=true; }catch(_){}
    try{
      var d=document.createElement('div');
      d.style.cssText='position:fixed;inset:0;z-index:2147483647;background:rgba(69,10,10,.97);color:#fecaca;display:flex;align-items:center;justify-content:center;padding:24px;font:14px/1.6 system-ui,sans-serif;';
      d.innerHTML='<div style="max-width:420px;text-align:center;background:#7f1d1d;border:2px solid #ef4444;border-radius:14px;padding:28px"><div style="font-size:38px;margin-bottom:10px">🚫</div><div style="font-weight:800;font-size:17px;margin-bottom:10px;color:#fca5a5">THIẾT BỊ/IP ĐÃ BỊ KHOÁ</div><div style="font-size:13px">Toàn bộ chức năng script đã bị server thu dọn từ xa.<br>Chỉ admin mở khoá trong panel mới dùng lại được.</div></div>';
      (document.documentElement||document.body).appendChild(d);
    }catch(_){}
  }catch(_){}
})();
`;
function buildLoaderSrc(req) {
  const origin = req.protocol + '://' + req.get('host');
  const SEC = SECRET, AP = API_PREFIX;
  const loaderSrc = `// ==UserScript==\n// @name         GOD MODE v10.1 Loader (iOS no-leak, fetch-based)\n// @namespace    godmode.v9\n// @version      10.3\n// @description  v10.3 iOS-first: retry 8 lan + backoff mang yeu; ban thi bi revoked (xoa du lieu client); bridge cuc bo, KHONG gan window.GM_*\n// @match        *://*.olm.vn/*\n// @match        *://olm.vn/*\n// @run-at       document-end\n// @grant        none\n// ==/UserScript==\n;(function(){\n  var SERVER_BASE = ${JSON.stringify(origin)};\n  var API_PREFIX = ${JSON.stringify(AP)};\n  var BOOT_KEY = ${JSON.stringify(BOOTSTRAP_PUBLIC_KEY)};\n  function _err(m){ try{ var d=document.createElement('div'); d.style.cssText='position:fixed;top:10px;left:10px;z-index:2147483647;background:#7f1d1d;color:#fff;padding:10px 14px;border-radius:8px;font:12px/1.5 monospace;max-width:85%'; d.textContent='GOD MODE: '+(m||''); (document.documentElement||document.body).appendChild(d); setTimeout(function(){try{d.remove();}catch(_){}},8000); }catch(_){} }\n  function _b64dec(b64){ var bin=atob(b64); var bytes=new Uint8Array(bin.length); for(var i=0;i<bin.length;i++) bytes[i]=bin.charCodeAt(i); return bytes.buffer; }\n  function _gmXhr(d){ d=d||{}; try{ var ctrl=(typeof AbortController!=='undefined')?new AbortController():null; var tmo=setTimeout(function(){if(ctrl)try{ctrl.abort();}catch(_){}}, d.timeout||20000); var opts={method:d.method||'GET',headers:d.headers||{}}; if(ctrl)opts.signal=ctrl.signal; if(d.data!==undefined&&d.data!==null)opts.body=d.data; fetch(d.url,opts).then(function(r){clearTimeout(tmo);return r.text().then(function(t){return{s:r.status,t:t};});}).then(function(o){if(d.onload)d.onload({status:o.s,responseText:o.t,response:o.t,readyState:4});}).catch(function(e){clearTimeout(tmo);if(d.onerror)d.onerror({error:String(e&&e.message||e)});}); }catch(e){ if(d.onerror)d.onerror({error:String(e&&e.message||e)}); } }\n  function _gmStyle(css){ try{ var st=document.createElement('style'); st.textContent=css; (document.head||document.documentElement).appendChild(st); }catch(_){} }\n  try{}catch(_){}\n  var __uw=(typeof unsafeWindow!=='undefined')?unsafeWindow:window;
  function _runConnector(src){ try{ (new Function('GM_xmlhttpRequest','GM_addStyle','unsafeWindow', src)).call(window, _gmXhr, _gmStyle, __uw); }catch(e){ _err('Connector loi: '+(e&&e.message||e)); } }\n  async function _boot(){ try{ localStorage.removeItem('_tl_boot_cache_v10'); }catch(_){}\n    try{\n      var r=null; for(var __t=0;__t<8;__t++){ try{ var __c=(typeof AbortController!=='undefined')?new AbortController():null; var __to=setTimeout(function(){try{__c&&__c.abort();}catch(_){}},18000); try{ r = await fetch(SERVER_BASE + API_PREFIX + '/bootstrap.js', {cache:'no-store',credentials:'omit',mode:'cors',signal:__c?__c.signal:undefined}); }finally{clearTimeout(__to);} if(r.ok) break; }catch(__e){} await new Promise(function(res){setTimeout(res,900*(__t+1));}); } if(!r){  _err('Khong ket noi server sau 8 lan thu (mang yeu/VPN, F5 lai).'); return; }\n      if(!r.ok){ if(r.status===403){ try{ var rj=await r.json(); if(rj&&rj.revoked){ try{var ks=['_tl_conn_key','_tl_conn_type','_tl_conn_exp','_tl_hwid','_tl_boot_cache_v10','_tl_poisoned','_tl_remote_locked'];for(var i=0;i<ks.length;i++){try{localStorage.removeItem(ks[i]);}catch(_){}} }catch(_){} try{['tl-panel','tl-floatBtn','tl-conn-overlay'].forEach(function(id){var e=document.getElementById(id);if(e)e.remove();});}catch(_){} _err('REVOKED: thiet bi/IP bi admin khoa. Lien he admin de mo khoa.'); return; } }catch(_){} } if(r.status===404){ _err('Server dang bao tri / script tam khoa (admin da chan keo script).'); } else { _err('Khong keo duoc bootstrap (HTTP '+r.status+')'); } return; }\n      var j = await r.json();\n      if(j&&j.revoked){ try{var ks=['_tl_conn_key','_tl_conn_type','_tl_conn_exp','_tl_hwid'];for(var i=0;i<ks.length;i++){try{localStorage.removeItem(ks[i]);}catch(_){}}}catch(_){} _err('REVOKED: thiet bi/IP bi admin khoa (revoked).'); return; }\n      if(!j||!j.ok||!j.payload){ _err('Bootstrap khong hop le.'); return; }\n      var enc = new TextEncoder();\n      var keyMat = await crypto.subtle.importKey('raw', enc.encode(BOOT_KEY), 'PBKDF2', false, ['deriveKey']);\n      var aesKey = await crypto.subtle.deriveKey({name:'PBKDF2', salt: enc.encode('tl-bootstrap-v8-salt'), iterations: 1000, hash:'SHA-256'}, keyMat, {name:'AES-GCM', length:256}, false, ['decrypt']);\n      var iv = _b64dec(j.payload.iv);\n      var data = _b64dec(j.payload.data);\n      var plain = await crypto.subtle.decrypt({name:'AES-GCM', iv: iv}, aesKey, data);\n      var src = new TextDecoder('utf-8').decode(plain); \n      _runConnector(src);\n    }catch(e){ _err('Loi giai ma bootstrap: '+(e&&e.message||e)); }\n  }\n  if(document.readyState==='loading'){ document.addEventListener('DOMContentLoaded', _boot); } else { _boot(); }\n})();\n`;
  const safeLoader = safeJs(loaderSrc, 'userscript-loader');
  return safeLoader.src;
}
function buildKvPayloadSrc(req) {
  const origin = req.protocol + '://' + req.get('host');
  const connSrc = renderConnectorSrc(req);
  const connB64 = Buffer.from(connSrc, 'utf8').toString('base64');
  return `\n;(function(){\n  if (window.__tl_kv_payload_v82) return;\n  window.__tl_kv_payload_v82 = 1;\n  function __tlFail(msg){\n    console.error('[TL-KV]', msg);\n    try {\n      var d=document.createElement('div');\n      d.style.cssText='position:fixed;top:8px;left:8px;z-index:2147483647;background:#7f1d1d;color:#fff;padding:8px 12px;border-radius:8px;font:12px/1.4 monospace;max-width:85%;box-shadow:0 4px 12px rgba(0,0,0,.4)';\n      d.textContent='Tool loi: '+(msg||'');\n      (document.documentElement||document.body).appendChild(d);\n      setTimeout(function(){ try{d.remove();}catch(_){} }, 7000);\n    } catch(_){}\n  }\n  try {\n    \n    var __uw = (typeof unsafeWindow !== 'undefined') ? unsafeWindow : window;\n    var __gmStyle = (typeof GM_addStyle !== 'undefined') ? GM_addStyle : function(css){ try { var s=document.createElement('style'); s.textContent=css; (document.head||document.documentElement).appendChild(s); } catch(_){} };\n    var __gmXhr = (typeof GM_xmlhttpRequest !== 'undefined') ? GM_xmlhttpRequest : function(d){\n      d = d || {};\n      try {\n        var ctrl = (typeof AbortController !== 'undefined') ? new AbortController() : null;\n        var tmo = setTimeout(function(){ if (ctrl) try{ ctrl.abort(); }catch(_){} }, d.timeout || 20000);\n        var opts = { method: d.method || 'GET', headers: d.headers || {} };\n        if (ctrl) opts.signal = ctrl.signal;\n        if (d.data !== undefined && d.data !== null) opts.body = d.data;\n        fetch(d.url, opts).then(function(r){\n          clearTimeout(tmo);\n          return r.text().then(function(t){ return { s: r.status, t: t }; });\n        }).then(function(o){\n          if (d.onload) d.onload({ status: o.s, responseText: o.t, response: o.t, readyState: 4 });\n        }).catch(function(e){\n          clearTimeout(tmo);\n          if (d.onerror) d.onerror({ error: String(e && e.message || e) });\n        });\n      } catch(e){ if (d.onerror) d.onerror({ error: String(e && e.message || e) }); }\n    };\n    var __gmGet = (typeof GM_getValue !== 'undefined') ? GM_getValue : function(k, d) { try { var v = localStorage.getItem('tlv.' + k); return (v == null || v === '') ? d : v; } catch (_) { return d; } };
    var __gmSet = (typeof GM_setValue !== 'undefined') ? GM_setValue : function(k, v) { try { localStorage.setItem('tlv.' + k, (v == null ? '' : String(v))); } catch (_) {} };
    try { if (!window.__tlFetchXhr) Object.defineProperty(window, '__tlFetchXhr', { value: __gmXhr, configurable: true, writable: true }); } catch (_) {}
    var __b64 = "${connB64}";\n    var bin = atob(__b64);\n    var bytes = new Uint8Array(bin.length);\n    for (var i=0;i<bin.length;i++) bytes[i]=bin.charCodeAt(i);\n    var __src = new TextDecoder('utf-8').decode(bytes);\n    \n    // [v6.7.1 iOS-FIX] KHONG gan window.GM_xmlhttpRequest / window.__GMFunc__ (tranh GM leak); __gmXhr/__gmStyle truyen qua tham so new Function.
    (new Function('GM_addStyle','GM_getValue','GM_setValue','GM_xmlhttpRequest','unsafeWindow', __src)).call(window, __gmStyle, __gmGet, __gmSet, __gmXhr, __uw);\n  } catch(e) {\n    __tlFail(e && e.message ? e.message : String(e));\n  }\n})();\n`;
}
const keyFail = new Map;
function recordKeyFail(ip) {
  if (!ip) return;
  const now = Date.now();
  const e = keyFail.get(ip);
  if (!e || now - e.first > 10 * 60 * 1e3) {
    keyFail.set(ip, {
      count: 1,
      first: now
    });
    return false;
  }
  e.count++;
  if (e.count >= 10) {
    keyFail.delete(ip);
    return true;
  }
  return false;
}
function resetKeyFail(ip) {
  if (ip) keyFail.delete(ip);
}
function isPremiumType(t) {
  return [ 'PREMIUM', 'VIP', 'UNLIMITED' ].includes(String(t || '').toUpperCase());
}
function keyAct(key) {
  if (!key) return {
    processCount: 0,
    fireCount: 0,
    moduleFetchCount: 0,
    hbZeroCount: 0,
    dumpScore: 0,
    firstAttestAt: 0,
    lastModuleAt: 0
  };
  let r = keyActivity.get(key);
  if (!r) {
    r = {
      firstAttestAt: 0,
      lastModuleAt: 0,
      moduleFetchCount: 0,
      processCount: 0,
      fireCount: 0,
      hbZeroCount: 0,
      dumpScore: 0
    };
    keyActivity.set(key, r);
  }
  return r;
}
const permaDevices = new Set();
function knownIpsOfHwid(hwid) {
  const out = new Set();
  try {
    const d = devices.get(hwid);
    if (d && d.ip) out.add(d.ip);
    const a = deviceActivity.get(hwid);
    if (a && a.ip) out.add(a.ip);
  } catch (_) {}
  return [...out].filter(validIpFmt);
}
function banDevicePerma(hwid, reason, deviceName) {
  if (!hwid || !validHwid(hwid)) return false;
  const id = String(hwid);
  permaDevices.add(id);
  const name = deviceName || (devices.get(id) || {}).name || '';
  addBan(null, id, reason || 'ban toàn diện thiết bị (admin)', name, 'admin');
  knownIpsOfHwid(id).forEach(ip => {
    try { addBan(ip, id, reason || 'ban toàn diện theo thiết bị (admin)', name, 'admin'); } catch (_) {}
  });
  kvSaveState();
  adminLog('ban-device-perma', { hwid: id, reason: reason || '', ips: knownIpsOfHwid(id), device: name });
  return true;
}
function enforcePermaDevice(req, res, ip, hwid) {
  if (!hwid || !permaDevices.has(String(hwid))) return false;
  const hid = String(hwid);
  const name = (devices.get(hid) || {}).name || '';
  const newIp = !!(ip && validIpFmt(ip) && !banned.has('ip:' + ip));
  if (newIp) {
    try { addBan(ip, hid, 'thiết bị vĩnh viễn bị khoá (mọi IP)', name, 'admin'); } catch (_) {}
    adminLog('perma-device-block', { ip: ip, hwid: hid, device: name, note: 'ghi nhận IP mới của thiết bị perma' });
  }
  res.status(403).json({
    success: false,
    blocked: true,
    revoked: true,
    permanent: true,
    reason: 'device_perma_banned',
    announce: getAnnouncePayload(),
    message: 'Thiết bị này đã bị khoá vĩnh viễn — mọi mạng/IP đều không sử dụng được script.'
  });
  return true;
}
function hookEnvBlock(req, res) {
  const env = req.body && req.body.env;
  if (!env || typeof env !== 'object') return false;
  const suspicious = !!(env.xhrHooked || env.fetchHooked || env.gmLeak || env.devtools);
  if (!suspicious) return false;
  const hwid = req.body && req.body.hwid;
  if (realMobileReq(req, hwid)) {
    adminLog('hook-soft-mobile', { ip: getClientIp(req), hwid: hwid, env: env, note: 'mobile that -> chi log' });
    return false;
  }
  const ip = getClientIp(req);
  const already = !!(ip && banned.has('ip:' + ip)) || !!(hwid && banned.has('dev:' + String(hwid)));
  if (!already) {
    addBan(ip, hwid, 'phát hiện hook/gỡ lỗi môi trường (anti-hook)', deviceNameOf(hwid), 'auto');
    adminLog('hook-block', { ip: ip, hwid: hwid, env: env });
  }
  res.status(403).json({
    success: false,
    blocked: true,
    reason: 'hook_env',
    announce: getAnnouncePayload(),
    message: 'Phát hiện công cụ hook/gỡ lỗi trang — môi trường không được phép sử dụng script.'
  });
  return true;
}
function enforceDumpPermanent(req, res, key, hwid, ip, reason, deviceName) {
  if (realMobileReq(req, hwid)) {
    adminLog('dump-soft-mobile', { key: maskKey(key), hwid: hwid, ip: ip, reason: reason });
    return false;
  }
  addKeyBan(key, reason, ip, hwid, deviceName);
  banDevicePerma(hwid, reason, deviceName);
  res.status(403).json({
    success: false,
    blocked: true,
    revoked: true,
    reason: 'dumper',
    announce: getAnnouncePayload(),
    message: 'Phát hiện hành vi dump/tải file cấu hình — thiết bị và key đã bị khoá vĩnh viễn.'
  });
  return true;
}
function isKeyBanned(key) {
  return key ? BANNED_KEYS.has(String(key).trim().toUpperCase()) : false;
}
function addKeyBan(key, reason, ip, hwid, deviceName) {
  if (!key) return false;
  const k = String(key).trim().toUpperCase();
  if (BANNED_KEYS.has(k)) return false;
  if (SMART_BAN && isRealMobileDevice(ip, hwid, recentUaByIp.get(ip) || '')) {
    adminLog('key-ban-blocked-real', {
      key: maskKey(key),
      reason: reason,
      ip: ip,
      hwid: hwid,
      device: deviceName || '',
      note: 'SMART_BAN: thiet bi di dong that, khong revokle key'
    });
    return false;
  }
  if (!SMART_BAN && SAFE_MODE) {
    adminLog('key-ban-soft', {
      key: maskKey(key),
      reason: reason,
      ip: ip,
      hwid: hwid,
      device: deviceName || '',
      note: 'SAFE_MODE: khong revokle key, chi log'
    });
    return false;
  }
  BANNED_KEYS.add(k);
  kvSaveState();
  addBan(ip, hwid, reason + ' — key bi revokle', deviceName);
  adminLog('key-ban', {
    key: maskKey(key),
    reason: reason,
    ip: ip,
    hwid: hwid,
    device: deviceName || ''
  });
  return true;
}
function dumperJudge(key, hwid, ip, deviceName, event) {
  if (!DUMPER_GUARD || !key) return null;
  const r = keyAct(key);
  const now = Date.now();
  if (event === 'attest') {
    if (!r.firstAttestAt) r.firstAttestAt = now;
    return null;
  }
  if (event === 'process') {
    r.processCount++;
    if (r.dumpScore > 0) r.dumpScore = Math.max(0, r.dumpScore - 2);
    return null;
  }
  if (event === 'fire') {
    r.fireCount++;
    r.dumpScore = 0;
    return null;
  }
  if (event === 'heartbeat-zero') {
    if (r.processCount === 0 && r.fireCount === 0) {
      r.hbZeroCount++;
      r.dumpScore += 1;
      if (r.hbZeroCount >= 5) return 'heartbeat zero-version >=5 lan va KHONG co hoat dong process/fire — chi co dumper';
    }
    return null;
  }
  if (event === 'module') {
    r.moduleFetchCount++;
    r.lastModuleAt = now;
    if (r.moduleFetchCount >= 2) return 'lay module truc tiep >=2 lan — nghi dump file';
    if (r.processCount === 0 && r.fireCount === 0) return 'goi /module nhung chua tung process/fire lan nao — dumper khong co hoat dong thuc';
    if (r.firstAttestAt && now - r.firstAttestAt < 1e4) return 'attest -> lay module trong vong <10s, khong co hoat dong thuc — dumper';
    return null;
  }
  if (event === 'code') {
    r.codeCount = (r.codeCount || 0) + 1;
    if (r.processCount === 0 && r.fireCount === 0 && r.codeCount >= 3) return 'lay connector/code nhieu ma khong co process/fire thuc — dump script';
    return null;
  }
  if (event === 'ansfile') {
    r.ansCount = (r.ansCount || 0) + 1;
    if (r.ansCount >= 25) return 'tai/giai file dap an bat thuong >=25 lan — dump kho du lieu';
    return null;
  }
  return null;
}
function watermarkSrc(src, key, hwid) {
  if (!MODULE_WATERMARK || !key) return src;
  const wm = hmacHex('wm:' + String(key).trim().toUpperCase() + ':' + (hwid || '')).slice(0, 16);
  return 'var _tlwm="' + wm + '";\n' + src;
}
const ADMIN_PATH = process.env.ADMIN_PATH || '/login/admin';
function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64');
}
function signSession(payload) {
  const body = b64url(JSON.stringify(payload));
  const sig = b64url(crypto.createHmac('sha256', SECRET).update('sess:' + body).digest());
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
  } catch (_) {
    return null;
  }
}
const SESSION_TTL = 5 * 60 * 1e3;
let ANNOUNCE = { enabled: false, level: 'info', title: '', message: '', updatedAt: 0, by: '' };
function getAnnouncePayload() {
  if (!ANNOUNCE || !ANNOUNCE.enabled || !String(ANNOUNCE.message || '').trim()) return null;
  return {
    level: ANNOUNCE.level || 'info',
    title: ANNOUNCE.title || 'Thông báo',
    message: String(ANNOUNCE.message || ''),
    ts: ANNOUNCE.updatedAt || 0,
    dismissible: ANNOUNCE.level !== 'blocked'
  };
}
const banned = new Map;
const devices = new Map;
let AUTO_BAN = process.env.AUTO_BAN !== 'false';
let MOBILE_ONLY = process.env.MOBILE_ONLY !== 'false';
let BAN_DESKTOP = process.env.BAN_DESKTOP === 'true';
let BLOCK_VM_SCRIPT = process.env.BLOCK_VM_SCRIPT === 'true';
let BLOCK_MODULE_10 = process.env.BLOCK_MODULE_10 !== 'false';
let HARD_DC_BAN = process.env.HARD_DC_BAN === 'true';
let SAFE_MODE = process.env.SAFE_MODE !== 'false';
let SMART_BAN = process.env.SMART_BAN !== 'false';
const realDevices = new Map;
const realIps = new Set;
const recentUaByIp = new Map;
let DUMPER_GUARD = process.env.DUMPER_GUARD !== 'false';
let MODULE_WATERMARK = process.env.MODULE_WATERMARK !== 'false';
const BANNED_KEYS = new Set((process.env.BANNED_KEYS || '').split(',').map(s => String(s).trim().toUpperCase()).filter(Boolean));
const keyActivity = new Map;
const deviceActivity = new Map;
function trackDevice(hwid, data) {
  if (!hwid) return;
  const ex = deviceActivity.get(hwid) || {};
  deviceActivity.set(hwid, Object.assign(ex, data, {
    lastSeen: Date.now()
  }));
}
const olmBans = new Map;
const answerBank = new Map;
const _lookupCache = new Map();
const LOOKUP_CACHE_TTL = 45e3;
const BANK_LIMIT_ITEMS = 2500;
const BANK_LIMIT_ENTRIES = 2000;
const bankTombstones = new Map();
const BANK_TOMB_TTL = 30 * 24 * 3600 * 1e3;
function tombMark(scope, id) { if (id == null || id === '') return; bankTombstones.set(scope + '::' + String(id), Date.now()); }
function tombHas(scope, id) { if (id == null || id === '') return false; const t = bankTombstones.get(scope + '::' + String(id)); return !!t && (Date.now() - t < BANK_TOMB_TTL); }
function applyBankTombstones() {
  try {
    const now = Date.now();
    for (const [k, t] of bankTombstones) if (now - t > BANK_TOMB_TTL) bankTombstones.delete(k);
    if (bankTombstones.has('subject::*')) { answerBank.clear(); return; }
    for (const [key, e] of [...answerBank.entries()]) {
      if (!e) continue;
      if (tombHas('subject', key) || (e.cate && tombHas('subject', 'cate::' + e.cate)) || (e.canon && tombHas('subject', 'canon::' + e.canon))) { answerBank.delete(key); continue; }
      if (Array.isArray(e.exercises)) {
        const before = e.exercises.length;
        e.exercises = e.exercises.filter(ex => ex && !tombHas('exercise', ex.key));
        if (e.exercises.length !== before) migrateBankEntry(e);
        if (!e.exercises.length && !(e.items || []).length) answerBank.delete(key);
      }
    }
  } catch (_) {}
}
function bankCateKey(meta) {
  return String((meta && meta.id_cate) || (meta && meta.subject_name) || 'none');
}
function normBankText(s) {
  return String(s == null ? '' : s).toLowerCase()
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .replace(/đ/g, 'd').replace(/[^a-z0-9\s]/g, ' ').replace(/\s+/g, ' ').trim();
}
function numHits(v) {
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return Math.min(Math.floor(n), 1e7);
}
function sanitizeBankHits() {
  try {
    for (const e of answerBank.values()) {
      if (!e) continue;
      e.hits = numHits(e.hits);
      if (Array.isArray(e.exercises)) e.exercises.forEach(ex => { if (ex) ex.hits = numHits(ex.hits); });
    }
  } catch (_) {}
}
const SUBJECT_RULES = [
  { key: 'dia-ly',    label: 'Địa lý',                                     words: ['dia ly', 'dia li', 'địa lý', 'địa lí', 'vi tri dia ly', 'khu vuc dong nam a'] },
  { key: 'ngu-van',   label: 'Ngữ văn',                                     words: ['ngu van', 'ngữ văn', 'loi tien dan', 'tien dan'] },
  { key: 'toan',      label: 'Toán',                                       words: ['toan hoc', 'toan', 'dai so', 'hinh hoc'] },
  { key: 'tieng-anh', label: 'Tiếng Anh',                                  words: ['tieng anh', 'tiếng anh', 'english', 'pronunciation', 'practice pronunciation'] },
  { key: 'gd-kpl',    label: 'Kinh tế Pháp luật (Giáo dục kinh tế và pháp luật)',       words: ['kinh doanh', 'phap luat', 'pháp luật', 'kinh te', 'giao duc kinh te', 'co hoi kinh doanh', 'y tuong kinh doanh', 'nang luc can thiet cua nguoi kinh doanh', 'nang luc nguoi kinh doanh', 'khoi nghiep'] },
  { key: 'lich-su',   label: 'Lịch sử',                                     words: ['lich su', 'lịch sử', 'su thoi dai'] },
  { key: 'sinh-hoc',  label: 'Sinh học',                                   words: ['sinh hoc', 'sinh học', 'sinh vat', 'di truyen'] },
  { key: 'vat-ly',    label: 'Vật lý',                                     words: ['vat ly', 'vat li', 'vật lý', 'vật lí', 'dòng điện', 'nhiet hoc'] },
  { key: 'hoa-hoc',   label: 'Hóa học',                                    words: ['hoa hoc', 'hóa học', 'phan ung hoa hoc'] },
  { key: 'cong-nghe', label: 'Công nghệ',                                  words: ['cong nghe', 'công nghệ', 'ky thuat', 'kỹ thuật', 'cong nghiep', 'công nghiệp', 'che tao', 'chế tạo', 'may moc', 'máy móc', 'dien tu', 'điện tử', 'nong nghiep', 'nông nghiệp'] },
  { key: 'the-duc',   label: 'Thể dục',                                     words: ['the duc', 'thể dục', 'the chat'] },
  { key: 'my-thuat',  label: 'Mỹ thuật',                                    words: ['my thuat', 'mỹ thuật', 'my hoa'] },
  { key: 'ngoai-ngu', label: 'Ngoại ngữ',                                   words: ['ngoai ngu', 'ngoại ngữ', 'tieng nhat', 'tieng han', 'tieng phap', 'tieng trung'] },
  { key: 'tin-hoc',   label: 'Tin học',                                     words: ['tin hoc', 'tin học', 'lap trinh'] },
  { key: 'dia-phuong', label: 'Địa phương',                                 words: ['dia phuong', 'địa phương'] }
];
const CANON_PRIORITY_KEYS = ['cong-nghe','vat-ly','hoa-hoc','sinh-hoc','tin-hoc','ngoai-ngu','toan','tieng-anh','ngu-van','lich-su','dia-ly','gd-kpl','the-duc','my-thuat','dia-phuong'];
function canonSubject(rawName, rawHint) {
  const nameFlat = normBankText(rawName);
  const scanRule = (flat, words) => words.some(w => { const wf = normBankText(w); return wf && (flat === wf || flat.indexOf(wf) !== -1); });
  const _hintEarly = normBankText(rawHint);
  if (
    _hintEarly.indexOf('nang luc can thiet cua nguoi kinh doanh') !== -1 ||
    (_hintEarly.indexOf('co hoi kinh doanh') !== -1 && _hintEarly.indexOf('y tuong') !== -1)
  ) {
    return { key: 'gd-kpl', label: ruleLabelByKey('gd-kpl') };
  }
  if (nameFlat.trim()) {
    for (const r of SUBJECT_RULES) { if (scanRule(nameFlat, r.words)) return { key: r.key, label: r.label }; }
  }
  let hintFlat = normBankText(rawHint);
  const DROP_IN_HINT = ['kinh te'];
  for (const w of DROP_IN_HINT) { const wf = normBankText(w); if (wf) hintFlat = hintFlat.split(wf).join(' '); }
  hintFlat = normBankText(hintFlat);
  if (hintFlat.trim()) {
    for (const key of CANON_PRIORITY_KEYS) {
      const r = SUBJECT_RULES.find(x => x.key === key);
      if (r && scanRule(hintFlat, r.words)) return { key: r.key, label: r.label };
    }
  }
  if (nameFlat.trim()) return { key: 'raw::' + nameFlat.slice(0, 60), label: String(rawName || '').trim() };
  return { key: '', label: '' };
}
function ruleLabelByKey(key) {
  const r = SUBJECT_RULES.find(x => x.key === key);
  return r ? r.label : '';
}
function entryCanon(e) {
  if (e && e.canon) return String(e.canon);
  if (e && e.subject) return canonSubject(e.subject, '').key || '';
  return '';
}
function bankSubjectDisplay(entry) {
  if (entry && entry.canon) { const lab = ruleLabelByKey(entry.canon); if (lab) return lab; }
  if (entry && entry.subject) return String(entry.subject);
  if (entry && entry.cate) return 'Môn ' + String(entry.cate);
  return 'Chưa rõ môn';
}
function rebuildFlatItems(entry) {
  const all = [];
  const _seen = new Set();
  (entry.exercises || []).forEach(ex => { (ex.items || []).forEach(it => {
    if (!it) return;
    const q = String(it.qid || ('idx_' + it.index));
    if (_seen.has(q)) return;
    _seen.add(q);
    all.push(it);
  }); });
  entry.items = all.slice(0, BANK_LIMIT_ITEMS);
  entry.count = entry.items.length;
}
function migrateBankEntry(entry) {
  if (!entry || typeof entry !== 'object') return;
  if (!Array.isArray(entry.exercises)) {
    const oldItems = Array.isArray(entry.items) ? entry.items.slice() : [];
    entry.exercises = [{
      key: 'legacy::' + (entry.cate || entry.key || 'x'),
      title: 'Bài tập cũ (chưa rõ tên)',
      cate: entry.cate || null,
      courseware: entry.courseware || null,
      items: oldItems,
      count: oldItems.length,
      hits: numHits(entry.hits),
      created_at: entry.created_at || Date.now(),
      updated_at: entry.updated_at || Date.now()
    }];
  }
  entry.exercises.forEach(ex => { if (!Array.isArray(ex.items)) ex.items = []; ex.count = ex.items.length; ex.hits = numHits(ex.hits); });
  rebuildFlatItems(entry);
  if (typeof entry.subject !== 'string') entry.subject = '';
}
function mergeBankEntries(dst, src) {
  if (!dst || !src || dst === src) return dst;
  migrateBankEntry(dst);
  migrateBankEntry(src);
  (src.exercises || []).forEach(ex => {
    if (!ex) return;
    let old = (dst.exercises || []).find(x => x && x.key === ex.key);
    if (!old && ex.courseware) old = (dst.exercises || []).find(x => x && x.courseware && String(x.courseware) === String(ex.courseware));
    if (!old) { if ((ex.items || []).length) dst.exercises.push(ex); return; }
    const byQ = new Map((old.items || []).map(it => [String(it.qid || ('idx_' + it.index)), it]));
    (ex.items || []).forEach(it => { if (it) byQ.set(String(it.qid || ('idx_' + it.index)), it); });
    old.items = Array.from(byQ.values());
    old.count = old.items.length;
    old.updated_at = Math.max(old.updated_at || 0, ex.updated_at || 0);
    old.hits = numHits(old.hits) + numHits(ex.hits);
    if ((ex.title || '').length > (old.title || '').length) old.title = ex.title;
    if (ex.courseware && !old.courseware) old.courseware = ex.courseware;
    if (ex.cate && !old.cate) old.cate = ex.cate;
  });
  const byQFlat = new Map((dst.items || []).map(it => [String(it.qid || ('idx_' + it.index)), it]));
  (src.items || []).forEach(it => { if (it && it.qid) byQFlat.set(String(it.qid), it); });
  dst.items = Array.from(byQFlat.values());
  rebuildFlatItems(dst);
  if (src.subject && (!dst.subject || String(src.subject).length > String(dst.subject).length)) dst.subject = src.subject;
  if (src.canon && !dst.canon) dst.canon = src.canon;
  if (dst.canon && ruleLabelByKey(dst.canon)) dst.subject = ruleLabelByKey(dst.canon);
  dst.cate = dst.cate || src.cate || null;
  dst.hits = numHits(dst.hits) + numHits(src.hits);
  dst.updated_at = Math.max(dst.updated_at || 0, src.updated_at || 0);
  if (src.olm_user && !dst.olm_user) dst.olm_user = src.olm_user;
  (src.sources || []).forEach(s => { if (dst.sources.indexOf(s) === -1) dst.sources.push(s); });
  return dst;
}
function dedupeExerciseList(exList) {
  const out = [];
  const byKey = new Map();
  (exList || []).forEach(ex => {
    if (!ex) return;
    const cw = ex.courseware ? String(ex.courseware) : '';
    const normTitle = normBankText(ex.title);
    const dkey = cw ? ('cw::' + cw) : (ex.key ? ('ex::' + ex.key) : ('t::' + normTitle));
    const old = byKey.get(dkey);
    if (!old) { byKey.set(dkey, ex); out.push(ex); return; }
    const byQ = new Map((old.items || []).map(it => [String(it.qid || ('idx_' + it.index)), it]));
    (ex.items || []).forEach(it => { if (it) byQ.set(String(it.qid || ('idx_' + it.index)), it); });
    old.items = Array.from(byQ.values());
    old.count = old.items.length;
    old.hits = numHits(old.hits) + numHits(ex.hits);
    old.updated_at = Math.max(old.updated_at || 0, ex.updated_at || 0);
    if ((ex.title || '').length > (old.title || '').length) old.title = ex.title;
    if (ex.courseware && !old.courseware) old.courseware = ex.courseware;
    if (ex.cate && !old.cate) old.cate = ex.cate;
  });
  return out;
}
function _coalesceMap(mp) {
  try {
    const groups = new Map();
    for (const [key, e] of mp) {
      if (!e) continue;
      migrateBankEntry(e);
      const ck = entryCanon(e);
      const sn = ck || normBankText(e.subject);
      if (!sn) continue;
      if (!groups.has(sn)) groups.set(sn, []);
      groups.get(sn).push(key);
    }
    for (const [, keys] of groups) {
      if (keys.length < 2) continue;
      keys.sort((a, b) => {
        const sa = mp.get(a), sb = mp.get(b);
        const score = e => (e && e.cate ? 2 : 0) + ((e && e.exercises) || []).length;
        return score(sb) - score(sa);
      });
      const dst = mp.get(keys[0]);
      keys.slice(1).forEach(k => {
        mergeBankEntries(dst, mp.get(k));
        mp.delete(k);
      });
      rebuildFlatItems(dst);
    }
  } catch (_) {}
}
function coalesceBankSubjects() { _coalesceMap(answerBank); }
function reclassifyBank() {
  try {
    const CN_RE = /(cong nghe|cong nghiep|ky thuat|che tao|may moc|dien tu|nong nghiep)/;
    for (const e of answerBank.values()) {
      if (!e) continue;
      if (e.canon === 'gd-kpl') continue;
      const titles = (e.exercises || []).map(ex => ex.title || '').join(' ') + ' ' + (e.subject || '');
      const flatTitles = normBankText(titles);
      if (!CN_RE.test(flatTitles)) continue;
      if (flatTitles.indexOf('co hoi kinh doanh') !== -1 || flatTitles.indexOf('nang luc can thiet cua nguoi kinh doanh') !== -1) continue;
      const c = canonSubject('', titles);
      if (c.key === 'cong-nghe') {
        e.canon = 'cong-nghe';
        e.subject = ruleLabelByKey('cong-nghe') || 'Công nghệ';
      }
    }
  } catch (_) {}
}
function exerciseKeyOf(meta, title) {
  const subj = normBankText((meta && meta.subject_name) || (meta && meta.id_cate) || 'mon') || 'mon';
  const t = normBankText(title) || 'bai-tap-chua-ro-ten';
  return subj.slice(0, 40) + '::' + t.slice(0, 140);
}
function bankUpsert(meta, processed, sourceKey, olmUser) {
  try {
    meta = meta || {};
    let key = bankCateKey(meta);
    let createdNew = false;
    const subjectName = safeStr(meta.subject_name, 120);
    const exerciseTitle = safeStr(meta.exercise_title, 300);
    const hintText = exerciseTitle + ' ' + (processed || []).slice(0, 15).map(p => p.stem || p.title || '').join(' ');
    const _can = canonSubject(subjectName, hintText);
    if ((!key || key === 'none') && _can.key) key = 'canon::' + _can.key;
    const subjNorm = normBankText(_can.label || subjectName);
    let entry = answerBank.get(key) || null;
    if (!entry && _can.key) entry = [...answerBank.values()].find(e => e && entryCanon(e) === _can.key) || null;
    if (!entry && subjNorm) entry = [...answerBank.values()].find(e => e && normBankText(e.subject) === subjNorm) || null;
    if (!entry) {
      if (tombHas('subject', key) || (meta.id_cate && tombHas('subject', 'cate::' + meta.id_cate)) || (_can.key && tombHas('subject', 'canon::' + _can.key))) return;
      if (answerBank.size >= BANK_LIMIT_ENTRIES) {
        let lruKey = null, lruAt = Infinity;
        for (const [k, v] of answerBank) { const empty = (!v || !(v.items || []).length && !(v.exercises || []).length); if (!empty) continue; const u = (v && v.updated_at) || 0; if (u < lruAt) { lruAt = u; lruKey = k; } }
        if (lruKey) answerBank.delete(lruKey);
      }
      entry = { key: key, cate: meta.id_cate || null, courseware: meta.id_courseware || null, canon: _can.key || '', subject: _can.label || subjectName, exercises: [], items: [], count: 0, hits: 0, sources: [], created_at: Date.now(), updated_at: Date.now() };
      answerBank.set(key, entry);
      createdNew = true;
    }
    migrateBankEntry(entry);
    if (_can.key) entry.canon = entry.canon || _can.key;
    const _dispLabel = (_can.key && ruleLabelByKey(_can.key)) || _can.label || subjectName;
    if (_dispLabel && (!entry.subject || entry.subject.length < _dispLabel.length)) entry.subject = _dispLabel;
    const valid = (processed || []).filter(p => Array.isArray(p.answers) && p.answers.some(a => a && a !== 'Lỗi giải mã' && a !== 'Không tự động trích xuất được.' && a !== 'Dữ liệu câu hỏi quá lớn — bỏ qua'));
    if (!valid.length) {
      if (createdNew) { answerBank.delete(key); }
      return;
    }
    const exKey = exerciseKeyOf(meta, exerciseTitle);
    let ex = (entry.exercises || []).find(x => x && x.key === exKey);
    if (!ex && meta.id_courseware) ex = (entry.exercises || []).find(x => x && x.courseware && String(x.courseware) === String(meta.id_courseware)) || null;
    if (!ex) {
      if (tombHas('exercise', exKey)) return;
      ex = { key: exKey, title: exerciseTitle || 'Bài tập chưa rõ tên', cate: meta.id_cate || null, courseware: meta.id_courseware || null, items: [], count: 0, hits: 0, created_at: Date.now(), updated_at: Date.now() };
      entry.exercises.push(ex);
    } else if (ex.key !== exKey) {
      ex.key = exKey;
    }
    if (exerciseTitle) ex.title = exerciseTitle;
    if (meta.id_courseware) ex.courseware = meta.id_courseware;
    if (meta.id_cate) ex.cate = meta.id_cate;
    const byQid = new Map((ex.items || []).map(it => [String(it.qid || ('idx_' + it.index)), it]));
    valid.forEach(p => {
      const qid = String(p.id || ('idx_' + p.index));
      const clean = (p.answers || []).map(a => safeStr(a, 300)).filter(x => x && x !== 'Lỗi giải mã' && x !== 'Không tự động trích xuất được.').slice(0, 8);
      if (!clean.length) return;
      const stem = safeStr(p.stem || '', 600);
      const title = safeStr(p.title, 300) || stem || ('Câu ' + p.index);
      byQid.set(qid, { qid: qid, index: p.index, title: title, stem: stem, answers: clean });
    });
    ex.items = Array.from(byQid.values()).slice(0, BANK_LIMIT_ITEMS);
    ex.count = ex.items.length;
    ex.updated_at = Date.now();
    rebuildFlatItems(entry);
    if (createdNew && entry.items.length === 0 && (entry.exercises || []).length === 0) { answerBank.delete(key); return; }
    if (olmUser) entry.olm_user = String(olmUser).slice(0, 80);
    if (meta.id_cate) entry.cate = meta.id_cate;
    if (meta.id_courseware) entry.courseware = meta.id_courseware;
    coalesceBankSubjects();
    reclassifyBank();
    coalesceBankSubjects();
    _lookupCache.clear();
    entry.updated_at = Date.now();
    if (sourceKey && entry.sources.indexOf(maskKey(sourceKey)) === -1) entry.sources.push(maskKey(sourceKey));
  } catch (_) {}
}
const SEED_GDKPL_EXERCISE = {
  key: 'gd-kpl::y-tuong-co-hoi-kinh-doanh-va-nang-luc-can-thiet-cua-nguoi-kinh-doanh',
  title: 'Bài 6: Ý tưởng, cơ hội kinh doanh và các năng lực cần thiết của người kinh doanh',
  cate: '3846568215',
  courseware: '119409073446'
};
const SEED_GDKPL_ITEMS = [
  { index: 1, qid: 'seed-gdkpl-1', title: 'Khái niệm ý tưởng kinh doanh', stem: 'Khái niệm trong lĩnh vực kinh doanh chỉ loại ý tưởng có tính sáng tạo, khả thi mang đến lợi nhuận trong hoạt động kinh doanh là ý tưởng kinh doanh, cơ hội kinh doanh, lợi nhuận kinh doanh, cổ tức kinh doanh.', answers: ['ý tưởng kinh doanh'] },
  { index: 2, qid: 'seed-gdkpl-2', title: 'Yếu tố lợi thế nội tại', stem: 'Ý tưởng kinh doanh xuất phát từ đam mê, hiểu biết, khả năng huy động các nguồn lực sẵn có (thời gian, tiền bạc, kinh nghiệm, mối quan hệ) của chủ thể kinh doanh được gọi là lợi thế nội tại.', answers: ['lợi thế nội tại'] },
  { index: 3, qid: 'seed-gdkpl-3', title: 'Cơ hội bên ngoài', stem: 'Ý tưởng kinh doanh bắt nguồn từ một nhu cầu mới chưa được đáp ứng hoặc lợi thế cạnh tranh, thuận lợi về vị trí triển khai hay thuận lợi từ một chính sách vĩ mô được gọi là cơ hội bên ngoài.', answers: ['cơ hội bên ngoài'] },
  { index: 4, qid: 'seed-gdkpl-4', title: 'Anh A đam mê giày da', stem: 'Anh A đam mê giày da, hiểu biết các hãng giày lớn, quyết định mở cửa hàng giày da ở quê hương. Ý tưởng kinh doanh của anh A xuất phát từ lợi thế nội tại.', answers: ['lợi thế nội tại'] },
  { index: 5, qid: 'seed-gdkpl-5', title: 'Chị D mở cửa hàng rau sạch', stem: 'Chị D nhận thấy nhiều khách hàng có nhu cầu mua đồ ăn sạch, rau an toàn, chị quyết định mở cửa hàng rau sạch, thực phẩm sạch. Ý tưởng kinh doanh của chị D xuất phát từ cơ hội bên ngoài.', answers: ['cơ hội bên ngoài'] }
];
function seedGdKplBank() {
  try {
    if (tombHas('subject', 'canon::gd-kpl')) return;
    let entry = answerBank.get('canon::gd-kpl')
      || [...answerBank.values()].find(e => e && entryCanon(e) === 'gd-kpl') || null;
    if (!entry) {
      entry = { key: 'canon::gd-kpl', cate: null, courseware: null, canon: 'gd-kpl', subject: ruleLabelByKey('gd-kpl'), exercises: [], items: [], count: 0, hits: 0, sources: ['seed-v31'], created_at: Date.now(), updated_at: Date.now() };
      answerBank.set('canon::gd-kpl', entry);
    }
    migrateBankEntry(entry);
    entry.canon = 'gd-kpl';
    entry.subject = ruleLabelByKey('gd-kpl');
    const s = SEED_GDKPL_EXERCISE;
    if (tombHas('exercise', s.key)) return;
    let ex = entry.exercises.find(x => x && x.key === s.key)
      || entry.exercises.find(x => x && normBankText(x.title).indexOf('co hoi kinh doanh') !== -1) || null;
    if (!ex) {
      ex = { key: s.key, title: s.title, cate: s.cate, courseware: s.courseware, items: [], count: 0, hits: 0, created_at: Date.now(), updated_at: Date.now() };
      entry.exercises.push(ex);
    }
    if (s.title) ex.title = s.title;
    if (s.cate && !ex.cate) ex.cate = s.cate;
    if (s.courseware && !ex.courseware) ex.courseware = s.courseware;
    const byQid = new Map((ex.items || []).map(it => [String(it.qid), it]));
    SEED_GDKPL_ITEMS.forEach(p => {
      if (!byQid.has(p.qid)) byQid.set(p.qid, { qid: p.qid, index: p.index, title: p.title, stem: p.stem, answers: p.answers.slice(0, 8) });
    });
    ex.items = Array.from(byQid.values());
    ex.count = ex.items.length;
    ex.updated_at = Date.now();
    rebuildFlatItems(entry);
    coalesceBankSubjects();
  } catch (_) {}
}
const lockedScripts = new Map;
try {
  (process.env.BANNED_LIST || '').split(',').map(s => s.trim()).filter(Boolean).forEach(k => {
    const key = k.includes(':') ? k : 'ip:' + k;
    banned.set(key, {
      reason: 'seed-env',
      device: '',
      t: Date.now(),
      by: 'env'
    });
  });
} catch (_) {}
const KV_URL = process.env.KV_REST_API_URL;
const KV_TOKEN = process.env.KV_REST_API_TOKEN;
const KV_ENABLED = !!(KV_URL && KV_TOKEN);
const KV_KEY = 'godmode_v4_state';
const KV_LOG_KEY = 'godmode_v4_logs';
function kvRequest(path) {
  return new Promise(resolve => {
    if (!KV_ENABLED) return resolve(null);
    const url = KV_URL.replace(/\/$/, '') + path;
    const u = new URL(url);
    const req = https.get({
      hostname: u.hostname,
      port: u.port || 443,
      path: u.pathname + u.search,
      headers: {
        Authorization: 'Bearer ' + KV_TOKEN
      },
      timeout: 4e3
    }, r => {
      let raw = '';
      r.on('data', c => raw += c);
      r.on('end', () => {
        try {
          resolve(JSON.parse(raw));
        } catch (_) {
          resolve(null);
        }
      });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => {
      req.destroy();
      resolve(null);
    });
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
      if (st && st.secret) {
        SECRET = st.secret;
        API_PREFIX = computeApiPrefix(SECRET);
      }
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
      if (st && Array.isArray(st.permaDevices)) st.permaDevices.forEach(k => permaDevices.add(String(k)));
      if (st && st.announce && typeof st.announce === 'object') ANNOUNCE = Object.assign({ enabled:false, level:'info', title:'', message:'', updatedAt:0, by:'' }, st.announce);
      if (st && st.olmBans) for (const [k, v] of Object.entries(st.olmBans)) olmBans.set(String(k).toLowerCase(), v);
      if (st && st.bankTombstones) for (const [k, t] of Object.entries(st.bankTombstones)) bankTombstones.set(k, Number(t) || Date.now());
      if (st && st.answers) {
        for (const [k, v] of Object.entries(st.answers)) {
          if (!v || typeof v !== 'object') continue;
          migrateBankEntry(v);
          v.hits = numHits(v.hits);
          if (Array.isArray(v.exercises)) v.exercises.forEach(ex => { if (ex) ex.hits = numHits(ex.hits); });
          const normKey = String(v.cate || String(k).split('::')[0] || 'none');
          const existing = answerBank.get(normKey);
          if (!existing) { v.key = normKey; answerBank.set(normKey, v); continue; }
          migrateBankEntry(existing);
          (v.exercises || []).forEach(ex => {
            const old = existing.exercises.find(x => x.key === ex.key);
            if (!old) { existing.exercises.push(ex); return; }
            const byQ = new Map((old.items || []).map(it => [String(it.qid || ('idx_' + it.index)), it]));
            (ex.items || []).forEach(it => { if (it) byQ.set(String(it.qid || ('idx_' + it.index)), it); });
            old.items = Array.from(byQ.values());
            old.count = old.items.length;
            old.updated_at = Math.max(old.updated_at || 0, ex.updated_at || 0);
            old.hits = numHits(old.hits) + numHits(ex.hits);
          });
          const byQFlat = new Map((existing.items || []).map(it => [String(it.qid || ('idx_' + it.index)), it]));
          (v.items || []).forEach(it => { if (it && it.qid) byQFlat.set(String(it.qid), it); });
          existing.items = Array.from(byQFlat.values());
          existing.count = existing.items.length;
          if (v.subject && (!existing.subject || existing.subject.length < v.subject.length)) existing.subject = v.subject;
          existing.updated_at = Math.max(existing.updated_at || 0, v.updated_at || 0);
          rebuildFlatItems(existing);
        }
        for (const e of answerBank.values()) { if (!e.canon) { const c = canonSubject(e.subject, ''); e.canon = c.key || ''; } }
        applyBankTombstones();
        coalesceBankSubjects();
        reclassifyBank();
        coalesceBankSubjects();
        seedGdKplBank();
        scheduleBankSave();
      }
    }
  } catch (_) {}
}
let _bankSaveTimer = null;
function scheduleBankSave() {
  if (_bankSaveTimer) clearTimeout(_bankSaveTimer);
  _bankSaveTimer = setTimeout(() => {
    _bankSaveTimer = null;
    if (KV_ENABLED) kvSaveState().catch(() => {});
    else bankFileSave();
  }, 3500);
}
async function kvSaveState() {
  if (!KV_ENABLED) { bankFileSave(); return; }
  try {
    let remote = null;
    try { const r = await kvRequest('/get/' + KV_KEY); if (r && r.result) remote = JSON.parse(Buffer.from(r.result, 'base64').toString()); } catch (_) {}
    const merged = new Map();
    const ingest = (obj) => {
      for (const [k, v] of Object.entries(obj || {})) {
        if (!v || typeof v !== 'object') continue;
        migrateBankEntry(v); v.key = k;
    v.hits = numHits(v.hits);
    if (Array.isArray(v.exercises)) v.exercises.forEach(ex => { if (ex) ex.hits = numHits(ex.hits); });
        const old = merged.get(k);
        if (!old) merged.set(k, v); else mergeBankEntries(old, v);
      }
    };
    if (remote && remote.answers) ingest(remote.answers);
    ingest(Object.fromEntries(answerBank));
    for (const [k, t] of bankTombstones) if (Date.now() - t > BANK_TOMB_TTL) bankTombstones.delete(k);
    if (bankTombstones.has('subject::*')) merged.clear();
    for (const [key, e] of [...merged.entries()]) {
      if (!e) continue;
      if (bankTombstones.has('subject::*')) break;
      if (tombHas('subject', key) || (e.cate && tombHas('subject', 'cate::' + e.cate)) || (e.canon && tombHas('subject', 'canon::' + e.canon))) { merged.delete(key); continue; }
      if (Array.isArray(e.exercises)) {
        e.exercises = e.exercises.filter(ex => ex && !tombHas('exercise', ex.key));
        migrateBankEntry(e);
        if (!e.exercises.length && !(e.items || []).length) merged.delete(key);
      }
    }
    _coalesceMap(merged);
    const st = {
      bans: Object.fromEntries(banned),
      devices: Object.fromEntries(devices),
      lockedScripts: Object.fromEntries(lockedScripts),
      autoBan: AUTO_BAN,
      mobileOnly: MOBILE_ONLY,
      banDesktop: BAN_DESKTOP,
      blockVmScript: BLOCK_VM_SCRIPT,
      blockModule10: BLOCK_MODULE_10,
      hardDcBan: HARD_DC_BAN,
      dumperGuard: DUMPER_GUARD,
      moduleWatermark: MODULE_WATERMARK,
      safeMode: SAFE_MODE,
      smartBan: SMART_BAN,
      realDevices: Object.fromEntries(realDevices),
      realIps: Array.from(realIps),
      bannedKeys: Array.from(BANNED_KEYS),
      permaDevices: Array.from(permaDevices),
      announce: ANNOUNCE,
      olmBans: Object.fromEntries(olmBans),
      answers: Object.fromEntries(merged),
      bankTombstones: Object.fromEntries(bankTombstones),
      adminHash: ADMIN_HASH,
      adminUser: ADMIN_USER,
      secret: SECRET,
      t: Date.now()
    };
    const val = Buffer.from(JSON.stringify(st)).toString('base64');
    await kvRequest('/set/' + KV_KEY + '/' + encodeURIComponent(val));
    kvSaveLogs().catch(() => {});
  } catch (_) {}
}
const BANK_FILE = process.env.BANK_FILE || path.join(__dirname, 'godmode_bank.json');
let BANK_FILE_OK = false;
function ingestBankObject(obj, target) {
  for (const [k, v] of Object.entries(obj || {})) {
    if (!v || typeof v !== 'object') continue;
    migrateBankEntry(v); v.key = k;
    v.hits = numHits(v.hits);
    if (Array.isArray(v.exercises)) v.exercises.forEach(ex => { if (ex) ex.hits = numHits(ex.hits); });
    const old = target.get(k);
    if (!old) { target.set(k, v); continue; }
    migrateBankEntry(old);
    mergeBankEntries(old, v);
  }
}
function filterBankByTombstones(mp) {
  for (const [key, e] of [...mp.entries()]) {
    if (!e) continue;
    if (tombHas('subject', key) || (e.cate && tombHas('subject', 'cate::' + e.cate)) || (e.canon && tombHas('subject', 'canon::' + e.canon))) { mp.delete(key); continue; }
    if (Array.isArray(e.exercises)) {
      e.exercises = e.exercises.filter(ex => ex && !tombHas('exercise', ex.key));
      migrateBankEntry(e);
      if (!e.exercises.length && !(e.items || []).length) mp.delete(key);
    }
  }
}
function bankFileLoad() {
  if (KV_ENABLED) return;
  try {
    if (!fs.existsSync(BANK_FILE)) return;
    const st = JSON.parse(fs.readFileSync(BANK_FILE, 'utf8'));
    if (st && st.bankTombstones) for (const [k, t] of Object.entries(st.bankTombstones)) bankTombstones.set(k, Number(t) || Date.now());
    if (st && st.answers) {
      ingestBankObject(st.answers, answerBank);
      for (const e of answerBank.values()) { if (!e.canon) { const c = canonSubject(e.subject, ''); e.canon = c.key || ''; } }
      applyBankTombstones();
      coalesceBankSubjects();
      reclassifyBank();
      coalesceBankSubjects();
      seedGdKplBank();
      scheduleBankSave();
    }
    BANK_FILE_OK = true;
  } catch (_) { BANK_FILE_OK = false; }
}
function bankFileSave() {
  if (KV_ENABLED) return;
  try {
    const merged = new Map();
    ingestBankObject(Object.fromEntries(answerBank), merged);
    for (const [k, t] of bankTombstones) if (Date.now() - t > BANK_TOMB_TTL) bankTombstones.delete(k);
    if (bankTombstones.has('subject::*')) merged.clear(); else filterBankByTombstones(merged);
    _coalesceMap(merged);
    const st = { answers: Object.fromEntries(merged), bankTombstones: Object.fromEntries(bankTombstones), t: Date.now() };
    const tmp = BANK_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(st));
    fs.renameSync(tmp, BANK_FILE);
    BANK_FILE_OK = true;
  } catch (_) { BANK_FILE_OK = false; }
}
let kvLoaded = false;
let kvLoadPromise = null;
function ensureKvLoaded() {
  if (!KV_ENABLED) return Promise.resolve();
  if (kvLoaded) return Promise.resolve();
  if (!kvLoadPromise) {
    kvLoadPromise = kvLoadState().then(() => {
      kvLoaded = true;
    });
  }
  return kvLoadPromise;
}
ensureKvLoaded();
bankFileLoad();
seedGdKplBank();
sanitizeBankHits();
function getBanRecord(ip, hwid) {
  if (ip && validIpFmt(ip) && banned.has('ip:' + ip)) return banned.get('ip:' + ip);
  if (hwid && validHwid(hwid) && banned.has('dev:' + String(hwid))) return banned.get('dev:' + String(hwid));
  return null;
}
function isBanned(ip, hwid) {
  return getBanRecord(ip, hwid);
}
function isAdminBan(rec) {
  return !!(rec && rec.by === 'admin');
}
function isRealMobileDevice(ip, hwid, uaHeader) {
  if (!SMART_BAN) return false;
  const ua = String(uaHeader || '').toLowerCase();
  if (/android|iphone|ipad|ipod|crios|fxios|focus|userscripts|harmonyos|webview|wv\)/.test(ua)) return true;
  if (hwid && realDevices.has(String(hwid))) return true;
  if (ip && realIps.has(ip)) return true;
  if (ip) {
    for (const v of realDevices.values()) if (v.ip === ip) return true;
  }
  return false;
}
function uaIsMobile(uaHeader) {
  return /android|iphone|ipad|ipod|harmonyos|huawei|honor|oppo|vivo|xiaomi|redmi|realme|samsung|crios|fxios|mobile safari|wv\)|webview|mobi/i.test(String(uaHeader || '').toLowerCase());
}
function isIosUa(uaHeader) {
  const ua = String(uaHeader || '').toLowerCase();
  if (!ua) return false;
  const looksIos = /iphone|ipad|ipod|crios|fxios|focus|userscripts|wkbrowser|mobile\/\d|applecoremedia/.test(ua);
  if (!looksIos) return false;
  if (/webdriver|headlesschrome|puppeteer|playwright|selenium|electron|phantomjs|node-fetch|undici|curl|python-requests|python-httpx|python-urllib|aiohttp|okhttp|scrapy|bot\/|headless\b/i.test(ua)) return false;
  return true;
}
function isIosReq(req) { return !!(req && req.headers && isIosUa(req.headers['user-agent'])); }
function realMobileReq(req, hwid) {
  const ua = req && req.headers ? req.headers['user-agent'] : '';
  if (isIosUa(ua) || uaIsMobile(ua) || isMobileUA(ua)) return true;
  if (hwid && realDevices.has(String(hwid))) return true;
  const ip = req ? getClientIp(req) : '';
  if (ip && realIps.has(ip)) return true;
  return false;
}
function reqBypass(req, hwid) {
  try {
    if (isIosReq(req)) return true;
    if (realMobileReq(req, hwid)) return true;
  } catch (_) {}
  return false;
}
function guardBanned(req, res, ip, hwid, label) {
  if (enforcePermaDevice(req, res, ip, hwid)) return true;
  const b = getBanRecord(ip, hwid);
  if (!b) return false;
  adminLog('ban-blocked-request', {
    ip: ip,
    hwid: hwid,
    label: label,
    reason: b.reason || '',
    by: b.by || 'auto'
  });
  res.status(403).json({
    success: false,
    blocked: true,
    revoked: true,
    banned: true,
    permanent: true,
    message: 'Thiết bị/IP đang bị khoá (' + (b.reason || label) + ') — chỉ admin mở khoá trong panel mới dùng lại được.',
    reason: b.reason || ''
  });
  return true;
}
function keyBlocked(req, res, key, ip, hwid, deviceName, label) {
  if (!isKeyBanned(key)) return false;
  adminLog('key-blocked', {
    key: maskKey(key),
    ip: ip,
    hwid: hwid,
    label: label
  });
  const botUa = !realMobileReq(req, hwid) && isBadUA(req.headers['user-agent']);
  if (botUa) {
    res.status(404).json({ error: 'Not found' });
    return true;
  }
  res.status(401).json({
    success: false,
    revoked: true,
    reason: 'key_revoked',
    message: 'Key đã bị thu hồi (dump/rò rỉ) — liên hệ admin để cấp key mới.'
  });
  return true;
}
function addBan(ip, hwid, reason, deviceName, origin) {
  const by = origin === 'admin' ? 'admin' : 'auto';
  if (by === 'auto') {
    if (SMART_BAN && isRealMobileDevice(ip, hwid, recentUaByIp.get(ip) || '')) {
      adminLog('ban-skip-real-device', {
        ip: ip,
        hwid: hwid,
        reason: reason,
        device: deviceName || '',
        note: 'SMART_BAN: thiet bi di dong that, KHONG auto-ban'
      });
      return;
    }
    if (!SMART_BAN && SAFE_MODE) {
      adminLog('ban-soft', {
        ip: ip,
        hwid: hwid,
        reason: reason,
        device: deviceName || '',
        note: 'SAFE_MODE: auto-ban chi log, KHONG khoa'
      });
      return;
    }
  }
  const now = Date.now();
  if (ip && !(by === 'auto' && isAdminBan(banned.get('ip:' + ip)))) {
    banned.set('ip:' + ip, {
      reason: reason,
      device: deviceName || '',
      t: now,
      by: by,
      revokedAt: now
    });
  }
  if (hwid && !(by === 'auto' && isAdminBan(banned.get('dev:' + String(hwid))))) {
    banned.set('dev:' + String(hwid), {
      reason: reason,
      device: deviceName || '',
      t: now,
      by: by,
      ip: ip || '',
      revokedAt: now
    });
  }
  kvSaveState();
  adminLog('ban', {
    ip: ip,
    hwid: hwid,
    reason: reason,
    device: deviceName || '',
    by: by
  });
}
function removeBan(key) {
  banned.delete(key);
  kvSaveState();
}
function normOlm(u) {
  return String(u || '').trim().toLowerCase();
}
function addOlmBan(olm, minutes, reason, by) {
  const k = normOlm(olm);
  if (!k) return false;
  const mins = Number(minutes);
  const until = minutes === -1 || minutes === '-1' || minutes === 'permanent' || isNaN(mins) || mins <= 0 ? null : Date.now() + Math.floor(mins) * 60 * 1e3;
  olmBans.set(k, {
    reason: String(reason || 'vi pham').slice(0, 200),
    until: until,
    t: Date.now(),
    by: by || 'admin'
  });
  kvSaveState();
  return true;
}
function removeOlmBan(olm) {
  const k = normOlm(olm);
  const had = olmBans.has(k);
  olmBans.delete(k);
  if (had) kvSaveState();
  return had;
}
function checkOlmBan(olm) {
  const k = normOlm(olm);
  if (!k) return null;
  const b = olmBans.get(k);
  if (!b) return null;
  if (b.until && b.until < Date.now()) {
    olmBans.delete(k);
    kvSaveState();
    return null;
  }
  let remain = '';
  if (b.until) {
    const ms = Math.max(0, b.until - Date.now());
    const d = Math.floor(ms / 864e5), h = Math.floor(ms % 864e5 / 36e5), m = Math.max(0, Math.floor(ms % 36e5 / 6e4));
    remain = (d ? d + ' ngay ' : '') + (h ? h + 'h ' : '') + m + 'p';
  }
  return {
    banned: true,
    reason: b.reason,
    until: b.until,
    permanent: !b.until,
    remain: remain,
    t: b.t,
    by: b.by
  };
}
function fmtOlmRemain(b) {
  if (!b) return '';
  return b.permanent ? 'VINH VIEN' : b.remain || 'con hieu luc';
}
function recordLockReport({hwid: hwid, ip: ip, device: device, reason: reason, keyMasked: keyMasked, olm_user: olm_user}) {
  return;
}
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
  } catch (_) {
    return false;
  }
}
let ADMIN_USER = process.env.ADMIN_USER || 'Adminn';
let ADMIN_HASH = process.env.ADMIN_PASS_HASH || hashPass(process.env.ADMIN_PASS || '120510@');
const adminLogins = new Map;
const adminSessions = new Map;
setInterval(() => {
  const now = Date.now();
  for (const [t, s] of adminSessions) if (s.exp < now) adminSessions.delete(t);
}, 6e4).unref();
const ADMIN_LOCK_TIER_MIN = [10, 20, 30, 45, 60];
const adminLockMap = new Map();
function adminLockActive(ip) {
  const e = adminLockMap.get(ip);
  if (!e || !e.lockedUntil || e.lockedUntil <= Date.now()) return null;
  return e;
}
function adminLockRemainingText(e) {
  const remainMin = Math.max(1, Math.ceil((e.lockedUntil - Date.now()) / 60000));
  const tierMin = ADMIN_LOCK_TIER_MIN[Math.min((e.tier || 1) - 1, ADMIN_LOCK_TIER_MIN.length - 1)];
  return `🔒 Đăng nhập admin tạm khoá: còn khoảng ${remainMin} phút (bậc ${e.tier} = ${tierMin} phút/lần). Lần sai tiếp theo sau khi hết khoá sẽ bị tăng thời gian khóa.`;
}
setInterval(() => {
  const now = Date.now();
  for (const [ip, e] of adminLockMap) {
    if (e && e.lockedUntil && e.lockedUntil < now - 30 * 60 * 1e3) adminLockMap.delete(ip);
  }
}, 5 * 6e4).unref();
const ADMIN_LOG = [];
const ADMIN_LOG_MAX = 35;
function adminLog(type, data) {
  try {
    const clean = {};
    for (const [k, v] of Object.entries(data || {})) {
      clean[k] = typeof v === 'string' ? v.slice(0, LIMITS.reason) : typeof v === 'number' || typeof v === 'boolean' ? v : v == null ? '' : String(v).slice(0, LIMITS.reason);
    }
    const entry = Object.assign({
      t: (new Date).toISOString(),
      type: type
    }, clean);
    ADMIN_LOG.unshift(entry);
    if (ADMIN_LOG.length > ADMIN_LOG_MAX) ADMIN_LOG.length = ADMIN_LOG_MAX;
    kvScheduleLogsFlush();
  } catch (_) {}
}
let logsLoaded = false;
let logSaving = false;
let logFlushTimer = null;
let lastLogSaveAt = 0;
function logEntryId(e) {
  return [
    e && e.t || '',
    e && e.type || '',
    e && e.ip || '',
    e && e.hwid || '',
    e && e.device || '',
    e && e.message || e.reason || e.questions || e.action || ''
  ].join('|');
}
function mergeLogEntries(base, extra) {
  const seen = new Set();
  const out = [];
  for (const e of base.concat(extra || [])) {
    if (!e || typeof e !== 'object') continue;
    const id = logEntryId(e);
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(e);
  }
  out.sort((a, b) => new Date(b.t || 0) - new Date(a.t || 0));
  return out.slice(0, ADMIN_LOG_MAX);
}
async function kvLoadLogs(force) {
  if (!KV_ENABLED) return;
  if (logsLoaded && !force) return;
  try {
    const r = await kvRequest('/get/' + KV_LOG_KEY);
    if (r && r.result) {
      const arr = JSON.parse(Buffer.from(r.result, 'base64').toString());
      if (Array.isArray(arr)) {
        const merged = mergeLogEntries(ADMIN_LOG, arr);
        ADMIN_LOG.length = 0;
        ADMIN_LOG.push.apply(ADMIN_LOG, merged);
      }
    }
  } catch (_) {}
  logsLoaded = true;
}
async function kvSaveLogs() {
  if (!KV_ENABLED || logSaving) return;
  logSaving = true;
  try {
    let remote = [];
    const r = await kvRequest('/get/' + KV_LOG_KEY);
    if (r && r.result) {
      try { remote = JSON.parse(Buffer.from(r.result, 'base64').toString()) || []; } catch (_) { remote = []; }
    }
    const merged = mergeLogEntries(remote, ADMIN_LOG);
    ADMIN_LOG.length = 0;
    ADMIN_LOG.push.apply(ADMIN_LOG, merged);
    const val = Buffer.from(JSON.stringify(merged)).toString('base64');
    await kvRequest('/set/' + KV_LOG_KEY + '/' + encodeURIComponent(val));
  } catch (_) {} finally {
    logSaving = false;
  }
}
function kvScheduleLogsFlush() {
  if (!KV_ENABLED) return;
  const now = Date.now();
  if (now - lastLogSaveAt > 4000) {
    lastLogSaveAt = now;
    kvSaveLogs().catch(() => {});
  }
  if (logFlushTimer) clearTimeout(logFlushTimer);
  logFlushTimer = setTimeout(() => {
    logFlushTimer = null;
    lastLogSaveAt = 0;
    kvSaveLogs().catch(() => {});
  }, 2500);
  if (logFlushTimer && typeof logFlushTimer.unref === 'function') logFlushTimer.unref();
}
async function ensureKvLogsLoaded() {
  if (!KV_ENABLED) return;
  if (logsLoaded) return;
  try { await kvLoadLogs(); } catch (_) {}
}
function maskKey(k) {
  if (!k) return '';
  const s = String(k);
  return s.length <= 4 ? '****' : s.slice(0, 3) + '***' + s.slice(-2);
}
const LIMITS = {
  key: 80,
  hwid: 128,
  user: 80,
  reason: 200,
  questions: 300,
  itemText: 2e5,
  fpJson: 8192
};
function safeStr(v, max) {
  v = v == null ? '' : String(v);
  return v.slice(0, max || LIMITS.reason);
}
function validKey(k) {
  return typeof k === 'string' && k.trim().length >= 4 && k.trim().length <= LIMITS.key && /^[A-Za-z0-9_-]+$/.test(k.trim());
}
function validHwid(h) {
  return typeof h === 'string' && h.trim().length >= 4 && h.trim().length <= LIMITS.hwid && /^[A-Za-z0-9:._-]+$/.test(h.trim());
}
function validIpFmt(ip) {
  return typeof ip === 'string' && /^[0-9a-fA-F:.]{3,45}$/.test(ip);
}
function validMode(m) {
  return [ 'practice', 'exam', 'video', 'test', 'custom', 'tl', 'review' ].includes(m) ? m : 'practice';
}
function validTimeStr(t) {
  t = String(t || '').trim();
  return /^\d{1,3}([.:]\d{1,2})?$/.test(t) ? t : '10.00';
}
function validGrade(g) {
  g = String(g == null ? '10' : g).trim();
  return /^\d{1,2}$/.test(g) ? g : '10';
}
function objSize(o) {
  try {
    return Buffer.byteLength(JSON.stringify(o || {}), 'utf8');
  } catch (_) {
    return 1e9;
  }
}
function deviceNameOf(hwid) {
  const d = hwid && devices.get(hwid);
  return d ? d.name : '';
}
function getClientIp(req) {
  const fwdAll = (req.headers['x-forwarded-for'] || '').split(',').map(x => x.trim()).filter(Boolean);
  let ip = '';
  if (req.ip && req.ip !== '::' && req.ip !== '::ffff:0.0.0.0') ip = req.ip; else if (fwdAll.length) ip = fwdAll[0]; else ip = req.socket && req.socket.remoteAddress || '';
  ip = String(ip).replace(/^::ffff:/, '');
  if (!/^[0-9a-fA-F:.]{3,45}$/.test(ip)) ip = '';
  return ip;
}
function isLoopbackIp(ip) {
  return ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';
}
const rateBuckets = new Map;
const RATE_BUCKETS_MAX = 50000;
function rateLimit(key, max, windowMs) {
  const now = Date.now();
  if (!rateBuckets.has(key) && rateBuckets.size >= RATE_BUCKETS_MAX) {
    const firstKey = rateBuckets.keys().next().value;
    rateBuckets.delete(firstKey);
  }
  const arr = (rateBuckets.get(key) || []).filter(t => now - t < windowMs);
  if (arr.length >= max) {
    rateBuckets.set(key, arr);
    return false;
  }
  arr.push(now);
  rateBuckets.set(key, arr);
  return true;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, arr] of rateBuckets) {
    const f = arr.filter(t => now - t < 12e4);
    if (f.length === 0) rateBuckets.delete(k); else rateBuckets.set(k, f);
  }
}, 6e4).unref();
const recentUaAt = new Map;
setInterval(() => {
  const now = Date.now();
  for (const [k, arr] of fireUsage) {
    const f = arr.filter(t => now - t < 3600 * 1e3);
    if (f.length) fireUsage.set(k, f); else fireUsage.delete(k);
  }
  for (const [k, v] of keyUsage) if (now - v.t > 2 * 3600 * 1e3) keyUsage.delete(k);
  for (const [ip, e] of keyFail) if (now - (e.first || 0) > 10 * 60 * 1e3) keyFail.delete(ip);
  for (const [hwid, v] of realDevices) if (now - (v.lastSeen || 0) > 30 * 86400 * 1e3) realDevices.delete(hwid);
  for (const [hwid, v] of devices) if (now - (v.lastSeen || 0) > 30 * 86400 * 1e3) devices.delete(hwid);
  for (const ip of [...realIps]) {
    let hit = false;
    for (const v of realDevices.values()) if (v.ip === ip) { hit = true; break; }
    if (!hit) realIps.delete(ip);
  }
  for (const [k, v] of keyActivity) {
    const last = Math.max(v.lastModuleAt || 0, v.firstAttestAt || 0);
    if (now - last > 24 * 3600 * 1e3 && !v.processCount && !v.fireCount) keyActivity.delete(k);
  }
  for (const [k, v] of deviceActivity) if (now - (v.lastSeen || 0) > 24 * 3600 * 1e3) deviceActivity.delete(k);
  for (const [ip, t] of recentUaAt) if (now - t > 3600 * 1e3) {
    recentUaAt.delete(ip);
    recentUaByIp.delete(ip);
  }
  for (const [ip, arr] of adminLogins) {
    const f = arr.filter(t => now - t < 10 * 60 * 1e3);
    if (f.length) adminLogins.set(ip, f); else adminLogins.delete(ip);
  }
  for (const [ip, h] of ipCache) if (h.expire <= now) ipCache.delete(ip);
  let dropped = 0;
  for (const [hwid, r] of lockedScripts) {
    if (r.status === 'unlocked' && now - (r.lastSeen || 0) > 7 * 86400 * 1e3) {
      lockedScripts.delete(hwid);
      dropped++;
    }
  }
  if (lockedScripts.size > 2e3) {
    const old = [ ...lockedScripts.entries() ].sort((a, b) => (a[1].lastSeen || 0) - (b[1].lastSeen || 0));
    for (let i = 0; i < lockedScripts.size - 2e3; i++) lockedScripts.delete(old[i][0]);
  }
}, 6e4).unref();
const HONEYPOT_PATHS = [
  '/api', '/.env', '/.env.local', '/.env.production', '/.env.backup',
  '/wp-admin', '/phpmyadmin', '/.git', '/.git/config', '/.git/HEAD',
  '/config', '/server.js', '/backup', '/source', '/install',
  '/console', '/debug', '/shell', '/etc', '/etc/passwd',
  '/admin/login.php', '/xmlrpc.php', '/.htaccess', '/wp-login.php',
  '/actuator', '/actuator/env', '/actuator/health',
  '/manager/html', '/solr', '/jmx-console',
  '/cgi-bin', '/cgi-bin/luci', '/boaform',
  '/setup.php', '/info.php', '/test.php', '/phpinfo.php',
  '/_profiler', '/telescope', '/horizon',
  '/vendor', '/node_modules', '/package.json', '/package-lock.json',
  '/yarn.lock', '/composer.json', '/Dockerfile', '/docker-compose.yml',
  '/.DS_Store', '/thumbs.db',
  '/admin.php', '/login.php',
  '/autodiscover/autodiscover.xml', '/owa', '/ecp',
  '/remote/login', '/dana-na', '/pulse/web/login',
  '/index.php?s=/Index/\\think\\app/invokefunction',
  '/.well-known/security.txt'
];
app.use(async (req, res, next) => {
  try {
  await ensureKvLoaded();
  await ensureKvLogsLoaded();
  } catch (_) {}
  try {
  const ip = getClientIp(req);
  if (ip && req.headers['user-agent']) {
    recentUaByIp.set(ip, String(req.headers['user-agent']));
    recentUaAt.set(ip, Date.now());
  }
  const hwidMw = req.headers['x-hwid'] || null;
  const hwidBodyMw = (req.body && req.body.hwid) || null;
  if (enforcePermaDevice(req, res, ip, hwidMw || hwidBodyMw)) return;
  const isLoopback = ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';
  if (getBanRecord(ip, hwidMw)) {
    return res.status(403).json({
      success: false,
      blocked: true,
      banned: true,
      revoked: true,
      permanent: true,
      message: 'Thiết bị/IP đang bị khoá — chỉ admin mở khoá trong panel mới dùng lại được.',
      reason: 'banned_by_admin'
    });
  }
  const p = req.path;
  if (HONEYPOT_PATHS.some(h => p === h || p.startsWith(h + '/'))) {
    const hwidHoneypot = req.headers['x-hwid'] || null;
    if (!isLoopback && AUTO_BAN && !reqBypass(req, hwidHoneypot)) addBan(ip, hwidHoneypot, 'honeypot-scan:' + p, '');
    else if (reqBypass(req, hwidHoneypot)) adminLog('honeypot-skip-real', { ip: ip, path: p });
    return res.status(404).json({
      error: 'Not found'
    });
  }
  } catch (err) { return next(err); }
  next();
});
const REQ_SIGN = process.env.REQ_SIGN !== 'false';
const usedNonces = new Map;
setInterval(() => {
  const now = Date.now();
  for (const [n, exp] of usedNonces) if (exp < now) usedNonces.delete(n);
}, 6e4).unref();
function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}
function verifyReqSig(req) {
  if (!REQ_SIGN) return true;
  const ts = req.headers['x-ts'], nonce = req.headers['x-nonce'], sign = req.headers['x-sign'];
  if (!ts || !nonce || !sign) {
    adminLog('sig-missing', {
      ip: getClientIp(req),
      path: req.path,
      ua: String(req.headers['user-agent'] || '').slice(0, 60)
    });
    return false;
  }
  const tsNum = parseInt(ts, 10);
  if (isNaN(tsNum) || Math.abs(Math.floor(Date.now() / 1e3) - tsNum) > 15) return false;
  const nonceKey = ts + ':' + nonce;
  if (usedNonces.has(nonceKey)) return false;
  const bodyHash = sha256Hex(req.rawBody || Buffer.from(''));
  const sessTok = req.headers['x-session'] || '';
  const expected = crypto.createHmac('sha256', SECRET).update(ts + '|' + nonce + '|' + bodyHash + '|' + sessTok).digest('hex');
  try {
    const ok = crypto.timingSafeEqual(Buffer.from(String(sign)), Buffer.from(expected));
    if (ok) usedNonces.set(nonceKey, Date.now() + 6e4);
    return ok;
  } catch (_) {
    return false;
  }
}
let FAKE_REQ_COUNT = 0;
app.use((req, res, next) => {
  if (req.path && req.path.startsWith(API_PREFIX)) {
    const _kvIp = getClientIp(req);
    if (!isLoopbackIp(_kvIp) && ALLOW_LIST.indexOf(_kvIp) < 0 && kvBlockedIps.has(_kvIp)) {
      adminLog('kv-ip-ban-block', { ip: _kvIp, path: req.path });
      return res.status(403).json({ success: false, blocked: true, revoked: true, reason: 'kv_ip_ban', announce: getAnnouncePayload(), message: 'IP đã bị khoá trên hệ thống quản lý key — không thể sử dụng script.' });
    }
  }
  next();
});
app.use((req, res, next) => {
  if (req.method === 'POST' && req.path.startsWith(API_PREFIX)) {
    if (!verifyReqSig(req)) {
      FAKE_REQ_COUNT++;
      const ip = getClientIp(req);
      const ua = String(req.headers['user-agent'] || '');
      const hwid = req.headers['x-hwid'] || null;
      if (isIosReq(req) || uaIsMobile(ua) || reqBypass(req, hwid)) {
        adminLog('nosign-mobile-soft', { ip: ip, path: req.path, ua: ua.slice(0, 80) });
        FAKE_REQ_COUNT--;
        return next();
      }
      adminLog('fake-req', {
        ip: ip,
        path: req.path,
        ua: ua.slice(0, 80)
      });
      if (AUTO_BAN && !isLoopbackIp(ip) && !rateLimit('fakereq:' + ip, 5, 6e4)) {
        addBan(ip, null, 'fake-req spam (>5 bad sigs/min)', '', 'auto');
      }
      return res.status(403).json({
        success: false,
        message: 'Chữ ký request không hợp lệ (anti-fake)'
      });
    }
  }
  next();
});
app.use((req, res, next) => {
  const ip = getClientIp(req);
  if (isLoopbackIp(ip) || ALLOW_LIST.includes(ip)) return next();
  const hwidRl = req.headers['x-hwid'] || null;
  const mobile = reqBypass(req, hwidRl);
  if (mobile) {
    if (!rateLimit('g:' + ip, 600, 6e4)) return res.status(429).json({ error: 'Too many requests' });
    if (!rateLimit('burst:' + ip, 60, 2e3)) return res.status(429).json({ error: 'Too many requests' });
    return next();
  }
  if (!rateLimit('g:' + ip, 90, 6e4)) {
    adminLog('ratelimit-global', {
      ip: ip,
      path: req.path,
      ua: String(req.headers['user-agent'] || '').slice(0, 50)
    });
    if (AUTO_BAN && !isLoopbackIp(ip)) addBan(ip, null, 'rate-limit-global (>90/min)', '', 'auto');
    return res.status(429).json({
      error: 'Too many requests'
    });
  }
  if (!rateLimit('burst:' + ip, 10, 2e3)) {
    adminLog('ratelimit-burst', {
      ip: ip,
      path: req.path,
      ua: String(req.headers['user-agent'] || '').slice(0, 50)
    });
    if (AUTO_BAN && !isLoopbackIp(ip)) addBan(ip, null, 'burst-flood (>10 req/2s)', '', 'auto');
    return res.status(429).json({
      error: 'Too many requests'
    });
  }
  next();
});
app.use(async (req, res, next) => {
  if (!HARD_DC_BAN || !req.path.startsWith(API_PREFIX)) return next();
  const ip = getClientIp(req);
  if (isLoopbackIp(ip) || ALLOW_LIST.includes(ip)) return next();
  if (reqBypass(req, req.headers['x-hwid'] || null)) return next();
  const hit = ipCache.get(ip);
  if (hit && hit.expire > Date.now() && hit.info && hit.info.risk === 'high' && hit.info.isDC && hit.info.isVPN) {
    if (uaIsMobile(req.headers['user-agent'])) {
      adminLog('dc-skip-real', {
        ip: ip,
        org: hit.info.org || ''
      });
      return next();
    }
    addBan(ip, null, 'IP datacenter/proxy goi API (HARD_DC_BAN) — ' + (hit.info.org || ''), '', 'auto');
    adminLog('dc-ban', {
      ip: ip,
      org: hit.info.org || '',
      country: hit.info.country || ''
    });
    return res.status(403).json({
      success: false,
      error: 'Not found',
      message: 'Mạng datacenter/proxy bị chặn.'
    });
  }
  next();
});
const ipCache = new Map;
const DC_KEYWORDS = [ 'amazon', 'google cloud', 'microsoft azure', 'digitalocean', 'ovh', 'hetzner', 'linode', 'vultr', 'choopa', 'leaseweb', 'colocrossing', 'data center', 'datacenter', 'hosting', 'proxy', 'vpn', 'shadowsocks', 'contabo', 'buyvm', 'greencloud', 'alibaba', 'tencent cloud', 'oracle cloud', 'ibm cloud', 'scaleway', 'online.net', 'dedibox', 'cloudflare', 'fastly' ];
const ALLOW_LIST = (process.env.PROXY_ALLOW_LIST || '').split(',').map(x => x.trim()).filter(Boolean);
function checkProxyIp(ip) {
  return new Promise(resolve => {
    if (!validIpFmt(ip) || ALLOW_LIST.includes(ip)) return resolve({
      risk: 'low'
    });
    const hit = ipCache.get(ip);
    if (hit && hit.expire > Date.now()) return resolve(hit.info);
    const done = (info, ttlMs) => {
      ipCache.set(ip, {
        info: info,
        expire: Date.now() + (ttlMs || 36e5)
      });
      resolve(info);
    };
    const finishFail = note => done({
      risk: 'low',
      degraded: true,
      note: note
    }, 6e4);
    const parseIpApiIs = raw => {
      try {
        const j = JSON.parse(raw);
        const org = String(j.asn && j.asn.org || j.company && j.company.name || '').toLowerCase();
        const isDC = !!(j.is_datacenter || j.company && j.company.type === 'hosting');
        const isVPN = !!(j.is_vpn || j.is_proxy || j.is_tor || j.is_abuser);
        const kw = DC_KEYWORDS.some(k => org.includes(k));
        const CARRIER_RE = /viettel|vinaphone|mobifone|fpt|vietnamobile|gtel|vietnam postal|hanoi telecom|sai gon|carrier|cellular|mobile network|telecom/i;
        if (CARRIER_RE.test(org)) {
          return {
            risk: 'low',
            carrier: true,
            isMobile: true,
            isDC: isDC,
            isVPN: isVPN,
            country: j.location && j.location.country_code || '',
            org: org
          };
        }
        return {
          risk: isDC && (isVPN || kw) ? 'high' : 'low',
          isDC: isDC,
          isVPN: isVPN,
          country: j.location && j.location.country_code || '',
          org: org
        };
      } catch (_) {
        return null;
      }
    };
    const fallback = () => {
      const r2 = http.get(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,country,org,isp,proxy,hosting,mobile`, {
        timeout: 3e3
      }, resp => {
        let raw = '';
        resp.on('data', c => raw += c);
        resp.on('end', () => {
          try {
            const j = JSON.parse(raw);
            if (j && j.status === 'success') {
              const org = String(j.isp || j.org || '').toLowerCase();
              const isDC = !!j.hosting;
              const isVPN = !!j.proxy;
              const isMobile = !!j.mobile;
              const kw = DC_KEYWORDS.some(k => org.includes(k));
              const CARRIER_RE2 = /viettel|vinaphone|mobifone|fpt|vietnamobile|gtel|vietnam postal|hanoi telecom|sai gon|carrier|cellular|mobile|telecom/i;
              if (isMobile || CARRIER_RE2.test(org)) {
                done({
                  risk: 'low',
                  isMobile: true,
                  carrier: true,
                  isDC: isDC,
                  isVPN: isVPN,
                  country: j.country || '',
                  org: org
                });
                return;
              }
              done({
                risk: isDC && (isVPN || kw) ? 'high' : 'low',
                isDC: isDC,
                isVPN: isVPN,
                country: j.country || '',
                org: org
              });
            } else {
              finishFail('fallback-fail');
            }
          } catch (_) {
            finishFail('fallback-parse');
          }
        });
      });
      r2.on('error', () => finishFail('fallback-error'));
      r2.on('timeout', () => {
        r2.destroy();
        finishFail('fallback-timeout');
      });
    };
    const req = https.get(`https://api.ipapi.is/?q=${encodeURIComponent(ip)}`, {
      timeout: 4e3
    }, r => {
      let raw = '';
      r.on('data', c => raw += c);
      r.on('end', () => {
        const info = parseIpApiIs(raw);
        if (info) done(info); else fallback();
      });
    });
    req.on('error', () => fallback());
    req.on('timeout', () => {
      req.destroy();
      fallback();
    });
  });
}
const EMU_MARKERS = [ 'emulator', 'sdk built for', 'genymotion', 'bluestacks', 'nox', 'ldplayer', 'memu', 'andy', 'droid4x', 'ipadian', 'windroy', 'youwave', 'leapdroid', 'koplayer', 'remix os', 'phoenixos', 'primeos', 'virtualbox', 'vmware', 'qemu', 'android_x86', 'x86_64; rv', 'android sdk', 'google_sdk', 'sdk_gphone', 'emulator64', 'vbox86', 'andvm', 'duos', 'appplayer', 'microvirt', 'titandx', 'browserless', 'phantomjs', 'slimerjs', 'nightmare', 'cypress', 'testcafe', 'headless' ];
const BAD_UA = [ 'headlesschrome', 'phantom', 'puppeteer', 'selenium', 'webdriver', 'playwright', 'electron', 'cef', 'wkhtml', 'chrome-lighthouse', 'bot', 'crawl', 'spider', 'scrapy', 'curl', 'wget', 'python-requests', 'axios', 'okhttp', 'java/', 'go-http-client', 'libwww', 'httpclient', 'postman', 'insomnia', 'libcurl', 'node-fetch', 'undici', 'deno', 'bun/', 'httpie', 'python-urllib', 'python-httpx', 'aiohttp', 'guzzle', 'reqwest', 'rust', 'php/', 'ruby/', 'k6', 'jmeter', 'loadrunner', 'headless' ];
function isBadUA(uaHeader) {
  const ua = String(uaHeader || '').toLowerCase();
  if (!ua || ua.length < 20) return true;
  if (/iphone|ipad|ipod|crios|fxios|focus\//.test(ua) && !/webdriver|headless|puppeteer|playwright|selenium|electron|phantomjs/i.test(ua)) return false;
  if (BAD_UA.some(k => ua.includes(k))) return true;
  if (EMU_MARKERS.some(k => ua.includes(k))) return true;
  return false;
}
function isMobileUA(uaHeader) {
  const ua = String(uaHeader || '').toLowerCase();
  return /android|iphone|ipad|ipod|harmonyos|huawei|honor|oppo|vivo|xiaomi|redmi|realme|samsung|crios|fxios|focus|mobile\/|wv\)|webview|mobi/.test(ua);
}
function validateDevice(fp, device, uaHeader) {
  const ua = String(fp && fp.ua || uaHeader || '').toLowerCase();
  const dev = device || {};
  const platform = String(fp && fp.platform || dev && dev.platform || '').toLowerCase();
  const vendor = String(fp && fp.vendor || dev && dev.vendor || '').toLowerCase();
  let score = 0;
  let softReason = '';
  if (!fp || typeof fp !== 'object') {
    score += 3;
    softReason = softReason || 'khong gui fingerprint';
  }
  if (!device || typeof device !== 'object') {
    score += 2;
    softReason = softReason || 'khong gui thong tin thiet bi';
  }
  const uaMobile = /android|iphone|ipad|ipod|harmonyos|focus/i.test(ua);
  const HARD_AUTO_RE = /webdriver|headlesschrome|puppeteer|playwright|selenium|phantomjs|electron/i;
  if (BAD_UA.some(k => ua.includes(k))) {
    if (!(uaMobile && !HARD_AUTO_RE.test(ua))) return {
      ok: false,
      ban: true,
      reason: 'trình duyệt giả/bot (UA)',
      deviceName: '',
      score: 99
    };
    score += 1;
    softReason = softReason || 'dau hieu UA soft tren mobile (v17 mien ban)';
  }
  if (fp && fp.webdriver === true) return {
    ok: false,
    ban: true,
    reason: 'webdriver/automation',
    deviceName: '',
    score: 99
  };
  if (!ua || ua.length < 20) {
    if (!uaMobile) return {
      ok: false,
      ban: true,
      reason: 'UA không hợp lệ',
      deviceName: '',
      score: 99
    };
    softReason = softReason || 'thieu UA header tren mobile (v17 soft)';
  }
  if (EMU_MARKERS.some(k => ua.includes(k))) {
    const STRONG_EMU_RE = /sdk_gphone|emulator|genymotion|bluestacks|nox|ldplayer|memu|vbox|qemu|virtualbox|vmware/i;
    if (!(uaMobile && !STRONG_EMU_RE.test(ua))) return {
      ok: false,
      ban: true,
      reason: 'máy ảo/emulator (UA marker)',
      deviceName: '',
      score: 99
    };
    score += 1;
    softReason = softReason || 'emu marker soft tren mobile (v17)';
  }
  const isAndroid = /android/i.test(ua);
  const _touchPts = dev.touchPoints != null ? dev.touchPoints : (fp && fp.maxTouchPoints) || 0;
  const isIOS = /iphone|ipad|ipod/i.test(ua) || (/macintosh|mac os x/i.test(ua) && _touchPts > 0);
  if (isIOS && /^win/i.test(platform)) {
    score += 1;
    softReason = softReason || 'platform iOS khai báo Windows — bất thường';
  }
  if (isAndroid && /win|mac|linux/.test(platform) && !/android/.test(platform)) {
    score += 1;
    softReason = softReason || 'platform không khớp Android (thường là Linux armv8l)';
  }
  if (false && isIOS && vendor && vendor.length > 0 && !vendor.includes('apple')) {
    score += 1;
    softReason = softReason || 'vendor không khớp iOS (soft)';
  }
  let deviceName = '';
  if (isAndroid) {
    const m = ua.match(/;\s*([^;)]+?)\s+build\//i) || ua.match(/android\s+[^;)]+;\s*([^;)]+)/i);
    deviceName = m ? m[1].trim() : dev.model || 'Android Device';
  } else if (isIOS) {
    deviceName = /ipad/i.test(ua) ? 'iPad' : /ipod/i.test(ua) ? 'iPod' : 'iPhone';
    if (dev.model) deviceName += ' ' + dev.model;
  } else {
    deviceName = dev.model || navigator_platform_fallback(fp);
  }
  if (MOBILE_ONLY && !isAndroid && !isIOS) {
    if (_touchPts > 0) {
      return {
        ok: true,
        ban: false,
        reason: '',
        deviceName: deviceName,
        score: 1,
        softScore: true
      };
    }
    return {
      ok: false,
      ban: BAN_DESKTOP,
      reason: 'không phải máy Android/iOS thật',
      deviceName: deviceName,
      score: 1
    };
  }
  const touch = dev.touchPoints != null ? dev.touchPoints : fp && fp.maxTouchPoints;
  if (isAndroid && (touch == null || touch < 1)) {
    score += 1;
    softReason = softReason || 'thiếu cảm ứng';
  }
  const cores = dev.cores || fp && fp.hardwareConcurrency || 0;
  if (cores && cores < 2 && !isIOS) {
    score += 1;
    softReason = softReason || 'CPU bất thường';
  }
  const scr = dev.screen || fp && fp.screen || '';
  const sm = String(scr).match(/(\d+)x(\d+)/);
  const w = sm ? parseInt(sm[1], 10) : 0;
  const maxW = isIOS ? 3200 : 1400;
  if (w && (w < 320 || (isAndroid || isIOS) && w > maxW)) {
    score += 1;
    softReason = softReason || 'màn hình bất thường';
  }
  const mem = dev.memory || fp && fp.deviceMemory || 0;
  if (mem && mem < 1) {
    score += 1;
    softReason = softReason || 'RAM bất thường';
  }
  const coresC = dev.cores || fp && fp.hardwareConcurrency || 0;
  const memC = dev.memory || fp && fp.deviceMemory || 0;
  if (coresC && memC && coresC > 8 && memC < 2) {
    score += 2;
    softReason = softReason || 'CPU/RAM mau thuan (cores>8 nhung RAM<2)';
  }
  const touchC = dev.touchPoints != null ? dev.touchPoints : fp && fp.maxTouchPoints;
  if (touchC && touchC >= 5 && w && w < 320) {
    score += 2;
    softReason = softReason || 'touch nhieu nhung man hinh qua nho';
  }
  if (isAndroid && vendor && !/google/.test(vendor)) {
    score += 1;
    softReason = softReason || 'vendor Android khong phai Google';
  }
  const suspicious = score >= 2;
  if (score >= 5 && !isAndroid && !isIOS) return {
    ok: false,
    ban: true,
    reason: 'đa dấu hiệu thiết bị giả (' + softReason + ')',
    deviceName: deviceName,
    score: score,
    suspicious: true
  };
  if (score >= 5) return {
    ok: true,
    ban: false,
    reason: '',
    deviceName: deviceName,
    score: score,
    suspicious: true,
    softScore: true
  };
  return {
    ok: true,
    ban: false,
    reason: '',
    deviceName: deviceName,
    score: score,
    suspicious: suspicious
  };
}
function navigator_platform_fallback(fp) {
  return fp && fp.platform || 'Unknown';
}
function deriveKey(sessionToken) {
  return crypto.pbkdf2Sync(String(sessionToken || '') + '|' + SECRET, 'godmode-v4-salt', 100000, 32, 'sha256');
}
function encryptAnswers(questions, sessionToken) {
  const key = deriveKey(sessionToken);
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  let enc = c.update(JSON.stringify(questions), 'utf8', 'base64');
  enc += c.final('base64');
  return {
    iv: iv.toString('base64'),
    tag: c.getAuthTag().toString('base64'),
    data: enc
  };
}
function fpHash(fp) {
  return crypto.createHmac('sha256', SECRET).update(JSON.stringify(fp || {}).slice(0, 800)).digest('hex').slice(0, 16);
}
const keyUsage = new Map;
let SHARE_DETECT_COUNT = 0;
const ANTI_SHARE = process.env.ANTI_SHARE !== 'false';
function checkKeyShare(key, hwid, ip) {
  if (!ANTI_SHARE || !key) return {
    shared: false
  };
  const now = Date.now();
  const prev = keyUsage.get(key);
  keyUsage.set(key, {
    hwid: hwid || '',
    ip: ip || '',
    t: now
  });
  if (prev && prev.hwid && hwid && prev.hwid !== hwid && now - prev.t < 2 * 3600 * 1e3) {
    SHARE_DETECT_COUNT++;
    adminLog('share-detect', {
      key: maskKey(key),
      hwid: hwid,
      ip: ip,
      prevHwid: prev.hwid,
      prevIp: prev.ip
    });
    return {
      shared: true
    };
  }
  return {
    shared: false
  };
}
const fireUsage = new Map;
let FIRE_ATTACK_COUNT = 0;
function fireRateOk(key) {
  const now = Date.now();
  const arr = (fireUsage.get(key) || []).filter(t => now - t < 3600 * 1e3);
  if (arr.length >= 100) {
    FIRE_ATTACK_COUNT++;
    return false;
  }
  arr.push(now);
  fireUsage.set(key, arr);
  return true;
}
function requireSession(req, res, opts) {
  const token = req.headers['x-session'];
  if (!token) {
    if (opts && opts.legacyLookup && String(req.path || '').endsWith('/answers/lookup')) {
      adminLog('legacy-lookup-no-session', {
        path: req.path,
        ip: getClientIp(req)
      });
      req._sess = null;
      req._token = null;
      return true;
    }
    adminLog('missing-session', {
      path: req.path,
      ip: getClientIp(req)
    });
    res.status(403).json({
      success: false,
      message: 'Thiếu phiên xác thực (F5 trang và nhập lại key) — server không cấp quyền khi chưa có phiên.'
    });
    return false;
  }
  const sess = verifySession(token);
  if (!sess) {
    res.status(403).json({
      success: false,
      message: 'Phiên không hợp lệ hoặc hết hạn'
    });
    return false;
  }
  const {key: key, hwid: hwid} = req.body || {};
  if (sess.k !== key) {
    res.status(403).json({
      success: false,
      message: 'Phiên không khớp key'
    });
    return false;
  }
  if (sess.h !== (hwid || '')) {
    res.status(403).json({
      success: false,
      message: 'Phiên không khớp thiết bị'
    });
    return false;
  }
  if (sess.ip && sess.ip !== getClientIp(req)) {
    adminLog('ip-rotated-soft', {
      oldIp: sess.ip,
      newIp: getClientIp(req),
      path: req.path
    });
  }
  const fph = req.headers['x-fp-hash'];
  if (fph && sess.fp && fph !== sess.fp) {
    adminLog('fp-changed-soft', {
      path: req.path,
      ip: getClientIp(req)
    });
  }
  if (String(req.headers['x-seq'] || '') !== String(sess.seq || '1')) {
    adminLog('seq-mismatch', {
      got: String(req.headers['x-seq'] || ''),
      expect: String(sess.seq || '1'),
      ip: getClientIp(req)
    });
  }
  if (sess.ua && sha256Hex(req.headers['user-agent'] || '').slice(0, 16) !== sess.ua) {
    if (uaIsMobile(req.headers['user-agent'])) {
      adminLog('ua-soft-mobile', {
        path: req.path,
        ip: getClientIp(req)
      });
    } else {
      res.status(403).json({
        success: false,
        message: 'Trình duyệt không khớp phiên (anti-share token)'
      });
      return false;
    }
  }
  req._sess = sess;
  req._token = token;
  return true;
}
function rotateSession(req, payload) {
  if (!req._sess) return payload;
  const old = req._sess;
  const nextSeq = (old.seq || 1) + 1;
  const newTok = signSession(Object.assign({}, old, {
    exp: Date.now() + SESSION_TTL,
    seq: nextSeq
  }));
  payload.next_session = newTok;
  payload.next_seq = nextSeq;
  return payload;
}
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
  } catch (e) {
    console.error('[decryptOLM]', e.message);
    return null;
  }
}
function extractAnswers(htmlContent) {
  if (typeof htmlContent !== 'string' || htmlContent.length > LIMITS.itemText) return [ 'Dữ liệu câu hỏi quá lớn — bỏ qua' ];
  const $ = cheerio.load(htmlContent.slice(0, LIMITS.itemText));
  let answers = [];
  const correctNodes = $('.correctAnswer');
  if (correctNodes.length > 0) {
    correctNodes.each((_, el) => answers.push($(el).text().replace('||', '').trim()));
    return answers;
  }
  const fillInNodes = $('input[data-accept]');
  if (fillInNodes.length > 0) {
    fillInNodes.each((_, el) => answers.push($(el).attr('data-accept')));
    return answers;
  }
  let isMatching = false;
  $('li').each((_, li) => {
    const text = $(li).text().trim();
    if (text.includes('||')) {
      isMatching = true;
      answers.push(text.split('||').map(s => s.trim()).filter(s => s).join(' ➔ '));
    }
  });
  if (isMatching) return answers;
  return [ 'Không tự động trích xuất được.' ];
}
function stripHtmlTags(s) {
  try {
    return String(s == null ? '' : s)
      .replace(/<script[\s\S]*?<\/script>/gi, ' ')
      .replace(/<style[\s\S]*?<\/style>/gi, ' ')
      .replace(/<[^>]+>/g, ' ')
      .replace(/&nbsp;/gi, ' ')
      .replace(/&amp;/gi, '&')
      .replace(/&quot;/gi, '"')
      .replace(/&#\d+;/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();
  } catch (_) { return String(s || ''); }
}
function extractQuestionStem(item, htmlContent) {
  try {
    if (item) {
      for (const k of ['stem', 'question', 'question_text', 'content_text', 'title']) {
        if (typeof item[k] === 'string' && item[k].trim().length >= 6) return safeStr(stripHtmlTags(item[k]), 600);
      }
    }
    if (typeof htmlContent !== 'string' || !htmlContent.trim()) return '';
    const raw = htmlContent.slice(0, LIMITS.itemText);
    const t0 = raw.trim();
    if (t0.startsWith('{') || t0.startsWith('[')) {
      try {
        const j = JSON.parse(t0);
        let best = '';
        const walk = (n, d) => {
          if (!n || d > 4 || typeof n !== 'object') return;
          for (const k of ['title', 'question', 'question_text', 'stem', 'content_text', 'text', 'name', 'content']) {
            const v = n[k];
            if (typeof v === 'string') {
              const clean = stripHtmlTags(v);
              if (clean.length > best.length && clean.length <= 800 && !/^(data-accept|true|false)$/i.test(clean)) best = clean;
            }
          }
          for (const k of ['content', 'json_content', 'children', 'questions', 'items', 'data', 'list', 'root']) {
            if (Array.isArray(n[k])) n[k].forEach(c => walk(c, d + 1));
            else if (n[k] && typeof n[k] === 'object') walk(n[k], d + 1);
          }
        };
        walk(j, 0);
        if (best) return safeStr(best, 600);
      } catch (_) {}
    }
    const $ = cheerio.load(raw);
    let best = '';
    $('[class*="question-content"],[class*="q-content"],[class*="stem"],[class*="question__content"],.question-text,.content-main,[class*="exam-question"]').each((_, el) => {
      const t = stripHtmlTags($(el).text());
      if (t.length > best.length && t.length <= 800) best = t;
    });
    if (best) return safeStr(best, 600);
    const parts = [];
    $('p, li, .quiz-content, .q-title, .title').each((_, el) => {
      const t = stripHtmlTags($(el).text());
      if (t.length >= 8 && t.length <= 500) parts.push(t);
    });
    if (parts.length) return safeStr(parts.join(' '), 600);
  } catch (_) {}
  return '';
}
const ANSFILE_SECTIONS = [ 'fc', 'tf', 'dg', 'nrq' ];
const ANSFILE_SECTION_ALIAS = { fc: 'fc', ff: 'fc', tf: 'tf', dg: 'dg', nrq: 'nrq', rnq: 'nrq' };
function normalizeAnsFile(o) {
  if (!o || typeof o !== 'object' || Array.isArray(o)) return null;
  const out = {};
  let any = false;
  for (const rawKey of Object.keys(o)) {
    const canon = ANSFILE_SECTION_ALIAS[String(rawKey).toLowerCase()];
    const v = o[rawKey];
    if (canon && v && typeof v === 'object' && !Array.isArray(v)) { out[canon] = v; any = true; }
  }
  return any ? out : null;
}
function _ansfileLooksGood(o) {
  return !!normalizeAnsFile(o);
}
function decodeAnsFilePayload(raw) {
  if (raw == null) return null;
  let str = typeof raw === 'string' ? raw : JSON.stringify(raw);
  str = String(str).trim();
  if (!str) return null;
  const tryParse = (s) => { try { return JSON.parse(s); } catch (_) { return null; } };
  const accept = (v) => normalizeAnsFile(v);
  let obj = tryParse(str);
  if (accept(obj)) return normalizeAnsFile(obj);
  if (obj && typeof obj === 'object') {
    for (const k of [ 'data', 'content', 'answer_file', 'file', 'payload', 'ans', 'answers', 'result', 'body' ]) {
      const v = obj[k];
      if (typeof v === 'string' && v.trim()) { const inner = decodeAnsFilePayload(v); if (inner) return inner; }
      else if (v && typeof v === 'object') { const inner = decodeAnsFilePayload(JSON.stringify(v)); if (inner) return inner; }
    }
  }
  const xorRaw = decryptOLM(str);
  if (xorRaw) { const jx = tryParse(xorRaw); if (accept(jx)) return normalizeAnsFile(jx); }
  try {
    const b64dec = Buffer.from(str, 'base64').toString('utf8');
    const j2 = tryParse(b64dec);
    if (accept(j2)) return normalizeAnsFile(j2);
    const xorB64 = decryptOLM(b64dec);
    if (xorB64) { const j3 = tryParse(xorB64); if (accept(j3)) return normalizeAnsFile(j3); }
  } catch (_) {}
  try {
    const tokens = str.match(/[A-Za-z0-9+/=_-]{40,}/g) || [];
    for (const tk of tokens.sort((a, b) => b.length - a.length)) {
      const inner = decodeAnsFilePayload(tk);
      if (inner) return inner;
    }
  } catch (_) {}
  return null;
}
function sectionCountsOf(decoded) {
  const out = {};
  ANSFILE_SECTIONS.forEach(k => { out[k] = decoded && decoded[k] && typeof decoded[k] === 'object' ? Object.keys(decoded[k]).length : 0; });
  return out;
}
function buildAnsFileItems(decoded) {
  const items = [];
  const LETTERS = [ 'A', 'B', 'C', 'D', 'E', 'F', 'G' ];
  let seq = 0;
  const pushEntry = (section, key, entry) => {
    if (!entry || typeof entry !== 'object') return;
    const ans = Array.isArray(entry.answer) ? entry.answer : [];
    const score = typeof entry.score === 'number' ? entry.score : (ans.length ? 1 : 0);
    seq += 1;
    const base = {
      index: seq,
      qid: String(section) + '_' + String(key),
      id: String(key),
      section: section,
      title: 'Câu ' + key,
      stem: '',
      score: score
    };
    if (section === 'fc') {
      const idxs = ans.map(v => parseInt(v, 10)).filter(n => Number.isFinite(n));
      const count = Math.max(4, ...idxs.map(n => n + 1));
      const labels = idxs.map(n => LETTERS[n] || ('#' + (n + 1)));
      items.push(Object.assign({}, base, { answers: labels, raw: { type: 1, ans: idxs.map(String), count: count, score: score, label: labels } }));
    } else if (section === 'tf') {
      const flags = ans.map(v => (v === 1 || v === '1' || v === true) ? '1' : '0');
      items.push(Object.assign({}, base, { answers: flags.map(f => f === '1' ? 'Đúng' : 'Sai'), raw: { type: 13, ans: flags, count: flags.length, score: score } }));
    } else if (section === 'dg') {
      items.push(Object.assign({}, base, { answers: ans.map(v => String(v)), raw: { type: 6, ans: ans.map((_, i) => String(i)), count: Math.max(2, ans.length), score: score, given: ans.map(v => String(v)) } }));
    } else if (section === 'nrq') {
      items.push(Object.assign({}, base, { answers: ans.map(v => String(v)), raw: { type: 4, ans: ans.map((_, i) => String(i)), count: ans.length || 1, score: score, isText: true } }));
    }
  };
  ANSFILE_SECTIONS.forEach(sec => {
    const map = decoded[sec];
    if (map && typeof map === 'object') {
      Object.keys(map).sort((a, b) => (parseInt(a, 10) || 0) - (parseInt(b, 10) || 0)).forEach(k => pushEntry(sec, k, map[k]));
    }
  });
  return items;
}
function synthesizeQuestionsFromAnswers(items) {
  const out = [];
  (items || []).forEach((it, idx) => {
    const raw = it && it.raw;
    if (!raw) return;
    const id = it.qid || it.id || ('syn_' + (idx + 1));
    const score = typeof raw.score === 'number' ? raw.score : 1;
    const base = { id: String(id), score: score };
    if (raw.type === 13) {
      base.q_type = 13;
      base.json_content = JSON.stringify({ type: 'olm-list', name: 'true-false', children: (raw.ans || []).map(v => ({ correct: v === '1' || v === 1 || v === true })) });
    } else if (raw.type === 6) {
      const n = Math.max(2, raw.count || (raw.ans || []).length || 2);
      base.q_type = 6;
      base.json_content = JSON.stringify({ type: 'olm-list', name: 'link-list', listType: 'matching', children: Array.from({ length: n }, (_, oi) => ({ idx: oi })) });
    } else if (raw.type === 4) {
      base.q_type = 11;
      base.type = 'fillme-input';
      base.content = String((raw.ans && raw.ans[0]) || '');
    } else {
      const count = Math.max(4, raw.count || 4);
      const chosen = new Set((raw.ans || []).map(a => parseInt(a, 10)).filter(n => Number.isFinite(n)));
      base.q_type = 1;
      base.json_content = JSON.stringify({ type: 'olm-list', name: 'choice', children: Array.from({ length: count }, (_, oi) => ({ correct: chosen.has(oi) })) });
    }
    out.push(base);
  });
  return out;
}
function buildParams(sq) {
  const count = sq.count || 4;
  if (sq.type === 6) {
    const orderArr = Array.from(Array(Math.max(count, 15)), (_, k) => k);
    return {
      js: '',
      order_l: orderArr,
      order_r: orderArr
    };
  }
  return {
    js: '',
    order: Array.from(Array(count), (_, k) => k)
  };
}
function findCorrectInfo(node) {
  const results = [];
  function traverse(n, depth) {
    depth = depth || 0;
    if (!n || depth > 30) return;
    const subQ_ID = n.id || n._id || (n.props ? n.props.id : null);
    const _contentIsText = typeof n.content === 'string';
    if ((n.type === 'fillme-input' && n.content) || (_contentIsText && n.content.includes('data-accept='))) {
      if (_contentIsText && n.content.includes('data-accept=')) {
        const regex = /data-accept="([^"]+)"/g;
        let match;
        while ((match = regex.exec(n.content)) !== null) results.push({
          type: 4,
          ans: [ match[1] ],
          count: 1,
          skill: n.id_skill,
          subId: subQ_ID || 'raw_' + Math.random(),
          isText: true
        });
      } else if (_contentIsText) {
        results.push({
          type: 4,
          ans: [ n.content ],
          count: 1,
          skill: n.id_skill,
          subId: subQ_ID,
          isText: true
        });
      }
      return;
    }
    if (n.type === 'olm-list' || Array.isArray(n.children) && n.children.length > 0) {
      const options = Array.isArray(n.children) ? n.children : null;
      if (options && (n.name === 'true-false' || n.listType === 'true-false')) {
        results.push({
          type: 13,
          ans: options.map(o => o.correct == true || o.correct === 'true' || o.correct == 1 ? '1' : '0'),
          count: options.length,
          skill: n.id_skill,
          subId: subQ_ID
        });
        return;
      }
      if (options && (n.name === 'link-list' || n.listType === 'matching')) {
        results.push({
          type: 6,
          ans: options.map((_, idx) => idx.toString()),
          count: options.length,
          skill: n.id_skill,
          subId: subQ_ID
        });
        return;
      }
      if (options && options.some(c => c.correct !== undefined)) {
        const trueIndex = options.findIndex(o => o.correct == true || o.correct === 'true' || o.correct == 1);
        results.push({
          type: 1,
          ans: [ (trueIndex === -1 ? 0 : trueIndex).toString() ],
          count: options.length,
          skill: n.id_skill,
          subId: subQ_ID
        });
        return;
      }
    }
    if (Array.isArray(n.children)) n.children.forEach(c => traverse(c, depth + 1)); else if (Array.isArray(n.questions)) n.questions.forEach(c => traverse(c, depth + 1)); else if (Array.isArray(n.items)) n.items.forEach(c => traverse(c, depth + 1)); else if (Array.isArray(n.list)) n.list.forEach(c => traverse(c, depth + 1)); else if (n.root) traverse(n.root, depth + 1);
  }
  let contentToParse = node.json_content || node.content;
  if (typeof contentToParse === 'string' && !contentToParse.trim().startsWith('{') && !contentToParse.trim().startsWith('[')) {
    const decoded = decryptOLM(contentToParse);
    if (decoded) contentToParse = decoded;
  }
  try {
    traverse(typeof contentToParse === 'string' ? JSON.parse(contentToParse) : contentToParse);
  } catch (_) {
    traverse(node);
  }
  if (results.length === 0) results.push({
    type: 1,
    ans: [ '0' ],
    count: 4,
    skill: null,
    subId: null
  });
  return results;
}
function _wrongAnsForFire(sq) {
  const t = sq && sq.type;
  if (t === 4) return [ '' ];
  if (t === 13) return (sq.ans || []).map(a => (a === '1' || a === 1 || a === true) ? '0' : '1');
  if (t === 6) {
    const n = Math.max(sq.count || (sq.ans || []).length || 2, 2);
    return (sq.ans || []).map((_, idx) => String((idx + 1) % n));
  }
  const c = parseInt(sq.ans && sq.ans[0], 10);
  const n2 = Math.max(sq.count || 4, 2);
  return [ String((isNaN(c) ? 0 : c + 1) % n2) ];
}
function buildFirePayload({raw_questions: raw_questions, meta: meta, video_length: video_length}, mode, timeStr, grade, targetScore) {
  const timeParts = (timeStr || '10.00').split('.');
  const userMins = parseInt(timeParts[0]) || 0;
  let userSecsStr = timeParts[1] || '0';
  if (userSecsStr.length === 1) userSecsStr += '0';
  const userSecs = parseInt(userSecsStr.substring(0, 2));
  let calcSeconds = userMins * 60 + userSecs;
  if (calcSeconds < 30) calcSeconds = 120;
  const totalPackages = raw_questions.length;
  const tgtScore = Math.min(10, Math.max(7, parseFloat(targetScore) || 10));
  const tgtRatio = tgtScore / 10;
  const tgtCorrectCount = Math.round(totalPackages * tgtRatio);
  const wrongSet = new Set();
  for (let wi = tgtCorrectCount; wi < totalPackages; wi++) wrongSet.add(wi);
  const isExam = mode === 'exam', isVideo = mode === 'video';
  const now = Math.floor(Date.now() / 1e3);
  let totalSeconds, timeInit;
  totalSeconds = calcSeconds;
  timeInit = now - totalSeconds;
  const params = new URLSearchParams;
  const fakeLog = [];
  let max_tn_score = 0, tn_score_calc = 0, tl_max_calc = 0;
  raw_questions.forEach((q, i) => {
    const subQuestions = findCorrectInfo(q);
    const sub_count = subQuestions.length;
    const is_tl = q.q_type == 18 || q.type == 18 || q.q_type == 11;
    let final_score = sub_count;
    if (q.score !== undefined && q.score !== null && q.score !== '') final_score = parseFloat(q.score); else if (q.point !== undefined && q.point !== null && q.point !== '') final_score = parseFloat(q.point);
    const makeWrong = tgtScore < 10 && wrongSet.has(i);
    const _isEssayQ = q.q_type == 18 || q.type == 18 || q.q_type == 11;
    if (!isVideo) {
      params.append('quiz_list[]', q.id || q._id);
      params.append(`score_list[${q.id || q._id}]`, (makeWrong && !_isEssayQ) ? '0' : final_score);
    }
    let skillIDs = [ ...new Set(subQuestions.map(sq => sq.skill).filter(s => s != null)) ];
    if (!isVideo) skillIDs.forEach(s => params.append('correct_skill[]', s));
    if (isVideo || isExam) {
      if (is_tl && isExam) {
        tl_max_calc += final_score;
        fakeLog.push({
          answer: JSON.stringify([ 'Học sinh đã làm phần tự luận trên máy.' ]),
          label: [ '' ],
          params: '{"js":"","order":[0]}',
          correct_skill: [],
          wrong_skill: [],
          type: [ 18 ],
          result: [ 0 ],
          idq: parseInt(q.id || q._id),
          score: final_score,
          chk: 0
        });
      } else {
        max_tn_score += final_score;
        if (!makeWrong) tn_score_calc += final_score;
        const ans_list = [], type_list = [], prs_list = [], resArr = [], mresult = [], listIdq = [], lbl_list = [];
        for (let j = 0; j < sub_count; j++) {
          const sq = subQuestions[j];
          if (makeWrong) {
            if (sq.type === 4) ans_list.push(JSON.stringify([ '' ]));
            else if (sq.type === 13) ans_list.push(JSON.stringify(sq.ans.map(a => a === '1' ? '0' : '1')));
            else if (sq.type === 6) ans_list.push(JSON.stringify(sq.ans.map((_, idx) => ((idx + 1) % Math.max(sq.count, 1)).toString())));
            else ans_list.push(JSON.stringify(((parseInt(sq.ans[0] || '0') + 1) % (sq.count || 4)).toString()));
          } else {
            if (sq.type === 4 || sq.type === 13 || sq.type === 6) ans_list.push(JSON.stringify(sq.ans)); else ans_list.push(JSON.stringify(sq.ans[0] || '0'));
          }
          type_list.push(sq.type || 1);
          prs_list.push(JSON.stringify(buildParams(sq)));
          resArr.push(makeWrong ? 0 : 1);
          mresult.push(makeWrong ? [ 0 ] : [ 1 ]);
          listIdq.push(sq.subId && sq.subId.toString().length > 5 ? sq.subId : `q${j}`);
          let lbl = '';
          if (!makeWrong && sq.ans.length === 1 && !isNaN(sq.ans[0]) && sq.type !== 4 && sq.type !== 13) lbl = [ 'A', 'B', 'C', 'D', 'E' ][parseInt(sq.ans[0])] || '';
          lbl_list.push(lbl);
        }
        const logItem = {
          answer: JSON.stringify(ans_list),
          label: sub_count === 1 ? lbl_list : [],
          labels: lbl_list,
          params: sub_count === 1 ? prs_list[0] : JSON.stringify({
            js: '',
            prs: prs_list,
            order: Array.from(Array(sub_count).keys())
          }),
          correct_skill: makeWrong ? [] : skillIDs,
          wrong_skill: makeWrong ? skillIDs : [],
          type: type_list,
          result: resArr,
          mresult: mresult,
          idq: parseInt(q.id || q._id),
          score: makeWrong ? 0 : final_score
        };
        if (isExam) {
          logItem.chk = makeWrong ? 0 : 1;
          if (sub_count > 1) logItem.list_idq = listIdq;
        }
        if (isVideo) {
          logItem.marker = q.marker || i + 1;
          logItem.id = (q.id || q._id).toString();
        }
        fakeLog.push(logItem);
      }
    } else {
      const q_params_arr = [], a_params_arr = [];
      subQuestions.forEach(sq => {
        q_params_arr.push(JSON.stringify(buildParams(sq)));
        a_params_arr.push(JSON.stringify(makeWrong ? _wrongAnsForFire(sq) : sq.ans));
      });
      fakeLog.push({
        q_params: JSON.stringify(q_params_arr),
        a_params: JSON.stringify(a_params_arr),
        result: makeWrong ? 0 : 1,
        correct: makeWrong ? 0 : 1,
        wrong: makeWrong ? 1 : 0,
        a_index: i,
        time_spent: Math.max(5, Math.round((totalSeconds / Math.max(1, totalPackages)) * (0.55 + Math.random() * 0.8)))
      });
    }
  });
  params.append('id_cate', meta.id_cate);
  params.append('id_courseware', meta.id_courseware || meta.id_cate);
  params.append('id_user', meta.id_user);
  params.append('id_grade', grade || meta.id_grade || '10');
  if (meta.id_school) params.append('id_school', meta.id_school);
  if (meta.id_group) params.append('id_group', meta.id_group);
  params.append('type_vip', '530');
  params.append('time_stored', '0');
  params.append('date_end', now);
  params.append('data_log', JSON.stringify(fakeLog));
  if (isVideo) {
    const vl = video_length || 900;
    params.append('type', '5');
    params.append('type_exam', '0');
    params.append('total_time', vl);
    params.append('current_time', vl);
    params.append('time_spent', totalSeconds + 2);
    params.append('score_10', tgtScore.toString());
    params.append('totalq', totalPackages);
    params.append('score', tn_score_calc);
    params.append('max_score', max_tn_score);
    params.append('answered', totalPackages);
    params.append('correct', tgtCorrectCount);
    params.append('count_problems', totalPackages);
    params.append('percent', Math.round(tgtScore * 10).toString());
    params.append('pscore', tgtScore.toString());
    params.append('score_status', tgtScore.toString());
    const vLog = {
      [timeInit]: 'start',
      [timeInit + 1]: 'start',
      [timeInit + 10]: 'reload'
    };
    params.append('log', JSON.stringify(vLog));
  } else if (isExam) {
    params.append('time_init', timeInit);
    params.append('time_spent', totalSeconds);
    params.append('total_time', totalSeconds);
    params.append('current_time', totalSeconds);
    params.append('score', tn_score_calc);
    params.append('max_score', max_tn_score + tl_max_calc);
    params.append('tn_score', tn_score_calc);
    params.append('type_exam', '1');
    params.append('correct', tn_score_calc);
    params.append('wrong', max_tn_score - tn_score_calc);
    params.append('name_user', '');
    params.append('tl_score', '0');
    params.append('times', '0');
    params.append('iframe', 'false');
    let curT = timeInit + Math.floor(totalSeconds * .1);
    const totalQs = raw_questions.length;
    const usableTime = Math.max(10, totalSeconds - Math.floor(totalSeconds * .1) - 10);
    const baseInterval = usableTime / (totalQs || 1);
    for (let c = 0; c < totalQs; c++) {
      curT += Math.floor(baseInterval * (.7 + Math.random() * .6));
      if (curT >= timeInit + totalSeconds) curT = timeInit + totalSeconds - 2;
      params.append(`choose_log[${c}][ind]`, c);
      params.append(`choose_log[${c}][t]`, Math.floor(curT));
      params.append(`choose_log[${c}][l]`, c + 1);
    }
  } else {
    params.append('time_init', timeInit);
    params.append('time_spent', totalSeconds);
    params.append('time_elapsed', totalSeconds);
    params.append('total_time', totalSeconds);
    params.append('current_time', totalSeconds);
    params.append('score', Math.round(tgtScore * 10).toString());
    params.append('score_10', tgtScore.toString());
    params.append('star', Math.round(tgtScore * 2).toString());
    params.append('theta', '0');
    params.append('max_score', '100');
    params.append('answered', totalPackages);
    params.append('correct', tgtCorrectCount);
    params.append('wrong', totalPackages - tgtCorrectCount);
    params.append('missed', '0');
    params.append('count_problems', totalPackages);
    params.append('type', '3');
    params.append('type_exam', '0');
    const pLog = {
      [timeInit]: 'start',
      [timeInit + 1]: 'start'
    };
    params.append('log', JSON.stringify(pLog));
  }
  params.append('count_redo', '0');
  params.append('ended', '1');
  params.append('save_star', '1');
  return params.toString();
}
function buildFireSummary(rawQuestions, mode) {
  const items = (rawQuestions || []).map((q, i) => {
    let answers = [];
    try {
      const subs = findCorrectInfo(q);
      answers = subs.flatMap(sq => {
        if (sq.type === 1) {
          const lbl = [ 'A', 'B', 'C', 'D', 'E' ][parseInt(sq.ans && sq.ans[0], 10)];
          return lbl ? [ lbl ] : [];
        }
        return (sq.ans || []).map(String);
      });
    } catch (_) {}
    return {
      i: i + 1,
      id: q.id || q._id || null,
      answers: answers
    };
  });
  return {
    count: (rawQuestions || []).length,
    mode: mode || 'practice',
    items: items
  };
}
const _kvVerifyCache = new Map();
const KV_OK_TTL = 120e3;
const KV_FAIL_TTL = 15e3;
const KV_GRACE_TTL = 10 * 60e3;
function proxyVerify(key, hwid, olmUser, meta) {
  const ck = String(key || '') + '|' + String(hwid || '') + '|' + String(olmUser || '');
  const now = Date.now();
  const hit = _kvVerifyCache.get(ck);
  if (hit && hit.exp > now && hit.res && hit.res.success) return Promise.resolve(hit.res);
  return _proxyVerifyRaw(key, hwid, olmUser, meta).then(res => {
    try {
      if (res && res.success) {
        _kvVerifyCache.set(ck, { res: res, exp: now + KV_OK_TTL, savedAt: now });
      } else if (res && res.infraError) {
        if (hit && hit.res && hit.res.success && now - (hit.savedAt || 0) < KV_GRACE_TTL) return hit.res;
        const ttl = KV_FAIL_TTL;
        _kvVerifyCache.set(ck, { res: res, exp: now + ttl, savedAt: hit ? hit.savedAt : now });
      } else {
        _kvVerifyCache.set(ck, { res: res, exp: now + KV_FAIL_TTL, savedAt: now });
      }
    } catch (_) {}
    return res;
  });
}
function infraSoft(res, kv, route) {
  adminLog('kv-infra-soft-' + route, { message: (kv && kv.message) || '' });
  res.json({
    success: false,
    infraError: true,
    message: (kv && kv.message) || 'Mạng/KeyVault tạm bận — tự thử lại sau (không phải sai key, không phải ban).'
  });
  return true;
}
function _proxyVerifyRaw(key, hwid, olmUser, meta) {
  return new Promise(resolve => {
    const postData = JSON.stringify(Object.assign({
      key: key,
      app: APP_ID,
      device: hwid || 'unknown',
      olm_user: olmUser || ''
    }, meta || {}));
    const opts = {
      hostname: 'keyvault-vn.onrender.com',
      port: 443,
      path: '/api/verify',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData)
      },
      timeout: 4e3
    };
    const req = https.request(opts, res => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => {
        if (res.statusCode !== 200) return resolve({
          success: false,
          infraError: true,
          message: `KeyVault lỗi HTTP ${res.statusCode}: ${raw.slice(0, 120) || 'không phản hồi'}`
        });
        try {
          const kv = JSON.parse(raw);
          resolve({
            success: kv.success !== undefined ? !!kv.success : !!kv.valid,
            infraError: false,
            message: kv.message || kv.reason || (kv.valid === false ? 'Key không hợp lệ (KeyVault từ chối)' : ''),
            type: kv.type || kv.plan || kv.level || '',
            expires_at: kv.expires_at || kv.exp || kv.expire || ''
          });
        } catch (_) {
          resolve({
            success: false,
            infraError: true,
            message: `KeyVault trả về không phải JSON (có thể đang khởi động): ${raw.slice(0, 80)}`
          });
        }
      });
    });
    req.on('error', e => resolve({
      success: false,
      infraError: true,
      message: 'Lỗi kết nối KeyVault: ' + e.message
    }));
    req.on('timeout', () => {
      req.destroy();
      resolve({
        success: false,
        infraError: true,
        message: 'KeyVault timeout (server đang ngủ — thử lại)'
      });
    });
    req.write(postData);
    req.end();
  });
}
const kvBlockedIps = new Set();
let kvIpsCacheUntil = 0;
function kvPostJson(path, payload, cb) {
  try {
    const body = JSON.stringify(payload || {});
    const r = https.request({ hostname: 'keyvault-vn.onrender.com', port: 443, path: path, method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }, timeout: 4e3 }, function (res) {
      let raw = '';
      res.on('data', function (c) { raw += c; });
      res.on('end', function () { try { cb && cb(null, { status: res.statusCode }); } catch (_) {} });
    });
    r.on('error', function (e) { try { cb && cb(e); } catch (_) {} });
    r.on('timeout', function () { r.destroy(); try { cb && cb(new Error('timeout')); } catch (_) {} });
    r.write(body);
    r.end();
  } catch (_) {}
}
function kvReportDevice(data) {
  try { kvPostJson('/api/device-report', Object.assign({ app: APP_ID, ts: Date.now() }, data || {}), function () {}); } catch (_) {}
}
function kvSyncBannedIps() {
  if (Date.now() < kvIpsCacheUntil) return;
  kvIpsCacheUntil = Date.now() + 60e3;
  const paths = [ '/api/banned-ips', '/api/blocked-ips', '/api/kv/blocked-ips' ];
  let idx = 0;
  function tryNext() {
    if (idx >= paths.length) return;
    const path = paths[idx++];
    const r = https.request({ hostname: 'keyvault-vn.onrender.com', port: 443, path: path, method: 'GET', timeout: 3500 }, function (res) {
      let raw = '';
      res.on('data', function (c) { raw += c; });
      res.on('end', function () {
        try {
          const j = JSON.parse(raw);
          const arr = Array.isArray(j) ? j : (j.ips || j.bannedIps || j.blocked || j.list || (j.data && j.data.ips) || []);
          if (Array.isArray(arr)) {
            kvBlockedIps.clear();
            arr.forEach(function (x) { const ip = String(x && (x.ip || x) || '').trim(); if (validIpFmt(ip)) kvBlockedIps.add(ip); });
            adminLog('kv-ipsync', { count: kvBlockedIps.size });
          }
        } catch (_) {}
      });
    });
    r.on('error', function () { tryNext(); });
    r.on('timeout', function () { r.destroy(); tryNext(); });
    r.end();
  }
  tryNext();
}
setInterval(kvSyncBannedIps, 60e3);
try { kvSyncBannedIps(); } catch (_) {}
app.get('/', (_req, res) => res.json({
  ok: true,
  t: Date.now()
}));
app.get(API_PREFIX + '/ping', (req, res) => {
  const ip = getClientIp(req);
  if (!isLoopbackIp(ip) && !rateLimit('ping:' + ip, 20, 6e4)) {
    return res.status(429).json({ error: 'Too many requests' });
  }
  const bPing = getBanRecord(ip, req.headers['x-hwid'] || null);
  if (bPing) {
    return res.status(403).json({
      ok: false,
      banned: true,
      revoked: true,
      blocked: true,
      reason: bPing.reason || '',
      t: Date.now()
    });
  }
  res.json({ ok: true, t: Date.now() });
});
app.get(API_PREFIX + '/bootstrap.js', async (req, res) => {
  const ip = getClientIp(req);
  const _hwBoot = req.headers['x-hwid'] || null;
  const banRec = getBanRecord(ip, _hwBoot);
  if (banRec) {
    adminLog('bootstrap-denied-banned', { ip: ip, hwid: _hwBoot, reason: banRec.reason || '' });
    res.status(403).json({
      ok: false,
      revoked: true,
      banned: true,
      blocked: true,
      permanent: true,
      reason: banRec.reason || 'banned',
      message: 'Thiết bị/IP đang bị admin khoá — server ngừng giao script và đã xoá dữ liệu chức năng trên máy. Chỉ admin mở khoá trong panel mới dùng lại được.'
    });
    return;
  }
  if (!reqBypass(req, _hwBoot) && !rateLimit('boot:' + ip, 60, 6e4)) return res.status(429).json({
    error: 'Too many requests'
  });
  if (!reqBypass(req, _hwBoot) && isBadUA(req.headers['user-agent'])) {
    adminLog('badua-block', {
      ip: ip,
      path: 'bootstrap.js',
      ua: String(req.headers['user-agent'] || '').slice(0, 60)
    });
    return res.status(404).json({
      error: 'Not found'
    });
  }
  const pBoot = reqBypass(req, _hwBoot) ? { risk: 'low' } : await checkProxyIp(ip);
  if (!reqBypass(req, _hwBoot) && HARD_DC_BAN && pBoot.risk === 'high' && pBoot.isDC && pBoot.isVPN && !(uaIsMobile(req.headers['user-agent']) || SMART_BAN && isRealMobileDevice(ip, null, req.headers['user-agent']))) {
    addBan(ip, null, 'IP datacenter/proxy keo bootstrap.js (HARD_DC_BAN v11) — ' + (pBoot.org || ''), '');
    adminLog('dc-ban', {
      ip: ip,
      path: 'bootstrap.js',
      org: pBoot.org || ''
    });
    return res.status(404).json({
      error: 'Not found'
    });
  }
  if (BLOCK_VM_SCRIPT && !isMobileUA(req.headers['user-agent']) && !reqBypass(req, _hwBoot)) {
    adminLog('vm-smart-block', {
      ip: ip,
      path: 'bootstrap.js',
      ua: String(req.headers['user-agent'] || '').slice(0, 60),
      isDC: !!pBoot.isDC
    });
    return res.status(404).json({
      error: 'Not found'
    });
  }
  try {
    const src = renderConnectorSrc(req);
    const bootChk = compileCheckJs(src, 'bootstrap-served');
    if (!bootChk.ok) {
      adminLog('bootstrap-invalid', { error: bootChk.error, bytes: src.length });
      return res.status(503).json({ ok: false, error: 'maintenance' });
    }
    const payload = bootstrapEncrypt(src);
    adminLog('bootstrap', {
      ip: ip,
      ua: String(req.headers['user-agent'] || '').slice(0, 80),
      bytes: src.length
    });
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Cache-Control', 'no-store');
    res.json({
      ok: true,
      v: CONNECTOR_MODULE_VERSION,
      payload: payload
    });
  } catch (err) {
    console.error('[/bootstrap.js]', err);
    res.status(500).json({
      ok: false,
      error: 'Server error'
    });
  }
});
app.get(API_PREFIX + '/kv-payload.js', async (req, res) => {
  const ip = getClientIp(req);
  const _hwKvp = req.headers['x-hwid'] || null;
  if (getBanRecord(ip, _hwKvp)) {
    adminLog('kvp-denied-banned', { ip: ip, hwid: _hwKvp });
    res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    return res.status(200).send(REVOKE_STUB_SRC);
  }
  if (!reqBypass(req, _hwKvp) && !rateLimit('kvp:' + ip, 40, 6e4)) return res.status(429).send('/* too many requests */');
  if (!reqBypass(req, _hwKvp) && isBadUA(req.headers['user-agent'])) {
    adminLog('badua-block', {
      ip: ip,
      path: 'kv-payload.js',
      ua: String(req.headers['user-agent'] || '').slice(0, 60)
    });
    return res.status(404).send('/* not found */');
  }
  const pKvp = reqBypass(req, _hwKvp) ? { risk: 'low' } : await checkProxyIp(ip);
  if (!reqBypass(req, _hwKvp) && HARD_DC_BAN && pKvp.risk === 'high' && pKvp.isDC && pKvp.isVPN && !(uaIsMobile(req.headers['user-agent']) || SMART_BAN && isRealMobileDevice(ip, null, req.headers['user-agent']))) {
    addBan(ip, null, 'IP datacenter/proxy keo kv-payload.js (HARD_DC_BAN v11) — ' + (pKvp.org || ''), '', 'auto');
    adminLog('dc-ban', {
      ip: ip,
      path: 'kv-payload.js',
      org: pKvp.org || ''
    });
    return res.status(404).send('/* not found */');
  }
  if (BLOCK_VM_SCRIPT && !isMobileUA(req.headers['user-agent']) && !reqBypass(req, _hwKvp)) {
    adminLog('vm-smart-block', {
      ip: ip,
      path: 'kv-payload.js',
      ua: String(req.headers['user-agent'] || '').slice(0, 60),
      isDC: !!pKvp.isDC
    });
    return res.status(404).send('/* not found */');
  }
  try {
    adminLog('kv-payload-served', {
      ip: ip,
      ua: String(req.headers['user-agent'] || '').slice(0, 80)
    });
    res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.send(buildKvPayloadSrc(req));
  } catch (err) {
    console.error('[/kv-payload.js]', err);
    res.status(500).send('/* server error */');
  }
});
app.get(API_PREFIX + '/loader.user.js', async (req, res) => {
  const ip = getClientIp(req);
  const _hwLdr = req.headers['x-hwid'] || null;
  if (getBanRecord(ip, _hwLdr)) {
    adminLog('loader-denied-banned', { ip: ip, hwid: _hwLdr });
    res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Access-Control-Allow-Origin', '*');
    return res.status(200).send(REVOKE_STUB_SRC);
  }
  if (!reqBypass(req, _hwLdr) && !rateLimit('ldr:' + ip, 30, 6e4)) return res.status(429).send('// too many requests');
  if (!reqBypass(req, _hwLdr) && isBadUA(req.headers['user-agent'])) {
    adminLog('badua-block', {
      ip: ip,
      path: 'loader.user.js',
      ua: String(req.headers['user-agent'] || '').slice(0, 60)
    });
    return res.status(404).send('// not found');
  }
  const pLdr = reqBypass(req, _hwLdr) ? { risk: 'low' } : await checkProxyIp(ip);
  if (!reqBypass(req, _hwLdr) && HARD_DC_BAN && pLdr.risk === 'high' && pLdr.isDC && pLdr.isVPN && !(uaIsMobile(req.headers['user-agent']) || SMART_BAN && isRealMobileDevice(ip, null, req.headers['user-agent']))) {
    addBan(ip, null, 'IP datacenter/proxy keo loader.user.js (HARD_DC_BAN v11) — ' + (pLdr.org || ''), '', 'auto');
    adminLog('dc-ban', {
      ip: ip,
      path: 'loader.user.js',
      org: pLdr.org || ''
    });
    return res.status(404).send('// not found');
  }
  if (BLOCK_VM_SCRIPT && !isMobileUA(req.headers['user-agent']) && !reqBypass(req, _hwLdr)) {
    adminLog('vm-smart-block', {
      ip: ip,
      path: 'loader.user.js',
      ua: String(req.headers['user-agent'] || '').slice(0, 60),
      isDC: !!pLdr.isDC
    });
    return res.status(404).send('// not found');
  }
  try {
    adminLog('loader-served', {
      ip: ip,
      ua: String(req.headers['user-agent'] || '').slice(0, 60)
    });
    res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.send(buildLoaderSrc(req));
  } catch (err) {
    console.error('[/loader.user.js]', err);
    res.status(500).send('// server error');
  }
});
app.post(API_PREFIX + '/olm-check', (req, res) => {
  const ip = getClientIp(req);
  if (!rateLimit('olmc:' + ip, 30, 6e4)) return res.status(429).json({
    banned: false
  });
  const olm_user = safeStr(req.body && req.body.olm_user || '', LIMITS.user);
  const ob = checkOlmBan(olm_user);
  if (ob) {
    adminLog('olm-ban-check', {
      olm_user: normOlm(olm_user),
      ip: ip,
      reason: ob.reason
    });
    return res.json({
      banned: true,
      permanent: ob.permanent,
      remain: ob.remain || '',
      reason: ob.reason,
      message: 'Tai khoan OLM ' + String(olm_user || '') + ' da bi BAN' + (ob.permanent ? ' VINH VIEN' : ' (con ' + ob.remain + ')') + '. Ly do: ' + ob.reason
    });
  }
  res.json({
    banned: false
  });
});
app.post(API_PREFIX + '/verify', async (req, res) => {
  const ip = getClientIp(req);
  if (guardBanned(req, res, ip, req.body && req.body.hwid || null, 'verify')) return;
  if (!rateLimit('verify:' + ip + '|' + (req.body && req.body.hwid || ''), 20, 6e4)) return res.status(429).json({
    success: false,
    message: 'Quá nhiều yêu cầu'
  });
  let {key: key, hwid: hwid, olm_user: olm_user} = req.body || {};
  if (!key) return res.status(400).json({
    success: false,
    message: 'Missing key'
  });
  if (!validKey(key)) return res.status(400).json({
    success: false,
    message: 'Định dạng key không hợp lệ'
  });
  if (hwid && !validHwid(hwid)) return res.status(400).json({
    success: false,
    message: 'Định dạng thiết bị (hwid) không hợp lệ'
  });
  key = String(key).trim();
  olm_user = safeStr(olm_user, LIMITS.user);
  const _obV = checkOlmBan(olm_user);
  if (_obV) {
    adminLog('olm-ban-verify', {
      olm_user: normOlm(olm_user),
      hwid: hwid,
      ip: ip,
      reason: _obV.reason,
      permanent: _obV.permanent
    });
    return res.status(403).json({
      success: false,
      olmBanned: true,
      permanent: _obV.permanent,
      remain: _obV.remain || '',
      message: 'Tai khoan OLM ' + String(olm_user || '') + ' da bi BAN' + (_obV.permanent ? ' VINH VIEN' : ' (con ' + _obV.remain + ')') + '. Ly do: ' + _obV.reason
    });
  }
  const shV = checkKeyShare(key, hwid, ip);
  if (shV.shared) {
    if (realMobileReq(req, hwid)) adminLog('share-soft-mobile', {
      key: maskKey(key),
      hwid: hwid,
      ip: ip,
      route: 'verify'
    }); else return res.status(403).json({
      success: false,
      message: 'Key đang được dùng trên nhiều thiết bị (anti-share)'
    });
  }
  const result = await proxyVerify(key, hwid, olm_user, { ip: ip, ua: String(req.headers['user-agent'] || ''), device_name: deviceNameOf(hwid), route: 'verify' });
  if (!result.success) {
    if (result.infraError) {
      adminLog('kv-infra-soft', { key: maskKey(key), hwid: hwid, ip: ip, message: result.message || '' });
    } else if (realMobileReq(req, hwid)) {
      adminLog('verify-fail-mobile-soft', { key: maskKey(key), hwid: hwid, ip: ip, message: result.message || '' });
    } else if (recordKeyFail(ip) && AUTO_BAN && !isLoopbackIp(ip)) addBan(ip, null, 'brute-force key (>=10 sai/10 phut)', '', 'auto');
  } else resetKeyFail(ip);
  if (result.success && keyBlocked(req, res, key, ip, hwid, deviceNameOf(hwid), 'verify')) return;
  adminLog('verify', {
    key: maskKey(key),
    hwid: hwid,
    device: deviceNameOf(hwid),
    olm_user: olm_user,
    ip: ip,
    success: !!result.success,
    type: result.type || '',
    message: result.message || ''
  });
  trackDevice(hwid, {
    olm_user: normOlm(olm_user),
    ip: ip
  });
  kvReportDevice({ key: key, hwid: hwid, olm_user: olm_user, ip: ip, ua: String(req.headers['user-agent'] || ''), route: 'verify' });
  if (result && typeof result === 'object') result.announce = getAnnouncePayload();
  res.json(result);
});
app.post(API_PREFIX + '/attest', async (req, res) => {
  const ip = getClientIp(req);
  const {key: key, hwid: hwid, fp: fp, device: device} = req.body || {};
  if (guardBanned(req, res, ip, hwid, 'attest')) return;
  if (hookEnvBlock(req, res)) return;
  if (!key) return res.status(400).json({
    success: false,
    message: 'Thiếu key'
  });
  if (!validKey(key)) return res.status(400).json({
    success: false,
    message: 'Định dạng key không hợp lệ'
  });
  if (hwid && !validHwid(hwid)) return res.status(400).json({
    success: false,
    message: 'Định dạng thiết bị (hwid) không hợp lệ'
  });
  if (objSize(fp) > LIMITS.fpJson || objSize(device) > LIMITS.fpJson) return res.status(413).json({
    success: false,
    message: 'Dữ liệu fingerprint/thiết bị quá lớn'
  });
  const shA = checkKeyShare(key, hwid, ip);
  if (shA.shared) {
    if (realMobileReq(req, hwid)) adminLog('share-soft-mobile', {
      key: maskKey(key),
      hwid: hwid,
      ip: ip,
      route: 'attest'
    }); else return res.status(403).json({
      success: false,
      message: 'Key đang được dùng trên nhiều thiết bị (anti-share)'
    });
  }
  if (!reqBypass(req, hwid) && !rateLimit('attest:' + ip + '|' + (hwid || ''), 30, 6e4)) return res.status(429).json({
    success: false,
    message: 'Quá nhiều lần xác thực'
  });
  const v = validateDevice(fp, device, req.headers['user-agent']);
  if (!v.ok) {
    if (isIosReq(req) || realMobileReq(req, hwid)) {
      adminLog('reject-soft-mobile', {
        ip: ip,
        hwid: hwid,
        device: v.deviceName,
        reason: v.reason
      });
    } else {
      if (v.ban && AUTO_BAN && !isLoopbackIp(ip)) addBan(ip, hwid, v.reason, v.deviceName, 'auto');
      adminLog('reject', {
        ip: ip,
        hwid: hwid,
        device: v.deviceName,
        reason: v.reason,
        banned: !!(v.ban && AUTO_BAN)
      });
      return res.status(403).json({
        success: false,
        message: v.ban ? 'Thiết bị/mạng không hợp lệ — đã bị khoá vĩnh viễn, liên hệ admin' : 'Chỉ hỗ trợ trên máy Android/iOS thật với trình duyệt thật'
      });
    }
  }
  if (SMART_BAN && /android|iphone|ipad|ipod/i.test(String(req.headers['user-agent'] || ''))) {
    const _rd = realDevices.get(hwid) || {};
    realDevices.set(hwid, {
      ip: ip,
      deviceName: v.deviceName,
      firstSeen: _rd.firstSeen || Date.now(),
      lastSeen: Date.now()
    });
  }
  const p = reqBypass(req, hwid) ? { risk: 'low' } : await checkProxyIp(ip);
  if (p.risk === 'high') {
    if (!reqBypass(req, hwid) && HARD_DC_BAN && p.isDC && p.isVPN && !(uaIsMobile(req.headers['user-agent']) || SMART_BAN && isRealMobileDevice(ip, hwid, req.headers['user-agent']))) {
      if (reqBypass(req, hwid)) { adminLog('proxy-warn-real', { ip: ip, hwid: hwid, device: v.deviceName, note: 'thiet bi that bo qua proxy-ban v33' }); } else addBan(ip, hwid, 'proxy/VPN/datacenter + IP datacenter (HARD_DC_BAN)', v.deviceName, 'auto');
      adminLog('proxy-ban', {
        ip: ip,
        hwid: hwid,
        device: v.deviceName,
        org: p.org || '',
        country: p.country || '',
        isDC: !!p.isDC,
        suspicious: !!v.suspicious
      });
      return res.status(403).json({
        success: false,
        message: 'Mạng không hợp lệ (proxy/VPN/datacenter) — đã khoá vĩnh viễn, liên hệ admin'
      });
    }
    adminLog('proxy-warn', {
      ip: ip,
      hwid: hwid,
      device: v.deviceName,
      reason: 'proxy/VPN (soft, co the la nha mang di dong CGNAT)',
      org: p.org || '',
      country: p.country || ''
    });
  }
  if (keyBlocked(req, res, key, ip, hwid, v.deviceName, 'attest')) return;
  dumperJudge(key, hwid, ip, v.deviceName, 'attest');
  const kv = await proxyVerify(key, hwid, null, { ip: ip, ua: String(req.headers['user-agent'] || ''), device_name: v.deviceName, os: (device && device.os) || '', model: (device && device.model) || '' });
  if (!kv.success) {
    if (realMobileReq(req, hwid)) adminLog('attest-fail-mobile-soft', { key: maskKey(key), hwid: hwid, ip: ip });
    else if (recordKeyFail(ip) && AUTO_BAN && !isLoopbackIp(ip)) addBan(ip, hwid, 'brute-force key (10 lần sai)', v.deviceName, 'auto');
    return res.status(401).json({
      success: false,
      message: kv.message || 'Key không hợp lệ'
    });
  }
  resetKeyFail(ip);
  devices.set(hwid || 'unknown', {
    name: v.deviceName,
    model: device && device.model || '',
    os: device && device.os || '',
    ip: ip,
    lastSeen: Date.now()
  });
  kvSaveState();
  kvReportDevice({ key: key, hwid: hwid, name: v.deviceName, os: (device && device.os) || '', model: (device && device.model) || '', ip: ip, ua: String(req.headers['user-agent'] || ''), route: 'attest' });
  const fph = fpHash(fp);
  const token = signSession({
    k: key,
    h: hwid || '',
    ip: ip,
    fp: fph,
    dev: v.deviceName,
    exp: Date.now() + SESSION_TTL,
    seq: 1,
    ua: sha256Hex(req.headers['user-agent'] || '').slice(0, 16),
    fireReady: false
  });
  const resp = {
    success: true,
    session: token,
    expiresIn: 300,
    fpHash: fph,
    device: v.deviceName,
    message: 'Thiết bị & mạng hợp lệ — phiên đã cấp',
    moduleVersion: PAYLOAD_MODULE_VERSION,
    connectorVersion: CONNECTOR_MODULE_VERSION,
    announce: getAnnouncePayload()
  };
  if (isPremiumType(kv.type) && !BLOCK_MODULE_10) {
    keyAct(key).moduleFetchCount++;
    resp.module = buildModulePayload(token, key, hwid);
  }
  trackDevice(hwid, {
    device: v.deviceName,
    ip: ip
  });
  resp.connector = buildConnectorPayload(token);
  adminLog('attest', {
    key: maskKey(key),
    hwid: hwid,
    device: v.deviceName,
    ip: ip,
    success: true,
    premium: isPremiumType(kv.type)
  });
  res.json(resp);
});
app.post(API_PREFIX + '/process', async (req, res) => {
  const ip = getClientIp(req);
  if (guardBanned(req, res, ip, req.body && req.body.hwid || null, 'process')) return;
  if (!requireSession(req, res)) return;
  if (!reqBypass(req, req.body && req.body.hwid) && !rateLimit('ip:' + ip + '|' + (req.body && req.body.hwid || ''), 30, 6e4)) return res.status(429).json({
    success: false,
    message: 'Quá nhiều yêu cầu (IP)'
  });
  const {key: key, hwid: hwid, questions: questions} = req.body || {};
  if (!key) return res.status(401).json({
    success: false,
    message: 'Missing key'
  });
  if (!Array.isArray(questions) || questions.length === 0) return res.status(400).json({
    success: false,
    message: 'No questions'
  });
  if (questions.length > LIMITS.questions) return res.status(413).json({
    success: false,
    message: 'Quá nhiều câu hỏi (tối đa ' + LIMITS.questions + ')'
  });
  const kv = await proxyVerify(key, hwid);
  if (!kv.success) return res.status(401).json({
    success: false,
    message: kv.message || 'Invalid key'
  });
  dumperJudge(key, hwid, ip, deviceNameOf(hwid), 'process');
  if (keyBlocked(req, res, key, ip, hwid, deviceNameOf(hwid), 'core')) return;
  adminLog('process', {
    key: maskKey(key),
    hwid: hwid,
    device: deviceNameOf(hwid),
    ip: ip,
    questions: questions.length,
    subject: (req.body && req.body.meta && req.body.meta.subject_name) || '',
    exercise: (req.body && req.body.meta && req.body.meta.exercise_title) || '',
    type: kv.type || ''
  });
  try {
  const processed = questions.slice(0, LIMITS.questions).map((item, index) => {
    const rawContent = item && (item.content || item.json_content) || '';
    const safeRaw = typeof rawContent === 'string' ? rawContent.slice(0, LIMITS.itemText) : '';
    const htmlDecrypted = safeRaw ? decryptOLM(safeRaw) : null;
    const answers = htmlDecrypted ? extractAnswers(htmlDecrypted) : [ 'Lỗi giải mã' ];
    const stem = extractQuestionStem(item, htmlDecrypted);
    return {
      index: index + 1,
      id: item ? safeStr(item.id, 80) : null,
      title: item ? safeStr(item.title, 200) || stem || `Câu ${index + 1}` : stem || `Câu ${index + 1}`,
      stem: stem,
      answers: answers
    };
  });
  if (req._sess) req._sess.fireReady = true;
  try {
    const _bmeta = (req.body && req.body.meta) || {};
    if (req.body && req.body.olm_user && !_bmeta.olm_user) _bmeta.olm_user = req.body.olm_user;
    bankUpsert(_bmeta, processed, key, (req.body && req.body.olm_user) || '');
    scheduleBankSave();
  } catch (_) {}
  const payload = {
    success: true,
    encrypted: true,
    count: processed.length,
    payload: encryptAnswers(processed, req.headers['x-session'])
  };
  res.json(rotateSession(req, payload));
  } catch (err) {
    console.error('[/process]', err);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});
app.post(API_PREFIX + '/ansfile/decode', async (req, res) => {
  const ip = getClientIp(req);
  if (guardBanned(req, res, ip, req.body && req.body.hwid || null, 'ansfile')) return;
  if (!requireSession(req, res)) return;
  if (!reqBypass(req, req.body && req.body.hwid) && !rateLimit('ansf:' + ip + '|' + (req.body && req.body.hwid || ''), 40, 6e4))
    return res.status(429).json({ success: false, message: 'Quá nhiều yêu cầu (IP)' });
  const { key: key, hwid: hwid, payload: payload, url: url, meta: meta } = req.body || {};
  if (!key) return res.status(401).json({ success: false, message: 'Missing key' });
  const _body0 = req.body || {};
  const rawPayload = typeof payload === 'string' && payload.trim()
    ? payload
    : (payload != null ? JSON.stringify(payload) : (_body0.file || _body0.content || _body0.answer_file || _body0.ans || ''));
  if (!rawPayload || !String(rawPayload).trim()) return res.status(400).json({ success: false, message: 'Thiếu dữ liệu file đáp án' });
  const kv = await proxyVerify(key, hwid);
  if (!kv.success) return res.status(401).json({ success: false, message: kv.message || 'Invalid key' });
  if (keyBlocked(req, res, key, ip, hwid, deviceNameOf(hwid), 'ansfile')) return;
  const djAns = dumperJudge(key, hwid, ip, deviceNameOf(hwid), 'ansfile');
  if (djAns) { if (enforceDumpPermanent(req, res, key, hwid, ip, djAns, deviceNameOf(hwid))) return; }
  const decoded = decodeAnsFilePayload(rawPayload);
  if (!decoded) return res.status(400).json({ success: false, message: 'Không giải mã được file đáp án (sai định dạng)' });
  const items = buildAnsFileItems(decoded);
  try {
    const bmeta = Object.assign({}, meta || {}, { olm_user: (req.body && req.body.olm_user) || (meta && meta.olm_user) || '' });
    if (items.length) {
      bankUpsert(bmeta, items, key, bmeta.olm_user || '');
      scheduleBankSave();
    }
  } catch (_) {}
  adminLog('ansfile-decode', { ip: ip, hwid: hwid, key: maskKey(key), count: items.length, sections: sectionCountsOf(decoded), url: String(url || '').slice(0, 160) });
  res.json(rotateSession(req, {
    success: true,
    source: 'ansfile',
    count: items.length,
    questions: items,
    items: items,
    sections: sectionCountsOf(decoded),
    decoded_sections: sectionCountsOf(decoded)
  }));
});
app.post(API_PREFIX + '/fire', async (req, res) => {
  const ip = getClientIp(req);
  if (guardBanned(req, res, ip, req.body && req.body.hwid || null, 'fire')) return;
  if (!requireSession(req, res)) return;
  const {key: key, hwid: hwid, session: session, mode: mode, time_str: time_str, grade: grade, target_score: target_score} = req.body || {};
  if (!key) return res.status(401).json({
    success: false,
    message: 'Missing key'
  });
  if (!req._sess || !req._sess.fireReady) {
    adminLog('fire-noready', {
      ip: ip,
      hwid: hwid,
      key: maskKey(key)
    });
  }
  dumperJudge(key, hwid, ip, deviceNameOf(hwid), 'fire');
  if (keyBlocked(req, res, key, ip, hwid, deviceNameOf(hwid), 'core')) return;
  const kvFire = await proxyVerify(key, hwid);
  if (!kvFire.success) {
    return res.status(401).json({
      success: false,
      message: kvFire.message || 'Key không hợp lệ hoặc đã bị thu hồi.'
    });
  }
  if (!fireRateOk(key) && !realMobileReq(req, hwid)) {
    adminLog('fire-ratelimit', {
      ip: ip,
      hwid: hwid,
      key: maskKey(key)
    });
    return res.status(429).json({
      success: false,
      message: 'Quá nhiều lần nộp bài (tối đa 100 lần/giờ)'
    });
  }
  if (!session || typeof session !== 'object') return res.status(400).json({
    success: false,
    message: 'Session dữ liệu không hợp lệ'
  });
  const hasAnswers = Array.isArray(session.answers) && session.answers.length > 0;
  if ((!Array.isArray(session.raw_questions) || session.raw_questions.length === 0) && !hasAnswers) return res.status(400).json({
    success: false,
    message: 'raw_questions rỗng!'
  });
  if ((session.raw_questions || []).length > LIMITS.questions) return res.status(413).json({
    success: false,
    message: 'Quá nhiều câu hỏi (tối đa ' + LIMITS.questions + ')'
  });
  if (!session.meta || typeof session.meta !== 'object') return res.status(400).json({
    success: false,
    message: 'Thiếu meta (id_user / id_cate)'
  });
  const safeMode = validMode(mode);
  const safeTime = validTimeStr(time_str);
  const safeGrade = validGrade(grade);
  const safeTargetScore = Math.min(10, Math.max(7, parseFloat(target_score) || 10));
  const safeSession = {
    raw_questions: (session.raw_questions || []).filter(q => q && typeof q === 'object').slice(0, LIMITS.questions),
    meta: {
      id_user: safeStr(session.meta.id_user, 80),
      id_cate: safeStr(session.meta.id_cate, 80),
      id_courseware: safeStr(session.meta.id_courseware || session.meta.id_cate, 80),
      id_school: safeStr(session.meta.id_school, 80),
      id_group: safeStr(session.meta.id_group, 80),
      csrf_token: safeStr(session.meta.csrf_token, 200),
      subject_name: safeStr(session.meta.subject_name, 120),
      exercise_title: safeStr(session.meta.exercise_title, 300)
    },
    video_length: Number.isFinite(+session.video_length) ? Math.min(86400, Math.max(0, Math.floor(+session.video_length))) : 0
  };
  if (!safeSession.raw_questions.length && hasAnswers) {
    safeSession.raw_questions = synthesizeQuestionsFromAnswers(session.answers);
  }
  if (!safeSession.raw_questions.length) return res.status(400).json({
    success: false,
    message: 'Không dựng được câu hỏi từ đáp án kho.'
  });
  const kv = await proxyVerify(key, hwid);
  if (!kv.success) return res.status(401).json({
    success: false,
    message: kv.message || 'Invalid key'
  });
  adminLog('fire', {
    key: maskKey(key),
    hwid: hwid,
    device: deviceNameOf(hwid),
    ip: ip,
    mode: mode || '',
    target_score: safeTargetScore,
    type: kv.type || ''
  });
  const keyType = (kv.type || '').toUpperCase();
  if (![ 'PREMIUM', 'VIP', 'UNLIMITED' ].includes(keyType)) return res.status(403).json({
    success: false,
    message: 'Chức năng này yêu cầu key PREMIUM/VIP!'
  });
  if (!safeSession.meta.id_user || !safeSession.meta.id_cate) return res.status(400).json({
    success: false,
    message: 'Thiếu meta (id_user / id_cate)'
  });
  trackDevice(hwid, {
    id_cate: safeSession.meta.id_cate,
    id_user: safeSession.meta.id_user,
    subject_name: safeSession.meta.subject_name,
    exercise_title: safeSession.meta.exercise_title,
    mode: safeMode,
    ip: ip
  });
  try {
    const paramsStr = buildFirePayload(safeSession, safeMode, safeTime, safeGrade, safeTargetScore);
    const summary = buildFireSummary(safeSession.raw_questions, safeMode);
    res.json(rotateSession(req, {
      success: true,
      params_str: paramsStr,
      endpoint: '/course/teacher-static',
      summary: summary,
      summary_mode: safeMode
    }));
  } catch (err) {
    console.error('[/fire]', err);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});
app.post(API_PREFIX + '/answers/lookup', async (req, res) => {
  const ip = getClientIp(req);
  const hwid0 = req.body && req.body.hwid;
  if (guardBanned(req, res, ip, hwid0, 'lookup')) return;
  if (!requireSession(req, res, { legacyLookup: true })) return;
  if (!reqBypass(req, hwid0) && !rateLimit('bank:' + ip + '|' + (hwid0 || ''), 30, 6e4)) return res.status(429).json({ success: false, message: 'Quá nhiều yêu cầu tra kho (IP)' });
  const { key: key, hwid: hwid, cate: cate, courseware: courseware, olm_user: olm_user, subject: subject, exercise_title: exercise_title } = req.body || {};
  if (!key) return res.status(401).json({ success: false, message: 'Missing key' });
  const kv = await proxyVerify(key, hwid);
  if (!kv.success) return res.status(401).json({ success: false, message: kv.message || 'Invalid key' });
  if (keyBlocked(req, res, key, ip, hwid, deviceNameOf(hwid), 'lookup')) return;
  const c = safeStr(cate, 80);
  const cw = safeStr(courseware, 80);
  const subj = safeStr(subject, 120);
  const exTitle = safeStr(exercise_title, 300);
  const _lkKey = [c, subj, cw, exTitle].join('|');
  const _lkHit = _lookupCache.get(_lkKey);
  if (_lkHit && _lkHit.exp > Date.now()) return res.json(rotateSession(req, Object.assign({}, _lkHit.body)));
  let entry = null;
  if (c) entry = answerBank.get(c) || null;
  if (!entry && c) entry = [...answerBank.values()].find(e => String(e.cate || '') === c || (e.exercises || []).some(ex => String(ex.cate || '') === c)) || null;
  if (!entry && subj) {
    const sc = canonSubject(subj, '');
    entry = [...answerBank.values()].find(e => sc.key && entryCanon(e) === sc.key)
         || [...answerBank.values()].find(e => normBankText(e.subject) === normBankText(subj)) || null;
  }
  if (!entry) {
    const _emptyBody = { success: true, found: false, cate: c || null, subject: subj || null, count: 0, items: [], exercises: [] };
    _lookupCache.set(_lkKey, { body: _emptyBody, exp: Date.now() + LOOKUP_CACHE_TTL });
    return res.json(rotateSession(req, Object.assign({}, _emptyBody)));
  }
  migrateBankEntry(entry);
  entry.exercises = dedupeExerciseList(entry.exercises || []);
  entry.hits = numHits(entry.hits) + 1;
  entry.last_lookup_at = Date.now();
  let targetEx = null;
  if (c) targetEx = (entry.exercises || []).find(ex => String(ex.cate || '') === c) || null;
  if (!targetEx && cw) targetEx = (entry.exercises || []).find(ex => String(ex.courseware || '') === cw) || null;
  if (exTitle) {
    const tn = normBankText(exTitle);
    if (!targetEx) targetEx = (entry.exercises || []).find(ex => {
      const en = normBankText(ex.title);
      return en === tn || (tn && en && (en.includes(tn) || tn.includes(en)));
    }) || null;
  }
  if (targetEx) { targetEx.hits = numHits(targetEx.hits) + 1; targetEx.last_lookup_at = Date.now(); }
  const scopedSource = (targetEx && targetEx.items && targetEx.items.length) ? targetEx.items : (entry.items || []);
  adminLog('bank-lookup', { ip: ip, hwid: hwid, cate: c, subject: subj, exercise: exTitle, matched: !!targetEx, matchedTitle: targetEx ? (targetEx.title || '') : '', count: scopedSource.length });
  const items = scopedSource.map((it, i) => ({ index: i + 1, qid: it.qid, title: it.title, stem: it.stem || '', answers: it.answers || [] }));
  const exercises = (entry.exercises || []).map(ex => ({
    key: ex.key,
    title: ex.title || '',
    cate: ex.cate || null,
    courseware: ex.courseware || null,
    count: ex.count || (ex.items || []).length,
    hits: ex.hits || 0,
    items: (ex.items || []).map((it, i) => ({ index: i + 1, qid: it.qid, title: it.title, stem: it.stem || '', answers: it.answers || [] }))
  }));
  const matchedExercise = targetEx ? {
    key: targetEx.key || null,
    title: targetEx.title || '',
    cate: targetEx.cate || null,
    courseware: targetEx.courseware || null,
    count: (targetEx.items || []).length
  } : null;
  const body = {
    success: true,
    found: true,
    matched: !!targetEx,
    matched_exercise: matchedExercise,
    cate: entry.cate || c,
    subject: entry.subject || (entry.canon && ruleLabelByKey(entry.canon)) || subj || null,
    exercise_title: targetEx ? targetEx.title : exTitle || null,
    courseware: targetEx ? (targetEx.courseware || cw) : (entry.courseware || cw),
    count: items.length,
    items: items,
    exercises: exercises
  };
  _lookupCache.set(_lkKey, { body: body, exp: Date.now() + LOOKUP_CACHE_TTL });
  res.json(rotateSession(req, Object.assign({}, body)));
});
app.post(API_PREFIX + '/code', async (req, res) => {
  const ip = getClientIp(req);
  if (guardBanned(req, res, ip, req.body && req.body.hwid || null, 'code')) return;
  if (!requireSession(req, res)) return;
  if (!reqBypass(req, req.body && req.body.hwid) && !rateLimit('code:' + ip + '|' + (req.body && req.body.hwid || ''), 10, 6e4)) return res.status(429).json({
    success: false,
    message: 'Quá nhiều yêu cầu'
  });
  const {key: key, hwid: hwid} = req.body || {};
  if (!key) return res.status(401).json({
    success: false,
    message: 'Missing key'
  });
  const kv = await proxyVerify(key, hwid);
  if (!kv.success) return res.status(401).json({
    success: false,
    message: kv.message || 'Invalid key'
  });
  if (keyBlocked(req, res, key, ip, hwid, deviceNameOf(hwid), 'code')) return;
  const djCode = dumperJudge(key, hwid, ip, deviceNameOf(hwid), 'code');
  if (djCode) { if (enforceDumpPermanent(req, res, key, hwid, ip, djCode, deviceNameOf(hwid))) return; }
  adminLog('code', {
    key: maskKey(key),
    hwid: hwid,
    device: deviceNameOf(hwid),
    ip: ip,
    connectorVersion: CONNECTOR_MODULE_VERSION
  });
  try {
  const payload = {
    success: true,
    encrypted: true,
    connectorVersion: CONNECTOR_MODULE_VERSION,
    connector: buildConnectorPayload(req._token)
  };
  res.json(rotateSession(req, payload));
  } catch (err) {
    console.error('[/code]', err);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});
app.post(API_PREFIX + '/heartbeat', async (req, res) => {
  const ip = getClientIp(req);
  if (guardBanned(req, res, ip, req.body && req.body.hwid || null, 'heartbeat')) return;
  if (hookEnvBlock(req, res)) return;
  const _hbHwid = req.body && req.body.hwid || null;
  if (!reqBypass(req, _hbHwid) && !rateLimit('hb:' + ip + '|' + _hbHwid, 30, 6e4)) return res.status(429).json({
    success: false,
    message: 'Quá nhiều yêu cầu'
  });
  const {key: key, hwid: hwid, fp: fp, device: device, clientVersion: clientVersion} = req.body || {};
  const connectorVersion = parseInt(req.body && req.body.connectorVersion, 10) || 0;
  if (!key) return res.status(400).json({
    success: false,
    message: 'Thiếu key'
  });
  if (hwid && !validHwid(hwid)) return res.status(400).json({
    success: false,
    message: 'Định dạng thiết bị (hwid) không hợp lệ'
  });
  if (objSize(fp) > LIMITS.fpJson || objSize(device) > LIMITS.fpJson) return res.status(413).json({
    success: false,
    message: 'Dữ liệu fingerprint/thiết bị quá lớn'
  });
  const shH = checkKeyShare(key, hwid, ip);
  if (shH.shared) {
    if (realMobileReq(req, hwid)) adminLog('share-soft-mobile', {
      key: maskKey(key),
      hwid: hwid,
      ip: ip,
      route: 'heartbeat'
    }); else return res.status(403).json({
      blocked: true,
      reason: 'share',
      message: 'Key đang được dùng trên nhiều thiết bị (anti-share)'
    });
  }
  const v = validateDevice(fp, device, req.headers['user-agent']);
  if (!v.ok) {
    if (isIosReq(req) || realMobileReq(req, hwid)) {
      adminLog('heartbeat-soft-mobile', {
        ip: ip,
        hwid: hwid,
        device: v.deviceName,
        reason: v.reason
      });
    } else {
      if (v.ban && AUTO_BAN && !isLoopbackIp(ip) && !realMobileReq(req, hwid)) addBan(ip, hwid, 'heartbeat: ' + v.reason, v.deviceName, 'auto');
      adminLog('heartbeat-block', {
        ip: ip,
        hwid: hwid,
        device: v.deviceName,
        reason: v.reason,
        banned: !!(v.ban && AUTO_BAN)
      });
      return res.status(403).json({
        blocked: true,
        reason: v.reason,
        message: 'Phát hiện môi trường không hợp lệ — đã khoá'
      });
    }
  }
  if (SMART_BAN && /android|iphone|ipad|ipod/i.test(String(req.headers['user-agent'] || ''))) {
    const _rdh = realDevices.get(hwid) || {};
    realDevices.set(hwid, {
      ip: ip,
      deviceName: v.deviceName,
      firstSeen: _rdh.firstSeen || Date.now(),
      lastSeen: Date.now()
    });
  }
  const p = reqBypass(req, hwid) ? { risk: 'low' } : await checkProxyIp(ip);
  if (p.risk === 'high') {
    if (!reqBypass(req, hwid) && HARD_DC_BAN && p.isDC && p.isVPN && !(uaIsMobile(req.headers['user-agent']) || SMART_BAN && isRealMobileDevice(ip, hwid, req.headers['user-agent']))) {
      addBan(ip, hwid, 'heartbeat: proxy/VPN/datacenter + IP datacenter (HARD_DC_BAN)', v.deviceName, 'auto');
      adminLog('proxy-ban', {
        ip: ip,
        hwid: hwid,
        device: v.deviceName,
        org: p.org || '',
        isDC: !!p.isDC
      });
      return res.status(403).json({
        blocked: true,
        reason: 'proxy',
        message: 'Mạng không hợp lệ — đã khoá vĩnh viễn'
      });
    }
    adminLog('heartbeat-warn', {
      ip: ip,
      hwid: hwid,
      device: v.deviceName,
      reason: 'proxy/VPN (soft, co the la nha mang di dong)',
      org: p.org || ''
    });
  }
  if (keyBlocked(req, res, key, ip, hwid, v.deviceName, 'heartbeat')) return;
  const kv = await proxyVerify(key, hwid);
  if (!kv.success) {
    if (kv.infraError) {
      adminLog('heartbeat-infra-soft', { ip: ip, hwid: hwid, message: kv.message || '' });
      return res.json({ ok: true, degraded: true, t: Date.now(), nextCheck: 15e3 });
    }
    adminLog('heartbeat-block', {
      ip: ip,
      hwid: hwid,
      reason: 'key thu hồi/hết hạn',
      message: kv.message || ''
    });
    return res.status(403).json({
      blocked: true,
      revoked: true,
      reason: 'key',
      message: kv.message || 'Key đã bị vô hiệu hoá'
    });
  }
  if (hwid && devices.has(hwid)) {
    const d = devices.get(hwid);
    d.lastSeen = Date.now();
    d.ip = ip;
  }
  const premium = isPremiumType(kv.type);
  const out = {
    ok: true,
    t: Date.now(),
    nextCheck: 3e4,
    moduleVersion: PAYLOAD_MODULE_VERSION,
    premium: premium,
    connectorVersion: CONNECTOR_MODULE_VERSION,
    announce: getAnnouncePayload()
  };
  const cv = parseInt(clientVersion, 10) || 0;
  if (cv === 0 && parseInt((req.body && req.body.connectorVersion) || '0', 10) === 0) {
    const dj0 = dumperJudge(key, hwid, ip, v.deviceName, 'heartbeat-zero');
    if (dj0) {
      if (enforceDumpPermanent(req, res, key, hwid, ip, dj0, v.deviceName)) return;
    }
  }
  if (premium && cv < PAYLOAD_MODULE_VERSION && !BLOCK_MODULE_10) {
    let tok = null;
    const sessTok = req.headers['x-session'];
    const sess = verifySession(sessTok);
    if (sess && sess.k === key && sess.h === (hwid || '')) tok = sessTok; else tok = signSession({
      k: key,
      h: hwid || '',
      ip: ip,
      fp: fpHash(fp),
      dev: v.deviceName,
      exp: Date.now() + SESSION_TTL,
      seq: 1,
      ua: sha256Hex(req.headers['user-agent'] || '').slice(0, 16),
      fireReady: false
    });
    out.module = buildModulePayload(tok, key, hwid);
    out.moduleSession = tok;
    adminLog('heartbeat-push', {
      key: maskKey(key),
      hwid: hwid,
      ip: ip,
      from: cv,
      to: PAYLOAD_MODULE_VERSION
    });
  }
  const ccv = connectorVersion;
  if (ccv < CONNECTOR_MODULE_VERSION) {
    let tok2 = null;
    const sessTok2 = req.headers['x-session'];
    const sess2 = verifySession(sessTok2);
    if (sess2 && sess2.k === key && sess2.h === (hwid || '')) tok2 = sessTok2; else tok2 = signSession({
      k: key,
      h: hwid || '',
      ip: ip,
      fp: fpHash(fp),
      dev: v.deviceName,
      exp: Date.now() + SESSION_TTL,
      seq: 1,
      ua: sha256Hex(req.headers['user-agent'] || '').slice(0, 16),
      fireReady: false
    });
    out.connector = buildConnectorPayload(tok2);
    out.connectorSession = tok2;
    adminLog('heartbeat-connector-push', {
      key: maskKey(key),
      hwid: hwid,
      ip: ip,
      from: ccv,
      to: CONNECTOR_MODULE_VERSION
    });
  }
  res.json(out);
});
app.post(API_PREFIX + '/lock-report', (req, res) => {
  const ip = getClientIp(req);
  if (!rateLimit('lockrep:' + ip, 10, 6e4)) return res.status(429).json({
    ok: false
  });
  let {hwid: hwid, reason: reason, olm_user: olm_user} = req.body || {};
  const key = req.body && req.body.key;
  if (!hwid || !validHwid(hwid)) return res.status(400).json({
    ok: false,
    message: 'hwid không hợp lệ'
  });
  reason = safeStr(reason, LIMITS.reason);
  olm_user = safeStr(olm_user, LIMITS.user);
  const device = req.body && req.body.device || {};
  const devName = device && device.model ? ((device.os || '') + ' ' + device.model).trim() : deviceNameOf(hwid);
  const lrBan = getBanRecord(ip, hwid);
  if (lrBan) {
    return res.json({ ok: false, locked: true, banned: true, revoked: true, reason: lrBan.reason || '' });
  }
  adminLog('lock-report', {
    hwid: hwid,
    ip: ip,
    device: devName,
    reason: String(reason || '').slice(0, 120),
    olm_user: olm_user || ''
  });
  res.json({
    ok: true,
    t: Date.now()
  });
});
app.post(API_PREFIX + '/lock-status', (req, res) => {
  const ip = getClientIp(req);
  if (!rateLimit('lockst:' + ip, 30, 6e4)) return res.status(429).json({
    ok: false
  });
  const {hwid: hwid} = req.body || {};
  if (hwid && !validHwid(hwid)) return res.json({ locked: false });
  const lb = getBanRecord(ip, hwid);
  if (lb) {
    return res.json({
      locked: true, banned: true, revoked: true, permanent: true,
      reason: lb.reason || '',
      announce: getAnnouncePayload(),
      t: Date.now()
    });
  }
  if (hwid && permaDevices.has(String(hwid))) {
    return res.json({
      locked: true, banned: true, revoked: true, permanent: true,
      reason: 'device_perma_banned',
      announce: getAnnouncePayload(),
      t: Date.now()
    });
  }
  const rec = hwid ? lockedScripts.get(hwid) : null;
  if (rec) {
    rec.lastSeen = Date.now();
    if (ip) rec.ip = ip;
  }
  const locked = !!(rec && rec.status === 'locked' && rec.lockedBy === 'admin');
  res.json({
    locked: locked,
    banned: false,
    revoked: false,
    reason: locked ? rec.reason || '' : '',
    announce: getAnnouncePayload(),
    t: Date.now()
  });
});
function _parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach(p => {
    const [k, ...v] = p.split('=');
    if (k) out[k.trim()] = decodeURIComponent(v.join('='));
  });
  return out;
}
function isAdmin(req) {
  const tok = _parseCookies(req)['god_admin'];
  const p = tok && verifySession(tok);
  return !!(p && p.admin === 1);
}
function requireAdmin(req, res) {
  if (!isAdmin(req)) {
    res.redirect(ADMIN_PATH);
    return false;
  }
  return true;
}
function _esc(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function adminLoginPage(msg) {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">\n<title>Admin — GOD MODE v4</title><style>\n*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0d1117;font-family:'Segoe UI',system-ui,sans-serif;color:#c9d1d9}\n.box{width:340px;background:#161b22;border:1px solid #30363d;border-radius:14px;padding:28px;box-shadow:0 0 40px rgba(0,0,0,.6)}\nh1{font-size:18px;margin:0 0 4px;background:linear-gradient(90deg,#00f2fe,#4facfe);-webkit-background-clip:text;-webkit-text-fill-color:transparent}\n.sub{font-size:11px;color:#8b949e;margin-bottom:20px;font-family:monospace}\nlabel{font-size:11px;color:#8b949e;display:block;margin:10px 0 4px;text-transform:uppercase;letter-spacing:.5px}\ninput{width:100%;padding:11px;background:#0d1117;border:1px solid #30363d;border-radius:8px;color:#00f2fe;font-family:monospace;font-size:14px;outline:none}\ninput:focus{border-color:#00f2fe;box-shadow:0 0 12px rgba(0,242,254,.3)}\nbutton{width:100%;margin-top:18px;padding:12px;border:none;border-radius:8px;background:linear-gradient(135deg,#00b09b,#96c93d);color:#fff;font-weight:700;cursor:pointer;font-size:13px;letter-spacing:1px}\nbutton:hover{filter:brightness(1.1)}\n.err{background:rgba(239,35,60,.12);border:1px solid rgba(239,35,60,.4);color:#ef233c;padding:8px;border-radius:6px;font-size:12px;margin-top:12px;text-align:center}\n</style></head><body><div class="box">\n<h1>🚀 GOD MODE v4 — ADMIN</h1><div class="sub">// server control panel</div>\n<form method="POST" action="${ADMIN_PATH}/login">\n<label>Tài khoản</label><input name="username" autocomplete="username" autofocus>\n<label>Mật khẩu</label><input type="password" name="password" autocomplete="current-password">\n<button>🔓 ĐĂNG NHẬP</button>\n${msg ? `<div class="err">${_esc(msg)}</div>` : ''}\n</form></div></body></html>`;
}
app.use((req, res, next) => {
  if (req.method === 'POST' && req.path.startsWith(ADMIN_PATH + '/')) {
    const origin = String(req.headers['origin'] || '').replace(/^https?:\/\//, '').split('/')[0];
    const referer = String(req.headers['referer'] || '').replace(/^https?:\/\//, '').split('/')[0];
    const host = req.get('host') || '';
    const ok = !origin && !referer || origin && origin === host || !origin && referer && (referer === host || referer.endsWith('.' + host));
    if (!ok) {
      adminLog('csrf-block', {
        ip: getClientIp(req),
        path: req.path,
        origin: origin,
        referer: referer,
        host: host
      });
      return res.status(403).send('CSRF check failed');
    }
  }
  if (req.path.startsWith(ADMIN_PATH)) res.setHeader('Referrer-Policy', 'same-origin');
  next();
});
app.get(ADMIN_PATH, (req, res) => {
  if (isAdmin(req)) return res.redirect(ADMIN_PATH + '/dashboard');
  res.send(adminLoginPage(''));
});
app.post(ADMIN_PATH + '/login', async (req, res) => {
  const ip = getClientIp(req);
  if (!isLoopbackIp(ip) && HARD_DC_BAN) {
    const pAdmin = await checkProxyIp(ip);
    if (pAdmin.risk === 'high' && pAdmin.isDC) {
      adminLog('admin-login-dc-block', { ip, org: pAdmin.org || '' });
      return res.status(403).send(adminLoginPage('Truy cập từ IP datacenter/proxy bị từ chối.'));
    }
  }
  const _prevLock = adminLockMap.get(ip);
  if (_prevLock && _prevLock.lockedUntil && _prevLock.lockedUntil <= Date.now()) { _prevLock.fails = 0; adminLockMap.set(ip, _prevLock); }
  const lockedNow = adminLockActive(ip);
  if (lockedNow) return res.status(429).send(adminLoginPage(adminLockRemainingText(lockedNow)));
  const {username: username, password: password} = req.body || {};
  if (username === ADMIN_USER && verifyPass(password, ADMIN_HASH)) {
    adminLockMap.delete(ip);
    adminLogins.delete(ip);
    const tok = signSession({
      admin: 1,
      u: ADMIN_USER,
      exp: Date.now() + 12 * 3600 * 1e3
    });
    const _secFlag = req.protocol === 'https' || req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
    res.setHeader('Set-Cookie', `god_admin=${tok}; Path=${ADMIN_PATH}; HttpOnly; Max-Age=43200; SameSite=Strict${_secFlag}`);
    adminLog('admin', {
      action: 'login',
      ip: ip
    });
    return res.redirect(ADMIN_PATH + '/dashboard');
  }
  const lockEntry = adminLockMap.get(ip) || { fails: 0, tier: 0, lockedUntil: 0 };
  lockEntry.fails += 1;
  if (lockEntry.fails >= 3) {
    lockEntry.tier = Math.min(lockEntry.tier + 1, ADMIN_LOCK_TIER_MIN.length);
    const mins = ADMIN_LOCK_TIER_MIN[lockEntry.tier - 1];
    lockEntry.lockedUntil = Date.now() + mins * 60 * 1e3;
    adminLockMap.set(ip, lockEntry);
    adminLog('admin-lockout', { ip: ip, fails: lockEntry.fails, tier: lockEntry.tier, minutes: mins });
    return res.status(429).send(adminLoginPage(`❌ Sai ${lockEntry.fails} lần liên tiếp → khoá ${mins} phút (bậc ${lockEntry.tier}). Hết khoá, nếu tiếp tục sai thời gian khoá sẽ tăng lên bậc tiếp theo.`));
  }
  adminLockMap.set(ip, lockEntry);
  res.status(401).send(adminLoginPage(`Sai tài khoản hoặc mật khẩu! (còn ${3 - lockEntry.fails} lần thử trước khi bị khoá)`));
});
app.get(ADMIN_PATH + '/logout', (req, res) => {
  const tok = _parseCookies(req)['god_admin'];
  if (tok) adminSessions.delete(tok);
  res.setHeader('Set-Cookie', `god_admin=; Path=${ADMIN_PATH}; HttpOnly; Max-Age=0; SameSite=Strict`);
  res.redirect(ADMIN_PATH);
});
function adminDashboardPage(msg) {
  const upt = Math.floor(process.uptime());
  const uptStr = Math.floor(upt / 3600) + 'h ' + Math.floor(upt % 3600 / 60) + 'm ' + upt % 60 + 's';
  const lockActive = [ ...lockedScripts.values() ].filter(x => x.status === 'locked').length;
  const secInfo = {
    reqSign: REQ_SIGN,
    antiShare: ANTI_SHARE,
    shareCount: SHARE_DETECT_COUNT,
    fakeCount: FAKE_REQ_COUNT,
    fireCount: FIRE_ATTACK_COUNT
  };
  const logRows = ADMIN_LOG.slice(0, ADMIN_LOG_MAX).map(e => `<tr>\n<td style="font-family:monospace;font-size:10px;color:#8b949e">${_esc(new Date(e.t).toLocaleString('vi-VN'))}</td>\n<td><span style="color:${e.type === 'verify' ? '#4facfe' : e.type === 'process' ? '#00e676' : e.type === 'ban' || e.type === 'reject' ? '#ef233c' : '#ffc107'}">${_esc(e.type)}</span></td>\n<td style="font-family:monospace">${_esc(e.device || '')}</td>\n<td style="font-family:monospace;font-size:10px">${_esc(e.hwid || '')}</td>\n<td style="font-size:10px">${_esc(e.ip || '')}</td>\n<td>${e.success === undefined ? '—' : e.success ? '<span style="color:#00e676">✅</span>' : '<span style="color:#ef233c">❌</span>'}</td>\n<td style="font-family:monospace;font-size:10px">${_esc(e.olm_user || '')}</td>\n<td style="font-size:10px;max-width:180px;overflow:hidden;text-overflow:ellipsis">${_esc(e.message || (e.questions ? e.questions + ' câu' : '') || e.reason || '')}</td>\n</tr>`).join('');
  const banRows = [ ...banned.entries() ].slice(0, 50).map(([k, v]) => `<tr>\n<td style="font-family:monospace;font-size:11px">${_esc(k)}</td>\n<td style="font-size:11px">${_esc(v.device || '')}</td>\n<td style="font-size:10px">${v.by === 'admin' ? '🔒 ADMIN' : 'auto'}</td>\n<td style="font-size:11px;color:#ef233c">${_esc(v.reason || '')}</td>\n<td style="font-size:10px;color:#8b949e">${_esc(new Date(v.t || 0).toLocaleString('vi-VN'))}</td>\n<td><form method="POST" action="${ADMIN_PATH}/unban" style="display:inline"><input type="hidden" name="key" value="${_esc(k)}"><button style="padding:4px 10px;font-size:10px;margin:0" class="danger">MỞ KHOÁ</button></form></td>\n</tr>`).join('');
  const permaRows = [...permaDevices].map(function (id) { return '<tr><td style="font-family:monospace;color:#fca5a5">' + _esc(id) + '</td><td><form method="POST" action="' + ADMIN_PATH + '/unban" class="inline"><input type="hidden" name="key" value="dev:' + _esc(id) + '"><button style="padding:4px 10px;font-size:10px" class="danger">🔓 MỞ KHOÁ</button></form></td></tr>'; }).join('');
  const devRows = [ ...devices.entries() ].slice(0, 50).map(([hwid, d]) => `<tr>\n<td style="font-family:monospace;font-size:11px">${_esc(hwid)}</td>\n<td style="font-size:11px;color:#00f2fe">${_esc(d.name || '')}</td>\n<td style="font-size:10px">${_esc(d.os || '')} ${_esc(d.model || '')}</td>\n<td style="font-size:10px">${_esc(d.ip || '')}</td>\n<td style="font-size:10px;color:#8b949e">${_esc(new Date(d.lastSeen || 0).toLocaleString('vi-VN'))}</td>\n<td><form method="POST" action="${ADMIN_PATH}/ban-device" class="inline" onsubmit="return confirm('Khoá TOÀN DIỆN thiết bị này? Mọi IP sẽ bị chặn vĩnh viễn.')"><input type="hidden" name="hwid" value="${_esc(hwid)}"><button style="padding:3px 9px;font-size:10px" class="danger">🛑 Khoá</button></form></td>\n</tr>`).join('');
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">\n<title>Dashboard — GOD MODE Admin v4</title><style>\n*{box-sizing:border-box}body{margin:0;background:#0d1117;font-family:'Segoe UI',system-ui,sans-serif;color:#c9d1d9;padding:20px}\n.wrap{max-width:1150px;margin:0 auto}\n.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:8px}\nh1{font-size:20px;margin:0;background:linear-gradient(90deg,#00f2fe,#4facfe);-webkit-background-clip:text;-webkit-text-fill-color:transparent}\na.logout{color:#ef233c;text-decoration:none;font-size:12px;border:1px solid rgba(239,35,60,.4);padding:6px 12px;border-radius:6px}\n.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:16px}\n.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:14px}\n.card .lbl{font-size:10px;color:#8b949e;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px}\n.card .val{font-size:14px;font-weight:700;font-family:monospace;color:#00f2fe;word-break:break-all}\n.card .val.ok{color:#00e676}.card .val.bad{color:#ef233c}\n.panel{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;margin-bottom:16px}\n.panel h2{font-size:13px;margin:0 0 12px;color:#4facfe;text-transform:uppercase;letter-spacing:1px}\nform.inline{display:flex;gap:8px;flex-wrap:wrap;align-items:center}\ninput{padding:9px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#00f2fe;font-family:monospace;font-size:12px;outline:none;min-width:160px}\nbutton{padding:9px 16px;border:none;border-radius:6px;background:linear-gradient(135deg,#00b09b,#96c93d);color:#fff;font-weight:700;cursor:pointer;font-size:12px}\nbutton.danger{background:linear-gradient(135deg,#d90429,#ef233c)}\nbutton.warn{background:linear-gradient(135deg,#f59e0b,#ef4444)}\n.msg{padding:8px 12px;border-radius:6px;font-size:12px;margin-bottom:12px}\n.msg.ok{background:rgba(0,230,118,.1);border:1px solid rgba(0,230,118,.3);color:#00e676}\n.msg.warn{background:rgba(255,193,7,.1);border:1px solid rgba(255,193,7,.3);color:#ffc107}\ntable{width:100%;border-collapse:collapse;font-size:11px}\nth,td{padding:6px 8px;text-align:left;border-bottom:1px solid #21262d;vertical-align:top}\nth{color:#8b949e;font-size:10px;text-transform:uppercase;letter-spacing:.5px}\n.hint{font-size:10px;color:#8b949e;margin-top:8px;line-height:1.6}\n.toggle-row{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:10px}\n.toggle{display:flex;align-items:center;gap:8px;font-size:12px;background:#0d1117;border:1px solid #30363d;padding:8px 12px;border-radius:8px}\n.toggle .st{font-weight:700}\n.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}\n@media(max-width:800px){.grid2{grid-template-columns:1fr}}\n</style></head><body><div class="wrap">\n<div class="top"><h1>⚙️ GOD MODE v4 — ADMIN DASHBOARD</h1><div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap"><a href="${ADMIN_PATH}/answers" style="color:#00e676;text-decoration:none;font-size:12px;border:1px solid rgba(0,230,118,.4);padding:6px 12px;border-radius:6px">📚 KHO ĐÁP ÁN (${answerBank.size} môn · ${[...answerBank.values()].reduce((s, e) => s + ((e.exercises || []).length || 0), 0)} bài tập)</a>
<a href="${ADMIN_PATH}/locked" style="color:#ffc107;text-decoration:none;font-size:12px;border:1px solid rgba(255,193,7,.4);padding:6px 12px;border-radius:6px">🔒 TAB KHOÁ SCRIPT LẠ (${lockActive})</a><a class="logout" href="${ADMIN_PATH}/logout">🚪 Đăng xuất</a></div></div>\n${msg ? `<div class="msg ${msg.includes('thành công') || msg.includes('OK') || msg.includes('✅') ? 'ok' : 'warn'}">${_esc(msg)}</div>` : ''}\n<div class="cards">\n<div class="card"><div class="lbl">Trạng thái server</div><div class="val ok">● ĐANG CHẠY</div></div>\n<div class="card"><div class="lbl">Uptime</div><div class="val">${uptStr}</div></div>\n<div class="card"><div class="lbl">Ẩn API Prefix</div><div class="val">${_esc(API_PREFIX)}</div></div>\n<div class="card"><div class="lbl">Auto-ban</div><div class="val ${AUTO_BAN ? 'ok' : 'bad'}">${AUTO_BAN ? 'BẬT' : 'TẮT'}</div></div>\n<div class="card"><div class="lbl">Chặn kèo script VM (chỉ VM/proxy/desktop)</div><div class="val ${BLOCK_VM_SCRIPT ? 'warn' : 'ok'}">${BLOCK_VM_SCRIPT ? '🛑 Chặn VM/proxy (mobile vẫn OK)' : '✅ Bình thường'}</div></div>\n<div class="card"><div class="lbl">Tài khoản OLM bị ban</div><div class="val" style="color:#ef4444">${olmBans.size}</div></div>\n<div class="card"><div class="lbl">Module 10 điểm</div><div class="val ${BLOCK_MODULE_10 ? 'bad' : 'ok'}">${BLOCK_MODULE_10 ? '🛑 ĐANG CHẶN' : '✅ Đang gửi'}</div></div>\n<div class="card"><div class="lbl">HARD_DC_BAN (proxy/VM gọi API→ban)</div><div class="val ${HARD_DC_BAN ? 'ok' : 'bad'}">${HARD_DC_BAN ? 'BẬT' : 'TẮT'}</div></div>\n<div class="card"><div class="lbl">SAFE_MODE (chống ban nhầm — auto-ban chỉ log)</div><div class="val ${SAFE_MODE ? 'ok' : 'bad'}">${SAFE_MODE ? 'BẬT (an toàn)' : 'TẮT (nguy cơ ban nhầm)'}</div></div>\n<div class="card"><div class="lbl">SMART_BAN heuristic (máy ảo/proxy)</div><div class="val ${SMART_BAN ? 'ok' : 'bad'}">${SMART_BAN ? 'BẬT' : 'TẮT'}</div></div>\n<div class="card"><div class="lbl">Ban thủ công (vĩnh viễn)</div><div class="val" style="color:#ef4444">Chỉ admin gỡ</div></div>\n<div class="card"><div class="lbl">Thiết bị thật đã nhận diện</div><div class="val" style="color:#4facfe">${realDevices.size} máy</div></div>\n<div class="card"><div class="lbl">DUMPER_GUARD (phát hiện dump→ban key)</div><div class="val ${DUMPER_GUARD ? 'ok' : 'bad'}">${DUMPER_GUARD ? 'BẬT' : 'TẮT'}</div></div>\n<div class="card"><div class="lbl">Watermark truy vết module</div><div class="val ${MODULE_WATERMARK ? 'ok' : 'bad'}">${MODULE_WATERMARK ? 'BẬT' : 'TẮT'}</div></div>\n<div class="card"><div class="lbl">Key đã khoá (revoke)</div><div class="val bad">${BANNED_KEYS.size} key</div></div>
<div class="card"><div class="lbl">Thiết bị khoá toàn diện (mọi IP)</div><div class="val bad">${permaDevices.size} máy</div></div>
<div class="card"><div class="lbl">Thông báo xuống script</div><div class="val ${ANNOUNCE.enabled && ANNOUNCE.message ? 'ok' : ''}">${ANNOUNCE.enabled && ANNOUNCE.message ? 'BẬT (' + _esc(ANNOUNCE.level) + ')' : 'TẮT'}</div></div>\n${SECRET === DEFAULT_SECRET ? '<div class="card" style="grid-column:1/-1;border-color:#ef4444"><div class="lbl" style="color:#ef4444">⚠️ SECRET MẶC ĐỊNH ĐÃ RÒ RỈ — đặt env GODMODE_SECRET NGAY</div></div>' : ''}\n<div class="card"><div class="lbl">Chỉ Android/iOS</div><div class="val ${MOBILE_ONLY ? 'ok' : 'bad'}">${MOBILE_ONLY ? 'BẬT' : 'TẮT'}</div></div>\n<div class="card"><div class="lbl">Đang bị khoá</div><div class="val bad">${banned.size} IP/thiết bị</div></div>\n<div class="card"><div class="lbl">Thiết bị đã kết nối</div><div class="val">${devices.size}</div></div>\n<div class="card"><div class="lbl">Lưu trữ ban vĩnh viễn</div><div class="val ${KV_ENABLED ? 'ok' : 'bad'}">${KV_ENABLED ? 'KV (bền vững)' : 'CHỈ bộ nhớ (mất khi restart)'}</div></div>
<div class="card"><div class="lbl">Lưu trữ log hoạt động</div><div class="val ${KV_ENABLED ? 'ok' : 'bad'}">${KV_ENABLED ? 'KV (không mất khi restart)' : 'CHỈ bộ nhớ (mất khi restart)'}</div></div>\n<div class="card"><div class="lbl">Khoá script lạ (mở được)</div><div class="val ${lockActive ? 'bad' : 'ok'}"><a href="${ADMIN_PATH}/locked" style="color:inherit;text-decoration:none">${lockActive} đang khoá</a></div></div>\n<div class="card"><div class="lbl">Chữ ký request (anti-fake)</div><div class="val ${secInfo.reqSign ? 'ok' : 'bad'}">${secInfo.reqSign ? 'BẬT' : 'TẮT'}</div></div>\n<div class="card"><div class="lbl">Anti-share key</div><div class="val ${secInfo.antiShare ? 'ok' : 'bad'}">${secInfo.antiShare ? 'BẬT' : 'TẮT'} • ${secInfo.shareCount} phát hiện</div></div>\n<div class="card"><div class="lbl">Tấn công fake/fire</div><div class="val ${secInfo.fakeCount + secInfo.fireCount ? 'bad' : 'ok'}">${secInfo.fakeCount} fake • ${secInfo.fireCount} fire</div></div>\n</div>\n\n<div class="panel">\n<h2>🎛 BẬT / TẮT BẢO MẬT</h2>\n<div class="toggle-row">\n<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="autoBan"><button class="${AUTO_BAN ? 'warn' : ''}">${AUTO_BAN ? '⛔ TẮT auto-ban' : '✅ BẬT auto-ban'}</button></form>\n<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="mobileOnly"><button class="${MOBILE_ONLY ? 'warn' : ''}">${MOBILE_ONLY ? '📴 TẮT chỉ-mobile' : '📱 BẬT chỉ-mobile'}</button></form>\n<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="banDesktop"><button class="${BAN_DESKTOP ? 'warn' : ''}">${BAN_DESKTOP ? '💻 TẮT ban desktop' : '💻 BẬT ban desktop'}</button></form>\n<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="blockVmScript"><button class="${BLOCK_VM_SCRIPT ? 'warn' : ''}" style="${BLOCK_VM_SCRIPT ? 'background:linear-gradient(135deg,#f59e0b,#eab308)' : ''}">${BLOCK_VM_SCRIPT ? '🛑 ĐANG chặn VM/proxy (Android/iOS vẫn OK) — bấm để TẮT' : '🔓 BẬT chặn kèo script VM (chỉ chặn VM/proxy/desktop)'}</button></form>\n<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="blockModule10"><button class="${BLOCK_MODULE_10 ? 'warn' : ''}" style="${BLOCK_MODULE_10 ? 'background:linear-gradient(135deg,#f59e0b,#ef4444)' : ''}">${BLOCK_MODULE_10 ? '🛑 ĐANG CHẶN module 10đ (bấm TẮT)' : '🔟 BẬT chặn module chuẩn bị 10đ'}</button></form>\n<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="hardDcBan"><button class="${HARD_DC_BAN ? 'warn' : ''}">${HARD_DC_BAN ? '🌐 TẮT HARD_DC_BAN' : '🌐 BẬT HARD_DC_BAN (proxy/VM→ban)'}</button></form>\n<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="safeMode"><button class="${SAFE_MODE ? '' : 'warn'}">${SAFE_MODE ? '🛡️ TẮT SAFE_MODE (cho phép ban cứng)' : '🛡️ BẬT SAFE_MODE (chống ban nhầm)'}</button></form>\n<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="smartBan"><button class="${SMART_BAN ? '' : 'warn'}">${SMART_BAN ? '🧠 TẮT SMART_BAN' : '🧠 BẬT SMART_BAN (chỉ ban máy ảo/proxy)'}</button></form>\n<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="dumperGuard"><button class="${DUMPER_GUARD ? 'warn' : ''}">${DUMPER_GUARD ? '🕵️ TẮT DUMPER_GUARD' : '🕵️ BẬT DUMPER_GUARD (dump→ban key)'}</button></form>\n<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="moduleWatermark"><button class="${MODULE_WATERMARK ? 'warn' : ''}">${MODULE_WATERMARK ? '💧 TẮT watermark' : '💧 BẬT watermark truy vết'}</button></form>\n<form method="POST" action="${ADMIN_PATH}/toggle" class="inline" style="display:flex;gap:4px"><input type="hidden" name="flag" value="bankey"><input name="key" placeholder="KEY cần khoá (revoke)" style="padding:8px;border-radius:6px;border:1px solid #30363d;background:#0d1117;color:#e6edf3;min-width:180px"><button style="background:linear-gradient(135deg,#ef4444,#b91c1c)">🔨 Khoá key</button></form>\n<form method="POST" action="${ADMIN_PATH}/toggle" class="inline" style="display:flex;gap:4px"><input type="hidden" name="flag" value="unbankey"><input name="key" placeholder="KEY cần mở khoá" style="padding:8px;border-radius:6px;border:1px solid #30363d;background:#0d1117;color:#e6edf3;min-width:180px"><button style="background:linear-gradient(135deg,#22c55e,#15803d)">🔓 Mở khoá key</button></form>\n<div class="panel" style="margin-top:16px;border-color:rgba(239,68,68,.4)">\n<h2 style="color:#ef4444">🚫 BAN TÀI KHOẢN OLM (phút / ngày / tháng / vĩnh viễn)</h2>\n<form method="POST" action="${ADMIN_PATH}/olm-ban" style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end;margin-bottom:14px">\n<div><label style="display:block;font-size:10px;color:#8b949e;margin-bottom:4px">Tài khoản OLM (email/username)</label>\n<input name="olm_user" required placeholder="vd: user@olm.vn" style="padding:7px 10px;border-radius:5px;border:1px solid #30363d;background:#0d1117;color:#c9d1d9;width:200px;font-size:12px"></div>\n<div><label style="display:block;font-size:10px;color:#8b949e;margin-bottom:4px">Thời gian</label>\n<input name="value" type="number" min="1" value="1" style="width:70px;padding:7px 10px;border-radius:5px;border:1px solid #30363d;background:#0d1117;color:#c9d1d9;font-size:12px"></div>\n<div><label style="display:block;font-size:10px;color:#8b949e;margin-bottom:4px">Đơn vị</label>\n<select name="unit" style="padding:7px 8px;border-radius:5px;border:1px solid #30363d;background:#0d1117;color:#c9d1d9;font-size:12px">\n<option value="minute">Phút</option>\n<option value="day" selected>Ngày</option>\n<option value="month">Tháng</option>\n<option value="permanent">Vĩnh viễn</option>\n</select></div>\n<div><label style="display:block;font-size:10px;color:#8b949e;margin-bottom:4px">Lý do</label>\n<input name="reason" placeholder="Vi phạm điều khoản" style="padding:7px 10px;border-radius:5px;border:1px solid #30363d;background:#0d1117;color:#c9d1d9;width:180px;font-size:12px"></div>\n<button type="submit" style="background:linear-gradient(135deg,#ef4444,#b91c1c);padding:8px 18px">🚫 BAN</button>\n</form>\n<div style="font-size:10px;color:#8b949e;margin-bottom:8px">💡 Khi BAN: script trên server tự check — người dùng đăng nhập tài khoản OLM bị ban sẽ thấy thông báo <b style="color:#fca5a5">TÀI KHOẢN OLM ĐÃ BỊ CẤM</b> full-screen. Ban hết hạn tự gỡ. Chọn "Vĩnh viễn" = không hết hạn.</div>\n<table><thead><tr><th>Tài khoản OLM</th><th>Thời gian còn lại</th><th>Lý do</th><th>Thời gian ban</th><th>Thao tác</th></tr></thead>\n<tbody id="olm-ban-tbody"><tr><td colspan="5" class="empty">Đang tải...</td></tr></tbody></table>\n</div>\n<script>\nfunction _escOl(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}\nfunction _unbanOl(olm){\n  var fd=new URLSearchParams(); fd.append('olm_user', olm);\n  fetch('${ADMIN_PATH}/olm-unban',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'},body:fd.toString()}).then(function(){ _refreshOl(); }).catch(function(){ _refreshOl(); });\n}\ndocument.addEventListener('click',function(e){ var b=e.target&&e.target.closest?e.target.closest('button[data-olm-unban]'):null; if(b){ _unbanOl(decodeURIComponent(b.getAttribute('data-olm-unban')||'')); } });\nfunction _renderOl(d){\n  var tb=document.getElementById('olm-ban-tbody');\n  var list=(d&&d.list)||[];\n  if(!list.length){ tb.innerHTML='<tr><td colspan="5" style="text-align:center;color:#00e676;padding:16px;font-size:12px">✅ Chưa có tài khoản OLM nào bị ban.</td></tr>'; return; }\n  var html='';\n  list.forEach(function(r){\n    html+='<tr style="background:rgba(239,68,68,.05)">';\n    html+='<td style="font-family:monospace;font-size:11px;color:#fca5a5">'+_escOl(r.olm)+'</td>';\n    html+='<td style="font-size:11px;color:#ef4444;font-weight:700">'+(r.permanent?'♾️ VĨNH VIÊN':('⏳ '+_escOl(r.remain)))+'</td>';\n    html+='<td style="font-size:10px;color:#ffc107;max-width:180px">'+_escOl(r.reason||'')+'</td>';\n    html+='<td style="font-size:10px;color:#8b949e;font-family:monospace">'+(r.t?new Date(r.t).toLocaleString('vi-VN'):'')+'</td>';\n    html+='<td><button data-olm-unban="'+encodeURIComponent(r.olm)+'" style="background:linear-gradient(135deg,#00b09b,#96c93d)">🔓 UNBAN</button></td>';
    html+='</tr>';\n  });\n  tb.innerHTML=html;\n}\nfunction _refreshOl(){ fetch('${ADMIN_PATH}/olm-bans.json').then(function(r){return r.json();}).then(function(d){_renderOl(d);setTimeout(_refreshOl,5000);}).catch(function(){setTimeout(_refreshOl,5000);}); }\n_refreshOl();\n<\/script>\n</div>\n<div class="hint">Auto-ban: khoá vĩnh viễn IP+thiết bị khi phát hiện máy ảo/proxy/VPN/trình duyệt giả. Chỉ-mobile: chỉ chấp nhận Android/iOS thật. Ban desktop: khoá cả máy tính (mặc định tắt — chỉ từ chối).</div>\n</div>\n\n<div class="grid2">\n<div class="panel">\n<h2>🔑 ĐỔI MẬT KHẨU ADMIN</h2>\n<form method="POST" action="${ADMIN_PATH}/change-password" class="inline" style="flex-direction:column;align-items:stretch">\n<input type="password" name="old" placeholder="Mật khẩu hiện tại" required>\n<input type="password" name="new" placeholder="Mật khẩu mới (tối thiểu 6 ký tự)" required>\n<input type="password" name="confirm" placeholder="Xác nhận mật khẩu mới" required>\n<button>💾 ĐỔI MẬT KHẨU</button>\n</form>\n<div class="hint">Mật khẩu được lưu dạng hash scrypt (không bao giờ lưu plaintext). Sau khi đổi, mọi phiên đăng nhập khác sẽ bị đăng xuất.${KV_ENABLED ? ' Đã lưu vào KV — tồn tại qua restart.' : ' ⚠️ Chưa có KV — đổi mật khẩu sẽ mất khi server restart (đặt env KV_REST_API_URL + KV_REST_API_TOKEN để bền vững).'}</div>\n</div>\n<div class="panel">\n<h2>🛡 ĐỔI SECRET (ẩn API + ký phiên)</h2>\n<form method="POST" action="${ADMIN_PATH}/set-secret" class="inline" style="flex-direction:column;align-items:stretch">\n<input name="secret" placeholder="64 ký tự hex (hoặc để trống = random)" value="">\n<button class="warn">⚠️ ĐỔI SECRET (sẽ đổi API prefix)</button>\n</form>\n<div class="hint">⚠️ Khi đổi SECRET, API prefix thay đổi → PHẢI cập nhật API_SECRET trong connector userscript cho khớp, nếu không script sẽ không kết nối được.${KV_ENABLED ? ' Đã lưu vào KV.' : ' ⚠️ Mất khi restart nếu không có KV.'}</div>\n</div>\n</div>\n\n
<div class="panel" style="border-color:rgba(79,172,254,.4)">
<h2 style="color:#4facfe">📢 THÔNG BÁO XUỐNG SCRIPT (hiển thị toàn màn hình trên thiết bị người dùng)</h2>
<form method="POST" action="${ADMIN_PATH}/announce-save" style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end">
<div><label style="display:block;font-size:10px;color:#8b949e;margin-bottom:4px">Mức</label>
<select name="level" style="padding:8px;border-radius:6px;border:1px solid #30363d;background:#0d1117;color:#c9d1d9;font-size:12px">
<option value="info"${ANNOUNCE.level === 'info' ? ' selected' : ''}>ℹ️ Thông tin</option>
<option value="warn"${ANNOUNCE.level === 'warn' ? ' selected' : ''}>⚠️ Cảnh báo</option>
<option value="error"${ANNOUNCE.level === 'error' ? ' selected' : ''}>⛔ Lỗi / bảo trì</option>
<option value="blocked"${ANNOUNCE.level === 'blocked' ? ' selected' : ''}>🚫 Chặn (không nút đóng)</option>
</select></div>
<div><label style="display:block;font-size:10px;color:#8b949e;margin-bottom:4px">Tiêu đề</label>
<input name="title" value="${_esc(ANNOUNCE.title)}" placeholder="VD: Bảo trì hệ thống 22h00" style="min-width:220px"></div>
<div style="flex:1;min-width:260px"><label style="display:block;font-size:10px;color:#8b949e;margin-bottom:4px">Nội dung</label>
<textarea name="message" rows="3" placeholder="Nội dung thông báo hiển thị giữa màn hình..." style="width:100%;padding:8px;border-radius:6px;border:1px solid #30363d;background:#0d1117;color:#c9d1d9;font-size:12px;font-family:inherit">${_esc(ANNOUNCE.message)}</textarea></div>
<div style="display:flex;flex-direction:column;gap:6px">
<label style="font-size:11px;color:#c9d1d9;display:flex;gap:6px;align-items:center"><input type="checkbox" name="enabled" value="on"${ANNOUNCE.enabled ? ' checked' : ''}> Bật hiển thị</label>
<button style="background:linear-gradient(135deg,#4facfe,#00f2fe);color:#0d1117">💾 Lưu & đẩy xuống</button>
</div>
</form>
<form method="POST" action="${ADMIN_PATH}/announce-clear" style="margin-top:8px"><button class="danger" style="font-size:11px;padding:6px 12px">🧺 Tắt & xoá thông báo</button></form>
<div class="hint">Thông báo đi kèm attest/heartbeat/lock-status; connector v38+ vẽ overlay toàn màn hình gọn đẹp. Mức <b>blocked</b> không cho đóng.</div>
</div>
<div class="panel" style="border-color:rgba(239,68,68,.45)">
<h2 style="color:#ef4444">🛑 KHOÁ TOÀN DIỆN THIẾT BỊ (HWID) — MỌI IP ĐỀU VĨNH VIỄN</h2>
<form method="POST" action="${ADMIN_PATH}/ban-device" class="inline">
<input name="hwid" placeholder="HWID thiết bị (vd: HW2334B90D)" required>
<input name="reason" placeholder="Lý do" value="vi phạm">
<button class="danger">🚫 KHOÁ TOÀN DIỆN</button>
</form>
<div class="hint">Khi khoá: HWID + mọi IP thiết bị từng dùng và IP sau này đều bị chặn; script thu dọn dữ liệu và chặn chạy. Chỉ admin mở khoá thủ công trong danh sách bên dưới.</div>
${permaDevices.size ? '<table style="margin-top:10px"><thead><tr><th>HWID vĩnh viễn</th><th>Thao tác</th></tr></thead><tbody>' + permaRows + '</tbody></table>' : '<div style="font-size:12px;color:#8b949e;padding:6px">Chưa có thiết bị nào bị khoá toàn diện.</div>'}
</div>
<div class="panel">\n<h2>🚫 DANH SÁCH BỊ KHOÁ VĨNH VIỄN (IP + THIẾT BỊ)</h2>\n<form method="POST" action="${ADMIN_PATH}/unban-all" style="margin-bottom:10px" onsubmit="return confirm('Mở khoá TẤT CẢ IP/thiết bị bị khoá + xóa cache IP? Các thiết bị bị khoá nhầm sẽ hoạt động lại ngay.')"><button type="submit" style="background:linear-gradient(135deg,#00b09b,#96c93d);padding:10px 20px;font-size:13px;font-weight:bold">🔓 MỞ KHOÁ TẤT CẢ (reset thiết bị bị khoá)</button></form>\n${banned.size === 0 ? '<div style="font-size:12px;color:#8b949e;padding:8px">Chưa có thiết bị/IP nào bị khoá.</div>' : `<table><thead><tr><th>Đối tượng</th><th>Tên máy</th><th>Nguồn</th><th>Lý do</th><th>Thời gian</th><th></th></tr></thead><tbody>${banRows}</tbody></table>`}\n<h2 style="margin-top:16px">➕ KHOÁ THỦ CÔNG</h2>\n<form method="POST" action="${ADMIN_PATH}/ban" class="inline">\n<input name="target" placeholder="IP hoặc HWID (vd: 1.2.3.4 hoặc HW1234ABCD)" required>\n<input name="reason" placeholder="Lý do" value="manual">\n<button class="danger">🚫 KHOÁ</button>\n</form>\n</div>\n\n<div class="panel">\n<h2>📱 THIẾT BỊ ĐÃ KẾT NỐI (tên máy)</h2>\n <a href="${ADMIN_PATH}/devices" style="color:#4facfe;text-decoration:none;font-size:11px;border:1px solid rgba(79,172,254,.4);padding:4px 10px;border-radius:6px;margin-left:10px">📱 Xem tab Thiết bị & OLM & Môn →</a>\n${devices.size === 0 ? '<div style="font-size:12px;color:#8b949e;padding:8px">Chưa có thiết bị nào xác thực thành công.</div>' : `<table><thead><tr><th>HWID</th><th>Tên máy</th><th>Hệ điều hành</th><th>IP cuối</th><th>Lần cuối</th><th></th></tr></thead><tbody>${devRows}</tbody></table>`}\n</div>\n\n<div class="panel">\n<h2>📜 LOG GẦN NHẤT (có tên máy gửi lên server) — ${ADMIN_LOG.length} bản ghi${KV_ENABLED ? ' · 💾 KV bền vững' : ''}</h2>\n<table><thead><tr><th>Thời gian</th><th>Loại</th><th>Tên máy</th><th>HWID</th><th>IP</th><th>OK</th><th>OLM User</th><th>Chi tiết</th></tr></thead>\n<tbody>${logRows || '<tr><td colspan="7" style="text-align:center;color:#8b949e">Chưa có request nào.</td></tr>'}</tbody></table>\n<div class="hint">verify = nhập key • attest = xác thực thiết bị/mạng • process = giải mã đáp án • fire = nộp bài • ban/reject = bị khoá/từ chối${KV_ENABLED ? ' • 💾 Log được lưu vào KV bền vững — không mất khi restart/cold start.' : ' • ⚠️ Chưa có KV — log mất khi restart; đặt KV_REST_API_URL + KV_REST_API_TOKEN để bền vững.'}</div>\n</div>\n</div></body></html>`;
}
app.get(ADMIN_PATH + '/dashboard', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try { await kvSaveLogs(); await ensureKvLogsLoaded(); } catch (_) {}
  res.send(adminDashboardPage(req.query.msg || ''));
});
function adminLockedPage() {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">\n<title>🔒 Khoá Script Lạ — GOD MODE Admin</title><style>\n*{box-sizing:border-box}body{margin:0;background:#0d1117;font-family:'Segoe UI',system-ui,sans-serif;color:#c9d1d9;padding:20px}\n.wrap{max-width:1200px;margin:0 auto}\n.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:8px}\nh1{font-size:18px;margin:0;background:linear-gradient(90deg,#ef233c,#ffc107);-webkit-background-clip:text;-webkit-text-fill-color:transparent}\na.back{color:#4facfe;text-decoration:none;font-size:12px;border:1px solid rgba(79,172,254,.4);padding:6px 12px;border-radius:6px}\na.logout{color:#ef233c;text-decoration:none;font-size:12px;border:1px solid rgba(239,35,60,.4);padding:6px 12px;border-radius:6px}\n.panel{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;margin-bottom:16px}\n.panel h2{font-size:13px;margin:0 0 12px;color:#ffc107;text-transform:uppercase;letter-spacing:1px}\n.stats{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:14px}\n.stat{background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:10px 16px;font-size:12px}\n.stat .n{font-size:20px;font-weight:900;font-family:monospace}\n.stat.bad .n{color:#ef233c}.stat.ok .n{color:#00e676}.stat.info .n{color:#4facfe}\ntable{width:100%;border-collapse:collapse;font-size:11px}\nth,td{padding:7px 8px;text-align:left;border-bottom:1px solid #21262d;vertical-align:top}\nth{color:#8b949e;font-size:10px;text-transform:uppercase;letter-spacing:.5px;position:sticky;top:0;background:#161b22}\ntr.locked-row{background:rgba(239,35,60,.05)}\n.badge{padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;font-family:monospace}\n.badge.locked{background:rgba(239,35,60,.15);color:#ef233c;border:1px solid rgba(239,35,60,.4)}\n.badge.unlocked{background:rgba(0,230,118,.12);color:#00e676;border:1px solid rgba(0,230,118,.4)}\nbutton{padding:5px 10px;border:none;border-radius:5px;color:#fff;font-weight:700;cursor:pointer;font-size:10px;margin-right:4px;margin-bottom:3px}\nbutton.unlock{background:linear-gradient(135deg,#00b09b,#96c93d)}\nbutton.relock{background:linear-gradient(135deg,#f59e0b,#ef4444)}\nbutton.del{background:rgba(139,148,158,.2);color:#8b949e;border:1px solid #30363d}\nbutton:hover{filter:brightness(1.15)}\n.empty{text-align:center;color:#8b949e;padding:24px;font-size:12px}\n.mono{font-family:monospace;font-size:10px;word-break:break-all}\n.reason{color:#ffc107;font-size:10px;max-width:200px}\n.hint{font-size:10px;color:#8b949e;margin-top:8px;line-height:1.6}\n#refresh-ind{font-size:10px;color:#00e676;font-family:monospace}\n</style></head><body><div class="wrap">\n<div class="top">\n<h1>🔒 THIẾT BỊ BỊ KHOÁ DO PHÁT HIỆN SCRIPT LẠ</h1>\n<div style="display:flex;gap:8px;align-items:center">\n<span id="refresh-ind">● tự động refresh mỗi 5s</span>\n<a href="${ADMIN_PATH}/answers" style="color:#00e676;text-decoration:none;font-size:12px;border:1px solid rgba(0,230,118,.4);padding:6px 12px;border-radius:6px">📚 Kho đáp án</a>\n<a class="back" href="${ADMIN_PATH}/dashboard">⬅ VỀ DASHBOARD</a>\n<a class="logout" href="${ADMIN_PATH}/logout">🚪 Đăng xuất</a>\n</div>\n</div>\n<div class="stats">\n<div class="stat bad"><div class="n" id="st-locked">—</div><div>Đang bị khoá</div></div>\n<div class="stat ok"><div class="n" id="st-unlocked">—</div><div>Đã mở khoá</div></div>\n<div class="stat info"><div class="n" id="st-total">—</div><div>Tổng lượt báo cáo</div></div>\n</div>\n<div class="panel">\n<h2>📋 DANH SÁCH (tự động cập nhật khi có thiết bị bị khoá)</h2>\n<table><thead><tr>\n<th>Trạng thái</th><th>Thời gian khoá</th><th>Tên máy / Thiết bị</th><th>HWID</th><th>IP</th><th>Key</th><th>OLM User</th><th>Lý do</th><th>Lần check cuối</th><th>Thao tác</th>\n</tr></thead><tbody id="tbody"><tr><td colspan="10" class="empty">Đang tải...</td></tr></tbody></table>\n<div class="hint">💡 Khi bấm <b style="color:#00e676">MỞ KHOÁ</b>: thiết bị đó sẽ tự động hoạt động lại trong vòng ~20s (script polling server), key được giữ nguyên — người dùng KHÔNG cần nhập lại key. Bấm <b style="color:#ffc107">KHOÁ LẠI</b> để khoá lại thiết bị đã mở. <b>XOÁ</b> = xoá bản ghi (cũng có tác dụng mở khoá).</div>\n</div>\n</div>\n<script>\nfunction fmt(t){try{return new Date(t).toLocaleString('vi-VN');}catch(e){return '';}}\nfunction esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}\nfunction act(hwid, action){\n  fetch('${ADMIN_PATH}/api/locked/'+action, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({hwid:hwid})})\n    .then(function(){ refresh(); })\n    .catch(function(){});\n}\nfunction render(d){\n  document.getElementById('st-locked').textContent = d.lockedActive||0;\n  document.getElementById('st-total').textContent = d.count||0;\n  document.getElementById('st-unlocked').textContent = (d.count||0)-(d.lockedActive||0);\n  var tb = document.getElementById('tbody');\n  var list = d.locked||[];\n  if(!list.length){ tb.innerHTML = '<tr><td colspan="10" class="empty">✅ Chưa có thiết bị nào bị khoá do script lạ.</td></tr>'; return; }\n  var html = '';\n  list.forEach(function(r){\n    var isLocked = r.status==='locked';\n    html += '<tr class="'+(isLocked?'locked-row':'')+'">';\n    html += '<td><span class="badge '+(isLocked?'locked':'unlocked')+'">'+(isLocked?'🔒 ĐANG KHOÁ':'✅ ĐÃ MỞ')+'</span></td>';\n    html += '<td class="mono">'+fmt(r.t)+'</td>';\n    html += '<td style="color:#00f2fe">'+esc(r.device||'')+'</td>';\n    html += '<td class="mono">'+esc(r.hwid||'')+'</td>';\n    html += '<td class="mono" style="color:#ffc107">'+esc(r.ip||'')+'</td>';\n    html += '<td class="mono">'+esc(r.keyMasked||'')+'</td>';\n    html += '<td class="mono">'+esc(r.olm_user||'')+'</td>';\n    html += '<td class="reason">'+esc(r.reason||'')+'</td>';\n    html += '<td class="mono">'+fmt(r.lastSeen)+'</td>';\n    html += '<td>';\n    if(isLocked){ html += '<button class="unlock" onclick="act(\\''+esc(r.hwid)+'\\',\\'unlock\\')">🔓 MỞ KHOÁ</button>'; }\n    else { html += '<button class="relock" onclick="act(\\''+esc(r.hwid)+'\\',\\'lock\\')">🔒 KHOÁ LẠI</button>'; }\n    html += '<button class="del" onclick="act(\\''+esc(r.hwid)+'\\',\\'delete\\')">🗑 XOÁ</button>';\n    html += '</td></tr>';\n  });\n  tb.innerHTML = html;\n}\nfunction refresh(){\n  fetch('${ADMIN_PATH}/api/locked')\n    .then(function(r){return r.json();})\n    .then(function(d){ render(d); setTimeout(refresh, 5000); })\n    .catch(function(){ setTimeout(refresh, 5000); });\n}\nrefresh();\n<\/script>\n</body></html>`;
}
function adminAnswersPage(msg, query) {
  query = query || {};
  const all = [...answerBank.values()].sort((a, b) => (b.updated_at || 0) - (a.updated_at || 0));
  all.forEach(e => migrateBankEntry(e));
  const qText = String(query.q || '').trim();
  const fSubject = String(query.subject || '').trim();
  const qNorm = normBankText(qText);
  let entries = all.slice();
  if (fSubject) entries = entries.filter(e => entryCanon(e) === fSubject || normBankText(e.subject) === normBankText(fSubject) || String(e.cate || '') === fSubject);
  if (qNorm) entries = entries.filter(e => {
    if (normBankText(bankSubjectDisplay(e)).includes(qNorm)) return true;
    return (e.exercises || []).some(ex => normBankText(ex.title).includes(qNorm) || (ex.items || []).some(it => normBankText(it.title || '').includes(qNorm)));
  });
  const groups = new Map();
  entries.forEach(e => {
    const key = entryCanon(e) || normBankText(e.subject) || ('cate::' + (e.cate || e.key));
    if (!groups.has(key)) groups.set(key, { label: bankSubjectDisplay(e), entries: [] });
    const g = groups.get(key);
    const lab = bankSubjectDisplay(e);
    if (lab && (!g.label || /^Môn /.test(g.label) || lab.length > String(g.label).length)) g.label = lab;
    g.entries.push(e);
  });
  let _bankAllEx = [];
  entries.forEach(e => { _bankAllEx = _bankAllEx.concat(e.exercises || []); });
  _bankAllEx = dedupeExerciseList(_bankAllEx);
  const totalEx = _bankAllEx.length;
  const totalQ = _bankAllEx.reduce((s, ex) => s + (ex.count || (ex.items || []).length || 0), 0);
  const totalHits = entries.reduce((s, e) => s + numHits(e.hits), 0);
  const subjectOpts = [];
  const seenS = new Set();
  all.forEach(e => {
    const lab = bankSubjectDisplay(e);
    const k = entryCanon(e) || normBankText(lab);
    if (k && !seenS.has(k)) { seenS.add(k); subjectOpts.push({ k: k, lab: lab }); }
  });
  const groupCards = [...groups.entries()].map(([gk, g]) => {
    let _gExList = [];
    g.entries.forEach(e => { _gExList = _gExList.concat(e.exercises || []); });
    _gExList = dedupeExerciseList(_gExList);
    const gEx = _gExList.length;
    const gQ = _gExList.reduce((s, ex) => s + (ex.count || (ex.items || []).length || 0), 0);
    let exHtml = '';
    _gExList.forEach(ex => {
      const owner = g.entries.find(e => (e.exercises || []).some(x => x === ex)) || g.entries[0];
      const qa = (ex.items || []).map((it, i) => '<div class="qa"><span class="qn">Câu ' + (i + 1) + '</span> ' + _esc(it.stem || it.title || '') + ' <span class="ans">→ ' + _esc((it.answers || []).join(' | ')) + '</span></div>').join('');
      const ownerKey = owner ? owner.key : '';
      exHtml += '<details class="ex"><summary><span class="ex-t">📝 ' + _esc(ex.title || 'Bài tập chưa rõ tên') + '</span><span class="ex-meta">' + (ex.count || 0) + ' câu · ' + (ex.hits || 0) + ' lượt' + (ex.courseware ? ' · cw ' + _esc(ex.courseware) : '') + '</span></summary><div class="qa-wrap">' + (qa || '<div class="empty-mini">Chưa có đáp án.</div>') + '<form method="POST" action="' + ADMIN_PATH + '/answers/exercise-delete" class="ex-del"><input type="hidden" name="key" value="' + _esc(ownerKey) + '"><input type="hidden" name="exKey" value="' + _esc(ex.key) + '"><button class="danger sm">🗑 Xoá bài tập này</button></form></div></details>';
    });
    const allCates = [...new Set(g.entries.flatMap(e => [e.cate, ...(e.exercises || []).map(ex => ex.cate)]).filter(Boolean).map(String))];
    const actHtml = g.entries.map(e =>
      '<div class="entry-row">' + allCates.map(c => '<span class="chip">cate: ' + _esc(c) + '</span>').join('')
      + (e.olm_user ? '<span class="chip user">' + _esc(e.olm_user) + '</span>' : '')
      + '<a href="' + ADMIN_PATH + '/answers/item-export?key=' + encodeURIComponent(e.key) + '&format=txt" download class="btn mini blue">📄 TXT</a>'
      + '<a href="' + ADMIN_PATH + '/answers/item-export?key=' + encodeURIComponent(e.key) + '&format=json" download class="btn mini green">⬇️ JSON</a>'
      + '<form method="POST" action="' + ADMIN_PATH + '/answers/delete" class="inline"><input type="hidden" name="key" value="' + _esc(e.key) + '"><button class="danger sm">🗑 Xoá môn này</button></form></div>'
    ).join('');
    return '<div class="subj-card"><div class="subj-head"><div class="subj-name">📚 ' + _esc(g.label) + '</div><div class="subj-counts">' + gEx + ' bài tập · ' + gQ + ' câu</div></div><div class="ex-list">' + (exHtml || '<div class="empty-mini">Chưa có bài tập.</div>') + '</div><div class="subj-actions">' + actHtml + '</div></div>';
  }).join('');
  const subjectOptsHtml = subjectOpts.map(o => '<option value="' + _esc(o.k) + '"' + (fSubject === o.k ? ' selected' : '') + '>' + _esc(o.lab) + '</option>').join('');
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>📚 Kho Đáp Án Theo Môn — GOD MODE Admin</title><style>
*{box-sizing:border-box}body{margin:0;background:#0d1117;font-family:'Segoe UI',system-ui,sans-serif;color:#c9d1d9;padding:20px}
.wrap{max-width:1280px;margin:0 auto}
.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:8px}
h1{font-size:18px;margin:0;background:linear-gradient(90deg,#00e676,#4facfe);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
a.back{color:#4facfe;text-decoration:none;font-size:12px;border:1px solid rgba(79,172,254,.4);padding:6px 12px;border-radius:6px}
a.logout{color:#ef233c;text-decoration:none;font-size:12px;border:1px solid rgba(239,35,60,.4);padding:6px 12px;border-radius:6px}
.panel{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;margin-bottom:16px}
.panel h2{font-size:13px;margin:0 0 12px;color:#00e676;text-transform:uppercase;letter-spacing:1px}
.stats{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:14px}
.stat{background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:10px 16px;font-size:12px}
.stat .n{font-size:20px;font-weight:900;font-family:monospace}
.stat.ok .n{color:#00e676}.stat.info .n{color:#4facfe}
.filter-bar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px}
.filter-bar select,.filter-bar input{padding:8px 10px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#c9d1d9;font-size:12px;outline:none}
.filter-bar input{min-width:260px}
button{padding:6px 12px;border:none;border-radius:6px;background:linear-gradient(135deg,#00b09b,#96c93d);color:#fff;font-weight:700;cursor:pointer;font-size:11px}
button.danger{background:linear-gradient(135deg,#d90429,#ef233c)}
button.sm{padding:4px 10px;font-size:10px}
.btn{display:inline-block;text-decoration:none;padding:4px 10px;font-size:10px;font-weight:700;border-radius:5px}
.btn.mini.blue{background:linear-gradient(135deg,#4facfe,#00f2fe);color:#0d1117}
.btn.mini.green{background:linear-gradient(135deg,#00b09b,#96c93d);color:#fff}
.btn.reset{color:#8b949e;border:1px solid #30363d;padding:6px 12px;border-radius:6px;font-size:11px}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:14px}
.subj-card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:14px;display:flex;flex-direction:column;gap:10px}
.subj-head{display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;border-bottom:1px solid #21262d;padding-bottom:8px}
.subj-name{font-size:14px;font-weight:800;color:#00e676}
.subj-counts{font-size:10px;color:#4facfe;font-family:monospace}
.chip{display:inline-block;background:#0d1117;border:1px solid #30363d;border-radius:4px;padding:2px 7px;font-size:9.5px;color:#8b949e;font-family:monospace}
.chip.user{color:#fca5a5;border-color:rgba(239,68,68,.35)}
.ex-list{display:flex;flex-direction:column;gap:8px;max-height:520px;overflow-y:auto;padding-right:2px}
details.ex{background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:8px}
details.ex summary{cursor:pointer;display:flex;flex-direction:column;gap:3px}
.ex-t{font-size:12px;font-weight:700;color:#c9d1d9}
.ex-meta{font-size:10px;color:#8b949e}
.qa-wrap{margin-top:8px;display:flex;flex-direction:column;gap:4px}
.qa{font-size:11px;color:#c9d1d9;line-height:1.5;border-left:2px solid rgba(79,172,254,.35);padding-left:8px}
.qa .qn{color:#4facfe;font-weight:700;font-family:monospace}
.qa .ans{color:#ffd166;font-weight:700}
.ex-del{margin-top:8px}
.subj-actions{display:flex;gap:6px;flex-wrap:wrap;align-items:center;border-top:1px solid #21262d;padding-top:8px}
.entry-row{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
.inline{display:inline;margin:0}
.empty-mini{font-size:11px;color:#8b949e;padding:6px}
.empty{text-align:center;color:#8b949e;padding:30px;font-size:13px;grid-column:1/-1}
.msg{padding:8px 12px;border-radius:6px;font-size:12px;margin-bottom:12px;background:rgba(0,230,118,.1);border:1px solid rgba(0,230,118,.3);color:#00e676}
.hint{font-size:10px;color:#8b949e;margin-top:14px;line-height:1.7}
.promo-banner{margin:12px 0;padding:12px 16px;border-radius:10px;background:linear-gradient(135deg,rgba(255,193,7,.14),rgba(239,68,68,.14));border:1px solid rgba(255,193,7,.45);color:#ffd166;font-weight:700;font-size:12.5px;text-align:center;letter-spacing:.3px}
</style></head><body><div class="wrap">
<div class="top">
<h1>📚 KHO ĐÁP ÁN THEO MÔN — BÀI TẬP → CÂU HỎI / ĐÁP ÁN</h1>
<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
<a class="back" href="${ADMIN_PATH}/dashboard">⬅ VỀ DASHBOARD</a>
<a class="logout" href="${ADMIN_PATH}/logout">🚪 Đăng xuất</a>
</div>
</div>
${msg ? `<div class="msg">${_esc(msg)}</div>` : ''}
<div class="stats">
<div class="stat info"><div class="n">${groups.size}</div><div>Môn (cột)</div></div>
<div class="stat info"><div class="n">${totalEx}</div><div>Bài tập</div></div>
<div class="stat ok"><div class="n">${totalQ}</div><div>Tổng câu trả lời</div></div>
<div class="stat info"><div class="n">${totalHits.toLocaleString('vi-VN')}</div><div>Lượt tra cứu</div></div>
<div class="stat ${(KV_ENABLED || BANK_FILE_OK) ? 'ok' : ''}"><div class="n">${KV_ENABLED ? 'KV' : (BANK_FILE_OK ? 'FILE' : 'MEMORY')}</div><div>${KV_ENABLED ? 'Lưu bền vững qua restart' : (BANK_FILE_OK ? 'Lưu file cục bộ, bền vững qua restart' : 'Chưa có lưu trữ bền vững — mất khi restart')}</div></div>
</div>
<div class="promo-banner">📢 THUÊ KEY — IB TÁO GIÁ HẠT RẺ &nbsp;·&nbsp; ✍️ by THIÊN TAI TÙ TỘI</div>
<div class="panel">
<h2>🔍 LỌC MÔN HỌC / TÌM BÀI TẬP</h2>
<form method="GET" action="${ADMIN_PATH}/answers" class="filter-bar">
<select name="subject"><option value="">— Tất cả môn —</option>${subjectOptsHtml}</select>
<input name="q" value="${_esc(qText)}" placeholder="Tìm theo tên bài tập / nội dung câu hỏi...">
<button type="submit">🔎 Lọc / Tìm</button>
<a class="btn reset" href="${ADMIN_PATH}/answers">↺ Xoá lọc</a>
</form>
<div class="toolbar">
<a href="${ADMIN_PATH}/answers/export.json" download style="background:linear-gradient(135deg,#00b09b,#96c93d);color:#fff;text-decoration:none;padding:8px 14px;border-radius:6px;font-size:11px;font-weight:700">⬇️ Toàn bộ — JSON</a>
<a href="${ADMIN_PATH}/answers/export.txt" download style="background:linear-gradient(135deg,#4facfe,#00f2fe);color:#0d1117;text-decoration:none;padding:8px 14px;border-radius:6px;font-size:11px;font-weight:700">⬇️ Toàn bộ — TXT</a>
<span style="font-size:10px;color:#8b949e">📥 TXT đọc được ngay; JSON để sao lưu/khôi phục cấu trúc môn → bài tập → câu hỏi.</span>
<form method="POST" action="${ADMIN_PATH}/answers/clear-all" class="inline" onsubmit="return confirm('Xoá TOÀN BỘ kho đáp án? Không thể hoàn tác.')">
<button class="danger">🧹 Xoá toàn bộ kho đáp án</button>
</form>
</div>
<div class="hint">💡 Mỗi môn học là một <b>cột/thẻ riêng</b>; bên trong liệt kê từng <b>bài tập</b> (tên bài tập được script tự lấy), mở từng bài tập để xem <b>câu hỏi + đáp án</b>. Kho tự lưu mỗi lần máy user giải đáp án (route /process). Script chờ 6s (thử lại 20s, 45s) rồi tra kho khi đang ở <b>trang bài tập</b>; trang danh sách/lớp học sẽ không tra kho.</div>
</div>
<div class="grid">${groupCards || '<div class="empty">✅ Chưa có dữ liệu. Khi script giải đáp án trên trang bài tập, môn → bài tập → đáp án sẽ tự hiển thị ở đây.</div>'}</div>
<div class="hint">🗑 <b>Xoá môn này</b> = xoá toàn bộ bài tập thuộc dòng môn (cate) đó; <b>Xoá bài tập này</b> = xoá đúng một bài tập. Thẻ môn hiển thị cả tài khoản nguồn (nếu có) và link tải TXT/JSON riêng.</div>
</div></body></html>`;
}
function adminDevicesPage() {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">\n<title>📱 Thiết bị & OLM — GOD MODE Admin</title><style>\n*{box-sizing:border-box}body{margin:0;background:#0d1117;font-family:'Segoe UI',system-ui,sans-serif;color:#c9d1d9;padding:20px}\n.wrap{max-width:1200px;margin:0 auto}\n.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:8px}\nh1{font-size:18px;margin:0;background:linear-gradient(90deg,#00f2fe,#4facfe);-webkit-background-clip:text;-webkit-text-fill-color:transparent}\na.back{color:#4facfe;text-decoration:none;font-size:12px;border:1px solid rgba(79,172,254,.4);padding:6px 12px;border-radius:6px}\na.logout{color:#ef233c;text-decoration:none;font-size:12px;border:1px solid rgba(239,35,60,.4);padding:6px 12px;border-radius:6px}\n.panel{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;margin-bottom:16px}\n.panel h2{font-size:13px;margin:0 0 12px;color:#00f2fe;text-transform:uppercase;letter-spacing:1px}\n.stats{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:14px}\n.stat{background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:10px 16px;font-size:12px}\n.stat .n{font-size:20px;font-weight:900;font-family:monospace}\n.stat.info .n{color:#4facfe}.stat.ok .n{color:#00e676}\ntable{width:100%;border-collapse:collapse;font-size:11px}\nth,td{padding:7px 8px;text-align:left;border-bottom:1px solid #21262d;vertical-align:top}\nth{color:#8b949e;font-size:10px;text-transform:uppercase;letter-spacing:.5px;position:sticky;top:0;background:#161b22}\n.mono{font-family:monospace;font-size:10px;word-break:break-all}\n.empty{text-align:center;color:#8b949e;padding:24px;font-size:12px}\n.hint{font-size:10px;color:#8b949e;margin-top:8px;line-height:1.6}\n#refresh-ind{font-size:10px;color:#00e676;font-family:monospace}\n.badge{padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;font-family:monospace;background:rgba(79,172,254,.15);color:#4facfe;border:1px solid rgba(79,172,254,.4)}\n</style></head><body><div class="wrap">\n<div class="top">\n<h1>📱 THIẾT BỊ & TÀI KHOẢN OLM & MÔN ĐANG LÀM</h1>\n<div style="display:flex;gap:8px;align-items:center">\n<span id="refresh-ind">● tự động refresh mỗi 5s</span>\n<a href="${ADMIN_PATH}/answers" style="color:#00e676;text-decoration:none;font-size:12px;border:1px solid rgba(0,230,118,.4);padding:6px 12px;border-radius:6px">📚 Kho đáp án</a>\n<a class="back" href="${ADMIN_PATH}/dashboard">⬅ VỀ DASHBOARD</a>\n<a class="logout" href="${ADMIN_PATH}/logout">🚪 Đăng xuất</a>\n</div>\n</div>\n<div class="stats">\n<div class="stat info"><div class="n" id="st-dev">—</div><div>Thiết bị hoạt động</div></div>\n<div class="stat ok"><div class="n" id="st-olm">—</div><div>Có tài khoản OLM</div></div>\n</div>\n<div class="panel">\n<h2>📋 DANH SÁCH (tự động cập nhật)</h2>\n<table><thead><tr>\n<th>Tên máy</th><th>HWID</th><th>IP</th><th>Tài khoản OLM</th><th>Môn (id_cate)</th><th>Chế độ làm bài</th><th>Lần hoạt động cuối</th>\n</tr></thead><tbody id="tbody"><tr><td colspan="7" class="empty">Đang tải...</td></tr></tbody></table>\n<div class="hint">💡 Cột <b>Tài khoản OLM</b> được ghi nhận khi user đăng nhập key (gửi kèm olm_user). Cột <b>Môn (id_cate)</b> + <b>Chế độ</b> được ghi nhận khi user nộp bài (/fire) — id_cate là mã môn của OLM. Thiết bị không hoạt động quá 24h tự biến mất.</div>\n</div>\n</div>\n<script>\nfunction fmt(t){try{return new Date(t).toLocaleString('vi-VN');}catch(e){return '';}}\nfunction esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}\nfunction modeLabel(m){ if(!m) return '—'; if(m==='exam') return '📝 Kiểm tra (exam)'; if(m==='video') return '🎬 Video'; return '✏️ Luyện tập (practice)'; }\nfunction render(d){\n  document.getElementById('st-dev').textContent = d.count||0;\n  document.getElementById('st-olm').textContent = d.withOlm||0;\n  var tb = document.getElementById('tbody');\n  var list = d.list||[];\n  if(!list.length){ tb.innerHTML = '<tr><td colspan="7" class="empty">✅ Chưa có thiết bị nào hoạt động. Khi user đăng nhập key & nộp bài sẽ hiện ở đây.</td></tr>'; return; }\n  var html = '';\n  list.forEach(function(r){\n    html += '<tr>';\n    html += '<td style="color:#00f2fe">'+esc(r.device||'')+'</td>';\n    html += '<td class="mono">'+esc(r.hwid||'')+'</td>';\n    html += '<td class="mono" style="color:#ffc107">'+esc(r.ip||'')+'</td>';\n    html += '<td class="mono" style="color:#fca5a5;font-weight:700">'+(r.olm_user?esc(r.olm_user):'<span style="color:#8b949e">— chưa gửi</span>')+'</td>';\n    html += '<td class="mono">'+(r.id_cate?('<span class="badge">'+esc(r.id_cate)+'</span>'):'<span style="color:#8b949e">—</span>')+'</td>';\n    html += '<td style="font-size:10px">'+modeLabel(r.mode)+'</td>';\n    html += '<td class="mono">'+fmt(r.lastSeen)+'</td>';\n    html += '</tr>';\n  });\n  tb.innerHTML = html;\n}\nfunction refresh(){\n  fetch('${ADMIN_PATH}/api/devices')\n    .then(function(r){return r.json();})\n    .then(function(d){ render(d); setTimeout(refresh, 5000); })\n    .catch(function(){ setTimeout(refresh, 5000); });\n}\nrefresh();\n<\/script>\n</body></html>`;
}
app.get(ADMIN_PATH + '/devices', (req, res) => {
  if (!requireAdmin(req, res)) return;
  res.send(adminDevicesPage());
});
app.get(ADMIN_PATH + '/api/devices', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const now = Date.now();
  const DAY = 24 * 3600 * 1e3;
  const list = [];
  let withOlm = 0;
  const all = new Set;
  deviceActivity.forEach((v, k) => all.add(k));
  devices.forEach((v, k) => all.add(k));
  all.forEach(hwid => {
    const act = deviceActivity.get(hwid) || {};
    const dev = devices.get(hwid) || {};
    const lastSeen = act.lastSeen || dev.lastSeen || 0;
    if (lastSeen && now - lastSeen > DAY) return;
    if (act.olm_user) withOlm++;
    list.push({
      hwid: hwid,
      device: act.device || dev.name || '',
      ip: act.ip || dev.ip || '',
      olm_user: act.olm_user || '',
      id_cate: act.id_cate || '',
      mode: act.mode || '',
      id_user: act.id_user || '',
      lastSeen: lastSeen
    });
  });
  list.sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0));
  res.json({
    list: list.slice(0, 200),
    count: list.length,
    withOlm: withOlm
  });
});
app.get(ADMIN_PATH + '/answers', (req, res) => {
  if (!requireAdmin(req, res)) return;
  res.send(adminAnswersPage(req.query.msg || '', req.query));
});
app.get(ADMIN_PATH + '/answers.json', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const list = [...answerBank.values()].sort((a, b) => (b.updated_at || 0) - (a.updated_at || 0));
  list.forEach(e => migrateBankEntry(e));
  sanitizeBankHits();
  res.json({ list: list });
});
app.post(ADMIN_PATH + '/answers/delete', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const k = String((req.body && req.body.key) || '');
  const _e = answerBank.get(k);
  if (_e) {
    tombMark('subject', k);
    if (_e.cate) tombMark('subject', 'cate::' + _e.cate);
    if (_e.canon) tombMark('subject', 'canon::' + _e.canon);
    (_e.exercises || []).forEach(ex => ex && tombMark('exercise', ex.key));
    answerBank.delete(k);
    kvSaveState();
    adminLog('bank-delete', { key: k });
  }
  res.redirect(ADMIN_PATH + '/answers?msg=' + encodeURIComponent('Đã xoá kho môn: ' + k));
});
app.post(ADMIN_PATH + '/answers/exercise-delete', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const k = String((req.body && req.body.key) || '');
  const exKey = String((req.body && req.body.exKey) || '');
  const entry = answerBank.get(k);
  if (entry && Array.isArray(entry.exercises)) {
    tombMark('exercise', exKey);
    entry.exercises = entry.exercises.filter(ex => ex && ex.key !== exKey);
    migrateBankEntry(entry);
    if (!entry.exercises.length) answerBank.delete(k);
    kvSaveState();
    adminLog('bank-exercise-delete', { key: k, exKey: exKey });
  }
  res.redirect(ADMIN_PATH + '/answers?msg=' + encodeURIComponent('Đã xoá bài tập khỏi kho.'));
});
app.post(ADMIN_PATH + '/answers/clear-all', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const n = answerBank.size;
  bankTombstones.set('subject::*', Date.now());
  answerBank.clear();
  kvSaveState();
  adminLog('bank-clear', { entries: n });
  res.redirect(ADMIN_PATH + '/answers?msg=' + encodeURIComponent('Đã xoá toàn bộ kho đáp án (' + n + ' môn).'));
});
function answersExportPayload() {
  const list = [...answerBank.values()].sort((a, b) => (b.updated_at || 0) - (a.updated_at || 0));
  list.forEach(e => migrateBankEntry(e));
  const subjects = list.map(e => ({
    key: e.key,
    subject: e.subject || '',
    subject_label: bankSubjectDisplay(e),
    cate: e.cate || null,
    courseware: e.courseware || null,
    olm_user: e.olm_user || '',
    sources: e.sources || [],
    count: dedupeExerciseList(e.exercises || []).reduce((s2, ex) => s2 + (ex.count || (ex.items || []).length || 0), 0),
    hits: numHits(e.hits),
    created_at: e.created_at || 0,
    updated_at: e.updated_at || 0,
    exercises: dedupeExerciseList(e.exercises || []).map(ex => ({
      key: ex.key,
      title: ex.title || '',
      cate: ex.cate || null,
      courseware: ex.courseware || null,
      count: ex.count || (ex.items || []).length || 0,
      hits: numHits(ex.hits),
      updated_at: ex.updated_at || 0,
      items: (ex.items || []).map(it => ({
        index: it.index,
        qid: it.qid || null,
        title: it.title || '',
        stem: it.stem || '',
        answers: it.answers || []
      }))
    })),
    items: (e.items || []).map(it => ({
      index: it.index,
      qid: it.qid || null,
      title: it.title || '',
      stem: it.stem || '',
      answers: it.answers || []
    }))
  }));
  return {
    exported_at: new Date().toISOString(),
    total_subjects: subjects.length,
    total_exercises: subjects.reduce((s, x) => s + (x.exercises || []).length, 0),
    total_questions: subjects.reduce((s, x) => s + x.count, 0),
    subjects: subjects
  };
}
function answersToText(payload) {
  const L = [];
  const bar = "═══════════════════════════════════════════════════";
  L.push(bar);
  L.push("  📚 KHO ĐÁP ÁN THEO MÔN — GOD MODE ADMIN");
  L.push("  Xuất lúc: " + new Date().toLocaleString("vi-VN"));
  L.push("  Tổng môn: " + payload.total_subjects + " | Tổng bài tập: " + (payload.total_exercises || 0) + " | Tổng câu: " + payload.total_questions);
  L.push(bar);
  (payload.subjects || []).forEach((s, si) => {
    L.push("");
    L.push("╔════════ MÔN " + (si + 1) + ": " + (s.subject_label || s.subject || s.cate || s.key) + " ════════╗");
    if (s.cate) L.push("  🆔 ID_CATE (môn): " + s.cate);
    if (s.courseware) L.push("  🆔 ID_COURSEWARE: " + s.courseware);
    if (s.olm_user) L.push("  👤 Tài khoản nguồn: " + s.olm_user);
    L.push("  📊 Bài tập: " + (s.exercises || []).length + " · Câu: " + s.count + " · Lượt tra: " + s.hits);
    if (s.updated_at) L.push("  🔄 Cập nhật: " + new Date(s.updated_at).toLocaleString("vi-VN"));
    const exList = (s.exercises && s.exercises.length) ? s.exercises : [{ title: "Bài tập", items: s.items || [] }];
    exList.forEach((ex, ei) => {
      L.push("");
      L.push("  📝 Bài tập " + (ei + 1) + ": " + (ex.title || "Chưa rõ tên") + " (" + (ex.count || (ex.items || []).length) + " câu)");
      L.push("  " + "─".repeat(44));
      (ex.items || []).forEach((it, i) => {
        const stem = String(it.stem || it.title || "");
        const answers = (it.answers || []).filter(a => a && a !== "Không tự động trích xuất được." && a !== "Lỗi giải mã" && a !== "Dữ liệu câu hỏi quá lớn — bỏ qua");
        L.push("  ❓ Câu " + (i + 1) + (it.qid ? " [qid:" + it.qid + "]" : ""));
        if (stem) L.push("     Câu hỏi: " + stem);
        const ansText = answers.length ? answers.join("  |  ") : "(Chưa có đáp án)";
        L.push("  ✅ **ĐÁP ÁN: " + ansText + "**");
      });
    });
  });
  L.push("");
  L.push(bar);
  L.push("  📢 THUÊ KEY — IB TÁO GIÁ HẠT RẺ");
  L.push("  ✍️  by THIÊN TAI TÙ TỘI");
  L.push(bar);
  return L.join("\n") + "\n";
}
function exportStamp() {
  return new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
}
app.get(ADMIN_PATH + '/answers/export.json', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const payload = answersExportPayload();
  adminLog('bank-export', { scope: 'all', format: 'json', subjects: payload.total_subjects, questions: payload.total_questions, ip: getClientIp(req) });
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="kho-dap-an-' + exportStamp() + '.json"');
  res.send(Buffer.from(JSON.stringify(payload, null, 2), 'utf8'));
});
app.get(ADMIN_PATH + '/answers/export.txt', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const payload = answersExportPayload();
  adminLog('bank-export', { scope: 'all', format: 'txt', subjects: payload.total_subjects, questions: payload.total_questions, ip: getClientIp(req) });
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="kho-dap-an-' + exportStamp() + '.txt"');
  res.send(Buffer.from(answersToText(payload), 'utf8'));
});
app.get(ADMIN_PATH + '/answers/item-export', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const key = safeStr(req.query && req.query.key || '', 80);
  const fmt = String((req.query && req.query.format) || 'txt').toLowerCase();
  let entry = answerBank.get(key) || null;
  if (!entry) entry = [...answerBank.values()].find(e => String(e.cate || '') === key || entryCanon(e) === key || normBankText(e.subject) === normBankText(key) || (e.exercises || []).some(ex => String(ex.cate || '') === key)) || null;
  if (!entry) return res.status(404).send('Khong tim thay mon: ' + key);
  const payload = answersExportPayload();
  const subj = payload.subjects.find(s => s.key === entry.key) || payload.subjects[0];
  const safeKey = String(key).replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 60) || 'mon';
  adminLog('bank-export', { scope: 'item', format: fmt, key: key, questions: subj.count, ip: getClientIp(req) });
  if (fmt === 'json') {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="dap-an-mon-' + safeKey + '-' + exportStamp() + '.json"');
    res.send(Buffer.from(JSON.stringify(subj, null, 2), 'utf8'));
  } else {
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="dap-an-mon-' + safeKey + '-' + exportStamp() + '.txt"');
    res.send(Buffer.from(answersToText({ total_subjects: 1, total_exercises: (subj.exercises || []).length, total_questions: subj.count, subjects: [subj] }), 'utf8'));
  }
});
app.get(ADMIN_PATH + '/locked', (req, res) => {
  if (!requireAdmin(req, res)) return;
  res.send(adminLockedPage());
});
app.post(ADMIN_PATH + '/change-password', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const {old: old, new: npass, confirm: confirm} = req.body || {};
  if (!verifyPass(old, ADMIN_HASH)) return res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent('❌ Sai mật khẩu hiện tại!'));
  if (!npass || npass.length < 6) return res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent('❌ Mật khẩu mới tối thiểu 6 ký tự!'));
  if (npass !== confirm) return res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent('❌ Xác nhận mật khẩu không khớp!'));
  ADMIN_HASH = hashPass(npass);
  adminSessions.clear();
  kvSaveState();
  adminLog('admin', {
    action: 'change-password',
    ip: getClientIp(req)
  });
  res.setHeader('Set-Cookie', 'god_admin=; Path=/; Max-Age=0');
  res.redirect(ADMIN_PATH + '?msg=' + encodeURIComponent('✅ Đổi mật khẩu thành công! Đăng nhập lại bằng mật khẩu mới.'));
});
app.post(ADMIN_PATH + '/toggle', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const flag = req.body && req.body.flag || '';
  let msg = '✅ Đã cập nhật.';
  if (flag === 'autoBan') {
    AUTO_BAN = !AUTO_BAN;
    msg = AUTO_BAN ? '✅ Đã BẬT auto-ban.' : '⚠️ Đã TẮT auto-ban.';
  } else if (flag === 'mobileOnly') {
    MOBILE_ONLY = !MOBILE_ONLY;
    msg = MOBILE_ONLY ? '✅ Đã BẬT chỉ chấp nhận Android/iOS.' : '⚠️ Đã TẮT chỉ-mobile (cho phép desktop).';
  } else if (flag === 'banDesktop') {
    BAN_DESKTOP = !BAN_DESKTOP;
    msg = BAN_DESKTOP ? '✅ Đã BẬT ban desktop.' : '⚠️ Đã TẮT ban desktop (desktop chỉ bị từ chối, không khoá).';
  } else if (flag === 'blockVmScript') {
    BLOCK_VM_SCRIPT = !BLOCK_VM_SCRIPT;
    msg = BLOCK_VM_SCRIPT ? '✅ Đã BẬT SMART_VM_BLOCK: chỉ chặn VM/proxy/datacenter/desktop; Android/iOS thật vẫn kéo code bình thường.' : '⚠️ Đã TẮT chặn (mọi người đều kéo code được, HARD_DC_BAN vẫn tự chặn datacenter).';
  } else if (flag === 'blockModule10') {
    BLOCK_MODULE_10 = !BLOCK_MODULE_10;
    msg = BLOCK_MODULE_10 ? '✅ Đã BẬT chặn module chuẩn bị 10 điểm (KHÔNG gửi xuống script).' : '⚠️ Đã TẮT chặn (module 10 điểm gửi xuống bình thường).';
  } else if (flag === 'hardDcBan') {
    HARD_DC_BAN = !HARD_DC_BAN;
    msg = HARD_DC_BAN ? '✅ Đã BẬT HARD_DC_BAN (IP datacenter/proxy gọi API → BAN NGAY).' : '⚠️ Đã TẮT HARD_DC_BAN.';
  } else if (flag === 'safeMode') {
    SAFE_MODE = !SAFE_MODE;
    msg = SAFE_MODE ? '✅ Đã BẬT SAFE_MODE: auto-ban chỉ log + từ chối, KHÔNG khoá vĩnh viễn (an toàn, tránh ban nhầm).' : '⚠️ Đã TẮT SAFE_MODE — auto-ban sẽ khoá vĩnh viễn IP/thiết bị (dễ ban nhầm nhà mạng CGNAT).';
  } else if (flag === 'smartBan') {
    SMART_BAN = !SMART_BAN;
    msg = SMART_BAN ? '✅ Đã BẬT SMART_BAN: heuristic chỉ nhắm máy ảo/proxy; máy thật Android/iOS không bị auto-ban. LƯU Ý: ban do admin vẫn tuyệt đối, không tự mở.' : '⚠️ Đã TẮT SMART_BAN — heuristic bám chặt hơn (dễ ban nhầm nhà mạng CGNAT).';
  } else if (flag === 'dumperGuard') {
    DUMPER_GUARD = !DUMPER_GUARD;
    msg = DUMPER_GUARD ? '✅ Đã BẬT DUMPER_GUARD (phát hiện dump → ban key+hwid+ip).' : '⚠️ Đã TẮT DUMPER_GUARD.';
  } else if (flag === 'moduleWatermark') {
    MODULE_WATERMARK = !MODULE_WATERMARK;
    msg = MODULE_WATERMARK ? '✅ Đã BẬT watermark truy vết module.' : '⚠️ Đã TẮT watermark.';
  } else if (flag === 'bankey') {
    const kk = String((req.body && req.body.key) || '').trim().toUpperCase();
    if (kk) {
      BANNED_KEYS.add(kk);
      kvSaveState();
      msg = '🔨 Đã KHOÁ key ' + maskKey(kk) + ' — mọi chức năng dùng key này bị server từ chối (revoke) và client tự xoá dữ liệu.';
    } else msg = 'Thiếu key để khoá.';
  } else if (flag === 'unbankey') {
    const uk = String((req.body && req.body.key) || '').trim().toUpperCase();
    if (uk && BANNED_KEYS.delete(uk)) {
      kvSaveState();
      msg = '🔓 Đã MỞ KHOÁ key ' + maskKey(uk) + '.';
    } else msg = 'Không tìm thấy key để mở khoá.';
  }
  kvSaveState();
  adminLog('admin', {
    action: 'toggle:' + flag,
    value: flag === 'autoBan' ? AUTO_BAN : flag === 'mobileOnly' ? MOBILE_ONLY : flag === 'banDesktop' ? BAN_DESKTOP : flag === 'blockVmScript' ? BLOCK_VM_SCRIPT : flag === 'blockModule10' ? BLOCK_MODULE_10 : flag === 'hardDcBan' ? HARD_DC_BAN : flag === 'safeMode' ? SAFE_MODE : flag === 'smartBan' ? SMART_BAN : flag === 'dumperGuard' ? DUMPER_GUARD : flag === 'moduleWatermark' ? MODULE_WATERMARK : (req.body && req.body.key) || '',
    ip: getClientIp(req)
  });
  res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent(msg));
});
app.post(ADMIN_PATH + '/unban', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const key = String(req.body && req.body.key || '').trim();
  if (key) {
    removeBan(key);
    if (key.indexOf('dev:') === 0) permaDevices.delete(String(key.slice(4)).trim());
    adminLog('admin', {
      action: 'unban',
      target: key,
      ip: getClientIp(req)
    });
  }
  res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent('✅ Đã mở khoá: ' + key));
});
app.post(ADMIN_PATH + '/unban-all', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const n = banned.size;
  banned.clear();
  permaDevices.clear();
  ipCache.clear();
  keyActivity.clear();
  lockedScripts.clear();
  kvSaveState();
  adminLog('admin', {
    action: 'unban-all',
    cleared: n,
    ip: getClientIp(req)
  });
  res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent('✅ Đã MỞ KHOÁ TẤT CẢ (' + n + ' IP/thiết bị). Cache IP đã xóa — mọi thiết bị bị khoá nhầm đã hoạt động lại.'));
});
app.post(ADMIN_PATH + '/ban', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const target = String(req.body && req.body.target || '').trim();
  const reason = String(req.body && req.body.reason || 'manual').trim();
  if (!target) return res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent('❌ Thiếu đối tượng khoá!'));
  const ipLike = /^\d+\.\d+\.\d+\.\d+$/.test(target);
  if (!ipLike && validHwid(target)) {
    banDevicePerma(target, reason, deviceNameOf(target));
    return res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent('✅ Đã KHOÁ TOÀN DIỆN thiết bị ' + target + ' — mọi IP của máy này bị chặn vĩnh viễn.'));
  }
  const key = target.includes(':') ? target : (ipLike ? 'ip:' + target : 'dev:' + target);
  const nowBan = Date.now();
  banned.set(key, {
    reason: reason,
    device: '',
    t: nowBan,
    by: 'admin',
    revokedAt: nowBan
  });
  kvSaveState();
  adminLog('admin', { action: 'ban', target: key, reason: reason, ip: getClientIp(req) });
  res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent('✅ Đã khoá: ' + key));
});
app.post(ADMIN_PATH + '/ban-device', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const hwid = String(req.body && (req.body.hwid || req.body.target) || '').trim();
  const reason = String(req.body && req.body.reason || 'admin-ban-device').trim();
  const wantsJson = (req.headers.accept || '').includes('application/json') || (req.body && req.body.json === '1');
  if (!hwid) {
    if (wantsJson) return res.json({ ok: false, message: 'Thieu HWID' });
    return res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent('Thieu HWID thiet bi!'));
  }
  banDevicePerma(hwid, reason, deviceNameOf(hwid));
  if (wantsJson) return res.json({ ok: true, hwid: hwid, ips: knownIpsOfHwid(hwid) });
  res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent('Da khoa toan dien thiet bi ' + hwid + ' (moi IP).'));
});
app.post(ADMIN_PATH + '/announce-save', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const enabled = String(req.body && req.body.enabled || '') === 'on' || String(req.body && req.body.enabled || '') === '1';
  const level = ['info','warn','error','blocked'].includes(String(req.body && req.body.level || '')) ? String(req.body.level) : 'info';
  const title = safeStr(req.body && req.body.title, 120).slice(0, 120);
  const message = safeStr(req.body && req.body.message, 2000).slice(0, 2000);
  ANNOUNCE = { enabled: enabled, level: level, title: title, message: message, updatedAt: Date.now(), by: getClientIp(req) };
  kvSaveState();
  adminLog('admin', { action: 'announce-save', enabled: enabled, level: level, title: title });
  res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent(enabled ? 'Da bat thong bao xuong script (' + level + ').' : 'Da luu (tat hien thi).'));
});
app.post(ADMIN_PATH + '/announce-clear', (req, res) => {
  if (!requireAdmin(req, res)) return;
  ANNOUNCE.enabled = false;
  ANNOUNCE.message = '';
  kvSaveState();
  adminLog('admin', { action: 'announce-clear' });
  res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent('Da tat/xoa thong bao.'));
});
app.post(ADMIN_PATH + '/olm-ban', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const olm = String(req.body && req.body.olm_user || '').trim();
  const unit = String(req.body && req.body.unit || 'day');
  const rawVal = parseFloat(req.body && req.body.value || '1');
  const val = (isNaN(rawVal) || rawVal <= 0) ? 1 : rawVal;
  const reason = String(req.body && req.body.reason || 'vi pham dieu khoan').trim();
  if (!olm) return res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent('❌ Thiếu tài khoản OLM!'));
  let minutes;
  if (unit === 'permanent') minutes = -1; else if (unit === 'minute') minutes = Math.max(1, val); else if (unit === 'month') minutes = Math.max(1, val) * 30 * 24 * 60; else minutes = Math.max(1, val) * 24 * 60;
  addOlmBan(olm, minutes, reason, 'admin');
  const unitLabel = unit === 'permanent' ? 'vinh vien' : unit === 'minute' ? 'phut' : unit === 'month' ? 'thang' : 'ngay';
  adminLog('admin', {
    action: 'olm-ban',
    olm: normOlm(olm),
    unit: unit,
    value: val,
    minutes: minutes,
    reason: reason,
    ip: getClientIp(req)
  });
  res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent('✅ Đã BAN tài khoản OLM: ' + olm + ' (' + (unit === 'permanent' ? 'VĨNH VIỄN' : val + ' ' + unitLabel) + ')'));
});
app.post(ADMIN_PATH + '/olm-unban', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const olm = String((req.body && (req.body.olm_user || req.body.olm)) || req.query.olm_user || '').trim();
  const wantsJson = (req.headers.accept || '').includes('application/json') || (req.headers['x-requested-with'] === 'XMLHttpRequest');
  if (!olm) {
    if (wantsJson) return res.status(400).json({
      ok: false,
      message: 'Thiếu tài khoản OLM!'
    });
    return res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent('❌ Thiếu tài khoản OLM!'));
  }
  const had = removeOlmBan(olm);
  adminLog('admin', {
    action: 'olm-unban',
    olm: normOlm(olm),
    had: had,
    ip: getClientIp(req)
  });
  if (wantsJson) return res.json({
    ok: had,
    olm: normOlm(olm)
  });
  res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent(had ? '✅ Đã UNBAN tài khoản OLM: ' + olm : '⚠️ Không tìm thấy tài khoản: ' + olm));
});
app.get(ADMIN_PATH + '/olm-bans.json', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const list = [ ...olmBans.entries() ].map(([k, v]) => {
    const ob = checkOlmBan(k);
    return {
      olm: k,
      reason: v.reason,
      until: v.until,
      permanent: !v.until,
      t: v.t,
      by: v.by,
      remain: ob ? ob.remain : 'đã hết hạn'
    };
  }).filter(x => x.remain !== 'đã hết hạn');
  res.json({
    list: list,
    count: list.length
  });
});
app.post(ADMIN_PATH + '/set-secret', (req, res) => {
  if (!requireAdmin(req, res)) return;
  let secret = String(req.body && req.body.secret || '').trim();
  if (!secret) secret = crypto.randomBytes(32).toString('hex');
  if (secret.length < 16 || !/^[A-Za-z0-9+/=._\-]{16,128}$/.test(secret)) return res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent('❌ SECRET cần tối thiểu 16 ký tự (chữ, số và ._+-) hoặc bấm để server tự sinh!'));
  SECRET = secret;
  API_PREFIX = computeApiPrefix(SECRET);
  kvSaveState();
  adminLog('admin', {
    action: 'set-secret',
    newLength: secret.length,
    ip: getClientIp(req)
  });
  res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent('✅ Đã đổi SECRET. API prefix mới: ' + API_PREFIX + ' — CẬP NHẬT API_SECRET trong connector!'));
});
app.get(ADMIN_PATH + '/logs.json', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try { await kvSaveLogs(); await kvLoadLogs(true); } catch (_) {}
  res.json({
    logs: ADMIN_LOG.slice(0, ADMIN_LOG_MAX),
    count: ADMIN_LOG.length,
    persistent: !!KV_ENABLED
  });
});
app.get(ADMIN_PATH + '/api/locked', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const list = [ ...lockedScripts.entries() ].slice(0, 200).map(([k, v]) => ({
    hwid: k,
    ip: v.ip || '',
    device: v.device || '',
    reason: v.reason || '',
    keyMasked: v.keyMasked || '',
    olm_user: v.olm_user || '',
    t: v.t || 0,
    lastSeen: v.lastSeen || 0,
    status: v.status || 'locked',
    unlockedAt: v.unlockedAt || 0
  })).sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0));
  res.json({
    locked: list,
    count: lockedScripts.size,
    lockedActive: list.filter(x => x.status === 'locked').length
  });
});
app.post(ADMIN_PATH + '/api/locked/unlock', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const hwid = String(req.body && req.body.hwid || '').trim();
  const rec = hwid && lockedScripts.get(hwid);
  if (rec) {
    rec.status = 'unlocked';
    rec.unlockedAt = Date.now();
    banned.delete('dev:' + hwid);
    if (rec.ip) banned.delete('ip:' + rec.ip);
    kvSaveState();
    adminLog('admin', {
      action: 'unlock-script',
      hwid: hwid,
      ip: rec.ip,
      device: rec.device || '',
      ipAdmin: getClientIp(req)
    });
  }
  res.json({
    ok: true,
    unlocked: !!rec
  });
});
app.post(ADMIN_PATH + '/api/locked/lock', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const hwid = String(req.body && req.body.hwid || '').trim();
  const reason = String(req.body && req.body.reason || 'admin re-lock').slice(0, 200);
  if (!hwid) return res.json({
    ok: false
  });
  const rec = lockedScripts.get(hwid) || {
    hwid: hwid,
    ip: '',
    device: '',
    keyMasked: '',
    olm_user: '',
    t: Date.now()
  };
  rec.status = 'locked';
  rec.lockedBy = 'admin';
  rec.reason = reason;
  rec.lastSeen = Date.now();
  lockedScripts.set(hwid, rec);
  kvSaveState();
  adminLog('admin', {
    action: 'lock-script',
    hwid: hwid,
    reason: reason,
    ipAdmin: getClientIp(req)
  });
  res.json({
    ok: true
  });
});
app.post(ADMIN_PATH + '/api/locked/delete', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const hwid = String(req.body && req.body.hwid || '').trim();
  if (hwid) {
    lockedScripts.delete(hwid);
    kvSaveState();
    adminLog('admin', {
      action: 'delete-lock-record',
      hwid: hwid,
      ipAdmin: getClientIp(req)
    });
  }
  res.json({
    ok: true
  });
});
app.use((_req, res) => res.status(404).json({
  success: false,
  error: 'Not found',
  message: 'Endpoint không tồn tại hoặc yêu cầu bị từ chối.'
}));
app.use((err, _req, res, _next) => {
  console.error('[server-error]', err && err.message ? err.message : err);
  res.status(500).json({
    success: false,
    error: 'Internal server error'
  });
});
process.on('unhandledRejection', (err) => {
  try {
    console.error('[unhandledRejection]', err && err.message ? err.message : err);
    adminLog('unhandled-rejection', {
      error: String(err && err.message || err || '').slice(0, LIMITS.reason)
    });
  } catch (_) {}
});
process.on('uncaughtException', (err) => {
  try {
    console.error('[uncaughtException]', err && err.stack || err);
  } catch (_) {}
});
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`\n🚀 GOD MODE Server v39.0 (server-authoritative slim) running → http://localhost:${PORT}`);
    console.log(`   Ẩn API prefix: ${API_PREFIX}`);
    console.log(`   Admin: ${ADMIN_PATH} (${ADMIN_USER})`);
    console.log(`   Lưu trữ bền vững (KV): ${KV_ENABLED ? 'CÓ' : 'KHÔNG — đặt env KV_REST_API_URL + KV_REST_API_TOKEN để ban/mật khẩu tồn tại qua restart'}`);
    if (!KV_ENABLED) console.log(`   Kho đáp án (file dự phòng): ${BANK_FILE_OK ? 'ĐANG DÙNG ' + BANK_FILE : 'không ghi được file (' + BANK_FILE + ') — kho chỉ còn trong RAM, sẽ mất khi restart'}`);
    if (SAFE_MODE) console.log('[32m[v13 SAFE_MODE ĐANG BẬT] Auto-ban chỉ log + từ chối, KHÔNG khoá vĩnh viễn — không còn ban nhầm IP thật. Tắt: env SAFE_MODE=false hoặc panel admin.[0m'); else console.log('[33m[v13] CẢNH BÁO: SAFE_MODE đang TẮT — auto-ban sẽ khoá vĩnh viễn, dễ ban nhầm IP nhà mạng di động (CGNAT).[0m');
    if (!HARD_DC_BAN) console.log('[33m[v13] HARD_DC_BAN đang TẮT (kill-switch). Bật trong panel admin nếu muốn chặn cứng IP datacenter.[0m');
    if (SMART_BAN) console.log('[32m[v14 SMART_BAN ĐANG BẬT] Chi ban may ao/emulator/proxy xac nhan; Android/iOS thật không bị auto-ban; ban admin là tuyệt đối, không tự mở.[0m'); else console.log('[33m[v14] SMART_BAN dang TAT — de ban thong minh, bat lai trong panel admin.[0m');
    if (!BLOCK_VM_SCRIPT) console.warn('[33m   [SECURITY v12] SMART_VM_BLOCK dang TAT — vao admin panel BAT de chi cho Android/iOS that keo code (chan VM/proxy/desktop, KHONG anh huong user that).[0m');
    if (BLOCK_VM_SCRIPT) console.log('[32m   [SECURITY v12] SMART_VM_BLOCK dang BAT: chi chan VM/proxy/datacenter/desktop, Android/iOS that van hoat dong binh thuong.[0m');
    if (SECRET === DEFAULT_SECRET) console.warn('[31m   [SECURITY] SECRET MAC DINH DA ROI ROI — dat env GODMODE_SECRET (64 hex) NGAY.[0m');
  });
}
module.exports = app;
