'use strict';

const express = require('express');

const cheerio = require('cheerio');

const cors = require('cors');

const https = require('https');

const http = require('http');

const crypto = require('crypto');

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
app.disable('etag'); // [v19] không để ETag/version fingerprint lộ framework

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
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    try {
      const u = new URL(origin);
      const host = u.hostname;
      if (/^([a-z0-9-]+)-extension:\/\//i.test(origin) || /^safari-extension:\/\//i.test(origin) || /^safari-web-extension:\/\//i.test(origin)) return cb(null, true);
      if (/(^|\.)olm\.vn$/i.test(host)) return cb(null, true);
      // FIX #1: req is NOT in scope inside CORS origin callback (strict mode ReferenceError).
      // Same-host check is handled per-route; remove the broken line here.
      if (CORS_ALLOWED_HOSTS.some(h => host === h || host.endsWith('.' + h))) return cb(null, true);
      return cb(null, false);
    } catch (_) {
      return cb(null, false);
    }
  },
  methods: [ 'GET', 'POST', 'OPTIONS' ],
  allowedHeaders: [ 'Content-Type', 'X-Session', 'X-Fp-Hash', 'X-Seq', 'X-HWID', 'X-Ts', 'X-Nonce', 'X-Sign' ],
  credentials: false
}));

app.options(/.*/, cors());

app.use((req, res, next) => {
  if (req.method === 'POST' && !req.path.startsWith(API_PREFIX)) {
    const LEGACY = [ '/verify', '/attest', '/process', '/fire', '/code', '/heartbeat', '/lock-report', '/lock-status', '/ping' ];
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
  console.warn('[33m[SECURITY][v18.1] Đang dùng cấu hình mặc định (secret/admin pass). Đặt GODMODE_SECRET, ADMIN_PASS trước khi public.[0m');
}

const PAYLOAD_MODULE_VERSION = 1;

const PAYLOAD_MODULE_SRC = `\nvar SESSION=ctx.SESSION, addLog=ctx.addLog, forceGetMeta=ctx.forceGetMeta;\nvar SECRET_KEY_CS='1047823200';\nfunction decryptOLM_CS(base64Str){if(!base64Str)return null;try{var raw=atob(base64Str);var dec='';for(var i=0;i<raw.length;i++)dec+=String.fromCharCode(raw.charCodeAt(i)^SECRET_KEY_CS.charCodeAt(i%SECRET_KEY_CS.length));return decodeURIComponent(escape(dec));}catch(e){return null;}}\nfunction buildParamsCS(sq){var count=sq.count||4;if(sq.type===6){var orderArr=Array.from(Array(Math.max(count,15)),function(_,k){return k;});return {js:'',order_l:orderArr,order_r:orderArr};}return {js:'',order:Array.from(Array(count),function(_,k){return k;})};}\nfunction findCorrectInfoCS(node){var results=[];function traverse(n){if(!n)return;var subQ_ID=n.id||n._id||(n.props?n.props.id:null);if((n.type==='fillme-input'&&n.content)||(typeof n.content==='string'&&n.content.includes('data-accept='))){if(typeof n.content==='string'&&n.content.includes('data-accept=')){var regex=/data-accept="([^"]+)"/g;var match;while((match=regex.exec(n.content))!==null)results.push({type:4,ans:[match[1]],count:1,skill:n.id_skill,subId:subQ_ID||('raw_'+Math.random()),isText:true});}else if(typeof n.content==='string'){results.push({type:4,ans:[n.content],count:1,skill:n.id_skill,subId:subQ_ID,isText:true});}return;}if(n.type==='olm-list'||(Array.isArray(n.children)&&n.children.length>0)){var options=Array.isArray(n.children)?n.children:null;if(options&&(n.name==='true-false'||n.listType==='true-false')){results.push({type:13,ans:options.map(function(o){return (o.correct==true||o.correct==='true'||o.correct==1)?'1':'0';}),count:options.length,skill:n.id_skill,subId:subQ_ID});return;}if(options&&(n.name==='link-list'||n.listType==='matching')){results.push({type:6,ans:options.map(function(_,idx){return idx.toString();}),count:options.length,skill:n.id_skill,subId:subQ_ID});return;}if(options&&options.some(function(c){return c.correct!==undefined;})){var trueIndex=options.findIndex(function(o){return o.correct==true||o.correct==='true'||o.correct==1;});results.push({type:1,ans:[(trueIndex===-1?0:trueIndex).toString()],count:options.length,skill:n.id_skill,subId:subQ_ID});return;}}if(Array.isArray(n.children))n.children.forEach(traverse);else if(Array.isArray(n.questions))n.questions.forEach(traverse);else if(Array.isArray(n.items))n.items.forEach(traverse);else if(Array.isArray(n.list))n.list.forEach(traverse);else if(n.root)traverse(n.root);}var contentToParse=node.json_content||node.content;if(typeof contentToParse==='string'&&!contentToParse.trim().startsWith('{')&&!contentToParse.trim().startsWith('[')){var decoded=decryptOLM_CS(contentToParse);if(decoded)contentToParse=decoded;}try{traverse(typeof contentToParse==='string'?JSON.parse(contentToParse):contentToParse);}catch(_){traverse(node);}if(results.length===0)results.push({type:1,ans:['0'],count:4,skill:null,subId:null});return results;}\nreturn async function(){\nforceGetMeta();\nif(!SESSION.meta.id_user||!SESSION.meta.id_cate){addLog('❌ Thiếu ID user/cate: user='+(SESSION.meta.id_user||'?')+' cate='+(SESSION.meta.id_cate||'?'),'err');return false;}\nvar totalPackages=SESSION.raw_questions.length;\nif(totalPackages===0){addLog('❌ Chưa có câu hỏi để nộp!','err');return false;}\nvar timeInput=document.getElementById('tl-god-time');\nvar timeStr=timeInput?timeInput.value.toString().trim():'10.00';\nvar tp=timeStr.split('.');\nvar userMins=parseInt(tp[0])||0;\nvar uss=tp[1]||'0';if(uss.length===1)uss+='0';\nvar userSecs=parseInt(uss.substring(0,2));\nvar calcSeconds=(userMins*60)+userSecs;\nif(calcSeconds<30)calcSeconds=120;\nvar modeSel=document.getElementById('tl-modeSelect');\nvar mode=modeSel?modeSel.value:'practice';\nvar isExam=mode==='exam',isVideo=mode==='video';\nvar tgtScoreSel=document.getElementById('tl-god-target-score');\nvar tgtScore=tgtScoreSel?Math.min(10,Math.max(7,parseFloat(tgtScoreSel.value)||10)):10;\nvar tgtRatio=tgtScore/10;\nvar tgtCorrectCount=Math.round(totalPackages*tgtRatio);\nvar wrongSet=new Set();for(var wi=tgtCorrectCount;wi<totalPackages;wi++)wrongSet.add(wi);\nvar now=Math.floor(Date.now()/1000);\nvar totalSeconds,timeInit;\nif(isVideo||isExam){totalSeconds=calcSeconds;timeInit=now-totalSeconds;}else{totalSeconds=totalPackages*15;timeInit=now-totalSeconds;}\nvar params=new URLSearchParams();\nvar fakeLog=[];\nvar max_tn_score=0,tn_score_calc=0,tl_max_calc=0;\nSESSION.raw_questions.forEach(function(q,i){\nvar subQuestions=findCorrectInfoCS(q);\nvar sub_count=subQuestions.length;\nvar is_tl=(q.q_type==18||q.type==18||q.q_type==11);\nvar final_score=sub_count;\nif(q.score!==undefined&&q.score!==null&&q.score!=='')final_score=parseFloat(q.score);\nelse if(q.point!==undefined&&q.point!==null&&q.point!=='')final_score=parseFloat(q.point);\nvar makeWrong=(tgtScore<10&&wrongSet.has(i));\nif(!isVideo){params.append('quiz_list[]',q.id||q._id);params.append('score_list['+(q.id||q._id)+']',final_score);}\nvar skillIDs=[].concat(Array.from(new Set(subQuestions.map(function(sq){return sq.skill;}).filter(function(s){return s!=null;}))));\nif(!isVideo)skillIDs.forEach(function(s){params.append('correct_skill[]',s);});\nif(isVideo||isExam){\nif(is_tl&&isExam){tl_max_calc+=final_score;fakeLog.push({answer:JSON.stringify(['Học sinh đã làm phần tự luận trên máy.']),label:[''],params:'{"js":"","order":[0]}',correct_skill:[],wrong_skill:[],type:[18],result:[0],idq:parseInt(q.id||q._id),score:final_score,chk:0});}\nelse{\nmax_tn_score+=final_score;if(!makeWrong)tn_score_calc+=final_score;\nvar ans_list=[],type_list=[],prs_list=[],resArr=[],mresult=[],listIdq=[],lbl_list=[];\nfor(var j=0;j<sub_count;j++){var sq=subQuestions[j];ans_list.push(JSON.stringify((sq.type===4||sq.type===13||sq.type===6)?sq.ans:(sq.ans[0]||'0')));type_list.push(sq.type||1);prs_list.push(JSON.stringify(buildParamsCS(sq)));resArr.push(makeWrong?0:1);mresult.push([makeWrong?0:1]);listIdq.push(sq.subId&&sq.subId.toString().length>5?sq.subId:'q'+j);var lbl='';if(!makeWrong&&sq.ans.length===1&&!isNaN(sq.ans[0])&&sq.type!==4&&sq.type!==13)lbl=['A','B','C','D','E'][parseInt(sq.ans[0])]||'';lbl_list.push(lbl);}\nvar logItem={answer:JSON.stringify(ans_list),label:sub_count===1?lbl_list:[],labels:lbl_list,params:sub_count===1?prs_list[0]:JSON.stringify({js:'',prs:prs_list,order:Array.from(Array(sub_count).keys())}),correct_skill:makeWrong?[]:skillIDs,wrong_skill:makeWrong?skillIDs:[],type:type_list,result:resArr,mresult:mresult,idq:parseInt(q.id||q._id),score:makeWrong?0:final_score};\nif(isExam){if(!makeWrong)logItem.chk=1;if(sub_count>1)logItem.list_idq=listIdq;}\nif(isVideo){logItem.marker=q.marker||(i+1);logItem.id=(q.id||q._id).toString();}\nfakeLog.push(logItem);\n}\n}else{\nvar qpa=[],apa=[];\nsubQuestions.forEach(function(sq){qpa.push(JSON.stringify(buildParamsCS(sq)));apa.push(JSON.stringify(sq.ans));});\nfakeLog.push({q_params:JSON.stringify(qpa),a_params:JSON.stringify(apa),result:makeWrong?0:1,correct:makeWrong?0:1,wrong:makeWrong?1:0,a_index:i,time_spent:Math.floor(Math.random()*15)+10});\n}\n});\nparams.append('id_cate',SESSION.meta.id_cate);\nparams.append('id_courseware',SESSION.meta.id_courseware||SESSION.meta.id_cate);\nparams.append('id_user',SESSION.meta.id_user);\nparams.append('id_grade',window.grade||window.id_grade||'10');\nif(SESSION.meta.id_school)params.append('id_school',SESSION.meta.id_school);\nif(SESSION.meta.id_group)params.append('id_group',SESSION.meta.id_group);\nparams.append('type_vip','530');params.append('time_stored','0');params.append('date_end',now);\nparams.append('data_log',JSON.stringify(fakeLog));\nif(isVideo){var vl=SESSION.video_length||900;params.append('type','5');params.append('type_exam','0');params.append('total_time',vl);params.append('current_time',vl);params.append('time_spent',totalSeconds+2);params.append('score_10',tgtScore.toString());params.append('totalq',totalPackages);params.append('score',tn_score_calc);params.append('max_score',max_tn_score);params.append('answered',totalPackages);params.append('correct',tgtCorrectCount);params.append('count_problems',totalPackages);params.append('percent',Math.round(tgtScore*10).toString());params.append('pscore',tgtScore.toString());params.append('score_status',tgtScore.toString());var vLog={};vLog[timeInit]='start';vLog[timeInit+1]='start';vLog[timeInit+10]='reload';params.append('log',JSON.stringify(vLog));}\nelse if(isExam){params.append('time_init',timeInit);params.append('time_spent',totalSeconds);params.append('score',tn_score_calc);params.append('max_score',max_tn_score+tl_max_calc);params.append('tn_score',tn_score_calc);params.append('type_exam','1');params.append('correct',tn_score_calc);params.append('wrong',max_tn_score-tn_score_calc);params.append('name_user','');params.append('tl_score','0');params.append('times','0');params.append('iframe','false');var curT=timeInit+Math.floor(totalSeconds*0.1);var totalQs=SESSION.raw_questions.length;var usableTime=Math.max(10,totalSeconds-Math.floor(totalSeconds*0.1)-10);var baseInterval=usableTime/(totalQs||1);for(var c=0;c<totalQs;c++){curT+=Math.floor(baseInterval*(0.7+Math.random()*0.6));if(curT>=timeInit+totalSeconds)curT=timeInit+totalSeconds-2;params.append('choose_log['+c+'][ind]',c);params.append('choose_log['+c+'][t]',Math.floor(curT));params.append('choose_log['+c+'][l]',c+1);}}\nelse{params.append('time_init',timeInit);params.append('time_spent',totalSeconds);params.append('time_elapsed',totalSeconds);params.append('score',Math.round(tgtScore*10).toString());params.append('score_10',tgtScore.toString());params.append('star',Math.round(tgtScore*2).toString());params.append('theta','0');params.append('max_score','100');params.append('answered',totalPackages);params.append('correct',tgtCorrectCount);params.append('wrong',(totalPackages-tgtCorrectCount).toString());params.append('missed','0');params.append('count_problems',totalPackages);params.append('type','3');params.append('type_exam','0');var pLog={};pLog[timeInit]='start';pLog[timeInit+1]='start';params.append('log',JSON.stringify(pLog));}\nparams.append('count_redo','0');params.append('ended','1');params.append('save_star','1');\ntry{\naddLog('📤 Đang nộp bài lên OLM...','info');\nvar csrf=SESSION.meta.csrf_token||(document.querySelector('meta[name="csrf-token"]')&&document.querySelector('meta[name="csrf-token"]').getAttribute('content'))||'';\nvar response=await fetch('/course/teacher-static',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded; charset=UTF-8','x-csrf-token':csrf,'x-requested-with':'XMLHttpRequest'},body:params.toString()});\nif(!response.ok){addLog('❌ OLM trả lỗi HTTP '+response.status,'err');return false;}\nreturn true;\n}catch(err){addLog('❌ Lỗi kết nối OLM: '+err.message,'err');return false;}\n};\n`;

function buildModulePayload(sessionToken, key, hwid) {
  return encryptAnswers({
    src: watermarkSrc(PAYLOAD_MODULE_SRC, key, hwid),
    v: PAYLOAD_MODULE_VERSION
  }, sessionToken);
}

const CONNECTOR_MODULE_EMBEDDED_B64 = 'Y29uc3QgU0VSVkVSX0JBU0UgPSAnaHR0cHM6Ly9tb2RnYW1lLnZlcmNlbC5hcHAnOwpjb25zdCBBUElfU0VDUkVUID0gJ2E3ZjNjOWUxYjJkNDg1MDZmYWUxYzdkM2I5ZjBlMmE0YzZkOGYxYTNiNWU3YzlkMGYyYTRjNmU4YjFkM2Y1YTcnOwpjb25zdCBSRVFVRVNUX0VOQ1JZUFRJT04gPSBmYWxzZTsKKGZ1bmN0aW9uKCkgewogICd1c2Ugc3RyaWN0JzsKICBjb25zdCBMU19LRVkgPSAnX3RsX2Nvbm5fa2V5JzsKICBjb25zdCBMU19UWVBFID0gJ190bF9jb25uX3R5cGUnOwogIGNvbnN0IExTX0VYUCA9ICdfdGxfY29ubl9leHAnOwogIGNvbnN0IExTX1RIRU1FID0gJ190aWVwX3RoZW1lJzsKICBsZXQgQ1VSUkVOVF9LRVkgPSBudWxsOwogIGxldCBLRVlfU1RBVFVTID0gewogICAgdmFsaWQ6IGZhbHNlLAogICAgdHlwZTogbnVsbCwKICAgIGV4cGlyZXNfYXQ6IG51bGwKICB9OwogIGxldCBDVVJSRU5UX0RFVklDRSA9ICcnOwogIGNvbnN0IFNFU1NJT04gPSB7CiAgICByYXdfcXVlc3Rpb25zOiBbXSwKICAgIG1ldGE6IHsKICAgICAgaWRfdXNlcjogbnVsbCwKICAgICAgaWRfY2F0ZTogbnVsbCwKICAgICAgaWRfY291cnNld2FyZTogbnVsbCwKICAgICAgaWRfc2Nob29sOiBudWxsLAogICAgICBpZF9ncm91cDogbnVsbCwKICAgICAgY3NyZl90b2tlbjogbnVsbCwKICAgICAgc3ViamVjdF9uYW1lOiBudWxsLAogICAgICBleGVyY2lzZV90aXRsZTogbnVsbCwKICAgICAgc3ViamVjdF9pZDogbnVsbAogICAgfSwKICAgIGF1dG9fbW9kZTogJ3ByYWN0aWNlJywKICAgIHZpZGVvX2xlbmd0aDogOTAwLAogICAgYmFua0Fuc3dlcnM6IFtdCiAgfTsKICAvLyBbdjI2XSDEkOG7k25nIGLhu5kgw7QgIk7huqFwIGThu68gbGnhu4d1OiBOIGPDonUiIHRoZW8gc+G7kSBjw6J1IHRo4bqtdCAoY8OidSBBUEkgT0xNIGhv4bq3YyDEkcOhcCDDoW4ga2hvIHNlcnZlcikKICBsZXQgX2xhc3RPbG1Vc2VyID0gJyc7CiAgZnVuY3Rpb24gX3NldFFDb3VudChuKSB7CiAgICB0cnkgewogICAgICBjb25zdCBlbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1xY291bnQnKTsKICAgICAgaWYgKGVsKSBlbC50ZXh0Q29udGVudCA9IFN0cmluZyhuIHx8IDApOwogICAgfSBjYXRjaCAoXykge30KICB9CiAgZnVuY3Rpb24gX3JlZnJlc2hRQ291bnQoKSB7CiAgICB0cnkgewogICAgICBjb25zdCByYXcgPSAoU0VTU0lPTi5yYXdfcXVlc3Rpb25zIHx8IFtdKS5sZW5ndGg7CiAgICAgIGNvbnN0IGJhbmsgPSAoU0VTU0lPTi5iYW5rQW5zd2VycyB8fCBbXSkubGVuZ3RoOwogICAgICBfc2V0UUNvdW50KHJhdyB8fCBiYW5rIHx8IDApOwogICAgfSBjYXRjaCAoXykge30KICB9CiAgc2V0SW50ZXJ2YWwoX3JlZnJlc2hRQ291bnQsIDI1MDApOwogIGxldCBfYmFua0ZhbGxiYWNrVGltZXIgPSBudWxsOwogIGxldCBDVVJSRU5UX1RIRU1FID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oTFNfVEhFTUUpIHx8ICdkZWZhdWx0JzsKICBmdW5jdGlvbiBpc1ByZW1pdW1LZXkoKSB7CiAgICBjb25zdCB0ID0gKEtFWV9TVEFUVVMudHlwZSB8fCBfc0xTLmdldChMU19UWVBFKSB8fCAnJykudG9TdHJpbmcoKS50b1VwcGVyQ2FzZSgpOwogICAgcmV0dXJuIHQgPT09ICdQUkVNSVVNJyB8fCB0ID09PSAnVklQJyB8fCB0ID09PSAnVU5MSU1JVEVEJzsKICB9CiAgZnVuY3Rpb24gaGFuZGxlT2xtTWlzbWF0Y2goc2VydmVyT2xtLCBjdXJyZW50T2xtKSB7CiAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShMU19LRVkpOwogICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oTFNfVFlQRSk7CiAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShMU19FWFApOwogICAgQ1VSUkVOVF9LRVkgPSBudWxsOwogICAgS0VZX1NUQVRVUyA9IHsKICAgICAgdmFsaWQ6IGZhbHNlLAogICAgICB0eXBlOiBudWxsLAogICAgICBleHBpcmVzX2F0OiBudWxsCiAgICB9OwogICAgX3NlY1Nlc3Npb24gPSB7CiAgICAgIHRva2VuOiBudWxsLAogICAgICBleHA6IDAsCiAgICAgIGZwSGFzaDogbnVsbCwKICAgICAgc2VxOiAxCiAgICB9OwogICAgQ1VSUkVOVF9ERVZJQ0UgPSAnJzsKICAgIGNvbnN0IHBhbmVsRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtcGFuZWwnKTsKICAgIGNvbnN0IGZiID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLWZsb2F0QnRuJyk7CiAgICBpZiAocGFuZWxFbCkgcGFuZWxFbC5yZW1vdmUoKTsKICAgIGlmIChmYikgZmIucmVtb3ZlKCk7CiAgICBzaG93Q3VzdG9tTW9kYWwoewogICAgICBpY29uOiAn8J+aqycsCiAgICAgIHRpdGxlOiAnVMOASSBLSE/huqJOIE9MTSBLSMOUTkcgS0jhu5pQIScsCiAgICAgIGxpbmVzOiBbIGBLZXkgxJHGsOG7o2MgxJHEg25nIGvDvSBjaG8gdMOgaSBraG/huqNuOiA8Yj4ke3NlcnZlck9sbX08L2I+YCwgYFTDoGkga2hv4bqjbiBPTE0gaGnhu4duIHThuqFpOiA8Yj4ke2N1cnJlbnRPbG19PC9iPmAsIGDimqDvuI8gVnVpIGzDsm5nIMSRxINuZyBuaOG6rXAgxJHDum5nIHTDoGkga2hv4bqjbiBPTE0gxJHhu4Mgc+G7rSBk4bulbmcga2V5IG7DoHksYCwgYGhv4bq3YyBsacOqbiBo4buHIGFkbWluIMSR4buDIMSRxrDhu6NjIGjhu5cgdHLhu6MhYCBdLAogICAgICBvbk9rOiAoKSA9PiBidWlsZExvY2tTY3JlZW4oJ+KaoO+4jyBUw6BpIGtob+G6o24gT0xNIGtow7RuZyBraOG7m3AgduG7m2kga2V5IMSRw6MgxJHEg25nIGvDvSEnKQogICAgfSk7CiAgfQogIGZ1bmN0aW9uIGdldFRoZW1lQ29sb3JzKHRoZW1lKSB7CiAgICBjb25zdCBUID0gewogICAgICBkZWZhdWx0OiB7CiAgICAgICAgYzE6ICcjMDBmMmZlJywKICAgICAgICBjMjogJyM0ZmFjZmUnLAogICAgICAgIGJnT3ZlcmxheTogJ3JnYmEoMTMsMTcsMjMsMC45NSknLAogICAgICAgIGJnUGFuZWw6ICdyZ2JhKDEzLDE3LDIzLDAuODgpJywKICAgICAgICBib3JkZXI6ICdyZ2JhKDAsMjQyLDI1NCwwLjIpJywKICAgICAgICBib3JkZXJTdHJvbmc6ICdyZ2JhKDAsMjQyLDI1NCwwLjMpJywKICAgICAgICBib3JkZXJTdWJ0bGU6ICdyZ2JhKDAsMjQyLDI1NCwwLjEyKScsCiAgICAgICAgaGVhZGVyQmc6ICdsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLHJnYmEoMCwyNDIsMjU0LDAuMDcpLHJnYmEoNzksMTcyLDI1NCwwLjA0KSknLAogICAgICAgIGdsb3dDb2xvcjogJ3JnYmEoMCwyNDIsMjU0LDAuNDUpJywKICAgICAgICBnbG93U3Ryb25nOiAncmdiYSgwLDI0MiwyNTQsMC43KScsCiAgICAgICAgZ2xvd01pZDogJ3JnYmEoMCwyNDIsMjU0LDAuMjUpJywKICAgICAgICBnbG93U3VidGxlOiAncmdiYSgwLDI0MiwyNTQsMC4wOCknLAogICAgICAgIGdsb3dQdWxzZTogJ3JnYmEoMCwyNDIsMjU0LDAuNTUpJywKICAgICAgICBpbnB1dEJvcmRlcjogJ3JnYmEoMCwyNDIsMjU0LDAuNCknLAogICAgICAgIGlucHV0Q29sb3I6ICcjMDBmMmZlJywKICAgICAgICBmbG9hdEdyYWRpZW50OiAnbGluZWFyLWdyYWRpZW50KDEzNWRlZywjMDBmMmZlLCM0ZmFjZmUpJywKICAgICAgICBicmFuZEdyYWRpZW50OiAnbGluZWFyLWdyYWRpZW50KDkwZGVnLCMwMGYyZmUsIzRmYWNmZSwjMDBmMmZlKScsCiAgICAgICAgc3RhdHVzQm9yZGVyOiAncmdiYSgwLDIzMCwxMjAsMC4yNSknLAogICAgICAgIHN0YXR1c0JnOiAncmdiYSgwLDIzMCwxMjAsMC4wNCknLAogICAgICAgIHBhbmVsSW5zZXQ6ICdyZ2JhKDAsMjQyLDI1NCwwLjA4KScsCiAgICAgICAgc2VsZWN0Qm9yZGVyOiAncmdiYSgwLDI0MiwyNTQsMC4yKScsCiAgICAgICAgY29uc29sZUJvcmRlcjogJ3JnYmEoMCwyNDIsMjU0LDAuMTIpJywKICAgICAgICBmeENTUzogJycsCiAgICAgICAgcGFuZWxFeHRyYTogJycsCiAgICAgICAgdGhlbWVMYWJlbDogJ/CflLUgTeG6t2MgxJDhu4tuaCcsCiAgICAgICAgcHJldmlld0JnOiAnbGluZWFyLWdyYWRpZW50KDEzNWRlZywjMDAxNTIwLCMwMGYyZmU1NSknLAogICAgICAgIHByZXZpZXdCb3JkZXI6ICdyZ2JhKDAsMjQyLDI1NCwwLjUpJywKICAgICAgICBwcmV2aWV3VGV4dDogJyMwMGYyZmUnCiAgICAgIH0sCiAgICAgIGdyYXk6IHsKICAgICAgICBjMTogJyNlMGUwZTAnLAogICAgICAgIGMyOiAnI2EwYTBhMCcsCiAgICAgICAgYmdPdmVybGF5OiAncmdiYSgxMCwxMCwxMCwwLjk3KScsCiAgICAgICAgYmdQYW5lbDogJ3JnYmEoMjAsMjAsMjAsMC45NCknLAogICAgICAgIGJvcmRlcjogJ3JnYmEoMjAwLDIwMCwyMDAsMC4xOCknLAogICAgICAgIGJvcmRlclN0cm9uZzogJ3JnYmEoMjMwLDIzMCwyMzAsMC4zKScsCiAgICAgICAgYm9yZGVyU3VidGxlOiAncmdiYSgxNzAsMTcwLDE3MCwwLjEpJywKICAgICAgICBoZWFkZXJCZzogJ2xpbmVhci1ncmFkaWVudCgxMzVkZWcscmdiYSgxMjAsMTIwLDEyMCwwLjEyKSxyZ2JhKDYwLDYwLDYwLDAuMDUpKScsCiAgICAgICAgZ2xvd0NvbG9yOiAncmdiYSgyMTAsMjEwLDIxMCwwLjM1KScsCiAgICAgICAgZ2xvd1N0cm9uZzogJ3JnYmEoMjIwLDIyMCwyMjAsMC42KScsCiAgICAgICAgZ2xvd01pZDogJ3JnYmEoMjAwLDIwMCwyMDAsMC4yKScsCiAgICAgICAgZ2xvd1N1YnRsZTogJ3JnYmEoMTYwLDE2MCwxNjAsMC4wNyknLAogICAgICAgIGdsb3dQdWxzZTogJ3JnYmEoMjAwLDIwMCwyMDAsMC40NSknLAogICAgICAgIGlucHV0Qm9yZGVyOiAncmdiYSgyMDAsMjAwLDIwMCwwLjM4KScsCiAgICAgICAgaW5wdXRDb2xvcjogJyNkOGQ4ZDgnLAogICAgICAgIGZsb2F0R3JhZGllbnQ6ICdsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLCNjMGMwYzAsIzY2NiknLAogICAgICAgIGJyYW5kR3JhZGllbnQ6ICdsaW5lYXItZ3JhZGllbnQoOTBkZWcsI2MwYzBjMCwjZmZmZmZmLCNkMGQwZDAsI2MwYzBjMCknLAogICAgICAgIHN0YXR1c0JvcmRlcjogJ3JnYmEoMTYwLDE2MCwxNjAsMC4yKScsCiAgICAgICAgc3RhdHVzQmc6ICdyZ2JhKDYwLDYwLDYwLDAuMDcpJywKICAgICAgICBwYW5lbEluc2V0OiAncmdiYSgyMDAsMjAwLDIwMCwwLjA3KScsCiAgICAgICAgc2VsZWN0Qm9yZGVyOiAncmdiYSgxOTAsMTkwLDE5MCwwLjIpJywKICAgICAgICBjb25zb2xlQm9yZGVyOiAncmdiYSgxNjAsMTYwLDE2MCwwLjEpJywKICAgICAgICBmeENTUzogYFxuICAgICAgICAgICAgICAgICAgICAjdGwtY29ubi1meC1iYXIgeyBoZWlnaHQ6MnB4OyBiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCg5MGRlZyx0cmFuc3BhcmVudCxyZ2JhKDI1NSwyNTUsMjU1LDAuMDgpLHJnYmEoMjU1LDI1NSwyNTUsMC41NSkscmdiYSgyNTUsMjU1LDI1NSwwLjA4KSx0cmFuc3BhcmVudCk7IGJhY2tncm91bmQtc2l6ZTozMDAlIDEwMCU7IGFuaW1hdGlvbjptZXRhbFN3ZWVwIDIuOHMgbGluZWFyIGluZmluaXRlOyB9XG4gICAgICAgICAgICAgICAgICAgIEBrZXlmcmFtZXMgbWV0YWxTd2VlcCB7IDAle2JhY2tncm91bmQtcG9zaXRpb246MTAwJSAwfSAxMDAle2JhY2tncm91bmQtcG9zaXRpb246LTIwMCUgMH0gfVxuICAgICAgICAgICAgICAgICAgICAjdGwtcGFuZWwgeyBib3gtc2hhZG93OiAwIDAgNjBweCByZ2JhKDAsMCwwLDAuODUpLCAwIDAgMzBweCByZ2JhKDE4MCwxODAsMTgwLDAuMDYpLCBpbnNldCAwIDFweCAwIHJnYmEoMjU1LDI1NSwyNTUsMC4wOCk7IH1cbiAgICAgICAgICAgICAgICAgICAgI3RsLWNvbm4tcGFuZWwgeyBib3gtc2hhZG93OiAwIDAgNjBweCByZ2JhKDAsMCwwLDAuODUpLCBpbnNldCAwIDFweCAwIHJnYmEoMjU1LDI1NSwyNTUsMC4wOCk7IH1cbiAgICAgICAgICAgICAgICBgLAogICAgICAgIHBhbmVsRXh0cmE6ICc8ZGl2IGlkPSJ0bC1jb25uLWZ4LWJhciI+PC9kaXY+JywKICAgICAgICB0aGVtZUxhYmVsOiAn4pqrIFjDoW0gQuG6oWMnLAogICAgICAgIHByZXZpZXdCZzogJ2xpbmVhci1ncmFkaWVudCgxMzVkZWcsIzFhMWExYSwjNjY2KScsCiAgICAgICAgcHJldmlld0JvcmRlcjogJ3JnYmEoMjIwLDIyMCwyMjAsMC40NSknLAogICAgICAgIHByZXZpZXdUZXh0OiAnI2UwZTBlMCcKICAgICAgfSwKICAgICAgcGluazogewogICAgICAgIGMxOiAnI2ZmNmViNCcsCiAgICAgICAgYzI6ICcjZmYxNDkzJywKICAgICAgICBiZ092ZXJsYXk6ICdyZ2JhKDE4LDQsMTQsMC45NyknLAogICAgICAgIGJnUGFuZWw6ICdyZ2JhKDI2LDQsMTgsMC45MyknLAogICAgICAgIGJvcmRlcjogJ3JnYmEoMjU1LDExMCwxODAsMC4yKScsCiAgICAgICAgYm9yZGVyU3Ryb25nOiAncmdiYSgyNTUsMTEwLDE4MCwwLjM4KScsCiAgICAgICAgYm9yZGVyU3VidGxlOiAncmdiYSgyNTUsMTEwLDE4MCwwLjEyKScsCiAgICAgICAgaGVhZGVyQmc6ICdsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLHJnYmEoMjU1LDExMCwxODAsMC4wOSkscmdiYSgyNTUsMjAsMTQ3LDAuMDQpKScsCiAgICAgICAgZ2xvd0NvbG9yOiAncmdiYSgyNTUsMTEwLDE4MCwwLjQ1KScsCiAgICAgICAgZ2xvd1N0cm9uZzogJ3JnYmEoMjU1LDExMCwxODAsMC43NSknLAogICAgICAgIGdsb3dNaWQ6ICdyZ2JhKDI1NSwxMTAsMTgwLDAuMjIpJywKICAgICAgICBnbG93U3VidGxlOiAncmdiYSgyNTUsMjAsMTQ3LDAuMDcpJywKICAgICAgICBnbG93UHVsc2U6ICdyZ2JhKDI1NSwxMTAsMTgwLDAuNTUpJywKICAgICAgICBpbnB1dEJvcmRlcjogJ3JnYmEoMjU1LDExMCwxODAsMC40MiknLAogICAgICAgIGlucHV0Q29sb3I6ICcjZmZiM2Q5JywKICAgICAgICBmbG9hdEdyYWRpZW50OiAnbGluZWFyLWdyYWRpZW50KDEzNWRlZywjZmY2ZWI0LCNmZjE0OTMpJywKICAgICAgICBicmFuZEdyYWRpZW50OiAnbGluZWFyLWdyYWRpZW50KDkwZGVnLCNmZjZlYjQsI2ZmY2NlOCwjZmYxNDkzLCNmZjZlYjQpJywKICAgICAgICBzdGF0dXNCb3JkZXI6ICdyZ2JhKDI1NSwxMTAsMTgwLDAuMiknLAogICAgICAgIHN0YXR1c0JnOiAncmdiYSgyNTUsMjAsMTQ3LDAuMDUpJywKICAgICAgICBwYW5lbEluc2V0OiAncmdiYSgyNTUsMTEwLDE4MCwwLjEpJywKICAgICAgICBzZWxlY3RCb3JkZXI6ICdyZ2JhKDI1NSwxMTAsMTgwLDAuMiknLAogICAgICAgIGNvbnNvbGVCb3JkZXI6ICdyZ2JhKDI1NSwxMTAsMTgwLDAuMTIpJywKICAgICAgICBmeENTUzogYFxuICAgICAgICAgICAgICAgICAgICAjdGwtcGFuZWwgeyBhbmltYXRpb246c2FrdXJhUGFuZWxHbG93IDNzIGVhc2UtaW4tb3V0IGluZmluaXRlOyB9XG4gICAgICAgICAgICAgICAgICAgICN0bC1jb25uLXBhbmVsIHsgYW5pbWF0aW9uOnNha3VyYVBhbmVsR2xvdyAzcyBlYXNlLWluLW91dCBpbmZpbml0ZTsgfVxuICAgICAgICAgICAgICAgICAgICBAa2V5ZnJhbWVzIHNha3VyYVBhbmVsR2xvdyB7XG4gICAgICAgICAgICAgICAgICAgICAgICAwJSwxMDAleyBib3gtc2hhZG93OjAgMCA2MHB4IHJnYmEoMCwwLDAsMC44KSwwIDAgMjVweCByZ2JhKDI1NSwxMTAsMTgwLDAuMSksaW5zZXQgMCAwIDAgMXB4IHJnYmEoMjU1LDExMCwxODAsMC4wNik7IH1cbiAgICAgICAgICAgICAgICAgICAgICAgIDUwJXsgYm94LXNoYWRvdzowIDAgNjBweCByZ2JhKDAsMCwwLDAuOCksMCAwIDQ1cHggcmdiYSgyNTUsMTEwLDE4MCwwLjIpLGluc2V0IDAgMCAwIDFweCByZ2JhKDI1NSwxMTAsMTgwLDAuMTIpOyB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgLnNha3VyYS1wZXRhbCB7IHBvc2l0aW9uOmFic29sdXRlOyBwb2ludGVyLWV2ZW50czpub25lOyBib3JkZXItcmFkaXVzOjUwJSAwIDUwJSAwOyBiYWNrZ3JvdW5kOnJnYmEoMjU1LDExMCwxODAsMC4yMik7IGFuaW1hdGlvbjpzYWt1cmFEcmlmdCBsaW5lYXIgaW5maW5pdGU7IH1cbiAgICAgICAgICAgICAgICAgICAgQGtleWZyYW1lcyBzYWt1cmFEcmlmdCB7IDAle3RyYW5zZm9ybTp0cmFuc2xhdGVZKC0xMHB4KSByb3RhdGUoMGRlZyk7b3BhY2l0eTowLjd9IDEwMCV7dHJhbnNmb3JtOnRyYW5zbGF0ZVkoNDIwcHgpIHJvdGF0ZSgyNzBkZWcpO29wYWNpdHk6MH0gfVxuICAgICAgICAgICAgICAgICAgICAjdGwtY29ubi1meC1wZXRhbHMgeyBwb3NpdGlvbjphYnNvbHV0ZTt0b3A6MDtsZWZ0OjA7cmlnaHQ6MDtoZWlnaHQ6MTAwJTtwb2ludGVyLWV2ZW50czpub25lO292ZXJmbG93OmhpZGRlbjt6LWluZGV4OjA7Ym9yZGVyLXJhZGl1czoxNnB4OyB9XG4gICAgICAgICAgICAgICAgYCwKICAgICAgICBwYW5lbEV4dHJhOiBgPGRpdiBpZD0idGwtY29ubi1meC1wZXRhbHMiPlxuICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJzYWt1cmEtcGV0YWwiIHN0eWxlPSJ3aWR0aDo3cHg7aGVpZ2h0OjdweDtsZWZ0OjglO3RvcDotMTBweDthbmltYXRpb24tZHVyYXRpb246My44czthbmltYXRpb24tZGVsYXk6MHM7Ij48L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0ic2FrdXJhLXBldGFsIiBzdHlsZT0id2lkdGg6NXB4O2hlaWdodDo1cHg7bGVmdDoyOCU7dG9wOi0xMHB4O2FuaW1hdGlvbi1kdXJhdGlvbjo1LjFzO2FuaW1hdGlvbi1kZWxheTowLjlzOyI+PC9kaXY+XG4gICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InNha3VyYS1wZXRhbCIgc3R5bGU9IndpZHRoOjhweDtoZWlnaHQ6OHB4O2xlZnQ6NTUlO3RvcDotMTBweDthbmltYXRpb24tZHVyYXRpb246NC40czthbmltYXRpb24tZGVsYXk6MS43czsiPjwvZGl2PlxuICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJzYWt1cmEtcGV0YWwiIHN0eWxlPSJ3aWR0aDo0cHg7aGVpZ2h0OjRweDtsZWZ0Ojc1JTt0b3A6LTEwcHg7YW5pbWF0aW9uLWR1cmF0aW9uOjMuMnM7YW5pbWF0aW9uLWRlbGF5OjAuNHM7Ij48L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0ic2FrdXJhLXBldGFsIiBzdHlsZT0id2lkdGg6NnB4O2hlaWdodDo2cHg7bGVmdDo5MiU7dG9wOi0xMHB4O2FuaW1hdGlvbi1kdXJhdGlvbjo0LjlzO2FuaW1hdGlvbi1kZWxheToyLjFzOyI+PC9kaXY+XG4gICAgICAgICAgICAgICAgPC9kaXY+YCwKICAgICAgICB0aGVtZUxhYmVsOiAn8J+MuCBI4buTbmcgU2FrdXJhJywKICAgICAgICBwcmV2aWV3Qmc6ICdsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLCMxYTA1MTAsI2ZmNmViNDU1KScsCiAgICAgICAgcHJldmlld0JvcmRlcjogJ3JnYmEoMjU1LDExMCwxODAsMC41NSknLAogICAgICAgIHByZXZpZXdUZXh0OiAnI2ZmNmViNCcKICAgICAgfQogICAgfTsKICAgIHJldHVybiBUW3RoZW1lXSB8fCBULmRlZmF1bHQ7CiAgfQogIGZ1bmN0aW9uIGdldExvY2tTY3JlZW5TdHlsZXMoKSB7CiAgICBjb25zdCB0YyA9IGdldFRoZW1lQ29sb3JzKENVUlJFTlRfVEhFTUUpOwogICAgcmV0dXJuIGBcbiAgICAgICAgICAgIEBpbXBvcnQgdXJsKCdodHRwczovL2ZvbnRzLmdvb2dsZWFwaXMuY29tL2NzczI/ZmFtaWx5PU9yYml0cm9uOndnaHRANDAwOzcwMDs5MDAmZmFtaWx5PVNoYXJlK1RlY2grTW9ubyZmYW1pbHk9UmFqZGhhbmk6d2dodEA0MDA7NjAwOzcwMCZkaXNwbGF5PXN3YXAnKTtcbiAgICAgICAgICAgICN0bC1jb25uLW92ZXJsYXkgeyBwb3NpdGlvbjpmaXhlZDt0b3A6MDtsZWZ0OjA7d2lkdGg6MTAwdnc7aGVpZ2h0OjEwMHZoO2JhY2tncm91bmQ6JHt0Yy5iZ092ZXJsYXl9O2JhY2tkcm9wLWZpbHRlcjpibHVyKDE1cHgpO3otaW5kZXg6MjE0NzQ4MzY0NztkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpjZW50ZXI7Zm9udC1mYW1pbHk6J1JhamRoYW5pJyxzYW5zLXNlcmlmOyB9XG4gICAgICAgICAgICAjdGwtY29ubi1wYW5lbCB7IHdpZHRoOjQyMHB4O2JhY2tncm91bmQ6JHt0Yy5iZ1BhbmVsfTtib3JkZXI6MXB4IHNvbGlkICR7dGMuYm9yZGVyU3Ryb25nfTtib3JkZXItcmFkaXVzOjIwcHg7Ym94LXNoYWRvdzowIDAgNjBweCByZ2JhKDAsMCwwLDAuOCksMCAwIDAgMXB4ICR7dGMucGFuZWxJbnNldH0gaW5zZXQ7dGV4dC1hbGlnbjpjZW50ZXI7b3ZlcmZsb3c6aGlkZGVuO2FuaW1hdGlvbjp0bEZhZGVJbiAwLjNzIGVhc2U7cG9zaXRpb246cmVsYXRpdmU7IH1cbiAgICAgICAgICAgIEBrZXlmcmFtZXMgdGxGYWRlSW4geyBmcm9te29wYWNpdHk6MDt0cmFuc2Zvcm06c2NhbGUoMC45NSl9dG97b3BhY2l0eToxO3RyYW5zZm9ybTpzY2FsZSgxKX0gfVxuICAgICAgICAgICAgI3RsLWNvbm4taGVhZGVyIHsgcGFkZGluZzoyMnB4O2JhY2tncm91bmQ6JHt0Yy5oZWFkZXJCZ307Ym9yZGVyLWJvdHRvbToxcHggc29saWQgJHt0Yy5ib3JkZXJ9OyB9XG4gICAgICAgICAgICAudGwtYnJhbmQtbmFtZSB7IGZvbnQtZmFtaWx5OidPcmJpdHJvbicsc2Fucy1zZXJpZjtmb250LXNpemU6MjJweDtmb250LXdlaWdodDo3MDA7YmFja2dyb3VuZDoke3RjLmJyYW5kR3JhZGllbnR9O2JhY2tncm91bmQtc2l6ZToyMDAlOy13ZWJraXQtYmFja2dyb3VuZC1jbGlwOnRleHQ7LXdlYmtpdC10ZXh0LWZpbGwtY29sb3I6dHJhbnNwYXJlbnQ7YW5pbWF0aW9uOnRsU2hpbW1lciAzcyBsaW5lYXIgaW5maW5pdGU7IH1cbiAgICAgICAgICAgIEBrZXlmcmFtZXMgdGxTaGltbWVyIHsgMTAwJXtiYWNrZ3JvdW5kLXBvc2l0aW9uOjIwMCUgNTAlfSB9XG4gICAgICAgICAgICAjdGwtY29ubi1ib2R5IHsgcGFkZGluZzozMHB4IDI1cHg7IH1cbiAgICAgICAgICAgIC50bC1zdWJ0aXRsZSB7IGNvbG9yOnJnYmEoMjU1LDI1NSwyNTUsMC43KTtmb250LXNpemU6MTNweDttYXJnaW4tYm90dG9tOjEwcHg7Zm9udC1mYW1pbHk6J1NoYXJlIFRlY2ggTW9ubyc7IH1cbiAgICAgICAgICAgIC50bC13YXJuaW5nIHsgY29sb3I6I2ZmYzEwNztmb250LXNpemU6MTJweDttYXJnaW4tYm90dG9tOjIwcHg7YmFja2dyb3VuZDpyZ2JhKDI1NSwxOTMsNywwLjEpO3BhZGRpbmc6OHB4O2JvcmRlci1yYWRpdXM6NnB4OyB9XG4gICAgICAgICAgICAudGwtaW5wdXQgeyB3aWR0aDoxMDAlO3BhZGRpbmc6MTRweDtiYWNrZ3JvdW5kOnJnYmEoMCwwLDAsMC41NSk7Ym9yZGVyOjFweCBzb2xpZCAke3RjLmlucHV0Qm9yZGVyfTtib3JkZXItcmFkaXVzOjEwcHg7Y29sb3I6JHt0Yy5pbnB1dENvbG9yfTtmb250LWZhbWlseTonU2hhcmUgVGVjaCBNb25vJztmb250LXNpemU6MTZweDt0ZXh0LWFsaWduOmNlbnRlcjttYXJnaW4tYm90dG9tOjE1cHg7dHJhbnNpdGlvbjowLjJzO2JveC1zaXppbmc6Ym9yZGVyLWJveDsgfVxuICAgICAgICAgICAgLnRsLWlucHV0OmZvY3VzIHsgb3V0bGluZTpub25lO2JvcmRlci1jb2xvcjoke3RjLmMxfTtib3gtc2hhZG93OjAgMCAxNnB4ICR7dGMuZ2xvd01pZH07IH1cbiAgICAgICAgICAgIC50bC1idG4geyB3aWR0aDoxMDAlO3BhZGRpbmc6MTRweDtib3JkZXI6bm9uZTtib3JkZXItcmFkaXVzOjEwcHg7Y3Vyc29yOnBvaW50ZXI7Zm9udC1mYW1pbHk6J09yYml0cm9uJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZToxNHB4O2ZvbnQtd2VpZ2h0OjkwMDttYXJnaW4tYm90dG9tOjEycHg7dHJhbnNpdGlvbjowLjJzOyB9XG4gICAgICAgICAgICAudGwtYnRuLXVubG9jayB7IGJhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDEzNWRlZywjMDBiMDliLCM5NmM5M2QpO2NvbG9yOiNmZmY7IH1cbiAgICAgICAgICAgIC50bC1idG4tdW5sb2NrOmhvdmVyIHsgdHJhbnNmb3JtOnNjYWxlKDEuMDIpO2JveC1zaGFkb3c6MCAwIDI1cHggcmdiYSgwLDE3NiwxNTUsMC42KTsgfVxuICAgICAgICAgICAgLnRsLWJ0bi12aXAgeyBiYWNrZ3JvdW5kOnJnYmEoMjE3LDQsNDEsMC4xKTtib3JkZXI6MXB4IHNvbGlkIHJnYmEoMjE3LDQsNDEsMC41KTtjb2xvcjojZWYyMzNjOyB9XG4gICAgICAgICAgICAudGwtYnRuLXZpcDpob3ZlciB7IGJhY2tncm91bmQ6cmdiYSgyMTcsNCw0MSwwLjIpO3RyYW5zZm9ybTpzY2FsZSgxLjAxKTsgfVxuICAgICAgICAgICAgI3RsLWVyciB7IGNvbG9yOiNlZjIzM2M7Zm9udC1zaXplOjEzcHg7bWFyZ2luLXRvcDoxMnB4O2Rpc3BsYXk6bm9uZTtmb250LWZhbWlseTonU2hhcmUgVGVjaCBNb25vJztiYWNrZ3JvdW5kOnJnYmEoMjM5LDM1LDYwLDAuMSk7cGFkZGluZzo4cHg7Ym9yZGVyLXJhZGl1czo2cHg7IH1cbiAgICAgICAgICAgIC50bC1od2lkIHsgY29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjIyKTtmb250LXNpemU6MTBweDttYXJnaW4tdG9wOjE1cHg7d29yZC1icmVhazpicmVhay1hbGw7Zm9udC1mYW1pbHk6bW9ub3NwYWNlOyB9XG4gICAgICAgICAgICAudGwtZm9vdCB7IG1hcmdpbi10b3A6MTVweDtmb250LXNpemU6MTFweDtjb2xvcjpyZ2JhKDI1NSwyNTUsMjU1LDAuMTMpOyB9XG4gICAgICAgICAgICAke3RjLmZ4Q1NTfVxuICAgICAgICBgOwogIH0KICBmdW5jdGlvbiBnZXRNYWluVUlTdHlsZXMoKSB7CiAgICBjb25zdCB0YyA9IGdldFRoZW1lQ29sb3JzKENVUlJFTlRfVEhFTUUpOwogICAgcmV0dXJuIGBcbiAgICAgICAgICAgIEBpbXBvcnQgdXJsKCdodHRwczovL2ZvbnRzLmdvb2dsZWFwaXMuY29tL2NzczI/ZmFtaWx5PU9yYml0cm9uOndnaHRANDAwOzcwMDs5MDAmZmFtaWx5PVNoYXJlK1RlY2grTW9ubyZmYW1pbHk9UmFqZGhhbmk6d2dodEA0MDA7NjAwOzcwMCZkaXNwbGF5PXN3YXAnKTtcbiAgICAgICAgICAgICN0bC1mbG9hdEJ0biB7IHBvc2l0aW9uOmZpeGVkO2JvdHRvbToyOHB4O3JpZ2h0OjI4cHg7d2lkdGg6NTZweDtoZWlnaHQ6NTZweDtib3JkZXItcmFkaXVzOjUwJTtib3JkZXI6bm9uZTtjdXJzb3I6cG9pbnRlcjt6LWluZGV4OjEwMDAwO2JhY2tncm91bmQ6JHt0Yy5mbG9hdEdyYWRpZW50fTtib3gtc2hhZG93OjAgMCAwIDAgJHt0Yy5nbG93U3Ryb25nfSwwIDAgMjBweCAke3RjLmdsb3dDb2xvcn0sMCA0cHggMjBweCByZ2JhKDAsMCwwLDAuNSk7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyO2ZvbnQtc2l6ZToyMnB4O3RyYW5zaXRpb246dHJhbnNmb3JtIDAuMnMgZWFzZSxib3gtc2hhZG93IDAuMnMgZWFzZTthbmltYXRpb246Y29ublB1bHNlUmluZyAyLjVzIGVhc2Utb3V0IGluZmluaXRlOyB9XG4gICAgICAgICAgICAjdGwtZmxvYXRCdG46aG92ZXIgeyB0cmFuc2Zvcm06c2NhbGUoMS4xMikgcm90YXRlKDE1ZGVnKTsgfVxuICAgICAgICAgICAgQGtleWZyYW1lcyBjb25uUHVsc2VSaW5nIHsgMCV7Ym94LXNoYWRvdzowIDAgMCAwICR7dGMuZ2xvd1B1bHNlfX03MCV7Ym94LXNoYWRvdzowIDAgMCAxNXB4IHJnYmEoMCwwLDAsMCl9MTAwJXtib3gtc2hhZG93OjAgMCAwIDAgcmdiYSgwLDAsMCwwKX0gfVxuICAgICAgICAgICAgQGtleWZyYW1lcyBjb25uQmxpbmsgeyAwJSwxMDAle29wYWNpdHk6MX01MCV7b3BhY2l0eTowLjN9IH1cbiAgICAgICAgICAgICN0bC1wYW5lbCB7IHBvc2l0aW9uOmZpeGVkO3RvcDo1MCU7bGVmdDo1MCU7dHJhbnNmb3JtOnRyYW5zbGF0ZSgtNTAlLC01MCUpO3dpZHRoOjM2MHB4O2JhY2tncm91bmQ6JHt0Yy5iZ1BhbmVsfTtiYWNrZHJvcC1maWx0ZXI6Ymx1cigyNHB4KTtib3JkZXI6MXB4IHNvbGlkICR7dGMuYm9yZGVyfTtib3JkZXItcmFkaXVzOjE2cHg7Ym94LXNoYWRvdzowIDAgNjBweCByZ2JhKDAsMCwwLDAuOCk7ei1pbmRleDo5OTk5O292ZXJmbG93OmhpZGRlbjtmb250LWZhbWlseTonUmFqZGhhbmknLHNhbnMtc2VyaWY7IH1cbiAgICAgICAgICAgICN0bC1wYW5lbC5oaWRkZW4geyBkaXNwbGF5Om5vbmU7IH1cbiAgICAgICAgICAgICN0bC1wLWhlYWRlciB7IGN1cnNvcjptb3ZlO3BhZGRpbmc6MTRweCAxNnB4IDEycHg7YmFja2dyb3VuZDoke3RjLmhlYWRlckJnfTtib3JkZXItYm90dG9tOjFweCBzb2xpZCAke3RjLmJvcmRlclN1YnRsZX07ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2VlbjsgfVxuICAgICAgICAgICAgLnRsLXAtYnJhbmQgeyBkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDo4cHg7IH1cbiAgICAgICAgICAgIC50bC1wLW5hbWUgeyBmb250LWZhbWlseTonT3JiaXRyb24nLHNhbnMtc2VyaWY7Zm9udC1zaXplOjExLjVweDtmb250LXdlaWdodDo3MDA7YmFja2dyb3VuZDoke3RjLmJyYW5kR3JhZGllbnR9O2JhY2tncm91bmQtc2l6ZToyMDAlOy13ZWJraXQtYmFja2dyb3VuZC1jbGlwOnRleHQ7LXdlYmtpdC10ZXh0LWZpbGwtY29sb3I6dHJhbnNwYXJlbnQ7YW5pbWF0aW9uOnRsU2hpbW1lciAzcyBsaW5lYXIgaW5maW5pdGU7IH1cbiAgICAgICAgICAgIEBrZXlmcmFtZXMgdGxTaGltbWVyIHsgMTAwJXtiYWNrZ3JvdW5kLXBvc2l0aW9uOjIwMCUgNTAlfSB9XG4gICAgICAgICAgICAudGwtYmFkZ2UgeyBmb250LWZhbWlseTonT3JiaXRyb24nO2ZvbnQtc2l6ZTo3LjVweDtmb250LXdlaWdodDo5MDA7Y29sb3I6I2ZmZjtib3JkZXItcmFkaXVzOjRweDtwYWRkaW5nOjNweCA2cHg7YmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLCM1NTUsIzc3Nyk7IH1cbiAgICAgICAgICAgIC50bC1iYWRnZS52aXAgeyBiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCgxMzVkZWcsI2E4NTVmNywjNjM2NmYxKTtib3gtc2hhZG93OjAgMCAxMHB4IHJnYmEoMTY4LDg1LDI0NywwLjQpOyB9XG4gICAgICAgICAgICAudGwtYmFkZ2UudW5saW1pdGVkIHsgYmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLCNmNTllMGIsI2VmNDQ0NCk7Ym94LXNoYWRvdzowIDAgMTBweCByZ2JhKDI0NSwxNTgsMTEsMC40KTsgfVxuICAgICAgICAgICAgI3RsLWNsb3NlQnRuLCN0bC1zZXR0aW5nc0J0biB7IHdpZHRoOjI4cHg7aGVpZ2h0OjI4cHg7Ym9yZGVyLXJhZGl1czo1MCU7Ym9yZGVyOjFweCBzb2xpZCByZ2JhKDI1NSwyNTUsMjU1LDAuMSk7YmFja2dyb3VuZDpyZ2JhKDI1NSwyNTUsMjU1LDAuMDQpO2NvbG9yOnJnYmEoMjU1LDI1NSwyNTUsMC41KTtjdXJzb3I6cG9pbnRlcjtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpjZW50ZXI7dHJhbnNpdGlvbjowLjJzO2ZvbnQtc2l6ZToxM3B4OyB9XG4gICAgICAgICAgICAjdGwtY2xvc2VCdG46aG92ZXIgeyBib3JkZXItY29sb3I6cmdiYSgyMTcsNCw0MSwwLjYpO2JhY2tncm91bmQ6cmdiYSgyMTcsNCw0MSwwLjE1KTtjb2xvcjojZWYyMzNjOyB9XG4gICAgICAgICAgICAjdGwtc2V0dGluZ3NCdG46aG92ZXIgeyBib3JkZXItY29sb3I6JHt0Yy5ib3JkZXJTdHJvbmd9O2JhY2tncm91bmQ6JHt0Yy5nbG93U3VidGxlfTtjb2xvcjoke3RjLmMxfTsgfVxuICAgICAgICAgICAgI3RsLXNldHRpbmdzQnRuLmFjdGl2ZSB7IGJvcmRlci1jb2xvcjoke3RjLmMxfTtiYWNrZ3JvdW5kOiR7dGMuZ2xvd1N1YnRsZX07Y29sb3I6JHt0Yy5jMX07IH1cbiAgICAgICAgICAgICN0bC1wLWJvZHkgeyBwYWRkaW5nOjE0cHg7ZGlzcGxheTpmbGV4O2ZsZXgtZGlyZWN0aW9uOmNvbHVtbjtnYXA6MTJweDsgfVxuICAgICAgICAgICAgLnRsLXN0YXRib3ggeyBib3JkZXI6MXB4IHNvbGlkICR7dGMuc3RhdHVzQm9yZGVyfTtib3JkZXItcmFkaXVzOjEwcHg7cGFkZGluZzoxMHB4O2JhY2tncm91bmQ6JHt0Yy5zdGF0dXNCZ307IH1cbiAgICAgICAgICAgIC50bC1zdGF0cm93IHsgZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6OHB4O2ZvbnQtZmFtaWx5OidTaGFyZSBUZWNoIE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6MTEuNXB4O2NvbG9yOiNjY2M7bWFyZ2luLXRvcDo0cHg7IH1cbiAgICAgICAgICAgICN0bC1tb2RlU2VsZWN0IHsgd2lkdGg6MTAwJTtwYWRkaW5nOjEwcHg7YmFja2dyb3VuZDpyZ2JhKDAsMCwwLDAuNCk7Ym9yZGVyOjFweCBzb2xpZCAke3RjLnNlbGVjdEJvcmRlcn07Ym9yZGVyLXJhZGl1czo4cHg7Y29sb3I6I2ZmZjtmb250LWZhbWlseTonUmFqZGhhbmknLHNhbnMtc2VyaWY7Zm9udC1zaXplOjE0cHg7b3V0bGluZTpub25lO21hcmdpbi10b3A6NXB4OyB9CiAgICAgICAgICAgICN0bC1nb2QtdGFyZ2V0LXNjb3JlIHsgd2lkdGg6MTAwJTtwYWRkaW5nOjEwcHg7YmFja2dyb3VuZDpyZ2JhKDAsMCwwLDAuNCk7Ym9yZGVyOjFweCBzb2xpZCAke3RjLnNlbGVjdEJvcmRlcn07Ym9yZGVyLXJhZGl1czo4cHg7Y29sb3I6I2ZmYzEwNztmb250LWZhbWlseTonUmFqZGhhbmknLHNhbnMtc2VyaWY7Zm9udC1zaXplOjE0cHg7b3V0bGluZTpub25lO21hcmdpbi10b3A6NXB4OyB9XG4gICAgICAgICAgICAudGwtZ29kLWlucHV0IHsgd2lkdGg6MTAwJTtwYWRkaW5nOjEwcHg7YmFja2dyb3VuZDpyZ2JhKDAsMCwwLDAuNCk7Ym9yZGVyOjFweCBzb2xpZCByZ2JhKDI1NSwxOTMsNywwLjMpO2JvcmRlci1yYWRpdXM6OHB4O2NvbG9yOiNmZmMxMDc7Zm9udC1mYW1pbHk6J1NoYXJlIFRlY2ggTW9ubyc7Zm9udC1zaXplOjEzcHg7b3V0bGluZTpub25lO21hcmdpbi10b3A6NXB4O2JveC1zaXppbmc6Ym9yZGVyLWJveDsgfVxuICAgICAgICAgICAgI3RsLWZpcmVCdG4geyB3aWR0aDoxMDAlO3BhZGRpbmc6MTNweDtiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCgxMzVkZWcsI2Q5MDQyOSwjZWYyMzNjKTtib3JkZXI6bm9uZTtib3JkZXItcmFkaXVzOjEwcHg7Y29sb3I6I2ZmZjtmb250LWZhbWlseTonT3JiaXRyb24nO2ZvbnQtd2VpZ2h0OjkwMDtmb250LXNpemU6MTRweDtjdXJzb3I6cG9pbnRlcjtib3gtc2hhZG93OjAgMCAyMHB4IHJnYmEoMjE3LDQsNDEsMC40KTt0cmFuc2l0aW9uOjAuMnM7bWFyZ2luLXRvcDo1cHg7IH1cbiAgICAgICAgICAgICN0bC1maXJlQnRuOmhvdmVyIHsgYm94LXNoYWRvdzowIDAgMzBweCByZ2JhKDIxNyw0LDQxLDAuNyk7IH1cbiAgICAgICAgICAgICN0bC1maXJlQnRuOmRpc2FibGVkIHsgb3BhY2l0eTowLjU7Y3Vyc29yOm5vdC1hbGxvd2VkOyB9XG4gICAgICAgICAgICAudGwtY29uc29sZSB7IGJvcmRlcjoxcHggc29saWQgJHt0Yy5jb25zb2xlQm9yZGVyfTtib3JkZXItcmFkaXVzOjEwcHg7YmFja2dyb3VuZDpyZ2JhKDAsMCwwLDAuNSk7cGFkZGluZzo4cHg7aGVpZ2h0OjgwcHg7b3ZlcmZsb3cteTphdXRvO2ZvbnQtZmFtaWx5OidTaGFyZSBUZWNoIE1vbm8nO2ZvbnQtc2l6ZToxMC41cHg7Y29sb3I6I2FhYTsgfVxuICAgICAgICAgICAgLnRsLWxvZyB7IG1hcmdpbi1ib3R0b206MnB4OyB9XG4gICAgICAgICAgICAudGwtbG9nLm9rICAgeyBjb2xvcjojMDBlNjc2OyB9XG4gICAgICAgICAgICAudGwtbG9nLmVyciAgeyBjb2xvcjojZWYyMzNjOyB9XG4gICAgICAgICAgICAudGwtbG9nLndhcm4geyBjb2xvcjojZmZjMTA3OyB9XG4gICAgICAgICAgICAudGwtbG9nLmluZm8geyBjb2xvcjojNGZhY2ZlOyB9XG4gICAgICAgICAgICAjdGwtcC1mb290ZXIgeyBwYWRkaW5nOjhweCAxNHB4O2JvcmRlci10b3A6MXB4IHNvbGlkICR7dGMuYm9yZGVyU3VidGxlfTtkaXNwbGF5OmZsZXg7anVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47Zm9udC1mYW1pbHk6J1NoYXJlIFRlY2ggTW9ubyc7Zm9udC1zaXplOjlweDtjb2xvcjpyZ2JhKDI1NSwyNTUsMjU1LDAuMik7IH1cbiAgICAgICAgICAgIFxuICAgICAgICAgICAgI3RsLXNvIHsgcG9zaXRpb246YWJzb2x1dGU7dG9wOjA7bGVmdDowO3JpZ2h0OjA7Ym90dG9tOjA7YmFja2dyb3VuZDoke3RjLmJnUGFuZWx9O2JhY2tkcm9wLWZpbHRlcjpibHVyKDEycHgpO3otaW5kZXg6MjA7Ym9yZGVyLXJhZGl1czoxNnB4O2Rpc3BsYXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47b3ZlcmZsb3c6aGlkZGVuOyB9XG4gICAgICAgICAgICAjdGwtc28uaGlkZGVuIHsgZGlzcGxheTpub25lOyB9XG4gICAgICAgICAgICAudGwtc28taGRyIHsgcGFkZGluZzoxM3B4IDE2cHg7YmFja2dyb3VuZDoke3RjLmhlYWRlckJnfTtib3JkZXItYm90dG9tOjFweCBzb2xpZCAke3RjLmJvcmRlclN1YnRsZX07ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2VlbjtmbGV4LXNocmluazowOyB9XG4gICAgICAgICAgICAudGwtc28tdGl0bGUgeyBmb250LWZhbWlseTonT3JiaXRyb24nLHNhbnMtc2VyaWY7Zm9udC1zaXplOjEwLjVweDtmb250LXdlaWdodDo3MDA7Y29sb3I6JHt0Yy5jMX07IH1cbiAgICAgICAgICAgICN0bC1zb0Nsb3NlIHsgd2lkdGg6MjZweDtoZWlnaHQ6MjZweDtib3JkZXItcmFkaXVzOjUwJTtib3JkZXI6MXB4IHNvbGlkICR7dGMuYm9yZGVyfTtiYWNrZ3JvdW5kOiR7dGMuZ2xvd1N1YnRsZX07Y29sb3I6JHt0Yy5jMX07Y3Vyc29yOnBvaW50ZXI7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyO2ZvbnQtc2l6ZToxMnB4O3RyYW5zaXRpb246MC4yczsgfVxuICAgICAgICAgICAgI3RsLXNvQ2xvc2U6aG92ZXIgeyBiYWNrZ3JvdW5kOnJnYmEoMjE3LDQsNDEsMC4xNSk7Ym9yZGVyLWNvbG9yOnJnYmEoMjE3LDQsNDEsMC41KTtjb2xvcjojZWYyMzNjOyB9XG4gICAgICAgICAgICAudGwtc28tYm9keSB7IHBhZGRpbmc6MTRweDtmbGV4OjE7ZGlzcGxheTpmbGV4O2ZsZXgtZGlyZWN0aW9uOmNvbHVtbjtnYXA6MTJweDtvdmVyZmxvdy15OmF1dG87IH1cbiAgICAgICAgICAgIC50bC1zby1sYmwgeyBmb250LXNpemU6OS41cHg7Zm9udC13ZWlnaHQ6NzAwO2NvbG9yOnJnYmEoMjU1LDI1NSwyNTUsMC4yOCk7dGV4dC10cmFuc2Zvcm06dXBwZXJjYXNlO2ZvbnQtZmFtaWx5OidPcmJpdHJvbic7bGV0dGVyLXNwYWNpbmc6MS4ycHg7bWFyZ2luLWJvdHRvbToycHg7IH1cbiAgICAgICAgICAgIC50bC10aGVtZS1jYXJkcyB7IGRpc3BsYXk6ZmxleDtnYXA6OHB4OyB9XG4gICAgICAgICAgICAudGwtdGMgeyBmbGV4OjE7Y3Vyc29yOnBvaW50ZXI7Ym9yZGVyLXJhZGl1czoxMHB4O2JvcmRlcjoycHggc29saWQgcmdiYSgyNTUsMjU1LDI1NSwwLjA3KTtwYWRkaW5nOjhweCA2cHg7dGV4dC1hbGlnbjpjZW50ZXI7dHJhbnNpdGlvbjphbGwgMC4yMnM7YmFja2dyb3VuZDpyZ2JhKDAsMCwwLDAuMyk7cG9zaXRpb246cmVsYXRpdmU7IH1cbiAgICAgICAgICAgIC50bC10Yzpob3ZlciB7IHRyYW5zZm9ybTp0cmFuc2xhdGVZKC0zcHgpO2JvcmRlci1jb2xvcjpyZ2JhKDI1NSwyNTUsMjU1LDAuMTgpO2JveC1zaGFkb3c6MCA2cHggMThweCByZ2JhKDAsMCwwLDAuNCk7IH1cbiAgICAgICAgICAgIC50bC10Yy5hY3RpdmUgeyBib3JkZXItY29sb3I6JHt0Yy5jMX07Ym94LXNoYWRvdzowIDAgMTRweCAke3RjLmdsb3dNaWR9OyB9XG4gICAgICAgICAgICAudGwtdGMtcHJldiB7IHdpZHRoOjEwMCU7aGVpZ2h0OjM4cHg7Ym9yZGVyLXJhZGl1czo3cHg7bWFyZ2luLWJvdHRvbTo3cHg7b3ZlcmZsb3c6aGlkZGVuO3Bvc2l0aW9uOnJlbGF0aXZlOyB9XG4gICAgICAgICAgICAudGwtdGMtcHJldi1pbm5lciB7IHBvc2l0aW9uOmFic29sdXRlO2luc2V0OjA7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyOyB9XG4gICAgICAgICAgICAudGwtdGMtcHJldi10ZXh0IHsgZm9udC1mYW1pbHk6J09yYml0cm9uJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZTo3cHg7Zm9udC13ZWlnaHQ6NzAwO2xldHRlci1zcGFjaW5nOjFweDtvcGFjaXR5OjAuOTsgfVxuICAgICAgICAgICAgLnRsLXRjLWxibCB7IGZvbnQtZmFtaWx5OidSYWpkaGFuaScsc2Fucy1zZXJpZjtmb250LXNpemU6MTAuNXB4O2ZvbnQtd2VpZ2h0OjYwMDtjb2xvcjpyZ2JhKDI1NSwyNTUsMjU1LDAuNik7IH1cbiAgICAgICAgICAgIC50bC10Yy5hY3RpdmUgLnRsLXRjLWxibCB7IGNvbG9yOiR7dGMuYzF9O2ZvbnQtd2VpZ2h0OjcwMDsgfVxuICAgICAgICAgICAgLnRsLXRjLmFjdGl2ZTo6YWZ0ZXIgeyBjb250ZW50OifinJMnO3Bvc2l0aW9uOmFic29sdXRlO3RvcDo1cHg7cmlnaHQ6N3B4O2NvbG9yOiR7dGMuYzF9O2ZvbnQtc2l6ZToxMXB4O2ZvbnQtd2VpZ2h0OjkwMDsgfVxuICAgICAgICAgICAgLnRsLXNvLWRpdmlkZXIgeyBoZWlnaHQ6MXB4O2JhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDkwZGVnLHRyYW5zcGFyZW50LCR7dGMuYm9yZGVyfSx0cmFuc3BhcmVudCk7IH1cbiAgICAgICAgICAgIC50bC1oaW50IHsgZm9udC1zaXplOjEwcHg7Y29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjIpO2ZvbnQtZmFtaWx5OidTaGFyZSBUZWNoIE1vbm8nO3RleHQtYWxpZ246Y2VudGVyO2xpbmUtaGVpZ2h0OjEuNjsgfVxuICAgICAgICAgICAgLnRsLWNoYW5nZS1rZXkgeyB3aWR0aDoxMDAlO3BhZGRpbmc6MTBweDtiYWNrZ3JvdW5kOnJnYmEoMjM5LDM1LDYwLDAuMSk7Ym9yZGVyOjFweCBzb2xpZCByZ2JhKDIzOSwzNSw2MCwwLjM4KTtib3JkZXItcmFkaXVzOjhweDtjb2xvcjojZWYyMzNjO2ZvbnQtZmFtaWx5OidPcmJpdHJvbicsc2Fucy1zZXJpZjtmb250LXNpemU6MTAuNXB4O2ZvbnQtd2VpZ2h0OjcwMDtjdXJzb3I6cG9pbnRlcjt0cmFuc2l0aW9uOjAuMnM7bGV0dGVyLXNwYWNpbmc6MC41cHg7IH1cbiAgICAgICAgICAgIC50bC1jaGFuZ2Uta2V5OmhvdmVyIHsgYmFja2dyb3VuZDpyZ2JhKDIzOSwzNSw2MCwwLjIpO2JvcmRlci1jb2xvcjpyZ2JhKDIzOSwzNSw2MCwwLjY1KTtib3gtc2hhZG93OjAgMCAxNHB4IHJnYmEoMjM5LDM1LDYwLDAuMjUpOyB9XG4gICAgICAgICAgICBcbiAgICAgICAgICAgICN0aWVwLW1vZGFsLW92ZXJsYXkgeyBwb3NpdGlvbjpmaXhlZDt0b3A6MDtsZWZ0OjA7d2lkdGg6MTAwdnc7aGVpZ2h0OjEwMHZoO2JhY2tncm91bmQ6cmdiYSgwLDAsMCwwLjcyKTt6LWluZGV4OjIxNDc0ODM2NDY7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyOyB9XG4gICAgICAgICAgICAudGllcC1tb2RhbC1ib3ggeyB3aWR0aDozMjBweDtiYWNrZ3JvdW5kOiR7dGMuYmdQYW5lbH07Ym9yZGVyOjFweCBzb2xpZCAke3RjLmJvcmRlclN0cm9uZ307Ym9yZGVyLXJhZGl1czoxNnB4O3BhZGRpbmc6MjZweCAyMnB4IDIycHg7dGV4dC1hbGlnbjpjZW50ZXI7Ym94LXNoYWRvdzowIDAgNjBweCByZ2JhKDAsMCwwLDAuOSksaW5zZXQgMCAwIDAgMXB4ICR7dGMucGFuZWxJbnNldH07Zm9udC1mYW1pbHk6J1JhamRoYW5pJyxzYW5zLXNlcmlmOyB9XG4gICAgICAgICAgICAudGllcC1tb2RhbC1pY29uIHsgZm9udC1zaXplOjM4cHg7bWFyZ2luLWJvdHRvbTo4cHg7IH1cbiAgICAgICAgICAgIC50aWVwLW1vZGFsLXRpdGxlIHsgZm9udC1mYW1pbHk6J09yYml0cm9uJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZToxMnB4O2ZvbnQtd2VpZ2h0OjcwMDtjb2xvcjoke3RjLmMxfTttYXJnaW4tYm90dG9tOjEycHg7bGluZS1oZWlnaHQ6MS41OyB9XG4gICAgICAgICAgICAudGllcC1tb2RhbC1saW5lcyB7IGNvbG9yOnJnYmEoMjU1LDI1NSwyNTUsMC43OCk7Zm9udC1zaXplOjEzcHg7bGluZS1oZWlnaHQ6MS42NTttYXJnaW4tYm90dG9tOjE4cHg7IH1cbiAgICAgICAgICAgIC50aWVwLW1vZGFsLWxpbmVzIGIgeyBjb2xvcjojZmZmOyB9XG4gICAgICAgICAgICAudGllcC1tb2RhbC1vayB7IHBhZGRpbmc6MTBweCAzNnB4O2JhY2tncm91bmQ6JHt0Yy5mbG9hdEdyYWRpZW50fTtib3JkZXI6bm9uZTtib3JkZXItcmFkaXVzOjhweDtjb2xvcjojZmZmO2ZvbnQtZmFtaWx5OidPcmJpdHJvbicsc2Fucy1zZXJpZjtmb250LXNpemU6MTEuNXB4O2ZvbnQtd2VpZ2h0OjkwMDtjdXJzb3I6cG9pbnRlcjt0cmFuc2l0aW9uOjAuMnM7Ym94LXNoYWRvdzowIDRweCAxNnB4ICR7dGMuZ2xvd0NvbG9yfTsgfVxuICAgICAgICAgICAgLnRpZXAtbW9kYWwtb2s6aG92ZXIgeyB0cmFuc2Zvcm06c2NhbGUoMS4wNik7Ym94LXNoYWRvdzowIDAgMjRweCAke3RjLmdsb3dDb2xvcn07IH1cbiAgICAgICAgICAgICR7dGMuZnhDU1N9XG4gICAgICAgIGA7CiAgfQogIGZ1bmN0aW9uIF9lbnN1cmVNb2RhbFN0eWxlKCkgewogICAgaWYgKGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0aWVwLW1vZGFsLXN0eWxlJykpIHJldHVybjsKICAgIGNvbnN0IHRjID0gZ2V0VGhlbWVDb2xvcnMoQ1VSUkVOVF9USEVNRSk7CiAgICBjb25zdCBtcyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ3N0eWxlJyk7CiAgICBtcy5pZCA9ICd0aWVwLW1vZGFsLXN0eWxlJzsKICAgIG1zLnRleHRDb250ZW50ID0gYFxuICAgICAgICAgICAgQGtleWZyYW1lcyB0bE1vZGFsSW57ZnJvbXtvcGFjaXR5OjA7dHJhbnNmb3JtOnNjYWxlKDAuOTIpfXRve29wYWNpdHk6MTt0cmFuc2Zvcm06c2NhbGUoMSl9fVxuICAgICAgICAgICAgI3RpZXAtbW9kYWwtb3ZlcmxheXtwb3NpdGlvbjpmaXhlZCFpbXBvcnRhbnQ7dG9wOjAhaW1wb3J0YW50O2xlZnQ6MCFpbXBvcnRhbnQ7d2lkdGg6MTAwdnchaW1wb3J0YW50O2hlaWdodDoxMDB2aCFpbXBvcnRhbnQ7YmFja2dyb3VuZDpyZ2JhKDAsMCwwLDAuNzUpIWltcG9ydGFudDt6LWluZGV4OjIxNDc0ODM2NDYhaW1wb3J0YW50O2Rpc3BsYXk6ZmxleCFpbXBvcnRhbnQ7YWxpZ24taXRlbXM6Y2VudGVyIWltcG9ydGFudDtqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyIWltcG9ydGFudDt9XG4gICAgICAgICAgICAudGllcC1tb2RhbC1ib3h7d2lkdGg6MzIwcHg7bWF4LXdpZHRoOjkwdnc7YmFja2dyb3VuZDoke3RjLmJnUGFuZWx9O2JvcmRlcjoxcHggc29saWQgJHt0Yy5ib3JkZXJTdHJvbmd9O2JvcmRlci1yYWRpdXM6MTZweDtwYWRkaW5nOjI2cHggMjJweCAyMnB4O3RleHQtYWxpZ246Y2VudGVyO2JveC1zaGFkb3c6MCAwIDYwcHggcmdiYSgwLDAsMCwwLjkpLGluc2V0IDAgMCAwIDFweCAke3RjLnBhbmVsSW5zZXR9O2ZvbnQtZmFtaWx5OidSYWpkaGFuaScsc2Fucy1zZXJpZjthbmltYXRpb246dGxNb2RhbEluIDAuMjJzIGVhc2U7fVxuICAgICAgICAgICAgLnRpZXAtbW9kYWwtaWNvbntmb250LXNpemU6MzhweDttYXJnaW4tYm90dG9tOjhweDt9XG4gICAgICAgICAgICAudGllcC1tb2RhbC10aXRsZXtmb250LWZhbWlseTonT3JiaXRyb24nLHNhbnMtc2VyaWY7Zm9udC1zaXplOjEycHg7Zm9udC13ZWlnaHQ6NzAwO2NvbG9yOiR7dGMuYzF9O21hcmdpbi1ib3R0b206MTJweDtsaW5lLWhlaWdodDoxLjU7fVxuICAgICAgICAgICAgLnRpZXAtbW9kYWwtbGluZXN7Y29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjgyKTtmb250LXNpemU6MTNweDtsaW5lLWhlaWdodDoxLjc7bWFyZ2luLWJvdHRvbToxOHB4O31cbiAgICAgICAgICAgIC50aWVwLW1vZGFsLWxpbmVzIGJ7Y29sb3I6I2ZmZjt9XG4gICAgICAgICAgICAudGllcC1tb2RhbC1va3twYWRkaW5nOjEwcHggMzZweDtiYWNrZ3JvdW5kOiR7dGMuZmxvYXRHcmFkaWVudH07Ym9yZGVyOm5vbmU7Ym9yZGVyLXJhZGl1czo4cHg7Y29sb3I6I2ZmZjtmb250LWZhbWlseTonT3JiaXRyb24nLHNhbnMtc2VyaWY7Zm9udC1zaXplOjExLjVweDtmb250LXdlaWdodDo5MDA7Y3Vyc29yOnBvaW50ZXI7dHJhbnNpdGlvbjowLjJzO2JveC1zaGFkb3c6MCA0cHggMTZweCAke3RjLmdsb3dDb2xvcn07fVxuICAgICAgICAgICAgLnRpZXAtbW9kYWwtb2s6aG92ZXJ7dHJhbnNmb3JtOnNjYWxlKDEuMDYpO2JveC1zaGFkb3c6MCAwIDI0cHggJHt0Yy5nbG93Q29sb3J9O31cbiAgICAgICAgYDsKICAgIGRvY3VtZW50LmhlYWQuYXBwZW5kQ2hpbGQobXMpOwogIH0KICBmdW5jdGlvbiBzaG93Q3VzdG9tTW9kYWwoe2ljb246IGljb24sIHRpdGxlOiB0aXRsZSwgbGluZXM6IGxpbmVzLCBvbk9rOiBvbk9rfSkgewogICAgX2Vuc3VyZU1vZGFsU3R5bGUoKTsKICAgIGNvbnN0IGV4aXN0aW5nID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RpZXAtbW9kYWwtb3ZlcmxheScpOwogICAgaWYgKGV4aXN0aW5nKSBleGlzdGluZy5yZW1vdmUoKTsKICAgIGNvbnN0IG92ZXJsYXkgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgIG92ZXJsYXkuaWQgPSAndGllcC1tb2RhbC1vdmVybGF5JzsKICAgIGNvbnN0IGxpbmVzSFRNTCA9IChBcnJheS5pc0FycmF5KGxpbmVzKSA/IGxpbmVzIDogWyBsaW5lcyBdKS5tYXAobCA9PiBgPGRpdj4ke2x9PC9kaXY+YCkuam9pbignJyk7CiAgICBvdmVybGF5LmlubmVySFRNTCA9IGBcbiAgICAgICAgICAgIDxkaXYgY2xhc3M9InRpZXAtbW9kYWwtYm94Ij5cbiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0aWVwLW1vZGFsLWljb24iPiR7aWNvbiB8fCAn4oS577iPJ308L2Rpdj5cbiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0aWVwLW1vZGFsLXRpdGxlIj4ke3RpdGxlIHx8ICdUaMO0bmcgYsOhbyd9PC9kaXY+XG4gICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGllcC1tb2RhbC1saW5lcyI+JHtsaW5lc0hUTUx9PC9kaXY+XG4gICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0idGllcC1tb2RhbC1vayIgaWQ9InRpZXAtbW9kYWwtb2stYnRuIj5PSzwvYnV0dG9uPlxuICAgICAgICAgICAgPC9kaXY+YDsKICAgIGRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQob3ZlcmxheSk7CiAgICBjb25zdCBjbG9zZSA9ICgpID0+IHsKICAgICAgb3ZlcmxheS5yZW1vdmUoKTsKICAgICAgaWYgKG9uT2spIG9uT2soKTsKICAgIH07CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGllcC1tb2RhbC1vay1idG4nKS5vbmNsaWNrID0gY2xvc2U7CiAgICBvdmVybGF5Lm9uY2xpY2sgPSBlID0+IHsKICAgICAgaWYgKGUudGFyZ2V0ID09PSBvdmVybGF5KSBjbG9zZSgpOwogICAgfTsKICB9CiAgZnVuY3Rpb24gc2hvd0NvbmZpcm1Nb2RhbCh7aWNvbjogaWNvbiwgdGl0bGU6IHRpdGxlLCBsaW5lczogbGluZXMsIG9rVGV4dDogb2tUZXh0LCBjYW5jZWxUZXh0OiBjYW5jZWxUZXh0LCBvbk9rOiBvbk9rfSkgewogICAgX2Vuc3VyZU1vZGFsU3R5bGUoKTsKICAgIGNvbnN0IGV4aXN0aW5nID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RpZXAtbW9kYWwtb3ZlcmxheScpOwogICAgaWYgKGV4aXN0aW5nKSBleGlzdGluZy5yZW1vdmUoKTsKICAgIGNvbnN0IG92ZXJsYXkgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgIG92ZXJsYXkuaWQgPSAndGllcC1tb2RhbC1vdmVybGF5JzsKICAgIGNvbnN0IGxpbmVzSFRNTCA9IChBcnJheS5pc0FycmF5KGxpbmVzKSA/IGxpbmVzIDogWyBsaW5lcyBdKS5tYXAobCA9PiBgPGRpdj4ke2x9PC9kaXY+YCkuam9pbignJyk7CiAgICBvdmVybGF5LmlubmVySFRNTCA9IGBcbiAgICAgICAgICAgIDxkaXYgY2xhc3M9InRpZXAtbW9kYWwtYm94Ij5cbiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0aWVwLW1vZGFsLWljb24iPiR7aWNvbiB8fCAn4p2TJ308L2Rpdj5cbiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0aWVwLW1vZGFsLXRpdGxlIj4ke3RpdGxlIHx8ICdYw6FjIG5o4bqtbid9PC9kaXY+XG4gICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGllcC1tb2RhbC1saW5lcyI+JHtsaW5lc0hUTUx9PC9kaXY+XG4gICAgICAgICAgICAgICAgPGRpdiBzdHlsZT0iZGlzcGxheTpmbGV4O2dhcDoxMHB4O2p1c3RpZnktY29udGVudDpjZW50ZXI7Ij5cbiAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0idGllcC1tb2RhbC1vayIgaWQ9InRpZXAtY29uZmlybS1jYW5jZWwtYnRuIiBzdHlsZT0iYmFja2dyb3VuZDpyZ2JhKDI1NSwyNTUsMjU1LDAuMDgpO2JveC1zaGFkb3c6bm9uZTsiPiR7Y2FuY2VsVGV4dCB8fCAnSOG7plknfTwvYnV0dG9uPlxuICAgICAgICAgICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJ0aWVwLW1vZGFsLW9rIiBpZD0idGllcC1jb25maXJtLW9rLWJ0biI+JHtva1RleHQgfHwgJ1jDgUMgTkjhuqxOJ308L2J1dHRvbj5cbiAgICAgICAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICAgIDwvZGl2PmA7CiAgICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKG92ZXJsYXkpOwogICAgY29uc3QgZGlzbWlzcyA9ICgpID0+IG92ZXJsYXkucmVtb3ZlKCk7CiAgICBjb25zdCBjb25maXJtID0gKCkgPT4gewogICAgICBvdmVybGF5LnJlbW92ZSgpOwogICAgICBpZiAob25Paykgb25PaygpOwogICAgfTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0aWVwLWNvbmZpcm0tY2FuY2VsLWJ0bicpLm9uY2xpY2sgPSBkaXNtaXNzOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RpZXAtY29uZmlybS1vay1idG4nKS5vbmNsaWNrID0gY29uZmlybTsKICAgIG92ZXJsYXkub25jbGljayA9IGUgPT4gewogICAgICBpZiAoZS50YXJnZXQgPT09IG92ZXJsYXkpIGRpc21pc3MoKTsKICAgIH07CiAgfQogIGZ1bmN0aW9uIGFwcGx5VGhlbWVMaXZlKG5ld1RoZW1lKSB7CiAgICBDVVJSRU5UX1RIRU1FID0gbmV3VGhlbWU7CiAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShMU19USEVNRSwgbmV3VGhlbWUpOwogICAgY29uc3QgdWlTdHlsZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC11aS1zdHlsZScpOwogICAgaWYgKHVpU3R5bGUpIHVpU3R5bGUudGV4dENvbnRlbnQgPSBnZXRNYWluVUlTdHlsZXMoKTsKICAgIGNvbnN0IGxvY2tTdHlsZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1sb2NrLXN0eWxlJyk7CiAgICBpZiAobG9ja1N0eWxlKSBsb2NrU3R5bGUudGV4dENvbnRlbnQgPSBnZXRMb2NrU2NyZWVuU3R5bGVzKCk7CiAgICBjb25zdCBtcyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0aWVwLW1vZGFsLXN0eWxlJyk7CiAgICBpZiAobXMpIG1zLnJlbW92ZSgpOwogICAgY29uc3QgZmIgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtZmxvYXRCdG4nKTsKICAgIGlmIChmYikgewogICAgICBmYi5zdHlsZS5hbmltYXRpb24gPSAnbm9uZSc7CiAgICAgIHZvaWQgZmIub2Zmc2V0V2lkdGg7CiAgICAgIGZiLnN0eWxlLmFuaW1hdGlvbiA9ICcnOwogICAgfQogICAgY29uc3QgbG9ja1BhbmVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLWNvbm4tcGFuZWwnKTsKICAgIGlmIChsb2NrUGFuZWwpIHsKICAgICAgY29uc3QgZXhpc3RGeCA9IGxvY2tQYW5lbC5xdWVyeVNlbGVjdG9yKCcjdGwtY29ubi1meC1iYXIsI3RsLWNvbm4tZngtcGV0YWxzJyk7CiAgICAgIGlmIChleGlzdEZ4KSBleGlzdEZ4LnJlbW92ZSgpOwogICAgICBjb25zdCB0YyA9IGdldFRoZW1lQ29sb3JzKG5ld1RoZW1lKTsKICAgICAgaWYgKHRjLnBhbmVsRXh0cmEpIHsKICAgICAgICBjb25zdCB0bXAgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgICAgICB0bXAuaW5uZXJIVE1MID0gdGMucGFuZWxFeHRyYTsKICAgICAgICBsb2NrUGFuZWwuaW5zZXJ0QmVmb3JlKHRtcC5maXJzdEVsZW1lbnRDaGlsZCwgbG9ja1BhbmVsLmZpcnN0Q2hpbGQpOwogICAgICB9CiAgICB9CiAgfQogIGxldCBfc2VjU2Vzc2lvbiA9IHsKICAgIHRva2VuOiBudWxsLAogICAgZXhwOiAwLAogICAgZnBIYXNoOiBudWxsLAogICAgc2VxOiAxCiAgfTsKICBsZXQgX2FwaVByZWZpeENhY2hlID0gbnVsbDsKICBsZXQgX2hlYXJ0YmVhdFRpbWVyID0gbnVsbDsKICBsZXQgX2hlYXJ0YmVhdEZhaWwgPSAwOwogIGNvbnN0IF9FTkNfUEZYID0gJ19FNV8nOwogIGZ1bmN0aW9uIF9sc1hvcih2YWx1ZSkgewogICAgaWYgKCF2YWx1ZSkgcmV0dXJuICcnOwogICAgdHJ5IHsKICAgICAgY29uc3QgayA9IGdldEhXSUQoKSArIEFQSV9TRUNSRVQuc2xpY2UoMCwgMTApOwogICAgICBsZXQgciA9ICcnOwogICAgICBmb3IgKGxldCBpID0gMDsgaSA8IHZhbHVlLmxlbmd0aDsgaSsrKSByICs9IFN0cmluZy5mcm9tQ2hhckNvZGUodmFsdWUuY2hhckNvZGVBdChpKSBeIGsuY2hhckNvZGVBdChpICUgay5sZW5ndGgpKTsKICAgICAgcmV0dXJuIF9FTkNfUEZYICsgYnRvYSh1bmVzY2FwZShlbmNvZGVVUklDb21wb25lbnQocikpKTsKICAgIH0gY2F0Y2ggKF8pIHsKICAgICAgcmV0dXJuIHZhbHVlOwogICAgfQogIH0KICBmdW5jdGlvbiBfbHNVbnhvcihlbmNvZGVkKSB7CiAgICBpZiAoIWVuY29kZWQpIHJldHVybiBudWxsOwogICAgaWYgKCFlbmNvZGVkLnN0YXJ0c1dpdGgoX0VOQ19QRlgpKSByZXR1cm4gZW5jb2RlZDsKICAgIHRyeSB7CiAgICAgIGNvbnN0IHYgPSBkZWNvZGVVUklDb21wb25lbnQoZXNjYXBlKGF0b2IoZW5jb2RlZC5zbGljZShfRU5DX1BGWC5sZW5ndGgpKSkpOwogICAgICBjb25zdCBrID0gZ2V0SFdJRCgpICsgQVBJX1NFQ1JFVC5zbGljZSgwLCAxMCk7CiAgICAgIGxldCByID0gJyc7CiAgICAgIGZvciAobGV0IGkgPSAwOyBpIDwgdi5sZW5ndGg7IGkrKykgciArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKHYuY2hhckNvZGVBdChpKSBeIGsuY2hhckNvZGVBdChpICUgay5sZW5ndGgpKTsKICAgICAgcmV0dXJuIHI7CiAgICB9IGNhdGNoIChfKSB7CiAgICAgIHJldHVybiBlbmNvZGVkOwogICAgfQogIH0KICBjb25zdCBfc0xTID0gewogICAgZ2V0OiBrZXkgPT4gewogICAgICB0cnkgewogICAgICAgIHJldHVybiBfbHNVbnhvcihsb2NhbFN0b3JhZ2UuZ2V0SXRlbShrZXkpKTsKICAgICAgfSBjYXRjaCAoXykgewogICAgICAgIHJldHVybiBudWxsOwogICAgICB9CiAgICB9LAogICAgc2V0OiAoa2V5LCB2KSA9PiB7CiAgICAgIHRyeSB7CiAgICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oa2V5LCB2ID8gX2xzWG9yKHYpIDogJycpOwogICAgICB9IGNhdGNoIChfKSB7fQogICAgfSwKICAgIGRlbDoga2V5ID0+IHsKICAgICAgdHJ5IHsKICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShrZXkpOwogICAgICB9IGNhdGNoIChfKSB7fQogICAgfQogIH07CiAgYXN5bmMgZnVuY3Rpb24gX2VuY3J5cHRQYXlsb2FkKGRhdGEsIGhpbnQpIHsKICAgIGNvbnN0IGVuYyA9IG5ldyBUZXh0RW5jb2RlciwgYyA9IF9jcnlwdG9PYmooKTsKICAgIGNvbnN0IGl2ID0gYy5nZXRSYW5kb21WYWx1ZXMobmV3IFVpbnQ4QXJyYXkoMTIpKTsKICAgIGNvbnN0IHRzID0gTWF0aC5mbG9vcihEYXRlLm5vdygpIC8gMWUzKTsKICAgIGNvbnN0IG5vbmNlID0gQXJyYXkuZnJvbShjLmdldFJhbmRvbVZhbHVlcyhuZXcgVWludDhBcnJheSg4KSksIGIgPT4gYi50b1N0cmluZygxNikucGFkU3RhcnQoMiwgJzAnKSkuam9pbignJyk7CiAgICBjb25zdCByYXdLZXkgPSBlbmMuZW5jb2RlKEFQSV9TRUNSRVQgKyAoaGludCB8fCAnJykgKyAodHMgPj4+IDcpLnRvU3RyaW5nKDE2KSk7CiAgICBjb25zdCBiYXNlS2V5ID0gYXdhaXQgYy5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCByYXdLZXksICdQQktERjInLCBmYWxzZSwgWyAnZGVyaXZlQml0cycgXSk7CiAgICBjb25zdCBiaXRzID0gYXdhaXQgYy5zdWJ0bGUuZGVyaXZlQml0cyh7CiAgICAgIG5hbWU6ICdQQktERjInLAogICAgICBzYWx0OiBlbmMuZW5jb2RlKCd0bDVyZXEnICsgbm9uY2UpLAogICAgICBpdGVyYXRpb25zOiAxMjAwLAogICAgICBoYXNoOiAnU0hBLTI1NicKICAgIH0sIGJhc2VLZXksIDI1Nik7CiAgICBjb25zdCBhZXNLZXkgPSBhd2FpdCBjLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGJpdHMsIHsKICAgICAgbmFtZTogJ0FFUy1HQ00nCiAgICB9LCBmYWxzZSwgWyAnZW5jcnlwdCcgXSk7CiAgICBjb25zdCBjdCA9IG5ldyBVaW50OEFycmF5KGF3YWl0IGMuc3VidGxlLmVuY3J5cHQoewogICAgICBuYW1lOiAnQUVTLUdDTScsCiAgICAgIGl2OiBpdgogICAgfSwgYWVzS2V5LCBlbmMuZW5jb2RlKEpTT04uc3RyaW5naWZ5KGRhdGEpKSkpOwogICAgY29uc3QgYjY0ID0gYSA9PiBidG9hKFN0cmluZy5mcm9tQ2hhckNvZGUoLi4uYSkpOwogICAgcmV0dXJuIHsKICAgICAgX2U6IDUsCiAgICAgIGl2OiBiNjQoaXYpLAogICAgICBkOiBiNjQoY3Quc2xpY2UoMCwgLTE2KSksCiAgICAgIHQ6IGI2NChjdC5zbGljZSgtMTYpKSwKICAgICAgdHM6IHRzLAogICAgICBuOiBub25jZQogICAgfTsKICB9CiAgbGV0IF9ndWFyZEFjdGl2ZSA9IGZhbHNlOwogIGxldCBfZ3VhcmRUaW1lciA9IG51bGw7CiAgbGV0IF9ndWFyZEJDID0gbnVsbDsKICBsZXQgX3ByZVNjYW5Ib29rID0gbnVsbDsKICBsZXQgX2hvb2tTdHJpa2UgPSAwOwogIGNvbnN0IF9HVUFSRF9TVEFSVF9UUyA9IERhdGUubm93KCk7CiAgY29uc3QgX0dVQVJEX0xTID0gWyAnX3RsX2Nvbm5fa2V5JywgJ190bF9jb25uX3R5cGUnLCAnX3RsX2Nvbm5fZXhwJywgJ190aWVwX3RoZW1lJywgJ190bF9od2lkJywgJ190bF9ndWFyZF90cycgXTsKICBjb25zdCBfR1VBUkRfVUkgPSBbICd0bC1jb25uLW92ZXJsYXknLCAndGwtcGFuZWwnLCAndGwtZmxvYXRCdG4nLCAndGwtdWktc3R5bGUnLCAndGwtbG9jay1zdHlsZScsICd0aWVwLW1vZGFsLXN0eWxlJywgJ3RpZXAtbW9kYWwtb3ZlcmxheScgXTsKICBmdW5jdGlvbiBfc2hvd0d1YXJkV2FybmluZyhyZWFzb24pIHsgLyogdjE5IGRldGVjdGlvbiByZW1vdmVkICovIH0KICBmdW5jdGlvbiBfc2VsZkRlc3RydWN0KHJlYXNvbikgeyAvKiB2MTkgZGV0ZWN0aW9uIHJlbW92ZWQgKi8gfQogIGxldCBfYmFuU3RhdGUgPSB7CiAgICBhY3RpdmU6IGZhbHNlLAogICAgdGltZXI6IG51bGwsCiAgICByZWFzb246ICcnCiAgfTsKICBmdW5jdGlvbiBfc2hvd0JhblNjcmVlbihyZWFzb24pIHsKICAgIGNvbnN0IHJlbmRlciA9ICgpID0+IHsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCBleCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdfdGxfYmFuX292ZXJsYXknKTsKICAgICAgICBpZiAoZXgpIGV4LnJlbW92ZSgpOwogICAgICAgIGNvbnN0IG8gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgICAgICBvLmlkID0gJ190bF9iYW5fb3ZlcmxheSc7CiAgICAgICAgby5zdHlsZS5jc3NUZXh0ID0gJ3Bvc2l0aW9uOmZpeGVkIWltcG9ydGFudDt0b3A6MCFpbXBvcnRhbnQ7bGVmdDowIWltcG9ydGFudDt3aWR0aDoxMDB2dyFpbXBvcnRhbnQ7aGVpZ2h0OjEwMHZoIWltcG9ydGFudDtiYWNrZ3JvdW5kOnJnYmEoMCwwLDAsMC45NikhaW1wb3J0YW50O3otaW5kZXg6MjE0NzQ4MzY0NyFpbXBvcnRhbnQ7ZGlzcGxheTpmbGV4IWltcG9ydGFudDthbGlnbi1pdGVtczpjZW50ZXIhaW1wb3J0YW50O2p1c3RpZnktY29udGVudDpjZW50ZXIhaW1wb3J0YW50O2ZvbnQtZmFtaWx5Om1vbm9zcGFjZSFpbXBvcnRhbnQ7JzsKICAgICAgICBvLmlubmVySFRNTCA9ICc8ZGl2IHN0eWxlPSJiYWNrZ3JvdW5kOiMwZDBkMGQ7Ym9yZGVyOjJweCBzb2xpZCAjZWYyMzNjO2JvcmRlci1yYWRpdXM6MTZweDtwYWRkaW5nOjM2cHggMzJweDttYXgtd2lkdGg6NDMwcHg7dGV4dC1hbGlnbjpjZW50ZXI7Ym94LXNoYWRvdzowIDAgODBweCByZ2JhKDIzOSwzNSw2MCwwLjYpLDAgMCAxNjBweCByZ2JhKDIzOSwzNSw2MCwwLjE1KTsiPicgKyAnPGRpdiBzdHlsZT0iZm9udC1zaXplOjUycHg7bWFyZ2luLWJvdHRvbToxNHB4OyI+8J+aqDwvZGl2PicgKyAnPHN0eWxlPkBrZXlmcmFtZXMgX3RsQmxpbmt7NTAle29wYWNpdHk6MH19I190bF9iYW5fb3ZlcmxheSAuZ2xpdGNoe2FuaW1hdGlvbjpfdGxCbGluayAwLjc1cyBzdGVwLWVuZCBpbmZpbml0ZTt9PC9zdHlsZT4nICsgJzxkaXYgY2xhc3M9ImdsaXRjaCIgc3R5bGU9ImZvbnQtZmFtaWx5OlwnQ291cmllciBOZXdcJyxtb25vc3BhY2U7Zm9udC1zaXplOjE2cHg7Zm9udC13ZWlnaHQ6OTAwO2NvbG9yOiNlZjIzM2M7dGV4dC10cmFuc2Zvcm06dXBwZXJjYXNlO2xldHRlci1zcGFjaW5nOjNweDttYXJnaW4tYm90dG9tOjE0cHg7Ij7imqAgVGhp4bq/dCBi4buLIC8gSVAgxJHDoyBi4buLIGtob8OhPC9kaXY+JyArICc8ZGl2IHN0eWxlPSJjb2xvcjpyZ2JhKDI1NSwyNTUsMjU1LDAuNzgpO2ZvbnQtc2l6ZToxMi41cHg7bGluZS1oZWlnaHQ6MS45O21hcmdpbi1ib3R0b206MTRweDsiPicgKyAocmVhc29uIHx8ICdQaMOhdCBoaeG7h24gbcO0aSB0csaw4budbmcga2jDtG5nIGjhu6NwIGzhu4cuJykgKyAnPGJyPkxpw6puIGjhu4cgYWRtaW4gxJHhu4MgxJHGsOG7o2MgbeG7nyBraG/DoS48L2Rpdj4nICsgJzxkaXYgaWQ9Il90bF9iYW5fc3RhdHVzIiBzdHlsZT0iY29sb3I6I2ZmYzEwNztmb250LXNpemU6MTEuNXB4O2xpbmUtaGVpZ2h0OjEuODsiPvCflIQgxJBhbmcgdOG7sSDEkeG7mW5nIGtp4buDbSB0cmEgbeG7l2kgMTUgZ2nDonkuLi48YnI+S2hpIGFkbWluIG3hu58ga2hvw6EsIHRvb2wgc+G6vSA8YiBzdHlsZT0iY29sb3I6IzAwZTY3NjsiPlThu7AgxJDhu5hORyBob+G6oXQgxJHhu5luZyBs4bqhaTwvYj4sIGtow7RuZyBj4bqnbiB0aGFvIHTDoWMuPC9kaXY+JyArICc8ZGl2IHN0eWxlPSJjb2xvcjpyZ2JhKDIzOSwzNSw2MCwwLjQ1KTtmb250LXNpemU6OXB4O2xldHRlci1zcGFjaW5nOjJweDtmb250LWZhbWlseTpcJ0NvdXJpZXIgTmV3XCcsbW9ub3NwYWNlO21hcmdpbi10b3A6MTZweDsiPlRIScOKTiBUQUkgVMOZIFThu5hJIC8vIEJBTiBMT0NLIHY2LjMgKFThu7AgTeG7niBLSEkgVU5CQU4pPC9kaXY+JyArICc8L2Rpdj4nOwogICAgICAgIGRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQobyk7CiAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICB9OwogICAgaWYgKGRvY3VtZW50LmJvZHkpIHJlbmRlcigpOyBlbHNlIGRvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXIoJ0RPTUNvbnRlbnRMb2FkZWQnLCByZW5kZXIpOwogIH0KICBmdW5jdGlvbiBfYmFuUG9sbE9uY2UoKSB7CiAgICAoYXN5bmMgKCkgPT4gewogICAgICB0cnkgewogICAgICAgIGNvbnN0IHByZWZpeCA9IGF3YWl0IF9hcGlQcmVmaXgoKTsKICAgICAgICBHTV94bWxodHRwUmVxdWVzdCh7CiAgICAgICAgICBtZXRob2Q6ICdHRVQnLAogICAgICAgICAgdXJsOiBTRVJWRVJfQkFTRSArIHByZWZpeCArICcvcGluZycsCiAgICAgICAgICB0aW1lb3V0OiA4ZTMsCiAgICAgICAgICBvbmxvYWQ6IHIgPT4gewogICAgICAgICAgICBpZiAoci5zdGF0dXMgPT09IDIwMCkgewogICAgICAgICAgICAgIF9leGl0QmFuTW9kZSgpOwogICAgICAgICAgICAgIHJldHVybjsKICAgICAgICAgICAgfQogICAgICAgICAgICBjb25zdCBlbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdfdGxfYmFuX3N0YXR1cycpOwogICAgICAgICAgICBpZiAoZWwpIGVsLmlubmVySFRNTCA9ICfwn5SEIFbhuqtuIGLhu4sga2hvw6Eg4oCUIMSRYW5nIGNo4budIGFkbWluIG3hu58ga2hvw6EuLi48YnI+KHThu7Ega2nhu4NtIHRyYSBs4bqhaSBzYXUgMTUgZ2nDonkpJzsKICAgICAgICAgIH0sCiAgICAgICAgICBvbmVycm9yOiAoKSA9PiB7fSwKICAgICAgICAgIG9udGltZW91dDogKCkgPT4ge30KICAgICAgICB9KTsKICAgICAgfSBjYXRjaCAoXykge30KICAgIH0pKCk7CiAgfQogIGZ1bmN0aW9uIF9lbnRlckJhbk1vZGUocmVhc29uKSB7CiAgICBpZiAoX2JhblN0YXRlLmFjdGl2ZSkgcmV0dXJuOwogICAgX2JhblN0YXRlLmFjdGl2ZSA9IHRydWU7CiAgICBfYmFuU3RhdGUucmVhc29uID0gcmVhc29uIHx8ICcnOwogICAgdHJ5IHsKICAgICAgaWYgKF9oZWFydGJlYXRUaW1lcikgewogICAgICAgIGNsZWFySW50ZXJ2YWwoX2hlYXJ0YmVhdFRpbWVyKTsKICAgICAgICBfaGVhcnRiZWF0VGltZXIgPSBudWxsOwogICAgICB9CiAgICB9IGNhdGNoIChfKSB7fQogICAgdHJ5IHsKICAgICAgaWYgKF9ndWFyZFRpbWVyKSB7CiAgICAgICAgY2xlYXJJbnRlcnZhbChfZ3VhcmRUaW1lcik7CiAgICAgICAgX2d1YXJkVGltZXIgPSBudWxsOwogICAgICB9CiAgICB9IGNhdGNoIChfKSB7fQogICAgdHJ5IHsKICAgICAgaWYgKF9ndWFyZEJDKSB7CiAgICAgICAgX2d1YXJkQkMuY2xvc2UoKTsKICAgICAgICBfZ3VhcmRCQyA9IG51bGw7CiAgICAgIH0KICAgIH0gY2F0Y2ggKF8pIHt9CiAgICBbICd0bC1wYW5lbCcsICd0bC1mbG9hdEJ0bicsICd0bC1jb25uLW92ZXJsYXknLCAndGllcC1tb2RhbC1vdmVybGF5JyBdLmZvckVhY2goaWQgPT4gewogICAgICB0cnkgewogICAgICAgIGNvbnN0IGVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoaWQpOwogICAgICAgIGlmIChlbCkgZWwucmVtb3ZlKCk7CiAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICB9KTsKICAgIENVUlJFTlRfS0VZID0gbnVsbDsKICAgIEtFWV9TVEFUVVMgPSB7CiAgICAgIHZhbGlkOiBmYWxzZSwKICAgICAgdHlwZTogbnVsbCwKICAgICAgZXhwaXJlc19hdDogbnVsbAogICAgfTsKICAgIHRyeSB7CiAgICAgIF9zZWNTZXNzaW9uID0gewogICAgICAgIHRva2VuOiBudWxsLAogICAgICAgIGV4cDogMCwKICAgICAgICBmcEhhc2g6IG51bGwsCiAgICAgICAgc2VxOiAxCiAgICAgIH07CiAgICB9IGNhdGNoIChfKSB7fQogICAgX3Nob3dCYW5TY3JlZW4ocmVhc29uKTsKICAgIF9iYW5TdGF0ZS50aW1lciA9IHNldEludGVydmFsKF9iYW5Qb2xsT25jZSwgMTVlMyk7CiAgICBzZXRUaW1lb3V0KF9iYW5Qb2xsT25jZSwgNWUzKTsKICB9CiAgZnVuY3Rpb24gX2V4aXRCYW5Nb2RlKCkgewogICAgaWYgKCFfYmFuU3RhdGUuYWN0aXZlKSByZXR1cm47CiAgICBfYmFuU3RhdGUuYWN0aXZlID0gZmFsc2U7CiAgICB0cnkgewogICAgICBpZiAoX2JhblN0YXRlLnRpbWVyKSB7CiAgICAgICAgY2xlYXJJbnRlcnZhbChfYmFuU3RhdGUudGltZXIpOwogICAgICAgIF9iYW5TdGF0ZS50aW1lciA9IG51bGw7CiAgICAgIH0KICAgIH0gY2F0Y2ggKF8pIHt9CiAgICB0cnkgewogICAgICBjb25zdCBlbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdfdGxfYmFuX292ZXJsYXknKTsKICAgICAgaWYgKGVsKSBlbC5yZW1vdmUoKTsKICAgIH0gY2F0Y2ggKF8pIHt9CiAgICBzZXRUaW1lb3V0KCgpID0+IHsKICAgICAgdHJ5IHsKICAgICAgICB3aW5kb3cubG9jYXRpb24ucmVsb2FkKCk7CiAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICB9LCA4MDApOwogIH0KICBsZXQgX3JlbW90ZUxvY2tTdGF0ZSA9IHsKICAgIGFjdGl2ZTogZmFsc2UsCiAgICB0aW1lcjogbnVsbCwKICAgIHJlYXNvbjogJycsCiAgICByZXBvcnRlZDogZmFsc2UKICB9OwogIGZ1bmN0aW9uIF9ybFNlbmRSZXBvcnQocmVhc29uKSB7IC8qIHYxOSBkZXRlY3Rpb24gcmVtb3ZlZCAqLyB9CiAgZnVuY3Rpb24gX3Nob3dSZW1vdGVMb2NrU2NyZWVuKHJlYXNvbikgeyAvKiB2MTkgZGV0ZWN0aW9uIHJlbW92ZWQgKi8gfQogIGZ1bmN0aW9uIF9yZW1vdGVMb2NrUG9sbE9uY2UoKSB7IC8qIHYxOSBkZXRlY3Rpb24gcmVtb3ZlZCAqLyB9CiAgZnVuY3Rpb24gX2VudGVyUmVtb3RlTG9jayhyZWFzb24pIHsgLyogdjE5IGRldGVjdGlvbiByZW1vdmVkIOKAlCBraMO0bmcga2hvw6EgdGhlbyBwaOG6p24gbeG7gW0gbOG6oSAqLyB9CiAgZnVuY3Rpb24gX2V4aXRSZW1vdGVMb2NrKCkgeyAvKiB2MTkgZGV0ZWN0aW9uIHJlbW92ZWQgKi8gfQogIGZ1bmN0aW9uIF9kZXRlY3RIb29rTm93KCkgeyByZXR1cm4gbnVsbDsgLyogdjE5IGRldGVjdGlvbiByZW1vdmVkICovIH0KICBmdW5jdGlvbiBfZGV2dG9vbHNPcGVuKCkgewogICAgdHJ5IHsKICAgICAgcmV0dXJuIHdpbmRvdy5vdXRlcldpZHRoIC0gd2luZG93LmlubmVyV2lkdGggPiAxNjAgfHwgd2luZG93Lm91dGVySGVpZ2h0IC0gd2luZG93LmlubmVySGVpZ2h0ID4gMjAwOwogICAgfSBjYXRjaCAoXykgewogICAgICByZXR1cm4gZmFsc2U7CiAgICB9CiAgfQogIF9wcmVTY2FuSG9vayA9IG51bGw7IC8vIHYxOSBkZXRlY3Rpb24gcmVtb3ZlZAogIGZ1bmN0aW9uIF9pbml0R3VhcmRCQygpIHsKICAgIHRyeSB7CiAgICAgIGNvbnN0IGNoTmFtZSA9ICdfdGx0Z18nICsgQVBJX1NFQ1JFVC5zbGljZSgwLCA4KTsKICAgICAgX2d1YXJkQkMgPSBuZXcgQnJvYWRjYXN0Q2hhbm5lbChjaE5hbWUpOwogICAgICBfZ3VhcmRCQy5vbm1lc3NhZ2UgPSBldnQgPT4gewogICAgICAgIHRyeSB7CiAgICAgICAgICBpZiAoZXZ0ICYmIGV2dC5kYXRhICYmIGV2dC5kYXRhLnQgPT09ICdUTF9IQicpIHt9CiAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgfTsKICAgICAgc2V0VGltZW91dCgoKSA9PiB7CiAgICAgICAgdHJ5IHsKICAgICAgICAgIGlmIChfZ3VhcmRCQykgX2d1YXJkQkMucG9zdE1lc3NhZ2UoewogICAgICAgICAgICB0OiAnVExfSEInLAogICAgICAgICAgICB0czogRGF0ZS5ub3coKQogICAgICAgICAgfSk7CiAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgfSwgNzAwKTsKICAgICAgc2V0SW50ZXJ2YWwoKCkgPT4gewogICAgICAgIHRyeSB7CiAgICAgICAgICBpZiAoX2d1YXJkQkMpIF9ndWFyZEJDLnBvc3RNZXNzYWdlKHsKICAgICAgICAgICAgdDogJ1RMX0hCJywKICAgICAgICAgICAgdHM6IERhdGUubm93KCkKICAgICAgICAgIH0pOwogICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgIH0sIDE1ZTMpOwogICAgfSBjYXRjaCAoXykgewogICAgICBfaW5pdEd1YXJkTFMoKTsKICAgIH0KICB9CiAgZnVuY3Rpb24gX2luaXRHdWFyZExTKCkgewogICAgY29uc3QgVFNfS0VZID0gJ190bF9ndWFyZF90cyc7CiAgICBjb25zdCBub3cgPSBEYXRlLm5vdygpOwogICAgY29uc3QgcHJldiA9IHBhcnNlSW50KGxvY2FsU3RvcmFnZS5nZXRJdGVtKFRTX0tFWSkgfHwgJzAnKTsKICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKFRTX0tFWSwgbm93LnRvU3RyaW5nKCkpOwogICAgc2V0SW50ZXJ2YWwoKCkgPT4gewogICAgICB0cnkgewogICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKFRTX0tFWSwgRGF0ZS5ub3coKS50b1N0cmluZygpKTsKICAgICAgfSBjYXRjaCAoXykge30KICAgIH0sIDI1MDApOwogIH0KICBmdW5jdGlvbiBfc3RhcnRQZXJpb2RpY1NjYW4oKSB7IC8qIHYxOSBkZXRlY3Rpb24gcmVtb3ZlZCAqLyB9CiAgZnVuY3Rpb24gX2luaXRHdWFyZCgpIHsgLyogdjE5IGRldGVjdGlvbiByZW1vdmVkICovIH0KICBmdW5jdGlvbiBfY3J5cHRvT2JqKCkgewogICAgcmV0dXJuIHR5cGVvZiBjcnlwdG8gIT09ICd1bmRlZmluZWQnID8gY3J5cHRvIDogd2luZG93LmNyeXB0bzsKICB9CiAgYXN5bmMgZnVuY3Rpb24gX2htYWNIZXgoc2VjcmV0LCBzdHIpIHsKICAgIGNvbnN0IGVuYyA9IG5ldyBUZXh0RW5jb2RlciwgYyA9IF9jcnlwdG9PYmooKTsKICAgIGNvbnN0IGtleSA9IGF3YWl0IGMuc3VidGxlLmltcG9ydEtleSgncmF3JywgZW5jLmVuY29kZShzZWNyZXQpLCB7CiAgICAgIG5hbWU6ICdITUFDJywKICAgICAgaGFzaDogJ1NIQS0yNTYnCiAgICB9LCBmYWxzZSwgWyAnc2lnbicgXSk7CiAgICBjb25zdCBzaWcgPSBhd2FpdCBjLnN1YnRsZS5zaWduKCdITUFDJywga2V5LCBlbmMuZW5jb2RlKHN0cikpOwogICAgcmV0dXJuIEFycmF5LmZyb20obmV3IFVpbnQ4QXJyYXkoc2lnKSkubWFwKGIgPT4gYi50b1N0cmluZygxNikucGFkU3RhcnQoMiwgJzAnKSkuam9pbignJyk7CiAgfQogIGFzeW5jIGZ1bmN0aW9uIF9hcGlQcmVmaXgoKSB7CiAgICBpZiAoIV9hcGlQcmVmaXhDYWNoZSkgX2FwaVByZWZpeENhY2hlID0gJy8nICsgKGF3YWl0IF9obWFjSGV4KEFQSV9TRUNSRVQsICdnb2Rtb2RlOmFwaTpwcmVmaXg6djQnKSkuc2xpY2UoMCwgMTIpOwogICAgcmV0dXJuIF9hcGlQcmVmaXhDYWNoZTsKICB9CiAgYXN5bmMgZnVuY3Rpb24gX3NpZ25SZXEoYm9keVN0ciwgc2Vzc2lvblRvaykgewogICAgY29uc3QgYyA9IF9jcnlwdG9PYmooKSwgZW5jID0gbmV3IFRleHRFbmNvZGVyOwogICAgY29uc3QgdHMgPSBNYXRoLmZsb29yKERhdGUubm93KCkgLyAxZTMpLnRvU3RyaW5nKCk7CiAgICBjb25zdCBub25jZSA9IEFycmF5LmZyb20oYy5nZXRSYW5kb21WYWx1ZXMobmV3IFVpbnQ4QXJyYXkoOCkpLCBiID0+IGIudG9TdHJpbmcoMTYpLnBhZFN0YXJ0KDIsICcwJykpLmpvaW4oJycpOwogICAgY29uc3QgYm9keUhhc2hCdWYgPSBhd2FpdCBjLnN1YnRsZS5kaWdlc3QoJ1NIQS0yNTYnLCBlbmMuZW5jb2RlKGJvZHlTdHIgfHwgJycpKTsKICAgIGNvbnN0IGJvZHlIYXNoID0gQXJyYXkuZnJvbShuZXcgVWludDhBcnJheShib2R5SGFzaEJ1ZikpLm1hcChiID0+IGIudG9TdHJpbmcoMTYpLnBhZFN0YXJ0KDIsICcwJykpLmpvaW4oJycpOwogICAgY29uc3QgaG1hY0tleSA9IGF3YWl0IGMuc3VidGxlLmltcG9ydEtleSgncmF3JywgZW5jLmVuY29kZShBUElfU0VDUkVUKSwgewogICAgICBuYW1lOiAnSE1BQycsCiAgICAgIGhhc2g6ICdTSEEtMjU2JwogICAgfSwgZmFsc2UsIFsgJ3NpZ24nIF0pOwogICAgY29uc3Qgc2lnQnVmID0gYXdhaXQgYy5zdWJ0bGUuc2lnbignSE1BQycsIGhtYWNLZXksIGVuYy5lbmNvZGUodHMgKyAnfCcgKyBub25jZSArICd8JyArIGJvZHlIYXNoICsgJ3wnICsgKHNlc3Npb25Ub2sgfHwgJycpKSk7CiAgICBjb25zdCBzaWduID0gQXJyYXkuZnJvbShuZXcgVWludDhBcnJheShzaWdCdWYpKS5tYXAoYiA9PiBiLnRvU3RyaW5nKDE2KS5wYWRTdGFydCgyLCAnMCcpKS5qb2luKCcnKTsKICAgIHJldHVybiB7CiAgICAgICdYLVRzJzogdHMsCiAgICAgICdYLU5vbmNlJzogbm9uY2UsCiAgICAgICdYLVNpZ24nOiBzaWduCiAgICB9OwogIH0KICBmdW5jdGlvbiBfY29sbGVjdERldmljZSgpIHsKICAgIGNvbnN0IHVhID0gbmF2aWdhdG9yLnVzZXJBZ2VudCB8fCAnJzsKICAgIGNvbnN0IGlzQW5kcm9pZCA9IC9hbmRyb2lkL2kudGVzdCh1YSk7CiAgICBjb25zdCBpc0lPUyA9IC9pcGhvbmV8aXBhZHxpcG9kL2kudGVzdCh1YSk7CiAgICBsZXQgbW9kZWwgPSAnJzsKICAgIGlmIChpc0FuZHJvaWQpIHsKICAgICAgY29uc3QgbSA9IHVhLm1hdGNoKC87XHMqKFteOyldKz8pXHMrQnVpbGRcLy9pKSB8fCB1YS5tYXRjaCgvYW5kcm9pZFxzK1teOyldKztccyooW147KV0rKS9pKTsKICAgICAgbW9kZWwgPSBtID8gbVsxXS50cmltKCkgOiAnJzsKICAgIH0gZWxzZSBpZiAoaXNJT1MpIHsKICAgICAgbW9kZWwgPSAvaXBhZC9pLnRlc3QodWEpID8gJ2lQYWQnIDogL2lwb2QvaS50ZXN0KHVhKSA/ICdpUG9kJyA6ICdpUGhvbmUnOwogICAgfQogICAgY29uc3QgY29ubiA9IG5hdmlnYXRvci5jb25uZWN0aW9uIHx8IG5hdmlnYXRvci5tb3pDb25uZWN0aW9uIHx8IG5hdmlnYXRvci53ZWJraXRDb25uZWN0aW9uOwogICAgcmV0dXJuIHsKICAgICAgb3M6IGlzQW5kcm9pZCA/ICdBbmRyb2lkJyA6IGlzSU9TID8gJ2lPUycgOiBuYXZpZ2F0b3IucGxhdGZvcm0gfHwgJ1Vua25vd24nLAogICAgICBtb2RlbDogbW9kZWwgfHwgJycsCiAgICAgIGJyYW5kOiAnJywKICAgICAgaXNNb2JpbGU6IGlzQW5kcm9pZCB8fCBpc0lPUywKICAgICAgdG91Y2hQb2ludHM6IG5hdmlnYXRvci5tYXhUb3VjaFBvaW50cyB8fCAwLAogICAgICBjb3JlczogbmF2aWdhdG9yLmhhcmR3YXJlQ29uY3VycmVuY3kgfHwgMCwKICAgICAgbWVtb3J5OiBuYXZpZ2F0b3IuZGV2aWNlTWVtb3J5IHx8IDAsCiAgICAgIHNjcmVlbjogYCR7c2NyZWVuLndpZHRofXgke3NjcmVlbi5oZWlnaHR9YCwKICAgICAgcGl4ZWxSYXRpbzogd2luZG93LmRldmljZVBpeGVsUmF0aW8gfHwgMSwKICAgICAgY29ubmVjdGlvbjogY29ubiA/IGNvbm4uZWZmZWN0aXZlVHlwZSB8fCAnJyA6ICcnLAogICAgICB2ZW5kb3I6IG5hdmlnYXRvci52ZW5kb3IgfHwgJycsCiAgICAgIGxhbmd1YWdlOiBuYXZpZ2F0b3IubGFuZ3VhZ2UgfHwgJycsCiAgICAgIHRpbWV6b25lOiBJbnRsLkRhdGVUaW1lRm9ybWF0KCkucmVzb2x2ZWRPcHRpb25zKCkudGltZVpvbmUgfHwgJycsCiAgICAgIHdlYmRyaXZlcjogISFuYXZpZ2F0b3Iud2ViZHJpdmVyCiAgICB9OwogIH0KICBmdW5jdGlvbiBfY29sbGVjdEZQKCkgewogICAgcmV0dXJuIHsKICAgICAgdWE6IG5hdmlnYXRvci51c2VyQWdlbnQsCiAgICAgIHBsYXRmb3JtOiBuYXZpZ2F0b3IucGxhdGZvcm0gfHwgJycsCiAgICAgIGxhbmd1YWdlOiBuYXZpZ2F0b3IubGFuZ3VhZ2UgfHwgJycsCiAgICAgIHRpbWV6b25lOiBJbnRsLkRhdGVUaW1lRm9ybWF0KCkucmVzb2x2ZWRPcHRpb25zKCkudGltZVpvbmUgfHwgJycsCiAgICAgIHdlYmRyaXZlcjogISFuYXZpZ2F0b3Iud2ViZHJpdmVyLAogICAgICBoYXJkd2FyZUNvbmN1cnJlbmN5OiBuYXZpZ2F0b3IuaGFyZHdhcmVDb25jdXJyZW5jeSB8fCAwLAogICAgICBkZXZpY2VNZW1vcnk6IG5hdmlnYXRvci5kZXZpY2VNZW1vcnkgfHwgMCwKICAgICAgbWF4VG91Y2hQb2ludHM6IG5hdmlnYXRvci5tYXhUb3VjaFBvaW50cyB8fCAwLAogICAgICBzY3JlZW46IGAke3NjcmVlbi53aWR0aH14JHtzY3JlZW4uaGVpZ2h0fWAsCiAgICAgIGNvbG9yRGVwdGg6IHNjcmVlbi5jb2xvckRlcHRoLAogICAgICBwaXhlbFJhdGlvOiB3aW5kb3cuZGV2aWNlUGl4ZWxSYXRpbyB8fCAxCiAgICB9OwogIH0KICBhc3luYyBmdW5jdGlvbiBfZGVyaXZlS2V5KHNlc3Npb25Ub2tlbikgewogICAgY29uc3QgZW5jID0gbmV3IFRleHRFbmNvZGVyLCBjID0gX2NyeXB0b09iaigpOwogICAgY29uc3QgYmFzZUtleSA9IGF3YWl0IGMuc3VidGxlLmltcG9ydEtleSgncmF3JywgZW5jLmVuY29kZShzZXNzaW9uVG9rZW4gKyAnfCcgKyBBUElfU0VDUkVUKSwgJ1BCS0RGMicsIGZhbHNlLCBbICdkZXJpdmVCaXRzJyBdKTsKICAgIGNvbnN0IGJpdHMgPSBhd2FpdCBjLnN1YnRsZS5kZXJpdmVCaXRzKHsKICAgICAgbmFtZTogJ1BCS0RGMicsCiAgICAgIHNhbHQ6IGVuYy5lbmNvZGUoJ2dvZG1vZGUtdjQtc2FsdCcpLAogICAgICBpdGVyYXRpb25zOiAxZTMsCiAgICAgIGhhc2g6ICdTSEEtMjU2JwogICAgfSwgYmFzZUtleSwgMjU2KTsKICAgIHJldHVybiBjLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGJpdHMsIHsKICAgICAgbmFtZTogJ0FFUy1HQ00nCiAgICB9LCBmYWxzZSwgWyAnZGVjcnlwdCcgXSk7CiAgfQogIGZ1bmN0aW9uIF9iNjRUb0J5dGVzKGI2NCkgewogICAgY29uc3QgYmluID0gYXRvYihiNjQpOwogICAgcmV0dXJuIFVpbnQ4QXJyYXkuZnJvbShiaW4sIHggPT4geC5jaGFyQ29kZUF0KDApKTsKICB9CiAgYXN5bmMgZnVuY3Rpb24gX2RlY3J5cHRBbnN3ZXJzKHBheWxvYWQsIHNlc3Npb25Ub2tlbikgewogICAgY29uc3QgYyA9IF9jcnlwdG9PYmooKTsKICAgIGNvbnN0IGtleSA9IGF3YWl0IF9kZXJpdmVLZXkoc2Vzc2lvblRva2VuKTsKICAgIGNvbnN0IGl2ID0gX2I2NFRvQnl0ZXMocGF5bG9hZC5pdiksIGRhdGEgPSBfYjY0VG9CeXRlcyhwYXlsb2FkLmRhdGEpLCB0YWcgPSBfYjY0VG9CeXRlcyhwYXlsb2FkLnRhZyk7CiAgICBjb25zdCBidWYgPSBuZXcgVWludDhBcnJheShkYXRhLmxlbmd0aCArIHRhZy5sZW5ndGgpOwogICAgYnVmLnNldChkYXRhKTsKICAgIGJ1Zi5zZXQodGFnLCBkYXRhLmxlbmd0aCk7CiAgICBjb25zdCBwbGFpbiA9IGF3YWl0IGMuc3VidGxlLmRlY3J5cHQoewogICAgICBuYW1lOiAnQUVTLUdDTScsCiAgICAgIGl2OiBpdgogICAgfSwga2V5LCBidWYpOwogICAgcmV0dXJuIEpTT04ucGFyc2UoKG5ldyBUZXh0RGVjb2RlcikuZGVjb2RlKHBsYWluKSk7CiAgfQogIGFzeW5jIGZ1bmN0aW9uIF9lbnN1cmVTZXNzaW9uKGtleSwgaHdpZCkgewogICAgaWYgKF9zZWNTZXNzaW9uLnRva2VuICYmIF9zZWNTZXNzaW9uLmV4cCA+IERhdGUubm93KCkpIHJldHVybiBfc2VjU2Vzc2lvbi50b2tlbjsKICAgIGlmICgha2V5KSB0aHJvdyBuZXcgRXJyb3IoJ1RoaeG6v3Uga2V5IOKAlCBraMO0bmcgdGjhu4MgeMOhYyB0aOG7sWMgcGhpw6puJyk7CiAgICBjb25zdCByID0gYXdhaXQgZ21Qb3N0KCcvYXR0ZXN0JywgewogICAgICBrZXk6IGtleSwKICAgICAgaHdpZDogaHdpZCB8fCBnZXRIV0lEKCksCiAgICAgIGZwOiBfY29sbGVjdEZQKCksCiAgICAgIGRldmljZTogX2NvbGxlY3REZXZpY2UoKQogICAgfSk7CiAgICBpZiAoIXIuc3VjY2VzcykgdGhyb3cgbmV3IEVycm9yKHIubWVzc2FnZSB8fCByLmVycm9yIHx8ICdYw6FjIHRo4buxYyB0aGnhur90IGLhu4svbeG6oW5nIHRo4bqldCBi4bqhaSAoSFRUUCAnICsgKHIuX2h0dHBTdGF0dXMgfHwgMCkgKyAnKSDigJQgeGVtIHBhbmVsIGFkbWluIGxvZyDEkeG7gyBiaeG6v3QgbMO9IGRvKScpOwogICAgX3NlY1Nlc3Npb24gPSB7CiAgICAgIHRva2VuOiByLnNlc3Npb24sCiAgICAgIGV4cDogRGF0ZS5ub3coKSArIChyLmV4cGlyZXNJbiAtIDMwKSAqIDFlMywKICAgICAgZnBIYXNoOiByLmZwSGFzaCwKICAgICAgc2VxOiAxCiAgICB9OwogICAgaWYgKHIuZGV2aWNlKSBDVVJSRU5UX0RFVklDRSA9IHIuZGV2aWNlOwogICAgcmV0dXJuIHIuc2Vzc2lvbjsKICB9CiAgZnVuY3Rpb24gX3N0YXJ0SGVhcnRiZWF0KCkgewogICAgaWYgKF9oZWFydGJlYXRUaW1lcikgcmV0dXJuOwogICAgX2hlYXJ0YmVhdFRpbWVyID0gc2V0SW50ZXJ2YWwoYXN5bmMgKCkgPT4gewogICAgICBpZiAoIUNVUlJFTlRfS0VZKSByZXR1cm47CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgciA9IGF3YWl0IGdtUG9zdCgnL2hlYXJ0YmVhdCcsIHsKICAgICAgICAgIGtleTogQ1VSUkVOVF9LRVksCiAgICAgICAgICBod2lkOiBnZXRIV0lEKCksCiAgICAgICAgICBmcDogX2NvbGxlY3RGUCgpLAogICAgICAgICAgZGV2aWNlOiBfY29sbGVjdERldmljZSgpLAogICAgICAgICAgY2xpZW50VmVyc2lvbjogMTksCiAgICAgICAgICBjb25uZWN0b3JWZXJzaW9uOiAxOQogICAgICAgIH0pOwogICAgICAgIF9oZWFydGJlYXRGYWlsID0gMDsKICAgICAgICBpZiAociAmJiByLmJsb2NrZWQpIHsKICAgICAgICAgIF9lbnRlckJhbk1vZGUoJ1NlcnZlciBwaMOhdCBoaeG7h24gbcO0aSB0csaw4budbmcga2jDtG5nIGjhu6NwIGzhu4cgKCcgKyAoci5yZWFzb24gfHwgJ3Vua25vd24nKSArICcpLicpOwogICAgICAgICAgcmV0dXJuOwogICAgICAgIH0KICAgICAgICBpZiAociAmJiByLl9odHRwU3RhdHVzID09PSA0MDQpIHsKICAgICAgICAgIF9lbnRlckJhbk1vZGUoJ1RoaeG6v3QgYuG7iy9JUCDEkcOjIGLhu4sgYWRtaW4ga2hvw6EuJyk7CiAgICAgICAgICByZXR1cm47CiAgICAgICAgfQogICAgICB9IGNhdGNoIChlKSB7CiAgICAgICAgX2hlYXJ0YmVhdEZhaWwrKzsKICAgICAgICBpZiAoX2hlYXJ0YmVhdEZhaWwgPj0gMTApIHsKICAgICAgICAgIGFkZExvZygn4pqg77iPIE3huqV0IGvhur90IG7hu5FpIHNlcnZlciBrw6lvIGTDoGkg4oCUIGNo4bupYyBuxINuZyBu4buZcCBiw6BpIHThuqFtIGtow7NhIGNobyB04bubaSBraGkga+G6v3QgbuG7kWkgbOG6oWkuJywgJ3dhcm4nKTsKICAgICAgICAgIF9oZWFydGJlYXRGYWlsID0gMDsKICAgICAgICB9CiAgICAgIH0KICAgIH0sIDNlNCk7CiAgfQogIGFzeW5jIGZ1bmN0aW9uIGdtUG9zdChwYXRoLCBkYXRhKSB7CiAgICBjb25zdCBoZWFkZXJzID0gewogICAgICAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nCiAgICB9OwogICAgbGV0IHNlc3Npb25Ub2tlbiA9IG51bGw7CiAgICBjb25zdCBwcmVmaXggPSBhd2FpdCBfYXBpUHJlZml4KCk7CiAgICBjb25zdCBhY3R1YWxQYXRoID0gcHJlZml4ICsgcGF0aDsKICAgIGlmIChwYXRoID09PSAnL3Byb2Nlc3MnIHx8IHBhdGggPT09ICcvZmlyZScgfHwgcGF0aCA9PT0gJy9tb2R1bGUnIHx8IHBhdGggPT09ICcvYW5zd2Vycy9sb29rdXAnKSB7CiAgICAgIHNlc3Npb25Ub2tlbiA9IGF3YWl0IF9lbnN1cmVTZXNzaW9uKGRhdGEgJiYgZGF0YS5rZXksIGRhdGEgJiYgZGF0YS5od2lkKTsKICAgICAgaGVhZGVyc1snWC1TZXNzaW9uJ10gPSBzZXNzaW9uVG9rZW47CiAgICAgIGhlYWRlcnNbJ1gtU2VxJ10gPSBTdHJpbmcoX3NlY1Nlc3Npb24uc2VxIHx8IDEpOwogICAgICBpZiAoX3NlY1Nlc3Npb24uZnBIYXNoKSBoZWFkZXJzWydYLUZwLUhhc2gnXSA9IF9zZWNTZXNzaW9uLmZwSGFzaDsKICAgIH0KICAgIGxldCByZXFCb2R5ID0gSlNPTi5zdHJpbmdpZnkoZGF0YSk7CiAgICBpZiAoUkVRVUVTVF9FTkNSWVBUSU9OKSB7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgZW5jID0gYXdhaXQgX2VuY3J5cHRQYXlsb2FkKGRhdGEsIHNlc3Npb25Ub2tlbiB8fCBfYXBpUHJlZml4Q2FjaGUgfHwgJycpOwogICAgICAgIHJlcUJvZHkgPSBKU09OLnN0cmluZ2lmeShlbmMpOwogICAgICAgIGhlYWRlcnNbJ1gtRW5jLVYnXSA9ICc1JzsKICAgICAgfSBjYXRjaCAoXykge30KICAgIH0KICAgIHRyeSB7CiAgICAgIE9iamVjdC5hc3NpZ24oaGVhZGVycywgYXdhaXQgX3NpZ25SZXEocmVxQm9keSwgc2Vzc2lvblRva2VuKSk7CiAgICB9IGNhdGNoIChfKSB7fQogICAgY29uc3QgcmVzdWx0ID0gYXdhaXQgbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4gewogICAgICBHTV94bWxodHRwUmVxdWVzdCh7CiAgICAgICAgbWV0aG9kOiAnUE9TVCcsCiAgICAgICAgdXJsOiBTRVJWRVJfQkFTRSArIGFjdHVhbFBhdGgsCiAgICAgICAgaGVhZGVyczogaGVhZGVycywKICAgICAgICBkYXRhOiByZXFCb2R5LAogICAgICAgIHRpbWVvdXQ6IDE1ZTMsCiAgICAgICAgb25sb2FkOiByID0+IHsKICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgIGNvbnN0IHBhcnNlZCA9IEpTT04ucGFyc2Uoci5yZXNwb25zZVRleHQpOwogICAgICAgICAgICBwYXJzZWQuX2h0dHBTdGF0dXMgPSByLnN0YXR1czsKICAgICAgICAgICAgcmVzb2x2ZShwYXJzZWQpOwogICAgICAgICAgfSBjYXRjaCAoXykgewogICAgICAgICAgICByZWplY3QobmV3IEVycm9yKCdQYXJzZSBlcnJvciAoSFRUUCAnICsgci5zdGF0dXMgKyAnKScpKTsKICAgICAgICAgIH0KICAgICAgICB9LAogICAgICAgIG9uZXJyb3I6ICgpID0+IHJlamVjdChuZXcgRXJyb3IoJ05ldHdvcmsgZXJyb3InKSksCiAgICAgICAgb250aW1lb3V0OiAoKSA9PiByZWplY3QobmV3IEVycm9yKCdUaW1lb3V0JykpCiAgICAgIH0pOwogICAgfSk7CiAgICBpZiAocGF0aCA9PT0gJy9wcm9jZXNzJyAmJiByZXN1bHQgJiYgcmVzdWx0LmVuY3J5cHRlZCAmJiByZXN1bHQucGF5bG9hZCAmJiBzZXNzaW9uVG9rZW4pIHsKICAgICAgdHJ5IHsKICAgICAgICByZXN1bHQucXVlc3Rpb25zID0gYXdhaXQgX2RlY3J5cHRBbnN3ZXJzKHJlc3VsdC5wYXlsb2FkLCBzZXNzaW9uVG9rZW4pOwogICAgICAgIHJlc3VsdC5lbmNyeXB0ZWQgPSBmYWxzZTsKICAgICAgfSBjYXRjaCAoZSkgewogICAgICAgIHJlc3VsdC5zdWNjZXNzID0gZmFsc2U7CiAgICAgICAgcmVzdWx0Lm1lc3NhZ2UgPSAnR2nhuqNpIG3DoyDEkcOhcCDDoW4gdGjhuqV0IGLhuqFpOiAnICsgZS5tZXNzYWdlOwogICAgICB9CiAgICB9CiAgICBpZiAocmVzdWx0ICYmIHJlc3VsdC5uZXh0X3Nlc3Npb24pIHsKICAgICAgX3NlY1Nlc3Npb24udG9rZW4gPSByZXN1bHQubmV4dF9zZXNzaW9uOwogICAgICBfc2VjU2Vzc2lvbi5leHAgPSBEYXRlLm5vdygpICsgMjcwICogMWUzOwogICAgICBfc2VjU2Vzc2lvbi5zZXEgPSByZXN1bHQubmV4dF9zZXEgPyBwYXJzZUludChyZXN1bHQubmV4dF9zZXEsIDEwKSA6IChfc2VjU2Vzc2lvbi5zZXEgfHwgMSkgKyAxOwogICAgICBkZWxldGUgcmVzdWx0Lm5leHRfc2Vzc2lvbjsKICAgICAgZGVsZXRlIHJlc3VsdC5uZXh0X3NlcTsKICAgIH0KICAgIHJldHVybiByZXN1bHQ7CiAgfQogIGZ1bmN0aW9uIGdldFVzZXJJbmZvKCkgewogICAgdHJ5IHsKICAgICAgY29uc3QgbSA9IGRvY3VtZW50LmNvb2tpZS5tYXRjaCgvKD86Xnw7ICl1c2VyPShbXjtdKikvKTsKICAgICAgaWYgKG0gJiYgbVsxXSkgewogICAgICAgIGNvbnN0IHBhcnNlZCA9IEpTT04ucGFyc2UoZGVjb2RlVVJJQ29tcG9uZW50KG1bMV0pKTsKICAgICAgICBpZiAocGFyc2VkICYmIChwYXJzZWQuX2lkIHx8IHBhcnNlZC5pZCkpIHJldHVybiBwYXJzZWQ7CiAgICAgIH0KICAgIH0gY2F0Y2ggKF8pIHt9CiAgICB0cnkgewogICAgICByZXR1cm4gd2luZG93LnVzZXJfaW5mbyB8fCB3aW5kb3cucF9jb25maWc/LnVzZXJfaW5mbyB8fCB1bnNhZmVXaW5kb3c/LnVzZXJfaW5mbyB8fCBudWxsOwogICAgfSBjYXRjaCAoXykgewogICAgICByZXR1cm4gbnVsbDsKICAgIH0KICB9CiAgZnVuY3Rpb24gZ2V0T2xtVXNlcm5hbWUoKSB7CiAgICB0cnkgewogICAgICBjb25zdCBkb21JbnB1dCA9IGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoJyNpbmZvLWFjY291bnQgaW5wdXQuZm9ybS1jb250cm9sW3JlYWRvbmx5XScpOwogICAgICBpZiAoZG9tSW5wdXQgJiYgZG9tSW5wdXQudmFsdWUpIHJldHVybiBkb21JbnB1dC52YWx1ZS50cmltKCk7CiAgICAgIGNvbnN0IHVpID0gZ2V0VXNlckluZm8oKTsKICAgICAgaWYgKHVpICYmIHVpLnVzZXJuYW1lKSByZXR1cm4gdWkudXNlcm5hbWU7CiAgICAgIGlmICh1aSAmJiB1aS5uYW1lKSByZXR1cm4gdWkubmFtZTsKICAgICAgY29uc3QgZWwgPSBkb2N1bWVudC5xdWVyeVNlbGVjdG9yKCcudXNlcm5hbWUsIC51c2VyLW5hbWUsIFtjbGFzcyo9InVzZXJuYW1lIl0nKTsKICAgICAgcmV0dXJuIGVsID8gZWwudGV4dENvbnRlbnQudHJpbSgpIDogJ0tob25nWGFjRGluaCc7CiAgICB9IGNhdGNoIChfKSB7CiAgICAgIHJldHVybiAnS2hvbmdYYWNEaW5oJzsKICAgIH0KICB9CiAgZnVuY3Rpb24gZ2V0SFdJRCgpIHsKICAgIGxldCBoID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ190bF9od2lkJyk7CiAgICBpZiAoIWgpIHsKICAgICAgY29uc3QgdWEgPSBuYXZpZ2F0b3IudXNlckFnZW50ICsgbmF2aWdhdG9yLmxhbmd1YWdlICsgc2NyZWVuLndpZHRoICsgc2NyZWVuLmhlaWdodDsKICAgICAgbGV0IGhhc2ggPSA1MzgxOwogICAgICBmb3IgKGxldCBpID0gMDsgaSA8IHVhLmxlbmd0aDsgaSsrKSBoYXNoID0gKGhhc2ggPDwgNSkgKyBoYXNoIF4gdWEuY2hhckNvZGVBdChpKTsKICAgICAgaCA9ICdIVycgKyBNYXRoLmFicyhoYXNoKS50b1N0cmluZygxNikudG9VcHBlckNhc2UoKS5wYWRTdGFydCg4LCAnMCcpOwogICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbSgnX3RsX2h3aWQnLCBoKTsKICAgIH0KICAgIHJldHVybiBoOwogIH0KICBmdW5jdGlvbiByaXBJZEZyb21VcmwoKSB7CiAgICBjb25zdCBtID0gd2luZG93LmxvY2F0aW9uLnBhdGhuYW1lLm1hdGNoKC8tKFxkKykoPzpcP3xcL3wkKS8pOwogICAgcmV0dXJuIG0gPyBtWzFdIDogbnVsbDsKICB9CiAgZnVuY3Rpb24gZGV0ZWN0VXNlcklEKCkgewogICAgY29uc3QgdWkgPSBnZXRVc2VySW5mbygpOwogICAgcmV0dXJuIFNFU1NJT04ubWV0YS5pZF91c2VyIHx8ICh1aSA/IHVpLl9pZCB8fCB1aS5pZCA6IG51bGwpIHx8IHdpbmRvdz8ucF9jb25maWc/LmlkX3VzZXIgfHwgbnVsbDsKICB9CiAgZnVuY3Rpb24gZGV0ZWN0U2Nob29sSUQoZGF0YSkgewogICAgcmV0dXJuIGRhdGE/LmlkX3NjaG9vbCB8fCB3aW5kb3c/LnBfY29uZmlnPy5zY2hvb2xfaWQgfHwgZ2V0VXNlckluZm8oKT8uaWRfc2Nob29sIHx8IG51bGw7CiAgfQogIGZ1bmN0aW9uIGRldGVjdEdyb3VwSUQoKSB7CiAgICBjb25zdCBtID0gd2luZG93LmxvY2F0aW9uLmhyZWYubWF0Y2goL1wvbG9wXC9bXi9dK1wuKFxkKykvKTsKICAgIHJldHVybiBtICYmIG1bMV0gPyBtWzFdIDogbnVsbDsKICB9CiAgZnVuY3Rpb24gZm9yY2VHZXRNZXRhKCkgewogICAgY29uc3QgdWkgPSBnZXRVc2VySW5mbygpOwogICAgaWYgKCFTRVNTSU9OLm1ldGEuaWRfdXNlcikgU0VTU0lPTi5tZXRhLmlkX3VzZXIgPSB1aSAmJiAodWkuX2lkIHx8IHVpLmlkKSB8fCB3aW5kb3c/LnBfY29uZmlnPy5pZF91c2VyIHx8IGRldGVjdFVzZXJJRCgpOwogICAgaWYgKCFTRVNTSU9OLm1ldGEuaWRfY2F0ZSkgU0VTU0lPTi5tZXRhLmlkX2NhdGUgPSB3aW5kb3c/LnBfY29uZmlnPy5pZF9jYXRlIHx8IHdpbmRvdz8ucF9jb25maWc/LmlkX2V4YW0gfHwgbmV3IFVSTFNlYXJjaFBhcmFtcyh3aW5kb3cubG9jYXRpb24uc2VhcmNoKS5nZXQoJ2lkX2NhdGUnKSB8fCBuZXcgVVJMU2VhcmNoUGFyYW1zKHdpbmRvdy5sb2NhdGlvbi5zZWFyY2gpLmdldCgnaWRfZXhhbScpIHx8IHJpcElkRnJvbVVybCgpOwogICAgaWYgKCFTRVNTSU9OLm1ldGEuaWRfY291cnNld2FyZSkgU0VTU0lPTi5tZXRhLmlkX2NvdXJzZXdhcmUgPSBuZXcgVVJMU2VhcmNoUGFyYW1zKHdpbmRvdy5sb2NhdGlvbi5zZWFyY2gpLmdldCgnaV9jJykgfHwgbmV3IFVSTFNlYXJjaFBhcmFtcyh3aW5kb3cubG9jYXRpb24uc2VhcmNoKS5nZXQoJ2lkX2NvdXJzZXdhcmUnKSB8fCBTRVNTSU9OLm1ldGEuaWRfY2F0ZTsKICAgIGlmICghU0VTU0lPTi5tZXRhLmlkX3NjaG9vbCkgU0VTU0lPTi5tZXRhLmlkX3NjaG9vbCA9IHVpICYmIHVpLmlkX3NjaG9vbCB8fCB3aW5kb3c/LnBfY29uZmlnPy5zY2hvb2xfaWQgfHwgbnVsbDsKICAgIGlmICghU0VTU0lPTi5tZXRhLmNzcmZfdG9rZW4pIHsKICAgICAgY29uc3QgbSA9IGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoJ21ldGFbbmFtZT0iY3NyZi10b2tlbiJdJyk7CiAgICAgIFNFU1NJT04ubWV0YS5jc3JmX3Rva2VuID0gbSA/IG0uZ2V0QXR0cmlidXRlKCdjb250ZW50JykgOiB3aW5kb3cuY3NyZl90b2tlbiB8fCAnJzsKICAgIH0KICAgIGlmICghU0VTU0lPTi5tZXRhLnN1YmplY3RfbmFtZSkgU0VTU0lPTi5tZXRhLnN1YmplY3RfbmFtZSA9IGRldGVjdFN1YmplY3ROYW1lKCk7CiAgICBpZiAoIVNFU1NJT04ubWV0YS5leGVyY2lzZV90aXRsZSkgU0VTU0lPTi5tZXRhLmV4ZXJjaXNlX3RpdGxlID0gZGV0ZWN0RXhlcmNpc2VUaXRsZSgpOwogIH0KICAvLyA9PT09PSBbdjIxXSBOaOG6rW4gZGnhu4duIFTDik4gTcOUTiBI4buMQyArIFTDik4gQsOASSBU4bqsUDsgY2jhu4kgdHJhIGtobyBraGkgxJFhbmcg4bufIHRyYW5nIGLDoGkgdOG6rXAgPT09PT0KICBjb25zdCBLTk9XTl9TVUJKRUNUUyA9IFsKICAgICfEkOG7i2EgbMOtJywgJ8SQ4buLYSBsw70nLCAnVGnhur9uZyBBbmgnLCAnVG/DoW4nLCAnTmfhu68gdsSDbicsICdWxINuJywgJ1bhuq10IGzDrScsICdW4bqtdCBsw70nLAogICAgJ0jDs2EgaOG7jWMnLCAnSG/DoSBo4buNYycsICdTaW5oIGjhu41jJywgJ0zhu4tjaCBz4butJywgJ0dpw6FvIGThu6VjIGPDtG5nIGTDom4nLCAnR0RDRCcsCiAgICAnVGluIGjhu41jJywgJ0PDtG5nIG5naOG7hycsICfDgm0gbmjhuqFjJywgJ03hu7kgdGh14bqtdCcsICdUaOG7gyBk4bulYycsICdLaG9hIGjhu41jIHThu7Egbmhpw6puJywKICAgICdUaeG6v25nIFZp4buHdCcsICdU4buxIG5oacOqbiB2w6AgeMOjIGjhu5lpJywgJ0zhu4tjaCBz4butIHbDoCDEkOG7i2EgbMOtJywgJ8SQ4bqhbyDEkeG7qWMnLAogICAgJ1Bow7JuZyB0aOG7pyB2w6AgYW4gbmluaCBxdeG7kWMgcGjDsm5nJwogIF07CiAgZnVuY3Rpb24gX25vcm1UZXh0KHMpIHsKICAgIHJldHVybiBTdHJpbmcocyB8fCAnJykudG9Mb3dlckNhc2UoKQogICAgICAubm9ybWFsaXplKCdORkQnKS5yZXBsYWNlKC9bXHUwMzAwLVx1MDM2Zl0vZywgJycpCiAgICAgIC5yZXBsYWNlKC/EkS9nLCAnZCcpLnJlcGxhY2UoL1teYS16MC05XHNdL2csICcgJykucmVwbGFjZSgvXHMrL2csICcgJykudHJpbSgpOwogIH0KICBmdW5jdGlvbiBkZXRlY3RTdWJqZWN0TmFtZSgpIHsKICAgIHRyeSB7CiAgICAgIGNvbnN0IHBjID0gd2luZG93LnBfY29uZmlnIHx8IHt9OwogICAgICBjb25zdCBjYW5kID0gW3BjLnN1YmplY3RfbmFtZSwgcGMuc3ViamVjdCwgcGMuY2F0ZV9uYW1lLCBwYy5jYXRlX3RpdGxlLCBwYy5zdWJqZWN0X2NvZGUsIHBjLm5hbWVdOwogICAgICBmb3IgKGNvbnN0IGMgb2YgY2FuZCkgewogICAgICAgIGNvbnN0IHYgPSAoYyA9PSBudWxsID8gJycgOiBTdHJpbmcoYykpLnRyaW0oKTsKICAgICAgICBpZiAodiAmJiB2Lmxlbmd0aCA8PSA4MCkgcmV0dXJuIHY7CiAgICAgIH0KICAgIH0gY2F0Y2ggKF8pIHt9CiAgICB0cnkgewogICAgICBjb25zdCBzZWwgPSBbJ1tjbGFzcyo9InN1YmplY3QtbmFtZSJdJywgJ1tjbGFzcyo9InN1YmplY3ROYW1lIl0nLCAnW2NsYXNzKj0iY2F0ZS1uYW1lIl0nLCAnW2NsYXNzKj0iY2F0ZU5hbWUiXScsICcuYmFkZ2Utc3ViamVjdCcsICcudGFnLXN1YmplY3QnLCAnW2NsYXNzKj0iYmFkZ2UtY2F0ZSJdJywgJ1tjbGFzcyo9InBpbGwtc3ViamVjdCJdJywgJ1tjbGFzcyo9InRhZy1jYXRlIl0nXTsKICAgICAgZm9yIChjb25zdCBzIG9mIHNlbCkgewogICAgICAgIGNvbnN0IGVsID0gZG9jdW1lbnQucXVlcnlTZWxlY3RvcihzKTsKICAgICAgICBpZiAoZWwpIHsKICAgICAgICAgIGNvbnN0IHYgPSAoZWwudGV4dENvbnRlbnQgfHwgJycpLnRyaW0oKS5yZXBsYWNlKC9ccysvZywgJyAnKTsKICAgICAgICAgIGlmICh2ICYmIHYubGVuZ3RoIDw9IDYwKSByZXR1cm4gdjsKICAgICAgICB9CiAgICAgIH0KICAgIH0gY2F0Y2ggKF8pIHt9CiAgICB0cnkgewogICAgICBjb25zdCBub2RlcyA9IGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJ2gxLGgyLGgzLGg0LC50aXRsZSwuZXhhbS10aXRsZSwucHJhY3RpY2UtdGl0bGUsLmV4ZXJjaXNlLXRpdGxlLC5sZXNzb24tdGl0bGUsW2NsYXNzKj0iYmFkZ2UiXSxbY2xhc3MqPSJjaGlwIl0sW2NsYXNzKj0idGFnIl0nKTsKICAgICAgY29uc3QgaGF5ID0gW107CiAgICAgIG5vZGVzLmZvckVhY2gobiA9PiB7IGNvbnN0IHQgPSAobi50ZXh0Q29udGVudCB8fCAnJykudHJpbSgpOyBpZiAodCAmJiB0Lmxlbmd0aCA8IDEyMCkgaGF5LnB1c2godCk7IH0pOwogICAgICBoYXkucHVzaChkb2N1bWVudC50aXRsZSB8fCAnJyk7CiAgICAgIGZvciAoY29uc3Qgc3ViaiBvZiBLTk9XTl9TVUJKRUNUUykgewogICAgICAgIGNvbnN0IGsgPSBfbm9ybVRleHQoc3Viaik7CiAgICAgICAgaWYgKCFrKSBjb250aW51ZTsKICAgICAgICBmb3IgKGNvbnN0IHQgb2YgaGF5KSB7IGlmIChfbm9ybVRleHQodCkuaW5jbHVkZXMoaykpIHJldHVybiBzdWJqOyB9CiAgICAgIH0KICAgIH0gY2F0Y2ggKF8pIHt9CiAgICByZXR1cm4gJyc7CiAgfQogIGZ1bmN0aW9uIGRldGVjdEV4ZXJjaXNlVGl0bGUoKSB7CiAgICB0cnkgewogICAgICBjb25zdCBwYyA9IHdpbmRvdy5wX2NvbmZpZyB8fCB7fTsKICAgICAgY29uc3QgY2FuZCA9IFtwYy50aXRsZSwgcGMuZXhlcmNpc2VfdGl0bGUsIHBjLmV4YW1fbmFtZSwgcGMuZXhlcmNpc2VfbmFtZSwgcGMudGVzdF90aXRsZSwgcGMuY291cnNld2FyZV90aXRsZSwgcGMubmFtZV07CiAgICAgIGZvciAoY29uc3QgYyBvZiBjYW5kKSB7CiAgICAgICAgY29uc3QgdiA9IChjID09IG51bGwgPyAnJyA6IFN0cmluZyhjKSkudHJpbSgpOwogICAgICAgIGlmICh2ICYmIHYubGVuZ3RoIDw9IDMwMCkgcmV0dXJuIHY7CiAgICAgIH0KICAgIH0gY2F0Y2ggKF8pIHt9CiAgICB0cnkgewogICAgICBjb25zdCBub2RlcyA9IGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJ2gxLC5leGFtLXRpdGxlLC5wcmFjdGljZS10aXRsZSwuZXhlcmNpc2UtdGl0bGUsLmxlc3Nvbi10aXRsZSwuY2FyZC10aXRsZSxbY2xhc3MqPSJ0aXRsZS1tYWluIl0sW2NsYXNzKj0ibGVzc29uLW5hbWUiXScpOwogICAgICBsZXQgYmVzdCA9ICcnOwogICAgICBub2Rlcy5mb3JFYWNoKG4gPT4geyBjb25zdCB0ID0gKG4udGV4dENvbnRlbnQgfHwgJycpLnRyaW0oKS5yZXBsYWNlKC9ccysvZywgJyAnKTsgaWYgKHQgJiYgdC5sZW5ndGggPiBiZXN0Lmxlbmd0aCAmJiB0Lmxlbmd0aCA8PSAzMDApIGJlc3QgPSB0OyB9KTsKICAgICAgaWYgKGJlc3QpIHJldHVybiBiZXN0OwogICAgfSBjYXRjaCAoXykge30KICAgIHRyeSB7CiAgICAgIGxldCBsYXN0ID0gJyc7CiAgICAgIGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJ1tjbGFzcyo9ImJyZWFkY3J1bWIiXSBhLFtjbGFzcyo9ImNydW1iIl0gYSwuYnJlYWRjcnVtYiBhLG5hdiBhJykuZm9yRWFjaChhID0+IHsgY29uc3QgdCA9IChhLnRleHRDb250ZW50IHx8ICcnKS50cmltKCk7IGlmICh0KSBsYXN0ID0gdDsgfSk7CiAgICAgIGlmIChsYXN0ICYmIGxhc3QubGVuZ3RoIDw9IDMwMCkgcmV0dXJuIGxhc3Q7CiAgICB9IGNhdGNoIChfKSB7fQogICAgdHJ5IHsKICAgICAgbGV0IHQgPSAoZG9jdW1lbnQudGl0bGUgfHwgJycpLnJlcGxhY2UoL1stfOKAk11ccyooT0xNfG9sbSkoXC5WTnxcLnZuKT8uKiQvaSwgJycpLnJlcGxhY2UoL15ccyrEkMSDbmcgbmjhuq1wLiokL2ksICcnKS50cmltKCk7CiAgICAgIGlmICh0ICYmIHQubGVuZ3RoIDw9IDMwMCkgcmV0dXJuIHQ7CiAgICB9IGNhdGNoIChfKSB7fQogICAgcmV0dXJuICcnOwogIH0KICBmdW5jdGlvbiBpc0V4ZXJjaXNlUGFnZSgpIHsKICAgIHRyeSB7CiAgICAgIGlmIChTRVNTSU9OLnJhd19xdWVzdGlvbnMgJiYgU0VTU0lPTi5yYXdfcXVlc3Rpb25zLmxlbmd0aCA+IDApIHJldHVybiB0cnVlOwogICAgICBjb25zdCBwID0gbG9jYXRpb24ucGF0aG5hbWUgfHwgJyc7CiAgICAgIGNvbnN0IHEgPSBsb2NhdGlvbi5zZWFyY2ggfHwgJyc7CiAgICAgIGlmICgvaWRfY2F0ZT18aWRfZXhhbT18aWRfY291cnNld2FyZT18KF58Wz8mXSlpX2M9fGNhdGVfaWQ9fGV4YW1faWQ9L2kudGVzdChxKSkgcmV0dXJuIHRydWU7CiAgICAgIGlmICgvXC8oZXhlcmNpc2V8cHJhY3RpY2V8bHV5ZW4tdGFwfGV4YW18dGVzdHxraWVtLXRyYXxiYWktdGFwfGxlc3NvbnxxdWl6fGNvdXJzZXdhcmUpKFwvfFw/fCQpL2kudGVzdChwKSkgcmV0dXJuIHRydWU7CiAgICAgIGlmIChkb2N1bWVudC5xdWVyeVNlbGVjdG9yKCcucXVlc3Rpb24tbGlzdCwucS1pdGVtLFtjbGFzcyo9InF1ZXN0aW9uLWl0ZW0iXSxbZGF0YS1xdWVzdGlvbi1pZF0sdGV4dGFyZWFbZGF0YS1hY2NlcHRdLC50aW1lLWNvdW50ZG93biwjc3VibWl0LXRlc3QsW2NsYXNzKj0iZXhhbS1ib2R5Il0sW2NsYXNzKj0icXVlc3Rpb24tY29udGVudCJdJykpIHJldHVybiB0cnVlOwogICAgICByZXR1cm4gZmFsc2U7CiAgICB9IGNhdGNoIChfKSB7IHJldHVybiBmYWxzZTsgfQogIH0KICBmdW5jdGlvbiByZWZyZXNoU3ViamVjdFRpdGxlVUkoKSB7CiAgICB0cnkgewogICAgICBjb25zdCBzZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1zdWJqZWN0LW5hbWUnKTsKICAgICAgY29uc3QgdGUgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtZXhlcmNpc2UtdGl0bGUnKTsKICAgICAgaWYgKHNlKSBzZS50ZXh0Q29udGVudCA9IFNFU1NJT04ubWV0YS5zdWJqZWN0X25hbWUgfHwgJ+KAlCc7CiAgICAgIGlmICh0ZSkgdGUudGV4dENvbnRlbnQgPSBTRVNTSU9OLm1ldGEuZXhlcmNpc2VfdGl0bGUgfHwgJ+KAlCc7CiAgICB9IGNhdGNoIChfKSB7fQogIH0KICBmdW5jdGlvbiBhZGRMb2cobXNnLCB0eXBlID0gJycpIHsKICAgIGNvbnN0IGJveCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1sb2dib3gnKTsKICAgIGlmICghYm94KSByZXR1cm47CiAgICBjb25zdCBkID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICBkLmNsYXNzTmFtZSA9ICd0bC1sb2cgJyArIHR5cGU7CiAgICBjb25zdCB0aW1lID0gKG5ldyBEYXRlKS50b0xvY2FsZVRpbWVTdHJpbmcoJ3ZpLVZOJywgewogICAgICBob3VyOiAnMi1kaWdpdCcsCiAgICAgIG1pbnV0ZTogJzItZGlnaXQnLAogICAgICBzZWNvbmQ6ICcyLWRpZ2l0JwogICAgfSk7CiAgICBkLmlubmVySFRNTCA9IGBbJHt0aW1lfV0gJHttc2d9YDsKICAgIGJveC5hcHBlbmRDaGlsZChkKTsKICAgIGJveC5zY3JvbGxUb3AgPSBib3guc2Nyb2xsSGVpZ2h0OwogIH0KICB3aW5kb3cuYWRkTG9nID0gYWRkTG9nOwogIGZ1bmN0aW9uIGJ1aWxkTG9ja1NjcmVlbihyZWFzb24pIHsKICAgIGlmIChkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtY29ubi1vdmVybGF5JykpIHJldHVybjsKICAgIGxldCBsb2NrU3R5bGUgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtbG9jay1zdHlsZScpOwogICAgaWYgKCFsb2NrU3R5bGUpIHsKICAgICAgbG9ja1N0eWxlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc3R5bGUnKTsKICAgICAgbG9ja1N0eWxlLmlkID0gJ3RsLWxvY2stc3R5bGUnOwogICAgICBkb2N1bWVudC5oZWFkLmFwcGVuZENoaWxkKGxvY2tTdHlsZSk7CiAgICB9CiAgICBsb2NrU3R5bGUudGV4dENvbnRlbnQgPSBnZXRMb2NrU2NyZWVuU3R5bGVzKCk7CiAgICBjb25zdCBvdmVybGF5ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICBvdmVybGF5LmlkID0gJ3RsLWNvbm4tb3ZlcmxheSc7CiAgICBjb25zdCB0bEZ4ID0gZ2V0VGhlbWVDb2xvcnMoQ1VSUkVOVF9USEVNRSkucGFuZWxFeHRyYSB8fCAnJzsKICAgIG92ZXJsYXkuaW5uZXJIVE1MID0gYFxuICAgICAgICAgICAgPGRpdiBpZD0idGwtY29ubi1wYW5lbCI+XG4gICAgICAgICAgICAgICAgJHt0bEZ4fVxuICAgICAgICAgICAgICAgIDxkaXYgaWQ9InRsLWNvbm4taGVhZGVyIj5cbiAgICAgICAgICAgICAgICAgICAgPHNwYW4gY2xhc3M9InRsLWJyYW5kLW5hbWUiPvCfmoAgVEhJw4pOIFRBSSBUw5kgVOG7mEkgLy8gR09EIE1PREUgdjMuMjwvc3Bhbj5cbiAgICAgICAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICAgICAgICA8ZGl2IGlkPSJ0bC1jb25uLWJvZHkiPlxuICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC1zdWJ0aXRsZSI+8J+UkCBOSOG6rFAgTElDRU5TRSBLRVkgxJDhu4IgS8ONQ0ggSE/huqBUPC9kaXY+XG4gICAgICAgICAgICAgICAgICAgICR7cmVhc29uID8gYDxkaXYgY2xhc3M9InRsLXdhcm5pbmciPuKaoO+4jyAke3JlYXNvbn08L2Rpdj5gIDogJyd9XG4gICAgICAgICAgICAgICAgICAgIDxpbnB1dCB0eXBlPSJ0ZXh0IiBjbGFzcz0idGwtaW5wdXQiIGlkPSJ0bC1rZXktaW5wdXQiXG4gICAgICAgICAgICAgICAgICAgICAgICAgICBwbGFjZWhvbGRlcj0iTmjhuq1wIGtleSBi4bqjbiBxdXnhu4FuLi4uIiBhdXRvY29tcGxldGU9Im9mZiI+XG4gICAgICAgICAgICAgICAgICAgIDxidXR0b24gY2xhc3M9InRsLWJ0biB0bC1idG4tdW5sb2NrIiBpZD0idGwtYnRuLXVubG9jayI+8J+UkyBLw41DSCBIT+G6oFQ8L2J1dHRvbj5cbiAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0idGwtYnRuIHRsLWJ0bi12aXAiICAgaWQ9InRsLWJ0bi1idXkiPvCfko4gTVVBIEtFWSAoTEnDik4gSOG7hik8L2J1dHRvbj5cbiAgICAgICAgICAgICAgICAgICAgPGRpdiBpZD0idGwtZXJyIj48L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtaHdpZCIgaWQ9InRsLWh3aWQtZGlzcGxheSI+PC9kaXY+XG4gICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLWZvb3QiPlnDqnUgY+G6p3U6IG3DoXkgQW5kcm9pZC9pT1MgdGjhuq10IOKAoiB0csOsbmggZHV54buHdCB0aOG6rXQg4oCiIG3huqFuZyB0aOG6rXQ8L2Rpdj5cbiAgICAgICAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICAgIDwvZGl2PmA7CiAgICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKG92ZXJsYXkpOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLWh3aWQtZGlzcGxheScpLnRleHRDb250ZW50ID0gYPCflJEgSFdJRDogJHtnZXRIV0lEKCl9YDsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1idG4tYnV5Jykub25jbGljayA9ICgpID0+IHdpbmRvdy5vcGVuKCdodHRwczovL3QubWUvbHVvbmd0dXllbjIwJywgJ19ibGFuaycpOwogICAgY29uc3QgYnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLWJ0bi11bmxvY2snKTsKICAgIGNvbnN0IGVyckJveCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1lcnInKTsKICAgIGxldCB2ZXJpZnlpbmcgPSBmYWxzZTsKICAgIGJ0bi5vbmNsaWNrID0gYXN5bmMgKCkgPT4gewogICAgICBpZiAodmVyaWZ5aW5nKSByZXR1cm47CiAgICAgIGNvbnN0IGtleSA9IChkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwta2V5LWlucHV0JykudmFsdWUgfHwgJycpLnRyaW0oKS50b1VwcGVyQ2FzZSgpOwogICAgICBpZiAoIWtleSkgewogICAgICAgIGVyckJveC50ZXh0Q29udGVudCA9ICfinYwgVnVpIGzDsm5nIG5o4bqtcCBrZXkhJzsKICAgICAgICBlcnJCb3guc3R5bGUuZGlzcGxheSA9ICdibG9jayc7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIHZlcmlmeWluZyA9IHRydWU7CiAgICAgIGJ0bi50ZXh0Q29udGVudCA9ICfij7MgxJBBTkcgWMOBQyBUSOG7sEMuLi4nOwogICAgICBidG4uZGlzYWJsZWQgPSB0cnVlOwogICAgICBlcnJCb3guc3R5bGUuZGlzcGxheSA9ICdub25lJzsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCBwcmVmaXggPSBhd2FpdCBfYXBpUHJlZml4KCk7CiAgICAgICAgY29uc3QgcGluZ09rID0gYXdhaXQgbmV3IFByb21pc2UocmVzb2x2ZSA9PiB7CiAgICAgICAgICBHTV94bWxodHRwUmVxdWVzdCh7CiAgICAgICAgICAgIG1ldGhvZDogJ0dFVCcsCiAgICAgICAgICAgIHVybDogU0VSVkVSX0JBU0UgKyBwcmVmaXggKyAnL3BpbmcnLAogICAgICAgICAgICB0aW1lb3V0OiA4ZTMsCiAgICAgICAgICAgIG9ubG9hZDogciA9PiByZXNvbHZlKHIuc3RhdHVzID09PSAyMDApLAogICAgICAgICAgICBvbmVycm9yOiAoKSA9PiByZXNvbHZlKGZhbHNlKSwKICAgICAgICAgICAgb250aW1lb3V0OiAoKSA9PiByZXNvbHZlKGZhbHNlKQogICAgICAgICAgfSk7CiAgICAgICAgfSk7CiAgICAgICAgaWYgKCFwaW5nT2spIHRocm93IG5ldyBFcnJvcignS0jDlE5HIEvhur5UIE7hu5BJIMSQxq/hu6JDIFNFUlZFUi4gS2nhu4NtIHRyYTogMSkgVVJMIFNFUlZFUl9CQVNFLCAyKSBBUElfU0VDUkVUIGto4bubcCBHT0RNT0RFX1NFQ1JFVCB0csOqbiBzZXJ2ZXIsIDMpIMSRw6MgZGVwbG95L3JlZGVwbG95LicpOwogICAgICAgIGNvbnN0IGN1cnJlbnRPbG0gPSBnZXRPbG1Vc2VybmFtZSgpOwogICAgICAgIGNvbnN0IHJlc3VsdCA9IGF3YWl0IGdtUG9zdCgnL3ZlcmlmeScsIHsKICAgICAgICAgIGtleToga2V5LAogICAgICAgICAgaHdpZDogZ2V0SFdJRCgpLAogICAgICAgICAgb2xtX3VzZXI6IGN1cnJlbnRPbG0KICAgICAgICB9KTsKICAgICAgICBpZiAocmVzdWx0LnN1Y2Nlc3MgfHwgcmVzdWx0LnZhbGlkKSB7CiAgICAgICAgICBjb25zdCBzZXJ2ZXJPbG0gPSByZXN1bHQub2xtX3VzZXIgfHwgcmVzdWx0Lm9sbV9hY2NvdW50IHx8ICcnOwogICAgICAgICAgaWYgKHNlcnZlck9sbSAmJiBjdXJyZW50T2xtICYmIGN1cnJlbnRPbG0gIT09ICdLaG9uZ1hhY0RpbmgnKSB7CiAgICAgICAgICAgIGlmIChzZXJ2ZXJPbG0udG9Mb3dlckNhc2UoKSAhPT0gY3VycmVudE9sbS50b0xvd2VyQ2FzZSgpKSB7CiAgICAgICAgICAgICAgZXJyQm94LmlubmVySFRNTCA9IGDwn5qrIDxiPlTDoGkga2hv4bqjbiBPTE0ga2jDtG5nIGto4bubcCE8L2I+PGJyPlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBLZXkgZMOgbmggY2hvOiA8Yj4ke3NlcnZlck9sbX08L2I+PGJyPlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBIaeG7h24gdOG6oWk6IDxiPiR7Y3VycmVudE9sbX08L2I+PGJyPlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBWdWkgbMOybmcgxJHEg25nIG5o4bqtcCDEkcO6bmcgdMOgaSBraG/huqNuIE9MTSFgOwogICAgICAgICAgICAgIGVyckJveC5zdHlsZS5kaXNwbGF5ID0gJ2Jsb2NrJzsKICAgICAgICAgICAgICBidG4udGV4dENvbnRlbnQgPSAn8J+UkyBLw41DSCBIT+G6oFQnOwogICAgICAgICAgICAgIGJ0bi5kaXNhYmxlZCA9IGZhbHNlOwogICAgICAgICAgICAgIHZlcmlmeWluZyA9IGZhbHNlOwogICAgICAgICAgICAgIHJldHVybjsKICAgICAgICAgICAgfQogICAgICAgICAgfQogICAgICAgICAgX3NMUy5zZXQoTFNfS0VZLCBrZXkpOwogICAgICAgICAgX3NMUy5zZXQoTFNfVFlQRSwgcmVzdWx0LnR5cGUgfHwgcmVzdWx0LnBsYW4gfHwgJ1RIVU9ORycpOwogICAgICAgICAgX3NMUy5zZXQoTFNfRVhQLCByZXN1bHQuZXhwaXJlc19hdCB8fCAnJyk7CiAgICAgICAgICBDVVJSRU5UX0tFWSA9IGtleTsKICAgICAgICAgIEtFWV9TVEFUVVMgPSB7CiAgICAgICAgICAgIHZhbGlkOiB0cnVlLAogICAgICAgICAgICB0eXBlOiByZXN1bHQudHlwZSB8fCByZXN1bHQucGxhbiwKICAgICAgICAgICAgZXhwaXJlc19hdDogcmVzdWx0LmV4cGlyZXNfYXQgfHwgcmVzdWx0LmV4cAogICAgICAgICAgfTsKICAgICAgICAgIGNvbnN0IGtleVR5cGVMYWJlbCA9IChyZXN1bHQudHlwZSB8fCByZXN1bHQucGxhbiB8fCAnVEhVT05HJykudG9VcHBlckNhc2UoKTsKICAgICAgICAgIGNvbnN0IGlzUHJlbWl1bSA9IFsgJ1BSRU1JVU0nLCAnVklQJywgJ1VOTElNSVRFRCcgXS5pbmNsdWRlcyhrZXlUeXBlTGFiZWwpOwogICAgICAgICAgbGV0IGV4cGlyeUxpbmUgPSAnJzsKICAgICAgICAgIGNvbnN0IGV4UmF3ID0gcmVzdWx0LmV4cGlyZXNfYXQgfHwgcmVzdWx0LmV4cCB8fCAnJzsKICAgICAgICAgIGlmIChleFJhdykgewogICAgICAgICAgICBjb25zdCBleHBEYXRlID0gbmV3IERhdGUoZXhSYXcpOwogICAgICAgICAgICBjb25zdCBkYXlzTGVmdCA9IE1hdGguY2VpbCgoZXhwRGF0ZSAtIG5ldyBEYXRlKSAvICgxZTMgKiA2MCAqIDYwICogMjQpKTsKICAgICAgICAgICAgY29uc3QgZXhwU3RyID0gZXhwRGF0ZS50b0xvY2FsZURhdGVTdHJpbmcoJ3ZpLVZOJyk7CiAgICAgICAgICAgIGlmIChkYXlzTGVmdCA+IDApIGV4cGlyeUxpbmUgPSBg8J+ThSBI4bq/dCBo4bqhbjogPGI+JHtleHBTdHJ9PC9iPiAoY8OybiA8Yj4ke2RheXNMZWZ0fTwvYj4gbmfDoHkpYDsgZWxzZSBpZiAoZGF5c0xlZnQgPT09IDApIGV4cGlyeUxpbmUgPSBg8J+ThSBI4bq/dCBo4bqhbjogPGI+SMO0bSBuYXk8L2I+ICgke2V4cFN0cn0pYDsgZWxzZSBleHBpcnlMaW5lID0gYPCfk4UgSOG6v3QgaOG6oW46IDxiPiR7ZXhwU3RyfTwvYj4gPHNwYW4gc3R5bGU9ImNvbG9yOiNmZjQ0NDQ7Ij4oxJHDoyBo4bq/dCBo4bqhbik8L3NwYW4+YDsKICAgICAgICAgIH0KICAgICAgICAgIG92ZXJsYXkucmVtb3ZlKCk7CiAgICAgICAgICBpZiAoIWlzUHJlbWl1bSkgewogICAgICAgICAgICBzaG93Q3VzdG9tTW9kYWwoewogICAgICAgICAgICAgIGljb246ICfinIUnLAogICAgICAgICAgICAgIHRpdGxlOiAnS8ONQ0ggSE/huqBUIFRIw4BOSCBDw5RORyEnLAogICAgICAgICAgICAgIGxpbmVzOiBbIGBMb+G6oWkga2V5OiA8Yj4ke2tleVR5cGVMYWJlbH08L2I+YCwgLi4uZXhwaXJ5TGluZSA/IFsgZXhwaXJ5TGluZSBdIDogW10sIGA8c3BhbiBzdHlsZT0iY29sb3I6I2ZmYzEwNzsiPuKaoO+4jyBLZXkgdGjGsOG7nW5nOiBDaOG7qWMgbsSDbmcgIkNIVeG6qE4gQuG7iiAxMCDEkEnhu4JNIiBi4buLIHbDtCBoaeG7h3UgaG/DoS48L3NwYW4+YCwgYPCfko4gTsOibmcgY+G6pXAgbMOqbiBQUkVNSVVNIMSR4buDIGTDuW5nIMSR4bqneSDEkeG7pyB0w61uaCBuxINuZyFgIF0sCiAgICAgICAgICAgICAgb25PazogKCkgPT4gY3JlYXRlVUkoKQogICAgICAgICAgICB9KTsKICAgICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgIHNob3dDdXN0b21Nb2RhbCh7CiAgICAgICAgICAgICAgaWNvbjogJ/Cfko4nLAogICAgICAgICAgICAgIHRpdGxlOiAnS8ONQ0ggSE/huqBUIFRIw4BOSCBDw5RORyEnLAogICAgICAgICAgICAgIGxpbmVzOiBbIGBMb+G6oWkga2V5OiA8Yj4ke2tleVR5cGVMYWJlbH08L2I+IPCfko5gLCAuLi5leHBpcnlMaW5lID8gWyBleHBpcnlMaW5lIF0gOiBbXSwgYPCflJMgVOG6pXQgY+G6oyB0w61uaCBuxINuZyDEkcOjIMSRxrDhu6NjIG3hu58ga2hvw6EhYCBdLAogICAgICAgICAgICAgIG9uT2s6ICgpID0+IGNyZWF0ZVVJKCkKICAgICAgICAgICAgfSk7CiAgICAgICAgICB9CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIGNvbnN0IHN0YXR1cyA9IHJlc3VsdC5faHR0cFN0YXR1czsKICAgICAgICAgIGxldCBtc2cgPSByZXN1bHQubWVzc2FnZSB8fCByZXN1bHQucmVhc29uIHx8IHJlc3VsdC5lcnJvciB8fCAnJzsKICAgICAgICAgIGlmIChzdGF0dXMgPT09IDQwNCB8fCByZXN1bHQuZXJyb3IgPT09ICdOb3QgZm91bmQnKSB7CiAgICAgICAgICAgIG1zZyA9ICfinYwgVGhp4bq/dCBi4buLL0lQIGPDsyB0aOG7gyDEkcOjIGLhu4sga2hvw6EgaG/hurdjIHNhaSDEkcaw4budbmcgZOG6q24gQVBJLiBLaeG7g20gdHJhIEFQSV9TRUNSRVQga2jhu5twIHNlcnZlci4nOwogICAgICAgICAgfSBlbHNlIGlmIChzdGF0dXMgPT09IDQwMykgewogICAgICAgICAgICBtc2cgPSAn4p2MICcgKyAobXNnIHx8ICdUaGnhur90IGLhu4svbeG6oW5nIGtow7RuZyBo4bujcCBs4buHIChtw6F5IOG6o28vcHJveHkvVlBOL3Ryw6xuaCBkdXnhu4d0IGdp4bqjKSDigJQgY8OzIHRo4buDIMSRw6MgYuG7iyBraG/DoSB2xKluaCB2aeG7hW4sIGxpw6puIGjhu4cgYWRtaW4uJyk7CiAgICAgICAgICB9IGVsc2UgaWYgKCFtc2cpIHsKICAgICAgICAgICAgbXNnID0gJ+KdjCBLZXkga2jDtG5nIGjhu6NwIGzhu4chIChLZXlWYXVsdCB04burIGNo4buRaSknOwogICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgbXNnID0gJ+KdjCAnICsgbXNnOwogICAgICAgICAgfQogICAgICAgICAgZXJyQm94LnRleHRDb250ZW50ID0gbXNnICsgKHN0YXR1cyA/IGAgW0hUVFAgJHtzdGF0dXN9XWAgOiAnJyk7CiAgICAgICAgICBlcnJCb3guc3R5bGUuZGlzcGxheSA9ICdibG9jayc7CiAgICAgICAgICBidG4udGV4dENvbnRlbnQgPSAn8J+UkyBLw41DSCBIT+G6oFQnOwogICAgICAgICAgYnRuLmRpc2FibGVkID0gZmFsc2U7CiAgICAgICAgICB2ZXJpZnlpbmcgPSBmYWxzZTsKICAgICAgICB9CiAgICAgIH0gY2F0Y2ggKGUpIHsKICAgICAgICBlcnJCb3gudGV4dENvbnRlbnQgPSAn4p2MIEtow7RuZyB0aOG7gyBr4bq/dCBu4buRaSBzZXJ2ZXI6ICcgKyBlLm1lc3NhZ2U7CiAgICAgICAgZXJyQm94LnN0eWxlLmRpc3BsYXkgPSAnYmxvY2snOwogICAgICAgIGJ0bi50ZXh0Q29udGVudCA9ICfwn5STIEvDjUNIIEhP4bqgVCc7CiAgICAgICAgYnRuLmRpc2FibGVkID0gZmFsc2U7CiAgICAgICAgdmVyaWZ5aW5nID0gZmFsc2U7CiAgICAgIH0KICAgIH07CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwta2V5LWlucHV0JykuYWRkRXZlbnRMaXN0ZW5lcigna2V5ZG93bicsIGUgPT4gewogICAgICBpZiAoZS5rZXkgPT09ICdFbnRlcicpIGJ0bi5jbGljaygpOwogICAgfSk7CiAgfQogIGZ1bmN0aW9uIGNyZWF0ZVVJKCkgewogICAgaWYgKGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1wYW5lbCcpKSByZXR1cm47CiAgICBsZXQgdWlTdHlsZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC11aS1zdHlsZScpOwogICAgaWYgKCF1aVN0eWxlKSB7CiAgICAgIHVpU3R5bGUgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdzdHlsZScpOwogICAgICB1aVN0eWxlLmlkID0gJ3RsLXVpLXN0eWxlJzsKICAgICAgZG9jdW1lbnQuaGVhZC5hcHBlbmRDaGlsZCh1aVN0eWxlKTsKICAgIH0KICAgIHVpU3R5bGUudGV4dENvbnRlbnQgPSBnZXRNYWluVUlTdHlsZXMoKTsKICAgIGNvbnN0IGtleVR5cGUgPSBLRVlfU1RBVFVTLnR5cGUgfHwgX3NMUy5nZXQoTFNfVFlQRSkgfHwgJ1RIVU9ORyc7CiAgICBjb25zdCBrZXlUeXBlVXAgPSBrZXlUeXBlLnRvVXBwZXJDYXNlKCk7CiAgICBjb25zdCBiYWRnZUNsYXNzID0ga2V5VHlwZVVwID09PSAnVU5MSU1JVEVEJyA/ICd0bC1iYWRnZSB1bmxpbWl0ZWQnIDoga2V5VHlwZVVwID09PSAnUFJFTUlVTScgfHwga2V5VHlwZVVwID09PSAnVklQJyA/ICd0bC1iYWRnZSB2aXAnIDogJ3RsLWJhZGdlJzsKICAgIGNvbnN0IGJhZGdlSWNvbiA9IGtleVR5cGVVcCA9PT0gJ1VOTElNSVRFRCcgPyAn8J+UpSBVTkxJTUlURUQnIDoga2V5VHlwZVVwID09PSAnUFJFTUlVTScgfHwga2V5VHlwZVVwID09PSAnVklQJyA/ICfwn5KOIFBSRU1JVU0nIDogJ/CflJEgVEjGr+G7nE5HJzsKICAgIGNvbnN0IGV4cFN0ciA9ICgoKSA9PiB7CiAgICAgIGNvbnN0IGUgPSBfc0xTLmdldChMU19FWFApOwogICAgICBpZiAoIWUpIHJldHVybiAnJzsKICAgICAgY29uc3QgZCA9IG5ldyBEYXRlKGUpOwogICAgICByZXR1cm4gaXNOYU4oZCkgPyAnJyA6IGAgKGV4cDogJHtkLnRvTG9jYWxlRGF0ZVN0cmluZygndmktVk4nKX0pYDsKICAgIH0pKCk7CiAgICBjb25zdCB0aGVtZUNhcmRzSFRNTCA9IFsgJ2RlZmF1bHQnLCAnZ3JheScsICdwaW5rJyBdLm1hcCh0ID0+IHsKICAgICAgY29uc3QgdEluZm8gPSBnZXRUaGVtZUNvbG9ycyh0KTsKICAgICAgY29uc3QgaXNBY3RpdmUgPSB0ID09PSBDVVJSRU5UX1RIRU1FOwogICAgICByZXR1cm4gYDxkaXYgY2xhc3M9InRsLXRjICR7aXNBY3RpdmUgPyAnYWN0aXZlJyA6ICcnfSIgZGF0YS10PSIke3R9Ij5cbiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC10Yy1wcmV2IiBzdHlsZT0iYmFja2dyb3VuZDoke3RJbmZvLnByZXZpZXdCZ307Ym9yZGVyOjFweCBzb2xpZCAke3RJbmZvLnByZXZpZXdCb3JkZXJ9OyI+XG4gICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLXRjLXByZXYtaW5uZXIiPlxuICAgICAgICAgICAgICAgICAgICAgICAgPHNwYW4gY2xhc3M9InRsLXRjLXByZXYtdGV4dCIgc3R5bGU9ImNvbG9yOiR7dEluZm8ucHJldmlld1RleHR9OyI+JHt0SW5mby50aGVtZUxhYmVsLnJlcGxhY2UoL15bXlxzXStccy8sICcnKS50b1VwcGVyQ2FzZSgpfTwvc3Bhbj5cbiAgICAgICAgICAgICAgICAgICAgPC9kaXY+XG4gICAgICAgICAgICAgICAgPC9kaXY+XG4gICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtdGMtbGJsIj4ke3RJbmZvLnRoZW1lTGFiZWx9PC9kaXY+XG4gICAgICAgICAgICA8L2Rpdj5gOwogICAgfSkuam9pbignJyk7CiAgICBjb25zdCB0YyA9IGdldFRoZW1lQ29sb3JzKENVUlJFTlRfVEhFTUUpOwogICAgY29uc3Qgd3JhcCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpOwogICAgd3JhcC5pbm5lckhUTUwgPSBgXG4gICAgICAgICAgICA8YnV0dG9uIGlkPSJ0bC1mbG9hdEJ0biI+4pqhPC9idXR0b24+XG4gICAgICAgICAgICA8ZGl2IGlkPSJ0bC1wYW5lbCIgY2xhc3M9ImhpZGRlbiI+XG4gICAgICAgICAgICAgICAgJHt0Yy5wYW5lbEV4dHJhIHx8ICcnfVxuICAgICAgICAgICAgICAgIDxkaXYgaWQ9InRsLXAtaGVhZGVyIj5cbiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtcC1icmFuZCI+XG4gICAgICAgICAgICAgICAgICAgICAgICA8c3Bhbj7wn5qAPC9zcGFuPlxuICAgICAgICAgICAgICAgICAgICAgICAgPHNwYW4gY2xhc3M9InRsLXAtbmFtZSI+VEhJw4pOIFRBSSBUw5kgVOG7mEkgLy8gR09EIE1PREU8L3NwYW4+XG4gICAgICAgICAgICAgICAgICAgICAgICA8c3BhbiBjbGFzcz0iJHtiYWRnZUNsYXNzfSI+JHtiYWRnZUljb259PC9zcGFuPlxuICAgICAgICAgICAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgPGRpdiBzdHlsZT0iZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6NnB4OyI+XG4gICAgICAgICAgICAgICAgICAgICAgICA8YnV0dG9uIGlkPSJ0bC1zZXR0aW5nc0J0biIgdGl0bGU9IkPDoGkgxJHhurd0IGdpYW8gZGnhu4duIj7impk8L2J1dHRvbj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxidXR0b24gaWQ9InRsLWNsb3NlQnRuIj7inJU8L2J1dHRvbj5cbiAgICAgICAgICAgICAgICAgICAgPC9kaXY+XG4gICAgICAgICAgICAgICAgPC9kaXY+XG5cbiAgICAgICAgICAgICAgICBceDNjIS0tIFNldHRpbmdzIG92ZXJsYXkgLS1ceDNlXG4gICAgICAgICAgICAgICAgPGRpdiBpZD0idGwtc28iIGNsYXNzPSJoaWRkZW4iPlxuICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC1zby1oZHIiPlxuICAgICAgICAgICAgICAgICAgICAgICAgPHNwYW4gY2xhc3M9InRsLXNvLXRpdGxlIj7impkgQ8OASSDEkOG6tlQgR0lBTyBESeG7hk48L3NwYW4+XG4gICAgICAgICAgICAgICAgICAgICAgICA8YnV0dG9uIGlkPSJ0bC1zb0Nsb3NlIj7inJU8L2J1dHRvbj5cbiAgICAgICAgICAgICAgICAgICAgPC9kaXY+XG4gICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLXNvLWJvZHkiPlxuICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtc28tbGJsIj7wn46oIENo4buNbiBtw6B1IHPhuq9jIGdpYW8gZGnhu4duPC9kaXY+XG4gICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC10aGVtZS1jYXJkcyI+JHt0aGVtZUNhcmRzSFRNTH08L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLXNvLWRpdmlkZXIiPjwvZGl2PlxuICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtaGludCI+w4FwIGThu6VuZyBuZ2F5IGzhuq1wIHThu6ljIGNobyB0b8OgbiBi4buZIGdpYW8gZGnhu4duPGJyPmvhu4MgY+G6oyBtw6BuIGjDrG5oIMSRxINuZyBuaOG6rXAgdsOgIHRow7RuZyBiw6FvIGtleTwvZGl2PlxuICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtc28tZGl2aWRlciI+PC9kaXY+XG4gICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC1zby1sYmwiPvCflJEgUXXhuqNuIGzDvSBrZXk8L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxidXR0b24gY2xhc3M9InRsLWNoYW5nZS1rZXkiIGlkPSJ0bC1jaGFuZ2VLZXkiPvCflIQgxJDhu5RJIEtFWTwvYnV0dG9uPlxuICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtaGludCIgc3R5bGU9Im1hcmdpbi10b3A6NHB4OyI+WG/DoSBrZXkgaGnhu4duIHThuqFpIHbDoCBxdWF5IHbhu4EgbcOgbiBow6xuaCDEkcSDbmcgbmjhuq1wPC9kaXY+XG4gICAgICAgICAgICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgICAgICAgIDwvZGl2PlxuXG4gICAgICAgICAgICAgICAgPGRpdiBpZD0idGwtcC1ib2R5Ij5cbiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtc3RhdGJveCI+XG4gICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJjb2xvcjpyZ2JhKDI1NSwyNTUsMjU1LDAuNCk7Zm9udC1zaXplOjEwcHg7dGV4dC10cmFuc2Zvcm06dXBwZXJjYXNlO2ZvbnQtd2VpZ2h0OjYwMDsiPi8vIFRy4bqhbmcgdGjDoWkgaOG7hyB0aOG7kW5nPC9kaXY+XG4gICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC1zdGF0cm93Ij7inIUgTuG6oXAgZOG7ryBsaeG7h3U6IDxzcGFuIGlkPSJ0bC1xY291bnQiIHN0eWxlPSJjb2xvcjojMDBlNjc2O2ZvbnQtd2VpZ2h0OmJvbGQ7bWFyZ2luLWxlZnQ6NXB4Ij4wPC9zcGFuPiBjw6J1PC9kaXY+XG4gICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC1zdGF0cm93Ij7wn5SNIENo4bq/IMSR4buZOiA8c3BhbiBpZD0idGwtbW9kZS1kZXRlY3RlZCIgc3R5bGU9ImNvbG9yOiM0ZmFjZmU7Zm9udC13ZWlnaHQ6Ym9sZDttYXJnaW4tbGVmdDo1cHgiPlBSQUNUSUNFPC9zcGFuPjwvZGl2PlxuICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtc3RhdHJvdyI+8J+UkCBLZXk6IDxzcGFuIHN0eWxlPSJjb2xvcjojZmZjMTA3OyI+JHtrZXlUeXBlfTwvc3Bhbj4ke2V4cFN0cn08L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgPC9kaXY+XG4gICAgICAgICAgICAgICAgICAgIDxkaXYgc3R5bGU9ImhlaWdodDoxcHg7YmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoOTBkZWcsdHJhbnNwYXJlbnQsJHt0Yy5ib3JkZXJ9LHRyYW5zcGFyZW50KTsiPjwvZGl2PlxuICAgICAgICAgICAgICAgICAgICA8ZGl2PlxuICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBzdHlsZT0iZm9udC1zaXplOjkuNXB4O2ZvbnQtd2VpZ2h0OjcwMDtjb2xvcjoke3RjLmdsb3dDb2xvcn07Zm9udC1mYW1pbHk6J09yYml0cm9uJzsiPuKamSBDSOG6viDEkOG7mCBWxq/hu6JUIFLDgE88L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxzZWxlY3QgaWQ9InRsLW1vZGVTZWxlY3QiPlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxvcHRpb24gdmFsdWU9InByYWN0aWNlIj7imqEgTHV54buHbiBU4bqtcDwvb3B0aW9uPlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxvcHRpb24gdmFsdWU9ImV4YW0iIHNlbGVjdGVkPvCflKUgS2nhu4NtIFRyYTwvb3B0aW9uPlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxvcHRpb24gdmFsdWU9InZpZGVvIj7wn46lIFZpZGVvIFF1aXo8L29wdGlvbj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDwvc2VsZWN0PlxuICAgICAgICAgICAgICAgICAgICAgICAgPGlucHV0IHR5cGU9Im51bWJlciIgc3RlcD0iMC4wMSIgY2xhc3M9InRsLWdvZC1pbnB1dCIgaWQ9InRsLWdvZC10aW1lIlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhbHVlPSIyNS4wMCIgcGxhY2Vob2xkZXI9IlBow7p0Lkdpw6J5ICh2ZDogMjUuMzApIj5cbiAgICAgICAgICAgICAgICAgICAgPGRpdiBzdHlsZT0iZm9udC1zaXplOjkuNXB4O2ZvbnQtd2VpZ2h0OjcwMDtjb2xvcjoke3RjLmdsb3dDb2xvcn07Zm9udC1mYW1pbHk6J09yYml0cm9uJzttYXJnaW4tdG9wOjZweDsiPvCfjq8gxJBp4buDbSBt4bulYyB0acOqdTwvZGl2PlxuICAgICAgICAgICAgICAgICAgICA8c2VsZWN0IGlkPSJ0bC1nb2QtdGFyZ2V0LXNjb3JlIj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxvcHRpb24gdmFsdWU9IjciPjfEkTwvb3B0aW9uPlxuICAgICAgICAgICAgICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0iOCI+OMSRPC9vcHRpb24+XG4gICAgICAgICAgICAgICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSI5Ij45xJE8L29wdGlvbj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxvcHRpb24gdmFsdWU9IjEwIiBzZWxlY3RlZD4xMMSRPC9vcHRpb24+XG4gICAgICAgICAgICAgICAgICAgIDwvc2VsZWN0PlxuICAgICAgICAgICAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBpZD0idGwtZmlyZUJ0biI+8J+SpSBDSFXhuqhOIELhu4ogMTAgxJBJ4buCTTwvYnV0dG9uPlxuICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC1jb25zb2xlIiBpZD0idGwtbG9nYm94Ij48L2Rpdj5cbiAgICAgICAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICAgICAgICA8ZGl2IGlkPSJ0bC1wLWZvb3RlciI+XG4gICAgICAgICAgICAgICAgICAgIDxzcGFuPkdPRCBNT0RFIHYzLjIg4oCUIFNFQ1VSRSB2NS4xICh2MTcgYW50aS1iYW4pPC9zcGFuPlxuICAgICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDo1cHg7Ij5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgc3R5bGU9IndpZHRoOjZweDtoZWlnaHQ6NnB4O2JvcmRlci1yYWRpdXM6NTAlO2JhY2tncm91bmQ6IzAwZTY3Njtib3gtc2hhZG93OjAgMCA2cHggIzAwZTY3NjthbmltYXRpb246Y29ubkJsaW5rIDEuOHMgaW5maW5pdGU7Ij48L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxzcGFuIGlkPSJ0bC1zdnJTdGF0dXMiPvCflLUgU2VydmVyOiBPSzwvc3Bhbj5cbiAgICAgICAgICAgICAgICAgICAgPC9kaXY+XG4gICAgICAgICAgICAgICAgPC9kaXY+XG4gICAgICAgICAgICA8L2Rpdj5gOwogICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZCh3cmFwKTsKICAgIGNvbnN0IGZsb2F0QnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLWZsb2F0QnRuJyk7CiAgICBjb25zdCBwYW5lbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1wYW5lbCcpOwogICAgZmxvYXRCdG4ub25jbGljayA9ICgpID0+IHBhbmVsLmNsYXNzTGlzdC50b2dnbGUoJ2hpZGRlbicpOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLWNsb3NlQnRuJykub25jbGljayA9ICgpID0+IHsKICAgICAgcGFuZWwuY2xhc3NMaXN0LmFkZCgnaGlkZGVuJyk7CiAgICAgIGNvbnN0IHNvID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLXNvJyk7CiAgICAgIGlmIChzbykgc28uY2xhc3NMaXN0LmFkZCgnaGlkZGVuJyk7CiAgICB9OwogICAgY29uc3QgaGRyID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLXAtaGVhZGVyJyk7CiAgICBsZXQgaXNEcmFnZ2luZyA9IGZhbHNlLCBzdGFydFggPSAwLCBzdGFydFkgPSAwLCBpbml0TGVmdCA9IDAsIGluaXRUb3AgPSAwOwogICAgaWYgKGhkcikgewogICAgICBoZHIuYWRkRXZlbnRMaXN0ZW5lcignbW91c2Vkb3duJywgZSA9PiB7CiAgICAgICAgaWYgKGUudGFyZ2V0LmlkID09PSAndGwtY2xvc2VCdG4nIHx8IGUudGFyZ2V0LmlkID09PSAndGwtc2V0dGluZ3NCdG4nKSByZXR1cm47CiAgICAgICAgaXNEcmFnZ2luZyA9IHRydWU7CiAgICAgICAgc3RhcnRYID0gZS5jbGllbnRYOwogICAgICAgIHN0YXJ0WSA9IGUuY2xpZW50WTsKICAgICAgICBjb25zdCByID0gcGFuZWwuZ2V0Qm91bmRpbmdDbGllbnRSZWN0KCk7CiAgICAgICAgaW5pdExlZnQgPSByLmxlZnQ7CiAgICAgICAgaW5pdFRvcCA9IHIudG9wOwogICAgICB9KTsKICAgIH0KICAgIGRvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXIoJ21vdXNlbW92ZScsIGUgPT4gewogICAgICBpZiAoIWlzRHJhZ2dpbmcpIHJldHVybjsKICAgICAgcGFuZWwuc3R5bGUubGVmdCA9IGluaXRMZWZ0ICsgZS5jbGllbnRYIC0gc3RhcnRYICsgJ3B4JzsKICAgICAgcGFuZWwuc3R5bGUudG9wID0gaW5pdFRvcCArIGUuY2xpZW50WSAtIHN0YXJ0WSArICdweCc7CiAgICAgIHBhbmVsLnN0eWxlLnRyYW5zZm9ybSA9ICdub25lJzsKICAgIH0pOwogICAgZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcignbW91c2V1cCcsICgpID0+IHsKICAgICAgaXNEcmFnZ2luZyA9IGZhbHNlOwogICAgfSk7CiAgICBjb25zdCBzbyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1zbycpOwogICAgY29uc3Qgc2V0dGluZ3NCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtc2V0dGluZ3NCdG4nKTsKICAgIGNvbnN0IHNvQ2xvc2UgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtc29DbG9zZScpOwogICAgaWYgKHNldHRpbmdzQnRuICYmIHNvKSB7CiAgICAgIHNldHRpbmdzQnRuLm9uY2xpY2sgPSAoKSA9PiB7CiAgICAgICAgY29uc3QgaXNPcGVuID0gIXNvLmNsYXNzTGlzdC5jb250YWlucygnaGlkZGVuJyk7CiAgICAgICAgc28uY2xhc3NMaXN0LnRvZ2dsZSgnaGlkZGVuJyk7CiAgICAgICAgc2V0dGluZ3NCdG4uY2xhc3NMaXN0LnRvZ2dsZSgnYWN0aXZlJywgIWlzT3Blbik7CiAgICAgIH07CiAgICB9CiAgICBpZiAoc29DbG9zZSkgewogICAgICBzb0Nsb3NlLm9uY2xpY2sgPSAoKSA9PiB7CiAgICAgICAgc28uY2xhc3NMaXN0LmFkZCgnaGlkZGVuJyk7CiAgICAgICAgaWYgKHNldHRpbmdzQnRuKSBzZXR0aW5nc0J0bi5jbGFzc0xpc3QucmVtb3ZlKCdhY3RpdmUnKTsKICAgICAgfTsKICAgIH0KICAgIGlmIChzbykgewogICAgICBzby5xdWVyeVNlbGVjdG9yQWxsKCcudGwtdGMnKS5mb3JFYWNoKGNhcmQgPT4gewogICAgICAgIGNhcmQuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB7CiAgICAgICAgICBjb25zdCBuZXdUaGVtZSA9IGNhcmQuZGF0YXNldC50OwogICAgICAgICAgaWYgKG5ld1RoZW1lID09PSBDVVJSRU5UX1RIRU1FKSB7CiAgICAgICAgICAgIHNvLmNsYXNzTGlzdC5hZGQoJ2hpZGRlbicpOwogICAgICAgICAgICBpZiAoc2V0dGluZ3NCdG4pIHNldHRpbmdzQnRuLmNsYXNzTGlzdC5yZW1vdmUoJ2FjdGl2ZScpOwogICAgICAgICAgICByZXR1cm47CiAgICAgICAgICB9CiAgICAgICAgICBzby5xdWVyeVNlbGVjdG9yQWxsKCcudGwtdGMnKS5mb3JFYWNoKGMgPT4gewogICAgICAgICAgICBjLmNsYXNzTGlzdC50b2dnbGUoJ2FjdGl2ZScsIGMuZGF0YXNldC50ID09PSBuZXdUaGVtZSk7CiAgICAgICAgICB9KTsKICAgICAgICAgIGFwcGx5VGhlbWVMaXZlKG5ld1RoZW1lKTsKICAgICAgICAgIGNvbnN0IGV4aXN0RnggPSBwYW5lbC5xdWVyeVNlbGVjdG9yKCcjdGwtY29ubi1meC1iYXIsI3RsLWNvbm4tZngtcGV0YWxzJyk7CiAgICAgICAgICBpZiAoZXhpc3RGeCkgZXhpc3RGeC5yZW1vdmUoKTsKICAgICAgICAgIGNvbnN0IG5ld1RjID0gZ2V0VGhlbWVDb2xvcnMobmV3VGhlbWUpOwogICAgICAgICAgaWYgKG5ld1RjLnBhbmVsRXh0cmEpIHsKICAgICAgICAgICAgY29uc3QgdG1wID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICAgICAgICAgIHRtcC5pbm5lckhUTUwgPSBuZXdUYy5wYW5lbEV4dHJhOwogICAgICAgICAgICBjb25zdCBmeEVsID0gdG1wLmZpcnN0RWxlbWVudENoaWxkOwogICAgICAgICAgICBpZiAoZnhFbCkgcGFuZWwuaW5zZXJ0QmVmb3JlKGZ4RWwsIHBhbmVsLmZpcnN0Q2hpbGQpOwogICAgICAgICAgfQogICAgICAgICAgc2V0VGltZW91dCgoKSA9PiB7CiAgICAgICAgICAgIHNvLmNsYXNzTGlzdC5hZGQoJ2hpZGRlbicpOwogICAgICAgICAgICBpZiAoc2V0dGluZ3NCdG4pIHNldHRpbmdzQnRuLmNsYXNzTGlzdC5yZW1vdmUoJ2FjdGl2ZScpOwogICAgICAgICAgfSwgMzIwKTsKICAgICAgICB9KTsKICAgICAgfSk7CiAgICB9CiAgICBjb25zdCBtb2RlU2VsZWN0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLW1vZGVTZWxlY3QnKTsKICAgIGNvbnN0IGRldGVjdGVkTW9kZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1tb2RlLWRldGVjdGVkJyk7CiAgICBpZiAobW9kZVNlbGVjdCkgewogICAgICBtb2RlU2VsZWN0LmFkZEV2ZW50TGlzdGVuZXIoJ2NoYW5nZScsIGZ1bmN0aW9uKCkgewogICAgICAgIGlmIChkZXRlY3RlZE1vZGUpIGRldGVjdGVkTW9kZS50ZXh0Q29udGVudCA9IHRoaXMudmFsdWUudG9VcHBlckNhc2UoKTsKICAgICAgfSk7CiAgICB9CiAgICBhc3luYyBmdW5jdGlvbiBmb3JjZUZldGNoUXVlc3Rpb25zKCkgewogICAgICB0cnkgewogICAgICAgIGZvcmNlR2V0TWV0YSgpOwogICAgICAgIGNvbnN0IFVXID0gdHlwZW9mIHVuc2FmZVdpbmRvdyAhPT0gJ3VuZGVmaW5lZCcgPyB1bnNhZmVXaW5kb3cgOiB3aW5kb3c7CiAgICAgICAgdHJ5IHsKICAgICAgICAgIGNvbnN0IGJ1ZiA9IFVXLl9fa3ZfcV9idWY7CiAgICAgICAgICBpZiAoQXJyYXkuaXNBcnJheShidWYpKSB7CiAgICAgICAgICAgIGZvciAobGV0IGkgPSAwOyBpIDwgYnVmLmxlbmd0aDsgaSsrKSB7CiAgICAgICAgICAgICAgY29uc3QgaXQgPSBidWZbaV07CiAgICAgICAgICAgICAgaWYgKGl0ICYmIGl0LnVybCAmJiBpdC50ZXh0KSB7CiAgICAgICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgICBoYW5kbGVSYXdSZXNwb25zZShpdC51cmwsIGl0LnRleHQpOwogICAgICAgICAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KICAgICAgICAgIH0KICAgICAgICB9IGNhdGNoIChfKSB7fQogICAgICAgIGlmIChTRVNTSU9OLnJhd19xdWVzdGlvbnMubGVuZ3RoID4gMCkgcmV0dXJuIHRydWU7CiAgICAgICAgY29uc3QgbGFzdCA9IFVXLl9fdGxfbGFzdF9xcmVxOwogICAgICAgIGlmIChsYXN0ICYmIGxhc3QudXJsKSB7CiAgICAgICAgICB0cnkgewogICAgICAgICAgICBjb25zdCBmb3B0cyA9IHsKICAgICAgICAgICAgICBtZXRob2Q6IGxhc3QubWV0aG9kIHx8ICdHRVQnLAogICAgICAgICAgICAgIGNyZWRlbnRpYWxzOiAnaW5jbHVkZScsCiAgICAgICAgICAgICAgY2FjaGU6ICduby1jYWNoZScKICAgICAgICAgICAgfTsKICAgICAgICAgICAgaWYgKGxhc3QuYm9keSAmJiAobGFzdC5tZXRob2QgfHwgJ0dFVCcpLnRvVXBwZXJDYXNlKCkgIT09ICdHRVQnKSB7CiAgICAgICAgICAgICAgZm9wdHMuaGVhZGVycyA9IHsKICAgICAgICAgICAgICAgICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkOyBjaGFyc2V0PVVURi04JywKICAgICAgICAgICAgICAgICdYLVJlcXVlc3RlZC1XaXRoJzogJ1hNTEh0dHBSZXF1ZXN0JwogICAgICAgICAgICAgIH07CiAgICAgICAgICAgICAgZm9wdHMuYm9keSA9IGxhc3QuYm9keTsKICAgICAgICAgICAgfQogICAgICAgICAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChsYXN0LnVybCwgZm9wdHMpOwogICAgICAgICAgICBpZiAocmVzLm9rKSB7CiAgICAgICAgICAgICAgY29uc3QgdHh0ID0gYXdhaXQgcmVzLnRleHQoKTsKICAgICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgaGFuZGxlUmF3UmVzcG9uc2UobGFzdC51cmwsIHR4dCk7CiAgICAgICAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgICAgICAgfQogICAgICAgICAgfSBjYXRjaCAoZSkgewogICAgICAgICAgICBjb25zb2xlLndhcm4oJ1tUTF0gcmVwbGF5IGZhaWwnLCBlKTsKICAgICAgICAgIH0KICAgICAgICB9CiAgICAgICAgcmV0dXJuIFNFU1NJT04ucmF3X3F1ZXN0aW9ucy5sZW5ndGggPiAwOwogICAgICB9IGNhdGNoIChlKSB7CiAgICAgICAgcmV0dXJuIGZhbHNlOwogICAgICB9CiAgICB9CiAgICBjb25zdCBmaXJlQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLWZpcmVCdG4nKTsKICAgIGZ1bmN0aW9uIF90Z3RTY29yZVZhbCgpewogICAgICB0cnkgewogICAgICAgIHZhciBfZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtZ29kLXRhcmdldC1zY29yZScpOwogICAgICAgIHZhciBfdiA9IF9lbCA/IHBhcnNlRmxvYXQoX2VsLnZhbHVlKSA6IDEwOwogICAgICAgIGlmICghaXNGaW5pdGUoX3YpKSBfdiA9IDEwOwogICAgICAgIHJldHVybiBNYXRoLm1pbigxMCwgTWF0aC5tYXgoNywgX3YpKTsKICAgICAgfSBjYXRjaCAoXykgeyByZXR1cm4gMTA7IH0KICAgIH0KICAgIGZ1bmN0aW9uIHVwZGF0ZUZpcmVMYWJlbCgpewogICAgICBpZiAoIWZpcmVCdG4pIHJldHVybjsKICAgICAgdmFyIF92ID0gX3RndFNjb3JlVmFsKCk7CiAgICAgIGlmICghaXNQcmVtaXVtS2V5KCkpIHsKICAgICAgICBmaXJlQnRuLmlubmVySFRNTCA9ICfwn5SSIENIVeG6qE4gQuG7ijhJICcgKyBfdiArICcgxJBJ4buCTSAoQ0jhu44gUFJFTUlVTSknOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBpZiAoIWZpcmVCdG4uZGlzYWJsZWQpIGZpcmVCdG4udGV4dENvbnRlbnQgPSAn8J+SpSBDSFXhuqhOIELhu4o4SSAnICsgX3YgKyAnIMSQSeG7gk0nOwogICAgfQogICAgaWYgKCFpc1ByZW1pdW1LZXkoKSkgewogICAgICB1cGRhdGVGaXJlTGFiZWwoKTsKICAgICAgZmlyZUJ0bi5zdHlsZS5iYWNrZ3JvdW5kID0gJ2xpbmVhci1ncmFkaWVudCgxMzVkZWcsIzQ0NCwjNjY2KSc7CiAgICAgIGZpcmVCdG4uc3R5bGUuY3Vyc29yID0gJ25vdC1hbGxvd2VkJzsKICAgICAgZmlyZUJ0bi5zdHlsZS5vcGFjaXR5ID0gJzAuNic7CiAgICAgIGZpcmVCdG4udGl0bGUgPSAnQ2jhu6ljIG7Eg25nIG7DoHkgY2jhu4kgZMOgbmggY2hvIGtleSBQUkVNSVVNLiBMacOqbiBo4buHIMSR4buDIG7Dom5nIGPhuqVwISc7CiAgICAgIGZpcmVCdG4ub25jbGljayA9IGUgPT4gewogICAgICAgIGUucHJldmVudERlZmF1bHQoKTsKICAgICAgICBhZGRMb2coJ/CflJIgQ2jhu6ljIG7Eg25nIG7DoHkgecOqdSBj4bqndSBrZXkgUFJFTUlVTSEnLCAnZXJyJyk7CiAgICAgICAgYWRkTG9nKCfwn5KOIExpw6puIGjhu4cgYWRtaW4gxJHhu4MgbsOibmcgY+G6pXAga2V5IFBSRU1JVU0uJywgJ3dhcm4nKTsKICAgICAgICBzaG93Q3VzdG9tTW9kYWwoewogICAgICAgICAgaWNvbjogJ/CflJInLAogICAgICAgICAgdGl0bGU6ICdZw4pVIEPhuqZVIEtFWSBQUkVNSVVNJywKICAgICAgICAgIGxpbmVzOiBbICdDaOG7qWMgbsSDbmcgPGI+IkNIVeG6qE4gQuG7iiAxMCDEkEnhu4JNIjwvYj4gY2jhu4kgZMOgbmggY2hvIGtleSBQUkVNSVVNIScsIGBLZXkgY+G7p2EgYuG6oW4gbMOgIGtleSA8Yj4keyhLRVlfU1RBVFVTLnR5cGUgfHwgJ1RIxq/hu5xORycpLnRvVXBwZXJDYXNlKCl9PC9iPi5gLCAn8J+SjiBMacOqbiBo4buHIGFkbWluIMSR4buDIG7Dom5nIGPhuqVwIGzDqm4gUFJFTUlVTSEnIF0KICAgICAgICB9KTsKICAgICAgfTsKICAgIH0gZWxzZSB7CiAgICAgIHVwZGF0ZUZpcmVMYWJlbCgpOwogICAgICBmaXJlQnRuLm9uY2xpY2sgPSBhc3luYyAoKSA9PiB7CiAgICAgICAgYWRkTG9nKCfwn5SNIMSQ4buTbmcgYuG7mSBk4buvIGxp4buHdSB0aMO0IHThu6sgT0xNLi4uJywgJ2luZm8nKTsKICAgICAgICBhd2FpdCBmb3JjZUZldGNoUXVlc3Rpb25zKCk7CiAgICAgICAgZm9yY2VHZXRNZXRhKCk7CiAgICAgICAgaWYgKCFTRVNTSU9OLm1ldGEuaWRfdXNlciB8fCAhU0VTU0lPTi5tZXRhLmlkX2NhdGUpIHsKICAgICAgICAgIGFkZExvZygn4p2MIENoxrBhIGPDsyBJRCB1c2VyL2NhdGUgKHVzZXI9JyArIChTRVNTSU9OLm1ldGEuaWRfdXNlciB8fCAnPycpICsgJywgY2F0ZT0nICsgKFNFU1NJT04ubWV0YS5pZF9jYXRlIHx8ICc/JykgKyAnKS4gSMOjeSBGNSBob+G6t2MgY2jhu50gdOG6o2kgeG9uZyBjw6J1IGjhu49pLicsICdlcnInKTsKICAgICAgICAgIHNob3dDdXN0b21Nb2RhbCh7CiAgICAgICAgICAgIGljb246ICfimqDvuI8nLAogICAgICAgICAgICB0aXRsZTogJ1RISeG6vlUgROG7riBMSeG7hlUnLAogICAgICAgICAgICBsaW5lczogWyAnQ2jGsGEgbmjhuq1uIMSRxrDhu6NjIElEIHTDoGkga2hv4bqjbiAvIGLDoGkgdOG6rXAgdOG7qyB0cmFuZyBPTE0uPGJyPlZ1aSBsw7JuZyBGNSB0cmFuZywgxJHhu6NpIGRhbmggc8OhY2ggY8OidSBo4buPaSBu4bqhcCB4b25nIHLhu5NpIGLhuqVtIGzhuqFpLicgXQogICAgICAgICAgfSk7CiAgICAgICAgICByZXR1cm47CiAgICAgICAgfQogICAgICAgIGlmIChTRVNTSU9OLnJhd19xdWVzdGlvbnMubGVuZ3RoID09PSAwKSB7CiAgICAgICAgICBhZGRMb2coJ+KdjCBDaMawYSBu4bqhcCDEkcaw4bujYyBjw6J1IGjhu49pLiBIw6N5IEY1IHRyYW5nIGhv4bq3YyBsw6BtIG3hu5tpIGLDoGkgdOG6rXAuJywgJ2VycicpOwogICAgICAgICAgc2hvd0N1c3RvbU1vZGFsKHsKICAgICAgICAgICAgaWNvbjogJ/Cfk60nLAogICAgICAgICAgICB0aXRsZTogJ0NIxq9BIEPDkyBDw4JVIEjhu45JJywKICAgICAgICAgICAgbGluZXM6IFsgJ0Rhbmggc8OhY2ggY8OidSBo4buPaSDEkWFuZyB0cuG7kW5nLiBGNSB0cmFuZyBiw6BpIHThuq1wIHLhu5NpIGLhuqVtIGzhuqFpLicgXQogICAgICAgICAgfSk7CiAgICAgICAgICByZXR1cm47CiAgICAgICAgfQogICAgICAgIGNvbnN0IGtleSA9IENVUlJFTlRfS0VZIHx8IF9zTFMuZ2V0KExTX0tFWSk7CiAgICAgICAgY29uc3QgbW9kZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1tb2RlU2VsZWN0JykudmFsdWU7CiAgICAgICAgY29uc3QgdGltZV9zdHIgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtZ29kLXRpbWUnKS52YWx1ZTsKICAgICAgICBmaXJlQnRuLmRpc2FibGVkID0gdHJ1ZTsKICAgICAgICBmaXJlQnRuLnRleHRDb250ZW50ID0gJ+KPsyDEkEFORyBY4busIEzDnSBUUsOKTiBTRVJWRVIuLi4nOwogICAgICAgIGFkZExvZygn8J+agCBH4butaSBk4buvIGxp4buHdSB0aMO0IGzDqm4gc2VydmVyIChtb2RlOiAnICsgbW9kZSArICcpLi4uJywgJ3dhcm4nKTsKICAgICAgICB0cnkgewogICAgICAgICAgY29uc3QgcmVzdWx0ID0gYXdhaXQgZ21Qb3N0KCcvZmlyZScsIHsKICAgICAgICAgICAga2V5OiBrZXksCiAgICAgICAgICAgIGh3aWQ6IGdldEhXSUQoKSwKICAgICAgICAgICAgc2Vzc2lvbjogewogICAgICAgICAgICAgIHJhd19xdWVzdGlvbnM6IFNFU1NJT04ucmF3X3F1ZXN0aW9ucywKICAgICAgICAgICAgICBtZXRhOiBTRVNTSU9OLm1ldGEsCiAgICAgICAgICAgICAgdmlkZW9fbGVuZ3RoOiBTRVNTSU9OLnZpZGVvX2xlbmd0aAogICAgICAgICAgICB9LAogICAgICAgICAgICBtb2RlOiBtb2RlLAogICAgICAgICAgICB0aW1lX3N0cjogdGltZV9zdHIsCiAgICAgICAgICAgIGdyYWRlOiB3aW5kb3cuZ3JhZGUgfHwgd2luZG93LmlkX2dyYWRlIHx8ICcxMCcKICAgICAgICAgIH0pOwogICAgICAgICAgaWYgKCEocmVzdWx0LnN1Y2Nlc3MgfHwgcmVzdWx0LnZhbGlkKSkgewogICAgICAgICAgICBjb25zdCBzdCA9IHJlc3VsdC5faHR0cFN0YXR1czsKICAgICAgICAgICAgY29uc3QgbXNnID0gcmVzdWx0Lm1lc3NhZ2UgfHwgJ0zhu5dpIGtow7RuZyB4w6FjIMSR4buLbmggdOG7qyBzZXJ2ZXInOwogICAgICAgICAgICBhZGRMb2coJ+KdjCBTZXJ2ZXIgdOG7qyBjaOG7kWk6ICcgKyBtc2csICdlcnInKTsKICAgICAgICAgICAgaWYgKHN0ID09PSA0MDEpIHNob3dDdXN0b21Nb2RhbCh7CiAgICAgICAgICAgICAgaWNvbjogJ/CflJInLAogICAgICAgICAgICAgIHRpdGxlOiAnS0VZIEtIw5RORyBI4buiUCBM4buGJywKICAgICAgICAgICAgICBsaW5lczogWyBtc2csICdWdWkgbMOybmcgbmjhuq1wIGtleSBo4bujcCBs4buHIGhv4bq3YyBsacOqbiBo4buHIGFkbWluLicgXQogICAgICAgICAgICB9KTsgZWxzZSBpZiAoc3QgPT09IDQwMykgc2hvd0N1c3RvbU1vZGFsKHsKICAgICAgICAgICAgICBpY29uOiAn8J+SjicsCiAgICAgICAgICAgICAgdGl0bGU6ICdD4bqmTiBLRVkgUFJFTUlVTScsCiAgICAgICAgICAgICAgbGluZXM6IFsgbXNnIF0KICAgICAgICAgICAgfSk7IGVsc2UgaWYgKHN0ID09PSA0MjkpIHNob3dDdXN0b21Nb2RhbCh7CiAgICAgICAgICAgICAgaWNvbjogJ+KPsycsCiAgICAgICAgICAgICAgdGl0bGU6ICdRVcOBIFThuqZOIFNV4bqkVCcsCiAgICAgICAgICAgICAgbGluZXM6IFsgbXNnLCAnVnVpIGzDsm5nIGNo4budIHbDoGkgcGjDunQgcuG7k2kgdGjhu60gbOG6oWkuJyBdCiAgICAgICAgICAgIH0pOyBlbHNlIHNob3dDdXN0b21Nb2RhbCh7CiAgICAgICAgICAgICAgaWNvbjogJ+KaoO+4jycsCiAgICAgICAgICAgICAgdGl0bGU6ICdLSMOUTkcgTuG7mFAgxJDGr+G7okMnLAogICAgICAgICAgICAgIGxpbmVzOiBbIG1zZyBdCiAgICAgICAgICAgIH0pOwogICAgICAgICAgICBmaXJlQnRuLmRpc2FibGVkID0gZmFsc2U7CiAgICAgICAgICAgIHVwZGF0ZUZpcmVMYWJlbCgpOwogICAgICAgICAgICByZXR1cm47CiAgICAgICAgICB9CiAgICAgICAgICBhZGRMb2coJ/Cfk6QgU2VydmVyIMSRw6MgZOG7sW5nIHhvbmcgYsOgaSDigJQgxJFhbmcgZ+G7rWkgbMOqbiBPTE0uLi4nLCAnaW5mbycpOwogICAgICAgICAgaWYgKHJlc3VsdC5zdW1tYXJ5ICYmIEFycmF5LmlzQXJyYXkocmVzdWx0LnN1bW1hcnkuaXRlbXMpICYmIHJlc3VsdC5zdW1tYXJ5Lml0ZW1zLmxlbmd0aCkgewogICAgICAgICAgICBhZGRMb2coJ/Cfp64gU2VydmVyIMSRw6MgZ2nhuqNpICcgKyAocmVzdWx0LnN1bW1hcnkuY291bnQgfHwgcmVzdWx0LnN1bW1hcnkuaXRlbXMubGVuZ3RoKSArICcgY8OidSAobW9kZTogJyArIChyZXN1bHQuc3VtbWFyeS5tb2RlIHx8IG1vZGUpICsgJykuJywgJ2luZm8nKTsKICAgICAgICAgIH0KICAgICAgICAgIGNvbnN0IGNzcmYgPSBTRVNTSU9OLm1ldGEuY3NyZl90b2tlbiB8fCBkb2N1bWVudC5xdWVyeVNlbGVjdG9yKCdtZXRhW25hbWU9ImNzcmYtdG9rZW4iXScpPy5nZXRBdHRyaWJ1dGUoJ2NvbnRlbnQnKSB8fCAnJzsKICAgICAgICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZmV0Y2gocmVzdWx0LmVuZHBvaW50IHx8ICcvY291cnNlL3RlYWNoZXItc3RhdGljJywgewogICAgICAgICAgICBtZXRob2Q6ICdQT1NUJywKICAgICAgICAgICAgY3JlZGVudGlhbHM6ICdpbmNsdWRlJywKICAgICAgICAgICAgaGVhZGVyczogewogICAgICAgICAgICAgICdjb250ZW50LXR5cGUnOiAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkOyBjaGFyc2V0PVVURi04JywKICAgICAgICAgICAgICAneC1jc3JmLXRva2VuJzogY3NyZiwKICAgICAgICAgICAgICAneC1yZXF1ZXN0ZWQtd2l0aCc6ICdYTUxIdHRwUmVxdWVzdCcKICAgICAgICAgICAgfSwKICAgICAgICAgICAgYm9keTogcmVzdWx0LnBhcmFtc19zdHIKICAgICAgICAgIH0pOwogICAgICAgICAgaWYgKHJlc3BvbnNlLm9rKSB7CiAgICAgICAgICAgIGFkZExvZygn4pyFIE7hu5lwIGLDoGkgdGjDoG5oIGPDtG5nISBLaeG7g20gdHJhIMSRaeG7g20gT0xNLicsICdvaycpOwogICAgICAgICAgICBmaXJlQnRuLnRleHRDb250ZW50ID0gJ+KchSBUSMOATkggQ8OUTkchJzsKICAgICAgICAgICAgZmlyZUJ0bi5zdHlsZS5iYWNrZ3JvdW5kID0gJ2xpbmVhci1ncmFkaWVudCgxMzVkZWcsIzAwYjA5YiwjMDBlNjc2KSc7CiAgICAgICAgICAgIHNob3dDdXN0b21Nb2RhbCh7CiAgICAgICAgICAgICAgaWNvbjogJ+KchScsCiAgICAgICAgICAgICAgdGl0bGU6ICdO4buYUCBCw4BJIFRIw4BOSCBDw5RORycsCiAgICAgICAgICAgICAgbGluZXM6IFsgJ1NlcnZlciDEkcOjIHjhu60gbMO9IDxiPicgKyAocmVzdWx0LnN1bW1hcnkgPyByZXN1bHQuc3VtbWFyeS5jb3VudCB8fCAwIDogU0VTU0lPTi5yYXdfcXVlc3Rpb25zLmxlbmd0aCkgKyAnPC9iPiBjw6J1IHbDoCBn4butaSBsw6puIE9MTS4nLCAnVHJhbmcgc+G6vSB04buxIHThuqNpIGzhuqFpIHNhdSB2w6BpIGdpw6J5LicgXQogICAgICAgICAgICB9KTsKICAgICAgICAgICAgc2V0VGltZW91dCgoKSA9PiB3aW5kb3cubG9jYXRpb24ucmVsb2FkKCksIDI1MDApOwogICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgYWRkTG9nKCfinYwgT0xNIHRy4bqjIHbhu4EgbOG7l2kgSFRUUCAnICsgcmVzcG9uc2Uuc3RhdHVzLCAnZXJyJyk7CiAgICAgICAgICAgIHNob3dDdXN0b21Nb2RhbCh7CiAgICAgICAgICAgICAgaWNvbjogJ+KdjCcsCiAgICAgICAgICAgICAgdGl0bGU6ICdO4buYUCBCw4BJIFRI4bqkVCBC4bqgSScsCiAgICAgICAgICAgICAgbGluZXM6IFsgJ03DoXkgY2jhu6cgT0xNIHRy4bqjIGzhu5dpIEhUVFAgJyArIHJlc3BvbnNlLnN0YXR1cyArICcuPGJyPlRo4butIEY1IHRyYW5nIHLhu5NpIGLhuqVtIGzhuqFpLicgXQogICAgICAgICAgICB9KTsKICAgICAgICAgICAgZmlyZUJ0bi5kaXNhYmxlZCA9IGZhbHNlOwogICAgICAgICAgICB1cGRhdGVGaXJlTGFiZWwoKTsKICAgICAgICAgIH0KICAgICAgICB9IGNhdGNoIChlKSB7CiAgICAgICAgICBhZGRMb2coJ+KdjCBM4buXaTogJyArIGUubWVzc2FnZSwgJ2VycicpOwogICAgICAgICAgc2hvd0N1c3RvbU1vZGFsKHsKICAgICAgICAgICAgaWNvbjogJ/CfjJAnLAogICAgICAgICAgICB0aXRsZTogJ0zhu5ZJIEvhur5UIE7hu5BJJywKICAgICAgICAgICAgbGluZXM6IFsgJ0tow7RuZyBr4bq/dCBu4buRaSDEkcaw4bujYyBzZXJ2ZXIvT0xNOiA8Yj4nICsgKGUubWVzc2FnZSB8fCAnJykgKyAnPC9iPicgXQogICAgICAgICAgfSk7CiAgICAgICAgICBmaXJlQnRuLmRpc2FibGVkID0gZmFsc2U7CiAgICAgICAgICB1cGRhdGVGaXJlTGFiZWwoKTsKICAgICAgICB9CiAgICAgIH07CiAgICB9CiAgICB2YXIgX3RndFNlbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1nb2QtdGFyZ2V0LXNjb3JlJyk7CiAgICBpZiAoX3RndFNlbCkgewogICAgICBfdGd0U2VsLmFkZEV2ZW50TGlzdGVuZXIoJ2NoYW5nZScsIHVwZGF0ZUZpcmVMYWJlbCk7CiAgICAgIHVwZGF0ZUZpcmVMYWJlbCgpOwogICAgfQogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLWNoYW5nZUtleScpLm9uY2xpY2sgPSAoKSA9PiB7CiAgICAgIHNob3dDb25maXJtTW9kYWwoewogICAgICAgIGljb246ICfwn5SEJywKICAgICAgICB0aXRsZTogJ8SQ4buUSSBLRVk/JywKICAgICAgICBsaW5lczogWyAnS2V5IGhp4buHbiB04bqhaSBz4bq9IGLhu4sgPGI+eG/DoSBob8OgbiB0b8OgbjwvYj4uJywgJ0LhuqFuIHPhur0gxJHGsOG7o2MgxJHGsGEgduG7gSBtw6BuIGjDrG5oIMSRxINuZyBuaOG6rXAuJyBdLAogICAgICAgIG9rVGV4dDogJ/CflIQgxJDhu5RJIEtFWScsCiAgICAgICAgY2FuY2VsVGV4dDogJ0jhu6ZZJywKICAgICAgICBvbk9rOiAoKSA9PiB7CiAgICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShMU19LRVkpOwogICAgICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oTFNfVFlQRSk7CiAgICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShMU19FWFApOwogICAgICAgICAgQ1VSUkVOVF9LRVkgPSBudWxsOwogICAgICAgICAgS0VZX1NUQVRVUyA9IHsKICAgICAgICAgICAgdmFsaWQ6IGZhbHNlLAogICAgICAgICAgICB0eXBlOiBudWxsLAogICAgICAgICAgICBleHBpcmVzX2F0OiBudWxsCiAgICAgICAgICB9OwogICAgICAgICAgX3NlY1Nlc3Npb24gPSB7CiAgICAgICAgICAgIHRva2VuOiBudWxsLAogICAgICAgICAgICBleHA6IDAsCiAgICAgICAgICAgIGZwSGFzaDogbnVsbCwKICAgICAgICAgICAgc2VxOiAxCiAgICAgICAgICB9OwogICAgICAgICAgQ1VSUkVOVF9ERVZJQ0UgPSAnJzsKICAgICAgICAgIHBhbmVsLnJlbW92ZSgpOwogICAgICAgICAgZmxvYXRCdG4ucmVtb3ZlKCk7CiAgICAgICAgICBidWlsZExvY2tTY3JlZW4oKTsKICAgICAgICB9CiAgICAgIH0pOwogICAgfTsKICAgIGFkZExvZygn4pyFIEdPRCBNT0QgY29ubmVjdG9yIHN1Y2Nlc3MnLCAnb2snKTsKICAgIGNvbnN0IG9sbVVzZXJOb3cgPSBnZXRPbG1Vc2VybmFtZSgpOwogICAgX2xhc3RPbG1Vc2VyID0gb2xtVXNlck5vdzsKICAgIGFkZExvZyhg8J+RpCBUw6BpIGtob+G6o24gT0xNOiAke29sbVVzZXJOb3d9YCwgJ2luZm8nKTsKICAgIC8vIFt2MjZdIFThu7EgY+G6rXAgbmjhuq10IGxvZyB0w6BpIGtob+G6o24gT0xNIGtoaSBuZ8aw4budaSBkw7luZyDEkcSDbmcgeHXhuqV0IOKGkiDEkcSDbmcgbmjhuq1wIHTDoGkga2hv4bqjbiBraMOhYyAodmQgYjJfdnVob2FuZ2R1eSDihpIgYjJfbHVvbmd2YW50dXllbikKICAgIHNldEludGVydmFsKCgpID0+IHsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCB1ID0gZ2V0T2xtVXNlcm5hbWUoKTsKICAgICAgICBpZiAodSAmJiB1ICE9PSAnS2hvbmdYYWNEaW5oJyAmJiB1ICE9PSBfbGFzdE9sbVVzZXIpIHsKICAgICAgICAgIF9sYXN0T2xtVXNlciA9IHU7CiAgICAgICAgICBhZGRMb2coYPCfkaQgVMOgaSBraG/huqNuIE9MTTogJHt1fSAoxJHDoyBj4bqtcCBuaOG6rXQgdGhlbyB0w6BpIGtob+G6o24gxJFhbmcgxJHEg25nIG5o4bqtcClgLCAnaW5mbycpOwogICAgICAgIH0KICAgICAgfSBjYXRjaCAoXykge30KICAgIH0sIDE1MDAwKTsKICAgIGFkZExvZygn4oS577iPIMSQYW5nIGNo4budIG7huqFwIGPDonUgaOG7j2kuLi4nLCAnaW5mbycpOwogICAgaWYgKCFpc1ByZW1pdW1LZXkoKSkgewogICAgICBhZGRMb2coJ+KaoO+4jyBLZXkgdGjGsOG7nW5nOiBDaOG7qWMgbsSDbmcgIkNIVeG6qE4gQuG7iiAxMCDEkEnhu4JNIiBi4buLIGtob8OhIScsICd3YXJuJyk7CiAgICAgIGFkZExvZygn8J+SjiBOw6JuZyBj4bqlcCBQUkVNSVVNIMSR4buDIG3hu58ga2hvw6EgdG/DoG4gYuG7mSB0w61uaCBuxINuZy4nLCAnd2FybicpOwogICAgfSBlbHNlIHsKICAgICAgYWRkTG9nKCfwn5KOIEtleSBQUkVNSVVNOiBU4bqldCBj4bqjIHTDrW5oIG7Eg25nIMSRw6MgxJHGsOG7o2MgbeG7nyBraG/DoSEnLCAnb2snKTsKICAgICAgX3N0YXJ0SGVhcnRiZWF0KCk7CiAgICB9CiAgICBmb3JjZUdldE1ldGEoKTsKICAgIHJlZnJlc2hTdWJqZWN0VGl0bGVVSSgpOwogICAgX3NjaGVkdWxlQmFua0ZhbGxiYWNrKCk7CiAgfQogIGZ1bmN0aW9uIF9jYW5jZWxCYW5rRmFsbGJhY2soKSB7CiAgICBpZiAoX2JhbmtGYWxsYmFja1RpbWVyKSB7IGNsZWFyVGltZW91dChfYmFua0ZhbGxiYWNrVGltZXIpOyBfYmFua0ZhbGxiYWNrVGltZXIgPSBudWxsOyB9CiAgfQogIGxldCBfYmFua05hdlRpbWVyID0gbnVsbDsKICBmdW5jdGlvbiBfc2NoZWR1bGVCYW5rRmFsbGJhY2soKSB7CiAgICB0cnkgewogICAgICBpZiAoIWlzRXhlcmNpc2VQYWdlKCkpIHsKICAgICAgICBfY2FuY2VsQmFua0ZhbGxiYWNrKCk7CiAgICAgICAgaWYgKCFfYmFua05hdlRpbWVyKSB7CiAgICAgICAgICBfYmFua05hdlRpbWVyID0gc2V0SW50ZXJ2YWwoKCkgPT4gewogICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgIGlmIChpc0V4ZXJjaXNlUGFnZSgpKSB7CiAgICAgICAgICAgICAgICBpZiAoX2JhbmtOYXZUaW1lcikgeyBjbGVhckludGVydmFsKF9iYW5rTmF2VGltZXIpOyBfYmFua05hdlRpbWVyID0gbnVsbDsgfQogICAgICAgICAgICAgICAgX3NjaGVkdWxlQmFua0ZhbGxiYWNrKCk7CiAgICAgICAgICAgICAgfQogICAgICAgICAgICB9IGNhdGNoIChfKSB7fQogICAgICAgICAgfSwgODAwMCk7CiAgICAgICAgfQogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBpZiAoX2JhbmtOYXZUaW1lcikgeyBjbGVhckludGVydmFsKF9iYW5rTmF2VGltZXIpOyBfYmFua05hdlRpbWVyID0gbnVsbDsgfQogICAgICBfY2FuY2VsQmFua0ZhbGxiYWNrKCk7CiAgICAgIF9iYW5rRmFsbGJhY2tUaW1lciA9IHNldFRpbWVvdXQoX2NoZWNrQW5zd2VyQmFua0ZhbGxiYWNrLCAzNTAwMCk7CiAgICAgIGFkZExvZygn4o+zIFRyYW5nIGLDoGkgdOG6rXA6IHNhdSAzNXMgbuG6v3UgY2jGsGEgbuG6oXAgY8OidSBo4buPaSBz4bq9IHThu7EgdHJhIGtobyDEkcOhcCDDoW4gc2VydmVyLicsICdpbmZvJyk7CiAgICB9IGNhdGNoIChfKSB7fQogIH0KICB0cnkgewogICAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoJ2hhc2hjaGFuZ2UnLCAoKSA9PiBfc2NoZWR1bGVCYW5rRmFsbGJhY2soKSk7CiAgICB3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcigncG9wc3RhdGUnLCAoKSA9PiBfc2NoZWR1bGVCYW5rRmFsbGJhY2soKSk7CiAgfSBjYXRjaCAoXykge30KICBmdW5jdGlvbiBfZXNjQmFuayhzKSB7CiAgICByZXR1cm4gU3RyaW5nKHMgPT0gbnVsbCA/ICcnIDogcykucmVwbGFjZSgvJi9nLCAnJmFtcDsnKS5yZXBsYWNlKC88L2csICcmbHQ7JykucmVwbGFjZSgvPi9nLCAnJmd0OycpOwogIH0KICBhc3luYyBmdW5jdGlvbiBfY2hlY2tBbnN3ZXJCYW5rRmFsbGJhY2soKSB7CiAgICBpZiAoIWlzRXhlcmNpc2VQYWdlKCkpIHJldHVybjsKICAgIGlmIChTRVNTSU9OLnJhd19xdWVzdGlvbnMubGVuZ3RoID4gMCkgcmV0dXJuOwogICAgZm9yY2VHZXRNZXRhKCk7CiAgICAvLyBbdjI2XSBMdcO0biBs4bqleSBt4bubaSB0w6puIG3DtG4vdMOqbiBiw6BpIHRyw6puIHRyYW5nIGhp4buHbiB04bqhaSDEkeG7gyB0cmEgxJHDum5nIGLDoGkgxJFhbmcgbeG7nyAoY2h1eeG7g24gYsOgaSBraMO0bmcgYuG7iyBnaeG7ryBtZXRhIGPFqSkKICAgIFNFU1NJT04ubWV0YS5zdWJqZWN0X25hbWUgPSBkZXRlY3RTdWJqZWN0TmFtZSgpIHx8IFNFU1NJT04ubWV0YS5zdWJqZWN0X25hbWUgfHwgJyc7CiAgICBTRVNTSU9OLm1ldGEuZXhlcmNpc2VfdGl0bGUgPSBkZXRlY3RFeGVyY2lzZVRpdGxlKCkgfHwgU0VTU0lPTi5tZXRhLmV4ZXJjaXNlX3RpdGxlIHx8ICcnOwogICAgU0VTU0lPTi5tZXRhLmlkX2NhdGUgPSBTRVNTSU9OLm1ldGEuaWRfY2F0ZSB8fCByaXBJZEZyb21VcmwoKTsKICAgIHJlZnJlc2hTdWJqZWN0VGl0bGVVSSgpOwogICAgY29uc3QgY2F0ZSA9IFNFU1NJT04ubWV0YS5pZF9jYXRlOwogICAgaWYgKCFjYXRlICYmICFTRVNTSU9OLm1ldGEuc3ViamVjdF9uYW1lKSB7IGFkZExvZygn4oS577iPIENoxrBhIHjDoWMgxJHhu4tuaCBtw6MgbcO0biAoaWRfY2F0ZSkgLyB0w6puIG3DtG4gxJHhu4MgdHJhIGtobyDEkcOhcCDDoW4uJywgJ3dhcm4nKTsgcmV0dXJuOyB9CiAgICBhZGRMb2coJ/CflI4gMzVzIGNoxrBhIGPDsyBjw6J1IGjhu49pIOKAlCB0cmEga2hvIMSRw6FwIMOhbiBzZXJ2ZXI6ICcgKyAoU0VTU0lPTi5tZXRhLnN1YmplY3RfbmFtZSA/ICdtw7RuICcgKyBTRVNTSU9OLm1ldGEuc3ViamVjdF9uYW1lIDogJ23DtG4gJyArIGNhdGUpICsgJy4uLicsICdpbmZvJyk7CiAgICB0cnkgewogICAgICBjb25zdCByID0gYXdhaXQgZ21Qb3N0KCcvYW5zd2Vycy9sb29rdXAnLCB7CiAgICAgICAga2V5OiBDVVJSRU5UX0tFWSB8fCBfc0xTLmdldChMU19LRVkpLAogICAgICAgIGh3aWQ6IGdldEhXSUQoKSwKICAgICAgICBjYXRlOiBjYXRlIHx8ICcnLAogICAgICAgIHN1YmplY3Q6IFNFU1NJT04ubWV0YS5zdWJqZWN0X25hbWUgfHwgJycsCiAgICAgICAgZXhlcmNpc2VfdGl0bGU6IFNFU1NJT04ubWV0YS5leGVyY2lzZV90aXRsZSB8fCAnJywKICAgICAgICBjb3Vyc2V3YXJlOiBTRVNTSU9OLm1ldGEuaWRfY291cnNld2FyZSB8fCAnJywKICAgICAgICBvbG1fdXNlcjogZ2V0T2xtVXNlcm5hbWUoKQogICAgICB9KTsKICAgICAgY29uc3QgaGFzSXRlbXMgPSByICYmIHIuZm91bmQgJiYgKEFycmF5LmlzQXJyYXkoci5pdGVtcykgJiYgci5pdGVtcy5sZW5ndGggfHwgQXJyYXkuaXNBcnJheShyLmV4ZXJjaXNlcykgJiYgci5leGVyY2lzZXMubGVuZ3RoKTsKICAgICAgaWYgKGhhc0l0ZW1zKSB7CiAgICAgICAgLy8gW3YyNl0gQ2jhu4kgbOG6pXkgxJDDgVAgw4FOIEPhu6ZBIMSQw5pORyBCw4BJIFThuqxQIMSQQU5HIE3hu54gKHNlcnZlciBs4buNYyB0aGVvIG1hdGNoZWRfZXhlcmNpc2UpOyBraMO0bmcgdHLhu5luIGLDoGkvbcO0biBraMOhYwogICAgICAgIGxldCBzY29wZWQgPSBbXTsKICAgICAgICBsZXQgbWF0Y2hlZEV4ID0gbnVsbDsKICAgICAgICBpZiAoci5tYXRjaGVkX2V4ZXJjaXNlICYmIEFycmF5LmlzQXJyYXkoci5leGVyY2lzZXMpICYmIHIuZXhlcmNpc2VzLmxlbmd0aCkgewogICAgICAgICAgbWF0Y2hlZEV4ID0gci5leGVyY2lzZXMuZmluZChleCA9PiBleC5rZXkgPT09IHIubWF0Y2hlZF9leGVyY2lzZS5rZXkpCiAgICAgICAgICAgIHx8IHIuZXhlcmNpc2VzLmZpbmQoZXggPT4gZXgudGl0bGUgPT09IHIubWF0Y2hlZF9leGVyY2lzZS50aXRsZSkKICAgICAgICAgICAgfHwgbnVsbDsKICAgICAgICB9CiAgICAgICAgaWYgKG1hdGNoZWRFeCAmJiAobWF0Y2hlZEV4Lml0ZW1zIHx8IFtdKS5sZW5ndGgpIHNjb3BlZCA9IG1hdGNoZWRFeC5pdGVtczsKICAgICAgICBlbHNlIGlmIChBcnJheS5pc0FycmF5KHIuZXhlcmNpc2VzKSAmJiByLmV4ZXJjaXNlcy5sZW5ndGggPT09IDEgJiYgKHIuZXhlcmNpc2VzWzBdLml0ZW1zIHx8IFtdKS5sZW5ndGgpIHNjb3BlZCA9IHIuZXhlcmNpc2VzWzBdLml0ZW1zOwogICAgICAgIGVsc2Ugc2NvcGVkID0gci5pdGVtcyB8fCBbXTsKICAgICAgICBTRVNTSU9OLmJhbmtBbnN3ZXJzID0gc2NvcGVkOwogICAgICAgIF9yZWZyZXNoUUNvdW50KCk7CiAgICAgICAgY29uc3QgYm94ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLWxvZ2JveCcpOwogICAgICAgIGlmIChib3gpIHsKICAgICAgICAgIGJveC5pbm5lckhUTUwgPSAnJzsKICAgICAgICAgIGlmIChtYXRjaGVkRXgpIHsKICAgICAgICAgICAgY29uc3QgaCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpOwogICAgICAgICAgICBoLmNsYXNzTmFtZSA9ICd0bC1sb2cgaW5mbyc7CiAgICAgICAgICAgIGguaW5uZXJIVE1MID0gJ/Cfk5ogPGI+JyArIF9lc2NCYW5rKHIuc3ViamVjdCB8fCAnTcO0bicpICsgJzwvYj4gwrcg8J+TnSAnICsgX2VzY0JhbmsobWF0Y2hlZEV4LnRpdGxlIHx8IHIuZXhlcmNpc2VfdGl0bGUgfHwgJ0LDoGkgdOG6rXAnKSArICcg4oCUICcgKyAobWF0Y2hlZEV4LmNvdW50IHx8IHNjb3BlZC5sZW5ndGgpICsgJyBjw6J1ICjEkcO6bmcgYsOgaSDEkWFuZyBt4bufKSc7CiAgICAgICAgICAgIGJveC5hcHBlbmRDaGlsZChoKTsKICAgICAgICAgICAgc2NvcGVkLnNsaWNlKDAsIDIwMCkuZm9yRWFjaChxID0+IHsKICAgICAgICAgICAgICBjb25zdCBkID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICAgICAgICAgICAgZC5jbGFzc05hbWUgPSAndGwtbG9nIG9rJzsKICAgICAgICAgICAgICBkLmlubmVySFRNTCA9ICdRJyArIChxLmluZGV4IHx8ICc/JykgKyAnOiAnICsgX2VzY0JhbmsoU3RyaW5nKHEudGl0bGUgfHwgJycpLnN1YnN0cmluZygwLCA2MCkpICsgJyDihpIgPHNwYW4gc3R5bGU9ImNvbG9yOiNmZmMxMDc7Ij4nICsgX2VzY0JhbmsoKHEuYW5zd2VycyB8fCBbXSkuam9pbignIHwgJykpICsgJzwvc3Bhbj4nOwogICAgICAgICAgICAgIGJveC5hcHBlbmRDaGlsZChkKTsKICAgICAgICAgICAgfSk7CiAgICAgICAgICB9IGVsc2UgaWYgKEFycmF5LmlzQXJyYXkoci5leGVyY2lzZXMpICYmIHIuZXhlcmNpc2VzLmxlbmd0aCkgewogICAgICAgICAgICByLmV4ZXJjaXNlcy5mb3JFYWNoKGV4ID0+IHsKICAgICAgICAgICAgICBjb25zdCBoID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICAgICAgICAgICAgaC5jbGFzc05hbWUgPSAndGwtbG9nIGluZm8nOwogICAgICAgICAgICAgIGguaW5uZXJIVE1MID0gJ/Cfk5ogPGI+JyArIF9lc2NCYW5rKHIuc3ViamVjdCB8fCAnTcO0bicpICsgJzwvYj4gwrcg8J+TnSAnICsgX2VzY0JhbmsoZXgudGl0bGUgfHwgJ0LDoGkgdOG6rXAnKSArICcg4oCUICcgKyAoZXguY291bnQgfHwgKGV4Lml0ZW1zIHx8IFtdKS5sZW5ndGgpICsgJyBjw6J1JzsKICAgICAgICAgICAgICBib3guYXBwZW5kQ2hpbGQoaCk7CiAgICAgICAgICAgICAgKGV4Lml0ZW1zIHx8IFtdKS5zbGljZSgwLCAyMDApLmZvckVhY2gocSA9PiB7CiAgICAgICAgICAgICAgICBjb25zdCBkID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICAgICAgICAgICAgICBkLmNsYXNzTmFtZSA9ICd0bC1sb2cgb2snOwogICAgICAgICAgICAgICAgZC5pbm5lckhUTUwgPSAnUScgKyAocS5pbmRleCB8fCAnPycpICsgJzogJyArIF9lc2NCYW5rKFN0cmluZyhxLnRpdGxlIHx8ICcnKS5zdWJzdHJpbmcoMCwgNjApKSArICcg4oaSIDxzcGFuIHN0eWxlPSJjb2xvcjojZmZjMTA3OyI+JyArIF9lc2NCYW5rKChxLmFuc3dlcnMgfHwgW10pLmpvaW4oJyB8ICcpKSArICc8L3NwYW4+JzsKICAgICAgICAgICAgICAgIGJveC5hcHBlbmRDaGlsZChkKTsKICAgICAgICAgICAgICB9KTsKICAgICAgICAgICAgfSk7CiAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICBzY29wZWQuc2xpY2UoMCwgODApLmZvckVhY2gocSA9PiB7CiAgICAgICAgICAgICAgY29uc3QgZCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpOwogICAgICAgICAgICAgIGQuY2xhc3NOYW1lID0gJ3RsLWxvZyBvayc7CiAgICAgICAgICAgICAgZC5pbm5lckhUTUwgPSAnPGI+UScgKyAocS5pbmRleCB8fCAnPycpICsgJzo8L2I+ICcgKyBfZXNjQmFuayhTdHJpbmcocS50aXRsZSB8fCAnJykuc3Vic3RyaW5nKDAsIDQwKSkgKyAnIOKGkiA8c3BhbiBzdHlsZT0iY29sb3I6I2ZmYzEwNzsiPicgKyBfZXNjQmFuaygocS5hbnN3ZXJzIHx8IFtdKS5qb2luKCcgfCAnKSkgKyAnPC9zcGFuPic7CiAgICAgICAgICAgICAgYm94LmFwcGVuZENoaWxkKGQpOwogICAgICAgICAgICB9KTsKICAgICAgICAgIH0KICAgICAgICAgIGJveC5zY3JvbGxUb3AgPSBib3guc2Nyb2xsSGVpZ2h0OwogICAgICAgIH0KICAgICAgICBhZGRMb2coJ+KchSBLaG8gc2VydmVyIGPDsyAnICsgc2NvcGVkLmxlbmd0aCArICcgxJHDoXAgw6FuIGNobyBiw6BpIHThuq1wIMSRYW5nIG3hu58g4oCUIMSRw6MgaGnhu4NuIHRo4buLIHh14buRbmcgZMaw4bubaSEnLCAnb2snKTsKICAgICAgfSBlbHNlIHsKICAgICAgICBhZGRMb2coJ+KEue+4jyBLaG8gc2VydmVyIGNoxrBhIGPDsyDEkcOhcCDDoW4gY2hvICcgKyAoU0VTU0lPTi5tZXRhLnN1YmplY3RfbmFtZSB8fCAoJ23DtG4gJyArIChjYXRlIHx8ICc/JykpKSArICcgYsOgaSB04bqtcCBuw6B5LicsICd3YXJuJyk7CiAgICAgIH0KICAgIH0gY2F0Y2ggKGUpIHsKICAgICAgYWRkTG9nKCfimqDvuI8gVHJhIGtobyDEkcOhcCDDoW4gbOG7l2k6ICcgKyAoKGUgJiYgZS5tZXNzYWdlKSB8fCBlKSwgJ2VycicpOwogICAgfQogIH0KICBjb25zdCBBUElfS0VZV09SRFMgPSBbICdnZXQtcXVlc3Rpb24tb2YtaWRzJywgJ2dldC1xdWVzdGlvbj9iZWxvbmdzPTEnLCAnZ2V0LXF1ZXN0aW9uJywgJ2dldC10ZXN0JyBdOwogIGZ1bmN0aW9uIGhhbmRsZVJhd1Jlc3BvbnNlKHVybCwgdGV4dCkgewogICAgaWYgKCF1cmwgfHwgIXRleHQpIHJldHVybjsKICAgIGNvbnN0IGlzUUFwaSA9IEFQSV9LRVlXT1JEUy5zb21lKGsgPT4gdXJsLmluY2x1ZGVzKGspKTsKICAgIGNvbnN0IGlzTGVnID0gdXJsLmluY2x1ZGVzKCdnZXQtcXVlc3Rpb24nKSB8fCB1cmwuaW5jbHVkZXMoJ2dldC10ZXN0JykgfHwgdGV4dC5pbmNsdWRlcygnanNvbl9jb250ZW50JykgfHwgdGV4dC5pbmNsdWRlcygnInF1ZXN0aW9ucyInKTsKICAgIGlmICghaXNRQXBpICYmICFpc0xlZykgcmV0dXJuOwogICAgbGV0IGRhdGE7CiAgICB0cnkgewogICAgICBkYXRhID0gSlNPTi5wYXJzZSh0ZXh0KTsKICAgIH0gY2F0Y2ggKF8pIHsKICAgICAgcmV0dXJuOwogICAgfQogICAgY29uc3QgcUxpc3QgPSBkYXRhLnF1ZXN0aW9ucyB8fCBkYXRhLmRhdGEgfHwgKEFycmF5LmlzQXJyYXkoZGF0YSkgPyBkYXRhIDogbnVsbCk7CiAgICBpZiAoIUFycmF5LmlzQXJyYXkocUxpc3QpIHx8IHFMaXN0Lmxlbmd0aCA9PT0gMCkgcmV0dXJuOwogICAgU0VTU0lPTi5yYXdfcXVlc3Rpb25zID0gcUxpc3Q7CiAgICBpZiAoX2JhbmtGYWxsYmFja1RpbWVyKSB7IGNsZWFyVGltZW91dChfYmFua0ZhbGxiYWNrVGltZXIpOyBfYmFua0ZhbGxiYWNrVGltZXIgPSBudWxsOyB9CiAgICBTRVNTSU9OLm1ldGEuaWRfdXNlciA9IHFMaXN0WzBdPy5pZF91c2VyIHx8IGRldGVjdFVzZXJJRCgpOwogICAgU0VTU0lPTi5tZXRhLmlkX2NvdXJzZXdhcmUgPSBkYXRhLmlkX2NvdXJzZXdhcmUgfHwgbmV3IFVSTFNlYXJjaFBhcmFtcyh3aW5kb3cubG9jYXRpb24uc2VhcmNoKS5nZXQoJ2lfYycpOwogICAgU0VTU0lPTi5tZXRhLmlkX2NhdGUgPSBkYXRhLmlkX2NhdGUgfHwgZGF0YS5pZF9leGFtIHx8IHJpcElkRnJvbVVybCgpOwogICAgU0VTU0lPTi5tZXRhLnN1YmplY3RfbmFtZSA9IGRhdGEuc3ViamVjdF9uYW1lIHx8IGRhdGEuc3ViamVjdCB8fCBkYXRhLmNhdGVfbmFtZSB8fCBkZXRlY3RTdWJqZWN0TmFtZSgpIHx8IFNFU1NJT04ubWV0YS5zdWJqZWN0X25hbWUgfHwgJyc7CiAgICBTRVNTSU9OLm1ldGEuZXhlcmNpc2VfdGl0bGUgPSBkYXRhLnRpdGxlIHx8IGRhdGEubmFtZSB8fCBkYXRhLmV4ZXJjaXNlX3RpdGxlIHx8IGRldGVjdEV4ZXJjaXNlVGl0bGUoKSB8fCBTRVNTSU9OLm1ldGEuZXhlcmNpc2VfdGl0bGUgfHwgJyc7CiAgICBTRVNTSU9OLm1ldGEuc3ViamVjdF9pZCA9IGRhdGEuc3ViamVjdF9pZCB8fCBkYXRhLmNhdGVfaWQgfHwgU0VTU0lPTi5tZXRhLnN1YmplY3RfaWQgfHwgbnVsbDsKICAgIHJlZnJlc2hTdWJqZWN0VGl0bGVVSSgpOwogICAgU0VTU0lPTi5tZXRhLmlkX3NjaG9vbCA9IGRldGVjdFNjaG9vbElEKGRhdGEpOwogICAgU0VTU0lPTi5tZXRhLmlkX2dyb3VwID0gZGV0ZWN0R3JvdXBJRCgpOwogICAgY29uc3QgbXQgPSBkb2N1bWVudC5xdWVyeVNlbGVjdG9yKCdtZXRhW25hbWU9ImNzcmYtdG9rZW4iXScpOwogICAgU0VTU0lPTi5tZXRhLmNzcmZfdG9rZW4gPSBtdCA/IG10LmdldEF0dHJpYnV0ZSgnY29udGVudCcpIDogd2luZG93LmNzcmZfdG9rZW4gfHwgJyc7CiAgICBpZiAod2luZG93LnRvdGFsX3RpbWUpIFNFU1NJT04udmlkZW9fbGVuZ3RoID0gTWF0aC5jZWlsKHdpbmRvdy50b3RhbF90aW1lKTsgZWxzZSBpZiAoZGF0YS50b3RhbF90aW1lKSBTRVNTSU9OLnZpZGVvX2xlbmd0aCA9IE1hdGguY2VpbChkYXRhLnRvdGFsX3RpbWUpOwogICAgaWYgKGRhdGEudHlwZSA9PSA1IHx8IHdpbmRvdy5sb2NhdGlvbi5ocmVmLmluY2x1ZGVzKCd2aWRlbycpIHx8IGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoJ3ZpZGVvLGlmcmFtZVtzcmMqPSJ5b3V0dWJlIl0nKSkgU0VTU0lPTi5hdXRvX21vZGUgPSAndmlkZW8nOyBlbHNlIGlmIChkYXRhLnR5cGVfZXhhbSA9PSAxIHx8IGRhdGEuaXNfZXhhbSA9PSAxIHx8IHdpbmRvdy5pc19leGFtID09IDEgfHwgZG9jdW1lbnQucXVlcnlTZWxlY3RvcignLnRpbWUtY291bnRkb3duLCNzdWJtaXQtdGVzdCcpKSBTRVNTSU9OLmF1dG9fbW9kZSA9ICdleGFtJzsgZWxzZSBTRVNTSU9OLmF1dG9fbW9kZSA9ICdwcmFjdGljZSc7CiAgICBjb25zdCBxY0VsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLXFjb3VudCcpOwogICAgY29uc3QgbWRFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1tb2RlLWRldGVjdGVkJyk7CiAgICBpZiAocWNFbCkgcWNFbC50ZXh0Q29udGVudCA9IHFMaXN0Lmxlbmd0aDsKICAgIF9yZWZyZXNoUUNvdW50KCk7CiAgICBpZiAobWRFbCkgewogICAgICBtZEVsLnRleHRDb250ZW50ID0gU0VTU0lPTi5hdXRvX21vZGUudG9VcHBlckNhc2UoKTsKICAgICAgY29uc3QgbXMgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtbW9kZVNlbGVjdCcpOwogICAgICBpZiAobXMpIG1zLnZhbHVlID0gU0VTU0lPTi5hdXRvX21vZGU7CiAgICB9CiAgICBhZGRMb2coYPCfk6UgWyR7U0VTU0lPTi5tZXRhLnN1YmplY3RfbmFtZSB8fCAnbcO0biA/J31dJHtTRVNTSU9OLm1ldGEuZXhlcmNpc2VfdGl0bGUgPyAnIMK3ICcgKyBTRVNTSU9OLm1ldGEuZXhlcmNpc2VfdGl0bGUgOiAnJ30g4oCUIG7huqFwICR7cUxpc3QubGVuZ3RofSBjw6J1IGjhu49pICgke1NFU1NJT04uYXV0b19tb2RlfSkuLi5gLCAnaW5mbycpOwogICAgY29uc3Qga2V5ID0gQ1VSUkVOVF9LRVkgfHwgX3NMUy5nZXQoTFNfS0VZKTsKICAgIGlmICgha2V5KSB7CiAgICAgIGFkZExvZygn4pqg77iPIENoxrBhIGPDsyBrZXkg4oCUIGtow7RuZyB0aOG7gyBnaeG6o2kgbcOjLicsICd3YXJuJyk7CiAgICAgIHJldHVybjsKICAgIH0KICAgIGdtUG9zdCgnL3Byb2Nlc3MnLCB7CiAgICAgIGtleToga2V5LAogICAgICBod2lkOiBnZXRIV0lEKCksCiAgICAgIHF1ZXN0aW9uczogcUxpc3QsCiAgICAgIG1ldGE6IHsKICAgICAgICBpZF91c2VyOiBTRVNTSU9OLm1ldGEuaWRfdXNlciB8fCBkZXRlY3RVc2VySUQoKSwKICAgICAgICBpZF9jYXRlOiBTRVNTSU9OLm1ldGEuaWRfY2F0ZSwKICAgICAgICBpZF9jb3Vyc2V3YXJlOiBTRVNTSU9OLm1ldGEuaWRfY291cnNld2FyZSwKICAgICAgICBzdWJqZWN0X25hbWU6IFNFU1NJT04ubWV0YS5zdWJqZWN0X25hbWUgfHwgJycsCiAgICAgICAgZXhlcmNpc2VfdGl0bGU6IFNFU1NJT04ubWV0YS5leGVyY2lzZV90aXRsZSB8fCAnJywKICAgICAgICBzdWJqZWN0X2lkOiBTRVNTSU9OLm1ldGEuc3ViamVjdF9pZCB8fCBudWxsLAogICAgICAgIG9sbV91c2VyOiBnZXRPbG1Vc2VybmFtZSgpCiAgICAgIH0KICAgIH0pLnRoZW4ocmVzdWx0ID0+IHsKICAgICAgaWYgKCEocmVzdWx0LnN1Y2Nlc3MgfHwgcmVzdWx0LnZhbGlkKSkgewogICAgICAgIGFkZExvZygn4p2MIFNlcnZlcjogJyArIChyZXN1bHQubWVzc2FnZSB8fCAnTOG7l2kgZ2nhuqNpIG3DoycpLCAnZXJyJyk7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIGNvbnN0IGJveCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1sb2dib3gnKTsKICAgICAgaWYgKGJveCkgewogICAgICAgIGJveC5pbm5lckhUTUwgPSAnJzsKICAgICAgICByZXN1bHQucXVlc3Rpb25zLmZvckVhY2gocSA9PiB7CiAgICAgICAgICBjb25zdCBkID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICAgICAgICBkLmNsYXNzTmFtZSA9ICd0bC1sb2cgb2snOwogICAgICAgICAgZC5pbm5lckhUTUwgPSBgPGI+USR7cS5pbmRleH06PC9iPiAkeyhxLnRpdGxlIHx8ICcnKS5zdWJzdHJpbmcoMCwgNDApfSDihpIgPHNwYW4gc3R5bGU9ImNvbG9yOiNmZmMxMDc7Ij4ke3EuYW5zd2Vycy5qb2luKCcgfCAnKX08L3NwYW4+YDsKICAgICAgICAgIGJveC5hcHBlbmRDaGlsZChkKTsKICAgICAgICB9KTsKICAgICAgICBib3guc2Nyb2xsVG9wID0gYm94LnNjcm9sbEhlaWdodDsKICAgICAgfQogICAgICBhZGRMb2coYOKchSDEkMOjIGhp4buDbiB0aOG7iyDEkcOhcCDDoW4gJHtyZXN1bHQuY291bnR9IGPDonUhYCwgJ29rJyk7CiAgICB9KS5jYXRjaChlID0+IGFkZExvZygn4p2MIEzhu5dpIGvhur90IG7hu5FpIHNlcnZlcjogJyArIGUubWVzc2FnZSwgJ2VycicpKTsKICB9CiAgKGZ1bmN0aW9uIGluamVjdFBhZ2VIb29rKCkgewogICAgdHJ5IHsKICAgICAgY29uc3QgY29kZSA9ICcoJyArIGZ1bmN0aW9uKCkgewogICAgICAgIGlmICh3aW5kb3cuX190bF9ob29rZWQpIHJldHVybjsKICAgICAgICB3aW5kb3cuX190bF9ob29rZWQgPSB0cnVlOwogICAgICAgIHdpbmRvdy5fX2t2X3FfYnVmID0gd2luZG93Ll9fa3ZfcV9idWYgfHwgW107CiAgICAgICAgZnVuY3Rpb24gX190bF9wdXNoKHVybCwgdGV4dCkgewogICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgd2luZG93Ll9fa3ZfcV9idWYucHVzaCh7CiAgICAgICAgICAgICAgdXJsOiB1cmwsCiAgICAgICAgICAgICAgdGV4dDogdGV4dCwKICAgICAgICAgICAgICB0czogRGF0ZS5ub3coKQogICAgICAgICAgICB9KTsKICAgICAgICAgICAgd2luZG93LmRpc3BhdGNoRXZlbnQobmV3IEN1c3RvbUV2ZW50KCdfX2t2X3FkYXRhJywgewogICAgICAgICAgICAgIGRldGFpbDogewogICAgICAgICAgICAgICAgdXJsOiB1cmwsCiAgICAgICAgICAgICAgICB0ZXh0OiB0ZXh0CiAgICAgICAgICAgICAgfQogICAgICAgICAgICB9KSk7CiAgICAgICAgICB9IGNhdGNoIChlKSB7fQogICAgICAgIH0KICAgICAgICBmdW5jdGlvbiBfX3RsX3JlbWVtYmVyX3JlcSh1cmwsIG1ldGhvZCwgYm9keSkgewogICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgdmFyIHUgPSAodXJsIHx8ICcnKS50b0xvd2VyQ2FzZSgpOwogICAgICAgICAgICBpZiAodS5pbmRleE9mKCdnZXQtcXVlc3Rpb24nKSAhPT0gLTEgfHwgdS5pbmRleE9mKCdnZXQtdGVzdCcpICE9PSAtMSkgewogICAgICAgICAgICAgIHdpbmRvdy5fX3RsX2xhc3RfcXJlcSA9IHsKICAgICAgICAgICAgICAgIHVybDogdXJsLAogICAgICAgICAgICAgICAgbWV0aG9kOiBtZXRob2QgfHwgJ0dFVCcsCiAgICAgICAgICAgICAgICBib2R5OiBib2R5IHx8IG51bGwsCiAgICAgICAgICAgICAgICB0czogRGF0ZS5ub3coKQogICAgICAgICAgICAgIH07CiAgICAgICAgICAgIH0KICAgICAgICAgIH0gY2F0Y2ggKGUpIHt9CiAgICAgICAgfQogICAgICAgIHZhciBfX28gPSBYTUxIdHRwUmVxdWVzdC5wcm90b3R5cGUub3BlbjsKICAgICAgICB2YXIgX19zID0gWE1MSHR0cFJlcXVlc3QucHJvdG90eXBlLnNlbmQ7CiAgICAgICAgWE1MSHR0cFJlcXVlc3QucHJvdG90eXBlLm9wZW4gPSBmdW5jdGlvbihtLCB1KSB7CiAgICAgICAgICB0aGlzLl9fdGxfdXJsID0gdTsKICAgICAgICAgIHJldHVybiBfX28uYXBwbHkodGhpcywgYXJndW1lbnRzKTsKICAgICAgICB9OwogICAgICAgIFhNTEh0dHBSZXF1ZXN0LnByb3RvdHlwZS5zZW5kID0gZnVuY3Rpb24oYm9keSkgewogICAgICAgICAgdmFyIHNlbGYgPSB0aGlzOwogICAgICAgICAgX190bF9yZW1lbWJlcl9yZXEoc2VsZi5fX3RsX3VybCB8fCAnJywgJ1BPU1QnLCBib2R5IHx8IG51bGwpOwogICAgICAgICAgdGhpcy5hZGRFdmVudExpc3RlbmVyKCdsb2FkJywgZnVuY3Rpb24oKSB7CiAgICAgICAgICAgIGlmIChzZWxmLnN0YXR1cyA9PT0gMjAwKSB7CiAgICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgIF9fdGxfcHVzaChzZWxmLnJlc3BvbnNlVVJMIHx8IHNlbGYuX190bF91cmwgfHwgJycsIHNlbGYucmVzcG9uc2VUZXh0IHx8ICcnKTsKICAgICAgICAgICAgICB9IGNhdGNoIChlKSB7fQogICAgICAgICAgICB9CiAgICAgICAgICB9KTsKICAgICAgICAgIHJldHVybiBfX3MuYXBwbHkodGhpcywgYXJndW1lbnRzKTsKICAgICAgICB9OwogICAgICAgIHZhciBfX2YgPSB3aW5kb3cuZmV0Y2g7CiAgICAgICAgd2luZG93LmZldGNoID0gZnVuY3Rpb24oKSB7CiAgICAgICAgICB2YXIgYXJncyA9IGFyZ3VtZW50czsKICAgICAgICAgIHZhciB1cmwgPSB0eXBlb2YgYXJnc1swXSA9PT0gJ3N0cmluZycgPyBhcmdzWzBdIDogYXJnc1swXSAmJiBhcmdzWzBdLnVybCA/IGFyZ3NbMF0udXJsIDogJyc7CiAgICAgICAgICB2YXIgb3B0cyA9IGFyZ3NbMV0gfHwgKHR5cGVvZiBhcmdzWzBdID09PSAnb2JqZWN0JyA/IGFyZ3NbMF0gOiBudWxsKTsKICAgICAgICAgIF9fdGxfcmVtZW1iZXJfcmVxKHVybCwgb3B0cyAmJiBvcHRzLm1ldGhvZCB8fCAnR0VUJywgb3B0cyAmJiBvcHRzLmJvZHkgfHwgbnVsbCk7CiAgICAgICAgICByZXR1cm4gX19mLmFwcGx5KHRoaXMsIGFyZ3MpLnRoZW4oZnVuY3Rpb24ocmVzKSB7CiAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgdmFyIGNsID0gcmVzLmNsb25lKCk7CiAgICAgICAgICAgICAgY2wudGV4dCgpLnRoZW4oZnVuY3Rpb24odCkgewogICAgICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgICAgX190bF9wdXNoKHVybCB8fCByZXMudXJsIHx8ICcnLCB0KTsKICAgICAgICAgICAgICAgIH0gY2F0Y2ggKGUpIHt9CiAgICAgICAgICAgICAgfSk7CiAgICAgICAgICAgIH0gY2F0Y2ggKGUpIHt9CiAgICAgICAgICAgIHJldHVybiByZXM7CiAgICAgICAgICB9KTsKICAgICAgICB9OwogICAgICAgIC8qIHYxOTogZm9yZWlnbi1ob29rIHBvbGxpbmcgaW50ZXJ2YWwgcmVtb3ZlZCAqLwogICAgICB9ICsgJykoKTsnOwogICAgICBjb25zdCBzRWwgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdzY3JpcHQnKTsKICAgICAgc0VsLnRleHRDb250ZW50ID0gY29kZTsKICAgICAgKGRvY3VtZW50LmhlYWQgfHwgZG9jdW1lbnQuZG9jdW1lbnRFbGVtZW50KS5hcHBlbmRDaGlsZChzRWwpOwogICAgICBzRWwucmVtb3ZlKCk7CiAgICB9IGNhdGNoIChlKSB7CiAgICAgIGNvbnNvbGUud2FybignW1RMXSBpbmplY3QgZmFpbCcsIGUpOwogICAgfQogIH0pKCk7CiAgZnVuY3Rpb24gc2V0dXBLVkJ1ZlJlYWRlcigpIHsKICAgIHRyeSB7CiAgICAgIGNvbnN0IFVXID0gdHlwZW9mIHVuc2FmZVdpbmRvdyAhPT0gJ3VuZGVmaW5lZCcgPyB1bnNhZmVXaW5kb3cgOiB3aW5kb3c7CiAgICAgIGxldCBwcm9jZXNzZWQgPSAwOwogICAgICBmdW5jdGlvbiBkcmFpbigpIHsKICAgICAgICB0cnkgewogICAgICAgICAgY29uc3QgYnVmID0gVVcuX19rdl9xX2J1ZjsKICAgICAgICAgIGlmICghQXJyYXkuaXNBcnJheShidWYpIHx8IGJ1Zi5sZW5ndGggPD0gcHJvY2Vzc2VkKSByZXR1cm47CiAgICAgICAgICBmb3IgKGxldCBpID0gcHJvY2Vzc2VkOyBpIDwgYnVmLmxlbmd0aDsgaSsrKSB7CiAgICAgICAgICAgIGNvbnN0IGl0ID0gYnVmW2ldOwogICAgICAgICAgICBpZiAoaXQgJiYgaXQudXJsICYmIGl0LnRleHQpIHsKICAgICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgaGFuZGxlUmF3UmVzcG9uc2UoaXQudXJsLCBpdC50ZXh0KTsKICAgICAgICAgICAgICB9IGNhdGNoIChfKSB7fQogICAgICAgICAgICB9CiAgICAgICAgICB9CiAgICAgICAgICBwcm9jZXNzZWQgPSBidWYubGVuZ3RoOwogICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgIH0KICAgICAgdHJ5IHsKICAgICAgICBVVy5hZGRFdmVudExpc3RlbmVyKCdfX2t2X3FkYXRhJywgZnVuY3Rpb24oZXZ0KSB7CiAgICAgICAgICB0cnkgewogICAgICAgICAgICBjb25zdCBkID0gZXZ0ICYmIGV2dC5kZXRhaWw7CiAgICAgICAgICAgIGlmIChkICYmIGQudXJsICYmIGQudGV4dCkgewogICAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgICBoYW5kbGVSYXdSZXNwb25zZShkLnVybCwgZC50ZXh0KTsKICAgICAgICAgICAgICB9IGNhdGNoIChfKSB7fQogICAgICAgICAgICB9CiAgICAgICAgICAgIGNvbnN0IGJ1ZiA9IFVXLl9fa3ZfcV9idWY7CiAgICAgICAgICAgIGlmIChBcnJheS5pc0FycmF5KGJ1ZikpIHByb2Nlc3NlZCA9IGJ1Zi5sZW5ndGg7CiAgICAgICAgICB9IGNhdGNoIChfKSB7fQogICAgICAgIH0pOwogICAgICB9IGNhdGNoIChfKSB7fQogICAgICBkcmFpbigpOwogICAgICBpZiAoZG9jdW1lbnQucmVhZHlTdGF0ZSA9PT0gJ2xvYWRpbmcnKSBkb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCdET01Db250ZW50TG9hZGVkJywgZHJhaW4pOyBlbHNlIHNldFRpbWVvdXQoZHJhaW4sIDgwMCk7CiAgICAgIGNvbnN0IGl2ID0gc2V0SW50ZXJ2YWwoZHJhaW4sIDUwMCk7CiAgICAgIHNldFRpbWVvdXQoKCkgPT4gY2xlYXJJbnRlcnZhbChpdiksIDI1ZTMpOwogICAgfSBjYXRjaCAoXykge30KICB9CiAgc2V0dXBLVkJ1ZlJlYWRlcigpOwogIC8qIHYxOTogX190bF9mb3JlaWduX2hvb2sgbGlzdGVuZXIgcmVtb3ZlZCAqLwovKiB2MTk6IGZvcmVpZ24gdXNlcnNjcmlwdC9ob29rIHNjYW4gcmVtb3ZlZCAqLwogIGFzeW5jIGZ1bmN0aW9uIHN0YXJ0dXAoKSB7CiAgICB0cnkgeyBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbSgnX3RsX3JlbW90ZV9sb2NrZWQnKTsgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oJ190bF9wb2lzb25lZCcpOyB9IGNhdGNoIChfKSB7fQogICAgY29uc3Qgc3RvcmVkS2V5ID0gX3NMUy5nZXQoTFNfS0VZKTsKICAgIGNvbnN0IHN0b3JlZEV4cCA9IF9zTFMuZ2V0KExTX0VYUCk7CiAgICBpZiAoc3RvcmVkS2V5KSB7CiAgICAgIGlmIChzdG9yZWRFeHApIHsKICAgICAgICBjb25zdCBleHBEYXRlID0gbmV3IERhdGUoc3RvcmVkRXhwKTsKICAgICAgICBjb25zdCBub3cgPSBuZXcgRGF0ZTsKICAgICAgICBpZiAoIWlzTmFOKGV4cERhdGUpICYmIGV4cERhdGUgPCBub3cpIHsKICAgICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKExTX0tFWSk7CiAgICAgICAgICBidWlsZExvY2tTY3JlZW4oJ+KPsCBLZXkgxJHDoyBo4bq/dCBo4bqhbiEgVnVpIGzDsm5nIG5o4bqtcCBrZXkgbeG7m2kuJyk7CiAgICAgICAgICByZXR1cm47CiAgICAgICAgfQogICAgICB9CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgY3VycmVudE9sbSA9IGdldE9sbVVzZXJuYW1lKCk7CiAgICAgICAgY29uc3QgciA9IGF3YWl0IGdtUG9zdCgnL3ZlcmlmeScsIHsKICAgICAgICAgIGtleTogc3RvcmVkS2V5LAogICAgICAgICAgaHdpZDogZ2V0SFdJRCgpLAogICAgICAgICAgb2xtX3VzZXI6IGN1cnJlbnRPbG0KICAgICAgICB9KTsKICAgICAgICBpZiAoci5zdWNjZXNzIHx8IHIudmFsaWQpIHsKICAgICAgICAgIGNvbnN0IHNlcnZlck9sbSA9IHIub2xtX3VzZXIgfHwgci5vbG1fYWNjb3VudCB8fCAnJzsKICAgICAgICAgIC8vIFt2MjddIEtow7RpIHBo4bulYzogbOG7h2NoIHTDoGkga2hv4bqjbiBPTE0gduG7m2kga2V5IMSRw6MgZ2hpbSAtPiB4b8OhIGtleSArIGtob8OhIHbhu4EgbcOgbiBow6xuaCBuaOG6rXAga2V5CiAgICAgICAgICBpZiAoc2VydmVyT2xtICYmIGN1cnJlbnRPbG0gJiYgY3VycmVudE9sbSAhPT0gJ0tob25nWGFjRGluaCcpIHsKICAgICAgICAgICAgaWYgKHNlcnZlck9sbS50b0xvd2VyQ2FzZSgpICE9PSBjdXJyZW50T2xtLnRvTG93ZXJDYXNlKCkpIHsKICAgICAgICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShMU19LRVkpOwogICAgICAgICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKExTX1RZUEUpOwogICAgICAgICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKExTX0VYUCk7CiAgICAgICAgICAgICAgaGFuZGxlT2xtTWlzbWF0Y2goc2VydmVyT2xtLCBjdXJyZW50T2xtKTsKICAgICAgICAgICAgICByZXR1cm47CiAgICAgICAgICAgIH0KICAgICAgICAgIH0KICAgICAgICAgIENVUlJFTlRfS0VZID0gc3RvcmVkS2V5OwogICAgICAgICAgS0VZX1NUQVRVUyA9IHsKICAgICAgICAgICAgdmFsaWQ6IHRydWUsCiAgICAgICAgICAgIHR5cGU6IHIudHlwZSwKICAgICAgICAgICAgZXhwaXJlc19hdDogci5leHBpcmVzX2F0CiAgICAgICAgICB9OwogICAgICAgICAgX3NMUy5zZXQoTFNfVFlQRSwgci50eXBlIHx8ICdUSFVPTkcnKTsKICAgICAgICAgIF9zTFMuc2V0KExTX0VYUCwgci5leHBpcmVzX2F0IHx8ICcnKTsKICAgICAgICAgIGNyZWF0ZVVJKCk7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIGlmIChyICYmIHIuX2h0dHBTdGF0dXMgPT09IDQwNCkgewogICAgICAgICAgICBfZW50ZXJCYW5Nb2RlKCdUaGnhur90IGLhu4svSVAgxJHDoyBi4buLIGFkbWluIGtob8OhLicpOwogICAgICAgICAgICByZXR1cm47CiAgICAgICAgICB9CiAgICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShMU19LRVkpOwogICAgICAgICAgYnVpbGRMb2NrU2NyZWVuKHIubWVzc2FnZSB8fCAnS2V5IGtow7RuZyBjw7JuIGjhu6NwIGzhu4chJyk7CiAgICAgICAgfQogICAgICB9IGNhdGNoIChfKSB7CiAgICAgICAgQ1VSUkVOVF9LRVkgPSBzdG9yZWRLZXk7CiAgICAgICAgS0VZX1NUQVRVUyA9IHsKICAgICAgICAgIHZhbGlkOiB0cnVlLAogICAgICAgICAgdHlwZTogX3NMUy5nZXQoTFNfVFlQRSksCiAgICAgICAgICBleHBpcmVzX2F0OiBzdG9yZWRFeHAKICAgICAgICB9OwogICAgICAgIGNyZWF0ZVVJKCk7CiAgICAgIH0KICAgIH0gZWxzZSB7CiAgICAgIGJ1aWxkTG9ja1NjcmVlbigpOwogICAgfQogICAgc2V0SW50ZXJ2YWwoYXN5bmMgKCkgPT4gewogICAgICBpZiAoIUNVUlJFTlRfS0VZKSByZXR1cm47CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgY3VycmVudE9sbSA9IGdldE9sbVVzZXJuYW1lKCk7CiAgICAgICAgY29uc3QgciA9IGF3YWl0IGdtUG9zdCgnL3ZlcmlmeScsIHsKICAgICAgICAgIGtleTogQ1VSUkVOVF9LRVksCiAgICAgICAgICBod2lkOiBnZXRIV0lEKCksCiAgICAgICAgICBvbG1fdXNlcjogY3VycmVudE9sbQogICAgICAgIH0pOwogICAgICAgIGlmICghKHIuc3VjY2VzcyB8fCByLnZhbGlkKSkgewogICAgICAgICAgaWYgKHIgJiYgci5faHR0cFN0YXR1cyA9PT0gNDA0KSB7CiAgICAgICAgICAgIF9lbnRlckJhbk1vZGUoJ1RoaeG6v3QgYuG7iy9JUCDEkcOjIGLhu4sgYWRtaW4ga2hvw6EuJyk7CiAgICAgICAgICAgIHJldHVybjsKICAgICAgICAgIH0KICAgICAgICAgIGNvbnN0IHBhbmVsRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtcGFuZWwnKTsKICAgICAgICAgIGNvbnN0IGZiID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLWZsb2F0QnRuJyk7CiAgICAgICAgICBpZiAocGFuZWxFbCkgcGFuZWxFbC5yZW1vdmUoKTsKICAgICAgICAgIGlmIChmYikgZmIucmVtb3ZlKCk7CiAgICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShMU19LRVkpOwogICAgICAgICAgQ1VSUkVOVF9LRVkgPSBudWxsOwogICAgICAgICAgX3NlY1Nlc3Npb24gPSB7CiAgICAgICAgICAgIHRva2VuOiBudWxsLAogICAgICAgICAgICBleHA6IDAsCiAgICAgICAgICAgIGZwSGFzaDogbnVsbCwKICAgICAgICAgICAgc2VxOiAxCiAgICAgICAgICB9OwogICAgICAgICAgQ1VSUkVOVF9ERVZJQ0UgPSAnJzsKICAgICAgICAgIHNob3dDdXN0b21Nb2RhbCh7CiAgICAgICAgICAgIGljb246ICfimqDvuI8nLAogICAgICAgICAgICB0aXRsZTogJ0tFWSDEkMODIELhu4ogS0jDk0EhJywKICAgICAgICAgICAgbGluZXM6IFsgci5tZXNzYWdlIHx8ICdLZXkgxJHDoyBi4buLIHbDtCBoaeG7h3UgaG/DoSEnLCAnVG9vbCBz4bq9IGLhu4sga2jDs2EgbmdheSBs4bqtcCB04bupYyEnIF0sCiAgICAgICAgICAgIG9uT2s6ICgpID0+IGJ1aWxkTG9ja1NjcmVlbihyLm1lc3NhZ2UgfHwgJ0tleSDEkcOjIGLhu4sgdsO0IGhp4buHdSBob8OhIScpCiAgICAgICAgICB9KTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgY29uc3Qgc2VydmVyT2xtID0gci5vbG1fdXNlciB8fCByLm9sbV9hY2NvdW50IHx8ICcnOwogICAgICAgICAgLy8gW3YyN10gS2jDtGkgcGjhu6VjOiBwb2xsIHBow6F0IGhp4buHbiBs4buHY2ggdMOgaSBraG/huqNuIE9MTSAtPiB4b8OhIGtleSArIGtob8OhIHbhu4EgbcOgbiBow6xuaCBuaOG6rXAga2V5CiAgICAgICAgICBpZiAoc2VydmVyT2xtICYmIGN1cnJlbnRPbG0gJiYgY3VycmVudE9sbSAhPT0gJ0tob25nWGFjRGluaCcpIHsKICAgICAgICAgICAgaWYgKHNlcnZlck9sbS50b0xvd2VyQ2FzZSgpICE9PSBjdXJyZW50T2xtLnRvTG93ZXJDYXNlKCkpIHsKICAgICAgICAgICAgICBoYW5kbGVPbG1NaXNtYXRjaChzZXJ2ZXJPbG0sIGN1cnJlbnRPbG0pOwogICAgICAgICAgICAgIHJldHVybjsKICAgICAgICAgICAgfQogICAgICAgICAgfQogICAgICAgIH0KICAgICAgfSBjYXRjaCAoXykge30KICAgIH0sIDUgKiA2MCAqIDFlMyk7CiAgfQogIGlmIChkb2N1bWVudC5yZWFkeVN0YXRlID09PSAnbG9hZGluZycpIHsKICAgIGRvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXIoJ0RPTUNvbnRlbnRMb2FkZWQnLCBzdGFydHVwKTsKICB9IGVsc2UgewogICAgc3RhcnR1cCgpOwogIH0KfSkoKTs=';

const CONNECTOR_MODULE_VERSION = parseInt(process.env.CONNECTOR_MODULE_VERSION || '20', 10); // [v27] giữ tính năng v26 (tra đúng bài, đếm câu 2.5s, log tài khoản OLM 15s, mobile-friendly) + KHÔI PHỤC khoá: lệch tài khoản OLM -> xoá key + về màn hình nhập key

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
    // Scanner dumper: không coi bridge hợp lệ của mình là "GM leak"
    // Mở rộng OWN whitelist — bao gồm cả biến thể chữ hoa/thường mà Violentmonkey iOS có thể leak
    if (out.includes('__tl_fus_guard: 1')) {
      out = out.replace(
        "__tl_fus_guard: 1",
        "__tl_fus_guard: 1,\n          GM_xmlhttpRequest: 1,\n          GM_xmlHttpRequest: 1,\n          GM_addStyle: 1,\n          __GMFunc__: 1,\n          GM_getValue: 1,\n          GM_setValue: 1,\n          GM_deleteValue: 1,\n          GM_listValues: 1,\n          GM_info: 1,\n          GM_notification: 1,\n          GM_openInTab: 1,\n          GM_registerMenuCommand: 1,\n          GM_cookie: 1,\n          GM_download: 1,\n          unsafeWindow: 1"
      );
    }

    // === XÓA PHÁT HIỆN PHẦN MỀM LẠ (disable foreign software detection) ===
    // 1. Vô hiệu hoá _preScanHook khởi tạo — không scan lúc load
    if (out.includes('_preScanHook = _detectHookNow();')) {
      out = out.replace('_preScanHook = _detectHookNow();', '_preScanHook = null; // detection disabled');
    }
    // 2. Vô hiệu hoá _startPeriodicScan — luôn trả h = null, không lock
    if (out.includes('const h = _detectHookNow();')) {
      out = out.replace('const h = _detectHookNow();', 'const h = null; // detection disabled');
    }
    // 3. Vô hiệu hoá listener __tl_foreign_hook (hook detection từ page script)
    out = out.replace(
      /_foreignStrike\+\+;\n(\s*)if \(_foreignStrike >= 3 && _guardActive\) \{/,
      '_foreignStrike = 0; // disabled\n$1if (false && _foreignStrike >= 3 && _guardActive) {'
    );
    // 4. Vô hiệu hoá _enterRemoteLock trong __tl_foreign_us listener (foreign userscript guard)
    // Target chuỗi duy nhất bên trong hàm listener của _initForeignUsGuard
    out = out.replace(
      /if \(d\.clean\) return;\n(\s*)_enterRemoteLock\('/g,
      "return; // detection disabled\n$1if (d.clean) return;\n$1_enterRemoteLock('"
    );

    // === FIX: PBKDF2 iterations mismatch — client 1e3 ≠ server 100000 → decrypt thất bại ===
    // Server dùng 100,000 iterations (FIX #5), client cũ chỉ dùng 1,000.
    // Khác iterations → khác key → AES-GCM decrypt luôn fail với mọi thiết bị.
    // Patch client _deriveKey() lên 1e5 để khớp server.
    out = out.replace(
      /salt:\s*enc\.encode\('godmode-v4-salt'\),\s*\n(\s*)iterations:\s*1e3,/,
      "salt: enc.encode('godmode-v4-salt'),\n$1iterations: 1e5,"
    );

    // === FIX v19: gửi điểm mục tiêu đã chọn (7/8/9/10đ) khi bấm "CHUẨN BỊ 10 ĐIỂM" ===
    // Trước đây body POST /fire thiếu target_score → server mặc định tgtScore = 10:
    // dù chọn 8đ/9đ ở dropdown "Điểm mục tiêu" vẫn nộp toàn bộ đúng, OLM trả 10/10.
    // Nay đọc #tl-god-target-score và đính kèm target_score; route /fire đã hỗ trợ sẵn.
    const fireGradeAnchor = "grade: window.grade || window.id_grade || '10'\n          });";
    if (out.includes(fireGradeAnchor)) {
      out = out.replace(
        fireGradeAnchor,
        "grade: window.grade || window.id_grade || '10',\n" +
        "            target_score: (function(){try{var el=document.getElementById('tl-god-target-score');var v=el?parseFloat(el.value):NaN;if(!isFinite(v))v=10;return String(Math.min(10,Math.max(7,v)));}catch(_){return '10';}})()\n" +
        "          });"
      );
    }
  } catch (_) {}
  // Fallback fetch-based GM_xmlhttpRequest khi chạy trực tiếp (không qua wrapper)
  const fallback = ";(function(){try{if(typeof window!=='undefined'&&typeof window.GM_xmlhttpRequest!=='function'){window.GM_xmlhttpRequest=function(d){d=d||{};fetch(d.url,{method:d.method||'GET',headers:d.headers||{},body:(d.data!=null?d.data:undefined)}).then(function(r){return r.text().then(function(t){if(d.onload)d.onload({status:r.status,responseText:t,response:t,readyState:4});});}).catch(function(e){if(d.onerror)d.onerror({error:String(e&&e.message||e)});});};}}catch(_){}})();\n";
  return fallback + out;
}

function buildConnectorPayload(sessionToken) {
  return encryptAnswers({
    src: GM_LEAK_SANITIZER + IOS_BRIDGE_SHIM + patchConnectorSrc(CONNECTOR_MODULE_SRC),
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

const GM_LEAK_SANITIZER = ';(function(){try{var KEEP={__gmfunc__:1,gm_xmlhttprequest:1,gm_addstyle:1};var _wn=Object.getOwnPropertyNames(window);for(var _i=0;_i<_wn.length;_i++){var _n=_wn[_i];if(KEEP[String(_n).toLowerCase()])continue;if(_n==="GM_info"||_n==="unsafeWindow"||/^(GM_|__gm|__u(ser)?script)/i.test(_n)){try{delete window[_n];}catch(_){try{window[_n]=undefined;}catch(_){}}}}}catch(_){}})();\n';

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
  if(typeof window==='undefined')return;
  try{ if(typeof window.GM_xmlhttpRequest!=='function'){ window.GM_xmlhttpRequest=__tlXhr; } }catch(_){}
  try{ if(typeof window.GM_addStyle!=='function'){ window.GM_addStyle=function(css){try{var s=document.createElement('style');s.textContent=css;(document.head||document.documentElement).appendChild(s);}catch(_){}}; } }catch(_){}
  try{
    if(!window.__GMFunc__){ window.__GMFunc__={GM_xmlhttpRequest:__tlXhr,xmlhttprequest:__tlXhr,xmlHttpRequest:__tlXhr}; }
    else if(typeof window.__GMFunc__==='object'&&window.__GMFunc__!==null){ if(typeof window.__GMFunc__.GM_xmlhttpRequest!=='function')window.__GMFunc__.GM_xmlhttpRequest=__tlXhr; if(typeof window.__GMFunc__.xmlhttprequest!=='function')window.__GMFunc__.xmlhttprequest=__tlXhr; }
  }catch(_){}
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
  return GM_LEAK_SANITIZER + IOS_BRIDGE_SHIM + src + buildOlmBanSnippet(origin, API_PREFIX);
}

function wrapConnectorWithBridge(src) {
  return src;
}

function buildLoaderSrc(req) {
  const origin = req.protocol + '://' + req.get('host');
  const SEC = SECRET, AP = API_PREFIX;
  return `// ==UserScript==\n// @name         GOD MODE v9 Loader (iOS-FIX, fetch-based)\n// @namespace    godmode.v9\n// @version      9.0\n// @description  Fix loi dang nhap key tren iOS: khong dung window.__GMFunc__ — mang qua fetch (CORS da bat).\n// @match        *://*.olm.vn/*\n// @match        *://olm.vn/*\n// @run-at       document-end\n// @grant        none\n// ==/UserScript==\n;(function(){\n  var SERVER_BASE = ${JSON.stringify(origin)};\n  var API_PREFIX = ${JSON.stringify(AP)};\n  var BOOT_KEY = ${JSON.stringify(BOOTSTRAP_PUBLIC_KEY)};\n  function _err(m){ try{ var d=document.createElement('div'); d.style.cssText='position:fixed;top:10px;left:10px;z-index:2147483647;background:#7f1d1d;color:#fff;padding:10px 14px;border-radius:8px;font:12px/1.5 monospace;max-width:85%'; d.textContent='GOD MODE: '+(m||''); (document.documentElement||document.body).appendChild(d); setTimeout(function(){try{d.remove();}catch(_){}},8000); }catch(_){} }\n  function _b64dec(b64){ var bin=atob(b64); var bytes=new Uint8Array(bin.length); for(var i=0;i<bin.length;i++) bytes[i]=bin.charCodeAt(i); return bytes.buffer; }\n  function _gmXhr(d){ d=d||{}; try{ var ctrl=(typeof AbortController!=='undefined')?new AbortController():null; var tmo=setTimeout(function(){if(ctrl)try{ctrl.abort();}catch(_){}}, d.timeout||20000); var opts={method:d.method||'GET',headers:d.headers||{}}; if(ctrl)opts.signal=ctrl.signal; if(d.data!==undefined&&d.data!==null)opts.body=d.data; fetch(d.url,opts).then(function(r){clearTimeout(tmo);return r.text().then(function(t){return{s:r.status,t:t};});}).then(function(o){if(d.onload)d.onload({status:o.s,responseText:o.t,response:o.t,readyState:4});}).catch(function(e){clearTimeout(tmo);if(d.onerror)d.onerror({error:String(e&&e.message||e)});}); }catch(e){ if(d.onerror)d.onerror({error:String(e&&e.message||e)}); } }\n  function _gmStyle(css){ try{ var st=document.createElement('style'); st.textContent=css; (document.head||document.documentElement).appendChild(st); }catch(_){} }\n  try{ if(typeof window!=='undefined'){ if(typeof window.GM_xmlhttpRequest!=='function'){ window.GM_xmlhttpRequest=_gmXhr; } if(!window.__GMFunc__){ window.__GMFunc__={GM_xmlhttpRequest:_gmXhr,xmlhttprequest:_gmXhr}; } else if(typeof window.__GMFunc__==='object'&&window.__GMFunc__!==null&&typeof window.__GMFunc__.GM_xmlhttpRequest!=='function'){ window.__GMFunc__.GM_xmlhttpRequest=_gmXhr; } } }catch(_){}\n  function _runConnector(src){ try{ (new Function('GM_xmlhttpRequest','GM_addStyle','unsafeWindow', src)).call(window, _gmXhr, _gmStyle, window); }catch(e){ _err('Connector loi: '+(e&&e.message||e)); } }\n  async function _boot(){\n    try{\n      var r = await fetch(SERVER_BASE + API_PREFIX + '/bootstrap.js', {cache:'no-store'});\n      if(!r.ok){ if(r.status===404){ _err('Server dang bao tri / script tam khoa (admin da chan keo script).'); } else { _err('Khong keo duoc bootstrap (HTTP '+r.status+')'); } return; }\n      var j = await r.json();\n      if(!j||!j.ok||!j.payload){ _err('Bootstrap khong hop le.'); return; }\n      var enc = new TextEncoder();\n      var keyMat = await crypto.subtle.importKey('raw', enc.encode(BOOT_KEY), 'PBKDF2', false, ['deriveKey']);\n      var aesKey = await crypto.subtle.deriveKey({name:'PBKDF2', salt: enc.encode('tl-bootstrap-v8-salt'), iterations: 1000, hash:'SHA-256'}, keyMat, {name:'AES-GCM', length:256}, false, ['decrypt']);\n      var iv = _b64dec(j.payload.iv);\n      var data = _b64dec(j.payload.data);\n      var plain = await crypto.subtle.decrypt({name:'AES-GCM', iv: iv}, aesKey, data);\n      var src = new TextDecoder('utf-8').decode(plain);\n      _runConnector(src);\n    }catch(e){ _err('Loi giai ma bootstrap: '+(e&&e.message||e)); }\n  }\n  if(document.readyState==='loading'){ document.addEventListener('DOMContentLoaded', _boot); } else { _boot(); }\n})();\n`;
}

function buildKvPayloadSrc(req) {
  const origin = req.protocol + '://' + req.get('host');
  const connSrc = renderConnectorSrc(req);
  const connB64 = Buffer.from(connSrc, 'utf8').toString('base64');
  return `\n;(function(){\n  if (window.__tl_kv_payload_v82) return;\n  window.__tl_kv_payload_v82 = 1;\n  function __tlFail(msg){\n    console.error('[TL-KV]', msg);\n    try {\n      var d=document.createElement('div');\n      d.style.cssText='position:fixed;top:8px;left:8px;z-index:2147483647;background:#7f1d1d;color:#fff;padding:8px 12px;border-radius:8px;font:12px/1.4 monospace;max-width:85%;box-shadow:0 4px 12px rgba(0,0,0,.4)';\n      d.textContent='Tool loi: '+(msg||'');\n      (document.documentElement||document.body).appendChild(d);\n      setTimeout(function(){ try{d.remove();}catch(_){} }, 7000);\n    } catch(_){}\n  }\n  try {\n    \n    var __uw = (typeof unsafeWindow !== 'undefined') ? unsafeWindow : window;\n    var __gmStyle = (typeof GM_addStyle !== 'undefined') ? GM_addStyle : function(css){ try { var s=document.createElement('style'); s.textContent=css; (document.head||document.documentElement).appendChild(s); } catch(_){} };\n    var __gmXhr = (typeof GM_xmlhttpRequest !== 'undefined') ? GM_xmlhttpRequest : function(d){\n      d = d || {};\n      try {\n        var ctrl = (typeof AbortController !== 'undefined') ? new AbortController() : null;\n        var tmo = setTimeout(function(){ if (ctrl) try{ ctrl.abort(); }catch(_){} }, d.timeout || 20000);\n        var opts = { method: d.method || 'GET', headers: d.headers || {} };\n        if (ctrl) opts.signal = ctrl.signal;\n        if (d.data !== undefined && d.data !== null) opts.body = d.data;\n        fetch(d.url, opts).then(function(r){\n          clearTimeout(tmo);\n          return r.text().then(function(t){ return { s: r.status, t: t }; });\n        }).then(function(o){\n          if (d.onload) d.onload({ status: o.s, responseText: o.t, response: o.t, readyState: 4 });\n        }).catch(function(e){\n          clearTimeout(tmo);\n          if (d.onerror) d.onerror({ error: String(e && e.message || e) });\n        });\n      } catch(e){ if (d.onerror) d.onerror({ error: String(e && e.message || e) }); }\n    };\n    var __b64 = "${connB64}";\n    var bin = atob(__b64);\n    var bytes = new Uint8Array(bin.length);\n    for (var i=0;i<bin.length;i++) bytes[i]=bin.charCodeAt(i);\n    var __src = new TextDecoder('utf-8').decode(bytes);\n    \n    try{ if(typeof window!=='undefined' && typeof window.GM_xmlhttpRequest!=='function'){ window.GM_xmlhttpRequest=__gmXhr; } }catch(_){}
    try{ if(typeof window!=='undefined' && !window.__GMFunc__){ window.__GMFunc__={GM_xmlhttpRequest:__gmXhr,xmlhttprequest:__gmXhr}; } }catch(_){}
    (new Function('GM_xmlhttpRequest','GM_addStyle','unsafeWindow', __src)).call(window, __gmXhr, __gmStyle, __uw);\n  } catch(e) {\n    __tlFail(e && e.message ? e.message : String(e));\n  }\n})();\n`;
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

// === IOS WHITELIST: thiết bị/IP được miễn hoàn toàn khỏi lock-report + ban ===
// Key: 'dev:HWID' hoặc 'ip:1.2.3.4' — value: { by, t, reason }
const iosWhitelist = new Map;

let autoUnbanCount = 0;

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

// === KHO ĐÁP ÁN (answer bank): MÔN (tên môn + id_cate) -> BÀI TẬP (tên bài tập) -> câu hỏi/đáp án, bền vững qua KV ===
const answerBank = new Map;
const BANK_LIMIT_ITEMS = 2500;
const BANK_LIMIT_ENTRIES = 2000;

// [v24] TOMBSTONE: môn/bài tập đã xoá KHÔNG hồi sinh sau restart, và không bị instance khác (Vercel multi lambda) ghi đè lại.
const bankTombstones = new Map(); // '<scope>::<id>' -> timestamp xoá
const BANK_TOMB_TTL = 30 * 24 * 3600 * 1e3;
function tombMark(scope, id) { if (id == null || id === '') return; bankTombstones.set(scope + '::' + String(id), Date.now()); }
function tombHas(scope, id) { if (id == null || id === '') return false; const t = bankTombstones.get(scope + '::' + String(id)); return !!t && (Date.now() - t < BANK_TOMB_TTL); }
function applyBankTombstones() {
  try {
    const now = Date.now();
    for (const [k, t] of bankTombstones) if (now - t > BANK_TOMB_TTL) bankTombstones.delete(k);
    // [v25] Giữ tombstone 'subject::*' đến hết TTL (30 ngày): không xoá sớm trong RAM, nếu không instance khác
    //       đọc KV cũ sẽ ghi đè lại toàn bộ kho đã bấm "Xoá toàn bộ".
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
  // [v21] 1 entry theo môn (ưu tiên id_cate, fallback tên môn); các bài tập nằm trong entry.exercises
  return String((meta && meta.id_cate) || (meta && meta.subject_name) || 'none');
}
function normBankText(s) {
  return String(s == null ? '' : s).toLowerCase()
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .replace(/đ/g, 'd').replace(/[^a-z0-9\s]/g, ' ').replace(/\s+/g, ' ').trim();
}

// [v24] CHUẨN HOÁ TÊN MÔN: gộp biến thể chính tả / dấu (lý ↔ lí, hoa thường) về MỘT môn duy nhất,
//       đồng thời nhận diện môn khi script không gửi subject_name (suy từ tên bài tập / nội dung câu).
const SUBJECT_RULES = [
  { key: 'dia-ly',    label: 'Địa lý',                                     words: ['dia ly', 'dia li', 'địa lý', 'địa lí', 'vi tri dia ly', 'khu vuc dong nam a'] },
  { key: 'ngu-van',   label: 'Ngữ văn',                                     words: ['ngu van', 'ngữ văn', 'loi tien dan', 'tien dan'] },
  { key: 'toan',      label: 'Toán',                                       words: ['toan hoc', 'toan', 'dai so', 'hinh hoc'] },
  { key: 'tieng-anh', label: 'Tiếng Anh',                                  words: ['tieng anh', 'tiếng anh', 'english', 'pronunciation', 'practice pronunciation'] },
  { key: 'gd-kpl',    label: 'Giáo dục kinh tế và pháp luật',              words: ['kinh doanh', 'phap luat', 'pháp luật', 'kinh te', 'giao duc kinh te', 'co hoi kinh doanh', 'nang luc can thiet cua nguoi kinh doanh'] },
  { key: 'lich-su',   label: 'Lịch sử',                                     words: ['lich su', 'lịch sử', 'su thoi dai'] },
  { key: 'sinh-hoc',  label: 'Sinh học',                                   words: ['sinh hoc', 'sinh học', 'sinh vat', 'di truyen'] },
  { key: 'vat-ly',    label: 'Vật lý',                                     words: ['vat ly', 'vat li', 'vật lý', 'vật lí', 'dòng điện', 'nhiet hoc'] },
  { key: 'hoa-hoc',   label: 'Hóa học',                                    words: ['hoa hoc', 'hóa học', 'phan ung hoa hoc'] },
  { key: 'cong-nghe', label: 'Công nghệ',                                  words: ['cong nghe', 'công nghệ', 'ky thuat'] },
  { key: 'the-duc',   label: 'Thể dục',                                     words: ['the duc', 'thể dục', 'the chat'] },
  { key: 'my-thuat',  label: 'Mỹ thuật',                                    words: ['my thuat', 'mỹ thuật', 'my hoa'] },
  { key: 'ngoai-ngu', label: 'Ngoại ngữ',                                   words: ['ngoai ngu', 'ngoại ngữ', 'tieng nhat', 'tieng han', 'tieng phap', 'tieng trung'] },
  { key: 'tin-hoc',   label: 'Tin học',                                     words: ['tin hoc', 'tin học', 'lap trinh'] },
  { key: 'dia-phuong', label: 'Địa phương',                                 words: ['dia phuong', 'địa phương'] }
];
function canonSubject(rawName, rawHint) {
  const flat = normBankText(String(rawName || '') + ' ' + String(rawHint || ''));
  if (!flat.trim()) return { key: '', label: '' };
  for (const r of SUBJECT_RULES) {
    if (r.words.some(w => { const wf = normBankText(w); return wf && (flat === wf || flat.indexOf(wf) !== -1); })) {
      return { key: r.key, label: r.label };
    }
  }
  const nk = normBankText(rawName);
  return { key: nk ? ('raw::' + nk.slice(0, 60)) : '', label: String(rawName || '').trim() };
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
  (entry.exercises || []).forEach(ex => { (ex.items || []).forEach(it => all.push(it)); });
  entry.items = all;
  entry.count = all.length;
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
      hits: entry.hits || 0,
      created_at: entry.created_at || Date.now(),
      updated_at: entry.updated_at || Date.now()
    }];
  }
  entry.exercises.forEach(ex => { if (!Array.isArray(ex.items)) ex.items = []; ex.count = ex.items.length; });
  rebuildFlatItems(entry);
  if (typeof entry.subject !== 'string') entry.subject = '';
}
// [v23] GỘP entry cùng TÊN MÔN: nhiều bài tập / nhiều id_cate của cùng 1 môn nằm CHUNG 1 thẻ môn
function mergeBankEntries(dst, src) {
  if (!dst || !src || dst === src) return dst;
  migrateBankEntry(dst);
  migrateBankEntry(src);
  (src.exercises || []).forEach(ex => {
    if (!ex) return;
    const old = (dst.exercises || []).find(x => x && x.key === ex.key);
    if (!old) { dst.exercises.push(ex); return; }
    const byQ = new Map((old.items || []).map(it => [String(it.qid || ('idx_' + it.index)), it]));
    (ex.items || []).forEach(it => { if (it) byQ.set(String(it.qid || ('idx_' + it.index)), it); });
    old.items = Array.from(byQ.values());
    old.count = old.items.length;
    old.updated_at = Math.max(old.updated_at || 0, ex.updated_at || 0);
    old.hits = (old.hits || 0) + (ex.hits || 0);
  });
  const byQFlat = new Map((dst.items || []).map(it => [String(it.qid || ('idx_' + it.index)), it]));
  (src.items || []).forEach(it => { if (it && it.qid) byQFlat.set(String(it.qid), it); });
  dst.items = Array.from(byQFlat.values());
  rebuildFlatItems(dst);
  if (src.subject && (!dst.subject || String(src.subject).length > String(dst.subject).length)) dst.subject = src.subject;
  // [v24] giữ canon môn sau gộp; hiển thị nhãn chuẩn (Địa lý thay vì Địa lý/Địa lí lẫn lộn)
  if (src.canon && !dst.canon) dst.canon = src.canon;
  if (dst.canon && ruleLabelByKey(dst.canon)) dst.subject = ruleLabelByKey(dst.canon);
  dst.cate = dst.cate || src.cate || null;
  dst.hits = (dst.hits || 0) + (src.hits || 0);
  dst.updated_at = Math.max(dst.updated_at || 0, src.updated_at || 0);
  if (src.olm_user && !dst.olm_user) dst.olm_user = src.olm_user;
  (src.sources || []).forEach(s => { if (dst.sources.indexOf(s) === -1) dst.sources.push(s); });
  return dst;
}
// [v24] Quét một Map kho: gộp mọi entry cùng MÔN (canon key) về 1 thẻ môn duy nhất;
//       entry chưa có canon gộp theo tên môn chuẩn hoá; entry không tên giữ riêng theo cate.
function _coalesceMap(mp) {
  try {
    const groups = new Map();
    for (const [key, e] of mp) {
      if (!e) continue;
      migrateBankEntry(e);
      const ck = entryCanon(e);
      const sn = ck || normBankText(e.subject);
      if (!sn) continue; // entry không có tên môn: giữ nguyên theo cate (fallback cũ)
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
    // [v24] Suy môn từ tên bài tập + nội dung câu đầu, phòng script cũ không gửi subject_name
    const hintText = exerciseTitle + ' ' + (processed || []).slice(0, 15).map(p => p.stem || p.title || '').join(' ');
    const _can = canonSubject(subjectName, hintText);
    // [v25] Không có id_cate lẫn tên môn mà nhận diện được môn → lấy key theo canon, tránh nhiều môn khác nhau dồn vào thẻ 'none'
    if ((!key || key === 'none') && _can.key) key = 'canon::' + _can.key;
    const subjNorm = normBankText(_can.label || subjectName);
    let entry = answerBank.get(key) || null;
    // [v24] Ưu tiên tìm entry theo CANON môn (lý/li gộp chung, môn nhận diện được) -> không tạo thẻ trùng môn
    if (!entry && _can.key) entry = [...answerBank.values()].find(e => e && entryCanon(e) === _can.key) || null;
    // [v23] Fallback: tìm entry theo TÊN MÔN chuẩn hoá (bài tập mới cùng môn, khác id_cate vẫn chung thẻ)
    if (!entry && subjNorm) entry = [...answerBank.values()].find(e => e && normBankText(e.subject) === subjNorm) || null;
    if (!entry) {
      // [v24] Không hồi sinh môn đã bị xoá (tombstone theo key / cate / canon)
      if (tombHas('subject', key) || (meta.id_cate && tombHas('subject', 'cate::' + meta.id_cate)) || (_can.key && tombHas('subject', 'canon::' + _can.key))) return;
      // Chỉ dọn entry RỖNG khi quá tải; tuyệt đối không xoá entry đang có câu hỏi/bài tập (chống mất cột môn cũ)
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
      // Không có đáp án hợp lệ: KHÔNG tạo bài tập rỗng, KHÔNG xoá môn/bài tập đã có (chống mất tab môn/bài tập khi chuyển bài A -> B cùng môn)
      if (createdNew) { answerBank.delete(key); }
      return;
    }
    const exKey = exerciseKeyOf(meta, exerciseTitle);
    if (tombHas('exercise', exKey)) return; // [v24] bài tập đã xoá: không hồi sinh
    let ex = (entry.exercises || []).find(x => x && x.key === exKey);
    if (!ex) {
      ex = { key: exKey, title: exerciseTitle || 'Bài tập chưa rõ tên', cate: meta.id_cate || null, courseware: meta.id_courseware || null, items: [], count: 0, hits: 0, created_at: Date.now(), updated_at: Date.now() };
      entry.exercises.push(ex);
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
    // [v24] Luôn gộp mọi entry cùng môn (canon) về 1 thẻ duy nhất — thêm bài mới không làm tách thẻ/mất thẻ cũ
    coalesceBankSubjects();
    entry.updated_at = Date.now();
    if (sourceKey && entry.sources.indexOf(maskKey(sourceKey)) === -1) entry.sources.push(maskKey(sourceKey));
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

// [v20] LOG bền vững: lưu riêng 1 key KV để không mất khi cold restart/Vercel scale
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
      if (st && st.iosWhitelist) for (const [_k, _v] of Object.entries(st.iosWhitelist)) iosWhitelist.set(_k, _v);
      if (st && Array.isArray(st.realIps)) st.realIps.forEach(x => realIps.add(x));
      if (st && typeof st.dumperGuard === 'boolean') DUMPER_GUARD = st.dumperGuard;
      if (st && typeof st.moduleWatermark === 'boolean') MODULE_WATERMARK = st.moduleWatermark;
      if (st && Array.isArray(st.bannedKeys)) st.bannedKeys.forEach(k => BANNED_KEYS.add(String(k).toUpperCase()));
      if (st && st.olmBans) for (const [k, v] of Object.entries(st.olmBans)) olmBans.set(String(k).toLowerCase(), v);
      // [v24] Nạp danh sách môn/bài tập đã xoá (tombstone) để không hồi sinh sau restart
      if (st && st.bankTombstones) for (const [k, t] of Object.entries(st.bankTombstones)) bankTombstones.set(k, Number(t) || Date.now());
      if (st && st.answers) {
        // [v21] gộp dữ liệu kho cũ về entry theo môn; migrate sang cấu trúc môn -> bài tập -> câu hỏi
        for (const [k, v] of Object.entries(st.answers)) {
          if (!v || typeof v !== 'object') continue;
          migrateBankEntry(v);
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
          });
          const byQFlat = new Map((existing.items || []).map(it => [String(it.qid || ('idx_' + it.index)), it]));
          (v.items || []).forEach(it => { if (it && it.qid) byQFlat.set(String(it.qid), it); });
          existing.items = Array.from(byQFlat.values());
          existing.count = existing.items.length;
          if (v.subject && (!existing.subject || existing.subject.length < v.subject.length)) existing.subject = v.subject;
          existing.updated_at = Math.max(existing.updated_at || 0, v.updated_at || 0);
          rebuildFlatItems(existing);
        }
        // [v24] Gán canon cho entry cũ chưa có; áp tombstones (xoá thật, không hồi sinh); gộp cùng môn về 1 thẻ
        for (const e of answerBank.values()) { if (!e.canon) { const c = canonSubject(e.subject, ''); e.canon = c.key || ''; } }
        applyBankTombstones();
        coalesceBankSubjects();
      }
    }
  } catch (_) {}
}

// [v22] Debounce ghi KV cho luồng tra/kho đáp án nhiều request/giây: gộp mỗi ~3.5s một lần, tránh PUT liên tục làm chậm server
// [v25] Không có KV thì ghi file dự phòng (local/Render), kho đáp án vẫn bền vững qua restart.
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
  if (!KV_ENABLED) { bankFileSave(); return; } // [v25] không KV → ghi file dự phòng
  try {
    // [v24] ĐỌC-MERGE-GHI KV: tránh instance Vercel này ghi đè lên dữ liệu instance khác (chống mất cột môn cũ),
    //       đồng thời áp tombstone để môn/bài tập đã xoá không bị ghi lại khi lưu.
    let remote = null;
    try { const r = await kvRequest('/get/' + KV_KEY); if (r && r.result) remote = JSON.parse(Buffer.from(r.result, 'base64').toString()); } catch (_) {}
    const merged = new Map();
    const ingest = (obj) => {
      for (const [k, v] of Object.entries(obj || {})) {
        if (!v || typeof v !== 'object') continue;
        migrateBankEntry(v); v.key = k;
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
      iosWhitelist: Object.fromEntries(iosWhitelist),
      realIps: Array.from(realIps),
      bannedKeys: Array.from(BANNED_KEYS),
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
    // [v20] mỗi lần lưu state chính, kèm theo flush log xuống KV (không chặn luồng chính)
    kvSaveLogs().catch(() => {});
  } catch (_) {}
}

// [v25] LƯU FILE DỰ PHÒNG KHO ĐÁP ÁN khi server KHÔNG có KV (chạy local/Render):
//       ghi nguyên trạng môn -> bài tập -> câu hỏi + tombstone ra JSON đĩa; restart server không mất cột môn/bài tập.
//       Trên Vercel (FS ephemeral/只读) ghi file lỗi sẽ tự bỏ qua, không làm crash; khi đó dùng KV như thường.
const BANK_FILE = process.env.BANK_FILE || path.join(__dirname, 'godmode_bank.json');
let BANK_FILE_OK = false;
function ingestBankObject(obj, target) {
  for (const [k, v] of Object.entries(obj || {})) {
    if (!v || typeof v !== 'object') continue;
    migrateBankEntry(v); v.key = k;
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
  if (KV_ENABLED) return; // KV là nguồn chính thức khi có
  try {
    if (!fs.existsSync(BANK_FILE)) return;
    const st = JSON.parse(fs.readFileSync(BANK_FILE, 'utf8'));
    if (st && st.bankTombstones) for (const [k, t] of Object.entries(st.bankTombstones)) bankTombstones.set(k, Number(t) || Date.now());
    if (st && st.answers) {
      ingestBankObject(st.answers, answerBank);
      for (const e of answerBank.values()) { if (!e.canon) { const c = canonSubject(e.subject, ''); e.canon = c.key || ''; } }
      applyBankTombstones();
      coalesceBankSubjects();
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
bankFileLoad(); // [v25] nạp kho đáp án từ file dự phòng khi không có KV (giữ nguyên sau restart)

// === iOS WHITELIST helper: thiết bị trong whitelist không bao giờ bị khoá ===
function isIosWhitelisted(ip, hwid) {
  if (hwid && iosWhitelist.has('dev:' + String(hwid))) return true;
  if (ip && iosWhitelist.has('ip:' + String(ip))) return true;
  return false;
}

function isBanned(ip, hwid) {
  // Thiết bị trong iOS whitelist luôn được miễn — bỏ qua mọi ban
  if (isIosWhitelisted(ip, hwid)) return null;
  if (banned.has('ip:' + ip)) return banned.get('ip:' + ip);
  if (hwid && banned.has('dev:' + hwid)) return banned.get('dev:' + hwid);
  return null;
}

function isRealMobileDevice(ip, hwid, uaHeader) {
  if (!SMART_BAN) return false;
  const ua = String(uaHeader || '').toLowerCase();
  if (/android|iphone|ipad|ipod/.test(ua)) return true;
  if (hwid && realDevices.has(String(hwid))) return true;
  if (ip && realIps.has(ip)) return true;
  if (ip) {
    for (const v of realDevices.values()) if (v.ip === ip) return true;
  }
  return false;
}

function autoUnbanIfReal(ip, hwid, uaHeader, reason) {
  if (!SMART_BAN) return false;
  if (!isRealMobileDevice(ip, hwid, uaHeader)) return false;
  if (ip) {
    realIps.add(ip);
    if (ipCache.has(ip)) ipCache.delete(ip);
  }
  let removed = 0;
  if (ip && banned.has('ip:' + ip)) {
    banned.delete('ip:' + ip);
    removed++;
  }
  if (hwid && banned.has('dev:' + String(hwid))) {
    banned.delete('dev:' + String(hwid));
    removed++;
  }
  if (removed > 0) {
    autoUnbanCount += removed;
    kvSaveState();
    adminLog('auto-unban', {
      ip: ip,
      hwid: hwid,
      reason: reason,
      removed: removed,
      total: autoUnbanCount
    });
  }
  return removed > 0;
}

function unlockReal(req, ip, hwid, source) {
  if (!SMART_BAN) return;
  autoUnbanIfReal(ip, hwid, req.headers && req.headers['user-agent'], source);
  softUnbanReal(req, ip, hwid, 'unlock:' + source);
}

function uaIsMobile(uaHeader) {
  // [v26] Nhận diện rộng mọi trình duyệt Android/iOS thật (WebView, in-app, hãng máy) để không chặn nhầm điện thoại
  return /android|iphone|ipad|ipod|harmonyos|huawei|honor|oppo|vivo|xiaomi|redmi|realme|samsung|crios|fxios|mobile safari|wv\)|webview|mobi/i.test(String(uaHeader || '').toLowerCase());
}

function realMobileReq(req, hwid) {
  const ua = req && req.headers ? req.headers['user-agent'] : '';
  if (uaIsMobile(ua)) return true;
  if (hwid && realDevices.has(String(hwid))) return true;
  const ip = req ? getClientIp(req) : '';
  if (ip && realIps.has(ip)) return true;
  return false;
}

function softUnbanReal(req, ip, hwid, reason) {
  if (!SMART_BAN) return false;
  if (!realMobileReq(req, hwid)) return false;
  if (ip) {
    realIps.add(ip);
    if (ipCache.has(ip)) ipCache.delete(ip);
  }
  let removed = 0;
  if (ip && banned.has('ip:' + ip)) {
    banned.delete('ip:' + ip);
    removed++;
  }
  if (hwid && banned.has('dev:' + String(hwid))) {
    banned.delete('dev:' + String(hwid));
    removed++;
  }
  if (removed > 0) {
    autoUnbanCount += removed;
    kvSaveState();
    adminLog('auto-unban-v17', {
      ip: ip,
      hwid: hwid,
      reason: reason,
      removed: removed
    });
  }
  return true;
}

function guardBanned(req, res, ip, hwid, label) {
  // [v26] Thiết bị Android/iOS thật luôn được đi qua (tự gỡ ban mềm), không chặn nhầm điện thoại thật
  if (realMobileReq(req, hwid)) { softUnbanReal(req, ip, hwid, 'guard-real:' + label); return false; }
  if (softUnbanReal(req, ip, hwid, 'guard:' + label)) return false;
  const b = isBanned(ip, hwid);
  if (!b) return false;
  res.status(403).json({
    success: false,
    blocked: true,
    message: 'Thiết bị/IP đang bị khoá (' + (b.reason || label) + ') — thiết bị thật Android/iOS sẽ tự mở khoá ở request kế tiếp.',
    reason: b.reason || ''
  });
  return true;
}

function keyBlocked(req, res, key, ip, hwid, deviceName, label) {
  if (!isKeyBanned(key)) return false;
  if (realMobileReq(req, hwid)) {
    adminLog('key-blocked-real-soft', {
      key: maskKey(key),
      ip: ip,
      hwid: hwid,
      label: label
    });
    res.status(401).json({
      success: false,
      message: 'Key đã bị thu hồi (dump/rò rỉ) — liên hệ admin để cấp key mới.',
      reason: 'key_revoked'
    });
    return true;
  }
  addBan(ip, hwid, 'key revokle (' + label + ')', deviceName || '');
  res.status(404).json({
    error: 'Not found'
  });
  return true;
}

function addBan(ip, hwid, reason, deviceName) {
  // Nếu thiết bị trong iOS whitelist → không bao giờ ban
  if (isIosWhitelisted(ip, hwid)) {
    adminLog('ban-blocked-whitelist', {
      ip: ip,
      hwid: hwid,
      reason: reason,
      device: deviceName || '',
      note: 'iOS WHITELIST: thiết bị được miễn khoá vĩnh viễn'
    });
    return;
  }
  if (SMART_BAN && isRealMobileDevice(ip, hwid, recentUaByIp.get(ip) || '')) {
    autoUnbanIfReal(ip, hwid, '', 'addBan-attempt-on-real-device');
    adminLog('ban-blocked-real', {
      ip: ip,
      hwid: hwid,
      reason: reason,
      device: deviceName || '',
      note: 'SMART_BAN: thiet bi di dong that, KHONG ban'
    });
    return;
  }
  if (!SMART_BAN && SAFE_MODE) {
    adminLog('ban-soft', {
      ip: ip,
      hwid: hwid,
      reason: reason,
      device: deviceName || '',
      note: 'SAFE_MODE: khong ban cung, chi tu choi'
    });
    return;
  }
  if (ip) banned.set('ip:' + ip, {
    reason: reason,
    device: deviceName || '',
    t: Date.now(),
    by: 'auto'
  });
  if (hwid) banned.set('dev:' + hwid, {
    reason: reason,
    device: deviceName || '',
    t: Date.now(),
    by: 'auto',
    ip: ip
  });
  kvSaveState();
  adminLog('ban', {
    ip: ip,
    hwid: hwid,
    reason: reason,
    device: deviceName || ''
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
  return; // [v19] auto-lock theo "phần mềm lạ" đã gỡ bỏ
  // Thiết bị trong iOS whitelist → bỏ qua lock-report hoàn toàn
  if (isIosWhitelisted(ip, hwid)) {
    adminLog('lock-report-skipped-whitelist', {
      hwid: hwid || 'unknown',
      ip: ip,
      reason: reason,
      note: 'iOS WHITELIST: bỏ qua lock-report'
    });
    return;
  }
  const now = Date.now();
  const existing = lockedScripts.get(hwid || 'unknown');
  lockedScripts.set(hwid || 'unknown', Object.assign({}, existing || {}, {
    hwid: hwid || 'unknown',
    ip: ip || existing && existing.ip || '',
    device: device || existing && existing.device || '',
    reason: reason || existing && existing.reason || '',
    keyMasked: keyMasked || existing && existing.keyMasked || '',
    olm_user: olm_user || existing && existing.olm_user || '',
    status: 'locked',
    t: existing && existing.t || now,
    lastSeen: now
  }));
  kvSaveState();
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

const ADMIN_LOG = [];

const ADMIN_LOG_MAX = 35; // [v23] Chỉ lưu vĩnh viễn 35 bản ghi log mới nhất (cả bộ nhớ lẫn KV bền vững)

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

// === [v20] LOG BỀN VỮNG: merge với KV, không mất khi restart/cold start ===
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

// FIX #8: cap rateBuckets to prevent unbounded memory growth under botnet attack.
const RATE_BUCKETS_MAX = 50000;

function rateLimit(key, max, windowMs) {
  const now = Date.now();
  // If map is at capacity and this is a new key, evict oldest entry before inserting.
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
  // Sweep keyFail/realDevices/realIps để tránh phình bộ nhớ do IP/HWID xoay vòng
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

// ENHANCE #1: extended honeypot — catches more common scanner / botnet probe paths.
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
  '/.well-known/security.txt' // allow this one? — keeping it out is fine since we have no program
];
// Note: add any additional paths via env EXTRA_HONEYPOT (comma-separated) if needed.

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
  const isLoopback = ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';
  if (isBanned(ip, req.headers['x-hwid'])) {
    if (!autoUnbanIfReal(ip, req.headers['x-hwid'], req.headers['user-agent'], 'middleware-banned-real-device') && !softUnbanReal(req, ip, req.headers['x-hwid'], 'middleware-banned-real-device-v17')) {
      return res.status(403).json({
        success: false,
        error: 'Not found',
        message: 'Thiết bị/IP đang bị khoá — thiết bị thật sẽ tự mở khoá ở request kế tiếp.'
      });
    }
  }
  const p = req.path;
  if (HONEYPOT_PATHS.some(h => p === h || p.startsWith(h + '/'))) {
    // FIX #4: also ban HWID when present so bots can't dodge by rotating IPs.
    const hwidHoneypot = req.headers['x-hwid'] || null;
    if (!isLoopback && AUTO_BAN) addBan(ip, hwidHoneypot, 'honeypot-scan:' + p, '');
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

setInterval(() => {
  if (!SMART_BAN) return;
  const realIps = new Set;
  for (const v of realDevices.values()) realIps.add(v.ip);
  let removed = 0;
  for (const k of [ ...banned.keys() ]) {
    let isReal = false;
    if (k.startsWith('ip:')) {
      const ip = k.slice(3);
      if (realIps.has(ip)) {
        isReal = true;
        ipCache.delete(ip);
      }
    } else if (k.startsWith('dev:')) {
      if (realDevices.has(k.slice(4))) isReal = true;
    }
    if (isReal) {
      banned.delete(k);
      removed++;
    }
  }
  if (removed > 0) {
    autoUnbanCount += removed;
    kvSaveState();
    adminLog('auto-unban-sweep', {
      removed: removed,
      total: autoUnbanCount,
      realDevices: realDevices.size
    });
  }
}, 5 * 60 * 1e3).unref();

function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function verifyReqSig(req) {
  if (!REQ_SIGN) return true;
  const ts = req.headers['x-ts'], nonce = req.headers['x-nonce'], sign = req.headers['x-sign'];
  if (!ts || !nonce || !sign) {
    // FIX #2: When REQ_SIGN is active, missing signature headers = REJECT.
    // Previously returned true (bypass). Botnets could omit headers to skip signing.
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

// === SMART FAKE-REQ CHECK v2: iOS + Android thật không bị chặn ===
// iOS Safari / Firefox (fxios) đôi khi không thể ký request (SubtleCrypto sandbox),
// Android thật đã hoạt động. Thiết bị thật được nhận ra qua UA + iOS whitelist.
app.use((req, res, next) => {
  if (req.method === 'POST' && req.path.startsWith(API_PREFIX)) {
    if (!verifyReqSig(req)) {
      FAKE_REQ_COUNT++;
      const ip = getClientIp(req);
      const ua = String(req.headers['user-agent'] || '');
      const hwid = req.headers['x-hwid'] || null;

      // Ưu tiên 1: Thiết bị trong iOS whitelist — không bao giờ chặn
      if (isIosWhitelisted(ip, hwid)) {
        adminLog('nosign-whitelist', { ip: ip, path: req.path, ua: ua.slice(0, 80) });
        FAKE_REQ_COUNT--;
        return next();
      }

      // Ưu tiên 2: UA là Android/iOS thật — cho qua, log nhẹ, không ban
      // (iOS Violentmonkey/Firefox đôi khi fail ký do SubtleCrypto sandbox)
      if (uaIsMobile(ua)) {
        adminLog('nosign-mobile', { ip: ip, path: req.path, ua: ua.slice(0, 80) });
        FAKE_REQ_COUNT--;
        // Vẫn áp dụng unlock cho thiết bị thật đã biết
        unlockReal(req, ip, hwid, 'nosign-mobile');
        return next();
      }

      // Desktop / bot / scanner → chặn và ban như cũ
      adminLog('fake-req', {
        ip: ip,
        path: req.path,
        ua: ua.slice(0, 80)
      });
      // ENHANCE #3: auto-ban IPs that repeatedly send unsigned/forged requests.
      if (AUTO_BAN && !isLoopbackIp(ip) && !rateLimit('fakereq:' + ip, 5, 6e4)) {
        addBan(ip, null, 'fake-req spam (>5 bad sigs/min)', '');
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
  // FIX #6a: reduce global limit 300 → 90 req/min to cut botnet capacity.
  if (!rateLimit('g:' + ip, 90, 6e4)) {
    adminLog('ratelimit-global', {
      ip: ip,
      path: req.path,
      ua: String(req.headers['user-agent'] || '').slice(0, 50)
    });
    if (AUTO_BAN && !isLoopbackIp(ip)) addBan(ip, null, 'rate-limit-global (>90/min)', '');
    return res.status(429).json({
      error: 'Too many requests'
    });
  }
  // FIX #6b: burst detection — block IPs hitting >10 req in 2s (botnet spray pattern).
  if (!rateLimit('burst:' + ip, 10, 2e3)) {
    adminLog('ratelimit-burst', {
      ip: ip,
      path: req.path,
      ua: String(req.headers['user-agent'] || '').slice(0, 50)
    });
    if (AUTO_BAN && !isLoopbackIp(ip)) addBan(ip, null, 'burst-flood (>10 req/2s)', '');
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
  const hit = ipCache.get(ip);
  if (hit && hit.expire > Date.now() && hit.info && hit.info.risk === 'high' && hit.info.isDC && hit.info.isVPN) {
    if (uaIsMobile(req.headers['user-agent']) || SMART_BAN && isRealMobileDevice(ip, null, req.headers['user-agent'])) {
      autoUnbanIfReal(ip, null, req.headers['user-agent'], 'dc-cache-real-mobile');
      softUnbanReal(req, ip, null, 'dc-cache-real-mobile-v17');
      adminLog('dc-skip-real', {
        ip: ip,
        org: hit.info.org || ''
      });
      return next();
    }
    addBan(ip, null, 'IP datacenter/proxy goi API (HARD_DC_BAN) — ' + (hit.info.org || ''), '');
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
  if (BAD_UA.some(k => ua.includes(k))) return true;
  if (EMU_MARKERS.some(k => ua.includes(k))) return true;
  return false;
}

function isMobileUA(uaHeader) {
  // [v26] Rộng hơn cho cổng BLOCK_VM_SCRIPT: bao gồm WebView/wv và hãng Trung Quốc
  const ua = String(uaHeader || '').toLowerCase();
  return /android|iphone|ipad|ipod|harmonyos|huawei|honor|oppo|vivo|xiaomi|redmi|realme|samsung|crios|fxios|wv\)|webview|mobi/.test(ua);
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
  const uaMobile = /android|iphone|ipad|ipod|harmonyos/i.test(ua);
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
  const isIOS = /iphone|ipad|ipod/i.test(ua);
  // iOS: iPad desktop-mode báo platform 'MacIntel' là bình thường — KHÔNG tính điểm phạt
  // Chỉ phạt nếu platform rõ ràng là Windows/Linux desktop (không phải Mac/iPad)
  if (isIOS && /^win/i.test(platform)) {
    score += 1;
    softReason = softReason || 'platform iOS khai báo Windows — bất thường';
  }
  if (isAndroid && /win|mac|linux/.test(platform) && !/android/.test(platform)) {
    score += 1;
    softReason = softReason || 'platform không khớp Android (thường là Linux armv8l)';
  }
  // iOS vendor: Safari trên iOS thật đôi khi báo vendor rỗng hoặc 'Apple Computer, Inc.' — chỉ phạt nhẹ
  if (isIOS && vendor && vendor.length > 0 && !vendor.includes('apple')) {
    score += 1; // Giảm từ 2 → 1 để tránh false positive
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
  if (cores && cores < 2) {
    score += 1;
    softReason = softReason || 'CPU bất thường';
  }
  const scr = dev.screen || fp && fp.screen || '';
  const sm = String(scr).match(/(\d+)x(\d+)/);
  const w = sm ? parseInt(sm[1], 10) : 0;
  // iOS thật: iPhone 15 Pro Max có độ phân giải 2796px, iPad Pro 2048px → nâng giới hạn
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
  // FIX #5: raise iteration count from 1,000 → 100,000 (NIST SP 800-132 baseline).
  // FIX: ép kiểu chuỗi để không ném lỗi khi token rỗng/undefined (legacy no-session).
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
  // [v26] Nâng trần 8 → 100 lần/giờ; điện thoại thật được bỏ chặn ở route để dùng bình thường
  if (arr.length >= 100) {
    FIRE_ATTACK_COUNT++;
    return false;
  }
  arr.push(now);
  fireUsage.set(key, arr);
  return true;
}

function requireSession(req, res) {
  const token = req.headers['x-session'];
  if (!token) {
    adminLog('legacy-no-session', {
      path: req.path,
      ip: getClientIp(req)
    });
    req._sess = null;
    req._token = null;
    return true;
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

// [v22] Trích xuất ĐỀ CÂU HỎI (stem) để lưu kèm đáp án; file TXT tải về hiển thị cả câu hỏi + đáp án
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

function buildFirePayload({raw_questions: raw_questions, meta: meta, video_length: video_length}, mode, timeStr, grade, targetScore) {
  const timeParts = (timeStr || '10.00').split('.');
  const userMins = parseInt(timeParts[0]) || 0;
  let userSecsStr = timeParts[1] || '0';
  if (userSecsStr.length === 1) userSecsStr += '0';
  const userSecs = parseInt(userSecsStr.substring(0, 2));
  let calcSeconds = userMins * 60 + userSecs;
  if (calcSeconds < 30) calcSeconds = 120;
  const totalPackages = raw_questions.length;
  // === TARGET SCORE (7–10đ) ===
  const tgtScore = Math.min(10, Math.max(7, parseFloat(targetScore) || 10));
  const tgtRatio = tgtScore / 10;
  const tgtCorrectCount = Math.round(totalPackages * tgtRatio);
  const wrongSet = new Set();
  for (let wi = tgtCorrectCount; wi < totalPackages; wi++) wrongSet.add(wi);
  const isExam = mode === 'exam', isVideo = mode === 'video';
  const now = Math.floor(Date.now() / 1e3);
  let totalSeconds, timeInit;
  if (isVideo || isExam) {
    totalSeconds = calcSeconds;
    timeInit = now - totalSeconds;
  } else {
    totalSeconds = totalPackages * 15;
    timeInit = now - totalSeconds;
  }
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
    if (!isVideo) {
      params.append('quiz_list[]', q.id || q._id);
      params.append(`score_list[${q.id || q._id}]`, final_score);
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
            // Tạo đáp án sai tương ứng với từng loại câu
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
        a_params_arr.push(JSON.stringify(sq.ans));
      });
      fakeLog.push({
        q_params: JSON.stringify(q_params_arr),
        a_params: JSON.stringify(a_params_arr),
        result: makeWrong ? 0 : 1,
        correct: makeWrong ? 0 : 1,
        wrong: makeWrong ? 1 : 0,
        a_index: i,
        time_spent: Math.floor(Math.random() * 15) + 10
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

function proxyVerify(key, hwid, olmUser) {
  return new Promise(resolve => {
    const postData = JSON.stringify({
      key: key,
      app: APP_ID,
      device: hwid || 'unknown',
      olm_user: olmUser || ''
    });
    const opts = {
      hostname: 'keyvault-vn.onrender.com',
      port: 443,
      path: '/api/verify',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData)
      },
      timeout: 15e3
    };
    const req = https.request(opts, res => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => {
        if (res.statusCode !== 200) return resolve({
          success: false,
          message: `KeyVault lỗi HTTP ${res.statusCode}: ${raw.slice(0, 120) || 'không phản hồi'}`
        });
        try {
          const kv = JSON.parse(raw);
          resolve({
            success: kv.success !== undefined ? !!kv.success : !!kv.valid,
            message: kv.message || kv.reason || (kv.valid === false ? 'Key không hợp lệ (KeyVault từ chối)' : ''),
            type: kv.type || kv.plan || kv.level || '',
            expires_at: kv.expires_at || kv.exp || kv.expire || ''
          });
        } catch (_) {
          resolve({
            success: false,
            message: `KeyVault trả về không phải JSON (có thể đang khởi động): ${raw.slice(0, 80)}`
          });
        }
      });
    });
    req.on('error', e => resolve({
      success: false,
      message: 'Lỗi kết nối KeyVault: ' + e.message
    }));
    req.on('timeout', () => {
      req.destroy();
      resolve({
        success: false,
        message: 'KeyVault timeout (server đang ngủ — thử lại)'
      });
    });
    req.write(postData);
    req.end();
  });
}

app.get('/', (_req, res) => res.json({
  ok: true,
  t: Date.now()
}));

app.get(API_PREFIX + '/ping', (req, res) => {
  // FIX #7: add rate limit to /ping to prevent scanner/amplification abuse.
  const ip = getClientIp(req);
  if (!isLoopbackIp(ip) && !rateLimit('ping:' + ip, 20, 6e4)) {
    return res.status(429).json({ error: 'Too many requests' });
  }
  res.json({ ok: true, t: Date.now() });
});

app.get(API_PREFIX + '/bootstrap.js', async (req, res) => {
  const ip = getClientIp(req);
  unlockReal(req, ip, null, 'bootstrap.js');
  if (guardBanned(req, res, ip, null, 'bootstrap.js')) return;
  if (!rateLimit('boot:' + ip, 60, 6e4)) return res.status(429).json({
    error: 'Too many requests'
  });
  if (isBadUA(req.headers['user-agent'])) {
    adminLog('badua-block', {
      ip: ip,
      path: 'bootstrap.js',
      ua: String(req.headers['user-agent'] || '').slice(0, 60)
    });
    return res.status(404).json({
      error: 'Not found'
    });
  }
  const pBoot = await checkProxyIp(ip);
  if (HARD_DC_BAN && pBoot.risk === 'high' && pBoot.isDC && pBoot.isVPN && !(uaIsMobile(req.headers['user-agent']) || SMART_BAN && isRealMobileDevice(ip, null, req.headers['user-agent']))) {
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
  if (BLOCK_VM_SCRIPT && !isMobileUA(req.headers['user-agent'])) { // [v26] chỉ chặn VM/proxy/desktop; Android/iOS thật (kể cả WebView/mạng lạ) luôn kéo được code
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
    const payload = bootstrapEncrypt(src);
    adminLog('bootstrap', {
      ip: ip,
      ua: String(req.headers['user-agent'] || '').slice(0, 80),
      bytes: src.length
    });
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
  unlockReal(req, ip, null, 'kv-payload.js');
  if (guardBanned(req, res, ip, null, 'kv-payload.js')) return;
  if (!rateLimit('kvp:' + ip, 40, 6e4)) return res.status(429).send('/* too many requests */');
  if (isBadUA(req.headers['user-agent'])) {
    adminLog('badua-block', {
      ip: ip,
      path: 'kv-payload.js',
      ua: String(req.headers['user-agent'] || '').slice(0, 60)
    });
    return res.status(404).send('/* not found */');
  }
  const pKvp = await checkProxyIp(ip);
  if (HARD_DC_BAN && pKvp.risk === 'high' && pKvp.isDC && pKvp.isVPN && !(uaIsMobile(req.headers['user-agent']) || SMART_BAN && isRealMobileDevice(ip, null, req.headers['user-agent']))) {
    addBan(ip, null, 'IP datacenter/proxy keo kv-payload.js (HARD_DC_BAN v11) — ' + (pKvp.org || ''), '');
    adminLog('dc-ban', {
      ip: ip,
      path: 'kv-payload.js',
      org: pKvp.org || ''
    });
    return res.status(404).send('/* not found */');
  }
  if (BLOCK_VM_SCRIPT && !isMobileUA(req.headers['user-agent'])) { // [v26] mobile thật luôn được phép
    adminLog('vm-smart-block', {
      ip: ip,
      path: 'kv-payload.js',
      ua: String(req.headers['user-agent'] || '').slice(0, 60),
      isDC: !!pKvp.isDC
    });
    return res.status(404).send('/* not found */');
  }
  try {
    adminLog('kv-payload-deprecated', {
      ip: ip,
      ua: String(req.headers['user-agent'] || '').slice(0, 80)
    });
    res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.send('/* v19: legacy payload disabled — code no longer served here */');
  } catch (err) {
    console.error('[/kv-payload.js]', err);
    res.status(500).send('/* server error */');
  }
});

app.get(API_PREFIX + '/loader.user.js', async (req, res) => {
  const ip = getClientIp(req);
  unlockReal(req, ip, null, 'loader.user.js');
  if (guardBanned(req, res, ip, null, 'loader.user.js')) return;
  if (!rateLimit('ldr:' + ip, 30, 6e4)) return res.status(429).send('// too many requests');
  if (isBadUA(req.headers['user-agent'])) {
    adminLog('badua-block', {
      ip: ip,
      path: 'loader.user.js',
      ua: String(req.headers['user-agent'] || '').slice(0, 60)
    });
    return res.status(404).send('// not found');
  }
  const pLdr = await checkProxyIp(ip);
  if (HARD_DC_BAN && pLdr.risk === 'high' && pLdr.isDC && pLdr.isVPN && !(uaIsMobile(req.headers['user-agent']) || SMART_BAN && isRealMobileDevice(ip, null, req.headers['user-agent']))) {
    addBan(ip, null, 'IP datacenter/proxy keo loader.user.js (HARD_DC_BAN v11) — ' + (pLdr.org || ''), '');
    adminLog('dc-ban', {
      ip: ip,
      path: 'loader.user.js',
      org: pLdr.org || ''
    });
    return res.status(404).send('// not found');
  }
  if (BLOCK_VM_SCRIPT && !isMobileUA(req.headers['user-agent'])) { // [v26] mobile thật luôn được phép
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
  unlockReal(req, ip, req.body && req.body.hwid || null, 'route');
  if (guardBanned(req, res, ip, req.body && req.body.hwid || null, 'api')) return;
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
  const result = await proxyVerify(key, hwid, olm_user);
  if (!result.success) {
    if (recordKeyFail(ip) && AUTO_BAN && !isLoopbackIp(ip)) addBan(ip, null, 'brute-force key (>=10 sai/10 phut)', '');
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
  res.json(result);
});

app.post(API_PREFIX + '/attest', async (req, res) => {
  const ip = getClientIp(req);
  const {key: key, hwid: hwid, fp: fp, device: device} = req.body || {};
  unlockReal(req, ip, hwid, 'attest');
  if (guardBanned(req, res, ip, hwid, 'attest')) return;
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
  if (!rateLimit('attest:' + ip + '|' + (hwid || ''), 30, 6e4)) return res.status(429).json({
    success: false,
    message: 'Quá nhiều lần xác thực'
  });
  const v = validateDevice(fp, device, req.headers['user-agent']);
  if (!v.ok) {
    if (realMobileReq(req, hwid)) {
      // [v26] Điện thoại thật: chỉ ghi log mềm, KHÔNG 403 — đảm bảo mọi Android/iOS đều dùng được
      adminLog('reject-soft-mobile', {
        ip: ip,
        hwid: hwid,
        device: v.deviceName,
        reason: v.reason
      });
    } else {
      if (v.ban && AUTO_BAN && !isLoopbackIp(ip)) addBan(ip, hwid, v.reason, v.deviceName);
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
    autoUnbanIfReal(ip, hwid, req.headers['user-agent'], 'attest-real-mobile');
  }
  const p = await checkProxyIp(ip);
  if (p.risk === 'high') {
    if (HARD_DC_BAN && p.isDC && p.isVPN && !(uaIsMobile(req.headers['user-agent']) || SMART_BAN && isRealMobileDevice(ip, hwid, req.headers['user-agent']))) {
      addBan(ip, hwid, 'proxy/VPN/datacenter + IP datacenter (HARD_DC_BAN)', v.deviceName);
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
  const kv = await proxyVerify(key, hwid);
  if (!kv.success) {
    if (recordKeyFail(ip) && AUTO_BAN && !isLoopbackIp(ip)) addBan(ip, hwid, 'brute-force key (10 lần sai)', v.deviceName);
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
    connectorVersion: CONNECTOR_MODULE_VERSION
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
  unlockReal(req, ip, req.body && req.body.hwid || null, 'route');
  if (guardBanned(req, res, ip, req.body && req.body.hwid || null, 'api')) return;
  if (!requireSession(req, res)) return;
  if (!rateLimit('ip:' + ip + '|' + (req.body && req.body.hwid || ''), 30, 6e4)) return res.status(429).json({
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

app.post(API_PREFIX + '/fire', async (req, res) => {
  const ip = getClientIp(req);
  unlockReal(req, ip, req.body && req.body.hwid || null, 'route');
  if (guardBanned(req, res, ip, req.body && req.body.hwid || null, 'api')) return;
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
  if (!Array.isArray(session.raw_questions) || session.raw_questions.length === 0) return res.status(400).json({
    success: false,
    message: 'raw_questions rỗng!'
  });
  if (session.raw_questions.length > LIMITS.questions) return res.status(413).json({
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
    raw_questions: session.raw_questions.filter(q => q && typeof q === 'object').slice(0, LIMITS.questions),
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
  unlockReal(req, ip, hwid0, 'answers-lookup');
  if (guardBanned(req, res, ip, hwid0, 'bank')) return;
  if (!requireSession(req, res)) return;
  if (!rateLimit('bank:' + ip + '|' + (hwid0 || ''), 30, 6e4)) return res.status(429).json({ success: false, message: 'Quá nhiều yêu cầu tra kho (IP)' });
  const { key: key, hwid: hwid, cate: cate, courseware: courseware, olm_user: olm_user, subject: subject, exercise_title: exercise_title } = req.body || {};
  if (!key) return res.status(401).json({ success: false, message: 'Missing key' });
  const kv = await proxyVerify(key, hwid);
  if (!kv.success) return res.status(401).json({ success: false, message: kv.message || 'Invalid key' });
  const c = safeStr(cate, 80);
  const cw = safeStr(courseware, 80);
  const subj = safeStr(subject, 120);
  const exTitle = safeStr(exercise_title, 300);
  let entry = null;
  if (c) entry = answerBank.get(c) || null;
  // [v23] Sau gộp theo tên môn: entry có thể không còn giữ key = id_cate → dò thêm trong cate của từng bài tập
  if (!entry && c) entry = [...answerBank.values()].find(e => String(e.cate || '') === c || (e.exercises || []).some(ex => String(ex.cate || '') === c)) || null;
  if (!entry && subj) {
    const sc = canonSubject(subj, '');
    entry = [...answerBank.values()].find(e => sc.key && entryCanon(e) === sc.key)
         || [...answerBank.values()].find(e => normBankText(e.subject) === normBankText(subj)) || null;
  }
  if (!entry) return res.json(rotateSession(req, { success: true, found: false, cate: c || null, subject: subj || null, count: 0, items: [], exercises: [] }));
  migrateBankEntry(entry);
  entry.hits = (entry.hits || 0) + 1;
  entry.last_lookup_at = Date.now();
  let targetEx = null;
  // [v26] Ưu tiên khớp ĐÚNG bài tập đang mở: (1) id_cate của bài, (2) id_courseware, (3) tên bài tương đồng
  if (c) targetEx = (entry.exercises || []).find(ex => String(ex.cate || '') === c) || null;
  if (!targetEx && cw) targetEx = (entry.exercises || []).find(ex => String(ex.courseware || '') === cw) || null;
  if (exTitle) {
    const tn = normBankText(exTitle);
    if (!targetEx) targetEx = (entry.exercises || []).find(ex => {
      const en = normBankText(ex.title);
      return en === tn || (tn && en && (en.includes(tn) || tn.includes(en)));
    }) || null;
  }
  if (targetEx) { targetEx.hits = (targetEx.hits || 0) + 1; targetEx.last_lookup_at = Date.now(); }
  scheduleBankSave();
  // [v26] items trả về = chính bài tập đang mở; chỉ khi không khớp bài nào mới fallback cả môn (tương thích bản cũ)
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
  res.json(rotateSession(req, {
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
  }));
});

app.post(API_PREFIX + '/code', async (req, res) => {
  const ip = getClientIp(req);
  unlockReal(req, ip, req.body && req.body.hwid || null, 'route');
  if (guardBanned(req, res, ip, req.body && req.body.hwid || null, 'api')) return;
  if (!requireSession(req, res)) return;
  if (!rateLimit('code:' + ip + '|' + (req.body && req.body.hwid || ''), 10, 6e4)) return res.status(429).json({
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
  unlockReal(req, ip, req.body && req.body.hwid || null, 'route');
  if (guardBanned(req, res, ip, req.body && req.body.hwid || null, 'api')) return;
  if (!rateLimit('hb:' + ip + '|' + (req.body && req.body.hwid || ''), 30, 6e4)) return res.status(429).json({
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
    if (realMobileReq(req, hwid)) {
      // [v26] Điện thoại thật: ghi log mềm, không chặn nhịp tim
      adminLog('heartbeat-soft-mobile', {
        ip: ip,
        hwid: hwid,
        device: v.deviceName,
        reason: v.reason
      });
    } else {
      if (v.ban && AUTO_BAN && !isLoopbackIp(ip)) addBan(ip, hwid, 'heartbeat: ' + v.reason, v.deviceName);
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
    autoUnbanIfReal(ip, hwid, req.headers['user-agent'], 'heartbeat-real-mobile');
  }
  const p = await checkProxyIp(ip);
  if (p.risk === 'high') {
    if (HARD_DC_BAN && p.isDC && p.isVPN && !(uaIsMobile(req.headers['user-agent']) || SMART_BAN && isRealMobileDevice(ip, hwid, req.headers['user-agent']))) {
      addBan(ip, hwid, 'heartbeat: proxy/VPN/datacenter + IP datacenter (HARD_DC_BAN)', v.deviceName);
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
    adminLog('heartbeat-block', {
      ip: ip,
      hwid: hwid,
      reason: 'key thu hồi/hết hạn',
      message: kv.message || ''
    });
    return res.status(403).json({
      blocked: true,
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
    connectorVersion: CONNECTOR_MODULE_VERSION
  };
  const cv = parseInt(clientVersion, 10) || 0;
  if (cv === 0 && parseInt((req.body && req.body.connectorVersion) || '0', 10) === 0) {
    const dj0 = dumperJudge(key, hwid, ip, v.deviceName, 'heartbeat-zero');
    if (dj0) {
      if (realMobileReq(req, hwid)) {
        adminLog('dumper-zero-soft-mobile', {
          key: maskKey(key),
          ip: ip,
          hwid: hwid,
          reason: dj0
        });
      } else {
        addKeyBan(key, dj0, ip, hwid, v.deviceName);
        return res.status(403).json({
          blocked: true,
          reason: 'dumper',
          message: 'Phát hiện dumper — key & thiết bị đã bị khoá vĩnh viễn'
        });
      }
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

  // === iOS Whitelist: bỏ qua lock-report hoàn toàn, trả ok ngay để script không bị treo ===
  if (isIosWhitelisted(ip, hwid)) {
    res.json({ ok: true, t: Date.now(), _wl: 1 });
    return;
  }

  // [v19] detection removed: không tự ghi khoá thiết bị qua lock-report
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
  // Thiết bị trong iOS whitelist luôn trả về không bị khoá (check cả IP lẫn HWID)
  if (isIosWhitelisted(ip, hwid)) return res.json({ locked: false, t: Date.now(), _wl: 1 });
  const rec = hwid ? lockedScripts.get(hwid) : null;
  if (rec) {
    rec.lastSeen = Date.now();
    if (ip) rec.ip = ip;
    // Nếu IP hiện tại (có thể mới) đã nằm trong whitelist thì coi như unlock
    if (isIosWhitelisted(rec.ip, hwid)) {
      rec.status = 'unlocked';
      rec.unlockedAt = Date.now();
      kvSaveState();
      return res.json({ locked: false, t: Date.now(), _wl: 1 });
    }
  }
  const locked = !!(rec && rec.status === 'locked' && rec.lockedBy === 'admin');
  res.json({
    locked: locked,
    reason: locked ? rec.reason || '' : '',
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
  // ENHANCE #2: block datacenter/proxy IPs from admin login to stop remote brute-force botnets.
  if (!isLoopbackIp(ip) && HARD_DC_BAN) {
    const pAdmin = await checkProxyIp(ip);
    if (pAdmin.risk === 'high' && pAdmin.isDC) {
      adminLog('admin-login-dc-block', { ip, org: pAdmin.org || '' });
      return res.status(403).send(adminLoginPage('Truy cập từ IP datacenter/proxy bị từ chối.'));
    }
  }
  const now = Date.now();
  const arr = (adminLogins.get(ip) || []).filter(t => now - t < 10 * 6e4);
  if (arr.length >= 5) {
    if (AUTO_BAN && !isLoopbackIp(ip)) addBan(ip, null, 'brute-force admin login', '');
    return res.status(429).send(adminLoginPage('Quá nhiều lần thử sai — IP đã bị khoá.'));
  }
  arr.push(now);
  adminLogins.set(ip, arr);
  const {username: username, password: password} = req.body || {};
  if (username === ADMIN_USER && verifyPass(password, ADMIN_HASH)) {
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
  res.status(401).send(adminLoginPage('Sai tài khoản hoặc mật khẩu!'));
});

app.get(ADMIN_PATH + '/logout', (req, res) => {
  const tok = _parseCookies(req)['god_admin'];
  if (tok) adminSessions.delete(tok);
  // FIX #3: Path must match the path used at Set-Cookie time so the browser actually clears it.
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
  const banRows = [ ...banned.entries() ].slice(0, 50).map(([k, v]) => `<tr>\n<td style="font-family:monospace;font-size:11px">${_esc(k)}</td>\n<td style="font-size:11px">${_esc(v.device || '')}</td>\n<td style="font-size:11px;color:#ef233c">${_esc(v.reason || '')}</td>\n<td style="font-size:10px;color:#8b949e">${_esc(new Date(v.t || 0).toLocaleString('vi-VN'))}</td>\n<td><form method="POST" action="${ADMIN_PATH}/unban" style="display:inline"><input type="hidden" name="key" value="${_esc(k)}"><button style="padding:4px 10px;font-size:10px;margin:0" class="danger">MỞ KHOÁ</button></form></td>\n</tr>`).join('');
  const devRows = [ ...devices.entries() ].slice(0, 50).map(([hwid, d]) => `<tr>\n<td style="font-family:monospace;font-size:11px">${_esc(hwid)}</td>\n<td style="font-size:11px;color:#00f2fe">${_esc(d.name || '')}</td>\n<td style="font-size:10px">${_esc(d.os || '')} ${_esc(d.model || '')}</td>\n<td style="font-size:10px">${_esc(d.ip || '')}</td>\n<td style="font-size:10px;color:#8b949e">${_esc(new Date(d.lastSeen || 0).toLocaleString('vi-VN'))}</td>\n</tr>`).join('');
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">\n<title>Dashboard — GOD MODE Admin v4</title><style>\n*{box-sizing:border-box}body{margin:0;background:#0d1117;font-family:'Segoe UI',system-ui,sans-serif;color:#c9d1d9;padding:20px}\n.wrap{max-width:1150px;margin:0 auto}\n.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:8px}\nh1{font-size:20px;margin:0;background:linear-gradient(90deg,#00f2fe,#4facfe);-webkit-background-clip:text;-webkit-text-fill-color:transparent}\na.logout{color:#ef233c;text-decoration:none;font-size:12px;border:1px solid rgba(239,35,60,.4);padding:6px 12px;border-radius:6px}\n.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:16px}\n.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:14px}\n.card .lbl{font-size:10px;color:#8b949e;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px}\n.card .val{font-size:14px;font-weight:700;font-family:monospace;color:#00f2fe;word-break:break-all}\n.card .val.ok{color:#00e676}.card .val.bad{color:#ef233c}\n.panel{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;margin-bottom:16px}\n.panel h2{font-size:13px;margin:0 0 12px;color:#4facfe;text-transform:uppercase;letter-spacing:1px}\nform.inline{display:flex;gap:8px;flex-wrap:wrap;align-items:center}\ninput{padding:9px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#00f2fe;font-family:monospace;font-size:12px;outline:none;min-width:160px}\nbutton{padding:9px 16px;border:none;border-radius:6px;background:linear-gradient(135deg,#00b09b,#96c93d);color:#fff;font-weight:700;cursor:pointer;font-size:12px}\nbutton.danger{background:linear-gradient(135deg,#d90429,#ef233c)}\nbutton.warn{background:linear-gradient(135deg,#f59e0b,#ef4444)}\n.msg{padding:8px 12px;border-radius:6px;font-size:12px;margin-bottom:12px}\n.msg.ok{background:rgba(0,230,118,.1);border:1px solid rgba(0,230,118,.3);color:#00e676}\n.msg.warn{background:rgba(255,193,7,.1);border:1px solid rgba(255,193,7,.3);color:#ffc107}\ntable{width:100%;border-collapse:collapse;font-size:11px}\nth,td{padding:6px 8px;text-align:left;border-bottom:1px solid #21262d;vertical-align:top}\nth{color:#8b949e;font-size:10px;text-transform:uppercase;letter-spacing:.5px}\n.hint{font-size:10px;color:#8b949e;margin-top:8px;line-height:1.6}\n.toggle-row{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:10px}\n.toggle{display:flex;align-items:center;gap:8px;font-size:12px;background:#0d1117;border:1px solid #30363d;padding:8px 12px;border-radius:8px}\n.toggle .st{font-weight:700}\n.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}\n@media(max-width:800px){.grid2{grid-template-columns:1fr}}\n</style></head><body><div class="wrap">\n<div class="top"><h1>⚙️ GOD MODE v4 — ADMIN DASHBOARD</h1><div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap"><a href="${ADMIN_PATH}/answers" style="color:#00e676;text-decoration:none;font-size:12px;border:1px solid rgba(0,230,118,.4);padding:6px 12px;border-radius:6px">📚 KHO ĐÁP ÁN (${answerBank.size} môn · ${[...answerBank.values()].reduce((s, e) => s + ((e.exercises || []).length || 0), 0)} bài tập)</a>
<a href="${ADMIN_PATH}/locked" style="color:#ffc107;text-decoration:none;font-size:12px;border:1px solid rgba(255,193,7,.4);padding:6px 12px;border-radius:6px">🔒 TAB KHOÁ SCRIPT LẠ (${lockActive})</a><a class="logout" href="${ADMIN_PATH}/logout">🚪 Đăng xuất</a></div></div>\n${msg ? `<div class="msg ${msg.includes('thành công') || msg.includes('OK') || msg.includes('✅') ? 'ok' : 'warn'}">${_esc(msg)}</div>` : ''}\n<div class="cards">\n<div class="card"><div class="lbl">Trạng thái server</div><div class="val ok">● ĐANG CHẠY</div></div>\n<div class="card"><div class="lbl">Uptime</div><div class="val">${uptStr}</div></div>\n<div class="card"><div class="lbl">Ẩn API Prefix</div><div class="val">${_esc(API_PREFIX)}</div></div>\n<div class="card"><div class="lbl">Auto-ban</div><div class="val ${AUTO_BAN ? 'ok' : 'bad'}">${AUTO_BAN ? 'BẬT' : 'TẮT'}</div></div>\n<div class="card"><div class="lbl">Chặn kèo script VM (chỉ VM/proxy/desktop)</div><div class="val ${BLOCK_VM_SCRIPT ? 'warn' : 'ok'}">${BLOCK_VM_SCRIPT ? '🛑 Chặn VM/proxy (mobile vẫn OK)' : '✅ Bình thường'}</div></div>\n<div class="card"><div class="lbl">Tài khoản OLM bị ban</div><div class="val" style="color:#ef4444">${olmBans.size}</div></div>\n<div class="card"><div class="lbl">Module 10 điểm</div><div class="val ${BLOCK_MODULE_10 ? 'bad' : 'ok'}">${BLOCK_MODULE_10 ? '🛑 ĐANG CHẶN' : '✅ Đang gửi'}</div></div>\n<div class="card"><div class="lbl">HARD_DC_BAN (proxy/VM gọi API→ban)</div><div class="val ${HARD_DC_BAN ? 'ok' : 'bad'}">${HARD_DC_BAN ? 'BẬT' : 'TẮT'}</div></div>\n<div class="card"><div class="lbl">SAFE_MODE (chống ban nhầm — auto-ban chỉ log)</div><div class="val ${SAFE_MODE ? 'ok' : 'bad'}">${SAFE_MODE ? 'BẬT (an toàn)' : 'TẮT (nguy cơ ban nhầm)'}</div></div>\n<div class="card"><div class="lbl">SMART_BAN (chỉ ban máy ảo/proxy, máy thật tự mở ban)</div><div class="val ${SMART_BAN ? 'ok' : 'bad'}">${SMART_BAN ? 'BẬT (thông minh)' : 'TẮT'}</div></div>\n<div class="card"><div class="lbl">Đã tự mở ban cho thiết bị thật</div><div class="val" style="color:#00e676">${autoUnbanCount} lần</div></div>\n<div class="card"><div class="lbl">Thiết bị thật đã nhận diện</div><div class="val" style="color:#4facfe">${realDevices.size} máy</div></div>\n<div class="card"><div class="lbl">DUMPER_GUARD (phát hiện dump→ban key)</div><div class="val ${DUMPER_GUARD ? 'ok' : 'bad'}">${DUMPER_GUARD ? 'BẬT' : 'TẮT'}</div></div>\n<div class="card"><div class="lbl">Watermark truy vết module</div><div class="val ${MODULE_WATERMARK ? 'ok' : 'bad'}">${MODULE_WATERMARK ? 'BẬT' : 'TẮT'}</div></div>\n<div class="card"><div class="lbl">Key đã khoá (revoke)</div><div class="val bad">${BANNED_KEYS.size} key</div></div>\n${SECRET === DEFAULT_SECRET ? '<div class="card" style="grid-column:1/-1;border-color:#ef4444"><div class="lbl" style="color:#ef4444">⚠️ SECRET MẶC ĐỊNH ĐÃ RÒ RỈ — đặt env GODMODE_SECRET NGAY</div></div>' : ''}\n<div class="card"><div class="lbl">Chỉ Android/iOS</div><div class="val ${MOBILE_ONLY ? 'ok' : 'bad'}">${MOBILE_ONLY ? 'BẬT' : 'TẮT'}</div></div>\n<div class="card"><div class="lbl">Đang bị khoá</div><div class="val bad">${banned.size} IP/thiết bị</div></div>\n<div class="card"><div class="lbl">Thiết bị đã kết nối</div><div class="val">${devices.size}</div></div>\n<div class="card"><div class="lbl">Lưu trữ ban vĩnh viễn</div><div class="val ${KV_ENABLED ? 'ok' : 'bad'}">${KV_ENABLED ? 'KV (bền vững)' : 'CHỈ bộ nhớ (mất khi restart)'}</div></div>
<div class="card"><div class="lbl">Lưu trữ log hoạt động</div><div class="val ${KV_ENABLED ? 'ok' : 'bad'}">${KV_ENABLED ? 'KV (không mất khi restart)' : 'CHỈ bộ nhớ (mất khi restart)'}</div></div>\n<div class="card"><div class="lbl">Khoá script lạ (mở được)</div><div class="val ${lockActive ? 'bad' : 'ok'}"><a href="${ADMIN_PATH}/locked" style="color:inherit;text-decoration:none">${lockActive} đang khoá</a></div></div>\n<div class="card"><div class="lbl">Chữ ký request (anti-fake)</div><div class="val ${secInfo.reqSign ? 'ok' : 'bad'}">${secInfo.reqSign ? 'BẬT' : 'TẮT'}</div></div>\n<div class="card"><div class="lbl">Anti-share key</div><div class="val ${secInfo.antiShare ? 'ok' : 'bad'}">${secInfo.antiShare ? 'BẬT' : 'TẮT'} • ${secInfo.shareCount} phát hiện</div></div>\n<div class="card"><div class="lbl">Tấn công fake/fire</div><div class="val ${secInfo.fakeCount + secInfo.fireCount ? 'bad' : 'ok'}">${secInfo.fakeCount} fake • ${secInfo.fireCount} fire</div></div>\n</div>\n\n<div class="panel">\n<h2>🎛 BẬT / TẮT BẢO MẬT</h2>\n<div class="toggle-row">\n<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="autoBan"><button class="${AUTO_BAN ? 'warn' : ''}">${AUTO_BAN ? '⛔ TẮT auto-ban' : '✅ BẬT auto-ban'}</button></form>\n<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="mobileOnly"><button class="${MOBILE_ONLY ? 'warn' : ''}">${MOBILE_ONLY ? '📴 TẮT chỉ-mobile' : '📱 BẬT chỉ-mobile'}</button></form>\n<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="banDesktop"><button class="${BAN_DESKTOP ? 'warn' : ''}">${BAN_DESKTOP ? '💻 TẮT ban desktop' : '💻 BẬT ban desktop'}</button></form>\n<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="blockVmScript"><button class="${BLOCK_VM_SCRIPT ? 'warn' : ''}" style="${BLOCK_VM_SCRIPT ? 'background:linear-gradient(135deg,#f59e0b,#eab308)' : ''}">${BLOCK_VM_SCRIPT ? '🛑 ĐANG chặn VM/proxy (Android/iOS vẫn OK) — bấm để TẮT' : '🔓 BẬT chặn kèo script VM (chỉ chặn VM/proxy/desktop)'}</button></form>\n<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="blockModule10"><button class="${BLOCK_MODULE_10 ? 'warn' : ''}" style="${BLOCK_MODULE_10 ? 'background:linear-gradient(135deg,#f59e0b,#ef4444)' : ''}">${BLOCK_MODULE_10 ? '🛑 ĐANG CHẶN module 10đ (bấm TẮT)' : '🔟 BẬT chặn module chuẩn bị 10đ'}</button></form>\n<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="hardDcBan"><button class="${HARD_DC_BAN ? 'warn' : ''}">${HARD_DC_BAN ? '🌐 TẮT HARD_DC_BAN' : '🌐 BẬT HARD_DC_BAN (proxy/VM→ban)'}</button></form>\n<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="safeMode"><button class="${SAFE_MODE ? '' : 'warn'}">${SAFE_MODE ? '🛡️ TẮT SAFE_MODE (cho phép ban cứng)' : '🛡️ BẬT SAFE_MODE (chống ban nhầm)'}</button></form>\n<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="smartBan"><button class="${SMART_BAN ? '' : 'warn'}">${SMART_BAN ? '🧠 TẮT SMART_BAN' : '🧠 BẬT SMART_BAN (chỉ ban máy ảo/proxy)'}</button></form>\n<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="dumperGuard"><button class="${DUMPER_GUARD ? 'warn' : ''}">${DUMPER_GUARD ? '🕵️ TẮT DUMPER_GUARD' : '🕵️ BẬT DUMPER_GUARD (dump→ban key)'}</button></form>\n<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="moduleWatermark"><button class="${MODULE_WATERMARK ? 'warn' : ''}">${MODULE_WATERMARK ? '💧 TẮT watermark' : '💧 BẬT watermark truy vết'}</button></form>\n<form method="POST" action="${ADMIN_PATH}/toggle" class="inline" style="display:flex;gap:4px"><input type="hidden" name="flag" value="bankey"><input name="key" placeholder="KEY cần khoá (revoke)" style="padding:8px;border-radius:6px;border:1px solid #30363d;background:#0d1117;color:#e6edf3;min-width:180px"><button style="background:linear-gradient(135deg,#ef4444,#b91c1c)">🔨 Khoá key</button></form>\n<form method="POST" action="${ADMIN_PATH}/toggle" class="inline" style="display:flex;gap:4px"><input type="hidden" name="flag" value="unbankey"><input name="key" placeholder="KEY cần mở khoá" style="padding:8px;border-radius:6px;border:1px solid #30363d;background:#0d1117;color:#e6edf3;min-width:180px"><button style="background:linear-gradient(135deg,#22c55e,#15803d)">🔓 Mở khoá key</button></form>\n<div class="panel" style="margin-top:16px;border-color:rgba(239,68,68,.4)">\n<h2 style="color:#ef4444">🚫 BAN TÀI KHOẢN OLM (phút / ngày / tháng / vĩnh viễn)</h2>\n<form method="POST" action="${ADMIN_PATH}/olm-ban" style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end;margin-bottom:14px">\n<div><label style="display:block;font-size:10px;color:#8b949e;margin-bottom:4px">Tài khoản OLM (email/username)</label>\n<input name="olm_user" required placeholder="vd: user@olm.vn" style="padding:7px 10px;border-radius:5px;border:1px solid #30363d;background:#0d1117;color:#c9d1d9;width:200px;font-size:12px"></div>\n<div><label style="display:block;font-size:10px;color:#8b949e;margin-bottom:4px">Thời gian</label>\n<input name="value" type="number" min="1" value="1" style="width:70px;padding:7px 10px;border-radius:5px;border:1px solid #30363d;background:#0d1117;color:#c9d1d9;font-size:12px"></div>\n<div><label style="display:block;font-size:10px;color:#8b949e;margin-bottom:4px">Đơn vị</label>\n<select name="unit" style="padding:7px 8px;border-radius:5px;border:1px solid #30363d;background:#0d1117;color:#c9d1d9;font-size:12px">\n<option value="minute">Phút</option>\n<option value="day" selected>Ngày</option>\n<option value="month">Tháng</option>\n<option value="permanent">Vĩnh viễn</option>\n</select></div>\n<div><label style="display:block;font-size:10px;color:#8b949e;margin-bottom:4px">Lý do</label>\n<input name="reason" placeholder="Vi phạm điều khoản" style="padding:7px 10px;border-radius:5px;border:1px solid #30363d;background:#0d1117;color:#c9d1d9;width:180px;font-size:12px"></div>\n<button type="submit" style="background:linear-gradient(135deg,#ef4444,#b91c1c);padding:8px 18px">🚫 BAN</button>\n</form>\n<div style="font-size:10px;color:#8b949e;margin-bottom:8px">💡 Khi BAN: script trên server tự check — người dùng đăng nhập tài khoản OLM bị ban sẽ thấy thông báo <b style="color:#fca5a5">TÀI KHOẢN OLM ĐÃ BỊ CẤM</b> full-screen. Ban hết hạn tự gỡ. Chọn "Vĩnh viễn" = không hết hạn.</div>\n<table><thead><tr><th>Tài khoản OLM</th><th>Thời gian còn lại</th><th>Lý do</th><th>Thời gian ban</th><th>Thao tác</th></tr></thead>\n<tbody id="olm-ban-tbody"><tr><td colspan="5" class="empty">Đang tải...</td></tr></tbody></table>\n</div>\n<script>\nfunction _escOl(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}\nfunction _unbanOl(olm){\n  var fd=new URLSearchParams(); fd.append('olm_user', olm);\n  fetch('${ADMIN_PATH}/olm-unban',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'},body:fd.toString()}).then(function(){ _refreshOl(); }).catch(function(){ _refreshOl(); });\n}\ndocument.addEventListener('click',function(e){ var b=e.target&&e.target.closest?e.target.closest('button[data-olm-unban]'):null; if(b){ _unbanOl(decodeURIComponent(b.getAttribute('data-olm-unban')||'')); } });\nfunction _renderOl(d){\n  var tb=document.getElementById('olm-ban-tbody');\n  var list=(d&&d.list)||[];\n  if(!list.length){ tb.innerHTML='<tr><td colspan="5" style="text-align:center;color:#00e676;padding:16px;font-size:12px">✅ Chưa có tài khoản OLM nào bị ban.</td></tr>'; return; }\n  var html='';\n  list.forEach(function(r){\n    html+='<tr style="background:rgba(239,68,68,.05)">';\n    html+='<td style="font-family:monospace;font-size:11px;color:#fca5a5">'+_escOl(r.olm)+'</td>';\n    html+='<td style="font-size:11px;color:#ef4444;font-weight:700">'+(r.permanent?'♾️ VĨNH VIÊN':('⏳ '+_escOl(r.remain)))+'</td>';\n    html+='<td style="font-size:10px;color:#ffc107;max-width:180px">'+_escOl(r.reason||'')+'</td>';\n    html+='<td style="font-size:10px;color:#8b949e;font-family:monospace">'+(r.t?new Date(r.t).toLocaleString('vi-VN'):'')+'</td>';\n    html+='<td><button data-olm-unban="'+encodeURIComponent(r.olm)+'" style="background:linear-gradient(135deg,#00b09b,#96c93d)">🔓 UNBAN</button></td>';
    html+='</tr>';\n  });\n  tb.innerHTML=html;\n}\nfunction _refreshOl(){ fetch('${ADMIN_PATH}/olm-bans.json').then(function(r){return r.json();}).then(function(d){_renderOl(d);setTimeout(_refreshOl,5000);}).catch(function(){setTimeout(_refreshOl,5000);}); }\n_refreshOl();\n<\/script>\n</div>\n<div class="hint">Auto-ban: khoá vĩnh viễn IP+thiết bị khi phát hiện máy ảo/proxy/VPN/trình duyệt giả. Chỉ-mobile: chỉ chấp nhận Android/iOS thật. Ban desktop: khoá cả máy tính (mặc định tắt — chỉ từ chối).</div>\n</div>\n\n<div class="grid2">\n<div class="panel">\n<h2>🔑 ĐỔI MẬT KHẨU ADMIN</h2>\n<form method="POST" action="${ADMIN_PATH}/change-password" class="inline" style="flex-direction:column;align-items:stretch">\n<input type="password" name="old" placeholder="Mật khẩu hiện tại" required>\n<input type="password" name="new" placeholder="Mật khẩu mới (tối thiểu 6 ký tự)" required>\n<input type="password" name="confirm" placeholder="Xác nhận mật khẩu mới" required>\n<button>💾 ĐỔI MẬT KHẨU</button>\n</form>\n<div class="hint">Mật khẩu được lưu dạng hash scrypt (không bao giờ lưu plaintext). Sau khi đổi, mọi phiên đăng nhập khác sẽ bị đăng xuất.${KV_ENABLED ? ' Đã lưu vào KV — tồn tại qua restart.' : ' ⚠️ Chưa có KV — đổi mật khẩu sẽ mất khi server restart (đặt env KV_REST_API_URL + KV_REST_API_TOKEN để bền vững).'}</div>\n</div>\n<div class="panel">\n<h2>🛡 ĐỔI SECRET (ẩn API + ký phiên)</h2>\n<form method="POST" action="${ADMIN_PATH}/set-secret" class="inline" style="flex-direction:column;align-items:stretch">\n<input name="secret" placeholder="64 ký tự hex (hoặc để trống = random)" value="">\n<button class="warn">⚠️ ĐỔI SECRET (sẽ đổi API prefix)</button>\n</form>\n<div class="hint">⚠️ Khi đổi SECRET, API prefix thay đổi → PHẢI cập nhật API_SECRET trong connector userscript cho khớp, nếu không script sẽ không kết nối được.${KV_ENABLED ? ' Đã lưu vào KV.' : ' ⚠️ Mất khi restart nếu không có KV.'}</div>\n</div>\n</div>\n\n<div class="panel" style="border-color:rgba(0,230,118,.4)">\n<h2 style="color:#00e676">🍎 Mở KHOÁ TOÀN BỘ (iOS Whitelist)</h2>\n<div style="font-size:11px;color:#8b949e;margin-bottom:10px">Nhập IP hoặc HWID → thiết bị <b style="color:#00e676">không bao giờ bị khoá lại</b> (kể cả lock-report, auto-ban). Dùng cho iOS thật bị phát hiện nhầm.</div>\n<form method="POST" action="${ADMIN_PATH}/full-unlock" style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px">\n<input name="target" placeholder="IP (vd: 171.254.0.1) hoặc HWID (vd: HW2334B90D)" required style="min-width:260px">\n<input name="reason" placeholder="Lý do" value="iOS thật bị khoá nhầm" style="min-width:160px">\n<button style="background:linear-gradient(135deg,#00e676,#00b09b);font-size:12px;padding:9px 16px">🔓 Mở KHOÁ TOÀN BỘ + WHITELIST</button>\n</form>\n<div id="wl-panel-data" style="font-size:11px;color:#8b949e">Đang tải...</div>\n<script>\nfunction _fmtWl(t){try{return new Date(t).toLocaleString('vi-VN');}catch(e){return ''}}\nfunction _escWl(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}\nfunction _rmWl(key){if(!confirm('Xoá whitelist: '+key+'?'))return;fetch('${ADMIN_PATH}/api/ios-whitelist/remove',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:key.replace(/^(ip:|dev:)/,'')})}).then(function(){_ldWl();});}\nfunction _ldWl(){fetch('${ADMIN_PATH}/ios-whitelist.json').then(function(r){return r.json();}).then(function(d){var el=document.getElementById('wl-panel-data');if(!el)return;var list=d.list||[];if(!list.length){el.innerHTML='<span style="color:#8b949e">Chưa có thiết bị nào trong whitelist.</span>';return;}var h='<table style="font-size:11px"><thead><tr><th>Key</th><th>Lý do</th><th>Thời gian</th><th></th></tr></thead><tbody>';list.forEach(function(r){h+='<tr><td style="font-family:monospace;color:#00e676">'+ _escWl(r.key)+'</td><td style="color:#ffc107">'+ _escWl(r.reason)+'</td><td style="color:#8b949e;font-family:monospace">'+ _fmtWl(r.t)+'</td><td><button onclick="_rmWl(\''+_escWl(r.key)+'\');" style="background:linear-gradient(135deg,#ef4444,#b91c1c);padding:3px 8px;font-size:10px;border:none;border-radius:4px;color:#fff;cursor:pointer">🗑</button></td></tr>';});h+='</tbody></table>';el.innerHTML=h;}).catch(function(){});}\n_ldWl();setInterval(_ldWl,8000);\n<\/script>\n</div>\n\n<div class="panel">\n<h2>🚫 DANH SÁCH BỊ KHOÁ VĨNH VIỄN (IP + THIẾT BỊ)</h2>\n<form method="POST" action="${ADMIN_PATH}/unban-all" style="margin-bottom:10px" onsubmit="return confirm('Mở khoá TẤT CẢ IP/thiết bị bị khoá + xóa cache IP? Các thiết bị bị khoá nhầm sẽ hoạt động lại ngay.')"><button type="submit" style="background:linear-gradient(135deg,#00b09b,#96c93d);padding:10px 20px;font-size:13px;font-weight:bold">🔓 MỞ KHOÁ TẤT CẢ (reset thiết bị bị khoá)</button></form>\n${banned.size === 0 ? '<div style="font-size:12px;color:#8b949e;padding:8px">Chưa có thiết bị/IP nào bị khoá.</div>' : `<table><thead><tr><th>Đối tượng</th><th>Tên máy</th><th>Lý do</th><th>Thời gian</th><th></th></tr></thead><tbody>${banRows}</tbody></table>`}\n<h2 style="margin-top:16px">➕ KHOÁ THỦ CÔNG</h2>\n<form method="POST" action="${ADMIN_PATH}/ban" class="inline">\n<input name="target" placeholder="IP hoặc HWID (vd: 1.2.3.4 hoặc HW1234ABCD)" required>\n<input name="reason" placeholder="Lý do" value="manual">\n<button class="danger">🚫 KHOÁ</button>\n</form>\n</div>\n\n<div class="panel">\n<h2>📱 THIẾT BỊ ĐÃ KẾT NỐI (tên máy)</h2>\n <a href="${ADMIN_PATH}/devices" style="color:#4facfe;text-decoration:none;font-size:11px;border:1px solid rgba(79,172,254,.4);padding:4px 10px;border-radius:6px;margin-left:10px">📱 Xem tab Thiết bị & OLM & Môn →</a>\n${devices.size === 0 ? '<div style="font-size:12px;color:#8b949e;padding:8px">Chưa có thiết bị nào xác thực thành công.</div>' : `<table><thead><tr><th>HWID</th><th>Tên máy</th><th>Hệ điều hành</th><th>IP cuối</th><th>Lần cuối</th></tr></thead><tbody>${devRows}</tbody></table>`}\n</div>\n\n<div class="panel">\n<h2>📜 LOG GẦN NHẤT (có tên máy gửi lên server) — ${ADMIN_LOG.length} bản ghi${KV_ENABLED ? ' · 💾 KV bền vững' : ''}</h2>\n<table><thead><tr><th>Thời gian</th><th>Loại</th><th>Tên máy</th><th>HWID</th><th>IP</th><th>OK</th><th>OLM User</th><th>Chi tiết</th></tr></thead>\n<tbody>${logRows || '<tr><td colspan="7" style="text-align:center;color:#8b949e">Chưa có request nào.</td></tr>'}</tbody></table>\n<div class="hint">verify = nhập key • attest = xác thực thiết bị/mạng • process = giải mã đáp án • fire = nộp bài • ban/reject = bị khoá/từ chối${KV_ENABLED ? ' • 💾 Log được lưu vào KV bền vững — không mất khi restart/cold start.' : ' • ⚠️ Chưa có KV — log mất khi restart; đặt KV_REST_API_URL + KV_REST_API_TOKEN để bền vững.'}</div>\n</div>\n</div></body></html>`;
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
  const totalEx = entries.reduce((s, e) => s + (e.exercises || []).length, 0);
  const totalQ = entries.reduce((s, e) => s + (e.count || (e.items || []).length || 0), 0);
  const totalHits = entries.reduce((s, e) => s + (e.hits || 0), 0);
  const subjectOpts = [];
  const seenS = new Set();
  all.forEach(e => {
    const lab = bankSubjectDisplay(e);
    const k = entryCanon(e) || normBankText(lab);
    if (k && !seenS.has(k)) { seenS.add(k); subjectOpts.push({ k: k, lab: lab }); }
  });
  const groupCards = [...groups.entries()].map(([gk, g]) => {
    const gEx = g.entries.reduce((s, e) => s + (e.exercises || []).length, 0);
    const gQ = g.entries.reduce((s, e) => s + (e.count || (e.items || []).length || 0), 0);
    let exHtml = '';
    g.entries.forEach(e => {
      exHtml += (e.exercises || []).map(ex => {
        const qa = (ex.items || []).map((it, i) => '<div class="qa"><span class="qn">Câu ' + (i + 1) + '</span> ' + _esc(it.stem || it.title || '') + ' <span class="ans">→ ' + _esc((it.answers || []).join(' | ')) + '</span></div>').join('');
        return '<details class="ex"><summary><span class="ex-t">📝 ' + _esc(ex.title || 'Bài tập chưa rõ tên') + '</span><span class="ex-meta">' + (ex.count || 0) + ' câu · ' + (ex.hits || 0) + ' lượt' + (ex.courseware ? ' · cw ' + _esc(ex.courseware) : '') + '</span></summary><div class="qa-wrap">' + (qa || '<div class="empty-mini">Chưa có đáp án.</div>') + '<form method="POST" action="' + ADMIN_PATH + '/answers/exercise-delete" class="ex-del"><input type="hidden" name="key" value="' + _esc(e.key) + '"><input type="hidden" name="exKey" value="' + _esc(ex.key) + '"><button class="danger sm">🗑 Xoá bài tập này</button></form></div></details>';
      }).join('');
    });
    // [v23] Gộp toàn bộ cate của mọi bài tập trong thẻ môn (1 thẻ môn chứa nhiều bài tập/cate)
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
.qa .ans{color:#ffc107}
.ex-del{margin-top:8px}
.subj-actions{display:flex;gap:6px;flex-wrap:wrap;align-items:center;border-top:1px solid #21262d;padding-top:8px}
.entry-row{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
.inline{display:inline;margin:0}
.empty-mini{font-size:11px;color:#8b949e;padding:6px}
.empty{text-align:center;color:#8b949e;padding:30px;font-size:13px;grid-column:1/-1}
.msg{padding:8px 12px;border-radius:6px;font-size:12px;margin-bottom:12px;background:rgba(0,230,118,.1);border:1px solid rgba(0,230,118,.3);color:#00e676}
.hint{font-size:10px;color:#8b949e;margin-top:14px;line-height:1.7}
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
<div class="stat info"><div class="n">${totalHits}</div><div>Lượt tra cứu</div></div>
<div class="stat ${(KV_ENABLED || BANK_FILE_OK) ? 'ok' : ''}"><div class="n">${KV_ENABLED ? 'KV' : (BANK_FILE_OK ? 'FILE' : 'MEMORY')}</div><div>${KV_ENABLED ? 'Lưu bền vững qua restart' : (BANK_FILE_OK ? 'Lưu file cục bộ, bền vững qua restart' : 'Chưa có lưu trữ bền vững — mất khi restart')}</div></div>
</div>
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
<div class="hint">💡 Mỗi môn học là một <b>cột/thẻ riêng</b>; bên trong liệt kê từng <b>bài tập</b> (tên bài tập được script tự lấy), mở từng bài tập để xem <b>câu hỏi + đáp án</b>. Kho tự lưu mỗi lần máy user giải đáp án (route /process). Script chỉ chờ 35s và tra kho khi đang ở <b>trang bài tập</b>; trang danh sách/lớp học sẽ không tra kho.</div>
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
    tombMark('exercise', exKey); // [v24] đánh dấu xoá bền vững, không hồi sinh sau restart
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
  bankTombstones.set('subject::*', Date.now()); // [v24] xoá toàn bộ là bền vững: restart không hiện lại kho cũ
  answerBank.clear();
  kvSaveState();
  adminLog('bank-clear', { entries: n });
  res.redirect(ADMIN_PATH + '/answers?msg=' + encodeURIComponent('Đã xoá toàn bộ kho đáp án (' + n + ' môn).'));
});

// === [v20] TẢI FILE ĐÁP ÁN VỀ MÁY (JSON / TXT — toàn bộ kho hoặc theo từng môn) ===
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
    count: e.count || (e.items || []).length || 0,
    hits: e.hits || 0,
    created_at: e.created_at || 0,
    updated_at: e.updated_at || 0,
    exercises: (e.exercises || []).map(ex => ({
      key: ex.key,
      title: ex.title || '',
      cate: ex.cate || null,
      courseware: ex.courseware || null,
      count: ex.count || (ex.items || []).length || 0,
      hits: ex.hits || 0,
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
  const lines = [];
  lines.push('==================================================');
  lines.push(' KHO DAP AN THEO MON - XUAT TU GOD MODE ADMIN');
  lines.push(' Xuat luc: ' + new Date().toLocaleString('vi-VN'));
  lines.push(' Tong mon: ' + payload.total_subjects + ' | Tong bai tap: ' + (payload.total_exercises || 0) + ' | Tong cau: ' + payload.total_questions);
  lines.push('==================================================');
  (payload.subjects || []).forEach((s, si) => {
    lines.push('');
    lines.push('========== MON ' + (si + 1) + ': ' + (s.subject_label || s.subject || s.cate || s.key) + ' ==========');
    if (s.cate) lines.push('ID_CATE (mon): ' + s.cate);
    if (s.courseware) lines.push('ID_COURSEWARE: ' + s.courseware);
    if (s.olm_user) lines.push('Tai khoan nguon: ' + s.olm_user);
    lines.push('So bai tap: ' + (s.exercises || []).length + ' | So cau: ' + s.count + ' | Luot tra: ' + s.hits);
    if (s.updated_at) lines.push('Cap nhat: ' + new Date(s.updated_at).toLocaleString('vi-VN'));
    const exList = (s.exercises && s.exercises.length) ? s.exercises : [{ title: 'Bài tập', items: s.items || [] }];
    exList.forEach((ex, ei) => {
      lines.push('');
      lines.push('  --- Bai tap ' + (ei + 1) + ': ' + (ex.title || 'Chua ro ten') + ' (' + (ex.count || (ex.items || []).length) + ' cau) ---');
      (ex.items || []).forEach((it, i) => {
        const stem = it.stem || it.title || '';
        const answers = (it.answers || []).filter(a => a && a !== 'Không tự động trích xuất được.' && a !== 'Lỗi giải mã' && a !== 'Dữ liệu câu hỏi quá lớn — bỏ qua');
        lines.push('  Cau ' + (i + 1) + (it.qid ? ' [qid:' + it.qid + ']' : ''));
        // [v23] File TXT luôn hiện CÂU HỎI + ĐÁP ÁN (giống hiển thị trên trang kho)
        lines.push('    Cau hoi: ' + (stem || '(Cau hoi dang lua chon/tu luan — xem noi dung tren trang kho dap an)'));
        if (it.title && it.stem && String(it.title).trim() && String(it.title).trim() !== String(stem).trim()) lines.push('    Tieu de: ' + it.title);
        lines.push('    Dap an: ' + (answers.length ? answers.join(' | ') : '(Chua co dap an)'));
      });
    });
  });
  return lines.join('\n') + '\n';
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
  // [v23] Sau gộp theo tên môn: cho phép tải theo cate cũ / tên môn
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
    msg = SMART_BAN ? '✅ Đã BẬT SMART_BAN: chỉ ban máy ảo/proxy ảo xác nhận; máy thật Android/iOS KHÔNG bao giờ bị ban + tự mở ban.' : '⚠️ Đã TẮT SMART_BAN — dùng quy tắc ban cũ (dễ ban nhầm).';
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
      msg = '🔨 Đã KHOÁ key ' + maskKey(kk) + ' — mọi thiết bị dùng key này bị 404.';
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
  const key = target.includes(':') ? 'ip:' + target : (/^\d+\.\d+\.\d+\.\d+$/.test(target) ? 'ip:' + target : 'dev:' + target);
  banned.set(key, {
    reason: reason,
    device: '',
    t: Date.now(),
    by: 'admin'
  });
  kvSaveState();
  adminLog('admin', {
    action: 'ban',
    target: key,
    reason: reason,
    ip: getClientIp(req)
  });
  res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent('✅ Đã khoá: ' + key));
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
  const addWl = req.body && req.body.whitelist !== false; // mặc định true
  const rec = hwid && lockedScripts.get(hwid);
  if (rec) {
    rec.status = 'unlocked';
    rec.unlockedAt = Date.now();
    banned.delete('dev:' + hwid);
    if (rec.ip) banned.delete('ip:' + rec.ip);
    // Thêm vào iOS whitelist để device không bị lock lại lần sau (Focus Browser)
    if (addWl) {
      iosWhitelist.set('dev:' + hwid, { by: 'admin', t: Date.now(), reason: 'unlock-script-panel (iOS thật Focus Browser)' });
      if (rec.ip) iosWhitelist.set('ip:' + rec.ip, { by: 'admin', t: Date.now(), reason: 'unlock-script-panel linked IP' });
    }
    kvSaveState();
    adminLog('admin', {
      action: 'unlock-script',
      hwid: hwid,
      ip: rec.ip,
      device: rec.device || '',
      whitelisted: !!addWl,
      ipAdmin: getClientIp(req)
    });
  }
  res.json({
    ok: true,
    unlocked: !!rec,
    whitelisted: !!(rec && addWl)
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

// ============================================================
// === MỞ KHOÁ ALL (iOS Whitelist) — Admin API ================
// ============================================================
// POST /admin/api/ios-whitelist/add   { target: 'IP hoặc HWID', reason: '...' }
// POST /admin/api/ios-whitelist/remove { target: 'IP hoặc HWID' }
// GET  /admin/api/ios-whitelist        → danh sách
// POST /admin/full-unlock              { target: 'IP hoặc HWID', reason: '...' }
//   → xoá khỏi banned + lockedScripts + thêm vào whitelist

function _parseWhitelistKey(raw) {
  const t = String(raw || '').trim();
  if (!t) return null;
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(t) || t.includes(':')) return 'ip:' + t;
  return 'dev:' + t;
}

// Thêm vào whitelist
app.post(ADMIN_PATH + '/api/ios-whitelist/add', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const target = String(req.body && req.body.target || '').trim();
  const reason = String(req.body && req.body.reason || 'admin-whitelist').slice(0, 200);
  const key = _parseWhitelistKey(target);
  if (!key) return res.json({ ok: false, message: 'Thiếu IP hoặc HWID' });
  iosWhitelist.set(key, { by: 'admin', t: Date.now(), reason: reason });
  kvSaveState();
  adminLog('admin', { action: 'ios-whitelist-add', key: key, reason: reason, ipAdmin: getClientIp(req) });
  res.json({ ok: true, key: key });
});

// Xoá khỏi whitelist
app.post(ADMIN_PATH + '/api/ios-whitelist/remove', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const target = String(req.body && req.body.target || '').trim();
  const key = _parseWhitelistKey(target);
  if (!key) return res.json({ ok: false, message: 'Thiếu IP hoặc HWID' });
  iosWhitelist.delete(key);
  kvSaveState();
  adminLog('admin', { action: 'ios-whitelist-remove', key: key, ipAdmin: getClientIp(req) });
  res.json({ ok: true, key: key });
});

// Lấy danh sách whitelist
app.get(ADMIN_PATH + '/api/ios-whitelist', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const list = [...iosWhitelist.entries()].map(([k, v]) => ({ key: k, ...v }));
  res.json({ ok: true, list: list, count: list.length });
});

// === FULL UNLOCK: mở khoá toàn bộ + whitelist ===
// Nhập IP hoặc HWID → xoá khỏi banned + lockedScripts + thêm vào whitelist
app.post(ADMIN_PATH + '/full-unlock', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const target = String(req.body && req.body.target || '').trim();
  const reason = String(req.body && req.body.reason || 'full-unlock-admin').slice(0, 200);
  if (!target) return res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent('❌ Nhập IP hoặc HWID!'));

  const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(target) || target.includes(':');
  const banKey = isIp ? 'ip:' + target : 'dev:' + target;
  const wlKey = banKey;

  // 1. Xoá khỏi banned
  if (!isIp) {
    // Nếu là HWID: đọc devRec TRƯỚC khi xoá để lấy IP liên quan
    const devRec = banned.get('dev:' + target);
    banned.delete(banKey);
    if (devRec && devRec.ip) {
      banned.delete('ip:' + devRec.ip);
      // Whitelist cả IP liên quan để không bị lock lại
      iosWhitelist.set('ip:' + devRec.ip, { by: 'admin', t: Date.now(), reason: reason + ' (linked IP)' });
    }
    // Xoá trong lockedScripts — xoá cứng status và cập nhật IP whitelist từ lockedScripts
    const lr = lockedScripts.get(target);
    if (lr) {
      lr.status = 'unlocked';
      lr.unlockedAt = Date.now();
      if (lr.ip) {
        banned.delete('ip:' + lr.ip);
        iosWhitelist.set('ip:' + lr.ip, { by: 'admin', t: Date.now(), reason: reason + ' (lock-report IP)' });
      }
    }
  } else {
    banned.delete(banKey);
    // Nếu là IP: tìm và unlock TẤT CẢ lockedScripts có IP này hoặc IP khớp
    for (const [hwid, lr] of lockedScripts) {
      if (lr.ip === target) {
        lr.status = 'unlocked';
        lr.unlockedAt = Date.now();
        banned.delete('dev:' + hwid);
        // Whitelist cả HWID để device không bị lock lại dù đổi IP
        iosWhitelist.set('dev:' + hwid, { by: 'admin', t: Date.now(), reason: reason + ' (linked HWID)' });
      }
    }
  }

  // 2. Thêm vào iOS whitelist (IP hoặc HWID được nhập)
  iosWhitelist.set(wlKey, { by: 'admin', t: Date.now(), reason: reason });

  kvSaveState();
  adminLog('admin', {
    action: 'full-unlock',
    target: banKey,
    reason: reason,
    ipAdmin: getClientIp(req)
  });

  res.redirect(ADMIN_PATH + '/dashboard?msg=' + encodeURIComponent(
    '✅ Đã MỞ KHOÁ TOÀN BỘ + thêm vào whitelist: ' + banKey + ' — thiết bị này sẽ không bao giờ bị khoá lại.'
  ));
});

// === API: danh sách whitelist (JSON cho dashboard) ===
app.get(ADMIN_PATH + '/ios-whitelist.json', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const list = [...iosWhitelist.entries()].map(([k, v]) => ({
    key: k,
    by: v.by || 'admin',
    t: v.t || 0,
    reason: v.reason || ''
  }));
  res.json({ ok: true, list: list, count: list.length });
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

// === FIX: global guards để một lỗi ngoài ý muốn không treo request/tiến trình ===
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
    console.log(`\n🚀 GOD MODE Server v18.0 (server-authoritative slim) running → http://localhost:${PORT}`);
    console.log(`   Ẩn API prefix: ${API_PREFIX}`);
    console.log(`   Admin: ${ADMIN_PATH} (${ADMIN_USER})`);
    console.log(`   Lưu trữ bền vững (KV): ${KV_ENABLED ? 'CÓ' : 'KHÔNG — đặt env KV_REST_API_URL + KV_REST_API_TOKEN để ban/mật khẩu tồn tại qua restart'}`);
    if (!KV_ENABLED) console.log(`   Kho đáp án (file dự phòng): ${BANK_FILE_OK ? 'ĐANG DÙNG ' + BANK_FILE : 'không ghi được file (' + BANK_FILE + ') — kho chỉ còn trong RAM, sẽ mất khi restart'}`);
    if (SAFE_MODE) console.log('[32m[v13 SAFE_MODE ĐANG BẬT] Auto-ban chỉ log + từ chối, KHÔNG khoá vĩnh viễn — không còn ban nhầm IP thật. Tắt: env SAFE_MODE=false hoặc panel admin.[0m'); else console.log('[33m[v13] CẢNH BÁO: SAFE_MODE đang TẮT — auto-ban sẽ khoá vĩnh viễn, dễ ban nhầm IP nhà mạng di động (CGNAT).[0m');
    if (!HARD_DC_BAN) console.log('[33m[v13] HARD_DC_BAN đang TẮT (kill-switch). Bật trong panel admin nếu muốn chặn cứng IP datacenter.[0m');
    if (SMART_BAN) console.log('[32m[v14 SMART_BAN ĐANG BẬT] Chi ban may ao/emulator/proxy xac nhan; may that Android/iOS KHONG bao gio bi ban + tu mo ban tu dong.[0m'); else console.log('[33m[v14] SMART_BAN dang TAT — de ban thong minh, bat lai trong panel admin.[0m');
    if (SMART_BAN) console.log('[36m[v15] AUTO_UNLOCK_REAL_IP: IP that cua Android/iOS tu dong mo khoa ngay khi ket noi — khong can admin thao tac.[0m');
    if (!BLOCK_VM_SCRIPT) console.warn('[33m   [SECURITY v12] SMART_VM_BLOCK dang TAT — vao admin panel BAT de chi cho Android/iOS that keo code (chan VM/proxy/desktop, KHONG anh huong user that).[0m');
    if (BLOCK_VM_SCRIPT) console.log('[32m   [SECURITY v12] SMART_VM_BLOCK dang BAT: chi chan VM/proxy/datacenter/desktop, Android/iOS that van hoat dong binh thuong.[0m');
    if (SECRET === DEFAULT_SECRET) console.warn('[31m   [SECURITY] SECRET MAC DINH DA ROI ROI — dat env GODMODE_SECRET (64 hex) NGAY.[0m');
  });
}

module.exports = app;