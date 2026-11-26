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
  // [v6.7.1 iOS-FIX] cho phép MỌI origin (auth trong body/header, không dùng cookie)
  // → iOS Focus / Firefox iOS / WKWebView không bị CORS chặn khi fetch bootstrap.
  origin: (origin, cb) => cb(null, true),
  methods: [ 'GET', 'POST', 'OPTIONS' ],
  allowedHeaders: [ 'Content-Type', 'X-Session', 'X-Fp-Hash', 'X-Seq', 'X-HWID', 'X-Ts', 'X-Nonce', 'X-Sign' ],
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
  console.warn('[33m[SECURITY][v18.1] Đang dùng cấu hình mặc định (secret/admin pass). Đặt GODMODE_SECRET, ADMIN_PASS trước khi public.[0m');
}

const PAYLOAD_MODULE_VERSION = 2; // [v29] practice nộp bài đúng tổng thời gian

const PAYLOAD_MODULE_SRC = `\nvar SESSION=ctx.SESSION, addLog=ctx.addLog, forceGetMeta=ctx.forceGetMeta;\nvar SECRET_KEY_CS='1047823200';\nfunction decryptOLM_CS(base64Str){if(!base64Str)return null;try{var raw=atob(base64Str);var dec='';for(var i=0;i<raw.length;i++)dec+=String.fromCharCode(raw.charCodeAt(i)^SECRET_KEY_CS.charCodeAt(i%SECRET_KEY_CS.length));return decodeURIComponent(escape(dec));}catch(e){return null;}}\nfunction buildParamsCS(sq){var count=sq.count||4;if(sq.type===6){var orderArr=Array.from(Array(Math.max(count,15)),function(_,k){return k;});return {js:'',order_l:orderArr,order_r:orderArr};}return {js:'',order:Array.from(Array(count),function(_,k){return k;})};}\nfunction findCorrectInfoCS(node){var results=[];function traverse(n){if(!n)return;var subQ_ID=n.id||n._id||(n.props?n.props.id:null);if((n.type==='fillme-input'&&n.content)||(typeof n.content==='string'&&n.content.includes('data-accept='))){if(typeof n.content==='string'&&n.content.includes('data-accept=')){var regex=/data-accept="([^"]+)"/g;var match;while((match=regex.exec(n.content))!==null)results.push({type:4,ans:[match[1]],count:1,skill:n.id_skill,subId:subQ_ID||('raw_'+Math.random()),isText:true});}else if(typeof n.content==='string'){results.push({type:4,ans:[n.content],count:1,skill:n.id_skill,subId:subQ_ID,isText:true});}return;}if(n.type==='olm-list'||(Array.isArray(n.children)&&n.children.length>0)){var options=Array.isArray(n.children)?n.children:null;if(options&&(n.name==='true-false'||n.listType==='true-false')){results.push({type:13,ans:options.map(function(o){return (o.correct==true||o.correct==='true'||o.correct==1)?'1':'0';}),count:options.length,skill:n.id_skill,subId:subQ_ID});return;}if(options&&(n.name==='link-list'||n.listType==='matching')){results.push({type:6,ans:options.map(function(_,idx){return idx.toString();}),count:options.length,skill:n.id_skill,subId:subQ_ID});return;}if(options&&options.some(function(c){return c.correct!==undefined;})){var trueIndex=options.findIndex(function(o){return o.correct==true||o.correct==='true'||o.correct==1;});results.push({type:1,ans:[(trueIndex===-1?0:trueIndex).toString()],count:options.length,skill:n.id_skill,subId:subQ_ID});return;}}if(Array.isArray(n.children))n.children.forEach(traverse);else if(Array.isArray(n.questions))n.questions.forEach(traverse);else if(Array.isArray(n.items))n.items.forEach(traverse);else if(Array.isArray(n.list))n.list.forEach(traverse);else if(n.root)traverse(n.root);}var contentToParse=node.json_content||node.content;if(typeof contentToParse==='string'&&!contentToParse.trim().startsWith('{')&&!contentToParse.trim().startsWith('[')){var decoded=decryptOLM_CS(contentToParse);if(decoded)contentToParse=decoded;}try{traverse(typeof contentToParse==='string'?JSON.parse(contentToParse):contentToParse);}catch(_){traverse(node);}if(results.length===0)results.push({type:1,ans:['0'],count:4,skill:null,subId:null});return results;}\nreturn async function(){\nforceGetMeta();\nif(!SESSION.meta.id_user||!SESSION.meta.id_cate){addLog('❌ Thiếu ID user/cate: user='+(SESSION.meta.id_user||'?')+' cate='+(SESSION.meta.id_cate||'?'),'err');return false;}\nvar totalPackages=SESSION.raw_questions.length;\nif(totalPackages===0){addLog('❌ Chưa có câu hỏi để nộp!','err');return false;}\nvar timeInput=document.getElementById('tl-god-time');\nvar timeStr=timeInput?timeInput.value.toString().trim():'10.00';\nvar tp=timeStr.split('.');\nvar userMins=parseInt(tp[0])||0;\nvar uss=tp[1]||'0';if(uss.length===1)uss+='0';\nvar userSecs=parseInt(uss.substring(0,2));\nvar calcSeconds=(userMins*60)+userSecs;\nif(calcSeconds<30)calcSeconds=120;\nvar modeSel=document.getElementById('tl-modeSelect');\nvar mode=modeSel?modeSel.value:'practice';\nvar isExam=mode==='exam',isVideo=mode==='video';\nvar tgtScoreSel=document.getElementById('tl-god-target-score');\nvar tgtScore=tgtScoreSel?Math.min(10,Math.max(7,parseFloat(tgtScoreSel.value)||10)):10;\nvar tgtRatio=tgtScore/10;\nvar tgtCorrectCount=Math.round(totalPackages*tgtRatio);\nvar wrongSet=new Set();for(var wi=tgtCorrectCount;wi<totalPackages;wi++)wrongSet.add(wi);\nvar now=Math.floor(Date.now()/1000);\nvar totalSeconds,timeInit;\ntotalSeconds=calcSeconds;timeInit=now-totalSeconds;\nvar params=new URLSearchParams();\nvar fakeLog=[];\nvar max_tn_score=0,tn_score_calc=0,tl_max_calc=0;\nSESSION.raw_questions.forEach(function(q,i){\nvar subQuestions=findCorrectInfoCS(q);\nvar sub_count=subQuestions.length;\nvar is_tl=(q.q_type==18||q.type==18||q.q_type==11);\nvar final_score=sub_count;\nif(q.score!==undefined&&q.score!==null&&q.score!=='')final_score=parseFloat(q.score);\nelse if(q.point!==undefined&&q.point!==null&&q.point!=='')final_score=parseFloat(q.point);\nvar makeWrong=(tgtScore<10&&wrongSet.has(i));\nif(!isVideo){params.append('quiz_list[]',q.id||q._id);params.append('score_list['+(q.id||q._id)+']',final_score);}\nvar skillIDs=[].concat(Array.from(new Set(subQuestions.map(function(sq){return sq.skill;}).filter(function(s){return s!=null;}))));\nif(!isVideo)skillIDs.forEach(function(s){params.append('correct_skill[]',s);});\nif(isVideo||isExam){\nif(is_tl&&isExam){tl_max_calc+=final_score;fakeLog.push({answer:JSON.stringify(['Học sinh đã làm phần tự luận trên máy.']),label:[''],params:'{"js":"","order":[0]}',correct_skill:[],wrong_skill:[],type:[18],result:[0],idq:parseInt(q.id||q._id),score:final_score,chk:0});}\nelse{\nmax_tn_score+=final_score;if(!makeWrong)tn_score_calc+=final_score;\nvar ans_list=[],type_list=[],prs_list=[],resArr=[],mresult=[],listIdq=[],lbl_list=[];\nfor(var j=0;j<sub_count;j++){var sq=subQuestions[j];ans_list.push(JSON.stringify((sq.type===4||sq.type===13||sq.type===6)?sq.ans:(sq.ans[0]||'0')));type_list.push(sq.type||1);prs_list.push(JSON.stringify(buildParamsCS(sq)));resArr.push(makeWrong?0:1);mresult.push([makeWrong?0:1]);listIdq.push(sq.subId&&sq.subId.toString().length>5?sq.subId:'q'+j);var lbl='';if(!makeWrong&&sq.ans.length===1&&!isNaN(sq.ans[0])&&sq.type!==4&&sq.type!==13)lbl=['A','B','C','D','E'][parseInt(sq.ans[0])]||'';lbl_list.push(lbl);}\nvar logItem={answer:JSON.stringify(ans_list),label:sub_count===1?lbl_list:[],labels:lbl_list,params:sub_count===1?prs_list[0]:JSON.stringify({js:'',prs:prs_list,order:Array.from(Array(sub_count).keys())}),correct_skill:makeWrong?[]:skillIDs,wrong_skill:makeWrong?skillIDs:[],type:type_list,result:resArr,mresult:mresult,idq:parseInt(q.id||q._id),score:makeWrong?0:final_score};\nif(isExam){if(!makeWrong)logItem.chk=1;if(sub_count>1)logItem.list_idq=listIdq;}\nif(isVideo){logItem.marker=q.marker||(i+1);logItem.id=(q.id||q._id).toString();}\nfakeLog.push(logItem);\n}\n}else{\nvar qpa=[],apa=[];\nsubQuestions.forEach(function(sq){qpa.push(JSON.stringify(buildParamsCS(sq)));apa.push(JSON.stringify(sq.ans));});\nfakeLog.push({q_params:JSON.stringify(qpa),a_params:JSON.stringify(apa),result:makeWrong?0:1,correct:makeWrong?0:1,wrong:makeWrong?1:0,a_index:i,time_spent:Math.max(5,Math.round((totalSeconds/Math.max(1,totalPackages))*(0.55+Math.random()*0.8)))});\n}\n});\nparams.append('id_cate',SESSION.meta.id_cate);\nparams.append('id_courseware',SESSION.meta.id_courseware||SESSION.meta.id_cate);\nparams.append('id_user',SESSION.meta.id_user);\nparams.append('id_grade',window.grade||window.id_grade||'10');\nif(SESSION.meta.id_school)params.append('id_school',SESSION.meta.id_school);\nif(SESSION.meta.id_group)params.append('id_group',SESSION.meta.id_group);\nparams.append('type_vip','530');params.append('time_stored','0');params.append('date_end',now);\nparams.append('data_log',JSON.stringify(fakeLog));\nif(isVideo){var vl=SESSION.video_length||900;params.append('type','5');params.append('type_exam','0');params.append('total_time',vl);params.append('current_time',vl);params.append('time_spent',totalSeconds+2);params.append('score_10',tgtScore.toString());params.append('totalq',totalPackages);params.append('score',tn_score_calc);params.append('max_score',max_tn_score);params.append('answered',totalPackages);params.append('correct',tgtCorrectCount);params.append('count_problems',totalPackages);params.append('percent',Math.round(tgtScore*10).toString());params.append('pscore',tgtScore.toString());params.append('score_status',tgtScore.toString());var vLog={};vLog[timeInit]='start';vLog[timeInit+1]='start';vLog[timeInit+10]='reload';params.append('log',JSON.stringify(vLog));}\nelse if(isExam){params.append('time_init',timeInit);params.append('time_spent',totalSeconds);params.append('total_time',totalSeconds);params.append('current_time',totalSeconds);params.append('score',tn_score_calc);params.append('max_score',max_tn_score+tl_max_calc);params.append('tn_score',tn_score_calc);params.append('type_exam','1');params.append('correct',tn_score_calc);params.append('wrong',max_tn_score-tn_score_calc);params.append('name_user','');params.append('tl_score','0');params.append('times','0');params.append('iframe','false');var curT=timeInit+Math.floor(totalSeconds*0.1);var totalQs=SESSION.raw_questions.length;var usableTime=Math.max(10,totalSeconds-Math.floor(totalSeconds*0.1)-10);var baseInterval=usableTime/(totalQs||1);for(var c=0;c<totalQs;c++){curT+=Math.floor(baseInterval*(0.7+Math.random()*0.6));if(curT>=timeInit+totalSeconds)curT=timeInit+totalSeconds-2;params.append('choose_log['+c+'][ind]',c);params.append('choose_log['+c+'][t]',Math.floor(curT));params.append('choose_log['+c+'][l]',c+1);}}\nelse{params.append('time_init',timeInit);params.append('time_spent',totalSeconds);params.append('time_elapsed',totalSeconds);params.append('total_time',totalSeconds);params.append('current_time',totalSeconds);params.append('score',Math.round(tgtScore*10).toString());params.append('score_10',tgtScore.toString());params.append('star',Math.round(tgtScore*2).toString());params.append('theta','0');params.append('max_score','100');params.append('answered',totalPackages);params.append('correct',tgtCorrectCount);params.append('wrong',(totalPackages-tgtCorrectCount).toString());params.append('missed','0');params.append('count_problems',totalPackages);params.append('type','3');params.append('type_exam','0');var pLog={};pLog[timeInit]='start';pLog[timeInit+1]='start';params.append('log',JSON.stringify(pLog));}\nparams.append('count_redo','0');params.append('ended','1');params.append('save_star','1');\ntry{\naddLog('📤 Đang nộp bài lên OLM...','info');\nvar csrf=SESSION.meta.csrf_token||(document.querySelector('meta[name="csrf-token"]')&&document.querySelector('meta[name="csrf-token"]').getAttribute('content'))||'';\nvar response=await fetch('/course/teacher-static',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded; charset=UTF-8','x-csrf-token':csrf,'x-requested-with':'XMLHttpRequest'},body:params.toString()});\nif(!response.ok){addLog('❌ OLM trả lỗi HTTP '+response.status,'err');return false;}\nreturn true;\n}catch(err){addLog('❌ Lỗi kết nối OLM: '+err.message,'err');return false;}\n};\n`;

function buildModulePayload(sessionToken, key, hwid) {
  return encryptAnswers({
    src: watermarkSrc(PAYLOAD_MODULE_SRC, key, hwid),
    v: PAYLOAD_MODULE_VERSION
  }, sessionToken);
}

const CONNECTOR_MODULE_EMBEDDED_B64 = 'Y29uc3QgU0VSVkVSX0JBU0UgPSAnaHR0cHM6Ly9tb2RnYW1lLnZlcmNlbC5hcHAnOwpjb25zdCBBUElfU0VDUkVUID0gJ2E3ZjNjOWUxYjJkNDg1MDZmYWUxYzdkM2I5ZjBlMmE0YzZkOGYxYTNiNWU3YzlkMGYyYTRjNmU4YjFkM2Y1YTcnOwpjb25zdCBSRVFVRVNUX0VOQ1JZUFRJT04gPSBmYWxzZTsKKGZ1bmN0aW9uKCkgewogICd1c2Ugc3RyaWN0JzsKICBjb25zdCBMU19LRVkgPSAnX3RsX2Nvbm5fa2V5JzsKICBjb25zdCBMU19UWVBFID0gJ190bF9jb25uX3R5cGUnOwogIGNvbnN0IExTX0VYUCA9ICdfdGxfY29ubl9leHAnOwogIGNvbnN0IExTX1RIRU1FID0gJ190aWVwX3RoZW1lJzsKICBsZXQgQ1VSUkVOVF9LRVkgPSBudWxsOwogIGxldCBLRVlfU1RBVFVTID0gewogICAgdmFsaWQ6IGZhbHNlLAogICAgdHlwZTogbnVsbCwKICAgIGV4cGlyZXNfYXQ6IG51bGwKICB9OwogIGxldCBDVVJSRU5UX0RFVklDRSA9ICcnOwogIGNvbnN0IFNFU1NJT04gPSB7CiAgICByYXdfcXVlc3Rpb25zOiBbXSwKICAgIG1ldGE6IHsKICAgICAgaWRfdXNlcjogbnVsbCwKICAgICAgaWRfY2F0ZTogbnVsbCwKICAgICAgaWRfY291cnNld2FyZTogbnVsbCwKICAgICAgaWRfc2Nob29sOiBudWxsLAogICAgICBpZF9ncm91cDogbnVsbCwKICAgICAgY3NyZl90b2tlbjogbnVsbCwKICAgICAgc3ViamVjdF9uYW1lOiBudWxsLAogICAgICBleGVyY2lzZV90aXRsZTogbnVsbCwKICAgICAgc3ViamVjdF9pZDogbnVsbAogICAgfSwKICAgIGF1dG9fbW9kZTogJ3ByYWN0aWNlJywKICAgIHZpZGVvX2xlbmd0aDogOTAwLAogICAgYmFua0Fuc3dlcnM6IFtdLAogICAgYW5zRmlsZUFuc3dlcnM6IFtdCiAgfTsKICAvLyBbdjI2XSDEkOG7k25nIGLhu5kgw7QgIk7huqFwIGThu68gbGnhu4d1OiBOIGPDonUiIHRoZW8gc+G7kSBjw6J1IHRo4bqtdCAoY8OidSBBUEkgT0xNIGhv4bq3YyDEkcOhcCDDoW4ga2hvIHNlcnZlcikKICBsZXQgX2xhc3RPbG1Vc2VyID0gJyc7CiAgZnVuY3Rpb24gX3NldFFDb3VudChuKSB7CiAgICB0cnkgewogICAgICBjb25zdCBlbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1xY291bnQnKTsKICAgICAgaWYgKGVsKSBlbC50ZXh0Q29udGVudCA9IFN0cmluZyhuIHx8IDApOwogICAgfSBjYXRjaCAoXykge30KICB9CiAgZnVuY3Rpb24gX3JlZnJlc2hRQ291bnQoKSB7CiAgICB0cnkgewogICAgICBjb25zdCByYXcgPSAoU0VTU0lPTi5yYXdfcXVlc3Rpb25zIHx8IFtdKS5sZW5ndGg7CiAgICAgIGNvbnN0IGJhbmsgPSAoU0VTU0lPTi5iYW5rQW5zd2VycyB8fCBbXSkubGVuZ3RoOwogICAgICBjb25zdCBhbnNmID0gKFNFU1NJT04uYW5zRmlsZUFuc3dlcnMgfHwgW10pLmxlbmd0aDsKICAgICAgX3NldFFDb3VudChyYXcgfHwgTWF0aC5tYXgoYmFuaywgYW5zZikgfHwgMCk7CiAgICB9IGNhdGNoIChfKSB7fQogIH0KICBzZXRJbnRlcnZhbChfcmVmcmVzaFFDb3VudCwgMjUwMCk7CiAgbGV0IF9iYW5rRmFsbGJhY2tUaW1lciA9IG51bGw7CiAgbGV0IF9iYW5rUmV0cnkgPSAwOwogIGxldCBDVVJSRU5UX1RIRU1FID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oTFNfVEhFTUUpIHx8ICdkZWZhdWx0JzsKICBmdW5jdGlvbiBpc1ByZW1pdW1LZXkoKSB7CiAgICBjb25zdCB0ID0gKEtFWV9TVEFUVVMudHlwZSB8fCBfc0xTLmdldChMU19UWVBFKSB8fCAnJykudG9TdHJpbmcoKS50b1VwcGVyQ2FzZSgpOwogICAgcmV0dXJuIHQgPT09ICdQUkVNSVVNJyB8fCB0ID09PSAnVklQJyB8fCB0ID09PSAnVU5MSU1JVEVEJzsKICB9CiAgZnVuY3Rpb24gaGFuZGxlT2xtTWlzbWF0Y2goc2VydmVyT2xtLCBjdXJyZW50T2xtKSB7CiAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShMU19LRVkpOwogICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oTFNfVFlQRSk7CiAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShMU19FWFApOwogICAgQ1VSUkVOVF9LRVkgPSBudWxsOwogICAgS0VZX1NUQVRVUyA9IHsKICAgICAgdmFsaWQ6IGZhbHNlLAogICAgICB0eXBlOiBudWxsLAogICAgICBleHBpcmVzX2F0OiBudWxsCiAgICB9OwogICAgX3NlY1Nlc3Npb24gPSB7CiAgICAgIHRva2VuOiBudWxsLAogICAgICBleHA6IDAsCiAgICAgIGZwSGFzaDogbnVsbCwKICAgICAgc2VxOiAxCiAgICB9OwogICAgQ1VSUkVOVF9ERVZJQ0UgPSAnJzsKICAgIGNvbnN0IHBhbmVsRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtcGFuZWwnKTsKICAgIGNvbnN0IGZiID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLWZsb2F0QnRuJyk7CiAgICBpZiAocGFuZWxFbCkgcGFuZWxFbC5yZW1vdmUoKTsKICAgIGlmIChmYikgZmIucmVtb3ZlKCk7CiAgICBzaG93Q3VzdG9tTW9kYWwoewogICAgICBpY29uOiAn8J+aqycsCiAgICAgIHRpdGxlOiAnVMOASSBLSE/huqJOIE9MTSBLSMOUTkcgS0jhu5pQIScsCiAgICAgIGxpbmVzOiBbIGBLZXkgxJHGsOG7o2MgxJHEg25nIGvDvSBjaG8gdMOgaSBraG/huqNuOiA8Yj4ke3NlcnZlck9sbX08L2I+YCwgYFTDoGkga2hv4bqjbiBPTE0gaGnhu4duIHThuqFpOiA8Yj4ke2N1cnJlbnRPbG19PC9iPmAsIGDimqDvuI8gVnVpIGzDsm5nIMSRxINuZyBuaOG6rXAgxJHDum5nIHTDoGkga2hv4bqjbiBPTE0gxJHhu4Mgc+G7rSBk4bulbmcga2V5IG7DoHksYCwgYGhv4bq3YyBsacOqbiBo4buHIGFkbWluIMSR4buDIMSRxrDhu6NjIGjhu5cgdHLhu6MhYCBdLAogICAgICBvbk9rOiAoKSA9PiBidWlsZExvY2tTY3JlZW4oJ+KaoO+4jyBUw6BpIGtob+G6o24gT0xNIGtow7RuZyBraOG7m3AgduG7m2kga2V5IMSRw6MgxJHEg25nIGvDvSEnKQogICAgfSk7CiAgfQogIGZ1bmN0aW9uIGdldFRoZW1lQ29sb3JzKHRoZW1lKSB7CiAgICBjb25zdCBUID0gewogICAgICBkZWZhdWx0OiB7CiAgICAgICAgYzE6ICcjMDBmMmZlJywKICAgICAgICBjMjogJyM0ZmFjZmUnLAogICAgICAgIGJnT3ZlcmxheTogJ3JnYmEoMTMsMTcsMjMsMC45NSknLAogICAgICAgIGJnUGFuZWw6ICdyZ2JhKDEzLDE3LDIzLDAuODgpJywKICAgICAgICBib3JkZXI6ICdyZ2JhKDAsMjQyLDI1NCwwLjIpJywKICAgICAgICBib3JkZXJTdHJvbmc6ICdyZ2JhKDAsMjQyLDI1NCwwLjMpJywKICAgICAgICBib3JkZXJTdWJ0bGU6ICdyZ2JhKDAsMjQyLDI1NCwwLjEyKScsCiAgICAgICAgaGVhZGVyQmc6ICdsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLHJnYmEoMCwyNDIsMjU0LDAuMDcpLHJnYmEoNzksMTcyLDI1NCwwLjA0KSknLAogICAgICAgIGdsb3dDb2xvcjogJ3JnYmEoMCwyNDIsMjU0LDAuNDUpJywKICAgICAgICBnbG93U3Ryb25nOiAncmdiYSgwLDI0MiwyNTQsMC43KScsCiAgICAgICAgZ2xvd01pZDogJ3JnYmEoMCwyNDIsMjU0LDAuMjUpJywKICAgICAgICBnbG93U3VidGxlOiAncmdiYSgwLDI0MiwyNTQsMC4wOCknLAogICAgICAgIGdsb3dQdWxzZTogJ3JnYmEoMCwyNDIsMjU0LDAuNTUpJywKICAgICAgICBpbnB1dEJvcmRlcjogJ3JnYmEoMCwyNDIsMjU0LDAuNCknLAogICAgICAgIGlucHV0Q29sb3I6ICcjMDBmMmZlJywKICAgICAgICBmbG9hdEdyYWRpZW50OiAnbGluZWFyLWdyYWRpZW50KDEzNWRlZywjMDBmMmZlLCM0ZmFjZmUpJywKICAgICAgICBicmFuZEdyYWRpZW50OiAnbGluZWFyLWdyYWRpZW50KDkwZGVnLCMwMGYyZmUsIzRmYWNmZSwjMDBmMmZlKScsCiAgICAgICAgc3RhdHVzQm9yZGVyOiAncmdiYSgwLDIzMCwxMjAsMC4yNSknLAogICAgICAgIHN0YXR1c0JnOiAncmdiYSgwLDIzMCwxMjAsMC4wNCknLAogICAgICAgIHBhbmVsSW5zZXQ6ICdyZ2JhKDAsMjQyLDI1NCwwLjA4KScsCiAgICAgICAgc2VsZWN0Qm9yZGVyOiAncmdiYSgwLDI0MiwyNTQsMC4yKScsCiAgICAgICAgY29uc29sZUJvcmRlcjogJ3JnYmEoMCwyNDIsMjU0LDAuMTIpJywKICAgICAgICBmeENTUzogJycsCiAgICAgICAgcGFuZWxFeHRyYTogJycsCiAgICAgICAgdGhlbWVMYWJlbDogJ/CflLUgTeG6t2MgxJDhu4tuaCcsCiAgICAgICAgcHJldmlld0JnOiAnbGluZWFyLWdyYWRpZW50KDEzNWRlZywjMDAxNTIwLCMwMGYyZmU1NSknLAogICAgICAgIHByZXZpZXdCb3JkZXI6ICdyZ2JhKDAsMjQyLDI1NCwwLjUpJywKICAgICAgICBwcmV2aWV3VGV4dDogJyMwMGYyZmUnCiAgICAgIH0sCiAgICAgIGdyYXk6IHsKICAgICAgICBjMTogJyNlMGUwZTAnLAogICAgICAgIGMyOiAnI2EwYTBhMCcsCiAgICAgICAgYmdPdmVybGF5OiAncmdiYSgxMCwxMCwxMCwwLjk3KScsCiAgICAgICAgYmdQYW5lbDogJ3JnYmEoMjAsMjAsMjAsMC45NCknLAogICAgICAgIGJvcmRlcjogJ3JnYmEoMjAwLDIwMCwyMDAsMC4xOCknLAogICAgICAgIGJvcmRlclN0cm9uZzogJ3JnYmEoMjMwLDIzMCwyMzAsMC4zKScsCiAgICAgICAgYm9yZGVyU3VidGxlOiAncmdiYSgxNzAsMTcwLDE3MCwwLjEpJywKICAgICAgICBoZWFkZXJCZzogJ2xpbmVhci1ncmFkaWVudCgxMzVkZWcscmdiYSgxMjAsMTIwLDEyMCwwLjEyKSxyZ2JhKDYwLDYwLDYwLDAuMDUpKScsCiAgICAgICAgZ2xvd0NvbG9yOiAncmdiYSgyMTAsMjEwLDIxMCwwLjM1KScsCiAgICAgICAgZ2xvd1N0cm9uZzogJ3JnYmEoMjIwLDIyMCwyMjAsMC42KScsCiAgICAgICAgZ2xvd01pZDogJ3JnYmEoMjAwLDIwMCwyMDAsMC4yKScsCiAgICAgICAgZ2xvd1N1YnRsZTogJ3JnYmEoMTYwLDE2MCwxNjAsMC4wNyknLAogICAgICAgIGdsb3dQdWxzZTogJ3JnYmEoMjAwLDIwMCwyMDAsMC40NSknLAogICAgICAgIGlucHV0Qm9yZGVyOiAncmdiYSgyMDAsMjAwLDIwMCwwLjM4KScsCiAgICAgICAgaW5wdXRDb2xvcjogJyNkOGQ4ZDgnLAogICAgICAgIGZsb2F0R3JhZGllbnQ6ICdsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLCNjMGMwYzAsIzY2NiknLAogICAgICAgIGJyYW5kR3JhZGllbnQ6ICdsaW5lYXItZ3JhZGllbnQoOTBkZWcsI2MwYzBjMCwjZmZmZmZmLCNkMGQwZDAsI2MwYzBjMCknLAogICAgICAgIHN0YXR1c0JvcmRlcjogJ3JnYmEoMTYwLDE2MCwxNjAsMC4yKScsCiAgICAgICAgc3RhdHVzQmc6ICdyZ2JhKDYwLDYwLDYwLDAuMDcpJywKICAgICAgICBwYW5lbEluc2V0OiAncmdiYSgyMDAsMjAwLDIwMCwwLjA3KScsCiAgICAgICAgc2VsZWN0Qm9yZGVyOiAncmdiYSgxOTAsMTkwLDE5MCwwLjIpJywKICAgICAgICBjb25zb2xlQm9yZGVyOiAncmdiYSgxNjAsMTYwLDE2MCwwLjEpJywKICAgICAgICBmeENTUzogYFxuICAgICAgICAgICAgICAgICAgICAjdGwtY29ubi1meC1iYXIgeyBoZWlnaHQ6MnB4OyBiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCg5MGRlZyx0cmFuc3BhcmVudCxyZ2JhKDI1NSwyNTUsMjU1LDAuMDgpLHJnYmEoMjU1LDI1NSwyNTUsMC41NSkscmdiYSgyNTUsMjU1LDI1NSwwLjA4KSx0cmFuc3BhcmVudCk7IGJhY2tncm91bmQtc2l6ZTozMDAlIDEwMCU7IGFuaW1hdGlvbjptZXRhbFN3ZWVwIDIuOHMgbGluZWFyIGluZmluaXRlOyB9XG4gICAgICAgICAgICAgICAgICAgIEBrZXlmcmFtZXMgbWV0YWxTd2VlcCB7IDAle2JhY2tncm91bmQtcG9zaXRpb246MTAwJSAwfSAxMDAle2JhY2tncm91bmQtcG9zaXRpb246LTIwMCUgMH0gfVxuICAgICAgICAgICAgICAgICAgICAjdGwtcGFuZWwgeyBib3gtc2hhZG93OiAwIDAgNjBweCByZ2JhKDAsMCwwLDAuODUpLCAwIDAgMzBweCByZ2JhKDE4MCwxODAsMTgwLDAuMDYpLCBpbnNldCAwIDFweCAwIHJnYmEoMjU1LDI1NSwyNTUsMC4wOCk7IH1cbiAgICAgICAgICAgICAgICAgICAgI3RsLWNvbm4tcGFuZWwgeyBib3gtc2hhZG93OiAwIDAgNjBweCByZ2JhKDAsMCwwLDAuODUpLCBpbnNldCAwIDFweCAwIHJnYmEoMjU1LDI1NSwyNTUsMC4wOCk7IH1cbiAgICAgICAgICAgICAgICBgLAogICAgICAgIHBhbmVsRXh0cmE6ICc8ZGl2IGlkPSJ0bC1jb25uLWZ4LWJhciI+PC9kaXY+JywKICAgICAgICB0aGVtZUxhYmVsOiAn4pqrIFjDoW0gQuG6oWMnLAogICAgICAgIHByZXZpZXdCZzogJ2xpbmVhci1ncmFkaWVudCgxMzVkZWcsIzFhMWExYSwjNjY2KScsCiAgICAgICAgcHJldmlld0JvcmRlcjogJ3JnYmEoMjIwLDIyMCwyMjAsMC40NSknLAogICAgICAgIHByZXZpZXdUZXh0OiAnI2UwZTBlMCcKICAgICAgfSwKICAgICAgcGluazogewogICAgICAgIGMxOiAnI2ZmNmViNCcsCiAgICAgICAgYzI6ICcjZmYxNDkzJywKICAgICAgICBiZ092ZXJsYXk6ICdyZ2JhKDE4LDQsMTQsMC45NyknLAogICAgICAgIGJnUGFuZWw6ICdyZ2JhKDI2LDQsMTgsMC45MyknLAogICAgICAgIGJvcmRlcjogJ3JnYmEoMjU1LDExMCwxODAsMC4yKScsCiAgICAgICAgYm9yZGVyU3Ryb25nOiAncmdiYSgyNTUsMTEwLDE4MCwwLjM4KScsCiAgICAgICAgYm9yZGVyU3VidGxlOiAncmdiYSgyNTUsMTEwLDE4MCwwLjEyKScsCiAgICAgICAgaGVhZGVyQmc6ICdsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLHJnYmEoMjU1LDExMCwxODAsMC4wOSkscmdiYSgyNTUsMjAsMTQ3LDAuMDQpKScsCiAgICAgICAgZ2xvd0NvbG9yOiAncmdiYSgyNTUsMTEwLDE4MCwwLjQ1KScsCiAgICAgICAgZ2xvd1N0cm9uZzogJ3JnYmEoMjU1LDExMCwxODAsMC43NSknLAogICAgICAgIGdsb3dNaWQ6ICdyZ2JhKDI1NSwxMTAsMTgwLDAuMjIpJywKICAgICAgICBnbG93U3VidGxlOiAncmdiYSgyNTUsMjAsMTQ3LDAuMDcpJywKICAgICAgICBnbG93UHVsc2U6ICdyZ2JhKDI1NSwxMTAsMTgwLDAuNTUpJywKICAgICAgICBpbnB1dEJvcmRlcjogJ3JnYmEoMjU1LDExMCwxODAsMC40MiknLAogICAgICAgIGlucHV0Q29sb3I6ICcjZmZiM2Q5JywKICAgICAgICBmbG9hdEdyYWRpZW50OiAnbGluZWFyLWdyYWRpZW50KDEzNWRlZywjZmY2ZWI0LCNmZjE0OTMpJywKICAgICAgICBicmFuZEdyYWRpZW50OiAnbGluZWFyLWdyYWRpZW50KDkwZGVnLCNmZjZlYjQsI2ZmY2NlOCwjZmYxNDkzLCNmZjZlYjQpJywKICAgICAgICBzdGF0dXNCb3JkZXI6ICdyZ2JhKDI1NSwxMTAsMTgwLDAuMiknLAogICAgICAgIHN0YXR1c0JnOiAncmdiYSgyNTUsMjAsMTQ3LDAuMDUpJywKICAgICAgICBwYW5lbEluc2V0OiAncmdiYSgyNTUsMTEwLDE4MCwwLjEpJywKICAgICAgICBzZWxlY3RCb3JkZXI6ICdyZ2JhKDI1NSwxMTAsMTgwLDAuMiknLAogICAgICAgIGNvbnNvbGVCb3JkZXI6ICdyZ2JhKDI1NSwxMTAsMTgwLDAuMTIpJywKICAgICAgICBmeENTUzogYFxuICAgICAgICAgICAgICAgICAgICAjdGwtcGFuZWwgeyBhbmltYXRpb246c2FrdXJhUGFuZWxHbG93IDNzIGVhc2UtaW4tb3V0IGluZmluaXRlOyB9XG4gICAgICAgICAgICAgICAgICAgICN0bC1jb25uLXBhbmVsIHsgYW5pbWF0aW9uOnNha3VyYVBhbmVsR2xvdyAzcyBlYXNlLWluLW91dCBpbmZpbml0ZTsgfVxuICAgICAgICAgICAgICAgICAgICBAa2V5ZnJhbWVzIHNha3VyYVBhbmVsR2xvdyB7XG4gICAgICAgICAgICAgICAgICAgICAgICAwJSwxMDAleyBib3gtc2hhZG93OjAgMCA2MHB4IHJnYmEoMCwwLDAsMC44KSwwIDAgMjVweCByZ2JhKDI1NSwxMTAsMTgwLDAuMSksaW5zZXQgMCAwIDAgMXB4IHJnYmEoMjU1LDExMCwxODAsMC4wNik7IH1cbiAgICAgICAgICAgICAgICAgICAgICAgIDUwJXsgYm94LXNoYWRvdzowIDAgNjBweCByZ2JhKDAsMCwwLDAuOCksMCAwIDQ1cHggcmdiYSgyNTUsMTEwLDE4MCwwLjIpLGluc2V0IDAgMCAwIDFweCByZ2JhKDI1NSwxMTAsMTgwLDAuMTIpOyB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgLnNha3VyYS1wZXRhbCB7IHBvc2l0aW9uOmFic29sdXRlOyBwb2ludGVyLWV2ZW50czpub25lOyBib3JkZXItcmFkaXVzOjUwJSAwIDUwJSAwOyBiYWNrZ3JvdW5kOnJnYmEoMjU1LDExMCwxODAsMC4yMik7IGFuaW1hdGlvbjpzYWt1cmFEcmlmdCBsaW5lYXIgaW5maW5pdGU7IH1cbiAgICAgICAgICAgICAgICAgICAgQGtleWZyYW1lcyBzYWt1cmFEcmlmdCB7IDAle3RyYW5zZm9ybTp0cmFuc2xhdGVZKC0xMHB4KSByb3RhdGUoMGRlZyk7b3BhY2l0eTowLjd9IDEwMCV7dHJhbnNmb3JtOnRyYW5zbGF0ZVkoNDIwcHgpIHJvdGF0ZSgyNzBkZWcpO29wYWNpdHk6MH0gfVxuICAgICAgICAgICAgICAgICAgICAjdGwtY29ubi1meC1wZXRhbHMgeyBwb3NpdGlvbjphYnNvbHV0ZTt0b3A6MDtsZWZ0OjA7cmlnaHQ6MDtoZWlnaHQ6MTAwJTtwb2ludGVyLWV2ZW50czpub25lO292ZXJmbG93OmhpZGRlbjt6LWluZGV4OjA7Ym9yZGVyLXJhZGl1czoxNnB4OyB9XG4gICAgICAgICAgICAgICAgYCwKICAgICAgICBwYW5lbEV4dHJhOiBgPGRpdiBpZD0idGwtY29ubi1meC1wZXRhbHMiPlxuICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJzYWt1cmEtcGV0YWwiIHN0eWxlPSJ3aWR0aDo3cHg7aGVpZ2h0OjdweDtsZWZ0OjglO3RvcDotMTBweDthbmltYXRpb24tZHVyYXRpb246My44czthbmltYXRpb24tZGVsYXk6MHM7Ij48L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0ic2FrdXJhLXBldGFsIiBzdHlsZT0id2lkdGg6NXB4O2hlaWdodDo1cHg7bGVmdDoyOCU7dG9wOi0xMHB4O2FuaW1hdGlvbi1kdXJhdGlvbjo1LjFzO2FuaW1hdGlvbi1kZWxheTowLjlzOyI+PC9kaXY+XG4gICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InNha3VyYS1wZXRhbCIgc3R5bGU9IndpZHRoOjhweDtoZWlnaHQ6OHB4O2xlZnQ6NTUlO3RvcDotMTBweDthbmltYXRpb24tZHVyYXRpb246NC40czthbmltYXRpb24tZGVsYXk6MS43czsiPjwvZGl2PlxuICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJzYWt1cmEtcGV0YWwiIHN0eWxlPSJ3aWR0aDo0cHg7aGVpZ2h0OjRweDtsZWZ0Ojc1JTt0b3A6LTEwcHg7YW5pbWF0aW9uLWR1cmF0aW9uOjMuMnM7YW5pbWF0aW9uLWRlbGF5OjAuNHM7Ij48L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0ic2FrdXJhLXBldGFsIiBzdHlsZT0id2lkdGg6NnB4O2hlaWdodDo2cHg7bGVmdDo5MiU7dG9wOi0xMHB4O2FuaW1hdGlvbi1kdXJhdGlvbjo0LjlzO2FuaW1hdGlvbi1kZWxheToyLjFzOyI+PC9kaXY+XG4gICAgICAgICAgICAgICAgPC9kaXY+YCwKICAgICAgICB0aGVtZUxhYmVsOiAn8J+MuCBI4buTbmcgU2FrdXJhJywKICAgICAgICBwcmV2aWV3Qmc6ICdsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLCMxYTA1MTAsI2ZmNmViNDU1KScsCiAgICAgICAgcHJldmlld0JvcmRlcjogJ3JnYmEoMjU1LDExMCwxODAsMC41NSknLAogICAgICAgIHByZXZpZXdUZXh0OiAnI2ZmNmViNCcKICAgICAgfQogICAgfTsKICAgIHJldHVybiBUW3RoZW1lXSB8fCBULmRlZmF1bHQ7CiAgfQogIGZ1bmN0aW9uIGdldExvY2tTY3JlZW5TdHlsZXMoKSB7CiAgICBjb25zdCB0YyA9IGdldFRoZW1lQ29sb3JzKENVUlJFTlRfVEhFTUUpOwogICAgcmV0dXJuIGBcbiAgICAgICAgICAgIEBpbXBvcnQgdXJsKCdodHRwczovL2ZvbnRzLmdvb2dsZWFwaXMuY29tL2NzczI/ZmFtaWx5PU9yYml0cm9uOndnaHRANDAwOzcwMDs5MDAmZmFtaWx5PVNoYXJlK1RlY2grTW9ubyZmYW1pbHk9UmFqZGhhbmk6d2dodEA0MDA7NjAwOzcwMCZkaXNwbGF5PXN3YXAnKTtcbiAgICAgICAgICAgICN0bC1jb25uLW92ZXJsYXkgeyBwb3NpdGlvbjpmaXhlZDt0b3A6MDtsZWZ0OjA7d2lkdGg6MTAwdnc7aGVpZ2h0OjEwMHZoO2JhY2tncm91bmQ6JHt0Yy5iZ092ZXJsYXl9O2JhY2tkcm9wLWZpbHRlcjpibHVyKDE1cHgpO3otaW5kZXg6MjE0NzQ4MzY0NztkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpjZW50ZXI7Zm9udC1mYW1pbHk6J1JhamRoYW5pJyxzYW5zLXNlcmlmOyB9XG4gICAgICAgICAgICAjdGwtY29ubi1wYW5lbCB7IHdpZHRoOjQyMHB4O2JhY2tncm91bmQ6JHt0Yy5iZ1BhbmVsfTtib3JkZXI6MXB4IHNvbGlkICR7dGMuYm9yZGVyU3Ryb25nfTtib3JkZXItcmFkaXVzOjIwcHg7Ym94LXNoYWRvdzowIDAgNjBweCByZ2JhKDAsMCwwLDAuOCksMCAwIDAgMXB4ICR7dGMucGFuZWxJbnNldH0gaW5zZXQ7dGV4dC1hbGlnbjpjZW50ZXI7b3ZlcmZsb3c6aGlkZGVuO2FuaW1hdGlvbjp0bEZhZGVJbiAwLjNzIGVhc2U7cG9zaXRpb246cmVsYXRpdmU7IH1cbiAgICAgICAgICAgIEBrZXlmcmFtZXMgdGxGYWRlSW4geyBmcm9te29wYWNpdHk6MDt0cmFuc2Zvcm06c2NhbGUoMC45NSl9dG97b3BhY2l0eToxO3RyYW5zZm9ybTpzY2FsZSgxKX0gfVxuICAgICAgICAgICAgI3RsLWNvbm4taGVhZGVyIHsgcGFkZGluZzoyMnB4O2JhY2tncm91bmQ6JHt0Yy5oZWFkZXJCZ307Ym9yZGVyLWJvdHRvbToxcHggc29saWQgJHt0Yy5ib3JkZXJ9OyB9XG4gICAgICAgICAgICAudGwtYnJhbmQtbmFtZSB7IGZvbnQtZmFtaWx5OidPcmJpdHJvbicsc2Fucy1zZXJpZjtmb250LXNpemU6MjJweDtmb250LXdlaWdodDo3MDA7YmFja2dyb3VuZDoke3RjLmJyYW5kR3JhZGllbnR9O2JhY2tncm91bmQtc2l6ZToyMDAlOy13ZWJraXQtYmFja2dyb3VuZC1jbGlwOnRleHQ7LXdlYmtpdC10ZXh0LWZpbGwtY29sb3I6dHJhbnNwYXJlbnQ7YW5pbWF0aW9uOnRsU2hpbW1lciAzcyBsaW5lYXIgaW5maW5pdGU7IH1cbiAgICAgICAgICAgIEBrZXlmcmFtZXMgdGxTaGltbWVyIHsgMTAwJXtiYWNrZ3JvdW5kLXBvc2l0aW9uOjIwMCUgNTAlfSB9XG4gICAgICAgICAgICAjdGwtY29ubi1ib2R5IHsgcGFkZGluZzozMHB4IDI1cHg7IH1cbiAgICAgICAgICAgIC50bC1zdWJ0aXRsZSB7IGNvbG9yOnJnYmEoMjU1LDI1NSwyNTUsMC43KTtmb250LXNpemU6MTNweDttYXJnaW4tYm90dG9tOjEwcHg7Zm9udC1mYW1pbHk6J1NoYXJlIFRlY2ggTW9ubyc7IH1cbiAgICAgICAgICAgIC50bC13YXJuaW5nIHsgY29sb3I6I2ZmYzEwNztmb250LXNpemU6MTJweDttYXJnaW4tYm90dG9tOjIwcHg7YmFja2dyb3VuZDpyZ2JhKDI1NSwxOTMsNywwLjEpO3BhZGRpbmc6OHB4O2JvcmRlci1yYWRpdXM6NnB4OyB9XG4gICAgICAgICAgICAudGwtaW5wdXQgeyB3aWR0aDoxMDAlO3BhZGRpbmc6MTRweDtiYWNrZ3JvdW5kOnJnYmEoMCwwLDAsMC41NSk7Ym9yZGVyOjFweCBzb2xpZCAke3RjLmlucHV0Qm9yZGVyfTtib3JkZXItcmFkaXVzOjEwcHg7Y29sb3I6JHt0Yy5pbnB1dENvbG9yfTtmb250LWZhbWlseTonU2hhcmUgVGVjaCBNb25vJztmb250LXNpemU6MTZweDt0ZXh0LWFsaWduOmNlbnRlcjttYXJnaW4tYm90dG9tOjE1cHg7dHJhbnNpdGlvbjowLjJzO2JveC1zaXppbmc6Ym9yZGVyLWJveDsgfVxuICAgICAgICAgICAgLnRsLWlucHV0OmZvY3VzIHsgb3V0bGluZTpub25lO2JvcmRlci1jb2xvcjoke3RjLmMxfTtib3gtc2hhZG93OjAgMCAxNnB4ICR7dGMuZ2xvd01pZH07IH1cbiAgICAgICAgICAgIC50bC1idG4geyB3aWR0aDoxMDAlO3BhZGRpbmc6MTRweDtib3JkZXI6bm9uZTtib3JkZXItcmFkaXVzOjEwcHg7Y3Vyc29yOnBvaW50ZXI7Zm9udC1mYW1pbHk6J09yYml0cm9uJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZToxNHB4O2ZvbnQtd2VpZ2h0OjkwMDttYXJnaW4tYm90dG9tOjEycHg7dHJhbnNpdGlvbjowLjJzOyB9XG4gICAgICAgICAgICAudGwtYnRuLXVubG9jayB7IGJhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDEzNWRlZywjMDBiMDliLCM5NmM5M2QpO2NvbG9yOiNmZmY7IH1cbiAgICAgICAgICAgIC50bC1idG4tdW5sb2NrOmhvdmVyIHsgdHJhbnNmb3JtOnNjYWxlKDEuMDIpO2JveC1zaGFkb3c6MCAwIDI1cHggcmdiYSgwLDE3NiwxNTUsMC42KTsgfVxuICAgICAgICAgICAgLnRsLWJ0bi12aXAgeyBiYWNrZ3JvdW5kOnJnYmEoMjE3LDQsNDEsMC4xKTtib3JkZXI6MXB4IHNvbGlkIHJnYmEoMjE3LDQsNDEsMC41KTtjb2xvcjojZWYyMzNjOyB9XG4gICAgICAgICAgICAudGwtYnRuLXZpcDpob3ZlciB7IGJhY2tncm91bmQ6cmdiYSgyMTcsNCw0MSwwLjIpO3RyYW5zZm9ybTpzY2FsZSgxLjAxKTsgfVxuICAgICAgICAgICAgI3RsLWVyciB7IGNvbG9yOiNlZjIzM2M7Zm9udC1zaXplOjEzcHg7bWFyZ2luLXRvcDoxMnB4O2Rpc3BsYXk6bm9uZTtmb250LWZhbWlseTonU2hhcmUgVGVjaCBNb25vJztiYWNrZ3JvdW5kOnJnYmEoMjM5LDM1LDYwLDAuMSk7cGFkZGluZzo4cHg7Ym9yZGVyLXJhZGl1czo2cHg7IH1cbiAgICAgICAgICAgIC50bC1od2lkIHsgY29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjIyKTtmb250LXNpemU6MTBweDttYXJnaW4tdG9wOjE1cHg7d29yZC1icmVhazpicmVhay1hbGw7Zm9udC1mYW1pbHk6bW9ub3NwYWNlOyB9XG4gICAgICAgICAgICAudGwtZm9vdCB7IG1hcmdpbi10b3A6MTVweDtmb250LXNpemU6MTFweDtjb2xvcjpyZ2JhKDI1NSwyNTUsMjU1LDAuMTMpOyB9XG4gICAgICAgICAgICAke3RjLmZ4Q1NTfVxuICAgICAgICBgOwogIH0KICBmdW5jdGlvbiBnZXRNYWluVUlTdHlsZXMoKSB7CiAgICBjb25zdCB0YyA9IGdldFRoZW1lQ29sb3JzKENVUlJFTlRfVEhFTUUpOwogICAgcmV0dXJuIGBcbiAgICAgICAgICAgIEBpbXBvcnQgdXJsKCdodHRwczovL2ZvbnRzLmdvb2dsZWFwaXMuY29tL2NzczI/ZmFtaWx5PU9yYml0cm9uOndnaHRANDAwOzcwMDs5MDAmZmFtaWx5PVNoYXJlK1RlY2grTW9ubyZmYW1pbHk9UmFqZGhhbmk6d2dodEA0MDA7NjAwOzcwMCZkaXNwbGF5PXN3YXAnKTtcbiAgICAgICAgICAgICN0bC1mbG9hdEJ0biB7IHBvc2l0aW9uOmZpeGVkO2JvdHRvbToyOHB4O3JpZ2h0OjI4cHg7d2lkdGg6NTZweDtoZWlnaHQ6NTZweDtib3JkZXItcmFkaXVzOjUwJTtib3JkZXI6bm9uZTtjdXJzb3I6cG9pbnRlcjt6LWluZGV4OjEwMDAwO2JhY2tncm91bmQ6JHt0Yy5mbG9hdEdyYWRpZW50fTtib3gtc2hhZG93OjAgMCAwIDAgJHt0Yy5nbG93U3Ryb25nfSwwIDAgMjBweCAke3RjLmdsb3dDb2xvcn0sMCA0cHggMjBweCByZ2JhKDAsMCwwLDAuNSk7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyO2ZvbnQtc2l6ZToyMnB4O3RyYW5zaXRpb246dHJhbnNmb3JtIDAuMnMgZWFzZSxib3gtc2hhZG93IDAuMnMgZWFzZTthbmltYXRpb246Y29ublB1bHNlUmluZyAyLjVzIGVhc2Utb3V0IGluZmluaXRlOyB9XG4gICAgICAgICAgICAjdGwtZmxvYXRCdG46aG92ZXIgeyB0cmFuc2Zvcm06c2NhbGUoMS4xMikgcm90YXRlKDE1ZGVnKTsgfVxuICAgICAgICAgICAgQGtleWZyYW1lcyBjb25uUHVsc2VSaW5nIHsgMCV7Ym94LXNoYWRvdzowIDAgMCAwICR7dGMuZ2xvd1B1bHNlfX03MCV7Ym94LXNoYWRvdzowIDAgMCAxNXB4IHJnYmEoMCwwLDAsMCl9MTAwJXtib3gtc2hhZG93OjAgMCAwIDAgcmdiYSgwLDAsMCwwKX0gfVxuICAgICAgICAgICAgQGtleWZyYW1lcyBjb25uQmxpbmsgeyAwJSwxMDAle29wYWNpdHk6MX01MCV7b3BhY2l0eTowLjN9IH1cbiAgICAgICAgICAgICN0bC1wYW5lbCB7IHBvc2l0aW9uOmZpeGVkO3RvcDo1MCU7bGVmdDo1MCU7dHJhbnNmb3JtOnRyYW5zbGF0ZSgtNTAlLC01MCUpO3dpZHRoOjM2MHB4O2JhY2tncm91bmQ6JHt0Yy5iZ1BhbmVsfTtiYWNrZHJvcC1maWx0ZXI6Ymx1cigyNHB4KTtib3JkZXI6MXB4IHNvbGlkICR7dGMuYm9yZGVyfTtib3JkZXItcmFkaXVzOjE2cHg7Ym94LXNoYWRvdzowIDAgNjBweCByZ2JhKDAsMCwwLDAuOCk7ei1pbmRleDo5OTk5O292ZXJmbG93OmhpZGRlbjtmb250LWZhbWlseTonUmFqZGhhbmknLHNhbnMtc2VyaWY7IH1cbiAgICAgICAgICAgICN0bC1wYW5lbC5oaWRkZW4geyBkaXNwbGF5Om5vbmU7IH1cbiAgICAgICAgICAgICN0bC1wLWhlYWRlciB7IGN1cnNvcjptb3ZlO3BhZGRpbmc6MTRweCAxNnB4IDEycHg7YmFja2dyb3VuZDoke3RjLmhlYWRlckJnfTtib3JkZXItYm90dG9tOjFweCBzb2xpZCAke3RjLmJvcmRlclN1YnRsZX07ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2VlbjsgfVxuICAgICAgICAgICAgLnRsLXAtYnJhbmQgeyBkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDo4cHg7IH1cbiAgICAgICAgICAgIC50bC1wLW5hbWUgeyBmb250LWZhbWlseTonT3JiaXRyb24nLHNhbnMtc2VyaWY7Zm9udC1zaXplOjExLjVweDtmb250LXdlaWdodDo3MDA7YmFja2dyb3VuZDoke3RjLmJyYW5kR3JhZGllbnR9O2JhY2tncm91bmQtc2l6ZToyMDAlOy13ZWJraXQtYmFja2dyb3VuZC1jbGlwOnRleHQ7LXdlYmtpdC10ZXh0LWZpbGwtY29sb3I6dHJhbnNwYXJlbnQ7YW5pbWF0aW9uOnRsU2hpbW1lciAzcyBsaW5lYXIgaW5maW5pdGU7IH1cbiAgICAgICAgICAgIEBrZXlmcmFtZXMgdGxTaGltbWVyIHsgMTAwJXtiYWNrZ3JvdW5kLXBvc2l0aW9uOjIwMCUgNTAlfSB9XG4gICAgICAgICAgICAudGwtYmFkZ2UgeyBmb250LWZhbWlseTonT3JiaXRyb24nO2ZvbnQtc2l6ZTo3LjVweDtmb250LXdlaWdodDo5MDA7Y29sb3I6I2ZmZjtib3JkZXItcmFkaXVzOjRweDtwYWRkaW5nOjNweCA2cHg7YmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLCM1NTUsIzc3Nyk7IH1cbiAgICAgICAgICAgIC50bC1iYWRnZS52aXAgeyBiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCgxMzVkZWcsI2E4NTVmNywjNjM2NmYxKTtib3gtc2hhZG93OjAgMCAxMHB4IHJnYmEoMTY4LDg1LDI0NywwLjQpOyB9XG4gICAgICAgICAgICAudGwtYmFkZ2UudW5saW1pdGVkIHsgYmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLCNmNTllMGIsI2VmNDQ0NCk7Ym94LXNoYWRvdzowIDAgMTBweCByZ2JhKDI0NSwxNTgsMTEsMC40KTsgfVxuICAgICAgICAgICAgI3RsLWNsb3NlQnRuLCN0bC1zZXR0aW5nc0J0biB7IHdpZHRoOjI4cHg7aGVpZ2h0OjI4cHg7Ym9yZGVyLXJhZGl1czo1MCU7Ym9yZGVyOjFweCBzb2xpZCByZ2JhKDI1NSwyNTUsMjU1LDAuMSk7YmFja2dyb3VuZDpyZ2JhKDI1NSwyNTUsMjU1LDAuMDQpO2NvbG9yOnJnYmEoMjU1LDI1NSwyNTUsMC41KTtjdXJzb3I6cG9pbnRlcjtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpjZW50ZXI7dHJhbnNpdGlvbjowLjJzO2ZvbnQtc2l6ZToxM3B4OyB9XG4gICAgICAgICAgICAjdGwtY2xvc2VCdG46aG92ZXIgeyBib3JkZXItY29sb3I6cmdiYSgyMTcsNCw0MSwwLjYpO2JhY2tncm91bmQ6cmdiYSgyMTcsNCw0MSwwLjE1KTtjb2xvcjojZWYyMzNjOyB9XG4gICAgICAgICAgICAjdGwtc2V0dGluZ3NCdG46aG92ZXIgeyBib3JkZXItY29sb3I6JHt0Yy5ib3JkZXJTdHJvbmd9O2JhY2tncm91bmQ6JHt0Yy5nbG93U3VidGxlfTtjb2xvcjoke3RjLmMxfTsgfVxuICAgICAgICAgICAgI3RsLXNldHRpbmdzQnRuLmFjdGl2ZSB7IGJvcmRlci1jb2xvcjoke3RjLmMxfTtiYWNrZ3JvdW5kOiR7dGMuZ2xvd1N1YnRsZX07Y29sb3I6JHt0Yy5jMX07IH1cbiAgICAgICAgICAgICN0bC1wLWJvZHkgeyBwYWRkaW5nOjE0cHg7ZGlzcGxheTpmbGV4O2ZsZXgtZGlyZWN0aW9uOmNvbHVtbjtnYXA6MTJweDsgfVxuICAgICAgICAgICAgLnRsLXN0YXRib3ggeyBib3JkZXI6MXB4IHNvbGlkICR7dGMuc3RhdHVzQm9yZGVyfTtib3JkZXItcmFkaXVzOjEwcHg7cGFkZGluZzoxMHB4O2JhY2tncm91bmQ6JHt0Yy5zdGF0dXNCZ307IH1cbiAgICAgICAgICAgIC50bC1zdGF0cm93IHsgZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6OHB4O2ZvbnQtZmFtaWx5OidTaGFyZSBUZWNoIE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6MTEuNXB4O2NvbG9yOiNjY2M7bWFyZ2luLXRvcDo0cHg7IH1cbiAgICAgICAgICAgICN0bC1tb2RlU2VsZWN0IHsgd2lkdGg6MTAwJTtwYWRkaW5nOjEwcHg7YmFja2dyb3VuZDpyZ2JhKDAsMCwwLDAuNCk7Ym9yZGVyOjFweCBzb2xpZCAke3RjLnNlbGVjdEJvcmRlcn07Ym9yZGVyLXJhZGl1czo4cHg7Y29sb3I6I2ZmZjtmb250LWZhbWlseTonUmFqZGhhbmknLHNhbnMtc2VyaWY7Zm9udC1zaXplOjE0cHg7b3V0bGluZTpub25lO21hcmdpbi10b3A6NXB4OyB9CiAgICAgICAgICAgICN0bC1nb2QtdGFyZ2V0LXNjb3JlIHsgd2lkdGg6MTAwJTtwYWRkaW5nOjEwcHg7YmFja2dyb3VuZDpyZ2JhKDAsMCwwLDAuNCk7Ym9yZGVyOjFweCBzb2xpZCAke3RjLnNlbGVjdEJvcmRlcn07Ym9yZGVyLXJhZGl1czo4cHg7Y29sb3I6I2ZmYzEwNztmb250LWZhbWlseTonUmFqZGhhbmknLHNhbnMtc2VyaWY7Zm9udC1zaXplOjE0cHg7b3V0bGluZTpub25lO21hcmdpbi10b3A6NXB4OyB9XG4gICAgICAgICAgICAudGwtZ29kLWlucHV0IHsgd2lkdGg6MTAwJTtwYWRkaW5nOjEwcHg7YmFja2dyb3VuZDpyZ2JhKDAsMCwwLDAuNCk7Ym9yZGVyOjFweCBzb2xpZCByZ2JhKDI1NSwxOTMsNywwLjMpO2JvcmRlci1yYWRpdXM6OHB4O2NvbG9yOiNmZmMxMDc7Zm9udC1mYW1pbHk6J1NoYXJlIFRlY2ggTW9ubyc7Zm9udC1zaXplOjEzcHg7b3V0bGluZTpub25lO21hcmdpbi10b3A6NXB4O2JveC1zaXppbmc6Ym9yZGVyLWJveDsgfVxuICAgICAgICAgICAgI3RsLWZpcmVCdG4geyB3aWR0aDoxMDAlO3BhZGRpbmc6MTNweDtiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCgxMzVkZWcsI2Q5MDQyOSwjZWYyMzNjKTtib3JkZXI6bm9uZTtib3JkZXItcmFkaXVzOjEwcHg7Y29sb3I6I2ZmZjtmb250LWZhbWlseTonT3JiaXRyb24nO2ZvbnQtd2VpZ2h0OjkwMDtmb250LXNpemU6MTRweDtjdXJzb3I6cG9pbnRlcjtib3gtc2hhZG93OjAgMCAyMHB4IHJnYmEoMjE3LDQsNDEsMC40KTt0cmFuc2l0aW9uOjAuMnM7bWFyZ2luLXRvcDo1cHg7IH1cbiAgICAgICAgICAgICN0bC1maXJlQnRuOmhvdmVyIHsgYm94LXNoYWRvdzowIDAgMzBweCByZ2JhKDIxNyw0LDQxLDAuNyk7IH1cbiAgICAgICAgICAgICN0bC1maXJlQnRuOmRpc2FibGVkIHsgb3BhY2l0eTowLjU7Y3Vyc29yOm5vdC1hbGxvd2VkOyB9XG4gICAgICAgICAgICAudGwtY29uc29sZSB7IGJvcmRlcjoxcHggc29saWQgJHt0Yy5jb25zb2xlQm9yZGVyfTtib3JkZXItcmFkaXVzOjEwcHg7YmFja2dyb3VuZDpyZ2JhKDAsMCwwLDAuODIpO3BhZGRpbmc6OHB4O2hlaWdodDo5NnB4O292ZXJmbG93LXk6YXV0bztmb250LWZhbWlseTonU2hhcmUgVGVjaCBNb25vJyxtb25vc3BhY2U7Zm9udC1zaXplOjEwLjVweDtsaW5lLWhlaWdodDoxLjU7Y29sb3I6I2FhYTsgfVxuICAgICAgICAgICAgLnRsLWxvZyB7IG1hcmdpbi1ib3R0b206MnB4O3BhZGRpbmc6MXB4IDNweDtsaW5lLWhlaWdodDoxLjU7d29yZC1icmVhazpicmVhay13b3JkO3doaXRlLXNwYWNlOm5vcm1hbDsgfVxuICAgICAgICAgICAgLnRsLWxvZy5vayAgIHsgY29sb3I6IzAwZTY3NjsgfVxuICAgICAgICAgICAgLnRsLWxvZy5lcnIgIHsgY29sb3I6I2VmMjMzYzsgfVxuICAgICAgICAgICAgLnRsLWxvZy53YXJuIHsgY29sb3I6I2ZmYzEwNzsgfVxuICAgICAgICAgICAgLnRsLWxvZy5pbmZvIHsgY29sb3I6IzRmYWNmZTsgfVxuICAgICAgICAgICAgI3RsLXAtZm9vdGVyIHsgcGFkZGluZzo4cHggMTRweDtib3JkZXItdG9wOjFweCBzb2xpZCAke3RjLmJvcmRlclN1YnRsZX07ZGlzcGxheTpmbGV4O2p1c3RpZnktY29udGVudDpzcGFjZS1iZXR3ZWVuO2ZvbnQtZmFtaWx5OidTaGFyZSBUZWNoIE1vbm8nO2ZvbnQtc2l6ZTo5cHg7Y29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjIpOyB9XG4gICAgICAgICAgICBcbiAgICAgICAgICAgICN0bC1zbyB7IHBvc2l0aW9uOmFic29sdXRlO3RvcDowO2xlZnQ6MDtyaWdodDowO2JvdHRvbTowO2JhY2tncm91bmQ6JHt0Yy5iZ1BhbmVsfTtiYWNrZHJvcC1maWx0ZXI6Ymx1cigxMnB4KTt6LWluZGV4OjIwO2JvcmRlci1yYWRpdXM6MTZweDtkaXNwbGF5OmZsZXg7ZmxleC1kaXJlY3Rpb246Y29sdW1uO292ZXJmbG93OmhpZGRlbjsgfVxuICAgICAgICAgICAgI3RsLXNvLmhpZGRlbiB7IGRpc3BsYXk6bm9uZTsgfVxuICAgICAgICAgICAgLnRsLXNvLWhkciB7IHBhZGRpbmc6MTNweCAxNnB4O2JhY2tncm91bmQ6JHt0Yy5oZWFkZXJCZ307Ym9yZGVyLWJvdHRvbToxcHggc29saWQgJHt0Yy5ib3JkZXJTdWJ0bGV9O2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47ZmxleC1zaHJpbms6MDsgfVxuICAgICAgICAgICAgLnRsLXNvLXRpdGxlIHsgZm9udC1mYW1pbHk6J09yYml0cm9uJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZToxMC41cHg7Zm9udC13ZWlnaHQ6NzAwO2NvbG9yOiR7dGMuYzF9OyB9XG4gICAgICAgICAgICAjdGwtc29DbG9zZSB7IHdpZHRoOjI2cHg7aGVpZ2h0OjI2cHg7Ym9yZGVyLXJhZGl1czo1MCU7Ym9yZGVyOjFweCBzb2xpZCAke3RjLmJvcmRlcn07YmFja2dyb3VuZDoke3RjLmdsb3dTdWJ0bGV9O2NvbG9yOiR7dGMuYzF9O2N1cnNvcjpwb2ludGVyO2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OmNlbnRlcjtmb250LXNpemU6MTJweDt0cmFuc2l0aW9uOjAuMnM7IH1cbiAgICAgICAgICAgICN0bC1zb0Nsb3NlOmhvdmVyIHsgYmFja2dyb3VuZDpyZ2JhKDIxNyw0LDQxLDAuMTUpO2JvcmRlci1jb2xvcjpyZ2JhKDIxNyw0LDQxLDAuNSk7Y29sb3I6I2VmMjMzYzsgfVxuICAgICAgICAgICAgLnRsLXNvLWJvZHkgeyBwYWRkaW5nOjE0cHg7ZmxleDoxO2Rpc3BsYXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47Z2FwOjEycHg7b3ZlcmZsb3cteTphdXRvOyB9XG4gICAgICAgICAgICAudGwtc28tbGJsIHsgZm9udC1zaXplOjkuNXB4O2ZvbnQtd2VpZ2h0OjcwMDtjb2xvcjpyZ2JhKDI1NSwyNTUsMjU1LDAuMjgpO3RleHQtdHJhbnNmb3JtOnVwcGVyY2FzZTtmb250LWZhbWlseTonT3JiaXRyb24nO2xldHRlci1zcGFjaW5nOjEuMnB4O21hcmdpbi1ib3R0b206MnB4OyB9XG4gICAgICAgICAgICAudGwtdGhlbWUtY2FyZHMgeyBkaXNwbGF5OmZsZXg7Z2FwOjhweDsgfVxuICAgICAgICAgICAgLnRsLXRjIHsgZmxleDoxO2N1cnNvcjpwb2ludGVyO2JvcmRlci1yYWRpdXM6MTBweDtib3JkZXI6MnB4IHNvbGlkIHJnYmEoMjU1LDI1NSwyNTUsMC4wNyk7cGFkZGluZzo4cHggNnB4O3RleHQtYWxpZ246Y2VudGVyO3RyYW5zaXRpb246YWxsIDAuMjJzO2JhY2tncm91bmQ6cmdiYSgwLDAsMCwwLjMpO3Bvc2l0aW9uOnJlbGF0aXZlOyB9XG4gICAgICAgICAgICAudGwtdGM6aG92ZXIgeyB0cmFuc2Zvcm06dHJhbnNsYXRlWSgtM3B4KTtib3JkZXItY29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjE4KTtib3gtc2hhZG93OjAgNnB4IDE4cHggcmdiYSgwLDAsMCwwLjQpOyB9XG4gICAgICAgICAgICAudGwtdGMuYWN0aXZlIHsgYm9yZGVyLWNvbG9yOiR7dGMuYzF9O2JveC1zaGFkb3c6MCAwIDE0cHggJHt0Yy5nbG93TWlkfTsgfVxuICAgICAgICAgICAgLnRsLXRjLXByZXYgeyB3aWR0aDoxMDAlO2hlaWdodDozOHB4O2JvcmRlci1yYWRpdXM6N3B4O21hcmdpbi1ib3R0b206N3B4O292ZXJmbG93OmhpZGRlbjtwb3NpdGlvbjpyZWxhdGl2ZTsgfVxuICAgICAgICAgICAgLnRsLXRjLXByZXYtaW5uZXIgeyBwb3NpdGlvbjphYnNvbHV0ZTtpbnNldDowO2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OmNlbnRlcjsgfVxuICAgICAgICAgICAgLnRsLXRjLXByZXYtdGV4dCB7IGZvbnQtZmFtaWx5OidPcmJpdHJvbicsc2Fucy1zZXJpZjtmb250LXNpemU6N3B4O2ZvbnQtd2VpZ2h0OjcwMDtsZXR0ZXItc3BhY2luZzoxcHg7b3BhY2l0eTowLjk7IH1cbiAgICAgICAgICAgIC50bC10Yy1sYmwgeyBmb250LWZhbWlseTonUmFqZGhhbmknLHNhbnMtc2VyaWY7Zm9udC1zaXplOjEwLjVweDtmb250LXdlaWdodDo2MDA7Y29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjYpOyB9XG4gICAgICAgICAgICAudGwtdGMuYWN0aXZlIC50bC10Yy1sYmwgeyBjb2xvcjoke3RjLmMxfTtmb250LXdlaWdodDo3MDA7IH1cbiAgICAgICAgICAgIC50bC10Yy5hY3RpdmU6OmFmdGVyIHsgY29udGVudDon4pyTJztwb3NpdGlvbjphYnNvbHV0ZTt0b3A6NXB4O3JpZ2h0OjdweDtjb2xvcjoke3RjLmMxfTtmb250LXNpemU6MTFweDtmb250LXdlaWdodDo5MDA7IH1cbiAgICAgICAgICAgIC50bC1zby1kaXZpZGVyIHsgaGVpZ2h0OjFweDtiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCg5MGRlZyx0cmFuc3BhcmVudCwke3RjLmJvcmRlcn0sdHJhbnNwYXJlbnQpOyB9XG4gICAgICAgICAgICAudGwtaGludCB7IGZvbnQtc2l6ZToxMHB4O2NvbG9yOnJnYmEoMjU1LDI1NSwyNTUsMC4yKTtmb250LWZhbWlseTonU2hhcmUgVGVjaCBNb25vJzt0ZXh0LWFsaWduOmNlbnRlcjtsaW5lLWhlaWdodDoxLjY7IH1cbiAgICAgICAgICAgIC50bC1jaGFuZ2Uta2V5IHsgd2lkdGg6MTAwJTtwYWRkaW5nOjEwcHg7YmFja2dyb3VuZDpyZ2JhKDIzOSwzNSw2MCwwLjEpO2JvcmRlcjoxcHggc29saWQgcmdiYSgyMzksMzUsNjAsMC4zOCk7Ym9yZGVyLXJhZGl1czo4cHg7Y29sb3I6I2VmMjMzYztmb250LWZhbWlseTonT3JiaXRyb24nLHNhbnMtc2VyaWY7Zm9udC1zaXplOjEwLjVweDtmb250LXdlaWdodDo3MDA7Y3Vyc29yOnBvaW50ZXI7dHJhbnNpdGlvbjowLjJzO2xldHRlci1zcGFjaW5nOjAuNXB4OyB9XG4gICAgICAgICAgICAudGwtY2hhbmdlLWtleTpob3ZlciB7IGJhY2tncm91bmQ6cmdiYSgyMzksMzUsNjAsMC4yKTtib3JkZXItY29sb3I6cmdiYSgyMzksMzUsNjAsMC42NSk7Ym94LXNoYWRvdzowIDAgMTRweCByZ2JhKDIzOSwzNSw2MCwwLjI1KTsgfVxuICAgICAgICAgICAgXG4gICAgICAgICAgICAjdGllcC1tb2RhbC1vdmVybGF5IHsgcG9zaXRpb246Zml4ZWQ7dG9wOjA7bGVmdDowO3dpZHRoOjEwMHZ3O2hlaWdodDoxMDB2aDtiYWNrZ3JvdW5kOnJnYmEoMCwwLDAsMC43Mik7ei1pbmRleDoyMTQ3NDgzNjQ2O2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OmNlbnRlcjsgfVxuICAgICAgICAgICAgLnRpZXAtbW9kYWwtYm94IHsgd2lkdGg6MzIwcHg7YmFja2dyb3VuZDoke3RjLmJnUGFuZWx9O2JvcmRlcjoxcHggc29saWQgJHt0Yy5ib3JkZXJTdHJvbmd9O2JvcmRlci1yYWRpdXM6MTZweDtwYWRkaW5nOjI2cHggMjJweCAyMnB4O3RleHQtYWxpZ246Y2VudGVyO2JveC1zaGFkb3c6MCAwIDYwcHggcmdiYSgwLDAsMCwwLjkpLGluc2V0IDAgMCAwIDFweCAke3RjLnBhbmVsSW5zZXR9O2ZvbnQtZmFtaWx5OidSYWpkaGFuaScsc2Fucy1zZXJpZjsgfVxuICAgICAgICAgICAgLnRpZXAtbW9kYWwtaWNvbiB7IGZvbnQtc2l6ZTozOHB4O21hcmdpbi1ib3R0b206OHB4OyB9XG4gICAgICAgICAgICAudGllcC1tb2RhbC10aXRsZSB7IGZvbnQtZmFtaWx5OidPcmJpdHJvbicsc2Fucy1zZXJpZjtmb250LXNpemU6MTJweDtmb250LXdlaWdodDo3MDA7Y29sb3I6JHt0Yy5jMX07bWFyZ2luLWJvdHRvbToxMnB4O2xpbmUtaGVpZ2h0OjEuNTsgfVxuICAgICAgICAgICAgLnRpZXAtbW9kYWwtbGluZXMgeyBjb2xvcjpyZ2JhKDI1NSwyNTUsMjU1LDAuNzgpO2ZvbnQtc2l6ZToxM3B4O2xpbmUtaGVpZ2h0OjEuNjU7bWFyZ2luLWJvdHRvbToxOHB4OyB9XG4gICAgICAgICAgICAudGllcC1tb2RhbC1saW5lcyBiIHsgY29sb3I6I2ZmZjsgfVxuICAgICAgICAgICAgLnRpZXAtbW9kYWwtb2sgeyBwYWRkaW5nOjEwcHggMzZweDtiYWNrZ3JvdW5kOiR7dGMuZmxvYXRHcmFkaWVudH07Ym9yZGVyOm5vbmU7Ym9yZGVyLXJhZGl1czo4cHg7Y29sb3I6I2ZmZjtmb250LWZhbWlseTonT3JiaXRyb24nLHNhbnMtc2VyaWY7Zm9udC1zaXplOjExLjVweDtmb250LXdlaWdodDo5MDA7Y3Vyc29yOnBvaW50ZXI7dHJhbnNpdGlvbjowLjJzO2JveC1zaGFkb3c6MCA0cHggMTZweCAke3RjLmdsb3dDb2xvcn07IH1cbiAgICAgICAgICAgIC50aWVwLW1vZGFsLW9rOmhvdmVyIHsgdHJhbnNmb3JtOnNjYWxlKDEuMDYpO2JveC1zaGFkb3c6MCAwIDI0cHggJHt0Yy5nbG93Q29sb3J9OyB9XG4gICAgICAgICAgICAke3RjLmZ4Q1NTfVxuICAgICAgICBgOwogIH0KICBmdW5jdGlvbiBfZW5zdXJlTW9kYWxTdHlsZSgpIHsKICAgIGlmIChkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGllcC1tb2RhbC1zdHlsZScpKSByZXR1cm47CiAgICBjb25zdCB0YyA9IGdldFRoZW1lQ29sb3JzKENVUlJFTlRfVEhFTUUpOwogICAgY29uc3QgbXMgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdzdHlsZScpOwogICAgbXMuaWQgPSAndGllcC1tb2RhbC1zdHlsZSc7CiAgICBtcy50ZXh0Q29udGVudCA9IGBcbiAgICAgICAgICAgIEBrZXlmcmFtZXMgdGxNb2RhbElue2Zyb217b3BhY2l0eTowO3RyYW5zZm9ybTpzY2FsZSgwLjkyKX10b3tvcGFjaXR5OjE7dHJhbnNmb3JtOnNjYWxlKDEpfX1cbiAgICAgICAgICAgICN0aWVwLW1vZGFsLW92ZXJsYXl7cG9zaXRpb246Zml4ZWQhaW1wb3J0YW50O3RvcDowIWltcG9ydGFudDtsZWZ0OjAhaW1wb3J0YW50O3dpZHRoOjEwMHZ3IWltcG9ydGFudDtoZWlnaHQ6MTAwdmghaW1wb3J0YW50O2JhY2tncm91bmQ6cmdiYSgwLDAsMCwwLjc1KSFpbXBvcnRhbnQ7ei1pbmRleDoyMTQ3NDgzNjQ2IWltcG9ydGFudDtkaXNwbGF5OmZsZXghaW1wb3J0YW50O2FsaWduLWl0ZW1zOmNlbnRlciFpbXBvcnRhbnQ7anVzdGlmeS1jb250ZW50OmNlbnRlciFpbXBvcnRhbnQ7fVxuICAgICAgICAgICAgLnRpZXAtbW9kYWwtYm94e3dpZHRoOjMyMHB4O21heC13aWR0aDo5MHZ3O2JhY2tncm91bmQ6JHt0Yy5iZ1BhbmVsfTtib3JkZXI6MXB4IHNvbGlkICR7dGMuYm9yZGVyU3Ryb25nfTtib3JkZXItcmFkaXVzOjE2cHg7cGFkZGluZzoyNnB4IDIycHggMjJweDt0ZXh0LWFsaWduOmNlbnRlcjtib3gtc2hhZG93OjAgMCA2MHB4IHJnYmEoMCwwLDAsMC45KSxpbnNldCAwIDAgMCAxcHggJHt0Yy5wYW5lbEluc2V0fTtmb250LWZhbWlseTonUmFqZGhhbmknLHNhbnMtc2VyaWY7YW5pbWF0aW9uOnRsTW9kYWxJbiAwLjIycyBlYXNlO31cbiAgICAgICAgICAgIC50aWVwLW1vZGFsLWljb257Zm9udC1zaXplOjM4cHg7bWFyZ2luLWJvdHRvbTo4cHg7fVxuICAgICAgICAgICAgLnRpZXAtbW9kYWwtdGl0bGV7Zm9udC1mYW1pbHk6J09yYml0cm9uJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZToxMnB4O2ZvbnQtd2VpZ2h0OjcwMDtjb2xvcjoke3RjLmMxfTttYXJnaW4tYm90dG9tOjEycHg7bGluZS1oZWlnaHQ6MS41O31cbiAgICAgICAgICAgIC50aWVwLW1vZGFsLWxpbmVze2NvbG9yOnJnYmEoMjU1LDI1NSwyNTUsMC44Mik7Zm9udC1zaXplOjEzcHg7bGluZS1oZWlnaHQ6MS43O21hcmdpbi1ib3R0b206MThweDt9XG4gICAgICAgICAgICAudGllcC1tb2RhbC1saW5lcyBie2NvbG9yOiNmZmY7fVxuICAgICAgICAgICAgLnRpZXAtbW9kYWwtb2t7cGFkZGluZzoxMHB4IDM2cHg7YmFja2dyb3VuZDoke3RjLmZsb2F0R3JhZGllbnR9O2JvcmRlcjpub25lO2JvcmRlci1yYWRpdXM6OHB4O2NvbG9yOiNmZmY7Zm9udC1mYW1pbHk6J09yYml0cm9uJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZToxMS41cHg7Zm9udC13ZWlnaHQ6OTAwO2N1cnNvcjpwb2ludGVyO3RyYW5zaXRpb246MC4ycztib3gtc2hhZG93OjAgNHB4IDE2cHggJHt0Yy5nbG93Q29sb3J9O31cbiAgICAgICAgICAgIC50aWVwLW1vZGFsLW9rOmhvdmVye3RyYW5zZm9ybTpzY2FsZSgxLjA2KTtib3gtc2hhZG93OjAgMCAyNHB4ICR7dGMuZ2xvd0NvbG9yfTt9XG4gICAgICAgIGA7CiAgICBkb2N1bWVudC5oZWFkLmFwcGVuZENoaWxkKG1zKTsKICB9CiAgZnVuY3Rpb24gc2hvd0N1c3RvbU1vZGFsKHtpY29uOiBpY29uLCB0aXRsZTogdGl0bGUsIGxpbmVzOiBsaW5lcywgb25Pazogb25Pa30pIHsKICAgIF9lbnN1cmVNb2RhbFN0eWxlKCk7CiAgICBjb25zdCBleGlzdGluZyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0aWVwLW1vZGFsLW92ZXJsYXknKTsKICAgIGlmIChleGlzdGluZykgZXhpc3RpbmcucmVtb3ZlKCk7CiAgICBjb25zdCBvdmVybGF5ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICBvdmVybGF5LmlkID0gJ3RpZXAtbW9kYWwtb3ZlcmxheSc7CiAgICBjb25zdCBsaW5lc0hUTUwgPSAoQXJyYXkuaXNBcnJheShsaW5lcykgPyBsaW5lcyA6IFsgbGluZXMgXSkubWFwKGwgPT4gYDxkaXY+JHtsfTwvZGl2PmApLmpvaW4oJycpOwogICAgb3ZlcmxheS5pbm5lckhUTUwgPSBgXG4gICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0aWVwLW1vZGFsLWJveCI+XG4gICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGllcC1tb2RhbC1pY29uIj4ke2ljb24gfHwgJ+KEue+4jyd9PC9kaXY+XG4gICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGllcC1tb2RhbC10aXRsZSI+JHt0aXRsZSB8fCAnVGjDtG5nIGLDoW8nfTwvZGl2PlxuICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRpZXAtbW9kYWwtbGluZXMiPiR7bGluZXNIVE1MfTwvZGl2PlxuICAgICAgICAgICAgICAgIDxidXR0b24gY2xhc3M9InRpZXAtbW9kYWwtb2siIGlkPSJ0aWVwLW1vZGFsLW9rLWJ0biI+T0s8L2J1dHRvbj5cbiAgICAgICAgICAgIDwvZGl2PmA7CiAgICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKG92ZXJsYXkpOwogICAgY29uc3QgY2xvc2UgPSAoKSA9PiB7CiAgICAgIG92ZXJsYXkucmVtb3ZlKCk7CiAgICAgIGlmIChvbk9rKSBvbk9rKCk7CiAgICB9OwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RpZXAtbW9kYWwtb2stYnRuJykub25jbGljayA9IGNsb3NlOwogICAgb3ZlcmxheS5vbmNsaWNrID0gZSA9PiB7CiAgICAgIGlmIChlLnRhcmdldCA9PT0gb3ZlcmxheSkgY2xvc2UoKTsKICAgIH07CiAgfQogIGZ1bmN0aW9uIHNob3dDb25maXJtTW9kYWwoe2ljb246IGljb24sIHRpdGxlOiB0aXRsZSwgbGluZXM6IGxpbmVzLCBva1RleHQ6IG9rVGV4dCwgY2FuY2VsVGV4dDogY2FuY2VsVGV4dCwgb25Pazogb25Pa30pIHsKICAgIF9lbnN1cmVNb2RhbFN0eWxlKCk7CiAgICBjb25zdCBleGlzdGluZyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0aWVwLW1vZGFsLW92ZXJsYXknKTsKICAgIGlmIChleGlzdGluZykgZXhpc3RpbmcucmVtb3ZlKCk7CiAgICBjb25zdCBvdmVybGF5ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICBvdmVybGF5LmlkID0gJ3RpZXAtbW9kYWwtb3ZlcmxheSc7CiAgICBjb25zdCBsaW5lc0hUTUwgPSAoQXJyYXkuaXNBcnJheShsaW5lcykgPyBsaW5lcyA6IFsgbGluZXMgXSkubWFwKGwgPT4gYDxkaXY+JHtsfTwvZGl2PmApLmpvaW4oJycpOwogICAgb3ZlcmxheS5pbm5lckhUTUwgPSBgXG4gICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0aWVwLW1vZGFsLWJveCI+XG4gICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGllcC1tb2RhbC1pY29uIj4ke2ljb24gfHwgJ+Kdkyd9PC9kaXY+XG4gICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGllcC1tb2RhbC10aXRsZSI+JHt0aXRsZSB8fCAnWMOhYyBuaOG6rW4nfTwvZGl2PlxuICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRpZXAtbW9kYWwtbGluZXMiPiR7bGluZXNIVE1MfTwvZGl2PlxuICAgICAgICAgICAgICAgIDxkaXYgc3R5bGU9ImRpc3BsYXk6ZmxleDtnYXA6MTBweDtqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyOyI+XG4gICAgICAgICAgICAgICAgICAgIDxidXR0b24gY2xhc3M9InRpZXAtbW9kYWwtb2siIGlkPSJ0aWVwLWNvbmZpcm0tY2FuY2VsLWJ0biIgc3R5bGU9ImJhY2tncm91bmQ6cmdiYSgyNTUsMjU1LDI1NSwwLjA4KTtib3gtc2hhZG93Om5vbmU7Ij4ke2NhbmNlbFRleHQgfHwgJ0jhu6ZZJ308L2J1dHRvbj5cbiAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0idGllcC1tb2RhbC1vayIgaWQ9InRpZXAtY29uZmlybS1vay1idG4iPiR7b2tUZXh0IHx8ICdYw4FDIE5I4bqsTid9PC9idXR0b24+XG4gICAgICAgICAgICAgICAgPC9kaXY+XG4gICAgICAgICAgICA8L2Rpdj5gOwogICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChvdmVybGF5KTsKICAgIGNvbnN0IGRpc21pc3MgPSAoKSA9PiBvdmVybGF5LnJlbW92ZSgpOwogICAgY29uc3QgY29uZmlybSA9ICgpID0+IHsKICAgICAgb3ZlcmxheS5yZW1vdmUoKTsKICAgICAgaWYgKG9uT2spIG9uT2soKTsKICAgIH07CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGllcC1jb25maXJtLWNhbmNlbC1idG4nKS5vbmNsaWNrID0gZGlzbWlzczsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0aWVwLWNvbmZpcm0tb2stYnRuJykub25jbGljayA9IGNvbmZpcm07CiAgICBvdmVybGF5Lm9uY2xpY2sgPSBlID0+IHsKICAgICAgaWYgKGUudGFyZ2V0ID09PSBvdmVybGF5KSBkaXNtaXNzKCk7CiAgICB9OwogIH0KICBmdW5jdGlvbiBhcHBseVRoZW1lTGl2ZShuZXdUaGVtZSkgewogICAgQ1VSUkVOVF9USEVNRSA9IG5ld1RoZW1lOwogICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oTFNfVEhFTUUsIG5ld1RoZW1lKTsKICAgIGNvbnN0IHVpU3R5bGUgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtdWktc3R5bGUnKTsKICAgIGlmICh1aVN0eWxlKSB1aVN0eWxlLnRleHRDb250ZW50ID0gZ2V0TWFpblVJU3R5bGVzKCk7CiAgICBjb25zdCBsb2NrU3R5bGUgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtbG9jay1zdHlsZScpOwogICAgaWYgKGxvY2tTdHlsZSkgbG9ja1N0eWxlLnRleHRDb250ZW50ID0gZ2V0TG9ja1NjcmVlblN0eWxlcygpOwogICAgY29uc3QgbXMgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGllcC1tb2RhbC1zdHlsZScpOwogICAgaWYgKG1zKSBtcy5yZW1vdmUoKTsKICAgIGNvbnN0IGZiID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLWZsb2F0QnRuJyk7CiAgICBpZiAoZmIpIHsKICAgICAgZmIuc3R5bGUuYW5pbWF0aW9uID0gJ25vbmUnOwogICAgICB2b2lkIGZiLm9mZnNldFdpZHRoOwogICAgICBmYi5zdHlsZS5hbmltYXRpb24gPSAnJzsKICAgIH0KICAgIGNvbnN0IGxvY2tQYW5lbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1jb25uLXBhbmVsJyk7CiAgICBpZiAobG9ja1BhbmVsKSB7CiAgICAgIGNvbnN0IGV4aXN0RnggPSBsb2NrUGFuZWwucXVlcnlTZWxlY3RvcignI3RsLWNvbm4tZngtYmFyLCN0bC1jb25uLWZ4LXBldGFscycpOwogICAgICBpZiAoZXhpc3RGeCkgZXhpc3RGeC5yZW1vdmUoKTsKICAgICAgY29uc3QgdGMgPSBnZXRUaGVtZUNvbG9ycyhuZXdUaGVtZSk7CiAgICAgIGlmICh0Yy5wYW5lbEV4dHJhKSB7CiAgICAgICAgY29uc3QgdG1wID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICAgICAgdG1wLmlubmVySFRNTCA9IHRjLnBhbmVsRXh0cmE7CiAgICAgICAgbG9ja1BhbmVsLmluc2VydEJlZm9yZSh0bXAuZmlyc3RFbGVtZW50Q2hpbGQsIGxvY2tQYW5lbC5maXJzdENoaWxkKTsKICAgICAgfQogICAgfQogIH0KICBsZXQgX3NlY1Nlc3Npb24gPSB7CiAgICB0b2tlbjogbnVsbCwKICAgIGV4cDogMCwKICAgIGZwSGFzaDogbnVsbCwKICAgIHNlcTogMQogIH07CiAgbGV0IF9hcGlQcmVmaXhDYWNoZSA9IG51bGw7CiAgbGV0IF9oZWFydGJlYXRUaW1lciA9IG51bGw7CiAgbGV0IF9oZWFydGJlYXRGYWlsID0gMDsKICBjb25zdCBfRU5DX1BGWCA9ICdfRTVfJzsKICBmdW5jdGlvbiBfbHNYb3IodmFsdWUpIHsKICAgIGlmICghdmFsdWUpIHJldHVybiAnJzsKICAgIHRyeSB7CiAgICAgIGNvbnN0IGsgPSBnZXRIV0lEKCkgKyBBUElfU0VDUkVULnNsaWNlKDAsIDEwKTsKICAgICAgbGV0IHIgPSAnJzsKICAgICAgZm9yIChsZXQgaSA9IDA7IGkgPCB2YWx1ZS5sZW5ndGg7IGkrKykgciArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKHZhbHVlLmNoYXJDb2RlQXQoaSkgXiBrLmNoYXJDb2RlQXQoaSAlIGsubGVuZ3RoKSk7CiAgICAgIHJldHVybiBfRU5DX1BGWCArIGJ0b2EodW5lc2NhcGUoZW5jb2RlVVJJQ29tcG9uZW50KHIpKSk7CiAgICB9IGNhdGNoIChfKSB7CiAgICAgIHJldHVybiB2YWx1ZTsKICAgIH0KICB9CiAgZnVuY3Rpb24gX2xzVW54b3IoZW5jb2RlZCkgewogICAgaWYgKCFlbmNvZGVkKSByZXR1cm4gbnVsbDsKICAgIGlmICghZW5jb2RlZC5zdGFydHNXaXRoKF9FTkNfUEZYKSkgcmV0dXJuIGVuY29kZWQ7CiAgICB0cnkgewogICAgICBjb25zdCB2ID0gZGVjb2RlVVJJQ29tcG9uZW50KGVzY2FwZShhdG9iKGVuY29kZWQuc2xpY2UoX0VOQ19QRlgubGVuZ3RoKSkpKTsKICAgICAgY29uc3QgayA9IGdldEhXSUQoKSArIEFQSV9TRUNSRVQuc2xpY2UoMCwgMTApOwogICAgICBsZXQgciA9ICcnOwogICAgICBmb3IgKGxldCBpID0gMDsgaSA8IHYubGVuZ3RoOyBpKyspIHIgKz0gU3RyaW5nLmZyb21DaGFyQ29kZSh2LmNoYXJDb2RlQXQoaSkgXiBrLmNoYXJDb2RlQXQoaSAlIGsubGVuZ3RoKSk7CiAgICAgIHJldHVybiByOwogICAgfSBjYXRjaCAoXykgewogICAgICByZXR1cm4gZW5jb2RlZDsKICAgIH0KICB9CiAgY29uc3QgX3NMUyA9IHsKICAgIGdldDoga2V5ID0+IHsKICAgICAgdHJ5IHsKICAgICAgICByZXR1cm4gX2xzVW54b3IobG9jYWxTdG9yYWdlLmdldEl0ZW0oa2V5KSk7CiAgICAgIH0gY2F0Y2ggKF8pIHsKICAgICAgICByZXR1cm4gbnVsbDsKICAgICAgfQogICAgfSwKICAgIHNldDogKGtleSwgdikgPT4gewogICAgICB0cnkgewogICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKGtleSwgdiA/IF9sc1hvcih2KSA6ICcnKTsKICAgICAgfSBjYXRjaCAoXykge30KICAgIH0sCiAgICBkZWw6IGtleSA9PiB7CiAgICAgIHRyeSB7CiAgICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oa2V5KTsKICAgICAgfSBjYXRjaCAoXykge30KICAgIH0KICB9OwogIGFzeW5jIGZ1bmN0aW9uIF9lbmNyeXB0UGF5bG9hZChkYXRhLCBoaW50KSB7CiAgICBjb25zdCBlbmMgPSBuZXcgVGV4dEVuY29kZXIsIGMgPSBfY3J5cHRvT2JqKCk7CiAgICBjb25zdCBpdiA9IGMuZ2V0UmFuZG9tVmFsdWVzKG5ldyBVaW50OEFycmF5KDEyKSk7CiAgICBjb25zdCB0cyA9IE1hdGguZmxvb3IoRGF0ZS5ub3coKSAvIDFlMyk7CiAgICBjb25zdCBub25jZSA9IEFycmF5LmZyb20oYy5nZXRSYW5kb21WYWx1ZXMobmV3IFVpbnQ4QXJyYXkoOCkpLCBiID0+IGIudG9TdHJpbmcoMTYpLnBhZFN0YXJ0KDIsICcwJykpLmpvaW4oJycpOwogICAgY29uc3QgcmF3S2V5ID0gZW5jLmVuY29kZShBUElfU0VDUkVUICsgKGhpbnQgfHwgJycpICsgKHRzID4+PiA3KS50b1N0cmluZygxNikpOwogICAgY29uc3QgYmFzZUtleSA9IGF3YWl0IGMuc3VidGxlLmltcG9ydEtleSgncmF3JywgcmF3S2V5LCAnUEJLREYyJywgZmFsc2UsIFsgJ2Rlcml2ZUJpdHMnIF0pOwogICAgY29uc3QgYml0cyA9IGF3YWl0IGMuc3VidGxlLmRlcml2ZUJpdHMoewogICAgICBuYW1lOiAnUEJLREYyJywKICAgICAgc2FsdDogZW5jLmVuY29kZSgndGw1cmVxJyArIG5vbmNlKSwKICAgICAgaXRlcmF0aW9uczogMTIwMCwKICAgICAgaGFzaDogJ1NIQS0yNTYnCiAgICB9LCBiYXNlS2V5LCAyNTYpOwogICAgY29uc3QgYWVzS2V5ID0gYXdhaXQgYy5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBiaXRzLCB7CiAgICAgIG5hbWU6ICdBRVMtR0NNJwogICAgfSwgZmFsc2UsIFsgJ2VuY3J5cHQnIF0pOwogICAgY29uc3QgY3QgPSBuZXcgVWludDhBcnJheShhd2FpdCBjLnN1YnRsZS5lbmNyeXB0KHsKICAgICAgbmFtZTogJ0FFUy1HQ00nLAogICAgICBpdjogaXYKICAgIH0sIGFlc0tleSwgZW5jLmVuY29kZShKU09OLnN0cmluZ2lmeShkYXRhKSkpKTsKICAgIGNvbnN0IGI2NCA9IGEgPT4gYnRvYShTdHJpbmcuZnJvbUNoYXJDb2RlKC4uLmEpKTsKICAgIHJldHVybiB7CiAgICAgIF9lOiA1LAogICAgICBpdjogYjY0KGl2KSwKICAgICAgZDogYjY0KGN0LnNsaWNlKDAsIC0xNikpLAogICAgICB0OiBiNjQoY3Quc2xpY2UoLTE2KSksCiAgICAgIHRzOiB0cywKICAgICAgbjogbm9uY2UKICAgIH07CiAgfQogIGxldCBfZ3VhcmRBY3RpdmUgPSBmYWxzZTsKICBsZXQgX2d1YXJkVGltZXIgPSBudWxsOwogIGxldCBfZ3VhcmRCQyA9IG51bGw7CiAgbGV0IF9wcmVTY2FuSG9vayA9IG51bGw7CiAgbGV0IF9ob29rU3RyaWtlID0gMDsKICBjb25zdCBfR1VBUkRfU1RBUlRfVFMgPSBEYXRlLm5vdygpOwogIGNvbnN0IF9HVUFSRF9MUyA9IFsgJ190bF9jb25uX2tleScsICdfdGxfY29ubl90eXBlJywgJ190bF9jb25uX2V4cCcsICdfdGllcF90aGVtZScsICdfdGxfaHdpZCcsICdfdGxfZ3VhcmRfdHMnIF07CiAgY29uc3QgX0dVQVJEX1VJID0gWyAndGwtY29ubi1vdmVybGF5JywgJ3RsLXBhbmVsJywgJ3RsLWZsb2F0QnRuJywgJ3RsLXVpLXN0eWxlJywgJ3RsLWxvY2stc3R5bGUnLCAndGllcC1tb2RhbC1zdHlsZScsICd0aWVwLW1vZGFsLW92ZXJsYXknIF07CiAgZnVuY3Rpb24gX3Nob3dHdWFyZFdhcm5pbmcocmVhc29uKSB7IC8qIHYxOSBkZXRlY3Rpb24gcmVtb3ZlZCAqLyB9CiAgZnVuY3Rpb24gX3NlbGZEZXN0cnVjdChyZWFzb24pIHsgLyogdjE5IGRldGVjdGlvbiByZW1vdmVkICovIH0KICBsZXQgX2JhblN0YXRlID0gewogICAgYWN0aXZlOiBmYWxzZSwKICAgIHRpbWVyOiBudWxsLAogICAgcmVhc29uOiAnJwogIH07CiAgZnVuY3Rpb24gX3Nob3dCYW5TY3JlZW4ocmVhc29uKSB7CiAgICBjb25zdCByZW5kZXIgPSAoKSA9PiB7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgZXggPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnX3RsX2Jhbl9vdmVybGF5Jyk7CiAgICAgICAgaWYgKGV4KSBleC5yZW1vdmUoKTsKICAgICAgICBjb25zdCBvID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICAgICAgby5pZCA9ICdfdGxfYmFuX292ZXJsYXknOwogICAgICAgIG8uc3R5bGUuY3NzVGV4dCA9ICdwb3NpdGlvbjpmaXhlZCFpbXBvcnRhbnQ7dG9wOjAhaW1wb3J0YW50O2xlZnQ6MCFpbXBvcnRhbnQ7d2lkdGg6MTAwdnchaW1wb3J0YW50O2hlaWdodDoxMDB2aCFpbXBvcnRhbnQ7YmFja2dyb3VuZDpyZ2JhKDAsMCwwLDAuOTYpIWltcG9ydGFudDt6LWluZGV4OjIxNDc0ODM2NDchaW1wb3J0YW50O2Rpc3BsYXk6ZmxleCFpbXBvcnRhbnQ7YWxpZ24taXRlbXM6Y2VudGVyIWltcG9ydGFudDtqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyIWltcG9ydGFudDtmb250LWZhbWlseTptb25vc3BhY2UhaW1wb3J0YW50Oyc7CiAgICAgICAgby5pbm5lckhUTUwgPSAnPGRpdiBzdHlsZT0iYmFja2dyb3VuZDojMGQwZDBkO2JvcmRlcjoycHggc29saWQgI2VmMjMzYztib3JkZXItcmFkaXVzOjE2cHg7cGFkZGluZzozNnB4IDMycHg7bWF4LXdpZHRoOjQzMHB4O3RleHQtYWxpZ246Y2VudGVyO2JveC1zaGFkb3c6MCAwIDgwcHggcmdiYSgyMzksMzUsNjAsMC42KSwwIDAgMTYwcHggcmdiYSgyMzksMzUsNjAsMC4xNSk7Ij4nICsgJzxkaXYgc3R5bGU9ImZvbnQtc2l6ZTo1MnB4O21hcmdpbi1ib3R0b206MTRweDsiPvCfmqg8L2Rpdj4nICsgJzxzdHlsZT5Aa2V5ZnJhbWVzIF90bEJsaW5rezUwJXtvcGFjaXR5OjB9fSNfdGxfYmFuX292ZXJsYXkgLmdsaXRjaHthbmltYXRpb246X3RsQmxpbmsgMC43NXMgc3RlcC1lbmQgaW5maW5pdGU7fTwvc3R5bGU+JyArICc8ZGl2IGNsYXNzPSJnbGl0Y2giIHN0eWxlPSJmb250LWZhbWlseTpcJ0NvdXJpZXIgTmV3XCcsbW9ub3NwYWNlO2ZvbnQtc2l6ZToxNnB4O2ZvbnQtd2VpZ2h0OjkwMDtjb2xvcjojZWYyMzNjO3RleHQtdHJhbnNmb3JtOnVwcGVyY2FzZTtsZXR0ZXItc3BhY2luZzozcHg7bWFyZ2luLWJvdHRvbToxNHB4OyI+4pqgIFRoaeG6v3QgYuG7iyAvIElQIMSRw6MgYuG7iyBraG/DoTwvZGl2PicgKyAnPGRpdiBzdHlsZT0iY29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjc4KTtmb250LXNpemU6MTIuNXB4O2xpbmUtaGVpZ2h0OjEuOTttYXJnaW4tYm90dG9tOjE0cHg7Ij4nICsgKHJlYXNvbiB8fCAnUGjDoXQgaGnhu4duIG3DtGkgdHLGsOG7nW5nIGtow7RuZyBo4bujcCBs4buHLicpICsgJzxicj5MacOqbiBo4buHIGFkbWluIMSR4buDIMSRxrDhu6NjIG3hu58ga2hvw6EuPC9kaXY+JyArICc8ZGl2IGlkPSJfdGxfYmFuX3N0YXR1cyIgc3R5bGU9ImNvbG9yOiNmZmMxMDc7Zm9udC1zaXplOjExLjVweDtsaW5lLWhlaWdodDoxLjg7Ij7wn5SEIMSQYW5nIHThu7EgxJHhu5luZyBraeG7g20gdHJhIG3hu5dpIDE1IGdpw6J5Li4uPGJyPktoaSBhZG1pbiBt4bufIGtob8OhLCB0b29sIHPhur0gPGIgc3R5bGU9ImNvbG9yOiMwMGU2NzY7Ij5U4buwIMSQ4buYTkcgaG/huqF0IMSR4buZbmcgbOG6oWk8L2I+LCBraMO0bmcgY+G6p24gdGhhbyB0w6FjLjwvZGl2PicgKyAnPGRpdiBzdHlsZT0iY29sb3I6cmdiYSgyMzksMzUsNjAsMC40NSk7Zm9udC1zaXplOjlweDtsZXR0ZXItc3BhY2luZzoycHg7Zm9udC1mYW1pbHk6XCdDb3VyaWVyIE5ld1wnLG1vbm9zcGFjZTttYXJnaW4tdG9wOjE2cHg7Ij5USEnDik4gVEFJIFTDmSBU4buYSSAvLyBCQU4gTE9DSyB2Ni4zIChU4buwIE3hu54gS0hJIFVOQkFOKTwvZGl2PicgKyAnPC9kaXY+JzsKICAgICAgICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKG8pOwogICAgICB9IGNhdGNoIChfKSB7fQogICAgfTsKICAgIGlmIChkb2N1bWVudC5ib2R5KSByZW5kZXIoKTsgZWxzZSBkb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCdET01Db250ZW50TG9hZGVkJywgcmVuZGVyKTsKICB9CiAgZnVuY3Rpb24gX2JhblBvbGxPbmNlKCkgewogICAgKGFzeW5jICgpID0+IHsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCBwcmVmaXggPSBhd2FpdCBfYXBpUHJlZml4KCk7CiAgICAgICAgR01feG1saHR0cFJlcXVlc3QoewogICAgICAgICAgbWV0aG9kOiAnR0VUJywKICAgICAgICAgIHVybDogU0VSVkVSX0JBU0UgKyBwcmVmaXggKyAnL3BpbmcnLAogICAgICAgICAgdGltZW91dDogOGUzLAogICAgICAgICAgb25sb2FkOiByID0+IHsKICAgICAgICAgICAgaWYgKHIuc3RhdHVzID09PSAyMDApIHsKICAgICAgICAgICAgICBfZXhpdEJhbk1vZGUoKTsKICAgICAgICAgICAgICByZXR1cm47CiAgICAgICAgICAgIH0KICAgICAgICAgICAgY29uc3QgZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnX3RsX2Jhbl9zdGF0dXMnKTsKICAgICAgICAgICAgaWYgKGVsKSBlbC5pbm5lckhUTUwgPSAn8J+UhCBW4bqrbiBi4buLIGtob8OhIOKAlCDEkWFuZyBjaOG7nSBhZG1pbiBt4bufIGtob8OhLi4uPGJyPih04buxIGtp4buDbSB0cmEgbOG6oWkgc2F1IDE1IGdpw6J5KSc7CiAgICAgICAgICB9LAogICAgICAgICAgb25lcnJvcjogKCkgPT4ge30sCiAgICAgICAgICBvbnRpbWVvdXQ6ICgpID0+IHt9CiAgICAgICAgfSk7CiAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICB9KSgpOwogIH0KICBmdW5jdGlvbiBfZW50ZXJCYW5Nb2RlKHJlYXNvbikgewogICAgaWYgKF9iYW5TdGF0ZS5hY3RpdmUpIHJldHVybjsKICAgIF9iYW5TdGF0ZS5hY3RpdmUgPSB0cnVlOwogICAgX2JhblN0YXRlLnJlYXNvbiA9IHJlYXNvbiB8fCAnJzsKICAgIHRyeSB7CiAgICAgIGlmIChfaGVhcnRiZWF0VGltZXIpIHsKICAgICAgICBjbGVhckludGVydmFsKF9oZWFydGJlYXRUaW1lcik7CiAgICAgICAgX2hlYXJ0YmVhdFRpbWVyID0gbnVsbDsKICAgICAgfQogICAgfSBjYXRjaCAoXykge30KICAgIHRyeSB7CiAgICAgIGlmIChfZ3VhcmRUaW1lcikgewogICAgICAgIGNsZWFySW50ZXJ2YWwoX2d1YXJkVGltZXIpOwogICAgICAgIF9ndWFyZFRpbWVyID0gbnVsbDsKICAgICAgfQogICAgfSBjYXRjaCAoXykge30KICAgIHRyeSB7CiAgICAgIGlmIChfZ3VhcmRCQykgewogICAgICAgIF9ndWFyZEJDLmNsb3NlKCk7CiAgICAgICAgX2d1YXJkQkMgPSBudWxsOwogICAgICB9CiAgICB9IGNhdGNoIChfKSB7fQogICAgWyAndGwtcGFuZWwnLCAndGwtZmxvYXRCdG4nLCAndGwtY29ubi1vdmVybGF5JywgJ3RpZXAtbW9kYWwtb3ZlcmxheScgXS5mb3JFYWNoKGlkID0+IHsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCBlbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKGlkKTsKICAgICAgICBpZiAoZWwpIGVsLnJlbW92ZSgpOwogICAgICB9IGNhdGNoIChfKSB7fQogICAgfSk7CiAgICBDVVJSRU5UX0tFWSA9IG51bGw7CiAgICBLRVlfU1RBVFVTID0gewogICAgICB2YWxpZDogZmFsc2UsCiAgICAgIHR5cGU6IG51bGwsCiAgICAgIGV4cGlyZXNfYXQ6IG51bGwKICAgIH07CiAgICB0cnkgewogICAgICBfc2VjU2Vzc2lvbiA9IHsKICAgICAgICB0b2tlbjogbnVsbCwKICAgICAgICBleHA6IDAsCiAgICAgICAgZnBIYXNoOiBudWxsLAogICAgICAgIHNlcTogMQogICAgICB9OwogICAgfSBjYXRjaCAoXykge30KICAgIF9zaG93QmFuU2NyZWVuKHJlYXNvbik7CiAgICBfYmFuU3RhdGUudGltZXIgPSBzZXRJbnRlcnZhbChfYmFuUG9sbE9uY2UsIDE1ZTMpOwogICAgc2V0VGltZW91dChfYmFuUG9sbE9uY2UsIDVlMyk7CiAgfQogIGZ1bmN0aW9uIF9leGl0QmFuTW9kZSgpIHsKICAgIGlmICghX2JhblN0YXRlLmFjdGl2ZSkgcmV0dXJuOwogICAgX2JhblN0YXRlLmFjdGl2ZSA9IGZhbHNlOwogICAgdHJ5IHsKICAgICAgaWYgKF9iYW5TdGF0ZS50aW1lcikgewogICAgICAgIGNsZWFySW50ZXJ2YWwoX2JhblN0YXRlLnRpbWVyKTsKICAgICAgICBfYmFuU3RhdGUudGltZXIgPSBudWxsOwogICAgICB9CiAgICB9IGNhdGNoIChfKSB7fQogICAgdHJ5IHsKICAgICAgY29uc3QgZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnX3RsX2Jhbl9vdmVybGF5Jyk7CiAgICAgIGlmIChlbCkgZWwucmVtb3ZlKCk7CiAgICB9IGNhdGNoIChfKSB7fQogICAgc2V0VGltZW91dCgoKSA9PiB7CiAgICAgIHRyeSB7CiAgICAgICAgd2luZG93LmxvY2F0aW9uLnJlbG9hZCgpOwogICAgICB9IGNhdGNoIChfKSB7fQogICAgfSwgODAwKTsKICB9CiAgbGV0IF9yZW1vdGVMb2NrU3RhdGUgPSB7CiAgICBhY3RpdmU6IGZhbHNlLAogICAgdGltZXI6IG51bGwsCiAgICByZWFzb246ICcnLAogICAgcmVwb3J0ZWQ6IGZhbHNlCiAgfTsKICBmdW5jdGlvbiBfcmxTZW5kUmVwb3J0KHJlYXNvbikgeyAvKiB2MTkgZGV0ZWN0aW9uIHJlbW92ZWQgKi8gfQogIGZ1bmN0aW9uIF9zaG93UmVtb3RlTG9ja1NjcmVlbihyZWFzb24pIHsgLyogdjE5IGRldGVjdGlvbiByZW1vdmVkICovIH0KICBmdW5jdGlvbiBfcmVtb3RlTG9ja1BvbGxPbmNlKCkgeyAvKiB2MTkgZGV0ZWN0aW9uIHJlbW92ZWQgKi8gfQogIGZ1bmN0aW9uIF9lbnRlclJlbW90ZUxvY2socmVhc29uKSB7IC8qIHYxOSBkZXRlY3Rpb24gcmVtb3ZlZCDigJQga2jDtG5nIGtob8OhIHRoZW8gcGjhuqduIG3hu4FtIGzhuqEgKi8gfQogIGZ1bmN0aW9uIF9leGl0UmVtb3RlTG9jaygpIHsgLyogdjE5IGRldGVjdGlvbiByZW1vdmVkICovIH0KICBmdW5jdGlvbiBfZGV0ZWN0SG9va05vdygpIHsgcmV0dXJuIG51bGw7IC8qIHYxOSBkZXRlY3Rpb24gcmVtb3ZlZCAqLyB9CiAgZnVuY3Rpb24gX2RldnRvb2xzT3BlbigpIHsKICAgIHRyeSB7CiAgICAgIHJldHVybiB3aW5kb3cub3V0ZXJXaWR0aCAtIHdpbmRvdy5pbm5lcldpZHRoID4gMTYwIHx8IHdpbmRvdy5vdXRlckhlaWdodCAtIHdpbmRvdy5pbm5lckhlaWdodCA+IDIwMDsKICAgIH0gY2F0Y2ggKF8pIHsKICAgICAgcmV0dXJuIGZhbHNlOwogICAgfQogIH0KICBfcHJlU2Nhbkhvb2sgPSBudWxsOyAvLyB2MTkgZGV0ZWN0aW9uIHJlbW92ZWQKICBmdW5jdGlvbiBfaW5pdEd1YXJkQkMoKSB7CiAgICB0cnkgewogICAgICBjb25zdCBjaE5hbWUgPSAnX3RsdGdfJyArIEFQSV9TRUNSRVQuc2xpY2UoMCwgOCk7CiAgICAgIF9ndWFyZEJDID0gbmV3IEJyb2FkY2FzdENoYW5uZWwoY2hOYW1lKTsKICAgICAgX2d1YXJkQkMub25tZXNzYWdlID0gZXZ0ID0+IHsKICAgICAgICB0cnkgewogICAgICAgICAgaWYgKGV2dCAmJiBldnQuZGF0YSAmJiBldnQuZGF0YS50ID09PSAnVExfSEInKSB7fQogICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgIH07CiAgICAgIHNldFRpbWVvdXQoKCkgPT4gewogICAgICAgIHRyeSB7CiAgICAgICAgICBpZiAoX2d1YXJkQkMpIF9ndWFyZEJDLnBvc3RNZXNzYWdlKHsKICAgICAgICAgICAgdDogJ1RMX0hCJywKICAgICAgICAgICAgdHM6IERhdGUubm93KCkKICAgICAgICAgIH0pOwogICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgIH0sIDcwMCk7CiAgICAgIHNldEludGVydmFsKCgpID0+IHsKICAgICAgICB0cnkgewogICAgICAgICAgaWYgKF9ndWFyZEJDKSBfZ3VhcmRCQy5wb3N0TWVzc2FnZSh7CiAgICAgICAgICAgIHQ6ICdUTF9IQicsCiAgICAgICAgICAgIHRzOiBEYXRlLm5vdygpCiAgICAgICAgICB9KTsKICAgICAgICB9IGNhdGNoIChfKSB7fQogICAgICB9LCAxNWUzKTsKICAgIH0gY2F0Y2ggKF8pIHsKICAgICAgX2luaXRHdWFyZExTKCk7CiAgICB9CiAgfQogIGZ1bmN0aW9uIF9pbml0R3VhcmRMUygpIHsKICAgIGNvbnN0IFRTX0tFWSA9ICdfdGxfZ3VhcmRfdHMnOwogICAgY29uc3Qgbm93ID0gRGF0ZS5ub3coKTsKICAgIGNvbnN0IHByZXYgPSBwYXJzZUludChsb2NhbFN0b3JhZ2UuZ2V0SXRlbShUU19LRVkpIHx8ICcwJyk7CiAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShUU19LRVksIG5vdy50b1N0cmluZygpKTsKICAgIHNldEludGVydmFsKCgpID0+IHsKICAgICAgdHJ5IHsKICAgICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShUU19LRVksIERhdGUubm93KCkudG9TdHJpbmcoKSk7CiAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICB9LCAyNTAwKTsKICB9CiAgZnVuY3Rpb24gX3N0YXJ0UGVyaW9kaWNTY2FuKCkgeyAvKiB2MTkgZGV0ZWN0aW9uIHJlbW92ZWQgKi8gfQogIGZ1bmN0aW9uIF9pbml0R3VhcmQoKSB7IC8qIHYxOSBkZXRlY3Rpb24gcmVtb3ZlZCAqLyB9CiAgZnVuY3Rpb24gX2NyeXB0b09iaigpIHsKICAgIHJldHVybiB0eXBlb2YgY3J5cHRvICE9PSAndW5kZWZpbmVkJyA/IGNyeXB0byA6IHdpbmRvdy5jcnlwdG87CiAgfQogIGFzeW5jIGZ1bmN0aW9uIF9obWFjSGV4KHNlY3JldCwgc3RyKSB7CiAgICBjb25zdCBlbmMgPSBuZXcgVGV4dEVuY29kZXIsIGMgPSBfY3J5cHRvT2JqKCk7CiAgICBjb25zdCBrZXkgPSBhd2FpdCBjLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGVuYy5lbmNvZGUoc2VjcmV0KSwgewogICAgICBuYW1lOiAnSE1BQycsCiAgICAgIGhhc2g6ICdTSEEtMjU2JwogICAgfSwgZmFsc2UsIFsgJ3NpZ24nIF0pOwogICAgY29uc3Qgc2lnID0gYXdhaXQgYy5zdWJ0bGUuc2lnbignSE1BQycsIGtleSwgZW5jLmVuY29kZShzdHIpKTsKICAgIHJldHVybiBBcnJheS5mcm9tKG5ldyBVaW50OEFycmF5KHNpZykpLm1hcChiID0+IGIudG9TdHJpbmcoMTYpLnBhZFN0YXJ0KDIsICcwJykpLmpvaW4oJycpOwogIH0KICBhc3luYyBmdW5jdGlvbiBfYXBpUHJlZml4KCkgewogICAgaWYgKCFfYXBpUHJlZml4Q2FjaGUpIF9hcGlQcmVmaXhDYWNoZSA9ICcvJyArIChhd2FpdCBfaG1hY0hleChBUElfU0VDUkVULCAnZ29kbW9kZTphcGk6cHJlZml4OnY0JykpLnNsaWNlKDAsIDEyKTsKICAgIHJldHVybiBfYXBpUHJlZml4Q2FjaGU7CiAgfQogIGFzeW5jIGZ1bmN0aW9uIF9zaWduUmVxKGJvZHlTdHIsIHNlc3Npb25Ub2spIHsKICAgIGNvbnN0IGMgPSBfY3J5cHRvT2JqKCksIGVuYyA9IG5ldyBUZXh0RW5jb2RlcjsKICAgIGNvbnN0IHRzID0gTWF0aC5mbG9vcihEYXRlLm5vdygpIC8gMWUzKS50b1N0cmluZygpOwogICAgY29uc3Qgbm9uY2UgPSBBcnJheS5mcm9tKGMuZ2V0UmFuZG9tVmFsdWVzKG5ldyBVaW50OEFycmF5KDgpKSwgYiA9PiBiLnRvU3RyaW5nKDE2KS5wYWRTdGFydCgyLCAnMCcpKS5qb2luKCcnKTsKICAgIGNvbnN0IGJvZHlIYXNoQnVmID0gYXdhaXQgYy5zdWJ0bGUuZGlnZXN0KCdTSEEtMjU2JywgZW5jLmVuY29kZShib2R5U3RyIHx8ICcnKSk7CiAgICBjb25zdCBib2R5SGFzaCA9IEFycmF5LmZyb20obmV3IFVpbnQ4QXJyYXkoYm9keUhhc2hCdWYpKS5tYXAoYiA9PiBiLnRvU3RyaW5nKDE2KS5wYWRTdGFydCgyLCAnMCcpKS5qb2luKCcnKTsKICAgIGNvbnN0IGhtYWNLZXkgPSBhd2FpdCBjLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGVuYy5lbmNvZGUoQVBJX1NFQ1JFVCksIHsKICAgICAgbmFtZTogJ0hNQUMnLAogICAgICBoYXNoOiAnU0hBLTI1NicKICAgIH0sIGZhbHNlLCBbICdzaWduJyBdKTsKICAgIGNvbnN0IHNpZ0J1ZiA9IGF3YWl0IGMuc3VidGxlLnNpZ24oJ0hNQUMnLCBobWFjS2V5LCBlbmMuZW5jb2RlKHRzICsgJ3wnICsgbm9uY2UgKyAnfCcgKyBib2R5SGFzaCArICd8JyArIChzZXNzaW9uVG9rIHx8ICcnKSkpOwogICAgY29uc3Qgc2lnbiA9IEFycmF5LmZyb20obmV3IFVpbnQ4QXJyYXkoc2lnQnVmKSkubWFwKGIgPT4gYi50b1N0cmluZygxNikucGFkU3RhcnQoMiwgJzAnKSkuam9pbignJyk7CiAgICByZXR1cm4gewogICAgICAnWC1Ucyc6IHRzLAogICAgICAnWC1Ob25jZSc6IG5vbmNlLAogICAgICAnWC1TaWduJzogc2lnbgogICAgfTsKICB9CiAgZnVuY3Rpb24gX2NvbGxlY3REZXZpY2UoKSB7CiAgICBjb25zdCB1YSA9IG5hdmlnYXRvci51c2VyQWdlbnQgfHwgJyc7CiAgICBjb25zdCBpc0FuZHJvaWQgPSAvYW5kcm9pZC9pLnRlc3QodWEpOwogICAgY29uc3QgaXNJT1MgPSAvaXBob25lfGlwYWR8aXBvZC9pLnRlc3QodWEpOwogICAgbGV0IG1vZGVsID0gJyc7CiAgICBpZiAoaXNBbmRyb2lkKSB7CiAgICAgIGNvbnN0IG0gPSB1YS5tYXRjaCgvO1xzKihbXjspXSs/KVxzK0J1aWxkXC8vaSkgfHwgdWEubWF0Y2goL2FuZHJvaWRccytbXjspXSs7XHMqKFteOyldKykvaSk7CiAgICAgIG1vZGVsID0gbSA/IG1bMV0udHJpbSgpIDogJyc7CiAgICB9IGVsc2UgaWYgKGlzSU9TKSB7CiAgICAgIG1vZGVsID0gL2lwYWQvaS50ZXN0KHVhKSA/ICdpUGFkJyA6IC9pcG9kL2kudGVzdCh1YSkgPyAnaVBvZCcgOiAnaVBob25lJzsKICAgICAgaWYgKC9mb2N1cy9pLnRlc3QodWEpKSBtb2RlbCArPSAnIChGb2N1cyknOwogICAgfQogICAgY29uc3QgY29ubiA9IG5hdmlnYXRvci5jb25uZWN0aW9uIHx8IG5hdmlnYXRvci5tb3pDb25uZWN0aW9uIHx8IG5hdmlnYXRvci53ZWJraXRDb25uZWN0aW9uOwogICAgcmV0dXJuIHsKICAgICAgb3M6IGlzQW5kcm9pZCA/ICdBbmRyb2lkJyA6IGlzSU9TID8gJ2lPUycgOiBuYXZpZ2F0b3IucGxhdGZvcm0gfHwgJ1Vua25vd24nLAogICAgICBtb2RlbDogbW9kZWwgfHwgJycsCiAgICAgIGJyYW5kOiAnJywKICAgICAgaXNNb2JpbGU6IGlzQW5kcm9pZCB8fCBpc0lPUywKICAgICAgdG91Y2hQb2ludHM6IG5hdmlnYXRvci5tYXhUb3VjaFBvaW50cyB8fCAwLAogICAgICBjb3JlczogbmF2aWdhdG9yLmhhcmR3YXJlQ29uY3VycmVuY3kgfHwgMCwKICAgICAgbWVtb3J5OiBuYXZpZ2F0b3IuZGV2aWNlTWVtb3J5IHx8IDAsCiAgICAgIHNjcmVlbjogYCR7c2NyZWVuLndpZHRofXgke3NjcmVlbi5oZWlnaHR9YCwKICAgICAgcGl4ZWxSYXRpbzogd2luZG93LmRldmljZVBpeGVsUmF0aW8gfHwgMSwKICAgICAgY29ubmVjdGlvbjogY29ubiA/IGNvbm4uZWZmZWN0aXZlVHlwZSB8fCAnJyA6ICcnLAogICAgICB2ZW5kb3I6IG5hdmlnYXRvci52ZW5kb3IgfHwgJycsCiAgICAgIGxhbmd1YWdlOiBuYXZpZ2F0b3IubGFuZ3VhZ2UgfHwgJycsCiAgICAgIHRpbWV6b25lOiBJbnRsLkRhdGVUaW1lRm9ybWF0KCkucmVzb2x2ZWRPcHRpb25zKCkudGltZVpvbmUgfHwgJycsCiAgICAgIHdlYmRyaXZlcjogISFuYXZpZ2F0b3Iud2ViZHJpdmVyCiAgICB9OwogIH0KICBmdW5jdGlvbiBfY29sbGVjdEZQKCkgewogICAgcmV0dXJuIHsKICAgICAgdWE6IG5hdmlnYXRvci51c2VyQWdlbnQsCiAgICAgIHBsYXRmb3JtOiBuYXZpZ2F0b3IucGxhdGZvcm0gfHwgJycsCiAgICAgIGxhbmd1YWdlOiBuYXZpZ2F0b3IubGFuZ3VhZ2UgfHwgJycsCiAgICAgIHRpbWV6b25lOiBJbnRsLkRhdGVUaW1lRm9ybWF0KCkucmVzb2x2ZWRPcHRpb25zKCkudGltZVpvbmUgfHwgJycsCiAgICAgIHdlYmRyaXZlcjogISFuYXZpZ2F0b3Iud2ViZHJpdmVyLAogICAgICBoYXJkd2FyZUNvbmN1cnJlbmN5OiBuYXZpZ2F0b3IuaGFyZHdhcmVDb25jdXJyZW5jeSB8fCAwLAogICAgICBkZXZpY2VNZW1vcnk6IG5hdmlnYXRvci5kZXZpY2VNZW1vcnkgfHwgMCwKICAgICAgbWF4VG91Y2hQb2ludHM6IG5hdmlnYXRvci5tYXhUb3VjaFBvaW50cyB8fCAwLAogICAgICBzY3JlZW46IGAke3NjcmVlbi53aWR0aH14JHtzY3JlZW4uaGVpZ2h0fWAsCiAgICAgIGNvbG9yRGVwdGg6IHNjcmVlbi5jb2xvckRlcHRoLAogICAgICBwaXhlbFJhdGlvOiB3aW5kb3cuZGV2aWNlUGl4ZWxSYXRpbyB8fCAxCiAgICB9OwogIH0KICBhc3luYyBmdW5jdGlvbiBfZGVyaXZlS2V5KHNlc3Npb25Ub2tlbikgewogICAgY29uc3QgZW5jID0gbmV3IFRleHRFbmNvZGVyLCBjID0gX2NyeXB0b09iaigpOwogICAgY29uc3QgYmFzZUtleSA9IGF3YWl0IGMuc3VidGxlLmltcG9ydEtleSgncmF3JywgZW5jLmVuY29kZSgoc2Vzc2lvblRva2VuIHx8ICcnKSArICd8JyArIEFQSV9TRUNSRVQpLCAnUEJLREYyJywgZmFsc2UsIFsgJ2Rlcml2ZUJpdHMnIF0pOwogICAgY29uc3QgYml0cyA9IGF3YWl0IGMuc3VidGxlLmRlcml2ZUJpdHMoewogICAgICBuYW1lOiAnUEJLREYyJywKICAgICAgc2FsdDogZW5jLmVuY29kZSgnZ29kbW9kZS12NC1zYWx0JyksCiAgICAgIGl0ZXJhdGlvbnM6IDFlMywKICAgICAgaGFzaDogJ1NIQS0yNTYnCiAgICB9LCBiYXNlS2V5LCAyNTYpOwogICAgcmV0dXJuIGMuc3VidGxlLmltcG9ydEtleSgncmF3JywgYml0cywgewogICAgICBuYW1lOiAnQUVTLUdDTScKICAgIH0sIGZhbHNlLCBbICdkZWNyeXB0JyBdKTsKICB9CiAgZnVuY3Rpb24gX2I2NFRvQnl0ZXMoYjY0KSB7CiAgICBjb25zdCBiaW4gPSBhdG9iKGI2NCk7CiAgICByZXR1cm4gVWludDhBcnJheS5mcm9tKGJpbiwgeCA9PiB4LmNoYXJDb2RlQXQoMCkpOwogIH0KICBhc3luYyBmdW5jdGlvbiBfZGVjcnlwdEFuc3dlcnMocGF5bG9hZCwgc2Vzc2lvblRva2VuKSB7CiAgICBjb25zdCBjID0gX2NyeXB0b09iaigpOwogICAgY29uc3Qga2V5ID0gYXdhaXQgX2Rlcml2ZUtleShzZXNzaW9uVG9rZW4pOwogICAgY29uc3QgaXYgPSBfYjY0VG9CeXRlcyhwYXlsb2FkLml2KSwgZGF0YSA9IF9iNjRUb0J5dGVzKHBheWxvYWQuZGF0YSksIHRhZyA9IF9iNjRUb0J5dGVzKHBheWxvYWQudGFnKTsKICAgIGNvbnN0IGJ1ZiA9IG5ldyBVaW50OEFycmF5KGRhdGEubGVuZ3RoICsgdGFnLmxlbmd0aCk7CiAgICBidWYuc2V0KGRhdGEpOwogICAgYnVmLnNldCh0YWcsIGRhdGEubGVuZ3RoKTsKICAgIGNvbnN0IHBsYWluID0gYXdhaXQgYy5zdWJ0bGUuZGVjcnlwdCh7CiAgICAgIG5hbWU6ICdBRVMtR0NNJywKICAgICAgaXY6IGl2CiAgICB9LCBrZXksIGJ1Zik7CiAgICByZXR1cm4gSlNPTi5wYXJzZSgobmV3IFRleHREZWNvZGVyKS5kZWNvZGUocGxhaW4pKTsKICB9CiAgYXN5bmMgZnVuY3Rpb24gX2Vuc3VyZVNlc3Npb24oa2V5LCBod2lkKSB7CiAgICBpZiAoX3NlY1Nlc3Npb24udG9rZW4gJiYgX3NlY1Nlc3Npb24uZXhwID4gRGF0ZS5ub3coKSkgcmV0dXJuIF9zZWNTZXNzaW9uLnRva2VuOwogICAgaWYgKCFrZXkpIHRocm93IG5ldyBFcnJvcignVGhp4bq/dSBrZXkg4oCUIGtow7RuZyB0aOG7gyB4w6FjIHRo4buxYyBwaGnDqm4nKTsKICAgIGNvbnN0IHIgPSBhd2FpdCBnbVBvc3QoJy9hdHRlc3QnLCB7CiAgICAgIGtleToga2V5LAogICAgICBod2lkOiBod2lkIHx8IGdldEhXSUQoKSwKICAgICAgZnA6IF9jb2xsZWN0RlAoKSwKICAgICAgZGV2aWNlOiBfY29sbGVjdERldmljZSgpCiAgICB9KTsKICAgIGlmICghci5zdWNjZXNzKSB0aHJvdyBuZXcgRXJyb3Ioci5tZXNzYWdlIHx8IHIuZXJyb3IgfHwgJ1jDoWMgdGjhu7FjIHRoaeG6v3QgYuG7iy9t4bqhbmcgdGjhuqV0IGLhuqFpIChIVFRQICcgKyAoci5faHR0cFN0YXR1cyB8fCAwKSArICcpIOKAlCB4ZW0gcGFuZWwgYWRtaW4gbG9nIMSR4buDIGJp4bq/dCBsw70gZG8pJyk7CiAgICBfc2VjU2Vzc2lvbiA9IHsKICAgICAgdG9rZW46IHIuc2Vzc2lvbiwKICAgICAgZXhwOiBEYXRlLm5vdygpICsgKHIuZXhwaXJlc0luIC0gMzApICogMWUzLAogICAgICBmcEhhc2g6IHIuZnBIYXNoLAogICAgICBzZXE6IDEKICAgIH07CiAgICBpZiAoci5kZXZpY2UpIENVUlJFTlRfREVWSUNFID0gci5kZXZpY2U7CiAgICByZXR1cm4gci5zZXNzaW9uOwogIH0KICBmdW5jdGlvbiBfc3RhcnRIZWFydGJlYXQoKSB7CiAgICBpZiAoX2hlYXJ0YmVhdFRpbWVyKSByZXR1cm47CiAgICBfaGVhcnRiZWF0VGltZXIgPSBzZXRJbnRlcnZhbChhc3luYyAoKSA9PiB7CiAgICAgIGlmICghQ1VSUkVOVF9LRVkpIHJldHVybjsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCByID0gYXdhaXQgZ21Qb3N0KCcvaGVhcnRiZWF0JywgewogICAgICAgICAga2V5OiBDVVJSRU5UX0tFWSwKICAgICAgICAgIGh3aWQ6IGdldEhXSUQoKSwKICAgICAgICAgIGZwOiBfY29sbGVjdEZQKCksCiAgICAgICAgICBkZXZpY2U6IF9jb2xsZWN0RGV2aWNlKCksCiAgICAgICAgICBjbGllbnRWZXJzaW9uOiAxOSwKICAgICAgICAgIGNvbm5lY3RvclZlcnNpb246IDE5CiAgICAgICAgfSk7CiAgICAgICAgX2hlYXJ0YmVhdEZhaWwgPSAwOwogICAgICAgIGlmIChyICYmIHIuYmxvY2tlZCkgewogICAgICAgICAgX2VudGVyQmFuTW9kZSgnU2VydmVyIHBow6F0IGhp4buHbiBtw7RpIHRyxrDhu51uZyBraMO0bmcgaOG7o3AgbOG7hyAoJyArIChyLnJlYXNvbiB8fCAndW5rbm93bicpICsgJykuJyk7CiAgICAgICAgICByZXR1cm47CiAgICAgICAgfQogICAgICAgIGlmIChyICYmIHIuX2h0dHBTdGF0dXMgPT09IDQwNCkgewogICAgICAgICAgX2VudGVyQmFuTW9kZSgnVGhp4bq/dCBi4buLL0lQIMSRw6MgYuG7iyBhZG1pbiBraG/DoS4nKTsKICAgICAgICAgIHJldHVybjsKICAgICAgICB9CiAgICAgIH0gY2F0Y2ggKGUpIHsKICAgICAgICBfaGVhcnRiZWF0RmFpbCsrOwogICAgICAgIGlmIChfaGVhcnRiZWF0RmFpbCA+PSAxMCkgewogICAgICAgICAgYWRkTG9nKCfimqDvuI8gTeG6pXQga+G6v3QgbuG7kWkgc2VydmVyIGvDqW8gZMOgaSDigJQgY2jhu6ljIG7Eg25nIG7hu5lwIGLDoGkgdOG6oW0ga2jDs2EgY2hvIHThu5tpIGtoaSBr4bq/dCBu4buRaSBs4bqhaS4nLCAnd2FybicpOwogICAgICAgICAgX2hlYXJ0YmVhdEZhaWwgPSAwOwogICAgICAgIH0KICAgICAgfQogICAgfSwgM2U0KTsKICB9CiAgYXN5bmMgZnVuY3Rpb24gZ21Qb3N0KHBhdGgsIGRhdGEpIHsKICAgIGNvbnN0IGhlYWRlcnMgPSB7CiAgICAgICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbicKICAgIH07CiAgICBsZXQgc2Vzc2lvblRva2VuID0gbnVsbDsKICAgIGNvbnN0IHByZWZpeCA9IGF3YWl0IF9hcGlQcmVmaXgoKTsKICAgIGNvbnN0IGFjdHVhbFBhdGggPSBwcmVmaXggKyBwYXRoOwogICAgaWYgKHBhdGggPT09ICcvcHJvY2VzcycgfHwgcGF0aCA9PT0gJy9maXJlJyB8fCBwYXRoID09PSAnL21vZHVsZScgfHwgcGF0aCA9PT0gJy9hbnN3ZXJzL2xvb2t1cCcgfHwgcGF0aCA9PT0gJy9hbnNmaWxlL2RlY29kZScpIHsKICAgICAgdHJ5IHsKICAgICAgICBzZXNzaW9uVG9rZW4gPSBhd2FpdCBfZW5zdXJlU2Vzc2lvbihkYXRhICYmIGRhdGEua2V5LCBkYXRhICYmIGRhdGEuaHdpZCk7CiAgICAgICAgaGVhZGVyc1snWC1TZXNzaW9uJ10gPSBzZXNzaW9uVG9rZW47CiAgICAgICAgaGVhZGVyc1snWC1TZXEnXSA9IFN0cmluZyhfc2VjU2Vzc2lvbi5zZXEgfHwgMSk7CiAgICAgICAgaWYgKF9zZWNTZXNzaW9uLmZwSGFzaCkgaGVhZGVyc1snWC1GcC1IYXNoJ10gPSBfc2VjU2Vzc2lvbi5mcEhhc2g7CiAgICAgIH0gY2F0Y2ggKF9zZXNzRXJyKSB7CiAgICAgICAgLy8gW3YzMl0gaU9TIEZvY3VzOiBwaGnDqm4gdOG6oW0gbOG7l2kg4oCUIHJpw6puZyB0cmEga2hvIMSRw6FwIMOhbiB24bqrbiBjaOG6oXkgbGVnYWN5CiAgICAgICAgaWYgKHBhdGggIT09ICcvYW5zd2Vycy9sb29rdXAnKSB0aHJvdyBfc2Vzc0VycjsKICAgICAgICBkZWxldGUgaGVhZGVyc1snWC1TZXNzaW9uJ107CiAgICAgIH0KICAgIH0KICAgIGxldCByZXFCb2R5ID0gSlNPTi5zdHJpbmdpZnkoZGF0YSk7CiAgICBpZiAoUkVRVUVTVF9FTkNSWVBUSU9OKSB7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgZW5jID0gYXdhaXQgX2VuY3J5cHRQYXlsb2FkKGRhdGEsIHNlc3Npb25Ub2tlbiB8fCBfYXBpUHJlZml4Q2FjaGUgfHwgJycpOwogICAgICAgIHJlcUJvZHkgPSBKU09OLnN0cmluZ2lmeShlbmMpOwogICAgICAgIGhlYWRlcnNbJ1gtRW5jLVYnXSA9ICc1JzsKICAgICAgfSBjYXRjaCAoXykge30KICAgIH0KICAgIHRyeSB7CiAgICAgIE9iamVjdC5hc3NpZ24oaGVhZGVycywgYXdhaXQgX3NpZ25SZXEocmVxQm9keSwgc2Vzc2lvblRva2VuKSk7CiAgICB9IGNhdGNoIChfKSB7fQogICAgLy8gW3YzMV0gVOG7kWkgxrB1IG3huqFuZyB54bq/dTogdGltZW91dCAxMnMgKyB04buxIHRo4butIGzhuqFpIDIgbOG6p24gKGJhY2tvZmYgMS4ycy8yLjRzKSBraGkgbOG7l2kgbeG6oW5nL3RpbWVvdXQvNXh4LgogICAgLy8gICAgICAgS2jDtG5nIHRo4butIGzhuqFpIHbhu5tpIDQwMS80MDMvNDI5IChs4buXaSBsb2dpYywgc2VydmVyIMSRw6MgcGjhuqNuIGjhu5NpKS4KICAgIGNvbnN0IE1BWF9SRVRSWSA9IHBhdGggPT09ICcvaGVhcnRiZWF0JyA/IDEgOiAyOwogICAgbGV0IHJlc3VsdCA9IG51bGw7CiAgICBmb3IgKGxldCBhdHRlbXB0ID0gMDsgYXR0ZW1wdCA8PSBNQVhfUkVUUlk7IGF0dGVtcHQrKykgewogICAgICB0cnkgewogICAgICAgIHJlc3VsdCA9IGF3YWl0IG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHsKICAgICAgICAgIEdNX3htbGh0dHBSZXF1ZXN0KHsKICAgICAgICAgICAgbWV0aG9kOiAnUE9TVCcsCiAgICAgICAgICAgIHVybDogU0VSVkVSX0JBU0UgKyBhY3R1YWxQYXRoLAogICAgICAgICAgICBoZWFkZXJzOiBoZWFkZXJzLAogICAgICAgICAgICBkYXRhOiByZXFCb2R5LAogICAgICAgICAgICB0aW1lb3V0OiBhdHRlbXB0ID09PSAwID8gMTJlMyA6IDhlMywKICAgICAgICAgICAgb25sb2FkOiByID0+IHsKICAgICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgY29uc3QgcGFyc2VkID0gSlNPTi5wYXJzZShyLnJlc3BvbnNlVGV4dCk7CiAgICAgICAgICAgICAgICBwYXJzZWQuX2h0dHBTdGF0dXMgPSByLnN0YXR1czsKICAgICAgICAgICAgICAgIHJlc29sdmUocGFyc2VkKTsKICAgICAgICAgICAgICB9IGNhdGNoIChfKSB7CiAgICAgICAgICAgICAgICByZWplY3QobmV3IEVycm9yKCdQYXJzZSBlcnJvciAoSFRUUCAnICsgci5zdGF0dXMgKyAnKScpKTsKICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIG9uZXJyb3I6ICgpID0+IHJlamVjdChuZXcgRXJyb3IoJ05ldHdvcmsgZXJyb3InKSksCiAgICAgICAgICAgIG9udGltZW91dDogKCkgPT4gcmVqZWN0KG5ldyBFcnJvcignVGltZW91dCcpKQogICAgICAgICAgfSk7CiAgICAgICAgfSk7CiAgICAgICAgaWYgKHJlc3VsdCAmJiByZXN1bHQuX2h0dHBTdGF0dXMgPj0gNTAwICYmIHJlc3VsdC5faHR0cFN0YXR1cyA8IDYwMCAmJiBhdHRlbXB0IDwgTUFYX1JFVFJZKSB7CiAgICAgICAgICBhd2FpdCBuZXcgUHJvbWlzZShyMiA9PiBzZXRUaW1lb3V0KHIyLCAxMjAwICogKGF0dGVtcHQgKyAxKSkpOwogICAgICAgICAgY29udGludWU7CiAgICAgICAgfQogICAgICAgIGJyZWFrOwogICAgICB9IGNhdGNoIChlKSB7CiAgICAgICAgaWYgKGF0dGVtcHQgPCBNQVhfUkVUUlkpIHsKICAgICAgICAgIGF3YWl0IG5ldyBQcm9taXNlKHIyID0+IHNldFRpbWVvdXQocjIsIDEyMDAgKiAoYXR0ZW1wdCArIDEpKSk7CiAgICAgICAgICBjb250aW51ZTsKICAgICAgICB9CiAgICAgICAgdGhyb3cgZTsKICAgICAgfQogICAgfQogICAgaWYgKHBhdGggPT09ICcvcHJvY2VzcycgJiYgcmVzdWx0ICYmIHJlc3VsdC5lbmNyeXB0ZWQgJiYgcmVzdWx0LnBheWxvYWQgJiYgc2Vzc2lvblRva2VuKSB7CiAgICAgIHRyeSB7CiAgICAgICAgcmVzdWx0LnF1ZXN0aW9ucyA9IGF3YWl0IF9kZWNyeXB0QW5zd2VycyhyZXN1bHQucGF5bG9hZCwgc2Vzc2lvblRva2VuKTsKICAgICAgICByZXN1bHQuZW5jcnlwdGVkID0gZmFsc2U7CiAgICAgIH0gY2F0Y2ggKGUpIHsKICAgICAgICByZXN1bHQuc3VjY2VzcyA9IGZhbHNlOwogICAgICAgIHJlc3VsdC5tZXNzYWdlID0gJ0dp4bqjaSBtw6MgxJHDoXAgw6FuIHRo4bqldCBi4bqhaTogJyArIGUubWVzc2FnZTsKICAgICAgfQogICAgfQogICAgaWYgKHJlc3VsdCAmJiByZXN1bHQubmV4dF9zZXNzaW9uKSB7CiAgICAgIF9zZWNTZXNzaW9uLnRva2VuID0gcmVzdWx0Lm5leHRfc2Vzc2lvbjsKICAgICAgX3NlY1Nlc3Npb24uZXhwID0gRGF0ZS5ub3coKSArIDI3MCAqIDFlMzsKICAgICAgX3NlY1Nlc3Npb24uc2VxID0gcmVzdWx0Lm5leHRfc2VxID8gcGFyc2VJbnQocmVzdWx0Lm5leHRfc2VxLCAxMCkgOiAoX3NlY1Nlc3Npb24uc2VxIHx8IDEpICsgMTsKICAgICAgZGVsZXRlIHJlc3VsdC5uZXh0X3Nlc3Npb247CiAgICAgIGRlbGV0ZSByZXN1bHQubmV4dF9zZXE7CiAgICB9CiAgICByZXR1cm4gcmVzdWx0OwogIH0KICBmdW5jdGlvbiBnZXRVc2VySW5mbygpIHsKICAgIHRyeSB7CiAgICAgIGNvbnN0IG0gPSBkb2N1bWVudC5jb29raWUubWF0Y2goLyg/Ol58OyApdXNlcj0oW147XSopLyk7CiAgICAgIGlmIChtICYmIG1bMV0pIHsKICAgICAgICBjb25zdCBwYXJzZWQgPSBKU09OLnBhcnNlKGRlY29kZVVSSUNvbXBvbmVudChtWzFdKSk7CiAgICAgICAgaWYgKHBhcnNlZCAmJiAocGFyc2VkLl9pZCB8fCBwYXJzZWQuaWQpKSByZXR1cm4gcGFyc2VkOwogICAgICB9CiAgICB9IGNhdGNoIChfKSB7fQogICAgdHJ5IHsKICAgICAgcmV0dXJuIHdpbmRvdy51c2VyX2luZm8gfHwgd2luZG93LnBfY29uZmlnPy51c2VyX2luZm8gfHwgdW5zYWZlV2luZG93Py51c2VyX2luZm8gfHwgbnVsbDsKICAgIH0gY2F0Y2ggKF8pIHsKICAgICAgcmV0dXJuIG51bGw7CiAgICB9CiAgfQogIGZ1bmN0aW9uIGdldE9sbVVzZXJuYW1lKCkgewogICAgdHJ5IHsKICAgICAgY29uc3QgZG9tSW5wdXQgPSBkb2N1bWVudC5xdWVyeVNlbGVjdG9yKCcjaW5mby1hY2NvdW50IGlucHV0LmZvcm0tY29udHJvbFtyZWFkb25seV0nKTsKICAgICAgaWYgKGRvbUlucHV0ICYmIGRvbUlucHV0LnZhbHVlKSByZXR1cm4gZG9tSW5wdXQudmFsdWUudHJpbSgpOwogICAgICBjb25zdCB1aSA9IGdldFVzZXJJbmZvKCk7CiAgICAgIGlmICh1aSAmJiB1aS51c2VybmFtZSkgcmV0dXJuIHVpLnVzZXJuYW1lOwogICAgICBpZiAodWkgJiYgdWkubmFtZSkgcmV0dXJuIHVpLm5hbWU7CiAgICAgIGlmICh1aSAmJiB1aS5lbWFpbCkgcmV0dXJuIHVpLmVtYWlsOwogICAgICBjb25zdCBlbCA9IGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoJy51c2VybmFtZSwgLnVzZXItbmFtZSwgW2NsYXNzKj0idXNlcm5hbWUiXScpOwogICAgICByZXR1cm4gZWwgPyBlbC50ZXh0Q29udGVudC50cmltKCkgOiAnS2hvbmdYYWNEaW5oJzsKICAgIH0gY2F0Y2ggKF8pIHsKICAgICAgcmV0dXJuICdLaG9uZ1hhY0RpbmgnOwogICAgfQogIH0KICBmdW5jdGlvbiBnZXRIV0lEKCkgewogICAgbGV0IGggPSBsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgnX3RsX2h3aWQnKTsKICAgIGlmICghaCkgewogICAgICBjb25zdCB1YSA9IG5hdmlnYXRvci51c2VyQWdlbnQgKyBuYXZpZ2F0b3IubGFuZ3VhZ2UgKyBzY3JlZW4ud2lkdGggKyBzY3JlZW4uaGVpZ2h0OwogICAgICBsZXQgaGFzaCA9IDUzODE7CiAgICAgIGZvciAobGV0IGkgPSAwOyBpIDwgdWEubGVuZ3RoOyBpKyspIGhhc2ggPSAoaGFzaCA8PCA1KSArIGhhc2ggXiB1YS5jaGFyQ29kZUF0KGkpOwogICAgICBoID0gJ0hXJyArIE1hdGguYWJzKGhhc2gpLnRvU3RyaW5nKDE2KS50b1VwcGVyQ2FzZSgpLnBhZFN0YXJ0KDgsICcwJyk7CiAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKCdfdGxfaHdpZCcsIGgpOwogICAgfQogICAgcmV0dXJuIGg7CiAgfQogIGZ1bmN0aW9uIHJpcElkRnJvbVVybCgpIHsKICAgIGNvbnN0IG0gPSB3aW5kb3cubG9jYXRpb24ucGF0aG5hbWUubWF0Y2goLy0oXGQrKSg/Olw/fFwvfCQpLyk7CiAgICByZXR1cm4gbSA/IG1bMV0gOiBudWxsOwogIH0KICBmdW5jdGlvbiBkZXRlY3RVc2VySUQoKSB7CiAgICBjb25zdCB1aSA9IGdldFVzZXJJbmZvKCk7CiAgICByZXR1cm4gU0VTU0lPTi5tZXRhLmlkX3VzZXIgfHwgKHVpID8gdWkuX2lkIHx8IHVpLmlkIDogbnVsbCkgfHwgd2luZG93Py5wX2NvbmZpZz8uaWRfdXNlciB8fCBudWxsOwogIH0KICBmdW5jdGlvbiBkZXRlY3RTY2hvb2xJRChkYXRhKSB7CiAgICByZXR1cm4gZGF0YT8uaWRfc2Nob29sIHx8IHdpbmRvdz8ucF9jb25maWc/LnNjaG9vbF9pZCB8fCBnZXRVc2VySW5mbygpPy5pZF9zY2hvb2wgfHwgbnVsbDsKICB9CiAgZnVuY3Rpb24gZGV0ZWN0R3JvdXBJRCgpIHsKICAgIGNvbnN0IG0gPSB3aW5kb3cubG9jYXRpb24uaHJlZi5tYXRjaCgvXC9sb3BcL1teL10rXC4oXGQrKS8pOwogICAgcmV0dXJuIG0gJiYgbVsxXSA/IG1bMV0gOiBudWxsOwogIH0KICBmdW5jdGlvbiBmb3JjZUdldE1ldGEoKSB7CiAgICBjb25zdCB1aSA9IGdldFVzZXJJbmZvKCk7CiAgICBpZiAoIVNFU1NJT04ubWV0YS5pZF91c2VyKSBTRVNTSU9OLm1ldGEuaWRfdXNlciA9IHVpICYmICh1aS5faWQgfHwgdWkuaWQpIHx8IHdpbmRvdz8ucF9jb25maWc/LmlkX3VzZXIgfHwgZGV0ZWN0VXNlcklEKCk7CiAgICBpZiAoIVNFU1NJT04ubWV0YS5pZF9jYXRlKSBTRVNTSU9OLm1ldGEuaWRfY2F0ZSA9IHdpbmRvdz8ucF9jb25maWc/LmlkX2NhdGUgfHwgd2luZG93Py5wX2NvbmZpZz8uaWRfZXhhbSB8fCBuZXcgVVJMU2VhcmNoUGFyYW1zKHdpbmRvdy5sb2NhdGlvbi5zZWFyY2gpLmdldCgnaWRfY2F0ZScpIHx8IG5ldyBVUkxTZWFyY2hQYXJhbXMod2luZG93LmxvY2F0aW9uLnNlYXJjaCkuZ2V0KCdpZF9leGFtJykgfHwgcmlwSWRGcm9tVXJsKCk7CiAgICBpZiAoIVNFU1NJT04ubWV0YS5pZF9jb3Vyc2V3YXJlKSBTRVNTSU9OLm1ldGEuaWRfY291cnNld2FyZSA9IG5ldyBVUkxTZWFyY2hQYXJhbXMod2luZG93LmxvY2F0aW9uLnNlYXJjaCkuZ2V0KCdpX2MnKSB8fCBuZXcgVVJMU2VhcmNoUGFyYW1zKHdpbmRvdy5sb2NhdGlvbi5zZWFyY2gpLmdldCgnaWRfY291cnNld2FyZScpIHx8IFNFU1NJT04ubWV0YS5pZF9jYXRlOwogICAgaWYgKCFTRVNTSU9OLm1ldGEuaWRfc2Nob29sKSBTRVNTSU9OLm1ldGEuaWRfc2Nob29sID0gdWkgJiYgdWkuaWRfc2Nob29sIHx8IHdpbmRvdz8ucF9jb25maWc/LnNjaG9vbF9pZCB8fCBudWxsOwogICAgaWYgKCFTRVNTSU9OLm1ldGEuY3NyZl90b2tlbikgewogICAgICBjb25zdCBtID0gZG9jdW1lbnQucXVlcnlTZWxlY3RvcignbWV0YVtuYW1lPSJjc3JmLXRva2VuIl0nKTsKICAgICAgU0VTU0lPTi5tZXRhLmNzcmZfdG9rZW4gPSBtID8gbS5nZXRBdHRyaWJ1dGUoJ2NvbnRlbnQnKSA6IHdpbmRvdy5jc3JmX3Rva2VuIHx8ICcnOwogICAgfQogICAgaWYgKCFTRVNTSU9OLm1ldGEuc3ViamVjdF9uYW1lKSBTRVNTSU9OLm1ldGEuc3ViamVjdF9uYW1lID0gZGV0ZWN0U3ViamVjdE5hbWUoKTsKICAgIGlmICghU0VTU0lPTi5tZXRhLmV4ZXJjaXNlX3RpdGxlKSBTRVNTSU9OLm1ldGEuZXhlcmNpc2VfdGl0bGUgPSBkZXRlY3RFeGVyY2lzZVRpdGxlKCk7CiAgfQogIC8vID09PT09IFt2MjFdIE5o4bqtbiBkaeG7h24gVMOKTiBNw5ROIEjhu4xDICsgVMOKTiBCw4BJIFThuqxQOyBjaOG7iSB0cmEga2hvIGtoaSDEkWFuZyDhu58gdHJhbmcgYsOgaSB04bqtcCA9PT09PQogIGNvbnN0IEtOT1dOX1NVQkpFQ1RTID0gWwogICAgJ8SQ4buLYSBsw60nLCAnxJDhu4thIGzDvScsICdUaeG6v25nIEFuaCcsICdUb8OhbicsICdOZ+G7ryB2xINuJywgJ1bEg24nLCAnVuG6rXQgbMOtJywgJ1bhuq10IGzDvScsCiAgICAnSMOzYSBo4buNYycsICdIb8OhIGjhu41jJywgJ1NpbmggaOG7jWMnLCAnTOG7i2NoIHPhu60nLCAnR2nDoW8gZOG7pWMgY8O0bmcgZMOibicsICdHRENEJywKICAgICdUaW4gaOG7jWMnLCAnQ8O0bmcgbmdo4buHJywgJ8OCbSBuaOG6oWMnLCAnTeG7uSB0aHXhuq10JywgJ1Ro4buDIGThu6VjJywgJ0tob2EgaOG7jWMgdOG7sSBuaGnDqm4nLAogICAgJ1Rp4bq/bmcgVmnhu4d0JywgJ1Thu7Egbmhpw6puIHbDoCB4w6MgaOG7mWknLCAnTOG7i2NoIHPhu60gdsOgIMSQ4buLYSBsw60nLCAnxJDhuqFvIMSR4bupYycsCiAgICAnUGjDsm5nIHRo4bunIHbDoCBhbiBuaW5oIHF14buRYyBwaMOybmcnCiAgXTsKICBmdW5jdGlvbiBfbm9ybVRleHQocykgewogICAgcmV0dXJuIFN0cmluZyhzIHx8ICcnKS50b0xvd2VyQ2FzZSgpCiAgICAgIC5ub3JtYWxpemUoJ05GRCcpLnJlcGxhY2UoL1tcdTAzMDAtXHUwMzZmXS9nLCAnJykKICAgICAgLnJlcGxhY2UoL8SRL2csICdkJykucmVwbGFjZSgvW15hLXowLTlcc10vZywgJyAnKS5yZXBsYWNlKC9ccysvZywgJyAnKS50cmltKCk7CiAgfQogIGZ1bmN0aW9uIGRldGVjdFN1YmplY3ROYW1lKCkgewogICAgdHJ5IHsKICAgICAgY29uc3QgcGMgPSB3aW5kb3cucF9jb25maWcgfHwge307CiAgICAgIGNvbnN0IGNhbmQgPSBbcGMuc3ViamVjdF9uYW1lLCBwYy5zdWJqZWN0LCBwYy5jYXRlX25hbWUsIHBjLmNhdGVfdGl0bGUsIHBjLnN1YmplY3RfY29kZSwgcGMubmFtZV07CiAgICAgIGZvciAoY29uc3QgYyBvZiBjYW5kKSB7CiAgICAgICAgY29uc3QgdiA9IChjID09IG51bGwgPyAnJyA6IFN0cmluZyhjKSkudHJpbSgpOwogICAgICAgIGlmICh2ICYmIHYubGVuZ3RoIDw9IDgwKSByZXR1cm4gdjsKICAgICAgfQogICAgfSBjYXRjaCAoXykge30KICAgIHRyeSB7CiAgICAgIGNvbnN0IHNlbCA9IFsnW2NsYXNzKj0ic3ViamVjdC1uYW1lIl0nLCAnW2NsYXNzKj0ic3ViamVjdE5hbWUiXScsICdbY2xhc3MqPSJjYXRlLW5hbWUiXScsICdbY2xhc3MqPSJjYXRlTmFtZSJdJywgJy5iYWRnZS1zdWJqZWN0JywgJy50YWctc3ViamVjdCcsICdbY2xhc3MqPSJiYWRnZS1jYXRlIl0nLCAnW2NsYXNzKj0icGlsbC1zdWJqZWN0Il0nLCAnW2NsYXNzKj0idGFnLWNhdGUiXSddOwogICAgICBmb3IgKGNvbnN0IHMgb2Ygc2VsKSB7CiAgICAgICAgY29uc3QgZWwgPSBkb2N1bWVudC5xdWVyeVNlbGVjdG9yKHMpOwogICAgICAgIGlmIChlbCkgewogICAgICAgICAgY29uc3QgdiA9IChlbC50ZXh0Q29udGVudCB8fCAnJykudHJpbSgpLnJlcGxhY2UoL1xzKy9nLCAnICcpOwogICAgICAgICAgaWYgKHYgJiYgdi5sZW5ndGggPD0gNjApIHJldHVybiB2OwogICAgICAgIH0KICAgICAgfQogICAgfSBjYXRjaCAoXykge30KICAgIHRyeSB7CiAgICAgIGNvbnN0IG5vZGVzID0gZG9jdW1lbnQucXVlcnlTZWxlY3RvckFsbCgnaDEsaDIsaDMsaDQsLnRpdGxlLC5leGFtLXRpdGxlLC5wcmFjdGljZS10aXRsZSwuZXhlcmNpc2UtdGl0bGUsLmxlc3Nvbi10aXRsZSxbY2xhc3MqPSJiYWRnZSJdLFtjbGFzcyo9ImNoaXAiXSxbY2xhc3MqPSJ0YWciXScpOwogICAgICBjb25zdCBoYXkgPSBbXTsKICAgICAgbm9kZXMuZm9yRWFjaChuID0+IHsgY29uc3QgdCA9IChuLnRleHRDb250ZW50IHx8ICcnKS50cmltKCk7IGlmICh0ICYmIHQubGVuZ3RoIDwgMTIwKSBoYXkucHVzaCh0KTsgfSk7CiAgICAgIGhheS5wdXNoKGRvY3VtZW50LnRpdGxlIHx8ICcnKTsKICAgICAgZm9yIChjb25zdCBzdWJqIG9mIEtOT1dOX1NVQkpFQ1RTKSB7CiAgICAgICAgY29uc3QgayA9IF9ub3JtVGV4dChzdWJqKTsKICAgICAgICBpZiAoIWspIGNvbnRpbnVlOwogICAgICAgIGZvciAoY29uc3QgdCBvZiBoYXkpIHsgaWYgKF9ub3JtVGV4dCh0KS5pbmNsdWRlcyhrKSkgcmV0dXJuIHN1Ymo7IH0KICAgICAgfQogICAgfSBjYXRjaCAoXykge30KICAgIHJldHVybiAnJzsKICB9CiAgZnVuY3Rpb24gZGV0ZWN0RXhlcmNpc2VUaXRsZSgpIHsKICAgIHRyeSB7CiAgICAgIGNvbnN0IHBjID0gd2luZG93LnBfY29uZmlnIHx8IHt9OwogICAgICBjb25zdCBjYW5kID0gW3BjLnRpdGxlLCBwYy5leGVyY2lzZV90aXRsZSwgcGMuZXhhbV9uYW1lLCBwYy5leGVyY2lzZV9uYW1lLCBwYy50ZXN0X3RpdGxlLCBwYy5jb3Vyc2V3YXJlX3RpdGxlLCBwYy5uYW1lXTsKICAgICAgZm9yIChjb25zdCBjIG9mIGNhbmQpIHsKICAgICAgICBjb25zdCB2ID0gKGMgPT0gbnVsbCA/ICcnIDogU3RyaW5nKGMpKS50cmltKCk7CiAgICAgICAgaWYgKHYgJiYgdi5sZW5ndGggPD0gMzAwKSByZXR1cm4gdjsKICAgICAgfQogICAgfSBjYXRjaCAoXykge30KICAgIHRyeSB7CiAgICAgIGNvbnN0IG5vZGVzID0gZG9jdW1lbnQucXVlcnlTZWxlY3RvckFsbCgnaDEsLmV4YW0tdGl0bGUsLnByYWN0aWNlLXRpdGxlLC5leGVyY2lzZS10aXRsZSwubGVzc29uLXRpdGxlLC5jYXJkLXRpdGxlLFtjbGFzcyo9InRpdGxlLW1haW4iXSxbY2xhc3MqPSJsZXNzb24tbmFtZSJdJyk7CiAgICAgIGxldCBiZXN0ID0gJyc7CiAgICAgIG5vZGVzLmZvckVhY2gobiA9PiB7IGNvbnN0IHQgPSAobi50ZXh0Q29udGVudCB8fCAnJykudHJpbSgpLnJlcGxhY2UoL1xzKy9nLCAnICcpOyBpZiAodCAmJiB0Lmxlbmd0aCA+IGJlc3QubGVuZ3RoICYmIHQubGVuZ3RoIDw9IDMwMCkgYmVzdCA9IHQ7IH0pOwogICAgICBpZiAoYmVzdCkgcmV0dXJuIGJlc3Q7CiAgICB9IGNhdGNoIChfKSB7fQogICAgdHJ5IHsKICAgICAgbGV0IGxhc3QgPSAnJzsKICAgICAgZG9jdW1lbnQucXVlcnlTZWxlY3RvckFsbCgnW2NsYXNzKj0iYnJlYWRjcnVtYiJdIGEsW2NsYXNzKj0iY3J1bWIiXSBhLC5icmVhZGNydW1iIGEsbmF2IGEnKS5mb3JFYWNoKGEgPT4geyBjb25zdCB0ID0gKGEudGV4dENvbnRlbnQgfHwgJycpLnRyaW0oKTsgaWYgKHQpIGxhc3QgPSB0OyB9KTsKICAgICAgaWYgKGxhc3QgJiYgbGFzdC5sZW5ndGggPD0gMzAwKSByZXR1cm4gbGFzdDsKICAgIH0gY2F0Y2ggKF8pIHt9CiAgICB0cnkgewogICAgICBsZXQgdCA9IChkb2N1bWVudC50aXRsZSB8fCAnJykucmVwbGFjZSgvWy184oCTXVxzKihPTE18b2xtKShcLlZOfFwudm4pPy4qJC9pLCAnJykucmVwbGFjZSgvXlxzKsSQxINuZyBuaOG6rXAuKiQvaSwgJycpLnRyaW0oKTsKICAgICAgaWYgKHQgJiYgdC5sZW5ndGggPD0gMzAwKSByZXR1cm4gdDsKICAgIH0gY2F0Y2ggKF8pIHt9CiAgICByZXR1cm4gJyc7CiAgfQogIGZ1bmN0aW9uIGlzRXhlcmNpc2VQYWdlKCkgewogICAgdHJ5IHsKICAgICAgaWYgKFNFU1NJT04ucmF3X3F1ZXN0aW9ucyAmJiBTRVNTSU9OLnJhd19xdWVzdGlvbnMubGVuZ3RoID4gMCkgcmV0dXJuIHRydWU7CiAgICAgIGNvbnN0IHAgPSBsb2NhdGlvbi5wYXRobmFtZSB8fCAnJzsKICAgICAgY29uc3QgcSA9IGxvY2F0aW9uLnNlYXJjaCB8fCAnJzsKICAgICAgaWYgKC9pZF9jYXRlPXxpZF9leGFtPXxpZF9jb3Vyc2V3YXJlPXwoXnxbPyZdKWlfYz18Y2F0ZV9pZD18ZXhhbV9pZD0vaS50ZXN0KHEpKSByZXR1cm4gdHJ1ZTsKICAgICAgaWYgKC9cLyhleGVyY2lzZXxwcmFjdGljZXxsdXllbi10YXB8ZXhhbXx0ZXN0fGtpZW0tdHJhfGJhaS10YXB8bGVzc29ufHF1aXp8Y291cnNld2FyZSkoXC98XD98JCkvaS50ZXN0KHApKSByZXR1cm4gdHJ1ZTsKICAgICAgaWYgKGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoJy5xdWVzdGlvbi1saXN0LC5xLWl0ZW0sW2NsYXNzKj0icXVlc3Rpb24taXRlbSJdLFtkYXRhLXF1ZXN0aW9uLWlkXSx0ZXh0YXJlYVtkYXRhLWFjY2VwdF0sLnRpbWUtY291bnRkb3duLCNzdWJtaXQtdGVzdCxbY2xhc3MqPSJleGFtLWJvZHkiXSxbY2xhc3MqPSJxdWVzdGlvbi1jb250ZW50Il0nKSkgcmV0dXJuIHRydWU7CiAgICAgIHJldHVybiBmYWxzZTsKICAgIH0gY2F0Y2ggKF8pIHsgcmV0dXJuIGZhbHNlOyB9CiAgfQogIGZ1bmN0aW9uIHJlZnJlc2hTdWJqZWN0VGl0bGVVSSgpIHsKICAgIHRyeSB7CiAgICAgIGNvbnN0IHNlID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLXN1YmplY3QtbmFtZScpOwogICAgICBjb25zdCB0ZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1leGVyY2lzZS10aXRsZScpOwogICAgICBpZiAoc2UpIHNlLnRleHRDb250ZW50ID0gU0VTU0lPTi5tZXRhLnN1YmplY3RfbmFtZSB8fCAn4oCUJzsKICAgICAgaWYgKHRlKSB0ZS50ZXh0Q29udGVudCA9IFNFU1NJT04ubWV0YS5leGVyY2lzZV90aXRsZSB8fCAn4oCUJzsKICAgIH0gY2F0Y2ggKF8pIHt9CiAgfQogIC8vIFt2MzNdIENo4buRbmcgbOG6t3AgbG9nOiBt4buXaSBu4buZaSBkdW5nIGNo4buJIGhp4buHbiAxIGzhuqduIChraMO0bmcgbmjDom4gNCBkw7JuZyBUaW1lb3V0IC8gIsSRw6MgaGnhu4NuIHRo4buLIMSRw6FwIMOhbiIpCiAgY29uc3QgX3RsTG9nU2VlbkFyciA9IFtdOwogIGNvbnN0IF90bExvZ1NlZW5TZXQgPSBuZXcgU2V0KCk7CiAgZnVuY3Rpb24gYWRkTG9nKG1zZywgdHlwZSA9ICcnKSB7CiAgICBjb25zdCBib3ggPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtbG9nYm94Jyk7CiAgICBpZiAoIWJveCkgcmV0dXJuOwogICAgdHJ5IHsKICAgICAgY29uc3QgX2xvZ0tleSA9ICh0eXBlIHx8ICcnKSArICd8JyArIFN0cmluZyhtc2cgPT0gbnVsbCA/ICcnIDogbXNnKTsKICAgICAgaWYgKF90bExvZ1NlZW5TZXQuaGFzKF9sb2dLZXkpKSByZXR1cm47CiAgICAgIF90bExvZ1NlZW5TZXQuYWRkKF9sb2dLZXkpOwogICAgICBfdGxMb2dTZWVuQXJyLnB1c2goX2xvZ0tleSk7CiAgICAgIGlmIChfdGxMb2dTZWVuQXJyLmxlbmd0aCA+IDMwMCkgX3RsTG9nU2VlblNldC5kZWxldGUoX3RsTG9nU2VlbkFyci5zaGlmdCgpKTsKICAgIH0gY2F0Y2ggKF8pIHt9CiAgICBjb25zdCBkID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICBkLmNsYXNzTmFtZSA9ICd0bC1sb2cgJyArIHR5cGU7CiAgICBjb25zdCB0aW1lID0gKG5ldyBEYXRlKS50b0xvY2FsZVRpbWVTdHJpbmcoJ3ZpLVZOJywgewogICAgICBob3VyOiAnMi1kaWdpdCcsCiAgICAgIG1pbnV0ZTogJzItZGlnaXQnLAogICAgICBzZWNvbmQ6ICcyLWRpZ2l0JwogICAgfSk7CiAgICBkLmlubmVySFRNTCA9IGBbJHt0aW1lfV0gJHttc2d9YDsKICAgIGJveC5hcHBlbmRDaGlsZChkKTsKICAgIGJveC5zY3JvbGxUb3AgPSBib3guc2Nyb2xsSGVpZ2h0OwogIH0KICB3aW5kb3cuYWRkTG9nID0gYWRkTG9nOwogIC8vIFt2MzFdIFRyYW5nICJM4bubcCBo4buNYyBj4bunYSB0w7RpIiAoaHR0cHM6Ly9vbG0udm4vbG9wLWhvYy1jdWEtdG9pKSBoaeG7g24gdGjhu4sgdMOgaSBraG/huqNuIE9MTTsKICAvLyAgICAgICB0cmFuZyBiw6BpIHThuq1wIC8ga2nhu4NtIHRyYSAvIHZpZGVvIEtIw5RORyBoaeG7g24gdGjhu4suCiAgLy8gW3YzM10gVGjDqm0gdHJhbmcgIkLDoGkgdOG6rXAgxJHGsOG7o2MgZ2lhbyIgKGh0dHBzOi8vb2xtLnZuL2JhaS10YXAtZHVvYy1naWFvKTogY8WpbmcgaGnhu4duIHTDoGkga2hv4bqjbiBPTE0gxJFhbmcgxJHEg25nIG5o4bqtcC4KICBmdW5jdGlvbiBfaXNDbGFzc0xpc3RQYWdlKCkgewogICAgdHJ5IHsKICAgICAgcmV0dXJuIFN0cmluZyhsb2NhdGlvbi5ocmVmIHx8ICcnKS5pbmRleE9mKCdsb3AtaG9jLWN1YS10b2knKSAhPT0gLTE7CiAgICB9IGNhdGNoIChfKSB7IHJldHVybiBmYWxzZTsgfQogIH0KICBmdW5jdGlvbiBfaXNIb21ld29ya0xpc3RQYWdlKCkgewogICAgdHJ5IHsKICAgICAgcmV0dXJuIFN0cmluZyhsb2NhdGlvbi5wYXRobmFtZSB8fCAnJykgPT09ICcvYmFpLXRhcC1kdW9jLWdpYW8nIHx8CiAgICAgICAgICAgICBTdHJpbmcobG9jYXRpb24uaHJlZiB8fCAnJykuaW5kZXhPZignYmFpLXRhcC1kdW9jLWdpYW8nKSAhPT0gLTE7CiAgICB9IGNhdGNoIChfKSB7IHJldHVybiBmYWxzZTsgfQogIH0KICBmdW5jdGlvbiBfYWNjb3VudFBhZ2UoKSB7CiAgICB0cnkgeyByZXR1cm4gX2lzQ2xhc3NMaXN0UGFnZSgpIHx8IF9pc0hvbWV3b3JrTGlzdFBhZ2UoKTsgfSBjYXRjaCAoXykgeyByZXR1cm4gZmFsc2U7IH0KICB9CiAgZnVuY3Rpb24gX3JlbW92ZU9sbUxvZ1Jvd3MoKSB7CiAgICB0cnkgewogICAgICBjb25zdCBib3ggPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtbG9nYm94Jyk7CiAgICAgIGlmICghYm94KSByZXR1cm47CiAgICAgIGJveC5xdWVyeVNlbGVjdG9yQWxsKCcudGwtbG9nJykuZm9yRWFjaChuID0+IHsKICAgICAgICBpZiAobi5nZXRBdHRyaWJ1dGUgJiYgbi5nZXRBdHRyaWJ1dGUoJ2RhdGEtb2xtLXJvdycpID09PSAnMScpIHsgbi5yZW1vdmUoKTsgcmV0dXJuOyB9CiAgICAgICAgaWYgKC9Uw6BpIGtob+G6o24gT0xNL2kudGVzdChuLnRleHRDb250ZW50IHx8ICcnKSkgbi5yZW1vdmUoKTsKICAgICAgfSk7CiAgICB9IGNhdGNoIChfKSB7fQogIH0KICBmdW5jdGlvbiBfZW5zdXJlT2xtTG9nKHUpIHsKICAgIHRyeSB7CiAgICAgIGNvbnN0IGJveCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1sb2dib3gnKTsKICAgICAgaWYgKCFib3gpIHJldHVybjsKICAgICAgaWYgKGJveC5xdWVyeVNlbGVjdG9yKCcudGwtbG9nW2RhdGEtb2xtLXJvdz0iMSJdJykpIHJldHVybjsKICAgICAgaWYgKCF1IHx8IHUgPT09ICdLaG9uZ1hhY0RpbmgnKSByZXR1cm47CiAgICAgIGNvbnN0IGQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgICAgZC5jbGFzc05hbWUgPSAndGwtbG9nIGluZm8nOwogICAgICBkLnNldEF0dHJpYnV0ZSgnZGF0YS1vbG0tcm93JywgJzEnKTsKICAgICAgY29uc3QgdGltZSA9IChuZXcgRGF0ZSkudG9Mb2NhbGVUaW1lU3RyaW5nKCd2aS1WTicsIHsgaG91cjogJzItZGlnaXQnLCBtaW51dGU6ICcyLWRpZ2l0Jywgc2Vjb25kOiAnMi1kaWdpdCcgfSk7CiAgICAgIGQuaW5uZXJIVE1MID0gYFske3RpbWV9XSDwn5GkIFTDoGkga2hv4bqjbiBPTE06ICR7dX1gOwogICAgICBib3guYXBwZW5kQ2hpbGQoZCk7CiAgICAgIGJveC5zY3JvbGxUb3AgPSBib3guc2Nyb2xsSGVpZ2h0OwogICAgfSBjYXRjaCAoXykge30KICB9CiAgZnVuY3Rpb24gYnVpbGRMb2NrU2NyZWVuKHJlYXNvbikgewogICAgaWYgKGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1jb25uLW92ZXJsYXknKSkgcmV0dXJuOwogICAgbGV0IGxvY2tTdHlsZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1sb2NrLXN0eWxlJyk7CiAgICBpZiAoIWxvY2tTdHlsZSkgewogICAgICBsb2NrU3R5bGUgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdzdHlsZScpOwogICAgICBsb2NrU3R5bGUuaWQgPSAndGwtbG9jay1zdHlsZSc7CiAgICAgIGRvY3VtZW50LmhlYWQuYXBwZW5kQ2hpbGQobG9ja1N0eWxlKTsKICAgIH0KICAgIGxvY2tTdHlsZS50ZXh0Q29udGVudCA9IGdldExvY2tTY3JlZW5TdHlsZXMoKTsKICAgIGNvbnN0IG92ZXJsYXkgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgIG92ZXJsYXkuaWQgPSAndGwtY29ubi1vdmVybGF5JzsKICAgIGNvbnN0IHRsRnggPSBnZXRUaGVtZUNvbG9ycyhDVVJSRU5UX1RIRU1FKS5wYW5lbEV4dHJhIHx8ICcnOwogICAgb3ZlcmxheS5pbm5lckhUTUwgPSBgXG4gICAgICAgICAgICA8ZGl2IGlkPSJ0bC1jb25uLXBhbmVsIj5cbiAgICAgICAgICAgICAgICAke3RsRnh9XG4gICAgICAgICAgICAgICAgPGRpdiBpZD0idGwtY29ubi1oZWFkZXIiPlxuICAgICAgICAgICAgICAgICAgICA8c3BhbiBjbGFzcz0idGwtYnJhbmQtbmFtZSI+8J+agCBUSEnDik4gVEFJIFTDmSBU4buYSSAvLyBHT0QgTU9ERSB2My40PC9zcGFuPlxuICAgICAgICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgICAgICAgIDxkaXYgaWQ9InRsLWNvbm4tYm9keSI+XG4gICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLXN1YnRpdGxlIj7wn5SQIE5I4bqsUCBMSUNFTlNFIEtFWSDEkOG7giBLw41DSCBIT+G6oFQ8L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgJHtyZWFzb24gPyBgPGRpdiBjbGFzcz0idGwtd2FybmluZyI+4pqg77iPICR7cmVhc29ufTwvZGl2PmAgOiAnJ31cbiAgICAgICAgICAgICAgICAgICAgPGlucHV0IHR5cGU9InRleHQiIGNsYXNzPSJ0bC1pbnB1dCIgaWQ9InRsLWtleS1pbnB1dCJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgIHBsYWNlaG9sZGVyPSJOaOG6rXAga2V5IGLhuqNuIHF1eeG7gW4uLi4iIGF1dG9jb21wbGV0ZT0ib2ZmIj5cbiAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0idGwtYnRuIHRsLWJ0bi11bmxvY2siIGlkPSJ0bC1idG4tdW5sb2NrIj7wn5STIEvDjUNIIEhP4bqgVDwvYnV0dG9uPlxuICAgICAgICAgICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJ0bC1idG4gdGwtYnRuLXZpcCIgICBpZD0idGwtYnRuLWJ1eSI+8J+SjiBNVUEgS0VZIChMScOKTiBI4buGKTwvYnV0dG9uPlxuICAgICAgICAgICAgICAgICAgICA8ZGl2IGlkPSJ0bC1lcnIiPjwvZGl2PlxuICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC1od2lkIiBpZD0idGwtaHdpZC1kaXNwbGF5Ij48L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtZm9vdCI+WcOqdSBj4bqndTogbcOheSBBbmRyb2lkL2lPUyB0aOG6rXQg4oCiIHRyw6xuaCBkdXnhu4d0IHRo4bqtdCDigKIgbeG6oW5nIHRo4bqtdDwvZGl2PlxuICAgICAgICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgICAgPC9kaXY+YDsKICAgIGRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQob3ZlcmxheSk7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtaHdpZC1kaXNwbGF5JykudGV4dENvbnRlbnQgPSBg8J+UkSBIV0lEOiAke2dldEhXSUQoKX1gOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLWJ0bi1idXknKS5vbmNsaWNrID0gKCkgPT4gd2luZG93Lm9wZW4oJ2h0dHBzOi8vdC5tZS9sdW9uZ3R1eWVuMjAnLCAnX2JsYW5rJyk7CiAgICBjb25zdCBidG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtYnRuLXVubG9jaycpOwogICAgY29uc3QgZXJyQm94ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLWVycicpOwogICAgbGV0IHZlcmlmeWluZyA9IGZhbHNlOwogICAgYnRuLm9uY2xpY2sgPSBhc3luYyAoKSA9PiB7CiAgICAgIGlmICh2ZXJpZnlpbmcpIHJldHVybjsKICAgICAgY29uc3Qga2V5ID0gKGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1rZXktaW5wdXQnKS52YWx1ZSB8fCAnJykudHJpbSgpLnRvVXBwZXJDYXNlKCk7CiAgICAgIGlmICgha2V5KSB7CiAgICAgICAgZXJyQm94LnRleHRDb250ZW50ID0gJ+KdjCBWdWkgbMOybmcgbmjhuq1wIGtleSEnOwogICAgICAgIGVyckJveC5zdHlsZS5kaXNwbGF5ID0gJ2Jsb2NrJzsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgdmVyaWZ5aW5nID0gdHJ1ZTsKICAgICAgYnRuLnRleHRDb250ZW50ID0gJ+KPsyDEkEFORyBYw4FDIFRI4buwQy4uLic7CiAgICAgIGJ0bi5kaXNhYmxlZCA9IHRydWU7CiAgICAgIGVyckJveC5zdHlsZS5kaXNwbGF5ID0gJ25vbmUnOwogICAgICB0cnkgewogICAgICAgIGNvbnN0IHByZWZpeCA9IGF3YWl0IF9hcGlQcmVmaXgoKTsKICAgICAgICBjb25zdCBwaW5nT2sgPSBhd2FpdCBuZXcgUHJvbWlzZShyZXNvbHZlID0+IHsKICAgICAgICAgIEdNX3htbGh0dHBSZXF1ZXN0KHsKICAgICAgICAgICAgbWV0aG9kOiAnR0VUJywKICAgICAgICAgICAgdXJsOiBTRVJWRVJfQkFTRSArIHByZWZpeCArICcvcGluZycsCiAgICAgICAgICAgIHRpbWVvdXQ6IDhlMywKICAgICAgICAgICAgb25sb2FkOiByID0+IHJlc29sdmUoci5zdGF0dXMgPT09IDIwMCksCiAgICAgICAgICAgIG9uZXJyb3I6ICgpID0+IHJlc29sdmUoZmFsc2UpLAogICAgICAgICAgICBvbnRpbWVvdXQ6ICgpID0+IHJlc29sdmUoZmFsc2UpCiAgICAgICAgICB9KTsKICAgICAgICB9KTsKICAgICAgICBpZiAoIXBpbmdPaykgdGhyb3cgbmV3IEVycm9yKCdLSMOUTkcgS+G6vlQgTuG7kEkgxJDGr+G7okMgU0VSVkVSLiBLaeG7g20gdHJhOiAxKSBVUkwgU0VSVkVSX0JBU0UsIDIpIEFQSV9TRUNSRVQga2jhu5twIEdPRE1PREVfU0VDUkVUIHRyw6puIHNlcnZlciwgMykgxJHDoyBkZXBsb3kvcmVkZXBsb3kuJyk7CiAgICAgICAgY29uc3QgY3VycmVudE9sbSA9IGdldE9sbVVzZXJuYW1lKCk7CiAgICAgICAgY29uc3QgcmVzdWx0ID0gYXdhaXQgZ21Qb3N0KCcvdmVyaWZ5JywgewogICAgICAgICAga2V5OiBrZXksCiAgICAgICAgICBod2lkOiBnZXRIV0lEKCksCiAgICAgICAgICBvbG1fdXNlcjogY3VycmVudE9sbQogICAgICAgIH0pOwogICAgICAgIGlmIChyZXN1bHQuc3VjY2VzcyB8fCByZXN1bHQudmFsaWQpIHsKICAgICAgICAgIGNvbnN0IHNlcnZlck9sbSA9IHJlc3VsdC5vbG1fdXNlciB8fCByZXN1bHQub2xtX2FjY291bnQgfHwgJyc7CiAgICAgICAgICBpZiAoc2VydmVyT2xtICYmIGN1cnJlbnRPbG0gJiYgY3VycmVudE9sbSAhPT0gJ0tob25nWGFjRGluaCcpIHsKICAgICAgICAgICAgaWYgKHNlcnZlck9sbS50b0xvd2VyQ2FzZSgpICE9PSBjdXJyZW50T2xtLnRvTG93ZXJDYXNlKCkpIHsKICAgICAgICAgICAgICBlcnJCb3guaW5uZXJIVE1MID0gYPCfmqsgPGI+VMOgaSBraG/huqNuIE9MTSBraMO0bmcga2jhu5twITwvYj48YnI+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEtleSBkw6BuaCBjaG86IDxiPiR7c2VydmVyT2xtfTwvYj48YnI+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEhp4buHbiB04bqhaTogPGI+JHtjdXJyZW50T2xtfTwvYj48YnI+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFZ1aSBsw7JuZyDEkcSDbmcgbmjhuq1wIMSRw7puZyB0w6BpIGtob+G6o24gT0xNIWA7CiAgICAgICAgICAgICAgZXJyQm94LnN0eWxlLmRpc3BsYXkgPSAnYmxvY2snOwogICAgICAgICAgICAgIGJ0bi50ZXh0Q29udGVudCA9ICfwn5STIEvDjUNIIEhP4bqgVCc7CiAgICAgICAgICAgICAgYnRuLmRpc2FibGVkID0gZmFsc2U7CiAgICAgICAgICAgICAgdmVyaWZ5aW5nID0gZmFsc2U7CiAgICAgICAgICAgICAgcmV0dXJuOwogICAgICAgICAgICB9CiAgICAgICAgICB9CiAgICAgICAgICBfc0xTLnNldChMU19LRVksIGtleSk7CiAgICAgICAgICBfc0xTLnNldChMU19UWVBFLCByZXN1bHQudHlwZSB8fCByZXN1bHQucGxhbiB8fCAnVEhVT05HJyk7CiAgICAgICAgICBfc0xTLnNldChMU19FWFAsIHJlc3VsdC5leHBpcmVzX2F0IHx8ICcnKTsKICAgICAgICAgIENVUlJFTlRfS0VZID0ga2V5OwogICAgICAgICAgS0VZX1NUQVRVUyA9IHsKICAgICAgICAgICAgdmFsaWQ6IHRydWUsCiAgICAgICAgICAgIHR5cGU6IHJlc3VsdC50eXBlIHx8IHJlc3VsdC5wbGFuLAogICAgICAgICAgICBleHBpcmVzX2F0OiByZXN1bHQuZXhwaXJlc19hdCB8fCByZXN1bHQuZXhwCiAgICAgICAgICB9OwogICAgICAgICAgY29uc3Qga2V5VHlwZUxhYmVsID0gKHJlc3VsdC50eXBlIHx8IHJlc3VsdC5wbGFuIHx8ICdUSFVPTkcnKS50b1VwcGVyQ2FzZSgpOwogICAgICAgICAgY29uc3QgaXNQcmVtaXVtID0gWyAnUFJFTUlVTScsICdWSVAnLCAnVU5MSU1JVEVEJyBdLmluY2x1ZGVzKGtleVR5cGVMYWJlbCk7CiAgICAgICAgICBsZXQgZXhwaXJ5TGluZSA9ICcnOwogICAgICAgICAgY29uc3QgZXhSYXcgPSByZXN1bHQuZXhwaXJlc19hdCB8fCByZXN1bHQuZXhwIHx8ICcnOwogICAgICAgICAgaWYgKGV4UmF3KSB7CiAgICAgICAgICAgIGNvbnN0IGV4cERhdGUgPSBuZXcgRGF0ZShleFJhdyk7CiAgICAgICAgICAgIGNvbnN0IGRheXNMZWZ0ID0gTWF0aC5jZWlsKChleHBEYXRlIC0gbmV3IERhdGUpIC8gKDFlMyAqIDYwICogNjAgKiAyNCkpOwogICAgICAgICAgICBjb25zdCBleHBTdHIgPSBleHBEYXRlLnRvTG9jYWxlRGF0ZVN0cmluZygndmktVk4nKTsKICAgICAgICAgICAgaWYgKGRheXNMZWZ0ID4gMCkgZXhwaXJ5TGluZSA9IGDwn5OFIEjhur90IGjhuqFuOiA8Yj4ke2V4cFN0cn08L2I+IChjw7JuIDxiPiR7ZGF5c0xlZnR9PC9iPiBuZ8OgeSlgOyBlbHNlIGlmIChkYXlzTGVmdCA9PT0gMCkgZXhwaXJ5TGluZSA9IGDwn5OFIEjhur90IGjhuqFuOiA8Yj5Iw7RtIG5heTwvYj4gKCR7ZXhwU3RyfSlgOyBlbHNlIGV4cGlyeUxpbmUgPSBg8J+ThSBI4bq/dCBo4bqhbjogPGI+JHtleHBTdHJ9PC9iPiA8c3BhbiBzdHlsZT0iY29sb3I6I2ZmNDQ0NDsiPijEkcOjIGjhur90IGjhuqFuKTwvc3Bhbj5gOwogICAgICAgICAgfQogICAgICAgICAgb3ZlcmxheS5yZW1vdmUoKTsKICAgICAgICAgIGlmICghaXNQcmVtaXVtKSB7CiAgICAgICAgICAgIHNob3dDdXN0b21Nb2RhbCh7CiAgICAgICAgICAgICAgaWNvbjogJ+KchScsCiAgICAgICAgICAgICAgdGl0bGU6ICdLw41DSCBIT+G6oFQgVEjDgE5IIEPDlE5HIScsCiAgICAgICAgICAgICAgbGluZXM6IFsgYExv4bqhaSBrZXk6IDxiPiR7a2V5VHlwZUxhYmVsfTwvYj5gLCAuLi5leHBpcnlMaW5lID8gWyBleHBpcnlMaW5lIF0gOiBbXSwgYDxzcGFuIHN0eWxlPSJjb2xvcjojZmZjMTA3OyI+4pqg77iPIEtleSB0aMaw4budbmc6IENo4bupYyBuxINuZyAiQ0hV4bqoTiBC4buKIDEwIMSQSeG7gk0iIGLhu4sgdsO0IGhp4buHdSBob8OhLjwvc3Bhbj5gLCBg8J+SjiBOw6JuZyBj4bqlcCBsw6puIFBSRU1JVU0gxJHhu4MgZMO5bmcgxJHhuqd5IMSR4bunIHTDrW5oIG7Eg25nIWAgXSwKICAgICAgICAgICAgICBvbk9rOiAoKSA9PiBjcmVhdGVVSSgpCiAgICAgICAgICAgIH0pOwogICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgc2hvd0N1c3RvbU1vZGFsKHsKICAgICAgICAgICAgICBpY29uOiAn8J+SjicsCiAgICAgICAgICAgICAgdGl0bGU6ICdLw41DSCBIT+G6oFQgVEjDgE5IIEPDlE5HIScsCiAgICAgICAgICAgICAgbGluZXM6IFsgYExv4bqhaSBrZXk6IDxiPiR7a2V5VHlwZUxhYmVsfTwvYj4g8J+SjmAsIC4uLmV4cGlyeUxpbmUgPyBbIGV4cGlyeUxpbmUgXSA6IFtdLCBg8J+UkyBU4bqldCBj4bqjIHTDrW5oIG7Eg25nIMSRw6MgxJHGsOG7o2MgbeG7nyBraG/DoSFgIF0sCiAgICAgICAgICAgICAgb25PazogKCkgPT4gY3JlYXRlVUkoKQogICAgICAgICAgICB9KTsKICAgICAgICAgIH0KICAgICAgICB9IGVsc2UgewogICAgICAgICAgY29uc3Qgc3RhdHVzID0gcmVzdWx0Ll9odHRwU3RhdHVzOwogICAgICAgICAgbGV0IG1zZyA9IHJlc3VsdC5tZXNzYWdlIHx8IHJlc3VsdC5yZWFzb24gfHwgcmVzdWx0LmVycm9yIHx8ICcnOwogICAgICAgICAgaWYgKHN0YXR1cyA9PT0gNDA0IHx8IHJlc3VsdC5lcnJvciA9PT0gJ05vdCBmb3VuZCcpIHsKICAgICAgICAgICAgbXNnID0gJ+KdjCBUaGnhur90IGLhu4svSVAgY8OzIHRo4buDIMSRw6MgYuG7iyBraG/DoSBob+G6t2Mgc2FpIMSRxrDhu51uZyBk4bqrbiBBUEkuIEtp4buDbSB0cmEgQVBJX1NFQ1JFVCBraOG7m3Agc2VydmVyLic7CiAgICAgICAgICB9IGVsc2UgaWYgKHN0YXR1cyA9PT0gNDAzKSB7CiAgICAgICAgICAgIG1zZyA9ICfinYwgJyArIChtc2cgfHwgJ1RoaeG6v3QgYuG7iy9t4bqhbmcga2jDtG5nIGjhu6NwIGzhu4cgKG3DoXkg4bqjby9wcm94eS9WUE4vdHLDrG5oIGR1eeG7h3QgZ2nhuqMpIOKAlCBjw7MgdGjhu4MgxJHDoyBi4buLIGtob8OhIHbEqW5oIHZp4buFbiwgbGnDqm4gaOG7hyBhZG1pbi4nKTsKICAgICAgICAgIH0gZWxzZSBpZiAoIW1zZykgewogICAgICAgICAgICBtc2cgPSAn4p2MIEtleSBraMO0bmcgaOG7o3AgbOG7hyEgKEtleVZhdWx0IHThu6sgY2jhu5FpKSc7CiAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICBtc2cgPSAn4p2MICcgKyBtc2c7CiAgICAgICAgICB9CiAgICAgICAgICBlcnJCb3gudGV4dENvbnRlbnQgPSBtc2cgKyAoc3RhdHVzID8gYCBbSFRUUCAke3N0YXR1c31dYCA6ICcnKTsKICAgICAgICAgIGVyckJveC5zdHlsZS5kaXNwbGF5ID0gJ2Jsb2NrJzsKICAgICAgICAgIGJ0bi50ZXh0Q29udGVudCA9ICfwn5STIEvDjUNIIEhP4bqgVCc7CiAgICAgICAgICBidG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgICAgIHZlcmlmeWluZyA9IGZhbHNlOwogICAgICAgIH0KICAgICAgfSBjYXRjaCAoZSkgewogICAgICAgIGVyckJveC50ZXh0Q29udGVudCA9ICfinYwgS2jDtG5nIHRo4buDIGvhur90IG7hu5FpIHNlcnZlcjogJyArIGUubWVzc2FnZTsKICAgICAgICBlcnJCb3guc3R5bGUuZGlzcGxheSA9ICdibG9jayc7CiAgICAgICAgYnRuLnRleHRDb250ZW50ID0gJ/CflJMgS8ONQ0ggSE/huqBUJzsKICAgICAgICBidG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgICB2ZXJpZnlpbmcgPSBmYWxzZTsKICAgICAgfQogICAgfTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1rZXktaW5wdXQnKS5hZGRFdmVudExpc3RlbmVyKCdrZXlkb3duJywgZSA9PiB7CiAgICAgIGlmIChlLmtleSA9PT0gJ0VudGVyJykgYnRuLmNsaWNrKCk7CiAgICB9KTsKICB9CiAgZnVuY3Rpb24gY3JlYXRlVUkoKSB7CiAgICBpZiAoZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLXBhbmVsJykpIHJldHVybjsKICAgIGxldCB1aVN0eWxlID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLXVpLXN0eWxlJyk7CiAgICBpZiAoIXVpU3R5bGUpIHsKICAgICAgdWlTdHlsZSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ3N0eWxlJyk7CiAgICAgIHVpU3R5bGUuaWQgPSAndGwtdWktc3R5bGUnOwogICAgICBkb2N1bWVudC5oZWFkLmFwcGVuZENoaWxkKHVpU3R5bGUpOwogICAgfQogICAgdWlTdHlsZS50ZXh0Q29udGVudCA9IGdldE1haW5VSVN0eWxlcygpOwogICAgY29uc3Qga2V5VHlwZSA9IEtFWV9TVEFUVVMudHlwZSB8fCBfc0xTLmdldChMU19UWVBFKSB8fCAnVEhVT05HJzsKICAgIGNvbnN0IGtleVR5cGVVcCA9IGtleVR5cGUudG9VcHBlckNhc2UoKTsKICAgIGNvbnN0IGJhZGdlQ2xhc3MgPSBrZXlUeXBlVXAgPT09ICdVTkxJTUlURUQnID8gJ3RsLWJhZGdlIHVubGltaXRlZCcgOiBrZXlUeXBlVXAgPT09ICdQUkVNSVVNJyB8fCBrZXlUeXBlVXAgPT09ICdWSVAnID8gJ3RsLWJhZGdlIHZpcCcgOiAndGwtYmFkZ2UnOwogICAgY29uc3QgYmFkZ2VJY29uID0ga2V5VHlwZVVwID09PSAnVU5MSU1JVEVEJyA/ICfwn5SlIFVOTElNSVRFRCcgOiBrZXlUeXBlVXAgPT09ICdQUkVNSVVNJyB8fCBrZXlUeXBlVXAgPT09ICdWSVAnID8gJ/Cfko4gUFJFTUlVTScgOiAn8J+UkSBUSMav4bucTkcnOwogICAgY29uc3QgZXhwU3RyID0gKCgpID0+IHsKICAgICAgY29uc3QgZSA9IF9zTFMuZ2V0KExTX0VYUCk7CiAgICAgIGlmICghZSkgcmV0dXJuICcnOwogICAgICBjb25zdCBkID0gbmV3IERhdGUoZSk7CiAgICAgIHJldHVybiBpc05hTihkKSA/ICcnIDogYCAoZXhwOiAke2QudG9Mb2NhbGVEYXRlU3RyaW5nKCd2aS1WTicpfSlgOwogICAgfSkoKTsKICAgIGNvbnN0IHRoZW1lQ2FyZHNIVE1MID0gWyAnZGVmYXVsdCcsICdncmF5JywgJ3BpbmsnIF0ubWFwKHQgPT4gewogICAgICBjb25zdCB0SW5mbyA9IGdldFRoZW1lQ29sb3JzKHQpOwogICAgICBjb25zdCBpc0FjdGl2ZSA9IHQgPT09IENVUlJFTlRfVEhFTUU7CiAgICAgIHJldHVybiBgPGRpdiBjbGFzcz0idGwtdGMgJHtpc0FjdGl2ZSA/ICdhY3RpdmUnIDogJyd9IiBkYXRhLXQ9IiR7dH0iPlxuICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLXRjLXByZXYiIHN0eWxlPSJiYWNrZ3JvdW5kOiR7dEluZm8ucHJldmlld0JnfTtib3JkZXI6MXB4IHNvbGlkICR7dEluZm8ucHJldmlld0JvcmRlcn07Ij5cbiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtdGMtcHJldi1pbm5lciI+XG4gICAgICAgICAgICAgICAgICAgICAgICA8c3BhbiBjbGFzcz0idGwtdGMtcHJldi10ZXh0IiBzdHlsZT0iY29sb3I6JHt0SW5mby5wcmV2aWV3VGV4dH07Ij4ke3RJbmZvLnRoZW1lTGFiZWwucmVwbGFjZSgvXlteXHNdK1xzLywgJycpLnRvVXBwZXJDYXNlKCl9PC9zcGFuPlxuICAgICAgICAgICAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC10Yy1sYmwiPiR7dEluZm8udGhlbWVMYWJlbH08L2Rpdj5cbiAgICAgICAgICAgIDwvZGl2PmA7CiAgICB9KS5qb2luKCcnKTsKICAgIGNvbnN0IHRjID0gZ2V0VGhlbWVDb2xvcnMoQ1VSUkVOVF9USEVNRSk7CiAgICBjb25zdCB3cmFwID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICB3cmFwLmlubmVySFRNTCA9IGBcbiAgICAgICAgICAgIDxidXR0b24gaWQ9InRsLWZsb2F0QnRuIj7imqE8L2J1dHRvbj5cbiAgICAgICAgICAgIDxkaXYgaWQ9InRsLXBhbmVsIiBjbGFzcz0iaGlkZGVuIj5cbiAgICAgICAgICAgICAgICAke3RjLnBhbmVsRXh0cmEgfHwgJyd9XG4gICAgICAgICAgICAgICAgPGRpdiBpZD0idGwtcC1oZWFkZXIiPlxuICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC1wLWJyYW5kIj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxzcGFuPvCfmoA8L3NwYW4+XG4gICAgICAgICAgICAgICAgICAgICAgICA8c3BhbiBjbGFzcz0idGwtcC1uYW1lIj5USEnDik4gVEFJIFTDmSBU4buYSSAvLyBHT0QgTU9ERTwvc3Bhbj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxzcGFuIGNsYXNzPSIke2JhZGdlQ2xhc3N9Ij4ke2JhZGdlSWNvbn08L3NwYW4+XG4gICAgICAgICAgICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDo2cHg7Ij5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxidXR0b24gaWQ9InRsLXNldHRpbmdzQnRuIiB0aXRsZT0iQ8OgaSDEkeG6t3QgZ2lhbyBkaeG7h24iPuKamTwvYnV0dG9uPlxuICAgICAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBpZD0idGwtY2xvc2VCdG4iPuKclTwvYnV0dG9uPlxuICAgICAgICAgICAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICAgICAgICA8L2Rpdj5cblxuICAgICAgICAgICAgICAgIFx4M2MhLS0gU2V0dGluZ3Mgb3ZlcmxheSAtLVx4M2VcbiAgICAgICAgICAgICAgICA8ZGl2IGlkPSJ0bC1zbyIgY2xhc3M9ImhpZGRlbiI+XG4gICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLXNvLWhkciI+XG4gICAgICAgICAgICAgICAgICAgICAgICA8c3BhbiBjbGFzcz0idGwtc28tdGl0bGUiPuKamSBDw4BJIMSQ4bq2VCBHSUFPIERJ4buGTjwvc3Bhbj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxidXR0b24gaWQ9InRsLXNvQ2xvc2UiPuKclTwvYnV0dG9uPlxuICAgICAgICAgICAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtc28tYm9keSI+XG4gICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC1zby1sYmwiPvCfjqggQ2jhu41uIG3DoHUgc+G6r2MgZ2lhbyBkaeG7h248L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLXRoZW1lLWNhcmRzIj4ke3RoZW1lQ2FyZHNIVE1MfTwvZGl2PlxuICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtc28tZGl2aWRlciI+PC9kaXY+XG4gICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC1oaW50Ij7DgXAgZOG7pW5nIG5nYXkgbOG6rXAgdOG7qWMgY2hvIHRvw6BuIGLhu5kgZ2lhbyBkaeG7h248YnI+a+G7gyBj4bqjIG3DoG4gaMOsbmggxJHEg25nIG5o4bqtcCB2w6AgdGjDtG5nIGLDoW8ga2V5PC9kaXY+XG4gICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC1zby1kaXZpZGVyIj48L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLXNvLWxibCI+8J+UkSBRdeG6o24gbMO9IGtleTwvZGl2PlxuICAgICAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0idGwtY2hhbmdlLWtleSIgaWQ9InRsLWNoYW5nZUtleSI+8J+UhCDEkOG7lEkgS0VZPC9idXR0b24+XG4gICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC1oaW50IiBzdHlsZT0ibWFyZ2luLXRvcDo0cHg7Ij5Yb8OhIGtleSBoaeG7h24gdOG6oWkgdsOgIHF1YXkgduG7gSBtw6BuIGjDrG5oIMSRxINuZyBuaOG6rXA8L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgPC9kaXY+XG4gICAgICAgICAgICAgICAgPC9kaXY+XG5cbiAgICAgICAgICAgICAgICA8ZGl2IGlkPSJ0bC1wLWJvZHkiPlxuICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC1zdGF0Ym94Ij5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgc3R5bGU9ImNvbG9yOnJnYmEoMjU1LDI1NSwyNTUsMC40KTtmb250LXNpemU6MTBweDt0ZXh0LXRyYW5zZm9ybTp1cHBlcmNhc2U7Zm9udC13ZWlnaHQ6NjAwOyI+Ly8gVHLhuqFuZyB0aMOhaSBo4buHIHRo4buRbmc8L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLXN0YXRyb3ciPuKchSBO4bqhcCBk4buvIGxp4buHdTogPHNwYW4gaWQ9InRsLXFjb3VudCIgc3R5bGU9ImNvbG9yOiMwMGU2NzY7Zm9udC13ZWlnaHQ6Ym9sZDttYXJnaW4tbGVmdDo1cHgiPjA8L3NwYW4+IGPDonU8L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLXN0YXRyb3ciPvCflI0gQ2jhur8gxJHhu5k6IDxzcGFuIGlkPSJ0bC1tb2RlLWRldGVjdGVkIiBzdHlsZT0iY29sb3I6IzRmYWNmZTtmb250LXdlaWdodDpib2xkO21hcmdpbi1sZWZ0OjVweCI+UFJBQ1RJQ0U8L3NwYW4+PC9kaXY+XG4gICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC1zdGF0cm93Ij7wn5SQIEtleTogPHNwYW4gc3R5bGU9ImNvbG9yOiNmZmMxMDc7Ij4ke2tleVR5cGV9PC9zcGFuPiR7ZXhwU3RyfTwvZGl2PlxuICAgICAgICAgICAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgPGRpdiBzdHlsZT0iaGVpZ2h0OjFweDtiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCg5MGRlZyx0cmFuc3BhcmVudCwke3RjLmJvcmRlcn0sdHJhbnNwYXJlbnQpOyI+PC9kaXY+XG4gICAgICAgICAgICAgICAgICAgIDxkaXY+XG4gICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJmb250LXNpemU6OS41cHg7Zm9udC13ZWlnaHQ6NzAwO2NvbG9yOiR7dGMuZ2xvd0NvbG9yfTtmb250LWZhbWlseTonT3JiaXRyb24nOyI+4pqZIENI4bq+IMSQ4buYIFbGr+G7olQgUsOATzwvZGl2PlxuICAgICAgICAgICAgICAgICAgICAgICAgPHNlbGVjdCBpZD0idGwtbW9kZVNlbGVjdCI+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0icHJhY3RpY2UiPuKaoSBMdXnhu4duIFThuq1wPC9vcHRpb24+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0iZXhhbSIgc2VsZWN0ZWQ+8J+UpSBLaeG7g20gVHJhPC9vcHRpb24+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0idmlkZW8iPvCfjqUgVmlkZW8gUXVpejwvb3B0aW9uPlxuICAgICAgICAgICAgICAgICAgICAgICAgPC9zZWxlY3Q+XG4gICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJmb250LXNpemU6OS41cHg7Zm9udC13ZWlnaHQ6NzAwO2NvbG9yOiR7dGMuZ2xvd0NvbG9yfTtmb250LWZhbWlseTonT3JiaXRyb24nO21hcmdpbi10b3A6NnB4OyI+4o+xIFRI4bucSSBHSUFOIEzDgE0gQsOASSAoUEjDmlQpPC9kaXY+XG4gICAgICAgICAgICAgICAgICAgICAgICA8aW5wdXQgdHlwZT0ibnVtYmVyIiBzdGVwPSIwLjAxIiBjbGFzcz0idGwtZ29kLWlucHV0IiBpZD0idGwtZ29kLXRpbWUiXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFsdWU9IjI1LjAwIiBwbGFjZWhvbGRlcj0iMjUgPSAyNSBwaMO6dCDCtyAyNS4zMCA9IDI1cDMwcyI+XG4gICAgICAgICAgICAgICAgICAgIDxkaXYgc3R5bGU9ImZvbnQtc2l6ZTo5LjVweDtmb250LXdlaWdodDo3MDA7Y29sb3I6JHt0Yy5nbG93Q29sb3J9O2ZvbnQtZmFtaWx5OidPcmJpdHJvbic7bWFyZ2luLXRvcDo2cHg7Ij7wn46vIMSQaeG7g20gbeG7pWMgdGnDqnU8L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgPHNlbGVjdCBpZD0idGwtZ29kLXRhcmdldC1zY29yZSI+XG4gICAgICAgICAgICAgICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSI3Ij43xJE8L29wdGlvbj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxvcHRpb24gdmFsdWU9IjgiPjjEkTwvb3B0aW9uPlxuICAgICAgICAgICAgICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0iOSI+OcSRPC9vcHRpb24+XG4gICAgICAgICAgICAgICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSIxMCIgc2VsZWN0ZWQ+MTDEkTwvb3B0aW9uPlxuICAgICAgICAgICAgICAgICAgICA8L3NlbGVjdD5cbiAgICAgICAgICAgICAgICAgICAgPC9kaXY+XG4gICAgICAgICAgICAgICAgICAgIDxidXR0b24gaWQ9InRsLWZpcmVCdG4iPvCfkqUgQ0hV4bqoTiBC4buKIDEwIMSQSeG7gk08L2J1dHRvbj5cbiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtY29uc29sZSIgaWQ9InRsLWxvZ2JveCI+PC9kaXY+XG4gICAgICAgICAgICAgICAgPC9kaXY+XG4gICAgICAgICAgICAgICAgPGRpdiBpZD0idGwtcC1mb290ZXIiPlxuICAgICAgICAgICAgICAgICAgICA8c3Bhbj5HT0QgTU9ERSB2My40IOKAlCBTRUNVUkUgdjUuMSAodjE3IGFudGktYmFuKTwvc3Bhbj5cbiAgICAgICAgICAgICAgICAgICAgPGRpdiBzdHlsZT0iZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6NXB4OyI+XG4gICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJ3aWR0aDo2cHg7aGVpZ2h0OjZweDtib3JkZXItcmFkaXVzOjUwJTtiYWNrZ3JvdW5kOiMwMGU2NzY7Ym94LXNoYWRvdzowIDAgNnB4ICMwMGU2NzY7YW5pbWF0aW9uOmNvbm5CbGluayAxLjhzIGluZmluaXRlOyI+PC9kaXY+XG4gICAgICAgICAgICAgICAgICAgICAgICA8c3BhbiBpZD0idGwtc3ZyU3RhdHVzIj7wn5S1IFNlcnZlcjogT0s8L3NwYW4+XG4gICAgICAgICAgICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgICAgPC9kaXY+YDsKICAgIGRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQod3JhcCk7CiAgICBjb25zdCBmbG9hdEJ0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1mbG9hdEJ0bicpOwogICAgY29uc3QgcGFuZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtcGFuZWwnKTsKICAgIGZsb2F0QnRuLm9uY2xpY2sgPSAoKSA9PiBwYW5lbC5jbGFzc0xpc3QudG9nZ2xlKCdoaWRkZW4nKTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1jbG9zZUJ0bicpLm9uY2xpY2sgPSAoKSA9PiB7CiAgICAgIHBhbmVsLmNsYXNzTGlzdC5hZGQoJ2hpZGRlbicpOwogICAgICBjb25zdCBzbyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1zbycpOwogICAgICBpZiAoc28pIHNvLmNsYXNzTGlzdC5hZGQoJ2hpZGRlbicpOwogICAgfTsKICAgIGNvbnN0IGhkciA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1wLWhlYWRlcicpOwogICAgbGV0IGlzRHJhZ2dpbmcgPSBmYWxzZSwgc3RhcnRYID0gMCwgc3RhcnRZID0gMCwgaW5pdExlZnQgPSAwLCBpbml0VG9wID0gMDsKICAgIGlmIChoZHIpIHsKICAgICAgaGRyLmFkZEV2ZW50TGlzdGVuZXIoJ21vdXNlZG93bicsIGUgPT4gewogICAgICAgIGlmIChlLnRhcmdldC5pZCA9PT0gJ3RsLWNsb3NlQnRuJyB8fCBlLnRhcmdldC5pZCA9PT0gJ3RsLXNldHRpbmdzQnRuJykgcmV0dXJuOwogICAgICAgIGlzRHJhZ2dpbmcgPSB0cnVlOwogICAgICAgIHN0YXJ0WCA9IGUuY2xpZW50WDsKICAgICAgICBzdGFydFkgPSBlLmNsaWVudFk7CiAgICAgICAgY29uc3QgciA9IHBhbmVsLmdldEJvdW5kaW5nQ2xpZW50UmVjdCgpOwogICAgICAgIGluaXRMZWZ0ID0gci5sZWZ0OwogICAgICAgIGluaXRUb3AgPSByLnRvcDsKICAgICAgfSk7CiAgICB9CiAgICBkb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCdtb3VzZW1vdmUnLCBlID0+IHsKICAgICAgaWYgKCFpc0RyYWdnaW5nKSByZXR1cm47CiAgICAgIHBhbmVsLnN0eWxlLmxlZnQgPSBpbml0TGVmdCArIGUuY2xpZW50WCAtIHN0YXJ0WCArICdweCc7CiAgICAgIHBhbmVsLnN0eWxlLnRvcCA9IGluaXRUb3AgKyBlLmNsaWVudFkgLSBzdGFydFkgKyAncHgnOwogICAgICBwYW5lbC5zdHlsZS50cmFuc2Zvcm0gPSAnbm9uZSc7CiAgICB9KTsKICAgIGRvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXIoJ21vdXNldXAnLCAoKSA9PiB7CiAgICAgIGlzRHJhZ2dpbmcgPSBmYWxzZTsKICAgIH0pOwogICAgY29uc3Qgc28gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtc28nKTsKICAgIGNvbnN0IHNldHRpbmdzQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLXNldHRpbmdzQnRuJyk7CiAgICBjb25zdCBzb0Nsb3NlID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLXNvQ2xvc2UnKTsKICAgIGlmIChzZXR0aW5nc0J0biAmJiBzbykgewogICAgICBzZXR0aW5nc0J0bi5vbmNsaWNrID0gKCkgPT4gewogICAgICAgIGNvbnN0IGlzT3BlbiA9ICFzby5jbGFzc0xpc3QuY29udGFpbnMoJ2hpZGRlbicpOwogICAgICAgIHNvLmNsYXNzTGlzdC50b2dnbGUoJ2hpZGRlbicpOwogICAgICAgIHNldHRpbmdzQnRuLmNsYXNzTGlzdC50b2dnbGUoJ2FjdGl2ZScsICFpc09wZW4pOwogICAgICB9OwogICAgfQogICAgaWYgKHNvQ2xvc2UpIHsKICAgICAgc29DbG9zZS5vbmNsaWNrID0gKCkgPT4gewogICAgICAgIHNvLmNsYXNzTGlzdC5hZGQoJ2hpZGRlbicpOwogICAgICAgIGlmIChzZXR0aW5nc0J0bikgc2V0dGluZ3NCdG4uY2xhc3NMaXN0LnJlbW92ZSgnYWN0aXZlJyk7CiAgICAgIH07CiAgICB9CiAgICBpZiAoc28pIHsKICAgICAgc28ucXVlcnlTZWxlY3RvckFsbCgnLnRsLXRjJykuZm9yRWFjaChjYXJkID0+IHsKICAgICAgICBjYXJkLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gewogICAgICAgICAgY29uc3QgbmV3VGhlbWUgPSBjYXJkLmRhdGFzZXQudDsKICAgICAgICAgIGlmIChuZXdUaGVtZSA9PT0gQ1VSUkVOVF9USEVNRSkgewogICAgICAgICAgICBzby5jbGFzc0xpc3QuYWRkKCdoaWRkZW4nKTsKICAgICAgICAgICAgaWYgKHNldHRpbmdzQnRuKSBzZXR0aW5nc0J0bi5jbGFzc0xpc3QucmVtb3ZlKCdhY3RpdmUnKTsKICAgICAgICAgICAgcmV0dXJuOwogICAgICAgICAgfQogICAgICAgICAgc28ucXVlcnlTZWxlY3RvckFsbCgnLnRsLXRjJykuZm9yRWFjaChjID0+IHsKICAgICAgICAgICAgYy5jbGFzc0xpc3QudG9nZ2xlKCdhY3RpdmUnLCBjLmRhdGFzZXQudCA9PT0gbmV3VGhlbWUpOwogICAgICAgICAgfSk7CiAgICAgICAgICBhcHBseVRoZW1lTGl2ZShuZXdUaGVtZSk7CiAgICAgICAgICBjb25zdCBleGlzdEZ4ID0gcGFuZWwucXVlcnlTZWxlY3RvcignI3RsLWNvbm4tZngtYmFyLCN0bC1jb25uLWZ4LXBldGFscycpOwogICAgICAgICAgaWYgKGV4aXN0RngpIGV4aXN0RngucmVtb3ZlKCk7CiAgICAgICAgICBjb25zdCBuZXdUYyA9IGdldFRoZW1lQ29sb3JzKG5ld1RoZW1lKTsKICAgICAgICAgIGlmIChuZXdUYy5wYW5lbEV4dHJhKSB7CiAgICAgICAgICAgIGNvbnN0IHRtcCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpOwogICAgICAgICAgICB0bXAuaW5uZXJIVE1MID0gbmV3VGMucGFuZWxFeHRyYTsKICAgICAgICAgICAgY29uc3QgZnhFbCA9IHRtcC5maXJzdEVsZW1lbnRDaGlsZDsKICAgICAgICAgICAgaWYgKGZ4RWwpIHBhbmVsLmluc2VydEJlZm9yZShmeEVsLCBwYW5lbC5maXJzdENoaWxkKTsKICAgICAgICAgIH0KICAgICAgICAgIHNldFRpbWVvdXQoKCkgPT4gewogICAgICAgICAgICBzby5jbGFzc0xpc3QuYWRkKCdoaWRkZW4nKTsKICAgICAgICAgICAgaWYgKHNldHRpbmdzQnRuKSBzZXR0aW5nc0J0bi5jbGFzc0xpc3QucmVtb3ZlKCdhY3RpdmUnKTsKICAgICAgICAgIH0sIDMyMCk7CiAgICAgICAgfSk7CiAgICAgIH0pOwogICAgfQogICAgY29uc3QgbW9kZVNlbGVjdCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1tb2RlU2VsZWN0Jyk7CiAgICBjb25zdCBkZXRlY3RlZE1vZGUgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtbW9kZS1kZXRlY3RlZCcpOwogICAgaWYgKG1vZGVTZWxlY3QpIHsKICAgICAgbW9kZVNlbGVjdC5hZGRFdmVudExpc3RlbmVyKCdjaGFuZ2UnLCBmdW5jdGlvbigpIHsKICAgICAgICBpZiAoZGV0ZWN0ZWRNb2RlKSBkZXRlY3RlZE1vZGUudGV4dENvbnRlbnQgPSB0aGlzLnZhbHVlLnRvVXBwZXJDYXNlKCk7CiAgICAgIH0pOwogICAgfQogICAgYXN5bmMgZnVuY3Rpb24gZm9yY2VGZXRjaFF1ZXN0aW9ucygpIHsKICAgICAgdHJ5IHsKICAgICAgICBmb3JjZUdldE1ldGEoKTsKICAgICAgICBjb25zdCBVVyA9IHR5cGVvZiB1bnNhZmVXaW5kb3cgIT09ICd1bmRlZmluZWQnID8gdW5zYWZlV2luZG93IDogd2luZG93OwogICAgICAgIHRyeSB7CiAgICAgICAgICBjb25zdCBidWYgPSBVVy5fX2t2X3FfYnVmOwogICAgICAgICAgaWYgKEFycmF5LmlzQXJyYXkoYnVmKSkgewogICAgICAgICAgICBmb3IgKGxldCBpID0gMDsgaSA8IGJ1Zi5sZW5ndGg7IGkrKykgewogICAgICAgICAgICAgIGNvbnN0IGl0ID0gYnVmW2ldOwogICAgICAgICAgICAgIGlmIChpdCAmJiBpdC51cmwgJiYgaXQudGV4dCkgewogICAgICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgICAgaGFuZGxlUmF3UmVzcG9uc2UoaXQudXJsLCBpdC50ZXh0KTsKICAgICAgICAgICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgICB9CiAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgICBpZiAoU0VTU0lPTi5yYXdfcXVlc3Rpb25zLmxlbmd0aCA+IDApIHJldHVybiB0cnVlOwogICAgICAgIC8vIFt2MzJdIGlPUyBGb2N1czogcXXDqXQgcmVzb3VyY2UgdGltaW5nIHLhu5NpIGZldGNoIGzhuqFpIEFQSSBjw6J1IGjhu49pIChraMO0bmcgcGjhu6UgdGh14buZYyBob29rIHdvcmxkKQogICAgICAgIHRyeSB7CiAgICAgICAgICBjb25zdCByZXNMaXN0ID0gKHR5cGVvZiBwZXJmb3JtYW5jZSAhPT0gJ3VuZGVmaW5lZCcgJiYgcGVyZm9ybWFuY2UuZ2V0RW50cmllc0J5VHlwZSkgPyBwZXJmb3JtYW5jZS5nZXRFbnRyaWVzQnlUeXBlKCdyZXNvdXJjZScpIDogW107CiAgICAgICAgICBmb3IgKGxldCByaSA9IDA7IHJpIDwgcmVzTGlzdC5sZW5ndGg7IHJpKyspIHsKICAgICAgICAgICAgY29uc3QgdSA9IHJlc0xpc3RbcmldLm5hbWUgfHwgJyc7CiAgICAgICAgICAgIGlmICghdSB8fCB1LmluZGV4T2YoU0VSVkVSX0JBU0UpICE9PSAtMSkgY29udGludWU7CiAgICAgICAgICAgIGlmICghKHUuaW5kZXhPZignZ2V0LXF1ZXN0aW9uJykgIT09IC0xIHx8IHUuaW5kZXhPZignZ2V0LXRlc3QnKSAhPT0gLTEgfHwgQVBJX0tFWVdPUkRTLnNvbWUoayA9PiB1LmluZGV4T2YoaykgIT09IC0xKSkpIGNvbnRpbnVlOwogICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgIGNvbnN0IHIyID0gYXdhaXQgZmV0Y2godSwgeyBjcmVkZW50aWFsczogJ2luY2x1ZGUnLCBjYWNoZTogJ25vLWNhY2hlJyB9KTsKICAgICAgICAgICAgICBpZiAocjIgJiYgcjIub2spIHsKICAgICAgICAgICAgICAgIGNvbnN0IHQyID0gYXdhaXQgcjIudGV4dCgpOwogICAgICAgICAgICAgICAgdHJ5IHsgaGFuZGxlUmF3UmVzcG9uc2UodSwgdDIpOyB9IGNhdGNoIChfKSB7fQogICAgICAgICAgICAgIH0KICAgICAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgICAgICAgaWYgKFNFU1NJT04ucmF3X3F1ZXN0aW9ucy5sZW5ndGggPiAwKSByZXR1cm4gdHJ1ZTsKICAgICAgICAgIH0KICAgICAgICB9IGNhdGNoIChfKSB7fQogICAgICAgIGNvbnN0IGxhc3QgPSBVVy5fX3RsX2xhc3RfcXJlcTsKICAgICAgICBpZiAobGFzdCAmJiBsYXN0LnVybCkgewogICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgY29uc3QgZm9wdHMgPSB7CiAgICAgICAgICAgICAgbWV0aG9kOiBsYXN0Lm1ldGhvZCB8fCAnR0VUJywKICAgICAgICAgICAgICBjcmVkZW50aWFsczogJ2luY2x1ZGUnLAogICAgICAgICAgICAgIGNhY2hlOiAnbm8tY2FjaGUnCiAgICAgICAgICAgIH07CiAgICAgICAgICAgIGlmIChsYXN0LmJvZHkgJiYgKGxhc3QubWV0aG9kIHx8ICdHRVQnKS50b1VwcGVyQ2FzZSgpICE9PSAnR0VUJykgewogICAgICAgICAgICAgIGZvcHRzLmhlYWRlcnMgPSB7CiAgICAgICAgICAgICAgICAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZDsgY2hhcnNldD1VVEYtOCcsCiAgICAgICAgICAgICAgICAnWC1SZXF1ZXN0ZWQtV2l0aCc6ICdYTUxIdHRwUmVxdWVzdCcKICAgICAgICAgICAgICB9OwogICAgICAgICAgICAgIGZvcHRzLmJvZHkgPSBsYXN0LmJvZHk7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2gobGFzdC51cmwsIGZvcHRzKTsKICAgICAgICAgICAgaWYgKHJlcy5vaykgewogICAgICAgICAgICAgIGNvbnN0IHR4dCA9IGF3YWl0IHJlcy50ZXh0KCk7CiAgICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgIGhhbmRsZVJhd1Jlc3BvbnNlKGxhc3QudXJsLCB0eHQpOwogICAgICAgICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgICAgIH0KICAgICAgICAgIH0gY2F0Y2ggKGUpIHsKICAgICAgICAgICAgY29uc29sZS53YXJuKCdbVExdIHJlcGxheSBmYWlsJywgZSk7CiAgICAgICAgICB9CiAgICAgICAgfQogICAgICAgIHJldHVybiBTRVNTSU9OLnJhd19xdWVzdGlvbnMubGVuZ3RoID4gMDsKICAgICAgfSBjYXRjaCAoZSkgewogICAgICAgIHJldHVybiBmYWxzZTsKICAgICAgfQogICAgfQogICAgZnVuY3Rpb24gX2FwcGx5RXhhbVRpbWUoKSB7CiAgICB0cnkgewogICAgICBjb25zdCBpbnAgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGwtZ29kLXRpbWUiKTsKICAgICAgaWYgKCFpbnApIHJldHVybjsKICAgICAgY29uc3QgbW9kZUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRsLW1vZGVTZWxlY3QiKTsKICAgICAgY29uc3QgbW9kZSA9IG1vZGVFbCA/IG1vZGVFbC52YWx1ZSA6ICJleGFtIjsKICAgICAgLy8gW3YyOV0gw6FwIHRo4budaSBnaWFuIMSRw6MgY2jhu41uIGNobyBj4bqjIEx1eeG7h24gdOG6rXAgKHByYWN0aWNlKTsgdHLGsOG7m2MgxJHDonkgY2jhu4kgS2nhu4NtIHRyYSAoZXhhbSkKICAgICAgY29uc3QgcyA9IFN0cmluZyhpbnAudmFsdWUgfHwgIiIpLnRyaW0oKSB8fCAiMjUuMDAiOwogICAgICBjb25zdCBwYXJ0cyA9IHMuc3BsaXQoL1suOl0vKTsKICAgICAgY29uc3QgbWlucyA9IHBhcnNlSW50KHBhcnRzWzBdKSB8fCAwOwogICAgICBsZXQgc2VjcyA9IHBhcnNlSW50KHBhcnRzWzFdIHx8ICIwIik7IGlmIChpc05hTihzZWNzKSkgc2VjcyA9IDA7CiAgICAgIGNvbnN0IHRvdGFsID0gTWF0aC5tYXgoMzAsIG1pbnMgKiA2MCArIHNlY3MpOwogICAgICB0cnkgeyB3aW5kb3cudG90YWxfdGltZSA9IHRvdGFsOyB9IGNhdGNoIChfKSB7fQogICAgICBjb25zdCBtbSA9IFN0cmluZyhNYXRoLmZsb29yKHRvdGFsIC8gNjApKS5wYWRTdGFydCgyLCAiMCIpOwogICAgICBjb25zdCBzcyA9IFN0cmluZyh0b3RhbCAlIDYwKS5wYWRTdGFydCgyLCAiMCIpOwogICAgICBkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCIudGltZS1jb3VudGRvd24sW2NsYXNzKj1jb3VudGRvd25dLFtpZCo9Y291bnRkb3duXSxbY2xhc3MqPXRpbWVyXSwjdGltZS1sZWZ0LCNleGFtLXRpbWVyIikuZm9yRWFjaChmdW5jdGlvbihlbCkgewogICAgICAgIGlmIChlbCAmJiBlbC50ZXh0Q29udGVudCAmJiAvXGR7MSwyfTpcZHsyfS8udGVzdChlbC50ZXh0Q29udGVudCkpIGVsLnRleHRDb250ZW50ID0gbW0gKyAiOiIgKyBzczsKICAgICAgfSk7CiAgICAgIGFkZExvZygi4o+x77iPIMSQ4bq3dCB0aOG7nWkgZ2lhbiBsw6BtIGLDoGk6ICIgKyBtaW5zICsgIiBwaMO6dCAiICsgc2VjcyArICIgZ2nDonkgKCIgKyBtbSArICI6IiArIHNzICsgIikuIiwgImluZm8iKTsKICAgIH0gY2F0Y2ggKF8pIHt9CiAgfQogIGNvbnN0IGZpcmVCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtZmlyZUJ0bicpOwogICAgZnVuY3Rpb24gX3RndFNjb3JlVmFsKCl7CiAgICAgIHRyeSB7CiAgICAgICAgdmFyIF9lbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1nb2QtdGFyZ2V0LXNjb3JlJyk7CiAgICAgICAgdmFyIF92ID0gX2VsID8gcGFyc2VGbG9hdChfZWwudmFsdWUpIDogMTA7CiAgICAgICAgaWYgKCFpc0Zpbml0ZShfdikpIF92ID0gMTA7CiAgICAgICAgcmV0dXJuIE1hdGgubWluKDEwLCBNYXRoLm1heCg3LCBfdikpOwogICAgICB9IGNhdGNoIChfKSB7IHJldHVybiAxMDsgfQogICAgfQogICAgZnVuY3Rpb24gdXBkYXRlRmlyZUxhYmVsKCl7CiAgICAgIGlmICghZmlyZUJ0bikgcmV0dXJuOwogICAgICB2YXIgX3YgPSBfdGd0U2NvcmVWYWwoKTsKICAgICAgaWYgKCFpc1ByZW1pdW1LZXkoKSkgewogICAgICAgIGZpcmVCdG4uaW5uZXJIVE1MID0gJ/CflJIgQ0hV4bqoTiBC4buKOEkgJyArIF92ICsgJyDEkEnhu4JNIChDSOG7jiBQUkVNSVVNKSc7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIGlmICghZmlyZUJ0bi5kaXNhYmxlZCkgZmlyZUJ0bi50ZXh0Q29udGVudCA9ICfwn5KlIENIVeG6qE4gQuG7ijhJICcgKyBfdiArICcgxJBJ4buCTSc7CiAgICB9CiAgICBpZiAoIWlzUHJlbWl1bUtleSgpKSB7CiAgICAgIHVwZGF0ZUZpcmVMYWJlbCgpOwogICAgICBmaXJlQnRuLnN0eWxlLmJhY2tncm91bmQgPSAnbGluZWFyLWdyYWRpZW50KDEzNWRlZywjNDQ0LCM2NjYpJzsKICAgICAgZmlyZUJ0bi5zdHlsZS5jdXJzb3IgPSAnbm90LWFsbG93ZWQnOwogICAgICBmaXJlQnRuLnN0eWxlLm9wYWNpdHkgPSAnMC42JzsKICAgICAgZmlyZUJ0bi50aXRsZSA9ICdDaOG7qWMgbsSDbmcgbsOgeSBjaOG7iSBkw6BuaCBjaG8ga2V5IFBSRU1JVU0uIExpw6puIGjhu4cgxJHhu4MgbsOibmcgY+G6pXAhJzsKICAgICAgZmlyZUJ0bi5vbmNsaWNrID0gZSA9PiB7CiAgICAgICAgZS5wcmV2ZW50RGVmYXVsdCgpOwogICAgICAgIGFkZExvZygn8J+UkiBDaOG7qWMgbsSDbmcgbsOgeSB5w6p1IGPhuqd1IGtleSBQUkVNSVVNIScsICdlcnInKTsKICAgICAgICBhZGRMb2coJ/Cfko4gTGnDqm4gaOG7hyBhZG1pbiDEkeG7gyBuw6JuZyBj4bqlcCBrZXkgUFJFTUlVTS4nLCAnd2FybicpOwogICAgICAgIHNob3dDdXN0b21Nb2RhbCh7CiAgICAgICAgICBpY29uOiAn8J+UkicsCiAgICAgICAgICB0aXRsZTogJ1nDilUgQ+G6plUgS0VZIFBSRU1JVU0nLAogICAgICAgICAgbGluZXM6IFsgJ0No4bupYyBuxINuZyA8Yj4iQ0hV4bqoTiBC4buKIDEwIMSQSeG7gk0iPC9iPiBjaOG7iSBkw6BuaCBjaG8ga2V5IFBSRU1JVU0hJywgYEtleSBj4bunYSBi4bqhbiBsw6Aga2V5IDxiPiR7KEtFWV9TVEFUVVMudHlwZSB8fCAnVEjGr+G7nE5HJykudG9VcHBlckNhc2UoKX08L2I+LmAsICfwn5KOIExpw6puIGjhu4cgYWRtaW4gxJHhu4MgbsOibmcgY+G6pXAgbMOqbiBQUkVNSVVNIScgXQogICAgICAgIH0pOwogICAgICB9OwogICAgfSBlbHNlIHsKICAgICAgdXBkYXRlRmlyZUxhYmVsKCk7CiAgICAgIGZpcmVCdG4ub25jbGljayA9IGFzeW5jICgpID0+IHsKICAgICAgICBhZGRMb2coJ/CflI0gxJDhu5NuZyBi4buZIGThu68gbGnhu4d1IHRow7QgdOG7qyBPTE0uLi4nLCAnaW5mbycpOwogICAgICAgIGF3YWl0IGZvcmNlRmV0Y2hRdWVzdGlvbnMoKTsKICAgICAgICBmb3JjZUdldE1ldGEoKTsKICAgICAgICBpZiAoIVNFU1NJT04ubWV0YS5pZF91c2VyIHx8ICFTRVNTSU9OLm1ldGEuaWRfY2F0ZSkgewogICAgICAgICAgYWRkTG9nKCfinYwgQ2jGsGEgY8OzIElEIHVzZXIvY2F0ZSAodXNlcj0nICsgKFNFU1NJT04ubWV0YS5pZF91c2VyIHx8ICc/JykgKyAnLCBjYXRlPScgKyAoU0VTU0lPTi5tZXRhLmlkX2NhdGUgfHwgJz8nKSArICcpLiBIw6N5IEY1IGhv4bq3YyBjaOG7nSB04bqjaSB4b25nIGPDonUgaOG7j2kuJywgJ2VycicpOwogICAgICAgICAgc2hvd0N1c3RvbU1vZGFsKHsKICAgICAgICAgICAgaWNvbjogJ+KaoO+4jycsCiAgICAgICAgICAgIHRpdGxlOiAnVEhJ4bq+VSBE4buuIExJ4buGVScsCiAgICAgICAgICAgIGxpbmVzOiBbICdDaMawYSBuaOG6rW4gxJHGsOG7o2MgSUQgdMOgaSBraG/huqNuIC8gYsOgaSB04bqtcCB04burIHRyYW5nIE9MTS48YnI+VnVpIGzDsm5nIEY1IHRyYW5nLCDEkeG7o2kgZGFuaCBzw6FjaCBjw6J1IGjhu49pIG7huqFwIHhvbmcgcuG7k2kgYuG6pW0gbOG6oWkuJyBdCiAgICAgICAgICB9KTsKICAgICAgICAgIHJldHVybjsKICAgICAgICB9CiAgICAgICAgaWYgKFNFU1NJT04ucmF3X3F1ZXN0aW9ucy5sZW5ndGggPT09IDApIHsKICAgICAgICAgIGlmICghX3N5bnRoZXNpemVRdWVzdGlvbnNGcm9tQW5zd2VycyhmYWxzZSkpIHsKICAgICAgICAgICAgYWRkTG9nKCfinYwgQ2jGsGEgbuG6oXAgxJHGsOG7o2MgY8OidSBo4buPaS4gSMOjeSBGNSB0cmFuZyBob+G6t2MgbMOgbSBt4bubaSBiw6BpIHThuq1wLicsICdlcnInKTsKICAgICAgICAgICAgc2hvd0N1c3RvbU1vZGFsKHsKICAgICAgICAgICAgICBpY29uOiAn8J+TrScsCiAgICAgICAgICAgICAgdGl0bGU6ICdDSMavQSBDw5MgQ8OCVSBI4buOSScsCiAgICAgICAgICAgICAgbGluZXM6IFsgJ0Rhbmggc8OhY2ggY8OidSBo4buPaSDEkWFuZyB0cuG7kW5nLiBGNSB0cmFuZyBiw6BpIHThuq1wIHLhu5NpIGLhuqVtIGzhuqFpLicgXQogICAgICAgICAgICB9KTsKICAgICAgICAgICAgcmV0dXJuOwogICAgICAgICAgfQogICAgICAgICAgYWRkTG9nKCfinIUgRMO5bmcgJyArIFNFU1NJT04ucmF3X3F1ZXN0aW9ucy5sZW5ndGggKyAnIGPDonUgZOG7sW5nIHThu6sgxJHDoXAgw6FuIGtoby9zZXJ2ZXIgxJHhu4MgbuG7mXAuJywgJ29rJyk7CiAgICAgICAgfQogICAgICAgIGNvbnN0IGtleSA9IENVUlJFTlRfS0VZIHx8IF9zTFMuZ2V0KExTX0tFWSk7CiAgICAgICAgY29uc3QgbW9kZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1tb2RlU2VsZWN0JykudmFsdWU7CiAgICAgICAgY29uc3QgdGltZV9zdHIgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtZ29kLXRpbWUnKS52YWx1ZTsKICAgICAgICBfYXBwbHlFeGFtVGltZSgpOyAvLyBbdjI5XSBwcmFjdGljZSBjxaluZyDEkeG6t3QgdGjhu51pIGdpYW4gbMOgbSBiw6BpIMSRw6MgY2jhu41uCiAgICAgICAgZmlyZUJ0bi5kaXNhYmxlZCA9IHRydWU7CiAgICAgICAgZmlyZUJ0bi50ZXh0Q29udGVudCA9ICfij7MgxJBBTkcgWOG7rCBMw50gVFLDik4gU0VSVkVSLi4uJzsKICAgICAgICBhZGRMb2coJ/CfmoAgR+G7rWkgZOG7ryBsaeG7h3UgdGjDtCBsw6puIHNlcnZlciAobW9kZTogJyArIG1vZGUgKyAnKS4uLicsICd3YXJuJyk7CiAgICAgICAgdHJ5IHsKICAgICAgICAgIGxldCByZXN1bHQgPSBudWxsOwogICAgICAgICAgZm9yIChsZXQgX2ZhID0gMDsgX2ZhIDwgMjsgX2ZhKyspIHsKICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICByZXN1bHQgPSBhd2FpdCBnbVBvc3QoJy9maXJlJywgewogICAgICAgICAgICAgICAga2V5OiBrZXksCiAgICAgICAgICAgICAgICBod2lkOiBnZXRIV0lEKCksCiAgICAgICAgICAgICAgICBzZXNzaW9uOiB7CiAgICAgICAgICAgICAgICAgIHJhd19xdWVzdGlvbnM6IFNFU1NJT04ucmF3X3F1ZXN0aW9ucywKICAgICAgICAgICAgICAgICAgYW5zd2VyczogW10uY29uY2F0KFNFU1NJT04uYW5zRmlsZUFuc3dlcnMgfHwgW10sIFNFU1NJT04uYmFua0Fuc3dlcnMgfHwgW10pLAogICAgICAgICAgICAgICAgICBtZXRhOiBTRVNTSU9OLm1ldGEsCiAgICAgICAgICAgICAgICAgIHZpZGVvX2xlbmd0aDogU0VTU0lPTi52aWRlb19sZW5ndGgKICAgICAgICAgICAgICAgIH0sCiAgICAgICAgICAgICAgICBtb2RlOiBtb2RlLAogICAgICAgICAgICAgICAgdGltZV9zdHI6IHRpbWVfc3RyLAogICAgICAgICAgICAgICAgZ3JhZGU6IHdpbmRvdy5ncmFkZSB8fCB3aW5kb3cuaWRfZ3JhZGUgfHwgJzEwJwogICAgICAgICAgICAgIH0pOwogICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICB9IGNhdGNoIChfZmUpIHsKICAgICAgICAgICAgICBpZiAoX2ZhID09PSAwKSB7CiAgICAgICAgICAgICAgICBhZGRMb2coJ+KaoO+4jyBN4bqldCBt4bqhbmcga2hpIGfhu61pIHNlcnZlciDigJQgdOG7sSB0aOG7rSBs4bqhaSBzYXUgMS41cy4uLicsICd3YXJuJyk7CiAgICAgICAgICAgICAgICBhd2FpdCBuZXcgUHJvbWlzZShyID0+IHNldFRpbWVvdXQociwgMTUwMCkpOwogICAgICAgICAgICAgICAgY29udGludWU7CiAgICAgICAgICAgICAgfQogICAgICAgICAgICAgIHRocm93IF9mZTsKICAgICAgICAgICAgfQogICAgICAgICAgfQogICAgICAgICAgaWYgKCEocmVzdWx0LnN1Y2Nlc3MgfHwgcmVzdWx0LnZhbGlkKSkgewogICAgICAgICAgICBjb25zdCBzdCA9IHJlc3VsdC5faHR0cFN0YXR1czsKICAgICAgICAgICAgY29uc3QgbXNnID0gcmVzdWx0Lm1lc3NhZ2UgfHwgJ0zhu5dpIGtow7RuZyB4w6FjIMSR4buLbmggdOG7qyBzZXJ2ZXInOwogICAgICAgICAgICBhZGRMb2coJ+KdjCBTZXJ2ZXIgdOG7qyBjaOG7kWk6ICcgKyBtc2csICdlcnInKTsKICAgICAgICAgICAgaWYgKHN0ID09PSA0MDEpIHNob3dDdXN0b21Nb2RhbCh7CiAgICAgICAgICAgICAgaWNvbjogJ/CflJInLAogICAgICAgICAgICAgIHRpdGxlOiAnS0VZIEtIw5RORyBI4buiUCBM4buGJywKICAgICAgICAgICAgICBsaW5lczogWyBtc2csICdWdWkgbMOybmcgbmjhuq1wIGtleSBo4bujcCBs4buHIGhv4bq3YyBsacOqbiBo4buHIGFkbWluLicgXQogICAgICAgICAgICB9KTsgZWxzZSBpZiAoc3QgPT09IDQwMykgc2hvd0N1c3RvbU1vZGFsKHsKICAgICAgICAgICAgICBpY29uOiAn8J+SjicsCiAgICAgICAgICAgICAgdGl0bGU6ICdD4bqmTiBLRVkgUFJFTUlVTScsCiAgICAgICAgICAgICAgbGluZXM6IFsgbXNnIF0KICAgICAgICAgICAgfSk7IGVsc2UgaWYgKHN0ID09PSA0MjkpIHNob3dDdXN0b21Nb2RhbCh7CiAgICAgICAgICAgICAgaWNvbjogJ+KPsycsCiAgICAgICAgICAgICAgdGl0bGU6ICdRVcOBIFThuqZOIFNV4bqkVCcsCiAgICAgICAgICAgICAgbGluZXM6IFsgbXNnLCAnVnVpIGzDsm5nIGNo4budIHbDoGkgcGjDunQgcuG7k2kgdGjhu60gbOG6oWkuJyBdCiAgICAgICAgICAgIH0pOyBlbHNlIHNob3dDdXN0b21Nb2RhbCh7CiAgICAgICAgICAgICAgaWNvbjogJ+KaoO+4jycsCiAgICAgICAgICAgICAgdGl0bGU6ICdLSMOUTkcgTuG7mFAgxJDGr+G7okMnLAogICAgICAgICAgICAgIGxpbmVzOiBbIG1zZyBdCiAgICAgICAgICAgIH0pOwogICAgICAgICAgICBmaXJlQnRuLmRpc2FibGVkID0gZmFsc2U7CiAgICAgICAgICAgIHVwZGF0ZUZpcmVMYWJlbCgpOwogICAgICAgICAgICByZXR1cm47CiAgICAgICAgICB9CiAgICAgICAgICBhZGRMb2coJ/Cfk6QgU2VydmVyIMSRw6MgZOG7sW5nIHhvbmcgYsOgaSDigJQgxJFhbmcgZ+G7rWkgbMOqbiBPTE0uLi4nLCAnaW5mbycpOwogICAgICAgICAgX2FwcGx5RXhhbVRpbWUoKTsKICAgICAgICAgIGlmIChyZXN1bHQuc3VtbWFyeSAmJiBBcnJheS5pc0FycmF5KHJlc3VsdC5zdW1tYXJ5Lml0ZW1zKSAmJiByZXN1bHQuc3VtbWFyeS5pdGVtcy5sZW5ndGgpIHsKICAgICAgICAgICAgYWRkTG9nKCfwn6euIFNlcnZlciDEkcOjIGdp4bqjaSAnICsgKHJlc3VsdC5zdW1tYXJ5LmNvdW50IHx8IHJlc3VsdC5zdW1tYXJ5Lml0ZW1zLmxlbmd0aCkgKyAnIGPDonUgKG1vZGU6ICcgKyAocmVzdWx0LnN1bW1hcnkubW9kZSB8fCBtb2RlKSArICcpLicsICdpbmZvJyk7CiAgICAgICAgICB9CiAgICAgICAgICBjb25zdCBjc3JmID0gU0VTU0lPTi5tZXRhLmNzcmZfdG9rZW4gfHwgZG9jdW1lbnQucXVlcnlTZWxlY3RvcignbWV0YVtuYW1lPSJjc3JmLXRva2VuIl0nKT8uZ2V0QXR0cmlidXRlKCdjb250ZW50JykgfHwgJyc7CiAgICAgICAgICAvLyBbdjMxXSBN4bqhbmcgeeG6v3U6IHThu7EgbuG7mXAgbOG6oWkgT0xNIHThu5FpIMSRYSAyIGzhuqduIChIVFRQIGzhu5dpIHThuqFtIHRo4budaSAvIG3huqV0IGvhur90IG7hu5FpKQogICAgICAgICAgbGV0IHJlc3BvbnNlID0gbnVsbDsKICAgICAgICAgIGZvciAobGV0IF9zYSA9IDA7IF9zYSA8IDI7IF9zYSsrKSB7CiAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgcmVzcG9uc2UgPSBhd2FpdCBmZXRjaChyZXN1bHQuZW5kcG9pbnQgfHwgJy9jb3Vyc2UvdGVhY2hlci1zdGF0aWMnLCB7CiAgICAgICAgICAgICAgICBtZXRob2Q6ICdQT1NUJywKICAgICAgICAgICAgICAgIGNyZWRlbnRpYWxzOiAnaW5jbHVkZScsCiAgICAgICAgICAgICAgICBoZWFkZXJzOiB7CiAgICAgICAgICAgICAgICAgICdjb250ZW50LXR5cGUnOiAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkOyBjaGFyc2V0PVVURi04JywKICAgICAgICAgICAgICAgICAgJ3gtY3NyZi10b2tlbic6IGNzcmYsCiAgICAgICAgICAgICAgICAgICd4LXJlcXVlc3RlZC13aXRoJzogJ1hNTEh0dHBSZXF1ZXN0JwogICAgICAgICAgICAgICAgfSwKICAgICAgICAgICAgICAgIGJvZHk6IHJlc3VsdC5wYXJhbXNfc3RyCiAgICAgICAgICAgICAgfSk7CiAgICAgICAgICAgICAgaWYgKHJlc3BvbnNlLm9rIHx8IF9zYSA9PT0gMSkgYnJlYWs7CiAgICAgICAgICAgICAgYWRkTG9nKCfimqDvuI8gT0xNIHRy4bqjIEhUVFAgJyArIHJlc3BvbnNlLnN0YXR1cyArICcg4oCUIHRo4butIGzhuqFpIHNhdSAxLjhzLi4uJywgJ3dhcm4nKTsKICAgICAgICAgICAgICBhd2FpdCBuZXcgUHJvbWlzZShyID0+IHNldFRpbWVvdXQociwgMTgwMCkpOwogICAgICAgICAgICB9IGNhdGNoIChfc2UpIHsKICAgICAgICAgICAgICBpZiAoX3NhID09PSAwKSB7CiAgICAgICAgICAgICAgICBhZGRMb2coJ+KaoO+4jyBN4bqldCBt4bqhbmcga2hpIG7hu5lwIE9MTSDigJQgdGjhu60gbOG6oWkgc2F1IDJzLi4uJywgJ3dhcm4nKTsKICAgICAgICAgICAgICAgIGF3YWl0IG5ldyBQcm9taXNlKHIgPT4gc2V0VGltZW91dChyLCAyMDAwKSk7CiAgICAgICAgICAgICAgICBjb250aW51ZTsKICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgdGhyb3cgX3NlOwogICAgICAgICAgICB9CiAgICAgICAgICB9CiAgICAgICAgICBpZiAocmVzcG9uc2Uub2spIHsKICAgICAgICAgICAgYWRkTG9nKCfinIUgTuG7mXAgYsOgaSB0aMOgbmggY8O0bmchIEtp4buDbSB0cmEgxJFp4buDbSBPTE0uJywgJ29rJyk7CiAgICAgICAgICAgIGZpcmVCdG4udGV4dENvbnRlbnQgPSAn4pyFIFRIw4BOSCBDw5RORyEnOwogICAgICAgICAgICBmaXJlQnRuLnN0eWxlLmJhY2tncm91bmQgPSAnbGluZWFyLWdyYWRpZW50KDEzNWRlZywjMDBiMDliLCMwMGU2NzYpJzsKICAgICAgICAgICAgc2hvd0N1c3RvbU1vZGFsKHsKICAgICAgICAgICAgICBpY29uOiAn4pyFJywKICAgICAgICAgICAgICB0aXRsZTogJ07hu5hQIELDgEkgVEjDgE5IIEPDlE5HJywKICAgICAgICAgICAgICBsaW5lczogWyAnU2VydmVyIMSRw6MgeOG7rSBsw70gPGI+JyArIChyZXN1bHQuc3VtbWFyeSA/IHJlc3VsdC5zdW1tYXJ5LmNvdW50IHx8IDAgOiBTRVNTSU9OLnJhd19xdWVzdGlvbnMubGVuZ3RoKSArICc8L2I+IGPDonUgdsOgIGfhu61pIGzDqm4gT0xNLicsICdUcmFuZyBz4bq9IHThu7EgdOG6o2kgbOG6oWkgc2F1IHbDoGkgZ2nDonkuJyBdCiAgICAgICAgICAgIH0pOwogICAgICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHdpbmRvdy5sb2NhdGlvbi5yZWxvYWQoKSwgMjUwMCk7CiAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICBhZGRMb2coJ+KdjCBPTE0gdHLhuqMgduG7gSBs4buXaSBIVFRQICcgKyByZXNwb25zZS5zdGF0dXMsICdlcnInKTsKICAgICAgICAgICAgc2hvd0N1c3RvbU1vZGFsKHsKICAgICAgICAgICAgICBpY29uOiAn4p2MJywKICAgICAgICAgICAgICB0aXRsZTogJ07hu5hQIELDgEkgVEjhuqRUIELhuqBJJywKICAgICAgICAgICAgICBsaW5lczogWyAnTcOheSBjaOG7pyBPTE0gdHLhuqMgbOG7l2kgSFRUUCAnICsgcmVzcG9uc2Uuc3RhdHVzICsgJy48YnI+VGjhu60gRjUgdHJhbmcgcuG7k2kgYuG6pW0gbOG6oWkuJyBdCiAgICAgICAgICAgIH0pOwogICAgICAgICAgICBmaXJlQnRuLmRpc2FibGVkID0gZmFsc2U7CiAgICAgICAgICAgIHVwZGF0ZUZpcmVMYWJlbCgpOwogICAgICAgICAgfQogICAgICAgIH0gY2F0Y2ggKGUpIHsKICAgICAgICAgIGFkZExvZygn4p2MIEzhu5dpOiAnICsgZS5tZXNzYWdlLCAnZXJyJyk7CiAgICAgICAgICBzaG93Q3VzdG9tTW9kYWwoewogICAgICAgICAgICBpY29uOiAn8J+MkCcsCiAgICAgICAgICAgIHRpdGxlOiAnTOG7lkkgS+G6vlQgTuG7kEknLAogICAgICAgICAgICBsaW5lczogWyAnS2jDtG5nIGvhur90IG7hu5FpIMSRxrDhu6NjIHNlcnZlci9PTE06IDxiPicgKyAoZS5tZXNzYWdlIHx8ICcnKSArICc8L2I+JyBdCiAgICAgICAgICB9KTsKICAgICAgICAgIGZpcmVCdG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgICAgIHVwZGF0ZUZpcmVMYWJlbCgpOwogICAgICAgIH0KICAgICAgfTsKICAgIH0KICAgIHZhciBfdGd0U2VsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLWdvZC10YXJnZXQtc2NvcmUnKTsKICAgIGlmIChfdGd0U2VsKSB7CiAgICAgIF90Z3RTZWwuYWRkRXZlbnRMaXN0ZW5lcignY2hhbmdlJywgdXBkYXRlRmlyZUxhYmVsKTsKICAgICAgdXBkYXRlRmlyZUxhYmVsKCk7CiAgICB9CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtY2hhbmdlS2V5Jykub25jbGljayA9ICgpID0+IHsKICAgICAgc2hvd0NvbmZpcm1Nb2RhbCh7CiAgICAgICAgaWNvbjogJ/CflIQnLAogICAgICAgIHRpdGxlOiAnxJDhu5RJIEtFWT8nLAogICAgICAgIGxpbmVzOiBbICdLZXkgaGnhu4duIHThuqFpIHPhur0gYuG7iyA8Yj54b8OhIGhvw6BuIHRvw6BuPC9iPi4nLCAnQuG6oW4gc+G6vSDEkcaw4bujYyDEkcawYSB24buBIG3DoG4gaMOsbmggxJHEg25nIG5o4bqtcC4nIF0sCiAgICAgICAgb2tUZXh0OiAn8J+UhCDEkOG7lEkgS0VZJywKICAgICAgICBjYW5jZWxUZXh0OiAnSOG7plknLAogICAgICAgIG9uT2s6ICgpID0+IHsKICAgICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKExTX0tFWSk7CiAgICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShMU19UWVBFKTsKICAgICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKExTX0VYUCk7CiAgICAgICAgICBDVVJSRU5UX0tFWSA9IG51bGw7CiAgICAgICAgICBLRVlfU1RBVFVTID0gewogICAgICAgICAgICB2YWxpZDogZmFsc2UsCiAgICAgICAgICAgIHR5cGU6IG51bGwsCiAgICAgICAgICAgIGV4cGlyZXNfYXQ6IG51bGwKICAgICAgICAgIH07CiAgICAgICAgICBfc2VjU2Vzc2lvbiA9IHsKICAgICAgICAgICAgdG9rZW46IG51bGwsCiAgICAgICAgICAgIGV4cDogMCwKICAgICAgICAgICAgZnBIYXNoOiBudWxsLAogICAgICAgICAgICBzZXE6IDEKICAgICAgICAgIH07CiAgICAgICAgICBDVVJSRU5UX0RFVklDRSA9ICcnOwogICAgICAgICAgcGFuZWwucmVtb3ZlKCk7CiAgICAgICAgICBmbG9hdEJ0bi5yZW1vdmUoKTsKICAgICAgICAgIGJ1aWxkTG9ja1NjcmVlbigpOwogICAgICAgIH0KICAgICAgfSk7CiAgICB9OwogICAgYWRkTG9nKCfinIUgR09EIE1PRCBjb25uZWN0b3Igc3VjY2VzcycsICdvaycpOwogICAgLy8gW3YzMV0gSGnhu4NuIHRo4buLIHTDoGkga2hv4bqjbiBPTE0g4bufIHRyYW5nIEzhu5twIGjhu41jIGPhu6dhIHTDtGk7IFt2MzNdIHRow6ptIHRyYW5nIELDoGkgdOG6rXAgxJHGsOG7o2MgZ2lhbzsgdHJhbmcgYsOgaSB04bqtcCDhuqluLgogICAgY29uc3Qgb2xtVXNlck5vdyA9IGdldE9sbVVzZXJuYW1lKCk7CiAgICBfbGFzdE9sbVVzZXIgPSBvbG1Vc2VyTm93OwogICAgaWYgKF9hY2NvdW50UGFnZSgpKSBfZW5zdXJlT2xtTG9nKG9sbVVzZXJOb3cpOwogICAgLy8gW3YyNl0gVOG7sSBj4bqtcCBuaOG6rXQgbG9nIHTDoGkga2hv4bqjbiBPTE0ga2hpIG5nxrDhu51pIGTDuW5nIMSRxINuZyB4deG6pXQg4oaSIMSRxINuZyBuaOG6rXAgdMOgaSBraG/huqNuIGtow6FjICh2ZCBiMl92dWhvYW5nZHV5IOKGkiBiMl9sdW9uZ3ZhbnR1eWVuKQogICAgc2V0SW50ZXJ2YWwoKCkgPT4gewogICAgICB0cnkgewogICAgICAgIGNvbnN0IHUgPSBnZXRPbG1Vc2VybmFtZSgpOwogICAgICAgIGlmICghdSB8fCB1ID09PSAnS2hvbmdYYWNEaW5oJykgcmV0dXJuOwogICAgICAgIGlmICh1ID09PSBfbGFzdE9sbVVzZXIpIHJldHVybjsKICAgICAgICBfbGFzdE9sbVVzZXIgPSB1OwogICAgICAgIGlmIChfYWNjb3VudFBhZ2UoKSkgX2Vuc3VyZU9sbUxvZyh1KTsKICAgICAgfSBjYXRjaCAoXykge30KICAgIH0sIDE1MDAwKTsKICAgIC8vIFt2MzFdIFRoZW8gZMO1aSBjaHV54buDbiB0cmFuZzogdsOgbyB0cmFuZyBs4bubcCBo4buNYyAvIGLDoGkgdOG6rXAgxJHGsOG7o2MgZ2lhbyDihpIgaGnhu4duIHTDoGkga2hv4bqjbjsgc2FuZyBiw6BpIHThuq1wIOKGkiBn4buhIGTDsm5nIHTDoGkga2hv4bqjbgogICAgc2V0SW50ZXJ2YWwoKCkgPT4gewogICAgICB0cnkgewogICAgICAgIGlmIChfYWNjb3VudFBhZ2UoKSkgX2Vuc3VyZU9sbUxvZyhfbGFzdE9sbVVzZXIpOwogICAgICAgIGVsc2UgX3JlbW92ZU9sbUxvZ1Jvd3MoKTsKICAgICAgfSBjYXRjaCAoXykge30KICAgIH0sIDgwMDApOwogICAgYWRkTG9nKCfihLnvuI8gxJBhbmcgY2jhu50gbuG6oXAgY8OidSBo4buPaS4uLicsICdpbmZvJyk7CiAgICBpZiAoIWlzUHJlbWl1bUtleSgpKSB7CiAgICAgIGFkZExvZygn4pqg77iPIEtleSB0aMaw4budbmc6IENo4bupYyBuxINuZyAiQ0hV4bqoTiBC4buKIDEwIMSQSeG7gk0iIGLhu4sga2hvw6EhJywgJ3dhcm4nKTsKICAgICAgYWRkTG9nKCfwn5KOIE7Dom5nIGPhuqVwIFBSRU1JVU0gxJHhu4MgbeG7nyBraG/DoSB0b8OgbiBi4buZIHTDrW5oIG7Eg25nLicsICd3YXJuJyk7CiAgICB9IGVsc2UgewogICAgICBhZGRMb2coJ/Cfko4gS2V5IFBSRU1JVU06IFThuqV0IGPhuqMgdMOtbmggbsSDbmcgxJHDoyDEkcaw4bujYyBt4bufIGtob8OhIScsICdvaycpOwogICAgICBfc3RhcnRIZWFydGJlYXQoKTsKICAgIH0KICAgIGZvcmNlR2V0TWV0YSgpOwogICAgcmVmcmVzaFN1YmplY3RUaXRsZVVJKCk7CiAgICBfc2NoZWR1bGVCYW5rRmFsbGJhY2soKTsKICB9CiAgZnVuY3Rpb24gX2NhbmNlbEJhbmtGYWxsYmFjaygpIHsKICAgIGlmIChfYmFua0ZhbGxiYWNrVGltZXIpIHsgY2xlYXJUaW1lb3V0KF9iYW5rRmFsbGJhY2tUaW1lcik7IF9iYW5rRmFsbGJhY2tUaW1lciA9IG51bGw7IH0KICAgIF9iYW5rUmV0cnkgPSAwOwogIH0KICBsZXQgX2JhbmtOYXZUaW1lciA9IG51bGw7CiAgZnVuY3Rpb24gX3NjaGVkdWxlQmFua0ZhbGxiYWNrKCkgewogICAgdHJ5IHsKICAgICAgaWYgKCFpc0V4ZXJjaXNlUGFnZSgpKSB7CiAgICAgICAgX2NhbmNlbEJhbmtGYWxsYmFjaygpOwogICAgICAgIGlmICghX2JhbmtOYXZUaW1lcikgewogICAgICAgICAgX2JhbmtOYXZUaW1lciA9IHNldEludGVydmFsKCgpID0+IHsKICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICBpZiAoaXNFeGVyY2lzZVBhZ2UoKSkgewogICAgICAgICAgICAgICAgaWYgKF9iYW5rTmF2VGltZXIpIHsgY2xlYXJJbnRlcnZhbChfYmFua05hdlRpbWVyKTsgX2JhbmtOYXZUaW1lciA9IG51bGw7IH0KICAgICAgICAgICAgICAgIF9zY2hlZHVsZUJhbmtGYWxsYmFjaygpOwogICAgICAgICAgICAgIH0KICAgICAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgICAgIH0sIDQwMDApOyAvLyBbdjMxXSBxdcOpdCBjaHV54buDbiB0cmFuZyBuaGFuaCA0cyB0aGF5IHbDrCA4cwogICAgICAgIH0KICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgaWYgKF9iYW5rTmF2VGltZXIpIHsgY2xlYXJJbnRlcnZhbChfYmFua05hdlRpbWVyKTsgX2JhbmtOYXZUaW1lciA9IG51bGw7IH0KICAgICAgX2NhbmNlbEJhbmtGYWxsYmFjaygpOwogICAgICBfYmFua1JldHJ5ID0gMDsKICAgICAgLy8gW3YzMV0gTeG6oW5nIHnhur91IHbhuqtuIHRyYSDEkcOhcCDDoW4gbmhhbmg6IGzhuqduIMSR4bqndSAyLjVzLCByZXRyeSA2LzEyLzIwLzMwLzQ1cywgdOG7kWkgxJFhIDYgbOG6p24uCiAgICAgIF9iYW5rRmFsbGJhY2tUaW1lciA9IHNldFRpbWVvdXQoX2NoZWNrQW5zd2VyQmFua0ZhbGxiYWNrLCAyNTAwKTsKICAgICAgYWRkTG9nKCfij7MgVHJhbmcgYsOgaSB04bqtcDogc2F1IDIuNXMgbuG6v3UgY2jGsGEgbuG6oXAgY8OidSBo4buPaSBz4bq9IHThu7EgdHJhIGtobyDEkcOhcCDDoW4gc2VydmVyICh0aOG7rSBs4bqhaSBuaGFuaCA2cywgMTJzLCAyMHMsIDMwcywgNDVzKS4nLCAnaW5mbycpOwogICAgfSBjYXRjaCAoXykge30KICB9CiAgdHJ5IHsKICAgIHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKCdoYXNoY2hhbmdlJywgKCkgPT4gX3NjaGVkdWxlQmFua0ZhbGxiYWNrKCkpOwogICAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoJ3BvcHN0YXRlJywgKCkgPT4gX3NjaGVkdWxlQmFua0ZhbGxiYWNrKCkpOwogIH0gY2F0Y2ggKF8pIHt9CiAgZnVuY3Rpb24gX2VzY0JhbmsocykgewogICAgcmV0dXJuIFN0cmluZyhzID09IG51bGwgPyAnJyA6IHMpLnJlcGxhY2UoLyYvZywgJyZhbXA7JykucmVwbGFjZSgvPC9nLCAnJmx0OycpLnJlcGxhY2UoLz4vZywgJyZndDsnKTsKICB9CiAgYXN5bmMgZnVuY3Rpb24gX2NoZWNrQW5zd2VyQmFua0ZhbGxiYWNrKCkgewogICAgaWYgKCFpc0V4ZXJjaXNlUGFnZSgpKSByZXR1cm47CiAgICBpZiAoU0VTU0lPTi5yYXdfcXVlc3Rpb25zLmxlbmd0aCA+IDApIHJldHVybjsKICAgIGZvcmNlR2V0TWV0YSgpOwogICAgLy8gW3YyNl0gTHXDtG4gbOG6pXkgbeG7m2kgdMOqbiBtw7RuL3TDqm4gYsOgaSB0csOqbiB0cmFuZyBoaeG7h24gdOG6oWkgxJHhu4MgdHJhIMSRw7puZyBiw6BpIMSRYW5nIG3hu58gKGNodXnhu4NuIGLDoGkga2jDtG5nIGLhu4sgZ2nhu68gbWV0YSBjxakpCiAgICBTRVNTSU9OLm1ldGEuc3ViamVjdF9uYW1lID0gZGV0ZWN0U3ViamVjdE5hbWUoKSB8fCBTRVNTSU9OLm1ldGEuc3ViamVjdF9uYW1lIHx8ICcnOwogICAgU0VTU0lPTi5tZXRhLmV4ZXJjaXNlX3RpdGxlID0gZGV0ZWN0RXhlcmNpc2VUaXRsZSgpIHx8IFNFU1NJT04ubWV0YS5leGVyY2lzZV90aXRsZSB8fCAnJzsKICAgIFNFU1NJT04ubWV0YS5pZF9jYXRlID0gU0VTU0lPTi5tZXRhLmlkX2NhdGUgfHwgcmlwSWRGcm9tVXJsKCk7CiAgICByZWZyZXNoU3ViamVjdFRpdGxlVUkoKTsKICAgIGNvbnN0IGNhdGUgPSBTRVNTSU9OLm1ldGEuaWRfY2F0ZTsKICAgIGlmICghY2F0ZSAmJiAhU0VTU0lPTi5tZXRhLnN1YmplY3RfbmFtZSkgeyBhZGRMb2coJ+KEue+4jyBDaMawYSB4w6FjIMSR4buLbmggbcOjIG3DtG4gKGlkX2NhdGUpIC8gdMOqbiBtw7RuIMSR4buDIHRyYSBraG8gxJHDoXAgw6FuLicsICd3YXJuJyk7IHJldHVybjsgfQogICAgYWRkTG9nKCfwn5SOIFRyYSBraG8gxJHDoXAgw6FuIHNlcnZlciAobOG6p24gdGjhu60gJyArIChfYmFua1JldHJ5ICsgMSkgKyAnKTogJyArIChTRVNTSU9OLm1ldGEuc3ViamVjdF9uYW1lID8gJ23DtG4gJyArIFNFU1NJT04ubWV0YS5zdWJqZWN0X25hbWUgOiAnbcO0biAnICsgY2F0ZSkgKyAnLi4uJywgJ2luZm8nKTsKICAgIHRyeSB7CiAgICAgIGNvbnN0IHIgPSBhd2FpdCBnbVBvc3QoJy9hbnN3ZXJzL2xvb2t1cCcsIHsKICAgICAgICBrZXk6IENVUlJFTlRfS0VZIHx8IF9zTFMuZ2V0KExTX0tFWSksCiAgICAgICAgaHdpZDogZ2V0SFdJRCgpLAogICAgICAgIGNhdGU6IGNhdGUgfHwgJycsCiAgICAgICAgc3ViamVjdDogU0VTU0lPTi5tZXRhLnN1YmplY3RfbmFtZSB8fCAnJywKICAgICAgICBleGVyY2lzZV90aXRsZTogU0VTU0lPTi5tZXRhLmV4ZXJjaXNlX3RpdGxlIHx8ICcnLAogICAgICAgIGNvdXJzZXdhcmU6IFNFU1NJT04ubWV0YS5pZF9jb3Vyc2V3YXJlIHx8ICcnLAogICAgICAgIG9sbV91c2VyOiBnZXRPbG1Vc2VybmFtZSgpCiAgICAgIH0pOwogICAgICBjb25zdCBoYXNJdGVtcyA9IHIgJiYgci5mb3VuZCAmJiAoQXJyYXkuaXNBcnJheShyLml0ZW1zKSAmJiByLml0ZW1zLmxlbmd0aCB8fCBBcnJheS5pc0FycmF5KHIuZXhlcmNpc2VzKSAmJiByLmV4ZXJjaXNlcy5sZW5ndGgpOwogICAgICBpZiAoaGFzSXRlbXMpIHsKICAgICAgICAvLyBbdjI2XSBDaOG7iSBs4bqleSDEkMOBUCDDgU4gQ+G7pkEgxJDDmk5HIELDgEkgVOG6rFAgxJBBTkcgTeG7niAoc2VydmVyIGzhu41jIHRoZW8gbWF0Y2hlZF9leGVyY2lzZSk7IGtow7RuZyB0cuG7mW4gYsOgaS9tw7RuIGtow6FjCiAgICAgICAgbGV0IHNjb3BlZCA9IFtdOwogICAgICAgIGxldCBtYXRjaGVkRXggPSBudWxsOwogICAgICAgIGlmIChyLm1hdGNoZWRfZXhlcmNpc2UgJiYgQXJyYXkuaXNBcnJheShyLmV4ZXJjaXNlcykgJiYgci5leGVyY2lzZXMubGVuZ3RoKSB7CiAgICAgICAgICBtYXRjaGVkRXggPSByLmV4ZXJjaXNlcy5maW5kKGV4ID0+IGV4LmtleSA9PT0gci5tYXRjaGVkX2V4ZXJjaXNlLmtleSkKICAgICAgICAgICAgfHwgci5leGVyY2lzZXMuZmluZChleCA9PiBleC50aXRsZSA9PT0gci5tYXRjaGVkX2V4ZXJjaXNlLnRpdGxlKQogICAgICAgICAgICB8fCBudWxsOwogICAgICAgIH0KICAgICAgICBpZiAobWF0Y2hlZEV4ICYmIChtYXRjaGVkRXguaXRlbXMgfHwgW10pLmxlbmd0aCkgc2NvcGVkID0gbWF0Y2hlZEV4Lml0ZW1zOwogICAgICAgIGVsc2UgaWYgKEFycmF5LmlzQXJyYXkoci5leGVyY2lzZXMpICYmIHIuZXhlcmNpc2VzLmxlbmd0aCA9PT0gMSAmJiAoci5leGVyY2lzZXNbMF0uaXRlbXMgfHwgW10pLmxlbmd0aCkgc2NvcGVkID0gci5leGVyY2lzZXNbMF0uaXRlbXM7CiAgICAgICAgZWxzZSBzY29wZWQgPSByLml0ZW1zIHx8IFtdOwogICAgICAgIFNFU1NJT04uYmFua0Fuc3dlcnMgPSBzY29wZWQ7CiAgICAgICAgX3JlZnJlc2hRQ291bnQoKTsKICAgICAgICBfc3ludGhlc2l6ZVF1ZXN0aW9uc0Zyb21BbnN3ZXJzKHRydWUpOyAvLyBbdjM0XSBk4buxbmcgY8OidSB04burIGtobyDEkeG7gyBi4bqlbSBDaHXhuqluIGLhu4sgMTAgxJFp4buDbSBraMO0bmcgYuG7iyB0cuG7kW5nCiAgICAgICAgcmVuZGVyQW5zd2Vyc0Jsb2NrKHNjb3BlZCwgIvCfk5ogS2hvIHNlcnZlcjogIiArIChyLnN1YmplY3QgfHwgIk3DtG4iKSArIChtYXRjaGVkRXggPyAoIiDCtyAiICsgKG1hdGNoZWRFeC50aXRsZSB8fCAiQsOgaSB04bqtcCIpKSA6ICIiKSArICIg4oCUICIgKyBzY29wZWQubGVuZ3RoICsgIiBjw6J1LCDEkeG6qXkgeHXhu5FuZyBsb2chIik7CiAgICAgICAgYWRkTG9nKCfinIUgS2hvIHNlcnZlciBjw7MgJyArIHNjb3BlZC5sZW5ndGggKyAnIMSRw6FwIMOhbiBjaG8gYsOgaSB04bqtcCDEkWFuZyBt4bufIOKAlCDEkcOjIGhp4buDbiB0aOG7iyB4deG7kW5nIGTGsOG7m2khJywgJ29rJyk7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgYWRkTG9nKCfihLnvuI8gS2hvIHNlcnZlciBjaMawYSBjw7MgxJHDoXAgw6FuIGNobyAnICsgKFNFU1NJT04ubWV0YS5zdWJqZWN0X25hbWUgfHwgKCdtw7RuICcgKyAoY2F0ZSB8fCAnPycpKSkgKyAnIGLDoGkgdOG6rXAgbsOgeS4nLCAnd2FybicpOwogICAgICAgIC8vIFt2MzFdIG3huqFuZyB54bq/dTogdGjhu60gbOG6oWkgbmhhbmggNnMvMTJzLzIwcy8zMHMvNDVzLCB04buRaSDEkWEgNiBs4bqnbgogICAgICAgIF9iYW5rUmV0cnkrKzsKICAgICAgICBpZiAoX2JhbmtSZXRyeSA8PSA1KSB7CiAgICAgICAgICBjb25zdCB3YWl0TXMgPSBbNjAwMCwgMTIwMDAsIDIwMDAwLCAzMDAwMCwgNDUwMDBdW19iYW5rUmV0cnkgLSAxXSB8fCA0NTAwMDsKICAgICAgICAgIF9iYW5rRmFsbGJhY2tUaW1lciA9IHNldFRpbWVvdXQoX2NoZWNrQW5zd2VyQmFua0ZhbGxiYWNrLCB3YWl0TXMpOwogICAgICAgIH0KICAgICAgfQogICAgfSBjYXRjaCAoZSkgewogICAgICBhZGRMb2coJ+KaoO+4jyBUcmEga2hvIMSRw6FwIMOhbiBs4buXaTogJyArICgoZSAmJiBlLm1lc3NhZ2UpIHx8IGUpLCAnZXJyJyk7CiAgICAgIC8vIFt2MzFdIG3huqV0IGvhur90IG7hu5FpIHThuqFtIHRo4budaTogdOG7sSB0aOG7rSBs4bqhaSBzYXUgNnMgdGhheSB2w6wgZOG7q25nIGjhurNuCiAgICAgIF9iYW5rUmV0cnkrKzsKICAgICAgaWYgKF9iYW5rUmV0cnkgPD0gNSkgewogICAgICAgIGNvbnN0IHdhaXRNcyA9IFs2MDAwLCAxMjAwMCwgMjAwMDAsIDMwMDAwLCA0NTAwMF1bX2JhbmtSZXRyeSAtIDFdIHx8IDQ1MDAwOwogICAgICAgIF9iYW5rRmFsbGJhY2tUaW1lciA9IHNldFRpbWVvdXQoX2NoZWNrQW5zd2VyQmFua0ZhbGxiYWNrLCB3YWl0TXMpOwogICAgICB9CiAgICB9CiAgfQogIC8vID09PSBbdjM0XSBBVVRPIGLhuq90IMSRw6FwIMOhbiB04burIEFQSSBnZXQtY3J0LWFucy1maWxlIC0+IGfhu61pIHNlcnZlciBnaeG6o2kgbcOjIC0+IMSR4bqpeSB4deG7kW5nIHBhbmVsID09PQogIGxldCBfbGFzdEFuc0ZpbGVLZXkgPSAnJzsKICBmdW5jdGlvbiBfZXh0cmFjdEFuc0ZpbGVSYXcodGV4dCkgewogICAgaWYgKHRleHQgPT0gbnVsbCkgcmV0dXJuICcnOwogICAgY29uc3QgdCA9IFN0cmluZyh0ZXh0KS50cmltKCk7CiAgICBpZiAoIXQpIHJldHVybiAnJzsKICAgIHRyeSB7CiAgICAgIGNvbnN0IGogPSBKU09OLnBhcnNlKHQpOwogICAgICBpZiAoaiAmJiB0eXBlb2YgaiA9PT0gJ29iamVjdCcpIHsKICAgICAgICBpZiAoai5mYyB8fCBqLmZmIHx8IGoudGYgfHwgai5kZyB8fCBqLm5ycSB8fCBqLnJucSkgcmV0dXJuIHQ7CiAgICAgICAgZm9yIChjb25zdCBrIG9mIFsgJ2RhdGEnLCAnY29udGVudCcsICdhbnN3ZXJfZmlsZScsICdmaWxlJywgJ3BheWxvYWQnLCAnYW5zJywgJ2Fuc3dlcnMnLCAncmVzdWx0JywgJ2JvZHknIF0pIHsKICAgICAgICAgIGlmICh0eXBlb2YgaltrXSA9PT0gJ3N0cmluZycgJiYgaltrXS50cmltKCkpIHJldHVybiBqW2tdOwogICAgICAgICAgaWYgKGpba10gJiYgdHlwZW9mIGpba10gPT09ICdvYmplY3QnKSByZXR1cm4gSlNPTi5zdHJpbmdpZnkoaltrXSk7CiAgICAgICAgfQogICAgICB9CiAgICB9IGNhdGNoIChfKSB7fQogICAgdHJ5IHsKICAgICAgY29uc3QgbSA9IHQubWF0Y2goL1tBLVphLXowLTkrLz1fLV17NDAsfS9nKTsKICAgICAgaWYgKG0gJiYgbS5sZW5ndGgpIHJldHVybiBtLnNvcnQoKGEsIGIpID0+IGIubGVuZ3RoIC0gYS5sZW5ndGgpWzBdOwogICAgfSBjYXRjaCAoXykge30KICAgIHJldHVybiB0OwogIH0KICBhc3luYyBmdW5jdGlvbiBoYW5kbGVBbnNGaWxlUmVzcG9uc2UodXJsLCB0ZXh0KSB7CiAgICB0cnkgewogICAgICBjb25zdCByYXcgPSBfZXh0cmFjdEFuc0ZpbGVSYXcodGV4dCk7CiAgICAgIGlmICghcmF3IHx8IHJhdy5sZW5ndGggPCAxNikgcmV0dXJuOwogICAgICBjb25zdCBrZXlTaWcgPSByYXcubGVuZ3RoICsgJ3wnICsgcmF3LnNsaWNlKDAsIDEyMCkgKyAnfCcgKyByYXcuc2xpY2UoLTEyMCk7CiAgICAgIGlmIChrZXlTaWcgPT09IF9sYXN0QW5zRmlsZUtleSkgcmV0dXJuOwogICAgICBmb3JjZUdldE1ldGEoKTsKICAgICAgY29uc3Qga2V5ID0gQ1VSUkVOVF9LRVkgfHwgX3NMUy5nZXQoTFNfS0VZKTsKICAgICAgaWYgKCFrZXkpIHJldHVybjsKICAgICAgX2xhc3RBbnNGaWxlS2V5ID0ga2V5U2lnOwogICAgICBhZGRMb2coJ/Cfl53vuI8gUGjDoXQgaGnhu4duIGZpbGUgxJHDoXAgw6FuIGdldC1jcnQtYW5zLWZpbGUg4oCUIGfhu61pIHNlcnZlciBnaeG6o2kgbcOjLi4uJywgJ3dhcm4nKTsKICAgICAgY29uc3QgciA9IGF3YWl0IGdtUG9zdCgnL2Fuc2ZpbGUvZGVjb2RlJywgewogICAgICAgIGtleToga2V5LAogICAgICAgIGh3aWQ6IGdldEhXSUQoKSwKICAgICAgICBwYXlsb2FkOiByYXcsCiAgICAgICAgdXJsOiB1cmwsCiAgICAgICAgb2xtX3VzZXI6IGdldE9sbVVzZXJuYW1lKCksCiAgICAgICAgbWV0YTogewogICAgICAgICAgaWRfdXNlcjogU0VTU0lPTi5tZXRhLmlkX3VzZXIgfHwgZGV0ZWN0VXNlcklEKCksCiAgICAgICAgICBpZF9jYXRlOiBTRVNTSU9OLm1ldGEuaWRfY2F0ZSwKICAgICAgICAgIGlkX2NvdXJzZXdhcmU6IFNFU1NJT04ubWV0YS5pZF9jb3Vyc2V3YXJlLAogICAgICAgICAgc3ViamVjdF9uYW1lOiBTRVNTSU9OLm1ldGEuc3ViamVjdF9uYW1lIHx8IGRldGVjdFN1YmplY3ROYW1lKCkgfHwgJycsCiAgICAgICAgICBleGVyY2lzZV90aXRsZTogU0VTU0lPTi5tZXRhLmV4ZXJjaXNlX3RpdGxlIHx8IGRldGVjdEV4ZXJjaXNlVGl0bGUoKSB8fCAnJywKICAgICAgICAgIHN1YmplY3RfaWQ6IFNFU1NJT04ubWV0YS5zdWJqZWN0X2lkIHx8IG51bGwsCiAgICAgICAgICBvbG1fdXNlcjogZ2V0T2xtVXNlcm5hbWUoKQogICAgICAgIH0KICAgICAgfSk7CiAgICAgIGlmICghKHIuc3VjY2VzcyB8fCByLnZhbGlkKSkgewogICAgICAgIGFkZExvZygn4p2MIFNlcnZlciBnaeG6o2kgbcOjIGZpbGUgxJHDoXAgw6FuIGzhu5dpOiAnICsgKHIubWVzc2FnZSB8fCAna2jDtG5nIHLDtScpLCAnZXJyJyk7CiAgICAgICAgX2xhc3RBbnNGaWxlS2V5ID0gJyc7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIGNvbnN0IGl0ZW1zID0gci5xdWVzdGlvbnMgfHwgci5pdGVtcyB8fCBbXTsKICAgICAgaWYgKCFpdGVtcy5sZW5ndGgpIHsgYWRkTG9nKCfihLnvuI8gRmlsZSDEkcOhcCDDoW4ga2jDtG5nIGPDsyBjw6J1IGjhu6NwIGzhu4cuJywgJ3dhcm4nKTsgcmV0dXJuOyB9CiAgICAgIFNFU1NJT04uYW5zRmlsZUFuc3dlcnMgPSBpdGVtczsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCBzZWVuID0gbmV3IFNldCgoU0VTU0lPTi5iYW5rQW5zd2VycyB8fCBbXSkubWFwKGIgPT4gYiAmJiBiLnFpZCkpOwogICAgICAgIChpdGVtcyB8fCBbXSkuZm9yRWFjaChpdCA9PiB7IGlmIChpdCAmJiBpdC5xaWQgJiYgIXNlZW4uaGFzKGl0LnFpZCkpIFNFU1NJT04uYmFua0Fuc3dlcnMucHVzaChpdCk7IH0pOwogICAgICB9IGNhdGNoIChfKSB7fQogICAgICBjb25zdCBzZWMgPSByLmRlY29kZWRfc2VjdGlvbnMgfHwgci5zZWN0aW9ucyB8fCB7fTsKICAgICAgY29uc3Qgc2VjTGFiZWwgPSBPYmplY3Qua2V5cyhzZWMpLmZpbHRlcihrID0+IHNlY1trXSkubWFwKGsgPT4gay50b1VwcGVyQ2FzZSgpICsgJz0nICsgc2VjW2tdKS5qb2luKCcgwrcgJyk7CiAgICAgIHJlbmRlckFuc3dlcnNCbG9jayhpdGVtcywgJ/Cfl4LvuI8gZ2V0LWNydC1hbnMtZmlsZTogJyArIGl0ZW1zLmxlbmd0aCArICcgxJHDoXAgw6FuJyArIChzZWNMYWJlbCA/ICcgKCcgKyBzZWNMYWJlbCArICcpJyA6ICcnKSArICcg4oCUIHNlcnZlciBnaeG6o2kgbcOjIHhvbmcsIGhp4buDbiB0aOG7iyB4deG7kW5nIGTGsOG7m2khJyk7CiAgICAgIGFkZExvZygn4pyFIMSQw6Mgbmjhuq1uICcgKyBpdGVtcy5sZW5ndGggKyAnIMSRw6FwIMOhbiB04burIGdldC1jcnQtYW5zLWZpbGUnICsgKHNlY0xhYmVsID8gJyBbJyArIHNlY0xhYmVsICsgJ10nIDogJycpICsgJy4nLCAnb2snKTsKICAgICAgX3JlZnJlc2hRQ291bnQoKTsKICAgICAgX3N5bnRoZXNpemVRdWVzdGlvbnNGcm9tQW5zd2Vycyh0cnVlKTsKICAgIH0gY2F0Y2ggKGUpIHsKICAgICAgYWRkTG9nKCfimqDvuI8gWOG7rSBsw70gZmlsZSDEkcOhcCDDoW4gbOG7l2k6ICcgKyAoZSAmJiBlLm1lc3NhZ2UgfHwgZSksICd3YXJuJyk7CiAgICB9CiAgfQogIGZ1bmN0aW9uIF9jb2xsZWN0RG9tUXVlc3Rpb25JZHMoKSB7CiAgICBjb25zdCBpZHMgPSBbXTsKICAgIHRyeSB7CiAgICAgIGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJ1tkYXRhLXF1ZXN0aW9uLWlkXSxbZGF0YS1xaWRdLFtkYXRhLXF1ZXN0aW9uXSxbZGF0YS1pZC1xXSxbaWRePSJxdWVzdGlvbi0iXSxbaWRePSJxaWQtIl0sLnF1ZXN0aW9uLWl0ZW0sW2NsYXNzKj0icXVlc3Rpb24taXRlbSJdLFtjbGFzcyo9InEtaXRlbSJdJykuZm9yRWFjaChmdW5jdGlvbiAoZWwpIHsKICAgICAgICBmb3IgKGNvbnN0IGEgb2YgWyAnZGF0YS1xdWVzdGlvbi1pZCcsICdkYXRhLXFpZCcsICdkYXRhLXF1ZXN0aW9uJywgJ2RhdGEtaWQtcScgXSkgewogICAgICAgICAgY29uc3QgdiA9IGVsLmdldEF0dHJpYnV0ZSAmJiBlbC5nZXRBdHRyaWJ1dGUoYSk7CiAgICAgICAgICBpZiAodiAmJiAvXlxkezMsfSQvLnRlc3QodikpIHsgaWRzLnB1c2godik7IHJldHVybjsgfQogICAgICAgIH0KICAgICAgICBjb25zdCBtID0gKGVsLmlkIHx8ICcnKS5tYXRjaCgvKFxkezMsfSkvKTsKICAgICAgICBpZiAobSAmJiBpZHMuaW5kZXhPZihtWzFdKSA9PT0gLTEpIGlkcy5wdXNoKG1bMV0pOwogICAgICB9KTsKICAgIH0gY2F0Y2ggKF8pIHt9CiAgICByZXR1cm4gaWRzOwogIH0KICBmdW5jdGlvbiBfYmFua0l0ZW1Ub1JhdyhpdCkgewogICAgY29uc3QgYW5zID0gQXJyYXkuaXNBcnJheShpdCAmJiBpdC5hbnN3ZXJzKSA/IGl0LmFuc3dlcnMubWFwKFN0cmluZykgOiBbXTsKICAgIGlmICghYW5zLmxlbmd0aCkgcmV0dXJuIG51bGw7CiAgICBjb25zdCBsZXR0ZXJzID0gYW5zLm1hcChhID0+IGEudHJpbSgpLnRvVXBwZXJDYXNlKCkpLmZpbHRlcihhID0+IC9eW0EtR10kLy50ZXN0KGEpKTsKICAgIGlmIChsZXR0ZXJzLmxlbmd0aCAmJiBsZXR0ZXJzLmxlbmd0aCA9PT0gYW5zLmxlbmd0aCkgewogICAgICByZXR1cm4geyB0eXBlOiAxLCBhbnM6IGxldHRlcnMubWFwKGwgPT4gU3RyaW5nKCdBQkNERUZHJy5pbmRleE9mKGwpKSksIGNvdW50OiA0LCBzY29yZTogMSB9OwogICAgfQogICAgY29uc3QgdGYgPSBhbnMubWFwKGEgPT4gKC/EkcO6bmcvaS50ZXN0KGEpID8gJzEnIDogKC9zYWkvaS50ZXN0KGEpID8gJzAnIDogbnVsbCkpKS5maWx0ZXIodiA9PiB2ICE9PSBudWxsKTsKICAgIGlmICh0Zi5sZW5ndGggJiYgdGYubGVuZ3RoID09PSBhbnMubGVuZ3RoKSByZXR1cm4geyB0eXBlOiAxMywgYW5zOiB0ZiwgY291bnQ6IHRmLmxlbmd0aCwgc2NvcmU6IDEgfTsKICAgIHJldHVybiB7IHR5cGU6IDQsIGFuczogYW5zLCBjb3VudDogYW5zLmxlbmd0aCwgc2NvcmU6IDEsIGlzVGV4dDogdHJ1ZSB9OwogIH0KICBmdW5jdGlvbiBfc3ludGhlc2l6ZVF1ZXN0aW9uc0Zyb21BbnN3ZXJzKGF1dG8pIHsKICAgIHRyeSB7CiAgICAgIGlmIChTRVNTSU9OLnJhd19xdWVzdGlvbnMgJiYgU0VTU0lPTi5yYXdfcXVlc3Rpb25zLmxlbmd0aCA+IDApIHJldHVybiB0cnVlOwogICAgICBjb25zdCBzb3VyY2VzID0gW10uY29uY2F0KFNFU1NJT04uYW5zRmlsZUFuc3dlcnMgfHwgW10sIFNFU1NJT04uYmFua0Fuc3dlcnMgfHwgW10pOwogICAgICBpZiAoIXNvdXJjZXMubGVuZ3RoKSByZXR1cm4gZmFsc2U7CiAgICAgIGNvbnN0IGRvbUlkcyA9IF9jb2xsZWN0RG9tUXVlc3Rpb25JZHMoKTsKICAgICAgY29uc3Qgc3ludGggPSBbXTsKICAgICAgc291cmNlcy5mb3JFYWNoKGZ1bmN0aW9uIChpdCwgaWR4KSB7CiAgICAgICAgY29uc3QgcmF3ID0gaXQucmF3IHx8IF9iYW5rSXRlbVRvUmF3KGl0KTsKICAgICAgICBpZiAoIXJhdykgcmV0dXJuOwogICAgICAgIGNvbnN0IGlkID0gZG9tSWRzW2lkeF0gfHwgaXQucWlkIHx8IGl0LmlkIHx8ICgnc3luXycgKyAoaWR4ICsgMSkpOwogICAgICAgIGNvbnN0IHNjb3JlID0gKHR5cGVvZiByYXcuc2NvcmUgPT09ICdudW1iZXInKSA/IHJhdy5zY29yZSA6IDE7CiAgICAgICAgY29uc3QgcSA9IHsgaWQ6IFN0cmluZyhpZCksIHNjb3JlOiBzY29yZSB9OwogICAgICAgIGlmIChyYXcudHlwZSA9PT0gMTMpIHsKICAgICAgICAgIHEucV90eXBlID0gMTM7CiAgICAgICAgICBxLmpzb25fY29udGVudCA9IEpTT04uc3RyaW5naWZ5KHsgdHlwZTogJ29sbS1saXN0JywgbmFtZTogJ3RydWUtZmFsc2UnLCBjaGlsZHJlbjogKHJhdy5hbnMgfHwgW10pLm1hcCh2ID0+ICh7IGNvcnJlY3Q6IHYgPT09ICcxJyB8fCB2ID09PSAxIHx8IHYgPT09IHRydWUgfSkpIH0pOwogICAgICAgIH0gZWxzZSBpZiAocmF3LnR5cGUgPT09IDYpIHsKICAgICAgICAgIGNvbnN0IG4gPSBNYXRoLm1heCgyLCByYXcuY291bnQgfHwgKHJhdy5hbnMgfHwgW10pLmxlbmd0aCB8fCAyKTsKICAgICAgICAgIHEucV90eXBlID0gNjsKICAgICAgICAgIHEuanNvbl9jb250ZW50ID0gSlNPTi5zdHJpbmdpZnkoeyB0eXBlOiAnb2xtLWxpc3QnLCBuYW1lOiAnbGluay1saXN0JywgbGlzdFR5cGU6ICdtYXRjaGluZycsIGNoaWxkcmVuOiBBcnJheS5mcm9tKHsgbGVuZ3RoOiBuIH0sIGZ1bmN0aW9uIChfLCBvaSkgeyByZXR1cm4geyBpZHg6IG9pIH07IH0pIH0pOwogICAgICAgIH0gZWxzZSBpZiAocmF3LnR5cGUgPT09IDQpIHsKICAgICAgICAgIHEucV90eXBlID0gMTE7CiAgICAgICAgICBxLnR5cGUgPSAnZmlsbG1lLWlucHV0JzsKICAgICAgICAgIHEuY29udGVudCA9IFN0cmluZygocmF3LmFucyAmJiByYXcuYW5zWzBdKSB8fCAnJyk7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIGNvbnN0IGNvdW50ID0gTWF0aC5tYXgoNCwgcmF3LmNvdW50IHx8IDQpOwogICAgICAgICAgY29uc3QgY2hvc2VuID0gbmV3IFNldCgocmF3LmFucyB8fCBbXSkubWFwKGEgPT4gcGFyc2VJbnQoYSwgMTApKS5maWx0ZXIobiA9PiBOdW1iZXIuaXNGaW5pdGUobikpKTsKICAgICAgICAgIHEucV90eXBlID0gMTsKICAgICAgICAgIHEuanNvbl9jb250ZW50ID0gSlNPTi5zdHJpbmdpZnkoeyB0eXBlOiAnb2xtLWxpc3QnLCBuYW1lOiAnY2hvaWNlJywgY2hpbGRyZW46IEFycmF5LmZyb20oeyBsZW5ndGg6IGNvdW50IH0sIGZ1bmN0aW9uIChfLCBvaSkgeyByZXR1cm4geyBjb3JyZWN0OiBjaG9zZW4uaGFzKG9pKSB9OyB9KSB9KTsKICAgICAgICB9CiAgICAgICAgc3ludGgucHVzaChxKTsKICAgICAgfSk7CiAgICAgIGlmICghc3ludGgubGVuZ3RoKSByZXR1cm4gZmFsc2U7CiAgICAgIFNFU1NJT04ucmF3X3F1ZXN0aW9ucyA9IHN5bnRoOwogICAgICBpZiAoIWF1dG8pIGFkZExvZygn8J+nrCBE4buxbmcgJyArIHN5bnRoLmxlbmd0aCArICcgY8OidSB04burIMSRw6FwIMOhbiBraG8vc2VydmVyIMSR4buDIHPhurVuIHPDoG5nIG7hu5lwLicsICdvaycpOwogICAgICBfcmVmcmVzaFFDb3VudCgpOwogICAgICByZXR1cm4gdHJ1ZTsKICAgIH0gY2F0Y2ggKF8pIHsgcmV0dXJuIGZhbHNlOyB9CiAgfQogIGNvbnN0IEFQSV9LRVlXT1JEUyA9IFsgJ2dldC1xdWVzdGlvbi1vZi1pZHMnLCAnZ2V0LXF1ZXN0aW9uP2JlbG9uZ3M9MScsICdnZXQtcXVlc3Rpb24nLCAnZ2V0LXRlc3QnLCAnZ2V0LWNydC1hbnMtZmlsZScgXTsKICBmdW5jdGlvbiByZW5kZXJBbnN3ZXJzQmxvY2sobGlzdCwgaGVhZGVyTXNnKSB7CiAgICBjb25zdCBib3ggPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGwtbG9nYm94Iik7CiAgICBpZiAoIWJveCkgcmV0dXJuOwogICAgbGV0IGJsb2NrID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRsLWFucy1ibG9jayIpOwogICAgaWYgKCFibG9jaykgewogICAgICBibG9jayA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICBibG9jay5pZCA9ICJ0bC1hbnMtYmxvY2siOwogICAgICBibG9jay5zdHlsZS5jc3NUZXh0ID0gImJvcmRlci10b3A6MXB4IGRhc2hlZCByZ2JhKDI1NSwxOTMsNywuMzUpO21hcmdpbi10b3A6NHB4O3BhZGRpbmctdG9wOjRweCI7CiAgICAgIGJveC5hcHBlbmRDaGlsZChibG9jayk7CiAgICB9CiAgICBibG9jay5pbm5lckhUTUwgPSAiIjsKICAgIGlmIChoZWFkZXJNc2cpIGFkZExvZyhoZWFkZXJNc2csICJvayIpOwogICAgY29uc3QgaXRlbXMgPSBBcnJheS5pc0FycmF5KGxpc3QpID8gbGlzdCA6IFtdOwogICAgbGV0IGkgPSAwOwogICAgZnVuY3Rpb24gY2h1bmsoKSB7CiAgICAgIGNvbnN0IGZyYWcgPSBkb2N1bWVudC5jcmVhdGVEb2N1bWVudEZyYWdtZW50KCk7CiAgICAgIGZvciAobGV0IG4gPSAwOyBuIDwgMTAgJiYgaSA8IGl0ZW1zLmxlbmd0aDsgbisrLCBpKyspIHsKICAgICAgICBjb25zdCBxID0gaXRlbXNbaV07CiAgICAgICAgY29uc3QgZCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGQuY2xhc3NOYW1lID0gInRsLWxvZyBvayI7CiAgICAgICAgY29uc3QgYW5zID0gKHEuYW5zd2VycyB8fCBbXSkuam9pbigiIHwgIik7CiAgICAgICAgZC5pbm5lckhUTUwgPSAiPGI+USIgKyAocS5pbmRleCB8fCAoaSArIDEpKSArICI6PC9iPiAiICsgX2VzY0JhbmsoU3RyaW5nKHEudGl0bGUgfHwgIiIpLnN1YnN0cmluZygwLCA2MCkpICsgJyDihpIgPHNwYW4gc3R5bGU9ImNvbG9yOiNmZmMxMDc7Zm9udC13ZWlnaHQ6NzAwOyI+JyArIF9lc2NCYW5rKGFucykgKyAiPC9zcGFuPiI7CiAgICAgICAgZnJhZy5hcHBlbmRDaGlsZChkKTsKICAgICAgfQogICAgICBibG9jay5hcHBlbmRDaGlsZChmcmFnKTsKICAgICAgYm94LnNjcm9sbFRvcCA9IGJveC5zY3JvbGxIZWlnaHQ7CiAgICAgIGlmIChpIDwgaXRlbXMubGVuZ3RoKSBzZXRUaW1lb3V0KGNodW5rLCAyNSk7CiAgICAgIGVsc2UgYWRkTG9nKCLinIUgxJDDoyBoaeG7g24gdGjhu4sgIiArIGl0ZW1zLmxlbmd0aCArICIgxJHDoXAgw6FuIiwgIm9rIik7CiAgICB9CiAgICBjaHVuaygpOwogIH0KICBmdW5jdGlvbiBoYW5kbGVSYXdSZXNwb25zZSh1cmwsIHRleHQpIHsKICAgIGlmICghdXJsIHx8ICF0ZXh0KSByZXR1cm47CiAgICBpZiAodXJsLmluZGV4T2YoJ2dldC1jcnQtYW5zLWZpbGUnKSAhPT0gLTEpIHsgdHJ5IHsgaGFuZGxlQW5zRmlsZVJlc3BvbnNlKHVybCwgdGV4dCk7IH0gY2F0Y2ggKF8pIHt9IHJldHVybjsgfQogICAgY29uc3QgaXNRQXBpID0gQVBJX0tFWVdPUkRTLnNvbWUoayA9PiB1cmwuaW5jbHVkZXMoaykpOwogICAgY29uc3QgaXNMZWcgPSB1cmwuaW5jbHVkZXMoJ2dldC1xdWVzdGlvbicpIHx8IHVybC5pbmNsdWRlcygnZ2V0LXRlc3QnKSB8fCB0ZXh0LmluY2x1ZGVzKCdqc29uX2NvbnRlbnQnKSB8fCB0ZXh0LmluY2x1ZGVzKCcicXVlc3Rpb25zIicpOwogICAgaWYgKCFpc1FBcGkgJiYgIWlzTGVnKSByZXR1cm47CiAgICBsZXQgZGF0YTsKICAgIHRyeSB7CiAgICAgIGRhdGEgPSBKU09OLnBhcnNlKHRleHQpOwogICAgfSBjYXRjaCAoXykgewogICAgICByZXR1cm47CiAgICB9CiAgICBjb25zdCBxTGlzdCA9IGRhdGEucXVlc3Rpb25zIHx8IGRhdGEuZGF0YSB8fCAoQXJyYXkuaXNBcnJheShkYXRhKSA/IGRhdGEgOiBudWxsKTsKICAgIGlmICghQXJyYXkuaXNBcnJheShxTGlzdCkgfHwgcUxpc3QubGVuZ3RoID09PSAwKSByZXR1cm47CiAgICBTRVNTSU9OLnJhd19xdWVzdGlvbnMgPSBxTGlzdDsKICAgIGlmIChfYmFua0ZhbGxiYWNrVGltZXIpIHsgY2xlYXJUaW1lb3V0KF9iYW5rRmFsbGJhY2tUaW1lcik7IF9iYW5rRmFsbGJhY2tUaW1lciA9IG51bGw7IH0KICAgIF9iYW5rUmV0cnkgPSAwOwogICAgU0VTU0lPTi5tZXRhLmlkX3VzZXIgPSBxTGlzdFswXT8uaWRfdXNlciB8fCBkZXRlY3RVc2VySUQoKTsKICAgIFNFU1NJT04ubWV0YS5pZF9jb3Vyc2V3YXJlID0gZGF0YS5pZF9jb3Vyc2V3YXJlIHx8IG5ldyBVUkxTZWFyY2hQYXJhbXMod2luZG93LmxvY2F0aW9uLnNlYXJjaCkuZ2V0KCdpX2MnKTsKICAgIFNFU1NJT04ubWV0YS5pZF9jYXRlID0gZGF0YS5pZF9jYXRlIHx8IGRhdGEuaWRfZXhhbSB8fCByaXBJZEZyb21VcmwoKTsKICAgIFNFU1NJT04ubWV0YS5zdWJqZWN0X25hbWUgPSBkYXRhLnN1YmplY3RfbmFtZSB8fCBkYXRhLnN1YmplY3QgfHwgZGF0YS5jYXRlX25hbWUgfHwgZGV0ZWN0U3ViamVjdE5hbWUoKSB8fCBTRVNTSU9OLm1ldGEuc3ViamVjdF9uYW1lIHx8ICcnOwogICAgU0VTU0lPTi5tZXRhLmV4ZXJjaXNlX3RpdGxlID0gZGF0YS50aXRsZSB8fCBkYXRhLm5hbWUgfHwgZGF0YS5leGVyY2lzZV90aXRsZSB8fCBkZXRlY3RFeGVyY2lzZVRpdGxlKCkgfHwgU0VTU0lPTi5tZXRhLmV4ZXJjaXNlX3RpdGxlIHx8ICcnOwogICAgU0VTU0lPTi5tZXRhLnN1YmplY3RfaWQgPSBkYXRhLnN1YmplY3RfaWQgfHwgZGF0YS5jYXRlX2lkIHx8IFNFU1NJT04ubWV0YS5zdWJqZWN0X2lkIHx8IG51bGw7CiAgICByZWZyZXNoU3ViamVjdFRpdGxlVUkoKTsKICAgIFNFU1NJT04ubWV0YS5pZF9zY2hvb2wgPSBkZXRlY3RTY2hvb2xJRChkYXRhKTsKICAgIFNFU1NJT04ubWV0YS5pZF9ncm91cCA9IGRldGVjdEdyb3VwSUQoKTsKICAgIGNvbnN0IG10ID0gZG9jdW1lbnQucXVlcnlTZWxlY3RvcignbWV0YVtuYW1lPSJjc3JmLXRva2VuIl0nKTsKICAgIFNFU1NJT04ubWV0YS5jc3JmX3Rva2VuID0gbXQgPyBtdC5nZXRBdHRyaWJ1dGUoJ2NvbnRlbnQnKSA6IHdpbmRvdy5jc3JmX3Rva2VuIHx8ICcnOwogICAgaWYgKHdpbmRvdy50b3RhbF90aW1lKSBTRVNTSU9OLnZpZGVvX2xlbmd0aCA9IE1hdGguY2VpbCh3aW5kb3cudG90YWxfdGltZSk7IGVsc2UgaWYgKGRhdGEudG90YWxfdGltZSkgU0VTU0lPTi52aWRlb19sZW5ndGggPSBNYXRoLmNlaWwoZGF0YS50b3RhbF90aW1lKTsKICAgIGlmIChkYXRhLnR5cGUgPT0gNSB8fCB3aW5kb3cubG9jYXRpb24uaHJlZi5pbmNsdWRlcygndmlkZW8nKSB8fCBkb2N1bWVudC5xdWVyeVNlbGVjdG9yKCd2aWRlbyxpZnJhbWVbc3JjKj0ieW91dHViZSJdJykpIFNFU1NJT04uYXV0b19tb2RlID0gJ3ZpZGVvJzsgZWxzZSBpZiAoZGF0YS50eXBlX2V4YW0gPT0gMSB8fCBkYXRhLmlzX2V4YW0gPT0gMSB8fCB3aW5kb3cuaXNfZXhhbSA9PSAxIHx8IGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoJy50aW1lLWNvdW50ZG93biwjc3VibWl0LXRlc3QnKSkgU0VTU0lPTi5hdXRvX21vZGUgPSAnZXhhbSc7IGVsc2UgU0VTU0lPTi5hdXRvX21vZGUgPSAncHJhY3RpY2UnOwogICAgY29uc3QgcWNFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1xY291bnQnKTsKICAgIGNvbnN0IG1kRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtbW9kZS1kZXRlY3RlZCcpOwogICAgaWYgKHFjRWwpIHFjRWwudGV4dENvbnRlbnQgPSBxTGlzdC5sZW5ndGg7CiAgICBfcmVmcmVzaFFDb3VudCgpOwogICAgaWYgKG1kRWwpIHsKICAgICAgbWRFbC50ZXh0Q29udGVudCA9IFNFU1NJT04uYXV0b19tb2RlLnRvVXBwZXJDYXNlKCk7CiAgICAgIGNvbnN0IG1zID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLW1vZGVTZWxlY3QnKTsKICAgICAgaWYgKG1zKSBtcy52YWx1ZSA9IFNFU1NJT04uYXV0b19tb2RlOwogICAgfQogICAgYWRkTG9nKGDwn5OlIFske1NFU1NJT04ubWV0YS5zdWJqZWN0X25hbWUgfHwgJ23DtG4gPyd9XSR7U0VTU0lPTi5tZXRhLmV4ZXJjaXNlX3RpdGxlID8gJyDCtyAnICsgU0VTU0lPTi5tZXRhLmV4ZXJjaXNlX3RpdGxlIDogJyd9IOKAlCBu4bqhcCAke3FMaXN0Lmxlbmd0aH0gY8OidSBo4buPaSAoJHtTRVNTSU9OLmF1dG9fbW9kZX0pLi4uYCwgJ2luZm8nKTsKICAgIGNvbnN0IGtleSA9IENVUlJFTlRfS0VZIHx8IF9zTFMuZ2V0KExTX0tFWSk7CiAgICBpZiAoIWtleSkgewogICAgICBhZGRMb2coJ+KaoO+4jyBDaMawYSBjw7Mga2V5IOKAlCBraMO0bmcgdGjhu4MgZ2nhuqNpIG3Doy4nLCAnd2FybicpOwogICAgICByZXR1cm47CiAgICB9CiAgICBhZGRMb2coJ/CflIQgU2VydmVyIMSRYW5nIGdp4bqjaSAnICsgcUxpc3QubGVuZ3RoICsgJyBjw6J1Li4uJywgJ2luZm8nKTsKICAgIGdtUG9zdCgnL3Byb2Nlc3MnLCB7CiAgICAgIGtleToga2V5LAogICAgICBod2lkOiBnZXRIV0lEKCksCiAgICAgIHF1ZXN0aW9uczogcUxpc3QsCiAgICAgIG1ldGE6IHsKICAgICAgICBpZF91c2VyOiBTRVNTSU9OLm1ldGEuaWRfdXNlciB8fCBkZXRlY3RVc2VySUQoKSwKICAgICAgICBpZF9jYXRlOiBTRVNTSU9OLm1ldGEuaWRfY2F0ZSwKICAgICAgICBpZF9jb3Vyc2V3YXJlOiBTRVNTSU9OLm1ldGEuaWRfY291cnNld2FyZSwKICAgICAgICBzdWJqZWN0X25hbWU6IFNFU1NJT04ubWV0YS5zdWJqZWN0X25hbWUgfHwgJycsCiAgICAgICAgZXhlcmNpc2VfdGl0bGU6IFNFU1NJT04ubWV0YS5leGVyY2lzZV90aXRsZSB8fCAnJywKICAgICAgICBzdWJqZWN0X2lkOiBTRVNTSU9OLm1ldGEuc3ViamVjdF9pZCB8fCBudWxsLAogICAgICAgIG9sbV91c2VyOiBnZXRPbG1Vc2VybmFtZSgpCiAgICAgIH0KICAgIH0pLnRoZW4ocmVzdWx0ID0+IHsKICAgICAgaWYgKCEocmVzdWx0LnN1Y2Nlc3MgfHwgcmVzdWx0LnZhbGlkKSkgewogICAgICAgIGFkZExvZygn4p2MIFNlcnZlcjogJyArIChyZXN1bHQubWVzc2FnZSB8fCAnTOG7l2kgZ2nhuqNpIG3DoycpLCAnZXJyJyk7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIHJlbmRlckFuc3dlcnNCbG9jayhyZXN1bHQucXVlc3Rpb25zLCAiIik7IC8vIFt2MjldIGNo4buJIGdp4buvICLinIUgxJDDoyBoaeG7g24gdGjhu4sgTiDEkcOhcCDDoW4iCiAgICB9KS5jYXRjaChlID0+IGFkZExvZygn4p2MIEzhu5dpIGvhur90IG7hu5FpIHNlcnZlcjogJyArIGUubWVzc2FnZSwgJ2VycicpKTsKICB9CiAgKGZ1bmN0aW9uIGluamVjdFBhZ2VIb29rKCkgewogICAgdHJ5IHsKICAgICAgY29uc3QgY29kZSA9ICcoJyArIGZ1bmN0aW9uKCkgewogICAgICAgIGlmICh3aW5kb3cuX190bF9ob29rZWQpIHJldHVybjsKICAgICAgICB3aW5kb3cuX190bF9ob29rZWQgPSB0cnVlOwogICAgICAgIHdpbmRvdy5fX2t2X3FfYnVmID0gd2luZG93Ll9fa3ZfcV9idWYgfHwgW107CiAgICAgICAgLy8gW3YzMl0gQnJpZGdlIERPTSBkw7luZyBjaHVuZyBnaeG7r2EgcGFnZS13b3JsZCB2w6AgaXNvbGF0ZWQtd29ybGQgKGlPUyBGb2N1cyAvIFdLV2ViVmlldykKICAgICAgICBmdW5jdGlvbiBfX3RsX2JyaWRnZUVsKCkgewogICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgdmFyIGIgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnX190bF9xYnJpZGdlJyk7CiAgICAgICAgICAgIGlmICghYikgewogICAgICAgICAgICAgIGIgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgICAgICAgICAgICBiLmlkID0gJ19fdGxfcWJyaWRnZSc7CiAgICAgICAgICAgICAgYi5zdHlsZS5kaXNwbGF5ID0gJ25vbmUnOwogICAgICAgICAgICAgIChkb2N1bWVudC5ib2R5IHx8IGRvY3VtZW50LmRvY3VtZW50RWxlbWVudCkuYXBwZW5kQ2hpbGQoYik7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgcmV0dXJuIGI7CiAgICAgICAgICB9IGNhdGNoIChlKSB7IHJldHVybiBudWxsOyB9CiAgICAgICAgfQogICAgICAgIGZ1bmN0aW9uIF9fdGxfcHVzaCh1cmwsIHRleHQpIHsKICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgIHdpbmRvdy5fX2t2X3FfYnVmLnB1c2goewogICAgICAgICAgICAgIHVybDogdXJsLAogICAgICAgICAgICAgIHRleHQ6IHRleHQsCiAgICAgICAgICAgICAgdHM6IERhdGUubm93KCkKICAgICAgICAgICAgfSk7CiAgICAgICAgICAgIHZhciBiID0gX190bF9icmlkZ2VFbCgpOwogICAgICAgICAgICBpZiAoYikgewogICAgICAgICAgICAgIHRyeSB7IGIuc2V0QXR0cmlidXRlKCdkYXRhLWxhdGVzdCcsIEpTT04uc3RyaW5naWZ5KHsgdXJsOiB1cmwsIHRleHQ6IHRleHQgfSkpOyB9IGNhdGNoIChlKSB7fQogICAgICAgICAgICAgIHRyeSB7IGIuZGlzcGF0Y2hFdmVudChuZXcgQ3VzdG9tRXZlbnQoJ19fdGxfcWJyaWRnZScsIHsgZGV0YWlsOiB7IHVybDogdXJsLCB0ZXh0OiB0ZXh0IH0gfSkpOyB9IGNhdGNoIChlKSB7fQogICAgICAgICAgICB9CiAgICAgICAgICAgIHRyeSB7IGRvY3VtZW50LmRpc3BhdGNoRXZlbnQobmV3IEN1c3RvbUV2ZW50KCdfX2t2X3FkYXRhJywgeyBkZXRhaWw6IHsgdXJsOiB1cmwsIHRleHQ6IHRleHQgfSB9KSk7IH0gY2F0Y2ggKGUpIHt9CiAgICAgICAgICAgIHdpbmRvdy5kaXNwYXRjaEV2ZW50KG5ldyBDdXN0b21FdmVudCgnX19rdl9xZGF0YScsIHsKICAgICAgICAgICAgICBkZXRhaWw6IHsKICAgICAgICAgICAgICAgIHVybDogdXJsLAogICAgICAgICAgICAgICAgdGV4dDogdGV4dAogICAgICAgICAgICAgIH0KICAgICAgICAgICAgfSkpOwogICAgICAgICAgfSBjYXRjaCAoZSkge30KICAgICAgICB9CiAgICAgICAgZnVuY3Rpb24gX190bF9yZW1lbWJlcl9yZXEodXJsLCBtZXRob2QsIGJvZHkpIHsKICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgIHZhciB1ID0gKHVybCB8fCAnJykudG9Mb3dlckNhc2UoKTsKICAgICAgICAgICAgaWYgKHUuaW5kZXhPZignZ2V0LXF1ZXN0aW9uJykgIT09IC0xIHx8IHUuaW5kZXhPZignZ2V0LXRlc3QnKSAhPT0gLTEpIHsKICAgICAgICAgICAgICB3aW5kb3cuX190bF9sYXN0X3FyZXEgPSB7CiAgICAgICAgICAgICAgICB1cmw6IHVybCwKICAgICAgICAgICAgICAgIG1ldGhvZDogbWV0aG9kIHx8ICdHRVQnLAogICAgICAgICAgICAgICAgYm9keTogYm9keSB8fCBudWxsLAogICAgICAgICAgICAgICAgdHM6IERhdGUubm93KCkKICAgICAgICAgICAgICB9OwogICAgICAgICAgICB9CiAgICAgICAgICB9IGNhdGNoIChlKSB7fQogICAgICAgIH0KICAgICAgICB2YXIgX19vID0gWE1MSHR0cFJlcXVlc3QucHJvdG90eXBlLm9wZW47CiAgICAgICAgdmFyIF9fcyA9IFhNTEh0dHBSZXF1ZXN0LnByb3RvdHlwZS5zZW5kOwogICAgICAgIFhNTEh0dHBSZXF1ZXN0LnByb3RvdHlwZS5vcGVuID0gZnVuY3Rpb24obSwgdSkgewogICAgICAgICAgdGhpcy5fX3RsX3VybCA9IHU7CiAgICAgICAgICByZXR1cm4gX19vLmFwcGx5KHRoaXMsIGFyZ3VtZW50cyk7CiAgICAgICAgfTsKICAgICAgICBYTUxIdHRwUmVxdWVzdC5wcm90b3R5cGUuc2VuZCA9IGZ1bmN0aW9uKGJvZHkpIHsKICAgICAgICAgIHZhciBzZWxmID0gdGhpczsKICAgICAgICAgIF9fdGxfcmVtZW1iZXJfcmVxKHNlbGYuX190bF91cmwgfHwgJycsICdQT1NUJywgYm9keSB8fCBudWxsKTsKICAgICAgICAgIHRoaXMuYWRkRXZlbnRMaXN0ZW5lcignbG9hZCcsIGZ1bmN0aW9uKCkgewogICAgICAgICAgICBpZiAoc2VsZi5zdGF0dXMgPT09IDIwMCkgewogICAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgICBfX3RsX3B1c2goc2VsZi5yZXNwb25zZVVSTCB8fCBzZWxmLl9fdGxfdXJsIHx8ICcnLCBzZWxmLnJlc3BvbnNlVGV4dCB8fCAnJyk7CiAgICAgICAgICAgICAgfSBjYXRjaCAoZSkge30KICAgICAgICAgICAgfQogICAgICAgICAgfSk7CiAgICAgICAgICByZXR1cm4gX19zLmFwcGx5KHRoaXMsIGFyZ3VtZW50cyk7CiAgICAgICAgfTsKICAgICAgICB2YXIgX19mID0gd2luZG93LmZldGNoOwogICAgICAgIHdpbmRvdy5mZXRjaCA9IGZ1bmN0aW9uKCkgewogICAgICAgICAgdmFyIGFyZ3MgPSBhcmd1bWVudHM7CiAgICAgICAgICB2YXIgdXJsID0gdHlwZW9mIGFyZ3NbMF0gPT09ICdzdHJpbmcnID8gYXJnc1swXSA6IGFyZ3NbMF0gJiYgYXJnc1swXS51cmwgPyBhcmdzWzBdLnVybCA6ICcnOwogICAgICAgICAgdmFyIG9wdHMgPSBhcmdzWzFdIHx8ICh0eXBlb2YgYXJnc1swXSA9PT0gJ29iamVjdCcgPyBhcmdzWzBdIDogbnVsbCk7CiAgICAgICAgICBfX3RsX3JlbWVtYmVyX3JlcSh1cmwsIG9wdHMgJiYgb3B0cy5tZXRob2QgfHwgJ0dFVCcsIG9wdHMgJiYgb3B0cy5ib2R5IHx8IG51bGwpOwogICAgICAgICAgcmV0dXJuIF9fZi5hcHBseSh0aGlzLCBhcmdzKS50aGVuKGZ1bmN0aW9uKHJlcykgewogICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgIHZhciBjbCA9IHJlcy5jbG9uZSgpOwogICAgICAgICAgICAgIGNsLnRleHQoKS50aGVuKGZ1bmN0aW9uKHQpIHsKICAgICAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgICAgIF9fdGxfcHVzaCh1cmwgfHwgcmVzLnVybCB8fCAnJywgdCk7CiAgICAgICAgICAgICAgICB9IGNhdGNoIChlKSB7fQogICAgICAgICAgICAgIH0pOwogICAgICAgICAgICB9IGNhdGNoIChlKSB7fQogICAgICAgICAgICByZXR1cm4gcmVzOwogICAgICAgICAgfSk7CiAgICAgICAgfTsKICAgICAgICAvKiB2MTk6IGZvcmVpZ24taG9vayBwb2xsaW5nIGludGVydmFsIHJlbW92ZWQgKi8KICAgICAgfSArICcpKCk7JzsKICAgICAgY29uc3Qgc0VsID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc2NyaXB0Jyk7CiAgICAgIHNFbC50ZXh0Q29udGVudCA9IGNvZGU7CiAgICAgIChkb2N1bWVudC5oZWFkIHx8IGRvY3VtZW50LmRvY3VtZW50RWxlbWVudCkuYXBwZW5kQ2hpbGQoc0VsKTsKICAgICAgc0VsLnJlbW92ZSgpOwogICAgfSBjYXRjaCAoZSkgewogICAgICBjb25zb2xlLndhcm4oJ1tUTF0gaW5qZWN0IGZhaWwnLCBlKTsKICAgIH0KICB9KSgpOwogIGZ1bmN0aW9uIHNldHVwS1ZCdWZSZWFkZXIoKSB7CiAgICB0cnkgewogICAgICBjb25zdCBVVyA9IHR5cGVvZiB1bnNhZmVXaW5kb3cgIT09ICd1bmRlZmluZWQnID8gdW5zYWZlV2luZG93IDogd2luZG93OwogICAgICBsZXQgcHJvY2Vzc2VkID0gMDsKICAgICAgZnVuY3Rpb24gZHJhaW4oKSB7CiAgICAgICAgdHJ5IHsKICAgICAgICAgIGNvbnN0IGJ1ZiA9IFVXLl9fa3ZfcV9idWY7CiAgICAgICAgICBpZiAoIUFycmF5LmlzQXJyYXkoYnVmKSB8fCBidWYubGVuZ3RoIDw9IHByb2Nlc3NlZCkgcmV0dXJuOwogICAgICAgICAgZm9yIChsZXQgaSA9IHByb2Nlc3NlZDsgaSA8IGJ1Zi5sZW5ndGg7IGkrKykgewogICAgICAgICAgICBjb25zdCBpdCA9IGJ1ZltpXTsKICAgICAgICAgICAgaWYgKGl0ICYmIGl0LnVybCAmJiBpdC50ZXh0KSB7CiAgICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgIGhhbmRsZVJhd1Jlc3BvbnNlKGl0LnVybCwgaXQudGV4dCk7CiAgICAgICAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgICAgICAgfQogICAgICAgICAgfQogICAgICAgICAgcHJvY2Vzc2VkID0gYnVmLmxlbmd0aDsKICAgICAgICB9IGNhdGNoIChfKSB7fQogICAgICB9CiAgICAgIHRyeSB7CiAgICAgICAgVVcuYWRkRXZlbnRMaXN0ZW5lcignX19rdl9xZGF0YScsIGZ1bmN0aW9uKGV2dCkgewogICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgY29uc3QgZCA9IGV2dCAmJiBldnQuZGV0YWlsOwogICAgICAgICAgICBpZiAoZCAmJiBkLnVybCAmJiBkLnRleHQpIHsKICAgICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgaGFuZGxlUmF3UmVzcG9uc2UoZC51cmwsIGQudGV4dCk7CiAgICAgICAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgICAgICAgfQogICAgICAgICAgICBjb25zdCBidWYgPSBVVy5fX2t2X3FfYnVmOwogICAgICAgICAgICBpZiAoQXJyYXkuaXNBcnJheShidWYpKSBwcm9jZXNzZWQgPSBidWYubGVuZ3RoOwogICAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgICB9KTsKICAgICAgICAvLyBbdjMyXSBkb2N1bWVudCBsw6Agbm9kZSBET00gZMO5bmcgY2h1bmc6IG5o4bqtbiBldmVudCB04burIGPhuqMgcGFnZS13b3JsZCB0csOqbiBpT1MgRm9jdXMKICAgICAgICBkb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCdfX2t2X3FkYXRhJywgZnVuY3Rpb24oZXZ0KSB7CiAgICAgICAgICB0cnkgewogICAgICAgICAgICBjb25zdCBkID0gZXZ0ICYmIGV2dC5kZXRhaWw7CiAgICAgICAgICAgIGlmIChkICYmIGQudXJsICYmIGQudGV4dCkgewogICAgICAgICAgICAgIHRyeSB7IGhhbmRsZVJhd1Jlc3BvbnNlKGQudXJsLCBkLnRleHQpOyB9IGNhdGNoIChfKSB7fQogICAgICAgICAgICAgIGNvbnN0IGJ1ZiA9IFVXLl9fa3ZfcV9idWY7CiAgICAgICAgICAgICAgaWYgKEFycmF5LmlzQXJyYXkoYnVmKSkgcHJvY2Vzc2VkID0gYnVmLmxlbmd0aDsKICAgICAgICAgICAgfQogICAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgICB9KTsKICAgICAgICB2YXIgYnJpZGdlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnX190bF9xYnJpZGdlJyk7CiAgICAgICAgaWYgKGJyaWRnZUVsKSB7CiAgICAgICAgICBicmlkZ2VFbC5hZGRFdmVudExpc3RlbmVyKCdfX3RsX3FicmlkZ2UnLCBmdW5jdGlvbihldnQpIHsKICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICBjb25zdCBkID0gZXZ0ICYmIGV2dC5kZXRhaWw7CiAgICAgICAgICAgICAgaWYgKGQgJiYgZC51cmwgJiYgZC50ZXh0KSB7CiAgICAgICAgICAgICAgICB0cnkgeyBoYW5kbGVSYXdSZXNwb25zZShkLnVybCwgZC50ZXh0KTsgfSBjYXRjaCAoXykge30KICAgICAgICAgICAgICAgIGNvbnN0IGJ1ZiA9IFVXLl9fa3ZfcV9idWY7CiAgICAgICAgICAgICAgICBpZiAoQXJyYXkuaXNBcnJheShidWYpKSBwcm9jZXNzZWQgPSBidWYubGVuZ3RoOwogICAgICAgICAgICAgIH0KICAgICAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgICAgIH0pOwogICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgdmFyIGxhdGVzdCA9IGJyaWRnZUVsLmdldEF0dHJpYnV0ZSgnZGF0YS1sYXRlc3QnKTsKICAgICAgICAgICAgaWYgKGxhdGVzdCkgewogICAgICAgICAgICAgIHZhciBwID0gSlNPTi5wYXJzZShsYXRlc3QpOwogICAgICAgICAgICAgIGlmIChwICYmIHAudXJsICYmIHAudGV4dCkgaGFuZGxlUmF3UmVzcG9uc2UocC51cmwsIHAudGV4dCk7CiAgICAgICAgICAgIH0KICAgICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgfQogICAgICB9IGNhdGNoIChfKSB7fQogICAgICBkcmFpbigpOwogICAgICBpZiAoZG9jdW1lbnQucmVhZHlTdGF0ZSA9PT0gJ2xvYWRpbmcnKSBkb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCdET01Db250ZW50TG9hZGVkJywgZHJhaW4pOyBlbHNlIHNldFRpbWVvdXQoZHJhaW4sIDgwMCk7CiAgICAgIGNvbnN0IGl2ID0gc2V0SW50ZXJ2YWwoZHJhaW4sIDE1MCk7CiAgICAgIHNldFRpbWVvdXQoKCkgPT4gY2xlYXJJbnRlcnZhbChpdiksIDkwZTMpOwogICAgfSBjYXRjaCAoXykge30KICB9CiAgc2V0dXBLVkJ1ZlJlYWRlcigpOwogIC8qIHYxOTogX190bF9mb3JlaWduX2hvb2sgbGlzdGVuZXIgcmVtb3ZlZCAqLwovKiB2MTk6IGZvcmVpZ24gdXNlcnNjcmlwdC9ob29rIHNjYW4gcmVtb3ZlZCAqLwogIGFzeW5jIGZ1bmN0aW9uIHN0YXJ0dXAoKSB7CiAgICB0cnkgeyBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbSgnX3RsX3JlbW90ZV9sb2NrZWQnKTsgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oJ190bF9wb2lzb25lZCcpOyB9IGNhdGNoIChfKSB7fQogICAgY29uc3Qgc3RvcmVkS2V5ID0gX3NMUy5nZXQoTFNfS0VZKTsKICAgIGNvbnN0IHN0b3JlZEV4cCA9IF9zTFMuZ2V0KExTX0VYUCk7CiAgICBpZiAoc3RvcmVkS2V5KSB7CiAgICAgIGlmIChzdG9yZWRFeHApIHsKICAgICAgICBjb25zdCBleHBEYXRlID0gbmV3IERhdGUoc3RvcmVkRXhwKTsKICAgICAgICBjb25zdCBub3cgPSBuZXcgRGF0ZTsKICAgICAgICBpZiAoIWlzTmFOKGV4cERhdGUpICYmIGV4cERhdGUgPCBub3cpIHsKICAgICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKExTX0tFWSk7CiAgICAgICAgICBidWlsZExvY2tTY3JlZW4oJ+KPsCBLZXkgxJHDoyBo4bq/dCBo4bqhbiEgVnVpIGzDsm5nIG5o4bqtcCBrZXkgbeG7m2kuJyk7CiAgICAgICAgICByZXR1cm47CiAgICAgICAgfQogICAgICB9CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgY3VycmVudE9sbSA9IGdldE9sbVVzZXJuYW1lKCk7CiAgICAgICAgY29uc3QgciA9IGF3YWl0IGdtUG9zdCgnL3ZlcmlmeScsIHsKICAgICAgICAgIGtleTogc3RvcmVkS2V5LAogICAgICAgICAgaHdpZDogZ2V0SFdJRCgpLAogICAgICAgICAgb2xtX3VzZXI6IGN1cnJlbnRPbG0KICAgICAgICB9KTsKICAgICAgICBpZiAoci5zdWNjZXNzIHx8IHIudmFsaWQpIHsKICAgICAgICAgIGNvbnN0IHNlcnZlck9sbSA9IHIub2xtX3VzZXIgfHwgci5vbG1fYWNjb3VudCB8fCAnJzsKICAgICAgICAgIC8vIFt2MjddIEtow7RpIHBo4bulYzogbOG7h2NoIHTDoGkga2hv4bqjbiBPTE0gduG7m2kga2V5IMSRw6MgZ2hpbSAtPiB4b8OhIGtleSArIGtob8OhIHbhu4EgbcOgbiBow6xuaCBuaOG6rXAga2V5CiAgICAgICAgICBpZiAoc2VydmVyT2xtICYmIGN1cnJlbnRPbG0gJiYgY3VycmVudE9sbSAhPT0gJ0tob25nWGFjRGluaCcpIHsKICAgICAgICAgICAgaWYgKHNlcnZlck9sbS50b0xvd2VyQ2FzZSgpICE9PSBjdXJyZW50T2xtLnRvTG93ZXJDYXNlKCkpIHsKICAgICAgICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShMU19LRVkpOwogICAgICAgICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKExTX1RZUEUpOwogICAgICAgICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKExTX0VYUCk7CiAgICAgICAgICAgICAgaGFuZGxlT2xtTWlzbWF0Y2goc2VydmVyT2xtLCBjdXJyZW50T2xtKTsKICAgICAgICAgICAgICByZXR1cm47CiAgICAgICAgICAgIH0KICAgICAgICAgIH0KICAgICAgICAgIENVUlJFTlRfS0VZID0gc3RvcmVkS2V5OwogICAgICAgICAgS0VZX1NUQVRVUyA9IHsKICAgICAgICAgICAgdmFsaWQ6IHRydWUsCiAgICAgICAgICAgIHR5cGU6IHIudHlwZSwKICAgICAgICAgICAgZXhwaXJlc19hdDogci5leHBpcmVzX2F0CiAgICAgICAgICB9OwogICAgICAgICAgX3NMUy5zZXQoTFNfVFlQRSwgci50eXBlIHx8ICdUSFVPTkcnKTsKICAgICAgICAgIF9zTFMuc2V0KExTX0VYUCwgci5leHBpcmVzX2F0IHx8ICcnKTsKICAgICAgICAgIGNyZWF0ZVVJKCk7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIGlmIChyICYmIHIuX2h0dHBTdGF0dXMgPT09IDQwNCkgewogICAgICAgICAgICBfZW50ZXJCYW5Nb2RlKCdUaGnhur90IGLhu4svSVAgxJHDoyBi4buLIGFkbWluIGtob8OhLicpOwogICAgICAgICAgICByZXR1cm47CiAgICAgICAgICB9CiAgICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShMU19LRVkpOwogICAgICAgICAgYnVpbGRMb2NrU2NyZWVuKHIubWVzc2FnZSB8fCAnS2V5IGtow7RuZyBjw7JuIGjhu6NwIGzhu4chJyk7CiAgICAgICAgfQogICAgICB9IGNhdGNoIChfKSB7CiAgICAgICAgQ1VSUkVOVF9LRVkgPSBzdG9yZWRLZXk7CiAgICAgICAgS0VZX1NUQVRVUyA9IHsKICAgICAgICAgIHZhbGlkOiB0cnVlLAogICAgICAgICAgdHlwZTogX3NMUy5nZXQoTFNfVFlQRSksCiAgICAgICAgICBleHBpcmVzX2F0OiBzdG9yZWRFeHAKICAgICAgICB9OwogICAgICAgIGNyZWF0ZVVJKCk7CiAgICAgIH0KICAgIH0gZWxzZSB7CiAgICAgIGJ1aWxkTG9ja1NjcmVlbigpOwogICAgfQogICAgc2V0SW50ZXJ2YWwoYXN5bmMgKCkgPT4gewogICAgICBpZiAoIUNVUlJFTlRfS0VZKSByZXR1cm47CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgY3VycmVudE9sbSA9IGdldE9sbVVzZXJuYW1lKCk7CiAgICAgICAgY29uc3QgciA9IGF3YWl0IGdtUG9zdCgnL3ZlcmlmeScsIHsKICAgICAgICAgIGtleTogQ1VSUkVOVF9LRVksCiAgICAgICAgICBod2lkOiBnZXRIV0lEKCksCiAgICAgICAgICBvbG1fdXNlcjogY3VycmVudE9sbQogICAgICAgIH0pOwogICAgICAgIGlmICghKHIuc3VjY2VzcyB8fCByLnZhbGlkKSkgewogICAgICAgICAgaWYgKHIgJiYgci5faHR0cFN0YXR1cyA9PT0gNDA0KSB7CiAgICAgICAgICAgIF9lbnRlckJhbk1vZGUoJ1RoaeG6v3QgYuG7iy9JUCDEkcOjIGLhu4sgYWRtaW4ga2hvw6EuJyk7CiAgICAgICAgICAgIHJldHVybjsKICAgICAgICAgIH0KICAgICAgICAgIGNvbnN0IHBhbmVsRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtcGFuZWwnKTsKICAgICAgICAgIGNvbnN0IGZiID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLWZsb2F0QnRuJyk7CiAgICAgICAgICBpZiAocGFuZWxFbCkgcGFuZWxFbC5yZW1vdmUoKTsKICAgICAgICAgIGlmIChmYikgZmIucmVtb3ZlKCk7CiAgICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShMU19LRVkpOwogICAgICAgICAgQ1VSUkVOVF9LRVkgPSBudWxsOwogICAgICAgICAgX3NlY1Nlc3Npb24gPSB7CiAgICAgICAgICAgIHRva2VuOiBudWxsLAogICAgICAgICAgICBleHA6IDAsCiAgICAgICAgICAgIGZwSGFzaDogbnVsbCwKICAgICAgICAgICAgc2VxOiAxCiAgICAgICAgICB9OwogICAgICAgICAgQ1VSUkVOVF9ERVZJQ0UgPSAnJzsKICAgICAgICAgIHNob3dDdXN0b21Nb2RhbCh7CiAgICAgICAgICAgIGljb246ICfimqDvuI8nLAogICAgICAgICAgICB0aXRsZTogJ0tFWSDEkMODIELhu4ogS0jDk0EhJywKICAgICAgICAgICAgbGluZXM6IFsgci5tZXNzYWdlIHx8ICdLZXkgxJHDoyBi4buLIHbDtCBoaeG7h3UgaG/DoSEnLCAnVG9vbCBz4bq9IGLhu4sga2jDs2EgbmdheSBs4bqtcCB04bupYyEnIF0sCiAgICAgICAgICAgIG9uT2s6ICgpID0+IGJ1aWxkTG9ja1NjcmVlbihyLm1lc3NhZ2UgfHwgJ0tleSDEkcOjIGLhu4sgdsO0IGhp4buHdSBob8OhIScpCiAgICAgICAgICB9KTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgY29uc3Qgc2VydmVyT2xtID0gci5vbG1fdXNlciB8fCByLm9sbV9hY2NvdW50IHx8ICcnOwogICAgICAgICAgLy8gW3YyN10gS2jDtGkgcGjhu6VjOiBwb2xsIHBow6F0IGhp4buHbiBs4buHY2ggdMOgaSBraG/huqNuIE9MTSAtPiB4b8OhIGtleSArIGtob8OhIHbhu4EgbcOgbiBow6xuaCBuaOG6rXAga2V5CiAgICAgICAgICBpZiAoc2VydmVyT2xtICYmIGN1cnJlbnRPbG0gJiYgY3VycmVudE9sbSAhPT0gJ0tob25nWGFjRGluaCcpIHsKICAgICAgICAgICAgaWYgKHNlcnZlck9sbS50b0xvd2VyQ2FzZSgpICE9PSBjdXJyZW50T2xtLnRvTG93ZXJDYXNlKCkpIHsKICAgICAgICAgICAgICBoYW5kbGVPbG1NaXNtYXRjaChzZXJ2ZXJPbG0sIGN1cnJlbnRPbG0pOwogICAgICAgICAgICAgIHJldHVybjsKICAgICAgICAgICAgfQogICAgICAgICAgfQogICAgICAgIH0KICAgICAgfSBjYXRjaCAoXykge30KICAgIH0sIDUgKiA2MCAqIDFlMyk7CiAgfQogIGlmIChkb2N1bWVudC5yZWFkeVN0YXRlID09PSAnbG9hZGluZycpIHsKICAgIGRvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXIoJ0RPTUNvbnRlbnRMb2FkZWQnLCBzdGFydHVwKTsKICB9IGVsc2UgewogICAgc3RhcnR1cCgpOwogIH0KfSkoKTs=';

const CONNECTOR_MODULE_VERSION = parseInt(process.env.CONNECTOR_MODULE_VERSION || '34', 10); // [v34] auto bắt get-crt-ans-file + giải mã server + dựng câu từ kho cho Chuẩn bị 10 điểm // [v32b] iOS Focus + fix counter + giữ giao diện log cũ // [v30] phân loại lại Công nghệ/Công nghiệp (không lẫn GD KT&PL); ẩn log info màu xanh nước biển (giữ đáp án); tra kho đáp án mỗi 60s // [v29] dedupe kho đáp án, log gọn, practice đúng phút // [v28] đẩy đáp án xuống log tức thì (batch 10 câu/lần, drain 150ms, bank fallback 6s+thử lại); exam đặt số phút tuỳ chọn khi bấm Chuẩn bị; TXT kho đáp án đẹp, đáp án đậm, banner thuê key

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

// [HARDEN v20] Kiem tra syntax connector luc khoi dong; neu file connector.module.js
// hong syntax thi tu rollback sang EMBEDDED base64 (self-contained) de khong gui code lo.
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

// === [HARDEN v20] Kiem tra syntax moi payload JS truoc khi ma hoa/giao client ===
// Loi cu: fallback bridge dung literal backslash-n (\n thai bang ky tu xuong dong)
// o dau connector -> loader new Function() nem SyntaxError ("Invalid or unexpected
// token" / "invalid escape sequence") va hien "LOADER: khong load duoc".
// Tu nay moi payload deu duoc compile-check bang vm.Script (chi compile, khong chay);
// neu loi thi dung payload bao tri hop le + ghi log admin, KHONG bao gio ma hoa code hong.
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

    // === [v30] (2) Ẩn dòng log MÀU XANH NƯỚC BIỂN (info) trong ô log; GIỮ NGUYÊN câu hỏi + đáp án xanh lá (ok), warn, err ===
    out = out.replace(
      "  function addLog(msg, type = '') {\n    const box = document.getElementById('tl-logbox');",
      "  function addLog(msg, type = '') {\n    if (type === 'info') return; // [v30] ẩn thông tin màu xanh nước biển; đáp án (ok) vẫn hiển thị\n    const box = document.getElementById('tl-logbox');"
    );
    // === [v30] (3) Tra kho đáp án bài đang làm theo CHU KỲ 60 GIÂY (1 phút) ===
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
    // === [v33 iOS-FOCUS] Noi cac bo cong cau hoi cho Focus/WKWebView (isolated world) ===
    // Connector v32 da co DOM bridge #__tl_qbridge, nhung listener gan 1 lan luc khoi tao;
    // neu hook MAIN-world tao phan tu CHAM HON -> listener lo, mat event cau hoi -> iOS khong hien thi cau hoi.
    // (A) drain() doc lai data-latest cua bridge moi nhat moi nhay (150ms).
    // (B) Tu gan lai listener cho bridge khi phan tu xuat hien (poll 250ms, 20s), khong bo lo event.
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

  // Fallback fetch-based GM_xmlhttpRequest khi chạy trực tiếp (không qua wrapper)
  // [HARDEN v20] dung mang join('\n'): ky tu xuong dong THUC. Khong dung literal
  // backslash-n o dau statement — ky tu do lam new Function() tren loader nem
  // SyntaxError ("Invalid or unexpected token" / "invalid escape sequence").
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
  const safe = safeJs(built, 'connector-payload'); // [HARDEN v20] chan code hong truoc khi encrypt
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
  // [v6.7.1 iOS-FIX] KHONG gan GM_xmlhttpRequest/GM_addStyle/__GMFunc__ len window (anti-cheat quet Object.getOwnPropertyNames(window)).
  // Chỉ expose tên an toàn __tlFetchXhr/__tlFetchStyle (không khớp regex /^(GM_|__gm|__uscript)/).
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
  const safe = safeJs(full, 'bootstrap-connector'); // [HARDEN v20] chan code hong truoc khi encrypt/giao loader
  return safe.src;
}

function wrapConnectorWithBridge(src) {
  return src;
}

function buildLoaderSrc(req) {
  const origin = req.protocol + '://' + req.get('host');
  const SEC = SECRET, AP = API_PREFIX;
  const loaderSrc = `// ==UserScript==\n// @name         GOD MODE v10.1 Loader (iOS no-leak, fetch-based)\n// @namespace    godmode.v9\n// @version      10.0\n// @description  v10.2 iOS-first: retry 5 lan, KHONG dung cache offline (luon lay moi no-store); bridge cuc bo, KHONG gan window.GM_* (tranh anti-cheat GM leak)\n// @match        *://*.olm.vn/*\n// @match        *://olm.vn/*\n// @run-at       document-end\n// @grant        none\n// ==/UserScript==\n;(function(){\n  var SERVER_BASE = ${JSON.stringify(origin)};\n  var API_PREFIX = ${JSON.stringify(AP)};\n  var BOOT_KEY = ${JSON.stringify(BOOTSTRAP_PUBLIC_KEY)};\n  function _err(m){ try{ var d=document.createElement('div'); d.style.cssText='position:fixed;top:10px;left:10px;z-index:2147483647;background:#7f1d1d;color:#fff;padding:10px 14px;border-radius:8px;font:12px/1.5 monospace;max-width:85%'; d.textContent='GOD MODE: '+(m||''); (document.documentElement||document.body).appendChild(d); setTimeout(function(){try{d.remove();}catch(_){}},8000); }catch(_){} }\n  function _b64dec(b64){ var bin=atob(b64); var bytes=new Uint8Array(bin.length); for(var i=0;i<bin.length;i++) bytes[i]=bin.charCodeAt(i); return bytes.buffer; }\n  function _gmXhr(d){ d=d||{}; try{ var ctrl=(typeof AbortController!=='undefined')?new AbortController():null; var tmo=setTimeout(function(){if(ctrl)try{ctrl.abort();}catch(_){}}, d.timeout||20000); var opts={method:d.method||'GET',headers:d.headers||{}}; if(ctrl)opts.signal=ctrl.signal; if(d.data!==undefined&&d.data!==null)opts.body=d.data; fetch(d.url,opts).then(function(r){clearTimeout(tmo);return r.text().then(function(t){return{s:r.status,t:t};});}).then(function(o){if(d.onload)d.onload({status:o.s,responseText:o.t,response:o.t,readyState:4});}).catch(function(e){clearTimeout(tmo);if(d.onerror)d.onerror({error:String(e&&e.message||e)});}); }catch(e){ if(d.onerror)d.onerror({error:String(e&&e.message||e)}); } }\n  function _gmStyle(css){ try{ var st=document.createElement('style'); st.textContent=css; (document.head||document.documentElement).appendChild(st); }catch(_){} }\n  try{ /* [v6.7.1 iOS-FIX] bridge la bien cuc bo _gmXhr/_gmStyle; KHONG gan window.GM_* (chong GM leak) */ }catch(_){}\n  var __uw=(typeof unsafeWindow!=='undefined')?unsafeWindow:window;
  function _runConnector(src){ try{ (new Function('GM_xmlhttpRequest','GM_addStyle','unsafeWindow', src)).call(window, _gmXhr, _gmStyle, __uw); }catch(e){ _err('Connector loi: '+(e&&e.message||e)); } }\n  async function _boot(){ try{ localStorage.removeItem('_tl_boot_cache_v10'); }catch(_){}\n    try{\n      var r=null; for(var __t=0;__t<5;__t++){ try{ var __c=(typeof AbortController!=='undefined')?new AbortController():null; var __to=setTimeout(function(){try{__c&&__c.abort();}catch(_){}},25000); try{ r = await fetch(SERVER_BASE + API_PREFIX + '/bootstrap.js', {cache:'no-store',credentials:'omit',mode:'cors',signal:__c?__c.signal:undefined}); }finally{clearTimeout(__to);} if(r.ok) break; }catch(__e){} await new Promise(function(res){setTimeout(res,700*(__t+1));}); } if(!r){  _err('Khong ket noi server sau 5 lan thu (kiem tra mang/VPN, F5 lai).'); return; }\n      if(!r.ok){ if(r.status===404){ _err('Server dang bao tri / script tam khoa (admin da chan keo script).'); } else { _err('Khong keo duoc bootstrap (HTTP '+r.status+')'); } return; }\n      var j = await r.json();\n      if(!j||!j.ok||!j.payload){ _err('Bootstrap khong hop le.'); return; }\n      var enc = new TextEncoder();\n      var keyMat = await crypto.subtle.importKey('raw', enc.encode(BOOT_KEY), 'PBKDF2', false, ['deriveKey']);\n      var aesKey = await crypto.subtle.deriveKey({name:'PBKDF2', salt: enc.encode('tl-bootstrap-v8-salt'), iterations: 1000, hash:'SHA-256'}, keyMat, {name:'AES-GCM', length:256}, false, ['decrypt']);\n      var iv = _b64dec(j.payload.iv);\n      var data = _b64dec(j.payload.data);\n      var plain = await crypto.subtle.decrypt({name:'AES-GCM', iv: iv}, aesKey, data);\n      var src = new TextDecoder('utf-8').decode(plain); \n      _runConnector(src);\n    }catch(e){ _err('Loi giai ma bootstrap: '+(e&&e.message||e)); }\n  }\n  if(document.readyState==='loading'){ document.addEventListener('DOMContentLoaded', _boot); } else { _boot(); }\n})();\n`;
  const safeLoader = safeJs(loaderSrc, 'userscript-loader'); // [HARDEN v20] chan loader hong
  return safeLoader.src;
}

function buildKvPayloadSrc(req) {
  const origin = req.protocol + '://' + req.get('host');
  const connSrc = renderConnectorSrc(req);
  const connB64 = Buffer.from(connSrc, 'utf8').toString('base64');
  return `\n;(function(){\n  if (window.__tl_kv_payload_v82) return;\n  window.__tl_kv_payload_v82 = 1;\n  function __tlFail(msg){\n    console.error('[TL-KV]', msg);\n    try {\n      var d=document.createElement('div');\n      d.style.cssText='position:fixed;top:8px;left:8px;z-index:2147483647;background:#7f1d1d;color:#fff;padding:8px 12px;border-radius:8px;font:12px/1.4 monospace;max-width:85%;box-shadow:0 4px 12px rgba(0,0,0,.4)';\n      d.textContent='Tool loi: '+(msg||'');\n      (document.documentElement||document.body).appendChild(d);\n      setTimeout(function(){ try{d.remove();}catch(_){} }, 7000);\n    } catch(_){}\n  }\n  try {\n    \n    var __uw = (typeof unsafeWindow !== 'undefined') ? unsafeWindow : window;\n    var __gmStyle = (typeof GM_addStyle !== 'undefined') ? GM_addStyle : function(css){ try { var s=document.createElement('style'); s.textContent=css; (document.head||document.documentElement).appendChild(s); } catch(_){} };\n    var __gmXhr = (typeof GM_xmlhttpRequest !== 'undefined') ? GM_xmlhttpRequest : function(d){\n      d = d || {};\n      try {\n        var ctrl = (typeof AbortController !== 'undefined') ? new AbortController() : null;\n        var tmo = setTimeout(function(){ if (ctrl) try{ ctrl.abort(); }catch(_){} }, d.timeout || 20000);\n        var opts = { method: d.method || 'GET', headers: d.headers || {} };\n        if (ctrl) opts.signal = ctrl.signal;\n        if (d.data !== undefined && d.data !== null) opts.body = d.data;\n        fetch(d.url, opts).then(function(r){\n          clearTimeout(tmo);\n          return r.text().then(function(t){ return { s: r.status, t: t }; });\n        }).then(function(o){\n          if (d.onload) d.onload({ status: o.s, responseText: o.t, response: o.t, readyState: 4 });\n        }).catch(function(e){\n          clearTimeout(tmo);\n          if (d.onerror) d.onerror({ error: String(e && e.message || e) });\n        });\n      } catch(e){ if (d.onerror) d.onerror({ error: String(e && e.message || e) }); }\n    };\n    var __b64 = "${connB64}";\n    var bin = atob(__b64);\n    var bytes = new Uint8Array(bin.length);\n    for (var i=0;i<bin.length;i++) bytes[i]=bin.charCodeAt(i);\n    var __src = new TextDecoder('utf-8').decode(bytes);\n    \n    // [v6.7.1 iOS-FIX] KHONG gan window.GM_xmlhttpRequest / window.__GMFunc__ (tranh GM leak); __gmXhr/__gmStyle truyen qua tham so new Function.
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
// [v31] Cache RAM cho luồng tra kho đáp án (45s): giảm quét kho + ghi KV khi mạng yếu; phản hồi gần như tức thì.
const _lookupCache = new Map();
const LOOKUP_CACHE_TTL = 45e3;
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

// [v32] Chuẩn hoá số lượt tra cứu (hits): dữ liệu cũ có thể là chuỗi ("12"+"34" = "1234" -> tổng 215 tỷ). Luôn ép Number.
function numHits(v) {
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return Math.min(Math.floor(n), 1e7); // [v32] chặn số liệu cũ hỏng (chuỗi cộng dồn hàng trăm tỷ); lượt thật tăng dần nên không bao giờ cần > 10 triệu
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

// [v24] CHUẨN HOÁ TÊN MÔN: gộp biến thể chính tả / dấu (lý ↔ lí, hoa thường) về MỘT môn duy nhất,
//       đồng thời nhận diện môn khi script không gửi subject_name (suy từ tên bài tập / nội dung câu).
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
// [v30] Thứ tự ưu tiên khi suy từ NỘI DUNG bài: môn đặc thù (Công nghệ, Vật lý...) trước môn rộng (GD KT&PL)
const CANON_PRIORITY_KEYS = ['cong-nghe','vat-ly','hoa-hoc','sinh-hoc','tin-hoc','ngoai-ngu','toan','tieng-anh','ngu-van','lich-su','dia-ly','gd-kpl','the-duc','my-thuat','dia-phuong'];
function canonSubject(rawName, rawHint) {
  const nameFlat = normBankText(rawName);
  const scanRule = (flat, words) => words.some(w => { const wf = normBankText(w); return wf && (flat === wf || flat.indexOf(wf) !== -1); });
  // [v31] Ưu tiên tuyệt đối bài KT&PL: "Ý tưởng, cơ hội kinh doanh và các năng lực cần thiết của người kinh doanh"
  //       dù OLM gắn tên môn hiển thị nhầm (vd Công nghệ) vẫn xếp đúng cột Kinh tế Pháp luật.
  const _hintEarly = normBankText(rawHint);
  if (
    _hintEarly.indexOf('nang luc can thiet cua nguoi kinh doanh') !== -1 ||
    (_hintEarly.indexOf('co hoi kinh doanh') !== -1 && _hintEarly.indexOf('y tuong') !== -1)
  ) {
    return { key: 'gd-kpl', label: ruleLabelByKey('gd-kpl') };
  }
  // Bước 1: tên môn chính thức (rawName) — khớp rule nào lấy ngay, không để nội dung câu hỏi kéo sai môn
  if (nameFlat.trim()) {
    for (const r of SUBJECT_RULES) { if (scanRule(nameFlat, r.words)) return { key: r.key, label: r.label }; }
  }
  // Bước 2: suy từ nội dung/tên bài (hint): ưu tiên môn đặc thù trước; chỉ loại từ "kinh te" quá chung
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
// [v23] GỘP entry cùng TÊN MÔN: nhiều bài tập / nhiều id_cate của cùng 1 môn nằm CHUNG 1 thẻ môn
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
  // [v24] giữ canon môn sau gộp; hiển thị nhãn chuẩn (Địa lý thay vì Địa lý/Địa lí lẫn lộn)
  if (src.canon && !dst.canon) dst.canon = src.canon;
  if (dst.canon && ruleLabelByKey(dst.canon)) dst.subject = ruleLabelByKey(dst.canon);
  dst.cate = dst.cate || src.cate || null;
  dst.hits = numHits(dst.hits) + numHits(src.hits);
  dst.updated_at = Math.max(dst.updated_at || 0, src.updated_at || 0);
  if (src.olm_user && !dst.olm_user) dst.olm_user = src.olm_user;
  (src.sources || []).forEach(s => { if (dst.sources.indexOf(s) === -1) dst.sources.push(s); });
  return dst;
}
// [v29] Khử trùng bài tập trong kho: cùng courseware (mã bài OLM) / cùng key / cùng tên chuẩn hoá
//       gộp thành 1 bài — trước đây thẻ Địa lý hiển thị 2-3 bài giống nhau chỉ khác cách đặt tên.
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
// [v30] Phân loại lại kho cũ: bài Công nghệ/Công nghiệp bị xếp nhầm thẻ GD KT&PL được chuyển về thẻ Công nghệ
function reclassifyBank() {
  try {
    const CN_RE = /(cong nghe|cong nghiep|ky thuat|che tao|may moc|dien tu|nong nghiep)/;
    for (const e of answerBank.values()) {
      if (!e) continue;
      if (e.canon === 'gd-kpl') continue; // [v31] cột Kinh tế Pháp luật không bị kéo về Công nghệ
      const titles = (e.exercises || []).map(ex => ex.title || '').join(' ') + ' ' + (e.subject || '');
      const flatTitles = normBankText(titles);
      if (!CN_RE.test(flatTitles)) continue;
      // [v31] bài có từ vựng KT&PL (cơ hội kinh doanh / năng lực người kinh doanh) giữ nguyên ở gd-kpl
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
    let ex = (entry.exercises || []).find(x => x && x.key === exKey);
    if (!ex && meta.id_courseware) ex = (entry.exercises || []).find(x => x && x.courseware && String(x.courseware) === String(meta.id_courseware)) || null;
    if (!ex) {
      if (tombHas('exercise', exKey)) return; // [v24] bài tập đã xoá: không hồi sinh
      ex = { key: exKey, title: exerciseTitle || 'Bài tập chưa rõ tên', cate: meta.id_cate || null, courseware: meta.id_courseware || null, items: [], count: 0, hits: 0, created_at: Date.now(), updated_at: Date.now() };
      entry.exercises.push(ex);
    } else if (ex.key !== exKey) {
      ex.key = exKey; // gộp vào bài cùng courseware; cập nhật khoá theo tên mới nhất
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
    reclassifyBank();
    coalesceBankSubjects();
    _lookupCache.clear(); // [v31] đáp án mới vừa ingest: xoá cache tra kho cũ để lượt tra sau lấy đáp án mới
    entry.updated_at = Date.now();
    if (sourceKey && entry.sources.indexOf(maskKey(sourceKey)) === -1) entry.sources.push(maskKey(sourceKey));
  } catch (_) {}
}

// === [v31] SEED CỘT KINH TẾ PHÁP LUẬT ===
// Bài "Ý tưởng, cơ hội kinh doanh và các năng lực cần thiết của người kinh doanh" mặc định nằm đúng
// cột Kinh tế Pháp luật; các câu còn lại được server tự bổ sung khi người dùng giải bài.
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
        // [v24] Gán canon cho entry cũ chưa có; áp tombstones (xoá thật, không hồi sinh); gộp cùng môn về 1 thẻ
        for (const e of answerBank.values()) { if (!e.canon) { const c = canonSubject(e.subject, ''); e.canon = c.key || ''; } }
        applyBankTombstones();
        coalesceBankSubjects();
        reclassifyBank();
        coalesceBankSubjects();
        seedGdKplBank(); // [v31] đảm bảo cột Kinh tế Pháp luật có bài kinh doanh sau khi nạp KV
        scheduleBankSave();
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
      reclassifyBank();
      coalesceBankSubjects();
      seedGdKplBank(); // [v31] seed cột Kinh tế Pháp luật cho deploy ghi file (không KV)
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
bankFileLoad(); // [v25] nạp kho đáp án từ file dự phòng khi không có KV (giữ nguyên sau restart)
seedGdKplBank(); // [v31] seed cột Kinh tế Pháp luật ngay khi khởi động (kể cả khi KV chưa load xong)
sanitizeBankHits(); // [v32] ép kiểu hits toàn bộ kho khi khởi động

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
  if (/android|iphone|ipad|ipod|crios|fxios|focus|userscripts|harmonyos|webview|wv\)/.test(ua)) return true;
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
  if (ip && !isLoopbackIp(ip)) {
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

// === [v6.7.1 iOS-FIX] KHÔNG anti cho iOS thật (Safari/Chrome CriOS/Firefox FxiOS/Focus/Userscripts/WKWebView) ===
function isIosUa(uaHeader) {
  const ua = String(uaHeader || '').toLowerCase();
  if (!ua) return false;
  const looksIos = /iphone|ipad|ipod|crios|fxios|focus|userscripts|wkbrowser|mobile\/\d|applecoremedia/.test(ua);
  if (!looksIos) return false;
  // Chi loai bo tool tu dong hoa; khong loai bo trinh duyet that (ke ca Focus iOS)
  if (/webdriver|headlesschrome|puppeteer|playwright|selenium|electron|phantomjs|node-fetch|undici|curl|python-requests|python-httpx|python-urllib|aiohttp|okhttp|scrapy|bot\/|headless\b/i.test(ua)) return false;
  return true;
}
function isIosReq(req) { return !!(req && req.headers && isIosUa(req.headers['user-agent'])); }
function autoWhitelistIos(ip, hwid) {
  try {
    if (ip && !isLoopbackIp(ip)) {
      iosWhitelist.set('ip:' + ip, { by: 'auto-ios', t: Date.now(), reason: 'thiet bi that auto-whitelist v33 (iOS/Android)' });
      realIps.add(ip);
    }
    if (hwid) iosWhitelist.set('dev:' + String(hwid), { by: 'auto-ios', t: Date.now(), reason: 'thiet bi that auto-whitelist v33 (iOS/Android)' });
    kvSaveState();
  } catch (_) {}
}

function realMobileReq(req, hwid) {
  const ua = req && req.headers ? req.headers['user-agent'] : '';
  if (isIosUa(ua) || uaIsMobile(ua) || isMobileUA(ua)) return true;
  if (hwid && realDevices.has(String(hwid))) return true;
  if (hwid && iosWhitelist.has('dev:' + String(hwid))) return true;
  const ip = req ? getClientIp(req) : '';
  if (ip && (realIps.has(ip) || iosWhitelist.has('ip:' + String(ip)))) return true;
  return false;
}

// Tat ca cong chan dung helper nay: thiet bi that (whitelist / UA mobile) luon duoc di qua, khong ban nham
function reqBypass(req, hwid) {
  try {
    if (isIosReq(req)) return true;
    if (realMobileReq(req, hwid)) return true;
    const ip = req ? getClientIp(req) : '';
    if (ip && isIosWhitelisted(ip, hwid)) return true;
  } catch (_) {}
  return false;
}

function softUnbanReal(req, ip, hwid, reason) {
  if (!SMART_BAN) return false;
  if (!realMobileReq(req, hwid)) return false;
  if (ip && !isLoopbackIp(ip)) {
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
  // [v6.7.1 iOS-FIX] iOS thật: auto-whitelist + luôn cho qua, không bao giờ 403/khoá
  if (isIosReq(req)) { autoWhitelistIos(ip, hwid); softUnbanReal(req, ip, hwid, 'guard-ios:' + label); return false; }
  // [v33] Thiết bị Android/iOS thật luôn được đi qua: auto whitelist vĩnh viễn + gỡ ban mềm
  if (realMobileReq(req, hwid)) { autoWhitelistIos(ip, hwid); softUnbanReal(req, ip, hwid, 'guard-real:' + label); return false; }
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
  // [v6.7.1 iOS-FIX] iOS thật tuyệt đối không bị addBan (kể cả proxy 4G/CGNAT hay key sai nhiều lần)
  if (isIosUa(recentUaByIp.get(ip) || '')) {
    adminLog('ban-blocked-ios', { ip: ip, hwid: hwid, reason: reason, device: deviceName || '', note: 'iOS that: KHONG ban (iOS-FIX v6.7.1)' });
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

// [v31] Khóa đăng nhập admin BẬC THANG: sai 3 lần → khoá 10 phút; các đợt sai sau tăng dần 20 → 30 → 45 → 60 phút.
const ADMIN_LOCK_TIER_MIN = [10, 20, 30, 45, 60];
const adminLockMap = new Map(); // ip -> { fails, tier, lockedUntil }
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
  const hwidMw = req.headers['x-hwid'] || null;
  const isLoopback = ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';
  if (reqBypass(req, hwidMw)) {
    autoWhitelistIos(ip, hwidMw);
    softUnbanReal(req, ip, hwidMw, 'middleware-real-bypass-v33');
  } else if (isBanned(ip, hwidMw)) {
    if (!autoUnbanIfReal(ip, hwidMw, req.headers['user-agent'], 'middleware-banned-real-device') && !softUnbanReal(req, ip, hwidMw, 'middleware-banned-real-device-v17')) {
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

      // [v6.7.1 iOS-FIX] iOS Safari/Focus đôi khi không ký được (SubtleCrypto sandbox) → cho qua, auto whitelist
      if (isIosReq(req)) {
        autoWhitelistIos(ip, hwid);
        FAKE_REQ_COUNT--;
        unlockReal(req, ip, hwid, 'nosign-ios');
        return next();
      }

      // Ưu tiên 1: Thiết bị trong iOS whitelist — không bao giờ chặn
      if (isIosWhitelisted(ip, hwid)) {
        adminLog('nosign-whitelist', { ip: ip, path: req.path, ua: ua.slice(0, 80) });
        FAKE_REQ_COUNT--;
        return next();
      }

      // [v33] Thiet bi that (Android/iOS/Focus) khong ky duoc (SubtleCrypto sandbox) -> cho qua, whitelist
      if (reqBypass(req, hwid)) {
        autoWhitelistIos(ip, hwid);
        FAKE_REQ_COUNT--;
        unlockReal(req, ip, hwid, 'nosign-real-v33');
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
  // [v33] iOS/Android that (ke ca Focus/WKWebView): bo qua gioi han + khong bao gio bi auto-ban vi rate
  const hwidRl = req.headers['x-hwid'] || null;
  if (reqBypass(req, hwidRl)) { autoWhitelistIos(ip, hwidRl); return next(); }
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
  if (reqBypass(req, req.headers['x-hwid'] || null)) return next(); // [v33] iOS/Android that (4G/Wi-Fi CGNAT) không bị chặn proxy/DC
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
  // [v32] iOS thật (Focus/Safari/Chrome iOS/Firefox iOS) không bị coi là bot khi không có dấu hiệu automation
  if (/iphone|ipad|ipod|crios|fxios|focus\//.test(ua) && !/webdriver|headless|puppeteer|playwright|selenium|electron|phantomjs/i.test(ua)) return false;
  if (BAD_UA.some(k => ua.includes(k))) return true;
  if (EMU_MARKERS.some(k => ua.includes(k))) return true;
  return false;
}

function isMobileUA(uaHeader) {
  // [v26] Rộng hơn cho cổng BLOCK_VM_SCRIPT: bao gồm WebView/wv và hãng Trung Quốc
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
  // [v33] iPad desktop-mode bao UA "Mac OS X" nhưng có cảm ứng -> coi là iOS thật, không phạt
  const isIOS = /iphone|ipad|ipod/i.test(ua) || (/macintosh|mac os x/i.test(ua) && _touchPts > 0);
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
  if (false && isIOS && vendor && vendor.length > 0 && !vendor.includes('apple')) {
    // [v32] bỏ phạt vendor iOS: Focus/WKWebView nhiều khi không báo vendor Apple, tránh false positive
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
    // [v33] Thiet bị cảm ứng (tablet hybrid / desktop-mode iPad) -> chấp nhận mềm, không 403/ban
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
  if (cores && cores < 2 && !isIOS) { // [v32] WKWebView iOS hay báo hardwareConcurrency=1, không phạt
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

// === [v34] Giải mã file đáp án OLM get-crt-ans-file (fc / tf / dg / nrq; chấp nhận alias ff / rnq) ===
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
  // (1) JSON thô {fc,tf,dg,nrq}
  let obj = tryParse(str);
  if (accept(obj)) return normalizeAnsFile(obj);
  // (2) JSON bọc wrapper {data|content|file|payload|...: <chuỗi b64 hoặc object>}
  if (obj && typeof obj === 'object') {
    for (const k of [ 'data', 'content', 'answer_file', 'file', 'payload', 'ans', 'answers', 'result', 'body' ]) {
      const v = obj[k];
      if (typeof v === 'string' && v.trim()) { const inner = decodeAnsFilePayload(v); if (inner) return inner; }
      else if (v && typeof v === 'object') { const inner = decodeAnsFilePayload(JSON.stringify(v)); if (inner) return inner; }
    }
  }
  // (3) XOR khoá OLM (SECRET_KEY='1047823200') rồi mới base64 — cùng cơ chế mã câu hỏi
  const xorRaw = decryptOLM(str);
  if (xorRaw) { const jx = tryParse(xorRaw); if (accept(jx)) return normalizeAnsFile(jx); }
  // (4) base64 UTF-8 thuần -> JSON
  try {
    const b64dec = Buffer.from(str, 'base64').toString('utf8');
    const j2 = tryParse(b64dec);
    if (accept(j2)) return normalizeAnsFile(j2);
    const xorB64 = decryptOLM(b64dec);
    if (xorB64) { const j3 = tryParse(xorB64); if (accept(j3)) return normalizeAnsFile(j3); }
  } catch (_) {}
  // (5) quét token base64 dài lẫn trong HTML/text
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
  // [v29] Practice (Luyện tập) cũng dùng đúng số phút người chọn ở ô thời gian;
  //       trước đây totalPackages * 15 giây nên bài 15 câu chỉ hiện ~3-4 phút dù đặt 15 phút.
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

// [v31] Tối ưu độ trễ mạng: cache kết quả verify KeyVault trong RAM (ok 120s / lỗi tạm 15s).
//       Mỗi bài /process, /fire, /verify, /heartbeat không gọi lại HTTPS tới KeyVault (Render hay cold-start ~30-60s).
const _kvVerifyCache = new Map();
const KV_OK_TTL = 120e3;
const KV_FAIL_TTL = 15e3;
function proxyVerify(key, hwid, olmUser) {
  const ck = String(key || '') + '|' + String(hwid || '') + '|' + String(olmUser || '');
  const now = Date.now();
  const hit = _kvVerifyCache.get(ck);
  if (hit && hit.exp > now) return Promise.resolve(hit.res);
  return _proxyVerifyRaw(key, hwid, olmUser).then(res => {
    try {
      const ttl = res && res.success ? KV_OK_TTL : KV_FAIL_TTL;
      _kvVerifyCache.set(ck, { res: res, exp: now + ttl });
    } catch (_) {}
    return res;
  });
}
function _proxyVerifyRaw(key, hwid, olmUser) {
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
      timeout: 10e3
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
  const _hwBoot = req.headers['x-hwid'] || null;
  if (reqBypass(req, _hwBoot)) autoWhitelistIos(ip, _hwBoot); // [v33] real auto whitelist
  unlockReal(req, ip, _hwBoot, 'bootstrap.js');
  if (guardBanned(req, res, ip, _hwBoot, 'bootstrap.js')) return;
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
  const pBoot = reqBypass(req, _hwBoot) ? { risk: 'low' } : await checkProxyIp(ip); // [v33] bo qua lookup proxy ngoai cho thiet bi that -> nhanh, khong timeout cold start
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
  if (BLOCK_VM_SCRIPT && !isMobileUA(req.headers['user-agent']) && !reqBypass(req, _hwBoot)) { // [v33] thiet bi that luon duoc keo code
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
    const bootChk = compileCheckJs(src, 'bootstrap-served'); // [HARDEN v20] chan cuoi cung truoc encrypt
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
  if (reqBypass(req, _hwKvp)) autoWhitelistIos(ip, _hwKvp);
  unlockReal(req, ip, _hwKvp, 'kv-payload.js');
  if (guardBanned(req, res, ip, _hwKvp, 'kv-payload.js')) return;
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
    addBan(ip, null, 'IP datacenter/proxy keo kv-payload.js (HARD_DC_BAN v11) — ' + (pKvp.org || ''), '');
    adminLog('dc-ban', {
      ip: ip,
      path: 'kv-payload.js',
      org: pKvp.org || ''
    });
    return res.status(404).send('/* not found */');
  }
  if (BLOCK_VM_SCRIPT && !isMobileUA(req.headers['user-agent']) && !reqBypass(req, _hwKvp)) { // [v33] thiet bi that luon duoc keo code
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
  const _hwLdr = req.headers['x-hwid'] || null;
  if (reqBypass(req, _hwLdr)) autoWhitelistIos(ip, _hwLdr);
  unlockReal(req, ip, _hwLdr, 'loader.user.js');
  if (guardBanned(req, res, ip, _hwLdr, 'loader.user.js')) return;
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
    addBan(ip, null, 'IP datacenter/proxy keo loader.user.js (HARD_DC_BAN v11) — ' + (pLdr.org || ''), '');
    adminLog('dc-ban', {
      ip: ip,
      path: 'loader.user.js',
      org: pLdr.org || ''
    });
    return res.status(404).send('// not found');
  }
  if (BLOCK_VM_SCRIPT && !isMobileUA(req.headers['user-agent']) && !reqBypass(req, _hwLdr)) { // [v33] thiet bi that luon duoc keo code
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
    if (recordKeyFail(ip) && AUTO_BAN && !isLoopbackIp(ip) && !reqBypass(req, hwid)) addBan(ip, null, 'brute-force key (>=10 sai/10 phut)', '');
    else if (reqBypass(req, hwid)) autoWhitelistIos(ip, hwid);
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
  if (isIosReq(req)) autoWhitelistIos(ip, hwid);
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
  if (!reqBypass(req, hwid) && !rateLimit('attest:' + ip + '|' + (hwid || ''), 30, 6e4)) return res.status(429).json({
    success: false,
    message: 'Quá nhiều lần xác thực'
  });
  const v = validateDevice(fp, device, req.headers['user-agent']);
  if (!v.ok) {
    if (isIosReq(req) || realMobileReq(req, hwid)) {
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
  const p = reqBypass(req, hwid) ? { risk: 'low' } : await checkProxyIp(ip);
  if (p.risk === 'high') {
    if (!reqBypass(req, hwid) && HARD_DC_BAN && p.isDC && p.isVPN && !(uaIsMobile(req.headers['user-agent']) || SMART_BAN && isRealMobileDevice(ip, hwid, req.headers['user-agent']))) {
      if (reqBypass(req, hwid)) { adminLog('proxy-warn-real', { ip: ip, hwid: hwid, device: v.deviceName, note: 'thiet bi that bo qua proxy-ban v33' }); } else addBan(ip, hwid, 'proxy/VPN/datacenter + IP datacenter (HARD_DC_BAN)', v.deviceName);
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
  unlockReal(req, ip, req.body && req.body.hwid || null, 'ansfile');
  if (guardBanned(req, res, ip, req.body && req.body.hwid || null, 'api')) return;
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
  unlockReal(req, ip, hwid0, 'answers-lookup');
  if (guardBanned(req, res, ip, hwid0, 'bank')) return;
  if (!requireSession(req, res)) return;
  if (!reqBypass(req, hwid0) && !rateLimit('bank:' + ip + '|' + (hwid0 || ''), 30, 6e4)) return res.status(429).json({ success: false, message: 'Quá nhiều yêu cầu tra kho (IP)' });
  const { key: key, hwid: hwid, cate: cate, courseware: courseware, olm_user: olm_user, subject: subject, exercise_title: exercise_title } = req.body || {};
  if (!key) return res.status(401).json({ success: false, message: 'Missing key' });
  const kv = await proxyVerify(key, hwid);
  if (!kv.success) return res.status(401).json({ success: false, message: kv.message || 'Invalid key' });
  const c = safeStr(cate, 80);
  const cw = safeStr(courseware, 80);
  const subj = safeStr(subject, 120);
  const exTitle = safeStr(exercise_title, 300);
  // [v31] Cache tra kho 45s: mạng yếu/3G trả đáp án ngay, không quét lại kho, không ghi KV mỗi request.
  const _lkKey = [c, subj, cw, exTitle].join('|');
  const _lkHit = _lookupCache.get(_lkKey);
  if (_lkHit && _lkHit.exp > Date.now()) return res.json(rotateSession(req, Object.assign({}, _lkHit.body)));
  let entry = null;
  if (c) entry = answerBank.get(c) || null;
  // [v23] Sau gộp theo tên môn: entry có thể không còn giữ key = id_cate → dò thêm trong cate của từng bài tập
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
  if (targetEx) { targetEx.hits = numHits(targetEx.hits) + 1; targetEx.last_lookup_at = Date.now(); }
  // [v31] Tra kho chỉ ĐỌC: không scheduleBankSave (tránh ghi KV 3.5s/lượt làm chậm khi nhiều người dùng)
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
  unlockReal(req, ip, req.body && req.body.hwid || null, 'route');
  if (guardBanned(req, res, ip, req.body && req.body.hwid || null, 'api')) return;
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
  const _hbHwid = req.body && req.body.hwid || null;
  if (!reqBypass(req, _hbHwid) && !rateLimit('hb:' + ip + '|' + _hbHwid, 30, 6e4)) return res.status(429).json({
    success: false,
    message: 'Quá nhiều yêu cầu'
  });
  if (reqBypass(req, _hbHwid)) autoWhitelistIos(ip, _hbHwid);
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
  const p = reqBypass(req, hwid) ? { risk: 'low' } : await checkProxyIp(ip);
  if (p.risk === 'high') {
    if (!reqBypass(req, hwid) && HARD_DC_BAN && p.isDC && p.isVPN && !(uaIsMobile(req.headers['user-agent']) || SMART_BAN && isRealMobileDevice(ip, hwid, req.headers['user-agent']))) {
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

  // === [v33] Thiet bi that / whitelist: bo qua lock-report, tra ok ngay de script khong bi treo ===
  if (reqBypass(req, hwid) || isIosWhitelisted(ip, hwid)) {
    autoWhitelistIos(ip, hwid);
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
  // [v31] Hết hạn khóa → reset bộ đếm fail nhưng GIỮ bậc tier để các đợt sai sau tăng dần thời gian khóa.
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
  // [v31] Sai tài khoản/mật khẩu: 3 lần liên tiếp → khoá 10 phút; sau khi hết khoá mà vẫn sai thì tăng dần 20 → 30 → 45 → 60 phút.
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