'use strict';

const express = require('express');

const cheerio = require('cheerio');

const cors = require('cors');

const https = require('https');

const http = require('http');

const crypto = require('crypto');

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

const PAYLOAD_MODULE_SRC = `\nvar SESSION=ctx.SESSION, addLog=ctx.addLog, forceGetMeta=ctx.forceGetMeta;\nvar SECRET_KEY_CS='1047823200';\nfunction decryptOLM_CS(base64Str){if(!base64Str)return null;try{var raw=atob(base64Str);var dec='';for(var i=0;i<raw.length;i++)dec+=String.fromCharCode(raw.charCodeAt(i)^SECRET_KEY_CS.charCodeAt(i%SECRET_KEY_CS.length));return decodeURIComponent(escape(dec));}catch(e){return null;}}\nfunction buildParamsCS(sq){var count=sq.count||4;if(sq.type===6){var orderArr=Array.from(Array(Math.max(count,15)),function(_,k){return k;});return {js:'',order_l:orderArr,order_r:orderArr};}return {js:'',order:Array.from(Array(count),function(_,k){return k;})};}\nfunction findCorrectInfoCS(node){var results=[];function traverse(n){if(!n)return;var subQ_ID=n.id||n._id||(n.props?n.props.id:null);if((n.type==='fillme-input'&&n.content)||(typeof n.content==='string'&&n.content.includes('data-accept='))){if(n.content.includes('data-accept=')){var regex=/data-accept="([^"]+)"/g;var match;while((match=regex.exec(n.content))!==null)results.push({type:4,ans:[match[1]],count:1,skill:n.id_skill,subId:subQ_ID||('raw_'+Math.random()),isText:true});}else{results.push({type:4,ans:[n.content],count:1,skill:n.id_skill,subId:subQ_ID,isText:true});}return;}if(n.type==='olm-list'||(Array.isArray(n.children)&&n.children.length>0)){var options=n.children;if(n.name==='true-false'||n.listType==='true-false'){results.push({type:13,ans:options.map(function(o){return (o.correct==true||o.correct==='true'||o.correct==1)?'1':'0';}),count:options.length,skill:n.id_skill,subId:subQ_ID});return;}if(n.name==='link-list'||n.listType==='matching'){results.push({type:6,ans:options.map(function(_,idx){return idx.toString();}),count:options.length,skill:n.id_skill,subId:subQ_ID});return;}if(options.some(function(c){return c.correct!==undefined;})){var trueIndex=options.findIndex(function(o){return o.correct==true||o.correct==='true'||o.correct==1;});results.push({type:1,ans:[(trueIndex===-1?0:trueIndex).toString()],count:options.length,skill:n.id_skill,subId:subQ_ID});return;}}if(Array.isArray(n.children))n.children.forEach(traverse);else if(Array.isArray(n.questions))n.questions.forEach(traverse);else if(Array.isArray(n.items))n.items.forEach(traverse);else if(Array.isArray(n.list))n.list.forEach(traverse);else if(n.root)traverse(n.root);}var contentToParse=node.json_content||node.content;if(typeof contentToParse==='string'&&!contentToParse.trim().startsWith('{')&&!contentToParse.trim().startsWith('[')){var decoded=decryptOLM_CS(contentToParse);if(decoded)contentToParse=decoded;}try{traverse(typeof contentToParse==='string'?JSON.parse(contentToParse):contentToParse);}catch(_){traverse(node);}if(results.length===0)results.push({type:1,ans:['0'],count:4,skill:null,subId:null});return results;}\nreturn async function(){\nforceGetMeta();\nif(!SESSION.meta.id_user||!SESSION.meta.id_cate){addLog('❌ Thiếu ID user/cate: user='+(SESSION.meta.id_user||'?')+' cate='+(SESSION.meta.id_cate||'?'),'err');return false;}\nvar totalPackages=SESSION.raw_questions.length;\nif(totalPackages===0){addLog('❌ Chưa có câu hỏi để nộp!','err');return false;}\nvar timeInput=document.getElementById('tl-god-time');\nvar timeStr=timeInput?timeInput.value.toString().trim():'10.00';\nvar tp=timeStr.split('.');\nvar userMins=parseInt(tp[0])||0;\nvar uss=tp[1]||'0';if(uss.length===1)uss+='0';\nvar userSecs=parseInt(uss.substring(0,2));\nvar calcSeconds=(userMins*60)+userSecs;\nif(calcSeconds<30)calcSeconds=120;\nvar modeSel=document.getElementById('tl-modeSelect');\nvar mode=modeSel?modeSel.value:'practice';\nvar isExam=mode==='exam',isVideo=mode==='video';\nvar now=Math.floor(Date.now()/1000);\nvar totalSeconds,timeInit;\nif(isVideo||isExam){totalSeconds=calcSeconds;timeInit=now-totalSeconds;}else{totalSeconds=totalPackages*15;timeInit=now-totalSeconds;}\nvar params=new URLSearchParams();\nvar fakeLog=[];\nvar max_tn_score=0,tn_score_calc=0,tl_max_calc=0;\nSESSION.raw_questions.forEach(function(q,i){\nvar subQuestions=findCorrectInfoCS(q);\nvar sub_count=subQuestions.length;\nvar is_tl=(q.q_type==18||q.type==18||q.q_type==11);\nvar final_score=sub_count;\nif(q.score!==undefined&&q.score!==null&&q.score!=='')final_score=parseFloat(q.score);\nelse if(q.point!==undefined&&q.point!==null&&q.point!=='')final_score=parseFloat(q.point);\nif(!isVideo){params.append('quiz_list[]',q.id||q._id);params.append('score_list['+(q.id||q._id)+']',final_score);}\nvar skillIDs=[].concat(Array.from(new Set(subQuestions.map(function(sq){return sq.skill;}).filter(function(s){return s!=null;}))));\nif(!isVideo)skillIDs.forEach(function(s){params.append('correct_skill[]',s);});\nif(isVideo||isExam){\nif(is_tl&&isExam){tl_max_calc+=final_score;fakeLog.push({answer:JSON.stringify(['Học sinh đã làm phần tự luận trên máy.']),label:[''],params:'{"js":"","order":[0]}',correct_skill:[],wrong_skill:[],type:[18],result:[0],idq:parseInt(q.id||q._id),score:final_score,chk:0});}\nelse{\nmax_tn_score+=final_score;tn_score_calc+=final_score;\nvar ans_list=[],type_list=[],prs_list=[],resArr=[],mresult=[],listIdq=[],lbl_list=[];\nfor(var j=0;j<sub_count;j++){var sq=subQuestions[j];ans_list.push(JSON.stringify((sq.type===4||sq.type===13||sq.type===6)?sq.ans:(sq.ans[0]||'0')));type_list.push(sq.type||1);prs_list.push(JSON.stringify(buildParamsCS(sq)));resArr.push(1);mresult.push([1]);listIdq.push(sq.subId&&sq.subId.toString().length>5?sq.subId:'q'+j);var lbl='';if(sq.ans.length===1&&!isNaN(sq.ans[0])&&sq.type!==4&&sq.type!==13)lbl=['A','B','C','D','E'][parseInt(sq.ans[0])]||'';lbl_list.push(lbl);}\nvar logItem={answer:JSON.stringify(ans_list),label:sub_count===1?lbl_list:[],labels:lbl_list,params:sub_count===1?prs_list[0]:JSON.stringify({js:'',prs:prs_list,order:Array.from(Array(sub_count).keys())}),correct_skill:skillIDs,wrong_skill:[],type:type_list,result:resArr,mresult:mresult,idq:parseInt(q.id||q._id),score:final_score};\nif(isExam){logItem.chk=1;if(sub_count>1)logItem.list_idq=listIdq;}\nif(isVideo){logItem.marker=q.marker||(i+1);logItem.id=(q.id||q._id).toString();}\nfakeLog.push(logItem);\n}\n}else{\nvar qpa=[],apa=[];\nsubQuestions.forEach(function(sq){qpa.push(JSON.stringify(buildParamsCS(sq)));apa.push(JSON.stringify(sq.ans));});\nfakeLog.push({q_params:JSON.stringify(qpa),a_params:JSON.stringify(apa),result:1,correct:1,wrong:0,a_index:i,time_spent:Math.floor(Math.random()*15)+10});\n}\n});\nparams.append('id_cate',SESSION.meta.id_cate);\nparams.append('id_courseware',SESSION.meta.id_courseware||SESSION.meta.id_cate);\nparams.append('id_user',SESSION.meta.id_user);\nparams.append('id_grade',window.grade||window.id_grade||'10');\nif(SESSION.meta.id_school)params.append('id_school',SESSION.meta.id_school);\nif(SESSION.meta.id_group)params.append('id_group',SESSION.meta.id_group);\nparams.append('type_vip','530');params.append('time_stored','0');params.append('date_end',now);\nparams.append('data_log',JSON.stringify(fakeLog));\nif(isVideo){var vl=SESSION.video_length||900;params.append('type','5');params.append('type_exam','0');params.append('total_time',vl);params.append('current_time',vl);params.append('time_spent',totalSeconds+2);params.append('score_10','10');params.append('totalq',totalPackages);params.append('score',tn_score_calc);params.append('max_score',max_tn_score);params.append('answered',totalPackages);params.append('correct',totalPackages);params.append('count_problems',totalPackages);params.append('percent','100');params.append('pscore','10');params.append('score_status','10');var vLog={};vLog[timeInit]='start';vLog[timeInit+1]='start';vLog[timeInit+10]='reload';params.append('log',JSON.stringify(vLog));}\nelse if(isExam){params.append('time_init',timeInit);params.append('time_spent',totalSeconds);params.append('score',tn_score_calc);params.append('max_score',max_tn_score+tl_max_calc);params.append('tn_score',tn_score_calc);params.append('type_exam','1');params.append('correct',tn_score_calc);params.append('wrong',0);params.append('name_user','');params.append('tl_score','0');params.append('times','0');params.append('iframe','false');var curT=timeInit+Math.floor(totalSeconds*0.1);var totalQs=SESSION.raw_questions.length;var usableTime=Math.max(10,totalSeconds-Math.floor(totalSeconds*0.1)-10);var baseInterval=usableTime/(totalQs||1);for(var c=0;c<totalQs;c++){curT+=Math.floor(baseInterval*(0.7+Math.random()*0.6));if(curT>=timeInit+totalSeconds)curT=timeInit+totalSeconds-2;params.append('choose_log['+c+'][ind]',c);params.append('choose_log['+c+'][t]',Math.floor(curT));params.append('choose_log['+c+'][l]',c+1);}}\nelse{params.append('time_init',timeInit);params.append('time_spent',totalSeconds);params.append('time_elapsed',totalSeconds);params.append('score','100');params.append('score_10','10');params.append('star','20');params.append('theta','0');params.append('max_score','100');params.append('answered',totalPackages);params.append('correct',totalPackages);params.append('wrong','0');params.append('missed','0');params.append('count_problems',totalPackages);params.append('type','3');params.append('type_exam','0');var pLog={};pLog[timeInit]='start';pLog[timeInit+1]='start';params.append('log',JSON.stringify(pLog));}\nparams.append('count_redo','0');params.append('ended','1');params.append('save_star','1');\ntry{\naddLog('📤 Đang nộp bài lên OLM...','info');\nvar csrf=SESSION.meta.csrf_token||(document.querySelector('meta[name="csrf-token"]')&&document.querySelector('meta[name="csrf-token"]').getAttribute('content'))||'';\nvar response=await fetch('/course/teacher-static',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded; charset=UTF-8','x-csrf-token':csrf,'x-requested-with':'XMLHttpRequest'},body:params.toString()});\nif(!response.ok){addLog('❌ OLM trả lỗi HTTP '+response.status,'err');return false;}\nreturn true;\n}catch(err){addLog('❌ Lỗi kết nối OLM: '+err.message,'err');return false;}\n};\n`;

function buildModulePayload(sessionToken, key, hwid) {
  return encryptAnswers({
    src: watermarkSrc(PAYLOAD_MODULE_SRC, key, hwid),
    v: PAYLOAD_MODULE_VERSION
  }, sessionToken);
}

const CONNECTOR_MODULE_EMBEDDED_B64 = 'Y29uc3QgU0VSVkVSX0JBU0UgPSAnaHR0cHM6Ly9tb2RnYW1lLnZlcmNlbC5hcHAnOwoKY29uc3QgQVBJX1NFQ1JFVCA9ICdhN2YzYzllMWIyZDQ4NTA2ZmFlMWM3ZDNiOWYwZTJhNGM2ZDhmMWEzYjVlN2M5ZDBmMmE0YzZlOGIxZDNmNWE3JzsKCmNvbnN0IFJFUVVFU1RfRU5DUllQVElPTiA9IGZhbHNlOwoKKGZ1bmN0aW9uKCkgewogICd1c2Ugc3RyaWN0JzsKICBjb25zdCBMU19LRVkgPSAnX3RsX2Nvbm5fa2V5JzsKICBjb25zdCBMU19UWVBFID0gJ190bF9jb25uX3R5cGUnOwogIGNvbnN0IExTX0VYUCA9ICdfdGxfY29ubl9leHAnOwogIGNvbnN0IExTX1RIRU1FID0gJ190aWVwX3RoZW1lJzsKICBsZXQgQ1VSUkVOVF9LRVkgPSBudWxsOwogIGxldCBLRVlfU1RBVFVTID0gewogICAgdmFsaWQ6IGZhbHNlLAogICAgdHlwZTogbnVsbCwKICAgIGV4cGlyZXNfYXQ6IG51bGwKICB9OwogIGxldCBDVVJSRU5UX0RFVklDRSA9ICcnOwogIGNvbnN0IFNFU1NJT04gPSB7CiAgICByYXdfcXVlc3Rpb25zOiBbXSwKICAgIG1ldGE6IHsKICAgICAgaWRfdXNlcjogbnVsbCwKICAgICAgaWRfY2F0ZTogbnVsbCwKICAgICAgaWRfY291cnNld2FyZTogbnVsbCwKICAgICAgaWRfc2Nob29sOiBudWxsLAogICAgICBpZF9ncm91cDogbnVsbCwKICAgICAgY3NyZl90b2tlbjogbnVsbAogICAgfSwKICAgIGF1dG9fbW9kZTogJ3ByYWN0aWNlJywKICAgIHZpZGVvX2xlbmd0aDogOTAwCiAgfTsKICBsZXQgQ1VSUkVOVF9USEVNRSA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKExTX1RIRU1FKSB8fCAnZGVmYXVsdCc7CiAgZnVuY3Rpb24gaXNQcmVtaXVtS2V5KCkgewogICAgY29uc3QgdCA9IChLRVlfU1RBVFVTLnR5cGUgfHwgX3NMUy5nZXQoTFNfVFlQRSkgfHwgJycpLnRvU3RyaW5nKCkudG9VcHBlckNhc2UoKTsKICAgIHJldHVybiB0ID09PSAnUFJFTUlVTScgfHwgdCA9PT0gJ1ZJUCcgfHwgdCA9PT0gJ1VOTElNSVRFRCc7CiAgfQogIGZ1bmN0aW9uIGhhbmRsZU9sbU1pc21hdGNoKHNlcnZlck9sbSwgY3VycmVudE9sbSkgewogICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oTFNfS0VZKTsKICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKExTX1RZUEUpOwogICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oTFNfRVhQKTsKICAgIENVUlJFTlRfS0VZID0gbnVsbDsKICAgIEtFWV9TVEFUVVMgPSB7CiAgICAgIHZhbGlkOiBmYWxzZSwKICAgICAgdHlwZTogbnVsbCwKICAgICAgZXhwaXJlc19hdDogbnVsbAogICAgfTsKICAgIF9zZWNTZXNzaW9uID0gewogICAgICB0b2tlbjogbnVsbCwKICAgICAgZXhwOiAwLAogICAgICBmcEhhc2g6IG51bGwsCiAgICAgIHNlcTogMQogICAgfTsKICAgIENVUlJFTlRfREVWSUNFID0gJyc7CiAgICBjb25zdCBwYW5lbEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLXBhbmVsJyk7CiAgICBjb25zdCBmYiA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1mbG9hdEJ0bicpOwogICAgaWYgKHBhbmVsRWwpIHBhbmVsRWwucmVtb3ZlKCk7CiAgICBpZiAoZmIpIGZiLnJlbW92ZSgpOwogICAgc2hvd0N1c3RvbU1vZGFsKHsKICAgICAgaWNvbjogJ/CfmqsnLAogICAgICB0aXRsZTogJ1TDgEkgS0hP4bqiTiBPTE0gS0jDlE5HIEtI4buaUCEnLAogICAgICBsaW5lczogWyBgS2V5IMSRxrDhu6NjIMSRxINuZyBrw70gY2hvIHTDoGkga2hv4bqjbjogPGI+JHtzZXJ2ZXJPbG19PC9iPmAsIGBUw6BpIGtob+G6o24gT0xNIGhp4buHbiB04bqhaTogPGI+JHtjdXJyZW50T2xtfTwvYj5gLCBg4pqg77iPIFZ1aSBsw7JuZyDEkcSDbmcgbmjhuq1wIMSRw7puZyB0w6BpIGtob+G6o24gT0xNIMSR4buDIHPhu60gZOG7pW5nIGtleSBuw6B5LGAsIGBob+G6t2MgbGnDqm4gaOG7hyBhZG1pbiDEkeG7gyDEkcaw4bujYyBo4buXIHRy4bujIWAgXSwKICAgICAgb25PazogKCkgPT4gYnVpbGRMb2NrU2NyZWVuKCfimqDvuI8gVMOgaSBraG/huqNuIE9MTSBraMO0bmcga2jhu5twIHbhu5tpIGtleSDEkcOjIMSRxINuZyBrw70hJykKICAgIH0pOwogIH0KICBmdW5jdGlvbiBnZXRUaGVtZUNvbG9ycyh0aGVtZSkgewogICAgY29uc3QgVCA9IHsKICAgICAgZGVmYXVsdDogewogICAgICAgIGMxOiAnIzAwZjJmZScsCiAgICAgICAgYzI6ICcjNGZhY2ZlJywKICAgICAgICBiZ092ZXJsYXk6ICdyZ2JhKDEzLDE3LDIzLDAuOTUpJywKICAgICAgICBiZ1BhbmVsOiAncmdiYSgxMywxNywyMywwLjg4KScsCiAgICAgICAgYm9yZGVyOiAncmdiYSgwLDI0MiwyNTQsMC4yKScsCiAgICAgICAgYm9yZGVyU3Ryb25nOiAncmdiYSgwLDI0MiwyNTQsMC4zKScsCiAgICAgICAgYm9yZGVyU3VidGxlOiAncmdiYSgwLDI0MiwyNTQsMC4xMiknLAogICAgICAgIGhlYWRlckJnOiAnbGluZWFyLWdyYWRpZW50KDEzNWRlZyxyZ2JhKDAsMjQyLDI1NCwwLjA3KSxyZ2JhKDc5LDE3MiwyNTQsMC4wNCkpJywKICAgICAgICBnbG93Q29sb3I6ICdyZ2JhKDAsMjQyLDI1NCwwLjQ1KScsCiAgICAgICAgZ2xvd1N0cm9uZzogJ3JnYmEoMCwyNDIsMjU0LDAuNyknLAogICAgICAgIGdsb3dNaWQ6ICdyZ2JhKDAsMjQyLDI1NCwwLjI1KScsCiAgICAgICAgZ2xvd1N1YnRsZTogJ3JnYmEoMCwyNDIsMjU0LDAuMDgpJywKICAgICAgICBnbG93UHVsc2U6ICdyZ2JhKDAsMjQyLDI1NCwwLjU1KScsCiAgICAgICAgaW5wdXRCb3JkZXI6ICdyZ2JhKDAsMjQyLDI1NCwwLjQpJywKICAgICAgICBpbnB1dENvbG9yOiAnIzAwZjJmZScsCiAgICAgICAgZmxvYXRHcmFkaWVudDogJ2xpbmVhci1ncmFkaWVudCgxMzVkZWcsIzAwZjJmZSwjNGZhY2ZlKScsCiAgICAgICAgYnJhbmRHcmFkaWVudDogJ2xpbmVhci1ncmFkaWVudCg5MGRlZywjMDBmMmZlLCM0ZmFjZmUsIzAwZjJmZSknLAogICAgICAgIHN0YXR1c0JvcmRlcjogJ3JnYmEoMCwyMzAsMTIwLDAuMjUpJywKICAgICAgICBzdGF0dXNCZzogJ3JnYmEoMCwyMzAsMTIwLDAuMDQpJywKICAgICAgICBwYW5lbEluc2V0OiAncmdiYSgwLDI0MiwyNTQsMC4wOCknLAogICAgICAgIHNlbGVjdEJvcmRlcjogJ3JnYmEoMCwyNDIsMjU0LDAuMiknLAogICAgICAgIGNvbnNvbGVCb3JkZXI6ICdyZ2JhKDAsMjQyLDI1NCwwLjEyKScsCiAgICAgICAgZnhDU1M6ICcnLAogICAgICAgIHBhbmVsRXh0cmE6ICcnLAogICAgICAgIHRoZW1lTGFiZWw6ICfwn5S1IE3hurdjIMSQ4buLbmgnLAogICAgICAgIHByZXZpZXdCZzogJ2xpbmVhci1ncmFkaWVudCgxMzVkZWcsIzAwMTUyMCwjMDBmMmZlNTUpJywKICAgICAgICBwcmV2aWV3Qm9yZGVyOiAncmdiYSgwLDI0MiwyNTQsMC41KScsCiAgICAgICAgcHJldmlld1RleHQ6ICcjMDBmMmZlJwogICAgICB9LAogICAgICBncmF5OiB7CiAgICAgICAgYzE6ICcjZTBlMGUwJywKICAgICAgICBjMjogJyNhMGEwYTAnLAogICAgICAgIGJnT3ZlcmxheTogJ3JnYmEoMTAsMTAsMTAsMC45NyknLAogICAgICAgIGJnUGFuZWw6ICdyZ2JhKDIwLDIwLDIwLDAuOTQpJywKICAgICAgICBib3JkZXI6ICdyZ2JhKDIwMCwyMDAsMjAwLDAuMTgpJywKICAgICAgICBib3JkZXJTdHJvbmc6ICdyZ2JhKDIzMCwyMzAsMjMwLDAuMyknLAogICAgICAgIGJvcmRlclN1YnRsZTogJ3JnYmEoMTcwLDE3MCwxNzAsMC4xKScsCiAgICAgICAgaGVhZGVyQmc6ICdsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLHJnYmEoMTIwLDEyMCwxMjAsMC4xMikscmdiYSg2MCw2MCw2MCwwLjA1KSknLAogICAgICAgIGdsb3dDb2xvcjogJ3JnYmEoMjEwLDIxMCwyMTAsMC4zNSknLAogICAgICAgIGdsb3dTdHJvbmc6ICdyZ2JhKDIyMCwyMjAsMjIwLDAuNiknLAogICAgICAgIGdsb3dNaWQ6ICdyZ2JhKDIwMCwyMDAsMjAwLDAuMiknLAogICAgICAgIGdsb3dTdWJ0bGU6ICdyZ2JhKDE2MCwxNjAsMTYwLDAuMDcpJywKICAgICAgICBnbG93UHVsc2U6ICdyZ2JhKDIwMCwyMDAsMjAwLDAuNDUpJywKICAgICAgICBpbnB1dEJvcmRlcjogJ3JnYmEoMjAwLDIwMCwyMDAsMC4zOCknLAogICAgICAgIGlucHV0Q29sb3I6ICcjZDhkOGQ4JywKICAgICAgICBmbG9hdEdyYWRpZW50OiAnbGluZWFyLWdyYWRpZW50KDEzNWRlZywjYzBjMGMwLCM2NjYpJywKICAgICAgICBicmFuZEdyYWRpZW50OiAnbGluZWFyLWdyYWRpZW50KDkwZGVnLCNjMGMwYzAsI2ZmZmZmZiwjZDBkMGQwLCNjMGMwYzApJywKICAgICAgICBzdGF0dXNCb3JkZXI6ICdyZ2JhKDE2MCwxNjAsMTYwLDAuMiknLAogICAgICAgIHN0YXR1c0JnOiAncmdiYSg2MCw2MCw2MCwwLjA3KScsCiAgICAgICAgcGFuZWxJbnNldDogJ3JnYmEoMjAwLDIwMCwyMDAsMC4wNyknLAogICAgICAgIHNlbGVjdEJvcmRlcjogJ3JnYmEoMTkwLDE5MCwxOTAsMC4yKScsCiAgICAgICAgY29uc29sZUJvcmRlcjogJ3JnYmEoMTYwLDE2MCwxNjAsMC4xKScsCiAgICAgICAgZnhDU1M6IGBcbiAgICAgICAgICAgICAgICAgICAgI3RsLWNvbm4tZngtYmFyIHsgaGVpZ2h0OjJweDsgYmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoOTBkZWcsdHJhbnNwYXJlbnQscmdiYSgyNTUsMjU1LDI1NSwwLjA4KSxyZ2JhKDI1NSwyNTUsMjU1LDAuNTUpLHJnYmEoMjU1LDI1NSwyNTUsMC4wOCksdHJhbnNwYXJlbnQpOyBiYWNrZ3JvdW5kLXNpemU6MzAwJSAxMDAlOyBhbmltYXRpb246bWV0YWxTd2VlcCAyLjhzIGxpbmVhciBpbmZpbml0ZTsgfVxuICAgICAgICAgICAgICAgICAgICBAa2V5ZnJhbWVzIG1ldGFsU3dlZXAgeyAwJXtiYWNrZ3JvdW5kLXBvc2l0aW9uOjEwMCUgMH0gMTAwJXtiYWNrZ3JvdW5kLXBvc2l0aW9uOi0yMDAlIDB9IH1cbiAgICAgICAgICAgICAgICAgICAgI3RsLXBhbmVsIHsgYm94LXNoYWRvdzogMCAwIDYwcHggcmdiYSgwLDAsMCwwLjg1KSwgMCAwIDMwcHggcmdiYSgxODAsMTgwLDE4MCwwLjA2KSwgaW5zZXQgMCAxcHggMCByZ2JhKDI1NSwyNTUsMjU1LDAuMDgpOyB9XG4gICAgICAgICAgICAgICAgICAgICN0bC1jb25uLXBhbmVsIHsgYm94LXNoYWRvdzogMCAwIDYwcHggcmdiYSgwLDAsMCwwLjg1KSwgaW5zZXQgMCAxcHggMCByZ2JhKDI1NSwyNTUsMjU1LDAuMDgpOyB9XG4gICAgICAgICAgICAgICAgYCwKICAgICAgICBwYW5lbEV4dHJhOiAnPGRpdiBpZD0idGwtY29ubi1meC1iYXIiPjwvZGl2PicsCiAgICAgICAgdGhlbWVMYWJlbDogJ+KaqyBYw6FtIELhuqFjJywKICAgICAgICBwcmV2aWV3Qmc6ICdsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLCMxYTFhMWEsIzY2NiknLAogICAgICAgIHByZXZpZXdCb3JkZXI6ICdyZ2JhKDIyMCwyMjAsMjIwLDAuNDUpJywKICAgICAgICBwcmV2aWV3VGV4dDogJyNlMGUwZTAnCiAgICAgIH0sCiAgICAgIHBpbms6IHsKICAgICAgICBjMTogJyNmZjZlYjQnLAogICAgICAgIGMyOiAnI2ZmMTQ5MycsCiAgICAgICAgYmdPdmVybGF5OiAncmdiYSgxOCw0LDE0LDAuOTcpJywKICAgICAgICBiZ1BhbmVsOiAncmdiYSgyNiw0LDE4LDAuOTMpJywKICAgICAgICBib3JkZXI6ICdyZ2JhKDI1NSwxMTAsMTgwLDAuMiknLAogICAgICAgIGJvcmRlclN0cm9uZzogJ3JnYmEoMjU1LDExMCwxODAsMC4zOCknLAogICAgICAgIGJvcmRlclN1YnRsZTogJ3JnYmEoMjU1LDExMCwxODAsMC4xMiknLAogICAgICAgIGhlYWRlckJnOiAnbGluZWFyLWdyYWRpZW50KDEzNWRlZyxyZ2JhKDI1NSwxMTAsMTgwLDAuMDkpLHJnYmEoMjU1LDIwLDE0NywwLjA0KSknLAogICAgICAgIGdsb3dDb2xvcjogJ3JnYmEoMjU1LDExMCwxODAsMC40NSknLAogICAgICAgIGdsb3dTdHJvbmc6ICdyZ2JhKDI1NSwxMTAsMTgwLDAuNzUpJywKICAgICAgICBnbG93TWlkOiAncmdiYSgyNTUsMTEwLDE4MCwwLjIyKScsCiAgICAgICAgZ2xvd1N1YnRsZTogJ3JnYmEoMjU1LDIwLDE0NywwLjA3KScsCiAgICAgICAgZ2xvd1B1bHNlOiAncmdiYSgyNTUsMTEwLDE4MCwwLjU1KScsCiAgICAgICAgaW5wdXRCb3JkZXI6ICdyZ2JhKDI1NSwxMTAsMTgwLDAuNDIpJywKICAgICAgICBpbnB1dENvbG9yOiAnI2ZmYjNkOScsCiAgICAgICAgZmxvYXRHcmFkaWVudDogJ2xpbmVhci1ncmFkaWVudCgxMzVkZWcsI2ZmNmViNCwjZmYxNDkzKScsCiAgICAgICAgYnJhbmRHcmFkaWVudDogJ2xpbmVhci1ncmFkaWVudCg5MGRlZywjZmY2ZWI0LCNmZmNjZTgsI2ZmMTQ5MywjZmY2ZWI0KScsCiAgICAgICAgc3RhdHVzQm9yZGVyOiAncmdiYSgyNTUsMTEwLDE4MCwwLjIpJywKICAgICAgICBzdGF0dXNCZzogJ3JnYmEoMjU1LDIwLDE0NywwLjA1KScsCiAgICAgICAgcGFuZWxJbnNldDogJ3JnYmEoMjU1LDExMCwxODAsMC4xKScsCiAgICAgICAgc2VsZWN0Qm9yZGVyOiAncmdiYSgyNTUsMTEwLDE4MCwwLjIpJywKICAgICAgICBjb25zb2xlQm9yZGVyOiAncmdiYSgyNTUsMTEwLDE4MCwwLjEyKScsCiAgICAgICAgZnhDU1M6IGBcbiAgICAgICAgICAgICAgICAgICAgI3RsLXBhbmVsIHsgYW5pbWF0aW9uOnNha3VyYVBhbmVsR2xvdyAzcyBlYXNlLWluLW91dCBpbmZpbml0ZTsgfVxuICAgICAgICAgICAgICAgICAgICAjdGwtY29ubi1wYW5lbCB7IGFuaW1hdGlvbjpzYWt1cmFQYW5lbEdsb3cgM3MgZWFzZS1pbi1vdXQgaW5maW5pdGU7IH1cbiAgICAgICAgICAgICAgICAgICAgQGtleWZyYW1lcyBzYWt1cmFQYW5lbEdsb3cge1xuICAgICAgICAgICAgICAgICAgICAgICAgMCUsMTAwJXsgYm94LXNoYWRvdzowIDAgNjBweCByZ2JhKDAsMCwwLDAuOCksMCAwIDI1cHggcmdiYSgyNTUsMTEwLDE4MCwwLjEpLGluc2V0IDAgMCAwIDFweCByZ2JhKDI1NSwxMTAsMTgwLDAuMDYpOyB9XG4gICAgICAgICAgICAgICAgICAgICAgICA1MCV7IGJveC1zaGFkb3c6MCAwIDYwcHggcmdiYSgwLDAsMCwwLjgpLDAgMCA0NXB4IHJnYmEoMjU1LDExMCwxODAsMC4yKSxpbnNldCAwIDAgMCAxcHggcmdiYSgyNTUsMTEwLDE4MCwwLjEyKTsgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIC5zYWt1cmEtcGV0YWwgeyBwb3NpdGlvbjphYnNvbHV0ZTsgcG9pbnRlci1ldmVudHM6bm9uZTsgYm9yZGVyLXJhZGl1czo1MCUgMCA1MCUgMDsgYmFja2dyb3VuZDpyZ2JhKDI1NSwxMTAsMTgwLDAuMjIpOyBhbmltYXRpb246c2FrdXJhRHJpZnQgbGluZWFyIGluZmluaXRlOyB9XG4gICAgICAgICAgICAgICAgICAgIEBrZXlmcmFtZXMgc2FrdXJhRHJpZnQgeyAwJXt0cmFuc2Zvcm06dHJhbnNsYXRlWSgtMTBweCkgcm90YXRlKDBkZWcpO29wYWNpdHk6MC43fSAxMDAle3RyYW5zZm9ybTp0cmFuc2xhdGVZKDQyMHB4KSByb3RhdGUoMjcwZGVnKTtvcGFjaXR5OjB9IH1cbiAgICAgICAgICAgICAgICAgICAgI3RsLWNvbm4tZngtcGV0YWxzIHsgcG9zaXRpb246YWJzb2x1dGU7dG9wOjA7bGVmdDowO3JpZ2h0OjA7aGVpZ2h0OjEwMCU7cG9pbnRlci1ldmVudHM6bm9uZTtvdmVyZmxvdzpoaWRkZW47ei1pbmRleDowO2JvcmRlci1yYWRpdXM6MTZweDsgfVxuICAgICAgICAgICAgICAgIGAsCiAgICAgICAgcGFuZWxFeHRyYTogYDxkaXYgaWQ9InRsLWNvbm4tZngtcGV0YWxzIj5cbiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0ic2FrdXJhLXBldGFsIiBzdHlsZT0id2lkdGg6N3B4O2hlaWdodDo3cHg7bGVmdDo4JTt0b3A6LTEwcHg7YW5pbWF0aW9uLWR1cmF0aW9uOjMuOHM7YW5pbWF0aW9uLWRlbGF5OjBzOyI+PC9kaXY+XG4gICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InNha3VyYS1wZXRhbCIgc3R5bGU9IndpZHRoOjVweDtoZWlnaHQ6NXB4O2xlZnQ6MjglO3RvcDotMTBweDthbmltYXRpb24tZHVyYXRpb246NS4xczthbmltYXRpb24tZGVsYXk6MC45czsiPjwvZGl2PlxuICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJzYWt1cmEtcGV0YWwiIHN0eWxlPSJ3aWR0aDo4cHg7aGVpZ2h0OjhweDtsZWZ0OjU1JTt0b3A6LTEwcHg7YW5pbWF0aW9uLWR1cmF0aW9uOjQuNHM7YW5pbWF0aW9uLWRlbGF5OjEuN3M7Ij48L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0ic2FrdXJhLXBldGFsIiBzdHlsZT0id2lkdGg6NHB4O2hlaWdodDo0cHg7bGVmdDo3NSU7dG9wOi0xMHB4O2FuaW1hdGlvbi1kdXJhdGlvbjozLjJzO2FuaW1hdGlvbi1kZWxheTowLjRzOyI+PC9kaXY+XG4gICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InNha3VyYS1wZXRhbCIgc3R5bGU9IndpZHRoOjZweDtoZWlnaHQ6NnB4O2xlZnQ6OTIlO3RvcDotMTBweDthbmltYXRpb24tZHVyYXRpb246NC45czthbmltYXRpb24tZGVsYXk6Mi4xczsiPjwvZGl2PlxuICAgICAgICAgICAgICAgIDwvZGl2PmAsCiAgICAgICAgdGhlbWVMYWJlbDogJ/CfjLggSOG7k25nIFNha3VyYScsCiAgICAgICAgcHJldmlld0JnOiAnbGluZWFyLWdyYWRpZW50KDEzNWRlZywjMWEwNTEwLCNmZjZlYjQ1NSknLAogICAgICAgIHByZXZpZXdCb3JkZXI6ICdyZ2JhKDI1NSwxMTAsMTgwLDAuNTUpJywKICAgICAgICBwcmV2aWV3VGV4dDogJyNmZjZlYjQnCiAgICAgIH0KICAgIH07CiAgICByZXR1cm4gVFt0aGVtZV0gfHwgVC5kZWZhdWx0OwogIH0KICBmdW5jdGlvbiBnZXRMb2NrU2NyZWVuU3R5bGVzKCkgewogICAgY29uc3QgdGMgPSBnZXRUaGVtZUNvbG9ycyhDVVJSRU5UX1RIRU1FKTsKICAgIHJldHVybiBgXG4gICAgICAgICAgICBAaW1wb3J0IHVybCgnaHR0cHM6Ly9mb250cy5nb29nbGVhcGlzLmNvbS9jc3MyP2ZhbWlseT1PcmJpdHJvbjp3Z2h0QDQwMDs3MDA7OTAwJmZhbWlseT1TaGFyZStUZWNoK01vbm8mZmFtaWx5PVJhamRoYW5pOndnaHRANDAwOzYwMDs3MDAmZGlzcGxheT1zd2FwJyk7XG4gICAgICAgICAgICAjdGwtY29ubi1vdmVybGF5IHsgcG9zaXRpb246Zml4ZWQ7dG9wOjA7bGVmdDowO3dpZHRoOjEwMHZ3O2hlaWdodDoxMDB2aDtiYWNrZ3JvdW5kOiR7dGMuYmdPdmVybGF5fTtiYWNrZHJvcC1maWx0ZXI6Ymx1cigxNXB4KTt6LWluZGV4OjIxNDc0ODM2NDc7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyO2ZvbnQtZmFtaWx5OidSYWpkaGFuaScsc2Fucy1zZXJpZjsgfVxuICAgICAgICAgICAgI3RsLWNvbm4tcGFuZWwgeyB3aWR0aDo0MjBweDtiYWNrZ3JvdW5kOiR7dGMuYmdQYW5lbH07Ym9yZGVyOjFweCBzb2xpZCAke3RjLmJvcmRlclN0cm9uZ307Ym9yZGVyLXJhZGl1czoyMHB4O2JveC1zaGFkb3c6MCAwIDYwcHggcmdiYSgwLDAsMCwwLjgpLDAgMCAwIDFweCAke3RjLnBhbmVsSW5zZXR9IGluc2V0O3RleHQtYWxpZ246Y2VudGVyO292ZXJmbG93OmhpZGRlbjthbmltYXRpb246dGxGYWRlSW4gMC4zcyBlYXNlO3Bvc2l0aW9uOnJlbGF0aXZlOyB9XG4gICAgICAgICAgICBAa2V5ZnJhbWVzIHRsRmFkZUluIHsgZnJvbXtvcGFjaXR5OjA7dHJhbnNmb3JtOnNjYWxlKDAuOTUpfXRve29wYWNpdHk6MTt0cmFuc2Zvcm06c2NhbGUoMSl9IH1cbiAgICAgICAgICAgICN0bC1jb25uLWhlYWRlciB7IHBhZGRpbmc6MjJweDtiYWNrZ3JvdW5kOiR7dGMuaGVhZGVyQmd9O2JvcmRlci1ib3R0b206MXB4IHNvbGlkICR7dGMuYm9yZGVyfTsgfVxuICAgICAgICAgICAgLnRsLWJyYW5kLW5hbWUgeyBmb250LWZhbWlseTonT3JiaXRyb24nLHNhbnMtc2VyaWY7Zm9udC1zaXplOjIycHg7Zm9udC13ZWlnaHQ6NzAwO2JhY2tncm91bmQ6JHt0Yy5icmFuZEdyYWRpZW50fTtiYWNrZ3JvdW5kLXNpemU6MjAwJTstd2Via2l0LWJhY2tncm91bmQtY2xpcDp0ZXh0Oy13ZWJraXQtdGV4dC1maWxsLWNvbG9yOnRyYW5zcGFyZW50O2FuaW1hdGlvbjp0bFNoaW1tZXIgM3MgbGluZWFyIGluZmluaXRlOyB9XG4gICAgICAgICAgICBAa2V5ZnJhbWVzIHRsU2hpbW1lciB7IDEwMCV7YmFja2dyb3VuZC1wb3NpdGlvbjoyMDAlIDUwJX0gfVxuICAgICAgICAgICAgI3RsLWNvbm4tYm9keSB7IHBhZGRpbmc6MzBweCAyNXB4OyB9XG4gICAgICAgICAgICAudGwtc3VidGl0bGUgeyBjb2xvcjpyZ2JhKDI1NSwyNTUsMjU1LDAuNyk7Zm9udC1zaXplOjEzcHg7bWFyZ2luLWJvdHRvbToxMHB4O2ZvbnQtZmFtaWx5OidTaGFyZSBUZWNoIE1vbm8nOyB9XG4gICAgICAgICAgICAudGwtd2FybmluZyB7IGNvbG9yOiNmZmMxMDc7Zm9udC1zaXplOjEycHg7bWFyZ2luLWJvdHRvbToyMHB4O2JhY2tncm91bmQ6cmdiYSgyNTUsMTkzLDcsMC4xKTtwYWRkaW5nOjhweDtib3JkZXItcmFkaXVzOjZweDsgfVxuICAgICAgICAgICAgLnRsLWlucHV0IHsgd2lkdGg6MTAwJTtwYWRkaW5nOjE0cHg7YmFja2dyb3VuZDpyZ2JhKDAsMCwwLDAuNTUpO2JvcmRlcjoxcHggc29saWQgJHt0Yy5pbnB1dEJvcmRlcn07Ym9yZGVyLXJhZGl1czoxMHB4O2NvbG9yOiR7dGMuaW5wdXRDb2xvcn07Zm9udC1mYW1pbHk6J1NoYXJlIFRlY2ggTW9ubyc7Zm9udC1zaXplOjE2cHg7dGV4dC1hbGlnbjpjZW50ZXI7bWFyZ2luLWJvdHRvbToxNXB4O3RyYW5zaXRpb246MC4ycztib3gtc2l6aW5nOmJvcmRlci1ib3g7IH1cbiAgICAgICAgICAgIC50bC1pbnB1dDpmb2N1cyB7IG91dGxpbmU6bm9uZTtib3JkZXItY29sb3I6JHt0Yy5jMX07Ym94LXNoYWRvdzowIDAgMTZweCAke3RjLmdsb3dNaWR9OyB9XG4gICAgICAgICAgICAudGwtYnRuIHsgd2lkdGg6MTAwJTtwYWRkaW5nOjE0cHg7Ym9yZGVyOm5vbmU7Ym9yZGVyLXJhZGl1czoxMHB4O2N1cnNvcjpwb2ludGVyO2ZvbnQtZmFtaWx5OidPcmJpdHJvbicsc2Fucy1zZXJpZjtmb250LXNpemU6MTRweDtmb250LXdlaWdodDo5MDA7bWFyZ2luLWJvdHRvbToxMnB4O3RyYW5zaXRpb246MC4yczsgfVxuICAgICAgICAgICAgLnRsLWJ0bi11bmxvY2sgeyBiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCgxMzVkZWcsIzAwYjA5YiwjOTZjOTNkKTtjb2xvcjojZmZmOyB9XG4gICAgICAgICAgICAudGwtYnRuLXVubG9jazpob3ZlciB7IHRyYW5zZm9ybTpzY2FsZSgxLjAyKTtib3gtc2hhZG93OjAgMCAyNXB4IHJnYmEoMCwxNzYsMTU1LDAuNik7IH1cbiAgICAgICAgICAgIC50bC1idG4tdmlwIHsgYmFja2dyb3VuZDpyZ2JhKDIxNyw0LDQxLDAuMSk7Ym9yZGVyOjFweCBzb2xpZCByZ2JhKDIxNyw0LDQxLDAuNSk7Y29sb3I6I2VmMjMzYzsgfVxuICAgICAgICAgICAgLnRsLWJ0bi12aXA6aG92ZXIgeyBiYWNrZ3JvdW5kOnJnYmEoMjE3LDQsNDEsMC4yKTt0cmFuc2Zvcm06c2NhbGUoMS4wMSk7IH1cbiAgICAgICAgICAgICN0bC1lcnIgeyBjb2xvcjojZWYyMzNjO2ZvbnQtc2l6ZToxM3B4O21hcmdpbi10b3A6MTJweDtkaXNwbGF5Om5vbmU7Zm9udC1mYW1pbHk6J1NoYXJlIFRlY2ggTW9ubyc7YmFja2dyb3VuZDpyZ2JhKDIzOSwzNSw2MCwwLjEpO3BhZGRpbmc6OHB4O2JvcmRlci1yYWRpdXM6NnB4OyB9XG4gICAgICAgICAgICAudGwtaHdpZCB7IGNvbG9yOnJnYmEoMjU1LDI1NSwyNTUsMC4yMik7Zm9udC1zaXplOjEwcHg7bWFyZ2luLXRvcDoxNXB4O3dvcmQtYnJlYWs6YnJlYWstYWxsO2ZvbnQtZmFtaWx5Om1vbm9zcGFjZTsgfVxuICAgICAgICAgICAgLnRsLWZvb3QgeyBtYXJnaW4tdG9wOjE1cHg7Zm9udC1zaXplOjExcHg7Y29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjEzKTsgfVxuICAgICAgICAgICAgJHt0Yy5meENTU31cbiAgICAgICAgYDsKICB9CiAgZnVuY3Rpb24gZ2V0TWFpblVJU3R5bGVzKCkgewogICAgY29uc3QgdGMgPSBnZXRUaGVtZUNvbG9ycyhDVVJSRU5UX1RIRU1FKTsKICAgIHJldHVybiBgXG4gICAgICAgICAgICBAaW1wb3J0IHVybCgnaHR0cHM6Ly9mb250cy5nb29nbGVhcGlzLmNvbS9jc3MyP2ZhbWlseT1PcmJpdHJvbjp3Z2h0QDQwMDs3MDA7OTAwJmZhbWlseT1TaGFyZStUZWNoK01vbm8mZmFtaWx5PVJhamRoYW5pOndnaHRANDAwOzYwMDs3MDAmZGlzcGxheT1zd2FwJyk7XG4gICAgICAgICAgICAjdGwtZmxvYXRCdG4geyBwb3NpdGlvbjpmaXhlZDtib3R0b206MjhweDtyaWdodDoyOHB4O3dpZHRoOjU2cHg7aGVpZ2h0OjU2cHg7Ym9yZGVyLXJhZGl1czo1MCU7Ym9yZGVyOm5vbmU7Y3Vyc29yOnBvaW50ZXI7ei1pbmRleDoxMDAwMDtiYWNrZ3JvdW5kOiR7dGMuZmxvYXRHcmFkaWVudH07Ym94LXNoYWRvdzowIDAgMCAwICR7dGMuZ2xvd1N0cm9uZ30sMCAwIDIwcHggJHt0Yy5nbG93Q29sb3J9LDAgNHB4IDIwcHggcmdiYSgwLDAsMCwwLjUpO2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OmNlbnRlcjtmb250LXNpemU6MjJweDt0cmFuc2l0aW9uOnRyYW5zZm9ybSAwLjJzIGVhc2UsYm94LXNoYWRvdyAwLjJzIGVhc2U7YW5pbWF0aW9uOmNvbm5QdWxzZVJpbmcgMi41cyBlYXNlLW91dCBpbmZpbml0ZTsgfVxuICAgICAgICAgICAgI3RsLWZsb2F0QnRuOmhvdmVyIHsgdHJhbnNmb3JtOnNjYWxlKDEuMTIpIHJvdGF0ZSgxNWRlZyk7IH1cbiAgICAgICAgICAgIEBrZXlmcmFtZXMgY29ublB1bHNlUmluZyB7IDAle2JveC1zaGFkb3c6MCAwIDAgMCAke3RjLmdsb3dQdWxzZX19NzAle2JveC1zaGFkb3c6MCAwIDAgMTVweCByZ2JhKDAsMCwwLDApfTEwMCV7Ym94LXNoYWRvdzowIDAgMCAwIHJnYmEoMCwwLDAsMCl9IH1cbiAgICAgICAgICAgIEBrZXlmcmFtZXMgY29ubkJsaW5rIHsgMCUsMTAwJXtvcGFjaXR5OjF9NTAle29wYWNpdHk6MC4zfSB9XG4gICAgICAgICAgICAjdGwtcGFuZWwgeyBwb3NpdGlvbjpmaXhlZDt0b3A6NTAlO2xlZnQ6NTAlO3RyYW5zZm9ybTp0cmFuc2xhdGUoLTUwJSwtNTAlKTt3aWR0aDozNjBweDtiYWNrZ3JvdW5kOiR7dGMuYmdQYW5lbH07YmFja2Ryb3AtZmlsdGVyOmJsdXIoMjRweCk7Ym9yZGVyOjFweCBzb2xpZCAke3RjLmJvcmRlcn07Ym9yZGVyLXJhZGl1czoxNnB4O2JveC1zaGFkb3c6MCAwIDYwcHggcmdiYSgwLDAsMCwwLjgpO3otaW5kZXg6OTk5OTtvdmVyZmxvdzpoaWRkZW47Zm9udC1mYW1pbHk6J1JhamRoYW5pJyxzYW5zLXNlcmlmOyB9XG4gICAgICAgICAgICAjdGwtcGFuZWwuaGlkZGVuIHsgZGlzcGxheTpub25lOyB9XG4gICAgICAgICAgICAjdGwtcC1oZWFkZXIgeyBjdXJzb3I6bW92ZTtwYWRkaW5nOjE0cHggMTZweCAxMnB4O2JhY2tncm91bmQ6JHt0Yy5oZWFkZXJCZ307Ym9yZGVyLWJvdHRvbToxcHggc29saWQgJHt0Yy5ib3JkZXJTdWJ0bGV9O2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47IH1cbiAgICAgICAgICAgIC50bC1wLWJyYW5kIHsgZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6OHB4OyB9XG4gICAgICAgICAgICAudGwtcC1uYW1lIHsgZm9udC1mYW1pbHk6J09yYml0cm9uJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZToxMS41cHg7Zm9udC13ZWlnaHQ6NzAwO2JhY2tncm91bmQ6JHt0Yy5icmFuZEdyYWRpZW50fTtiYWNrZ3JvdW5kLXNpemU6MjAwJTstd2Via2l0LWJhY2tncm91bmQtY2xpcDp0ZXh0Oy13ZWJraXQtdGV4dC1maWxsLWNvbG9yOnRyYW5zcGFyZW50O2FuaW1hdGlvbjp0bFNoaW1tZXIgM3MgbGluZWFyIGluZmluaXRlOyB9XG4gICAgICAgICAgICBAa2V5ZnJhbWVzIHRsU2hpbW1lciB7IDEwMCV7YmFja2dyb3VuZC1wb3NpdGlvbjoyMDAlIDUwJX0gfVxuICAgICAgICAgICAgLnRsLWJhZGdlIHsgZm9udC1mYW1pbHk6J09yYml0cm9uJztmb250LXNpemU6Ny41cHg7Zm9udC13ZWlnaHQ6OTAwO2NvbG9yOiNmZmY7Ym9yZGVyLXJhZGl1czo0cHg7cGFkZGluZzozcHggNnB4O2JhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDEzNWRlZywjNTU1LCM3NzcpOyB9XG4gICAgICAgICAgICAudGwtYmFkZ2UudmlwIHsgYmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLCNhODU1ZjcsIzYzNjZmMSk7Ym94LXNoYWRvdzowIDAgMTBweCByZ2JhKDE2OCw4NSwyNDcsMC40KTsgfVxuICAgICAgICAgICAgLnRsLWJhZGdlLnVubGltaXRlZCB7IGJhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDEzNWRlZywjZjU5ZTBiLCNlZjQ0NDQpO2JveC1zaGFkb3c6MCAwIDEwcHggcmdiYSgyNDUsMTU4LDExLDAuNCk7IH1cbiAgICAgICAgICAgICN0bC1jbG9zZUJ0biwjdGwtc2V0dGluZ3NCdG4geyB3aWR0aDoyOHB4O2hlaWdodDoyOHB4O2JvcmRlci1yYWRpdXM6NTAlO2JvcmRlcjoxcHggc29saWQgcmdiYSgyNTUsMjU1LDI1NSwwLjEpO2JhY2tncm91bmQ6cmdiYSgyNTUsMjU1LDI1NSwwLjA0KTtjb2xvcjpyZ2JhKDI1NSwyNTUsMjU1LDAuNSk7Y3Vyc29yOnBvaW50ZXI7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyO3RyYW5zaXRpb246MC4ycztmb250LXNpemU6MTNweDsgfVxuICAgICAgICAgICAgI3RsLWNsb3NlQnRuOmhvdmVyIHsgYm9yZGVyLWNvbG9yOnJnYmEoMjE3LDQsNDEsMC42KTtiYWNrZ3JvdW5kOnJnYmEoMjE3LDQsNDEsMC4xNSk7Y29sb3I6I2VmMjMzYzsgfVxuICAgICAgICAgICAgI3RsLXNldHRpbmdzQnRuOmhvdmVyIHsgYm9yZGVyLWNvbG9yOiR7dGMuYm9yZGVyU3Ryb25nfTtiYWNrZ3JvdW5kOiR7dGMuZ2xvd1N1YnRsZX07Y29sb3I6JHt0Yy5jMX07IH1cbiAgICAgICAgICAgICN0bC1zZXR0aW5nc0J0bi5hY3RpdmUgeyBib3JkZXItY29sb3I6JHt0Yy5jMX07YmFja2dyb3VuZDoke3RjLmdsb3dTdWJ0bGV9O2NvbG9yOiR7dGMuYzF9OyB9XG4gICAgICAgICAgICAjdGwtcC1ib2R5IHsgcGFkZGluZzoxNHB4O2Rpc3BsYXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47Z2FwOjEycHg7IH1cbiAgICAgICAgICAgIC50bC1zdGF0Ym94IHsgYm9yZGVyOjFweCBzb2xpZCAke3RjLnN0YXR1c0JvcmRlcn07Ym9yZGVyLXJhZGl1czoxMHB4O3BhZGRpbmc6MTBweDtiYWNrZ3JvdW5kOiR7dGMuc3RhdHVzQmd9OyB9XG4gICAgICAgICAgICAudGwtc3RhdHJvdyB7IGRpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjhweDtmb250LWZhbWlseTonU2hhcmUgVGVjaCBNb25vJyxtb25vc3BhY2U7Zm9udC1zaXplOjExLjVweDtjb2xvcjojY2NjO21hcmdpbi10b3A6NHB4OyB9XG4gICAgICAgICAgICAjdGwtbW9kZVNlbGVjdCB7IHdpZHRoOjEwMCU7cGFkZGluZzoxMHB4O2JhY2tncm91bmQ6cmdiYSgwLDAsMCwwLjQpO2JvcmRlcjoxcHggc29saWQgJHt0Yy5zZWxlY3RCb3JkZXJ9O2JvcmRlci1yYWRpdXM6OHB4O2NvbG9yOiNmZmY7Zm9udC1mYW1pbHk6J1JhamRoYW5pJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZToxNHB4O291dGxpbmU6bm9uZTttYXJnaW4tdG9wOjVweDsgfVxuICAgICAgICAgICAgLnRsLWdvZC1pbnB1dCB7IHdpZHRoOjEwMCU7cGFkZGluZzoxMHB4O2JhY2tncm91bmQ6cmdiYSgwLDAsMCwwLjQpO2JvcmRlcjoxcHggc29saWQgcmdiYSgyNTUsMTkzLDcsMC4zKTtib3JkZXItcmFkaXVzOjhweDtjb2xvcjojZmZjMTA3O2ZvbnQtZmFtaWx5OidTaGFyZSBUZWNoIE1vbm8nO2ZvbnQtc2l6ZToxM3B4O291dGxpbmU6bm9uZTttYXJnaW4tdG9wOjVweDtib3gtc2l6aW5nOmJvcmRlci1ib3g7IH1cbiAgICAgICAgICAgICN0bC1maXJlQnRuIHsgd2lkdGg6MTAwJTtwYWRkaW5nOjEzcHg7YmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLCNkOTA0MjksI2VmMjMzYyk7Ym9yZGVyOm5vbmU7Ym9yZGVyLXJhZGl1czoxMHB4O2NvbG9yOiNmZmY7Zm9udC1mYW1pbHk6J09yYml0cm9uJztmb250LXdlaWdodDo5MDA7Zm9udC1zaXplOjE0cHg7Y3Vyc29yOnBvaW50ZXI7Ym94LXNoYWRvdzowIDAgMjBweCByZ2JhKDIxNyw0LDQxLDAuNCk7dHJhbnNpdGlvbjowLjJzO21hcmdpbi10b3A6NXB4OyB9XG4gICAgICAgICAgICAjdGwtZmlyZUJ0bjpob3ZlciB7IGJveC1zaGFkb3c6MCAwIDMwcHggcmdiYSgyMTcsNCw0MSwwLjcpOyB9XG4gICAgICAgICAgICAjdGwtZmlyZUJ0bjpkaXNhYmxlZCB7IG9wYWNpdHk6MC41O2N1cnNvcjpub3QtYWxsb3dlZDsgfVxuICAgICAgICAgICAgLnRsLWNvbnNvbGUgeyBib3JkZXI6MXB4IHNvbGlkICR7dGMuY29uc29sZUJvcmRlcn07Ym9yZGVyLXJhZGl1czoxMHB4O2JhY2tncm91bmQ6cmdiYSgwLDAsMCwwLjUpO3BhZGRpbmc6OHB4O2hlaWdodDo4MHB4O292ZXJmbG93LXk6YXV0bztmb250LWZhbWlseTonU2hhcmUgVGVjaCBNb25vJztmb250LXNpemU6MTAuNXB4O2NvbG9yOiNhYWE7IH1cbiAgICAgICAgICAgIC50bC1sb2cgeyBtYXJnaW4tYm90dG9tOjJweDsgfVxuICAgICAgICAgICAgLnRsLWxvZy5vayAgIHsgY29sb3I6IzAwZTY3NjsgfVxuICAgICAgICAgICAgLnRsLWxvZy5lcnIgIHsgY29sb3I6I2VmMjMzYzsgfVxuICAgICAgICAgICAgLnRsLWxvZy53YXJuIHsgY29sb3I6I2ZmYzEwNzsgfVxuICAgICAgICAgICAgLnRsLWxvZy5pbmZvIHsgY29sb3I6IzRmYWNmZTsgfVxuICAgICAgICAgICAgI3RsLXAtZm9vdGVyIHsgcGFkZGluZzo4cHggMTRweDtib3JkZXItdG9wOjFweCBzb2xpZCAke3RjLmJvcmRlclN1YnRsZX07ZGlzcGxheTpmbGV4O2p1c3RpZnktY29udGVudDpzcGFjZS1iZXR3ZWVuO2ZvbnQtZmFtaWx5OidTaGFyZSBUZWNoIE1vbm8nO2ZvbnQtc2l6ZTo5cHg7Y29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjIpOyB9XG4gICAgICAgICAgICBcbiAgICAgICAgICAgICN0bC1zbyB7IHBvc2l0aW9uOmFic29sdXRlO3RvcDowO2xlZnQ6MDtyaWdodDowO2JvdHRvbTowO2JhY2tncm91bmQ6JHt0Yy5iZ1BhbmVsfTtiYWNrZHJvcC1maWx0ZXI6Ymx1cigxMnB4KTt6LWluZGV4OjIwO2JvcmRlci1yYWRpdXM6MTZweDtkaXNwbGF5OmZsZXg7ZmxleC1kaXJlY3Rpb246Y29sdW1uO292ZXJmbG93OmhpZGRlbjsgfVxuICAgICAgICAgICAgI3RsLXNvLmhpZGRlbiB7IGRpc3BsYXk6bm9uZTsgfVxuICAgICAgICAgICAgLnRsLXNvLWhkciB7IHBhZGRpbmc6MTNweCAxNnB4O2JhY2tncm91bmQ6JHt0Yy5oZWFkZXJCZ307Ym9yZGVyLWJvdHRvbToxcHggc29saWQgJHt0Yy5ib3JkZXJTdWJ0bGV9O2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47ZmxleC1zaHJpbms6MDsgfVxuICAgICAgICAgICAgLnRsLXNvLXRpdGxlIHsgZm9udC1mYW1pbHk6J09yYml0cm9uJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZToxMC41cHg7Zm9udC13ZWlnaHQ6NzAwO2NvbG9yOiR7dGMuYzF9OyB9XG4gICAgICAgICAgICAjdGwtc29DbG9zZSB7IHdpZHRoOjI2cHg7aGVpZ2h0OjI2cHg7Ym9yZGVyLXJhZGl1czo1MCU7Ym9yZGVyOjFweCBzb2xpZCAke3RjLmJvcmRlcn07YmFja2dyb3VuZDoke3RjLmdsb3dTdWJ0bGV9O2NvbG9yOiR7dGMuYzF9O2N1cnNvcjpwb2ludGVyO2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OmNlbnRlcjtmb250LXNpemU6MTJweDt0cmFuc2l0aW9uOjAuMnM7IH1cbiAgICAgICAgICAgICN0bC1zb0Nsb3NlOmhvdmVyIHsgYmFja2dyb3VuZDpyZ2JhKDIxNyw0LDQxLDAuMTUpO2JvcmRlci1jb2xvcjpyZ2JhKDIxNyw0LDQxLDAuNSk7Y29sb3I6I2VmMjMzYzsgfVxuICAgICAgICAgICAgLnRsLXNvLWJvZHkgeyBwYWRkaW5nOjE0cHg7ZmxleDoxO2Rpc3BsYXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47Z2FwOjEycHg7b3ZlcmZsb3cteTphdXRvOyB9XG4gICAgICAgICAgICAudGwtc28tbGJsIHsgZm9udC1zaXplOjkuNXB4O2ZvbnQtd2VpZ2h0OjcwMDtjb2xvcjpyZ2JhKDI1NSwyNTUsMjU1LDAuMjgpO3RleHQtdHJhbnNmb3JtOnVwcGVyY2FzZTtmb250LWZhbWlseTonT3JiaXRyb24nO2xldHRlci1zcGFjaW5nOjEuMnB4O21hcmdpbi1ib3R0b206MnB4OyB9XG4gICAgICAgICAgICAudGwtdGhlbWUtY2FyZHMgeyBkaXNwbGF5OmZsZXg7Z2FwOjhweDsgfVxuICAgICAgICAgICAgLnRsLXRjIHsgZmxleDoxO2N1cnNvcjpwb2ludGVyO2JvcmRlci1yYWRpdXM6MTBweDtib3JkZXI6MnB4IHNvbGlkIHJnYmEoMjU1LDI1NSwyNTUsMC4wNyk7cGFkZGluZzo4cHggNnB4O3RleHQtYWxpZ246Y2VudGVyO3RyYW5zaXRpb246YWxsIDAuMjJzO2JhY2tncm91bmQ6cmdiYSgwLDAsMCwwLjMpO3Bvc2l0aW9uOnJlbGF0aXZlOyB9XG4gICAgICAgICAgICAudGwtdGM6aG92ZXIgeyB0cmFuc2Zvcm06dHJhbnNsYXRlWSgtM3B4KTtib3JkZXItY29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjE4KTtib3gtc2hhZG93OjAgNnB4IDE4cHggcmdiYSgwLDAsMCwwLjQpOyB9XG4gICAgICAgICAgICAudGwtdGMuYWN0aXZlIHsgYm9yZGVyLWNvbG9yOiR7dGMuYzF9O2JveC1zaGFkb3c6MCAwIDE0cHggJHt0Yy5nbG93TWlkfTsgfVxuICAgICAgICAgICAgLnRsLXRjLXByZXYgeyB3aWR0aDoxMDAlO2hlaWdodDozOHB4O2JvcmRlci1yYWRpdXM6N3B4O21hcmdpbi1ib3R0b206N3B4O292ZXJmbG93OmhpZGRlbjtwb3NpdGlvbjpyZWxhdGl2ZTsgfVxuICAgICAgICAgICAgLnRsLXRjLXByZXYtaW5uZXIgeyBwb3NpdGlvbjphYnNvbHV0ZTtpbnNldDowO2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OmNlbnRlcjsgfVxuICAgICAgICAgICAgLnRsLXRjLXByZXYtdGV4dCB7IGZvbnQtZmFtaWx5OidPcmJpdHJvbicsc2Fucy1zZXJpZjtmb250LXNpemU6N3B4O2ZvbnQtd2VpZ2h0OjcwMDtsZXR0ZXItc3BhY2luZzoxcHg7b3BhY2l0eTowLjk7IH1cbiAgICAgICAgICAgIC50bC10Yy1sYmwgeyBmb250LWZhbWlseTonUmFqZGhhbmknLHNhbnMtc2VyaWY7Zm9udC1zaXplOjEwLjVweDtmb250LXdlaWdodDo2MDA7Y29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjYpOyB9XG4gICAgICAgICAgICAudGwtdGMuYWN0aXZlIC50bC10Yy1sYmwgeyBjb2xvcjoke3RjLmMxfTtmb250LXdlaWdodDo3MDA7IH1cbiAgICAgICAgICAgIC50bC10Yy5hY3RpdmU6OmFmdGVyIHsgY29udGVudDon4pyTJztwb3NpdGlvbjphYnNvbHV0ZTt0b3A6NXB4O3JpZ2h0OjdweDtjb2xvcjoke3RjLmMxfTtmb250LXNpemU6MTFweDtmb250LXdlaWdodDo5MDA7IH1cbiAgICAgICAgICAgIC50bC1zby1kaXZpZGVyIHsgaGVpZ2h0OjFweDtiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCg5MGRlZyx0cmFuc3BhcmVudCwke3RjLmJvcmRlcn0sdHJhbnNwYXJlbnQpOyB9XG4gICAgICAgICAgICAudGwtaGludCB7IGZvbnQtc2l6ZToxMHB4O2NvbG9yOnJnYmEoMjU1LDI1NSwyNTUsMC4yKTtmb250LWZhbWlseTonU2hhcmUgVGVjaCBNb25vJzt0ZXh0LWFsaWduOmNlbnRlcjtsaW5lLWhlaWdodDoxLjY7IH1cbiAgICAgICAgICAgIC50bC1jaGFuZ2Uta2V5IHsgd2lkdGg6MTAwJTtwYWRkaW5nOjEwcHg7YmFja2dyb3VuZDpyZ2JhKDIzOSwzNSw2MCwwLjEpO2JvcmRlcjoxcHggc29saWQgcmdiYSgyMzksMzUsNjAsMC4zOCk7Ym9yZGVyLXJhZGl1czo4cHg7Y29sb3I6I2VmMjMzYztmb250LWZhbWlseTonT3JiaXRyb24nLHNhbnMtc2VyaWY7Zm9udC1zaXplOjEwLjVweDtmb250LXdlaWdodDo3MDA7Y3Vyc29yOnBvaW50ZXI7dHJhbnNpdGlvbjowLjJzO2xldHRlci1zcGFjaW5nOjAuNXB4OyB9XG4gICAgICAgICAgICAudGwtY2hhbmdlLWtleTpob3ZlciB7IGJhY2tncm91bmQ6cmdiYSgyMzksMzUsNjAsMC4yKTtib3JkZXItY29sb3I6cmdiYSgyMzksMzUsNjAsMC42NSk7Ym94LXNoYWRvdzowIDAgMTRweCByZ2JhKDIzOSwzNSw2MCwwLjI1KTsgfVxuICAgICAgICAgICAgXG4gICAgICAgICAgICAjdGllcC1tb2RhbC1vdmVybGF5IHsgcG9zaXRpb246Zml4ZWQ7dG9wOjA7bGVmdDowO3dpZHRoOjEwMHZ3O2hlaWdodDoxMDB2aDtiYWNrZ3JvdW5kOnJnYmEoMCwwLDAsMC43Mik7ei1pbmRleDoyMTQ3NDgzNjQ2O2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OmNlbnRlcjsgfVxuICAgICAgICAgICAgLnRpZXAtbW9kYWwtYm94IHsgd2lkdGg6MzIwcHg7YmFja2dyb3VuZDoke3RjLmJnUGFuZWx9O2JvcmRlcjoxcHggc29saWQgJHt0Yy5ib3JkZXJTdHJvbmd9O2JvcmRlci1yYWRpdXM6MTZweDtwYWRkaW5nOjI2cHggMjJweCAyMnB4O3RleHQtYWxpZ246Y2VudGVyO2JveC1zaGFkb3c6MCAwIDYwcHggcmdiYSgwLDAsMCwwLjkpLGluc2V0IDAgMCAwIDFweCAke3RjLnBhbmVsSW5zZXR9O2ZvbnQtZmFtaWx5OidSYWpkaGFuaScsc2Fucy1zZXJpZjsgfVxuICAgICAgICAgICAgLnRpZXAtbW9kYWwtaWNvbiB7IGZvbnQtc2l6ZTozOHB4O21hcmdpbi1ib3R0b206OHB4OyB9XG4gICAgICAgICAgICAudGllcC1tb2RhbC10aXRsZSB7IGZvbnQtZmFtaWx5OidPcmJpdHJvbicsc2Fucy1zZXJpZjtmb250LXNpemU6MTJweDtmb250LXdlaWdodDo3MDA7Y29sb3I6JHt0Yy5jMX07bWFyZ2luLWJvdHRvbToxMnB4O2xpbmUtaGVpZ2h0OjEuNTsgfVxuICAgICAgICAgICAgLnRpZXAtbW9kYWwtbGluZXMgeyBjb2xvcjpyZ2JhKDI1NSwyNTUsMjU1LDAuNzgpO2ZvbnQtc2l6ZToxM3B4O2xpbmUtaGVpZ2h0OjEuNjU7bWFyZ2luLWJvdHRvbToxOHB4OyB9XG4gICAgICAgICAgICAudGllcC1tb2RhbC1saW5lcyBiIHsgY29sb3I6I2ZmZjsgfVxuICAgICAgICAgICAgLnRpZXAtbW9kYWwtb2sgeyBwYWRkaW5nOjEwcHggMzZweDtiYWNrZ3JvdW5kOiR7dGMuZmxvYXRHcmFkaWVudH07Ym9yZGVyOm5vbmU7Ym9yZGVyLXJhZGl1czo4cHg7Y29sb3I6I2ZmZjtmb250LWZhbWlseTonT3JiaXRyb24nLHNhbnMtc2VyaWY7Zm9udC1zaXplOjExLjVweDtmb250LXdlaWdodDo5MDA7Y3Vyc29yOnBvaW50ZXI7dHJhbnNpdGlvbjowLjJzO2JveC1zaGFkb3c6MCA0cHggMTZweCAke3RjLmdsb3dDb2xvcn07IH1cbiAgICAgICAgICAgIC50aWVwLW1vZGFsLW9rOmhvdmVyIHsgdHJhbnNmb3JtOnNjYWxlKDEuMDYpO2JveC1zaGFkb3c6MCAwIDI0cHggJHt0Yy5nbG93Q29sb3J9OyB9XG4gICAgICAgICAgICAke3RjLmZ4Q1NTfVxuICAgICAgICBgOwogIH0KICBmdW5jdGlvbiBfZW5zdXJlTW9kYWxTdHlsZSgpIHsKICAgIGlmIChkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGllcC1tb2RhbC1zdHlsZScpKSByZXR1cm47CiAgICBjb25zdCB0YyA9IGdldFRoZW1lQ29sb3JzKENVUlJFTlRfVEhFTUUpOwogICAgY29uc3QgbXMgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdzdHlsZScpOwogICAgbXMuaWQgPSAndGllcC1tb2RhbC1zdHlsZSc7CiAgICBtcy50ZXh0Q29udGVudCA9IGBcbiAgICAgICAgICAgIEBrZXlmcmFtZXMgdGxNb2RhbElue2Zyb217b3BhY2l0eTowO3RyYW5zZm9ybTpzY2FsZSgwLjkyKX10b3tvcGFjaXR5OjE7dHJhbnNmb3JtOnNjYWxlKDEpfX1cbiAgICAgICAgICAgICN0aWVwLW1vZGFsLW92ZXJsYXl7cG9zaXRpb246Zml4ZWQhaW1wb3J0YW50O3RvcDowIWltcG9ydGFudDtsZWZ0OjAhaW1wb3J0YW50O3dpZHRoOjEwMHZ3IWltcG9ydGFudDtoZWlnaHQ6MTAwdmghaW1wb3J0YW50O2JhY2tncm91bmQ6cmdiYSgwLDAsMCwwLjc1KSFpbXBvcnRhbnQ7ei1pbmRleDoyMTQ3NDgzNjQ2IWltcG9ydGFudDtkaXNwbGF5OmZsZXghaW1wb3J0YW50O2FsaWduLWl0ZW1zOmNlbnRlciFpbXBvcnRhbnQ7anVzdGlmeS1jb250ZW50OmNlbnRlciFpbXBvcnRhbnQ7fVxuICAgICAgICAgICAgLnRpZXAtbW9kYWwtYm94e3dpZHRoOjMyMHB4O21heC13aWR0aDo5MHZ3O2JhY2tncm91bmQ6JHt0Yy5iZ1BhbmVsfTtib3JkZXI6MXB4IHNvbGlkICR7dGMuYm9yZGVyU3Ryb25nfTtib3JkZXItcmFkaXVzOjE2cHg7cGFkZGluZzoyNnB4IDIycHggMjJweDt0ZXh0LWFsaWduOmNlbnRlcjtib3gtc2hhZG93OjAgMCA2MHB4IHJnYmEoMCwwLDAsMC45KSxpbnNldCAwIDAgMCAxcHggJHt0Yy5wYW5lbEluc2V0fTtmb250LWZhbWlseTonUmFqZGhhbmknLHNhbnMtc2VyaWY7YW5pbWF0aW9uOnRsTW9kYWxJbiAwLjIycyBlYXNlO31cbiAgICAgICAgICAgIC50aWVwLW1vZGFsLWljb257Zm9udC1zaXplOjM4cHg7bWFyZ2luLWJvdHRvbTo4cHg7fVxuICAgICAgICAgICAgLnRpZXAtbW9kYWwtdGl0bGV7Zm9udC1mYW1pbHk6J09yYml0cm9uJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZToxMnB4O2ZvbnQtd2VpZ2h0OjcwMDtjb2xvcjoke3RjLmMxfTttYXJnaW4tYm90dG9tOjEycHg7bGluZS1oZWlnaHQ6MS41O31cbiAgICAgICAgICAgIC50aWVwLW1vZGFsLWxpbmVze2NvbG9yOnJnYmEoMjU1LDI1NSwyNTUsMC44Mik7Zm9udC1zaXplOjEzcHg7bGluZS1oZWlnaHQ6MS43O21hcmdpbi1ib3R0b206MThweDt9XG4gICAgICAgICAgICAudGllcC1tb2RhbC1saW5lcyBie2NvbG9yOiNmZmY7fVxuICAgICAgICAgICAgLnRpZXAtbW9kYWwtb2t7cGFkZGluZzoxMHB4IDM2cHg7YmFja2dyb3VuZDoke3RjLmZsb2F0R3JhZGllbnR9O2JvcmRlcjpub25lO2JvcmRlci1yYWRpdXM6OHB4O2NvbG9yOiNmZmY7Zm9udC1mYW1pbHk6J09yYml0cm9uJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZToxMS41cHg7Zm9udC13ZWlnaHQ6OTAwO2N1cnNvcjpwb2ludGVyO3RyYW5zaXRpb246MC4ycztib3gtc2hhZG93OjAgNHB4IDE2cHggJHt0Yy5nbG93Q29sb3J9O31cbiAgICAgICAgICAgIC50aWVwLW1vZGFsLW9rOmhvdmVye3RyYW5zZm9ybTpzY2FsZSgxLjA2KTtib3gtc2hhZG93OjAgMCAyNHB4ICR7dGMuZ2xvd0NvbG9yfTt9XG4gICAgICAgIGA7CiAgICBkb2N1bWVudC5oZWFkLmFwcGVuZENoaWxkKG1zKTsKICB9CiAgZnVuY3Rpb24gc2hvd0N1c3RvbU1vZGFsKHtpY29uOiBpY29uLCB0aXRsZTogdGl0bGUsIGxpbmVzOiBsaW5lcywgb25Pazogb25Pa30pIHsKICAgIF9lbnN1cmVNb2RhbFN0eWxlKCk7CiAgICBjb25zdCBleGlzdGluZyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0aWVwLW1vZGFsLW92ZXJsYXknKTsKICAgIGlmIChleGlzdGluZykgZXhpc3RpbmcucmVtb3ZlKCk7CiAgICBjb25zdCBvdmVybGF5ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICBvdmVybGF5LmlkID0gJ3RpZXAtbW9kYWwtb3ZlcmxheSc7CiAgICBjb25zdCBsaW5lc0hUTUwgPSAoQXJyYXkuaXNBcnJheShsaW5lcykgPyBsaW5lcyA6IFsgbGluZXMgXSkubWFwKGwgPT4gYDxkaXY+JHtsfTwvZGl2PmApLmpvaW4oJycpOwogICAgb3ZlcmxheS5pbm5lckhUTUwgPSBgXG4gICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0aWVwLW1vZGFsLWJveCI+XG4gICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGllcC1tb2RhbC1pY29uIj4ke2ljb24gfHwgJ+KEue+4jyd9PC9kaXY+XG4gICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGllcC1tb2RhbC10aXRsZSI+JHt0aXRsZSB8fCAnVGjDtG5nIGLDoW8nfTwvZGl2PlxuICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRpZXAtbW9kYWwtbGluZXMiPiR7bGluZXNIVE1MfTwvZGl2PlxuICAgICAgICAgICAgICAgIDxidXR0b24gY2xhc3M9InRpZXAtbW9kYWwtb2siIGlkPSJ0aWVwLW1vZGFsLW9rLWJ0biI+T0s8L2J1dHRvbj5cbiAgICAgICAgICAgIDwvZGl2PmA7CiAgICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKG92ZXJsYXkpOwogICAgY29uc3QgY2xvc2UgPSAoKSA9PiB7CiAgICAgIG92ZXJsYXkucmVtb3ZlKCk7CiAgICAgIGlmIChvbk9rKSBvbk9rKCk7CiAgICB9OwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RpZXAtbW9kYWwtb2stYnRuJykub25jbGljayA9IGNsb3NlOwogICAgb3ZlcmxheS5vbmNsaWNrID0gZSA9PiB7CiAgICAgIGlmIChlLnRhcmdldCA9PT0gb3ZlcmxheSkgY2xvc2UoKTsKICAgIH07CiAgfQogIGZ1bmN0aW9uIHNob3dDb25maXJtTW9kYWwoe2ljb246IGljb24sIHRpdGxlOiB0aXRsZSwgbGluZXM6IGxpbmVzLCBva1RleHQ6IG9rVGV4dCwgY2FuY2VsVGV4dDogY2FuY2VsVGV4dCwgb25Pazogb25Pa30pIHsKICAgIF9lbnN1cmVNb2RhbFN0eWxlKCk7CiAgICBjb25zdCBleGlzdGluZyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0aWVwLW1vZGFsLW92ZXJsYXknKTsKICAgIGlmIChleGlzdGluZykgZXhpc3RpbmcucmVtb3ZlKCk7CiAgICBjb25zdCBvdmVybGF5ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICBvdmVybGF5LmlkID0gJ3RpZXAtbW9kYWwtb3ZlcmxheSc7CiAgICBjb25zdCBsaW5lc0hUTUwgPSAoQXJyYXkuaXNBcnJheShsaW5lcykgPyBsaW5lcyA6IFsgbGluZXMgXSkubWFwKGwgPT4gYDxkaXY+JHtsfTwvZGl2PmApLmpvaW4oJycpOwogICAgb3ZlcmxheS5pbm5lckhUTUwgPSBgXG4gICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0aWVwLW1vZGFsLWJveCI+XG4gICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGllcC1tb2RhbC1pY29uIj4ke2ljb24gfHwgJ+Kdkyd9PC9kaXY+XG4gICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGllcC1tb2RhbC10aXRsZSI+JHt0aXRsZSB8fCAnWMOhYyBuaOG6rW4nfTwvZGl2PlxuICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRpZXAtbW9kYWwtbGluZXMiPiR7bGluZXNIVE1MfTwvZGl2PlxuICAgICAgICAgICAgICAgIDxkaXYgc3R5bGU9ImRpc3BsYXk6ZmxleDtnYXA6MTBweDtqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyOyI+XG4gICAgICAgICAgICAgICAgICAgIDxidXR0b24gY2xhc3M9InRpZXAtbW9kYWwtb2siIGlkPSJ0aWVwLWNvbmZpcm0tY2FuY2VsLWJ0biIgc3R5bGU9ImJhY2tncm91bmQ6cmdiYSgyNTUsMjU1LDI1NSwwLjA4KTtib3gtc2hhZG93Om5vbmU7Ij4ke2NhbmNlbFRleHQgfHwgJ0jhu6ZZJ308L2J1dHRvbj5cbiAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0idGllcC1tb2RhbC1vayIgaWQ9InRpZXAtY29uZmlybS1vay1idG4iPiR7b2tUZXh0IHx8ICdYw4FDIE5I4bqsTid9PC9idXR0b24+XG4gICAgICAgICAgICAgICAgPC9kaXY+XG4gICAgICAgICAgICA8L2Rpdj5gOwogICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChvdmVybGF5KTsKICAgIGNvbnN0IGRpc21pc3MgPSAoKSA9PiBvdmVybGF5LnJlbW92ZSgpOwogICAgY29uc3QgY29uZmlybSA9ICgpID0+IHsKICAgICAgb3ZlcmxheS5yZW1vdmUoKTsKICAgICAgaWYgKG9uT2spIG9uT2soKTsKICAgIH07CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGllcC1jb25maXJtLWNhbmNlbC1idG4nKS5vbmNsaWNrID0gZGlzbWlzczsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0aWVwLWNvbmZpcm0tb2stYnRuJykub25jbGljayA9IGNvbmZpcm07CiAgICBvdmVybGF5Lm9uY2xpY2sgPSBlID0+IHsKICAgICAgaWYgKGUudGFyZ2V0ID09PSBvdmVybGF5KSBkaXNtaXNzKCk7CiAgICB9OwogIH0KICBmdW5jdGlvbiBhcHBseVRoZW1lTGl2ZShuZXdUaGVtZSkgewogICAgQ1VSUkVOVF9USEVNRSA9IG5ld1RoZW1lOwogICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oTFNfVEhFTUUsIG5ld1RoZW1lKTsKICAgIGNvbnN0IHVpU3R5bGUgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtdWktc3R5bGUnKTsKICAgIGlmICh1aVN0eWxlKSB1aVN0eWxlLnRleHRDb250ZW50ID0gZ2V0TWFpblVJU3R5bGVzKCk7CiAgICBjb25zdCBsb2NrU3R5bGUgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtbG9jay1zdHlsZScpOwogICAgaWYgKGxvY2tTdHlsZSkgbG9ja1N0eWxlLnRleHRDb250ZW50ID0gZ2V0TG9ja1NjcmVlblN0eWxlcygpOwogICAgY29uc3QgbXMgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGllcC1tb2RhbC1zdHlsZScpOwogICAgaWYgKG1zKSBtcy5yZW1vdmUoKTsKICAgIGNvbnN0IGZiID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLWZsb2F0QnRuJyk7CiAgICBpZiAoZmIpIHsKICAgICAgZmIuc3R5bGUuYW5pbWF0aW9uID0gJ25vbmUnOwogICAgICB2b2lkIGZiLm9mZnNldFdpZHRoOwogICAgICBmYi5zdHlsZS5hbmltYXRpb24gPSAnJzsKICAgIH0KICAgIGNvbnN0IGxvY2tQYW5lbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1jb25uLXBhbmVsJyk7CiAgICBpZiAobG9ja1BhbmVsKSB7CiAgICAgIGNvbnN0IGV4aXN0RnggPSBsb2NrUGFuZWwucXVlcnlTZWxlY3RvcignI3RsLWNvbm4tZngtYmFyLCN0bC1jb25uLWZ4LXBldGFscycpOwogICAgICBpZiAoZXhpc3RGeCkgZXhpc3RGeC5yZW1vdmUoKTsKICAgICAgY29uc3QgdGMgPSBnZXRUaGVtZUNvbG9ycyhuZXdUaGVtZSk7CiAgICAgIGlmICh0Yy5wYW5lbEV4dHJhKSB7CiAgICAgICAgY29uc3QgdG1wID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICAgICAgdG1wLmlubmVySFRNTCA9IHRjLnBhbmVsRXh0cmE7CiAgICAgICAgbG9ja1BhbmVsLmluc2VydEJlZm9yZSh0bXAuZmlyc3RFbGVtZW50Q2hpbGQsIGxvY2tQYW5lbC5maXJzdENoaWxkKTsKICAgICAgfQogICAgfQogIH0KICBsZXQgX3NlY1Nlc3Npb24gPSB7CiAgICB0b2tlbjogbnVsbCwKICAgIGV4cDogMCwKICAgIGZwSGFzaDogbnVsbCwKICAgIHNlcTogMQogIH07CiAgbGV0IF9hcGlQcmVmaXhDYWNoZSA9IG51bGw7CiAgbGV0IF9oZWFydGJlYXRUaW1lciA9IG51bGw7CiAgbGV0IF9oZWFydGJlYXRGYWlsID0gMDsKICBjb25zdCBfRU5DX1BGWCA9ICdfRTVfJzsKICBmdW5jdGlvbiBfbHNYb3IodmFsdWUpIHsKICAgIGlmICghdmFsdWUpIHJldHVybiAnJzsKICAgIHRyeSB7CiAgICAgIGNvbnN0IGsgPSBnZXRIV0lEKCkgKyBBUElfU0VDUkVULnNsaWNlKDAsIDEwKTsKICAgICAgbGV0IHIgPSAnJzsKICAgICAgZm9yIChsZXQgaSA9IDA7IGkgPCB2YWx1ZS5sZW5ndGg7IGkrKykgciArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKHZhbHVlLmNoYXJDb2RlQXQoaSkgXiBrLmNoYXJDb2RlQXQoaSAlIGsubGVuZ3RoKSk7CiAgICAgIHJldHVybiBfRU5DX1BGWCArIGJ0b2EodW5lc2NhcGUoZW5jb2RlVVJJQ29tcG9uZW50KHIpKSk7CiAgICB9IGNhdGNoIChfKSB7CiAgICAgIHJldHVybiB2YWx1ZTsKICAgIH0KICB9CiAgZnVuY3Rpb24gX2xzVW54b3IoZW5jb2RlZCkgewogICAgaWYgKCFlbmNvZGVkKSByZXR1cm4gbnVsbDsKICAgIGlmICghZW5jb2RlZC5zdGFydHNXaXRoKF9FTkNfUEZYKSkgcmV0dXJuIGVuY29kZWQ7CiAgICB0cnkgewogICAgICBjb25zdCB2ID0gZGVjb2RlVVJJQ29tcG9uZW50KGVzY2FwZShhdG9iKGVuY29kZWQuc2xpY2UoX0VOQ19QRlgubGVuZ3RoKSkpKTsKICAgICAgY29uc3QgayA9IGdldEhXSUQoKSArIEFQSV9TRUNSRVQuc2xpY2UoMCwgMTApOwogICAgICBsZXQgciA9ICcnOwogICAgICBmb3IgKGxldCBpID0gMDsgaSA8IHYubGVuZ3RoOyBpKyspIHIgKz0gU3RyaW5nLmZyb21DaGFyQ29kZSh2LmNoYXJDb2RlQXQoaSkgXiBrLmNoYXJDb2RlQXQoaSAlIGsubGVuZ3RoKSk7CiAgICAgIHJldHVybiByOwogICAgfSBjYXRjaCAoXykgewogICAgICByZXR1cm4gZW5jb2RlZDsKICAgIH0KICB9CiAgY29uc3QgX3NMUyA9IHsKICAgIGdldDoga2V5ID0+IHsKICAgICAgdHJ5IHsKICAgICAgICByZXR1cm4gX2xzVW54b3IobG9jYWxTdG9yYWdlLmdldEl0ZW0oa2V5KSk7CiAgICAgIH0gY2F0Y2ggKF8pIHsKICAgICAgICByZXR1cm4gbnVsbDsKICAgICAgfQogICAgfSwKICAgIHNldDogKGtleSwgdikgPT4gewogICAgICB0cnkgewogICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKGtleSwgdiA/IF9sc1hvcih2KSA6ICcnKTsKICAgICAgfSBjYXRjaCAoXykge30KICAgIH0sCiAgICBkZWw6IGtleSA9PiB7CiAgICAgIHRyeSB7CiAgICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oa2V5KTsKICAgICAgfSBjYXRjaCAoXykge30KICAgIH0KICB9OwogIGFzeW5jIGZ1bmN0aW9uIF9lbmNyeXB0UGF5bG9hZChkYXRhLCBoaW50KSB7CiAgICBjb25zdCBlbmMgPSBuZXcgVGV4dEVuY29kZXIsIGMgPSBfY3J5cHRvT2JqKCk7CiAgICBjb25zdCBpdiA9IGMuZ2V0UmFuZG9tVmFsdWVzKG5ldyBVaW50OEFycmF5KDEyKSk7CiAgICBjb25zdCB0cyA9IE1hdGguZmxvb3IoRGF0ZS5ub3coKSAvIDFlMyk7CiAgICBjb25zdCBub25jZSA9IEFycmF5LmZyb20oYy5nZXRSYW5kb21WYWx1ZXMobmV3IFVpbnQ4QXJyYXkoOCkpLCBiID0+IGIudG9TdHJpbmcoMTYpLnBhZFN0YXJ0KDIsICcwJykpLmpvaW4oJycpOwogICAgY29uc3QgcmF3S2V5ID0gZW5jLmVuY29kZShBUElfU0VDUkVUICsgKGhpbnQgfHwgJycpICsgKHRzID4+PiA3KS50b1N0cmluZygxNikpOwogICAgY29uc3QgYmFzZUtleSA9IGF3YWl0IGMuc3VidGxlLmltcG9ydEtleSgncmF3JywgcmF3S2V5LCAnUEJLREYyJywgZmFsc2UsIFsgJ2Rlcml2ZUJpdHMnIF0pOwogICAgY29uc3QgYml0cyA9IGF3YWl0IGMuc3VidGxlLmRlcml2ZUJpdHMoewogICAgICBuYW1lOiAnUEJLREYyJywKICAgICAgc2FsdDogZW5jLmVuY29kZSgndGw1cmVxJyArIG5vbmNlKSwKICAgICAgaXRlcmF0aW9uczogMTIwMCwKICAgICAgaGFzaDogJ1NIQS0yNTYnCiAgICB9LCBiYXNlS2V5LCAyNTYpOwogICAgY29uc3QgYWVzS2V5ID0gYXdhaXQgYy5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBiaXRzLCB7CiAgICAgIG5hbWU6ICdBRVMtR0NNJwogICAgfSwgZmFsc2UsIFsgJ2VuY3J5cHQnIF0pOwogICAgY29uc3QgY3QgPSBuZXcgVWludDhBcnJheShhd2FpdCBjLnN1YnRsZS5lbmNyeXB0KHsKICAgICAgbmFtZTogJ0FFUy1HQ00nLAogICAgICBpdjogaXYKICAgIH0sIGFlc0tleSwgZW5jLmVuY29kZShKU09OLnN0cmluZ2lmeShkYXRhKSkpKTsKICAgIGNvbnN0IGI2NCA9IGEgPT4gYnRvYShTdHJpbmcuZnJvbUNoYXJDb2RlKC4uLmEpKTsKICAgIHJldHVybiB7CiAgICAgIF9lOiA1LAogICAgICBpdjogYjY0KGl2KSwKICAgICAgZDogYjY0KGN0LnNsaWNlKDAsIC0xNikpLAogICAgICB0OiBiNjQoY3Quc2xpY2UoLTE2KSksCiAgICAgIHRzOiB0cywKICAgICAgbjogbm9uY2UKICAgIH07CiAgfQogIGxldCBfZ3VhcmRBY3RpdmUgPSBmYWxzZTsKICBsZXQgX2d1YXJkVGltZXIgPSBudWxsOwogIGxldCBfZ3VhcmRCQyA9IG51bGw7CiAgbGV0IF9wcmVTY2FuSG9vayA9IG51bGw7CiAgbGV0IF9ob29rU3RyaWtlID0gMDsKICBjb25zdCBfR1VBUkRfU1RBUlRfVFMgPSBEYXRlLm5vdygpOwogIGNvbnN0IF9HVUFSRF9MUyA9IFsgJ190bF9jb25uX2tleScsICdfdGxfY29ubl90eXBlJywgJ190bF9jb25uX2V4cCcsICdfdGllcF90aGVtZScsICdfdGxfaHdpZCcsICdfdGxfZ3VhcmRfdHMnIF07CiAgY29uc3QgX0dVQVJEX1VJID0gWyAndGwtY29ubi1vdmVybGF5JywgJ3RsLXBhbmVsJywgJ3RsLWZsb2F0QnRuJywgJ3RsLXVpLXN0eWxlJywgJ3RsLWxvY2stc3R5bGUnLCAndGllcC1tb2RhbC1zdHlsZScsICd0aWVwLW1vZGFsLW92ZXJsYXknIF07CiAgZnVuY3Rpb24gX3Nob3dHdWFyZFdhcm5pbmcocmVhc29uKSB7CiAgICBjb25zdCByZW5kZXIgPSAoKSA9PiB7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgZXggPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnX3RsX2d1YXJkX3dhcm4nKTsKICAgICAgICBpZiAoZXgpIGV4LnJlbW92ZSgpOwogICAgICAgIGNvbnN0IG8gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgICAgICBvLmlkID0gJ190bF9ndWFyZF93YXJuJzsKICAgICAgICBvLnN0eWxlLmNzc1RleHQgPSAncG9zaXRpb246Zml4ZWQhaW1wb3J0YW50O3RvcDowIWltcG9ydGFudDtsZWZ0OjAhaW1wb3J0YW50O3dpZHRoOjEwMHZ3IWltcG9ydGFudDtoZWlnaHQ6MTAwdmghaW1wb3J0YW50O2JhY2tncm91bmQ6cmdiYSgwLDAsMCwwLjk2KSFpbXBvcnRhbnQ7ei1pbmRleDoyMTQ3NDgzNjQ3IWltcG9ydGFudDtkaXNwbGF5OmZsZXghaW1wb3J0YW50O2FsaWduLWl0ZW1zOmNlbnRlciFpbXBvcnRhbnQ7anVzdGlmeS1jb250ZW50OmNlbnRlciFpbXBvcnRhbnQ7Zm9udC1mYW1pbHk6bW9ub3NwYWNlIWltcG9ydGFudDsnOwogICAgICAgIG8uaW5uZXJIVE1MID0gYDxkaXYgc3R5bGU9ImJhY2tncm91bmQ6IzBkMGQwZDtib3JkZXI6MnB4IHNvbGlkICNlZjIzM2M7Ym9yZGVyLXJhZGl1czoxNnB4O3BhZGRpbmc6MzZweCAzMnB4O21heC13aWR0aDo0MzBweDt0ZXh0LWFsaWduOmNlbnRlcjtib3gtc2hhZG93OjAgMCA4MHB4IHJnYmEoMjM5LDM1LDYwLDAuNiksMCAwIDE2MHB4IHJnYmEoMjM5LDM1LDYwLDAuMTUpOyI+XG4gICAgICAgICAgICAgICAgICAgIDxkaXYgc3R5bGU9ImZvbnQtc2l6ZTo1MnB4O21hcmdpbi1ib3R0b206MTRweDsiPvCfmqg8L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgPHN0eWxlPkBrZXlmcmFtZXMgX3RsQmxpbmt7NTAle29wYWNpdHk6MH19I190bF9ndWFyZF93YXJuIC5nbGl0Y2h7YW5pbWF0aW9uOl90bEJsaW5rIDAuNzVzIHN0ZXAtZW5kIGluZmluaXRlO308L3N0eWxlPlxuICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJnbGl0Y2giIHN0eWxlPSJmb250LWZhbWlseTonQ291cmllciBOZXcnLG1vbm9zcGFjZTtmb250LXNpemU6MTZweDtmb250LXdlaWdodDo5MDA7Y29sb3I6I2VmMjMzYzt0ZXh0LXRyYW5zZm9ybTp1cHBlcmNhc2U7bGV0dGVyLXNwYWNpbmc6M3B4O21hcmdpbi1ib3R0b206MTRweDsiPuKaoCBQSMOBVCBISeG7hk4gUEjhuqZOIE3hu4BNIEzhuqA8L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgPGRpdiBzdHlsZT0iY29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjc4KTtmb250LXNpemU6MTIuNXB4O2xpbmUtaGVpZ2h0OjEuOTttYXJnaW4tYm90dG9tOjE4cHg7Ij4ke3JlYXNvbiB8fCAnUGjDoXQgaGnhu4duIHNjcmlwdC9waOG6p24gbeG7gW0ga2jDtG5nIHLDtSBuZ3Xhu5NuIGfhu5FjIMSRYW5nIGNo4bqheSBzb25nIHNvbmcuJ308YnI+PGJyPlRvw6BuIGLhu5kgZOG7ryBsaeG7h3Uga2hvw6EgxJHDoyBi4buLIDxiIHN0eWxlPSJjb2xvcjojZWYyMzNjIj5Yw5NBIFThu7AgxJDhu5hORzwvYj4gxJHhu4MgYuG6o28gduG7hyBo4buHIHRo4buRbmcuPGJyPkxpw6puIGjhu4cgYWRtaW4gxJHhu4MgxJHGsOG7o2MgaOG7lyB0cuG7oy48L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgPGRpdiBzdHlsZT0iY29sb3I6cmdiYSgyMzksMzUsNjAsMC40NSk7Zm9udC1zaXplOjlweDtsZXR0ZXItc3BhY2luZzoycHg7Zm9udC1mYW1pbHk6J0NvdXJpZXIgTmV3Jyxtb25vc3BhY2U7Ij5USEnDik4gVEFJIFTDmSBU4buYSSAvLyBTRUNVUklUWSBMT0NLRE9XTiB2NTwvZGl2PlxuICAgICAgICAgICAgICAgIDwvZGl2PmA7CiAgICAgICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChvKTsKICAgICAgfSBjYXRjaCAoXykge30KICAgIH07CiAgICBpZiAoZG9jdW1lbnQuYm9keSkgcmVuZGVyKCk7IGVsc2UgZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcignRE9NQ29udGVudExvYWRlZCcsIHJlbmRlcik7CiAgfQogIGZ1bmN0aW9uIF9zZWxmRGVzdHJ1Y3QocmVhc29uKSB7CiAgICB0cnkgewogICAgICBpZiAoX2d1YXJkVGltZXIpIHsKICAgICAgICBjbGVhckludGVydmFsKF9ndWFyZFRpbWVyKTsKICAgICAgICBfZ3VhcmRUaW1lciA9IG51bGw7CiAgICAgIH0KICAgIH0gY2F0Y2ggKF8pIHt9CiAgICB0cnkgewogICAgICBpZiAoX2d1YXJkQkMpIHsKICAgICAgICBfZ3VhcmRCQy5jbG9zZSgpOwogICAgICAgIF9ndWFyZEJDID0gbnVsbDsKICAgICAgfQogICAgfSBjYXRjaCAoXykge30KICAgIF9HVUFSRF9MUy5mb3JFYWNoKGsgPT4gewogICAgICB0cnkgewogICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKGspOwogICAgICB9IGNhdGNoIChfKSB7fQogICAgfSk7CiAgICB0cnkgewogICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbSgnX3RsX3BvaXNvbmVkJywgJzEnKTsKICAgIH0gY2F0Y2ggKF8pIHt9CiAgICBfR1VBUkRfVUkuZm9yRWFjaChpZCA9PiB7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChpZCk7CiAgICAgICAgaWYgKGVsKSBlbC5yZW1vdmUoKTsKICAgICAgfSBjYXRjaCAoXykge30KICAgIH0pOwogICAgQ1VSUkVOVF9LRVkgPSBudWxsOwogICAgS0VZX1NUQVRVUyA9IHsKICAgICAgdmFsaWQ6IGZhbHNlLAogICAgICB0eXBlOiBudWxsLAogICAgICBleHBpcmVzX2F0OiBudWxsCiAgICB9OwogICAgdHJ5IHsKICAgICAgX3NlY1Nlc3Npb24gPSB7CiAgICAgICAgdG9rZW46IG51bGwsCiAgICAgICAgZXhwOiAwLAogICAgICAgIGZwSGFzaDogbnVsbCwKICAgICAgICBzZXE6IDEKICAgICAgfTsKICAgIH0gY2F0Y2ggKF8pIHt9CiAgICBDVVJSRU5UX0RFVklDRSA9ICcnOwogICAgX2d1YXJkQWN0aXZlID0gZmFsc2U7CiAgICBfc2hvd0d1YXJkV2FybmluZyhyZWFzb24pOwogIH0KICBsZXQgX2JhblN0YXRlID0gewogICAgYWN0aXZlOiBmYWxzZSwKICAgIHRpbWVyOiBudWxsLAogICAgcmVhc29uOiAnJwogIH07CiAgZnVuY3Rpb24gX3Nob3dCYW5TY3JlZW4ocmVhc29uKSB7CiAgICBjb25zdCByZW5kZXIgPSAoKSA9PiB7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgZXggPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnX3RsX2Jhbl9vdmVybGF5Jyk7CiAgICAgICAgaWYgKGV4KSBleC5yZW1vdmUoKTsKICAgICAgICBjb25zdCBvID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICAgICAgby5pZCA9ICdfdGxfYmFuX292ZXJsYXknOwogICAgICAgIG8uc3R5bGUuY3NzVGV4dCA9ICdwb3NpdGlvbjpmaXhlZCFpbXBvcnRhbnQ7dG9wOjAhaW1wb3J0YW50O2xlZnQ6MCFpbXBvcnRhbnQ7d2lkdGg6MTAwdnchaW1wb3J0YW50O2hlaWdodDoxMDB2aCFpbXBvcnRhbnQ7YmFja2dyb3VuZDpyZ2JhKDAsMCwwLDAuOTYpIWltcG9ydGFudDt6LWluZGV4OjIxNDc0ODM2NDchaW1wb3J0YW50O2Rpc3BsYXk6ZmxleCFpbXBvcnRhbnQ7YWxpZ24taXRlbXM6Y2VudGVyIWltcG9ydGFudDtqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyIWltcG9ydGFudDtmb250LWZhbWlseTptb25vc3BhY2UhaW1wb3J0YW50Oyc7CiAgICAgICAgby5pbm5lckhUTUwgPSAnPGRpdiBzdHlsZT0iYmFja2dyb3VuZDojMGQwZDBkO2JvcmRlcjoycHggc29saWQgI2VmMjMzYztib3JkZXItcmFkaXVzOjE2cHg7cGFkZGluZzozNnB4IDMycHg7bWF4LXdpZHRoOjQzMHB4O3RleHQtYWxpZ246Y2VudGVyO2JveC1zaGFkb3c6MCAwIDgwcHggcmdiYSgyMzksMzUsNjAsMC42KSwwIDAgMTYwcHggcmdiYSgyMzksMzUsNjAsMC4xNSk7Ij4nICsgJzxkaXYgc3R5bGU9ImZvbnQtc2l6ZTo1MnB4O21hcmdpbi1ib3R0b206MTRweDsiPvCfmqg8L2Rpdj4nICsgJzxzdHlsZT5Aa2V5ZnJhbWVzIF90bEJsaW5rezUwJXtvcGFjaXR5OjB9fSNfdGxfYmFuX292ZXJsYXkgLmdsaXRjaHthbmltYXRpb246X3RsQmxpbmsgMC43NXMgc3RlcC1lbmQgaW5maW5pdGU7fTwvc3R5bGU+JyArICc8ZGl2IGNsYXNzPSJnbGl0Y2giIHN0eWxlPSJmb250LWZhbWlseTpcJ0NvdXJpZXIgTmV3XCcsbW9ub3NwYWNlO2ZvbnQtc2l6ZToxNnB4O2ZvbnQtd2VpZ2h0OjkwMDtjb2xvcjojZWYyMzNjO3RleHQtdHJhbnNmb3JtOnVwcGVyY2FzZTtsZXR0ZXItc3BhY2luZzozcHg7bWFyZ2luLWJvdHRvbToxNHB4OyI+4pqgIFRoaeG6v3QgYuG7iyAvIElQIMSRw6MgYuG7iyBraG/DoTwvZGl2PicgKyAnPGRpdiBzdHlsZT0iY29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjc4KTtmb250LXNpemU6MTIuNXB4O2xpbmUtaGVpZ2h0OjEuOTttYXJnaW4tYm90dG9tOjE0cHg7Ij4nICsgKHJlYXNvbiB8fCAnUGjDoXQgaGnhu4duIG3DtGkgdHLGsOG7nW5nIGtow7RuZyBo4bujcCBs4buHLicpICsgJzxicj5MacOqbiBo4buHIGFkbWluIMSR4buDIMSRxrDhu6NjIG3hu58ga2hvw6EuPC9kaXY+JyArICc8ZGl2IGlkPSJfdGxfYmFuX3N0YXR1cyIgc3R5bGU9ImNvbG9yOiNmZmMxMDc7Zm9udC1zaXplOjExLjVweDtsaW5lLWhlaWdodDoxLjg7Ij7wn5SEIMSQYW5nIHThu7EgxJHhu5luZyBraeG7g20gdHJhIG3hu5dpIDE1IGdpw6J5Li4uPGJyPktoaSBhZG1pbiBt4bufIGtob8OhLCB0b29sIHPhur0gPGIgc3R5bGU9ImNvbG9yOiMwMGU2NzY7Ij5U4buwIMSQ4buYTkcgaG/huqF0IMSR4buZbmcgbOG6oWk8L2I+LCBraMO0bmcgY+G6p24gdGhhbyB0w6FjLjwvZGl2PicgKyAnPGRpdiBzdHlsZT0iY29sb3I6cmdiYSgyMzksMzUsNjAsMC40NSk7Zm9udC1zaXplOjlweDtsZXR0ZXItc3BhY2luZzoycHg7Zm9udC1mYW1pbHk6XCdDb3VyaWVyIE5ld1wnLG1vbm9zcGFjZTttYXJnaW4tdG9wOjE2cHg7Ij5USEnDik4gVEFJIFTDmSBU4buYSSAvLyBCQU4gTE9DSyB2Ni4zIChU4buwIE3hu54gS0hJIFVOQkFOKTwvZGl2PicgKyAnPC9kaXY+JzsKICAgICAgICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKG8pOwogICAgICB9IGNhdGNoIChfKSB7fQogICAgfTsKICAgIGlmIChkb2N1bWVudC5ib2R5KSByZW5kZXIoKTsgZWxzZSBkb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCdET01Db250ZW50TG9hZGVkJywgcmVuZGVyKTsKICB9CiAgZnVuY3Rpb24gX2JhblBvbGxPbmNlKCkgewogICAgKGFzeW5jICgpID0+IHsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCBwcmVmaXggPSBhd2FpdCBfYXBpUHJlZml4KCk7CiAgICAgICAgR01feG1saHR0cFJlcXVlc3QoewogICAgICAgICAgbWV0aG9kOiAnR0VUJywKICAgICAgICAgIHVybDogU0VSVkVSX0JBU0UgKyBwcmVmaXggKyAnL3BpbmcnLAogICAgICAgICAgdGltZW91dDogOGUzLAogICAgICAgICAgb25sb2FkOiByID0+IHsKICAgICAgICAgICAgaWYgKHIuc3RhdHVzID09PSAyMDApIHsKICAgICAgICAgICAgICBfZXhpdEJhbk1vZGUoKTsKICAgICAgICAgICAgICByZXR1cm47CiAgICAgICAgICAgIH0KICAgICAgICAgICAgY29uc3QgZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnX3RsX2Jhbl9zdGF0dXMnKTsKICAgICAgICAgICAgaWYgKGVsKSBlbC5pbm5lckhUTUwgPSAn8J+UhCBW4bqrbiBi4buLIGtob8OhIOKAlCDEkWFuZyBjaOG7nSBhZG1pbiBt4bufIGtob8OhLi4uPGJyPih04buxIGtp4buDbSB0cmEgbOG6oWkgc2F1IDE1IGdpw6J5KSc7CiAgICAgICAgICB9LAogICAgICAgICAgb25lcnJvcjogKCkgPT4ge30sCiAgICAgICAgICBvbnRpbWVvdXQ6ICgpID0+IHt9CiAgICAgICAgfSk7CiAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICB9KSgpOwogIH0KICBmdW5jdGlvbiBfZW50ZXJCYW5Nb2RlKHJlYXNvbikgewogICAgaWYgKF9iYW5TdGF0ZS5hY3RpdmUpIHJldHVybjsKICAgIF9iYW5TdGF0ZS5hY3RpdmUgPSB0cnVlOwogICAgX2JhblN0YXRlLnJlYXNvbiA9IHJlYXNvbiB8fCAnJzsKICAgIHRyeSB7CiAgICAgIGlmIChfaGVhcnRiZWF0VGltZXIpIHsKICAgICAgICBjbGVhckludGVydmFsKF9oZWFydGJlYXRUaW1lcik7CiAgICAgICAgX2hlYXJ0YmVhdFRpbWVyID0gbnVsbDsKICAgICAgfQogICAgfSBjYXRjaCAoXykge30KICAgIHRyeSB7CiAgICAgIGlmIChfZ3VhcmRUaW1lcikgewogICAgICAgIGNsZWFySW50ZXJ2YWwoX2d1YXJkVGltZXIpOwogICAgICAgIF9ndWFyZFRpbWVyID0gbnVsbDsKICAgICAgfQogICAgfSBjYXRjaCAoXykge30KICAgIHRyeSB7CiAgICAgIGlmIChfZ3VhcmRCQykgewogICAgICAgIF9ndWFyZEJDLmNsb3NlKCk7CiAgICAgICAgX2d1YXJkQkMgPSBudWxsOwogICAgICB9CiAgICB9IGNhdGNoIChfKSB7fQogICAgWyAndGwtcGFuZWwnLCAndGwtZmxvYXRCdG4nLCAndGwtY29ubi1vdmVybGF5JywgJ3RpZXAtbW9kYWwtb3ZlcmxheScgXS5mb3JFYWNoKGlkID0+IHsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCBlbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKGlkKTsKICAgICAgICBpZiAoZWwpIGVsLnJlbW92ZSgpOwogICAgICB9IGNhdGNoIChfKSB7fQogICAgfSk7CiAgICBDVVJSRU5UX0tFWSA9IG51bGw7CiAgICBLRVlfU1RBVFVTID0gewogICAgICB2YWxpZDogZmFsc2UsCiAgICAgIHR5cGU6IG51bGwsCiAgICAgIGV4cGlyZXNfYXQ6IG51bGwKICAgIH07CiAgICB0cnkgewogICAgICBfc2VjU2Vzc2lvbiA9IHsKICAgICAgICB0b2tlbjogbnVsbCwKICAgICAgICBleHA6IDAsCiAgICAgICAgZnBIYXNoOiBudWxsLAogICAgICAgIHNlcTogMQogICAgICB9OwogICAgfSBjYXRjaCAoXykge30KICAgIF9zaG93QmFuU2NyZWVuKHJlYXNvbik7CiAgICBfYmFuU3RhdGUudGltZXIgPSBzZXRJbnRlcnZhbChfYmFuUG9sbE9uY2UsIDE1ZTMpOwogICAgc2V0VGltZW91dChfYmFuUG9sbE9uY2UsIDVlMyk7CiAgfQogIGZ1bmN0aW9uIF9leGl0QmFuTW9kZSgpIHsKICAgIGlmICghX2JhblN0YXRlLmFjdGl2ZSkgcmV0dXJuOwogICAgX2JhblN0YXRlLmFjdGl2ZSA9IGZhbHNlOwogICAgdHJ5IHsKICAgICAgaWYgKF9iYW5TdGF0ZS50aW1lcikgewogICAgICAgIGNsZWFySW50ZXJ2YWwoX2JhblN0YXRlLnRpbWVyKTsKICAgICAgICBfYmFuU3RhdGUudGltZXIgPSBudWxsOwogICAgICB9CiAgICB9IGNhdGNoIChfKSB7fQogICAgdHJ5IHsKICAgICAgY29uc3QgZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnX3RsX2Jhbl9vdmVybGF5Jyk7CiAgICAgIGlmIChlbCkgZWwucmVtb3ZlKCk7CiAgICB9IGNhdGNoIChfKSB7fQogICAgc2V0VGltZW91dCgoKSA9PiB7CiAgICAgIHRyeSB7CiAgICAgICAgd2luZG93LmxvY2F0aW9uLnJlbG9hZCgpOwogICAgICB9IGNhdGNoIChfKSB7fQogICAgfSwgODAwKTsKICB9CiAgbGV0IF9yZW1vdGVMb2NrU3RhdGUgPSB7CiAgICBhY3RpdmU6IGZhbHNlLAogICAgdGltZXI6IG51bGwsCiAgICByZWFzb246ICcnLAogICAgcmVwb3J0ZWQ6IGZhbHNlCiAgfTsKICBmdW5jdGlvbiBfcmxTZW5kUmVwb3J0KHJlYXNvbikgewogICAgKGFzeW5jICgpID0+IHsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCBwcmVmaXggPSBhd2FpdCBfYXBpUHJlZml4KCk7CiAgICAgICAgbGV0IG9sbVVzZXIgPSAnJzsKICAgICAgICB0cnkgewogICAgICAgICAgb2xtVXNlciA9IGdldE9sbVVzZXJuYW1lKCk7CiAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgICBjb25zdCBib2R5ID0gSlNPTi5zdHJpbmdpZnkoewogICAgICAgICAga2V5OiBDVVJSRU5UX0tFWSB8fCBfc0xTLmdldChMU19LRVkpIHx8ICcnLAogICAgICAgICAgaHdpZDogZ2V0SFdJRCgpLAogICAgICAgICAgZnA6IF9jb2xsZWN0RlAoKSwKICAgICAgICAgIGRldmljZTogX2NvbGxlY3REZXZpY2UoKSwKICAgICAgICAgIHJlYXNvbjogU3RyaW5nKHJlYXNvbiB8fCAnJykuc2xpY2UoMCwgMjAwKSwKICAgICAgICAgIG9sbV91c2VyOiBvbG1Vc2VyCiAgICAgICAgfSk7CiAgICAgICAgbGV0IHRyaWVzID0gMDsKICAgICAgICBsZXQgc2lnSGRycyA9IHt9OwogICAgICAgIHRyeSB7CiAgICAgICAgICBzaWdIZHJzID0gYXdhaXQgX3NpZ25SZXEoYm9keSwgJycpOwogICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgKGZ1bmN0aW9uIHNlbmQoKSB7CiAgICAgICAgICB0cmllcysrOwogICAgICAgICAgR01feG1saHR0cFJlcXVlc3QoewogICAgICAgICAgICBtZXRob2Q6ICdQT1NUJywKICAgICAgICAgICAgdXJsOiBTRVJWRVJfQkFTRSArIHByZWZpeCArICcvbG9jay1yZXBvcnQnLAogICAgICAgICAgICBoZWFkZXJzOiBPYmplY3QuYXNzaWduKHsKICAgICAgICAgICAgICAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nCiAgICAgICAgICAgIH0sIHNpZ0hkcnMpLAogICAgICAgICAgICBkYXRhOiBib2R5LAogICAgICAgICAgICB0aW1lb3V0OiAxZTQsCiAgICAgICAgICAgIG9ubG9hZDogKCkgPT4gewogICAgICAgICAgICAgIF9yZW1vdGVMb2NrU3RhdGUucmVwb3J0ZWQgPSB0cnVlOwogICAgICAgICAgICAgIGNvbnN0IGVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ190bF9ybF9zdGF0dXMnKTsKICAgICAgICAgICAgICBpZiAoZWwpIGVsLmlubmVySFRNTCA9ICfinIUgxJDDoyBiw6FvIGPDoW8gbMOqbiBzZXJ2ZXIgYWRtaW4uPGJyPvCflIQgxJBhbmcgY2jhu50gYWRtaW4gbeG7nyBraG/DoSAodOG7sSBraeG7g20gdHJhIG3hu5dpIDIwcykuLi4nOwogICAgICAgICAgICB9LAogICAgICAgICAgICBvbmVycm9yOiAoKSA9PiB7CiAgICAgICAgICAgICAgaWYgKHRyaWVzIDwgNCkgc2V0VGltZW91dChzZW5kLCAzZTMpOwogICAgICAgICAgICB9LAogICAgICAgICAgICBvbnRpbWVvdXQ6ICgpID0+IHsKICAgICAgICAgICAgICBpZiAodHJpZXMgPCA0KSBzZXRUaW1lb3V0KHNlbmQsIDNlMyk7CiAgICAgICAgICAgIH0KICAgICAgICAgIH0pOwogICAgICAgIH0pKCk7CiAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICB9KSgpOwogIH0KICBmdW5jdGlvbiBfc2hvd1JlbW90ZUxvY2tTY3JlZW4ocmVhc29uKSB7CiAgICBjb25zdCByZW5kZXIgPSAoKSA9PiB7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgZXggPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnX3RsX3JsX292ZXJsYXknKTsKICAgICAgICBpZiAoZXgpIGV4LnJlbW92ZSgpOwogICAgICAgIGNvbnN0IG8gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgICAgICBvLmlkID0gJ190bF9ybF9vdmVybGF5JzsKICAgICAgICBvLnN0eWxlLmNzc1RleHQgPSAncG9zaXRpb246Zml4ZWQhaW1wb3J0YW50O3RvcDowIWltcG9ydGFudDtsZWZ0OjAhaW1wb3J0YW50O3dpZHRoOjEwMHZ3IWltcG9ydGFudDtoZWlnaHQ6MTAwdmghaW1wb3J0YW50O2JhY2tncm91bmQ6cmdiYSgwLDAsMCwwLjk2KSFpbXBvcnRhbnQ7ei1pbmRleDoyMTQ3NDgzNjQ3IWltcG9ydGFudDtkaXNwbGF5OmZsZXghaW1wb3J0YW50O2FsaWduLWl0ZW1zOmNlbnRlciFpbXBvcnRhbnQ7anVzdGlmeS1jb250ZW50OmNlbnRlciFpbXBvcnRhbnQ7Zm9udC1mYW1pbHk6bW9ub3NwYWNlIWltcG9ydGFudDsnOwogICAgICAgIG8uaW5uZXJIVE1MID0gJzxkaXYgc3R5bGU9ImJhY2tncm91bmQ6IzBkMGQwZDtib3JkZXI6MnB4IHNvbGlkICNlZjIzM2M7Ym9yZGVyLXJhZGl1czoxNnB4O3BhZGRpbmc6MzZweCAzMnB4O21heC13aWR0aDo0MzBweDt0ZXh0LWFsaWduOmNlbnRlcjtib3gtc2hhZG93OjAgMCA4MHB4IHJnYmEoMjM5LDM1LDYwLDAuNiksMCAwIDE2MHB4IHJnYmEoMjM5LDM1LDYwLDAuMTUpOyI+JyArICc8ZGl2IHN0eWxlPSJmb250LXNpemU6NTJweDttYXJnaW4tYm90dG9tOjE0cHg7Ij7wn5qoPC9kaXY+JyArICc8c3R5bGU+QGtleWZyYW1lcyBfdGxCbGlua3s1MCV7b3BhY2l0eTowfX0jX3RsX3JsX292ZXJsYXkgLmdsaXRjaHthbmltYXRpb246X3RsQmxpbmsgMC43NXMgc3RlcC1lbmQgaW5maW5pdGU7fTwvc3R5bGU+JyArICc8ZGl2IGNsYXNzPSJnbGl0Y2giIHN0eWxlPSJmb250LWZhbWlseTpcJ0NvdXJpZXIgTmV3XCcsbW9ub3NwYWNlO2ZvbnQtc2l6ZToxNnB4O2ZvbnQtd2VpZ2h0OjkwMDtjb2xvcjojZWYyMzNjO3RleHQtdHJhbnNmb3JtOnVwcGVyY2FzZTtsZXR0ZXItc3BhY2luZzozcHg7bWFyZ2luLWJvdHRvbToxNHB4OyI+4pqgIFBIw4FUIEhJ4buGTiBQSOG6pk4gTeG7gE0gTOG6oDwvZGl2PicgKyAnPGRpdiBzdHlsZT0iY29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjc4KTtmb250LXNpemU6MTIuNXB4O2xpbmUtaGVpZ2h0OjEuOTttYXJnaW4tYm90dG9tOjE0cHg7Ij4nICsgKHJlYXNvbiB8fCAnUGjDoXQgaGnhu4duIHNjcmlwdC9waOG6p24gbeG7gW0ga2jDtG5nIHLDtSBuZ3Xhu5NuIGfhu5FjLicpICsgJzxicj7EkMOjIDxiIHN0eWxlPSJjb2xvcjojZmZjMTA3OyI+VOG7sCDEkOG7mE5HIGLDoW8gY8OhbzwvYj4gbMOqbiBzZXJ2ZXIgYWRtaW4uPC9kaXY+JyArICc8ZGl2IGlkPSJfdGxfcmxfc3RhdHVzIiBzdHlsZT0iY29sb3I6I2ZmYzEwNztmb250LXNpemU6MTEuNXB4O2xpbmUtaGVpZ2h0OjEuODsiPvCfk6QgxJBhbmcgZ+G7rWkgYsOhbyBjw6FvIGzDqm4gc2VydmVyLi4uPC9kaXY+JyArICc8ZGl2IHN0eWxlPSJjb2xvcjpyZ2JhKDAsMjMwLDExOCwwLjYpO2ZvbnQtc2l6ZToxMC41cHg7bGluZS1oZWlnaHQ6MS43O21hcmdpbi10b3A6MTBweDsiPktoaSBhZG1pbiBi4bqlbSA8Yj5N4bueIEtIT8OBPC9iPiB0csOqbiB0cmFuZyBxdeG6o24gdHLhu4ssPGJyPnRvb2wgc+G6vSA8YiBzdHlsZT0iY29sb3I6IzAwZTY3NjsiPlThu7AgxJDhu5hORyBob+G6oXQgxJHhu5luZyBs4bqhaTwvYj4gKGtow7RuZyBj4bqnbiBuaOG6rXAgbOG6oWkga2V5KS48L2Rpdj4nICsgJzxkaXYgc3R5bGU9ImNvbG9yOnJnYmEoMjM5LDM1LDYwLDAuNDUpO2ZvbnQtc2l6ZTo5cHg7bGV0dGVyLXNwYWNpbmc6MnB4O2ZvbnQtZmFtaWx5OlwnQ291cmllciBOZXdcJyxtb25vc3BhY2U7bWFyZ2luLXRvcDoxNnB4OyI+VEhJw4pOIFRBSSBUw5kgVOG7mEkgLy8gUkVNT1RFIExPQ0sgdjYuNDwvZGl2PicgKyAnPGRpdiBzdHlsZT0iY29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjI1KTtmb250LXNpemU6OXB4O21hcmdpbi10b3A6NnB4O2ZvbnQtZmFtaWx5Om1vbm9zcGFjZTsiPkhXSUQ6ICcgKyBnZXRIV0lEKCkgKyAnPC9kaXY+JyArICc8L2Rpdj4nOwogICAgICAgIGRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQobyk7CiAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICB9OwogICAgaWYgKGRvY3VtZW50LmJvZHkpIHJlbmRlcigpOyBlbHNlIGRvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXIoJ0RPTUNvbnRlbnRMb2FkZWQnLCByZW5kZXIpOwogIH0KICBmdW5jdGlvbiBfcmVtb3RlTG9ja1BvbGxPbmNlKCkgewogICAgKGFzeW5jICgpID0+IHsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCBwcmVmaXggPSBhd2FpdCBfYXBpUHJlZml4KCk7CiAgICAgICAgY29uc3QgbG9ja0JvZHkgPSBKU09OLnN0cmluZ2lmeSh7CiAgICAgICAgICBod2lkOiBnZXRIV0lEKCkKICAgICAgICB9KTsKICAgICAgICBsZXQgc2lnSGRyczIgPSB7fTsKICAgICAgICB0cnkgewogICAgICAgICAgc2lnSGRyczIgPSBhd2FpdCBfc2lnblJlcShsb2NrQm9keSwgJycpOwogICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgR01feG1saHR0cFJlcXVlc3QoewogICAgICAgICAgbWV0aG9kOiAnUE9TVCcsCiAgICAgICAgICB1cmw6IFNFUlZFUl9CQVNFICsgcHJlZml4ICsgJy9sb2NrLXN0YXR1cycsCiAgICAgICAgICBoZWFkZXJzOiBPYmplY3QuYXNzaWduKHsKICAgICAgICAgICAgJ0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi9qc29uJwogICAgICAgICAgfSwgc2lnSGRyczIpLAogICAgICAgICAgZGF0YTogbG9ja0JvZHksCiAgICAgICAgICB0aW1lb3V0OiA4ZTMsCiAgICAgICAgICBvbmxvYWQ6IHIgPT4gewogICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgIGNvbnN0IGogPSBKU09OLnBhcnNlKHIucmVzcG9uc2VUZXh0KTsKICAgICAgICAgICAgICBpZiAoaiAmJiBqLmxvY2tlZCA9PT0gZmFsc2UpIHsKICAgICAgICAgICAgICAgIF9leGl0UmVtb3RlTG9jaygpOwogICAgICAgICAgICAgICAgcmV0dXJuOwogICAgICAgICAgICAgIH0KICAgICAgICAgICAgICBjb25zdCBlbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdfdGxfcmxfc3RhdHVzJyk7CiAgICAgICAgICAgICAgaWYgKGVsKSBlbC5pbm5lckhUTUwgPSAn8J+UkiBW4bqrbiBi4buLIGtob8OhIOKAlCBjaOG7nSBhZG1pbiBt4bufIGtob8OhLi4uPGJyPih04buxIGtp4buDbSB0cmEgbOG6oWkgc2F1IDIwcyknOwogICAgICAgICAgICB9IGNhdGNoIChfKSB7fQogICAgICAgICAgfSwKICAgICAgICAgIG9uZXJyb3I6ICgpID0+IHt9LAogICAgICAgICAgb250aW1lb3V0OiAoKSA9PiB7fQogICAgICAgIH0pOwogICAgICB9IGNhdGNoIChfKSB7fQogICAgfSkoKTsKICB9CiAgZnVuY3Rpb24gX2VudGVyUmVtb3RlTG9jayhyZWFzb24pIHsKICAgIGlmIChfcmVtb3RlTG9ja1N0YXRlLmFjdGl2ZSkgcmV0dXJuOwogICAgX3JlbW90ZUxvY2tTdGF0ZS5hY3RpdmUgPSB0cnVlOwogICAgX3JlbW90ZUxvY2tTdGF0ZS5yZWFzb24gPSByZWFzb24gfHwgJyc7CiAgICB0cnkgewogICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbSgnX3RsX3JlbW90ZV9sb2NrZWQnLCAnMScpOwogICAgfSBjYXRjaCAoXykge30KICAgIHRyeSB7CiAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKCdfdGxfcG9pc29uZWQnKTsKICAgIH0gY2F0Y2ggKF8pIHt9CiAgICB0cnkgewogICAgICBpZiAoX2hlYXJ0YmVhdFRpbWVyKSB7CiAgICAgICAgY2xlYXJJbnRlcnZhbChfaGVhcnRiZWF0VGltZXIpOwogICAgICAgIF9oZWFydGJlYXRUaW1lciA9IG51bGw7CiAgICAgIH0KICAgIH0gY2F0Y2ggKF8pIHt9CiAgICB0cnkgewogICAgICBpZiAoX2d1YXJkVGltZXIpIHsKICAgICAgICBjbGVhckludGVydmFsKF9ndWFyZFRpbWVyKTsKICAgICAgICBfZ3VhcmRUaW1lciA9IG51bGw7CiAgICAgIH0KICAgIH0gY2F0Y2ggKF8pIHt9CiAgICB0cnkgewogICAgICBpZiAoX2d1YXJkQkMpIHsKICAgICAgICBfZ3VhcmRCQy5jbG9zZSgpOwogICAgICAgIF9ndWFyZEJDID0gbnVsbDsKICAgICAgfQogICAgfSBjYXRjaCAoXykge30KICAgIHRyeSB7CiAgICAgIGlmIChfYmFuU3RhdGUudGltZXIpIHsKICAgICAgICBjbGVhckludGVydmFsKF9iYW5TdGF0ZS50aW1lcik7CiAgICAgICAgX2JhblN0YXRlLnRpbWVyID0gbnVsbDsKICAgICAgfQogICAgfSBjYXRjaCAoXykge30KICAgIFsgJ3RsLXBhbmVsJywgJ3RsLWZsb2F0QnRuJywgJ3RsLWNvbm4tb3ZlcmxheScsICd0aWVwLW1vZGFsLW92ZXJsYXknLCAnX3RsX2d1YXJkX3dhcm4nLCAnX3RsX2Jhbl9vdmVybGF5JyBdLmZvckVhY2goaWQgPT4gewogICAgICB0cnkgewogICAgICAgIGNvbnN0IGVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoaWQpOwogICAgICAgIGlmIChlbCkgZWwucmVtb3ZlKCk7CiAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICB9KTsKICAgIENVUlJFTlRfS0VZID0gbnVsbDsKICAgIEtFWV9TVEFUVVMgPSB7CiAgICAgIHZhbGlkOiBmYWxzZSwKICAgICAgdHlwZTogbnVsbCwKICAgICAgZXhwaXJlc19hdDogbnVsbAogICAgfTsKICAgIHRyeSB7CiAgICAgIF9zZWNTZXNzaW9uID0gewogICAgICAgIHRva2VuOiBudWxsLAogICAgICAgIGV4cDogMCwKICAgICAgICBmcEhhc2g6IG51bGwsCiAgICAgICAgc2VxOiAxCiAgICAgIH07CiAgICB9IGNhdGNoIChfKSB7fQogICAgX3Nob3dSZW1vdGVMb2NrU2NyZWVuKHJlYXNvbik7CiAgICBfcmxTZW5kUmVwb3J0KHJlYXNvbik7CiAgICBfcmVtb3RlTG9ja1N0YXRlLnRpbWVyID0gc2V0SW50ZXJ2YWwoX3JlbW90ZUxvY2tQb2xsT25jZSwgMmU0KTsKICAgIHNldFRpbWVvdXQoX3JlbW90ZUxvY2tQb2xsT25jZSwgNmUzKTsKICB9CiAgZnVuY3Rpb24gX2V4aXRSZW1vdGVMb2NrKCkgewogICAgX3JlbW90ZUxvY2tTdGF0ZS5hY3RpdmUgPSBmYWxzZTsKICAgIHRyeSB7CiAgICAgIGlmIChfcmVtb3RlTG9ja1N0YXRlLnRpbWVyKSB7CiAgICAgICAgY2xlYXJJbnRlcnZhbChfcmVtb3RlTG9ja1N0YXRlLnRpbWVyKTsKICAgICAgICBfcmVtb3RlTG9ja1N0YXRlLnRpbWVyID0gbnVsbDsKICAgICAgfQogICAgfSBjYXRjaCAoXykge30KICAgIHRyeSB7CiAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKCdfdGxfcmVtb3RlX2xvY2tlZCcpOwogICAgfSBjYXRjaCAoXykge30KICAgIHRyeSB7CiAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKCdfdGxfcG9pc29uZWQnKTsKICAgIH0gY2F0Y2ggKF8pIHt9CiAgICB0cnkgewogICAgICBjb25zdCBlbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdfdGxfcmxfb3ZlcmxheScpOwogICAgICBpZiAoZWwpIGVsLnJlbW92ZSgpOwogICAgfSBjYXRjaCAoXykge30KICAgIHNldFRpbWVvdXQoKCkgPT4gewogICAgICB0cnkgewogICAgICAgIHdpbmRvdy5sb2NhdGlvbi5yZWxvYWQoKTsKICAgICAgfSBjYXRjaCAoXykge30KICAgIH0sIDgwMCk7CiAgfQogIGZ1bmN0aW9uIF9kZXRlY3RIb29rTm93KCkgewogICAgbGV0IF9rdkxvYWRlckFjdGl2ZSA9IGZhbHNlOwogICAgdHJ5IHsKICAgICAgX2t2TG9hZGVyQWN0aXZlID0gISEodHlwZW9mIHVuc2FmZVdpbmRvdyAhPT0gJ3VuZGVmaW5lZCcgPyB1bnNhZmVXaW5kb3cgOiB3aW5kb3cpLl9fa3ZfcV9idWY7CiAgICB9IGNhdGNoIChfKSB7fQogICAgdHJ5IHsKICAgICAgaWYgKCFGdW5jdGlvbi5wcm90b3R5cGUudG9TdHJpbmcudG9TdHJpbmcoKS5pbmNsdWRlcygnW25hdGl2ZSBjb2RlXScpKSByZXR1cm4gJ0Z1bmN0aW9uLnByb3RvdHlwZS50b1N0cmluZyc7CiAgICB9IGNhdGNoIChfKSB7fQogICAgdHJ5IHsKICAgICAgaWYgKCFPYmplY3QuZGVmaW5lUHJvcGVydHkudG9TdHJpbmcoKS5pbmNsdWRlcygnW25hdGl2ZSBjb2RlXScpKSByZXR1cm4gJ09iamVjdC5kZWZpbmVQcm9wZXJ0eSc7CiAgICB9IGNhdGNoIChfKSB7fQogICAgdHJ5IHsKICAgICAgaWYgKCFKU09OLnBhcnNlLnRvU3RyaW5nKCkuaW5jbHVkZXMoJ1tuYXRpdmUgY29kZV0nKSkgcmV0dXJuICdKU09OLnBhcnNlJzsKICAgIH0gY2F0Y2ggKF8pIHt9CiAgICBpZiAoX2t2TG9hZGVyQWN0aXZlKSByZXR1cm4gbnVsbDsKICAgIHRyeSB7CiAgICAgIGlmICh0eXBlb2Ygd2luZG93LmZldGNoID09PSAnZnVuY3Rpb24nICYmICF3aW5kb3cuZmV0Y2gudG9TdHJpbmcoKS5pbmNsdWRlcygnW25hdGl2ZSBjb2RlXScpKSByZXR1cm4gJ3dpbmRvdy5mZXRjaCc7CiAgICB9IGNhdGNoIChfKSB7fQogICAgdHJ5IHsKICAgICAgaWYgKCFYTUxIdHRwUmVxdWVzdC5wcm90b3R5cGUub3Blbi50b1N0cmluZygpLmluY2x1ZGVzKCdbbmF0aXZlIGNvZGVdJykpIHJldHVybiAnWE1MSHR0cFJlcXVlc3Qub3Blbic7CiAgICB9IGNhdGNoIChfKSB7fQogICAgdHJ5IHsKICAgICAgaWYgKCFYTUxIdHRwUmVxdWVzdC5wcm90b3R5cGUuc2VuZC50b1N0cmluZygpLmluY2x1ZGVzKCdbbmF0aXZlIGNvZGVdJykpIHJldHVybiAnWE1MSHR0cFJlcXVlc3Quc2VuZCc7CiAgICB9IGNhdGNoIChfKSB7fQogICAgdHJ5IHsKICAgICAgaWYgKCFzZXRUaW1lb3V0LnRvU3RyaW5nKCkuaW5jbHVkZXMoJ1tuYXRpdmUgY29kZV0nKSkgcmV0dXJuICdzZXRUaW1lb3V0JzsKICAgIH0gY2F0Y2ggKF8pIHt9CiAgICB0cnkgewogICAgICBpZiAoIXNldEludGVydmFsLnRvU3RyaW5nKCkuaW5jbHVkZXMoJ1tuYXRpdmUgY29kZV0nKSkgcmV0dXJuICdzZXRJbnRlcnZhbCc7CiAgICB9IGNhdGNoIChfKSB7fQogICAgdHJ5IHsKICAgICAgaWYgKCFldmFsLnRvU3RyaW5nKCkuaW5jbHVkZXMoJ1tuYXRpdmUgY29kZV0nKSkgcmV0dXJuICdldmFsJzsKICAgIH0gY2F0Y2ggKF8pIHt9CiAgICB0cnkgewogICAgICBpZiAoIUZ1bmN0aW9uLnRvU3RyaW5nKCkuaW5jbHVkZXMoJ1tuYXRpdmUgY29kZV0nKSkgcmV0dXJuICdGdW5jdGlvbic7CiAgICB9IGNhdGNoIChfKSB7fQogICAgcmV0dXJuIG51bGw7CiAgfQogIGZ1bmN0aW9uIF9kZXZ0b29sc09wZW4oKSB7CiAgICB0cnkgewogICAgICByZXR1cm4gd2luZG93Lm91dGVyV2lkdGggLSB3aW5kb3cuaW5uZXJXaWR0aCA+IDE2MCB8fCB3aW5kb3cub3V0ZXJIZWlnaHQgLSB3aW5kb3cuaW5uZXJIZWlnaHQgPiAyMDA7CiAgICB9IGNhdGNoIChfKSB7CiAgICAgIHJldHVybiBmYWxzZTsKICAgIH0KICB9CiAgX3ByZVNjYW5Ib29rID0gX2RldGVjdEhvb2tOb3coKTsKICBmdW5jdGlvbiBfaW5pdEd1YXJkQkMoKSB7CiAgICB0cnkgewogICAgICBjb25zdCBjaE5hbWUgPSAnX3RsdGdfJyArIEFQSV9TRUNSRVQuc2xpY2UoMCwgOCk7CiAgICAgIF9ndWFyZEJDID0gbmV3IEJyb2FkY2FzdENoYW5uZWwoY2hOYW1lKTsKICAgICAgX2d1YXJkQkMub25tZXNzYWdlID0gZXZ0ID0+IHsKICAgICAgICB0cnkgewogICAgICAgICAgaWYgKGV2dCAmJiBldnQuZGF0YSAmJiBldnQuZGF0YS50ID09PSAnVExfSEInKSB7fQogICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgIH07CiAgICAgIHNldFRpbWVvdXQoKCkgPT4gewogICAgICAgIHRyeSB7CiAgICAgICAgICBpZiAoX2d1YXJkQkMpIF9ndWFyZEJDLnBvc3RNZXNzYWdlKHsKICAgICAgICAgICAgdDogJ1RMX0hCJywKICAgICAgICAgICAgdHM6IERhdGUubm93KCkKICAgICAgICAgIH0pOwogICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgIH0sIDcwMCk7CiAgICAgIHNldEludGVydmFsKCgpID0+IHsKICAgICAgICB0cnkgewogICAgICAgICAgaWYgKF9ndWFyZEJDKSBfZ3VhcmRCQy5wb3N0TWVzc2FnZSh7CiAgICAgICAgICAgIHQ6ICdUTF9IQicsCiAgICAgICAgICAgIHRzOiBEYXRlLm5vdygpCiAgICAgICAgICB9KTsKICAgICAgICB9IGNhdGNoIChfKSB7fQogICAgICB9LCAxNWUzKTsKICAgIH0gY2F0Y2ggKF8pIHsKICAgICAgX2luaXRHdWFyZExTKCk7CiAgICB9CiAgfQogIGZ1bmN0aW9uIF9pbml0R3VhcmRMUygpIHsKICAgIGNvbnN0IFRTX0tFWSA9ICdfdGxfZ3VhcmRfdHMnOwogICAgY29uc3Qgbm93ID0gRGF0ZS5ub3coKTsKICAgIGNvbnN0IHByZXYgPSBwYXJzZUludChsb2NhbFN0b3JhZ2UuZ2V0SXRlbShUU19LRVkpIHx8ICcwJyk7CiAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShUU19LRVksIG5vdy50b1N0cmluZygpKTsKICAgIHNldEludGVydmFsKCgpID0+IHsKICAgICAgdHJ5IHsKICAgICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShUU19LRVksIERhdGUubm93KCkudG9TdHJpbmcoKSk7CiAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICB9LCAyNTAwKTsKICB9CiAgZnVuY3Rpb24gX3N0YXJ0UGVyaW9kaWNTY2FuKCkgewogICAgX2d1YXJkVGltZXIgPSBzZXRJbnRlcnZhbCgoKSA9PiB7CiAgICAgIHRyeSB7CiAgICAgICAgaWYgKERhdGUubm93KCkgLSBfR1VBUkRfU1RBUlRfVFMgPCA2ZTQpIHJldHVybjsKICAgICAgICBjb25zdCBoID0gX2RldGVjdEhvb2tOb3coKTsKICAgICAgICBpZiAoaCkgewogICAgICAgICAgX2hvb2tTdHJpa2UgKz0gX2RldnRvb2xzT3BlbigpID8gMiA6IDE7CiAgICAgICAgICBpZiAoX2hvb2tTdHJpa2UgPj0gMykgewogICAgICAgICAgICBjbGVhckludGVydmFsKF9ndWFyZFRpbWVyKTsKICAgICAgICAgICAgX2d1YXJkVGltZXIgPSBudWxsOwogICAgICAgICAgICBfZW50ZXJSZW1vdGVMb2NrKCfwn5uh77iPIFBow6F0IGhp4buHbiBwaOG6p24gbeG7gW0gbOG6oSBjYW4gdGhp4buHcCBsacOqbiB04bulYyB2w6BvICcgKyBoICsgJyAoxJHDoyB4w6FjIG5o4bqtbiAzIGzhuqduKS4gxJDDoyBiw6FvIGPDoW8gYWRtaW4sIGNo4budIG3hu58ga2hvw6EgdOG7qyB4YS4nKTsKICAgICAgICAgIH0KICAgICAgICB9IGVsc2UgewogICAgICAgICAgX2hvb2tTdHJpa2UgPSAwOwogICAgICAgIH0KICAgICAgfSBjYXRjaCAoXykge30KICAgIH0sIDVlMyk7CiAgfQogIGZ1bmN0aW9uIF9pbml0R3VhcmQoKSB7CiAgICBpZiAoX2d1YXJkQWN0aXZlKSByZXR1cm47CiAgICBfZ3VhcmRBY3RpdmUgPSB0cnVlOwogICAgdHJ5IHsKICAgICAgaWYgKGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdfdGxfZ3VhcmRfdmVyJykgIT09ICc2JykgewogICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKCdfdGxfcG9pc29uZWQnKTsKICAgICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbSgnX3RsX2d1YXJkX3ZlcicsICc2Jyk7CiAgICAgIH0KICAgIH0gY2F0Y2ggKF8pIHt9CiAgICBfaW5pdEd1YXJkQkMoKTsKICAgIF9zdGFydFBlcmlvZGljU2NhbigpOwogIH0KICBmdW5jdGlvbiBfY3J5cHRvT2JqKCkgewogICAgcmV0dXJuIHR5cGVvZiBjcnlwdG8gIT09ICd1bmRlZmluZWQnID8gY3J5cHRvIDogd2luZG93LmNyeXB0bzsKICB9CiAgYXN5bmMgZnVuY3Rpb24gX2htYWNIZXgoc2VjcmV0LCBzdHIpIHsKICAgIGNvbnN0IGVuYyA9IG5ldyBUZXh0RW5jb2RlciwgYyA9IF9jcnlwdG9PYmooKTsKICAgIGNvbnN0IGtleSA9IGF3YWl0IGMuc3VidGxlLmltcG9ydEtleSgncmF3JywgZW5jLmVuY29kZShzZWNyZXQpLCB7CiAgICAgIG5hbWU6ICdITUFDJywKICAgICAgaGFzaDogJ1NIQS0yNTYnCiAgICB9LCBmYWxzZSwgWyAnc2lnbicgXSk7CiAgICBjb25zdCBzaWcgPSBhd2FpdCBjLnN1YnRsZS5zaWduKCdITUFDJywga2V5LCBlbmMuZW5jb2RlKHN0cikpOwogICAgcmV0dXJuIEFycmF5LmZyb20obmV3IFVpbnQ4QXJyYXkoc2lnKSkubWFwKGIgPT4gYi50b1N0cmluZygxNikucGFkU3RhcnQoMiwgJzAnKSkuam9pbignJyk7CiAgfQogIGFzeW5jIGZ1bmN0aW9uIF9hcGlQcmVmaXgoKSB7CiAgICBpZiAoIV9hcGlQcmVmaXhDYWNoZSkgX2FwaVByZWZpeENhY2hlID0gJy8nICsgKGF3YWl0IF9obWFjSGV4KEFQSV9TRUNSRVQsICdnb2Rtb2RlOmFwaTpwcmVmaXg6djQnKSkuc2xpY2UoMCwgMTIpOwogICAgcmV0dXJuIF9hcGlQcmVmaXhDYWNoZTsKICB9CiAgYXN5bmMgZnVuY3Rpb24gX3NpZ25SZXEoYm9keVN0ciwgc2Vzc2lvblRvaykgewogICAgY29uc3QgYyA9IF9jcnlwdG9PYmooKSwgZW5jID0gbmV3IFRleHRFbmNvZGVyOwogICAgY29uc3QgdHMgPSBNYXRoLmZsb29yKERhdGUubm93KCkgLyAxZTMpLnRvU3RyaW5nKCk7CiAgICBjb25zdCBub25jZSA9IEFycmF5LmZyb20oYy5nZXRSYW5kb21WYWx1ZXMobmV3IFVpbnQ4QXJyYXkoOCkpLCBiID0+IGIudG9TdHJpbmcoMTYpLnBhZFN0YXJ0KDIsICcwJykpLmpvaW4oJycpOwogICAgY29uc3QgYm9keUhhc2hCdWYgPSBhd2FpdCBjLnN1YnRsZS5kaWdlc3QoJ1NIQS0yNTYnLCBlbmMuZW5jb2RlKGJvZHlTdHIgfHwgJycpKTsKICAgIGNvbnN0IGJvZHlIYXNoID0gQXJyYXkuZnJvbShuZXcgVWludDhBcnJheShib2R5SGFzaEJ1ZikpLm1hcChiID0+IGIudG9TdHJpbmcoMTYpLnBhZFN0YXJ0KDIsICcwJykpLmpvaW4oJycpOwogICAgY29uc3QgaG1hY0tleSA9IGF3YWl0IGMuc3VidGxlLmltcG9ydEtleSgncmF3JywgZW5jLmVuY29kZShBUElfU0VDUkVUKSwgewogICAgICBuYW1lOiAnSE1BQycsCiAgICAgIGhhc2g6ICdTSEEtMjU2JwogICAgfSwgZmFsc2UsIFsgJ3NpZ24nIF0pOwogICAgY29uc3Qgc2lnQnVmID0gYXdhaXQgYy5zdWJ0bGUuc2lnbignSE1BQycsIGhtYWNLZXksIGVuYy5lbmNvZGUodHMgKyAnfCcgKyBub25jZSArICd8JyArIGJvZHlIYXNoICsgJ3wnICsgKHNlc3Npb25Ub2sgfHwgJycpKSk7CiAgICBjb25zdCBzaWduID0gQXJyYXkuZnJvbShuZXcgVWludDhBcnJheShzaWdCdWYpKS5tYXAoYiA9PiBiLnRvU3RyaW5nKDE2KS5wYWRTdGFydCgyLCAnMCcpKS5qb2luKCcnKTsKICAgIHJldHVybiB7CiAgICAgICdYLVRzJzogdHMsCiAgICAgICdYLU5vbmNlJzogbm9uY2UsCiAgICAgICdYLVNpZ24nOiBzaWduCiAgICB9OwogIH0KICBmdW5jdGlvbiBfY29sbGVjdERldmljZSgpIHsKICAgIGNvbnN0IHVhID0gbmF2aWdhdG9yLnVzZXJBZ2VudCB8fCAnJzsKICAgIGNvbnN0IGlzQW5kcm9pZCA9IC9hbmRyb2lkL2kudGVzdCh1YSk7CiAgICBjb25zdCBpc0lPUyA9IC9pcGhvbmV8aXBhZHxpcG9kL2kudGVzdCh1YSk7CiAgICBsZXQgbW9kZWwgPSAnJzsKICAgIGlmIChpc0FuZHJvaWQpIHsKICAgICAgY29uc3QgbSA9IHVhLm1hdGNoKC87XHMqKFteOyldKz8pXHMrQnVpbGRcLy9pKSB8fCB1YS5tYXRjaCgvYW5kcm9pZFxzK1teOyldKztccyooW147KV0rKS9pKTsKICAgICAgbW9kZWwgPSBtID8gbVsxXS50cmltKCkgOiAnJzsKICAgIH0gZWxzZSBpZiAoaXNJT1MpIHsKICAgICAgbW9kZWwgPSAvaXBhZC9pLnRlc3QodWEpID8gJ2lQYWQnIDogL2lwb2QvaS50ZXN0KHVhKSA/ICdpUG9kJyA6ICdpUGhvbmUnOwogICAgfQogICAgY29uc3QgY29ubiA9IG5hdmlnYXRvci5jb25uZWN0aW9uIHx8IG5hdmlnYXRvci5tb3pDb25uZWN0aW9uIHx8IG5hdmlnYXRvci53ZWJraXRDb25uZWN0aW9uOwogICAgcmV0dXJuIHsKICAgICAgb3M6IGlzQW5kcm9pZCA/ICdBbmRyb2lkJyA6IGlzSU9TID8gJ2lPUycgOiBuYXZpZ2F0b3IucGxhdGZvcm0gfHwgJ1Vua25vd24nLAogICAgICBtb2RlbDogbW9kZWwgfHwgJycsCiAgICAgIGJyYW5kOiAnJywKICAgICAgaXNNb2JpbGU6IGlzQW5kcm9pZCB8fCBpc0lPUywKICAgICAgdG91Y2hQb2ludHM6IG5hdmlnYXRvci5tYXhUb3VjaFBvaW50cyB8fCAwLAogICAgICBjb3JlczogbmF2aWdhdG9yLmhhcmR3YXJlQ29uY3VycmVuY3kgfHwgMCwKICAgICAgbWVtb3J5OiBuYXZpZ2F0b3IuZGV2aWNlTWVtb3J5IHx8IDAsCiAgICAgIHNjcmVlbjogYCR7c2NyZWVuLndpZHRofXgke3NjcmVlbi5oZWlnaHR9YCwKICAgICAgcGl4ZWxSYXRpbzogd2luZG93LmRldmljZVBpeGVsUmF0aW8gfHwgMSwKICAgICAgY29ubmVjdGlvbjogY29ubiA/IGNvbm4uZWZmZWN0aXZlVHlwZSB8fCAnJyA6ICcnLAogICAgICB2ZW5kb3I6IG5hdmlnYXRvci52ZW5kb3IgfHwgJycsCiAgICAgIGxhbmd1YWdlOiBuYXZpZ2F0b3IubGFuZ3VhZ2UgfHwgJycsCiAgICAgIHRpbWV6b25lOiBJbnRsLkRhdGVUaW1lRm9ybWF0KCkucmVzb2x2ZWRPcHRpb25zKCkudGltZVpvbmUgfHwgJycsCiAgICAgIHdlYmRyaXZlcjogISFuYXZpZ2F0b3Iud2ViZHJpdmVyCiAgICB9OwogIH0KICBmdW5jdGlvbiBfY29sbGVjdEZQKCkgewogICAgcmV0dXJuIHsKICAgICAgdWE6IG5hdmlnYXRvci51c2VyQWdlbnQsCiAgICAgIHBsYXRmb3JtOiBuYXZpZ2F0b3IucGxhdGZvcm0gfHwgJycsCiAgICAgIGxhbmd1YWdlOiBuYXZpZ2F0b3IubGFuZ3VhZ2UgfHwgJycsCiAgICAgIHRpbWV6b25lOiBJbnRsLkRhdGVUaW1lRm9ybWF0KCkucmVzb2x2ZWRPcHRpb25zKCkudGltZVpvbmUgfHwgJycsCiAgICAgIHdlYmRyaXZlcjogISFuYXZpZ2F0b3Iud2ViZHJpdmVyLAogICAgICBoYXJkd2FyZUNvbmN1cnJlbmN5OiBuYXZpZ2F0b3IuaGFyZHdhcmVDb25jdXJyZW5jeSB8fCAwLAogICAgICBkZXZpY2VNZW1vcnk6IG5hdmlnYXRvci5kZXZpY2VNZW1vcnkgfHwgMCwKICAgICAgbWF4VG91Y2hQb2ludHM6IG5hdmlnYXRvci5tYXhUb3VjaFBvaW50cyB8fCAwLAogICAgICBzY3JlZW46IGAke3NjcmVlbi53aWR0aH14JHtzY3JlZW4uaGVpZ2h0fWAsCiAgICAgIGNvbG9yRGVwdGg6IHNjcmVlbi5jb2xvckRlcHRoLAogICAgICBwaXhlbFJhdGlvOiB3aW5kb3cuZGV2aWNlUGl4ZWxSYXRpbyB8fCAxCiAgICB9OwogIH0KICBhc3luYyBmdW5jdGlvbiBfZGVyaXZlS2V5KHNlc3Npb25Ub2tlbikgewogICAgY29uc3QgZW5jID0gbmV3IFRleHRFbmNvZGVyLCBjID0gX2NyeXB0b09iaigpOwogICAgY29uc3QgYmFzZUtleSA9IGF3YWl0IGMuc3VidGxlLmltcG9ydEtleSgncmF3JywgZW5jLmVuY29kZShzZXNzaW9uVG9rZW4gKyAnfCcgKyBBUElfU0VDUkVUKSwgJ1BCS0RGMicsIGZhbHNlLCBbICdkZXJpdmVCaXRzJyBdKTsKICAgIGNvbnN0IGJpdHMgPSBhd2FpdCBjLnN1YnRsZS5kZXJpdmVCaXRzKHsKICAgICAgbmFtZTogJ1BCS0RGMicsCiAgICAgIHNhbHQ6IGVuYy5lbmNvZGUoJ2dvZG1vZGUtdjQtc2FsdCcpLAogICAgICBpdGVyYXRpb25zOiAxZTMsCiAgICAgIGhhc2g6ICdTSEEtMjU2JwogICAgfSwgYmFzZUtleSwgMjU2KTsKICAgIHJldHVybiBjLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGJpdHMsIHsKICAgICAgbmFtZTogJ0FFUy1HQ00nCiAgICB9LCBmYWxzZSwgWyAnZGVjcnlwdCcgXSk7CiAgfQogIGZ1bmN0aW9uIF9iNjRUb0J5dGVzKGI2NCkgewogICAgY29uc3QgYmluID0gYXRvYihiNjQpOwogICAgcmV0dXJuIFVpbnQ4QXJyYXkuZnJvbShiaW4sIHggPT4geC5jaGFyQ29kZUF0KDApKTsKICB9CiAgYXN5bmMgZnVuY3Rpb24gX2RlY3J5cHRBbnN3ZXJzKHBheWxvYWQsIHNlc3Npb25Ub2tlbikgewogICAgY29uc3QgYyA9IF9jcnlwdG9PYmooKTsKICAgIGNvbnN0IGtleSA9IGF3YWl0IF9kZXJpdmVLZXkoc2Vzc2lvblRva2VuKTsKICAgIGNvbnN0IGl2ID0gX2I2NFRvQnl0ZXMocGF5bG9hZC5pdiksIGRhdGEgPSBfYjY0VG9CeXRlcyhwYXlsb2FkLmRhdGEpLCB0YWcgPSBfYjY0VG9CeXRlcyhwYXlsb2FkLnRhZyk7CiAgICBjb25zdCBidWYgPSBuZXcgVWludDhBcnJheShkYXRhLmxlbmd0aCArIHRhZy5sZW5ndGgpOwogICAgYnVmLnNldChkYXRhKTsKICAgIGJ1Zi5zZXQodGFnLCBkYXRhLmxlbmd0aCk7CiAgICBjb25zdCBwbGFpbiA9IGF3YWl0IGMuc3VidGxlLmRlY3J5cHQoewogICAgICBuYW1lOiAnQUVTLUdDTScsCiAgICAgIGl2OiBpdgogICAgfSwga2V5LCBidWYpOwogICAgcmV0dXJuIEpTT04ucGFyc2UoKG5ldyBUZXh0RGVjb2RlcikuZGVjb2RlKHBsYWluKSk7CiAgfQogIGFzeW5jIGZ1bmN0aW9uIF9lbnN1cmVTZXNzaW9uKGtleSwgaHdpZCkgewogICAgaWYgKF9zZWNTZXNzaW9uLnRva2VuICYmIF9zZWNTZXNzaW9uLmV4cCA+IERhdGUubm93KCkpIHJldHVybiBfc2VjU2Vzc2lvbi50b2tlbjsKICAgIGlmICgha2V5KSB0aHJvdyBuZXcgRXJyb3IoJ1RoaeG6v3Uga2V5IOKAlCBraMO0bmcgdGjhu4MgeMOhYyB0aOG7sWMgcGhpw6puJyk7CiAgICBjb25zdCByID0gYXdhaXQgZ21Qb3N0KCcvYXR0ZXN0JywgewogICAgICBrZXk6IGtleSwKICAgICAgaHdpZDogaHdpZCB8fCBnZXRIV0lEKCksCiAgICAgIGZwOiBfY29sbGVjdEZQKCksCiAgICAgIGRldmljZTogX2NvbGxlY3REZXZpY2UoKQogICAgfSk7CiAgICBpZiAoIXIuc3VjY2VzcykgdGhyb3cgbmV3IEVycm9yKHIubWVzc2FnZSB8fCByLmVycm9yIHx8ICdYw6FjIHRo4buxYyB0aGnhur90IGLhu4svbeG6oW5nIHRo4bqldCBi4bqhaSAoSFRUUCAnICsgKHIuX2h0dHBTdGF0dXMgfHwgMCkgKyAnKSDigJQgeGVtIHBhbmVsIGFkbWluIGxvZyDEkeG7gyBiaeG6v3QgbMO9IGRvKScpOwogICAgX3NlY1Nlc3Npb24gPSB7CiAgICAgIHRva2VuOiByLnNlc3Npb24sCiAgICAgIGV4cDogRGF0ZS5ub3coKSArIChyLmV4cGlyZXNJbiAtIDMwKSAqIDFlMywKICAgICAgZnBIYXNoOiByLmZwSGFzaCwKICAgICAgc2VxOiAxCiAgICB9OwogICAgaWYgKHIuZGV2aWNlKSBDVVJSRU5UX0RFVklDRSA9IHIuZGV2aWNlOwogICAgcmV0dXJuIHIuc2Vzc2lvbjsKICB9CiAgZnVuY3Rpb24gX3N0YXJ0SGVhcnRiZWF0KCkgewogICAgaWYgKF9oZWFydGJlYXRUaW1lcikgcmV0dXJuOwogICAgX2hlYXJ0YmVhdFRpbWVyID0gc2V0SW50ZXJ2YWwoYXN5bmMgKCkgPT4gewogICAgICBpZiAoIUNVUlJFTlRfS0VZKSByZXR1cm47CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgciA9IGF3YWl0IGdtUG9zdCgnL2hlYXJ0YmVhdCcsIHsKICAgICAgICAgIGtleTogQ1VSUkVOVF9LRVksCiAgICAgICAgICBod2lkOiBnZXRIV0lEKCksCiAgICAgICAgICBmcDogX2NvbGxlY3RGUCgpLAogICAgICAgICAgZGV2aWNlOiBfY29sbGVjdERldmljZSgpLAogICAgICAgICAgY2xpZW50VmVyc2lvbjogMTgsCiAgICAgICAgICBjb25uZWN0b3JWZXJzaW9uOiAxOAogICAgICAgIH0pOwogICAgICAgIF9oZWFydGJlYXRGYWlsID0gMDsKICAgICAgICBpZiAociAmJiByLmJsb2NrZWQpIHsKICAgICAgICAgIF9lbnRlckJhbk1vZGUoJ1NlcnZlciBwaMOhdCBoaeG7h24gbcO0aSB0csaw4budbmcga2jDtG5nIGjhu6NwIGzhu4cgKCcgKyAoci5yZWFzb24gfHwgJ3Vua25vd24nKSArICcpLicpOwogICAgICAgICAgcmV0dXJuOwogICAgICAgIH0KICAgICAgICBpZiAociAmJiByLl9odHRwU3RhdHVzID09PSA0MDQpIHsKICAgICAgICAgIF9lbnRlckJhbk1vZGUoJ1RoaeG6v3QgYuG7iy9JUCDEkcOjIGLhu4sgYWRtaW4ga2hvw6EuJyk7CiAgICAgICAgICByZXR1cm47CiAgICAgICAgfQogICAgICB9IGNhdGNoIChlKSB7CiAgICAgICAgX2hlYXJ0YmVhdEZhaWwrKzsKICAgICAgICBpZiAoX2hlYXJ0YmVhdEZhaWwgPj0gMTApIHsKICAgICAgICAgIGFkZExvZygn4pqg77iPIE3huqV0IGvhur90IG7hu5FpIHNlcnZlciBrw6lvIGTDoGkg4oCUIGNo4bupYyBuxINuZyBu4buZcCBiw6BpIHThuqFtIGtow7NhIGNobyB04bubaSBraGkga+G6v3QgbuG7kWkgbOG6oWkuJywgJ3dhcm4nKTsKICAgICAgICAgIF9oZWFydGJlYXRGYWlsID0gMDsKICAgICAgICB9CiAgICAgIH0KICAgIH0sIDNlNCk7CiAgfQogIGFzeW5jIGZ1bmN0aW9uIGdtUG9zdChwYXRoLCBkYXRhKSB7CiAgICBjb25zdCBoZWFkZXJzID0gewogICAgICAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nCiAgICB9OwogICAgbGV0IHNlc3Npb25Ub2tlbiA9IG51bGw7CiAgICBjb25zdCBwcmVmaXggPSBhd2FpdCBfYXBpUHJlZml4KCk7CiAgICBjb25zdCBhY3R1YWxQYXRoID0gcHJlZml4ICsgcGF0aDsKICAgIGlmIChwYXRoID09PSAnL3Byb2Nlc3MnIHx8IHBhdGggPT09ICcvZmlyZScgfHwgcGF0aCA9PT0gJy9tb2R1bGUnKSB7CiAgICAgIHNlc3Npb25Ub2tlbiA9IGF3YWl0IF9lbnN1cmVTZXNzaW9uKGRhdGEgJiYgZGF0YS5rZXksIGRhdGEgJiYgZGF0YS5od2lkKTsKICAgICAgaGVhZGVyc1snWC1TZXNzaW9uJ10gPSBzZXNzaW9uVG9rZW47CiAgICAgIGhlYWRlcnNbJ1gtU2VxJ10gPSBTdHJpbmcoX3NlY1Nlc3Npb24uc2VxIHx8IDEpOwogICAgICBpZiAoX3NlY1Nlc3Npb24uZnBIYXNoKSBoZWFkZXJzWydYLUZwLUhhc2gnXSA9IF9zZWNTZXNzaW9uLmZwSGFzaDsKICAgIH0KICAgIGxldCByZXFCb2R5ID0gSlNPTi5zdHJpbmdpZnkoZGF0YSk7CiAgICBpZiAoUkVRVUVTVF9FTkNSWVBUSU9OKSB7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgZW5jID0gYXdhaXQgX2VuY3J5cHRQYXlsb2FkKGRhdGEsIHNlc3Npb25Ub2tlbiB8fCBfYXBpUHJlZml4Q2FjaGUgfHwgJycpOwogICAgICAgIHJlcUJvZHkgPSBKU09OLnN0cmluZ2lmeShlbmMpOwogICAgICAgIGhlYWRlcnNbJ1gtRW5jLVYnXSA9ICc1JzsKICAgICAgfSBjYXRjaCAoXykge30KICAgIH0KICAgIHRyeSB7CiAgICAgIE9iamVjdC5hc3NpZ24oaGVhZGVycywgYXdhaXQgX3NpZ25SZXEocmVxQm9keSwgc2Vzc2lvblRva2VuKSk7CiAgICB9IGNhdGNoIChfKSB7fQogICAgY29uc3QgcmVzdWx0ID0gYXdhaXQgbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4gewogICAgICBHTV94bWxodHRwUmVxdWVzdCh7CiAgICAgICAgbWV0aG9kOiAnUE9TVCcsCiAgICAgICAgdXJsOiBTRVJWRVJfQkFTRSArIGFjdHVhbFBhdGgsCiAgICAgICAgaGVhZGVyczogaGVhZGVycywKICAgICAgICBkYXRhOiByZXFCb2R5LAogICAgICAgIHRpbWVvdXQ6IDE1ZTMsCiAgICAgICAgb25sb2FkOiByID0+IHsKICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgIGNvbnN0IHBhcnNlZCA9IEpTT04ucGFyc2Uoci5yZXNwb25zZVRleHQpOwogICAgICAgICAgICBwYXJzZWQuX2h0dHBTdGF0dXMgPSByLnN0YXR1czsKICAgICAgICAgICAgcmVzb2x2ZShwYXJzZWQpOwogICAgICAgICAgfSBjYXRjaCAoXykgewogICAgICAgICAgICByZWplY3QobmV3IEVycm9yKCdQYXJzZSBlcnJvciAoSFRUUCAnICsgci5zdGF0dXMgKyAnKScpKTsKICAgICAgICAgIH0KICAgICAgICB9LAogICAgICAgIG9uZXJyb3I6ICgpID0+IHJlamVjdChuZXcgRXJyb3IoJ05ldHdvcmsgZXJyb3InKSksCiAgICAgICAgb250aW1lb3V0OiAoKSA9PiByZWplY3QobmV3IEVycm9yKCdUaW1lb3V0JykpCiAgICAgIH0pOwogICAgfSk7CiAgICBpZiAocGF0aCA9PT0gJy9wcm9jZXNzJyAmJiByZXN1bHQgJiYgcmVzdWx0LmVuY3J5cHRlZCAmJiByZXN1bHQucGF5bG9hZCAmJiBzZXNzaW9uVG9rZW4pIHsKICAgICAgdHJ5IHsKICAgICAgICByZXN1bHQucXVlc3Rpb25zID0gYXdhaXQgX2RlY3J5cHRBbnN3ZXJzKHJlc3VsdC5wYXlsb2FkLCBzZXNzaW9uVG9rZW4pOwogICAgICAgIHJlc3VsdC5lbmNyeXB0ZWQgPSBmYWxzZTsKICAgICAgfSBjYXRjaCAoZSkgewogICAgICAgIHJlc3VsdC5zdWNjZXNzID0gZmFsc2U7CiAgICAgICAgcmVzdWx0Lm1lc3NhZ2UgPSAnR2nhuqNpIG3DoyDEkcOhcCDDoW4gdGjhuqV0IGLhuqFpOiAnICsgZS5tZXNzYWdlOwogICAgICB9CiAgICB9CiAgICBpZiAocmVzdWx0ICYmIHJlc3VsdC5uZXh0X3Nlc3Npb24pIHsKICAgICAgX3NlY1Nlc3Npb24udG9rZW4gPSByZXN1bHQubmV4dF9zZXNzaW9uOwogICAgICBfc2VjU2Vzc2lvbi5leHAgPSBEYXRlLm5vdygpICsgMjcwICogMWUzOwogICAgICBfc2VjU2Vzc2lvbi5zZXEgPSByZXN1bHQubmV4dF9zZXEgPyBwYXJzZUludChyZXN1bHQubmV4dF9zZXEsIDEwKSA6IChfc2VjU2Vzc2lvbi5zZXEgfHwgMSkgKyAxOwogICAgICBkZWxldGUgcmVzdWx0Lm5leHRfc2Vzc2lvbjsKICAgICAgZGVsZXRlIHJlc3VsdC5uZXh0X3NlcTsKICAgIH0KICAgIHJldHVybiByZXN1bHQ7CiAgfQogIGZ1bmN0aW9uIGdldFVzZXJJbmZvKCkgewogICAgdHJ5IHsKICAgICAgY29uc3QgbSA9IGRvY3VtZW50LmNvb2tpZS5tYXRjaCgvKD86Xnw7ICl1c2VyPShbXjtdKikvKTsKICAgICAgaWYgKG0gJiYgbVsxXSkgewogICAgICAgIGNvbnN0IHBhcnNlZCA9IEpTT04ucGFyc2UoZGVjb2RlVVJJQ29tcG9uZW50KG1bMV0pKTsKICAgICAgICBpZiAocGFyc2VkICYmIChwYXJzZWQuX2lkIHx8IHBhcnNlZC5pZCkpIHJldHVybiBwYXJzZWQ7CiAgICAgIH0KICAgIH0gY2F0Y2ggKF8pIHt9CiAgICB0cnkgewogICAgICByZXR1cm4gd2luZG93LnVzZXJfaW5mbyB8fCB3aW5kb3cucF9jb25maWc/LnVzZXJfaW5mbyB8fCB1bnNhZmVXaW5kb3c/LnVzZXJfaW5mbyB8fCBudWxsOwogICAgfSBjYXRjaCAoXykgewogICAgICByZXR1cm4gbnVsbDsKICAgIH0KICB9CiAgZnVuY3Rpb24gZ2V0T2xtVXNlcm5hbWUoKSB7CiAgICB0cnkgewogICAgICBjb25zdCBkb21JbnB1dCA9IGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoJyNpbmZvLWFjY291bnQgaW5wdXQuZm9ybS1jb250cm9sW3JlYWRvbmx5XScpOwogICAgICBpZiAoZG9tSW5wdXQgJiYgZG9tSW5wdXQudmFsdWUpIHJldHVybiBkb21JbnB1dC52YWx1ZS50cmltKCk7CiAgICAgIGNvbnN0IHVpID0gZ2V0VXNlckluZm8oKTsKICAgICAgaWYgKHVpICYmIHVpLnVzZXJuYW1lKSByZXR1cm4gdWkudXNlcm5hbWU7CiAgICAgIGlmICh1aSAmJiB1aS5uYW1lKSByZXR1cm4gdWkubmFtZTsKICAgICAgY29uc3QgZWwgPSBkb2N1bWVudC5xdWVyeVNlbGVjdG9yKCcudXNlcm5hbWUsIC51c2VyLW5hbWUsIFtjbGFzcyo9InVzZXJuYW1lIl0nKTsKICAgICAgcmV0dXJuIGVsID8gZWwudGV4dENvbnRlbnQudHJpbSgpIDogJ0tob25nWGFjRGluaCc7CiAgICB9IGNhdGNoIChfKSB7CiAgICAgIHJldHVybiAnS2hvbmdYYWNEaW5oJzsKICAgIH0KICB9CiAgZnVuY3Rpb24gZ2V0SFdJRCgpIHsKICAgIGxldCBoID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ190bF9od2lkJyk7CiAgICBpZiAoIWgpIHsKICAgICAgY29uc3QgdWEgPSBuYXZpZ2F0b3IudXNlckFnZW50ICsgbmF2aWdhdG9yLmxhbmd1YWdlICsgc2NyZWVuLndpZHRoICsgc2NyZWVuLmhlaWdodDsKICAgICAgbGV0IGhhc2ggPSA1MzgxOwogICAgICBmb3IgKGxldCBpID0gMDsgaSA8IHVhLmxlbmd0aDsgaSsrKSBoYXNoID0gKGhhc2ggPDwgNSkgKyBoYXNoIF4gdWEuY2hhckNvZGVBdChpKTsKICAgICAgaCA9ICdIVycgKyBNYXRoLmFicyhoYXNoKS50b1N0cmluZygxNikudG9VcHBlckNhc2UoKS5wYWRTdGFydCg4LCAnMCcpOwogICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbSgnX3RsX2h3aWQnLCBoKTsKICAgIH0KICAgIHJldHVybiBoOwogIH0KICBmdW5jdGlvbiByaXBJZEZyb21VcmwoKSB7CiAgICBjb25zdCBtID0gd2luZG93LmxvY2F0aW9uLnBhdGhuYW1lLm1hdGNoKC8tKFxkKykoPzpcP3xcL3wkKS8pOwogICAgcmV0dXJuIG0gPyBtWzFdIDogbnVsbDsKICB9CiAgZnVuY3Rpb24gZGV0ZWN0VXNlcklEKCkgewogICAgY29uc3QgdWkgPSBnZXRVc2VySW5mbygpOwogICAgcmV0dXJuIFNFU1NJT04ubWV0YS5pZF91c2VyIHx8ICh1aSA/IHVpLl9pZCB8fCB1aS5pZCA6IG51bGwpIHx8IHdpbmRvdz8ucF9jb25maWc/LmlkX3VzZXIgfHwgbnVsbDsKICB9CiAgZnVuY3Rpb24gZGV0ZWN0U2Nob29sSUQoZGF0YSkgewogICAgcmV0dXJuIGRhdGE/LmlkX3NjaG9vbCB8fCB3aW5kb3c/LnBfY29uZmlnPy5zY2hvb2xfaWQgfHwgZ2V0VXNlckluZm8oKT8uaWRfc2Nob29sIHx8IG51bGw7CiAgfQogIGZ1bmN0aW9uIGRldGVjdEdyb3VwSUQoKSB7CiAgICBjb25zdCBtID0gd2luZG93LmxvY2F0aW9uLmhyZWYubWF0Y2goL1wvbG9wXC9bXi9dK1wuKFxkKykvKTsKICAgIHJldHVybiBtICYmIG1bMV0gPyBtWzFdIDogbnVsbDsKICB9CiAgZnVuY3Rpb24gZm9yY2VHZXRNZXRhKCkgewogICAgY29uc3QgdWkgPSBnZXRVc2VySW5mbygpOwogICAgaWYgKCFTRVNTSU9OLm1ldGEuaWRfdXNlcikgU0VTU0lPTi5tZXRhLmlkX3VzZXIgPSB1aSAmJiAodWkuX2lkIHx8IHVpLmlkKSB8fCB3aW5kb3c/LnBfY29uZmlnPy5pZF91c2VyIHx8IGRldGVjdFVzZXJJRCgpOwogICAgaWYgKCFTRVNTSU9OLm1ldGEuaWRfY2F0ZSkgU0VTU0lPTi5tZXRhLmlkX2NhdGUgPSB3aW5kb3c/LnBfY29uZmlnPy5pZF9jYXRlIHx8IHdpbmRvdz8ucF9jb25maWc/LmlkX2V4YW0gfHwgbmV3IFVSTFNlYXJjaFBhcmFtcyh3aW5kb3cubG9jYXRpb24uc2VhcmNoKS5nZXQoJ2lkX2NhdGUnKSB8fCBuZXcgVVJMU2VhcmNoUGFyYW1zKHdpbmRvdy5sb2NhdGlvbi5zZWFyY2gpLmdldCgnaWRfZXhhbScpIHx8IHJpcElkRnJvbVVybCgpOwogICAgaWYgKCFTRVNTSU9OLm1ldGEuaWRfY291cnNld2FyZSkgU0VTU0lPTi5tZXRhLmlkX2NvdXJzZXdhcmUgPSBuZXcgVVJMU2VhcmNoUGFyYW1zKHdpbmRvdy5sb2NhdGlvbi5zZWFyY2gpLmdldCgnaV9jJykgfHwgbmV3IFVSTFNlYXJjaFBhcmFtcyh3aW5kb3cubG9jYXRpb24uc2VhcmNoKS5nZXQoJ2lkX2NvdXJzZXdhcmUnKSB8fCBTRVNTSU9OLm1ldGEuaWRfY2F0ZTsKICAgIGlmICghU0VTU0lPTi5tZXRhLmlkX3NjaG9vbCkgU0VTU0lPTi5tZXRhLmlkX3NjaG9vbCA9IHVpICYmIHVpLmlkX3NjaG9vbCB8fCB3aW5kb3c/LnBfY29uZmlnPy5zY2hvb2xfaWQgfHwgbnVsbDsKICAgIGlmICghU0VTU0lPTi5tZXRhLmNzcmZfdG9rZW4pIHsKICAgICAgY29uc3QgbSA9IGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoJ21ldGFbbmFtZT0iY3NyZi10b2tlbiJdJyk7CiAgICAgIFNFU1NJT04ubWV0YS5jc3JmX3Rva2VuID0gbSA/IG0uZ2V0QXR0cmlidXRlKCdjb250ZW50JykgOiB3aW5kb3cuY3NyZl90b2tlbiB8fCAnJzsKICAgIH0KICB9CiAgZnVuY3Rpb24gYWRkTG9nKG1zZywgdHlwZSA9ICcnKSB7CiAgICBjb25zdCBib3ggPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtbG9nYm94Jyk7CiAgICBpZiAoIWJveCkgcmV0dXJuOwogICAgY29uc3QgZCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpOwogICAgZC5jbGFzc05hbWUgPSAndGwtbG9nICcgKyB0eXBlOwogICAgY29uc3QgdGltZSA9IChuZXcgRGF0ZSkudG9Mb2NhbGVUaW1lU3RyaW5nKCd2aS1WTicsIHsKICAgICAgaG91cjogJzItZGlnaXQnLAogICAgICBtaW51dGU6ICcyLWRpZ2l0JywKICAgICAgc2Vjb25kOiAnMi1kaWdpdCcKICAgIH0pOwogICAgZC5pbm5lckhUTUwgPSBgWyR7dGltZX1dICR7bXNnfWA7CiAgICBib3guYXBwZW5kQ2hpbGQoZCk7CiAgICBib3guc2Nyb2xsVG9wID0gYm94LnNjcm9sbEhlaWdodDsKICB9CiAgd2luZG93LmFkZExvZyA9IGFkZExvZzsKICBmdW5jdGlvbiBidWlsZExvY2tTY3JlZW4ocmVhc29uKSB7CiAgICBpZiAoZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLWNvbm4tb3ZlcmxheScpKSByZXR1cm47CiAgICBsZXQgbG9ja1N0eWxlID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLWxvY2stc3R5bGUnKTsKICAgIGlmICghbG9ja1N0eWxlKSB7CiAgICAgIGxvY2tTdHlsZSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ3N0eWxlJyk7CiAgICAgIGxvY2tTdHlsZS5pZCA9ICd0bC1sb2NrLXN0eWxlJzsKICAgICAgZG9jdW1lbnQuaGVhZC5hcHBlbmRDaGlsZChsb2NrU3R5bGUpOwogICAgfQogICAgbG9ja1N0eWxlLnRleHRDb250ZW50ID0gZ2V0TG9ja1NjcmVlblN0eWxlcygpOwogICAgY29uc3Qgb3ZlcmxheSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpOwogICAgb3ZlcmxheS5pZCA9ICd0bC1jb25uLW92ZXJsYXknOwogICAgY29uc3QgdGxGeCA9IGdldFRoZW1lQ29sb3JzKENVUlJFTlRfVEhFTUUpLnBhbmVsRXh0cmEgfHwgJyc7CiAgICBvdmVybGF5LmlubmVySFRNTCA9IGBcbiAgICAgICAgICAgIDxkaXYgaWQ9InRsLWNvbm4tcGFuZWwiPlxuICAgICAgICAgICAgICAgICR7dGxGeH1cbiAgICAgICAgICAgICAgICA8ZGl2IGlkPSJ0bC1jb25uLWhlYWRlciI+XG4gICAgICAgICAgICAgICAgICAgIDxzcGFuIGNsYXNzPSJ0bC1icmFuZC1uYW1lIj7wn5qAIFRIScOKTiBUQUkgVMOZIFThu5hJIC8vIEdPRCBNT0RFIHYzLjI8L3NwYW4+XG4gICAgICAgICAgICAgICAgPC9kaXY+XG4gICAgICAgICAgICAgICAgPGRpdiBpZD0idGwtY29ubi1ib2R5Ij5cbiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtc3VidGl0bGUiPvCflJAgTkjhuqxQIExJQ0VOU0UgS0VZIMSQ4buCIEvDjUNIIEhP4bqgVDwvZGl2PlxuICAgICAgICAgICAgICAgICAgICAke3JlYXNvbiA/IGA8ZGl2IGNsYXNzPSJ0bC13YXJuaW5nIj7imqDvuI8gJHtyZWFzb259PC9kaXY+YCA6ICcnfVxuICAgICAgICAgICAgICAgICAgICA8aW5wdXQgdHlwZT0idGV4dCIgY2xhc3M9InRsLWlucHV0IiBpZD0idGwta2V5LWlucHV0IlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgcGxhY2Vob2xkZXI9Ik5o4bqtcCBrZXkgYuG6o24gcXV54buBbi4uLiIgYXV0b2NvbXBsZXRlPSJvZmYiPlxuICAgICAgICAgICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJ0bC1idG4gdGwtYnRuLXVubG9jayIgaWQ9InRsLWJ0bi11bmxvY2siPvCflJMgS8ONQ0ggSE/huqBUPC9idXR0b24+XG4gICAgICAgICAgICAgICAgICAgIDxidXR0b24gY2xhc3M9InRsLWJ0biB0bC1idG4tdmlwIiAgIGlkPSJ0bC1idG4tYnV5Ij7wn5KOIE1VQSBLRVkgKExJw4pOIEjhu4YpPC9idXR0b24+XG4gICAgICAgICAgICAgICAgICAgIDxkaXYgaWQ9InRsLWVyciI+PC9kaXY+XG4gICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLWh3aWQiIGlkPSJ0bC1od2lkLWRpc3BsYXkiPjwvZGl2PlxuICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC1mb290Ij5Zw6p1IGPhuqd1OiBtw6F5IEFuZHJvaWQvaU9TIHRo4bqtdCDigKIgdHLDrG5oIGR1eeG7h3QgdGjhuq10IOKAoiBt4bqhbmcgdGjhuq10PC9kaXY+XG4gICAgICAgICAgICAgICAgPC9kaXY+XG4gICAgICAgICAgICA8L2Rpdj5gOwogICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChvdmVybGF5KTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1od2lkLWRpc3BsYXknKS50ZXh0Q29udGVudCA9IGDwn5SRIEhXSUQ6ICR7Z2V0SFdJRCgpfWA7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtYnRuLWJ1eScpLm9uY2xpY2sgPSAoKSA9PiB3aW5kb3cub3BlbignaHR0cHM6Ly90Lm1lL2x1b25ndHV5ZW4yMCcsICdfYmxhbmsnKTsKICAgIGNvbnN0IGJ0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1idG4tdW5sb2NrJyk7CiAgICBjb25zdCBlcnJCb3ggPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtZXJyJyk7CiAgICBsZXQgdmVyaWZ5aW5nID0gZmFsc2U7CiAgICBidG4ub25jbGljayA9IGFzeW5jICgpID0+IHsKICAgICAgaWYgKHZlcmlmeWluZykgcmV0dXJuOwogICAgICBjb25zdCBrZXkgPSAoZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLWtleS1pbnB1dCcpLnZhbHVlIHx8ICcnKS50cmltKCkudG9VcHBlckNhc2UoKTsKICAgICAgaWYgKCFrZXkpIHsKICAgICAgICBlcnJCb3gudGV4dENvbnRlbnQgPSAn4p2MIFZ1aSBsw7JuZyBuaOG6rXAga2V5ISc7CiAgICAgICAgZXJyQm94LnN0eWxlLmRpc3BsYXkgPSAnYmxvY2snOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICB2ZXJpZnlpbmcgPSB0cnVlOwogICAgICBidG4udGV4dENvbnRlbnQgPSAn4o+zIMSQQU5HIFjDgUMgVEjhu7BDLi4uJzsKICAgICAgYnRuLmRpc2FibGVkID0gdHJ1ZTsKICAgICAgZXJyQm94LnN0eWxlLmRpc3BsYXkgPSAnbm9uZSc7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgcHJlZml4ID0gYXdhaXQgX2FwaVByZWZpeCgpOwogICAgICAgIGNvbnN0IHBpbmdPayA9IGF3YWl0IG5ldyBQcm9taXNlKHJlc29sdmUgPT4gewogICAgICAgICAgR01feG1saHR0cFJlcXVlc3QoewogICAgICAgICAgICBtZXRob2Q6ICdHRVQnLAogICAgICAgICAgICB1cmw6IFNFUlZFUl9CQVNFICsgcHJlZml4ICsgJy9waW5nJywKICAgICAgICAgICAgdGltZW91dDogOGUzLAogICAgICAgICAgICBvbmxvYWQ6IHIgPT4gcmVzb2x2ZShyLnN0YXR1cyA9PT0gMjAwKSwKICAgICAgICAgICAgb25lcnJvcjogKCkgPT4gcmVzb2x2ZShmYWxzZSksCiAgICAgICAgICAgIG9udGltZW91dDogKCkgPT4gcmVzb2x2ZShmYWxzZSkKICAgICAgICAgIH0pOwogICAgICAgIH0pOwogICAgICAgIGlmICghcGluZ09rKSB0aHJvdyBuZXcgRXJyb3IoJ0tIw5RORyBL4bq+VCBO4buQSSDEkMav4buiQyBTRVJWRVIuIEtp4buDbSB0cmE6IDEpIFVSTCBTRVJWRVJfQkFTRSwgMikgQVBJX1NFQ1JFVCBraOG7m3AgR09ETU9ERV9TRUNSRVQgdHLDqm4gc2VydmVyLCAzKSDEkcOjIGRlcGxveS9yZWRlcGxveS4nKTsKICAgICAgICBjb25zdCBjdXJyZW50T2xtID0gZ2V0T2xtVXNlcm5hbWUoKTsKICAgICAgICBjb25zdCByZXN1bHQgPSBhd2FpdCBnbVBvc3QoJy92ZXJpZnknLCB7CiAgICAgICAgICBrZXk6IGtleSwKICAgICAgICAgIGh3aWQ6IGdldEhXSUQoKSwKICAgICAgICAgIG9sbV91c2VyOiBjdXJyZW50T2xtCiAgICAgICAgfSk7CiAgICAgICAgaWYgKHJlc3VsdC5zdWNjZXNzIHx8IHJlc3VsdC52YWxpZCkgewogICAgICAgICAgY29uc3Qgc2VydmVyT2xtID0gcmVzdWx0Lm9sbV91c2VyIHx8IHJlc3VsdC5vbG1fYWNjb3VudCB8fCAnJzsKICAgICAgICAgIGlmIChzZXJ2ZXJPbG0gJiYgY3VycmVudE9sbSAmJiBjdXJyZW50T2xtICE9PSAnS2hvbmdYYWNEaW5oJykgewogICAgICAgICAgICBpZiAoc2VydmVyT2xtLnRvTG93ZXJDYXNlKCkgIT09IGN1cnJlbnRPbG0udG9Mb3dlckNhc2UoKSkgewogICAgICAgICAgICAgIGVyckJveC5pbm5lckhUTUwgPSBg8J+aqyA8Yj5Uw6BpIGtob+G6o24gT0xNIGtow7RuZyBraOG7m3AhPC9iPjxicj5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgS2V5IGTDoG5oIGNobzogPGI+JHtzZXJ2ZXJPbG19PC9iPjxicj5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgSGnhu4duIHThuqFpOiA8Yj4ke2N1cnJlbnRPbG19PC9iPjxicj5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgVnVpIGzDsm5nIMSRxINuZyBuaOG6rXAgxJHDum5nIHTDoGkga2hv4bqjbiBPTE0hYDsKICAgICAgICAgICAgICBlcnJCb3guc3R5bGUuZGlzcGxheSA9ICdibG9jayc7CiAgICAgICAgICAgICAgYnRuLnRleHRDb250ZW50ID0gJ/CflJMgS8ONQ0ggSE/huqBUJzsKICAgICAgICAgICAgICBidG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgICAgICAgICB2ZXJpZnlpbmcgPSBmYWxzZTsKICAgICAgICAgICAgICByZXR1cm47CiAgICAgICAgICAgIH0KICAgICAgICAgIH0KICAgICAgICAgIF9zTFMuc2V0KExTX0tFWSwga2V5KTsKICAgICAgICAgIF9zTFMuc2V0KExTX1RZUEUsIHJlc3VsdC50eXBlIHx8IHJlc3VsdC5wbGFuIHx8ICdUSFVPTkcnKTsKICAgICAgICAgIF9zTFMuc2V0KExTX0VYUCwgcmVzdWx0LmV4cGlyZXNfYXQgfHwgJycpOwogICAgICAgICAgQ1VSUkVOVF9LRVkgPSBrZXk7CiAgICAgICAgICBLRVlfU1RBVFVTID0gewogICAgICAgICAgICB2YWxpZDogdHJ1ZSwKICAgICAgICAgICAgdHlwZTogcmVzdWx0LnR5cGUgfHwgcmVzdWx0LnBsYW4sCiAgICAgICAgICAgIGV4cGlyZXNfYXQ6IHJlc3VsdC5leHBpcmVzX2F0IHx8IHJlc3VsdC5leHAKICAgICAgICAgIH07CiAgICAgICAgICBjb25zdCBrZXlUeXBlTGFiZWwgPSAocmVzdWx0LnR5cGUgfHwgcmVzdWx0LnBsYW4gfHwgJ1RIVU9ORycpLnRvVXBwZXJDYXNlKCk7CiAgICAgICAgICBjb25zdCBpc1ByZW1pdW0gPSBbICdQUkVNSVVNJywgJ1ZJUCcsICdVTkxJTUlURUQnIF0uaW5jbHVkZXMoa2V5VHlwZUxhYmVsKTsKICAgICAgICAgIGxldCBleHBpcnlMaW5lID0gJyc7CiAgICAgICAgICBjb25zdCBleFJhdyA9IHJlc3VsdC5leHBpcmVzX2F0IHx8IHJlc3VsdC5leHAgfHwgJyc7CiAgICAgICAgICBpZiAoZXhSYXcpIHsKICAgICAgICAgICAgY29uc3QgZXhwRGF0ZSA9IG5ldyBEYXRlKGV4UmF3KTsKICAgICAgICAgICAgY29uc3QgZGF5c0xlZnQgPSBNYXRoLmNlaWwoKGV4cERhdGUgLSBuZXcgRGF0ZSkgLyAoMWUzICogNjAgKiA2MCAqIDI0KSk7CiAgICAgICAgICAgIGNvbnN0IGV4cFN0ciA9IGV4cERhdGUudG9Mb2NhbGVEYXRlU3RyaW5nKCd2aS1WTicpOwogICAgICAgICAgICBpZiAoZGF5c0xlZnQgPiAwKSBleHBpcnlMaW5lID0gYPCfk4UgSOG6v3QgaOG6oW46IDxiPiR7ZXhwU3RyfTwvYj4gKGPDsm4gPGI+JHtkYXlzTGVmdH08L2I+IG5nw6B5KWA7IGVsc2UgaWYgKGRheXNMZWZ0ID09PSAwKSBleHBpcnlMaW5lID0gYPCfk4UgSOG6v3QgaOG6oW46IDxiPkjDtG0gbmF5PC9iPiAoJHtleHBTdHJ9KWA7IGVsc2UgZXhwaXJ5TGluZSA9IGDwn5OFIEjhur90IGjhuqFuOiA8Yj4ke2V4cFN0cn08L2I+IDxzcGFuIHN0eWxlPSJjb2xvcjojZmY0NDQ0OyI+KMSRw6MgaOG6v3QgaOG6oW4pPC9zcGFuPmA7CiAgICAgICAgICB9CiAgICAgICAgICBvdmVybGF5LnJlbW92ZSgpOwogICAgICAgICAgaWYgKCFpc1ByZW1pdW0pIHsKICAgICAgICAgICAgc2hvd0N1c3RvbU1vZGFsKHsKICAgICAgICAgICAgICBpY29uOiAn4pyFJywKICAgICAgICAgICAgICB0aXRsZTogJ0vDjUNIIEhP4bqgVCBUSMOATkggQ8OUTkchJywKICAgICAgICAgICAgICBsaW5lczogWyBgTG/huqFpIGtleTogPGI+JHtrZXlUeXBlTGFiZWx9PC9iPmAsIC4uLmV4cGlyeUxpbmUgPyBbIGV4cGlyeUxpbmUgXSA6IFtdLCBgPHNwYW4gc3R5bGU9ImNvbG9yOiNmZmMxMDc7Ij7imqDvuI8gS2V5IHRoxrDhu51uZzogQ2jhu6ljIG7Eg25nICJDSFXhuqhOIELhu4ogMTAgxJBJ4buCTSIgYuG7iyB2w7QgaGnhu4d1IGhvw6EuPC9zcGFuPmAsIGDwn5KOIE7Dom5nIGPhuqVwIGzDqm4gUFJFTUlVTSDEkeG7gyBkw7luZyDEkeG6p3kgxJHhu6cgdMOtbmggbsSDbmchYCBdLAogICAgICAgICAgICAgIG9uT2s6ICgpID0+IGNyZWF0ZVVJKCkKICAgICAgICAgICAgfSk7CiAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICBzaG93Q3VzdG9tTW9kYWwoewogICAgICAgICAgICAgIGljb246ICfwn5KOJywKICAgICAgICAgICAgICB0aXRsZTogJ0vDjUNIIEhP4bqgVCBUSMOATkggQ8OUTkchJywKICAgICAgICAgICAgICBsaW5lczogWyBgTG/huqFpIGtleTogPGI+JHtrZXlUeXBlTGFiZWx9PC9iPiDwn5KOYCwgLi4uZXhwaXJ5TGluZSA/IFsgZXhwaXJ5TGluZSBdIDogW10sIGDwn5STIFThuqV0IGPhuqMgdMOtbmggbsSDbmcgxJHDoyDEkcaw4bujYyBt4bufIGtob8OhIWAgXSwKICAgICAgICAgICAgICBvbk9rOiAoKSA9PiBjcmVhdGVVSSgpCiAgICAgICAgICAgIH0pOwogICAgICAgICAgfQogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICBjb25zdCBzdGF0dXMgPSByZXN1bHQuX2h0dHBTdGF0dXM7CiAgICAgICAgICBsZXQgbXNnID0gcmVzdWx0Lm1lc3NhZ2UgfHwgcmVzdWx0LnJlYXNvbiB8fCByZXN1bHQuZXJyb3IgfHwgJyc7CiAgICAgICAgICBpZiAoc3RhdHVzID09PSA0MDQgfHwgcmVzdWx0LmVycm9yID09PSAnTm90IGZvdW5kJykgewogICAgICAgICAgICBtc2cgPSAn4p2MIFRoaeG6v3QgYuG7iy9JUCBjw7MgdGjhu4MgxJHDoyBi4buLIGtob8OhIGhv4bq3YyBzYWkgxJHGsOG7nW5nIGThuqtuIEFQSS4gS2nhu4NtIHRyYSBBUElfU0VDUkVUIGto4bubcCBzZXJ2ZXIuJzsKICAgICAgICAgIH0gZWxzZSBpZiAoc3RhdHVzID09PSA0MDMpIHsKICAgICAgICAgICAgbXNnID0gJ+KdjCAnICsgKG1zZyB8fCAnVGhp4bq/dCBi4buLL23huqFuZyBraMO0bmcgaOG7o3AgbOG7hyAobcOheSDhuqNvL3Byb3h5L1ZQTi90csOsbmggZHV54buHdCBnaeG6oykg4oCUIGPDsyB0aOG7gyDEkcOjIGLhu4sga2hvw6EgdsSpbmggdmnhu4VuLCBsacOqbiBo4buHIGFkbWluLicpOwogICAgICAgICAgfSBlbHNlIGlmICghbXNnKSB7CiAgICAgICAgICAgIG1zZyA9ICfinYwgS2V5IGtow7RuZyBo4bujcCBs4buHISAoS2V5VmF1bHQgdOG7qyBjaOG7kWkpJzsKICAgICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgIG1zZyA9ICfinYwgJyArIG1zZzsKICAgICAgICAgIH0KICAgICAgICAgIGVyckJveC50ZXh0Q29udGVudCA9IG1zZyArIChzdGF0dXMgPyBgIFtIVFRQICR7c3RhdHVzfV1gIDogJycpOwogICAgICAgICAgZXJyQm94LnN0eWxlLmRpc3BsYXkgPSAnYmxvY2snOwogICAgICAgICAgYnRuLnRleHRDb250ZW50ID0gJ/CflJMgS8ONQ0ggSE/huqBUJzsKICAgICAgICAgIGJ0bi5kaXNhYmxlZCA9IGZhbHNlOwogICAgICAgICAgdmVyaWZ5aW5nID0gZmFsc2U7CiAgICAgICAgfQogICAgICB9IGNhdGNoIChlKSB7CiAgICAgICAgZXJyQm94LnRleHRDb250ZW50ID0gJ+KdjCBLaMO0bmcgdGjhu4Mga+G6v3QgbuG7kWkgc2VydmVyOiAnICsgZS5tZXNzYWdlOwogICAgICAgIGVyckJveC5zdHlsZS5kaXNwbGF5ID0gJ2Jsb2NrJzsKICAgICAgICBidG4udGV4dENvbnRlbnQgPSAn8J+UkyBLw41DSCBIT+G6oFQnOwogICAgICAgIGJ0bi5kaXNhYmxlZCA9IGZhbHNlOwogICAgICAgIHZlcmlmeWluZyA9IGZhbHNlOwogICAgICB9CiAgICB9OwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLWtleS1pbnB1dCcpLmFkZEV2ZW50TGlzdGVuZXIoJ2tleWRvd24nLCBlID0+IHsKICAgICAgaWYgKGUua2V5ID09PSAnRW50ZXInKSBidG4uY2xpY2soKTsKICAgIH0pOwogIH0KICBmdW5jdGlvbiBjcmVhdGVVSSgpIHsKICAgIGlmIChkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtcGFuZWwnKSkgcmV0dXJuOwogICAgbGV0IHVpU3R5bGUgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtdWktc3R5bGUnKTsKICAgIGlmICghdWlTdHlsZSkgewogICAgICB1aVN0eWxlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc3R5bGUnKTsKICAgICAgdWlTdHlsZS5pZCA9ICd0bC11aS1zdHlsZSc7CiAgICAgIGRvY3VtZW50LmhlYWQuYXBwZW5kQ2hpbGQodWlTdHlsZSk7CiAgICB9CiAgICB1aVN0eWxlLnRleHRDb250ZW50ID0gZ2V0TWFpblVJU3R5bGVzKCk7CiAgICBjb25zdCBrZXlUeXBlID0gS0VZX1NUQVRVUy50eXBlIHx8IF9zTFMuZ2V0KExTX1RZUEUpIHx8ICdUSFVPTkcnOwogICAgY29uc3Qga2V5VHlwZVVwID0ga2V5VHlwZS50b1VwcGVyQ2FzZSgpOwogICAgY29uc3QgYmFkZ2VDbGFzcyA9IGtleVR5cGVVcCA9PT0gJ1VOTElNSVRFRCcgPyAndGwtYmFkZ2UgdW5saW1pdGVkJyA6IGtleVR5cGVVcCA9PT0gJ1BSRU1JVU0nIHx8IGtleVR5cGVVcCA9PT0gJ1ZJUCcgPyAndGwtYmFkZ2UgdmlwJyA6ICd0bC1iYWRnZSc7CiAgICBjb25zdCBiYWRnZUljb24gPSBrZXlUeXBlVXAgPT09ICdVTkxJTUlURUQnID8gJ/CflKUgVU5MSU1JVEVEJyA6IGtleVR5cGVVcCA9PT0gJ1BSRU1JVU0nIHx8IGtleVR5cGVVcCA9PT0gJ1ZJUCcgPyAn8J+SjiBQUkVNSVVNJyA6ICfwn5SRIFRIxq/hu5xORyc7CiAgICBjb25zdCBleHBTdHIgPSAoKCkgPT4gewogICAgICBjb25zdCBlID0gX3NMUy5nZXQoTFNfRVhQKTsKICAgICAgaWYgKCFlKSByZXR1cm4gJyc7CiAgICAgIGNvbnN0IGQgPSBuZXcgRGF0ZShlKTsKICAgICAgcmV0dXJuIGlzTmFOKGQpID8gJycgOiBgIChleHA6ICR7ZC50b0xvY2FsZURhdGVTdHJpbmcoJ3ZpLVZOJyl9KWA7CiAgICB9KSgpOwogICAgY29uc3QgdGhlbWVDYXJkc0hUTUwgPSBbICdkZWZhdWx0JywgJ2dyYXknLCAncGluaycgXS5tYXAodCA9PiB7CiAgICAgIGNvbnN0IHRJbmZvID0gZ2V0VGhlbWVDb2xvcnModCk7CiAgICAgIGNvbnN0IGlzQWN0aXZlID0gdCA9PT0gQ1VSUkVOVF9USEVNRTsKICAgICAgcmV0dXJuIGA8ZGl2IGNsYXNzPSJ0bC10YyAke2lzQWN0aXZlID8gJ2FjdGl2ZScgOiAnJ30iIGRhdGEtdD0iJHt0fSI+XG4gICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtdGMtcHJldiIgc3R5bGU9ImJhY2tncm91bmQ6JHt0SW5mby5wcmV2aWV3Qmd9O2JvcmRlcjoxcHggc29saWQgJHt0SW5mby5wcmV2aWV3Qm9yZGVyfTsiPlxuICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC10Yy1wcmV2LWlubmVyIj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxzcGFuIGNsYXNzPSJ0bC10Yy1wcmV2LXRleHQiIHN0eWxlPSJjb2xvcjoke3RJbmZvLnByZXZpZXdUZXh0fTsiPiR7dEluZm8udGhlbWVMYWJlbC5yZXBsYWNlKC9eW15cc10rXHMvLCAnJykudG9VcHBlckNhc2UoKX08L3NwYW4+XG4gICAgICAgICAgICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLXRjLWxibCI+JHt0SW5mby50aGVtZUxhYmVsfTwvZGl2PlxuICAgICAgICAgICAgPC9kaXY+YDsKICAgIH0pLmpvaW4oJycpOwogICAgY29uc3QgdGMgPSBnZXRUaGVtZUNvbG9ycyhDVVJSRU5UX1RIRU1FKTsKICAgIGNvbnN0IHdyYXAgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgIHdyYXAuaW5uZXJIVE1MID0gYFxuICAgICAgICAgICAgPGJ1dHRvbiBpZD0idGwtZmxvYXRCdG4iPuKaoTwvYnV0dG9uPlxuICAgICAgICAgICAgPGRpdiBpZD0idGwtcGFuZWwiIGNsYXNzPSJoaWRkZW4iPlxuICAgICAgICAgICAgICAgICR7dGMucGFuZWxFeHRyYSB8fCAnJ31cbiAgICAgICAgICAgICAgICA8ZGl2IGlkPSJ0bC1wLWhlYWRlciI+XG4gICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLXAtYnJhbmQiPlxuICAgICAgICAgICAgICAgICAgICAgICAgPHNwYW4+8J+agDwvc3Bhbj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxzcGFuIGNsYXNzPSJ0bC1wLW5hbWUiPlRIScOKTiBUQUkgVMOZIFThu5hJIC8vIEdPRCBNT0RFPC9zcGFuPlxuICAgICAgICAgICAgICAgICAgICAgICAgPHNwYW4gY2xhc3M9IiR7YmFkZ2VDbGFzc30iPiR7YmFkZ2VJY29ufTwvc3Bhbj5cbiAgICAgICAgICAgICAgICAgICAgPC9kaXY+XG4gICAgICAgICAgICAgICAgICAgIDxkaXYgc3R5bGU9ImRpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjZweDsiPlxuICAgICAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBpZD0idGwtc2V0dGluZ3NCdG4iIHRpdGxlPSJDw6BpIMSR4bq3dCBnaWFvIGRp4buHbiI+4pqZPC9idXR0b24+XG4gICAgICAgICAgICAgICAgICAgICAgICA8YnV0dG9uIGlkPSJ0bC1jbG9zZUJ0biI+4pyVPC9idXR0b24+XG4gICAgICAgICAgICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgICAgICAgIDwvZGl2PlxuXG4gICAgICAgICAgICAgICAgXHgzYyEtLSBTZXR0aW5ncyBvdmVybGF5IC0tXHgzZVxuICAgICAgICAgICAgICAgIDxkaXYgaWQ9InRsLXNvIiBjbGFzcz0iaGlkZGVuIj5cbiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtc28taGRyIj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxzcGFuIGNsYXNzPSJ0bC1zby10aXRsZSI+4pqZIEPDgEkgxJDhurZUIEdJQU8gREnhu4ZOPC9zcGFuPlxuICAgICAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBpZD0idGwtc29DbG9zZSI+4pyVPC9idXR0b24+XG4gICAgICAgICAgICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC1zby1ib2R5Ij5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLXNvLWxibCI+8J+OqCBDaOG7jW4gbcOgdSBz4bqvYyBnaWFvIGRp4buHbjwvZGl2PlxuICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtdGhlbWUtY2FyZHMiPiR7dGhlbWVDYXJkc0hUTUx9PC9kaXY+XG4gICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bC1zby1kaXZpZGVyIj48L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLWhpbnQiPsOBcCBk4bulbmcgbmdheSBs4bqtcCB04bupYyBjaG8gdG/DoG4gYuG7mSBnaWFvIGRp4buHbjxicj5r4buDIGPhuqMgbcOgbiBow6xuaCDEkcSDbmcgbmjhuq1wIHbDoCB0aMO0bmcgYsOhbyBrZXk8L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLXNvLWRpdmlkZXIiPjwvZGl2PlxuICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtc28tbGJsIj7wn5SRIFF14bqjbiBsw70ga2V5PC9kaXY+XG4gICAgICAgICAgICAgICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJ0bC1jaGFuZ2Uta2V5IiBpZD0idGwtY2hhbmdlS2V5Ij7wn5SEIMSQ4buUSSBLRVk8L2J1dHRvbj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLWhpbnQiIHN0eWxlPSJtYXJnaW4tdG9wOjRweDsiPlhvw6Ega2V5IGhp4buHbiB04bqhaSB2w6AgcXVheSB24buBIG3DoG4gaMOsbmggxJHEg25nIG5o4bqtcDwvZGl2PlxuICAgICAgICAgICAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICAgICAgICA8L2Rpdj5cblxuICAgICAgICAgICAgICAgIDxkaXYgaWQ9InRsLXAtYm9keSI+XG4gICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLXN0YXRib3giPlxuICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBzdHlsZT0iY29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjQpO2ZvbnQtc2l6ZToxMHB4O3RleHQtdHJhbnNmb3JtOnVwcGVyY2FzZTtmb250LXdlaWdodDo2MDA7Ij4vLyBUcuG6oW5nIHRow6FpIGjhu4cgdGjhu5FuZzwvZGl2PlxuICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtc3RhdHJvdyI+4pyFIE7huqFwIGThu68gbGnhu4d1OiA8c3BhbiBpZD0idGwtcWNvdW50IiBzdHlsZT0iY29sb3I6IzAwZTY3Njtmb250LXdlaWdodDpib2xkO21hcmdpbi1sZWZ0OjVweCI+MDwvc3Bhbj4gY8OidTwvZGl2PlxuICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGwtc3RhdHJvdyI+8J+UjSBDaOG6vyDEkeG7mTogPHNwYW4gaWQ9InRsLW1vZGUtZGV0ZWN0ZWQiIHN0eWxlPSJjb2xvcjojNGZhY2ZlO2ZvbnQtd2VpZ2h0OmJvbGQ7bWFyZ2luLWxlZnQ6NXB4Ij5QUkFDVElDRTwvc3Bhbj48L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLXN0YXRyb3ciPvCflJAgS2V5OiA8c3BhbiBzdHlsZT0iY29sb3I6I2ZmYzEwNzsiPiR7a2V5VHlwZX08L3NwYW4+JHtleHBTdHJ9PC9kaXY+XG4gICAgICAgICAgICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJoZWlnaHQ6MXB4O2JhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDkwZGVnLHRyYW5zcGFyZW50LCR7dGMuYm9yZGVyfSx0cmFuc3BhcmVudCk7Ij48L2Rpdj5cbiAgICAgICAgICAgICAgICAgICAgPGRpdj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgc3R5bGU9ImZvbnQtc2l6ZTo5LjVweDtmb250LXdlaWdodDo3MDA7Y29sb3I6JHt0Yy5nbG93Q29sb3J9O2ZvbnQtZmFtaWx5OidPcmJpdHJvbic7Ij7impkgQ0jhur4gxJDhu5ggVsav4buiVCBSw4BPPC9kaXY+XG4gICAgICAgICAgICAgICAgICAgICAgICA8c2VsZWN0IGlkPSJ0bC1tb2RlU2VsZWN0Ij5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSJwcmFjdGljZSI+4pqhIEx1eeG7h24gVOG6rXA8L29wdGlvbj5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSJleGFtIiBzZWxlY3RlZD7wn5SlIEtp4buDbSBUcmE8L29wdGlvbj5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSJ2aWRlbyI+8J+OpSBWaWRlbyBRdWl6PC9vcHRpb24+XG4gICAgICAgICAgICAgICAgICAgICAgICA8L3NlbGVjdD5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxpbnB1dCB0eXBlPSJudW1iZXIiIHN0ZXA9IjAuMDEiIGNsYXNzPSJ0bC1nb2QtaW5wdXQiIGlkPSJ0bC1nb2QtdGltZSJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YWx1ZT0iMjUuMDAiIHBsYWNlaG9sZGVyPSJQaMO6dC5HacOieSAodmQ6IDI1LjMwKSI+XG4gICAgICAgICAgICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgICAgICAgICAgICA8YnV0dG9uIGlkPSJ0bC1maXJlQnRuIj7wn5KlIENIVeG6qE4gQuG7iiAxMCDEkEnhu4JNPC9idXR0b24+XG4gICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRsLWNvbnNvbGUiIGlkPSJ0bC1sb2dib3giPjwvZGl2PlxuICAgICAgICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgICAgICAgIDxkaXYgaWQ9InRsLXAtZm9vdGVyIj5cbiAgICAgICAgICAgICAgICAgICAgPHNwYW4+R09EIE1PREUgdjMuMiDigJQgU0VDVVJFIHY1LjEgKHYxNyBhbnRpLWJhbik8L3NwYW4+XG4gICAgICAgICAgICAgICAgICAgIDxkaXYgc3R5bGU9ImRpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjVweDsiPlxuICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBzdHlsZT0id2lkdGg6NnB4O2hlaWdodDo2cHg7Ym9yZGVyLXJhZGl1czo1MCU7YmFja2dyb3VuZDojMDBlNjc2O2JveC1zaGFkb3c6MCAwIDZweCAjMDBlNjc2O2FuaW1hdGlvbjpjb25uQmxpbmsgMS44cyBpbmZpbml0ZTsiPjwvZGl2PlxuICAgICAgICAgICAgICAgICAgICAgICAgPHNwYW4gaWQ9InRsLXN2clN0YXR1cyI+8J+UtSBTZXJ2ZXI6IE9LPC9zcGFuPlxuICAgICAgICAgICAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICAgIDwvZGl2PmA7CiAgICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKHdyYXApOwogICAgY29uc3QgZmxvYXRCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtZmxvYXRCdG4nKTsKICAgIGNvbnN0IHBhbmVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLXBhbmVsJyk7CiAgICBmbG9hdEJ0bi5vbmNsaWNrID0gKCkgPT4gcGFuZWwuY2xhc3NMaXN0LnRvZ2dsZSgnaGlkZGVuJyk7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtY2xvc2VCdG4nKS5vbmNsaWNrID0gKCkgPT4gewogICAgICBwYW5lbC5jbGFzc0xpc3QuYWRkKCdoaWRkZW4nKTsKICAgICAgY29uc3Qgc28gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtc28nKTsKICAgICAgaWYgKHNvKSBzby5jbGFzc0xpc3QuYWRkKCdoaWRkZW4nKTsKICAgIH07CiAgICBjb25zdCBoZHIgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtcC1oZWFkZXInKTsKICAgIGxldCBpc0RyYWdnaW5nID0gZmFsc2UsIHN0YXJ0WCA9IDAsIHN0YXJ0WSA9IDAsIGluaXRMZWZ0ID0gMCwgaW5pdFRvcCA9IDA7CiAgICBpZiAoaGRyKSB7CiAgICAgIGhkci5hZGRFdmVudExpc3RlbmVyKCdtb3VzZWRvd24nLCBlID0+IHsKICAgICAgICBpZiAoZS50YXJnZXQuaWQgPT09ICd0bC1jbG9zZUJ0bicgfHwgZS50YXJnZXQuaWQgPT09ICd0bC1zZXR0aW5nc0J0bicpIHJldHVybjsKICAgICAgICBpc0RyYWdnaW5nID0gdHJ1ZTsKICAgICAgICBzdGFydFggPSBlLmNsaWVudFg7CiAgICAgICAgc3RhcnRZID0gZS5jbGllbnRZOwogICAgICAgIGNvbnN0IHIgPSBwYW5lbC5nZXRCb3VuZGluZ0NsaWVudFJlY3QoKTsKICAgICAgICBpbml0TGVmdCA9IHIubGVmdDsKICAgICAgICBpbml0VG9wID0gci50b3A7CiAgICAgIH0pOwogICAgfQogICAgZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcignbW91c2Vtb3ZlJywgZSA9PiB7CiAgICAgIGlmICghaXNEcmFnZ2luZykgcmV0dXJuOwogICAgICBwYW5lbC5zdHlsZS5sZWZ0ID0gaW5pdExlZnQgKyBlLmNsaWVudFggLSBzdGFydFggKyAncHgnOwogICAgICBwYW5lbC5zdHlsZS50b3AgPSBpbml0VG9wICsgZS5jbGllbnRZIC0gc3RhcnRZICsgJ3B4JzsKICAgICAgcGFuZWwuc3R5bGUudHJhbnNmb3JtID0gJ25vbmUnOwogICAgfSk7CiAgICBkb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCdtb3VzZXVwJywgKCkgPT4gewogICAgICBpc0RyYWdnaW5nID0gZmFsc2U7CiAgICB9KTsKICAgIGNvbnN0IHNvID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLXNvJyk7CiAgICBjb25zdCBzZXR0aW5nc0J0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1zZXR0aW5nc0J0bicpOwogICAgY29uc3Qgc29DbG9zZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1zb0Nsb3NlJyk7CiAgICBpZiAoc2V0dGluZ3NCdG4gJiYgc28pIHsKICAgICAgc2V0dGluZ3NCdG4ub25jbGljayA9ICgpID0+IHsKICAgICAgICBjb25zdCBpc09wZW4gPSAhc28uY2xhc3NMaXN0LmNvbnRhaW5zKCdoaWRkZW4nKTsKICAgICAgICBzby5jbGFzc0xpc3QudG9nZ2xlKCdoaWRkZW4nKTsKICAgICAgICBzZXR0aW5nc0J0bi5jbGFzc0xpc3QudG9nZ2xlKCdhY3RpdmUnLCAhaXNPcGVuKTsKICAgICAgfTsKICAgIH0KICAgIGlmIChzb0Nsb3NlKSB7CiAgICAgIHNvQ2xvc2Uub25jbGljayA9ICgpID0+IHsKICAgICAgICBzby5jbGFzc0xpc3QuYWRkKCdoaWRkZW4nKTsKICAgICAgICBpZiAoc2V0dGluZ3NCdG4pIHNldHRpbmdzQnRuLmNsYXNzTGlzdC5yZW1vdmUoJ2FjdGl2ZScpOwogICAgICB9OwogICAgfQogICAgaWYgKHNvKSB7CiAgICAgIHNvLnF1ZXJ5U2VsZWN0b3JBbGwoJy50bC10YycpLmZvckVhY2goY2FyZCA9PiB7CiAgICAgICAgY2FyZC5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHsKICAgICAgICAgIGNvbnN0IG5ld1RoZW1lID0gY2FyZC5kYXRhc2V0LnQ7CiAgICAgICAgICBpZiAobmV3VGhlbWUgPT09IENVUlJFTlRfVEhFTUUpIHsKICAgICAgICAgICAgc28uY2xhc3NMaXN0LmFkZCgnaGlkZGVuJyk7CiAgICAgICAgICAgIGlmIChzZXR0aW5nc0J0bikgc2V0dGluZ3NCdG4uY2xhc3NMaXN0LnJlbW92ZSgnYWN0aXZlJyk7CiAgICAgICAgICAgIHJldHVybjsKICAgICAgICAgIH0KICAgICAgICAgIHNvLnF1ZXJ5U2VsZWN0b3JBbGwoJy50bC10YycpLmZvckVhY2goYyA9PiB7CiAgICAgICAgICAgIGMuY2xhc3NMaXN0LnRvZ2dsZSgnYWN0aXZlJywgYy5kYXRhc2V0LnQgPT09IG5ld1RoZW1lKTsKICAgICAgICAgIH0pOwogICAgICAgICAgYXBwbHlUaGVtZUxpdmUobmV3VGhlbWUpOwogICAgICAgICAgY29uc3QgZXhpc3RGeCA9IHBhbmVsLnF1ZXJ5U2VsZWN0b3IoJyN0bC1jb25uLWZ4LWJhciwjdGwtY29ubi1meC1wZXRhbHMnKTsKICAgICAgICAgIGlmIChleGlzdEZ4KSBleGlzdEZ4LnJlbW92ZSgpOwogICAgICAgICAgY29uc3QgbmV3VGMgPSBnZXRUaGVtZUNvbG9ycyhuZXdUaGVtZSk7CiAgICAgICAgICBpZiAobmV3VGMucGFuZWxFeHRyYSkgewogICAgICAgICAgICBjb25zdCB0bXAgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgICAgICAgICAgdG1wLmlubmVySFRNTCA9IG5ld1RjLnBhbmVsRXh0cmE7CiAgICAgICAgICAgIGNvbnN0IGZ4RWwgPSB0bXAuZmlyc3RFbGVtZW50Q2hpbGQ7CiAgICAgICAgICAgIGlmIChmeEVsKSBwYW5lbC5pbnNlcnRCZWZvcmUoZnhFbCwgcGFuZWwuZmlyc3RDaGlsZCk7CiAgICAgICAgICB9CiAgICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHsKICAgICAgICAgICAgc28uY2xhc3NMaXN0LmFkZCgnaGlkZGVuJyk7CiAgICAgICAgICAgIGlmIChzZXR0aW5nc0J0bikgc2V0dGluZ3NCdG4uY2xhc3NMaXN0LnJlbW92ZSgnYWN0aXZlJyk7CiAgICAgICAgICB9LCAzMjApOwogICAgICAgIH0pOwogICAgICB9KTsKICAgIH0KICAgIGNvbnN0IG1vZGVTZWxlY3QgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtbW9kZVNlbGVjdCcpOwogICAgY29uc3QgZGV0ZWN0ZWRNb2RlID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLW1vZGUtZGV0ZWN0ZWQnKTsKICAgIGlmIChtb2RlU2VsZWN0KSB7CiAgICAgIG1vZGVTZWxlY3QuYWRkRXZlbnRMaXN0ZW5lcignY2hhbmdlJywgZnVuY3Rpb24oKSB7CiAgICAgICAgaWYgKGRldGVjdGVkTW9kZSkgZGV0ZWN0ZWRNb2RlLnRleHRDb250ZW50ID0gdGhpcy52YWx1ZS50b1VwcGVyQ2FzZSgpOwogICAgICB9KTsKICAgIH0KICAgIGFzeW5jIGZ1bmN0aW9uIGZvcmNlRmV0Y2hRdWVzdGlvbnMoKSB7CiAgICAgIHRyeSB7CiAgICAgICAgZm9yY2VHZXRNZXRhKCk7CiAgICAgICAgY29uc3QgVVcgPSB0eXBlb2YgdW5zYWZlV2luZG93ICE9PSAndW5kZWZpbmVkJyA/IHVuc2FmZVdpbmRvdyA6IHdpbmRvdzsKICAgICAgICB0cnkgewogICAgICAgICAgY29uc3QgYnVmID0gVVcuX19rdl9xX2J1ZjsKICAgICAgICAgIGlmIChBcnJheS5pc0FycmF5KGJ1ZikpIHsKICAgICAgICAgICAgZm9yIChsZXQgaSA9IDA7IGkgPCBidWYubGVuZ3RoOyBpKyspIHsKICAgICAgICAgICAgICBjb25zdCBpdCA9IGJ1ZltpXTsKICAgICAgICAgICAgICBpZiAoaXQgJiYgaXQudXJsICYmIGl0LnRleHQpIHsKICAgICAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgICAgIGhhbmRsZVJhd1Jlc3BvbnNlKGl0LnVybCwgaXQudGV4dCk7CiAgICAgICAgICAgICAgICB9IGNhdGNoIChfKSB7fQogICAgICAgICAgICAgIH0KICAgICAgICAgICAgfQogICAgICAgICAgfQogICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgaWYgKFNFU1NJT04ucmF3X3F1ZXN0aW9ucy5sZW5ndGggPiAwKSByZXR1cm4gdHJ1ZTsKICAgICAgICBjb25zdCBsYXN0ID0gVVcuX190bF9sYXN0X3FyZXE7CiAgICAgICAgaWYgKGxhc3QgJiYgbGFzdC51cmwpIHsKICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgIGNvbnN0IGZvcHRzID0gewogICAgICAgICAgICAgIG1ldGhvZDogbGFzdC5tZXRob2QgfHwgJ0dFVCcsCiAgICAgICAgICAgICAgY3JlZGVudGlhbHM6ICdpbmNsdWRlJywKICAgICAgICAgICAgICBjYWNoZTogJ25vLWNhY2hlJwogICAgICAgICAgICB9OwogICAgICAgICAgICBpZiAobGFzdC5ib2R5ICYmIChsYXN0Lm1ldGhvZCB8fCAnR0VUJykudG9VcHBlckNhc2UoKSAhPT0gJ0dFVCcpIHsKICAgICAgICAgICAgICBmb3B0cy5oZWFkZXJzID0gewogICAgICAgICAgICAgICAgJ0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQ7IGNoYXJzZXQ9VVRGLTgnLAogICAgICAgICAgICAgICAgJ1gtUmVxdWVzdGVkLVdpdGgnOiAnWE1MSHR0cFJlcXVlc3QnCiAgICAgICAgICAgICAgfTsKICAgICAgICAgICAgICBmb3B0cy5ib2R5ID0gbGFzdC5ib2R5OwogICAgICAgICAgICB9CiAgICAgICAgICAgIGNvbnN0IHJlcyA9IGF3YWl0IGZldGNoKGxhc3QudXJsLCBmb3B0cyk7CiAgICAgICAgICAgIGlmIChyZXMub2spIHsKICAgICAgICAgICAgICBjb25zdCB0eHQgPSBhd2FpdCByZXMudGV4dCgpOwogICAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgICBoYW5kbGVSYXdSZXNwb25zZShsYXN0LnVybCwgdHh0KTsKICAgICAgICAgICAgICB9IGNhdGNoIChfKSB7fQogICAgICAgICAgICB9CiAgICAgICAgICB9IGNhdGNoIChlKSB7CiAgICAgICAgICAgIGNvbnNvbGUud2FybignW1RMXSByZXBsYXkgZmFpbCcsIGUpOwogICAgICAgICAgfQogICAgICAgIH0KICAgICAgICByZXR1cm4gU0VTU0lPTi5yYXdfcXVlc3Rpb25zLmxlbmd0aCA+IDA7CiAgICAgIH0gY2F0Y2ggKGUpIHsKICAgICAgICByZXR1cm4gZmFsc2U7CiAgICAgIH0KICAgIH0KICAgIGNvbnN0IGZpcmVCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtZmlyZUJ0bicpOwogICAgaWYgKCFpc1ByZW1pdW1LZXkoKSkgewogICAgICBmaXJlQnRuLmlubmVySFRNTCA9ICfwn5SSIENIVeG6qE4gQuG7iiAxMCDEkEnhu4JNIChDSOG7iCBQUkVNSVVNKSc7CiAgICAgIGZpcmVCdG4uc3R5bGUuYmFja2dyb3VuZCA9ICdsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLCM0NDQsIzY2NiknOwogICAgICBmaXJlQnRuLnN0eWxlLmN1cnNvciA9ICdub3QtYWxsb3dlZCc7CiAgICAgIGZpcmVCdG4uc3R5bGUub3BhY2l0eSA9ICcwLjYnOwogICAgICBmaXJlQnRuLnRpdGxlID0gJ0No4bupYyBuxINuZyBuw6B5IGNo4buJIGTDoG5oIGNobyBrZXkgUFJFTUlVTS4gTGnDqm4gaOG7hyDEkeG7gyBuw6JuZyBj4bqlcCEnOwogICAgICBmaXJlQnRuLm9uY2xpY2sgPSBlID0+IHsKICAgICAgICBlLnByZXZlbnREZWZhdWx0KCk7CiAgICAgICAgYWRkTG9nKCfwn5SSIENo4bupYyBuxINuZyBuw6B5IHnDqnUgY+G6p3Uga2V5IFBSRU1JVU0hJywgJ2VycicpOwogICAgICAgIGFkZExvZygn8J+SjiBMacOqbiBo4buHIGFkbWluIMSR4buDIG7Dom5nIGPhuqVwIGtleSBQUkVNSVVNLicsICd3YXJuJyk7CiAgICAgICAgc2hvd0N1c3RvbU1vZGFsKHsKICAgICAgICAgIGljb246ICfwn5SSJywKICAgICAgICAgIHRpdGxlOiAnWcOKVSBD4bqmVSBLRVkgUFJFTUlVTScsCiAgICAgICAgICBsaW5lczogWyAnQ2jhu6ljIG7Eg25nIDxiPiJDSFXhuqhOIELhu4ogMTAgxJBJ4buCTSI8L2I+IGNo4buJIGTDoG5oIGNobyBrZXkgUFJFTUlVTSEnLCBgS2V5IGPhu6dhIGLhuqFuIGzDoCBrZXkgPGI+JHsoS0VZX1NUQVRVUy50eXBlIHx8ICdUSMav4bucTkcnKS50b1VwcGVyQ2FzZSgpfTwvYj4uYCwgJ/Cfko4gTGnDqm4gaOG7hyBhZG1pbiDEkeG7gyBuw6JuZyBj4bqlcCBsw6puIFBSRU1JVU0hJyBdCiAgICAgICAgfSk7CiAgICAgIH07CiAgICB9IGVsc2UgewogICAgICBmaXJlQnRuLm9uY2xpY2sgPSBhc3luYyAoKSA9PiB7CiAgICAgICAgYWRkTG9nKCfwn5SNIMSQ4buTbmcgYuG7mSBk4buvIGxp4buHdSB0aMO0IHThu6sgT0xNLi4uJywgJ2luZm8nKTsKICAgICAgICBhd2FpdCBmb3JjZUZldGNoUXVlc3Rpb25zKCk7CiAgICAgICAgZm9yY2VHZXRNZXRhKCk7CiAgICAgICAgaWYgKCFTRVNTSU9OLm1ldGEuaWRfdXNlciB8fCAhU0VTU0lPTi5tZXRhLmlkX2NhdGUpIHsKICAgICAgICAgIGFkZExvZygn4p2MIENoxrBhIGPDsyBJRCB1c2VyL2NhdGUgKHVzZXI9JyArIChTRVNTSU9OLm1ldGEuaWRfdXNlciB8fCAnPycpICsgJywgY2F0ZT0nICsgKFNFU1NJT04ubWV0YS5pZF9jYXRlIHx8ICc/JykgKyAnKS4gSMOjeSBGNSBob+G6t2MgY2jhu50gdOG6o2kgeG9uZyBjw6J1IGjhu49pLicsICdlcnInKTsKICAgICAgICAgIHNob3dDdXN0b21Nb2RhbCh7CiAgICAgICAgICAgIGljb246ICfimqDvuI8nLAogICAgICAgICAgICB0aXRsZTogJ1RISeG6vlUgROG7riBMSeG7hlUnLAogICAgICAgICAgICBsaW5lczogWyAnQ2jGsGEgbmjhuq1uIMSRxrDhu6NjIElEIHTDoGkga2hv4bqjbiAvIGLDoGkgdOG6rXAgdOG7qyB0cmFuZyBPTE0uPGJyPlZ1aSBsw7JuZyBGNSB0cmFuZywgxJHhu6NpIGRhbmggc8OhY2ggY8OidSBo4buPaSBu4bqhcCB4b25nIHLhu5NpIGLhuqVtIGzhuqFpLicgXQogICAgICAgICAgfSk7CiAgICAgICAgICByZXR1cm47CiAgICAgICAgfQogICAgICAgIGlmIChTRVNTSU9OLnJhd19xdWVzdGlvbnMubGVuZ3RoID09PSAwKSB7CiAgICAgICAgICBhZGRMb2coJ+KdjCBDaMawYSBu4bqhcCDEkcaw4bujYyBjw6J1IGjhu49pLiBIw6N5IEY1IHRyYW5nIGhv4bq3YyBsw6BtIG3hu5tpIGLDoGkgdOG6rXAuJywgJ2VycicpOwogICAgICAgICAgc2hvd0N1c3RvbU1vZGFsKHsKICAgICAgICAgICAgaWNvbjogJ/Cfk60nLAogICAgICAgICAgICB0aXRsZTogJ0NIxq9BIEPDkyBDw4JVIEjhu45JJywKICAgICAgICAgICAgbGluZXM6IFsgJ0Rhbmggc8OhY2ggY8OidSBo4buPaSDEkWFuZyB0cuG7kW5nLiBGNSB0cmFuZyBiw6BpIHThuq1wIHLhu5NpIGLhuqVtIGzhuqFpLicgXQogICAgICAgICAgfSk7CiAgICAgICAgICByZXR1cm47CiAgICAgICAgfQogICAgICAgIGNvbnN0IGtleSA9IENVUlJFTlRfS0VZIHx8IF9zTFMuZ2V0KExTX0tFWSk7CiAgICAgICAgY29uc3QgbW9kZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1tb2RlU2VsZWN0JykudmFsdWU7CiAgICAgICAgY29uc3QgdGltZV9zdHIgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtZ29kLXRpbWUnKS52YWx1ZTsKICAgICAgICBmaXJlQnRuLmRpc2FibGVkID0gdHJ1ZTsKICAgICAgICBmaXJlQnRuLnRleHRDb250ZW50ID0gJ+KPsyDEkEFORyBY4busIEzDnSBUUsOKTiBTRVJWRVIuLi4nOwogICAgICAgIGFkZExvZygn8J+agCBH4butaSBk4buvIGxp4buHdSB0aMO0IGzDqm4gc2VydmVyIChtb2RlOiAnICsgbW9kZSArICcpLi4uJywgJ3dhcm4nKTsKICAgICAgICB0cnkgewogICAgICAgICAgY29uc3QgcmVzdWx0ID0gYXdhaXQgZ21Qb3N0KCcvZmlyZScsIHsKICAgICAgICAgICAga2V5OiBrZXksCiAgICAgICAgICAgIGh3aWQ6IGdldEhXSUQoKSwKICAgICAgICAgICAgc2Vzc2lvbjogewogICAgICAgICAgICAgIHJhd19xdWVzdGlvbnM6IFNFU1NJT04ucmF3X3F1ZXN0aW9ucywKICAgICAgICAgICAgICBtZXRhOiBTRVNTSU9OLm1ldGEsCiAgICAgICAgICAgICAgdmlkZW9fbGVuZ3RoOiBTRVNTSU9OLnZpZGVvX2xlbmd0aAogICAgICAgICAgICB9LAogICAgICAgICAgICBtb2RlOiBtb2RlLAogICAgICAgICAgICB0aW1lX3N0cjogdGltZV9zdHIsCiAgICAgICAgICAgIGdyYWRlOiB3aW5kb3cuZ3JhZGUgfHwgd2luZG93LmlkX2dyYWRlIHx8ICcxMCcKICAgICAgICAgIH0pOwogICAgICAgICAgaWYgKCEocmVzdWx0LnN1Y2Nlc3MgfHwgcmVzdWx0LnZhbGlkKSkgewogICAgICAgICAgICBjb25zdCBzdCA9IHJlc3VsdC5faHR0cFN0YXR1czsKICAgICAgICAgICAgY29uc3QgbXNnID0gcmVzdWx0Lm1lc3NhZ2UgfHwgJ0zhu5dpIGtow7RuZyB4w6FjIMSR4buLbmggdOG7qyBzZXJ2ZXInOwogICAgICAgICAgICBhZGRMb2coJ+KdjCBTZXJ2ZXIgdOG7qyBjaOG7kWk6ICcgKyBtc2csICdlcnInKTsKICAgICAgICAgICAgaWYgKHN0ID09PSA0MDEpIHNob3dDdXN0b21Nb2RhbCh7CiAgICAgICAgICAgICAgaWNvbjogJ/CflJInLAogICAgICAgICAgICAgIHRpdGxlOiAnS0VZIEtIw5RORyBI4buiUCBM4buGJywKICAgICAgICAgICAgICBsaW5lczogWyBtc2csICdWdWkgbMOybmcgbmjhuq1wIGtleSBo4bujcCBs4buHIGhv4bq3YyBsacOqbiBo4buHIGFkbWluLicgXQogICAgICAgICAgICB9KTsgZWxzZSBpZiAoc3QgPT09IDQwMykgc2hvd0N1c3RvbU1vZGFsKHsKICAgICAgICAgICAgICBpY29uOiAn8J+SjicsCiAgICAgICAgICAgICAgdGl0bGU6ICdD4bqmTiBLRVkgUFJFTUlVTScsCiAgICAgICAgICAgICAgbGluZXM6IFsgbXNnIF0KICAgICAgICAgICAgfSk7IGVsc2UgaWYgKHN0ID09PSA0MjkpIHNob3dDdXN0b21Nb2RhbCh7CiAgICAgICAgICAgICAgaWNvbjogJ+KPsycsCiAgICAgICAgICAgICAgdGl0bGU6ICdRVcOBIFThuqZOIFNV4bqkVCcsCiAgICAgICAgICAgICAgbGluZXM6IFsgbXNnLCAnVnVpIGzDsm5nIGNo4budIHbDoGkgcGjDunQgcuG7k2kgdGjhu60gbOG6oWkuJyBdCiAgICAgICAgICAgIH0pOyBlbHNlIHNob3dDdXN0b21Nb2RhbCh7CiAgICAgICAgICAgICAgaWNvbjogJ+KaoO+4jycsCiAgICAgICAgICAgICAgdGl0bGU6ICdLSMOUTkcgTuG7mFAgxJDGr+G7okMnLAogICAgICAgICAgICAgIGxpbmVzOiBbIG1zZyBdCiAgICAgICAgICAgIH0pOwogICAgICAgICAgICBmaXJlQnRuLmRpc2FibGVkID0gZmFsc2U7CiAgICAgICAgICAgIGZpcmVCdG4udGV4dENvbnRlbnQgPSAn8J+SpSBDSFXhuqhOIELhu4ogMTAgxJBJ4buCTSc7CiAgICAgICAgICAgIHJldHVybjsKICAgICAgICAgIH0KICAgICAgICAgIGFkZExvZygn8J+TpCBTZXJ2ZXIgxJHDoyBk4buxbmcgeG9uZyBiw6BpIOKAlCDEkWFuZyBn4butaSBsw6puIE9MTS4uLicsICdpbmZvJyk7CiAgICAgICAgICBpZiAocmVzdWx0LnN1bW1hcnkgJiYgQXJyYXkuaXNBcnJheShyZXN1bHQuc3VtbWFyeS5pdGVtcykgJiYgcmVzdWx0LnN1bW1hcnkuaXRlbXMubGVuZ3RoKSB7CiAgICAgICAgICAgIGFkZExvZygn8J+nriBTZXJ2ZXIgxJHDoyBnaeG6o2kgJyArIChyZXN1bHQuc3VtbWFyeS5jb3VudCB8fCByZXN1bHQuc3VtbWFyeS5pdGVtcy5sZW5ndGgpICsgJyBjw6J1IChtb2RlOiAnICsgKHJlc3VsdC5zdW1tYXJ5Lm1vZGUgfHwgbW9kZSkgKyAnKS4nLCAnaW5mbycpOwogICAgICAgICAgfQogICAgICAgICAgY29uc3QgY3NyZiA9IFNFU1NJT04ubWV0YS5jc3JmX3Rva2VuIHx8IGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoJ21ldGFbbmFtZT0iY3NyZi10b2tlbiJdJyk/LmdldEF0dHJpYnV0ZSgnY29udGVudCcpIHx8ICcnOwogICAgICAgICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBmZXRjaChyZXN1bHQuZW5kcG9pbnQgfHwgJy9jb3Vyc2UvdGVhY2hlci1zdGF0aWMnLCB7CiAgICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLAogICAgICAgICAgICBjcmVkZW50aWFsczogJ2luY2x1ZGUnLAogICAgICAgICAgICBoZWFkZXJzOiB7CiAgICAgICAgICAgICAgJ2NvbnRlbnQtdHlwZSc6ICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQ7IGNoYXJzZXQ9VVRGLTgnLAogICAgICAgICAgICAgICd4LWNzcmYtdG9rZW4nOiBjc3JmLAogICAgICAgICAgICAgICd4LXJlcXVlc3RlZC13aXRoJzogJ1hNTEh0dHBSZXF1ZXN0JwogICAgICAgICAgICB9LAogICAgICAgICAgICBib2R5OiByZXN1bHQucGFyYW1zX3N0cgogICAgICAgICAgfSk7CiAgICAgICAgICBpZiAocmVzcG9uc2Uub2spIHsKICAgICAgICAgICAgYWRkTG9nKCfinIUgTuG7mXAgYsOgaSB0aMOgbmggY8O0bmchIEtp4buDbSB0cmEgxJFp4buDbSBPTE0uJywgJ29rJyk7CiAgICAgICAgICAgIGZpcmVCdG4udGV4dENvbnRlbnQgPSAn4pyFIFRIw4BOSCBDw5RORyEnOwogICAgICAgICAgICBmaXJlQnRuLnN0eWxlLmJhY2tncm91bmQgPSAnbGluZWFyLWdyYWRpZW50KDEzNWRlZywjMDBiMDliLCMwMGU2NzYpJzsKICAgICAgICAgICAgc2hvd0N1c3RvbU1vZGFsKHsKICAgICAgICAgICAgICBpY29uOiAn4pyFJywKICAgICAgICAgICAgICB0aXRsZTogJ07hu5hQIELDgEkgVEjDgE5IIEPDlE5HJywKICAgICAgICAgICAgICBsaW5lczogWyAnU2VydmVyIMSRw6MgeOG7rSBsw70gPGI+JyArIChyZXN1bHQuc3VtbWFyeSA/IHJlc3VsdC5zdW1tYXJ5LmNvdW50IHx8IDAgOiBTRVNTSU9OLnJhd19xdWVzdGlvbnMubGVuZ3RoKSArICc8L2I+IGPDonUgdsOgIGfhu61pIGzDqm4gT0xNLicsICdUcmFuZyBz4bq9IHThu7EgdOG6o2kgbOG6oWkgc2F1IHbDoGkgZ2nDonkuJyBdCiAgICAgICAgICAgIH0pOwogICAgICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHdpbmRvdy5sb2NhdGlvbi5yZWxvYWQoKSwgMjUwMCk7CiAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICBhZGRMb2coJ+KdjCBPTE0gdHLhuqMgduG7gSBs4buXaSBIVFRQICcgKyByZXNwb25zZS5zdGF0dXMsICdlcnInKTsKICAgICAgICAgICAgc2hvd0N1c3RvbU1vZGFsKHsKICAgICAgICAgICAgICBpY29uOiAn4p2MJywKICAgICAgICAgICAgICB0aXRsZTogJ07hu5hQIELDgEkgVEjhuqRUIELhuqBJJywKICAgICAgICAgICAgICBsaW5lczogWyAnTcOheSBjaOG7pyBPTE0gdHLhuqMgbOG7l2kgSFRUUCAnICsgcmVzcG9uc2Uuc3RhdHVzICsgJy48YnI+VGjhu60gRjUgdHJhbmcgcuG7k2kgYuG6pW0gbOG6oWkuJyBdCiAgICAgICAgICAgIH0pOwogICAgICAgICAgICBmaXJlQnRuLmRpc2FibGVkID0gZmFsc2U7CiAgICAgICAgICAgIGZpcmVCdG4udGV4dENvbnRlbnQgPSAn8J+SpSBDSFXhuqhOIELhu4ogMTAgxJBJ4buCTSc7CiAgICAgICAgICB9CiAgICAgICAgfSBjYXRjaCAoZSkgewogICAgICAgICAgYWRkTG9nKCfinYwgTOG7l2k6ICcgKyBlLm1lc3NhZ2UsICdlcnInKTsKICAgICAgICAgIHNob3dDdXN0b21Nb2RhbCh7CiAgICAgICAgICAgIGljb246ICfwn4yQJywKICAgICAgICAgICAgdGl0bGU6ICdM4buWSSBL4bq+VCBO4buQSScsCiAgICAgICAgICAgIGxpbmVzOiBbICdLaMO0bmcga+G6v3QgbuG7kWkgxJHGsOG7o2Mgc2VydmVyL09MTTogPGI+JyArIChlLm1lc3NhZ2UgfHwgJycpICsgJzwvYj4nIF0KICAgICAgICAgIH0pOwogICAgICAgICAgZmlyZUJ0bi5kaXNhYmxlZCA9IGZhbHNlOwogICAgICAgICAgZmlyZUJ0bi50ZXh0Q29udGVudCA9ICfwn5KlIENIVeG6qE4gQuG7iiAxMCDEkEnhu4JNJzsKICAgICAgICB9CiAgICAgIH07CiAgICB9CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtY2hhbmdlS2V5Jykub25jbGljayA9ICgpID0+IHsKICAgICAgc2hvd0NvbmZpcm1Nb2RhbCh7CiAgICAgICAgaWNvbjogJ/CflIQnLAogICAgICAgIHRpdGxlOiAnxJDhu5RJIEtFWT8nLAogICAgICAgIGxpbmVzOiBbICdLZXkgaGnhu4duIHThuqFpIHPhur0gYuG7iyA8Yj54b8OhIGhvw6BuIHRvw6BuPC9iPi4nLCAnQuG6oW4gc+G6vSDEkcaw4bujYyDEkcawYSB24buBIG3DoG4gaMOsbmggxJHEg25nIG5o4bqtcC4nIF0sCiAgICAgICAgb2tUZXh0OiAn8J+UhCDEkOG7lEkgS0VZJywKICAgICAgICBjYW5jZWxUZXh0OiAnSOG7plknLAogICAgICAgIG9uT2s6ICgpID0+IHsKICAgICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKExTX0tFWSk7CiAgICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShMU19UWVBFKTsKICAgICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKExTX0VYUCk7CiAgICAgICAgICBDVVJSRU5UX0tFWSA9IG51bGw7CiAgICAgICAgICBLRVlfU1RBVFVTID0gewogICAgICAgICAgICB2YWxpZDogZmFsc2UsCiAgICAgICAgICAgIHR5cGU6IG51bGwsCiAgICAgICAgICAgIGV4cGlyZXNfYXQ6IG51bGwKICAgICAgICAgIH07CiAgICAgICAgICBfc2VjU2Vzc2lvbiA9IHsKICAgICAgICAgICAgdG9rZW46IG51bGwsCiAgICAgICAgICAgIGV4cDogMCwKICAgICAgICAgICAgZnBIYXNoOiBudWxsLAogICAgICAgICAgICBzZXE6IDEKICAgICAgICAgIH07CiAgICAgICAgICBDVVJSRU5UX0RFVklDRSA9ICcnOwogICAgICAgICAgcGFuZWwucmVtb3ZlKCk7CiAgICAgICAgICBmbG9hdEJ0bi5yZW1vdmUoKTsKICAgICAgICAgIGJ1aWxkTG9ja1NjcmVlbigpOwogICAgICAgIH0KICAgICAgfSk7CiAgICB9OwogICAgYWRkTG9nKCfinIUgR09EIE1PRCBjb25uZWN0b3Igc3VjY2VzcycsICdvaycpOwogICAgY29uc3Qgb2xtVXNlck5vdyA9IGdldE9sbVVzZXJuYW1lKCk7CiAgICBhZGRMb2coYPCfkaQgVMOgaSBraG/huqNuIE9MTTogJHtvbG1Vc2VyTm93fWAsICdpbmZvJyk7CiAgICBhZGRMb2coJ+KEue+4jyDEkGFuZyBjaOG7nSBu4bqhcCBjw6J1IGjhu49pLi4uJywgJ2luZm8nKTsKICAgIGlmICghaXNQcmVtaXVtS2V5KCkpIHsKICAgICAgYWRkTG9nKCfimqDvuI8gS2V5IHRoxrDhu51uZzogQ2jhu6ljIG7Eg25nICJDSFXhuqhOIELhu4ogMTAgxJBJ4buCTSIgYuG7iyBraG/DoSEnLCAnd2FybicpOwogICAgICBhZGRMb2coJ/Cfko4gTsOibmcgY+G6pXAgUFJFTUlVTSDEkeG7gyBt4bufIGtob8OhIHRvw6BuIGLhu5kgdMOtbmggbsSDbmcuJywgJ3dhcm4nKTsKICAgIH0gZWxzZSB7CiAgICAgIGFkZExvZygn8J+SjiBLZXkgUFJFTUlVTTogVOG6pXQgY+G6oyB0w61uaCBuxINuZyDEkcOjIMSRxrDhu6NjIG3hu58ga2hvw6EhJywgJ29rJyk7CiAgICAgIF9zdGFydEhlYXJ0YmVhdCgpOwogICAgfQogIH0KICBjb25zdCBBUElfS0VZV09SRFMgPSBbICdnZXQtcXVlc3Rpb24tb2YtaWRzJywgJ2dldC1xdWVzdGlvbj9iZWxvbmdzPTEnLCAnZ2V0LXF1ZXN0aW9uJywgJ2dldC10ZXN0JyBdOwogIGZ1bmN0aW9uIGhhbmRsZVJhd1Jlc3BvbnNlKHVybCwgdGV4dCkgewogICAgaWYgKCF1cmwgfHwgIXRleHQpIHJldHVybjsKICAgIGNvbnN0IGlzUUFwaSA9IEFQSV9LRVlXT1JEUy5zb21lKGsgPT4gdXJsLmluY2x1ZGVzKGspKTsKICAgIGNvbnN0IGlzTGVnID0gdXJsLmluY2x1ZGVzKCdnZXQtcXVlc3Rpb24nKSB8fCB1cmwuaW5jbHVkZXMoJ2dldC10ZXN0JykgfHwgdGV4dC5pbmNsdWRlcygnanNvbl9jb250ZW50JykgfHwgdGV4dC5pbmNsdWRlcygnInF1ZXN0aW9ucyInKTsKICAgIGlmICghaXNRQXBpICYmICFpc0xlZykgcmV0dXJuOwogICAgbGV0IGRhdGE7CiAgICB0cnkgewogICAgICBkYXRhID0gSlNPTi5wYXJzZSh0ZXh0KTsKICAgIH0gY2F0Y2ggKF8pIHsKICAgICAgcmV0dXJuOwogICAgfQogICAgY29uc3QgcUxpc3QgPSBkYXRhLnF1ZXN0aW9ucyB8fCBkYXRhLmRhdGEgfHwgKEFycmF5LmlzQXJyYXkoZGF0YSkgPyBkYXRhIDogbnVsbCk7CiAgICBpZiAoIUFycmF5LmlzQXJyYXkocUxpc3QpIHx8IHFMaXN0Lmxlbmd0aCA9PT0gMCkgcmV0dXJuOwogICAgU0VTU0lPTi5yYXdfcXVlc3Rpb25zID0gcUxpc3Q7CiAgICBTRVNTSU9OLm1ldGEuaWRfdXNlciA9IHFMaXN0WzBdPy5pZF91c2VyIHx8IGRldGVjdFVzZXJJRCgpOwogICAgU0VTU0lPTi5tZXRhLmlkX2NvdXJzZXdhcmUgPSBkYXRhLmlkX2NvdXJzZXdhcmUgfHwgbmV3IFVSTFNlYXJjaFBhcmFtcyh3aW5kb3cubG9jYXRpb24uc2VhcmNoKS5nZXQoJ2lfYycpOwogICAgU0VTU0lPTi5tZXRhLmlkX2NhdGUgPSBkYXRhLmlkX2NhdGUgfHwgZGF0YS5pZF9leGFtIHx8IHJpcElkRnJvbVVybCgpOwogICAgU0VTU0lPTi5tZXRhLmlkX3NjaG9vbCA9IGRldGVjdFNjaG9vbElEKGRhdGEpOwogICAgU0VTU0lPTi5tZXRhLmlkX2dyb3VwID0gZGV0ZWN0R3JvdXBJRCgpOwogICAgY29uc3QgbXQgPSBkb2N1bWVudC5xdWVyeVNlbGVjdG9yKCdtZXRhW25hbWU9ImNzcmYtdG9rZW4iXScpOwogICAgU0VTU0lPTi5tZXRhLmNzcmZfdG9rZW4gPSBtdCA/IG10LmdldEF0dHJpYnV0ZSgnY29udGVudCcpIDogd2luZG93LmNzcmZfdG9rZW4gfHwgJyc7CiAgICBpZiAod2luZG93LnRvdGFsX3RpbWUpIFNFU1NJT04udmlkZW9fbGVuZ3RoID0gTWF0aC5jZWlsKHdpbmRvdy50b3RhbF90aW1lKTsgZWxzZSBpZiAoZGF0YS50b3RhbF90aW1lKSBTRVNTSU9OLnZpZGVvX2xlbmd0aCA9IE1hdGguY2VpbChkYXRhLnRvdGFsX3RpbWUpOwogICAgaWYgKGRhdGEudHlwZSA9PSA1IHx8IHdpbmRvdy5sb2NhdGlvbi5ocmVmLmluY2x1ZGVzKCd2aWRlbycpIHx8IGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoJ3ZpZGVvLGlmcmFtZVtzcmMqPSJ5b3V0dWJlIl0nKSkgU0VTU0lPTi5hdXRvX21vZGUgPSAndmlkZW8nOyBlbHNlIGlmIChkYXRhLnR5cGVfZXhhbSA9PSAxIHx8IGRhdGEuaXNfZXhhbSA9PSAxIHx8IHdpbmRvdy5pc19leGFtID09IDEgfHwgZG9jdW1lbnQucXVlcnlTZWxlY3RvcignLnRpbWUtY291bnRkb3duLCNzdWJtaXQtdGVzdCcpKSBTRVNTSU9OLmF1dG9fbW9kZSA9ICdleGFtJzsgZWxzZSBTRVNTSU9OLmF1dG9fbW9kZSA9ICdwcmFjdGljZSc7CiAgICBjb25zdCBxY0VsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RsLXFjb3VudCcpOwogICAgY29uc3QgbWRFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1tb2RlLWRldGVjdGVkJyk7CiAgICBpZiAocWNFbCkgcWNFbC50ZXh0Q29udGVudCA9IHFMaXN0Lmxlbmd0aDsKICAgIGlmIChtZEVsKSB7CiAgICAgIG1kRWwudGV4dENvbnRlbnQgPSBTRVNTSU9OLmF1dG9fbW9kZS50b1VwcGVyQ2FzZSgpOwogICAgICBjb25zdCBtcyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1tb2RlU2VsZWN0Jyk7CiAgICAgIGlmIChtcykgbXMudmFsdWUgPSBTRVNTSU9OLmF1dG9fbW9kZTsKICAgIH0KICAgIGFkZExvZyhg8J+TpSBO4bqhcCAke3FMaXN0Lmxlbmd0aH0gY8OidSBo4buPaSAoJHtTRVNTSU9OLmF1dG9fbW9kZX0pIOKAlCDEkWFuZyBnaeG6o2kgbcOjLi4uYCwgJ2luZm8nKTsKICAgIGNvbnN0IGtleSA9IENVUlJFTlRfS0VZIHx8IF9zTFMuZ2V0KExTX0tFWSk7CiAgICBpZiAoIWtleSkgewogICAgICBhZGRMb2coJ+KaoO+4jyBDaMawYSBjw7Mga2V5IOKAlCBraMO0bmcgdGjhu4MgZ2nhuqNpIG3Doy4nLCAnd2FybicpOwogICAgICByZXR1cm47CiAgICB9CiAgICBnbVBvc3QoJy9wcm9jZXNzJywgewogICAgICBrZXk6IGtleSwKICAgICAgaHdpZDogZ2V0SFdJRCgpLAogICAgICBxdWVzdGlvbnM6IHFMaXN0CiAgICB9KS50aGVuKHJlc3VsdCA9PiB7CiAgICAgIGlmICghKHJlc3VsdC5zdWNjZXNzIHx8IHJlc3VsdC52YWxpZCkpIHsKICAgICAgICBhZGRMb2coJ+KdjCBTZXJ2ZXI6ICcgKyAocmVzdWx0Lm1lc3NhZ2UgfHwgJ0zhu5dpIGdp4bqjaSBtw6MnKSwgJ2VycicpOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBjb25zdCBib3ggPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtbG9nYm94Jyk7CiAgICAgIGlmIChib3gpIHsKICAgICAgICBib3guaW5uZXJIVE1MID0gJyc7CiAgICAgICAgcmVzdWx0LnF1ZXN0aW9ucy5mb3JFYWNoKHEgPT4gewogICAgICAgICAgY29uc3QgZCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpOwogICAgICAgICAgZC5jbGFzc05hbWUgPSAndGwtbG9nIG9rJzsKICAgICAgICAgIGQuaW5uZXJIVE1MID0gYDxiPlEke3EuaW5kZXh9OjwvYj4gJHsocS50aXRsZSB8fCAnJykuc3Vic3RyaW5nKDAsIDQwKX0g4oaSIDxzcGFuIHN0eWxlPSJjb2xvcjojZmZjMTA3OyI+JHtxLmFuc3dlcnMuam9pbignIHwgJyl9PC9zcGFuPmA7CiAgICAgICAgICBib3guYXBwZW5kQ2hpbGQoZCk7CiAgICAgICAgfSk7CiAgICAgICAgYm94LnNjcm9sbFRvcCA9IGJveC5zY3JvbGxIZWlnaHQ7CiAgICAgIH0KICAgICAgYWRkTG9nKGDinIUgxJDDoyBoaeG7g24gdGjhu4sgxJHDoXAgw6FuICR7cmVzdWx0LmNvdW50fSBjw6J1IWAsICdvaycpOwogICAgfSkuY2F0Y2goZSA9PiBhZGRMb2coJ+KdjCBM4buXaSBr4bq/dCBu4buRaSBzZXJ2ZXI6ICcgKyBlLm1lc3NhZ2UsICdlcnInKSk7CiAgfQogIChmdW5jdGlvbiBpbmplY3RQYWdlSG9vaygpIHsKICAgIHRyeSB7CiAgICAgIGNvbnN0IGNvZGUgPSAnKCcgKyBmdW5jdGlvbigpIHsKICAgICAgICBpZiAod2luZG93Ll9fdGxfaG9va2VkKSByZXR1cm47CiAgICAgICAgd2luZG93Ll9fdGxfaG9va2VkID0gdHJ1ZTsKICAgICAgICB3aW5kb3cuX19rdl9xX2J1ZiA9IHdpbmRvdy5fX2t2X3FfYnVmIHx8IFtdOwogICAgICAgIGZ1bmN0aW9uIF9fdGxfcHVzaCh1cmwsIHRleHQpIHsKICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgIHdpbmRvdy5fX2t2X3FfYnVmLnB1c2goewogICAgICAgICAgICAgIHVybDogdXJsLAogICAgICAgICAgICAgIHRleHQ6IHRleHQsCiAgICAgICAgICAgICAgdHM6IERhdGUubm93KCkKICAgICAgICAgICAgfSk7CiAgICAgICAgICAgIHdpbmRvdy5kaXNwYXRjaEV2ZW50KG5ldyBDdXN0b21FdmVudCgnX19rdl9xZGF0YScsIHsKICAgICAgICAgICAgICBkZXRhaWw6IHsKICAgICAgICAgICAgICAgIHVybDogdXJsLAogICAgICAgICAgICAgICAgdGV4dDogdGV4dAogICAgICAgICAgICAgIH0KICAgICAgICAgICAgfSkpOwogICAgICAgICAgfSBjYXRjaCAoZSkge30KICAgICAgICB9CiAgICAgICAgZnVuY3Rpb24gX190bF9yZW1lbWJlcl9yZXEodXJsLCBtZXRob2QsIGJvZHkpIHsKICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgIHZhciB1ID0gKHVybCB8fCAnJykudG9Mb3dlckNhc2UoKTsKICAgICAgICAgICAgaWYgKHUuaW5kZXhPZignZ2V0LXF1ZXN0aW9uJykgIT09IC0xIHx8IHUuaW5kZXhPZignZ2V0LXRlc3QnKSAhPT0gLTEpIHsKICAgICAgICAgICAgICB3aW5kb3cuX190bF9sYXN0X3FyZXEgPSB7CiAgICAgICAgICAgICAgICB1cmw6IHVybCwKICAgICAgICAgICAgICAgIG1ldGhvZDogbWV0aG9kIHx8ICdHRVQnLAogICAgICAgICAgICAgICAgYm9keTogYm9keSB8fCBudWxsLAogICAgICAgICAgICAgICAgdHM6IERhdGUubm93KCkKICAgICAgICAgICAgICB9OwogICAgICAgICAgICB9CiAgICAgICAgICB9IGNhdGNoIChlKSB7fQogICAgICAgIH0KICAgICAgICB2YXIgX19vID0gWE1MSHR0cFJlcXVlc3QucHJvdG90eXBlLm9wZW47CiAgICAgICAgdmFyIF9fcyA9IFhNTEh0dHBSZXF1ZXN0LnByb3RvdHlwZS5zZW5kOwogICAgICAgIFhNTEh0dHBSZXF1ZXN0LnByb3RvdHlwZS5vcGVuID0gZnVuY3Rpb24obSwgdSkgewogICAgICAgICAgdGhpcy5fX3RsX3VybCA9IHU7CiAgICAgICAgICByZXR1cm4gX19vLmFwcGx5KHRoaXMsIGFyZ3VtZW50cyk7CiAgICAgICAgfTsKICAgICAgICBYTUxIdHRwUmVxdWVzdC5wcm90b3R5cGUuc2VuZCA9IGZ1bmN0aW9uKGJvZHkpIHsKICAgICAgICAgIHZhciBzZWxmID0gdGhpczsKICAgICAgICAgIF9fdGxfcmVtZW1iZXJfcmVxKHNlbGYuX190bF91cmwgfHwgJycsICdQT1NUJywgYm9keSB8fCBudWxsKTsKICAgICAgICAgIHRoaXMuYWRkRXZlbnRMaXN0ZW5lcignbG9hZCcsIGZ1bmN0aW9uKCkgewogICAgICAgICAgICBpZiAoc2VsZi5zdGF0dXMgPT09IDIwMCkgewogICAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgICBfX3RsX3B1c2goc2VsZi5yZXNwb25zZVVSTCB8fCBzZWxmLl9fdGxfdXJsIHx8ICcnLCBzZWxmLnJlc3BvbnNlVGV4dCB8fCAnJyk7CiAgICAgICAgICAgICAgfSBjYXRjaCAoZSkge30KICAgICAgICAgICAgfQogICAgICAgICAgfSk7CiAgICAgICAgICByZXR1cm4gX19zLmFwcGx5KHRoaXMsIGFyZ3VtZW50cyk7CiAgICAgICAgfTsKICAgICAgICB2YXIgX19mID0gd2luZG93LmZldGNoOwogICAgICAgIHdpbmRvdy5mZXRjaCA9IGZ1bmN0aW9uKCkgewogICAgICAgICAgdmFyIGFyZ3MgPSBhcmd1bWVudHM7CiAgICAgICAgICB2YXIgdXJsID0gdHlwZW9mIGFyZ3NbMF0gPT09ICdzdHJpbmcnID8gYXJnc1swXSA6IGFyZ3NbMF0gJiYgYXJnc1swXS51cmwgPyBhcmdzWzBdLnVybCA6ICcnOwogICAgICAgICAgdmFyIG9wdHMgPSBhcmdzWzFdIHx8ICh0eXBlb2YgYXJnc1swXSA9PT0gJ29iamVjdCcgPyBhcmdzWzBdIDogbnVsbCk7CiAgICAgICAgICBfX3RsX3JlbWVtYmVyX3JlcSh1cmwsIG9wdHMgJiYgb3B0cy5tZXRob2QgfHwgJ0dFVCcsIG9wdHMgJiYgb3B0cy5ib2R5IHx8IG51bGwpOwogICAgICAgICAgcmV0dXJuIF9fZi5hcHBseSh0aGlzLCBhcmdzKS50aGVuKGZ1bmN0aW9uKHJlcykgewogICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgIHZhciBjbCA9IHJlcy5jbG9uZSgpOwogICAgICAgICAgICAgIGNsLnRleHQoKS50aGVuKGZ1bmN0aW9uKHQpIHsKICAgICAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgICAgIF9fdGxfcHVzaCh1cmwgfHwgcmVzLnVybCB8fCAnJywgdCk7CiAgICAgICAgICAgICAgICB9IGNhdGNoIChlKSB7fQogICAgICAgICAgICAgIH0pOwogICAgICAgICAgICB9IGNhdGNoIChlKSB7fQogICAgICAgICAgICByZXR1cm4gcmVzOwogICAgICAgICAgfSk7CiAgICAgICAgfTsKICAgICAgICB3aW5kb3cuX190bF9teV9vcGVuID0gWE1MSHR0cFJlcXVlc3QucHJvdG90eXBlLm9wZW47CiAgICAgICAgd2luZG93Ll9fdGxfbXlfc2VuZCA9IFhNTEh0dHBSZXF1ZXN0LnByb3RvdHlwZS5zZW5kOwogICAgICAgIHdpbmRvdy5fX3RsX215X2ZldGNoID0gd2luZG93LmZldGNoOwogICAgICAgIHNldEludGVydmFsKGZ1bmN0aW9uKCkgewogICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgaWYgKFhNTEh0dHBSZXF1ZXN0LnByb3RvdHlwZS5vcGVuICE9PSB3aW5kb3cuX190bF9teV9vcGVuIHx8IFhNTEh0dHBSZXF1ZXN0LnByb3RvdHlwZS5zZW5kICE9PSB3aW5kb3cuX190bF9teV9zZW5kIHx8IHdpbmRvdy5mZXRjaCAhPT0gd2luZG93Ll9fdGxfbXlfZmV0Y2gpIHsKICAgICAgICAgICAgICB3aW5kb3cuZGlzcGF0Y2hFdmVudChuZXcgQ3VzdG9tRXZlbnQoJ19fdGxfZm9yZWlnbl9ob29rJywgewogICAgICAgICAgICAgICAgZGV0YWlsOiB7CiAgICAgICAgICAgICAgICAgIHQ6IERhdGUubm93KCkKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICB9KSk7CiAgICAgICAgICAgIH0KICAgICAgICAgIH0gY2F0Y2ggKGUpIHt9CiAgICAgICAgfSwgOGUzKTsKICAgICAgfSArICcpKCk7JzsKICAgICAgY29uc3Qgc0VsID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc2NyaXB0Jyk7CiAgICAgIHNFbC50ZXh0Q29udGVudCA9IGNvZGU7CiAgICAgIChkb2N1bWVudC5oZWFkIHx8IGRvY3VtZW50LmRvY3VtZW50RWxlbWVudCkuYXBwZW5kQ2hpbGQoc0VsKTsKICAgICAgc0VsLnJlbW92ZSgpOwogICAgfSBjYXRjaCAoZSkgewogICAgICBjb25zb2xlLndhcm4oJ1tUTF0gaW5qZWN0IGZhaWwnLCBlKTsKICAgIH0KICB9KSgpOwogIGZ1bmN0aW9uIHNldHVwS1ZCdWZSZWFkZXIoKSB7CiAgICB0cnkgewogICAgICBjb25zdCBVVyA9IHR5cGVvZiB1bnNhZmVXaW5kb3cgIT09ICd1bmRlZmluZWQnID8gdW5zYWZlV2luZG93IDogd2luZG93OwogICAgICBsZXQgcHJvY2Vzc2VkID0gMDsKICAgICAgZnVuY3Rpb24gZHJhaW4oKSB7CiAgICAgICAgdHJ5IHsKICAgICAgICAgIGNvbnN0IGJ1ZiA9IFVXLl9fa3ZfcV9idWY7CiAgICAgICAgICBpZiAoIUFycmF5LmlzQXJyYXkoYnVmKSB8fCBidWYubGVuZ3RoIDw9IHByb2Nlc3NlZCkgcmV0dXJuOwogICAgICAgICAgZm9yIChsZXQgaSA9IHByb2Nlc3NlZDsgaSA8IGJ1Zi5sZW5ndGg7IGkrKykgewogICAgICAgICAgICBjb25zdCBpdCA9IGJ1ZltpXTsKICAgICAgICAgICAgaWYgKGl0ICYmIGl0LnVybCAmJiBpdC50ZXh0KSB7CiAgICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgIGhhbmRsZVJhd1Jlc3BvbnNlKGl0LnVybCwgaXQudGV4dCk7CiAgICAgICAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgICAgICAgfQogICAgICAgICAgfQogICAgICAgICAgcHJvY2Vzc2VkID0gYnVmLmxlbmd0aDsKICAgICAgICB9IGNhdGNoIChfKSB7fQogICAgICB9CiAgICAgIHRyeSB7CiAgICAgICAgVVcuYWRkRXZlbnRMaXN0ZW5lcignX19rdl9xZGF0YScsIGZ1bmN0aW9uKGV2dCkgewogICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgY29uc3QgZCA9IGV2dCAmJiBldnQuZGV0YWlsOwogICAgICAgICAgICBpZiAoZCAmJiBkLnVybCAmJiBkLnRleHQpIHsKICAgICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgaGFuZGxlUmF3UmVzcG9uc2UoZC51cmwsIGQudGV4dCk7CiAgICAgICAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgICAgICAgfQogICAgICAgICAgICBjb25zdCBidWYgPSBVVy5fX2t2X3FfYnVmOwogICAgICAgICAgICBpZiAoQXJyYXkuaXNBcnJheShidWYpKSBwcm9jZXNzZWQgPSBidWYubGVuZ3RoOwogICAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgICB9KTsKICAgICAgfSBjYXRjaCAoXykge30KICAgICAgZHJhaW4oKTsKICAgICAgaWYgKGRvY3VtZW50LnJlYWR5U3RhdGUgPT09ICdsb2FkaW5nJykgZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcignRE9NQ29udGVudExvYWRlZCcsIGRyYWluKTsgZWxzZSBzZXRUaW1lb3V0KGRyYWluLCA4MDApOwogICAgICBjb25zdCBpdiA9IHNldEludGVydmFsKGRyYWluLCA1MDApOwogICAgICBzZXRUaW1lb3V0KCgpID0+IGNsZWFySW50ZXJ2YWwoaXYpLCAyNWUzKTsKICAgIH0gY2F0Y2ggKF8pIHt9CiAgfQogIHNldHVwS1ZCdWZSZWFkZXIoKTsKICB0cnkgewogICAgY29uc3QgVVcgPSB0eXBlb2YgdW5zYWZlV2luZG93ICE9PSAndW5kZWZpbmVkJyA/IHVuc2FmZVdpbmRvdyA6IHdpbmRvdzsKICAgIGxldCBfZm9yZWlnblN0cmlrZSA9IDA7CiAgICBVVy5hZGRFdmVudExpc3RlbmVyKCdfX3RsX2ZvcmVpZ25faG9vaycsICgpID0+IHsKICAgICAgdHJ5IHsKICAgICAgICBpZiAoVVcuX19rdl9xX2J1ZikgcmV0dXJuOwogICAgICB9IGNhdGNoIChfKSB7fQogICAgICBfZm9yZWlnblN0cmlrZSsrOwogICAgICBpZiAoX2ZvcmVpZ25TdHJpa2UgPj0gMyAmJiBfZ3VhcmRBY3RpdmUpIHsKICAgICAgICBfZW50ZXJSZW1vdGVMb2NrKCfwn5uh77iPIFBow6F0IGhp4buHbiB1c2Vyc2NyaXB0L3Bo4bqnbiBt4buBbSBs4bqhIGNhbiB0aGnhu4dwIHbDoG8ga+G6v3QgbuG7kWkgKMSRw6MgeMOhYyBuaOG6rW4gMyBs4bqnbikuIMSQw6MgYsOhbyBjw6FvIGFkbWluLCBjaOG7nSBt4bufIGtob8OhIHThu6sgeGEuJyk7CiAgICAgIH0KICAgIH0pOwogIH0gY2F0Y2ggKF8pIHt9CiAgKGZ1bmN0aW9uIF9pbml0Rm9yZWlnblVzR3VhcmQoKSB7CiAgICB0cnkgewogICAgICBsZXQgX2Z1c1N0cmlrZSA9IDA7CiAgICAgIGNvbnN0IFVXID0gdHlwZW9mIHVuc2FmZVdpbmRvdyAhPT0gJ3VuZGVmaW5lZCcgPyB1bnNhZmVXaW5kb3cgOiB3aW5kb3c7CiAgICAgIFVXLmFkZEV2ZW50TGlzdGVuZXIoJ19fdGxfZm9yZWlnbl91cycsIGZ1bmN0aW9uKGV2dCkgewogICAgICAgIHRyeSB7CiAgICAgICAgICBjb25zdCBkID0gZXZ0ICYmIGV2dC5kZXRhaWwgfHwge307CiAgICAgICAgICBpZiAoZC5jbGVhbikgcmV0dXJuOwogICAgICAgICAgX2VudGVyUmVtb3RlTG9jaygn8J+boe+4jyBQaMOhdCBoaeG7h24gdXNlcnNjcmlwdC9waOG6p24gbeG7gW0gbOG6oSBjaOG6oXkgc29uZyBzb25nICgnICsgKGQuc2lnIHx8ICd1bmtub3duJykgKyAnKS4gxJDDoyBjaOG6t24gbmdheSBs4bqtcCB04bupYywgYsOhbyBjw6FvIGFkbWluLCBjaOG7nSBt4bufIGtob8OhIHThu6sgeGEuJyk7CiAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgfSk7CiAgICAgIGNvbnN0IGNvZGUgPSAnKCcgKyBmdW5jdGlvbigpIHsKICAgICAgICBpZiAod2luZG93Ll9fdGxfZnVzX2d1YXJkKSByZXR1cm47CiAgICAgICAgd2luZG93Ll9fdGxfZnVzX2d1YXJkID0gdHJ1ZTsKICAgICAgICB2YXIgX2Jhc2VOYXQgPSB7fTsKICAgICAgICB0cnkgewogICAgICAgICAgX2Jhc2VOYXQuc2V0VGltZW91dCA9ICcnICsgc2V0VGltZW91dDsKICAgICAgICB9IGNhdGNoIChlKSB7fQogICAgICAgIHRyeSB7CiAgICAgICAgICBfYmFzZU5hdC5zZXRJbnRlcnZhbCA9ICcnICsgc2V0SW50ZXJ2YWw7CiAgICAgICAgfSBjYXRjaCAoZSkge30KICAgICAgICB0cnkgewogICAgICAgICAgX2Jhc2VOYXQuZXZhbCA9ICcnICsgZXZhbDsKICAgICAgICB9IGNhdGNoIChlKSB7fQogICAgICAgIHRyeSB7CiAgICAgICAgICBfYmFzZU5hdC5GdW5jdGlvbiA9ICcnICsgRnVuY3Rpb247CiAgICAgICAgfSBjYXRjaCAoZSkge30KICAgICAgICB0cnkgewogICAgICAgICAgX2Jhc2VOYXQuZGVmaW5lUHJvcGVydHkgPSAnJyArIE9iamVjdC5kZWZpbmVQcm9wZXJ0eTsKICAgICAgICB9IGNhdGNoIChlKSB7fQogICAgICAgIHRyeSB7CiAgICAgICAgICBfYmFzZU5hdC5KU09OcGFyc2UgPSAnJyArIEpTT04ucGFyc2U7CiAgICAgICAgfSBjYXRjaCAoZSkge30KICAgICAgICB0cnkgewogICAgICAgICAgX2Jhc2VOYXQuZm5Ub1N0cmluZyA9ICcnICsgRnVuY3Rpb24ucHJvdG90eXBlLnRvU3RyaW5nOwogICAgICAgIH0gY2F0Y2ggKGUpIHt9CiAgICAgICAgdmFyIE9XTiA9IHsKICAgICAgICAgIF9fdGxfaG9va2VkOiAxLAogICAgICAgICAgX19rdl9xX2J1ZjogMSwKICAgICAgICAgIF9fdGxfbXlfb3BlbjogMSwKICAgICAgICAgIF9fdGxfbXlfc2VuZDogMSwKICAgICAgICAgIF9fdGxfbXlfZmV0Y2g6IDEsCiAgICAgICAgICBfX3RsX2xhc3RfcXJlcTogMSwKICAgICAgICAgIF9fdGxfZnVzX2d1YXJkOiAxCiAgICAgICAgfTsKICAgICAgICB2YXIgVVNfUkUgPSAvPT1Vc2VyU2NyaXB0PT18QGdyYW50fEBtYXRjaHxHTV94bWxodHRwUmVxdWVzdHxHTV9hZGRTdHlsZXxHTV9zZXRWYWx1ZXxHTV9nZXRWYWx1ZXxHTV9yZWdpc3Rlck1lbnVDb21tYW5kfEdNX25vdGlmaWNhdGlvbnxHTV9jb29raWV8R01fZG93bmxvYWR8dW5zYWZlV2luZG93fEdNX2luZm8vaTsKICAgICAgICB2YXIgR01fTEVBS19SRSA9IC9eKEdNX3xfX2dtfF9fdShzZXIpP3NjcmlwdCkvaTsKICAgICAgICBmdW5jdGlvbiBmaXJlKHNpZykgewogICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgd2luZG93LmRpc3BhdGNoRXZlbnQobmV3IEN1c3RvbUV2ZW50KCdfX3RsX2ZvcmVpZ25fdXMnLCB7CiAgICAgICAgICAgICAgZGV0YWlsOiB7CiAgICAgICAgICAgICAgICBzaWc6IHNpZywKICAgICAgICAgICAgICAgIHQ6IERhdGUubm93KCkKICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0pKTsKICAgICAgICAgIH0gY2F0Y2ggKGUpIHt9CiAgICAgICAgfQogICAgICAgIGZ1bmN0aW9uIGNsZWFuKCkgewogICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgd2luZG93LmRpc3BhdGNoRXZlbnQobmV3IEN1c3RvbUV2ZW50KCdfX3RsX2ZvcmVpZ25fdXMnLCB7CiAgICAgICAgICAgICAgZGV0YWlsOiB7CiAgICAgICAgICAgICAgICBjbGVhbjogdHJ1ZSwKICAgICAgICAgICAgICAgIHQ6IERhdGUubm93KCkKICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0pKTsKICAgICAgICAgIH0gY2F0Y2ggKGUpIHt9CiAgICAgICAgfQogICAgICAgIHZhciBiYXNlbGluZSA9IG51bGw7CiAgICAgICAgdmFyIHBlbmRpbmcgPSB7fTsKICAgICAgICBzZXRUaW1lb3V0KGZ1bmN0aW9uKCkgewogICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgYmFzZWxpbmUgPSB7fTsKICAgICAgICAgICAgT2JqZWN0LmdldE93blByb3BlcnR5TmFtZXMod2luZG93KS5mb3JFYWNoKGZ1bmN0aW9uKG4pIHsKICAgICAgICAgICAgICBiYXNlbGluZVtuXSA9IDE7CiAgICAgICAgICAgIH0pOwogICAgICAgICAgfSBjYXRjaCAoZSkge30KICAgICAgICB9LCAxNWUzKTsKICAgICAgICBmdW5jdGlvbiBzY2FuKCkgewogICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgdmFyIGhpdCA9IG51bGwsIGksIG4sIHY7CiAgICAgICAgICAgIGlmICghaGl0KSB7CiAgICAgICAgICAgICAgdmFyIGN1ciA9IHt9OwogICAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgICBjdXIuc2V0VGltZW91dCA9ICcnICsgc2V0VGltZW91dDsKICAgICAgICAgICAgICB9IGNhdGNoIChlKSB7fQogICAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgICBjdXIuc2V0SW50ZXJ2YWwgPSAnJyArIHNldEludGVydmFsOwogICAgICAgICAgICAgIH0gY2F0Y2ggKGUpIHt9CiAgICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgIGN1ci5ldmFsID0gJycgKyBldmFsOwogICAgICAgICAgICAgIH0gY2F0Y2ggKGUpIHt9CiAgICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgIGN1ci5GdW5jdGlvbiA9ICcnICsgRnVuY3Rpb247CiAgICAgICAgICAgICAgfSBjYXRjaCAoZSkge30KICAgICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgY3VyLmRlZmluZVByb3BlcnR5ID0gJycgKyBPYmplY3QuZGVmaW5lUHJvcGVydHk7CiAgICAgICAgICAgICAgfSBjYXRjaCAoZSkge30KICAgICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgY3VyLkpTT05wYXJzZSA9ICcnICsgSlNPTi5wYXJzZTsKICAgICAgICAgICAgICB9IGNhdGNoIChlKSB7fQogICAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgICBjdXIuZm5Ub1N0cmluZyA9ICcnICsgRnVuY3Rpb24ucHJvdG90eXBlLnRvU3RyaW5nOwogICAgICAgICAgICAgIH0gY2F0Y2ggKGUpIHt9CiAgICAgICAgICAgICAgZm9yICh2YXIgayBpbiBfYmFzZU5hdCkgewogICAgICAgICAgICAgICAgaWYgKF9iYXNlTmF0W2tdICYmIGN1cltrXSAhPT0gX2Jhc2VOYXRba10pIHsKICAgICAgICAgICAgICAgICAgaGl0ID0gJ2hvb2tlZCBhZnRlciBpbml0OiAnICsgazsKICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgICAgIGlmICghaGl0KSB7CiAgICAgICAgICAgICAgdmFyIHNjcyA9IGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJ3NjcmlwdDpub3QoW3NyY10pJyk7CiAgICAgICAgICAgICAgZm9yIChpID0gMDsgaSA8IHNjcy5sZW5ndGg7IGkrKykgewogICAgICAgICAgICAgICAgdmFyIHQgPSBzY3NbaV0udGV4dENvbnRlbnQgfHwgJyc7CiAgICAgICAgICAgICAgICBpZiAodC5sZW5ndGggPiA4MCAmJiBVU19SRS50ZXN0KHQpKSB7CiAgICAgICAgICAgICAgICAgIGhpdCA9ICd1c2Vyc2NyaXB0IGlubGluZSBtYXJrZXInOwogICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KICAgICAgICAgICAgaWYgKCFoaXQpIHsKICAgICAgICAgICAgICB2YXIgbmFtZXMgPSBPYmplY3QuZ2V0T3duUHJvcGVydHlOYW1lcyh3aW5kb3cpOwogICAgICAgICAgICAgIGZvciAoaSA9IDA7IGkgPCBuYW1lcy5sZW5ndGg7IGkrKykgewogICAgICAgICAgICAgICAgbiA9IG5hbWVzW2ldOwogICAgICAgICAgICAgICAgaWYgKE9XTltuXSkgY29udGludWU7CiAgICAgICAgICAgICAgICBpZiAobiA9PT0gJ0dNX2luZm8nIHx8IG4gPT09ICd1bnNhZmVXaW5kb3cnIHx8IEdNX0xFQUtfUkUudGVzdChuKSkgewogICAgICAgICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgICAgIHYgPSB3aW5kb3dbbl07CiAgICAgICAgICAgICAgICAgICAgaWYgKHR5cGVvZiB2ICE9PSAndW5kZWZpbmVkJykgewogICAgICAgICAgICAgICAgICAgICAgaGl0ID0gJ0dNIGxlYWs6ICcgKyBuOwogICAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICB9IGNhdGNoIChlKSB7fQogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgIH0KICAgICAgICAgICAgfQogICAgICAgICAgICBpZiAoIWhpdCAmJiBiYXNlbGluZSkgewogICAgICAgICAgICAgIHZhciBjdXIgPSBPYmplY3QuZ2V0T3duUHJvcGVydHlOYW1lcyh3aW5kb3cpOwogICAgICAgICAgICAgIHZhciBzZWVuTm93ID0ge307CiAgICAgICAgICAgICAgdmFyIGNvbmZpcm1lZCA9IDA7CiAgICAgICAgICAgICAgZm9yIChpID0gMDsgaSA8IGN1ci5sZW5ndGg7IGkrKykgewogICAgICAgICAgICAgICAgbiA9IGN1cltpXTsKICAgICAgICAgICAgICAgIGlmIChPV05bbl0gfHwgYmFzZWxpbmVbbl0pIGNvbnRpbnVlOwogICAgICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgICAgdiA9IHdpbmRvd1tuXTsKICAgICAgICAgICAgICAgICAgaWYgKHR5cGVvZiB2ICE9PSAnZnVuY3Rpb24nICYmICh0eXBlb2YgdiAhPT0gJ29iamVjdCcgfHwgdiA9PT0gbnVsbCkpIGNvbnRpbnVlOwogICAgICAgICAgICAgICAgfSBjYXRjaCAoZSkgewogICAgICAgICAgICAgICAgICBjb250aW51ZTsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIHNlZW5Ob3dbbl0gPSAxOwogICAgICAgICAgICAgICAgaWYgKHBlbmRpbmdbbl0pIGNvbmZpcm1lZCsrOyBlbHNlIHBlbmRpbmdbbl0gPSAxOwogICAgICAgICAgICAgIH0KICAgICAgICAgICAgICBmb3IgKHZhciBwayBpbiBwZW5kaW5nKSB7CiAgICAgICAgICAgICAgICBpZiAoIXNlZW5Ob3dbcGtdKSBkZWxldGUgcGVuZGluZ1twa107CiAgICAgICAgICAgICAgfQogICAgICAgICAgICAgIGlmIChjb25maXJtZWQgPj0gOCkgaGl0ID0gY29uZmlybWVkICsgJyBuZXcgcGVyc2lzdGVudCBnbG9iYWxzJzsKICAgICAgICAgICAgfQogICAgICAgICAgICBpZiAoaGl0KSBmaXJlKGhpdCk7IGVsc2UgY2xlYW4oKTsKICAgICAgICAgIH0gY2F0Y2ggKGUpIHt9CiAgICAgICAgfQogICAgICAgIHNldFRpbWVvdXQoc2NhbiwgNTAwKTsKICAgICAgICBzZXRUaW1lb3V0KGZ1bmN0aW9uKCkgewogICAgICAgICAgc2V0SW50ZXJ2YWwoc2NhbiwgM2UzKTsKICAgICAgICB9LCAxZTMpOwogICAgICB9ICsgJykoKTsnOwogICAgICBjb25zdCBzRWwgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdzY3JpcHQnKTsKICAgICAgc0VsLnRleHRDb250ZW50ID0gY29kZTsKICAgICAgKGRvY3VtZW50LmhlYWQgfHwgZG9jdW1lbnQuZG9jdW1lbnRFbGVtZW50KS5hcHBlbmRDaGlsZChzRWwpOwogICAgICBzRWwucmVtb3ZlKCk7CiAgICB9IGNhdGNoIChfKSB7fQogIH0pKCk7CiAgYXN5bmMgZnVuY3Rpb24gc3RhcnR1cCgpIHsKICAgIGlmIChsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgnX3RsX3JlbW90ZV9sb2NrZWQnKSA9PT0gJzEnIHx8IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdfdGxfcG9pc29uZWQnKSA9PT0gJzEnKSB7CiAgICAgIF9lbnRlclJlbW90ZUxvY2soJ1Bow6F0IGhp4buHbiBwaOG6p24gbeG7gW0gbOG6oSAoxJHDoyB4w6FjIG5o4bqtbikuIMSQYW5nIGNo4budIGFkbWluIG3hu58ga2hvw6EgdOG7qyB4YS4nKTsKICAgICAgcmV0dXJuOwogICAgfQogICAgX2luaXRHdWFyZCgpOwogICAgY29uc3Qgc3RvcmVkS2V5ID0gX3NMUy5nZXQoTFNfS0VZKTsKICAgIGNvbnN0IHN0b3JlZEV4cCA9IF9zTFMuZ2V0KExTX0VYUCk7CiAgICBpZiAoc3RvcmVkS2V5KSB7CiAgICAgIGlmIChzdG9yZWRFeHApIHsKICAgICAgICBjb25zdCBleHBEYXRlID0gbmV3IERhdGUoc3RvcmVkRXhwKTsKICAgICAgICBjb25zdCBub3cgPSBuZXcgRGF0ZTsKICAgICAgICBpZiAoIWlzTmFOKGV4cERhdGUpICYmIGV4cERhdGUgPCBub3cpIHsKICAgICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKExTX0tFWSk7CiAgICAgICAgICBidWlsZExvY2tTY3JlZW4oJ+KPsCBLZXkgxJHDoyBo4bq/dCBo4bqhbiEgVnVpIGzDsm5nIG5o4bqtcCBrZXkgbeG7m2kuJyk7CiAgICAgICAgICByZXR1cm47CiAgICAgICAgfQogICAgICB9CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgY3VycmVudE9sbSA9IGdldE9sbVVzZXJuYW1lKCk7CiAgICAgICAgY29uc3QgciA9IGF3YWl0IGdtUG9zdCgnL3ZlcmlmeScsIHsKICAgICAgICAgIGtleTogc3RvcmVkS2V5LAogICAgICAgICAgaHdpZDogZ2V0SFdJRCgpLAogICAgICAgICAgb2xtX3VzZXI6IGN1cnJlbnRPbG0KICAgICAgICB9KTsKICAgICAgICBpZiAoci5zdWNjZXNzIHx8IHIudmFsaWQpIHsKICAgICAgICAgIGNvbnN0IHNlcnZlck9sbSA9IHIub2xtX3VzZXIgfHwgci5vbG1fYWNjb3VudCB8fCAnJzsKICAgICAgICAgIGlmIChzZXJ2ZXJPbG0gJiYgY3VycmVudE9sbSAmJiBjdXJyZW50T2xtICE9PSAnS2hvbmdYYWNEaW5oJykgewogICAgICAgICAgICBpZiAoc2VydmVyT2xtLnRvTG93ZXJDYXNlKCkgIT09IGN1cnJlbnRPbG0udG9Mb3dlckNhc2UoKSkgewogICAgICAgICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKExTX0tFWSk7CiAgICAgICAgICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oTFNfVFlQRSk7CiAgICAgICAgICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oTFNfRVhQKTsKICAgICAgICAgICAgICBoYW5kbGVPbG1NaXNtYXRjaChzZXJ2ZXJPbG0sIGN1cnJlbnRPbG0pOwogICAgICAgICAgICAgIHJldHVybjsKICAgICAgICAgICAgfQogICAgICAgICAgfQogICAgICAgICAgQ1VSUkVOVF9LRVkgPSBzdG9yZWRLZXk7CiAgICAgICAgICBLRVlfU1RBVFVTID0gewogICAgICAgICAgICB2YWxpZDogdHJ1ZSwKICAgICAgICAgICAgdHlwZTogci50eXBlLAogICAgICAgICAgICBleHBpcmVzX2F0OiByLmV4cGlyZXNfYXQKICAgICAgICAgIH07CiAgICAgICAgICBfc0xTLnNldChMU19UWVBFLCByLnR5cGUgfHwgJ1RIVU9ORycpOwogICAgICAgICAgX3NMUy5zZXQoTFNfRVhQLCByLmV4cGlyZXNfYXQgfHwgJycpOwogICAgICAgICAgY3JlYXRlVUkoKTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgaWYgKHIgJiYgci5faHR0cFN0YXR1cyA9PT0gNDA0KSB7CiAgICAgICAgICAgIF9lbnRlckJhbk1vZGUoJ1RoaeG6v3QgYuG7iy9JUCDEkcOjIGLhu4sgYWRtaW4ga2hvw6EuJyk7CiAgICAgICAgICAgIHJldHVybjsKICAgICAgICAgIH0KICAgICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKExTX0tFWSk7CiAgICAgICAgICBidWlsZExvY2tTY3JlZW4oci5tZXNzYWdlIHx8ICdLZXkga2jDtG5nIGPDsm4gaOG7o3AgbOG7hyEnKTsKICAgICAgICB9CiAgICAgIH0gY2F0Y2ggKF8pIHsKICAgICAgICBDVVJSRU5UX0tFWSA9IHN0b3JlZEtleTsKICAgICAgICBLRVlfU1RBVFVTID0gewogICAgICAgICAgdmFsaWQ6IHRydWUsCiAgICAgICAgICB0eXBlOiBfc0xTLmdldChMU19UWVBFKSwKICAgICAgICAgIGV4cGlyZXNfYXQ6IHN0b3JlZEV4cAogICAgICAgIH07CiAgICAgICAgY3JlYXRlVUkoKTsKICAgICAgfQogICAgfSBlbHNlIHsKICAgICAgYnVpbGRMb2NrU2NyZWVuKCk7CiAgICB9CiAgICBzZXRJbnRlcnZhbChhc3luYyAoKSA9PiB7CiAgICAgIGlmICghQ1VSUkVOVF9LRVkpIHJldHVybjsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCBjdXJyZW50T2xtID0gZ2V0T2xtVXNlcm5hbWUoKTsKICAgICAgICBjb25zdCByID0gYXdhaXQgZ21Qb3N0KCcvdmVyaWZ5JywgewogICAgICAgICAga2V5OiBDVVJSRU5UX0tFWSwKICAgICAgICAgIGh3aWQ6IGdldEhXSUQoKSwKICAgICAgICAgIG9sbV91c2VyOiBjdXJyZW50T2xtCiAgICAgICAgfSk7CiAgICAgICAgaWYgKCEoci5zdWNjZXNzIHx8IHIudmFsaWQpKSB7CiAgICAgICAgICBpZiAociAmJiByLl9odHRwU3RhdHVzID09PSA0MDQpIHsKICAgICAgICAgICAgX2VudGVyQmFuTW9kZSgnVGhp4bq/dCBi4buLL0lQIMSRw6MgYuG7iyBhZG1pbiBraG/DoS4nKTsKICAgICAgICAgICAgcmV0dXJuOwogICAgICAgICAgfQogICAgICAgICAgY29uc3QgcGFuZWxFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0bC1wYW5lbCcpOwogICAgICAgICAgY29uc3QgZmIgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGwtZmxvYXRCdG4nKTsKICAgICAgICAgIGlmIChwYW5lbEVsKSBwYW5lbEVsLnJlbW92ZSgpOwogICAgICAgICAgaWYgKGZiKSBmYi5yZW1vdmUoKTsKICAgICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKExTX0tFWSk7CiAgICAgICAgICBDVVJSRU5UX0tFWSA9IG51bGw7CiAgICAgICAgICBfc2VjU2Vzc2lvbiA9IHsKICAgICAgICAgICAgdG9rZW46IG51bGwsCiAgICAgICAgICAgIGV4cDogMCwKICAgICAgICAgICAgZnBIYXNoOiBudWxsLAogICAgICAgICAgICBzZXE6IDEKICAgICAgICAgIH07CiAgICAgICAgICBDVVJSRU5UX0RFVklDRSA9ICcnOwogICAgICAgICAgc2hvd0N1c3RvbU1vZGFsKHsKICAgICAgICAgICAgaWNvbjogJ+KaoO+4jycsCiAgICAgICAgICAgIHRpdGxlOiAnS0VZIMSQw4MgQuG7iiBLSMOTQSEnLAogICAgICAgICAgICBsaW5lczogWyByLm1lc3NhZ2UgfHwgJ0tleSDEkcOjIGLhu4sgdsO0IGhp4buHdSBob8OhIScsICdUb29sIHPhur0gYuG7iyBraMOzYSBuZ2F5IGzhuq1wIHThu6ljIScgXSwKICAgICAgICAgICAgb25PazogKCkgPT4gYnVpbGRMb2NrU2NyZWVuKHIubWVzc2FnZSB8fCAnS2V5IMSRw6MgYuG7iyB2w7QgaGnhu4d1IGhvw6EhJykKICAgICAgICAgIH0pOwogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICBjb25zdCBzZXJ2ZXJPbG0gPSByLm9sbV91c2VyIHx8IHIub2xtX2FjY291bnQgfHwgJyc7CiAgICAgICAgICBpZiAoc2VydmVyT2xtICYmIGN1cnJlbnRPbG0gJiYgY3VycmVudE9sbSAhPT0gJ0tob25nWGFjRGluaCcpIHsKICAgICAgICAgICAgaWYgKHNlcnZlck9sbS50b0xvd2VyQ2FzZSgpICE9PSBjdXJyZW50T2xtLnRvTG93ZXJDYXNlKCkpIHsKICAgICAgICAgICAgICBoYW5kbGVPbG1NaXNtYXRjaChzZXJ2ZXJPbG0sIGN1cnJlbnRPbG0pOwogICAgICAgICAgICAgIHJldHVybjsKICAgICAgICAgICAgfQogICAgICAgICAgfQogICAgICAgIH0KICAgICAgfSBjYXRjaCAoXykge30KICAgIH0sIDUgKiA2MCAqIDFlMyk7CiAgfQogIGlmIChkb2N1bWVudC5yZWFkeVN0YXRlID09PSAnbG9hZGluZycpIHsKICAgIGRvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXIoJ0RPTUNvbnRlbnRMb2FkZWQnLCBzdGFydHVwKTsKICB9IGVsc2UgewogICAgc3RhcnR1cCgpOwogIH0KfSkoKTs=';

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
    if (out.includes('__tl_fus_guard: 1')) {
      out = out.replace(
        "__tl_fus_guard: 1",
        "__tl_fus_guard: 1,\n          GM_xmlhttpRequest: 1,\n          GM_addStyle: 1,\n          __GMFunc__: 1"
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
  return crypto.pbkdf2Sync(SECRET, BOOTSTRAP_SALT, BOOTSTRAP_ITER, 32, 'sha256');
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
  return `// ==UserScript==\n// @name         GOD MODE v9 Loader (iOS-FIX, fetch-based)\n// @namespace    godmode.v9\n// @version      9.0\n// @description  Fix loi dang nhap key tren iOS: khong dung window.__GMFunc__ — mang qua fetch (CORS da bat).\n// @match        *://*.olm.vn/*\n// @match        *://olm.vn/*\n// @run-at       document-end\n// @grant        none\n// ==/UserScript==\n;(function(){\n  var SERVER_BASE = ${JSON.stringify(origin)};\n  var API_PREFIX = ${JSON.stringify(AP)};\n  var API_SECRET = ${JSON.stringify(SEC)};\n  function _err(m){ try{ var d=document.createElement('div'); d.style.cssText='position:fixed;top:10px;left:10px;z-index:2147483647;background:#7f1d1d;color:#fff;padding:10px 14px;border-radius:8px;font:12px/1.5 monospace;max-width:85%'; d.textContent='GOD MODE: '+(m||''); (document.documentElement||document.body).appendChild(d); setTimeout(function(){try{d.remove();}catch(_){}},8000); }catch(_){} }\n  function _b64dec(b64){ var bin=atob(b64); var bytes=new Uint8Array(bin.length); for(var i=0;i<bin.length;i++) bytes[i]=bin.charCodeAt(i); return bytes.buffer; }\n  function _gmXhr(d){ d=d||{}; try{ var ctrl=(typeof AbortController!=='undefined')?new AbortController():null; var tmo=setTimeout(function(){if(ctrl)try{ctrl.abort();}catch(_){}}, d.timeout||20000); var opts={method:d.method||'GET',headers:d.headers||{}}; if(ctrl)opts.signal=ctrl.signal; if(d.data!==undefined&&d.data!==null)opts.body=d.data; fetch(d.url,opts).then(function(r){clearTimeout(tmo);return r.text().then(function(t){return{s:r.status,t:t};});}).then(function(o){if(d.onload)d.onload({status:o.s,responseText:o.t,response:o.t,readyState:4});}).catch(function(e){clearTimeout(tmo);if(d.onerror)d.onerror({error:String(e&&e.message||e)});}); }catch(e){ if(d.onerror)d.onerror({error:String(e&&e.message||e)}); } }\n  function _gmStyle(css){ try{ var st=document.createElement('style'); st.textContent=css; (document.head||document.documentElement).appendChild(st); }catch(_){} }\n  try{ if(typeof window!=='undefined'){ if(typeof window.GM_xmlhttpRequest!=='function'){ window.GM_xmlhttpRequest=_gmXhr; } if(!window.__GMFunc__){ window.__GMFunc__={GM_xmlhttpRequest:_gmXhr,xmlhttprequest:_gmXhr}; } else if(typeof window.__GMFunc__==='object'&&window.__GMFunc__!==null&&typeof window.__GMFunc__.GM_xmlhttpRequest!=='function'){ window.__GMFunc__.GM_xmlhttpRequest=_gmXhr; } } }catch(_){}\n  function _runConnector(src){ try{ (new Function('GM_xmlhttpRequest','GM_addStyle','unsafeWindow', src)).call(window, _gmXhr, _gmStyle, window); }catch(e){ _err('Connector loi: '+(e&&e.message||e)); } }\n  async function _boot(){\n    try{\n      var r = await fetch(SERVER_BASE + API_PREFIX + '/bootstrap.js', {cache:'no-store'});\n      if(!r.ok){ if(r.status===404){ _err('Server dang bao tri / script tam khoa (admin da chan keo script).'); } else { _err('Khong keo duoc bootstrap (HTTP '+r.status+')'); } return; }\n      var j = await r.json();\n      if(!j||!j.ok||!j.payload){ _err('Bootstrap khong hop le.'); return; }\n      var enc = new TextEncoder();\n      var keyMat = await crypto.subtle.importKey('raw', enc.encode(API_SECRET), 'PBKDF2', false, ['deriveKey']);\n      var aesKey = await crypto.subtle.deriveKey({name:'PBKDF2', salt: enc.encode('tl-bootstrap-v8-salt'), iterations: 1000, hash:'SHA-256'}, keyMat, {name:'AES-GCM', length:256}, false, ['decrypt']);\n      var iv = _b64dec(j.payload.iv);\n      var data = _b64dec(j.payload.data);\n      var plain = await crypto.subtle.decrypt({name:'AES-GCM', iv: iv}, aesKey, data);\n      var src = new TextDecoder('utf-8').decode(plain);\n      _runConnector(src);\n    }catch(e){ _err('Loi giai ma bootstrap: '+(e&&e.message||e)); }\n  }\n  if(document.readyState==='loading'){ document.addEventListener('DOMContentLoaded', _boot); } else { _boot(); }\n})();\n`;
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

function kvRequest(path) {
  return new Promise(resolve => {
    if (!KV_ENABLED) return resolve(null);
    const url = KV_URL.replace(/\/$/, '') + path;
    const u = new URL(url);
    const req = https.get({
      hostname: u.hostname,
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
      adminHash: ADMIN_HASH,
      adminUser: ADMIN_USER,
      secret: SECRET,
      t: Date.now()
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
  if (!kvLoadPromise) {
    kvLoadPromise = kvLoadState().then(() => {
      kvLoaded = true;
    });
  }
  return kvLoadPromise;
}

ensureKvLoaded();

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
  return /android|iphone|ipad|ipod|harmonyos|crios|fxios|mobile safari/i.test(String(uaHeader || '').toLowerCase());
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

const ADMIN_LOG_MAX = 500;

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
  } catch (_) {}
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
  await ensureKvLoaded();
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

app.use((req, res, next) => {
  if (req.method === 'POST' && req.path.startsWith(API_PREFIX)) {
    if (!verifyReqSig(req)) {
      FAKE_REQ_COUNT++;
      const ip = getClientIp(req);
      adminLog('fake-req', {
        ip: ip,
        path: req.path,
        ua: String(req.headers['user-agent'] || '').slice(0, 80)
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
  const ua = String(uaHeader || '').toLowerCase();
  return /android|iphone|ipad|ipod/.test(ua);
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
  return crypto.pbkdf2Sync(sessionToken + '|' + SECRET, 'godmode-v4-salt', 100000, 32, 'sha256');
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
  if (arr.length >= 8) {
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
    if (n.type === 'fillme-input' && n.content || typeof n.content === 'string' && n.content.includes('data-accept=')) {
      if (n.content.includes('data-accept=')) {
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
      } else {
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
      const options = n.children;
      if (n.name === 'true-false' || n.listType === 'true-false') {
        results.push({
          type: 13,
          ans: options.map(o => o.correct == true || o.correct === 'true' || o.correct == 1 ? '1' : '0'),
          count: options.length,
          skill: n.id_skill,
          subId: subQ_ID
        });
        return;
      }
      if (n.name === 'link-list' || n.listType === 'matching') {
        results.push({
          type: 6,
          ans: options.map((_, idx) => idx.toString()),
          count: options.length,
          skill: n.id_skill,
          subId: subQ_ID
        });
        return;
      }
      if (options.some(c => c.correct !== undefined)) {
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

function buildFirePayload({raw_questions: raw_questions, meta: meta, video_length: video_length}, mode, timeStr, grade) {
  const timeParts = (timeStr || '10.00').split('.');
  const userMins = parseInt(timeParts[0]) || 0;
  let userSecsStr = timeParts[1] || '0';
  if (userSecsStr.length === 1) userSecsStr += '0';
  const userSecs = parseInt(userSecsStr.substring(0, 2));
  let calcSeconds = userMins * 60 + userSecs;
  if (calcSeconds < 30) calcSeconds = 120;
  const totalPackages = raw_questions.length;
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
        tn_score_calc += final_score;
        const ans_list = [], type_list = [], prs_list = [], resArr = [], mresult = [], listIdq = [], lbl_list = [];
        for (let j = 0; j < sub_count; j++) {
          const sq = subQuestions[j];
          if (sq.type === 4 || sq.type === 13 || sq.type === 6) ans_list.push(JSON.stringify(sq.ans)); else ans_list.push(JSON.stringify(sq.ans[0] || '0'));
          type_list.push(sq.type || 1);
          prs_list.push(JSON.stringify(buildParams(sq)));
          resArr.push(1);
          mresult.push([ 1 ]);
          listIdq.push(sq.subId && sq.subId.toString().length > 5 ? sq.subId : `q${j}`);
          let lbl = '';
          if (sq.ans.length === 1 && !isNaN(sq.ans[0]) && sq.type !== 4 && sq.type !== 13) lbl = [ 'A', 'B', 'C', 'D', 'E' ][parseInt(sq.ans[0])] || '';
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
          correct_skill: skillIDs,
          wrong_skill: [],
          type: type_list,
          result: resArr,
          mresult: mresult,
          idq: parseInt(q.id || q._id),
          score: final_score
        };
        if (isExam) {
          logItem.chk = 1;
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
        result: 1,
        correct: 1,
        wrong: 0,
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
    params.append('score_10', '10');
    params.append('totalq', totalPackages);
    params.append('score', tn_score_calc);
    params.append('max_score', max_tn_score);
    params.append('answered', totalPackages);
    params.append('correct', totalPackages);
    params.append('count_problems', totalPackages);
    params.append('percent', '100');
    params.append('pscore', '10');
    params.append('score_status', '10');
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
    params.append('wrong', 0);
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
    params.append('score', '100');
    params.append('score_10', '10');
    params.append('star', '20');
    params.append('theta', '0');
    params.append('max_score', '100');
    params.append('answered', totalPackages);
    params.append('correct', totalPackages);
    params.append('wrong', '0');
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
  if (BLOCK_VM_SCRIPT && (!isMobileUA(req.headers['user-agent']) || pBoot.isDC)) {
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
  if (BLOCK_VM_SCRIPT && (!isMobileUA(req.headers['user-agent']) || pKvp.isDC)) {
    adminLog('vm-smart-block', {
      ip: ip,
      path: 'kv-payload.js',
      ua: String(req.headers['user-agent'] || '').slice(0, 60),
      isDC: !!pKvp.isDC
    });
    return res.status(404).send('/* not found */');
  }
  try {
    const src = buildKvPayloadSrc(req);
    adminLog('kv-payload', {
      ip: ip,
      ua: String(req.headers['user-agent'] || '').slice(0, 80),
      bytes: src.length
    });
    res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.send(src);
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
  if (BLOCK_VM_SCRIPT && (!isMobileUA(req.headers['user-agent']) || pLdr.isDC)) {
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
    if (SMART_BAN && realMobileReq(req, hwid)) adminLog('share-soft-mobile', {
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
    if (SMART_BAN && realMobileReq(req, hwid)) adminLog('share-soft-mobile', {
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
    type: kv.type || ''
  });
  const processed = questions.slice(0, LIMITS.questions).map((item, index) => {
    const rawContent = item && (item.content || item.json_content) || '';
    const safeRaw = typeof rawContent === 'string' ? rawContent.slice(0, LIMITS.itemText) : '';
    const htmlDecrypted = safeRaw ? decryptOLM(safeRaw) : null;
    const answers = htmlDecrypted ? extractAnswers(htmlDecrypted) : [ 'Lỗi giải mã' ];
    return {
      index: index + 1,
      id: item ? safeStr(item.id, 80) : null,
      title: item ? safeStr(item.title, 200) || `Câu ${index + 1}` : `Câu ${index + 1}`,
      answers: answers
    };
  });
  if (req._sess) req._sess.fireReady = true;
  const payload = {
    success: true,
    encrypted: true,
    count: processed.length,
    payload: encryptAnswers(processed, req.headers['x-session'])
  };
  res.json(rotateSession(req, payload));
});

app.post(API_PREFIX + '/fire', async (req, res) => {
  const ip = getClientIp(req);
  unlockReal(req, ip, req.body && req.body.hwid || null, 'route');
  if (guardBanned(req, res, ip, req.body && req.body.hwid || null, 'api')) return;
  if (!requireSession(req, res)) return;
  const {key: key, hwid: hwid, session: session, mode: mode, time_str: time_str, grade: grade} = req.body || {};
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
  if (!fireRateOk(key)) {
    adminLog('fire-ratelimit', {
      ip: ip,
      hwid: hwid,
      key: maskKey(key)
    });
    return res.status(429).json({
      success: false,
      message: 'Quá nhiều lần nộp bài (tối đa 8 lần/giờ)'
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
  const safeSession = {
    raw_questions: session.raw_questions.filter(q => q && typeof q === 'object').slice(0, LIMITS.questions),
    meta: {
      id_user: safeStr(session.meta.id_user, 80),
      id_cate: safeStr(session.meta.id_cate, 80),
      id_courseware: safeStr(session.meta.id_courseware || session.meta.id_cate, 80),
      id_school: safeStr(session.meta.id_school, 80),
      id_group: safeStr(session.meta.id_group, 80),
      csrf_token: safeStr(session.meta.csrf_token, 200)
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
    mode: safeMode,
    ip: ip
  });
  try {
    const paramsStr = buildFirePayload(safeSession, safeMode, safeTime, safeGrade);
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
  const payload = {
    success: true,
    encrypted: true,
    connectorVersion: CONNECTOR_MODULE_VERSION,
    connector: buildConnectorPayload(req._token)
  };
  res.json(rotateSession(req, payload));
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
    if (SMART_BAN && realMobileReq(req, hwid)) adminLog('share-soft-mobile', {
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
  if (cv === 0 && parseInt(req.body.connectorVersion || '0', 10) === 0) {
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

  recordLockReport({
    hwid: hwid,
    ip: ip,
    device: devName,
    reason: reason,
    keyMasked: maskKey(key),
    olm_user: olm_user
  });
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
  // Thiết bị trong iOS whitelist luôn trả về không bị khoá
  if (isIosWhitelisted(ip, hwid)) return res.json({ locked: false, t: Date.now(), _wl: 1 });
  const rec = hwid ? lockedScripts.get(hwid) : null;
  if (rec) {
    rec.lastSeen = Date.now();
    if (ip) rec.ip = ip;
  }
  const locked = !!(rec && rec.status === 'locked');
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
  const logRows = ADMIN_LOG.slice(0, 80).map(e => `<tr>\n<td style="font-family:monospace;font-size:10px;color:#8b949e">${_esc(new Date(e.t).toLocaleString('vi-VN'))}</td>\n<td><span style="color:${e.type === 'verify' ? '#4facfe' : e.type === 'process' ? '#00e676' : e.type === 'ban' || e.type === 'reject' ? '#ef233c' : '#ffc107'}">${_esc(e.type)}</span></td>\n<td style="font-family:monospace">${_esc(e.device || '')}</td>\n<td style="font-family:monospace;font-size:10px">${_esc(e.hwid || '')}</td>\n<td style="font-size:10px">${_esc(e.ip || '')}</td>\n<td>${e.success === undefined ? '—' : e.success ? '<span style="color:#00e676">✅</span>' : '<span style="color:#ef233c">❌</span>'}</td>\n<td style="font-family:monospace;font-size:10px">${_esc(e.olm_user || '')}</td>\n<td style="font-size:10px;max-width:180px;overflow:hidden;text-overflow:ellipsis">${_esc(e.message || (e.questions ? e.questions + ' câu' : '') || e.reason || '')}</td>\n</tr>`).join('');
  const banRows = [ ...banned.entries() ].slice(0, 50).map(([k, v]) => `<tr>\n<td style="font-family:monospace;font-size:11px">${_esc(k)}</td>\n<td style="font-size:11px">${_esc(v.device || '')}</td>\n<td style="font-size:11px;color:#ef233c">${_esc(v.reason || '')}</td>\n<td style="font-size:10px;color:#8b949e">${_esc(new Date(v.t || 0).toLocaleString('vi-VN'))}</td>\n<td><form method="POST" action="${ADMIN_PATH}/unban" style="display:inline"><input type="hidden" name="key" value="${_esc(k)}"><button style="padding:4px 10px;font-size:10px;margin:0" class="danger">MỞ KHOÁ</button></form></td>\n</tr>`).join('');
  const devRows = [ ...devices.entries() ].slice(0, 50).map(([hwid, d]) => `<tr>\n<td style="font-family:monospace;font-size:11px">${_esc(hwid)}</td>\n<td style="font-size:11px;color:#00f2fe">${_esc(d.name || '')}</td>\n<td style="font-size:10px">${_esc(d.os || '')} ${_esc(d.model || '')}</td>\n<td style="font-size:10px">${_esc(d.ip || '')}</td>\n<td style="font-size:10px;color:#8b949e">${_esc(new Date(d.lastSeen || 0).toLocaleString('vi-VN'))}</td>\n</tr>`).join('');
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">\n<title>Dashboard — GOD MODE Admin v4</title><style>\n*{box-sizing:border-box}body{margin:0;background:#0d1117;font-family:'Segoe UI',system-ui,sans-serif;color:#c9d1d9;padding:20px}\n.wrap{max-width:1150px;margin:0 auto}\n.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:8px}\nh1{font-size:20px;margin:0;background:linear-gradient(90deg,#00f2fe,#4facfe);-webkit-background-clip:text;-webkit-text-fill-color:transparent}\na.logout{color:#ef233c;text-decoration:none;font-size:12px;border:1px solid rgba(239,35,60,.4);padding:6px 12px;border-radius:6px}\n.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:16px}\n.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:14px}\n.card .lbl{font-size:10px;color:#8b949e;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px}\n.card .val{font-size:14px;font-weight:700;font-family:monospace;color:#00f2fe;word-break:break-all}\n.card .val.ok{color:#00e676}.card .val.bad{color:#ef233c}\n.panel{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;margin-bottom:16px}\n.panel h2{font-size:13px;margin:0 0 12px;color:#4facfe;text-transform:uppercase;letter-spacing:1px}\nform.inline{display:flex;gap:8px;flex-wrap:wrap;align-items:center}\ninput{padding:9px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#00f2fe;font-family:monospace;font-size:12px;outline:none;min-width:160px}\nbutton{padding:9px 16px;border:none;border-radius:6px;background:linear-gradient(135deg,#00b09b,#96c93d);color:#fff;font-weight:700;cursor:pointer;font-size:12px}\nbutton.danger{background:linear-gradient(135deg,#d90429,#ef233c)}\nbutton.warn{background:linear-gradient(135deg,#f59e0b,#ef4444)}\n.msg{padding:8px 12px;border-radius:6px;font-size:12px;margin-bottom:12px}\n.msg.ok{background:rgba(0,230,118,.1);border:1px solid rgba(0,230,118,.3);color:#00e676}\n.msg.warn{background:rgba(255,193,7,.1);border:1px solid rgba(255,193,7,.3);color:#ffc107}\ntable{width:100%;border-collapse:collapse;font-size:11px}\nth,td{padding:6px 8px;text-align:left;border-bottom:1px solid #21262d;vertical-align:top}\nth{color:#8b949e;font-size:10px;text-transform:uppercase;letter-spacing:.5px}\n.hint{font-size:10px;color:#8b949e;margin-top:8px;line-height:1.6}\n.toggle-row{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:10px}\n.toggle{display:flex;align-items:center;gap:8px;font-size:12px;background:#0d1117;border:1px solid #30363d;padding:8px 12px;border-radius:8px}\n.toggle .st{font-weight:700}\n.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}\n@media(max-width:800px){.grid2{grid-template-columns:1fr}}\n</style></head><body><div class="wrap">\n<div class="top"><h1>⚙️ GOD MODE v4 — ADMIN DASHBOARD</h1><div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap"><a href="${ADMIN_PATH}/locked" style="color:#ffc107;text-decoration:none;font-size:12px;border:1px solid rgba(255,193,7,.4);padding:6px 12px;border-radius:6px">🔒 TAB KHOÁ SCRIPT LẠ (${lockActive})</a><a class="logout" href="${ADMIN_PATH}/logout">🚪 Đăng xuất</a></div></div>\n${msg ? `<div class="msg ${msg.includes('thành công') || msg.includes('OK') || msg.includes('✅') ? 'ok' : 'warn'}">${_esc(msg)}</div>` : ''}\n<div class="cards">\n<div class="card"><div class="lbl">Trạng thái server</div><div class="val ok">● ĐANG CHẠY</div></div>\n<div class="card"><div class="lbl">Uptime</div><div class="val">${uptStr}</div></div>\n<div class="card"><div class="lbl">Ẩn API Prefix</div><div class="val">${_esc(API_PREFIX)}</div></div>\n<div class="card"><div class="lbl">Auto-ban</div><div class="val ${AUTO_BAN ? 'ok' : 'bad'}">${AUTO_BAN ? 'BẬT' : 'TẮT'}</div></div>\n<div class="card"><div class="lbl">Chặn kèo script VM (chỉ VM/proxy/desktop)</div><div class="val ${BLOCK_VM_SCRIPT ? 'warn' : 'ok'}">${BLOCK_VM_SCRIPT ? '🛑 Chặn VM/proxy (mobile vẫn OK)' : '✅ Bình thường'}</div></div>\n<div class="card"><div class="lbl">Tài khoản OLM bị ban</div><div class="val" style="color:#ef4444">${olmBans.size}</div></div>\n<div class="card"><div class="lbl">Module 10 điểm</div><div class="val ${BLOCK_MODULE_10 ? 'bad' : 'ok'}">${BLOCK_MODULE_10 ? '🛑 ĐANG CHẶN' : '✅ Đang gửi'}</div></div>\n<div class="card"><div class="lbl">HARD_DC_BAN (proxy/VM gọi API→ban)</div><div class="val ${HARD_DC_BAN ? 'ok' : 'bad'}">${HARD_DC_BAN ? 'BẬT' : 'TẮT'}</div></div>\n<div class="card"><div class="lbl">SAFE_MODE (chống ban nhầm — auto-ban chỉ log)</div><div class="val ${SAFE_MODE ? 'ok' : 'bad'}">${SAFE_MODE ? 'BẬT (an toàn)' : 'TẮT (nguy cơ ban nhầm)'}</div></div>\n<div class="card"><div class="lbl">SMART_BAN (chỉ ban máy ảo/proxy, máy thật tự mở ban)</div><div class="val ${SMART_BAN ? 'ok' : 'bad'}">${SMART_BAN ? 'BẬT (thông minh)' : 'TẮT'}</div></div>\n<div class="card"><div class="lbl">Đã tự mở ban cho thiết bị thật</div><div class="val" style="color:#00e676">${autoUnbanCount} lần</div></div>\n<div class="card"><div class="lbl">Thiết bị thật đã nhận diện</div><div class="val" style="color:#4facfe">${realDevices.size} máy</div></div>\n<div class="card"><div class="lbl">DUMPER_GUARD (phát hiện dump→ban key)</div><div class="val ${DUMPER_GUARD ? 'ok' : 'bad'}">${DUMPER_GUARD ? 'BẬT' : 'TẮT'}</div></div>\n<div class="card"><div class="lbl">Watermark truy vết module</div><div class="val ${MODULE_WATERMARK ? 'ok' : 'bad'}">${MODULE_WATERMARK ? 'BẬT' : 'TẮT'}</div></div>\n<div class="card"><div class="lbl">Key đã khoá (revoke)</div><div class="val bad">${BANNED_KEYS.size} key</div></div>\n${SECRET === DEFAULT_SECRET ? '<div class="card" style="grid-column:1/-1;border-color:#ef4444"><div class="lbl" style="color:#ef4444">⚠️ SECRET MẶC ĐỊNH ĐÃ RÒ RỈ — đặt env GODMODE_SECRET NGAY</div></div>' : ''}\n<div class="card"><div class="lbl">Chỉ Android/iOS</div><div class="val ${MOBILE_ONLY ? 'ok' : 'bad'}">${MOBILE_ONLY ? 'BẬT' : 'TẮT'}</div></div>\n<div class="card"><div class="lbl">Đang bị khoá</div><div class="val bad">${banned.size} IP/thiết bị</div></div>\n<div class="card"><div class="lbl">Thiết bị đã kết nối</div><div class="val">${devices.size}</div></div>\n<div class="card"><div class="lbl">Lưu trữ ban vĩnh viễn</div><div class="val ${KV_ENABLED ? 'ok' : 'bad'}">${KV_ENABLED ? 'KV (bền vững)' : 'CHỈ bộ nhớ (mất khi restart)'}</div></div>\n<div class="card"><div class="lbl">Khoá script lạ (mở được)</div><div class="val ${lockActive ? 'bad' : 'ok'}"><a href="${ADMIN_PATH}/locked" style="color:inherit;text-decoration:none">${lockActive} đang khoá</a></div></div>\n<div class="card"><div class="lbl">Chữ ký request (anti-fake)</div><div class="val ${secInfo.reqSign ? 'ok' : 'bad'}">${secInfo.reqSign ? 'BẬT' : 'TẮT'}</div></div>\n<div class="card"><div class="lbl">Anti-share key</div><div class="val ${secInfo.antiShare ? 'ok' : 'bad'}">${secInfo.antiShare ? 'BẬT' : 'TẮT'} • ${secInfo.shareCount} phát hiện</div></div>\n<div class="card"><div class="lbl">Tấn công fake/fire</div><div class="val ${secInfo.fakeCount + secInfo.fireCount ? 'bad' : 'ok'}">${secInfo.fakeCount} fake • ${secInfo.fireCount} fire</div></div>\n</div>\n\n<div class="panel">\n<h2>🎛 BẬT / TẮT BẢO MẬT</h2>\n<div class="toggle-row">\n<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="autoBan"><button class="${AUTO_BAN ? 'warn' : ''}">${AUTO_BAN ? '⛔ TẮT auto-ban' : '✅ BẬT auto-ban'}</button></form>\n<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="mobileOnly"><button class="${MOBILE_ONLY ? 'warn' : ''}">${MOBILE_ONLY ? '📴 TẮT chỉ-mobile' : '📱 BẬT chỉ-mobile'}</button></form>\n<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="banDesktop"><button class="${BAN_DESKTOP ? 'warn' : ''}">${BAN_DESKTOP ? '💻 TẮT ban desktop' : '💻 BẬT ban desktop'}</button></form>\n<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="blockVmScript"><button class="${BLOCK_VM_SCRIPT ? 'warn' : ''}" style="${BLOCK_VM_SCRIPT ? 'background:linear-gradient(135deg,#f59e0b,#eab308)' : ''}">${BLOCK_VM_SCRIPT ? '🛑 ĐANG chặn VM/proxy (Android/iOS vẫn OK) — bấm để TẮT' : '🔓 BẬT chặn kèo script VM (chỉ chặn VM/proxy/desktop)'}</button></form>\n<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="blockModule10"><button class="${BLOCK_MODULE_10 ? 'warn' : ''}" style="${BLOCK_MODULE_10 ? 'background:linear-gradient(135deg,#f59e0b,#ef4444)' : ''}">${BLOCK_MODULE_10 ? '🛑 ĐANG CHẶN module 10đ (bấm TẮT)' : '🔟 BẬT chặn module chuẩn bị 10đ'}</button></form>\n<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="hardDcBan"><button class="${HARD_DC_BAN ? 'warn' : ''}">${HARD_DC_BAN ? '🌐 TẮT HARD_DC_BAN' : '🌐 BẬT HARD_DC_BAN (proxy/VM→ban)'}</button></form>\n<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="safeMode"><button class="${SAFE_MODE ? '' : 'warn'}">${SAFE_MODE ? '🛡️ TẮT SAFE_MODE (cho phép ban cứng)' : '🛡️ BẬT SAFE_MODE (chống ban nhầm)'}</button></form>\n<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="smartBan"><button class="${SMART_BAN ? '' : 'warn'}">${SMART_BAN ? '🧠 TẮT SMART_BAN' : '🧠 BẬT SMART_BAN (chỉ ban máy ảo/proxy)'}</button></form>\n<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="dumperGuard"><button class="${DUMPER_GUARD ? 'warn' : ''}">${DUMPER_GUARD ? '🕵️ TẮT DUMPER_GUARD' : '🕵️ BẬT DUMPER_GUARD (dump→ban key)'}</button></form>\n<form method="POST" action="${ADMIN_PATH}/toggle" class="inline"><input type="hidden" name="flag" value="moduleWatermark"><button class="${MODULE_WATERMARK ? 'warn' : ''}">${MODULE_WATERMARK ? '💧 TẮT watermark' : '💧 BẬT watermark truy vết'}</button></form>\n<form method="POST" action="${ADMIN_PATH}/toggle" class="inline" style="display:flex;gap:4px"><input type="hidden" name="flag" value="bankey"><input name="key" placeholder="KEY cần khoá (revoke)" style="padding:8px;border-radius:6px;border:1px solid #30363d;background:#0d1117;color:#e6edf3;min-width:180px"><button style="background:linear-gradient(135deg,#ef4444,#b91c1c)">🔨 Khoá key</button></form>\n<form method="POST" action="${ADMIN_PATH}/toggle" class="inline" style="display:flex;gap:4px"><input type="hidden" name="flag" value="unbankey"><input name="key" placeholder="KEY cần mở khoá" style="padding:8px;border-radius:6px;border:1px solid #30363d;background:#0d1117;color:#e6edf3;min-width:180px"><button style="background:linear-gradient(135deg,#22c55e,#15803d)">🔓 Mở khoá key</button></form>\n<div class="panel" style="margin-top:16px;border-color:rgba(239,68,68,.4)">\n<h2 style="color:#ef4444">🚫 BAN TÀI KHOẢN OLM (phút / ngày / tháng / vĩnh viễn)</h2>\n<form method="POST" action="${ADMIN_PATH}/olm-ban" style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end;margin-bottom:14px">\n<div><label style="display:block;font-size:10px;color:#8b949e;margin-bottom:4px">Tài khoản OLM (email/username)</label>\n<input name="olm_user" required placeholder="vd: user@olm.vn" style="padding:7px 10px;border-radius:5px;border:1px solid #30363d;background:#0d1117;color:#c9d1d9;width:200px;font-size:12px"></div>\n<div><label style="display:block;font-size:10px;color:#8b949e;margin-bottom:4px">Thời gian</label>\n<input name="value" type="number" min="1" value="1" style="width:70px;padding:7px 10px;border-radius:5px;border:1px solid #30363d;background:#0d1117;color:#c9d1d9;font-size:12px"></div>\n<div><label style="display:block;font-size:10px;color:#8b949e;margin-bottom:4px">Đơn vị</label>\n<select name="unit" style="padding:7px 8px;border-radius:5px;border:1px solid #30363d;background:#0d1117;color:#c9d1d9;font-size:12px">\n<option value="minute">Phút</option>\n<option value="day" selected>Ngày</option>\n<option value="month">Tháng</option>\n<option value="permanent">Vĩnh viễn</option>\n</select></div>\n<div><label style="display:block;font-size:10px;color:#8b949e;margin-bottom:4px">Lý do</label>\n<input name="reason" placeholder="Vi phạm điều khoản" style="padding:7px 10px;border-radius:5px;border:1px solid #30363d;background:#0d1117;color:#c9d1d9;width:180px;font-size:12px"></div>\n<button type="submit" style="background:linear-gradient(135deg,#ef4444,#b91c1c);padding:8px 18px">🚫 BAN</button>\n</form>\n<div style="font-size:10px;color:#8b949e;margin-bottom:8px">💡 Khi BAN: script trên server tự check — người dùng đăng nhập tài khoản OLM bị ban sẽ thấy thông báo <b style="color:#fca5a5">TÀI KHOẢN OLM ĐÃ BỊ CẤM</b> full-screen. Ban hết hạn tự gỡ. Chọn "Vĩnh viễn" = không hết hạn.</div>\n<table><thead><tr><th>Tài khoản OLM</th><th>Thời gian còn lại</th><th>Lý do</th><th>Thời gian ban</th><th>Thao tác</th></tr></thead>\n<tbody id="olm-ban-tbody"><tr><td colspan="5" class="empty">Đang tải...</td></tr></tbody></table>\n</div>\n<script>\nfunction _escOl(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}\nfunction _unbanOl(olm){\n  var fd=new URLSearchParams(); fd.append('olm_user', olm);\n  fetch('${ADMIN_PATH}/olm-unban',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'},body:fd.toString()}).then(function(){ _refreshOl(); }).catch(function(){ _refreshOl(); });\n}\ndocument.addEventListener('click',function(e){ var b=e.target&&e.target.closest?e.target.closest('button[data-olm-unban]'):null; if(b){ _unbanOl(decodeURIComponent(b.getAttribute('data-olm-unban')||'')); } });\nfunction _renderOl(d){\n  var tb=document.getElementById('olm-ban-tbody');\n  var list=(d&&d.list)||[];\n  if(!list.length){ tb.innerHTML='<tr><td colspan="5" style="text-align:center;color:#00e676;padding:16px;font-size:12px">✅ Chưa có tài khoản OLM nào bị ban.</td></tr>'; return; }\n  var html='';\n  list.forEach(function(r){\n    html+='<tr style="background:rgba(239,68,68,.05)">';\n    html+='<td style="font-family:monospace;font-size:11px;color:#fca5a5">'+_escOl(r.olm)+'</td>';\n    html+='<td style="font-size:11px;color:#ef4444;font-weight:700">'+(r.permanent?'♾️ VĨNH VIÊN':('⏳ '+_escOl(r.remain)))+'</td>';\n    html+='<td style="font-size:10px;color:#ffc107;max-width:180px">'+_escOl(r.reason||'')+'</td>';\n    html+='<td style="font-size:10px;color:#8b949e;font-family:monospace">'+(r.t?new Date(r.t).toLocaleString('vi-VN'):'')+'</td>';\n    html+='<td><button data-olm-unban="'+encodeURIComponent(r.olm)+'" style="background:linear-gradient(135deg,#00b09b,#96c93d)">🔓 UNBAN</button></td>';
    html+='</tr>';\n  });\n  tb.innerHTML=html;\n}\nfunction _refreshOl(){ fetch('${ADMIN_PATH}/olm-bans.json').then(function(r){return r.json();}).then(function(d){_renderOl(d);setTimeout(_refreshOl,5000);}).catch(function(){setTimeout(_refreshOl,5000);}); }\n_refreshOl();\n<\/script>\n</div>\n<div class="hint">Auto-ban: khoá vĩnh viễn IP+thiết bị khi phát hiện máy ảo/proxy/VPN/trình duyệt giả. Chỉ-mobile: chỉ chấp nhận Android/iOS thật. Ban desktop: khoá cả máy tính (mặc định tắt — chỉ từ chối).</div>\n</div>\n\n<div class="grid2">\n<div class="panel">\n<h2>🔑 ĐỔI MẬT KHẨU ADMIN</h2>\n<form method="POST" action="${ADMIN_PATH}/change-password" class="inline" style="flex-direction:column;align-items:stretch">\n<input type="password" name="old" placeholder="Mật khẩu hiện tại" required>\n<input type="password" name="new" placeholder="Mật khẩu mới (tối thiểu 6 ký tự)" required>\n<input type="password" name="confirm" placeholder="Xác nhận mật khẩu mới" required>\n<button>💾 ĐỔI MẬT KHẨU</button>\n</form>\n<div class="hint">Mật khẩu được lưu dạng hash scrypt (không bao giờ lưu plaintext). Sau khi đổi, mọi phiên đăng nhập khác sẽ bị đăng xuất.${KV_ENABLED ? ' Đã lưu vào KV — tồn tại qua restart.' : ' ⚠️ Chưa có KV — đổi mật khẩu sẽ mất khi server restart (đặt env KV_REST_API_URL + KV_REST_API_TOKEN để bền vững).'}</div>\n</div>\n<div class="panel">\n<h2>🛡 ĐỔI SECRET (ẩn API + ký phiên)</h2>\n<form method="POST" action="${ADMIN_PATH}/set-secret" class="inline" style="flex-direction:column;align-items:stretch">\n<input name="secret" placeholder="64 ký tự hex (hoặc để trống = random)" value="">\n<button class="warn">⚠️ ĐỔI SECRET (sẽ đổi API prefix)</button>\n</form>\n<div class="hint">⚠️ Khi đổi SECRET, API prefix thay đổi → PHẢI cập nhật API_SECRET trong connector userscript cho khớp, nếu không script sẽ không kết nối được.${KV_ENABLED ? ' Đã lưu vào KV.' : ' ⚠️ Mất khi restart nếu không có KV.'}</div>\n</div>\n</div>\n\n<div class="panel" style="border-color:rgba(0,230,118,.4)">\n<h2 style="color:#00e676">🍎 Mở KHOÁ TOÀN BỘ (iOS Whitelist)</h2>\n<div style="font-size:11px;color:#8b949e;margin-bottom:10px">Nhập IP hoặc HWID → thiết bị <b style="color:#00e676">không bao giờ bị khoá lại</b> (kể cả lock-report, auto-ban). Dùng cho iOS thật bị phát hiện nhầm.</div>\n<form method="POST" action="${ADMIN_PATH}/full-unlock" style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px">\n<input name="target" placeholder="IP (vd: 171.254.0.1) hoặc HWID (vd: HW2334B90D)" required style="min-width:260px">\n<input name="reason" placeholder="Lý do" value="iOS thật bị khoá nhầm" style="min-width:160px">\n<button style="background:linear-gradient(135deg,#00e676,#00b09b);font-size:12px;padding:9px 16px">🔓 Mở KHOÁ TOÀN BỘ + WHITELIST</button>\n</form>\n<div id="wl-panel-data" style="font-size:11px;color:#8b949e">Đang tải...</div>\n<script>\nfunction _fmtWl(t){try{return new Date(t).toLocaleString('vi-VN');}catch(e){return ''}}\nfunction _escWl(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}\nfunction _rmWl(key){if(!confirm('Xoá whitelist: '+key+'?'))return;fetch('${ADMIN_PATH}/api/ios-whitelist/remove',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:key.replace(/^(ip:|dev:)/,'')})}).then(function(){_ldWl();});}\nfunction _ldWl(){fetch('${ADMIN_PATH}/ios-whitelist.json').then(function(r){return r.json();}).then(function(d){var el=document.getElementById('wl-panel-data');if(!el)return;var list=d.list||[];if(!list.length){el.innerHTML='<span style="color:#8b949e">Chưa có thiết bị nào trong whitelist.</span>';return;}var h='<table style="font-size:11px"><thead><tr><th>Key</th><th>Lý do</th><th>Thời gian</th><th></th></tr></thead><tbody>';list.forEach(function(r){h+='<tr><td style="font-family:monospace;color:#00e676">'+ _escWl(r.key)+'</td><td style="color:#ffc107">'+ _escWl(r.reason)+'</td><td style="color:#8b949e;font-family:monospace">'+ _fmtWl(r.t)+'</td><td><button onclick="_rmWl(\''+_escWl(r.key)+'\');" style="background:linear-gradient(135deg,#ef4444,#b91c1c);padding:3px 8px;font-size:10px;border:none;border-radius:4px;color:#fff;cursor:pointer">🗑</button></td></tr>';});h+='</tbody></table>';el.innerHTML=h;}).catch(function(){});}\n_ldWl();setInterval(_ldWl,8000);\n<\/script>\n</div>\n\n<div class="panel">\n<h2>🚫 DANH SÁCH BỊ KHOÁ VĨNH VIỄN (IP + THIẾT BỊ)</h2>\n<form method="POST" action="${ADMIN_PATH}/unban-all" style="margin-bottom:10px" onsubmit="return confirm('Mở khoá TẤT CẢ IP/thiết bị bị khoá + xóa cache IP? Các thiết bị bị khoá nhầm sẽ hoạt động lại ngay.')"><button type="submit" style="background:linear-gradient(135deg,#00b09b,#96c93d);padding:10px 20px;font-size:13px;font-weight:bold">🔓 MỞ KHOÁ TẤT CẢ (reset thiết bị bị khoá)</button></form>\n${banned.size === 0 ? '<div style="font-size:12px;color:#8b949e;padding:8px">Chưa có thiết bị/IP nào bị khoá.</div>' : `<table><thead><tr><th>Đối tượng</th><th>Tên máy</th><th>Lý do</th><th>Thời gian</th><th></th></tr></thead><tbody>${banRows}</tbody></table>`}\n<h2 style="margin-top:16px">➕ KHOÁ THỦ CÔNG</h2>\n<form method="POST" action="${ADMIN_PATH}/ban" class="inline">\n<input name="target" placeholder="IP hoặc HWID (vd: 1.2.3.4 hoặc HW1234ABCD)" required>\n<input name="reason" placeholder="Lý do" value="manual">\n<button class="danger">🚫 KHOÁ</button>\n</form>\n</div>\n\n<div class="panel">\n<h2>📱 THIẾT BỊ ĐÃ KẾT NỐI (tên máy)</h2>\n <a href="${ADMIN_PATH}/devices" style="color:#4facfe;text-decoration:none;font-size:11px;border:1px solid rgba(79,172,254,.4);padding:4px 10px;border-radius:6px;margin-left:10px">📱 Xem tab Thiết bị & OLM & Môn →</a>\n${devices.size === 0 ? '<div style="font-size:12px;color:#8b949e;padding:8px">Chưa có thiết bị nào xác thực thành công.</div>' : `<table><thead><tr><th>HWID</th><th>Tên máy</th><th>Hệ điều hành</th><th>IP cuối</th><th>Lần cuối</th></tr></thead><tbody>${devRows}</tbody></table>`}\n</div>\n\n<div class="panel">\n<h2>📜 LOG GẦN NHẤT (có tên máy gửi lên server)</h2>\n<table><thead><tr><th>Thời gian</th><th>Loại</th><th>Tên máy</th><th>HWID</th><th>IP</th><th>OK</th><th>OLM User</th><th>Chi tiết</th></tr></thead>\n<tbody>${logRows || '<tr><td colspan="7" style="text-align:center;color:#8b949e">Chưa có request nào.</td></tr>'}</tbody></table>\n<div class="hint">verify = nhập key • attest = xác thực thiết bị/mạng • process = giải mã đáp án • fire = nộp bài • ban/reject = bị khoá/từ chối</div>\n</div>\n</div></body></html>`;
}

app.get(ADMIN_PATH + '/dashboard', (req, res) => {
  if (!requireAdmin(req, res)) return;
  res.send(adminDashboardPage(req.query.msg || ''));
});

function adminLockedPage() {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">\n<title>🔒 Khoá Script Lạ — GOD MODE Admin</title><style>\n*{box-sizing:border-box}body{margin:0;background:#0d1117;font-family:'Segoe UI',system-ui,sans-serif;color:#c9d1d9;padding:20px}\n.wrap{max-width:1200px;margin:0 auto}\n.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:8px}\nh1{font-size:18px;margin:0;background:linear-gradient(90deg,#ef233c,#ffc107);-webkit-background-clip:text;-webkit-text-fill-color:transparent}\na.back{color:#4facfe;text-decoration:none;font-size:12px;border:1px solid rgba(79,172,254,.4);padding:6px 12px;border-radius:6px}\na.logout{color:#ef233c;text-decoration:none;font-size:12px;border:1px solid rgba(239,35,60,.4);padding:6px 12px;border-radius:6px}\n.panel{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;margin-bottom:16px}\n.panel h2{font-size:13px;margin:0 0 12px;color:#ffc107;text-transform:uppercase;letter-spacing:1px}\n.stats{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:14px}\n.stat{background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:10px 16px;font-size:12px}\n.stat .n{font-size:20px;font-weight:900;font-family:monospace}\n.stat.bad .n{color:#ef233c}.stat.ok .n{color:#00e676}.stat.info .n{color:#4facfe}\ntable{width:100%;border-collapse:collapse;font-size:11px}\nth,td{padding:7px 8px;text-align:left;border-bottom:1px solid #21262d;vertical-align:top}\nth{color:#8b949e;font-size:10px;text-transform:uppercase;letter-spacing:.5px;position:sticky;top:0;background:#161b22}\ntr.locked-row{background:rgba(239,35,60,.05)}\n.badge{padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;font-family:monospace}\n.badge.locked{background:rgba(239,35,60,.15);color:#ef233c;border:1px solid rgba(239,35,60,.4)}\n.badge.unlocked{background:rgba(0,230,118,.12);color:#00e676;border:1px solid rgba(0,230,118,.4)}\nbutton{padding:5px 10px;border:none;border-radius:5px;color:#fff;font-weight:700;cursor:pointer;font-size:10px;margin-right:4px;margin-bottom:3px}\nbutton.unlock{background:linear-gradient(135deg,#00b09b,#96c93d)}\nbutton.relock{background:linear-gradient(135deg,#f59e0b,#ef4444)}\nbutton.del{background:rgba(139,148,158,.2);color:#8b949e;border:1px solid #30363d}\nbutton:hover{filter:brightness(1.15)}\n.empty{text-align:center;color:#8b949e;padding:24px;font-size:12px}\n.mono{font-family:monospace;font-size:10px;word-break:break-all}\n.reason{color:#ffc107;font-size:10px;max-width:200px}\n.hint{font-size:10px;color:#8b949e;margin-top:8px;line-height:1.6}\n#refresh-ind{font-size:10px;color:#00e676;font-family:monospace}\n</style></head><body><div class="wrap">\n<div class="top">\n<h1>🔒 THIẾT BỊ BỊ KHOÁ DO PHÁT HIỆN SCRIPT LẠ</h1>\n<div style="display:flex;gap:8px;align-items:center">\n<span id="refresh-ind">● tự động refresh mỗi 5s</span>\n<a class="back" href="${ADMIN_PATH}/dashboard">⬅ VỀ DASHBOARD</a>\n<a class="logout" href="${ADMIN_PATH}/logout">🚪 Đăng xuất</a>\n</div>\n</div>\n<div class="stats">\n<div class="stat bad"><div class="n" id="st-locked">—</div><div>Đang bị khoá</div></div>\n<div class="stat ok"><div class="n" id="st-unlocked">—</div><div>Đã mở khoá</div></div>\n<div class="stat info"><div class="n" id="st-total">—</div><div>Tổng lượt báo cáo</div></div>\n</div>\n<div class="panel">\n<h2>📋 DANH SÁCH (tự động cập nhật khi có thiết bị bị khoá)</h2>\n<table><thead><tr>\n<th>Trạng thái</th><th>Thời gian khoá</th><th>Tên máy / Thiết bị</th><th>HWID</th><th>IP</th><th>Key</th><th>OLM User</th><th>Lý do</th><th>Lần check cuối</th><th>Thao tác</th>\n</tr></thead><tbody id="tbody"><tr><td colspan="10" class="empty">Đang tải...</td></tr></tbody></table>\n<div class="hint">💡 Khi bấm <b style="color:#00e676">MỞ KHOÁ</b>: thiết bị đó sẽ tự động hoạt động lại trong vòng ~20s (script polling server), key được giữ nguyên — người dùng KHÔNG cần nhập lại key. Bấm <b style="color:#ffc107">KHOÁ LẠI</b> để khoá lại thiết bị đã mở. <b>XOÁ</b> = xoá bản ghi (cũng có tác dụng mở khoá).</div>\n</div>\n</div>\n<script>\nfunction fmt(t){try{return new Date(t).toLocaleString('vi-VN');}catch(e){return '';}}\nfunction esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}\nfunction act(hwid, action){\n  fetch('${ADMIN_PATH}/api/locked/'+action, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({hwid:hwid})})\n    .then(function(){ refresh(); })\n    .catch(function(){});\n}\nfunction render(d){\n  document.getElementById('st-locked').textContent = d.lockedActive||0;\n  document.getElementById('st-total').textContent = d.count||0;\n  document.getElementById('st-unlocked').textContent = (d.count||0)-(d.lockedActive||0);\n  var tb = document.getElementById('tbody');\n  var list = d.locked||[];\n  if(!list.length){ tb.innerHTML = '<tr><td colspan="10" class="empty">✅ Chưa có thiết bị nào bị khoá do script lạ.</td></tr>'; return; }\n  var html = '';\n  list.forEach(function(r){\n    var isLocked = r.status==='locked';\n    html += '<tr class="'+(isLocked?'locked-row':'')+'">';\n    html += '<td><span class="badge '+(isLocked?'locked':'unlocked')+'">'+(isLocked?'🔒 ĐANG KHOÁ':'✅ ĐÃ MỞ')+'</span></td>';\n    html += '<td class="mono">'+fmt(r.t)+'</td>';\n    html += '<td style="color:#00f2fe">'+esc(r.device||'')+'</td>';\n    html += '<td class="mono">'+esc(r.hwid||'')+'</td>';\n    html += '<td class="mono" style="color:#ffc107">'+esc(r.ip||'')+'</td>';\n    html += '<td class="mono">'+esc(r.keyMasked||'')+'</td>';\n    html += '<td class="mono">'+esc(r.olm_user||'')+'</td>';\n    html += '<td class="reason">'+esc(r.reason||'')+'</td>';\n    html += '<td class="mono">'+fmt(r.lastSeen)+'</td>';\n    html += '<td>';\n    if(isLocked){ html += '<button class="unlock" onclick="act(\\''+esc(r.hwid)+'\\',\\'unlock\\')">🔓 MỞ KHOÁ</button>'; }\n    else { html += '<button class="relock" onclick="act(\\''+esc(r.hwid)+'\\',\\'lock\\')">🔒 KHOÁ LẠI</button>'; }\n    html += '<button class="del" onclick="act(\\''+esc(r.hwid)+'\\',\\'delete\\')">🗑 XOÁ</button>';\n    html += '</td></tr>';\n  });\n  tb.innerHTML = html;\n}\nfunction refresh(){\n  fetch('${ADMIN_PATH}/api/locked')\n    .then(function(r){return r.json();})\n    .then(function(d){ render(d); setTimeout(refresh, 5000); })\n    .catch(function(){ setTimeout(refresh, 5000); });\n}\nrefresh();\n<\/script>\n</body></html>`;
}

function adminDevicesPage() {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">\n<title>📱 Thiết bị & OLM — GOD MODE Admin</title><style>\n*{box-sizing:border-box}body{margin:0;background:#0d1117;font-family:'Segoe UI',system-ui,sans-serif;color:#c9d1d9;padding:20px}\n.wrap{max-width:1200px;margin:0 auto}\n.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:8px}\nh1{font-size:18px;margin:0;background:linear-gradient(90deg,#00f2fe,#4facfe);-webkit-background-clip:text;-webkit-text-fill-color:transparent}\na.back{color:#4facfe;text-decoration:none;font-size:12px;border:1px solid rgba(79,172,254,.4);padding:6px 12px;border-radius:6px}\na.logout{color:#ef233c;text-decoration:none;font-size:12px;border:1px solid rgba(239,35,60,.4);padding:6px 12px;border-radius:6px}\n.panel{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;margin-bottom:16px}\n.panel h2{font-size:13px;margin:0 0 12px;color:#00f2fe;text-transform:uppercase;letter-spacing:1px}\n.stats{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:14px}\n.stat{background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:10px 16px;font-size:12px}\n.stat .n{font-size:20px;font-weight:900;font-family:monospace}\n.stat.info .n{color:#4facfe}.stat.ok .n{color:#00e676}\ntable{width:100%;border-collapse:collapse;font-size:11px}\nth,td{padding:7px 8px;text-align:left;border-bottom:1px solid #21262d;vertical-align:top}\nth{color:#8b949e;font-size:10px;text-transform:uppercase;letter-spacing:.5px;position:sticky;top:0;background:#161b22}\n.mono{font-family:monospace;font-size:10px;word-break:break-all}\n.empty{text-align:center;color:#8b949e;padding:24px;font-size:12px}\n.hint{font-size:10px;color:#8b949e;margin-top:8px;line-height:1.6}\n#refresh-ind{font-size:10px;color:#00e676;font-family:monospace}\n.badge{padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;font-family:monospace;background:rgba(79,172,254,.15);color:#4facfe;border:1px solid rgba(79,172,254,.4)}\n</style></head><body><div class="wrap">\n<div class="top">\n<h1>📱 THIẾT BỊ & TÀI KHOẢN OLM & MÔN ĐANG LÀM</h1>\n<div style="display:flex;gap:8px;align-items:center">\n<span id="refresh-ind">● tự động refresh mỗi 5s</span>\n<a class="back" href="${ADMIN_PATH}/dashboard">⬅ VỀ DASHBOARD</a>\n<a class="logout" href="${ADMIN_PATH}/logout">🚪 Đăng xuất</a>\n</div>\n</div>\n<div class="stats">\n<div class="stat info"><div class="n" id="st-dev">—</div><div>Thiết bị hoạt động</div></div>\n<div class="stat ok"><div class="n" id="st-olm">—</div><div>Có tài khoản OLM</div></div>\n</div>\n<div class="panel">\n<h2>📋 DANH SÁCH (tự động cập nhật)</h2>\n<table><thead><tr>\n<th>Tên máy</th><th>HWID</th><th>IP</th><th>Tài khoản OLM</th><th>Môn (id_cate)</th><th>Chế độ làm bài</th><th>Lần hoạt động cuối</th>\n</tr></thead><tbody id="tbody"><tr><td colspan="7" class="empty">Đang tải...</td></tr></tbody></table>\n<div class="hint">💡 Cột <b>Tài khoản OLM</b> được ghi nhận khi user đăng nhập key (gửi kèm olm_user). Cột <b>Môn (id_cate)</b> + <b>Chế độ</b> được ghi nhận khi user nộp bài (/fire) — id_cate là mã môn của OLM. Thiết bị không hoạt động quá 24h tự biến mất.</div>\n</div>\n</div>\n<script>\nfunction fmt(t){try{return new Date(t).toLocaleString('vi-VN');}catch(e){return '';}}\nfunction esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}\nfunction modeLabel(m){ if(!m) return '—'; if(m==='exam') return '📝 Kiểm tra (exam)'; if(m==='video') return '🎬 Video'; return '✏️ Luyện tập (practice)'; }\nfunction render(d){\n  document.getElementById('st-dev').textContent = d.count||0;\n  document.getElementById('st-olm').textContent = d.withOlm||0;\n  var tb = document.getElementById('tbody');\n  var list = d.list||[];\n  if(!list.length){ tb.innerHTML = '<tr><td colspan="7" class="empty">✅ Chưa có thiết bị nào hoạt động. Khi user đăng nhập key & nộp bài sẽ hiện ở đây.</td></tr>'; return; }\n  var html = '';\n  list.forEach(function(r){\n    html += '<tr>';\n    html += '<td style="color:#00f2fe">'+esc(r.device||'')+'</td>';\n    html += '<td class="mono">'+esc(r.hwid||'')+'</td>';\n    html += '<td class="mono" style="color:#ffc107">'+esc(r.ip||'')+'</td>';\n    html += '<td class="mono" style="color:#fca5a5;font-weight:700">'+(r.olm_user?esc(r.olm_user):'<span style="color:#8b949e">— chưa gửi</span>')+'</td>';\n    html += '<td class="mono">'+(r.id_cate?('<span class="badge">'+esc(r.id_cate)+'</span>'):'<span style="color:#8b949e">—</span>')+'</td>';\n    html += '<td style="font-size:10px">'+modeLabel(r.mode)+'</td>';\n    html += '<td class="mono">'+fmt(r.lastSeen)+'</td>';\n    html += '</tr>';\n  });\n  tb.innerHTML = html;\n}\nfunction refresh(){\n  fetch('${ADMIN_PATH}/api/devices')\n    .then(function(r){return r.json();})\n    .then(function(d){ render(d); setTimeout(refresh, 5000); })\n    .catch(function(){ setTimeout(refresh, 5000); });\n}\nrefresh();\n<\/script>\n</body></html>`;
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
    const kk = String(req.body.key || '').trim().toUpperCase();
    if (kk) {
      BANNED_KEYS.add(kk);
      kvSaveState();
      msg = '🔨 Đã KHOÁ key ' + maskKey(kk) + ' — mọi thiết bị dùng key này bị 404.';
    } else msg = 'Thiếu key để khoá.';
  } else if (flag === 'unbankey') {
    const uk = String(req.body.key || '').trim().toUpperCase();
    if (uk && BANNED_KEYS.delete(uk)) {
      kvSaveState();
      msg = '🔓 Đã MỞ KHOÁ key ' + maskKey(uk) + '.';
    } else msg = 'Không tìm thấy key để mở khoá.';
  }
  kvSaveState();
  adminLog('admin', {
    action: 'toggle:' + flag,
    value: flag === 'autoBan' ? AUTO_BAN : flag === 'mobileOnly' ? MOBILE_ONLY : flag === 'banDesktop' ? BAN_DESKTOP : flag === 'blockVmScript' ? BLOCK_VM_SCRIPT : flag === 'blockModule10' ? BLOCK_MODULE_10 : flag === 'hardDcBan' ? HARD_DC_BAN : flag === 'safeMode' ? SAFE_MODE : flag === 'smartBan' ? SMART_BAN : flag === 'dumperGuard' ? DUMPER_GUARD : flag === 'moduleWatermark' ? MODULE_WATERMARK : req.body.key || '',
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

app.get(ADMIN_PATH + '/logs.json', (req, res) => {
  if (!requireAdmin(req, res)) return;
  res.json({
    logs: ADMIN_LOG.slice(0, 100),
    count: ADMIN_LOG.length
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
  banned.delete(banKey);
  if (!isIp) {
    // Nếu là HWID: xoá cả IP liên quan nếu có
    const devRec = banned.get('dev:' + target);
    if (devRec && devRec.ip) banned.delete('ip:' + devRec.ip);
    // Xoá trong lockedScripts
    const lr = lockedScripts.get(target);
    if (lr) {
      lr.status = 'unlocked';
      lr.unlockedAt = Date.now();
      if (lr.ip) banned.delete('ip:' + lr.ip);
    }
  } else {
    // Nếu là IP: tìm và unlock lockedScripts liên quan
    for (const [hwid, lr] of lockedScripts) {
      if (lr.ip === target) {
        lr.status = 'unlocked';
        lr.unlockedAt = Date.now();
        banned.delete('dev:' + hwid);
        // Cũng thêm HWID vào whitelist
        iosWhitelist.set('dev:' + hwid, { by: 'admin', t: Date.now(), reason: reason + ' (linked HWID)' });
      }
    }
  }

  // 2. Thêm vào iOS whitelist
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

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`\n🚀 GOD MODE Server v18.0 (server-authoritative slim) running → http://localhost:${PORT}`);
    console.log(`   Ẩn API prefix: ${API_PREFIX}`);
    console.log(`   Admin: ${ADMIN_PATH} (${ADMIN_USER})`);
    console.log(`   Lưu trữ bền vững (KV): ${KV_ENABLED ? 'CÓ' : 'KHÔNG — đặt env KV_REST_API_URL + KV_REST_API_TOKEN để ban/mật khẩu tồn tại qua restart'}`);
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