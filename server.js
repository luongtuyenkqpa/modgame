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
    allowedHeaders: ['Content-Type', 'X-Key', 'X-HWID', 'X-App']
}));
app.options(/.*/, cors());

// ─── Không bao giờ serve static JS gốc ───────────────────────────────────────
// (Không dùng express.static — script gốc nằm ngoài www-root)


// ══════════════════════════════════════════════════════════════════════════════
//  CORE LOGIC (adapted từ userscript gốc — chạy trên Node.js)
// ══════════════════════════════════════════════════════════════════════════════

const SECRET_KEY = '1047823200';   // OLM XOR key — ẩn hoàn toàn trong server
const APP_ID     = 'tiep_god_mode_v3';

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
            timeout:  10000
        };
        const req = https.request(opts, (res) => {
            let raw = '';
            res.on('data', c => raw += c);
            res.on('end', () => {
                try {
                    const kv = JSON.parse(raw);
                    // Chuẩn hóa: keyvault có thể trả {valid, reason} hoặc {success, message}
                    resolve({
                        success:    kv.success !== undefined ? !!kv.success : !!kv.valid,
                        message:    kv.message || kv.reason || '',
                        type:       kv.type || kv.plan || kv.level || '',
                        expires_at: kv.expires_at || kv.exp || kv.expire || ''
                    });
                } catch (_) { resolve({ success: false, message: 'Server parse error' }); }
            });
        });
        req.on('error', e => resolve({ success: false, message: e.message }));
        req.on('timeout', ()  => { req.destroy(); resolve({ success: false, message: 'Timeout' }); });
        req.write(postData);
        req.end();
    });
}


// ══════════════════════════════════════════════════════════════════════════════
//  ROUTES
// ══════════════════════════════════════════════════════════════════════════════

/** Ping / health check */
// Trang chủ — kiểm tra deploy thành công
app.get('/', (_req, res) => {
    res.json({
        status: 'ok',
        name: 'GOD MODE Server v3.2',
        endpoints: {
            'GET  /':             'thông tin server (trang này)',
            'GET  /api/ping':     'health check',
            'POST /api/verify':   'xác thực key {key, hwid, olm_user}',
            'POST /api/process':  'giải mã đáp án {key, hwid, questions}',
            'POST /api/fire':     'tạo payload nộp bài {key, hwid, session, mode, time_str, grade}'
        },
        ts: Date.now()
    });
});

app.get('/api/ping', (_req, res) => {
    res.json({ status: 'ok', version: '3.2', ts: Date.now() });
});

/** Key verification (proxy) */
app.post('/api/verify', async (req, res) => {
    const { key, hwid, olm_user } = req.body;
    if (!key) return res.status(400).json({ success: false, message: 'Missing key' });
    const result = await proxyVerify(key, hwid, olm_user);
    res.json(result);
});

/**
 * Process raw question list → trả về đáp án đã giải mã
 * Body: { key, hwid, questions: [...] }
 */
app.post('/api/process', async (req, res) => {
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

    res.json({ success: true, questions: processed, count: processed.length });
});

/**
 * Build & return fire payload (server-side)
 * Body: { key, hwid, session: { raw_questions, meta, video_length }, mode, time_str, grade }
 * Response: { success, params_str, endpoint }
 */
app.post('/api/fire', async (req, res) => {
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
        res.json({ success: true, params_str: paramsStr, endpoint: '/course/teacher-static' });
    } catch (err) {
        console.error('[/api/fire]', err);
        res.status(500).json({ success: false, message: 'Server error: ' + err.message });
    }
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
        console.log(`\n🚀 GOD MODE Server v3.2 running → http://localhost:${PORT}`);
        console.log(`   POST /api/verify   — xác thực key`);
        console.log(`   POST /api/process  — giải mã đáp án`);
        console.log(`   POST /api/fire     — tạo payload nộp bài`);
        console.log(`   GET  /api/ping     — health check\n`);
    });
}
module.exports = app;
