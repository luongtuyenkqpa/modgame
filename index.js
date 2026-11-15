// Vercel serverless entry — export Express app từ server.js
// Đặt file này tại: <project>/api/index.js
// Đặt server.js tại: <project>/server.js
// vercel.json sẽ rewrite mọi request vào file này.
const app = require('../server.js');
module.exports = app;
