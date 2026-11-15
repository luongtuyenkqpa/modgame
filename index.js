// Vercel serverless entry — đặt file này TẠI GỐC repo (cùng thư mục với server.js)
// ⚠️ ĐỂ Ở GỐC, KHÔNG đặt trong thư mục api/ (khớp với vercel.json builds src=index.js)
const app = require('./server.js');
module.exports = app;
