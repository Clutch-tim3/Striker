const http = require('http');
const fs   = require('fs');
const path = require('path');

const PORT  = process.env.PORT || 8080;
const INDEX = path.join(__dirname, 'deploy/public/apps/mahoraga/index.html');

http.createServer((req, res) => {
  const url = req.url.split('?')[0].replace(/\/$/, '');
  if (url === '' || url === '/' || url === '/apps/mahoraga') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(fs.readFileSync(INDEX));
  } else {
    res.writeHead(302, { Location: '/apps/mahoraga' });
    res.end();
  }
}).listen(PORT, () => console.log(`Mahoraga listing on :${PORT}`));
