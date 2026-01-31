const http = require('http');
const fs = require('fs');
const path = require('path');
const nodemailer = require('nodemailer');

// Supervisor sets PORT=3000 and HOST=0.0.0.0
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';

// Serve the cloned repo static files
const STATIC_ROOT = path.resolve(__dirname, '../repo');

const mimeTypes = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.webp': 'image/webp',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.ico': 'image/x-icon',
  '.pdf': 'application/pdf'
};

function safeResolve(requestPath) {
  // Prevent directory traversal; normalize and ensure within STATIC_ROOT
  const normalized = path.posix.normalize(requestPath);
  const stripped = normalized.startsWith('/') ? normalized.slice(1) : normalized;
  const resolved = path.resolve(STATIC_ROOT, stripped);
  if (!resolved.startsWith(STATIC_ROOT)) {
    return null;
  }
  return resolved;
}

function json(res, status, payload) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(payload));
}

function getTransporter() {
  const user = process.env.EMAIL_USER;
  const pass = process.env.EMAIL_PASS;
  if (!user || !pass) return null;

  return nodemailer.createTransport({
    service: 'gmail',
    auth: { user, pass }
  });
}

const server = http.createServer((req, res) => {
  // Simple API for the signup flow
  if (req.method === 'POST' && req.url === '/send-verification') {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk.toString();
    });

    req.on('end', async () => {
      try {
        const { email } = JSON.parse(body || '{}');
        if (!email) {
          return json(res, 400, { success: false, error: 'Missing email' });
        }

        const transporter = getTransporter();
        if (!transporter) {
          return json(res, 501, {
            success: false,
            error: 'Email sending is not configured. Set EMAIL_USER and EMAIL_PASS.'
          });
        }

        const mailOptions = {
          from: process.env.EMAIL_USER,
          to: email,
          subject: 'Verify your WillowWealth account',
          html: `
            <h1>Welcome to WillowWealth</h1>
            <p>Please click the link below to verify your email address and complete your setup:</p>
            <a href="http://${req.headers.host}/verify-email.html" style="background-color: #002e30; color: white; padding: 14px 28px; text-decoration: none; border-radius: 50px; display: inline-block;">Verify Email Address</a>
            <p>If you did not create an account, please ignore this email.</p>
          `
        };

        await transporter.sendMail(mailOptions);
        return json(res, 200, { success: true });
      } catch (error) {
        console.error('Email error:', error);
        return json(res, 500, { success: false, error: error.message });
      }
    });

    return;
  }

  // Static routing
  const urlPath = req.url && req.url !== '/' ? req.url : '/index.html';
  const resolved = safeResolve(urlPath);

  if (!resolved) {
    return json(res, 400, { success: false, error: 'Invalid path' });
  }

  const ext = path.extname(resolved);
  const contentType = mimeTypes[ext] || 'application/octet-stream';

  fs.readFile(resolved, (err, content) => {
    if (err) {
      if (err.code === 'ENOENT') {
        // SPA-ish fallback: serve index.html
        const indexPath = path.resolve(STATIC_ROOT, 'index.html');
        fs.readFile(indexPath, (indexErr, indexContent) => {
          if (indexErr) {
            res.writeHead(404);
            res.end('Not Found');
            return;
          }
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(indexContent);
        });
        return;
      }

      res.writeHead(500);
      res.end('Server Error');
      return;
    }

    res.writeHead(200, { 'Content-Type': contentType });
    res.end(content);
  });
});

server.listen(PORT, HOST, () => {
  console.log(`Willowwealth frontend server running at http://${HOST}:${PORT}`);
  console.log(`Serving static files from: ${STATIC_ROOT}`);
});
