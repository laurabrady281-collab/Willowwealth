const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const PORT = 5000;

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const BASE_URL = process.env.REPLIT_DEV_DOMAIN
  ? `https://${process.env.REPLIT_DEV_DOMAIN}`
  : (process.env.BASE_URL || `http://localhost:${PORT}`);

const sessions = {};
const oauthStates = {};

const mimeTypes = {
    '.html': 'text/html',
    '.css': 'text/css',
    '.js': 'application/javascript',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.webp': 'image/webp',
    '.jpg': 'image/jpeg',
    '.ico': 'image/x-icon',
    '.json': 'application/json'
};

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

function parseBody(req) {
    return new Promise((resolve, reject) => {
        let body = '';
        req.on('data', chunk => { body += chunk.toString(); });
        req.on('end', () => {
            try {
                resolve(JSON.parse(body));
            } catch (e) {
                resolve({});
            }
        });
        req.on('error', reject);
    });
}

function parseCookies(req) {
    const cookies = {};
    const cookieHeader = req.headers.cookie;
    if (cookieHeader) {
        cookieHeader.split(';').forEach(cookie => {
            const [name, ...rest] = cookie.trim().split('=');
            cookies[name] = rest.join('=');
        });
    }
    return cookies;
}

function setSessionCookie(res, token) {
    const isSecure = BASE_URL.startsWith('https');
    res.setHeader('Set-Cookie',
        `session=${token}; HttpOnly; Path=/; Max-Age=86400; SameSite=Lax${isSecure ? '; Secure' : ''}`
    );
}

function jsonResponse(res, statusCode, data) {
    res.writeHead(statusCode, {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-cache'
    });
    res.end(JSON.stringify(data));
}

function redirect(res, url) {
    res.writeHead(302, { Location: url });
    res.end();
}

function parseQuery(url) {
    const queryString = url.split('?')[1] || '';
    const params = {};
    queryString.split('&').forEach(pair => {
        const [key, ...vals] = pair.split('=');
        if (key) params[decodeURIComponent(key)] = decodeURIComponent(vals.join('='));
    });
    return params;
}

function setCookie(res, name, value, maxAge) {
    const isSecure = BASE_URL.startsWith('https');
    const existing = res.getHeader('Set-Cookie') || [];
    const cookies = Array.isArray(existing) ? existing : [existing];
    cookies.push(
        `${name}=${value}; HttpOnly; Path=/; Max-Age=${maxAge}; SameSite=Lax${isSecure ? '; Secure' : ''}`
    );
    res.setHeader('Set-Cookie', cookies);
}

async function handleGoogleAuth(req, res) {
    const query = parseQuery(req.url);
    const mode = query.mode || 'login';

    if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
        return redirect(res, `/${mode === 'signup' ? 'signup' : 'login'}.html?error=google_not_configured`);
    }

    const state = generateToken();
    oauthStates[state] = { provider: 'google', mode, created: Date.now() };

    setTimeout(() => { delete oauthStates[state]; }, 600000);

    setCookie(res, 'oauth_state', state, 600);

    const params = new URLSearchParams({
        client_id: GOOGLE_CLIENT_ID,
        redirect_uri: `${BASE_URL}/auth/google/callback`,
        response_type: 'code',
        scope: 'openid email profile',
        state: state,
        access_type: 'offline',
        prompt: 'select_account'
    });

    redirect(res, `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`);
}

async function handleGoogleCallback(req, res) {
    const query = parseQuery(req.url);
    const { code, state, error } = query;

    if (error) {
        console.error('Google OAuth error:', error);
        return redirect(res, '/login.html?error=auth_cancelled');
    }

    const cookies = parseCookies(req);
    const cookieState = cookies.oauth_state;

    if (!state || !cookieState || state !== cookieState) {
        return redirect(res, '/login.html?error=invalid_state');
    }

    const stateData = oauthStates[state];
    if (!stateData || stateData.provider !== 'google') {
        return redirect(res, '/login.html?error=invalid_state');
    }
    delete oauthStates[state];

    try {
        const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                code,
                client_id: GOOGLE_CLIENT_ID,
                client_secret: GOOGLE_CLIENT_SECRET,
                redirect_uri: `${BASE_URL}/auth/google/callback`,
                grant_type: 'authorization_code'
            }).toString()
        });

        if (!tokenRes.ok) {
            const errBody = await tokenRes.text();
            console.error('Google token exchange failed:', errBody);
            return redirect(res, '/login.html?error=token_exchange_failed');
        }

        const tokenData = await tokenRes.json();

        const userRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
            headers: { Authorization: `Bearer ${tokenData.access_token}` }
        });

        if (!userRes.ok) {
            console.error('Google userinfo fetch failed');
            return redirect(res, '/login.html?error=userinfo_failed');
        }

        const userInfo = await userRes.json();

        const sessionToken = generateToken();
        sessions[sessionToken] = {
            provider: 'google',
            userId: userInfo.id,
            email: userInfo.email,
            name: userInfo.name,
            picture: userInfo.picture,
            created: Date.now(),
            mode: stateData.mode
        };

        setCookie(res, 'oauth_state', '', 0);
        setSessionCookie(res, sessionToken);

        redirect(res, '/dashboard.html');
    } catch (err) {
        console.error('Google OAuth callback error:', err);
        redirect(res, '/login.html?error=auth_failed');
    }
}

async function handleAppleAuth(req, res) {
    const query = parseQuery(req.url);
    const mode = query.mode || 'login';

    const APPLE_CLIENT_ID = process.env.APPLE_CLIENT_ID;
    if (!APPLE_CLIENT_ID) {
        return redirect(res, `/${mode === 'signup' ? 'signup' : 'login'}.html?error=apple_not_configured`);
    }

    const state = generateToken();
    oauthStates[state] = { provider: 'apple', mode, created: Date.now() };
    setTimeout(() => { delete oauthStates[state]; }, 600000);
    setCookie(res, 'oauth_state', state, 600);

    const params = new URLSearchParams({
        client_id: APPLE_CLIENT_ID,
        redirect_uri: `${BASE_URL}/auth/apple/callback`,
        response_type: 'code id_token',
        scope: 'name email',
        state: state,
        response_mode: 'form_post'
    });

    redirect(res, `https://appleid.apple.com/auth/authorize?${params.toString()}`);
}

async function handleAppleCallback(req, res) {
    const body = await parseBody(req);
    const { code, state, id_token, error: appleError } = body;

    if (appleError) {
        console.error('Apple OAuth error:', appleError);
        return redirect(res, '/login.html?error=auth_cancelled');
    }

    const cookies = parseCookies(req);
    const cookieState = cookies.oauth_state;

    if (!state || !cookieState || state !== cookieState) {
        return redirect(res, '/login.html?error=invalid_state');
    }

    const stateData = oauthStates[state];
    if (!stateData || stateData.provider !== 'apple') {
        return redirect(res, '/login.html?error=invalid_state');
    }
    delete oauthStates[state];

    setCookie(res, 'oauth_state', '', 0);
    redirect(res, '/login.html?error=apple_not_configured');
}

async function handleAuthStatus(req, res) {
    const cookies = parseCookies(req);
    const session = sessions[cookies.session];

    if (session) {
        jsonResponse(res, 200, {
            authenticated: true,
            user: {
                email: session.email,
                name: session.name,
                picture: session.picture,
                provider: session.provider
            }
        });
    } else {
        jsonResponse(res, 200, { authenticated: false });
    }
}

async function handleLogout(req, res) {
    const cookies = parseCookies(req);
    if (cookies.session) {
        delete sessions[cookies.session];
    }
    const isSecure = BASE_URL.startsWith('https');
    res.setHeader('Set-Cookie',
        `session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax${isSecure ? '; Secure' : ''}`
    );
    redirect(res, '/index.html');
}

const server = http.createServer(async (req, res) => {
    const urlPath = req.url.split('?')[0];

    if (req.method === 'GET' && urlPath === '/auth/google') {
        return handleGoogleAuth(req, res);
    }
    if (req.method === 'GET' && urlPath === '/auth/google/callback') {
        return handleGoogleCallback(req, res);
    }
    if (req.method === 'GET' && urlPath === '/auth/apple') {
        return handleAppleAuth(req, res);
    }
    if (req.method === 'POST' && urlPath === '/auth/apple/callback') {
        return handleAppleCallback(req, res);
    }
    if (req.method === 'GET' && urlPath === '/auth/status') {
        return handleAuthStatus(req, res);
    }
    if (req.method === 'GET' && urlPath === '/auth/logout') {
        return handleLogout(req, res);
    }

    if (req.method === 'POST' && urlPath === '/send-verification') {
        try {
            const { email } = await parseBody(req);

            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: email,
                subject: 'Verify your WillowWealth account',
                html: `
                    <h1>Welcome to WillowWealth</h1>
                    <p>Please click the link below to verify your email address and complete your setup:</p>
                    <a href="${BASE_URL}/verify-email.html" style="background-color: #002e30; color: white; padding: 14px 28px; text-decoration: none; border-radius: 50px; display: inline-block;">Verify Email Address</a>
                    <p>If you did not create an account, please ignore this email.</p>
                `
            };

            await transporter.sendMail(mailOptions);
            jsonResponse(res, 200, { success: true });
        } catch (error) {
            console.error('Email error:', error);
            jsonResponse(res, 500, { success: false, error: error.message });
        }
        return;
    }

    let filePath = urlPath === '/' ? '/index.html' : urlPath;
    filePath = path.join(__dirname, filePath);

    const ext = path.extname(filePath);
    const contentType = mimeTypes[ext] || 'application/octet-stream';

    fs.readFile(filePath, (err, content) => {
        if (err) {
            if (err.code === 'ENOENT') {
                fs.readFile(path.join(__dirname, 'index.html'), (err, content) => {
                    res.writeHead(200, { 'Content-Type': 'text/html', 'Cache-Control': 'no-cache' });
                    res.end(content);
                });
            } else {
                res.writeHead(500);
                res.end('Server Error');
            }
        } else {
            res.writeHead(200, { 'Content-Type': contentType, 'Cache-Control': 'no-cache' });
            res.end(content);
        }
    });
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running at ${BASE_URL}`);
    console.log(`Google OAuth: ${GOOGLE_CLIENT_ID ? 'configured' : 'NOT configured - set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET'}`);
    console.log(`Apple OAuth: placeholder ready for future integration`);
});
