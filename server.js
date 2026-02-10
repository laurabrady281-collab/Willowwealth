const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const PORT = 5000;

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const BASE_URL = process.env.REPLIT_DEV_DOMAIN
  ? `https://${process.env.REPLIT_DEV_DOMAIN}`
  : (process.env.BASE_URL || `http://localhost:${PORT}`);

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const sessions = {};
const oauthStates = {};

const ONBOARDING_STEPS = [
    { key: 'legal_name_completed', page: '/legal-name.html' }
];

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
                const ct = req.headers['content-type'] || '';
                if (ct.includes('application/x-www-form-urlencoded')) {
                    const params = {};
                    body.split('&').forEach(pair => {
                        const [k, ...v] = pair.split('=');
                        if (k) params[decodeURIComponent(k)] = decodeURIComponent(v.join('='));
                    });
                    resolve(params);
                } else {
                    resolve(JSON.parse(body));
                }
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
    const existing = res.getHeader('Set-Cookie') || [];
    const cookies = Array.isArray(existing) ? existing : (existing ? [existing] : []);
    cookies.push(
        `session=${token}; HttpOnly; Path=/; Max-Age=86400; SameSite=Lax${isSecure ? '; Secure' : ''}`
    );
    res.setHeader('Set-Cookie', cookies);
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
    const cookies = Array.isArray(existing) ? existing : (existing ? [existing] : []);
    cookies.push(
        `${name}=${value}; HttpOnly; Path=/; Max-Age=${maxAge}; SameSite=Lax${isSecure ? '; Secure' : ''}`
    );
    res.setHeader('Set-Cookie', cookies);
}

async function findOrCreateUser({ email, name, picture, provider, providerId }) {
    let user = (await pool.query('SELECT * FROM users WHERE email = $1', [email])).rows[0];
    if (!user) {
        const result = await pool.query(
            `INSERT INTO users (email, name, picture, provider, provider_id)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING *`,
            [email, name, picture, provider, providerId]
        );
        user = result.rows[0];
        console.log('Created new user:', email);
    } else {
        await pool.query(
            `UPDATE users SET name = COALESCE($1, name), picture = COALESCE($2, picture), updated_at = NOW() WHERE id = $3`,
            [name, picture, user.id]
        );
        user.name = name || user.name;
        user.picture = picture || user.picture;
        console.log('Existing user logged in:', email);
    }
    return user;
}

function getNextOnboardingStep(user) {
    for (const step of ONBOARDING_STEPS) {
        if (!user[step.key]) {
            return step;
        }
    }
    return null;
}

function getOnboardingRedirect(user) {
    const nextStep = getNextOnboardingStep(user);
    if (nextStep) return nextStep.page;
    return '/dashboard.html';
}

async function createSessionForUser(res, user) {
    const sessionToken = generateToken();
    sessions[sessionToken] = {
        userId: user.id,
        provider: user.provider,
        email: user.email,
        name: user.name,
        picture: user.picture,
        created: Date.now()
    };
    setSessionCookie(res, sessionToken);
    return sessionToken;
}

function getSessionUser(req) {
    const cookies = parseCookies(req);
    return sessions[cookies.session] || null;
}

async function getFullUser(sessionData) {
    if (!sessionData || !sessionData.userId) return null;
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [sessionData.userId]);
    return result.rows[0] || null;
}

async function handleGoogleAuth(req, res) {
    const query = parseQuery(req.url);
    const mode = query.mode || 'login';

    if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
        console.error('Google OAuth not configured. GOOGLE_CLIENT_ID:', !!GOOGLE_CLIENT_ID, 'GOOGLE_CLIENT_SECRET:', !!GOOGLE_CLIENT_SECRET);
        return redirect(res, `/${mode === 'signup' ? 'signup' : 'login'}.html?error=google_not_configured`);
    }

    const state = generateToken();
    oauthStates[state] = { provider: 'google', mode, created: Date.now() };
    setTimeout(() => { delete oauthStates[state]; }, 600000);
    setCookie(res, 'oauth_state', state, 600);

    const redirectUri = `${BASE_URL}/auth/google/callback`;

    console.log('=== GOOGLE OAUTH DEBUG ===');
    console.log('client_id:', GOOGLE_CLIENT_ID);
    console.log('redirect_uri:', redirectUri);
    console.log('scope:', 'openid email profile');
    console.log('response_type:', 'code');
    console.log('==========================');

    const params = new URLSearchParams({
        client_id: GOOGLE_CLIENT_ID,
        redirect_uri: redirectUri,
        response_type: 'code',
        scope: 'openid email profile',
        state: state,
        access_type: 'offline',
        prompt: 'select_account'
    });

    const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
    console.log('Full auth URL:', authUrl);
    redirect(res, authUrl);
}

async function handleGoogleCallback(req, res) {
    const query = parseQuery(req.url);
    const { code, state, error, error_description } = query;

    if (error) {
        console.error('Google OAuth error:', error, 'Description:', error_description || 'none');
        return redirect(res, '/login.html?error=auth_cancelled');
    }

    const cookies = parseCookies(req);
    const cookieState = cookies.oauth_state;

    if (!state || !cookieState || state !== cookieState) {
        console.error('Google OAuth state mismatch. State:', !!state, 'Cookie:', !!cookieState, 'Match:', state === cookieState);
        return redirect(res, '/login.html?error=invalid_state');
    }

    const stateData = oauthStates[state];
    if (!stateData || stateData.provider !== 'google') {
        console.error('Google OAuth state not found or wrong provider');
        return redirect(res, '/login.html?error=invalid_state');
    }
    const mode = stateData.mode;
    delete oauthStates[state];

    try {
        const redirectUri = `${BASE_URL}/auth/google/callback`;
        console.log('Google OAuth callback - exchanging code, redirect_uri:', redirectUri);

        const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                code,
                client_id: GOOGLE_CLIENT_ID,
                client_secret: GOOGLE_CLIENT_SECRET,
                redirect_uri: redirectUri,
                grant_type: 'authorization_code'
            }).toString()
        });

        if (!tokenRes.ok) {
            const errBody = await tokenRes.text();
            console.error('Google token exchange failed (status', tokenRes.status, '):', errBody);
            return redirect(res, `/${mode === 'signup' ? 'signup' : 'login'}.html?error=token_exchange_failed`);
        }

        const tokenData = await tokenRes.json();

        const userRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
            headers: { Authorization: `Bearer ${tokenData.access_token}` }
        });

        if (!userRes.ok) {
            const errBody = await userRes.text();
            console.error('Google userinfo fetch failed (status', userRes.status, '):', errBody);
            return redirect(res, `/${mode === 'signup' ? 'signup' : 'login'}.html?error=userinfo_failed`);
        }

        const userInfo = await userRes.json();
        console.log('Google OAuth success - user:', userInfo.email);

        const user = await findOrCreateUser({
            email: userInfo.email,
            name: userInfo.name,
            picture: userInfo.picture,
            provider: 'google',
            providerId: userInfo.id
        });

        setCookie(res, 'oauth_state', '', 0);
        await createSessionForUser(res, user);

        const dest = getOnboardingRedirect(user);
        console.log('Redirecting user to:', dest, '(onboarding_completed:', user.onboarding_completed, ')');
        redirect(res, dest);
    } catch (err) {
        console.error('Google OAuth callback error:', err.message, err.stack);
        redirect(res, `/${mode === 'signup' ? 'signup' : 'login'}.html?error=auth_failed`);
    }
}

async function handleAppleAuth(req, res) {
    const query = parseQuery(req.url);
    const mode = query.mode || 'login';

    const APPLE_CLIENT_ID = process.env.APPLE_CLIENT_ID;
    if (!APPLE_CLIENT_ID) {
        console.log('Apple Sign-In not configured - redirecting back with notice');
        return redirect(res, `/${mode === 'signup' ? 'signup' : 'login'}.html?error=apple_coming_soon`);
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
    redirect(res, '/login.html?error=apple_coming_soon');
}

async function handleEmailSignup(req, res) {
    try {
        const { firstName, lastName, email, password } = await parseBody(req);

        if (!firstName || !lastName || !email || !password) {
            return jsonResponse(res, 400, { success: false, error: 'All fields are required' });
        }

        const existing = (await pool.query('SELECT id FROM users WHERE email = $1', [email])).rows[0];
        if (existing) {
            return jsonResponse(res, 409, { success: false, error: 'An account with this email already exists' });
        }

        const passwordHash = await bcrypt.hash(password, 10);
        const result = await pool.query(
            `INSERT INTO users (email, name, provider, password_hash)
             VALUES ($1, $2, 'email', $3)
             RETURNING *`,
            [email, `${firstName} ${lastName}`, passwordHash]
        );
        const user = result.rows[0];
        console.log('Email signup - new user created:', email);

        await createSessionForUser(res, user);

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
        transporter.sendMail(mailOptions).catch(err => {
            console.error('Verification email failed:', err.message);
        });

        const dest = getOnboardingRedirect(user);
        jsonResponse(res, 200, { success: true, redirect: dest });
    } catch (error) {
        console.error('Email signup error:', error);
        jsonResponse(res, 500, { success: false, error: 'An error occurred during signup' });
    }
}

async function handleEmailLogin(req, res) {
    try {
        const { email, password } = await parseBody(req);

        if (!email || !password) {
            return jsonResponse(res, 400, { success: false, error: 'Email and password are required' });
        }

        const user = (await pool.query('SELECT * FROM users WHERE email = $1 AND provider = $2', [email, 'email'])).rows[0];
        if (!user) {
            return jsonResponse(res, 401, { success: false, error: 'Invalid email or password' });
        }

        const valid = await bcrypt.compare(password, user.password_hash);
        if (!valid) {
            return jsonResponse(res, 401, { success: false, error: 'Invalid email or password' });
        }

        console.log('Email login success:', email);
        await createSessionForUser(res, user);

        const dest = getOnboardingRedirect(user);
        jsonResponse(res, 200, { success: true, redirect: dest });
    } catch (error) {
        console.error('Email login error:', error);
        jsonResponse(res, 500, { success: false, error: 'An error occurred during login' });
    }
}

async function handleAuthStatus(req, res) {
    const sessionData = getSessionUser(req);

    if (sessionData) {
        const user = await getFullUser(sessionData);
        if (!user) {
            return jsonResponse(res, 200, { authenticated: false });
        }

        const nextStep = getNextOnboardingStep(user);
        jsonResponse(res, 200, {
            authenticated: true,
            user: {
                email: user.email,
                name: user.name,
                picture: user.picture,
                provider: user.provider,
                legalFirstName: user.legal_first_name,
                legalLastName: user.legal_last_name
            },
            onboarding: {
                completed: user.onboarding_completed,
                legalNameCompleted: user.legal_name_completed,
                nextStep: nextStep ? nextStep.page : null
            }
        });
    } else {
        jsonResponse(res, 200, { authenticated: false });
    }
}

async function handleSaveLegalName(req, res) {
    const sessionData = getSessionUser(req);
    if (!sessionData) {
        return jsonResponse(res, 401, { success: false, error: 'Not authenticated' });
    }

    const { firstName, lastName } = await parseBody(req);
    if (!firstName || !lastName || !firstName.trim() || !lastName.trim()) {
        return jsonResponse(res, 400, { success: false, error: 'First and last name are required' });
    }

    await pool.query(
        `UPDATE users SET legal_first_name = $1, legal_last_name = $2, legal_name_completed = TRUE, updated_at = NOW() WHERE id = $3`,
        [firstName.trim(), lastName.trim(), sessionData.userId]
    );

    const user = (await pool.query('SELECT * FROM users WHERE id = $1', [sessionData.userId])).rows[0];

    const allComplete = ONBOARDING_STEPS.every(step => user[step.key]);
    if (allComplete) {
        await pool.query('UPDATE users SET onboarding_completed = TRUE, updated_at = NOW() WHERE id = $1', [user.id]);
    }

    const nextStep = getNextOnboardingStep(user);
    const dest = nextStep ? nextStep.page : '/dashboard.html';

    console.log('Legal name saved for user:', user.email, '- next:', dest);
    jsonResponse(res, 200, { success: true, redirect: dest });
}

async function handleOnboardingStatus(req, res) {
    const sessionData = getSessionUser(req);
    if (!sessionData) {
        return jsonResponse(res, 401, { success: false, error: 'Not authenticated' });
    }

    const user = await getFullUser(sessionData);
    if (!user) {
        return jsonResponse(res, 401, { success: false, error: 'User not found' });
    }

    const nextStep = getNextOnboardingStep(user);
    jsonResponse(res, 200, {
        completed: user.onboarding_completed,
        legalNameCompleted: user.legal_name_completed,
        nextStep: nextStep ? nextStep.page : null,
        redirect: nextStep ? nextStep.page : '/dashboard.html'
    });
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

const PROTECTED_PAGES = ['/dashboard.html', '/legal-name.html', '/mobile-phone.html'];
const ONBOARDING_PAGES = ['/legal-name.html', '/mobile-phone.html'];

const server = http.createServer(async (req, res) => {
    const urlPath = req.url.split('?')[0];

    if (req.method === 'GET' && urlPath === '/auth/error') {
        const filePath = path.join(__dirname, 'auth-error.html');
        return fs.readFile(filePath, (err, content) => {
            res.writeHead(200, { 'Content-Type': 'text/html', 'Cache-Control': 'no-cache' });
            res.end(content);
        });
    }
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

    if (req.method === 'POST' && urlPath === '/api/signup') {
        return handleEmailSignup(req, res);
    }
    if (req.method === 'POST' && urlPath === '/api/login') {
        return handleEmailLogin(req, res);
    }
    if (req.method === 'POST' && urlPath === '/api/onboarding/legal-name') {
        return handleSaveLegalName(req, res);
    }
    if (req.method === 'GET' && urlPath === '/api/onboarding/status') {
        return handleOnboardingStatus(req, res);
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

    if (req.method === 'GET' && PROTECTED_PAGES.includes(urlPath)) {
        const sessionData = getSessionUser(req);

        if (!sessionData) {
            return redirect(res, '/login.html');
        }

        const user = await getFullUser(sessionData);
        if (!user) {
            return redirect(res, '/login.html');
        }

        const correctPage = getOnboardingRedirect(user);

        if (urlPath === '/dashboard.html' && !user.onboarding_completed) {
            return redirect(res, correctPage);
        }

        if (ONBOARDING_PAGES.includes(urlPath) && user.onboarding_completed) {
            return redirect(res, '/dashboard.html');
        }

        if (ONBOARDING_PAGES.includes(urlPath) && urlPath !== correctPage) {
            return redirect(res, correctPage);
        }
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
    console.log(`Database: connected`);
    console.log(`Google OAuth: ${GOOGLE_CLIENT_ID ? 'configured' : 'NOT configured - set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET'}`);
    console.log(`Apple OAuth: placeholder ready for future integration`);
    console.log(`Onboarding steps: ${ONBOARDING_STEPS.map(s => s.key).join(', ')}`);
});
