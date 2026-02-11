const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const PORT = 5000;

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const APPLE_CLIENT_ID = process.env.APPLE_CLIENT_ID;
const APPLE_TEAM_ID = process.env.APPLE_TEAM_ID;
const APPLE_KEY_ID = process.env.APPLE_KEY_ID;
const APPLE_PRIVATE_KEY = (process.env.APPLE_PRIVATE_KEY || '').replace(/\\n/g, '\n');
const BASE_URL = process.env.REPLIT_DEV_DOMAIN
  ? `https://${process.env.REPLIT_DEV_DOMAIN}`
  : (process.env.BASE_URL || `http://localhost:${PORT}`);

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const sessions = {};
const oauthStates = {};
const twoFactorCodes = {};
const emailVerificationTokens = {};

const ONBOARDING_STEPS = [
    { key: 'terms_accepted', page: '/signup/terms-review' },
    { key: 'accreditation_completed', page: '/signup/accreditation' },
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

function generate2FACode() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

function maskEmail(email) {
    const [local, domain] = email.split('@');
    if (local.length <= 2) return local[0] + '***@' + domain;
    return local[0] + '*'.repeat(Math.min(local.length - 2, 14)) + local.slice(-1) + '@' + domain;
}

async function send2FACode(email, user) {
    const code = generate2FACode();
    const token = generateToken();
    twoFactorCodes[token] = { code, email, userId: user.id, created: Date.now(), attempts: 0 };
    setTimeout(() => { delete twoFactorCodes[token]; }, 600000);

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Your WillowWealth verification code',
        html: `
            <div style="font-family: 'Inter', Arial, sans-serif; max-width: 480px; margin: 0 auto; padding: 40px 20px;">
                <h1 style="font-size: 24px; color: #1a1a1a; margin-bottom: 16px;">Verify your identity</h1>
                <p style="font-size: 14px; color: #4b5563; line-height: 1.6;">Your verification code is:</p>
                <div style="font-size: 32px; font-weight: 700; color: #002e30; letter-spacing: 8px; margin: 24px 0; padding: 20px; background: #f3f4f6; border-radius: 12px; text-align: center;">${code}</div>
                <p style="font-size: 14px; color: #4b5563; line-height: 1.6;">This code expires in 10 minutes. If you did not request this code, please ignore this email.</p>
                <p style="font-size: 12px; color: #9ca3af; margin-top: 32px;">&copy; 2026 Willow Wealth Inc.</p>
            </div>
        `
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log('2FA code sent to:', maskEmail(email));
    } catch (err) {
        console.error('Failed to send 2FA email:', err.message);
    }

    return { token, maskedEmail: maskEmail(email) };
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
        const isOAuthProvider = (provider === 'google' || provider === 'apple');
        const result = await pool.query(
            `INSERT INTO users (email, name, picture, provider, provider_id, email_verified)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING *`,
            [email, name, picture, provider, providerId, isOAuthProvider]
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
        console.log('Google OAuth success - user:', userInfo.email, '- mode:', mode);

        setCookie(res, 'oauth_state', '', 0);

        if (mode === 'login') {
            const existing = (await pool.query('SELECT * FROM users WHERE email = $1', [userInfo.email])).rows[0];
            if (!existing) {
                console.log('Login attempt but no account found for:', userInfo.email);
                return redirect(res, '/login.html?error=no_account');
            }
            await pool.query(
                'UPDATE users SET name = COALESCE($1, name), picture = COALESCE($2, picture), updated_at = NOW() WHERE id = $3',
                [userInfo.name, userInfo.picture, existing.id]
            );
            existing.name = userInfo.name || existing.name;
            existing.picture = userInfo.picture || existing.picture;

            const { token: twoFAToken, maskedEmail } = await send2FACode(userInfo.email, existing);
            console.log('2FA required for Google login user:', maskEmail(userInfo.email));
            redirect(res, `/verify-identity.html?token=${twoFAToken}&email=${encodeURIComponent(maskedEmail)}`);
        } else {
            const user = await findOrCreateUser({
                email: userInfo.email,
                name: userInfo.name,
                picture: userInfo.picture,
                provider: 'google',
                providerId: userInfo.id
            });
            await createSessionForUser(res, user);
            const dest = getOnboardingRedirect(user);
            console.log('Redirecting user to:', dest, '(onboarding_completed:', user.onboarding_completed, ')');
            redirect(res, dest);
        }
    } catch (err) {
        console.error('Google OAuth callback error:', err.message, err.stack);
        redirect(res, `/${mode === 'signup' ? 'signup' : 'login'}.html?error=auth_failed`);
    }
}

function generateAppleClientSecret() {
    const now = Math.floor(Date.now() / 1000);
    const payload = {
        iss: APPLE_TEAM_ID,
        iat: now,
        exp: now + 15777000,
        aud: 'https://appleid.apple.com',
        sub: APPLE_CLIENT_ID
    };
    return jwt.sign(payload, APPLE_PRIVATE_KEY, {
        algorithm: 'ES256',
        header: { alg: 'ES256', kid: APPLE_KEY_ID }
    });
}

let applePublicKeysCache = null;
let appleKeysCacheTime = 0;

async function getApplePublicKeys() {
    if (applePublicKeysCache && Date.now() - appleKeysCacheTime < 3600000) {
        return applePublicKeysCache;
    }
    const res = await fetch('https://appleid.apple.com/auth/keys');
    const data = await res.json();
    applePublicKeysCache = data.keys;
    appleKeysCacheTime = Date.now();
    return applePublicKeysCache;
}

async function verifyAppleIdToken(idToken) {
    const decoded = jwt.decode(idToken, { complete: true });
    if (!decoded) throw new Error('Invalid Apple ID token');

    const keys = await getApplePublicKeys();
    const matchingKey = keys.find(k => k.kid === decoded.header.kid);
    if (!matchingKey) throw new Error('No matching Apple public key found');

    const publicKey = crypto.createPublicKey({
        key: matchingKey,
        format: 'jwk'
    });

    const verified = jwt.verify(idToken, publicKey, {
        algorithms: ['RS256'],
        issuer: 'https://appleid.apple.com',
        audience: APPLE_CLIENT_ID
    });

    return verified;
}

async function exchangeAppleCode(code) {
    const clientSecret = generateAppleClientSecret();
    const params = new URLSearchParams({
        client_id: APPLE_CLIENT_ID,
        client_secret: clientSecret,
        code: code,
        grant_type: 'authorization_code',
        redirect_uri: `${BASE_URL}/auth/apple/callback`
    });

    const tokenRes = await fetch('https://appleid.apple.com/auth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: params.toString()
    });

    if (!tokenRes.ok) {
        const errBody = await tokenRes.text();
        console.error('Apple token exchange failed (status', tokenRes.status, '):', errBody);
        throw new Error('Apple token exchange failed');
    }

    return await tokenRes.json();
}

async function handleAppleAuth(req, res) {
    const query = parseQuery(req.url);
    const mode = query.mode || 'login';

    if (!APPLE_CLIENT_ID || !APPLE_TEAM_ID || !APPLE_KEY_ID || !APPLE_PRIVATE_KEY) {
        console.error('Apple Sign-In not configured. APPLE_CLIENT_ID:', !!APPLE_CLIENT_ID,
            'APPLE_TEAM_ID:', !!APPLE_TEAM_ID, 'APPLE_KEY_ID:', !!APPLE_KEY_ID,
            'APPLE_PRIVATE_KEY:', !!APPLE_PRIVATE_KEY);
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
    const { code, state, id_token, user: userJson, error: appleError } = body;

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
    const mode = stateData.mode || 'login';
    delete oauthStates[state];
    setCookie(res, 'oauth_state', '', 0);

    try {
        if (!code) {
            console.error('Apple callback: no authorization code received');
            return redirect(res, `/${mode === 'signup' ? 'signup' : 'login'}.html?error=auth_failed`);
        }

        const tokenData = await exchangeAppleCode(code);
        const verifiedToken = tokenData.id_token;

        if (!verifiedToken) {
            console.error('Apple callback: no id_token in token response');
            return redirect(res, `/${mode === 'signup' ? 'signup' : 'login'}.html?error=auth_failed`);
        }

        const appleUser = await verifyAppleIdToken(verifiedToken);
        const email = appleUser.email;

        if (!email) {
            console.error('Apple Sign-In: no email in token');
            return redirect(res, `/${mode === 'signup' ? 'signup' : 'login'}.html?error=auth_failed`);
        }

        let userName = null;
        if (userJson) {
            try {
                const parsed = typeof userJson === 'string' ? JSON.parse(userJson) : userJson;
                if (parsed.name) {
                    const first = parsed.name.firstName || '';
                    const last = parsed.name.lastName || '';
                    userName = `${first} ${last}`.trim() || null;
                }
            } catch (e) {
                console.log('Could not parse Apple user data:', e.message);
            }
        }

        console.log('Apple OAuth success - email:', email, '- mode:', mode);

        if (mode === 'login') {
            const existing = (await pool.query('SELECT * FROM users WHERE email = $1', [email])).rows[0];
            if (!existing) {
                console.log('Apple login attempt but no account found for:', email);
                return redirect(res, '/login.html?error=no_account');
            }
            if (userName) {
                await pool.query('UPDATE users SET name = COALESCE($1, name), updated_at = NOW() WHERE id = $2', [userName, existing.id]);
                existing.name = userName || existing.name;
            }
            await createSessionForUser(res, existing);
            const dest = getOnboardingRedirect(existing);
            console.log('Apple login: redirecting existing user to:', dest);
            redirect(res, dest);
        } else {
            const user = await findOrCreateUser({
                email: email,
                name: userName,
                picture: null,
                provider: 'apple',
                providerId: appleUser.sub
            });
            await createSessionForUser(res, user);
            const dest = getOnboardingRedirect(user);
            console.log('Apple signup: redirecting user to:', dest, '(onboarding_completed:', user.onboarding_completed, ')');
            redirect(res, dest);
        }
    } catch (err) {
        console.error('Apple OAuth callback error:', err.message, err.stack);
        redirect(res, `/${mode === 'signup' ? 'signup' : 'login'}.html?error=auth_failed`);
    }
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

        const verifyToken = crypto.randomBytes(32).toString('hex');
        emailVerificationTokens[verifyToken] = { email, createdAt: Date.now() };
        const verifyLink = `${BASE_URL}/api/verify-email?token=${verifyToken}`;
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Verify your WillowWealth account',
            html: `
                <div style="font-family: 'Inter', Arial, sans-serif; max-width: 480px; margin: 0 auto; padding: 40px 20px;">
                    <h1 style="font-size: 24px; color: #1a2b23; margin-bottom: 16px;">Welcome to WillowWealth</h1>
                    <p style="font-size: 14px; color: #4b5563; line-height: 1.6;">Please click the button below to verify your email address and complete your setup:</p>
                    <a href="${verifyLink}" style="background-color: #002e30; color: white; padding: 14px 28px; text-decoration: none; border-radius: 50px; display: inline-block; margin: 24px 0; font-weight: 600;">Verify Email Address</a>
                    <p style="font-size: 12px; color: #9ca3af;">If you did not create an account, please ignore this email. This link expires in 24 hours.</p>
                </div>
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

async function handleVerify2FA(req, res) {
    try {
        const { token, code } = await parseBody(req);

        if (!token || !code) {
            return jsonResponse(res, 400, { success: false, error: 'Token and code are required' });
        }

        const twoFA = twoFactorCodes[token];
        if (!twoFA) {
            return jsonResponse(res, 400, { success: false, error: 'Verification code has expired. Please log in again.' });
        }

        if (Date.now() - twoFA.created > 600000) {
            delete twoFactorCodes[token];
            return jsonResponse(res, 400, { success: false, error: 'Verification code has expired. Please log in again.' });
        }

        twoFA.attempts++;
        if (twoFA.attempts > 5) {
            delete twoFactorCodes[token];
            return jsonResponse(res, 400, { success: false, error: 'Too many attempts. Please log in again.' });
        }

        if (twoFA.code !== code.trim()) {
            return jsonResponse(res, 400, { success: false, error: 'Invalid code. Please try again.' });
        }

        delete twoFactorCodes[token];

        const user = (await pool.query('SELECT * FROM users WHERE id = $1', [twoFA.userId])).rows[0];
        if (!user) {
            return jsonResponse(res, 400, { success: false, error: 'User not found. Please log in again.' });
        }

        await createSessionForUser(res, user);
        const dest = getOnboardingRedirect(user);
        console.log('2FA verified for user:', maskEmail(twoFA.email), '- redirecting to:', dest);
        jsonResponse(res, 200, { success: true, redirect: dest });
    } catch (error) {
        console.error('2FA verification error:', error);
        jsonResponse(res, 500, { success: false, error: 'An error occurred during verification' });
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
                legalLastName: user.legal_last_name,
                emailVerified: user.email_verified || false
            },
            onboarding: {
                completed: user.onboarding_completed,
                termsAccepted: user.terms_accepted,
                accreditationCompleted: user.accreditation_completed,
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

async function handleTermsAcceptance(req, res) {
    const sessionData = getSessionUser(req);
    if (!sessionData) {
        return jsonResponse(res, 401, { success: false, error: 'Not authenticated' });
    }

    const { accepted } = await parseBody(req);
    if (!accepted) {
        return jsonResponse(res, 400, { success: false, error: 'You must accept the terms to continue' });
    }

    await pool.query(
        'UPDATE users SET terms_accepted = TRUE, updated_at = NOW() WHERE id = $1',
        [sessionData.userId]
    );

    const user = (await pool.query('SELECT * FROM users WHERE id = $1', [sessionData.userId])).rows[0];

    const allComplete = ONBOARDING_STEPS.every(step => user[step.key]);
    if (allComplete) {
        await pool.query('UPDATE users SET onboarding_completed = TRUE, updated_at = NOW() WHERE id = $1', [user.id]);
    }

    const nextStep = getNextOnboardingStep(user);
    const dest = nextStep ? nextStep.page : '/dashboard.html';

    console.log('Terms accepted for user:', user.email, '- next:', dest);
    jsonResponse(res, 200, { success: true, redirect: dest });
}

async function handleAccreditation(req, res) {
    const sessionData = getSessionUser(req);
    if (!sessionData) {
        return jsonResponse(res, 401, { success: false, error: 'Not authenticated' });
    }

    const { status } = await parseBody(req);
    if (!status) {
        return jsonResponse(res, 400, { success: false, error: 'Please select an option' });
    }

    await pool.query(
        'UPDATE users SET accreditation_status = $1, accreditation_completed = TRUE, updated_at = NOW() WHERE id = $2',
        [status, sessionData.userId]
    );

    const user = (await pool.query('SELECT * FROM users WHERE id = $1', [sessionData.userId])).rows[0];

    const allComplete = ONBOARDING_STEPS.every(step => user[step.key]);
    if (allComplete) {
        await pool.query('UPDATE users SET onboarding_completed = TRUE, updated_at = NOW() WHERE id = $1', [user.id]);
    }

    const nextStep = getNextOnboardingStep(user);
    const dest = nextStep ? nextStep.page : '/dashboard.html';

    console.log('Accreditation saved for user:', user.email, '- status:', status, '- next:', dest);
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

const PROTECTED_PAGES = ['/dashboard.html', '/legal-name.html', '/mobile-phone.html', '/signup/terms-review', '/signup/accreditation', '/signup/terms-review.html', '/signup/accreditation.html'];
const ONBOARDING_PAGES = ['/legal-name.html', '/mobile-phone.html', '/signup/terms-review', '/signup/accreditation', '/signup/terms-review.html', '/signup/accreditation.html'];

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
    if (req.method === 'POST' && urlPath === '/api/verify-2fa') {
        return handleVerify2FA(req, res);
    }
    if (req.method === 'POST' && urlPath === '/api/onboarding/terms') {
        return handleTermsAcceptance(req, res);
    }
    if (req.method === 'POST' && urlPath === '/api/onboarding/accreditation') {
        return handleAccreditation(req, res);
    }
    if (req.method === 'POST' && urlPath === '/api/onboarding/legal-name') {
        return handleSaveLegalName(req, res);
    }
    if (req.method === 'GET' && urlPath === '/api/onboarding/status') {
        return handleOnboardingStatus(req, res);
    }

    if (req.method === 'POST' && urlPath === '/send-verification') {
        try {
            const sessionData = getSessionUser(req);
            const body = await parseBody(req);
            var targetEmail = null;

            if (sessionData) {
                const user = await getFullUser(sessionData);
                if (user) {
                    targetEmail = user.email;
                    if (user.email_verified) {
                        return jsonResponse(res, 200, { success: true, message: 'Already verified' });
                    }
                }
            }

            if (!targetEmail && body.email) {
                const existingUser = (await pool.query('SELECT id FROM users WHERE email = $1', [body.email])).rows[0];
                if (existingUser) {
                    targetEmail = body.email;
                }
            }

            if (!targetEmail) {
                return jsonResponse(res, 400, { success: false, error: 'Email not found' });
            }

            const recentTokens = Object.values(emailVerificationTokens).filter(t => t.email === targetEmail && Date.now() - t.createdAt < 60000);
            if (recentTokens.length > 0) {
                return jsonResponse(res, 429, { success: false, error: 'Please wait before requesting another email' });
            }

            const token = crypto.randomBytes(32).toString('hex');
            emailVerificationTokens[token] = { email: targetEmail, createdAt: Date.now() };
            const verifyLink = `${BASE_URL}/api/verify-email?token=${token}`;
            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: targetEmail,
                subject: 'Verify your WillowWealth account',
                html: `
                    <div style="font-family: 'Inter', Arial, sans-serif; max-width: 480px; margin: 0 auto; padding: 40px 20px;">
                        <h1 style="font-size: 24px; color: #1a2b23; margin-bottom: 16px;">Welcome to WillowWealth</h1>
                        <p style="font-size: 14px; color: #4b5563; line-height: 1.6;">Please click the button below to verify your email address and complete your setup:</p>
                        <a href="${verifyLink}" style="background-color: #002e30; color: white; padding: 14px 28px; text-decoration: none; border-radius: 50px; display: inline-block; margin: 24px 0; font-weight: 600;">Verify Email Address</a>
                        <p style="font-size: 12px; color: #9ca3af;">If you did not create an account, please ignore this email. This link expires in 24 hours.</p>
                    </div>
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

    if (req.method === 'GET' && urlPath === '/api/verify-email') {
        try {
            const urlParams = new URL(req.url, BASE_URL).searchParams;
            const token = urlParams.get('token');
            if (!token || !emailVerificationTokens[token]) {
                res.writeHead(200, { 'Content-Type': 'text/html', 'Cache-Control': 'no-cache' });
                res.end(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Verification Failed</title><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet"></head><body style="font-family:'Inter',sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f8fafb;"><div style="text-align:center;max-width:400px;padding:40px;"><h1 style="color:#dc2626;font-size:24px;">Verification Failed</h1><p style="color:#64748b;">This verification link is invalid or has expired.</p><a href="/legal-name.html" style="color:#002e30;font-weight:600;">Return to your account</a></div></body></html>`);
                return;
            }
            const tokenData = emailVerificationTokens[token];
            const elapsed = Date.now() - tokenData.createdAt;
            if (elapsed > 24 * 60 * 60 * 1000) {
                delete emailVerificationTokens[token];
                res.writeHead(200, { 'Content-Type': 'text/html', 'Cache-Control': 'no-cache' });
                res.end(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Link Expired</title><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet"></head><body style="font-family:'Inter',sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f8fafb;"><div style="text-align:center;max-width:400px;padding:40px;"><h1 style="color:#dc2626;font-size:24px;">Link Expired</h1><p style="color:#64748b;">This verification link has expired. Please request a new one.</p><a href="/legal-name.html" style="color:#002e30;font-weight:600;">Return to your account</a></div></body></html>`);
                return;
            }
            await pool.query('UPDATE users SET email_verified = TRUE, updated_at = NOW() WHERE email = $1', [tokenData.email]);
            delete emailVerificationTokens[token];
            res.writeHead(200, { 'Content-Type': 'text/html', 'Cache-Control': 'no-cache' });
            res.end(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Email Verified</title><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet"></head><body style="font-family:'Inter',sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f8fafb;"><div style="text-align:center;max-width:400px;padding:40px;"><div style="width:64px;height:64px;border-radius:50%;background:#d1fae5;display:flex;align-items:center;justify-content:center;margin:0 auto 24px;"><svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg></div><h1 style="color:#1a2b23;font-size:24px;">Email Verified!</h1><p style="color:#64748b;">Your email address has been successfully verified.</p><a href="/legal-name.html" style="display:inline-block;background:#002e30;color:white;padding:14px 28px;border-radius:50px;text-decoration:none;font-weight:600;margin-top:16px;">Continue Setup</a></div></body></html>`);
        } catch (error) {
            console.error('Email verification error:', error);
            res.writeHead(500, { 'Content-Type': 'text/html' });
            res.end('Verification failed. Please try again.');
        }
        return;
    }

    if (req.method === 'GET' && urlPath === '/api/email-verification-status') {
        const sessionData = getSessionUser(req);
        if (!sessionData) {
            return jsonResponse(res, 401, { verified: false });
        }
        try {
            const result = await pool.query('SELECT email_verified FROM users WHERE id = $1', [sessionData.userId]);
            const verified = result.rows[0]?.email_verified || false;
            jsonResponse(res, 200, { verified });
        } catch (error) {
            jsonResponse(res, 500, { verified: false });
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

        var normalizedUrl = urlPath.replace(/\.html$/, '');
        var normalizedCorrect = correctPage.replace(/\.html$/, '');
        if (ONBOARDING_PAGES.includes(urlPath) && normalizedUrl !== normalizedCorrect) {
            return redirect(res, correctPage);
        }
    }

    const cleanRoutes = {
        '/signup/terms-review': '/signup/terms-review.html',
        '/signup/accreditation': '/signup/accreditation.html'
    };
    let filePath = urlPath === '/' ? '/index.html' : (cleanRoutes[urlPath] || urlPath);
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
    console.log(`Apple OAuth: ${APPLE_CLIENT_ID ? 'configured' : 'NOT configured - set APPLE_CLIENT_ID, APPLE_TEAM_ID, APPLE_KEY_ID, APPLE_PRIVATE_KEY'}`);
    console.log(`Onboarding steps: ${ONBOARDING_STEPS.map(s => s.key).join(', ')}`);
});
