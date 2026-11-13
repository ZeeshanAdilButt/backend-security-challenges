// Lab 01: subdomain token isolation.
//
// One Node process pretends to be four different hosts. It looks at the Host
// header (req.hostname) and routes each request to the matching "server":
//
//   auth.<apex>     the identity provider (IdP). It logs you in.
//   api.<apex>      the resource server. It holds the data.
//   gaming.<apex>   tenant A, a legitimate app.
//   finance.<apex>  sibling B, an app we do not trust.
//
// This is a local teaching lab. It binds to 127.0.0.1 only, has one demo user
// and no passwords. Do not deploy it.

import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import jwt from 'jsonwebtoken';

const PORT = Number(process.env.PORT) || 3000;

// The shared parent domain of the four hosts. The lab README explains why this
// is "lab.localhost" and not plain "localhost".
const APEX = (process.env.LAB_APEX || 'lab.localhost').toLowerCase();

const HOSTS = {
  auth: `auth.${APEX}`,
  api: `api.${APEX}`,
  gaming: `gaming.${APEX}`,
  finance: `finance.${APEX}`,
};
const ROLE_BY_HOST = Object.fromEntries(Object.entries(HOSTS).map(([role, host]) => [host, role]));
const originOf = (host) => `http://${host}:${PORT}`;

// Pages that are allowed to call auth and api from the browser.
const WEB_ORIGINS = new Set([HOSTS.auth, HOSTS.gaming, HOSTS.finance].map(originOf));
// Hosts that can own a token. The IdP itself is not a tenant.
const TENANT_HOSTS = new Set([HOSTS.gaming, HOSTS.finance]);

// The JWT signing key is random and lives only in memory. Every restart makes
// a new one, so there is no secret to commit and old tokens stop working.
const JWT_KEY = crypto.randomBytes(32);
const ISSUER = originOf(HOSTS.auth);
const AUDIENCE = originOf(HOSTS.api);
const TOKEN_TTL_SECONDS = 120;
const SESSION_TTL_SECONDS = 3600;

// One demo user. "Login" is a button, so nobody types a password in this lab.
const USER = { id: 'user-1001', name: 'Alice Demo' };

// What the API protects, split per tenant.
const ACCOUNT = {
  [HOSTS.gaming]: { handle: 'alice_plays', level: 42, guild: 'Night Owls' },
  [HOSTS.finance]: { accountEnding: '4821', balanceUsd: 12850.75 },
};

// Server-side sessions: session id -> { userId, mode }.
const sessions = new Map();

function newSession(mode) {
  const id = crypto.randomBytes(16).toString('hex');
  sessions.set(id, { userId: USER.id, mode });
  return id;
}

function readCookies(req) {
  const cookies = {};
  for (const part of (req.headers.cookie || '').split(';')) {
    const eq = part.indexOf('=');
    if (eq > 0) cookies[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
  }
  return cookies;
}

// The two cookies, written out by hand so you can read the exact attributes.
//
// Vulnerable: Domain=.<apex> tells the browser to send this cookie to the apex
// and to EVERY subdomain under it. There is no HttpOnly, so page scripts on
// every subdomain can also read it.
const badCookie = (id) =>
  `master_session=${id}; Domain=.${APEX}; Path=/; Max-Age=${SESSION_TTL_SECONDS}; SameSite=Lax`;
// Hardened: no Domain attribute makes it "host-only". The browser sends it to
// auth.<apex> and nowhere else. HttpOnly hides it from every page script.
const goodCookie = (id) =>
  `auth_idp_session=${id}; Path=/; Max-Age=${SESSION_TTL_SECONDS}; HttpOnly; SameSite=Lax`;
const clearBadCookie = `master_session=; Domain=.${APEX}; Path=/; Max-Age=0; SameSite=Lax`;
const clearGoodCookie = 'auth_idp_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax';

function dropSessions(req) {
  const cookies = readCookies(req);
  sessions.delete(cookies.master_session);
  sessions.delete(cookies.auth_idp_session);
}

// Strict, dynamic CORS. We never answer with "*". We echo the Origin back only
// when it is on the allow list, and we refuse the request when it is not.
function cors({ credentials }) {
  return (req, res, next) => {
    res.vary('Origin');
    const origin = req.headers.origin;
    if (origin) {
      if (!WEB_ORIGINS.has(origin)) {
        return res.status(403).json({ error: 'origin_not_allowed', origin });
      }
      res.set('Access-Control-Allow-Origin', origin);
      if (credentials) res.set('Access-Control-Allow-Credentials', 'true');
    }
    if (req.method === 'OPTIONS') {
      // Preflight: the browser asks first when a request carries Authorization.
      res.set('Access-Control-Allow-Methods', 'GET, POST');
      res.set('Access-Control-Allow-Headers', 'Authorization, Content-Type');
      res.set('Access-Control-Max-Age', '600');
      return res.sendStatus(204);
    }
    next();
  };
}

const here = path.dirname(fileURLToPath(import.meta.url));
const sendDashboard = (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.sendFile(path.join(here, 'public', 'dashboard.html'));
};

// ---------------------------------------------------------------------------
// auth.<apex>: the identity provider
// ---------------------------------------------------------------------------
const auth = express.Router();
auth.get('/', sendDashboard);
auth.use(cors({ credentials: true }));

// Vulnerable login: one cookie for the whole apex.
function loginBad(req, res) {
  dropSessions(req);
  const id = newSession('vulnerable');
  res.append('Set-Cookie', badCookie(id));
  res.append('Set-Cookie', clearGoodCookie);
  res.json({
    ok: true,
    mode: 'vulnerable',
    cookie: 'master_session',
    scope: `.${APEX} (the apex and every subdomain)`,
  });
}

// Hardened login: a host-only cookie that never leaves auth.<apex>.
function loginGood(req, res) {
  dropSessions(req);
  const id = newSession('hardened');
  res.append('Set-Cookie', goodCookie(id));
  res.append('Set-Cookie', clearBadCookie);
  res.json({
    ok: true,
    mode: 'hardened',
    cookie: 'auth_idp_session',
    scope: `${HOSTS.auth} only (host-only, HttpOnly)`,
  });
}

function logout(req, res) {
  dropSessions(req);
  res.append('Set-Cookie', clearBadCookie);
  res.append('Set-Cookie', clearGoodCookie);
  res.json({ ok: true });
}

// GET is accepted too so you can try these from the address bar or curl.
auth.route('/login-bad').get(loginBad).post(loginBad);
auth.route('/login-good').get(loginGood).post(loginGood);
auth.route('/logout').get(logout).post(logout);

// Lets a dashboard show whether the IdP knows you, even when the page itself
// cannot see any cookie.
auth.get('/session', (req, res) => {
  const cookies = readCookies(req);
  const session = sessions.get(cookies.auth_idp_session) || sessions.get(cookies.master_session);
  res.set('Cache-Control', 'no-store');
  res.json(session ? { loggedIn: true, mode: session.mode, user: USER.name } : { loggedIn: false });
});

// Mint a short-lived token for ONE tenant.
// The tenant is not taken on trust from the query string. It must match the
// Origin header, which the browser sets and page scripts cannot change. So a
// page on finance cannot ask for a token that says "gaming".
auth.get('/mint-token', (req, res) => {
  res.set('Cache-Control', 'no-store');
  const session = sessions.get(readCookies(req).auth_idp_session);
  if (!session || session.mode !== 'hardened') {
    return res.status(401).json({
      error: 'no_idp_session',
      message: 'No hardened IdP session. Log in with /login-good first.',
    });
  }
  const tenant = String(req.query.tenant || '').toLowerCase();
  if (!TENANT_HOSTS.has(tenant)) {
    return res.status(400).json({ error: 'unknown_tenant', tenant });
  }
  const origin = req.headers.origin;
  if (!origin || new URL(origin).hostname !== tenant) {
    return res.status(403).json({
      error: 'tenant_origin_mismatch',
      message: 'A page can only get a token for its own subdomain.',
      requestedTenant: tenant,
      requestOrigin: origin || null,
    });
  }
  const token = jwt.sign({ tenant }, JWT_KEY, {
    algorithm: 'HS256',
    issuer: ISSUER,
    audience: AUDIENCE,
    subject: session.userId,
    expiresIn: TOKEN_TTL_SECONDS,
  });
  res.json({ token, token_type: 'Bearer', expires_in: TOKEN_TTL_SECONDS, tenant });
});

// ---------------------------------------------------------------------------
// api.<apex>: the resource server
// ---------------------------------------------------------------------------
const api = express.Router();

// Cookie-authenticated endpoint. It trusts whatever session cookie arrives.
// With an apex cookie, the browser attaches it for every sibling subdomain,
// so every sibling gets the whole account.
api.use('/api/cookie-data', cors({ credentials: true }));
api.get('/api/cookie-data', (req, res) => {
  res.set('Cache-Control', 'no-store');
  const cookies = readCookies(req);
  const session = sessions.get(cookies.master_session);
  if (!session || session.mode !== 'vulnerable') {
    return res.status(401).json({
      error: 'no_session_cookie',
      message: 'No valid master_session cookie reached the API.',
      cookiesReceived: Object.keys(cookies),
    });
  }
  res.json({
    ok: true,
    authenticatedBy: 'cookie master_session',
    cookieScope: `.${APEX}`,
    requestOrigin: req.headers.origin || null,
    user: USER,
    // No tenant check is possible here: the cookie says who you are, not
    // which app is asking. So the answer is the whole account.
    data: ACCOUNT,
  });
});

// Token-authenticated endpoint. No cookies involved, so no credentials flag.
api.use('/api/secure-data', cors({ credentials: false }));
api.get('/api/secure-data', (req, res) => {
  res.set('Cache-Control', 'no-store');
  const match = /^Bearer (\S+)$/.exec(req.headers.authorization || '');
  if (!match) {
    return res.status(401).json({ error: 'missing_token', message: 'Send Authorization: Bearer <token>.' });
  }
  let payload;
  try {
    // Checks the signature, the expiry, the issuer and the audience.
    payload = jwt.verify(match[1], JWT_KEY, { algorithms: ['HS256'], issuer: ISSUER, audience: AUDIENCE });
  } catch (err) {
    return res.status(401).json({ error: 'invalid_token', message: err.message });
  }
  const origin = req.headers.origin;
  if (!origin) {
    return res.status(403).json({ error: 'origin_required', message: 'This endpoint needs an Origin header.' });
  }
  // The check this lab is about: the token must be used from the subdomain
  // it was minted for. A valid token replayed from a sibling stops here.
  const originHost = new URL(origin).hostname;
  if (payload.tenant !== originHost) {
    return res.status(403).json({
      error: 'tenant_mismatch',
      message: 'Valid token, wrong subdomain. Replay blocked.',
      tokenTenant: payload.tenant,
      requestOrigin: originHost,
    });
  }
  res.json({
    ok: true,
    authenticatedBy: 'bearer token',
    tenant: payload.tenant,
    user: payload.sub,
    // Only this tenant's slice of the account. That is the blast radius.
    data: ACCOUNT[payload.tenant],
  });
});

api.use((req, res) => res.status(404).json({ error: 'not_found' }));

// ---------------------------------------------------------------------------
// gaming.<apex> and finance.<apex>: the two apps. Both serve the dashboard.
// ---------------------------------------------------------------------------
const tenant = express.Router();
tenant.get('/', sendDashboard);

// ---------------------------------------------------------------------------
// One port, four hosts.
// ---------------------------------------------------------------------------
const app = express();
app.disable('x-powered-by');

app.use((req, res, next) => {
  const role = ROLE_BY_HOST[req.hostname];
  res.on('finish', () => {
    const from = req.headers.origin ? ` origin=${req.headers.origin}` : '';
    console.log(`[${role || 'unknown host'}] ${req.method} ${req.originalUrl}${from} -> ${res.statusCode}`);
  });
  if (role === 'auth') return auth(req, res, next);
  if (role === 'api') return api(req, res, next);
  if (role) return tenant(req, res, next);
  // Any other name (for example plain localhost) goes to the gaming dashboard.
  res.redirect(`${originOf(HOSTS.gaming)}/`);
});

app.use((req, res) => res.status(404).json({ error: 'not_found' }));

// 127.0.0.1 only: nothing outside this machine can reach the lab.
app.listen(PORT, '127.0.0.1', () => {
  console.log(`Lab 01 is listening on 127.0.0.1:${PORT}`);
  console.log(`  identity provider  ${originOf(HOSTS.auth)}`);
  console.log(`  tenant A (trusted) ${originOf(HOSTS.gaming)}`);
  console.log(`  sibling B          ${originOf(HOSTS.finance)}`);
  console.log(`  resource server    ${originOf(HOSTS.api)}`);
  console.log(`Open ${originOf(HOSTS.gaming)} in your browser to start.`);
});
