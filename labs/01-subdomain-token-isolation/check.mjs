// Automated check for Lab 01. Run it with: npm run check
//
// It starts its own copy of the server on a spare port, then uses curl with
// custom Host and Origin headers against 127.0.0.1 to prove that the
// vulnerable and the hardened endpoints behave the way the README says.
//
// curl cannot prove what a real browser does with cookies. For that part,
// follow the walkthrough in README.md.

import { execFileSync, spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const PORT = process.env.CHECK_PORT || '3100';
const APEX = process.env.LAB_APEX || 'lab.localhost';
const BASE = `http://127.0.0.1:${PORT}`;
const CURL = process.platform === 'win32' ? 'curl.exe' : 'curl';
const here = path.dirname(fileURLToPath(import.meta.url));

const hostOf = (name) => `${name}.${APEX}`;
const originOf = (name) => `http://${hostOf(name)}:${PORT}`;

// One curl call. Returns { status, headers, setCookie, json }.
function curl({ host, url, method = 'GET', origin, cookie, bearer, headers = [] }) {
  const args = ['-s', '-i', '--max-time', '5', '-X', method, '-H', `Host: ${hostOf(host)}:${PORT}`];
  if (origin) args.push('-H', `Origin: ${origin}`);
  if (cookie) args.push('-H', `Cookie: ${cookie}`);
  if (bearer) args.push('-H', `Authorization: Bearer ${bearer}`);
  for (const header of headers) args.push('-H', header);
  args.push(BASE + url);
  const raw = execFileSync(CURL, args, { encoding: 'utf8' });
  const split = raw.indexOf('\r\n\r\n');
  const head = raw.slice(0, split).split('\r\n');
  const body = raw.slice(split + 4);
  const result = { status: Number(head[0].split(' ')[1]), headers: {}, setCookie: [], json: null };
  for (const line of head.slice(1)) {
    const colon = line.indexOf(':');
    const name = line.slice(0, colon).toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (name === 'set-cookie') result.setCookie.push(value);
    else result.headers[name] = value;
  }
  try { result.json = JSON.parse(body); } catch { /* not JSON */ }
  return result;
}

let passed = 0;
let failed = 0;
function check(name, ok, got) {
  if (ok) {
    passed += 1;
    console.log(`  PASS  ${name}`);
  } else {
    failed += 1;
    console.log(`  FAIL  ${name}${got === undefined ? '' : `  (got: ${JSON.stringify(got)})`}`);
  }
}

const findCookie = (res, name) => res.setCookie.find((c) => c.startsWith(`${name}=`) && !c.startsWith(`${name}=;`));
const cookiePair = (setCookie) => setCookie.split(';')[0];
const decodePayload = (token) => JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));

function runChecks() {
  const gaming = originOf('gaming');
  const finance = originOf('finance');

  console.log('\nHosts');
  let res = curl({ host: 'gaming', url: '/' });
  check('gaming serves the dashboard', res.status === 200 && (res.headers['content-type'] || '').includes('text/html'), res.status);
  res = curl({ host: 'finance', url: '/' });
  check('finance serves the dashboard', res.status === 200, res.status);
  res = curl({ host: 'api', url: '/' });
  check('api serves no dashboard (404)', res.status === 404, res.status);

  console.log('\nVulnerable mode: apex cookie');
  res = curl({ host: 'auth', url: '/login-bad', method: 'POST', origin: gaming });
  const bad = findCookie(res, 'master_session') || '';
  check('/login-bad sets master_session', res.status === 200 && bad !== '', res.setCookie);
  check(`master_session has Domain=.${APEX}`, bad.includes(`Domain=.${APEX}`), bad);
  check('master_session has Path=/ and SameSite=Lax', bad.includes('Path=/') && bad.includes('SameSite=Lax'), bad);
  check('master_session is not HttpOnly (page scripts can read it)', !/httponly/i.test(bad), bad);
  const badPair = cookiePair(bad);

  res = curl({ host: 'api', url: '/api/cookie-data', origin: gaming, cookie: badPair });
  check('gaming + apex cookie -> 200 from /api/cookie-data', res.status === 200, res.status);
  res = curl({ host: 'api', url: '/api/cookie-data', origin: finance, cookie: badPair });
  check('LEAK: finance + the same cookie -> 200 too', res.status === 200, res.status);
  check('LEAK: finance receives gaming data', Boolean(res.json?.data?.[hostOf('gaming')]), res.json);
  check('CORS echoes the finance origin', res.headers['access-control-allow-origin'] === finance, res.headers['access-control-allow-origin']);
  check('CORS allows credentials on the cookie endpoint', res.headers['access-control-allow-credentials'] === 'true', res.headers['access-control-allow-credentials']);
  res = curl({ host: 'api', url: '/api/cookie-data', origin: 'http://evil.example', cookie: badPair });
  check('unknown origin is refused (403, no CORS headers)', res.status === 403 && !res.headers['access-control-allow-origin'], res.status);
  res = curl({ host: 'api', url: '/api/cookie-data', origin: finance });
  check('no cookie -> 401', res.status === 401, res.status);

  console.log('\nHardened mode: host-only cookie');
  res = curl({ host: 'auth', url: '/login-good', method: 'POST', origin: gaming });
  const good = findCookie(res, 'auth_idp_session') || '';
  check('/login-good sets auth_idp_session', res.status === 200 && good !== '', res.setCookie);
  check('auth_idp_session has no Domain attribute (host-only)', !/domain=/i.test(good), good);
  check('auth_idp_session is HttpOnly and SameSite=Lax', /httponly/i.test(good) && good.includes('SameSite=Lax'), good);
  const goodPair = cookiePair(good);
  res = curl({ host: 'api', url: '/api/cookie-data', origin: finance, cookie: goodPair });
  check('the API does not accept the IdP cookie (401)', res.status === 401, res.status);

  console.log('\nHardened mode: scoped tokens');
  res = curl({ host: 'auth', url: `/mint-token?tenant=${hostOf('gaming')}`, origin: gaming });
  check('/mint-token without a session -> 401', res.status === 401, res.status);
  res = curl({ host: 'auth', url: `/mint-token?tenant=${hostOf('gaming')}`, origin: gaming, cookie: badPair });
  check('/mint-token with only the apex cookie -> 401', res.status === 401, res.status);
  res = curl({ host: 'auth', url: `/mint-token?tenant=${hostOf('gaming')}`, origin: finance, cookie: goodPair });
  check('finance asking for a gaming token -> 403', res.status === 403 && res.json?.error === 'tenant_origin_mismatch', res.status);
  res = curl({ host: 'auth', url: `/mint-token?tenant=${hostOf('gaming')}`, origin: gaming, cookie: goodPair });
  const token = res.json?.token || '';
  check('gaming asking for a gaming token -> 200 with a JWT', res.status === 200 && token.split('.').length === 3, res.status);
  const claims = token ? decodePayload(token) : {};
  check('JWT has iss, aud and sub', claims.iss === originOf('auth') && claims.aud === originOf('api') && Boolean(claims.sub), claims);
  check('JWT tenant claim is the gaming host', claims.tenant === hostOf('gaming'), claims.tenant);
  check('JWT is short-lived (5 minutes or less)', claims.exp - claims.iat > 0 && claims.exp - claims.iat <= 300, claims.exp - claims.iat);

  console.log('\nResource server: /api/secure-data');
  res = curl({ host: 'api', url: '/api/secure-data', method: 'OPTIONS', origin: gaming, headers: ['Access-Control-Request-Method: GET', 'Access-Control-Request-Headers: authorization'] });
  check('preflight allows the Authorization header', res.status === 204 && /authorization/i.test(res.headers['access-control-allow-headers'] || ''), res.status);
  res = curl({ host: 'api', url: '/api/secure-data', origin: gaming, bearer: token });
  check('gaming token used from gaming -> 200', res.status === 200 && res.json?.tenant === hostOf('gaming'), res.status);
  check('response holds gaming data only', Boolean(res.json?.data?.handle) && !JSON.stringify(res.json).includes('balanceUsd'), res.json);
  res = curl({ host: 'api', url: '/api/secure-data', origin: finance, bearer: token });
  check('REPLAY: gaming token used from finance -> 403', res.status === 403 && res.json?.error === 'tenant_mismatch', res.status);
  res = curl({ host: 'api', url: '/api/secure-data', bearer: token });
  check('token with no Origin header -> 403', res.status === 403, res.status);
  const tampered = token.slice(0, -2) + (token.endsWith('AA') ? 'BB' : 'AA');
  res = curl({ host: 'api', url: '/api/secure-data', origin: gaming, bearer: tampered });
  check('tampered signature -> 401', res.status === 401 && res.json?.error === 'invalid_token', res.status);
  const forgedPayload = Buffer.from(JSON.stringify({ ...claims, tenant: hostOf('finance') })).toString('base64url');
  const forged = [token.split('.')[0], forgedPayload, token.split('.')[2]].join('.');
  res = curl({ host: 'api', url: '/api/secure-data', origin: finance, bearer: forged });
  check('tenant claim rewritten to finance -> 401 (signature no longer matches)', res.status === 401, res.status);
  res = curl({ host: 'api', url: '/api/secure-data', origin: gaming });
  check('no token -> 401', res.status === 401, res.status);

  console.log('\nLogout');
  res = curl({ host: 'auth', url: '/logout', method: 'POST', origin: gaming, cookie: goodPair });
  check('/logout clears both cookies', res.setCookie.length === 2 && res.setCookie.every((c) => c.includes('Max-Age=0')), res.setCookie);
  res = curl({ host: 'auth', url: `/mint-token?tenant=${hostOf('gaming')}`, origin: gaming, cookie: goodPair });
  check('the old session cookie no longer mints tokens (401)', res.status === 401, res.status);
}

// Start a private copy of the server, wait until it listens, run, stop.
const server = spawn(process.execPath, ['server.js'], {
  cwd: here,
  env: { ...process.env, PORT, LAB_APEX: APEX },
  stdio: ['ignore', 'pipe', 'pipe'],
});
let serverErrors = '';
server.stderr.on('data', (chunk) => { serverErrors += chunk; });

const ready = new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error('the server did not start within 10 seconds')), 10000);
  server.stdout.on('data', (chunk) => {
    if (String(chunk).includes('listening')) {
      clearTimeout(timer);
      resolve();
    }
  });
  server.on('exit', (code) => {
    clearTimeout(timer);
    reject(new Error(`the server stopped early (exit code ${code}). Is port ${PORT} in use? Try CHECK_PORT=3200.\n${serverErrors}`));
  });
});

let exitCode = 1;
try {
  await ready;
  console.log(`Lab 01 check: curl against ${BASE} with Host and Origin headers for *.${APEX}`);
  runChecks();
  console.log(`\n${passed} passed, ${failed} failed`);
  exitCode = failed === 0 ? 0 : 1;
} catch (err) {
  console.error(`Check could not run: ${err.message}`);
} finally {
  server.removeAllListeners('exit');
  server.kill();
}
process.exit(exitCode);
