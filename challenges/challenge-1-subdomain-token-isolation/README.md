# Challenge 1: Subdomain Token Isolation

**The question:** your company runs many apps under one domain. Users should log in once. Is one session cookie for the whole domain a good idea?

**The short answer:** no. One weak subdomain then compromises all of them. In this challenge you watch that happen in your own browser, and then you fix it.

You will:

1. Log in with a cookie scoped to the whole domain and watch an untrusted sibling subdomain use it.
2. Switch to a host-only cookie plus a short-lived token that is tied to one subdomain.
3. Steal that token, replay it from the sibling, and watch the API answer `403`.

## Quickstart

You need Node.js 18 or newer.

```bash
npm install && npm start
```

Then open <http://gaming.lab.localhost:3000>.

There is no hosts file to edit. Modern browsers send every name that ends in `.localhost` to your own machine.

To run the automated check instead of clicking:

```bash
npm run check
```

## The cast

One Node process plays four hosts. It reads the `Host` header of each request and answers as the matching server.

| Host | Role | Think of it as |
| --- | --- | --- |
| `auth.lab.localhost:3000` | Identity provider (IdP) | The login service |
| `api.lab.localhost:3000` | Resource server | The API that holds user data |
| `gaming.lab.localhost:3000` | Tenant A | A legitimate app. The user wants to be here |
| `finance.lab.localhost:3000` | Sibling B | An app you do not trust. Someone else runs it, or it was taken over |

There is one demo user, Alice, and no password. Logging in is a button.

## First principles

You only need five ideas for this challenge.

### 1. An origin is the browser's wall

An **origin** is three things together: scheme, host and port.

```
http://gaming.lab.localhost:3000
\__/   \__________________/ \__/
scheme        host          port
```

`http://gaming.lab.localhost:3000` and `http://finance.lab.localhost:3000` are **different origins**, because the hosts differ. A page from one origin cannot read pages, storage or responses that belong to another. This rule is the same-origin policy, and almost all browser security rests on it.

### 2. Cookies do not follow that wall

Cookies are older than the same-origin policy and use a looser rule. A cookie belongs to a **domain**, not to an origin.

When a server sets a cookie, it chooses how wide the cookie goes:

| What the server sends | Who gets the cookie |
| --- | --- |
| `Set-Cookie: id=1` (no `Domain`) | Only the exact host that set it. This is a **host-only** cookie |
| `Set-Cookie: id=1; Domain=.lab.localhost` | `lab.localhost` and **every subdomain under it** |

So `auth` can set a cookie that the browser will also send to `gaming`, `finance` and `api`. The wall from idea 1 does not stop it.

### 3. The apex domain and the Public Suffix List

How wide can a cookie go? Up to the **registrable domain**, also called the **apex**. That is the part you can register, plus one label: `example.com`, `example.co.uk`.

A browser cannot guess where that boundary is. `co.uk` looks like a domain, but it is shared by thousands of unrelated companies. So browsers ship a list of such shared endings, the [Public Suffix List](https://publicsuffix.org). It holds entries like `com`, `co.uk` and `github.io`. A browser refuses any cookie whose `Domain` is a public suffix. Otherwise one site could set a cookie for all of `.com`.

Two origins that share a registrable domain are called **same-site**. `gaming.lab.localhost` and `finance.lab.localhost` are different origins but the same site.

> **Why this challenge uses `lab.localhost` and not plain `localhost`.** A name with no entry on the list is treated like a top-level domain. So `localhost` counts as a public suffix, just like `com`. We tested it: Chromium silently drops `Set-Cookie: ...; Domain=.localhost` when it comes from `auth.localhost`. One level deeper it works. `lab.localhost` plays the role that `example.com` plays in real life.

### 4. `credentials: "include"`

By default, `fetch` does not send cookies to a different origin. A page has to ask for it:

```js
fetch('http://api.lab.localhost:3000/api/cookie-data', { credentials: 'include' });
```

Now the browser attaches every cookie that matches the **destination**. Notice what it does not ask: which page is making the request. A cookie says who the user is. It says nothing about which app is asking. Security people call this **ambient authority**.

The API must agree before the page may read the answer. It has to reply with `Access-Control-Allow-Credentials: true` and name the exact origin in `Access-Control-Allow-Origin`. A wildcard `*` is not allowed here. This challenge's API does that strictly, with an allow list. It still leaks, because `finance` is a real, allowed app. CORS decides who may read a response. It does not decide which cookies get attached.

What about `SameSite=Lax`? It stops cookies on requests that come from a different **site**. Sibling subdomains are the same site, so `SameSite` does nothing here.

### 5. Blast radius

When one part of a system is broken into, how much else falls with it? That amount is the **blast radius**.

| Design | If `finance` is compromised, the attacker gets |
| --- | --- |
| One apex cookie | The user's session for every app, for as long as the session lives |
| Host-only cookie plus scoped tokens | Only what `finance` could already do |

Good security design is mostly about keeping that radius small.

## The dashboard

Every page shows the same four areas.

- **Context banner.** Which origin you are on, what `document.cookie` holds (what scripts on this page can read), what the IdP says about your session, and which token the page holds in memory.
- **Experiments.** One button per step.
- **Traffic flow.** Packets move between the browser, the IdP, the two subdomains and the API. Green means isolated or verified. Red means a leaked cookie or a blocked attack. Every packet is a real HTTP request, and each one is listed below the picture.
- **JWT inspector and last response.** The decoded token, with the `tenant` claim highlighted, and the raw JSON the server sent back.

Keep the terminal visible too. The server prints every request with the host that received it.

## Experiment 1: the apex cookie leak

1. Open <http://gaming.lab.localhost:3000>.
2. Click **Log in: vulnerable (apex cookie)**. The IdP answers with:

   ```
   Set-Cookie: master_session=...; Domain=.lab.localhost; Path=/; SameSite=Lax
   ```

   Look at the banner. `document.cookie` now shows `master_session`, on a page that is not the IdP.
3. Click **Trigger apex cookie leak**. The API answers `200`. So far this looks like a feature: one login, and the app works.
4. Now switch to <http://finance.lab.localhost:3000> with the tabs at the top. You did nothing on this page, yet the banner already shows `master_session`. The untrusted sibling can read your session id.
5. Click **Trigger apex cookie leak** here. The packets turn red. The API answers `200` again and returns the whole account, gaming data included.

**What happened.** `finance` never logged you in. Its script called the API with `credentials: 'include'`, and the browser attached the cookie because the cookie covers `.lab.localhost`. The API saw a valid session and had no way to tell which app was asking.

## Experiment 2: the scoped token

1. On either page, click **Log in: hardened (host-only cookie)**. This time the IdP answers with:

   ```
   Set-Cookie: auth_idp_session=...; Path=/; HttpOnly; SameSite=Lax
   ```

   There is no `Domain` attribute, so the cookie is locked to `auth.lab.localhost`. Look at the banner: `document.cookie` is empty, but the IdP session line says you are logged in.
2. Click **Trigger apex cookie leak** again, on `finance` if you like. The API answers `401`. No cookie reached it. There is nothing left to leak.
3. Go to `gaming` and click **Request scoped JWT**. The page calls `auth.lab.localhost/mint-token?tenant=gaming.lab.localhost`. The browser sends the host-only cookie, because this request goes to `auth`. The IdP answers with a signed token.
4. Read the **JWT inspector**:

   | Claim | Meaning |
   | --- | --- |
   | `iss` | Who issued the token: the IdP |
   | `aud` | Who the token is for: the API |
   | `sub` | The user |
   | `tenant` | The one subdomain that may use this token |
   | `exp` | When it stops working: 120 seconds after it was issued |

5. Click **Call API with token**. The API answers `200` and returns only the gaming slice of the account.

**What changed.** The long-lived secret, the session cookie, never leaves `auth`. Each app holds a short-lived token in a JavaScript variable. The token says which app it belongs to, and the API checks that.

## Experiment 3: token theft and replay

A token in page memory can still be stolen, for example through a script injection bug on `gaming`. Suppose the attacker on `finance` gets a valid gaming token. How much is it worth?

1. On `gaming`, with a hardened login, click **Simulate token theft / replay attack**.
2. The page hands its token to `finance`. This hand-off is the only simulated part. Everything after it is real.
3. You land on `finance`. It sends the stolen token to `GET /api/secure-data` right away.
4. The API answers **`403 Forbidden`** with `tenant_mismatch`.

**Why it failed.** The API first verified the signature, so it knows the token is real. Then it ran this check from `server.js`:

```js
const originHost = new URL(req.headers.origin).hostname;
if (payload.tenant !== originHost) {
  return res.status(403).json({ error: 'tenant_mismatch' /* ... */ });
}
```

The token says `gaming.lab.localhost`. The browser set the `Origin` header to `http://finance.lab.localhost:3000`, and no page script can change that header. The two do not match, so the request is refused.

Two more things to try on `finance`:

- Click **Ask the IdP for a gaming token**. The IdP answers `403`. It compares the `tenant` you ask for with the `Origin` of the page that asks, so a sibling cannot simply request someone else's token.
- Click **Request scoped JWT** and then **Call API with token**. `finance` gets its own token and its own data, and nothing more. That is the small blast radius from idea 5.

The attacker also cannot edit the token to say `tenant: finance`. Changing one character breaks the signature, and the API answers `401`. `npm run check` proves that too.

## Where to look in the code

Everything is in `server.js`, top to bottom:

| Look for | What it shows |
| --- | --- |
| `badCookie` and `goodCookie` | The two `Set-Cookie` lines, written out by hand |
| `cors()` | Strict CORS: an allow list, never `*`, and a `403` for unknown origins |
| `/mint-token` | The IdP binding the token to the requesting subdomain |
| `/api/cookie-data` | The endpoint that trusts any session cookie |
| `/api/secure-data` | Signature check, then the tenant check |

## Run the automated check

```bash
npm run check
```

The script starts its own copy of the server on port 3100. It then calls it with `curl`, setting the `Host` and `Origin` headers by hand, and checks more than thirty facts: the exact cookie attributes, the leak, the token claims, the `403` on replay, the `401` on a tampered token.

If port 3100 is taken, pick another one:

```bash
CHECK_PORT=3200 npm run check
```

`curl` sends whatever cookies you tell it to. It cannot prove how a real browser scopes them. That is what the dashboard is for.

## What this challenge does not solve

Be honest about the limits of the fix.

- **The `Origin` check only stops browsers.** A browser always sets `Origin` truthfully. A script outside a browser, such as `curl`, can send any `Origin` it likes. If a token leaves the browser, the tenant check alone will not save you. That is why the token lives for only two minutes. Stronger answers bind the token to a key the client holds (DPoP, mutual TLS).
- **A bug on `gaming` is still a bug on `gaming`.** An attacker who can run script on `gaming` can use the gaming token from there. The fix keeps that damage inside one app. It does not remove it.
- **Logging out does not cancel tokens.** A token that was already minted works until it expires. Short lifetimes keep that window small. Challenge 2 covers refresh and revocation.
- **Shortcuts taken here.** This challenge uses plain HTTP, one shared signing key (HS256) and a login with no password. A real system uses HTTPS, `Secure` cookies with the `__Host-` prefix, and asymmetric keys (RS256 or ES256) so the API only holds a public key.

## Troubleshooting

- **The page does not open.** Checked with a Chromium-based browser (Chrome 156 engine). Chrome, Edge and Firefox resolve `*.localhost` on their own. If your browser does not, add this line to your hosts file:

  ```
  127.0.0.1 auth.lab.localhost api.lab.localhost gaming.lab.localhost finance.lab.localhost
  ```

- **Port 3000 is in use.** Start on another port with `PORT=3001 npm start` (PowerShell: `$env:PORT=3001; npm start`) and use that port in the URLs.
- **Every button gives `401` after a restart.** Sessions and the signing key live in memory. Log in again.

## Go further

- In `server.js`, delete the tenant check in `/api/secure-data` and run `npm run check`. Which line fails?
- Add `HttpOnly` to `badCookie`. `finance` can no longer read the session id. Does experiment 1 still leak? Why?
- See the public suffix rule for yourself: start with `LAB_APEX=localhost npm start`, open `http://gaming.localhost:3000` and log in the vulnerable way. The cookie never appears.
