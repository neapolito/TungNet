// TungNet - a small rewriting web proxy. Zero dependencies. Requires Node 18+.
// Run: node server.js   (PORT env var sets the port, default 8080)

const http = require('http');
const dns = require('dns').promises;
const net = require('net');
const crypto = require('crypto');
const { Readable } = require('stream');

const PORT = process.env.PORT || 8080;
const enc = (s) => Buffer.from(s).toString('base64url');
const dec = (s) => Buffer.from(s, 'base64url').toString();

// ---------- URL helpers ----------
function px(u, base) {
  try {
    if (u == null) return u;
    u = String(u).trim();
    if (!u || u[0] === '#' || /^(data|blob|javascript|mailto|tel|about):/i.test(u)) return u;
    if (u.startsWith('/p/')) return u;
    const a = new URL(u, base);
    if (!/^https?:$/.test(a.protocol)) return u;
    const hash = a.hash;
    a.hash = '';
    return '/p/' + enc(a.href) + hash;
  } catch { return u; }
}

function toTarget(input) {
  input = (input || '').trim();
  if (!input) return null;
  try { const u = new URL(input); if (/^https?:$/.test(u.protocol)) return u.href; } catch {}
  if (/^[\w-]+(\.[\w-]+)+(:\d+)?(\/.*)?$/.test(input)) return 'https://' + input;
  return 'https://www.google.com/search?q=' + encodeURIComponent(input);
}

// ---------- Safety: don't let the proxy reach private networks ----------
const priv = (ip) =>
  /^(10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip) || /^(::1$|fc|fd|fe80)/i.test(ip);
async function safeHost(h) {
  if (net.isIP(h)) return !priv(h);
  try { return (await dns.lookup(h, { all: true })).every((x) => !priv(x.address)); }
  catch { return false; }
}

// ---------- Per-visitor cookie jars (server side) ----------
const jars = new Map();
function getSid(req, res) {
  const m = /(?:^|;\s*)tn_sid=([^;]+)/.exec(req.headers.cookie || '');
  let sid = m && m[1];
  if (!sid || !jars.has(sid)) {
    sid = crypto.randomBytes(16).toString('hex');
    if (jars.size > 5000) jars.delete(jars.keys().next().value);
    jars.set(sid, new Map());
    res.setHeader('Set-Cookie', `tn_sid=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000`);
  }
  return jars.get(sid);
}
function storeCookies(jar, host, list) {
  for (const c of list) {
    const parts = c.split(';').map((s) => s.trim());
    const [n, ...v] = parts[0].split('=');
    let dom = host, del = false;
    for (const p of parts.slice(1)) {
      const [k, ...r] = p.split('=');
      const key = k.toLowerCase(), val = r.join('=');
      if (key === 'domain') dom = val.replace(/^\./, '').toLowerCase();
      if (key === 'max-age' && parseInt(val) <= 0) del = true;
      if (key === 'expires' && new Date(val) < new Date()) del = true;
    }
    const m = jar.get(dom) || new Map();
    del ? m.delete(n) : m.set(n, v.join('='));
    jar.set(dom, m);
  }
}
function cookieFor(jar, host) {
  const out = [];
  for (const [d, m] of jar) if (host === d || host.endsWith('.' + d)) for (const [n, v] of m) out.push(n + '=' + v);
  return out.join('; ');
}

// ---------- Rewriters ----------
const rewriteCss = (t, base) =>
  t.replace(/url\(\s*(['"]?)(.*?)\1\s*\)/gi, (m, q, u) => (/^(data:|#)/i.test(u) ? m : `url(${q}${px(u, base)}${q})`))
   .replace(/@import\s+(['"])(.*?)\1/gi, (m, q, u) => `@import ${q}${px(u, base)}${q}`);

// Runs inside every proxied page: routes dynamic requests back through TungNet.
function shim(B) {
  function enc(s) { return btoa(unescape(encodeURIComponent(s))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function px(u) {
    try {
      if (u == null) return u;
      u = String(u);
      if (!u || u[0] === '#' || /^(data|blob|javascript|mailto|tel|about):/i.test(u)) return u;
      if (u.indexOf('/p/') === 0 || u.indexOf(location.origin + '/p/') === 0) return u;
      var a = new URL(u, B);
      if (!/^https?:$/.test(a.protocol)) return u;
      var h = a.hash; a.hash = '';
      return '/p/' + enc(a.href) + h;
    } catch (e) { return u; }
  }
  var f = window.fetch;
  window.fetch = function (i, o) {
    try {
      if (typeof i === 'string' || i instanceof URL) i = px(i);
      else if (i && i.url) i = new Request(px(i.url), i);
    } catch (e) {}
    return f.call(this, i, o);
  };
  var xo = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (m, u) { arguments[1] = px(u); return xo.apply(this, arguments); };
  var sa = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function (n, v) {
    if (/^(src|href|action|poster|data-src)$/i.test(n)) v = px(v);
    return sa.call(this, n, v);
  };
  [[HTMLImageElement, 'src'], [HTMLScriptElement, 'src'], [HTMLLinkElement, 'href'], [HTMLAnchorElement, 'href'],
   [HTMLIFrameElement, 'src'], [HTMLSourceElement, 'src'], [HTMLMediaElement, 'src'], [HTMLFormElement, 'action']
  ].forEach(function (p) {
    var d = Object.getOwnPropertyDescriptor(p[0].prototype, p[1]);
    if (d && d.set) Object.defineProperty(p[0].prototype, p[1], {
      get: d.get, configurable: true, set: function (v) { d.set.call(this, px(v)); }
    });
  });
  var wo = window.open;
  window.open = function (u) { arguments[0] = u ? px(u) : u; return wo.apply(this, arguments); };
  ['pushState', 'replaceState'].forEach(function (k) {
    var o = history[k];
    history[k] = function (s, t, u) { try { return o.call(this, s, t, u == null ? u : px(u)); } catch (e) { return o.call(this, s, t); } };
  });
  if (navigator.serviceWorker) navigator.serviceWorker.register = function () { return Promise.reject(new Error('disabled')); };
  new MutationObserver(function (ms) {
    ms.forEach(function (m) {
      m.addedNodes.forEach(function (n) {
        if (n.nodeType !== 1) return;
        var els = [n].concat([].slice.call(n.querySelectorAll ? n.querySelectorAll('[href],[src],[action]') : []));
        els.forEach(function (e) {
          ['href', 'src', 'action'].forEach(function (a) {
            var v = e.getAttribute && e.getAttribute(a);
            if (v && v.indexOf('/p/') !== 0 && !/^(#|data:|blob:|javascript:)/i.test(v)) sa.call(e, a, px(v));
          });
        });
      });
    });
  }).observe(document.documentElement, { childList: true, subtree: true });
}

function rewriteHtml(html, base) {
  html = html
    .replace(/<meta[^>]+http-equiv=["']?content-security-policy[^>]*>/gi, '')
    .replace(/<base\b[^>]*>/gi, '')
    .replace(/\s(integrity|nonce|crossorigin)=("[^"]*"|'[^']*'|[^\s>]+)/gi, '')
    .replace(/(\s(?:href|src|action|poster|data-src|formaction)\s*=\s*)("([^"]*)"|'([^']*)')/gi, (m, p, q, a, b) => {
      const v = (a !== undefined ? a : b).replace(/&amp;/g, '&');
      return p + q[0] + px(v, base) + q[0];
    })
    .replace(/(\ssrcset\s*=\s*)"([^"]*)"/gi, (m, p, v) =>
      p + '"' + v.split(',').map((s) => { const [u, ...d] = s.trim().split(/\s+/); return [px(u, base), ...d].join(' '); }).join(', ') + '"')
    .replace(/(<style[^>]*>)([\s\S]*?)(<\/style>)/gi, (m, a, c, z) => a + rewriteCss(c, base) + z)
    .replace(/(style\s*=\s*")([^"]*)"/gi, (m, a, c) => a + rewriteCss(c, base) + '"');
  const tag = `<script>(${shim.toString()})(${JSON.stringify(base).replace(/</g, '\\u003c')})</script>`;
  return /<head[^>]*>/i.test(html) ? html.replace(/<head[^>]*>/i, (m) => m + tag) : tag + html;
}

// ---------- Core proxy ----------
const DROP_RES = new Set(['content-encoding', 'content-security-policy', 'content-security-policy-report-only',
  'x-frame-options', 'set-cookie', 'strict-transport-security', 'report-to', 'nel', 'transfer-encoding',
  'cross-origin-opener-policy', 'cross-origin-embedder-policy', 'cross-origin-resource-policy', 'connection']);

async function proxy(req, res, targetStr, jar) {
  let target;
  try { target = new URL(targetStr); } catch { res.writeHead(400); return res.end('Bad URL'); }
  if (!/^https?:$/.test(target.protocol) || !(await safeHost(target.hostname))) {
    res.writeHead(403, { 'content-type': 'text/plain' });
    return res.end('TungNet cannot open that address.');
  }
  const h = {
    'user-agent': req.headers['user-agent'] || 'Mozilla/5.0',
    accept: req.headers.accept || '*/*',
    'accept-language': req.headers['accept-language'] || 'en-US,en;q=0.9',
    referer: target.origin + '/',
  };
  if (req.headers.range) h.range = req.headers.range;
  if (req.headers['content-type']) h['content-type'] = req.headers['content-type'];
  if (req.headers.origin) h.origin = target.origin;
  const ck = cookieFor(jar, target.hostname);
  if (ck) h.cookie = ck;

  let body;
  if (!['GET', 'HEAD'].includes(req.method)) {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    body = Buffer.concat(chunks);
  }

  const ac = new AbortController();
  res.on('close', () => ac.abort());
  let r;
  try {
    r = await fetch(target.href, { method: req.method, headers: h, body, redirect: 'manual', signal: ac.signal });
  } catch (e) {
    res.writeHead(502, { 'content-type': 'text/plain' });
    return res.end('TungNet could not reach ' + target.hostname + '.');
  }
  storeCookies(jar, target.hostname, r.headers.getSetCookie ? r.headers.getSetCookie() : []);

  const out = {};
  r.headers.forEach((v, k) => { if (!DROP_RES.has(k)) out[k] = v; });
  if (r.status >= 300 && r.status < 400 && out.location) {
    out.location = px(out.location, target.href);
    res.writeHead(r.status, out);
    return res.end();
  }
  const type = (r.headers.get('content-type') || '').toLowerCase();
  const isHtml = type.includes('text/html');
  if (isHtml || type.includes('text/css')) {
    const text = await r.text();
    delete out['content-length'];
    res.writeHead(r.status, out);
    return res.end(isHtml ? rewriteHtml(text, target.href) : rewriteCss(text, target.href));
  }
  if (r.headers.get('content-encoding')) delete out['content-length'];
  res.writeHead(r.status, out);
  if (!r.body || req.method === 'HEAD') return res.end();
  Readable.fromWeb(r.body).on('error', () => res.destroy()).pipe(res);
}

// ---------- Home page ----------
const HOME = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>TungNet</title>
<style>
:root{--bg:#1c120b;--panel:#2a1b11;--line:#4a3220;--text:#f1e4d3;--muted:#b89c80;--accent:#d9a05b;--ink:#2a1706}
*{box-sizing:border-box}html,body{height:100%;margin:0}
body{background:radial-gradient(900px 500px at 50% -10%,#3a2415,var(--bg));color:var(--text);font-family:Georgia,serif;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:24px}
h1{font-size:clamp(3rem,10vw,5.5rem);margin:0 0 8px;letter-spacing:-.03em}h1 span{color:var(--accent)}
p{margin:0 0 32px;color:var(--muted)}
form{width:min(640px,100%);display:flex;gap:8px}
input{flex:1;min-width:0;padding:16px 20px;font:inherit;font-size:1.05rem;color:var(--text);background:var(--panel);border:1px solid var(--line);border-radius:999px;outline:none}
input:focus{border-color:var(--accent);box-shadow:0 0 0 3px #d9a05b33}
button{padding:0 26px;font:inherit;font-weight:700;color:var(--ink);background:var(--accent);border:0;border-radius:999px;cursor:pointer}
.q{display:flex;flex-wrap:wrap;gap:10px;justify-content:center;margin-top:28px}
.q a{color:var(--text);text-decoration:none;padding:10px 18px;border:1px solid var(--line);border-radius:12px;background:var(--panel)}
.q a:hover,a:focus-visible,button:focus-visible{border-color:var(--accent);outline:2px solid var(--accent)}
</style></head><body>
<h1>Tung<span>Net</span></h1><p>Search or enter a web address.</p>
<form action="/go" method="get"><input name="q" placeholder="Search Google or type a URL" aria-label="Search or URL" autofocus autocomplete="off"><button>Go</button></form>
<div class="q"><a href="/go?q=https://www.youtube.com">YouTube</a><a href="/go?q=https://www.tiktok.com">TikTok</a><a href="/go?q=https://www.google.com">Google</a><a href="/go?q=https://www.wikipedia.org">Wikipedia</a></div>
</body></html>`;

// ---------- Server ----------
http.createServer(async (req, res) => {
  try {
    const u = new URL(req.url, 'http://x');
    if (u.pathname === '/' ) { res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }); return res.end(HOME); }
    if (u.pathname === '/go') {
      const t = toTarget(u.searchParams.get('q'));
      res.writeHead(302, { location: t ? '/p/' + enc(t) : '/' });
      return res.end();
    }
    const jar = getSid(req, res);
    if (u.pathname.startsWith('/p/')) {
      let target = dec(u.pathname.slice(3).split('/')[0]);
      if (u.search) { // GET forms append their query to the proxied path
        const t = new URL(target);
        t.search = t.search ? t.search + '&' + u.search.slice(1) : u.search;
        target = t.href;
      }
      return proxy(req, res, target, jar);
    }
    // Fallback: a page used a root-relative URL we couldn't rewrite. Resolve it against the page it came from.
    const m = /\/p\/([^/?#]+)/.exec(req.headers.referer || '');
    if (m) return proxy(req, res, new URL(req.url, dec(m[1])).href, jar);
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('Not found');
  } catch (e) {
    if (!res.headersSent) res.writeHead(500, { 'content-type': 'text/plain' });
    res.end('TungNet error');
  }
}).listen(PORT, () => console.log('TungNet running on http://localhost:' + PORT));
