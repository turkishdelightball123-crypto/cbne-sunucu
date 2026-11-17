'use strict';
/* Countryballs: No Escape – oyun sunucusu
   - index.html'i sunar
   - Hesaplar (benzersiz kullanıcı adı + scrypt ile şifrelenmiş şifre), kalıcı: data.json
   - Sıralama (en ileri lobi)
   - /ws: WebRTC/PeerJS yerine WebSocket aktarıcı (VPN / güvenlik duvarı sorunu yok)  */
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const { WebSocketServer } = require('ws');

const SERVER_VER = '1.1.0';
const PORT = +process.env.PORT || 3000;
const AV_RE = /^data:image\/jpeg;base64,[A-Za-z0-9+\/=]+$/;   // profil fotoğrafı: küçük JPEG (istemci 80x80'e küçültür)
const DIR = process.env.DATA_DIR || __dirname;
const FILE = path.join(DIR, 'data.json');

let DB = { users: {}, sessions: {} };
try { DB = Object.assign(DB, JSON.parse(fs.readFileSync(FILE, 'utf8'))); } catch (e) {}
let dirty = false;
const touch = () => { dirty = true; };
const flush = () => {
  if (!dirty) return; dirty = false;
  try { fs.writeFileSync(FILE + '.tmp', JSON.stringify(DB)); fs.renameSync(FILE + '.tmp', FILE); }
  catch (e) { console.error('Kayıt hatası:', e.message); }
};
setInterval(flush, 3000);
['SIGINT', 'SIGTERM'].forEach(s => process.on(s, () => { flush(); process.exit(0); }));

/* kullanıcı adı: büyük/küçük harf, Türkçe harf ve _ . - farkları yok sayılarak benzersiz */
const FOLD = { 'ı': 'i', 'İ': 'i', 'ğ': 'g', 'Ğ': 'g', 'ü': 'u', 'Ü': 'u', 'ş': 's', 'Ş': 's', 'ö': 'o', 'Ö': 'o', 'ç': 'c', 'Ç': 'c' };
const keyOf = n => n.replace(/[ıİğĞüÜşŞöÖçÇ]/g, c => FOLD[c]).toLowerCase().replace(/[_.\-]/g, '');
const NAME_RE = /^[A-Za-z0-9_.\-ğüşıöçĞÜŞİÖÇ]{3,12}$/;
const hashPw = (p, salt) => crypto.scryptSync(p, salt, 32).toString('hex');

const hits = new Map();
const limited = ip => { const n = Date.now(), a = (hits.get(ip) || []).filter(t => n - t < 60000); a.push(n); hits.set(ip, a); return a.length > 25; };
setInterval(() => hits.clear(), 120000);

function readBody(req, cb) {
  let s = '';
  req.on('data', d => { s += d; if (s.length > 20000) req.destroy(); });
  req.on('end', () => { try { cb(JSON.parse(s || '{}')); } catch (e) { cb({}); } });
}

const server = http.createServer((req, res) => {
  const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS' };
  const json = (code, o) => { res.writeHead(code, Object.assign({ 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }, cors)); res.end(JSON.stringify(o)); };
  if (req.method === 'OPTIONS') { res.writeHead(204, cors); return res.end(); }
  const url = req.url.split('?')[0];
  if (url === '/' || url === '/index.html') {
    return fs.readFile(path.join(__dirname, 'index.html'), (e, b) => {
      if (e) { res.writeHead(404); return res.end('index.html bulunamadı (server.js ile aynı klasörde olmalı)'); }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); res.end(b);
    });
  }
  if (!url.startsWith('/api/')) { res.writeHead(404); return res.end('Not found'); }

  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  const tok = (req.headers.authorization || '').replace(/^Bearer /, '');
  const ukey = DB.sessions[tok], user = ukey && DB.users[ukey];
  const pub = u => ({ name: u.name, best: u.best, c: u.c || 'TR', av: u.av || '', sk: u.sk ? 1 : 0 });

  if (url === '/api/ping') return json(200, { ok: true, game: 'cbne', v: SERVER_VER });
  if (url === '/api/lb') {
    const list = Object.values(DB.users).sort((a, b) => b.best - a.best || a.t - b.t).slice(0, 100).map((u, i) => ({ n: u.name, b: u.best, c: u.c || 'TR', a: i < 20 ? (u.av || '') : '' }));
    return json(200, { list });
  }
  if (url === '/api/me') return user ? json(200, { user: pub(user) }) : json(401, { err: 'Oturum yok' });

  if (req.method !== 'POST') return json(405, { err: 'Yöntem desteklenmiyor' });
  readBody(req, b => {
    if (url === '/api/register' || url === '/api/login') {
      if (limited(ip)) return json(429, { err: 'Çok fazla deneme. Bir dakika bekle.' });
      const u = String(b.u || '').trim(), p = String(b.p || '');
      if (!NAME_RE.test(u)) return json(400, { err: 'Kullanıcı adı 3-12 karakter: harf, rakam, _ . -' });
      if (p.length < 4 || p.length > 64) return json(400, { err: 'Şifre 4-64 karakter olmalı.' });
      const k = keyOf(u);
      if (url === '/api/register') {
        if (DB.users[k]) return json(409, { err: 'Bu kullanıcı adı zaten alınmış. Başka bir ad dene.' });
        if (Object.keys(DB.users).length >= 100000) return json(503, { err: 'Kayıt dolu.' });
        const salt = crypto.randomBytes(16).toString('hex');
        const best = Math.min(100, Math.max(1, b.best | 0));
        DB.users[k] = { name: u, salt, hash: hashPw(p, salt), best, t: Date.now(), c: /^[A-Z]{2}$/.test(b.c) ? b.c : 'TR', created: Date.now() };
      }
      const acc = DB.users[k];
      if (!acc) return json(401, { err: 'Kullanıcı adı veya şifre hatalı.' });
      const a = Buffer.from(hashPw(p, acc.salt), 'hex'), h = Buffer.from(acc.hash, 'hex');
      if (a.length !== h.length || !crypto.timingSafeEqual(a, h)) return json(401, { err: 'Kullanıcı adı veya şifre hatalı.' });
      const t = crypto.randomBytes(24).toString('hex');
      DB.sessions[t] = k; touch();
      return json(200, { token: t, user: pub(acc) });
    }
    if (url === '/api/profile') {
      if (!user) return json(401, { err: 'Oturum yok' });
      if (limited(ip)) return json(429, { err: 'Çok fazla deneme. Bir dakika bekle.' });
      const av = typeof b.av === 'string' ? b.av : '';
      if (av && (av.length > 9000 || !AV_RE.test(av))) return json(400, { err: 'Fotoğraf geçersiz veya çok büyük.' });
      user.av = av; user.sk = av && b.sk ? 1 : 0;
      touch();
      return json(200, { user: pub(user) });
    }
    if (url === '/api/progress') {
      if (!user) return json(401, { err: 'Oturum yok' });
      const best = Math.min(100, Math.max(1, b.best | 0));
      if (best > user.best) { user.best = best; user.t = Date.now(); }
      if (/^[A-Z]{2}$/.test(b.c || '')) user.c = b.c;
      touch();
      return json(200, { user: pub(user) });
    }
    json(404, { err: 'Bulunamadı' });
  });
});

/* ---------- WebSocket aktarıcı (PeerJS yerine) ---------- */
const peers = new Map();
const send = (ws, o) => { if (ws.readyState === 1) ws.send(JSON.stringify(o)); };
const rid = () => crypto.randomBytes(6).toString('hex');
const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 131072 });
wss.on('connection', ws => {
  ws.id = null; ws.links = new Set(); ws.alive = true;
  ws.on('pong', () => { ws.alive = true; });
  ws.on('message', raw => {
    let m; try { m = JSON.parse(raw); } catch (e) { return; }
    if (m.op === 'p') return;
    if (m.op === 'reg') {
      if (ws.id) return;
      let id = m.id ? String(m.id).slice(0, 40) : null;
      if (id) { if (peers.has(id)) return send(ws, { op: 'err', type: 'unavailable-id' }); }
      else { do { id = rid(); } while (peers.has(id)); }
      ws.id = id; peers.set(id, ws); return send(ws, { op: 'open', id });
    }
    if (!ws.id) return;
    if (m.op === 'c') {
      const t = peers.get(m.to);
      if (!t || t === ws) return send(ws, { op: 'err', type: 'peer-unavailable' });
      ws.links.add(m.to); t.links.add(ws.id);
      send(t, { op: 'inc', from: ws.id }); send(ws, { op: 'ok', to: m.to });
    } else if (m.op === 'd') {
      const t = peers.get(m.to);
      if (t && ws.links.has(m.to)) send(t, { op: 'd', from: ws.id, d: m.d });
    } else if (m.op === 'x') {
      const t = peers.get(m.to);
      ws.links.delete(m.to);
      if (t) { t.links.delete(ws.id); send(t, { op: 'x', from: ws.id }); }
    }
  });
  ws.on('close', () => {
    if (!ws.id) return;
    if (peers.get(ws.id) === ws) peers.delete(ws.id);
    ws.links.forEach(o => { const t = peers.get(o); if (t) { t.links.delete(ws.id); send(t, { op: 'x', from: ws.id }); } });
  });
  ws.on('error', () => {});
});
setInterval(() => wss.clients.forEach(ws => { if (!ws.alive) return ws.terminate(); ws.alive = false; try { ws.ping(); } catch (e) {} }), 25000);

server.listen(PORT, () => console.log('Countryballs sunucusu hazır: http://localhost:' + PORT));
