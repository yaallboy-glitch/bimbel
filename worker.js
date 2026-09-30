/**
 * Alief Bimbel — API Worker (Cloudflare D1)
 *
 * Butuh:
 *  - D1 binding bernama  DB
 *  - Secret bernama      ADMIN_KEY   (PIN untuk masuk dashboard)
 *
 * Endpoint (semua /api/* wajib header  X-Admin-Key: <ADMIN_KEY>):
 *  GET    /api/data           -> semua data {siswa, guru, jadwal, bayar, absen}
 *  PUT    /api/:kind/:id      -> simpan / update 1 record (body JSON)
 *  DELETE /api/:kind/:id      -> hapus 1 record (+ cascade)
 *  POST   /api/import         -> impor banyak record sekaligus
 *
 * Portal guru / orang tua (tanpa X-Admin-Key):
 *  POST   /api/login          -> {role:'guru'|'ortu', wa, pin} => {token, role, ...data}
 *  GET    /api/me             -> data milik sendiri (header Authorization: Bearer <token>)
 *  PUT    /api/absen/:id      -> guru mengisi absensi (hadir/izin/sakit) untuk jadwalnya
 */

const KINDS = ['siswa', 'guru', 'jadwal', 'bayar', 'absen', 'pengaturan'];
const ID_RE = /^[A-Za-z0-9_.\-]{1,120}$/;
const MAX_BODY = 20 * 1024;        // 20 KB per record
const MAX_IMPORT = 5000;           // maks record per impor

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, PUT, POST, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Key, Authorization',
  'Access-Control-Max-Age': '86400',
};

let schemaReady = false;

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS });
    }

    try {
      const url = new URL(request.url);
      const path = url.pathname.replace(/\/+$/, '') || '/';

      // Health check (tanpa auth)
      if (path === '/') {
        return json({ ok: true, service: 'alief-bimbel-api' });
      }
      if (!path.startsWith('/api/')) {
        return json({ error: 'Not found' }, 404);
      }

      if (!env.DB) {
        return json({ error: 'D1 binding "DB" belum dipasang di Worker' }, 500);
      }
      // ---- tarif & nomor WA publik (diatur admin) ----
      if (request.method === 'GET' && path === '/api/public/info') {
        await ensureSchema(env.DB);
        const p = (await getAll(env.DB)).pengaturan.find((x) => x.id === 'utama') || {};
        return json({ wa: p.wa || '', tarif: p.tarif || {} });
      }

      // ---- jadwal publik (untuk landing page, tanpa login) ----
      if (request.method === 'GET' && path === '/api/public/jadwal') {
        await ensureSchema(env.DB);
        const all = await getAll(env.DB);
        const nama = Object.fromEntries(all.guru.map((g) => [g.id, g.nama]));
        return json({
          jadwal: all.jadwal.map((j) => ({ hari: j.hari, jam: j.jam, durasi: j.durasi, mapel: j.mapel, kelas: j.kelas, guruNama: nama[j.guruId] || '' })),
        });
      }

      if (!env.ADMIN_KEY) {
        return json({ error: 'Secret "ADMIN_KEY" belum diset di Worker' }, 500);
      }
      // ---- portal guru / orang tua ----
      const hasAdminKey = request.headers.has('X-Admin-Key');
      const isLogin = request.method === 'POST' && path === '/api/login';
      if (isLogin || (!hasAdminKey && request.headers.has('Authorization'))) {
        await ensureSchema(env.DB);
        return await portal(request, env, path, isLogin);
      }

      if (!isAuthorized(request, env.ADMIN_KEY)) {
        return json({ error: 'PIN salah' }, 401);
      }

      await ensureSchema(env.DB);

      const parts = path.split('/').filter(Boolean); // ['api', ...]

      // GET /api/data
      if (request.method === 'GET' && parts[1] === 'data' && parts.length === 2) {
        return json(await getAll(env.DB));
      }

      // POST /api/import
      if (request.method === 'POST' && parts[1] === 'import' && parts.length === 2) {
        const body = await readJson(request, MAX_IMPORT * 1024);
        return json(await importAll(env.DB, body));
      }

      // PUT / DELETE /api/:kind/:id
      if (parts.length === 3 && KINDS.includes(parts[1])) {
        const kind = parts[1];
        const id = decodeURIComponent(parts[2]);
        if (!ID_RE.test(id)) return json({ error: 'ID tidak valid' }, 400);

        if (request.method === 'PUT') {
          const body = await readJson(request, MAX_BODY);
          if (!isPlainObject(body)) return json({ error: 'Body harus objek JSON' }, 400);
          body.id = id;
          await env.DB
            .prepare(UPSERT_SQL)
            .bind(kind, id, JSON.stringify(body), Date.now())
            .run();
          return json({ ok: true, id });
        }

        if (request.method === 'DELETE') {
          await removeRecord(env.DB, kind, id);
          return json({ ok: true, id });
        }
      }

      return json({ error: 'Endpoint tidak ditemukan' }, 404);
    } catch (err) {
      if (err instanceof HttpError) return json({ error: err.message }, err.status);
      console.error(err);
      return json({ error: 'Terjadi kesalahan di server' }, 500);
    }
  },
};

/* ---------------- helpers ---------------- */

class HttpError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...CORS },
  });
}

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function isAuthorized(request, adminKey) {
  const given = request.headers.get('X-Admin-Key') || '';
  return safeEqual(given, adminKey);
}

// perbandingan waktu-konstan
function safeEqual(a, b) {
  const len = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < len; i++) {
    diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }
  return diff === 0;
}

async function readJson(request, maxBytes) {
  const text = await request.text();
  if (text.length > maxBytes) throw new HttpError('Data terlalu besar', 413);
  try {
    return JSON.parse(text);
  } catch {
    throw new HttpError('JSON tidak valid', 400);
  }
}

async function ensureSchema(db) {
  if (schemaReady) return;
  await db
    .prepare(
      `CREATE TABLE IF NOT EXISTS records (
         kind TEXT NOT NULL,
         id TEXT NOT NULL,
         data TEXT NOT NULL,
         updated_at INTEGER NOT NULL,
         PRIMARY KEY (kind, id)
       )`
    )
    .run();
  schemaReady = true;
}

const UPSERT_SQL = `INSERT INTO records (kind, id, data, updated_at)
  VALUES (?1, ?2, ?3, ?4)
  ON CONFLICT(kind, id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at`;

async function getAll(db) {
  const { results } = await db.prepare('SELECT kind, data FROM records ORDER BY updated_at ASC').all();
  const out = {};
  KINDS.forEach((k) => (out[k] = []));
  for (const row of results || []) {
    if (!out[row.kind]) continue;
    try {
      out[row.kind].push(JSON.parse(row.data));
    } catch {
      /* lewati record rusak */
    }
  }
  return out;
}

async function removeRecord(db, kind, id) {
  const stmts = [db.prepare('DELETE FROM records WHERE kind = ?1 AND id = ?2').bind(kind, id)];

  if (kind === 'siswa') {
    // hapus pembayaran milik siswa
    stmts.push(
      db.prepare("DELETE FROM records WHERE kind = 'bayar' AND json_extract(data, '$.siswaId') = ?1").bind(id)
    );
  }
  if (kind === 'jadwal') {
    // hapus absensi milik jadwal
    stmts.push(
      db.prepare("DELETE FROM records WHERE kind = 'absen' AND json_extract(data, '$.jadwalId') = ?1").bind(id)
    );
  }
  if (kind === 'guru') {
    // kosongkan guru di jadwal terkait
    stmts.push(
      db
        .prepare(
          "UPDATE records SET data = json_set(data, '$.guruId', '') WHERE kind = 'jadwal' AND json_extract(data, '$.guruId') = ?1"
        )
        .bind(id)
    );
  }
  await db.batch(stmts);
}

async function importAll(db, body) {
  if (!isPlainObject(body)) throw new HttpError('Body harus objek JSON', 400);

  const stmts = [];
  const now = Date.now();
  for (const kind of KINDS) {
    const list = Array.isArray(body[kind]) ? body[kind] : [];
    for (const rec of list) {
      if (!isPlainObject(rec) || !rec.id || !ID_RE.test(String(rec.id))) continue;
      stmts.push(db.prepare(UPSERT_SQL).bind(kind, String(rec.id), JSON.stringify(rec), now));
    }
  }
  if (stmts.length > MAX_IMPORT) throw new HttpError('Terlalu banyak record', 413);

  for (let i = 0; i < stmts.length; i += 50) {
    await db.batch(stmts.slice(i, i + 50));
  }
  return { ok: true, imported: stmts.length };
}


/* ---------------- portal guru / orang tua ---------------- */

const TOKEN_TTL = 12 * 3600 * 1000; // 12 jam
const enc = new TextEncoder();

const normWa = (v) => {
  let d = String(v || '').replace(/\D/g, '');
  if (d.startsWith('62')) d = d.slice(2);
  else if (d.startsWith('0')) d = d.slice(1);
  return d;
};
const b64u = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

async function sign(payload, secret) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret + ':portal'), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64u(await crypto.subtle.sign('HMAC', key, enc.encode(payload)));
}
async function makeToken(obj, secret) {
  const p = b64u(enc.encode(JSON.stringify({ ...obj, exp: Date.now() + TOKEN_TTL })));
  return p + '.' + (await sign(p, secret));
}
async function readToken(request, secret) {
  const t = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  const [p, sig] = t.split('.');
  if (!p || !sig || !safeEqual(sig, await sign(p, secret))) throw new HttpError('Sesi tidak valid', 401);
  let obj;
  try {
    obj = JSON.parse(atob(p.replace(/-/g, '+').replace(/_/g, '/')));
  } catch {
    throw new HttpError('Sesi tidak valid', 401);
  }
  if (!obj.exp || obj.exp < Date.now()) throw new HttpError('Sesi berakhir, masuk lagi', 401);
  return obj;
}

// data yang boleh dilihat pemilik token (tanpa PIN / data orang lain)
async function scoped(db, t) {
  const all = await getAll(db);
  if (t.role === 'guru') {
    const guru = all.guru.find((g) => g.id === t.id && g.status === 'aktif');
    if (!guru) throw new HttpError('Akun tidak aktif', 401);
    const jadwal = all.jadwal.filter((j) => j.guruId === guru.id);
    const ids = new Set(jadwal.map((j) => j.id));
    return { role: 'guru', guru: { id: guru.id, nama: guru.nama }, jadwal, absen: all.absen.filter((a) => ids.has(a.jadwalId)) };
  }
  const ids = new Set(t.ids || []);
  const siswa = all.siswa.filter((s) => ids.has(s.id)).map((s) => ({ id: s.id, nama: s.nama, kelas: s.kelas, program: s.program }));
  if (!siswa.length) throw new HttpError('Akun tidak ditemukan', 401);
  const kelas = new Set(siswa.map((s) => s.kelas));
  const namaGuru = Object.fromEntries(all.guru.map((g) => [g.id, g.nama]));
  const jadwal = all.jadwal
    .filter((j) => kelas.has(j.kelas))
    .map((j) => ({ id: j.id, hari: j.hari, jam: j.jam, durasi: j.durasi, mapel: j.mapel, kelas: j.kelas, guruNama: namaGuru[j.guruId] || '' }));
  return { role: 'ortu', siswa, jadwal, bayar: all.bayar.filter((b) => ids.has(b.siswaId)) };
}

async function portal(request, env, path, isLogin) {
  const db = env.DB;

  if (isLogin) {
    const { role, wa, pin } = await readJson(request, MAX_BODY);
    const w = normWa(wa);
    const p = String(pin || '');
    if (!w || !p || !['guru', 'ortu'].includes(role)) throw new HttpError('Data login tidak lengkap', 400);
    const all = await getAll(db);
    let t;
    if (role === 'guru') {
      const g = all.guru.find((x) => x.status === 'aktif' && normWa(x.wa) === w && x.pin && safeEqual(p, String(x.pin)));
      if (g) t = { role, id: g.id };
    } else {
      const ids = all.siswa.filter((s) => normWa(s.wa) === w && s.pin && safeEqual(p, String(s.pin))).map((s) => s.id);
      if (ids.length) t = { role, ids };
    }
    if (!t) throw new HttpError('Nomor WhatsApp atau PIN salah', 401);
    return json({ token: await makeToken(t, env.ADMIN_KEY), ...(await scoped(db, t)) });
  }

  const t = await readToken(request, env.ADMIN_KEY);
  const parts = path.split('/').filter(Boolean);

  if (request.method === 'GET' && path === '/api/me') return json(await scoped(db, t));

  // guru mengisi absensi
  if (request.method === 'PUT' && parts.length === 3 && parts[1] === 'absen' && t.role === 'guru') {
    const id = decodeURIComponent(parts[2]);
    const b = await readJson(request, MAX_BODY);
    if (!isPlainObject(b)) throw new HttpError('Body harus objek JSON', 400);
    if (!['hadir', 'izin', 'sakit'].includes(b.status)) throw new HttpError('Status tidak valid', 400);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(String(b.tanggal))) throw new HttpError('Tanggal tidak valid', 400);

    const me = await scoped(db, t);
    const j = me.jadwal.find((x) => x.id === b.jadwalId);
    if (!j) throw new HttpError('Jadwal bukan milik Anda', 403);
    const hari = ['Minggu', 'Senin', 'Selasa', 'Rabu', 'Kamis', 'Jumat', 'Sabtu'][new Date(b.tanggal + 'T00:00:00Z').getUTCDay()];
    if (hari !== j.hari) throw new HttpError('Tanggal tidak sesuai hari jadwal', 400);
    if (id !== 'absen_' + j.id + '_' + b.tanggal) throw new HttpError('ID tidak valid', 400);

    const old = me.absen.find((a) => a.id === id);
    if (old && old.status === 'alpa') throw new HttpError('Absensi dikunci oleh admin', 403);
    const rec = { id, jadwalId: j.id, tanggal: b.tanggal, status: b.status, createdAt: old?.createdAt || Date.now() };
    await db.prepare(UPSERT_SQL).bind('absen', id, JSON.stringify(rec), Date.now()).run();
    return json({ ok: true, id });
  }

  return json({ error: 'Endpoint tidak ditemukan' }, 404);
}
