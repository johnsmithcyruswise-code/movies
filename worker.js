// ============================================================
// Fylm — Cloudflare Worker
// Routes:
//   GET  /                      health check
//   GET  /catalog               full catalog JSON (from R2)
//   POST /bulk-add              append curated archive.org / external links
//   GET  /tmdb/search?q=        TMDB metadata proxy
//   GET  /tmdb/movie/:id        TMDB single-movie proxy
//   POST /upload                presigned R2 PUT (optional direct upload path)
//   POST /confirm               finalize an R2 upload
// ============================================================

const ALLOWED_ORIGINS = [
  'https://movies-eight-azure.vercel.app',
  'https://fylm.vercel.app',
  'http://localhost:3000',
  'http://localhost:5173',
]

const MAX_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024
const MAX_JSON_BYTES   = 8192
const MAX_BULK_BATCH   = 100
const MAX_BULK_TOTAL   = 5000
const MAX_BULK_BYTES   = 5 * 1024 * 1024

const ALLOWED_TYPES = [
  'video/mp4', 'video/webm', 'video/ogg', 'video/quicktime',
  'video/x-matroska', 'video/x-msvideo', 'video/mpeg',
  'audio/mpeg', 'audio/mp4', 'audio/ogg', 'audio/wav', 'audio/flac',
]

const EXT_FOR_TYPE = {
  'video/mp4': '.mp4', 'video/webm': '.webm', 'video/ogg': '.ogv',
  'video/quicktime': '.mov', 'video/x-matroska': '.mkv',
  'video/x-msvideo': '.avi', 'video/mpeg': '.mpg',
  'audio/mpeg': '.mp3', 'audio/mp4': '.m4a', 'audio/ogg': '.ogg',
  'audio/wav': '.wav', 'audio/flac': '.flac',
}

// ---------- CORS ----------
function corsHeaders(origin) {
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0]
  return {
    'Access-Control-Allow-Origin': allowed,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  }
}

function json(body, status, origin) {
  return new Response(JSON.stringify(body), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
  })
}

// ---------- JWT ----------
function b64urlToBytes(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/')
  while (s.length % 4) s += '='
  const bin = atob(s)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

const b64urlDecodeString = s => new TextDecoder().decode(b64urlToBytes(s))

async function verifySupabaseJwt(env, token) {
  if (!token) throw new Error('missing token')
  const parts = token.split('.')
  if (parts.length !== 3) throw new Error('malformed jwt')
  const header = JSON.parse(b64urlDecodeString(parts[0]))
  if (!header.kid) throw new Error('no kid in jwt header')
  const jwksRes = await fetch(env.SUPABASE_JWKS_URL, { cf: { cacheTtl: 3600 } })
  if (!jwksRes.ok) throw new Error('jwks fetch failed')
  const { keys } = await jwksRes.json()
  const jwk = keys.find(k => k.kid === header.kid)
  if (!jwk) throw new Error('kid not found in jwks')
  const key = await crypto.subtle.importKey(
    'jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']
  )
  const sig = b64urlToBytes(parts[2])
  const data = new TextEncoder().encode(parts[0] + '.' + parts[1])
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, sig, data)
  if (!ok) throw new Error('bad signature')
  const claims = JSON.parse(b64urlDecodeString(parts[1]))
  const now = Math.floor(Date.now() / 1000)
  const SKEW = 30
  if (claims.exp && claims.exp < now - SKEW) throw new Error('token expired')
  if (claims.nbf && claims.nbf > now + SKEW) throw new Error('token not yet valid')
  if (claims.aud && claims.aud !== 'authenticated') throw new Error('bad aud')
  if (env.SUPABASE_ISSUER && claims.iss && claims.iss !== env.SUPABASE_ISSUER)
    throw new Error('bad iss')
  if (!claims.sub) throw new Error('no sub in claims')
  return claims
}

// ---------- AWS SigV4 ----------
async function hmac(key, data) {
  const raw = typeof key === 'string' ? new TextEncoder().encode(key) : key
  const ck = await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  return new Uint8Array(await crypto.subtle.sign('HMAC', ck, new TextEncoder().encode(data)))
}

async function sha256Hex(data) {
  const buf = typeof data === 'string' ? new TextEncoder().encode(data) : data
  const hash = await crypto.subtle.digest('SHA-256', buf)
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, '0')).join('')
}

const toHex = buf => [...buf].map(b => b.toString(16).padStart(2, '0')).join('')

async function presignPut(env, objectKey, contentType, sizeBytes, expiresSec) {
  const method = 'PUT'
  const host = `${env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`
  const now = new Date()
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '')
  const dateStamp = amzDate.slice(0, 8)
  const region = 'auto', service = 's3'
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`
  const canonicalUri = '/' + env.R2_BUCKET + '/' + objectKey.split('/').map(encodeURIComponent).join('/')
  const signedHeaders = 'content-length;content-type;host'
  const params = new URLSearchParams({
    'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
    'X-Amz-Credential': `${env.R2_ACCESS_KEY_ID}/${credentialScope}`,
    'X-Amz-Date': amzDate,
    'X-Amz-Expires': String(expiresSec),
    'X-Amz-SignedHeaders': signedHeaders,
  })
  const canonicalQuery = [...params.entries()]
    .sort(([a], [b]) => (a < b ? -1 : 1))
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&')
  const canonicalHeaders = `content-length:${sizeBytes}\ncontent-type:${contentType}\nhost:${host}\n`
  const payloadHash = 'UNSIGNED-PAYLOAD'
  const canonicalRequest = [method, canonicalUri, canonicalQuery, canonicalHeaders, signedHeaders, payloadHash].join('\n')
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, credentialScope, await sha256Hex(canonicalRequest)].join('\n')
  let k = await hmac('AWS4' + env.R2_SECRET_ACCESS_KEY, dateStamp)
  k = await hmac(k, region); k = await hmac(k, service); k = await hmac(k, 'aws4_request')
  const signature = toHex(await hmac(k, stringToSign))
  return `https://${host}${canonicalUri}?${canonicalQuery}&X-Amz-Signature=${signature}`
}

// ---------- Catalog ----------
const EMPTY_CATALOG = () => ({ version: 1, updatedAt: 0, movies: [], uploads: {} })

async function readCatalog(env) {
  const r = await fetch(`${env.R2_PUBLIC_URL}/catalog.json`, { cf: { cacheTtl: 0 } })
  if (r.status === 404) return EMPTY_CATALOG()
  if (!r.ok) throw new Error('catalog read failed: ' + r.status)
  const data = await r.json().catch(() => null)
  if (!data || !Array.isArray(data.movies)) return EMPTY_CATALOG()
  return data
}

async function writeCatalog(env, catalog) {
  catalog.updatedAt = Date.now()
  const body = JSON.stringify(catalog, null, 2)
  const url = await presignPut(env, 'catalog.json', 'application/json', body.length, 300)
  const r = await fetch(url, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', 'Content-Length': String(body.length) },
    body,
  })
  if (!r.ok) throw new Error('catalog write failed: ' + r.status + ' ' + await r.text())
}

// ---------- TMDB ----------
const TMDB_BASE = 'https://api.themoviedb.org/3'
const TMDB_IMG  = 'https://image.tmdb.org/t/p/w500'

function tmdbToMovie(t) {
  const year = (t.release_date || '').slice(0, 4) || null
  return {
    id: 'tmdb:' + t.id,
    source: 'tmdb',
    title: t.title || t.original_title || 'Untitled',
    year: year ? Number(year) : null,
    description: t.overview || '',
    posterUrl: t.poster_path ? TMDB_IMG + t.poster_path : null,
    streamUrls: [],
    downloadUrls: [],
    popularity: Math.min(1, (t.popularity || 0) / 100),
    verified: false,
    tmdbId: t.id,
    voteAverage: t.vote_average || null,
  }
}

async function tmdbFetch(env, path, params) {
  if (!env.TMDB_ACCESS_TOKEN) throw new Error('TMDB token not configured')
  const url = new URL(TMDB_BASE + path)
  for (const [k, v] of Object.entries(params || {})) {
    if (v !== undefined && v !== null && v !== '') url.searchParams.set(k, v)
  }
  const r = await fetch(url.toString(), {
    headers: {
      Authorization: 'Bearer ' + env.TMDB_ACCESS_TOKEN,
      Accept: 'application/json',
    },
    cf: { cacheTtl: 3600, cacheEverything: true },
  })
  if (!r.ok) throw new Error('tmdb ' + r.status + ' ' + (await r.text()).slice(0, 200))
  return r.json()
}

async function handleTmdbSearch(req, env, origin) {
  const url = new URL(req.url)
  const q = (url.searchParams.get('q') || '').trim()
  const page = Math.max(1, Number(url.searchParams.get('page') || 1))
  if (!q) return json({ docs: [], numFound: 0 }, 200, origin)
  try {
    const data = await tmdbFetch(env, '/search/movie', { query: q, page, include_adult: 'false', language: 'en-US' })
    const docs = (data.results || []).map(tmdbToMovie)
    return json({ docs, numFound: data.total_results || docs.length }, 200, origin)
  } catch (e) {
    return json({ error: e.message }, 502, origin)
  }
}

async function handleTmdbMovie(req, env, origin, id) {
  if (!/^\d+$/.test(id)) return json({ error: 'bad id' }, 400, origin)
  try {
    const data = await tmdbFetch(env, '/movie/' + id, { language: 'en-US' })
    return json({ movie: tmdbToMovie(data) }, 200, origin)
  } catch (e) {
    return json({ error: e.message }, 502, origin)
  }
}

// ---------- Bulk add ----------
function isHttpUrl(s) {
  if (typeof s !== 'string' || s.length > 2000) return false
  try {
    const u = new URL(s)
    return u.protocol === 'http:' || u.protocol === 'https:'
  } catch { return false }
}

function validateBulkMovie(m) {
  if (!m || typeof m !== 'object') return 'not an object'
  if (typeof m.title !== 'string' || !m.title.trim()) return 'title required'
  if (m.title.length > 300) return 'title too long'
  if (!Array.isArray(m.streamUrls) || !m.streamUrls.length) return 'streamUrls required'
  if (m.streamUrls.length > 10) return 'too many streamUrls (max 10)'
  for (let i = 0; i < m.streamUrls.length; i++) {
    const s = m.streamUrls[i]
    if (!s || typeof s !== 'object') return 'streamUrls[' + i + '] must be object'
    if (!isHttpUrl(s.url)) return 'streamUrls[' + i + '].url must be http(s)'
  }
  if (m.posterUrl && !isHttpUrl(m.posterUrl)) return 'posterUrl must be http(s)'
  return null
}

async function handleBulkAdd(req, env, origin) {
  const auth = req.headers.get('Authorization') || ''
  const bearer = auth.startsWith('Bearer ') ? auth.slice(7) : null

  let claims = null
  if (bearer && env.ADMIN_TOKEN && bearer === env.ADMIN_TOKEN) {
    claims = { sub: 'admin', email: 'admin' }
  } else if (bearer) {
    try { claims = await verifySupabaseJwt(env, bearer) }
    catch (e) { return json({ error: 'unauthorized: ' + e.message }, 401, origin) }
  } else {
    return json({ error: 'missing token' }, 401, origin)
  }

  const len = Number(req.headers.get('content-length') || 0)
  if (len > MAX_BULK_BYTES) return json({ error: 'body too large' }, 413, origin)

  const body = await req.json().catch(() => null)
  if (!body || !Array.isArray(body.movies)) return json({ error: 'movies[] required' }, 400, origin)
  if (body.movies.length > MAX_BULK_BATCH) return json({ error: 'max ' + MAX_BULK_BATCH + ' per batch' }, 400, origin)
  for (let i = 0; i < body.movies.length; i++) {
    const err = validateBulkMovie(body.movies[i])
    if (err) return json({ error: 'movies[' + i + ']: ' + err }, 400, origin)
  }

  let catalog
  try { catalog = await readCatalog(env) }
  catch (e) { return json({ error: 'catalog unavailable, try again' }, 503, origin) }

  if ((catalog.movies || []).length + body.movies.length > MAX_BULK_TOTAL)
    return json({ error: 'catalog would exceed ' + MAX_BULK_TOTAL + ' entries' }, 400, origin)

  const existing = new Set((catalog.movies || []).map(m => m.id || m.identifier || ''))
  let added = 0, skipped = 0

  for (const m of body.movies) {
    const ident = m.identifier
      ? 'archive:' + m.identifier
      : 'ext:' + ((m.streamUrls[0].url.match(/[^/]+$/) || ['item'])[0])
    if (existing.has(ident)) { skipped++; continue }

    const record = {
      id: ident,
      source: m.identifier ? 'archive.org' : 'external',
      identifier: m.identifier || null,
      title: String(m.title).slice(0, 300),
      year: m.year ? Number(m.year) || null : null,
      decade: m.decade || null,
      genre: m.genre || null,
      silent: !!m.silent,
      description: String(m.description || '').slice(0, 2000),
      posterUrl: m.posterUrl || null,
      streamUrls: m.streamUrls.map(s => ({
        url: String(s.url),
        type: String(s.type || 'video/mp4'),
        quality: String(s.quality || 'original'),
      })),
      downloadUrls: m.streamUrls.map(s => ({ url: s.url, sizeBytes: Number(m.sizeBytes) || 0 })),
      sizeBytes: Number(m.sizeBytes) || 0,
      voteAverage: m.voteAverage || null,
      popularity: 0.5,
      verified: true,
      uploader: claims.sub,
      uploaderEmail: claims.email || null,
      uploadedAt: Date.now(),
    }
    catalog.movies.push(record)
    existing.add(ident)
    added++
  }

  try { await writeCatalog(env, catalog) }
  catch (e) { return json({ error: 'catalog write failed: ' + e.message }, 500, origin) }

  return json({ ok: true, added, skipped, total: catalog.movies.length }, 200, origin)
}

// ---------- Upload / Confirm (optional direct-upload path) ----------
async function handleUpload(req, env, claims, origin) {
  const body = await req.json().catch(() => null)
  if (!body) return json({ error: 'invalid json' }, 400, origin)
  const { filename, contentType, size } = body
  if (!filename || !contentType || !size) return json({ error: 'filename, contentType, size required' }, 400, origin)
  if (!ALLOWED_TYPES.includes(contentType)) return json({ error: 'file type not allowed' }, 400, origin)
  if (size > MAX_UPLOAD_BYTES) return json({ error: 'file too large (max 2GB)' }, 400, origin)
  if (size <= 0) return json({ error: 'empty file' }, 400, origin)

  const userId = claims.sub
  const movieId = 'r2_' + crypto.randomUUID().replace(/-/g, '').slice(0, 16)
  const base = filename.replace(/[^a-zA-Z0-9._-]/g, '_').replace(/\.[^.]+$/, '').slice(0, 60)
  const forcedExt = EXT_FOR_TYPE[contentType] || '.bin'
  const objectKey = `uploads/${userId}/${movieId}/${base}${forcedExt}`
  const uploadUrl = await presignPut(env, objectKey, contentType, size, 600)
  const publicUrl = `${env.R2_PUBLIC_URL}/${objectKey}`
  return json({ uploadUrl, movieId, objectKey, publicUrl }, 200, origin)
}

async function handleConfirm(req, env, claims, origin) {
  const body = await req.json().catch(() => null)
  if (!body) return json({ error: 'invalid json' }, 400, origin)
  const { movieId, title, year, description, objectKey, size, durationSec } = body
  if (!movieId || !title || !objectKey) return json({ error: 'movieId, title, objectKey required' }, 400, origin)
  if (!objectKey.startsWith(`uploads/${claims.sub}/`)) return json({ error: 'not your object' }, 403, origin)

  const publicUrl = `${env.R2_PUBLIC_URL}/${objectKey}`
  const ext = (objectKey.match(/\.[a-z0-9]+$/i) || [''])[0].toLowerCase()
  const contentType = Object.entries(EXT_FOR_TYPE).find(([, e]) => e === ext)?.[0] || 'application/octet-stream'

  let catalog
  try { catalog = await readCatalog(env) }
  catch (e) { return json({ error: 'catalog unavailable' }, 503, origin) }

  catalog.movies = (catalog.movies || []).filter(m => m.id !== movieId)
  catalog.movies.push({
    id: movieId, source: 'r2',
    title: String(title).slice(0, 200),
    year: year ? Number(year) || null : null,
    description: String(description || '').slice(0, 2000),
    posterUrl: null,
    streamUrls: [{ quality: 'original', url: publicUrl, type: contentType }],
    downloadUrls: [{ quality: 'original', url: publicUrl, sizeBytes: Number(size) || 0 }],
    durationSec: Number.isFinite(Number(durationSec)) && Number(durationSec) > 0 ? Math.floor(Number(durationSec)) : null,
    contentType, sizeBytes: Number(size) || 0,
    popularity: 0.5, verified: true,
    uploader: claims.sub, uploaderEmail: claims.email || null,
    uploadedAt: Date.now(), fileKey: objectKey,
  })

  try { await writeCatalog(env, catalog) }
  catch (e) { return json({ error: 'catalog write failed' }, 500, origin) }
  return json({ ok: true, movieId }, 200, origin)
}

async function handleCatalog(req, env, origin) {
  try { return json(await readCatalog(env), 200, origin) }
  catch (e) { return json({ error: 'catalog unavailable' }, 503, origin) }
}

function tooLarge(req) {
  return Number(req.headers.get('content-length') || 0) > MAX_JSON_BYTES
}

// ---------- Router ----------
export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url)
    const origin = req.headers.get('Origin') || ''

    if (req.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) })
    }

    if (url.pathname === '/' && req.method === 'GET') {
      return json({
        name: 'fylm', ok: true,
        routes: ['/catalog', '/bulk-add', '/tmdb/search', '/tmdb/movie/:id', '/upload', '/confirm'],
      }, 200, origin)
    }

    if (url.pathname === '/catalog' && req.method === 'GET') {
      return handleCatalog(req, env, origin)
    }

    if (url.pathname === '/tmdb/search' && req.method === 'GET') {
      return handleTmdbSearch(req, env, origin)
    }
    const tmdbMatch = url.pathname.match(/^\/tmdb\/movie\/(\d+)$/)
    if (tmdbMatch && req.method === 'GET') {
      return handleTmdbMovie(req, env, origin, tmdbMatch[1])
    }

    if (url.pathname === '/bulk-add' && req.method === 'POST') {
      return handleBulkAdd(req, env, origin)
    }

    if (url.pathname === '/upload' && req.method === 'POST') {
      if (tooLarge(req)) return json({ error: 'body too large' }, 413, origin)
      const auth = req.headers.get('Authorization') || ''
      const token = auth.startsWith('Bearer ') ? auth.slice(7) : null
      let claims
      try { claims = await verifySupabaseJwt(env, token) }
      catch (e) { return json({ error: 'unauthorized: ' + e.message }, 401, origin) }
      return handleUpload(req, env, claims, origin)
    }

    if (url.pathname === '/confirm' && req.method === 'POST') {
      if (tooLarge(req)) return json({ error: 'body too large' }, 413, origin)
      const auth = req.headers.get('Authorization') || ''
      const token = auth.startsWith('Bearer ') ? auth.slice(7) : null
      let claims
      try { claims = await verifySupabaseJwt(env, token) }
      catch (e) { return json({ error: 'unauthorized: ' + e.message }, 401, origin) }
      return handleConfirm(req, env, claims, origin)
    }

    return json({ error: 'not found' }, 404, origin)
  },
}
