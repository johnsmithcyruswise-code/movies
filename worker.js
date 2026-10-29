// ============================================================
// Vela / Fylm — Cloudflare Worker
// Uploads → Cloudflare R2 (presigned PUT, content-length locked)
// Auth    → Supabase Google login (JWT verified via JWKS)
// Catalog → catalog.json in R2, read via R2_PUBLIC_URL
// ============================================================

const ALLOWED_ORIGINS = [
  'https://movies-eight-azure.vercel.app',
  'https://fylm.vercel.app',            // ← add your real Fylm origin(s)
  'http://localhost:3000',
  'http://localhost:5173',
]

const MAX_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024 // 2 GB
const MAX_JSON_BYTES   = 8192                  // /upload, /confirm bodies are tiny

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
    'jwk', jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false, ['verify']
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
  const cryptoKey = await crypto.subtle.importKey(
    'raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  )
  return new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(data)))
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
  const region = 'auto'
  const service = 's3'
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`

  const canonicalUri = '/' + env.R2_BUCKET + '/' +
    objectKey.split('/').map(encodeURIComponent).join('/')

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
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&')

  const canonicalHeaders =
    `content-length:${sizeBytes}\n` +
    `content-type:${contentType}\n` +
    `host:${host}\n`

  const payloadHash = 'UNSIGNED-PAYLOAD'

  const canonicalRequest = [
    method, canonicalUri, canonicalQuery, canonicalHeaders, signedHeaders, payloadHash,
  ].join('\n')

  const stringToSign = [
    'AWS4-HMAC-SHA256', amzDate, credentialScope, await sha256Hex(canonicalRequest),
  ].join('\n')

  let k = await hmac('AWS4' + env.R2_SECRET_ACCESS_KEY, dateStamp)
  k = await hmac(k, region)
  k = await hmac(k, service)
  k = await hmac(k, 'aws4_request')
  const signature = toHex(await hmac(k, stringToSign))

  return `https://${host}${canonicalUri}?${canonicalQuery}&X-Amz-Signature=${signature}`
}

// ---------- Catalog ----------

const EMPTY_CATALOG = () => ({ version: 1, updatedAt: 0, movies: [], uploads: {} })

async function readCatalog(env) {
  const r = await fetch(`${env.R2_PUBLIC_URL}/catalog.json`, { cf: { cacheTtl: 0 } })
  if (r.status === 404) return EMPTY_CATALOG()      // brand-new bucket
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

// ---------- Handlers ----------

async function handleUpload(req, env, claims, origin) {
  const body = await req.json().catch(() => null)
  if (!body) return json({ error: 'invalid json' }, 400, origin)

  const { filename, contentType, size } = body
  if (!filename || !contentType || !size)
    return json({ error: 'filename, contentType, size required' }, 400, origin)
  if (!ALLOWED_TYPES.includes(contentType))
    return json({ error: 'file type not allowed: ' + contentType }, 400, origin)
  if (size > MAX_UPLOAD_BYTES)
    return json({ error: 'file too large (max 2GB)' }, 400, origin)
  if (size <= 0)
    return json({ error: 'empty file' }, 400, origin)

  const userId = claims.sub
  const movieId = 'r2_' + crypto.randomUUID().replace(/-/g, '').slice(0, 16)

  // Force the extension from the (validated) content-type.
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
  if (!movieId || !title || !objectKey)
    return json({ error: 'movieId, title, objectKey required' }, 400, origin)
  if (!objectKey.startsWith(`uploads/${claims.sub}/`))
    return json({ error: 'not your object' }, 403, origin)

  // Re-derive publicUrl on the server — never trust the client.
  const publicUrl = `${env.R2_PUBLIC_URL}/${objectKey}`
  // Re-derive contentType from the object key's extension (defence in depth).
  const ext = (objectKey.match(/\.[a-z0-9]+$/i) || [''])[0].toLowerCase()
  const contentType = Object.entries(EXT_FOR_TYPE).find(([, e]) => e === ext)?.[0] || 'application/octet-stream'

  let catalog
  try {
    catalog = await readCatalog(env)
  } catch (e) {
    // Do NOT overwrite the catalog if we couldn't read it.
    return json({ error: 'catalog unavailable, try again' }, 503, origin)
  }

  catalog.movies = (catalog.movies || []).filter(m => m.id !== movieId)
  const record = {
    id: movieId,
    source: 'r2',
    title: String(title).slice(0, 200),
    year: year ? Number(year) || null : null,
    description: String(description || '').slice(0, 2000),
    posterUrl: null,
    streamUrls: [{ quality: 'original', url: publicUrl, type: contentType }],
    downloadUrls: [{ quality: 'original', url: publicUrl, sizeBytes: Number(size) || 0 }],
    durationSec: Number.isFinite(Number(durationSec)) && Number(durationSec) > 0
      ? Math.floor(Number(durationSec)) : null,
    contentType,
    sizeBytes: Number(size) || 0,
    popularity: 0.5,
    verified: true,
    uploader: claims.sub,
    uploaderEmail: claims.email || null,
    uploadedAt: Date.now(),
    fileKey: objectKey,
  }
  catalog.movies.push(record)

  catalog.uploads = catalog.uploads || {}
  const u = catalog.uploads[claims.sub] || {
    email: claims.email || null,
    firstUploadAt: Date.now(),
    uploadCount: 0,
  }
  u.lastUploadAt = Date.now()
  u.uploadCount = (u.uploadCount || 0) + 1
  catalog.uploads[claims.sub] = u

  try {
    await writeCatalog(env, catalog)
  } catch (e) {
    return json({ error: 'could not save catalog: ' + e.message }, 500, origin)
  }
  return json({ ok: true, movieId, movie: record }, 200, origin)
}

async function handleCatalog(req, env, origin) {
  let catalog
  try {
    catalog = await readCatalog(env)
  } catch (e) {
    return json({ error: 'catalog unavailable' }, 503, origin)
  }
  return json(catalog, 200, origin)
}

function tooLarge(req) {
  const len = Number(req.headers.get('content-length') || 0)
  return len > MAX_JSON_BYTES
}

// ---------- Router ----------

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url)
    const origin = req.headers.get('Origin') || ''

    if (req.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) })
    }

    if (url.pathname === '/catalog' && req.method === 'GET') {
      return handleCatalog(req, env, origin)
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
