import { withSupabase } from '@supabase/server'

const ALLOWED_ORIGINS = [
  'https://movies-eight-azure.vercel.app',
  'http://localhost:3000',
  'http://localhost:5173',
]

const MAX_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024

const ALLOWED_TYPES = [
  'video/mp4', 'video/webm', 'video/ogg', 'video/quicktime',
  'video/x-matroska', 'video/x-msvideo', 'video/mpeg',
  'audio/mpeg', 'audio/mp4', 'audio/ogg', 'audio/wav', 'audio/flac',
]

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

async function hmac(key, data) {
  const cryptoKey = await crypto.subtle.importKey(
    'raw', typeof key === 'string' ? new TextEncoder().encode(key) : key,
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  )
  return new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(data)))
}

async function sha256Hex(data) {
  const buf = typeof data === 'string' ? new TextEncoder().encode(data) : data
  const hash = await crypto.subtle.digest('SHA-256', buf)
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, '0')).join('')
}

function toHex(buf) {
  return [...buf].map(b => b.toString(16).padStart(2, '0')).join('')
}

async function presignPut(env, objectKey, contentType, expiresSec) {
  const method = 'PUT'
  const host = `${env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`
  const now = new Date()
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '')
  const dateStamp = amzDate.slice(0, 8)
  const region = 'auto'
  const service = 's3'
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`

  const canonicalUri = '/' + env.R2_BUCKET + '/' + objectKey.split('/').map(encodeURIComponent).join('/')
  const params = new URLSearchParams({
    'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
    'X-Amz-Credential': `${env.R2_ACCESS_KEY_ID}/${credentialScope}`,
    'X-Amz-Date': amzDate,
    'X-Amz-Expires': String(expiresSec),
    'X-Amz-SignedHeaders': 'content-type;host',
  })
  const canonicalQuery = [...params.entries()]
    .sort(([a], [b]) => a < b ? -1 : 1)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&')

  const canonicalHeaders = `content-type:${contentType}\nhost:${host}\n`
  const signedHeaders = 'content-type;host'
  const payloadHash = 'UNSIGNED-PAYLOAD'

  const canonicalRequest = [method, canonicalUri, canonicalQuery, canonicalHeaders, signedHeaders, payloadHash].join('\n')
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, credentialScope, await sha256Hex(canonicalRequest)].join('\n')

  let k = await hmac('AWS4' + env.R2_SECRET_ACCESS_KEY, dateStamp)
  k = await hmac(k, region)
  k = await hmac(k, service)
  k = await hmac(k, 'aws4_request')
  const signature = toHex(await hmac(k, stringToSign))

  return `https://${host}${canonicalUri}?${canonicalQuery}&X-Amz-Signature=${signature}`
}

async function readCatalog(env) {
  try {
    const r = await fetch(`${env.R2_PUBLIC_URL}/catalog.json`, { cf: { cacheTtl: 0 } })
    if (!r.ok) return { version: 1, updatedAt: 0, movies: [], uploads: {} }
    return await r.json()
  } catch {
    return { version: 1, updatedAt: 0, movies: [], uploads: {} }
  }
}

async function writeCatalog(env, catalog) {
  catalog.updatedAt = Date.now()
  const body = JSON.stringify(catalog, null, 2)
  const url = await presignPut(env, 'catalog.json', 'application/json', 300)
  const r = await fetch(url, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body })
  if (!r.ok) throw new Error('catalog write failed: ' + r.status)
}

async function handleUpload(req, env, ctx) {
  const origin = req.headers.get('Origin') || ''
  const body = await req.json().catch(() => null)
  if (!body) return json({ error: 'invalid json' }, 400, origin)

  const { filename, contentType, size } = body
  if (!filename || !contentType || !size) return json({ error: 'filename, contentType, size required' }, 400, origin)
  if (!ALLOWED_TYPES.includes(contentType)) return json({ error: 'file type not allowed: ' + contentType }, 400, origin)
  if (size > MAX_UPLOAD_BYTES) return json({ error: 'file too large (max 2GB)' }, 400, origin)

  const userId = ctx.jwtClaims.sub
  const movieId = 'r2_' + crypto.randomUUID().replace(/-/g, '').slice(0, 16)
  const safe = filename.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 80)
  const objectKey = `uploads/${userId}/${movieId}/${safe}`

  const uploadUrl = await presignPut(env, objectKey, contentType, 600)
  const publicUrl = `${env.R2_PUBLIC_URL}/${objectKey}`

  return json({ uploadUrl, movieId, objectKey, publicUrl }, 200, origin)
}

async function handleConfirm(req, env, ctx) {
  const origin = req.headers.get('Origin') || ''
  const body = await req.json().catch(() => null)
  if (!body) return json({ error: 'invalid json' }, 400, origin)

  const { movieId, title, year, description, objectKey, publicUrl, contentType, size, durationSec } = body
  if (!movieId || !title || !objectKey) return json({ error: 'movieId, title, objectKey required' }, 400, origin)
  if (!objectKey.startsWith(`uploads/${ctx.jwtClaims.sub}/`)) return json({ error: 'not your object' }, 403, origin)

  const catalog = await readCatalog(env)
  catalog.movies = (catalog.movies || []).filter(m => m.id !== movieId)
  const record = {
    id: movieId,
    source: 'r2',
    title: String(title).slice(0, 200),
    year: year ? Number(year) : null,
    description: String(description || '').slice(0, 2000),
    posterUrl: null,
    streamUrls: [{ quality: 'original', url: publicUrl, type: contentType }],
    downloadUrls: [{ quality: 'original', url: publicUrl, sizeBytes: Number(size) || 0 }],
    durationSec: durationSec ? Number(durationSec) : null,
    contentType,
    sizeBytes: Number(size) || 0,
    popularity: 0.5,
    verified: true,
    uploader: ctx.jwtClaims.sub,
    uploaderEmail: ctx.jwtClaims.email || null,
    uploadedAt: Date.now(),
    fileKey: objectKey,
  }
  catalog.movies.push(record)

  catalog.uploads = catalog.uploads || {}
  const u = catalog.uploads[ctx.jwtClaims.sub] || {
    email: ctx.jwtClaims.email || null,
    firstUploadAt: Date.now(),
    uploadCount: 0,
  }
  u.lastUploadAt = Date.now()
  u.uploadCount = (u.uploadCount || 0) + 1
  catalog.uploads[ctx.jwtClaims.sub] = u

  await writeCatalog(env, catalog)
  return json({ ok: true, movieId, movie: record }, 200, origin)
}

async function handleCatalog(req, env) {
  const origin = req.headers.get('Origin') || ''
  const catalog = await readCatalog(env)
  return json(catalog, 200, origin)
}

const userHandler = withSupabase({ auth: 'user' }, async (req, env, ctx) => {
  const url = new URL(req.url)
  const path = url.pathname
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders(req.headers.get('Origin') || '') })
  if (path === '/upload' && req.method === 'POST') return handleUpload(req, env, ctx)
  if (path === '/confirm' && req.method === 'POST') return handleConfirm(req, env, ctx)
  return json({ error: 'not found' }, 404, req.headers.get('Origin') || '')
})

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url)
    if (url.pathname === '/catalog') {
      if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders(req.headers.get('Origin') || '') })
      return handleCatalog(req, env)
    }
    return userHandler(req, env, ctx)
  }
}
