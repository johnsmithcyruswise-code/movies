// worker.js — Cloudflare Worker
// Verifies Supabase JWT, generates R2 presigned upload URL,
// appends uploaded movie metadata to catalog.json in R2.

import { withSupabase } from '@supabase/server'

const R2_BUCKET = 'YOUR_R2_BUCKET'
const R2_PUBLIC_URL = 'YOUR_R2_PUBLIC_URL'
const R2_ACCOUNT_ID = 'YOUR_R2_ACCOUNT_ID'
const R2_ACCESS_KEY_ID = 'YOUR_R2_ACCESS_KEY_ID'
const R2_SECRET_ACCESS_KEY = 'YOUR_R2_SECRET_ACCESS_KEY'

const ALLOWED_ORIGINS = [
  'https://movies-eight-azure.vercel.app',
  'http://localhost:3000',
  'http://localhost:5173',
]

const MAX_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024   // 2 GB

const ALLOWED_TYPES = [
  'video/mp4', 'video/webm', 'video/ogg', 'video/quicktime',
  'video/x-matroska', 'video/x-msvideo', 'video/mpeg',
  'audio/mpeg', 'audio/mp4', 'audio/ogg', 'audio/wav', 'audio/flac',
]

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

// ---------- AWS SigV4 for R2 presigned PUT ----------
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

async function presignPut(objectKey, contentType, expiresSec) {
  const method = 'PUT'
  const host = `${R2_ACCOUNT_ID}.r2.cloudflarestorage.com`
  const now = new Date()
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '')
  const dateStamp = amzDate.slice(0, 8)
  const region = 'auto'
  const service = 's3'
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`

  const canonicalUri = '/' + R2_BUCKET + '/' + objectKey.split('/').map(encodeURIComponent).join('/')
  const params = new URLSearchParams({
    'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
    'X-Amz-Credential': `${R2_ACCESS_KEY_ID}/${credentialScope}`,
    'X-Amz-Date': amzDate,
    'X-Amz-Expires': String(expiresSec),
    'X-Amz-SignedHeaders': 'content-type;host',
  })
  const canonicalQuery = [...params.entries()]
    .sort(([a], [b]) => a < b ? -1 : 1)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&')

  const canonicalHeaders =
    `content-type:${contentType}\n` +
    `host:${host}\n`
  const signedHeaders = 'content-type;host'
  const payloadHash = 'UNSIGNED-PAYLOAD'

  const canonicalRequest = [
    method, canonicalUri, canonicalQuery,
    canonicalHeaders, signedHeaders, payloadHash,
  ].join('\n')

  const stringToSign = [
    'AWS4-HMAC-SHA256', amzDate, credentialScope,
    await sha256Hex(canonicalRequest),
  ].join('\n')

  let k = await hmac('AWS4' + R2_SECRET_ACCESS_KEY, dateStamp)
  k = await hmac(k, region)
  k = await hmac(k, service)
  k = await hmac(k, 'aws4_request')
  const signature = toHex(await hmac(k, stringToSign))

  return `https://${host}${canonicalUri}?${canonicalQuery}&X-Amz-Signature=${signature}`
}

// ---------- R2 catalog read/write ----------
async function readCatalog() {
  try {
    const url = `${R2_PUBLIC_URL}/catalog.json`
    const r = await fetch(url, { cf: { cacheTtl: 0 } })
    if (!r.ok) return { movies: [] }
    return await r.json()
  } catch {
    return { movies: [] }
  }
}

// Write catalog via S3 PutObject (not presigned — Worker has direct credentials)
async function writeCatalog(catalog) {
  const body = JSON.stringify(catalog, null, 2)
  const url = await presignPut('catalog.json', 'application/json', 300)
  const r = await fetch(url, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body,
  })
  if (!r.ok) throw new Error('catalog write failed: ' + r.status)
}

// ---------- routes ----------
async function handleUpload(req, ctx) {
  const origin = req.headers.get('Origin') || ''
  const body = await req.json().catch(() => null)
  if (!body) return json({ error: 'invalid json' }, 400, origin)

  const { filename, contentType, size } = body
  if (!filename || !contentType || !size) {
    return json({ error: 'filename, contentType, size required' }, 400, origin)
  }
  if (!ALLOWED_TYPES.includes(contentType)) {
    return json({ error: 'file type not allowed: ' + contentType }, 400, origin)
  }
  if (size > MAX_UPLOAD_BYTES) {
    return json({ error: 'file too large (max 2GB)' }, 400, origin)
  }

  const userId = ctx.jwtClaims.sub
  const movieId = 'r2_' + crypto.randomUUID().replace(/-/g, '').slice(0, 16)
  const safe = filename.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 80)
  const objectKey = `uploads/${userId}/${movieId}/${safe}`

  const uploadUrl = await presignPut(objectKey, contentType, 600)
  const publicUrl = `${R2_PUBLIC_URL}/${objectKey}`

  return json({ uploadUrl, movieId, objectKey, publicUrl }, 200, origin)
}

async function handleConfirm(req, ctx) {
  const origin = req.headers.get('Origin') || ''
  const body = await req.json().catch(() => null)
  if (!body) return json({ error: 'invalid json' }, 400, origin)

  const { movieId, title, year, description, objectKey, publicUrl, contentType, size } = body
  if (!movieId || !title || !objectKey) {
    return json({ error: 'movieId, title, objectKey required' }, 400, origin)
  }
  if (!objectKey.startsWith(`uploads/${ctx.jwtClaims.sub}/`)) {
    return json({ error: 'not your object' }, 403, origin)
  }

  const catalog = await readCatalog()
  catalog.movies = catalog.movies.filter(m => m.id !== movieId)
  catalog.movies.push({
    id: movieId,
    source: 'r2',
    title: String(title).slice(0, 200),
    year: year ? Number(year) : null,
    description: String(description || '').slice(0, 2000),
    uploader: ctx.jwtClaims.sub,
    uploaderEmail: ctx.jwtClaims.email || null,
    uploadedAt: Date.now(),
    fileKey: objectKey,
    streamUrl: publicUrl,
    contentType,
    sizeBytes: Number(size) || 0,
    verified: true,
  })
  await writeCatalog(catalog)

  return json({ ok: true, movieId }, 200, origin)
}

async function handleCatalog(req) {
  const origin = req.headers.get('Origin') || ''
  const catalog = await readCatalog()
  return json(catalog, 200, origin)
}

// ---------- main ----------
const userHandler = withSupabase({ auth: 'user' }, async (req, ctx) => {
  const url = new URL(req.url)
  const path = url.pathname

  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders(req.headers.get('Origin') || '') })
  }
  if (path === '/upload' && req.method === 'POST') return handleUpload(req, ctx)
  if (path === '/confirm' && req.method === 'POST') return handleConfirm(req, ctx)
  return json({ error: 'not found' }, 404, req.headers.get('Origin') || '')
})

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url)
    // public endpoint (no auth) — the catalog is public
    if (url.pathname === '/catalog') {
      if (req.method === 'OPTIONS') {
        return new Response(null, { status: 204, headers: corsHeaders(req.headers.get('Origin') || '') })
      }
      return handleCatalog(req)
    }
    return userHandler(req, env, ctx)
  }
}
