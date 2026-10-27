import { WORKER_URL } from './supabase-config.js'

async function searchArchive(query, page, size) {
  const q = '(' + query + ') AND mediatype:(movies)'
  const url = 'https://archive.org/advancedsearch.php' +
    '?q=' + encodeURIComponent(q) +
    '&fl[]=identifier&fl[]=title&fl[]=year&fl[]=description&fl[]=downloads' +
    '&sort[]=downloads+desc&rows=' + (size * 3) + '&page=1&output=json'
  try {
    const r = await fetch(url)
    if (!r.ok) return []
    const data = await r.json()
    const docs = (data.response && data.response.docs) || []
    return docs.filter(d => d && d.identifier).map(d => ({
      id: 'archive:' + d.identifier,
      source: 'archive',
      title: Array.isArray(d.title) ? d.title[0] : (d.title || d.identifier),
      year: d.year || null,
      description: Array.isArray(d.description) ? d.description.join(' ') : (d.description || ''),
      posterUrl: 'https://archive.org/services/img/' + d.identifier,
      streamUrls: [],
      downloadUrls: [],
      popularity: Math.min(1, (d.downloads || 0) / 100000),
      verified: false,
      archiveId: d.identifier,
    }))
  } catch { return [] }
}

async function searchR2(query, page, size) {
  try {
    const r = await fetch(WORKER_URL + '/catalog')
    if (!r.ok) return []
    const data = await r.json()
    const q = query.toLowerCase()
    return (data.movies || []).filter(m =>
      m.title.toLowerCase().includes(q) ||
      (m.description || '').toLowerCase().includes(q)
    ).map(m => ({
      id: m.id,
      source: 'r2',
      title: m.title,
      year: m.year,
      description: m.description,
      posterUrl: m.posterUrl,
      streamUrls: m.streamUrls || [],
      downloadUrls: m.downloadUrls || [],
      popularity: m.popularity || 0.5,
      verified: true,
      uploadedAt: m.uploadedAt,
      fileKey: m.fileKey,
    }))
  } catch { return [] }
}

function fingerprint(doc) {
  return (doc.title || '').toLowerCase().replace(/\W+/g, '') + '|' + (doc.year || '')
}

function score(doc) {
  const popularity = doc.popularity || 0
  const freshness = doc.uploadedAt
    ? Math.max(0, 1 - (Date.now() - doc.uploadedAt) / (90 * 24 * 3600 * 1000))
    : 0
  const verified = doc.verified ? 0.15 : 0
  return 0.6 * popularity + 0.25 * freshness + verified
}

function rankAndDedupe(docs) {
  const byFp = new Map()
  for (const d of docs) {
    const fp = fingerprint(d)
    const existing = byFp.get(fp)
    if (!existing || score(d) > score(existing)) byFp.set(fp, d)
  }
  return [...byFp.values()].sort((a, b) => score(b) - score(a))
}

export async function unifiedSearch(query, page, pageSize) {
  page = page || 1
  pageSize = pageSize || 30
  if (!query || !query.trim()) return { docs: [], numFound: 0, hasMore: false }

  const [archive, r2] = await Promise.all([
    searchArchive(query, 1, pageSize * page),
    searchR2(query, 1, pageSize * page),
  ])
  const merged = rankAndDedupe([...archive, ...r2])
  const start = (page - 1) * pageSize
  const docs = merged.slice(start, start + pageSize)
  return { docs, numFound: merged.length, hasMore: start + pageSize < merged.length }
}
