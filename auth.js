import { SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY } from './supabase-config.js'

let _supabase = null
let _session = null
const _listeners = []

async function loadSupabase() {
  if (_supabase) return _supabase
  const mod = await import('https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/+esm')
  _supabase = mod.createClient(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, {
    auth: {
      persistSession: true,
      autoRefreshToken: true,
      detectSessionInUrl: true,
      // Refresh a bit earlier than the server clock to avoid boundary 401s
      // (Supabase default is 1h; this refreshes proactively in the client)
      storageKey: 'fylm-auth',
    },
  })
  _supabase.auth.onAuthStateChange((event, session) => {
    _session = session
    _listeners.forEach(fn => { try { fn(session) } catch (e) { console.error(e) } })
  })
  const { data } = await _supabase.auth.getSession()
  _session = data.session
  return _supabase
}

export async function signInWithGoogle() {
  const sb = await loadSupabase()
  await sb.auth.signInWithOAuth({
    provider: 'google',
    options: {
      redirectTo: window.location.origin,
      queryParams: { prompt: 'select_account' },
    },
  })
}

export async function signOut() {
  const sb = await loadSupabase()
  await sb.auth.signOut()
  _session = null
  _listeners.forEach(fn => { try { fn(null) } catch (e) { console.error(e) } })
}

export async function getSession() {
  await loadSupabase()
  return _session
}

/**
 * Returns a *fresh* access token, refreshing it if it's expired or about to
 * expire. This is the one function the worker relies on — always call it right
 * before a fetch to /upload or /confirm.
 */
export async function getAccessToken() {
  const sb = await loadSupabase()

  // 1. Ask the client for its current session (this hits storage, not network,
  //    when the token is still valid).
  const { data: current, error } = await sb.auth.getSession()
  if (error || !current.session) return null

  const session = current.session
  const nowSec = Math.floor(Date.now() / 1000)
  const expiresAt = session.expires_at || 0
  // Refresh if expired OR within 60s of expiry
  const needsRefresh = !expiresAt || expiresAt - nowSec < 60

  if (!needsRefresh) {
    _session = session
    return session.access_token
  }

  // 2. Refresh — the client will hit Supabase's /token endpoint.
  const { data: refreshed, error: refreshErr } = await sb.auth.refreshSession()
  if (refreshErr || !refreshed.session) {
    // Refresh token is invalid — the user must sign in again.
    _session = null
    _listeners.forEach(fn => { try { fn(null) } catch (e) {} })
    return null
  }

  _session = refreshed.session
  return refreshed.session.access_token
}

export function onAuthChange(fn) {
  _listeners.push(fn)
  // Fire immediately with current state so late subscribers aren't stuck on null
  if (_session !== null || _supabase) {
    try { fn(_session) } catch (e) { console.error(e) }
  }
}
