// auth.js
import { SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY } from './supabase-config.js'

let _supabase = null
let _session = null
let _listeners = []

async function loadSupabase() {
  if (_supabase) return _supabase
  const mod = await import('https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/+esm')
  _supabase = mod.createClient(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY)
  _supabase.auth.onAuthStateChange((event, session) => {
    _session = session
    _listeners.forEach(fn => fn(session))
  })
  const { data } = await _supabase.auth.getSession()
  _session = data.session
  return _supabase
}

export async function signInWithGoogle() {
  const sb = await loadSupabase()
  await sb.auth.signInWithOAuth({
    provider: 'google',
    options: { redirectTo: window.location.origin },
  })
}

export async function signOut() {
  const sb = await loadSupabase()
  await sb.auth.signOut()
  _session = null
  _listeners.forEach(fn => fn(null))
}

export async function getSession() {
  await loadSupabase()
  return _session
}

export async function getAccessToken() {
  const s = await getSession()
  return s ? s.access_token : null
}

export function onAuthChange(fn) {
  _listeners.push(fn)
  if (_session !== undefined) fn(_session)
}
