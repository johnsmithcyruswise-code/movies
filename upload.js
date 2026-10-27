import { getAccessToken } from './auth.js'
import { WORKER_URL } from './supabase-config.js'

export function openUploadDialog(onDone) {
  const overlay = document.createElement('div')
  overlay.className = 'modal open'
  overlay.innerHTML = `
    <div class="modal-box" style="max-width:560px;">
      <div class="modal-head">
        <div class="m-info">
          <h2>Upload a film</h2>
          <p>Goes straight to storage. Appears in search once confirmed.</p>
        </div>
        <button class="btn-close" id="upClose">&times;</button>
      </div>
      <div class="modal-body">
        <div style="display:flex;flex-direction:column;gap:12px;">
          <input id="upTitle" placeholder="Film title" style="padding:12px;border-radius:8px;border:1px solid rgba(255,255,255,.1);background:rgba(255,255,255,.04);color:#fff;font-size:14px;">
          <input id="upYear" type="number" placeholder="Year (optional)" style="padding:12px;border-radius:8px;border:1px solid rgba(255,255,255,.1);background:rgba(255,255,255,.04);color:#fff;font-size:14px;">
          <textarea id="upDesc" placeholder="Short description (optional)" rows="3" style="padding:12px;border-radius:8px;border:1px solid rgba(255,255,255,.1);background:rgba(255,255,255,.04);color:#fff;font-size:14px;resize:vertical;"></textarea>
          <input id="upFile" type="file" accept="video/*,audio/*" style="padding:10px;border-radius:8px;border:1px solid rgba(255,255,255,.1);background:rgba(255,255,255,.04);color:#fff;font-size:13px;">
          <div id="upProgress" style="font-size:12px;color:#999;min-height:16px;"></div>
          <button id="upGo" style="padding:13px;border-radius:60px;border:none;cursor:pointer;font-weight:600;color:#1a1205;background:linear-gradient(135deg,#f59e0b,#f97316,#facc15);font-size:14px;">Upload</button>
        </div>
      </div>
    </div>`
  document.body.appendChild(overlay)

  const close = () => overlay.remove()
  overlay.querySelector('#upClose').onclick = close
  overlay.onclick = e => { if (e.target === overlay) close() }

  overlay.querySelector('#upGo').onclick = async () => {
    const title = overlay.querySelector('#upTitle').value.trim()
    const year  = overlay.querySelector('#upYear').value.trim()
    const desc  = overlay.querySelector('#upDesc').value.trim()
    const file  = overlay.querySelector('#upFile').files[0]
    const prog  = overlay.querySelector('#upProgress')
    const btn   = overlay.querySelector('#upGo')

    if (!title || !file) { prog.textContent = 'Title and file are required.'; return }

    btn.disabled = true
    try {
      const token = await getAccessToken()
      if (!token) { prog.textContent = 'Please sign in first.'; btn.disabled = false; return }

      prog.textContent = 'Requesting upload URL…'
      const presignRes = await fetch(`${WORKER_URL}/upload`, {
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' },
        body: JSON.stringify({ filename: file.name, contentType: file.type, size: file.size }),
      })
      if (!presignRes.ok) throw new Error('presign failed: ' + await presignRes.text())
      const { uploadUrl, movieId, objectKey, publicUrl } = await presignRes.json()

      prog.textContent = 'Uploading…'
      const xhr = new XMLHttpRequest()
      await new Promise((resolve, reject) => {
        xhr.upload.onprogress = e => {
          if (e.lengthComputable) prog.textContent = `Uploading… ${Math.round(e.loaded / e.total * 100)}%`
        }
        xhr.onload = () => xhr.status < 300 ? resolve() : reject(new Error('storage PUT ' + xhr.status))
        xhr.onerror = () => reject(new Error('storage network error'))
        xhr.open('PUT', uploadUrl)
        xhr.setRequestHeader('Content-Type', file.type)
        xhr.send(file)
      })

      prog.textContent = 'Saving metadata…'
      const confirmRes = await fetch(`${WORKER_URL}/confirm`, {
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          movieId, title, year: year || null, description: desc,
          objectKey, publicUrl, contentType: file.type, size: file.size,
        }),
      })
      if (!confirmRes.ok) throw new Error('confirm failed: ' + await confirmRes.text())

      prog.textContent = '✅ Done — the film is now searchable.'
      setTimeout(() => { close(); onDone && onDone() }, 900)
    } catch (err) {
      prog.textContent = '❌ ' + err.message
      btn.disabled = false
    }
  }
}
