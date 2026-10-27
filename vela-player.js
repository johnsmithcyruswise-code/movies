import Plyr from 'https://cdn.jsdelivr.net/npm/plyr@3.7.8/dist/plyr.mjs'

export class VelaPlayer {
  constructor(root, opts = {}) {
    this.root = root
    this.opts = opts
    const video = root.querySelector('video.vp-video')
    if (!video) throw new Error('[VelaPlayer] missing <video class="vp-video">')
    this.video = video
    this.currentQualityIdx = 0

    const accent = opts.accent || root.dataset.accent
    if (accent) root.style.setProperty('--vp-accent', accent)

    this.qualities = Array.from(video.querySelectorAll('source'))
      .map((s, i) => ({
        quality: s.dataset.quality || `src${i + 1}`,
        size: Number(s.getAttribute('size') || 0),
        label: s.dataset.quality || `${i + 1}`,
      }))
      .sort((a, b) => b.size - a.size)

    this.plyr = new Plyr(video, {
      controls: ['play-large','play','progress','current-time','duration','mute','volume','settings','pip','fullscreen'],
      settings: ['quality','speed'],
      speed: { selected: 1, options: [0.5,0.75,1,1.25,1.5,2] },
      keyboard: { focused: true, global: false },
      tooltips: { controls: true, seek: true },
      seekTime: 10,
      ratio: '16:9',
      fullscreen: { enabled: true, fallback: true, iosNative: true },
      storage: { enabled: true, key: 'vela-player' },
      autoplay: opts.autoplay || false,
      muted: opts.autoplay || false,
    })

    this.wireLoading()
    this.wireError()
    this.wireEvents()
    this.wireQualityControl()
    if (opts.autoplay) this.plyr.play().catch(() => {})
  }

  wireLoading() {
    const loader = this.root.querySelector('.vp-loader')
    const show = () => { loader.hidden = false }
    const hide = () => { loader.hidden = true }
    hide()
    this.video.addEventListener('loadstart', show)
    this.video.addEventListener('waiting', show)
    this.video.addEventListener('stalled', show)
    this.video.addEventListener('seeking', show)
    this.video.addEventListener('canplay', hide)
    this.video.addEventListener('playing', hide)
    this.video.addEventListener('seeked', hide)
    this.video.addEventListener('loadedmetadata', hide)
  }

  wireError() {
    const box = this.root.querySelector('.vp-error')
    const msg = this.root.querySelector('.vp-error-msg')
    const retry = this.root.querySelector('.vp-retry')
    this.video.addEventListener('error', () => {
      const code = this.video.error?.code
      const human =
        code === 1 ? 'Playback aborted.' :
        code === 2 ? 'Network error — check your connection.' :
        code === 3 ? 'Video decode error — the format may not be supported.' :
        code === 4 ? 'Video source not found or unavailable.' :
        'Unknown playback error.'
      msg.textContent = human
      box.hidden = false
      this.opts.onError?.(human)
    })
    retry.addEventListener('click', () => {
      box.hidden = true
      this.video.load()
      this.plyr.play().catch(() => {})
    })
  }

  wireEvents() {
    let lastQuality = this.currentQualityLabel()
    this.video.addEventListener('timeupdate', () => {
      this.opts.onTimeUpdate?.(this.video.currentTime, this.video.duration || 0)
      const q = this.currentQualityLabel()
      if (q !== lastQuality) { lastQuality = q; this.opts.onQualityChange?.(q) }
    })
    this.video.addEventListener('play', () => this.opts.onPlay?.())
    this.video.addEventListener('pause', () => this.opts.onPause?.())
    this.video.addEventListener('ended', () => this.opts.onEnded?.())
  }

  currentQualityLabel() {
    return this.qualities[this.currentQualityIdx]?.label || 'auto'
  }

  switchQuality(idx, keepTime = true) {
    if (idx === this.currentQualityIdx) return
    if (!this.qualities[idx]) return
    const wasPlaying = !this.video.paused
    const t = this.video.currentTime
    const target = Array.from(this.video.querySelectorAll('source'))
      .find(s => (s.dataset.quality || '') === this.qualities[idx].label)
    if (!target) return
    this.video.src = target.src
    this.currentQualityIdx = idx
    if (keepTime) this.video.currentTime = t
    this.video.load()
    if (wasPlaying) this.video.play().catch(() => {})
    this.opts.onQualityChange?.(this.qualities[idx].label)
  }

  wireQualityControl() {
    if (this.qualities.length < 2) return
    const controls = this.root.querySelector('.plyr__controls')
    if (!controls) { setTimeout(() => this.wireQualityControl(), 60); return }
    if (controls.querySelector('.vp-quality-btn')) return

    const btn = document.createElement('button')
    btn.type = 'button'
    btn.className = 'plyr__control vp-quality-btn'
    btn.title = 'Quality'
    btn.innerHTML = `<span class="vp-q-label">${this.currentQualityLabel()}</span>`
    btn.addEventListener('click', (e) => { e.stopPropagation(); this.openQualityMenu(btn) })
    const settings = controls.querySelector('[data-plyr="settings"]')
    if (settings && settings.parentElement) settings.parentElement.insertBefore(btn, settings)
    else controls.appendChild(btn)
  }

  openQualityMenu(anchor) {
    let menu = this.root.querySelector('.vp-quality-menu')
    if (!menu) {
      menu = document.createElement('div')
      menu.className = 'vp-quality-menu'
      this.root.appendChild(menu)
    }
    menu.innerHTML = ''
    this.qualities.forEach((q, i) => {
      const b = document.createElement('button')
      b.type = 'button'
      b.textContent = q.label
      if (i === this.currentQualityIdx) b.classList.add('active')
      b.addEventListener('click', () => {
        this.switchQuality(i)
        menu.classList.remove('open')
        const label = anchor.querySelector('.vp-q-label')
        if (label) label.textContent = q.label
      })
      menu.appendChild(b)
    })
    const rect = anchor.getBoundingClientRect()
    const rootRect = this.root.getBoundingClientRect()
    menu.style.left = `${rect.left - rootRect.left}px`
    menu.style.bottom = `${rootRect.bottom - rect.top + 8}px`
    menu.classList.add('open')
    const closeOnOutside = (e) => {
      if (!menu.contains(e.target) && e.target !== anchor) {
        menu.classList.remove('open')
        document.removeEventListener('click', closeOnOutside)
      }
    }
    setTimeout(() => document.addEventListener('click', closeOnOutside), 0)
  }

  play() { return this.plyr.play() }
  pause() { this.plyr.pause() }
  toggle() { this.plyr.togglePlay() }
  setQuality(label) {
    const idx = this.qualities.findIndex(q => q.label === label)
    if (idx >= 0) this.switchQuality(idx)
  }
  destroy() { this.plyr.destroy() }
}

export function initAllVelaPlayers(opts = {}) {
  return Array.from(document.querySelectorAll('.vela-player'))
    .map(el => new VelaPlayer(el, opts))
}

if (typeof window !== 'undefined') {
  window.VelaPlayer = VelaPlayer
  window.initAllVelaPlayers = initAllVelaPlayers
}
