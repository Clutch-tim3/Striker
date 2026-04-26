'use strict';

/**
 * ctf-animation.js — CTF win/lose full-screen overlays.
 */
const CTFAnimation = (function () {

  const WIN_ART = [
    '  ██╗   ██╗ ██████╗ ██╗   ██╗    ██╗    ██╗ ██████╗ ███╗   ██╗',
    '  ╚██╗ ██╔╝██╔═══██╗██║   ██║    ██║    ██║██╔═══██╗████╗  ██║',
    '   ╚████╔╝ ██║   ██║██║   ██║    ██║ █╗ ██║██║   ██║██╔██╗ ██║',
    '    ╚██╔╝  ██║   ██║██║   ██║    ██║███╗██║██║   ██║██║╚██╗██║',
    '     ██║   ╚██████╔╝╚██████╔╝    ╚███╔███╔╝╚██████╔╝██║ ╚████║',
    '     ╚═╝    ╚═════╝  ╚═════╝      ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═══╝',
  ];

  const LOSE_ART = [
    '  ██████╗  █████╗ ███████╗███████╗    ██╗      ██████╗ ███████╗████████╗',
    '  ██╔══██╗██╔══██╗██╔════╝██╔════╝    ██║     ██╔═══██╗██╔════╝╚══██╔══╝',
    '  ██████╔╝███████║███████╗█████╗      ██║     ██║   ██║███████╗   ██║   ',
    '  ██╔══██╗██╔══██║╚════██║██╔══╝      ██║     ██║   ██║╚════██║   ██║   ',
    '  ██████╔╝██║  ██║███████║███████╗    ███████╗╚██████╔╝███████║   ██║   ',
    '  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝    ╚══════╝ ╚═════╝ ╚══════╝   ╚═╝  ',
  ];

  function _ensureParticleStyle() {
    if (document.getElementById('ctf-particle-style')) return;
    const style = document.createElement('style');
    style.id = 'ctf-particle-style';
    style.textContent = `
      @keyframes ctf-particle {
        0%   { transform: translate(-50%,-50%) rotate(var(--angle)) translateX(0) scale(1); opacity:1; }
        100% { transform: translate(-50%,-50%) rotate(var(--angle)) translateX(var(--dist)) scale(0); opacity:0; }
      }
      @keyframes sb-fadeOut { to { opacity:0; } }
    `;
    document.head.appendChild(style);
  }

  function _spawnParticles(colour) {
    _ensureParticleStyle();
    const col = colour === 'gold' ? 'rgba(255,200,0,0.9)' : 'rgba(220,80,80,0.9)';
    for (let i = 0; i < 32; i++) {
      const p = document.createElement('div');
      const angle = Math.random() * 360;
      const dist  = 100 + Math.random() * 220;
      p.style.cssText = `
        position:fixed;left:50%;top:50%;width:5px;height:5px;
        border-radius:50%;background:${col};pointer-events:none;z-index:10001;
        --angle:${angle}deg;--dist:${dist}px;
        animation:ctf-particle 1.2s ease-out ${Math.random() * 0.3}s forwards;
      `;
      document.body.appendChild(p);
      setTimeout(() => p.remove(), 1700);
    }
  }

  function _typeArt(el, lines, colour) {
    const full = lines.join('\n');
    el.style.color = colour;
    el.style.textShadow = `0 0 10px ${colour}`;
    let i = 0;
    el.textContent = '';
    const iv = setInterval(() => {
      i += 4;
      el.textContent = full.slice(0, i);
      if (i >= full.length) clearInterval(iv);
    }, 10);
  }

  function _overlay() {
    const existing = document.getElementById('ctf-overlay');
    if (existing) existing.remove();
    const el = document.createElement('div');
    el.id = 'ctf-overlay';
    el.style.cssText = `
      position:fixed;inset:0;background:rgba(0,0,0,0.93);z-index:9999;
      display:flex;align-items:center;justify-content:center;flex-direction:column;
      font-family:'DM Mono',monospace;
    `;
    return el;
  }

  function showWin(stats) {
    const overlay = _overlay();
    overlay.innerHTML = `
      <div style="text-align:center;max-width:660px;padding:0 24px">
        <pre id="ctf-art" style="font-size:11px;line-height:1.3;margin-bottom:24px"></pre>
        <div style="font-size:9px;letter-spacing:0.24em;color:rgba(80,200,120,0.7);margin-bottom:12px">✓ BASE CAPTURED</div>
        <div style="font-family:'Cormorant Garamond',serif;font-weight:300;font-size:46px;color:#fff;letter-spacing:-0.02em;margin-bottom:8px">You broke through.</div>
        <div style="font-size:13px;color:rgba(255,255,255,0.4);font-style:italic;margin-bottom:32px;line-height:1.7">
          Striker did not detect your attack within the challenge window.<br>
          Your technique has been logged as a zero-day for the antibody archive.
        </div>
        <div style="display:flex;gap:16px;justify-content:center;margin-bottom:28px">
          <div style="padding:16px 24px;background:rgba(80,200,120,0.1);border:1px solid rgba(80,200,120,0.3);border-radius:100px;text-align:center">
            <div style="font-size:26px;color:rgba(80,200,120,0.9)">${stats && stats.elapsed ? stats.elapsed : '—'}</div>
            <div style="font-size:8px;letter-spacing:0.12em;color:rgba(255,255,255,0.3)">TIME SURVIVED</div>
          </div>
          <div style="padding:16px 24px;background:rgba(255,200,0,0.1);border:1px solid rgba(255,200,0,0.3);border-radius:100px;text-align:center">
            <div style="font-size:26px;color:rgba(255,200,0,0.9)">${stats && stats.points ? stats.points : 0}</div>
            <div style="font-size:8px;letter-spacing:0.12em;color:rgba(255,255,255,0.3)">POINTS</div>
          </div>
        </div>
        <div style="display:flex;gap:12px;justify-content:center">
          <button onclick="document.getElementById('ctf-overlay').remove()"
            style="padding:12px 28px;border-radius:100px;background:rgba(80,200,120,0.2);border:1px solid rgba(80,200,120,0.4);color:rgba(80,200,120,0.9);font-family:'DM Mono',monospace;font-size:10px;letter-spacing:0.12em;text-transform:uppercase;cursor:pointer">
            Continue
          </button>
        </div>
      </div>`;
    document.body.appendChild(overlay);
    _typeArt(overlay.querySelector('#ctf-art'), WIN_ART, 'rgba(255,200,0,0.9)');
    _spawnParticles('gold');
  }

  function showLose(reason, adaptedIn) {
    const overlay = _overlay();
    overlay.innerHTML = `
      <div style="text-align:center;max-width:700px;padding:0 24px">
        <pre id="ctf-art" style="font-size:10px;line-height:1.3;margin-bottom:24px"></pre>
        <div style="font-size:9px;letter-spacing:0.24em;color:rgba(220,80,80,0.7);margin-bottom:12px">✗ BASE LOST · STRIKER ADAPTED</div>
        <div style="font-family:'Cormorant Garamond',serif;font-weight:300;font-size:46px;color:#fff;letter-spacing:-0.02em;margin-bottom:8px">Striker adapted.</div>
        <div style="font-size:13px;color:rgba(255,255,255,0.4);font-style:italic;margin-bottom:12px;line-height:1.7">
          Your attack was detected, neutralised, and archived as a new antibody.<br>
          Striker is now immune to this technique.
        </div>
        <div style="font-size:10px;color:rgba(220,80,80,0.6);margin-bottom:28px">
          ${adaptedIn ? 'Adapted in: ' + adaptedIn + ' · ' : ''}Reason: ${reason || 'Detection threshold exceeded'}
        </div>
        <div style="display:flex;gap:12px;justify-content:center">
          <button onclick="document.getElementById('ctf-overlay').remove()"
            style="padding:12px 28px;border-radius:100px;background:transparent;border:1px solid rgba(255,255,255,0.15);color:rgba(255,255,255,0.5);font-family:'DM Mono',monospace;font-size:10px;letter-spacing:0.12em;text-transform:uppercase;cursor:pointer">
            Try again
          </button>
          <button onclick="document.getElementById('ctf-overlay').remove(); window.location.href='offense.html'"
            style="padding:12px 28px;border-radius:100px;background:rgba(220,80,80,0.15);border:1px solid rgba(220,80,80,0.35);color:rgba(220,80,80,0.9);font-family:'DM Mono',monospace;font-size:10px;letter-spacing:0.12em;text-transform:uppercase;cursor:pointer">
            View offense tactics →
          </button>
        </div>
      </div>`;
    document.body.appendChild(overlay);
    _typeArt(overlay.querySelector('#ctf-art'), LOSE_ART, 'rgba(220,80,80,0.9)');
    _spawnParticles('red');
  }

  return { showWin, showLose };
})();

window.CTFAnimation = CTFAnimation;
