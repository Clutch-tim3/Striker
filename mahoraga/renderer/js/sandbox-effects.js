'use strict';

/**
 * sandbox-effects.js — visual effects for attack detection and adaptation.
 */
const SandboxEffects = (function () {

  function scanline() {
    const el = document.createElement('div');
    el.className = 'sb-scanline';
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 1600);
  }

  function matrixRain(count = 8) {
    const chars = '01アイウエオカキクケコ▓▒░█◈⊗◉■□';
    for (let i = 0; i < count; i++) {
      const col = document.createElement('div');
      col.className = 'sb-matrix-col';
      col.style.left = (5 + Math.random() * 90) + '%';
      col.style.setProperty('--dur', (1 + Math.random() * 2) + 's');
      col.style.setProperty('--delay', (Math.random() * 0.5) + 's');
      col.textContent = Array.from({ length: 20 },
        () => chars[Math.floor(Math.random() * chars.length)]).join('');
      document.body.appendChild(col);
      setTimeout(() => col.remove(), 3500);
    }
  }

  function flashScreen(colour) {
    colour = colour || 'rgba(220,80,80,0.15)';
    const flash = document.createElement('div');
    flash.style.cssText = `position:fixed;inset:0;background:${colour};pointer-events:none;z-index:999;animation:sb-fadeOut 0.6s ease both;`;
    document.body.appendChild(flash);
    setTimeout(() => flash.remove(), 700);
  }

  function adaptationBox(attackType, terminalId) {
    terminalId = terminalId || 'sb-terminal-body';
    const terminal = document.getElementById(terminalId);
    if (!terminal) return;

    const box = document.createElement('div');
    box.className = 'sb-adapt-box';
    box.innerHTML = [
      '<span class="sb-adapt-border">╔══════════════════════════════════════╗</span>',
      '<span class="sb-adapt-title">║  ⚡ STRIKER IS ADAPTING              ║</span>',
      `<span class="sb-adapt-line">║  Learning: ${(attackType || 'unknown').padEnd(24)} ║</span>`,
      '<span class="sb-adapt-line">║  Updating antibody model...          ║</span>',
      '<span class="sb-adapt-line">║  <span id="sb-adapt-bar">[░░░░░░░░░░░░░░░░░░░░] 0%  </span> ║</span>',
      '<span class="sb-adapt-border">╚══════════════════════════════════════╝</span>',
    ].join('\n');

    terminal.appendChild(box);
    terminal.scrollTop = terminal.scrollHeight;

    let progress = 0;
    const iv = setInterval(() => {
      progress = Math.min(progress + 3, 100);
      const filled = Math.round(progress / 5);
      const empty  = 20 - filled;
      const barEl  = box.querySelector('#sb-adapt-bar');
      if (barEl) {
        barEl.textContent = '[' + '█'.repeat(filled) + '░'.repeat(empty) + '] ' + progress + '%  ';
      }
      if (progress >= 100) {
        clearInterval(iv);
        setTimeout(() => {
          box.remove();
          _printLine(terminal, '[·] Adaptation complete. Model updated.', 'sb-t-blue');
        }, 600);
      }
    }, 60);
  }

  function setEyeState(state) {
    const eyeChars = { idle: '◈', detect: '⊗', adapt: '◉', win: '◆' };
    const ch = eyeChars[state] || '◈';
    document.querySelectorAll('.sb-mascot-eye').forEach(eye => {
      eye.textContent = ch;
      eye.className = 'sb-mascot-eye sb-eye-' + state;
    });
  }

  function glitchMascot() {
    const face = document.getElementById('sb-mascot-face');
    if (!face) return;
    face.classList.add('sb-glitch');
    setTimeout(() => face.classList.remove('sb-glitch'), 500);
  }

  function _printLine(terminal, text, cls) {
    const div = document.createElement('div');
    div.className = cls || 'sb-t-dim';
    div.textContent = text;
    terminal.appendChild(div);
    terminal.scrollTop = terminal.scrollHeight;
  }

  return { scanline, matrixRain, flashScreen, adaptationBox, setEyeState, glitchMascot };
})();

window.SandboxEffects = SandboxEffects;
