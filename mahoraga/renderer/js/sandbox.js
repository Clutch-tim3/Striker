'use strict';

// ── Target definitions ────────────────────────────────────────────────────────

const TARGETS = [
  {
    id: 'WIN-SRV-01', name: 'WIN-SRV-01', os: 'Windows Server 2019',
    ip: '10.0.0.12', diff: 'medium', vulns: 4, platform: 'Windows',
    desc: 'Exposed RDP, unpatched SMB, weak admin credentials.',
  },
  {
    id: 'UBN-WEB-03', name: 'UBN-WEB-03', os: 'Ubuntu 22.04 LTS',
    ip: '10.0.0.31', diff: 'hard', vulns: 6, platform: 'Linux',
    desc: 'Web server with misconfigured Apache, exposed /admin.',
  },
  {
    id: 'MAC-DEV-07', name: 'MAC-DEV-07', os: 'macOS Ventura 13.4',
    ip: '10.0.0.47', diff: 'easy', vulns: 3, platform: 'Darwin',
    desc: 'Developer machine with exposed SSH and Docker daemon.',
  },
  {
    id: 'WIN-DC-01', name: 'WIN-DC-01', os: 'Windows Server 2022 DC',
    ip: '10.0.0.5', diff: 'expert', vulns: 8, platform: 'Windows',
    desc: 'Domain controller — Kerberoastable SPNs, DCSync risk.',
  },
];

// ── State ─────────────────────────────────────────────────────────────────────

let state = {
  selectedTarget:   null,
  selectedModule:   null,
  currentModules:   [],
  running:          false,
  score:            0,
  caught:           0,
  evaded:           0,
  log:              [],
  completedModules: new Set(),
};

let _progressInterval = null;

// ── Init ──────────────────────────────────────────────────────────────────────

function sbInit() {
  window.mahoraga.onEvent(handlePythonEvent);

  // ── Event delegation — no inline onclick anywhere ─────────────────────────

  // Target list
  document.getElementById('sb-target-list').addEventListener('click', function (e) {
    const card = e.target.closest('[data-target-id]');
    if (card) sbSelectTarget(card.dataset.targetId);
  });

  // Module list
  document.getElementById('sb-module-list').addEventListener('click', function (e) {
    const card = e.target.closest('[data-module-id]');
    if (card) sbModuleClick(card.dataset.moduleId);
  });

  // Reset button
  const btnReset = document.getElementById('btn-reset');
  if (btnReset) btnReset.addEventListener('click', sbReset);

  // Result modal — close on overlay click
  const modal = document.getElementById('sb-result-modal');
  if (modal) {
    modal.addEventListener('click', function (e) {
      if (e.target === modal) sbCloseModal();
    });
  }

  // Modal buttons (close / next attack)
  const btnClose = document.getElementById('sb-modal-close');
  const btnNext  = document.getElementById('sb-modal-next');
  if (btnClose) btnClose.addEventListener('click', sbCloseModal);
  if (btnNext)  btnNext.addEventListener('click', function () {
    sbCloseModal();
    sbNextAttack();
  });

  renderTargets();
  renderModules();
  renderLog();
}

// ── Python event router ───────────────────────────────────────────────────────

function handlePythonEvent(event) {
  const d = event.data;
  switch (event.type) {
    case 'SANDBOX_MODULES':         onSandboxModules(d);    break;
    case 'SANDBOX_ATTACK_STARTED':  onAttackStarted(d);     break;
    case 'SANDBOX_TERMINAL_LINE':   onTerminalLine(d);      break;
    case 'SANDBOX_DETECTION':       onSandboxDetection(d);  break;
    case 'SANDBOX_ATTACK_COMPLETE': onAttackComplete(d);    break;
    case 'SANDBOX_SESSION_RESET':   onSessionReset(d);      break;
    case 'SANDBOX_ERROR':           onSandboxError(d);      break;
  }
}

// ── Python event handlers ─────────────────────────────────────────────────────

function onSandboxModules({ modules, target_id }) {
  if (target_id !== state.selectedTarget) return;
  state.currentModules = modules || [];
  renderModules();
  sbTerminalPrint([['dim', `${state.currentModules.length} attack modules loaded. Select one to launch.`]]);
}

function onAttackStarted(d) {
  sbTerminalPrint([
    ['dim', ''],
    ['red', `> ${d.module_name} launched against ${d.target_id}`],
    ['dim', `  ${d.mitre_id} · ${d.technique}`],
    ['dim', `  ~${d.duration_sec}s runtime · ${d.points} pts at stake`],
  ]);
  document.getElementById('sb-live-dot').style.opacity = '1';
  startProgressBar(d.duration_sec);
}

function onTerminalLine({ line }) {
  const cls = line.startsWith('[MAHORAGA]') ? 'red'
            : line.startsWith('>') ? 'green'
            : 'dim';
  sbTerminalPrint([[cls, line]]);
}

function onSandboxDetection(d) {
  const caught = d.result === 'caught';
  state.caught = d.stats.caught;
  state.evaded = d.stats.evaded;
  state.score  = d.stats.points;
  updateScoreUI();

  if (caught) {
    sbTerminalPrint([
      ['dim', ''],
      ['red', '>> MAHORAGA DETECTION <<<'],
      ['red', `   THREAT NEUTRALISED — sev ${d.severity}/10 · +${d.points} pts`],
      ['dim', ''],
    ]);
  } else {
    sbTerminalPrint([
      ['dim', ''],
      ['yellow', '>> LOW-CONFIDENCE SIGNAL <<<'],
      ['yellow', `   sev ${d.severity}/10 — below threshold, not escalated`],
      ['dim', ''],
    ]);
  }

  sbAddDetectionEvent({
    caught,
    label:    d.attack_type || d.module_id || 'unknown',
    severity: d.severity,
    points:   d.points || 0,
  });
}

function onAttackComplete(d) {
  clearInterval(_progressInterval);
  const fill = document.getElementById('sb-progress-fill');
  const pct  = document.getElementById('sb-progress-pct');
  if (fill) fill.style.width = '100%';
  if (pct)  pct.textContent  = '100%';
  setTimeout(() => {
    const el = document.getElementById('sb-attack-progress');
    if (el) el.style.display = 'none';
  }, 600);

  state.running = false;
  state.completedModules.add(d.module_id);
  document.getElementById('sb-live-dot').style.opacity = '0.3';
  sbTerminalPrint([['dim', ''], ['dim', '[Attack complete]'], ['dim', '']]);

  const mod = state.currentModules.find(m => m.id === d.module_id)
    || { name: d.module_id, mitre_id: '—', technique: '—', points: 0 };
  showResultModal(mod, d.stats);

  state.log.unshift({
    name:   mod.name || d.module_id,
    caught: d.stats.caught > 0,
    pts:    d.stats.points,
  });
  renderLog();
  renderModules();
}

function onSessionReset() {
  state = {
    selectedTarget: null, selectedModule: null, currentModules: [],
    running: false, score: 0, caught: 0, evaded: 0,
    log: [], completedModules: new Set(),
  };
  updateScoreUI();
  document.getElementById('sb-detect-body').innerHTML =
    '<div class="sb-detect-empty" id="sb-detect-empty">No attacks launched yet.<br>Detection events will appear here.</div>';
  document.getElementById('sb-terminal-body').innerHTML =
    '<div class="sb-terminal-welcome">' +
    '<span class="sb-t-red">mahoraga</span><span class="sb-t-dim">@sandbox</span><span class="sb-t-dim">:~$</span>' +
    ' <span class="sb-t-muted">Session reset. Select a target to begin.</span>' +
    '</div>';
  document.getElementById('sb-live-dot').style.opacity = '0.3';
  document.getElementById('sb-terminal-title').textContent = 'mahoraga-sandbox — bash';
  const prog = document.getElementById('sb-attack-progress');
  if (prog) prog.style.display = 'none';
  renderTargets();
  renderModules();
  renderLog();
}

function onSandboxError({ message }) {
  sbTerminalPrint([['red', `[ERROR] ${message}`]]);
  state.running = false;
  renderModules();
}

// ── Targets ───────────────────────────────────────────────────────────────────
// data-target-id instead of onclick — avoids CSP inline-script block

function renderTargets() {
  const el = document.getElementById('sb-target-list');
  el.innerHTML = TARGETS.map(t => `
    <div class="sb-target${state.selectedTarget === t.id ? ' selected' : ''}"
         data-target-id="${t.id}">
      <div class="sb-target-row">
        <div>
          <div class="sb-target-name">${t.name}</div>
          <div class="sb-target-os">${t.os}</div>
          <div class="sb-target-ip">${t.ip}</div>
        </div>
        <span class="sb-diff sb-diff-${t.diff}">${t.diff}</span>
      </div>
      <div class="sb-target-vuln-count"><span>${t.vulns}</span> vulnerabilities</div>
    </div>
  `).join('');
}

function sbSelectTarget(id) {
  if (state.running) return;
  state.selectedTarget = id;
  state.selectedModule = null;
  state.currentModules = [];
  renderTargets();
  renderModules();

  const t = TARGETS.find(x => x.id === id);
  document.getElementById('sb-terminal-title').textContent = `${t.name} — ${t.ip}`;
  sbTerminalPrint([
    ['dim', ''],
    ['dim', '-----------------------------------------'],
    ['bright', `Target: ${t.name} (${t.ip})`],
    ['dim', `OS: ${t.os}  ·  ${t.vulns} vulnerabilities`],
    ['dim', t.desc],
    ['dim', '-----------------------------------------'],
    ['dim', 'Loading attack modules...'],
  ]);

  document.getElementById('sb-module-list').innerHTML =
    '<div class="sb-module-empty">Loading attack modules...</div>';

  window.mahoraga.send('SANDBOX_GET_MODULES', { target_id: id });
}

// ── Modules ───────────────────────────────────────────────────────────────────
// data-module-id instead of onclick

function renderModules() {
  const el = document.getElementById('sb-module-list');
  if (!state.selectedTarget) {
    el.innerHTML = '<div class="sb-module-empty">Select a target to see available attack modules.</div>';
    return;
  }
  if (!state.currentModules.length) {
    return;
  }
  el.innerHTML = state.currentModules.map(m => {
    const done     = state.completedModules.has(m.id);
    const selected = state.selectedModule === m.id;
    const disabled = state.running;
    return `
      <div class="sb-module${done ? ' done' : ''}${selected ? ' selected' : ''}${disabled ? ' disabled' : ''}"
           data-module-id="${m.id}">
        <div class="sb-module-title">
          <span>${m.name}</span>
          <span class="sb-module-badge sb-badge-${m.difficulty}">${m.difficulty}</span>
        </div>
        <div class="sb-module-desc">${m.description}</div>
        <div class="sb-module-footer">
          <span class="sb-module-mitre">${m.mitre_id}</span>
          <span class="sb-module-dur">~${m.duration_sec}s</span>
          <span style="margin-left:auto;font-size:10px;font-weight:700;color:var(--text-3)">+${m.points} pts</span>
        </div>
        ${selected && !done && !disabled ? '<div class="sb-module-launch-hint">Click again to launch &#9654;</div>' : ''}
        <div class="sb-module-tick">&#10003;</div>
      </div>
    `;
  }).join('');
}

function sbModuleClick(moduleId) {
  if (state.running) return;
  if (state.selectedModule === moduleId) {
    _doLaunch(moduleId);
  } else {
    state.selectedModule = moduleId;
    renderModules();
  }
}

function _doLaunch(moduleId) {
  if (!state.selectedTarget || !moduleId || state.running) return;
  const mod = state.currentModules.find(m => m.id === moduleId);
  if (!mod) return;

  state.running = true;
  renderModules();
  sbTerminalPrint([['dim', ''], ['red', `> Launching: ${mod.name}`]]);
  window.mahoraga.send('SANDBOX_LAUNCH', { module_id: moduleId, target_id: state.selectedTarget });
}

// ── Progress bar ──────────────────────────────────────────────────────────────

function startProgressBar(durationSec) {
  const progressEl   = document.getElementById('sb-attack-progress');
  const progressFill = document.getElementById('sb-progress-fill');
  const progressPct  = document.getElementById('sb-progress-pct');
  const progressText = document.getElementById('sb-progress-text');

  progressEl.style.display = 'block';
  progressFill.style.width = '0%';
  progressPct.textContent  = '0%';

  const mod = state.currentModules.find(m => m.id === state.selectedModule);
  if (progressText) progressText.textContent = mod ? `${mod.name}...` : 'Running exploit...';

  let elapsed = 0;
  const total = durationSec * 1000;
  clearInterval(_progressInterval);
  _progressInterval = setInterval(() => {
    elapsed += 200;
    const pct = Math.min(Math.round((elapsed / total) * 95), 95);
    progressFill.style.width = pct + '%';
    progressPct.textContent  = pct + '%';
    if (elapsed >= total) clearInterval(_progressInterval);
  }, 200);
}

// ── Terminal ──────────────────────────────────────────────────────────────────

function sbTerminalPrint(lines) {
  const body = document.getElementById('sb-terminal-body');
  lines.forEach(([cls, text]) => {
    const div = document.createElement('div');
    div.className = cls === 'dim'    ? 'sb-t-dim'    :
                    cls === 'bright' ? 'sb-t-bright sb-t-prompt' :
                    cls === 'green'  ? 'sb-t-green'  :
                    cls === 'yellow' ? 'sb-t-yellow'  :
                    cls === 'blue'   ? 'sb-t-blue'    :
                    cls === 'red'    ? 'sb-t-red'     : 'sb-t-muted';
    div.textContent = text;
    body.appendChild(div);
  });
  body.scrollTop = body.scrollHeight;
}

// ── Detection feed ────────────────────────────────────────────────────────────

function sbAddDetectionEvent({ caught, label, severity, points }) {
  const body  = document.getElementById('sb-detect-body');
  const empty = document.getElementById('sb-detect-empty');
  if (empty) empty.style.display = 'none';

  const ev = document.createElement('div');
  ev.className = 'sb-detect-event ' + (caught ? 'caught' : 'evaded');
  const top    = document.createElement('div');
  top.className = 'sb-de-top';
  const nameEl   = document.createElement('span');
  nameEl.className = 'sb-de-event';
  nameEl.textContent = label;
  const verdictEl  = document.createElement('span');
  verdictEl.className = 'sb-de-verdict ' + (caught ? 'caught' : 'evaded');
  verdictEl.textContent = caught ? 'DETECTED' : 'EVADED';
  top.appendChild(nameEl);
  top.appendChild(verdictEl);
  const detail = document.createElement('div');
  detail.className = 'sb-de-detail';
  detail.textContent = 'sev=' + severity + (caught ? ' · +' + points + ' pts' : '');
  ev.appendChild(top);
  ev.appendChild(detail);
  body.insertBefore(ev, body.firstChild);
}

// ── Result modal ──────────────────────────────────────────────────────────────

function showResultModal(mod, stats) {
  const top     = document.getElementById('sb-result-top');
  const icon    = document.getElementById('sb-result-icon');
  const verdict = document.getElementById('sb-result-verdict');
  const sub     = document.getElementById('sb-result-sub');
  const rows    = document.getElementById('sb-result-rows');

  const didCatch = stats.caught > 0;
  top.className       = 'sb-result-top ' + (didCatch ? 'detected' : 'evaded');
  icon.textContent    = didCatch ? '\uD83D\uDEE1' : '\uD83D\uDC80';
  verdict.textContent = didCatch ? 'Detected' : 'Evaded';
  sub.textContent     = didCatch
    ? 'Mahoraga caught the attack before it completed.'
    : "Attack succeeded — Mahoraga missed this one. It's adapting now.";

  const makeRow = (lbl, val, style) => {
    const row = document.createElement('div');
    row.className = 'sb-result-row';
    const l = document.createElement('span'); l.className = 'lbl'; l.textContent = lbl;
    const v = document.createElement('span'); v.className = 'val'; v.textContent = val;
    if (style) v.setAttribute('style', style);
    row.appendChild(l); row.appendChild(v);
    return row;
  };
  rows.innerHTML = '';
  rows.appendChild(makeRow('Attack',      mod.name));
  rows.appendChild(makeRow('MITRE',       mod.mitre_id || '—'));
  rows.appendChild(makeRow('Technique',   mod.technique || '—'));
  rows.appendChild(makeRow('Caught',      stats.caught));
  rows.appendChild(makeRow('Evaded',      stats.evaded));
  rows.appendChild(makeRow('Total points', '\u26A1 ' + stats.points, 'color:var(--red)'));

  document.getElementById('sb-result-modal').style.display = 'flex';
}

function sbCloseModal() {
  document.getElementById('sb-result-modal').style.display = 'none';
}

function sbNextAttack() {
  document.getElementById('sb-module-list').scrollIntoView({ behavior: 'smooth' });
}

// ── Score UI ──────────────────────────────────────────────────────────────────

function updateScoreUI() {
  document.getElementById('sb-score').textContent  = state.score;
  document.getElementById('sb-caught').textContent = state.caught;
  document.getElementById('sb-evaded').textContent = state.evaded;
}

// ── Session log ───────────────────────────────────────────────────────────────

function renderLog() {
  const el = document.getElementById('sb-log');
  if (!state.log.length) {
    el.innerHTML = '<div class="sb-log-empty">No completed attacks yet.</div>';
    return;
  }
  el.innerHTML = state.log.slice(0, 10).map(e => `
    <div class="sb-log-row">
      <span class="sb-log-name">${e.name}</span>
      <div class="sb-log-right">
        <span class="sb-log-result ${e.caught ? 'caught' : 'evaded'}">${e.caught ? 'detected' : 'evaded'}</span>
        <span class="sb-log-pts">\u26A1 ${e.pts}</span>
      </div>
    </div>
  `).join('');
}

// ── Reset ─────────────────────────────────────────────────────────────────────

function sbReset() {
  if (state.running) return;
  window.mahoraga.send('SANDBOX_RESET', {});
}

// ── Boot ──────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', sbInit);
