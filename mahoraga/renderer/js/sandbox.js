'use strict';

// ── Target definitions (match Python TARGET_MODULES keys) ─────────────────

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

// ── State ──────────────────────────────────────────────────────────────────

let state = {
  selectedTarget: null,
  selectedModule: null,
  currentModules: [],
  running: false,
  score: 0,
  caught: 0,
  evaded: 0,
  log: [],
  completedModules: new Set(),
};

let _progressInterval = null;

// ── Init ──────────────────────────────────────────────────────────────────

function sbInit() {
  window.mahoraga.onEvent(handlePythonEvent);
  renderTargets();
  renderModules();
  renderLog();
}

// ── Python event router ───────────────────────────────────────────────────

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

// ── Python event handlers ─────────────────────────────────────────────────

function onSandboxModules({ modules, target_id }) {
  if (target_id !== state.selectedTarget) return; // stale response
  state.currentModules = modules || [];
  renderModules();
  sbTerminalPrint([['dim', `${state.currentModules.length} attack modules loaded. Select one to launch.`]]);
}

function onAttackStarted(d) {
  sbTerminalPrint([
    ['dim', ''],
    ['red', `❯ ${d.module_name} launched against ${d.target_id}`],
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
  state.caught  = d.stats.caught;
  state.evaded  = d.stats.evaded;
  state.score   = d.stats.points;
  updateScoreUI();

  if (caught) {
    sbTerminalPrint([
      ['dim', ''],
      ['red',    `╔══ MAHORAGA DETECTION ══════════════════`],
      ['red',    `║  THREAT NEUTRALISED`],
      ['red',    `║  Severity: ${d.severity}/10  ·  +${d.points} pts scored`],
      ['red',    `╚════════════════════════════════════════`],
      ['dim', ''],
    ]);
  } else {
    sbTerminalPrint([
      ['dim', ''],
      ['yellow', `╔══ MAHORAGA SIGNAL ═════════════════════`],
      ['yellow', `║  Low-confidence signal (sev ${d.severity}/10)`],
      ['yellow', `║  Below escalation threshold — evaded`],
      ['yellow', `╚════════════════════════════════════════`],
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
  sbTerminalPrint([['dim', ''], ['dim', `[Attack complete]`], ['dim', '']]);

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

function onSessionReset(d) {
  state = {
    selectedTarget: null, selectedModule: null, currentModules: [],
    running: false, score: 0, caught: 0, evaded: 0,
    log: [], completedModules: new Set(),
  };
  updateScoreUI();
  document.getElementById('sb-detect-body').innerHTML =
    '<div class="sb-detect-empty" id="sb-detect-empty">No attacks launched yet.<br>Detection events will appear here.</div>';
  document.getElementById('sb-terminal-body').innerHTML = `
    <div class="sb-terminal-welcome">
      <span class="sb-t-red">mahoraga</span><span class="sb-t-dim">@sandbox</span><span class="sb-t-dim">:~$</span>
      <span class="sb-t-muted"> Session reset. Select a target to begin.</span><br><br>
    </div>`;
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

// ── Targets ───────────────────────────────────────────────────────────────

function renderTargets() {
  const el = document.getElementById('sb-target-list');
  el.innerHTML = TARGETS.map(t => `
    <div class="sb-target${state.selectedTarget === t.id ? ' selected' : ''}"
         onclick="sbSelectTarget('${t.id}')">
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
    ['dim', '─────────────────────────────────────────'],
    ['bright', `Target: ${t.name} (${t.ip})`],
    ['dim', `OS: ${t.os}  ·  ${t.vulns} vulnerabilities`],
    ['dim', t.desc],
    ['dim', '─────────────────────────────────────────'],
    ['dim', 'Loading attack modules...'],
  ]);

  document.getElementById('sb-module-list').innerHTML =
    '<div class="sb-module-empty">Loading attack modules...</div>';

  window.mahoraga.send('SANDBOX_GET_MODULES', { target_id: id });
}

// ── Modules ───────────────────────────────────────────────────────────────

function renderModules() {
  const el = document.getElementById('sb-module-list');
  if (!state.selectedTarget) {
    el.innerHTML = '<div class="sb-module-empty">Select a target to see available attack modules.</div>';
    return;
  }
  if (!state.currentModules.length) {
    return; // keep loading state until Python responds
  }
  el.innerHTML = state.currentModules.map(m => {
    const done     = state.completedModules.has(m.id);
    const selected = state.selectedModule === m.id;
    const disabled = state.running;
    return `
      <div class="sb-module${done ? ' done' : ''}${selected ? ' selected' : ''}${disabled ? ' disabled' : ''}"
           onclick="sbModuleClick('${m.id}')">
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
        ${selected && !done && !disabled ? '<div class="sb-module-launch-hint">▶ Click again to launch</div>' : ''}
        <div class="sb-module-tick">✓</div>
      </div>
    `;
  }).join('');
}

function sbModuleClick(moduleId) {
  if (state.running) return;
  if (state.selectedModule === moduleId) {
    // Second click → launch
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

  sbTerminalPrint([['dim', ''], ['red', `❯ Launching: ${mod.name}`]]);

  window.mahoraga.send('SANDBOX_LAUNCH', {
    module_id: moduleId,
    target_id: state.selectedTarget,
  });
}

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

// ── Terminal ──────────────────────────────────────────────────────────────

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

// ── Detection feed ────────────────────────────────────────────────────────

function sbAddDetectionEvent({ caught, label, severity, points }) {
  const body  = document.getElementById('sb-detect-body');
  const empty = document.getElementById('sb-detect-empty');
  if (empty) empty.style.display = 'none';

  const ev = document.createElement('div');
  ev.className = `sb-detect-event ${caught ? 'caught' : 'evaded'}`;
  ev.innerHTML = `
    <div class="sb-de-top">
      <span class="sb-de-event">${label}</span>
      <span class="sb-de-verdict ${caught ? 'caught' : 'evaded'}">${caught ? 'DETECTED' : 'EVADED'}</span>
    </div>
    <div class="sb-de-detail">sev=${severity}${caught ? ` · +${points} pts` : ''}</div>
  `;
  body.insertBefore(ev, body.firstChild);
}

// ── Result modal ──────────────────────────────────────────────────────────

function showResultModal(mod, stats) {
  const top     = document.getElementById('sb-result-top');
  const icon    = document.getElementById('sb-result-icon');
  const verdict = document.getElementById('sb-result-verdict');
  const sub     = document.getElementById('sb-result-sub');
  const rows    = document.getElementById('sb-result-rows');

  const didCatch = stats.caught > 0;
  top.className       = 'sb-result-top ' + (didCatch ? 'detected' : 'evaded');
  icon.textContent    = didCatch ? '🛡' : '💀';
  verdict.textContent = didCatch ? 'Detected' : 'Evaded';
  sub.textContent     = didCatch
    ? 'Mahoraga caught the attack before it completed.'
    : "Attack succeeded — Mahoraga missed this one. It's adapting now.";

  rows.innerHTML = `
    <div class="sb-result-row"><span class="lbl">Attack</span><span class="val">${mod.name}</span></div>
    <div class="sb-result-row"><span class="lbl">MITRE</span><span class="val mono">${mod.mitre_id || '—'}</span></div>
    <div class="sb-result-row"><span class="lbl">Technique</span><span class="val">${mod.technique || '—'}</span></div>
    <div class="sb-result-row"><span class="lbl">Caught</span><span class="val">${stats.caught}</span></div>
    <div class="sb-result-row"><span class="lbl">Evaded</span><span class="val">${stats.evaded}</span></div>
    <div class="sb-result-row"><span class="lbl">Total points</span><span class="val" style="color:var(--red)">⚡ ${stats.points}</span></div>
  `;

  document.getElementById('sb-result-modal').style.display = 'flex';
}

function sbCloseModal(e) {
  if (e && e.target !== document.getElementById('sb-result-modal')) return;
  document.getElementById('sb-result-modal').style.display = 'none';
}

function sbNextAttack() {
  document.getElementById('sb-module-list').scrollIntoView({ behavior: 'smooth' });
}

// ── Score UI ──────────────────────────────────────────────────────────────

function updateScoreUI() {
  document.getElementById('sb-score').textContent  = state.score;
  document.getElementById('sb-caught').textContent = state.caught;
  document.getElementById('sb-evaded').textContent = state.evaded;
}

// ── Session log ───────────────────────────────────────────────────────────

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
        <span class="sb-log-pts">⚡ ${e.pts}</span>
      </div>
    </div>
  `).join('');
}

// ── Reset ─────────────────────────────────────────────────────────────────

function sbReset() {
  if (state.running) return;
  window.mahoraga.send('SANDBOX_RESET', {});
}

// ── Boot ──────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', sbInit);
