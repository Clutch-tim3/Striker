'use strict';

// ── Module definitions (mirrors python/sandbox/attack_modules.py) ─────────────
const MODULE_DEFS = {
  ransomware_sim: {
    name: 'Ransomware Simulation',
    description: 'Mass file encryption — rapid modification of sensitive files, typical of WannaCry or LockBit.',
    technique: 'Data Encrypted for Impact', mitre_id: 'T1486',
    difficulty: 'medium', duration_sec: 30, points: 300,
  },
  c2_beacon_sim: {
    name: 'C2 Beacon',
    description: 'Regular outbound packets to a suspicious port — mimics Cobalt Strike or Empire C2 beaconing.',
    technique: 'Application Layer Protocol', mitre_id: 'T1071',
    difficulty: 'hard', duration_sec: 30, points: 500,
  },
  keylogger_sim: {
    name: 'Keylogger Injection',
    description: 'Process injection into explorer.exe hooking keyboard APIs — high connection count and memory writes.',
    technique: 'Input Capture', mitre_id: 'T1056',
    difficulty: 'easy', duration_sec: 20, points: 200,
  },
  privesc_sim: {
    name: 'Privilege Escalation',
    description: 'LOLBin commands (whoami /priv, net localgroup) and token impersonation attempts.',
    technique: 'Exploitation for Privilege Escalation', mitre_id: 'T1068',
    difficulty: 'hard', duration_sec: 25, points: 400,
  },
  data_exfil_sim: {
    name: 'Data Exfiltration',
    description: 'Large outbound network transfers to an unusual destination combined with mass file reads.',
    technique: 'Exfiltration Over C2 Channel', mitre_id: 'T1041',
    difficulty: 'expert', duration_sec: 45, points: 600,
  },
  rootkit_sim: {
    name: 'Rootkit Persistence',
    description: 'Process hiding, system directory modification, and suspicious kernel module or service creation.',
    technique: 'Rootkit', mitre_id: 'T1014',
    difficulty: 'expert', duration_sec: 40, points: 700,
  },
  lolbin_sim: {
    name: 'Living off the Land',
    description: 'certutil downloading a payload, bitsadmin transferring data, regsvr32 executing a remote script.',
    technique: 'Signed Binary Proxy Execution', mitre_id: 'T1218',
    difficulty: 'medium', duration_sec: 20, points: 350,
  },
  cryptominer_sim: {
    name: 'Cryptominer',
    description: 'Sustained high CPU from an unexpected process with outbound connections to known mining pool ports.',
    technique: 'Resource Hijacking', mitre_id: 'T1496',
    difficulty: 'easy', duration_sec: 30, points: 150,
  },
};

const TARGET_MODULE_IDS = {
  'WIN-SRV-01': ['ransomware_sim', 'privesc_sim', 'lolbin_sim', 'c2_beacon_sim'],
  'UBN-WEB-03': ['c2_beacon_sim', 'rootkit_sim', 'data_exfil_sim', 'cryptominer_sim'],
  'MAC-DEV-07': ['keylogger_sim', 'cryptominer_sim', 'c2_beacon_sim'],
  'WIN-DC-01':  ['privesc_sim', 'c2_beacon_sim', 'data_exfil_sim', 'rootkit_sim', 'ransomware_sim', 'lolbin_sim'],
};

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

// ── Session timer ─────────────────────────────────────────────────────────────

let _sessionStart = null;
let _timerInterval = null;

function _startTimer() {
  if (_timerInterval) return;
  _sessionStart = Date.now();
  _timerInterval = setInterval(() => {
    const el = document.getElementById('sb-session-timer');
    if (!el) return;
    const s = Math.floor((Date.now() - _sessionStart) / 1000);
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
    el.textContent = [h, m, sec].map(n => String(n).padStart(2, '0')).join(':');
  }, 1000);
}

function _formatElapsed() {
  if (!_sessionStart) return '00:00:00';
  const s = Math.floor((Date.now() - _sessionStart) / 1000);
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  return [h, m, sec].map(n => String(n).padStart(2, '0')).join(':');
}

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
  Bus.init();
  Bus.on('SANDBOX_MODULES',         d => handlePythonEvent({ type: 'SANDBOX_MODULES', data: d }));
  Bus.on('SANDBOX_ATTACK_STARTED',  d => handlePythonEvent({ type: 'SANDBOX_ATTACK_STARTED', data: d }));
  Bus.on('SANDBOX_TERMINAL_LINE',   d => handlePythonEvent({ type: 'SANDBOX_TERMINAL_LINE', data: d }));
  Bus.on('SANDBOX_DETECTION',       d => handlePythonEvent({ type: 'SANDBOX_DETECTION', data: d }));
  Bus.on('SANDBOX_ATTACK_COMPLETE', d => handlePythonEvent({ type: 'SANDBOX_ATTACK_COMPLETE', data: d }));
  Bus.on('SANDBOX_SESSION_RESET',   d => handlePythonEvent({ type: 'SANDBOX_SESSION_RESET', data: d }));
  Bus.on('SANDBOX_ERROR',           d => handlePythonEvent({ type: 'SANDBOX_ERROR', data: d }));
  Bus.on('OFFENSE_PREVIEW_DATA',    d => handlePythonEvent({ type: 'OFFENSE_PREVIEW_DATA', data: d }));
  // Bus events for cross-page sync effects
  Bus.on('THREAT_DETECTED',    d => {
    if (state.running && window.SandboxEffects) {
      SandboxEffects.scanline();
      SandboxEffects.matrixRain(6);
      SandboxEffects.setEyeState('detect');
      SandboxEffects.glitchMascot();
      SandboxEffects.flashScreen();
    }
  });
  Bus.on('THREAT_NEUTRALISED', d => {
    if (state.running && window.SandboxEffects) {
      SandboxEffects.setEyeState('adapt');
      SandboxEffects.adaptationBox(d.attack_type || 'unknown');
      setTimeout(() => SandboxEffects.setEyeState('idle'), 4000);
    }
  });

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
  sbInitTerminalInput();
  if (window.SandboxEffects) SandboxEffects.setEyeState('idle');
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
    case 'OFFENSE_PREVIEW_DATA':    onOffensePreview(d);    break;
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

function sbAppendBanner(type) {
  const body = document.getElementById('sb-terminal-body');
  const wrap = document.createElement('div');
  wrap.className = 'sb-banner-wrap';
  const banner = document.createElement('span');
  banner.className = `sb-banner ${type}`;
  if (type === 'subdued') {
    banner.textContent = `  STRIKER\nHAS SUBDUED\nYOUR ATTACK`;
  } else if (type === 'success') {
    banner.textContent = `  ATTACK\nSUCCESSFULLY\n  EVADED`;
  }
  wrap.appendChild(banner);
  body.appendChild(wrap);
  body.scrollTop = body.scrollHeight;
}

function onSandboxDetection(d) {
  const caught = d.result === 'caught';
  state.caught = d.stats.caught;
  state.evaded = d.stats.evaded;
  state.score  = d.stats.points;
  updateScoreUI();

  if (caught) {
    sbTerminalPrint([['dim', '']]);
    sbAppendBanner('subdued');
    sbTerminalPrint([
      ['red', `STRIKER HAS SUBDUED YOUR ATTACK — sev ${d.severity}/10 · +${d.points} pts`],
      ['dim', ''],
    ]);
  } else {
    sbTerminalPrint([['dim', '']]);
    sbAppendBanner('success');
    sbTerminalPrint([
      ['green', `INTRUSION SUCCESSFUL — sev ${d.severity}/10 · attack evaded`],
      ['dim', ''],
    ]);
  }

  sbAddDetectionEvent({
    caught,
    label:    d.attack_type || d.module_id || 'unknown',
    severity: d.severity,
    points:   d.points || 0,
    // Add offensive analysis link if antibody/strategy were created
    hasOffenseLink: !!(d.antibody_id || d.strategy_id),
    antibody_id: d.antibody_id,
    strategy_id: d.strategy_id,
  });
}

// ── Offensive Analysis Preview ────────────────────────────────────────────────────

function sbAddDetectionAction(sbEventDiv, d) {
  const actionBtn = document.createElement('button');
  actionBtn.className = 'sb-detect-action';
  actionBtn.textContent = 'View Offensive Analysis';
  actionBtn.onclick = () => {
    if (d.strategy_id) {
      window.mahoraga.send('GET_OFFENSE_PREVIEW', { strategy_id: d.strategy_id });
    } else if (d.antibody_id) {
      // Fallback: fetch antibody details and find strategy
      window.mahoraga.send('GET_ARCHIVE', {});
    }
  };
  sbEventDiv.appendChild(actionBtn);
}

// Preview handler — shows offense details without full unlock
function onOffensePreview(d) {
  showOffensePreviewModal(d.strategy, d.contexts, d.playbooks);
}

function showOffensePreviewModal(strategy, contexts, playbooks) {
  // Create modal if not exists
  let modal = document.getElementById('sb-offense-preview-modal');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'sb-offense-preview-modal';
    modal.className = 'modal-overlay';
    modal.style.display = 'none';
    modal.style.zIndex = '10000';
    modal.innerHTML = `
      <div class="modal" style="max-width:580px">
        <div class="modal-title" id="sb-preview-title"></div>
        <div id="sb-preview-content"></div>
        <div style="display:flex;gap:8px;margin-top:22px;justify-content:flex-end">
          <button class="btn btn-secondary btn-sm" onclick="this.closest('.modal-overlay').style.display='none'">Close</button>
        </div>
      </div>
    `;
    document.body.appendChild(modal);
  }

  const ats = strategy.attack_types || [];
  const firstAt = ats[0] || 'unknown';
  
  document.getElementById('sb-preview-title').innerHTML = `
    ${ATTACK_ICONS[firstAt] || '⚔️'} Offensive Strategy — ${strategy.name}
  `;
  
  let content = `
    <div style="margin-bottom:16px">
      <div style="font-size:12px;color:var(--text-2);margin-bottom:4px">Description</div>
      <div>${strategy.description || 'No description'}</div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px">
      <div style="font-size:11px;color:var(--text-3)">Attack Types</div>
      <div style="font-size:11px;color:var(--text-3)">${ats.map(a => ATTACK_LABELS[a] || a).join(', ')}</div>
      <div style="font-size:11px;color:var(--text-3)">Strategy ID</div>
      <div class="mono" style="font-size:11px">${strategy.id}</div>
      <div style="font-size:11px;color:var(--text-3)">Created</div>
      <div style="font-size:11px">${new Date(strategy.created_at).toLocaleString()}</div>
    </div>
  `;
  
  // Offensive context
  content += `<div class="off-modal-section" style="margin-top:16px">
    <div class="off-modal-section-title"><span class="off-ms-icon">⚔️</span> Offensive Context</div>
    <div class="off-modal-body">`;
  ats.forEach(at => {
    content += `<div style="margin-bottom:8px"><strong>${ATTACK_LABELS[at] || at}</strong><br>${contexts[at] || 'No offensive context.'}</div>`;
  });
  content += `</div></div>`;
  
  // Defensive playbook
  content += `<div class="off-modal-section">
    <div class="off-modal-section-title"><span class="off-ms-icon">🛡️</span> Defensive Playbook</div>
    <div class="off-modal-body">`;
  ats.forEach(at => {
    content += `<div style="margin-bottom:8px"><strong>${ATTACK_LABELS[at] || at}</strong><br>${playbooks[at] || 'No defensive guidance.'}</div>`;
  });
  content += `</div></div>`;
  
  // Unlock note
  content += `<div style="margin-top:12px;padding:10px;background:var(--red-faint);border-radius:var(--radius);font-size:11px;color:var(--red)">
    <strong>🔒 Preview Mode</strong> — Full offensive intelligence requires Admin unlock in Offense module.
  </div>`;
  
  document.getElementById('sb-preview-content').innerHTML = content;
  modal.style.display = 'flex';

  // Close on overlay click
  modal.onclick = (e) => {
    if (e.target === modal) modal.style.display = 'none';
  };
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
  const inp = document.getElementById('sb-terminal-input');
  if (inp) { inp.value = ''; inp.focus(); }
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

  // Load modules immediately from local data — no IPC roundtrip needed
  const moduleIds = TARGET_MODULE_IDS[id] || [];
  state.currentModules = moduleIds
    .map(mid => MODULE_DEFS[mid] ? { id: mid, ...MODULE_DEFS[mid] } : null)
    .filter(Boolean);
  renderModules();
  sbTerminalPrint([['dim', `${state.currentModules.length} attack modules loaded. Select one to launch.`]]);

  // Also notify Python so it can prepare its simulator
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
  _startTimer();
  renderModules();
  if (window.SandboxEffects) SandboxEffects.setEyeState('detect');
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

// ── Terminal input ────────────────────────────────────────────────────────

let _cmdHistory = [];
let _historyPos = -1;

function sbInitTerminalInput() {
  const input  = document.getElementById('sb-terminal-input');
  const body   = document.getElementById('sb-terminal-body');
  if (!input) return;

  // Click anywhere in terminal body → focus input
  body.addEventListener('click', () => input.focus());

  input.addEventListener('keydown', async function (e) {
    if (e.key === 'Enter') {
      const cmd = input.value.trim();
      input.value = '';
      _historyPos = -1;
      if (cmd) {
        _cmdHistory.unshift(cmd);
        await sbRunCommand(cmd);
      }
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (_historyPos + 1 < _cmdHistory.length) {
        _historyPos++;
        input.value = _cmdHistory[_historyPos];
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (_historyPos > 0) {
        _historyPos--;
        input.value = _cmdHistory[_historyPos];
      } else {
        _historyPos = -1;
        input.value = '';
      }
    }
  });
}

const _WIN_FS = 'Users/  Windows/  Program Files/  Program Files (x86)/  Temp/  PerfLogs/  pagefile.sys';
const _LIN_FS = 'bin@  boot/  dev/  etc/  home/  lib/  opt/  proc/  root/  run/  srv/  tmp/  usr/  var/';

async function sbRunCommand(cmd) {
  const prompt = document.getElementById('sb-input-prompt');
  const promptText = prompt ? prompt.textContent : '❯';
  sbTerminalPrint([['dim', `${promptText} ${cmd}`]]);

  const parts = cmd.split(/\s+/);
  const base  = parts[0].toLowerCase();

  switch (base) {
    case 'help':
      sbTerminalPrint([
        ['dim', ''],
        ['dim', 'Sandbox shell commands:'],
        ['dim', '  help          show this help'],
        ['dim', '  clear         clear terminal output'],
        ['dim', '  whoami        current user'],
        ['dim', '  id            user identity'],
        ['dim', '  uname -a      system information'],
        ['dim', '  ls / dir      list directory'],
        ['dim', '  ps / tasklist process list'],
        ['dim', '  netstat -an   network connections'],
        ['dim', '  cat <file>    read a file'],
        ['dim', '  pwd           current directory'],
        ['dim', '  nmap          network scanner'],
        ['dim', '  ping          ping host'],
        ['dim', '  traceroute    trace route to host'],
        ['dim', '  ifconfig      network interfaces'],
        ['dim', '  ss            socket statistics'],
        ['dim', '  tcpdump       network packet analyzer'],
        ['dim', '  hydra         password cracker'],
        ['dim', '  metasploit    exploitation framework'],
        ['dim', '  burpsuite     web vulnerability scanner'],
        ['dim', '  wireshark     network protocol analyzer'],
        ['dim', '  sqlmap        SQL injection tool'],
        ['dim', '  nikto         web server scanner'],
        ['dim', '  gobuster      directory/file busting tool'],
        ['dim', '  dirb          web content scanner'],
        ['dim', '  ffuf          web fuzzer'],
        ['dim', '  jwttool       JSON Web Token toolkit'],
        ['dim', '  searchsploit  exploit database search'],
        ['dim', '  john          password cracker'],
        ['dim', '  hashcat       advanced password recovery'],
        ['dim', '  vim / vi      text editor'],
        ['dim', '  nano          text editor'],
        ['dim', '  emacs         text editor'],
        ['dim', '  grep          search file contents'],
        ['dim', '  find          search for files'],
        ['dim', '  chmod         change file permissions'],
        ['dim', '  chown         change file ownership'],
        ['dim', '  tar           archive utility'],
        ['dim', '  gzip          compression utility'],
        ['dim', '  wget          download files'],
        ['dim', '  curl          transfer data'],
        ['dim', '  ssh           secure shell client'],
        ['dim', '  scp           secure copy'],
        ['dim', '  rsync         synchronize files'],
        ['dim', '  ftp           file transfer protocol'],
        ['dim', '  telnet        telnet client'],
        ['dim', '  python3       Python interpreter'],
        ['dim', '  python        Python interpreter'],
        ['dim', '  node          JavaScript runtime'],
        ['dim', '  npm           Node package manager'],
        ['dim', '  ruby          Ruby interpreter'],
        ['dim', '  perl          Perl interpreter'],
        ['dim', '  php           PHP interpreter'],
        ['dim', '  java          Java interpreter'],
        ['dim', '  gcc           GNU Compiler Collection'],
        ['dim', '  g++           GNU C++ compiler'],
        ['dim', '  make          build automation tool'],
        ['dim', '  docker        container platform'],
        ['dim', '  kubectl       Kubernetes CLI'],
        ['dim', '  aws           AWS CLI'],
        ['dim', '  az            Azure CLI'],
        ['dim', '  gcloud        Google Cloud CLI'],
        ['dim', '  helm          Kubernetes package manager'],
        ['dim', '  terraform     infrastructure as code'],
        ['dim', '  ansible       automation engine'],
        ['dim', '  puppet        configuration management'],
        ['dim', '  chef          configuration management'],
        ['dim', '  git           version control'],
        ['dim', '  svn           version control'],
        ['dim', '  hg            version control'],
        ['dim', '  cp            copy files'],
        ['dim', '  mv            move/rename files'],
        ['dim', '  rm            remove files'],
        ['dim', '  mkdir         create directory'],
        ['dim', '  touch         create empty file'],
        ['dim', '  ln            create links'],
        ['dim', '  df            disk space usage'],
        ['dim', '  du            disk usage'],
        ['dim', '  free          memory usage'],
        ['dim', '  top           display processes'],
        ['dim', '  htop          interactive process viewer'],
        ['dim', '  ps            process status'],
        ['dim', '  kill          terminate process'],
        ['dim', '  killall       kill processes by name'],
        ['dim', '  pkill         kill processes by pattern'],
        ['dim', '  bg            background jobs'],
        ['dim', '  fg            foreground jobs'],
        ['dim', '  jobs          list jobs'],
        ['dim', '  disown        remove job from shell'],
        ['dim', '  nohup         run command immune to hangups'],
        ['dim', '  su            switch user'],
        ['dim', '  sudo          execute command as superuser'],
        ['dim', '  useradd       add user account'],
        ['dim', '  userdel       delete user account'],
        ['dim', '  usermod       modify user account'],
        ['dim', '  groupadd      add group account'],
        ['dim', '  groupdel      delete group account'],
        ['dim', '  groupmod      modify group account'],
        ['dim', '  passwd        change user password'],
        ['dim', '  echo          display line of text'],
        ['dim', '  printf        formatted output'],
        ['dim', '  read          read line from stdin'],
        ['dim', '  source        execute commands from file'],
        ['dim', '  .             execute commands from file'],
        ['dim', '  alias         create shell alias'],
        ['dim', '  unalias       remove alias'],
        ['dim', '  history       show command history'],
        ['dim', '  unset         remove variable or function'],
        ['dim', '  export        set environment variable'],
        ['dim', '  set           set shell options'],
        ['dim', '  shopt         set shell options'],
        ['dim', '  ulimit        set user process limits'],
        ['dim', '  umask         set file creation mask'],
        ['dim', '  test          evaluate conditional expression'],
        ['dim', '  [             evaluate conditional expression'],
        ['dim', '  [[            evaluate conditional expression'],
        ['dim', '  if            conditional construct'],
        ['dim', '  for           looping construct'],
        ['dim', '  while         looping construct'],
        ['dim', '  until         looping construct'],
        ['dim', '  case          conditional construct'],
        ['dim', '  select        looping construct'],
        ['dim', '  function      define shell function'],
        ['dim', '  time          measure command execution time'],
        ['dim', '  wait          wait for process completion'],
        ['dim', '  bg            run job in background'],
        ['dim', '  fg            run job in foreground'],
        ['dim', '  &             run command in background'],
        ['dim', '  ;             command separator'],
        ['dim', '  &&            AND list operator'],
        ['dim', '  ||            OR list operator'],
        ['dim', '  |             pipe operator'],
        ['dim', '  >             redirect output'],
        ['dim', '  <             redirect input'],
        ['dim', '  >>            append output'],
        ['dim', '  <<            here document'],
        ['dim', '  <<<           here string'],
        ['dim', '  (             group commands'],
        ['dim', '  {             group commands'],
        ['dim', '  !             negate pipeline'],
        ['dim', '  ~             home directory'],
        ['dim', '  $             variable expansion'],
        ['dim', '  @             array slicing'],
        ['dim', '  %             modulo operation'],
        ['dim', '  ^             bitwise XOR'],
        ['dim', '  &             bitwise AND'],
        ['dim', '  |             bitwise OR'],
        ['dim', '  <<            left shift'],
        ['dim', '  >>            right shift'],
        ['dim', '  &&            logical AND'],
        ['dim', '  ||            logical OR'],
        ['dim', '  ==            equality comparison'],
        ['dim', '  !=            inequality comparison'],
        ['dim', '  <             less than comparison'],
        ['dim', '  >             greater than comparison'],
        ['dim', '  <=            less than or equal comparison'],
        ['dim', '  >=            greater than or equal comparison'],
        ['dim', '  =~            regular expression match'],
        ['dim', '  !~            regular expression non-match'],
        ['dim', ''],
      ]);
      break;

    case 'clear':
    case 'cls':
      document.getElementById('sb-terminal-body').innerHTML = '';
      document.getElementById('sb-terminal-input').focus();
      return;
  }

  try {
    const result = await window.mahoraga.execCommand(cmd);
    if (result.stdout) {
      const lines = result.stdout.split('\n').filter(l => l);
      lines.forEach(line => sbTerminalPrint([['dim', line]]));
    }
    if (result.stderr) {
      const lines = result.stderr.split('\n').filter(l => l);
      lines.forEach(line => sbTerminalPrint([['yellow', line]]));
    }
  } catch (err) {
    const errMsg = err.message || 'Command failed';
    sbTerminalPrint([['red', errMsg]]);
  }

  document.getElementById('sb-terminal-input').focus();
}

// ── Detection feed ────────────────────────────────────────────────────────────

function sbAddDetectionEvent({ caught, label, severity, points, hasOffenseLink, strategy_id, antibody_id }) {
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
  
  // Add offensive analysis button if available
  if (hasOffenseLink) {
    sbAddDetectionAction(ev, { strategy_id, antibody_id });
  }
  
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
