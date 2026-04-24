'use strict';

let _allStrategies = [];
let _currentFilter = 'all';
let _gateMode = false;      // optional global lock
let _gateUnlocked = false;  // session flag

const ATTACK_LABELS = {
  ransomware: 'Ransomware', keylogger: 'Keylogger', rootkit: 'Rootkit',
  c2_beacon: 'C2 Beacon', data_exfil: 'Data Exfiltration',
  cryptominer: 'Cryptominer', worm: 'Worm', backdoor: 'Backdoor',
  privilege_escalation: 'Privilege Escalation',
  gatekeeper_bypass: 'Gatekeeper Bypass', applescript_execution: 'AppleScript Execution',
  keychain_access: 'Keychain Access', persistence_mechanism: 'Persistence Mechanism',
  reverse_shell: 'Reverse Shell', ld_preload_injection: 'LD_PRELOAD Injection',
  kernel_module_load: 'Kernel Module Load',
};

const ATTACK_ICONS = {
  ransomware: '🔒', keylogger: '⌨️', rootkit: '🕳️', c2_beacon: '📡',
  data_exfil: '📤', cryptominer: '⛏️', worm: '🪱', backdoor: '🚪',
  privilege_escalation: '⬆️', gatekeeper_bypass: '🚧', applescript_execution: '🍎',
  keychain_access: '🔑', persistence_mechanism: '🔁', reverse_shell: '🐚',
  ld_preload_injection: '💉', kernel_module_load: '⚙️',
};

function offInit() {
  window.mahoraga.onEvent(handleEvent);

  // Load gate mode preference (default false)
  const stored = sessionStorage.getItem('mahoraga_offense_gate');
  _gateMode = stored === '1';
  document.getElementById('gate-toggle-checkbox').checked = _gateMode;

  if (_gateMode) {
    // Show gate overlay, wait for unlock
    document.getElementById('off-gate').style.display = 'flex';
    document.getElementById('off-content').style.display = 'none';
  } else {
    _showContent();
  }

  // Load strategies
  offLoadStrategies();
  // Auto-refresh every 5 seconds
  setInterval(offLoadStrategies, 5000);
}

function handleEvent(e) {
  if (e.type === 'OFFENSIVE_STRATEGIES_DATA') {
    _allStrategies = e.data.strategies || [];
    updateStats();
    offFilter();
  }
  if (e.type === 'OFFENSIVE_STRATEGY_UNLOCKED') {
    const { strategy_id, ok } = e.data;
    if (ok) {
      const s = _allStrategies.find(s => s.id === strategy_id);
      if (s) s.locked = 0;
      const cur = window._currentStrategyModalId;
      if (cur === strategy_id) {
        offShowStrategyModal(JSON.stringify(s));
      }
      updateStats();
      offFilter();
    } else {
      const err = document.getElementById('off-modal-unlock-error');
      if (err) err.style.display = 'block';
    }
  }
  if (e.type === 'OFFENSIVE_UNLOCKED') {
    // Global gate unlock
    if (e.data.ok) {
      _gateUnlocked = true;
      _showContent();
    } else {
      const err = document.getElementById('off-gate-error');
      if (err) { err.style.display = 'block'; setTimeout(() => { err.style.display = 'none'; }, 3500); }
      const input = document.getElementById('off-gate-input');
      if (input) { input.value = ''; input.focus(); }
    }
  }
}

function updateStats() {
  document.getElementById('off-stat-strategies').textContent = _allStrategies.length;
  const locked = _allStrategies.filter(s => s.locked === 1).length;
  document.getElementById('off-stat-locked').textContent = locked;
}

// ── Gate & Content ─────────────────────────────────────────────────────────────

function offUnlock() {
  const input = document.getElementById('off-gate-input');
  const key = (input && input.value.trim()) || '';
  if (!key) { input && input.focus(); return; }
  window.mahoraga.send('UNLOCK_OFFENSIVE', { key });
}

function offLock() {
  offLockContent();
}

function offLockContent() {
  _gateUnlocked = false;
  document.getElementById('off-gate').style.display = 'flex';
  document.getElementById('off-content').style.display = 'none';
  const input = document.getElementById('off-gate-input');
  if (input) input.value = '';
}

function offToggleGate(enabled) {
  _gateMode = enabled;
  sessionStorage.setItem('mahoraga_offense_gate', enabled ? '1' : '0');
  if (enabled) {
    offLockContent();
  } else {
    document.getElementById('off-gate').style.display = 'none';
    _showContent();
  }
}

function _showContent() {
  document.getElementById('off-gate').style.display = 'none';
  document.getElementById('off-content').style.display = 'flex';
  offLoadStrategies();
}

// ── Load Strategies ─────────────────────────────────────────────────────────────

function offLoadStrategies() {
  window.mahoraga.send('GET_OFFENSIVE_STRATEGIES', {});
}

// ── Rendering ───────────────────────────────────────────────────────────────────

function offFilter() {
  const search = (document.getElementById('off-search').value || '').toLowerCase();
  const filter = _currentFilter;

  const visible = _allStrategies.filter(s => {
    if (filter === 'locked'   && s.locked === 0) return false;
    if (filter === 'unlocked' && s.locked === 1) return false;
    if (search) {
      const name = (s.name || '').toLowerCase();
      const desc = (s.description || '').toLowerCase();
      const types = (s.attack_types || '').toLowerCase();
      return name.includes(search) || desc.includes(search) || types.includes(search);
    }
    return true;
  });

  const grid = document.getElementById('off-strategy-grid');
  document.getElementById('off-loading') && (document.getElementById('off-loading').style.display = 'none');

  if (!visible.length) {
    grid.innerHTML = '<div class="off-empty">No strategies match your filter.</div>';
    return;
  }
  grid.innerHTML = visible.map(buildStrategyCard).join('');
}

function offSetFilter(f, btn) {
  _currentFilter = f;
  document.querySelectorAll('.off-tab').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  offFilter();
}

function buildStrategyCard(s) {
  const name = s.name || 'Unnamed Strategy';
  const desc = s.description || 'No description provided.';
  const attackTypes = s.attack_types ? s.attack_types.split(',').map(t => t.trim()).filter(Boolean) : [];
  const locked = s.locked === 1;
  const createdAt = s.created_at ? new Date(s.created_at).toLocaleDateString() : '—';

  // Build attack type badges (show up to 4, then +N more)
  const tags = attackTypes.map(at => {
    const label = ATTACK_LABELS[at] || at.replace(/_/g, ' ');
    const icon = ATTACK_ICONS[at] || '⚠️';
    return `<span class="mitre-tag" title="${label}">${icon} ${label}</span>`;
  });
  const tagsHtml = tags.length ? tags.slice(0, 4).join('') + (tags.length > 4 ? `<span class="mitre-tag">+${tags.length - 4} more</span>` : '') : '';

  // Card classes
  const cardClass = `strategy-card${locked ? ' strategy-locked' : ''}`;

  return `
    <div class="${cardClass}" data-id="${s.id}" onclick="offShowStrategyModal(${JSON.stringify(JSON.stringify(s))})">
      <div class="strategy-card-top">
        <div class="strategy-card-icon">${locked ? '🔒' : '⚔️'}</div>
        <div style="flex:1;min-width:0">
          <div class="strategy-card-title">${name}</div>
          <div class="strategy-card-meta">Created ${createdAt} · ${attackTypes.length} technique${attackTypes.length !== 1 ? 's' : ''}</div>
        </div>
        ${locked ? '<span class="badge badge-critical">LOCKED</span>' : '<span class="badge">UNLOCKED</span>'}
      </div>
      <div class="strategy-card-desc">${desc}</div>
      ${tagsHtml ? `<div class="strategy-card-tags" style="margin-top:8px">${tagsHtml}</div>` : ''}
      ${locked ? `
        <div class="strategy-lock-overlay" onclick="event.stopPropagation(); offUnlockStrategyFromCard('${s.id}')">
          <span class="btn btn-secondary btn-sm">🔓 Unlock</span>
        </div>
      ` : ''}
    </div>`;
}

// ── Modal ────────────────────────────────────────────────────────────────────────

window._currentStrategyModalId = null;

function offShowStrategyModal(sJson) {
  const s = JSON.parse(sJson);
  window._currentStrategyModalId = s.id;

  // Header
  document.getElementById('off-modal-status').textContent = s.locked ? '🔒 LOCKED' : '⚔ UNLOCKED';
  document.getElementById('off-modal-title').textContent = s.name || 'Unnamed Strategy';

  // Stats
  const attackTypes = s.attack_types ? s.attack_types.split(',').map(t => t.trim()).filter(Boolean) : [];
  const created = s.created_at ? new Date(s.created_at).toLocaleDateString() : '—';
  document.getElementById('off-modal-stats').innerHTML = `
    <div class="off-ms-row">
      <div class="off-ms-stat"><div class="off-ms-val">${attackTypes.length}</div><div class="off-ms-lbl">Techniques</div></div>
      <div class="off-ms-stat"><div class="off-ms-val">${created}</div><div class="off-ms-lbl">Created</div></div>
      <div class="off-ms-stat"><div class="off-ms-val"><span class="badge ${s.locked ? 'badge-critical' : ''}">${s.locked ? 'Locked' : 'Unlocked'}</span></div><div class="off-ms-lbl">Status</div></div>
    </div>
  `;

  // Strategy Details
  document.getElementById('off-modal-details').textContent = s.description || 'No description provided.';

  // Offensive Context per attack type
  const offensiveEl = document.getElementById('off-modal-offensive');
  if (attackTypes.length) {
    offensiveEl.innerHTML = attackTypes.map(at => {
      const label = ATTACK_LABELS[at] || at.replace(/_/g, ' ');
      const icon = ATTACK_ICONS[at] || '⚠️';
      const context = s.offensive_contexts ? s.offensive_contexts[at] : 'No offensive context available.';
      return `<div style="margin-bottom:14px">
                <div style="font-weight:700;margin-bottom:4px">${icon} ${label}</div>
                <div style="font-size:13px;color:var(--text-1);line-height:1.6">${context}</div>
              </div>`;
    }).join('');
  } else {
    offensiveEl.textContent = 'No attack types associated with this strategy.';
  }

  // Defensive Playbook per attack type
  const defensiveEl = document.getElementById('off-modal-defensive');
  if (attackTypes.length) {
    defensiveEl.innerHTML = attackTypes.map(at => {
      const label = ATTACK_LABELS[at] || at.replace(/_/g, ' ');
      const playbook = s.defensive_playbooks ? s.defensive_playbooks[at] : 'No defensive playbook entry available.';
      return `<div style="margin-bottom:14px">
                <div style="font-weight:700;margin-bottom:4px">${label}</div>
                <div style="font-size:13px;color:var(--text-1);line-height:1.6">${playbook}</div>
              </div>`;
    }).join('');
  } else {
    defensiveEl.textContent = 'No defensive guidance available for this strategy.';
  }

  // Unlock section
  const unlockWrap = document.getElementById('off-modal-unlock-wrap');
  const input = document.getElementById('off-modal-unlock-input');
  const btn = document.getElementById('off-modal-unlock-btn');
  const err = document.getElementById('off-modal-unlock-error');

  if (s.locked) {
    unlockWrap.style.display = 'block';
    input.value = '';
    err.style.display = 'none';
    // Replace button with fresh one to clear previous listeners
    const newBtn = btn.cloneNode(true);
    btn.parentNode.replaceChild(newBtn, btn);
    newBtn.onclick = () => offUnlockStrategy(s.id);
    // Allow Enter key
    input.onkeydown = (e) => { if (e.key === 'Enter') offUnlockStrategy(s.id); };
  } else {
    unlockWrap.style.display = 'none';
  }

  document.getElementById('off-modal').style.display = 'flex';
}

function offCloseModal(e) {
  if (e && e.target !== document.getElementById('off-modal')) return;
  document.getElementById('off-modal').style.display = 'none';
  window._currentStrategyModalId = null;
}

// ── Unlock ──────────────────────────────────────────────────────────────────────

function offUnlockStrategyFromCard(strategyId) {
  const s = _allStrategies.find(s => s.id === strategyId);
  if (s) offShowStrategyModal(JSON.stringify(s));
}

function offUnlockStrategy(strategyId) {
  const input = document.getElementById('off-modal-unlock-input');
  const key = (input && input.value.trim()) || '';
  if (!key) { input && input.focus(); return; }
  window.mahoraga.send('UNLOCK_OFFENSIVE_STRATEGY', { strategy_id: strategyId, key });
}

// ── Helpers ─────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', offInit);
