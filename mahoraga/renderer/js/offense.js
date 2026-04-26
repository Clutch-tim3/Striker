'use strict';

let _allStrategies = [];
let _currentFilter = 'all';
let _currentStrategy = null;

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

// attack type → sandbox module id (for Simulate button)
const SANDBOX_MODULE_MAP = {
  ransomware:           'ransomware_sim',
  c2_beacon:            'c2_beacon_sim',
  keylogger:            'keylogger_sim',
  privilege_escalation: 'privesc_sim',
  data_exfil:           'data_exfil_sim',
  rootkit:              'rootkit_sim',
  backdoor:             'lolbin_sim',
  cryptominer:          'cryptominer_sim',
};

// ── Init ──────────────────────────────────────────────────────────────────────

function offInit() {
  window.mahoraga.onEvent(handleEvent);

  // Event delegation — no JSON in onclick attributes
  document.getElementById('off-strategy-grid').addEventListener('click', e => {
    const card = e.target.closest('[data-strategy-id]');
    if (card) offShowStrategyModal(card.dataset.strategyId);
  });

  offLoadStrategies();
  setInterval(offLoadStrategies, 5000);
}

function handleEvent(e) {
  if (e.type === 'OFFENSIVE_STRATEGIES_DATA') {
    _allStrategies = e.data.strategies || [];
    _updateHeaderStats(_allStrategies.length, e.data.current_cycle);
    _populateFilterTabs(_allStrategies);
    offFilter();
  }
  if (e.type === 'OFFENSIVE_STRATEGY_CREATED') {
    _allStrategies.unshift(e.data);
    _updateHeaderStats(_allStrategies.length);
    _populateFilterTabs(_allStrategies);
    offFilter();
    _showToast(`New intel: ${e.data.name}`);
  }
}

// ── Header stats ──────────────────────────────────────────────────────────────

function _updateHeaderStats(count, cycle) {
  document.getElementById('off-stat-strategies').textContent = count;
  if (cycle !== undefined) {
    const el = document.getElementById('off-stat-cycle');
    if (el) el.textContent = cycle;
  }
}

// ── Filter tabs ───────────────────────────────────────────────────────────────

function _populateFilterTabs(strategies) {
  const tabs = document.getElementById('off-filter-tabs');
  const types = new Set();
  strategies.forEach(s =>
    (s.attack_types || '').split(',').forEach(t => { t = t.trim(); if (t) types.add(t); })
  );

  tabs.innerHTML =
    `<button class="off-tab${_currentFilter === 'all' ? ' active' : ''}" onclick="offSetFilter('all',this)">All</button>`;
  types.forEach(type => {
    const label = ATTACK_LABELS[type] || type.replace(/_/g, ' ');
    const active = _currentFilter === type ? ' active' : '';
    tabs.insertAdjacentHTML('beforeend',
      `<button class="off-tab${active}" onclick="offSetFilter('${type}',this)">${label}</button>`);
  });
}

function offSetFilter(f, btn) {
  _currentFilter = f;
  document.querySelectorAll('.off-tab').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  offFilter();
}

// ── Load & render ─────────────────────────────────────────────────────────────

function offLoadStrategies() {
  window.mahoraga.send('GET_OFFENSIVE_STRATEGIES', {});
}

function offFilter() {
  const search = (document.getElementById('off-search').value || '').toLowerCase();

  const visible = _allStrategies.filter(s => {
    if (_currentFilter !== 'all') {
      const types = (s.attack_types || '').split(',').map(t => t.trim());
      if (!types.includes(_currentFilter)) return false;
    }
    if (search) {
      return (s.name || '').toLowerCase().includes(search) ||
             (s.description || '').toLowerCase().includes(search) ||
             (s.attack_types || '').toLowerCase().includes(search);
    }
    return true;
  });

  const grid = document.getElementById('off-strategy-grid');
  const loading = document.getElementById('off-loading');
  if (loading) loading.style.display = 'none';

  grid.innerHTML = visible.length
    ? visible.map(_buildStrategyCard).join('')
    : '<div class="off-empty">No strategies match your filter.</div>';
}

function _buildStrategyCard(s) {
  const name = s.name || 'Unnamed Strategy';
  const desc = s.description || '';
  const attackTypes = (s.attack_types || '').split(',').map(t => t.trim()).filter(Boolean);
  const createdAt = s.created_at ? new Date(s.created_at).toLocaleDateString() : '—';
  const version = s.adaptation_version || 0;
  const primaryIcon = attackTypes[0] ? (ATTACK_ICONS[attackTypes[0]] || '⚔️') : '⚔️';

  const tags = attackTypes.slice(0, 3).map(at =>
    `<span class="mitre-tag">${ATTACK_ICONS[at] || ''} ${ATTACK_LABELS[at] || at}</span>`
  ).join('');
  const extra = attackTypes.length > 3
    ? `<span class="mitre-tag">+${attackTypes.length - 3} more</span>` : '';

  return `
    <div class="strategy-card" data-strategy-id="${s.id}">
      <div class="strategy-card-top">
        <div class="strategy-card-icon">${primaryIcon}</div>
        <div style="flex:1;min-width:0">
          <div class="strategy-card-title">${name}</div>
          <div class="strategy-card-meta">${createdAt} · ${attackTypes.length} technique${attackTypes.length !== 1 ? 's' : ''}</div>
        </div>
        <div class="off-version-badge">v${version}</div>
      </div>
      ${desc ? `<div class="strategy-card-desc">${desc}</div>` : ''}
      ${tags ? `<div class="strategy-card-tags">${tags}${extra}</div>` : ''}
      <div class="strategy-card-cta">View intelligence →</div>
    </div>`;
}

// ── Modal ─────────────────────────────────────────────────────────────────────

function offShowStrategyModal(id) {
  const s = _allStrategies.find(x => x.id === id);
  if (!s) return;
  _currentStrategy = s;

  const attackTypes = (s.attack_types || '').split(',').map(t => t.trim()).filter(Boolean);
  const created = s.created_at ? new Date(s.created_at).toLocaleDateString() : '—';

  document.getElementById('off-modal-status').textContent = '⚔ OFFENSIVE INTEL';
  document.getElementById('off-modal-title').textContent = s.name || 'Unnamed Strategy';

  document.getElementById('off-modal-stats').innerHTML = `
    <div class="off-ms-row">
      <div class="off-ms-stat">
        <div class="off-ms-val">${attackTypes.length}</div>
        <div class="off-ms-lbl">Techniques</div>
      </div>
      <div class="off-ms-stat">
        <div class="off-ms-val">${created}</div>
        <div class="off-ms-lbl">Catalogued</div>
      </div>
      <div class="off-ms-stat">
        <div class="off-ms-val">v${s.adaptation_version || 0}</div>
        <div class="off-ms-lbl">Adaptation</div>
      </div>
    </div>`;

  document.getElementById('off-modal-details').textContent =
    s.description || 'No description provided.';

  // Offensive context — one block per attack type
  const offEl = document.getElementById('off-modal-offensive');
  offEl.innerHTML = attackTypes.length
    ? attackTypes.map(at => {
        const label = ATTACK_LABELS[at] || at.replace(/_/g, ' ');
        const icon  = ATTACK_ICONS[at] || '⚠️';
        const ctx   = (s.offensive_contexts && s.offensive_contexts[at])
                      || 'No offensive context available for this technique.';
        const canSim = !!SANDBOX_MODULE_MAP[at];
        return `
          <div class="off-technique-block">
            <div class="off-technique-header">
              <span class="off-technique-icon">${icon}</span>
              <span class="off-technique-label">${label}</span>
              ${canSim ? `<button class="off-simulate-btn" onclick="offSimulateAttackType('${at}')">⚗ Simulate</button>` : ''}
            </div>
            <div class="off-modal-body">${ctx}</div>
          </div>`;
      }).join('')
    : '<p style="color:var(--text-3);font-size:13px">No attack types associated with this strategy.</p>';

  // Defensive playbook — one block per attack type
  const defEl = document.getElementById('off-modal-defensive');
  defEl.innerHTML = attackTypes.length
    ? attackTypes.map(at => {
        const label    = ATTACK_LABELS[at] || at.replace(/_/g, ' ');
        const playbook = (s.defensive_playbooks && s.defensive_playbooks[at])
                         || 'No defensive playbook entry available.';
        return `
          <div class="off-technique-block">
            <div class="off-technique-header">
              <span class="off-technique-label">${label}</span>
            </div>
            <div class="off-modal-body" style="border-left-color:var(--border-dark)">${playbook}</div>
          </div>`;
      }).join('')
    : '<p style="color:var(--text-3);font-size:13px">No defensive guidance available.</p>';

  document.getElementById('off-modal').style.display = 'flex';
}

function offCloseModal(e) {
  if (e && e.target !== document.getElementById('off-modal')) return;
  document.getElementById('off-modal').style.display = 'none';
  _currentStrategy = null;
}

// ── Offensive actions ─────────────────────────────────────────────────────────

function offSimulateAttackType(attackType) {
  const label = ATTACK_LABELS[attackType] || attackType;
  _showToast(`Opening Sandbox — select the ${label} module to run this attack pattern`);
  setTimeout(() => { window.location.href = 'sandbox.html'; }, 1400);
}

function offCopyTactics() {
  const s = _currentStrategy;
  if (!s) return;
  const attackTypes = (s.attack_types || '').split(',').map(t => t.trim()).filter(Boolean);
  const divider = '─'.repeat(56);
  let text = `OFFENSIVE INTELLIGENCE REPORT\n${divider}\n${s.name}\n${divider}\n\n${s.description || ''}\n\nAdaptation: v${s.adaptation_version || 0}\n\n`;
  for (const at of attackTypes) {
    const label = ATTACK_LABELS[at] || at;
    const ctx   = s.offensive_contexts && s.offensive_contexts[at];
    if (ctx) text += `[ ${label.toUpperCase()} ]\n${ctx}\n\n`;
  }
  navigator.clipboard.writeText(text.trim())
    .then(() => _showToast('Tactics copied to clipboard'))
    .catch(() => _showToast('Copy failed'));
}

// ── Toast ─────────────────────────────────────────────────────────────────────

function _showToast(msg) {
  document.querySelectorAll('.off-toast').forEach(t => t.remove());
  const el = document.createElement('div');
  el.className = 'off-toast';
  el.textContent = msg;
  document.body.appendChild(el);
  requestAnimationFrame(() => el.classList.add('off-toast-visible'));
  setTimeout(() => {
    el.classList.remove('off-toast-visible');
    setTimeout(() => el.remove(), 300);
  }, 3000);
}

document.addEventListener('DOMContentLoaded', offInit);
