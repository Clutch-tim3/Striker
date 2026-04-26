'use strict';

let _allTactics = [];
let _currentFilter = 'all';
let _currentTactic = null;

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

function _sevColour(sev) {
  if (sev >= 8) return '#dc2020';
  if (sev >= 5) return '#d97706';
  if (sev >= 3) return '#0284c7';
  return '#6b7280';
}

// ── Init ──────────────────────────────────────────────────────────────────────

function offInit() {
  Bus.init();

  Bus.on('OFFENSE_DATA', d => {
    _allTactics = d.tactics || [];
    _updateCount(_allTactics.length);
    _buildFilterTabs(_allTactics);
    offFilter();
  });

  Bus.on('OFFENSE_SAVED', d => {
    _allTactics.unshift(d);
    _updateCount(_allTactics.length);
    _buildFilterTabs(_allTactics);
    offFilter();
    _toast(`New tactic: ${ATTACK_LABELS[d.attack_type] || d.attack_type}`);
  });

  // Event delegation for tactic grid
  document.getElementById('off-tactic-grid').addEventListener('click', e => {
    const copyBtn = e.target.closest('[data-copy-cmd]');
    if (copyBtn) { e.stopPropagation(); _copyCmd(copyBtn.dataset.copyCmd, copyBtn); return; }
    const runBtn = e.target.closest('[data-run-tactic]');
    if (runBtn) { e.stopPropagation(); window.location.href = 'sandbox.html?tactic=' + runBtn.dataset.runTactic; return; }
    const card = e.target.closest('[data-tactic-id]');
    if (card) offShowModal(card.dataset.tacticId);
  });

  // Filter tabs (event delegation)
  document.getElementById('off-filter-tabs').addEventListener('click', e => {
    const btn = e.target.closest('[data-filter]');
    if (!btn) return;
    _currentFilter = btn.dataset.filter;
    document.querySelectorAll('.off-tab').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    offFilter();
  });

  document.getElementById('off-search').addEventListener('input', offFilter);

  // Modal copy buttons (event delegation)
  document.getElementById('off-modal').addEventListener('click', e => {
    const copyBtn = e.target.closest('[data-copy-cmd]');
    if (copyBtn) { e.stopPropagation(); _copyCmd(copyBtn.dataset.copyCmd, copyBtn); }
  });

  window.mahoraga.send('GET_OFFENSE', {});
}

// ── Count + filter tabs ───────────────────────────────────────────────────────

function _updateCount(n) {
  const el = document.getElementById('off-stat-count');
  if (el) el.textContent = n;
}

function _buildFilterTabs(tactics) {
  const types = new Set(tactics.map(t => t.attack_type).filter(Boolean));
  const tabs = document.getElementById('off-filter-tabs');
  tabs.innerHTML = `<button class="off-tab${_currentFilter === 'all' ? ' active' : ''}" data-filter="all">All</button>`;
  types.forEach(type => {
    const label  = ATTACK_LABELS[type] || type.replace(/_/g, ' ');
    const active = _currentFilter === type ? ' active' : '';
    tabs.insertAdjacentHTML('beforeend',
      `<button class="off-tab${active}" data-filter="${type}">${label}</button>`);
  });
}

// ── Filter ────────────────────────────────────────────────────────────────────

function offFilter() {
  const search = (document.getElementById('off-search').value || '').toLowerCase();
  const visible = _allTactics.filter(t => {
    if (_currentFilter !== 'all' && t.attack_type !== _currentFilter) return false;
    if (search) {
      return (t.attack_type || '').includes(search) ||
             (t.description || '').toLowerCase().includes(search) ||
             (t.technique || '').toLowerCase().includes(search);
    }
    return true;
  });

  const grid = document.getElementById('off-tactic-grid');
  const loading = document.getElementById('off-loading');
  if (loading) loading.style.display = 'none';

  if (!visible.length) {
    grid.innerHTML = _allTactics.length === 0
      ? `<div class="off-empty-state">
           <div class="off-empty-icon">🔬</div>
           <div class="off-empty-title">No tactics archived yet.</div>
           <div class="off-empty-sub">Run sandbox attacks to generate your first entries.</div>
           <a href="sandbox.html" class="btn btn-sm" style="background:var(--black);color:#fff;margin-top:14px;text-decoration:none;display:inline-block;padding:8px 18px;border-radius:var(--radius)">Open Sandbox →</a>
         </div>`
      : `<div class="off-empty">No tactics match your filter.</div>`;
    return;
  }

  grid.innerHTML = visible.map(_buildCard).join('');
}

// ── Card builder ──────────────────────────────────────────────────────────────

function _buildCard(t) {
  const icon     = ATTACK_ICONS[t.attack_type] || '⚔️';
  const label    = ATTACK_LABELS[t.attack_type] || t.attack_type;
  const sev      = t.severity || 0;
  const sevCol   = _sevColour(sev);
  const date     = t.created_at ? new Date(t.created_at).toLocaleDateString() : '—';
  const commands = Array.isArray(t.commands) ? t.commands : [];
  const firstCmd = commands[0] || '';

  return `
    <div class="off-tactic-card" data-tactic-id="${_esc(t.id)}" style="border-left-color:${sevCol}">
      <div class="off-tc-header">
        <div class="off-tc-left">
          <span class="off-tc-icon">${icon}</span>
          <div>
            <div class="off-tc-name">${label}</div>
            <div class="off-tc-meta">
              ${t.mitre_id ? `<span class="mitre-tag">${t.mitre_id}</span>` : ''}
              <span class="off-sev-badge" style="background:${sevCol}20;color:${sevCol};border:1px solid ${sevCol}40">SEV ${sev}</span>
            </div>
          </div>
        </div>
        <span class="off-tc-date">${date}</span>
      </div>
      ${t.description ? `<div class="off-tc-desc">${_escHtml(t.description)}</div>` : ''}
      ${firstCmd ? `
      <div class="off-tc-cmd-preview">
        <div class="off-cmd-label">COMMANDS</div>
        <div class="off-cmd-block">
          <code class="off-cmd-code">${_escHtml(firstCmd)}</code>
          <button class="off-copy-btn" data-copy-cmd="${_escAttr(firstCmd)}">Copy</button>
        </div>
        ${commands.length > 1 ? `<div class="off-cmd-more">+${commands.length - 1} more — click card for all</div>` : ''}
      </div>` : ''}
      <div class="off-tc-actions">
        <button class="off-run-btn" data-run-tactic="${_esc(t.id)}">▶ Run in Sandbox</button>
        <span class="off-tc-cta">View all commands →</span>
      </div>
    </div>`;
}

// ── Modal ─────────────────────────────────────────────────────────────────────

function offShowModal(id) {
  const t = _allTactics.find(x => x.id === id);
  if (!t) return;
  _currentTactic = t;

  const icon     = ATTACK_ICONS[t.attack_type] || '⚔️';
  const label    = ATTACK_LABELS[t.attack_type] || t.attack_type;
  const sev      = t.severity || 0;
  const sevCol   = _sevColour(sev);
  const commands = Array.isArray(t.commands) ? t.commands : [];
  const date     = t.created_at ? new Date(t.created_at).toLocaleString() : '—';

  document.getElementById('off-modal-title').textContent = `${icon} ${label}`;
  document.getElementById('off-modal-status').textContent =
    `⚔ OFFENSE TACTIC${t.mitre_id ? ' · ' + t.mitre_id : ''}`;

  document.getElementById('off-modal-stats').innerHTML = `
    <div class="off-ms-row">
      <div class="off-ms-stat">
        <div class="off-ms-val" style="color:${sevCol}">${sev}/10</div>
        <div class="off-ms-lbl">Severity</div>
      </div>
      <div class="off-ms-stat">
        <div class="off-ms-val">${commands.length}</div>
        <div class="off-ms-lbl">Commands</div>
      </div>
      <div class="off-ms-stat">
        <div class="off-ms-val">${date.split(',')[0]}</div>
        <div class="off-ms-lbl">Catalogued</div>
      </div>
    </div>`;

  document.getElementById('off-modal-details').textContent =
    t.description || 'No description provided.';

  document.getElementById('off-modal-commands').innerHTML = commands.length
    ? commands.map(cmd => `
        <div class="off-modal-cmd-block">
          <code class="off-modal-cmd-code">${_escHtml(cmd)}</code>
          <button class="off-copy-btn" data-copy-cmd="${_escAttr(cmd)}">Copy</button>
        </div>`).join('')
    : '<p style="color:var(--text-3);font-size:13px">No commands available.</p>';

  document.getElementById('off-modal').style.display = 'flex';
}

function offCloseModal(e) {
  if (e && e.target !== document.getElementById('off-modal')) return;
  document.getElementById('off-modal').style.display = 'none';
  _currentTactic = null;
}

// ── Actions ───────────────────────────────────────────────────────────────────

function offCopyAll() {
  const t = _currentTactic;
  if (!t) return;
  const commands = Array.isArray(t.commands) ? t.commands : [];
  const label    = ATTACK_LABELS[t.attack_type] || t.attack_type;
  const text = `# ${label} — Offense Tactic\n# MITRE: ${t.mitre_id || '—'} · Severity: ${t.severity}\n\n` +
               commands.join('\n\n');
  navigator.clipboard.writeText(text)
    .then(() => _toast('All commands copied'))
    .catch(() => _toast('Copy failed'));
}

function offRunInSandbox() {
  const t = _currentTactic;
  if (t) window.location.href = `sandbox.html?tactic=${t.id}`;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function _copyCmd(cmd, btn) {
  navigator.clipboard.writeText(cmd).then(() => {
    const orig = btn.textContent;
    btn.textContent = 'Copied ✓';
    btn.style.color = 'rgba(80,200,120,0.9)';
    setTimeout(() => { btn.textContent = orig; btn.style.color = ''; }, 1800);
  }).catch(() => _toast('Copy failed'));
}

function _toast(msg) {
  document.querySelectorAll('.off-toast').forEach(t => t.remove());
  const el = document.createElement('div');
  el.className = 'off-toast';
  el.textContent = msg;
  document.body.appendChild(el);
  requestAnimationFrame(() => el.classList.add('off-toast-visible'));
  setTimeout(() => { el.classList.remove('off-toast-visible'); setTimeout(() => el.remove(), 300); }, 3000);
}

function _esc(s) { return String(s || '').replace(/"/g, '&quot;'); }
function _escHtml(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
function _escAttr(s) {
  return String(s || '').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

document.addEventListener('DOMContentLoaded', offInit);
