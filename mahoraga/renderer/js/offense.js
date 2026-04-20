'use strict';

let _allTechniques = [];
let _currentFilter = 'all';
let _unlocked = false;

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

const PLATFORM_TAGS = {
  ransomware: 'Windows · Linux', keylogger: 'Windows', rootkit: 'Linux · Windows',
  c2_beacon: 'All platforms', data_exfil: 'All platforms',
  cryptominer: 'All platforms', worm: 'All platforms', backdoor: 'All platforms',
  privilege_escalation: 'Windows · Linux', gatekeeper_bypass: 'macOS',
  applescript_execution: 'macOS', keychain_access: 'macOS',
  persistence_mechanism: 'macOS · Linux', reverse_shell: 'Linux · macOS',
  ld_preload_injection: 'Linux', kernel_module_load: 'Linux',
};

// ── Boot ──────────────────────────────────────────────────────────────────────

function offInit() {
  window.mahoraga.onEvent(handleEvent);
}

function handleEvent(e) {
  if (e.type === 'OFFENSIVE_UNLOCKED') {
    if (e.data.ok) {
      _unlocked = true;
      _showUnlocked();
      window.mahoraga.send('GET_OFFENSIVE_INTEL', {});
    } else {
      const err = document.getElementById('off-gate-error');
      if (err) {
        err.style.display = 'block';
        setTimeout(() => { err.style.display = 'none'; }, 3500);
      }
      const input = document.getElementById('off-gate-input');
      if (input) { input.value = ''; input.focus(); }
    }
  }
  if (e.type === 'OFFENSIVE_INTEL_DATA') {
    _renderIntel(e.data);
  }
  if (e.type === 'OFFENSIVE_INTEL_ERROR') {
    document.getElementById('off-loading').textContent =
      'Failed to load intelligence data: ' + (e.data.message || 'Unknown error');
  }
}

// ── Auth ──────────────────────────────────────────────────────────────────────

function offUnlock() {
  const input = document.getElementById('off-gate-input');
  const key = (input && input.value.trim()) || '';
  if (!key) { input && input.focus(); return; }
  window.mahoraga.send('UNLOCK_OFFENSIVE', { key });
}

function offLock() {
  _unlocked = false;
  document.getElementById('off-gate').style.display = 'flex';
  document.getElementById('off-content').style.display = 'none';
  const input = document.getElementById('off-gate-input');
  if (input) input.value = '';
}

function _showUnlocked() {
  document.getElementById('off-gate').style.display = 'none';
  document.getElementById('off-content').style.display = 'flex';
}

// ── Render ────────────────────────────────────────────────────────────────────

function _renderIntel({ techniques, total_encounters, families_learned }) {
  _allTechniques = techniques || [];

  document.getElementById('off-stat-families').textContent = families_learned;
  document.getElementById('off-stat-encounters').textContent = total_encounters;

  offFilter();
}

function offFilter() {
  const search = (document.getElementById('off-search').value || '').toLowerCase();
  const filter = _currentFilter;

  const visible = _allTechniques.filter(t => {
    if (filter === 'seen'   && t.encounter_count === 0) return false;
    if (filter === 'unseen' && t.encounter_count > 0)   return false;
    if (search) {
      const label = (ATTACK_LABELS[t.attack_type] || t.attack_type).toLowerCase();
      return label.includes(search) || (t.mitre_id || '').toLowerCase().includes(search);
    }
    return true;
  });

  const grid = document.getElementById('off-grid');
  document.getElementById('off-loading') && (document.getElementById('off-loading').style.display = 'none');

  if (!visible.length) {
    grid.innerHTML = '<div class="off-empty">No techniques match your filter.</div>';
    return;
  }
  grid.innerHTML = visible.map(buildCard).join('');
}

function offSetFilter(f, btn) {
  _currentFilter = f;
  document.querySelectorAll('.off-tab').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  offFilter();
}

function buildCard(t) {
  const label    = ATTACK_LABELS[t.attack_type] || t.attack_type.replace(/_/g, ' ');
  const icon     = ATTACK_ICONS[t.attack_type] || '⚠️';
  const platform = PLATFORM_TAGS[t.attack_type] || 'All platforms';
  const seen     = t.encounter_count > 0;
  const sev      = t.max_severity || 0;
  const sevLabel = sev >= 9 ? 'critical' : sev >= 7 ? 'high' : sev >= 4 ? 'medium' : 'low';

  const preview = t.offensive_text
    ? t.offensive_text.slice(0, 140) + (t.offensive_text.length > 140 ? '…' : '')
    : 'No offensive context available.';

  return `
    <div class="off-card${seen ? ' off-card-seen' : ''}"
         onclick="offShowModal(${JSON.stringify(JSON.stringify(t))})">
      <div class="off-card-top">
        <div class="off-card-icon">${icon}</div>
        <div style="flex:1;min-width:0">
          <div class="off-card-title">${label}</div>
          <div class="off-card-platform">${platform}</div>
        </div>
        ${t.mitre_id ? `<span class="mitre-tag">${t.mitre_id}</span>` : ''}
      </div>
      <div class="off-card-preview">${preview}</div>
      <div class="off-card-footer">
        ${seen
          ? `<span class="off-encounter-badge"><span class="off-enc-dot"></span>${t.encounter_count} encounter${t.encounter_count !== 1 ? 's' : ''}</span>
             <span class="badge badge-${sevLabel}" style="font-size:10px">sev ${sev}</span>`
          : `<span class="off-unseen-badge">Not yet encountered</span>`}
        <span class="off-card-cta">View intel →</span>
      </div>
    </div>`;
}

// ── Modal ─────────────────────────────────────────────────────────────────────

function offShowModal(tJson) {
  const t = JSON.parse(tJson);
  const label    = ATTACK_LABELS[t.attack_type] || t.attack_type.replace(/_/g, ' ');
  const icon     = ATTACK_ICONS[t.attack_type] || '⚠️';
  const seen     = t.encounter_count > 0;
  const sev      = t.max_severity || 0;
  const sevLabel = sev >= 9 ? 'critical' : sev >= 7 ? 'high' : sev >= 4 ? 'medium' : 'low';

  document.getElementById('off-modal-mitre').textContent =
    [t.mitre_id, t.mitre_name].filter(Boolean).join(' · ') || 'MITRE ATT&CK';
  document.getElementById('off-modal-title').textContent = `${icon} ${label}`;

  document.getElementById('off-modal-stats').innerHTML = seen ? `
    <div class="off-ms-row">
      <div class="off-ms-stat"><div class="off-ms-val">${t.encounter_count}</div><div class="off-ms-lbl">Encounters</div></div>
      <div class="off-ms-stat"><div class="off-ms-val"><span class="badge badge-${sevLabel}">${sev}</span></div><div class="off-ms-lbl">Max Severity</div></div>
      <div class="off-ms-stat"><div class="off-ms-val" style="font-size:12px">${_fmtDate(t.first_seen)}</div><div class="off-ms-lbl">First Seen</div></div>
      <div class="off-ms-stat"><div class="off-ms-val" style="font-size:12px">${_fmtDate(t.last_seen)}</div><div class="off-ms-lbl">Last Seen</div></div>
    </div>` : `<div class="off-ms-row"><div class="off-unseen-banner">This technique has not yet been encountered in the wild on this system.</div></div>`;

  document.getElementById('off-modal-offensive').textContent = t.offensive_text || 'No data.';

  const defWrap = document.getElementById('off-modal-defensive-wrap');
  const defBody = document.getElementById('off-modal-defensive');
  if (seen) {
    defWrap.style.display = 'block';
    // Defensive text comes from insight_generator.DEFENSIVE_PLAYBOOK via antibody insights
    // We show a static note — full per-antibody text is in the archive
    defBody.innerHTML = `See the <a href="archive.html" style="color:var(--red);text-decoration:underline">Antibody Archive</a> for per-encounter defensive analysis for this technique.`;
  } else {
    defWrap.style.display = 'none';
  }

  document.getElementById('off-modal').style.display = 'flex';
}

function offCloseModal(e) {
  if (e && e.target !== document.getElementById('off-modal')) return;
  document.getElementById('off-modal').style.display = 'none';
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function _fmtDate(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleDateString('en-GB', { day:'numeric', month:'short', year:'numeric' });
  } catch { return iso.slice(0, 10); }
}

document.addEventListener('DOMContentLoaded', offInit);
