let allAntibodies = [];
let currentView = 'grid';



// Canonical source of truth for all 16 attack types
const ATTACK_TYPES = [
  { id: 'ransomware',               label: 'Ransomware',           icon: '🔒' },
  { id: 'keylogger',                label: 'Keylogger',            icon: '⌨️'  },
  { id: 'rootkit',                  label: 'Rootkit',              icon: '🕳️' },
  { id: 'c2_beacon',                label: 'C2 Beacon',            icon: '📡' },
  { id: 'data_exfil',               label: 'Data Exfiltration',    icon: '📤' },
  { id: 'cryptominer',              label: 'Cryptominer',          icon: '⛏️'  },
  { id: 'worm',                     label: 'Worm',                 icon: '🪱' },
  { id: 'backdoor',                 label: 'Backdoor',             icon: '🚪' },
  { id: 'privilege_escalation',     label: 'Privilege Escalation', icon: '⬆️'  },
  { id: 'gatekeeper_bypass',        label: 'Gatekeeper Bypass',    icon: '🚧' },
  { id: 'applescript_execution',    label: 'AppleScript Execution',icon: '🍎' },
  { id: 'keychain_access',          label: 'Keychain Access',      icon: '🔑' },
  { id: 'persistence_mechanism',    label: 'Persistence Mechanism',icon: '🔁' },
  { id: 'reverse_shell',            label: 'Reverse Shell',        icon: '🐚' },
  { id: 'ld_preload_injection',     label: 'LD_PRELOAD Injection', icon: '💉' },
  { id: 'kernel_module_load',       label: 'Kernel Module Load',   icon: '⚙️'  },
];

// Helper lookups derived from canonical ATTACK_TYPES
const ATTACK_LABELS = Object.fromEntries(ATTACK_TYPES.map(t => [t.id, t.label]));
const ATTACK_ICONS  = Object.fromEntries(ATTACK_TYPES.map(t => [t.id, t.icon]));

function init() {
  window.mahoraga.onEvent(handleEvent);
  refreshArchive();
  // Dynamically populate filter dropdown from ATTACK_TYPES
  populateFilterDropdown();
  // Auto-refresh archive every 2 seconds for real-time updates
  setInterval(refreshArchive, 2000);
}

function populateFilterDropdown() {
  const select = document.getElementById('filter-type');
  if (!select) return;
  // Keep first option (All Attack Types), clear the rest
  while (select.options.length > 1) {
    select.remove(1);
  }
  ATTACK_TYPES.forEach(t => {
    const opt = document.createElement('option');
    opt.value = t.id;
    opt.textContent = t.label;
    select.appendChild(opt);
  });
}

function refreshArchive() {
  window.mahoraga.send('GET_ARCHIVE', {});
}

function handleEvent(event) {
  if (event.type === 'ARCHIVE_DATA') {
    allAntibodies = event.data.antibodies || [];
    document.getElementById('archive-total').textContent = allAntibodies.length;
    renderArchive(allAntibodies);
  }
  if (event.type === 'ARCHIVE_UPDATED') {
    // Real-time update: refresh archive immediately
    // Only refresh if we're currently viewing the archive page
    if (document.getElementById('archive-view')) {
      window.mahoraga.send('GET_ARCHIVE', {});
    }
  }
  if (event.type === 'ARCHIVE_ERROR') {
    // Show toast notification (non-blocking, dismissible after 5s)
    const toast = document.createElement('div');
    toast.style.cssText = 'position:fixed;top:20px;right:20px;background:var(--red, #e74c3c);color:#fff;padding:12px 18px;border-radius:6px;z-index:9999;font-size:13px;font-family:inherit;box-shadow:0 4px 12px rgba(0,0,0,0.3);max-width:400px;';
    toast.textContent = `Archive Error: ${event.data?.message || 'Unknown error'}`;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 5000);

    const grid = document.getElementById('grid-view');
    if (grid) grid.innerHTML = `<div class="empty-state" style="grid-column:1/-1">
      <div class="empty-state-icon">⚠️</div>
      <div class="empty-state-title">Archive unavailable</div>
      <div class="empty-state-sub">${event.data?.message || 'Database error'}</div>
    </div>`;
  }
  if (event.type === 'THREAT_NEUTRALISED') {
    window.mahoraga.send('GET_ARCHIVE', {});
  }
  if (event.type === 'OFFENSIVE_STRATEGY_CREATED') {
    if (document.getElementById('archive-view')) {
      window.mahoraga.send('GET_ARCHIVE', {});
    }
  }
}

function filterArchive() {
  const search = document.getElementById('search-input').value.toLowerCase();
  const type = document.getElementById('filter-type').value;
  const minSev = parseInt(document.getElementById('filter-severity').value) || 0;

  const filtered = allAntibodies.filter(ab => {
    const matchType = !type || ab.attack_type === type;
    const matchSev = ab.severity >= minSev;
    const matchSearch = !search || (
      (ab.attack_type || '').includes(search) ||
      (ab.mitre_id || '').toLowerCase().includes(search) ||
      (ab.mitre_name || '').toLowerCase().includes(search) ||
      (ab.id || '').includes(search)
    );
    return matchType && matchSev && matchSearch;
  });

  renderArchive(filtered);
}

function setView(view) {
  currentView = view;
  document.getElementById('grid-view').style.display = view === 'grid' ? 'grid' : 'none';
  document.getElementById('list-view').style.display = view === 'list' ? 'block' : 'none';
  document.getElementById('btn-grid').classList.toggle('active', view === 'grid');
  document.getElementById('btn-list').classList.toggle('active', view === 'list');
}

function renderArchive(antibodies) {
  renderGrid(antibodies);
  renderList(antibodies);
}

function renderGrid(antibodies) {
  const grid = document.getElementById('grid-view');
  const empty = document.getElementById('archive-empty');

  if (!antibodies.length) {
    grid.innerHTML = '';
    grid.appendChild(empty || buildEmpty());
    return;
  }

  grid.innerHTML = antibodies.map(ab => buildAntibodyCard(ab)).join('');
}

function buildEmpty() {
  const el = document.createElement('div');
  el.className = 'empty-state';
  el.style.gridColumn = '1 / -1';
  el.id = 'archive-empty';
  el.innerHTML = `
    <div class="empty-state-icon">🔬</div>
    <div class="empty-state-title">No antibodies found</div>
    <div class="empty-state-sub">Try adjusting the filters.</div>`;
  return el;
}

function buildAntibodyCard(ab) {
  const sev = ab.severity || 0;
  const sevLabel = getSeverityLabel(sev);
  const attackType = ab.attack_type || 'unknown';
  const label = ATTACK_LABELS[attackType] || attackType;
  const icon = ATTACK_ICONS[attackType] || '⚠';
  const responses = tryParseJSON(ab.response_json) || [];

  return `
    <div class="antibody-card" onclick="showAntibodyModal(${JSON.stringify(JSON.stringify(ab))})">
      <div class="antibody-card-top">
        <div class="antibody-title">${icon} ${label}</div>
        <div class="severity-chip sc-${sevLabel}">${sev}</div>
      </div>
      ${ab.mitre_id ? `
      <div style="margin-bottom:2px">
        <span class="mitre-tag">${ab.mitre_id}</span>
        <span style="font-size:11px;color:var(--text-2);margin-left:6px">${ab.mitre_name || ''}</span>
      </div>` : ''}
      <div class="antibody-meta">
        <span class="antibody-meta-item">${timeAgo(ab.created_at)}</span>
        <span class="antibody-meta-item">·</span>
        <span class="antibody-meta-item">${ab.platform || 'unknown'}</span>
        <span class="antibody-meta-item">·</span>
        <span class="antibody-meta-item">${ab.source || 'system'}</span>
      </div>
      ${responses.length ? `
      <div class="antibody-responses">
        ${responses.map(r => `<span class="badge badge-critical" style="font-size:10px">${r}</span>`).join('')}
      </div>` : ''}
    </div>`;
}

function renderList(antibodies) {
  const tbody = document.getElementById('list-tbody');
  if (!antibodies.length) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:var(--text-2);padding:40px">No antibodies found.</td></tr>`;
    return;
  }
  tbody.innerHTML = antibodies.map(ab => {
    const sev = ab.severity || 0;
    const sevLabel = getSeverityLabel(sev);
    const responses = tryParseJSON(ab.response_json) || [];
    const LABELS = ATTACK_LABELS;
    return `
      <tr style="cursor:pointer" onclick="showAntibodyModal(${JSON.stringify(JSON.stringify(ab))})">
        <td class="text-primary">${LABELS[ab.attack_type] || ab.attack_type || '—'}</td>
        <td>${ab.mitre_id ? `<span class="mitre-tag">${ab.mitre_id}</span>` : '—'}</td>
        <td><span class="badge badge-${sevLabel}">${sev}</span></td>
        <td>${ab.source || '—'}</td>
        <td>${responses.slice(0,2).map(r=>`<span class="badge badge-critical" style="font-size:10px">${r}</span>`).join(' ') || '<span style="color:var(--text-2)">notify</span>'}</td>
        <td>${formatDate(ab.created_at)}</td>
        <td><button class="btn btn-secondary btn-sm">Details</button></td>
      </tr>`;
  }).join('');
}

function showAntibodyModal(abJson) {
  const ab = JSON.parse(abJson);
  const modal = document.getElementById('antibody-modal');
  const title = document.getElementById('antibody-modal-title');
  const content = document.getElementById('antibody-modal-content');

  const sev = ab.severity || 0;
  const sevLabel = getSeverityLabel(sev);
  const attackType = ab.attack_type || 'unknown';
  const label = ATTACK_LABELS[attackType] || attackType;
  const icon = ATTACK_ICONS[attackType] || '⚠️';
  const responses = tryParseJSON(ab.response_json) || [];
  const telemetry = tryParseJSON(ab.telemetry_json) || {};

  title.textContent = `${icon} Antibody — ${label}`;
  content.innerHTML = `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px">
      <div><div class="label">ID</div><div class="mono" style="font-size:10px;word-break:break-all">${ab.id}</div></div>
      <div><div class="label">Severity</div><span class="badge badge-${sevLabel}">Level ${sev}</span></div>
    </div>
    ${ab.mitre_id ? `
    <div style="margin-bottom:16px">
      <div class="label">MITRE ATT&amp;CK</div>
      <span class="mitre-tag">${ab.mitre_id}</span>
      <span style="color:var(--text-1);margin-left:8px;font-size:12px">${ab.mitre_name || ''}</span>
    </div>` : ''}
    <div style="margin-bottom:16px">
      <div class="label">Detected</div>
      <div>${formatDate(ab.created_at)}</div>
    </div>
    <div style="margin-bottom:16px">
      <div class="label">Platform / Source</div>
      <div>${ab.platform || '—'} / ${ab.source || '—'}</div>
    </div>
    <div style="margin-bottom:16px">
      <div class="label">Anomaly Score</div>
      <div>${((ab.anomaly_score || 0) * 100).toFixed(1)}%</div>
    </div>
    <div style="margin-bottom:16px">
      <div class="label">Response Actions</div>
      <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:4px">
        ${responses.length
          ? responses.map(r => `<span class="badge badge-critical">${r}</span>`).join('')
          : '<span style="color:var(--text-2);font-size:12px">Notification only</span>'}
      </div>
    </div>
    ${telemetry.event ? `
    <div style="margin-bottom:16px">
      <div class="label">Trigger Event</div>
      <div class="mono">${telemetry.event}</div>
    </div>` : ''}
    ${buildAntibodyInsights(ab)}
  `;

  modal.style.display = 'flex';
}

function buildAntibodyInsights(ab) {
  const ins = tryParseJSON(ab.insights_json);
  const offensiveData = ins && ins.offensive;

  const offensiveSection = offensiveData
    ? `
      <div class="insight-block insight-offensive">
        <div class="insight-block-header">
          <span class="insight-block-icon">⚔️</span>
          <span class="insight-block-title">Offensive Context</span>
        </div>
        ${ins ? `<p class="insight-body">${ins.offensive}</p>` : ''}
        <div class="label" style="margin-top:12px">Raw Telemetry</div>
        <pre class="mono" style="font-size:10px;overflow:auto;max-height:200px;color:var(--text-1)">${JSON.stringify(tryParseJSON(ab.telemetry_json) || {}, null, 2)}</pre>
      </div>`
    : '';

  if (!ins) return offensiveSection;

  return `
    <div class="insight-sections" style="margin-top:20px">
      <div class="insight-block insight-learned">
        <div class="insight-block-header">
          <span class="insight-block-icon">🧠</span>
          <span class="insight-block-title">What Mahoraga Learned</span>
        </div>
        <p class="insight-body">${ins.learned}</p>
      </div>
      <div class="insight-block insight-adapted">
        <div class="insight-block-header">
          <span class="insight-block-icon">⚙️</span>
          <span class="insight-block-title">How It Adapted</span>
        </div>
        <p class="insight-body">${ins.adapted}</p>
      </div>
      <div class="insight-block insight-defensive">
        <div class="insight-block-header">
          <span class="insight-block-icon">🛡️</span>
          <span class="insight-block-title">Defensive Application</span>
        </div>
        <p class="insight-body">${ins.defensive}</p>
      </div>
      ${offensiveSection}
    </div>`;
}

function closeAntibodyModal(event) {
  if (event && event.target !== document.getElementById('antibody-modal')) return;
  document.getElementById('antibody-modal').style.display = 'none';
}

function exportArchive() {
  if (!allAntibodies.length) return;
  const headers = ['id','created_at','attack_type','mitre_id','mitre_name','severity','anomaly_score','source','platform'];
  const rows = allAntibodies.map(ab =>
    headers.map(h => JSON.stringify(ab[h] ?? '')).join(',')
  );
  const csv = [headers.join(','), ...rows].join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `mahoraga-archive-${Date.now()}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

function tryParseJSON(str) {
  try { return JSON.parse(str); } catch { return null; }
}

document.addEventListener('DOMContentLoaded', init);
