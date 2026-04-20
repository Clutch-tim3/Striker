const ATTACK_LABELS = {
  ransomware:           'Ransomware',
  keylogger:            'Keylogger',
  rootkit:              'Rootkit',
  c2_beacon:            'C2 Beacon',
  data_exfil:           'Data Exfiltration',
  cryptominer:          'Cryptominer',
  worm:                 'Worm',
  backdoor:             'Backdoor',
  privilege_escalation: 'Privilege Escalation',
};

const ATTACK_ICONS = {
  ransomware:           '🔒',
  keylogger:            '⌨️',
  rootkit:              '🕳️',
  c2_beacon:            '📡',
  data_exfil:           '📤',
  cryptominer:          '⛏️',
  worm:                 '🪱',
  backdoor:             '🚪',
  privilege_escalation: '⬆️',
};

let currentThreat = null;
let feedEntryCounter = 0;

function buildThreatEntry(threat) {
  const sev = threat.severity || 0;
  const sevLabel = getSeverityLabel(sev);
  const attackType = threat.attack_type || 'unknown';
  const label = ATTACK_LABELS[attackType] || attackType;
  const icon = ATTACK_ICONS[attackType] || '⚠️';
  const mitre = threat.mitre_id || {};
  const source = threat.telemetry?.source || 'system';
  const entryId = `threat-entry-${++feedEntryCounter}`;

  const el = document.createElement('div');
  el.className = 'threat-entry';
  el.id = entryId;
  el.dataset.threat = JSON.stringify(threat);
  el.dataset.attackType = attackType;
  el.dataset.threatId = threat.threat_id || '';
  el.onclick = () => showThreatModal(JSON.parse(el.dataset.threat));

  el.innerHTML = `
    <div class="threat-sev-bar sev-${sevLabel}"></div>
    <div class="threat-body">
      <div class="threat-name">${icon} ${label}</div>
      <div class="threat-meta">
        <span class="badge badge-${sevLabel}">Sev ${sev}</span>
        ${mitre.technique_id ? `<span class="mitre-tag">${mitre.technique_id}</span>` : ''}
        <span style="color:var(--text-2)">${source}</span>
      </div>
    </div>
    <div class="threat-time">${formatTime(new Date().toISOString())}</div>
  `;

  return el;
}

function addThreatToFeed(threat) {
  const feed = document.getElementById('threat-feed');
  const empty = document.getElementById('feed-empty');
  if (empty) empty.style.display = 'none';

  const entry = buildThreatEntry(threat);
  feed.insertBefore(entry, feed.firstChild);

  while (feed.children.length > 101) {
    feed.removeChild(feed.lastChild);
  }
}

// Called by dashboard.js when THREAT_NEUTRALISED arrives with insights
function attachInsightsToFeed(threatId, insights, antibodyId) {
  const feed = document.getElementById('threat-feed');
  const entry = feed.querySelector(`.threat-entry[data-threat-id="${threatId}"]`);
  if (!entry) return;
  const t = JSON.parse(entry.dataset.threat);
  t._insights = insights;
  t._antibodyId = antibodyId;
  entry.dataset.threat = JSON.stringify(t);
  const modal = document.getElementById('threat-modal');
  if (modal && modal.style.display !== 'none') {
    modal.dataset.antibodyId = antibodyId;
  }
  if (currentThreat && currentThreat.threat_id === threatId) {
    currentThreat = t;
    if (insights) renderModalInsights(insights, antibodyId);
  }
}

function clearFeed() {
  const feed = document.getElementById('threat-feed');
  feed.innerHTML = `
    <div class="empty-state" id="feed-empty">
      <div class="empty-state-icon">🛡️</div>
      <div class="empty-state-title">All clear</div>
      <div class="empty-state-sub">No threats detected. System is monitoring.</div>
    </div>`;
}

// ── MODAL ─────────────────────────────────────────────────────────────────────

function showThreatModal(threat) {
  currentThreat = threat;
  const modal = document.getElementById('threat-modal');
  const title = document.getElementById('modal-threat-title');
  const killBtn = document.getElementById('modal-kill-btn');
  const qBtn = document.getElementById('modal-quarantine-btn');

  const attackType = threat.attack_type || 'unknown';
  const label = ATTACK_LABELS[attackType] || attackType;
  const icon = ATTACK_ICONS[attackType] || '⚠️';
  const mitre = threat.mitre_id || {};
  const t = threat.telemetry || {};
  const sev = threat.severity || 0;
  const sevLabel = getSeverityLabel(sev);

  title.textContent = `${icon} ${label}`;

  // ── Overview section ──────────────────────────────────────────────────────
  const row = (lbl, val) => `
    <div class="modal-row">
      <div class="modal-row-label">${lbl}</div>
      <div class="modal-row-value">${val}</div>
    </div>`;

  const content = document.getElementById('modal-content');
  content.innerHTML = `
    <div class="modal-overview">
      ${row('Severity', `<span class="badge badge-${sevLabel}">Level ${sev} — ${sevLabel.toUpperCase()}</span>`)}
      ${row('Anomaly Score', `<strong>${((threat.anomaly_score || 0) * 100).toFixed(0)}%</strong>`)}
      ${mitre.technique_id ? row('MITRE ATT&CK', `<span class="mitre-tag">${mitre.technique_id}</span><span class="modal-mitre-name">${mitre.technique_name || ''}</span>`) : ''}
      ${row('Source', `<span style="color:var(--text-1)">${t.source || 'unknown'}</span><span class="modal-sep">·</span><span style="color:var(--text-2)">${t.event || ''}</span>`)}
      ${t.pid ? row('Process', `<span class="mono">${t.name || 'unknown'}</span><span class="modal-pid">PID ${t.pid}</span>${t.cmdline ? `<div class="mono modal-cmdline">${(t.cmdline||[]).join(' ')}</div>` : ''}`) : ''}
      ${t.file_path ? row('File', `<span class="mono modal-filepath">${t.file_path}</span>`) : ''}
      ${t.dest_ip ? row('Destination', `<span class="mono">${t.dest_ip}:${t.dest_port || '?'}</span>`) : ''}
      ${threat.similar_past && threat.similar_past.length > 0 ? row('Antibody Match', `<span class="modal-match-hit">✓ Similar threat found in archive</span>`) : ''}
      ${row('Response', (threat.response || []).length === 0
        ? '<span style="color:var(--text-3)">Notification only</span>'
        : (threat.response || []).map(r => `<span class="badge badge-critical" style="margin-right:4px">${r}</span>`).join('')
      )}
    </div>

    <div class="insight-sections" id="modal-insights">
      ${threat._insights ? buildInsightHTML(threat._insights, threat._antibodyId) : buildPendingInsights()}
    </div>
  `;

  killBtn.style.display = t.pid ? 'inline-flex' : 'none';
  killBtn.onclick = () => { window.mahoraga.send('KILL_PROCESS', { pid: t.pid }); closeThreatModal(); };

  qBtn.style.display = t.file_path ? 'inline-flex' : 'none';
  qBtn.onclick = () => { window.mahoraga.send('QUARANTINE', { path: t.file_path }); closeThreatModal(); };

  modal.style.display = 'flex';
}

function renderModalInsights(insights, antibodyId) {
  const container = document.getElementById('modal-insights');
  if (container) container.innerHTML = buildInsightHTML(insights, antibodyId);
}

function buildPendingInsights() {
  return `
    <div class="insight-pending" id="modal-analysis-pending">
      <div class="insight-pending-dot" id="modal-analysis-dot"></div>
      <span id="modal-analysis-label">Generating analysis…</span>
    </div>`;
}

function onAnalysisReady(data) {
  const modal = document.getElementById('threat-modal');
  if (!modal || modal.style.display === 'none') return;
  if (modal.dataset.antibodyId !== data.antibody_id) return;
  const pending = document.getElementById('modal-analysis-pending');
  if (!pending) return;
  const container = document.getElementById('modal-insights');
  if (!container) return;
  container.innerHTML = `
    <div class="insight-block insight-learned">
      <div class="insight-block-header">
        <span class="insight-block-icon">🧠</span>
        <span class="insight-block-title">Threat Analysis</span>
      </div>
      <p class="insight-body">${data.analysis}</p>
    </div>`;
}

function buildInsightHTML(ins, antibodyId) {
  const abRef = antibodyId ? `<span class="insight-ab-id">Antibody ${antibodyId.slice(0, 8)}</span>` : '';
  return `
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
        <span class="insight-block-title">How It Adapted ${abRef}</span>
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

    <div class="insight-block insight-offensive">
      <div class="insight-block-header">
        <span class="insight-block-icon">⚔️</span>
        <span class="insight-block-title">Offensive Context</span>
      </div>
      <p class="insight-body">${ins.offensive}</p>
    </div>
  `;
}

function closeThreatModal(event) {
  if (event && event.target !== document.getElementById('threat-modal')) return;
  document.getElementById('threat-modal').style.display = 'none';
  currentThreat = null;
}
