let monitoring = true;
let threatsToday = 0;
let neutralisedCount = 0;
let antibodyCount = 0;
let adaptationScore = 72;
let attackTypeCounts = {};
let activityData = new Array(24).fill(0);

function init() {
  renderActivityChart('activity-chart', activityData);
  renderAdaptationArc(adaptationScore);

  window.mahoraga.onEvent(handleEvent);
  window.mahoraga.send('GET_CONFIG');
  window.mahoraga.send('GET_ARCHIVE_STATS', {});
}

function handleEvent(event) {
  switch (event.type) {
    case 'MONITORING_STARTED':
      setMonitoringState(true);
      if (event.data && event.data.demo) {
        const b = document.getElementById('demo-banner');
        if (b) b.style.display = 'flex';
      }
      break;

    case 'MONITORING_STOPPED':
      setMonitoringState(false);
      break;

    case 'THREAT_DETECTED':
      onThreatDetected(event.data);
      break;

    case 'THREAT_NEUTRALISED':
      onThreatNeutralised(event.data);
      break;

    case 'ARCHIVE_STATS':
      antibodyCount = event.data.total || 0;
      document.getElementById('antibody-count').textContent = antibodyCount;
      const archiveBadge = document.getElementById('archive-count');
      if (archiveBadge && antibodyCount > 0) {
        archiveBadge.textContent = antibodyCount;
        archiveBadge.style.display = 'inline-block';
      }
      break;

    case 'ARCHIVE_UPDATED':
      // Real-time update from batch commit
      if (event.data && event.data.count !== undefined) {
        antibodyCount = event.data.count;
        document.getElementById('antibody-count').textContent = antibodyCount;
        const archiveBadge = document.getElementById('archive-count');
        if (archiveBadge) {
          archiveBadge.textContent = antibodyCount;
          archiveBadge.style.display = 'inline-block';
        }
      }
      // Flash indicator for new additions
      const indicator = document.getElementById('antibody-count');
      if (indicator) {
        indicator.style.transition = 'none';
        indicator.style.transform = 'scale(1.3)';
        indicator.style.color = 'var(--red)';
        setTimeout(() => {
          indicator.style.transition = 'all 0.3s ease';
          indicator.style.transform = 'scale(1)';
          indicator.style.color = '';
        }, 300);
      }
      break;

    case 'THREAT_ANALYSIS_READY':
      if (typeof onAnalysisReady === 'function') onAnalysisReady(event.data);
      break;

    case 'CONFIG_DATA':
      applyConfig(event.data);
      break;
  }
}

function onThreatDetected(threat) {
  threatsToday++;
  document.getElementById('threats-today').textContent = threatsToday;
  document.getElementById('stat-threats').classList.add('has-activity');

  // Track attack type
  const at = threat.attack_type || 'unknown';
  attackTypeCounts[at] = (attackTypeCounts[at] || 0) + 1;
  renderAttackTypes();

  // Update hourly activity
  const hour = new Date().getHours();
  activityData[hour]++;
  renderActivityChart('activity-chart', activityData);

  // Show alert banner for high severity
  if ((threat.severity || 0) >= 8) {
    showAlert(threat);
  }

  addThreatToFeed(threat);
}

function onThreatNeutralised(data) {
  neutralisedCount++;
  document.getElementById('neutralised-count').textContent = neutralisedCount;
  antibodyCount++;
  document.getElementById('antibody-count').textContent = antibodyCount;

  const archiveBadge = document.getElementById('archive-count');
  if (archiveBadge) {
    archiveBadge.textContent = antibodyCount;
    archiveBadge.style.display = 'inline-block';
  }

  adaptationScore = Math.min(99, adaptationScore + 0.5);
  renderAdaptationArc(Math.round(adaptationScore));
  document.getElementById('model-score').textContent = Math.round(adaptationScore);

  // Wire antibody_id to feed entry + modal so THREAT_ANALYSIS_READY can resolve
  if (data.threat_id && data.antibody_id) {
    attachInsightsToFeed(data.threat_id, null, data.antibody_id);
  }
}

function renderAttackTypes() {
  const container = document.getElementById('attack-type-list');
  const entries = Object.entries(attackTypeCounts).sort((a, b) => b[1] - a[1]);
  if (!entries.length) return;

  const max = entries[0][1];
  const LABELS = {
    ransomware: 'Ransomware', c2_beacon: 'C2 Beacon',
    data_exfil: 'Data Exfil', rootkit: 'Rootkit',
    backdoor: 'Backdoor', keylogger: 'Keylogger',
    cryptominer: 'Cryptominer', worm: 'Worm',
    privilege_escalation: 'Priv. Escalation',
  };

  container.innerHTML = entries.slice(0, 6).map(([type, count]) => `
    <div class="attack-type-row">
      <div class="attack-type-name">${LABELS[type] || type}</div>
      <div class="attack-type-bar">
        <div class="attack-type-fill" style="width:${Math.round((count/max)*100)}%"></div>
      </div>
      <div class="attack-type-count">${count}</div>
    </div>
  `).join('');
}

function showAlert(threat) {
  const banner = document.getElementById('active-alert');
  const title = document.getElementById('alert-title');
  const sub = document.getElementById('alert-sub');
  const LABELS = { ransomware:'Ransomware', c2_beacon:'C2 Beacon', data_exfil:'Data Exfiltration',
    rootkit:'Rootkit', backdoor:'Backdoor' };
  const label = LABELS[threat.attack_type] || (threat.attack_type || 'Unknown threat');
  title.textContent = `Critical: ${label} detected (severity ${threat.severity})`;
  sub.textContent = `MITRE ${threat.mitre_id?.technique_id || 'T0000'} — ${threat.mitre_id?.technique_name || ''}`;
  banner.style.display = 'flex';

  document.getElementById('status-dot').className = 'status-dot alert';
  document.getElementById('status-text').textContent = 'Alert';
  document.getElementById('status-text').className = 'alert';
}

function dismissAlert() {
  document.getElementById('active-alert').style.display = 'none';
  document.getElementById('status-dot').className = 'status-dot';
  document.getElementById('status-text').textContent = 'Active';
  document.getElementById('status-text').className = '';
}

function toggleMonitoring() {
  const btn = document.getElementById('btn-start-stop');
  if (monitoring) {
    window.mahoraga.send('STOP_MONITORING');
    btn.textContent = 'Resume';
  } else {
    window.mahoraga.send('START_MONITORING');
    btn.textContent = 'Pause';
  }
}

function setMonitoringState(active) {
  monitoring = active;
  const dot = document.getElementById('status-dot');
  const text = document.getElementById('status-text');
  const liveDot = document.getElementById('live-dot');
  const btn = document.getElementById('btn-start-stop');

  if (active) {
    dot.className = 'status-dot';
    text.textContent = 'Active';
    text.className = '';
    liveDot.style.display = 'block';
    btn.textContent = 'Pause';
  } else {
    dot.className = 'status-dot inactive';
    text.textContent = 'Paused';
    text.className = 'inactive';
    liveDot.style.display = 'none';
    btn.textContent = 'Resume';
  }
}

function applyConfig(cfg) {
  if (cfg.tier) {
    const badge = document.getElementById('tier-badge');
    badge.textContent = cfg.tier.charAt(0).toUpperCase() + cfg.tier.slice(1);
    badge.className = 'tier-badge ' + cfg.tier;
  }
}

document.addEventListener('DOMContentLoaded', init);
