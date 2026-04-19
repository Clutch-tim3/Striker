function renderActivityChart(containerId, data) {
  const container = document.getElementById(containerId);
  if (!container) return;

  const max = Math.max(...data, 1);
  container.innerHTML = data.map((v, i) => {
    const pct = Math.round((v / max) * 100);
    const isLast = i === data.length - 1;
    return `<div class="activity-bar ${isLast ? 'active' : ''}"
      style="height:${Math.max(pct, 4)}%"
      title="${v} events"></div>`;
  }).join('');
}

function renderAdaptationArc(score) {
  const arc = document.getElementById('adaptation-arc');
  const pctEl = document.getElementById('adaptation-pct');
  if (!arc || !pctEl) return;

  const circumference = 213.6;
  const offset = circumference - (score / 100) * circumference;
  arc.style.strokeDashoffset = offset;
  pctEl.textContent = score;
}

function getSeverityColor(severity) {
  if (severity >= 9) return 'var(--red)';
  if (severity >= 7) return 'var(--orange)';
  if (severity >= 5) return 'var(--yellow)';
  return 'var(--blue)';
}

function getSeverityLabel(severity) {
  if (severity >= 9) return 'critical';
  if (severity >= 7) return 'high';
  if (severity >= 5) return 'medium';
  return 'low';
}

function formatTime(isoString) {
  if (!isoString) return 'now';
  const d = new Date(isoString);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function formatDate(isoString) {
  if (!isoString) return '';
  const d = new Date(isoString);
  return d.toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' })
    + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function timeAgo(isoString) {
  const diff = (Date.now() - new Date(isoString).getTime()) / 1000;
  if (diff < 60) return `${Math.round(diff)}s ago`;
  if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.round(diff / 3600)}h ago`;
  return `${Math.round(diff / 86400)}d ago`;
}
