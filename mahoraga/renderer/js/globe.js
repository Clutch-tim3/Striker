// Mahoraga 3D Threat Globe

const RED       = '#922724';
const RED_MID   = '#c44a47';
const RED_FAINT = 'rgba(146,39,36,';

// ── Continent outlines [lat, lon] ────────────────────────────────────────────
// Change 5: additional vertices on problem edges before subdivision
const LAND = [
  // North America — Gulf Coast + west coast gaps filled
  [[71,-140],[70,-95],[68,-76],[63,-64],[60,-65],[48,-53],[44,-66],
   [41,-70],[35,-76],[26,-80],[25,-81],[24,-82],[24,-84],[24,-87],[23,-88],
   [17,-88],[10,-83],[8,-77],
   [15,-92],[22,-106],[23,-106],[25,-108],[27,-110],[29,-110],
   [32,-117],[37,-122],[49,-124],
   [54,-130],[58,-136],[61,-146],[65,-168],[68,-166],[71,-140]],
  // Greenland
  [[83,-30],[83,-52],[76,-68],[72,-56],[65,-53],[64,-42],[70,-22],[83,-22],[83,-30]],
  // South America
  [[11,-73],[11,-63],[8,-60],[2,-50],[-5,-35],[-10,-37],[-16,-39],
   [-23,-43],[-33,-53],[-40,-62],[-52,-68],[-55,-65],[-54,-70],
   [-50,-75],[-42,-73],[-30,-71],[-18,-70],[-16,-75],[-5,-81],[4,-77],[11,-73]],
  // Europe
  [[71,28],[70,18],[65,14],[62,6],[58,5],[51,2],[44,3],[37,0],
   [36,5],[38,15],[41,19],[42,29],[45,29],[47,38],[55,22],[59,25],[65,26],[71,28]],
  // Africa — Horn filled
  [[37,10],[33,32],[22,38],[12,44],[11,45],[10,46],[10,49],[11,51],[12,51],
   [5,41],[-5,41],[-15,36],[-26,35],[-35,19],[-35,17],[-26,-15],[-18,-12],
   [-5,8],[5,2],[10,15],[20,38],[30,32],[37,10]],
  // Asia main
  [[71,30],[68,48],[60,60],[55,82],[52,88],[47,88],[40,68],
   [30,48],[22,60],[13,43],[22,38],[30,32],[37,37],[42,28],
   [44,42],[50,60],[55,82],[60,100],[65,120],[71,140],[75,100],[71,30]],
  // India + SE Asia — peninsula tip + Malay corrected
  [[25,68],[22,88],[20,86],[13,80],[8,77],[8,77],[7,78],[7,79],[8,80],
   [7,80],[2,103],[3,102],[4,101],[5,100],[10,99],[15,100],
   [20,100],[25,90],[22,88],[25,68]],
  // Australia — north coast gap filled
  [[-14,130],[-15,134],[-16,138],[-17,142],[-18,146],[-19,148],
   [-28,154],[-37,150],[-39,147],[-38,140],[-35,136],[-32,133],[-22,114],[-14,130]],
  // Japan
  [[45,141],[43,141],[40,140],[35,136],[33,131],[30,131],[34,132],[38,140],[42,140],[45,141]],
  // UK
  [[58,-3],[57,-6],[55,-5],[52,-4],[51,0],[52,1],[54,0],[56,-2],[58,-3]],
];

// Pre-computed subdivided polygons (populated at init — zero per-frame cost)
let LAND_SUB = [];

// ── Cities ───────────────────────────────────────────────────────────────────
const CITIES = [
  { name: 'New York',    lat: 40.7,  lon: -74.0 },
  { name: 'London',      lat: 51.5,  lon:  -0.1 },
  { name: 'Moscow',      lat: 55.8,  lon:  37.6 },
  { name: 'Beijing',     lat: 39.9,  lon: 116.4 },
  { name: 'Tokyo',       lat: 35.7,  lon: 139.7 },
  { name: 'Sydney',      lat:-33.9,  lon: 151.2 },
  { name: 'Dubai',       lat: 25.2,  lon:  55.3 },
  { name: 'Singapore',   lat:  1.4,  lon: 103.8 },
  { name: 'São Paulo',   lat:-23.5,  lon: -46.6 },
  { name: 'Lagos',       lat:  6.5,  lon:   3.4 },
  { name: 'Mumbai',      lat: 19.1,  lon:  72.9 },
  { name: 'Toronto',     lat: 43.7,  lon: -79.4 },
  { name: 'Berlin',      lat: 52.5,  lon:  13.4 },
  { name: 'Seoul',       lat: 37.6,  lon: 127.0 },
  { name: 'Cape Town',   lat:-33.9,  lon:  18.4 },
  { name: 'Shanghai',    lat: 31.2,  lon: 121.5 },
  { name: 'Mexico City', lat: 19.4,  lon: -99.1 },
  { name: 'Cairo',       lat: 30.1,  lon:  31.2 },
];

// ── Active attack pairs (source → target city index) ────────────────────────
const ALL_PAIRS = [
  [2,0],[3,1],[3,0],[7,12],[7,6],[4,0],[2,12],[9,1],
  [8,0],[14,1],[6,0],[1,0],[13,4],[16,0],[2,1],[10,6],
  [3,4],[5,0],[15,4],[11,0],
];

// ── Cyber terms for glass blocks ─────────────────────────────────────────────
const TERMS = [
  'SYN_FLOOD_DETECTED','EXPLOIT/CVE-2024-1337','LATERAL_MOVEMENT_BLOCKED',
  'ZERO_DAY_PATTERN_MATCH','C2_BEACON_TERMINATED','RANSOMWARE_SIG: T1486',
  'PRIVILEGE_ESC_ATTEMPT','KERNEL_ROOTKIT_DETECTED','DNS_TUNNELING_BLOCKED',
  'MITRE: T1071.001','ANOMALY_SCORE: 0.94','BRUTE_FORCE: 192.168.1.45',
  'PROCESS_INJECTION_BLOCKED','DLL_HIJACK_DETECTED','PASS_THE_HASH_BLOCKED',
  'MEMORY_SCAN: WX_REGION','EXFIL_BLOCKED: 58.4KB','CRYPTOMINER_KILLED: xmrig',
  'HONEYPOT_TRIGGERED: 4444','TLS_FINGERPRINT_MISMATCH','BEACON_INTERVAL: 47s±12%',
  'ENTROPY_SPIKE: 0.97','ANTIBODY_MATCH: 0.89_SIM','ISOLATION_FOREST_TRAINED',
  'YARA_RULE_MATCHED','LOLBIN_DETECTED: certutil','POWERSHELL_ENCODED_CMD',
  'REGISTRY_PERSIST_BLOCKED','FIREWALL_RULE_UPDATED','ANOMALY_RETRAIN: 500_OBS',
  'PORT_SCAN_BLOCKED: masscan','CREDENTIAL_DUMP_ATTEMPT','WORM_PROPAGATION_STOPPED',
  'SUPPLY_CHAIN_SIGNATURE_FAIL','SHADOW_COPY_DELETE_BLOCKED',
];

// ─────────────────────────────────────────────────────────────────────────────
// State
// ─────────────────────────────────────────────────────────────────────────────
let canvas, ctx, glassLayer;
let W = 0, H = 0, cx = 0, cy = 0, R = 0;
let rotation = 0;
let startTime = 0;
let activePairs = [];

// ─────────────────────────────────────────────────────────────────────────────
// Projection
// ─────────────────────────────────────────────────────────────────────────────
function toRad(d) { return d * Math.PI / 180; }

// Change 2: geodesic subdivision — insert intermediate lat/lon points every maxDeg degrees
function subdivide(poly, maxDeg) {
  const out = [];
  for (let i = 0; i < poly.length; i++) {
    const [lat0, lon0] = poly[i];
    const [lat1, lon1] = poly[(i + 1) % poly.length];
    out.push([lat0, lon0]);
    const dist  = Math.sqrt((lat1 - lat0) ** 2 + (lon1 - lon0) ** 2);
    const steps = Math.ceil(dist / maxDeg);
    for (let s = 1; s < steps; s++) {
      const t = s / steps;
      out.push([lat0 + (lat1 - lat0) * t, lon0 + (lon1 - lon0) * t]);
    }
  }
  return out;
}

function project(lat, lon) {
  const φ = toRad(lat);
  const λ = toRad(lon - rotation);
  const x = R * Math.cos(φ) * Math.sin(λ);
  const y = -R * Math.sin(φ);
  const z = R * Math.cos(φ) * Math.cos(λ);
  return { x: cx + x, y: cy + y, z };
}

// ─────────────────────────────────────────────────────────────────────────────
// Draw helpers
// ─────────────────────────────────────────────────────────────────────────────
function drawSphere() {
  const ocean = ctx.createRadialGradient(cx - R*0.3, cy - R*0.3, R*0.05, cx, cy, R);
  ocean.addColorStop(0,   'rgba(38,8,8,1)');
  ocean.addColorStop(0.6, 'rgba(14,3,3,1)');
  ocean.addColorStop(1,   'rgba(4,1,1,1)');
  ctx.beginPath();
  ctx.arc(cx, cy, R, 0, Math.PI * 2);
  ctx.fillStyle = ocean;
  ctx.fill();

  const glint = ctx.createRadialGradient(cx - R*0.35, cy - R*0.35, 0, cx - R*0.3, cy - R*0.3, R*0.45);
  glint.addColorStop(0, 'rgba(255,200,200,0.07)');
  glint.addColorStop(1, 'rgba(255,200,200,0)');
  ctx.beginPath();
  ctx.arc(cx, cy, R, 0, Math.PI * 2);
  ctx.fillStyle = glint;
  ctx.fill();
}

// Change 4: atmosphere with shadowBlur for softer glow
function drawAtmosphere() {
  ctx.save();
  ctx.shadowColor = 'rgba(146,39,36,0.4)';
  ctx.shadowBlur  = 18;
  const atm = ctx.createRadialGradient(cx, cy, R * 0.88, cx, cy, R * 1.18);
  atm.addColorStop(0,   'rgba(146,39,36,0.35)');
  atm.addColorStop(0.5, 'rgba(146,39,36,0.10)');
  atm.addColorStop(1,   'rgba(146,39,36,0)');
  ctx.beginPath();
  ctx.arc(cx, cy, R * 1.18, 0, Math.PI * 2);
  ctx.fillStyle = atm;
  ctx.fill();
  ctx.restore(); // clear shadowBlur before limb darkening

  const limb = ctx.createRadialGradient(cx, cy, R * 0.75, cx, cy, R);
  limb.addColorStop(0, 'rgba(0,0,0,0)');
  limb.addColorStop(1, 'rgba(0,0,0,0.55)');
  ctx.beginPath();
  ctx.arc(cx, cy, R, 0, Math.PI * 2);
  ctx.fillStyle = limb;
  ctx.fill();
}

function drawGrid() {
  ctx.save();
  ctx.beginPath(); ctx.arc(cx, cy, R, 0, Math.PI*2); ctx.clip();
  ctx.strokeStyle = 'rgba(146,39,36,0.09)';
  ctx.lineWidth   = 0.5;

  for (let lat = -60; lat <= 60; lat += 30) {
    ctx.beginPath();
    let first = true;
    for (let lon = -180; lon <= 180; lon += 2) {
      const p = project(lat, lon);
      if (p.z > 0) { first ? ctx.moveTo(p.x, p.y) : ctx.lineTo(p.x, p.y); first = false; }
      else { first = true; }
    }
    ctx.stroke();
  }

  for (let lon = 0; lon < 360; lon += 30) {
    ctx.beginPath();
    let first = true;
    for (let lat = -90; lat <= 90; lat += 2) {
      const p = project(lat, lon);
      if (p.z > 0) { first ? ctx.moveTo(p.x, p.y) : ctx.lineTo(p.x, p.y); first = false; }
      else { first = true; }
    }
    ctx.stroke();
  }

  ctx.restore();
}

// Change 3: terminator interpolation — no more hard polygon breaks
function drawLand() {
  ctx.save();
  ctx.beginPath(); ctx.arc(cx, cy, R, 0, Math.PI*2); ctx.clip();

  for (const poly of LAND_SUB) {
    ctx.beginPath();
    const pts = poly.map(([lat, lon]) => project(lat, lon));
    const n   = pts.length;
    let started = false;

    for (let i = 0; i < n; i++) {
      const cur  = pts[i];
      const next = pts[(i + 1) % n];

      if (cur.z > 0) {
        if (!started) { ctx.moveTo(cur.x, cur.y); started = true; }
        else            ctx.lineTo(cur.x, cur.y);

        if (next.z <= 0) {
          // Crossing to back face: draw to exact limb point
          const t = cur.z / (cur.z - next.z);
          ctx.lineTo(cur.x + t * (next.x - cur.x), cur.y + t * (next.y - cur.y));
        }
      } else if (next.z > 0) {
        // Crossing to front face: start from exact limb point
        const t  = cur.z / (cur.z - next.z);
        const lx = cur.x + t * (next.x - cur.x);
        const ly = cur.y + t * (next.y - cur.y);
        if (!started) { ctx.moveTo(lx, ly); started = true; }
        else            ctx.lineTo(lx, ly);
      }
      // Both hidden: skip segment entirely
    }

    // Per-polygon radial gradient: brighter facing viewer, darker at limb
    const cx0 = pts.reduce((s, p) => s + p.x, 0) / n;
    const cy0 = pts.reduce((s, p) => s + p.y, 0) / n;
    const g   = ctx.createRadialGradient(cx0, cy0, 0, cx0, cy0, R * 0.6);
    g.addColorStop(0, 'rgba(180,55,50,0.38)');
    g.addColorStop(1, 'rgba(110,28,26,0.22)');

    ctx.closePath();
    ctx.fillStyle   = g;
    ctx.strokeStyle = 'rgba(210,70,65,0.70)';
    ctx.lineWidth   = 0.75;
    ctx.fill();
    ctx.stroke();
  }

  ctx.restore();
}

function drawConnections(elapsed) {
  ctx.save();
  ctx.beginPath(); ctx.arc(cx, cy, R * 1.02, 0, Math.PI*2); ctx.clip();

  for (const pair of activePairs) {
    const src = CITIES[pair.src];
    const tgt = CITIES[pair.tgt];
    const ps  = project(src.lat, src.lon);
    const pt  = project(tgt.lat, tgt.lon);
    if (ps.z <= 0 || pt.z <= 0) continue;

    const mx   = (ps.x + pt.x) / 2;
    const my   = (ps.y + pt.y) / 2;
    const dvx  = mx - cx, dvy = my - cy;
    const dlen = Math.sqrt(dvx*dvx + dvy*dvy) || 1;
    const pull = R * 0.55;
    const cpx  = mx + (dvx / dlen) * pull;
    const cpy  = my + (dvy / dlen) * pull;

    // Glow pass
    ctx.lineWidth   = 3;
    ctx.strokeStyle = RED_FAINT + '0.12)';
    ctx.setLineDash([]);
    ctx.beginPath();
    ctx.moveTo(ps.x, ps.y);
    ctx.quadraticCurveTo(cpx, cpy, pt.x, pt.y);
    ctx.stroke();

    // Animated dash
    ctx.lineWidth      = 1.2;
    ctx.strokeStyle    = RED_FAINT + '0.75)';
    ctx.setLineDash([5, 8]);
    ctx.lineDashOffset = -(elapsed * 0.04 + pair.offset);
    ctx.beginPath();
    ctx.moveTo(ps.x, ps.y);
    ctx.quadraticCurveTo(cpx, cpy, pt.x, pt.y);
    ctx.stroke();
  }

  ctx.setLineDash([]);
  ctx.restore();
}

function drawCities(elapsed) {
  const activeSet = new Set(activePairs.flatMap(p => [p.src, p.tgt]));

  for (let i = 0; i < CITIES.length; i++) {
    const c = CITIES[i];
    const p = project(c.lat, c.lon);
    if (p.z <= 0) continue;

    const active = activeSet.has(i);
    const dotR   = active ? 3.5 : 1.8;
    const pulse  = active ? 0.5 + 0.5 * Math.sin(elapsed * 0.004 + i) : 0;

    if (active) {
      for (let ring = 0; ring < 3; ring++) {
        const prog  = ((elapsed * 0.0006 + ring / 3 + i * 0.17) % 1);
        const rR    = dotR + prog * 22;
        const alpha = (1 - prog) * 0.5;
        ctx.beginPath();
        ctx.arc(p.x, p.y, rR, 0, Math.PI * 2);
        ctx.strokeStyle = RED_FAINT + alpha + ')';
        ctx.lineWidth   = 1;
        ctx.stroke();
      }

      const glow = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, 12 + pulse * 4);
      glow.addColorStop(0, RED_FAINT + '0.5)');
      glow.addColorStop(1, RED_FAINT + '0)');
      ctx.beginPath();
      ctx.arc(p.x, p.y, 12 + pulse * 4, 0, Math.PI * 2);
      ctx.fillStyle = glow;
      ctx.fill();
    }

    ctx.beginPath();
    ctx.arc(p.x, p.y, dotR + pulse, 0, Math.PI * 2);
    ctx.fillStyle = active ? RED_MID : 'rgba(146,39,36,0.55)';
    ctx.fill();
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Glass blocks
// ─────────────────────────────────────────────────────────────────────────────
function spawnGlassBlock() {
  const el   = document.createElement('div');
  const term = TERMS[Math.floor(Math.random() * TERMS.length)];
  const side = Math.floor(Math.random() * 4);
  const margin = 24;
  let left, top;

  switch (side) {
    case 0:
      left = margin + Math.random() * (W - 260);
      top  = margin + Math.random() * (H * 0.2);
      break;
    case 1:
      left = margin + Math.random() * (W - 260);
      top  = H * 0.78 + Math.random() * (H * 0.18);
      break;
    case 2:
      left = margin + Math.random() * (W * 0.15);
      top  = H * 0.2 + Math.random() * (H * 0.6);
      break;
    default:
      left = W * 0.78 + Math.random() * (W * 0.18);
      top  = H * 0.2 + Math.random() * (H * 0.6);
  }

  el.className    = 'glass-block';
  el.textContent  = term;
  el.style.left   = left + 'px';
  el.style.top    = top  + 'px';
  glassLayer.appendChild(el);

  const lifetime = 3500 + Math.random() * 3000;
  setTimeout(() => {
    el.classList.add('glass-block-out');
    setTimeout(() => el.remove(), 500);
  }, lifetime);
}

// ─────────────────────────────────────────────────────────────────────────────
// Active pairs management
// ─────────────────────────────────────────────────────────────────────────────
function refreshPairs() {
  const TARGET = 7;
  while (activePairs.length < TARGET) {
    const candidate = ALL_PAIRS[Math.floor(Math.random() * ALL_PAIRS.length)];
    const already   = activePairs.some(p => p.src === candidate[0] && p.tgt === candidate[1]);
    if (!already) {
      activePairs.push({ src: candidate[0], tgt: candidate[1], offset: Math.random() * 100 });
    }
  }
}

function rotatePairs() {
  if (activePairs.length > 0) {
    activePairs.splice(Math.floor(Math.random() * activePairs.length), 1);
  }
  refreshPairs();
}

// ─────────────────────────────────────────────────────────────────────────────
// Resize — Change 1: devicePixelRatio
// ─────────────────────────────────────────────────────────────────────────────
function resize() {
  const container = canvas.parentElement;
  const dpr = window.devicePixelRatio || 1;
  W = container.clientWidth;
  H = container.clientHeight;
  canvas.width  = Math.round(W * dpr);
  canvas.height = Math.round(H * dpr);
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0); // absolute — safe to call on every resize
  cx = W / 2;
  cy = H / 2;
  R  = Math.min(W, H) * 0.38;
}

// ─────────────────────────────────────────────────────────────────────────────
// Main loop
// ─────────────────────────────────────────────────────────────────────────────
function frame(ts) {
  if (!startTime) startTime = ts;
  const elapsed = ts - startTime;

  rotation = (elapsed * 0.003) % 360;

  ctx.clearRect(0, 0, W, H);

  drawAtmosphere();
  drawSphere();
  drawGrid();
  drawLand();
  drawConnections(elapsed);
  drawCities(elapsed);

  requestAnimationFrame(frame);
}

// ─────────────────────────────────────────────────────────────────────────────
// Boot
// ─────────────────────────────────────────────────────────────────────────────
function init() {
  canvas     = document.getElementById('globe-canvas');
  ctx        = canvas.getContext('2d');
  glassLayer = document.getElementById('glass-layer');

  // Change 2: pre-compute subdivided polygons once at startup
  LAND_SUB = LAND.map(poly => subdivide(poly, 1.0));
  ctx.imageSmoothingEnabled = true;
  ctx.imageSmoothingQuality = 'high';

  resize();
  window.addEventListener('resize', resize);

  refreshPairs();
  requestAnimationFrame(frame);

  function schedulePairRotation() {
    setTimeout(() => { rotatePairs(); schedulePairRotation(); }, 8000 + Math.random() * 6000);
  }
  schedulePairRotation();

  function scheduleGlass() {
    spawnGlassBlock();
    setTimeout(scheduleGlass, 1800 + Math.random() * 2200);
  }
  setTimeout(scheduleGlass, 800);

  const statEl = document.getElementById('globe-threat-count');
  if (statEl) {
    setInterval(() => {
      statEl.textContent = (120 + Math.floor(Math.random() * 80)).toLocaleString();
    }, 3000);
  }
}

document.addEventListener('DOMContentLoaded', init);
