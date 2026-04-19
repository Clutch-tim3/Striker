"""
Generates human-readable insight for every detected threat across four dimensions:
  1. What the engine learned from this attack
  2. How Mahoraga adapted its models/antibodies
  3. How the antibody defends against future recurrence
  4. How this technique is used offensively (educational)
"""

OFFENSIVE_CONTEXT = {
    'ransomware': (
        "Ransomware operators typically deploy in three stages: initial access via phishing or "
        "RDP brute-force, privilege escalation to SYSTEM, then the encryption loop. Modern strains "
        "delete Volume Shadow Copies first (vssadmin delete shadows /all) to prevent recovery, then "
        "encrypt using AES-256 per-file keys wrapped in an attacker-controlled RSA public key. "
        "Speed is critical — LockBit 3.0 can encrypt 25,000 files/min. Operators target NAS shares "
        "and mapped drives before local files to maximise ransom leverage."
    ),
    'c2_beacon': (
        "C2 beaconing is the heartbeat of post-exploitation frameworks (Cobalt Strike, Sliver, "
        "Havoc). After initial compromise, the implant calls home on a jittered schedule (typically "
        "60s ± 30% jitter) to avoid time-series anomaly detection. Traffic is usually over HTTPS to "
        "blending-capable domains (domain fronting via CDNs like Cloudflare). Port 4444 is Metasploit "
        "default; 1337 is common in custom implants. Operators rotate C2 infrastructure every 24–72h "
        "to evade IP-based blocklists."
    ),
    'data_exfil': (
        "Data exfiltration operators stage data locally first (compression, encryption), then exfil "
        "over allowed protocols — HTTPS to cloud storage (Mega, Dropbox), DNS tunnelling, or ICMP "
        "covert channels. Large single transfers (>50 KB) to external IPs during business hours are "
        "a common pattern; so is slow-drip exfil (small packets, high frequency) to stay under DLP "
        "thresholds. Dual-extortion groups exfil before encrypting to apply additional ransom pressure."
    ),
    'privilege_escalation': (
        "Privilege escalation is the bridge between initial foothold and full domain compromise. "
        "Common paths: token impersonation (whoami /priv → SeImpersonatePrivilege → PrintSpoofer), "
        "UAC bypass (fodhelper, eventvwr), kernel exploits (PrintNightmare, EternalBlue), and "
        "credential dumping via LSASS (mimikatz sekurlsa::logonpasswords). Once SYSTEM is achieved, "
        "attackers dump the SAM/NTDS.dit for lateral movement via Pass-the-Hash."
    ),
    'rootkit': (
        "Kernel rootkits operate below the OS to hide processes, files, and network connections from "
        "standard tools. They hook SSDT (System Service Descriptor Table) or use DKOM (Direct Kernel "
        "Object Manipulation) to delink malicious processes from the active process list. Writable+executable "
        "memory regions (W^X violation) indicate shellcode injection or inline function hooking — a "
        "classic sign of a kernel implant establishing persistence before hiding itself."
    ),
    'cryptominer': (
        "Cryptominers hijack CPU/GPU cycles to mine Monero (XMR) — preferred for its untraceable "
        "transactions. Deployment vectors include: supply-chain compromise (npm packages, PyPI), "
        "container escape from misconfigured Kubernetes clusters, and Log4Shell-style RCE. xmrig is "
        "the most common open-source miner used in attacks. Operators throttle CPU usage to 50–70% "
        "to avoid detection, only pinning at 95%+ on idle machines or VMs."
    ),
    'keylogger': (
        "Keyloggers capture credentials before they reach the application layer, bypassing TLS. "
        "Kernel-mode keyloggers hook keyboard IRPs (I/O Request Packets) for undetectable capture. "
        "User-mode variants use SetWindowsHookEx or polling GetAsyncKeyState. Modern stealers "
        "(RedLine, Raccoon) combine keylogging with form-grabbing (hooking browser APIs) and "
        "clipboard hijacking for crypto wallet addresses."
    ),
    'backdoor': (
        "Backdoors establish covert persistence beyond standard autoruns. Techniques include: "
        "DLL search order hijacking (placing malicious DLLs in application directories), COM "
        "object hijacking (HKCU registry overrides), and Windows service creation. Advanced "
        "implants use WMI event subscriptions for fileless persistence — no binary on disk, "
        "payload lives in WMI repository and executes on triggers like logon or system idle."
    ),
    'worm': (
        "Network worms spread autonomously via exploitable services. EternalBlue (MS17-010) remains "
        "active 7 years after WannaCry. Modern worms scan for open ports (445, 22, 80, 8080) using "
        "masscan at 1M pkt/s, then exploit RCE vulnerabilities. Propagation is typically: exploit → "
        "download dropper → establish persistence → scan subnet → repeat. Worms often carry secondary "
        "payloads (ransomware, cryptominer) activated after propagation phase."
    ),
}

DEFENSIVE_PLAYBOOK = {
    'ransomware': (
        "The antibody monitors file modification velocity against the baseline established during "
        "normal operation. Triggers: (1) >15 file writes/sec to a single directory, (2) extension "
        "change to known ransomware suffixes (.locked, .encrypted, .crypt, .pay2me), (3) concurrent "
        "read+delete+write on sensitive paths. Auto-response at severity ≥ 8: process kill → "
        "file quarantine. Future variants are caught via the vector similarity search — any telemetry "
        "within 0.82 cosine similarity of this antibody will auto-escalate."
    ),
    'c2_beacon': (
        "The antibody encodes the beacon signature: destination port, packet cadence, and connection "
        "frequency. Future beacons to the same port range (4444, 1337, 6667, 8080) are scored higher "
        "by the anomaly model. The network sniffer watches for jittered periodic connections to "
        "non-browser processes. Defensive action: isolate network at severity ≥ 6 for known C2 "
        "attack types, preventing exfil and receiving further commands."
    ),
    'data_exfil': (
        "The antibody captures the outbound packet size signature and destination IP. The anomaly "
        "model now scores large single-session transfers to external IPs higher. Defensive posture: "
        "any packet_size > 50,000 bytes to a non-allowlisted IP triggers elevated scoring. "
        "Network isolation fires if attack_type confirms data_exfil at severity ≥ 6, cutting "
        "the exfil channel before the transfer completes."
    ),
    'privilege_escalation': (
        "The antibody captures the command-line pattern: whoami /priv, net localgroup, token "
        "manipulation syscalls. The heuristic engine flags any process executing this combination "
        "regardless of binary name — a renamed cmd.exe will still match. The vector index now "
        "has a reference point for privilege escalation telemetry; similar future attempts score "
        "above threshold immediately, triggering process kill before escalation completes."
    ),
    'rootkit': (
        "The antibody flags the W^X (writable + executable) memory region signature. Future "
        "processes allocating RWX memory regions are immediately elevated in the anomaly score. "
        "The heuristic fires on wx_memory_region events regardless of anomaly score, ensuring "
        "kernel-level threats are never filtered out by the ML threshold. At severity ≥ 6, "
        "the process is killed before the rootkit can complete its hook installation."
    ),
    'cryptominer': (
        "The antibody encodes the CPU spike signature (>90% sustained) combined with known miner "
        "binary names (xmrig, minerd, cpuminer). The anomaly model now treats sustained high-CPU "
        "processes on non-standard binaries as anomalous. The behaviour classifier, once retrained "
        "with this data point, will recognise the cryptominer resource profile directly without "
        "needing the binary name to match."
    ),
    'keylogger': (
        "The antibody records the process behaviour: high input-monitoring API calls with low "
        "CPU and no visible window. The heuristic engine flags processes using SetWindowsHookEx "
        "or polling keyboard state without a foreground window. The vector index similarity "
        "search will catch renamed keyloggers that share the same behavioural fingerprint "
        "even without matching binary names or signatures."
    ),
    'backdoor': (
        "The antibody captures the persistence mechanism signature. The file watcher monitors "
        "for DLL drops in application directories and registry key writes to Run/RunOnce. "
        "The process monitor flags new services created outside of known installer contexts. "
        "Future backdoor installations with similar telemetry patterns auto-match this antibody "
        "and are quarantined before execution."
    ),
    'worm': (
        "The antibody encodes the lateral movement signature: rapid outbound connection attempts "
        "to subnet peers on exploit-common ports. The network sniffer now scores port-scanning "
        "patterns higher. The isolation response fires automatically for worm-classified threats "
        "to contain spread — network isolation prevents the infected host from reaching other "
        "machines while investigation proceeds."
    ),
}


def generate(threat: dict, antibody: dict, response_taken: list) -> dict:
    attack_type = threat.get('attack_type') or 'unknown'
    telemetry = threat.get('telemetry', {})
    anomaly_score = threat.get('anomaly_score', 0.0)
    mitre = threat.get('mitre_id', {})
    severity = threat.get('severity', 0)
    ab_id = antibody.get('id', '')[:8]

    # ── WHAT WE LEARNED ─────────────────────────────────────────────────────
    detection_signals = []
    if anomaly_score > 0.75:
        detection_signals.append(
            f"anomaly model flagged a score of {anomaly_score:.2f} — "
            f"{int(anomaly_score * 100)}% deviation from the established baseline"
        )
    if telemetry.get('event') in ('mass_file_modification', 'ransomware_extension_detected',
                                   'high_risk_process', 'wx_memory_region', 'beacon_pattern',
                                   'suspicious_port_connection', 'resource_spike'):
        detection_signals.append(
            f"zero-day heuristic matched on event type '{telemetry.get('event')}'"
        )

    source_detail = ''
    if telemetry.get('source') == 'file':
        count = telemetry.get('count', '')
        fp = telemetry.get('file_path', '')
        source_detail = f" targeting {count} files" if count else (f" at {fp}" if fp else '')
    elif telemetry.get('source') == 'network':
        ip = telemetry.get('dest_ip', '')
        port = telemetry.get('dest_port', '')
        source_detail = f" to {ip}:{port}" if ip else (f" on port {port}" if port else '')
    elif telemetry.get('source') == 'process':
        name = telemetry.get('name', '')
        pid = telemetry.get('pid', '')
        source_detail = f" via {name} (PID {pid})" if name and pid else ''

    signal_text = ' and '.join(detection_signals) if detection_signals else \
        "behavioural pattern matched against known attack signatures"

    learned = (
        f"Mahoraga identified this as a {attack_type.replace('_', ' ')} attack{source_detail}. "
        f"Detection was triggered by {signal_text}. "
        f"Severity was scored at {severity}/10 using weighted analysis of anomaly score, "
        f"telemetry context, and MITRE technique {mitre.get('technique_id', 'classification')} "
        f"({mitre.get('technique_name', attack_type)}). "
        f"{'The vector index found a similar past antibody — pattern recognition accelerated classification.' if threat.get('similar_past') else 'No prior antibody matched — this is a new pattern being indexed for the first time.'}"
    )

    # ── HOW IT ADAPTED ──────────────────────────────────────────────────────
    response_text = (
        ', '.join(r.replace('_', ' ').title() for r in response_taken)
        if response_taken else 'threat logged and flagged for review'
    )
    adapted = (
        f"Antibody {ab_id} was created and written to the SQLite archive. "
        f"The threat telemetry vector was added to the FAISS index — future attacks within "
        f"0.82 cosine similarity of this signature will auto-match without waiting for heuristics. "
        f"The isolation forest training buffer absorbed this data point; once the buffer reaches "
        f"500 samples it will retrain online, tightening the anomaly boundary around this attack class. "
        f"Immediate response taken: {response_text}."
    )

    # ── DEFENSIVE APPLICATION ────────────────────────────────────────────────
    defensive = DEFENSIVE_PLAYBOOK.get(
        attack_type,
        (
            f"The antibody encoding this {attack_type.replace('_', ' ')} pattern is now active in the "
            f"vector index. Future telemetry matching this signature within threshold will be "
            f"auto-classified and responded to without requiring heuristic confirmation."
        )
    )

    # ── OFFENSIVE CONTEXT ────────────────────────────────────────────────────
    offensive = OFFENSIVE_CONTEXT.get(
        attack_type,
        (
            f"This attack technique ({mitre.get('technique_id', attack_type)}) is used by threat "
            f"actors to compromise target systems. Understanding the offensive methodology enables "
            f"Mahoraga to anticipate follow-on actions and pre-position defensive responses."
        )
    )

    return {
        'learned':   learned,
        'adapted':   adapted,
        'defensive': defensive,
        'offensive': offensive,
    }
