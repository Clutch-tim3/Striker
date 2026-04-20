"""
Generates a plain-English analysis paragraph for a detected threat.
Runs in a daemon thread after antibody creation so it never blocks the pipeline.
"""

from python.core.logger import get_logger
from python.core.ipc_server import emit

logger = get_logger('threat_analyser')

_HIGH = 'high'
_MED  = 'medium'
_LOW  = 'low'

TEMPLATES = {
    'ransomware': {
        _HIGH: (
            "This is an active ransomware attack. The process is performing mass modification "
            "of sensitive files at an abnormal rate, consistent with file encryption behaviour "
            "seen in LockBit, WannaCry, and BlackCat. Every second of delay increases the number "
            "of files encrypted. Mahoraga has flagged the process — check for ransom notes and "
            "verify backup integrity before restoring."
        ),
        _MED: (
            "Suspicious file modification behaviour detected. A process is modifying sensitive "
            "files above the established baseline, consistent with early-stage ransomware. "
            "Verify whether this is legitimate backup or archiving software before taking action."
        ),
        _LOW: (
            "Mild anomaly in file modification patterns. Volume is slightly above baseline "
            "but does not yet meet the threshold for confirmed ransomware. Continue monitoring."
        ),
    },
    'c2_beacon': {
        _HIGH: (
            "A command-and-control beaconing pattern has been detected. A process is making "
            "regular outbound connections to an external IP on a port associated with malicious "
            "infrastructure — typical of Cobalt Strike or Meterpreter. The regularity of the "
            "connection intervals is the key indicator. The system may already be under attacker "
            "control; network isolation is recommended immediately."
        ),
        _MED: (
            "Suspicious outbound network behaviour detected. A process is making periodic "
            "connections to an external host on a non-standard port. This may indicate C2 "
            "beaconing. Verify the process origin and destination IP against threat intelligence."
        ),
        _LOW: (
            "Low-confidence network anomaly. Outbound connection on an unusual port detected. "
            "Could be legitimate application behaviour. Review the process before acting."
        ),
    },
    'keylogger': {
        _HIGH: (
            "A keylogger injection has been detected. A process has hooked into a system input "
            "API — the mechanism used by keyloggers to capture keystrokes in real time. This "
            "gives an attacker the ability to harvest passwords and credentials. All credentials "
            "entered on this system since the process started should be considered compromised."
        ),
        _MED: (
            "Suspicious API hook detected. The behaviour is consistent with keylogger activity "
            "— the process is accessing input-handling functions outside its normal baseline."
        ),
        _LOW: (
            "Minor anomaly in process API access. The deviation is within the range that could "
            "be explained by legitimate software. No action required at this time."
        ),
    },
    'privilege_escalation': {
        _HIGH: (
            "A privilege escalation attempt has been detected. A process is querying elevated "
            "privilege tokens and attempting to modify the local Administrators group. If "
            "successful, all security boundaries on this machine will be bypassed. The process "
            "must be terminated before the escalation completes."
        ),
        _MED: (
            "Suspicious privilege-related commands detected. A process is running commands "
            "associated with privilege enumeration. This may be legitimate admin activity or "
            "an early-stage escalation attempt."
        ),
        _LOW: (
            "Privilege-related command observed. The command alone is insufficient to confirm "
            "malicious intent — common in legitimate system administration."
        ),
    },
    'data_exfil': {
        _HIGH: (
            "Active data exfiltration detected. A large volume of data is being transferred "
            "outbound to an external IP in a pattern inconsistent with normal business "
            "operations. Combined with prior file access, this indicates an attacker is "
            "actively stealing data. Network isolation has been triggered."
        ),
        _MED: (
            "Abnormal outbound data transfer detected. The volume significantly exceeds the "
            "established baseline. This may indicate exfiltration or a large legitimate "
            "backup. Verify the destination and authorisation."
        ),
        _LOW: (
            "Elevated outbound traffic detected. Volume is above average but within a range "
            "explainable by software updates or cloud sync."
        ),
    },
    'rootkit': {
        _HIGH: (
            "A rootkit installation attempt has been detected. The process is modifying "
            "kernel-level files and attempting to hide itself from the process table — the "
            "defining behaviour of a rootkit. If successful it will persist across reboots "
            "and be invisible to standard tools. Isolate and restore from a clean backup."
        ),
        _MED: (
            "Suspicious kernel-level file modification detected. A process is writing to "
            "protected system directories consistent with rootkit installation."
        ),
        _LOW: (
            "Anomalous system file access detected. May be caused by legitimate maintenance "
            "tools. Verify before taking action."
        ),
    },
    'cryptominer': {
        _HIGH: (
            "A cryptominer has been detected. A process is consuming near-maximum CPU "
            "continuously and has an active connection to a known mining pool. Your hardware "
            "is being used to generate cryptocurrency for a third party. The process has been "
            "flagged — this also confirms an attacker has execution capability on this machine."
        ),
        _MED: (
            "Suspected cryptomining activity. Sustained abnormal CPU usage from an "
            "unrecognised process with external network connections."
        ),
        _LOW: (
            "High CPU usage from an unrecognised process. Could be legitimate computation. "
            "Review before acting."
        ),
    },
    'lolbin': {
        _HIGH: (
            "A Living-off-the-Land attack has been detected. A legitimate Windows binary "
            "(certutil, regsvr32, or similar) is being abused to download and execute a "
            "remote payload — specifically designed to evade traditional antivirus by using "
            "trusted system tools. Treat all files downloaded by this process as malicious."
        ),
        _MED: (
            "A system binary is being used in an unusual way consistent with LOLBin abuse. "
            "The command-line arguments indicate a download or remote execution attempt."
        ),
        _LOW: (
            "A system tool has been invoked with non-standard arguments. Low confidence of "
            "malicious intent — could be legitimate scripting."
        ),
    },
    'backdoor': {
        _HIGH: (
            "A backdoor installation has been detected. A process is downloading and executing "
            "a remote script — the standard mechanism for establishing persistent backdoor "
            "access. The pattern of fetching a remote shell script and piping it to a "
            "shell interpreter is one of the most common initial access techniques in Linux "
            "environments. Review all files created and check for cron jobs, systemd services, "
            "or SSH keys added during this session."
        ),
        _MED: (
            "Suspicious remote script execution. A process is fetching content from a remote "
            "URL and executing it in a shell — a common pattern for backdoor installation."
        ),
        _LOW: (
            "Remote script download detected. This pattern can be legitimate (software "
            "installation) but warrants review of the source URL and script content."
        ),
    },
    'unknown': {
        _HIGH: (
            "An unclassified critical-severity threat has been detected. The behavioural "
            "signals do not match a known pattern in Mahoraga's current model, which may "
            "indicate a novel or highly customised technique. This event has been archived "
            "as a new antibody and will improve future detection accuracy. Manual review "
            "of the process and its network activity is recommended."
        ),
        _MED: (
            "Anomalous behaviour detected that does not match a known attack pattern. "
            "The signals are suspicious but not yet classified. Logged for analysis."
        ),
        _LOW: (
            "Low-level anomaly detected. Behaviour deviates from baseline but does not "
            "meet threat thresholds. Logged for trend analysis."
        ),
    },
}


def _severity_band(severity: int) -> str:
    if severity >= 8:
        return _HIGH
    if severity >= 5:
        return _MED
    return _LOW


def generate_analysis(threat: dict, antibody: dict) -> str:
    attack_type = (threat.get('attack_type') or 'unknown').lower().replace(' ', '_')
    severity    = int(threat.get('severity', 0))
    band        = _severity_band(severity)

    bucket = TEMPLATES.get(attack_type, TEMPLATES['unknown'])
    text   = bucket.get(band, bucket.get(_HIGH, ''))

    if threat.get('similar_past'):
        text += (
            " A similar threat pattern was previously encountered and archived — "
            "pattern recognition accelerated classification."
        )

    mitre = threat.get('mitre_id', {})
    if isinstance(mitre, dict) and mitre.get('technique_id'):
        text += (
            f" This behaviour maps to MITRE ATT&CK {mitre['technique_id']}"
            f" ({mitre.get('technique_name', '')})."
        )

    return text.strip()


def emit_analysis(antibody_id: str, threat: dict, antibody: dict):
    """Generate analysis and emit to the renderer. Safe to call in a daemon thread."""
    try:
        analysis = generate_analysis(threat, antibody)
        emit('THREAT_ANALYSIS_READY', {
            'antibody_id': antibody_id,
            'analysis':    analysis,
        })
        logger.info(f'Analysis emitted for {antibody_id[:8]}')
    except Exception as e:
        logger.error(f'Analysis generation failed: {e}')
        emit('THREAT_ANALYSIS_READY', {
            'antibody_id': antibody_id,
            'analysis':    'Analysis could not be generated for this event.',
        })
