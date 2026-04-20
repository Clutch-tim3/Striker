"""
Attack module definitions for the in-app sandbox competition.
These are simulators — they do not execute real malicious code.
"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class AttackModule:
    id:           str
    name:         str
    description:  str
    technique:    str
    mitre_id:     str
    difficulty:   str          # easy / medium / hard / expert
    duration_sec: int
    target_os:    List[str]
    points:       int


ATTACK_MODULES = [
    AttackModule(
        id='ransomware_sim',
        name='Ransomware Simulation',
        description='Mass file encryption — rapid modification of sensitive files, '
                    'typical of WannaCry or LockBit.',
        technique='Data Encrypted for Impact',
        mitre_id='T1486',
        difficulty='medium',
        duration_sec=30,
        target_os=['windows', 'linux'],
        points=300,
    ),
    AttackModule(
        id='c2_beacon_sim',
        name='C2 Beacon',
        description='Regular outbound packets to a suspicious port — mimics '
                    'Cobalt Strike or Empire C2 beaconing.',
        technique='Application Layer Protocol',
        mitre_id='T1071',
        difficulty='hard',
        duration_sec=30,
        target_os=['all'],
        points=500,
    ),
    AttackModule(
        id='keylogger_sim',
        name='Keylogger Injection',
        description='Process injection into explorer.exe hooking keyboard APIs — '
                    'high connection count and memory writes.',
        technique='Input Capture',
        mitre_id='T1056',
        difficulty='easy',
        duration_sec=20,
        target_os=['windows'],
        points=200,
    ),
    AttackModule(
        id='privesc_sim',
        name='Privilege Escalation',
        description='LOLBin commands (whoami /priv, net localgroup) and token '
                    'impersonation attempts.',
        technique='Exploitation for Privilege Escalation',
        mitre_id='T1068',
        difficulty='hard',
        duration_sec=25,
        target_os=['windows'],
        points=400,
    ),
    AttackModule(
        id='data_exfil_sim',
        name='Data Exfiltration',
        description='Large outbound network transfers to an unusual destination '
                    'combined with mass file reads.',
        technique='Exfiltration Over C2 Channel',
        mitre_id='T1041',
        difficulty='expert',
        duration_sec=45,
        target_os=['all'],
        points=600,
    ),
    AttackModule(
        id='rootkit_sim',
        name='Rootkit Persistence',
        description='Process hiding, system directory modification, and suspicious '
                    'kernel module or service creation.',
        technique='Rootkit',
        mitre_id='T1014',
        difficulty='expert',
        duration_sec=40,
        target_os=['linux', 'windows'],
        points=700,
    ),
    AttackModule(
        id='lolbin_sim',
        name='Living off the Land',
        description='certutil downloading a payload, bitsadmin transferring data, '
                    'regsvr32 executing a remote script.',
        technique='Signed Binary Proxy Execution',
        mitre_id='T1218',
        difficulty='medium',
        duration_sec=20,
        target_os=['windows'],
        points=350,
    ),
    AttackModule(
        id='cryptominer_sim',
        name='Cryptominer',
        description='Sustained high CPU from an unexpected process with outbound '
                    'connections to known mining pool ports.',
        technique='Resource Hijacking',
        mitre_id='T1496',
        difficulty='easy',
        duration_sec=30,
        target_os=['all'],
        points=150,
    ),
]

MODULES_BY_ID = {m.id: m for m in ATTACK_MODULES}

TARGET_MODULES = {
    'WIN-SRV-01': ['ransomware_sim', 'privesc_sim', 'lolbin_sim', 'c2_beacon_sim'],
    'UBN-WEB-03': ['c2_beacon_sim', 'rootkit_sim', 'data_exfil_sim', 'cryptominer_sim'],
    'MAC-DEV-07': ['keylogger_sim', 'cryptominer_sim', 'c2_beacon_sim'],
    'WIN-DC-01':  ['privesc_sim', 'c2_beacon_sim', 'data_exfil_sim',
                   'rootkit_sim', 'ransomware_sim', 'lolbin_sim'],
}
