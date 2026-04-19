import json
import os
from datetime import datetime, timezone
from python.core.logger import get_logger

logger = get_logger('remediation_report')

REPORTS_DIR = os.path.expanduser('~/.mahoraga/reports')


class RemediationReport:
    def generate(self, threat: dict, response_taken: list) -> str:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        now = datetime.now(timezone.utc)
        ts = now.strftime('%Y%m%d_%H%M%S')
        filename = f'report_{ts}.txt'
        path = os.path.join(REPORTS_DIR, filename)

        t = threat.get('telemetry', {})
        mitre = threat.get('mitre_id', {})

        lines = [
            '=' * 60,
            'MAHORAGA INCIDENT REPORT',
            f'Generated: {now.isoformat()}',
            '=' * 60,
            '',
            f'Attack Type:   {threat.get("attack_type", "unknown").upper()}',
            f'Severity:      {threat.get("severity", 0)}/10',
            f'Anomaly Score: {threat.get("anomaly_score", 0):.2%}',
            '',
            'MITRE ATT&CK:',
            f'  Technique ID:   {mitre.get("technique_id", "—")}',
            f'  Technique Name: {mitre.get("technique_name", "—")}',
            f'  Reference:      {mitre.get("url", "—")}',
            '',
            'TELEMETRY:',
            f'  Source:    {t.get("source", "—")}',
            f'  Event:     {t.get("event", "—")}',
            f'  PID:       {t.get("pid", "—")}',
            f'  Process:   {t.get("name", "—")}',
            f'  File:      {t.get("file_path", "—")}',
            '',
            'RESPONSE ACTIONS TAKEN:',
        ]
        if response_taken:
            for action in response_taken:
                lines.append(f'  ✓ {action}')
        else:
            lines.append('  — No automatic action (severity below threshold)')

        lines += ['', '=' * 60]

        with open(path, 'w') as f:
            f.write('\n'.join(lines))

        logger.info(f'Remediation report saved: {path}')
        return path
