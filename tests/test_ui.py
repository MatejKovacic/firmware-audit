from __future__ import annotations

import json
import re
from pathlib import Path
import unittest

from jinja2 import Environment, FileSystemLoader



class SnapshotUiTests(unittest.TestCase):
    def render_index(self) -> str:
        report = json.loads(Path('sample/example-report.json').read_text(encoding='utf-8'))
        report['integrity_verification'] = {'valid': True}
        env = Environment(loader=FileSystemLoader('templates'))
        env.globals.update(
            url_for=lambda *args, **kwargs: '#',
            app_version='0.12.0',
            auth_enabled=True,
            get_flashed_messages=lambda **kwargs: [],
            format_duration_ms=lambda value: f'{int(value)//1000} s',
        )
        return env.get_template('index.html').render(report=report, scan_status={'state':'running','current_area':'Installed files and persistence','message':'Checking installed files','progress_percent':48,'log':[{'at':'now','area':'Installed files and persistence','message':'Checking installed files'}]}, upload_status={'enabled': True, 'available': True, 'destination': 'audit.telefoncek.si', 'message': ''}, upload_csrf='csrf-test')

    def test_collection_checks_remains_platform_neutral(self) -> None:
        text = Path("COLLECTION-CHECKS.md").read_text(encoding="utf-8").lower()
        for token in ("debian", "ubuntu", "fedora", "linux", "dpkg", "rpm", "systemd", "fwupd", "mokutil", "tpm2", "journalctl", "sysfs", "procfs"):
            self.assertNotIn(token, text)

    def test_dashboard_is_one_expanded_snapshot_table(self) -> None:
        html = self.render_index()
        self.assertIn('Current security snapshot', html)
        self.assertIn('expanded-assessment', html)
        self.assertIn('What to do', html)
        self.assertIn('What it means', html)
        self.assertIn('Security notes', html)
        self.assertNotIn('Recent reports', html)
        self.assertNotIn('Events and changes since the previous scan', html)
        self.assertNotIn('>Open<', html)
        self.assertIn('Scanning security areas', html)
        self.assertIn('Installed files and persistence', html)
        self.assertNotIn('confidence', html.lower())
        self.assertNotIn('configured evidence sources collected', html.lower())
        self.assertNotRegex(html.lower(), r'evidence\s+\d+\s*/\s*\d+')
        self.assertNotRegex(html.lower(), r'evidence\s+\d+%')
        self.assertIn('Upload report', html)
        self.assertIn('audit.telefoncek.si', html)
        self.assertIn('csrf-test', html)


if __name__ == '__main__':
    unittest.main()
