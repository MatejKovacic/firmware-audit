from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import uploader


class UploaderTests(unittest.TestCase):
    def make_report(self, path: Path) -> tuple[dict, str]:
        report = {
            "format": {"name": "firmware-audit-report", "version": 1},
            "report": {"id": "test-report"},
            "system": {"hostname": "test"},
            "results": {"overall": {"status": "good"}},
            "evidence": {"commands": {}, "artifacts": {}},
        }
        canonical = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        digest = hashlib.sha256(canonical).hexdigest()
        report["integrity"] = {
            "algorithm": "sha256",
            "scope": "canonical JSON excluding this integrity object",
            "digest": digest,
        }
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return report, digest

    def test_upload_url_requires_https_and_no_embedded_credentials(self) -> None:
        self.assertEqual(uploader.parse_upload_url("https://audit.telefoncek.si/api/v1/reports").hostname, "audit.telefoncek.si")
        with self.assertRaises(ValueError):
            uploader.parse_upload_url("http://audit.telefoncek.si/api/v1/reports")
        with self.assertRaises(ValueError):
            uploader.parse_upload_url("https://user:secret@audit.telefoncek.si/api/v1/reports")

    def test_report_integrity_is_verified_before_upload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "current.json")
            _, digest = self.make_report(path)
            raw, _, verified = uploader.load_and_verify_report(path)
            self.assertEqual(verified, digest)
            self.assertTrue(raw.endswith(b"\n"))
            data = json.loads(path.read_text())
            data["system"]["hostname"] = "changed"
            path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "integrity"):
                uploader.load_and_verify_report(path)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "current.json")
            path.write_text('{"format":{"name":"firmware-audit-report","version":1},"x":1,"x":2}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                uploader.load_and_verify_report(path)

    @patch("uploader.urllib.request.build_opener")
    def test_remote_upload_sends_no_credentials_and_exact_body(self, build_opener: Mock) -> None:
        response = Mock()
        response.status = 201
        response.read.return_value = b'{"status":"ok","digest":"abc","duplicate":false}'
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        opener = build_opener.return_value
        opener.open.return_value = response
        raw = b'{"example":1}\n'
        status, result = uploader.remote_upload(raw, "https://audit.telefoncek.si/api/v1/reports", 30)
        self.assertEqual(status, 201)
        self.assertEqual(result["status"], "ok")
        req = opener.open.call_args.args[0]
        self.assertEqual(req.data, raw)
        self.assertIsNone(req.get_header("Authorization"))
        self.assertEqual(req.get_header("Content-type"), "application/json")

    def test_destination_label_exposes_no_path(self) -> None:
        self.assertEqual(uploader.destination_label("https://audit.telefoncek.si/api/v1/reports"), "audit.telefoncek.si")

    def test_status_requires_only_enabled_https_url(self) -> None:
        source = Path("uploader.py").read_text(encoding="utf-8")
        self.assertNotIn("UPLOAD_KEY_FILE", source)
        self.assertNotIn("Bearer ", source)
        self.assertIn('"available": available', source)


if __name__ == "__main__":
    unittest.main()
