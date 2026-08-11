from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

try:
    import flask  # noqa: F401
except ImportError:
    webapp = None
else:
    import app as webapp


@unittest.skipIf(webapp is None, "Flask is not installed in the source-test environment")
class WebUploadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.report_dir = root / "reports"
        self.report_dir.mkdir()
        self.csrf = root / "csrf.key"
        self.csrf.write_bytes(b"x" * 32)
        report = {
            "format": {"name": "firmware-audit-report", "version": 1},
            "report": {"id": "test-report", "scope": "full", "timing": {}, "requested_areas": []},
            "system": {"hostname": "test"},
            "results": {"overall": {"status": "good", "coverage": {"status": "complete"}}, "areas": [], "findings": [], "security_notes": []},
            "evidence": {"commands": {}, "artifacts": {}},
        }
        canonical = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        self.digest = hashlib.sha256(canonical).hexdigest()
        report["integrity"] = {"algorithm": "sha256", "digest": self.digest, "scope": "canonical JSON excluding this integrity object"}
        (self.report_dir / "current.json").write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
        webapp.app.config.update(
            TESTING=True,
            REPORT_DIR=self.report_dir,
            STATUS_FILE=root / "status.json",
            WEB_USERNAME="",
            WEB_PASSWORD_HASH="",
            UPLOAD_ENABLED=True,
            UPLOAD_SOCKET=str(root / "uploader.sock"),
            CSRF_SECRET_FILE=self.csrf,
        )
        self.client = webapp.app.test_client()

    def test_invalid_csrf_is_rejected_before_uploader(self) -> None:
        with patch.object(webapp, "uploader_request") as uploader_request:
            response = self.client.post("/upload", data={"csrf_token": "bad"})
        self.assertEqual(response.status_code, 403)
        uploader_request.assert_not_called()

    def test_valid_manual_upload_uses_local_helper(self) -> None:
        token = webapp.upload_csrf_token(self.digest)
        with patch.object(webapp, "uploader_request", return_value=(200, {
            "status": "ok",
            "digest": self.digest,
            "report_id": "test-report",
            "duplicate": False,
            "destination": "audit.telefoncek.si",
        })) as uploader_request:
            response = self.client.post("/upload", data={"csrf_token": token})
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["status"], "ok")
        self.assertIn("uploaded successfully", payload["message"].lower())
        uploader_request.assert_called_once_with("POST", "/upload-current", {"digest": self.digest})


if __name__ == "__main__":
    unittest.main()
