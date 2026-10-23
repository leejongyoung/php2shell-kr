# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lee Jongyoung
"""배포 묶음(단일 .bat / .sh / .ps1, 체크섬) 검증."""
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.path.insert(0, ROOT)

import build_dist  # noqa: E402
import php2shell_triage  # noqa: E402


class DistBundle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out = tempfile.mkdtemp()
        build_dist.main(["--out", cls.out])
        cls.dir = os.path.join(cls.out, "php2shell-triage-%s" % php2shell_triage.__version__)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.out, ignore_errors=True)

    def test_expected_files_and_archives(self):
        for name in ("php2shell-quickcheck.sh", "php2shell-quickcheck.bat", "php2shell-quickcheck.ps1", "php2shell_triage.py",
                     "LICENSE", "NOTICE", "SHA256SUMS", "data/advisory.json", "virtual-patch/README.ko.md"):
            self.assertTrue(os.path.isfile(os.path.join(self.dir, name)), name)
        base = "php2shell-triage-%s" % php2shell_triage.__version__
        self.assertTrue(os.path.isfile(os.path.join(self.out, base + ".zip")))
        self.assertTrue(os.path.isfile(os.path.join(self.out, base + ".tar.gz")))

    def test_checksums_match_every_file(self):
        with open(os.path.join(self.dir, "SHA256SUMS"), encoding="utf-8") as handle:
            lines = [line.rstrip("\n") for line in handle if line.strip()]
        self.assertGreater(len(lines), 10)
        for line in lines:
            digest, _, rel = line.partition("  ")
            with open(os.path.join(self.dir, rel), "rb") as data:
                self.assertEqual(hashlib.sha256(data.read()).hexdigest(), digest, rel)

    def test_bat_is_a_faithful_single_file_launcher(self):
        with open(os.path.join(self.dir, "php2shell-quickcheck.bat"), "rb") as handle:
            raw = handle.read()
        marker = (build_dist.MARKER + "\r\n").encode("ascii")
        self.assertEqual(raw.count(b"\r\n" + build_dist.MARKER.encode("ascii") + b"\r\n") + (1 if raw.startswith(marker) else 0), 1)
        header, payload = raw.split(b"\r\n" + build_dist.MARKER.encode("ascii") + b"\r\n", 1)
        header.decode("ascii")  # 헤더는 ASCII 전용이어야 한다 (cmd.exe 코드 페이지 문제 방지)
        self.assertNotIn(b"\n", header.replace(b"\r\n", b""))  # 모든 줄바꿈이 CRLF
        with open(os.path.join(ROOT, "quickcheck", "php2shell-quickcheck.ps1"), "rb") as handle:
            source = handle.read()
        if source.startswith(b"\xef\xbb\xbf"):
            source = source[3:]
        self.assertEqual(payload.decode("utf-8").replace("\r\n", "\n"), source.decode("utf-8").replace("\r\n", "\n"))
        self.assertIn(b"-ExecutionPolicy Bypass", header)
        self.assertIn(b"exit /b %P2S_RC%", header)

    @unittest.skipUnless(shutil.which("sh") and os.name == "posix", "POSIX sh 필요")
    def test_sh_is_valid_and_standalone(self):
        script = os.path.join(self.dir, "php2shell-quickcheck.sh")
        self.assertEqual(subprocess.call(["sh", "-n", script]), 0)
        with tempfile.TemporaryDirectory() as lone:  # 다른 파일 없이 혼자 실행
            lone_script = os.path.join(lone, "q.sh")
            shutil.copyfile(script, lone_script)
            proc = subprocess.run(["sh", lone_script, "--classify", "8.4.27"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            self.assertEqual(proc.stdout.strip(), "fixed", proc.stderr)

    @unittest.skipUnless(os.name == "nt", "Windows 전용: 실제 cmd.exe 로 .bat 실행")
    def test_bat_runs_on_windows(self):
        bat = os.path.join(self.dir, "php2shell-quickcheck.bat")
        proc = subprocess.run(["cmd.exe", "/c", bat, "-Classify", "8.4.26"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        self.assertEqual(proc.stdout.strip().splitlines()[-1], "vulnerable", proc.stderr)
        proc = subprocess.run(["cmd.exe", "/c", bat, "-Classify", "8.4.27"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        self.assertEqual(proc.stdout.strip().splitlines()[-1], "fixed", proc.stderr)


if __name__ == "__main__":
    unittest.main()
