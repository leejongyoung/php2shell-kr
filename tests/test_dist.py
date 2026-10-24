# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lee Jongyoung
"""배포 묶음(단일 .bat / .sh / .ps1, 체크섬) 검증."""
import hashlib
import json
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
import php2shell_kr  # noqa: E402


class DistBundle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out = tempfile.mkdtemp()
        build_dist.main(["--out", cls.out])
        cls.dir = os.path.join(cls.out, "php2shell-kr-%s" % php2shell_kr.__version__)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.out, ignore_errors=True)

    def test_expected_files_and_archives(self):
        for name in ("php2shell-quickcheck.sh", "php2shell-quickcheck.bat", "php2shell-quickcheck.ps1", "php2shell_kr.py",
                     "LICENSE", "NOTICE", "SHA256SUMS", "data/advisory.json", "virtual-patch/README.ko.md"):
            self.assertTrue(os.path.isfile(os.path.join(self.dir, name)), name)
        base = "php2shell-kr-%s" % php2shell_kr.__version__
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
        self.assertIn(b"%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", header)
        self.assertIn(b"[scriptblock]::Create", header)
        self.assertIn(b"P2S_NOPAUSE", header)
        self.assertNotIn(b"where powershell", header.lower())
        self.assertNotIn(b"P2S_TMP", header)
        self.assertNotIn(b"WriteAllText", header)
        self.assertNotIn(b"%TEMP%", header)
        self.assertNotIn(b"%RANDOM%", header)

    @staticmethod
    def _powershell_host():
        host = os.environ.get("P2S_TEST_PWSH") or shutil.which("pwsh")
        if not host and os.name == "nt":
            candidate = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32",
                                     "WindowsPowerShell", "v1.0", "powershell.exe")
            if os.path.isfile(candidate):
                host = candidate
        return host

    @staticmethod
    def _run_host(host, command, env):
        # 출력은 UTF-8 로 명시해 읽는다(Windows 시스템 코드 페이지 cp1252/cp949 로 해석하면 디코드 오류).
        return subprocess.run([host, "-NoProfile", "-Command", command], env=env,
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              encoding="utf-8", errors="replace", timeout=60)

    @unittest.skipUnless(os.environ.get("P2S_TEST_PWSH") or shutil.which("pwsh") or os.name == "nt",
                         "PowerShell 필요(pwsh, P2S_TEST_PWSH 또는 Windows PowerShell)")
    def test_in_memory_launcher_command_and_argument_binding(self):
        """실제 .bat의 -Command를 PowerShell에서 실행: 임시 파일 없음, 값을 코드로 평가하지 않음."""
        host = self._powershell_host()
        if not host:
            self.skipTest("PowerShell 실행 파일을 찾을 수 없음")
        command = next(line for line in build_dist.BAT_HEADER.splitlines()
                       if line.startswith('"%P2S_HOST%"'))
        command = command.split(' -Command "', 1)[1][:-1].replace("%%", "%")
        bat = os.path.join(self.dir, "php2shell-quickcheck.bat")
        env = dict(os.environ, P2S_SELF=bat, P2S_NOPAUSE="1")
        env.pop("PHP2SHELL_TEST_VERSION_FILE", None)
        env["P2S_ARGS"] = "-Classify 8.4.26"
        proc = self._run_host(host, command, env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), "vulnerable", proc.stderr)
        with tempfile.TemporaryDirectory(prefix="p2s launcher ") as root:
            php = os.path.join(root, "php")
            os.mkdir(php)
            with open(os.path.join(php, "php.exe"), "wb") as handle:
                handle.write(b"X-Powered-By: PHP/8.4.26\0")
            plan = os.path.join(root, "review plan.ps1")
            env["P2S_ARGS"] = '-Json -NoExec -Offline -Root "%s" -PlanFile "%s"' % (root, plan)
            proc = self._run_host(host, command, env)
            self.assertEqual(proc.returncode, 1, proc.stderr)
            self.assertTrue(proc.stdout, proc.stderr)
            result = json.loads(proc.stdout.lstrip("\ufeff"))
            self.assertEqual(result["exit_code"], 1)
            self.assertEqual(result["plan_file"], plan)
            self.assertTrue(os.path.isfile(plan))
            env["P2S_ARGS"] = '-Json -NoExec -Root "%s" -PlanFile "%s"' % (root, plan)
            again = self._run_host(host, command, env)
            self.assertEqual(again.returncode, 2, again.stderr)
        env["P2S_ARGS"] = "-Unknown"
        bad = self._run_host(host, command, env)
        self.assertEqual(bad.returncode, 2)

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
        cmd = os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe")
        env = dict(os.environ, P2S_NOPAUSE="1")
        with tempfile.TemporaryDirectory() as untrusted:
            # cwd/PATH의 가짜 호스트를 절대 경로 호출이 선택하지 않음.
            with open(os.path.join(untrusted, "powershell.exe"), "wb") as handle:
                handle.write(b"not a trusted executable")
            env["PATH"] = untrusted + os.pathsep + env.get("PATH", "")
            proc = subprocess.run([cmd, "/c", bat, "-Classify", "8.4.26"], env=env, cwd=untrusted,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout.strip().splitlines()[-1], "vulnerable", proc.stderr)
            proc = subprocess.run([cmd, "/c", bat, "-Classify", "8.4.27"], env=env, cwd=untrusted,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout.strip().splitlines()[-1], "fixed", proc.stderr)


if __name__ == "__main__":
    unittest.main()
