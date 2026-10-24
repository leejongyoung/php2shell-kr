# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
"""docs/output-format.ko.md 의 1.x 호환 약속: JSON 공통 필드, 열거 값, 종료 코드. 실제 CLI 를 실행해 확인한다."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PY = os.path.join(ROOT, "php2shell_kr.py")
SH = os.path.join(ROOT, "quickcheck", "php2shell-quickcheck.sh")
POSIX = unittest.skipIf(os.name == "nt", "POSIX 전용 픽스처")

TOP_FIELDS = {"tool", "as_of", "host", "platform", "installations", "summary", "exit_code"}
INSTALLATION_FIELDS = {"path", "version", "class", "verdict", "sapi", "running", "pids", "package", "vendor_patch", "needs_restart", "notes"}
SUMMARY_FIELDS = {"vulnerable", "fixed", "vendor_patched", "eol", "unknown", "needs_restart"}
CLASSES = {"fixed", "vulnerable", "eol_backport", "eol_no_fix", "old_unsupported", "unknown"}
VERDICTS = {"fixed", "vendor_patched", "vulnerable", "eol", "unknown"}
SAPIS = {"cli", "cgi", "fpm", "apache", "litespeed", "frankenphp", "unknown"}


def make_root(version):
    """버전 문자열만 든 가짜 php-fpm 이 있는 루트 트리(바이너리를 실행하지 않는 --root 경로)."""
    root = tempfile.mkdtemp()
    path = os.path.join(root, "usr", "sbin", "php-fpm")
    os.makedirs(os.path.dirname(path))
    marker = b"X-Powered-By: PHP/" + version.encode() + b"\0" if version else b"nothing to see\0"
    with open(path, "wb") as handle:
        handle.write(b"\x7fELF" + b"\0" * 8 + marker + b"\0" * 8)
    os.chmod(path, 0o755)
    return root


def run(command, root, *extra):
    result = subprocess.run([sys.executable if command == PY else "sh", command, "--root", root, "--json"] + list(extra),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode, json.loads(result.stdout.decode("utf-8"))      # 도구는 항상 UTF-8 로 출력한다(콘솔 코드 페이지와 무관)


class OutputContract(unittest.TestCase):
    def check_core(self, data, code):
        self.assertTrue(TOP_FIELDS <= set(data), TOP_FIELDS - set(data))
        self.assertTrue(SUMMARY_FIELDS <= set(data["summary"]))
        self.assertEqual(data["exit_code"], code)
        for item in data["installations"]:
            self.assertTrue(INSTALLATION_FIELDS <= set(item), INSTALLATION_FIELDS - set(item))
            self.assertIn(item["class"], CLASSES)
            self.assertIn(item["verdict"], VERDICTS)
            self.assertIn(item["sapi"], SAPIS)
            self.assertIn(item["vendor_patch"], ("yes", "no", "unknown"))
            self.assertIsInstance(item["running"], bool)
            self.assertIsInstance(item["pids"], list)
            self.assertIsInstance(item["notes"], list)

    @POSIX
    def test_exit_codes_and_core_fields_are_the_same_in_python_and_sh(self):
        # 취약 → 1, 수정됨 → 0, 버전을 읽지 못함 → 3, 설치 없음 → 0
        for version, code, verdict in (("8.4.26", 1, "vulnerable"), ("8.4.27", 0, "fixed"), (None, 3, "unknown")):
            root = make_root(version)
            self.addCleanup(shutil.rmtree, root, True)
            for command in (PY, SH):
                got_code, data = run(command, root, *(["--no-response"] if command == PY else []))
                self.assertEqual(got_code, code, (command, version))
                self.check_core(data, code)
                self.assertEqual([i["verdict"] for i in data["installations"]], [verdict], (command, version))
        empty = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, empty, True)
        for command in (PY, SH):
            got_code, data = run(command, empty)
            self.assertEqual((got_code, data["installations"]), (0, []), command)

    @POSIX
    def test_exit_code_2_when_the_output_file_cannot_be_written_and_nothing_is_overwritten(self):
        root = make_root("8.4.27")
        self.addCleanup(shutil.rmtree, root, True)
        with tempfile.NamedTemporaryFile("w", delete=False) as existing:
            existing.write("keep")
        self.addCleanup(os.unlink, existing.name)
        result = subprocess.run([sys.executable, PY, "--root", root, "--output", existing.name], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        self.assertEqual(result.returncode, 2)
        with open(existing.name) as handle:
            self.assertEqual(handle.read(), "keep")

    @POSIX
    def test_summary_counts_match_installations(self):
        root = make_root("8.4.26")
        self.addCleanup(shutil.rmtree, root, True)
        _, data = run(PY, root, "--no-response")
        counted = {key: sum(1 for i in data["installations"] if i["verdict"] == key) for key in ("vulnerable", "fixed", "vendor_patched", "eol", "unknown")}
        self.assertEqual({key: data["summary"][key] for key in counted}, counted)


if __name__ == "__main__":
    unittest.main()
