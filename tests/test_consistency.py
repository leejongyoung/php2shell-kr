# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lee Jongyoung
"""Python 전체판과 POSIX sh 간이판이 같은 서버 트리에서 같은 판정을 내리는지 확인한다."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

CASES = [
    ("usr/bin/php", "8.4.26", "vulnerable"),
    ("usr/sbin/php-fpm8.4", "8.4.27", "fixed"),
    ("usr/local/bin/php-cgi", "8.3.35", "vulnerable"),
    ("usr/local/sbin/php-fpm", "8.2.36", "fixed"),
    ("opt/remi/php74/root/usr/bin/php", "7.4.33", "vulnerable"),
    ("opt/plesk/php/7.2/bin/php", "7.2.34", "vulnerable"),
]


def fake_php(path, version):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as handle:
        handle.write("#!/bin/sh\n[ \"$1\" = \"-n\" ] && shift\necho 'PHP %s (cli) (built: Oct  1 2026 00:00:00)'\n" % version)
    os.chmod(path, 0o755)


def rows(data):
    return sorted((os.path.basename(i["path"]), i["version"], i["class"], i["verdict"], i["sapi"]) for i in data["installations"])


@unittest.skipUnless(shutil.which("sh") and os.name == "posix", "POSIX sh 필요")
class PythonAndShellAgree(unittest.TestCase):
    def run_both(self, root, *extra):
        py = subprocess.run([sys.executable, os.path.join(ROOT, "php2shell_triage.py"), "--root", root, "--exec", "--json", "--no-response"] + list(extra),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        sh = subprocess.run(["sh", os.path.join(ROOT, "quickcheck", "php2shell-quickcheck.sh"), "--root", root, "--exec", "--json"] + list(extra),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        return py, sh

    def test_same_verdicts_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as root:
            for path, version, _ in CASES:
                fake_php(os.path.join(root, path), version)
            py, sh = self.run_both(root)
            self.assertEqual(py.returncode, 1)
            self.assertEqual(sh.returncode, 1, sh.stderr)
            self.assertEqual(rows(json.loads(py.stdout)), rows(json.loads(sh.stdout)))

    def test_all_fixed_exit_zero_in_both(self):
        with tempfile.TemporaryDirectory() as root:
            fake_php(os.path.join(root, "usr/bin/php"), "8.5.12")
            fake_php(os.path.join(root, "usr/sbin/php-fpm8.5"), "8.5.13")
            py, sh = self.run_both(root)
            self.assertEqual((py.returncode, sh.returncode), (0, 0), sh.stderr)
            self.assertEqual(rows(json.loads(py.stdout)), rows(json.loads(sh.stdout)))

    def test_empty_tree_exit_zero_in_both(self):
        with tempfile.TemporaryDirectory() as root:
            py, sh = self.run_both(root)
            self.assertEqual((py.returncode, sh.returncode), (0, 0), sh.stderr)
            self.assertEqual(json.loads(py.stdout)["installations"], [])
            self.assertEqual(json.loads(sh.stdout)["installations"], [])

    def test_no_exec_never_runs_binaries_in_either(self):
        with tempfile.TemporaryDirectory() as root:
            marker = os.path.join(root, "ran")
            path = os.path.join(root, "usr/bin/php")
            os.makedirs(os.path.dirname(path))
            with open(path, "w") as handle:
                handle.write("#!/bin/sh\ntouch %s\necho 'PHP 8.4.27'\n" % marker)
            os.chmod(path, 0o755)
            self.run_both(root, "--no-exec")
            self.assertFalse(os.path.exists(marker))


if __name__ == "__main__":
    unittest.main()
