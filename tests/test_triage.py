# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lee Jongyoung
"""php2shell_triage 단위 테스트 (표준 라이브러리 unittest, Python 3.6+)."""
import gzip
import copy
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import php2shell_triage as triage  # noqa: E402

ADVISORY = triage.load_advisory()
POSIX = unittest.skipIf(os.name == "nt", "POSIX 전용 픽스처(셸 스크립트 실행)")


def write(path, text, mode=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    if mode:
        os.chmod(path, mode)


def fake_php(path, version, sapi_flag="cli"):
    script = "#!/bin/sh\n[ \"$1\" = \"-n\" ] && shift\necho 'PHP %s (%s) (built: Oct  1 2026 00:00:00)'\n" % (version, sapi_flag)
    write(path, script, 0o755)


class VersionVectors(unittest.TestCase):
    def test_every_shared_vector(self):
        with open(os.path.join(HERE, "vectors", "versions.json"), encoding="utf-8") as handle:
            cases = json.load(handle)["cases"]
        for case in cases:
            self.assertEqual(triage.classify(case["version"], ADVISORY), case["class"], case["version"])

    def test_embedded_advisory_matches_data_file(self):
        code = subprocess.call([sys.executable, os.path.join(ROOT, "tools", "sync_embedded_advisory.py"), "--check"])
        self.assertEqual(code, 0)

    def test_sync_check_accepts_crlf_checkout(self):
        # Windows autocrlf 체크아웃을 흉내: 소스와 권고 데이터를 CRLF 로 복사해 --check 가 통과해야 한다.
        with tempfile.TemporaryDirectory() as tmp:
            for rel in ("php2shell_triage.py", os.path.join("tools", "sync_embedded_advisory.py"), os.path.join("data", "advisory.json")):
                os.makedirs(os.path.dirname(os.path.join(tmp, rel)), exist_ok=True)
                with open(os.path.join(ROOT, rel), "rb") as handle:
                    data = handle.read().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
                with open(os.path.join(tmp, rel), "wb") as handle:
                    handle.write(data)
            code = subprocess.call([sys.executable, os.path.join(tmp, "tools", "sync_embedded_advisory.py"), "--check"])
            self.assertEqual(code, 0)

    def test_verdict_depends_on_vendor_evidence_only_for_affected_classes(self):
        self.assertEqual(triage.verdict_for("fixed", "no"), "fixed")
        self.assertEqual(triage.verdict_for("vulnerable", "yes"), "vendor_patched")
        self.assertEqual(triage.verdict_for("vulnerable", "unknown"), "vulnerable")
        self.assertEqual(triage.verdict_for("eol_backport", "yes"), "vendor_patched")
        self.assertEqual(triage.verdict_for("eol_no_fix", "no"), "vulnerable")
        self.assertEqual(triage.verdict_for("old_unsupported", "unknown"), "eol")


class VendorEvidence(unittest.TestCase):
    def test_needs_both_cves(self):
        both = "php8.4 (8.4.26-1+deb12u2) stable; urgency=high\n * Fix CVE-2026-109618, CVE-2026-109619\n"
        one = both.replace(", CVE-2026-109619", "")
        self.assertEqual(triage.has_vendor_evidence(both, ADVISORY), "yes")
        self.assertEqual(triage.has_vendor_evidence(one, ADVISORY), "no")
        self.assertEqual(triage.has_vendor_evidence(None, ADVISORY), "unknown")

    def test_debian_changelog_is_read_from_root(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "usr/share/doc/php8.4-fpm/changelog.Debian.gz")
            os.makedirs(os.path.dirname(path))
            with gzip.open(path, "wt", encoding="utf-8") as handle:
                handle.write("php8.4 (8.4.26-1+deb12u2) bookworm-security; urgency=high\n * CVE-2026-109618 CVE-2026-109619\n")
            text = triage.vendor_changelog("apt", "php8.4-fpm", root)
            self.assertEqual(triage.has_vendor_evidence(text, ADVISORY), "yes")
            self.assertIsNone(triage.vendor_changelog("apt", "php8.3-fpm", root))


class ConfigParsing(unittest.TestCase):
    def test_ini_flags_and_sizes(self):
        parsed = triage.parse_ini("; c\nsession.upload_progress.enabled = Off\nmemory_limit = 256M ; x\n[PHP]\npost_max_size=8M\n", "php.ini")
        self.assertEqual(parsed["session.upload_progress.enabled"][0], "0")
        self.assertEqual(parsed["memory_limit"][0], "256M")
        self.assertEqual(triage.size_bytes("8M"), 8 * 1024 * 1024)
        self.assertEqual(triage.size_bytes("-1"), -1)
        self.assertIsNone(triage.size_bytes("lots"))

    def test_pool_and_apache_admin_flags(self):
        pool = triage.parse_pool_or_vhost(
            "php_admin_value[memory_limit] = -1\nphp_value[post_max_size] = 8M\n;php_admin_flag[session.auto_start] = off\n", "pool.conf")
        self.assertEqual(pool["memory_limit"], ("-1", "pool.conf", True))
        self.assertFalse(pool["post_max_size"][2])
        self.assertNotIn("session.auto_start", pool)
        apache = triage.parse_pool_or_vhost("php_admin_flag session.upload_progress.enabled off\n", "a.conf", apache=True)
        self.assertEqual(apache["session.upload_progress.enabled"], ("0", "a.conf", True))

    def test_mitigation_status_levels(self):
        with tempfile.TemporaryDirectory() as root:
            ini = os.path.join(root, "php.ini")
            pool = os.path.join(root, "pool.conf")
            write(ini, "memory_limit = 128M\n")
            write(pool, "")
            none = triage.evaluate_config("fpm", "8.4", {"ini": [ini], "pool": [pool]})
            self.assertEqual(none["status"], "none")
            write(ini, "session.upload_progress.enabled = 0\n")
            partial = triage.evaluate_config("fpm", "8.4", {"ini": [ini], "pool": [pool]})
            self.assertEqual(partial["status"], "partial")
            write(pool, "php_admin_value[memory_limit] = -1\n")
            full = triage.evaluate_config("fpm", "8.4", {"ini": [ini], "pool": [pool]})
            self.assertEqual(full["status"], "interim")
            # memory_limit=-1 set only in php.ini is not admin-locked -> not counted
            write(pool, "")
            write(ini, "session.upload_progress.enabled = 0\nmemory_limit = -1\n")
            unlocked = triage.evaluate_config("fpm", "8.4", {"ini": [ini], "pool": [pool]})
            self.assertEqual(unlocked["status"], "partial")
            self.assertTrue(any("고정되지 않아" in note for note in unlocked["notes"]))
            # PHP 8.5 additionally needs fatal_error_backtraces=0
            write(pool, "php_admin_value[memory_limit] = -1\n")
            self.assertEqual(triage.evaluate_config("fpm", "8.5", {"ini": [ini], "pool": [pool]})["status"], "partial")
            write(ini, "session.upload_progress.enabled = 0\nfatal_error_backtraces = 0\n")
            self.assertEqual(triage.evaluate_config("fpm", "8.5", {"ini": [ini], "pool": [pool]})["status"], "interim")


@POSIX
class ScanFixtures(unittest.TestCase):
    def scan_root(self, root, **kwargs):
        result, info = triage.scan(ADVISORY, root=root, exec_mode="all", **kwargs)
        return result, info

    def test_vulnerable_and_fixed_binaries_by_exec(self):
        with tempfile.TemporaryDirectory() as root:
            fake_php(os.path.join(root, "usr/bin/php"), "8.4.26")
            fake_php(os.path.join(root, "usr/sbin/php-fpm8.4"), "8.4.27", "fpm-fcgi")
            result, _ = self.scan_root(root)
            by_name = {os.path.basename(i["path"]): i for i in result["installations"]}
            self.assertEqual(by_name["php"]["verdict"], "vulnerable")
            self.assertEqual(by_name["php-fpm8.4"]["verdict"], "fixed")
            self.assertEqual(by_name["php-fpm8.4"]["sapi"], "fpm")
            self.assertEqual(result["exit_code"], 1)

    def test_all_fixed_exits_zero(self):
        with tempfile.TemporaryDirectory() as root:
            fake_php(os.path.join(root, "usr/bin/php"), "8.3.36")
            result, _ = self.scan_root(root)
            self.assertEqual(result["exit_code"], 0)
            self.assertEqual(result["summary"]["fixed"], 1)

    def test_no_exec_never_runs_the_binary(self):
        with tempfile.TemporaryDirectory() as root:
            marker = os.path.join(root, "ran")
            write(os.path.join(root, "usr/bin/php"), "#!/bin/sh\ntouch %s\necho 'PHP 8.4.27'\n" % marker, 0o755)
            result, _ = self.scan_root(root, no_exec=True)
            self.assertFalse(os.path.exists(marker))
            self.assertEqual(result["installations"][0]["verdict"], "unknown")
            self.assertEqual(result["exit_code"], 3)

    def test_eol_branches(self):
        with tempfile.TemporaryDirectory() as root:
            fake_php(os.path.join(root, "usr/bin/php"), "7.4.33")
            fake_php(os.path.join(root, "usr/local/bin/php8"), "7.2.34")
            result, _ = self.scan_root(root)
            classes = sorted(i["class"] for i in result["installations"])
            self.assertEqual(classes, ["eol_backport", "eol_no_fix"])
            self.assertEqual(result["summary"]["vulnerable"], 2)

    def test_empty_root_is_clean(self):
        with tempfile.TemporaryDirectory() as root:
            result, _ = self.scan_root(root)
            self.assertEqual(result["installations"], [])
            self.assertEqual(result["exit_code"], 0)

    def test_alternatives_symlink_is_reported_as_the_real_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            real_binary = os.path.join(tmp, "php8.3")
            fake_php(real_binary, "8.3.36")
            link = os.path.join(tmp, "php")
            os.symlink(real_binary, link)

            def processes():
                return [{"pid": 9, "exe": link, "deleted": False, "kind": "php", "module": None, "start": None, "unit": None}], False

            result, _ = triage.scan(ADVISORY, root=None, runner_processes=processes, exec_mode="all")
            items = [i for i in result["installations"] if i["path"] == os.path.realpath(real_binary)]
            self.assertEqual(len(items), 1)
            self.assertEqual(items[0]["alias"], link)
            self.assertEqual(items[0]["verdict"], "fixed")


    def test_running_process_with_old_binary_needs_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = os.path.join(tmp, "php-fpm")
            fake_php(binary, "8.4.27", "fpm-fcgi")
            started = os.stat(binary).st_mtime - 3600

            def processes():
                return [{"pid": 4242, "exe": binary, "deleted": False, "kind": "php", "module": None,
                         "start": started, "unit": "php8.4-fpm.service"}], False

            result, _ = triage.scan(ADVISORY, root=None, runner_processes=processes, exec_mode="all")
            item = [i for i in result["installations"] if i["path"] == os.path.realpath(binary)][0]
            self.assertEqual(item["verdict"], "fixed")
            self.assertTrue(item["needs_restart"])
            self.assertEqual(item["units"], ["php8.4-fpm.service"])
            self.assertEqual(result["exit_code"], 1)
            deleted = lambda: ([{"pid": 7, "exe": binary, "deleted": True, "kind": "php", "module": None, "start": None, "unit": None}], False)  # noqa: E731
            result, _ = triage.scan(ADVISORY, root=None, runner_processes=deleted, exec_mode="all")
            self.assertTrue([i for i in result["installations"] if i["path"] == os.path.realpath(binary)][0]["needs_restart"])


class BinaryStringVersion(unittest.TestCase):
    @POSIX
    def test_no_exec_reads_version_from_binary_without_running_it(self):
        with tempfile.TemporaryDirectory() as root:
            marker = os.path.join(root, "ran")
            payload = b"\x7fELF" + b"\0" * 8 + b"X-Powered-By: PHP/8.4.26\0" + b"\0" * 8
            path = os.path.join(root, "usr/sbin/php-fpm")
            os.makedirs(os.path.dirname(path))
            with open(path, "wb") as handle:
                handle.write(payload)
            os.chmod(path, 0o755)
            result, _ = triage.scan(ADVISORY, root=root, no_exec=True)
            item = result["installations"][0]
            self.assertEqual((item["version"], item["verdict"], item["version_source"]), ("8.4.26", "vulnerable", "binary-string"))
            self.assertFalse(os.path.exists(marker))


    @POSIX
    def test_root_never_executes_binaries_unless_asked(self):
        with tempfile.TemporaryDirectory() as root:
            marker = os.path.join(root, "ran")
            path = os.path.join(root, "usr/bin/php")
            os.makedirs(os.path.dirname(path))
            with open(path, "w") as handle:
                handle.write("#!/bin/sh\ntouch %s\necho 'PHP 8.4.27'\n" % marker)
            os.chmod(path, 0o755)
            result, _ = triage.scan(ADVISORY, root=root)
            self.assertFalse(os.path.exists(marker))
            self.assertEqual(result["installations"][0]["verdict"], "unknown")
            self.assertTrue(any("--exec" in note for note in result["installations"][0]["notes"]))
            triage.scan(ADVISORY, root=root, exec_mode="all")
            self.assertTrue(os.path.exists(marker))

    def test_unreadable_or_stringless_binary_is_unknown(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "x")
            with open(path, "wb") as handle:
                handle.write(b"no version here")
            self.assertIsNone(triage.binary_version(path))
            self.assertIsNone(triage.binary_version(os.path.join(root, "missing")))


class Recommendations(unittest.TestCase):
    def sit(self, **overrides):
        base = {"bad": [], "supported_vuln": [], "eol_backport": [], "eol_nofix": [], "unknown": [], "restart": [],
                "mod_php": [], "container": False, "pkg": "apt"}
        base.update(overrides)
        return base

    def order(self, sit, mode="online"):
        return [option for option, _ in triage.recommend(sit, mode)]

    def item(self, **kwargs):
        base = {"path": "/usr/bin/php", "version": "8.4.26", "class": "vulnerable", "verdict": "vulnerable", "sapi": "fpm",
                "running": True, "pids": [1], "units": [], "package": None, "needs_restart": False}
        base.update(kwargs)
        return base

    def test_supported_branch_online_vs_offline(self):
        bad = [self.item()]
        online = self.order(self.sit(bad=bad, supported_vuln=bad))
        offline = self.order(self.sit(bad=bad, supported_vuln=bad), "offline")
        self.assertEqual(online[0], "patch-online")
        self.assertEqual(offline[0], "patch-offline")
        self.assertNotIn("patch-online", offline)
        self.assertEqual(online[-3:], ["virtual-patch", "contain", "restart"])

    def test_container_prefers_rebuild(self):
        bad = [self.item()]
        self.assertEqual(self.order(self.sit(bad=bad, supported_vuln=bad, container=True))[:2], ["container", "patch-online"])

    def test_eol_without_fix_never_recommends_a_package_update(self):
        bad = [self.item(version="7.2.34", **{"class": "eol_no_fix"})]
        order = self.order(self.sit(bad=bad, eol_nofix=bad))
        self.assertEqual(order[0], "migrate")
        self.assertIn("isolate", order)
        self.assertNotIn("patch-online", order)

    def test_backport_branches_ask_the_vendor_first(self):
        bad = [self.item(version="7.4.33", **{"class": "eol_backport"})]
        order = self.order(self.sit(bad=bad, eol_backport=bad))
        self.assertEqual(order[:3], ["vendor", "source", "migrate"])

    def test_mod_php_adds_isolation_before_virtual_patch(self):
        bad = [self.item(sapi="apache")]
        order = self.order(self.sit(bad=bad, supported_vuln=bad, mod_php=bad))
        self.assertLess(order.index("isolate"), order.index("virtual-patch"))

    def test_restart_only(self):
        fixed = [self.item(verdict="fixed", **{"class": "fixed"}, needs_restart=True)]
        self.assertEqual(self.order(self.sit(restart=fixed)), ["restart"])

    def test_nothing_to_do(self):
        self.assertEqual(self.order(self.sit()), [])

    def test_response_details_exist_for_every_recommended_option(self):
        bad = [self.item()]
        info = {"pkg": "apt", "container": False}
        result = {"installations": bad}
        response = triage.build_response(result, info, ADVISORY, "offline", "no")
        for rec in response["recommended"]:
            self.assertTrue(response["details"][rec["id"]]["steps"], rec["id"])
        self.assertIn("격리", response["evidence_order_ko"])
        offline = " ".join(response["details"]["patch-offline"]["steps"])
        self.assertIn("apt-get install --download-only", offline)
        self.assertIn("해시", offline)


class VirtualPatchEmit(unittest.TestCase):
    def test_tokens_are_replaced_and_conditional_files_follow_uploads(self):
        for uploads, post_max, has_block in (("no", "8M", True), ("yes", "32M", False), ("unknown", "8M", False)):
            with tempfile.TemporaryDirectory() as out:
                written = triage.emit_virtual_patch(out, uploads)
                self.assertTrue(written)
                blocked = [p for p in written if "block-multipart" in p]
                self.assertEqual(bool(blocked), has_block, uploads)
                iis = os.path.join(out, "iis", "web.config.block-multipart.xml")
                self.assertEqual(os.path.isfile(iis), uploads == "no")
                with open(os.path.join(out, "iis", "web.config.snippet.xml"), encoding="utf-8") as handle:
                    self.assertNotIn("<rewrite>", handle.read())
                text = ""
                for path in written:
                    with open(path, encoding="utf-8") as handle:
                        content = handle.read()
                    self.assertNotIn("@@", content, path)
                    text += content
                self.assertIn(post_max, text)

    def test_no_exploit_payloads_in_templates(self):
        base = os.path.join(ROOT, "virtual-patch")
        for folder, _, names in os.walk(base):
            for name in names:
                with open(os.path.join(folder, name), encoding="utf-8") as handle:
                    content = handle.read().lower()
                for needle in ("/bin/sh -c", "bash -i", "nc -e", "base64 -d", "<?php system", "eval($_"):
                    self.assertNotIn(needle, content, "%s contains %s" % (name, needle))


class PatchPlan(unittest.TestCase):
    def result(self, **overrides):
        item = {"path": "/usr/sbin/php-fpm8.2", "version": "8.2.28", "class": "vulnerable", "verdict": "vulnerable", "sapi": "fpm",
                "exposure": "web", "running": True, "pids": [10], "units": ["php8.2-fpm.service"], "package": "php8.2-fpm",
                "vendor_patch": "no", "needs_restart": False, "notes": [], "version_source": "exec"}
        item.update(overrides)
        return {"host": "web01", "platform": "Debian 12", "installations": [item], "summary": {}, "exit_code": 1}

    def emit(self, result, pkg="apt", mode="online", fmt="auto", container=False):
        out = tempfile.mkdtemp()
        info = {"pkg": pkg, "container": container, "system": "Linux"}
        return out, triage.emit_patch_plan(out, result, info, ADVISORY, mode, fmt)

    @POSIX
    def test_plan_is_tailored_to_the_analysed_system(self):
        out, written = self.emit(self.result())
        names = sorted(os.path.basename(path) for path in written)
        self.assertEqual(names, ["patch-plan.md", "patch-plan.sh"])
        with open(os.path.join(out, "patch-plan.sh"), encoding="utf-8") as handle:
            script = handle.read()
        self.assertIn("sudo apt-get install --only-upgrade php8.2-fpm", script)
        self.assertIn("sudo systemctl restart php8.2-fpm.service", script)
        self.assertIn("dpkg-query -W 'php*'", script)
        self.assertIn("changelog.Debian.gz", script)
        self.assertLess(script.index("증거 먼저 보존"), script.index("apt-get install --only-upgrade"))

    @POSIX
    def test_script_is_review_only(self):
        out, _ = self.emit(self.result())
        plan = os.path.join(out, "patch-plan.sh")
        self.assertEqual(subprocess.call(["sh", "-n", plan]), 0)
        env = {k: v for k, v in os.environ.items() if k != triage.PLAN_GUARD_ENV}
        self.assertEqual(subprocess.call(["sh", plan], env=env, cwd=out, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
                         triage.PLAN_GUARD_EXIT)
        # even when "reviewed", every step asks for confirmation; with no answer nothing runs
        env[triage.PLAN_GUARD_ENV] = "yes"
        proc = subprocess.run(["sh", plan], env=env, cwd=out, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, universal_newlines=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("건너뜀", proc.stdout)
        self.assertEqual([n for n in os.listdir(out) if n.startswith("php2shell-")], [])

    @POSIX
    def test_hostile_package_names_are_not_suggested(self):
        hostile = "evil'; touch /tmp/never-run; '"
        out, _ = self.emit(self.result(package=hostile))
        with open(os.path.join(out, "patch-plan.sh"), encoding="utf-8") as handle:
            script = handle.read()
        self.assertNotIn(hostile, script)
        self.assertNotIn("touch /tmp/never-run", script)

    def test_offline_container_and_unpackaged_variants(self):
        out, _ = self.emit(self.result(), mode="offline")
        with open(os.path.join(out, "patch-plan.sh"), encoding="utf-8") as handle:
            self.assertIn("폐쇄망", handle.read())
        out, _ = self.emit(self.result(package=None, units=["container"]), container=True)
        with open(os.path.join(out, "patch-plan.sh"), encoding="utf-8") as handle:
            script = handle.read()
        self.assertIn("FROM php:8.4.27", script)
        self.assertNotIn("apt-get install --only-upgrade", script)

    def test_eol_plan_does_not_offer_a_package_update_as_the_fix(self):
        out, _ = self.emit(self.result(version="7.2.34", **{"class": "eol_no_fix"}))
        with open(os.path.join(out, "patch-plan.md"), encoding="utf-8") as handle:
            text = handle.read()
        self.assertIn("수정이 없습니다", text)

    def test_windows_plan_is_powershell_with_bom_and_guard(self):
        out, written = self.emit(self.result(path="C:\\php\\php-cgi.exe", package=None, units=[]), pkg="windows")
        names = sorted(os.path.basename(path) for path in written)
        self.assertEqual(names, ["patch-plan.md", "patch-plan.ps1"])
        with open(os.path.join(out, "patch-plan.ps1"), "rb") as handle:
            raw = handle.read()
        self.assertTrue(raw.startswith(b"\xef\xbb\xbf"))
        text = raw.decode("utf-8-sig")
        self.assertIn("exit 64", text)
        self.assertIn("Get-FileHash", text)
        self.assertIn("iisreset", text)


class Cli(unittest.TestCase):
    def run_main(self, argv):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = triage.main(argv)
        return code, buffer.getvalue()

    def test_list_options_needs_no_scan(self):
        code, out = self.run_main(["--list-options"])
        self.assertEqual(code, 0)
        self.assertIn("가상 패치", out)
        self.assertIn("오프라인", out)

    @POSIX
    def test_json_output_contract_and_text_report(self):
        with tempfile.TemporaryDirectory() as root:
            fake_php(os.path.join(root, "usr/bin/php"), "8.4.26")
            code, out = self.run_main(["--root", root, "--exec", "--json", "--mode", "offline"])
            data = json.loads(out)
            self.assertEqual(code, 1)
            self.assertEqual(data["exit_code"], 1)
            for key in ("tool", "as_of", "host", "platform", "installations", "summary", "exit_code", "response"):
                self.assertIn(key, data)
            self.assertEqual(data["installations"][0]["class"], "vulnerable")
            self.assertEqual(data["response"]["recommended"][0]["id"], "patch-offline")
            code, text = self.run_main(["--root", root, "--exec"])
            self.assertIn("[취약]", text)
            self.assertIn("권장 대응 순서", text)
            self.assertIn("완전한 해결이 아닙니다", text)

    @POSIX
    def test_markdown_and_output_file(self):
        with tempfile.TemporaryDirectory() as root:
            fake_php(os.path.join(root, "usr/bin/php"), "8.4.27")
            target = os.path.join(root, "report.md")
            code, _ = self.run_main(["--root", root, "--exec", "--format", "md", "--output", target])
            self.assertEqual(code, 0)
            with open(target, encoding="utf-8") as handle:
                self.assertIn("# PHP2Shell 점검 보고", handle.read())

    def test_emit_virtual_patch_flag(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as out:
            code, _ = self.run_main(["--root", root, "--no-response", "--emit-virtual-patch", os.path.join(out, "vp"), "--uploads", "no"])
            self.assertEqual(code, 0)
            self.assertTrue(os.path.isdir(os.path.join(out, "vp")))


class SecurityRegression(unittest.TestCase):
    @POSIX
    def test_trust_predicate_checks_file_every_parent_and_temp_locations(self):
        binary = "/usr/local/bin/php"
        def fake_stat(changed=None, owner=0, mode=None):
            def inspect(path):
                current_mode = stat.S_IFREG | 0o755 if path == binary else stat.S_IFDIR | 0o755
                return SimpleNamespace(st_uid=owner if path == changed else 0,
                                       st_mode=mode if path == changed and mode is not None else current_mode)
            return inspect
        self.assertTrue(triage.trusted_binary(binary, fake_stat()))
        for changed, owner, mode in ((binary, 1, None), ("/usr/local", 1000, None),
                                     (binary, 0, stat.S_IFREG | 0o777),
                                     ("/usr/local/bin", 0, stat.S_IFDIR | 0o775),
                                     ("/usr", 0, stat.S_IFDIR | 0o1777),
                                     (binary, 0, stat.S_IFIFO | 0o644)):
            self.assertFalse(triage.trusted_binary(binary, fake_stat(changed, owner, mode)), changed)
        for path in ("/tmp/php", "/var/tmp/php", "/dev/shm/php", "/run/user/1/php", "/home/x/php", "/Users/x/php"):
            self.assertFalse(triage.trusted_binary(path, fake_stat()), path)

    def test_run_scrubs_environment_closes_stdin_and_caps_output(self):
        with mock.patch.dict(os.environ, {"PHP2SHELL_SECRET_TEST": "do-not-leak", "PYTHONPATH": "/untrusted"}):
            code, output = triage.run([sys.executable, "-c",
                "import os,sys; print(os.environ.get('PHP2SHELL_SECRET_TEST','ABSENT')); "
                "print(os.environ.get('PYTHONPATH','ABSENT')); print(repr(sys.stdin.read())); "
                "print(os.environ.get('LC_ALL','')); print(os.environ['PATH'])"])
        self.assertEqual(code, 0)
        output = output.replace("\r\n", "\n")  # Windows 자식 프로세스의 print 는 CRLF
        self.assertIn("ABSENT\nABSENT\n''", output)
        self.assertNotIn("do-not-leak", output)
        if os.name != "nt":
            self.assertIn(triage.SAFE_PATH, output)
            self.assertIn("\nC\n", output)
        else:
            self.assertEqual(output.splitlines()[-1], os.path.join(triage.windows_systemroot(), "System32"))
        _, output = triage.run([sys.executable, "-c", "import sys; sys.stdout.write('x'*1000000)"])
        self.assertEqual(len(output.encode("utf-8")), 4096)
        code, _ = triage.run([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.1)
        self.assertIsNone(code)

    @POSIX
    def test_auto_privileged_does_not_execute_temp_binary_and_unprivileged_does(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "php")
            marker = os.path.join(directory, "executed")
            write(path, "#!/bin/sh\n# X-Powered-By: PHP/8.4.26\n"
                        "touch '%s'\necho 'PHP 8.4.27'\n" % marker, 0o755)
            with mock.patch.object(triage, "discover_files", return_value=[path]), \
                    mock.patch.object(triage, "privileged", return_value=True), \
                    mock.patch.object(triage, "package_owner", return_value=(None, None)):
                result, _ = triage.scan(ADVISORY, runner_processes=lambda: ([], False))
                self.assertEqual(result["exec_policy"], "trusted-only")
                item = result["installations"][0]
                self.assertFalse(item["executed"])
                self.assertIn("신뢰할 수 없는 위치", item["exec_note"])
                self.assertEqual(item["verdict"], "vulnerable")
                self.assertFalse(os.path.exists(marker))
                with mock.patch.object(triage, "privileged", return_value=False):
                    result, _ = triage.scan(ADVISORY, runner_processes=lambda: ([], False))
                self.assertTrue(result["installations"][0]["executed"])
                self.assertEqual(result["exec_policy"], "all")
                self.assertTrue(os.path.exists(marker))
            os.unlink(marker)
            with mock.patch.object(triage, "discover_files", return_value=[path]), \
                    mock.patch.object(triage, "package_owner", return_value=(None, None)):
                triage.scan(ADVISORY, no_exec=True, exec_mode="all", runner_processes=lambda: ([], False))
            self.assertFalse(os.path.exists(marker))

    @POSIX
    def test_parent_symlink_is_removed_before_trust_check_and_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            real_dir = os.path.join(directory, "real")
            path = os.path.join(real_dir, "php")
            fake_php(path, "8.4.27")
            alias_dir = os.path.join(directory, "alias")
            os.symlink(real_dir, alias_dir)
            alias = os.path.join(alias_dir, "php")
            with mock.patch.object(triage, "discover_files", return_value=[alias]), \
                    mock.patch.object(triage, "privileged", return_value=True), \
                    mock.patch.object(triage, "trusted_binary", return_value=True) as trusted, \
                    mock.patch.object(triage, "exec_version", return_value="8.4.27") as execute, \
                    mock.patch.object(triage, "package_owner", return_value=(None, None)):
                result, _ = triage.scan(ADVISORY, runner_processes=lambda: ([], False))
            canonical = os.path.realpath(path)
            trusted.assert_called_once_with(canonical)
            execute.assert_called_once_with(canonical, "cli", None)
            self.assertEqual(result["installations"][0]["alias"], alias)

    def test_unknown_keeps_exit_three_even_with_fixed_install(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "usr/bin/php"), "X-Powered-By: PHP/8.4.27")
            write(os.path.join(root, "usr/bin/php8"), "unknown")
            result, _ = triage.scan(ADVISORY, root=root)
            self.assertEqual(result["summary"]["fixed"], 1)
            self.assertEqual(result["summary"]["unknown"], 1)
            self.assertEqual(result["exit_code"], 3)
            self.assertNotIn("조치가 필요한 설치는 없습니다", triage.render_text(result, None, ADVISORY))

    @POSIX
    def test_root_escapes_nonregular_files_and_oversize_files_are_absent(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
            escaped = os.path.join(outside, "php")
            write(escaped, "X-Powered-By: PHP/8.4.27")
            directory = os.path.join(root, "usr/bin")
            os.makedirs(directory)
            os.symlink(escaped, os.path.join(directory, "php"))
            os.symlink("../../../" + os.path.relpath(escaped, os.path.dirname(root)),
                       os.path.join(directory, "php8"))
            os.mkfifo(os.path.join(directory, "php7"))
            self.assertIsNone(triage.binary_version(os.path.join(directory, "php7")))
            self.assertIsNone(triage.read_text(os.path.join(directory, "php7")))
            result, _ = triage.scan(ADVISORY, root=root, exec_mode="all")
            self.assertEqual(result["installations"], [])
            self.assertTrue(result["notes"])
            self.assertIsNone(triage.binary_version(os.path.join(directory, "php"), root=root))
            # An intermediate directory link is rejected before glob can traverse it.
            os.symlink(outside, os.path.join(root, "opt"))
            self.assertEqual(triage.safe_glob(root, "/opt/php*"), [])
            local = os.path.join(directory, "php9")
            write(local, "X-Powered-By: PHP/8.4.27")
            os.symlink("php9", os.path.join(directory, "php5"))
            self.assertEqual(triage.binary_version(os.path.join(directory, "php5"), root=root), "8.4.27")
            self.assertIsNone(triage.binary_version(local, limit=4, root=root))
            self.assertIsNone(triage.read_text(local, limit=4, root=root))
            self.assertIsNone(triage.read_text(directory))

    def test_vendor_mentions_must_be_inside_one_entry_and_evidence_is_printed(self):
        ids = "CVE-2026-109618 CVE-2026-109619"
        header = "php8.4 (8.4.26-1) stable-security; urgency=high\n"
        text = header + " * Fix " + ids + "\n -- Maintainer  Thu, 22 Oct 2026\n"
        self.assertEqual(triage.has_vendor_evidence(ids, ADVISORY), "no")
        self.assertEqual(triage.has_vendor_evidence(text, ADVISORY), "yes")
        self.assertEqual(triage.has_vendor_evidence(header + " * not yet fixed " + ids, ADVISORY), "no")
        self.assertEqual(triage.has_vendor_evidence(
            header + " * CVE-2026-109618\n" + header + " * CVE-2026-109619\n", ADVISORY), "no")
        rpm = "* Thu Oct 22 2026 Maintainer - 8.4.26-2\n- Fix " + ids
        self.assertEqual(triage.has_vendor_evidence(rpm, ADVISORY), "yes")
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "php")
            write(path, "X-Powered-By: PHP/8.4.26")
            with mock.patch.object(triage, "discover_files", return_value=[path]), \
                    mock.patch.object(triage, "package_owner", return_value=("php8.4-cli", "8.4.26-1")), \
                    mock.patch.object(triage, "vendor_changelog", return_value=text):
                result, _ = triage.scan(ADVISORY, exec_mode="never", runner_processes=lambda: ([], False))
            self.assertEqual(result["installations"][0]["verdict"], "vendor_patched")
            self.assertIn("Fix " + ids, triage.render_text(result, None, ADVISORY))
            self.assertIn("Fix " + ids, triage.render_markdown(result, None, ADVISORY))

    def test_advisory_shape_and_hostile_values_are_rejected_and_source_is_hashed(self):
        for field, value in (("as_of", "2026-10-23\nid"), ("as_of", "2026;id"), ("extra", "x")):
            data = copy.deepcopy(triage.EMBEDDED_ADVISORY)
            data[field] = value
            with self.assertRaises(ValueError):
                triage.validate_advisory(data)
        for mutate in (lambda d: d["cves"].__setitem__(0, "CVE-x"),
                       lambda d: d["fixed_releases"].__setitem__("8.4", "8.4.27;id"),
                       lambda d: d["sources"][0].__setitem__("url", "https://example.org/\x1b[2J"),
                       lambda d: d["sources"][0].__setitem__("url", "file:///tmp/x")):
            data = copy.deepcopy(triage.EMBEDDED_ADVISORY)
            mutate(data)
            with self.assertRaises(ValueError):
                triage.validate_advisory(data)
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "advisory.json")
            raw = json.dumps(triage.EMBEDDED_ADVISORY, ensure_ascii=False).encode("utf-8")
            with open(path, "wb") as handle:
                handle.write(raw)
            advisory = triage.load_advisory(path)
            result, _ = triage.scan(advisory, root=root)
            self.assertEqual(result["advisory_source"]["path"], path)
            digest = hashlib.sha256(raw).hexdigest()
            self.assertEqual(result["advisory_source"]["sha256"], digest)
            text = triage.render_text(result, None, advisory)
            self.assertIn(digest, text)
            self.assertIn("사용자 지정", text)
            with mock.patch.object(triage.os.path, "lexists", return_value=False):
                embedded = triage.load_advisory()
            self.assertTrue(embedded.source["path"].startswith("embedded:"))
            self.assertEqual(len(embedded.source["sha256"]), 64)

    def test_parsed_lines_are_capped(self):
        text = "x" * 4096 + "session.upload_progress.enabled=0"
        self.assertEqual(triage.parse_ini(text, "hostile"), {})
        self.assertEqual(triage.parse_pool_or_vhost(text, "hostile"), {})
        self.assertIsNone(triage.parse_version("x" * 4096 + "8.4.27"))
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "text")
            write(path, "x" * 10000)
            self.assertEqual(len(triage.read_text(path)), 4096)
            compressed = os.path.join(root, "usr/share/doc/php/changelog.gz")
            os.makedirs(os.path.dirname(compressed))
            with gzip.open(compressed, "wb") as handle:
                handle.write(b"x" * 2000001)
            self.assertIsNone(triage.vendor_changelog("apt", "php", root))


class SafeOutputRegression(unittest.TestCase):
    def test_output_plan_and_templates_refuse_overwrite_and_honor_force(self):
        with tempfile.TemporaryDirectory() as root:
            output = os.path.join(root, "report")
            args = ["--root", root, "--no-response", "--output", output]
            self.assertEqual(triage.main(args), 0)
            self.assertEqual(triage.main(args), 2)
            self.assertEqual(triage.main(args + ["--force"]), 0)
            result = PatchPlan().result()
            info = {"pkg": "apt", "container": False}
            plans = os.path.join(root, "plans")
            paths = triage.emit_patch_plan(plans, result, info, ADVISORY)
            with self.assertRaises(FileExistsError):
                triage.emit_patch_plan(plans, result, info, ADVISORY)
            triage.emit_patch_plan(plans, result, info, ADVISORY, force=True)
            templates = os.path.join(root, "templates")
            triage.emit_virtual_patch(templates, "yes")
            with self.assertRaises(FileExistsError):
                triage.emit_virtual_patch(templates, "yes")
            triage.emit_virtual_patch(templates, "yes", force=True)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(os.stat(output).st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(os.stat(plans).st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(os.stat(os.path.join(plans, "patch-plan.sh")).st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(os.stat(paths[0]).st_mode), 0o600)

    @POSIX
    def test_output_plan_and_template_symlinks_are_never_followed_even_force(self):
        with tempfile.TemporaryDirectory() as root:
            target = os.path.join(root, "target")
            write(target, "keep")
            link = os.path.join(root, "link")
            os.symlink(target, link)
            for force in (False, True):
                with self.assertRaises(FileExistsError):
                    triage.safe_write(link, "bad", force=force)
                self.assertEqual(triage.main(["--root", root, "--output", link] + (["--force"] if force else [])), 2)
            plans = os.path.join(root, "plans")
            os.mkdir(plans)
            os.symlink(target, os.path.join(plans, "patch-plan.md"))
            with self.assertRaises(FileExistsError):
                triage.emit_patch_plan(plans, PatchPlan().result(), {"pkg": "apt"}, ADVISORY, force=True)
            templates = os.path.join(root, "templates")
            os.mkdir(templates)
            os.symlink(root, os.path.join(templates, "apache"))
            with self.assertRaises(OSError):
                triage.emit_virtual_patch(templates, "yes", force=True)
            os.unlink(link)
            os.symlink(os.path.join(root, "missing"), link)
            with self.assertRaises(FileExistsError):
                triage.safe_write(link, "bad", force=True)
            self.assertFalse(os.path.exists(os.path.join(root, "missing")))
            self.assertEqual(triage.read_text(target), "keep")

    def test_hostile_data_cannot_forge_output_or_escape_plan_guards_and_literals(self):
        hostile = "/tmp/a\nFORGED\x1b[2J\r\u0085\u2028\u2029'’‘‚‛;|`/php"
        result = PatchPlan().result(path=hostile, package=None, units=["php;id.service"])
        result.update(process_visibility="full", exec_policy="never",
                      summary={"vulnerable": 1, "eol": 0, "fixed": 0, "vendor_patched": 0, "unknown": 0, "needs_restart": 0})
        result["host"] = "host\nBAD\x1b[2J"
        info = {"pkg": "apt", "container": False}
        steps = triage.build_patch_plan(result, info, ADVISORY)
        shell = triage.render_plan_sh(steps, result, ADVISORY)
        self.assertEqual(shell.splitlines()[1], 'if [ "${PHP2SHELL_I_REVIEWED:-}" != "yes" ]; then')
        self.assertNotIn("restart 'php;id.service'", shell)
        self.assertNotIn(hostile, shell)
        self.assertNotIn("\nFORGED", shell)
        self.assertLess(shell.index("if confirm"), shell.index("패키지 관리자가 소유하지 않은"))
        self.assertLess(shell.index("umask 077"), shell.index('mkdir -m 700 "$EV"'))
        for text in (shell, triage.render_text(result, None, ADVISORY),
                     triage.render_markdown(result, None, ADVISORY), triage.render_plan_md(steps, result, ADVISORY)):
            for control in ("\x1b", "\r", "\u0085", "\u2028", "\u2029"):
                self.assertNotIn(control, text)
            self.assertNotIn("\nFORGED", text)
        markdown = triage.render_markdown(result, None, ADVISORY)
        self.assertIn("&#124;", markdown)
        self.assertIn("&#96;", markdown)
        windows_path = "C:\\php'’‘‚‛;evil\\php.exe"
        result["installations"][0]["path"] = windows_path
        windows_steps = triage.build_patch_plan(result, {"pkg": "windows"}, ADVISORY)
        ps1 = triage.render_plan_ps1(windows_steps, result, ADVISORY)
        self.assertTrue(ps1.startswith("if ($env:PHP2SHELL_I_REVIEWED"))
        for quote in "'’‘‚‛":
            self.assertIn(quote * 2, triage.ps_literal(windows_path))
        self.assertIn("-LiteralPath " + triage.ps_literal("C:\\php'’‘‚‛;evil"), ps1)
        self.assertLess(ps1.index("if (Confirm-Step"), ps1.index("Copy-Item"))
        self.assertIn("/inheritance:r /grant:r", ps1)
        self.assertNotIn(windows_path, ps1)


if __name__ == "__main__":
    unittest.main()
