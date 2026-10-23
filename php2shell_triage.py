#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lee Jongyoung
"""php2shell-triage: PHP2Shell(CVE-2026-109618 / CVE-2026-109619) 로컬 점검 도구.

이 도구는 방어용입니다. 익스플로잇을 포함하지 않고 서버 설정·패키지를 바꾸지 않습니다.
신뢰할 수 있는 PHP 바이너리만 `-n -v` 로 실행합니다(--no-exec 로 끌 수 있음).
네트워크로 아무것도 보내지 않습니다. 조치는 명령으로 '출력'만 합니다.

  python3 php2shell_triage.py                 # 이 서버의 PHP를 찾아 판정과 조치 계획 출력
  python3 php2shell_triage.py --json          # 기계가 읽는 JSON
  python3 php2shell_triage.py --no-exec       # 발견한 바이너리를 실행하지 않음(침해 의심 서버)
  python3 php2shell_triage.py --root /mnt/img # 마운트한 파일시스템을 오프라인으로 점검

종료 코드: 0 조치 필요 없음 / 1 취약·EOL·재시작 필요 설치가 있음 / 3 확인 불가(권한 등).
표준 라이브러리만 사용하며 Python 3.6 이상에서 동작합니다.
"""
import argparse
import glob
import gzip
import json
import os
import hashlib
import fnmatch
import ntpath
import platform
import re
import shlex
import shutil
import socket
import subprocess
import stat
import sys
import time
import threading
from urllib.parse import urlsplit

__version__ = "0.1.0"
TOOL = "php2shell-triage"

# --- 권고 데이터 -----------------------------------------------------------------
# data/advisory.json 이 있으면 그것을 우선 쓰고(최신 데이터로 교체 가능), 없으면 아래 내장본을 씁니다.
# 내장본은 tools/sync_embedded_advisory.py 가 data/advisory.json 에서 생성합니다.
# BEGIN EMBEDDED ADVISORY
EMBEDDED_ADVISORY = json.loads(r'''{
 "name": "PHP2Shell",
 "cves": [
  "CVE-2026-109618",
  "CVE-2026-109619"
 ],
 "cvss_v4": 9.2,
 "as_of": "2026-10-23",
 "summary_ko": "PHP 엔진의 메모리 안전성 결함으로 인증 없이 원격 코드 실행과 프로세스 메모리 노출이 가능합니다. 웹 요청을 처리하는 모든 SAPI(mod_php, PHP-FPM, php-cgi, FrankenPHP, LiteSpeed)가 해당합니다.",
 "affected_range": "5.4 - 8.5 (8.6.0 RC3 이하 포함)",
 "fixed_releases": {
  "8.2": "8.2.35",
  "8.3": "8.3.36",
  "8.4": "8.4.27",
  "8.5": "8.5.12",
  "8.6": "8.6.0RC4"
 },
 "affected_no_official_fix": {
  "eol_no_fix_branches": [
   "5.4",
   "5.5",
   "5.6",
   "7.0",
   "7.1",
   "7.2",
   "7.3"
  ],
  "source_backport_only_branches": [
   "7.4",
   "8.0",
   "8.1"
  ]
 },
 "source_backport_urls": {
  "7.4": "https://github.com/php/php-src/tree/PHP-7.4-CVE-2026-109618-109619",
  "8.0": "https://github.com/php/php-src/tree/PHP-8.0-CVE-2026-109618-109619",
  "8.1": "https://github.com/php/php-src/tree/PHP-8.1-CVE-2026-109618-109619"
 },
 "security_support_ends": {
  "8.2": "2026-12-31"
 },
 "first_exploitation_observed": "2026-10-17",
 "log_review_since_default": "2026-10-17",
 "vendor_patch_evidence_cves": [
  "CVE-2026-109618",
  "CVE-2026-109619"
 ],
 "interim_mitigation": {
  "note_ko": "임시 조치는 일부 공격 경로만 줄이며 완전한 해결이 아닙니다. 업데이트만이 근본 조치입니다.",
  "settings": [
   {
    "key": "session.upload_progress.enabled",
    "value": "0",
    "applies_to": [
     "fpm",
     "cgi",
     "apache"
    ],
    "admin_only": true
   },
   {
    "key": "memory_limit",
    "value": "-1",
    "applies_to": [
     "fpm",
     "cgi",
     "apache"
    ],
    "admin_only": true,
    "warning_ko": "메모리 상한이 없어지므로 컨테이너·cgroup·systemd MemoryMax 등 OS 수준 상한을 함께 설정해야 합니다. RLIMIT_AS/RLIMIT_DATA는 쓰지 마세요."
   },
   {
    "key": "session.auto_start",
    "value": "0",
    "applies_to": [
     "fpm",
     "cgi",
     "apache"
    ],
    "admin_only": true,
    "source": "Xint",
    "warning_ko": "session_start()를 호출하지 않는 페이지의 세션 기능이 멈출 수 있습니다."
   },
   {
    "key": "post_max_size",
    "value": "8M",
    "applies_to": [
     "fpm",
     "cgi",
     "apache"
    ],
    "admin_only": false,
    "note_ko": "업로드가 필요 없으면 8M, 필요하면 32M 수준. upload_max_filesize는 post_max_size보다 작게 유지."
   },
   {
    "key": "fatal_error_backtraces",
    "value": "0",
    "applies_to": [
     "fpm",
     "cgi",
     "apache"
    ],
    "admin_only": false,
    "only_branches": [
     "8.5"
    ]
   }
  ]
 },
 "sources": [
  {
   "id": "php-official",
   "title": "PHP.net Security advisory: Critical remote code execution vulnerabilities, update now",
   "url": "https://www.php.net/archive/2026.php#2026-10-21-5",
   "fetched": "2026-10-23"
  },
  {
   "id": "ghsa-109618",
   "title": "GHSA-w8hw-w9fx-j79w (CVE-2026-109618)",
   "url": "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w",
   "fetched": "2026-10-23"
  },
  {
   "id": "ghsa-109619",
   "title": "GHSA-6wmf-4rv5-p3rp (CVE-2026-109619)",
   "url": "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp",
   "fetched": "2026-10-23"
  },
  {
   "id": "kisa",
   "title": "KISA 보호나라: PHP 보안취약점(PHP2Shell) 관련 기업 보안 대응 수칙 (2026-10-22)",
   "url": "https://www.boho.or.kr/kr/bbs/view.do?bbsId=B0000133&menuNo=205020&nttId=72230",
   "fetched": "2026-10-23"
  },
  {
   "id": "ncsc-nl",
   "title": "NCSC-NL/CERT-EU php2shell operational information",
   "url": "https://github.com/NCSC-NL/php2shell",
   "fetched": "2026-10-23"
  },
  {
   "id": "sysdig",
   "title": "Sysdig: PHP2Shell detection and recommendations",
   "url": "https://www.sysdig.com/blog/php2shell-cve-2026-109618-and-cve-2026-109619-detecting-unauthenticated-remote-code-execution-in-php-core",
   "fetched": "2026-10-23"
  },
  {
   "id": "xint",
   "title": "Xint: PHP2Shell 긴급 대응 방안",
   "url": "https://xint.io/ko/blog/php2shell-vulnerability-emergency-response",
   "fetched": "2026-10-23"
  }
 ]
}''')
# END EMBEDDED ADVISORY


class Advisory(dict):
    """권고 내용과 별도로 실제로 읽은 데이터의 출처를 보존한다."""


def clean(value):
    return re.sub(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]", "?", str(value))


def markdown_value(value):
    return clean(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace(
        "`", "&#96;").replace("|", "&#124;")


def validate_advisory(data):
    """내장 스키마의 알려진 키/타입만 허용하며 코드/제어문자는 거부한다."""
    def visit(value, template, key=""):
        if type(value) is not type(template):
            raise ValueError("권고 데이터 타입 오류: " + key)
        if isinstance(value, dict):
            if set(value) != set(template):
                raise ValueError("권고 데이터 키 오류: " + key)
            for child in value:
                visit(value[child], template[child], child)
        elif isinstance(value, list):
            if not value or not template:
                raise ValueError("빈 권고 목록: " + key)
            if key == "settings" and len(value) != len(template):
                raise ValueError("완화 설정 목록 오류")
            for index, child in enumerate(value):
                visit(child, template[index] if key == "settings" else template[0], key)
        elif isinstance(value, str):
            if len(value) > 4096 or clean(value) != value:
                raise ValueError("권고 데이터 제어문자/길이 오류: " + key)
            if key in ("cves", "vendor_patch_evidence_cves"):
                valid = re.fullmatch(r"CVE-\d{4}-\d+", value)
            elif key == "url" or key in EMBEDDED_ADVISORY["source_backport_urls"]:
                url = urlsplit(value)
                valid = (url.scheme in ("https", "http") and url.netloc and
                         not re.search(r"[\s'\"`\\<>]", value))
            elif key.endswith("_ko") or key in ("title", "affected_range"):
                valid = True
            else:
                valid = re.fullmatch(r"[0-9A-Za-z.\-+~: /_()]*", value)
            if not valid:
                raise ValueError("권고 데이터 값 오류: " + key)
        elif isinstance(value, float) and not (0 <= value <= 10):
            raise ValueError("권고 점수 오류")
    visit(data, EMBEDDED_ADVISORY)
    if set(data["cves"]) != set(EMBEDDED_ADVISORY["cves"]) or set(
            data["vendor_patch_evidence_cves"]) != set(EMBEDDED_ADVISORY["cves"]):
        raise ValueError("대상 CVE 불일치")
    for branch, version in data["fixed_releases"].items():
        if not re.fullmatch(re.escape(branch) + r"\.\d+(?:RC\d+)?", version):
            raise ValueError("수정 버전 오류: " + branch)
    return data


def load_advisory(path=None):
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [path] if path else [os.path.join(here, "data", "advisory.json"),
                                    os.path.join(here, "advisory.json")]
    for candidate in candidates:
        if path or os.path.lexists(candidate):
            raw = read_bytes(candidate, 2000000)
            if raw is None:
                raise ValueError("권고 데이터를 읽을 수 없습니다: " + clean(candidate))
            data = Advisory(validate_advisory(json.loads(raw.decode("utf-8"))))
            data.source = {"path": os.path.abspath(candidate), "sha256": hashlib.sha256(raw).hexdigest(),
                           "custom": bool(path)}
            return data
    raw = json.dumps(EMBEDDED_ADVISORY, ensure_ascii=False, sort_keys=True).encode("utf-8")
    data = Advisory(validate_advisory(EMBEDDED_ADVISORY.copy()))
    data.source = {"path": "embedded:" + os.path.abspath(__file__), "sha256": hashlib.sha256(raw).hexdigest(),
                   "custom": False}
    return data


# --- 버전 판정 -------------------------------------------------------------------
_VERSION_RE = re.compile(
    r"(?<![\d.])(\d+)\.(\d+)\.(\d+)(?:\.\d+)?(?:[-.]?(alpha|beta|RC|dev)\.?(\d*))?", re.IGNORECASE
)
_PRE_RANK = {"dev": 0, "alpha": 1, "beta": 2, "rc": 3}
_RELEASE_RANK = 9


def parse_version(text):
    """문자열에서 처음 나오는 X.Y.Z(+선택적 사전 릴리스 표기)를 (major, minor, patch, rank, num)로."""
    match = _VERSION_RE.search((text or "")[:4096])
    if not match:
        return None
    major, minor, patch = int(match.group(1)), int(match.group(2)), int(match.group(3))
    tag = match.group(4)
    if tag:
        rank = _PRE_RANK[tag.lower()]
        num = int(match.group(5)) if match.group(5) else 0
    else:
        rank, num = _RELEASE_RANK, 0
    return (major, minor, patch, rank, num)


def classify(version_text, advisory):
    """업스트림 버전 번호만으로 분류. 벤더 백포트는 따로 판단한다."""
    parsed = parse_version(version_text)
    if parsed is None:
        return "unknown"
    major, minor = parsed[0], parsed[1]
    branch = "%d.%d" % (major, minor)
    if (major, minor) < (5, 4):
        return "old_unsupported"
    if branch in advisory["affected_no_official_fix"]["source_backport_only_branches"]:
        return "eol_backport"
    if (major, minor) <= (7, 3):
        return "eol_no_fix"
    fixed = advisory["fixed_releases"]
    if branch in fixed:
        return "fixed" if parsed >= parse_version(fixed[branch]) else "vulnerable"
    if (major, minor) > (8, 6):
        return "fixed"
    return "unknown"


def verdict_for(cls, vendor_patch):
    if cls == "fixed":
        return "fixed"
    if cls in ("vulnerable", "eol_backport", "eol_no_fix"):
        return "vendor_patched" if vendor_patch == "yes" else "vulnerable"
    if cls == "old_unsupported":
        return "eol"
    return "unknown"


VERDICT_KO = {
    "fixed": "수정됨",
    "vendor_patched": "벤더 패치 확인",
    "vulnerable": "취약",
    "eol": "지원 종료(EOL)",
    "unknown": "확인 필요",
}
CLASS_KO = {
    "fixed": "수정 버전 이상",
    "vulnerable": "수정 전 버전",
    "eol_backport": "공식 업데이트 없음(7.4/8.0/8.1: 벤더 패치 또는 소스 백포트만)",
    "eol_no_fix": "EOL, 어디에도 수정 없음",
    "old_unsupported": "5.4 미만, 오래전 지원 종료",
    "unknown": "버전을 해석하지 못함",
}


# --- 실행 도우미 -----------------------------------------------------------------
SAFE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
OUTPUT_LIMIT = 4096
PS_OUTPUT_LIMIT = 8 * 1024 * 1024   # 프로세스 목록은 4KB 를 훨씬 넘는다. 넘으면 뒤쪽 프로세스(php-fpm 등)를 놓친다


def privileged():
    if os.name == "nt":
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    return hasattr(os, "geteuid") and os.geteuid() == 0


def windows_systemroot():
    import ctypes
    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetWindowsDirectoryW(buffer, len(buffer))
    if not length or length >= len(buffer):
        raise OSError("Windows 시스템 디렉터리를 확인할 수 없습니다")
    return buffer.value


def helper_path(name):
    if os.path.isabs(name):
        return name
    if os.name == "nt":
        system = os.path.join(windows_systemroot(), "System32")
        if name.lower() in ("powershell", "powershell.exe"):
            return os.path.join(system, "WindowsPowerShell", "v1.0", "powershell.exe")
        return os.path.join(system, name)
    return shutil.which(name, path=SAFE_PATH)


def run(cmd, timeout=6, pass_fds=(), limit=OUTPUT_LIMIT):
    """최소 환경, 닫힌 stdin, 제한 시간 및 stdout 상한(기본 4096바이트). stderr는 보관하지 않는다."""
    env = {"LC_ALL": "C", "PATH": SAFE_PATH}
    if os.name == "nt":
        systemroot = windows_systemroot()
        env = {"SystemRoot": systemroot, "PATH": os.path.join(systemroot, "System32")}
    proc = None
    try:
        command = list(cmd)
        command[0] = helper_path(command[0])
        if not command[0]:
            return None, ""
        options = {"pass_fds": pass_fds} if os.name != "nt" else {}
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                env=env, stdin=subprocess.DEVNULL, bufsize=0, **options)
        chunks = []
        def collect():
            remaining = limit
            try:
                while remaining:
                    chunk = os.read(proc.stdout.fileno(), min(1024, remaining))
                    if not chunk:
                        return
                    chunks.append(chunk)
                    remaining -= len(chunk)
                proc.kill()
            except (OSError, ValueError):
                pass
        reader = threading.Thread(target=collect)
        reader.daemon = True
        reader.start()
        try:
            code = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            code = None
        reader.join(timeout=1)
        proc.stdout.close()
        return code, b"".join(chunks).decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError, ValueError):
        if proc is not None:
            proc.kill()
            proc.wait()
        return None, ""


def open_directory(path):
    """POSIX: 전체 경로를 디렉터리 FD로 고정하며 중간 링크도 거부한다."""
    directory = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in os.path.abspath(path).strip(os.sep).split(os.sep):
            if not component:
                continue
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        return directory
    except BaseException:
        os.close(directory)
        raise


def resolve_inside(root, path):
    """루트 밖으로 나가는 링크와 '..'를 거부한다. 링크는 최대 40회만 해석한다."""
    root = os.path.realpath(root)
    path = os.path.abspath(path)
    try:
        if os.path.commonpath([root, path]) != root:
            return None
    except ValueError:
        return None
    todo = os.path.relpath(path, root).split(os.sep)
    parts, links, directories = [], 0, []
    try:
        if os.name != "nt":
            directories.append(open_directory(root))
        while todo:
            part = todo.pop(0)
            if part in ("", "."):
                continue
            if part == "..":
                if not parts:
                    return None
                parts.pop()
                if len(directories) > len(parts) + 1:
                    os.close(directories.pop())
                continue
            current = os.path.join(root, *(parts + [part]))
            info = (os.stat(part, dir_fd=directories[-1], follow_symlinks=False)
                    if directories else os.lstat(current))
            if stat.S_ISLNK(info.st_mode):
                links += 1
                if links > 40:
                    return None
                target = os.readlink(part, dir_fd=directories[-1]) if directories else os.readlink(current)
                if os.path.isabs(target):
                    if os.path.commonpath([root, target]) != root:
                        return None
                    parts = []
                    while len(directories) > 1:
                        os.close(directories.pop())
                    target = os.path.relpath(target, root)
                todo = target.split(os.sep) + todo
            else:
                if getattr(info, "st_file_attributes", 0) & 0x400:
                    return None
                parts.append(part)
                if todo and directories:
                    directories.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                               dir_fd=directories[-1]))
        return os.path.join(root, *parts)
    except (OSError, ValueError):
        return None
    finally:
        for directory in directories:
            os.close(directory)


def under(root, path):
    if not root or root == "/":
        return path
    return os.path.join(os.path.realpath(root), path.lstrip("/"))


def safe_glob(root, pattern, notes=None):
    if not root:
        return glob.glob(pattern)
    paths = [os.path.realpath(root)]
    for component in pattern.lstrip("/").split("/"):
        children = []
        for parent in paths:
            # 이전 컴포넌트가 바뀌었다면 호스트 쪽을 열거하지 않는다.
            resolved_parent = resolve_inside(root, parent)
            if resolved_parent is None:
                continue
            try:
                if os.name == "nt":
                    names = os.listdir(resolved_parent)
                else:
                    directory = open_directory(resolved_parent)
                    try:
                        names = os.listdir(directory)
                    finally:
                        os.close(directory)
            except OSError:
                continue
            for name in fnmatch.filter(names, component):
                candidate = os.path.join(resolved_parent, name)
                resolved = resolve_inside(root, candidate)
                if resolved is not None:
                    children.append(resolved)
                elif notes is not None:
                    notes.append("루트 밖/해석 불가 링크 제외: " + clean(candidate))
        paths = children
    return paths


def open_regular(path, limit, root=None):
    """링크를 먼저 해석한 후 모든 디렉터리를 NOFOLLOW로 열어 교체 경쟁도 차단한다."""
    resolved = resolve_inside(root, path) if root else os.path.realpath(path)
    # fallback: resolve_inside 가 심볼릭 링크 체인 등을 처리 못 해서 None 을 반환할 때,
    # 여전히 루트 안이라면 realpath 로 폴백한다(보안: 루트 밖이면 거부).
    if resolved is None and root:
        try:
            real = os.path.realpath(path)
            if os.path.commonpath([os.path.realpath(root), real]) == os.path.realpath(root):
                resolved = real
        except OSError:
            pass
    if resolved is None:
        return None
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory = None
    fd = None
    try:
        if os.name != "nt":
            directory = open_directory(os.path.dirname(resolved))
            fd = os.open(os.path.basename(resolved), flags, dir_fd=directory)
        else:
            fd = os.open(resolved, flags | getattr(os, "O_BINARY", 0))
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            os.close(fd)
            fd = None
            return None
        handle = os.fdopen(fd, "rb")
        fd = None
        return handle
    except OSError:
        if fd is not None:
            os.close(fd)
        return None
    finally:
        if directory is not None:
            os.close(directory)


def read_bytes(path, limit, root=None):
    handle = open_regular(path, limit, root)
    if handle is None:
        return None
    try:
        with handle:
            data = handle.read(limit + 1)
        return data if len(data) <= limit else None
    except OSError:
        return None


def read_text(path, limit=2000000, root=None):
    data = read_bytes(path, min(limit, 2000000), root)
    return "\n".join(line[:4096] for line in data.decode("utf-8", "replace").splitlines()) if data is not None else None


def trusted_binary(path, stat_fn=os.stat):
    """POSIX root 소유권/권한 검사. stat_fn 주입으로 비특권 테스트 가능."""
    path = os.path.realpath(path)
    if os.name == "nt":
        # ACL을 확인할 수 없으면 안전하게 실행하지 않는다.
        script = (
            "$p=" + ps_literal(path) + "; try { while ($p) { "
            "$i=Get-Item -LiteralPath $p -Force -ErrorAction Stop; "
            "if ($i.Attributes -band [IO.FileAttributes]::ReparsePoint) { exit 1 }; "
            "$a=Get-Acl -LiteralPath $p -ErrorAction Stop; "
            "$o=$a.GetOwner([Security.Principal.SecurityIdentifier]).Value; "
            "if ($o -notin @('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')) { exit 1 }; "
            "foreach ($r in $a.Access) { "
            "if ($r.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) { continue }; "
            "$s=$r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value; "
            "if ($s -in @('S-1-1-0','S-1-5-32-545','S-1-5-11') -and "
            "$r.AccessControlType -eq 'Allow' -and ([int]$r.FileSystemRights -band 0xD0156)) { exit 1 } }; "
            "$n=[IO.Path]::GetDirectoryName($p); if (!$n -or $n -eq $p) { break }; $p=$n }; "
            "Write-Output TRUSTED } catch { exit 1 }")
        code, out = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], 20)
        return code == 0 and out.strip() == "TRUSTED"
    if any(path == p or path.startswith(p + "/") for p in
           ("/tmp", "/var/tmp", "/private/tmp", "/private/var/tmp", "/dev/shm", "/run/user", "/home", "/Users")):
        return False
    first = True
    try:
        while True:
            info = stat_fn(path)
            if info.st_uid != 0 or info.st_mode & 0o022:
                return False
            if first and not stat.S_ISREG(info.st_mode):
                return False
            if not first and not stat.S_ISDIR(info.st_mode):
                return False
            if path == os.path.dirname(path):
                return True
            path, first = os.path.dirname(path), False
    except OSError:
        return False


def ps_literal(value):
    return "'" + re.sub(r"['\u2018\u2019\u201a\u201b]", lambda m: m.group(0) * 2, clean(value)) + "'"


def valid_unit(value):
    return bool(re.fullmatch(r"[A-Za-z0-9@._:-]+\.(?:service|socket)", value))


def valid_package(value):
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+_.:@-]*", value))


# --- 플랫폼 ----------------------------------------------------------------------
def detect_platform(root=None):
    system = platform.system()
    info = {"system": system, "pretty": "%s %s" % (system, platform.release()), "id": system.lower(),
            "container": False, "pkg": None}
    if system == "Linux":
        osrel = read_text(under(root, "/etc/os-release"), root=root) or ""
        values = {}
        for line in osrel.splitlines():
            if "=" in line:
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip().strip('"')
        info["id"] = values.get("ID", "linux")
        info["id_like"] = values.get("ID_LIKE", "")
        if values.get("PRETTY_NAME"):
            info["pretty"] = values["PRETTY_NAME"]
        # 호스트가 컨테이너인지는 실제 호스트를 볼 때만 의미가 있다(--root 로 다른 트리를 점검할 때는 알 수 없음).
        if not root:
            cgroup = read_text("/proc/1/cgroup") or ""
            info["container"] = os.path.exists("/.dockerenv") or "docker" in cgroup or "kubepods" in cgroup
    elif system == "Darwin":
        info["pretty"] = "macOS %s" % platform.mac_ver()[0]
    info["pkg"] = detect_package_manager(info, root)
    return info


def detect_package_manager(info, root=None):
    ident = set((info.get("id", "") + " " + info.get("id_like", "")).lower().split())
    system = info.get("system")
    if system == "Darwin":
        return "brew"
    if system == "Windows":
        return "windows"
    if system == "FreeBSD":
        return "pkg"
    if ident & {"debian", "ubuntu"}:
        return "apt"
    if ident & {"rhel", "fedora", "centos", "rocky", "almalinux", "alma", "amzn", "ol", "oracle"}:
        return "dnf" if helper_path("dnf") or not helper_path("yum") else "yum"
    if "alpine" in ident:
        return "apk"
    if ident & {"suse", "sles", "opensuse", "opensuse-leap", "opensuse-tumbleweed"}:
        return "zypper"
    for tool, name in (("apt-get", "apt"), ("dnf", "dnf"), ("yum", "yum"), ("apk", "apk"), ("zypper", "zypper")):
        if helper_path(tool):
            return name
    return None


# --- 프로세스 열거 ---------------------------------------------------------------
_PHP_EXE_RE = re.compile(r"^(php(-fpm|-cgi|-win)?[0-9.]*|lsphp[0-9.]*|frankenphp)(\.exe)?$", re.IGNORECASE)
_APACHE_EXE_RE = re.compile(r"^(apache2|httpd|httpd\.worker|httpd\.event|httpd\.prefork)(\.exe)?$", re.IGNORECASE)


def sapi_from_name(name):
    base = os.path.basename(name).lower()
    if base.startswith("php-fpm"):
        return "fpm"
    if base.startswith("php-cgi") or base.startswith("php-win"):
        return "cgi" if base.startswith("php-cgi") else "cli"
    if base.startswith("lsphp"):
        return "litespeed"
    if base.startswith("frankenphp"):
        return "frankenphp"
    if base.startswith("libphp") or ("php" in base and base.endswith((".so", ".dylib", ".dll"))):
        return "apache"
    if base.startswith("php"):
        return "cli"
    return "unknown"


def _boot_time():
    stat = read_text("/proc/stat") or ""
    for line in stat.splitlines():
        if line.startswith("btime "):
            return int(line.split()[1])
    return None


def linux_processes():
    """/proc 로 PHP 관련 실행 중 프로세스를 찾는다. (processes, 권한 문제 여부)"""
    processes = []
    denied = 0
    boot = _boot_time()
    try:
        ticks = os.sysconf("SC_CLK_TCK")
    except (ValueError, OSError, AttributeError):
        ticks = 100
    try:
        names = os.listdir("/proc")
    except OSError:
        return processes, True
    for name in names:
        if not name.isdigit():
            continue
        base = "/proc/" + name
        try:
            exe = os.readlink(base + "/exe")
        except PermissionError:
            exe = None
            denied += 1
        except OSError:
            # 커널 스레드(exe 링크 없음)나 조회 중 종료된 프로세스: 권한 문제가 아니다
            exe = None
        comm = (read_text(base + "/comm", 256) or "").strip()
        label = os.path.basename(exe.replace(" (deleted)", "")) if exe else comm
        is_php = bool(_PHP_EXE_RE.match(label)) or bool(_PHP_EXE_RE.match(comm))
        is_apache = bool(_APACHE_EXE_RE.match(label)) or bool(_APACHE_EXE_RE.match(comm))
        if not (is_php or is_apache):
            continue
        entry = {"pid": int(name), "exe": exe, "deleted": bool(exe and exe.endswith(" (deleted)")),
                 "kind": "php" if is_php else "apache", "module": None, "start": None, "unit": None}
        if exe:
            entry["exe"] = exe.replace(" (deleted)", "")
        if is_apache:
            for line in (read_text(base + "/maps", 4000000) or "").splitlines():
                if "libphp" in line or re.search(r"php\d*apache", line, re.IGNORECASE):
                    path = line.split(None, 5)[-1].strip() if len(line.split(None, 5)) >= 6 else ""
                    if path:
                        entry["module"] = path.replace(" (deleted)", "")
                        entry["module_deleted"] = path.endswith(" (deleted)")
                        break
            if not entry["module"]:
                continue
        stat = read_text(base + "/stat", 4096)
        if stat and boot:
            try:
                fields = stat.rsplit(")", 1)[1].split()
                entry["start"] = boot + int(fields[19]) / float(ticks)
            except (IndexError, ValueError):
                pass
        cgroup = read_text(base + "/cgroup", 4096) or ""
        unit = re.search(r"/([^/\n]+\.service)\b", cgroup)
        if unit:
            entry["unit"] = unit.group(1)
        elif re.search(r"docker|containerd|kubepods|libpod", cgroup):
            entry["unit"] = "container"
        processes.append(entry)
    return processes, denied > 0


def ps_exe_for_pid(pid):
    """프로세스 제목이 바뀐 PHP(php-fpm: master process ...)의 실제 실행 파일 경로. FreeBSD 는 procstat, macOS 는 lsof."""
    if helper_path("procstat"):
        code, out = run([helper_path("procstat"), "-b", str(pid)], timeout=10)
        lines = out.splitlines() if code == 0 else []
        if len(lines) >= 2 and lines[1].split() and lines[1].split()[-1].startswith("/"):
            return lines[1].split()[-1]
    elif platform.system() == "Darwin" and helper_path("lsof"):
        code, out = run([helper_path("lsof"), "-a", "-p", str(pid), "-d", "txt", "-Fn"], timeout=10)
        for line in (out.splitlines() if code == 0 else []):
            if line.startswith("n/"):
                return line[1:]
    return None


def ps_processes():
    """macOS/BSD: ps 로 PHP 프로세스를 찾는다. 반환: (processes, 일부 프로세스의 실행 파일을 알 수 없었는지)."""
    # "-o pid=,command=" 는 FreeBSD 에서 pid 열의 머리글을 ",command=" 로 바꿔 command 열이 없다. -o 를 따로 준다(Linux·macOS·BSD 공통)
    code, out = run(["ps", "-ax", "-o", "pid=", "-o", "command="], limit=PS_OUTPUT_LIMIT)
    processes = []
    if code is None:
        return processes, True
    unresolved = False
    for line in out.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) < 2 or not parts[0].isdigit():
            continue
        command = parts[1]
        first = command.split(" ", 1)[0]
        exe = first if command.startswith("/") else None
        label = os.path.basename(exe) if exe else first
        if not exe and label.endswith(":"):
            # php-fpm 은 setproctitle 로 "php-fpm: master process (설정)" / "php-fpm: pool www" 처럼 제목을 바꾼다
            label = label[:-1]
            if _PHP_EXE_RE.match(label):
                exe = ps_exe_for_pid(int(parts[0]))
                if not exe:
                    unresolved = True
                    continue
        if _PHP_EXE_RE.match(label) and exe:
            processes.append({"pid": int(parts[0]), "exe": exe, "deleted": False, "kind": "php",
                              "module": None, "start": None, "unit": None})
    return processes, unresolved


def windows_processes():
    script = ("Get-CimInstance Win32_Process | Where-Object { $_.Name -match '^(php|php-cgi|php-win|httpd)' } | "
              "Select-Object ProcessId,Name,ExecutablePath | ConvertTo-Json -Compress")
    code, out = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], timeout=30)
    processes = []
    if code is None or not out.strip():
        return processes, code is None
    try:
        data = json.loads(out)
    except ValueError:
        return processes, True
    if isinstance(data, dict):
        data = [data]
    for item in data:
        exe = item.get("ExecutablePath")
        if exe:
            processes.append({"pid": item.get("ProcessId"), "exe": exe, "deleted": False, "kind": "php",
                              "module": None, "start": None, "unit": None})
    return processes, False


def live_processes():
    system = platform.system()
    if system == "Linux":
        return linux_processes()
    if system == "Windows":
        return windows_processes()
    return ps_processes()


# --- 파일 탐색 -------------------------------------------------------------------
POSIX_BINARY_GLOBS = [
    "/usr/bin/php*", "/usr/sbin/php-fpm*", "/usr/local/bin/php*", "/usr/local/sbin/php-fpm*",
    "/opt/remi/php*/root/usr/bin/php*", "/opt/remi/php*/root/usr/sbin/php-fpm*",
    "/opt/plesk/php/*/bin/php*", "/opt/plesk/php/*/sbin/php-fpm*",
    "/opt/cpanel/ea-php*/root/usr/bin/php*", "/opt/cpanel/ea-php*/root/usr/sbin/php-fpm*",
    "/usr/local/php*/bin/php*", "/usr/local/php*/sbin/php-fpm*",
    "/usr/local/lsws/lsphp*/bin/lsphp*", "/usr/local/bin/frankenphp", "/usr/bin/frankenphp",
    "/opt/homebrew/bin/php*", "/opt/homebrew/sbin/php-fpm*", "/opt/homebrew/opt/php*/bin/php*",
    "/opt/homebrew/opt/php*/sbin/php-fpm*", "/usr/local/opt/php*/bin/php*", "/usr/local/opt/php*/sbin/php-fpm*",
    "/Applications/MAMP/bin/php/php*/bin/php*", "/Applications/XAMPP/xamppfiles/bin/php*",
    "/opt/lampp/bin/php*", "/opt/lampp/sbin/php-fpm*",
    "/usr/lib/apache2/modules/libphp*.so", "/usr/lib64/httpd/modules/libphp*.so",
    "/usr/lib/httpd/modules/libphp*.so", "/usr/local/apache2/modules/libphp*.so",
    "/usr/lib/apache2/modules/libphp*.dylib", "/opt/homebrew/opt/php*/lib/httpd/modules/libphp*.so",
]
WINDOWS_BINARY_GLOBS = [
    "C:\\php*\\php*.exe", "C:\\xampp\\php\\php*.exe", "C:\\wamp*\\bin\\php\\php*\\php*.exe",
    "C:\\laragon\\bin\\php\\php*\\php*.exe", "C:\\Program Files\\PHP*\\php*.exe",
    "C:\\Program Files (x86)\\PHP*\\php*.exe", "C:\\tools\\php*\\php*.exe",
    "C:\\Program Files (x86)\\Plesk\\Additional\\PleskPHP*\\php*.exe",
]
_SKIP_NAMES = re.compile(r"(-config|ize|-dbg|-debug|\.(ini|conf|sample|default|1|md|txt|sh|d)$|^php-fpm\.conf)", re.IGNORECASE)


def _is_binary_candidate(path):
    base = os.path.basename(path)
    if _SKIP_NAMES.search(base):
        return False
    try:
        if not stat.S_ISREG(os.stat(path).st_mode):
            return False
    except OSError:
        return False
    low = base.lower()
    if low.endswith((".so", ".dylib", ".dll")):
        return low.startswith("libphp") or "apache" in low
    return bool(_PHP_EXE_RE.match(base))


def discover_files(root=None, notes=None):
    found = []
    if platform.system() == "Windows" and not root:
        patterns = WINDOWS_BINARY_GLOBS
    else:
        patterns = POSIX_BINARY_GLOBS
    for pattern in patterns:
        for path in safe_glob(root, pattern, notes):
            if _is_binary_candidate(path):
                found.append(path)
    return sorted(set(found))


# --- 버전 확인 / 패키지 -----------------------------------------------------------
def exec_version(path, sapi, root=None):
    """정책을 통과한 바이너리만 실행. --root에서는 검사한 파일 디스크립터를 직접 실행한다."""
    base = os.path.basename(path).lower()
    if sapi == "apache":
        return None
    handle = open_regular(path, 120 * 1024 * 1024, root) if root else None
    if root and handle is None:
        return None
    try:
        executable = path
        descriptors = ()
        if handle is not None and os.name != "nt" and sys.platform.startswith("linux"):
            descriptors = (handle.fileno(),)
            executable = "/proc/self/fd/" + str(handle.fileno())
        arguments = ["version"] if base.startswith("frankenphp") else ["-n", "-v"]
        code, out = run([executable] + arguments, pass_fds=descriptors)
    finally:
        if handle is not None:
            handle.close()
    if code is None:
        return None
    match = re.search(r"PHP\s+(\d+\.\d+\.\d+\S*)", out) or re.search(r"(\d+\.\d+\.\d+\S*)", out)
    return match.group(1) if match else None


_POWERED_BY_RE = re.compile(rb"X-Powered-By: PHP/(\d+\.\d+\.\d+[A-Za-z0-9._+~-]*)")


def binary_version(path, limit=120 * 1024 * 1024, root=None):
    """실행 없이 크기가 제한된 일반 파일에서 버전 표지를 읽는다."""
    data = read_bytes(path, min(limit, 120 * 1024 * 1024), root)
    if data is None:
        return None
    match = _POWERED_BY_RE.search(data)
    return match.group(1).decode("ascii", "replace") if match else None


def package_owner(path, pkg):
    """(패키지명, 설치 버전 문자열). 알 수 없으면 (None, None)."""
    if pkg == "apt":
        code, out = run(["dpkg", "-S", path])
        if code == 0 and ":" in out:
            name = out.split(":", 1)[0].split(",")[0].strip().split(":")[0]
            if not valid_package(name):
                return None, None
            _, version = run(["dpkg-query", "-W", "-f=${Version}", name])
            return name, (version or "").strip() or None
    elif pkg in ("dnf", "yum", "zypper"):
        code, out = run(["rpm", "-qf", "--qf", "%{NAME} %{VERSION}-%{RELEASE}\n", path])
        if code == 0 and out.strip() and "not owned" not in out:
            name, _, version = out.strip().splitlines()[0].partition(" ")
            return name, version or None
    elif pkg == "apk":
        code, out = run(["apk", "info", "-W", path])
        match = re.search(r"owned by (\S+)-(\d\S*-r\d+)", out)
        if match:
            return match.group(1), match.group(2)
    elif pkg == "pkg":
        code, out = run(["pkg", "which", path])
        match = re.search(r"was installed by package (\S+)-(\S+)", out)
        if match:
            return match.group(1), match.group(2)
    elif pkg == "brew":
        match = re.search(r"/Cellar/([^/]+)/([^/]+)/", os.path.realpath(path))
        if match:
            return match.group(1), match.group(2)
    return None, None


def vendor_changelog(pkg_manager, name, root=None):
    """deb/rpm 패키지 변경 이력만 읽는다. 압축 해제 크기도 제한한다."""
    if not name or not valid_package(name):
        return None
    if pkg_manager == "apt":
        for doc in ("changelog.Debian.gz", "changelog.gz"):
            handle = open_regular(under(root, "/usr/share/doc/%s/%s" % (name, doc)), 2000000, root)
            if handle is not None:
                try:
                    with handle, gzip.GzipFile(fileobj=handle) as compressed:
                        raw = compressed.read(2000001)
                    if len(raw) > 2000000:
                        return None
                    return "\n".join(line[:4096] for line in raw.decode("utf-8", "replace").splitlines())
                except (OSError, EOFError):
                    return None
    elif not root and pkg_manager in ("dnf", "yum", "zypper"):
        code, out = run(["rpm", "-q", "--changelog", name], timeout=20)
        if code == 0 or out:
            return out
    return None


def vendor_evidence_lines(changelog, advisory):
    """문서의 임의 언급이 아닌 Debian/rpm 변경 이력 엔트리 내부의 근거만 인정."""
    entries, current = [], None
    for raw in (changelog or "").splitlines():
        line = raw[:4096]
        header = (re.match(r"^[A-Za-z0-9][A-Za-z0-9+_.-]* \([^)]+\) [^;]+; urgency=", line) or
                  re.match(r"^\* [A-Z][a-z]{2} [A-Z][a-z]{2} +\d{1,2} \d{4} .+ - \S+", line))
        if header:
            current = []
            entries.append(current)
        elif line.startswith(" -- "):
            current = None
        elif current is not None:
            current.append(line)
    evidence = []
    required = advisory["vendor_patch_evidence_cves"]
    for entry in entries:
        matched = [line for line in entry if any(cve in line.upper() for cve in required)]
        if all(any(cve in line.upper() for line in matched) for cve in required) and not any(
                re.search(r"\b(not (?:yet )?fixed|unfixed|pending|unpatched)\b", line, re.I) for line in matched):
            evidence.extend(clean(line.strip()) for line in matched)
    return evidence


def has_vendor_evidence(changelog, advisory):
    if not changelog:
        return "unknown"
    return "yes" if vendor_evidence_lines(changelog, advisory) else "no"


# --- 설정 점검 -------------------------------------------------------------------
INI_KEYS = ("session.upload_progress.enabled", "memory_limit", "session.auto_start", "post_max_size",
            "upload_max_filesize", "fatal_error_backtraces")
DEFAULTS = {"session.upload_progress.enabled": "1", "memory_limit": "128M", "session.auto_start": "0",
            "post_max_size": "8M", "upload_max_filesize": "2M"}
_TRUE = ("1", "on", "true", "yes")
_FALSE = ("0", "off", "false", "no", "none", "")


def normalize(key, raw):
    value = raw.strip().strip("\"'").strip()
    low = value.lower()
    if key in ("session.upload_progress.enabled", "session.auto_start", "fatal_error_backtraces"):
        if low in _TRUE:
            return "1"
        if low in _FALSE:
            return "0"
    return value


def size_bytes(value):
    match = re.fullmatch(r"(-?\d+)\s*([kKmMgG]?)[bB]?", (value or "")[:4096].strip())
    if not match:
        return None
    number = int(match.group(1))
    unit = match.group(2).lower()
    return number * {"": 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}[unit]


def parse_ini(text, source):
    """php.ini 류 파일에서 관심 키만 {key: (value, source)} 로."""
    result = {}
    for line in (text or "").splitlines():
        line = line[:4096].strip()
        if not line or line[0] in ";#[":
            continue
        key, sep, value = line.partition("=")
        key = key.strip()
        if sep and key in INI_KEYS:
            value = value.partition(";")[0]
            result[key] = (normalize(key, value), source)
    return result


_POOL_RE = re.compile(r"^(php_admin_value|php_admin_flag|php_value|php_flag)\s*\[\s*([\w.]+)\s*\]\s*=\s*(.*)$")
_APACHE_RE = re.compile(r"^(php_admin_value|php_admin_flag|php_value|php_flag)\s+([\w.]+)\s+(.*)$")


def parse_pool_or_vhost(text, source, apache=False):
    """FPM pool 또는 Apache 설정의 php_* 지시어. {key: (value, source, admin)}"""
    pattern = _APACHE_RE if apache else _POOL_RE
    result = {}
    for line in (text or "").splitlines():
        line = line[:4096].strip()
        if line.lstrip().startswith(("#", ";")):
            continue
        match = pattern.match(line)
        if match and match.group(2) in INI_KEYS:
            result[match.group(2)] = (normalize(match.group(2), match.group(3)), source,
                                      match.group(1).startswith("php_admin"))
    return result


def config_files(root, branch_hint=None, notes=None):
    """SAPI별 ini / pool / apache 설정 파일 후보. 반환: {sapi: {"ini":[...], "pool":[...], "apache":[...]}}"""
    def g(*patterns):
        files = []
        for pattern in patterns:
            files.extend(sorted(safe_glob(root, pattern, notes)))
        return files

    result = {"fpm": {"ini": [], "pool": [], "apache": []}, "cgi": {"ini": [], "pool": [], "apache": []},
              "apache": {"ini": [], "pool": [], "apache": []}}
    result["fpm"]["ini"] = g("/etc/php/*/fpm/php.ini", "/etc/php/*/fpm/conf.d/*.ini", "/etc/php.ini", "/etc/php.d/*.ini",
                             "/etc/php[0-9]*/php.ini", "/etc/php[0-9]*/conf.d/*.ini", "/usr/local/etc/php/php.ini",
                             "/usr/local/etc/php/conf.d/*.ini", "/opt/remi/php*/root/etc/php.ini",
                             "/opt/remi/php*/root/etc/php.d/*.ini", "/opt/homebrew/etc/php/*/php.ini",
                             "/opt/homebrew/etc/php/*/conf.d/*.ini")
    result["fpm"]["pool"] = g("/etc/php/*/fpm/pool.d/*.conf", "/etc/php-fpm.d/*.conf", "/usr/local/etc/php-fpm.d/*.conf",
                              "/etc/php[0-9]*/php-fpm.d/*.conf", "/opt/remi/php*/root/etc/php-fpm.d/*.conf",
                              "/opt/homebrew/etc/php/*/php-fpm.d/*.conf")
    result["cgi"]["ini"] = g("/etc/php/*/cgi/php.ini", "/etc/php/*/cgi/conf.d/*.ini") or result["fpm"]["ini"]
    result["apache"]["ini"] = g("/etc/php/*/apache2/php.ini", "/etc/php/*/apache2/conf.d/*.ini") or result["fpm"]["ini"]
    result["apache"]["apache"] = g("/etc/apache2/*.conf", "/etc/apache2/*/*.conf", "/etc/httpd/conf/*.conf",
                                   "/etc/httpd/conf.d/*.conf", "/usr/local/apache2/conf/*.conf",
                                   "/usr/local/apache2/conf/extra/*.conf", "/opt/homebrew/etc/httpd/*.conf",
                                   "/opt/homebrew/etc/httpd/extra/*.conf")
    return result


def evaluate_config(sapi, branch, files, root=None):
    """정적으로 읽은 설정으로 임시 완화 적용 상태를 계산한다. 웹 요청별 실제 값은 알 수 없다."""
    states = {}
    for path in files.get("ini", []):
        for key, (value, source) in parse_ini(read_text(path, root=root), path).items():
            states[key] = {"value": value, "source": source, "admin_locked": False}
    if sapi in ("fpm", "cgi"):
        for path in files.get("pool", []):
            for key, (value, source, admin) in parse_pool_or_vhost(read_text(path, root=root), path).items():
                states[key] = {"value": value, "source": source, "admin_locked": admin}
    if sapi == "apache":
        for path in files.get("apache", []):
            for key, (value, source, admin) in parse_pool_or_vhost(read_text(path, root=root), path, apache=True).items():
                states[key] = {"value": value, "source": source, "admin_locked": admin}
    for key in INI_KEYS:
        if key not in states:
            states[key] = {"value": DEFAULTS.get(key), "source": None, "admin_locked": False,
                           "default": True}
    upload_off = states["session.upload_progress.enabled"]["value"] == "0"
    memory = states["memory_limit"]
    memory_unlimited = memory["value"] == "-1" and memory["admin_locked"]
    backtraces_off = states["fatal_error_backtraces"]["value"] == "0"
    needed = [upload_off, memory_unlimited]
    if branch == "8.5":
        needed.append(backtraces_off)
    applied = sum(1 for item in needed if item)
    status = "interim" if applied == len(needed) else ("partial" if applied else "none")
    notes = []
    if memory["value"] == "-1" and not memory["admin_locked"]:
        notes.append("memory_limit=-1 이 php_admin_value 로 고정되지 않아 애플리케이션이 다시 낮출 수 있습니다.")
    if memory["value"] not in ("-1", None) and memory["source"] and memory["admin_locked"]:
        notes.append("memory_limit 이 관리자 설정으로 유한한 값에 고정되어 있습니다.")
    notes.append("정적 분석입니다. .user.ini, .htaccess, ini_set(), 가상호스트별 값은 반영하지 못합니다.")
    return {"status": status, "settings": states, "notes": notes,
            "files": sorted(set(files.get("ini", []) + files.get("pool", []) + files.get("apache", [])))}


# --- 점검 본체 -------------------------------------------------------------------
def real(path):
    try:
        return os.path.realpath(path)
    except OSError:
        return path


def scan(advisory, root=None, no_exec=False, runner_processes=None, exec_mode="auto"):
    if exec_mode not in ("auto", "never", "all"):
        raise ValueError("exec_mode must be auto, never, or all")
    root = os.path.realpath(root) if root else None
    root_forced = bool(root) and exec_mode != "all" and not no_exec
    policy = ("never" if no_exec or exec_mode == "never" or root_forced else
              "all" if exec_mode == "all" or not privileged() else "trusted-only")
    no_exec = policy == "never"
    info = detect_platform(root)
    if root:
        processes, denied = [], False
        process_visibility = "skipped"
    else:
        processes, denied = (runner_processes or live_processes)()
        process_visibility = "limited" if denied else "full"
    candidates = {}
    scan_notes = []
    for path in discover_files(root, scan_notes):
        resolved = resolve_inside(root, path) if root else real(path)
        if resolved:
            candidates.setdefault(resolved, {"path": resolved if root else path, "pids": [], "units": set(), "start": None, "deleted": False})
    for proc in processes:
        path = proc.get("module") if proc["kind"] == "apache" else proc.get("exe")
        if not path:
            continue
        key = real(path) if os.path.exists(path) else path
        entry = candidates.setdefault(key, {"path": path, "pids": [], "units": set(), "start": None, "deleted": False})
        entry["pids"].append(proc["pid"])
        if proc.get("unit") and (proc["unit"] == "container" or valid_unit(proc["unit"])):
            entry["units"].add(proc["unit"])
        if proc.get("start") and (entry["start"] is None or proc["start"] < entry["start"]):
            entry["start"] = proc["start"]
        if proc.get("deleted") or proc.get("module_deleted"):
            entry["deleted"] = True
    installations = []
    for key in sorted(candidates):
        entry = candidates[key]
        path = entry["path"]
        alias = None
        if not root:
            resolved = real(path)  # 마지막 파일뿐 아니라 부모 디렉터리 링크도 제거한 경로만 실행한다.
            if resolved != path and os.path.exists(resolved):
                alias, path = path, resolved
        sapi = sapi_from_name(path)
        version, version_source = None, None
        executed = False
        exec_note = None
        allowed = not no_exec and not entry["deleted"] and (policy == "all" or trusted_binary(path))
        if no_exec:
            exec_note = "실행 안 함: --root 기본 정책(--exec 로 변경)" if root_forced else "실행 안 함: --no-exec"
        elif entry["deleted"]:
            exec_note = "실행 안 함: 삭제된 프로세스 바이너리"
        elif not allowed:
            exec_note = "실행 안 함: 신뢰할 수 없는 위치(쓰기 가능하거나 소유자가 root/관리자가 아님)"
        if allowed and sapi != "apache" and _is_binary_candidate(path):
            executed = True
            version = exec_version(path, sapi, root)
            version_source = "exec" if version else None
        package, package_version = (None, None)
        if not root:
            package, package_version = package_owner(path, info["pkg"]) if os.path.exists(path) else (None, None)
        if not version and package_version:
            version = package_version
            version_source = "package"
        if not version and os.path.isfile(path):
            version = binary_version(path, root=root)
            version_source = "binary-string" if version else version_source
        if not version and os.name == "nt":
            code, out = run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                             "(Get-Item -LiteralPath %s).VersionInfo.ProductVersion" % ps_literal(path)])
            if code == 0 and parse_version(out):
                version, version_source = out.strip(), "file-version"
        changelog = vendor_changelog(info["pkg"], package, root)
        parsed = parse_version(version or "")
        cls = classify(version or "", advisory)
        # 배포판 패키지는 업스트림 번호가 낡아도 백포트했을 수 있으므로 패키지 변경 이력을 근거로 삼는다.
        vendor = has_vendor_evidence(changelog, advisory) if cls in ("vulnerable", "eol_backport", "eol_no_fix") else "unknown"
        if package and cls in ("vulnerable", "eol_backport", "eol_no_fix") and vendor == "unknown":
            vendor = "unknown"
        verdict = verdict_for(cls, vendor)
        needs_restart = None
        notes = [exec_note] if exec_note else []
        if vendor == "yes":
            notes.extend("벤더 변경 이력 근거: " + line for line in vendor_evidence_lines(changelog, advisory))
        if entry["pids"]:
            needs_restart = False
            try:
                mtime = os.stat(path).st_mtime if os.path.exists(path) else None
            except OSError:
                mtime = None
            if entry["deleted"]:
                needs_restart = True
                notes.append("실행 중인 프로세스가 이미 교체·삭제된 옛 파일을 쓰고 있습니다. 모든 PHP 프로세스를 재시작해야 합니다.")
            elif entry["start"] and mtime and entry["start"] < mtime - 60:
                needs_restart = True
                notes.append("바이너리가 프로세스 시작 이후에 바뀌었습니다. 옛 코드가 계속 실행 중일 수 있어 재시작이 필요합니다.")
        if not version:
            notes.append("버전을 확인하지 못했습니다" + (" (--root 에서는 바이너리를 실행하지 않습니다. 신뢰할 수 있는 트리라면 --exec)" if root_forced
                                                           else " (--no-exec)" if no_exec else "") + ".")
        if sapi == "apache" and version_source == "package":
            notes.append("mod_php 는 가장 위험한 SAPI 입니다(요청 처리 전에 공격이 가능).")
        installation = {
            "path": path, "alias": alias, "version": version, "class": cls, "verdict": verdict, "sapi": sapi,
            "exposure": "cli" if sapi == "cli" else "web", "running": bool(entry["pids"]),
            "pids": sorted(entry["pids"]), "units": sorted(entry["units"]), "package": package,
            "vendor_patch": vendor, "needs_restart": needs_restart, "notes": notes,
            "version_source": version_source, "exec_note": exec_note, "executed": executed,
        }
        if sapi in ("fpm", "cgi", "apache") and parsed:
            branch = "%d.%d" % (parsed[0], parsed[1])
            files = config_files(root, notes=scan_notes).get(sapi, {})
            installation["mitigation"] = evaluate_config(sapi, branch, files, root)
            installation["mitigation"]["branch"] = branch
        installations.append(installation)
    summary = {"vulnerable": 0, "fixed": 0, "vendor_patched": 0, "eol": 0, "unknown": 0, "needs_restart": 0}
    for item in installations:
        summary[item["verdict"]] += 1
        if item["needs_restart"]:
            summary["needs_restart"] += 1
    action = summary["vulnerable"] + summary["eol"] + summary["needs_restart"]
    if action:
        exit_code = 1
    elif not installations and process_visibility == "limited":
        exit_code = 3
    elif summary["unknown"]:
        exit_code = 3
    else:
        exit_code = 0
    return {
        "tool": TOOL, "tool_version": __version__, "as_of": advisory["as_of"], "host": socket.gethostname(),
        "platform": info["pretty"], "package_manager": info["pkg"], "container": info["container"],
        "process_visibility": process_visibility, "installations": installations, "summary": summary,
        "exit_code": exit_code, "exec_policy": policy, "notes": sorted(set(scan_notes)),
        "advisory_source": getattr(advisory, "source", {"path": "provided-api", "sha256": hashlib.sha256(
            json.dumps(advisory, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest(), "custom": True}),
    }, info


# --- 대응 옵션 -------------------------------------------------------------------
DOCS_HINT = "docs/response-options.ko.md"
OPTIONS = [
    ("patch-online", "A. 온라인 패치 (패키지 업데이트)"),
    ("patch-offline", "B. 오프라인·폐쇄망 패치"),
    ("container", "C. 컨테이너 이미지 재빌드·재배포"),
    ("source", "D. 소스 빌드 (7.4/8.0/8.1 은 PHP 보안팀 백포트 브랜치)"),
    ("vendor", "E. 벤더·호스팅·장비 제조사에 패치 요청"),
    ("virtual-patch", "F. 가상 패치 (WAF·웹서버·PHP·OS 임시 대응)"),
    ("isolate", "G. 노출 축소·서비스 중단"),
    ("contain", "H. 사후 피해 억제·탐지"),
    ("migrate", "I. 지원 버전으로 이전"),
    ("restart", "R. 재시작 (패치 후 반드시)"),
]
OPTION_TITLE = dict(OPTIONS)


def detect_webservers(root=None):
    """설정 파일 존재로 웹서버 종류를 짐작한다 (가상 패치 파일 선택용)."""
    found = []
    checks = (("nginx", ("/etc/nginx/nginx.conf", "/usr/local/etc/nginx/nginx.conf", "/opt/homebrew/etc/nginx/nginx.conf")),
              ("apache", ("/etc/apache2/apache2.conf", "/etc/httpd/conf/httpd.conf", "/usr/local/apache2/conf/httpd.conf",
                          "/opt/homebrew/etc/httpd/httpd.conf")),
              ("litespeed", ("/usr/local/lsws/conf/httpd_config.xml",)),
              ("iis", ("C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config",)))
    for name, paths in checks:
        if any((resolve_inside(root, under(root, path)) if root else os.path.exists(path)) for path in paths):
            found.append(name)
    return found


def situation(result, info):
    items = result["installations"]
    bad = [i for i in items if i["verdict"] in ("vulnerable", "eol")]
    return {
        "bad": bad,
        "supported_vuln": [i for i in bad if i["class"] == "vulnerable"],
        "eol_backport": [i for i in bad if i["class"] == "eol_backport"],
        "eol_nofix": [i for i in bad if i["class"] in ("eol_no_fix", "old_unsupported")],
        "unknown": [i for i in items if i["verdict"] == "unknown"],
        "restart": [i for i in items if i["needs_restart"]],
        "mod_php": [i for i in bad if i["sapi"] == "apache" and i["running"]],
        "container": bool(info.get("container")),
        "pkg": info.get("pkg"),
    }


def recommend(sit, mode):
    """시스템 분석 결과로 대응 옵션의 권장 순서를 정한다. [(옵션 id, [이유...])]"""
    order, why = [], {}

    def add(option, reason):
        if option not in order:
            order.append(option)
        why.setdefault(option, []).append(reason)

    if sit["supported_vuln"]:
        if sit["container"]:
            add("container", "컨테이너 안에서 실행 중입니다. 이미지를 수정 버전으로 다시 빌드해 재배포하는 것이 정석입니다.")
        if mode == "offline":
            add("patch-offline", "인터넷이 없는 환경으로 지정했습니다(--mode offline). 연결된 PC에서 패키지를 받아 반입합니다.")
        else:
            add("patch-online", "지원되는 브랜치(8.2~8.5)의 수정 전 버전입니다. 업데이트가 유일한 근본 조치입니다.")
    if sit["eol_backport"]:
        add("vendor", "7.4/8.0/8.1 은 공식 릴리스가 없습니다. 배포판·LTS 벤더의 패치 제공 여부를 먼저 확인하세요.")
        add("source", "벤더 패치가 없으면 PHP 보안팀 백포트 브랜치로 소스 빌드할 수 있습니다.")
        add("migrate", "근본적으로는 지원 버전(8.3 이상)으로 이전해야 합니다.")
    if sit["eol_nofix"]:
        add("migrate", "5.x/7.0~7.3 은 수정이 어디에도 없습니다. 지원 버전으로 이전해야 합니다.")
    if sit["bad"]:
        if sit["mod_php"] or sit["eol_nofix"]:
            reason = "mod_php 가 실행 중이라 요청 처리 전에 공격이 가능합니다." if sit["mod_php"] else "수정 버전이 없어 패치로 해결할 수 없습니다."
            add("isolate", reason + " 패치 전까지 외부 노출을 줄이거나 서비스를 일시 중단하는 것을 검토하세요 (KISA 수칙 4).")
        add("virtual-patch", "패치 전까지의 시간 벌기입니다. 완전한 해결이 아니며 우회가 쉽습니다.")
        add("contain", "성공한 공격의 피해를 줄이고 흔적을 잡기 위한 보조 수단입니다.")
    if sit["supported_vuln"] or sit["restart"]:
        add("restart", "패치 후 모든 PHP 프로세스를 재시작하지 않으면 옛 코드가 계속 실행됩니다 (KISA 수칙 2).")
    if sit["unknown"] and not order:
        add("vendor", "버전을 확인하지 못한 설치가 있습니다. root 로 --no-exec 없이 다시 점검하거나 담당자에게 확인하세요.")
    return [(option, why[option]) for option in order]


def _update_steps(sit, info):
    pkg = info.get("pkg")
    packages = sorted({i["package"] for i in sit["bad"] if i["package"] and valid_package(i["package"])})
    names = " ".join(shlex.quote(name) for name in packages) if packages else None
    if pkg == "windows":
        return ["https://windows.php.net/download 에서 수정 버전 ZIP 을 받아 페이지의 SHA256 과 대조 (Apache 는 Thread Safe, IIS FastCGI 는 Non Thread Safe)",
                "사이트/앱 풀 중지(iisreset /stop 또는 Stop-Service Apache2.4) -> PHP 폴더 교체(php.ini 보존, 이전 폴더는 이름을 바꿔 보관) -> 시작",
                "XAMPP/WAMP/Laragon 은 해당 배포판의 업데이트를 사용"]
    if pkg == "apt":
        return ["sudo apt-get update", "sudo apt-get install --only-upgrade %s" % (names or "'php*'"),
                "apt list --upgradable 2>/dev/null | grep -i php   # 남은 PHP 패키지 확인"]
    if pkg in ("dnf", "yum"):
        return ["sudo %s upgrade --refresh %s" % (pkg, names or "'php*'")]
    if pkg == "apk":
        return ["sudo apk update && sudo apk upgrade %s" % (names or "'php*'")]
    if pkg == "zypper":
        return ["sudo zypper refresh", "sudo zypper update %s" % (names or "'php*'")]
    if pkg == "pkg":
        return ["sudo pkg update && sudo pkg upgrade %s" % (names or "'php*'")]
    if pkg == "brew":
        return ["brew update", "brew upgrade php   # 또는 php@8.x 포뮬러"]
    return ["패키지 관리자를 식별하지 못했습니다. 배포판 보안 공지에서 수정 패키지를 확인하세요."]


def _offline_steps(info):
    pkg = info.get("pkg")
    download = {
        "apt": "apt-get install --download-only <패키지>  (또는 apt-get download <패키지와 의존성>)",
        "dnf": "dnf download --resolve --alldeps <패키지>",
        "yum": "yumdownloader --resolve --destdir=<디렉터리> <패키지>   (yum-utils 필요)",
        "apk": "apk fetch -R -o <디렉터리> <패키지>",
        "zypper": "zypper install --download-only <패키지>",
        "pkg": "pkg fetch -d <패키지>",
    }.get(pkg)
    install = {
        "apt": "sudo apt-get install ./*.deb   (또는 sudo dpkg -i *.deb)",
        "dnf": "sudo dnf install ./*.rpm",
        "yum": "sudo yum localinstall ./*.rpm",
        "apk": "sudo apk add ./*.apk   (서명 검증이 실패하면 해시를 별도 경로로 확인한 뒤에만 --allow-untrusted)",
        "zypper": "sudo zypper install ./*.rpm",
        "pkg": "sudo pkg add <받은 파일>",
    }.get(pkg)
    if pkg == "windows":
        steps = ["인터넷이 되는 PC에서 windows.php.net 의 수정 버전 ZIP 과 SHA256 을 받아 `Get-FileHash -Algorithm SHA256 <zip>` 으로 대조",
                 "이동 매체로 반입 -> 사이트/서비스 중지 -> PHP 폴더 교체(php.ini 보존) -> 시작 (VC++ 재배포 가능 패키지 요구사항 확인)"]
    else:
        steps = ["대상 서버에서 현재 PHP 패키지 이름과 버전을 기록 (예: dpkg-query -W 'php*' / rpm -qa 'php*' / apk info -v | grep php)",
                 "인터넷이 되는 같은 배포판·같은 CPU 아키텍처의 PC 또는 컨테이너에서 수정 패키지와 의존성을 내려받기"
                 + ((": " + download) if download else ""),
                 "내려받은 파일의 체크섬·서명을 배포판이 공개한 값과 별도 경로로 대조하고 대조한 해시를 기록",
                 "이동 매체로 반입 (매체 자체는 신뢰하지 말고 반입 후 해시를 다시 확인)",
                 "대상 서버에서 설치" + ((": " + install) if install else ""),
                 "모든 PHP 프로세스를 재시작한 뒤 변경 이력에서 CVE 번호를 확인"]
    steps.append("컨테이너 이미지는 `docker pull` -> `docker save` 로 반출, `docker load` 로 반입하고 digest 를 비교")
    steps.append("자세한 절차와 검증 결과: docs/offline-patching.ko.md")
    return steps


def option_detail(option, sit, info, advisory, webservers):
    fixed = advisory["fixed_releases"]
    branches = []
    for item in sit["bad"]:
        parsed = parse_version(item["version"] or "")
        if parsed:
            branches.append("%d.%d" % parsed[:2])
    branches = sorted(set(branches))
    if option == "patch-online":
        return {"steps": _update_steps(sit, info) + [
            "Ondřej Surý·Remi 같은 서드파티 저장소를 쓰는 경우 그 저장소가 수정 패키지를 제공하는지 변경 이력으로 확인 (%s)" % " / ".join(advisory["cves"]),
            "수정 버전: " + ", ".join("%s -> %s" % (k, fixed[k]) for k in ("8.2", "8.3", "8.4", "8.5")) + " 이상 (8.2 는 2026-12-31 보안 지원 종료)"]}
    if option == "patch-offline":
        return {"steps": _offline_steps(info)}
    if option == "container":
        tag = fixed.get(branches[0], fixed["8.4"]) if branches else fixed["8.4"]
        return {"steps": ["Dockerfile 의 베이스를 수정 버전으로 변경: FROM php:%s-<fpm|apache|cli>   (태그가 존재하는지 먼저 확인)" % tag,
                          "docker build --pull --no-cache -t <이름>:<새 태그> . -> 레지스트리 푸시 -> 재배포 (실행 중 컨테이너 안에서 패키지만 올리면 이미지에는 남지 않습니다)",
                          "검증: docker run --rm <이미지> php -v, 또는 이 도구를 컨테이너 안에서 실행",
                          "공식 이미지가 아닌 외부 이미지는 제작자의 재빌드 공지를 확인"]}
    if option == "source":
        urls = advisory.get("source_backport_urls", {})
        return {"steps": ["현재 빌드 옵션 확인: php -i | grep 'Configure Command' (같은 옵션으로 다시 빌드)",
                          "지원 브랜치: php.net 의 수정 버전 소스(%s)를 받아 해시/서명을 확인한 뒤 빌드" % ", ".join(fixed[k] for k in ("8.2", "8.3", "8.4", "8.5")),
                          "7.4/8.0/8.1: PHP 보안팀 백포트 브랜치 " + ", ".join("%s(%s)" % (k, v) for k, v in sorted(urls.items()))
                          + " (최소 백포트이며 공식 릴리스·바이너리가 아닙니다)",
                          "빌드 후 테스트 환경에서 검증 -> 설치 -> 모든 PHP 프로세스 재시작"]}
    if option == "vendor":
        return {"steps": ["PHP 를 관리하는 주체(호스팅 업체, 장비·솔루션 제조사, 외주 개발사)에 수정 패키지 제공 여부와 적용 일정을 문서로 요청",
                          "요청 시 묻기: 대상 CVE(%s), 현재 PHP 버전과 SAPI, 백포트 여부와 변경 이력, 임시 완화 적용 여부" % ", ".join(advisory["cves"]),
                          "제조사 현황 확인처: KISA 보호나라 보안공지, NCSC-NL 소프트웨어 목록(https://github.com/NCSC-NL/php2shell)"]}
    if option == "virtual-patch":
        detected = ", ".join(webservers) if webservers else "감지 못함"
        return {"steps": ["감지된 웹서버: %s. 이 서버용 설정 파일을 만들려면: python3 php2shell_triage.py --emit-virtual-patch ./virtual-patch-out --uploads yes|no" % detected,
                          "계층: 요청 크기·필드 수 제한 / `PHP_SESSION_UPLOAD_PROGRESS` 표지·깊은 중첩·빈 filename 대량 multipart 차단(WAF) / php_admin_* 설정 / cgroup 메모리 상한 / (업로드가 없으면) multipart 차단",
                          "ModSecurity 는 DetectionOnly 로 먼저 적용해 오탐을 확인한 뒤 차단으로 전환",
                          "한계: PHP 는 '완전한 완화책은 없다'고 밝혔습니다. 문자셋 변형·RFC 2231/5987 인코딩 등으로 우회될 수 있으니 패치 전까지의 시간 벌기로만 쓰세요.",
                          "memory_limit=-1 은 반드시 OS 수준 메모리 상한과 함께, RLIMIT_AS/RLIMIT_DATA 는 쓰지 마세요. session.auto_start=0 은 $_SESSION 을 session_start() 없이 쓰는 페이지를 깨뜨릴 수 있습니다.",
                          "자세한 내용: virtual-patch/README.ko.md, docs/virtual-patching.ko.md"]}
    if option == "isolate":
        return {"steps": ["유지보수 페이지로 전환하거나, 관리자·내부망 IP만 허용(웹서버 allow/deny 또는 방화벽)하거나, VPN 뒤로 이동",
                          "그래도 어렵다면 외부 접속 차단 또는 서비스 일시 중단 (KISA 수칙 4)",
                          "침해가 의심되는 서버는 재시작하지 말고 외부 접속만 차단하세요 (증거 보존)"]}
    if option == "contain":
        return {"steps": ["웹 서버 계정의 신규 외부 연결 차단·허용목록화 (virtual-patch/os/nftables-egress-example.nft)",
                          "SELinux/AppArmor 로 php-fpm·httpd 제한 (virtual-patch/os/selinux-apparmor-notes.ko.md), 업로드·임시 디렉터리 noexec, 컨테이너는 read-only 루트",
                          "웹 계정의 execve·웹 루트 쓰기 감사 (virtual-patch/os/auditd-php2shell.rules), 웹 루트 무결성 감시",
                          "%s 이후 로그 점검(docs/runbook.ko.md)과 DB 비밀번호·API 키·세션 키 교체 — 로그에 이상이 없어도 안전이 보장되지 않습니다" % advisory["log_review_since_default"]]}
    if option == "migrate":
        return {"steps": ["지원 버전(8.3 이상 권장, 8.2 는 2026-12-31 종료)으로 이전 계획 수립: 확장 모듈·프레임워크 호환성, 스테이징 테스트",
                          "이전 전까지는 벤더 패치(E) 또는 소스 백포트(D)와 가상 패치(F), 노출 축소(G)를 함께 적용"]}
    if option == "restart":
        steps = []
        for item in sit["bad"] + sit["restart"]:
            for unit in item["units"]:
                if unit == "container":
                    steps.append("컨테이너 이미지를 재배포 (컨테이너 안에서 재시작만으로는 새 이미지가 되지 않음)")
                elif valid_unit(unit):
                    steps.append("sudo systemctl restart %s" % shlex.quote(unit))
        steps = sorted(set(steps)) or ["PHP 를 쓰는 모든 서비스(PHP-FPM, Apache mod_php, php-cgi, FrankenPHP, LiteSpeed)를 재시작"]
        steps += ["확인: 이 도구를 다시 실행하거나 웹 프로세스의 /proc/<pid>/exe 와 시작 시각을 확인 (`php -v` 는 CLI 만 보여 줍니다)",
                  "침해가 의심되면 재시작 전에 증거(로그, 프로세스 목록, 네트워크 연결)를 먼저 보존"]
        return {"steps": steps}
    return {"steps": []}


def build_response(result, info, advisory, mode="online", uploads="unknown", root=None):
    sit = situation(result, info)
    recommended = recommend(sit, mode)
    webservers = detect_webservers(root)
    details = {}
    for option, _ in recommended:
        details[option] = option_detail(option, sit, info, advisory, webservers)
        details[option]["title"] = OPTION_TITLE[option]
    return {
        "mode": mode, "uploads": uploads, "webservers": webservers,
        "recommended": [{"id": option, "title": OPTION_TITLE[option], "why": reasons} for option, reasons in recommended],
        "details": details,
        "others": [{"id": key, "title": title} for key, title in OPTIONS if key not in details],
        "evidence_order_ko": "침해 의심 시: ① 격리(재시작 금지, 외부 접속만 차단) ② 신고(KISA 보호나라, 국번 없이 118) ③ 증거 확보 ④ 조치 (KISA 수칙 7). "
                             "신고와 증거 확보는 병행하세요. 법정 신고 기한은 증거 수집을 기다려 주지 않습니다 (docs/contacts.ko.md).",
        "docs": DOCS_HINT,
    }


def safe_parent(path):
    """출력 부모를 0700으로 만들고 링크를 거부한다. POSIX에서는 dirfd로 경쟁을 막는다."""
    absolute = os.path.abspath(path)
    if sys.platform == "darwin":
        # macOS의 root 소유 OS 별칭만 허용한다. 사용자 제공 부모 링크는 계속 거부한다.
        for alias in ("/var", "/tmp", "/etc"):
            if absolute.startswith(alias + "/") and os.path.islink(alias) and os.lstat(alias).st_uid == 0:
                absolute = os.path.realpath(alias) + absolute[len(alias):]
    parent, name = os.path.dirname(absolute), os.path.basename(absolute)
    if not name:
        raise ValueError("출력 파일 이름이 없습니다")
    if os.name == "nt":
        drive, rest = os.path.splitdrive(parent)
        current = drive + os.sep
        for component in rest.strip(os.sep).split(os.sep):
            if not component:
                continue
            current = os.path.join(current, component)
            try:
                os.mkdir(current, 0o700)
            except FileExistsError:
                pass
            info = os.lstat(current)
            if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise OSError("출력 경로 링크/재분석 지점 거부: " + clean(current))
        return None, absolute
    # 각 부모는 NOFOLLOW로 열어 검사 이후 바꿔치기도 거부한다.
    directory = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in parent.strip(os.sep).split(os.sep):
            if not component:
                continue
            try:
                os.mkdir(component, 0o700, dir_fd=directory)
            except FileExistsError:
                pass
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        return directory, name
    except BaseException:
        os.close(directory)
        raise


def safe_write(path, text, force=False, script=False, encoding="utf-8"):
    """기존 파일은 명시적 force로만 교체. 링크는 force로도 거부하고 절대 truncate하지 않는다."""
    directory, target = safe_parent(path)
    kwargs = {"dir_fd": directory} if directory is not None else {}
    fd = None
    try:
        try:
            existing = os.stat(target, follow_symlinks=False, **kwargs)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if not force or not stat.S_ISREG(existing.st_mode) or getattr(existing, "st_file_attributes", 0) & 0x400:
                raise FileExistsError("기존 파일/링크를 덮어쓰지 않습니다 (--force): " + clean(path))
            os.unlink(target, **kwargs)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        fd = os.open(target, flags, 0o700 if script else 0o600, **kwargs)
        if os.name != "nt":
            os.fchmod(fd, 0o700 if script else 0o600)
        with os.fdopen(fd, "wb") as handle:
            fd = None
            handle.write(text.encode(encoding))
    finally:
        if fd is not None:
            os.close(fd)
        if directory is not None:
            os.close(directory)


def display_data(value, markdown=False):
    """구조는 유지하되 모든 동적 표시 문자열을 먼저 정리한다. JSON에는 적용하지 않는다."""
    if isinstance(value, str):
        return markdown_value(value) if markdown else clean(value)
    if isinstance(value, dict):
        return {key: display_data(child, markdown) for key, child in value.items()}
    if isinstance(value, list):
        return [display_data(child, markdown) for child in value]
    return value


def emit_virtual_patch(out_dir, uploads, force=False):
    """저장소의 virtual-patch/ 템플릿에 값을 채워 out_dir 로 복사한다. 점검 대상 서버 설정은 건드리지 않는다."""
    here = os.path.dirname(os.path.abspath(__file__))
    source = os.path.join(here, "virtual-patch")
    if not os.path.isdir(source):
        raise SystemExit("virtual-patch/ 디렉터리를 찾을 수 없습니다. 저장소 전체(ZIP)를 내려받아 실행하세요.")
    heavy = uploads == "yes"
    tokens = {"@@POST_MAX_BYTES@@": "33554432" if heavy else "8388608",
              "@@POST_MAX@@": "32M" if heavy else "8M", "@@UPLOAD_MAX@@": "20M" if heavy else "2M"}
    written = []
    for folder, _, names in os.walk(source):
        for name in sorted(names):
            if "block-multipart" in name and uploads != "no":
                continue
            src = os.path.join(folder, name)
            dst = os.path.join(out_dir, os.path.relpath(src, source))
            text = read_text(src)
            if text is None:
                raise OSError("템플릿을 읽을 수 없습니다: " + clean(src))
            for token, value in tokens.items():
                text = text.replace(token, value)
            safe_write(dst, text, force=force)
            written.append(dst)
    return sorted(written)


# --- 출력 ------------------------------------------------------------------------
def render_text(result, response, advisory):
    result, response, advisory = [display_data(value) for value in (result, response, advisory)]
    lines = ["PHP2Shell 점검 (%s) — %s, %s, 권고 기준일 %s" % (TOOL, result["host"], result["platform"], advisory["as_of"]),
             "대상 CVE: %s (CVSS v4.0 %s). 서버 설정·패키지를 바꾸지 않습니다. 신뢰할 수 있는 PHP 바이너리만 -n -v 로 실행합니다(--no-exec 로 끌 수 있음)." % (", ".join(advisory["cves"]), advisory["cvss_v4"]),
             ""]
    source = result.get("advisory_source")
    if source:
        lines.append("권고 데이터: %s / SHA256 %s" % (source["path"], source["sha256"]))
        if source.get("custom"):
            lines.append("주의: 사용자 지정 권고 데이터입니다. 출처와 SHA256을 별도 경로로 확인하세요.")
    lines.append("바이너리 실행 정책: " + result.get("exec_policy", "unknown"))
    lines.extend("주의: " + note for note in result.get("notes", []))
    if result["process_visibility"] == "limited":
        lines.append("주의: 일부 프로세스를 읽지 못했습니다. root 권한으로 다시 실행하면 더 정확합니다.")
    if not result["installations"]:
        lines.append("PHP 설치를 찾지 못했습니다.")
    for item in result["installations"]:
        lines.append("[%s] %s  %s  (SAPI: %s%s)" % (VERDICT_KO[item["verdict"]], item["path"], item["version"] or "버전 미확인",
                                                    item["sapi"], ", 실행 중 pid " + ",".join(str(p) for p in item["pids"][:6]) if item["pids"] else ""))
        lines.append("    분류: %s" % CLASS_KO[item["class"]])
        if item["package"]:
            lines.append("    패키지: %s, 벤더 패치 근거: %s" % (item["package"], {"yes": "있음", "no": "없음", "unknown": "확인 불가"}[item["vendor_patch"]]))
        if item["needs_restart"]:
            lines.append("    재시작 필요: 예")
        mitigation = item.get("mitigation")
        if mitigation:
            label = {"interim": "임시 완화 적용됨(그래도 업데이트 필요)", "partial": "일부만 적용", "none": "적용 안 됨"}[mitigation["status"]]
            lines.append("    임시 완화: %s" % label)
            for key in ("session.upload_progress.enabled", "memory_limit", "session.auto_start", "post_max_size"):
                state = mitigation["settings"][key]
                lines.append("      - %s = %s%s%s" % (key, state["value"], " (관리자 고정)" if state["admin_locked"] else "",
                                                       " (기본값)" if state.get("default") else ""))
        for note in item["notes"]:
            lines.append("    * " + note)
    summary = result["summary"]
    lines += ["", "요약: 취약 %d, EOL %d, 수정됨 %d, 벤더 패치 %d, 확인 필요 %d, 재시작 필요 %d" % (
        summary["vulnerable"], summary["eol"], summary["fixed"], summary["vendor_patched"], summary["unknown"], summary["needs_restart"])]
    if result["exit_code"] == 0 and result["installations"]:
        lines.append("판정: 확인한 범위에서 조치가 필요한 설치는 없습니다. 로그 점검과 인증정보 교체는 별도로 진행하세요.")
    elif result["exit_code"] == 3:
        lines.append("판정: 확인 불가. 권한 또는 환경 때문에 결론을 내리지 못했습니다.")
    elif result["exit_code"] == 1:
        lines.append("판정: 조치가 필요합니다. 임시 완화는 완전한 해결이 아닙니다.")
    if response and response["recommended"]:
        lines += ["", "=== 권장 대응 순서 (시스템 분석 기준 / 조치는 자동 실행하지 않습니다) ==="]
        for index, item in enumerate(response["recommended"], 1):
            lines.append("%d. %s" % (index, item["title"]))
            lines += ["     이유: " + reason for reason in item["why"]]
        for item in response["recommended"]:
            lines += ["", "[%s]" % item["title"]] + ["  - " + step for step in response["details"][item["id"]]["steps"]]
        lines += ["", response["evidence_order_ko"]]
        if response["others"]:
            lines += ["", "그 밖의 선택지: " + " / ".join(item["title"] for item in response["others"]),
                      "전체 안내: %s (--mode offline 폐쇄망 / --uploads yes|no 업로드 여부 / --emit-virtual-patch DIR 가상 패치 파일 생성)" % response["docs"]]
    lines += ["", "출처:"] + ["  - %s <%s>" % (src["title"], src["url"]) for src in advisory["sources"]]
    return "\n".join(lines) + "\n"


def render_markdown(result, response, advisory):
    result, response, advisory = [display_data(value, markdown=True) for value in (result, response, advisory)]
    lines = ["# PHP2Shell 점검 보고", "", "- 호스트: `%s` / %s" % (result["host"], result["platform"]),
             "- 권고 기준일: %s / CVE: %s" % (advisory["as_of"], ", ".join(advisory["cves"])),
             "- 종료 코드: %d" % result["exit_code"], "", "| 판정 | 경로 | 버전 | SAPI | 실행 중 | 재시작 필요 |", "| --- | --- | --- | --- | --- | --- |"]
    for item in result["installations"]:
        lines.append("| %s | `%s` | %s | %s | %s | %s |" % (VERDICT_KO[item["verdict"]], item["path"], item["version"] or "-", item["sapi"],
                                                         "예" if item["running"] else "아니오", {True: "예", False: "아니오", None: "-"}[item["needs_restart"]]))
    lines.append("")
    for item in result["installations"]:
        lines.extend("- 근거/주의 (%s): %s" % (item["path"], note) for note in item.get("notes", []))
    source = result.get("advisory_source")
    if source:
        lines += ["", "- 권고 데이터: %s / SHA256 %s" % (source["path"], source["sha256"])]
        if source.get("custom"):
            lines.append("- 주의: 사용자 지정 권고 데이터. 출처와 SHA256을 별도 경로로 확인하세요.")
    lines.extend("- 주의: " + note for note in result.get("notes", []))
    if response and response["recommended"]:
        lines += ["", "## 권장 대응 순서"]
        for index, item in enumerate(response["recommended"], 1):
            lines.append("%d. %s — %s" % (index, item["title"], " ".join(item["why"])))
        for item in response["recommended"]:
            lines += ["", "### " + item["title"]] + ["- " + step for step in response["details"][item["id"]]["steps"]]
        lines += ["", "> " + response["evidence_order_ko"]]
    return "\n".join(lines) + "\n"


CATALOG = [
    ("patch-online", "인터넷이 되는 서버에서 패키지 관리자로 수정 버전 설치 (가장 빠른 근본 조치)"),
    ("patch-offline", "인터넷이 없는 서버: 연결된 PC에서 패키지/ZIP/이미지를 받아 해시 대조 후 반입·설치"),
    ("container", "이미지를 수정 버전 베이스로 재빌드·재배포"),
    ("source", "소스 빌드. 7.4/8.0/8.1 은 PHP 보안팀 백포트 브랜치"),
    ("vendor", "호스팅·장비 제조사·외주 개발사에 패치 요청 (PHP 내장 제품)"),
    ("virtual-patch", "패치 전까지 WAF·웹서버·PHP 설정·OS 상한으로 공격 경로를 줄임 (우회 가능, 시간 벌기)"),
    ("isolate", "점검 페이지, IP 허용목록, VPN, 서비스 일시 중단"),
    ("contain", "외부 통신 차단, SELinux/AppArmor, noexec, 감사 로그, 인증정보 교체"),
    ("migrate", "지원 버전(8.3 이상)으로 이전"),
    ("restart", "패치 후 모든 PHP 프로세스 재시작"),
]


def render_catalog():
    lines = ["PHP2Shell 대응 옵션 목록 (시스템 점검 없이 보기). 상황별 권장 순서는 점검 결과에서 계산됩니다.", ""]
    for key, text in CATALOG:
        lines.append("%-26s %s" % (OPTION_TITLE[key], text))
    lines += ["", "자세한 안내: %s, docs/offline-patching.ko.md, docs/virtual-patching.ko.md, docs/runbook.ko.md" % DOCS_HINT,
              "완전한 완화책은 없고 업데이트만이 근본 조치입니다 (PHP 공식 입장)."]
    return "\n".join(lines) + "\n"




# --- 맞춤 패치 계획 파일 ----------------------------------------------------------
# 이 도구는 패치를 직접 적용하지 않습니다(체계관리자 책임). 대신 '분석한 이 시스템'에 맞춘 명령을
# 관리자가 검토하며 한 단계씩 실행하는 파일로 만들어 줍니다. 생성된 스크립트는 검토 확인 전에는 실행되지 않습니다.
PLAN_GUARD_ENV = "PHP2SHELL_I_REVIEWED"
PLAN_GUARD_EXIT = 64


def _plan_context(result, info):
    items = result["installations"]
    bad = [i for i in items if i["verdict"] in ("vulnerable", "eol")]
    dirname = ntpath.dirname if info.get("pkg") == "windows" else os.path.dirname
    ctx = {
        "bad": bad,
        "packages": sorted({i["package"] for i in bad if i["package"] and valid_package(i["package"])}),
        "units": sorted({u for i in items if i["running"] for u in i["units"] if valid_unit(u)}),
        "container": bool(info.get("container")) or any("container" in i["units"] for i in items),
        "unpackaged": [i for i in bad if not i["package"]],
        "config_dirs": sorted({os.path.dirname(f) for i in items for f in (i.get("mitigation") or {}).get("files", [])}),
        "install_dirs": sorted({dirname(i["path"]) for i in items}),
        "log_dirs": [p for p in ("/var/log/apache2", "/var/log/httpd", "/var/log/nginx", "/var/log/php-fpm", "/var/log/php") if os.path.isdir(p)],
        "pkg": info.get("pkg"),
    }
    return ctx


def build_patch_plan(result, info, advisory, mode="online"):
    """맞춤 패치 단계 목록. 각 단계: {"title", "notes":[...], "commands":[...]} (windows 는 PowerShell 명령)."""
    ctx = _plan_context(result, info)
    pkg = ctx["pkg"]
    windows = pkg == "windows"
    cves = " ".join(advisory["cves"])
    steps = []
    if windows:
        steps.append({"title": "침해 의심 시 증거 먼저 보존 (의심이 없으면 건너뜀)", "notes": [
            "침해가 의심되면 재시작·교체 전에 이 단계를 먼저 하세요 (KISA 수칙 7: 서버를 재시작하면 메모리 흔적이 사라집니다)."], "commands": [
            "$ev = \".\\php2shell-evidence-$(Get-Date -Format yyyyMMdd-HHmmss)\"; New-Item -ItemType Directory -Path $ev -ErrorAction Stop | Out-Null",
            "& \"$env:SystemRoot\\System32\\icacls.exe\" $ev /inheritance:r /grant:r 'Administrators:(OI)(CI)F' 'SYSTEM:(OI)(CI)F'; if ($LASTEXITCODE -ne 0) { throw 'Evidence ACL failed' }",
            "Get-Process | Select-Object Id,ProcessName,Path,StartTime | Export-Csv \"$ev\\processes.csv\" -NoTypeInformation",
            "Get-NetTCPConnection | Export-Csv \"$ev\\tcp.csv\" -NoTypeInformation",
            "Copy-Item 'C:\\inetpub\\logs\\LogFiles' -Destination $ev -Recurse -ErrorAction SilentlyContinue",
            "@(Get-ChildItem $ev -Recurse -File) | Get-FileHash -Algorithm SHA256 | Export-Csv \"$ev\\SHA256.csv\" -NoTypeInformation"]})
        backups = ["Copy-Item -Recurse -LiteralPath %s -Destination (%s + '.bak-' + (Get-Date -Format yyyyMMdd))" %
                   (ps_literal(d), ps_literal(d)) for d in ctx["install_dirs"]]
        steps.append({"title": "현재 상태 기록·백업", "notes": ["PHP 폴더(php.ini 포함)를 통째로 백업합니다."], "commands": backups or ["# PHP 폴더를 찾지 못했습니다. 설치 경로를 직접 확인하세요."]})
        steps.append({"title": "수정 버전 내려받기 (수동)", "notes": [
            "https://windows.php.net/download 에서 수정 버전(%s)을 받습니다. Apache(mod_php)는 Thread Safe, IIS FastCGI(php-cgi)는 Non Thread Safe." % ", ".join(
                advisory["fixed_releases"][k] for k in ("8.5", "8.4", "8.3", "8.2")),
            "페이지에 표시된 SHA256 과 대조하세요. 아래 값을 채우고 주석을 해제해 실행합니다."] + (
                ["폐쇄망: 인터넷이 되는 PC에서 받은 ZIP 과 해시를 이동 매체로 옮긴 뒤 같은 방법으로 대조하세요."] if mode == "offline" else []),
            "commands": ["# $zip = '<내려받은 ZIP 경로>'", "# Get-FileHash -Algorithm SHA256 $zip   # 다운로드 페이지의 SHA256 과 일치하는지 확인"]})
        steps.append({"title": "서비스 중지 -> PHP 폴더 교체 -> 시작", "notes": [
            "점검 시간대에 수행하세요. php.ini 는 백업본을 새 폴더로 복사해 설정을 유지합니다. 서비스 이름은 환경에 맞게 확인하세요."], "commands": [
            "# iisreset /stop            # IIS FastCGI 인 경우   (Apache 는: Stop-Service Apache2.4)",
            "# Expand-Archive -Path $zip -DestinationPath '<새 PHP 폴더>'",
            "# Copy-Item '<백업 폴더>\\php.ini' '<새 PHP 폴더>\\php.ini'",
            "# iisreset /start           # (Apache 는: Start-Service Apache2.4)"]})
        steps.append({"title": "검증", "notes": ["`php -v` 는 CLI 만 보여 줍니다. 이 점검을 다시 실행해 웹 서비스가 쓰는 PHP 를 확인하세요."], "commands": [
            "powershell -NoProfile -ExecutionPolicy Bypass -File .\\php2shell-quickcheck.ps1",
            "Get-Process php-cgi,w3wp,httpd -ErrorAction SilentlyContinue | Select-Object Id,ProcessName,StartTime   # 시작 시각이 교체 이후여야 함"]})
        return steps
    # ---- Linux / Unix / macOS ----
    evidence = ["OLD_UMASK=$(umask); umask 077",
                "EV=\"./php2shell-evidence-$(date +%Y%m%d-%H%M%S)\"; mkdir -m 700 \"$EV\" || exit 2",
                "ps -eo pid,ppid,lstart,user,args > \"$EV/ps.txt\"",
                "(ss -tanp 2>/dev/null || netstat -anp 2>/dev/null || netstat -an) > \"$EV/network.txt\"",
                "(last -n 50 2>/dev/null) > \"$EV/last.txt\""]
    for log_dir in ctx["log_dirs"]:
        evidence.append("cp -Rp %s \"$EV/\" 2>/dev/null || true" % shlex.quote(log_dir))
    evidence.append("(cd \"$EV\" && find . -type f -exec sha256sum {} + 2>/dev/null || find . -type f -exec shasum -a 256 {} +) > \"$EV/SHA256SUMS\"")
    evidence.append("umask \"$OLD_UMASK\"")
    steps.append({"title": "침해 의심 시 증거 먼저 보존 (의심이 없으면 건너뜀)", "notes": [
        "침해가 의심되면 재시작·패치 전에 이 단계를 먼저 하세요 (KISA 수칙 7). 서버를 끄거나 재시작하면 메모리 흔적이 사라집니다.",
        "격리는 서버 종료가 아니라 외부 접속 차단으로 하고, 신고(KISA 118 / https://boho.or.kr)와 병행하세요."], "commands": evidence})
    before = {"apt": "dpkg-query -W 'php*' > \"$WORK/php-before.txt\"", "dnf": "rpm -qa 'php*' | sort > \"$WORK/php-before.txt\"",
              "yum": "rpm -qa 'php*' | sort > \"$WORK/php-before.txt\"", "zypper": "rpm -qa 'php*' | sort > \"$WORK/php-before.txt\"",
              "apk": "apk info -v | grep -i php > \"$WORK/php-before.txt\"", "pkg": "pkg info | grep -i php > \"$WORK/php-before.txt\"",
              "brew": "brew list --versions | grep -i php > \"$WORK/php-before.txt\""}.get(pkg)
    backup = ["(umask 077; mkdir -p \"$WORK\"); chmod 700 \"$WORK\""]
    if before:
        backup.append(before)
    existing = [d for d in ctx["config_dirs"] if clean(d) == d and os.path.isdir(d)]
    if existing:
        backup.append("tar czf \"$WORK/php-config-backup.tgz\" " + " ".join(shlex.quote(d) for d in existing) + " 2>/dev/null")
    else:
        backup.append("# 설정 디렉터리를 찾지 못했습니다. php.ini, php-fpm 풀, 웹서버 설정을 직접 백업하세요.")
    steps.append({"title": "현재 상태 기록·백업", "notes": ["패치 전 패키지 버전과 설정을 저장합니다. 롤백이 필요할 때의 근거가 됩니다."], "commands": backup})
    patch_commands = []
    notes = []
    if ctx["container"]:
        notes.append("이 시스템은 컨테이너입니다. 컨테이너 안에서 패키지를 올리지 말고 호스트/CI 에서 이미지를 수정 버전 베이스로 다시 빌드·재배포하세요.")
        fixed = advisory["fixed_releases"]
        patch_commands += ["# Dockerfile: FROM php:%s-<fpm|apache|cli>   (태그 존재 여부 확인)" % fixed["8.4"],
                           "# docker build --pull --no-cache -t <이름>:<새 태그> . && docker push <이름>:<새 태그>"]
    elif ctx["bad"]:
        if mode == "offline":
            notes.append("폐쇄망 모드: 아래 1)~3) 은 인터넷이 되는 같은 배포판·아키텍처의 PC 에서, 4) 는 이 서버에서 수행합니다. 해시는 별도 경로로 대조하세요.")
            patch_commands += ["# 1) 연결된 PC: " + step for step in _offline_steps(info)[:3]] + [
                "# 4) 이 서버: 반입한 패키지 설치 (설치 명령은 docs/offline-patching.ko.md 참고)"]
        else:
            patch_commands += [c for c in _update_steps({"bad": ctx["bad"]}, info)]
        if ctx["unpackaged"]:
            notes.append("패키지 관리자가 소유하지 않은 PHP 가 있습니다(소스 빌드·벤더 설치): %s. 수정 버전으로 다시 빌드하거나 벤더 패치를 확인하세요."
                         % ", ".join(i["path"] for i in ctx["unpackaged"]))
        if any(i["class"] == "eol_backport" for i in ctx["bad"]):
            urls = advisory.get("source_backport_urls", {})
            notes.append("7.4/8.0/8.1: 공식 릴리스가 없습니다. 배포판·LTS 벤더 패치를 먼저 확인하고, 없으면 PHP 보안팀 백포트 브랜치(%s)로 빌드하거나 지원 버전으로 이전하세요." % ", ".join(sorted(urls.values())))
        if any(i["class"] in ("eol_no_fix", "old_unsupported") for i in ctx["bad"]):
            notes.append("5.x/7.0~7.3 은 수정이 없습니다. 지원 버전으로 이전하고, 그 전에는 노출 축소(G)와 가상 패치(F)를 적용하세요.")
    else:
        notes.append("분석 결과 패키지 업데이트가 필요한 취약 설치가 없습니다. 이 단계는 건너뛰세요.")
    steps.append({"title": "패치 (자동 적용 아님: 직접 검토하고 실행)", "notes": notes, "commands": patch_commands or ["# 해당 없음"]})
    restart = ["sudo systemctl restart %s" % shlex.quote(u) for u in ctx["units"]]
    steps.append({"title": "모든 PHP 프로세스 재시작", "notes": [
        "패치 후 재시작하지 않으면 메모리의 옛 코드가 계속 실행됩니다 (KISA 수칙 2). 컨테이너는 이미지를 재배포하세요."],
        "commands": restart or ["# 재시작할 서비스 유닛을 찾지 못했습니다. PHP-FPM, Apache(mod_php), php-cgi, FrankenPHP, LiteSpeed 를 쓰는 서비스를 직접 재시작하세요."]})
    verify = []
    for name in ctx["packages"]:
        if pkg == "apt":
            verify.append("zcat /usr/share/doc/%s/changelog.Debian.gz | grep -m2 -E 'CVE-2026-1096(18|19)' || echo '변경 이력에 CVE 없음: 수정 버전인지 확인 필요'" % shlex.quote(name))
        elif pkg in ("dnf", "yum", "zypper"):
            verify.append("rpm -q --changelog %s | grep -m2 -E 'CVE-2026-1096(18|19)' || echo '변경 이력에 CVE 없음: 수정 버전인지 확인 필요'" % shlex.quote(name))
    if before:
        verify.append(before.replace("php-before.txt", "php-after.txt") + " ; diff \"$WORK/php-before.txt\" \"$WORK/php-after.txt\" || true")
    verify += ["python3 php2shell_triage.py   # 또는 php2shell-quickcheck.sh — 판정이 '수정됨', 재시작 필요 없음이어야 합니다",
               "# 주의: `php -v` 로만 확인하지 마세요 (CLI 와 웹 SAPI 가 다를 수 있음)"]
    steps.append({"title": "적용 확인", "notes": ["배포판 패키지는 버전 번호가 그대로여도 패치됐을 수 있으니 변경 이력에서 %s 를 확인합니다." % cves], "commands": verify})
    steps.append({"title": "사후 조치 (안내)", "notes": [
        "%s 이후 로그 점검과 DB 비밀번호·API 키·세션 키 교체: docs/runbook.ko.md. 로그에 이상이 없어도 안전이 보장되지 않습니다." % advisory["log_review_since_default"],
        "패치로 장애가 나면 이전 버전으로 되돌리기 전에 가상 패치(F)와 노출 축소(G)로 버티며 원인을 해결하세요. 이전 버전은 다시 취약합니다. 롤백이 불가피하면 \"$WORK/php-before.txt\" 의 버전으로 되돌립니다."],
        "commands": ["# 해당 없음 (안내)"]})
    return steps


def render_plan_sh(steps, result, advisory):
    lines = ["#!/bin/sh",
             "if [ \"${%s:-}\" != \"yes\" ]; then" % PLAN_GUARD_ENV,
             "    echo '자동 실행용이 아닙니다. PHP2SHELL_I_REVIEWED=yes 필요.' >&2",
             "    exit %d" % PLAN_GUARD_EXIT,
             "fi",
             "# php2shell-triage 맞춤 패치 계획 — %s (%s), 권고 기준일 %s" %
             (clean(result["host"]), clean(result["platform"]), clean(advisory["as_of"])),
             "# 자동 패치가 아닙니다. 각 명령을 검토하고 직접 실행하며 책임은 관리자에게 있습니다.",
             "set -u",
             "WORK=\"${PHP2SHELL_WORKDIR:-./php2shell-work-$(date +%Y%m%d-%H%M%S)}\"",
             "confirm() { printf '%s [y/N] ' \"$1\"; read -r ans || ans=n; case \"$ans\" in y|Y|yes|YES) return 0 ;; *) echo '  -> 건너뜀'; return 1 ;; esac; }", ""]
    for number, step in enumerate(steps):
        lines.append("printf '%s\\n' " + shlex.quote(clean("=== 단계 %d: %s ===" % (number, step["title"]))))
        lines.append("if confirm '이 단계를 실행할까요?'; then")
        lines.append("    :")
        lines.extend("    printf '%s\\n' " + shlex.quote(clean(note)) for note in step["notes"])
        lines.extend("    " + clean(command) for command in step["commands"])
        lines += ["fi", ""]
    return "\n".join(lines)


def render_plan_ps1(steps, result, advisory):
    lines = ["if ($env:%s -ne 'yes') {" % PLAN_GUARD_ENV,
             "    Write-Host '자동 실행용이 아닙니다. PHP2SHELL_I_REVIEWED=yes 필요.'",
             "    exit %d" % PLAN_GUARD_EXIT,
             "}",
             "# php2shell-triage 맞춤 패치 계획 — %s (%s), 권고 기준일 %s" %
             (clean(result["host"]), clean(result["platform"]), clean(advisory["as_of"])),
             "# 자동 패치가 아닙니다. 각 명령을 검토하고 직접 실행하며 책임은 관리자에게 있습니다.",
             "function Confirm-Step([string]$Message) { $a = Read-Host \"$Message [y/N]\"; return ($a -match '^(y|yes)$') }", ""]
    for number, step in enumerate(steps):
        lines.append("Write-Host " + ps_literal("=== 단계 %d: %s ===" % (number, step["title"])))
        lines.append("if (Confirm-Step '이 단계를 실행할까요?') {")
        lines.extend("    Write-Host " + ps_literal(note) for note in step["notes"])
        lines.extend("    " + clean(command) for command in step["commands"])
        lines += ["}", ""]
    return "\n".join(lines)


def render_plan_md(steps, result, advisory):
    result, advisory = [display_data(value, markdown=True) for value in (result, advisory)]
    lines = ["# 맞춤 패치 계획", "",
             "- 대상: `%s` / %s (권고 기준일 %s, 대상 CVE %s)" % (result["host"], result["platform"], advisory["as_of"], ", ".join(advisory["cves"])),
             "- 이 문서와 스크립트는 **자동 패치가 아닙니다.** 체계관리자가 검토하고 직접 실행하며 패치의 책임은 관리자에게 있습니다.", ""]
    for number, step in enumerate(steps):
        lines += ["## 단계 %d. %s" % (number, markdown_value(step["title"])), ""] + [
            "- " + markdown_value(note) for note in step["notes"]] + ["", "```"] + [
            clean(command).replace("`", "&#96;") for command in step["commands"]] + ["```", ""]
    return "\n".join(lines)


def emit_patch_plan(out_dir, result, info, advisory, mode="online", fmt="auto", force=False):
    steps = build_patch_plan(result, info, advisory, mode)
    written = []
    windows = info.get("pkg") == "windows"
    kind = fmt if fmt != "auto" else ("ps1" if windows else "sh")
    path = os.path.join(out_dir, "patch-plan.md")
    safe_write(path, render_plan_md(steps, result, advisory) + "\n", force=force)
    written.append(path)
    if kind in ("sh", "ps1"):
        if (kind == "ps1") != windows:
            steps = build_patch_plan(result, dict(info, pkg="windows" if kind == "ps1" else info.get("pkg")), advisory, mode)
        path = os.path.join(out_dir, "patch-plan." + kind)
        text = render_plan_sh(steps, result, advisory) if kind == "sh" else render_plan_ps1(steps, result, advisory)
        safe_write(path, text + "\n", force=force, script=True,
                   encoding="utf-8-sig" if kind == "ps1" else "utf-8")
        written.append(path)
    return written


# --- CLI -------------------------------------------------------------------------
def build_parser():
    parser = argparse.ArgumentParser(prog="php2shell_triage.py", description=__doc__.split("\n\n")[0],
                                     epilog="서버 설정·패키지를 바꾸지 않습니다. 기본: 신뢰할 수 있는 PHP 바이너리만 -n -v 로 실행합니다. 의심되는 호스트에서는 --no-exec.")
    parser.add_argument("--json", action="store_true", help="JSON 출력")
    parser.add_argument("--format", choices=("text", "json", "md"), help="출력 형식 (기본 text)")
    parser.add_argument("--output", help="결과를 파일로 저장")
    parser.add_argument("--no-exec", action="store_true", help="발견한 바이너리를 절대 실행하지 않음 (패키지 DB/정적 문자열 사용)")
    parser.add_argument("--root", help="점검 대상 파일시스템 루트 (오프라인 점검: 실행 중 프로세스 점검 생략, 바이너리는 기본적으로 실행하지 않음)")
    parser.add_argument("--exec", dest="force_exec", action="store_true",
                        help="신뢰되지 않은 위치 및 --root 포함 모든 바이너리 실행 강제. 신뢰하는 호스트에서만 사용")
    parser.add_argument("--force", action="store_true", help="기존 일반 출력 파일 교체 허용 (심볼릭 링크는 항상 거부)")
    parser.add_argument("--advisory", help="권고 데이터 JSON 경로 (기본: data/advisory.json 또는 내장본)")
    parser.add_argument("--no-response", action="store_true", help="대응 옵션 출력 생략")
    parser.add_argument("--mode", choices=("online", "offline"), default="online",
                        help="패치 환경: online(기본) 또는 offline(폐쇄망)")
    parser.add_argument("--uploads", choices=("yes", "no", "unknown"), default="unknown",
                        help="사이트에 파일 업로드가 필요한가 (가상 패치 파일 값 선택)")
    parser.add_argument("--emit-virtual-patch", metavar="DIR",
                        help="가상 패치 설정 파일(WAF·웹서버·PHP·OS)을 DIR 에 생성 (대상 서버는 바꾸지 않음)")
    parser.add_argument("--emit-patch-plan", metavar="DIR",
                        help="이 서버 맞춤 패치 계획(patch-plan.md 와 검토용 스크립트)을 DIR 에 생성. 패치를 직접 적용하지는 않음")
    parser.add_argument("--plan-format", choices=("auto", "sh", "ps1", "md"), default="auto",
                        help="패치 계획 스크립트 형식 (기본: 점검 대상 OS 에 맞춤)")
    parser.add_argument("--list-options", action="store_true", help="대응 옵션 목록만 출력 (점검 안 함)")
    parser.add_argument("--classify", metavar="VERSION", help=argparse.SUPPRESS)
    parser.add_argument("--version", action="version", version="%s %s" % (TOOL, __version__))
    return parser


def _main(args):
    advisory = load_advisory(args.advisory)
    if args.classify is not None:
        print(classify(args.classify, advisory))
        return 0
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if args.list_options:
        print(render_catalog())
        return 0
    if args.emit_virtual_patch:
        written = emit_virtual_patch(args.emit_virtual_patch, args.uploads, force=args.force)
        print("가상 패치 파일 %d개를 %s 에 만들었습니다 (점검 대상 서버는 바꾸지 않았습니다). 적용 전에 반드시 테스트하세요."
              % (len(written), clean(args.emit_virtual_patch)), file=sys.stderr)
    result, info = scan(advisory, root=args.root, no_exec=args.no_exec, exec_mode="all" if args.force_exec else "auto")
    if args.emit_patch_plan:
        planned = emit_patch_plan(args.emit_patch_plan, result, info, advisory, args.mode, args.plan_format, force=args.force)
        print("맞춤 패치 계획을 만들었습니다 (자동 패치 아님, 관리자가 검토 후 직접 실행): %s" % clean(", ".join(planned)), file=sys.stderr)
    response = None if args.no_response else build_response(result, info, advisory, args.mode, args.uploads, args.root)
    fmt = args.format or ("json" if args.json else "text")
    if fmt == "json":
        payload = dict(result)
        payload["response"] = response
        body = json.dumps(payload, ensure_ascii=False, indent=2)
    elif fmt == "md":
        body = render_markdown(result, response, advisory)
    else:
        body = render_text(result, response, advisory)
    if args.output:
        safe_write(args.output, body if body.endswith("\n") else body + "\n", force=args.force)
        print("saved: %s" % clean(args.output), file=sys.stderr)
    else:
        print(body)
    return result["exit_code"]


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return _main(args)
    except (OSError, ValueError) as error:
        print("오류: " + clean(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
