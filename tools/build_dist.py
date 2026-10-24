#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""배포 묶음을 만든다: 체계관리자가 서버에 바로 올려 쓸 수 있는 단일 파일들과 체크섬.

  python3 tools/build_dist.py [--out dist]

만들어지는 것 (dist/php2shell-kr-<버전>/):
  php2shell-quickcheck.sh    Linux/Unix/macOS 용, Python 없이 동작 (POSIX sh, 단일 파일)
  php2shell-quickcheck.bat   Windows 용 단일 파일 (PowerShell 스크립트를 내장한 배치 파일, 더블클릭 가능)
  php2shell-quickcheck.ps1   Windows PowerShell 용 (위 .bat 가 내장한 것과 같은 내용)
  php2shell_kr.py        Python 3.6+ 용 전체 기능판 (+ data/, virtual-patch/, docs/)
  SHA256SUMS                 모든 파일의 SHA-256
  + php2shell-kr-<버전>.zip / .tar.gz
"""
import argparse
import hashlib
import os
import shutil
import sys
import tarfile
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import php2shell_kr  # noqa: E402

MARKER = "#PS1-PAYLOAD-BEGIN"

# 헤더는 반드시 ASCII 입니다 (cmd.exe 가 코드 페이지와 무관하게 읽을 수 있도록). 한글은 PowerShell 페이로드 안에만 있습니다.
BAT_HEADER = r"""@echo off
rem php2shell-kr for Windows. Does not change server configuration or packages.
rem Runs trusted PHP binaries with -n -v by default. Use -NoExec on suspect hosts; -Exec forces execution.
rem Usage: php2shell-quickcheck.bat [-Json] [-NoExec] [-Exec] [-Offline] [-Root dir] [-PlanFile new.ps1] [-Help]
rem Exit codes: 0 nothing to do / 1 action required / 3 inconclusive / 2 launcher error
setlocal
set "P2S_SELF=%~f0"
rem Execute the embedded script in memory: no extracted file, temp directory, or elevated temp-file race.
set "P2S_ARGS=%*"
set "P2S_HOST=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%P2S_HOST%" (
  echo [php2shell] Windows PowerShell is required but was not found at the system path.
  exit /b 2
)
"%P2S_HOST%" -NoProfile -ExecutionPolicy Bypass -Command "try { if((New-Object IO.FileInfo($env:P2S_SELF)).Length -gt 2097152){exit 2}; $s=[IO.File]::ReadAllText($env:P2S_SELF,[Text.Encoding]::UTF8); $i=$s.LastIndexOf([string][char]10+'#PS1-PAYLOAD-BEGIN'); if($i -lt 0){exit 2}; $q=[string][char]34; $pattern=$q+'[^'+$q+']*'+$q+'|[^\s'+$q+']+'; $raw=[string]$env:P2S_ARGS; if((($raw.ToCharArray() | Where-Object {$_ -eq [char]34} | Measure-Object).Count -band 1) -ne 0){throw 'Unmatched argument quote'}; $tokens=@([regex]::Matches($raw,$pattern)); $parsed=@{}; for($n=0;$n -lt $tokens.Count;$n++){ $k=$tokens[$n].Value; if($k -notmatch '^-(Json|NoExec|Exec|Offline|Root|PlanFile|Help|Classify)$'){throw ('Unknown option: '+$k)}; $name=$k.Substring(1); if($name -match '^(Root|PlanFile|Classify)$'){ $n++; if($n -ge $tokens.Count){throw ('Missing value: '+$k)}; $parsed[$name]=$tokens[$n].Value.Trim([char]34) }else{ $parsed[$name]=$true } }; Remove-Item Env:P2S_ARGS -ErrorAction SilentlyContinue; & ([scriptblock]::Create($s.Substring($i+1))) @parsed; exit $LASTEXITCODE } catch { [Console]::Error.WriteLine('[php2shell] '+$_.Exception.Message); exit 2 }"
set "P2S_RC=%ERRORLEVEL%"
if "%~1"=="" if not defined P2S_NOPAUSE pause
exit /b %P2S_RC%
"""


def display(path):
    """저장소 기준 상대 경로. 드라이브가 다른 Windows 경로(임시 폴더 등)에서는 절대 경로를 그대로 쓴다."""
    try:
        return os.path.relpath(path, ROOT)
    except ValueError:
        return path


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def build_bat(ps1_path, bat_path):
    with open(ps1_path, "rb") as handle:
        payload = handle.read()
    if payload.startswith(b"\xef\xbb\xbf"):
        payload = payload[3:]
    text = payload.decode("utf-8")
    if MARKER in text:
        raise SystemExit("PowerShell 스크립트가 내장 표지(%s)를 이미 포함합니다." % MARKER)
    header = BAT_HEADER.replace("\r\n", "\n").replace("\n", "\r\n")
    body = text.replace("\r\n", "\n").replace("\n", "\r\n")
    with open(bat_path, "wb") as handle:
        handle.write(header.encode("ascii"))
        handle.write((MARKER + "\r\n").encode("ascii"))
        handle.write(body.encode("utf-8"))


def copy(src, dst):
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copyfile(src, dst)
    shutil.copymode(src, dst)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", default=os.path.join(ROOT, "dist"))
    args = parser.parse_args(argv)
    version = php2shell_kr.__version__
    name = "php2shell-kr-%s" % version
    target = os.path.join(args.out, name)
    if os.path.isdir(target):
        shutil.rmtree(target)
    os.makedirs(target)
    required = [("quickcheck/php2shell-quickcheck.sh", "php2shell-quickcheck.sh"),
                ("quickcheck/php2shell-quickcheck.ps1", "php2shell-quickcheck.ps1"),
                ("php2shell_kr.py", "php2shell_kr.py"), ("LICENSE", "LICENSE"), ("NOTICE", "NOTICE"),
                ("README.md", "README.md")]
    for src, dst in required:
        path = os.path.join(ROOT, src)
        if not os.path.isfile(path):
            raise SystemExit("필요한 파일이 없습니다: %s" % src)
        copy(path, os.path.join(target, dst))
    for folder in ("data", "virtual-patch", "docs", "templates"):
        source = os.path.join(ROOT, folder)
        if os.path.isdir(source):
            shutil.copytree(source, os.path.join(target, folder), ignore=shutil.ignore_patterns("__pycache__", ".DS_Store"))
    build_bat(os.path.join(ROOT, "quickcheck", "php2shell-quickcheck.ps1"), os.path.join(target, "php2shell-quickcheck.bat"))
    os.chmod(os.path.join(target, "php2shell-quickcheck.sh"), 0o755)
    lines = []
    for folder, _, names in sorted(os.walk(target)):
        for file_name in sorted(names):
            if file_name == "SHA256SUMS":
                continue
            path = os.path.join(folder, file_name)
            lines.append("%s  %s" % (sha256(path), os.path.relpath(path, target).replace(os.sep, "/")))
    with open(os.path.join(target, "SHA256SUMS"), "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines) + "\n")
    zip_path = os.path.join(args.out, name + ".zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for folder, _, names in sorted(os.walk(target)):
            for file_name in sorted(names):
                path = os.path.join(folder, file_name)
                archive.write(path, os.path.join(name, os.path.relpath(path, target)))
    tar_path = os.path.join(args.out, name + ".tar.gz")
    with tarfile.open(tar_path, "w:gz") as archive:
        archive.add(target, arcname=name)
    for archive_path in (zip_path, tar_path):
        print("%s  %s" % (sha256(archive_path), display(archive_path)))
    print("dist: %s" % display(target))
    return 0


if __name__ == "__main__":
    sys.exit(main())
