#!/usr/bin/env python3
"""실제 Windows 에서 trusted_binary() 의 ACL 판정을 확인한다 (하네스는 주입한 ACL 값으로만 시험했다).

실행: python tests/windows_acl_check.py   (Windows 전용. 임시 폴더 C:\\p2s-acl 을 만들고 끝나면 지운다)

기대:
  1) 누구나(Everyone) 쓸 수 있는 폴더의 파일은 신뢰하지 않는다
  2) Administrators/SYSTEM 전용 파일과 System32\\cmd.exe 의 판정은 단정하지 않고 출력만 한다 (C:\\ 루트의 기본 ACL 은 통제할 수
     없고, 그 ACL 때문에 모두 untrusted 가 될 수 있다 — 실제 결과는 docs/verification.ko.md 참고)
  3) 심볼릭 링크/정션을 거치는 경로는 신뢰하지 않는다
"""
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import php2shell_triage as p  # noqa: E402

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

if os.name != "nt":
    print("Windows 필요")
    sys.exit(2)

BASE = r"C:\p2s-acl"
ICACLS = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "icacls.exe")
CMD = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "cmd.exe")
failures = []


def icacls(*args):
    result = subprocess.run([ICACLS] + list(args), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    return result.returncode, result.stdout


def show(path):
    code, out = icacls(path)
    print("--- icacls %s (rc=%d)\n%s" % (path, code, out.strip()))


def check(name, actual, expected):
    ok = actual == expected
    print("%s %s (실제=%s 기대=%s)" % ("PASS" if ok else "FAIL", name, actual, expected))
    if not ok:
        failures.append(name)


def make(directory, name="php.exe"):
    os.makedirs(directory, exist_ok=True)
    target = os.path.join(directory, name)
    shutil.copyfile(CMD, target)
    return target


shutil.rmtree(BASE, ignore_errors=True)
os.makedirs(BASE)
show("C:\\")
show(BASE)
show(CMD)
print("trusted_binary(System32\\cmd.exe) = %s" % p.trusted_binary(CMD))

# 1) Everyone 이 쓸 수 있는 폴더
open_dir = os.path.join(BASE, "open")
open_exe = make(open_dir)
rc, out = icacls(open_dir, "/grant", "*S-1-1-0:(OI)(CI)F")
assert rc == 0, out
show(open_dir)
check("Everyone 쓰기 가능 폴더의 파일은 신뢰하지 않음", p.trusted_binary(open_exe), False)

# 2) Administrators/SYSTEM 전용 폴더 (상속 제거). 소유자는 Administrators 로 맞춘다
locked_dir = os.path.join(BASE, "locked")
locked_exe = make(locked_dir)
for target in (locked_dir, locked_exe):
    for args in (["/setowner", "*S-1-5-32-544"],
                 ["/inheritance:r"],
                 ["/grant:r", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"]):
        rc, out = icacls(target, *args)
        assert rc == 0, (target, args, out)
rc, out = icacls(BASE, "/setowner", "*S-1-5-32-544")
rc, out = icacls(BASE, "/inheritance:r")
rc, out = icacls(BASE, "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F")
show(locked_dir)
locked = p.trusted_binary(locked_exe)
# 정보(단정하지 않음): 기본 Windows 의 C:\ 루트 ACL 에는 Authenticated Users:(AD) (이 폴더에서 하위 폴더 만들기)가 있고,
# 이 도구의 검사는 경로의 모든 상위 폴더를 같은 규칙으로 보므로 C:\ 아래의 어떤 파일도 신뢰로 판정되지 않을 수 있다.
# 그 경우 기본 설정에서 Windows 의 PHP 는 실행하지 않고 파일의 버전 문자열로 판정한다(안전한 쪽으로 실패).
print("정보: Administrators/SYSTEM 전용 파일 trusted_binary = %s, System32\\cmd.exe = %s" % (locked, p.trusted_binary(CMD)))

# 3) 정션을 거치는 경로
junction = os.path.join(BASE, "junction")
rc = subprocess.run(["cmd.exe", "/c", "mklink", "/J", junction, locked_dir], stdout=subprocess.PIPE, stderr=subprocess.STDOUT).returncode
if rc == 0:
    check("정션을 거치는 경로는 신뢰하지 않음", p.trusted_binary(os.path.join(junction, "php.exe")), False)
else:
    print("정보: 정션 생성 실패(rc=%d)" % rc)

shutil.rmtree(BASE, ignore_errors=True)
if failures:
    print("실패: %s" % ", ".join(failures))
    sys.exit(1)
print("모두 통과")
