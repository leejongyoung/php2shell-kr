#!/usr/bin/env python3
"""실제 Windows 에서 trusted_binary() 의 ACL 판정을 확인한다 (하네스는 주입한 ACL 값으로만 시험했다).

실행: python tests/windows_acl_check.py   (Windows 전용. 임시 폴더 C:\\p2s-acl 을 만들고 끝나면 지운다)

기대:
  1) 누구나(Everyone) 쓸 수 있는 폴더의 파일은 신뢰하지 않는다
  2) Administrators/SYSTEM 만 쓸 수 있고 상위 폴더도 그런 파일은 신뢰한다 (C:\\ 루트의 기본 ACL 은 통제할 수 없으므로
     루트가 막는지 여부를 함께 출력한다)
  3) 심볼릭 링크/정션을 거치는 경로는 신뢰하지 않는다
"""
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import php2shell_triage as p  # noqa: E402

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
print("trusted_binary(locked) = %s" % locked)
if not locked:
    # 루트(C:\)의 기본 ACL 에 Users 쓰기(폴더 만들기/데이터 추가)가 있으면 어떤 파일도 신뢰되지 않는다.
    root_blocks = not p.trusted_binary("C:\\")
    print("정보: C:\\ 루트 자체의 신뢰 판정 = %s" % (not root_blocks))
check("Administrators/SYSTEM 전용 파일의 판정이 루트 ACL 에 막히지 않음", locked, True)

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
