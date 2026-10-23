#!/usr/bin/env python3
"""실제 Windows 에서 trusted_binary() 의 ACL 판정을 확인한다 (하네스는 주입한 ACL 값으로만 시험했다).

실행: python tests/windows_acl_check.py   (Windows 전용. 임시 폴더 C:\\p2s-acl 을 만들고 끝나면 지운다)

기대:
  1) 누구나(Everyone) 쓸 수 있는 폴더의 파일은 신뢰하지 않는다
  2) Administrators/SYSTEM 전용 폴더의 파일과 System32\\cmd.exe 는 신뢰한다 (기본 C:\\ 루트의 Authenticated Users:(AD) 는
     앱 폴더 위의 상위 폴더에서는 무시한다)
  3) 앱 폴더에 Users 가 새 파일을 만들 수 있으면(DLL 심기) 신뢰하지 않는다. 앱 폴더 위의 상위 폴더에 Users:(AD) 가 있어도 신뢰하지만
     Users:(DC)(하위 항목 삭제)가 있으면 신뢰하지 않는다
  4) 심볼릭 링크/정션을 거치는 경로는 신뢰하지 않는다
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


def check(name, actual, expected, path_for_explain=None):
    ok = actual == expected
    print("%s %s (실제=%s 기대=%s)" % ("PASS" if ok else "FAIL", name, actual, expected))
    if not ok:
        failures.append(name)
        if expected is True and path_for_explain:
            explain(path_for_explain)


def explain(path):
    """trusted_binary 가 untrusted 를 낼 때 원인(종료 코드·출력·오류·소요 시간)을 보이기 위해 같은 스크립트를 직접 실행한다."""
    import time
    root = p.windows_systemroot()
    started = time.time()
    try:
        real = subprocess.run([p.helper_path("powershell"), "-NoProfile", "-NonInteractive", "-Command", p.windows_trust_script(path)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=120,
                              env={"SystemRoot": root, "PATH": os.path.join(root, "System32")})
        print("  설명 %s rc=%d %.1fs stdout=%r stderr=%r" % (path, real.returncode, time.time() - started, real.stdout[:100], real.stderr[:1200]))
    except subprocess.TimeoutExpired:
        print("  설명 %s: 120초 안에 끝나지 않음" % path)


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
import time
_t0 = time.time()
_cmd_trusted = p.trusted_binary(CMD)
print("정보: System32\\cmd.exe 신뢰 판정 소요 %.1f초" % (time.time() - _t0))
check("System32\\cmd.exe 는 신뢰함(C:\\ 루트의 (AD) 는 무시)", _cmd_trusted, True, CMD)

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
check("Administrators/SYSTEM 전용 폴더의 파일은 신뢰함", p.trusted_binary(locked_exe), True, locked_exe)

# 3) 앱 폴더 / 상위 폴더의 권한. locked_exe 기준: 파일(0) -> locked_dir(앱 폴더, 1) -> BASE(상위, 2)
rc, out = icacls(locked_dir, "/grant", "*S-1-5-32-545:(WD)")   # Users: 이 폴더에 새 파일 만들기
assert rc == 0, out
check("앱 폴더에 Users 가 새 파일을 만들 수 있으면 신뢰하지 않음", p.trusted_binary(locked_exe), False)
icacls(locked_dir, "/remove:g", "*S-1-5-32-545")
check("앱 폴더 권한을 되돌리면 다시 신뢰함", p.trusted_binary(locked_exe), True)
rc, out = icacls(BASE, "/grant", "*S-1-5-11:(AD)")           # Authenticated Users: 이 폴더에 하위 폴더 만들기 (기본 C:\ 와 같은 권한)
assert rc == 0, out
check("상위 폴더의 Authenticated Users:(AD) 는 무시하고 신뢰함", p.trusted_binary(locked_exe), True)
rc, out = icacls(BASE, "/grant", "*S-1-5-11:(DC)")           # 하위 항목 삭제 = 이미 있는 폴더를 지우고 바꿀 수 있음
assert rc == 0, out
show(BASE)
check("상위 폴더에서 Authenticated Users 가 하위 항목을 삭제할 수 있으면 신뢰하지 않음", p.trusted_binary(locked_exe), False)
icacls(BASE, "/remove:g", "*S-1-5-11")

# 4) 정션을 거치는 경로
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
