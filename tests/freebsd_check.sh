#!/bin/sh
# FreeBSD 에서 sh 간이판·Python 판과 docs/response-options.ko.md 의 pkg 절차를 실제로 확인한다 (root 필요, 임시 VM 전용).
#   1) sh 하네스(tests/test_quickcheck_sh.sh) 통과
#   2) pkg 로 설치한 php84 를 sh 판·Python 판이 둘 다 찾고 패키지 관리자를 pkg 로 인식한다
#   3) 문서의 `pkg audit -F`, `pkg upgrade -g 'php*'`, `service php_fpm ...` 명령이 동작한다
#   4) 서비스를 띄우면 실행 중인 php-fpm 을 running=true 로 찾는다
# 사용: sh tests/freebsd_check.sh
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=1; }
[ "$(uname -s)" = FreeBSD ] || { echo "FreeBSD 필요"; exit 2; }

if sh "$ROOT/tests/test_quickcheck_sh.sh" >/tmp/qc-harness.out 2>&1; then pass "sh 하네스 통과: $(tail -1 /tmp/qc-harness.out)"; else fail "sh 하네스"; tail -20 /tmp/qc-harness.out; fi

env ASSUME_ALWAYS_YES=yes pkg install -y php84 python3 >/tmp/pkg-install.out 2>&1 || { fail "pkg install php84 python3"; tail -20 /tmp/pkg-install.out; exit 1; }
PKGVER="$(pkg info php84 | awk '/^Version/ {print $3}' | sed 's/[_,].*//')"
echo "pkg php84 버전: $PKGVER"

INSPECT="python3 $ROOT/tests/_inspect_json.py"
SHJSON="$(sh "$ROOT/quickcheck/php2shell-quickcheck.sh" --json 2>/dev/null)"
PYJSON="$(python3 "$ROOT/php2shell_triage.py" --json --no-response 2>/dev/null)"
if echo "$SHJSON" | $INSPECT --path '^/usr/local/(bin/php|sbin/php-fpm)$' --version "$PKGVER"; then pass "sh 판이 pkg php84 $PKGVER 를 찾음"; else fail "sh 판이 php84 $PKGVER 를 찾지 못함"; fi
if echo "$PYJSON" | $INSPECT --path '^/usr/local/(bin/php|sbin/php-fpm)$' --version "$PKGVER"; then pass "python 판이 pkg php84 $PKGVER 를 찾음"; else fail "python 판이 php84 $PKGVER 를 찾지 못함"; fi
if echo "$PYJSON" | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin)["package_manager"] == "pkg" else 1)'; then pass "python 판이 패키지 관리자를 pkg 로 인식함"; else fail "python 판이 패키지 관리자를 pkg 로 인식하지 못함"; fi

if pkg audit -F >/tmp/pkg-audit.out 2>&1; then pass "pkg audit -F 정상 종료(취약 패키지 없음)"; else
  rc=$?; [ "$rc" -eq 1 ] && pass "pkg audit -F 종료 코드 1(취약 패키지 보고 가능): $(tail -1 /tmp/pkg-audit.out)" || { fail "pkg audit -F 실패 rc=$rc"; tail -5 /tmp/pkg-audit.out; }; fi
echo "--- pkg audit -F 출력"; head -30 /tmp/pkg-audit.out
if pkg upgrade -n -g 'php*' >/tmp/pkg-up.out 2>&1; then pass "pkg upgrade -n -g 'php*' 동작"; else fail "pkg upgrade -g 'php*'"; tail -5 /tmp/pkg-up.out; fi

sysrc php_fpm_enable=YES >/dev/null
if service php_fpm onestart >/tmp/fpm-start.out 2>&1 || service php_fpm start >>/tmp/fpm-start.out 2>&1; then
  sleep 3
  echo "--- service 출력"; cat /tmp/fpm-start.out; service php_fpm onestatus; sockstat -l 2>/dev/null | grep -i php
  echo "--- 진단: id=$(id -u) see_other_uids=$(sysctl -n security.bsd.see_other_uids 2>&1) jail=$(sysctl -n security.jail.jailed 2>&1)"; echo "pgrep:"; pgrep -l php 2>&1; echo "ps auxww:"; ps auxww 2>&1 | grep -i php | grep -v grep | cut -c1-160; echo "ps -ax 줄 수: $(ps -ax 2>&1 | wc -l)"; echo "--- ps (진단: 탐지 도구가 보는 프로세스 이름)"; echo "ps 출력 크기: $(ps -axo pid=,comm=,command= 2>&1 | wc -c) 바이트"; ps -axo pid=,comm=,command= 2>&1 | grep -i php | grep -v grep | cut -c1-200
  echo "ps -axo 원문:"; ps -axo pid=,comm=,command= 2>&1 | head -12; echo "ps -axwwo command 만:"; ps -axwwo pid=,command= 2>&1 | grep -i php | head -5
  SHJSON="$(sh "$ROOT/quickcheck/php2shell-quickcheck.sh" --json 2>/dev/null)"
  if echo "$SHJSON" | $INSPECT --sapi fpm --running; then pass "실행 중인 php-fpm 을 running=true 로 찾음"; else fail "실행 중인 php-fpm 을 찾지 못함"; fi
  PYJSON="$(python3 "$ROOT/php2shell_triage.py" --json --no-response 2>/dev/null)"
  if echo "$PYJSON" | $INSPECT --sapi fpm --running; then pass "python 판이 실행 중인 php-fpm 을 running=true 로 찾음"; else fail "python 판이 실행 중인 php-fpm 을 찾지 못함"; fi
  if service php_fpm restart >/tmp/fpm-restart.out 2>&1; then pass "service php_fpm restart 동작"; else fail "service php_fpm restart"; cat /tmp/fpm-restart.out; fi
  service php_fpm stop >/dev/null 2>&1
else
  fail "service php_fpm start"; cat /tmp/fpm-start.out
fi
exit "$FAIL"
