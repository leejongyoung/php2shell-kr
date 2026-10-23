#!/bin/sh
# 컨테이너로는 확인할 수 없는 Linux 호스트 동작을 실제 systemd 가 있는 호스트에서 확인한다 (Ubuntu/Debian, root 필요).
#   1) 패키지 PHP-FPM 을 systemd 로 띄우고 virtual-patch/os/systemd-php-fpm-dropin.conf 를 적용(daemon-reload + restart)해
#      MemoryMax·OOMPolicy 가 실제로 반영되는지
#   2) 패키지 파일을 교체(재설치)하면 점검 도구가 "재시작 필요"를 보고하고, `systemctl restart` 뒤에는 사라지는지
#   3) virtual-patch/os/auditd-php2shell.rules 가 auditd 에 로드되는지
#   4) virtual-patch/os/nftables-egress-example.nft 가 문법을 통과하고, 적용하면 www-data 의 신규 외부 연결만 막는지
# 사용: sudo sh tests/linux_host_check.sh   (호스트에 패키지를 설치하고 nft 규칙을 잠시 적용한다: 임시 VM/CI 러너 전용)
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=1; }
[ "$(id -u)" -eq 0 ] || { echo "root 필요"; exit 2; }
command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] || { echo "systemd 호스트 필요"; exit 2; }
export DEBIAN_FRONTEND=noninteractive

# apt 가 설치 중 서비스를 자동 시작·재시작하지 않게 한다 (재시작 필요 상태를 직접 만들기 위해)
printf '#!/bin/sh\nexit 101\n' >/usr/sbin/policy-rc.d; chmod +x /usr/sbin/policy-rc.d
apt-get update -qq >/dev/null
apt-get install -y -qq php-fpm >/dev/null 2>&1 || { fail "php-fpm 설치"; exit 1; }
UNIT="$(systemctl list-unit-files --no-legend 'php*-fpm.service' | awk '{print $1}' | head -1)"
[ -n "$UNIT" ] || { fail "php-fpm systemd 유닛 없음"; exit 1; }
echo "유닛: $UNIT"
# policy-rc.d 는 재설치 단계(2)가 끝날 때까지 둔다: 패키지 스크립트가 서비스를 자동 재시작하면 "재시작 필요" 상태를 만들 수 없다
systemctl start "$UNIT" && systemctl is-active --quiet "$UNIT" && pass "$UNIT 시작" || { fail "$UNIT 시작"; exit 1; }

# 1) systemd drop-in
mkdir -p "/etc/systemd/system/$UNIT.d"
cp "$ROOT/virtual-patch/os/systemd-php-fpm-dropin.conf" "/etc/systemd/system/$UNIT.d/php2shell.conf"
systemctl daemon-reload && systemctl restart "$UNIT"
if systemctl is-active --quiet "$UNIT"; then pass "drop-in 적용 후 restart, 서비스 active"; else fail "drop-in 적용 후 서비스가 active 가 아님"; fi
MM="$(systemctl show -p MemoryMax --value "$UNIT")"; OP="$(systemctl show -p OOMPolicy --value "$UNIT")"
[ "$MM" = 2147483648 ] && pass "MemoryMax=2G 반영($MM)" || fail "MemoryMax 가 반영되지 않음: $MM"
[ "$OP" = continue ] && pass "OOMPolicy=continue 반영" || fail "OOMPolicy 가 반영되지 않음: $OP"
rm -f "/etc/systemd/system/$UNIT.d/php2shell.conf"; systemctl daemon-reload && systemctl restart "$UNIT"
MM="$(systemctl show -p MemoryMax --value "$UNIT")"
[ "$MM" = infinity ] && pass "롤백(파일 삭제 + daemon-reload + restart) 후 MemoryMax 원복" || fail "롤백 후에도 MemoryMax=$MM"

# 2) 재시작 필요 탐지
PKG="$(dpkg -S "$(command -v "${UNIT%.service}" 2>/dev/null || ls /usr/sbin/php-fpm* | head -1)" 2>/dev/null | head -1 | cut -d: -f1)"
echo "패키지: $PKG"
BEFORE_PID="$(systemctl show -p MainPID --value "$UNIT")"
apt-get install -y -qq --reinstall "$PKG" >/dev/null 2>&1 || fail "$PKG 재설치"
rm -f /usr/sbin/policy-rc.d
AFTER_PID="$(systemctl show -p MainPID --value "$UNIT")"
EXE_LINK="$(readlink "/proc/$AFTER_PID/exe" 2>/dev/null)"
echo "정보: 재설치 전 MainPID=$BEFORE_PID, 후 MainPID=$AFTER_PID, /proc/<pid>/exe -> $EXE_LINK"
case "$EXE_LINK" in
  *"(deleted)") pass "apt 재설치가 실행 중인 서비스의 바이너리를 교체함(프로세스는 삭제된 옛 파일을 사용 중)" ;;
  *)
    echo "정보: apt 재설치로 (deleted) 상태가 만들어지지 않음 (서비스 재시작 여부 또는 파일 교체 방식 차이). 패키지 갱신과 같은 효과(새 파일을 rename 으로 덮어쓰기)로 대체한다"
    BIN="$(readlink -f "/proc/$AFTER_PID/exe")"
    cp -p "$BIN" "$BIN.new" && mv "$BIN.new" "$BIN" ;;
esac
INSPECT="python3 $ROOT/tests/_inspect_json.py"
JSON="$(python3 "$ROOT/php2shell_triage.py" --json --no-response 2>/dev/null)"
if echo "$JSON" | $INSPECT --sapi fpm --running --needs-restart; then
  pass "패키지 파일 교체 후 도구가 재시작 필요를 보고"
else
  fail "재시작 필요를 탐지하지 못함"
fi
# 점검 도구가 root 로 실행돼도 커널 스레드 때문에 process_visibility 가 limited 가 되지 않는다 (수정한 결함의 실환경 확인)
case "$(echo "$JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["process_visibility"])')" in
  full) pass "root 실행에서 process_visibility=full" ;; *) fail "root 실행인데 process_visibility 가 full 이 아님" ;;
esac
systemctl restart "$UNIT"
JSON="$(python3 "$ROOT/php2shell_triage.py" --json --no-response 2>/dev/null)"
if echo "$JSON" | $INSPECT --no-needs-restart; then
  pass "systemctl restart 후 재시작 필요가 사라짐"
else
  fail "restart 후에도 재시작 필요가 남음"
fi

# 3) auditd
apt-get install -y -qq auditd >/dev/null 2>&1 || fail "auditd 설치"
WEBUID="$(id -u www-data)"
mkdir -p /var/www/html
sed "s/uid=33/uid=$WEBUID/" "$ROOT/virtual-patch/os/auditd-php2shell.rules" >/etc/audit/rules.d/php2shell.rules
if augenrules --check >/dev/null 2>&1 || true; then :; fi
if auditctl -R /etc/audit/rules.d/php2shell.rules >/tmp/auditctl.out 2>&1; then
  if auditctl -l | grep -q php2shell_exec && auditctl -l | grep -q php2shell_webroot; then pass "auditd 규칙 로드와 목록 확인(auditctl -l)"; else fail "규칙이 목록에 없음"; auditctl -l; fi
  auditctl -D >/dev/null 2>&1
else
  fail "auditctl -R 실패"; cat /tmp/auditctl.out
fi

# 4) nftables
apt-get install -y -qq nftables curl >/dev/null 2>&1 || fail "nftables 설치"
if nft -c -f "$ROOT/virtual-patch/os/nftables-egress-example.nft"; then pass "nft -c 문법 검사 통과"; else fail "nft -c 실패"; fi
if nft -f "$ROOT/virtual-patch/os/nftables-egress-example.nft"; then
  pass "nft 규칙 적용"
  if su -s /bin/sh www-data -c 'curl -sS -m 6 -o /dev/null https://example.com' >/dev/null 2>&1; then fail "www-data 의 신규 외부 연결이 차단되지 않음"; else pass "www-data 의 신규 외부 연결 차단"; fi
  if curl -sS -m 10 -o /dev/null https://example.com >/dev/null 2>&1; then pass "root 의 외부 연결은 유지"; else fail "root 의 외부 연결까지 막힘"; fi
  nft delete table inet php2shell_egress && pass "롤백(nft delete table)" || fail "롤백 실패"
else
  fail "nft 규칙 적용 실패"
fi
exit "$FAIL"
