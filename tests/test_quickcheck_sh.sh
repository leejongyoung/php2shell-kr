#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lee Jongyoung
# tests/test_quickcheck_sh.sh - quickcheck/php2shell-quickcheck.sh 검증 하네스 (POSIX sh, jq/python 불필요)
#
# (a) tests/vectors/versions.json 의 모든 케이스를 --classify 로 확인
# (b) 가짜 PHP 실행 파일이 있는 임시 루트 트리를 만들어 --root --json 판정 확인
# (c) --plan-file 결과의 문법(sh -n)과 가드(종료 코드 64) 확인
# 하나라도 실패하면 0 이 아닌 종료 코드로 끝납니다.
#
# 사용법: sh tests/test_quickcheck_sh.sh

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
QC="$REPO/quickcheck/php2shell-quickcheck.sh"
VEC="$REPO/tests/vectors/versions.json"
ADV="$REPO/data/advisory.json"

PASS=0
FAIL=0

ok() { PASS=$((PASS + 1)); }
bad() { FAIL=$((FAIL + 1)); printf 'FAIL: %s\n' "$1"; }

TMP=$(mktemp -d 2>/dev/null) || TMP=$(mktemp -d -t qctest) || { echo 'mktemp 실패'; exit 1; }
trap 'rm -rf "$TMP"' EXIT

if [ ! -f "$QC" ]; then echo "스크립트가 없습니다: $QC"; exit 1; fi
if [ ! -f "$VEC" ]; then echo "벡터 파일이 없습니다: $VEC"; exit 1; fi

contains() { # 설명 출력문자열 부분문자열(고정 문자열)
  if printf '%s' "$2" | grep -qF -- "$3"; then ok; else bad "$1: '$3' 없음"; printf '%s\n' "$2" | head -c 1500; echo; fi
}
not_contains() {
  if printf '%s' "$2" | grep -qF -- "$3"; then bad "$1: '$3' 이(가) 있으면 안 됨"; else ok; fi
}
equals() { # 설명 기대값 실제값
  if [ "$2" = "$3" ]; then ok; else bad "$1: 기대 '$2', 실제 '$3'"; fi
}

# ---------------------------------------------------------------- (a) 분류 벡터
sed -n 's/.*"version": *"\([^"]*\)", *"class": *"\([^"]*\)".*/\1|\2/p' "$VEC" > "$TMP/cases.txt"
NCASES=$(wc -l < "$TMP/cases.txt" | tr -d ' ')
if [ "$NCASES" -lt 40 ]; then bad "versions.json 케이스를 충분히 읽지 못함($NCASES)"; fi
while IFS= read -r line; do
  ver=${line%|*}
  want=${line##*|}
  got=$(sh "$QC" --classify "$ver")
  if [ "$got" = "$want" ]; then ok; else bad "classify '$ver': 기대 $want, 실제 $got"; fi
done < "$TMP/cases.txt"
printf '(a) versions.json 케이스 %s개 확인\n' "$NCASES"

# advisory.json 의 출처 URL 이 스크립트에 모두 들어 있는지
sed -n 's/.*"url": *"\([^"]*\)".*/\1/p' "$ADV" > "$TMP/urls.txt"
NURL=0
while IFS= read -r u; do
  NURL=$((NURL + 1))
  if grep -qF -- "$u" "$QC"; then ok; else bad "advisory URL 이 스크립트에 없음: $u"; fi
done < "$TMP/urls.txt"
[ "$NURL" -ge 5 ] || bad "advisory.json 에서 URL 을 읽지 못함"

# ---------------------------------------------------------------- 픽스처 도우미
mkfake() { # 파일 버전줄 [표식파일]
  {
    printf '#!/bin/sh\n'
    if [ -n "$3" ]; then printf 'echo executed >> "%s"\n' "$3"; fi
    printf 'echo "%s"\n' "$2"
  } > "$1"
  chmod 755 "$1"
}

mkroot() { d="$TMP/$1"; mkdir -p "$d/usr/bin" "$d/usr/sbin"; printf '%s' "$d"; }

run_json() { sh "$QC" --json "$@" 2>/dev/null; }

# ---------------------------------------------------------------- (b-1) 취약
R=$(mkroot vuln)
mkfake "$R/usr/bin/php8.4" 'PHP 8.4.26 (cli) (built: Oct  1 2026 00:00:00) (NTS)'
ln -s php8.4 "$R/usr/bin/php"
mkfake "$R/usr/sbin/php-fpm8.4" 'PHP 8.4.26 (fpm-fcgi) (built: Oct  1 2026 00:00:00) (NTS)'
out=$(run_json --root "$R" --exec); rc=$?
equals 'vuln exit code' 1 "$rc"
contains 'vuln cli' "$out" '"path":"/usr/bin/php8.4","version":"8.4.26","class":"vulnerable","verdict":"vulnerable","sapi":"cli"'
contains 'vuln fpm' "$out" '"path":"/usr/sbin/php-fpm8.4","version":"8.4.26","class":"vulnerable","verdict":"vulnerable","sapi":"fpm"'
contains 'vuln summary' "$out" '"summary":{"vulnerable":2,"fixed":0,"vendor_patched":0,"eol":0,"unknown":0,"needs_restart":0}'
contains 'vuln tool' "$out" '"tool":"php2shell-quickcheck-sh"'
contains 'vuln as_of' "$out" '"as_of":"2026-10-23"'
contains 'vuln exit_code field' "$out" '"exit_code":1}'
# php 심볼릭 링크가 별도 설치로 중복 집계되지 않아야 함
n=$(printf '%s' "$out" | grep -o '"path":' | wc -l | tr -d ' ')
equals 'vuln dedupe (설치 2개)' 2 "$n"
# 사람이 읽는 출력
txt=$(sh "$QC" --root "$R" --exec 2>/dev/null)
contains 'text 취약 표시' "$txt" '[취약] 8.4.26'
contains 'text 조치 계획' "$txt" '조치 계획'
contains 'text 증거 보존' "$txt" '증거 보존/신고'
contains 'text KISA' "$txt" 'KISA 118'
contains 'text boho' "$txt" 'https://boho.or.kr'
contains 'text 가상 패치' "$txt" 'virtual-patch/'
not_contains 'text 오프라인은 기본 미출력' "$txt" '오프라인/폐쇄망 패치 절차'
txt2=$(sh "$QC" --root "$R" --exec --offline 2>/dev/null)
contains 'text --offline' "$txt2" '오프라인/폐쇄망 패치 절차'

# JSON 유효성(도구가 있을 때만 추가 검증)
if command -v python3 >/dev/null 2>&1; then
  if printf '%s' "$out" | python3 -c 'import json,sys; json.load(sys.stdin)' 2>/dev/null; then ok; else bad 'JSON 이 python3 로 파싱되지 않음'; fi
elif command -v jq >/dev/null 2>&1; then
  if printf '%s' "$out" | jq . >/dev/null 2>&1; then ok; else bad 'JSON 이 jq 로 파싱되지 않음'; fi
fi

# ---------------------------------------------------------------- (b-2) 수정됨
R=$(mkroot fixed)
mkfake "$R/usr/bin/php8.4" 'PHP 8.4.27 (cli) (built: Oct 22 2026 00:00:00) (NTS)'
out=$(run_json --root "$R" --exec); rc=$?
equals 'fixed exit code' 0 "$rc"
contains 'fixed verdict' "$out" '"version":"8.4.27","class":"fixed","verdict":"fixed"'
contains 'fixed summary' "$out" '"summary":{"vulnerable":0,"fixed":1,"vendor_patched":0,"eol":0,"unknown":0,"needs_restart":0}'

# ---------------------------------------------------------------- (b-3) EOL
R=$(mkroot eol)
mkfake "$R/usr/bin/php7.4" 'PHP 7.4.33 (cli)'
mkfake "$R/usr/bin/php5.3" 'PHP 5.3.29 (cli)'
out=$(run_json --root "$R" --exec); rc=$?
equals 'eol exit code' 1 "$rc"
contains 'eol_backport 은 vulnerable verdict' "$out" '"version":"7.4.33","class":"eol_backport","verdict":"vulnerable"'
contains 'old_unsupported 은 eol verdict' "$out" '"version":"5.3.29","class":"old_unsupported","verdict":"eol"'
contains 'eol summary' "$out" '"vulnerable":1,"fixed":0,"vendor_patched":0,"eol":1'

# ---------------------------------------------------------------- (b-4) Debian 벤더 패치
mkdeb() { # 루트 changelog내용 모드(both|one)
  mkdir -p "$1/var/lib/dpkg/info" "$1/usr/share/doc/php8.2-fpm"
  printf 'NAME="Debian GNU/Linux"\nID=debian\nPRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nVERSION_ID="12"\n' > "$1/etc-os-release.tmp"
  mkdir -p "$1/etc"; mv "$1/etc-os-release.tmp" "$1/etc/os-release"
  printf 'Package: php8.2-fpm\nStatus: install ok installed\nVersion: 8.2.34-1~deb12u2\nArchitecture: amd64\n\n' > "$1/var/lib/dpkg/status"
  printf '/usr\n/usr/sbin\n/usr/sbin/php-fpm8.2\n' > "$1/var/lib/dpkg/info/php8.2-fpm.list"
  if [ "$3" = both ]; then
    printf 'php8.2 (8.2.34-1~deb12u2) bookworm-security; urgency=high\n\n  * Fix %s\n  * Fix %s\n\n -- Maintainer <m@example.org>  Fri, 23 Oct 2026 00:00:00 +0000\n' CVE-2026-109618 CVE-2026-109619 > "$1/clog.txt"
  else
    printf 'php8.2 (8.2.34-1~deb12u2) bookworm-security; urgency=high\n\n  * Fix %s\n\n -- Maintainer <m@example.org>  Fri, 23 Oct 2026 00:00:00 +0000\n' CVE-2026-109618 > "$1/clog.txt"
  fi
  if command -v gzip >/dev/null 2>&1; then
    gzip -c "$1/clog.txt" > "$1/usr/share/doc/php8.2-fpm/changelog.Debian.gz"
  else
    cp "$1/clog.txt" "$1/usr/share/doc/php8.2-fpm/changelog.Debian"
  fi
  rm -f "$1/clog.txt"
}

R=$(mkroot deb)
mkfake "$R/usr/sbin/php-fpm8.2" 'PHP 8.2.34 (fpm-fcgi) (built: Oct 20 2026 00:00:00) (NTS)'
mkdeb "$R" x both
out=$(run_json --root "$R" --exec); rc=$?
equals 'deb vendor_patched exit code' 0 "$rc"
contains 'deb vendor_patched' "$out" '"path":"/usr/sbin/php-fpm8.2","version":"8.2.34","class":"vulnerable","verdict":"vendor_patched","sapi":"fpm"'
contains 'deb package' "$out" '"package":"php8.2-fpm","vendor_patch":"yes"'
contains 'deb summary' "$out" '"summary":{"vulnerable":0,"fixed":0,"vendor_patched":1'

R=$(mkroot debone)
mkfake "$R/usr/sbin/php-fpm8.2" 'PHP 8.2.34 (fpm-fcgi)'
mkdeb "$R" x one
out=$(run_json --root "$R" --exec); rc=$?
equals 'deb 한 개 CVE 만 있으면 vulnerable (exit)' 1 "$rc"
contains 'deb 한 개 CVE 만' "$out" '"verdict":"vulnerable"'
contains 'deb vendor_patch no' "$out" '"package":"php8.2-fpm","vendor_patch":"no"'

# ---------------------------------------------------------------- (b-5) --no-exec
R=$(mkroot noexec)
MARK="$TMP/executed.mark"
rm -f "$MARK"
{
  printf '#!/bin/sh\necho executed >> "%s"\n' "$MARK"
  printf '# X-Powered-By: PHP/8.4.26\n'
  printf 'echo "PHP 8.4.27 (cli)"\n'
} > "$R/usr/bin/php8.4"
chmod 755 "$R/usr/bin/php8.4"
out=$(run_json --root "$R" --no-exec); rc=$?
if [ -e "$MARK" ]; then bad '--no-exec 인데 바이너리가 실행됨'; else ok; fi
equals 'no-exec exit' 1 "$rc"
contains 'no-exec 정적 문자열 버전' "$out" '"version":"8.4.26","class":"vulnerable","verdict":"vulnerable"'
# 같은 파일을 실행 모드로 돌리면 실제 실행 결과(8.4.27)를 사용
out=$(run_json --root "$R" --exec); rc=$?
if [ -e "$MARK" ]; then ok; else bad '실행 모드인데 바이너리가 실행되지 않음'; fi
contains 'exec 모드 버전' "$out" '"version":"8.4.27","class":"fixed","verdict":"fixed"'

# 패키지 DB 로 버전 확인(--no-exec, 정적 문자열 없음)
R=$(mkroot noexecdeb)
rm -f "$MARK"
mkfake "$R/usr/sbin/php-fpm8.2" 'PHP 8.2.99 (fpm-fcgi)' "$MARK"
mkdeb "$R" x both
out=$(run_json --root "$R" --no-exec); rc=$?
if [ -e "$MARK" ]; then bad '--no-exec(deb) 인데 바이너리가 실행됨'; else ok; fi
contains 'no-exec 패키지 DB 버전' "$out" '"version":"8.2.34","class":"vulnerable","verdict":"vendor_patched"'

# ---------------------------------------------------------------- (b-5b) --root 만 주면 기본 비실행, --exec 로만 실행
R=$(mkroot rootdefault)
rm -f "$MARK"
{
  printf '#!/bin/sh\necho executed >> "%s"\n' "$MARK"
  printf '# X-Powered-By: PHP/8.4.26\n'
  printf 'echo "PHP 8.4.27 (cli)"\n'
} > "$R/usr/bin/php8.4"
chmod 755 "$R/usr/bin/php8.4"
out=$(run_json --root "$R"); rc=$?
if [ -e "$MARK" ]; then bad '--root 기본값인데 바이너리가 실행됨'; else ok; fi
contains 'root 기본 비실행: 문자열 기반 판정' "$out" '"version":"8.4.26","class":"vulnerable","verdict":"vulnerable"'
contains 'root 기본 비실행: 출처 표시' "$out" '정적 문자열 스캔'
equals 'root 기본 비실행 exit' 1 "$rc"
txt=$(sh "$QC" --root "$R" 2>/dev/null)
if [ -e "$MARK" ]; then bad '--root 기본값(text)인데 바이너리가 실행됨'; else ok; fi
contains 'root 기본 비실행 모드 안내' "$txt" '--root 기본 비실행'
# --exec 와 --no-exec 를 함께 주면 --no-exec 가 우선
out=$(run_json --root "$R" --exec --no-exec)
if [ -e "$MARK" ]; then bad '--exec --no-exec 인데 바이너리가 실행됨'; else ok; fi
# --exec 를 주면 실행
out=$(run_json --root "$R" --exec)
if [ -e "$MARK" ]; then ok; else bad '--root --exec 인데 실행되지 않음'; fi
contains '--root --exec 는 실행 결과 사용' "$out" '"version":"8.4.27","class":"fixed","verdict":"fixed"'
# 문자열이 없으면 버전 미확인 + 안내 노트
R=$(mkroot rootunknown)
rm -f "$MARK"
mkfake "$R/usr/bin/php8.4" 'PHP 8.4.26 (cli)' "$MARK"
out=$(run_json --root "$R"); rc=$?
if [ -e "$MARK" ]; then bad '--root 기본값(unknown)인데 바이너리가 실행됨'; else ok; fi
equals 'root 기본 비실행 버전 미확인 exit' 3 "$rc"
contains 'root 기본 비실행 미확인 verdict' "$out" '"version":null,"class":"unknown","verdict":"unknown"'
contains 'root 기본 비실행 안내 노트' "$out" '--root 에서는 바이너리를 실행하지 않습니다. 신뢰할 수 있는 트리라면 --exec'

# 버전을 알 수 없을 때
R=$(mkroot unknown)
mkfake "$R/usr/bin/php8.4" 'garbage output'
out=$(run_json --root "$R" --no-exec); rc=$?
equals 'unknown exit code' 3 "$rc"
contains 'unknown verdict' "$out" '"version":null,"class":"unknown","verdict":"unknown"'

# ---------------------------------------------------------------- (b-6) 빈 루트
R="$TMP/empty"; mkdir -p "$R"
out=$(run_json --root "$R"); rc=$?
equals 'empty exit code' 0 "$rc"
contains 'empty installations' "$out" '"installations":[]'
contains 'empty summary' "$out" '"summary":{"vulnerable":0,"fixed":0,"vendor_patched":0,"eol":0,"unknown":0,"needs_restart":0}'

# ---------------------------------------------------------------- (b-7) 잘못된 인자
sh "$QC" --bogus >/dev/null 2>&1; equals '잘못된 옵션은 종료 코드 2' 2 "$?"
sh "$QC" --root "$TMP/nonexistent-dir" >/dev/null 2>&1; equals '없는 --root 는 종료 코드 2' 2 "$?"
out=$(sh "$QC" --help 2>&1); equals '--help 종료 코드' 0 "$?"
contains '--help 에 --plan-file' "$out" '--plan-file'

# ---------------------------------------------------------------- (c) --plan-file
R=$(mkroot plan)
mkdir -p "$R/run/systemd/system"
mkfake "$R/usr/sbin/php-fpm8.2" 'PHP 8.2.34 (fpm-fcgi)'
mkdeb "$R" x one
PF="$TMP/plan-out.sh"
out=$(sh "$QC" --root "$R" --plan-file "$PF" 2>/dev/null); rc=$?
equals 'plan-file 실행 종료 코드(취약이므로 1)' 1 "$rc"
if [ -s "$PF" ]; then ok; else bad 'plan-file 이 만들어지지 않음'; fi
contains 'plan-file 저장 안내' "$out" '조치 계획 파일 저장'
if sh -n "$PF" 2>/dev/null; then ok; else bad 'plan-file sh -n 문법 오류'; fi
first=$(head -1 "$PF")
equals 'plan-file 첫 줄 shebang' '#!/bin/sh' "$first"
body=$(cat "$PF")
contains 'plan-file 경고 주석' "$body" '자동 실행용이 아닙니다'
contains 'plan-file 가드 변수' "$body" 'PHP2SHELL_I_REVIEWED'
contains 'plan-file exit 64' "$body" 'exit 64'
contains 'plan-file confirm 함수' "$body" 'confirm() {'
contains 'plan-file 패키지 이름 반영' "$body" 'apt-get install --only-upgrade php8.2-fpm'
contains 'plan-file 서비스 유닛 반영' "$body" 'systemctl restart php8.2-fpm'
contains 'plan-file 증거 보존 단계' "$body" '단계 0: 증거 보존'
l0=$(grep -n '단계 0: 증거 보존' "$PF" | head -1 | cut -d: -f1)
l1=$(grep -n '단계 1: 업데이트' "$PF" | head -1 | cut -d: -f1)
l3=$(grep -n '단계 3: 재시작' "$PF" | head -1 | cut -d: -f1)
if [ -n "$l0" ] && [ -n "$l1" ] && [ -n "$l3" ] && [ "$l0" -lt "$l1" ] && [ "$l1" -lt "$l3" ]; then ok; else bad 'plan-file 단계 순서(증거 보존 -> 업데이트 -> 재시작)'; fi
if grep -q 'if confirm .*업그레이드' "$PF" && grep -q 'if confirm .*재시작' "$PF"; then ok; else bad 'plan-file 위험 단계 앞 confirm 없음'; fi
# 가드: 환경변수 없이 실행하면 64
msg=$(env -u PHP2SHELL_I_REVIEWED sh "$PF" 2>&1 </dev/null); rc=$?
equals 'plan-file 가드 종료 코드 64' 64 "$rc"
contains 'plan-file 가드 메시지' "$msg" '자동 실행용이 아닙니다. 각 단계를 검토한 뒤 직접 실행하세요'
# 가드를 통과해도 stdin 이 닫혀 있으면 첫 confirm 에서 중단되어 아무것도 실행되지 않음
msg=$(PHP2SHELL_I_REVIEWED=yes sh "$PF" 2>&1 </dev/null); rc=$?
equals 'plan-file 검토 후에도 첫 confirm 에서 중단(1)' 1 "$rc"
contains 'plan-file 증거 보존 먼저' "$msg" '[단계 0] 증거 보존'
not_contains 'plan-file 단계 1 은 실행되지 않음' "$msg" '[단계 1]'
# 기존 파일은 덮어쓰지 않음
sh "$QC" --root "$R" --plan-file "$PF" >/dev/null 2>&1; equals '기존 plan-file 은 덮어쓰지 않음(2)' 2 "$?"
# --json 과 함께 쓰면 stdout 은 JSON 만
PF2="$TMP/plan-json.sh"
out=$(sh "$QC" --root "$R" --json --plan-file "$PF2" 2>/dev/null)
contains 'json+plan-file stdout 은 JSON' "$out" '"tool":"php2shell-quickcheck-sh"'
not_contains 'json+plan-file stdout 에 안내 없음' "$out" '조치 계획 파일 저장'
if [ -s "$PF2" ] && sh -n "$PF2" 2>/dev/null; then ok; else bad 'json+plan-file 파일 문법'; fi
# --offline 은 파일의 단계 5 주석에 오프라인 절차를 추가
PF3="$TMP/plan-off.sh"
sh "$QC" --root "$R" --offline --plan-file "$PF3" >/dev/null 2>&1
contains 'plan-file --offline' "$(cat "$PF3")" '오프라인/폐쇄망 패치 절차'
if sh -n "$PF3" 2>/dev/null; then ok; else bad 'plan-file(--offline) sh -n'; fi
# 도구가 계획 명령을 실행하지 않았음: 취약 fixture 의 표식 파일 없음(--no-exec 사용)
PF4="$TMP/plan-noexec.sh"
sh "$QC" --root "$R" --no-exec --plan-file "$PF4" >/dev/null 2>&1
if sh -n "$PF4" 2>/dev/null; then ok; else bad 'plan-file(--no-exec) sh -n'; fi

# ---------------------------------------------------------------- (d) 보안 회귀
# H1: auto 정책은 root 일 때 /tmp 트리를 신뢰하지 않고, --exec 만 강제 실행.
R=$(mkroot trustauto)
rm -f "$MARK"
mkfake "$R/usr/bin/php8.4" 'PHP 8.4.26 (cli)' "$MARK"
out=$(run_json --root "$R" --test-exec-policy auto); rc=$?
if [ "$(id -u)" = 0 ]; then
  if [ -e "$MARK" ]; then bad 'auto privileged 에서 /tmp 의 바이너리를 실행함'; else ok; fi
  contains 'auto privileged 거부 설명' "$out" '실행 안 함: 신뢰할 수 없는 위치'
  equals 'auto privileged unknown' 3 "$rc"
else
  if [ -e "$MARK" ]; then ok; else bad 'auto 비특권 실행은 허용되어야 함'; fi
fi
out=$(run_json --root "$R" --exec)
if [ -e "$MARK" ]; then ok; else bad '--exec 강제 실행되지 않음'; fi

# 신뢰 함수의 metadata seam: 실제 파일은 필요하지만 UID/모드는 주입 가능.
awk '/^# BEGIN TRUST POLICY/ {p=1;next} /^# END TRUST POLICY/ {p=0} p' "$QC" > "$TMP/trust-functions.sh"
# 신뢰 predicate 는 심볼릭 링크 파일을 거부하므로(호출자가 해석한 경로를 넘김) 링크가 아닌 실제 파일을 고름.
# openSUSE 처럼 /bin 이 /usr/bin 링크이고 /bin/ls 도 링크인 배포판이 있음.
TRUST_FILE=""
for cand in /usr/bin/ls /bin/ls /bin/busybox /usr/bin/cat /bin/cat /usr/bin/env /bin/sh; do
  if [ -f "$cand" ] && [ ! -L "$cand" ]; then TRUST_FILE=$cand; break; fi
done
if [ -z "$TRUST_FILE" ]; then bad '신뢰 predicate 테스트용 실제 파일을 찾지 못함'; TRUST_FILE=/bin/ls; fi
if (
  . "$TMP/trust-functions.sh"
  trust_metadata() { printf '%s 1 %s 0 1 Jan 1 00:00 target\n' "${TEST_MODE:--rwxr-xr-x}" "${TEST_UID:-0}"; }
  TEST_UID=0; TEST_MODE=-rwxr-xr-x
  trusted_path "$TRUST_FILE" || exit 1
  TEST_UID=1000; trusted_path "$TRUST_FILE" && exit 2
  TEST_UID=0; TEST_MODE=-rwxrwxr-x; trusted_path "$TRUST_FILE" && exit 3
  TEST_MODE=-rwxr-xrwx; trusted_path "$TRUST_FILE" && exit 4
  TEST_MODE=-rwxr-xr-x
  exec_allowed auto /tmp/php 0 1000 || exit 5
  exec_allowed never "$TRUST_FILE" 0 1000 && exit 6
  exec_allowed all "$TRUST_FILE" 1 0 && exit 7
  exec_allowed all /proc/123/exe 0 0 && exit 8
  trust_metadata() {
    if [ "$1" = / ]; then echo 'drwxrwxrwx 1 0 0 1 Jan 1 00:00 root'
    else echo '-rwxr-xr-x 1 0 0 1 Jan 1 00:00 file'; fi
  }
  trusted_path "$TRUST_FILE" && exit 9
  exit 0
); then ok; else bad "신뢰 predicate metadata/policy 회귀: $?"; fi

# env -i: 비밀 환경변수/PATH 를 자식에게 전달하지 않음.
R=$(mkroot envclean)
cat > "$R/usr/bin/php8.4" <<'ENVFIX'
#!/bin/sh
if [ -n "${PHP2SHELL_SECRET_TEST:-}" ] || [ "$PATH" != /usr/sbin:/usr/bin:/sbin:/bin ] || [ "$LC_ALL" != C ]; then
  echo 'PHP 8.4.26 (cli)'
else
  echo 'PHP 8.4.27 (cli)'
fi
ENVFIX
chmod 755 "$R/usr/bin/php8.4"
out=$(PHP2SHELL_SECRET_TEST=leak run_json --root "$R" --exec)
contains 'env -i 비밀/PATH 제거' "$out" '"version":"8.4.27","class":"fixed"'
# 상속 PATH 에 가짜 시스템 도구가 있어도 사용하지 않음.
mkdir -p "$TMP/badtools"
mkfake "$TMP/badtools/uname" 'HIJACKED'
out=$(PATH="$TMP/badtools:$PATH" /bin/sh "$QC" --root "$R" --exec --json 2>/dev/null)
not_contains '절대 경로 도구: PATH 탈취 방지' "$out" 'HIJACKED'

# 자식 출력 4096바이트 이후의 버전 문자열은 판정에 사용하지 않음.
R=$(mkroot hugeoutput)
cat > "$R/usr/bin/php8.4" <<'BIGFIX'
#!/bin/sh
awk 'BEGIN {for(i=0;i<5000;i++) printf "A"; print ""; print "PHP 8.4.27 (cli)"}'
BIGFIX
chmod 755 "$R/usr/bin/php8.4"
out=$(run_json --root "$R" --exec); rc=$?
equals '실행 출력 4096바이트 상한' 3 "$rc"
contains '4096 이후 버전 미인정' "$out" '"version":null,"class":"unknown"'

# M1: 수정된 설치가 있어도 unknown 한 건이면 종료 코드 3.
R=$(mkroot mixedunknown)
mkfake "$R/usr/bin/php8.4" 'PHP 8.4.27 (cli)'
mkfake "$R/usr/bin/php8.3" 'garbage'
out=$(run_json --root "$R" --exec); rc=$?
equals 'fixed + unknown 은 exit 3' 3 "$rc"
contains 'mixed fixed' "$out" '"fixed":1'
contains 'mixed unknown' "$out" '"unknown":1'

# M5: 상대 링크 탈출/디렉터리 링크 탈출 거부, 절대 링크는 트리 안으로 재루팅.
R=$(mkroot containment)
mkdir -p "$TMP/outside"
rm -f "$MARK"
mkfake "$TMP/outside/php" 'PHP 8.4.27 (cli)' "$MARK"
ln -s ../../../outside/php "$R/usr/bin/php8.4"
out=$(sh "$QC" --root "$R" --exec --json 2>"$TMP/escape.err")
if [ -e "$MARK" ]; then bad '상대 링크로 ROOT 밖 바이너리 실행'; else ok; fi
contains '상대 링크 밖 파일은 미탐색' "$out" '"installations":[]'
contains '탈출 경로 무시 안내' "$(cat "$TMP/escape.err")" '경로 무시'
rm "$R/usr/bin/php8.4"
ln -s /usr/sbin/php-fpm8.4 "$R/usr/bin/php8.4"
mkfake "$R/usr/sbin/php-fpm8.4" 'PHP 8.4.26 (fpm-fcgi)'
out=$(run_json --root "$R" --exec)
contains '절대 링크 재루팅' "$out" '"path":"/usr/sbin/php-fpm8.4","version":"8.4.26"'
n=$(printf '%s' "$out" | grep -o '"path":' | wc -l | tr -d ' ')
equals '절대 링크 재루팅 중복 제거' 1 "$n"
R=$(mkroot dircontainment)
rm -rf "$R/usr/bin"
ln -s ../../outside "$R/usr/bin"
out=$(run_json --root "$R" --exec)
if [ -e "$MARK" ]; then bad '디렉터리 링크로 ROOT 밖 실행'; else ok; fi
contains '디렉터리 링크 탈출 거부' "$out" '"installations":[]'
# FIFO 는 열지 않음. 대형 regular file 문자열도 스캔하지 않음.
R=$(mkroot nonregular)
mkfifo "$R/usr/bin/php8.4"
out=$(run_json --root "$R")
contains 'FIFO 무시(블로킹 없음)' "$out" '"installations":[]'
rm "$R/usr/bin/php8.4"
printf '# X-Powered-By: PHP/8.4.27\n' > "$R/usr/bin/php8.4"
dd if=/dev/zero of="$R/usr/bin/php8.4" bs=1 count=1 seek=125829121 2>/dev/null
out=$(run_json --root "$R"); rc=$?
equals '120MB 초과 바이너리 미판정' 3 "$rc"
contains '대형 파일 버전 미인정' "$out" '"version":null,"class":"unknown"'
# config 와 changelog 의 ROOT 밖 링크도 읽지 않음.
R=$(mkroot configcontainment)
mkfake "$R/usr/sbin/php-fpm8.2" 'PHP 8.2.34 (fpm-fcgi)'
mkdeb "$R" x one
printf 'session.auto_start = 999\n' > "$TMP/outside/php.ini"
ln -s ../../outside/php.ini "$R/etc/php.ini"
txt=$(sh "$QC" --root "$R" 2>/dev/null)
not_contains '설정 파일 탈출 미읽기' "$txt" 'session.auto_start = 999'
rm -f "$R/usr/share/doc/php8.2-fpm/changelog.Debian" "$R/usr/share/doc/php8.2-fpm/changelog.Debian.gz"
printf 'php8.2 (8.2.34) stable; urgency=high\n  * Fix CVE-2026-109618 and CVE-2026-109619\n' > "$TMP/outside/changelog"
ln -s ../../../../../../outside/changelog "$R/usr/share/doc/php8.2-fpm/changelog.Debian"
out=$(run_json --root "$R")
not_contains '변경 이력 탈출 미읽기' "$out" '"verdict":"vendor_patched"'

# M6: 변경 이력 항목 경계 + 일치 줄 notes.
R=$(mkroot debentry)
mkfake "$R/usr/sbin/php-fpm8.2" 'PHP 8.2.34 (fpm-fcgi)'
mkdeb "$R" x both
out=$(run_json --root "$R")
contains '벤더 근거 일치 줄 노출' "$out" '벤더 변경 이력 일치 줄:'
contains '벤더 근거 실제 줄' "$out" '* Fix CVE-2026-109618'
rm -f "$R/usr/share/doc/php8.2-fpm/changelog.Debian.gz"
printf 'Bare documentation: CVE-2026-109618 CVE-2026-109619\n' > "$R/usr/share/doc/php8.2-fpm/changelog.Debian"
out=$(run_json --root "$R")
contains '항목 밖 두 CVE 언급 불인정' "$out" '"verdict":"vulnerable"'
cat > "$R/usr/share/doc/php8.2-fpm/changelog.Debian" <<'SPLITDEB'
php8.2 (8.2.34-1) stable; urgency=high
  * Fix CVE-2026-109618
 -- Maintainer  Fri, 23 Oct 2026
php8.2 (8.2.33-1) stable; urgency=high
  * Fix CVE-2026-109619
 -- Maintainer  Thu, 22 Oct 2026
SPLITDEB
out=$(run_json --root "$R")
contains '서로 다른 항목의 CVE 불인정' "$out" '"verdict":"vulnerable"'
# RPM parser 는 실제 함수 추출로 rpm 유무와 관계없이 양쪽 형식의 경계를 검증.
awk '/^vendor_entries\(\)/ {p=1} p {print} p && /^}/ {exit}' "$QC" > "$TMP/vendor-parser.sh"
rpm_ok=$(
  . "$TMP/vendor-parser.sh"
  printf '* Fri Oct 23 2026 Maintainer - 8.2.34\n- Fix CVE-2026-109618\n- Fix CVE-2026-109619\n' | vendor_entries rpm
)
contains 'RPM 유효 항목 인식' "$rpm_ok" 'CVE-2026-109619'
rpm_bad=$(
  . "$TMP/vendor-parser.sh"
  printf 'CVE-2026-109618 CVE-2026-109619\n* Fri Oct 23 2026 Maintainer - 8.2.34\n- Fix CVE-2026-109618\n* Thu Oct 22 2026 Maintainer - 8.2.33\n- Fix CVE-2026-109619\n' | vendor_entries rpm
)
equals 'RPM 항목 밖/분리 항목 불인정' "" "$rpm_bad"
# gzip bomb: 2MB 뒤 두 CVE 가 있어도 버퍼를 넘겨 읽지 않음.
if command -v gzip >/dev/null 2>&1; then
  {
    printf 'php8.2 (8.2.34-1) stable; urgency=high\n'
    awk 'BEGIN {for(i=0;i<40000;i++) print "  padding padding padding padding padding padding padding padding"}'
    printf '  * Fix CVE-2026-109618 and CVE-2026-109619\n'
  } | gzip -c > "$R/usr/share/doc/php8.2-fpm/changelog.Debian.gz"
  out=$(run_json --root "$R")
  contains 'gzip 출력 2MB 상한' "$out" '"verdict":"vulnerable"'
fi

# M7/LOW: 터미널 제어문자/IFS 구분자는 데이터로만, 유닛명에 세미콜론은 제안 안 함.
R=$(mkroot hostile)
mkdeb "$R" x one
mkdir -p "$R/run/systemd/system"
ESC=$(printf '\033'); SEP=$(printf '\037'); REC=$(printf '\036'); NL='
'
for hostile in "php-fpm8.4;UNSAFE" "php8.4${ESC}[2K" "php8.4${SEP}fixed" "php8.4${REC}fixed" "php8.4${NL}fixed"; do
  mkfake "$R/usr/sbin/$hostile" 'PHP 8.4.26 (fpm-fcgi)'
done
txt=$(sh "$QC" --root "$R" --exec 2>/dev/null)
if printf '%s' "$txt" | grep -q "$ESC"; then bad '터미널 ESC 가 그대로 출력됨'; else ok; fi
if printf '%s' "$txt" | grep -q "$SEP"; then bad 'IFS 구분자 US 가 출력됨'; else ok; fi
if printf '%s' "$txt" | grep -q "$REC"; then bad 'IFS 구분자 RS 가 출력됨'; else ok; fi
not_contains '악성 유닛명 제안 거부' "$txt" 'systemctl restart php-fpm8.4;UNSAFE'
not_contains '경로로 fixed 행 위조 불가' "$txt" '[수정됨]'
HPLAN="$TMP/hostile-plan.sh"
sh "$QC" --root "$R" --exec --plan-file "$HPLAN" >/dev/null 2>&1
if sh -n "$HPLAN"; then ok; else bad 'hostile plan 문법'; fi
not_contains 'plan 악성 유닛 거부' "$(cat "$HPLAN")" 'restart php-fpm8.4;UNSAFE'
# Unicode NEL / line separator 도 한국어를 손상시키지 않고 제거.
R=$(mkroot unicodehost)
mkdir -p "$R/etc"
printf 'ID=debian\nPRETTY_NAME="한글\302\205X\342\200\250Y\342\200\251Z"\n' > "$R/etc/os-release"
txt=$(sh "$QC" --root "$R" 2>/dev/null)
contains 'Unicode 제어문자 정화, 한글 보존' "$txt" '한글?X?Y?Z'

# M9/M10: dangling symlink/기존 파일 거부, 0700, 첫 실행문 가드, 증거 umask.
R=$(mkroot safewrite)
DANGLE="$TMP/dangling-plan.sh"
ln -s "$TMP/must-not-exist" "$DANGLE"
sh "$QC" --root "$R" --plan-file "$DANGLE" >/dev/null 2>&1
equals 'dangling plan 링크 거부 exit2' 2 "$?"
if [ -e "$TMP/must-not-exist" ]; then bad 'dangling plan 링크를 따라 파일 생성'; else ok; fi
SECPLAN="$TMP/private-plan.sh"
sh "$QC" --root "$R" --plan-file "$SECPLAN" >/dev/null 2>&1
mode=$(ls -ld "$SECPLAN"); mode=${mode%% *}; mode=${mode%@}
equals 'plan 권한 0700' '-rwx------' "$mode"
guard=$(awk '/^[[:space:]]*#/ || /^[[:space:]]*$/ {next} {print;exit}' "$SECPLAN")
contains 'plan 첫 실행문은 review 가드' "$guard" 'PHP2SHELL_I_REVIEWED'
maskline=$(grep -n '^umask 077$' "$SECPLAN" | head -1 | cut -d: -f1)
mkdirline=$(grep -n 'mkdir -p "$EVID"' "$SECPLAN" | head -1 | cut -d: -f1)
if [ -n "$maskline" ] && [ -n "$mkdirline" ] && [ "$maskline" -lt "$mkdirline" ]; then ok; else bad '증거 mkdir 전에 umask 077 없음'; fi
# 기존 파일을 교체하지 않고 그대로 두는지 내용까지 확인.
printf 'keep me\n' > "$TMP/existing-plan.sh"
sh "$QC" --root "$R" --plan-file "$TMP/existing-plan.sh" >/dev/null 2>&1
equals '기존 파일 거부 exit2' 2 "$?"
equals '기존 파일 내용 보존' 'keep me' "$(cat "$TMP/existing-plan.sh")"

# ---------------------------------------------------------------- 결과
printf '통과 %s / 실패 %s\n' "$PASS" "$FAIL"
if [ "$FAIL" -ne 0 ]; then
  echo 'RESULT: FAIL'
  exit 1
fi
echo 'RESULT: PASS'
exit 0
