#!/bin/sh
# macOS Homebrew 의 PHP 를 점검 도구가 올바르게 찾고 판정하는지, 문서의 brew 명령이 동작하는지 확인한다.
#   1) `brew install php` 로 설치한 php/php-fpm 을 Python 판·sh 판이 둘 다 찾고 버전이 brew 와 같다
#      (비root 이므로 바이너리를 실행하거나 문자열로 읽는 경로)
#   2) `brew info php` 가 설치 버전을 보여 준다
#   3) `brew services start php` 후 실행 중인 php-fpm 프로세스를 running=true 로 찾는다
#      (launchd 서비스가 이 환경에서 시작되지 않으면 php-fpm 을 직접 띄워 탐지만 확인하고, 서비스 시작은 미검증으로 보고한다)
# 사용: sh tests/brew_check.sh   (macOS + Homebrew. 이미 php 가 설치돼 있으면 설치를 건너뛴다. 서비스는 시험 후 중지한다)
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INSPECT="python3 $ROOT/tests/_inspect_json.py"
FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=1; }
info() { echo "INFO $*"; }
[ "$(uname -s)" = Darwin ] && command -v brew >/dev/null 2>&1 || { echo "macOS + Homebrew 필요"; exit 2; }
FPM_PID=""
trap 'brew services stop php >/dev/null 2>&1; [ -n "$FPM_PID" ] && kill "$FPM_PID" 2>/dev/null' EXIT

brew list --versions php >/dev/null 2>&1 || brew install php >/dev/null 2>&1 || { fail "brew install php"; exit 1; }
BREWVER="$(brew list --versions php | awk '{print $2}' | sed 's/_.*//')"
echo "brew php 버전: $BREWVER ($(sw_vers -productVersion), $(uname -m))"
if brew info php 2>&1 | grep -q "$BREWVER"; then pass "brew info php 가 설치 버전 $BREWVER 를 보여 줌"; else fail "brew info php 에 설치 버전이 없음"; fi

PYJSON="$(python3 "$ROOT/php2shell_kr.py" --json --no-response 2>/dev/null)"
SHJSON="$(sh "$ROOT/quickcheck/php2shell-quickcheck.sh" --json 2>/dev/null)"
if echo "$PYJSON" | $INSPECT --path '/(Cellar|opt)/php[^/]*/[^"]*bin/php$' --version "$BREWVER"; then pass "python 판이 Homebrew php $BREWVER 를 찾음"; else fail "python 판이 Homebrew php $BREWVER 를 찾지 못함"; fi
if echo "$SHJSON" | $INSPECT --path '/(Cellar|opt)/php[^/]*/[^"]*bin/php$' --version "$BREWVER"; then pass "sh 판이 Homebrew php $BREWVER 를 찾음"; else fail "sh 판이 Homebrew php $BREWVER 를 찾지 못함"; fi

SVC="$(brew services start php 2>&1)"; echo "$SVC" | tail -3
i=0; while [ "$i" -lt 20 ] && ! pgrep -f "php-fpm" >/dev/null 2>&1; do sleep 1; i=$((i+1)); done
if pgrep -f "php-fpm" >/dev/null 2>&1; then
  pass "brew services start php 로 php-fpm 이 시작됨"
else
  info "brew services start php 가 이 환경에서 php-fpm 을 시작하지 못함(launchd 사용자 도메인 없음 등): 서비스 시작은 미검증, 탐지만 직접 실행으로 확인"
  "$(brew --prefix php)/sbin/php-fpm" --nodaemonize >/tmp/p2s-fpm.log 2>&1 &
  FPM_PID=$!
  sleep 3
fi
SHJSON="$(sh "$ROOT/quickcheck/php2shell-quickcheck.sh" --json 2>/dev/null)"
PYJSON="$(python3 "$ROOT/php2shell_kr.py" --json --no-response 2>/dev/null)"
if echo "$SHJSON" | $INSPECT --sapi fpm --running; then pass "sh 판이 실행 중인 php-fpm 을 running=true 로 찾음"; else fail "sh 판이 실행 중인 php-fpm 을 찾지 못함"; fi
if echo "$PYJSON" | $INSPECT --sapi fpm --running; then pass "python 판이 실행 중인 php-fpm 을 running=true 로 찾음"; else fail "python 판이 실행 중인 php-fpm 을 찾지 못함"; fi
exit "$FAIL"
