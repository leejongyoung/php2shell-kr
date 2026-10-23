#!/bin/sh
# macOS Homebrew 의 PHP 를 점검 도구가 올바르게 찾고 판정하는지, 문서의 brew 명령이 동작하는지 확인한다.
#   1) `brew install php` 로 설치한 php/php-fpm 을 Python 판·sh 판이 둘 다 찾는다
#   2) 도구가 읽은 버전이 `brew list --versions php` 와 같다 (비root 이므로 바이너리 문자열로 읽는 경로)
#   3) `brew info php` 가 문서가 안내한 대로 설치 버전을 보여 준다
#   4) `brew services start php` 후 실행 중인 php-fpm 프로세스를 running=true 로 찾는다
# 사용: sh tests/brew_check.sh   (macOS + Homebrew. 이미 php 가 설치돼 있으면 설치를 건너뛴다. 서비스는 시험 후 중지한다)
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=1; }
[ "$(uname -s)" = Darwin ] && command -v brew >/dev/null 2>&1 || { echo "macOS + Homebrew 필요"; exit 2; }
trap 'brew services stop php >/dev/null 2>&1' EXIT

brew list --versions php >/dev/null 2>&1 || brew install php >/dev/null 2>&1 || { fail "brew install php"; exit 1; }
BREWVER="$(brew list --versions php | awk '{print $2}' | sed 's/_.*//')"
echo "brew php 버전: $BREWVER"
if brew info php 2>&1 | grep -q "$BREWVER"; then pass "brew info php 가 설치 버전 $BREWVER 를 보여 줌"; else fail "brew info php 에 설치 버전이 없음"; fi

PYJSON="$(python3 "$ROOT/php2shell_triage.py" --json --no-response 2>/dev/null)"
SHJSON="$(sh "$ROOT/quickcheck/php2shell-quickcheck.sh" --json 2>/dev/null)"
for name in "python:$PYJSON" "sh:$SHJSON"; do
  impl="${name%%:*}"; json="${name#*:}"
  if echo "$json" | grep -Eq "\"path\": ?\"[^\"]*/(Cellar|opt)/php[^\"]*/bin/php\", ?\"version\": ?\"$BREWVER\""; then
    pass "$impl 판이 Homebrew php $BREWVER 를 찾음"
  else
    fail "$impl 판이 Homebrew php $BREWVER 를 찾지 못함"; echo "$json" | head -c 1200
  fi
done

brew services start php >/dev/null 2>&1 || fail "brew services start php"
i=0; while [ "$i" -lt 20 ] && ! pgrep -f "php-fpm" >/dev/null 2>&1; do sleep 1; i=$((i+1)); done
if pgrep -f "php-fpm" >/dev/null 2>&1; then
  SHJSON="$(sh "$ROOT/quickcheck/php2shell-quickcheck.sh" --json 2>/dev/null)"
  if echo "$SHJSON" | grep -Eq "\"sapi\": ?\"fpm\", ?\"running\": ?true"; then pass "실행 중인 brew php-fpm 을 running=true 로 찾음"; else fail "실행 중인 php-fpm 을 찾지 못함"; echo "$SHJSON" | head -c 1500; fi
else
  fail "brew services start php 후 php-fpm 프로세스가 없음"
fi
exit "$FAIL"
