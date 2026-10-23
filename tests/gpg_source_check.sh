#!/bin/sh
# docs/offline-patching.ko.md 11.1 의 서명 검증 절차를 실제로 실행해 확인한다.
#   1) php-8.4.27.tar.xz 의 .asc 서명이 정상이고, 서명 키 지문이 php.net 의 GPG 키 페이지에 있다
#   2) 파일을 1바이트 바꾸면 BAD signature 로 실패한다
#   3) 백포트 브랜치(7.4/8.0/8.1) 끝 커밋의 서명이 커미터의 GitHub 공개 키로 검증된다
#      (이 키의 지문은 php.net 키 페이지에 없을 수 있다: 독립 채널 대조는 별도로 필요하다)
# 사용: sh tests/gpg_source_check.sh   (curl, gpg, git, python3 필요. 임시 GNUPGHOME 을 만들어 쓰므로 사용자 키링을 건드리지 않는다)
set -u
VER="${PHP_VER:-8.4.27}"
KEYSERVER="${KEYSERVER:-https://keyserver.ubuntu.com}"
WORK="$(mktemp -d)"
export GNUPGHOME="$WORK/gnupg"
mkdir -m 700 "$GNUPGHOME"
trap 'rm -rf "$WORK"' EXIT
FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=1; }
retry() { n=0; until "$@"; do n=$((n + 1)); [ "$n" -ge 3 ] && return 1; sleep $((5 * n)); done; }   # 네트워크 일시 오류 재시도

cd "$WORK" || exit 2
retry curl -fsSL -o "php-$VER.tar.xz" "https://www.php.net/distributions/php-$VER.tar.xz" || { fail "tarball 다운로드"; exit 1; }
retry curl -fsSL -o "php-$VER.tar.xz.asc" "https://www.php.net/distributions/php-$VER.tar.xz.asc" || { fail "서명 다운로드"; exit 1; }
retry curl -fsSL -o keys.html https://www.php.net/gpg-keys.php || { fail "php.net 키 페이지 다운로드"; exit 1; }

# 서명에 쓰인 키 지문 (gpg --verify 의 VALIDSIG/ERRSIG 상태 줄)
FP="$(gpg --status-fd 1 --verify "php-$VER.tar.xz.asc" "php-$VER.tar.xz" 2>/dev/null | awk '/ERRSIG/ {print $3}')"
[ -n "$FP" ] || { fail "서명 키 ID 를 읽지 못함"; exit 1; }
echo "서명 키 ID: $FP"
FULLFP="$(curl -fsSL "$KEYSERVER/pks/lookup?op=get&search=0x$FP" | gpg --import --import-options show-only --with-colons 2>/dev/null | awk -F: '/^fpr/ {print $10; exit}')"
curl -fsSL "$KEYSERVER/pks/lookup?op=get&search=0x$FP" | gpg --import 2>/dev/null
if sed 's/ //g' keys.html | grep -q "$FULLFP"; then pass "서명 키 지문이 php.net 키 페이지에 있음: $FULLFP"; else fail "서명 키 지문이 php.net 키 페이지에 없음: $FULLFP"; fi

if gpg --verify "php-$VER.tar.xz.asc" "php-$VER.tar.xz" 2>&1 | grep -q "Good signature"; then pass "원본 tarball 서명 정상"; else fail "원본 tarball 서명 검증 실패"; fi
echo x >>"php-$VER.tar.xz"
if gpg --verify "php-$VER.tar.xz.asc" "php-$VER.tar.xz" 2>&1 | grep -q "BAD signature"; then pass "변조된 tarball 은 BAD signature"; else fail "변조가 탐지되지 않음"; fi

for b in 7.4 8.0 8.1; do
  br="PHP-$b-CVE-2026-109618-109619"
  dir="src-$b"
  retry git clone -q --filter=blob:none --no-checkout --single-branch --branch "$br" https://github.com/php/php-src.git "$dir" || { fail "$br 클론"; continue; }
  tip="$(git -C "$dir" rev-parse HEAD)"
  login="$(curl -fsSL "https://api.github.com/repos/php/php-src/commits/$tip" | python3 -c 'import json,sys; print(json.load(sys.stdin)["committer"]["login"])')"
  curl -fsSL "https://github.com/$login.gpg" | gpg --import 2>/dev/null
  if git -C "$dir" verify-commit "$tip" 2>&1 | grep -q "Good signature"; then
    pass "$br 끝 커밋 $tip 서명 정상 (커미터 GitHub: $login)"
  else
    fail "$br 끝 커밋 $tip 서명 검증 실패"
  fi
done
exit "$FAIL"
