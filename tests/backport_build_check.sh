#!/bin/sh
# docs/response-options.ko.md 8절 / offline-patching.ko.md 11절: PHP 보안팀 백포트 브랜치를
# 최소 구성으로 실제로 빌드해 CLI·FPM 이 실행되는지 확인한다.
# 사용: sh tests/backport_build_check.sh [7.4 8.0 8.1]   (Docker, git 필요. 빌드에 수 분 걸린다)
set -u
REGISTRY="${REGISTRY:-mirror.gcr.io/library}"
IMAGE="${IMAGE:-$REGISTRY/debian:12-slim}"
[ "$#" -gt 0 ] || set -- 7.4 8.0 8.1
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
FAIL=0

cat >"$WORK/build.sh" <<'E'
set -e
apt-get update -qq >/dev/null
apt-get install -y -qq build-essential autoconf bison re2c pkg-config libxml2-dev libsqlite3-dev >/dev/null
mkdir /w && tar -x -C /w -f /in/src.tar && cd /w/src
./buildconf --force >/dev/null 2>&1
./configure --disable-all --enable-cli --enable-fpm >/dev/null
make -j"$(nproc)" >/dev/null 2>&1
sapi/cli/php -n -r 'echo "cli ", PHP_VERSION, "\n";'
sapi/fpm/php-fpm -n -v | head -1
E

for b in "$@"; do
  br="PHP-$b-CVE-2026-109618-109619"
  d="$WORK/$b"; mkdir -p "$d"
  git clone -q --filter=blob:none --no-checkout --single-branch --branch "$br" https://github.com/php/php-src.git "$d/repo" || { echo "FAIL $br 클론"; FAIL=1; continue; }
  git -C "$d/repo" archive --format=tar --prefix=src/ HEAD -o "$d/src.tar" || { echo "FAIL $br archive"; FAIL=1; continue; }
  cp "$WORK/build.sh" "$d/build.sh"
  out="$(docker run --rm -v "$d:/in:ro" "$IMAGE" sh /in/build.sh 2>&1)"
  if [ $? -eq 0 ] && echo "$out" | grep -q "^cli $b\."; then
    echo "PASS $br 빌드 후 실행: $(echo "$out" | tr '\n' ' ')"
  else
    echo "FAIL $br"; echo "$out" | tail -15; FAIL=1
  fi
done
exit "$FAIL"
