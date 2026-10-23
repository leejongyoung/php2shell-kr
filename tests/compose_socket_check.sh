#!/bin/sh
# docker-compose 하드닝(cap_drop: ALL) 구성에서 PHP-FPM 을 unix 소켓으로 listen 할 때
# 필요한 capability 를 실제로 확인한다. (virtual-patch/os/docker-compose-hardening.yml 의 주장 검증)
#   1) SETUID, SETGID 만 → 소켓 chown 실패로 FPM 초기화 실패
#   2) SETUID, SETGID, CHOWN → nginx 가 소켓으로 FastCGI 요청해 HTTP 200
# 사용: sh tests/compose_socket_check.sh   (Docker + docker compose 필요, 인터넷으로 이미지 pull)
set -u
REGISTRY="${REGISTRY:-mirror.gcr.io/library}"
PORT="${PORT:-18080}"
WORK="$(mktemp -d)"
PROJECT="p2ssock$$"
FAIL=0
trap 'docker compose -p "$PROJECT" -f "$WORK/compose.yml" down -v -t 1 >/dev/null 2>&1; rm -rf "$WORK"' EXIT

cat >"$WORK/fpm.conf" <<'E'
[global]
error_log = /proc/self/fd/2
daemonize = no
[www]
user = www-data
group = www-data
listen = /run/php/fpm.sock
listen.owner = www-data
listen.group = www-data
; nginx 이미지의 워커 UID 가 달라 그룹 권한으로는 접속할 수 없으므로 시험에서만 0666
listen.mode = 0666
pm = static
pm.max_children = 2
E
cat >"$WORK/nginx.conf" <<'E'
events {}
http { server { listen 8080; location / { fastcgi_pass unix:/run/php/fpm.sock; include fastcgi_params; fastcgi_param SCRIPT_FILENAME /var/www/html/index.php; } } }
E
echo '<?php echo "ok-", PHP_VERSION;' >"$WORK/index.php"

run_case() { # $1=caps  $2=expect(ok|fail)
  caps="$1"; expect="$2"
  cat >"$WORK/compose.yml" <<E
services:
  php:
    image: $REGISTRY/php:8.4.27-fpm
    read_only: true
    tmpfs: ["/tmp:rw,noexec,nosuid,size=64m"]
    cap_drop: [ALL]
    cap_add: [$caps]
    security_opt: ["no-new-privileges:true"]
    command: ["php-fpm", "-F", "-y", "/etc/fpm.conf"]
    volumes: ["$WORK/fpm.conf:/etc/fpm.conf:ro", "$WORK/index.php:/var/www/html/index.php:ro", "sock:/run/php"]
  web:
    image: $REGISTRY/nginx:stable-alpine
    ports: ["$PORT:8080"]
    volumes: ["$WORK/nginx.conf:/etc/nginx/nginx.conf:ro", "sock:/run/php"]
    depends_on: [php]
volumes:
  sock: {}
E
  docker compose -p "$PROJECT" -f "$WORK/compose.yml" down -v -t 1 >/dev/null 2>&1
  docker compose -p "$PROJECT" -f "$WORK/compose.yml" up -d >/dev/null 2>&1 || { echo "FAIL [$caps] compose up"; FAIL=1; return; }
  sleep 6
  body="$(curl -s -m 5 "http://127.0.0.1:$PORT/")"
  logs="$(docker compose -p "$PROJECT" -f "$WORK/compose.yml" logs php 2>&1)"
  if [ "$expect" = ok ]; then
    case "$body" in ok-8.4.27*) echo "PASS [$caps] HTTP 응답: $body" ;; *) echo "FAIL [$caps] 응답 없음: $body"; echo "$logs" | tail -5; FAIL=1 ;; esac
  else
    case "$logs" in *"failed to chown() the socket"*) echo "PASS [$caps] 예상대로 소켓 chown 실패" ;; *) echo "FAIL [$caps] 실패 로그가 없음"; echo "$logs" | tail -5; FAIL=1 ;; esac
  fi
}

run_case "SETUID, SETGID" fail
run_case "SETUID, SETGID, CHOWN" ok
exit "$FAIL"
