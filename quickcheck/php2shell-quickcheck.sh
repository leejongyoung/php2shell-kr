#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lee Jongyoung
# php2shell-quickcheck.sh - PHP2Shell (CVE-2026-109618 / CVE-2026-109619) 방어용 점검 도구 (POSIX sh)
#
# Python 이 없는 환경(오래된 CentOS 7, Alpine, BSD, 최소 컨테이너)용 대체 점검기입니다.
# - 서버 설정·패키지를 바꾸지 않습니다. 신뢰할 수 있는 PHP 바이너리만 `-n -v` 로 실행합니다(--no-exec 로 끌 수 있음).
# - 의심되는 호스트에서는 --no-exec 를 쓰세요. --exec 는 신뢰하는 호스트에서만 사용하세요.
# - 조치 명령은 화면에 "출력"만 합니다. 실행하지 않습니다.
# - 취약점을 유발하는 코드는 포함하지 않습니다.
#
# 종료 코드: 0 = 조치 필요 없음, 1 = 취약/EOL 또는 수정 파일은 설치됐으나 옛 코드가 실행 중,
#            3 = 판정 불가(프로세스/권한/버전 확인 불가), 2 = 사용법 오류.

LC_ALL=C
export LC_ALL

# 도구 탐색은 관리되는 시스템 경로로 고정하고 실제 호출도 절대 경로 함수로 묶습니다.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset CDPATH ENV BASH_ENV
umask 077
for helper in awk basename cat chmod date dirname env find getconf grep gzip head hostname id ls mkdir mktemp ps readlink rm rpm sed sleep sort stat sw_vers timeout tr uname wc zcat pkg procstat; do
  for helper_dir in /usr/bin /bin /usr/sbin /sbin; do
    if [ -f "$helper_dir/$helper" ] && [ -x "$helper_dir/$helper" ]; then
      eval "$helper() { \"$helper_dir/$helper\" \"\$@\"; }"
      [ "$helper" = env ] && ENV_BIN=$helper_dir/$helper
      break
    fi
  done
done
EUID_NUM=$(id -u 2>/dev/null)
[ -n "$EUID_NUM" ] || EUID_NUM=0

# UTF-8 C1/NEL/행 구분과 ASCII 제어문자를 치환하고 한국어 UTF-8 은 유지합니다.
clean_stream() {
  tr '\000-\011\013-\037\177' '?' | awk '{ gsub(/\302[\200-\237]|\342\200[\250\251]/, "?"); print }'
}
clean_value() {
  cv_text=$(printf '%sX' "$1" | clean_stream)
  cv_text=${cv_text%X}
  printf '%s' "$cv_text" | tr '\n' '?'
}
safe_name() {
  case $1 in ''|*[!A-Za-z0-9._+:@-]*|-*|.*) return 1 ;; esac
  return 0
}
safe_unit() {
  safe_name "$1" || return 1
  case $1 in *.service|*.socket) return 0 ;; esac
  return 1
}

AS_OF="2026-10-23"
TOOL="php2shell-quickcheck-sh"
CVE1="CVE-2026-109618"
CVE2="CVE-2026-109619"
US=$(printf '\037')
RS=$(printf '\036')

JSON=0
NOEXEC=0
EXEC=0
ROOT_NOEXEC=0
OFFLINE=0
PLAN_FILE=""
ROOT=""
ROOTMODE=0
POLICY_TEST=""
ROOT_ARG=""

usage() {
  cat <<'EOF'
사용법: php2shell-quickcheck.sh [옵션]

PHP2Shell (CVE-2026-109618 / CVE-2026-109619) 점검 도구.
서버 설정·패키지를 바꾸지 않습니다. 신뢰할 수 있는 PHP 바이너리만 `-n -v` 로 실행합니다(--no-exec 로 끌 수 있음).
의심되는 호스트에서는 --no-exec 를 사용하세요.

  --json        기계가 읽는 JSON 을 stdout 으로 출력
  --no-exec     발견한 어떤 바이너리도 실행하지 않음 (패키지 DB / 파일 메타데이터 / 정적 문자열만 사용)
  --exec        신뢰하는 호스트에서만 사용: 신뢰 판정과 --root 기본 비실행을 무시하고 실행을 강제(--no-exec 가 우선, 삭제된 /proc 실행 파일은 항상 제외)
  --offline     조치 계획에 오프라인(폐쇄망) 패치 절차를 추가로 출력
  --plan-file FILE  이 서버에 맞춘 조치 계획을 사람이 검토하는 sh 스크립트로 저장 (도구는 절대 실행하지 않음, 기존 파일은 덮어쓰지 않음)
  --root DIR    DIR 을 파일시스템 루트로 간주하여 파일을 찾고, 실행 중 프로세스 점검은 건너뜀. 기본적으로 트리 안 바이너리를 실행하지 않음(--no-exec 와 동일)
  --help        이 도움말

종료 코드: 0 조치 불필요 / 1 취약·EOL·재시작 필요 / 3 판정 불가 / 2 사용법 오류
EOF
}

# ---------------------------------------------------------------- 인자
while [ $# -gt 0 ]; do
  case $1 in
    --json) JSON=1 ;;
    --no-exec) NOEXEC=1 ;;
    --exec) EXEC=1 ;;
    --test-exec-policy)
      # 테스트 전용: 실제 auto 신뢰 판정 검사(권한/신뢰 검사는 생략하지 않음).
      if [ $# -lt 2 ] || [ "$2" != auto ]; then exit 2; fi
      shift; POLICY_TEST=auto ;;
    --offline) OFFLINE=1 ;;
    --plan-file)
      if [ $# -lt 2 ]; then usage >&2; exit 2; fi
      shift; PLAN_FILE=$1 ;;
    --plan-file=*) PLAN_FILE=${1#--plan-file=} ;;
    --root)
      if [ $# -lt 2 ]; then usage >&2; exit 2; fi
      shift; ROOT_ARG=$1; ROOTMODE=1 ;;
    --root=*) ROOT_ARG=${1#--root=}; ROOTMODE=1 ;;
    --classify)
      if [ $# -lt 2 ]; then CLASSIFY_ARG=""; else CLASSIFY_ARG=$2; fi
      DO_CLASSIFY=1; break ;;
    -h|--help) usage; exit 0 ;;
    *) printf '알 수 없는 옵션: %s\n' "$(clean_value "$1")" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

# ---------------------------------------------------------------- 버전 파싱/분류
# 규칙: 문자열에서 첫 X.Y.Z 를 취함(4번째 숫자 성분 무시). 바로 뒤의 alpha|beta|RC|dev (앞에 - 또는 . 허용, 숫자 허용)는
# 정식 릴리스보다 낮음. Debian/Ubuntu 접미사(-1+deb12u1, -1ubuntu1)는 prerelease 가 아님.
# mode=class -> 분류 문자열, mode=norm -> 정규화된 버전 문자열
verparse() {
  printf '%s\n' "$2" | awk -v mode="$1" '
  {
    s = substr($0,1,4096)
    if (!match(s, /[0-9]+\.[0-9]+\.[0-9]+/)) {
      if (mode == "class") print "unknown"; else print ""
      exit
    }
    v = substr(s, RSTART, RLENGTH)
    rest = substr(s, RSTART + RLENGTH)
    split(v, a, ".")
    ma = a[1] + 0; mi = a[2] + 0; pa = a[3] + 0
    if (match(rest, /^\.[0-9]+/)) rest = substr(rest, RLENGTH + 1)
    r = tolower(rest)
    sub(/^[-.]/, "", r)
    rk = 9; num = 0; tag = ""
    if (substr(r, 1, 3) == "dev") { rk = 1; tag = "-dev"; r = substr(r, 4) }
    else if (substr(r, 1, 5) == "alpha") { rk = 2; tag = "alpha"; r = substr(r, 6) }
    else if (substr(r, 1, 4) == "beta") { rk = 3; tag = "beta"; r = substr(r, 5) }
    else if (substr(r, 1, 2) == "rc") { rk = 4; tag = "RC"; r = substr(r, 3) }
    if (rk < 9) {
      sub(/^[-.]/, "", r)
      if (match(r, /^[0-9]+/)) num = substr(r, 1, RLENGTH) + 0
      if (rk > 1) tag = tag num
    }
    if (mode == "norm") { print v tag; exit }
    score = pa * 100000 + rk * 1000 + num
    cls = "unknown"
    if (ma >= 9) cls = "fixed"
    else if (ma == 8) {
      if (mi >= 7) cls = "fixed"
      else if (mi == 6) cls = (score >= 4004) ? "fixed" : "vulnerable"
      else if (mi == 5) cls = (score >= 12 * 100000 + 9000) ? "fixed" : "vulnerable"
      else if (mi == 4) cls = (score >= 27 * 100000 + 9000) ? "fixed" : "vulnerable"
      else if (mi == 3) cls = (score >= 36 * 100000 + 9000) ? "fixed" : "vulnerable"
      else if (mi == 2) cls = (score >= 35 * 100000 + 9000) ? "fixed" : "vulnerable"
      else cls = "eol_backport"
    }
    else if (ma == 7) {
      if (mi == 4) cls = "eol_backport"
      else if (mi < 4) cls = "eol_no_fix"
    }
    else if (ma == 5) cls = (mi >= 4) ? "eol_no_fix" : "old_unsupported"
    else if (ma < 5) cls = "old_unsupported"
    print cls
    exit
  }'
}

classify() { verparse class "$1"; }
norm_version() { verparse norm "$1"; }

# 필수 도구 확인: 없으면 거짓 "이상 없음"을 내지 않고 판정 불가(3)로 끝냄
pre_missing=""
for pre_t in awk sed grep tr sort head dirname basename; do
  command -v "$pre_t" >/dev/null 2>&1 || pre_missing="$pre_missing $pre_t"
done
if [ -n "$pre_missing" ]; then
  printf '오류: 필수 도구가 없어 점검할 수 없습니다:%s\n' "$pre_missing" >&2
  printf '설치 예) zypper install gawk / apt-get install gawk / dnf install gawk / apk add gawk (최소 컨테이너에는 awk 가 없을 수 있음). 판정 불가(종료 코드 3).\n' >&2
  exit 3
fi

if [ "${DO_CLASSIFY:-0}" = 1 ]; then
  classify "$CLASSIFY_ARG"
  exit 0
fi

if [ -n "$PLAN_FILE" ]; then
  if [ -e "$PLAN_FILE" ] || [ -L "$PLAN_FILE" ]; then
    printf '오류: --plan-file 대상이 이미 있습니다(덮어쓰지 않음): %s\n' "$(clean_value "$PLAN_FILE")" >&2
    exit 2
  fi
  pf_dir=$(dirname "$PLAN_FILE")
  if [ ! -d "$pf_dir" ] || [ ! -w "$pf_dir" ]; then
    printf '오류: --plan-file 디렉터리에 쓸 수 없습니다: %s\n' "$(clean_value "$pf_dir")" >&2
    exit 2
  fi
fi

# --root 에서는 (의심 이미지, 다른 아키텍처 대비) 기본적으로 트리 안 바이너리를 호스트에서 실행하지 않음. --exec 로만 허용
if [ "$ROOTMODE" = 1 ] && [ "$EXEC" = 0 ] && [ "$NOEXEC" = 0 ]; then
  NOEXEC=1
  ROOT_NOEXEC=1
fi
EXEC_MODE=auto
if [ "$NOEXEC" = 1 ]; then EXEC_MODE=never
elif [ "$EXEC" = 1 ]; then EXEC_MODE=all
fi
if [ "$POLICY_TEST" = auto ] && [ "$ROOT_NOEXEC" = 1 ]; then
  EXEC_MODE=auto; NOEXEC=0; ROOT_NOEXEC=0
fi

# ---------------------------------------------------------------- 준비
if [ "$ROOTMODE" = 1 ]; then
  if [ ! -d "$ROOT_ARG" ]; then
    printf '오류: --root 디렉터리가 없습니다: %s\n' "$(clean_value "$ROOT_ARG")" >&2
    exit 2
  fi
  ROOT=$(cd -P "$ROOT_ARG" && pwd -P)
  [ "$ROOT" = "/" ] && ROOT=""
fi

TMPD=$(mktemp -d 2>/dev/null) || TMPD=$(mktemp -d -t php2shell 2>/dev/null) || {
  TMPD=${TMPDIR:-/tmp}/php2shell.$$
  (umask 077; mkdir "$TMPD") || { printf '임시 디렉터리를 만들 수 없습니다\n' >&2; exit 3; }
}
trap 'rm -rf "$TMPD"' EXIT
trap 'exit 3' HUP INT TERM

say() { printf '%s\n' "$*" | clean_stream; }

NOTES=""
add_note() {
  an_clean=$(clean_value "$1")
  if [ -z "$NOTES" ]; then NOTES=$an_clean; else NOTES=$NOTES$RS$an_clean; fi
}

# 구성요소별 ROOT 경로 해석: 절대 링크 재루팅, ROOT 밖으로 가는 .. 거부.
rp() {
  rr_todo=${1#"$ROOT"}; rr_todo=${rr_todo#/}; rr_done=""; rr_links=0
  while [ -n "$rr_todo" ]; do
    case $rr_todo in
      */*) rr_part=${rr_todo%%/*}; rr_todo=${rr_todo#*/} ;;
      *) rr_part=$rr_todo; rr_todo="" ;;
    esac
    case $rr_part in
      ''|.) continue ;;
      ..)
        [ -n "$rr_done" ] || return 1
        rr_done=${rr_done%/*}
        continue ;;
    esac
    rr_probe=$ROOT$rr_done/$rr_part
    if [ -L "$rr_probe" ]; then
      rr_links=$((rr_links + 1)); [ "$rr_links" -le 40 ] || return 1
      rr_link=$(readlink "$rr_probe") || return 1
      case $rr_link in /*) rr_done=""; rr_link=${rr_link#/} ;; esac
      rr_todo=$rr_link${rr_todo:+/}$rr_todo
    else
      rr_done=$rr_done/$rr_part
    fi
  done
  printf '%s' "${ROOT}${rr_done:-/}"
}

regular_capped() { # path, byte cap; FIFO/장치/과대 파일은 열지 않습니다.
  [ -f "$1" ] && [ -r "$1" ] || return 1
  rc_line=$(ls -ldn "$1" 2>/dev/null) || return 1
  set -- "$2" $rc_line
  case $6 in ''|*[!0-9]*) return 1 ;; esac
  [ "$6" -le "$1" ]
}
root_file() {
  rf_path=$(rp "$1") || return 1
  [ ! -L "$rf_path" ] && regular_capped "$rf_path" "${2:-2097152}" || return 1
  printf '%s' "$rf_path"
}

# BEGIN TRUST POLICY (하네스가 함수만 추출해 소유자/모드를 주입하여 검사)
trust_metadata() { ls -ldn "$1" 2>/dev/null; }
trusted_path() {
  case $1 in /tmp/*|/var/tmp/*|/private/tmp/*|/private/var/tmp/*|/dev/shm/*|/run/user/*|/home/*|/Users/*) return 1 ;; esac
  tp_path=$1
  [ -f "$tp_path" ] && [ ! -L "$tp_path" ] || return 1
  while :; do
    tp_meta=$(trust_metadata "$tp_path") || return 1
    set -- $tp_meta
    [ "$3" = 0 ] || return 1
    case $1 in ?????w????*|????????w*|*+) return 1 ;; esac
    [ "$tp_path" = / ] && return 0
    tp_path=${tp_path%/*}; [ -n "$tp_path" ] || tp_path=/
    [ -d "$tp_path" ] || return 1
  done
}
exec_allowed() { # 명시적 정책 auto|never|all, path, deleted, euid
  EXEC_NOTE=""
  case $2 in /proc/*/exe) EXEC_NOTE="실행 안 함: /proc 실행 파일은 직접 실행하지 않습니다."; return 1 ;; esac
  if [ "$3" = 1 ]; then EXEC_NOTE="실행 안 함: 삭제/교체된 실행 파일입니다."; return 1; fi
  case $1 in
    never) return 1 ;;
    all) return 0 ;;
    auto)
      [ "$4" != 0 ] && return 0
      if trusted_path "$2"; then return 0; fi
      EXEC_NOTE="실행 안 함: 신뢰할 수 없는 위치(쓰기 가능하거나 소유자가 root/관리자가 아님)"
      return 1 ;;
  esac
  return 1
}
# END TRUST POLICY

# timeout 지원 감지
TO_MODE=none
if command -v timeout >/dev/null 2>&1; then
  if timeout 5 true >/dev/null 2>&1; then TO_MODE=modern
  elif timeout -t 5 true >/dev/null 2>&1; then TO_MODE=busybox
  fi
fi

# 시간 제한 실행: stdout+stderr 를 stdout 으로
run_to() {
  case $TO_MODE in
    modern) timeout 10 "$ENV_BIN" -i LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin "$@" 2>&1 </dev/null | head -c 4096; return 0 ;;
    busybox) timeout -t 10 "$ENV_BIN" -i LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin "$@" 2>&1 </dev/null | head -c 4096; return 0 ;;
  esac
  # timeout 없는 macOS/BSD: 출력은 4096바이트로 자르고 실행 프로세스를 직접 감시합니다.
  rm -f "$TMPD/exec.pipe"
  /usr/bin/mkfifo "$TMPD/exec.pipe" 2>/dev/null || /bin/mkfifo "$TMPD/exec.pipe" 2>/dev/null || return 1
  head -c 4096 < "$TMPD/exec.pipe" > "$TMPD/rto" &
  rt_reader=$!
  "$ENV_BIN" -i LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin "$@" > "$TMPD/exec.pipe" 2>&1 </dev/null &
  rt_pid=$!
  rt_n=0
  while kill -0 "$rt_pid" 2>/dev/null; do
    if [ "$rt_n" -ge 10 ]; then kill -9 "$rt_pid" 2>/dev/null; break; fi
    sleep 1
    rt_n=$((rt_n + 1))
  done
  { wait "$rt_pid"; wait "$rt_reader"; } 2>/dev/null
  head -c 4096 "$TMPD/rto" 2>/dev/null
  rm -f "$TMPD/exec.pipe"
}

mtime_of() {
  mo=$(stat -c %Y "$1" 2>/dev/null) || mo=
  case $mo in ''|*[!0-9]*) mo=$(stat -f %m "$1" 2>/dev/null) ;; esac
  case $mo in ''|*[!0-9]*) mo= ;; esac
  printf '%s' "$mo"
}

# ---------------------------------------------------------------- 플랫폼
OS=$(uname -s 2>/dev/null || echo unknown)
OS_ID=""; OS_LIKE=""; OS_PRETTY=""; OS_VER=""
for osr in "$ROOT/etc/os-release" "$ROOT/usr/lib/os-release"; do
  osr=$(root_file "$osr") || continue
  if [ -r "$osr" ]; then
    os_text=$(head -c 2097152 "$osr" | awk '{print substr($0,1,4096)}')
    OS_ID=$(printf '%s\n' "$os_text" | sed -n 's/^ID=//p' | head -1 | tr -d '"'"'")
    OS_LIKE=$(printf '%s\n' "$os_text" | sed -n 's/^ID_LIKE=//p' | head -1 | tr -d '"'"'")
    OS_PRETTY=$(printf '%s\n' "$os_text" | sed -n 's/^PRETTY_NAME=//p' | head -1 | tr -d '"'"'")
    OS_VER=$(printf '%s\n' "$os_text" | sed -n 's/^VERSION_ID=//p' | head -1 | tr -d '"'"'")
    break
  fi
done
# --root 아래에 os-release 가 있으면 호스트가 아니라 그 트리의 OS 를 기준으로 삼음
if [ "$ROOTMODE" = 1 ] && [ -n "$OS_ID" ]; then OS=Linux; fi
case $OS in
  Darwin) PLATFORM="macOS $(sw_vers -productVersion 2>/dev/null)" ;;
  FreeBSD) PLATFORM="FreeBSD $(uname -r 2>/dev/null)" ;;
  Linux)
    if [ -n "$OS_PRETTY" ]; then PLATFORM="Linux / $OS_PRETTY"; else PLATFORM="Linux"; fi ;;
  *) PLATFORM="$OS $(uname -r 2>/dev/null)" ;;
esac

HOSTN=$(hostname 2>/dev/null)
[ -n "$HOSTN" ] || HOSTN=$(uname -n 2>/dev/null)
[ -n "$HOSTN" ] || { read -r HOSTN < /proc/sys/kernel/hostname; } 2>/dev/null
[ -n "$HOSTN" ] || HOSTN=unknown

# 패키지 관리자
PM=none
have_rpm_db=0
if [ -d "$ROOT/var/lib/rpm" ] || [ -d "$ROOT/usr/lib/sysimage/rpm" ]; then have_rpm_db=1; fi
if [ "$ROOTMODE" = 0 ] && command -v rpm >/dev/null 2>&1; then have_rpm_db=1; fi
case " $OS_ID $OS_LIKE " in *suse*|*sles*) is_suse=1 ;; *) is_suse=0 ;; esac
if [ -f "$ROOT/var/lib/dpkg/status" ]; then PM=apt
elif [ -f "$ROOT/lib/apk/db/installed" ]; then PM=apk
elif [ "$is_suse" = 1 ]; then PM=zypper
elif [ "$have_rpm_db" = 1 ]; then
  if [ "$ROOTMODE" = 0 ] && command -v dnf >/dev/null 2>&1; then PM=dnf
  elif [ "$ROOTMODE" = 0 ] && command -v microdnf >/dev/null 2>&1; then PM=microdnf
  elif [ "$ROOTMODE" = 0 ] && command -v yum >/dev/null 2>&1; then PM=yum
  else
    case $OS_VER in 6*|7*) PM=yum ;; *) PM=dnf ;; esac
  fi
elif [ "$OS" = FreeBSD ]; then PM=pkg
elif [ "$OS" = Darwin ]; then PM=brew
fi

# 컨테이너 여부
CONTAINER=0
if [ -f "$ROOT/.dockerenv" ] || [ -f "$ROOT/run/.containerenv" ]; then CONTAINER=1; fi
if [ "$ROOTMODE" = 0 ] && [ -r /proc/1/cgroup ] && grep -qE 'docker|kubepods|containerd|lxc|libpod' /proc/1/cgroup 2>/dev/null; then CONTAINER=1; fi

# init 시스템
INIT=none
case $OS in
  Darwin) INIT=launchd ;;
  FreeBSD) INIT=bsdrc ;;
  *)
    if [ -d "$ROOT/run/systemd/system" ]; then INIT=systemd
    elif [ "$ROOTMODE" = 0 ] && [ -r /proc/1/comm ] && { read -r init_comm < /proc/1/comm; } 2>/dev/null && [ "$init_comm" = systemd ]; then INIT=systemd
    elif [ "$ROOTMODE" = 0 ] && command -v rc-service >/dev/null 2>&1 && [ "$CONTAINER" = 0 ]; then INIT=openrc
    elif [ "$CONTAINER" = 1 ]; then INIT=none
    elif [ "$ROOTMODE" = 0 ] && command -v service >/dev/null 2>&1; then INIT=sysv
    fi ;;
esac

# 프로세스 시작 시각 계산 준비
BTIME=""; CLK_TCK=100
PROC_MODE=none
if [ "$ROOTMODE" = 1 ]; then
  PROC_MODE=skip
elif [ -L /proc/self/exe ]; then
  PROC_MODE=linux
  BTIME=$(awk '/^btime/ {print $2}' /proc/stat 2>/dev/null)
  c=$(getconf CLK_TCK 2>/dev/null); case $c in ''|*[!0-9]*) ;; *) CLK_TCK=$c ;; esac
elif command -v ps >/dev/null 2>&1; then
  PROC_MODE=ps
fi
IS_ROOT=0
[ "$EUID_NUM" = 0 ] && IS_ROOT=1

# ---------------------------------------------------------------- 탐색
CAND="$TMPD/cand.txt"
: > "$CAND"
PROC_ENUM=0
WEB_UNREAD=0

php_name_ok() {
  case $1 in
    *.conf|*.ini|*.1|*.sh|*.service|*-config*) return 1 ;;
    php|php[0-9]*|php-fpm*|php-cgi*|lsphp*|frankenphp*|libphp*) return 0 ;;
  esac
  return 1
}

add_cand() { # key disp acc kind cont del pid
  ac_key=$(clean_value "$1"); ac_disp=$(clean_value "$2"); ac_acc=$3; ac_kind=$4
  if [ "$ac_key" != "$1" ] || [ "$ac_disp" != "$2" ] || [ "$(clean_value "$3")" != "$3" ]; then
    ac_acc=""; ac_kind=unresolved
  fi
  printf '%s\n' "$ac_key$US$ac_disp$US$ac_acc$US$ac_kind$US$5$US$6$US$7" >> "$CAND"
}

disc_files() {
  (
    cd "${ROOT:-/}" 2>/dev/null || exit 0
    for f in \
      usr/bin/php* usr/bin/lsphp* usr/bin/frankenphp bin/php* sbin/php-fpm* \
      usr/sbin/php* usr/local/bin/php* usr/local/bin/lsphp* usr/local/bin/frankenphp usr/local/sbin/php* \
      opt/remi/php*/root/usr/bin/php* opt/remi/php*/root/usr/sbin/php* \
      opt/plesk/php/*/bin/php* opt/plesk/php/*/sbin/php* \
      opt/cpanel/ea-php*/root/usr/bin/php* opt/cpanel/ea-php*/root/usr/sbin/php* \
      usr/local/php*/bin/php* usr/local/php*/sbin/php* \
      usr/local/lsws/lsphp*/bin/lsphp* usr/local/lsws/lsphp*/bin/php* \
      usr/lib/apache2/modules/libphp*.so usr/lib/apache2/libphp*.so \
      usr/lib64/httpd/modules/libphp*.so usr/lib/httpd/modules/libphp*.so \
      usr/libexec/apache2/libphp*.so usr/local/libexec/apache24/libphp*.so \
      usr/local/apache2/modules/libphp*.so opt/lampp/modules/libphp*.so opt/lampp/bin/php* \
      opt/homebrew/bin/php* opt/homebrew/opt/php*/bin/php* opt/homebrew/opt/php*/sbin/php-fpm \
      usr/local/opt/php*/bin/php* usr/local/opt/php*/sbin/php-fpm \
      Applications/MAMP/bin/php/php*/bin/php*
    do
      [ -e "$f" ] || [ -L "$f" ] || continue
      php_name_ok "${f##*/}" || continue
      if [ "$(clean_value "$f")" != "$f" ]; then
        add_cand "unsafe:$f" "/$f" "" unresolved 0 0 ""
        continue
      fi
      printf '%s\n' "$f"
    done
  ) > "$TMPD/files.txt"
  while IFS= read -r df_f <&3; do
    df_acc=$(rp "$ROOT/$df_f") || {
      say "경로 무시: --root 밖으로 나가거나 순환하는 심볼릭 링크: /$df_f" >&2
      continue
    }
    [ -f "$df_acc" ] && [ ! -L "$df_acc" ] || continue
    df_disp=${df_acc#"$ROOT"}
    case ${df_disp##*/} in libphp*) df_kind=lib ;; *) df_kind=bin ;; esac
    add_cand "$df_acc" "$df_disp" "$df_acc" "$df_kind" 0 0 ""
  done 3< "$TMPD/files.txt"
}

proc_match_bin() {
  case $1 in
    php|php[0-9]*|php-fpm*|php-cgi*|lsphp*|frankenphp*) return 0 ;;
  esac
  return 1
}

add_proc() { # pid exe del cont nsid comm
  ap_pid=$1; ap_exe=$2; ap_del=$3; ap_cont=$4; ap_ns=$5; ap_comm=$6
  case $ap_exe in
    /*) ;;
    *) add_cand "name:$ap_comm" "$ap_comm" "" unresolved 0 0 "$ap_pid"; return 0 ;;
  esac
  case ${ap_exe##*/} in libphp*) ap_kind=lib ;; *) ap_kind=bin ;; esac
  if [ "$ap_cont" = 1 ]; then
    ap_acc=/proc/$ap_pid/root$ap_exe
    [ -e "$ap_acc" ] || ap_acc=/proc/$ap_pid/exe
    add_cand "ns:$ap_ns:$ap_exe" "$ap_exe" "$ap_acc" "$ap_kind" 1 "$ap_del" "$ap_pid"
  elif [ -e "$ap_exe" ]; then
    ap_acc=$(rp "$ap_exe")
    add_cand "$ap_acc" "$ap_acc" "$ap_acc" "$ap_kind" 0 "$ap_del" "$ap_pid"
  else
    add_cand "gone:$ap_exe" "$ap_exe" "/proc/$ap_pid/exe" "$ap_kind" 0 1 "$ap_pid"
  fi
}

disc_procs() {
  case $PROC_MODE in
    linux)
      PROC_ENUM=1
      self_ns=$(readlink /proc/self/ns/mnt 2>/dev/null)
      for dp_d in /proc/[0-9]*; do
        dp_pid=${dp_d#/proc/}
        dp_comm=""
        { read -r dp_comm < "$dp_d/comm"; } 2>/dev/null
        [ -n "$dp_comm" ] || continue
        if proc_match_bin "$dp_comm"; then
          dp_exe=$(readlink "$dp_d/exe" 2>/dev/null)
          dp_del=0
          case $dp_exe in *" (deleted)") dp_del=1; dp_exe=${dp_exe% (deleted)} ;; esac
          dp_ns=$(readlink "$dp_d/ns/mnt" 2>/dev/null)
          dp_cont=0
          if [ -n "$dp_ns" ] && [ -n "$self_ns" ] && [ "$dp_ns" != "$self_ns" ]; then dp_cont=1; fi
          add_proc "$dp_pid" "$dp_exe" "$dp_del" "$dp_cont" "$dp_ns" "$dp_comm"
        else
          case $dp_comm in
            httpd*|apache2*|apache|litespeed|lshttpd) ;;
            *) continue ;;
          esac
          if [ ! -r "$dp_d/maps" ]; then WEB_UNREAD=1; continue; fi
          dp_ns=$(readlink "$dp_d/ns/mnt" 2>/dev/null)
          dp_cont=0
          if [ -n "$dp_ns" ] && [ -n "$self_ns" ] && [ "$dp_ns" != "$self_ns" ]; then dp_cont=1; fi
          awk '$6 ~ /libphp/ { print $6 (($7 == "(deleted)") ? "\037D" : "\037N") }' "$dp_d/maps" 2>/dev/null | sort -u > "$TMPD/maps.txt"
          while IFS=$US read -r dp_lib dp_flag <&4; do
            [ -n "$dp_lib" ] || continue
            if [ "$dp_flag" = D ]; then dp_del=1; else dp_del=0; fi
            add_proc "$dp_pid" "$dp_lib" "$dp_del" "$dp_cont" "$dp_ns" "$dp_comm"
          done 4< "$TMPD/maps.txt"
        fi
      done
      ;;
    ps)
      if ps -axo pid=,comm= > "$TMPD/ps.txt" 2>/dev/null || ps -eo pid=,comm= > "$TMPD/ps.txt" 2>/dev/null || ps -o pid=,comm= > "$TMPD/ps.txt" 2>/dev/null; then
        PROC_ENUM=1
        while read -r dp_pid dp_path <&3; do
          case $dp_pid in ''|*[!0-9]*) continue ;; esac
          dp_base=${dp_path##*/}
          proc_match_bin "$dp_base" || continue
          dp_exe=$dp_path
          case $dp_exe in
            /*) ;;
            *)
              if command -v procstat >/dev/null 2>&1; then
                dp_exe=$(procstat -b "$dp_pid" 2>/dev/null | awk 'NR == 2 {print $NF}')
              fi ;;
          esac
          add_proc "$dp_pid" "$dp_exe" 0 0 "" "$dp_base"
        done 3< "$TMPD/ps.txt"
      fi
      ;;
  esac
}

disc_files
disc_procs

# 그룹화(같은 키 병합, 경로를 모르는 프로세스는 이름이 일치하는 후보에 병합)
awk -F "$US" -v OFS="$US" '
{
  k = $1
  if (!(k in seen)) { seen[k] = 1; order[++n] = k; disp[k] = $2; acc[k] = $3; kind[k] = $4; cont[k] = $5; del[k] = 0; pids[k] = "" }
  if ($6 == 1) del[k] = 1
  if ($7 != "") pids[k] = (pids[k] == "" ? $7 : pids[k] " " $7)
  if (index(acc[k], "/proc/") == 1 && index($3, "/proc/") != 1 && $3 != "") acc[k] = $3
}
END {
  for (i = 1; i <= n; i++) {
    k = order[i]
    if (index(k, "name:") != 1) continue
    comm = disp[k]
    for (j = 1; j <= n; j++) {
      k2 = order[j]
      if (index(k2, "name:") == 1 || index(k2, "gone:") == 1 || cont[k2] == 1) continue
      m = split(disp[k2], p, "/")
      if (index(p[m], comm) == 1) {
        pids[k2] = (pids[k2] == "" ? pids[k] : pids[k2] " " pids[k])
        merged[k] = 1
        break
      }
    }
  }
  for (i = 1; i <= n; i++) {
    k = order[i]
    if (k in merged) continue
    print k, disp[k], acc[k], kind[k], cont[k], del[k], pids[k]
  }
}' "$CAND" > "$TMPD/groups.txt"

# ---------------------------------------------------------------- 정적 설정 스캔(php -i 를 쓰지 않음)
MIT_KEYS='session\.upload_progress\.enabled|memory_limit|session\.auto_start|post_max_size|fatal_error_backtraces'
MIT_RE="^[[:space:]]*((php_admin_value|php_admin_flag|php_value|php_flag)(\\[|[[:space:]]+))?($MIT_KEYS)[]]?[[:space:]]*(=|\$)"
MIT_RE_APACHE="^[[:space:]]*php_(admin_)?(value|flag)[[:space:]]+($MIT_KEYS)([[:space:]]|\$)"
MITF="$TMPD/mit.txt"
: > "$MITF"

mit_label() {
  case $1 in
    */fpm/*|*php-fpm*|*pool.d*) printf 'fpm' ;;
    */apache2/*|*/httpd/*|*apache2*|*httpd*) printf 'apache' ;;
    */cgi/*) printf 'cgi' ;;
    */cli/*) printf 'cli' ;;
    */litespeed/*|*lsphp*) printf 'litespeed' ;;
    *) printf 'shared' ;;
  esac
}

mit_scan() {
  (
    cd "${ROOT:-/}" 2>/dev/null || exit 0
    for f in \
      etc/php.ini etc/php/php.ini etc/php/conf.d/*.ini etc/php/*/*/php.ini etc/php/*/*/conf.d/*.ini \
      etc/php/*/fpm/pool.d/*.conf etc/php.d/*.ini etc/php-fpm.d/*.conf etc/php-fpm.conf \
      etc/php*/php.ini etc/php*/conf.d/*.ini etc/php*/php-fpm.d/*.conf etc/php*/php-fpm.conf \
      usr/local/etc/php/php.ini usr/local/etc/php/conf.d/*.ini usr/local/etc/php-fpm.conf usr/local/etc/php-fpm.d/*.conf \
      usr/local/etc/php.ini usr/local/lib/php.ini usr/local/etc/php/*.ini \
      opt/remi/php*/root/etc/php.ini opt/remi/php*/root/etc/php.d/*.ini opt/remi/php*/root/etc/php-fpm.d/*.conf \
      etc/opt/remi/php*/php.ini etc/opt/remi/php*/php.d/*.ini etc/opt/remi/php*/php-fpm.d/*.conf \
      opt/homebrew/etc/php/*/php.ini opt/homebrew/etc/php/*/conf.d/*.ini opt/homebrew/etc/php/*/php-fpm.d/*.conf \
      usr/local/etc/php/*/php.ini usr/local/etc/php/*/conf.d/*.ini usr/local/etc/php/*/php-fpm.d/*.conf \
      Applications/MAMP/bin/php/php*/conf/php.ini Applications/MAMP/conf/php*/php.ini opt/lampp/etc/php.ini \
      opt/cpanel/ea-php*/root/etc/php.ini opt/cpanel/ea-php*/root/etc/php.d/*.ini \
      opt/plesk/php/*/etc/php.ini opt/plesk/php/*/etc/php.d/*.ini opt/plesk/php/*/etc/php-fpm.d/*.conf
    do
      if [ -e "$f" ] || [ -L "$f" ]; then
        [ "$(clean_value "$f")" = "$f" ] && printf '%s\n' "$f"
      fi
    done
  ) | sort -u > "$TMPD/mitfiles.txt"
  while IFS= read -r ms_f <&3; do
    ms_acc=$(root_file "$ROOT/$ms_f") || continue
    ms_lab=$(mit_label "$ms_f")
    head -c 2097152 "$ms_acc" | awk '{print substr($0,1,4096)}' | grep -nE "$MIT_RE" 2>/dev/null | clean_stream | awk -v lab="$ms_lab" -v f="/$ms_f" -v us="$US" '
      { i = index($0, ":"); n = substr($0, 1, i - 1); t = substr($0, i + 1); sub(/^[ \t]+/, "", t); print lab us f us n us substr(t, 1, 160) }' >> "$MITF"
  done 3< "$TMPD/mitfiles.txt"
  for ms_d in etc/apache2 etc/httpd usr/local/apache2/conf usr/local/etc/apache24 opt/homebrew/etc/httpd opt/lampp/etc; do
    ms_dir=$(rp "$ROOT/$ms_d") || continue
    [ -d "$ms_dir" ] || continue
    find "$ms_dir" -type f -print 2>/dev/null > "$TMPD/apachefiles.txt"
    while IFS= read -r ms_acc <&4; do
      [ "$(clean_value "$ms_acc")" = "$ms_acc" ] || continue
      ms_acc=$(root_file "$ms_acc") || continue
      ms_disp=${ms_acc#"$ROOT"}
      head -c 2097152 "$ms_acc" | awk '{print substr($0,1,4096)}' | grep -nE "$MIT_RE_APACHE" | clean_stream |
        awk -v f="$ms_disp" -v us="$US" '{i=index($0,":"); print "apache" us f us substr($0,1,i-1) us substr($0,i+1,160)}' >> "$MITF"
    done 4< "$TMPD/apachefiles.txt"
  done
}
mit_scan

# ---------------------------------------------------------------- 패키지/벤더 근거
PKG_NAME=""; PKG_VER=""; PKG_TIME=""; PKG_PM=""

apk_owner() {
  ao_db=$(root_file "$ROOT/lib/apk/db/installed") || return 0
  awk -v want="$1" 'BEGIN { RS = ""; FS = "\n" }
    { p = ""; v = ""; d = ""; found = 0
      for (i = 1; i <= NF; i++) {
        c = substr($i, 1, 2); x = substr($i, 3)
        if (c == "P:") p = x
        else if (c == "V:") v = x
        else if (c == "F:") d = x
        else if (c == "R:") { full = (d == "") ? x : d "/" x; if (full == want) found = 1 }
      }
      if (found) { print p " " v; exit } }' "$ao_db" 2>/dev/null | head -c 4096
}

pkg_lookup() { # $1 = ROOT 기준 절대 경로
  PKG_NAME=""; PKG_VER=""; PKG_TIME=""; PKG_PM=""
  pl_p=$1
  case $pl_p in
    */Cellar/*)
      PKG_NAME=$(printf '%s' "$pl_p" | sed -n 's#.*/Cellar/\([^/]*\)/.*#\1#p')
      PKG_VER=$(printf '%s' "$pl_p" | sed -n 's#.*/Cellar/[^/]*/\([^/]*\)/.*#\1#p')
      PKG_PM=brew
      return 0 ;;
  esac
  case $PM in
    apt)
      pl_info=$(rp "$ROOT/var/lib/dpkg/info") || return 0
      [ -d "$pl_info" ] || return 0
      pl_list=""
      for pl_f in "$pl_info"/*.list; do
        pl_f=$(root_file "$pl_f") || continue
        if head -c 2097152 "$pl_f" | grep -qFx -- "$pl_p"; then pl_list=$pl_f; break; fi
        case $pl_p in /usr/*)
          if head -c 2097152 "$pl_f" | grep -qFx -- "${pl_p#/usr}"; then pl_list=$pl_f; break; fi ;;
        esac
      done
      if [ -n "$pl_list" ]; then
        PKG_NAME=${pl_list##*/}; PKG_NAME=${PKG_NAME%.list}; PKG_NAME=${PKG_NAME%%:*}
        safe_name "$PKG_NAME" || { PKG_NAME=""; return 0; }
        pl_status=$(root_file "$ROOT/var/lib/dpkg/status") || return 0
        PKG_VER=$(head -c 2097152 "$pl_status" | awk -v n="$PKG_NAME" '{ $0=substr($0,1,4096) } $1 == "Package:" { p = $2 } $1 == "Version:" && p == n { print $2; exit }')
        PKG_TIME=$(mtime_of "$pl_list")
        PKG_PM=apt
      fi ;;
    dnf|yum|microdnf|zypper)
      pl_fmt='%{NAME} %{VERSION}-%{RELEASE} %{INSTALLTIME}\n'
      if [ -n "$ROOT" ]; then
        pl_out=$(rpm --root "$ROOT" -qf --qf "$pl_fmt" "$pl_p" 2>/dev/null </dev/null | head -c 4096 | head -1)
      else
        pl_out=$(rpm -qf --qf "$pl_fmt" "$pl_p" 2>/dev/null </dev/null | head -c 4096 | head -1)
      fi
      case $pl_out in file\ *|'') pl_out="" ;; esac
      if [ -n "$pl_out" ]; then
        set -- $pl_out
        PKG_NAME=$1; PKG_VER=$2
        case $3 in ''|*[!0-9]*) ;; *) PKG_TIME=$3 ;; esac
        PKG_PM=rpm
      fi ;;
    apk)
      pl_out=$(apk_owner "${pl_p#/}")
      if [ -z "$pl_out" ]; then
        case $pl_p in /usr/*) pl_out=$(apk_owner "${pl_p#/usr/}") ;; esac
      fi
      if [ -n "$pl_out" ]; then
        set -- $pl_out
        PKG_NAME=$1; PKG_VER=$2; PKG_PM=apk
      fi ;;
    pkg)
      if [ -z "$ROOT" ] && command -v pkg >/dev/null 2>&1; then
        pl_out=$(pkg which -q "$pl_p" 2>/dev/null </dev/null | head -c 4096 | head -1)
        if [ -n "$pl_out" ]; then
          PKG_NAME=$(printf '%s' "$pl_out" | sed 's/-[^-]*$//')
          PKG_VER=$(printf '%s' "$pl_out" | sed 's/.*-//')
          PKG_PM=pkg
        fi
      fi ;;
  esac
  if [ -n "$PKG_NAME" ] && ! safe_name "$PKG_NAME"; then PKG_NAME=""; PKG_VER=""; PKG_PM=""; fi
  PKG_VER=$(clean_value "$PKG_VER")
  return 0
}

chg_cat() {
  case $1 in
    *.gz) gzip -dc "$1" 2>/dev/null | head -c 2097152 ;;
    *) head -c 2097152 "$1" 2>/dev/null ;;
  esac
}

# 같은 유효한 변경 이력 항목 안에 두 CVE 가 모두 있어야 인정합니다.
# 항목 밖의 문서 언급, 서로 다른 항목의 한 건씩 언급은 근거가 아닙니다.
vendor_entries() {
  awk -v format="$1" '
    function flush() { if (a && b) { print lines; found=1; exit } }
    {
      s=substr($0,1,4096)
      header=(format=="deb" ? s ~ /^[A-Za-z0-9][A-Za-z0-9+.-]* \([^)]*\) [^;]*;/ : s ~ /^\* [A-Za-z]/)
      if (header) { flush(); active=1; a=0; b=0; lines=""; next }
      if (format=="deb" && s ~ /^ -- /) { flush(); active=0 }
      if (!active || (format=="deb" && s !~ /^[ \t]/)) next
      lower=tolower(s)
      if (lower ~ /not (yet )?fixed|unfixed|wontfix/) next
      if (s ~ /CVE-2026-109618/) { a=1; lines=lines (lines=="" ? "" : "\n") s }
      if (s ~ /CVE-2026-109619/) { b=1; if (s !~ /CVE-2026-109618/) lines=lines (lines=="" ? "" : "\n") s }
    }
    END { if (!found && a && b) print lines }
  '
}

VENDOR=unknown
vendor_check() {
  VENDOR=unknown
  safe_name "$PKG_NAME" || return 0
  vc_lines=""
  case $PKG_PM in
    apt)
      for vc_f in changelog.Debian.gz changelog.Debian changelog.gz changelog; do
        vc_p=$(root_file "$ROOT/usr/share/doc/$PKG_NAME/$vc_f") || continue
        vc_lines=$(chg_cat "$vc_p" | vendor_entries deb)
        VENDOR=no
        [ -n "$vc_lines" ] && VENDOR=yes
        break
      done ;;
    rpm)
      if [ -n "$ROOT" ]; then
        rpm --root "$ROOT" -q --changelog "$PKG_NAME" 2>/dev/null </dev/null | head -c 2097152 > "$TMPD/chg.txt"
      else
        rpm -q --changelog "$PKG_NAME" 2>/dev/null </dev/null | head -c 2097152 > "$TMPD/chg.txt"
      fi
      if [ -s "$TMPD/chg.txt" ]; then
        vc_lines=$(vendor_entries rpm < "$TMPD/chg.txt")
        VENDOR=no
        [ -n "$vc_lines" ] && VENDOR=yes
      fi ;;
  esac
  if [ "$VENDOR" = yes ]; then
    printf '%s\n' "$vc_lines" > "$TMPD/vendor-lines.txt"
    while IFS= read -r vc_line <&5; do
      add_note "벤더 변경 이력 일치 줄: $vc_line"
    done 5< "$TMPD/vendor-lines.txt"
  fi
}

# ---------------------------------------------------------------- 버전 결정
ver_from_output() {
  printf '%s\n' "$1" | awk '{ if (match($0, /PHP [0-9]+\.[0-9]+\.[0-9]+/)) { print substr($0, RSTART + 4); exit } }'
}

ver_static() {
  regular_capped "$1" 125829120 || return 0
  head -c 125829120 "$1" 2>/dev/null | LC_ALL=C grep -a -o 'X-Powered-By: PHP/[0-9][0-9A-Za-z.+~_-]*' | head -1 | head -c 4096 | sed 's/^X-Powered-By: PHP\///'
}

ver_from_path() {
  printf '%s' "$1" | awk '{ if (match($0, /php[-@]?[0-9]+\.[0-9]+\.[0-9]+/)) { s = substr($0, RSTART, RLENGTH); sub(/^php[-@]?/, "", s); print s } }'
}

# ---------------------------------------------------------------- 재시작 필요 여부
proc_start() { # pid -> epoch
  ps_pid=$1; ps_res=""
  if [ "$PROC_MODE" = linux ] && [ -n "$BTIME" ]; then
    ps_line=""
    { read -r ps_line < "/proc/$ps_pid/stat"; } 2>/dev/null
    if [ -n "$ps_line" ]; then
      ps_rest=${ps_line##*) }
      set -- $ps_rest
      if [ $# -ge 20 ]; then
        shift 19
        case $1 in ''|*[!0-9]*) ;; *) ps_res=$((BTIME + $1 / CLK_TCK)) ;; esac
      fi
    fi
  fi
  if [ -z "$ps_res" ] && [ "$PROC_MODE" != skip ] && [ "$PROC_MODE" != none ]; then
    ps_et=$(ps -o etime= -p "$ps_pid" 2>/dev/null | awk '{ s = $1; d = 0
      if (index(s, "-") > 0) { split(s, x, "-"); d = x[1]; s = x[2] }
      n = split(s, t, ":"); sec = 0
      for (i = 1; i <= n; i++) sec = sec * 60 + t[i]
      print d * 86400 + sec }')
    case $ps_et in ''|*[!0-9]*) ;; *)
      ps_now=$(date +%s 2>/dev/null)
      case $ps_now in ''|*[!0-9]*) ;; *) ps_res=$((ps_now - ps_et)) ;; esac ;;
    esac
  fi
  printf '%s' "$ps_res"
}

NEEDS=null
nr_eval() { # ev_pids ev_del ev_acc PKG_TIME 사용
  NEEDS=null
  [ "$ROOTMODE" = 1 ] && return 0
  [ "$PROC_MODE" = none ] && return 0
  if [ -z "$ev_pids" ]; then NEEDS=false; return 0; fi
  if [ "$ev_del" = 1 ]; then NEEDS=true; return 0; fi
  nr_mt=$(mtime_of "$ev_acc")
  nr_unk=0
  nr_true=0
  for nr_pid in $ev_pids; do
    nr_st=$(proc_start "$nr_pid")
    if [ -z "$nr_st" ]; then nr_unk=1; continue; fi
    if [ -n "$nr_mt" ] && [ $((nr_mt - nr_st)) -gt 2 ]; then nr_true=1; fi
    if [ -n "$PKG_TIME" ] && [ $((PKG_TIME - nr_st)) -gt 2 ]; then nr_true=1; fi
  done
  if [ "$nr_true" = 1 ]; then NEEDS=true
  elif [ "$nr_unk" = 1 ]; then NEEDS=null
  else NEEDS=false
  fi
}

# ---------------------------------------------------------------- 평가
RESULTS="$TMPD/results.txt"
: > "$RESULTS"
C_VULN=0; C_FIXED=0; C_VP=0; C_EOL=0; C_UNK=0; C_NR=0; C_TOTAL=0; C_LIB=0
PLAN_PKGS=""
PLAN_SAPIS=""
FPM_UNITS=""
BREW_FORMULAE=""
BRANCH_LINES="$TMPD/branches.txt"
: > "$BRANCH_LINES"

list_add() { # 변수이름 값  (공백 구분 중복 제거)
  safe_name "$2" || return 0
  eval "la_cur=\$$1"
  case " $la_cur " in *" $2 "*) return 0 ;; esac
  if [ -z "$la_cur" ]; then eval "$1=\$2"; else eval "$1=\"\$la_cur \$2\""; fi
}

fpm_unit_for() { # disp -> unit 이름
  fu_d=$1; fu_b=${fu_d##*/}
  safe_name "$fu_b" || return 1
  case $fu_d in
    */opt/remi/php*)
      fu_c=$(printf '%s' "$fu_d" | sed -n 's#.*/opt/remi/\(php[0-9]*\)/.*#\1#p')
      printf '%s-php-fpm' "$fu_c"; return 0 ;;
  esac
  case $fu_b in
    php-fpm[0-9]*)
      fu_v=${fu_b#php-fpm}
      case $fu_v in
        *.*) printf 'php%s-fpm' "$fu_v" ;;
        *) printf 'php-fpm%s' "$fu_v" ;;
      esac ;;
    *) printf 'php-fpm' ;;
  esac
}

sapi_of() { # kind bn
  case $1 in
    lib) SAPI=apache; return 0 ;;
    unresolved) SAPI=unknown; return 0 ;;
  esac
  case $2 in
    php-fpm*) SAPI=fpm ;;
    php-cgi*) SAPI=cgi ;;
    lsphp*) SAPI=litespeed ;;
    frankenphp*) SAPI=frankenphp ;;
    php|php[0-9]*) SAPI=cli ;;
    *) SAPI=unknown ;;
  esac
}

evaluate() {
  NOTES=""
  ev_bn=${ev_disp##*/}
  sapi_of "$ev_kind" "$ev_bn"
  VER=""; VSRC=""
  PKG_NAME=""; PKG_VER=""; PKG_TIME=""; PKG_PM=""
  VENDOR=unknown
  ev_pkgable=1
  case $ev_key in name:*|gone:*|ns:*) ev_pkgable=0 ;; esac

  if [ "$ev_kind" = unresolved ]; then
    add_note "권한 부족 등으로 실행 파일 경로를 확인하지 못한 프로세스입니다(PID: $ev_pids). root 로 다시 실행하세요."
    ev_acc=""
  fi

  if [ "$ev_pkgable" = 1 ]; then pkg_lookup "$ev_disp"; fi

  # 1) 실행(-n -v)
  EXEC_NOTE=""
  if [ "$ev_kind" = bin ] && [ "$ev_cont" = 0 ] && [ -x "$ev_acc" ] && regular_capped "$ev_acc" 125829120 && exec_allowed "$EXEC_MODE" "$ev_acc" "$ev_del" "$EUID_NUM"; then
    case $ev_bn in
      frankenphp*) ev_out=$(run_to "$ev_acc" version) ;;
      *) ev_out=$(run_to "$ev_acc" -n -v) ;;
    esac
    ev_raw=$(ver_from_output "$ev_out")
    VER=$(norm_version "$ev_raw")
    if [ -n "$VER" ]; then VSRC="exec"; else add_note "실행 결과에서 버전을 읽지 못했습니다(실행 실패 또는 시간 초과). 다른 방법으로 대체합니다."; fi
  fi
  if [ -n "${EXEC_NOTE:-}" ]; then add_note "$EXEC_NOTE"; fi
  # 2) 패키지 DB
  if [ -z "$VER" ] && [ -n "$PKG_VER" ]; then
    VER=$(norm_version "$PKG_VER")
    [ -n "$VER" ] && VSRC="package-db"
  fi
  # 3) 정적 문자열 스캔(실행 없음)
  if [ -z "$VER" ] && [ -n "$ev_acc" ] && [ -r "$ev_acc" ]; then
    ev_raw=$(ver_static "$ev_acc")
    VER=$(norm_version "$ev_raw")
    [ -n "$VER" ] && VSRC="static-scan"
  fi
  # 4) 경로명 추정
  if [ -z "$VER" ] && [ "$ev_kind" != unresolved ]; then
    ev_raw=$(ver_from_path "$ev_disp")
    VER=$(norm_version "$ev_raw")
    [ -n "$VER" ] && VSRC="path-name"
  fi

  case $VSRC in
    exec) add_note "버전 출처: \`-n -v\` 실행 결과" ;;
    package-db) add_note "버전 출처: 패키지 데이터베이스 ($PKG_NAME $PKG_VER)" ;;
    static-scan) add_note "버전 출처: 바이너리 정적 문자열 스캔(실행 안 함)" ;;
    path-name) add_note "버전 출처: 경로명에서 추정(신뢰도 낮음, 직접 확인 필요)" ;;
    *) if [ "$ev_kind" != unresolved ]; then
         if [ "$ROOT_NOEXEC" = 1 ]; then
           add_note "버전을 확인하지 못했습니다. --root 에서는 바이너리를 실행하지 않습니다. 신뢰할 수 있는 트리라면 --exec"
         else
           add_note "버전을 확인하지 못했습니다(--no-exec 이거나 패키지 DB/문자열 정보 없음)."
         fi
       fi ;;
  esac
  if [ -n "$PKG_VER" ] && [ "$VSRC" = exec ]; then
    case $PKG_VER in *[!0-9.]*) add_note "패키지 버전 문자열: $PKG_VER" ;; esac
  fi

  # 분류
  if [ -n "$VER" ]; then CLASS=$(classify "$VER"); else CLASS=unknown; fi

  # 벤더 근거
  if [ -n "$PKG_PM" ]; then vendor_check; fi
  if [ "$ev_pkgable" = 0 ] && [ "$ev_cont" = 1 ]; then
    add_note "다른 마운트 네임스페이스(컨테이너)의 프로세스입니다. 패키지 DB/벤더 변경 이력은 해당 컨테이너 안에서 확인하세요."
  fi

  # 판정
  case $CLASS in
    fixed) VERDICT=fixed ;;
    vulnerable|eol_backport|eol_no_fix)
      if [ "$VENDOR" = yes ]; then VERDICT=vendor_patched; else VERDICT=vulnerable; fi ;;
    old_unsupported) VERDICT=eol ;;
    *) VERDICT=unknown ;;
  esac
  if [ "$VENDOR" = yes ] && [ "$VERDICT" = vendor_patched ]; then
    add_note "벤더 변경 이력에 $CVE1, $CVE2 가 모두 있습니다. 실제 수정 여부는 벤더 보안 공지로 교차 확인하세요."
  elif [ "$VENDOR" = no ]; then
    add_note "벤더 변경 이력을 읽었지만 두 CVE 번호가 모두 확인되지 않았습니다."
  fi
  case $PKG_PM in apk|pkg|brew)
    [ "$CLASS" != fixed ] && add_note "이 패키지 관리자는 변경 이력(changelog) 확인을 지원하지 않아 벤더 패치 여부를 알 수 없습니다." ;;
  esac

  # 재시작
  nr_eval
  if [ -n "$ev_pids" ]; then RUNNING=true; else RUNNING=false; fi
  if [ "$ev_del" = 1 ]; then
    add_note "실행 중인 프로세스의 바이너리/라이브러리가 교체 또는 삭제되었습니다((deleted)). 옛 코드가 메모리에 남아 있어 재시작이 필요합니다."
    ev_first=${ev_pids%% *}
    if [ -n "$ev_first" ] && [ -r "/proc/$ev_first/exe" ] && [ "$ev_cont" = 0 ]; then
      ev_old=$(norm_version "$(ver_static "/proc/$ev_first/exe")")
      [ -n "$ev_old" ] && add_note "실행 중인 이전 코드의 버전(추정): $ev_old"
    fi
  fi
  if [ "$NEEDS" = true ] && [ "$ev_del" != 1 ]; then
    add_note "프로세스 시작 시각이 바이너리/패키지 파일 시각보다 오래되었습니다. 옛 코드가 실행 중일 수 있습니다."
  fi
  if [ "$ROOTMODE" = 1 ]; then add_note "--root 모드: 실행 중 프로세스 점검을 건너뛰었습니다."; fi

  # 정적 설정 스캔 결과 첨부
  case $SAPI in fpm|apache|cgi|cli|litespeed) ev_lab=$SAPI ;; *) ev_lab=shared ;; esac
  if [ -s "$MITF" ] && [ "$ev_kind" != unresolved ]; then
    awk -F "$US" -v lab="$ev_lab" '$1 == lab || $1 == "shared" { print "[" $1 "] " $2 ":" $3 ": " $4 }' "$MITF" | head -6 > "$TMPD/mitn.txt"
    while IFS= read -r mn_l <&3; do
      add_note "정적 설정: $mn_l"
    done 3< "$TMPD/mitn.txt"
  fi
  if [ "$ev_kind" != unresolved ] && [ "$SAPI" != cli ]; then
    add_note "설정 관찰은 ini/pool/vhost 파일을 정적으로 읽은 결과이며 php -i 가 아닙니다. 완화 설정은 안전 보장이 아닙니다."
  fi

  # 집계
  C_TOTAL=$((C_TOTAL + 1))
  case $VERDICT in
    vulnerable) C_VULN=$((C_VULN + 1)) ;;
    fixed) C_FIXED=$((C_FIXED + 1)) ;;
    vendor_patched) C_VP=$((C_VP + 1)) ;;
    eol) C_EOL=$((C_EOL + 1)) ;;
    *) C_UNK=$((C_UNK + 1)) ;;
  esac
  [ "$NEEDS" = true ] && C_NR=$((C_NR + 1))
  [ "$ev_kind" = lib ] && C_LIB=$((C_LIB + 1))

  # 조치 계획 재료
  if [ "$VERDICT" != fixed ] || [ "$NEEDS" = true ]; then
    list_add PLAN_SAPIS "$SAPI"
    if [ -n "$PKG_NAME" ] && [ "$PKG_PM" != brew ]; then list_add PLAN_PKGS "$PKG_NAME"; fi
    if [ "$PKG_PM" = brew ] && [ -n "$PKG_NAME" ]; then list_add BREW_FORMULAE "$PKG_NAME"; fi
    if [ "$SAPI" = fpm ]; then list_add FPM_UNITS "$(fpm_unit_for "$ev_disp")"; fi
    printf '%s\n' "$ev_disp$US$VER$US$CLASS" >> "$BRANCH_LINES"
  fi

  if [ -n "$ev_pids" ]; then ev_pj=$ev_pids; else ev_pj=""; fi
  if [ -z "$VER" ]; then ev_verout=""; else ev_verout=$VER; fi
  ev_pkgout=$(clean_value "$PKG_NAME")
  printf '%s\n' "$ev_disp$US$ev_verout$US$CLASS$US$VERDICT$US$SAPI$US$RUNNING$US$ev_pj$US$ev_pkgout$US$VENDOR$US$NEEDS$US$NOTES" >> "$RESULTS"
}

while IFS=$US read -r ev_key ev_disp ev_acc ev_kind ev_cont ev_del ev_pids <&3; do
  [ -n "$ev_key" ] || continue
  evaluate
done 3< "$TMPD/groups.txt"

# ---------------------------------------------------------------- 종료 코드
EXITC=0
if [ $((C_VULN + C_EOL + C_NR)) -gt 0 ]; then EXITC=1
elif [ "$C_UNK" -gt 0 ]; then EXITC=3
elif [ "$WEB_UNREAD" = 1 ] && [ "$C_LIB" = 0 ]; then EXITC=3
elif [ "$ROOTMODE" = 0 ] && [ "$PROC_ENUM" = 0 ] && [ "$C_TOTAL" = 0 ]; then EXITC=3
fi

# ---------------------------------------------------------------- 출력 도우미
jesc() { tr '\000-\037' '?' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }
jstr() { printf '"%s"' "$(printf '%s' "$1" | jesc)"; }
jnull_or_str() { if [ -z "$1" ]; then printf 'null'; else jstr "$1"; fi; }

emit_json() {
  printf '{"tool":"%s","as_of":"%s","host":%s,"platform":%s,"installations":[' "$TOOL" "$AS_OF" "$(jstr "$HOSTN")" "$(jstr "$PLATFORM")"
  ej_first=1
  while IFS=$US read -r f_path f_ver f_class f_verdict f_sapi f_run f_pids f_pkg f_vendor f_needs f_notes <&3; do
    [ "$ej_first" = 1 ] || printf ','
    ej_first=0
    printf '{"path":%s,"version":%s,"class":"%s","verdict":"%s","sapi":"%s","running":%s,"pids":[' "$(jstr "$f_path")" "$(jnull_or_str "$f_ver")" "$f_class" "$f_verdict" "$f_sapi" "$f_run"
    ej_p=1
    for ej_pid in $f_pids; do
      [ "$ej_p" = 1 ] || printf ','
      ej_p=0
      printf '%s' "$ej_pid"
    done
    printf '],"package":%s,"vendor_patch":"%s","needs_restart":%s,"notes":[' "$(jnull_or_str "$f_pkg")" "$f_vendor" "$f_needs"
    ej_rest=$f_notes; ej_n=1
    while [ -n "$ej_rest" ]; do
      case $ej_rest in
        *"$RS"*) ej_one=${ej_rest%%"$RS"*}; ej_rest=${ej_rest#*"$RS"} ;;
        *) ej_one=$ej_rest; ej_rest="" ;;
      esac
      [ "$ej_n" = 1 ] || printf ','
      ej_n=0
      jstr "$ej_one"
    done
    printf ']}'
  done 3< "$RESULTS"
  printf '],"summary":{"vulnerable":%s,"fixed":%s,"vendor_patched":%s,"eol":%s,"unknown":%s,"needs_restart":%s},"exit_code":%s}\n' \
    "$C_VULN" "$C_FIXED" "$C_VP" "$C_EOL" "$C_UNK" "$C_NR" "$EXITC"
}

vlabel() {
  case $1 in
    vulnerable) printf '취약' ;;
    fixed) printf '수정됨' ;;
    vendor_patched) printf '벤더 패치 확인' ;;
    eol) printf '지원 종료(EOL)' ;;
    *) printf '판정 불가' ;;
  esac
}

class_reason() {
  case $1 in
    fixed) say "  설명: 업스트림 수정 릴리스 이상입니다." ;;
    vulnerable) say "  설명: 지원 중인 브랜치이지만 수정 릴리스(8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 / 8.6.0RC4) 미만입니다." ;;
    eol_backport) say "  설명: 7.4 / 8.0 / 8.1 은 영향을 받으며 공식 수정 릴리스가 없습니다. 벤더 패치 또는 소스 백포트만 가능합니다." ;;
    eol_no_fix) say "  설명: 5.4 - 7.3 은 영향을 받고 EOL 이라 수정이 어디에도 없습니다. 지원되는 브랜치로 이전하세요." ;;
    old_unsupported) say "  설명: 5.4 미만은 공표된 영향 범위 밖이지만 오래전에 EOL 입니다. 안전하지 않으므로 이전하세요." ;;
    *) say "  설명: 버전을 해석하지 못했습니다." ;;
  esac
}

target_for() { # 버전 -> 목표 버전 문구
  case $1 in
    8.2.*) printf '8.2.35 이상' ;;
    8.3.*) printf '8.3.36 이상' ;;
    8.4.*) printf '8.4.27 이상' ;;
    8.5.*) printf '8.5.12 이상' ;;
    8.6.*) printf '8.6.0RC4 이상(정식 8.6.0 권장)' ;;
    8.0.*|8.1.*|7.4.*) printf '공식 수정 없음 -> 벤더 패치 패키지(CVE 2건 확인) 또는 8.2 이상으로 이전' ;;
    *) printf '지원되는 브랜치(8.2 이상, 수정 릴리스)로 이전' ;;
  esac
}

render_text() {
  say "PHP2Shell (CVE-2026-109618 / CVE-2026-109619) 점검 결과  [기준일 $AS_OF]"
  say "호스트: $HOSTN"
  say "플랫폼: $PLATFORM"
  [ "$ROOTMODE" = 1 ] && say "모드: --root ${ROOT:-/} (파일만 점검, 실행 중 프로세스 점검 생략)"
  if [ "$ROOT_NOEXEC" = 1 ]; then say "모드: --root 기본 비실행(바이너리를 실행하지 않음, 신뢰할 수 있는 트리라면 --exec)"
  elif [ "$NOEXEC" = 1 ]; then say "모드: --no-exec (어떤 바이너리도 실행하지 않음)"; fi
  if [ "$ROOTMODE" = 0 ] && [ "$IS_ROOT" = 0 ]; then
    say "주의: root 가 아니므로 다른 사용자 프로세스 정보가 제한될 수 있습니다. sudo 로 다시 실행하세요."
  fi
  say ""
  if [ "$C_TOTAL" = 0 ]; then
    if [ "$ROOTMODE" = 1 ]; then
      say "PHP 설치를 찾지 못했습니다(지정한 루트 아래 일반 경로 기준)."
    elif [ "$PROC_ENUM" = 1 ]; then
      say "PHP 를 찾지 못했습니다(프로세스 열거 가능, 일반 경로 파일 탐색 완료)."
      say "비표준 경로(소스 빌드, 번들 패키지)나 컨테이너 안에는 있을 수 있습니다. 해당 컨테이너 안에서도 실행하세요."
    else
      say "PHP 를 찾지 못했지만 프로세스를 열거하지 못해 판정할 수 없습니다."
    fi
    say ""
  fi
  while IFS=$US read -r f_path f_ver f_class f_verdict f_sapi f_run f_pids f_pkg f_vendor f_needs f_notes <&3; do
    say "[$(vlabel "$f_verdict")] ${f_ver:-버전 불명}  $f_path"
    say "  판정: $f_verdict (class: $f_class)"
    say "  SAPI: $f_sapi"
    if [ "$f_run" = true ]; then say "  실행 중: 예 (PID: $f_pids)"; else say "  실행 중: 아니오/확인 안 됨"; fi
    say "  패키지: ${f_pkg:-없음(소스 설치 또는 번들 가능)}   벤더 패치 근거: $f_vendor   재시작 필요: $f_needs"
    class_reason "$f_class"
    case $f_verdict in
      vulnerable|eol) say "  목표: $(target_for "$f_ver")" ;;
    esac
    if [ "$f_verdict" = fixed ] && [ "$f_needs" = true ]; then
      say "  경고: 디스크의 파일은 수정 버전이지만 옛 코드가 실행 중입니다. 재시작해야 반영됩니다."
    fi
    ej_rest=$f_notes
    while [ -n "$ej_rest" ]; do
      case $ej_rest in
        *"$RS"*) ej_one=${ej_rest%%"$RS"*}; ej_rest=${ej_rest#*"$RS"} ;;
        *) ej_one=$ej_rest; ej_rest="" ;;
      esac
      say "    - $ej_one"
    done
    say ""
  done 3< "$RESULTS"
  say "요약: 취약 $C_VULN / 수정됨 $C_FIXED / 벤더 패치 $C_VP / EOL $C_EOL / 판정 불가 $C_UNK / 재시작 필요 $C_NR   (종료 코드 $EXITC)"
  if [ "$EXITC" = 3 ]; then
    say "판정 불가: 프로세스/권한/버전 정보를 충분히 얻지 못했습니다. root 로 다시 실행하거나 --no-exec 없이 실행해 보세요."
  fi
  say ""
}

# ---------------------------------------------------------------- 조치 계획
plan_update() {
  say "[1] 업데이트 (근본 조치: 이것만이 실제 해결입니다)"
  pk=$PLAN_PKGS
  case $PM in
    apt)
      say "  sudo apt-get update"
      if [ -n "$pk" ]; then say "  sudo apt-get install --only-upgrade $pk"
      else say "  sudo apt-get install --only-upgrade 'php*' 'libapache2-mod-php*'"; fi
      say "  # 벤더 패치 확인: 두 CVE 번호가 모두 나와야 함"
      pk1=${pk%% *}; say "  apt-get changelog ${pk1:-php-cli} | grep -E 'CVE-2026-109618|CVE-2026-109619'"
      say "  # 보안 저장소에 아직 수정 패키지가 없으면 배포판 보안 공지를 확인하거나 외부 저장소(예: Sury)의 서명/신뢰를 검토한 뒤 사용" ;;
    dnf|microdnf|yum)
      case $PM in
        dnf) say "  sudo dnf clean expire-cache && sudo dnf upgrade --refresh ${pk:-'php*'}" ;;
        microdnf) say "  microdnf upgrade ${pk:-'php*'}" ;;
        yum) say "  sudo yum clean expire-cache && sudo yum update ${pk:-'php*'}" ;;
      esac
      say "  # 벤더 패치 확인: 두 CVE 번호가 모두 나와야 함"
      pk1=${pk%% *}; say "  rpm -q --changelog ${pk1:-php-fpm} | grep -E 'CVE-2026-109618|CVE-2026-109619'"
      case $OS_VER in
        6*|7*)
          if [ "$OS_ID" = centos ] || [ "$OS_ID" = rhel ]; then
            say "  # EL${OS_VER%%.*} 는 EOL 이라 공식 수정 패키지가 없을 수 있습니다: 연장 지원(ELS) 벤더 패키지 또는 8 이상으로 이전"
          fi ;;
      esac
      say "  # Remi 등 외부 저장소 사용 시 해당 저장소가 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 이상을 제공하는지 확인" ;;
    zypper)
      say "  sudo zypper refresh && sudo zypper update ${pk:-'php*'}"
      pk1=${pk%% *}; say "  rpm -q --changelog ${pk1:-php} | grep -E 'CVE-2026-109618|CVE-2026-109619'" ;;
    apk)
      say "  apk update && apk upgrade ${pk:-php}   # root 로 실행. 패키지 이름은 php83, php84 처럼 버전 접미사가 붙음"
      pk1=${pk%% *}; say "  apk policy ${pk1:-php}    # 설치/후보 버전 확인 (apk 는 changelog 로 벤더 패치 여부를 확인할 수 없음)"
      say "  # Alpine 브랜치에 수정 버전이 아직 없으면 더 새 브랜치(edge 포함)의 수정 버전을 검토하거나 이미지를 교체" ;;
    pkg)
      say "  sudo pkg update && sudo pkg upgrade -g 'php*'"
      say "  sudo pkg audit -F    # 취약점 데이터베이스 갱신(네트워크 사용)과 PHP 패키지 확인" ;;
    brew)
      say "  brew update && brew upgrade ${BREW_FORMULAE:-php}"
      pk1=${BREW_FORMULAE%% *}; say "  brew info ${pk1:-php}    # 설치된 버전이 수정 릴리스 이상인지 확인" ;;
    *)
      say "  패키지 관리자를 확인하지 못했습니다. 번들(XAMPP, MAMP 등)이면 번들을 수정 버전으로 교체하고,"
      say "  소스 빌드이면 https://www.php.net/downloads 에서 수정 릴리스를 받아 다시 빌드하세요." ;;
  esac
  if [ "$PM" != brew ] && [ "$PM" != none ]; then
    say "  # 패키지 소유자가 없는 PHP(소스 빌드, 번들)는 위 명령으로 갱신되지 않습니다. 해당 경로를 직접 교체하세요."
  fi
  say "  # Docker: 컨테이너 안에서 패치하지 말고 수정 태그(php:8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 이상)로 이미지를 다시 빌드하세요."
  say "  docker build --pull --no-cache -t IMAGE . && docker compose up -d --force-recreate"
  if [ "$CONTAINER" = 1 ]; then
    say "  # 이 호스트는 컨테이너로 보입니다: 위 패키지 명령은 이 컨테이너에만 임시로 적용되며 이미지를 다시 빌드해야 영구 반영됩니다."
  fi
  say "  # 7.4 / 8.0 / 8.1 은 공식 수정이 없습니다: 벤더 패치(Ubuntu Pro/ESM, Debian LTS, RHEL, 연장 지원 사업자)를 확인하거나 8.2 이상으로 이전하세요."
  say "  # 5.4 - 7.3 은 수정이 없습니다: 지원되는 브랜치로 이전하고, 이전 전까지는 외부 노출을 차단하세요."
  say ""
}

plan_restart() {
  say "[2] 재시작 (업데이트 후 모든 워커를 재시작해야 새 코드가 반영됩니다)"
  say "  # reload/graceful 은 옛 바이너리가 남을 수 있으므로 restart 를 사용하고, 서비스 이름은 환경에 맞게 확인하세요."
  case $INIT in
    systemd)
      say "  systemctl list-units --type=service | grep -Ei 'php|fpm|httpd|apache|nginx|lsws|frankenphp'"
      case " $PLAN_SAPIS " in *" fpm "*|*" cgi "*)
        for u in ${FPM_UNITS:-php-fpm}; do safe_unit "$u.service" && say "  sudo systemctl restart $u.service"; done ;;
      esac
      case " $PLAN_SAPIS " in *" apache "*)
        case $PM in apt|zypper|apk) say "  sudo systemctl restart apache2.service" ;; *) say "  sudo systemctl restart httpd.service" ;; esac ;;
      esac
      case " $PLAN_SAPIS " in *" litespeed "*) say "  sudo /usr/local/lsws/bin/lswsctrl restart" ;; esac
      case " $PLAN_SAPIS " in *" frankenphp "*) say "  sudo systemctl restart frankenphp.service" ;; esac ;;
    openrc)
      case " $PLAN_SAPIS " in *" fpm "*|*" cgi "*)
        for u in ${FPM_UNITS:-php-fpm}; do say "  sudo rc-service $u restart"; done ;;
      esac
      case " $PLAN_SAPIS " in *" apache "*) say "  sudo rc-service apache2 restart" ;; esac
      case " $PLAN_SAPIS " in *" litespeed "*) say "  sudo /usr/local/lsws/bin/lswsctrl restart" ;; esac ;;
    bsdrc)
      case " $PLAN_SAPIS " in *" fpm "*|*" cgi "*) say "  sudo service php_fpm restart" ;; esac
      case " $PLAN_SAPIS " in *" apache "*) say "  sudo service apache24 restart" ;; esac ;;
    launchd)
      case " $PLAN_SAPIS " in *" fpm "*|*" cgi "*) pk1=${BREW_FORMULAE%% *}; say "  brew services restart ${pk1:-php}" ;; esac
      case " $PLAN_SAPIS " in *" apache "*) say "  sudo apachectl restart   # 또는 brew services restart httpd" ;; esac
      say "  # launchd 직접 관리 시: sudo launchctl kickstart -k system/SERVICE_LABEL" ;;
    sysv)
      case " $PLAN_SAPIS " in *" fpm "*|*" cgi "*)
        for u in ${FPM_UNITS:-php-fpm}; do say "  sudo service $u restart   # 또는 /etc/init.d/$u restart"; done ;;
      esac
      case " $PLAN_SAPIS " in *" apache "*) say "  sudo service apache2 restart   # RHEL 계열은 httpd" ;; esac ;;
    *)
      say "  # init 시스템을 감지하지 못했습니다(컨테이너로 보일 수 있음). 컨테이너는 이미지를 다시 빌드하여 재생성하세요."
      say "  docker compose up -d --force-recreate" ;;
  esac
  case " $PLAN_SAPIS " in *" cgi "*) say "  # php-cgi 는 FastCGI 관리자(nginx+spawn-fcgi, lighttpd 등)나 웹 서버를 함께 재시작해야 합니다." ;; esac
  case " $PLAN_SAPIS " in *" cli "*) say "  # 장기 실행 CLI(큐 워커, supervisor, systemd 서비스, Swoole 등)도 모두 재시작하세요." ;; esac
  say "  # 재시작 후 확인: 실행 파일이 (deleted) 가 아닌지, 프로세스 시작 시각이 업데이트 이후인지"
  say "  #   ls -l /proc/PID/exe     ps -o pid,lstart,cmd -p PID"
  say "  # 그리고 이 도구를 다시 실행해 재시작 필요 항목이 없는지 확인하세요."
  say ""
}

plan_mitigation() {
  say "[3] 임시 완화 (업데이트 전 한시적 조치, 일부 공격 경로만 줄이며 완전한 해결이 아님)"
  say "  임시 조치는 일부 공격 경로만 줄이며 완전한 해결이 아닙니다. 업데이트만이 근본 조치입니다. 완화 설정이 있어도 '안전'하다고 판단하지 마세요."
  say "  설정은 관리자만 바꿀 수 있는 위치에 두세요: FPM pool 의 php_admin_value[...], Apache 의 php_admin_value."
  say "  ini_set(), .user.ini, php_value 로 넣은 설정은 애플리케이션/공격자 코드가 덮어쓰거나 PERDIR 제한으로 적용되지 않을 수 있습니다."
  say "  적용 후 해당 SAPI 의 모든 워커를 재시작하고, 설정 확인은 CLI(php -i)가 아니라 웹 요청 경로로 하세요(CLI 는 다른 ini 를 읽습니다)."
  say ""
  say "  FPM pool 파일(풀마다):"
  cat <<'EOF'
    php_admin_value[session.upload_progress.enabled] = 0
    php_admin_value[memory_limit] = -1
    php_admin_value[session.auto_start] = 0
    php_admin_value[post_max_size] = 8M
    php_admin_value[fatal_error_backtraces] = 0
EOF
  say "  Apache(mod_php) vhost / 서버 설정:"
  cat <<'EOF'
    php_admin_value session.upload_progress.enabled 0
    php_admin_value memory_limit -1
    php_admin_value session.auto_start 0
    php_admin_value post_max_size 8M
EOF
  say "  php-cgi / 공용 php.ini:"
  cat <<'EOF'
    session.upload_progress.enabled = 0
    memory_limit = -1
    session.auto_start = 0
    post_max_size = 8M
EOF
  say ""
  say "  주의 사항:"
  say "   - memory_limit=-1 은 PHP 의 메모리 상한을 없애므로 컨테이너·cgroup·systemd MemoryMax 등 OS 수준 상한을 반드시 함께 설정하세요. RLIMIT_AS/RLIMIT_DATA 는 쓰지 마세요."
  say "   - session.auto_start=0: session_start() 를 호출하지 않는 페이지의 세션 기능이 멈출 수 있습니다."
  say "   - post_max_size: 업로드가 필요 없으면 8M, 필요하면 32M 수준. upload_max_filesize 는 post_max_size 보다 작게 유지하세요."
  say "   - fatal_error_backtraces=0 은 PHP 8.5 에만 해당합니다."
  say ""
  say "  이 호스트에서 정적으로 읽은 관련 설정(php -i 아님, 웹 SAPI 와 CLI 의 ini 는 다를 수 있음):"
  if [ -s "$MITF" ]; then
    awk -F "$US" '{ print "    [" $1 "] " $2 ":" $3 ": " $4 }' "$MITF" | sort -u | clean_stream
  else
    say "    관련 키를 명시한 파일을 찾지 못했습니다(PHP 기본값 적용: upload_progress 사용 가능, memory_limit 128M, auto_start 0, post_max_size 8M)."
    say "    표준 경로 밖의 설정 파일이 있을 수 있습니다."
  fi
  say ""
}

plan_virtual_patch() {
  say "[4] 가상 패치 (임시 대응) - 업데이트가 불가능한 동안만 적용하는 보조 수단"
  say "  자세한 규칙과 예시는 저장소의 virtual-patch/ 디렉터리를 참고하세요. 가상 패치는 완전한 해결이 아니며 우회될 수 있습니다."
  say "   - 요청 크기 제한: 리버스 프록시/웹 서버에서 본문 크기 제한 (nginx client_max_body_size, Apache LimitRequestBody)"
  say "   - multipart/form-data 차단: 업로드가 필요 없는 경로에서는 해당 Content-Type 요청을 프록시/WAF 에서 거부"
  say "   - WAF 규칙: 벤더가 제공하는 PHP2Shell 관련 규칙을 차단(block) 모드로 적용하고 오탐은 로그로 확인"
  say "   - php_admin_* 설정: 위 [3] 의 값을 FPM pool / Apache 에 관리자 전용으로 적용"
  say "   - cgroup 메모리 상한: systemd MemoryMax, 컨테이너 --memory 로 PHP 프로세스의 메모리 사용을 OS 수준에서 제한"
  say "   - 노출 축소: 관리자/점검 페이지는 IP 허용목록 또는 VPN 뒤로 이동하고, 불필요한 PHP 엔드포인트는 제거"
  say "   - 외부 통신 차단: 웹 서버 계정의 아웃바운드 연결을 방화벽/egress 정책으로 최소화하여 침해 시 확산과 유출을 줄임"
  say ""
}

plan_offline() {
  say "[5] 오프라인/폐쇄망 패치 절차 (--offline)"
  say "  인터넷이 되는 PC(대상 서버와 같은 배포판/버전/아키텍처)에서 패키지 번들을 만들고, 반입한 뒤 대상 서버에서 설치합니다."
  pk=${PLAN_PKGS:-php}
  case $PM in
    apt)
      say "  (a) 번들 만들기 - 인터넷 PC. 설치 상태가 같도록 대상 서버의 /var/lib/dpkg/status 사본을 쓰거나 같은 이미지에서 실행:"
      say "      sudo apt-get update"
      say "      apt-get --print-uris -y install --only-upgrade $pk > uris.txt"
      say "      grep \"^'\" uris.txt | awk '{print \$1}' | tr -d \"'\" > urls.txt"
      say "      mkdir bundle && (cd bundle && xargs -n1 curl -fLO < ../urls.txt)"
      say "      # uris.txt 의 4번째 필드(SHA256:...)가 각 .deb 의 기대 체크섬입니다: sha256sum bundle/*.deb 와 대조"
      say "  (b) 대상 서버에 bundle/ 반입 후 설치 - 대상 서버:"
      say "      sha256sum bundle/*.deb    # 반입 전 값과 일치하는지 확인"
      say "      sudo apt-get install ./bundle/*.deb     # 또는 sudo dpkg -i bundle/*.deb"
      say "  (c) dpkg -i 는 서명을 검증하지 않습니다: 반드시 서명이 검증된 저장소 인덱스(InRelease)의 체크섬과 대조하세요." ;;
    dnf|microdnf|yum)
      say "  (a) 번들 만들기 - 인터넷 PC:"
      say "      dnf download --resolve --alldeps --destdir bundle $pk     # dnf-plugins-core 필요"
      say "      yumdownloader --resolve --destdir bundle $pk              # yum-utils (구형 EL)"
      say "      sha256sum bundle/*.rpm > bundle/SHA256SUMS"
      say "  (b) 대상 서버에서 설치:"
      say "      (cd bundle && sha256sum -c SHA256SUMS)"
      say "      rpm -K bundle/*.rpm     # GPG 서명 검증(저장소 공개키가 import 되어 있어야 함)"
      say "      sudo dnf install ./bundle/*.rpm     # 구형: sudo yum localinstall bundle/*.rpm 또는 sudo rpm -Uvh bundle/*.rpm"
      say "  (c) 서명 검증이 실패하는 파일은 설치하지 말고 벤더 사이트의 체크섬과 대조하세요." ;;
    zypper)
      say "  (a) 번들 만들기 - 인터넷 PC: sudo zypper --pkg-cache-dir ./bundle install --download-only $pk"
      say "      sha256sum bundle/*/*.rpm > SHA256SUMS"
      say "  (b) 대상 서버: sha256sum -c SHA256SUMS && rpm -K <파일>.rpm && sudo zypper install ./<파일>.rpm" ;;
    apk)
      say "  (a) 번들 만들기 - 인터넷 PC(같은 Alpine 브랜치/아키텍처):"
      say "      apk update && apk fetch -R -o bundle $pk"
      say "      sha256sum bundle/*.apk > bundle/SHA256SUMS"
      say "  (b) 대상 서버: (cd bundle && sha256sum -c SHA256SUMS) && apk add --no-network bundle/*.apk"
      say "  (c) 서명은 /etc/apk/keys 로 검증됩니다. --allow-untrusted 는 쓰지 마세요." ;;
    pkg)
      say "  (a) 번들 만들기 - 인터넷 PC: pkg fetch -d -y -o bundle php84    # 패키지 이름은 설치된 것에 맞춤"
      say "  (b) 대상 서버: sha256sum 대조 후 sudo pkg add bundle/All/*.pkg" ;;
    brew)
      say "  (a) 인터넷 PC: brew fetch --deps php    (bottle 을 다운로드)"
      say "  (b) 대상 Mac 으로 반입 후 체크섬 대조: shasum -a 256 <bottle 파일>, 이어서 brew install <bottle 파일>" ;;
    *)
      say "  (a) 소스 설치: 인터넷 PC 에서 https://www.php.net/downloads 의 수정 릴리스 tar.xz 와 SHA256/서명을 받아 반입"
      say "  (b) 대상 서버: sha256sum 과 gpg --verify 로 대조한 뒤 빌드/설치" ;;
  esac
  say "  공통: 반입 매체의 체크섬(SHA-256)을 별도 경로로 기록해 두고, 설치 후에는 이 도구를 다시 실행해 버전과 재시작 여부를 확인하세요."
  say ""
}

plan_verify() {
  say "[6] 검증"
  say "  - 웹 요청 경로로 확인: 관리자 전용 임시 진단 페이지(IP 제한)에서 PHP_VERSION 을 출력해 확인한 뒤 즉시 삭제하세요. CLI 결과는 웹 SAPI 와 다를 수 있습니다."
  say "  - expose_php 가 켜져 있다면: curl -sI https://YOUR_HOST/ | grep -i x-powered-by"
  say "  - 이 도구를 다시 실행: 종료 코드 0 이고 재시작 필요 항목이 없어야 합니다."
  say ""
}

plan_evidence() {
  say "[증거 보존/신고]"
  say "  - 침해가 의심되면 재시작/재부팅/재설치 전에 증거를 먼저 수집하세요(메모리·프로세스 목록·웹/PHP-FPM 로그·최근 변경 파일)."
  say "    재시작하면 메모리 속 흔적이 사라집니다. 수집본은 읽기 전용 매체에 복사하고 해시를 기록하세요."
  say "  - 로그 점검 기준일: 2026-10-17 이후(최초 악용 관측일)."
  say "    예) 웹 루트의 최근 변경 PHP 파일 확인: find /var/www -type f -name '*.php' -mtime -14"
  say "  - 신고/상담: KISA 118 (국번 없이), https://boho.or.kr"
  say ""
}

plan_sources() {
  say "[출처]"
  say "  - PHP.net 공식 공지: https://www.php.net/archive/2026.php#2026-10-21-5"
  say "  - GHSA-w8hw-w9fx-j79w (CVE-2026-109618): https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w"
  say "  - GHSA-6wmf-4rv5-p3rp (CVE-2026-109619): https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp"
  say "  - KISA 보호나라: https://www.boho.or.kr/kr/bbs/view.do?bbsId=B0000133&menuNo=205020&nttId=72230"
  say "  - NCSC-NL/CERT-EU: https://github.com/NCSC-NL/php2shell"
  say "  - Sysdig: https://www.sysdig.com/blog/php2shell-cve-2026-109618-and-cve-2026-109619-detecting-unauthenticated-remote-code-execution-in-php-core"
  say "  - Xint: https://xint.io/ko/blog/php2shell-vulnerability-emergency-response"
}

render_plan() {
  say "================ 조치 계획 ================"
  if [ "$EXITC" = 0 ] && [ "$C_TOTAL" -gt 0 ]; then
    say "조치가 필요한 항목이 없습니다. 그래도 이전 노출 기간(2026-10-17 이후)의 로그는 점검하세요."
    say ""
  else
    say "플랫폼: $PLATFORM / 패키지 관리자: $PM / init: $INIT / 컨테이너: $([ "$CONTAINER" = 1 ] && printf '예' || printf '아니오')"
    say ""
    plan_update
    plan_restart
    plan_mitigation
    plan_virtual_patch
    if [ "$OFFLINE" = 1 ]; then plan_offline; plan_verify; else plan_verify; fi
  fi
  if [ "$EXITC" = 0 ] && [ "$C_TOTAL" -gt 0 ] && [ "$OFFLINE" = 1 ]; then
    plan_offline
  fi
  plan_evidence
  plan_sources
}

# ---------------------------------------------------------------- 맞춤 조치 계획 파일 (--plan-file)
# 이 도구는 파일을 "쓰기만" 합니다. 파일 안의 명령은 절대 실행하지 않습니다.
safe_words() { # 공백 구분 목록에서 셸에 안전한 단어만 남김
  sw_out=""
  for sw_w in $1; do
    case $sw_w in ''|*[!A-Za-z0-9._+:@-]*) continue ;; esac
    sw_out="$sw_out $sw_w"
  done
  printf '%s' "${sw_out# }"
}

write_plan_file() {
  wp_f=$1
  wp_pk=$(safe_words "$PLAN_PKGS")
  wp_units=$(safe_words "${FPM_UNITS:-php-fpm}")
  wp_brew=$(safe_words "$BREW_FORMULAE")
  wp_hn=$(printf '%s' "$HOSTN" | tr -cd 'A-Za-z0-9._-')
  wp_pl=$(printf '%s' "$PLATFORM" | tr -cd 'A-Za-z0-9._ /()-')
  wp_now=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
  case $PM in apt) wp_glob="'php*' 'libapache2-mod-php*'" ;; *) wp_glob="'php*'" ;; esac
  wp_pkg_arg=${wp_pk:-$wp_glob}
  case $PM in apt|zypper|apk) wp_web=apache2 ;; *) wp_web=httpd ;; esac
  (
    umask 077
    set -C
    [ ! -L "$wp_f" ] && [ ! -e "$wp_f" ] || exit 2
    {
      printf '%s\n' '#!/bin/sh'
      cat <<'PF_HEAD'
# ============================================================================
# PHP2Shell (CVE-2026-109618 / CVE-2026-109619) 서버 맞춤 조치 계획
# php2shell-quickcheck.sh 가 생성했습니다. 생성 도구는 아래 명령을 실행하지 않았습니다.
# ============================================================================
# 경고:
#  - 사람이 검토하는 용도입니다. 자동 실행(cron, 배포 파이프라인, 원격 일괄 실행)에 쓰지 마세요.
#  - 각 단계를 읽고 이 서버에 맞는지 확인한 뒤, 시스템 관리자가 책임지고 직접 실행하세요.
#  - 패키지 이름과 서비스 이름은 탐지 결과에서 추정한 값이라 틀릴 수 있습니다.
#  - 임시 완화(설정 변경, 가상 패치)는 완전한 해결이 아닙니다. 업데이트만이 근본 조치입니다.
PF_HEAD
      printf '# 생성 시각: %s / 호스트: %s / 플랫폼: %s\n' "$wp_now" "$wp_hn" "$wp_pl"
      printf '# 패키지 관리자: %s / init: %s / 탐지한 SAPI:%s\n' "$PM" "$INIT" " ${PLAN_SAPIS:-없음}"
      if [ "$EXITC" = 0 ] && [ "$C_TOTAL" -gt 0 ]; then
        printf '%s\n' '# 참고: 점검 시점에는 조치가 필요한 항목이 발견되지 않았습니다.'
      fi
      cat <<'PF_GUARD'

if [ "${PHP2SHELL_I_REVIEWED:-}" != yes ]; then
  echo '자동 실행용이 아닙니다. 각 단계를 검토한 뒤 직접 실행하세요.' >&2
  echo '검토를 마쳤다면: PHP2SHELL_I_REVIEWED=yes sh 이_파일' >&2
  exit 64
fi

confirm() {
  printf '%s [y/N] ' "$1"
  read -r _ans || return 1
  case $_ans in y|Y|yes|YES) return 0 ;; esac
  echo '건너뜁니다.'
  return 1
}

SUDO=""
if [ "$(id -u)" != 0 ]; then SUDO=sudo; fi

# --- 단계 0: 증거 보존 (가장 먼저) --------------------------------------------
echo '[단계 0] 증거 보존'
echo '침해가 의심되면 재시작/재부팅/재설치 전에 증거를 먼저 확보하세요. 재시작하면 메모리 속 흔적이 사라집니다.'
echo '신고/상담: KISA 118 (국번 없이), https://boho.or.kr'
if ! confirm '증거 보존을 마쳤거나 침해 의심이 없음을 확인했습니까? (아니오이면 여기서 중단)'; then
  echo '중단합니다. 증거를 확보한 뒤 다시 실행하세요.'
  exit 1
fi
umask 077
EVID=${PHP2SHELL_EVIDENCE_DIR:-./php2shell-evidence}
if confirm "프로세스/네트워크 상태를 $EVID 에 읽기 전용으로 수집할까요?"; then
  mkdir -p "$EVID" || exit 1
  ps auxww > "$EVID/ps.txt" 2>&1
  (ss -tanp 2>/dev/null || netstat -an 2>/dev/null) > "$EVID/net.txt"
  date > "$EVID/collected_at.txt"
  echo "수집 완료: $EVID  (웹/PHP-FPM 로그와 최근 변경 PHP 파일 목록은 직접 추가로 보존하세요)"
fi

PF_GUARD
      # ---- 단계 1: 업데이트
      printf '%s\n' '# --- 단계 1: 업데이트 (패키지 업그레이드, 근본 조치) --------------------------'
      printf '%s\n' "echo '[단계 1] 패키지 업그레이드'"
      printf '%s\n' "if confirm '패키지를 업그레이드합니다. 계속할까요?'; then"
      case $PM in
        apt)
          printf '%s\n' '  $SUDO apt-get update'
          printf '%s\n' "  \$SUDO apt-get install --only-upgrade $wp_pkg_arg" ;;
        dnf) printf '%s\n' "  \$SUDO dnf upgrade --refresh $wp_pkg_arg" ;;
        microdnf) printf '%s\n' "  \$SUDO microdnf upgrade $wp_pkg_arg" ;;
        yum) printf '%s\n' "  \$SUDO yum update $wp_pkg_arg" ;;
        zypper)
          printf '%s\n' '  $SUDO zypper refresh'
          printf '%s\n' "  \$SUDO zypper update $wp_pkg_arg" ;;
        apk)
          printf '%s\n' '  $SUDO apk update'
          printf '%s\n' "  \$SUDO apk upgrade ${wp_pk:-php}" ;;
        pkg)
          printf '%s\n' '  $SUDO pkg update'
          printf '%s\n' "  \$SUDO pkg upgrade -g 'php*'" ;;
        brew)
          printf '%s\n' '  brew update'
          printf '%s\n' "  brew upgrade ${wp_brew:-php}" ;;
        *)
          printf '%s\n' "  echo '패키지 관리자를 확인하지 못했습니다. 번들/소스 설치이면 수정 릴리스로 교체하거나 다시 빌드하세요.'" ;;
      esac
      printf '%s\n' "  echo '컨테이너라면 이 명령은 임시입니다. 수정 태그(php:8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 이상)로 이미지를 다시 빌드하세요.'"
      printf '%s\n' 'fi'
      printf '\n'
      # ---- 단계 2: 벤더 패치 근거 확인 (읽기 전용)
      printf '%s\n' '# --- 단계 2: 벤더 패치 근거 확인 (읽기 전용) ---------------------------------'
      printf '%s\n' "echo '[단계 2] 벤더 패치 근거 확인(두 CVE 번호가 모두 있어야 근거로 인정)'"
      case $PM in
        apt)
          if [ -n "$wp_pk" ]; then
            printf '%s\n' "for p in $wp_pk; do"
            printf '%s\n' '  f=/usr/share/doc/$p/changelog.Debian.gz'
            printf '%s\n' '  if [ -r "$f" ]; then'
            printf '%s\n' '    n1=$(gzip -dc "$f" | grep -c CVE-2026-109618)'
            printf '%s\n' '    n2=$(gzip -dc "$f" | grep -c CVE-2026-109619)'
            printf '%s\n' '    echo "$p: CVE-2026-109618=${n1}줄 CVE-2026-109619=${n2}줄 (둘 다 1 이상이어야 함)"'
            printf '%s\n' '  else'
            printf '%s\n' '    echo "$p: changelog 를 읽을 수 없습니다. 배포판 보안 공지를 직접 확인하세요."'
            printf '%s\n' '  fi'
            printf '%s\n' 'done'
          else
            printf '%s\n' "echo '탐지된 패키지 이름이 없습니다. 배포판 보안 공지를 직접 확인하세요.'"
          fi ;;
        dnf|microdnf|yum|zypper)
          if [ -n "$wp_pk" ]; then
            printf '%s\n' "for p in $wp_pk; do"
            printf '%s\n' '  n1=$(rpm -q --changelog "$p" | grep -c CVE-2026-109618)'
            printf '%s\n' '  n2=$(rpm -q --changelog "$p" | grep -c CVE-2026-109619)'
            printf '%s\n' '  echo "$p: CVE-2026-109618=${n1}줄 CVE-2026-109619=${n2}줄 (둘 다 1 이상이어야 함)"'
            printf '%s\n' 'done'
          else
            printf '%s\n' "echo '탐지된 패키지 이름이 없습니다. 배포판 보안 공지를 직접 확인하세요.'"
          fi ;;
        apk)
          printf '%s\n' "apk policy ${wp_pk:-php}"
          printf '%s\n' "echo 'apk 는 changelog 로 벤더 패치 여부를 확인할 수 없습니다. 설치 버전이 수정 릴리스 이상인지 확인하세요.'" ;;
        *)
          printf '%s\n' "echo '이 패키지 관리자는 changelog 확인을 지원하지 않습니다. 설치 버전이 수정 릴리스 이상인지 확인하세요.'" ;;
      esac
      printf '\n'
      # ---- 단계 3: 재시작
      printf '%s\n' '# --- 단계 3: 재시작 (모든 워커를 재시작해야 새 코드가 반영됨) ------------------'
      printf '%s\n' "echo '[단계 3] 서비스 재시작'"
      printf '%s\n' "if confirm '서비스를 재시작합니다(순간적으로 요청이 끊길 수 있음). 계속할까요?'; then"
      wp_any=0
      case $INIT in
        systemd)
          case " $PLAN_SAPIS " in *" fpm "*|*" cgi "*)
            for u in $wp_units; do safe_unit "$u.service" || continue; printf '%s\n' "  \$SUDO systemctl restart $u.service"; wp_any=1; done ;;
          esac
          case " $PLAN_SAPIS " in *" apache "*) printf '%s\n' "  \$SUDO systemctl restart $wp_web.service"; wp_any=1 ;; esac
          case " $PLAN_SAPIS " in *" litespeed "*) printf '%s\n' '  $SUDO /usr/local/lsws/bin/lswsctrl restart'; wp_any=1 ;; esac
          case " $PLAN_SAPIS " in *" frankenphp "*) printf '%s\n' '  $SUDO systemctl restart frankenphp.service'; wp_any=1 ;; esac ;;
        openrc)
          case " $PLAN_SAPIS " in *" fpm "*|*" cgi "*)
            for u in $wp_units; do printf '%s\n' "  \$SUDO rc-service $u restart"; wp_any=1; done ;;
          esac
          case " $PLAN_SAPIS " in *" apache "*) printf '%s\n' '  $SUDO rc-service apache2 restart'; wp_any=1 ;; esac
          case " $PLAN_SAPIS " in *" litespeed "*) printf '%s\n' '  $SUDO /usr/local/lsws/bin/lswsctrl restart'; wp_any=1 ;; esac ;;
        bsdrc)
          case " $PLAN_SAPIS " in *" fpm "*|*" cgi "*) printf '%s\n' '  $SUDO service php_fpm restart'; wp_any=1 ;; esac
          case " $PLAN_SAPIS " in *" apache "*) printf '%s\n' '  $SUDO service apache24 restart'; wp_any=1 ;; esac ;;
        launchd)
          wp_b1=${wp_brew%% *}; wp_b1=${wp_b1:-php}
          case " $PLAN_SAPIS " in *" fpm "*|*" cgi "*) printf '%s\n' "  brew services restart $wp_b1"; wp_any=1 ;; esac
          case " $PLAN_SAPIS " in *" apache "*) printf '%s\n' '  $SUDO apachectl restart'; wp_any=1 ;; esac ;;
        sysv)
          case " $PLAN_SAPIS " in *" fpm "*|*" cgi "*)
            for u in $wp_units; do printf '%s\n' "  \$SUDO service $u restart"; wp_any=1; done ;;
          esac
          case " $PLAN_SAPIS " in *" apache "*) printf '%s\n' "  \$SUDO service $wp_web restart"; wp_any=1 ;; esac ;;
      esac
      if [ "$wp_any" = 0 ]; then
        printf '%s\n' "  echo '자동으로 정한 재시작 대상이 없습니다(컨테이너이거나 CLI 전용). 컨테이너는 이미지를 다시 빌드해 재생성하세요: docker compose up -d --force-recreate'"
      fi
      case " $PLAN_SAPIS " in *" cli "*) printf '%s\n' "  echo '장기 실행 CLI(큐 워커, supervisor, Swoole 등)도 직접 재시작하세요.'" ;; esac
      printf '%s\n' 'fi'
      printf '\n'
      # ---- 단계 4: 검증
      cat <<'PF_VERIFY'
# --- 단계 4: 검증 (읽기 전용) -------------------------------------------------
echo '[단계 4] 검증'
ps -eo pid,lstart,args 2>/dev/null | grep -E '[p]hp-fpm|[p]hp-cgi|[l]sphp|[a]pache2|[h]ttpd|[f]rankenphp' || ps auxww | grep -E '[p]hp|[a]pache|[h]ttpd'
echo '프로세스 시작 시각이 업데이트 이후인지, /proc/PID/exe 가 (deleted) 가 아닌지 확인하세요.'
echo '웹 요청 경로로 버전을 확인하세요(관리자 전용 임시 페이지에서 PHP_VERSION 출력 후 즉시 삭제). CLI 결과는 웹 SAPI 와 다를 수 있습니다.'
echo 'php2shell-quickcheck.sh 를 다시 실행해 종료 코드 0 과 재시작 필요 항목 없음을 확인하세요.'

PF_VERIFY
      # ---- 단계 5: 임시 완화/가상 패치/오프라인 (주석 안내만, 자동 적용 없음)
      printf '%s\n' '# --- 단계 5 (선택): 임시 완화 / 가상 패치 / 오프라인 안내 ----------------------'
      printf '%s\n' '# 아래는 설정 파일을 직접 편집해야 하는 안내입니다. 이 스크립트는 파일을 수정하지 않습니다.'
      plan_mitigation | sed 's/^/# /'
      plan_virtual_patch | sed 's/^/# /'
      if [ "$OFFLINE" = 1 ]; then plan_offline | sed 's/^/# /'; fi
      plan_evidence | sed 's/^/# /'
      printf '%s\n' "echo '조치 계획 스크립트가 끝났습니다. 결과를 직접 확인하세요.'"
    } > "$wp_f"
  ) || return 2
  chmod 700 "$wp_f" 2>/dev/null
}

if [ -n "$PLAN_FILE" ]; then
  if write_plan_file "$PLAN_FILE" && [ -s "$PLAN_FILE" ]; then
    if [ "$JSON" = 1 ]; then
      printf '조치 계획 파일 저장: %s\n' "$(clean_value "$PLAN_FILE")" >&2
    else
      say "조치 계획 파일 저장: $PLAN_FILE"
      say "  (사람이 검토하는 파일입니다. 도구는 실행하지 않았습니다. 검토 후 PHP2SHELL_I_REVIEWED=yes sh $PLAN_FILE 로 직접 실행하세요.)"
      say ""
    fi
  else
    printf '오류: 조치 계획 파일을 쓰지 못했습니다: %s\n' "$(clean_value "$PLAN_FILE")" >&2
    exit 2
  fi
fi

if [ "$JSON" = 1 ]; then
  emit_json
else
  render_text
  render_plan
fi

exit "$EXITC"
