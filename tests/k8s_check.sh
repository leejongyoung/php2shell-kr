#!/bin/sh
# Kubernetes 에서 문서의 절차가 실제로 동작하는지 확인한다 (docs/runbook.ko.md, docs/response-options.ko.md).
#   1) 취약 이미지(php:8.4.26-fpm)를 Deployment 로 띄운다
#   2) `kubectl get pods -A -o jsonpath=...` 로 이미지 목록을 뽑으면 그 이미지가 보인다
#   3) 파드 안에서 php2shell-quickcheck.sh 가 vulnerable(종료 코드 1)로 판정한다
#   4) `kubectl set image` 로 수정 이미지(8.4.27)로 바꾸고 `kubectl rollout status` 가 성공한다
#   5) 새 파드에서 같은 점검이 fixed(종료 코드 0)로 판정한다
# 사용: sh tests/k8s_check.sh   (현재 kubectl 컨텍스트의 클러스터를 쓴다. 임시 네임스페이스를 만들고 끝나면 지운다)
set -u
REGISTRY="${REGISTRY:-mirror.gcr.io/library}"
NS="p2s-k8s-$$"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
FAIL=0
trap 'kubectl delete namespace "$NS" --wait=false >/dev/null 2>&1; rm -rf "$WORK"' EXIT
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=1; }

kubectl create namespace "$NS" >/dev/null || { echo "클러스터에 접속할 수 없음"; exit 2; }
kubectl -n "$NS" create deployment web --image="$REGISTRY/php:8.4.26-fpm" >/dev/null
kubectl -n "$NS" rollout status deployment/web --timeout=240s >/dev/null || { fail "초기 롤아웃"; exit 1; }

# runbook.ko.md 에 적는 이미지 목록 명령 (이미지 이름만 보고 판단하지 않도록 파드별로 나열)
LIST="$(kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{"\t"}{range .spec.containers[*]}{.image}{" "}{end}{"\n"}{end}')"
if echo "$LIST" | grep -q "^$NS/.*php:8.4.26-fpm"; then pass "jsonpath 이미지 목록에 취약 이미지가 보임"; else fail "jsonpath 목록에 이미지가 없음"; echo "$LIST"; fi

check_pod() { # $1=기대 verdict $2=기대 종료 코드
  pod="$(kubectl -n "$NS" get pods -l app=web --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')"
  kubectl -n "$NS" cp "$ROOT/quickcheck/php2shell-quickcheck.sh" "$pod:/tmp/q.sh" >/dev/null 2>&1
  kubectl -n "$NS" exec "$pod" -- sh /tmp/q.sh --json >"$WORK/out.json" 2>"$WORK/err.txt"
  code=$?
  if [ "$code" -eq "$2" ] && grep -q "\"path\":\"/usr/local/sbin/php-fpm\",\"version\":\"[0-9.]*\",\"class\":\"[a-z_]*\",\"verdict\":\"$1\"" "$WORK/out.json"; then
    pass "파드 $pod: php-fpm verdict=$1, 종료 코드 $code"
  else
    fail "파드 $pod: 기대 verdict=$1 종료 코드 $2, 실제 종료 코드 $code"; head -c 1500 "$WORK/out.json"; cat "$WORK/err.txt"
  fi
}

check_pod vulnerable 1

OLDPOD="$(kubectl -n "$NS" get pods -l app=web -o jsonpath='{.items[0].metadata.name}')"
kubectl -n "$NS" set image deployment/web php="$REGISTRY/php:8.4.27-fpm" >/dev/null
if kubectl -n "$NS" rollout status deployment/web --timeout=240s >/dev/null; then pass "kubectl rollout status 성공"; else fail "롤아웃 실패"; fi
# 옛 파드가 종료될 때까지 기다린 뒤 새 파드를 점검
kubectl -n "$NS" wait --for=delete "pod/$OLDPOD" --timeout=120s >/dev/null 2>&1
NEWIMG="$(kubectl -n "$NS" get pods -l app=web --field-selector=status.phase=Running -o jsonpath='{.items[*].spec.containers[0].image}')"
case "$NEWIMG" in *8.4.26*) fail "롤아웃 후에도 옛 이미지 파드가 남음: $NEWIMG" ;; *8.4.27*) pass "실행 중 파드는 모두 8.4.27 이미지" ;; *) fail "이미지 확인 실패: $NEWIMG" ;; esac
check_pod fixed 0
exit "$FAIL"
