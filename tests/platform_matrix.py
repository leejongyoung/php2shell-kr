#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Docker 기반 플랫폼 점검: 실제 PHP 이미지와 배포판 패키지를 컨테이너에서 띄워 점검 도구를 돌린다.

  python3 tests/platform_matrix.py                 # 전체
  python3 tests/platform_matrix.py --only php-8.4.26-fpm --only needs-restart
  python3 tests/platform_matrix.py --list
  python3 tests/platform_matrix.py --registry docker.io/library   # 기본은 mirror.gcr.io/library (Docker Hub 429 회피)

각 시나리오는 컨테이너 안에서 `php2shell_kr.py`(Python 전체판)와 `quickcheck/php2shell-quickcheck.sh`(sh 간이판)를
모두 실행해 판정이 기대와 같고 두 구현이 서로 일치하는지 본다. 저장소는 읽기 전용으로 마운트하며 호스트는 바꾸지 않는다.
익스플로잇은 쓰지 않는다: 점검은 버전·프로세스·설정만 읽는다.
기본 실행 정책(auto)은 root 소유 /usr/local/bin/php만 실행하며 --exec-mode never/all 로 새 플래그도 확인할 수 있다.
"""
import argparse
import json
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import php2shell_kr as kr  # noqa: E402

APT_PY = "apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq python3 >/dev/null 2>&1"
APK_PY = "apk add --no-cache python3 >/dev/null 2>&1"
DNF_PY = "(command -v python3 >/dev/null || dnf install -y -q python3 >/dev/null 2>&1)"

# expect: 판정 기대 {바이너리 이름: verdict}, exit: 종료 코드, running: 실행 중이어야 하는 이름
SCENARIOS = [
    {"name": "php-8.4.26-fpm", "image": "php:8.4.26-fpm", "setup": APT_PY, "start": "php-fpm -D",
     "expect": {"verdicts": {"php-fpm": "vulnerable", "php": "vulnerable"}, "exit": 1, "running": ["php-fpm"]}},
    {"name": "php-8.4.27-fpm", "image": "php:8.4.27-fpm", "setup": APT_PY, "start": "php-fpm -D",
     "expect": {"verdicts": {"php-fpm": "fixed", "php": "fixed"}, "exit": 0, "running": ["php-fpm"]}},
    {"name": "php-8.4.26-apache", "image": "php:8.4.26-apache", "setup": APT_PY, "start": "apache2ctl start >/dev/null 2>&1",
     "expect": {"verdicts": {"libphp.so": "vulnerable", "php": "vulnerable"}, "exit": 1, "running": ["libphp.so"]}},
    {"name": "php-8.4.27-apache", "image": "php:8.4.27-apache", "setup": APT_PY, "start": "apache2ctl start >/dev/null 2>&1",
     "expect": {"verdicts": {"libphp.so": "fixed", "php": "fixed"}, "exit": 0, "running": ["libphp.so"]}},
    {"name": "php-8.1-fpm-eol", "image": "php:8.1-fpm", "setup": APT_PY, "start": "php-fpm -D",
     "expect": {"verdicts": {"php-fpm": "vulnerable", "php": "vulnerable"}, "exit": 1, "running": ["php-fpm"]}},
    {"name": "php-8.4.26-fpm-alpine", "image": "php:8.4.26-fpm-alpine", "setup": APK_PY, "start": "php-fpm -D",
     "expect": {"verdicts": {"php-fpm": "vulnerable", "php": "vulnerable"}, "exit": 1, "running": ["php-fpm"]}},
    # 패치 후 재시작 안 한 서버: 새 바이너리로 교체하면 실행 중인 프로세스는 옛 코드를 계속 쓴다.
    {"name": "needs-restart", "image": "php:8.4.27-fpm", "setup": APT_PY,
     "start": "php-fpm -D; sleep 1; cp /usr/local/sbin/php-fpm /tmp/php-fpm.new && mv -f /tmp/php-fpm.new /usr/local/sbin/php-fpm",
     "expect": {"verdicts": {"php-fpm": "fixed"}, "exit": 1, "running": ["php-fpm"], "needs_restart": ["php-fpm"]}},
    # 배포판 패키지: 실제 저장소의 현재 상태를 보여 준다(기대 판정 고정 없음, 불변식만 검사).
    {"name": "debian12-php8.2-fpm", "image": "debian:12-slim", "info": True,
     "setup": "apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq python3 php8.2-fpm >/dev/null 2>&1",
     "start": "mkdir -p /run/php; php-fpm8.2 -D"},
    {"name": "ubuntu24.04-php8.3-fpm", "image": "ubuntu:24.04", "info": True,
     "setup": "apt-get update -qq >/dev/null 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 php8.3-fpm >/dev/null 2>&1",
     "start": "mkdir -p /run/php; php-fpm8.3 -D"},
    {"name": "rocky9-php-fpm", "image": "rockylinux:9", "info": True,
     "setup": "dnf install -y -q python3 php-fpm >/dev/null 2>&1", "start": "mkdir -p /run/php-fpm; php-fpm -D"},
    {"name": "alpine3.20-php83-fpm", "image": "alpine:3.20", "info": True,
     "setup": "apk add --no-cache python3 php83-fpm >/dev/null 2>&1", "start": "php-fpm83 -D"},
]


def docker(args, timeout):
    return subprocess.run(["docker"] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=timeout)


def run_scenario(scenario, registry, exec_mode="auto"):
    image = "%s/%s" % (registry, scenario["image"]) if registry else scenario["image"]
    flags = {"auto": "", "never": "--no-exec", "all": "--exec"}[exec_mode]
    script = (
        "set -u; %s; %s; sleep 2; "
        "echo ==PY==; python3 /repo/php2shell_kr.py --json --no-response %s; echo ==PYRC=$?; "
        "echo ==SH==; sh /repo/quickcheck/php2shell-quickcheck.sh --json %s; echo ==SHRC=$?"
    ) % (scenario["setup"], scenario["start"], flags, flags)
    started = time.time()
    try:
        proc = docker(["run", "--rm", "-v", "%s:/repo:ro" % ROOT, image, "sh", "-c", script], timeout=900)
    except subprocess.TimeoutExpired:
        return {"name": scenario["name"], "status": "ERROR", "detail": "timeout"}
    out = proc.stdout
    if "==PY==" not in out:
        return {"name": scenario["name"], "status": "ERROR", "detail": (proc.stderr or out)[-300:].strip()}

    def section(begin, end):
        text = out.split(begin, 1)[1].split(end, 1)[0]
        return text.strip()

    try:
        py = json.loads(section("==PY==", "==PYRC="))
        py_rc = int(out.split("==PYRC=", 1)[1].split()[0])
        sh = json.loads(section("==SH==", "==SHRC="))
        sh_rc = int(out.split("==SHRC=", 1)[1].split()[0])
    except (ValueError, IndexError) as exc:
        return {"name": scenario["name"], "status": "ERROR", "detail": "출력 해석 실패: %s" % exc}
    problems = []
    expected_policy = {"auto": "trusted-only", "never": "never", "all": "all"}[exec_mode]
    if py.get("exec_policy") != expected_policy:
        problems.append("실행 정책 불일치: %s" % py.get("exec_policy"))
    if exec_mode == "auto" and scenario["image"].startswith("php:"):
        cli = [i for i in py["installations"] if i["path"] == "/usr/local/bin/php"]
        if not cli or not all(i.get("executed") for i in cli):
            problems.append("root 소유 공식 이미지 PHP CLI가 기본 정책에서 실행되지 않음")
    if exec_mode == "never" and any(i.get("executed") for i in py["installations"]):
        problems.append("--no-exec 에서 바이너리 실행됨")
    rows = [(os.path.basename(i["path"]), i["version"], i["verdict"], i["class"], i["vendor_patch"], i["running"], i["needs_restart"])
            for i in py["installations"]]
    advisory = kr.load_advisory()
    for item in py["installations"]:  # 불변식: 판정은 분류와 벤더 근거에서 정해진다
        if item["verdict"] != kr.verdict_for(item["class"], item["vendor_patch"]):
            problems.append("판정 불변식 위반: %s" % item["path"])
        if item["version"] and item["class"] != kr.classify(item["version"], advisory):
            problems.append("분류 불일치: %s" % item["path"])
    py_set = sorted((os.path.basename(i["path"]), i["version"], i["class"]) for i in py["installations"])
    sh_set = sorted((os.path.basename(i["path"]), i["version"], i["class"]) for i in sh["installations"])
    if py_set != sh_set:
        problems.append("Python 과 sh 결과가 다름: py=%s sh=%s" % (py_set, sh_set))
    if py_rc != sh_rc:
        problems.append("종료 코드가 다름: py=%s sh=%s" % (py_rc, sh_rc))
    expect = scenario.get("expect")
    if expect:
        by_name = {}
        for item in py["installations"]:
            by_name.setdefault(os.path.basename(item["path"]), []).append(item)
        for name, verdict in expect["verdicts"].items():
            hits = by_name.get(name, [])
            if not hits:
                problems.append("%s 를 찾지 못함 (찾은 것: %s)" % (name, sorted(by_name)))
            elif any(h["verdict"] != verdict for h in hits):
                problems.append("%s 판정 %s != 기대 %s" % (name, [h["verdict"] for h in hits], verdict))
        for name in expect.get("running", []):
            if not any(h["running"] for h in by_name.get(name, [])):
                problems.append("%s 가 실행 중으로 탐지되지 않음" % name)
        for name in expect.get("needs_restart", []):
            if not any(h["needs_restart"] for h in by_name.get(name, [])):
                problems.append("%s 의 재시작 필요가 탐지되지 않음" % name)
        if py_rc != expect["exit"]:
            problems.append("종료 코드 %s != 기대 %s" % (py_rc, expect["exit"]))
    elif not py["installations"]:
        problems.append("설치된 PHP 를 찾지 못함 (패키지 설치 실패일 수 있음)")
    return {"name": scenario["name"], "status": "FAIL" if problems else ("INFO" if scenario.get("info") else "PASS"),
            "detail": "; ".join(problems), "rows": rows, "exit": py_rc, "seconds": int(time.time() - started)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--only", action="append", help="이름이 일치하는 시나리오만 (반복 가능)")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--registry", default="mirror.gcr.io/library", help="이미지 레지스트리 접두사 (비우면 기본 docker.io)")
    parser.add_argument("--json", help="결과를 JSON 파일로 저장")
    parser.add_argument("--exec-mode", choices=("auto", "never", "all"), default="auto")
    parser.add_argument("--force", action="store_true", help="기존 JSON 결과 교체 허용")
    args = parser.parse_args(argv)
    if args.list:
        for scenario in SCENARIOS:
            print("%-26s %s%s" % (scenario["name"], scenario["image"], "  (info)" if scenario.get("info") else ""))
        return 0
    if subprocess.call(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
        print("Docker 데몬에 연결할 수 없습니다 (OrbStack/Docker Desktop 을 시작하세요).", file=sys.stderr)
        return 2
    selected = [s for s in SCENARIOS if not args.only or s["name"] in args.only]
    results = []
    for scenario in selected:
        print("... %s (%s)" % (scenario["name"], scenario["image"]), flush=True)
        result = run_scenario(scenario, args.registry, args.exec_mode)
        results.append(result)
        print("%-5s %s %s" % (result["status"], result["name"], result.get("detail", "")), flush=True)
        for row in result.get("rows", []):
            print("        %-14s %-22s %-14s class=%s vendor=%s running=%s restart=%s" % row, flush=True)
    if args.json:
        kr.safe_write(args.json, json.dumps(results, ensure_ascii=False, indent=2) + "\n", force=args.force)
    failed = [r for r in results if r["status"] in ("FAIL", "ERROR")]
    print("\n통과 %d / 정보 %d / 실패 %d" % (sum(r["status"] == "PASS" for r in results), sum(r["status"] == "INFO" for r in results), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
