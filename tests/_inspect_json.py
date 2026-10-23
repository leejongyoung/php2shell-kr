#!/usr/bin/env python3
"""tests/*_check.sh 가 점검 도구의 JSON(Python 판·sh 판 공통)을 검사할 때 쓰는 도우미.

사용: <도구> --json | python3 tests/_inspect_json.py [--path REGEX] [--version V] [--sapi S] [--running] [--needs-restart] [--any-needs-restart]
조건을 모두 만족하는 installation 이 있으면 종료 코드 0, 없으면 1 (그리고 요약을 출력한다).
--no-needs-restart 는 needs_restart 가 true 인 설치가 하나도 없을 때 0.
"""
import argparse
import json
import re
import sys

parser = argparse.ArgumentParser()
parser.add_argument("--path")
parser.add_argument("--version")
parser.add_argument("--sapi")
parser.add_argument("--running", action="store_true")
parser.add_argument("--needs-restart", action="store_true")
parser.add_argument("--no-needs-restart", action="store_true")
args = parser.parse_args()

text = sys.stdin.read()
try:
    data = json.loads(text)
except ValueError as error:
    print("JSON 해석 실패: %s\n%s" % (error, text[:800]))
    sys.exit(1)
items = data.get("installations", [])


def summary():
    return "\n".join("  %s version=%s sapi=%s running=%s pids=%s needs_restart=%s verdict=%s" % (
        i.get("path"), i.get("version"), i.get("sapi"), i.get("running"), i.get("pids"), i.get("needs_restart"), i.get("verdict"))
        for i in items) + "\n  process_visibility=%s exit_code=%s" % (data.get("process_visibility"), data.get("exit_code"))


if args.no_needs_restart:
    ok = not any(i.get("needs_restart") for i in items)
else:
    ok = any(
        (not args.path or re.search(args.path, i.get("path") or ""))
        and (not args.version or i.get("version") == args.version)
        and (not args.sapi or i.get("sapi") == args.sapi)
        and (not args.running or i.get("running") is True)
        and (not args.needs_restart or i.get("needs_restart") is True)
        for i in items)
if not ok:
    print(summary())
sys.exit(0 if ok else 1)
