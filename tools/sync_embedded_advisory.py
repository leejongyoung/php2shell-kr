#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lee Jongyoung
"""data/advisory.json 내용을 php2shell_triage.py 의 내장 권고 데이터 블록에 반영한다.

사용: python3 tools/sync_embedded_advisory.py          (파일을 갱신)
      python3 tools/sync_embedded_advisory.py --check  (어긋나면 종료 코드 1)

내장본은 json.loads(문자열) 형태라 Python 버전과 무관하게 같은 텍스트가 나온다.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL = os.path.join(ROOT, "php2shell_triage.py")
DATA = os.path.join(ROOT, "data", "advisory.json")
BEGIN, END = "# BEGIN EMBEDDED ADVISORY\n", "# END EMBEDDED ADVISORY\n"
QUOTE3 = "'" * 3


def render():
    with open(DATA, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    text = json.dumps(data, ensure_ascii=False, indent=1)
    if QUOTE3 in text or "\\" in text:
        raise SystemExit("advisory.json 에 세 개의 작은따옴표나 역슬래시가 있어 내장할 수 없습니다.")
    return "EMBEDDED_ADVISORY = json.loads(r" + QUOTE3 + text + QUOTE3 + ")\n"


def main(argv):
    with open(TOOL, "r", encoding="utf-8") as handle:
        text = handle.read()
    head, rest = text.split(BEGIN, 1)
    _, tail = rest.split(END, 1)
    new = head + BEGIN + render() + END + tail
    if "--check" in argv:
        if new != text:
            print("내장 권고 데이터가 data/advisory.json 과 다릅니다: python3 tools/sync_embedded_advisory.py", file=sys.stderr)
            return 1
        return 0
    with open(TOOL, "w", encoding="utf-8") as handle:
        handle.write(new)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
