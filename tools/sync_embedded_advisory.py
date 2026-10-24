#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lee Jongyoung
"""data/advisory.json 내용을 php2shell_kr.py 의 내장 권고 데이터 블록에 반영한다.

사용: python3 tools/sync_embedded_advisory.py --force  (기존 소스를 안전하게 교체)
      python3 tools/sync_embedded_advisory.py --check  (어긋나면 종료 코드 1)

내장본은 json.loads(문자열) 형태라 Python 버전과 무관하게 같은 텍스트가 나온다.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL = os.path.join(ROOT, "php2shell_kr.py")
DATA = os.path.join(ROOT, "data", "advisory.json")
BEGIN, END = "# BEGIN EMBEDDED ADVISORY\n", "# END EMBEDDED ADVISORY\n"
sys.path.insert(0, ROOT)
import php2shell_kr as kr
QUOTE3 = "'" * 3


def render():
    data = kr.load_advisory(DATA)
    text = json.dumps(data, ensure_ascii=False, indent=1)
    if QUOTE3 in text or "\\" in text:
        raise SystemExit("advisory.json 에 세 개의 작은따옴표나 역슬래시가 있어 내장할 수 없습니다.")
    return "EMBEDDED_ADVISORY = json.loads(r" + QUOTE3 + text + QUOTE3 + ")\n"


def main(argv):
    raw = kr.read_bytes(TOOL, 2000000)
    if raw is None:
        raise SystemExit("소스를 읽을 수 없습니다.")
    # Windows 체크아웃(autocrlf)은 CRLF 일 수 있다: 비교는 LF 로 정규화하고, 쓸 때 원래 줄바꿈을 유지한다.
    crlf = "\r\n" in raw.decode("utf-8")
    text = raw.decode("utf-8").replace("\r\n", "\n")
    head, rest = text.split(BEGIN, 1)
    _, tail = rest.split(END, 1)
    new = head + BEGIN + render() + END + tail
    if "--check" in argv:
        if new != text:
            print("내장 권고 데이터가 다릅니다: python3 tools/sync_embedded_advisory.py --force", file=sys.stderr)
            return 1
        return 0
    if "--force" not in argv:
        print("기존 소스 교체에는 --force가 필요합니다.", file=sys.stderr)
        return 2
    kr.safe_write(TOOL, new.replace("\n", "\r\n") if crlf else new, force=True, script=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
