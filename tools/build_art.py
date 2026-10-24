#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
"""README 용 픽셀아트(코끼리·서버)를 만든다. 표준 라이브러리만 쓴다.

실행: python3 tools/build_art.py            -> docs/assets/elephant.svg, server.svg, banner.svg

이 그림은 이 저장소를 위해 새로 그린 오리지널이다. 픽셀아트라는 표현 방식과 "코끼리 + 서버"라는 소재의 느낌만 비슷할 뿐,
다른 사이트의 그림·스프라이트 데이터·색상표·코드를 가져다 쓰지 않았다. 코끼리는 타원·사각형 같은 도형을 칸 위에 그린 뒤
테두리와 음영을 규칙으로 계산해 만들고(문자열로 찍은 도트 지도가 아님), 서버는 사각형 조합으로 만든다.
출력은 항상 같다(난수 없음). 결과 SVG 는 외부 참조·스크립트·글꼴이 없다.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(os.path.dirname(HERE), "docs", "assets")

PALETTE = {
    "O": "#1F3B3A",   # 테두리
    "B": "#5DB5A4",   # 몸
    "L": "#9BE0D0",   # 밝은 면
    "D": "#3F8F83",   # 그늘
    "E": "#F0A8A0",   # 귀 안쪽
    "T": "#FFF3D6",   # 상아
    "K": "#14202B",   # 눈
    "S": "#DCE3EA",   # 서버 겉면
    "s": "#AEB9C5",   # 서버 그늘
    "N": "#2B3440",   # 서버 어두운 면
    "n": "#46526A",   # 서버 칸 안쪽
    "G": "#3DDC84",   # 켜진 LED
    "Y": "#FFC857",   # 경고 LED / 방패 테두리
    "H": "#2E7D6B",   # 방패
    "W": "#FFFFFF",
}


class Canvas(object):
    def __init__(self, width, height):
        self.w, self.h = width, height
        self.cells = [[None] * width for _ in range(height)]

    def put(self, x, y, key):
        if 0 <= x < self.w and 0 <= y < self.h:
            self.cells[y][x] = key

    def get(self, x, y):
        return self.cells[y][x] if 0 <= x < self.w and 0 <= y < self.h else None

    def rect(self, x, y, w, h, key):
        for yy in range(y, y + h):
            for xx in range(x, x + w):
                self.put(xx, yy, key)

    def ellipse(self, cx, cy, rx, ry, key):
        """중심(cx, cy), 반지름 rx/ry 인 칸 단위 타원을 채운다(칸 중심 기준)."""
        for yy in range(self.h):
            for xx in range(self.w):
                if ((xx - cx) / float(rx)) ** 2 + ((yy - cy) / float(ry)) ** 2 <= 1.0:
                    self.put(xx, yy, key)

    def mask(self):
        return {(x, y) for y in range(self.h) for x in range(self.w) if self.cells[y][x]}

    def outline(self, region, key):
        """region 의 바깥 경계 칸(상하좌우 중 하나가 region 밖)을 key 로 칠한다."""
        for (x, y) in region:
            if any((x + dx, y + dy) not in region for dx, dy in ((1, 0), (-1, 0), (0, 1), (0, -1))):
                self.put(x, y, key)

    def svg_rects(self, ox=0, oy=0):
        out = []
        for y in range(self.h):
            x = 0
            while x < self.w:
                key = self.cells[y][x]
                if not key:
                    x += 1
                    continue
                x2 = x
                while x2 + 1 < self.w and self.cells[y][x2 + 1] == key:
                    x2 += 1
                out.append('<rect x="%d" y="%d" width="%d" height="1" fill="%s"/>' % (x + ox, y + oy, x2 - x + 1, PALETTE[key]))
                x = x2 + 1
        return "".join(out)


def elephant():
    """왼쪽을 보고 서 있는 코끼리, 34 x 26 칸. 옆구리에 방어용 방패 무늬를 달았다."""
    c = Canvas(34, 26)
    # 실루엣: 몸통, 머리, 다리 네 개, 코, 꼬리
    c.ellipse(21, 11, 11.2, 7.2, "B")
    c.ellipse(9, 10, 6.5, 6.5, "B")
    for x in (12, 17, 23, 29):
        c.rect(x, 15, 4, 10, "B")
    c.rect(2, 12, 4, 10, "B")         # 코(아래로 늘어짐)
    c.rect(1, 20, 3, 3, "B")          # 코끝이 앞으로 말림
    c.rect(32, 8, 2, 6, "B")          # 꼬리
    body = c.mask()
    # 밝은 면: 머리·등 윗부분
    for (x, y) in sorted(body):
        if 4 <= y <= 7 and x <= 27 and (x + y) % 4 != 0:
            c.put(x, y, "L")
    # 그늘: 배 아래, 다리 안쪽, 코 안쪽
    for (x, y) in sorted(body):
        if 14 <= y <= 17 and 11 <= x <= 31:
            c.put(x, y, "D")
    for x in (12, 17, 23, 29):
        c.rect(x + 3, 17, 1, 8, "D")
    c.rect(5, 13, 1, 9, "D")
    # 귀: 어두운 큰 타원 안에 작은 분홍
    c.ellipse(13, 10.5, 4.2, 5.0, "D")
    ear = {(x, y) for y in range(c.h) for x in range(c.w)
           if ((x - 13) / 4.2) ** 2 + ((y - 10.5) / 5.0) ** 2 <= 1.0}
    c.ellipse(13, 10.5, 1.8, 3.0, "E")
    c.outline(ear, "O")
    # 상아와 눈
    c.rect(6, 16, 1, 3, "T")
    c.rect(7, 17, 1, 2, "T")
    c.put(5, 8, "K")
    c.put(5, 9, "K")
    c.put(6, 8, "W")
    # 옆구리 방패 무늬 (방어용 도구라는 뜻)
    c.rect(20, 8, 6, 7, "O")
    c.rect(21, 8, 4, 6, "H")
    c.rect(22, 9, 2, 3, "Y")
    c.put(22, 13, "H")
    c.put(23, 13, "H")
    c.put(21, 8, "H")
    # 발바닥
    for x in (12, 17, 23, 29):
        c.rect(x, 24, 4, 1, "O")
    # 전체 바깥 테두리
    c.outline(c.mask(), "O")
    return c


def server():
    """서버 타워, 18 x 28 칸. 드라이브 칸 세 개, LED, 방패 배지, 발."""
    c = Canvas(18, 28)
    c.rect(0, 0, 18, 26, "N")
    c.rect(1, 1, 16, 24, "S")
    c.rect(1, 1, 16, 1, "W")
    c.rect(16, 1, 1, 24, "s")
    c.rect(1, 24, 16, 1, "s")
    for i in range(3):
        top = 3 + i * 6
        c.rect(2, top, 14, 5, "N")
        c.rect(3, top + 1, 12, 3, "n")
        c.rect(4, top + 2, 5, 1, "N")                # 슬릿
        c.put(11, top + 2, "G" if i != 2 else "Y")   # LED
        c.put(13, top + 2, "G")
    # 하단 방패 배지
    c.rect(6, 21, 6, 3, "N")
    c.rect(7, 21, 4, 2, "H")
    c.put(8, 21, "Y")
    c.put(9, 21, "Y")
    c.rect(2, 26, 3, 2, "N")
    c.rect(13, 26, 3, 2, "N")
    return c


def wrap(width, height, inner, scale, title):
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d" shape-rendering="crispEdges" role="img" aria-label="%s">'
            '<title>%s</title>%s</svg>\n' % (width, height, width * scale, height * scale, title, title, inner))


def build():
    elephant_art, server_art = elephant(), server()
    files = {
        "elephant.svg": wrap(elephant_art.w, elephant_art.h, elephant_art.svg_rects(), 8, "방패를 건 픽셀아트 코끼리"),
        "server.svg": wrap(server_art.w, server_art.h, server_art.svg_rects(), 8, "픽셀아트 서버 타워"),
    }
    gap, ground = 4, 3
    width = elephant_art.w + gap + server_art.w + 6
    height = max(elephant_art.h, server_art.h) + ground
    scene = Canvas(width, height)
    for x in range(width):                                    # 바닥 선
        scene.put(x, height - 2, "O")
        scene.put(x, height - 1, "D" if x % 4 < 2 else "B")
    inner = scene.svg_rects()
    inner += elephant_art.svg_rects(2, height - ground - elephant_art.h + 1)
    inner += server_art.svg_rects(2 + elephant_art.w + gap, height - ground - server_art.h + 1)
    files["banner.svg"] = wrap(width, height, inner, 8, "방패를 건 코끼리와 서버 타워")
    return files


def main():
    os.makedirs(OUT, exist_ok=True)
    for name, text in sorted(build().items()):
        path = os.path.join(OUT, name)
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        print("wrote", os.path.relpath(path, os.path.dirname(HERE)), len(text), "bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
