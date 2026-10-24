#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
"""README 용 픽셀아트(보라색 코끼리와 서버)를 만든다. 표준 라이브러리만 쓴다.

실행: python3 tools/build_art.py
  -> docs/assets/banner.svg   (애니메이션: 코끼리가 코로 서버 전원 버튼을 눌러 불을 하나씩 끄고 잠든다)
     docs/assets/elephant.svg (정적)
     docs/assets/server.svg   (정적, 불이 켜진 상태)

이 그림은 이 저장소를 위해 새로 그린 오리지널이다. 픽셀아트라는 표현 방식과 "코끼리 + 서버"라는 소재의 느낌만 비슷할 뿐,
다른 사이트의 그림·스프라이트 데이터·색상표·코드를 가져다 쓰지 않았다. 코끼리는 타원·사각형 같은 도형을 칸 위에 그린 뒤
테두리와 음영을 규칙으로 계산해 만들고(문자열로 찍은 도트 지도가 아님), 서버는 사각형 조합으로 만든다.
애니메이션은 SVG 안의 CSS(@keyframes, steps)만 쓴다: 스크립트·외부 참조·글꼴이 없고, 움직임 줄이기 설정이면 정지 화면(불 켜진 상태)이 된다.
출력은 항상 같다(난수 없음).
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(os.path.dirname(HERE), "docs", "assets")

PALETTE = {
    "O": "#2B2455",   # 코끼리 테두리
    "B": "#8174C8",   # 몸(보라)
    "L": "#AEA3E8",   # 밝은 면
    "D": "#5C4FA3",   # 그늘
    "E": "#F2A7C3",   # 귀 안쪽
    "T": "#FFF3D6",   # 상아
    "K": "#14102B",   # 눈
    "S": "#DCE3EA",   # 서버 겉면
    "s": "#AEB9C5",   # 서버 그늘
    "N": "#2B3440",   # 서버 어두운 면
    "n": "#46526A",   # 켜진 칸 안쪽
    "o": "#161B24",   # 꺼진 칸 안쪽
    "G": "#3DDC84",   # 켜진 LED
    "Y": "#FFC857",   # 경고 LED / 방패 무늬
    "q": "#3B2A33",   # 꺼진 LED
    "R": "#8A2F3A",   # 대기 상태 전원 버튼
    "H": "#2E7D6B",   # 방패
    "W": "#FFFFFF",
}

CYCLE = "9s"                       # 애니메이션 한 바퀴
# (이름, 구간) = 퍼센트 단위로 켜졌다 꺼지는 시점. 불은 92% 에 한꺼번에 다시 켜진다.
T_REACH, T_PRESS, T_LED3, T_LED2, T_LED1, T_BAYS, T_RETRACT, T_SLEEP, T_WAKE = 12, 18, 22, 26, 30, 34, 40, 42, 92


class Canvas(object):
    def __init__(self, width, height):
        self.w, self.h = width, height
        self.cells = [[None] * width for _ in range(height)]

    def put(self, x, y, key):
        if 0 <= x < self.w and 0 <= y < self.h:
            self.cells[y][x] = key

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


class Shifted(object):
    """도형 좌표에 가로 오프셋을 더해 그리는 얇은 래퍼(코가 몸통 왼쪽으로 뻗을 여백 때문에 쓴다)."""

    def __init__(self, canvas, dx):
        self.c, self.dx = canvas, dx

    def rect(self, x, y, w, h, key):
        self.c.rect(x + self.dx, y, w, h, key)

    def put(self, x, y, key):
        self.c.put(x + self.dx, y, key)

    def ellipse(self, cx, cy, rx, ry, key):
        self.c.ellipse(cx + self.dx, cy, rx, ry, key)


ELEPHANT_W, ELEPHANT_H, MARGIN = 34, 26, 12


def elephant(trunk="down"):
    """왼쪽을 보고 서 있는 보라색 코끼리. trunk: 'down'(코를 내림) 또는 'reach'(코를 왼쪽 위로 뻗음).

    캔버스는 코가 뻗을 왼쪽 여백(MARGIN)을 포함한 (MARGIN + 34) x 26 칸이다.
    """
    c = Canvas(MARGIN + ELEPHANT_W, ELEPHANT_H)
    v = Shifted(c, MARGIN)
    # 실루엣: 몸통, 머리, 다리 네 개, 꼬리
    v.ellipse(21, 11, 11.2, 7.2, "B")
    v.ellipse(9, 10, 6.5, 6.5, "B")
    for x in (12, 17, 23, 29):
        v.rect(x, 15, 4, 10, "B")
    v.rect(32, 8, 2, 6, "B")
    if trunk == "down":
        v.rect(2, 12, 4, 10, "B")         # 코(아래로 늘어짐)
        v.rect(1, 20, 3, 3, "B")          # 코끝이 앞으로 말림
    else:
        for i in range(10):               # 코를 왼쪽 위로 45도 뻗음
            v.rect(4 - i, 10 - i, 3, 2, "B")
    body = c.mask()
    # 밝은 면: 머리·등 윗부분
    for (x, y) in sorted(body):
        if 4 <= y <= 7 and x - MARGIN <= 27 and (x + y) % 4 != 0 and x >= MARGIN + 2:
            c.put(x, y, "L")
    # 그늘: 배 아래, 다리 안쪽
    for (x, y) in sorted(body):
        if 14 <= y <= 17 and MARGIN + 11 <= x <= MARGIN + 31:
            c.put(x, y, "D")
    for x in (12, 17, 23, 29):
        v.rect(x + 3, 17, 1, 8, "D")
    if trunk == "down":
        v.rect(5, 13, 1, 9, "D")
    # 귀: 어두운 큰 타원 안에 작은 분홍
    v.ellipse(13, 10.5, 4.2, 5.0, "D")
    ear = {(x, y) for y in range(c.h) for x in range(c.w)
           if ((x - MARGIN - 13) / 4.2) ** 2 + ((y - 10.5) / 5.0) ** 2 <= 1.0}
    v.ellipse(13, 10.5, 1.8, 3.0, "E")
    c.outline(ear, "O")
    # 상아
    if trunk == "down":
        v.rect(6, 16, 1, 3, "T")
        v.rect(7, 17, 1, 2, "T")
    else:
        v.rect(4, 14, 1, 3, "T")
    # 눈
    v.put(5, 8, "K")
    v.put(5, 9, "K")
    v.put(6, 8, "W")
    # 옆구리 방패 무늬 (방어용 도구라는 뜻)
    v.rect(20, 8, 6, 7, "O")
    v.rect(21, 8, 4, 6, "H")
    v.rect(22, 9, 2, 3, "Y")
    v.put(22, 13, "H")
    v.put(23, 13, "H")
    v.put(21, 8, "H")
    # 발바닥
    for x in (12, 17, 23, 29):
        v.rect(x, 24, 4, 1, "O")
    # 전체 바깥 테두리
    c.outline(c.mask(), "O")
    return c


SERVER_W, SERVER_H = 18, 28
BAY_TOPS = (7, 12, 17)


def server_base():
    """서버 타워의 꺼진 상태(항상 깔린다). 18 x 28 칸."""
    c = Canvas(SERVER_W, SERVER_H)
    c.rect(0, 0, 18, 26, "N")
    c.rect(1, 1, 16, 24, "S")
    c.rect(1, 1, 16, 1, "W")
    c.rect(16, 1, 1, 24, "s")
    c.rect(1, 24, 16, 1, "s")
    c.rect(2, 2, 14, 4, "N")                 # 위쪽 전원 패널
    c.rect(13, 3, 2, 2, "R")                 # 전원 버튼(대기 상태)
    for top in BAY_TOPS:
        c.rect(2, top, 14, 4, "N")
        c.rect(3, top + 1, 12, 2, "o")       # 꺼진 칸
        c.put(11, top + 1, "q")              # 꺼진 LED
        c.put(13, top + 1, "q")
    c.rect(6, 21, 6, 3, "N")                 # 하단 방패 배지
    c.rect(7, 21, 4, 2, "H")
    c.rect(8, 21, 2, 1, "Y")
    c.rect(2, 26, 3, 2, "N")                 # 발
    c.rect(13, 26, 3, 2, "N")
    return c


def overlay(cells):
    c = Canvas(SERVER_W, SERVER_H)
    for (x, y, key) in cells:
        c.put(x, y, key)
    return c


def server_overlays():
    """불이 켜진 상태를 이루는 조각들. 끄는 순서대로 따로 둔다: 전원 버튼, LED 3개, 칸 안쪽."""
    button = overlay([(13, 3, "G"), (14, 3, "G"), (13, 4, "G"), (14, 4, "G")])
    leds = []
    for index, top in enumerate(BAY_TOPS):
        leds.append(overlay([(11, top + 1, "Y" if index == 2 else "G"), (13, top + 1, "G")]))
    bays = []
    for top in BAY_TOPS:
        cells = [(x, top + 1 + dy, "n") for x in range(3, 15) for dy in (0, 1)]
        cells += [(x, top + 1, "N") for x in range(4, 9)]            # 슬릿
        bays.append(overlay(cells))
    return button, leds, bays


def glyph_z(size):
    """작은 'Z' 글자(잠든 표시). 위·아래 가로선과 그 사이의 대각선, size 는 4 또는 5 칸."""
    c = Canvas(size, size)
    c.rect(0, 0, size, 1, "L")
    c.rect(0, size - 1, size, 1, "L")
    for i in range(1, size - 1):
        c.put(size - 1 - i, i, "L")
    return c


def wrap(width, height, inner, scale, title, style=""):
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d" shape-rendering="crispEdges" role="img" aria-label="%s">'
            '<title>%s</title>%s%s</svg>\n' % (width, height, width * scale, height * scale, title, title, style, inner))


def css():
    """애니메이션 정의. steps(1,end) 로 구간마다 값이 뚝 바뀌는 픽셀 느낌의 켜고 끄기를 만든다."""
    def keyframes(name, points):
        body = "".join("%d%%{opacity:%d}" % (pct, value) for pct, value in points)
        return "@keyframes %s{%s}" % (name, body)

    rules = [
        ".a{animation-duration:%s;animation-iteration-count:infinite;animation-timing-function:steps(1,end)}" % CYCLE,
        ".down{animation-name:kDown}.reach{animation-name:kReach}.btn{animation-name:kBtn}.led3{animation-name:kLed3}.led2{animation-name:kLed2}",
        ".led1{animation-name:kLed1}.bays{animation-name:kBays}.sleep{animation-name:kSleep}.z1{animation-name:kZ1}.z2{animation-name:kZ2}",
        keyframes("kDown", [(0, 1), (T_REACH, 0), (T_RETRACT, 1), (100, 1)]),
        keyframes("kReach", [(0, 0), (T_REACH, 1), (T_RETRACT, 0), (100, 0)]),
        keyframes("kBtn", [(0, 1), (T_PRESS, 0), (T_WAKE, 1), (100, 1)]),
        keyframes("kLed3", [(0, 1), (T_LED3, 0), (T_WAKE, 1), (100, 1)]),
        keyframes("kLed2", [(0, 1), (T_LED2, 0), (T_WAKE, 1), (100, 1)]),
        keyframes("kLed1", [(0, 1), (T_LED1, 0), (T_WAKE, 1), (100, 1)]),
        keyframes("kBays", [(0, 1), (T_BAYS, 0), (T_WAKE, 1), (100, 1)]),
        keyframes("kSleep", [(0, 0), (T_SLEEP, 1), (T_WAKE, 0), (100, 0)]),
        keyframes("kZ1", [(0, 0), (T_SLEEP, 1), (62, 0), (72, 1), (82, 0), (T_WAKE, 0), (100, 0)]),
        keyframes("kZ2", [(0, 0), (T_SLEEP + 6, 1), (67, 0), (77, 1), (87, 0), (T_WAKE, 0), (100, 0)]),
        "@media (prefers-reduced-motion:reduce){.a{animation:none}}",
    ]
    return "<style>%s</style>" % "".join(rules)


def group(inner, cls=None, hidden=False):
    attrs = ""
    if cls:
        attrs += ' class="a %s"' % cls
    if hidden:
        attrs += ' opacity="0"'
    return "<g%s>%s</g>" % (attrs, inner)


def scene(animated=True):
    """서버(왼쪽)와 코끼리(오른쪽, 서버를 향함). 코끼리가 코로 전원 버튼을 눌러 불을 끄고 잠든다."""
    pad_top, ground = 5, 3
    server_x = 1
    # 코를 뻗으면 끝이 서버 전원 버튼(서버 안 x=13..14, y=3..4) 오른쪽 바로 옆에 닿도록 코끼리 위치를 정한다.
    tip_local_x = MARGIN + 4 - 9               # reach 포즈에서 코끝의 왼쪽 x (캔버스 기준)
    elephant_x = server_x + 15 - tip_local_x
    elephant_y = pad_top + SERVER_H - ELEPHANT_H
    server_y = pad_top
    width = elephant_x + MARGIN + ELEPHANT_W + 1
    height = pad_top + SERVER_H + ground

    floor = Canvas(width, height)
    for x in range(width):
        floor.put(x, height - 2, "O")
        floor.put(x, height - 1, "D" if x % 4 < 2 else "B")

    base = server_base()
    button, leds, bays = server_overlays()
    down, reach = elephant("down"), elephant("reach")

    parts = [floor.svg_rects(), base.svg_rects(server_x, server_y)]
    sx = (server_x, server_y)
    # 칸 안쪽은 한 그룹으로 묶어 같은 시점에 꺼지게 한다
    parts.append(group("".join(bays[i].svg_rects(*sx) for i in range(3)), "bays" if animated else None))
    for index, name in enumerate(("led1", "led2", "led3")):
        parts.append(group(leds[index].svg_rects(*sx), name if animated else None))
    parts.append(group(button.svg_rects(*sx), "btn" if animated else None))

    ex, ey = elephant_x, elephant_y
    parts.append(group(down.svg_rects(ex, ey), "down" if animated else None))
    if animated:
        parts.append(group(reach.svg_rects(ex, ey), "reach", hidden=True))
        # 잠든 눈: 눈 칸을 몸 색으로 덮고 감은 눈(가로선)을 그린다
        eye = Canvas(down.w, down.h)
        for (x, y) in ((5, 8), (5, 9), (6, 8)):
            eye.put(MARGIN + x, y, "B")
        eye.put(MARGIN + 5, 9, "K")
        eye.put(MARGIN + 6, 9, "K")
        parts.append(group(eye.svg_rects(ex, ey), "sleep", hidden=True))
        z1, z2 = glyph_z(4), glyph_z(5)
        zx = ex + MARGIN + 3
        parts.append(group(z1.svg_rects(zx, ey - 2), "z1", hidden=True))
        parts.append(group(z2.svg_rects(zx - 5, ey - 5), "z2", hidden=True))
    title = "보라색 코끼리가 코로 서버 전원 버튼을 눌러 불을 끄고 잠드는 픽셀아트"
    return wrap(width, height, "".join(parts), 8, title, css() if animated else "")


def static_svgs():
    elephant_art = elephant("down")
    server_art = server_base()
    button, leds, bays = server_overlays()
    for layer in bays + leds + [button]:
        for y in range(layer.h):
            for x in range(layer.w):
                if layer.cells[y][x]:
                    server_art.cells[y][x] = layer.cells[y][x]
    crop = Canvas(ELEPHANT_W, ELEPHANT_H)
    for y in range(ELEPHANT_H):
        for x in range(ELEPHANT_W):
            crop.cells[y][x] = elephant_art.cells[y][x + MARGIN]
    return {
        "elephant.svg": wrap(crop.w, crop.h, crop.svg_rects(), 8, "방패 무늬를 단 보라색 픽셀아트 코끼리"),
        "server.svg": wrap(server_art.w, server_art.h, server_art.svg_rects(), 8, "불이 켜진 픽셀아트 서버 타워"),
    }


def build():
    files = static_svgs()
    files["banner.svg"] = scene(animated=True)
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
