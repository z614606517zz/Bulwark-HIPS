# -*- coding: utf-8 -*-
"""生成符合 Bulwark 设计语言的 NSIS 安装包位图素材。

设计令牌来自 cpp/ui/src/design/Theme.h:
  背景 #151413 / 侧栏 #0E1B18 / 文字 #EFEAE2 / 次级 #BDB7AD / 弱化 #9B948A
  品牌青绿 #3DC4A5 / 深青 #138270·#0E6A5C / 黄铜点缀 #C9A063
徽标构图复刻 ShieldEmblem.cpp(径向辉光 + 60 刻度环 + 内盘 + 盾形字标)。
输出:
  installer/brand/wizard-side.bmp  164x314 (欢迎/完成页侧栏)
  installer/brand/header.bmp       150x57  (各页页眉右上)
"""
from PIL import Image, ImageDraw, ImageFont, ImageFilter
import math
import os

# 设计令牌 (RGB)
BG          = (0x15, 0x14, 0x13)
BG_SIDEBAR  = (0x0E, 0x1B, 0x18)
SURFACE     = (0x1D, 0x1C, 0x1A)
TEXT        = (0xEF, 0xEA, 0xE2)
TEXT2       = (0xBD, 0xB7, 0xAD)
MUTED       = (0x9B, 0x94, 0x8A)
ACCENT      = (0x3D, 0xC4, 0xA5)
ACCENT_STR  = (0x13, 0x82, 0x70)
ACCENT_DEEP = (0x0E, 0x6A, 0x5C)
BRASS       = (0xC9, 0xA0, 0x63)

HERE  = os.path.dirname(os.path.abspath(__file__))
OUT   = os.path.join(HERE, 'brand')
ICO   = os.path.join(HERE, 'payload', 'app.ico')
F_BOLD = r'C:\Windows\Fonts\msyhbd.ttc'
F_REG  = r'C:\Windows\Fonts\msyh.ttc'
F_EN   = r'C:\Windows\Fonts\segoeui.ttf'

os.makedirs(OUT, exist_ok=True)


def vgrad(w, h, top, bottom):
    img = Image.new('RGB', (w, h))
    d = ImageDraw.Draw(img)
    for y in range(h):
        t = y / max(1, h - 1)
        c = tuple(int(top[i] * (1 - t) + bottom[i] * t) for i in range(3))
        d.line([(0, y), (w, y)], fill=c)
    return img


def glow(img, cx, cy, r, color, peak=0.30):
    """径向辉光:与 ShieldEmblem 的 QRadialGradient 同构。"""
    from PIL import ImageChops
    lay = Image.new('RGB', img.size, (0, 0, 0))
    d = ImageDraw.Draw(lay)
    steps = 48
    for i in range(steps, 0, -1):
        t = i / steps
        rr = r * t
        a = (1 - t) ** 1.6 * peak
        c = tuple(int(color[k] * a) for k in range(3))
        d.ellipse([cx - rr, cy - rr, cx + rr, cy + rr], fill=c)
    lay = lay.filter(ImageFilter.GaussianBlur(2))
    return ImageChops.add(img, lay)


def tick_ring(img, cx, cy, side, color, alpha=0.26):
    """60 刻度环(每 5 格加长)——ShieldEmblem::paintEvent 的刻度。"""
    lay = Image.new('RGBA', img.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(lay)
    col = color + (int(255 * alpha),)
    outer = side * 0.462
    for k in range(60):
        a = k * (2 * math.pi / 60)
        inner = side * 0.418 if k % 5 == 0 else side * 0.438
        x1, y1 = cx + inner * math.cos(a), cy + inner * math.sin(a)
        x2, y2 = cx + outer * math.cos(a), cy + outer * math.sin(a)
        d.line([x1, y1, x2, y2], fill=col, width=1)
    img.paste(lay, (0, 0), lay)
    return img


def ring(img, cx, cy, r, color, alpha=0.32, width=2):
    lay = Image.new('RGBA', img.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(lay)
    d.ellipse([cx - r, cy - r, cx + r, cy + r], outline=color + (int(255 * alpha),), width=width)
    img.paste(lay, (0, 0), lay)
    return img


def draw_side_panel():
    W, H = 164, 314
    img = vgrad(W, H, BG_SIDEBAR, BG)

    # 徽标构图
    cx, cy = W // 2, 106
    side = 150
    img = glow(img, cx, cy, side * 0.5, ACCENT, peak=0.30)
    img = tick_ring(img, cx, cy, side, ACCENT, alpha=0.24)
    img = ring(img, cx, cy, side * 0.375, ACCENT, alpha=0.30, width=1)

    # 产品图标(青绿圆角底 + 白盾)
    ico = Image.open(ICO).convert('RGBA')
    sz = 104
    ico = ico.resize((sz, sz), Image.LANCZOS)
    img.paste(ico, (cx - sz // 2, cy - sz // 2), ico)

    d = ImageDraw.Draw(img)

    # 主标题
    f_title = ImageFont.truetype(F_BOLD, 23)
    t = '磐垒主动防御'
    w = d.textlength(t, font=f_title)
    d.text(((W - w) / 2, 196), t, font=f_title, fill=TEXT)

    # 英文副题(带字距)
    f_en = ImageFont.truetype(F_EN, 11)
    t2 = 'B U L W A R K   H I P S'
    w2 = d.textlength(t2, font=f_en)
    d.text(((W - w2) / 2, 228), t2, font=f_en, fill=MUTED)

    # 黄铜嵌线(inlay,仅装饰)
    d.line([(W // 2 - 36, 258), (W // 2 + 36, 258)], fill=BRASS, width=1)
    d.ellipse([W // 2 - 2, 256, W // 2 + 2, 260], fill=BRASS)

    # 版本
    f_v = ImageFont.truetype(F_EN, 11)
    t3 = 'v1.0.9'
    w3 = d.textlength(t3, font=f_v)
    d.text(((W - w3) / 2, 272), t3, font=f_v, fill=(0x8C, 0xA8, 0xA0))

    img.save(os.path.join(OUT, 'wizard-side.bmp'))
    print('wizard-side.bmp', img.size)


def draw_header():
    W, H = 150, 57
    img = vgrad(W, H, (0x12, 0x1A, 0x18), BG)
    cx, cy = 34, H // 2

    img = glow(img, cx, cy, 30, ACCENT, peak=0.22)
    img = tick_ring(img, cx, cy, 56, ACCENT, alpha=0.20)

    ico = Image.open(ICO).convert('RGBA')
    sz = 38
    ico = ico.resize((sz, sz), Image.LANCZOS)
    img.paste(ico, (cx - sz // 2, cy - sz // 2), ico)

    d = ImageDraw.Draw(img)
    f = ImageFont.truetype(F_BOLD, 14)
    t = '磐垒主动防御'
    d.text((62, cy - 18), t, font=f, fill=TEXT)
    f2 = ImageFont.truetype(F_EN, 9)
    d.text((63, cy + 4), 'Bulwark HIPS', font=f2, fill=MUTED)

    d.line([(0, H - 1), (W, H - 1)], fill=ACCENT_STR, width=1)

    img.save(os.path.join(OUT, 'header.bmp'))
    print('header.bmp', img.size)


if __name__ == '__main__':
    draw_side_panel()
    draw_header()
    print('done ->', OUT)
