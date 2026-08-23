#!/usr/bin/env python3
"""Render a terminal-style demo GIF of the skillvet watcher quarantining a skill."""
from PIL import Image, ImageDraw, ImageFont

W, H = 920, 440
BG = (13, 17, 23)          # github dark
BAR = (22, 27, 34)
FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONTB = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
f = ImageFont.truetype(FONT, 20)
fb = ImageFont.truetype(FONTB, 20)
ft = ImageFont.truetype(FONT, 15)

GREEN = (63, 185, 80)
WHITE = (230, 237, 243)
GRAY = (139, 148, 158)
RED = (248, 81, 73)
ORANGE = (255, 123, 114)
BLUE = (88, 166, 255)

# each line = list of (text, color, bold)
LINES = [
    [("$ ", GREEN, True), ("skillvet watch", WHITE, False)],
    [("skillvet watcher started (event-based). quarantine=on", GRAY, False)],
    [("  watching ~/.claude/skills", GRAY, False)],
    [("", GRAY, False)],
    [("# you install a skill from GitHub...", GRAY, False)],
    [("$ ", GREEN, True), ("cp -r pdf-helper ~/.claude/skills/", WHITE, False)],
    [("", GRAY, False)],
    [("[QUARANTINED] ", RED, True), ("pdf-helper  5 critical / 6 high", WHITE, False)],
    [("  moved to .quarantine/  ", ORANGE, False), ("Claude will not load it", GRAY, False)],
    [("", GRAY, False)],
    [("$ ", GREEN, True), ("skillvet approve pdf-helper", BLUE, False), ("   # or: reject", GRAY, False)],
]

PAD_X, TOP = 24, 52
LH = 31


def render(n, cursor):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    # title bar
    d.rectangle([0, 0, W, 36], fill=BAR)
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([18 + i * 22, 12, 30 + i * 22, 24], fill=c)
    d.text((W // 2 - 60, 10), "skillvet watcher", font=ft, fill=GRAY)
    # lines
    for li in range(n):
        x = PAD_X
        y = TOP + li * LH
        for (txt, col, bold) in LINES[li]:
            d.text((x, y), txt, font=(fb if bold else f), fill=col)
            x += int(d.textlength(txt, font=(fb if bold else f)))
        if li == n - 1 and cursor and any(t[0] for t in LINES[li]):
            d.rectangle([x + 2, y + 3, x + 13, y + 24], fill=WHITE)
    return img


frames, durations = [], []
# reveal line by line
plan = [(1, 500), (2, 380), (3, 380), (4, 150), (5, 600), (6, 620),
        (7, 200), (7, 650), (8, 950), (9, 620), (10, 160), (11, 800)]
for (n, dur) in plan:
    frames.append(render(n, cursor=True)); durations.append(dur)
# blink cursor + hold at the end
for _ in range(2):
    frames.append(render(11, cursor=False)); durations.append(450)
    frames.append(render(11, cursor=True)); durations.append(450)
frames.append(render(11, cursor=True)); durations.append(2600)

frames[0].save("skillvet-demo.gif", save_all=True, append_images=frames[1:],
                duration=durations, loop=0, optimize=True)
print("wrote skillvet-demo.gif", f"{len(frames)} frames")
