"""Generate the Sweep application icon (dev-time only; runtime uses the PNG)."""

import os
import math

from PIL import Image, ImageDraw

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "docs", "icon.png")

SIZE = 256
BG = (22, 24, 29, 255)          # #16181d
ACCENT = (79, 157, 255, 255)    # #4f9dff
TEAL = (87, 201, 138, 255)      # #57c98a


def rounded(draw: ImageDraw.ImageDraw, box, radius, fill):
    draw.rounded_rectangle(box, radius=radius, fill=fill)


def main() -> None:
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    rounded(d, (8, 8, SIZE - 8, SIZE - 8), 56, BG)

    # three "sweep" arcs of decreasing length, like motion lines
    cx, cy = SIZE // 2, SIZE // 2 + 6
    specs = [
        (-200, -20, 96, 10, ACCENT),
        (-185, -45, 74, 9, TEAL),
        (-170, -70, 52, 8, (200, 214, 235, 255)),
    ]
    for start, end, radius, width, color in specs:
        d.arc((cx - radius, cy - radius, cx + radius, cy + radius),
              start=start, end=end, fill=color, width=width)

    # a dot at the arc centre reads as the "broom head"
    dot = 13
    d.ellipse((cx - dot, cy - dot, cx + dot, cy + dot), fill=(230, 236, 246, 255))

    # small spark off the tip
    ang = math.radians(-20)
    r = 96
    tx, ty = cx + r * math.cos(ang), cy + r * math.sin(ang)
    d.ellipse((tx - 7, ty - 7, tx + 7, ty + 7), fill=ACCENT)

    img.save(OUT, "PNG")
    print("wrote", OUT, img.size)

    # a small version for window chrome, same art
    small = img.resize((64, 64), Image.LANCZOS)
    small.save(OUT.replace(".png", "-64.png"), "PNG")


if __name__ == "__main__":
    main()
