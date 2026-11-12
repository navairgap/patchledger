"""Generate the PatchLedger pixel-wordmark banner SVGs (Shannon-style).

Clean chunky version: solid pixel blocks on a seamless background (no
border, no baked-in text — subtitles are README text), with a solid
dark-amber drop layer offset behind the letters for the 3D pixel effect.
"""

from pathlib import Path

GLYPHS = {
    "P": ["11110", "10001", "10001", "11110", "10000", "10000", "10000"],
    "A": ["01110", "10001", "10001", "11111", "10001", "10001", "10001"],
    "T": ["11111", "00100", "00100", "00100", "00100", "00100", "00100"],
    "C": ["01111", "10000", "10000", "10000", "10000", "10000", "01111"],
    "H": ["10001", "10001", "10001", "11111", "10001", "10001", "10001"],
    "L": ["10000", "10000", "10000", "10000", "10000", "10000", "11111"],
    "E": ["11111", "10000", "10000", "11110", "10000", "10000", "11111"],
    "D": ["11110", "10001", "10001", "10001", "10001", "10001", "11110"],
    "G": ["01111", "10000", "10000", "10111", "10001", "10001", "01110"],
    "R": ["11110", "10001", "10001", "11110", "10100", "10010", "10001"],
}

WORD = "PATCHLEDGER"
BLOCK = 16
GAP = 1
PITCH = BLOCK + GAP
COLS = sum(len(GLYPHS[ch][0]) for ch in WORD) + (len(WORD) - 1)
ROWS = 7
ART_W = COLS * PITCH - GAP
ART_H = ROWS * PITCH - GAP
MARGIN_X = (1200 - ART_W) // 2
HEIGHT = 240
ART_TOP = (HEIGHT - ART_H) // 2


def rects(fill: str, dx: int = 0, dy: int = 0) -> str:
    out = []
    x = MARGIN_X + dx
    for ch in WORD:
        glyph = GLYPHS[ch]
        for r, row in enumerate(glyph):
            for c, bit in enumerate(row):
                if bit == "1":
                    out.append(
                        f'<rect x="{x + c * PITCH}" y="{ART_TOP + dy + r * PITCH}" '
                        f'width="{BLOCK}" height="{BLOCK}" rx="1.5" fill="{fill}"/>'
                    )
        x += (len(glyph[0]) + 1) * PITCH
    return "\n  ".join(out)


def svg(theme: str) -> str:
    if theme == "dark":
        bg, grad_top = "#0d1117", "#fde047"   # matches GitHub dark exactly
        echo, stroke = "#7c2d12", "#0d1117"
    else:
        bg, grad_top = "#ffffff", "#f59e0b"
        echo, stroke = "#fdba74", "#ffffff"
    grad = (
        f'<linearGradient id="amber" x1="0" y1="0" x2="0" y2="1">'
        f'<stop offset="0" stop-color="{grad_top}"/>'
        f'<stop offset="0.55" stop-color="#f59e0b"/>'
        f'<stop offset="1" stop-color="#ea580c"/>'
        f"</linearGradient>"
    )
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="{HEIGHT}" viewBox="0 0 1200 {HEIGHT}" role="img" aria-label="PatchLedger">
  <defs>{grad}</defs>
  <rect width="1200" height="{HEIGHT}" fill="{bg}"/>
  <!-- solid drop layer behind the word -->
  {rects(echo, dx=6, dy=6)}
  <!-- pixel word -->
  {rects(f"url(#amber)")}
</svg>
'''


out = Path(__file__).resolve().parent.parent / "website" / "assets"
(out / "banner-pixel-dark.svg").write_text(svg("dark"), encoding="utf-8")
(out / "banner-pixel-light.svg").write_text(svg("light"), encoding="utf-8")
print(f"art {ART_W}x{ART_H}, banner 1200x{HEIGHT}, seamless bg")
