"""Generate the PatchLedger pixel-wordmark banner SVGs (Shannon-style)."""

from pathlib import Path

# 5x7 pixel glyphs for the letters in PATCHLEDGER
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
BLOCK = 15      # px per pixel
GAP = 2         # dark gap between blocks
PITCH = BLOCK + GAP
COLS = sum(len(GLYPHS[ch][0]) for ch in WORD) + (len(WORD) - 1)  # + letter gaps
ROWS = 7
ART_W = COLS * PITCH - GAP
ART_H = ROWS * PITCH - GAP

MARGIN_X = (1200 - ART_W) // 2
ART_TOP = 64


def rects(fill: str, stroke: str, dx: int = 0, dy: int = 0, stroke_w: int = 0) -> str:
    out = []
    x = MARGIN_X + dx
    for ch in WORD:
        glyph = GLYPHS[ch]
        for r, row in enumerate(glyph):
            for c, bit in enumerate(row):
                if bit == "1":
                    out.append(
                        f'<rect x="{x + c * PITCH}" y="{ART_TOP + dy + r * PITCH}" '
                        f'width="{BLOCK}" height="{BLOCK}" rx="2" fill="{fill}"'
                        + (f' stroke="{stroke}" stroke-width="{stroke_w}"' if stroke else "")
                        + "/>"
                    )
        x += (len(glyph[0]) + 1) * PITCH
    return "\n  ".join(out)


def svg(theme: str) -> str:
    if theme == "dark":
        bg, border, dot = "#0b0e14", "#232c3e", "#8a94a6"
        sub, muted = "#eef1f6", "#8a94a6"
    else:
        bg, border, dot = "#f6f8fa", "#d0d7de", "#57606a"
        sub, muted = "#0d1117", "#57606a"
    grad = (
        f'<linearGradient id="amber" x1="0" y1="0" x2="0" y2="1">'
        f'<stop offset="0" stop-color="{"#fde047" if theme == "dark" else "#f59e0b"}"/>'
        f'<stop offset="0.5" stop-color="#f59e0b"/>'
        f'<stop offset="1" stop-color="#ea580c"/>'
        f"</linearGradient>"
    )
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="300" viewBox="0 0 1200 300" role="img" aria-label="PatchLedger">
  <defs>
    {grad}
    <pattern id="dots" width="26" height="26" patternUnits="userSpaceOnUse">
      <circle cx="1.2" cy="1.2" r="1.2" fill="{dot}" opacity="0.12"/>
    </pattern>
  </defs>
  <rect width="1200" height="300" fill="{bg}"/>
  <rect width="1200" height="300" fill="url(#dots)"/>
  <rect x="0.5" y="0.5" width="1199" height="299" fill="none" stroke="{border}"/>
  <!-- echo outlines behind the word -->
  <g opacity="0.55">
  {rects("none", "#b45309", dx=7, dy=7, stroke_w=2)}
  </g>
  <!-- pixel word -->
  {rects("url(#amber)", bg, stroke_w=2)}
  <text x="600" y="{ART_TOP + ART_H + 46}" text-anchor="middle" font-family="ui-sans-serif,-apple-system,'Segoe UI',Helvetica,Arial,sans-serif" font-size="26" font-weight="700" fill="{sub}">Security findings, verified fixed.</text>
  <text x="600" y="{ART_TOP + ART_H + 78}" text-anchor="middle" font-family="ui-sans-serif,-apple-system,'Segoe UI',Helvetica,Arial,sans-serif" font-size="18" fill="{muted}">-Run only against repositories you are authorized to assess-</text>
  <text x="600" y="286" text-anchor="middle" font-family="ui-monospace,Menlo,Consolas,monospace" font-size="13" fill="{muted}" opacity="0.75" letter-spacing="0.8">SCAN → NORMALIZE → FINGERPRINT → VERIFY · NO AI API · LOCAL-FIRST · MIT</text>
</svg>
'''


out = Path(__file__).resolve().parent.parent / "website" / "assets"
(out / "banner-pixel-dark.svg").write_text(svg("dark"), encoding="utf-8")
(out / "banner-pixel-light.svg").write_text(svg("light"), encoding="utf-8")
print(f"art {ART_W}x{ART_H}px, margin_x={MARGIN_X}")
print("wrote banner-pixel-dark.svg and banner-pixel-light.svg")
