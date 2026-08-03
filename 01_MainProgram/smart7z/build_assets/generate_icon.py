"""Generate the multi-resolution Windows icon used by release builds."""

from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)


def _font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = (
        Path(r"C:\Windows\Fonts\segoeuib.ttf"),
        Path(r"C:\Windows\Fonts\arialbd.ttf"),
    )
    for path in candidates:
        if path.is_file():
            return ImageFont.truetype(str(path), max(8, round(size * 0.56)))
    return ImageFont.load_default()


def _frame(size: int) -> Image.Image:
    scale = size / 256
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    inset = max(1, round(10 * scale))
    radius = max(2, round(42 * scale))
    draw.rounded_rectangle(
        (inset, inset, size - inset - 1, size - inset - 1),
        radius=radius,
        fill=(25, 34, 43, 255),
        outline=(61, 76, 87, 255),
        width=max(1, round(4 * scale)),
    )

    rail_x = round(72 * scale)
    rail_w = max(2, round(18 * scale))
    draw.rounded_rectangle(
        (rail_x, round(36 * scale), rail_x + rail_w, round(220 * scale)),
        radius=max(1, round(8 * scale)),
        fill=(31, 180, 134, 255),
    )
    tooth = max(2, round(18 * scale))
    for index, y in enumerate((50, 86, 122, 158, 194)):
        x = rail_x + rail_w if index % 2 == 0 else rail_x - tooth
        draw.rounded_rectangle(
            (x, round(y * scale), x + tooth, round((y + 13) * scale)),
            radius=max(1, round(4 * scale)),
            fill=(245, 184, 65, 255),
        )

    label = "7"
    font = _font(size)
    box = draw.textbbox((0, 0), label, font=font)
    text_w = box[2] - box[0]
    text_h = box[3] - box[1]
    center_x = round(163 * scale)
    center_y = round(126 * scale)
    draw.text(
        (center_x - text_w / 2, center_y - text_h / 2 - box[1]),
        label,
        font=font,
        fill=(248, 250, 252, 255),
    )
    return image


def main() -> int:
    output = (
        Path(sys.argv[1]).resolve()
        if len(sys.argv) > 1
        else Path(__file__).with_name("smart7z.ico")
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    frames = [_frame(size) for size in SIZES]
    frames[-1].save(
        output,
        format="ICO",
        append_images=frames[:-1],
        sizes=[(size, size) for size in SIZES],
    )
    print(f"Generated {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
