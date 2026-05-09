#!/usr/bin/env python3
"""
Rasterize gui/resources/app_icon.svg into ICO (multi-resolution) and PNG.

Requires: pip install resvg-py pillow
"""

from __future__ import annotations

from io import BytesIO
from pathlib import Path

from PIL import Image

try:
    from resvg_py import svg_to_bytes
except ImportError as exc:  # pragma: no cover - dev tooling
    raise SystemExit("render_gui_icons needs resvg-py and pillow: pip install resvg-py pillow") from exc


def _svg_png(svg_path: Path, size: int) -> Image.Image:
    blob = svg_to_bytes(svg_path=str(svg_path), width=size, height=size, background=None)
    img = Image.open(BytesIO(blob)).convert("RGBA")
    return img


def main() -> None:
    repo = Path(__file__).resolve().parent.parent
    svg_path = repo / "dhtrack" / "gui" / "resources" / "app_icon.svg"
    if not svg_path.is_file():
        raise SystemExit(f"missing SVG: {svg_path}")
    png_path = svg_path.with_name("app_icon.png")
    ico_path = svg_path.with_name("app_icon.ico")

    master = _svg_png(svg_path, 512)
    master.save(png_path, format="PNG", optimize=True)

    sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    images: list[Image.Image] = []
    for w, h in sizes:
        images.append(master.resize((w, h), Image.Resampling.LANCZOS))

    images[0].save(
        ico_path,
        format="ICO",
        append_images=images[1:],
        sizes=[(img.width, img.height) for img in images],
    )
    print(f"wrote {png_path.relative_to(repo)}")
    print(f"wrote {ico_path.relative_to(repo)}")


if __name__ == "__main__":
    main()
