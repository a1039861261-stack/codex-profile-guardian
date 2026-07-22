from __future__ import annotations

import argparse
from pathlib import Path

from PIL import Image, ImageDraw


ICON_SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)
CANVAS = 1024


def _point(x: float, y: float) -> tuple[int, int]:
    return round(x * CANVAS / 48), round(y * CANVAS / 48)


def _cubic(
    start: tuple[float, float],
    control_1: tuple[float, float],
    control_2: tuple[float, float],
    end: tuple[float, float],
    steps: int = 24,
) -> list[tuple[int, int]]:
    points: list[tuple[int, int]] = []
    for index in range(1, steps + 1):
        t = index / steps
        inverse = 1 - t
        x = (
            inverse**3 * start[0]
            + 3 * inverse**2 * t * control_1[0]
            + 3 * inverse * t**2 * control_2[0]
            + t**3 * end[0]
        )
        y = (
            inverse**3 * start[1]
            + 3 * inverse**2 * t * control_1[1]
            + 3 * inverse * t**2 * control_2[1]
            + t**3 * end[1]
        )
        points.append(_point(x, y))
    return points


def render_guardian_mark() -> Image.Image:
    image = Image.new("RGBA", (CANVAS, CANVAS), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle(
        (0, 0, CANVAS - 1, CANVAS - 1),
        radius=round(11 * CANVAS / 48),
        fill="#1d4ed8",
    )
    shield = [_point(24, 4), _point(38, 9), _point(38, 19.2)]
    shield += _cubic((38, 19.2), (38, 28.4), (32.6, 36.7), (24, 42))
    shield += _cubic((24, 42), (15.4, 36.7), (10, 28.4), (10, 19.2))
    shield += [_point(10, 9), _point(24, 4)]
    stroke = round(3.1 * CANVAS / 48)
    draw.line(shield, fill="white", width=stroke, joint="curve")
    branch = [_point(14.5, 22), _point(22.7, 22), _point(31.5, 16.2)]
    draw.line(branch, fill="white", width=stroke, joint="curve")
    draw.line([_point(22.7, 22), _point(31.5, 27.8)], fill="white", width=stroke)
    radius = 2.6 * CANVAS / 48
    for x, y in ((14.5, 22), (31.5, 16.2), (31.5, 27.8)):
        center_x, center_y = _point(x, y)
        draw.ellipse(
            (
                round(center_x - radius),
                round(center_y - radius),
                round(center_x + radius),
                round(center_y + radius),
            ),
            fill="white",
        )
    return image


def generate_icon(target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    render_guardian_mark().save(target, format="ICO", sizes=[(size, size) for size in ICON_SIZES])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "target",
        nargs="?",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "assets" / "guardian.ico",
    )
    args = parser.parse_args()
    generate_icon(args.target.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
