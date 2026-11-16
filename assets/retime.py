"""Re-time an asciicast for playback as a looping README animation.

rich writes the whole report in a single burst, so a raw recording spends over
a second on the progress lines and renders every table in the final ten
milliseconds — by which point the animation loops and the tables are never
seen. This spaces the events evenly and holds the last frame on screen.

Both asciicast v2 (absolute timestamps, asciinema 2.x) and v3 (intervals since
the previous event, asciinema 3.x) are accepted; the output keeps the input
version.

The scan itself is real and untouched; only playback pacing is rewritten.

Usage:
    python assets/retime.py <in.cast> <out.cast> [step seconds] [hold seconds]
"""

from __future__ import annotations

import json
import sys


def is_typing(payload: str) -> bool:
    """Keystrokes arrive one character at a time and carry no newline.

    Their original rhythm is what makes the demo look like someone typing, so
    it is preserved; only whole lines of program output get spaced out.
    """
    return "\n" not in payload and len(payload) <= 2


def load(path: str) -> tuple[dict, list[list]]:
    with open(path, encoding="utf-8") as fh:
        lines = [line for line in fh.read().splitlines() if line.strip()]
    if not lines:
        raise SystemExit(f"{path}: empty recording")
    try:
        header = json.loads(lines[0])
        events = [json.loads(line) for line in lines[1:]]
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path}: not an asciicast file ({exc})") from exc
    if not isinstance(header, dict) or header.get("version") not in (2, 3):
        raise SystemExit(f"{path}: unsupported asciicast version {header.get('version')!r}")
    if not events:
        raise SystemExit(f"{path}: recording has no events")
    return header, events


def absolute_times(header: dict, events: list[list]) -> list[float]:
    if header["version"] == 2:
        return [float(e[0]) for e in events]
    clock = 0.0
    times = []
    for event in events:
        clock += float(event[0])
        times.append(clock)
    return times


def retime(header: dict, events: list[list], step: float, hold: float) -> list[list]:
    times = absolute_times(header, events)
    new_times = []
    clock = 0.5
    previous = times[0]
    for event, when in zip(events, times, strict=True):
        gap = when - previous
        previous = when
        output = event[1] == "o"
        clock += gap if (not output or is_typing(event[2])) else max(gap, step)
        new_times.append(round(clock, 2))

    # A no-op reset sequence in the future keeps the final frame visible before
    # the animation loops back to the start.
    new_times.append(round(new_times[-1] + hold, 2))
    events = events + [[0, "o", "\x1b[0m"]]

    if header["version"] == 2:
        return [[t, *e[1:]] for t, e in zip(new_times, events, strict=True)]
    out, last = [], 0.0
    for t, e in zip(new_times, events, strict=True):
        out.append([round(t - last, 2), *e[1:]])
        last = t
    return out


def main(argv: list[str]) -> None:
    if len(argv) < 3:
        raise SystemExit(__doc__)
    src, dst = argv[1], argv[2]
    step = float(argv[3]) if len(argv) > 3 else 0.75
    hold = float(argv[4]) if len(argv) > 4 else 8.0

    header, events = load(src)
    retimed = retime(header, events, step, hold)
    header["idle_time_limit"] = hold + step + 5
    if header["version"] == 3:
        header.setdefault("term", {})

    with open(dst, "w", encoding="utf-8") as f:
        f.write(json.dumps(header) + "\n")
        for event in retimed:
            f.write(json.dumps(event) + "\n")

    total = sum(e[0] for e in retimed) if header["version"] == 3 else retimed[-1][0]
    print(f"{len(retimed) - 1} events, final frame held {hold:.0f}s")
    print(f"total playback: {total:.1f}s")


if __name__ == "__main__":
    main(sys.argv)
