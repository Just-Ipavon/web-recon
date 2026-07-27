"""Re-time an asciicast for playback as a looping README animation.

rich writes the whole report in a single burst, so a raw recording spends over
a second on the progress lines and renders every table in the final ten
milliseconds — by which point the animation loops and the tables are never
seen. This spaces the events evenly and holds the last frame on screen.

The scan itself is real and untouched; only playback pacing is rewritten.

Usage:
    python assets/retime.py <in.cast> <out.cast> [step seconds] [hold seconds]
"""

import json
import sys

src_path = sys.argv[1]
dst_path = sys.argv[2]
step = float(sys.argv[3]) if len(sys.argv) > 3 else 0.75
hold = float(sys.argv[4]) if len(sys.argv) > 4 else 8.0

lines = open(src_path).read().splitlines()
header = json.loads(lines[0])
events = [json.loads(line) for line in lines[1:]]

def is_typing(payload: str) -> bool:
    """Keystrokes arrive one character at a time and carry no newline.

    Their original rhythm is what makes the demo look like someone typing, so
    it is preserved; only whole lines of program output get spaced out.
    """
    return "\n" not in payload and len(payload) <= 2


clock = 0.5
previous = events[0][0]
for event in events:
    gap = event[0] - previous
    previous = event[0]
    clock += gap if is_typing(event[2]) else max(gap, step)
    event[0] = round(clock, 2)

# A no-op reset sequence in the future keeps the final frame visible before the
# animation loops back to the start.
end = events[-1][0]
events.append([round(end + hold, 2), "o", "\x1b[0m"])

header["idle_time_limit"] = hold + step + 5

with open(dst_path, "w") as f:
    f.write(json.dumps(header) + "\n")
    for event in events:
        f.write(json.dumps(event) + "\n")

print(f"{len(events) - 1} events over {end:.1f}s, final frame held {hold:.0f}s")
print(f"total playback: {events[-1][0]:.1f}s")
