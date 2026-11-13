"""Append new immutable recordings; refuse any changed existing golden."""
import json
from pathlib import Path
import sys
path = Path(__file__).with_name("goldens.json")
goldens = json.loads(path.read_text())
for source in sys.argv[1:]:
    recorded = json.loads(Path(source).read_text())
    for key, value in recorded["cases"].items():
        if key in goldens["cases"]:
            assert goldens["cases"][key] == value, f"refusing changed golden {key}"
        else:
            goldens["cases"][key] = value
    goldens.setdefault("recordings", []).append({**{key: value for key, value in recorded.items() if key != "cases"}, "cases": list(recorded["cases"])})
path.write_text(json.dumps(goldens, indent=2) + "\n")
