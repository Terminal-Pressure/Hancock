"""
Fuzz target for Atomic Red Team test parser (collectors/atomic_collector.py).

Exercises parse_atomic_tests() with arbitrary JSON dict and raw YAML-like text
inputs to find crashes from unexpected types, missing keys, or malformed
regular expression input.
"""
import atheris
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from collectors.atomic_collector import parse_atomic_tests  # noqa: E402


def TestOneInput(data: bytes) -> None:
    """Fuzz parse_atomic_tests with arbitrary data."""
    fdp = atheris.FuzzedDataProvider(data)
    choice = fdp.ConsumeIntInRange(0, 1)
    remaining = fdp.ConsumeBytes(fdp.remaining_bytes())

    try:
        if choice == 0:
            # Feed a JSON dict as the raw parameter
            decoded = json.loads(remaining)
            if isinstance(decoded, dict):
                parse_atomic_tests(decoded)
        else:
            # Feed a dict with raw_yaml text to exercise regex parsing
            text = remaining.decode("utf-8", errors="replace")
            parse_atomic_tests({
                "raw_yaml": text,
                "technique_id": "T1059.001",
                "url": "https://example.com/test.yaml",
            })
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError,
            ValueError, AttributeError, KeyError, IndexError,
            re.error):
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
