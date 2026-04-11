"""
Fuzz target for input validation utilities (input_validator.py).

Exercises detect_ioc_type, validate_payload, validate_mode, validate_siem,
validate_ciso_output, validate_ioc_type, and sanitize_string with arbitrary
byte data to find crashes, hangs, or unexpected exceptions.
"""
import atheris
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from input_validator import (  # noqa: E402
    detect_ioc_type,
    validate_payload,
    validate_mode,
    validate_siem,
    validate_ciso_output,
    validate_ioc_type,
    sanitize_string,
)


def TestOneInput(data: bytes) -> None:
    """Fuzz input_validator functions with arbitrary data."""
    fdp = atheris.FuzzedDataProvider(data)
    choice = fdp.ConsumeIntInRange(0, 6)
    remaining = fdp.ConsumeBytes(fdp.remaining_bytes())

    try:
        if choice == 0:
            # detect_ioc_type with arbitrary string
            detect_ioc_type(remaining.decode("utf-8", errors="replace"))
        elif choice == 1:
            # validate_payload with fuzzed JSON dict
            decoded = json.loads(remaining)
            if isinstance(decoded, dict):
                validate_payload(decoded, required=["alert", "mode"])
        elif choice == 2:
            # validate_payload with non-dict input
            validate_payload(remaining.decode("utf-8", errors="replace"))
        elif choice == 3:
            validate_mode(remaining.decode("utf-8", errors="replace"))
        elif choice == 4:
            validate_siem(remaining.decode("utf-8", errors="replace"))
        elif choice == 5:
            validate_ciso_output(remaining.decode("utf-8", errors="replace"))
        elif choice == 6:
            text = remaining.decode("utf-8", errors="replace")
            validate_ioc_type(text)
            sanitize_string(text)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError,
            ValueError, AttributeError):
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
