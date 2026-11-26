#!/usr/bin/env python3
"""Atheris fuzz target for scripts/loophole_scanner.py.

Writes each fuzz input to a temp file with a random scanned extension and runs
the scanner. Failures are unexpected exceptions or inputs that take longer than
INPUT_BUDGET_SEC (catastrophic backtracking in a rule pattern).

Not part of the normal unittest suite (filename is fuzz_*.py, not test_*.py).
Atheris is an optional dependency — install with: pip install -r requirements-fuzz.txt

  python tests/fuzz_loophole_scanner.py -max_total_time=60
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

import atheris

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

with atheris.instrument_imports():
    import loophole_scanner as ls  # noqa: E402

INPUT_BUDGET_SEC = 1.0
_EXTENSIONS = sorted(ls.SCAN_EXTENSIONS)


def TestOneInput(data: bytes) -> None:
    if not data:
        return
    fdp = atheris.FuzzedDataProvider(data)
    ext = fdp.PickValueInList(_EXTENSIONS)
    # Cap payload size so we spend time on regexes, not huge files (scanner also skips >512 KiB).
    payload = fdp.ConsumeBytes(min(fdp.remaining_bytes(), 64 * 1024))
    started = time.perf_counter()
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / f"fuzz{ext}"
        path.write_bytes(payload)
        ls.scan_repo(Path(tmp))
    elapsed = time.perf_counter() - started
    if elapsed > INPUT_BUDGET_SEC:
        raise TimeoutError(
            f"scan_repo took {elapsed:.3f}s (budget {INPUT_BUDGET_SEC}s); possible ReDoS in a rule"
        )


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
