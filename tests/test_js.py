"""Runs the JavaScript unit tests for the shared gap analysis module (lib/coverage.cjs)."""

import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_shared_module_unit_tests_pass():
    assert shutil.which("node"), "Node.js is needed for the shared module tests"
    # Name each file: Node 24 (CI) reads a folder argument as a module, Node 26 accepts it.
    files = sorted(str(p) for p in (ROOT / "tests" / "js").glob("*.test.cjs"))
    assert files
    result = subprocess.run(["node", "--test", *files], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-2000:]
