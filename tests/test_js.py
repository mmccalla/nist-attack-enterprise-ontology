"""Runs the JavaScript unit tests for the shared gap analysis module (lib/coverage.cjs)."""

import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_shared_module_unit_tests_pass():
    assert shutil.which("node"), "Node.js is needed for the shared module tests"
    result = subprocess.run(["node", "--test", str(ROOT / "tests" / "js")], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-2000:]
