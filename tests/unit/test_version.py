import subprocess
import sys

from haca import __version__


def test_version_constant() -> None:
    assert __version__ == "0.1.0.dev0"


def test_module_version_cli() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "haca", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "haca 0.1.0.dev0"