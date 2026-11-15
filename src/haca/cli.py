"""HACA command-line interface."""

from __future__ import annotations

import argparse

from haca import __version__


def main() -> None:
    parser = argparse.ArgumentParser(prog="haca", description="Hikvision configuration auditor")
    parser.add_argument(
        "--version",
        action="version",
        version=f"haca {__version__}",
    )
    parser.parse_args()