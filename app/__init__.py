"""AWS CIS assessment GUI and CLI entry point."""

from .assessment import run_assessment  # noqa: F401
from .gui import launch_app  # noqa: F401

__all__ = ["run_assessment", "launch_app"]
