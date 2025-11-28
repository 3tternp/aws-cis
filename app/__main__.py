"""CLI entry point for launching the Tkinter GUI."""

from .gui import launch_app


def main() -> None:
    launch_app()


if __name__ == "__main__":  # pragma: no cover - CLI entry
    main()
