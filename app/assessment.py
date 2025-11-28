"""Placeholder AWS CIS assessment runner."""

from __future__ import annotations

from typing import Callable

import boto3
from botocore.exceptions import ClientError


def run_assessment(session: boto3.Session, update_status: Callable[[str], None] | None = None) -> None:
    """Placeholder entry point for future CIS checks.

    Parameters
    ----------
    session:
        A boto3 :class:`~boto3.session.Session` configured with user-provided
        credentials and region.
    update_status:
        Optional callback for streaming status messages to the GUI.
    """

    def _notify(message: str) -> None:
        if update_status:
            update_status(message)

    try:
        _notify("Initializing AWS identity check…")
        sts = session.client("sts")
        _notify("Calling sts:GetCallerIdentity to verify permissions…")
        sts.get_caller_identity()
        _notify("Placeholder CIS assessment complete. Add checks here.")
    except ClientError as exc:  # pragma: no cover - runtime safety path
        _notify("Permission error encountered during assessment.")
        raise PermissionError(
            "Failed to perform AWS operations due to insufficient permissions."
        ) from exc
