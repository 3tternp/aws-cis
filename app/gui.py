"""Tkinter application for collecting AWS credentials and running assessments."""

from __future__ import annotations

import re
import tkinter as tk
from tkinter import messagebox

import boto3

from .assessment import run_assessment

REGIONS = [
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "eu-west-1",
    "eu-west-2",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-northeast-1",
    "ap-northeast-2",
]

ACCESS_KEY_PATTERN = re.compile(r"^(AKIA|ASIA)[A-Z0-9]{16}$")
SECRET_KEY_PATTERN = re.compile(r"^[A-Za-z0-9/+=]{40}$")


class AssessmentApp:
    """Main application window for collecting credentials."""

    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("AWS CIS Assessment")
        root.geometry("420x320")

        self.access_key_var = tk.StringVar()
        self.secret_key_var = tk.StringVar()
        self.region_var = tk.StringVar(value=REGIONS[0])

        self._build_form()

    def _build_form(self) -> None:
        pad = {"padx": 10, "pady": 5}

        tk.Label(self.root, text="AWS Access Key ID").grid(row=0, column=0, sticky="w", **pad)
        self.access_entry = tk.Entry(self.root, textvariable=self.access_key_var, width=40)
        self.access_entry.grid(row=0, column=1, **pad)

        tk.Label(self.root, text="AWS Secret Access Key").grid(row=1, column=0, sticky="w", **pad)
        self.secret_entry = tk.Entry(self.root, textvariable=self.secret_key_var, show="*", width=40)
        self.secret_entry.grid(row=1, column=1, **pad)

        tk.Label(self.root, text="Region").grid(row=2, column=0, sticky="w", **pad)
        tk.OptionMenu(self.root, self.region_var, *REGIONS).grid(row=2, column=1, sticky="w", **pad)

        self.status_text = tk.Text(self.root, height=8, width=50, state="disabled", wrap="word")
        self.status_text.grid(row=3, column=0, columnspan=2, **pad)

        self.start_button = tk.Button(self.root, text="Start", command=self.start_assessment)
        self.start_button.grid(row=4, column=0, columnspan=2, **pad)

    def _set_status(self, message: str) -> None:
        self.status_text.configure(state="normal")
        self.status_text.insert(tk.END, f"{message}\n")
        self.status_text.configure(state="disabled")
        self.status_text.see(tk.END)

    def _validate_inputs(self) -> bool:
        access_key = self.access_key_var.get().strip()
        secret_key = self.secret_key_var.get().strip()

        if not ACCESS_KEY_PATTERN.match(access_key):
            messagebox.showerror(
                "Invalid Access Key ID",
                "Access Key ID must start with AKIA or ASIA and be 20 characters long.",
            )
            return False

        if not SECRET_KEY_PATTERN.match(secret_key):
            messagebox.showerror(
                "Invalid Secret Access Key",
                "Secret Access Key must be 40 characters and contain only base64 characters.",
            )
            return False

        return True

    def start_assessment(self) -> None:
        if not self._validate_inputs():
            return

        self.status_text.configure(state="normal")
        self.status_text.delete("1.0", tk.END)
        self.status_text.configure(state="disabled")

        access_key = self.access_key_var.get().strip()
        secret_key = self.secret_key_var.get().strip()
        region = self.region_var.get()

        try:
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=region,
            )
            self._set_status("Session created. Starting assessment…")
            run_assessment(session, self._set_status)
            messagebox.showinfo("Assessment Complete", "Assessment finished successfully.")
        except PermissionError as exc:
            messagebox.showerror("Permission Error", str(exc))
        except Exception as exc:  # pragma: no cover - runtime safeguard
            messagebox.showerror("Unexpected Error", str(exc))


def launch_app() -> None:
    root = tk.Tk()
    app = AssessmentApp(root)
    root.mainloop()


__all__ = ["AssessmentApp", "launch_app"]
