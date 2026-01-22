"""
About frame for application details and build info.
"""
import customtkinter as ctk
from pathlib import Path

from config import (
    APP_NAME,
    APP_VERSION,
    DATA_DIR,
    SESSION_TIMEOUT_MINUTES,
    COLOR_BG,
    COLOR_SURFACE,
    COLOR_ACCENT,
    COLOR_TEXT,
    COLOR_TEXT_DIM,
)


class AboutFrame(ctk.CTkFrame):
    """About page with app metadata."""

    def __init__(self, master, db_manager=None, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.db = db_manager

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        container = ctk.CTkFrame(self, fg_color=COLOR_SURFACE, corner_radius=16)
        container.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        container.grid_columnconfigure(0, weight=1)

        title = ctk.CTkLabel(
            container,
            text=f"{APP_NAME}",
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color=COLOR_TEXT,
        )
        title.grid(row=0, column=0, sticky="w", padx=20, pady=(20, 6))

        version = ctk.CTkLabel(
            container,
            text=f"Version {APP_VERSION}",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLOR_ACCENT,
        )
        version.grid(row=1, column=0, sticky="w", padx=20, pady=(0, 14))

        description = (
            "BitMarrow is a local-first vault for passwords, notes, and keys. "
            "All sensitive data is encrypted at rest using a master key derived "
            "from your login."
        )
        ctk.CTkLabel(
            container,
            text=description,
            font=ctk.CTkFont(size=13),
            text_color=COLOR_TEXT_DIM,
            wraplength=650,
            justify="left",
        ).grid(row=2, column=0, sticky="w", padx=20, pady=(0, 16))

        info = ctk.CTkFrame(container, fg_color=COLOR_BG, corner_radius=12)
        info.grid(row=3, column=0, sticky="ew", padx=20, pady=(0, 20))
        info.grid_columnconfigure(1, weight=1)

        self._add_info_row(info, 0, "Data directory", str(Path(DATA_DIR)))
        self._add_info_row(info, 1, "Session timeout", f"{SESSION_TIMEOUT_MINUTES} minutes")
        self._add_info_row(info, 2, "Platform", self._platform_label())

    def _add_info_row(self, parent, row: int, label: str, value: str):
        ctk.CTkLabel(
            parent,
            text=label,
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=COLOR_TEXT,
        ).grid(row=row, column=0, sticky="w", padx=16, pady=10)

        ctk.CTkLabel(
            parent,
            text=value,
            font=ctk.CTkFont(size=12),
            text_color=COLOR_TEXT_DIM,
        ).grid(row=row, column=1, sticky="w", padx=10, pady=10)

    def _platform_label(self) -> str:
        import platform

        return f"{platform.system()} {platform.release()}"

    def show(self):
        """No-op hook to match app navigation calls."""
        return
