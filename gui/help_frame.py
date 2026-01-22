"""
Help frame with basic usage guidance.
"""
import customtkinter as ctk

from config import COLOR_BG, COLOR_SURFACE, COLOR_ACCENT, COLOR_TEXT, COLOR_TEXT_DIM


class HelpFrame(ctk.CTkFrame):
    """Help page with quick tips and troubleshooting."""

    def __init__(self, master, db_manager=None, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.db = db_manager

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        container = ctk.CTkFrame(self, fg_color=COLOR_SURFACE, corner_radius=16)
        container.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        container.grid_columnconfigure(0, weight=1)
        container.grid_rowconfigure(1, weight=1)

        header = ctk.CTkLabel(
            container,
            text="Help and Tips",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color=COLOR_TEXT,
        )
        header.grid(row=0, column=0, sticky="w", padx=20, pady=(20, 10))

        body = ctk.CTkScrollableFrame(container, fg_color=COLOR_BG, corner_radius=12)
        body.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))

        self._add_section(
            body,
            "Getting started",
            [
                "Unlock with your master password or everyday password.",
                "Set a PIN from Settings to enable quick unlock.",
                "Use the sidebar to switch between vaults, notes, and tools.",
            ],
        )

        self._add_section(
            body,
            "Security reminders",
            [
                "Keep your recovery phrase offline and private.",
                "Use the lock button to end the session immediately.",
                "Back up the vault after major changes.",
            ],
        )

        self._add_section(
            body,
            "Troubleshooting",
            [
                "If unlock fails, verify keyboard layout and caps lock.",
                "If a tab looks empty, click it again to refresh.",
                "Restart the app if the vault file is in use by another instance.",
            ],
        )

    def _add_section(self, parent, title: str, items: list[str]):
        section = ctk.CTkFrame(parent, fg_color="transparent")
        section.pack(fill="x", padx=16, pady=(14, 4))

        ctk.CTkLabel(
            section,
            text=title,
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLOR_ACCENT,
        ).pack(anchor="w")

        for item in items:
            ctk.CTkLabel(
                section,
                text=f"- {item}",
                font=ctk.CTkFont(size=12),
                text_color=COLOR_TEXT_DIM,
                wraplength=620,
                justify="left",
            ).pack(anchor="w", pady=2)

    def show(self):
        """No-op hook to match app navigation calls."""
        return
