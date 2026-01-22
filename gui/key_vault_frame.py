"""
Key vault frame for viewing and managing cryptographic keys and certificates.
"""
import customtkinter as ctk
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

from utils.clipboard import ClipboardManager

from config import COLOR_BG, COLOR_SURFACE, COLOR_ACCENT, COLOR_TEXT, COLOR_TEXT_DIM

class KeyVaultFrame(ctk.CTkFrame):
    """View and manage saved cryptographic keys and certificates with a modern UI."""
    
    def __init__(self, master, db_manager, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        
        self.db = db_manager
        self.keys: List[Dict[str, Any]] = []
        self.selected_id: Optional[int] = None
        
        # Split pane
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=2)
        self.grid_rowconfigure(0, weight=1)
        
        self._create_list_panel()
        self._create_detail_panel()
    
    def _create_list_panel(self):
        """Create left panel with keys list."""
        self.list_frame = ctk.CTkFrame(self, fg_color=COLOR_SURFACE, corner_radius=15)
        self.list_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        
        # Header
        header = ctk.CTkFrame(self.list_frame, fg_color="transparent")
        header.pack(fill="x", padx=15, pady=20)
        
        ctk.CTkLabel(
            header, text="Certificates & Keys",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(side="left")
        
        # Search
        search_frame = ctk.CTkFrame(self.list_frame, fg_color=COLOR_BG, corner_radius=10, height=45)
        search_frame.pack(fill="x", padx=15, pady=(0, 15))
        search_frame.pack_propagate(False)

        self.search_entry = ctk.CTkEntry(
            search_frame, placeholder_text="Search keys...",
            fg_color="transparent", border_width=0,
            font=ctk.CTkFont(size=13)
        )
        self.search_entry.pack(fill="both", expand=True, padx=10)
        self.search_entry.bind("<KeyRelease>", self._on_search)

        filter_frame = ctk.CTkFrame(self.list_frame, fg_color="transparent")
        filter_frame.pack(fill="x", padx=15, pady=(0, 10))

        ctk.CTkLabel(
            filter_frame, text="Expiry Filter",
            font=ctk.CTkFont(size=11), text_color=COLOR_TEXT_DIM
        ).pack(side="left")

        self.expiry_filter = ctk.StringVar(value="All")
        self.expiry_filter_combo = ctk.CTkComboBox(
            filter_frame,
            values=["All", "Valid", "Expiring Soon", "Expired", "No Expiry"],
            variable=self.expiry_filter,
            width=160,
            fg_color=COLOR_BG,
            border_color="#333333",
            command=lambda _: self._update_list(self.search_entry.get())
        )
        self.expiry_filter_combo.pack(side="right")
        
        # Scrollable list
        self.list_scroll = ctk.CTkScrollableFrame(self.list_frame, fg_color="transparent")
        self.list_scroll.pack(fill="both", expand=True, padx=5, pady=5)
    
    def _create_detail_panel(self):
        """Create right panel with key details."""
        self.detail_frame = ctk.CTkFrame(self, fg_color=COLOR_SURFACE, corner_radius=15)
        self.detail_frame.grid(row=0, column=1, sticky="nsew")
        
        # Content area
        self.detail_content = ctk.CTkScrollableFrame(self.detail_frame, fg_color="transparent")
        self.detail_content.pack(fill="both", expand=True, padx=25, pady=25)
        
        # Empty state
        self.empty_label = ctk.CTkLabel(
            self.detail_content,
            text="Select a cryptographic key or certificate to view its properties and actual data.",
            text_color=COLOR_TEXT_DIM,
            font=ctk.CTkFont(size=14),
            wraplength=350
        )
        self.empty_label.pack(expand=True, pady=100)
        
        # Detail area (hidden initially)
        self.data_frame = ctk.CTkFrame(self.detail_content, fg_color="transparent")
        
        header_row = ctk.CTkFrame(self.data_frame, fg_color="transparent")
        header_row.pack(fill="x")

        self.title_label = ctk.CTkLabel(
            header_row, text="",
            font=ctk.CTkFont(size=24, weight="bold"),
            anchor="w"
        )
        self.title_label.pack(side="left", fill="x", expand=True)

        self.type_badge = ctk.CTkLabel(
            header_row, text="",
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color="#34495e", text_color="#ecf0f1",
            corner_radius=8, padx=10, height=25
        )
        self.type_badge.pack(side="right")
        
        # Metadata area
        ctk.CTkLabel(
            self.data_frame, text="Key Metadata",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=COLOR_TEXT_DIM
        ).pack(anchor="w", pady=(20, 10))

        self.meta_frame = ctk.CTkFrame(self.data_frame, fg_color=COLOR_BG, corner_radius=12)
        self.meta_frame.pack(fill="x", pady=(0, 20))
        
        # Keys area
        self.keys_area = ctk.CTkFrame(self.data_frame, fg_color="transparent")
        self.keys_area.pack(fill="x")
        
        self._create_key_field("public", "Public Key / Certificate")
        self._create_key_field("private", "Private Key")

        self.notes_frame = ctk.CTkFrame(self.data_frame, fg_color="transparent")
        self.notes_frame.pack(fill="x", pady=(15, 5))

        notes_header = ctk.CTkFrame(self.notes_frame, fg_color="transparent")
        notes_header.pack(fill="x", pady=(0, 5))
        ctk.CTkLabel(
            notes_header, text="Notes",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=COLOR_TEXT_DIM
        ).pack(side="left")
        self.save_notes_btn = ctk.CTkButton(
            notes_header, text="Save Notes",
            height=28, fg_color="transparent", border_width=1, border_color="#555555",
            font=ctk.CTkFont(size=11),
            command=self._save_notes
        )
        self.save_notes_btn.pack(side="right")

        self.notes_text = ctk.CTkTextbox(
            self.notes_frame, height=120,
            fg_color=COLOR_BG, border_color="#333333", border_width=1,
            font=ctk.CTkFont(size=12)
        )
        self.notes_text.pack(fill="x")
        
        # Actions
        self.actions_frame = ctk.CTkFrame(self.data_frame, fg_color="transparent")
        self.actions_frame.pack(fill="x", pady=(30, 0))
        
        self.delete_btn = ctk.CTkButton(
            self.actions_frame, text="Delete from Vault",
            height=40, font=ctk.CTkFont(weight="bold"),
            fg_color="transparent", border_width=1, border_color="#e74c3c",
            text_color="#e74c3c", hover_color="#c0392b",
            command=self._delete_key
        )
        self.delete_btn.pack(side="left")
    
    def _create_key_field(self, name: str, label: str):
        frame = ctk.CTkFrame(self.keys_area, fg_color="transparent")
        frame.pack(fill="x", pady=10)
        
        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.pack(fill="x", pady=(0, 5))
        
        label_obj = ctk.CTkLabel(
            header, text=label, 
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=COLOR_TEXT_DIM
        )
        label_obj.pack(side="left")
        setattr(self, f"{name}_label", label_obj)
        
        btn_box = ctk.CTkFrame(header, fg_color="transparent")
        btn_box.pack(side="right")

        if name == "private":
            self.private_visible = False
            toggle_btn = ctk.CTkButton(
                btn_box, text="Show", width=70, height=28,
                fg_color="transparent", border_width=1, border_color="#555555",
                font=ctk.CTkFont(size=11),
                command=self._toggle_private_visibility
            )
            toggle_btn.pack(side="left", padx=5)
            self.toggle_private_btn = toggle_btn

        copy_btn = ctk.CTkButton(
            btn_box, text="Copy", width=70, height=28,
            fg_color=COLOR_ACCENT if name == "public" else "transparent",
            text_color="black" if name == "public" else COLOR_TEXT,
            border_width=0 if name == "public" else 1,
            border_color="#555555",
            font=ctk.CTkFont(size=11, weight="bold" if name == "public" else "normal"),
            command=lambda n=name: self._copy_key(n)
        )
        copy_btn.pack(side="left")
        setattr(self, f"copy_{name}_btn", copy_btn)
        
        text = ctk.CTkTextbox(
            frame, height=180, 
            fg_color=COLOR_BG, border_color="#333333", border_width=1,
            font=ctk.CTkFont(family="Consolas", size=12)
        )
        text.pack(fill="x")
        setattr(self, f"{name}_text", text)
        setattr(self, f"{name}_frame", frame)
    
    def _create_meta_row(self, label: str, value: str, color: str = COLOR_TEXT):
        row = ctk.CTkFrame(self.meta_frame, fg_color="transparent")
        row.pack(fill="x", padx=15, pady=8)
        
        ctk.CTkLabel(
            row, text=label, 
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=COLOR_TEXT_DIM,
            width=120, anchor="w"
        ).pack(side="left")
        
        ctk.CTkLabel(
            row, text=value,
            font=ctk.CTkFont(size=12),
            text_color=color, anchor="w"
        ).pack(side="left", fill="x", expand=True)

    def refresh(self):
        """Refresh keys list."""
        self.keys = self.db.get_all_crypto_keys()
        self._update_list()
    
    def _update_list(self, filter_text: str = ""):
        for widget in self.list_scroll.winfo_children():
            widget.destroy()
        
        keys = self._filter_keys(filter_text)
            
        for key in keys:
            self._create_list_item(key)
            
        if not keys:
            ctk.CTkLabel(
                self.list_scroll, text="No keys found",
                text_color=COLOR_TEXT_DIM,
                pady=40
            ).pack()

    def _filter_keys(self, filter_text: str) -> List[Dict[str, Any]]:
        keys = self.keys
        if filter_text:
            filter_lower = filter_text.lower()
            keys = [k for k in keys if filter_lower in k['name'].lower()]

        filter_mode = self.expiry_filter.get()
        if filter_mode == "All":
            return keys

        def matches_filter(key: Dict[str, Any]) -> bool:
            status = self._get_expiry_status(key)
            if filter_mode == "Expired":
                return status == "expired"
            if filter_mode == "Expiring Soon":
                return status == "expiring"
            if filter_mode == "Valid":
                return status == "valid"
            if filter_mode == "No Expiry":
                return status == "none"
            return True

        return [k for k in keys if matches_filter(k)]

    def _get_expiry_status(self, key: Dict[str, Any]) -> str:
        expiry_raw = key.get("expiry_date")
        if not expiry_raw:
            return "none"
        try:
            expiry = datetime.fromisoformat(expiry_raw)
        except ValueError:
            return "none"
        now = datetime.utcnow()
        if expiry < now:
            return "expired"
        if expiry - now <= timedelta(days=30):
            return "expiring"
        return "valid"
            
    def _create_list_item(self, key: Dict[str, Any]):
        is_selected = self.selected_id == key['id']
        bg_color = "#333333" if is_selected else "transparent"

        item = ctk.CTkFrame(self.list_scroll, height=70, fg_color=bg_color, cursor="hand2", corner_radius=10)
        item.pack(fill="x", pady=4, padx=5)
        item.pack_propagate(False)

        status = self._get_expiry_status(key)
        status_tag = ""
        name_color = COLOR_TEXT
        if status == "expired":
            status_tag = " (EXPIRED)"
            name_color = "#e74c3c"
        elif status == "expiring":
            status_tag = " (EXPIRING)"
            name_color = "#f39c12"

        prefix = "CERT" if key['key_type'] == "X.509 Certificate" else "KEY"

        content = ctk.CTkFrame(item, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=15, pady=10)
        
        ctk.CTkLabel(
            content, text=f"{prefix}  {key['name']}{status_tag}", 
            font=ctk.CTkFont(size=14, weight="bold"),
            anchor="w", text_color=name_color
        ).pack(fill="x")
        
        ctk.CTkLabel(
            content, text=key['key_type'], 
            font=ctk.CTkFont(size=11),
            text_color=COLOR_TEXT_DIM, anchor="w"
        ).pack(fill="x")
        
        def handle_click(e):
            self._select_key(key)
            self._update_list(self.search_entry.get())

        for widget in [item, content] + list(content.winfo_children()):
            widget.bind("<Button-1>", handle_click)
            
    def _select_key(self, key_summary: Dict[str, Any]):
        key = self.db.get_crypto_key(key_summary['id'])
        if not key: return
        
        self.selected_id = key['id']
        self.current_key_data = key
        
        self.empty_label.pack_forget()
        self.data_frame.pack(fill="both", expand=True)
        
        self.title_label.configure(text=key['name'])
        self.type_badge.configure(text=key['key_type'].upper())
        
        # Standardize labels
        if key['key_type'] == "X.509 Certificate":
            self.public_label.configure(text="Certificate (PEM)")
        elif "SSH" in key['key_type']:
            self.public_label.configure(text="SSH Public Key")
        else:
            self.public_label.configure(text="Public Key")
        self.private_label.configure(text="Private Key")

        # Update metadata
        for widget in self.meta_frame.winfo_children(): widget.destroy()
        
        if key['expiry_date']:
            expiry = datetime.fromisoformat(key['expiry_date'])
            status = self._get_expiry_status(key)
            if status == "expired":
                color = "#e74c3c"
            elif status == "expiring":
                color = "#f39c12"
            else:
                color = COLOR_ACCENT
            self._create_meta_row("Expiry Date", expiry.strftime("%Y-%m-%d %H:%M"), color)
            
        if key['metadata']:
            for k, v in key['metadata'].items():
                if k != "expiry_date":
                    label = k.replace('_', ' ').title()
                    self._create_meta_row(label, str(v))
                    
        self._create_meta_row("Saved On", key['created_at'])
        
        # Update keys
        self._update_text_field("public", key['public_key'])
        
        # Reset visibility and update private field
        self.private_visible = False
        self.toggle_private_btn.configure(text="Show")
        self._update_private_display()

        self.notes_text.delete("1.0", "end")
        self.notes_text.insert("1.0", key.get("notes") or "")
        
    def _update_private_display(self):
        """Update the private key text box based on visibility."""
        if not hasattr(self, 'current_key_data') or not self.current_key_data:
            self.private_frame.pack_forget()
            return
            
        value = self.current_key_data.get('private_key')
        if not value:
            self.private_frame.pack_forget()
            return
            
        self.private_frame.pack(fill="x", pady=5)
        self.private_text.configure(state="normal")
        self.private_text.delete("1.0", "end")
        
        if self.private_visible:
            self.private_text.insert("1.0", value)
        else:
            lines = value.splitlines()
            if len(lines) > 2:
                masked = f"{lines[0]}\n\n[ SENSITIVE PRIVATE KEY MASKED ]\n\n{lines[-1]}"
            else:
                masked = "[ SENSITIVE PRIVATE KEY MASKED ]"
            self.private_text.insert("1.0", masked)
        self.private_text.configure(state="disabled")

    def _toggle_private_visibility(self):
        """Toggle private key visibility."""
        self.private_visible = not self.private_visible
        self.toggle_private_btn.configure(text="Hide" if self.private_visible else "Show")
        self._update_private_display()

    def _update_text_field(self, name: str, value: str):
        frame = getattr(self, f"{name}_frame")
        text = getattr(self, f"{name}_text")
        if value:
            frame.pack(fill="x", pady=5)
            text.configure(state="normal")
            text.delete("1.0", "end")
            text.insert("1.0", value)
            text.configure(state="disabled")
        else:
            frame.pack_forget()
            
    def _copy_key(self, name: str):
        """Copy actual raw key even if masked."""
        btn = getattr(self, f"copy_{name}_btn")
        
        if name == "private" and hasattr(self, 'current_key_data'):
            text = self.current_key_data.get('private_key', "").strip()
        else:
            text = self.current_key_data.get('public_key', "").strip()
            
        if text:
            ClipboardManager.copy(text)
            btn.configure(text="Copied")
            self.after(2000, lambda: btn.configure(text="Copy"))

    def _save_notes(self):
        if not self.selected_id:
            return
        notes = self.notes_text.get("1.0", "end").strip()
        self.db.update_crypto_key_notes(self.selected_id, notes)
        if hasattr(self, "current_key_data") and self.current_key_data:
            self.current_key_data["notes"] = notes
        self.save_notes_btn.configure(text="Saved")
        self.after(1500, lambda: self.save_notes_btn.configure(text="Save Notes"))

    def _delete_key(self):
        if self.selected_id:
            dialog = ctk.CTkInputDialog(text="Type 'DELETE' to confirm deletion:", title="Confirm Wipe")
            if dialog.get_input() == "DELETE":
                self.db.delete_crypto_key(self.selected_id)
                self.selected_id = None
                self.data_frame.pack_forget()
                self.empty_label.pack(expand=True, pady=100)
                self.refresh()

    def _on_search(self, event=None):
        query = self.search_entry.get()
        self._update_list(query)
