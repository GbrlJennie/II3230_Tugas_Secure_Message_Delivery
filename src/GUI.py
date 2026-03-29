"""
GUI.py
Antarmuka grafis (GUI) untuk End-to-End Secure Message Delivery.
Menampilkan jendela Alice (pengirim) dan Bob (penerima) secara bersamaan.
Jalankan: python GUI.py
"""

import sys
import os
import time
import threading
import json
import base64
import tkinter as tk
from tkinter import ttk, scrolledtext, font as tkfont, messagebox

# ── Tambahkan direktori script ke path ──────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from key_manager import setup_all_keys
from alice import Alice
from bob import Bob
from crypto_utils import payload_to_json


# ════════════════════════════════════════════════════════════════════════════
#  TEMA & WARNA
# ════════════════════════════════════════════════════════════════════════════
THEME = {
    "bg":            "#0d1117",      # latar utama (hitam GitHub)
    "panel":         "#161b22",      # panel / card
    "border":        "#30363d",      # border tipis
    "alice_accent":  "#58a6ff",      # biru Alice
    "alice_dark":    "#1f3a5c",
    "bob_accent":    "#3fb950",      # hijau Bob
    "bob_dark":      "#1a3a26",
    "warning":       "#f0883e",
    "error":         "#f85149",
    "success":       "#3fb950",
    "text":          "#e6edf3",
    "text_dim":      "#8b949e",
    "text_mono":     "#79c0ff",
    "highlight":     "#ffa657",
    "tag_key":       "#d2a8ff",
    "tag_val":       "#a5d6ff",
    "tag_ok":        "#56d364",
    "tag_err":       "#f85149",
    "tag_info":      "#79c0ff",
}

FONTS = {
    "title":   ("Consolas", 13, "bold"),
    "heading": ("Consolas", 11, "bold"),
    "mono":    ("Consolas", 9),
    "mono_sm": ("Consolas", 8),
    "ui":      ("Segoe UI", 10),
    "ui_sm":   ("Segoe UI", 9),
    "badge":   ("Consolas", 8, "bold"),
}

DEFAULT_PORT = 9999
DEFAULT_PLAINTEXT = "Bob, transfer dana penelitian sebesar 10 juta ke rekening Lab Keamanan ITB."


# ════════════════════════════════════════════════════════════════════════════
#  WIDGET HELPERS
# ════════════════════════════════════════════════════════════════════════════

def styled_frame(parent, bg=None, bd=0, relief="flat", **kw):
    bg = bg or THEME["panel"]
    return tk.Frame(parent, bg=bg, bd=bd, relief=relief, **kw)


def label(parent, text, font=None, fg=None, bg=None, **kw):
    return tk.Label(parent, text=text,
                    font=font or FONTS["ui"],
                    fg=fg or THEME["text"],
                    bg=bg or THEME["panel"], **kw)


def separator(parent, bg=None):
    return tk.Frame(parent, bg=bg or THEME["border"], height=1)


def mono_label(parent, text, fg=None, bg=None, **kw):
    return tk.Label(parent, text=text, font=FONTS["mono"],
                    fg=fg or THEME["text_mono"],
                    bg=bg or THEME["panel"], **kw)


def badge(parent, text, color, bg=None):
    return tk.Label(parent, text=f" {text} ", font=FONTS["badge"],
                    fg="#0d1117", bg=color, padx=4, pady=1)


class ScrolledLog(tk.Frame):
    """Log terminal dengan dukungan tag warna."""

    def __init__(self, parent, accent_color, **kw):
        super().__init__(parent, bg=THEME["bg"], **kw)
        self.accent = accent_color
        self.text = tk.Text(
            self, bg="#0a0e14", fg=THEME["text"],
            font=FONTS["mono_sm"], relief="flat", bd=0,
            insertbackground=accent_color,
            selectbackground=THEME["border"],
            wrap="word", state="disabled",
            highlightthickness=1, highlightbackground=THEME["border"],
        )
        sb = ttk.Scrollbar(self, command=self.text.yview)
        self.text.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.text.pack(side="left", fill="both", expand=True)

        # Tags
        self.text.tag_config("ok",    foreground=THEME["tag_ok"])
        self.text.tag_config("err",   foreground=THEME["tag_err"])
        self.text.tag_config("info",  foreground=THEME["tag_info"])
        self.text.tag_config("key",   foreground=THEME["tag_key"])
        self.text.tag_config("val",   foreground=THEME["tag_val"])
        self.text.tag_config("warn",  foreground=THEME["warning"])
        self.text.tag_config("dim",   foreground=THEME["text_dim"])
        self.text.tag_config("hi",    foreground=THEME["highlight"])
        self.text.tag_config("accent", foreground=accent_color)

    def clear(self):
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.configure(state="disabled")

    def append(self, text, tag=""):
        self.text.configure(state="normal")
        self.text.insert("end", text, tag)
        self.text.see("end")
        self.text.configure(state="disabled")

    def line(self, text, tag=""):
        self.append(text + "\n", tag)

    def divider(self, char="─", n=60, tag="dim"):
        self.line(char * n, tag)

    def kv(self, key, val, key_tag="key", val_tag="val"):
        self.append(f"  {key}: ", key_tag)
        self.line(val, val_tag)


# ════════════════════════════════════════════════════════════════════════════
#  PANEL ALICE
# ════════════════════════════════════════════════════════════════════════════

class AlicePanel(tk.Frame):
    def __init__(self, parent, app, **kw):
        super().__init__(parent, bg=THEME["panel"], **kw)
        self.app = app
        self.accent = THEME["alice_accent"]
        self._build()

    def _build(self):
        # Header
        hdr = styled_frame(self, bg=THEME["alice_dark"])
        hdr.pack(fill="x")
        tk.Frame(hdr, bg=self.accent, width=4).pack(side="left", fill="y")
        inner_hdr = styled_frame(hdr, bg=THEME["alice_dark"])
        inner_hdr.pack(side="left", fill="both", expand=True, padx=12, pady=10)
        label(inner_hdr, "🔒  ALICE", font=FONTS["title"],
              fg=self.accent, bg=THEME["alice_dark"]).pack(anchor="w")
        label(inner_hdr, "Pengirim Pesan  ·  Sender",
              font=FONTS["ui_sm"], fg=THEME["text_dim"],
              bg=THEME["alice_dark"]).pack(anchor="w")

        separator(self).pack(fill="x")

        # Body
        body = styled_frame(self)
        body.pack(fill="both", expand=True, padx=12, pady=10)

        # ── Plaintext input ──────────────────────────────────────────────
        label(body, "Pesan Plaintext", font=FONTS["heading"],
              fg=self.accent).pack(anchor="w")
        self.plaintext_var = tk.StringVar(value=DEFAULT_PLAINTEXT)
        entry_frame = styled_frame(body, bg="#0a0e14",
                                   highlightthickness=1,
                                   highlightbackground=self.accent)
        entry_frame.pack(fill="x", pady=(4, 10))
        self.plaintext_entry = tk.Entry(
            entry_frame, textvariable=self.plaintext_var,
            font=FONTS["mono"], fg=THEME["text"], bg="#0a0e14",
            insertbackground=self.accent, relief="flat",
            highlightthickness=0,
        )
        self.plaintext_entry.pack(fill="x", padx=8, pady=6)

        # ── IP / Port config ─────────────────────────────────────────────
        cfg_row = styled_frame(body)
        cfg_row.pack(fill="x", pady=(0, 10))

        def _field(parent, lbl, var, w=14):
            f = styled_frame(parent)
            f.pack(side="left", padx=(0, 12))
            label(f, lbl, font=FONTS["ui_sm"],
                  fg=THEME["text_dim"]).pack(anchor="w")
            e = tk.Entry(f, textvariable=var, width=w,
                         font=FONTS["mono_sm"], fg=THEME["text"],
                         bg="#0a0e14", insertbackground=self.accent,
                         relief="flat", highlightthickness=1,
                         highlightbackground=THEME["border"])
            e.pack(fill="x")
            return e

        self.alice_ip_var = tk.StringVar(value="127.0.0.1")
        self.bob_ip_var   = tk.StringVar(value="127.0.0.1")
        self.port_var     = tk.StringVar(value=str(DEFAULT_PORT))
        _field(cfg_row, "IP Alice (sumber)",   self.alice_ip_var)
        _field(cfg_row, "IP Bob (tujuan)",     self.bob_ip_var)
        _field(cfg_row, "Port", self.port_var, w=7)

        # ── Action buttons ───────────────────────────────────────────────
        btn_row = styled_frame(body)
        btn_row.pack(fill="x", pady=(0, 10))

        self.btn_prepare = self._make_btn(btn_row, "⚙  Siapkan Pesan", self._on_prepare)
        self.btn_prepare.pack(side="left", padx=(0, 8))

        self.btn_send = self._make_btn(btn_row, "📡  Kirim ke Bob", self._on_send,
                                       state="disabled")
        self.btn_send.pack(side="left", padx=(0, 8))

        self.btn_all = self._make_btn(btn_row, "⚡  Siapkan & Kirim", self._on_all)
        self.btn_all.pack(side="left")

        separator(body).pack(fill="x", pady=(0, 8))

        # ── Payload viewer ───────────────────────────────────────────────
        pv_row = styled_frame(body)
        pv_row.pack(fill="x")
        label(pv_row, "Payload JSON", font=FONTS["heading"],
              fg=self.accent).pack(side="left", anchor="w")
        self.btn_copy_payload = tk.Button(
            pv_row, text="Copy", font=FONTS["ui_sm"],
            fg=self.accent, bg=THEME["alice_dark"],
            activebackground=self.accent, activeforeground="#000",
            relief="flat", bd=0, cursor="hand2",
            command=self._copy_payload
        )
        self.btn_copy_payload.pack(side="right")

        self.payload_text = tk.Text(
            body, height=9, bg="#0a0e14", fg=THEME["text_dim"],
            font=FONTS["mono_sm"], relief="flat", bd=0,
            insertbackground=self.accent, wrap="none",
            highlightthickness=1, highlightbackground=THEME["border"],
            state="disabled",
        )
        self.payload_text.pack(fill="x", pady=(4, 8))
        # Horizontal scrollbar
        px_sb = ttk.Scrollbar(body, orient="horizontal",
                               command=self.payload_text.xview)
        self.payload_text.configure(xscrollcommand=px_sb.set)
        px_sb.pack(fill="x")

        # ── Log ──────────────────────────────────────────────────────────
        separator(body).pack(fill="x", pady=8)
        label(body, "Log Proses Alice", font=FONTS["heading"],
              fg=self.accent).pack(anchor="w")
        self.log = ScrolledLog(body, self.accent, height=160)
        self.log.pack(fill="both", expand=True, pady=(4, 0))

        self._payload_data = None

    def _make_btn(self, parent, text, cmd, state="normal"):
        return tk.Button(
            parent, text=text, command=cmd, state=state,
            font=FONTS["ui"], fg="#0d1117", bg=self.accent,
            activebackground="#a8d8ff", activeforeground="#000",
            relief="flat", bd=0, padx=14, pady=6, cursor="hand2",
            disabledforeground="#555",
        )

    def _on_prepare(self):
        self.log.clear()
        plaintext = self.plaintext_var.get().strip()
        if not plaintext:
            messagebox.showwarning("Input Kosong", "Masukkan pesan plaintext terlebih dahulu.")
            return
        self.log.line("━━━ ALICE: Menyiapkan Pesan ━━━", "accent")
        self.log.kv("Plaintext", plaintext, "key", "hi")

        def run():
            alice = self.app.get_alice(
                self.alice_ip_var.get(), self.bob_ip_var.get()
            )
            payload = alice.prepare_secure_message(plaintext)
            self._payload_data = payload
            self.app.root.after(0, lambda: self._display_alice_log(alice.log, payload))

        threading.Thread(target=run, daemon=True).start()

    def _on_send(self):
        if not self._payload_data:
            messagebox.showwarning("Belum Siap", "Siapkan pesan terlebih dahulu.")
            return
        port = int(self.port_var.get())
        self.log.line("━━━ ALICE: Mengirim Payload ━━━", "accent")

        def run():
            alice = self.app.get_alice(
                self.alice_ip_var.get(), self.bob_ip_var.get()
            )
            ok = alice.send_payload(self._payload_data, port=port)
            msg = f"Payload {'berhasil' if ok else 'GAGAL'} dikirim ke {self.bob_ip_var.get()}:{port}"
            tag = "ok" if ok else "err"
            self.app.root.after(0, lambda: self.log.line(f"  {'✓' if ok else '✗'} {msg}", tag))

        threading.Thread(target=run, daemon=True).start()

    def _on_all(self):
        self.log.clear()
        plaintext = self.plaintext_var.get().strip()
        if not plaintext:
            messagebox.showwarning("Input Kosong", "Masukkan pesan plaintext terlebih dahulu.")
            return
        port = int(self.port_var.get())
        self.log.line("━━━ ALICE: Siapkan & Kirim ━━━", "accent")

        def run():
            alice = self.app.get_alice(
                self.alice_ip_var.get(), self.bob_ip_var.get()
            )
            payload = alice.prepare_secure_message(plaintext)
            self._payload_data = payload
            self.app.root.after(0, lambda: self._display_alice_log(alice.log, payload))
            time.sleep(0.1)
            ok = alice.send_payload(payload, port=port)
            msg = f"Payload {'berhasil' if ok else 'GAGAL'} dikirim"
            tag = "ok" if ok else "err"
            self.app.root.after(0, lambda: self.log.line(f"  {'✓' if ok else '✗'} {msg}", tag))

        threading.Thread(target=run, daemon=True).start()

    def _display_alice_log(self, logs, payload):
        for entry in logs:
            if "ERROR" in entry:
                self.log.line(f"  {entry}", "err")
            elif "AES Key" in entry and "hex" in entry.lower():
                self.log.line(f"  {entry}", "key")
            elif "Hash" in entry:
                self.log.line(f"  {entry}", "val")
            elif "Signature" in entry:
                self.log.line(f"  {entry}", "key")
            elif "Ciphertext" in entry:
                self.log.line(f"  {entry}", "val")
            elif "siap" in entry.lower() or "berhasil" in entry.lower():
                self.log.line(f"  ✓ {entry}", "ok")
            else:
                self.log.line(f"  {entry}", "info")

        # Enable send button
        self.btn_send.config(state="normal")

        # Show payload
        payload_str = payload_to_json(payload)
        self.payload_text.configure(state="normal")
        self.payload_text.delete("1.0", "end")
        self.payload_text.insert("end", payload_str)
        self.payload_text.configure(state="disabled")

    def _copy_payload(self):
        self.payload_text.configure(state="normal")
        content = self.payload_text.get("1.0", "end").strip()
        self.payload_text.configure(state="disabled")
        if content:
            self.app.root.clipboard_clear()
            self.app.root.clipboard_append(content)
            self.btn_copy_payload.config(text="Copied ✓")
            self.app.root.after(2000, lambda: self.btn_copy_payload.config(text="Copy"))


# ════════════════════════════════════════════════════════════════════════════
#  PANEL BOB
# ════════════════════════════════════════════════════════════════════════════

class BobPanel(tk.Frame):
    def __init__(self, parent, app, **kw):
        super().__init__(parent, bg=THEME["panel"], **kw)
        self.app = app
        self.accent = THEME["bob_accent"]
        self._bob_instance: Bob | None = None
        self._build()

    def _build(self):
        # Header
        hdr = styled_frame(self, bg=THEME["bob_dark"])
        hdr.pack(fill="x")
        tk.Frame(hdr, bg=self.accent, width=4).pack(side="left", fill="y")
        inner_hdr = styled_frame(hdr, bg=THEME["bob_dark"])
        inner_hdr.pack(side="left", fill="both", expand=True, padx=12, pady=10)
        label(inner_hdr, "🔓  BOB", font=FONTS["title"],
              fg=self.accent, bg=THEME["bob_dark"]).pack(anchor="w")
        label(inner_hdr, "Penerima Pesan  ·  Receiver",
              font=FONTS["ui_sm"], fg=THEME["text_dim"],
              bg=THEME["bob_dark"]).pack(anchor="w")
        # Status badge
        self.status_var = tk.StringVar(value="OFFLINE")
        self.status_lbl = badge(inner_hdr, "● OFFLINE", THEME["border"])
        self.status_lbl.pack(anchor="e")

        separator(self).pack(fill="x")

        body = styled_frame(self)
        body.pack(fill="both", expand=True, padx=12, pady=10)

        # ── Server config ────────────────────────────────────────────────
        cfg_row = styled_frame(body)
        cfg_row.pack(fill="x", pady=(0, 10))

        label(cfg_row, "Listen IP:", font=FONTS["ui_sm"],
              fg=THEME["text_dim"]).pack(side="left", padx=(0, 4))
        self.listen_ip_var = tk.StringVar(value="0.0.0.0")
        tk.Entry(cfg_row, textvariable=self.listen_ip_var, width=14,
                 font=FONTS["mono_sm"], fg=THEME["text"], bg="#0a0e14",
                 insertbackground=self.accent, relief="flat",
                 highlightthickness=1, highlightbackground=THEME["border"]
                 ).pack(side="left", padx=(0, 12))

        label(cfg_row, "Port:", font=FONTS["ui_sm"],
              fg=THEME["text_dim"]).pack(side="left", padx=(0, 4))
        self.port_var = tk.StringVar(value=str(DEFAULT_PORT))
        tk.Entry(cfg_row, textvariable=self.port_var, width=7,
                 font=FONTS["mono_sm"], fg=THEME["text"], bg="#0a0e14",
                 insertbackground=self.accent, relief="flat",
                 highlightthickness=1, highlightbackground=THEME["border"]
                 ).pack(side="left")

        # ── Buttons ──────────────────────────────────────────────────────
        btn_row = styled_frame(body)
        btn_row.pack(fill="x", pady=(0, 10))

        self.btn_start = self._make_btn(btn_row, "▶  Mulai Listen", self._on_start)
        self.btn_start.pack(side="left", padx=(0, 8))

        self.btn_stop = self._make_btn(btn_row, "■  Stop", self._on_stop, state="disabled",
                                       color=THEME["error"])
        self.btn_stop.pack(side="left", padx=(0, 8))

        self.btn_clear = tk.Button(
            btn_row, text="🗑 Clear", font=FONTS["ui"],
            fg=THEME["text_dim"], bg=THEME["panel"],
            activeforeground=THEME["text"], activebackground=THEME["border"],
            relief="flat", bd=0, padx=10, pady=6, cursor="hand2",
            command=self._on_clear
        )
        self.btn_clear.pack(side="left")

        separator(body).pack(fill="x", pady=(0, 8))

        # ── Hasil verifikasi ─────────────────────────────────────────────
        label(body, "Hasil Verifikasi", font=FONTS["heading"],
              fg=self.accent).pack(anchor="w")

        result_frame = styled_frame(body, bg="#0a0e14",
                                    highlightthickness=1,
                                    highlightbackground=THEME["border"])
        result_frame.pack(fill="x", pady=(4, 8))

        self.result_inner = styled_frame(result_frame, bg="#0a0e14")
        self.result_inner.pack(fill="x", padx=10, pady=8)

        self._make_result_row("Plaintext Diterima", "plaintext_val")
        self._make_result_row("AES Key (dekripsi)", "aeskey_val")
        self._make_result_row("Hash (lokal)",       "hash_local_val")
        self._make_result_row("Hash (payload)",     "hash_recv_val")
        self._make_result_row("Hash Match",         "hash_match_val")
        self._make_result_row("Signature Valid",    "sig_val")

        # Verdict
        verdict_frame = styled_frame(body, bg="#0a0e14",
                                     highlightthickness=1,
                                     highlightbackground=THEME["border"])
        verdict_frame.pack(fill="x", pady=(0, 8))
        self.verdict_lbl = tk.Label(
            verdict_frame, text="Menunggu pesan...",
            font=("Consolas", 11, "bold"),
            fg=THEME["text_dim"], bg="#0a0e14",
            pady=10
        )
        self.verdict_lbl.pack()

        separator(body).pack(fill="x", pady=(0, 8))

        # ── Log ──────────────────────────────────────────────────────────
        label(body, "Log Proses Bob", font=FONTS["heading"],
              fg=self.accent).pack(anchor="w")
        self.log = ScrolledLog(body, self.accent, height=160)
        self.log.pack(fill="both", expand=True, pady=(4, 0))

        self._result_widgets = {}

    def _make_result_row(self, lbl_text, attr_name):
        row = styled_frame(self.result_inner, bg="#0a0e14")
        row.pack(fill="x", pady=1)
        label(row, f"{lbl_text}:", font=FONTS["ui_sm"],
              fg=THEME["text_dim"], bg="#0a0e14", width=22, anchor="w").pack(side="left")
        val_lbl = tk.Label(row, text="—", font=FONTS["mono_sm"],
                           fg=THEME["text_dim"], bg="#0a0e14",
                           anchor="w", wraplength=340, justify="left")
        val_lbl.pack(side="left", fill="x", expand=True)
        setattr(self, attr_name, val_lbl)

    def _make_btn(self, parent, text, cmd, state="normal", color=None):
        color = color or self.accent
        return tk.Button(
            parent, text=text, command=cmd, state=state,
            font=FONTS["ui"], fg="#0d1117", bg=color,
            activebackground="#8aff9a", activeforeground="#000",
            relief="flat", bd=0, padx=14, pady=6, cursor="hand2",
            disabledforeground="#555",
        )

    def _on_start(self):
        port = int(self.port_var.get())
        listen_ip = self.listen_ip_var.get()
        keys = self.app.keys
        if not keys:
            messagebox.showerror("Keys Not Ready", "Kunci belum di-generate.")
            return

        self._bob_instance = Bob(
            private_key=keys["bob_private"],
            alice_public_key=keys["alice_public"],
            listen_ip=listen_ip,
            port=port,
        )
        self._bob_instance.start_listening(callback=self._on_message_received)

        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        self._set_status(True)
        self.log.clear()
        self.log.line(f"  ● Mendengarkan di {listen_ip}:{port}...", "ok")

    def _on_stop(self):
        if self._bob_instance:
            self._bob_instance.stop_listening()
            self._bob_instance = None
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self._set_status(False)
        self.log.line("  ■ Server dihentikan.", "warn")

    def _on_clear(self):
        self.log.clear()
        for attr in ["plaintext_val", "aeskey_val", "hash_local_val",
                     "hash_recv_val", "hash_match_val", "sig_val"]:
            getattr(self, attr).config(text="—", fg=THEME["text_dim"])
        self.verdict_lbl.config(text="Menunggu pesan...", fg=THEME["text_dim"])

    def _set_status(self, online: bool):
        if online:
            self.status_lbl.config(text=" ● ONLINE ", bg=THEME["bob_accent"], fg="#0d1117")
        else:
            self.status_lbl.config(text=" ● OFFLINE ", bg=THEME["border"], fg=THEME["text_dim"])

    def _on_message_received(self, result):
        """Dipanggil dari thread Bob — jadwalkan update UI ke main thread."""
        self.app.root.after(0, lambda: self._display_result(result))

    def _display_result(self, result):
        self.log.clear()
        self.log.line("━━━ BOB: Pesan Diterima ━━━", "accent")

        for entry in result.log:
            if "ERROR" in entry:
                self.log.line(f"  {entry}", "err")
            elif "✓" in entry:
                self.log.line(f"  {entry}", "ok")
            elif "✗" in entry:
                self.log.line(f"  {entry}", "err")
            elif "Hash" in entry and ("dihitung" in entry or "diterima" in entry):
                self.log.line(f"  {entry}", "val")
            elif "AES Key" in entry:
                self.log.line(f"  {entry}", "key")
            elif "Plaintext" in entry:
                self.log.line(f"  {entry}", "hi")
            else:
                self.log.line(f"  {entry}", "info")

        # Update result fields
        def _set(widget, text, ok=None):
            fg = THEME["text"]
            if ok is True:
                fg = THEME["tag_ok"]
            elif ok is False:
                fg = THEME["tag_err"]
            widget.config(text=text, fg=fg)

        _set(self.plaintext_val, result.plaintext or result.error)
        aes_preview = (result.aes_key_hex[:32] + "...") if result.aes_key_hex else "—"
        _set(self.aeskey_val, aes_preview)
        _set(self.hash_local_val, (result.computed_hash_hex[:32] + "...") if result.computed_hash_hex else "—")
        _set(self.hash_recv_val, (result.received_hash_hex[:32] + "...") if result.received_hash_hex else "—")
        _set(self.hash_match_val,
             "✓ VALID — Pesan tidak dimodifikasi" if result.hash_match else "✗ INVALID — Pesan mungkin dimodifikasi",
             ok=result.hash_match)
        _set(self.sig_val,
             "✓ VALID — Pengirim terverifikasi (Alice)" if result.signature_valid else "✗ INVALID — Pengirim tidak dikenal",
             ok=result.signature_valid)

        # Verdict
        if result.success:
            self.verdict_lbl.config(
                text="✓  PESAN SAH  —  Dekripsi berhasil · Integritas terjaga · Pengirim Alice terverifikasi",
                fg=THEME["tag_ok"]
            )
        else:
            self.verdict_lbl.config(
                text="✗  PESAN TIDAK SAH  —  Gagal verifikasi",
                fg=THEME["tag_err"]
            )


# ════════════════════════════════════════════════════════════════════════════
#  MAIN APP
# ════════════════════════════════════════════════════════════════════════════

class App:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("End-to-End Secure Message Delivery  ·  II3230 Keamanan Informasi")
        self.root.configure(bg=THEME["bg"])
        self.root.geometry("1340x860")
        self.root.minsize(1100, 720)

        self.keys = None
        self._alice_cache: dict[tuple, Alice] = {}

        self._setup_style()
        self._build_header()
        self._build_main()
        self._build_footer()
        self._init_keys()

    def _setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Vertical.TScrollbar",
                        background=THEME["border"],
                        troughcolor=THEME["bg"],
                        bordercolor=THEME["bg"],
                        arrowcolor=THEME["text_dim"])
        style.configure("Horizontal.TScrollbar",
                        background=THEME["border"],
                        troughcolor=THEME["bg"],
                        bordercolor=THEME["bg"],
                        arrowcolor=THEME["text_dim"])

    def _build_header(self):
        hdr = tk.Frame(self.root, bg="#0a0e14", pady=0)
        hdr.pack(fill="x")

        # Color bar
        bar = tk.Frame(hdr, height=3, bg="#0d1117")
        bar.pack(fill="x")
        for color in [THEME["alice_accent"], "#30363d", THEME["bob_accent"]]:
            tk.Frame(bar, bg=color, height=3, width=self.root.winfo_screenwidth()//3).pack(side="left", fill="y")

        content = tk.Frame(hdr, bg="#0a0e14")
        content.pack(fill="x", padx=20, pady=12)

        title = tk.Label(content,
                         text="End-to-End Secure Message Delivery",
                         font=("Consolas", 16, "bold"),
                         fg=THEME["text"], bg="#0a0e14")
        title.pack(side="left")

        sub = tk.Label(content,
                       text="II3230 Keamanan Informasi  ·  AES-256-CBC · RSA-2048-OAEP · SHA-256 · RSA-PSS",
                       font=FONTS["ui_sm"], fg=THEME["text_dim"], bg="#0a0e14")
        sub.pack(side="left", padx=20)

        self.key_status_lbl = tk.Label(content, text="⏳ Loading keys...",
                                       font=FONTS["badge"],
                                       fg=THEME["warning"], bg="#0a0e14")
        self.key_status_lbl.pack(side="right")

    def _build_main(self):
        main = tk.Frame(self.root, bg=THEME["bg"])
        main.pack(fill="both", expand=True, padx=8, pady=8)

        # Left: Alice
        alice_outer = tk.Frame(main, bg=THEME["border"], bd=0)
        alice_outer.pack(side="left", fill="both", expand=True, padx=(0, 4))
        self.alice_panel = AlicePanel(alice_outer, self)
        self.alice_panel.pack(fill="both", expand=True)

        # Right: Bob
        bob_outer = tk.Frame(main, bg=THEME["border"], bd=0)
        bob_outer.pack(side="left", fill="both", expand=True, padx=(4, 0))
        self.bob_panel = BobPanel(bob_outer, self)
        self.bob_panel.pack(fill="both", expand=True)

    def _build_footer(self):
        footer = tk.Frame(self.root, bg="#0a0e14", pady=6)
        footer.pack(fill="x", side="bottom")
        tk.Label(footer,
                 text="II3230 Keamanan Informasi K03  ·  Dr. Phil. Eng. Hari Purnama, S.Si., M.Si.  ·  2026",
                 font=FONTS["ui_sm"], fg=THEME["text_dim"], bg="#0a0e14"
                 ).pack()

    def _init_keys(self):
        def _run():
            try:
                keys = setup_all_keys()
                self.keys = keys
                self.root.after(0, lambda: self.key_status_lbl.config(
                    text="✓ RSA Keys Ready (2048-bit)",
                    fg=THEME["tag_ok"]
                ))
            except Exception as e:
                self.root.after(0, lambda: self.key_status_lbl.config(
                    text=f"✗ Key Error: {e}", fg=THEME["tag_err"]
                ))

        threading.Thread(target=_run, daemon=True).start()

    def get_alice(self, alice_ip: str, bob_ip: str) -> Alice:
        """Return (cached) Alice instance untuk IP combo."""
        if not self.keys:
            raise RuntimeError("Keys not ready")
        key = (alice_ip, bob_ip)
        if key not in self._alice_cache:
            self._alice_cache[key] = Alice(
                private_key=self.keys["alice_private"],
                public_key=self.keys["alice_public"],
                bob_public_key=self.keys["bob_public"],
                alice_ip=alice_ip,
                bob_ip=bob_ip,
            )
        return self._alice_cache[key]

    def run(self):
        self.root.mainloop()


# ════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    app = App()
    app.run()
