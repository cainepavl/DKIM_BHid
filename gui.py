import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import os

import dkim_verifier

# ── Theme palettes ──────────────────────────────────────────────────
DARK = {
    "bg":        "#0a0a0a",
    "fg":        "#00ff41",
    "fg_dim":    "#00882a",
    "fg_err":    "#ff3333",
    "pass_bg":   "#003300",
    "pass_fg":   "#00ff41",
    "fail_bg":   "#330000",
    "fail_fg":   "#ff3333",
    "btn_bg":    "#111111",
    "btn_fg":    "#00ff41",
    "btn_act":   "#001a00",
    "sep":       "#003300",
    "font":      ("Courier New", 14, "bold"),
    "font_b":    ("Courier New", 14, "bold"),
    "font_mono": ("Courier New", 13, "bold"),
}

LIGHT = {
    "bg":        "#f2f2f2",
    "fg":        "#1a1a1a",
    "fg_dim":    "#666666",
    "fg_err":    "#b71c1c",
    "pass_bg":   "#2e7d32",
    "pass_fg":   "#ffffff",
    "fail_bg":   "#c62828",
    "fail_fg":   "#ffffff",
    "btn_bg":    "#dcdcdc",
    "btn_fg":    "#1a1a1a",
    "btn_act":   "#b0b0b0",
    "sep":       "#cccccc",
    "font":      ("TkDefaultFont", 12, "bold"),
    "font_b":    ("TkDefaultFont", 12, "bold"),
    "font_mono": ("TkFixedFont", 11),
}


# ── Pill toggle switch ──────────────────────────────────────────────
class PillSwitch(tk.Canvas):
    W, H = 46, 22

    def __init__(self, parent, on_toggle, **kw):
        super().__init__(parent, width=self.W, height=self.H,
                         bd=0, highlightthickness=0, cursor="hand2", **kw)
        self._on = False
        self._cb = on_toggle
        self.bind("<Button-1>", lambda _e: self._flip())
        self._redraw()

    def _flip(self):
        self._on = not self._on
        self._redraw()
        self._cb(self._on)

    def set(self, on: bool):
        if self._on != on:
            self._on = on
            self._redraw()

    def _redraw(self):
        self.delete("all")
        w, h, r = self.W, self.H, self.H // 2
        track = "#00ff41" if self._on else "#444444"
        # track pill
        self.create_oval(0, 0, h, h, fill=track, outline="")
        self.create_rectangle(r, 0, w - r, h, fill=track, outline="")
        self.create_oval(w - h, 0, w, h, fill=track, outline="")
        # knob
        kx = w - r - 1 if self._on else r + 1
        self.create_oval(kx - r + 3, 3, kx + r - 3, h - 3, fill="white", outline="")

    def apply_bg(self, bg: str):
        self.configure(bg=bg)
        self._redraw()


# ── Main app ────────────────────────────────────────────────────────
class DKIMVerifierApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("DKIM Verifier")
        self.minsize(820, 640)
        self.geometry("900x680")
        self._dark = False
        self._t = LIGHT
        self._result: dict | None = None
        self._build_ui()
        self._apply_theme()

    # ── UI construction ─────────────────────────────────────────────

    def _build_ui(self):
        self.configure(padx=14, pady=14)

        # Theme-able widget buckets
        self._bg_only: list  = []   # bg only
        self._fg_lbl:  list  = []   # bg + fg (normal text)
        self._dim_lbl: list  = []   # bg + fg_dim
        self._btn_lst: list  = []   # buttons
        self._sep_lst: list  = []   # 1-px separator frames
        self._lf_lst:  list  = []   # LabelFrames (bg + fg)
        self._mono_lbl: list = []   # monospace value labels

        # ── Top bar ─────────────────────────────────────────────────
        top = self._frame()
        top.pack(fill="x", pady=(0, 10))

        self._btn_load = self._button(top, "Load .eml File", self._load_file)
        self._btn_load.pack(side="left")
        self._btn_clear = self._button(top, "Clear", self._clear)
        self._btn_clear.pack(side="left", padx=6)

        self._file_label = self._label(top, "No file loaded", dim=True)
        self._file_label.pack(side="left", padx=10)

        # Theme toggle (right-aligned)
        toggle_frame = self._frame(top)
        toggle_frame.pack(side="right")
        self._toggle_lbl = self._label(toggle_frame, "DARK", dim=True)
        self._toggle_lbl.pack(side="left", padx=(0, 6))
        self._toggle = PillSwitch(toggle_frame, self._on_toggle)
        self._bg_only.append(self._toggle)
        self._toggle.pack(side="left")

        # ── Signature Info ──────────────────────────────────────────
        info_lf = self._labelframe("Signature Info")
        info_lf.pack(fill="x", pady=(0, 10))
        info_lf.columnconfigure(1, weight=1)

        self._info_vars: dict = {}
        for i, (lbl_text, key) in enumerate([
            ("Domain (d=):",     "domain"),
            ("Selector (s=):",   "selector"),
            ("Algorithm:",       "algorithm"),
            ("Canonicalization:","canonicalization"),
            ("From:",            "from"),
            ("Signed Headers:",  "signed_headers"),
        ]):
            lbl = self._label(info_lf, lbl_text, dim=True)
            lbl.configure(width=20, anchor="e")
            lbl.grid(row=i, column=0, sticky="e", pady=1, padx=(0, 6))

            var = tk.StringVar(value="—")
            self._info_vars[key] = var
            val_lbl = self._label(info_lf, "", var=var)
            val_lbl.configure(anchor="w", wraplength=520)
            val_lbl.grid(row=i, column=1, sticky="w")

        # ── Verification Results ─────────────────────────────────────
        res_lf = self._labelframe("Verification Results")
        res_lf.pack(fill="both", expand=True, pady=(0, 10))

        # bh= row
        bh_row = self._frame(res_lf)
        bh_row.pack(fill="x", pady=(0, 4))
        bh_title = self._label(bh_row, "Body Hash (bh=):", bold=True)
        bh_title.pack(side="left")
        self._bh_badge = tk.Label(bh_row, text="  —  ", relief="flat")
        self._bh_badge.pack(side="left", padx=(10, 0))

        bh_detail = self._frame(res_lf)
        bh_detail.pack(fill="x", padx=24, pady=(0, 4))
        self._label(bh_detail, "Expected:", dim=True, width=10, anchor="w").grid(
            row=0, column=0, sticky="w")
        self._bh_expected = self._label(bh_detail, "—", mono=True)
        self._bh_expected.configure(anchor="w", wraplength=520)
        self._bh_expected.grid(row=0, column=1, sticky="w")
        self._label(bh_detail, "Computed:", dim=True, width=10, anchor="w").grid(
            row=1, column=0, sticky="w")
        self._bh_computed = self._label(bh_detail, "—", mono=True)
        self._bh_computed.configure(anchor="w", wraplength=520)
        self._bh_computed.grid(row=1, column=1, sticky="w")

        sep = self._sep(res_lf)
        sep.pack(fill="x", pady=8)

        # b= row
        b_row = self._frame(res_lf)
        b_row.pack(fill="x", pady=(0, 4))
        b_title = self._label(b_row, "Signature  (b=):", bold=True)
        b_title.pack(side="left")
        self._b_badge = tk.Label(b_row, text="  —  ", relief="flat")
        self._b_badge.pack(side="left", padx=(10, 0))

        self._b_detail = self._label(res_lf, "", dim=True)
        self._b_detail.configure(anchor="w", wraplength=620)
        self._b_detail.pack(fill="x", padx=24)

        # ── Status bar ───────────────────────────────────────────────
        self._sep(self).pack(fill="x", pady=(0, 6))
        self._status_var = tk.StringVar(value="Ready — open an .eml file to begin")
        status_lbl = self._label(self, "", var=self._status_var, dim=True)
        status_lbl.configure(anchor="w")
        status_lbl.pack(fill="x")

    # ── Widget factory helpers ──────────────────────────────────────

    def _frame(self, parent=None) -> tk.Frame:
        f = tk.Frame(parent or self)
        self._bg_only.append(f)
        return f

    def _label(self, parent, text, *, var=None, dim=False, bold=False,
               mono=False, width=None, anchor=None) -> tk.Label:
        kw: dict = {"text": text, "anchor": anchor or "w"}
        if var:
            kw["textvariable"] = var
        if width:
            kw["width"] = width
        lbl = tk.Label(parent, **kw)
        if mono:
            self._mono_lbl.append(lbl)
        elif dim:
            self._dim_lbl.append(lbl)
        else:
            self._fg_lbl.append(lbl)
        return lbl

    def _button(self, parent, text, cmd) -> tk.Button:
        btn = tk.Button(parent, text=text, command=cmd, relief="flat",
                        padx=10, pady=4, cursor="hand2")
        self._btn_lst.append(btn)
        return btn

    def _labelframe(self, title) -> tk.LabelFrame:
        lf = tk.LabelFrame(self, text=title, padx=10, pady=8)
        self._lf_lst.append(lf)
        return lf

    def _sep(self, parent) -> tk.Frame:
        s = tk.Frame(parent, height=1)
        self._sep_lst.append(s)
        return s

    # ── Theming ─────────────────────────────────────────────────────

    def _on_toggle(self, on: bool):
        self._dark = on
        self._apply_theme()

    def _apply_theme(self):
        t = DARK if self._dark else LIGHT
        self._t = t
        bg, fg, fd, fb = t["bg"], t["fg"], t["fg_dim"], t["font_b"]

        self.configure(bg=bg)

        for w in self._bg_only:
            w.configure(bg=bg)
        for w in self._fg_lbl:
            w.configure(bg=bg, fg=fg, font=t["font"])
        for w in self._dim_lbl:
            w.configure(bg=bg, fg=fd, font=t["font"])
        for w in self._mono_lbl:
            w.configure(bg=bg, fg=fg, font=t["font_mono"])
        for w in self._btn_lst:
            w.configure(bg=t["btn_bg"], fg=t["btn_fg"], font=t["font"],
                        activebackground=t["btn_act"], activeforeground=t["btn_fg"])
        for w in self._sep_lst:
            w.configure(bg=t["sep"])
        for w in self._lf_lst:
            w.configure(bg=bg, fg=fg, font=fb)

        self._toggle.apply_bg(bg)
        self._toggle_lbl.configure(bg=bg, fg=fd, font=t["font"])

        # Bold labels need font_b
        for attr in ("_bh_badge", "_b_badge"):
            badge = getattr(self, attr)
            badge.configure(font=fb)

        # Re-apply badge colors using current result state
        self._reapply_badges()

    def _reapply_badges(self):
        """Recolor badges to match current result after a theme switch."""
        t = self._t
        bg = t["bg"]
        for badge in (self._bh_badge, self._b_badge):
            text = badge.cget("text").strip()
            if text == "PASS":
                badge.configure(bg=t["pass_bg"], fg=t["pass_fg"])
            elif text == "FAIL":
                badge.configure(bg=t["fail_bg"], fg=t["fail_fg"])
            else:
                badge.configure(bg=bg, fg=t["fg_dim"])

        # b_detail error color
        if self._result and self._result.get("b_pass") is False:
            self._b_detail.configure(fg=t["fg_err"])

    # ── Actions ─────────────────────────────────────────────────────

    def _load_file(self):
        path = filedialog.askopenfilename(
            title="Open Email File",
            filetypes=[("Email files", "*.eml"), ("All files", "*.*")],
        )
        if not path:
            return
        self._file_label.configure(text=os.path.basename(path))
        self._status_var.set("Verifying — DNS lookup may take a moment…")
        self._clear_results()
        threading.Thread(target=self._run_verify, args=(path,), daemon=True).start()

    def _run_verify(self, path):
        try:
            result = dkim_verifier.verify_email(path)
            self.after(0, self._show_result, result)
        except Exception as exc:
            self.after(0, self._show_error, str(exc))

    def _show_result(self, r: dict):
        self._result = r
        t = self._t

        for key, var in self._info_vars.items():
            var.set(r.get(key) or "—")

        self._bh_expected.configure(text=r.get("bh_expected") or "—")
        self._bh_computed.configure(text=r.get("bh_computed") or "—")
        self._set_badge(self._bh_badge, r["bh_pass"])

        b_pass = r["b_pass"]
        if b_pass is True:
            self._set_badge(self._b_badge, True)
            self._b_detail.configure(
                text=f"Key fetched from {r['selector']}._domainkey.{r['domain']}",
                fg=t["fg_dim"])
        elif b_pass is False:
            self._set_badge(self._b_badge, False)
            self._b_detail.configure(
                text=r.get("b_error") or "Verification failed",
                fg=t["fg_err"])
        else:
            self._b_badge.configure(text="  SKIP  ", bg=t["bg"], fg=t["fg_dim"])
            self._b_detail.configure(text="", fg=t["fg_dim"])

        if r["bh_pass"] and b_pass is True:
            summary = "All checks PASSED"
        elif r["bh_pass"] and b_pass is False:
            summary = "Body hash PASSED  |  Signature FAILED (see error above)"
        elif not r["bh_pass"]:
            summary = "Body hash FAILED"
        else:
            summary = "Body hash PASSED  |  Signature skipped"
        self._status_var.set(summary)

    def _set_badge(self, badge: tk.Label, passed: bool):
        t = self._t
        if passed:
            badge.configure(text="  PASS  ", bg=t["pass_bg"], fg=t["pass_fg"])
        else:
            badge.configure(text="  FAIL  ", bg=t["fail_bg"], fg=t["fail_fg"])

    def _show_error(self, msg: str):
        self._status_var.set(f"Error: {msg}")
        messagebox.showerror("Verification Error", msg)

    def _clear_results(self):
        self._result = None
        t = self._t
        for var in self._info_vars.values():
            var.set("—")
        self._bh_expected.configure(text="—")
        self._bh_computed.configure(text="—")
        for badge in (self._bh_badge, self._b_badge):
            badge.configure(text="  —  ", bg=t["bg"], fg=t["fg_dim"])
        self._b_detail.configure(text="", fg=t["fg_dim"])

    def _clear(self):
        self._file_label.configure(text="No file loaded")
        self._status_var.set("Ready — open an .eml file to begin")
        self._clear_results()


if __name__ == "__main__":
    app = DKIMVerifierApp()
    app.mainloop()
