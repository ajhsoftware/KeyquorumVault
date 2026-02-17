from __future__ import annotations
# pip install reportlab qrcode[pil] pyotp
from qtpy.QtWidgets import (
    QDialog, QVBoxLayout, QLabel, QTextEdit, QHBoxLayout, QPushButton, QFileDialog, QMessageBox
)
from qtpy.QtGui import QTextOption
from qtpy.QtPrintSupport import QPrinter, QPrintDialog

class EmergencyKitDialog(QDialog):
    """
    Shows one-time recovery materials; lets the user Print or Save a PDF.
    - "Save PDF…" (full) uses reportlab + qrcode (embeds QR if provided).
    - "Quick PDF" is a text-only PDF via Qt (no external deps, no QR images).
    Caller MUST pass plaintext values in; never read from DB here.
    """
    def __init__(
        self,
        parent,
        *,
        username: str,
        app_version: str,
        recovery_key: str | None,
        recovery_backup_codes: list[str] | None,
        twofa_backup_codes: list[str] | None,
        totp_uri: str | None = None,
        totp_secret_hint: str | None = None,
        totp_qr_png: bytes | None = None,
    ):
        super().__init__(parent)
        self.setWindowTitle(self.tr("Emergency Kit — Save / Print"))
        self.setMinimumWidth(720)

        self.username = username
        self.app_version = app_version
        self.recovery_key = recovery_key
        self.recovery_backup_codes = (recovery_backup_codes or []).copy()
        self.twofa_backup_codes = (twofa_backup_codes or []).copy()
        self.totp_uri = totp_uri
        self.totp_secret_hint = totp_secret_hint
        self.totp_qr_png = totp_qr_png

        v = QVBoxLayout(self)
        warn = QLabel(self.tr("⚠️ Anyone with this sheet can access your account. Store it offline (printed and in a safe)."))
        v.addWidget(warn)

        # Read-only preview
        self.preview = QTextEdit(self)
        self.preview.setReadOnly(True)
        self.preview.setWordWrapMode(QTextOption.WrapMode.WordWrap)
        self.preview.setPlainText(self._make_preview_text())
        v.addWidget(self.preview, 1)

        # Buttons row
        btns = QHBoxLayout()
        self.btn_print = QPushButton(self.tr("Print…"), self)
        self.btn_save_pdf = QPushButton(self.tr("Save PDF… (full)"), self)     # reportlab path (with QR)
        self.btn_quick_pdf = QPushButton(self.tr("Quick PDF (text-only)"), self)  # Qt-only (no deps)
        self.btn_close = QPushButton(self.tr("Done"), self)
        btns.addWidget(self.btn_print)
        btns.addWidget(self.btn_save_pdf)
        btns.addWidget(self.btn_quick_pdf)
        btns.addStretch(1)
        btns.addWidget(self.btn_close)
        v.addLayout(btns)

        try:
            from app.basic import is_dev
            # Diagnose
            if is_dev:
                self.btn_diag = QPushButton(self.tr("Diagnose…"), self)
                btns.addWidget(self.btn_diag)
                self.btn_diag.clicked.connect(self._on_diag)
        except Exception as e:
            pass # no dev ok

        self.btn_print.clicked.connect(self._on_print)
        self.btn_save_pdf.clicked.connect(self._on_save_pdf_full)
        self.btn_quick_pdf.clicked.connect(self._on_save_pdf_quick)
        self.btn_close.clicked.connect(self.accept)

    def _make_preview_text(self) -> str:
        lines = []
        lines.append(self.tr("Keyquorum Vault — Emergency Kit"))
        lines.append(self.tr("Username") + f": {self.username}")
        lines.append(self.tr("App Version") + f": {self.app_version}")
        lines.append("")
        if self.recovery_key:
            lines.append(self.tr("Recovery Key (one-time):"))
            lines.append(self.recovery_key)
            lines.append("")
        if self.recovery_backup_codes:
            lines.append(self.tr("Recovery Backup Codes (use with Recovery Key):"))
            for i, c in enumerate(self.recovery_backup_codes, 1):
                lines.append(f"  {i}. {c}")
            lines.append("")
        if self.twofa_backup_codes:
            lines.append(self.tr("2FA Backup Codes (login fallback):"))
            for i, c in enumerate(self.twofa_backup_codes, 1):
                lines.append(f"  {i}. {c}")
            lines.append("")
        if self.totp_uri or self.totp_secret_hint or self.totp_qr_png:
            lines.append(self.tr("Two-Factor Authenticator (TOTP):"))
            if self.totp_secret_hint:
                lines.append(f"  Secret (hint): {self.totp_secret_hint}")
            lines.append(self.tr("  (QR will be embedded in the full PDF)"))
            lines.append("")
        lines.append(self.tr("Guidance:"))
        lines.append(self.tr("• Print and store securely; avoid digital copies/cloud."))
        lines.append(self.tr("• Recovery codes are for password reset (with Recovery Key)."))
        lines.append(self.tr("• 2FA backup codes are for login if your authenticator is unavailable."))
        lines.append(self.tr("• Never share this with anyone. Keyquorum will never ask for it."))
        return "\n".join(lines)

    # --- Actions -----------------


    def _save_pdf_full_to_path(self, path: str, *, show_saved_message: bool = True) -> bool:
        """Build the full Emergency Kit PDF (reportlab) to a specific path."""
        import sys
        try:
            from auth.emergency_kit.emergency_kit import build_emergency_kit_pdf
        except Exception as e:
            QMessageBox.critical(
                self,
                self.tr("Missing dependency"),
                self.tr(
                    "Full PDF requires 'reportlab' and (optionally) 'qrcode'.\n"
                    "Install with: pip install reportlab qrcode[pil]\n\n"
                    "Import failed:\n{err}\n\n"
                    "Python: {py}\n\n"
                    "Tip: click 'Diagnose…' for details."
                ).format(err=e, py=sys.executable),
            )
            return False

        try:
            build_emergency_kit_pdf(
                path,
                username=self.username,
                app_version=self.app_version,
                recovery_key=self.recovery_key,
                recovery_backup_codes=self.recovery_backup_codes,
                twofa_backup_codes=self.twofa_backup_codes,
                totp_uri=self.totp_uri,
                totp_secret_hint=self.totp_secret_hint,
                totp_qr_png=self.totp_qr_png,
            )
        except Exception as e:
            QMessageBox.critical(
                self,
                self.tr("Save failed"),
                self.tr("Could not save PDF:\n{err}").format(err=e),
            )
            return False

        if show_saved_message:
            QMessageBox.information(
                self,
                self.tr("Saved"),
                self.tr("Emergency Kit saved to") + f":\n{path}",
            )
        return True

    def _on_print(self):
        """
        Print the FULL Emergency Kit (same layout as Save PDF… full).
        We generate the full PDF to a temporary file, then send that PDF to the printer.
        """
        try:
            import os
            import tempfile
            import time
            from pathlib import Path

            tmp_dir = Path(tempfile.gettempdir()) / "Keyquorum"
            tmp_dir.mkdir(parents=True, exist_ok=True)

            ts = time.strftime("%Y%m%d-%H%M%S")
            tmp_pdf = tmp_dir / f"Keyquorum_EmergencyKit_{self.username}_{ts}.pdf"

            ok = self._save_pdf_full_to_path(str(tmp_pdf), show_saved_message=False)
            if not ok:
                return

            if os.name == "nt":
                try:
                    os.startfile(str(tmp_pdf), "print")
                except Exception as e:
                    QMessageBox.warning(
                        self,
                        self.tr("Print"),
                        self.tr("Could not send to printer automatically."
                            "The full PDF was created here:{p}"
                            "Open it and print from your PDF viewer."
                            "Error: {e}"
                        ).format(p=str(tmp_pdf), e=str(e)),
                    )
                    return
            else:
                # Cross-platform: open the PDF for the user to print from their viewer
                try:
                    from qtpy.QtCore import QUrl
                    from qtpy.QtGui import QDesktopServices
                    QDesktopServices.openUrl(QUrl.fromLocalFile(str(tmp_pdf)))
                except Exception:
                    pass
                QMessageBox.information(
                    self,
                    self.tr("Print"),
                    self.tr("The full PDF has been created. Please print it from your PDF viewer:") + f"{tmp_pdf}",
                )

        except Exception as e:
            QMessageBox.critical(self, self.tr("Print failed"), self.tr("Error: {e}").format(e=str(e)))

    def _on_save_pdf_full(self):
        """Full PDF via reportlab (with QR images if available)."""
        default = f"Keyquorum_EmergencyKit_{self.username}.pdf"
        path, _ = QFileDialog.getSaveFileName(self, self.tr("Save Emergency Kit (PDF)"), default, self.tr("PDF Files (*.pdf)"))
        if not path:
            return
        if not path.lower().endswith(".pdf"):
            path += ".pdf"
        
        ok = self._save_pdf_full_to_path(path, show_saved_message=True)
        if not ok:
            return
    
    def _on_save_pdf_quick(self):
        """
        Qt-only text PDF (no external packages, no QR images).
        Uses the preview text as the PDF contents.
        """
        default = f"EmergencyKit_{self.username}.pdf"
        path, _ = QFileDialog.getSaveFileName(self, self.tr("Save Quick PDF (text only)"), default, self.tr("PDF Files ") + "(*.pdf)")
        if not path:
            return
        if not path.lower().endswith(".pdf"):
            path += ".pdf"

        printer = QPrinter(QPrinter.PrinterMode.HighResolution)
        printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
        printer.setOutputFileName(path)
        # Wider page helps readability
        printer.setPageMargins(12, 12, 12, 12, QPrinter.Unit.Millimeter)
        self.preview.document().print_(printer)
        QMessageBox.information(
            self,
            "Saved",
            "Emergency Kit (text-only) saved to" + f":\n{path}"
        )

    def _on_diag(self):
        import sys, traceback
        from qtpy.QtWidgets import QMessageBox
        details = []
        details.append(f"sys.executable: {sys.executable}")
        details.append(f"sys.path[0:5]: {sys.path[:5]}")

        # Try importing reportlab + qrcode and show versions + file locations
        try:
            import importlib.metadata as m
            rl_ver = m.version("reportlab")
        except Exception:
            rl_ver = "n/a"
        try:
            import reportlab
            details.append(f"reportlab: version={getattr(reportlab, 'Version', 'n/a')} file={getattr(reportlab, '__file__', 'n/a')}")
            details.append(f"reportlab (pkg ver): {rl_ver}")
        except Exception as e:
            details.append(f"reportlab import FAILED: {e}")

        try:
            import importlib.metadata as m
            qr_ver = m.version("qrcode")
        except Exception:
            qr_ver = "n/a"
        try:
            import qrcode
            details.append(f"qrcode: file={getattr(qrcode, '__file__', 'n/a')}")
            details.append(f"qrcode (pkg ver): {qr_ver}")
        except Exception as e:
            details.append(f"qrcode import FAILED: {e}")
        try:
            from auth.emergency_kit.emergency_kit import build_emergency_kit_pdf  # noqa
            details.append(self.tr("emergency_kit import: OK"))
        except Exception as e:
            details.append(self.tr("emergency_kit import FAILED:") + f" {e}")

        QMessageBox.information(
            self,
            self.tr("PDF Diagnostics"),
            "\n".join(details)
        )
