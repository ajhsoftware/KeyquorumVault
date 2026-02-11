"""
Keyquorum Vault
Copyright (C) 2025-2026 Anthony Hatton (AJH Software)

This file is part of Keyquorum Vault.

Keyquorum Vault is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Keyquorum Vault is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import io
import json
import os
import re
from typing import Optional

from .types import ParsedKit, AccountSnapshot

try:
    from qtpy.QtCore import QCoreApplication  # type: ignore
    def _tr(text: str) -> str:
        return QCoreApplication.translate("emergency_kit", text)
except Exception:  # pragma: no cover
    def _tr(text: str) -> str:
        return text

# ReportLab is required for "full" Emergency Kit PDF generation.
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    Flowable,
    Image,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# Optional icon resolver from your app
try:
    from app.paths import icon_file  # type: ignore
except Exception:  # pragma: no cover
    icon_file = None  # type: ignore


# ----------------------------- public API ----------------------------------

def build_emergency_kit_pdf(
    path: str,
    *,
    username: str,
    app_version: str,
    recovery_key: Optional[str],
    include_recovery_qr: bool = False,  # opt-in: less secure
    recovery_backup_codes: Optional[list[str]] = None,
    twofa_backup_codes: Optional[list[str]] = None,
    totp_uri: Optional[str] = None,          # DEPRECATED/ignored for safety
    totp_secret_hint: Optional[str] = None,  # masked hint only (not stored in payload)
    totp_qr_png: Optional[bytes] = None,     # preferred if you explicitly want a reference QR
    logo_path: Optional[str] = None,         # optional override; auto-resolves if None
    watermark_opacity: float = 0.10,
) -> str:
    """
    Generate a branded Emergency Kit PDF and save to `path`.

    Security posture:
      - NEVER accepts or prints a raw TOTP secret/URI by default.
      - totp_uri is deprecated/ignored; provide totp_qr_png explicitly if you want a reference QR.
      - Payload contains *no* TOTP secret material.
      - Recovery Key QR is OFF by default (must opt-in).

    Returns:
      The output path (same as `path`).
    """
    recovery_backup_codes = list(recovery_backup_codes or [])
    twofa_backup_codes = list(twofa_backup_codes or [])

    # Resolve default logo if not provided
    if not logo_path and icon_file is not None:
        try:
            logo_path = icon_file("icon.png")
        except Exception:
            logo_path = None

    doc = SimpleDocTemplate(
        path,
        pagesize=A4,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    # Minimise metadata at creation time
    doc.title = "Document"
    doc.author = ""
    doc.subject = ""
    doc.creator = ""
    doc.producer = ""

    styles = getSampleStyleSheet()
    H1 = styles["Title"]
    H2 = styles["Heading2"]
    NORMAL = styles["BodyText"]
    SMALL = ParagraphStyle("Small", parent=NORMAL, fontSize=8, leading=10, textColor=colors.grey)

    class Watermark(Flowable):
        def __init__(self, text: str = "Keyquorum Vault", opacity: float = watermark_opacity):
            super().__init__()
            self.text = text
            self.opacity = opacity

        def draw(self):
            c = self.canv
            c.saveState()
            c.setFillGray(0, self.opacity)
            c.setFont("Helvetica-Bold", 72)
            c.rotate(30)
            c.drawString(80, 0, self.text)
            c.restoreState()

    elements: list[object] = [Watermark()]

    # Header logo
    if logo_path and os.path.exists(logo_path):
        try:
            elements.append(Image(logo_path, width=64, height=64))
            elements.append(Spacer(1, 6))
        except Exception:
            pass

    elements.append(Paragraph(_tr("Keyquorum Vault — Emergency Kit"), H1))

    generated_iso = _now_utc_iso()
    meta = (
        _tr("Username:") + f" <b>{_esc(username)}</b> • "
        + _tr("App Version:") + f" <b>{_esc(app_version)}</b> • "
        + _tr("Generated:") + f" {_esc(generated_iso)}"
    )
    elements.append(Paragraph(meta, SMALL))
    elements.append(Spacer(1, 8))

    # Machine-readable Emergency Kit ID (QR + hidden text marker)
    kit_payload = _build_kit_payload(
        username=username,
        app_version=app_version,
        generated_iso=generated_iso,
        recovery_key=recovery_key,
        recovery_backup_codes=recovery_backup_codes,
        twofa_backup_codes=twofa_backup_codes,
    )
    elements.append(Paragraph(_tr("Emergency Kit ID (for migration / update)"), SMALL))
    qr_flow = _qr_image(kit_payload, box_size=4, size_px=120)
    if qr_flow is not None:
        elements.append(qr_flow)
    else:
        elements.append(Paragraph(_tr("QR generation unavailable (missing qrcode)."), SMALL))
    # Hidden machine-readable line (tiny white text, but visible to PDF text extractors)
    elements.append(Paragraph(f"<font size=1 color='#FFFFFF'>{_esc(kit_payload)}</font>", SMALL))
    elements.append(Spacer(1, 12))
    elements.append(
        _warn_box(
            _tr(
                "⚠️ CRITICAL SECURITY WARNING ⚠️\n\n"
                "This document contains account recovery material. Anyone who can read or photograph it may be able to access your vault.\n\n"
                "REQUIRED:\n"
                "• Print immediately (avoid saving to disk/cloud)\n"
                "• Store in a physical safe / secure location\n"
                "• Do not photograph, scan, email, or upload\n"
                "• If you suspect exposure: rotate salt, change your password, and regenerate Recovery Key and Backup Codes\n"
                "  (Settings → Profile → Change Password)\n"
            )
        )
    )
    elements.append(Spacer(1, 12))
    # Recovery Key
    if recovery_key:
        elements.append(Paragraph(_tr("Recovery Key (one-time)"), H2))
        elements.append(_highlight_box(f"<font size=12><b>{_esc(recovery_key)}</b></font>"))
        elements.append(Spacer(1, 6))
        # Fingerprint (first 16 hex chars of SHA-256)
        try:
            fp16 = hashlib.sha256(recovery_key.encode("utf-8")).hexdigest()[:16]
            elements.append(Paragraph(_tr("Fingerprint ") + f"(SHA-256, first 16): <b>{fp16}</b>", SMALL))
        except Exception:
            pass
        elements.append(Spacer(1, 12))

        # Optional QR of recovery key (convenience, less secure) — OFF by default
        if include_recovery_qr:
            elements.append(_warn_box(_tr(
                "⚠️ WARNING: This QR contains your unencrypted Recovery Key.\n"
                "Anyone who photographs this page can scan it and access your account."
            )))
            elements.append(Spacer(1, 6))
            elements.append(Paragraph(_tr("QR of Recovery Key (less secure)"), SMALL))
            rk_qr = _qr_image(recovery_key, box_size=6, size_px=200)
            if rk_qr is not None:
                elements.append(rk_qr)
            else:
                elements.append(Paragraph(_tr("QR generation unavailable (missing qrcode)."), SMALL))
            elements.append(Spacer(1, 12))

    # Recovery Backup Codes
    if recovery_backup_codes:
        elements.append(Paragraph(_tr("Recovery Backup Codes (use with Recovery Key)"), H2))
        elements.append(_codes_table(recovery_backup_codes))
        elements.append(Spacer(1, 12))

    # 2FA Backup Codes
    if twofa_backup_codes:
        elements.append(Paragraph(_tr("2FA Backup Codes (login fallback)"), H2))
        elements.append(_codes_table(twofa_backup_codes))
        elements.append(Spacer(1, 12))

    _ = totp_uri # deprecated/ignored (kept to avoid breaking callers)
    if totp_qr_png:
        elements.append(Paragraph(_tr("Two-Factor Authenticator (TOTP)"), H2))
        try:
            elements.append(Image(io.BytesIO(totp_qr_png), width=200, height=200))
        except Exception:
            elements.append(Paragraph(_tr("TOTP QR image could not be embedded."), SMALL))
        elements.append(Spacer(1, 6))
        if totp_secret_hint:
            elements.append(Paragraph(_tr("Secret (hint): ") + f"<b>{_esc(totp_secret_hint)}</b>", SMALL))
            elements.append(Spacer(1, 4))
        elements.append(Paragraph(
            _tr(
                "This QR is for reference only. If you have already set up TOTP, you do NOT need to scan it again. "
                "If your authenticator is unavailable, use your 2FA backup codes."
            ),
            SMALL,
        ))
        elements.append(Spacer(1, 12))

    # Guidance
    elements.append(_guidelines_box([
        _tr("Print and store securely; avoid digital/cloud copies."),
        _tr("Recovery codes are for password reset (with Recovery Key)."),
        _tr("2FA backup codes are for login if your authenticator is unavailable."),
        _tr("Never share this with anyone. Keyquorum will never ask for it."),
        _tr("Regenerate this kit if you suspect it has been compromised."),
        _tr("Consider regenerating annually as a security best practice."),]))

    elements.append(Spacer(1, 20))
    elements.append(Paragraph(_tr("— Keep this sheet offline. Do not email or upload to cloud storage. —"), SMALL))

    def _footer(canvas, doc_):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.grey)
        canvas.drawRightString(doc_.pagesize[0] - 36, 20, f"Page {doc_.page} • Keyquorum Emergency Kit • Confidential")
        canvas.restoreState()

    doc.build(elements, onFirstPage=_footer, onLaterPages=_footer)

    # Best-effort metadata wipe
    _sanitize_pdf_metadata(path)
    return path


# ----------------------------- payload -------------------------------------

def _build_kit_payload(
    *,
    username: str,
    app_version: str,
    generated_iso: str,
    recovery_key: Optional[str],
    recovery_backup_codes: list[str],
    twofa_backup_codes: list[str],
) -> str:
    """
    Build a compact, versioned token we can later parse from the PDF
    (via text extraction or by scanning the QR).

    Format: KQEM1:<base64-url-safe-json>

    Security note: we do NOT include any TOTP secret material in this payload.
    """
    try:
        rk_fp = hashlib.sha256(recovery_key.encode("utf-8")).hexdigest() if recovery_key else None
    except Exception:
        rk_fp = None

    payload = {
        "kq_type": "emergency_kit",
        "kq_ver": 1,
        "username": username,
        "app_version": app_version,
        "generated": generated_iso,
        "has_recovery_key": bool(recovery_key),
        "recovery_key_fp": rk_fp,
        "recovery_backup_codes": list(recovery_backup_codes or []),
        "twofa_backup_codes": list(twofa_backup_codes or []),
        # no TOTP secret material
    }

    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    token = base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii")
    return "KQEM1:" + token


# ----------------------------- helpers -------------------------------------

def _codes_table(codes: list[str]):
    rows = [[f"{i+1}. {c}"] for i, c in enumerate(codes)]
    t = Table([[_tr("Codes")]] + rows, hAlign="LEFT", colWidths=[400])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.black),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.black),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (-1, 0), "LEFT"),
    ]))
    return t


def _highlight_box(html: str):
    styles = getSampleStyleSheet()
    t = Table([[Paragraph(html, styles["BodyText"])]], colWidths=[520])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#eef6ff")),
        ("BOX", (0, 0), (-1, -1), 0.7, colors.blue),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return t


def _qr_image(payload: str, *, box_size: int = 8, border: int = 4, size_px: int = 220):
    """
    Returns a reportlab Image flowable for a QR, or None if qrcode isn't available.
    """
    try:
        import qrcode  # type: ignore
    except Exception:
        return None

    qr = qrcode.QRCode(box_size=box_size, border=border)
    qr.add_data(payload)
    qr.make(fit=True)
    im = qr.make_image()
    buf = io.BytesIO()
    im.save(buf, format="PNG")
    buf.seek(0)
    return Image(buf, width=size_px, height=size_px)


def _warn_box(text: str):
    styles = getSampleStyleSheet()
    html = _esc(text).replace("\n", "<br/>")
    t = Table([[Paragraph(html, styles["BodyText"])]], colWidths=[520])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.Color(1, 0.95, 0.8)),
        ("BOX", (0, 0), (-1, -1), 0.7, colors.orange),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return t


def _guidelines_box(lines: list[str]):
    styles = getSampleStyleSheet()
    bullets = "<br/>".join(f"• {_esc(l)}" for l in lines)
    t = Table([[Paragraph(bullets, styles["BodyText"])]], colWidths=[520])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.whitesmoke),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.grey),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return t


def _now_utc_iso() -> str:
    return _dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _esc(s: object) -> str:
    if s is None:
        return ""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _sanitize_pdf_metadata(path: str) -> None:
    """
    Best-effort metadata wipe.
    - Clears classic Info dictionary fields
    - Clears XMP metadata if present
    Requires pikepdf; silently no-ops if not installed.
    """
    try:
        import pikepdf  # type: ignore
    except Exception:
        return

    try:
        with pikepdf.open(path, allow_overwriting_input=True) as pdf:
            info = pdf.docinfo
            for k in ["/Title", "/Author", "/Subject", "/Keywords", "/Creator", "/Producer", "/CreationDate", "/ModDate"]:
                if k in info:
                    del info[k]
            try:
                with pdf.open_metadata() as meta:
                    meta.clear()
            except Exception:
                pass
            pdf.save(path)
    except Exception:
        return
