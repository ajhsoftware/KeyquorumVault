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

import logging, io, time, os
log = logging.getLogger('keyquorum')
import qrcode
from qtpy.QtCore import Qt, QSize,  QTimer
from typing import Dict, Any
from qtpy.QtGui import QPixmap, QImage, QGuiApplication
from qtpy.QtWidgets import (
    QDialog, QVBoxLayout, QLabel, QHBoxLayout, QPushButton,
    QFileDialog, QMessageBox, QAction
)
# import numpy as np

from qtpy.QtCore import QCoreApplication

def _tr(text: str) -> str:
    return QCoreApplication.translate("qr_tools", text)


def _decode_qr_from_image_cv(img):
    """Robust QR decode from a BGR image using multiple preprocessing attempts."""
    det = cv2.QRCodeDetector()

    def _try_multi(frame):
        try:
            # OpenCV ≥4.5 has detectAndDecodeMulti; returns (data_list, points, straight_qrcode)
            datas, points, _ = det.detectAndDecodeMulti(frame)
            if datas:
                # Pick the longest non-empty string
                best = max([d for d in datas if isinstance(d, str)], key=len, default="")
                return best if best else None
        except Exception:
            pass
        # Fallback to single
        try:
            data, pts, _ = det.detectAndDecode(frame)
            return data if data else None
        except Exception:
            return None

    frames = []

    # Original
    frames.append(img)

    # Handle alpha channel (BGRA -> BGR)
    if img.ndim == 3 and img.shape[2] == 4:
        frames.append(cv2.cvtColor(img, cv2.COLOR_BGRA2BGR))

    # Grayscale
    try:
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        frames.append(gray)
        # Adaptive threshold (helps on screenshots)
        thr = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_MEAN_C,
                                    cv2.THRESH_BINARY, 35, 5)
        frames.append(thr)
        # Light blur (remove JPEG speckle)
        blr = cv2.medianBlur(gray, 3)
        frames.append(blr)
    except Exception:
        pass

    # Upscale 2x / 3x with nearest neighbor (sharpens QR modules)
    try:
        up2 = cv2.resize(img, None, fx=2.0, fy=2.0, interpolation=cv2.INTER_NEAREST)
        frames.append(up2)
        up3 = cv2.resize(img, None, fx=3.0, fy=3.0, interpolation=cv2.INTER_NEAREST)
        frames.append(up3)
    except Exception:
        pass

    # Try each frame variant
    best = None
    for f in frames:
        data = _try_multi(f)
        if data and (best is None or len(data) > len(best)):
            best = data
    return best

def _json_or_raw_to_obj(text):
    """Return dict if text is JSON; else {'raw': text}."""
    if not isinstance(text, str) or not text.strip():
        return None
    try:
        return json.loads(text)
    except Exception:
        # Some generators base64-encode the JSON; try that too
        try:
            dec = base64.b64decode(text)
            return json.loads(dec.decode("utf-8"))
        except Exception:
            return {"raw": text}

# --- Multi-QR scan & assemble -----------------------------------------------
import base64, json

def _detect_qr_part(obj: dict):
    """
    Return (part_idx_1based, total_parts, chunk_str, group_id) if this looks like a multipage QR,
    else None. Supports a few common schemas:
      {"kq_share_part":1,"of":2,"data":"...","id":"..."}
      {"type":"kqshare_part","part":1,"of":2,"chunk":"...","gid":"..."}
    """
    if not isinstance(obj, dict):
        return None
    # variant A
    if "kq_share_part" in obj and "of" in obj:
        idx = int(obj.get("kq_share_part", 0) or 0)
        total = int(obj.get("of", 0) or 0)
        chunk = obj.get("data") or obj.get("chunk") or obj.get("payload")
        gid = obj.get("id") or obj.get("mpid") or obj.get("group") or "kq"
        if idx >= 1 and total >= 2 and isinstance(chunk, str):
            return (idx, total, chunk, str(gid))
    # variant B
    if obj.get("type") in ("kqshare_part", "kq_part") and "part" in obj and "of" in obj:
        idx = int(obj.get("part", 0) or 0)
        total = int(obj.get("of", 0) or 0)
        chunk = obj.get("chunk") or obj.get("data") or obj.get("payload")
        gid = obj.get("gid") or obj.get("id") or "kq"
        if idx >= 1 and total >= 2 and isinstance(chunk, str):
            return (idx, total, chunk, str(gid))
    return None

def _try_join_and_parse(chunks: list[str]):
    """Try to parse joined chunks: first as JSON text, then as base64→JSON."""
    buf = "".join(chunks)
    # direct JSON
    try:
        return json.loads(buf)
    except Exception:
        pass
    # base64 → JSON
    try:
        data = base64.b64decode(buf)
        return json.loads(data.decode("utf-8", errors="strict"))
    except Exception:
        return None

def scan_qr_any(parent=None, use_camera: bool = False):
    """
    Scan one QR. If it's a full JSON packet → return dict.
    If it's a multi-part page, prompt the user to scan remaining pages, reassemble, and return dict.
    Returns None on cancel.
    """
    first = scan_qr_json(parent=parent, use_camera=use_camera)  # existing function you already have
    if not first:
        return None

    # Full object?
    part_info = _detect_qr_part(first)
    if not part_info:
        return first  # single QR payload

    # Multipart: collect the rest
    idx, total, chunk, gid = part_info
    parts = {idx: chunk}
    while len(parts) < total:
        msg = _tr("Scanned page ") + f"{len(parts)}" + _tr(" of ") + f"{total}.\n" + _tr("Please scan the next page…")
        QMessageBox.information(
            parent, _tr("Scan next QR"),
            msg)
        nxt = scan_qr_json(parent=parent, use_camera=use_camera)
        if not nxt:
            return None
        info = _detect_qr_part(nxt)
        if not info:
            QMessageBox.warning(parent, _tr("QR"), _tr("That wasn't a bundle page. Try again."))
            continue
        i2, t2, ch2, gid2 = info
        if t2 != total or str(gid2) != str(gid):
            QMessageBox.warning(parent, _tr("QR"), _tr("That page belongs to a different bundle. Try again."))
            continue
        if i2 in parts:
            # already have it; ignore duplicates
            continue
        parts[i2] = ch2

    # Reassemble in order 1..total
    ordered = [parts[i] for i in range(1, total + 1)]
    obj = _try_join_and_parse(ordered)
    if obj is None:
        QMessageBox.critical(parent, _tr("QR"), _tr("Could not reconstruct the payload from QR parts."))
        return None
    return obj


class QRScanDialog(QDialog):
    """Live camera QR scanner that can be closed normally."""
    def __init__(self, parent=None, camera_index: int = 0):
        super().__init__(parent)
        self.setWindowTitle(_tr("Scan QR"))
        self.setModal(True)
        self.setAttribute(Qt.WA_DeleteOnClose, True)
        self.setMinimumSize(640, 420)

        self.result = None
        self._cap = None
        self._timer = None
        self._detector = None

        v = QVBoxLayout(self)
        self._label = QLabel(_tr("Opening camera…"), self)
        self._label.setAlignment(Qt.AlignCenter)
        self._label.setMinimumSize(640, 360)
        v.addWidget(self._label)

        h = QHBoxLayout()
        cancel = QPushButton(_tr("Cancel"), self)
        cancel.clicked.connect(self.reject)
        h.addStretch(1)
        h.addWidget(cancel)
        v.addLayout(h)

        try:
            self._cap = cv2.VideoCapture(camera_index)
            if not self._cap or not self._cap.isOpened():
                raise RuntimeError(_tr("Camera not available."))
            self._detector = cv2.QRCodeDetector()
            self._timer = QTimer(self)
            self._timer.timeout.connect(self._on_frame)
            self._timer.start(30)
        except Exception as e:
            QMessageBox.critical(self, _tr("QR"), _tr("Could not open camera:") + f"\n{e}")
            self.reject()

    def _on_frame(self):
        ok, frame = self._cap.read()
        if not ok or frame is None:
            return
        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        h, w, ch = rgb.shape
        qimg = QImage(rgb.data, w, h, ch * w, QImage.Format.Format_RGB888)
        self._label.setPixmap(QPixmap.fromImage(qimg).scaled(
            self._label.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation
        ))
        data, pts, _ = self._detector.detectAndDecode(frame)
        if data:
            try:
                self.result = json.loads(data)
            except Exception:
                self.result = {"raw": data}
            self.accept()

    def reject(self):
        self._cleanup()
        super().reject()

    def closeEvent(self, e):
        self._cleanup()
        super().closeEvent(e)

    def _cleanup(self):
        if self._timer:
            self._timer.stop()
        if self._cap:
            self._cap.release()



# ================== QR scanner (optional; uses OpenCV) ==================
try:
    import cv2  
except Exception:
    cv2 = None

import json

def scan_qr_json(parent=None, use_camera: bool = False):
    """
    Scan a QR from camera (Qt dialog) or pick an image file.
    Returns a parsed JSON dict or {'raw': <text>} or None on cancel.
    Robust file decoding: handles screenshots, alpha, resizing, and multi-decode.
    """
    import json, base64
    try:
        from qtpy.QtWidgets import QFileDialog, QMessageBox
    except Exception:
        return None

    # --------- tiny helpers (local to this function) ----------
    def _json_or_raw_to_obj(text: str):
        if not isinstance(text, str) or not text.strip():
            return None
        # JSON (plain)
        try:
            return json.loads(text)
        except Exception:
            pass
        # JSON (base64-wrapped)
        try:
            dec = base64.b64decode(text)
            return json.loads(dec.decode("utf-8"))
        except Exception:
            return {"raw": text}

    def _decode_qr_from_image_cv(img):
        """Robust QR decode from a BGR/BGRA/Gray image using multiple preprocessing attempts."""
        try:
            import cv2  
        except Exception:
            return None

        det = cv2.QRCodeDetector()

        def _try_multi(frame):
            # Try multi first (if available), then single
            try:
                datas, points, _ = det.detectAndDecodeMulti(frame)
                if datas:
                    best = max([d for d in datas if isinstance(d, str)], key=len, default="")
                    if best:
                        return best
            except Exception:
                pass
            try:
                data, pts, _ = det.detectAndDecode(frame)
                return data if data else None
            except Exception:
                return None

        frames = []

        # Normalize to BGR/Gray candidates
        frames.append(img)
        if img is not None and img.ndim == 3 and img.shape[2] == 4:
            try:
                frames.append(cv2.cvtColor(img, cv2.COLOR_BGRA2BGR))
            except Exception:
                pass
        try:
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            frames.append(gray)
            thr = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_MEAN_C,
                                        cv2.THRESH_BINARY, 35, 5)
            frames.append(thr)
            blr = cv2.medianBlur(gray, 3)
            frames.append(blr)
        except Exception:
            pass

        # Upscale to help with tiny screenshots
        try:
            up2 = cv2.resize(img, None, fx=2.0, fy=2.0, interpolation=cv2.INTER_NEAREST)
            frames.append(up2)
            up3 = cv2.resize(img, None, fx=3.0, fy=3.0, interpolation=cv2.INTER_NEAREST)
            frames.append(up3)
        except Exception:
            pass

        best = None
        for f in frames:
            data = _try_multi(f)
            if data and (best is None or len(data) > len(best)):
                best = data
        return best
    # ----------------------------------------------------------

    # --- Camera path (uses your QRScanDialog; cleanly closable) ---
    if use_camera:
        try:
            import cv2  # ensure OpenCV exists for capture
        except Exception:
            QMessageBox.information(parent, _tr("QR"), _tr("OpenCV not available in this build."))
            return None
        try:
            # QRScanDialog must be defined in this module (as shared earlier)
            dlg = QRScanDialog(parent=parent)
        except Exception as e:
            QMessageBox.critical(parent, _tr("QR"), _tr("Camera scanner not available:") + f"\n{e}")
            return None
        if dlg.exec() == QDialog.DialogCode.Accepted:
            return dlg.result
        return None

    # --- File path (robust decode for screenshots/images) ---
    try:
        import cv2  
    except Exception:
        QMessageBox.information(parent, _tr("QR"), _tr("OpenCV not available in this build."))
        return None

    path, _ = QFileDialog.getOpenFileName(
        parent, _tr("Scan QR (image)"),
        "", _tr("Images (*.png *.jpg *.jpeg *.bmp *.webp *.tif *.tiff)"))
    if not path:
        return None

    img = cv2.imread(path, cv2.IMREAD_UNCHANGED)
    if img is None:
        QMessageBox.warning(parent, _tr("QR"), _tr("Invalid or unreadable image."))
        return None

    data = _decode_qr_from_image_cv(img)
    if not data:
        QMessageBox.information(parent, _tr("QR"), _tr("No QR code found."))
        return None

    return _json_or_raw_to_obj(data)

# ---------- QR helpers ----------
def _make_qr_image(payload: str,
                   box_size: int = 5,    # qr size
                   border: int = 2,
                   fg: str = "black",
                   bg: str = "white") -> QImage:
    """Return a QImage (not scaled yet)."""
    try:
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_Q,
            box_size=box_size,
            border=border
        )
        qr.add_data("" if payload is None else str(payload))
        qr.make(fit=True)
        img = qr.make_image(fill_color=fg, back_color=bg)
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        buf.seek(0)
        qimg = QImage.fromData(buf.getvalue(), 'PNG')
        return qimg
    except Exception as e:
        log.error(f"[QR] build failed: {e}")
        return QImage()

def _scaled_pixmap_for_label(base: QImage, target: QSize) -> QPixmap:
    """Scale image to fit label while keeping aspect ratio, HiDPI-aware."""
    if base.isNull():
        return QPixmap()
    # Use device pixel ratio for crisp result on HiDPI
    dpr = QGuiApplication.primaryScreen().devicePixelRatio() if QGuiApplication.primaryScreen() else 1.0
    tw = max(1, int(target.width() * dpr))
    th = max(1, int(target.height() * dpr))
    scaled = base.scaled(tw, th, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
    pm = QPixmap.fromImage(scaled)

    if dpr and dpr != 1.0:
        pm.setDevicePixelRatio(dpr)
    return pm

def make_qr_pixmap(payload: str, size: int = 200) -> QPixmap:
    """Direct helper if you just want a fixed-size pixmap."""
    qimg = _make_qr_image(payload)
    if qimg.isNull():
        return QPixmap()
    scaled = qimg.scaled(size, size, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
    return QPixmap.fromImage(scaled)

# ---------- Dialog ----------
class QRPreviewDialog(QDialog):
    """Modal preview dialog with Copy Image/Text + Save (PNG/SVG) actions."""

    def __init__(self, title: str, payload: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.setMinimumSize(100, 100) 

        self._payload = "" if payload is None else str(payload)
        # Build a higher-res base image so enlarging the dialog stays sharp
        self._base_image = _make_qr_image(self._payload, box_size=5, border=2)

        layout = QVBoxLayout(self)

        self.label = QLabel(self)
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setMinimumSize(100, 100)  # qr size
        # initial pixmap
        self._apply_scaled_pixmap()
        layout.addWidget(self.label)

        btn_row = QHBoxLayout()
        self.btn_copy_img = QPushButton(_tr('Copy Image'))
        self.btn_copy_text = QPushButton(_tr('Copy Text'))
        self.btn_save = QPushButton(_tr('Save'))
        self.btn_close = QPushButton(_tr('Close'))
        btn_row.addStretch(1)
        btn_row.addWidget(self.btn_copy_img)
        btn_row.addWidget(self.btn_copy_text)
        btn_row.addWidget(self.btn_save)
        btn_row.addWidget(self.btn_close)
        layout.addLayout(btn_row)

        # Actions
        self.btn_copy_img.clicked.connect(self._copy_image)
        self.btn_copy_text.clicked.connect(self._copy_text)
        self.btn_save.clicked.connect(self._save_dialog)
        self.btn_close.clicked.connect(self.accept)

        # Keyboard shortcuts (Esc to close, Ctrl+C copies image)
        close_act = QAction(self)
        close_act.setShortcut(_tr('Escape'))
        close_act.triggered.connect(self.accept)
        self.addAction(close_act)

        copy_act = QAction(self)
        copy_act.setShortcut(_tr('Ctrl+C'))
        copy_act.triggered.connect(self._copy_image)
        self.addAction(copy_act)

    # Keep image crisp on resize
    def resizeEvent(self, e):
        super().resizeEvent(e)
        self._apply_scaled_pixmap()

    def _apply_scaled_pixmap(self):  # set this for size of qr code
        target = self.label.size()
        # Floor to a comfortable minimum in case the layout hasn't expanded yet
        if target.width() < 200 or target.height() < 200:
            target = QSize(max(200, target.width()), max(200, target.height()))
        pm = _scaled_pixmap_for_label(self._base_image, target)
        self.label.setPixmap(pm)

    # --- Actions ---
    def _copy_image(self):
        pm = self.label.pixmap()
        if not pm or pm.isNull():
            return
        try:
            QGuiApplication.clipboard().setPixmap(pm)
            QMessageBox.information(self, _tr('QR'), _tr('QR image copied to clipboard.'))
        except Exception as e:
            log.error(f"[QR] copy image failed: {e}")

    def _copy_text(self):
        try:
            QGuiApplication.clipboard().setText(self._payload or "")
            QMessageBox.information(self, _tr('QR'), _tr('QR text copied to clipboard.'))
        except Exception as e:
            log.error(f"[QR] copy text failed: {e}")

    def _save_dialog(self):
        # Offer PNG and (if available) SVG
        filters = _tr("PNG Image (*.png)")
        svg_supported = False
        try:
            import qrcode.image.svg as _qr_svg  # noqa: F401
            filters = _tr("PNG Image (*.png);;SVG Image (*.svg)")
            svg_supported = True
        except Exception:
            pass

        ts = time.strftime("%Y%m%d_%H%M%S")
        default_name = f"qr_{ts}.png"
        path, selected = QFileDialog.getSaveFileName(self, _tr('Save QR'), default_name, filters)
        if not path:
            return

        try:
            if path.lower().endswith(".svg") or (svg_supported and selected and "SVG" in selected.upper()):
                # Save vector SVG (crisp at any size)
                import qrcode.image.svg as qr_svg
                factory = qr_svg.SvgPathImage
                qr = qrcode.QRCode(
                    version=None,
                    error_correction=qrcode.constants.ERROR_CORRECT_Q,
                    box_size=5, border=2, image_factory=factory
                )
                qr.add_data(self._payload)
                qr.make(fit=True)
                img = qr.make_image()
                svg_bytes = img.to_string()
                with open(path, "wb") as f:
                    f.write(svg_bytes)
            else:
                # Save PNG from current pixmap to keep what user sees
                pm = self.label.pixmap()
                if not pm or pm.isNull():
                    pm = make_qr_pixmap(self._payload, size=512)
                pm.save(path, 'PNG')

            QMessageBox.information(self, _tr('Saved'), _tr("Saved to:") + f"\n{os.path.abspath(path)}")
        except Exception as e:
            log.error(f"[QR] save failed: {e}")
            QMessageBox.critical(self, _tr('Error'), _tr("Could not save file:") + f"\n{e}")



# ================== KQ share/ID QR helpers (compact + chunked) ==================
import json, gzip, base64
from typing import Dict, Any

# Conservative chunk size (post-base64) for fast scanning on average phones
_KQ_QR_PREFIX = "KQ1"          # protocol tag so scanners know how to reassemble
_KQ_QR_CHUNK_BYTES = 900       # tune if you find your camera easily handles larger payloads

def _kq_qr_encode_obj(obj: Dict[str, Any]) -> bytes:
    """json -> gzip -> base64 bytes"""
    data = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    gz = gzip.compress(data, compresslevel=9)
    return base64.b64encode(gz)

def kq_qr_chunks_for_object(obj: Dict[str, Any]) -> list[str]:
    """
    Returns 1..N ASCII strings, each a QR payload:
    KQ1:<i>/<N>:<base64_gzip_json_chunk>
    """
    b64 = _kq_qr_encode_obj(obj)
    chunks: list[str] = []
    total = (len(b64) + _KQ_QR_CHUNK_BYTES - 1) // _KQ_QR_CHUNK_BYTES
    for i in range(total):
        part = b64[i*_KQ_QR_CHUNK_BYTES : (i+1)*_KQ_QR_CHUNK_BYTES]
        chunks.append(f"{_KQ_QR_PREFIX}:{i+1}/{total}:" + part.decode("ascii"))
    if not chunks:  # empty payload edge case
        chunks = [f"{_KQ_QR_PREFIX}:1/1:"]
    return chunks

# -------- Multi-page QR dialog (reuse same look & buttons) --------

class MultiQRPreviewDialog(QDialog):
    """
    Shows a sequence of QR codes with Prev/Next and (optionally) a Continue button.
    If continue_text is provided, clicking it will accept() the dialog.
    """
    def __init__(self, title: str, pages: list[str], parent=None,
                 subtitle: str | None = None,
                 continue_text: str | None = None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.setMinimumSize(250, 350)

        self._pages = pages or [""]
        self._idx = 0
        self._continue_text = continue_text

        v = QVBoxLayout(self)

        # QR image
        self.label = QLabel(self)
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setMinimumSize(200, 200)
        v.addWidget(self.label)

        # Page indicator
        self.page_lbl = QLabel(self)
        self.page_lbl.setAlignment(Qt.AlignCenter)
        v.addWidget(self.page_lbl)

        # Optional subtitle/explainer
        self.sub_lbl = QLabel(self)
        self.sub_lbl.setAlignment(Qt.AlignCenter)
        self.sub_lbl.setWordWrap(True)
        self.sub_lbl.setText(subtitle or "")
        self.sub_lbl.setVisible(bool(subtitle))
        v.addWidget(self.sub_lbl)

        # Controls
        h = QHBoxLayout()
        self.prev_btn = QPushButton(_tr("◀ Prev"), self)
        self.next_btn = QPushButton(_tr("Next ▶"), self)
        self.prev_btn.clicked.connect(self._prev)
        self.next_btn.clicked.connect(self._next)
        h.addWidget(self.prev_btn)
        h.addWidget(self.next_btn)
        h.addStretch(1)

        # Optional Continue button (accepts the dialog)
        if continue_text:
            self.continue_btn = QPushButton(continue_text, self)
            self.continue_btn.clicked.connect(self.accept)
            h.addWidget(self.continue_btn)
        v.addLayout(h)

        self._update_view()

    def _update_view(self):
        total = len(self._pages)
        payload = self._pages[self._idx]
        base_img = _make_qr_image(payload, box_size=18, border=2)  # bigger, sharper
        pm = _scaled_pixmap_for_label(base_img, self.label.size() if not self.label.size().isEmpty() else QSize(360, 360))
        self.label.setPixmap(pm)
        self.page_lbl.setText(_tr("Page ") + f"{self._idx+1}" + _tr(" of ") + f"{total}")
        self.prev_btn.setEnabled(self._idx > 0)
        self.next_btn.setEnabled(self._idx < total - 1)

    def resizeEvent(self, e):
        super().resizeEvent(e)
        self._update_view()

    def _next(self):
        if self._idx < len(self._pages) - 1:
            self._idx += 1
            self._update_view()

    def _prev(self):
        if self._idx > 0:
            self._idx -= 1
            self._update_view()

            
def _tweak_qr_dialog_for_shareid(dlg):
    # Hide Copy buttons and rename Close → Continue for Share ID (single-QR dialog)
    try:
        for btn in dlg.findChildren(QPushButton):
            label = (btn.text() or "").replace("&", "").strip().lower()
            if label in (_tr("copy image"), _tr("copy text")):
                btn.hide()
            elif label == "close":
                btn.setText(_tr("Continue"))
                try:
                    btn.clicked.disconnect()
                except Exception:
                    pass
                btn.clicked.connect(dlg.accept)  # make "Continue" = accept
    except Exception:
        pass

def show_qr_for_object(title: str, obj: Dict[str, Any], parent=None, mode: str = "normal") -> bool:
    """
    Shows QR for obj. Returns True if user chose to 'Continue' (for share flows),
    False if they closed/cancelled.
      mode:
        "normal"  -> full buttons, no special continue semantics
        "shareid" -> single-QR: hide Copy buttons, Close→Continue (accept)
        "kqshare" -> multi- or single-QR: show subtitle and a Continue button to proceed to Save
    """
    chunks = kq_qr_chunks_for_object(obj)

    # SINGLE-QR path
    if len(chunks) == 1:
        dlg = QRPreviewDialog(title, chunks[0], parent)
        if mode == "shareid":
            _tweak_qr_dialog_for_shareid(dlg)
            return dlg.exec() == QDialog.DialogCode.Accepted
        else:
            # Normal or share packet that fits in one QR: just show; user closes.
            return dlg.exec() == QDialog.DialogCode.Accepted

    # MULTI-QR path
    subtitle = None
    continue_text = None
    if mode == "kqshare":
        subtitle = _tr("Scan each page in order to import. Or click Continue to save the .kqshare file.")
        continue_text = _tr("Continue to Save")

    dlg = MultiQRPreviewDialog(title, chunks, parent, subtitle=subtitle, continue_text=continue_text)
    return dlg.exec() == QDialog.DialogCode.Accepted
