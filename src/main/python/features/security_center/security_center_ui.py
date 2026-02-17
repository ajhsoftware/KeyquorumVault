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

""" move from main for shrink and easer matinase w = w"""

# --- pysider6 backend
from qtpy.QtWidgets import QMessageBox
from qtpy.QtCore import QCoreApplication
# --- log ---
import logging
log = logging.getLogger("keyquorum")

# --- helpers ---
from security.preflight import (load_security_prefs, _any_av_present, scan_for_suspicious_processes,)
from device.system_info import get_basic_system_info, get_windows_update_status
from security.integrity_manifest import verify_manifest_auto
from auth.login.login_handler import get_user_record, get_user_setting, set_user_record, _load_vault_salt_for
from features.clipboard.secure_clipboard import _win_clipboard_risk_state
from app.platform_utils import IS_WINDOWS
from security.baseline_signer import _baseline_tracked_files, verify_baseline
from workers.securitycenter_worker import SecurityCenterWorker

def _tr(text: str) -> str:
    """Qt translation helper scoped to the Watchtower UI."""
    return QCoreApplication.translate("uiwatchtower", text)

def _sc_on_progress(w, msg: str):
    """Worker progress callback (runs on GUI thread via Qt signal)."""
    try:
        # Runs on GUI thread (Qt signal); safe to touch UI
        w.set_status_txt(_tr(str(msg)))
    except Exception:
        pass
  
def _sc_on_finished(w, data: dict | None = None, error: object | None = None) -> None:
    """
    Called when the background SecurityCenterWorker completes.
    We just re-enable the button, show status, then run the
    normal synchronous UI logic to populate all fields.
    """
    try:
        w.securityRefreshButton.setEnabled(True)
    except Exception:
        pass
    if error:
        log.error(f"[SecurityCenter] worker error: {error}")
    
    # Nice footer in the status bar
    try:
        w.set_status_txt(_tr("Scan complete") + " ✔")
    except Exception:
        pass

    # Populate the panel synchronously (fast parts). Skip AV here because WMI can
    # hang the UI thread on some systems; AV gets checked in the background worker.
    try:
        on_security_refresh_clicked(w, skip_av=True)
    except Exception as e:
        log.error(f"[SecurityCenter] on_security_refresh_clicked failed after worker: {e}")
        try:
            QMessageBox.warning(
                w,
                _tr("Security Center"),
                _tr("Security scan finished but updating the panel failed:\n{err}").format(err=e),
            )
        except Exception:
            pass

    # Apply AV result from worker (no UI-thread WMI calls)
    try:
        av = (data or {}).get("antivirus") or {}
        present = av.get("present")
        if present is True:
            names = av.get("names") or []
            source = av.get("source") or ""
            product_list = ", ".join(names) if names else _tr("Unknown product")
            if source == "wmi":
                src_txt = _tr("Detected via Windows Security Center.")
            elif source == "defender-fallback":
                src_txt = _tr("Windows Defender service appears to be running.")
            else:
                src_txt = _tr("Detection source: fallback.")
            w.antivirusStatus.setText(_tr("Status:") + " ✔ " + _tr("Antivirus detected"))
            w.antivirusDetails.setText(_tr("Details: {products}\n{source}").format(
                products=product_list,
                source=src_txt,
            ))
        elif present is False:
            w.antivirusStatus.setText(_tr("Status:") + " ⚠ " + _tr("No antivirus found"))
            w.antivirusDetails.setText(_tr(
                "Details: No active antivirus was detected. "
                "Consider enabling Microsoft Defender or another AV product."
            ))
        else:
            # Unknown / not responding – don't scare the user, just mark as unavailable
            w.antivirusStatus.setText(_tr("Status:") + " … " + _tr("Unavailable"))
            w.antivirusDetails.setText(_tr(
                "Details: Antivirus status could not be determined (not responding)."
            ))
    except Exception:
        pass

def _run_security_center_scan(w):

    username = w.currentUsername.text().strip()
    if not username:
        QMessageBox.warning(w, _tr("Security Center"), _tr("No user loaded."))
        return

    # Disable button to prevent double-click spam
    w.securityRefreshButton.setEnabled(False)
    w.set_status_txt(_tr("Scanning… please wait"))

    # Thread worker
    w._sc_worker = SecurityCenterWorker(username)
    # IMPORTANT: connect to module functions using lambdas.
    # After split, `w` may not have `_sc_on_progress/_sc_on_finished` attributes,
    # which can crash on click.
    w._sc_worker.progress.connect(lambda msg: _sc_on_progress(w, msg))
    w._sc_worker.finished.connect(lambda results, err=None: _sc_on_finished(w, results, err))

    w._sc_worker.start()

def on_security_refresh_clicked(w, *, skip_av: bool = False) -> None:
    username = (w.currentUsername.text() or "").strip()
    if not username:
        QMessageBox.information(
            w,
            _tr("Security Center"),
            _tr("Please log in or select a user first."),
        )
        return

    # Default flags for scoring
    baseline_ok = False
    manifest_ok = False
    preflight_ok = False
    av_ok = False

    # ---------- Baseline Integrity ----------
    try:
        salt = _load_vault_salt_for(username)
        files = _baseline_tracked_files(username)

        # First, run the normal verifier
        changed, missing, new, mac_ok = verify_baseline(username, salt, files)
        baseline_ok = mac_ok and not changed and not missing

        # High-level status label
        if not mac_ok:
            status = _tr("Status:") + " ⚠ " + _tr("Signature failed")
        elif changed or missing or new:
            status = _tr("Status:") + " ⚠ " + _tr("Differences detected")
        else:
            status = _tr("Status:") + " ✔ " + _tr("All tracked files match baseline")

        w.baselineIntegrityStatus.setText(status)

        # ---- Build per-file hash summary (baseline vs current) ----
        from pathlib import Path, PurePath
        import json, hashlib
        from app.paths import baseline_file  # same helper baseline_signer uses

        def _sha256_file(p: Path, buf: int = 1024 * 1024) -> str:
            h = hashlib.sha256()
            with p.open("rb") as f:
                for chunk in iter(lambda: f.read(buf), b""):
                    h.update(chunk)
            return h.hexdigest()

        def _tail(h: str | None) -> str:
            if not h:
                return "—"
            h = str(h)
            return h[-6:] if len(h) > 6 else h

        # Load stored baseline hashes
        base_map: dict[str, str] = {}
        try:
            bpath = Path(baseline_file(username, ensure_parent=True, name_only=False))
            if bpath.exists():
                data = json.loads(bpath.read_text(encoding="utf-8"))
                payload = data.get("payload") or {}
                files_section = payload.get("files") or {}
                if isinstance(files_section, dict):
                    for k, v in files_section.items():
                        base_map[str(k)] = str(v)
        except Exception:
            # If manifest can't be read, we still keep going with an empty map
            base_map = {}

        # Compute current hashes for the tracked files
        now_map: dict[str, str] = {}
        for f in files or []:
            try:
                p = Path(f)
            except Exception:
                continue
            try:
                if p.exists() and p.is_file():
                    now_map[str(p)] = _sha256_file(p)
            except Exception:
                # unreadable → treat as no hash
                now_map[str(p)] = ""

        # Build union of all relevant paths so we show everything
        all_paths = sorted(set(base_map.keys()) | set(now_map.keys()))

        lines: list[str] = []

        if not mac_ok:
            lines.append(
                _tr(
                    "The baseline manifest's HMAC did not verify with your vault salt. "
                    "If you did not recently reinstall or reset the baseline, treat this "
                    "as a strong tamper warning."
                )
            )

        if not all_paths:
            lines.append(
                _tr(
                    "No baseline manifest is stored yet for this user. Once you run an "
                    "integrity update, file hashes will appear here."
                )
            )
        else:
            lines.append(
                _tr(
                    "Per-file summary (showing last 6 characters of each SHA-256 hash):"
                )
            )

            changed_set = set(changed)
            missing_set = set(missing)
            new_set      = set(new)

            for path_str in all_paths:
                base_h = base_map.get(path_str)
                now_h  = now_map.get(path_str)
                name   = PurePath(path_str).name

                if path_str in missing_set:
                    tag = "[MISSING]"
                elif path_str in new_set:
                    tag = "[NEW]"
                elif path_str in changed_set:
                    tag = "[CHANGED]"
                else:
                    tag = "[OK]"

                line = _tr(
                    "• {name}: current {now_tail} (baseline {base_tail}) {tag}"
                ).format(
                    name=name,
                    now_tail=_tail(now_h),
                    base_tail=_tail(base_h),
                    tag=tag,
                )
                lines.append(line)

        # Add a short guidance footer
        if changed or missing or new:
            lines.append(
                "\n"
                + _tr(
                    "If you recently updated or moved Keyquorum, some CHANGED/NEW/MISSING "
                    "entries can be normal. If you did not make changes, treat non-OK entries "
                    "as potential tamper signals and consider restoring from a trusted backup."
                )
            )
        elif all_paths:
            lines.append(
                "\n"
                + _tr(
                    "All tracked files are [OK]: current hashes match the stored baseline. "
                    "This means your install matches the last trusted state."
                )
            )

        w.baselineIntegrityDetails.setText(
            _tr("Details:\n") + "\n".join(lines)
        )

    except Exception as e:
        baseline_ok = False
        w.baselineIntegrityStatus.setText(_tr("Status:") + " ⚠ " + _tr("Error"))
        w.baselineIntegrityDetails.setText(
            _tr(
                "Details: Could not read or verify the baseline manifest.\n"
                "Reason: {err}"
            ).format(err=e)
        )

    # ---------- Windows Clipboard History ----------
    try:
        from device.system_info import get_clipboard_history_state
        clip_txt, clip_on = get_clipboard_history_state()

        if clip_on:
            w.windowsClipboardStatusLabel.setText(
                _tr("Status:") + " ⚠ " + _tr("Enabled")
            )
            w.windowsClipboardDetailsLabel.setText(
                _tr(
                    "Details: Windows Clipboard History is ON. "
                    "This means anything you copy (including passwords) is stored in a multi-item history buffer "
                    "until manually cleared. Consider disabling it for better security."
                )
            )
        else:
            w.windowsClipboardStatusLabel.setText(
                _tr("Status:") + " ✔ " + _tr("Disabled")
            )
            w.windowsClipboardDetailsLabel.setText(
                _tr(
                    "Details: Clipboard History is OFF, which is recommended for password managers."
                )
            )
    except Exception as e:
        w.windowsClipboardStatusLabel.setText(_tr("Status:") + " ⚠ " + _tr("Error"))
        w.windowsClipboardDetailsLabel.setText(
            _tr("Details: {err}").format(err=e)
        )
        clip_on = False

    # ---------- Preflight / Process Scan (read-only snapshot) ----------
    try:
        prefs = load_security_prefs()
        suspects = scan_for_suspicious_processes(prefs or {})
        preflight_ok = len(suspects) == 0

        if preflight_ok:
            w.processScanStatus.setText(_tr("Status:") + " ✔ " + _tr("Clean"))
            w.processScanDetails.setText(
                _tr(
                    "Details: No suspicious tools from your Preflight list are currently running."
                )
            )
        else:
            w.processScanStatus.setText(_tr("Status:") + " ⚠ " + _tr("Issues"))
            w.processScanDetails.setText(
                _tr(
                    "Details: Suspicious tools detected: {tools}"
                ).format(tools=", ".join(sorted(suspects)))
            )
    except Exception as e:
        preflight_ok = False
        w.processScanStatus.setText(_tr("Status:") + " ⚠ " + _tr("Error"))
        w.processScanDetails.setText(
            _tr("Details: Preflight check error: {err}").format(err=e)
        )

    # ---------- Vault Status (live) ----------
    try:
        entry_count = getattr(w, "tableWidget", None)
        if entry_count:
            rows = entry_count.rowCount()
        else:
            rows = 0

        if getattr(w, "userKey", None) is not None:
            status_txt = _tr("Status: Unlocked ({rows} entries loaded)").format(
                rows=rows
            )
            detail_txt = _tr(
                "Details: Your vault is currently decrypted in memory. "
                "It will auto-lock when you log out or the timeout triggers."
            )
        else:
            status_txt = _tr("Status: Locked")
            detail_txt = _tr(
                "Details: Vault data is encrypted on disk and not loaded."
            )

        w.vaultStatusLabel.setText(status_txt)
        w.vaultDetailsLabel.setText(detail_txt)
    except Exception as e:
        w.vaultStatusLabel.setText(_tr("Status:") + " ⚠ " + _tr(" Error"))
        w.vaultDetailsLabel.setText(
            _tr("Details: {err}").format(err=e)
        )

    # ---------- Antivirus ----------
    # NOTE: AV detection can block (WMI hangs) → never run it on the GUI thread
    # when called from the background scan completion.
    if not skip_av:
        try:
            present, names, source = _any_av_present(False)
            av_ok = bool(present)

            if av_ok:
                product_list = ", ".join(names) if names else _tr("Unknown product")
                if source == "wmi":
                    src_txt = _tr("Detected via Windows Security Center.")
                elif source == "defender-fallback":
                    src_txt = _tr("Windows Defender service appears to be running.")
                else:
                    src_txt = _tr("Detection source: fallback.")

                w.antivirusStatus.setText(_tr("Status:") + " ✔ " + _tr("Antivirus detected"))
                w.antivirusDetails.setText(_tr("Details: {products}\n{source}").format(
                    products=product_list,
                    source=src_txt,
                ))
            else:
                w.antivirusStatus.setText(_tr("Status:") + " ⚠ " + _tr("No antivirus found"))
                w.antivirusDetails.setText(_tr(
                    "Details: No active antivirus was detected. "
                    "Consider enabling Microsoft Defender or another AV product."
                ))

        except Exception as e:
            av_ok = False
            w.antivirusStatus.setText(_tr("Status:") + " ⚠ " + _tr("Error"))
            w.antivirusDetails.setText(_tr(
                "Details: Antivirus detection error.\n"
                "Reason: {err}"
            ).format(err=e))
    else:
        # Called from worker completion – show a non-blocking placeholder.
        try:
            w.antivirusStatus.setText(_tr("Status:") + " … " + _tr("Checking"))
            w.antivirusDetails.setText(_tr("Details: Antivirus check is running in the background."))
        except Exception:
            pass

    # ---------- Manifest Integrity ----------
    try:
        # Use the auto-resolver so dev runs hit target/keyquorum-vault
        manifest_ok, why = verify_manifest_auto(
            show_ui=False,
            parent=w,
            dev_app_name="keyquorum-vault",
            log_each=True,
        )

        if manifest_ok:
            w.manifestIntegrityStatus.setText(
                _tr("Status:") + " ✔ " + _tr("App files match signed manifest")
            )
            if why:
                details = _tr("Details: {reason}").format(reason=why)
            else:
                details = _tr(
                    "Details: All core executable and resource files match the signed manifest. "
                    "This helps detect tampering with the Keyquorum install folder."
                )
            w.manifestIntegrityDetails.setText(details)
        else:
            w.manifestIntegrityStatus.setText(
                _tr("Status:") + " ⚠ " + _tr("Manifest mismatch")
            )
            if why:
                details = _tr("Details: {reason}").format(reason=why)
            else:
                details = _tr(
                    "Details: One or more app files do not match the signed manifest. "
                    "If you just updated or reinstalled Keyquorum, this can be expected. "
                    "If not, treat this as a potential tamper and consider re-installing "
                    "from a trusted source."
                )
            w.manifestIntegrityDetails.setText(details)
    except Exception as e:
        manifest_ok = False
        w.manifestIntegrityStatus.setText(_tr("Status:") + " ⚠ " + _tr("Error"))
        w.manifestIntegrityDetails.setText(
            _tr(
                "Details: Manifest integrity check failed.\n"
                "Reason: {err}"
            ).format(err=e)
        )

    # ---------- Account / System / Updates (identity_store + helpers) ----------
    twofa_on, yubikey_on, backups_ok, strong_password = \
        w._update_security_account_section(username)

    # System info (hostname/OS/etc.)
    system_ok = w._update_security_system_section()

    # Windows Update recency (Get-HotFix via system_info helper)
    updates_ok = w._update_security_windows_updates()

    # Windows clipboard
    clipboard_ok = w._update_security_clipboard_section()

    # Vault security
    vault_ok = w._update_security_vault_section(username)

    # --- Final: compute score ---
    w._update_security_score(
        baseline_ok=baseline_ok,
        manifest_ok=manifest_ok,
        preflight_ok=preflight_ok,
        av_ok=av_ok,
        twofa_on=twofa_on,
        yubikey_on=yubikey_on,
        backups_ok=backups_ok,
        strong_password=strong_password,
        system_ok=system_ok,
        updates_ok=updates_ok,
        clipboard_ok=clipboard_ok,
        vault_ok=vault_ok,
    )

def _update_security_vault_section(w, username: str) -> bool:
    """
    Populate the 'Vault' panel on the Security Center tab.

    Returns:
        vault_ok (bool) – True if the vault file exists and can be decrypted
        with the current key; False if decryption fails or file is missing.
    """
    from pathlib import Path
    from datetime import datetime
    import time

    vault_ok = False
    corrupted = False
    status_txt = _tr("Status: (unknown)")
    detail_lines: list[str] = []

    # --- Basic state: locked / unlocked & entry count ---
    user_key = getattr(w, "userKey", None)
    unlocked = user_key is not None

    entry_count = 0
    if unlocked:
        try:
            from vault_store.vault_store import load_vault
            entries = load_vault(username, user_key) or []
            entry_count = len(entries)
            vault_ok = True
        except Exception as e:
            corrupted = True
            vault_ok = False
            detail_lines.append(_tr("Decrypt test failed:") + f" {e}. " + _tr("The vault file may be corrupted or the current key does not match.")
            )

    # --- Status line text ---
    if not unlocked:
        status_txt = _tr("Status:") + " 🔒 " + _tr("Locked")
        detail_lines.append(
            _tr("The vault is currently locked. Data is only stored encrypted on disk.")
        )
    elif corrupted:
        status_txt = _tr("Status:") + " ⚠ " + _tr("Vault may be corrupted")
    else:
        status_txt = _tr("Status:") + " 🔓 " + _tr("Unlocked") + f" ({entry_count} " + _tr("entries loaded)")

    # --- Vault file info (size + last write + size heuristics) ---
    vault_size_kb = None
    try:
        from app.paths import vault_file
        vpath = Path(vault_file(username, ensure_parent=True, name_only=False))
        if vpath.exists():
            st = vpath.stat()
            vault_size_kb = st.st_size / 1024.0
            mtime = datetime.fromtimestamp(st.st_mtime)
            age_sec = max(0, time.time() - st.st_mtime)

            # human-friendly "X ago"
            mins = int(age_sec // 60)
            hrs = int(mins // 60)
            days = int(hrs // 24)
            if days > 0:
                age_txt = f"~{days}"+ _tr("day(s) ago")
            elif hrs > 0:
                age_txt = f"~{hrs} "+ _tr("hour(s) ago")
            elif mins > 0:
                age_txt = f"~{mins} " + _tr("minute(s) ago")
            else:
                age_txt =  _tr("just now")

            detail_lines.append(
                    _tr("Vault file") + f": {vpath.name} ({vault_size_kb:.1f} KB)"
            )
            detail_lines.append(
                    _tr("Last write") + f": {mtime.strftime('%Y-%m-%d %H:%M:%S')} ({age_txt})"
            )

            # Heuristic 1: suspiciously large vault
            if st.st_size > 50 * 1024 * 1024:  # > 50 MB
                detail_lines.append(_tr(
                    "Warning: Vault file is unusually large (> 50 MB). "
                    "This may indicate embedded binary blobs or very large attachments. "
                    "Review whether all stored data is really needed.")
                )

            # Heuristic 2: very small vault vs high entry count
            if entry_count >= 100 and vault_size_kb is not None:
                # rough: < 0.5 KB per entry is suspicious
                kb_per_entry = vault_size_kb / max(1, entry_count)
                if kb_per_entry < 0.5:
                    detail_lines.append(_tr(
                        "Warning: Vault size is very small compared to the number of "
                        "entries. This can indicate truncation or an incomplete write. "
                        "Consider exporting an encrypted backup and verifying it.")
                    )
        else:
            detail_lines.append(_tr(
                "Vault file: not found on disk. If you haven't created any entries yet "
                "this can be normal; otherwise treat this as a serious issue.")
            )
    except Exception as e:
        detail_lines.append(_tr("Could not read vault file info") + f": {e}")

    # --- Encryption / KDF mode (static description) ---
    detail_lines.append(
            _tr("Encryption: AES-256-GCM for vault data, Argon2id for key derivation.")
    )

    # --- Backup reminder / auto-backup state ---
    try:
        mode = getattr(w, "_backup_remind_mode", "both")
        mode = (mode or "both").lower()
        if mode not in ("off", "changes", "logout", "both"):
            mode = "both"

        pending = 0
        if hasattr(w, "backupAdvisor") and w.backupAdvisor:
            try:
                pending = int(w.backupAdvisor.pending_changes())
            except Exception:
                pending = 0

        if mode == "off":
            detail_lines.append(
                    _tr("Backup reminders: Off. You won't be prompted to export encrypted backups automatically.")
            )
        else:
            pretty_mode = {
                "changes":  _tr("After N changes"),
                "logout":  _tr("On logout"),
                "both":    _tr("After changes and on logout"),
            }.get(mode, mode)
            detail_lines.append(
                    _tr("Backup reminders") + f": {pretty_mode} " +
                    _tr("(pending unsaved changes counter") + f": {pending})."
            )
    except Exception as e:
        detail_lines.append(_tr("Backup reminder state unavailable:") + f" {e}")

    # --- Last successful encrypted backup age (from user record) ---
    try:
           
        record = get_user_record(username) or {}
        backups = record.get("backups", {}) or {}
        # prefer vault-only backup, fall back to full backup
        last_ts = (
            backups.get("last_vault_backup")
            or backups.get("last_full_backup")
        )

        if last_ts:
            # try ISO first
            try:
                dt = datetime.fromisoformat(str(last_ts))
                days_ago = (datetime.utcnow().date() - dt.date()).days
                detail_lines.append(
                    _tr("Last encrypted backup:") + f" {dt.date().isoformat()} "
                    f"(~{days_ago} " + _tr("day(s) ago, recommended < 14 days).")
                )
                if days_ago > 30:
                    detail_lines.append(_tr(
                        "Warning: It has been more than 30 days since the last encrypted backup. "
                        "Consider creating a fresh backup and storing it offline.")
                    )
            except Exception:
                # unknown format: still show raw
                detail_lines.append(_tr("Last encrypted backup (raw timestamp): ") + f"{last_ts} " +
                    _tr("(format not recognised for age calculation).")
                )
        else:
            detail_lines.append(
                _tr("Last encrypted backup: none recorded yet. "
                "Consider creating an encrypted backup and storing it offline.")
            )
    except Exception as e:
        detail_lines.append(_tr("Backup history unavailable") + f": {e}")

    # --- Corruption flag explicit line ---
    if corrupted:
        detail_lines.append(_tr(
            "Vault corruption check") + ": ⚠ FAILED " + _tr("(see decrypt error above). "
            "If this persists, restore from a recent encrypted backup.")
        )
    elif vault_ok:
        detail_lines.append(_tr("Vault corruption check") + ": ✔ " + _tr("Passed (file decrypted successfully).")
        )

    # --- Push to UI ---
    try:
        w.vaultStatusLabel.setText(status_txt)
    except Exception:
        pass

    try:
        # Prepend a translated "Details:" to the joined lines
        w.vaultDetailsLabel.setText(
            _tr("Details:\n") + "\n".join(detail_lines)
        )
    except Exception:
        pass

    return vault_ok

def _update_security_clipboard_section(w) -> bool:
    """
    Update the 'Windows Clipboard History' row on the Security Center tab.

    Returns:
        clipboard_ok (bool) – True if history/cloud sync are OFF,
        False if either is ON.
    """
    clipboard_ok = False

    try:
        state = _win_clipboard_risk_state()
        history_on = bool(state.get("history"))
        cloud_on   = bool(state.get("cloud"))
        history_gpo = state.get("history_gpo")
        cloud_gpo   = state.get("cloud_gpo")

        # If GPO explicitly disables clipboard history/cloud, treat as safe
        gpo_forces_off = (
            history_gpo == 0 and cloud_gpo == 0
        )

        risky = history_on or cloud_on
        clipboard_ok = (not risky) or gpo_forces_off

        if not risky and not gpo_forces_off:
            # Both features off, no GPO overrides
            status = _tr("Status: ✔ Disabled")
            details = _tr(
                "Details: Windows Clipboard History and Cloud Clipboard are OFF. "
                "This is the recommended setting when using a password manager."
            )
        elif gpo_forces_off:
            status = _tr("Status: ✔ Disabled by policy")
            details = _tr(
                "Details: Group Policy disables clipboard history and cloud sync. "
                "Copied secrets will not be stored in Windows' multi-item clipboard."
            )
        else:
            # At least one is on
            warn_bits: list[str] = []
            if history_on:
                warn_bits.append(_tr("Clipboard History"))
            if cloud_on:
                warn_bits.append(_tr("Cloud Clipboard"))
            enabled_txt = " & ".join(warn_bits)

            status = _tr("Status:") + " ⚠ " + _tr("Enabled")
            details = _tr(
                "Details: {features} is ON. This means copied data can persist "
                "in the Windows clipboard history and/or sync between devices. "
                "For best security, consider turning these off in Windows Settings."
            ).format(features=enabled_txt)

    except Exception as e:
        status = _tr("Status:") + " ⚠ " + _tr("Error")
        details = _tr(
            "Details: Could not read clipboard settings: {err}"
        ).format(err=e)
        clipboard_ok = False

    try:
        w.systemClipboardStatusLabel.setText(status)
    except Exception:
        pass
    try:
        w.systemClipboardDetailsLabel.setText(details)
    except Exception:
        pass

    return clipboard_ok

def on_security_open_integrity_clicked(w) -> None:
    """Run the normal integrity check dialog from the Security Center tab."""
    username = (w.currentUsername.text() or "").strip()
    if not username:
        QMessageBox.information(w, _tr("Integrity Check"),
                                _tr("Please log in or select a user first."))
        return

    try:
        w.integrity_check_and_prompt(username)
    except Exception as e:
        msg = _tr("Could not run integrity check:") + f"\n{e}"
        QMessageBox.warning(w, _tr("Integrity Check"), msg)               

def _update_security_score(
    w,
    *,
    baseline_ok: bool,
    manifest_ok: bool,
    preflight_ok: bool,
    av_ok: bool,
    twofa_on: bool,
    yubikey_on: bool,
    backups_ok: bool,
    strong_password: bool,
    system_ok: bool,
    updates_ok: bool,
    clipboard_ok: bool,
    vault_ok: bool,
) -> None:
    score = 0

    # Weights – tune these however you like
    if strong_password:
        score += 15
    if twofa_on:
        score += 15
    if yubikey_on:
        score += 10
    if backups_ok:
        score += 10

    if baseline_ok:
        score += 15
    if manifest_ok:
        score += 10
    if preflight_ok:
        score += 10
    if av_ok:
        score += 5

    if system_ok:
        score += 5
    if updates_ok:
        score += 5

    if clipboard_ok:
        score += 5

    if vault_ok:
        score += 5 

    score = max(0, min(100, score))

    if score >= 90:
        level = _tr("Excellent")
    elif score >= 70:
        level = _tr("Strong")
    elif score >= 40:
        level = _tr("Moderate")
    else:
        level = _tr("Weak")

    try:
        #w.securityScoreLabel.setText(f"Security Score: {score}/100 — {level}")
        w.securityScoreLabel.setText(_tr("Security Score:") + f" {score}/100 — {level}")
    except Exception:
        pass

    try:
        w.securityScoreBar.setValue(score)
    except Exception:
        pass

def _update_security_account_section(w, username: str):
    """
    Fill the Account section on the Security Center tab.

    Returns:
        (twofa_on, yubikey_on, backups_ok, strong_password)
    """
    from auth.identity_store import (
        has_totp_quick,
        get_login_backup_count_quick,
        get_yubi_meta_quick,
    )
    from security.timestamp_utils import format_timestamp_for_display


    twofa_on = False
    yubikey_on = False
    backups_ok = False
    strong_password = False

    # --- Defaults for display ---
    pwd_strength_txt = _tr("Password Strength: (unknown)")
    twofa_txt = _tr("2FA: (unknown)")
    yk_txt = _tr("YubiKey: (unknown)")
    backup_txt = _tr("Backup codes: (unknown)")
    last_full = _tr("Last Full Backup: (unknown)")
    last_vault = _tr("Last Vault Backup: (unknown)")
    last_pwd = _tr("Last Password Change: (unknown)")

    # --- Load user record from normal user_db path ---
    record = {}
    try:
        record = get_user_record(username) or {}
    except Exception:
        record = {}

    # --- Account type / mode ---
    try:
        if get_user_setting(username, "recovery_mode") is True:
            account_type_mod = _tr("Account Mode: Recovery Enabled")
        else:
            account_type_mod = _tr("Account Mode: Maximum Security (No Recovery)")
    except Exception:
        account_type_mod = _tr("Account Mode: (unknown)")

    # --- Password strength (per-session, from w.ps_score) ---
    try:
        score = getattr(w, "ps_score", None)
        if score is None:
            pwd_strength_txt = _tr(
                "Password Strength: (unknown — requires active login)"
            )
            strong_password = False
        else:
            score = int(score)
            if score >= 80:
                level = _tr("Very Strong")
            elif score >= 60:
                level = _tr("Strong")
            elif score >= 40:
                level = _tr("Medium")
            else:
                level = _tr("Weak")

            pwd_strength_txt = _tr("Password Strength") + f": {level} ({score}/100)"
            strong_password = score >= 60
    except Exception:
        pwd_strength_txt = _tr("Password Strength: (unknown)")
        strong_password = False

    # --- 2FA status (prefer identity_store header flag) ---
    live_has_2fa = None
    try:
        live_has_2fa = bool(has_totp_quick(username))
    except Exception:
        live_has_2fa = None

    # fallback to record if needed
    try:
        rec_twofa = record.get("twofa", {}) if isinstance(record, dict) else {}
        rec_enabled = bool(rec_twofa.get("enabled", False))
        last_2fa_ts = rec_twofa.get("last_updated") or rec_twofa.get("created_at")
    except Exception:
        rec_twofa = {}
        rec_enabled = False
        last_2fa_ts = None

    if live_has_2fa is not None:
        twofa_on = live_has_2fa
    else:
        twofa_on = rec_enabled

    if twofa_on:
        if last_2fa_ts:
            twofa_txt = _tr(
                "2FA: Enabled (since {timestamp})"
            ).format(timestamp=format_timestamp_for_display(last_2fa_ts))
        else:
            twofa_txt = _tr("2FA: Enabled")
    else:
        twofa_txt = _tr("2FA: Disabled")

    # --- YubiKey status (quick header) ---
    try:
        yk_enabled, mode = get_yubi_meta_quick(username)
        yubikey_on = bool(yk_enabled)
        if yubikey_on:
            yk_txt = _tr("YubiKey: Enabled ({mode})").format(
                mode=mode or _tr("Unknown mode")
            )
        else:
            yk_txt = _tr("YubiKey: Disabled")
    except Exception:
        yubikey_on = False
        # Keep previous default text for yk_txt

    # --- Backups (full + vault timestamps from user_db) ---
    login_backup_count = 0
    try:
        backups = record.get("backups", {}) if isinstance(record, dict) else {}
        last_full_ts = backups.get("last_full_backup")
        last_vault_ts = backups.get("last_vault_backup")

        if last_full_ts:
            last_full = _tr("Last Full Backup: {ts}").format(
                ts=format_timestamp_for_display(last_full_ts)
            )
        if last_vault_ts:
            last_vault = _tr("Last Vault Backup: {ts}").format(
                ts=format_timestamp_for_display(last_vault_ts)
            )

        # plain backups_ok if we have *any* backup timestamp
        backups_ok = bool(last_full_ts or last_vault_ts)
        backup_txt = (
            _tr("Backups: Available")
            if backups_ok
            else _tr("Backups: None recorded")
        )
    except Exception as e:
        log.info(f"Backup text error {e}")
        # keep defaults

    # --- Login backup codes (identity_store quick header) ---
    try:
        login_backup_count = int(get_login_backup_count_quick(username))
    except Exception:
        login_backup_count = 0

    # Include them in the backup summary
    if login_backup_count > 0:
        backup_txt += _tr(
            " — {count} login backup codes configured"
        ).format(count=login_backup_count)
        backups_ok = True  # having codes is good for overall score
    else:
        backup_txt += _tr(" — no login backup codes configured")

    # --- Last password change (from user_db) ---
    try:
        last_pwd_ts = record.get("last_password_change")
        if last_pwd_ts:
            last_pwd = _tr("Last Password Change: {ts}").format(
                ts=format_timestamp_for_display(last_pwd_ts)
            )
    except Exception:
        pass

    # --- Push to UI (guarded so older UI doesn’t crash) ---
    def _set(lbl_name: str, text: str):
        try:
            getattr(w, lbl_name).setText(text)
        except Exception:
            pass

    _set("recovery_m_2", account_type_mod)
    _set("accountPasswordStrengthLabel", pwd_strength_txt)
    _set("accountTwofaStatusLabel", twofa_txt)
    _set("accountYubiStatusLabel", yk_txt)
    _set("accountBackupStatusLabel", backup_txt)
    _set("accountBackupLastFullLabel", last_full)
    _set("accountBackupLastVaultLabel", last_vault)
    _set("accountPasswordLastChangedLabel", last_pwd)

    return twofa_on, yubikey_on, backups_ok, strong_password

def _update_security_system_section(w):
    """
    Fully detailed System section.
    Returns boolean 'system_ok' used in scoring.
    """
    from device.system_info import get_basic_system_info

    # Windows-only security signals (TPM / Secure Boot / DMA protection / activation)
    if IS_WINDOWS:
        from security.windows_security import (
            tpm_status, secure_boot_status,
            kernel_dma_protection, windows_activation_status
        )
    else:
        # Graceful fallback on macOS/Linux
        def tpm_status(): return ("N/A (not Windows)", True)
        def secure_boot_status(): return ("N/A (not Windows)", True)
        def kernel_dma_protection(): return ("N/A (not Windows)", True)
        def windows_activation_status(): return ("N/A (not Windows)", True)

    sysmeta = get_basic_system_info()

    # --- TPM ---
    tpm_txt, tpm_good = tpm_status()

    # --- Secure Boot ---
    sb_txt, sb_good = secure_boot_status()

    # --- Kernel DMA ---
    dma_txt, dma_good = kernel_dma_protection()

    # --- Activation ---
    act_txt, act_good = windows_activation_status()

    # Good system if Windows + 64-bit + TPM + Secure Boot
    system_ok = bool(
        (sysmeta.get("os_name", "").lower().startswith("win"))
        and sysmeta.get("bits") == 64
        and tpm_good
        and sb_good
    )

    # --- Write to labels ---
    def _set(lbl, val):
        try:
            getattr(w, lbl).setText(val)
        except Exception:
            pass

    _set(
        "systemTpmStatusLabel",
        _tr("TPM Status: {status}").format(status=tpm_txt),
    )
    _set(
        "systemSecureBootStatusLabel",
        _tr("Secure Boot Status: {status}").format(status=sb_txt),
    )
    _set(
        "systemKernelDmaStatusLabel",
        _tr("Kernel DMA Protection: {status}").format(status=dma_txt),
    )
    _set(
        "systemWindowsActivatedLabel",
        _tr("Activation: {status}").format(status=act_txt),
    )

    # OS line
    pretty = sysmeta.get("pretty", None) or _tr("Unknown")
    arch = sysmeta.get("arch", "")
    hostname = sysmeta.get("hostname", "(unknown)")
    _set(
        "systemDeviceIdLabel",
        _tr("Device: {hostname} • {pretty} • {arch}").format(
            hostname=hostname,
            pretty=pretty,
            arch=arch,
        ),
    )

    return system_ok

def _update_security_windows_updates(w):
    from device.system_info import get_windows_update_status

    try:
        upd = get_windows_update_status()
    except Exception as e:
        upd = {
            "ok": False,
            "status_text": _tr("Error: {err}").format(err=e)
        }

    ok = upd.get("ok", False)

    if ok:
        status_txt = _tr("Status: ✔ Up to date (within policy window)")
    else:
        status_txt = _tr("Status: ⚠ Stale or Unknown")

    # status_text may be a template string from system_info, so wrap if literal
    detail_raw = upd.get("status_text", "")
    if isinstance(detail_raw, str):
        detail = detail_raw  # already a string, might be translated above
    else:
        detail = _tr("No update information available.")

    try:
        w.windowsUpdatesStatusLabel.setText(status_txt)
        w.windowsUpdatesDetailsLabel.setText(
            _tr("Details: {detail}").format(detail=detail)
        )
    except Exception:
        pass

    return ok

def _sec_center_collect_system_info(w, force: bool = False) -> dict:
    """
    Collect system + Windows Update info for the Security Center tab.
    Uses security.system_info helpers (best effort).
    """
    info: dict = {"system": {}, "updates": {}}
    try:
        info["system"] = get_basic_system_info() or {}
    except Exception as e:
        log.warning("[SEC] system basic info failed: %s", e)

    try:
        info["updates"] = get_windows_update_status() or {}
    except Exception as e:
        log.warning("[SEC] Windows Update status failed: %s", e)

    return info

def _update_backup_timestamp(w, username: str, field: str) -> None:
    """
    Persist a backup timestamp for Security Center.

    field should usually be:
        - 'last_full_backup'
        - 'last_vault_backup'
    """
    if not username:
        return

    try:
        from security.timestamp_utils import now_utc_iso

        record = get_user_record(username) or {}
        backups = record.get("backups", {}) or {}
        backups[field] = now_utc_iso()
        record["backups"] = backups
        set_user_record(username, record)
    except Exception as e:
        log.warning(
            "[SEC] Failed to persist backup timestamp %r for %r: %s",
            field,
            username,
            e,
        )

def _security_center_clear_ui(w) -> None:
    """
    Clear Security Center UI + any cached per-session state so the next user
    doesn't see previous user's results.
    Call this on logout and before loading a different user.
    """
    # --- stop/ignore any running worker ---
    try:
        w = getattr(w, "_sc_worker", None)
        if w:
            # mark worker as cancelled so finish signal can't update UI
            setattr(w, "_kq_cancelled", True)
            # ask thread to stop if it supports it
            try:
                w.requestInterruption()
            except Exception:
                pass
            try:
                w.quit()
            except Exception:
                pass
            try:
                w.wait(150)  # small wait; don't hang UI
            except Exception:
                pass
    except Exception:
        pass

    # --- clear labels / text fields (guarded) ---
    def _set(name: str, text: str = ""):
        try:
            getattr(w, name).setText(text)
        except Exception:
            pass

    # Baseline
    _set("baselineIntegrityStatus", _tr("Status: (not scanned)"))
    _set("baselineIntegrityDetails", "")

    # Manifest
    _set("manifestIntegrityStatus", _tr("Status: (not scanned)"))
    _set("manifestIntegrityDetails", "")

    # Process scan / preflight
    _set("processScanStatus", _tr("Status: (not scanned)"))
    _set("processScanDetails", "")

    # Vault status
    _set("vaultStatusLabel", _tr("Status: Locked"))
    _set("vaultDetailsLabel", "")

    # Antivirus
    _set("antivirusStatus", _tr("Status: (unknown)"))
    _set("antivirusDetails", "")

    # Clipboard history section (you have two variants; clear both safely)
    _set("windowsClipboardStatusLabel", _tr("Status: (unknown)"))
    _set("windowsClipboardDetailsLabel", "")
    _set("systemClipboardStatusLabel", _tr("Status: (unknown)"))
    _set("systemClipboardDetailsLabel", "")

    # Windows updates
    _set("windowsUpdatesStatusLabel", _tr("Status: (unknown)"))
    _set("windowsUpdatesDetailsLabel", "")

    # Account section
    _set("recovery_m_2", _tr("Account Mode: (unknown)"))
    _set("accountPasswordStrengthLabel", _tr("Password Strength: (unknown)"))
    _set("accountTwofaStatusLabel", _tr("2FA: (unknown)"))
    _set("accountYubiStatusLabel", _tr("YubiKey: (unknown)"))
    _set("accountBackupStatusLabel", _tr("Backups: (unknown)"))
    _set("accountBackupLastFullLabel", _tr("Last Full Backup: (unknown)"))
    _set("accountBackupLastVaultLabel", _tr("Last Vault Backup: (unknown)"))
    _set("accountPasswordLastChangedLabel", _tr("Last Password Change: (unknown)"))

    # System section
    _set("systemTpmStatusLabel", "")
    _set("systemSecureBootStatusLabel", "")
    _set("systemKernelDmaStatusLabel", "")
    _set("systemWindowsActivatedLabel", "")
    _set("systemDeviceIdLabel", "")

    # Score / status bar
    try:
        w.securityScoreBar.setValue(0)
    except Exception:
        pass
    _set("securityScoreLabel", _tr("Security Score: 0/100 — (not scanned)"))

    try:
        w.set_status_txt(_tr("Logged out — Security Center cleared"))
    except Exception:
        pass

    # --- clear per-session cache values that affect account panel ---
    try:
        if hasattr(w, "ps_score"):
            w.ps_score = None
    except Exception:
        pass
