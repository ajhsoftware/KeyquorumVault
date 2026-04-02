from __future__ import annotations

import re
import webbrowser
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

import requests
from qtpy.QtCore import QObject, Signal
from qtpy.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
)

from app.basic import get_app_version
from features.url.main_url import SITE_GITHUB


CURRENT_VERSION = str(get_app_version() or "0.0.0")
PREFERRED_ASSET_EXTENSIONS = (".exe", ".msi", ".zip")
BLOCKED_RELEASE_KEYWORDS = (
    "lang",
    "language",
    "pack",
    "theme",
    "icons",
    "assets-only",
    "schema",
    "category",
)


@dataclass
class ReleaseInfo:
    tag_name: str
    name: str
    html_url: str
    body: str
    published_at: str
    asset_name: Optional[str] = None
    asset_url: Optional[str] = None


class UpdateError(Exception):
    pass


def _repo_from_url(url: str) -> tuple[str, str]:
    """Extract owner/repo from a GitHub repo URL."""
    text = (url or "").strip()
    if not text:
        raise UpdateError("SITE_GITHUB is empty.")

    parsed = urlparse(text)
    parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) < 2:
        raise UpdateError(f"Could not parse GitHub owner/repo from: {text}")

    owner = parts[0]
    repo = parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    return owner, repo


DEFAULT_OWNER, DEFAULT_REPO = _repo_from_url(SITE_GITHUB)


def _normalize_version(version: str) -> tuple[int, ...]:
    if not version:
        return (0,)

    version = str(version).strip().lower()
    if version.startswith("v"):
        version = version[1:]

    parts = re.findall(r"\d+", version)
    if not parts:
        return (0,)
    return tuple(int(p) for p in parts)


def is_newer_version(latest: str, current: str) -> bool:
    return _normalize_version(latest) > _normalize_version(current)


def _looks_like_app_release(tag: str, name: str, body: str = "") -> bool:
    """
    Return True only for real app releases.

    Important:
    - Reject language packs / schema packs / asset-only releases first
    - Then accept normal app version tags such as v1.7.2
    """
    tag_l = (tag or "").strip().lower()
    name_l = (name or "").strip().lower()
    body_l = (body or "").strip().lower()
    text = f"{tag_l} {name_l} {body_l}"

    # Reject non-app releases first.
    if any(word in text for word in BLOCKED_RELEASE_KEYWORDS):
        return False

    # Accept proper app version tags.
    if re.fullmatch(r"v\d+(?:\.\d+){1,3}", tag_l):
        return True

    # Fallback: allow explicit version text in title/body if it is not blocked.
    if re.search(r"\bv\d+(?:\.\d+){1,3}\b", text):
        return True

    return False


def _pick_preferred_asset(assets: list[dict]) -> tuple[Optional[str], Optional[str]]:
    for ext in PREFERRED_ASSET_EXTENSIONS:
        for asset in assets or []:
            candidate_name = str(asset.get("name") or "")
            candidate_url = str(asset.get("browser_download_url") or "")
            if candidate_name.lower().endswith(ext) and candidate_url:
                return candidate_name, candidate_url
    return None, None


def _release_from_json(data: dict) -> ReleaseInfo:
    tag_name = str(data.get("tag_name") or "").strip()
    name = str(data.get("name") or tag_name or "Untitled release").strip()
    html_url = str(data.get("html_url") or "").strip()
    body = str(data.get("body") or "").strip()
    published_at = str(data.get("published_at") or "").strip()

    if not tag_name or not html_url:
        raise UpdateError("Release data is incomplete.")

    asset_name, asset_url = _pick_preferred_asset(data.get("assets") or [])
    return ReleaseInfo(
        tag_name=tag_name,
        name=name,
        html_url=html_url,
        body=body,
        published_at=published_at,
        asset_name=asset_name,
        asset_url=asset_url,
    )


def fetch_latest_release(owner: str, repo: str, timeout: int = 8) -> ReleaseInfo:
    """
    Privacy-first updater behaviour:
    - Manual check only
    - No telemetry
    - Only contacts GitHub when the user clicks the update button
    - Uses the releases list so we can skip non-app releases like language packs
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/releases"
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": f"{repo}-manual-update-check",
    }

    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
    except requests.RequestException as exc:
        raise UpdateError(f"Could not contact GitHub: {exc}") from exc

    if resp.status_code == 404:
        raise UpdateError("No GitHub releases found. Check the repo URL and make sure releases exist.")
    if resp.status_code == 403:
        raise UpdateError("GitHub rate limit reached. Please try again later.")
    if resp.status_code != 200:
        raise UpdateError(f"GitHub returned HTTP {resp.status_code}")

    try:
        releases = resp.json()
    except ValueError as exc:
        raise UpdateError("GitHub returned invalid JSON.") from exc

    if not isinstance(releases, list) or not releases:
        raise UpdateError("No GitHub releases were returned.")

    for rel in releases:
        if not isinstance(rel, dict):
            continue

        if rel.get("draft"):
            continue

        if rel.get("prerelease"):
            continue

        tag = str(rel.get("tag_name") or "")
        name = str(rel.get("name") or "")
        body = str(rel.get("body") or "")

        if not _looks_like_app_release(tag, name, body):
            continue
        return _release_from_json(rel)

    raise UpdateError("No suitable app release was found in GitHub releases.")


class UpdateDialog(QDialog):
    def __init__(self, parent, current_version: str, release: ReleaseInfo):
        super().__init__(parent)
        self.setWindowTitle("Update available")
        self.resize(700, 500)

        layout = QVBoxLayout(self)

        info = QLabel(
            f"<b>Current version:</b> {current_version}<br>"
            f"<b>Latest version:</b> {release.tag_name}<br>"
            f"<b>Release:</b> {release.name}<br>"
            f"<b>Published:</b> {release.published_at}"
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        notes = QTextEdit(self)
        notes.setReadOnly(True)
        notes.setPlainText(release.body or "No release notes provided.")
        layout.addWidget(notes)

        privacy_note = QLabel(
            "Manual check only. No background updater or telemetry. "
            "Downloads open in your browser only if you choose them."
        )
        privacy_note.setWordWrap(True)
        layout.addWidget(privacy_note)

        btn_row = QHBoxLayout()

        self.btn_open_release = QPushButton("Open Release Page")
        self.btn_open_release.clicked.connect(lambda: webbrowser.open(release.html_url))
        btn_row.addWidget(self.btn_open_release)

        self.btn_download = QPushButton("Download Installer")
        self.btn_download.setEnabled(bool(release.asset_url))
        if release.asset_url:
            self.btn_download.clicked.connect(lambda: webbrowser.open(release.asset_url))
        btn_row.addWidget(self.btn_download)

        self.btn_close = QPushButton("Close")
        self.btn_close.clicked.connect(self.accept)
        btn_row.addWidget(self.btn_close)

        layout.addLayout(btn_row)


class AppUpdater(QObject):
    update_check_started = Signal()
    update_check_finished = Signal(bool, str)

    def __init__(
        self,
        parent=None,
        owner: str = DEFAULT_OWNER,
        repo: str = DEFAULT_REPO,
        current_version: str = CURRENT_VERSION,
    ):
        super().__init__(parent)
        self.parent = parent
        self.owner = owner
        self.repo = repo
        self.current_version = str(current_version or "0.0.0")

    def check_for_updates(self, show_no_update_message: bool = True) -> None:
        self.update_check_started.emit()

        try:
            release = fetch_latest_release(self.owner, self.repo)
        except UpdateError as exc:
            self.update_check_finished.emit(False, str(exc))
            QMessageBox.warning(self.parent, "Update check failed", str(exc))
            return

        latest = release.tag_name

       
        if is_newer_version(latest, self.current_version):
            try:
                from features.systemtray.systemtry_ops import notify_update
                notify_update(self, latest)
            except Exception:
                pass

            self.update_check_finished.emit(True, latest)
            dlg = UpdateDialog(self.parent, self.current_version, release)
            dlg.exec()
            return

        self.update_check_finished.emit(True, latest)

        try:
            from features.systemtray.systemtry_ops import notify_other
            notify_other(self, "No update availabl", "You are already on the latest version.")
        except Exception:
            pass
        QMessageBox.information(
            self.parent,
            "No update available",
            "You are already on the latest version.\n\n"
            f"Current version: {self.current_version}\n"
            f"Latest version: {latest}",
        )


def bind_update_button(window) -> AppUpdater:
    """
    Helper to wire update_btn from a settings page/window.

    Usage:
        self.updater = bind_update_button(self)
    """
    updater = AppUpdater(parent=window)
    btn = getattr(window, "update_btn", None)
    if btn is None:
        raise AttributeError("Window does not have an 'update_btn' attribute.")
    btn.clicked.connect(updater.check_for_updates)
    return updater
