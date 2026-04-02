from __future__ import annotations
import hashlib, json, logging
from qtpy.QtCore import QObject, Signal, Slot

log = logging.getLogger("keyquorum")


class WatchtowerReminderWorker(QObject):
    changed = Signal(dict)
    error = Signal(str)

    def __init__(self, app):
        super().__init__()
        self.app = app
        self._last = None

    def _digest(self, data):
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

    @Slot()
    def run_once(self):
        try:
            username = self.app._active_username()
            session = getattr(self.app, "core_session_handle", None)

            if not username or not session:
                return
            # watchtower scan
            self.app._watchtower_rescan()
            # --- reminders ---
            from features.reminders.reminder_ops import scan_due_reminders
            rows = scan_due_reminders(self.app) or []

            overdue = sum(1 for r in rows if r["status"] == "overdue")
            today = sum(1 for r in rows if r["status"] == "today")
            upcoming = sum(1 for r in rows if r["status"] == "upcoming")

            data = {
                "reminders": (overdue, today, upcoming),
            }

            d = self._digest(data)

            if d != self._last:
                self._last = d
                self.changed.emit(data)

        except Exception as e:
            self.error.emit(str(e))
