import datetime as dt
from app.qt_imports import *

# ===========
# --- scan for reminders
# ===========
def scan_due_reminders(self):
    try:
        from vault_store.vault_store import load_vault
        from features.reminders.reminders_dialog import _parse_date
    except Exception as e:
        log.error(f"[REMINDERS] import failed: {e}")
        return []

    username = self._active_username() if hasattr(self, "_active_username") else ""
    session = getattr(self, "core_session_handle", None)

    if not username or not session:
        return []

    try:
        entries = load_vault(username, session) or []
    except Exception as e:
        log.error(f"[REMINDERS] load failed: {e}")
        return []

    today = dt.datetime.now().date()
    due_rows = []

    for idx, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue

        due_raw = (
            entry.get("Reminder Date")
            or entry.get("reminder_date")
            or entry.get("Reminder")
            or entry.get("reminder")
            or entry.get("due_date")
            or entry.get("due")
        )

        due = _parse_date(due_raw)
        if not due:
            continue

        title = (
            entry.get("Title")
            or entry.get("title")
            or entry.get("Name")
            or entry.get("name")
            or entry.get("Service")
            or entry.get("service")
            or entry.get("Platform")
            or entry.get("platform")
            or f"Item #{idx+1}"
        )

        days = (due - today).days
        if days < 0:
            status = "overdue"
        elif days == 0:
            status = "today"
        elif days <= 7:
            status = "upcoming"
        else:
            status = "scheduled"

        due_rows.append({
            "index": idx,
            "title": str(title).strip(),
            "due": due,
            "status": status,
        })

    return due_rows


# =============
# --- send to tray
# =============
def notify_due_reminders(self, force_not=False):
    rows = self.scan_due_reminders()
    if not rows:
        return
   
    overdue = [r for r in rows if r["status"] == "overdue"]
    today = [r for r in rows if r["status"] == "today"]
    upcoming = [r for r in rows if r["status"] == "upcoming"]

    total_alert = len(overdue) + len(today) + len(upcoming)
    if total_alert <= 0:
        return

    summary = (
        len(overdue),
        len(today),
        len(upcoming),
    )


    if getattr(self, "_last_reminder_summary", None) == summary and not force_not:
        return

    self._last_reminder_summary = summary

    from features.systemtray.systemtry_ops import notify
    notify(
        self,
        "🔔 Reminders",
        f"Overdue: {len(overdue)} | Due today: {len(today)} | Upcoming: {len(upcoming)}"
    )


# ==============================
# --- background worker to check reminders every 10 mins ---
# ==============================
def start_watchtower_reminder_worker(self):
    try:
        from qtpy.QtCore import QThread, QTimer
        from workers.watchtower_reminder_worker import WatchtowerReminderWorker

        if getattr(self, "_wtr_thread", None):
            return

        self._wtr_thread = QThread(self)
        self._wtr_worker = WatchtowerReminderWorker(self)
        self._wtr_worker.moveToThread(self._wtr_thread)

        self._wtr_worker.changed.connect(self._on_worker_alert)

        self._wtr_thread.start()

        self._wtr_timer = QTimer(self)
        self._wtr_timer.timeout.connect(self._wtr_worker.run_once)
        self._wtr_timer.start(10 * 60 * 1000)  # 10 mins

        # run once after login
        QTimer.singleShot(3000, self._wtr_worker.run_once)

    except Exception as e:
        log.error(f"start watchtower reminder error: {e}")


def _on_worker_alert(self, data):
    try:
        from features.systemtray.systemtry_ops import notify, notify_update_watchtower
        rem = data["reminders"]
        # --- reminders ---
        if sum(rem) > 0:
            notify(
                self,
                "🔔 Reminders",
                f"Overdue: {rem[0]} | Today: {rem[1]} | Upcoming: {rem[2]}"
            )
    except Exception as e:
        log.error(f"[WORKER] notify failed: {e}")
