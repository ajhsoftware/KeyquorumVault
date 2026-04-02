from app.qt_imports import *
import time


def setup_tray(self):
    try:
        from app.paths import icon_file
        icon = QIcon(str(icon_file("icon.png")))

        self.tray = QSystemTrayIcon(self)
        self.tray.setIcon(icon)
        self.tray.setToolTip("Keyquorum Vault")
        self.tray.show()

     
        self.tray.showMessage(
            "Keyquorum test 2",
            "Testing custom icon notification.",
            QSystemTrayIcon.Information,
            5000,
        )

        self.last_alerts = {
            "expired": 0,
            "breach": 0,
            "reminder": 0,
            "watchtower": 0,
        }

        self.last_counts = {
            "expired": 0,
            "breach": 0,
            "reminder": 0,
        }

    except Exception as e:
        log.error(f"Tray Setup Error {e}")


def notify(self, title, message, icon=QSystemTrayIcon.Information):
    if getattr(self, "tray", None):
        self.tray.showMessage(title, message, icon, 5000)


def timer_set(self):
    self.alert_timer = QTimer(self)
    self.alert_timer.timeout.connect(self.run_alert_checks)
    self.alert_timer.start(15 * 60 * 1000)


def _should_alert(self, key, count, cooldown_secs=900):
    now = time.time()
    last_time = self.last_alerts.get(key, 0)
    last_count = self.last_counts.get(key, 0)

    changed = count != last_count
    cooled_down = (now - last_time) >= cooldown_secs

    if changed or cooled_down:
        self.last_alerts[key] = now
        self.last_counts[key] = count
        return True
    return False


def notify_breached_passwords(self, breached_passwords):
    count = len(breached_passwords or [])
    if count <= 0:
        return
    if self._should_alert("breach", count):
        notify(self,
            "🚨 Security Alert",
            f"{count} password(s) found in breaches!"
        )


def notify_other(self, title, text):
    notify(self, title, text)


def notify_update(self, version):
    notify(self,
        "🔄 App Update",
        f"A newer version is available: {version}"
    )


def notify_update_watchtower(
    self,
    weak_pw=0,
    reused_pw=0,
    breach_pw=0,
    http_only_urls=0,
    missing_username=0,
    missing_urls=0,
    tfa_disabled=0,
    card_exp=0,
    item_exp=0,
):
    total = (
        weak_pw
        + reused_pw
        + breach_pw
        + http_only_urls
        + missing_username
        + missing_urls
        + tfa_disabled
        + card_exp
        + item_exp
    )

    if total <= 0:
        return

    notify(self,
        "👁️‍🗨️ Watchtower Checker",
        (
            f"Weak: {weak_pw} | "
            f"Reused: {reused_pw} | "
            f"Breach: {breach_pw} | "
            f"HTTP: {http_only_urls} | "
            f"No username: {missing_username} | "
            f"No URL: {missing_urls} | "
            f"No 2FA: {tfa_disabled} | "
            f"Cards Exp: {card_exp} | "
            f"Expired: {item_exp}"
        )
    )


# ============
# --- Quick toast 
# ============

def _toast(self, message: str, msec: int = 2500):
    # Quick toast
    try: 
        pos = self.mapToGlobal(QPoint(20, 20))
        QToolTip.showText(pos, message, self, self.rect(), msec)
    except Exception:
        pass      
