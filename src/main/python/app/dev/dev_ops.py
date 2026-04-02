import os

# set using powershell: [System.Environment]::SetEnvironmentVariable("KEYQUORUM_DEV", "1", "User")
# check: echo $env:KEYQUORUM_DEV
dev_set = False
STRICT_NATIVE_CORE = True
DEBUG_ON = False

def is_dev_mode() -> bool:
    """Return whether developer mode is enabled for this process."""
    global dev_set
    try:
        dev_set = os.environ.get("KEYQUORUM_DEV", "0") == "1"
        return dev_set
    except Exception as e:
        dev_set = False
        return False

def set_dev_values() -> bool:
    """Initialise module-level dev flags from the environment and return dev state."""
    global DEBUG_ON, STRICT_NATIVE_CORE
    dev_enabled = is_dev_mode()
    DEBUG_ON = bool(dev_enabled)
    # Public builds stay strict native even in dev unless changed manually for testing.
    STRICT_NATIVE_CORE = True
    if dev_enabled:
        os.environ["KQ_CONSOLE"] = "1"
    return dev_enabled

def is_dev() -> bool:
    """Convenience helper for code that wants a function call."""
    return bool(dev_set)

# Initialise once on import so every module sees a consistent value.
set_dev_values()
