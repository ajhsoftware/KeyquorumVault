import sys

def is_frozen() -> bool:
    return getattr(sys, "frozen", False)
