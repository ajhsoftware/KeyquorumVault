from pathlib import Path
from native.keyquorum_core_ctypes import KeyquorumCore

dll = Path(__file__).resolve().parent / "bin" / "keyquorum_core.dll"

core = KeyquorumCore(str(dll))
print("✅ DLL loaded successfully")
