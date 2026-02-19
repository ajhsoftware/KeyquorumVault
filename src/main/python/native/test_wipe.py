# all keep users testing: a quick wipe testing using dll file
# run python -m native.test_wipe
# Working respnose: ✅ secure_wipe worked 

from native.native_core import get_core

core = get_core()
assert core, "DLL not loaded"

buf = bytearray(b"SECRETSECRETSECRET")
print("Before:", buf)

core.secure_wipe(buf)
print("After: ", buf)

# This should print all zeros:
assert all(b == 0 for b in buf), "wipe failed"
print("✅ secure_wipe worked")
