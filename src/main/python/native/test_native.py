# quick test Native
# python -m native.test_native

from native.native_core import get_core

core = get_core()

if core:
    print("Native version:", core.version())
else:
    print("Native core NOT loaded")
