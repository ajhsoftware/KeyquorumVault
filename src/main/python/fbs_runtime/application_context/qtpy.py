import os
import sys

class ApplicationContext:
    """
    Minimal compatibility shim for fbs_runtime.application_context.qtpy.ApplicationContext
    """

    def __init__(self):
        self.build_settings = {
            "version": "v1.8.9"
        }

    def get_resource(self, relative_path: str) -> str:
        """
        Best-effort resource resolver compatible with fbs-style calls.
        """
        base = getattr(sys, "_MEIPASS", os.getcwd())
        return os.path.join(base, relative_path)
