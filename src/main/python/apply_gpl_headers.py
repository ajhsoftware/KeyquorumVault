"""
Keyquorum Vault
Copyright (C) 2025-2026 Anthony Hatton (AJH Software)

This file is part of Keyquorum Vault.

Keyquorum Vault is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Keyquorum Vault is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
"""

from pathlib import Path

GPL_HEADER = '''"""
Keyquorum Vault
Copyright (C) 2025-2026 Anthony Hatton (AJH Software)

This file is part of Keyquorum Vault.

Keyquorum Vault is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Keyquorum Vault is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
"""

'''

PROJECT_ROOT = Path(".")

for py_file in PROJECT_ROOT.rglob("*.py"):
    if "__pycache__" in str(py_file):
        continue

    content = py_file.read_text(encoding="utf-8")

    # Remove old proprietary header if present
    if "All rights reserved" in content or "AJH Software" in content.split("\n", 5)[0]:
        lines = content.split("\n")
        # Remove first docstring block
        if lines[0].startswith('"""'):
            end = 0
            for i, line in enumerate(lines[1:], 1):
                if line.startswith('"""'):
                    end = i
                    break
            content = "\n".join(lines[end+1:])

    py_file.write_text(GPL_HEADER + content, encoding="utf-8")

print("GPL headers applied successfully.")
