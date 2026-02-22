# Keyquorum Vault - Development / Smoke Test Tool
# Copyright (C) 2026 Anthony Hatton
#
# This file is part of Keyquorum Vault.
#
# Keyquorum Vault is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Keyquorum Vault is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

# ============================================================================================================

@echo off
cd /d "%~dp0"
python kv_auto_tests_V5.py --all
