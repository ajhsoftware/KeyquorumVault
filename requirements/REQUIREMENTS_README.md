# Requirements files (Keyquorum Vault)

These files were cleaned up to match the Python project you uploaded.

## Files

- `requirements.txt`
  Human-edited runtime dependencies for normal development.

- `requirements-lock.txt`
  Pinned runtime dependencies for clean release / build installs.

- `requirements-build.txt`
  Packaging tools used for builds.

- `requirements-dev.txt`
  Extra tools for local development and tests.

## Notes

- `fbs Pro` is **not** installed from pip like a normal package. If you use it, install or activate it separately.
- Your code imports `PySide6`, `QtPy`, `requests`, `cryptography`, `argon2-cffi`, `bcrypt`, `pyotp`, `qrcode`, `segno`, `reportlab`, `PyPDF2`, `pikepdf`, `numpy`, `opencv-python`, `psutil`, `tldextract`, and several Windows-only packages.
- Old extras such as `googletrans`, `httpx`, `httpcore`, and similar packages were **not** kept because they do not appear to be imported by the uploaded project.

## Recommended install flows

### Normal dev install

```bat
python -m venv venv
venv\Scripts\activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements/requirements.txt
python -m pip install -r requirements/requirements-dev.txt
```

### Clean release / build install

```bat
python -m venv venv
venv\Scripts\activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements/requirements-lock.txt
python -m pip install -r requirements/requirements-build.txt
python -m pip check
```

## Why this version is cleaner

- Removes packages that appear to be stale leftovers rather than active project dependencies.
- Keeps build-only tooling out of runtime requirements.
- Keeps Windows-only helpers behind platform markers.
- Makes the pinned file the clear source for reproducible builds.
