# Requirements files (Keyquorum Vault)

You’re using a venv and fbs Pro, so it helps to keep requirements split by purpose.

## Files

- `requirements.in`  
  Minimal, human-edited runtime dependencies. Good for day-to-day development.

- `requirements.txt`  
  Pinned runtime dependencies (best for repeatable fbs Pro builds).

- `requirements-dev.txt`  
  Test/dev tools (pytest etc).

- `requirements-build.txt`  
  Packaging/build tooling (PyInstaller etc).

## Typical workflow (venv)

### Dev install (flexible)
```bat
python -m venv .venv
.venv\Scripts\activate
python -m pip install -U pip
python -m pip install -r requirements.in
python -m pip install -r requirements-dev.txt
```

### Reproducible build install (recommended before fbs)
```bat
python -m venv .venv
.venv\Scripts\activate
python -m pip install -U pip
python -m pip install -r requirements.txt
python -m pip install -r requirements-build.txt
```

## Why this helps

- Less “pip freeze noise” in your public repo
- Faster installs
- Easier Linux/macOS portability
- Repeatable builds for releases
