# keyquorum_core (native module)

This folder contains the C++ source for the Keyquorum Vault native helper DLL.

## What it does
- Argon2id key-derivation (via `argon2id_hash_raw`)
- AES-256-GCM encrypt/decrypt (OpenSSL EVP)
- Secure memory wiping helpers

## Licensing
This code is part of Keyquorum Vault and is distributed under GPL-3.0 (see repo root `LICENSE`).

This module links against third-party libraries:
- OpenSSL (Apache-2.0) — see `licenses/apache-2.0.txt` and `licenses/openssl.txt` in the repo.
- Argon2 reference implementation (CC0) — see `licenses/argon2.txt` in the repo.

## Build (Visual Studio)
Open `keyquorum_core.sln` and build the `keyquorum_core` project.
You will need OpenSSL and Argon2 development headers/libraries available to the project.
