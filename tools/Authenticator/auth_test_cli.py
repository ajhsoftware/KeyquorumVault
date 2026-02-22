# Keyquorum Vault - Authenticator Testing Utility
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


import argparse, time, hashlib, sys
try:
    import pyotp
except ImportError:
    print("pip install pyotp", file=sys.stderr); raise

def main():
    ap = argparse.ArgumentParser(description="Out-of-app TOTP test (CLI)")
    ap.add_argument("--secret", help="BASE32 secret to reuse (default: random)")
    ap.add_argument("--issuer", default="KeyquorumTest", help="Issuer name")
    ap.add_argument("--account", default="user@example.com", help="Account label")
    ap.add_argument("--digits", type=int, default=6, choices=[6,7,8])
    ap.add_argument("--period", type=int, default=30)
    ap.add_argument("--algo", default="SHA1", choices=["SHA1","SHA256","SHA512"])
    args = ap.parse_args()

    secret = args.secret or pyotp.random_base32()
    digest = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}[args.algo]
    totp = pyotp.TOTP(secret, digits=args.digits, interval=args.period, digest=digest)

    uri = pyotp.totp.TOTP(secret, issuer=args.issuer, name=args.account,
                          digits=args.digits, interval=args.period, digest=digest).provisioning_uri()
    print("\n=== TOTP Test ===")
    print("Secret (BASE32):", secret)
    print("otpauth URI:    ", uri)
    print(f"Digits={args.digits}  Period={args.period}s  Algorithm={args.algo}")
    print("\nAdd this to your app (manual or QR). Codes below should match.\n")

    try:
        while True:
            now = int(time.time())
            rem = args.period - (now % args.period)
            code = totp.now()
            print(f"\rCode: {code}   (refresh in {rem:2d}s)   ", end="", flush=True)
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nBye.")

if __name__ == "__main__":
    main()
