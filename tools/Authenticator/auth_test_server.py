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

import base64, io, hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse as urlparse
from string import Template

try:
    import pyotp
except ImportError:
    raise SystemExit("pip install pyotp")
try:
    import qrcode
except ImportError:
    raise SystemExit("pip install qrcode[pil]")

HOST, PORT = "127.0.0.1", 8778

def make_uri(secret=None, issuer="KeyquorumTest", account="user@example.com", digits=6, period=30, algo="SHA1"):
    import hashlib as _hashlib
    digest = {"SHA1": _hashlib.sha1, "SHA256": _hashlib.sha256, "SHA512": _hashlib.sha512}[algo]
    secret = secret or pyotp.random_base32()
    totp = pyotp.TOTP(secret, digits=digits, interval=period, digest=digest)
    uri = totp.provisioning_uri(name=account, issuer_name=issuer)
    return secret, uri

def qr_png_data(uri: str) -> bytes:
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()

HTML_TMPL = Template("""<!doctype html><meta charset="utf-8">
<title>TOTP Test QR</title>
<style>
body{font-family:system-ui,Arial,sans-serif;margin:24px;max-width:720px}
code{background:#f4f4f4;padding:2px 4px;border-radius:4px}
.small{color:#666}
.qr{border:1px solid #ccc;display:inline-block;padding:8px;border-radius:8px}
</style>
<h2>Out-of-App TOTP Test</h2>
<p>Scan this QR with your Keyquorum <b>Authenticator</b> tab (Add from QR).<br>
Or use <b>Add (manual)</b> with the Base32 secret below.</p>
<div class="qr"><img src="data:image/png;base64,$b64" alt="QR"></div>
<p><b>Secret (BASE32):</b> <code>$secret</code></p>
<p class="small">
Issuer: <code>$issuer</code> &nbsp; Account: <code>$account</code> &nbsp;
Digits: <code>$digits</code> &nbsp; Period: <code>$period s</code> &nbsp; Algo: <code>$algo</code>
</p>
<p class="small">otpauth URI:<br><code style="word-break:break-all">$uri</code></p>
""")

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # keep default logging; comment this method out to silence
        super().log_message(fmt, *args)

    def do_GET(self):
        pr = urlparse.urlparse(self.path)
        q = dict(urlparse.parse_qsl(pr.query))

        issuer = q.get("issuer","KeyquorumTest")
        account = q.get("account","user@example.com")
        try:
            digits = int(q.get("digits", 6))
        except Exception:
            digits = 6
        try:
            period = int(q.get("period", 30))
        except Exception:
            period = 30
        algo   = (q.get("algo","SHA1") or "SHA1").upper()
        secret, uri = make_uri(q.get("secret"), issuer, account, digits, period, algo)
        png = qr_png_data(uri)

        # write PNG for file-based import if desired
        try:
            with open("otpauth.png","wb") as f:
                f.write(png)
        except Exception:
            pass

        b64 = base64.b64encode(png).decode("ascii")
        html = HTML_TMPL.substitute(
            b64=b64, secret=secret, issuer=issuer, account=account,
            digits=digits, period=period, algo=algo, uri=uri
        )

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

def run():
    print(f"Serving TOTP test QR at http://{HOST}:{PORT}/")
    print("Optional params: ?issuer=GitHub&account=you@site.com&digits=6&period=30&algo=SHA1&secret=BASE32")
    HTTPServer((HOST, PORT), Handler).serve_forever()

if __name__ == "__main__":
    run()
