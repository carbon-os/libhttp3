# browser_test.md — WebTransport Browser Testing (Linux)

Guide to installing Chrome on Linux and launching it against libhttp3's
WebTransport server with a self-signed TLS certificate.

---

## 1. Install Google Chrome

**Option A — direct .deb download** (no repo setup required):
```bash
wget -q https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo apt install ./google-chrome-stable_current_amd64.deb
```

**Option B — via apt** (if the Google Chrome repo is already configured,
which Option A sets up automatically for future updates):
```bash
sudo apt install google-chrome-stable
```

> If Option B returns `Unable to locate package`, run Option A first — it
> installs the package and registers the Google apt repository in
> `/etc/apt/sources.list.d/` so that `sudo apt install google-chrome-stable`
> and `sudo apt upgrade` will work from that point on.

Verify:
```bash
google-chrome --version
# Google Chrome 12x.x.x.x
```

---

## 2. Generate a self-signed TLS certificate
```bash
openssl req -x509 -newkey rsa:2048 \
  -keyout server.key -out server.crt \
  -days 365 -nodes -subj "/CN=localhost"
```

---

## 3. Start the WebTransport server
```bash
./build/h3_webtransport_server server.crt server.key 5010
```

---

## 4. Launch Chrome

Prefer opening the test page as a **local file** — no HTTP server needed,
no background process to manage, and Chrome's localhost QUIC exemption still
applies fully.
```bash
# Compute SPKI fingerprint (harmless on localhost, required for LAN/hostname)
SPKI=$(openssl x509 -in server.crt -noout -pubkey \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | base64)

google-chrome \
  --origin-to-force-quic-on=localhost:5010 \
  --ignore-certificate-errors-spki-list="$SPKI" \
  --enable-experimental-web-platform-features \
  --user-data-dir=/tmp/chrome-wt-test \
  --no-first-run \
  --no-default-browser-check \
  "file:///home/user/libhttp3/tests/browser/index.html"
```

> **Prefer `file://` over `http://`** — loading the test page via a local
> file path requires no web server and works identically. Only reach for
> `python3 -m http.server` if you need a proper origin (e.g. testing
> Service Workers or other APIs that block on `file://`).

### What each flag does

| Flag | Purpose |
|---|---|
| `--origin-to-force-quic-on=localhost:5010` | Forces QUIC (required for WebTransport) on that origin instead of falling back to TCP |
| `--ignore-certificate-errors-spki-list=<BASE64>` | Whitelists the cert by its SPKI fingerprint — safe, targeted TLS bypass |
| `--enable-experimental-web-platform-features` | Ensures the WebTransport JS API is enabled (on by default in Chrome 97+) |
| `--user-data-dir=/tmp/chrome-wt-test` | Isolated profile — flags do not affect your normal browser session |
| `--no-first-run --no-default-browser-check` | Skips setup dialogs that would block the test |

> Chrome may print `unsupported command --ignore-certificate-errors-spki-list`
> at startup — this is a cosmetic warning only, the flag is still applied.
> On `localhost` Chrome also grants a built-in TLS exemption for QUIC, so
> the connection will succeed either way.

---

## 5. Testing against a LAN IP or hostname

When moving off localhost (e.g. `192.168.1.x` or a custom hostname) the
built-in exemption no longer applies. The SPKI flag then becomes required
and the origin must be updated to match:
```bash
SPKI=$(openssl x509 -in server.crt -noout -pubkey \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | base64)

google-chrome \
  --origin-to-force-quic-on=192.168.1.x:5010 \
  --ignore-certificate-errors-spki-list="$SPKI" \
  --enable-experimental-web-platform-features \
  --user-data-dir=/tmp/chrome-wt-test \
  --no-first-run \
  --no-default-browser-check \
  "file:///home/user/libhttp3/tests/browser/index.html"
```

You can still open the page as a `file://` URL even here — the origin
restriction only applies to the WebTransport endpoint, not the page itself.

---

## 6. Test page

The test page lives at:
```
tests/browser/index.html
```

It covers all three server endpoints:

| Endpoint | What is tested |
|---|---|
| `/echo` | Bidi stream send + echo, datagram send + echo |
| `/chat` | Server-initiated welcome unidi stream, bidi send + reply, datagram broadcast |
| `/stream_test` | Server pushes 3 unidi streams, 2 bidi streams, and 5 datagrams on connect |

Each panel has its own scrolling log with colour-coded entries:

| Colour | Meaning |
|---|---|
| Blue | Sent (TX) |
| Green | Received (RX) |
| Purple | Datagram |
| Grey | Info / lifecycle |
| Red | Error |

---

## 7. Useful Chrome internals pages
```
chrome://net-internals/#quic      — live QUIC session list
chrome://net-internals/#events    — full connection event log (filter: QUIC)
chrome://flags/#enable-quic       — master QUIC toggle (leave as Default)
```

---

## 8. Troubleshooting

| Symptom | Fix |
|---|---|
| `Failed to connect` | Confirm the server is running and listening on UDP 5010; check firewall |
| `WebTransport is not defined` | Add `--enable-experimental-web-platform-features`; Chrome 97+ has it on by default |
| TLS error on non-localhost | Recompute the SPKI Base64 and confirm it matches the cert the server is using |
| QUIC not negotiated | Confirm `--origin-to-force-quic-on` matches the exact host:port; some VPNs block UDP |
| `ERR_QUIC_PROTOCOL_ERROR` | Check `chrome://flags/#enable-quic` is Default or Enabled, then relaunch |
| Page blank on `file://` | Confirm the absolute path is correct; check the Chrome console (F12) for errors |
| `Unable to locate package google-chrome-stable` | Run Option A (the .deb download) first to register the Google apt repo |

---

## Notes

- These flags are **for local development and testing only** — never use them
  in a production or end-user environment.
- `--ignore-certificate-errors-spki-list` is always preferred over the blunt
  `--ignore-certificate-errors` flag because it only bypasses TLS for the
  specific certificate, leaving all other security checks intact.
- The `--user-data-dir` flag ensures the test profile is completely isolated
  from your normal Chrome session.