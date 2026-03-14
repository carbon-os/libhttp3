# libhttp3

An HTTP/3 server and client library for C++17, built on [MsQuic](https://github.com/microsoft/msquic).

## Features

- HTTP/3 (QUIC + TLS 1.3) via MsQuic
- Familiar cpp-httplib-style API
- Route patterns with `:param` capture and full regex support
- Query string parsing
- QPACK header compression (static table + Huffman, RFC 9204)
- Lazy connection — client connects on first request and reuses the connection
- Configurable TLS verification and CA certificate

## Requirements

- C++17 compiler (MSVC, GCC, Clang)
- CMake 3.20+
- [MsQuic](https://github.com/microsoft/msquic) installed and findable via `find_package(msquic CONFIG REQUIRED)`

## Building

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

This produces:
- `libhttp3.a` (or `http3.lib` on Windows)
- `h3_server` — example server binary
- `h3_client` — example client binary

## TLS certificates

MsQuic requires a real TLS certificate. For local testing, generate a self-signed one:

```bash
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt \
  -days 365 -nodes -subj "/CN=localhost"
```

## Quick start

### Server

```cpp
#include <http3.h>

int main() {
    http3::Server svr;

    svr.Get("/", [](const http3::Request&, http3::Response& res) {
        res.set_content("Hello, HTTP/3!", "text/plain");
    });

    svr.Get("/users/:id", [](const http3::Request& req, http3::Response& res) {
        res.set_content("User: " + req.matches[1].str(), "text/plain");
    });

    svr.Post("/echo", [](const http3::Request& req, http3::Response& res) {
        res.set_content(req.body, "text/plain");
    });

    svr.listen("0.0.0.0", 4433, "server.crt", "server.key");
}
```

### Client

```cpp
#include <http3.h>

int main() {
    http3::Client cli("localhost", 4433);
    cli.enable_server_certificate_verification(false); // for self-signed certs

    auto res = cli.Get("/");
    if (res) {
        printf("status=%d  body=%s\n", res->status, res->body.c_str());
    } else {
        printf("error: %s\n", http3::to_string(res.error()));
    }
}
```

## API reference

### Server

```cpp
// Register routes
svr.Get    ("/path", handler);
svr.Post   ("/path", handler);
svr.Put    ("/path", handler);
svr.Delete ("/path", handler);
svr.Head   ("/path", handler);
svr.Options("/path", handler);
svr.Patch  ("/path", handler);

// Custom 404 / error handler
svr.set_error_handler(handler);

// Start (blocks until stop() is called)
svr.listen("0.0.0.0", 4433, "server.crt", "server.key");
svr.listen("0.0.0.0", 4433, "server.crt", "server.key", "h3"); // custom ALPN

svr.stop();
svr.is_running();
```

#### Route patterns

| Pattern | Example match |
|---|---|
| `/users/:id` | `/users/42` → `req.matches[1] == "42"` |
| `/files/:dir/:name` | `/files/docs/readme` |
| `R"(/items/(\d+))"` | Raw regex — full `std::regex` syntax |

#### Request

```cpp
req.method          // "GET", "POST", …
req.path            // "/users/42"
req.query_string    // "foo=bar&x=1"
req.body            // request body as std::string
req.headers         // std::multimap<string, string>
req.params          // parsed query params
req.matches         // std::smatch — regex captures

req.has_header("content-type")
req.get_header_value("content-type", "text/plain")
req.has_param("page")
req.get_param_value("page", "1")
```

#### Response

```cpp
res.status = 200;
res.set_content("body text", "text/plain");
res.set_header("x-custom", "value");
res.set_redirect("/new-location");      // 302
res.set_redirect("/new-location", 301); // permanent
```

### Client

```cpp
http3::Client cli("localhost", 4433);

// TLS
cli.enable_server_certificate_verification(true);
cli.set_ca_cert_path("/path/to/ca.crt");

// Timeouts (seconds)
cli.set_connection_timeout(10);
cli.set_read_timeout(30);

// Methods
auto res = cli.Get    ("/path");
auto res = cli.Get    ("/path", headers);
auto res = cli.Post   ("/path", body, content_type);
auto res = cli.Post   ("/path", body, content_type, headers);
auto res = cli.Put    ("/path", body, content_type);
auto res = cli.Delete ("/path");
auto res = cli.Head   ("/path");
auto res = cli.Options("/path");
auto res = cli.Patch  ("/path", body, content_type);
```

#### Result

```cpp
if (res) {                          // true on HTTP success (any status)
    res->status                     // int
    res->body                       // std::string
    res->headers                    // std::multimap<string, string>
    res->get_header_value("etag")
} else {
    http3::to_string(res.error())   // human-readable error
}
```

#### Error codes

| Error | Meaning |
|---|---|
| `Error::Connection` | Could not connect or connection lost |
| `Error::ConnectionTimeout` | Timed out waiting to connect |
| `Error::ReadTimeout` | Timed out waiting for response |
| `Error::SendFailed` | Failed to send request |
| `Error::QpackError` | QPACK decode failure |
| `Error::ProtocolError` | Unexpected HTTP/3 framing |

## Running the examples

```bash
# Terminal 1 — server
./build/h3_server server.crt server.key 4433

# Terminal 2 — C++ client
./build/h3_client localhost 4433

# Terminal 2 — Go test suite (requires github.com/quic-go/quic-go)
cd tests
go run client.go -addr localhost:4433 -insecure -count 5
```

## Project layout

```
include/
  http3.h                   ← public API (only file users need)
  http3/
    http3_defs.h            ← frame types, stream types, error codes
    http3_varint.h          ← QUIC variable-length integer codec
    http3_frame.h           ← H3 frame builder / parser, StreamBuf
    http3_qpack.h           ← QPACK encoder / decoder
    http3_client_impl.h     ← Client::Impl and ReqState
    http3_server_impl.h     ← Server::Impl, Route, SrvConnCtx, SrvStreamCtx
src/
  http3_varint.cpp
  http3_frame.cpp
  http3_qpack.cpp
  http3_server.cpp
  http3_client.cpp
examples/
  server.cpp
  client.cpp
tests/
  client.go                 ← Go test suite; Go's quic-go stack has one of the
                               most mature QUIC/HTTP3/WebTransport implementations
                               available, making it a reliable independent client
                               for validating interoperability against the C++ server
```

## Limitations

- QPACK static table only — no dynamic table, no server push
- Single-process; no built-in thread pool for handlers (each request dispatches synchronously on the MsQuic callback thread)
- No HTTP/1.1 or HTTP/2 fallback

## License

MIT

---

## References

- [MsQuic](https://github.com/microsoft/msquic) — Microsoft's cross-platform QUIC implementation
- [yhirose/cpp-httplib](https://github.com/yhirose/cpp-httplib) — API design and handler conventions
- [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114) — HTTP/3
- [RFC 9204](https://www.rfc-editor.org/rfc/rfc9204) — QPACK header compression
- [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) — QUIC transport
- [RFC 7541](https://www.rfc-editor.org/rfc/rfc7541) — HPACK / Huffman coding (used by QPACK)