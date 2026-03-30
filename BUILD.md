# BUILD.md

## Prerequisites

- CMake
- OpenSSL
- Go (for running tests)

---

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/carbon-os/libhttp3.git
cd libhttp3
```

### 2. Bootstrap vcpkg and install dependencies

```bash
git clone https://github.com/microsoft/vcpkg.git
./vcpkg/bootstrap-vcpkg.sh
./vcpkg/vcpkg install
```

### 3. Generate a self-signed TLS certificate

```bash
openssl req -x509 -newkey rsa:2048 \
  -keyout server.key -out server.crt \
  -days 365 -nodes -subj "/CN=localhost"
```

### 4. Configure and build

```bash
cmake -B build \
  -DCMAKE_TOOLCHAIN_FILE=./vcpkg/scripts/buildsystems/vcpkg.cmake \
  -DCMAKE_BUILD_TYPE=Release

cmake --build build --config Release
```

---

## Running the Examples

### HTTP/3

**Terminal 1 — Start the server**
```bash
./build/h3_server server.crt server.key 4005
```

**Terminal 2 — Run the client**
```bash
./build/h3_client localhost 4005
```

---

### WebTransport

**Terminal 1 — Start the server**
```bash
./build/h3_webtransport_server server.crt server.key 4006
```

**Terminal 2 — Run the client**
```bash
./build/h3_webtransport_client localhost 5010
```

---

## Tests

The test suite uses a Go client that runs five checks in sequence against a live WebTransport server.

| # | Test | Description |
|---|------|-------------|
| 1 | `plain HTTP sanity check` | `GET /healthz` over the same QUIC connection |
| 2 | `test_echo` | Bidi stream round-trip + datagram echo on `/echo` |
| 3 | `test_chat` | Server-push unidi stream + bidi reply on `/chat` |
| 4 | `test_stream_test` | Server opens 3 unidi + 2 bidi streams, sends 5 datagrams on `/stream_test` |
| 5 | `test_rejected` | Verifies `/does-not-exist` returns a `404` |

### Running the tests

**Terminal 1 — Start the WebTransport server**
```bash
./build/h3_webtransport_server server.crt server.key 4006
```

**Terminal 2 — Run the Go test client**
```bash
go run tests/webtransport_client.go -addr localhost:4006 -insecure
```

**Optional: enable verbose output**
```bash
go run tests/webtransport_client.go -addr localhost:4006 -insecure -v
```