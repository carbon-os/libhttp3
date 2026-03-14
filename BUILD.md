cd libhttp3

# Bootstrap vcpkg + install msquic
git clone https://github.com/microsoft/vcpkg.git
./vcpkg/bootstrap-vcpkg.sh
./vcpkg/vcpkg install

# Generate cert
openssl req -x509 -newkey rsa:2048 -keyout server.key \
  -out server.crt -days 365 -nodes -subj "/CN=localhost"

# Configure + build
cmake -B build \
  -DCMAKE_TOOLCHAIN_FILE=./vcpkg/scripts/buildsystems/vcpkg.cmake \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release

# ── HTTP/3 examples ───────────────────────────────────────────────────────────

# Terminal 1 — HTTP/3 server
./build/h3_server server.crt server.key 4005

# Terminal 2 — HTTP/3 client
./build/h3_client localhost 4005

# ── WebTransport examples ─────────────────────────────────────────────────────

# Terminal 1 — WebTransport server (can share port with h3_server or use its own)
./build/h3_webtransport_server server.crt server.key 4006

# Terminal 2 — WebTransport client
./build/h3_webtransport_client localhost 5010



# tests

# start the server first
./build/h3_webtransport_server server.crt server.key 4006

# run the Go client
go run tests/webtransport_client.go -addr localhost:4006 -insecure

# extra verbosity
go run webtransport_client.go -addr localhost:4007 -insecure -v



# The WebTransport client runs four tests in sequence:
#   1. plain HTTP sanity check  — GET /healthz on the same QUIC connection
#   2. test_echo                — bidi stream round-trip + datagram echo on /echo
#   3. test_chat                — server-push unidi stream + bidi reply on /chat
#   4. test_stream_test         — server opens 3 unidi + 2 bidi streams,
#                                 sends 5 datagrams on /stream_test
#   5. test_rejected            — verifies /does-not-exist returns a 404