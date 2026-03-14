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

# Run server
./build/h3_server server.crt server.key 4005

# Run client (separate terminal)
./build/h3_client localhost 4005