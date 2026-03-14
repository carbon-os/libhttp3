#pragma once
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace webtransport {

class Session;
class BidirectionalStream;
class SendStream;
class ReceiveStream;

// ── BidirectionalStream ───────────────────────────────────────────────────────
class BidirectionalStream {
public:
    using DataCallback  = std::function<void(const uint8_t* data, size_t len)>;
    using CloseCallback = std::function<void()>;

    uint64_t id() const noexcept;

    bool write(const void* data, size_t len);
    bool write(const std::vector<uint8_t>& d) { return write(d.data(), d.size()); }
    bool write(const std::string& s)          { return write(s.data(), s.size()); }

    void close_write();
    void reset(uint64_t app_error = 0);

    void on_data (DataCallback  cb);
    void on_close(CloseCallback cb);

    struct Impl;
    explicit BidirectionalStream(std::unique_ptr<Impl> p);
    ~BidirectionalStream();
    BidirectionalStream(BidirectionalStream&&) noexcept;
    BidirectionalStream(const BidirectionalStream&)            = delete;
    BidirectionalStream& operator=(const BidirectionalStream&) = delete;
    Impl* impl() const { return impl_.get(); }

private:
    std::unique_ptr<Impl> impl_;
};

// ── SendStream ────────────────────────────────────────────────────────────────
class SendStream {
public:
    uint64_t id() const noexcept;

    bool write(const void* data, size_t len);
    bool write(const std::vector<uint8_t>& d) { return write(d.data(), d.size()); }
    bool write(const std::string& s)          { return write(s.data(), s.size()); }

    void close_write();
    void reset(uint64_t app_error = 0);

    struct Impl;
    explicit SendStream(std::unique_ptr<Impl> p);
    ~SendStream();
    SendStream(SendStream&&) noexcept;
    SendStream(const SendStream&)            = delete;
    SendStream& operator=(const SendStream&) = delete;
    Impl* impl() const { return impl_.get(); }

private:
    std::unique_ptr<Impl> impl_;
};

// ── ReceiveStream ─────────────────────────────────────────────────────────────
class ReceiveStream {
public:
    using DataCallback  = std::function<void(const uint8_t* data, size_t len)>;
    using CloseCallback = std::function<void()>;

    uint64_t id() const noexcept;

    void on_data (DataCallback  cb);
    void on_close(CloseCallback cb);

    struct Impl;
    explicit ReceiveStream(std::unique_ptr<Impl> p);
    ~ReceiveStream();
    ReceiveStream(ReceiveStream&&) noexcept;
    ReceiveStream(const ReceiveStream&)            = delete;
    ReceiveStream& operator=(const ReceiveStream&) = delete;
    Impl* impl() const { return impl_.get(); }

private:
    std::unique_ptr<Impl> impl_;
};

// ── Session ───────────────────────────────────────────────────────────────────
class Session {
public:
    using BidiStreamCallback    = std::function<void(BidirectionalStream&)>;
    using ReceiveStreamCallback = std::function<void(ReceiveStream&)>;
    using DatagramCallback      = std::function<void(const uint8_t* data, size_t len)>;
    using CloseCallback         = std::function<void(uint32_t code, std::string_view reason)>;

    uint64_t session_id() const noexcept;

    // ── outbound ──────────────────────────────────────────────────────────────
    BidirectionalStream* open_bidi_stream();
    SendStream*          open_send_stream();

    bool send_datagram(const void* data, size_t len);
    bool send_datagram(const std::vector<uint8_t>& d)
        { return send_datagram(d.data(), d.size()); }
    bool send_datagram(const std::string& s)
        { return send_datagram(s.data(), s.size()); }

    // ── inbound callbacks ─────────────────────────────────────────────────────
    void on_bidi_stream   (BidiStreamCallback    cb);   // client-initiated bidi
    void on_receive_stream(ReceiveStreamCallback cb);   // client-initiated unidi
    void on_datagram      (DatagramCallback      cb);
    void on_close         (CloseCallback         cb);

    // ── lifecycle ─────────────────────────────────────────────────────────────
    void wait();
    void close(uint32_t error_code = 0, const std::string& reason = {});

    struct Impl;
    explicit Session(std::unique_ptr<Impl> p);
    ~Session();
    Session(const Session&)            = delete;
    Session& operator=(const Session&) = delete;
    Impl* impl() const { return impl_.get(); }

private:
    std::unique_ptr<Impl> impl_;
};

// ── WebTransport standalone client ───────────────────────────────────────────
// For apps that only need WebTransport (no plain HTTP/3 requests needed).
// URL format: "https://host:port/path"
class WebTransport {
public:
    explicit WebTransport(const std::string& url);
    ~WebTransport();
    WebTransport(const WebTransport&)            = delete;
    WebTransport& operator=(const WebTransport&) = delete;

    void verify_cert(bool enable);
    void set_connection_timeout(int sec);
    void set_read_timeout(int sec);

    // Blocks until the server responds. Returns nullptr on failure.
    std::unique_ptr<Session> connect();

    struct Impl;
private:
    std::unique_ptr<Impl> impl_;
};

// ── Error ─────────────────────────────────────────────────────────────────────
enum class Error { Success, Connection, Rejected, Timeout, Protocol };

} // namespace webtransport