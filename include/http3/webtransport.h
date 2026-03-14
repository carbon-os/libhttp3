#pragma once
// ╔══════════════════════════════════════════════════════════════════════╗
// ║  WebTransport over HTTP/3  (draft-ietf-webtrans-http3)              ║
// ║  Sessions via extended CONNECT; streams and datagrams multiplexed   ║
// ║  within the same HTTP/3 / QUIC connection.                          ║
// ╚══════════════════════════════════════════════════════════════════════╝
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace http3 {

// ── Forward declarations ──────────────────────────────────────────────────────
class WtSession;
class WtStream;

// ── WtStream ──────────────────────────────────────────────────────────────────
// Represents one logical stream inside a WebTransport session.
// Lifetime: valid until on_close fires; do NOT use after that.
class WtStream {
public:
    using DataCallback  = std::function<void(const uint8_t* data, size_t len)>;
    using CloseCallback = std::function<void()>;

    uint64_t id()      const noexcept;
    bool     is_bidi() const noexcept;

    // Send data (may be called from any thread).
    bool write(const void* data, size_t len);
    bool write(const std::vector<uint8_t>& d) { return write(d.data(), d.size()); }
    bool write(const std::string& s)          { return write(s.data(), s.size()); }

    // FIN the send side (remote can still send).
    void close_write();

    // Abruptly reset the stream.
    void reset(uint64_t app_error = 0);

    // Register callbacks (must be called before stream data arrives).
    void on_data (DataCallback  cb);
    void on_close(CloseCallback cb);

    // ── internal ──────────────────────────────────────────────────────────────
    struct Impl;
    explicit WtStream(std::unique_ptr<Impl> p);
    ~WtStream();
    WtStream(const WtStream&)            = delete;
    WtStream& operator=(const WtStream&) = delete;
    WtStream(WtStream&&) noexcept;
    Impl* impl() const { return impl_.get(); }

private:
    std::unique_ptr<Impl> impl_;
};

// ── WtSession ─────────────────────────────────────────────────────────────────
// Represents a WebTransport session (anchored to one CONNECT stream).
class WtSession {
public:
    using StreamCallback   = std::function<void(WtStream& s)>;
    using DatagramCallback = std::function<void(const uint8_t* data, size_t len)>;
    using CloseCallback    = std::function<void(uint32_t error_code, std::string reason)>;

    uint64_t session_id() const noexcept;

    // ── outbound ──────────────────────────────────────────────────────────────
    // Returns a non-owning pointer valid until on_close fires on the stream.
    WtStream* open_unidi_stream();
    WtStream* open_bidi_stream();

    bool send_datagram(const void* data, size_t len);
    bool send_datagram(const std::vector<uint8_t>& d) { return send_datagram(d.data(), d.size()); }

    // ── session teardown ─────────────────────────────────────────────────────
    void close(uint32_t error_code = 0, const std::string& reason = {});

    // Block the calling thread until the session is terminated
    // (useful in server handlers when you want to keep the session alive).
    void wait();

    // ── inbound callbacks ─────────────────────────────────────────────────────
    void on_stream  (StreamCallback);
    void on_datagram(DatagramCallback);
    void on_close   (CloseCallback);

    // ── internal ──────────────────────────────────────────────────────────────
    struct Impl;
    explicit WtSession(std::unique_ptr<Impl> p);
    ~WtSession();
    WtSession(const WtSession&)            = delete;
    WtSession& operator=(const WtSession&) = delete;
    Impl* impl() const { return impl_.get(); }

private:
    std::unique_ptr<Impl> impl_;
};

// ── WtResult (client-side return value) ──────────────────────────────────────
class WtResult {
public:
    enum class Error { Success, Connection, Rejected, Timeout, Protocol };

    WtResult()                                   : err_(Error::Connection) {}
    explicit WtResult(Error e)                   : err_(e) {}
    explicit WtResult(std::unique_ptr<WtSession> s)
        : sess_(std::move(s)), err_(Error::Success) {}

    explicit operator bool() const noexcept { return sess_ != nullptr; }
    WtSession*       operator->()       { return sess_.get(); }
    const WtSession* operator->() const { return sess_.get(); }
    WtSession&       operator*()        { return *sess_; }
    Error error()    const noexcept     { return err_; }

    std::unique_ptr<WtSession> take() { return std::move(sess_); }

private:
    std::unique_ptr<WtSession> sess_;
    Error err_;
};

} // namespace http3