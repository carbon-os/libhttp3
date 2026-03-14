#pragma once
// ╔══════════════════════════════════════════════════════════════════════╗
// ║  http3  —  HTTP/3 server + client  +  WebTransport                  ║
// ║  API modelled after yhirose/cpp-httplib                              ║
// ║  Transport: MsQuic (QUIC + TLS 1.3)                                 ║
// ╚══════════════════════════════════════════════════════════════════════╝

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <regex>
#include <string>
#include <vector>

namespace http3 {

// ── Error ─────────────────────────────────────────────────────────────────────
enum class Error {
    Success = 0,
    Connection,
    ConnectionTimeout,
    ReadTimeout,
    SendFailed,
    QpackError,
    ProtocolError,
    Unknown,
};

inline const char* to_string(Error e) noexcept {
    switch (e) {
    case Error::Success:           return "Success";
    case Error::Connection:        return "Connection error";
    case Error::ConnectionTimeout: return "Connection timeout";
    case Error::ReadTimeout:       return "Read timeout";
    case Error::SendFailed:        return "Send failed";
    case Error::QpackError:        return "QPACK error";
    case Error::ProtocolError:     return "Protocol error";
    default:                       return "Unknown";
    }
}

// ── Headers / Params ──────────────────────────────────────────────────────────
using Headers = std::multimap<std::string, std::string>;
using Params  = std::multimap<std::string, std::string>;

// ── Request ───────────────────────────────────────────────────────────────────
struct Request {
    std::string method;
    std::string path;
    std::string query_string;
    std::string body;
    Headers     headers;
    Params      params;
    std::smatch matches;

    bool has_header(const std::string& k) const { return headers.count(k) > 0; }
    std::string get_header_value(const std::string& k,
                                  const std::string& def = {}) const {
        auto it = headers.find(k);
        return it != headers.end() ? it->second : def;
    }
    bool has_param(const std::string& k) const { return params.count(k) > 0; }
    std::string get_param_value(const std::string& k,
                                 const std::string& def = {}) const {
        auto it = params.find(k);
        return it != params.end() ? it->second : def;
    }
};

// ── Response ──────────────────────────────────────────────────────────────────
struct Response {
    int         status = 200;
    std::string body;
    Headers     headers;

    void set_content(const std::string& content, const std::string& content_type) {
        body = content;
        headers.erase("content-type");
        headers.erase("content-length");
        headers.emplace("content-type",   content_type);
        headers.emplace("content-length", std::to_string(content.size()));
    }
    void set_header(const std::string& k, const std::string& v) {
        headers.erase(k); headers.emplace(k, v);
    }
    bool has_header(const std::string& k) const { return headers.count(k) > 0; }
    std::string get_header_value(const std::string& k,
                                  const std::string& def = {}) const {
        auto it = headers.find(k);
        return it != headers.end() ? it->second : def;
    }
    void set_redirect(const std::string& location, int code = 302) {
        status = code; set_header("location", location);
    }
};

// ── HTTP Handler ──────────────────────────────────────────────────────────────
using Handler      = std::function<void(const Request&, Response&)>;
using ErrorHandler = std::function<void(const Request&, Response&)>;

// ── Result ────────────────────────────────────────────────────────────────────
class Result {
public:
    Result()                             : err_(Error::Unknown) {}
    explicit Result(Error e)             : err_(e) {}
    explicit Result(std::unique_ptr<Response> r)
        : resp_(std::move(r)), err_(Error::Success) {}

    explicit operator bool() const noexcept { return resp_ != nullptr; }
    Response*       operator->()            { return resp_.get(); }
    const Response* operator->() const      { return resp_.get(); }
    Response&       operator*()             { return *resp_; }
    const Response& operator*()  const      { return *resp_; }
    Error error()    const noexcept         { return err_; }

private:
    std::unique_ptr<Response> resp_;
    Error err_;
};

// ╔══════════════════════════════════════════════════════════════════════╗
// ║  WebTransport                                                        ║
// ╚══════════════════════════════════════════════════════════════════════╝

// ── WtStream ──────────────────────────────────────────────────────────────────
// One logical stream (unidirectional or bidirectional) inside a WtSession.
// Lifetime: valid until the on_close callback fires; do NOT use after that.
class WtStream {
public:
    using DataCallback  = std::function<void(const uint8_t* data, size_t len)>;
    using CloseCallback = std::function<void()>;

    uint64_t id()      const noexcept;
    bool     is_bidi() const noexcept;

    // Send raw bytes. Thread-safe.
    bool write(const void* data, size_t len);
    bool write(const std::vector<uint8_t>& d) { return write(d.data(), d.size()); }
    bool write(const std::string& s)          { return write(s.data(), s.size()); }

    // Gracefully FIN the send side (peer may still send).
    void close_write();

    // Abruptly reset with an application error code.
    void reset(uint64_t app_error = 0);

    // Register callbacks. Call before stream data can arrive.
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
// One WebTransport session, anchored to a single CONNECT stream.
// The session is alive as long as the CONNECT stream is open.
class WtSession {
public:
    using StreamCallback   = std::function<void(WtStream& s)>;
    using DatagramCallback = std::function<void(const uint8_t* data, size_t len)>;
    using CloseCallback    = std::function<void(uint32_t error_code,
                                                 std::string reason)>;

    uint64_t session_id() const noexcept;

    // ── outbound ──────────────────────────────────────────────────────────────
    // Returned pointer is owned by the session; valid until the stream closes.
    WtStream* open_unidi_stream();
    WtStream* open_bidi_stream();

    bool send_datagram(const void* data, size_t len);
    bool send_datagram(const std::vector<uint8_t>& d)
        { return send_datagram(d.data(), d.size()); }
    bool send_datagram(const std::string& s)
        { return send_datagram(s.data(), s.size()); }

    // ── session teardown ─────────────────────────────────────────────────────
    // Sends WT_CLOSE_SESSION capsule and FINs the CONNECT stream.
    void close(uint32_t error_code = 0, const std::string& reason = {});

    // Block the calling thread until the session terminates.
    // Useful inside a server handler to keep the session alive.
    void wait();

    // ── inbound callbacks ─────────────────────────────────────────────────────
    void on_stream  (StreamCallback   cb);
    void on_datagram(DatagramCallback cb);
    void on_close   (CloseCallback    cb);

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

    WtResult()                                      : err_(Error::Connection) {}
    explicit WtResult(Error e)                      : err_(e) {}
    explicit WtResult(std::unique_ptr<WtSession> s)
        : sess_(std::move(s)), err_(Error::Success) {}

    explicit operator bool() const noexcept { return sess_ != nullptr; }
    WtSession*       operator->()       { return sess_.get(); }
    const WtSession* operator->() const { return sess_.get(); }
    WtSession&       operator*()        { return *sess_; }
    const WtSession& operator*()  const { return *sess_; }
    Error error()    const noexcept     { return err_; }

    // Transfer ownership to caller (e.g. to store session long-term).
    std::unique_ptr<WtSession> take() { return std::move(sess_); }

private:
    std::unique_ptr<WtSession> sess_;
    Error err_;
};

// ── WebTransport handler ──────────────────────────────────────────────────────
using WtHandler = std::function<void(WtSession&)>;

// ╔══════════════════════════════════════════════════════════════════════╗
// ║  Server                                                              ║
// ╚══════════════════════════════════════════════════════════════════════╝
class Server {
public:
     Server();
    ~Server();
    Server(const Server&)            = delete;
    Server& operator=(const Server&) = delete;

    // ── HTTP routes ───────────────────────────────────────────────────────────
    Server& Get    (const std::string& pattern, Handler h);
    Server& Post   (const std::string& pattern, Handler h);
    Server& Put    (const std::string& pattern, Handler h);
    Server& Delete (const std::string& pattern, Handler h);
    Server& Head   (const std::string& pattern, Handler h);
    Server& Options(const std::string& pattern, Handler h);
    Server& Patch  (const std::string& pattern, Handler h);

    // ── WebTransport route ────────────────────────────────────────────────────
    // Pattern is matched against the :path pseudo-header of the CONNECT request.
    // The handler is called on a dedicated thread; call session.wait() to keep
    // it alive until the peer closes.
    Server& WebTransport(const std::string& pattern, WtHandler h);

    // ── Error handler (called when no route matches) ──────────────────────────
    void set_error_handler(ErrorHandler h);

    // ── Lifecycle ─────────────────────────────────────────────────────────────
    // Blocks until stop() is called.
    bool listen(const std::string& host, uint16_t port,
                const std::string& cert,
                const std::string& key,
                const std::string& alpn = "h3");
    void stop();
    bool is_running() const noexcept;

    struct Impl;
private:
    std::unique_ptr<Impl> impl_;
};

// ╔══════════════════════════════════════════════════════════════════════╗
// ║  Client                                                              ║
// ╚══════════════════════════════════════════════════════════════════════╝
class Client {
public:
    Client(const std::string& host, uint16_t port);
    ~Client();
    Client(const Client&)            = delete;
    Client& operator=(const Client&) = delete;

    // ── TLS / connection options ──────────────────────────────────────────────
    void enable_server_certificate_verification(bool enable);
    void set_ca_cert_path(const std::string& path);
    void set_connection_timeout(int sec);
    void set_read_timeout(int sec);

    // ── HTTP methods ──────────────────────────────────────────────────────────
    Result Get    (const std::string& path,
                   const Headers& headers = {});
    Result Post   (const std::string& path,
                   const std::string& body,
                   const std::string& content_type,
                   const Headers& headers = {});
    Result Put    (const std::string& path,
                   const std::string& body,
                   const std::string& content_type,
                   const Headers& headers = {});
    Result Delete (const std::string& path,
                   const std::string& body         = {},
                   const std::string& content_type = {},
                   const Headers& headers          = {});
    Result Head   (const std::string& path,
                   const Headers& headers = {});
    Result Options(const std::string& path,
                   const Headers& headers = {});
    Result Patch  (const std::string& path,
                   const std::string& body,
                   const std::string& content_type,
                   const Headers& headers = {});

    // ── WebTransport ──────────────────────────────────────────────────────────
    // Sends an extended CONNECT to path and returns a live WtSession on success.
    // The underlying QUIC connection is shared with HTTP requests.
    WtResult WebTransport(const std::string& path,
                           const std::string& origin  = {},
                           const Headers&     headers = {});

    struct Impl;
private:
    std::unique_ptr<Impl> impl_;
};

} // namespace http3