#pragma once
// ╔══════════════════════════════════════════════════════════════════════╗
// ║  http3  —  HTTP/3 server + client                                   ║
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

// ── Handler ───────────────────────────────────────────────────────────────────
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

// ── Server ────────────────────────────────────────────────────────────────────
class Server {
public:
     Server();
    ~Server();
    Server(const Server&)            = delete;
    Server& operator=(const Server&) = delete;

    Server& Get    (const std::string& pattern, Handler h);
    Server& Post   (const std::string& pattern, Handler h);
    Server& Put    (const std::string& pattern, Handler h);
    Server& Delete (const std::string& pattern, Handler h);
    Server& Head   (const std::string& pattern, Handler h);
    Server& Options(const std::string& pattern, Handler h);
    Server& Patch  (const std::string& pattern, Handler h);

    void set_error_handler(ErrorHandler h);

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

// ── Client ────────────────────────────────────────────────────────────────────
class Client {
public:
    Client(const std::string& host, uint16_t port);
    ~Client();
    Client(const Client&)            = delete;
    Client& operator=(const Client&) = delete;

    void enable_server_certificate_verification(bool enable);
    void set_ca_cert_path(const std::string& path);
    void set_connection_timeout(int sec);
    void set_read_timeout(int sec);

    Result Get    (const std::string& path, const Headers& headers = {});
    Result Post   (const std::string& path, const std::string& body,
                   const std::string& content_type, const Headers& headers = {});
    Result Put    (const std::string& path, const std::string& body,
                   const std::string& content_type, const Headers& headers = {});
    Result Delete (const std::string& path, const std::string& body = {},
                   const std::string& content_type = {}, const Headers& headers = {});
    Result Head   (const std::string& path, const Headers& headers = {});
    Result Options(const std::string& path, const Headers& headers = {});
    Result Patch  (const std::string& path, const std::string& body,
                   const std::string& content_type, const Headers& headers = {});

    struct Impl;
private:
    std::unique_ptr<Impl> impl_;
};

} // namespace http3