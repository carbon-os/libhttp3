#pragma once
#include <http3.h>
#include <http3/http3_defs.h>
#include <http3/http3_frame.h>
#include <http3/http3_qpack.h>
#include <msquic.h>
#include <atomic>
#include <mutex>
#include <regex>
#include <vector>

namespace http3 {

struct Route {
    std::string method;
    std::regex  pattern;
    Handler     handler;
};

struct SrvConnCtx {
    const QUIC_API_TABLE* msquic;
    HQUIC                 conn;
    Server::Impl*         srv;
    HQUIC ctrl_out{}, qenc_out{}, qdec_out{};
};

struct SrvStreamCtx {
    const QUIC_API_TABLE* msquic;
    HQUIC                 stream;
    bool                  is_request;
    detail::StreamBuf     buf;
    Request               req;
    bool                  hdr_done{false};
    bool                  body_done{false};
    SrvConnCtx*           conn;
};

struct Server::Impl {
    std::vector<Route> routes;
    ErrorHandler       error_handler;
    std::mutex         routes_mu;

    const QUIC_API_TABLE* msquic   = nullptr;
    HQUIC                 reg      = nullptr;
    HQUIC                 config   = nullptr;
    HQUIC                 listener = nullptr;
    std::atomic<bool>     running{false};

    void add_route(const std::string& method,
                   const std::string& pattern, Handler h);
    bool match(const std::string& method, const std::string& path,
               Route& out, std::smatch& caps);

    bool start(const std::string& host, uint16_t port,
               const std::string& cert, const std::string& key,
               const std::string& alpn);
    void stop_impl();

    void open_server_streams(SrvConnCtx* cc);
    void send_unidi(SrvConnCtx* cc, HQUIC s, std::vector<uint8_t> data);
    void dispatch(SrvStreamCtx* sc);
    void send_response(SrvConnCtx* cc, HQUIC stream,
                       const Request& req, Response& resp);

    static QUIC_STATUS QUIC_API cb_listener(HQUIC, void*, QUIC_LISTENER_EVENT*);
    static QUIC_STATUS QUIC_API cb_conn    (HQUIC, void*, QUIC_CONNECTION_EVENT*);
    static QUIC_STATUS QUIC_API cb_stream  (HQUIC, void*, QUIC_STREAM_EVENT*);
    static QUIC_STATUS QUIC_API cb_send    (HQUIC, void*, QUIC_STREAM_EVENT*);
};

} // namespace http3