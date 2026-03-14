#pragma once
#include <http3.h>
#include <http3/http3_defs.h>
#include <http3/http3_frame.h>
#include <http3/http3_qpack.h>
#include <http3/http3_wt_impl.h>
#include <msquic.h>
#include <atomic>
#include <condition_variable>
#include <future>
#include <map>
#include <mutex>

namespace http3 {

struct ReqState {
    struct SendBuf { std::vector<uint8_t> data; QUIC_BUFFER qb; };

    HQUIC                stream  = nullptr;
    detail::StreamBuf    buf;
    Response             resp;
    bool                 hdr_done  = false;
    bool                 fulfilled = false;
    std::promise<http3::Result> promise;
    Client::Impl*        client    = nullptr;

    void fulfill(Result r) {
        if (!fulfilled) { fulfilled = true; promise.set_value(std::move(r)); }
    }
};

// ── WebTransport CONNECT in-flight state ─────────────────────────────────────
struct WtConnectState {
    struct SendBuf { std::vector<uint8_t> data; QUIC_BUFFER qb; };

    using SessionPtr = std::unique_ptr<webtransport::Session>;

    HQUIC                          stream    = nullptr;
    detail::StreamBuf              buf;
    bool                           hdr_done  = false;
    bool                           fulfilled = false;
    std::promise<SessionPtr>       promise;
    Client::Impl*                  client    = nullptr;
    std::string                    path;

    void fulfill(SessionPtr s) {
        if (!fulfilled) { fulfilled = true; promise.set_value(std::move(s)); }
    }
    void fail() {
        if (!fulfilled) { fulfilled = true; promise.set_value(nullptr); }
    }
};

struct Client::Impl {
    std::string host;
    uint16_t    port;
    bool        verify_cert  = false;
    std::string ca_cert_path;
    int         conn_timeout = 10;
    int         read_timeout = 30;

    const QUIC_API_TABLE* msquic  = nullptr;
    HQUIC                 reg     = nullptr;
    HQUIC                 config  = nullptr;
    HQUIC                 conn    = nullptr;

    HQUIC ctrl_out{}, qenc_out{}, qdec_out{};

    std::atomic<bool>       connected{false};
    std::atomic<bool>       conn_failed{false};
    std::mutex              mu;
    std::condition_variable cv;

    std::mutex                                          wt_mu;
    std::map<uint64_t, webtransport::Session::Impl*>    wt_sessions;

    ~Impl();
    bool   ensure_connected();
    void   disconnect();
    void   open_outbound_streams();
    Result do_request(const std::string& method,
                      const std::string& path,
                      const std::string& body,
                      const std::string& content_type,
                      const Headers&     extra);
    std::unique_ptr<webtransport::Session>
           do_webtransport(const std::string& path,
                           const std::string& origin,
                           const Headers&     extra);

    void register_wt_session  (webtransport::Session::Impl* s);
    void unregister_wt_session(uint64_t sid);
    webtransport::Session::Impl* find_wt_session(uint64_t sid);

    static QUIC_STATUS QUIC_API cb_conn      (HQUIC, void*, QUIC_CONNECTION_EVENT*);
    static QUIC_STATUS QUIC_API cb_stream    (HQUIC, void*, QUIC_STREAM_EVENT*);
    static QUIC_STATUS QUIC_API cb_wt_connect(HQUIC, void*, QUIC_STREAM_EVENT*);
    static QUIC_STATUS QUIC_API cb_unidi     (HQUIC, void*, QUIC_STREAM_EVENT*);
    static QUIC_STATUS QUIC_API cb_send      (HQUIC, void*, QUIC_STREAM_EVENT*);
};

} // namespace http3