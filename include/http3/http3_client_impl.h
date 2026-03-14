#pragma once
#include <http3.h>
#include <http3/http3_defs.h>
#include <http3/http3_frame.h>
#include <http3/http3_qpack.h>
#include <msquic.h>
#include <atomic>
#include <condition_variable>
#include <future>
#include <mutex>

namespace http3 {

struct ReqState {
    struct SendBuf { std::vector<uint8_t> data; QUIC_BUFFER qb; };

    HQUIC                stream  = nullptr;
    detail::StreamBuf    buf;
    Response             resp;
    bool                 hdr_done  = false;
    bool                 fulfilled = false;
    std::promise<Result> promise;
    Client::Impl*        client    = nullptr;

    void fulfill(Result r) {
        if (!fulfilled) { fulfilled = true; promise.set_value(std::move(r)); }
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

    ~Impl();

    bool   ensure_connected();
    void   disconnect();
    void   open_outbound_streams();
    Result do_request(const std::string& method,
                      const std::string& path,
                      const std::string& body,
                      const std::string& content_type,
                      const Headers&     extra);

    static QUIC_STATUS QUIC_API cb_conn  (HQUIC, void*, QUIC_CONNECTION_EVENT*);
    static QUIC_STATUS QUIC_API cb_stream(HQUIC, void*, QUIC_STREAM_EVENT*);
    static QUIC_STATUS QUIC_API cb_unidi (HQUIC, void*, QUIC_STREAM_EVENT*);
    static QUIC_STATUS QUIC_API cb_send  (HQUIC, void*, QUIC_STREAM_EVENT*);
};

} // namespace http3