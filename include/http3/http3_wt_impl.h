#pragma once
#include <http3/webtransport.h>
#include <http3/http3_defs.h>
#include <http3/http3_frame.h>
#include <http3/http3_varint.h>
#include <msquic.h>
#include <atomic>
#include <condition_variable>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <vector>

namespace http3 {
struct WtStreamImplBase {
    webtransport::Session::Impl* sess{nullptr};
    uint64_t                     qstream_id{UINT64_MAX};
    bool                         bidi{false};
    bool                         peer_initiated{false};

    std::function<void(const uint8_t*, size_t)> data_cb;
    std::function<void()>                        close_cb;
};
}

namespace webtransport {
struct BidirectionalStream::Impl : http3::WtStreamImplBase {};
struct SendStream::Impl          : http3::WtStreamImplBase {};
struct ReceiveStream::Impl       : http3::WtStreamImplBase {};
}

namespace http3 {
struct WtStreamState {
    HQUIC handle{nullptr};

    enum class Kind { Bidi, Send, Receive } kind{Kind::Bidi};
    bool peer_initiated{false};
    bool close_fired{false};

    std::unique_ptr<webtransport::BidirectionalStream> bidi_obj;
    std::unique_ptr<webtransport::SendStream>          send_obj;
    std::unique_ptr<webtransport::ReceiveStream>       recv_obj;

    std::function<void(const uint8_t*, size_t)> data_cb;
    std::function<void()>                        close_cb;
};
}

namespace webtransport {
struct Session::Impl {
    const QUIC_API_TABLE* msquic{nullptr};
    HQUIC                 conn{nullptr};
    HQUIC                 connect_stream{nullptr};
    uint64_t              session_id{0};

    std::mutex                              mu;
    std::map<uint64_t, http3::WtStreamState> streams;
    Session::BidiStreamCallback             bidi_stream_cb;
    Session::ReceiveStreamCallback          receive_stream_cb;
    Session::DatagramCallback               datagram_cb;
    Session::CloseCallback                  close_cb;
    std::condition_variable                 close_cv;
    bool                                    closed{false};
    std::function<void(uint64_t)>           unregister_cb;

    ~Impl();

    void on_peer_stream      (uint64_t qsid, HQUIC stream, bool is_bidi);
    void on_stream_data      (uint64_t qsid, const uint8_t* p, size_t n);
    void on_stream_close     (uint64_t qsid);
    void on_stream_shutdown_complete(uint64_t qsid);
    void on_datagram_recv    (const uint8_t* p, size_t n);
    void on_session_terminated(uint32_t ec, const std::string& reason);

    BidirectionalStream* open_bidi_stream_impl();
    SendStream* open_send_stream_impl();
    void send_close_capsule(uint32_t ec, const std::string& reason);

    struct SendBuf { std::vector<uint8_t> data; QUIC_BUFFER qb; };
};
}

namespace http3 {
struct WtStreamCallbackCtx {
    const QUIC_API_TABLE* msquic{nullptr};
    HQUIC                        stream{nullptr};
    uint64_t                     qstream_id{UINT64_MAX};
    uint64_t                     session_id{0};
    webtransport::Session::Impl* sess{nullptr};
    bool                         is_bidi{false};

    struct SendBuf { std::vector<uint8_t> data; QUIC_BUFFER qb; };
    static QUIC_STATUS QUIC_API cb(HQUIC, void*, QUIC_STREAM_EVENT*);
};

inline std::vector<uint8_t> build_capsule(uint64_t type, const uint8_t* payload, size_t len) {
    std::vector<uint8_t> c;
    detail::varint_append(c, type);
    detail::varint_append(c, len);
    c.insert(c.end(), payload, payload + len);
    return c;
}
}