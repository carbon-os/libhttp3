#pragma once
// Internal implementation types for WebTransport sessions and streams.
// Not part of the public API.
#include <http3.h>
#include <http3/http3_defs.h>
#include <http3/http3_frame.h>
#include <msquic.h>
#include <atomic>
#include <condition_variable>
#include <map>
#include <mutex>
#include <set>
#include <vector>

namespace http3 {

// ── Stream callback context (used as MsQuic stream callback context) ──────────
// One of these lives per open WT stream opened *by this endpoint*.
// Peer-initiated streams are routed through SrvStreamCtx/ReqState detection.
struct WtStreamCallbackCtx {
    const QUIC_API_TABLE* msquic;
    HQUIC                 stream;
    uint64_t              qstream_id;     // QUIC stream id
    uint64_t              session_id;     // WT session id
    WtSession::Impl*      sess;           // non-owning, valid while session alive
    bool                  is_bidi;

    struct SendBuf { std::vector<uint8_t> data; QUIC_BUFFER qb; };
    static QUIC_STATUS QUIC_API cb(HQUIC, void*, QUIC_STREAM_EVENT*);
};

// ── WtStream::Impl ────────────────────────────────────────────────────────────
struct WtStream::Impl {
    WtSession::Impl* sess;          // non-owning; null after close
    uint64_t         qstream_id;
    bool             bidi;

    WtStream::DataCallback  data_cb;
    WtStream::CloseCallback close_cb;
};

// ── Per-stream state stored inside WtSession ──────────────────────────────────
struct WtStreamState {
    HQUIC    handle;           // may be null for peer-initiated until sent
    bool     is_bidi;
    bool     peer_initiated;

    WtStream::DataCallback  data_cb;
    WtStream::CloseCallback close_cb;

    // User-facing object. Created lazily when peer stream first arrives.
    std::unique_ptr<WtStream> wt_obj;
};

// ── WtSession::Impl ───────────────────────────────────────────────────────────
struct WtSession::Impl {
    const QUIC_API_TABLE* msquic;
    HQUIC                 conn;
    HQUIC                 connect_stream;
    uint64_t              session_id;

    std::mutex                              mu;
    std::map<uint64_t, WtStreamState>       streams;   // keyed on QUIC stream id
    WtSession::StreamCallback               stream_cb;
    WtSession::DatagramCallback             datagram_cb;
    WtSession::CloseCallback                close_cb;
    std::condition_variable                 close_cv;
    bool                                    closed{false};

    // ── called from server/client stream callbacks ────────────────────────────
    void on_peer_stream(uint64_t qsid, HQUIC stream, bool is_bidi);
    void on_stream_data(uint64_t qsid, const uint8_t* p, size_t n);
    void on_stream_close(uint64_t qsid);
    void on_datagram_recv(const uint8_t* p, size_t n);
    void on_session_terminated(uint32_t ec, const std::string& reason);

    // ── outbound helpers ─────────────────────────────────────────────────────
    WtStream* open_stream_impl(bool bidi);

    // ── capsule encoding ─────────────────────────────────────────────────────
    // Sends a WT_CLOSE_SESSION capsule on the CONNECT stream and closes it.
    void send_close_capsule(uint32_t ec, const std::string& reason);

    struct SendBuf { std::vector<uint8_t> data; QUIC_BUFFER qb; };
};

// ── Helper: encode a capsule (type + length + payload) ────────────────────────
inline std::vector<uint8_t> build_capsule(uint64_t type,
                                           const uint8_t* payload, size_t len)
{
    std::vector<uint8_t> c;
    detail::varint_append(c, type);
    detail::varint_append(c, len);
    c.insert(c.end(), payload, payload + len);
    return c;
}

} // namespace http3