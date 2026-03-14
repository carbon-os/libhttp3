// WebTransport session and stream implementation.
#include <http3/http3_log.h>
#include <http3/http3_wt_impl.h>
#include <http3/http3_varint.h>
#include <cstring>
#include <stdexcept>

namespace http3 {

// ═══════════════════════════════════════════════════════════════════════════════
// WtSession::Impl helpers
// ═══════════════════════════════════════════════════════════════════════════════

// Called when a peer-initiated WT stream header has been decoded (server or client).
void WtSession::Impl::on_peer_stream(uint64_t qsid, HQUIC stream, bool is_bidi)
{
    WtStream* raw_ptr = nullptr;
    {
        std::unique_lock<std::mutex> lock(mu);
        if (closed) return;

        WtStreamState st{};
        st.handle         = stream;
        st.is_bidi        = is_bidi;
        st.peer_initiated = true;

        auto wt_impl = std::make_unique<WtStream::Impl>();
        wt_impl->sess       = this;
        wt_impl->qstream_id = qsid;
        wt_impl->bidi       = is_bidi;
        st.wt_obj = std::make_unique<WtStream>(std::move(wt_impl));

        raw_ptr = st.wt_obj.get();
        streams[qsid] = std::move(st);
    } // ← release lock before calling user callback

    if (stream_cb) stream_cb(*raw_ptr);
}

// Called when data arrives on a peer-initiated WT stream.
void WtSession::Impl::on_stream_data(uint64_t qsid, const uint8_t* p, size_t n)
{
    // Copy the callback out while holding the lock, then call it outside.
    // Calling user code under mu causes deadlock when the callback calls
    // WtStream::write(), which also acquires mu.
    WtStream::DataCallback cb;
    {
        std::lock_guard<std::mutex> lock(mu);
        auto it = streams.find(qsid);
        if (it == streams.end()) return;
        if (it->second.data_cb)
            cb = it->second.data_cb;
        else if (it->second.wt_obj && it->second.wt_obj->impl())
            cb = it->second.wt_obj->impl()->data_cb;
    } // ← release lock before calling user callback

    if (cb) cb(p, n);
}

// Called when the peer FINs a WT stream.
void WtSession::Impl::on_stream_close(uint64_t qsid)
{
    WtStream::CloseCallback cb;
    {
        std::unique_lock<std::mutex> lock(mu);
        auto it = streams.find(qsid);
        if (it == streams.end()) return;
        if (it->second.close_cb)
            cb = it->second.close_cb;
        else if (it->second.wt_obj && it->second.wt_obj->impl())
            cb = it->second.wt_obj->impl()->close_cb;
        streams.erase(it); // destroy WtStream before releasing lock
    } // ← release lock before calling user callback

    if (cb) cb();
}

void WtSession::Impl::on_datagram_recv(const uint8_t* p, size_t n)
{
    if (datagram_cb) datagram_cb(p, n);
}

void WtSession::Impl::on_session_terminated(uint32_t ec, const std::string& reason)
{
    {
        std::lock_guard<std::mutex> lock(mu);
        if (closed) return;
        closed = true;
    }
    if (close_cb) close_cb(ec, reason);
    close_cv.notify_all();
}

void WtSession::Impl::send_close_capsule(uint32_t ec, const std::string& reason)
{
    // WT_CLOSE_SESSION capsule payload: u32 error_code + UTF-8 reason
    std::vector<uint8_t> payload;
    payload.push_back((ec >> 24) & 0xFF);
    payload.push_back((ec >> 16) & 0xFF);
    payload.push_back((ec >>  8) & 0xFF);
    payload.push_back( ec        & 0xFF);
    payload.insert(payload.end(), reason.begin(), reason.end());

    auto capsule = build_capsule(detail::CAPSULE_WT_CLOSE_SESSION,
                                  payload.data(), payload.size());
    auto* sb      = new WtSession::Impl::SendBuf();
    sb->data      = std::move(capsule);
    sb->qb.Buffer = sb->data.data();
    sb->qb.Length = (uint32_t)sb->data.size();
    // Send FIN after capsule to cleanly close the CONNECT stream
    if (QUIC_FAILED(msquic->StreamSend(connect_stream, &sb->qb, 1,
                                        QUIC_SEND_FLAG_FIN, sb)))
        delete sb;
}

WtStream* WtSession::Impl::open_stream_impl(bool bidi)
{
    // Allocate a callback context for this outbound stream
    auto* wctx       = new WtStreamCallbackCtx{};
    wctx->msquic     = msquic;
    wctx->session_id = session_id;
    wctx->sess       = this;
    wctx->is_bidi    = bidi;

    QUIC_STREAM_OPEN_FLAGS flags =
        bidi ? QUIC_STREAM_OPEN_FLAG_NONE
             : QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL;
    HQUIC stream = nullptr;
    if (QUIC_FAILED(msquic->StreamOpen(conn, flags,
            WtStreamCallbackCtx::cb, wctx, &stream))) {
        delete wctx; return nullptr;
    }
    if (QUIC_FAILED(msquic->StreamStart(stream, QUIC_STREAM_START_FLAG_IMMEDIATE))) {
        msquic->StreamClose(stream); delete wctx; return nullptr;
    }

    uint64_t qsid = 0;
    uint32_t plen = sizeof(qsid);
    msquic->GetParam(stream, QUIC_PARAM_STREAM_ID, &plen, &qsid);
    wctx->stream    = stream;
    wctx->qstream_id = qsid;

    // Write the WT stream header
    std::vector<uint8_t> hdr;
    if (bidi) {
        detail::varint_append(hdr, detail::FRAME_WEBTRANSPORT_STREAM);
        detail::varint_append(hdr, session_id);
    } else {
        detail::varint_append(hdr, detail::STREAM_WT_UNIDI);
        detail::varint_append(hdr, session_id);
    }
    auto* sb      = new WtStreamCallbackCtx::SendBuf();
    sb->data      = std::move(hdr);
    sb->qb.Buffer = sb->data.data();
    sb->qb.Length = (uint32_t)sb->data.size();
    if (QUIC_FAILED(msquic->StreamSend(stream, &sb->qb, 1, QUIC_SEND_FLAG_NONE, sb))) {
        delete sb; msquic->StreamClose(stream); delete wctx; return nullptr;
    }

    // Create the user-visible WtStream
    auto impl = std::make_unique<WtStream::Impl>();
    impl->sess       = this;
    impl->qstream_id = qsid;
    impl->bidi       = bidi;
    auto* wt = new WtStream(std::move(impl));

    WtStreamState st{};
    st.handle         = stream;
    st.is_bidi        = bidi;
    st.peer_initiated = false;
    st.wt_obj.reset(wt);

    {
        std::lock_guard<std::mutex> lock(mu);
        streams[qsid] = std::move(st);
    }
    return wt;
}

// ═══════════════════════════════════════════════════════════════════════════════
// WtStreamCallbackCtx::cb  — MsQuic stream callback for outbound WT streams
// ═══════════════════════════════════════════════════════════════════════════════
QUIC_STATUS QUIC_API WtStreamCallbackCtx::cb(
    HQUIC /*s*/, void* ctx, QUIC_STREAM_EVENT* ev)
{
    auto* wctx = static_cast<WtStreamCallbackCtx*>(ctx);

    switch (ev->Type) {
    case QUIC_STREAM_EVENT_RECEIVE:
        if (wctx->sess) {
            for (uint32_t i = 0; i < ev->RECEIVE.BufferCount; ++i) {
                wctx->sess->on_stream_data(
                    wctx->qstream_id,
                    ev->RECEIVE.Buffers[i].Buffer,
                    ev->RECEIVE.Buffers[i].Length);
            }
            // Detect FIN delivered with the final RECEIVE event
            if (ev->RECEIVE.Flags & QUIC_RECEIVE_FLAG_FIN) {
                wctx->sess->on_stream_close(wctx->qstream_id);
            }
        }
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        if (wctx->sess) wctx->sess->on_stream_close(wctx->qstream_id);
        break;
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        delete static_cast<WtStreamCallbackCtx::SendBuf*>(ev->SEND_COMPLETE.ClientContext);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        if (wctx->sess) wctx->sess->on_stream_close(wctx->qstream_id);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        wctx->msquic->StreamClose(wctx->stream);
        delete wctx;
        break;
    default: break;
    }
    return QUIC_STATUS_SUCCESS;
}

// ═══════════════════════════════════════════════════════════════════════════════
// WtStream public API
// ═══════════════════════════════════════════════════════════════════════════════
WtStream::WtStream(std::unique_ptr<Impl> p) : impl_(std::move(p)) {}
WtStream::~WtStream() = default;
WtStream::WtStream(WtStream&& o) noexcept : impl_(std::move(o.impl_)) {}

uint64_t WtStream::id()      const noexcept { return impl_ ? impl_->qstream_id : UINT64_MAX; }
bool     WtStream::is_bidi() const noexcept { return impl_ && impl_->bidi; }

bool WtStream::write(const void* data, size_t len)
{
    if (!impl_ || !impl_->sess) {
        H3LOG_INFO("WtStream::write: no impl/sess  qsid=%" PRIu64,
                   impl_ ? impl_->qstream_id : UINT64_MAX);
        return false;
    }
    auto& sess = *impl_->sess;
    std::lock_guard<std::mutex> lock(sess.mu);
    auto it = sess.streams.find(impl_->qstream_id);
    if (it == sess.streams.end() || !it->second.handle) {
        H3LOG_INFO("WtStream::write: stream not found or no handle  qsid=%" PRIu64,
                   impl_->qstream_id);
        return false;
    }

    auto* sb      = new WtStreamCallbackCtx::SendBuf();
    sb->data.assign(static_cast<const uint8_t*>(data),
                    static_cast<const uint8_t*>(data) + len);
    sb->qb.Buffer = sb->data.data();
    sb->qb.Length = (uint32_t)sb->data.size();

    QUIC_STATUS qs = sess.msquic->StreamSend(
        it->second.handle, &sb->qb, 1, QUIC_SEND_FLAG_NONE, sb);
    if (QUIC_FAILED(qs)) {
        H3LOG_INFO("WtStream::write: StreamSend FAILED  qsid=%" PRIu64
                   "  status=0x%x", impl_->qstream_id, qs);
        delete sb;
        return false;
    }
    H3LOG_VERBOSE("WtStream::write: StreamSend OK  qsid=%" PRIu64
                  "  len=%zu", impl_->qstream_id, len);
    return true;
}

void WtStream::close_write()
{
    if (!impl_ || !impl_->sess) return;
    auto& sess = *impl_->sess;
    std::lock_guard<std::mutex> lock(sess.mu);
    auto it = sess.streams.find(impl_->qstream_id);
    if (it != sess.streams.end() && it->second.handle)
        sess.msquic->StreamShutdown(it->second.handle,
            QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
}

void WtStream::reset(uint64_t app_error)
{
    if (!impl_ || !impl_->sess) return;
    auto& sess = *impl_->sess;
    std::lock_guard<std::mutex> lock(sess.mu);
    auto it = sess.streams.find(impl_->qstream_id);
    if (it != sess.streams.end() && it->second.handle)
        sess.msquic->StreamShutdown(it->second.handle,
            QUIC_STREAM_SHUTDOWN_FLAG_ABORT, app_error);
}

void WtStream::on_data (WtStream::DataCallback  cb)
{
    if (impl_) impl_->data_cb = std::move(cb);
}
void WtStream::on_close(WtStream::CloseCallback cb)
{
    if (impl_) impl_->close_cb = std::move(cb);
}

// ═══════════════════════════════════════════════════════════════════════════════
// WtSession public API
// ═══════════════════════════════════════════════════════════════════════════════
WtSession::WtSession(std::unique_ptr<Impl> p) : impl_(std::move(p)) {}
WtSession::~WtSession() {
    if (impl_ && !impl_->closed)
        impl_->send_close_capsule(0, {});
}

uint64_t WtSession::session_id() const noexcept {
    return impl_ ? impl_->session_id : UINT64_MAX;
}

WtStream* WtSession::open_unidi_stream() {
    return impl_ ? impl_->open_stream_impl(false) : nullptr;
}
WtStream* WtSession::open_bidi_stream() {
    return impl_ ? impl_->open_stream_impl(true) : nullptr;
}

bool WtSession::send_datagram(const void* data, size_t len)
{
    if (!impl_) return false;
    // Datagram payload: Quarter Stream ID (varint) + data
    // Quarter Stream ID = session_id / 4
    uint64_t qsid = impl_->session_id / 4;
    std::vector<uint8_t> buf;
    detail::varint_append(buf, qsid);
    buf.insert(buf.end(),
               static_cast<const uint8_t*>(data),
               static_cast<const uint8_t*>(data) + len);

    auto* sb      = new WtSession::Impl::SendBuf();
    sb->data      = std::move(buf);
    sb->qb.Buffer = sb->data.data();
    sb->qb.Length = (uint32_t)sb->data.size();
    QUIC_STATUS s = impl_->msquic->DatagramSend(
        impl_->conn, &sb->qb, 1, QUIC_SEND_FLAG_NONE, sb);
    if (QUIC_FAILED(s)) { delete sb; return false; }
    return true;
}

void WtSession::close(uint32_t error_code, const std::string& reason) {
    if (impl_) impl_->send_close_capsule(error_code, reason);
}

void WtSession::wait() {
    if (!impl_) return;
    std::unique_lock<std::mutex> lock(impl_->mu);
    impl_->close_cv.wait(lock, [this]{ return impl_->closed; });
}

void WtSession::on_stream  (StreamCallback   cb) { if (impl_) impl_->stream_cb   = std::move(cb); }
void WtSession::on_datagram(DatagramCallback cb) { if (impl_) impl_->datagram_cb = std::move(cb); }
void WtSession::on_close   (CloseCallback    cb) { if (impl_) impl_->close_cb    = std::move(cb); }

} // namespace http3