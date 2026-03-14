#include <http3.h>
#include <http3/http3_wt_impl.h>
#include <http3/http3_log.h>
#include <cstring>

using namespace webtransport;
using namespace http3;

Session::Impl::~Impl() {
    std::function<void(uint64_t)> cb;
    {
        std::lock_guard<std::mutex> lk(mu);
        cb = std::move(unregister_cb);
        unregister_cb = nullptr;
        closed = true;
        
        // Explicitly abort all active streams tracked by this session.
        for (auto& [qsid, st] : streams) {
            if (st.handle) {
                msquic->StreamShutdown(st.handle, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
            }
        }
    }
    
    // Disconnect from the Server/Client connection map first
    if (cb) cb(session_id);

    // Wait safely until MsQuic finishes asynchronously closing all streams.
    std::unique_lock<std::mutex> lk(mu);
    close_cv.wait(lk, [this]{ return streams.empty(); });
}

void Session::Impl::on_peer_stream(uint64_t qsid, HQUIC stream, bool is_bidi) {
    std::function<void()> fire;
    {
        std::lock_guard<std::mutex> lk(mu);
        if (closed) return;

        WtStreamState st{};
        st.handle         = stream;
        st.peer_initiated = true;

        if (is_bidi) {
            st.kind = WtStreamState::Kind::Bidi;
            auto impl_ptr           = std::make_unique<BidirectionalStream::Impl>();
            impl_ptr->sess          = this;
            impl_ptr->qstream_id    = qsid;
            impl_ptr->bidi          = true;
            impl_ptr->peer_initiated = true;
            st.bidi_obj = std::make_unique<BidirectionalStream>(std::move(impl_ptr));

            auto* raw = st.bidi_obj.get();
            streams[qsid] = std::move(st);

            if (bidi_stream_cb) {
                auto cb = bidi_stream_cb;
                fire = [cb, raw]{ cb(*raw); };
            }
        } else {
            st.kind = WtStreamState::Kind::Receive;
            auto impl_ptr           = std::make_unique<ReceiveStream::Impl>();
            impl_ptr->sess          = this;
            impl_ptr->qstream_id    = qsid;
            impl_ptr->bidi          = false;
            impl_ptr->peer_initiated = true;
            st.recv_obj = std::make_unique<ReceiveStream>(std::move(impl_ptr));

            auto* raw = st.recv_obj.get();
            streams[qsid] = std::move(st);

            if (receive_stream_cb) {
                auto cb = receive_stream_cb;
                fire = [cb, raw]{ cb(*raw); };
            }
        }
    }
    if (fire) fire();
}

void Session::Impl::on_stream_data(uint64_t qsid, const uint8_t* p, size_t n) {
    std::function<void(const uint8_t*, size_t)> cb;
    {
        std::lock_guard<std::mutex> lk(mu);
        auto it = streams.find(qsid);
        if (it == streams.end()) return;
        cb = it->second.data_cb;
    }
    if (cb) cb(p, n);
}

void Session::Impl::on_stream_close(uint64_t qsid) {
    std::function<void()> cb;
    {
        std::lock_guard<std::mutex> lk(mu);
        auto it = streams.find(qsid);
        if (it == streams.end() || it->second.close_fired) return;
        it->second.close_fired = true;
        cb = it->second.close_cb;
    }
    if (cb) cb();
}

void Session::Impl::on_stream_shutdown_complete(uint64_t qsid) {
    std::lock_guard<std::mutex> lk(mu);
    streams.erase(qsid);
    close_cv.notify_all(); // Wake up the destructor if it is waiting
}

void Session::Impl::on_datagram_recv(const uint8_t* p, size_t n) {
    if (datagram_cb) datagram_cb(p, n);
}

void Session::Impl::on_session_terminated(uint32_t ec, const std::string& reason) {
    {
        std::lock_guard<std::mutex> lk(mu);
        if (closed) return;
        closed = true;
    }
    if (close_cb) close_cb(ec, std::string_view{reason});
    close_cv.notify_all();
}

void Session::Impl::send_close_capsule(uint32_t ec, const std::string& reason) {
    std::vector<uint8_t> payload;
    payload.push_back((ec >> 24) & 0xFF);
    payload.push_back((ec >> 16) & 0xFF);
    payload.push_back((ec >>  8) & 0xFF);
    payload.push_back( ec        & 0xFF);
    payload.insert(payload.end(), reason.begin(), reason.end());

    auto cap = build_capsule(detail::CAPSULE_WT_CLOSE_SESSION, payload.data(), payload.size());
    auto* sb = new Session::Impl::SendBuf();
    sb->data = std::move(cap);
    sb->qb.Buffer = sb->data.data();
    sb->qb.Length = (uint32_t)sb->data.size();
    if (QUIC_FAILED(msquic->StreamSend(connect_stream, &sb->qb, 1, QUIC_SEND_FLAG_FIN, sb)))
        delete sb;
}

BidirectionalStream* Session::Impl::open_bidi_stream_impl() {
    auto* wctx = new WtStreamCallbackCtx{};
    wctx->msquic = msquic; wctx->session_id = session_id; wctx->sess = this; wctx->is_bidi = true;

    HQUIC stream = nullptr;
    if (QUIC_FAILED(msquic->StreamOpen(conn, QUIC_STREAM_OPEN_FLAG_NONE, WtStreamCallbackCtx::cb, wctx, &stream))) {
        delete wctx; return nullptr;
    }
    if (QUIC_FAILED(msquic->StreamStart(stream, QUIC_STREAM_START_FLAG_IMMEDIATE))) {
        msquic->StreamClose(stream); delete wctx; return nullptr;
    }

    uint64_t qsid = 0; uint32_t plen = sizeof(qsid);
    msquic->GetParam(stream, QUIC_PARAM_STREAM_ID, &plen, &qsid);
    wctx->stream = stream; wctx->qstream_id = qsid;

    std::vector<uint8_t> hdr;
    detail::varint_append(hdr, detail::FRAME_WEBTRANSPORT_STREAM);
    detail::varint_append(hdr, session_id);
    auto* sb = new WtStreamCallbackCtx::SendBuf();
    sb->data = std::move(hdr);
    sb->qb.Buffer = sb->data.data();
    sb->qb.Length = (uint32_t)sb->data.size();
    if (QUIC_FAILED(msquic->StreamSend(stream, &sb->qb, 1, QUIC_SEND_FLAG_NONE, sb))) {
        delete sb; msquic->StreamClose(stream); delete wctx; return nullptr;
    }

    auto impl_ptr = std::make_unique<BidirectionalStream::Impl>();
    impl_ptr->sess = this; impl_ptr->qstream_id = qsid; impl_ptr->bidi = true; impl_ptr->peer_initiated = false;
    auto* obj = new BidirectionalStream(std::move(impl_ptr));

    WtStreamState st{};
    st.handle = stream; st.kind = WtStreamState::Kind::Bidi; st.peer_initiated = false;
    st.bidi_obj.reset(obj);

    { std::lock_guard<std::mutex> lk(mu); streams[qsid] = std::move(st); }
    return obj;
}

SendStream* Session::Impl::open_send_stream_impl() {
    auto* wctx = new WtStreamCallbackCtx{};
    wctx->msquic = msquic; wctx->session_id = session_id; wctx->sess = this; wctx->is_bidi = false;

    HQUIC stream = nullptr;
    if (QUIC_FAILED(msquic->StreamOpen(conn, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL, WtStreamCallbackCtx::cb, wctx, &stream))) {
        delete wctx; return nullptr;
    }
    if (QUIC_FAILED(msquic->StreamStart(stream, QUIC_STREAM_START_FLAG_IMMEDIATE))) {
        msquic->StreamClose(stream); delete wctx; return nullptr;
    }

    uint64_t qsid = 0; uint32_t plen = sizeof(qsid);
    msquic->GetParam(stream, QUIC_PARAM_STREAM_ID, &plen, &qsid);
    wctx->stream = stream; wctx->qstream_id = qsid;

    std::vector<uint8_t> hdr;
    detail::varint_append(hdr, detail::STREAM_WT_UNIDI);
    detail::varint_append(hdr, session_id);
    auto* sb = new WtStreamCallbackCtx::SendBuf();
    sb->data = std::move(hdr);
    sb->qb.Buffer = sb->data.data();
    sb->qb.Length = (uint32_t)sb->data.size();
    if (QUIC_FAILED(msquic->StreamSend(stream, &sb->qb, 1, QUIC_SEND_FLAG_NONE, sb))) {
        delete sb; msquic->StreamClose(stream); delete wctx; return nullptr;
    }

    auto impl_ptr = std::make_unique<SendStream::Impl>();
    impl_ptr->sess = this; impl_ptr->qstream_id = qsid; impl_ptr->bidi = false; impl_ptr->peer_initiated = false;
    auto* obj = new SendStream(std::move(impl_ptr));

    WtStreamState st{};
    st.handle = stream; st.kind = WtStreamState::Kind::Send; st.peer_initiated = false;
    st.send_obj.reset(obj);

    { std::lock_guard<std::mutex> lk(mu); streams[qsid] = std::move(st); }
    return obj;
}

QUIC_STATUS QUIC_API WtStreamCallbackCtx::cb(HQUIC /*s*/, void* ctx, QUIC_STREAM_EVENT* ev) {
    auto* wctx = static_cast<WtStreamCallbackCtx*>(ctx);

    switch (ev->Type) {
    case QUIC_STREAM_EVENT_RECEIVE:
        if (wctx->sess) {
            for (uint32_t i = 0; i < ev->RECEIVE.BufferCount; ++i)
                wctx->sess->on_stream_data(wctx->qstream_id, ev->RECEIVE.Buffers[i].Buffer, ev->RECEIVE.Buffers[i].Length);
            if (ev->RECEIVE.Flags & QUIC_RECEIVE_FLAG_FIN)
                wctx->sess->on_stream_close(wctx->qstream_id);
        }
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        if (wctx->sess) wctx->sess->on_stream_close(wctx->qstream_id);
        break;
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        delete static_cast<WtStreamCallbackCtx::SendBuf*>(ev->SEND_COMPLETE.ClientContext);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        if (wctx->sess) wctx->sess->on_stream_shutdown_complete(wctx->qstream_id);
        wctx->msquic->StreamClose(wctx->stream);
        delete wctx;
        break;
    default: break;
    }
    return QUIC_STATUS_SUCCESS;
}

static bool stream_write(WtStreamImplBase* impl, const void* data, size_t len) {
    if (!impl || !impl->sess) return false;
    auto& sess = *impl->sess;
    std::lock_guard<std::mutex> lk(sess.mu);
    auto it = sess.streams.find(impl->qstream_id);
    if (it == sess.streams.end() || !it->second.handle) return false;

    auto* sb = new WtStreamCallbackCtx::SendBuf();
    sb->data.assign(static_cast<const uint8_t*>(data), static_cast<const uint8_t*>(data) + len);
    sb->qb.Buffer = sb->data.data();
    sb->qb.Length = (uint32_t)sb->data.size();
    if (QUIC_FAILED(sess.msquic->StreamSend(it->second.handle, &sb->qb, 1, QUIC_SEND_FLAG_NONE, sb))) {
        delete sb; return false;
    }
    return true;
}

static void stream_close_write(WtStreamImplBase* impl) {
    if (!impl || !impl->sess) return;
    auto& sess = *impl->sess;
    std::lock_guard<std::mutex> lk(sess.mu);
    auto it = sess.streams.find(impl->qstream_id);
    if (it != sess.streams.end() && it->second.handle)
        sess.msquic->StreamShutdown(it->second.handle, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
}

static void stream_reset(WtStreamImplBase* impl, uint64_t app_error) {
    if (!impl || !impl->sess) return;
    auto& sess = *impl->sess;
    std::lock_guard<std::mutex> lk(sess.mu);
    auto it = sess.streams.find(impl->qstream_id);
    if (it != sess.streams.end() && it->second.handle)
        sess.msquic->StreamShutdown(it->second.handle, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, app_error);
}

template<typename ImplT>
static void stream_on_data(ImplT* impl, std::function<void(const uint8_t*, size_t)> cb) {
    if (!impl) return;
    impl->data_cb = cb;
    if (!impl->sess) return;
    std::lock_guard<std::mutex> lk(impl->sess->mu);
    auto it = impl->sess->streams.find(impl->qstream_id);
    if (it != impl->sess->streams.end())
        it->second.data_cb = std::move(cb);
}

template<typename ImplT>
static void stream_on_close(ImplT* impl, std::function<void()> cb) {
    if (!impl) return;
    impl->close_cb = cb;
    if (!impl->sess) return;
    std::lock_guard<std::mutex> lk(impl->sess->mu);
    auto it = impl->sess->streams.find(impl->qstream_id);
    if (it != impl->sess->streams.end())
        it->second.close_cb = std::move(cb);
}

BidirectionalStream::BidirectionalStream(std::unique_ptr<Impl> p) : impl_(std::move(p)) {}
BidirectionalStream::~BidirectionalStream() = default;
BidirectionalStream::BidirectionalStream(BidirectionalStream&&) noexcept = default;
uint64_t BidirectionalStream::id() const noexcept { return impl_ ? impl_->qstream_id : UINT64_MAX; }
bool BidirectionalStream::write(const void* d, size_t n) { return stream_write(impl_.get(), d, n); }
void BidirectionalStream::close_write() { stream_close_write(impl_.get()); }
void BidirectionalStream::reset(uint64_t e) { stream_reset(impl_.get(), e); }
void BidirectionalStream::on_data(DataCallback cb) { stream_on_data(impl_.get(), std::move(cb)); }
void BidirectionalStream::on_close(CloseCallback cb) { stream_on_close(impl_.get(), std::move(cb)); }

SendStream::SendStream(std::unique_ptr<Impl> p) : impl_(std::move(p)) {}
SendStream::~SendStream() = default;
SendStream::SendStream(SendStream&&) noexcept = default;
uint64_t SendStream::id() const noexcept { return impl_ ? impl_->qstream_id : UINT64_MAX; }
bool SendStream::write(const void* d, size_t n) { return stream_write(impl_.get(), d, n); }
void SendStream::close_write() { stream_close_write(impl_.get()); }
void SendStream::reset(uint64_t e) { stream_reset(impl_.get(), e); }

ReceiveStream::ReceiveStream(std::unique_ptr<Impl> p) : impl_(std::move(p)) {}
ReceiveStream::~ReceiveStream() = default;
ReceiveStream::ReceiveStream(ReceiveStream&&) noexcept = default;
uint64_t ReceiveStream::id() const noexcept { return impl_ ? impl_->qstream_id : UINT64_MAX; }
void ReceiveStream::on_data(DataCallback cb) { stream_on_data(impl_.get(), std::move(cb)); }
void ReceiveStream::on_close(CloseCallback cb) { stream_on_close(impl_.get(), std::move(cb)); }

Session::Session(std::unique_ptr<Impl> p) : impl_(std::move(p)) {}
Session::~Session() { if (impl_ && !impl_->closed) impl_->send_close_capsule(0, {}); }
uint64_t Session::session_id() const noexcept { return impl_ ? impl_->session_id : UINT64_MAX; }
BidirectionalStream* Session::open_bidi_stream() { return impl_ ? impl_->open_bidi_stream_impl() : nullptr; }
SendStream* Session::open_send_stream() { return impl_ ? impl_->open_send_stream_impl() : nullptr; }

bool Session::send_datagram(const void* data, size_t len) {
    if (!impl_) return false;
    uint64_t qsid = impl_->session_id / 4;
    std::vector<uint8_t> buf;
    detail::varint_append(buf, qsid);
    buf.insert(buf.end(), static_cast<const uint8_t*>(data), static_cast<const uint8_t*>(data) + len);
    auto* sb = new Session::Impl::SendBuf();
    sb->data = std::move(buf);
    sb->qb.Buffer = sb->data.data();
    sb->qb.Length = (uint32_t)sb->data.size();
    if (QUIC_FAILED(impl_->msquic->DatagramSend(impl_->conn, &sb->qb, 1, QUIC_SEND_FLAG_NONE, sb))) {
        delete sb; return false;
    }
    return true;
}

void Session::on_bidi_stream   (BidiStreamCallback    cb) { if (impl_) impl_->bidi_stream_cb    = std::move(cb); }
void Session::on_receive_stream(ReceiveStreamCallback cb) { if (impl_) impl_->receive_stream_cb = std::move(cb); }
void Session::on_datagram      (DatagramCallback      cb) { if (impl_) impl_->datagram_cb       = std::move(cb); }
void Session::on_close         (CloseCallback         cb) { if (impl_) impl_->close_cb          = std::move(cb); }
void Session::close(uint32_t ec, const std::string& reason) { if (impl_) impl_->send_close_capsule(ec, reason); }

void Session::wait() {
    if (!impl_) return;
    std::unique_lock<std::mutex> lk(impl_->mu);
    impl_->close_cv.wait(lk, [this]{ return impl_->closed; });
}

struct WebTransport::Impl {
    std::string host; uint16_t port{443}; std::string path; bool do_verify{true}; int conn_timeout{5}; int read_timeout{30};
    std::unique_ptr<http3::Client> cli; // Binds client lifetime to the WebTransport object
};

WebTransport::WebTransport(const std::string& url) : impl_(std::make_unique<Impl>()) {
    auto s = url; if (s.rfind("https://", 0) == 0) s = s.substr(8);
    auto slash = s.find('/'); std::string authority = (slash == std::string::npos) ? s : s.substr(0, slash);
    impl_->path = (slash == std::string::npos) ? "/" : s.substr(slash);
    auto colon = authority.rfind(':');
    if (colon != std::string::npos) { impl_->host = authority.substr(0, colon); impl_->port = (uint16_t)std::stoi(authority.substr(colon + 1)); }
    else { impl_->host = authority; impl_->port = 443; }
}
WebTransport::~WebTransport() = default;
void WebTransport::verify_cert(bool e) { impl_->do_verify = e; }
void WebTransport::set_connection_timeout(int s) { impl_->conn_timeout = s; }
void WebTransport::set_read_timeout(int s) { impl_->read_timeout = s; }

std::unique_ptr<Session> WebTransport::connect() {
    impl_->cli = std::make_unique<http3::Client>(impl_->host, impl_->port);
    impl_->cli->enable_server_certificate_verification(impl_->do_verify);
    impl_->cli->set_connection_timeout(impl_->conn_timeout);
    impl_->cli->set_read_timeout(impl_->read_timeout);
    return impl_->cli->WebTransport(impl_->path);
}