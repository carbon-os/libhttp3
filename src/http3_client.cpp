#include <http3/http3_client_impl.h>
#include <cstdio>
#include <cstring>
#include <chrono>

namespace http3 {

struct SendBuf { std::vector<uint8_t> data; QUIC_BUFFER qb; };

// ── Impl destructor / disconnect ──────────────────────────────────────────────
Client::Impl::~Impl() {
    disconnect();
    if (msquic) { MsQuicClose(msquic); msquic = nullptr; }
}

void Client::Impl::disconnect() {
    connected   = false;
    conn_failed = false;
    ctrl_out = qenc_out = qdec_out = nullptr;
    if (conn)   { msquic->ConnectionClose(conn);      conn   = nullptr; }
    if (config) { msquic->ConfigurationClose(config); config = nullptr; }
    if (reg)    { msquic->RegistrationClose(reg);     reg    = nullptr; }
}

// ── WT session registry ───────────────────────────────────────────────────────
void Client::Impl::register_wt_session(WtSession::Impl* s) {
    std::lock_guard<std::mutex> lock(wt_mu);
    wt_sessions[s->session_id] = s;
}
void Client::Impl::unregister_wt_session(uint64_t sid) {
    std::lock_guard<std::mutex> lock(wt_mu);
    wt_sessions.erase(sid);
}
WtSession::Impl* Client::Impl::find_wt_session(uint64_t sid) {
    std::lock_guard<std::mutex> lock(wt_mu);
    auto it = wt_sessions.find(sid);
    return it != wt_sessions.end() ? it->second : nullptr;
}

// ── ensure_connected ──────────────────────────────────────────────────────────
bool Client::Impl::ensure_connected() {
    std::unique_lock<std::mutex> lock(mu);
    if (connected) return true;
    if (conn_failed) { conn_failed = false; }

    if (!msquic) {
        QUIC_STATUS s;
        if (QUIC_FAILED(s = MsQuicOpen2(&msquic))) {
            fprintf(stderr, "[http3] MsQuicOpen2 failed: 0x%x\n", s);
            return false;
        }
        const QUIC_REGISTRATION_CONFIG rc{ "libhttp3-client",
                                            QUIC_EXECUTION_PROFILE_LOW_LATENCY };
        if (QUIC_FAILED(s = msquic->RegistrationOpen(&rc, &reg))) {
            MsQuicClose(msquic); msquic = nullptr; return false;
        }

        QUIC_SETTINGS settings{};
        settings.IdleTimeoutMs              = 30000;
        settings.IsSet.IdleTimeoutMs        = TRUE;
        settings.PeerUnidiStreamCount       = 16;
        settings.IsSet.PeerUnidiStreamCount = TRUE;
        // Enable QUIC datagrams for WebTransport
        settings.DatagramReceiveEnabled     = TRUE;
        settings.IsSet.DatagramReceiveEnabled = TRUE;

        const std::string alpn_str = "h3";
        QUIC_BUFFER ab{ (uint32_t)alpn_str.size(),
            reinterpret_cast<uint8_t*>(const_cast<char*>(alpn_str.c_str())) };

        if (QUIC_FAILED(s = msquic->ConfigurationOpen(
                reg, &ab, 1, &settings, sizeof(settings), nullptr, &config))) {
            msquic->RegistrationClose(reg); reg = nullptr;
            MsQuicClose(msquic); msquic = nullptr; return false;
        }

        QUIC_CREDENTIAL_CONFIG cred{};
        memset(&cred, 0, sizeof(cred));
        cred.Type  = QUIC_CREDENTIAL_TYPE_NONE;
        cred.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
        if (!verify_cert)
            cred.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
        if (!ca_cert_path.empty()) {
            cred.CaCertificateFile  = ca_cert_path.c_str();
            cred.Flags             |= QUIC_CREDENTIAL_FLAG_SET_CA_CERTIFICATE_FILE;
        }
        if (QUIC_FAILED(s = msquic->ConfigurationLoadCredential(config, &cred))) {
            fprintf(stderr, "[http3] client TLS credential failed: 0x%x\n", s);
            return false;
        }
    }

    QUIC_STATUS s;
    if (QUIC_FAILED(s = msquic->ConnectionOpen(reg, cb_conn, this, &conn))) {
        fprintf(stderr, "[http3] ConnectionOpen failed: 0x%x\n", s); return false;
    }
    if (QUIC_FAILED(s = msquic->ConnectionStart(
            conn, config, QUIC_ADDRESS_FAMILY_UNSPEC,
            host.c_str(), port))) {
        fprintf(stderr, "[http3] ConnectionStart failed: 0x%x\n", s);
        msquic->ConnectionClose(conn); conn = nullptr; return false;
    }

    bool ok = cv.wait_for(lock, std::chrono::seconds(conn_timeout),
        [this]{ return connected.load() || conn_failed.load(); });
    return ok && connected;
}

// ── Open outbound H3 control / QPACK streams ──────────────────────────────────
void Client::Impl::open_outbound_streams() {
    auto open = [&](HQUIC& handle, uint64_t stype,
                     std::vector<uint8_t> extra) {
        if (QUIC_FAILED(msquic->StreamOpen(
                conn, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL,
                cb_send, this, &handle))) return;
        if (QUIC_FAILED(msquic->StreamStart(
                handle, QUIC_STREAM_START_FLAG_IMMEDIATE))) return;
        std::vector<uint8_t> wire;
        detail::varint_append(wire, stype);
        wire.insert(wire.end(), extra.begin(), extra.end());
        auto* sb      = new SendBuf();
        sb->data      = std::move(wire);
        sb->qb.Buffer = sb->data.data();
        sb->qb.Length = (uint32_t)sb->data.size();
        if (QUIC_FAILED(msquic->StreamSend(handle, &sb->qb, 1,
                                            QUIC_SEND_FLAG_NONE, sb)))
            delete sb;
    };
    open(ctrl_out, detail::STREAM_CONTROL,       detail::build_settings_frame());
    open(qenc_out, detail::STREAM_QPACK_ENCODER, {});
    open(qdec_out, detail::STREAM_QPACK_DECODER, {});
}

// ── HTTP request ──────────────────────────────────────────────────────────────
Result Client::Impl::do_request(const std::string& method,
                                  const std::string& path,
                                  const std::string& body,
                                  const std::string& content_type,
                                  const Headers&     extra) {
    if (!ensure_connected()) return Result(Error::Connection);

    std::vector<detail::QpackHeader> qh;
    qh.push_back({":method",    method});
    qh.push_back({":path",      path});
    qh.push_back({":scheme",    "https"});
    qh.push_back({":authority", host + ":" + std::to_string(port)});
    if (!content_type.empty())
        qh.push_back({"content-type",   content_type});
    if (!body.empty())
        qh.push_back({"content-length", std::to_string(body.size())});
    for (auto& [k, v] : extra) qh.push_back({k, v});

    auto qblock = detail::qpack_encode(qh);
    auto wire   = detail::build_frame(detail::FRAME_HEADERS, qblock);
    if (!body.empty()) {
        auto df = detail::build_frame(detail::FRAME_DATA,
            reinterpret_cast<const uint8_t*>(body.data()), body.size());
        wire.insert(wire.end(), df.begin(), df.end());
    }

    auto* rs    = new ReqState();
    rs->client  = this;
    auto future = rs->promise.get_future();

    HQUIC stream = nullptr;
    if (QUIC_FAILED(msquic->StreamOpen(
            conn, QUIC_STREAM_OPEN_FLAG_NONE,
            cb_stream, rs, &stream)) ||
        QUIC_FAILED(msquic->StreamStart(
            stream, QUIC_STREAM_START_FLAG_IMMEDIATE)))
    {
        delete rs; return Result(Error::Connection);
    }
    rs->stream = stream;

    auto* sb      = new ReqState::SendBuf();
    sb->data      = std::move(wire);
    sb->qb.Buffer = sb->data.data();
    sb->qb.Length = (uint32_t)sb->data.size();
    if (QUIC_FAILED(msquic->StreamSend(stream, &sb->qb, 1,
                                        QUIC_SEND_FLAG_FIN, sb))) {
        delete sb; delete rs; return Result(Error::SendFailed);
    }

    if (future.wait_for(std::chrono::seconds(read_timeout))
        != std::future_status::ready)
    {
        msquic->StreamShutdown(stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        return Result(Error::ReadTimeout);
    }
    return future.get();
}

// ── WebTransport CONNECT ──────────────────────────────────────────────────────
WtResult Client::Impl::do_webtransport(const std::string& path,
                                        const std::string& origin,
                                        const Headers&     extra) {
    if (!ensure_connected()) return WtResult(WtResult::Error::Connection);

    // Extended CONNECT (RFC 9220) with :protocol = webtransport-h3
    std::vector<detail::QpackHeader> qh;
    qh.push_back({":method",    "CONNECT"});
    qh.push_back({":protocol",  "webtransport-h3"});
    qh.push_back({":scheme",    "https"});
    qh.push_back({":authority", host + ":" + std::to_string(port)});
    qh.push_back({":path",      path});
    if (!origin.empty())
        qh.push_back({"origin", origin});
    for (auto& [k, v] : extra) qh.push_back({k, v});

    auto qblock = detail::qpack_encode(qh);
    // HEADERS frame — no DATA, no FIN (CONNECT stream must stay open)
    auto wire   = detail::build_frame(detail::FRAME_HEADERS, qblock);

    auto* ws    = new WtConnectState{};
    ws->client  = this;
    ws->path    = path;
    auto future = ws->promise.get_future();

    HQUIC stream = nullptr;
    if (QUIC_FAILED(msquic->StreamOpen(
            conn, QUIC_STREAM_OPEN_FLAG_NONE,
            cb_wt_connect, ws, &stream)) ||
        QUIC_FAILED(msquic->StreamStart(
            stream, QUIC_STREAM_START_FLAG_IMMEDIATE)))
    {
        delete ws; return WtResult(WtResult::Error::Connection);
    }
    ws->stream = stream;

    auto* sb      = new WtConnectState::SendBuf();
    sb->data      = std::move(wire);
    sb->qb.Buffer = sb->data.data();
    sb->qb.Length = (uint32_t)sb->data.size();
    // Intentionally NO QUIC_SEND_FLAG_FIN
    if (QUIC_FAILED(msquic->StreamSend(stream, &sb->qb, 1,
                                        QUIC_SEND_FLAG_NONE, sb))) {
        delete sb; delete ws;
        return WtResult(WtResult::Error::Connection);
    }

    if (future.wait_for(std::chrono::seconds(read_timeout))
        != std::future_status::ready)
        return WtResult(WtResult::Error::Timeout);

    return future.get();
}

// ── cb_conn ───────────────────────────────────────────────────────────────────
QUIC_STATUS QUIC_API Client::Impl::cb_conn(
    HQUIC /*conn*/, void* ctx, QUIC_CONNECTION_EVENT* ev) {
    auto* impl = static_cast<Client::Impl*>(ctx);

    switch (ev->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        impl->open_outbound_streams();
        {
            std::lock_guard<std::mutex> lk(impl->mu);
            impl->connected = true;
        }
        impl->cv.notify_all();
        break;

    // ── Server-initiated streams (WT unidi data or H3 control) ───────────────
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
        bool unidi = (ev->PEER_STREAM_STARTED.Flags &
                      QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL) != 0;
        // We register a lightweight callback that detects the WT unidi
        // stream prefix and routes data to the correct session.
        // Server-initiated bidi streams are not defined in H3, so we use
        // cb_unidi for all peer streams here.
        (void)unidi;
        impl->msquic->SetCallbackHandler(
            ev->PEER_STREAM_STARTED.Stream,
            reinterpret_cast<void*>(cb_unidi), impl);
        break;
    }

    // ── QUIC datagram received — route to WT session ─────────────────────────
    case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED: {
        const uint8_t* buf = ev->DATAGRAM_RECEIVED.Buffer->Buffer;
        uint32_t       len = ev->DATAGRAM_RECEIVED.Buffer->Length;
        uint64_t qsid = 0;
        size_t n = detail::varint_read(buf, len, qsid);
        if (n && n <= len) {
            auto* wi = impl->find_wt_session(qsid * 4);
            if (wi) wi->on_datagram_recv(buf + n, len - n);
        }
        break;
    }

    // ── Datagram send completion — free send buffer ───────────────────────────
    case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
        if (ev->DATAGRAM_SEND_STATE_CHANGED.State == QUIC_DATAGRAM_SEND_SENT ||
            ev->DATAGRAM_SEND_STATE_CHANGED.State == QUIC_DATAGRAM_SEND_CANCELED)
            delete static_cast<WtSession::Impl::SendBuf*>(
                ev->DATAGRAM_SEND_STATE_CHANGED.ClientContext);
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        {
            std::lock_guard<std::mutex> lk(impl->mu);
            impl->connected   = false;
            impl->conn_failed = true;
        }
        impl->cv.notify_all();
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        impl->msquic->ConnectionClose(impl->conn);
        impl->conn = nullptr;
        {
            std::lock_guard<std::mutex> lk(impl->mu);
            impl->connected   = false;
            impl->conn_failed = true;
        }
        impl->cv.notify_all();
        break;

    default: break;
    }
    return QUIC_STATUS_SUCCESS;
}

// ── cb_stream: handles regular HTTP/3 request/response streams ───────────────
QUIC_STATUS QUIC_API Client::Impl::cb_stream(
    HQUIC /*s*/, void* ctx, QUIC_STREAM_EVENT* ev) {
    auto* rs   = static_cast<ReqState*>(ctx);
    auto* impl = rs->client;

    switch (ev->Type) {
    case QUIC_STREAM_EVENT_RECEIVE:
        for (uint32_t i = 0; i < ev->RECEIVE.BufferCount; ++i)
            rs->buf.append(ev->RECEIVE.Buffers[i].Buffer,
                           ev->RECEIVE.Buffers[i].Length);
        for (;;) {
            detail::H3Frame f; size_t pos = 0;
            if (!detail::try_parse_frame(rs->buf.ptr(), rs->buf.size(), pos, f))
                break;
            if (f.type == detail::FRAME_HEADERS && !rs->hdr_done) {
                std::vector<detail::QpackHeader> qh;
                if (!detail::qpack_decode(f.payload, (size_t)f.length, qh)) {
                    rs->fulfill(Result(Error::QpackError)); break;
                }
                for (auto& h : qh) {
                    if (h.name == ":status")
                        rs->resp.status = std::stoi(h.value);
                    else
                        rs->resp.headers.emplace(h.name, h.value);
                }
                rs->hdr_done = true;
            } else if (f.type == detail::FRAME_DATA) {
                rs->resp.body.append(
                    reinterpret_cast<const char*>(f.payload),
                    (size_t)f.length);
            }
            rs->buf.consume(pos);
        }
        break;

    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        delete static_cast<ReqState::SendBuf*>(ev->SEND_COMPLETE.ClientContext);
        break;

    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        if (rs->hdr_done)
            rs->fulfill(Result(std::make_unique<Response>(rs->resp)));
        else
            rs->fulfill(Result(Error::ProtocolError));
        break;

    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        rs->fulfill(Result(Error::Connection));
        break;

    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        impl->msquic->StreamClose(
            ev->SHUTDOWN_COMPLETE.ConnectionShutdown ? nullptr : rs->stream);
        if (!rs->fulfilled)
            rs->fulfill(Result(Error::Connection));
        delete rs;
        break;

    default: break;
    }
    return QUIC_STATUS_SUCCESS;
}

// ── cb_wt_connect: handles the WT CONNECT stream ─────────────────────────────
QUIC_STATUS QUIC_API Client::Impl::cb_wt_connect(
    HQUIC /*s*/, void* ctx, QUIC_STREAM_EVENT* ev) {
    auto* ws   = static_cast<WtConnectState*>(ctx);
    auto* impl = ws->client;

    switch (ev->Type) {
    case QUIC_STREAM_EVENT_RECEIVE:
        for (uint32_t i = 0; i < ev->RECEIVE.BufferCount; ++i)
            ws->buf.append(ev->RECEIVE.Buffers[i].Buffer,
                           ev->RECEIVE.Buffers[i].Length);

        if (!ws->hdr_done) {
            // Parse the server's :status response
            for (;;) {
                detail::H3Frame f; size_t pos = 0;
                if (!detail::try_parse_frame(
                        ws->buf.ptr(), ws->buf.size(), pos, f)) break;

                if (f.type == detail::FRAME_HEADERS) {
                    std::vector<detail::QpackHeader> qh;
                    if (!detail::qpack_decode(f.payload,
                                              (size_t)f.length, qh)) {
                        ws->fulfill(WtResult(WtResult::Error::Protocol));
                        break;
                    }
                    int status = 0;
                    for (auto& h : qh)
                        if (h.name == ":status") status = std::stoi(h.value);

                    ws->buf.consume(pos);

                    if (status == 200) {
                        ws->hdr_done = true;

                        // QUIC stream ID = Session ID
                        uint64_t session_id = 0;
                        uint32_t plen = sizeof(session_id);
                        impl->msquic->GetParam(ws->stream,
                            QUIC_PARAM_STREAM_ID, &plen, &session_id);

                        auto* wi           = new WtSession::Impl{};
                        wi->msquic         = impl->msquic;
                        wi->conn           = impl->conn;
                        wi->connect_stream = ws->stream;
                        wi->session_id     = session_id;

                        impl->register_wt_session(wi);

                        ws->fulfill(WtResult(std::make_unique<WtSession>(
                            std::unique_ptr<WtSession::Impl>(wi))));
                    } else {
                        ws->fulfill(WtResult(WtResult::Error::Rejected));
                    }
                    break; // only one HEADERS frame expected
                }
                ws->buf.consume(pos);
            }
        } else {
            // Post-handshake: parse capsules on the CONNECT stream.
            // Handle WT_CLOSE_SESSION; discard everything else.
            const uint8_t* p   = ws->buf.ptr();
            size_t         rem = ws->buf.size();
            while (rem > 0) {
                uint64_t ctype = 0, clen = 0;
                size_t n1 = detail::varint_read(p, rem, ctype);
                if (!n1) break;
                size_t n2 = detail::varint_read(p + n1, rem - n1, clen);
                if (!n2 || n1 + n2 + clen > rem) break;

                if (ctype == detail::CAPSULE_WT_CLOSE_SESSION && clen >= 4) {
                    uint32_t ec = ((uint32_t)p[n1+n2+0] << 24) |
                                  ((uint32_t)p[n1+n2+1] << 16) |
                                  ((uint32_t)p[n1+n2+2] <<  8) |
                                   (uint32_t)p[n1+n2+3];
                    std::string reason(
                        reinterpret_cast<const char*>(p + n1 + n2 + 4),
                        (size_t)clen - 4);
                    // Look up session and notify
                    uint64_t session_id = 0;
                    uint32_t plen = sizeof(session_id);
                    impl->msquic->GetParam(ws->stream, QUIC_PARAM_STREAM_ID,
                                           &plen, &session_id);
                    auto* wi = impl->find_wt_session(session_id);
                    if (wi) {
                        impl->unregister_wt_session(session_id);
                        wi->on_session_terminated(ec, reason);
                    }
                }
                p   += n1 + n2 + (size_t)clen;
                rem -= n1 + n2 + (size_t)clen;
            }
            ws->buf.consume(ws->buf.size());
        }
        break;

    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        delete static_cast<WtConnectState::SendBuf*>(
            ev->SEND_COMPLETE.ClientContext);
        break;

    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN: {
        // Server closed the CONNECT stream → session terminated
        uint64_t session_id = 0;
        uint32_t plen = sizeof(session_id);
        impl->msquic->GetParam(ws->stream, QUIC_PARAM_STREAM_ID,
                               &plen, &session_id);
        auto* wi = impl->find_wt_session(session_id);
        if (wi) {
            impl->unregister_wt_session(session_id);
            wi->on_session_terminated(0, {});
        }
        if (!ws->fulfilled)
            ws->fulfill(WtResult(WtResult::Error::Connection));
        break;
    }

    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED: {
        uint64_t session_id = 0;
        uint32_t plen = sizeof(session_id);
        impl->msquic->GetParam(ws->stream, QUIC_PARAM_STREAM_ID,
                               &plen, &session_id);
        auto* wi = impl->find_wt_session(session_id);
        if (wi) {
            impl->unregister_wt_session(session_id);
            wi->on_session_terminated(
                (uint32_t)ev->PEER_SEND_ABORTED.ErrorCode, "stream aborted");
        }
        if (!ws->fulfilled)
            ws->fulfill(WtResult(WtResult::Error::Connection));
        break;
    }

    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        impl->msquic->StreamClose(ws->stream);
        if (!ws->fulfilled)
            ws->fulfill(WtResult(WtResult::Error::Connection));
        delete ws;
        break;

    default: break;
    }
    return QUIC_STATUS_SUCCESS;
}

// ── cb_unidi: server-initiated streams (WT unidi + H3 control) ───────────────
QUIC_STATUS QUIC_API Client::Impl::cb_unidi(
    HQUIC s, void* ctx, QUIC_STREAM_EVENT* ev) {
    auto* impl = static_cast<Client::Impl*>(ctx);

    switch (ev->Type) {
    case QUIC_STREAM_EVENT_RECEIVE: {
        std::vector<uint8_t> tmp;
        for (uint32_t i = 0; i < ev->RECEIVE.BufferCount; ++i)
            tmp.insert(tmp.end(),
                       ev->RECEIVE.Buffers[i].Buffer,
                       ev->RECEIVE.Buffers[i].Buffer +
                       ev->RECEIVE.Buffers[i].Length);

        if (tmp.empty()) break;

        uint64_t stream_type = 0;
        size_t n = detail::varint_read(tmp.data(), tmp.size(), stream_type);
        if (!n) break;

        if (stream_type == detail::STREAM_WT_UNIDI) {
            uint64_t sid = 0;
            size_t n2 = detail::varint_read(tmp.data() + n, tmp.size() - n, sid);
            if (!n2) break;
            const uint8_t* data = tmp.data() + n + n2;
            size_t         dlen = tmp.size() - n - n2;
            uint64_t qsid = 0;
            uint32_t plen = sizeof(qsid);
            impl->msquic->GetParam(s, QUIC_PARAM_STREAM_ID, &plen, &qsid);
            auto* wi = impl->find_wt_session(sid);
            if (wi) {
                wi->on_peer_stream(qsid, s, false);
                if (dlen > 0) wi->on_stream_data(qsid, data, dlen);
            }
        }
        // else: H3 control / QPACK — discard
        break;
    }

    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED: {
        uint64_t qsid = 0;
        uint32_t plen = sizeof(qsid);
        impl->msquic->GetParam(s, QUIC_PARAM_STREAM_ID, &plen, &qsid);
        std::lock_guard<std::mutex> lock(impl->wt_mu);
        for (auto& [sid, wi] : impl->wt_sessions)
            wi->on_stream_close(qsid);
        break;
    }

    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        delete static_cast<SendBuf*>(ev->SEND_COMPLETE.ClientContext);
        break;

    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        impl->msquic->StreamClose(s);
        break;

    default: break;
    }
    return QUIC_STATUS_SUCCESS;
}

// ── cb_send (control stream send completion) ──────────────────────────────────
QUIC_STATUS QUIC_API Client::Impl::cb_send(
    HQUIC /*s*/, void* /*ctx*/, QUIC_STREAM_EVENT* ev) {
    if (ev->Type == QUIC_STREAM_EVENT_SEND_COMPLETE)
        delete static_cast<SendBuf*>(ev->SEND_COMPLETE.ClientContext);
    return QUIC_STATUS_SUCCESS;
}

// ── Public Client API ─────────────────────────────────────────────────────────
Client::Client(const std::string& host, uint16_t port)
    : impl_(std::make_unique<Impl>()) {
    impl_->host = host;
    impl_->port = port;
}
Client::~Client() = default;

void Client::enable_server_certificate_verification(bool e) { impl_->verify_cert   = e; }
void Client::set_ca_cert_path(const std::string& p)         { impl_->ca_cert_path  = p; }
void Client::set_connection_timeout(int s)                   { impl_->conn_timeout  = s; }
void Client::set_read_timeout(int s)                         { impl_->read_timeout  = s; }

Result Client::Get    (const std::string& p, const Headers& h)
    { return impl_->do_request("GET",    p, {}, {}, h); }
Result Client::Post   (const std::string& p, const std::string& b,
                        const std::string& ct, const Headers& h)
    { return impl_->do_request("POST",   p, b, ct, h); }
Result Client::Put    (const std::string& p, const std::string& b,
                        const std::string& ct, const Headers& h)
    { return impl_->do_request("PUT",    p, b, ct, h); }
Result Client::Delete (const std::string& p, const std::string& b,
                        const std::string& ct, const Headers& h)
    { return impl_->do_request("DELETE", p, b, ct, h); }
Result Client::Head   (const std::string& p, const Headers& h)
    { return impl_->do_request("HEAD",   p, {}, {}, h); }
Result Client::Options(const std::string& p, const Headers& h)
    { return impl_->do_request("OPTIONS",p, {}, {}, h); }
Result Client::Patch  (const std::string& p, const std::string& b,
                        const std::string& ct, const Headers& h)
    { return impl_->do_request("PATCH",  p, b, ct, h); }

WtResult Client::WebTransport(const std::string& path,
                               const std::string& origin,
                               const Headers&     headers)
    { return impl_->do_webtransport(path, origin, headers); }

} // namespace http3