#include <http3/http3_server_impl.h>
#include <http3/http3_log.h>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <inttypes.h>
#include <sstream>
#include <thread>
#ifndef _WIN32
#include <unistd.h>
#endif

namespace http3 {

// ── Route pattern compiler ────────────────────────────────────────────────────
// Returns the compiled regex AND the ordered list of :param names found.
static std::pair<std::regex, std::vector<std::string>>
compile_pattern(const std::string& p)
{
    std::vector<std::string> names;
    if (p.find('(') != std::string::npos)
        return {std::regex(p), names};

    std::string re = "^";
    for (size_t i = 0; i < p.size(); ) {
        if (p[i] == ':') {
            size_t j = i + 1;
            while (j < p.size() && (isalnum((unsigned char)p[j]) || p[j] == '_'))
                ++j;
            names.push_back(p.substr(i + 1, j - i - 1));
            re += "([^/]+)";
            i = j;
        } else {
            static const std::string meta = "^$.|?*+()[]{}\\";
            if (meta.find(p[i]) != std::string::npos) re += '\\';
            re += p[i++];
        }
    }
    re += "$";
    return {std::regex(re), names};
}

static Params parse_params(const std::string& qs) {
    Params p;
    std::istringstream ss(qs);
    std::string token;
    while (std::getline(ss, token, '&')) {
        auto eq = token.find('=');
        if (eq == std::string::npos) p.emplace(token, "");
        else                         p.emplace(token.substr(0, eq),
                                               token.substr(eq + 1));
    }
    return p;
}

static std::string now_rfc1123() {
    time_t t = time(nullptr);
    char buf[64];
    strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", gmtime(&t));
    return buf;
}

struct SendBuf { std::vector<uint8_t> data; QUIC_BUFFER qb; };

// ── SrvConnCtx helpers ────────────────────────────────────────────────────────
void SrvConnCtx::register_wt_session(webtransport::Session::Impl* s) {
    std::lock_guard<std::mutex> lk(wt_mu);
    H3LOG_INFO("register_wt_session: id=%" PRIu64, s->session_id);
    wt_sessions[s->session_id] = s;
}
void SrvConnCtx::unregister_wt_session(uint64_t sid) {
    std::lock_guard<std::mutex> lk(wt_mu);
    H3LOG_INFO("unregister_wt_session: id=%" PRIu64, sid);
    wt_sessions.erase(sid);
}
webtransport::Session::Impl* SrvConnCtx::find_wt_session(uint64_t sid) {
    std::lock_guard<std::mutex> lk(wt_mu);
    auto it = wt_sessions.find(sid);
    return it != wt_sessions.end() ? it->second : nullptr;
}

// ── Route management ──────────────────────────────────────────────────────────
void Server::Impl::add_route(const std::string& method,
                              const std::string& pattern, Handler h) {
    std::lock_guard<std::mutex> lk(routes_mu);
    H3LOG_INFO("add_route: %s %s", method.c_str(), pattern.c_str());
    auto [rx, names] = compile_pattern(pattern);
    routes.push_back({method, std::move(rx), std::move(names), std::move(h)});
}

void Server::Impl::add_wt_route(const std::string& pattern, WtHandler h) {
    std::lock_guard<std::mutex> lk(routes_mu);
    H3LOG_INFO("add_wt_route: %s", pattern.c_str());
    auto [rx, names] = compile_pattern(pattern);
    wt_routes.push_back({std::move(rx), std::move(h)});
}

bool Server::Impl::match(const std::string& method, const std::string& path,
                          Route& out, std::smatch& caps) {
    std::lock_guard<std::mutex> lk(routes_mu);
    for (auto& r : routes) {
        if (r.method != method && r.method != "*") continue;
        if (std::regex_match(path, caps, r.pattern)) {
            out = r; return true;
        }
    }
    return false;
}

bool Server::Impl::match_wt(const std::string& path, WtRoute& out) {
    std::lock_guard<std::mutex> lk(routes_mu);
    std::smatch caps;
    for (auto& r : wt_routes) {
        if (std::regex_match(path, caps, r.pattern)) {
            out = r; return true;
        }
    }
    return false;
}

// ── Open server-initiated unidirectional streams ──────────────────────────────
void Server::Impl::open_server_streams(SrvConnCtx* cc) {
    auto open = [&](HQUIC& handle, uint64_t stype, std::vector<uint8_t> extra) {
        if (QUIC_FAILED(msquic->StreamOpen(cc->conn,
                QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL,
                cb_send, this, &handle))) return;
        if (QUIC_FAILED(msquic->StreamStart(handle,
                QUIC_STREAM_START_FLAG_IMMEDIATE))) return;
        std::vector<uint8_t> wire;
        detail::varint_append(wire, stype);
        wire.insert(wire.end(), extra.begin(), extra.end());
        send_unidi(cc, handle, std::move(wire));
    };
    open(cc->ctrl_out, detail::STREAM_CONTROL,       detail::build_settings_frame());
    open(cc->qenc_out, detail::STREAM_QPACK_ENCODER, {});
    open(cc->qdec_out, detail::STREAM_QPACK_DECODER, {});
}

void Server::Impl::send_unidi(SrvConnCtx*, HQUIC s, std::vector<uint8_t> data) {
    auto* sb      = new SendBuf();
    sb->data      = std::move(data);
    sb->qb.Buffer = sb->data.data();
    sb->qb.Length = (uint32_t)sb->data.size();
    if (QUIC_FAILED(msquic->StreamSend(s, &sb->qb, 1,
                                        QUIC_SEND_FLAG_NONE, sb)))
        delete sb;
}

// ── HTTP dispatch ─────────────────────────────────────────────────────────────
void Server::Impl::dispatch(SrvStreamCtx* sc) {
    Route r; std::smatch caps;
    Response resp;
    if (!match(sc->req.method, sc->req.path, r, caps)) {
        if (error_handler) error_handler(sc->req, resp);
        else { resp.status = 404; resp.set_content("Not Found", "text/plain"); }
    } else {
        sc->req.matches = caps;
        // Populate named path params
        sc->req.path_params.clear();
        for (size_t i = 0; i < r.param_names.size() && i + 1 < caps.size(); ++i)
            sc->req.path_params[r.param_names[i]] = caps[(int)(i + 1)].str();
        try { r.handler(sc->req, resp); }
        catch (...) {
            resp.status = 500;
            resp.set_content("Internal Server Error", "text/plain");
        }
    }
    if (!resp.has_header("date"))   resp.set_header("date",   now_rfc1123());
    if (!resp.has_header("server")) resp.set_header("server", "libhttp3/1.0");
    send_response(sc->conn, sc->stream, sc->req, resp);
}

void Server::Impl::send_response(SrvConnCtx*, HQUIC stream,
                                  const Request& req, Response& resp) {
    std::vector<detail::QpackHeader> qh;
    qh.push_back({":status", std::to_string(resp.status)});
    for (auto& [k, v] : resp.headers) qh.push_back({k, v});

    auto qblock = detail::qpack_encode(qh);
    auto wire   = detail::build_frame(detail::FRAME_HEADERS, qblock);

    if (req.method != "HEAD" && !resp.body.empty()) {
        auto df = detail::build_frame(detail::FRAME_DATA,
            reinterpret_cast<const uint8_t*>(resp.body.data()), resp.body.size());
        wire.insert(wire.end(), df.begin(), df.end());
    }
    auto* sb      = new SendBuf();
    sb->data      = std::move(wire);
    sb->qb.Buffer = sb->data.data();
    sb->qb.Length = (uint32_t)sb->data.size();
    if (QUIC_FAILED(msquic->StreamSend(stream, &sb->qb, 1,
                                        QUIC_SEND_FLAG_FIN, sb)))
        delete sb;
}

void Server::Impl::send_wt_accept(HQUIC stream) {
    std::vector<detail::QpackHeader> qh;
    qh.push_back({":status", "200"});
    qh.push_back({"sec-webtransport-http3-draft", "draft02"});
    auto frame  = detail::build_frame(detail::FRAME_HEADERS,
                                       detail::qpack_encode(qh));
    auto* sb      = new SendBuf();
    sb->data      = std::move(frame);
    sb->qb.Buffer = sb->data.data();
    sb->qb.Length = (uint32_t)sb->data.size();
    if (QUIC_FAILED(msquic->StreamSend(stream, &sb->qb, 1,
                                        QUIC_SEND_FLAG_NONE, sb)))
        delete sb;
}

// ── WebTransport CONNECT dispatch ─────────────────────────────────────────────
void Server::Impl::dispatch_wt(SrvStreamCtx* sc) {
    WtRoute wr;
    if (!match_wt(sc->req.path, wr)) {
        Response resp;
        resp.status = 404;
        resp.set_content("WebTransport path not found", "text/plain");
        send_response(sc->conn, sc->stream, sc->req, resp);
        return;
    }
    send_wt_accept(sc->stream);

    uint64_t session_id = sc->quic_stream_id;
    auto* wi           = new webtransport::Session::Impl{};
    wi->msquic         = msquic;
    wi->conn           = sc->conn->conn;
    wi->connect_stream = sc->stream;
    wi->session_id     = session_id;
    
    // Bind cleanup callback to the parent connection context
    wi->unregister_cb  = [cc = sc->conn](uint64_t sid) { cc->unregister_wt_session(sid); };

    sc->conn->register_wt_session(wi);
    sc->kind = SrvStreamCtx::Kind::WtConnect;

    auto sess = std::make_unique<webtransport::Session>(
        std::unique_ptr<webtransport::Session::Impl>(wi));

    std::thread([h = wr.handler, sess = std::move(sess)]() mutable {
        h(*sess);
    }).detach();
}

// ── start() / stop() ──────────────────────────────────────────────────────────
bool Server::Impl::start(const std::string&, uint16_t port,
                          const std::string& cert, const std::string& key,
                          const std::string& alpn) {
    QUIC_STATUS s;
    if (QUIC_FAILED(s = MsQuicOpen2(&msquic))) return false;

    const QUIC_REGISTRATION_CONFIG rc{"libhttp3-server",
                                       QUIC_EXECUTION_PROFILE_LOW_LATENCY};
    if (QUIC_FAILED(msquic->RegistrationOpen(&rc, &reg))) return false;

    QUIC_SETTINGS settings{};
    settings.IdleTimeoutMs               = 30000;
    settings.IsSet.IdleTimeoutMs         = TRUE;
    settings.ServerResumptionLevel       = QUIC_SERVER_RESUME_AND_ZERORTT;
    settings.IsSet.ServerResumptionLevel = TRUE;
    settings.PeerBidiStreamCount         = 512;
    settings.IsSet.PeerBidiStreamCount   = TRUE;
    settings.PeerUnidiStreamCount        = 256;
    settings.IsSet.PeerUnidiStreamCount  = TRUE;
    settings.DatagramReceiveEnabled      = TRUE;
    settings.IsSet.DatagramReceiveEnabled = TRUE;

    QUIC_BUFFER ab{(uint32_t)alpn.size(),
                   reinterpret_cast<uint8_t*>(const_cast<char*>(alpn.c_str()))};
    if (QUIC_FAILED(msquic->ConfigurationOpen(reg, &ab, 1, &settings,
                                               sizeof(settings), nullptr, &config)))
        return false;

    static QUIC_CERTIFICATE_FILE cf{};
    cf.CertificateFile = cert.c_str();
    cf.PrivateKeyFile  = key.c_str();
    QUIC_CREDENTIAL_CONFIG cc{};
    cc.Type            = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    cc.Flags           = QUIC_CREDENTIAL_FLAG_NONE;
    cc.CertificateFile = &cf;
    if (QUIC_FAILED(msquic->ConfigurationLoadCredential(config, &cc))) return false;

    if (QUIC_FAILED(msquic->ListenerOpen(reg, cb_listener, this, &listener)))
        return false;

    QUIC_ADDR addr{};
    QuicAddrSetFamily(&addr, QUIC_ADDRESS_FAMILY_UNSPEC);
    QuicAddrSetPort(&addr, port);
    if (QUIC_FAILED(msquic->ListenerStart(listener, &ab, 1, &addr))) return false;

    running = true;
    return true;
}

void Server::Impl::stop_impl() {
    running = false;
    if (listener) { msquic->ListenerClose(listener);    listener = nullptr; }
    if (config)   { msquic->ConfigurationClose(config); config   = nullptr; }
    if (reg)      { msquic->RegistrationClose(reg);     reg      = nullptr; }
    if (msquic)   { MsQuicClose(msquic);                msquic   = nullptr; }
}

// ── cb_listener ───────────────────────────────────────────────────────────────
QUIC_STATUS QUIC_API Server::Impl::cb_listener(
    HQUIC, void* ctx, QUIC_LISTENER_EVENT* ev)
{
    auto* impl = static_cast<Server::Impl*>(ctx);
    if (ev->Type != QUIC_LISTENER_EVENT_NEW_CONNECTION)
        return QUIC_STATUS_SUCCESS;

    auto* cc   = new SrvConnCtx{};
    cc->msquic = impl->msquic;
    cc->conn   = ev->NEW_CONNECTION.Connection;
    cc->srv    = impl;
    impl->msquic->SetCallbackHandler(cc->conn,
        reinterpret_cast<void*>(cb_conn), cc);
    if (QUIC_FAILED(impl->msquic->ConnectionSetConfiguration(
            cc->conn, impl->config))) {
        delete cc; return QUIC_STATUS_INTERNAL_ERROR;
    }
    return QUIC_STATUS_SUCCESS;
}

// ── cb_conn ───────────────────────────────────────────────────────────────────
QUIC_STATUS QUIC_API Server::Impl::cb_conn(
    HQUIC, void* ctx, QUIC_CONNECTION_EVENT* ev)
{
    auto* cc = static_cast<SrvConnCtx*>(ctx);
    switch (ev->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        cc->srv->open_server_streams(cc);
        cc->srv->msquic->ConnectionSendResumptionTicket(
            cc->conn, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, nullptr);
        break;

    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
        auto* sc       = new SrvStreamCtx{};
        sc->msquic     = cc->srv->msquic;
        sc->stream     = ev->PEER_STREAM_STARTED.Stream;
        sc->is_request = !(ev->PEER_STREAM_STARTED.Flags &
                           QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL);
        sc->conn       = cc;
        sc->kind       = SrvStreamCtx::Kind::Pending;
        uint32_t plen  = sizeof(sc->quic_stream_id);
        cc->srv->msquic->GetParam(sc->stream, QUIC_PARAM_STREAM_ID,
                                   &plen, &sc->quic_stream_id);
        cc->srv->msquic->SetCallbackHandler(sc->stream,
            reinterpret_cast<void*>(cb_stream), sc);
        break;
    }

    case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED: {
        const uint8_t* buf = ev->DATAGRAM_RECEIVED.Buffer->Buffer;
        uint32_t       len = ev->DATAGRAM_RECEIVED.Buffer->Length;
        uint64_t qsid = 0;
        size_t n = detail::varint_read(buf, len, qsid);
        if (n && n <= len) {
            auto* wi = cc->find_wt_session(qsid * 4);
            if (wi) wi->on_datagram_recv(buf + n, len - n);
        }
        break;
    }

    case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
        if (ev->DATAGRAM_SEND_STATE_CHANGED.State == QUIC_DATAGRAM_SEND_SENT ||
            ev->DATAGRAM_SEND_STATE_CHANGED.State == QUIC_DATAGRAM_SEND_CANCELED)
            delete static_cast<webtransport::Session::Impl::SendBuf*>(
                ev->DATAGRAM_SEND_STATE_CHANGED.ClientContext);
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        {
            std::lock_guard<std::mutex> lk(cc->wt_mu);
            for (auto& [sid, wi] : cc->wt_sessions) {
                if (wi) {
                    {
                        std::lock_guard<std::mutex> wilk(wi->mu);
                        wi->unregister_cb = nullptr;
                    }
                    wi->on_session_terminated(0, "connection closed");
                }
            }
            cc->wt_sessions.clear();
        }
        cc->srv->msquic->ConnectionClose(cc->conn);
        delete cc;
        break;

    default: break;
    }
    return QUIC_STATUS_SUCCESS;
}

// ── cb_stream ─────────────────────────────────────────────────────────────────
QUIC_STATUS QUIC_API Server::Impl::cb_stream(
    HQUIC, void* ctx, QUIC_STREAM_EVENT* ev)
{
    auto* sc = static_cast<SrvStreamCtx*>(ctx);

    switch (ev->Type) {
    case QUIC_STREAM_EVENT_RECEIVE: {
        for (uint32_t i = 0; i < ev->RECEIVE.BufferCount; ++i)
            sc->buf.append(ev->RECEIVE.Buffers[i].Buffer,
                           ev->RECEIVE.Buffers[i].Length);

        // ── Detect stream kind ────────────────────────────────────────────────
        if (sc->kind == SrvStreamCtx::Kind::Pending && !sc->buf.empty()) {
            uint64_t first = 0;
            size_t n = detail::varint_read(sc->buf.ptr(), sc->buf.size(), first);
            if (!n) break;

            if (!sc->is_request) {
                if (first == detail::STREAM_WT_UNIDI) {
                    uint64_t sid = 0;
                    size_t n2 = detail::varint_read(sc->buf.ptr() + n,
                                                    sc->buf.size() - n, sid);
                    if (!n2) break;
                    sc->buf.consume(n + n2);
                    sc->kind          = SrvStreamCtx::Kind::WtUnidi;
                    sc->wt_session_id = sid;
                    auto* wi = sc->conn->find_wt_session(sid);
                    if (wi) wi->on_peer_stream(sc->quic_stream_id, sc->stream, false);
                } else {
                    sc->buf.consume(n);
                    sc->kind = SrvStreamCtx::Kind::H3Control;
                }
            } else {
                if (first == detail::FRAME_WEBTRANSPORT_STREAM) {
                    uint64_t sid = 0;
                    size_t n2 = detail::varint_read(sc->buf.ptr() + n,
                                                    sc->buf.size() - n, sid);
                    if (!n2) break;
                    sc->buf.consume(n + n2);
                    sc->kind          = SrvStreamCtx::Kind::WtBidi;
                    sc->wt_session_id = sid;
                    auto* wi = sc->conn->find_wt_session(sid);
                    if (wi) wi->on_peer_stream(sc->quic_stream_id, sc->stream, true);
                } else {
                    sc->kind = SrvStreamCtx::Kind::H3;
                }
            }
        }

        // ── Route data ────────────────────────────────────────────────────────
        if (sc->kind == SrvStreamCtx::Kind::WtBidi ||
            sc->kind == SrvStreamCtx::Kind::WtUnidi) {
            if (!sc->buf.empty()) {
                auto* wi = sc->conn->find_wt_session(sc->wt_session_id);
                if (wi) wi->on_stream_data(sc->quic_stream_id,
                                           sc->buf.ptr(), sc->buf.size());
                sc->buf.consume(sc->buf.size());
            }
            if (ev->RECEIVE.Flags & QUIC_RECEIVE_FLAG_FIN) {
                auto* wi = sc->conn->find_wt_session(sc->wt_session_id);
                if (wi) wi->on_stream_close(sc->quic_stream_id);
            }
            break;
        }

        if (sc->kind == SrvStreamCtx::Kind::H3Control) {
            sc->buf.consume(sc->buf.size()); break;
        }

        if (sc->kind == SrvStreamCtx::Kind::WtConnect) {
            // Parse WT_CLOSE_SESSION capsules
            const uint8_t* p   = sc->buf.ptr();
            size_t         rem = sc->buf.size();
            while (rem > 0) {
                uint64_t ctype = 0, clen = 0;
                size_t n1 = detail::varint_read(p, rem, ctype); if (!n1) break;
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
                    auto* wi = sc->conn->find_wt_session(sc->quic_stream_id);
                    if (wi) {
                        sc->conn->unregister_wt_session(sc->quic_stream_id);
                        wi->on_session_terminated(ec, reason);
                    }
                }
                p   += n1 + n2 + (size_t)clen;
                rem -= n1 + n2 + (size_t)clen;
            }
            sc->buf.consume(sc->buf.size());
            break;
        }

        // ── H3 frame parsing ─────────────────────────────────────────────────
        if (sc->kind == SrvStreamCtx::Kind::H3) {
            for (;;) {
                detail::H3Frame f; size_t pos = 0;
                if (!detail::try_parse_frame(sc->buf.ptr(), sc->buf.size(), pos, f))
                    break;
                if (f.type == detail::FRAME_HEADERS && !sc->hdr_done) {
                    std::vector<detail::QpackHeader> qh;
                    if (!detail::qpack_decode(f.payload, (size_t)f.length, qh)) {
                        sc->conn->msquic->StreamShutdown(sc->stream,
                            QUIC_STREAM_SHUTDOWN_FLAG_ABORT,
                            detail::H3_MESSAGE_ERROR);
                        break;
                    }
                    bool is_wt = false;
                    for (auto& h : qh) {
                        if      (h.name == ":method")   sc->req.method = h.value;
                        else if (h.name == ":protocol")
                            is_wt = (h.value == "webtransport-h3" ||
                                     h.value == "webtransport");
                        else if (h.name == ":path") {
                            auto q = h.value.find('?');
                            if (q == std::string::npos) {
                                sc->req.path = h.value;
                            } else {
                                sc->req.path         = h.value.substr(0, q);
                                sc->req.query_string = h.value.substr(q + 1);
                                sc->req.params = parse_params(sc->req.query_string);
                            }
                        }
                        else if (h.name == ":authority")
                            sc->req.headers.emplace("host", h.value);
                        else if (h.name != ":scheme")
                            sc->req.headers.emplace(h.name, h.value);
                    }
                    sc->hdr_done = true;
                    sc->buf.consume(pos);
                    if (is_wt && sc->req.method == "CONNECT") {
                        sc->conn->srv->dispatch_wt(sc);
                        return QUIC_STATUS_SUCCESS;
                    }
                } else if (f.type == detail::FRAME_DATA) {
                    sc->req.body.append(
                        reinterpret_cast<const char*>(f.payload),
                        (size_t)f.length);
                    sc->buf.consume(pos);
                } else {
                    sc->buf.consume(pos);
                }
            }
        }
        break;
    } // QUIC_STREAM_EVENT_RECEIVE

    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        switch (sc->kind) {
        case SrvStreamCtx::Kind::WtConnect: {
            auto* wi = sc->conn->find_wt_session(sc->quic_stream_id);
            if (wi) {
                sc->conn->unregister_wt_session(sc->quic_stream_id);
                wi->on_session_terminated(0, {});
            }
            break;
        }
        case SrvStreamCtx::Kind::WtBidi: {
            auto* wi = sc->conn->find_wt_session(sc->wt_session_id);
            if (wi) wi->on_stream_close(sc->quic_stream_id);
            sc->msquic->StreamShutdown(sc->stream,
                QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
            break;
        }
        case SrvStreamCtx::Kind::WtUnidi: {
            auto* wi = sc->conn->find_wt_session(sc->wt_session_id);
            if (wi) wi->on_stream_close(sc->quic_stream_id);
            break;
        }
        case SrvStreamCtx::Kind::H3:
        case SrvStreamCtx::Kind::Pending:
            if (sc->is_request && sc->hdr_done) {
                sc->body_done = true;
                sc->conn->srv->dispatch(sc);
            }
            break;
        default: break;
        }
        break;

    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        switch (sc->kind) {
        case SrvStreamCtx::Kind::WtConnect: {
            auto* wi = sc->conn->find_wt_session(sc->quic_stream_id);
            if (wi) {
                sc->conn->unregister_wt_session(sc->quic_stream_id);
                wi->on_session_terminated(
                    (uint32_t)ev->PEER_SEND_ABORTED.ErrorCode, "stream aborted");
            }
            break;
        }
        case SrvStreamCtx::Kind::WtBidi:
        case SrvStreamCtx::Kind::WtUnidi: {
            auto* wi = sc->conn->find_wt_session(sc->wt_session_id);
            if (wi) wi->on_stream_close(sc->quic_stream_id);
            break;
        }
        default:
            sc->conn->msquic->StreamShutdown(sc->stream,
                QUIC_STREAM_SHUTDOWN_FLAG_ABORT, detail::H3_REQUEST_CANCELLED);
            break;
        }
        break;

    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        delete static_cast<SendBuf*>(ev->SEND_COMPLETE.ClientContext);
        break;

    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        if (sc->kind == SrvStreamCtx::Kind::WtBidi || sc->kind == SrvStreamCtx::Kind::WtUnidi) {
            auto* wi = sc->conn->find_wt_session(sc->wt_session_id);
            if (wi) wi->on_stream_shutdown_complete(sc->quic_stream_id);
        }
        sc->conn->msquic->StreamClose(sc->stream);
        delete sc;
        break;

    default: break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API Server::Impl::cb_send(
    HQUIC, void*, QUIC_STREAM_EVENT* ev) {
    if (ev->Type == QUIC_STREAM_EVENT_SEND_COMPLETE)
        delete static_cast<SendBuf*>(ev->SEND_COMPLETE.ClientContext);
    return QUIC_STATUS_SUCCESS;
}

// ── Public Server API ─────────────────────────────────────────────────────────
Server::Server()  : impl_(std::make_unique<Impl>()) {}
Server::~Server() { stop(); }

Server& Server::Get    (const std::string& p, Handler h)
    { impl_->add_route("GET",    p, h); return *this; }
Server& Server::Post   (const std::string& p, Handler h)
    { impl_->add_route("POST",   p, h); return *this; }
Server& Server::Put    (const std::string& p, Handler h)
    { impl_->add_route("PUT",    p, h); return *this; }
Server& Server::Delete (const std::string& p, Handler h)
    { impl_->add_route("DELETE", p, h); return *this; }
Server& Server::Head   (const std::string& p, Handler h)
    { impl_->add_route("HEAD",   p, h); return *this; }
Server& Server::Options(const std::string& p, Handler h)
    { impl_->add_route("OPTIONS",p, h); return *this; }
Server& Server::Patch  (const std::string& p, Handler h)
    { impl_->add_route("PATCH",  p, h); return *this; }
Server& Server::WebTransport(const std::string& p, WtHandler h)
    { impl_->add_wt_route(p, std::move(h)); return *this; }

void Server::set_error_handler(ErrorHandler h)
    { impl_->error_handler = std::move(h); }

bool Server::listen(const std::string& host, uint16_t port,
                    const std::string& cert, const std::string& key,
                    const std::string& alpn) {
    if (!impl_->start(host, port, cert, key, alpn)) return false;
    printf("[http3] listening on :%u  alpn=%s\n", port, alpn.c_str());
    while (impl_->running) {
#ifdef _WIN32
        Sleep(200);
#else
        usleep(200'000);
#endif
    }
    return true;
}

void Server::stop()                      { impl_->stop_impl(); }
bool Server::is_running() const noexcept { return impl_->running.load(); }

} // namespace http3