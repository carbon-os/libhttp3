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
static std::regex compile_pattern(const std::string& p) {
    if (p.find('(') != std::string::npos) return std::regex(p);
    std::string re = "^";
    for (size_t i = 0; i < p.size(); ) {
        if (p[i] == ':') {
            size_t j = i + 1;
            while (j < p.size() && (isalnum(p[j]) || p[j] == '_')) ++j;
            re += "([^/]+)"; i = j;
        } else {
            static const std::string meta = "^$.|?*+()[]{}\\";
            if (meta.find(p[i]) != std::string::npos) re += '\\';
            re += p[i++];
        }
    }
    re += "$";
    return std::regex(re);
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
void SrvConnCtx::register_wt_session(WtSession::Impl* s) {
    std::lock_guard<std::mutex> lock(wt_mu);
    H3LOG_INFO("register_wt_session: id=%" PRIu64, s->session_id);
    wt_sessions[s->session_id] = s;
}
void SrvConnCtx::unregister_wt_session(uint64_t sid) {
    std::lock_guard<std::mutex> lock(wt_mu);
    H3LOG_INFO("unregister_wt_session: id=%" PRIu64, sid);
    wt_sessions.erase(sid);
}
WtSession::Impl* SrvConnCtx::find_wt_session(uint64_t sid) {
    std::lock_guard<std::mutex> lock(wt_mu);
    auto it = wt_sessions.find(sid);
    if (it != wt_sessions.end()) {
        H3LOG_VERBOSE("find_wt_session: id=%" PRIu64 " FOUND", sid);
        return it->second;
    }
    H3LOG_VERBOSE("find_wt_session: id=%" PRIu64 " NOT FOUND  registered=%zu",
                  sid, wt_sessions.size());
    return nullptr;
}

// ── Route management ──────────────────────────────────────────────────────────
void Server::Impl::add_route(const std::string& method,
                              const std::string& pattern, Handler h) {
    std::lock_guard<std::mutex> lock(routes_mu);
    H3LOG_INFO("add_route: %s %s", method.c_str(), pattern.c_str());
    routes.push_back({ method, compile_pattern(pattern), std::move(h) });
}

void Server::Impl::add_wt_route(const std::string& pattern, WtHandler h) {
    std::lock_guard<std::mutex> lock(routes_mu);
    H3LOG_INFO("add_wt_route: %s", pattern.c_str());
    wt_routes.push_back({ compile_pattern(pattern), std::move(h) });
}

bool Server::Impl::match(const std::string& method, const std::string& path,
                          Route& out, std::smatch& caps) {
    std::lock_guard<std::mutex> lock(routes_mu);
    for (auto& r : routes) {
        if (r.method != method && r.method != "*") continue;
        if (std::regex_match(path, caps, r.pattern)) {
            H3LOG_INFO("match: %s %s → matched", method.c_str(), path.c_str());
            out = r; return true;
        }
    }
    H3LOG_INFO("match: %s %s → no match", method.c_str(), path.c_str());
    return false;
}

bool Server::Impl::match_wt(const std::string& path, WtRoute& out) {
    std::lock_guard<std::mutex> lock(routes_mu);
    std::smatch caps;
    for (auto& r : wt_routes) {
        if (std::regex_match(path, caps, r.pattern)) {
            H3LOG_INFO("match_wt: %s → matched", path.c_str());
            out = r; return true;
        }
    }
    H3LOG_INFO("match_wt: %s → no match", path.c_str());
    return false;
}

// ── Open server-initiated unidirectional streams ──────────────────────────────
void Server::Impl::open_server_streams(SrvConnCtx* cc) {
    H3LOG_INFO("open_server_streams: opening control + qpack enc/dec streams");
    auto open_unidi = [&](HQUIC& handle, uint64_t stype,
                           std::vector<uint8_t> extra) {
        H3LOG_VERBOSE("open_unidi: type=0x%" PRIx64, stype);
        if (QUIC_FAILED(msquic->StreamOpen(
                cc->conn, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL,
                cb_send, this, &handle))) {
            H3LOG_INFO("open_unidi: StreamOpen FAILED  type=0x%" PRIx64, stype);
            return;
        }
        if (QUIC_FAILED(msquic->StreamStart(
                handle, QUIC_STREAM_START_FLAG_IMMEDIATE))) {
            H3LOG_INFO("open_unidi: StreamStart FAILED  type=0x%" PRIx64, stype);
            return;
        }
        std::vector<uint8_t> wire;
        detail::varint_append(wire, stype);
        wire.insert(wire.end(), extra.begin(), extra.end());
        H3LOG_VERBOSE("open_unidi: sending %zu bytes  type=0x%" PRIx64,
                      wire.size(), stype);
        send_unidi(cc, handle, std::move(wire));
    };
    open_unidi(cc->ctrl_out,  detail::STREAM_CONTROL,
               detail::build_settings_frame());
    open_unidi(cc->qenc_out,  detail::STREAM_QPACK_ENCODER, {});
    open_unidi(cc->qdec_out,  detail::STREAM_QPACK_DECODER, {});
    H3LOG_INFO("open_server_streams: done");
}

void Server::Impl::send_unidi(SrvConnCtx* /*cc*/, HQUIC s,
                               std::vector<uint8_t> data) {
    auto* sb      = new SendBuf();
    sb->data      = std::move(data);
    sb->qb.Buffer = sb->data.data();
    sb->qb.Length = (uint32_t)sb->data.size();
    if (QUIC_FAILED(msquic->StreamSend(s, &sb->qb, 1,
                                        QUIC_SEND_FLAG_NONE, sb))) {
        H3LOG_INFO("send_unidi: StreamSend FAILED");
        delete sb;
    }
}

// ── HTTP dispatch ─────────────────────────────────────────────────────────────
void Server::Impl::dispatch(SrvStreamCtx* sc) {
    H3LOG_INFO("dispatch: method=%s  path=%s",
               sc->req.method.c_str(), sc->req.path.c_str());
    Route r; std::smatch caps;
    Response resp;

    if (!match(sc->req.method, sc->req.path, r, caps)) {
        H3LOG_INFO("dispatch: no route — invoking error handler");
        if (error_handler) { error_handler(sc->req, resp); }
        else               { resp.status = 404;
                             resp.set_content("Not Found", "text/plain"); }
    } else {
        sc->req.matches = caps;
        try { r.handler(sc->req, resp); }
        catch (...) {
            H3LOG_INFO("dispatch: handler threw — returning 500");
            resp.status = 500;
            resp.set_content("Internal Server Error", "text/plain");
        }
    }
    if (!resp.has_header("date"))   resp.set_header("date",   now_rfc1123());
    if (!resp.has_header("server")) resp.set_header("server", "libhttp3/1.0");

    H3LOG_INFO("dispatch: sending response  status=%d", resp.status);
    send_response(sc->conn, sc->stream, sc->req, resp);
}

void Server::Impl::send_response(SrvConnCtx* /*cc*/, HQUIC stream,
                                  const Request& req, Response& resp) {
    H3LOG_INFO("send_response: status=%d  body=%zu bytes",
               resp.status, resp.body.size());

    std::vector<detail::QpackHeader> qh;
    qh.push_back({":status", std::to_string(resp.status)});
    for (auto& [k, v] : resp.headers) qh.push_back({k, v});

    auto qblock    = detail::qpack_encode(qh);
    auto hdr_frame = detail::build_frame(detail::FRAME_HEADERS, qblock);
    std::vector<uint8_t> wire = hdr_frame;

    bool has_body = (req.method != "HEAD") && !resp.body.empty();
    if (has_body) {
        H3LOG_VERBOSE("send_response: appending DATA frame  len=%zu",
                      resp.body.size());
        auto df = detail::build_frame(detail::FRAME_DATA,
            reinterpret_cast<const uint8_t*>(resp.body.data()),
            resp.body.size());
        wire.insert(wire.end(), df.begin(), df.end());
    }

    H3LOG_VERBOSE("send_response: total wire=%zu bytes  FIN=1", wire.size());
    auto* sb      = new SendBuf();
    sb->data      = std::move(wire);
    sb->qb.Buffer = sb->data.data();
    sb->qb.Length = (uint32_t)sb->data.size();
    QUIC_STATUS s = msquic->StreamSend(stream, &sb->qb, 1,
                                        QUIC_SEND_FLAG_FIN, sb);
    if (QUIC_FAILED(s)) {
        H3LOG_INFO("send_response: StreamSend FAILED  status=0x%x", s);
        delete sb;
    }
}

// ── WebTransport: send :status 200 without FIN ───────────────────────────────
void Server::Impl::send_wt_accept(HQUIC stream) {
    H3LOG_INFO("send_wt_accept: encoding :status 200 + sec-webtransport-http3-draft");
    std::vector<detail::QpackHeader> qh;
    qh.push_back({":status", "200"});
    qh.push_back({"sec-webtransport-http3-draft", "draft02"});

    auto qblock = detail::qpack_encode(qh);
    H3LOG_VERBOSE("send_wt_accept: qblock=%zu bytes", qblock.size());
    auto frame  = detail::build_frame(detail::FRAME_HEADERS, qblock);
    H3LOG_VERBOSE("send_wt_accept: frame=%zu bytes — sending (no FIN)", frame.size());

    auto* sb      = new SendBuf();
    sb->data      = std::move(frame);
    sb->qb.Buffer = sb->data.data();
    sb->qb.Length = (uint32_t)sb->data.size();
    // Intentionally no QUIC_SEND_FLAG_FIN — CONNECT stream is the session lifeline
    QUIC_STATUS s = msquic->StreamSend(stream, &sb->qb, 1,
                                        QUIC_SEND_FLAG_NONE, sb);
    if (QUIC_FAILED(s)) {
        H3LOG_INFO("send_wt_accept: StreamSend FAILED  status=0x%x", s);
        delete sb;
    } else {
        H3LOG_INFO("send_wt_accept: StreamSend OK");
    }
}

// ── WebTransport CONNECT dispatch ─────────────────────────────────────────────
void Server::Impl::dispatch_wt(SrvStreamCtx* sc) {
    H3LOG_INFO("dispatch_wt: path=%s  qsid=%" PRIu64,
               sc->req.path.c_str(), sc->quic_stream_id);
    WtRoute wr;
    if (!match_wt(sc->req.path, wr)) {
        H3LOG_INFO("dispatch_wt: no route for '%s' — sending 404",
                   sc->req.path.c_str());
        Response resp;
        resp.status = 404;
        resp.set_content("WebTransport path not found", "text/plain");
        send_response(sc->conn, sc->stream, sc->req, resp);
        return;
    }

    H3LOG_INFO("dispatch_wt: route matched — sending 200 accept");
    send_wt_accept(sc->stream);

    uint64_t session_id = sc->quic_stream_id;
    H3LOG_INFO("dispatch_wt: session_id=%" PRIu64, session_id);

    auto* wi           = new WtSession::Impl{};
    wi->msquic         = msquic;
    wi->conn           = sc->conn->conn;
    wi->connect_stream = sc->stream;
    wi->session_id     = session_id;

    sc->conn->register_wt_session(wi);
    sc->kind = SrvStreamCtx::Kind::WtConnect;

    H3LOG_INFO("dispatch_wt: session registered — launching handler thread");
    auto sess = std::make_unique<WtSession>(
        std::unique_ptr<WtSession::Impl>(wi));

    std::thread([h = wr.handler, s = std::move(sess)]() mutable {
        H3LOG_INFO("dispatch_wt: handler thread started  session=%" PRIu64,
                   s->session_id());
        h(*s);
        H3LOG_INFO("dispatch_wt: handler thread exiting  session=%" PRIu64,
                   s->session_id());
    }).detach();
}

// ── start() ──────────────────────────────────────────────────────────────────
bool Server::Impl::start(const std::string& /*host*/, uint16_t port,
                          const std::string& cert, const std::string& key,
                          const std::string& alpn) {
    H3LOG_INFO("start: port=%u  cert=%s  key=%s  alpn=%s",
               port, cert.c_str(), key.c_str(), alpn.c_str());
    QUIC_STATUS s;
    if (QUIC_FAILED(s = MsQuicOpen2(&msquic))) {
        fprintf(stderr, "[http3] MsQuicOpen2 failed: 0x%x\n", s); return false;
    }

    const QUIC_REGISTRATION_CONFIG rc{ "libhttp3-server",
                                        QUIC_EXECUTION_PROFILE_LOW_LATENCY };
    if (QUIC_FAILED(s = msquic->RegistrationOpen(&rc, &reg))) {
        fprintf(stderr, "[http3] RegistrationOpen failed: 0x%x\n", s); return false;
    }

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

    H3LOG_INFO("start: QUIC settings  idle=%ums  bidi=%u  unidi=%u  datagrams=1",
               (unsigned)settings.IdleTimeoutMs,
               (unsigned)settings.PeerBidiStreamCount,
               (unsigned)settings.PeerUnidiStreamCount);

    QUIC_BUFFER ab{ (uint32_t)alpn.size(),
                    reinterpret_cast<uint8_t*>(const_cast<char*>(alpn.c_str())) };

    if (QUIC_FAILED(s = msquic->ConfigurationOpen(
            reg, &ab, 1, &settings, sizeof(settings), nullptr, &config))) {
        fprintf(stderr, "[http3] ConfigurationOpen failed: 0x%x\n", s); return false;
    }

    static QUIC_CERTIFICATE_FILE cf{};
    cf.CertificateFile = cert.c_str();
    cf.PrivateKeyFile  = key.c_str();
    QUIC_CREDENTIAL_CONFIG cc{};
    cc.Type            = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    cc.Flags           = QUIC_CREDENTIAL_FLAG_NONE;
    cc.CertificateFile = &cf;
    if (QUIC_FAILED(s = msquic->ConfigurationLoadCredential(config, &cc))) {
        fprintf(stderr, "[http3] TLS credential failed: 0x%x\n", s); return false;
    }

    if (QUIC_FAILED(s = msquic->ListenerOpen(reg, cb_listener, this, &listener))) {
        fprintf(stderr, "[http3] ListenerOpen failed: 0x%x\n", s); return false;
    }

    QUIC_ADDR addr{};
    QuicAddrSetFamily(&addr, QUIC_ADDRESS_FAMILY_UNSPEC);
    QuicAddrSetPort(&addr, port);
    if (QUIC_FAILED(s = msquic->ListenerStart(listener, &ab, 1, &addr))) {
        fprintf(stderr, "[http3] ListenerStart failed: 0x%x\n", s); return false;
    }

    H3LOG_INFO("start: listening on :%u", port);
    running = true;
    return true;
}

void Server::Impl::stop_impl() {
    H3LOG_INFO("stop_impl");
    running = false;
    if (listener) { msquic->ListenerClose(listener);    listener = nullptr; }
    if (config)   { msquic->ConfigurationClose(config); config   = nullptr; }
    if (reg)      { msquic->RegistrationClose(reg);     reg      = nullptr; }
    if (msquic)   { MsQuicClose(msquic);                msquic   = nullptr; }
}

// ── cb_listener ───────────────────────────────────────────────────────────────
QUIC_STATUS QUIC_API Server::Impl::cb_listener(
    HQUIC /*lst*/, void* ctx, QUIC_LISTENER_EVENT* ev) {
    auto* impl = static_cast<Server::Impl*>(ctx);
    if (ev->Type != QUIC_LISTENER_EVENT_NEW_CONNECTION)
        return QUIC_STATUS_SUCCESS;

    H3LOG_INFO("cb_listener: NEW_CONNECTION");
    auto* cc   = new SrvConnCtx{};
    cc->msquic = impl->msquic;
    cc->conn   = ev->NEW_CONNECTION.Connection;
    cc->srv    = impl;

    impl->msquic->SetCallbackHandler(
        cc->conn, reinterpret_cast<void*>(cb_conn), cc);
    if (QUIC_FAILED(impl->msquic->ConnectionSetConfiguration(
            cc->conn, impl->config))) {
        H3LOG_INFO("cb_listener: ConnectionSetConfiguration FAILED");
        delete cc; return QUIC_STATUS_INTERNAL_ERROR;
    }
    return QUIC_STATUS_SUCCESS;
}

// ── cb_conn ───────────────────────────────────────────────────────────────────
QUIC_STATUS QUIC_API Server::Impl::cb_conn(
    HQUIC /*conn*/, void* ctx, QUIC_CONNECTION_EVENT* ev) {
    auto* cc = static_cast<SrvConnCtx*>(ctx);

    switch (ev->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        H3LOG_INFO("cb_conn: CONNECTED — opening server streams");
        cc->srv->open_server_streams(cc);
        cc->srv->msquic->ConnectionSendResumptionTicket(
            cc->conn, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, nullptr);
        break;

    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
        bool unidi = (ev->PEER_STREAM_STARTED.Flags &
                      QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL) != 0;

        auto* sc       = new SrvStreamCtx{};
        sc->msquic     = cc->srv->msquic;
        sc->stream     = ev->PEER_STREAM_STARTED.Stream;
        sc->is_request = !unidi;
        sc->conn       = cc;
        sc->kind       = SrvStreamCtx::Kind::Pending;

        uint32_t plen = sizeof(sc->quic_stream_id);
        cc->srv->msquic->GetParam(sc->stream, QUIC_PARAM_STREAM_ID,
                                   &plen, &sc->quic_stream_id);
        H3LOG_INFO("cb_conn: PEER_STREAM_STARTED  qsid=%" PRIu64 "  unidi=%d",
                   sc->quic_stream_id, (int)unidi);

        cc->srv->msquic->SetCallbackHandler(
            sc->stream, reinterpret_cast<void*>(cb_stream), sc);
        break;
    }

    case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED: {
        const uint8_t* buf = ev->DATAGRAM_RECEIVED.Buffer->Buffer;
        uint32_t       len = ev->DATAGRAM_RECEIVED.Buffer->Length;
        H3LOG_VERBOSE("cb_conn: DATAGRAM_RECEIVED  len=%u", len);
        uint64_t qsid = 0;
        size_t n = detail::varint_read(buf, len, qsid);
        if (n && n <= len) {
            H3LOG_VERBOSE("cb_conn: datagram  qsid=%" PRIu64
                          "  session_id=%" PRIu64, qsid, qsid * 4);
            auto* wi = cc->find_wt_session(qsid * 4);
            if (wi) wi->on_datagram_recv(buf + n, len - n);
            else H3LOG_INFO("cb_conn: datagram — no session for id=%" PRIu64,
                            qsid * 4);
        } else {
            H3LOG_INFO("cb_conn: datagram — bad qsid varint  len=%u", len);
        }
        break;
    }

    case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
        if (ev->DATAGRAM_SEND_STATE_CHANGED.State == QUIC_DATAGRAM_SEND_SENT ||
            ev->DATAGRAM_SEND_STATE_CHANGED.State == QUIC_DATAGRAM_SEND_CANCELED)
            delete static_cast<WtSession::Impl::SendBuf*>(
                ev->DATAGRAM_SEND_STATE_CHANGED.ClientContext);
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        H3LOG_INFO("cb_conn: SHUTDOWN_COMPLETE");
        cc->srv->msquic->ConnectionClose(cc->conn);
        delete cc;
        break;

    default:
        H3LOG_VERBOSE("cb_conn: event type=%d (ignored)", (int)ev->Type);
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

// ── cb_stream ─────────────────────────────────────────────────────────────────
QUIC_STATUS QUIC_API Server::Impl::cb_stream(
    HQUIC /*s*/, void* ctx, QUIC_STREAM_EVENT* ev) {
    auto* sc = static_cast<SrvStreamCtx*>(ctx);

    switch (ev->Type) {
    case QUIC_STREAM_EVENT_RECEIVE: {
        size_t new_bytes = 0;
        for (uint32_t i = 0; i < ev->RECEIVE.BufferCount; ++i) {
            sc->buf.append(ev->RECEIVE.Buffers[i].Buffer,
                           ev->RECEIVE.Buffers[i].Length);
            new_bytes += ev->RECEIVE.Buffers[i].Length;
        }
        H3LOG_VERBOSE("cb_stream: RECEIVE  qsid=%" PRIu64
                      "  new=%zu  total=%zu  kind=%s",
                      sc->quic_stream_id, new_bytes, sc->buf.size(),
                      detail::stream_kind_str((uint8_t)sc->kind));

        // ── Detect stream kind on first byte(s) ───────────────────────────────
        if (sc->kind == SrvStreamCtx::Kind::Pending) {
            if (sc->buf.empty()) break;

            uint64_t first = 0;
            size_t n = detail::varint_read(sc->buf.ptr(), sc->buf.size(), first);
            if (!n) {
                H3LOG_VERBOSE("cb_stream: Pending — need more bytes for type varint");
                break;
            }
            H3LOG_INFO("cb_stream: first varint=0x%" PRIx64
                       "  is_request=%d  qsid=%" PRIu64,
                       first, (int)sc->is_request, sc->quic_stream_id);

            if (!sc->is_request) {
                if (first == detail::STREAM_WT_UNIDI) {
                    uint64_t sid = 0;
                    size_t n2 = detail::varint_read(sc->buf.ptr() + n,
                                                    sc->buf.size() - n, sid);
                    if (!n2) {
                        H3LOG_VERBOSE("cb_stream: WT_UNIDI need session_id");
                        break;
                    }
                    sc->buf.consume(n + n2);
                    sc->kind          = SrvStreamCtx::Kind::WtUnidi;
                    sc->wt_session_id = sid;
                    H3LOG_INFO("cb_stream: → WtUnidi  session=%" PRIu64, sid);
                    auto* wi = sc->conn->find_wt_session(sid);
                    if (wi) wi->on_peer_stream(sc->quic_stream_id,
                                               sc->stream, false);
                    else H3LOG_INFO("cb_stream: WtUnidi — no session for %" PRIu64,
                                    sid);
                } else {
                    H3LOG_INFO("cb_stream: → H3Control  type=0x%" PRIx64, first);
                    sc->buf.consume(n);
                    sc->kind = SrvStreamCtx::Kind::H3Control;
                }
            } else {
                if (first == detail::FRAME_WEBTRANSPORT_STREAM) {
                    uint64_t sid = 0;
                    size_t n2 = detail::varint_read(sc->buf.ptr() + n,
                                                    sc->buf.size() - n, sid);
                    if (!n2) {
                        H3LOG_VERBOSE("cb_stream: WT_BIDI need session_id");
                        break;
                    }
                    sc->buf.consume(n + n2);
                    sc->kind          = SrvStreamCtx::Kind::WtBidi;
                    sc->wt_session_id = sid;
                    H3LOG_INFO("cb_stream: → WtBidi  session=%" PRIu64, sid);
                    auto* wi = sc->conn->find_wt_session(sid);
                    if (wi) wi->on_peer_stream(sc->quic_stream_id,
                                               sc->stream, true);
                    else H3LOG_INFO("cb_stream: WtBidi — no session for %" PRIu64,
                                    sid);
                } else {
                    H3LOG_INFO("cb_stream: → H3  first_frame=0x%" PRIx64
                               " (%s)  qsid=%" PRIu64,
                               first, detail::frame_type_str(first),
                               sc->quic_stream_id);
                    sc->kind = SrvStreamCtx::Kind::H3;
                }
            }
        }

        // ── Route data based on confirmed kind ────────────────────────────────

        if (sc->kind == SrvStreamCtx::Kind::WtBidi ||
            sc->kind == SrvStreamCtx::Kind::WtUnidi) {
            if (!sc->buf.empty()) {
                auto* wi = sc->conn->find_wt_session(sc->wt_session_id);
                if (wi) wi->on_stream_data(sc->quic_stream_id,
                                           sc->buf.ptr(), sc->buf.size());
                sc->buf.consume(sc->buf.size());
            }

            // FIN delivered together with data via QUIC_RECEIVE_FLAG_FIN.
            // Do NOT call StreamShutdown here — doing so inside the RECEIVE
            // callback causes MsQuic to discard any pending outgoing data
            // (e.g. the echo reply that was just queued above).
            // The application is responsible for calling close_write() after
            // it has finished writing; we only notify the session of the
            // peer's FIN so it can fire on_close callbacks.
            if (ev->RECEIVE.Flags & QUIC_RECEIVE_FLAG_FIN) {
                H3LOG_INFO("cb_stream: RECEIVE+FIN  qsid=%" PRIu64
                           "  kind=%s — notifying session (no auto-FIN)",
                           sc->quic_stream_id,
                           detail::stream_kind_str((uint8_t)sc->kind));
                auto* wi = sc->conn->find_wt_session(sc->wt_session_id);
                if (wi) wi->on_stream_close(sc->quic_stream_id);
            }
            break;
        }

        if (sc->kind == SrvStreamCtx::Kind::H3Control) {
            H3LOG_VERBOSE("cb_stream: H3Control — discarding %zu bytes",
                          sc->buf.size());
            sc->buf.consume(sc->buf.size());
            break;
        }

        if (sc->kind == SrvStreamCtx::Kind::WtConnect) {
            const uint8_t* p   = sc->buf.ptr();
            size_t         rem = sc->buf.size();
            H3LOG_VERBOSE("cb_stream: WtConnect capsule parse  bytes=%zu", rem);
            while (rem > 0) {
                uint64_t ctype = 0, clen = 0;
                size_t n1 = detail::varint_read(p, rem, ctype);
                if (!n1) break;
                size_t n2 = detail::varint_read(p + n1, rem - n1, clen);
                if (!n2 || n1 + n2 + clen > rem) break;
                H3LOG_INFO("cb_stream: capsule  type=0x%" PRIx64
                           "  len=%" PRIu64, ctype, clen);
                if (ctype == detail::CAPSULE_WT_CLOSE_SESSION && clen >= 4) {
                    uint32_t ec = ((uint32_t)p[n1+n2+0] << 24) |
                                  ((uint32_t)p[n1+n2+1] << 16) |
                                  ((uint32_t)p[n1+n2+2] <<  8) |
                                   (uint32_t)p[n1+n2+3];
                    std::string reason(
                        reinterpret_cast<const char*>(p + n1 + n2 + 4),
                        (size_t)clen - 4);
                    H3LOG_INFO("cb_stream: WT_CLOSE_SESSION  ec=%u  reason=%s",
                               ec, reason.c_str());
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

        // ── H3 frame parsing (regular requests) ──────────────────────────────
        if (sc->kind == SrvStreamCtx::Kind::H3) {
            for (;;) {
                detail::H3Frame f; size_t pos = 0;
                if (!detail::try_parse_frame(sc->buf.ptr(),
                                              sc->buf.size(), pos, f)) break;
                H3LOG_INFO("cb_stream: H3 frame  type=0x%" PRIx64 " (%s)"
                           "  len=%" PRIu64 "  qsid=%" PRIu64,
                           f.type, detail::frame_type_str(f.type),
                           f.length, sc->quic_stream_id);

                if (f.type == detail::FRAME_HEADERS && !sc->hdr_done) {
                    std::vector<detail::QpackHeader> qh;
                    if (!detail::qpack_decode(f.payload,
                                              (size_t)f.length, qh)) {
                        H3LOG_INFO("cb_stream: QPACK decode FAILED — aborting");
                        sc->conn->msquic->StreamShutdown(
                            sc->stream,
                            QUIC_STREAM_SHUTDOWN_FLAG_ABORT,
                            detail::H3_MESSAGE_ERROR);
                        break;
                    }
                    bool is_wt_connect = false;
                    for (auto& h : qh) {
                        if      (h.name == ":method") {
                            sc->req.method = h.value;
                            H3LOG_VERBOSE("cb_stream: :method=%s", h.value.c_str());
                        }
                        else if (h.name == ":protocol") {
                            H3LOG_INFO("cb_stream: :protocol=%s", h.value.c_str());
                            if (h.value == "webtransport-h3" ||
                                h.value == "webtransport") {
                                is_wt_connect = true;
                            }
                        }
                        else if (h.name == ":path") {
                            auto q = h.value.find('?');
                            if (q == std::string::npos) {
                                sc->req.path = h.value;
                            } else {
                                sc->req.path         = h.value.substr(0, q);
                                sc->req.query_string = h.value.substr(q + 1);
                                sc->req.params =
                                    parse_params(sc->req.query_string);
                            }
                            H3LOG_VERBOSE("cb_stream: :path=%s", sc->req.path.c_str());
                        }
                        else if (h.name == ":scheme")
                            sc->req.headers.emplace("scheme",    h.value);
                        else if (h.name == ":authority")
                            sc->req.headers.emplace("host",      h.value);
                        else
                            sc->req.headers.emplace(h.name,      h.value);
                    }
                    sc->hdr_done = true;
                    sc->buf.consume(pos);

                    H3LOG_INFO("cb_stream: parsed request  method=%s  path=%s"
                               "  is_wt=%d",
                               sc->req.method.c_str(), sc->req.path.c_str(),
                               (int)is_wt_connect);

                    if (is_wt_connect && sc->req.method == "CONNECT") {
                        H3LOG_INFO("cb_stream: → dispatch_wt");
                        sc->conn->srv->dispatch_wt(sc);
                        return QUIC_STATUS_SUCCESS;
                    }
                } else if (f.type == detail::FRAME_DATA) {
                    H3LOG_VERBOSE("cb_stream: DATA  len=%" PRIu64, f.length);
                    sc->req.body.append(
                        reinterpret_cast<const char*>(f.payload),
                        (size_t)f.length);
                    sc->buf.consume(pos);
                } else {
                    H3LOG_VERBOSE("cb_stream: unknown frame 0x%" PRIx64
                                  " — skipping", f.type);
                    sc->buf.consume(pos);
                }
            }
        }
        break;
    } // QUIC_STREAM_EVENT_RECEIVE

    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        H3LOG_INFO("cb_stream: PEER_SEND_SHUTDOWN  qsid=%" PRIu64 "  kind=%s",
                sc->quic_stream_id,
                detail::stream_kind_str((uint8_t)sc->kind));
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
            // Notify session the peer closed their write side
            auto* wi = sc->conn->find_wt_session(sc->wt_session_id);
            if (wi) wi->on_stream_close(sc->quic_stream_id);
            // Auto-FIN our write side — any queued echo/reply data will flush
            // first, then the FIN is sent. Without this the remote's io.ReadAll
            // never returns.
            H3LOG_INFO("cb_stream: WtBidi PEER_SEND_SHUTDOWN — auto-FIN write side"
                    "  qsid=%" PRIu64, sc->quic_stream_id);
            sc->msquic->StreamShutdown(sc->stream,
                QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
            break;
        }
        case SrvStreamCtx::Kind::WtUnidi: {
            // Unidi — peer closed their only direction, just notify
            auto* wi = sc->conn->find_wt_session(sc->wt_session_id);
            if (wi) wi->on_stream_close(sc->quic_stream_id);
            break;
        }
        case SrvStreamCtx::Kind::H3:
        case SrvStreamCtx::Kind::Pending:
            if (sc->is_request && sc->hdr_done) {
                H3LOG_INFO("cb_stream: dispatching H3  method=%s  path=%s",
                        sc->req.method.c_str(), sc->req.path.c_str());
                sc->body_done = true;
                sc->conn->srv->dispatch(sc);
            } else {
                H3LOG_INFO("cb_stream: PEER_SEND_SHUTDOWN  hdr_done=%d"
                        " is_request=%d — ignoring",
                        (int)sc->hdr_done, (int)sc->is_request);
            }
            break;
        default: break;
        }
        break;

    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        H3LOG_INFO("cb_stream: PEER_SEND_ABORTED  qsid=%" PRIu64
                   "  ec=%" PRIu64 "  kind=%s",
                   sc->quic_stream_id,
                   ev->PEER_SEND_ABORTED.ErrorCode,
                   detail::stream_kind_str((uint8_t)sc->kind));
        switch (sc->kind) {
        case SrvStreamCtx::Kind::WtConnect: {
            auto* wi = sc->conn->find_wt_session(sc->quic_stream_id);
            if (wi) {
                sc->conn->unregister_wt_session(sc->quic_stream_id);
                wi->on_session_terminated(
                    (uint32_t)ev->PEER_SEND_ABORTED.ErrorCode,
                    "stream aborted");
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
                QUIC_STREAM_SHUTDOWN_FLAG_ABORT,
                detail::H3_REQUEST_CANCELLED);
            break;
        }
        break;

    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        H3LOG_VERBOSE("cb_stream: SEND_COMPLETE  qsid=%" PRIu64,
                      sc->quic_stream_id);
        delete static_cast<SendBuf*>(ev->SEND_COMPLETE.ClientContext);
        break;

    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        H3LOG_INFO("cb_stream: SHUTDOWN_COMPLETE  qsid=%" PRIu64,
                   sc->quic_stream_id);
        sc->conn->msquic->StreamClose(sc->stream);
        delete sc;
        break;

    default:
        H3LOG_VERBOSE("cb_stream: event type=%d  qsid=%" PRIu64,
                      (int)ev->Type, sc->quic_stream_id);
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

// ── cb_send (unidirectional control stream send completion) ───────────────────
QUIC_STATUS QUIC_API Server::Impl::cb_send(
    HQUIC /*s*/, void* /*ctx*/, QUIC_STREAM_EVENT* ev) {
    if (ev->Type == QUIC_STREAM_EVENT_SEND_COMPLETE)
        delete static_cast<SendBuf*>(ev->SEND_COMPLETE.ClientContext);
    return QUIC_STATUS_SUCCESS;
}

// ── Public Server API ─────────────────────────────────────────────────────────
Server::Server()  : impl_(std::make_unique<Impl>()) {}
Server::~Server() { stop(); }

Server& Server::Get    (const std::string& p, Handler h) { impl_->add_route("GET",     p, h); return *this; }
Server& Server::Post   (const std::string& p, Handler h) { impl_->add_route("POST",    p, h); return *this; }
Server& Server::Put    (const std::string& p, Handler h) { impl_->add_route("PUT",     p, h); return *this; }
Server& Server::Delete (const std::string& p, Handler h) { impl_->add_route("DELETE",  p, h); return *this; }
Server& Server::Head   (const std::string& p, Handler h) { impl_->add_route("HEAD",    p, h); return *this; }
Server& Server::Options(const std::string& p, Handler h) { impl_->add_route("OPTIONS", p, h); return *this; }
Server& Server::Patch  (const std::string& p, Handler h) { impl_->add_route("PATCH",   p, h); return *this; }

Server& Server::WebTransport(const std::string& p, WtHandler h) {
    impl_->add_wt_route(p, std::move(h)); return *this;
}

void Server::set_error_handler(ErrorHandler h) { impl_->error_handler = std::move(h); }

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