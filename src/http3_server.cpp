#include <http3/http3_server_impl.h>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <sstream>

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
            while (j < p.size() && (isalnum(p[j]) || p[j]=='_')) ++j;
            re += "([^/]+)"; i = j;
        } else {
            static const std::string meta="^$.|?*+()[]{}\\";
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
        else                         p.emplace(token.substr(0,eq), token.substr(eq+1));
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

void Server::Impl::add_route(const std::string& method,
                              const std::string& pattern, Handler h)
{
    std::lock_guard<std::mutex> lock(routes_mu);
    routes.push_back({ method, compile_pattern(pattern), std::move(h) });
}

bool Server::Impl::match(const std::string& method, const std::string& path,
                          Route& out, std::smatch& caps)
{
    std::lock_guard<std::mutex> lock(routes_mu);
    for (auto& r : routes) {
        if (r.method != method && r.method != "*") continue;
        if (std::regex_match(path, caps, r.pattern)) { out = r; return true; }
    }
    return false;
}

void Server::Impl::open_server_streams(SrvConnCtx* cc)
{
    auto open_unidi = [&](HQUIC& handle, uint64_t stype,
                           std::vector<uint8_t> extra) {
        if (QUIC_FAILED(msquic->StreamOpen(
                cc->conn, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL,
                cb_send, this, &handle))) return;
        if (QUIC_FAILED(msquic->StreamStart(
                handle, QUIC_STREAM_START_FLAG_IMMEDIATE))) return;
        std::vector<uint8_t> wire;
        detail::varint_append(wire, stype);
        wire.insert(wire.end(), extra.begin(), extra.end());
        send_unidi(cc, handle, std::move(wire));
    };
    open_unidi(cc->ctrl_out,  detail::STREAM_CONTROL,       detail::build_settings_frame());
    open_unidi(cc->qenc_out,  detail::STREAM_QPACK_ENCODER, {});
    open_unidi(cc->qdec_out,  detail::STREAM_QPACK_DECODER, {});
}

void Server::Impl::send_unidi(SrvConnCtx* /*cc*/, HQUIC s,
                               std::vector<uint8_t> data)
{
    auto* sb      = new SendBuf();
    sb->data      = std::move(data);
    sb->qb.Buffer = sb->data.data();
    sb->qb.Length = (uint32_t)sb->data.size();
    if (QUIC_FAILED(msquic->StreamSend(s, &sb->qb, 1,
                                        QUIC_SEND_FLAG_NONE, sb)))
        delete sb;
}

void Server::Impl::dispatch(SrvStreamCtx* sc)
{
    Route r; std::smatch caps;
    Response resp;

    if (!match(sc->req.method, sc->req.path, r, caps)) {
        if (error_handler) { error_handler(sc->req, resp); }
        else               { resp.status = 404; resp.set_content("Not Found","text/plain"); }
    } else {
        sc->req.matches = caps;
        try { r.handler(sc->req, resp); }
        catch (...) { resp.status = 500; resp.set_content("Internal Server Error","text/plain"); }
    }
    if (!resp.has_header("date"))   resp.set_header("date",   now_rfc1123());
    if (!resp.has_header("server")) resp.set_header("server", "libhttp3/1.0");

    send_response(sc->conn, sc->stream, sc->req, resp);
}

void Server::Impl::send_response(SrvConnCtx* /*cc*/, HQUIC stream,
                                  const Request& req, Response& resp)
{
    std::vector<detail::QpackHeader> qh;
    qh.push_back({":status", std::to_string(resp.status)});
    for (auto& [k, v] : resp.headers) qh.push_back({k, v});

    auto qblock    = detail::qpack_encode(qh);
    auto hdr_frame = detail::build_frame(detail::FRAME_HEADERS, qblock);
    std::vector<uint8_t> wire = hdr_frame;

    bool has_body = (req.method != "HEAD") && !resp.body.empty();
    if (has_body) {
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

bool Server::Impl::start(const std::string& /*host*/, uint16_t port,
                          const std::string& cert, const std::string& key,
                          const std::string& alpn)
{
    QUIC_STATUS s;
    if (QUIC_FAILED(s = MsQuicOpen2(&msquic))) {
        fprintf(stderr,"[http3] MsQuicOpen2 failed: 0x%x\n",s); return false; }

    const QUIC_REGISTRATION_CONFIG rc{"libhttp3-server",
                                       QUIC_EXECUTION_PROFILE_LOW_LATENCY};
    if (QUIC_FAILED(s = msquic->RegistrationOpen(&rc,&reg))) {
        fprintf(stderr,"[http3] RegistrationOpen failed: 0x%x\n",s); return false; }

    QUIC_SETTINGS settings{};
    settings.IdleTimeoutMs               = 30000; settings.IsSet.IdleTimeoutMs         = TRUE;
    settings.ServerResumptionLevel       = QUIC_SERVER_RESUME_AND_ZERORTT;
    settings.IsSet.ServerResumptionLevel = TRUE;
    settings.PeerBidiStreamCount         = 128;   settings.IsSet.PeerBidiStreamCount   = TRUE;
    settings.PeerUnidiStreamCount        = 3;     settings.IsSet.PeerUnidiStreamCount  = TRUE;

    QUIC_BUFFER ab{ (uint32_t)alpn.size(),
                    reinterpret_cast<uint8_t*>(const_cast<char*>(alpn.c_str())) };

    if (QUIC_FAILED(s = msquic->ConfigurationOpen(
            reg,&ab,1,&settings,sizeof(settings),nullptr,&config))) {
        fprintf(stderr,"[http3] ConfigurationOpen failed: 0x%x\n",s); return false; }

    static QUIC_CERTIFICATE_FILE cf{};
    cf.CertificateFile = cert.c_str();
    cf.PrivateKeyFile  = key.c_str();
    QUIC_CREDENTIAL_CONFIG cc{};
    cc.Type            = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    cc.Flags           = QUIC_CREDENTIAL_FLAG_NONE;
    cc.CertificateFile = &cf;
    if (QUIC_FAILED(s = msquic->ConfigurationLoadCredential(config,&cc))) {
        fprintf(stderr,"[http3] TLS credential failed: 0x%x\n",s); return false; }

    if (QUIC_FAILED(s = msquic->ListenerOpen(reg,cb_listener,this,&listener))) {
        fprintf(stderr,"[http3] ListenerOpen failed: 0x%x\n",s); return false; }

    QUIC_ADDR addr{};
    QuicAddrSetFamily(&addr, QUIC_ADDRESS_FAMILY_UNSPEC);
    QuicAddrSetPort(&addr, port);
    if (QUIC_FAILED(s = msquic->ListenerStart(listener,&ab,1,&addr))) {
        fprintf(stderr,"[http3] ListenerStart failed: 0x%x\n",s); return false; }

    running = true;
    return true;
}

void Server::Impl::stop_impl()
{
    running = false;
    if (listener) { msquic->ListenerClose(listener);     listener = nullptr; }
    if (config)   { msquic->ConfigurationClose(config);  config   = nullptr; }
    if (reg)      { msquic->RegistrationClose(reg);      reg      = nullptr; }
    if (msquic)   { MsQuicClose(msquic);                 msquic   = nullptr; }
}

QUIC_STATUS QUIC_API Server::Impl::cb_listener(
    HQUIC /*lst*/, void* ctx, QUIC_LISTENER_EVENT* ev)
{
    auto* impl = static_cast<Server::Impl*>(ctx);
    if (ev->Type != QUIC_LISTENER_EVENT_NEW_CONNECTION) return QUIC_STATUS_SUCCESS;

    auto* cc = new SrvConnCtx{ impl->msquic,
                                ev->NEW_CONNECTION.Connection, impl, {}, {}, {} };
    impl->msquic->SetCallbackHandler(
        cc->conn, reinterpret_cast<void*>(cb_conn), cc);
    if (QUIC_FAILED(impl->msquic->ConnectionSetConfiguration(
            cc->conn, impl->config))) {
        delete cc; return QUIC_STATUS_INTERNAL_ERROR;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API Server::Impl::cb_conn(
    HQUIC /*conn*/, void* ctx, QUIC_CONNECTION_EVENT* ev)
{
    auto* cc = static_cast<SrvConnCtx*>(ctx);
    switch (ev->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        cc->srv->open_server_streams(cc);
        cc->srv->msquic->ConnectionSendResumptionTicket(
            cc->conn, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, nullptr);
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
        bool unidi = (ev->PEER_STREAM_STARTED.Flags &
                      QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL) != 0;
        auto* sc = new SrvStreamCtx{ cc->srv->msquic,
                                      ev->PEER_STREAM_STARTED.Stream,
                                      !unidi, {}, {}, false, false, cc };
        cc->srv->msquic->SetCallbackHandler(
            sc->stream, reinterpret_cast<void*>(cb_stream), sc);
        break;
    }
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        cc->srv->msquic->ConnectionClose(cc->conn);
        delete cc;
        break;
    default: break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API Server::Impl::cb_stream(
    HQUIC /*s*/, void* ctx, QUIC_STREAM_EVENT* ev)
{
    auto* sc = static_cast<SrvStreamCtx*>(ctx);
    switch (ev->Type) {
    case QUIC_STREAM_EVENT_RECEIVE:
        for (uint32_t i = 0; i < ev->RECEIVE.BufferCount; ++i)
            sc->buf.append(ev->RECEIVE.Buffers[i].Buffer,
                           ev->RECEIVE.Buffers[i].Length);
        if (sc->is_request) {
            for (;;) {
                detail::H3Frame f; size_t pos = 0;
                if (!detail::try_parse_frame(sc->buf.ptr(),sc->buf.size(),pos,f)) break;
                if (f.type == detail::FRAME_HEADERS && !sc->hdr_done) {
                    std::vector<detail::QpackHeader> qh;
                    if (!detail::qpack_decode(f.payload,(size_t)f.length,qh)) {
                        sc->conn->msquic->StreamShutdown(sc->stream,
                            QUIC_STREAM_SHUTDOWN_FLAG_ABORT,
                            detail::H3_MESSAGE_ERROR);
                        break;
                    }
                    for (auto& h : qh) {
                        if      (h.name==":method")    sc->req.method = h.value;
                        else if (h.name==":path")      {
                            auto q = h.value.find('?');
                            if (q==std::string::npos) { sc->req.path=h.value; }
                            else { sc->req.path=h.value.substr(0,q);
                                   sc->req.query_string=h.value.substr(q+1);
                                   sc->req.params=parse_params(sc->req.query_string); }
                        }
                        else if (h.name==":scheme")    sc->req.headers.emplace("scheme",h.value);
                        else if (h.name==":authority") sc->req.headers.emplace("host",h.value);
                        else                           sc->req.headers.emplace(h.name,h.value);
                    }
                    sc->hdr_done = true;
                } else if (f.type == detail::FRAME_DATA) {
                    sc->req.body.append(
                        reinterpret_cast<const char*>(f.payload),(size_t)f.length);
                }
                sc->buf.consume(pos);
            }
        } else {
            sc->buf.consume(sc->buf.size());
        }
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        sc->body_done = true;
        if (sc->is_request && sc->hdr_done)
            sc->conn->srv->dispatch(sc);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        sc->conn->msquic->StreamShutdown(sc->stream,
            QUIC_STREAM_SHUTDOWN_FLAG_ABORT, detail::H3_REQUEST_CANCELLED);
        break;
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        delete static_cast<SendBuf*>(ev->SEND_COMPLETE.ClientContext);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        sc->conn->msquic->StreamClose(sc->stream);
        delete sc;
        break;
    default: break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API Server::Impl::cb_send(
    HQUIC /*s*/, void* /*ctx*/, QUIC_STREAM_EVENT* ev)
{
    if (ev->Type == QUIC_STREAM_EVENT_SEND_COMPLETE)
        delete static_cast<SendBuf*>(ev->SEND_COMPLETE.ClientContext);
    return QUIC_STATUS_SUCCESS;
}

Server::Server()  : impl_(std::make_unique<Impl>()) {}
Server::~Server() { stop(); }

Server& Server::Get    (const std::string& p, Handler h) { impl_->add_route("GET",    p,h); return *this; }
Server& Server::Post   (const std::string& p, Handler h) { impl_->add_route("POST",   p,h); return *this; }
Server& Server::Put    (const std::string& p, Handler h) { impl_->add_route("PUT",    p,h); return *this; }
Server& Server::Delete (const std::string& p, Handler h) { impl_->add_route("DELETE", p,h); return *this; }
Server& Server::Head   (const std::string& p, Handler h) { impl_->add_route("HEAD",   p,h); return *this; }
Server& Server::Options(const std::string& p, Handler h) { impl_->add_route("OPTIONS",p,h); return *this; }
Server& Server::Patch  (const std::string& p, Handler h) { impl_->add_route("PATCH",  p,h); return *this; }

void Server::set_error_handler(ErrorHandler h) { impl_->error_handler = std::move(h); }

bool Server::listen(const std::string& host, uint16_t port,
                    const std::string& cert, const std::string& key,
                    const std::string& alpn)
{
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

void Server::stop()           { impl_->stop_impl(); }
bool Server::is_running() const noexcept { return impl_->running.load(); }

} // namespace http3