#include <http3/http3_client_impl.h>
#include <cstdio>
#include <cstring>
#include <chrono>

namespace http3 {

struct SendBuf { std::vector<uint8_t> data; QUIC_BUFFER qb; };

Client::Impl::~Impl() {
    disconnect();
    if (msquic) { MsQuicClose(msquic); msquic = nullptr; }
}

void Client::Impl::disconnect() {
    connected   = false;
    conn_failed = false;
    ctrl_out = qenc_out = qdec_out = nullptr;
    if (conn)   { msquic->ConnectionClose(conn);         conn   = nullptr; }
    if (config) { msquic->ConfigurationClose(config);    config = nullptr; }
    if (reg)    { msquic->RegistrationClose(reg);        reg    = nullptr; }
}

bool Client::Impl::ensure_connected() {
    std::unique_lock<std::mutex> lock(mu);
    if (connected) return true;
    if (conn_failed) { conn_failed = false; }

    if (!msquic) {
        QUIC_STATUS s;
        if (QUIC_FAILED(s = MsQuicOpen2(&msquic))) {
            fprintf(stderr,"[http3] MsQuicOpen2 failed: 0x%x\n",s); return false;
        }
        const QUIC_REGISTRATION_CONFIG rc{"libhttp3-client",
                                           QUIC_EXECUTION_PROFILE_LOW_LATENCY};
        if (QUIC_FAILED(s = msquic->RegistrationOpen(&rc,&reg))) {
            MsQuicClose(msquic); msquic=nullptr; return false;
        }

        QUIC_SETTINGS settings{};
        settings.IdleTimeoutMs              = 30000;
        settings.IsSet.IdleTimeoutMs        = TRUE;
        settings.PeerUnidiStreamCount       = 3;
        settings.IsSet.PeerUnidiStreamCount = TRUE;

        const std::string alpn_str = "h3";
        QUIC_BUFFER ab{ (uint32_t)alpn_str.size(),
            reinterpret_cast<uint8_t*>(const_cast<char*>(alpn_str.c_str())) };

        if (QUIC_FAILED(s = msquic->ConfigurationOpen(
                reg,&ab,1,&settings,sizeof(settings),nullptr,&config))) {
            msquic->RegistrationClose(reg); reg=nullptr;
            MsQuicClose(msquic); msquic=nullptr; return false;
        }

        QUIC_CREDENTIAL_CONFIG cred{};
        memset(&cred,0,sizeof(cred));
        cred.Type  = QUIC_CREDENTIAL_TYPE_NONE;
        cred.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
        if (!verify_cert)
            cred.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
        if (!ca_cert_path.empty()) {
            cred.CaCertificateFile = ca_cert_path.c_str();
            cred.Flags |= QUIC_CREDENTIAL_FLAG_SET_CA_CERTIFICATE_FILE;
        }
        if (QUIC_FAILED(s = msquic->ConfigurationLoadCredential(config,&cred))) {
            fprintf(stderr,"[http3] client TLS credential failed: 0x%x\n",s);
            return false;
        }
    }

    QUIC_STATUS s;
    if (QUIC_FAILED(s = msquic->ConnectionOpen(reg, cb_conn, this, &conn))) {
        fprintf(stderr,"[http3] ConnectionOpen failed: 0x%x\n",s); return false;
    }
    if (QUIC_FAILED(s = msquic->ConnectionStart(
            conn, config, QUIC_ADDRESS_FAMILY_UNSPEC, host.c_str(), port))) {
        fprintf(stderr,"[http3] ConnectionStart failed: 0x%x\n",s);
        msquic->ConnectionClose(conn); conn=nullptr; return false;
    }

    bool ok = cv.wait_for(lock, std::chrono::seconds(conn_timeout),
        [this]{ return connected.load() || conn_failed.load(); });
    return ok && connected;
}

void Client::Impl::open_outbound_streams() {
    auto open = [&](HQUIC& handle, uint64_t stype, std::vector<uint8_t> extra) {
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
        if (QUIC_FAILED(msquic->StreamSend(handle,&sb->qb,1,
                                            QUIC_SEND_FLAG_NONE,sb)))
            delete sb;
    };
    open(ctrl_out,  detail::STREAM_CONTROL,       detail::build_settings_frame());
    open(qenc_out,  detail::STREAM_QPACK_ENCODER, {});
    open(qdec_out,  detail::STREAM_QPACK_DECODER, {});
}

Result Client::Impl::do_request(const std::string& method,
                                  const std::string& path,
                                  const std::string& body,
                                  const std::string& content_type,
                                  const Headers&     extra)
{
    if (!ensure_connected()) return Result(Error::Connection);

    std::vector<detail::QpackHeader> qh;
    qh.push_back({":method",    method});
    qh.push_back({":path",      path});
    qh.push_back({":scheme",    "https"});
    qh.push_back({":authority", host + ":" + std::to_string(port)});
    if (!content_type.empty())
        qh.push_back({"content-type", content_type});
    if (!body.empty())
        qh.push_back({"content-length", std::to_string(body.size())});
    for (auto& [k,v] : extra) qh.push_back({k,v});

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
    if (QUIC_FAILED(msquic->StreamSend(stream,&sb->qb,1,
                                        QUIC_SEND_FLAG_FIN, sb))) {
        delete sb; delete rs; return Result(Error::SendFailed);
    }

    if (future.wait_for(std::chrono::seconds(read_timeout))
        != std::future_status::ready)
    {
        msquic->StreamShutdown(stream,QUIC_STREAM_SHUTDOWN_FLAG_ABORT,0);
        return Result(Error::ReadTimeout);
    }
    return future.get();
}

QUIC_STATUS QUIC_API Client::Impl::cb_conn(
    HQUIC /*conn*/, void* ctx, QUIC_CONNECTION_EVENT* ev)
{
    auto* impl = static_cast<Client::Impl*>(ctx);
    switch (ev->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        impl->open_outbound_streams();
        { std::lock_guard<std::mutex> lk(impl->mu);
          impl->connected = true; }
        impl->cv.notify_all();
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        impl->msquic->SetCallbackHandler(
            ev->PEER_STREAM_STARTED.Stream,
            reinterpret_cast<void*>(cb_unidi), impl);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        { std::lock_guard<std::mutex> lk(impl->mu);
          impl->connected   = false;
          impl->conn_failed = true; }
        impl->cv.notify_all();
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        impl->msquic->ConnectionClose(impl->conn);
        impl->conn = nullptr;
        { std::lock_guard<std::mutex> lk(impl->mu);
          impl->connected   = false;
          impl->conn_failed = true; }
        impl->cv.notify_all();
        break;
    default: break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API Client::Impl::cb_stream(
    HQUIC /*s*/, void* ctx, QUIC_STREAM_EVENT* ev)
{
    auto* rs   = static_cast<ReqState*>(ctx);
    auto* impl = rs->client;

    switch (ev->Type) {
    case QUIC_STREAM_EVENT_RECEIVE:
        for (uint32_t i = 0; i < ev->RECEIVE.BufferCount; ++i)
            rs->buf.append(ev->RECEIVE.Buffers[i].Buffer,
                           ev->RECEIVE.Buffers[i].Length);
        for (;;) {
            detail::H3Frame f; size_t pos = 0;
            if (!detail::try_parse_frame(rs->buf.ptr(),rs->buf.size(),pos,f)) break;
            if (f.type == detail::FRAME_HEADERS && !rs->hdr_done) {
                std::vector<detail::QpackHeader> qh;
                if (!detail::qpack_decode(f.payload,(size_t)f.length,qh)) {
                    rs->fulfill(Result(Error::QpackError)); break;
                }
                for (auto& h : qh) {
                    if (h.name==":status") rs->resp.status = std::stoi(h.value);
                    else                   rs->resp.headers.emplace(h.name,h.value);
                }
                rs->hdr_done = true;
            } else if (f.type == detail::FRAME_DATA) {
                rs->resp.body.append(
                    reinterpret_cast<const char*>(f.payload),(size_t)f.length);
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
        impl->msquic->StreamClose(ev->SHUTDOWN_COMPLETE.ConnectionShutdown ?
                                    nullptr : rs->stream);
        if (!rs->fulfilled)
            rs->fulfill(Result(Error::Connection));
        delete rs;
        break;
    default: break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API Client::Impl::cb_unidi(
    HQUIC /*s*/, void* /*ctx*/, QUIC_STREAM_EVENT* /*ev*/)
{
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API Client::Impl::cb_send(
    HQUIC /*s*/, void* /*ctx*/, QUIC_STREAM_EVENT* ev)
{
    if (ev->Type == QUIC_STREAM_EVENT_SEND_COMPLETE)
        delete static_cast<SendBuf*>(ev->SEND_COMPLETE.ClientContext);
    return QUIC_STATUS_SUCCESS;
}

Client::Client(const std::string& host, uint16_t port)
    : impl_(std::make_unique<Impl>())
{
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

} // namespace http3