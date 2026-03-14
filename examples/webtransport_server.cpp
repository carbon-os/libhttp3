#include <http3.h>
#include <http3/webtransport.h>
#include <cinttypes>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

static http3::Server* g_svr = nullptr;
static void on_signal(int) { if (g_svr) g_svr->stop(); }

// ── /echo ─────────────────────────────────────────────────────────────────────
static void wt_echo(webtransport::Session& sess) {
    printf("[echo] session %" PRIu64 " opened\n", sess.session_id());

    // Handle client-initiated bidirectional streams
    sess.on_bidi_stream([](webtransport::BidirectionalStream& s) {
        uint64_t sid = s.id();
        printf("[echo] new bidi stream %" PRIu64 "\n", sid);

        s.on_data([&s, sid](const uint8_t* data, size_t len) {
            printf("[echo] stream %" PRIu64 " rx %zu bytes\n", sid, len);
            bool ok = s.write(data, len);
            printf("[echo] stream %" PRIu64 " echo write=%s\n",
                   sid, ok ? "OK" : "FAILED");
            // FIN our write side now — we have echoed everything
            s.close_write();
        });
        
        s.on_close([sid]() {
            printf("[echo] stream %" PRIu64 " closed\n", sid);
        });
    });

    // Handle client-initiated unidirectional (receive-only) streams
    sess.on_receive_stream([](webtransport::ReceiveStream& s) {
        uint64_t sid = s.id();
        printf("[echo] new receive stream %" PRIu64 "\n", sid);

        s.on_data([sid](const uint8_t* data, size_t len) {
            printf("[echo] stream %" PRIu64 " rx %zu bytes (unidi, cannot echo)\n", sid, len);
        });
        
        s.on_close([sid]() {
            printf("[echo] receive stream %" PRIu64 " closed\n", sid);
        });
    });

    // Handle datagrams
    sess.on_datagram([&sess](const uint8_t* data, size_t len) {
        printf("[echo] datagram rx %zu bytes\n", len);
        sess.send_datagram(data, len);
    });

    sess.on_close([](uint32_t ec, std::string_view reason) {
        printf("[echo] session closed  ec=%u  reason=%.*s\n",
               ec, (int)reason.size(), reason.data());
    });

    sess.wait();
    printf("[echo] session handler returning\n");
}

// ── /chat ─────────────────────────────────────────────────────────────────────
static void wt_chat(webtransport::Session& sess) {
    printf("[chat] session %" PRIu64 " opened\n", sess.session_id());

    // Send a welcome message via a server-initiated unidi stream
    webtransport::SendStream* announce = sess.open_send_stream();
    if (announce) {
        std::string hello = "welcome to /chat";
        announce->write(hello);
        announce->close_write();
    }

    sess.on_bidi_stream([&sess](webtransport::BidirectionalStream& s) {
        uint64_t sid = s.id();
        printf("[chat] peer opened bidi stream %" PRIu64 "\n", sid);

        s.on_data([&sess, &s, sid](const uint8_t* data, size_t len) {
            std::string msg(reinterpret_cast<const char*>(data), len);
            printf("[chat] stream %" PRIu64 " says: %s\n", sid, msg.c_str());
            
            std::string reply = "server heard: " + msg;
            bool ok = s.write(reply);
            printf("[chat] stream %" PRIu64 " reply write=%s\n",
                   sid, ok ? "OK" : "FAILED");
            s.close_write();
            
            // Broadcast via datagram as well
            sess.send_datagram(data, len);
        });
        
        s.on_close([sid]() {
            printf("[chat] bidi stream %" PRIu64 " closed\n", sid);
        });
    });

    sess.on_receive_stream([&sess](webtransport::ReceiveStream& s) {
        uint64_t sid = s.id();
        printf("[chat] peer opened receive stream %" PRIu64 "\n", sid);

        s.on_data([&sess, sid](const uint8_t* data, size_t len) {
            std::string msg(reinterpret_cast<const char*>(data), len);
            printf("[chat] stream %" PRIu64 " says (unidi): %s\n", sid, msg.c_str());
            sess.send_datagram(data, len); // Bounce via datagram
        });

        s.on_close([sid]() {
            printf("[chat] receive stream %" PRIu64 " closed\n", sid);
        });
    });

    sess.on_datagram([&sess](const uint8_t* data, size_t len) {
        printf("[chat] datagram rx %zu bytes — bouncing\n", len);
        sess.send_datagram(data, len);
    });

    sess.on_close([](uint32_t ec, std::string_view reason) {
        printf("[chat] session closed  ec=%u  reason=%.*s\n",
               ec, (int)reason.size(), reason.data());
    });

    sess.wait();
    printf("[chat] session handler returning\n");
}

// ── /stream_test ──────────────────────────────────────────────────────────────
static void wt_stream_test(webtransport::Session& sess) {
    printf("[stream_test] session %" PRIu64 " opened\n", sess.session_id());

    sess.on_close([](uint32_t ec, std::string_view reason) {
        printf("[stream_test] session closed  ec=%u  reason=%.*s\n",
               ec, (int)reason.size(), reason.data());
    });

    for (int i = 0; i < 3; ++i) {
        webtransport::SendStream* s = sess.open_send_stream();
        if (!s) { printf("[stream_test] open_send_stream failed\n"); continue; }
        std::string msg = "unidi stream #" + std::to_string(i);
        s->write(msg);
        s->close_write();
        printf("[stream_test] sent on unidi stream %" PRIu64 ": %s\n",
               s->id(), msg.c_str());
    }

    for (int i = 0; i < 2; ++i) {
        webtransport::BidirectionalStream* s = sess.open_bidi_stream();
        if (!s) { printf("[stream_test] open_bidi_stream failed\n"); continue; }
        uint64_t sid = s->id();
        s->on_data([sid](const uint8_t* data, size_t len) {
            printf("[stream_test] bidi stream %" PRIu64 " echoed: %.*s\n",
                   sid, (int)len, data);
        });
        s->on_close([sid]() {
            printf("[stream_test] bidi stream %" PRIu64 " closed\n", sid);
        });
        std::string msg = "bidi stream #" + std::to_string(i);
        s->write(msg);
        s->close_write();
        printf("[stream_test] sent on bidi stream %" PRIu64 ": %s\n",
               sid, msg.c_str());
    }

    for (int i = 0; i < 5; ++i) {
        std::string dg = "datagram #" + std::to_string(i);
        sess.send_datagram(dg);
        printf("[stream_test] sent datagram: %s\n", dg.c_str());
    }

    sess.wait();
    printf("[stream_test] session handler returning\n");
}

int main(int argc, char* argv[]) {
    const char* cert = (argc > 1) ? argv[1] : "server.crt";
    const char* key  = (argc > 2) ? argv[2] : "server.key";
    uint16_t    port = (argc > 3) ? (uint16_t)std::stoi(argv[3]) : 4433;

    http3::Server svr;
    g_svr = &svr;
    signal(SIGINT, on_signal);

    // Plain HTTP routes alongside WebTransport
    svr.Get("/", [](const http3::Request&, http3::Response& res) {
        res.set_content("WebTransport test server", "text/plain");
    });
    svr.Get("/healthz", [](const http3::Request&, http3::Response& res) {
        res.set_content(R"({"status":"ok"})", "application/json");
    });

    svr.WebTransport("/echo",        wt_echo);
    svr.WebTransport("/chat",        wt_chat);
    svr.WebTransport("/stream_test", wt_stream_test);

    svr.set_error_handler([](const http3::Request& req, http3::Response& res) {
        res.status = 404;
        res.set_content("404 — " + req.path + " not found", "text/plain");
    });

    printf("WebTransport server  cert=%s  key=%s  port=%u\n", cert, key, port);
    printf("  WT paths: /echo  /chat  /stream_test\n");
    svr.listen("0.0.0.0", port, cert, key);
}