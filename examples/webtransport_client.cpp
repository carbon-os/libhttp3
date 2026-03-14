#include <http3.h>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <chrono>
#include <mutex>
#include <condition_variable>
#include <string>
#include <thread>

// ── Small helper: blocks until a condition or timeout ─────────────────────────
struct Gate {
    std::mutex              mu;
    std::condition_variable cv;
    bool                    fired{false};

    void signal() {
        std::lock_guard<std::mutex> lk(mu);
        fired = true;
        cv.notify_all();
    }
    bool wait_for(int ms) {
        std::unique_lock<std::mutex> lk(mu);
        return cv.wait_for(lk, std::chrono::milliseconds(ms),
                           [this]{ return fired; });
    }
};

// ── Test 1: /echo — send data on a bidi stream, expect it back ────────────────
static void test_echo(http3::Client& cli) {
    printf("\n=== test_echo ===\n");

    auto wtr = cli.WebTransport("/echo");
    if (!wtr) {
        printf("FAIL: could not open /echo session\n"); return;
    }
    http3::WtSession& sess = *wtr;
    printf("session_id=%" PRIu64 "\n", sess.session_id());

    // ── bidi stream round-trip ────────────────────────────────────────────────
    {
        Gate rx_gate;
        std::string received;

        http3::WtStream* s = sess.open_bidi_stream();
        if (!s) { printf("FAIL: open_bidi_stream\n"); return; }

        s->on_data([&](const uint8_t* data, size_t len) {
            received.assign(reinterpret_cast<const char*>(data), len);
            printf("[echo/bidi] rx: %s\n", received.c_str());
            rx_gate.signal();
        });
        s->on_close([&]() { printf("[echo/bidi] stream closed\n"); });

        const std::string payload = "hello-webtransport";
        s->write(payload);
        printf("[echo/bidi] sent: %s\n", payload.c_str());

        if (!rx_gate.wait_for(5000))
            printf("FAIL: bidi echo timed out\n");
        else if (received == payload)
            printf("PASS: bidi echo matched\n");
        else
            printf("FAIL: expected '%s' got '%s'\n",
                   payload.c_str(), received.c_str());

        s->close_write();
    }

    // ── datagram round-trip ───────────────────────────────────────────────────
    {
        Gate dg_gate;
        std::string dg_received;

        sess.on_datagram([&](const uint8_t* data, size_t len) {
            dg_received.assign(reinterpret_cast<const char*>(data), len);
            printf("[echo/datagram] rx: %s\n", dg_received.c_str());
            dg_gate.signal();
        });

        const std::string dg = "datagram-ping";
        sess.send_datagram(dg);
        printf("[echo/datagram] sent: %s\n", dg.c_str());

        if (!dg_gate.wait_for(5000))
            printf("FAIL: datagram echo timed out\n");
        else if (dg_received == dg)
            printf("PASS: datagram echo matched\n");
        else
            printf("FAIL: expected '%s' got '%s'\n",
                   dg.c_str(), dg_received.c_str());
    }

    sess.close(0, "test_echo done");
    printf("[echo] session closed by client\n");
}

// ── Test 2: /chat — open bidi stream, send a message, read reply ──────────────
static void test_chat(http3::Client& cli) {
    printf("\n=== test_chat ===\n");

    auto wtr = cli.WebTransport("/chat");
    if (!wtr) {
        printf("FAIL: could not open /chat session\n"); return;
    }
    http3::WtSession& sess = *wtr;
    printf("session_id=%" PRIu64 "\n", sess.session_id());

    Gate stream_gate;   // fires when server sends the welcome unidi stream
    Gate reply_gate;    // fires when server echoes our message
    std::string welcome_msg;
    std::string reply_msg;

    // Server will push a unidi stream with "welcome to /chat"
    sess.on_stream([&](http3::WtStream& s) {
        printf("[chat] server opened %s stream %" PRIu64 "\n",
               s.is_bidi() ? "bidi" : "unidi", s.id());
        s.on_data([&](const uint8_t* data, size_t len) {
            welcome_msg.assign(reinterpret_cast<const char*>(data), len);
            printf("[chat] welcome msg: %s\n", welcome_msg.c_str());
            stream_gate.signal();
        });
        s.on_close([&s]() {
            printf("[chat] server stream %" PRIu64 " closed\n", s.id());
        });
    });

    // Datagram callback — server bounces datagrams
    sess.on_datagram([&](const uint8_t* data, size_t len) {
        std::string dg(reinterpret_cast<const char*>(data), len);
        printf("[chat] datagram rx: %s\n", dg.c_str());
    });

    // Open a bidi stream and send a message
    http3::WtStream* s = sess.open_bidi_stream();
    if (!s) { printf("FAIL: open_bidi_stream\n"); return; }

    s->on_data([&](const uint8_t* data, size_t len) {
        reply_msg.assign(reinterpret_cast<const char*>(data), len);
        printf("[chat] server reply: %s\n", reply_msg.c_str());
        reply_gate.signal();
    });
    s->on_close([&s]() {
        printf("[chat] bidi stream %" PRIu64 " closed\n", s->id());
    });

    const std::string msg = "hi from client";
    s->write(msg);
    printf("[chat] sent: %s\n", msg.c_str());

    // Wait for welcome unidi stream
    if (stream_gate.wait_for(5000))
        printf("PASS: received welcome stream\n");
    else
        printf("WARN: no welcome stream received\n");

    // Wait for bidi reply
    if (reply_gate.wait_for(5000))
        printf("PASS: received bidi reply\n");
    else
        printf("FAIL: bidi reply timed out\n");

    s->close_write();
    sess.close(0, "test_chat done");
    printf("[chat] session closed by client\n");
}

// ── Test 3: /stream_test — receive server-initiated streams and datagrams ─────
static void test_stream_test(http3::Client& cli) {
    printf("\n=== test_stream_test ===\n");

    auto wtr = cli.WebTransport("/stream_test");
    if (!wtr) {
        printf("FAIL: could not open /stream_test session\n"); return;
    }
    http3::WtSession& sess = *wtr;
    printf("session_id=%" PRIu64 "\n", sess.session_id());

    std::mutex       count_mu;
    int              unidi_count{0};
    int              bidi_count{0};
    int              datagram_count{0};

    sess.on_stream([&](http3::WtStream& s) {
        bool bidi = s.is_bidi();
        printf("[stream_test] server opened %s stream %" PRIu64 "\n",
               bidi ? "bidi" : "unidi", s.id());

        s.on_data([&, bidi, &s](const uint8_t* data, size_t len) {
            std::string msg(reinterpret_cast<const char*>(data), len);
            printf("[stream_test] stream %" PRIu64 " rx: %s\n", s.id(), msg.c_str());
            if (bidi) {
                // Echo back so server can verify
                s.write(data, len);
            }
        });
        s.on_close([&, bidi]() {
            std::lock_guard<std::mutex> lk(count_mu);
            if (bidi) ++bidi_count; else ++unidi_count;
            printf("[stream_test] stream closed  unidi=%d bidi=%d\n",
                   unidi_count, bidi_count);
        });
    });

    sess.on_datagram([&](const uint8_t* data, size_t len) {
        std::string dg(reinterpret_cast<const char*>(data), len);
        printf("[stream_test] datagram rx: %s\n", dg.c_str());
        std::lock_guard<std::mutex> lk(count_mu);
        ++datagram_count;
    });

    sess.on_close([](uint32_t ec, std::string reason) {
        printf("[stream_test] session closed  ec=%u  reason=%s\n",
               ec, reason.c_str());
    });

    // Give the server time to push all streams and datagrams
    std::this_thread::sleep_for(std::chrono::seconds(3));

    {
        std::lock_guard<std::mutex> lk(count_mu);
        printf("RESULT: unidi_streams=%d (expected 3)  "
               "bidi_streams=%d (expected 2)  "
               "datagrams=%d (expected 5)\n",
               unidi_count, bidi_count, datagram_count);
    }

    sess.close(0, "test_stream_test done");
    printf("[stream_test] session closed by client\n");
}

// ── Test 4: rejected path ─────────────────────────────────────────────────────
static void test_rejected(http3::Client& cli) {
    printf("\n=== test_rejected ===\n");

    auto wtr = cli.WebTransport("/does-not-exist");
    if (!wtr) {
        printf("PASS: /does-not-exist correctly rejected  error=%d\n",
               (int)wtr.error());
    } else {
        printf("FAIL: expected rejection, got session %" PRIu64 "\n",
               wtr->session_id());
        wtr->close();
    }
}

int main(int argc, char* argv[]) {
    const char* host = (argc > 1) ? argv[1] : "localhost";
    uint16_t    port = (argc > 2) ? (uint16_t)std::stoi(argv[2]) : 4433;

    printf("WebTransport client  host=%s  port=%u\n", host, port);

    http3::Client cli(host, port);
    cli.enable_server_certificate_verification(false);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(10);

    // Verify plain HTTP still works on the same connection
    printf("\n=== plain HTTP sanity check ===\n");
    {
        auto res = cli.Get("/healthz");
        if (res)
            printf("PASS: GET /healthz  status=%d  body=%s\n",
                   res->status, res->body.c_str());
        else
            printf("FAIL: GET /healthz  error=%s\n",
                   http3::to_string(res.error()));
    }

    test_echo(cli);
    test_chat(cli);
    test_stream_test(cli);
    test_rejected(cli);

    printf("\nAll tests done.\n");
    return 0;
}