#include <http3.h>
#include <http3/webtransport.h>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <chrono>
#include <mutex>
#include <condition_variable>
#include <string>
#include <thread>

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

static void test_echo(http3::Client& cli) {
    printf("\n=== test_echo ===\n");

    auto wtr = cli.WebTransport("/echo");
    if (!wtr) { printf("FAIL: could not open /echo session\n"); return; }
    webtransport::Session& sess = *wtr;
    printf("session_id=%" PRIu64 "\n", sess.session_id());

    {
        Gate rx_gate;
        std::string received;

        webtransport::BidirectionalStream* s = sess.open_bidi_stream();
        if (!s) { printf("FAIL: open_bidi_stream\n"); return; }

        uint64_t sid = s->id(); // Extract ID now!
        s->on_data([&](const uint8_t* data, size_t len) {
            received.assign(reinterpret_cast<const char*>(data), len);
            printf("[echo/bidi] rx: %s\n", received.c_str());
            rx_gate.signal();
        });
        
        // BUG FIX: Capture sid by value. Capturing pointer 's' by reference is 
        // a dangling pointer trap once `test_echo` returns.
        s->on_close([sid]() { 
            printf("[echo/bidi] stream %" PRIu64 " closed\n", sid); 
        });

        const std::string payload = "hello-webtransport";
        s->write(payload);
        printf("[echo/bidi] sent: %s\n", payload.c_str());

        if (!rx_gate.wait_for(5000)) printf("FAIL: bidi echo timed out\n");
        else if (received == payload) printf("PASS: bidi echo matched\n");
        s->close_write();
    }

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

        if (!dg_gate.wait_for(5000)) printf("FAIL: datagram echo timed out\n");
        else if (dg_received == dg) printf("PASS: datagram echo matched\n");
    }

    sess.close(0, "test_echo done");
    printf("[echo] session closed by client\n");
}

static void test_chat(http3::Client& cli) {
    printf("\n=== test_chat ===\n");

    auto wtr = cli.WebTransport("/chat");
    if (!wtr) { printf("FAIL: could not open /chat session\n"); return; }
    webtransport::Session& sess = *wtr;
    printf("session_id=%" PRIu64 "\n", sess.session_id());

    Gate stream_gate, reply_gate;
    std::string welcome_msg, reply_msg;

    sess.on_receive_stream([&](webtransport::ReceiveStream& s) {
        uint64_t sid = s.id();
        printf("[chat] server opened receive stream %" PRIu64 "\n", sid);
        s.on_data([&](const uint8_t* data, size_t len) {
            welcome_msg.assign(reinterpret_cast<const char*>(data), len);
            printf("[chat] welcome msg: %s\n", welcome_msg.c_str());
            stream_gate.signal();
        });
        s.on_close([sid]() { printf("[chat] server receive stream %" PRIu64 " closed\n", sid); });
    });

    sess.on_datagram([&](const uint8_t* data, size_t len) {
        std::string dg(reinterpret_cast<const char*>(data), len);
        printf("[chat] datagram rx: %s\n", dg.c_str());
    });

    webtransport::BidirectionalStream* s = sess.open_bidi_stream();
    if (!s) { printf("FAIL: open_bidi_stream\n"); return; }

    uint64_t sid = s->id();
    s->on_data([&](const uint8_t* data, size_t len) {
        reply_msg.assign(reinterpret_cast<const char*>(data), len);
        printf("[chat] server reply: %s\n", reply_msg.c_str());
        reply_gate.signal();
    });
    s->on_close([sid]() { printf("[chat] bidi stream %" PRIu64 " closed\n", sid); });

    const std::string msg = "hi from client";
    s->write(msg);
    printf("[chat] sent: %s\n", msg.c_str());

    if (stream_gate.wait_for(5000)) printf("PASS: received welcome stream\n");
    if (reply_gate.wait_for(5000)) printf("PASS: received bidi reply\n");

    s->close_write();
    sess.close(0, "test_chat done");
    printf("[chat] session closed by client\n");
}

static void test_stream_test(http3::Client& cli) {
    printf("\n=== test_stream_test ===\n");

    auto wtr = cli.WebTransport("/stream_test");
    if (!wtr) { printf("FAIL: could not open /stream_test session\n"); return; }
    webtransport::Session& sess = *wtr;
    printf("session_id=%" PRIu64 "\n", sess.session_id());

    std::mutex count_mu;
    int unidi_count{0}, bidi_count{0}, datagram_count{0};

    sess.on_bidi_stream([&](webtransport::BidirectionalStream& s) {
        uint64_t sid = s.id();
        printf("[stream_test] server opened bidi stream %" PRIu64 "\n", sid);
        s.on_data([&s](const uint8_t* data, size_t len) { s.write(data, len); });
        s.on_close([&, sid]() {
            std::lock_guard<std::mutex> lk(count_mu); ++bidi_count;
        });
    });

    sess.on_receive_stream([&](webtransport::ReceiveStream& s) {
        uint64_t sid = s.id();
        printf("[stream_test] server opened receive stream %" PRIu64 "\n", sid);
        s.on_data([](const uint8_t*, size_t) {});
        s.on_close([&, sid]() {
            std::lock_guard<std::mutex> lk(count_mu); ++unidi_count;
        });
    });

    sess.on_datagram([&](const uint8_t* data, size_t len) {
        std::string dg(reinterpret_cast<const char*>(data), len);
        printf("[stream_test] datagram rx: %s\n", dg.c_str());
        std::lock_guard<std::mutex> lk(count_mu); ++datagram_count;
    });

    sess.on_close([](uint32_t ec, std::string_view reason) {
        printf("[stream_test] session closed  ec=%u  reason=%.*s\n", ec, (int)reason.size(), reason.data());
    });

    std::this_thread::sleep_for(std::chrono::seconds(3));
    {
        std::lock_guard<std::mutex> lk(count_mu);
        printf("RESULT: unidi_streams=%d  bidi_streams=%d  datagrams=%d\n", unidi_count, bidi_count, datagram_count);
    }
    sess.close(0, "test_stream_test done");
}

int main(int argc, char* argv[]) {
    const char* host = (argc > 1) ? argv[1] : "localhost";
    uint16_t    port = (argc > 2) ? (uint16_t)std::stoi(argv[2]) : 4433;

    http3::Client cli(host, port);
    cli.enable_server_certificate_verification(false);
    cli.set_connection_timeout(5); cli.set_read_timeout(10);

    test_echo(cli);
    test_chat(cli);
    test_stream_test(cli);
    printf("\nAll tests done.\n");
    return 0;
}