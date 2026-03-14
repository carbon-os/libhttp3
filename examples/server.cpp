#include <http3.h>
#include <csignal>
#include <cstdio>
#include <thread>

static http3::Server* g_svr = nullptr;
static void on_signal(int) { if (g_svr) g_svr->stop(); }

int main(int argc, char* argv[]) {
    const char* cert = (argc>1) ? argv[1] : "server.crt";
    const char* key  = (argc>2) ? argv[2] : "server.key";
    uint16_t    port = (argc>3) ? (uint16_t)std::stoi(argv[3]) : 4433;

    http3::Server svr;
    g_svr = &svr;
    signal(SIGINT, on_signal);

    svr.Get("/", [](const http3::Request&, http3::Response& res) {
        res.set_content("Hello from libhttp3!", "text/plain");
    });

    svr.Get("/healthz", [](const http3::Request&, http3::Response& res) {
        res.set_content(R"({"status":"ok"})", "application/json");
    });

    svr.Get("/users/:id", [](const http3::Request& req, http3::Response& res) {
        res.set_content("User: " + req.matches[1].str(), "text/plain");
    });

    svr.Get(R"(/numbers/(\d+))", [](const http3::Request& req, http3::Response& res) {
        res.set_content("Number: " + req.matches[1].str(), "text/plain");
    });

    svr.Get("/echo", [](const http3::Request& req, http3::Response& res) {
        std::string body;
        if (req.has_param("msg"))
            body = req.get_param_value("msg");
        else if (!req.body.empty())
            body = req.body;
        else
            body = "(empty)";
        res.set_content(body, "text/plain");
    });

    svr.Post("/echo", [](const http3::Request& req, http3::Response& res) {
        res.set_content(req.body, req.get_header_value("content-type", "text/plain"));
    });

    svr.Get("/headers", [](const http3::Request& req, http3::Response& res) {
        std::string json = "{\n";
        bool first = true;
        for (auto& [k,v] : req.headers) {
            if (!first) json += ",\n";
            json += "  \"" + k + "\": \"" + v + "\"";
            first = false;
        }
        json += "\n}";
        res.set_content(json, "application/json");
    });

    svr.Get("/large", [](const http3::Request&, http3::Response& res) {
        res.set_content(std::string(65536, 'A'), "text/plain");
    });

    svr.Post("/data", [](const http3::Request& req, http3::Response& res) {
        res.set_content("received " + std::to_string(req.body.size()) + " bytes",
                        "text/plain");
    });

    svr.Get("/stop", [&](const http3::Request&, http3::Response& res) {
        res.set_content("stopping", "text/plain");
        std::thread([&]{ svr.stop(); }).detach();
    });

    svr.set_error_handler([](const http3::Request& req, http3::Response& res) {
        res.status = 404;
        res.set_content("404 — " + req.path + " not found", "text/plain");
    });

    printf("libhttp3 server  cert=%s  key=%s  port=%u\n", cert, key, port);
    svr.listen("0.0.0.0", port, cert, key);
}