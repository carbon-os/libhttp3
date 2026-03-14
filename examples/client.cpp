#include <http3.h>
#include <cstdio>
#include <string>

static void print_result(const char* label, http3::Result& res) {
    if (res) {
        printf("[%s]  status=%d  body_len=%zu  body=%.80s\n",
               label, res->status, res->body.size(), res->body.c_str());
    } else {
        printf("[%s]  ERROR: %s\n", label, http3::to_string(res.error()));
    }
}

int main(int argc, char* argv[]) {
    const char* host = (argc>1) ? argv[1] : "localhost";
    uint16_t    port = (argc>2) ? (uint16_t)std::stoi(argv[2]) : 4433;

    http3::Client cli(host, port);
    cli.enable_server_certificate_verification(false);

    { auto res = cli.Get("/");         print_result("GET /", res); }
    { auto res = cli.Get("/healthz");  print_result("GET /healthz", res); }

    { auto res = cli.Get("/echo?msg=hello-quic");
      print_result("GET /echo?msg=", res); }

    { auto res = cli.Post("/echo", R"({"hello":"world"})", "application/json");
      print_result("POST /echo", res); }

    { http3::Headers h;
      h.emplace("x-request-id", "abc-123");
      h.emplace("accept",       "application/json");
      auto res = cli.Get("/headers", h);
      print_result("GET /headers", res); }

    { auto res = cli.Get("/large");
      printf("[GET /large]  status=%d  body_len=%zu\n",
             res ? res->status : 0,
             res ? res->body.size() : 0uz); }

    { auto res = cli.Head("/");  print_result("HEAD /", res); }

    { std::string bin(1024, '\xff');
      auto res = cli.Post("/data", bin, "application/octet-stream");
      print_result("POST /data", res); }

    { auto res = cli.Get("/does-not-exist");
      print_result("GET /404", res); }

    { http3::Client bad("localhost", 19999);
      bad.set_connection_timeout(2);
      auto res = bad.Get("/");
      if (!res) printf("[bad host]  error: %s\n", http3::to_string(res.error()));
    }

    return 0;
}