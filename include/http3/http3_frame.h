#pragma once
#include <http3/http3_defs.h>
#include <http3/http3_varint.h>
#include <cstdint>
#include <vector>

namespace http3::detail {

struct StreamBuf {
    std::vector<uint8_t> data;
    void   append(const uint8_t* p, size_t n) { data.insert(data.end(), p, p+n); }
    size_t size()  const { return data.size(); }
    void   consume(size_t n) { data.erase(data.begin(), data.begin()+(ptrdiff_t)n); }
    const uint8_t* ptr() const { return data.data(); }
};

struct H3Frame {
    uint64_t       type;
    uint64_t       length;
    const uint8_t* payload;
};

std::vector<uint8_t> build_frame(uint64_t type, const std::vector<uint8_t>& payload);
std::vector<uint8_t> build_frame(uint64_t type, const uint8_t* p, size_t len);
std::vector<uint8_t> build_settings_frame();
bool try_parse_frame(const uint8_t* data, size_t len, size_t& pos, H3Frame& out);

} // namespace http3::detail