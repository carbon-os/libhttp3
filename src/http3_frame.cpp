#include <http3/http3_frame.h>

namespace http3::detail {

std::vector<uint8_t> build_frame(uint64_t type, const std::vector<uint8_t>& payload)
{
    std::vector<uint8_t> f;
    f.reserve(16 + payload.size());
    varint_append(f, type);
    varint_append(f, payload.size());
    f.insert(f.end(), payload.begin(), payload.end());
    return f;
}

std::vector<uint8_t> build_frame(uint64_t type, const uint8_t* p, size_t len)
{
    std::vector<uint8_t> f;
    f.reserve(16 + len);
    varint_append(f, type);
    varint_append(f, len);
    f.insert(f.end(), p, p + len);
    return f;
}

std::vector<uint8_t> build_settings_frame()
{
    return build_frame(FRAME_SETTINGS, {});
}

bool try_parse_frame(const uint8_t* data, size_t len, size_t& pos, H3Frame& out)
{
    size_t p = pos;
    uint64_t type = 0, flen = 0;
    size_t n1 = varint_read(data + p, len - p, type); if (!n1) return false; p += n1;
    size_t n2 = varint_read(data + p, len - p, flen); if (!n2) return false; p += n2;
    if (len - p < flen) return false;
    out.type    = type;
    out.length  = flen;
    out.payload = data + p;
    pos         = p + (size_t)flen;
    return true;
}

} // namespace http3::detail