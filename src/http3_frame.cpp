#include <http3/http3_frame.h>
#include <http3/http3_log.h>

namespace http3::detail {

std::vector<uint8_t> build_frame(uint64_t type, const std::vector<uint8_t>& payload)
{
    H3LOG_VERBOSE("build_frame  type=0x%" PRIx64 " (%s)  payload=%zu bytes",
                  type, frame_type_str(type), payload.size());
    std::vector<uint8_t> f;
    f.reserve(16 + payload.size());
    varint_append(f, type);
    varint_append(f, payload.size());
    f.insert(f.end(), payload.begin(), payload.end());
    return f;
}

std::vector<uint8_t> build_frame(uint64_t type, const uint8_t* p, size_t len)
{
    H3LOG_VERBOSE("build_frame  type=0x%" PRIx64 " (%s)  payload=%zu bytes",
                  type, frame_type_str(type), len);
    std::vector<uint8_t> f;
    f.reserve(16 + len);
    varint_append(f, type);
    varint_append(f, len);
    f.insert(f.end(), p, p + len);
    return f;
}

static void append_setting(std::vector<uint8_t>& v, uint64_t id, uint64_t val) {
    H3LOG_VERBOSE("  setting  id=0x%" PRIx64 "  val=%" PRIu64, id, val);
    varint_append(v, id);
    varint_append(v, val);
}

std::vector<uint8_t> build_settings_frame()
{
    H3LOG_INFO("build_settings_frame");
    std::vector<uint8_t> payload;
    append_setting(payload, SETTING_ENABLE_CONNECT_PROTOCOL, 1);
    append_setting(payload, SETTING_H3_DATAGRAM,             1);
    append_setting(payload, SETTING_WT_ENABLED,              1);
    append_setting(payload, SETTING_WT_INITIAL_MAX_STREAMS_UNI,  256);
    append_setting(payload, SETTING_WT_INITIAL_MAX_STREAMS_BIDI, 256);
    append_setting(payload, SETTING_WT_INITIAL_MAX_DATA,         1u << 20);
    auto frame = build_frame(FRAME_SETTINGS, payload);
    H3LOG_INFO("settings frame total=%zu bytes", frame.size());
    return frame;
}

bool try_parse_frame(const uint8_t* data, size_t len, size_t& pos, H3Frame& out)
{
    size_t p = pos;
    uint64_t type = 0, flen = 0;
    size_t n1 = varint_read(data + p, len - p, type); if (!n1) {
        H3LOG_VERBOSE("try_parse_frame: need more data for type varint  buf=%zu", len - p);
        return false;
    }
    p += n1;
    size_t n2 = varint_read(data + p, len - p, flen); if (!n2) {
        H3LOG_VERBOSE("try_parse_frame: need more data for length varint");
        return false;
    }
    p += n2;
    if (len - p < flen) {
        H3LOG_VERBOSE("try_parse_frame: incomplete payload  have=%zu need=%" PRIu64,
                      len - p, flen);
        return false;
    }
    out.type    = type;
    out.length  = flen;
    out.payload = data + p;
    pos         = p + (size_t)flen;
    H3LOG_VERBOSE("try_parse_frame: OK  type=0x%" PRIx64 " (%s)  len=%" PRIu64
                  "  pos=%zu→%zu",
                  type, frame_type_str(type), flen, pos - (size_t)flen - n1 - n2, pos);
    return true;
}

} // namespace http3::detail