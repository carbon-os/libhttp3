#pragma once
#include <cinttypes>
#include <cstdio>
#include <cstdint>

namespace http3::detail {

// Set to 0 to silence, 1 for info, 2 for verbose frame/byte traces
#ifndef HTTP3_LOG_LEVEL
#  define HTTP3_LOG_LEVEL 2
#endif

#define H3LOG(lvl, fmt, ...)                                          \
    do {                                                              \
        if ((lvl) <= HTTP3_LOG_LEVEL)                                 \
            fprintf(stderr, "[http3] " fmt "\n", ##__VA_ARGS__);     \
    } while(0)

#define H3LOG_INFO(fmt, ...)    H3LOG(1, fmt, ##__VA_ARGS__)
#define H3LOG_VERBOSE(fmt, ...) H3LOG(2, fmt, ##__VA_ARGS__)

inline const char* frame_type_str(uint64_t t) {
    switch (t) {
    case 0x00: return "DATA";
    case 0x01: return "HEADERS";
    case 0x03: return "CANCEL_PUSH";
    case 0x04: return "SETTINGS";
    case 0x07: return "GOAWAY";
    case 0x41: return "WT_BIDI_STREAM";
    default:   return "UNKNOWN";
    }
}

inline const char* stream_kind_str(uint8_t k) {
    switch (k) {
    case 0: return "Pending";
    case 1: return "H3";
    case 2: return "H3Control";
    case 3: return "WtBidi";
    case 4: return "WtUnidi";
    case 5: return "WtConnect";
    default: return "?";
    }
}

} // namespace http3::detail