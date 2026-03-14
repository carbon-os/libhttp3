#pragma once
#include <cstdint>

namespace http3::detail {

// ── H3 stream types ───────────────────────────────────────────────────────────
constexpr uint64_t STREAM_CONTROL        = 0x00;
constexpr uint64_t STREAM_PUSH           = 0x01;
constexpr uint64_t STREAM_QPACK_ENCODER  = 0x02;
constexpr uint64_t STREAM_QPACK_DECODER  = 0x03;
constexpr uint64_t STREAM_WT_UNIDI       = 0x54; // RFC-draft: WT unidirectional stream type

// ── H3 frame types ────────────────────────────────────────────────────────────
constexpr uint64_t FRAME_DATA                  = 0x00;
constexpr uint64_t FRAME_HEADERS               = 0x01;
constexpr uint64_t FRAME_CANCEL_PUSH           = 0x03;
constexpr uint64_t FRAME_SETTINGS              = 0x04;
constexpr uint64_t FRAME_GOAWAY                = 0x07;
constexpr uint64_t FRAME_WEBTRANSPORT_STREAM   = 0x41; // WT bidi-stream header frame

// ── H3 SETTINGS identifiers ───────────────────────────────────────────────────
constexpr uint64_t SETTING_QPACK_MAX_TABLE_CAPACITY    = 0x01;
constexpr uint64_t SETTING_MAX_FIELD_SECTION_SIZE      = 0x06;
constexpr uint64_t SETTING_QPACK_BLOCKED_STREAMS       = 0x07;
// Extended CONNECT (RFC 9220)
constexpr uint64_t SETTING_ENABLE_CONNECT_PROTOCOL     = 0x08;
// HTTP Datagrams (RFC 9297)
constexpr uint64_t SETTING_H3_DATAGRAM                 = 0x33;
// WebTransport (draft-ietf-webtrans-http3)
constexpr uint64_t SETTING_WT_ENABLED                  = 0x2b603742;
constexpr uint64_t SETTING_WT_INITIAL_MAX_STREAMS_UNI  = 0x190B4D39;
constexpr uint64_t SETTING_WT_INITIAL_MAX_STREAMS_BIDI = 0x190B4D3A;
constexpr uint64_t SETTING_WT_INITIAL_MAX_DATA         = 0x190B4D3B;

// ── H3 error codes ────────────────────────────────────────────────────────────
constexpr uint64_t H3_NO_ERROR               = 0x100;
constexpr uint64_t H3_GENERAL_PROTOCOL_ERROR = 0x101;
constexpr uint64_t H3_INTERNAL_ERROR         = 0x102;
constexpr uint64_t H3_STREAM_CREATION_ERROR  = 0x103;
constexpr uint64_t H3_CLOSED_CRITICAL_STREAM = 0x104;
constexpr uint64_t H3_FRAME_UNEXPECTED       = 0x105;
constexpr uint64_t H3_FRAME_ERROR            = 0x106;
constexpr uint64_t H3_MESSAGE_ERROR          = 0x10E;
constexpr uint64_t H3_REQUEST_CANCELLED      = 0x10C;

// ── WebTransport error / capsule codes ────────────────────────────────────────
constexpr uint64_t WT_SESSION_GONE           = 0x170D7B68;
constexpr uint64_t CAPSULE_WT_CLOSE_SESSION  = 0x2843;

} // namespace http3::detail