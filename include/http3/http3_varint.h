#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

namespace http3::detail {

size_t varint_read  (const uint8_t* buf, size_t len, uint64_t& out);
size_t varint_write (uint8_t* buf, size_t cap, uint64_t v);
size_t varint_size  (uint64_t v);
void   varint_append(std::vector<uint8_t>& buf, uint64_t v);

} // namespace http3::detail