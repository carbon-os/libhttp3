#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace http3::detail {

struct QpackHeader { std::string name, value; };

bool                 qpack_decode(const uint8_t* data, size_t len,
                                  std::vector<QpackHeader>& out);
std::vector<uint8_t> qpack_encode(const std::vector<QpackHeader>& headers);

} // namespace http3::detail