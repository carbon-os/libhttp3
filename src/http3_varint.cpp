#include <http3/http3_varint.h>

namespace http3::detail {

size_t varint_read(const uint8_t* buf, size_t len, uint64_t& out)
{
    if (!len) return 0;
    uint8_t prefix = buf[0] >> 6;
    size_t  need   = 1u << prefix;
    if (len < need) return 0;
    switch (prefix) {
    case 0: out = buf[0] & 0x3f; return 1;
    case 1: out = ((uint64_t)(buf[0]&0x3f)<<8)|buf[1]; return 2;
    case 2: out = ((uint64_t)(buf[0]&0x3f)<<24)|((uint64_t)buf[1]<<16)|
                  ((uint64_t)buf[2]<<8)|buf[3]; return 4;
    default:out = ((uint64_t)(buf[0]&0x3f)<<56)|((uint64_t)buf[1]<<48)|
                  ((uint64_t)buf[2]<<40)|((uint64_t)buf[3]<<32)|
                  ((uint64_t)buf[4]<<24)|((uint64_t)buf[5]<<16)|
                  ((uint64_t)buf[6]<<8)|buf[7]; return 8;
    }
}

size_t varint_write(uint8_t* buf, size_t cap, uint64_t v)
{
    if (v < (1u<<6))  { if (cap<1) return 0; buf[0]=(uint8_t)v;                   return 1; }
    if (v < (1u<<14)) { if (cap<2) return 0; buf[0]=(uint8_t)(0x40|(v>>8));
                                              buf[1]=(uint8_t)v;                   return 2; }
    if (v < (1u<<30)) { if (cap<4) return 0; buf[0]=(uint8_t)(0x80|(v>>24));
                                              buf[1]=(uint8_t)(v>>16);
                                              buf[2]=(uint8_t)(v>>8);
                                              buf[3]=(uint8_t)v;                   return 4; }
    if (cap<8) return 0;
    buf[0]=(uint8_t)(0xc0|(v>>56)); buf[1]=(uint8_t)(v>>48);
    buf[2]=(uint8_t)(v>>40);        buf[3]=(uint8_t)(v>>32);
    buf[4]=(uint8_t)(v>>24);        buf[5]=(uint8_t)(v>>16);
    buf[6]=(uint8_t)(v>>8);         buf[7]=(uint8_t)v; return 8;
}

size_t varint_size(uint64_t v) {
    if (v < (1u<<6))  return 1;
    if (v < (1u<<14)) return 2;
    if (v < (1u<<30)) return 4;
    return 8;
}

void varint_append(std::vector<uint8_t>& buf, uint64_t v) {
    uint8_t tmp[8];
    size_t  n = varint_write(tmp, 8, v);
    buf.insert(buf.end(), tmp, tmp+n);
}

} // namespace http3::detail