// QPACK codec (RFC 9204) — static table + Huffman (RFC 7541 Appendix B)
#include <http3/http3_qpack.h>
#include <cstring>
#include <memory>
#include <mutex>

namespace http3::detail {

// ── RFC 7541 Huffman table ────────────────────────────────────────────────────
static const uint32_t HC[256] = {
    0x1ff8,0x7fffd8,0xfffffe2,0xfffffe3,0xfffffe4,0xfffffe5,0xfffffe6,0xfffffe7,
    0xfffffe8,0xffffea,0x3ffffffc,0xfffffe9,0xfffffea,0x3ffffffd,0xfffffeb,0xfffffec,
    0xfffffed,0xfffffee,0xfffffef,0xffffff0,0xffffff1,0xffffff2,0x3ffffffe,0xffffff3,
    0xffffff4,0xffffff5,0xffffff6,0xffffff7,0xffffff8,0xffffff9,0xffffffa,0xffffffb,
    0x14,0x3f8,0x3f9,0xffa,0x1ff9,0x15,0xf8,0x7fa,0x3fa,0x3fb,0xf9,0x7fb,0xfa,
    0x16,0x17,0x18,0x0,0x1,0x2,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x5c,0xfb,
    0x7ffc,0x20,0xffb,0x3fc,0x1ffa,0x21,0x5d,0x5e,0x5f,0x60,0x61,0x62,0x63,0x64,
    0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,0x70,0x71,0x72,0xfc,
    0x73,0xfd,0x1ffb,0x7fff0,0x1ffc,0x3ffc,0x22,0x7ffd,0x3,0x23,0x4,0x24,0x5,0x25,
    0x26,0x27,0x6,0x74,0x75,0x28,0x29,0x2a,0x7,0x2b,0x76,0x2c,0x8,0x9,0x2d,0x77,
    0x78,0x79,0x7a,0x7b,0x7ffe,0x7fc,0x3ffd,0x1ffd,0xffffffc,0xfffe6,0x3fffd2,
    0xfffe7,0xfffe8,0x3fffd3,0x3fffd4,0x3fffd5,0x7fffd9,0x3fffd6,0x7fffda,0x7fffdb,
    0x7fffdc,0x7fffdd,0x7fffde,0xffffeb,0x7fffdf,0xffffec,0xffffed,0x3fffd7,0x7fffe0,
    0xffffee,0x7fffe1,0x7fffe2,0x7fffe3,0x7fffe4,0x1fffdc,0x3fffd8,0x7fffe5,0x3fffd9,
    0x7fffe6,0x7fffe7,0xffffef,0x3fffda,0x1fffdd,0xfffe9,0x3fffdb,0x3fffdc,0x7fffe8,
    0x7fffe9,0x1fffde,0x7fffea,0x3fffdd,0x3fffde,0xfffff0,0x1fffdf,0x3fffdf,0x7fffeb,
    0x7fffec,0x1fffe0,0x1fffe1,0x3fffe0,0x1fffe2,0x7fffed,0x3fffe1,0x7fffee,0x7fffef,
    0xfffea,0x3fffe2,0x3fffe3,0x3fffe4,0x7ffff0,0x3fffe5,0x3fffe6,0x7ffff1,0x3ffffe0,
    0x3ffffe1,0xfffeb,0x7fff1,0x3fffe7,0x7ffff2,0x3fffe8,0x1ffffec,0x3ffffe2,0x3ffffe3,
    0x3ffffe4,0x7ffffde,0x7ffffdf,0x3ffffe5,0xfffff1,0x1ffffed,0x7fff2,0x1fffe3,
    0x3ffffe6,0x7ffffe0,0x7ffffe1,0x3ffffe7,0x7ffffe2,0xfffff2,0x1fffe4,0x1fffe5,
    0x3ffffe8,0x3ffffe9,0xffffffd,0x7ffffe3,0x7ffffe4,0x7ffffe5,0xfffec,0xfffff3,
    0xfffed,0x1fffe6,0x3fffe9,0x1fffe7,0x1fffe8,0x7ffff3,0x3fffea,0x3fffeb,0x1ffffee,
    0x1ffffef,0xfffff4,0xfffff5,0x3ffffea,0x7ffff4,0x3ffffeb,0x7ffffe6,0x3ffffec,
    0x3ffffed,0x7ffffe7,0x7ffffe8,0x7ffffe9,0x7ffffea,0x7ffffeb,0xffffffe,0x7ffffec,
    0x7ffffed,0x7ffffee,0x7ffffef,0x7fffff0,0x3ffffee,
};
static const uint8_t HL[256] = {
    13,23,28,28,28,28,28,28,28,24,30,28,28,30,28,28,28,28,28,28,28,28,30,28,28,28,28,
    28,28,28,28,28,6,10,10,12,13,6,8,11,10,10,8,11,8,6,6,6,5,5,5,6,6,6,6,6,6,6,7,8,
    15,6,12,10,13,6,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,8,7,8,13,19,13,14,6,
    15,5,6,5,6,5,6,6,6,5,7,7,6,6,6,5,6,7,6,5,5,6,7,7,7,7,7,15,11,14,13,28,20,22,20,
    20,22,22,22,23,22,23,23,23,23,23,24,23,24,24,22,23,24,23,23,23,23,21,22,23,22,23,
    23,24,22,21,20,22,22,23,23,21,23,22,22,24,21,22,23,23,21,21,22,21,23,22,23,23,20,
    22,22,22,23,22,22,23,26,26,20,19,22,23,22,25,26,26,26,27,27,26,24,25,19,21,26,27,
    27,26,27,24,21,21,26,26,28,27,27,27,20,24,20,21,22,21,21,23,22,22,25,25,24,24,26,
    23,26,27,26,26,27,27,27,27,27,28,27,27,27,27,27,26,
};

// ── Huffman trie ──────────────────────────────────────────────────────────────
struct HNode {
    HNode* ch[256]; uint8_t sym, codeLen; bool leaf;
    HNode(): sym(0),codeLen(0),leaf(false){ memset(ch,0,sizeof(ch)); }
};
static HNode*         g_root = nullptr;
static std::once_flag g_once;

static void buildTrie() {
    g_root = new HNode();
    for (int s=0;s<256;s++){
        uint32_t code=HC[s]; uint8_t rem=HL[s];
        HNode* cur=g_root;
        while(rem>8){
            rem-=8; uint8_t idx=(uint8_t)(code>>rem);
            if(!cur->ch[idx]) cur->ch[idx]=new HNode();
            cur=cur->ch[idx];
        }
        uint8_t shift=8-rem;
        int start=(int)(uint8_t)((uint8_t)code<<shift), count=1<<shift;
        for(int i=start;i<start+count;i++){
            if(!cur->ch[i]) cur->ch[i]=new HNode();
            cur->ch[i]->sym=s; cur->ch[i]->codeLen=rem; cur->ch[i]->leaf=true;
        }
    }
}

static bool huffDecode(const uint8_t* src, size_t srcLen, std::string& out) {
    std::call_once(g_once, buildTrie);
    HNode* root=g_root; HNode* n=root;
    uint32_t cur=0; uint8_t cbits=0,sbits=0;
    for(size_t i=0;i<srcLen;i++){
        cur=(cur<<8)|src[i]; cbits+=8; sbits+=8;
        while(cbits>=8){
            n=n->ch[(uint8_t)(cur>>(cbits-8))]; if(!n) return false;
            if(n->leaf){ out+=(char)n->sym; cbits-=n->codeLen;
                if(cbits<32) cur&=(1u<<cbits)-1u; n=root; sbits=cbits; }
            else cbits-=8;
        }
    }
    while(cbits>0){
        n=n->ch[(uint8_t)(cur<<(8-cbits))]; if(!n) return false;
        if(!n->leaf||n->codeLen>cbits) break;
        out+=(char)n->sym; cbits-=n->codeLen;
        if(cbits<32) cur&=(1u<<cbits)-1u; n=root; sbits=cbits;
    }
    if(sbits>7) return false;
    uint32_t mask=(cbits==0)?0u:(1u<<cbits)-1u;
    return (cur&mask)==mask;
}

// ── Prefix-integer (RFC 7541 §5.1) ───────────────────────────────────────────
static bool readPI(const uint8_t* b, size_t len, size_t& pos,
                    uint8_t nbits, uint64_t& out) {
    if(pos>=len) return false;
    uint64_t k=(1ull<<nbits)-1ull;
    out=b[pos]&k; ++pos;
    if(out<k) return true;
    uint64_t m=0;
    while(pos<len){ uint8_t x=b[pos++]; out+=(uint64_t)(x&0x7fu)<<m; m+=7;
        if(!(x&0x80)) return true; if(m>=63) return false; }
    return false;
}
static bool readStr(const uint8_t* b, size_t len, size_t& pos,
                     uint8_t nbits, std::string& out) {
    if(pos>=len) return false;
    bool huff=(b[pos]&(1u<<nbits))!=0;
    uint64_t slen=0;
    if(!readPI(b,len,pos,nbits,slen)) return false;
    if(pos+slen>len) return false;
    if(huff){ if(!huffDecode(b+pos,(size_t)slen,out)) return false; }
    else     { out.assign((const char*)b+pos,(size_t)slen); }
    pos+=(size_t)slen; return true;
}

// ── QPACK static table (RFC 9204 Appendix A) ─────────────────────────────────
static const struct { const char* n; const char* v; } ST[99] = {
    {":authority",""},{":path","/"}, {"age","0"},{"content-disposition",""},
    {"content-length","0"},{"cookie",""},{"date",""},{"etag",""},
    {"if-modified-since",""},{"if-none-match",""},{"last-modified",""},
    {"link",""},{"location",""},{"referer",""},{"set-cookie",""},
    {":method","CONNECT"},{":method","DELETE"},{":method","GET"},
    {":method","HEAD"},{":method","OPTIONS"},{":method","POST"},{":method","PUT"},
    {":scheme","http"},{":scheme","https"},{":status","103"},{":status","200"},
    {":status","304"},{":status","404"},{":status","503"},
    {"accept","*/*"},{"accept","application/dns-message"},
    {"accept-encoding","gzip, deflate, br"},{"accept-ranges","bytes"},
    {"access-control-allow-headers","cache-control"},
    {"access-control-allow-headers","content-type"},
    {"access-control-allow-origin","*"},
    {"cache-control","max-age=0"},{"cache-control","max-age=2592000"},
    {"cache-control","max-age=604800"},{"cache-control","no-cache"},
    {"cache-control","no-store"},{"cache-control","public, max-age=31536000"},
    {"content-encoding","br"},{"content-encoding","gzip"},
    {"content-type","application/dns-message"},
    {"content-type","application/javascript"},{"content-type","application/json"},
    {"content-type","application/x-www-form-urlencoded"},
    {"content-type","image/gif"},{"content-type","image/jpeg"},
    {"content-type","image/png"},{"content-type","text/css"},
    {"content-type","text/html; charset=utf-8"},{"content-type","text/plain"},
    {"content-type","text/plain;charset=utf-8"},{"range","bytes=0-"},
    {"strict-transport-security","max-age=31536000"},
    {"strict-transport-security","max-age=31536000; includesubdomains"},
    {"strict-transport-security","max-age=31536000; includesubdomains; preload"},
    {"vary","accept-encoding"},{"vary","origin"},
    {"x-content-type-options","nosniff"},{"x-xss-protection","1; mode=block"},
    {":status","100"},{":status","204"},{":status","206"},{":status","302"},
    {":status","400"},{":status","403"},{":status","421"},{":status","425"},
    {":status","500"},{"accept-language",""},
    {"access-control-allow-credentials","FALSE"},
    {"access-control-allow-credentials","TRUE"},
    {"access-control-allow-headers","*"},
    {"access-control-allow-methods","get"},
    {"access-control-allow-methods","get, post, options"},
    {"access-control-allow-methods","options"},
    {"access-control-expose-headers","content-length"},
    {"access-control-request-headers","content-type"},
    {"access-control-request-method","get"},{"access-control-request-method","post"},
    {"alt-svc","clear"},{"authorization",""},
    {"content-security-policy","script-src 'none'; object-src 'none'; base-uri 'none'"},
    {"early-data","1"},{"expect-ct",""},{"forwarded",""},{"if-range",""},
    {"origin",""},{"purpose","prefetch"},{"server",""},
    {"timing-allow-origin","*"},{"upgrade-insecure-requests","1"},
    {"user-agent",""},{"x-forwarded-for",""},
    {"x-frame-options","deny"},{"x-frame-options","sameorigin"},
};

// ── Public API ────────────────────────────────────────────────────────────────
bool qpack_decode(const uint8_t* data, size_t len, std::vector<QpackHeader>& out) {
    size_t pos=0;
    uint64_t ric=0; if(!readPI(data,len,pos,8,ric)||ric!=0) return false;
    uint64_t base=0; if(!readPI(data,len,pos,7,base)||base!=0) return false;
    while(pos<len){
        uint8_t b=data[pos];
        if(b&0x80){
            if(!(b&0x40)) return false;
            uint64_t idx=0; if(!readPI(data,len,pos,6,idx)||idx>=99) return false;
            out.push_back({ST[idx].n,ST[idx].v});
        } else if((b&0xc0)==0x40){
            if(!(b&0x10)) return false;
            uint64_t idx=0; if(!readPI(data,len,pos,4,idx)||idx>=99) return false;
            std::string val; if(!readStr(data,len,pos,7,val)) return false;
            out.push_back({ST[idx].n,std::move(val)});
        } else if((b&0xe0)==0x20){
            std::string name,val;
            if(!readStr(data,len,pos,3,name)) return false;
            if(!readStr(data,len,pos,7,val))  return false;
            out.push_back({std::move(name),std::move(val)});
        } else return false;
    }
    return true;
}

static void appPI(std::vector<uint8_t>& buf,uint8_t pb,uint8_t nb,uint64_t v){
    uint64_t k=(1ull<<nb)-1ull;
    if(v<k){ buf.push_back(pb|(uint8_t)v); return; }
    buf.push_back(pb|(uint8_t)k); v-=k;
    while(v>=128){ buf.push_back((uint8_t)((v&0x7fu)|0x80u)); v>>=7; }
    buf.push_back((uint8_t)v);
}
static void appSL(std::vector<uint8_t>& buf,uint8_t nb,const std::string& s){
    appPI(buf,0x00u,nb,s.size());
    buf.insert(buf.end(),s.begin(),s.end());
}

std::vector<uint8_t> qpack_encode(const std::vector<QpackHeader>& headers) {
    std::vector<uint8_t> out;
    out.reserve(64);
    appPI(out,0x00u,8,0);
    appPI(out,0x00u,7,0);
    for(const auto& h:headers){
        for(int i=0;i<99;i++){
            if(h.name==ST[i].n&&h.value==ST[i].v){
                appPI(out,0xc0u,6,(uint64_t)i); goto next; }}
        for(int i=0;i<99;i++){
            if(h.name==ST[i].n){
                appPI(out,0x50u,4,(uint64_t)i);
                appSL(out,7,h.value); goto next; }}
        { appPI(out,0x20u,3,h.name.size());
          out.insert(out.end(),h.name.begin(),h.name.end());
          appSL(out,7,h.value); }
        next:;
    }
    return out;
}

} // namespace http3::detail