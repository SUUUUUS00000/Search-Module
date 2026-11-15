#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <initializer_list>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#if defined(_MSC_VER) && defined(_M_X64) && !defined(__clang__)
#include <intrin.h>
#endif

#if __cplusplus >= 202002L && __has_include(<span>)
#include <span>
#define LUAU_FILTER_HAS_SPAN 1
#else
#define LUAU_FILTER_HAS_SPAN 0
#endif

namespace luau_filter {

namespace detail {

// -----------------------------------------------------------------------------
// Fast 64-bit hashing (wyhash-style)
// -----------------------------------------------------------------------------
inline uint64_t wymix(uint64_t a, uint64_t b) noexcept {
#if defined(__SIZEOF_INT128__)
    __uint128_t r = static_cast<__uint128_t>(a) * static_cast<__uint128_t>(b);
    return static_cast<uint64_t>(r) ^ static_cast<uint64_t>(r >> 64);
#elif defined(_MSC_VER) && defined(_M_X64)
    uint64_t hi = 0;
    uint64_t lo = _umul128(a, b, &hi);
    return lo ^ hi;
#else
    uint64_t ha = a >> 32, hb = b >> 32;
    uint64_t la = static_cast<uint32_t>(a), lb = static_cast<uint32_t>(b);
    uint64_t rh = ha * hb, rm0 = ha * lb, rm1 = hb * la, rl = la * lb;
    uint64_t t = rl + (rm0 << 32);
    uint64_t c = t < rl;
    uint64_t lo = t + (rm1 << 32);
    c += lo < t;
    uint64_t hi = rh + (rm0 >> 32) + (rm1 >> 32) + c;
    return lo ^ hi;
#endif
}

inline void wymum(uint64_t& a, uint64_t& b) noexcept {
#if defined(__SIZEOF_INT128__)
    __uint128_t r = static_cast<__uint128_t>(a) * static_cast<__uint128_t>(b);
    a = static_cast<uint64_t>(r);
    b = static_cast<uint64_t>(r >> 64);
#elif defined(_MSC_VER) && defined(_M_X64)
    uint64_t hi = 0;
    uint64_t lo = _umul128(a, b, &hi);
    a = lo;
    b = hi;
#else
    uint64_t ha = a >> 32, hb = b >> 32;
    uint64_t la = static_cast<uint32_t>(a), lb = static_cast<uint32_t>(b);
    uint64_t rh = ha * hb, rm0 = ha * lb, rm1 = hb * la, rl = la * lb;
    uint64_t t = rl + (rm0 << 32);
    uint64_t c = t < rl;
    uint64_t lo = t + (rm1 << 32);
    c += lo < t;
    uint64_t hi = rh + (rm0 >> 32) + (rm1 >> 32) + c;
    a = lo;
    b = hi;
#endif
}

inline uint64_t read_u64_unaligned(const uint8_t* p) noexcept {
    uint64_t v;
    std::memcpy(&v, p, 8);
    return v;
}

inline uint64_t read_u32_unaligned_u64(const uint8_t* p) noexcept {
    uint32_t v;
    std::memcpy(&v, p, 4);
    return v;
}

inline uint64_t hash_bytes(const char* data, size_t len) noexcept {
    static constexpr uint64_t s0 = 0xa0761d6478bd642full;
    static constexpr uint64_t s1 = 0xe7037ed1a0b428dbull;
    static constexpr uint64_t s2 = 0x8ebc6af09c88c6e3ull;
    static constexpr uint64_t s3 = 0x589965cc75374cc3ull;
    const uint8_t* p = reinterpret_cast<const uint8_t*>(data);
    uint64_t seed = 0x9e3779b97f4a7c15ull;
    uint64_t a = 0, b = 0;
    if (len <= 16) {
        if (len >= 4) {
            a = (read_u32_unaligned_u64(p) << 32) | read_u32_unaligned_u64(p + ((len >> 3) << 2));
            b = (read_u32_unaligned_u64(p + len - 4) << 32) | read_u32_unaligned_u64(p + len - 4 - ((len >> 3) << 2));
        } else if (len > 0) {
            a = (static_cast<uint64_t>(p[0]) << 16) | (static_cast<uint64_t>(p[len >> 1]) << 8) | p[len - 1];
        }
    } else {
        size_t i = len;
        if (i > 48) {
            uint64_t see1 = seed, see2 = seed;
            do {
                seed = wymix(read_u64_unaligned(p) ^ s1, read_u64_unaligned(p + 8) ^ seed);
                see1 = wymix(read_u64_unaligned(p + 16) ^ s2, read_u64_unaligned(p + 24) ^ see1);
                see2 = wymix(read_u64_unaligned(p + 32) ^ s3, read_u64_unaligned(p + 40) ^ see2);
                p += 48;
                i -= 48;
            } while (i > 48);
            seed ^= see1 ^ see2;
        }
        while (i > 16) {
            seed = wymix(read_u64_unaligned(p) ^ s1, read_u64_unaligned(p + 8) ^ seed);
            i -= 16;
            p += 16;
        }
        a = read_u64_unaligned(p + i - 16);
        b = read_u64_unaligned(p + i - 8);
    }
    a ^= s1;
    b ^= seed;
    wymum(a, b);
    uint64_t h = wymix(a ^ s0 ^ len, b ^ s1);
    return h == 0 ? 1 : h;
}

inline uint64_t hash_sv(std::string_view sv) noexcept {
    return hash_bytes(sv.data(), sv.size());
}

inline uint64_t hash_u32_triple(uint32_t a, uint32_t b, uint32_t c) noexcept {
    uint64_t x = (static_cast<uint64_t>(a) << 32) | b;
    uint64_t y = static_cast<uint64_t>(c) * 0x9e3779b97f4a7c15ull;
    uint64_t h = wymix(x ^ 0xa0761d6478bd642full, y ^ 0xe7037ed1a0b428dbull);
    return h == 0 ? 1 : h;
}

// -----------------------------------------------------------------------------
// Little-endian readers
// -----------------------------------------------------------------------------
inline uint16_t read_u16_le(const uint8_t* p) noexcept {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}

inline int16_t read_i16_le(const uint8_t* p) noexcept {
    uint16_t u = read_u16_le(p);
    int16_t s;
    std::memcpy(&s, &u, sizeof(s));
    return s;
}

inline uint32_t read_u32_le(const uint8_t* p) noexcept {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

// -----------------------------------------------------------------------------
// ASCII helpers (автовекторизуемые, без зависимости от локали)
// -----------------------------------------------------------------------------
inline void to_lower_ascii(const char* src, char* dst, size_t n) noexcept {
    for (size_t i = 0; i < n; ++i) {
        uint8_t c = static_cast<uint8_t>(src[i]);
        uint8_t is_upper = static_cast<uint8_t>(c - 'A') <= static_cast<uint8_t>('Z' - 'A');
        dst[i] = static_cast<char>(c | (is_upper << 5));
    }
}

inline std::string to_lower_str(std::string_view s) {
    std::string out(s.size(), '\0');
    if (!s.empty()) to_lower_ascii(s.data(), &out[0], s.size());
    return out;
}

inline char to_upper_ascii_char(char ch) noexcept {
    uint8_t c = static_cast<uint8_t>(ch);
    if (c >= 'a' && c <= 'z') return static_cast<char>(c - 32);
    return ch;
}

inline bool has_ascii_alpha(std::string_view s) noexcept {
    for (char ch : s) {
        uint8_t c = static_cast<uint8_t>(ch);
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) return true;
    }
    return false;
}

inline constexpr std::array<int8_t, 256> make_kind_lut() noexcept {
    std::array<int8_t, 256> t{};
    for (int b = 0; b < 256; ++b) {
        if (b >= 'a' && b <= 'z') t[b] = 1;
        else if (b >= 'A' && b <= 'Z') t[b] = 2;
        else if (b >= '0' && b <= '9') t[b] = 0;
        else t[b] = -1;
    }
    return t;
}
inline constexpr std::array<int8_t, 256> KIND_LUT = make_kind_lut();

// -----------------------------------------------------------------------------
// Быстрый поиск подстроки через SIMD memchr + 2-й якорь
// -----------------------------------------------------------------------------
struct SearchPattern {
    std::string needle;
    size_t a1 = 0;
    size_t a2 = 0;

    SearchPattern() = default;
    explicit SearchPattern(std::string s) : needle(std::move(s)) { init_anchors(); }

    void init_anchors() noexcept {
        static constexpr auto rank = []() {
            std::array<uint8_t, 256> r{};
            for (int i = 0; i < 256; ++i) r[i] = 1;
            for (int i = '0'; i <= '9'; ++i) r[i] = 2;
            for (int i = 'A'; i <= 'Z'; ++i) r[i] = 2;
            for (int i = 'a'; i <= 'z'; ++i) r[i] = 4;
            for (unsigned char ch : {'e', 't', 'a', 'o', 'i', 'n', 's', 'r', 'l', 'c', 'u', 'd'}) r[ch] = 6;
            r[':'] = 8;
            r['\0'] = 9;
            return r;
        }();
        const size_t n = needle.size();
        if (n <= 1) { a1 = a2 = 0; return; }
        size_t best1 = 0, best2 = n - 1;
        uint8_t r1 = 255, r2 = 255;
        for (size_t i = 0; i < n; ++i) {
            uint8_t rk = rank[static_cast<uint8_t>(needle[i])];
            if (rk < r1) { r2 = r1; best2 = best1; r1 = rk; best1 = i; }
            else if (rk < r2) { r2 = rk; best2 = i; }
        }
        if (best1 == best2) best2 = (best1 == 0) ? (n - 1) : 0;
        a1 = best1;
        a2 = best2;
    }
};

inline size_t fast_find(std::string_view hay, std::string_view needle, size_t a1, size_t a2, size_t pos = 0) noexcept {
    const size_t hlen = hay.size();
    const size_t nlen = needle.size();
    if (nlen == 0) return pos <= hlen ? pos : std::string_view::npos;
    if (nlen > hlen || pos > hlen - nlen) return std::string_view::npos;
    const char* h = hay.data();
    const char* nd = needle.data();
    if (nlen == 1) {
        const void* p = std::memchr(h + pos, static_cast<unsigned char>(nd[0]), hlen - pos);
        return p ? static_cast<size_t>(static_cast<const char*>(p) - h) : std::string_view::npos;
    }
    const unsigned char ach = static_cast<unsigned char>(nd[a1]);
    const char c2 = nd[a2];
    size_t cur = pos + a1;
    const size_t end = (hlen - nlen) + a1 + 1;
    while (cur < end) {
        const void* hit = std::memchr(h + cur, ach, end - cur);
        if (!hit) return std::string_view::npos;
        const size_t idx = static_cast<size_t>(static_cast<const char*>(hit) - h);
        const size_t start = idx - a1;
        if (h[start + a2] == c2) {
            if (nlen <= 2 || std::memcmp(h + start, nd, nlen) == 0) return start;
        }
        cur = idx + 1;
    }
    return std::string_view::npos;
}

inline size_t fast_find(std::string_view hay, const SearchPattern& pat, size_t pos = 0) noexcept {
    return fast_find(hay, pat.needle, pat.a1, pat.a2, pos);
}

inline size_t fast_find_sv(std::string_view hay, std::string_view needle, size_t pos = 0) noexcept {
    const size_t hlen = hay.size();
    const size_t nlen = needle.size();
    if (nlen == 0) return pos <= hlen ? pos : std::string_view::npos;
    if (nlen > hlen || pos > hlen - nlen) return std::string_view::npos;
    if (nlen == 1) {
        const void* hit = std::memchr(hay.data() + pos, static_cast<unsigned char>(needle[0]), hlen - pos);
        return hit ? static_cast<size_t>(static_cast<const char*>(hit) - hay.data()) : std::string_view::npos;
    }
    size_t a1 = (needle[0] == '\0' && nlen > 2) ? (nlen - 2) : 0;
    size_t a2 = (a1 == 0) ? (nlen - 1) : 0;
    if (nlen >= 3) {
        for (size_t i = 0; i < nlen; ++i) {
            uint8_t c = static_cast<uint8_t>(needle[i]);
            if (c != '\0' && c != ':' && !(c >= 'a' && c <= 'z')) { a1 = i; break; }
        }
        if (a2 == a1) a2 = (a1 == 0) ? (nlen - 1) : 0;
    }
    return fast_find(hay, needle, a1, a2, pos);
}

// -----------------------------------------------------------------------------
// Статические таблицы Luau-опкодов и тегов (v4.5.0)
// -----------------------------------------------------------------------------
inline constexpr uint32_t INVALID_STEP = 1073741824u;
inline constexpr int32_t IMPBASE = 16777216;

inline constexpr std::array<uint8_t, 95> OP_LEN = {
  1,1,1,1,1,1,1,2,2,1,1,1,2,1,1,2,
  2,1,1,1,2,1,1,1,1,1,1,2,2,2,2,2,
  2,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,2,1,2,1,1,2,1,2,1,1,1,
  1,1,2,1,1,1,1,1,1,1,2,2,1,2,2,2,
  2,1,1,2,2,2,2,2,2,1,2,2,1,2,2,
};

inline constexpr std::array<uint16_t, 95> make_class_by_op() noexcept {
    std::array<uint16_t, 95> c{};
    for (int op : {4,5,9,13,17,51,66,90,91,93}) c[op] = 1;
    c[24]=122; c[27]=112; c[28]=114; c[29]=115; c[30]=113; c[31]=116; c[32]=117; c[55]=128;
    c[19]=223; c[33]=230; c[34]=231; c[35]=232; c[36]=233; c[37]=234; c[38]=235;
    c[39]=230; c[40]=231; c[41]=232; c[42]=233; c[43]=234; c[44]=235;
    c[45]=209; c[46]=210; c[47]=209; c[48]=210; c[49]=229; c[50]=211; c[52]=237;
    c[53]=226; c[54]=227; c[64]=224; c[71]=231; c[72]=233; c[81]=236; c[82]=236;
    c[15] = 2; c[7] = 2; c[83] = 3;
    c[21] = 4; c[87] = 4;
    c[6] = 5;
    c[12] = 6;
    c[20] = 7; c[85] = 8;
    c[16] = 9; c[8] = 9; c[84] = 10; c[86] = 11;
    c[22] = 12;
    c[26] = 13; c[25] = 14;
    c[2] = 15; c[3] = 16;
    for (int op : {68,73,74,75,60}) c[op] = 17;
    for (int op : {77,78,79,80}) c[op] = 18;
    c[57] = 19; c[58] = 20; c[63] = 21; c[89] = 22;
    c[56] = 318; c[59] = 321; c[61] = 320; c[76] = 319;
    return c;
}
inline constexpr std::array<uint16_t, 95> CLASS_BY_OP = make_class_by_op();

struct OpTables {
    std::array<uint32_t, 256> step_p{};
    std::array<uint32_t, 256> step_e{};
    std::array<uint16_t, 256> cls_p{};
    std::array<uint16_t, 256> cls_e{};
    std::array<uint8_t, 256> encode_step{};
    std::array<uint8_t, 256> plain_step{};
    std::array<uint8_t, 256> fastcall_tid{};
};

inline constexpr OpTables make_op_tables() noexcept {
    OpTables t{};
    for (int raw = 0; raw < 256; ++raw) {
        if (raw < 95) {
            uint8_t sp = static_cast<uint8_t>(OP_LEN[raw] * 4);
            t.plain_step[raw] = sp;
            t.step_p[raw] = sp;
            t.cls_p[raw] = CLASS_BY_OP[raw];
        } else {
            t.plain_step[raw] = 0;
            t.step_p[raw] = INVALID_STEP;
            t.cls_p[raw] = 0;
        }
        int dec = (raw * 203) % 256;
        if (dec < 95) {
            uint8_t se = static_cast<uint8_t>(OP_LEN[dec] * 4);
            t.encode_step[raw] = se;
            t.step_e[raw] = se;
            t.cls_e[raw] = CLASS_BY_OP[dec];
        } else {
            t.encode_step[raw] = 0;
            t.step_e[raw] = INVALID_STEP;
            t.cls_e[raw] = 0;
        }
        t.fastcall_tid[raw] = (raw >= 1 && raw <= 134) ? static_cast<uint8_t>(100 + raw) : 0;
    }
    return t;
}
inline constexpr OpTables OP_TABLES = make_op_tables();

inline constexpr uint16_t RAW_CALL1_P = 21;
inline constexpr uint16_t RAW_CALL2_P = 87;
inline constexpr uint8_t  RAW_LOADB_P = 3;
inline constexpr uint8_t  RAW_MOVE_P  = 6;

inline constexpr uint16_t RAW_CALL1_E = (21 * 227) % 256;
inline constexpr uint16_t RAW_CALL2_E = (87 * 227) % 256;
inline constexpr uint8_t  RAW_LOADB_E = (3 * 227) % 256;
inline constexpr uint8_t  RAW_MOVE_E  = (6 * 227) % 256;

struct StaticTagInfo {
    std::array<std::string_view, 240> tag_str{};
    std::array<uint8_t, 240> tag_len{};
    std::array<std::string_view, 136> builtin_list{};
    std::array<uint8_t, 256> builtin_b0_map{};
    std::string static_ci_haystack;
    std::array<std::string, 240> owned_tags;

    StaticTagInfo() {
        static constexpr std::array<std::string_view, 39> base_tags = {
            "return:void","return:value","return:call","return:nil","return:false","return:true",
            "if:then","if:not-then","cond:and","cond:or","cond:not","if:eq","if:ne","if:le","if:lt","if:gt","if:ge",
            "loop:for-num","loop:for-in","loop:for-in-next","loop:for-in-inext","loop:jumpback",
            "function:closure","function:dup","vararg:get","table:new","table:dup","table:setlist",
            "concat","arith:add","arith:sub","arith:mul","arith:div","arith:mod","arith:pow","arith:idiv","arith:length",
            "call:pcall","call:xpcall"
        };
        static constexpr std::array<std::string_view, 134> builtin_calls = {
            "assert","math.abs","math.acos","math.asin","math.atan2","math.atan","math.ceil","math.cosh","math.cos",
            "math.deg","math.exp","math.floor","math.fmod","math.frexp","math.ldexp","math.log10","math.log","math.max",
            "math.min","math.modf","math.pow","math.rad","math.sinh","math.sin","math.sqrt","math.tanh","math.tan",
            "bit32.arshift","bit32.band","bit32.bnot","bit32.bor","bit32.bxor","bit32.btest","bit32.extract",
            "bit32.lrotate","bit32.lshift","bit32.replace","bit32.rrotate","bit32.rshift",
            "type","string.byte","string.char","string.len","typeof","string.sub","math.clamp","math.sign","math.round",
            "rawset","rawget","rawequal","table.insert","table.unpack","vector","bit32.countlz","bit32.countrz",
            "select","rawlen","bit32.extractk","getmetatable","setmetatable","tonumber","tostring","bit32.byteswap",
            "buffer.readi8","buffer.readu8","buffer.writeu8","buffer.readi16","buffer.readu16","buffer.writeu16",
            "buffer.readi32","buffer.readu32","buffer.writeu32","buffer.readf32","buffer.writef32","buffer.readf64","buffer.writef64",
            "vector.magnitude","vector.normalize","vector.cross","vector.dot","vector.floor","vector.ceil","vector.abs",
            "vector.sign","vector.clamp","vector.min","vector.max","math.lerp","vector.lerp","math.isnan","math.isinf","math.isfinite",
            "integer.create","integer.tonumber","integer.neg","integer.add","integer.sub","integer.mul","integer.div",
            "integer.min","integer.max","integer.rem","integer.idiv","integer.udiv","integer.urem","integer.mod","integer.clamp",
            "integer.band","integer.bor","integer.bnot","integer.bxor","integer.lt","integer.le","integer.ult","integer.ule",
            "integer.gt","integer.ge","integer.ugt","integer.uge","integer.lshift","integer.rshift","integer.arshift",
            "integer.lrotate","integer.rrotate","integer.extract","integer.btest","integer.countrz","integer.countlz","integer.bswap",
            "buffer.readinteger","buffer.writeinteger","table.create","table.clear"
        };

        for (size_t i = 0; i < base_tags.size(); ++i) {
            size_t id = i + 1;
            owned_tags[id] = std::string(base_tags[i]);
            owned_tags[id].push_back('\0');
            tag_str[id] = std::string_view(owned_tags[id].data(), owned_tags[id].size() - 1);
            tag_len[id] = static_cast<uint8_t>(owned_tags[id].size());
        }
        builtin_list[0] = "pcall";
        builtin_list[1] = "xpcall";
        for (size_t i = 0; i < builtin_calls.size(); ++i) {
            size_t id = 101 + i;
            builtin_list[2 + i] = builtin_calls[i];
            owned_tags[id].reserve(6 + builtin_calls[i].size());
            owned_tags[id].assign("call:");
            owned_tags[id].append(builtin_calls[i]);
            owned_tags[id].push_back('\0');
            tag_str[id] = std::string_view(owned_tags[id].data(), owned_tags[id].size() - 1);
            tag_len[id] = static_cast<uint8_t>(owned_tags[id].size());
        }

        static_ci_haystack.reserve(2600);
        static_ci_haystack.push_back('\0');
        for (size_t id = 1; id < 240; ++id) {
            if (tag_len[id] > 0) {
                std::string_view s = tag_str[id];
                for (char ch : s) {
                    uint8_t c = static_cast<uint8_t>(ch);
                    uint8_t is_upper = static_cast<uint8_t>(c - 'A') <= static_cast<uint8_t>('Z' - 'A');
                    static_ci_haystack.push_back(static_cast<char>(c | (is_upper << 5)));
                }
                static_ci_haystack.push_back('\0');
                if (s.size() > 5 && s.compare(0, 5, "call:") == 0) {
                    std::string_view raw_name = s.substr(5);
                    if (raw_name.find('.') == std::string_view::npos) {
                        builtin_b0_map[static_cast<uint8_t>(raw_name[0])] = 1;
                    }
                }
            }
        }
    }

    uint16_t find_tag_id(std::string_view name) const noexcept {
        for (size_t id = 1; id < 240; ++id) {
            if (tag_len[id] > 0 && tag_str[id] == name) return static_cast<uint16_t>(id);
        }
        return 0;
    }

    uint16_t find_builtin_raw_id(std::string_view raw_name) const noexcept {
        if (raw_name.size() < 4 || raw_name.size() > 12) return 0;
        if (!builtin_b0_map[static_cast<uint8_t>(raw_name[0])]) return 0;
        static constexpr std::array<uint8_t, 15> ids = {
            38, 39, 101, 140, 144, 149, 150, 151, 154, 157, 158, 160, 161, 162, 163
        };
        for (uint8_t id : ids) {
            std::string_view s = tag_str[id];
            if (s.size() == 5 + raw_name.size() && std::memcmp(s.data() + 5, raw_name.data(), raw_name.size()) == 0) {
                return id;
            }
        }
        return 0;
    }
};

inline const StaticTagInfo& static_tags() noexcept {
    static const StaticTagInfo info;
    return info;
}

inline bool is_hint_tag(std::string_view tag) noexcept {
    switch (tag.size()) {
        case 3: return tag == "get" || tag == "set";
        case 4: return tag == "func" || tag == "call";
        case 5: return tag == "local" || tag == "upval";
        case 6: return tag == "string" || tag == "method" || tag == "import";
        default: return false;
    }
}

// -----------------------------------------------------------------------------
// Стабильная строковая арена без инвалидации указателей
// -----------------------------------------------------------------------------
class ChunkedArena {
    static constexpr size_t DEFAULT_CHUNK = 65536;
    struct Chunk {
        std::vector<char> data;
        size_t used = 0;
        explicit Chunk(size_t cap) : data(cap) {}
    };
    std::vector<Chunk> chunks_;

public:
    std::string_view alloc_copy(std::string_view s) {
        if (s.empty()) return {};
        if (chunks_.empty() || chunks_.back().used + s.size() > chunks_.back().data.size()) {
            chunks_.emplace_back(std::max(DEFAULT_CHUNK, s.size()));
        }
        Chunk& c = chunks_.back();
        char* dst = c.data.data() + c.used;
        std::memcpy(dst, s.data(), s.size());
        c.used += s.size();
        return std::string_view(dst, s.size());
    }

    char* alloc_uninit(size_t n) {
        if (n == 0) return nullptr;
        if (chunks_.empty() || chunks_.back().used + n > chunks_.back().data.size()) {
            chunks_.emplace_back(std::max(DEFAULT_CHUNK, n));
        }
        Chunk& c = chunks_.back();
        char* dst = c.data.data() + c.used;
        c.used += n;
        return dst;
    }

    void clear() noexcept { chunks_.clear(); }
};

// -----------------------------------------------------------------------------
// Плоские хеш-таблицы с открытой адресацией (без томбстоунов)
// -----------------------------------------------------------------------------
class FlatSvSet {
    struct Slot {
        uint64_t hash = 0;
        std::string_view sv;
    };
    std::vector<Slot> slots_;
    size_t size_ = 0;

    void rehash(size_t new_cap) {
        std::vector<Slot> ns(new_cap);
        const size_t mask = new_cap - 1;
        for (const Slot& sl : slots_) {
            if (sl.hash == 0) continue;
            size_t idx = static_cast<size_t>(sl.hash) & mask;
            while (ns[idx].hash != 0) idx = (idx + 1) & mask;
            ns[idx] = sl;
        }
        slots_.swap(ns);
    }

public:
    bool contains(std::string_view sv, uint64_t h) const noexcept {
        if (size_ == 0) return false;
        const size_t mask = slots_.size() - 1;
        size_t idx = static_cast<size_t>(h) & mask;
        while (true) {
            const Slot& sl = slots_[idx];
            if (sl.hash == 0) return false;
            if (sl.hash == h && sl.sv == sv) return true;
            idx = (idx + 1) & mask;
        }
    }

    bool contains(std::string_view sv) const noexcept {
        return size_ > 0 && contains(sv, hash_sv(sv));
    }

    bool insert(std::string_view sv, uint64_t h) {
        if ((size_ + 1) * 10 >= slots_.size() * 7) {
            rehash(slots_.empty() ? 16 : slots_.size() * 2);
        }
        const size_t mask = slots_.size() - 1;
        size_t idx = static_cast<size_t>(h) & mask;
        while (true) {
            Slot& sl = slots_[idx];
            if (sl.hash == 0) {
                sl.hash = h;
                sl.sv = sv;
                ++size_;
                return true;
            }
            if (sl.hash == h && sl.sv == sv) return false;
            idx = (idx + 1) & mask;
        }
    }

    bool insert(std::string_view sv) { return insert(sv, hash_sv(sv)); }

    void reserve(size_t count) {
        size_t need = (count * 10 + 6) / 7;
        size_t cap = 16;
        while (cap < need) cap *= 2;
        if (cap > slots_.size()) rehash(cap);
    }

    void clear_keep_cap() noexcept {
        if (size_ > 0) {
            for (Slot& sl : slots_) sl.hash = 0;
            size_ = 0;
        }
    }
};

template <typename V>
class FlatSvMap {
    struct Slot {
        uint64_t hash = 0;
        std::string_view key;
        V val{};
    };
    std::vector<Slot> slots_;
    size_t size_ = 0;

    void rehash(size_t new_cap) {
        std::vector<Slot> ns(new_cap);
        const size_t mask = new_cap - 1;
        for (Slot& sl : slots_) {
            if (sl.hash == 0) continue;
            size_t idx = static_cast<size_t>(sl.hash) & mask;
            while (ns[idx].hash != 0) idx = (idx + 1) & mask;
            ns[idx] = std::move(sl);
        }
        slots_.swap(ns);
    }

public:
    const V* find(std::string_view key, uint64_t h) const noexcept {
        if (size_ == 0) return nullptr;
        const size_t mask = slots_.size() - 1;
        size_t idx = static_cast<size_t>(h) & mask;
        while (true) {
            const Slot& sl = slots_[idx];
            if (sl.hash == 0) return nullptr;
            if (sl.hash == h && sl.key == key) return &sl.val;
            idx = (idx + 1) & mask;
        }
    }

    std::pair<V*, bool> emplace(std::string_view key, V val, uint64_t h) {
        if ((size_ + 1) * 10 >= slots_.size() * 7) {
            rehash(slots_.empty() ? 16 : slots_.size() * 2);
        }
        const size_t mask = slots_.size() - 1;
        size_t idx = static_cast<size_t>(h) & mask;
        while (true) {
            Slot& sl = slots_[idx];
            if (sl.hash == 0) {
                sl.hash = h;
                sl.key = key;
                sl.val = std::move(val);
                ++size_;
                return {&sl.val, true};
            }
            if (sl.hash == h && sl.key == key) return {&sl.val, false};
            idx = (idx + 1) & mask;
        }
    }

    std::pair<V*, bool> emplace(std::string_view key, V val) {
        return emplace(key, std::move(val), hash_sv(key));
    }

    void clear_keep_cap() noexcept {
        if (size_ > 0) {
            for (Slot& sl : slots_) { sl.hash = 0; sl.key = {}; }
            size_ = 0;
        }
    }

    void clear() noexcept { slots_.clear(); size_ = 0; }
};

class ImpMemoMap {
    struct Slot {
        uint64_t hash = 0;
        uint32_t s1 = 0, s2 = 0, s3 = 0;
        uint32_t id = 0;
    };
    std::vector<Slot> slots_;
    size_t size_ = 0;

    void rehash(size_t new_cap) {
        std::vector<Slot> ns(new_cap);
        const size_t mask = new_cap - 1;
        for (const Slot& sl : slots_) {
            if (sl.hash == 0) continue;
            size_t idx = static_cast<size_t>(sl.hash) & mask;
            while (ns[idx].hash != 0) idx = (idx + 1) & mask;
            ns[idx] = sl;
        }
        slots_.swap(ns);
    }

public:
    bool find(uint32_t s1, uint32_t s2, uint32_t s3, uint32_t& out_id) const noexcept {
        if (size_ == 0) return false;
        uint64_t h = hash_u32_triple(s1, s2, s3);
        const size_t mask = slots_.size() - 1;
        size_t idx = static_cast<size_t>(h) & mask;
        while (true) {
            const Slot& sl = slots_[idx];
            if (sl.hash == 0) return false;
            if (sl.hash == h && sl.s1 == s1 && sl.s2 == s2 && sl.s3 == s3) {
                out_id = sl.id;
                return true;
            }
            idx = (idx + 1) & mask;
        }
    }

    void insert(uint32_t s1, uint32_t s2, uint32_t s3, uint32_t id) {
        if ((size_ + 1) * 10 >= slots_.size() * 7) {
            rehash(slots_.empty() ? 64 : slots_.size() * 2);
        }
        uint64_t h = hash_u32_triple(s1, s2, s3);
        const size_t mask = slots_.size() - 1;
        size_t idx = static_cast<size_t>(h) & mask;
        while (true) {
            Slot& sl = slots_[idx];
            if (sl.hash == 0) {
                sl.hash = h;
                sl.s1 = s1; sl.s2 = s2; sl.s3 = s3;
                sl.id = id;
                ++size_;
                return;
            }
            if (sl.hash == h && sl.s1 == s1 && sl.s2 == s2 && sl.s3 == s3) {
                sl.id = id;
                return;
            }
            idx = (idx + 1) & mask;
        }
    }

    void clear_keep_cap() noexcept {
        if (size_ > 0) {
            for (Slot& sl : slots_) sl.hash = 0;
            size_ = 0;
        }
    }
};

// -----------------------------------------------------------------------------
// Таблицы декодирования Hex и Base64
// -----------------------------------------------------------------------------
inline constexpr std::array<int8_t, 256> make_hex_lut() noexcept {
    std::array<int8_t, 256> t{};
    for (int i = 0; i < 256; ++i) t[i] = -1;
    for (int c = '0'; c <= '9'; ++c) t[c] = static_cast<int8_t>(c - '0');
    for (int c = 'a'; c <= 'f'; ++c) t[c] = static_cast<int8_t>(10 + (c - 'a'));
    for (int c = 'A'; c <= 'F'; ++c) t[c] = static_cast<int8_t>(10 + (c - 'A'));
    return t;
}
inline constexpr std::array<int8_t, 256> HEX_LUT = make_hex_lut();

inline constexpr std::array<int8_t, 256> make_b64_lut() noexcept {
    std::array<int8_t, 256> t{};
    for (int i = 0; i < 256; ++i) t[i] = -1;
    for (int c = 'A'; c <= 'Z'; ++c) t[c] = static_cast<int8_t>(c - 'A');
    for (int c = 'a'; c <= 'z'; ++c) t[c] = static_cast<int8_t>(26 + (c - 'a'));
    for (int c = '0'; c <= '9'; ++c) t[c] = static_cast<int8_t>(52 + (c - '0'));
    t['+'] = 62; t['-'] = 62;
    t['/'] = 63; t['_'] = 63;
    t['='] = -2;
    t[' '] = -3; t['\t'] = -3; t['\r'] = -3; t['\n'] = -3;
    return t;
}
inline constexpr std::array<int8_t, 256> B64_LUT = make_b64_lut();

} // namespace detail

enum class InputFormat : uint8_t { Auto = 0, Raw = 1, Base64 = 2, Hex = 3 };

inline bool decode_hex(std::string_view in, std::string& out) {
    out.clear();
    while (!in.empty() && (in.front() == ' ' || in.front() == '\t' || in.front() == '\r' || in.front() == '\n')) {
        in.remove_prefix(1);
    }
    if (in.size() >= 2 && in[0] == '0' && (in[1] == 'x' || in[1] == 'X')) {
        in.remove_prefix(2);
    }
    out.reserve(in.size() / 2);
    int hi = -1;
    for (unsigned char ch : in) {
        int8_t v = detail::HEX_LUT[ch];
        if (v >= 0) {
            if (hi < 0) hi = v;
            else {
                out.push_back(static_cast<char>((hi << 4) | v));
                hi = -1;
            }
        } else if (ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n') {
            return false;
        }
    }
    return hi < 0;
}

inline bool decode_base64(std::string_view in, std::string& out) {
    out.clear();
    out.reserve((in.size() * 3) / 4 + 3);
    uint32_t acc = 0;
    int bits = 0;
    int pad_count = 0;
    for (unsigned char ch : in) {
        int8_t v = detail::B64_LUT[ch];
        if (v >= 0) {
            if (pad_count != 0) return false;
            acc = (acc << 6) | static_cast<uint32_t>(v);
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out.push_back(static_cast<char>((acc >> bits) & 0xFFu));
            }
        } else if (v == -2) {
            ++pad_count;
            if (pad_count > 2) return false;
        } else if (v != -3) {
            return false;
        }
    }
    if (bits == 6) return false;
    if (pad_count != 0) {
        if (bits == 4 && pad_count != 2) return false;
        if (bits == 2 && pad_count != 1) return false;
        if (bits == 0) return false;
    }
    return true;
}

inline bool decode_input(std::string_view in, InputFormat fmt, std::string& tmp_buf, std::string_view& out_raw) {
    if (fmt == InputFormat::Raw) { out_raw = in; return true; }
    if (fmt == InputFormat::Base64) {
        if (!decode_base64(in, tmp_buf)) return false;
        out_raw = tmp_buf;
        return true;
    }
    if (fmt == InputFormat::Hex) {
        if (!decode_hex(in, tmp_buf)) return false;
        out_raw = tmp_buf;
        return true;
    }

    if (in.size() < 2) return false;
    uint8_t b0 = static_cast<uint8_t>(in[0]);
    if ((b0 >= 3 && b0 <= 14) || b0 == 100) {
        if (b0 == '\t' || b0 == '\n' || b0 == '\r') {
            std::string_view trimmed = in;
            while (!trimmed.empty() && (trimmed.front() == ' ' || trimmed.front() == '\t' || trimmed.front() == '\r' || trimmed.front() == '\n')) {
                trimmed.remove_prefix(1);
            }
            if (!trimmed.empty()) {
                char c0 = trimmed.front();
                if ((c0 == 'A' || c0 == 'B' || c0 == 'C' || c0 == 'D' || c0 == 'Z') &&
                    decode_base64(trimmed, tmp_buf) && !tmp_buf.empty()) {
                    uint8_t v = static_cast<uint8_t>(tmp_buf[0]);
                    if ((v >= 3 && v <= 14) || v == 100) { out_raw = tmp_buf; return true; }
                }
                if ((c0 == '0' || c0 == '6') && decode_hex(trimmed, tmp_buf) && !tmp_buf.empty()) {
                    uint8_t v = static_cast<uint8_t>(tmp_buf[0]);
                    if ((v >= 3 && v <= 14) || v == 100) { out_raw = tmp_buf; return true; }
                }
            }
        }
        out_raw = in;
        return true;
    }

    std::string_view trimmed = in;
    while (!trimmed.empty() && (trimmed.front() == ' ' || trimmed.front() == '\t' || trimmed.front() == '\r' || trimmed.front() == '\n')) {
        trimmed.remove_prefix(1);
    }
    if (trimmed.empty()) return false;
    char c0 = trimmed.front();
    if (c0 == '0' || c0 == '6') {
        if (decode_hex(trimmed, tmp_buf)) { out_raw = tmp_buf; return true; }
    }
    if (decode_base64(trimmed, tmp_buf)) { out_raw = tmp_buf; return true; }
    if (decode_hex(trimmed, tmp_buf)) { out_raw = tmp_buf; return true; }
    return false;
}

// -----------------------------------------------------------------------------
// BytecodeFilter (полный эквивалент Luau-модуля v4.5.0)
// -----------------------------------------------------------------------------
class BytecodeFilter {
public:
    static constexpr std::string_view version = "4.5.0";

    struct PreparedCorpus {
        std::vector<std::string_view> bytecodes;
        std::vector<uint64_t> hashes;
        mutable std::vector<uint32_t> slot_hints;
        mutable uint64_t clear_gen = 0;
    };

private:
    enum class SlotState : uint8_t { HdrOnly = 0, Parsed = 1, Invalid = 2 };

    struct Entry {
        std::string raw_blob;
        std::string low_blob;
        bool has_low_blob = false;

        std::vector<std::string_view> word_list;
        bool has_word_list = false;

        detail::FlatSvSet word_set;
        bool has_word_set = false;
        uint64_t query_gen = 0;

        std::vector<std::string_view> token_list;
        bool has_token_list = false;
    };

    struct CacheSlot {
        std::string key;
        SlotState state = SlotState::Invalid;
        std::string low_hdr;
        Entry entry;
    };

    struct MapBucket {
        uint64_t hash = 0;
        uint32_t slot_idx = 0;
    };

    std::vector<MapBucket> map_buckets_;
    size_t map_size_ = 0;
    std::deque<CacheSlot> slots_;
    uint64_t query_serial_ = 0;
    uint64_t clear_gen_ = 1;

    static constexpr size_t TOK_MEMO_MAX = 60000;
    static constexpr size_t TOK_MEMO_KEY_MAX = 96;
    struct TokenSlice { uint32_t start = 0, count = 0; };
    detail::ChunkedArena tok_arena_;
    std::vector<std::string_view> tok_memo_pool_;
    detail::FlatSvMap<TokenSlice> tok_memo_;
    size_t tok_memo_n_ = 0;

    std::vector<uint32_t> scratch_str_off_, scratch_str_len_, scratch_constants_;
    std::vector<int32_t>  scratch_const_sidx_;
    std::vector<uint64_t> scratch_fs_str_, scratch_fs_get_, scratch_fs_set_, scratch_fs_call_;
    std::vector<uint64_t> scratch_fs_meth_, scratch_fs_func_, scratch_fs_loc_, scratch_fs_upv_;
    std::array<int32_t, 520> scratch_reg_{};
    std::array<uint64_t, 240> scratch_tag_seen_{};
    std::vector<uint64_t> scratch_imp_stamp_;
    std::vector<uint32_t> scratch_imp_tid_;

    detail::FlatSvSet scratch_imp_seen_;
    detail::ImpMemoMap scratch_imp_memo_;
    detail::FlatSvMap<uint32_t> scratch_path_ids_;
    detail::ChunkedArena scratch_imp_chunked_;
    struct ImportTuple {
        uint32_t last_k = 0;
        uint16_t ctid = 0;
        uint32_t pid = 0;
        uint64_t done = 0;
    };
    std::vector<ImportTuple> scratch_tuples_;
    std::vector<std::string_view> scratch_t_path_sv_, scratch_t_cpat_sv_;
    std::vector<uint64_t> scratch_p_imp_, scratch_p_get_;
    uint32_t scratch_n_tuples_ = 0, scratch_n_paths_ = 0;
    bool scratch_dirty_ = false;
    int scratch_max_reg_ = 0;
    uint64_t import_gen_counter_ = 0, script_gen_counter_ = 0;
    std::vector<char> scratch_blob_buf_;

    std::vector<std::string_view> tmp_bvs_, tmp_tvs_;
    std::string decode_buf_;
    std::vector<std::string> tmp_decoded_bcs_;

    template <typename StringContainer>
    inline void decode_to_tmp_bvs(const StringContainer& src, size_t n, InputFormat fmt) {
        tmp_decoded_bcs_.resize(n);
        tmp_bvs_.clear();
        tmp_bvs_.reserve(n);
        for (size_t i = 0; i < n; ++i) {
            std::string_view raw;
            if (decode_input(std::string_view(src[i]), fmt, tmp_decoded_bcs_[i], raw)) {
                tmp_bvs_.push_back(raw);
            } else {
                tmp_bvs_.emplace_back();
            }
        }
    }

    struct CompiledTerms {
        struct ExactTerm {
            detail::SearchPattern needle;
            std::string_view term_view;
            bool plain_ok = true;
        };
        std::vector<ExactTerm> exact;
        std::vector<detail::SearchPattern> prefix;
        struct BareTerm {
            detail::SearchPattern fast_needle;
            detail::SearchPattern lower_needle;
        };
        std::vector<BareTerm> bare;
        std::vector<detail::SearchPattern> bare_prefix;
        struct FragTerm {
            detail::SearchPattern raw;
            detail::SearchPattern lower;
            bool has_alpha = false;
        };
        std::vector<FragTerm> frag;
        std::vector<detail::SearchPattern> cold_hints;
        struct ColdCiHint {
            detail::SearchPattern ci;
            detail::SearchPattern title;
            bool has_title = false;
        };
        std::vector<ColdCiHint> cold_ci;
        bool valid = false;
    };
    CompiledTerms compiled_buf_;

    void rehash_map(size_t new_cap) {
        std::vector<MapBucket> nb(new_cap);
        const size_t mask = new_cap - 1;
        for (const MapBucket& b : map_buckets_) {
            if (b.hash == 0) continue;
            size_t idx = static_cast<size_t>(b.hash) & mask;
            while (nb[idx].hash != 0) idx = (idx + 1) & mask;
            nb[idx] = b;
        }
        map_buckets_.swap(nb);
    }

    uint32_t find_slot_idx(std::string_view bc, uint64_t h) const noexcept {
        if (map_size_ == 0) return UINT32_MAX;
        const size_t mask = map_buckets_.size() - 1;
        size_t idx = static_cast<size_t>(h) & mask;
        while (true) {
            const MapBucket& b = map_buckets_[idx];
            if (b.hash == 0) return UINT32_MAX;
            if (b.hash == h && slots_[b.slot_idx].key == bc) return b.slot_idx;
            idx = (idx + 1) & mask;
        }
    }

    uint32_t get_or_create_slot(std::string_view bc, uint64_t h, bool& created) {
        if ((map_size_ + 1) * 10 >= map_buckets_.size() * 7) {
            rehash_map(map_buckets_.empty() ? 256 : map_buckets_.size() * 2);
        }
        const size_t mask = map_buckets_.size() - 1;
        size_t idx = static_cast<size_t>(h) & mask;
        while (true) {
            MapBucket& b = map_buckets_[idx];
            if (b.hash == 0) {
                uint32_t sidx = static_cast<uint32_t>(slots_.size());
                slots_.emplace_back();
                slots_.back().key.assign(bc.data(), bc.size());
                b.hash = h;
                b.slot_idx = sidx;
                ++map_size_;
                created = true;
                return sidx;
            }
            if (b.hash == h && slots_[b.slot_idx].key == bc) {
                created = false;
                return b.slot_idx;
            }
            idx = (idx + 1) & mask;
        }
    }

    static inline bool read_varint_tail(const uint8_t* buf, size_t& pos, size_t len, uint8_t b0, uint64_t& out) noexcept {
        uint64_t result = static_cast<uint64_t>(b0 - 128);
        unsigned shift = 7;
        ++pos;
        while (true) {
            if (pos >= len) return false;
            uint8_t b = buf[pos++];
            if (b < 128) {
                if (shift < 64) result |= static_cast<uint64_t>(b) << shift;
                out = result;
                return true;
            }
            if (shift < 64) result |= static_cast<uint64_t>(b - 128) << shift;
            shift += 7;
        }
    }

    static inline bool read_varint(const uint8_t* buf, size_t& pos, size_t limit_len, size_t buf_len, uint64_t& out) noexcept {
        if (pos >= buf_len) return false;
        uint8_t b0 = buf[pos];
        if (b0 < 128) { ++pos; out = b0; return true; }
        return read_varint_tail(buf, pos, limit_len, b0, out);
    }

    static std::optional<std::string_view> get_str_table_slice(std::string_view bc) noexcept {
        const size_t blen = bc.size();
        if (blen < 4) return std::nullopt;
        const uint8_t* buf = reinterpret_cast<const uint8_t*>(bc.data());
        uint8_t version = buf[0];
        if (version < 3 || (version > 14 && version != 100)) return std::nullopt;
        size_t pos = (version >= 4) ? 2 : 1;
        uint64_t str_count = 0;
        if (!read_varint(buf, pos, blen, blen, str_count)) return std::nullopt;
        const size_t str_start = pos;
        uint64_t rem = str_count;
        while (rem >= 4) {
            if (pos >= blen) return std::nullopt;
            uint8_t s1 = buf[pos];
            if (s1 >= 128) break;
            size_t p2 = pos + 1 + s1;
            if (p2 >= blen) { pos = p2; --rem; break; }
            uint8_t s2 = buf[p2];
            if (s2 >= 128) { pos = p2; --rem; break; }
            size_t p3 = p2 + 1 + s2;
            if (p3 >= blen) { pos = p3; rem -= 2; break; }
            uint8_t s3 = buf[p3];
            if (s3 >= 128) { pos = p3; rem -= 2; break; }
            size_t p4 = p3 + 1 + s3;
            if (p4 >= blen) { pos = p4; rem -= 3; break; }
            uint8_t s4 = buf[p4];
            if (s4 >= 128) { pos = p4; rem -= 3; break; }
            pos = p4 + 1 + s4;
            rem -= 4;
        }
        while (rem > 0) {
            uint64_t slen = 0;
            if (!read_varint(buf, pos, blen, blen, slen)) return std::nullopt;
            if (slen > blen - pos) return std::nullopt;
            pos += static_cast<size_t>(slen);
            --rem;
        }
        if (pos > blen) return std::nullopt;
        if (pos <= str_start) return std::string_view{};
        return bc.substr(str_start, pos - str_start);
    }

    static inline bool is_valid_stream_detect(const uint8_t* buf, size_t insn_base, size_t insn_end, bool& certain_plain) noexcept {
        size_t off = insn_base;
        certain_plain = false;
        while (off < insn_end) {
            uint8_t raw = buf[off];
            uint8_t step = detail::OP_TABLES.plain_step[raw];
            if (step == 0 || step > insn_end - off) return false;
            if (!certain_plain && detail::OP_TABLES.encode_step[raw] == 0) certain_plain = true;
            off += step;
        }
        return true;
    }

    static inline bool is_valid_stream_true(const uint8_t* buf, size_t insn_base, size_t insn_end) noexcept {
        size_t off = insn_base;
        while (off < insn_end) {
            uint8_t step = detail::OP_TABLES.encode_step[buf[off]];
            if (step == 0 || step > insn_end - off) return false;
            off += step;
        }
        return true;
    }

    uint32_t resolve_import_safe(const char* bc_data, uint32_t const_count, uint32_t idx1) {
        if (idx1 < 1 || idx1 > const_count || scratch_const_sidx_[idx1] != -1) return 0;
        const uint32_t iid = scratch_constants_[idx1];
        const uint32_t cnt = iid >> 30;
        const uint32_t k1 = cnt >= 1 ? ((iid >> 20) & 1023u) + 1u : 0u;
        const uint32_t k2 = cnt >= 2 ? ((iid >> 10) & 1023u) + 1u : 0u;
        const uint32_t k3 = cnt >= 3 ? (iid & 1023u) + 1u : 0u;

        int32_t s1_raw = (k1 >= 1 && k1 <= const_count) ? scratch_const_sidx_[k1] : 0;
        int32_t s2_raw = (k2 >= 1 && k2 <= const_count) ? scratch_const_sidx_[k2] : 0;
        int32_t s3_raw = (k3 >= 1 && k3 <= const_count) ? scratch_const_sidx_[k3] : 0;
        uint32_t idx_s1 = s1_raw > 0 ? static_cast<uint32_t>(s1_raw) : 0u;
        uint32_t idx_s2 = s2_raw > 0 ? static_cast<uint32_t>(s2_raw) : 0u;
        uint32_t idx_s3 = s3_raw > 0 ? static_cast<uint32_t>(s3_raw) : 0u;

        uint32_t cached_id = 0;
        if (scratch_imp_memo_.find(idx_s1, idx_s2, idx_s3, cached_id)) return cached_id;
        if (idx_s1 == 0 && idx_s2 == 0 && idx_s3 == 0) {
            scratch_imp_memo_.insert(idx_s1, idx_s2, idx_s3, 0);
            return 0;
        }

        auto get_sv = [&](uint32_t sidx) noexcept -> std::string_view {
            return std::string_view(bc_data + scratch_str_off_[sidx], scratch_str_len_[sidx]);
        };
        std::string_view s1 = idx_s1 > 0 ? get_sv(idx_s1) : std::string_view{};
        std::string_view s2 = idx_s2 > 0 ? get_sv(idx_s2) : std::string_view{};
        std::string_view s3 = idx_s3 > 0 ? get_sv(idx_s3) : std::string_view{};

        std::string_view path_sv, last;
        uint32_t last_k = 0;

        auto join2 = [&](std::string_view a, std::string_view b) -> std::string_view {
            size_t len = a.size() + 1 + b.size();
            char* p = scratch_imp_chunked_.alloc_uninit(len);
            if (!a.empty()) std::memcpy(p, a.data(), a.size());
            p[a.size()] = '.';
            if (!b.empty()) std::memcpy(p + a.size() + 1, b.data(), b.size());
            return std::string_view(p, len);
        };

        if (idx_s1 > 0 && idx_s2 > 0 && idx_s3 > 0) {
            size_t len = s1.size() + 1 + s2.size() + 1 + s3.size();
            char* p = scratch_imp_chunked_.alloc_uninit(len);
            if (!s1.empty()) std::memcpy(p, s1.data(), s1.size());
            p[s1.size()] = '.';
            if (!s2.empty()) std::memcpy(p + s1.size() + 1, s2.data(), s2.size());
            p[s1.size() + 1 + s2.size()] = '.';
            if (!s3.empty()) std::memcpy(p + s1.size() + 2 + s2.size(), s3.data(), s3.size());
            path_sv = std::string_view(p, len);
            last = s3; last_k = idx_s3;
        } else if (idx_s1 > 0 && idx_s2 > 0) {
            path_sv = join2(s1, s2); last = s2; last_k = idx_s2;
        } else if (idx_s1 > 0 && idx_s3 > 0) {
            path_sv = join2(s1, s3); last = s3; last_k = idx_s3;
        } else if (idx_s2 > 0 && idx_s3 > 0) {
            path_sv = join2(s2, s3); last = s3; last_k = idx_s3;
        } else {
            uint32_t lk = idx_s1 > 0 ? idx_s1 : (idx_s2 > 0 ? idx_s2 : idx_s3);
            path_sv = get_sv(lk);
            last = path_sv; last_k = lk;
        }

        std::string_view sh = last;
        size_t dot = last.rfind('.');
        if (dot != std::string_view::npos && dot + 1 < last.size()) {
            sh = last.substr(dot + 1);
        }

        size_t cpat_len = 5 + sh.size();
        char* cp_buf = scratch_imp_chunked_.alloc_uninit(cpat_len);
        std::memcpy(cp_buf, "call:", 5);
        if (!sh.empty()) std::memcpy(cp_buf + 5, sh.data(), sh.size());
        std::string_view cpat_sv(cp_buf, cpat_len);

        uint32_t id = ++scratch_n_tuples_;
        if (id >= scratch_tuples_.size()) {
            size_t ns = std::max<size_t>(id + 64, scratch_tuples_.size() * 2);
            scratch_tuples_.resize(ns);
            scratch_t_path_sv_.resize(ns);
            scratch_t_cpat_sv_.resize(ns);
        }

        uint16_t ctid = detail::static_tags().find_tag_id(cpat_sv);
        auto [pid_ptr, inserted] = scratch_path_ids_.emplace(path_sv, scratch_n_paths_ + 1);
        uint32_t pid = *pid_ptr;
        if (inserted) {
            ++scratch_n_paths_;
            if (pid >= scratch_p_imp_.size()) {
                size_t np = std::max<size_t>(pid + 64, scratch_p_imp_.size() * 2);
                scratch_p_imp_.resize(np, 0);
                scratch_p_get_.resize(np, 0);
            }
            scratch_p_imp_[pid] = 0;
            scratch_p_get_[pid] = 0;
        }

        ImportTuple& tup = scratch_tuples_[id];
        tup.last_k = (sh.size() == last.size()) ? last_k : 0;
        tup.ctid = ctid;
        tup.pid = pid;
        tup.done = 0;
        scratch_t_path_sv_[id] = path_sv;
        scratch_t_cpat_sv_[id] = cpat_sv;

        scratch_imp_memo_.insert(idx_s1, idx_s2, idx_s3, id);
        return id;
    }

    inline void ensure_blob_cap(size_t need) {
        if (need > scratch_blob_buf_.size()) {
            size_t cap = std::max<size_t>(65536, scratch_blob_buf_.size());
            while (cap < need) cap *= 2;
            scratch_blob_buf_.resize(cap);
        }
    }

    inline size_t write_blob_bytes(size_t wpos, const char* p, size_t n) {
        ensure_blob_cap(wpos + n);
        std::memcpy(scratch_blob_buf_.data() + wpos, p, n);
        return wpos + n;
    }

    inline size_t write_blob_prefixed(size_t wpos, const char* pfx, size_t pfx_len, const char* body, size_t body_len) {
        size_t need = wpos + pfx_len + body_len + 1;
        ensure_blob_cap(need);
        char* dst = scratch_blob_buf_.data() + wpos;
        std::memcpy(dst, pfx, pfx_len);
        if (body_len) std::memcpy(dst + pfx_len, body, body_len);
        dst[pfx_len + body_len] = '\0';
        return need;
    }

    bool parse_and_extract(std::string_view bytecode, std::string& out_blob) {
        const size_t blen = bytecode.size();
        if (blen < 2) return false;
        const char* bc_data = bytecode.data();
        const uint8_t* buf = reinterpret_cast<const uint8_t*>(bc_data);
        size_t pos = 0;

        uint8_t version = buf[pos++];
        if (version < 3 || (version > 14 && version != 100)) return false;

        uint8_t typesversion = 0;
        if (version >= 4) {
            if (pos >= blen) return false;
            typesversion = buf[pos++];
        }

        uint64_t str_count_u64 = 0;
        if (!read_varint(buf, pos, blen, blen, str_count_u64)) return false;
        if (str_count_u64 > blen - pos) return false;
        const uint32_t str_count = static_cast<uint32_t>(str_count_u64);

        if (str_count + 1 > scratch_str_off_.size()) {
            size_t ns = str_count + 1;
            scratch_str_off_.resize(ns); scratch_str_len_.resize(ns);
            scratch_fs_str_.resize(ns, 0); scratch_fs_get_.resize(ns, 0);
            scratch_fs_set_.resize(ns, 0); scratch_fs_call_.resize(ns, 0);
            scratch_fs_meth_.resize(ns, 0); scratch_fs_func_.resize(ns, 0);
            scratch_fs_loc_.resize(ns, 0); scratch_fs_upv_.resize(ns, 0);
        }

        for (uint32_t i = 1; i <= str_count; ++i) {
            uint64_t slen = 0;
            if (!read_varint(buf, pos, blen, blen, slen)) return false;
            if (slen > blen - pos) return false;
            scratch_str_off_[i] = static_cast<uint32_t>(pos);
            scratch_str_len_[i] = static_cast<uint32_t>(slen);
            pos += static_cast<size_t>(slen);
        }

        if (typesversion == 3) {
            while (true) {
                if (pos >= blen) return false;
                uint8_t tag = buf[pos++];
                if (tag == 0) break;
                uint64_t tv = 0;
                if (!read_varint(buf, pos, blen, blen, tv)) return false;
            }
        }

        uint64_t proto_count = 0;
        if (!read_varint(buf, pos, blen, blen, proto_count)) return false;

        const uint64_t script_gen = ++script_gen_counter_;
        if (scratch_dirty_) {
            scratch_imp_seen_.clear_keep_cap();
            scratch_imp_memo_.clear_keep_cap();
            scratch_path_ids_.clear_keep_cap();
            scratch_imp_chunked_.clear();
            scratch_dirty_ = false;
        }
        scratch_n_tuples_ = 0;
        scratch_n_paths_ = 0;

        ensure_blob_cap(256);
        scratch_blob_buf_[0] = '\0';
        size_t wpos = 1;

        const bool has_size = (version >= 12 || version == 100);
        int8_t encoded_mode = -1;
        const auto& st = detail::static_tags();
        const auto& ot = detail::OP_TABLES;

        for (uint64_t p_idx = 0; p_idx < proto_count; ++p_idx) {
            size_t blob_end = 0;
            if (has_size) {
                uint64_t sz = 0;
                if (!read_varint(buf, pos, blen, blen, sz)) return false;
                if (sz > blen - pos) break;
                blob_end = pos + static_cast<size_t>(sz);
            }

            const size_t limit = has_size ? blob_end : blen;
            size_t bp = pos + 4;
            if (version >= 4) {
                ++bp;
                uint64_t tsize = 0;
                if (!read_varint(buf, bp, limit, blen, tsize)) return false;
                if (tsize > std::numeric_limits<size_t>::max() - bp) return false;
                bp += static_cast<size_t>(tsize);
            }

            uint64_t insn_count = 0;
            if (!read_varint(buf, bp, limit, blen, insn_count)) return false;
            if (bp > limit || insn_count > (limit - bp) / 4) return false;
            const size_t insn_base = bp;
            const size_t insn_end = bp + static_cast<size_t>(insn_count) * 4;
            bp = insn_end;

            uint64_t const_count_u64 = 0;
            if (!read_varint(buf, bp, limit, blen, const_count_u64)) return false;

            const uint32_t max_possible_consts = static_cast<uint32_t>(
                std::min<uint64_t>(const_count_u64, bp < limit ? (limit - bp) : 0));
            if (max_possible_consts + 1 > scratch_constants_.size()) {
                size_t nc = max_possible_consts + 1;
                scratch_constants_.resize(nc);
                scratch_const_sidx_.resize(nc, 0);
                scratch_imp_stamp_.resize(nc, 0);
                scratch_imp_tid_.resize(nc, 0);
            }

            bool has_imports = false, broken_const = false;
            uint32_t parsed_consts = 0;

            for (uint64_t ci64 = 1; ci64 <= const_count_u64; ++ci64) {
                if (bp >= limit) { broken_const = true; break; }
                uint32_t ci = static_cast<uint32_t>(ci64);
                parsed_consts = ci;
                uint8_t ctype = buf[bp++];

                if (ctype == 3) {
                    uint64_t sidx64 = 0;
                    if (!read_varint(buf, bp, limit, blen, sidx64)) return false;
                    if (sidx64 >= 1 && sidx64 <= str_count) {
                        uint32_t sidx = static_cast<uint32_t>(sidx64);
                        scratch_const_sidx_[ci] = static_cast<int32_t>(sidx);
                        uint32_t slen = scratch_str_len_[sidx];
                        if (slen > 0 && scratch_fs_str_[sidx] != script_gen) {
                            scratch_fs_str_[sidx] = script_gen;
                            wpos = write_blob_prefixed(wpos, "string:", 7, bc_data + scratch_str_off_[sidx], slen);
                        }
                    } else {
                        scratch_const_sidx_[ci] = 0;
                    }
                } else if (ctype == 2) { scratch_const_sidx_[ci] = 0; bp += 8; }
                else if (ctype == 4) {
                    if (bp + 4 > limit) return false;
                    scratch_constants_[ci] = detail::read_u32_le(buf + bp);
                    scratch_const_sidx_[ci] = -1;
                    has_imports = true;
                    bp += 4;
                } else if (ctype == 1) { scratch_const_sidx_[ci] = 0; bp += 1; }
                else if (ctype == 0) { scratch_const_sidx_[ci] = 0; }
                else if (ctype == 5) {
                    scratch_const_sidx_[ci] = 0;
                    uint64_t n = 0;
                    if (!read_varint(buf, bp, limit, blen, n)) return false;
                    for (uint64_t j = 0; j < n; ++j) {
                        uint64_t v = 0;
                        if (!read_varint(buf, bp, limit, blen, v)) return false;
                    }
                } else if (ctype == 6) {
                    scratch_const_sidx_[ci] = 0;
                    uint64_t v = 0;
                    if (!read_varint(buf, bp, limit, blen, v)) return false;
                } else if (ctype == 7) { scratch_const_sidx_[ci] = 0; bp += 16; }
                else if (ctype == 8) {
                    scratch_const_sidx_[ci] = 0;
                    uint64_t n = 0;
                    if (!read_varint(buf, bp, limit, blen, n)) return false;
                    for (uint64_t j = 0; j < n; ++j) {
                        uint64_t v = 0;
                        if (!read_varint(buf, bp, limit, blen, v)) return false;
                        bp += 4;
                    }
                } else if (ctype == 9) {
                    scratch_const_sidx_[ci] = 0; bp += 1;
                    uint64_t v = 0;
                    if (!read_varint(buf, bp, limit, blen, v)) return false;
                } else if (ctype == 10) {
                    scratch_const_sidx_[ci] = 0;
                    uint64_t v1 = 0, pc2 = 0, mc = 0;
                    if (!read_varint(buf, bp, limit, blen, v1)) return false;
                    if (!read_varint(buf, bp, limit, blen, pc2)) return false;
                    if (!read_varint(buf, bp, limit, blen, mc)) return false;
                    if (pc2 > std::numeric_limits<uint64_t>::max() - mc) return false;
                    uint64_t total_pv = pc2 + mc;
                    for (uint64_t j = 0; j < total_pv; ++j) {
                        uint64_t pv = 0;
                        if (!read_varint(buf, bp, limit, blen, pv)) return false;
                    }
                } else if (ctype == 11) { scratch_const_sidx_[ci] = 0; bp += 32; }
                else {
                    --parsed_consts;
                    broken_const = true;
                    break;
                }
            }

            if (insn_base < insn_end) {
                bool use_encode = false, run = true;
                if (encoded_mode == 1) use_encode = true;
                else if (encoded_mode == 0) use_encode = false;
                else {
                    bool certain_plain = false;
                    if (is_valid_stream_detect(buf, insn_base, insn_end, certain_plain)) {
                        use_encode = false;
                        if (certain_plain) encoded_mode = 0;
                    } else if (is_valid_stream_true(buf, insn_base, insn_end)) {
                        use_encode = true;
                        encoded_mode = 1;
                    } else {
                        run = false;
                    }
                }

                if (run) {
                    if (scratch_max_reg_ >= 1) {
                        std::memset(&scratch_reg_[1], 0, static_cast<size_t>(scratch_max_reg_) * sizeof(int32_t));
                    }
                    scratch_max_reg_ = 256;

                    const uint32_t* STEP = use_encode ? ot.step_e.data() : ot.step_p.data();
                    const uint16_t* CLS  = use_encode ? ot.cls_e.data() : ot.cls_p.data();
                    const uint16_t RAW_CALL1 = use_encode ? detail::RAW_CALL1_E : detail::RAW_CALL1_P;
                    const uint16_t RAW_CALL2 = use_encode ? detail::RAW_CALL2_E : detail::RAW_CALL2_P;
                    const uint8_t  RAW_LOADB = use_encode ? detail::RAW_LOADB_E : detail::RAW_LOADB_P;
                    const uint8_t  RAW_MOVE  = use_encode ? detail::RAW_MOVE_E  : detail::RAW_MOVE_P;

                    if (broken_const) has_imports = true;
                    uint64_t active_imp_gen = 0;
                    if (has_imports) {
                        active_imp_gen = ++import_gen_counter_;
                        scratch_dirty_ = true;
                    }

                    int max_reg = 0;
                    size_t off = insn_base;

                    while (off < insn_end) {
                        uint8_t raw = buf[off];
                        uint32_t stp = STEP[raw];
                        if (stp > insn_end - off) break;
                        size_t nxt = off + stp;
                        uint16_t c = CLS[raw];

                        if (c != 0) {
                            if (c == 1) {
                                scratch_reg_[buf[off + 1] + 1] = 0;
                            } else {
                                uint16_t tid = 0;
                                if (c < 100) {
                                    if (c < 4) {
                                        uint8_t a = buf[off + 1];
                                        int r1 = a + 1;
                                        uint32_t idx1 = (c == 2 ? detail::read_u32_le(buf + off + 4) : detail::read_u16_le(buf + off + 4)) + 1u;
                                        int32_t sidx = (idx1 <= parsed_consts) ? scratch_const_sidx_[idx1] : 0;
                                        if (sidx > 0 && scratch_str_len_[sidx] > 0) {
                                            if (scratch_fs_get_[sidx] != script_gen) {
                                                bool is_call = false;
                                                if (nxt < insn_end) {
                                                    uint16_t w = detail::read_u16_le(buf + nxt);
                                                    uint16_t ca = static_cast<uint16_t>(a) << 8;
                                                    if (w == RAW_CALL1 + ca || w == RAW_CALL2 + ca) is_call = true;
                                                }
                                                if (!is_call) {
                                                    scratch_fs_get_[sidx] = script_gen;
                                                    wpos = write_blob_prefixed(wpos, "get:", 4, bc_data + scratch_str_off_[sidx], scratch_str_len_[sidx]);
                                                }
                                            }
                                            scratch_reg_[r1] = sidx;
                                        } else {
                                            scratch_reg_[r1] = 0;
                                        }
                                        if (r1 > max_reg) max_reg = r1;
                                    } else if (c == 4) {
                                        uint8_t a = buf[off + 1];
                                        int r1 = a + 1;
                                        int32_t cp = scratch_reg_[r1];
                                        if (cp > 0) {
                                            if (cp < detail::IMPBASE) {
                                                if (scratch_fs_call_[cp] != script_gen) {
                                                    scratch_fs_call_[cp] = script_gen;
                                                    uint32_t slen = scratch_str_len_[cp], soff = scratch_str_off_[cp];
                                                    uint16_t st_id = st.find_builtin_raw_id(std::string_view(bc_data + soff, slen));
                                                    if (st_id != 0) tid = st_id;
                                                    else wpos = write_blob_prefixed(wpos, "call:", 5, bc_data + soff, slen);
                                                }
                                            } else {
                                                uint32_t id = static_cast<uint32_t>(cp - detail::IMPBASE);
                                                ImportTuple& tup = scratch_tuples_[id];
                                                if (tup.done != script_gen) {
                                                    tup.done = script_gen;
                                                    if (tup.ctid != 0) tid = tup.ctid;
                                                    else {
                                                        std::string_view cpat = scratch_t_cpat_sv_[id];
                                                        if (scratch_imp_seen_.insert(cpat)) {
                                                            size_t need = wpos + cpat.size() + 1;
                                                            ensure_blob_cap(need);
                                                            std::memcpy(scratch_blob_buf_.data() + wpos, cpat.data(), cpat.size());
                                                            scratch_blob_buf_[wpos + cpat.size()] = '\0';
                                                            wpos = need;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        int nres = static_cast<int>(buf[off + 3]) - 1;
                                        if (nres < 0) {
                                            for (int r = r1; r <= max_reg; ++r) scratch_reg_[r] = 0;
                                            scratch_reg_[r1] = -3;
                                            if (r1 > max_reg) max_reg = r1;
                                        } else if (nres == 0) {
                                            scratch_reg_[r1] = 0;
                                        } else {
                                            int top = static_cast<int>(a) + nres;
                                            for (int r = r1; r <= top; ++r) scratch_reg_[r] = -3;
                                            if (top > max_reg) max_reg = top;
                                        }
                                    } else if (c == 5) {
                                        int r1 = buf[off + 1] + 1;
                                        scratch_reg_[r1] = scratch_reg_[buf[off + 2] + 1];
                                        if (r1 > max_reg) max_reg = r1;
                                    } else if (c == 6) {
                                        uint8_t a = buf[off + 1];
                                        int r1 = a + 1;
                                        uint32_t id = 0;
                                        if (has_imports) {
                                            uint32_t idx1 = static_cast<uint32_t>(detail::read_u16_le(buf + off + 2)) + 1u;
                                            if (idx1 <= parsed_consts) {
                                                if (scratch_imp_stamp_[idx1] == active_imp_gen) {
                                                    id = scratch_imp_tid_[idx1];
                                                } else {
                                                    scratch_imp_stamp_[idx1] = active_imp_gen;
                                                    id = resolve_import_safe(bc_data, parsed_consts, idx1);
                                                    scratch_imp_tid_[idx1] = id;
                                                }
                                            }
                                        }
                                        if (id != 0) {
                                            const ImportTuple& tup = scratch_tuples_[id];
                                            uint32_t pid = tup.pid;
                                            std::string_view path_sv = scratch_t_path_sv_[id];
                                            if (scratch_p_imp_[pid] != script_gen) {
                                                scratch_p_imp_[pid] = script_gen;
                                                wpos = write_blob_prefixed(wpos, "import:", 7, path_sv.data(), path_sv.size());
                                            }
                                            if (scratch_p_get_[pid] != script_gen) {
                                                bool is_call = false;
                                                if (nxt < insn_end) {
                                                    uint16_t w = detail::read_u16_le(buf + nxt);
                                                    uint16_t ca = static_cast<uint16_t>(a) << 8;
                                                    if (w == RAW_CALL1 + ca || w == RAW_CALL2 + ca) is_call = true;
                                                }
                                                if (!is_call) {
                                                    scratch_p_get_[pid] = script_gen;
                                                    wpos = write_blob_prefixed(wpos, "get:", 4, path_sv.data(), path_sv.size());
                                                }
                                            }
                                            scratch_reg_[r1] = tup.last_k != 0
                                                ? static_cast<int32_t>(tup.last_k)
                                                : (detail::IMPBASE + static_cast<int32_t>(id));
                                        } else {
                                            scratch_reg_[r1] = 0;
                                        }
                                        if (r1 > max_reg) max_reg = r1;
                                    } else if (c < 9) {
                                        int r1 = buf[off + 1] + 1;
                                        uint32_t idx1 = (c == 7 ? detail::read_u32_le(buf + off + 4) : detail::read_u16_le(buf + off + 4)) + 1u;
                                        int32_t sidx = (idx1 <= parsed_consts) ? scratch_const_sidx_[idx1] : 0;
                                        if (sidx > 0 && scratch_str_len_[sidx] > 0) {
                                            uint32_t slen = scratch_str_len_[sidx], soff = scratch_str_off_[sidx];
                                            if (scratch_fs_meth_[sidx] != script_gen) {
                                                scratch_fs_meth_[sidx] = script_gen;
                                                wpos = write_blob_prefixed(wpos, "method:", 7, bc_data + soff, slen);
                                            }
                                            if (scratch_fs_call_[sidx] != script_gen) {
                                                scratch_fs_call_[sidx] = script_gen;
                                                uint16_t st_id = st.find_builtin_raw_id(std::string_view(bc_data + soff, slen));
                                                if (st_id != 0) tid = st_id;
                                                else wpos = write_blob_prefixed(wpos, "call:", 5, bc_data + soff, slen);
                                            }
                                            scratch_reg_[r1] = sidx;
                                        } else {
                                            scratch_reg_[r1] = 0;
                                        }
                                        int r2 = r1 + 1;
                                        scratch_reg_[r2] = 0;
                                        if (r2 > max_reg) max_reg = r2;
                                    } else if (c < 12) {
                                        if (c != 11 || buf[off + 2] == 0) {
                                            uint32_t idx1 = (c == 10 ? detail::read_u16_le(buf + off + 4) : detail::read_u32_le(buf + off + 4)) + 1u;
                                            int32_t sidx = (idx1 <= parsed_consts) ? scratch_const_sidx_[idx1] : 0;
                                            if (sidx > 0 && scratch_fs_set_[sidx] != script_gen) {
                                                uint32_t slen = scratch_str_len_[sidx];
                                                if (slen > 0) {
                                                    scratch_fs_set_[sidx] = script_gen;
                                                    wpos = write_blob_prefixed(wpos, "set:", 4, bc_data + scratch_str_off_[sidx], slen);
                                                }
                                            }
                                        }
                                    } else if (c == 12) {
                                        if (buf[off + 2] == 1) tid = 1;
                                        else {
                                            int32_t v = scratch_reg_[buf[off + 1] + 1];
                                            tid = (v < 0) ? static_cast<uint16_t>(-v) : 2;
                                        }
                                    } else if (c < 15) {
                                        bool is_andor = false;
                                        int64_t target_off = static_cast<int64_t>(off) + 4 + static_cast<int64_t>(detail::read_i16_le(buf + off + 2)) * 4;
                                        if (target_off >= static_cast<int64_t>(insn_base) && target_off < static_cast<int64_t>(insn_end)) {
                                            uint8_t top = buf[target_off];
                                            if (top == RAW_LOADB) is_andor = (buf[target_off + 3] != 0);
                                            else if (top == RAW_MOVE) is_andor = true;
                                        }
                                        if (c == 13) {
                                            if (is_andor) tid = 9;
                                            else {
                                                if (scratch_tag_seen_[8] != script_gen) {
                                                    scratch_tag_seen_[8] = script_gen;
                                                    wpos = write_blob_bytes(wpos, st.owned_tags[8].data(), st.tag_len[8]);
                                                }
                                                tid = 7;
                                            }
                                        } else {
                                            tid = is_andor ? 10 : 7;
                                        }
                                    } else if (c == 15) {
                                        int r1 = buf[off + 1] + 1;
                                        scratch_reg_[r1] = -4;
                                        if (r1 > max_reg) max_reg = r1;
                                    } else if (c == 16) {
                                        int r1 = buf[off + 1] + 1;
                                        uint8_t b = buf[off + 2];
                                        scratch_reg_[r1] = (b == 0) ? -5 : ((b == 1) ? -6 : 0);
                                        if (r1 > max_reg) max_reg = r1;
                                    } else if (c == 17) {
                                        tid = ot.fastcall_tid[buf[off + 1]];
                                    } else if (c == 18) {
                                        tid = (buf[off + 7] >= 128) ? 13 : 12;
                                    } else if (c == 19) {
                                        int r1 = buf[off + 1] + 1;
                                        tid = 18;
                                        scratch_reg_[r1 + 2] = 0; scratch_reg_[r1 + 3] = 0;
                                    } else if (c == 20) {
                                        int r1 = buf[off + 1] + 1;
                                        tid = 19;
                                        int end_r = r1 + 2 + buf[off + 4];
                                        for (int r = r1 + 2; r <= end_r; ++r) scratch_reg_[r] = 0;
                                    } else if (c == 21) {
                                        uint8_t a = buf[off + 1];
                                        int r1 = a + 1;
                                        uint8_t b = buf[off + 2];
                                        tid = 25;
                                        if (b == 0) {
                                            for (int r = r1; r <= max_reg; ++r) scratch_reg_[r] = 0;
                                        } else if (b >= 2) {
                                            int top = static_cast<int>(a) + static_cast<int>(b) - 1;
                                            for (int r = r1; r <= top; ++r) scratch_reg_[r] = 0;
                                        }
                                    } else {
                                        uint8_t a = buf[off + 1];
                                        if (a == 0) tid = 38;
                                        else if (a == 1) tid = 39;
                                    }
                                } else if (c < 200) {
                                    tid = c - 100;
                                } else if (c < 300) {
                                    tid = c - 200;
                                    scratch_reg_[buf[off + 1] + 1] = 0;
                                } else {
                                    tid = c - 300;
                                    int r1 = buf[off + 1] + 1;
                                    scratch_reg_[r1] = scratch_reg_[r1 + 1] = scratch_reg_[r1 + 2] = scratch_reg_[r1 + 3] = 0;
                                }

                                if (tid != 0 && scratch_tag_seen_[tid] != script_gen) {
                                    scratch_tag_seen_[tid] = script_gen;
                                    wpos = write_blob_bytes(wpos, st.owned_tags[tid].data(), st.tag_len[tid]);
                                }
                            }
                        }
                        off = nxt;
                    }
                    scratch_max_reg_ = max_reg;
                }
            }

            if (broken_const) {
                if (has_size) pos = blob_end;
                else break;
            } else {
                if (bp < limit) {
                    uint64_t child_count = 0;
                    if (!read_varint(buf, bp, limit, blen, child_count)) return false;
                    for (uint64_t j = 0; j < child_count; ++j) {
                        uint64_t cv = 0;
                        if (!read_varint(buf, bp, limit, blen, cv)) return false;
                    }
                    uint64_t ld = 0, didx = 0;
                    if (!read_varint(buf, bp, limit, blen, ld)) return false;
                    if (!read_varint(buf, bp, limit, blen, didx)) return false;
                    if (didx >= 1 && didx <= str_count) {
                        uint32_t di = static_cast<uint32_t>(didx);
                        if (scratch_fs_func_[di] != script_gen && scratch_str_len_[di] > 0) {
                            scratch_fs_func_[di] = script_gen;
                            wpos = write_blob_prefixed(wpos, "func:", 5, bc_data + scratch_str_off_[di], scratch_str_len_[di]);
                        }
                    }

                    if (bp < limit) {
                        if (bp >= blen) return false;
                        if (buf[bp] == 1) {
                            if (bp + 1 >= limit) {
                                if (has_size) bp = limit;
                                else return false;
                            } else {
                                if (bp + 1 >= blen) return false;
                                uint8_t linegap = buf[bp + 1];
                                uint64_t intervals = (insn_count > 0 && linegap < 32)
                                    ? (((insn_count - 1) >> linegap) + 1)
                                    : 1;
                                uint64_t skip = 2 + insn_count + intervals * 4;
                                if (skip > std::numeric_limits<size_t>::max() - bp) bp = std::numeric_limits<size_t>::max();
                                else bp += static_cast<size_t>(skip);
                            }
                        } else {
                            ++bp;
                        }
                    }

                    if (bp < limit) {
                        if (bp >= blen) return false;
                        if (buf[bp] == 1) {
                            ++bp;
                            uint64_t lc = 0;
                            if (!read_varint(buf, bp, limit, blen, lc)) return false;
                            for (uint64_t j = 0; j < lc; ++j) {
                                uint64_t vidx = 0;
                                if (!read_varint(buf, bp, limit, blen, vidx)) return false;
                                if (vidx >= 1 && vidx <= str_count) {
                                    uint32_t vi = static_cast<uint32_t>(vidx);
                                    if (scratch_fs_loc_[vi] != script_gen && scratch_str_len_[vi] > 0) {
                                        scratch_fs_loc_[vi] = script_gen;
                                        wpos = write_blob_prefixed(wpos, "local:", 6, bc_data + scratch_str_off_[vi], scratch_str_len_[vi]);
                                    }
                                }
                                if (bp >= limit) return false;
                                uint64_t b1 = 0, b2 = 0;
                                if (!read_varint(buf, bp, limit, blen, b1)) return false;
                                if (bp >= limit) return false;
                                if (!read_varint(buf, bp, limit, blen, b2)) return false;
                                ++bp;
                            }
                            if (bp < limit) {
                                uint64_t uc = 0;
                                if (!read_varint(buf, bp, limit, blen, uc)) return false;
                                for (uint64_t j = 0; j < uc; ++j) {
                                    uint64_t uidx = 0;
                                    if (!read_varint(buf, bp, limit, blen, uidx)) return false;
                                    if (uidx >= 1 && uidx <= str_count) {
                                        uint32_t ui = static_cast<uint32_t>(uidx);
                                        if (scratch_fs_upv_[ui] != script_gen && scratch_str_len_[ui] > 0) {
                                            scratch_fs_upv_[ui] = script_gen;
                                            wpos = write_blob_prefixed(wpos, "upval:", 6, bc_data + scratch_str_off_[ui], scratch_str_len_[ui]);
                                        }
                                    }
                                }
                            }
                        } else {
                            ++bp;
                        }
                    }
                }

                if (has_size) {
                    pos = blob_end;
                } else {
                    if ((version >= 11 || version == 100) && bp < limit) {
                        uint64_t fb = 0;
                        if (!read_varint(buf, bp, limit, blen, fb)) return false;
                        for (uint64_t j = 0; j < fb; ++j) {
                            ++bp;
                            uint64_t fv = 0;
                            if (!read_varint(buf, bp, limit, blen, fv)) return false;
                        }
                    }
                    pos = bp;
                }
            }
        }

        if (wpos <= 1) return false;
        out_blob.assign(scratch_blob_buf_.data(), wpos);
        return true;
    }

    static inline bool check_bare_token_at(const std::string& raw_blob, const std::string& low_blob,
                                           const detail::SearchPattern& lpat, size_t pos) noexcept {
        const char* raw = raw_blob.data();
        const size_t rlen = raw_blob.size();
        const size_t nlen = lpat.needle.size();
        const int8_t* KIND = detail::KIND_LUT.data();

        while (pos != std::string::npos) {
            bool start_ok = false;
            if (pos == 0 || raw[pos - 1] == '\0') {
                size_t p = pos;
                start_ok = true;
                while (p < rlen) {
                    char ch = raw[p];
                    if (ch == '\0') break;
                    if (ch == ':') { start_ok = false; break; }
                    ++p;
                }
            } else {
                int8_t pk = KIND[static_cast<uint8_t>(raw[pos - 1])];
                if (pk < 0) start_ok = true;
                else {
                    int8_t fk = KIND[static_cast<uint8_t>(raw[pos])];
                    if (fk < 0) start_ok = true;
                    else if (fk == 2) start_ok = (pk == 1 || pk == 0 || (pk == 2 && pos + 1 < rlen && KIND[static_cast<uint8_t>(raw[pos + 1])] == 1));
                    else if (fk == 0) start_ok = (pk > 0);
                    else start_ok = (pk == 0);
                }
            }
            if (start_ok) {
                size_t e_pos = pos + nlen - 1;
                if (e_pos + 1 >= rlen) return true;
                int8_t nk = KIND[static_cast<uint8_t>(raw[e_pos + 1])];
                if (nk < 0) return true;
                int8_t lk = KIND[static_cast<uint8_t>(raw[e_pos])];
                if (lk < 0) return true;
                if (nk == 2) {
                    if (lk == 1 || lk == 0 || (lk == 2 && e_pos + 2 < rlen && KIND[static_cast<uint8_t>(raw[e_pos + 2])] == 1))
                        return true;
                } else if (nk == 0) {
                    if (lk > 0) return true;
                } else if (lk == 0) {
                    return true;
                }
            }
            pos = detail::fast_find(low_blob, lpat, pos + 1);
        }
        return false;
    }

    static inline bool check_bare_prefix_at(const std::string& raw_blob, const std::string& low_blob,
                                            const detail::SearchPattern& lpat, size_t pos) noexcept {
        const char* raw = raw_blob.data();
        const size_t rlen = raw_blob.size();
        const int8_t* KIND = detail::KIND_LUT.data();

        while (pos != std::string::npos) {
            if (pos == 0 || raw[pos - 1] == '\0') {
                size_t p = pos;
                bool ok = true;
                while (p < rlen) {
                    char ch = raw[p];
                    if (ch == '\0') break;
                    if (ch == ':') { ok = false; break; }
                    ++p;
                }
                if (ok) return true;
            } else {
                int8_t pk = KIND[static_cast<uint8_t>(raw[pos - 1])];
                if (pk < 0) return true;
                int8_t fk = KIND[static_cast<uint8_t>(raw[pos])];
                if (fk < 0) return true;
                if (fk == 2) {
                    if (pk == 1 || pk == 0 || (pk == 2 && pos + 1 < rlen && KIND[static_cast<uint8_t>(raw[pos + 1])] == 1))
                        return true;
                } else if (fk == 0) {
                    if (pk > 0) return true;
                } else if (pk == 0) {
                    return true;
                }
            }
            pos = detail::fast_find(low_blob, lpat, pos + 1);
        }
        return false;
    }

    static inline const std::string& ensure_low_blob(Entry& e) {
        if (!e.has_low_blob) {
            e.low_blob.resize(e.raw_blob.size());
            detail::to_lower_ascii(e.raw_blob.data(), &e.low_blob[0], e.raw_blob.size());
            e.has_low_blob = true;
        }
        return e.low_blob;
    }

    static const std::vector<std::string_view>& entry_words(Entry& e) {
        if (e.has_word_list) return e.word_list;
        const std::string& rb = e.raw_blob;
        const size_t rlen = rb.size();
        const char* p = rb.data();
        size_t pos = 1;
        while (pos < rlen) {
            const void* z = std::memchr(p + pos, '\0', rlen - pos);
            if (!z) break;
            size_t nxt = static_cast<size_t>(static_cast<const char*>(z) - p);
            if (nxt > pos) e.word_list.emplace_back(p + pos, nxt - pos);
            pos = nxt + 1;
        }
        e.has_word_list = true;
        return e.word_list;
    }

    inline bool entry_has_word(Entry& e, std::string_view term, const detail::SearchPattern& eneedle) {
        if (!e.has_word_set) {
            if (e.query_gen == 0 || e.query_gen == query_serial_) {
                e.query_gen = query_serial_;
                return detail::fast_find(e.raw_blob, eneedle) != std::string_view::npos;
            }
            const auto& wlist = entry_words(e);
            e.word_set.reserve(wlist.size());
            for (std::string_view w : wlist) e.word_set.insert(w);
            e.has_word_set = true;
        }
        return e.word_set.contains(term);
    }

    Entry* parse_slot(uint32_t sidx, std::string_view bc) {
        CacheSlot& slot = slots_[sidx];
        slot.low_hdr.clear();
        slot.low_hdr.shrink_to_fit();
        if (parse_and_extract(bc, slot.entry.raw_blob)) {
            slot.state = SlotState::Parsed;
            return &slot.entry;
        }
        slot.state = SlotState::Invalid;
        return nullptr;
    }

    Entry* parse_and_cache(std::string_view bc, uint64_t h) {
        bool created = false;
        uint32_t sidx = get_or_create_slot(bc, h, created);
        return parse_slot(sidx, bc);
    }

    Entry* get_entry(std::string_view bc) {
        if (bc.size() < 2) return nullptr;
        uint64_t h = detail::hash_sv(bc);
        bool created = false;
        uint32_t sidx = get_or_create_slot(bc, h, created);
        CacheSlot& slot = slots_[sidx];
        if (!created) {
            if (slot.state == SlotState::Parsed) return &slot.entry;
            if (slot.state == SlotState::Invalid) return nullptr;
        }
        return parse_slot(sidx, bc);
    }

    static std::optional<std::string_view> longest_dot_segment(std::string_view val) noexcept {
        std::optional<std::string_view> best;
        size_t best_len = 0, start = 0, vlen = val.size();
        while (start < vlen) {
            size_t dot = val.find('.', start);
            size_t seg_end = (dot == std::string_view::npos) ? vlen : dot;
            size_t seg_len = seg_end - start;
            if (seg_len > best_len) { best_len = seg_len; best = val.substr(start, seg_len); }
            if (dot == std::string_view::npos) break;
            start = dot + 1;
        }
        return best;
    }

    static bool matches_builtin_prefix(std::string_view val) noexcept {
        for (std::string_view bn : detail::static_tags().builtin_list) {
            if (bn.size() >= val.size() && bn.compare(0, val.size(), val) == 0) return true;
        }
        return false;
    }

    static std::optional<std::string_view> extract_cold_hint(std::string_view term, bool is_prefix) noexcept {
        size_t colon = term.find(':');
        if (colon == std::string_view::npos) return std::nullopt;
        std::string_view tag = term.substr(0, colon);
        if (!detail::is_hint_tag(tag)) return std::nullopt;
        std::string_view val = term.substr(colon + 1);
        if (val.empty()) return std::nullopt;
        if (tag == "call") {
            if (is_prefix) return matches_builtin_prefix(val) ? std::nullopt : std::optional<std::string_view>(val);
            return detail::static_tags().find_tag_id(term) != 0 ? std::nullopt : std::optional<std::string_view>(val);
        }
        if (tag == "import" || tag == "get") {
            if (val.find('.') != std::string_view::npos) {
                return is_prefix ? std::nullopt : longest_dot_segment(val);
            }
            return val;
        }
        return val;
    }

    static std::optional<std::string_view> extract_cold_ci_hint(std::string_view lneedle) noexcept {
        if (lneedle.empty()) return std::nullopt;
        const std::string& hay = detail::static_tags().static_ci_haystack;
        if (detail::fast_find_sv(hay, lneedle) != std::string_view::npos) return std::nullopt;
        return lneedle;
    }

    const std::string* get_or_build_low_hdr(std::string_view bc, uint64_t h, uint32_t& out_slot_idx) {
        auto hdr_opt = get_str_table_slice(bc);
        bool created = false;
        uint32_t sidx = get_or_create_slot(bc, h, created);
        out_slot_idx = sidx;
        CacheSlot& slot = slots_[sidx];
        if (!hdr_opt) { slot.state = SlotState::Invalid; return nullptr; }
        slot.state = SlotState::HdrOnly;
        slot.low_hdr.resize(hdr_opt->size());
        if (!hdr_opt->empty()) detail::to_lower_ascii(hdr_opt->data(), &slot.low_hdr[0], hdr_opt->size());
        return &slot.low_hdr;
    }

    static void compile_terms(std::string_view const* terms, size_t nterms, CompiledTerms& out) {
        out.exact.clear(); out.prefix.clear(); out.bare.clear();
        out.bare_prefix.clear(); out.frag.clear(); out.cold_hints.clear(); out.cold_ci.clear();
        out.valid = false;

        for (size_t t = 0; t < nterms; ++t) {
            std::string_view term = terms[t];
            if (term.empty()) return;

            if (term[0] == '~') {
                std::string_view needle = term.substr(1);
                if (!needle.empty()) {
                    std::string lneedle = detail::to_lower_str(needle);
                    bool alpha = detail::has_ascii_alpha(needle);
                    if (auto ch = extract_cold_ci_hint(lneedle)) {
                        typename CompiledTerms::ColdCiHint cci;
                        cci.ci = detail::SearchPattern(std::string(*ch));
                        if (alpha) {
                            std::string tstr(*ch);
                            tstr[0] = detail::to_upper_ascii_char(tstr[0]);
                            cci.title = detail::SearchPattern(std::move(tstr));
                            cci.has_title = true;
                        }
                        out.cold_ci.push_back(std::move(cci));
                    }
                    typename CompiledTerms::FragTerm ft;
                    ft.raw = detail::SearchPattern(std::string(needle));
                    ft.lower = detail::SearchPattern(std::move(lneedle));
                    ft.has_alpha = alpha;
                    out.frag.push_back(std::move(ft));
                }
            } else if (term.back() == '*') {
                std::string_view needle = term.substr(0, term.size() - 1);
                if (!needle.empty()) {
                    if (needle.find(':') != std::string_view::npos) {
                        std::string p; p.reserve(1 + needle.size()); p.push_back('\0'); p.append(needle);
                        out.prefix.emplace_back(std::move(p));
                        if (auto h = extract_cold_hint(needle, true)) out.cold_hints.emplace_back(std::string(*h));
                    } else {
                        std::string lneedle = detail::to_lower_str(needle);
                        if (auto ch = extract_cold_ci_hint(lneedle)) {
                            typename CompiledTerms::ColdCiHint cci;
                            cci.ci = detail::SearchPattern(std::string(*ch));
                            if (detail::has_ascii_alpha(needle)) {
                                std::string tstr(*ch);
                                tstr[0] = detail::to_upper_ascii_char(tstr[0]);
                                cci.title = detail::SearchPattern(std::move(tstr));
                                cci.has_title = true;
                            }
                            out.cold_ci.push_back(std::move(cci));
                        }
                        out.bare_prefix.emplace_back(std::move(lneedle));
                    }
                }
            } else {
                if (term.find(':') != std::string_view::npos) {
                    std::string e; e.reserve(2 + term.size()); e.push_back('\0'); e.append(term); e.push_back('\0');
                    typename CompiledTerms::ExactTerm et;
                    et.needle = detail::SearchPattern(std::move(e));
                    et.plain_ok = (term.find('\0') == std::string_view::npos);
                    out.exact.push_back(std::move(et));
                    if (auto h = extract_cold_hint(term, false)) out.cold_hints.emplace_back(std::string(*h));
                } else {
                    std::string lterm = detail::to_lower_str(term);
                    std::string fn; fn.reserve(2 + term.size());
                    fn.push_back(term == "concat" ? '\0' : ':'); fn.append(term); fn.push_back('\0');
                    if (auto ch = extract_cold_ci_hint(lterm)) {
                        typename CompiledTerms::ColdCiHint cci;
                        cci.ci = detail::SearchPattern(std::string(*ch));
                        if (detail::has_ascii_alpha(term)) {
                            std::string tstr(*ch);
                            tstr[0] = detail::to_upper_ascii_char(tstr[0]);
                            cci.title = detail::SearchPattern(std::move(tstr));
                            cci.has_title = true;
                        }
                        out.cold_ci.push_back(std::move(cci));
                    }
                    typename CompiledTerms::BareTerm bt;
                    bt.fast_needle = detail::SearchPattern(std::move(fn));
                    bt.lower_needle = detail::SearchPattern(std::move(lterm));
                    out.bare.push_back(std::move(bt));
                }
            }
        }

        if (out.exact.size() > 1) {
            std::sort(out.exact.begin(), out.exact.end(), [](const auto& a, const auto& b) {
                return a.needle.needle.size() > b.needle.needle.size();
            });
        }
        for (auto& et : out.exact) {
            et.term_view = std::string_view(et.needle.needle.data() + 1, et.needle.needle.size() - 2);
        }
        out.valid = true;
    }

    inline bool entry_matches(Entry& e, const CompiledTerms& ct) {
        const std::string& raw_blob = e.raw_blob;
        for (const auto& et : ct.exact) {
            if (et.plain_ok) {
                if (!entry_has_word(e, et.term_view, et.needle)) return false;
            } else if (detail::fast_find(raw_blob, et.needle) == std::string_view::npos) return false;
        }
        for (const auto& p : ct.prefix) {
            if (detail::fast_find(raw_blob, p) == std::string_view::npos) return false;
        }
        for (const auto& bt : ct.bare) {
            if (e.has_low_blob || detail::fast_find(raw_blob, bt.fast_needle) == std::string_view::npos) {
                const std::string& lb = ensure_low_blob(e);
                size_t pos = detail::fast_find(lb, bt.lower_needle);
                if (pos == std::string_view::npos || !check_bare_token_at(raw_blob, lb, bt.lower_needle, pos)) return false;
            }
        }
        for (const auto& bp : ct.bare_prefix) {
            const std::string& lb = ensure_low_blob(e);
            size_t pos = detail::fast_find(lb, bp);
            if (pos == std::string_view::npos || !check_bare_prefix_at(raw_blob, lb, bp, pos)) return false;
        }
        for (const auto& ft : ct.frag) {
            if (ft.has_alpha) {
                if (e.has_low_blob) {
                    if (detail::fast_find(e.low_blob, ft.lower) == std::string_view::npos) return false;
                } else if (detail::fast_find(raw_blob, ft.raw) == std::string_view::npos) {
                    const std::string& lb = ensure_low_blob(e);
                    if (detail::fast_find(lb, ft.lower) == std::string_view::npos) return false;
                }
            } else if (detail::fast_find(raw_blob, ft.raw) == std::string_view::npos) return false;
        }
        return true;
    }

    inline Entry* resolve_for_query_cold(
        std::string_view bc, uint64_t h, bool has_hash,
        const CompiledTerms& ct, bool& did_parse, uint32_t* slot_hint = nullptr)
    {
        for (const auto& ch : ct.cold_hints) {
            if (detail::fast_find(bc, ch) == std::string_view::npos) return nullptr;
        }
        if (!ct.cold_ci.empty()) {
            bool all_fast = true;
            for (const auto& cci : ct.cold_ci) {
                if (!((cci.has_title && detail::fast_find(bc, cci.title) != std::string_view::npos) ||
                      detail::fast_find(bc, cci.ci) != std::string_view::npos)) {
                    all_fast = false; break;
                }
            }
            if (!all_fast) {
                if (!has_hash) { h = detail::hash_sv(bc); has_hash = true; }
                uint32_t sidx = 0;
                const std::string* lh = get_or_build_low_hdr(bc, h, sidx);
                if (slot_hint) *slot_hint = sidx;
                if (!lh) return nullptr;
                for (const auto& cci : ct.cold_ci) {
                    if (detail::fast_find(*lh, cci.ci) == std::string_view::npos) return nullptr;
                }
            }
        }
        if (!has_hash) h = detail::hash_sv(bc);
        bool created = false;
        uint32_t sidx = get_or_create_slot(bc, h, created);
        if (slot_hint) *slot_hint = sidx;
        did_parse = true;
        return parse_slot(sidx, bc);
    }

    inline Entry* resolve_for_query(
        std::string_view bc, uint64_t h, bool has_hash,
        const CompiledTerms& ct, bool& did_parse, uint32_t* slot_hint = nullptr)
    {
        if (map_size_ == 0) return resolve_for_query_cold(bc, h, has_hash, ct, did_parse, slot_hint);
        if (!has_hash) { h = detail::hash_sv(bc); has_hash = true; }
        uint32_t sidx = find_slot_idx(bc, h);
        if (sidx == UINT32_MAX) return resolve_for_query_cold(bc, h, true, ct, did_parse, slot_hint);
        if (slot_hint) *slot_hint = sidx;
        CacheSlot& slot = slots_[sidx];
        if (slot.state == SlotState::Parsed) return &slot.entry;
        if (slot.state == SlotState::Invalid) return nullptr;
        for (const auto& ch : ct.cold_hints) {
            if (detail::fast_find(bc, ch) == std::string_view::npos) return nullptr;
        }
        for (const auto& cci : ct.cold_ci) {
            if (detail::fast_find(slot.low_hdr, cci.ci) == std::string_view::npos) return nullptr;
        }
        did_parse = true;
        return parse_slot(sidx, bc);
    }

    std::vector<uint32_t> filter_single_term(
        std::string_view const* bytecodes, size_t nbc, std::string_view term,
        const uint64_t* pre_hashes = nullptr, uint32_t* slot_hints = nullptr)
    {
        std::vector<uint32_t> matches;
        if (term.empty()) return matches;

        auto lookup_slot = [&](size_t i, uint64_t& h, bool& has_h) -> uint32_t {
            if (slot_hints && slot_hints[i] != UINT32_MAX) return slot_hints[i];
            if (map_size_ == 0) return UINT32_MAX;
            if (pre_hashes) { h = pre_hashes[i]; has_h = true; }
            else if (!has_h) { h = detail::hash_sv(bytecodes[i]); has_h = true; }
            uint32_t sidx = find_slot_idx(bytecodes[i], h);
            if (slot_hints && sidx != UINT32_MAX) slot_hints[i] = sidx;
            return sidx;
        };

        auto ensure_parsed = [&](size_t i, uint32_t sidx, uint64_t h, bool has_h) -> Entry* {
            std::string_view bc = bytecodes[i];
            if (sidx == UINT32_MAX) {
                if (!has_h) h = pre_hashes ? pre_hashes[i] : detail::hash_sv(bc);
                bool created = false;
                sidx = get_or_create_slot(bc, h, created);
                if (slot_hints) slot_hints[i] = sidx;
            }
            return parse_slot(sidx, bc);
        };

        auto cold_ci_ok = [&](size_t i, uint32_t& sidx, uint64_t& h, bool& has_h,
                              const detail::SearchPattern& ci_pat, const detail::SearchPattern* title_pat) -> bool {
            std::string_view bc = bytecodes[i];
            if ((title_pat && detail::fast_find(bc, *title_pat) != std::string_view::npos) ||
                detail::fast_find(bc, ci_pat) != std::string_view::npos) return true;
            if (!has_h) { h = pre_hashes ? pre_hashes[i] : detail::hash_sv(bc); has_h = true; }
            const std::string* lh = get_or_build_low_hdr(bc, h, sidx);
            if (slot_hints) slot_hints[i] = sidx;
            return lh != nullptr && detail::fast_find(*lh, ci_pat) != std::string_view::npos;
        };

        if (term[0] == '~') {
            std::string_view needle = term.substr(1);
            bool non_empty = !needle.empty();
            std::string lneedle = detail::to_lower_str(needle);
            bool has_alpha = non_empty && detail::has_ascii_alpha(needle);
            auto ci_hint_opt = non_empty ? extract_cold_ci_hint(lneedle) : std::nullopt;
            bool has_ci = ci_hint_opt.has_value();
            detail::SearchPattern ci_pat = has_ci ? detail::SearchPattern(std::string(*ci_hint_opt)) : detail::SearchPattern{};
            bool has_title = has_ci && has_alpha;
            detail::SearchPattern title_pat;
            if (has_title) {
                std::string ts(*ci_hint_opt); ts[0] = detail::to_upper_ascii_char(ts[0]);
                title_pat = detail::SearchPattern(std::move(ts));
            }
            detail::SearchPattern raw_pat = non_empty ? detail::SearchPattern(std::string(needle)) : detail::SearchPattern{};
            detail::SearchPattern low_pat = (non_empty && has_alpha) ? detail::SearchPattern(std::move(lneedle)) : detail::SearchPattern{};

            for (size_t i = 0; i < nbc; ++i) {
                std::string_view bc = bytecodes[i];
                if (bc.size() < 2) continue;
                uint64_t h = 0; bool has_h = false;
                uint32_t sidx = lookup_slot(i, h, has_h);
                Entry* e = nullptr;
                if (sidx == UINT32_MAX) {
                    if (!has_ci || cold_ci_ok(i, sidx, h, has_h, ci_pat, has_title ? &title_pat : nullptr))
                        e = ensure_parsed(i, sidx, h, has_h);
                } else {
                    CacheSlot& sl = slots_[sidx];
                    if (sl.state == SlotState::Parsed) e = &sl.entry;
                    else if (sl.state == SlotState::HdrOnly && (!has_ci || detail::fast_find(sl.low_hdr, ci_pat) != std::string_view::npos))
                        e = parse_slot(sidx, bc);
                }
                if (!e) continue;
                if (!non_empty) matches.push_back(static_cast<uint32_t>(i));
                else if (has_alpha) {
                    if (e->has_low_blob) {
                        if (detail::fast_find(e->low_blob, low_pat) != std::string_view::npos) matches.push_back(static_cast<uint32_t>(i));
                    } else if (detail::fast_find(e->raw_blob, raw_pat) != std::string_view::npos) {
                        matches.push_back(static_cast<uint32_t>(i));
                    } else {
                        const std::string& lb = ensure_low_blob(*e);
                        if (detail::fast_find(lb, low_pat) != std::string_view::npos) matches.push_back(static_cast<uint32_t>(i));
                    }
                } else if (detail::fast_find(e->raw_blob, raw_pat) != std::string_view::npos) {
                    matches.push_back(static_cast<uint32_t>(i));
                }
            }
        } else if (term.back() == '*') {
            std::string_view needle = term.substr(0, term.size() - 1);
            bool non_empty = !needle.empty();
            if (needle.find(':') != std::string_view::npos) {
                std::string p; p.reserve(1 + needle.size()); p.push_back('\0'); p.append(needle);
                detail::SearchPattern ppat(std::move(p));
                auto hint_opt = extract_cold_hint(needle, true);
                bool has_hint = hint_opt.has_value();
                detail::SearchPattern hpat = has_hint ? detail::SearchPattern(std::string(*hint_opt)) : detail::SearchPattern{};

                for (size_t i = 0; i < nbc; ++i) {
                    std::string_view bc = bytecodes[i];
                    if (bc.size() < 2) continue;
                    uint64_t h = 0; bool has_h = false;
                    uint32_t sidx = lookup_slot(i, h, has_h);
                    Entry* e = nullptr;
                    if (sidx == UINT32_MAX || slots_[sidx].state == SlotState::HdrOnly) {
                        if (!has_hint || detail::fast_find(bc, hpat) != std::string_view::npos) e = ensure_parsed(i, sidx, h, has_h);
                    } else if (slots_[sidx].state == SlotState::Parsed) {
                        e = &slots_[sidx].entry;
                    }
                    if (e && (!non_empty || detail::fast_find(e->raw_blob, ppat) != std::string_view::npos))
                        matches.push_back(static_cast<uint32_t>(i));
                }
            } else {
                std::string lneedle = detail::to_lower_str(needle);
                auto ci_hint_opt = non_empty ? extract_cold_ci_hint(lneedle) : std::nullopt;
                bool has_ci = ci_hint_opt.has_value();
                detail::SearchPattern ci_pat = has_ci ? detail::SearchPattern(std::string(*ci_hint_opt)) : detail::SearchPattern{};
                bool has_title = has_ci && detail::has_ascii_alpha(needle);
                detail::SearchPattern title_pat;
                if (has_title) {
                    std::string ts(*ci_hint_opt); ts[0] = detail::to_upper_ascii_char(ts[0]);
                    title_pat = detail::SearchPattern(std::move(ts));
                }
                detail::SearchPattern lpat(std::move(lneedle));

                for (size_t i = 0; i < nbc; ++i) {
                    std::string_view bc = bytecodes[i];
                    if (bc.size() < 2) continue;
                    uint64_t h = 0; bool has_h = false;
                    uint32_t sidx = lookup_slot(i, h, has_h);
                    Entry* e = nullptr;
                    if (sidx == UINT32_MAX) {
                        if (!has_ci || cold_ci_ok(i, sidx, h, has_h, ci_pat, has_title ? &title_pat : nullptr))
                            e = ensure_parsed(i, sidx, h, has_h);
                    } else {
                        CacheSlot& sl = slots_[sidx];
                        if (sl.state == SlotState::Parsed) e = &sl.entry;
                        else if (sl.state == SlotState::HdrOnly && (!has_ci || detail::fast_find(sl.low_hdr, ci_pat) != std::string_view::npos))
                            e = parse_slot(sidx, bc);
                    }
                    if (!e) continue;
                    if (!non_empty) matches.push_back(static_cast<uint32_t>(i));
                    else {
                        const std::string& lb = ensure_low_blob(*e);
                        size_t pos = detail::fast_find(lb, lpat);
                        if (pos != std::string_view::npos && check_bare_prefix_at(e->raw_blob, lb, lpat, pos))
                            matches.push_back(static_cast<uint32_t>(i));
                    }
                }
            }
        } else if (term.find(':') != std::string_view::npos) {
            std::string en; en.reserve(2 + term.size()); en.push_back('\0'); en.append(term); en.push_back('\0');
            detail::SearchPattern epat(std::move(en));
            auto hint_opt = extract_cold_hint(term, false);
            bool has_hint = hint_opt.has_value();
            detail::SearchPattern hpat = has_hint ? detail::SearchPattern(std::string(*hint_opt)) : detail::SearchPattern{};
            bool plain_ok = (term.find('\0') == std::string_view::npos);

            for (size_t i = 0; i < nbc; ++i) {
                std::string_view bc = bytecodes[i];
                if (bc.size() < 2) continue;
                uint64_t h = 0; bool has_h = false;
                uint32_t sidx = lookup_slot(i, h, has_h);
                Entry* e = nullptr;
                if (sidx == UINT32_MAX || slots_[sidx].state == SlotState::HdrOnly) {
                    if (!has_hint || detail::fast_find(bc, hpat) != std::string_view::npos) e = ensure_parsed(i, sidx, h, has_h);
                } else if (slots_[sidx].state == SlotState::Parsed) {
                    e = &slots_[sidx].entry;
                }
                if (e) {
                    bool hit = plain_ok ? entry_has_word(*e, term, epat) : (detail::fast_find(e->raw_blob, epat) != std::string_view::npos);
                    if (hit) matches.push_back(static_cast<uint32_t>(i));
                }
            }
        } else {
            std::string en; en.reserve(2 + term.size());
            en.push_back(term == "concat" ? '\0' : ':'); en.append(term); en.push_back('\0');
            detail::SearchPattern epat(std::move(en));
            std::string lterm = detail::to_lower_str(term);
            auto ci_hint_opt = extract_cold_ci_hint(lterm);
            bool has_ci = ci_hint_opt.has_value();
            detail::SearchPattern ci_pat = has_ci ? detail::SearchPattern(std::string(*ci_hint_opt)) : detail::SearchPattern{};
            bool has_title = has_ci && detail::has_ascii_alpha(term);
            detail::SearchPattern title_pat;
            if (has_title) {
                std::string ts(*ci_hint_opt); ts[0] = detail::to_upper_ascii_char(ts[0]);
                title_pat = detail::SearchPattern(std::move(ts));
            }
            detail::SearchPattern lpat(std::move(lterm));

            for (size_t i = 0; i < nbc; ++i) {
                std::string_view bc = bytecodes[i];
                if (bc.size() < 2) continue;
                uint64_t h = 0; bool has_h = false;
                uint32_t sidx = lookup_slot(i, h, has_h);
                Entry* e = nullptr;
                if (sidx == UINT32_MAX) {
                    if (!has_ci || cold_ci_ok(i, sidx, h, has_h, ci_pat, has_title ? &title_pat : nullptr))
                        e = ensure_parsed(i, sidx, h, has_h);
                } else {
                    CacheSlot& sl = slots_[sidx];
                    if (sl.state == SlotState::Parsed) e = &sl.entry;
                    else if (sl.state == SlotState::HdrOnly && (!has_ci || detail::fast_find(sl.low_hdr, ci_pat) != std::string_view::npos))
                        e = parse_slot(sidx, bc);
                }
                if (!e) continue;
                if (!e->has_low_blob && detail::fast_find(e->raw_blob, epat) != std::string_view::npos) {
                    matches.push_back(static_cast<uint32_t>(i));
                } else {
                    const std::string& lb = ensure_low_blob(*e);
                    size_t pos = detail::fast_find(lb, lpat);
                    if (pos != std::string_view::npos && check_bare_token_at(e->raw_blob, lb, lpat, pos))
                        matches.push_back(static_cast<uint32_t>(i));
                }
            }
        }
        return matches;
    }

    std::pair<uint32_t, uint32_t> word_tokens_cached(std::string_view pat) {
        uint64_t h = detail::hash_sv(pat);
        if (const TokenSlice* cached = tok_memo_.find(pat, h)) return {cached->start, cached->count};
        const uint32_t start = static_cast<uint32_t>(tok_memo_pool_.size());
        size_t colon = pat.find(':');
        size_t base = (colon == std::string_view::npos) ? 0 : (colon + 1);
        const size_t len = pat.size();
        const size_t vlen = len - base;
        const int8_t* KIND = detail::KIND_LUT.data();

        if (vlen > 0 && vlen <= 4096) {
            char stack_buf[4096];
            detail::to_lower_ascii(pat.data() + base, stack_buf, vlen);
            auto emit_tok = [&](size_t s, size_t e) {
                tok_memo_pool_.push_back(tok_arena_.alloc_copy(std::string_view(stack_buf + (s - base), e - s + 1)));
            };
            size_t idx = base;
            while (idx < len) {
                int8_t k0 = KIND[static_cast<uint8_t>(pat[idx])];
                if (k0 < 0) {
                    ++idx;
                } else {
                    size_t seg_start = idx++;
                    while (idx < len && KIND[static_cast<uint8_t>(pat[idx])] >= 0) ++idx;
                    size_t seg_end = idx - 1;
                    emit_tok(seg_start, seg_end);
                    if (seg_end > seg_start) {
                        size_t sub_start = seg_start;
                        int8_t prev_k = k0;
                        for (size_t j = seg_start + 1; j <= seg_end; ++j) {
                            int8_t k = KIND[static_cast<uint8_t>(pat[j])];
                            if ((k == 0 && prev_k != 0) ||
                                (k != 0 && prev_k == 0) ||
                                (k == 2 && (prev_k == 1 || (prev_k == 2 && j < seg_end && KIND[static_cast<uint8_t>(pat[j + 1])] == 1)))) {
                                emit_tok(sub_start, j - 1);
                                sub_start = j;
                            }
                            prev_k = k;
                        }
                        if (sub_start > seg_start) emit_tok(sub_start, seg_end);
                    }
                }
            }
        }
        const uint32_t count = static_cast<uint32_t>(tok_memo_pool_.size() - start);
        if (len <= TOK_MEMO_KEY_MAX && tok_memo_n_ < TOK_MEMO_MAX) {
            tok_memo_.emplace(tok_arena_.alloc_copy(pat), TokenSlice{start, count}, h);
            ++tok_memo_n_;
        }
        return {start, count};
    }

    inline void fill_tmp_bvs(const std::vector<std::string>& v) {
        tmp_bvs_.clear();
        tmp_bvs_.reserve(v.size());
        for (const auto& s : v) tmp_bvs_.emplace_back(s);
    }

    inline void fill_tmp_tvs(const std::vector<std::string>& v) {
        tmp_tvs_.clear();
        tmp_tvs_.reserve(v.size());
        for (const auto& s : v) tmp_tvs_.emplace_back(s);
    }

public:
    BytecodeFilter() = default;

    std::vector<uint32_t> filter(
        std::string_view const* bytecodes, size_t nbc,
        std::string_view const* terms, size_t nterms)
    {
        ++query_serial_;
        std::vector<uint32_t> matches;

        if (nterms == 0) {
            for (size_t i = 0; i < nbc; ++i) {
                if (bytecodes[i].size() >= 2 && get_entry(bytecodes[i]) != nullptr)
                    matches.push_back(static_cast<uint32_t>(i));
            }
            return matches;
        }
        if (nterms == 1) return filter_single_term(bytecodes, nbc, terms[0]);

        compile_terms(terms, nterms, compiled_buf_);
        if (!compiled_buf_.valid) return matches;

        for (size_t i = 0; i < nbc; ++i) {
            std::string_view bc = bytecodes[i];
            if (bc.size() < 2) continue;
            bool did_parse = false;
            Entry* e = resolve_for_query(bc, 0, false, compiled_buf_, did_parse);
            if (e && entry_matches(*e, compiled_buf_)) matches.push_back(static_cast<uint32_t>(i));
        }
        return matches;
    }

    std::vector<uint32_t> filter(const std::vector<std::string_view>& bytecodes, const std::vector<std::string_view>& terms) {
        return filter(bytecodes.data(), bytecodes.size(), terms.data(), terms.size());
    }
    std::vector<uint32_t> filter(const std::vector<std::string>& bytecodes, const std::vector<std::string>& terms) {
        fill_tmp_bvs(bytecodes); fill_tmp_tvs(terms);
        return filter(tmp_bvs_.data(), tmp_bvs_.size(), tmp_tvs_.data(), tmp_tvs_.size());
    }
    std::vector<uint32_t> filter(const std::vector<std::string>& bytecodes, std::initializer_list<std::string_view> terms) {
        fill_tmp_bvs(bytecodes);
        return filter(tmp_bvs_.data(), tmp_bvs_.size(), terms.begin(), terms.size());
    }
    std::vector<uint32_t> filter(const std::vector<std::string_view>& bytecodes, std::initializer_list<std::string_view> terms) {
        return filter(bytecodes.data(), bytecodes.size(), terms.begin(), terms.size());
    }
#if LUAU_FILTER_HAS_SPAN
    std::vector<uint32_t> filter(std::span<const std::string_view> bytecodes, std::span<const std::string_view> terms) {
        return filter(bytecodes.data(), bytecodes.size(), terms.data(), terms.size());
    }
#endif

    // Перегрузки с декодированием Base64 / Hex / Auto
    std::vector<uint32_t> filter(
        std::string_view const* bytecodes, size_t nbc,
        std::string_view const* terms, size_t nterms,
        InputFormat fmt)
    {
        if (fmt == InputFormat::Raw) return filter(bytecodes, nbc, terms, nterms);
        decode_to_tmp_bvs(bytecodes, nbc, fmt);
        return filter(tmp_bvs_.data(), tmp_bvs_.size(), terms, nterms);
    }
    std::vector<uint32_t> filter(const std::vector<std::string_view>& bytecodes, const std::vector<std::string_view>& terms, InputFormat fmt) {
        if (fmt == InputFormat::Raw) return filter(bytecodes, terms);
        decode_to_tmp_bvs(bytecodes, bytecodes.size(), fmt);
        return filter(tmp_bvs_.data(), tmp_bvs_.size(), terms.data(), terms.size());
    }
    std::vector<uint32_t> filter(const std::vector<std::string>& bytecodes, const std::vector<std::string>& terms, InputFormat fmt) {
        if (fmt == InputFormat::Raw) return filter(bytecodes, terms);
        decode_to_tmp_bvs(bytecodes, bytecodes.size(), fmt);
        fill_tmp_tvs(terms);
        return filter(tmp_bvs_.data(), tmp_bvs_.size(), tmp_tvs_.data(), tmp_tvs_.size());
    }
    std::vector<uint32_t> filter(const std::vector<std::string>& bytecodes, std::initializer_list<std::string_view> terms, InputFormat fmt) {
        if (fmt == InputFormat::Raw) return filter(bytecodes, terms);
        decode_to_tmp_bvs(bytecodes, bytecodes.size(), fmt);
        return filter(tmp_bvs_.data(), tmp_bvs_.size(), terms.begin(), terms.size());
    }
    std::vector<uint32_t> filter(const std::vector<std::string_view>& bytecodes, std::initializer_list<std::string_view> terms, InputFormat fmt) {
        if (fmt == InputFormat::Raw) return filter(bytecodes, terms);
        decode_to_tmp_bvs(bytecodes, bytecodes.size(), fmt);
        return filter(tmp_bvs_.data(), tmp_bvs_.size(), terms.begin(), terms.size());
    }

    // Предварительное хеширование набора байткодов для мгновенных повторных запросов
    PreparedCorpus prepare(std::string_view const* bytecodes, size_t nbc) const {
        PreparedCorpus c;
        c.bytecodes.assign(bytecodes, bytecodes + nbc);
        c.hashes.resize(nbc);
        c.slot_hints.assign(nbc, UINT32_MAX);
        c.clear_gen = clear_gen_;
        for (size_t i = 0; i < nbc; ++i) {
            if (bytecodes[i].size() >= 2) c.hashes[i] = detail::hash_sv(bytecodes[i]);
        }
        return c;
    }
    PreparedCorpus prepare(const std::vector<std::string>& bytecodes) const {
        std::vector<std::string_view> bvs;
        bvs.reserve(bytecodes.size());
        for (const auto& s : bytecodes) bvs.emplace_back(s);
        return prepare(bvs.data(), bvs.size());
    }
    PreparedCorpus prepare(const std::vector<std::string_view>& bytecodes) const {
        return prepare(bytecodes.data(), bytecodes.size());
    }

    std::vector<uint32_t> filter(const PreparedCorpus& corpus, std::string_view const* terms, size_t nterms) {
        ++query_serial_;
        if (corpus.clear_gen != clear_gen_) {
            std::fill(corpus.slot_hints.begin(), corpus.slot_hints.end(), UINT32_MAX);
            corpus.clear_gen = clear_gen_;
        }
        const size_t nbc = corpus.bytecodes.size();
        const std::string_view* bcs = corpus.bytecodes.data();
        const uint64_t* hs = corpus.hashes.data();
        uint32_t* hints = corpus.slot_hints.data();

        std::vector<uint32_t> matches;
        if (nterms == 0) {
            for (size_t i = 0; i < nbc; ++i) {
                if (bcs[i].size() < 2) continue;
                Entry* e = nullptr;
                if (hints[i] != UINT32_MAX) {
                    CacheSlot& sl = slots_[hints[i]];
                    if (sl.state == SlotState::Parsed) e = &sl.entry;
                    else if (sl.state == SlotState::Invalid) continue;
                    else e = parse_slot(hints[i], bcs[i]);
                } else {
                    bool created = false;
                    uint32_t sidx = get_or_create_slot(bcs[i], hs[i], created);
                    hints[i] = sidx;
                    CacheSlot& sl = slots_[sidx];
                    if (!created) {
                        if (sl.state == SlotState::Parsed) e = &sl.entry;
                        else if (sl.state == SlotState::Invalid) continue;
                        else e = parse_slot(sidx, bcs[i]);
                    } else e = parse_slot(sidx, bcs[i]);
                }
                if (e) matches.push_back(static_cast<uint32_t>(i));
            }
            return matches;
        }
        if (nterms == 1) return filter_single_term(bcs, nbc, terms[0], hs, hints);

        compile_terms(terms, nterms, compiled_buf_);
        if (!compiled_buf_.valid) return matches;

        for (size_t i = 0; i < nbc; ++i) {
            std::string_view bc = bcs[i];
            if (bc.size() < 2) continue;
            Entry* e = nullptr;
            if (hints[i] != UINT32_MAX) {
                CacheSlot& sl = slots_[hints[i]];
                if (sl.state == SlotState::Parsed) e = &sl.entry;
                else if (sl.state == SlotState::Invalid) continue;
                else {
                    bool ok = true;
                    for (const auto& ch : compiled_buf_.cold_hints) {
                        if (detail::fast_find(bc, ch) == std::string_view::npos) { ok = false; break; }
                    }
                    if (ok) {
                        for (const auto& cci : compiled_buf_.cold_ci) {
                            if (detail::fast_find(sl.low_hdr, cci.ci) == std::string_view::npos) { ok = false; break; }
                        }
                    }
                    if (ok) e = parse_slot(hints[i], bc);
                }
            } else {
                bool did_parse = false;
                e = resolve_for_query(bc, hs[i], true, compiled_buf_, did_parse, &hints[i]);
            }
            if (e && entry_matches(*e, compiled_buf_)) matches.push_back(static_cast<uint32_t>(i));
        }
        return matches;
    }

    std::vector<uint32_t> filter(const PreparedCorpus& corpus, std::initializer_list<std::string_view> terms) {
        return filter(corpus, terms.begin(), terms.size());
    }
    std::vector<uint32_t> filter(const PreparedCorpus& corpus, const std::vector<std::string_view>& terms) {
        return filter(corpus, terms.data(), terms.size());
    }
    std::vector<uint32_t> filter(const PreparedCorpus& corpus, const std::vector<std::string>& terms) {
        fill_tmp_tvs(terms);
        return filter(corpus, tmp_tvs_.data(), tmp_tvs_.size());
    }

    template <typename YieldFn = std::nullptr_t>
    std::vector<uint32_t> filter_async(
        std::string_view const* bytecodes, size_t nbc,
        std::string_view const* terms, size_t nterms,
        double budget_ms = 4.0, YieldFn&& yield_fn = nullptr)
    {
        ++query_serial_;
        std::vector<uint32_t> matches;

        constexpr bool has_yield = !std::is_same_v<std::decay_t<YieldFn>, std::nullptr_t>;
        using clock = std::chrono::steady_clock;
        const auto budget_ns = std::chrono::duration_cast<clock::duration>(
            std::chrono::duration<double, std::milli>(budget_ms));
        auto slice_start = clock::now();

        auto maybe_yield = [&](bool force_check, size_t idx) {
            if constexpr (has_yield) {
                if ((force_check || ((idx + 1) & 63) == 0) && (clock::now() - slice_start) >= budget_ns) {
                    yield_fn();
                    slice_start = clock::now();
                }
            } else { (void)force_check; (void)idx; }
        };

        if (nterms == 0) {
            for (size_t i = 0; i < nbc; ++i) {
                std::string_view bc = bytecodes[i];
                if (bc.size() >= 2) {
                    uint64_t h = detail::hash_sv(bc);
                    uint32_t sidx = find_slot_idx(bc, h);
                    bool was_cached = (sidx != UINT32_MAX);
                    Entry* e = nullptr;
                    if (!was_cached) e = parse_and_cache(bc, h);
                    else {
                        CacheSlot& sl = slots_[sidx];
                        if (sl.state == SlotState::Parsed) e = &sl.entry;
                        else if (sl.state == SlotState::HdrOnly) e = parse_slot(sidx, bc);
                    }
                    if (e) matches.push_back(static_cast<uint32_t>(i));
                    maybe_yield(!was_cached, i);
                }
            }
            return matches;
        }

        compile_terms(terms, nterms, compiled_buf_);
        if (!compiled_buf_.valid) return matches;

        for (size_t i = 0; i < nbc; ++i) {
            std::string_view bc = bytecodes[i];
            if (bc.size() >= 2) {
                bool did_parse = false;
                Entry* e = resolve_for_query(bc, 0, false, compiled_buf_, did_parse);
                if (e && entry_matches(*e, compiled_buf_)) matches.push_back(static_cast<uint32_t>(i));
                maybe_yield(did_parse, i);
            }
        }
        return matches;
    }

    template <typename YieldFn = std::nullptr_t>
    std::vector<uint32_t> filter_async(const std::vector<std::string_view>& bytecodes, const std::vector<std::string_view>& terms,
                                       double budget_ms = 4.0, YieldFn&& yield_fn = nullptr) {
        return filter_async(bytecodes.data(), bytecodes.size(), terms.data(), terms.size(), budget_ms, std::forward<YieldFn>(yield_fn));
    }
    template <typename YieldFn = std::nullptr_t>
    std::vector<uint32_t> filter_async(const std::vector<std::string>& bytecodes, const std::vector<std::string>& terms,
                                       double budget_ms = 4.0, YieldFn&& yield_fn = nullptr) {
        fill_tmp_bvs(bytecodes); fill_tmp_tvs(terms);
        return filter_async(tmp_bvs_.data(), tmp_bvs_.size(), tmp_tvs_.data(), tmp_tvs_.size(), budget_ms, std::forward<YieldFn>(yield_fn));
    }

    template <typename YieldFn = std::nullptr_t>
    void warmup(std::string_view const* bytecodes, size_t nbc, double budget_ms = 4.0, YieldFn&& yield_fn = nullptr) {
        constexpr bool has_yield = !std::is_same_v<std::decay_t<YieldFn>, std::nullptr_t>;
        using clock = std::chrono::steady_clock;
        const auto budget_ns = std::chrono::duration_cast<clock::duration>(
            std::chrono::duration<double, std::milli>(budget_ms));
        auto slice_start = clock::now();

        for (size_t i = 0; i < nbc; ++i) {
            std::string_view bc = bytecodes[i];
            if (bc.size() >= 2) {
                uint64_t h = detail::hash_sv(bc);
                uint32_t sidx = find_slot_idx(bc, h);
                if (sidx == UINT32_MAX || slots_[sidx].state == SlotState::HdrOnly) {
                    parse_and_cache(bc, h);
                    if constexpr (has_yield) {
                        if ((clock::now() - slice_start) >= budget_ns) { yield_fn(); slice_start = clock::now(); }
                    }
                }
            }
        }
    }

    template <typename YieldFn = std::nullptr_t>
    void warmup(const std::vector<std::string_view>& bytecodes, double budget_ms = 4.0, YieldFn&& yield_fn = nullptr) {
        warmup(bytecodes.data(), bytecodes.size(), budget_ms, std::forward<YieldFn>(yield_fn));
    }
    template <typename YieldFn = std::nullptr_t>
    void warmup(const std::vector<std::string>& bytecodes, double budget_ms = 4.0, YieldFn&& yield_fn = nullptr) {
        fill_tmp_bvs(bytecodes);
        warmup(tmp_bvs_.data(), tmp_bvs_.size(), budget_ms, std::forward<YieldFn>(yield_fn));
    }

    const std::vector<std::string_view>* words(std::string_view bytecode, InputFormat fmt = InputFormat::Raw) {
        std::string_view raw = bytecode;
        if (fmt != InputFormat::Raw) {
            if (!decode_input(bytecode, fmt, decode_buf_, raw)) return nullptr;
        }
        Entry* e = get_entry(raw);
        if (!e) return nullptr;
        return &entry_words(*e);
    }

    const std::vector<std::string_view>* tokens(std::string_view bytecode, InputFormat fmt = InputFormat::Raw) {
        std::string_view raw = bytecode;
        if (fmt != InputFormat::Raw) {
            if (!decode_input(bytecode, fmt, decode_buf_, raw)) return nullptr;
        }
        Entry* e = get_entry(raw);
        if (!e) return nullptr;
        if (e->has_token_list) return &e->token_list;

        const auto& wlist = entry_words(*e);
        detail::FlatSvSet tset;
        tset.reserve(wlist.size() * 2);
        for (std::string_view pat : wlist) {
            auto [start, count] = word_tokens_cached(pat);
            for (uint32_t j = 0; j < count; ++j) {
                std::string_view tok = tok_memo_pool_[start + j];
                if (tset.insert(tok)) e->token_list.push_back(tok);
            }
        }
        e->has_token_list = true;
        return &e->token_list;
    }

    void clear() noexcept {
        map_buckets_.clear();
        map_size_ = 0;
        slots_.clear();
        tok_memo_.clear();
        tok_memo_pool_.clear();
        tok_arena_.clear();
        tok_memo_n_ = 0;
        decode_buf_.clear();
        tmp_decoded_bcs_.clear();
        ++clear_gen_;
    }
};

} // namespace luau_filter
