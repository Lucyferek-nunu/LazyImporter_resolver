#ifndef LIRES_FNV_HPP
#define LIRES_FNV_HPP

#include <cstdint>

namespace lires {

// FNV-1a same as lazy_importer's khash (v ^ c) * prime only it starts from the per call site offset instead of the usual basis
inline std::uint32_t hash_char(std::uint32_t v, char c, bool nocase)
{
    if (nocase && c >= 'A' && c <= 'Z')
        c += 0x20;
    return (v ^ static_cast<std::uint8_t>(c)) * 16777619u;
}

inline std::uint32_t hash_name(const char* s, std::uint32_t seed, bool nocase)
{
    std::uint32_t v = seed;
    while (*s)
        v = hash_char(v, *s++, nocase);
    return v;
}

}

#endif