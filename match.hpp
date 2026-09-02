#ifndef LIRES_MATCH_HPP
#define LIRES_MATCH_HPP

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "dict.hpp"
#include "pe.hpp"

namespace lires {

struct MatchOptions {
    bool case_insensitive = false;
    std::uint32_t window = 96; // max distance between the seed mov and the hash cmp
    std::uint32_t min_seed = 0x10000; // skip tiny mov immediates they are never seeds
};

struct Recovered {
    std::string name;
    std::string module;
    std::uint32_t offset = 0;
    std::uint32_t hash = 0;
    int sites = 0; // how many call sites resolved this one
};

struct ResolveResult {
    std::vector<Recovered> functions;
    std::vector<Recovered> modules;
    std::size_t mov_count = 0;
    std::size_t cmp_count = 0;
};

// the file offsets it appears at
using SiteMap = std::unordered_map<std::uint32_t, std::vector<std::uint32_t>>;

struct Immediates {
    SiteMap mov; // mov r32 imm seed candidates
    SiteMap cmp; // cmp r32 imm hash candidates
};

void extract_immediates(const PeFile& pe, Immediates& out);
ResolveResult resolve_imports(const PeFile& target, const Dictionary& dict, const MatchOptions& opt);

}

#endif