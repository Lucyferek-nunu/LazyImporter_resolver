#include "match.hpp"

#include <algorithm>
#include <cstring>

#include "fnv.hpp"

namespace lires {
namespace {

// smallest cmp_pos - mov_pos that still lands in 0, window UINT64_MAX = none
std::uint64_t forward_gap(const std::vector<std::uint32_t>& movs,
                          const std::vector<std::uint32_t>& cmps,
                          std::uint32_t window)
{
    std::uint64_t best = UINT64_MAX;
    for (std::uint32_t m : movs) {
        auto it = std::lower_bound(cmps.begin(), cmps.end(), m);
        if (it != cmps.end()) {
            std::uint64_t d = *it - m;
            if (d <= window && d < best)
                best = d;
        }
    }
    return best;
}

struct Hit {
    std::uint32_t seed = 0, hash = 0;
    int sites = 0;
    const std::string* module = nullptr;
};

void run(const Immediates& imm,
         const std::vector<std::uint32_t>& seeds,
         const std::vector<std::string>& names,
         const std::vector<std::string>* modules,
         const MatchOptions& opt,
         std::vector<Recovered>& out)
{
    std::unordered_map<std::string, Hit> found;

    for (std::uint32_t seed : seeds) {
        auto mv = imm.mov.find(seed);
        if (mv == imm.mov.end())
            continue;

        for (std::size_t i = 0; i < names.size(); ++i) {
            std::uint32_t h = hash_name(names[i].c_str(), seed, opt.case_insensitive);
            auto cm = imm.cmp.find(h);
            if (cm == imm.cmp.end())
                continue;
            if (forward_gap(mv->second, cm->second, opt.window) == UINT64_MAX)
                continue;

            Hit& f = found[names[i]];
            f.sites++;
            f.seed = seed;
            f.hash = h;
            if (modules)
                f.module = &(*modules)[i];
        }
    }

    for (auto& kv : found) {
        Recovered r;
        r.name = kv.first;
        r.module = kv.second.module ? *kv.second.module : std::string();
        r.offset = kv.second.seed;
        r.hash = kv.second.hash;
        r.sites = kv.second.sites;
        out.push_back(std::move(r));
    }

    std::sort(out.begin(), out.end(), [](const Recovered& a, const Recovered& b) { return a.name < b.name; });
}

}

void extract_immediates(const PeFile& pe, Immediates& out)
{
    const auto& b = pe.bytes();
    for (const auto& s : pe.sections()) {
        if (!s.executable())
            continue;
        std::size_t start = s.raw_ptr;
        std::size_t end = std::size_t(s.raw_ptr) + s.raw_size;
        if (end > b.size() || s.raw_size < 5)
            continue;

        // an imm32 starts at i look at the byte or bytes right before it to tell what it is
        for (std::size_t i = start + 1; i + 4 <= end; ++i) {
            std::uint8_t op = b[i - 1];

            bool mov = op >= 0xB8 && op <= 0xBF;         // mov r32, imm32
            bool cmp = op == 0x3D;                       // cmp eax, imm32
            if (!cmp && i >= start + 2)                  // cmp r32, imm32  (81 /7)
                cmp = b[i - 2] == 0x81 && op >= 0xF8 && op <= 0xFF;
            if (!mov && !cmp)
                continue;

            std::uint32_t v;
            std::memcpy(&v, b.data() + i, 4);
            auto pos = std::uint32_t(i);
            if (mov) out.mov[v].push_back(pos);
            if (cmp) out.cmp[v].push_back(pos);
        }
    }
}

ResolveResult resolve_imports(const PeFile& target, const Dictionary& dict, const MatchOptions& opt)
{
    ResolveResult res;

    Immediates imm;
    extract_immediates(target, imm);
    res.mov_count = imm.mov.size();
    res.cmp_count = imm.cmp.size();

    std::vector<std::uint32_t> seeds;
    seeds.reserve(imm.mov.size());
    for (auto& kv : imm.mov)
        if (kv.first >= opt.min_seed)
            seeds.push_back(kv.first);

    run(imm, seeds, dict.func_names, &dict.func_module, opt, res.functions);
    run(imm, seeds, dict.module_names, nullptr, opt, res.modules);
    return res;
}

}