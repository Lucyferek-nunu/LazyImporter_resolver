#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "dict.hpp"
#include "match.hpp"
#include "pe.hpp"

namespace {

void print_help()
{
    std::puts(
        "LazyImporter RE resolver\n"
        "\n"
        "Usage: resolver <target.exe> [options]\n"
        "\n"
        "  --dlls-dir <path>   export dictionary source (default C:\\Windows\\System32)\n"
        "  --dll <name>        add an extra DLL to the dictionary (repeatable)\n"
        "  --ci                case-insensitive hashing\n"
        "  --names-only        print one recovered function name per line\n"
        "  --json              emit JSON\n"
        "  -h, --help          show this help");
}

std::string join_path(const std::string& dir, const std::string& file)
{
    if (dir.empty())
        return file;
    const char last = dir.back();
    if (last == '\\' || last == '/')
        return dir + file;
    return dir + "\\" + file;
}

std::string json_escape(const std::string& s)
{
    std::string o;
    o.reserve(s.size() + 2);
    for (char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            default:   o += c;      break;
        }
    }
    return o;
}

}

int main(int argc, char** argv)
{
    std::string              target;
    std::string              dlls_dir = "C:\\Windows\\System32";
    std::vector<std::string> extra_dlls;
    lires::MatchOptions      opt;
    bool                     names_only = false;
    bool                     json       = false;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto next = [&](const char* what) -> std::string {
            if (i + 1 >= argc) { std::fprintf(stderr, "error: %s needs a value\n", what); std::exit(2); }
            return argv[++i];
        };
        if (a == "-h" || a == "--help")   { print_help(); return 0; }
        else if (a == "--dlls-dir")       dlls_dir = next("--dlls-dir");
        else if (a == "--dll")            extra_dlls.push_back(next("--dll"));
        else if (a == "--ci")             opt.case_insensitive = true;
        else if (a == "--names-only")     names_only = true;
        else if (a == "--json")           json = true;
        else if (!a.empty() && a[0] == '-') { std::fprintf(stderr, "unknown option: %s\n", a.c_str()); return 2; }
        else if (target.empty())          target = a;
        else                              { std::fprintf(stderr, "unexpected argument: %s\n", a.c_str()); return 2; }
    }

    if (target.empty()) {
        print_help();
        return 2;
    }

    lires::PeFile pe;
    std::string   err;
    if (!pe.load(target, &err)) {
        std::fprintf(stderr, "error: cannot parse '%s': %s\n", target.c_str(), err.c_str());
        return 1;
    }

    std::vector<std::string> dll_paths;
    for (const auto& n : lires::default_dll_names())
        dll_paths.push_back(join_path(dlls_dir, n));
    for (const auto& n : extra_dlls)
        dll_paths.push_back(n.find('\\') != std::string::npos || n.find('/') != std::string::npos
                                ? n
                                : join_path(dlls_dir, n));

    lires::Dictionary        dict;
    std::vector<std::string> warnings;
    if (!lires::build_dictionary(dll_paths, dict, &warnings)) {
        std::fprintf(stderr, "error: could not build export dictionary from %s\n", dlls_dir.c_str());
        for (const auto& w : warnings) std::fprintf(stderr, "  %s\n", w.c_str());
        return 1;
    }

    const lires::ResolveResult r = lires::resolve_imports(pe, dict, opt);

    if (names_only) {
        for (const auto& f : r.functions)
            std::printf("%s\n", f.name.c_str());
        return 0;
    }

    if (json) {
        std::printf("{\n");
        std::printf("  \"target\": \"%s\",\n", json_escape(target).c_str());
        std::printf("  \"arch\": \"%s\",\n", pe.is64() ? "x64" : "x86");
        std::printf("  \"functions\": [\n");
        for (std::size_t i = 0; i < r.functions.size(); ++i) {
            const auto& f = r.functions[i];
            std::printf("    {\"name\": \"%s\", \"module\": \"%s\", \"offset\": \"0x%08X\", "
                        "\"hash\": \"0x%08X\", \"sites\": %d}%s\n",
                        json_escape(f.name).c_str(), json_escape(f.module).c_str(),
                        f.offset, f.hash, f.sites,
                        i + 1 < r.functions.size() ? "," : "");
        }
        std::printf("  ],\n");
        std::printf("  \"modules\": [\n");
        for (std::size_t i = 0; i < r.modules.size(); ++i) {
            const auto& m = r.modules[i];
            std::printf("    {\"name\": \"%s\", \"offset\": \"0x%08X\", \"hash\": \"0x%08X\", "
                        "\"sites\": %d}%s\n",
                        json_escape(m.name).c_str(), m.offset, m.hash, m.sites,
                        i + 1 < r.modules.size() ? "," : "");
        }
        std::printf("  ]\n}\n");
        return 0;
    }

    std::printf("Target      : %s (%s)\n", target.c_str(), pe.is64() ? "x64" : "x86");
    std::printf("Dictionary  : %zu names from %zu modules (%s)\n",
                dict.func_names.size(), dict.module_names.size(), dlls_dir.c_str());
    std::printf("Immediates  : %zu mov (seed) / %zu cmp (hash) candidates in exec sections\n",
                r.mov_count, r.cmp_count);
    std::printf("Hash mode   : %s\n\n", opt.case_insensitive ? "case-insensitive" : "case-sensitive");
    for (const auto& w : warnings)
        std::printf("  [warn] %s\n", w.c_str());
    if (!warnings.empty())
        std::printf("\n");

    auto print_table = [](const char* title, const std::vector<lires::Recovered>& v, bool with_module) {
        std::printf("%s (%zu)\n", title, v.size());
        std::printf("  %-28s  %-18s  %-10s  %-10s  %s\n",
                    "NAME", with_module ? "MODULE" : "", "OFFSET", "HASH", "SITES");
        for (const auto& e : v) {
            std::printf("  %-28s  %-18s  0x%08X  0x%08X  %d\n",
                        e.name.c_str(),
                        with_module ? e.module.c_str() : "",
                        e.offset, e.hash, e.sites);
        }
        std::printf("\n");
    };

    print_table("Recovered imports", r.functions, true);
    if (!r.modules.empty())
        print_table("Recovered modules", r.modules, false);

    std::printf("Summary: %zu hidden imports recovered.\n", r.functions.size());
    return 0;
}