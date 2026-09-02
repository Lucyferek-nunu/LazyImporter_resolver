#include "dict.hpp"

#include <algorithm>
#include <unordered_map>

#include "pe.hpp"

namespace lires {
namespace {

std::string base_name(const std::string& path)
{
    auto pos = path.find_last_of("\\/");
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

bool csv_has(const std::string& csv, const std::string& token)
{
    std::size_t start = 0;
    while (start <= csv.size()) {
        std::size_t comma = csv.find(',', start);
        std::size_t end = comma == std::string::npos ? csv.size() : comma;
        if (csv.compare(start, end - start, token) == 0)
            return true;
        if (comma == std::string::npos)
            break;
        start = comma + 1;
    }
    return false;
}

}

std::vector<std::string> default_dll_names()
{
    return {
        "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll", "advapi32.dll",
        "gdi32.dll", "shell32.dll", "ole32.dll", "oleaut32.dll", "ws2_32.dll",
        "msvcrt.dll", "shlwapi.dll", "combase.dll", "sechost.dll",
    };
}

bool build_dictionary(const std::vector<std::string>& dll_paths,
                      Dictionary& out,
                      std::vector<std::string>* warnings)
{
    std::unordered_map<std::string, std::string> where;
    where.reserve(1 << 16);

    for (const auto& path : dll_paths) {
        PeFile pe;
        std::string err;
        if (!pe.load(path, &err)) {
            if (warnings) warnings->push_back("skip " + path + ": " + err);
            continue;
        }
        std::vector<std::string> names;
        if (!parse_export_names(pe, names, &err)) {
            if (warnings) warnings->push_back("skip " + path + ": " + err);
            continue;
        }

        std::string mod = base_name(path);
        out.module_names.push_back(mod);
        for (auto& n : names) {
            auto it = where.find(n);
            if (it == where.end())
                where.emplace(std::move(n), mod);
            else if (!csv_has(it->second, mod))
                it->second += "," + mod;
        }
    }

    if (where.empty())
        return false;

    // flatten sorted by name so the output is stable
    std::vector<std::pair<std::string, std::string>> items(where.begin(), where.end());
    std::sort(items.begin(), items.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });
    for (auto& it : items) {
        out.func_names.push_back(std::move(it.first));
        out.func_module.push_back(std::move(it.second));
    }

    std::sort(out.module_names.begin(), out.module_names.end());
    out.module_names.erase(std::unique(out.module_names.begin(), out.module_names.end()),
                           out.module_names.end());
    return true;
}

}