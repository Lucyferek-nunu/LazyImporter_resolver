#ifndef LIRES_DICT_HPP
#define LIRES_DICT_HPP

#include <string>
#include <vector>

namespace lires {

struct Dictionary {
    std::vector<std::string> func_names;
    std::vector<std::string> func_module;
    std::vector<std::string> module_names;
};

std::vector<std::string> default_dll_names();

bool build_dictionary(const std::vector<std::string>& dll_paths, Dictionary& out, std::vector<std::string>* warnings);

}

#endif