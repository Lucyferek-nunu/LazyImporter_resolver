#ifndef LIRES_PE_HPP
#define LIRES_PE_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace lires {

struct Section {
    std::string name;
    std::uint32_t virtual_address = 0;
    std::uint32_t virtual_size = 0;
    std::uint32_t raw_ptr = 0;
    std::uint32_t raw_size = 0;
    std::uint32_t characteristics = 0;

    bool executable() const;
};

class PeFile {
public:
    bool load(const std::string& path, std::string* err);

    bool is64() const { return is64_; }
    const std::vector<Section>& sections() const { return sections_; }
    const std::vector<std::uint8_t>& bytes() const { return data_; }

    bool rva_to_offset(std::uint32_t rva, std::size_t& off) const;
    bool data_directory(int index, std::uint32_t& rva, std::uint32_t& size) const;

private:
    std::vector<std::uint8_t> data_;
    bool is64_ = false;
    std::vector<Section> sections_;

    struct DataDir { std::uint32_t rva = 0, size = 0; };
    std::vector<DataDir> data_dirs_;
};

bool parse_export_names(const PeFile& pe, std::vector<std::string>& out, std::string* err);

}

#endif