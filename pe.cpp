#include "pe.hpp"

#include <cstring>
#include <fstream>

namespace lires {
namespace {

template <class T>
bool read_at(const std::vector<std::uint8_t>& b, std::size_t off, T& out)
{
    if (off + sizeof(T) > b.size())
        return false;
    std::memcpy(&out, b.data() + off, sizeof(T));
    return true;
}

constexpr std::uint16_t DOS_MAGIC = 0x5A4D;
constexpr std::uint32_t PE_SIG    = 0x00004550;
constexpr std::uint16_t OPT32     = 0x010B;
constexpr std::uint16_t OPT64     = 0x020B;
constexpr std::uint32_t SCN_EXEC  = 0x20000000;

} // namespace

bool Section::executable() const
{
    return (characteristics & SCN_EXEC) != 0;
}

bool PeFile::load(const std::string& path, std::string* err)
{
    auto fail = [&](const char* m) { if (err) *err = m; return false; };

    std::ifstream f(path, std::ios::binary);
    if (!f)
        return fail("cannot open file");
    f.seekg(0, std::ios::end);
    std::streamoff sz = f.tellg();
    if (sz <= 0)
        return fail("empty file");
    f.seekg(0, std::ios::beg);
    data_.resize(static_cast<std::size_t>(sz));
    f.read(reinterpret_cast<char*>(data_.data()), sz);
    if (!f)
        return fail("read error");

    std::uint16_t mz = 0;
    if (!read_at(data_, 0, mz) || mz != DOS_MAGIC)
        return fail("not a PE image (no MZ)");

    std::uint32_t e_lfanew = 0;
    if (!read_at(data_, 0x3C, e_lfanew))
        return fail("truncated DOS header");

    std::uint32_t sig = 0;
    if (!read_at(data_, e_lfanew, sig) || sig != PE_SIG)
        return fail("bad PE signature");

    std::size_t fh = e_lfanew + 4; // IMAGE_FILE_HEADER
    std::uint16_t num_sections = 0, opt_size = 0;
    if (!read_at(data_, fh + 2, num_sections) || !read_at(data_, fh + 16, opt_size))
        return fail("truncated file header");

    std::size_t opt = fh + 20; // optional header
    std::uint16_t magic = 0;
    if (!read_at(data_, opt, magic))
        return fail("truncated optional header");

    std::size_t dd_off = 0;
    std::uint32_t num_dd = 0;
    if (magic == OPT64) {
        is64_ = true;
        read_at(data_, opt + 108, num_dd); // NumberOfRvaAndSizes
        dd_off = opt + 112;
    } else if (magic == OPT32) {
        is64_ = false;
        read_at(data_, opt + 92, num_dd);
        dd_off = opt + 96;
    } else {
        return fail("unknown optional header magic");
    }

    if (num_dd > 16)
        num_dd = 16;
    for (std::uint32_t i = 0; i < num_dd; ++i) {
        DataDir d;
        read_at(data_, dd_off + i * 8, d.rva);
        read_at(data_, dd_off + i * 8 + 4, d.size);
        data_dirs_.push_back(d);
    }

    std::size_t sh = opt + opt_size; // section headers
    for (std::uint16_t i = 0; i < num_sections; ++i) {
        std::size_t s = sh + std::size_t(i) * 40;
        if (s + 40 > data_.size())
            break;
        Section sec;
        char name[9] = {0};
        std::memcpy(name, data_.data() + s, 8);
        sec.name = name;
        read_at(data_, s + 8,  sec.virtual_size);
        read_at(data_, s + 12, sec.virtual_address);
        read_at(data_, s + 16, sec.raw_size);
        read_at(data_, s + 20, sec.raw_ptr);
        read_at(data_, s + 36, sec.characteristics);
        sections_.push_back(sec);
    }

    return true;
}

bool PeFile::rva_to_offset(std::uint32_t rva, std::size_t& off) const
{
    for (const auto& s : sections_) {
        std::uint32_t span = s.raw_size > s.virtual_size ? s.raw_size : s.virtual_size;
        if (rva >= s.virtual_address && rva < s.virtual_address + span) {
            std::uint32_t delta = rva - s.virtual_address;
            if (delta >= s.raw_size)
                return false;
            off = std::size_t(s.raw_ptr) + delta;
            return off < data_.size();
        }
    }
    // headers map 1:1
    if (!sections_.empty() && rva < sections_.front().virtual_address && rva < data_.size()) {
        off = rva;
        return true;
    }
    return false;
}

bool PeFile::data_directory(int index, std::uint32_t& rva, std::uint32_t& size) const
{
    if (index < 0 || std::size_t(index) >= data_dirs_.size())
        return false;
    rva = data_dirs_[index].rva;
    size = data_dirs_[index].size;
    return rva != 0;
}

bool parse_export_names(const PeFile& pe, std::vector<std::string>& out, std::string* err)
{
    auto fail = [&](const char* m) { if (err) *err = m; return false; };

    std::uint32_t exp_rva = 0, exp_size = 0;
    if (!pe.data_directory(0, exp_rva, exp_size))
        return fail("no export directory");

    std::size_t exp_off = 0;
    if (!pe.rva_to_offset(exp_rva, exp_off))
        return fail("export dir unmapped");

    const auto& b = pe.bytes();
    // IMAGE_EXPORT_DIRECTORY NumberOfNames @ +24, AddressOfNames @ +32
    std::uint32_t count = 0, names_rva = 0;
    if (!read_at(b, exp_off + 24, count) || !read_at(b, exp_off + 32, names_rva))
        return fail("truncated export directory");

    std::size_t names_off = 0;
    if (!pe.rva_to_offset(names_rva, names_off))
        return fail("AddressOfNames unmapped");

    out.reserve(out.size() + count);
    for (std::uint32_t i = 0; i < count; ++i) {
        std::uint32_t name_rva = 0;
        if (!read_at(b, names_off + i * 4, name_rva))
            break;
        std::size_t str = 0;
        if (!pe.rva_to_offset(name_rva, str))
            continue;
        std::string s;
        for (std::size_t k = str; k < b.size() && b[k] && s.size() < 512; ++k)
            s.push_back(char(b[k]));
        if (!s.empty())
            out.push_back(std::move(s));
    }
    return true;
}

}