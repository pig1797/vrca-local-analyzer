#include "common.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <codecvt>
#include <fstream>
#include <iomanip>
#include <locale>
#include <sstream>
#include <stdexcept>

namespace fs = std::filesystem;

namespace vrc {
namespace {

constexpr std::array<std::uint32_t, 64> kSha256K = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u};

constexpr std::uint32_t RotateRight(const std::uint32_t value,
    const unsigned count) {
    return (value >> count) | (value << (32u - count));
}

class Sha256 {
public:
    void Update(const void* raw, std::size_t size) {
        const auto* data = static_cast<const unsigned char*>(raw);
        total_ += static_cast<std::uint64_t>(size);
        while (size) {
            const std::size_t count = std::min(size, block_.size() - used_);
            std::copy_n(data, count, block_.begin() +
                static_cast<std::ptrdiff_t>(used_));
            data += count;
            size -= count;
            used_ += count;
            if (used_ == block_.size()) {
                Transform(block_.data());
                used_ = 0;
            }
        }
    }

    std::array<unsigned char, 32> Final() {
        const std::uint64_t bits = total_ * 8u;
        block_[used_++] = 0x80u;
        if (used_ > 56) {
            std::fill(block_.begin() + static_cast<std::ptrdiff_t>(used_),
                block_.end(), 0);
            Transform(block_.data());
            used_ = 0;
        }
        std::fill(block_.begin() + static_cast<std::ptrdiff_t>(used_),
            block_.begin() + 56, 0);
        for (int index = 0; index < 8; ++index)
            block_[63 - index] = static_cast<unsigned char>(
                bits >> static_cast<unsigned>(index * 8));
        Transform(block_.data());
        std::array<unsigned char, 32> output{};
        for (std::size_t index = 0; index < state_.size(); ++index)
            for (int byte = 0; byte < 4; ++byte)
                output[index * 4 + static_cast<std::size_t>(byte)] =
                    static_cast<unsigned char>(state_[index] >>
                        static_cast<unsigned>(24 - byte * 8));
        return output;
    }

private:
    void Transform(const unsigned char* data) {
        std::array<std::uint32_t, 64> words{};
        for (std::size_t index = 0; index < 16; ++index) {
            const std::size_t offset = index * 4;
            words[index] = (static_cast<std::uint32_t>(data[offset]) << 24u) |
                (static_cast<std::uint32_t>(data[offset + 1]) << 16u) |
                (static_cast<std::uint32_t>(data[offset + 2]) << 8u) |
                static_cast<std::uint32_t>(data[offset + 3]);
        }
        for (std::size_t index = 16; index < words.size(); ++index) {
            const std::uint32_t s0 = RotateRight(words[index - 15], 7) ^
                RotateRight(words[index - 15], 18) ^ (words[index - 15] >> 3u);
            const std::uint32_t s1 = RotateRight(words[index - 2], 17) ^
                RotateRight(words[index - 2], 19) ^ (words[index - 2] >> 10u);
            words[index] = words[index - 16] + s0 + words[index - 7] + s1;
        }
        std::uint32_t a=state_[0],b=state_[1],c=state_[2],d=state_[3];
        std::uint32_t e=state_[4],f=state_[5],g=state_[6],h=state_[7];
        for (std::size_t index = 0; index < words.size(); ++index) {
            const std::uint32_t s1 = RotateRight(e, 6) ^ RotateRight(e, 11) ^
                RotateRight(e, 25);
            const std::uint32_t choice = (e & f) ^ ((~e) & g);
            const std::uint32_t temp1 = h + s1 + choice + kSha256K[index] +
                words[index];
            const std::uint32_t s0 = RotateRight(a, 2) ^ RotateRight(a, 13) ^
                RotateRight(a, 22);
            const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
            const std::uint32_t temp2 = s0 + majority;
            h=g; g=f; f=e; e=d+temp1; d=c; c=b; b=a; a=temp1+temp2;
        }
        state_[0]+=a; state_[1]+=b; state_[2]+=c; state_[3]+=d;
        state_[4]+=e; state_[5]+=f; state_[6]+=g; state_[7]+=h;
    }

    std::array<std::uint32_t, 8> state_{0x6a09e667u,0xbb67ae85u,
        0x3c6ef372u,0xa54ff53au,0x510e527fu,0x9b05688cu,0x1f83d9abu,
        0x5be0cd19u};
    std::array<unsigned char, 64> block_{};
    std::size_t used_ = 0;
    std::uint64_t total_ = 0;
};

std::string Hex(const unsigned char* data, const std::size_t size,
    const bool upper) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    if (upper) output << std::uppercase;
    for (std::size_t index = 0; index < size; ++index)
        output << std::setw(2) << static_cast<unsigned>(data[index]);
    return output.str();
}

}  // namespace

std::string WideToUtf8(const std::wstring& value) {
    if (value.empty()) return {};
    std::wstring_convert<std::codecvt_utf8<wchar_t>> convert;
    return convert.to_bytes(value);
}

std::wstring Utf8ToWide(const std::string& value) {
    if (value.empty()) return {};
    std::wstring_convert<std::codecvt_utf8<wchar_t>> convert;
    return convert.from_bytes(value);
}

std::string ReadUtf8File(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("unable to open file: " + path.string());
    std::ostringstream buffer;
    buffer << input.rdbuf();
    std::string data = buffer.str();
    if (data.size() >= 3 && static_cast<unsigned char>(data[0]) == 0xEF &&
            static_cast<unsigned char>(data[1]) == 0xBB &&
            static_cast<unsigned char>(data[2]) == 0xBF)
        data.erase(0, 3);
    return data;
}

void WriteUtf8FileAtomic(const fs::path& path, const std::string& data) {
    if (!path.parent_path().empty()) fs::create_directories(path.parent_path());
    fs::path temporary = path;
    temporary += ".tmp-native";
    {
        std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
        if (!output) throw std::runtime_error("unable to create file: " +
            temporary.string());
        output.write(data.data(), static_cast<std::streamsize>(data.size()));
        output.flush();
        if (!output) throw std::runtime_error("unable to write file: " +
            temporary.string());
    }
    std::error_code error;
    fs::rename(temporary, path, error);
    if (error) {
        fs::remove(path, error);
        error.clear();
        fs::rename(temporary, path, error);
        if (error) {
            fs::remove(temporary);
            throw std::runtime_error("unable to replace file: " + path.string());
        }
    }
}

std::string Sha256Hex(const void* data, const std::size_t size,
    const bool upper) {
    Sha256 hash;
    hash.Update(data, size);
    const auto digest = hash.Final();
    return Hex(digest.data(), digest.size(), upper);
}

std::string Sha256Hex(const std::string& data, const bool upper) {
    return Sha256Hex(data.data(), data.size(), upper);
}

std::string Sha256File(const fs::path& path, const bool upper) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("unable to open file: " + path.string());
    Sha256 hash;
    std::array<char, 1024 * 1024> buffer{};
    while (input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize count = input.gcount();
        if (count > 0) hash.Update(buffer.data(), static_cast<std::size_t>(count));
    }
    const auto digest = hash.Final();
    return Hex(digest.data(), digest.size(), upper);
}

std::string JsonEscape(const std::string& value) {
    std::ostringstream output;
    for (const unsigned char ch : value) {
        switch (ch) {
        case '"': output << "\\\""; break;
        case '\\': output << "\\\\"; break;
        case '\b': output << "\\b"; break;
        case '\f': output << "\\f"; break;
        case '\n': output << "\\n"; break;
        case '\r': output << "\\r"; break;
        case '\t': output << "\\t"; break;
        default:
            if (ch < 0x20) output << "\\u" << std::hex << std::setw(4)
                << std::setfill('0') << static_cast<int>(ch) << std::dec;
            else output << static_cast<char>(ch);
        }
    }
    return output.str();
}

std::string Trim(std::string value) {
    const auto first = std::find_if_not(value.begin(), value.end(),
        [](const unsigned char ch) { return std::isspace(ch) != 0; });
    const auto last = std::find_if_not(value.rbegin(), value.rend(),
        [](const unsigned char ch) { return std::isspace(ch) != 0; }).base();
    return first >= last ? std::string{} : std::string(first, last);
}

std::string LowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](const unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return value;
}

bool IContainsAscii(const std::string& value, const std::string& needle) {
    return LowerAscii(value).find(LowerAscii(needle)) != std::string::npos;
}

std::vector<fs::path> RecursiveFilesWithExtension(const fs::path& root,
    const std::wstring& extension) {
    std::vector<fs::path> files;
    const std::string wanted = LowerAscii(WideToUtf8(extension));
    if (fs::is_regular_file(root)) {
        if (LowerAscii(root.extension().string()) == wanted) files.push_back(root);
        return files;
    }
    std::error_code error;
    for (fs::recursive_directory_iterator iterator(root,
            fs::directory_options::skip_permission_denied, error), end;
            iterator != end; iterator.increment(error)) {
        if (error) { error.clear(); continue; }
        if (iterator->is_regular_file(error) &&
                LowerAscii(iterator->path().extension().string()) == wanted)
            files.push_back(iterator->path());
    }
    std::sort(files.begin(), files.end());
    return files;
}

}  // namespace vrc

