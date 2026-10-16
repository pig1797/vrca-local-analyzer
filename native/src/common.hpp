#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace vrc {

std::string WideToUtf8(const std::wstring& value);
std::wstring Utf8ToWide(const std::string& value);
std::string ReadUtf8File(const std::filesystem::path& path);
void WriteUtf8FileAtomic(const std::filesystem::path& path, const std::string& data);
std::string Sha256Hex(const void* data, std::size_t size, bool upper = true);
std::string Sha256Hex(const std::string& data, bool upper = true);
std::string Sha256File(const std::filesystem::path& path, bool upper = true);
std::string JsonEscape(const std::string& value);
std::string Trim(std::string value);
std::string LowerAscii(std::string value);
bool IContainsAscii(const std::string& value, const std::string& needle);
std::vector<std::filesystem::path> RecursiveFilesWithExtension(
    const std::filesystem::path& root, const std::wstring& extension);

}  // namespace vrc

