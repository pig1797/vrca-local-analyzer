#pragma once

#include "mini_json.hpp"

#include <filesystem>

namespace vrc {

// Analyze a normalized, data-only snapshot produced by the Unity reader.
// All password/lock decisions intentionally live in the native core; the
// reader is only responsible for serializing objects without interpretation.
json::Value AnalyzeNormalizedGraph(const std::filesystem::path& graph_path);

// Render the stable line protocol consumed by the existing C# UI.
// PWD/GUIDE/FEATURE/LOCK/PARSEFAIL lines are kept compatible with v1.x.
std::string RenderAnalysisProtocol(const json::Value& report);

}  // namespace vrc
