#pragma once

#include "mini_json.hpp"

#include <filesystem>

namespace vrc {

// Adds deterministic, name-independent selection handles to a freshly
// generated server report. Existing plan_options are replaced.
void AttachServerPlanOptions(json::Value& report);

// Re-validates plan_options, applies selected option dependency closure and
// returns either a scoped physical plan or a bounded deep-evidence request.
json::Value ScopeServerPlan(const std::filesystem::path& report_path,
    const std::filesystem::path& selection_path);

}  // namespace vrc

