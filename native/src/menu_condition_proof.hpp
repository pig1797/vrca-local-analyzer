#pragma once
#include "mini_json.hpp"
#include <string>

namespace vrc {
// Proves a bounded Boolean predicate substitution only. It does NOT classify
// a lock, authenticate an input route, authorize a write or sign a plan.
struct MenuConditionSubstitutionProof {
    bool accepted = false;
    std::string reason;
    json::Value::Array rewrites;
};
MenuConditionSubstitutionProof ProveMenuBooleanConditionSubstitution(
    const json::Value& graph, const std::string& parameter);
}
