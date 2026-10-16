#pragma once

#include "mini_json.hpp"
#include <cmath>
#include <limits>
#include <map>
#include <stdexcept>
#include <string>
#include <utility>

namespace vrc {

// This is serialization arbitration, not an authorization or semantic proof.
// Call only after ALL detector commitments (including both Contact halves)
// have been checked, and before final protected validation and plan sealing.
inline json::Value::Array CanonicalizeStatePlans(const json::Value::Array& plans) {
    json::Value::Array result;
    std::map<std::pair<std::string, int>, std::size_t> physical;
    const auto integer = [](const json::Value& row, const char* field) {
        const auto* value = row.find(field);
        if (!value || !value->is_number() || !std::isfinite(value->number()) ||
            value->number() < 0 || value->number() > std::numeric_limits<int>::max() ||
            value->number() != std::floor(value->number()))
            throw std::runtime_error(std::string("invalid state plan field: ") + field);
        return static_cast<int>(value->number());
    };
    for (const auto& plan : plans) {
        const auto* path = plan.find("path_id");
        const auto* method = plan.find("method");
        if (!path || !path->is_string() || path->string().empty() ||
            !method || !method->is_string() || method->string().empty() ||
            plan.find("equivalent_proofs"))
            throw std::runtime_error("invalid state plan identity/provenance");
        const int machine = integer(plan, "machine_index");
        const int before = integer(plan, "before");
        const int after = integer(plan, "unlock_state");
        const auto inserted = physical.emplace(std::make_pair(path->string(), machine), result.size());
        if (inserted.second) { result.push_back(plan); continue; }
        auto& first = result[inserted.first->second];
        if (integer(first, "before") != before || integer(first, "unlock_state") != after)
            // Never choose one side or leave a partial Contact transaction.
            // No report/plan is returned, so nothing conflicting can be sealed.
            throw std::runtime_error("conflicting physical state rewrite plans");
        if (!first.find("equivalent_proofs")) {
            json::Value::Array proofs{first};
            first["equivalent_proofs"] = std::move(proofs);
        }
        first["equivalent_proofs"].array().push_back(plan);
    }
    return result;
}

} // namespace vrc
