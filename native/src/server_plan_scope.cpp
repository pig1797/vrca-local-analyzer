#include "server_plan_scope.hpp"

#include "common.hpp"

#include <algorithm>
#include <cmath>
#include <functional>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <tuple>

namespace fs = std::filesystem;

namespace vrc {
namespace {

const json::Value* Field(const json::Value& value, const char* key) {
    return value.is_object() ? value.find(key) : nullptr;
}

const json::Value::Array& Array(const json::Value& value, const char* key) {
    static const json::Value::Array empty;
    const auto* item = Field(value, key);
    return item && item->is_array() ? item->array() : empty;
}

std::string String(const json::Value& value, const char* key,
    const std::string& fallback = {}) {
    const auto* item = Field(value, key);
    return item && item->is_string() ? item->string() : fallback;
}

int Integer(const json::Value& value, const char* key,
    const int fallback = -1) {
    const auto* item = Field(value, key);
    if (!item || !item->is_number() || !std::isfinite(item->number()) ||
            std::floor(item->number()) != item->number() ||
            item->number() < std::numeric_limits<int>::min() ||
            item->number() > std::numeric_limits<int>::max()) return fallback;
    return static_cast<int>(item->number());
}

bool IsLowerHex64(const std::string& value) {
    return value.size() == 64 && std::all_of(value.begin(), value.end(),
        [](const unsigned char ch) {
            return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
        });
}

using StateCoordinate = std::tuple<std::string, int, int>;

StateCoordinate Coordinate(const json::Value& plan) {
    const std::string path = String(plan, "path_id");
    const int machine = Integer(plan, "machine_index");
    const int state = Integer(plan, "unlock_state");
    if (path.empty() || machine < 0 || state < 0)
        throw std::runtime_error("invalid state plan coordinate");
    return {path, machine, state};
}

std::vector<StateCoordinate> Dependencies(const json::Value& plan) {
    std::vector<StateCoordinate> result;
    const auto append = [&](const json::Value& item) {
        result.push_back(Coordinate(item));
    };
    if (const auto* item = Field(plan, "depends_on")) {
        if (!item->is_object())
            throw std::runtime_error("invalid state plan dependency");
        append(*item);
    }
    if (const auto* items = Field(plan, "dependencies")) {
        if (!items->is_array())
            throw std::runtime_error("invalid state plan dependencies");
        for (const auto& item : items->array()) {
            if (!item.is_object())
                throw std::runtime_error("invalid state plan dependency item");
            append(item);
        }
    }
    std::sort(result.begin(), result.end());
    result.erase(std::unique(result.begin(), result.end()), result.end());
    return result;
}

std::string CoordinateText(const StateCoordinate& coordinate) {
    const auto& [path, machine, state] = coordinate;
    return std::to_string(path.size()) + ':' + path + '|' +
        std::to_string(machine) + '|' + std::to_string(state);
}

std::string StateOptionMaterial(const json::Value& plan) {
    std::ostringstream output;
    output << "state|" << CoordinateText(Coordinate(plan)) << '|'
           << Integer(plan, "before") << '|' << String(plan, "method") << '|'
           << String(plan, "proof_family") << '|';
    for (const auto& dependency : Dependencies(plan))
        output << CoordinateText(dependency) << ',';
    return output.str();
}

void AppendSized(std::ostringstream& output, const std::string& value) {
    output << value.size() << ':' << value << '|';
}

// A user chooses an input route, not an unproved terminal-state number.  Fast
// analysis may therefore expose terminal_state=-1 and targeted deep analysis
// may later prove the real state.  Keep the opaque selection identity stable
// across that enrichment while still committing every other route/input field
// that distinguishes two locks.  A collision is rejected by the existing
// duplicate option-id checks; it never broadens the selected plan.  Family and
// confidence are intentionally excluded because strict proof may enrich those
// labels without changing the user's concrete input route.
std::string CandidateSelectionMaterial(const json::Value& candidate) {
    std::ostringstream output;
    output << "candidate-selection-v1|";
    AppendSized(output, String(candidate, "controller_path_id"));
    AppendSized(output, String(candidate, "controller"));
    output << Integer(candidate, "machine_index") << '|';
    AppendSized(output, String(candidate, "password"));
    AppendSized(output, String(candidate, "parameter"));
    AppendSized(output, String(candidate, "raw"));
    AppendSized(output, String(candidate, "input_kind"));
    return output.str();
}

std::string MenuOptionMaterial(const json::Value& plan) {
    std::ostringstream output;
    output << "menu|" << String(plan, "path_id").size() << ':'
           << String(plan, "path_id") << '|' << Integer(plan, "control_index")
           << '|' << String(plan, "before_submenu").size() << ':'
           << String(plan, "before_submenu") << '|'
           << String(plan, "after_submenu").size() << ':'
           << String(plan, "after_submenu") << '|' << String(plan, "method");
    return output.str();
}

std::string OptionId(const json::Value& report, const std::string& material) {
    return Sha256Hex("VPF-PLAN-OPTION-1|" + String(report, "source_sha256") +
        '|' + String(report, "policy_hash") + '|' + material, false);
}

std::set<std::size_t> ReadIndexArray(const json::Value& value,
    const char* key, const std::size_t limit) {
    const auto* array = Field(value, key);
    if (!array || !array->is_array())
        throw std::runtime_error(std::string("missing option index array: ") + key);
    std::set<std::size_t> result;
    for (const auto& item : array->array()) {
        if (!item.is_number() || !std::isfinite(item.number()) ||
                std::floor(item.number()) != item.number() ||
                item.number() < 0 || item.number() >= limit)
            throw std::runtime_error(std::string("invalid option index: ") + key);
        if (!result.insert(static_cast<std::size_t>(item.number())).second)
            throw std::runtime_error(std::string("duplicate option index: ") + key);
    }
    return result;
}

bool SameCandidatePlan(const json::Value& candidate,
    const json::Value& plan) {
    return !String(candidate, "controller_path_id").empty() &&
        String(candidate, "controller_path_id") == String(plan, "path_id") &&
        Integer(candidate, "machine_index") == Integer(plan, "machine_index") &&
        Integer(candidate, "terminal_state") == Integer(plan, "unlock_state");
}

bool TechnicalProducer(const json::Value& plan) {
    return String(plan, "proof_family") ==
        "guarded_numeric_gate_producer_v1";
}

json::Value BaseOption(const std::string& id, const char* kind,
    const int result_index, const int candidate_index,
    const std::string& display, const std::string& confidence,
    const bool has_plan) {
    json::Value::Object option;
    option["option_id"] = id;
    option["option_kind"] = kind;
    option["result_index"] = result_index;
    option["candidate_index"] = candidate_index;
    option["display_value"] = display;
    option["confidence"] = confidence;
    option["has_safe_plan"] = has_plan;
    option["requires_option_ids"] = json::Value::Array{};
    option["state_plan_indices"] = json::Value::Array{};
    option["menu_plan_indices"] = json::Value::Array{};
    option["condition_plan_indices"] = json::Value::Array{};
    return option;
}

json::Value MergeConfirmationRequests(const json::Value& report,
    const std::vector<const json::Value*>& options) {
    std::map<std::string, std::set<int>> controllers;
    json::Value::Array candidate_ids;
    for (const auto* option : options) {
        const int index = Integer(*option, "candidate_index");
        const auto& candidates = Array(report, "password_candidates");
        if (index < 0 || static_cast<std::size_t>(index) >= candidates.size())
            continue;
        const auto& candidate = candidates[static_cast<std::size_t>(index)];
        const auto* request = Field(candidate, "confirmation_deep_scan_request");
        if (!request || !request->is_object()) continue;
        const std::string candidate_id = String(candidate, "candidate_id");
        if (!candidate_id.empty()) candidate_ids.push_back(candidate_id);
        for (const auto& owner : Array(*request, "controllers")) {
            const std::string path = String(owner, "path_id");
            if (path.empty()) continue;
            for (const auto& machine : Array(owner, "machine_indices"))
                if (machine.is_number() && std::isfinite(machine.number()) &&
                        std::floor(machine.number()) == machine.number() &&
                        machine.number() >= 0 && machine.number() <= 65535)
                    controllers[path].insert(static_cast<int>(machine.number()));
        }
    }
    if (controllers.empty()) return nullptr;
    json::Value::Object request;
    request["schema"] = 1;
    request["source_sha256"] = String(report, "source_sha256");
    request["reason"] = "confirmed_candidates_effect_closure";
    request["requires_strict_reproof"] = true;
    request["candidate_ids"] = std::move(candidate_ids);
    json::Value::Array owners;
    std::int64_t count = 0;
    for (const auto& [path, machines] : controllers) {
        json::Value::Object owner;
        owner["path_id"] = path;
        json::Value::Array indices;
        for (const int machine : machines) {
            indices.push_back(machine);
            ++count;
        }
        owner["machine_indices"] = std::move(indices);
        owners.push_back(std::move(owner));
    }
    request["controllers"] = std::move(owners);
    request["machine_count"] = count;
    return request;
}

void AddCommonScopeFields(json::Value& output, const json::Value& report,
    const std::string& report_hash, const std::string& selection_hash,
    const std::set<std::string>& selected,
    const std::set<std::string>& resolved,
    const std::set<std::string>& automatic) {
    output["source_sha256"] = String(report, "source_sha256");
    output["policy_version"] = String(report, "policy_version");
    output["policy_hash"] = String(report, "policy_hash");
    output["report_sha256"] = report_hash;
    output["selection_sha256"] = selection_hash;
    const auto strings = [](const std::set<std::string>& values) {
        json::Value::Array result;
        for (const auto& value : values) result.push_back(value);
        return result;
    };
    output["selected_option_ids"] = strings(selected);
    output["resolved_option_ids"] = strings(resolved);
    output["auto_included_option_ids"] = strings(automatic);
}

}  // namespace

void AttachServerPlanOptions(json::Value& report) {
    if (!report.is_object() || String(report, "engine") != "VrcNativeCore/cpp" ||
            !IsLowerHex64(String(report, "source_sha256")) ||
            !IsLowerHex64(String(report, "policy_hash")))
        throw std::runtime_error("invalid server report bindings");
    const auto& state = Array(report, "state_bypasses");
    const auto& menu = Array(report, "menu_bypasses");
    const auto& condition = Array(report, "condition_rewrites");
    const auto& results = Array(report, "results");
    const auto& candidates = Array(report, "password_candidates");

    std::map<StateCoordinate, std::size_t> state_by_coordinate;
    std::set<StateCoordinate> depended_on;
    for (std::size_t index = 0; index < state.size(); ++index) {
        if (!state[index].is_object())
            throw std::runtime_error("invalid state plan option source");
        const auto coordinate = Coordinate(state[index]);
        if (!state_by_coordinate.emplace(coordinate, index).second)
            throw std::runtime_error("duplicate state plan option source");
        for (const auto& dependency : Dependencies(state[index]))
            depended_on.insert(dependency);
    }

    json::Value::Array options;
    std::map<std::size_t, std::string> state_option_ids;
    std::set<std::string> option_ids;
    for (std::size_t index = 0; index < state.size(); ++index) {
        const auto coordinate = Coordinate(state[index]);
        int result_index = -1;
        for (std::size_t candidate = 0; candidate < results.size(); ++candidate)
            if (SameCandidatePlan(results[candidate], state[index])) {
                result_index = static_cast<int>(candidate);
                break;
            }
        const json::Value* input_route = result_index >= 0
            ? &results[static_cast<std::size_t>(result_index)] : nullptr;
        if (!input_route) {
            bool ambiguous = false;
            for (const auto& candidate : candidates) {
                if (!SameCandidatePlan(candidate, state[index])) continue;
                if (input_route && CandidateSelectionMaterial(*input_route) != CandidateSelectionMaterial(candidate)) {
                    ambiguous = true; break;
                }
                input_route = &candidate;
            }
            if (ambiguous) input_route = nullptr;
        }
        std::set<std::size_t> physical_indices{index};
        if (TechnicalProducer(state[index]) && depended_on.count(coordinate)) {
            if (!input_route) continue;
            // A selected reference producer must not lose its identity after
            // terminal proof. Its alias authorizes the whole independently
            // proved pair, never an orphan producer write.
            std::set<std::size_t> dependents;
            for (std::size_t other = 0; other < state.size(); ++other)
                for (const auto& dependency : Dependencies(state[other]))
                    if (dependency == coordinate) dependents.insert(other);
            if (dependents.size() != 1) continue;
            physical_indices.insert(*dependents.begin());
        }
        const std::string id = OptionId(report, input_route
            ? CandidateSelectionMaterial(*input_route) : StateOptionMaterial(state[index]));
        if (!option_ids.insert(id).second)
            throw std::runtime_error("duplicate generated option id");
        const std::string display = result_index >= 0
            ? String(results[static_cast<std::size_t>(result_index)], "password") : "";
        const std::string confidence = result_index >= 0
            ? String(results[static_cast<std::size_t>(result_index)], "confidence", u8"高")
            : u8"高";
        auto option = BaseOption(id, "safe_plan", result_index, -1,
            display, confidence, true);
        json::Value::Array indices;
        for (const auto physical_index : physical_indices)
            indices.push_back(static_cast<std::int64_t>(physical_index));
        option["state_plan_indices"] = std::move(indices);
        state_option_ids[index] = id;
        options.push_back(std::move(option));
    }
    for (std::size_t index = 0; index < menu.size(); ++index) {
        if (!menu[index].is_object())
            throw std::runtime_error("invalid menu plan option source");
        const std::string id = OptionId(report, MenuOptionMaterial(menu[index]));
        if (!option_ids.insert(id).second)
            throw std::runtime_error("duplicate generated option id");
        int result_index = -1;
        for (std::size_t candidate = 0; candidate < results.size(); ++candidate) {
            if (String(results[candidate], "input_kind") == "menu" &&
                    Integer(results[candidate], "machine_index") < 0) {
                int preceding = 0;
                for (std::size_t prior = 0; prior < candidate; ++prior)
                    if (String(results[prior], "input_kind") == "menu" &&
                            Integer(results[prior], "machine_index") < 0)
                        ++preceding;
                if (preceding == static_cast<int>(index)) {
                    result_index = static_cast<int>(candidate);
                    break;
                }
            }
        }
        const std::string stable_id = result_index >= 0
            ? OptionId(report, CandidateSelectionMaterial(
                results[static_cast<std::size_t>(result_index)]))
            : id;
        if (stable_id != id) {
            option_ids.erase(id);
            if (!option_ids.insert(stable_id).second)
                throw std::runtime_error("duplicate generated option id");
        }
        auto option = BaseOption(stable_id, "safe_plan", result_index, -1,
            result_index >= 0
                ? String(results[static_cast<std::size_t>(result_index)], "password") : "",
            result_index >= 0
                ? String(results[static_cast<std::size_t>(result_index)], "confidence", u8"高") : u8"高",
            true);
        option["menu_plan_indices"] =
            json::Value::Array{static_cast<std::int64_t>(index)};
        options.push_back(std::move(option));
    }

    // Condition substitutions are one atomic operation per menu input route.
    // Keep every transition rewrite together; selecting only one of the eight
    // guarded feature edges would leave the lock partially active.
    std::set<std::string> condition_parameters;
    for (const auto& item : condition) {
        const std::string parameter = String(item, "input_parameter");
        if (parameter.empty()) throw std::runtime_error("condition rewrite input missing");
        condition_parameters.insert(parameter);
    }
    for (const auto& parameter : condition_parameters) {
        std::vector<std::size_t> indices;
        for (std::size_t index = 0; index < condition.size(); ++index)
            if (String(condition[index], "input_parameter") == parameter)
                indices.push_back(index);
        if (indices.empty()) continue;
        int result_index = -1;
        for (std::size_t index = 0; index < results.size(); ++index) {
            if (String(results[index], "input_kind") == "menu" &&
                    String(results[index], "parameter") == parameter &&
                    String(results[index], "confidence", u8"参考") == u8"高") {
                result_index = static_cast<int>(index); break;
            }
        }
        const json::Value* input_route = result_index >= 0
            ? &results[static_cast<std::size_t>(result_index)] : nullptr;
        if (!input_route) {
            for (std::size_t index = 0; index < candidates.size(); ++index) {
                if (String(candidates[index], "input_kind") == "menu" &&
                        String(candidates[index], "parameter") == parameter) {
                    if (input_route) throw std::runtime_error("ambiguous condition rewrite route");
                    input_route = &candidates[index];
                }
            }
        }
        if (!input_route) throw std::runtime_error("condition rewrite result missing");
        const std::string id = OptionId(report, CandidateSelectionMaterial(*input_route));
        if (!option_ids.insert(id).second)
            throw std::runtime_error("duplicate condition rewrite option");
        auto option = BaseOption(id, "safe_plan", result_index, -1,
            String(*input_route, "password"), u8"高", true);
        json::Value::Array rewrite_indices;
        for (const auto index : indices) rewrite_indices.push_back(static_cast<std::int64_t>(index));
        option["condition_plan_indices"] = std::move(rewrite_indices);
        options.push_back(std::move(option));
    }

    // Populate option-level dependencies only when the dependency is itself a
    // user-selectable lock. Hidden technical producers remain physical plan
    // dependencies and are still included by ScopeServerPlan.
    for (auto& option : options) {
        std::set<std::string> required;
        for (const auto index : ReadIndexArray(option,
                "state_plan_indices", state.size())) {
            for (const auto& dependency : Dependencies(state[index])) {
                const auto found = state_by_coordinate.find(dependency);
                if (found == state_by_coordinate.end())
                    throw std::runtime_error("missing state plan dependency");
                const auto visible = state_option_ids.find(found->second);
                if (visible != state_option_ids.end() &&
                        visible->second != String(option, "option_id"))
                    required.insert(visible->second);
            }
        }
        json::Value::Array ids;
        for (const auto& id : required) ids.push_back(id);
        option["requires_option_ids"] = std::move(ids);
    }

    for (std::size_t index = 0; index < candidates.size(); ++index) {
        bool has_plan = false;
        const bool has_condition_plan = condition_parameters.count(
            String(candidates[index], "parameter")) != 0;
        for (const auto& plan : state)
            if (SameCandidatePlan(candidates[index], plan)) {
                has_plan = true;
                break;
            }
        if (has_plan || has_condition_plan) continue;
        std::ostringstream material;
        material << CandidateSelectionMaterial(candidates[index]);
        const std::string id = OptionId(report, material.str());
        if (!option_ids.insert(id).second) {
            const bool promoted_safe_option = std::any_of(options.begin(),
                options.end(), [&](const json::Value& option) {
                    return String(option, "option_id") == id &&
                        String(option, "option_kind") == "safe_plan";
                });
            // Only an unproved terminal may be collapsed into the strict plan
            // that promoted the same input route.  A second, already-known but
            // different terminal sharing that identity is contradictory
            // evidence and must fail closed instead of silently choosing one.
            if (promoted_safe_option &&
                    Integer(candidates[index], "terminal_state") < 0)
                continue;
            throw std::runtime_error("duplicate candidate selection identity");
        }
        options.push_back(BaseOption(id, "candidate", -1,
            static_cast<int>(index), String(candidates[index], "password"),
            String(candidates[index], "confidence", u8"参考"), false));
    }
    report["plan_options"] = std::move(options);
}

json::Value ScopeServerPlan(const fs::path& report_path,
    const fs::path& selection_path) {
    const std::string report_bytes = ReadUtf8File(report_path);
    const std::string selection_bytes = ReadUtf8File(selection_path);
    json::Value report = json::Parse(report_bytes);
    const json::Value selection = json::Parse(selection_bytes);
    if (!report.is_object() || String(report, "engine") != "VrcNativeCore/cpp" ||
            String(report, "graph_schema_version") != "vpf-structural-graph/1" ||
            !IsLowerHex64(String(report, "source_sha256")) ||
            !IsLowerHex64(String(report, "policy_hash")) ||
            String(report, "policy_version").empty())
        throw std::runtime_error("invalid scoped report bindings");
    if (!selection.is_object() || selection.object().size() != 1 ||
            !Field(selection, "selected_option_ids") ||
            !Field(selection, "selected_option_ids")->is_array())
        throw std::runtime_error("invalid selection shape");
    std::set<std::string> selected;
    for (const auto& item : Array(selection, "selected_option_ids")) {
        if (!item.is_string() || !IsLowerHex64(item.string()) ||
                !selected.insert(item.string()).second)
            throw std::runtime_error("invalid selected option id");
    }
    if (selected.empty() || selected.size() > 64)
        throw std::runtime_error("empty or excessive selection");

    const auto* supplied_options = Field(report, "plan_options");
    if (!supplied_options || !supplied_options->is_array())
        throw std::runtime_error("missing plan options");
    const std::string supplied_material = supplied_options->dump(0);
    AttachServerPlanOptions(report);
    if (Field(report, "plan_options")->dump(0) != supplied_material)
        throw std::runtime_error("plan options integrity mismatch");

    std::map<std::string, const json::Value*> options;
    for (const auto& option : Array(report, "plan_options")) {
        const std::string id = String(option, "option_id");
        const std::string kind = String(option, "option_kind");
        if (!IsLowerHex64(id) || (kind != "safe_plan" && kind != "candidate") ||
                !options.emplace(id, &option).second)
            throw std::runtime_error("invalid plan option record");
    }
    std::vector<const json::Value*> chosen;
    for (const auto& id : selected) {
        const auto found = options.find(id);
        if (found == options.end())
            throw std::runtime_error("unknown selected option id");
        chosen.push_back(found->second);
    }

    const std::string report_hash = Sha256Hex(report_bytes, false);
    const std::string selection_hash = Sha256Hex(selection_bytes, false);
    std::set<std::string> resolved = selected;
    std::set<std::string> automatic;
    json::Value output(json::Value::Object{});
    output["state_bypasses"] = json::Value::Array{};
    output["menu_bypasses"] = json::Value::Array{};
    output["condition_rewrites"] = json::Value::Array{};

    if (const auto* deep = Field(report, "deep_analysis_request")) {
        if (!deep->is_object())
            throw std::runtime_error("invalid deep analysis request");
        output["status"] = "need_evidence";
        output["deep_analysis_request"] = *deep;
        AddCommonScopeFields(output, report, report_hash, selection_hash,
            selected, resolved, automatic);
        return output;
    }

    std::vector<const json::Value*> candidate_options;
    for (const auto* option : chosen)
        if (String(*option, "option_kind") == "candidate")
            candidate_options.push_back(option);
    if (!candidate_options.empty()) {
        const auto request = MergeConfirmationRequests(report, candidate_options);
        output["status"] = request.is_object() ? "need_evidence" : "no_plan";
        if (request.is_object())
            output["confirmation_deep_scan_request"] = request;
        AddCommonScopeFields(output, report, report_hash, selection_hash,
            selected, resolved, automatic);
        return output;
    }

    const auto& state = Array(report, "state_bypasses");
    const auto& menu = Array(report, "menu_bypasses");
    const auto& condition = Array(report, "condition_rewrites");
    std::map<StateCoordinate, std::size_t> state_by_coordinate;
    for (std::size_t index = 0; index < state.size(); ++index)
        if (!state_by_coordinate.emplace(Coordinate(state[index]), index).second)
            throw std::runtime_error("duplicate state plan coordinate");
    std::set<std::size_t> state_indices;
    std::set<std::size_t> menu_indices;
    std::set<std::size_t> condition_indices;
    for (const auto* option : chosen) {
        const auto option_state = ReadIndexArray(*option,
            "state_plan_indices", state.size());
        const auto option_menu = ReadIndexArray(*option,
            "menu_plan_indices", menu.size());
        const auto option_condition = ReadIndexArray(*option,
            "condition_plan_indices", condition.size());
        state_indices.insert(option_state.begin(), option_state.end());
        menu_indices.insert(option_menu.begin(), option_menu.end());
        condition_indices.insert(option_condition.begin(), option_condition.end());
    }

    std::set<std::size_t> visiting;
    std::function<void(std::size_t)> include_dependencies =
        [&](const std::size_t index) {
            if (state_indices.count(index) && !visiting.insert(index).second)
                throw std::runtime_error("state plan dependency cycle");
            for (const auto& dependency : Dependencies(state[index])) {
                const auto found = state_by_coordinate.find(dependency);
                if (found == state_by_coordinate.end())
                    throw std::runtime_error("missing state plan dependency");
                if (state_indices.insert(found->second).second)
                    include_dependencies(found->second);
            }
            visiting.erase(index);
        };
    const auto roots = state_indices;
    for (const auto index : roots) include_dependencies(index);

    for (const auto& [id, option] : options) {
        if (selected.count(id) || String(*option, "option_kind") != "safe_plan")
            continue;
        const auto indices = ReadIndexArray(*option,
            "state_plan_indices", state.size());
        const auto menus = ReadIndexArray(*option,
            "menu_plan_indices", menu.size());
        const auto conditions = ReadIndexArray(*option,
            "condition_plan_indices", condition.size());
        const bool included = (!indices.empty() && std::all_of(indices.begin(),
            indices.end(), [&](const auto index) { return state_indices.count(index) != 0; })) ||
            (!menus.empty() && std::all_of(menus.begin(), menus.end(),
            [&](const auto index) { return menu_indices.count(index) != 0; })) ||
            (!conditions.empty() && std::all_of(conditions.begin(), conditions.end(),
            [&](const auto index) { return condition_indices.count(index) != 0; }));
        if (included) {
            automatic.insert(id);
            resolved.insert(id);
        }
    }

    json::Value::Array scoped_state;
    json::Value::Array scoped_menu;
    json::Value::Array scoped_condition;
    for (std::size_t index = 0; index < state.size(); ++index)
        if (state_indices.count(index)) scoped_state.push_back(state[index]);
    for (std::size_t index = 0; index < menu.size(); ++index)
        if (menu_indices.count(index)) scoped_menu.push_back(menu[index]);
    for (std::size_t index = 0; index < condition.size(); ++index)
        if (condition_indices.count(index)) scoped_condition.push_back(condition[index]);
    output["state_bypasses"] = scoped_state;
    output["menu_bypasses"] = scoped_menu;
    output["condition_rewrites"] = scoped_condition;
    output["status"] = (scoped_state.empty() && scoped_menu.empty() && scoped_condition.empty())
        ? "no_plan" : "ready";
    if (!scoped_state.empty() || !scoped_menu.empty() || !scoped_condition.empty()) {
        json::Value::Object material;
        material["menu_bypasses"] = scoped_menu;
        material["state_bypasses"] = scoped_state;
        material["condition_rewrites"] = scoped_condition;
        output["plan_sha256"] = Sha256Hex(
            json::Value(material).dump(0), false);
    }
    AddCommonScopeFields(output, report, report_hash, selection_hash,
        selected, resolved, automatic);
    return output;
}

}  // namespace vrc
