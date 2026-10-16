#include "menu_condition_proof.hpp"
#include <cmath>
#include <cstdint>
#include <limits>
#include <set>

namespace vrc {
namespace {
const json::Value* F(const json::Value& v, const char* key) { return v.is_object() ? v.find(key) : nullptr; }
const json::Value::Array& A(const json::Value& v, const char* key) {
    static const json::Value::Array empty;
    const auto* p = F(v, key); return p && p->is_array() ? p->array() : empty;
}
std::string S(const json::Value& v, const char* key) {
    const auto* p = F(v, key); return p && p->is_string() ? p->string() : std::string{};
}
bool B(const json::Value& v, const char* key) {
    const auto* p = F(v, key); return p && p->is_bool() && p->boolean();
}
bool HasArray(const json::Value& v, const char* key) {
    const auto* p = F(v, key); return p && p->is_array();
}
bool UInt32Field(const json::Value& v, const char* key) {
    const auto* p = F(v, key);
    return p && p->is_number() && p->number() >= 0 && p->number() <= 4294967295.0 &&
        std::floor(p->number()) == p->number();
}
int I(const json::Value& v, const char* key, int fallback = -1) {
    const auto* p = F(v, key);
    return p && p->is_number() && std::isfinite(p->number()) &&
        std::floor(p->number()) == p->number() &&
        p->number() >= std::numeric_limits<int>::min() && p->number() <= std::numeric_limits<int>::max()
        ? static_cast<int>(p->number()) : fallback;
}
std::uint32_t Hash(const std::string& text) {
    std::uint32_t crc = 0xffffffffu;
    for (unsigned char c : text) {
        crc ^= c;
        for (int i = 0; i != 8; ++i) crc = (crc >> 1u) ^ (0xedb88320u & (0u - (crc & 1u)));
    }
    return crc ^ 0xffffffffu;
}
bool ValidCondition(const json::Value& condition) {
    const int mode = I(condition, "mode");
    const auto* threshold = F(condition, "threshold");
    const auto* hash = F(condition, "parameter_hash");
    const auto* exit_time = F(condition, "exit_time");
    return !S(condition, "parameter").empty() &&
        (mode == 1 || mode == 2 || mode == 3 || mode == 4 || mode == 6 || mode == 7) &&
        !F(condition, "threshold_encoding") && threshold && threshold->is_number() &&
        std::isfinite(threshold->number()) && hash && hash->is_number() &&
        hash->number() >= 0 && hash->number() <= 4294967295.0 &&
        std::floor(hash->number()) == hash->number() && exit_time && exit_time->is_number() &&
        exit_time->number() == 0.0 && !std::signbit(exit_time->number());
}
json::Value Condition(const json::Value& value) {
    json::Value::Object result;
    result["mode"] = I(value, "mode");
    result["parameter"] = S(value, "parameter");
    result["parameter_hash"] = *F(value, "parameter_hash");
    result["threshold"] = *F(value, "threshold");
    result["exit_time"] = *F(value, "exit_time");
    return result;
}
}

MenuConditionSubstitutionProof ProveMenuBooleanConditionSubstitution(
    const json::Value& graph, const std::string& parameter) {
    const auto reject = [](const char* reason) { return MenuConditionSubstitutionProof{false, reason, {}}; };
    if (parameter.empty() || parameter.size() > 1024 || Hash(parameter) == 0)
        return reject("invalid_parameter");
    const std::set<std::string> environment_parameters{"IsLocal", "AFK", "Seated", "InStation",
        "Grounded", "MuteSelf", "Earmuffs", "IsOnFriendsList", "ScaleModified", "AvatarVersion"};
    if (environment_parameters.count(parameter)) return reject("environment_parameter_not_a_menu_gate");
    if (S(graph, "analysis_depth") != "targeted_deep") return reject("deep_evidence_required");
    const auto* stats = F(graph, "stats");
    if (!stats || I(*stats, "controller_fail") != 0) return reject("controller_parse_incomplete");
    int expression_matches = 0;
    std::set<std::string> expression_names, menu_names;
    for (const auto& item : A(graph, "expression_parameters")) {
        if (!S(item, "name").empty()) expression_names.insert(S(item, "name"));
        if (S(item, "name") == parameter) {
        ++expression_matches;
        if (I(item, "value_type") != 2) return reject("gate_not_expression_bool");
        }
    }
    if (expression_matches != 1) return reject("ambiguous_expression_parameter");
    for (const auto& menu : A(graph, "menus"))
        for (const auto& control : A(menu, "controls")) {
            if (!S(control, "parameter").empty()) menu_names.insert(S(control, "parameter"));
            for (const auto& sub : A(control, "sub_parameters"))
                if (sub.is_string() && !sub.string().empty()) menu_names.insert(sub.string());
        }
    std::set<std::string> active, seen;
    for (const auto& item : A(graph, "active_fx_controller_ids")) {
        if (!item.is_string() || item.string().empty() || !active.insert(item.string()).second)
            return reject("ambiguous_active_fx");
    }
    if (active.empty()) return reject("active_fx_missing");
    const auto& controllers = A(graph, "controllers");
    if (controllers.empty() || controllers.size() > 256) return reject("controller_budget");
    MenuConditionSubstitutionProof proof;
    const std::set<std::string> understood_behaviours{
        "VRCAvatarParameterDriver", "VRCAnimatorLayerControl", "VRCPlayableLayerControl",
        "VRCAnimatorTrackingControl", "VRCAnimatorLocomotionControl", "VRCAnimatorTemporaryPoseSpace"};
    for (const auto& controller : controllers) {
        const std::string path = S(controller, "path_id");
        if (path.empty() || !seen.insert(path).second) return reject("ambiguous_controller");
        // Only active FX layers can consume the menu gate. Detached copied
        // controllers are retained in the graph for provenance, but their
        // optional behaviour mapping must not make an active proof fail or
        // become evidence of a competing writer.
        if (!active.count(path)) continue;
        const auto* evidence = F(controller, "parameter_read_evidence");
        if (!evidence || !B(*evidence, "state_fields_complete") || !B(*evidence, "driver_mapping_complete"))
            return reject("parameter_consumer_evidence_incomplete");
        if (!HasArray(*evidence, "behaviour_scripts") || !HasArray(*evidence, "other_state_reads"))
            return reject("parameter_consumer_evidence_incomplete");
        for (const auto& script : A(*evidence, "behaviour_scripts"))
            if (!script.is_string() || !understood_behaviours.count(script.string()))
                return reject("unknown_state_behaviour");
        for (const auto& read : A(*evidence, "other_state_reads")) {
            const auto* hash = F(read, "parameter_hash");
            if (!UInt32Field(read, "parameter_hash")) return reject("state_parameter_hash_missing");
            if (S(read, "parameter") == parameter ||
                (hash && hash->is_number() && hash->number() == Hash(parameter)))
                return reject("gate_controls_state_motion");
        }
        int declarations = 0;
        for (const auto& item : A(controller, "parameter_defaults")) if (S(item, "name") == parameter) {
            ++declarations;
            if (S(item, "type") != "bool") return reject("gate_controller_type_mismatch");
        }
        const auto& machines = A(controller, "machines");
        for (std::size_t mi = 0; mi < machines.size(); ++mi) {
            const auto& machine = machines[mi];
            for (const auto& transition : A(machine, "any_transitions"))
                for (const auto& condition : A(transition, "conditions"))
                    if (S(condition, "parameter") == parameter ||
                        (UInt32Field(condition, "parameter_hash") && F(condition, "parameter_hash")->number() == Hash(parameter)))
                        return reject("any_state_gate_not_supported");
            const auto& states = A(machine, "states");
            for (std::size_t si = 0; si < states.size(); ++si) {
                const auto& state = states[si];
                if (!HasArray(state, "parameter_writes") || !HasArray(state, "blend_parameter_reads") ||
                    !HasArray(state, "transitions")) return reject("state_evidence_incomplete");
                for (const auto& write : A(state, "parameter_writes"))
                    if ((!S(write, "source").empty() && Hash(S(write, "source")) == Hash(parameter)) ||
                        (!S(write, "name").empty() && Hash(S(write, "name")) == Hash(parameter)))
                        return reject("gate_driver_dependency");
                for (const auto& read : A(state, "blend_parameter_reads")) {
                    const auto* hash = F(read, "parameter_hash");
                    if (!UInt32Field(read, "parameter_hash")) return reject("blend_parameter_hash_missing");
                    if (S(read, "parameter") == parameter ||
                        (hash && hash->is_number() && hash->number() == Hash(parameter)))
                        return reject("gate_controls_blending");
                }
                const auto& transitions = A(state, "transitions");
                for (std::size_t ti = 0; ti < transitions.size(); ++ti) {
                    const auto& transition = transitions[ti];
                    const auto& conditions = A(transition, "conditions");
                    if (!HasArray(transition, "conditions") ||
                        I(transition, "raw_condition_count") != static_cast<int>(conditions.size()))
                        return reject("condition_indices_incomplete");
                    std::vector<std::size_t> gates;
                    std::size_t copy = conditions.size();
                    for (std::size_t ci = 0; ci < conditions.size(); ++ci) {
                        const auto* hash = F(conditions[ci], "parameter_hash");
                        if (!UInt32Field(conditions[ci], "parameter_hash") || I(conditions[ci], "raw_index") != static_cast<int>(ci))
                            return reject("serialized_condition_identity_missing");
                        const bool hash_match = hash && hash->is_number() && hash->number() == Hash(parameter);
                        const bool name_match = S(conditions[ci], "parameter") == parameter;
                        if (hash_match != name_match) return reject("parameter_name_hash_mismatch");
                        if (name_match) gates.push_back(ci);
                        else if (copy == conditions.size()) copy = ci;
                    }
                    if (gates.empty()) continue;
                    if (!active.count(path) || declarations != 1) return reject("gate_owner_not_proven");
                    if (conditions.size() != 2 || copy == conditions.size()) return reject("gate_without_feature_predicate");
                    if (I(transition, "raw_condition_count") != static_cast<int>(conditions.size()))
                        return reject("condition_indices_incomplete");
                    if (I(transition, "destination") < 0 ||
                        I(transition, "destination") >= static_cast<int>(states.size()))
                        return reject("destination_not_resolved");
                    for (std::size_t ci = 0; ci < conditions.size(); ++ci)
                        if (!ValidCondition(conditions[ci]) || I(conditions[ci], "raw_index") != static_cast<int>(ci))
                            return reject("unknown_condition_semantics");
                    const std::string donor_parameter = S(conditions[copy], "parameter");
                    const int donor_mode = I(conditions[copy], "mode");
                    if (!expression_names.count(donor_parameter) || !menu_names.count(donor_parameter) ||
                        donor_mode != 3 && donor_mode != 4 && donor_mode != 6 && donor_mode != 7)
                        return reject("donor_not_menu_numeric_predicate");
                    const auto* destination = F(transition, "raw_destination");
                    if (!destination || !destination->is_number() || destination->number() < 0 ||
                        destination->number() > 4294967295.0 || std::floor(destination->number()) != destination->number())
                        return reject("serialized_destination_missing");
                    for (const auto ci : gates) {
                        if (I(conditions[ci], "mode") != 1) return reject("gate_polarity_not_positive");
                        json::Value::Object rewrite;
                        rewrite["path_id"] = path;
                        rewrite["machine_index"] = static_cast<std::int64_t>(mi);
                        rewrite["state_index"] = static_cast<std::int64_t>(si);
                        rewrite["transition_index"] = static_cast<std::int64_t>(ti);
                        rewrite["condition_index"] = static_cast<std::int64_t>(ci);
                        rewrite["copy_condition_index"] = static_cast<std::int64_t>(copy);
                        rewrite["condition_count"] = static_cast<std::int64_t>(conditions.size());
                        rewrite["destination"] = I(transition, "destination");
                        rewrite["raw_destination"] = *destination;
                        rewrite["before"] = Condition(conditions[ci]);
                        rewrite["after"] = Condition(conditions[copy]);
                        rewrite["method"] = "native_menu_boolean_guard_substitution";
                        proof.rewrites.push_back(std::move(rewrite));
                        if (proof.rewrites.size() > 4096) return reject("rewrite_budget");
                    }
                }
            }
        }
    }
    for (const auto& id : active) if (!seen.count(id)) return reject("active_fx_missing");
    if (proof.rewrites.empty()) return reject("no_positive_gate_uses");
    proof.accepted = true;
    proof.reason = "and_idempotence_equivalent_to_gate_true";
    return proof;
}
}
