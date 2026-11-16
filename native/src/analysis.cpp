#include "analysis.hpp"

#include "avacrypt_v1_solver.hpp"
#include "common.hpp"
#include "rule_profile.hpp"
#include "state_plan_contract.hpp"
#include "menu_condition_proof.hpp"
#include "vmp_bridge.hpp"
#if defined(VRC_ENABLE_LOCAL_SMT)
#include "local_smt_experiment.hpp"
#endif

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cmath>
#include <cstring>
#include <deque>
#include <fstream>
#include <functional>
#include <iomanip>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>

namespace fs = std::filesystem;

namespace vrc {
namespace {

struct Condition { int mode = 0; std::string parameter; double threshold = 0; };
struct Transition {
    int destination = -1;
    std::vector<Condition> conditions;
    bool has_exit_time = false;
    double exit_time = 0;
    double duration = 0;
    bool has_fixed_duration = false;
    int interruption_source = 0;
    bool ordered_interruption = false;
    bool can_transition_to_self = false;
};
struct ParameterWrite {
    std::string name, source;
    int type = -1;
    double value = 0;
    std::map<std::string, bool> operation_flags{};
    std::map<std::string, double> operation_numbers{};
};
struct AnimationWrite {
    std::string name, path, source;
    std::uint32_t path_hash = 0, attribute_hash = 0;
    double value = 0;
    std::string binding_status, target_id;
    int target_type = 0;
    bool serialized_active_known = false, serialized_active = false;
    int clip_index = -1;
    std::string target_path;
};
struct BlendParameterRead {
    std::string parameter;
    std::uint32_t parameter_hash = 0;
    int tree_index = -1, node_index = -1, child_node_index = -1;
    int clip_id = -1;
};
struct StreamKey {
    double time = 0;
    std::array<double, 4> coefficients{};
};
struct StreamCurve {
    int curve_index = -1;
    std::string attribute;
    std::uint32_t attribute_hash = 0, path_hash = 0;
    int type_id = 0;
    std::vector<StreamKey> keys;
};
struct StreamedClipEvidence {
    int clip_index = -1;
    double start_time = 0, stop_time = 0;
    std::vector<StreamCurve> curves;
};
struct MotionEvidence {
    bool has_cycle_offset = false;
    double cycle_offset = 0;
    std::string cycle_offset_parameter;
    std::vector<int> clip_ids;
    std::vector<StreamedClipEvidence> streamed_clips;
};
struct State {
    std::string name;
    std::vector<Transition> transitions;
    std::vector<ParameterWrite> writes;
    std::vector<AnimationWrite> animation_writes;
    std::vector<AnimationWrite> manual_activation_writes;
    std::vector<BlendParameterRead> blend_parameter_reads;
    MotionEvidence motion;
};
struct Machine { int default_state = 0; double default_weight = 1.0; bool default_weight_known = true; std::vector<State> states; std::vector<Transition> any_transitions; bool has_selector_semantics = false; };
struct ParameterDefault { std::string type; double value = 0; };
struct WriterCensus {
    std::map<std::string, std::set<std::size_t>> set_owners;
    std::set<std::string> non_set_names;
    std::set<std::string> animation_names;
};
struct Controller {
    std::string path_id, name;
    std::map<std::string, ParameterDefault> parameter_defaults;
    std::vector<Machine> machines;
    // Controllers are immutable after ParseSnapshot; this cache is owned by
    // that snapshot (never global or keyed by a reused pointer).
    mutable std::optional<WriterCensus> writer_census;
};
struct MenuControl {
    std::string name, parameter, submenu;
    std::string icon_path_id, icon_type;
    std::vector<std::string> sub_parameters;
    int type = 0; double value = 0; bool has_icon = false;
};
struct Menu { std::string id, name; std::vector<MenuControl> controls; };
struct RadialControlRef { std::string name, parameter; };
struct RadialGroup { std::string menu; std::vector<RadialControlRef> controls; };
struct Candidate {
    std::string controller, parameter, raw, password, note, confidence;
    int unlock_state;
    std::string unlock_method;
    bool generic_chain;
    bool menu_mapped = false;
    // Reverse-derived candidates are allowed to remain visible as bounded
    // references, but a click guide is only valid after the exact state plan
    // (and, for Contact locks, its producer half) has been committed.
    bool guide_allowed = true;
    std::string analysis_origin = "legacy";
    std::string family;
    std::string runtime_status = "runtime_possible";
    // menu: visible wheel buttons; osc: raw expression-parameter values that
    // remain enterable even when the serialized menu reference is absent.
    std::string input_kind = "menu";
    // Internal provenance is intentionally omitted from the public report.
    // It lets the final arbiter require an exact state-rewrite plan for the
    // same controller/machine/terminal instead of accepting an unrelated plan
    // emitted elsewhere in a large FX controller.
    std::string controller_path_id;
    std::size_t machine_index = static_cast<std::size_t>(-1);
    // A Contact-aware terminal proof is bound to the candidate that it
    // produced.  Reusing these exact producer coordinates later prevents the
    // plan arbiter from independently selecting a different writer machine in
    // a large controller.
    std::size_t contact_producer_machine = static_cast<std::size_t>(-1);
    int contact_ready_state = -1;
    // Read-only menu provenance, deliberately excluded from CandidateJson
    // and candidate_id. A one-action terminal retains its historical public
    // navigation identity while evidence selection follows the actual input.
    std::string menu_terminal_parameter;

    Candidate(std::string controller_value, std::string parameter_value,
        std::string raw_value, std::string password_value,
        std::string note_value, std::string confidence_value = u8"参考",
        int unlock_state_value = -1, std::string unlock_method_value = {},
        bool generic_chain_value = false)
        : controller(std::move(controller_value)),
          parameter(std::move(parameter_value)), raw(std::move(raw_value)),
          password(std::move(password_value)), note(std::move(note_value)),
          confidence(std::move(confidence_value)),
          unlock_state(unlock_state_value),
          unlock_method(std::move(unlock_method_value)),
          generic_chain(generic_chain_value) {}
};

// A reverse password is considered proven only after the exact rewrite plan
// that realizes its terminal has been committed to the final report.  Contact
// gated locks need two coordinated rewrites, so keep their complete identities
// while staging instead of using a first-wins producer-machine key.
using ReversePlanKey =
    std::tuple<std::string, std::size_t, int, std::string>;
using DynamicProducerKey =
    std::tuple<std::string, std::size_t, int, std::string>;
using DynamicKeypadKey =
    std::tuple<std::string, std::size_t, int, std::string>;
using DynamicPairKey = std::pair<DynamicProducerKey, DynamicKeypadKey>;

struct StagedDynamicContactPlan {
    DynamicPairKey key;
    int producer_before = -1;
    int keypad_before = -1;
    json::Value::Object producer_bypass;
    json::Value::Object keypad_bypass;
    bool inconsistent_duplicate = false;
};
struct Guide {
    std::string password, menu, parameter;
    std::vector<std::string> keys;
    std::vector<int> values;
    // Most keypads write one numeric parameter. Split-button generators use
    // one Bool per digit, so retain an optional parameter for every step.
    // Empty keeps the legacy protocol and UI behavior unchanged.
    std::vector<std::string> parameters;
};
struct MenuMapEntry {
    std::string name;
    int raw_value = 0;
};
using MenuKeyMap = std::map<int, MenuMapEntry>;
using MenuMaps = std::map<std::string,
    std::vector<std::pair<std::string, MenuKeyMap>>>;
struct ContactBindingCandidate {
    std::string parameter, sender;
    std::set<std::uint32_t> path_hashes;
};
struct RawContactComponent {
    std::string path_id, kind, parameter, transform, parent_transform;
    std::set<std::string> tags;
    std::set<std::uint32_t> hierarchy_path_hashes;
    std::array<double, 3> position{};
    std::array<double, 3> local_position{};
    bool position_known = false, local_position_known = false;
    bool enabled = false, game_object_active = false, allow_self = false;
    int receiver_type = -1;
};
struct Snapshot {
    int nonfinite_condition_count = 0;
    std::vector<ContactBindingCandidate> contact_binding_candidates;
    std::string source_sha256;
    // Historical graph fixtures predate adaptive extraction and already
    // contain every effect their extractor elected to keep.  Treat absence
    // as complete so a new core never changes old graph outcomes.
    std::string analysis_depth = "legacy_complete";
    int deep_scan_machine_count = 0;
    std::vector<Controller> controllers;
    std::vector<Menu> menus;
    int controller_ok = 0, controller_fail = 0, md5_parameters = 0, unicode_obfuscated = 0;
    int avacrypt_v1_materials = 0, avacrypt_v2_materials = 0;
    std::set<int> avacrypt_v2_bit_indices;
    std::size_t avacrypt_v2_mesh_offset_signatures = 0;
    bool avacrypt_leaked = false;
    std::vector<std::string> avacrypt_v1_parameters;
    std::vector<std::string> avacrypt_v2_parameters;
    std::vector<AvaCryptV1MeshProbe> avacrypt_v1_mesh_probes;
    std::set<std::string> shell_protector_parameters;
    std::set<std::string> shell_protector_raw_markers;
    std::set<int> shell_protector_direct_key_indices;
    bool shell_protector_multiplexed = false;
    std::set<std::string> expression_parameters;
    std::set<std::string> saved_expression_parameters;
    std::map<std::string, ParameterDefault> expression_parameter_defaults;
    std::set<std::string> forced_contact_parameters;
    // Contact receiver parameters are externally mutable at runtime even when
    // the extractor cannot prove a fixed self-contact geometry.  Keep them
    // separate from forced/dynamic gates so a keypad guarded by a user contact
    // is not misclassified as a dead branch.
    std::set<std::string> contact_input_parameters;
    std::set<std::string> dynamic_contact_parameters;
    std::vector<RawContactComponent> raw_contact_components;
    // Remote structural graphs carry raw Contact components rather than
    // client-derived gates.  A fast graph cannot prove that a geometrically
    // overlapping sender is never animated, so those parameters trigger a
    // targeted deep request before they can become forced gates.
    bool raw_contact_effects_pending = false;
    std::string graph_schema_version;
    std::set<std::string> active_fx_controller_ids;
    std::set<std::string> selected_controller_ids;
    std::set<std::string> active_root_menu_ids;
    int avatar_descriptor_count = 0;
    int custom_expressions_count = 0;
    int missing_expression_parameters_count = 0;
    int missing_expression_menu_count = 0;
    int custom_fx_count = 0;
    int missing_fx_controller_count = 0;
    int animation_hash_count = 0;
    int animation_hash_unique_count = 0;
};

#include "causal_trace.inc"

const ParameterDefault* EffectiveRuntimeDefault(
    const Snapshot& snapshot, const Controller& controller,
    const std::string& parameter);
bool HasStrongPasswordSemantics(const Machine& machine,
    const std::string& keypad_parameter);

// ParameterDriver type 0 is the only write operation modelled by the
// normalized graph simulator.  A non-type-0 write or an animation constant
// targeting a value that participates in a proof is not equivalent to
// "no write"; treating it as absent can turn an unknown path into a trusted
// password.  Keep a small per-controller census so detectors can fail closed
// without rejecting unrelated writes to other parameters.
const WriterCensus& BuildWriterCensus(const Controller& controller) {
    if (controller.writer_census) return *controller.writer_census;
    WriterCensus census;
    for (std::size_t machine_index = 0;
         machine_index < controller.machines.size(); ++machine_index) {
        const auto& machine = controller.machines[machine_index];
        for (const auto& state : machine.states) {
            for (const auto& write : state.writes) {
                if (write.name.empty()) continue;
                if (write.type == 0)
                    census.set_owners[write.name].insert(machine_index);
                else
                    census.non_set_names.insert(write.name);
            }
            for (const auto& write : state.animation_writes)
                if (!write.name.empty()) census.animation_names.insert(write.name);
        }
    }
    controller.writer_census = std::move(census);
    return *controller.writer_census;
}

bool HasActiveOtherControllerWriter(const Snapshot& snapshot,
    const Controller& current, const std::string& parameter) {
    if (snapshot.active_fx_controller_ids.empty() ||
        current.path_id.empty() ||
        snapshot.active_fx_controller_ids.count(current.path_id) == 0)
        return false;
    for (const auto& controller : snapshot.controllers) {
        if (controller.path_id == current.path_id ||
            snapshot.active_fx_controller_ids.count(controller.path_id) == 0)
            continue;
        for (const auto& machine : controller.machines)
            for (const auto& state : machine.states) {
                for (const auto& write : state.writes)
                    if (write.name == parameter) return true;
                for (const auto& write : state.animation_writes)
                    if (write.name == parameter) return true;
            }
    }
    return false;
}

const json::Value* Field(const json::Value& v, const char* key) { return v.is_object() ? v.find(key) : nullptr; }
std::string String(const json::Value& v, const char* key, std::string fallback = {}) {
    const auto* p = Field(v, key); return p && p->is_string() ? p->string() : fallback;
}
int Integer(const json::Value& v, const char* key, int fallback = 0) {
    const auto* p = Field(v, key); return p && p->is_number() ? static_cast<int>(std::llround(p->number())) : fallback;
}
double Number(const json::Value& v, const char* key, double fallback = 0) {
    const auto* p = Field(v, key); return p && p->is_number() ? p->number() : fallback;
}
bool Boolean(const json::Value& v, const char* key, bool fallback = false) {
    const auto* p = Field(v, key); return p && p->is_bool() ? p->boolean() : fallback;
}
const json::Value::Array& Array(const json::Value& v, const char* key) {
    static const json::Value::Array empty; const auto* p = Field(v, key); return p && p->is_array() ? p->array() : empty;
}

bool Vector3Field(const json::Value& value, const char* key,
    std::array<double, 3>& output) {
    const auto& values = Array(value, key);
    if (values.size() != 3) return false;
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (!values[index].is_number() || !std::isfinite(values[index].number()))
            return false;
        output[index] = values[index].number();
    }
    return true;
}

bool NearZero(const std::array<double, 3>& value) {
    return std::all_of(value.begin(), value.end(),
        [](const double item) { return std::abs(item) <= 1e-6; });
}

std::uint32_t Crc32(const std::string& value) {
    std::uint32_t crc = 0xFFFFFFFFu;
    for (const unsigned char byte : value) {
        crc ^= byte;
        for (int bit = 0; bit < 8; ++bit)
            crc = (crc >> 1u) ^ (0xEDB88320u &
                static_cast<std::uint32_t>(-static_cast<int>(crc & 1u)));
    }
    return crc ^ 0xFFFFFFFFu;
}

bool IsHexDigest(const std::string& value) {
    if (value.size() != 64) return false;
    return std::all_of(value.begin(), value.end(), [](const unsigned char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') ||
            (ch >= 'A' && ch <= 'F');
    });
}

void DeriveRawContactFacts(Snapshot& snapshot) {
    if (snapshot.raw_contact_components.empty()) return;
    std::map<std::string, std::vector<const RawContactComponent*>> by_tag;
    for (const auto& contact : snapshot.raw_contact_components)
        for (const auto& tag : contact.tags)
            by_tag[tag].push_back(&contact);

    const std::uint32_t enabled_hash = Crc32("m_Enabled");
    const std::uint32_t active_hash = Crc32("m_IsActive");
    const auto active_controller = [&](const Controller& controller) {
        return snapshot.active_fx_controller_ids.empty() ||
            snapshot.active_fx_controller_ids.count(controller.path_id) != 0;
    };
    for (const auto& receiver : snapshot.raw_contact_components) {
        if (receiver.kind != "receiver" || receiver.parameter.empty()) continue;
        snapshot.contact_input_parameters.insert(receiver.parameter);
        std::set<const RawContactComponent*> matching_senders;
        for (const auto& tag : receiver.tags) {
            const auto found = by_tag.find(tag);
            if (found == by_tag.end()) continue;
            for (const auto* candidate : found->second)
                if (candidate->kind == "sender") matching_senders.insert(candidate);
        }
        for (const auto* sender : matching_senders) {
            if (!sender->hierarchy_path_hashes.empty()) {
                snapshot.contact_binding_candidates.push_back({
                    receiver.parameter, sender->path_id,
                    sender->hierarchy_path_hashes});
            }
            const bool nested = sender->parent_transform == receiver.transform ||
                receiver.parent_transform == sender->transform ||
                sender->transform == receiver.transform;
            const bool fixed_geometry = receiver.enabled &&
                receiver.game_object_active && receiver.allow_self &&
                receiver.receiver_type == 0 && receiver.position_known &&
                NearZero(receiver.position) && sender->enabled &&
                sender->game_object_active && sender->position_known &&
                sender->local_position_known && NearZero(sender->position) &&
                NearZero(sender->local_position) && nested;
            if (!fixed_geometry) continue;

            // Fast structural graphs intentionally omit animation effects.
            // A geometrically overlapping sender is therefore only a pending
            // fact, never a forced gate, until a targeted graph proves whether
            // its active/enabled state is animated.
            if (snapshot.analysis_depth == "fast") {
                snapshot.raw_contact_effects_pending = true;
                continue;
            }
            std::set<int> activation_values;
            for (const auto& controller : snapshot.controllers) {
                if (!active_controller(controller)) continue;
                for (const auto& machine : controller.machines)
                    for (const auto& state : machine.states)
                        for (const auto& write : state.animation_writes) {
                            if ((write.attribute_hash != enabled_hash &&
                                    write.attribute_hash != active_hash) ||
                                    sender->hierarchy_path_hashes.count(
                                        write.path_hash) == 0) continue;
                            activation_values.insert(write.value > 0.5 ? 1 : 0);
                        }
            }
            if (activation_values == std::set<int>{0, 1})
                snapshot.dynamic_contact_parameters.insert(receiver.parameter);
            else
                snapshot.forced_contact_parameters.insert(receiver.parameter);
        }
    }
}

bool ParseAvaCryptQuadratic(const json::Value& value,
                           AvaCryptV1Quadratic& out) {
    const auto& q = Array(value, "q");
    const auto& p = Array(value, "p");
    if (q.size() != 4 || p.size() != 4) return false;
    for (std::size_t i = 0; i < 4; ++i) {
        if (!q[i].is_array() || q[i].array().size() != 4 ||
            !p[i].is_number()) return false;
        out.p[i] = p[i].number();
        for (std::size_t j = 0; j < 4; ++j) {
            if (!q[i].array()[j].is_number()) return false;
            out.q[i][j] = q[i].array()[j].number();
        }
    }
    out.r = Number(value, "r");
    out.count = static_cast<std::size_t>(
        std::max(0, Integer(value, "count")));
    return std::isfinite(out.r) && out.r > 0.0 && out.count > 0;
}

std::string SafeProtocol(std::string value) {
    std::replace(value.begin(), value.end(), '|', '/');
    std::replace(value.begin(), value.end(), '\r', ' ');
    std::replace(value.begin(), value.end(), '\n', ' ');
    return value;
}

Snapshot ParseSnapshot(const json::Value& root) {
    if (!root.is_object() || root.find("engine") ||
        !root.find("controllers") || !root.find("controllers")->is_array() ||
        !root.find("menus") || !root.find("menus")->is_array())
        throw std::runtime_error("invalid normalized graph: controllers/menus arrays required; analysis reports are not inputs");
    Snapshot out;
    out.source_sha256 = String(root, "source_sha256");
    out.graph_schema_version = String(root, "graph_schema_version");
    if (out.graph_schema_version != "vpf-structural-graph/1" ||
            !IsHexDigest(out.source_sha256) ||
            out.source_sha256 != LowerAscii(out.source_sha256) ||
            root.find("contact_gates") || root.find("contact_inputs") ||
            root.find("dynamic_contact_parameters") || root.find("avacrypt") ||
            root.find("shell_protector") ||
            !root.find("contact_components") ||
            !root.find("contact_components")->is_array())
        throw std::runtime_error("invalid normalized structural graph schema");
    out.analysis_depth = String(root, "analysis_depth", "legacy_complete");
    out.deep_scan_machine_count = Integer(root, "deep_scan_machine_count");
    const auto* stats = Field(root, "stats");
    if (stats) {
        out.controller_ok = Integer(*stats, "controller_ok");
        out.controller_fail = Integer(*stats, "controller_fail");
        out.md5_parameters = Integer(*stats, "md5_parameters");
        out.unicode_obfuscated = Integer(*stats, "unicode_obfuscated");
    }
    const auto* ava = Field(root, "avacrypt");
    if (ava && ava->is_object()) {
        out.avacrypt_v1_materials = Integer(*ava, "v1_material_count");
        out.avacrypt_v2_materials = Integer(
            *ava, "v2_material_count", Integer(*ava, "material_count"));
        out.avacrypt_leaked = Boolean(*ava, "leaked");
        const auto& v1_parameters = Array(*ava, "v1_parameters").empty()
            ? Array(*ava, "parameters") : Array(*ava, "v1_parameters");
        for (const auto& p : v1_parameters)
            if (p.is_string()) out.avacrypt_v1_parameters.push_back(p.string());
        for (const auto& p : Array(*ava, "v2_parameters"))
            if (p.is_string()) out.avacrypt_v2_parameters.push_back(p.string());
        for (const auto& bit : Array(*ava, "v2_bit_indices")) {
            if (!bit.is_number()) continue;
            const int index = static_cast<int>(std::llround(bit.number()));
            if (index >= 0 && index <= 255)
                out.avacrypt_v2_bit_indices.insert(index);
        }
        out.avacrypt_v2_mesh_offset_signatures =
            Array(*ava, "v2_mesh_offset_signatures").size();
        for (const auto& item : Array(*ava, "v1_mesh_probes")) {
            AvaCryptV1MeshProbe probe;
            probe.name = String(item, "name", "?");
            probe.vertex_count = static_cast<std::size_t>(
                std::max(0, Integer(item, "vertex_count")));
            const auto* train = Field(item, "train");
            const auto* validation = Field(item, "validation");
            if (train && validation &&
                ParseAvaCryptQuadratic(*train, probe.train) &&
                ParseAvaCryptQuadratic(*validation, probe.validation))
                out.avacrypt_v1_mesh_probes.push_back(std::move(probe));
        }
    }
    const auto* shell = Field(root, "shell_protector");
    if (shell && shell->is_object()) {
        out.shell_protector_multiplexed = Boolean(*shell, "multiplexed");
        for (const auto& parameter : Array(*shell, "parameters"))
            if (parameter.is_string() && !parameter.string().empty())
                out.shell_protector_parameters.insert(parameter.string());
        for (const auto& marker : Array(*shell, "raw_parameter_markers"))
            if (marker.is_string() && !marker.string().empty())
                out.shell_protector_raw_markers.insert(marker.string());
        for (const auto& index : Array(*shell, "direct_key_indices")) {
            if (!index.is_number()) continue;
            const int value = static_cast<int>(std::llround(index.number()));
            if (value >= 0 && value <= 255)
                out.shell_protector_direct_key_indices.insert(value);
        }
    }
    for (const auto& jc : Array(root, "controllers")) {
        Controller controller; controller.path_id = String(jc, "path_id"); controller.name = String(jc, "name", "?");
        for (const auto& item : Array(jc, "parameter_defaults")) {
            const std::string name = String(item, "name");
            const std::string type = String(item, "type");
            const auto* value = Field(item, "default");
            if (name.empty() || !value) continue;
            double numeric = 0.0;
            if (value->is_number()) numeric = value->number();
            else if (value->is_bool()) numeric = value->boolean() ? 1.0 : 0.0;
            else continue;
            if (std::isfinite(numeric))
                controller.parameter_defaults[name] = {type, numeric};
        }
        for (const auto& jm : Array(jc, "machines")) {
            Machine machine; machine.default_state = Integer(jm, "default_state");
            machine.has_selector_semantics = !Array(jm, "selector_states").empty();
            if (const auto* weight = Field(jm, "default_weight")) {
                machine.default_weight_known = weight->is_number();
                machine.default_weight = weight->is_number() ? weight->number() : 0.0;
            }
            auto parse_transition = [&out](const json::Value& jt) {
                Transition tr; tr.destination = Integer(jt, "destination", -1);
                tr.has_exit_time = Boolean(jt, "has_exit_time");
                tr.exit_time = Number(jt, "exit_time");
                tr.duration = Number(jt, "duration");
                tr.has_fixed_duration = Boolean(jt, "has_fixed_duration");
                tr.interruption_source = Integer(jt, "interruption_source");
                tr.ordered_interruption = Boolean(jt, "ordered_interruption");
                tr.can_transition_to_self = Boolean(jt, "can_transition_to_self");
                for (const auto& jcond : Array(jt, "conditions")) {
                    // Nonfinite thresholds are losslessly tagged in JSON by
                    // the reader. Until their runtime semantics are modelled,
                    // retain the edge as UNKNOWN, never as a zero predicate.
                    const bool tagged = Field(jcond, "threshold_encoding") != nullptr;
                    const auto* threshold = Field(jcond, "threshold");
                    const bool unknown = tagged || (threshold && !threshold->is_number());
                    if (unknown) ++out.nonfinite_condition_count;
                    tr.conditions.push_back({unknown ? 0 : Integer(jcond, "mode"), String(jcond, "parameter"), Number(jcond, "threshold")});
                }
                return tr;
            };
            for (const auto& js : Array(jm, "states")) {
                State state; state.name = String(js, "name");
                for (const auto& jt : Array(js, "transitions")) state.transitions.push_back(parse_transition(jt));
                for (const auto& write : Array(js, "parameter_writes")) {
                    const std::string name = String(write, "name");
                    const double value = Number(write, "value");
                    if (!name.empty() && std::isfinite(value)) {
                        ParameterWrite parsed{name, String(write, "source"),
                            Integer(write, "type", -1), value};
                        const auto* metadata = Field(write, "operation_metadata");
                        if (metadata && metadata->is_object()) {
                            for (const auto& [key, item] : metadata->object()) {
                                if (item.is_bool()) parsed.operation_flags[key] = item.boolean();
                                else if (item.is_number() && std::isfinite(item.number()))
                                    parsed.operation_numbers[key] = item.number();
                            }
                        }
                        state.writes.push_back(std::move(parsed));
                    }
                }
                for (const auto* channel : {"animation_constant_writes", "manual_activation_writes"}) {
                auto& output_writes = std::string(channel) == "animation_constant_writes"
                    ? state.animation_writes : state.manual_activation_writes;
                for (const auto& write : Array(js, channel)) {
                    const std::string name = String(write, "attribute",
                        String(write, "name"));
                    const double value = Number(write, "value");
                    if (!name.empty() && std::isfinite(value)) {
                        AnimationWrite parsed;
                        parsed.name = name;
                        parsed.path = String(write, "path");
                        parsed.source = String(write, "source");
                        parsed.path_hash = static_cast<std::uint32_t>(
                            Integer(write, "path_hash", 0));
                        parsed.attribute_hash = static_cast<std::uint32_t>(
                            Integer(write, "attribute_hash", 0));
                        parsed.value = value;
                        output_writes.push_back(std::move(parsed));
                        const auto* binding = Field(write, "component_binding");
                        if (binding && binding->is_object()) {
                            auto& parsed = output_writes.back();
                            parsed.binding_status = String(*binding, "status");
                            parsed.target_id = String(*binding, "target_id");
                            parsed.target_path = String(*binding, "path");
                            // Resolved bindings carry the concrete component
                            // type inside component_binding.  When hierarchy
                            // reconstruction is incomplete, preserve the
                            // serialized curve's top-level type_id instead of
                            // degrading it to zero.
                            parsed.target_type = Integer(*binding, "type_id",
                                Integer(write, "type_id"));
                            const auto serialized_active = binding->find("serialized_active");
                            if (serialized_active && serialized_active->is_bool()) {
                                parsed.serialized_active_known = true;
                                parsed.serialized_active = serialized_active->boolean();
                            }
                        }
                        output_writes.back().clip_index = Integer(
                            write, "clip_index", -1);
                    }
                }
                }
                for (const auto& read : Array(js, "blend_parameter_reads")) {
                    const std::string parameter = String(read, "parameter");
                    if (parameter.empty()) continue;
                    state.blend_parameter_reads.push_back({parameter,
                        static_cast<std::uint32_t>(Integer(read,
                            "parameter_hash", 0)),
                        Integer(read, "tree_index", -1),
                        Integer(read, "node_index", -1),
                        Integer(read, "child_node_index", -1),
                        Integer(read, "clip_id", -1)});
                }
                if (const auto* motion = Field(js, "motion")) {
                    if (motion->is_object()) {
                        const auto* cycle = Field(*motion, "cycle_offset");
                        if (cycle && cycle->is_number() &&
                            std::isfinite(cycle->number())) {
                            state.motion.has_cycle_offset = true;
                            state.motion.cycle_offset = cycle->number();
                        }
                        state.motion.cycle_offset_parameter =
                            String(*motion, "cycle_offset_parameter");
                        for (const auto& id : Array(*motion, "clip_ids")) {
                            if (!id.is_number()) continue;
                            const int clip = static_cast<int>(
                                std::llround(id.number()));
                            if (clip >= 0 && clip <= 1000000)
                                state.motion.clip_ids.push_back(clip);
                        }
                        for (const auto& raw_clip :
                             Array(*motion, "streamed_curves")) {
                            if (!raw_clip.is_object()) continue;
                            StreamedClipEvidence clip;
                            clip.clip_index = Integer(raw_clip, "clip_index", -1);
                            clip.start_time = Number(raw_clip, "start_time",
                                std::numeric_limits<double>::quiet_NaN());
                            clip.stop_time = Number(raw_clip, "stop_time",
                                std::numeric_limits<double>::quiet_NaN());
                            if (clip.clip_index < 0 ||
                                !std::isfinite(clip.start_time) ||
                                !std::isfinite(clip.stop_time) ||
                                clip.stop_time <= clip.start_time)
                                continue;
                            const auto& raw_curves = Array(raw_clip, "curves");
                            if (raw_curves.empty() || raw_curves.size() > 16)
                                continue;
                            bool valid_clip = true;
                            for (const auto& raw_curve : raw_curves) {
                                if (!raw_curve.is_object()) { valid_clip = false; break; }
                                StreamCurve curve;
                                curve.curve_index = Integer(raw_curve, "curve_index", -1);
                                curve.attribute = String(raw_curve, "attribute");
                                curve.attribute_hash = static_cast<std::uint32_t>(
                                    Integer(raw_curve, "attribute_hash", 0));
                                curve.path_hash = static_cast<std::uint32_t>(
                                    Integer(raw_curve, "path_hash", 0));
                                curve.type_id = Integer(raw_curve, "type_id", 0);
                                if (curve.curve_index < 0 || curve.attribute.empty()) {
                                    valid_clip = false; break;
                                }
                                const auto& keys = Array(raw_curve, "keys");
                                if (keys.empty() || keys.size() > 4096) {
                                    valid_clip = false; break;
                                }
                                for (const auto& raw_key : keys) {
                                    if (!raw_key.is_object()) { valid_clip = false; break; }
                                    StreamKey key;
                                    key.time = Number(raw_key, "time",
                                        std::numeric_limits<double>::quiet_NaN());
                                    const auto& coeffs = Array(raw_key, "coefficients");
                                    if (!std::isfinite(key.time) || coeffs.size() != 4) {
                                        valid_clip = false; break;
                                    }
                                    for (std::size_t i = 0; i < coeffs.size(); ++i) {
                                        if (!coeffs[i].is_number() ||
                                            !std::isfinite(coeffs[i].number())) {
                                            valid_clip = false; break;
                                        }
                                        key.coefficients[i] = coeffs[i].number();
                                    }
                                    if (!valid_clip) break;
                                    curve.keys.push_back(std::move(key));
                                }
                                if (!valid_clip) break;
                                clip.curves.push_back(std::move(curve));
                            }
                            if (valid_clip) state.motion.streamed_clips.push_back(
                                std::move(clip));
                        }
                    }
                }
                machine.states.push_back(std::move(state));
            }
            for (const auto& jt : Array(jm, "any_transitions")) machine.any_transitions.push_back(parse_transition(jt));
            controller.machines.push_back(std::move(machine));
        }
        out.controllers.push_back(std::move(controller));
    }
    for (const auto& parameter : Array(root, "expression_parameters")) {
        const std::string name = String(parameter, "name");
        if (name.empty()) continue;
        out.expression_parameters.insert(name);
        if (Boolean(parameter, "saved"))
            out.saved_expression_parameters.insert(name);
        const auto* default_value = Field(parameter, "default");
        if (!default_value) continue;
        double numeric = 0.0;
        if (default_value->is_number()) numeric = default_value->number();
        else if (default_value->is_bool())
            numeric = default_value->boolean() ? 1.0 : 0.0;
        else continue;
        if (!std::isfinite(numeric)) continue;
        const int value_type = Integer(parameter, "value_type", -1);
        const std::string type = value_type == 2 ? "bool" :
            (value_type == 0 ? "int" : "float");
        out.expression_parameter_defaults[name] = {type, numeric};
    }
    for (const auto& gate : Array(root, "contact_gates")) {
        const std::string parameter = String(gate, "parameter");
        const std::string evidence = String(gate, "evidence");
        const double forced_value = Number(gate, "forced_value");
        if (!parameter.empty() && forced_value > 0.5 &&
            evidence == "enabled_zero_offset_nested_self_contact")
            out.forced_contact_parameters.insert(parameter);
    }
    for (const auto& item : Array(root, "dynamic_contact_parameters"))
        if (item.is_string() && !item.string().empty())
            out.dynamic_contact_parameters.insert(item.string());
    for (const auto& item : Array(root, "contact_inputs")) {
        if (!item.is_object()) continue;
        const std::string parameter = String(item, "parameter");
        if (!parameter.empty()) out.contact_input_parameters.insert(parameter);
        if (parameter.empty()) continue;
        for (const auto& sender : Array(item, "matched_senders")) {
            ContactBindingCandidate binding;
            binding.parameter = parameter;
            binding.sender = String(sender, "path_id");
            if (binding.sender.empty()) continue;
            for (const auto& hash : Array(sender, "hierarchy_path_hashes")) {
                if (!hash.is_number()) continue;
                const auto value = hash.number();
                if (std::isfinite(value) && value >= 0 && value <= 4294967295.0 && std::floor(value) == value)
                    binding.path_hashes.insert(static_cast<std::uint32_t>(value));
            }
            if (!binding.path_hashes.empty()) out.contact_binding_candidates.push_back(std::move(binding));
        }
    }
    for (const auto& item : Array(root, "contact_components")) {
        if (!item.is_object())
            throw std::runtime_error("invalid raw Contact component");
        RawContactComponent contact;
        contact.path_id = String(item, "path_id");
        contact.kind = String(item, "kind");
        contact.parameter = String(item, "parameter");
        contact.transform = String(item, "transform");
        contact.parent_transform = String(item, "parent_transform");
        contact.enabled = Boolean(item, "enabled");
        contact.game_object_active = Boolean(item, "game_object_active");
        contact.allow_self = Boolean(item, "allow_self");
        contact.receiver_type = Integer(item, "receiver_type", -1);
        contact.position_known = Vector3Field(item, "position", contact.position);
        contact.local_position_known = Vector3Field(
            item, "local_position", contact.local_position);
        for (const auto& tag : Array(item, "tags"))
            if (tag.is_string() && !tag.string().empty() &&
                    tag.string().size() <= 256)
                contact.tags.insert(tag.string());
        for (const auto& hash : Array(item, "hierarchy_path_hashes")) {
            if (!hash.is_number() || !std::isfinite(hash.number()) ||
                    hash.number() < 0 || hash.number() > 4294967295.0 ||
                    std::floor(hash.number()) != hash.number()) continue;
            contact.hierarchy_path_hashes.insert(
                static_cast<std::uint32_t>(hash.number()));
        }
        if (contact.path_id.empty() ||
                (contact.kind != "sender" && contact.kind != "receiver"))
            throw std::runtime_error("invalid raw Contact identity");
        if (contact.kind == "receiver" && contact.parameter.empty())
            continue;
        out.raw_contact_components.push_back(std::move(contact));
    }
    for (const auto& item : Array(root, "active_fx_controller_ids"))
        if (item.is_string() && !item.string().empty())
            out.active_fx_controller_ids.insert(item.string());
    for (const auto& item : Array(root, "active_root_menu_ids"))
        if (item.is_string() && !item.string().empty())
            out.active_root_menu_ids.insert(item.string());
    DeriveRawContactFacts(out);
    const auto* avatar = Field(root, "avatar_diagnostics");
    if (avatar && avatar->is_object()) {
        for (const auto& root : Array(*avatar, "controller_binding_roots")) {
            auto id = String(root, "controller");
            if (Boolean(*avatar, "controller_selection_complete") && !id.empty()) out.selected_controller_ids.insert(id);
        }
        out.avatar_descriptor_count = Integer(*avatar, "descriptor_count");
        out.custom_expressions_count = Integer(*avatar, "custom_expressions_count");
        out.missing_expression_parameters_count =
            Integer(*avatar, "missing_expression_parameters_count");
        out.missing_expression_menu_count =
            Integer(*avatar, "missing_expression_menu_count");
        out.custom_fx_count = Integer(*avatar, "custom_fx_count");
        out.missing_fx_controller_count =
            Integer(*avatar, "missing_fx_controller_count");
        out.animation_hash_count = Integer(*avatar, "animation_hash_count");
        out.animation_hash_unique_count =
            Integer(*avatar, "animation_hash_unique_count");
    }
    for (const auto& jm : Array(root, "menus")) {
        Menu menu; menu.id = String(jm, "id"); menu.name = String(jm, "name", "?");
        for (const auto& jc : Array(jm, "controls")) {
            MenuControl control;
            control.name = String(jc, "name"); control.parameter = String(jc, "parameter");
            control.submenu = String(jc, "submenu"); control.type = Integer(jc, "type");
            control.value = Number(jc, "value"); control.has_icon = Boolean(jc, "has_icon");
            control.icon_path_id = String(jc, "icon_path_id");
            control.icon_type = String(jc, "icon_type");
            for (const auto& item : Array(jc, "sub_parameters")) if (item.is_string()) control.sub_parameters.push_back(item.string());
            menu.controls.push_back(std::move(control));
        }
        out.menus.push_back(std::move(menu));
    }
    return out;
}

std::optional<bool> ConditionMatches(
    const Condition& condition,
    const std::map<std::string, double>& values) {
    const auto found = values.find(condition.parameter);
    if (found == values.end()) return std::nullopt;
    const double value = found->second;
    switch (condition.mode) {
    case 1: return value > 0.5;
    case 2: return value <= 0.5;
    case 3: return value > condition.threshold;
    case 4: return value < condition.threshold;
    case 6: return std::abs(value - condition.threshold) <= 1e-5;
    case 7: return std::abs(value - condition.threshold) > 1e-5;
    default: return std::nullopt;
    }
}

std::optional<double> SimulateDeterministicMachine(
    const Snapshot& snapshot, const Controller& controller,
    std::size_t machine_index,
    const std::string& output_parameter,
    const std::set<std::string>& externally_mutable,
    const std::map<std::string, std::set<std::size_t>>& writers) {
    if (machine_index >= controller.machines.size()) return std::nullopt;
    const auto& machine = controller.machines[machine_index];
    if (machine.default_state < 0 ||
        machine.default_state >= static_cast<int>(machine.states.size()))
        return std::nullopt;
    // AnyState transitions are active independently of the current state.
    // The simulator has no ordering/timing model for them, so silently
    // ignoring one would be a fail-open decision.
    if (!machine.any_transitions.empty()) return std::nullopt;

    std::set<std::string> dependencies;
    for (const auto& state : machine.states)
        for (const auto& transition : state.transitions)
            for (const auto& condition : transition.conditions)
                if (!condition.parameter.empty())
                    dependencies.insert(condition.parameter);
    for (const auto& transition : machine.any_transitions)
        for (const auto& condition : transition.conditions)
            if (!condition.parameter.empty())
                dependencies.insert(condition.parameter);

    std::map<std::string, double> values;
    for (const auto& [name, item] : controller.parameter_defaults)
        values[name] = item.value;
    for (const auto& [name, item] : snapshot.expression_parameter_defaults)
        values[name] = item.value;
    values["AvatarVersion"] = 3.0;

    for (const auto& dependency : dependencies) {
        if (dependency == "AvatarVersion" || dependency == output_parameter)
            continue;
        if (externally_mutable.count(dependency)) return std::nullopt;
        const auto writer = writers.find(dependency);
        if (writer != writers.end() &&
            (writer->second.size() != 1 || !writer->second.count(machine_index)))
            return std::nullopt;
        if (!values.count(dependency) && writer == writers.end())
            return std::nullopt;
    }

    const auto& census = BuildWriterCensus(controller);
    for (const auto& dependency : dependencies) {
        if (census.non_set_names.count(dependency) != 0 ||
            census.animation_names.count(dependency) != 0)
            return std::nullopt;
    }
    if (census.non_set_names.count(output_parameter) != 0 ||
        census.animation_names.count(output_parameter) != 0)
        return std::nullopt;

    int state_index = machine.default_state;
    std::set<std::string> seen;
    for (int step = 0; step < 128; ++step) {
        if (state_index < 0 ||
            state_index >= static_cast<int>(machine.states.size()))
            break;
        const auto& state = machine.states[static_cast<std::size_t>(state_index)];
        for (const auto& write : state.writes) {
            // VRCAvatarParameterDriver type 0 is an explicit Set operation.
            if (write.type == 0) values[write.name] = write.value;
        }

        std::ostringstream signature;
        signature << state_index;
        for (const auto& dependency : dependencies) {
            const auto value = values.find(dependency);
            if (value != values.end()) signature << '|' << dependency << '=' << value->second;
        }
        if (!seen.insert(signature.str()).second) {
            const auto output = values.find(output_parameter);
            return output == values.end() ? std::nullopt
                                          : std::optional<double>(output->second);
        }

        bool moved = false;
        for (const auto& transition : state.transitions) {
            bool enabled = true;
            for (const auto& condition : transition.conditions) {
                const auto match = ConditionMatches(condition, values);
                if (!match.has_value()) return std::nullopt;
                if (!*match) { enabled = false; break; }
            }
            if (!enabled) continue;
            if (transition.destination < 0 ||
                transition.destination >= static_cast<int>(machine.states.size())) {
                // A malformed/unknown destination is not an implicit sink.
                return std::nullopt;
            }
            state_index = transition.destination;
            moved = true;
            break;
        }
        if (!moved) {
            const auto output = values.find(output_parameter);
            return output == values.end() ? std::nullopt
                                          : std::optional<double>(output->second);
        }
    }
    return std::nullopt;
}

bool HasDynamicContactGuardDependency(
    const Snapshot& snapshot, const Controller& controller,
    std::size_t candidate_machine_index, const Machine& candidate_machine,
    const Candidate& candidate);

enum class GuardReachability {
    ProvenBlocked,
    ProvenReachable,
    Unknown,
};

GuardReachability CandidateHasDeterministicallyBlockedGuard(
    const Snapshot& snapshot, const Controller& controller,
    std::size_t candidate_machine_index,
    const Machine& candidate_machine, const Candidate& candidate) {
    // Fast raw-contact geometry has not yet been checked against animation.
    // Even an abstract high/low receiver witness cannot certify those missing
    // effects. In particular, a fixed/incorrectly bound sender may invalidate
    // the apparent pulse once the targeted graph arrives.
    if (snapshot.raw_contact_effects_pending &&
        HasDynamicContactGuardDependency(snapshot, controller,
            candidate_machine_index, candidate_machine, candidate))
        return GuardReachability::Unknown;
    // A hidden/dynamic Contact detector has already proved the producer and
    // ready state for this exact candidate.  The generic default-state guard
    // probe intentionally cannot model that user-triggered pulse, so treating
    // its unknown default as a failure would downgrade a fully proven pair.
    if (candidate.contact_producer_machine < controller.machines.size() &&
        candidate.contact_ready_state >= 0 &&
        candidate.contact_ready_state < static_cast<int>(controller.machines[
            candidate.contact_producer_machine].states.size()))
        return GuardReachability::ProvenReachable;
    if (HasDynamicContactGuardDependency(snapshot, controller,
            candidate_machine_index, candidate_machine, candidate))
        // A receiver read proves a dependency, not the high/low pulse,
        // animation binding or producer-ready witness needed to enter digits.
        // Only the exact detector witness above may certify that prerequisite.
        return GuardReachability::Unknown;
    std::map<std::string, std::array<int, 2>> guard_votes;
    for (const auto& state : candidate_machine.states) {
        for (const auto& transition : state.transitions) {
            const bool digit_edge = std::any_of(
                transition.conditions.begin(), transition.conditions.end(),
                [&](const Condition& condition) {
                    return condition.parameter == candidate.parameter &&
                        condition.mode == 6;
                });
            if (!digit_edge) continue;
            for (const auto& condition : transition.conditions) {
                if (condition.parameter.empty() ||
                    condition.parameter == candidate.parameter ||
                    (condition.mode != 1 && condition.mode != 2)) continue;
                const bool required = condition.mode == 1;
                ++guard_votes[condition.parameter][required ? 1 : 0];
            }
        }
    }
    if (guard_votes.empty()) return GuardReachability::ProvenReachable;

    const auto& census = BuildWriterCensus(controller);
    const auto& writers = census.set_owners;
    std::set<std::string> externally_mutable = snapshot.expression_parameters;
    externally_mutable.insert(snapshot.contact_input_parameters.begin(),
        snapshot.contact_input_parameters.end());
    externally_mutable.insert(snapshot.dynamic_contact_parameters.begin(),
        snapshot.dynamic_contact_parameters.end());
    for (const auto& menu : snapshot.menus)
        for (const auto& control : menu.controls) {
            if (!control.parameter.empty())
                externally_mutable.insert(control.parameter);
            externally_mutable.insert(control.sub_parameters.begin(),
                control.sub_parameters.end());
        }

    bool saw_unknown = false;
    bool saw_reachable = false;
    for (const auto& [guard, votes] : guard_votes) {
        std::optional<bool> required;
        if (votes[0] >= 3 && votes[0] >= votes[1] * 3) required = false;
        else if (votes[1] >= 3 && votes[1] >= votes[0] * 3) required = true;
        if (!required.has_value() || externally_mutable.count(guard)) {
            saw_unknown = true;
            continue;
        }
        if (census.non_set_names.count(guard) != 0 ||
            census.animation_names.count(guard) != 0 ||
            HasActiveOtherControllerWriter(snapshot, controller, guard)) {
            saw_unknown = true;
            continue;
        }
        const auto producer = writers.find(guard);
        if (producer == writers.end() || producer->second.size() != 1) {
            saw_unknown = true;
            continue;
        }
        const std::size_t producer_machine = *producer->second.begin();
        if (producer_machine >= controller.machines.size()) {
            saw_unknown = true;
            continue;
        }
        if (producer_machine == candidate_machine_index) {
            // A same-machine writer is not automatically a valid producer.
            // If every write of the required guard polarity is reachable only
            // through an edge that already requires that polarity, the graph
            // is circularly blocked.  Prove this with an over-approximating
            // reachability walk: ignore every non-guard predicate and reject a
            // transition only when its guard predicate is definitely false at
            // the runtime default.  Finding any required-polarity writer by
            // this permissive walk is enough to avoid a false blocked verdict.
            const auto* guard_default = EffectiveRuntimeDefault(
                snapshot, controller, guard);
            if (!guard_default ||
                (guard_default->type != "bool" &&
                 guard_default->type != "float" &&
                 guard_default->type != "int") ||
                candidate_machine.default_state < 0 ||
                candidate_machine.default_state >= static_cast<int>(
                    candidate_machine.states.size())) {
                saw_unknown = true;
                continue;
            }
            if ((guard_default->value > 0.5) == *required) {
                saw_reachable = true;
                continue;
            }

            const auto definitely_blocked_by_guard =
                [&](const Transition& transition) {
                    std::map<std::string, double> values;
                    values[guard] = guard_default->value;
                    for (const auto& condition : transition.conditions) {
                        if (condition.parameter != guard) continue;
                        const auto match = ConditionMatches(condition, values);
                        if (match.has_value() && !*match) return true;
                    }
                    return false;
                };
            const auto writes_required_guard = [&](const State& state) {
                return std::any_of(state.writes.begin(), state.writes.end(),
                    [&](const ParameterWrite& write) {
                        return write.type == 0 && write.name == guard &&
                            (std::abs(write.value) <= 1e-5 ||
                             std::abs(write.value - 1.0) <= 1e-5) &&
                            ((write.value > 0.5) == *required);
                    });
            };

            std::set<int> reachable{candidate_machine.default_state};
            bool unknown_path = false;
            bool reached_required_writer = false;
            bool changed = true;
            while (changed) {
                changed = false;
                for (int source : std::vector<int>(
                         reachable.begin(), reachable.end())) {
                    if (writes_required_guard(candidate_machine.states[
                            static_cast<std::size_t>(source)])) {
                        reached_required_writer = true;
                        reachable.clear();
                        break;
                    }
                    const auto visit = [&](const Transition& transition) {
                        if (transition.destination < 0 ||
                            transition.destination >= static_cast<int>(
                                candidate_machine.states.size())) {
                            unknown_path = true;
                            return;
                        }
                        for (const auto& condition : transition.conditions) {
                            if (condition.parameter == guard &&
                                (condition.mode != 1 && condition.mode != 2 &&
                                 condition.mode != 3 && condition.mode != 4 &&
                                 condition.mode != 6 && condition.mode != 7)) {
                                unknown_path = true;
                                return;
                            }
                        }
                        if (definitely_blocked_by_guard(transition))
                            return;
                        changed |= reachable.insert(
                            transition.destination).second;
                    };
                    // AnyState is intentionally not part of this over-
                    // approximation.  If present, the path is unknown rather
                    // than deterministically blocked.
                    if (!candidate_machine.any_transitions.empty()) {
                        unknown_path = true;
                        break;
                    }
                    for (const auto& transition : candidate_machine.states[
                             static_cast<std::size_t>(source)].transitions)
                        visit(transition);
                }
                if (reachable.empty() || unknown_path) break;
            }
            if (reached_required_writer) {
                saw_reachable = true;
                continue;
            }
            if (unknown_path) {
                saw_unknown = true;
                continue;
            }
            if (!reachable.empty()) return GuardReachability::ProvenBlocked;
            saw_unknown = true;
            continue;
        }
        // A producer that depends on a Contact receiver can legitimately
        // reach the required guard value after user interaction.  Its
        // default-state output must not be treated as a deterministic block.
        const auto& producer_state_machine =
            controller.machines[producer_machine];
        const auto depends_on_contact_input = [&](const std::vector<Transition>& transitions) {
            return std::any_of(transitions.begin(), transitions.end(),
                [&](const Transition& transition) {
                    return std::any_of(transition.conditions.begin(),
                        transition.conditions.end(), [&](const Condition& condition) {
                            return snapshot.contact_input_parameters.count(
                                condition.parameter) != 0;
                        });
                });
        };
        bool contact_dependency = depends_on_contact_input(
            producer_state_machine.any_transitions);
        bool fixed_dependency = false;
        for (const auto& state : producer_state_machine.states)
            contact_dependency = contact_dependency ||
                depends_on_contact_input(state.transitions);
        const auto depends_on_fixed_contact = [&](const std::vector<Transition>& transitions) {
            return std::any_of(transitions.begin(), transitions.end(),
                [&](const Transition& transition) {
                    return std::any_of(transition.conditions.begin(),
                        transition.conditions.end(), [&](const Condition& condition) {
                            return snapshot.forced_contact_parameters.count(
                                condition.parameter) != 0;
                        });
                });
        };
        fixed_dependency = depends_on_fixed_contact(
            producer_state_machine.any_transitions);
        for (const auto& state : producer_state_machine.states)
            fixed_dependency = fixed_dependency ||
                depends_on_fixed_contact(state.transitions);
        if (contact_dependency && !fixed_dependency) {
            saw_unknown = true;
            continue;
        }
        const auto actual = SimulateDeterministicMachine(snapshot, controller,
            producer_machine, guard, externally_mutable, writers);
        if (!actual.has_value()) {
            saw_unknown = true;
            continue;
        }
        if ((*actual > 0.5) != *required)
            return GuardReachability::ProvenBlocked;
        saw_reachable = true;
    }
    if (saw_unknown) return GuardReachability::Unknown;
    return saw_reachable ? GuardReachability::ProvenReachable
                         : GuardReachability::Unknown;
}

std::optional<std::pair<std::size_t, int>> DynamicContactSettlementState(
    const Snapshot& snapshot, const Controller& controller,
    std::size_t candidate_machine_index, const Machine& candidate_machine,
    const Candidate& candidate) {
    if (candidate.contact_producer_machine < controller.machines.size() &&
        candidate.contact_ready_state >= 0 &&
        candidate.contact_ready_state < static_cast<int>(controller.machines[
            candidate.contact_producer_machine].states.size()))
        return std::make_pair(candidate.contact_producer_machine,
            candidate.contact_ready_state);
    if (snapshot.dynamic_contact_parameters.empty() &&
        snapshot.contact_input_parameters.empty()) return std::nullopt;

    std::map<std::string, std::array<int, 2>> guard_votes;
    for (const auto& state : candidate_machine.states) {
        for (const auto& transition : state.transitions) {
            const bool digit_edge = std::any_of(
                transition.conditions.begin(), transition.conditions.end(),
                [&](const Condition& condition) {
                    return condition.parameter == candidate.parameter &&
                        condition.mode == 6;
                });
            if (!digit_edge) continue;
            for (const auto& condition : transition.conditions) {
                if (condition.parameter.empty() ||
                    condition.parameter == candidate.parameter ||
                    (condition.mode != 1 && condition.mode != 2)) continue;
                ++guard_votes[condition.parameter][condition.mode == 1 ? 1 : 0];
            }
        }
    }

    const auto& census = BuildWriterCensus(controller);
    const auto& writers = census.set_owners;

    std::vector<std::pair<std::size_t, int>> matches;
    for (const auto& [guard, votes] : guard_votes) {
        std::optional<bool> required;
        if (votes[0] >= 3 && votes[0] >= votes[1] * 3) required = false;
        else if (votes[1] >= 3 && votes[1] >= votes[0] * 3) required = true;
        if (!required.has_value()) continue;
        if (census.non_set_names.count(guard) != 0 ||
            census.animation_names.count(guard) != 0 ||
            HasActiveOtherControllerWriter(snapshot, controller, guard))
            continue;
        const auto producer = writers.find(guard);
        if (producer == writers.end() || producer->second.size() != 1) continue;
        const std::size_t producer_machine = *producer->second.begin();
        if (producer_machine == candidate_machine_index ||
            producer_machine >= controller.machines.size()) continue;
        const auto& machine = controller.machines[producer_machine];
        bool dynamic_dependency = false;
        bool fixed_dependency = false;
        auto scan = [&](const std::vector<Transition>& transitions) {
            for (const auto& transition : transitions)
                for (const auto& condition : transition.conditions)
                    if (snapshot.dynamic_contact_parameters.count(
                            condition.parameter) ||
                        snapshot.contact_input_parameters.count(
                            condition.parameter))
                        dynamic_dependency = true;
                    else if (snapshot.forced_contact_parameters.count(
                            condition.parameter))
                        fixed_dependency = true;
        };
        for (const auto& state : machine.states) scan(state.transitions);
        scan(machine.any_transitions);
        if (!dynamic_dependency || fixed_dependency) continue;

        std::vector<int> terminals;
        std::vector<int> blocked_terminals;
        for (std::size_t state_index = 0; state_index < machine.states.size();
             ++state_index) {
            const auto& state = machine.states[state_index];
            // Unknown/non-concrete edges are still outgoing edges.  They cannot
            // be treated as a stable sink merely because the destination was
            // not normalized.
            if (!state.transitions.empty()) continue;
            std::optional<bool> written_guard;
            bool malformed_guard_write = false;
            for (const auto& write : state.writes) {
                if (write.name != guard) continue;
                if (write.type != 0 ||
                    (std::abs(write.value) > 1e-5 &&
                     std::abs(write.value - 1.0) > 1e-5)) {
                    malformed_guard_write = true;
                    break;
                }
                const bool value = write.value > 0.5;
                if (written_guard.has_value() && *written_guard != value) {
                    malformed_guard_write = true;
                    break;
                }
                written_guard = value;
            }
            if (malformed_guard_write) {
                terminals.clear();
                blocked_terminals.clear();
                break;
            }
            if (!written_guard.has_value()) continue;
            if (*written_guard == *required)
                terminals.push_back(static_cast<int>(state_index));
            else
                blocked_terminals.push_back(static_cast<int>(state_index));
        }
        // A mere dynamic/contact dependency plus one ready sink is not a
        // settlement proof.  Require the complementary stable failure sink as
        // well; pulse/retry-cycle producers are accepted only through their
        // stricter detector, which binds explicit evidence to the candidate.
        if (terminals.size() == 1 && blocked_terminals.size() == 1 &&
            terminals.front() != machine.default_state)
            matches.push_back({producer_machine, terminals.front()});
    }
    std::sort(matches.begin(), matches.end());
    matches.erase(std::unique(matches.begin(), matches.end()), matches.end());
    return matches.size() == 1
        ? std::optional<std::pair<std::size_t, int>>(matches.front())
        : std::nullopt;
}

bool HasDynamicContactGuardDependency(
    const Snapshot& snapshot, const Controller& controller,
    std::size_t candidate_machine_index, const Machine& candidate_machine,
    const Candidate& candidate) {
    if (candidate.contact_producer_machine < controller.machines.size() &&
        candidate.contact_ready_state >= 0)
        return true;
    if (snapshot.dynamic_contact_parameters.empty() &&
        snapshot.contact_input_parameters.empty()) return false;

    std::map<std::string, std::array<int, 2>> guard_votes;
    for (const auto& state : candidate_machine.states) {
        for (const auto& transition : state.transitions) {
            const bool digit_edge = std::any_of(
                transition.conditions.begin(), transition.conditions.end(),
                [&](const Condition& condition) {
                    return condition.parameter == candidate.parameter &&
                        condition.mode == 6;
                });
            if (!digit_edge) continue;
            for (const auto& condition : transition.conditions) {
                if (condition.parameter.empty() ||
                    condition.parameter == candidate.parameter ||
                    (condition.mode != 1 && condition.mode != 2)) continue;
                ++guard_votes[condition.parameter][condition.mode == 1 ? 1 : 0];
            }
        }
    }

    const auto& census = BuildWriterCensus(controller);
    const auto& writers = census.set_owners;

    for (const auto& [guard, votes] : guard_votes) {
        const bool stable_requirement =
            (votes[0] >= 3 && votes[0] >= votes[1] * 3) ||
            (votes[1] >= 3 && votes[1] >= votes[0] * 3);
        if (!stable_requirement) continue;
        if (census.non_set_names.count(guard) != 0 ||
            census.animation_names.count(guard) != 0 ||
            HasActiveOtherControllerWriter(snapshot, controller, guard))
            continue;
        const auto producer = writers.find(guard);
        if (producer == writers.end()) continue;
        for (const std::size_t producer_machine : producer->second) {
            if (producer_machine == candidate_machine_index ||
                producer_machine >= controller.machines.size()) continue;
            const auto& machine = controller.machines[producer_machine];
            auto depends_on_dynamic_contact = [&]( 
                const std::vector<Transition>& transitions) {
                return std::any_of(
                    transitions.begin(), transitions.end(),
                    [&](const Transition& transition) {
                        return std::any_of(
                            transition.conditions.begin(),
                            transition.conditions.end(),
                            [&](const Condition& condition) {
                                return snapshot.dynamic_contact_parameters.count(
                                    condition.parameter) != 0 ||
                                    snapshot.contact_input_parameters.count(
                                        condition.parameter) != 0;
                            });
                    });
            };
            auto depends_on_fixed_contact = [&](const std::vector<Transition>& transitions) {
                return std::any_of(transitions.begin(), transitions.end(),
                    [&](const Transition& transition) {
                        return std::any_of(transition.conditions.begin(),
                            transition.conditions.end(), [&](const Condition& condition) {
                                return snapshot.forced_contact_parameters.count(
                                    condition.parameter) != 0;
                            });
                    });
            };
            bool fixed_dependency = depends_on_fixed_contact(machine.any_transitions);
            for (const auto& state : machine.states)
                fixed_dependency = fixed_dependency ||
                    depends_on_fixed_contact(state.transitions);
            if (!fixed_dependency && (depends_on_dynamic_contact(machine.any_transitions) ||
                std::any_of(machine.states.begin(), machine.states.end(),
                    [&](const State& state) {
                        return depends_on_dynamic_contact(state.transitions);
                    }))) return true;
        }
    }
    return false;
}

// Contact receiver parameters are externally mutable, but the normalized
// graph may not include sender animation polarities or a physical trigger
// path.  Keep the password as a reference candidate while downgrading
// confidence; otherwise a static chain would be presented as a confirmed
// password merely because a contact input exists somewhere in the avatar.
bool HasUnprovenContactInputDependency(
    const Snapshot& snapshot, const Controller& controller,
    std::size_t candidate_machine_index, const Machine& candidate_machine,
    const Candidate& candidate) {
    if (candidate.contact_producer_machine < controller.machines.size() &&
        candidate.contact_ready_state >= 0 &&
        !snapshot.raw_contact_effects_pending)
        return false;
    if (snapshot.contact_input_parameters.empty()) return false;
    std::map<std::string, std::set<std::size_t>> writers;
    for (std::size_t machine_index = 0;
         machine_index < controller.machines.size(); ++machine_index)
        for (const auto& state : controller.machines[machine_index].states)
            for (const auto& write : state.writes)
                if (write.type == 0) writers[write.name].insert(machine_index);
    std::set<std::string> guards;
    for (const auto& state : candidate_machine.states)
        for (const auto& transition : state.transitions) {
            const bool digit_edge = std::any_of(
                transition.conditions.begin(), transition.conditions.end(),
                [&](const Condition& condition) {
                    return condition.parameter == candidate.parameter &&
                        condition.mode == 6;
                });
            if (!digit_edge) continue;
            for (const auto& condition : transition.conditions)
                if ((condition.mode == 1 || condition.mode == 2) &&
                    !condition.parameter.empty() &&
                    condition.parameter != candidate.parameter)
                    guards.insert(condition.parameter);
        }
    for (const auto& guard : guards) {
        const auto producer = writers.find(guard);
        if (producer == writers.end() || producer->second.size() != 1) continue;
        const auto producer_index = *producer->second.begin();
        if (producer_index == candidate_machine_index ||
            producer_index >= controller.machines.size()) continue;
        const auto& producer_machine = controller.machines[producer_index];
        bool contact_input = false;
        auto scan = [&](const std::vector<Transition>& transitions) {
            for (const auto& transition : transitions)
                for (const auto& condition : transition.conditions) {
                    if (snapshot.contact_input_parameters.count(
                            condition.parameter))
                        contact_input = true;
                    if (snapshot.dynamic_contact_parameters.count(
                            condition.parameter))
                        contact_input = true;
                }
        };
        scan(producer_machine.any_transitions);
        for (const auto& state : producer_machine.states) scan(state.transitions);
        // Seeing both activation polarities somewhere in the controller is
        // not a reachable, correctly ordered pulse for this candidate.
        if (contact_input) return true;
    }
    return false;
}

std::optional<std::string> FixedContactBlockedGuard(
    const Snapshot& snapshot, const Controller& controller,
    std::size_t candidate_machine_index, const Machine& candidate_machine,
    const Candidate& candidate) {
    if (snapshot.forced_contact_parameters.empty()) return std::nullopt;

    std::map<std::string, std::array<int, 2>> guard_votes;
    for (const auto& state : candidate_machine.states) {
        for (const auto& transition : state.transitions) {
            const bool digit_edge = std::any_of(
                transition.conditions.begin(), transition.conditions.end(),
                [&](const Condition& condition) {
                    return condition.parameter == candidate.parameter &&
                        condition.mode == 6;
                });
            if (!digit_edge) continue;
            for (const auto& condition : transition.conditions) {
                if (condition.parameter.empty() ||
                    condition.parameter == candidate.parameter ||
                    (condition.mode != 1 && condition.mode != 2)) continue;
                ++guard_votes[condition.parameter][condition.mode == 1 ? 1 : 0];
            }
        }
    }

    const auto& census = BuildWriterCensus(controller);
    const auto& writers = census.set_owners;
    std::set<std::string> externally_mutable = snapshot.expression_parameters;
    externally_mutable.insert(snapshot.dynamic_contact_parameters.begin(),
        snapshot.dynamic_contact_parameters.end());
    for (const auto& menu : snapshot.menus)
        for (const auto& control : menu.controls) {
            if (!control.parameter.empty())
                externally_mutable.insert(control.parameter);
            externally_mutable.insert(control.sub_parameters.begin(),
                control.sub_parameters.end());
        }

    for (const auto& [guard, votes] : guard_votes) {
        std::optional<bool> required;
        if (votes[0] >= 3 && votes[0] >= votes[1] * 3) required = false;
        else if (votes[1] >= 3 && votes[1] >= votes[0] * 3) required = true;
        if (!required.has_value()) continue;
        if (census.non_set_names.count(guard) != 0 ||
            census.animation_names.count(guard) != 0 ||
            HasActiveOtherControllerWriter(snapshot, controller, guard))
            continue;
        const auto producer = writers.find(guard);
        if (producer == writers.end() || producer->second.size() != 1) continue;
        const std::size_t producer_machine = *producer->second.begin();
        if (producer_machine == candidate_machine_index ||
            producer_machine >= controller.machines.size()) continue;

        bool depends_on_fixed_contact = false;
        const auto& machine = controller.machines[producer_machine];
        auto scan_dependencies = [&](const std::vector<Transition>& transitions) {
            for (const auto& transition : transitions)
                for (const auto& condition : transition.conditions)
                    if (snapshot.forced_contact_parameters.count(
                            condition.parameter))
                        depends_on_fixed_contact = true;
        };
        for (const auto& state : machine.states)
            scan_dependencies(state.transitions);
        scan_dependencies(machine.any_transitions);
        if (!depends_on_fixed_contact) continue;

        const auto actual = SimulateDeterministicMachine(snapshot, controller,
            producer_machine, guard, externally_mutable, writers);
        if (actual.has_value() && ((*actual > 0.5) != *required))
            return guard;
    }
    return std::nullopt;
}

std::optional<int> SemanticUnlockedTerminal(
    const Controller& controller, const Machine& candidate_machine) {
    std::map<std::string, std::array<int, 2>> written_polarities;
    for (const auto& state : candidate_machine.states) {
        for (const auto& write : state.writes) {
            if (write.type != 0 ||
                (std::abs(write.value) > 1e-5 &&
                 std::abs(write.value - 1.0) > 1e-5)) continue;
            ++written_polarities[write.name][write.value > 0.5 ? 1 : 0];
        }
    }

    std::vector<int> terminals;
    for (std::size_t state_index = 0;
         state_index < candidate_machine.states.size(); ++state_index) {
        const auto& state = candidate_machine.states[state_index];
        const bool concrete_outgoing = std::any_of(
            state.transitions.begin(), state.transitions.end(),
            [&](const Transition& transition) {
                return transition.destination >= 0 &&
                    transition.destination <
                        static_cast<int>(candidate_machine.states.size());
            });
        if (concrete_outgoing) continue;
        for (const auto& write : state.writes) {
            if (write.type != 0) continue;
            const auto default_it = controller.parameter_defaults.find(write.name);
            const auto polarities = written_polarities.find(write.name);
            if (default_it == controller.parameter_defaults.end() ||
                default_it->second.type != "bool" ||
                default_it->second.value <= 0.5 || write.value > 0.5 ||
                polarities == written_polarities.end() ||
                polarities->second[0] == 0 || polarities->second[1] == 0)
                continue;

            int unlocked_consumers = 0;
            for (const auto& machine : controller.machines) {
                auto count_conditions = [&](const std::vector<Transition>& transitions) {
                    for (const auto& transition : transitions)
                        for (const auto& condition : transition.conditions)
                            if (condition.parameter == write.name &&
                                condition.mode == 2)
                                ++unlocked_consumers;
                };
                for (const auto& candidate_state : machine.states)
                    count_conditions(candidate_state.transitions);
                count_conditions(machine.any_transitions);
            }
            if (unlocked_consumers >= 3) {
                terminals.push_back(static_cast<int>(state_index));
                break;
            }
        }
    }
    std::sort(terminals.begin(), terminals.end());
    terminals.erase(std::unique(terminals.begin(), terminals.end()),
        terminals.end());
    return terminals.size() == 1
        ? std::optional<int>(terminals.front()) : std::nullopt;
}

bool ContainsI(const std::string& value, const std::string& needle) {
    return LowerAscii(value).find(LowerAscii(needle)) != std::string::npos;
}
bool LooksLock(const std::string& value) {
    static const std::vector<std::string> words = {u8"密码", u8"解锁", u8"锁", "password", "passcode", "pincode", "pin", "code", "unlock", "locked", "keypad", "anipin", "wait_digit"};
    return std::any_of(words.begin(), words.end(), [&](const auto& word){ return ContainsI(value, word); });
}
bool LooksFeature(const std::string& value) {
    static const std::vector<std::string> words = {"keitai","phone","halo","wing","hair","skirt","light","glow","particle","outfit","costume","dress","camera","mirror","dance"};
    const bool readable = std::count_if(value.begin(), value.end(), [](unsigned char c){ return c < 128; }) >= static_cast<int>(std::max<std::size_t>(3, value.size() * 3 / 5));
    return readable && std::any_of(words.begin(), words.end(), [&](const auto& word){ return ContainsI(value, word); });
}
bool SkipParameter(const std::string& value) {
    static const std::vector<std::string> words = {"contact","intensity","proximity","stretch","squish","physbone","jiggle","bounce","blink","breath","velocity","smooth","weight","blend","distance","radius","grab","stocking","cloth","emote","viseme","gesture","toggle","puppet"};
    return std::any_of(words.begin(), words.end(), [&](const auto& word){ return ContainsI(value, word); });
}

using Edge = std::tuple<int, int, int>;
std::vector<std::vector<int>> ReconstructChains(const std::vector<Edge>& edges) {
    std::map<int, std::vector<std::pair<int,int>>> next;
    std::set<int> sources, destinations;
    for (const auto& [s,d,t] : edges) { next[s].push_back({d,t}); sources.insert(s); destinations.insert(t); }
    std::vector<int> heads; for (int s : sources) if (!destinations.count(s)) heads.push_back(s);
    if (heads.empty()) heads.assign(sources.begin(), sources.end());
    std::map<int,std::vector<int>> memo; std::set<int> visiting;
    std::function<std::vector<int>(int,int)> longest = [&](int current, int depth) -> std::vector<int> {
        if (depth >= 64 || visiting.count(current)) return {};
        if (const auto it = memo.find(current); it != memo.end()) return it->second;
        visiting.insert(current); std::vector<int> best;
        for (const auto& [digit,destination] : next[current]) {
            auto child = longest(destination, depth + 1); child.insert(child.begin(), digit);
            if (child.size() > best.size()) best = std::move(child);
        }
        visiting.erase(current); return memo[current] = best;
    };
    std::vector<std::vector<int>> result;
    for (int head : heads) { auto chain = longest(head, 0); if (chain.size() >= 2) result.push_back(std::move(chain)); }
    return result;
}

std::pair<std::string,std::string> ExtractPassword(const std::vector<int>& sequence) {
    if (sequence.size() < 2) return {};
    bool even_zero = true, odd_zero = true;
    for (std::size_t i=0;i<sequence.size();++i) (i%2 ? odd_zero : even_zero) &= sequence[i] == 0;
    std::ostringstream value;
    if (even_zero && !odd_zero) { for (std::size_t i=1;i<sequence.size();i+=2) value << sequence[i]; return {value.str(),u8"回零确认步在偶数位"}; }
    if (odd_zero && !even_zero) { for (std::size_t i=0;i<sequence.size();i+=2) value << sequence[i]; return {value.str(),u8"回零确认步在奇数位"}; }
    for (int v : sequence) value << v;
    return {value.str(),u8"无回零模式(原始链)"};
}

std::optional<std::string> DetectAniPin(const Machine& m) {
    bool has_pin=false; int unlock=-1;
    for (std::size_t i=0;i<m.states.size();++i) {
        const auto low=LowerAscii(m.states[i].name); if (low.find("pin")!=std::string::npos) has_pin=true;
        if (low=="unlocked" || (low.find("unlock")!=std::string::npos && low.find("await")==std::string::npos)) unlock=static_cast<int>(i);
    }
    if (!has_pin || unlock<0 || m.default_state<0 || m.default_state>=static_cast<int>(m.states.size())) return std::nullopt;
    int current=m.default_state; std::set<int> seen; std::ostringstream password; int count=0;
    for (int step=0;step<40 && !seen.count(current);++step) {
        seen.insert(current); if (current==unlock) break; std::optional<std::pair<int,int>> next;
        for (const auto& tr : m.states[current].transitions) {
            if (tr.destination<0 || tr.destination>=static_cast<int>(m.states.size())) continue;
            const auto dn=LowerAscii(m.states[tr.destination].name); if (dn.find("await")!=std::string::npos || dn.find("reset")!=std::string::npos) continue;
            for (const auto& c : tr.conditions) if (c.mode==6) {
                const int value=static_cast<int>(std::llround(c.threshold)); if (value==12) continue;
                if (seen.count(tr.destination) && tr.destination!=unlock) continue;
                next={{tr.destination,value}}; if (value!=0) break;
            }
            if (next && next->second!=0) break;
        }
        if (!next) break;
        if (next->second!=0) {password<<next->second; ++count;}
        current=next->first;
    }
    return count>=2 ? std::optional<std::string>(password.str()) : std::nullopt;
}

std::optional<std::string> DetectWaitDigit(const Machine& m) {
    bool unlocked=false, characteristic=false; int start=-1;
    for (std::size_t i=0;i<m.states.size();++i) {
        const auto& n=m.states[i].name; if (n=="Unlocked") unlocked=true;
        if (n.find("Wait_Digit")!=std::string::npos || n.find("Locked_Idle")!=std::string::npos || n.find("Locked_Standby")!=std::string::npos) characteristic=true;
        if (n=="Locked_Idle") start=static_cast<int>(i); else if (start<0 && n.rfind("Locked",0)==0) start=static_cast<int>(i);
    }
    if (!unlocked || !characteristic || start<0) return std::nullopt;
    int current=start; std::set<int> seen; std::ostringstream password; int count=0;
    for (int step=0;step<40 && !seen.count(current);++step) {
        seen.insert(current); if (m.states[current].name=="Unlocked") break;
        std::optional<std::pair<int,int>> digit, release;
        for (const auto& tr : m.states[current].transitions) {
            if (tr.destination<0 || tr.destination>=static_cast<int>(m.states.size())) continue;
            const auto& dn=m.states[tr.destination].name;
            if (dn.find("Fail")!=std::string::npos || dn.find("Reset")!=std::string::npos || dn=="Locked_Idle") continue;
            std::vector<int> eq; for (const auto& c:tr.conditions) if(c.mode==6) eq.push_back(static_cast<int>(std::llround(c.threshold)));
            const auto nz=std::count_if(eq.begin(),eq.end(),[](int v){return v!=0;});
            if (nz==1 && (dn.find("Wait")!=std::string::npos || dn.find("Release")!=std::string::npos || dn.find("Unlock")!=std::string::npos)) {
                const int v=*std::find_if(eq.begin(),eq.end(),[](int x){return x!=0;}); digit={{tr.destination,v}};
            } else if (!eq.empty() && nz==0 && !release) release={{tr.destination,0}};
        }
        const auto next=digit?digit:release; if(!next) break;
        const int v=next->second; if(v!=0 && v!=11 && v!=12){password<<(v==10?0:v);++count;} current=next->first;
    }
    return count>=3 ? std::optional<std::string>(password.str()) : std::nullopt;
}

std::optional<std::pair<std::string,std::string>> DetectScrambledDial(const Machine& m) {
    using Dest=std::pair<int,int>; std::map<std::string,std::map<int,std::vector<Dest>>> per; std::set<int> has_output;
    for(std::size_t si=0;si<m.states.size();++si){if(!m.states[si].transitions.empty()) has_output.insert(static_cast<int>(si)); for(const auto& tr:m.states[si].transitions){
        std::vector<Condition> eq; for(const auto& c:tr.conditions) if(c.mode==6) eq.push_back(c);
        if(eq.size()==1 && tr.destination>=0 && tr.destination<static_cast<int>(m.states.size())) per[eq[0].parameter][static_cast<int>(si)].push_back({static_cast<int>(std::llround(eq[0].threshold)),tr.destination});
    }}
    for(const auto& [parameter,edges]:per){std::vector<int> pads; for(const auto& [s,list]:edges){std::set<int> values;for(auto [v,d]:list)values.insert(v);if(values.size()>=4)pads.push_back(s);} if(pads.empty())continue;
        const auto& first=edges.at(pads.front()); const double dead=first.empty()?0.0:static_cast<double>(std::count_if(first.begin(),first.end(),[&](Dest d){return !has_output.count(d.second);}))/static_cast<double>(first.size());
        if(!LooksLock(parameter)&&dead<0.5)continue;
        int current=m.default_state;std::set<int>seen;std::ostringstream password;int count=0;
        for(int step=0;step<24&&!seen.count(current);++step){seen.insert(current);std::optional<Dest>next;const auto it=edges.find(current);if(it!=edges.end())for(auto d:it->second)if(has_output.count(d.second)&&!seen.count(d.second)&&d.second!=m.default_state){next=d;break;}if(!next)break;password<<next->first;++count;current=next->second;}
        if(count>=3)return std::make_pair(password.str(),parameter);
    } return std::nullopt;
}

std::optional<std::string> DetectCheckGrab(const Machine& m) {
    std::map<int,std::vector<std::pair<int,int>>> edges; std::map<int,int> indegree;
    for(std::size_t si=0;si<m.states.size();++si)for(const auto& tr:m.states[si].transitions){if(tr.destination<0||tr.destination==static_cast<int>(si))continue;for(const auto& c:tr.conditions)if(c.mode==6&&(ContainsI(c.parameter,"CheckGrabType")||ContainsI(c.parameter,"GrabType"))){const int v=static_cast<int>(std::llround(c.threshold));if(v>0){edges[static_cast<int>(si)].push_back({v,tr.destination});++indegree[tr.destination];}}}
    if(edges.empty())return std::nullopt;
    std::map<int,std::vector<int>>memo;std::set<int>visiting;std::function<std::vector<int>(int)>longest=[&](int s){if(auto it=memo.find(s);it!=memo.end())return it->second;if(visiting.count(s))return std::vector<int>{};visiting.insert(s);std::vector<int>best;for(auto [v,d]:edges[s]){auto child=longest(d);child.insert(child.begin(),v);if(child.size()>best.size())best=std::move(child);}visiting.erase(s);return memo[s]=best;};
    std::vector<int>best;for(const auto& [s,_]:edges)if(!indegree[s]){auto p=longest(s);if(p.size()>best.size())best=std::move(p);}if(best.size()<3){for(const auto& [s,list]:edges)if(!list.empty()&&(best.empty()||best.back()!=list.front().first))best.push_back(list.front().first);}if(best.size()<3)return std::nullopt;std::ostringstream value;for(int v:best)value<<v;return value.str();
}

std::optional<std::string> DetectRecordKeypad(const Snapshot& snapshot,
    const MenuMaps& menu_maps) {
    // A state with many equality conditions is not automatically a keypad.
    // VRCFury action multiplexers and dance selectors commonly serialize one
    // edge per action value to the same destination.  Require the parameter to
    // be backed by a recovered numeric/anonymous keypad page and require at
    // least eight of the dispatched values to be actual keys on that page.
    // This keeps the detector independent of readable parameter/state names
    // while rejecting ordinary integer feature buses such as SyncDances.
    for (const auto& controller : snapshot.controllers) {
        if (!snapshot.active_fx_controller_ids.empty() &&
            snapshot.active_fx_controller_ids.count(controller.path_id) == 0)
            continue;
        for (const auto& machine : controller.machines) {
            for (std::size_t source = 0; source < machine.states.size(); ++source) {
                std::map<std::pair<std::string, int>, std::set<int>> grouped;
                for (const auto& transition : machine.states[source].transitions) {
                    if (transition.destination < 0 ||
                        transition.destination >= static_cast<int>(machine.states.size()) ||
                        transition.destination == static_cast<int>(source))
                        continue;
                    for (const auto& condition : transition.conditions) {
                        if (condition.mode != 6 || condition.parameter.empty()) continue;
                        const int value = static_cast<int>(
                            std::llround(condition.threshold));
                        if (value >= 0 && value <= 19)
                            grouped[{condition.parameter,
                                transition.destination}].insert(value);
                    }
                }
                for (const auto& [key, values] : grouped) {
                    if (values.size() < 8) continue;
                    const auto mapped = menu_maps.find(key.first);
                    if (mapped == menu_maps.end()) continue;
                    std::set<int> keypad_raw_values;
                    for (const auto& [menu_name, mapping] : mapped->second) {
                        (void)menu_name;
                        for (const auto& [visible, entry] : mapping) {
                            (void)visible;
                            keypad_raw_values.insert(entry.raw_value);
                        }
                    }
                    std::size_t mapped_dispatch_values = 0;
                    for (int value : values)
                        mapped_dispatch_values += keypad_raw_values.count(value);
                    if (mapped_dispatch_values >= 8) return key.first;
                }
            }
        }
    }
    return std::nullopt;
}

void AnalyzeMachine(const std::string& controller, const Machine& m, std::vector<Candidate>& out) {
    if (auto p = DetectAniPin(m))
        out.push_back({controller, u8"AniPIN键盘锁", *p, *p,
            u8"AniPIN路径值拼接", u8"高"});
    if (auto p = DetectScrambledDial(m))
        out.push_back({controller, p->second, p->first, p->first,
            u8"打乱式拨码盘·前进路径", u8"高"});
    if (auto p = DetectWaitDigit(m))
        out.push_back({controller, u8"Wait_Digit序列锁", *p, *p,
            u8"Wait_Digit序列锁", u8"高"});
    if (auto p = DetectCheckGrab(m))
        out.push_back({controller, u8"CheckGrab抓取序列锁", *p, *p,
            u8"CheckGrab抓取类型链", u8"高"});

    static const std::set<std::string> standard = {
        "GestureLeft", "GestureRight", "GestureLeftWeight",
        "GestureRightWeight", "VRCEmote", "Viseme", "VRMode",
        "AvatarVersion", "SetExpression", "Voice", "TrackingType", "AFK",
        "Seated", "InStation", "IsLocal", "Grounded", "Upright",
        "VelocityX", "VelocityY", "VelocityZ"
    };
    std::map<std::string, std::vector<Edge>> by_parameter;
    std::set<std::string> guarded_parameters;
    std::map<std::string, std::set<std::string>> guards_by_parameter;
    for (std::size_t source = 0; source < m.states.size(); ++source) {
        for (const auto& transition : m.states[source].transitions) {
            if (transition.destination < 0 ||
                transition.destination >= static_cast<int>(m.states.size()))
                continue;
            for (const auto& condition : transition.conditions) {
                if (condition.mode != 6) continue;
                const int digit = static_cast<int>(std::llround(condition.threshold));
                std::string base = condition.parameter;
                const auto slash = base.find_last_of('/');
                if (slash != std::string::npos) base = base.substr(slash + 1);
                const auto dollar = base.find('$');
                if (dollar != std::string::npos) base = base.substr(0, dollar);
                if (standard.count(base) != 0 || digit < 0 || digit > 19) continue;
                by_parameter[condition.parameter].push_back({
                    static_cast<int>(source), digit == 10 ? 0 : digit,
                    transition.destination
                });
                if (transition.conditions.size() == 1) continue;
                guarded_parameters.insert(condition.parameter);
                for (const auto& guard : transition.conditions) {
                    if (guard.parameter != condition.parameter &&
                        !guard.parameter.empty())
                        guards_by_parameter[condition.parameter].insert(
                            guard.parameter);
                }
            }
        }
    }
    for (const auto& [parameter, edges] : by_parameter) {
        if (SkipParameter(parameter) || LooksFeature(parameter)) continue;
        bool digits = true;
        int self = 0;
        std::set<int> sources;
        for (const auto& [source, digit, destination] : edges) {
            digits &= digit >= 0 && digit <= 9;
            self += source == destination;
            sources.insert(source);
        }
        if (!digits || self >= std::max(1, static_cast<int>(edges.size() / 2)))
            continue;
        const bool dead = std::any_of(edges.begin(), edges.end(),
            [&](const Edge& edge) {
                return !sources.count(std::get<2>(edge));
            });
        for (const auto& sequence : ReconstructChains(edges)) {
            if (sequence.size() < 3) continue;
            auto [password, note] = ExtractPassword(sequence);
            if (password.size() < 2) continue;
            const bool confirm = note.find(u8"回零确认") != std::string::npos;
            if (!LooksLock(parameter) && !dead && !confirm) continue;
            std::ostringstream raw;
            for (int value : sequence) raw << value;
            // Alternating press/release values and a dead end prove only that a
            // numeric input chain exists.  Without a verified success terminal,
            // a generic longest-chain candidate can never be high confidence.
            if (guarded_parameters.count(parameter)) {
                note += u8" | 含额外运行条件，仅是必要按键子序列";
                const auto guards = guards_by_parameter.find(parameter);
                if (guards != guards_by_parameter.end() &&
                    !guards->second.empty()) {
                    note += u8" (外部门: ";
                    bool first = true;
                    for (const auto& guard : guards->second) {
                        if (!first) note += ", ";
                        note += guard;
                        first = false;
                    }
                    note += ")";
                }
            }
            out.push_back({controller, parameter, raw.str(), password, note,
                u8"参考", -1, {}, true});
        }
    }
}

bool IsRadialControl(const MenuControl& control) {
    // Unity serializes VRCExpressionsMenu RadialPuppet as 203.  Type 4 is
    // accepted only for older normalized/YAML adapters.  A stale single
    // subParameter on a Button must never turn that Button into a radial.
    return (control.type == 203 || control.type == 4) &&
        control.sub_parameters.size() == 1 &&
        !control.sub_parameters.front().empty();
}

int AvaCryptV1KeyIndex(const std::string& parameter) {
    const std::string lower = LowerAscii(Trim(parameter));
    static const std::string prefix = "avacryptkey";
    if (lower.size() != prefix.size() + 1 ||
        lower.compare(0, prefix.size(), prefix) != 0) return -1;
    const char suffix = lower.back();
    return suffix >= '0' && suffix <= '3' ? suffix - '0' : -1;
}

struct AvaCryptV1MenuEvidence {
    std::string menu;
    std::array<std::string,4> parameters;
};

std::optional<AvaCryptV1MenuEvidence> DetectAvaCryptV1Menu(
    const Snapshot& snapshot) {
    for (const auto& menu : snapshot.menus) {
        AvaCryptV1MenuEvidence evidence;
        evidence.menu = menu.name;
        std::array<bool,4> found{};
        for (const auto& control : menu.controls) {
            if (!IsRadialControl(control)) continue;
            const auto& parameter = control.sub_parameters.front();
            const int index = AvaCryptV1KeyIndex(parameter);
            if (index < 0) continue;
            found[static_cast<std::size_t>(index)] = true;
            evidence.parameters[static_cast<std::size_t>(index)] = parameter;
        }
        if (std::all_of(found.begin(), found.end(), [](bool value) { return value; }))
            return evidence;
    }
    return std::nullopt;
}

std::vector<RadialGroup> CollectRadialGroups(const Snapshot& snapshot) {
    std::vector<RadialGroup> result;
    for (const auto& menu : snapshot.menus) {
        RadialGroup group;
        group.menu = menu.name;
        std::set<std::string> seen;
        for (const auto& control : menu.controls) {
            if (!IsRadialControl(control)) continue;
            const auto& parameter = control.sub_parameters.front();
            if (seen.insert(parameter).second)
                group.controls.push_back({control.name, parameter});
        }
        if (!group.controls.empty()) result.push_back(std::move(group));
    }
    return result;
}

bool IsUnlockStateName(const std::string& value) {
    std::string compact;
    for (unsigned char ch : LowerAscii(Trim(value)))
        if (std::isalnum(ch)) compact.push_back(static_cast<char>(ch));
    return compact == "unlocked" || compact == "unlock" ||
        compact == "authorized" || compact == "success" || compact == "open" ||
        compact.find("unlocked") != std::string::npos ||
        compact.find("authorized") != std::string::npos ||
        compact.find("unlocksuccess") != std::string::npos;
}

void DetectRadialDial(const std::string& controller, const Machine& machine,
    const std::vector<RadialGroup>& radial_groups,
    std::vector<Candidate>& out) {
    if (radial_groups.empty()) return;

    std::set<int> reachable;
    if (machine.default_state >= 0 &&
        machine.default_state < static_cast<int>(machine.states.size())) {
        std::deque<int> queue{machine.default_state};
        reachable.insert(machine.default_state);
        while (!queue.empty()) {
            const int source = queue.front();
            queue.pop_front();
            for (const auto& transition :
                 machine.states[static_cast<std::size_t>(source)].transitions) {
                if (transition.destination >= 0 &&
                    transition.destination < static_cast<int>(machine.states.size()) &&
                    reachable.insert(transition.destination).second)
                    queue.push_back(transition.destination);
            }
        }
    }

    auto inspect_transition = [&](int source, const Transition& transition) {
        if (transition.destination < 0 ||
            transition.destination >= static_cast<int>(machine.states.size())) return;
        if (source >= 0 && !reachable.count(source)) return;
        for (const auto& group : radial_groups) {
            std::map<std::string,std::vector<double>> lower, upper;
            for (const auto& condition : transition.conditions) {
                if (condition.mode != 3 && condition.mode != 4) continue;
                if (condition.threshold < 0.0 || condition.threshold > 1.0) continue;
                (condition.mode == 3 ? lower : upper)[condition.parameter]
                    .push_back(condition.threshold);
            }

            struct Window { std::string name, parameter; double low, high, center; };
            std::vector<Window> windows;
            for (const auto& control : group.controls) {
                const auto low_it = lower.find(control.parameter);
                const auto high_it = upper.find(control.parameter);
                if (low_it == lower.end() || high_it == upper.end()) continue;
                const double low = *std::max_element(
                    low_it->second.begin(), low_it->second.end());
                const double high = *std::min_element(
                    high_it->second.begin(), high_it->second.end());
                if (low < high && high - low <= 0.25)
                    windows.push_back({control.name, control.parameter,
                        low, high, (low + high) / 2.0});
            }
            if (windows.size() < 2) continue;

            const std::string destination_name =
                machine.states[static_cast<std::size_t>(transition.destination)].name;
            // A percentage-window result is actionable only when the very
            // transition carrying every interval goes to the unlock state.
            // Merely finding some unrelated Open/Success state elsewhere in
            // the machine is not enough to authorize a bypass.
            if (!IsUnlockStateName(destination_name)) continue;

            bool digit_mode = true;
            for (const auto& window : windows) {
                const double scaled = window.center * 10.0;
                if (std::abs(scaled - std::round(scaled)) > 0.025) {
                    digit_mode = false;
                    break;
                }
            }

            std::ostringstream password, raw, detail;
            for (std::size_t index = 0; index < windows.size(); ++index) {
                const auto& window = windows[index];
                if (index) {
                    raw << '/';
                    detail << " / ";
                    if (!digit_mode) password << " / ";
                }
                raw.setf(std::ios::fixed); raw.precision(2); raw << window.center;
                const int value = digit_mode
                    ? static_cast<int>(std::llround(window.center * 10.0))
                    : static_cast<int>(std::llround(window.center * 100.0));
                if (digit_mode) password << value;
                else password << value << '%';
                detail << (window.name.empty() ? window.parameter : window.name)
                    << ':' << value << (digit_mode ? "" : "%");
            }
            out.push_back({controller,
                digit_mode ? u8"轮盘旋钮区间锁" : u8"轮盘百分比组合锁",
                raw.str(), password.str(),
                std::string(u8"同一解锁转换的区间窗口中心 / ") + detail.str(),
                u8"高", transition.destination,
                "native_radial_window_terminal"});
        }
    };

    for (std::size_t source = 0; source < machine.states.size(); ++source)
        for (const auto& transition : machine.states[source].transitions)
            inspect_transition(static_cast<int>(source), transition);
    for (const auto& transition : machine.any_transitions)
        inspect_transition(-1, transition);
}

int NamedUnlockState(const Machine& machine) {
    for (std::size_t index = 0; index < machine.states.size(); ++index) {
        if (IsUnlockStateName(machine.states[index].name))
            return static_cast<int>(index);
    }
    return -1;
}

std::optional<int> VisibleSingleDigit(const std::string& value) {
    // VRChat menu authors commonly decorate keypad labels as "[1]", "(1)"
    // or rich-text-wrapped variants.  Accept one and only one ASCII digit,
    // while rejecting names that contain another ASCII letter/digit.  This
    // keeps ordinary feature labels such as "Outfit 1" out of keypad maps.
    std::optional<int> digit;
    bool in_tag = false;
    for (unsigned char ch : value) {
        if (ch == '<') { in_tag = true; continue; }
        if (ch == '>' && in_tag) { in_tag = false; continue; }
        if (ch == '[' || ch == '(' || ch == '{' ||
            ch == ']' || ch == ')' || ch == '}') continue;
        if (in_tag || std::isspace(ch)) continue;
        if (std::isdigit(ch)) {
            if (digit.has_value()) return std::nullopt;
            digit = ch - '0';
            continue;
        }
        if (std::isalpha(ch))
            return std::nullopt;
    }
    return digit;
}

bool IsInvisibleMenuCodePoint(unsigned int code_point) {
    if (code_point <= 0x7f)
        return std::isspace(static_cast<unsigned char>(code_point)) != 0;
    return code_point == 0x00a0 || code_point == 0x034f ||
        code_point == 0x061c || code_point == 0x115f ||
        code_point == 0x1160 || code_point == 0x17b4 ||
        code_point == 0x17b5 || code_point == 0x180e ||
        (code_point >= 0x2000 && code_point <= 0x200f) ||
        (code_point >= 0x2028 && code_point <= 0x202f) ||
        (code_point >= 0x205f && code_point <= 0x206f) ||
        code_point == 0x3000 || code_point == 0x3164 ||
        (code_point >= 0xfe00 && code_point <= 0xfe0f) ||
        code_point == 0xfeff || code_point == 0xffa0 ||
        (code_point >= 0xe0100 && code_point <= 0xe01ef);
}

bool IsVisuallyBlankMenuLabel(const std::string& value) {
    std::size_t offset = 0;
    while (offset < value.size()) {
        // Rich-text markup does not make an otherwise invisible label a
        // visible key name.  Malformed tags remain visible and fail closed.
        if (value[offset] == '<') {
            const auto close = value.find('>', offset + 1);
            if (close == std::string::npos) return false;
            offset = close + 1;
            continue;
        }

        const unsigned char lead = static_cast<unsigned char>(value[offset]);
        unsigned int code_point = 0;
        std::size_t length = 0;
        if (lead <= 0x7f) {
            code_point = lead;
            length = 1;
        } else if ((lead & 0xe0) == 0xc0) {
            code_point = lead & 0x1f;
            length = 2;
        } else if ((lead & 0xf0) == 0xe0) {
            code_point = lead & 0x0f;
            length = 3;
        } else if ((lead & 0xf8) == 0xf0) {
            code_point = lead & 0x07;
            length = 4;
        } else {
            return false;
        }
        if (offset + length > value.size()) return false;
        for (std::size_t index = 1; index < length; ++index) {
            const unsigned char continuation =
                static_cast<unsigned char>(value[offset + index]);
            if ((continuation & 0xc0) != 0x80) return false;
            code_point = (code_point << 6) | (continuation & 0x3f);
        }
        const bool overlong = (length == 2 && code_point < 0x80) ||
            (length == 3 && code_point < 0x800) ||
            (length == 4 && code_point < 0x10000);
        if (overlong || code_point > 0x10ffff ||
            (code_point >= 0xd800 && code_point <= 0xdfff) ||
            !IsInvisibleMenuCodePoint(code_point))
            return false;
        offset += length;
    }
    return true;
}

std::string VisibleDigitName(int digit) {
    return std::to_string(digit);
}

std::string EffectiveMenuGuideName(const Snapshot& snapshot,
    const Menu& menu) {
    const std::string own_name = Trim(menu.name);
    if (!own_name.empty()) return own_name;
    std::set<std::string> incoming_labels;
    for (const auto& parent : snapshot.menus)
        for (const auto& control : parent.controls)
            if (control.submenu == menu.id && !Trim(control.name).empty())
                incoming_labels.insert(Trim(control.name));
    return incoming_labels.size() == 1
        ? *incoming_labels.begin() : std::string{};
}

MenuMaps BuildMenuMaps(const Snapshot& snapshot, const RuleProfile& rules) {
    MenuMaps result;
    using AnonymousRawPage = std::pair<std::string, std::set<int>>;
    std::map<std::string, std::vector<AnonymousRawPage>> anonymous_pages;
    for (const auto& menu : snapshot.menus) {
        const std::string guide_menu_name =
            EffectiveMenuGuideName(snapshot, menu);
        std::map<std::string, std::vector<const MenuControl*>> groups;
        for (const auto& control : menu.controls)
            if (!control.parameter.empty()) groups[control.parameter].push_back(&control);

        for (const auto& [parameter, items] : groups) {
            MenuKeyMap mapping;
            bool explicit_names = true;
            for (const auto* control : items) {
                const auto name = Trim(control->name);
                const auto visible_digit = VisibleSingleDigit(name);
                if (!visible_digit.has_value()) {
                    explicit_names = false;
                    break;
                }
                const int raw_value = static_cast<int>(std::llround(control->value));
                int logical_digit = raw_value == 10 ? 0 : raw_value;
                logical_digit = *visible_digit;
                if (logical_digit < 0 || logical_digit > rules.menu_max_digit ||
                    mapping.count(logical_digit) != 0) {
                    explicit_names = false;
                    break;
                }
                mapping[logical_digit] = {
                    VisibleDigitName(logical_digit), raw_value};
            }
            if (explicit_names && mapping.size() >= static_cast<std::size_t>(
                    (std::max)(3, rules.menu_min_numeric_keys))) {
                result[parameter].push_back({guide_menu_name, mapping});
                continue;
            }

            // Some generators render keypad glyphs entirely through control
            // icons or shaders and leave only Unicode format characters in
            // the serialized names.  A single anonymous page is too weak to
            // call a keypad, so retain only strict Button pages here and
            // require a compatible multi-page union below.
            std::set<int> anonymous_raw_values;
            bool anonymous_page = items.size() >= static_cast<std::size_t>(
                (std::max)(4, rules.menu_min_numeric_keys));
            for (const auto* control : items) {
                if (control->type != 101 ||
                    !IsVisuallyBlankMenuLabel(control->name) ||
                    !std::isfinite(control->value) ||
                    std::abs(control->value - std::round(control->value)) > 1e-5) {
                    anonymous_page = false;
                    break;
                }
                const int raw_value = static_cast<int>(
                    std::llround(control->value));
                const bool allowed_zero = std::find(
                    rules.zero_raw_values.begin(), rules.zero_raw_values.end(),
                    raw_value) != rules.zero_raw_values.end();
                if (raw_value <= 0 ||
                    (raw_value > rules.menu_max_digit && !allowed_zero) ||
                    !anonymous_raw_values.insert(raw_value).second) {
                    anonymous_page = false;
                    break;
                }
            }
            if (anonymous_page)
                anonymous_pages[parameter].push_back(
                    {guide_menu_name, std::move(anonymous_raw_values)});

            std::set<int> values;
            bool icon = true, empty = true;
            for (const auto* control : items) {
                values.insert(static_cast<int>(std::llround(control->value)));
                icon &= control->has_icon;
                empty &= Trim(control->name).empty();
            }
            const std::set<int> one_to_eight = {1,2,3,4,5,6,7,8};
            if (items.size() == 8 && values == one_to_eight && icon && empty) {
                mapping.clear();
                for (int raw_value = 1; raw_value <= 8; ++raw_value) {
                    const int logical_digit =
                        std::find(rules.zero_raw_values.begin(),
                            rules.zero_raw_values.end(), raw_value) !=
                                rules.zero_raw_values.end()
                        ? 0 : raw_value;
                    mapping[logical_digit] = {
                        logical_digit == 0 ? "0" : std::to_string(logical_digit),
                        raw_value
                    };
                }
                result[parameter].push_back({guide_menu_name, mapping});
            }

            // Bracketed/generated labels such as [1]..[8] are explicit
            // key names, but an unrelated menu page using the same parameter
            // may make the aggregate group non-explicit. Recover the numeric
            // subset independently when its raw values are unambiguous.
            mapping.clear();
            bool subset_ok = true;
            for (const auto* control : items) {
                const auto logical = VisibleSingleDigit(Trim(control->name));
                if (!logical.has_value()) continue;
                const int raw_value = static_cast<int>(
                    std::llround(control->value));
                const auto present = mapping.find(*logical);
                if (present != mapping.end() &&
                    present->second.raw_value != raw_value) {
                    subset_ok = false;
                    break;
                }
                mapping[*logical] = {
                    VisibleDigitName(*logical), raw_value};
            }
            if (subset_ok && mapping.size() >= static_cast<std::size_t>(
                    (std::max)(4, rules.menu_min_numeric_keys)))
                result[parameter].push_back({guide_menu_name, mapping});
        }
    }

    // Anonymous generated keypads are accepted only when at least two pages
    // for the same exact parameter combine into eight or more distinct
    // digits.  Raw values above the configured digit range (commonly 10) may
    // represent visible zero; in-range alternatives such as raw 8 remain 8
    // when the larger, unambiguous zero encoding is present.
    for (const auto& [parameter, pages] : anonymous_pages) {
        if (pages.size() < 2) continue;
        std::set<int> raw_values;
        std::set<std::string> guide_names;
        for (const auto& [guide_name, page_values] : pages) {
            raw_values.insert(page_values.begin(), page_values.end());
            if (!guide_name.empty()) guide_names.insert(guide_name);
        }

        std::optional<int> zero_raw;
        bool zero_ambiguous = false;
        for (const int raw_value : raw_values) {
            if (raw_value <= rules.menu_max_digit ||
                std::find(rules.zero_raw_values.begin(),
                    rules.zero_raw_values.end(), raw_value) ==
                        rules.zero_raw_values.end())
                continue;
            if (zero_raw.has_value() && *zero_raw != raw_value) {
                zero_ambiguous = true;
                break;
            }
            zero_raw = raw_value;
        }
        if (zero_ambiguous) continue;

        MenuKeyMap mapping;
        bool compatible = true;
        for (const int raw_value : raw_values) {
            const int logical_digit = zero_raw.has_value() &&
                    raw_value == *zero_raw
                ? 0 : raw_value;
            if (logical_digit < 0 || logical_digit > rules.menu_max_digit ||
                mapping.count(logical_digit) != 0) {
                compatible = false;
                break;
            }
            mapping[logical_digit] = {
                VisibleDigitName(logical_digit), raw_value};
        }
        if (!compatible || mapping.size() < static_cast<std::size_t>(
                (std::max)(8, rules.menu_min_numeric_keys)))
            continue;
        result[parameter].push_back({
            guide_names.size() == 1 ? *guide_names.begin() : std::string{},
            std::move(mapping)});
    }

    // Generated keypads commonly split 0..6 and 7..9 across two linked
    // VRCExpressionsMenu pages.  Keep the per-page maps for diagnostics, but
    // also add one compatible union per parameter so a password that crosses
    // the page boundary still receives a complete guide.  A conflict in the
    // visible label or raw value makes the union ambiguous and is rejected.
    for (auto& [parameter, pages] : result) {
        if (pages.size() < 2) continue;
        MenuKeyMap merged;
        bool compatible = true;
        std::size_t anchor = 0;
        for (std::size_t page_index = 0; page_index < pages.size(); ++page_index) {
            if (pages[page_index].second.size() > pages[anchor].second.size() ||
                (pages[page_index].second.size() == pages[anchor].second.size() &&
                 LooksLock(pages[page_index].first) && !LooksLock(pages[anchor].first)))
                anchor = page_index;
            for (const auto& [digit, entry] : pages[page_index].second) {
                const auto existing = merged.find(digit);
                if (existing != merged.end() &&
                    (existing->second.raw_value != entry.raw_value ||
                     existing->second.name != entry.name)) {
                    compatible = false;
                    break;
                }
                merged[digit] = entry;
            }
            if (!compatible) break;
        }
        if (compatible && merged.size() > pages[anchor].second.size())
            pages.insert(pages.begin(), {pages[anchor].first, std::move(merged)});
    }
    return result;
}

// -------------------------------------------------------------------------
// Semantic IR pass
// -------------------------------------------------------------------------
//
// Older detectors intentionally recognize a number of well-proven generator
// layouts.  The pass below is complementary: it starts at concrete avatar
// effects, follows parameter data flow backwards, solves only the input
// transitions that can reach those effects, and replays the exact serialized
// transition order.  It never removes an older result.  A semantic candidate
// may be displayed after a successful menu mapping, while a rewrite plan is
// emitted only for a unique, replayed, stable terminal.

struct SemanticConsumer {
    const Controller* controller = nullptr;
    std::size_t machine_index = 0;
    int source_state = -1;
    int destination_state = -1;
    const Transition* transition = nullptr;
};

struct SemanticUsage {
    std::map<std::string, std::vector<SemanticConsumer>> consumers;
    std::map<std::string, int> writer_count;
    std::map<std::string, std::set<double>> written_values;
    std::map<std::string, std::set<std::pair<std::string, std::size_t>>>
        writer_machines;
    std::set<std::string> unsupported_writer_parameters;
    std::map<std::string, std::set<std::string>> read_sources;
    std::map<std::string, std::set<std::pair<std::string, std::size_t>>> all_writer_machines;
};

struct SemanticPathEdge {
    int source = -1;
    int destination = -1;
    std::size_t order = 0;
    const Transition* transition = nullptr;
};

struct SemanticIrCandidate {
    std::string controller;
    std::string controller_path_id;
    std::string parameter;
    std::string menu;
    std::string password;
    std::string raw;
    std::string family;
    std::vector<int> raw_values;
    std::vector<int> visible_values;
    std::size_t machine_index = static_cast<std::size_t>(-1);
    int terminal_state = -1;
    int effect_score = 0;
    bool replay_verified = false;
    bool strict_terminal = false;
    bool terminal_stable_shape = false;
    std::string input_kind = "menu";
};

struct SemanticIrResult {
    std::vector<SemanticIrCandidate> candidates;
    int machine_count = 0;
    int effect_terminal_count = 0;
    int sliced_machine_count = 0;
    int replayed_path_count = 0;
    std::size_t expanded_configurations = 0;
    std::size_t sliced_states = 0;
    std::size_t pruned_states = 0;
    std::size_t dependency_machines = 0;
    int budget_exhausted_count = 0;
    int unsupported_semantics_count = 0;
    int independent_replay_count = 0;
    int smt_attempt_count = 0;
    int smt_candidate_count = 0;
    int smt_unknown_count = 0;
    int smt_unsupported_count = 0;
    int smt_skipped_verified = 0;
    int smt_skipped_no_arithmetic = 0;
    std::map<std::string, int> smt_rejection_reasons;
    std::map<std::string, std::set<std::size_t>> deep_scan_machines;
};

// Preserve concrete predicate semantics. Decimal quantization is NOT a
// bisimulation: e.g. 0.1001 and 0.1004 differ for a >0.10025 guard.
std::uint64_t SemanticExactBits(double value) {
    if (value == 0.0) value = 0.0; // normalize negative zero only
    std::uint64_t bits = 0;
    static_assert(sizeof(bits) == sizeof(value));
    std::memcpy(&bits, &value, sizeof(bits));
    return bits;
}

std::uint64_t SemanticHash(std::string_view value) {
    std::uint64_t hash = UINT64_C(1469598103934665603);
    for (unsigned char byte : value) {
        hash ^= byte;
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

std::string SemanticHashText(std::string_view value) {
    std::ostringstream out;
    out << std::hex << std::setw(16) << std::setfill('0')
        << SemanticHash(value);
    return out.str();
}

int DirectAnimationEffectScore(const State& state) {
    int score = 0;
    // manual_activation_writes are the same serialized AnimationClip
    // bindings recovered through the stable-streamed-clip path.  They must
    // participate in terminal scoring; otherwise a real m_IsActive terminal
    // is invisible to the safety proof.
    const auto score_write = [&](const AnimationWrite& write) {
        const std::string attribute = LowerAscii(write.name);
        const std::string path = LowerAscii(write.path);
        if (attribute.find("m_isactive") != std::string::npos ||
            attribute == "active" || attribute == "enabled")
            score = std::max(score, 45);
        else if (attribute.find("blendshape") != std::string::npos)
            score = std::max(score, 35);
        else if (attribute.find("constraint") != std::string::npos ||
                 attribute.find("m_weight") != std::string::npos)
            score = std::max(score, 30);
        else if (attribute.find("material") != std::string::npos ||
                 attribute.find("renderer") != std::string::npos)
            score = std::max(score, 25);
        else if (!path.empty())
            score = std::max(score, 12);
    };
    for (const auto& write : state.animation_writes) score_write(write);
    for (const auto& write : state.manual_activation_writes) score_write(write);
    return score;
}

SemanticUsage BuildSemanticUsage(const Snapshot& snapshot) {
    SemanticUsage usage;
    for (const auto& controller : snapshot.controllers) {
        if (!snapshot.active_fx_controller_ids.empty() &&
            snapshot.active_fx_controller_ids.count(controller.path_id) == 0)
            continue;
        for (std::size_t machine_index = 0;
             machine_index < controller.machines.size(); ++machine_index) {
            const auto& machine = controller.machines[machine_index];
            auto scan = [&](int source, const std::vector<Transition>& transitions) {
                for (const auto& transition : transitions)
                    for (const auto& condition : transition.conditions) {
                        if (condition.parameter.empty()) continue;
                        usage.consumers[condition.parameter].push_back({
                            &controller, machine_index, source,
                            transition.destination, &transition});
                    }
            };
            for (std::size_t state_index = 0;
                 state_index < machine.states.size(); ++state_index) {
                const auto& state = machine.states[state_index];
                scan(static_cast<int>(state_index), state.transitions);
                for (const auto& write : state.writes) {
                    if (write.name.empty()) continue;
                    usage.all_writer_machines[write.name].insert({controller.path_id, machine_index});
                    if (!write.source.empty()) usage.read_sources[write.name].insert(write.source);
                    if (write.type != 0) {
                        usage.unsupported_writer_parameters.insert(write.name);
                        continue;
                    }
                    ++usage.writer_count[write.name];
                    usage.written_values[write.name].insert(write.value);
                    usage.writer_machines[write.name].insert(
                        {controller.path_id, machine_index});
                }
                for (const auto& write : state.animation_writes)
                    if (!write.name.empty())
                        usage.unsupported_writer_parameters.insert(write.name);
            }
            scan(-1, machine.any_transitions);
        }
    }
    return usage;
}

bool SemanticValueSatisfies(const Condition& condition, double value) {
    std::map<std::string, double> values{{condition.parameter, value}};
    const auto result = ConditionMatches(condition, values);
    return result.has_value() && *result;
}

int SemanticDownstreamEffect(const Snapshot& snapshot,
    const SemanticUsage& usage, const std::string& parameter, double value,
    int depth, std::set<std::pair<std::string, std::uint64_t>>& visiting,
    std::map<std::tuple<std::string, std::uint64_t, int>, int>& memo) {
    if (depth > 4) return 0;
    const auto quantized = SemanticExactBits(value);
    const auto memo_key = std::make_tuple(parameter, quantized, depth);
    const auto memo_found = memo.find(memo_key);
    if (memo_found != memo.end()) return memo_found->second;
    if (!visiting.insert({parameter, quantized}).second) return 0;
    int best = 0;
    const auto found = usage.consumers.find(parameter);
    if (found != usage.consumers.end()) {
        for (const auto& consumer : found->second) {
            if (!consumer.transition || !consumer.controller) continue;
            bool value_edge = false;
            for (const auto& condition : consumer.transition->conditions)
                if (condition.parameter == parameter &&
                    SemanticValueSatisfies(condition, value)) {
                    value_edge = true;
                    break;
                }
            if (!value_edge) continue;
            if (consumer.machine_index >= consumer.controller->machines.size())
                continue;
            const auto& machine =
                consumer.controller->machines[consumer.machine_index];
            if (consumer.destination_state < 0 ||
                consumer.destination_state >= static_cast<int>(machine.states.size()))
                continue;
            const auto& destination = machine.states[
                static_cast<std::size_t>(consumer.destination_state)];
            int score = DirectAnimationEffectScore(destination);
            for (const auto& write : destination.writes) {
                if (write.type != 0 || write.name == parameter) continue;
                score = std::max(score,
                    SemanticDownstreamEffect(snapshot, usage, write.name,
                        write.value, depth + 1, visiting, memo));
            }
            if (consumer.source_state < 0) score += 8;
            best = std::max(best, score);
        }
    }
    visiting.erase({parameter, quantized});
    memo[memo_key] = best;
    return best;
}

int SemanticStateEffectScore(const Snapshot& snapshot,
    const SemanticUsage& usage, const Controller& controller,
    std::size_t machine_index, const State& state,
    std::map<std::tuple<std::string, std::uint64_t, int>, int>& memo) {
    int score = DirectAnimationEffectScore(state);
    for (const auto& write : state.writes) {
        if (write.type != 0 || write.name.empty()) continue;
        int write_score = 0;
        const auto* runtime_default =
            EffectiveRuntimeDefault(snapshot, controller, write.name);
        if (runtime_default &&
            std::abs(runtime_default->value - write.value) > 1e-5)
            write_score += 18;
        const auto values = usage.written_values.find(write.name);
        if (values != usage.written_values.end() && values->second.size() >= 2)
            write_score += 10;
        if (snapshot.saved_expression_parameters.count(write.name) != 0)
            write_score += 12;
        const auto owners = usage.writer_machines.find(write.name);
        if (owners != usage.writer_machines.end() && owners->second.size() == 1 &&
            owners->second.count({controller.path_id, machine_index}) != 0)
            write_score += 8;
        std::set<std::pair<std::string, std::uint64_t>> visiting;
        const int downstream = SemanticDownstreamEffect(
            snapshot, usage, write.name, write.value, 0, visiting, memo);
        if (downstream > 0) write_score += 25 + downstream;
        score = std::max(score, write_score);
    }
    return score;
}

bool SemanticStrictTerminalEffectProof(const Snapshot& snapshot,
    const SemanticUsage& usage, const Controller& controller,
    std::size_t machine_index, const State& terminal) {
    // Stable streamed-clip bindings are direct effects even when the
    // extractor routes them through manual_activation_writes.  Treat a
    // uniquely bound, known active/inactive target as a valid terminal proof;
    // the previous proof only inspected ParameterDriver writes and therefore
    // rejected confirmed locks whose success state directly toggles a
    // GameObject/Renderer.
    for (const auto& effect : terminal.manual_activation_writes) {
        const std::string attribute = LowerAscii(effect.name);
        if (effect.binding_status == "unique_serialized_target" &&
            effect.serialized_active_known &&
            (attribute.find("m_isactive") != std::string::npos ||
             attribute.find("m_enabled") != std::string::npos))
            return true;
    }
    for (const auto& write : terminal.writes) {
        if (write.type != 0 || write.name.empty()) continue;
        const auto* runtime_default =
            EffectiveRuntimeDefault(snapshot, controller, write.name);
        if (!runtime_default ||
            std::abs(runtime_default->value - write.value) <= 1e-5)
            continue;

        const auto writer_count = usage.writer_count.find(write.name);
        const auto owners = usage.writer_machines.find(write.name);
        if (writer_count == usage.writer_count.end() ||
            writer_count->second != 1 ||
            owners == usage.writer_machines.end() ||
            owners->second.size() != 1 ||
            owners->second.count({controller.path_id, machine_index}) == 0)
            continue;

        // Non-Set or animation-driven writes to the same latch are outside
        // the semantic simulator and invalidate a permanent rewrite proof.
        if (usage.unsupported_writer_parameters.count(write.name) != 0)
            continue;

        const auto consumers = usage.consumers.find(write.name);
        if (consumers == usage.consumers.end()) continue;
        for (const auto& consumer : consumers->second) {
            if (!consumer.controller || !consumer.transition ||
                consumer.machine_index >= consumer.controller->machines.size())
                continue;
            bool exact_write_guard = !consumer.transition->conditions.empty();
            auto values = std::map<std::string, double>{};
            for (const auto& [name, item] : consumer.controller->parameter_defaults)
                values[name] = item.value;
            for (const auto& [name, item] : snapshot.expression_parameter_defaults)
                values[name] = item.value;
            values[write.name] = write.value;
            for (const auto& condition : consumer.transition->conditions) {
                // The latch write is only one input to a compound downstream
                // gate.  The previous implementation rejected every edge
                // containing any second condition, which discarded valid
                // confirmed candidates whose effect terminal also required a
                // normal avatar parameter (tracking, mode, or page state).
                const auto match = ConditionMatches(condition, values);
                if (!match || !*match) {
                    exact_write_guard = false;
                    break;
                }
            }
            if (!exact_write_guard) continue;
            const auto& consumer_machine =
                consumer.controller->machines[consumer.machine_index];
            if (!consumer_machine.any_transitions.empty() ||
                consumer.destination_state < 0 ||
                consumer.destination_state >=
                    static_cast<int>(consumer_machine.states.size()))
                continue;
            const auto& effect_state = consumer_machine.states[
                static_cast<std::size_t>(consumer.destination_state)];
            const bool stable = std::none_of(effect_state.transitions.begin(),
                effect_state.transitions.end(), [&](const Transition& transition) {
                    return transition.destination >= 0 &&
                        transition.destination <
                            static_cast<int>(consumer_machine.states.size()) &&
                        transition.destination != consumer.destination_state;
                });
            if (stable && DirectAnimationEffectScore(effect_state) >= 25) {
                // Prove the consumer can actually run, not merely that an
                // unreachable edge with the right latch value exists.
                auto values = std::map<std::string, double>{};
                for (const auto& [name, item] : consumer.controller->parameter_defaults)
                    values[name] = item.value;
                for (const auto& [name, item] : snapshot.expression_parameter_defaults)
                    values[name] = item.value;
                values[write.name] = write.value;
                int current = consumer_machine.default_state;
                std::set<int> seen;
                while (current >= 0 && current < static_cast<int>(consumer_machine.states.size()) &&
                    seen.insert(current).second) {
                    if (current == consumer.destination_state) return true;
                    const auto& state = consumer_machine.states[static_cast<std::size_t>(current)];
                    bool supported = true;
                    for (const auto& assignment : state.writes) {
                        if (assignment.type != 0) { supported = false; break; }
                        values[assignment.name] = assignment.value;
                    }
                    if (!supported) break;
                    const Transition* next = nullptr;
                    for (const auto& tr : state.transitions) {
                        if (tr.has_exit_time || std::abs(tr.duration) > 1e-9) { supported = false; break; }
                        bool enabled = true;
                        for (const auto& condition : tr.conditions) {
                            const auto match = ConditionMatches(condition, values);
                            if (!match) { supported = false; break; }
                            enabled &= *match;
                        }
                        if (!supported) break;
                        if (enabled) { next = &tr; break; }
                    }
                    if (!supported || !next) break;
                    current = next->destination;
                }
            }
        }
    }
    return false;
}

std::map<std::string, double> SemanticInitialValues(
    const Snapshot& snapshot, const Controller& controller) {
    std::map<std::string, double> values;
    for (const auto& [name, item] : controller.parameter_defaults)
        values[name] = item.value;
    for (const auto& [name, item] : snapshot.expression_parameter_defaults)
        values[name] = item.value;
    values["AvatarVersion"] = 3.0;
    return values;
}

std::optional<bool> SemanticTransitionEnabled(const Transition& transition,
    const std::map<std::string, double>& values) {
    bool unknown = false;
    for (const auto& condition : transition.conditions) {
        const auto match = ConditionMatches(condition, values);
        if (!match.has_value()) unknown = true;
        else if (!*match) return false;
    }
    return unknown ? std::optional<bool>{} : std::optional<bool>{true};
}


struct SemanticInputSpec {
    std::string parameter;
    std::string menu;
    std::string input_kind = "menu";
    std::map<int, int> raw_to_visible;
    double released_value = 0.0;
};

struct SemanticRuntimeNode {
    int state = -1;
    bool entry_pending = true;
    bool pressed = false;
    bool deterministic = true;
    std::map<std::string, double> values;
    std::vector<int> raw_values;
    std::vector<int> visible_values;
    std::string trace;
    std::vector<std::pair<int,int>> actions;
};

std::vector<SemanticInputSpec> SemanticInputSpecs(
    const Snapshot& snapshot, const Controller& controller,
    const Machine& machine, const MenuMaps& menu_maps,
    const std::set<std::string>& condition_parameters) {
    std::vector<SemanticInputSpec> specs;
    std::set<std::string> seen;
    const auto append = [&](SemanticInputSpec spec,
                            std::vector<SemanticInputSpec>& output,
                            std::set<std::string>& keys) {
        std::ostringstream key;
        key << spec.parameter << '|' << spec.input_kind << '|';
        for (const auto& [raw, visible] : spec.raw_to_visible)
            key << raw << '=' << visible << ',';
        if (!keys.insert(key.str()).second) return;
        output.push_back(std::move(spec));
    };

    for (const auto& [parameter, pages] : menu_maps) {
        if (condition_parameters.count(parameter) == 0) continue;
        const auto* runtime_default =
            EffectiveRuntimeDefault(snapshot, controller, parameter);
        for (const auto& [menu_name, mapping] : pages) {
            SemanticInputSpec spec;
            spec.parameter = parameter;
            spec.menu = menu_name;
            spec.released_value = runtime_default ? runtime_default->value : 0.0;
            for (const auto& [visible, entry] : mapping)
                spec.raw_to_visible[entry.raw_value] = visible;
            if (spec.raw_to_visible.size() >= 3)
                append(std::move(spec), specs, seen);
        }
    }

    // If a serialized menu reference is missing, an Expression Parameter can
    // still be written through VRChat OSC.  Keep this as a raw-value input,
    // but demand a repeated keypad-shaped consumer before exposing it.  This
    // deliberately excludes ordinary one-shot feature parameters.
    for (const auto& parameter : condition_parameters) {
        if (menu_maps.count(parameter) != 0 ||
            snapshot.expression_parameters.count(parameter) == 0)
            continue;
        const auto* runtime_default =
            EffectiveRuntimeDefault(snapshot, controller, parameter);
        const double released = runtime_default ? runtime_default->value : 0.0;
        std::set<int> raw_values;
        std::set<int> consuming_states;
        int release_edges = 0;
        for (std::size_t state_index = 0;
             state_index < machine.states.size(); ++state_index) {
            for (const auto& transition : machine.states[state_index].transitions) {
                bool consumes = false;
                for (const auto& condition : transition.conditions) {
                    if (condition.parameter != parameter) continue;
                    consumes = true;
                    if (condition.mode == 6 &&
                        std::isfinite(condition.threshold) &&
                        std::abs(condition.threshold -
                            std::round(condition.threshold)) <= 1e-5) {
                        const int raw = static_cast<int>(
                            std::llround(condition.threshold));
                        if (raw >= 0 && raw <= 9 &&
                            std::abs(static_cast<double>(raw) - released) > 1e-5)
                            raw_values.insert(raw);
                    } else if (condition.mode == 7) {
                        ++release_edges;
                    }
                }
                if (consumes) consuming_states.insert(
                    static_cast<int>(state_index));
            }
        }
        if (raw_values.size() < 3 || consuming_states.size() < 5 ||
            (release_edges < 2 &&
             !HasStrongPasswordSemantics(machine, parameter)))
            continue;
        SemanticInputSpec spec;
        spec.parameter = parameter;
        spec.input_kind = "osc";
        spec.released_value = released;
        for (int raw : raw_values) spec.raw_to_visible[raw] = raw;
        append(std::move(spec), specs, seen);
    }
    return specs;
}

std::string SemanticRuntimeSignature(const SemanticRuntimeNode& node,
    const std::set<std::string>& relevant_parameters) {
    std::ostringstream signature;
    // An assumed initial-value variant must never dominate the same runtime
    // configuration reached deterministically from the canonical defaults.
    // Strict rewrite eligibility depends on that provenance, so it is part
    // of the search state even though it does not alter transition truth.
    signature << node.state << '|' << (node.pressed ? 'P' : 'R')
              << '|' << (node.deterministic ? 'D' : 'U');
    for (const auto& parameter : relevant_parameters) {
        const auto value = node.values.find(parameter);
        signature << '|' << parameter.size() << ':' << parameter << '=';
        if (value == node.values.end()) signature << '?';
        else signature << SemanticExactBits(value->second);
    }
    return signature.str();
}

void AppendSemanticTransitionShape(std::string& trace,
    const Machine& machine, int source, const Transition& transition,
    std::size_t order, bool any_state, bool timed,
    const std::string& input_parameter) {
    trace += any_state ? "A" : "L";
    trace += timed ? "T" : "I";
    trace += ':' + std::to_string(order) + ':';
    if (source >= 0 && source < static_cast<int>(machine.states.size()))
        trace += std::to_string(
            machine.states[static_cast<std::size_t>(source)].transitions.size());
    trace += ':' + std::to_string(transition.conditions.size()) + ':';
    for (const auto& condition : transition.conditions) {
        trace += condition.parameter == input_parameter ? 'K' : 'G';
        trace += std::to_string(condition.mode) + ',';
    }
    if (transition.destination >= 0 &&
        transition.destination < static_cast<int>(machine.states.size())) {
        const auto& destination = machine.states[
            static_cast<std::size_t>(transition.destination)];
        trace += "W" + std::to_string(destination.writes.size());
        trace += "E" + std::to_string(
            DirectAnimationEffectScore(destination) / 10);
    }
    trace += ';';
}

const Transition* SelectSemanticTransition(
    const Machine& machine, const SemanticRuntimeNode& node, bool timed,
    std::size_t& order, bool& any_state, bool& known) {
    known = true;
    const auto select = [&](const std::vector<Transition>& transitions,
                            bool from_any) -> const Transition* {
        for (std::size_t index = 0; index < transitions.size(); ++index) {
            const auto& transition = transitions[index];
            if (transition.has_exit_time != timed) continue;
            if (from_any && transition.destination == node.state &&
                !transition.can_transition_to_self)
                continue;
            const auto enabled =
                SemanticTransitionEnabled(transition, node.values);
            if (!enabled.has_value()) {
                known = false;
                // Unknown conditions are retained as a possible path for
                // operator candidates, never as a strict rewrite proof.
                order = index;
                any_state = from_any;
                return &transition;
            }
            if (!*enabled) continue;
            order = index;
            any_state = from_any;
            return &transition;
        }
        return nullptr;
    };
    if (const auto* transition = select(machine.any_transitions, true))
        return transition;
    if (node.state < 0 ||
        node.state >= static_cast<int>(machine.states.size()))
        return nullptr;
    return select(machine.states[static_cast<std::size_t>(node.state)].transitions,
        false);
}

#include "semantic_slice.inc"
#include "distributed_keypad.inc"

std::vector<std::pair<std::map<std::string, double>, bool>>
SemanticInitialVariants(const Snapshot& snapshot,
    const SemanticUsage& usage, const Controller& controller,
    const std::string& input_parameter,
    const std::set<std::string>& relevant_parameters, SemanticIrResult& diagnostics) {
    auto canonical = SemanticInitialValues(snapshot, controller);
    bool canonical_complete = true;
    for (const auto& parameter : relevant_parameters) {
        if (canonical.count(parameter) != 0) continue;
        canonical_complete = false;
    }
    std::vector<std::pair<std::map<std::string, double>, bool>> variants;
    variants.push_back({canonical, canonical_complete});

    struct Domain { std::string parameter; std::set<double> values; };
    std::vector<Domain> domains;
    for (const auto& parameter : relevant_parameters) {
        if (parameter == input_parameter || parameter == "AvatarVersion" ||
            canonical.count(parameter) == 0)
            continue;
        std::set<double> values{canonical[parameter]};
        const auto written = usage.written_values.find(parameter);
        if (written != usage.written_values.end())
            values.insert(written->second.begin(), written->second.end());
        const auto controller_default = controller.parameter_defaults.find(parameter);
        if (controller_default != controller.parameter_defaults.end())
            values.insert(controller_default->second.value);
        const bool externally_mutable =
            snapshot.contact_input_parameters.count(parameter) != 0 ||
            snapshot.dynamic_contact_parameters.count(parameter) != 0 ||
            snapshot.forced_contact_parameters.count(parameter) != 0 ||
            snapshot.saved_expression_parameters.count(parameter) != 0 ||
            (written != usage.written_values.end() &&
             usage.writer_machines.count(parameter) != 0);
        if (!externally_mutable || values.size() < 2)
            continue;
        if (values.size() > 4) { ++diagnostics.budget_exhausted_count; continue; }
        domains.push_back({parameter, std::move(values)});
    }
    std::sort(domains.begin(), domains.end(),
        [&](const Domain& left, const Domain& right) {
            const auto left_usage = usage.consumers.find(left.parameter);
            const auto right_usage = usage.consumers.find(right.parameter);
            const auto left_count = left_usage == usage.consumers.end()
                ? 0 : left_usage->second.size();
            const auto right_count = right_usage == usage.consumers.end()
                ? 0 : right_usage->second.size();
            if (left_count != right_count) return left_count > right_count;
            return left.parameter < right.parameter;
        });
    if (domains.size() > 5) {
        ++diagnostics.budget_exhausted_count;
        domains.resize(5);
    }

    for (const auto& domain : domains) {
        const auto existing = variants;
        for (const auto& [values, unused] : existing) {
            (void)unused;
            for (double value : domain.values) {
                if (std::abs(value - canonical[domain.parameter]) <= 1e-5)
                    continue;
                auto alternative = values;
                alternative[domain.parameter] = value;
                variants.push_back({std::move(alternative), false});
                if (variants.size() >= 32) break;
            }
            if (variants.size() >= 32) break;
        }
        if (variants.size() >= 32) {
            ++diagnostics.budget_exhausted_count;
            break;
        }
    }
    return variants;
}

std::vector<SemanticIrCandidate> SolveSemanticRuntime(
    const Snapshot& snapshot, const SemanticUsage& usage,
    const Controller& controller, std::size_t machine_index,
    const Machine& machine, const SemanticInputSpec& input,
    const std::vector<std::pair<int, int>>& terminal_scores,
    int& replayed_count, SemanticIrResult& diagnostics) {
    std::vector<SemanticIrCandidate> solved;
    if (machine.default_state < 0 ||
        machine.default_state >= static_cast<int>(machine.states.size()) ||
        input.raw_to_visible.size() < 3)
        return solved;

    std::set<std::string> relevant_parameters{input.parameter};
    for (const auto& state : machine.states)
        for (const auto& transition : state.transitions)
            for (const auto& condition : transition.conditions)
                if (!condition.parameter.empty())
                    relevant_parameters.insert(condition.parameter);
    for (const auto& transition : machine.any_transitions)
        for (const auto& condition : transition.conditions)
            if (!condition.parameter.empty())
                relevant_parameters.insert(condition.parameter);

    std::set<int> terminals;
    std::map<int, int> effect_scores;
    for (const auto& [terminal, score] : terminal_scores) {
        terminals.insert(terminal);
        effect_scores[terminal] = score;
    }
    const auto slice = BuildSemanticSlice(usage, controller, machine_index,
        machine, input.parameter, terminals);
    diagnostics.sliced_states += slice.states.size();
    diagnostics.pruned_states += machine.states.size() - slice.states.size();
    diagnostics.dependency_machines += slice.dependencies.size();
    if (!slice.states.count(machine.default_state)) return solved;
    relevant_parameters = slice.parameters;
    const int budget_before = diagnostics.budget_exhausted_count;
    const auto initial_variants = SemanticInitialVariants(snapshot, usage,
        controller, input.parameter, relevant_parameters, diagnostics);
    constexpr std::size_t kMaximumConfigurations = 4096;
    constexpr std::size_t kMaximumPresses = 24;
    constexpr std::size_t kMaximumSolved = 24;

    std::deque<SemanticRuntimeNode> pending;
    std::map<std::string, std::size_t> best_configuration_depth;
    std::map<int, bool> strict_effect_proofs;
    const auto record_terminals = [&](const SemanticRuntimeNode& node,
                                      const std::set<int>& touched,
                                      bool stable) {
        if (node.visible_values.size() < 3 ||
            node.visible_values.size() > kMaximumPresses)
            return;
        for (int terminal : touched) {
            const auto effect = effect_scores.find(terminal);
            if (effect == effect_scores.end()) continue;
            std::ostringstream password;
            std::ostringstream raw;
            bool valid = true;
            for (std::size_t index = 0;
                 index < node.visible_values.size(); ++index) {
                const int visible = node.visible_values[index];
                if (visible < 0 || visible > 9) {
                    valid = false;
                    break;
                }
                password << visible;
                if (index) raw << ',';
                raw << node.raw_values[index];
            }
            if (!valid) continue;
            std::ostringstream family_shape;
            family_shape << "input:" << input.input_kind
                         << "|alphabet:" << input.raw_to_visible.size()
                         << "|trace:" << node.trace;
            SemanticIrCandidate candidate;
            candidate.controller = controller.name;
            candidate.controller_path_id = controller.path_id;
            candidate.parameter = input.parameter;
            candidate.menu = input.menu;
            candidate.password = password.str();
            candidate.raw = raw.str();
            candidate.raw_values = node.raw_values;
            candidate.visible_values = node.visible_values;
            candidate.family = "semantic_effect_slice_v2_" +
                SemanticHashText(family_shape.str()).substr(0, 12);
            candidate.machine_index = machine_index;
            candidate.terminal_state = terminal;
            candidate.effect_score = effect->second;
            candidate.replay_verified = node.deterministic;
            const bool no_concrete_outgoing = std::none_of(
                machine.states[static_cast<std::size_t>(terminal)]
                    .transitions.begin(),
                machine.states[static_cast<std::size_t>(terminal)]
                    .transitions.end(),
                [&](const Transition& transition) {
                    return transition.destination >= 0 &&
                        transition.destination <
                            static_cast<int>(machine.states.size()) &&
                        transition.destination != terminal;
                });
            auto strict_effect = strict_effect_proofs.find(terminal);
            if (strict_effect == strict_effect_proofs.end()) {
                strict_effect = strict_effect_proofs.emplace(terminal,
                    SemanticStrictTerminalEffectProof(snapshot, usage,
                        controller, machine_index,
                        machine.states[static_cast<std::size_t>(terminal)]))
                    .first;
            }
            candidate.strict_terminal = stable && node.deterministic &&
                !slice.competing_writers &&
                no_concrete_outgoing && machine.any_transitions.empty() &&
                effect->second >= 85 && strict_effect->second;
            if (candidate.strict_terminal) {
                candidate.strict_terminal = ReplaySemanticWitness(snapshot,
                    controller, machine, input, node.actions, terminal);
                if (candidate.strict_terminal) ++diagnostics.independent_replay_count;
            }
            candidate.terminal_stable_shape = no_concrete_outgoing;
            candidate.input_kind = input.input_kind;
            solved.push_back(std::move(candidate));
            ++replayed_count;
            if (solved.size() >= kMaximumSolved) return;
        }
    };

    for (const auto& [initial_values, canonical] : initial_variants) {
        SemanticRuntimeNode initial;
        initial.state = machine.default_state;
        initial.values = initial_values;
        initial.values[input.parameter] = input.released_value;
        initial.deterministic = canonical;
        for (auto& branch : NormalizeSemanticBranches(snapshot, controller, machine, input,
                std::move(initial), terminals, slice, diagnostics)) {
            record_terminals(branch.node, branch.touched,
                branch.touched.count(branch.node.state) != 0);
            const auto signature = SemanticRuntimeSignature(branch.node, relevant_parameters);
            if (best_configuration_depth.emplace(signature, 0).second)
                pending.push_back(std::move(branch.node));
        }
    }

    std::size_t expanded = 0;
    while (!pending.empty() && expanded < kMaximumConfigurations &&
           solved.size() < kMaximumSolved) {
        SemanticRuntimeNode node = std::move(pending.front());
        pending.pop_front();
        ++expanded;

        const auto enqueue = [&](SemanticRuntimeNode next,
                                 std::set<int> touched,
                                 bool stable_terminal,
                                 std::deque<SemanticRuntimeNode>& queue,
                                 std::map<std::string, std::size_t>& best) {
            for (auto& branch : NormalizeSemanticBranches(snapshot, controller, machine, input,
                    std::move(next), terminals, slice, diagnostics)) {
                branch.touched.insert(touched.begin(), touched.end());
                auto& settled = branch.node;
                record_terminals(settled, branch.touched,
                    stable_terminal || branch.touched.count(settled.state) != 0);
                const auto signature = SemanticRuntimeSignature(settled, relevant_parameters);
                const auto found = best.find(signature);
                if (found != best.end() && found->second <= settled.visible_values.size())
                    continue;
                best[signature] = settled.visible_values.size();
                queue.push_back(std::move(settled));
            }
        };

        if (!node.pressed &&
            node.visible_values.size() < kMaximumPresses) {
            for (const auto& [raw, visible] : input.raw_to_visible) {
                SemanticRuntimeNode next = node;
                next.values[input.parameter] = static_cast<double>(raw);
                next.pressed = true;
                next.raw_values.push_back(raw);
                next.visible_values.push_back(visible);
                next.trace += "P;";
                next.actions.emplace_back(0, raw);
                enqueue(std::move(next), {}, false, pending,
                    best_configuration_depth);
            }
        } else if (node.pressed) {
            SemanticRuntimeNode next = node;
            next.values[input.parameter] = input.released_value;
            next.pressed = false;
            next.trace += "R;";
            next.actions.emplace_back(1, 0);
            enqueue(std::move(next), {}, false, pending,
                best_configuration_depth);
        }
        else if (node.visible_values.size() >= kMaximumPresses &&
                 !terminals.count(node.state)) {
            ++diagnostics.budget_exhausted_count;
        }

        std::size_t order = 0;
        bool any_state = false;
        bool known = true;
        const auto* timed = SelectSemanticTransition(
            machine, node, true, order, any_state, known);
        if (timed && timed->destination >= 0 &&
            timed->destination < static_cast<int>(machine.states.size())) {
            SemanticRuntimeNode next = node;
            if (!known) next.deterministic = false;
            if (!known || std::abs(timed->duration) > 1e-9 ||
                timed->interruption_source != 0) {
                next.deterministic = false;
                ++diagnostics.unsupported_semantics_count;
            }
            AppendSemanticTransitionShape(next.trace, machine, node.state,
                *timed, order, any_state, true, input.parameter);
            next.state = timed->destination;
            next.entry_pending = true;
            next.actions.emplace_back(2, 0);
            enqueue(std::move(next), {}, false, pending,
                best_configuration_depth);
        }
    }


    diagnostics.expanded_configurations += expanded;
    if (!pending.empty()) ++diagnostics.budget_exhausted_count;
    if (diagnostics.budget_exhausted_count != budget_before)
        for (auto& candidate : solved) candidate.strict_terminal = false;
    const bool has_stable_terminal = std::any_of(solved.begin(), solved.end(),
        [](const auto& candidate) {
            return candidate.terminal_stable_shape;
        });
    if (has_stable_terminal) {
        solved.erase(std::remove_if(solved.begin(), solved.end(),
            [](const auto& candidate) {
                return !candidate.terminal_stable_shape;
            }), solved.end());
    }
    std::sort(solved.begin(), solved.end(),
        [](const auto& left, const auto& right) {
            // Identical input/terminal pairs can be reached both from the
            // canonical defaults and from an assumed initial-value variant.
            // Keep the canonical deterministic proof when deduplicating.
            if (left.strict_terminal != right.strict_terminal)
                return left.strict_terminal > right.strict_terminal;
            if (left.replay_verified != right.replay_verified)
                return left.replay_verified > right.replay_verified;
            if (left.terminal_stable_shape != right.terminal_stable_shape)
                return left.terminal_stable_shape >
                    right.terminal_stable_shape;
            if (left.effect_score != right.effect_score)
                return left.effect_score > right.effect_score;
            if (left.password.size() != right.password.size())
                return left.password.size() < right.password.size();
            if (left.password != right.password)
                return left.password < right.password;
            return left.terminal_state < right.terminal_state;
        });
    solved.erase(std::unique(solved.begin(), solved.end(),
        [](const auto& left, const auto& right) {
            return left.password == right.password &&
                left.terminal_state == right.terminal_state &&
                left.input_kind == right.input_kind;
        }), solved.end());
    std::map<int, int> terminal_counts;
    for (const auto& candidate : solved)
        ++terminal_counts[candidate.terminal_state];
    for (auto& candidate : solved)
        if (terminal_counts[candidate.terminal_state] != 1)
            candidate.strict_terminal = false;
    if (solved.size() > 5) solved.resize(5);
    return solved;
}

#include "semantic_smt_dispatch.inc"

SemanticIrResult AnalyzeSemanticIr(const Snapshot& snapshot,
    const MenuMaps& menu_maps) {
    SemanticIrResult result;
    const auto usage = BuildSemanticUsage(snapshot);
    std::map<std::tuple<std::string, std::uint64_t, int>, int> downstream_memo;
    for (const auto& controller : snapshot.controllers) {
        if (!snapshot.active_fx_controller_ids.empty() &&
            snapshot.active_fx_controller_ids.count(controller.path_id) == 0)
            continue;
        for (std::size_t machine_index = 0;
             machine_index < controller.machines.size(); ++machine_index) {
            ++result.machine_count;
            const auto& machine = controller.machines[machine_index];
            if (machine.states.size() < 4)
                continue;
            std::set<std::string> machine_condition_parameters;
            for (const auto& state : machine.states)
                for (const auto& transition : state.transitions)
                    for (const auto& condition : transition.conditions)
                        if (!condition.parameter.empty())
                            machine_condition_parameters.insert(
                                condition.parameter);
            for (const auto& transition : machine.any_transitions)
                for (const auto& condition : transition.conditions)
                    if (!condition.parameter.empty())
                        machine_condition_parameters.insert(condition.parameter);
            const auto input_specs = SemanticInputSpecs(snapshot, controller,
                machine, menu_maps, machine_condition_parameters);
            // Effect scoring walks cross-machine consumers recursively.  A
            // machine without any menu/OSC-shaped input can never yield a
            // password candidate, so reject it before that expensive pass.
            if (input_specs.empty()) continue;
            // The fast snapshot deliberately omits most clip effects.  Once a
            // real menu/OSC input machine is present, request effect data only
            // for its active controller.  Detached controller copies remain
            // outside the request, which is the main speed win over a full
            // AnimationClip scan.
            if (snapshot.analysis_depth == "fast") {
                const bool has_effect_writes = std::any_of(
                    controller.machines.begin(), controller.machines.end(),
                    [](const Machine& candidate_machine) {
                        return std::any_of(candidate_machine.states.begin(),
                            candidate_machine.states.end(), [](const State& state) {
                                return !state.animation_writes.empty() ||
                                    !state.manual_activation_writes.empty();
                            });
                    });
                if (!has_effect_writes && controller.machines.size() <= 512) {
                    auto& requested = result.deep_scan_machines[controller.path_id];
                    requested.insert(machine_index);
                    for (const auto& parameter : machine_condition_parameters) {
                        const auto owners = usage.all_writer_machines.find(parameter);
                        if (owners == usage.all_writer_machines.end()) continue;
                        for (const auto& [owner_path, owner_machine] : owners->second)
                            result.deep_scan_machines[owner_path].insert(owner_machine);
                    }
                }
            }
            if (machine.states.size() > 1024) {
                ++result.budget_exhausted_count;
                continue;
            }

            std::vector<std::pair<int, int>> terminals;
            for (std::size_t state_index = 0;
                 state_index < machine.states.size(); ++state_index) {
                const int score = SemanticStateEffectScore(snapshot, usage,
                    controller, machine_index, machine.states[state_index],
                    downstream_memo);
                if (score >= 45)
                    terminals.push_back({static_cast<int>(state_index), score});
            }
            if (terminals.empty()) continue;
            result.effect_terminal_count += static_cast<int>(terminals.size());
            bool machine_sliced = false;
            for (const auto& input : input_specs) {
                auto solved = SolveSemanticRuntime(snapshot, usage,
                    controller, machine_index, machine, input, terminals,
                    result.replayed_path_count, result);
#if defined(VRC_ENABLE_LOCAL_SMT)
                if (std::none_of(solved.begin(), solved.end(),
                        [](const auto& candidate) { return candidate.strict_terminal; })) {
                    auto candidate = SolveLocalSmtSlice(snapshot, usage, controller,
                        machine_index, machine, input, terminals, result);
                    if (candidate) solved.push_back(std::move(*candidate));
                } else ++result.smt_skipped_verified;
#endif
                if (solved.empty()) continue;
                machine_sliced = true;
                result.candidates.insert(result.candidates.end(),
                    std::make_move_iterator(solved.begin()),
                    std::make_move_iterator(solved.end()));
            }
            if (machine_sliced) ++result.sliced_machine_count;
        }
    }
    std::sort(result.candidates.begin(), result.candidates.end(),
        [](const auto& left, const auto& right) {
            const bool left_smt = left.family.rfind("local_smt_integer_", 0) == 0;
            const bool right_smt = right.family.rfind("local_smt_integer_", 0) == 0;
            if (left_smt != right_smt) return !left_smt;
            if (left.strict_terminal != right.strict_terminal)
                return left.strict_terminal > right.strict_terminal;
            if (left.effect_score != right.effect_score)
                return left.effect_score > right.effect_score;
            if (left.password != right.password)
                return left.password < right.password;
            if (left.controller_path_id != right.controller_path_id)
                return left.controller_path_id < right.controller_path_id;
            return left.machine_index < right.machine_index;
        });
    result.candidates.erase(std::unique(result.candidates.begin(),
        result.candidates.end(), [](const auto& left, const auto& right) {
            return left.password == right.password &&
                left.parameter == right.parameter &&
                left.controller_path_id == right.controller_path_id &&
                left.machine_index == right.machine_index &&
                left.terminal_state == right.terminal_state &&
                left.input_kind == right.input_kind;
        }), result.candidates.end());
    return result;
}

struct PressReleaseDetection {
    int safe_unlock_state = -1;
    bool needs_menu_recovery = false;
};

bool StrongPressReleaseSemanticTerminal(const Controller& controller,
    const Machine& machine, int state_index) {
    if (state_index < 0 ||
        state_index >= static_cast<int>(machine.states.size())) return false;
    const auto& state = machine.states[static_cast<std::size_t>(state_index)];
    std::set<std::string> bool_names;
    int changed_defaults = 0;
    for (const auto& write : state.writes) {
        if (write.type != 0 ||
            (std::abs(write.value) > 1e-5 &&
             std::abs(write.value - 1.0) > 1e-5)) continue;
        const auto found = controller.parameter_defaults.find(write.name);
        if (found == controller.parameter_defaults.end() ||
            found->second.type != "bool") continue;
        bool_names.insert(write.name);
        if ((found->second.value > 0.5) != (write.value > 0.5))
            ++changed_defaults;
    }
    if (bool_names.size() < 2 || changed_defaults < 1) return false;

    // Generated locks often execute ParameterDriver writes in the success
    // state and immediately fall through to a silent idle state.  Accept only
    // unconditional fall-throughs whose destination neither writes parameters
    // nor has another concrete transition; anything stateful remains unsafe.
    for (const auto& transition : state.transitions) {
        if (transition.destination < 0 ||
            transition.destination >= static_cast<int>(machine.states.size()))
            continue;
        if (!transition.conditions.empty()) return false;
        const auto& idle = machine.states[
            static_cast<std::size_t>(transition.destination)];
        if (!idle.writes.empty()) return false;
        const bool idle_has_concrete_outgoing = std::any_of(
            idle.transitions.begin(), idle.transitions.end(),
            [&](const Transition& next) {
                return next.destination >= 0 &&
                    next.destination < static_cast<int>(machine.states.size());
            });
        if (idle_has_concrete_outgoing) return false;
    }
    return true;
}

const ParameterDefault* EffectiveRuntimeDefault(const Snapshot& snapshot,
    const Controller& controller, const std::string& parameter) {
    // VRChat initializes expression parameters from the descriptor asset. A
    // saved Boolean may intentionally disagree with the Animator Controller's
    // own default so the first runtime frame starts locked. Prefer that
    // runtime-visible default; falling back keeps older snapshots compatible.
    const auto expression =
        snapshot.expression_parameter_defaults.find(parameter);
    if (expression != snapshot.expression_parameter_defaults.end())
        return &expression->second;
    const auto controller_default = controller.parameter_defaults.find(parameter);
    return controller_default == controller.parameter_defaults.end()
        ? nullptr : &controller_default->second;
}

// A generated two-stage lock commonly stores a numeric input chain in one
// state machine and lets a second state machine consume a latch written by a
// first chain.  The older AnalyzeMachine detector deliberately reports the
// numeric chain as a reference only; this proof pass upgrades it only when the
// complete gate/terminal/effect relationship is present.  No names, PathIDs,
// or sample passwords are used here.
struct GuardedNumericPathProof {
    std::string parameter;
    std::string gate_parameter;
    int gate_mode = 0;
    std::vector<int> raw_values;
    int numeric_endpoint = -1;
    int terminal_state = -1;
    std::vector<const Transition*> input_transitions;
};

std::optional<int> NumericTransitionValue(const Transition& transition,
    const std::string& parameter) {
    std::optional<int> value;
    for (const auto& condition : transition.conditions) {
        if (condition.parameter != parameter) continue;
        if (condition.mode != 6 || !std::isfinite(condition.threshold))
            return std::nullopt;
        const int rounded = static_cast<int>(std::llround(condition.threshold));
        if (rounded < 0 || rounded > 19 ||
            std::abs(condition.threshold - rounded) > 1e-5 || value.has_value())
            return std::nullopt;
        value = rounded;
    }
    return value;
}

std::vector<GuardedNumericPathProof> EnumerateGuardedNumericPaths(
    const Snapshot& snapshot, const Controller& controller,
    const Machine& machine) {
    (void)snapshot;
    std::set<std::string> parameters;
    for (const auto& state : machine.states)
        for (const auto& transition : state.transitions)
            for (const auto& condition : transition.conditions)
                if (condition.mode == 6 && !condition.parameter.empty() &&
                    std::isfinite(condition.threshold) &&
                    condition.threshold >= 0.0 && condition.threshold <= 19.0)
                    parameters.insert(condition.parameter);

    std::vector<GuardedNumericPathProof> result;
    if (machine.default_state < 0 ||
        machine.default_state >= static_cast<int>(machine.states.size()))
        return result;

    for (const auto& parameter : parameters) {
        struct Node {
            int state = -1;
            std::vector<int> values;
            std::vector<const Transition*> transitions;
            std::set<int> visited;
        };
        std::vector<Node> pending;
        pending.push_back({machine.default_state, {}, {},
            {machine.default_state}});
        std::size_t expanded = 0;
        while (!pending.empty() && result.size() < 256 && expanded++ < 4096) {
            Node node = std::move(pending.back());
            pending.pop_back();
            if (node.state < 0 ||
                node.state >= static_cast<int>(machine.states.size()))
                continue;
            std::vector<std::pair<int, const Transition*>> edges;
            for (const auto& transition : machine.states[
                    static_cast<std::size_t>(node.state)].transitions) {
                const auto value = NumericTransitionValue(transition, parameter);
                if (!value.has_value() || transition.destination < 0 ||
                    transition.destination >= static_cast<int>(machine.states.size()) ||
                    node.visited.count(transition.destination) != 0)
                    continue;
                edges.push_back({*value, &transition});
            }
            if (edges.empty()) {
                if (node.values.size() < 3) continue;
                std::map<std::pair<std::string, int>, int> votes;
                for (const auto* transition : node.transitions) {
                    std::set<std::pair<std::string, int>> per_edge;
                    for (const auto& condition : transition->conditions)
                        if (condition.parameter != parameter &&
                            (condition.mode == 1 || condition.mode == 2) &&
                            !condition.parameter.empty())
                            per_edge.insert({condition.parameter, condition.mode});
                    for (const auto& key : per_edge) ++votes[key];
                }
                std::vector<std::pair<std::string, int>> common;
                for (const auto& [key, count] : votes)
                    if (count == static_cast<int>(node.transitions.size()))
                        common.push_back(key);
                // More than one common Boolean guard is ambiguous: choosing one
                // would make the later producer relation order-dependent.
                if (common.size() != 1) continue;
                GuardedNumericPathProof proof;
                proof.parameter = parameter;
                proof.gate_parameter = common.front().first;
                proof.gate_mode = common.front().second;
                proof.raw_values = std::move(node.values);
                proof.numeric_endpoint = node.state;
                proof.input_transitions = std::move(node.transitions);

                std::set<int> settlements;
                for (const auto& transition : machine.states[
                        static_cast<std::size_t>(node.state)].transitions) {
                    if (transition.destination < 0 ||
                        transition.destination >= static_cast<int>(machine.states.size()) ||
                        transition.destination == node.state ||
                        NumericTransitionValue(transition, parameter).has_value())
                        continue;
                    const bool gate = std::any_of(transition.conditions.begin(),
                        transition.conditions.end(), [&](const Condition& condition) {
                            return condition.parameter == proof.gate_parameter &&
                                condition.mode == proof.gate_mode;
                        });
                    if (gate) settlements.insert(transition.destination);
                }
                if (settlements.size() > 1) continue;
                proof.terminal_state = settlements.empty()
                    ? node.state : *settlements.begin();
                result.push_back(std::move(proof));
                continue;
            }
            for (const auto& [value, transition] : edges) {
                Node next = node;
                next.state = transition->destination;
                next.values.push_back(value);
                next.transitions.push_back(transition);
                next.visited.insert(next.state);
                if (next.values.size() <= 32) pending.push_back(std::move(next));
            }
        }
    }

    std::sort(result.begin(), result.end(), [](const auto& left, const auto& right) {
        return std::tie(left.parameter, left.raw_values, left.numeric_endpoint,
            left.terminal_state) < std::tie(right.parameter, right.raw_values,
                right.numeric_endpoint, right.terminal_state);
    });
    result.erase(std::unique(result.begin(), result.end(), [](const auto& left,
        const auto& right) {
        return left.parameter == right.parameter &&
            left.raw_values == right.raw_values &&
            left.numeric_endpoint == right.numeric_endpoint &&
            left.terminal_state == right.terminal_state;
    }), result.end());
    return result;
}

std::map<std::string, double> RuntimeValuesForTerminal(
    const Snapshot& snapshot, const Controller& controller,
    const State& state) {
    std::map<std::string, double> values;
    for (const auto& [name, item] : controller.parameter_defaults)
        values[name] = item.value;
    for (const auto& [name, item] : snapshot.expression_parameter_defaults)
        values[name] = item.value;
    values["AvatarVersion"] = 3.0;
    for (const auto& write : state.writes)
        if (write.type == 0) values[write.name] = write.value;
    return values;
}

bool TerminalStableAfterWrites(const Snapshot& snapshot,
    const Controller& controller, const Machine& machine, int state_index) {
    if (state_index < 0 || state_index >= static_cast<int>(machine.states.size()))
        return false;
    const auto values = RuntimeValuesForTerminal(snapshot, controller,
        machine.states[static_cast<std::size_t>(state_index)]);
    for (const auto& transition : machine.states[static_cast<std::size_t>(state_index)].transitions) {
        if (transition.destination < 0 ||
            transition.destination >= static_cast<int>(machine.states.size()))
            return false;
        if (transition.destination == state_index) continue;
        bool enabled = true;
        for (const auto& condition : transition.conditions) {
            const auto match = ConditionMatches(condition, values);
            if (!match.has_value()) return false;
            if (!*match) { enabled = false; break; }
        }
        if (enabled) return false;
    }
    return true;
}

bool ParameterHasRuntimeEffect(const Snapshot& snapshot,
    const std::string& parameter) {
    for (const auto& controller : snapshot.controllers)
        for (const auto& machine : controller.machines)
            for (const auto& state : machine.states) {
                for (const auto& read : state.blend_parameter_reads)
                    if (read.parameter == parameter) return true;
                for (const auto& transition : state.transitions)
                    for (const auto& condition : transition.conditions)
                        if (condition.parameter == parameter) return true;
            }
    return false;
}

bool HasNumericEffectTerminal(const Snapshot& snapshot,
    const Controller& controller, const Machine& machine, int state_index) {
    if (!TerminalStableAfterWrites(snapshot, controller, machine, state_index))
        return false;
    const auto& state = machine.states[static_cast<std::size_t>(state_index)];
    std::set<std::string> set_outputs;
    bool changed = false;
    for (const auto& write : state.writes) {
        if (write.type != 0 || write.name.empty()) continue;
        set_outputs.insert(write.name);
        const auto* runtime_default = EffectiveRuntimeDefault(snapshot,
            controller, write.name);
        if (!runtime_default ||
            std::abs(runtime_default->value - write.value) > 1e-5)
            changed = true;
    }
    bool direct_effect = false;
    const auto check_animation = [&](const AnimationWrite& write) {
        const auto attribute = LowerAscii(write.name);
        return attribute.find("m_isactive") != std::string::npos ||
            attribute.find("m_enabled") != std::string::npos ||
            attribute.find("blendshape") != std::string::npos ||
            attribute.find("material") != std::string::npos ||
            attribute.find("renderer") != std::string::npos;
    };
    for (const auto& write : state.animation_writes)
        direct_effect |= check_animation(write);
    for (const auto& write : state.manual_activation_writes)
        direct_effect |= check_animation(write);
    bool consumed = false;
    for (const auto& output : set_outputs)
        consumed |= ParameterHasRuntimeEffect(snapshot, output);
    for (const auto& write : state.writes)
        if (write.type != 0 && !write.source.empty() &&
            set_outputs.count(write.source) != 0)
            consumed |= ParameterHasRuntimeEffect(snapshot, write.name);
    return changed && (direct_effect || consumed);
}

bool IsGateProducerTerminal(const Snapshot& snapshot,
    const Controller& controller, const Machine& machine, int state_index,
    const std::string& gate_parameter, int gate_mode) {
    if (!TerminalStableAfterWrites(snapshot, controller, machine, state_index))
        return false;
    const bool required = gate_mode == 1;
    const auto& state = machine.states[static_cast<std::size_t>(state_index)];
    int set_count = 0;
    bool gate_written = false;
    bool changed = false;
    for (const auto& write : state.writes) {
        if (write.type != 0 || write.name.empty()) continue;
        ++set_count;
        if (write.name == gate_parameter) {
            if (std::abs(write.value) > 1e-5 &&
                std::abs(write.value - 1.0) > 1e-5)
                return false;
            if ((write.value > 0.5) != required) return false;
            gate_written = true;
        }
        const auto* runtime_default = EffectiveRuntimeDefault(snapshot,
            controller, write.name);
        if (!runtime_default ||
            std::abs(runtime_default->value - write.value) > 1e-5)
            changed = true;
    }
    return gate_written && set_count >= 2 && changed;
}

struct ReachableNumericPageEvidence {
    std::string parameter;
    std::string menu_name;
    std::map<int, int> visible_to_raw;
    std::map<int, int> raw_to_visible;
};

struct NoResetSynchronizingEvidence {
    std::string parameter;
    std::string latch_parameter;
    int success_state = -1;
    bool success_value = false;
    std::vector<int> raw_spine;
    std::vector<int> visible_spine;
    std::string menu_name;
    std::vector<std::string> guide_keys;
    std::vector<int> guide_values;
    std::set<int> reachable_states;
    std::map<int, std::map<int, int>> transition_table;
};

struct FailStopDualLatchEvidence {
    std::string parameter;
    std::string menu_name;
    std::string success_latch;
    std::string failure_latch;
    int success_state = -1;
    int failure_state = -1;
    std::vector<int> raw_spine;
    std::vector<int> visible_spine;
};

struct NoResetStep {
    int destination = -1;
    int transition_index = -1;
};

std::vector<ReachableNumericPageEvidence> ReachableNumericPages(
    const Snapshot& snapshot, const RuleProfile& rules) {
    std::vector<ReachableNumericPageEvidence> result;
    if (snapshot.active_root_menu_ids.empty()) return result;

    std::map<std::string, const Menu*> menus;
    for (const auto& menu : snapshot.menus) {
        if (menu.id.empty() || !menus.emplace(menu.id, &menu).second)
            return {};
    }

    std::set<std::string> reachable;
    std::deque<std::string> queue;
    for (const auto& root_id : snapshot.active_root_menu_ids) {
        if (!menus.count(root_id)) return {};
        if (reachable.insert(root_id).second) queue.push_back(root_id);
    }
    while (!queue.empty()) {
        const std::string current = queue.front();
        queue.pop_front();
        for (const auto& control : menus.at(current)->controls) {
            if (control.type != 103 || control.submenu.empty()) continue;
            if (!menus.count(control.submenu)) return {};
            if (reachable.insert(control.submenu).second)
                queue.push_back(control.submenu);
        }
    }

    std::map<std::string, std::vector<ReachableNumericPageEvidence>> pages;
    std::set<std::string> invalid_parameters;
    const std::size_t minimum_keys = static_cast<std::size_t>(
        (std::max)(4, rules.menu_min_numeric_keys));
    for (const auto& menu_id : reachable) {
        const auto& menu = *menus.at(menu_id);
        std::map<std::string, std::vector<const MenuControl*>> groups;
        for (const auto& control : menu.controls)
            if (!control.parameter.empty())
                groups[control.parameter].push_back(&control);

        for (const auto& [parameter, controls] : groups) {
            ReachableNumericPageEvidence page;
            page.parameter = parameter;
            page.menu_name = EffectiveMenuGuideName(snapshot, menu);
            bool valid = controls.size() >= minimum_keys &&
                !page.menu_name.empty();
            for (const auto* control : controls) {
                const auto visible = VisibleSingleDigit(Trim(control->name));
                if (control->type != 101 || !visible.has_value() ||
                    *visible < 0 || *visible > rules.menu_max_digit ||
                    !std::isfinite(control->value) || control->value <= 0.0 ||
                    control->value > 65535.0 ||
                    std::abs(control->value - std::round(control->value)) > 1e-5) {
                    valid = false;
                    break;
                }
                const int raw = static_cast<int>(std::llround(control->value));
                if (raw == 0 || page.visible_to_raw.count(*visible) != 0 ||
                    page.raw_to_visible.count(raw) != 0) {
                    valid = false;
                    break;
                }
                page.visible_to_raw[*visible] = raw;
                page.raw_to_visible[raw] = *visible;
            }
            if (!valid || page.visible_to_raw.size() < minimum_keys) {
                invalid_parameters.insert(parameter);
                continue;
            }
            pages[parameter].push_back(std::move(page));
        }
    }

    for (auto& [parameter, parameter_pages] : pages) {
        // A second reachable page would make the operator guide ambiguous even
        // when its raw/visible map happened to be identical.  Fail closed.
        if (invalid_parameters.count(parameter) != 0 ||
            parameter_pages.size() != 1)
            continue;
        result.push_back(std::move(parameter_pages.front()));
    }
    return result;
}

std::optional<NoResetSynchronizingEvidence>
DetectNoResetSynchronizingLatch(const Snapshot& snapshot,
    const Controller& controller, std::size_t machine_index,
    const Machine& machine, const RuleProfile& rules,
    const std::vector<ReachableNumericPageEvidence>& numeric_pages) {
    (void)machine_index;
    if (snapshot.active_fx_controller_ids.empty() ||
        controller.path_id.empty() ||
        snapshot.active_fx_controller_ids.count(controller.path_id) == 0 ||
        machine.default_state < 0 ||
        machine.default_state >= static_cast<int>(machine.states.size()) ||
        machine.states.size() < 2 || !machine.any_transitions.empty())
        return std::nullopt;

    std::vector<NoResetSynchronizingEvidence> matches;
    constexpr double epsilon = 1e-5;

    for (const auto& page : numeric_pages) {
        const std::string& parameter = page.parameter;
        if (snapshot.expression_parameters.count(parameter) == 0) continue;
        const auto* input_default = EffectiveRuntimeDefault(
            snapshot, controller, parameter);
        if (!input_default || input_default->type != "int" ||
            !std::isfinite(input_default->value) ||
            std::abs(input_default->value) > epsilon)
            continue;

        std::set<int> alphabet;
        for (const auto& [raw, unused] : page.raw_to_visible) {
            (void)unused;
            alphabet.insert(raw);
        }
        if (alphabet.size() < static_cast<std::size_t>(
                (std::max)(4, rules.menu_min_numeric_keys)) ||
            alphabet.count(0) != 0)
            continue;
        std::set<int> domain = alphabet;
        domain.insert(0);

        bool valid_machine = true;
        for (const auto& state : machine.states) {
            for (const auto& transition : state.transitions) {
                if (transition.destination < 0 ||
                    transition.destination >= static_cast<int>(machine.states.size()) ||
                    transition.conditions.empty() || transition.has_exit_time ||
                    !std::isfinite(transition.exit_time) ||
                    !std::isfinite(transition.duration) ||
                    std::abs(transition.duration) > epsilon) {
                    valid_machine = false;
                    break;
                }
                for (const auto& condition : transition.conditions) {
                    if (condition.parameter != parameter ||
                        (condition.mode != 6 && condition.mode != 7) ||
                        !std::isfinite(condition.threshold) ||
                        std::abs(condition.threshold -
                            std::round(condition.threshold)) > epsilon ||
                        condition.threshold < -65535.0 ||
                        condition.threshold > 65535.0 ||
                        domain.count(static_cast<int>(
                            std::llround(condition.threshold))) == 0) {
                        valid_machine = false;
                        break;
                    }
                }
                if (!valid_machine) break;
            }
            if (!valid_machine) break;
        }
        if (!valid_machine) continue;

        std::vector<std::map<int, NoResetStep>> table(machine.states.size());
        for (std::size_t state_index = 0;
             state_index < machine.states.size() && valid_machine;
             ++state_index) {
            const auto& transitions = machine.states[state_index].transitions;
            for (int raw : domain) {
                NoResetStep step{static_cast<int>(state_index), -1};
                bool found = false;
                for (std::size_t transition_index = 0;
                     transition_index < transitions.size(); ++transition_index) {
                    const auto& transition = transitions[transition_index];
                    bool eligible = true;
                    for (const auto& condition : transition.conditions) {
                        const int threshold = static_cast<int>(
                            std::llround(condition.threshold));
                        const bool condition_true = condition.mode == 6
                            ? raw == threshold : raw != threshold;
                        if (!condition_true) {
                            eligible = false;
                            break;
                        }
                    }
                    if (!eligible) continue;
                    if (!found) {
                        found = true;
                        step.destination = transition.destination;
                        step.transition_index = static_cast<int>(transition_index);
                    } else if (step.destination != transition.destination) {
                        // Serialized priority alone is insufficient when two
                        // simultaneously eligible transitions have different
                        // observable destinations.
                        valid_machine = false;
                        break;
                    }
                }
                table[state_index][raw] = step;
                if (!valid_machine) break;
            }
        }
        if (!valid_machine) continue;

        std::set<int> reachable{machine.default_state};
        std::deque<int> pending{machine.default_state};
        while (!pending.empty()) {
            const int source = pending.front();
            pending.pop_front();
            for (int raw : domain) {
                const int destination = table[static_cast<std::size_t>(source)]
                    .at(raw).destination;
                if (reachable.insert(destination).second)
                    pending.push_back(destination);
            }
        }
        if (reachable.size() < 2) continue;
        bool zero_holds = true;
        for (int state : reachable)
            if (table[static_cast<std::size_t>(state)].at(0).destination != state) {
                zero_holds = false;
                break;
            }
        if (!zero_holds) continue;

        struct SuccessEvidence {
            int state = -1;
            std::string latch;
            bool value = false;
        };
        std::vector<SuccessEvidence> success_candidates;
        for (std::size_t state_index = 0;
             state_index < machine.states.size(); ++state_index) {
            const auto& state = machine.states[state_index];
            if (static_cast<int>(state_index) == machine.default_state ||
                !state.transitions.empty())
                continue;
            std::map<std::string, bool> changed_latches;
            bool conflicting_write = false;
            for (const auto& write : state.writes) {
                if (write.type != 0 || !std::isfinite(write.value) ||
                    (std::abs(write.value) > epsilon &&
                     std::abs(write.value - 1.0) > epsilon) ||
                    snapshot.expression_parameters.count(write.name) == 0 ||
                    snapshot.saved_expression_parameters.count(write.name) == 0)
                    continue;
                const auto* runtime_default = EffectiveRuntimeDefault(
                    snapshot, controller, write.name);
                if (!runtime_default || runtime_default->type != "bool" ||
                    !std::isfinite(runtime_default->value) ||
                    (std::abs(runtime_default->value) > epsilon &&
                     std::abs(runtime_default->value - 1.0) > epsilon) ||
                    ((runtime_default->value > 0.5) == (write.value > 0.5)))
                    continue;
                const bool value = write.value > 0.5;
                const auto inserted = changed_latches.emplace(write.name, value);
                if (!inserted.second && inserted.first->second != value)
                    conflicting_write = true;
            }
            if (!conflicting_write && changed_latches.size() == 1)
                success_candidates.push_back({static_cast<int>(state_index),
                    changed_latches.begin()->first,
                    changed_latches.begin()->second});
        }
        if (success_candidates.size() != 1) continue;
        const auto success = success_candidates.front();
        if (reachable.count(success.state) == 0) continue;

        bool latch_externally_writable =
            snapshot.contact_input_parameters.count(success.latch) != 0 ||
            snapshot.dynamic_contact_parameters.count(success.latch) != 0 ||
            snapshot.forced_contact_parameters.count(success.latch) != 0;
        for (const auto& menu : snapshot.menus) {
            for (const auto& control : menu.controls) {
                latch_externally_writable |= control.parameter == success.latch ||
                    std::find(control.sub_parameters.begin(),
                        control.sub_parameters.end(), success.latch) !=
                        control.sub_parameters.end();
            }
        }
        if (latch_externally_writable) continue;

        // A dead same-polarity writer is harmless only after structural
        // reachability from that machine's default state proves it unreachable.
        bool writer_audit_ok = true;
        for (const auto& other_controller : snapshot.controllers) {
            if (!snapshot.active_fx_controller_ids.count(
                    other_controller.path_id))
                continue;
            for (std::size_t other_machine_index = 0;
                 other_machine_index < other_controller.machines.size();
                 ++other_machine_index) {
                const auto& other_machine =
                    other_controller.machines[other_machine_index];
                bool has_latch_writer = false;
                for (const auto& state : other_machine.states) {
                    for (const auto& write : state.writes)
                        has_latch_writer |= write.name == success.latch;
                    for (const auto& write : state.animation_writes)
                        has_latch_writer |= write.name == success.latch;
                }
                if (!has_latch_writer) continue;
                if (other_machine.default_state < 0 ||
                    other_machine.default_state >= static_cast<int>(
                        other_machine.states.size())) {
                    writer_audit_ok = false;
                    break;
                }
                bool malformed = false;
                auto validate_destinations = [&](const std::vector<Transition>& transitions) {
                    for (const auto& transition : transitions)
                        if (transition.destination < 0 ||
                            transition.destination >= static_cast<int>(
                                other_machine.states.size()))
                            malformed = true;
                };
                validate_destinations(other_machine.any_transitions);
                for (const auto& state : other_machine.states)
                    validate_destinations(state.transitions);
                if (malformed) {
                    writer_audit_ok = false;
                    break;
                }
                std::set<int> structurally_reachable{
                    other_machine.default_state};
                std::deque<int> structural_pending{
                    other_machine.default_state};
                while (!structural_pending.empty()) {
                    const int source = structural_pending.front();
                    structural_pending.pop_front();
                    auto add_destinations = [&](const std::vector<Transition>& transitions) {
                        for (const auto& transition : transitions)
                            if (structurally_reachable.insert(
                                    transition.destination).second)
                                structural_pending.push_back(
                                    transition.destination);
                    };
                    add_destinations(other_machine.any_transitions);
                    add_destinations(other_machine.states[
                        static_cast<std::size_t>(source)].transitions);
                }
                for (int state_index : structurally_reachable) {
                    const auto& writer_state = other_machine.states[
                        static_cast<std::size_t>(state_index)];
                    for (const auto& write : writer_state.writes) {
                        if (write.name != success.latch) continue;
                        const bool exact_success_state =
                            &other_controller == &controller &&
                            other_machine_index == machine_index &&
                            state_index == success.state;
                        if (!exact_success_state || write.type != 0 ||
                            !std::isfinite(write.value) ||
                            ((write.value > 0.5) != success.value)) {
                            writer_audit_ok = false;
                            break;
                        }
                    }
                    if (std::any_of(writer_state.animation_writes.begin(),
                            writer_state.animation_writes.end(),
                            [&](const AnimationWrite& write) {
                                return write.name == success.latch;
                            }))
                        writer_audit_ok = false;
                    if (!writer_audit_ok) break;
                }
                if (!writer_audit_ok) break;
            }
            if (!writer_audit_ok) break;
        }
        if (!writer_audit_ok) continue;

        auto pure_equality_raw = [&](const Transition& transition)
            -> std::optional<int> {
            if (transition.conditions.size() != 1 || transition.has_exit_time ||
                std::abs(transition.duration) > epsilon)
                return std::nullopt;
            const auto& condition = transition.conditions.front();
            if (condition.parameter != parameter || condition.mode != 6 ||
                !std::isfinite(condition.threshold) ||
                std::abs(condition.threshold -
                    std::round(condition.threshold)) > epsilon)
                return std::nullopt;
            const int raw = static_cast<int>(
                std::llround(condition.threshold));
            return alphabet.count(raw) != 0
                ? std::optional<int>(raw) : std::nullopt;
        };

        struct SpineEdge { int source = -1; int destination = -1; int raw = 0; };
        std::vector<SpineEdge> reverse_spine;
        std::set<int> visited{success.state};
        int current = success.state;
        bool spine_ok = true;
        while (current != machine.default_state) {
            std::set<std::pair<int, int>> predecessors;
            for (std::size_t source = 0; source < machine.states.size(); ++source) {
                if (static_cast<int>(source) == current) continue;
                const auto& transitions = machine.states[source].transitions;
                for (const auto& transition : transitions) {
                    if (transition.destination != current) continue;
                    const auto raw = pure_equality_raw(transition);
                    if (!raw.has_value()) continue;
                    if (table[source].at(*raw).destination == current)
                        predecessors.insert({static_cast<int>(source), *raw});
                }
            }
            if (predecessors.size() != 1) {
                spine_ok = false;
                break;
            }
            const auto [source, raw] = *predecessors.begin();
            if (!visited.insert(source).second ||
                reverse_spine.size() >= static_cast<std::size_t>(
                    (std::max)(1, rules.max_path_depth))) {
                spine_ok = false;
                break;
            }
            reverse_spine.push_back({source, current, raw});
            current = source;
        }
        if (!spine_ok || reverse_spine.empty()) continue;
        std::reverse(reverse_spine.begin(), reverse_spine.end());
        if (reverse_spine.front().source != machine.default_state ||
            reverse_spine.back().destination != success.state)
            continue;

        // The success sink may only be entered through the final canonical
        // Equality edge.  A NotEqual shortcut is a different family.
        const auto& final_edge = reverse_spine.back();
        bool unique_success_entry = true;
        for (std::size_t source = 0; source < machine.states.size(); ++source) {
            for (const auto& transition : machine.states[source].transitions) {
                if (transition.destination != success.state) continue;
                const auto raw = pure_equality_raw(transition);
                if (static_cast<int>(source) != final_edge.source ||
                    !raw.has_value() || *raw != final_edge.raw) {
                    unique_success_entry = false;
                    break;
                }
            }
            if (!unique_success_entry) break;
        }
        if (!unique_success_entry) continue;

        int replay = machine.default_state;
        for (const auto& edge : reverse_spine) {
            if (replay != edge.source) {
                spine_ok = false;
                break;
            }
            replay = table[static_cast<std::size_t>(replay)]
                .at(edge.raw).destination;
            if (replay != edge.destination) {
                spine_ok = false;
                break;
            }
        }
        if (!spine_ok || replay != success.state) continue;

        std::vector<int> raw_spine;
        std::vector<int> visible_spine;
        for (const auto& edge : reverse_spine) {
            const auto visible = page.raw_to_visible.find(edge.raw);
            if (visible == page.raw_to_visible.end()) {
                spine_ok = false;
                break;
            }
            raw_spine.push_back(edge.raw);
            visible_spine.push_back(visible->second);
        }
        if (!spine_ok) continue;

        for (int start : reachable) {
            if (start == success.state) continue;
            int state = start;
            for (int raw : raw_spine)
                state = table[static_cast<std::size_t>(state)]
                    .at(raw).destination;
            if (state != success.state) {
                spine_ok = false;
                break;
            }
        }
        if (!spine_ok) continue;

        for (int source : reachable) {
            if (source == success.state) continue;
            for (int raw : alphabet) {
                const auto step = table[static_cast<std::size_t>(source)].at(raw);
                if (reachable.count(step.destination) == 0 ||
                    (step.destination == success.state &&
                     (source != final_edge.source || raw != final_edge.raw))) {
                    spine_ok = false;
                    break;
                }
            }
            if (!spine_ok) break;
        }
        if (!spine_ok) continue;

        NoResetSynchronizingEvidence evidence;
        evidence.parameter = parameter;
        evidence.latch_parameter = success.latch;
        evidence.success_state = success.state;
        evidence.success_value = success.value;
        evidence.raw_spine = std::move(raw_spine);
        evidence.visible_spine = std::move(visible_spine);
        evidence.menu_name = page.menu_name;
        evidence.reachable_states = std::move(reachable);
        for (std::size_t state_index = 0;
             state_index < table.size(); ++state_index)
            for (const auto& [raw, step] : table[state_index])
                evidence.transition_table[static_cast<int>(state_index)][raw] =
                    step.destination;
        for (std::size_t index = 0;
             index < evidence.visible_spine.size(); ++index) {
            evidence.guide_keys.push_back(
                VisibleDigitName(evidence.visible_spine[index]));
            evidence.guide_values.push_back(evidence.raw_spine[index]);
        }
        matches.push_back(std::move(evidence));
    }

    return matches.size() == 1
        ? std::optional<NoResetSynchronizingEvidence>(
            std::move(matches.front()))
        : std::nullopt;
}

std::optional<FailStopDualLatchEvidence>
DetectFailStopDualSavedLatch(const Snapshot& snapshot,
    const Controller& controller, std::size_t machine_index,
    const Machine& machine, const MenuMaps& menu_maps) {
    if (snapshot.active_fx_controller_ids.empty() ||
        controller.path_id.empty() ||
        snapshot.active_fx_controller_ids.count(controller.path_id) == 0 ||
        machine.default_state < 0 ||
        machine.default_state >= static_cast<int>(machine.states.size()) ||
        machine.states.size() < 6 || !machine.any_transitions.empty())
        return std::nullopt;

    constexpr double epsilon = 1e-5;
    const WriterCensus& census = BuildWriterCensus(controller);

    std::map<std::string, std::vector<std::pair<std::size_t, int>>>
        exact_set_writers;
    for (std::size_t owner_machine = 0;
         owner_machine < controller.machines.size(); ++owner_machine)
        for (std::size_t state_index = 0;
             state_index < controller.machines[owner_machine].states.size();
             ++state_index)
            for (const auto& write :
                 controller.machines[owner_machine].states[state_index].writes)
                if (write.type == 0 && !write.name.empty())
                    exact_set_writers[write.name].push_back(
                        {owner_machine, static_cast<int>(state_index)});

    auto externally_writable = [&](const std::string& parameter) {
        if (snapshot.contact_input_parameters.count(parameter) != 0 ||
            snapshot.dynamic_contact_parameters.count(parameter) != 0 ||
            snapshot.forced_contact_parameters.count(parameter) != 0)
            return true;
        for (const auto& menu : snapshot.menus)
            for (const auto& control : menu.controls) {
                if (control.parameter == parameter) return true;
                if (std::find(control.sub_parameters.begin(),
                        control.sub_parameters.end(), parameter) !=
                    control.sub_parameters.end()) return true;
            }
        return false;
    };

    struct StableLatch {
        std::string parameter;
        bool value = false;
    };
    std::map<int, StableLatch> stable_latches;
    for (std::size_t state_index = 0; state_index < machine.states.size();
         ++state_index) {
        const auto& state = machine.states[state_index];
        std::vector<const ParameterWrite*> qualifying;
        bool unsupported_write = !state.animation_writes.empty();
        for (const auto& write : state.writes) {
            if (write.type != 0 || !std::isfinite(write.value)) {
                unsupported_write = true;
                continue;
            }
            if (std::abs(write.value) > epsilon &&
                std::abs(write.value - 1.0) > epsilon)
                continue;
            if (snapshot.expression_parameters.count(write.name) == 0 ||
                snapshot.saved_expression_parameters.count(write.name) == 0)
                continue;
            const auto* runtime_default = EffectiveRuntimeDefault(
                snapshot, controller, write.name);
            if (!runtime_default || runtime_default->type != "bool" ||
                !std::isfinite(runtime_default->value) ||
                ((runtime_default->value > 0.5) == (write.value > 0.5)))
                continue;
            qualifying.push_back(&write);
        }
        if (unsupported_write || qualifying.size() != 1) continue;
        const auto& latch_write = *qualifying.front();
        if (state.writes.size() != 1 ||
            externally_writable(latch_write.name) ||
            exact_set_writers[latch_write.name].size() != 1 ||
            exact_set_writers[latch_write.name].front() !=
                std::make_pair(machine_index, static_cast<int>(state_index)) ||
            census.non_set_names.count(latch_write.name) != 0 ||
            census.animation_names.count(latch_write.name) != 0 ||
            HasActiveOtherControllerWriter(
                snapshot, controller, latch_write.name))
            continue;

        std::map<std::string, double> post_values{
            {latch_write.name, latch_write.value}};
        bool stable = true;
        for (const auto& transition : state.transitions) {
            if (transition.destination < 0 ||
                transition.destination >= static_cast<int>(machine.states.size())) {
                stable = false;
                break;
            }
            if (transition.destination == static_cast<int>(state_index))
                continue;
            bool disabled_by_latch = false;
            for (const auto& condition : transition.conditions) {
                if (condition.parameter != latch_write.name) continue;
                const auto outcome = ConditionMatches(condition, post_values);
                disabled_by_latch |= outcome.has_value() && !*outcome;
            }
            if (!disabled_by_latch) {
                stable = false;
                break;
            }
        }
        if (stable)
            stable_latches[static_cast<int>(state_index)] = {
                latch_write.name, latch_write.value > 0.5};
    }
    if (stable_latches.size() < 2) return std::nullopt;

    struct MatchKey {
        std::string parameter;
        int success = -1;
        int failure = -1;
        std::vector<int> raw;
        bool operator<(const MatchKey& other) const {
            return std::tie(parameter, success, failure, raw) <
                std::tie(other.parameter, other.success, other.failure,
                    other.raw);
        }
    };
    std::map<MatchKey, FailStopDualLatchEvidence> matches;

    for (const auto& [parameter, pages] : menu_maps) {
        if (snapshot.expression_parameters.count(parameter) == 0) continue;
        const auto* input_default = EffectiveRuntimeDefault(
            snapshot, controller, parameter);
        if (!input_default || input_default->type != "int" ||
            !std::isfinite(input_default->value) ||
            std::abs(input_default->value) > epsilon)
            continue;

        for (const auto& [menu_name, mapping] : pages) {
            if (mapping.size() < 4) continue;
            std::map<int, int> raw_to_visible;
            bool mapping_valid = true;
            for (const auto& [visible, entry] : mapping) {
                const auto inserted = raw_to_visible.emplace(
                    entry.raw_value, visible);
                if (!inserted.second && inserted.first->second != visible) {
                    mapping_valid = false;
                    break;
                }
            }
            if (!mapping_valid || raw_to_visible.size() < 4) continue;
            std::set<int> alphabet;
            for (const auto& [raw, unused] : raw_to_visible) {
                (void)unused;
                alphabet.insert(raw);
            }
            std::set<int> domain = alphabet;
            domain.insert(0);

            std::vector<std::map<int, int>> table(machine.states.size());
            bool table_valid = true;
            for (std::size_t source = 0;
                 source < machine.states.size() && table_valid; ++source) {
                if (stable_latches.count(static_cast<int>(source)) != 0) {
                    for (int raw : domain)
                        table[source][raw] = static_cast<int>(source);
                    continue;
                }
                const auto& transitions = machine.states[source].transitions;
                for (int raw : domain) {
                    int destination = static_cast<int>(source);
                    for (const auto& transition : transitions) {
                        if (transition.destination < 0 ||
                            transition.destination >=
                                static_cast<int>(machine.states.size()) ||
                            transition.conditions.empty() ||
                            transition.has_exit_time ||
                            !std::isfinite(transition.duration) ||
                            std::abs(transition.duration) > epsilon) {
                            table_valid = false;
                            break;
                        }
                        bool eligible = true;
                        for (const auto& condition : transition.conditions) {
                            if (condition.parameter != parameter ||
                                (condition.mode != 6 && condition.mode != 7) ||
                                !std::isfinite(condition.threshold) ||
                                std::abs(condition.threshold -
                                    std::round(condition.threshold)) > epsilon ||
                                domain.count(static_cast<int>(
                                    std::llround(condition.threshold))) == 0) {
                                table_valid = false;
                                break;
                            }
                            const int threshold = static_cast<int>(
                                std::llround(condition.threshold));
                            const bool condition_true = condition.mode == 6
                                ? raw == threshold : raw != threshold;
                            if (!condition_true) eligible = false;
                        }
                        if (!table_valid) break;
                        // Unity evaluates transitions in their serialized
                        // order.  This family deliberately places the exact
                        // Equality edge before an overlapping failure guard.
                        if (eligible) {
                            destination = transition.destination;
                            break;
                        }
                    }
                    if (!table_valid) break;
                    table[source][raw] = destination;
                }
            }
            if (!table_valid) continue;

            auto canonical_raw = [&](const Transition& transition)
                -> std::optional<int> {
                if (transition.has_exit_time ||
                    std::abs(transition.duration) > epsilon ||
                    transition.conditions.empty())
                    return std::nullopt;
                std::optional<int> equality;
                for (const auto& condition : transition.conditions) {
                    if (condition.parameter != parameter ||
                        !std::isfinite(condition.threshold) ||
                        std::abs(condition.threshold -
                            std::round(condition.threshold)) > epsilon)
                        return std::nullopt;
                    const int threshold = static_cast<int>(
                        std::llround(condition.threshold));
                    if (condition.mode == 6) {
                        if (equality.has_value()) return std::nullopt;
                        equality = threshold;
                    } else if (condition.mode != 7 || threshold != 0) {
                        return std::nullopt;
                    }
                }
                return equality.has_value() && alphabet.count(*equality) != 0
                    ? equality : std::nullopt;
            };

            struct SpineEdge {
                int source = -1;
                int destination = -1;
                int raw = 0;
            };
            for (const auto& [success_state, success_latch] : stable_latches) {
                std::vector<SpineEdge> reverse_spine;
                std::set<int> visited{success_state};
                int current = success_state;
                bool spine_ok = true;
                while (current != machine.default_state) {
                    std::set<std::pair<int, int>> predecessors;
                    for (std::size_t source = 0;
                         source < machine.states.size(); ++source) {
                        if (static_cast<int>(source) == current) continue;
                        for (const auto& transition :
                             machine.states[source].transitions) {
                            if (transition.destination != current) continue;
                            const auto raw = canonical_raw(transition);
                            if (raw.has_value() &&
                                table[source].at(*raw) == current)
                                predecessors.insert({
                                    static_cast<int>(source), *raw});
                        }
                    }
                    if (predecessors.size() != 1) {
                        spine_ok = false;
                        break;
                    }
                    const auto [source, raw] = *predecessors.begin();
                    if (!visited.insert(source).second ||
                        reverse_spine.size() >= 24) {
                        spine_ok = false;
                        break;
                    }
                    reverse_spine.push_back({source, current, raw});
                    current = source;
                }
                if (!spine_ok) continue;
                std::reverse(reverse_spine.begin(), reverse_spine.end());
                if (reverse_spine.size() < 4 ||
                    reverse_spine.front().source != machine.default_state ||
                    reverse_spine.back().destination != success_state)
                    continue;

                const auto& final_edge = reverse_spine.back();
                bool unique_success_entry = true;
                for (std::size_t source = 0;
                     source < machine.states.size(); ++source) {
                    if (static_cast<int>(source) == success_state) continue;
                    for (const auto& transition :
                         machine.states[source].transitions) {
                        if (transition.destination != success_state) continue;
                        const auto raw = canonical_raw(transition);
                        if (static_cast<int>(source) != final_edge.source ||
                            !raw.has_value() || *raw != final_edge.raw) {
                            unique_success_entry = false;
                            break;
                        }
                    }
                    if (!unique_success_entry) break;
                }
                if (!unique_success_entry) continue;

                int replay = machine.default_state;
                for (const auto& edge : reverse_spine) {
                    if (replay != edge.source ||
                        table[static_cast<std::size_t>(replay)].at(edge.raw) !=
                            edge.destination) {
                        spine_ok = false;
                        break;
                    }
                    replay = edge.destination;
                }
                if (!spine_ok || replay != success_state) continue;

                std::map<int, int> failure_votes;
                bool mismatch_safe = true;
                for (const auto& edge : reverse_spine) {
                    std::set<int> stable_destinations;
                    for (int raw : alphabet) {
                        if (raw == edge.raw) continue;
                        const int destination = table[static_cast<std::size_t>(
                            edge.source)].at(raw);
                        if (destination == success_state) {
                            mismatch_safe = false;
                            break;
                        }
                        if (destination != edge.source &&
                            stable_latches.count(destination) != 0)
                            stable_destinations.insert(destination);
                    }
                    if (!mismatch_safe || stable_destinations.size() != 1) {
                        mismatch_safe = false;
                        break;
                    }
                    ++failure_votes[*stable_destinations.begin()];
                }
                if (!mismatch_safe || failure_votes.size() != 1) continue;
                const auto [failure_state, votes] = *failure_votes.begin();
                if (votes != static_cast<int>(reverse_spine.size()) ||
                    failure_state == success_state ||
                    stable_latches.at(failure_state).parameter ==
                        success_latch.parameter)
                    continue;

                FailStopDualLatchEvidence evidence;
                evidence.parameter = parameter;
                evidence.menu_name = menu_name;
                evidence.success_latch = success_latch.parameter;
                evidence.failure_latch =
                    stable_latches.at(failure_state).parameter;
                evidence.success_state = success_state;
                evidence.failure_state = failure_state;
                for (const auto& edge : reverse_spine) {
                    const auto visible = raw_to_visible.find(edge.raw);
                    if (visible == raw_to_visible.end()) {
                        spine_ok = false;
                        break;
                    }
                    evidence.raw_spine.push_back(edge.raw);
                    evidence.visible_spine.push_back(visible->second);
                }
                if (!spine_ok) continue;
                MatchKey key{parameter, success_state, failure_state,
                    evidence.raw_spine};
                auto existing = matches.find(key);
                if (existing == matches.end() ||
                    (existing->second.menu_name.empty() &&
                     !evidence.menu_name.empty()))
                    matches[key] = std::move(evidence);
            }
        }
    }

    return matches.size() == 1
        ? std::optional<FailStopDualLatchEvidence>(
            std::move(matches.begin()->second))
        : std::nullopt;
}

std::optional<int> SingleLatchedParameterDriverTerminal(
    const Snapshot& snapshot, const Controller& controller,
    const Machine& machine) {
    // Some generated keypad families use one saved Boolean as the entire lock
    // latch.  Their success state writes the non-default value and deliberately
    // keeps a re-lock edge which can only become true after an external write.
    // Requiring a write-less sink therefore misses the real terminal.  Accept
    // this shape only when the latch is runtime-visible, consumed by several
    // independent machines, has one complementary failure/reset state, and the
    // success write itself makes every outgoing edge false.
    std::map<std::string, std::set<std::size_t>> consumer_machines;
    for (std::size_t machine_index = 0;
         machine_index < controller.machines.size(); ++machine_index) {
        const auto& consumer = controller.machines[machine_index];
        auto collect = [&](const std::vector<Transition>& transitions) {
            for (const auto& transition : transitions)
                for (const auto& condition : transition.conditions)
                    if (!condition.parameter.empty())
                        consumer_machines[condition.parameter].insert(machine_index);
        };
        for (const auto& state : consumer.states) collect(state.transitions);
        collect(consumer.any_transitions);
    }

    auto condition_matches = [](const Condition& condition, double value)
        -> std::optional<bool> {
        switch (condition.mode) {
        case 1: return value > 0.5;
        case 2: return value <= 0.5;
        case 3: return value > condition.threshold;
        case 4: return value < condition.threshold;
        case 6: return std::abs(value - condition.threshold) <= 1e-5;
        case 7: return std::abs(value - condition.threshold) > 1e-5;
        default: return std::nullopt;
        }
    };

    std::vector<int> matches;
    for (std::size_t success_index = 0; success_index < machine.states.size();
         ++success_index) {
        if (!machine.any_transitions.empty()) continue;
        const auto& success = machine.states[success_index];
        // The lock latch may share its terminal state with an unrelated float
        // or bookkeeping write.  Select exactly one saved expression Boolean
        // whose terminal value differs from its runtime default; do not require
        // that it be the only ParameterDriver operation in the state.
        std::vector<const ParameterWrite*> qualifying_latches;
        for (const auto& write : success.writes) {
            if (write.type != 0 ||
                (std::abs(write.value) > 1e-5 &&
                 std::abs(write.value - 1.0) > 1e-5) ||
                snapshot.expression_parameters.count(write.name) == 0)
                continue;
            const auto* runtime_default = EffectiveRuntimeDefault(
                snapshot, controller, write.name);
            if (runtime_default && runtime_default->type == "bool" &&
                std::abs(runtime_default->value - write.value) > 1e-5)
                qualifying_latches.push_back(&write);
        }
        if (qualifying_latches.size() != 1) continue;
        const auto& success_write = *qualifying_latches.front();
        const auto* effective_default = EffectiveRuntimeDefault(
            snapshot, controller, success_write.name);
        if (!effective_default) continue;
        const auto consumers = consumer_machines.find(success_write.name);
        // Some explicit Wait_Digit generators keep the saved lock latch inside
        // the keypad machine itself.  They do not have three independent
        // downstream consumers, but the serialized Unlocked terminal is still
        // strong evidence when every other single-latch safeguard below also
        // holds (self-stabilizing write, unique opposite state, many failure
        // inputs, and a deterministic reset path).  Preserve the stricter
        // consumer threshold for anonymous/obfuscated terminals.
        const bool explicitly_named_unlock = IsUnlockStateName(success.name);
        if ((consumers == consumer_machines.end() ||
             consumers->second.size() < 3) && !explicitly_named_unlock)
            continue;

        bool write_stabilizes_terminal = true;
        for (const auto& transition : success.transitions) {
            if (transition.destination < 0 ||
                transition.destination >= static_cast<int>(machine.states.size()))
                continue;
            bool blocked_by_latch_write = false;
            for (const auto& condition : transition.conditions) {
                if (condition.parameter != success_write.name) continue;
                const auto matches_written_value =
                    condition_matches(condition, success_write.value);
                if (matches_written_value.has_value() && !*matches_written_value)
                    blocked_by_latch_write = true;
            }
            if (!blocked_by_latch_write) write_stabilizes_terminal = false;
        }
        // A sink is already stable.  If concrete outgoing edges exist, every
        // one must be disabled by the saved latch value written on entry.
        if (!write_stabilizes_terminal) continue;

        int opposite_state = -1;
        for (std::size_t state_index = 0; state_index < machine.states.size();
             ++state_index) {
            if (state_index == success_index) continue;
            for (const auto& write : machine.states[state_index].writes) {
                if (write.type == 0 && write.name == success_write.name &&
                    std::abs(write.value - (1.0 - success_write.value)) <= 1e-5) {
                    if (opposite_state >= 0) opposite_state = -2;
                    else opposite_state = static_cast<int>(state_index);
                    break;
                }
            }
        }
        if (opposite_state < 0) continue;

        int reset_incoming_states = 0;
        int success_incoming_states = 0;
        for (std::size_t state_index = 0; state_index < machine.states.size();
             ++state_index) {
            bool reaches_reset = false;
            bool reaches_success = false;
            for (const auto& transition : machine.states[state_index].transitions) {
                reaches_reset |= transition.destination == opposite_state &&
                    !transition.conditions.empty();
                reaches_success |= transition.destination ==
                    static_cast<int>(success_index) &&
                    !transition.conditions.empty();
            }
            reset_incoming_states += reaches_reset ? 1 : 0;
            success_incoming_states += reaches_success ? 1 : 0;
        }
        const auto& reset = machine.states[static_cast<std::size_t>(opposite_state)];
        const bool reset_can_return_on_other_input = std::any_of(
            reset.transitions.begin(), reset.transitions.end(),
            [&](const Transition& transition) {
                return transition.destination >= 0 &&
                    transition.destination < static_cast<int>(machine.states.size()) &&
                    std::any_of(transition.conditions.begin(),
                        transition.conditions.end(), [&](const Condition& condition) {
                            return !condition.parameter.empty() &&
                                condition.parameter != success_write.name;
                        });
            });
        if (reset_incoming_states < 3 || success_incoming_states < 1 ||
            !reset_can_return_on_other_input) continue;
        matches.push_back(static_cast<int>(success_index));
    }
    std::sort(matches.begin(), matches.end());
    matches.erase(std::unique(matches.begin(), matches.end()), matches.end());
    return matches.size() == 1 ? std::optional<int>(matches.front()) : std::nullopt;
}

std::optional<int> MonotonicSavedUnlockTerminal(
    const Snapshot& snapshot, const Controller& controller,
    const Machine& machine) {
    // Some older keypad generators never emit a complementary re-lock writer.
    // Their only success action is a one-way write to a saved Boolean which is
    // then consumed by several independent feature machines.  Treating an
    // arbitrary leaf as success is unsafe; instead require one unique writer,
    // a runtime-default polarity flip, a stable terminal, and broad downstream
    // consumption of the written polarity.  The caller still has to prove the
    // complete menu-backed numeric path to this exact state.
    std::map<std::string, std::set<std::size_t>> polarity_consumers;
    std::map<std::string, int> condition_counts;
    for (std::size_t machine_index = 0;
         machine_index < controller.machines.size(); ++machine_index) {
        const auto& consumer = controller.machines[machine_index];
        auto collect = [&](const std::vector<Transition>& transitions) {
            for (const auto& transition : transitions) {
                for (const auto& condition : transition.conditions) {
                    if (condition.parameter.empty()) continue;
                    ++condition_counts[condition.parameter];
                    if (condition.mode == 1 || condition.mode == 2)
                        polarity_consumers[condition.parameter].insert(
                            machine_index);
                }
            }
        };
        for (const auto& state : consumer.states) collect(state.transitions);
        collect(consumer.any_transitions);
    }

    std::map<std::string, int> writer_counts;
    for (const auto& candidate_machine : controller.machines)
        for (const auto& state : candidate_machine.states)
            for (const auto& write : state.writes)
                if (write.type == 0 && !write.name.empty())
                    ++writer_counts[write.name];

    auto condition_matches = [](const Condition& condition, double value)
        -> std::optional<bool> {
        switch (condition.mode) {
        case 1: return value > 0.5;
        case 2: return value <= 0.5;
        case 3: return value > condition.threshold;
        case 4: return value < condition.threshold;
        case 6: return std::abs(value - condition.threshold) <= 1e-5;
        case 7: return std::abs(value - condition.threshold) > 1e-5;
        default: return std::nullopt;
        }
    };

    std::vector<int> matches;
    for (std::size_t state_index = 0; state_index < machine.states.size();
         ++state_index) {
        if (static_cast<int>(state_index) == machine.default_state) continue;
        const auto& state = machine.states[state_index];
        for (const auto& write : state.writes) {
            if (write.type != 0 ||
                (std::abs(write.value) > 1e-5 &&
                 std::abs(write.value - 1.0) > 1e-5) ||
                snapshot.saved_expression_parameters.count(write.name) == 0 ||
                writer_counts[write.name] != 1)
                continue;
            const auto* runtime_default = EffectiveRuntimeDefault(
                snapshot, controller, write.name);
            if (!runtime_default || runtime_default->type != "bool" ||
                std::abs(runtime_default->value - write.value) <= 1e-5)
                continue;

            const auto consumers = polarity_consumers.find(write.name);
            if (consumers == polarity_consumers.end() ||
                consumers->second.size() < 3 ||
                condition_counts[write.name] < 5)
                continue;

            // At least three independent machines must actually consume the
            // polarity written by this state, not merely mention the latch.
            std::set<std::size_t> matching_consumers;
            for (std::size_t consumer_index = 0;
                 consumer_index < controller.machines.size(); ++consumer_index) {
                const auto& consumer = controller.machines[consumer_index];
                auto scan = [&](const std::vector<Transition>& transitions) {
                    for (const auto& transition : transitions)
                        for (const auto& condition : transition.conditions)
                            if (condition.parameter == write.name) {
                                const auto result = condition_matches(
                                    condition, write.value);
                                if (result.has_value() && *result)
                                    matching_consumers.insert(consumer_index);
                            }
                };
                for (const auto& consumer_state : consumer.states)
                    scan(consumer_state.transitions);
                scan(consumer.any_transitions);
            }
            if (matching_consumers.size() < 3) continue;

            // A sink is stable.  Otherwise every concrete outgoing edge must
            // be disabled by the value written on entry.
            bool stable = true;
            for (const auto& transition : state.transitions) {
                if (transition.destination < 0 ||
                    transition.destination >= static_cast<int>(machine.states.size())) {
                    stable = false;
                    break;
                }
                bool disabled_by_write = false;
                for (const auto& condition : transition.conditions) {
                    if (condition.parameter != write.name) continue;
                    const auto result = condition_matches(condition, write.value);
                    if (result.has_value() && !*result)
                        disabled_by_write = true;
                }
                if (!disabled_by_write) {
                    stable = false;
                    break;
                }
            }
            if (stable) matches.push_back(static_cast<int>(state_index));
        }
    }
    std::sort(matches.begin(), matches.end());
    matches.erase(std::unique(matches.begin(), matches.end()), matches.end());
    return matches.size() == 1 ? std::optional<int>(matches.front())
                               : std::nullopt;
}

std::optional<int> ComplementaryParameterDriverTerminal(
    const Snapshot& snapshot, const Controller& controller,
    const Machine& machine) {
    // Generated Kanna/KannaProtecc locks keep their success flags internal to
    // the FX controller.  They are deliberately absent from expression
    // parameters, but are still consumed by many downstream transitions.  A
    // sink state with at least two writes that are complemented by another
    // state, plus a concretely consumed Boolean, is a stronger success signal
    // than the parameter being user-visible.  Keep the old expression-
    // parameter path for generators that expose their flags directly.
    std::map<std::string, int> condition_consumers;
    for (const auto& consumer_machine : controller.machines) {
        auto count = [&](const std::vector<Transition>& transitions) {
            for (const auto& transition : transitions)
                for (const auto& condition : transition.conditions)
                    if (!condition.parameter.empty())
                        ++condition_consumers[condition.parameter];
        };
        for (const auto& state : consumer_machine.states)
            count(state.transitions);
        count(consumer_machine.any_transitions);
    }

    std::vector<int> matches;
    for (std::size_t success_index = 0; success_index < machine.states.size();
         ++success_index) {
        const auto& success = machine.states[success_index];
        if (success.writes.size() < 2) continue;
        bool has_expression_parameter = false;
        for (const auto& write : success.writes)
            has_expression_parameter |= snapshot.expression_parameters.count(write.name) != 0;

        // A ParameterDriver state can be a stable terminal even when Unity
        // serialized a concrete outgoing edge.  Accept that edge only when
        // one of its conjunctive conditions is deterministically false after
        // this state's own Set writes have run.  Unconditional, unknown, or
        // still-true edges remain unsafe and reject the terminal.
        std::map<std::string, double> deterministic_writes;
        std::set<std::string> conflicting_writes;
        for (const auto& write : success.writes) {
            if (write.type != 0 || write.name.empty()) continue;
            const auto inserted = deterministic_writes.emplace(
                write.name, write.value);
            if (!inserted.second &&
                std::abs(inserted.first->second - write.value) > 1e-5) {
                deterministic_writes.erase(write.name);
                conflicting_writes.insert(write.name);
            }
        }
        auto condition_matches = [](const Condition& condition,
                                     double value) -> std::optional<bool> {
            switch (condition.mode) {
            case 1: return value > 0.5;
            case 2: return value <= 0.5;
            case 3: return value > condition.threshold;
            case 4: return value < condition.threshold;
            case 6: return std::abs(value - condition.threshold) <= 1e-5;
            case 7: return std::abs(value - condition.threshold) > 1e-5;
            default: return std::nullopt;
            }
        };
        bool stable_terminal = true;
        for (const auto& transition : success.transitions) {
            if (transition.destination < 0 ||
                transition.destination >= static_cast<int>(machine.states.size())) {
                stable_terminal = false;
                break;
            }
            bool disabled_by_own_write = false;
            for (const auto& condition : transition.conditions) {
                if (conflicting_writes.count(condition.parameter) != 0)
                    continue;
                const auto written = deterministic_writes.find(
                    condition.parameter);
                if (written == deterministic_writes.end()) continue;
                const auto matches = condition_matches(
                    condition, written->second);
                if (matches.has_value() && !*matches) {
                    disabled_by_own_write = true;
                    break;
                }
            }
            if (!disabled_by_own_write) {
                stable_terminal = false;
                break;
            }
        }
        if (!stable_terminal) continue;

        bool has_opposite_state = false;
        bool has_consumed_internal_complement = false;
        for (std::size_t failure_index = 0; failure_index < machine.states.size();
             ++failure_index) {
            if (failure_index == success_index) continue;
            int opposite = 0;
            int consumed_opposites = 0;
            for (const auto& success_write : success.writes) {
                if (success_write.type != 0 ||
                    (std::abs(success_write.value) > 1e-5 &&
                     std::abs(success_write.value - 1.0) > 1e-5)) continue;
                for (const auto& failure_write : machine.states[failure_index].writes) {
                    if (failure_write.name == success_write.name &&
                        failure_write.type == 0 &&
                        std::abs(failure_write.value - (1.0 - success_write.value)) <= 1e-5) {
                        ++opposite;
                        if (condition_consumers[success_write.name] >= 2)
                            ++consumed_opposites;
                        break;
                    }
                }
            }
            if (opposite >= 2) {
                has_opposite_state = true;
                has_consumed_internal_complement |= consumed_opposites >= 1;
                break;
            }
        }
        if (!has_opposite_state) continue;

        const bool internal_semantic_terminal =
            !has_expression_parameter &&
            has_consumed_internal_complement;
        if (!has_expression_parameter && !internal_semantic_terminal) continue;

        bool unlock_polarity = internal_semantic_terminal ||
            IsUnlockStateName(success.name);
        for (const auto& write : success.writes) {
            const auto found = controller.parameter_defaults.find(write.name);
            if (found == controller.parameter_defaults.end()) continue;
            // Internal generators commonly use a Float pulse for the restored
            // state and a Boolean for the failure latch.  The write operation
            // type does not describe the Animator parameter type, so compare
            // against the controller's typed default for every numeric kind.
            if (std::abs(found->second.value - write.value) > 1e-5)
                unlock_polarity = true;
        }
        if (unlock_polarity) matches.push_back(static_cast<int>(success_index));
    }
    std::sort(matches.begin(), matches.end());
    matches.erase(std::unique(matches.begin(), matches.end()), matches.end());
    if (matches.size() == 1) return matches.front();
    if (!matches.empty()) return std::nullopt;
    return SingleLatchedParameterDriverTerminal(snapshot, controller, machine);
}

struct DynamicContactTerminalEvidence {
    int success_state = -1;
    int failure_state = -1;
    std::string guard_parameter;
    bool ready_guard_value = false;
    std::size_t producer_machine = static_cast<std::size_t>(-1);
    int producer_ready_state = -1;
    int producer_failure_state = -1;
};

struct HiddenReceiverPulseEvidence {
    std::size_t producer_machine = static_cast<std::size_t>(-1);
    int ready_state = -1;
    int retry_state = -1;
    int success_state = -1;
    std::string guard_parameter;
    bool ready_guard_value = false;
};

std::optional<DynamicContactTerminalEvidence>
DynamicContactStabilizedTerminal(
    const Snapshot& snapshot, const Controller& controller,
    std::size_t keypad_machine_index, const Machine& keypad_machine,
    const std::string& keypad_parameter) {
    if (keypad_parameter.empty() || keypad_machine_index >= controller.machines.size() ||
        keypad_machine.default_state < 0 ||
        keypad_machine.default_state >= static_cast<int>(keypad_machine.states.size()))
        return std::nullopt;

    const auto condition_matches_value = [](const Condition& condition,
                                             double value)
        -> std::optional<bool> {
        switch (condition.mode) {
        case 1: return value > 0.5;
        case 2: return value <= 0.5;
        case 3: return value > condition.threshold;
        case 4: return value < condition.threshold;
        case 6: return std::abs(value - condition.threshold) <= 1e-5;
        case 7: return std::abs(value - condition.threshold) > 1e-5;
        default: return std::nullopt;
        }
    };
    const auto concrete_transition = [](const Transition& transition,
                                        std::size_t state_count) {
        return transition.destination >= 0 &&
            transition.destination < static_cast<int>(state_count);
    };

    // The external guard must dominate the visible digit edges.  Requiring a
    // single 3:1 Bool polarity prevents ordinary feature buses with occasional
    // auxiliary conditions from being treated as Contact locks.
    std::map<std::string, std::array<int, 2>> guard_votes;
    for (const auto& state : keypad_machine.states) {
        for (const auto& transition : state.transitions) {
            int keypad_equalities = 0;
            for (const auto& condition : transition.conditions) {
                if (condition.parameter != keypad_parameter ||
                    condition.mode != 6 || condition.threshold < 0.0 ||
                    condition.threshold > 19.0) continue;
                const int rounded = static_cast<int>(
                    std::llround(condition.threshold));
                if (std::abs(condition.threshold - rounded) <= 1e-5)
                    ++keypad_equalities;
            }
            if (keypad_equalities != 1) continue;
            for (const auto& condition : transition.conditions) {
                if (condition.parameter.empty() ||
                    condition.parameter == keypad_parameter ||
                    (condition.mode != 1 && condition.mode != 2)) continue;
                ++guard_votes[condition.parameter][
                    condition.mode == 1 ? 1 : 0];
            }
        }
    }

    std::set<std::string> externally_mutable = snapshot.expression_parameters;
    externally_mutable.insert(snapshot.contact_input_parameters.begin(),
        snapshot.contact_input_parameters.end());
    externally_mutable.insert(snapshot.dynamic_contact_parameters.begin(),
        snapshot.dynamic_contact_parameters.end());
    externally_mutable.insert(snapshot.forced_contact_parameters.begin(),
        snapshot.forced_contact_parameters.end());
    for (const auto& menu : snapshot.menus) {
        for (const auto& control : menu.controls) {
            if (!control.parameter.empty())
                externally_mutable.insert(control.parameter);
            externally_mutable.insert(control.sub_parameters.begin(),
                control.sub_parameters.end());
        }
    }

    std::vector<std::pair<std::string, bool>> dominant_guards;
    for (const auto& [guard, votes] : guard_votes) {
        std::optional<bool> required;
        if (votes[0] >= 3 && votes[0] >= votes[1] * 3)
            required = false;
        else if (votes[1] >= 3 && votes[1] >= votes[0] * 3)
            required = true;
        const auto guard_default = controller.parameter_defaults.find(guard);
        if (!required.has_value() || externally_mutable.count(guard) != 0 ||
            guard_default == controller.parameter_defaults.end() ||
            guard_default->second.type != "bool")
            continue;
        dominant_guards.push_back({guard, *required});
    }
    if (dominant_guards.size() != 1) return std::nullopt;
    const auto& guard = dominant_guards.front().first;
    const bool ready_guard_value = dominant_guards.front().second;

    const auto& census = BuildWriterCensus(controller);
    const auto& writers = census.set_owners;
    const auto guard_writers = writers.find(guard);
    if (guard_writers == writers.end() || guard_writers->second.size() != 1)
        return std::nullopt;
    if (census.non_set_names.count(guard) != 0 ||
        census.animation_names.count(guard) != 0 ||
        HasActiveOtherControllerWriter(snapshot, controller, guard))
        return std::nullopt;
    const std::size_t producer_index = *guard_writers->second.begin();
    if (producer_index == keypad_machine_index ||
        producer_index >= controller.machines.size())
        return std::nullopt;
    const auto& producer = controller.machines[producer_index];
    if (producer.default_state < 0 ||
        producer.default_state >= static_cast<int>(producer.states.size()))
        return std::nullopt;

    std::set<std::string> contact_dependencies;
    bool fixed_contact_dependency = false;
    auto scan_dependencies = [&](const std::vector<Transition>& transitions) {
        for (const auto& transition : transitions) {
            for (const auto& condition : transition.conditions) {
                if (snapshot.dynamic_contact_parameters.count(
                        condition.parameter) != 0 ||
                    snapshot.contact_input_parameters.count(
                        condition.parameter) != 0)
                    contact_dependencies.insert(condition.parameter);
                if (snapshot.forced_contact_parameters.count(
                        condition.parameter) != 0)
                    fixed_contact_dependency = true;
            }
        }
    };
    scan_dependencies(producer.any_transitions);
    for (const auto& state : producer.states)
        scan_dependencies(state.transitions);
    if (fixed_contact_dependency || contact_dependencies.size() != 1)
        return std::nullopt;
    const std::string contact_parameter = *contact_dependencies.begin();

    // AnyState edges would also remain active while parked in a sink.  This
    // family proof deliberately rejects them instead of assuming an ordering
    // or polarity that the normalized graph did not prove.
    if (!producer.any_transitions.empty())
        return std::nullopt;

    auto stable_sink = [&](const State& state) {
        // Unknown destinations are not proof of a sink.  The normalized graph
        // must contain no outgoing edge at all for a permanent producer state.
        return state.transitions.empty();
    };
    auto bool_write = [&](const State& state, const std::string& parameter)
        -> std::optional<bool> {
        std::optional<bool> value;
        for (const auto& write : state.writes) {
            if (write.type != 0 || write.name != parameter ||
                (std::abs(write.value) > 1e-5 &&
                 std::abs(write.value - 1.0) > 1e-5))
                continue;
            const bool current = write.value > 0.5;
            if (value.has_value() && *value != current) return std::nullopt;
            value = current;
        }
        return value;
    };

    std::vector<int> ready_states;
    std::vector<int> producer_failure_states;
    for (std::size_t state_index = 0; state_index < producer.states.size();
         ++state_index) {
        const auto& state = producer.states[state_index];
        if (!stable_sink(state)) continue;
        const auto value = bool_write(state, guard);
        if (!value.has_value()) continue;
        if (*value == ready_guard_value)
            ready_states.push_back(static_cast<int>(state_index));
        else
            producer_failure_states.push_back(static_cast<int>(state_index));
    }
    if (ready_states.size() != 1 || producer_failure_states.size() != 1 ||
        ready_states.front() == producer.default_state)
        return std::nullopt;
    const int ready_state = ready_states.front();
    const int producer_failure_state = producer_failure_states.front();

    struct ContactSimulation {
        int sink = -1;
        bool used_high_only_edge = false;
        bool used_low_only_edge = false;
    };
    const auto simulate_contact = [&](int high_steps)
        -> std::optional<ContactSimulation> {
        std::map<std::string, double> values;
        for (const auto& [name, item] : controller.parameter_defaults)
            values[name] = item.value;
        for (const auto& [name, item] : snapshot.expression_parameter_defaults)
            values[name] = item.value;
        values["AvatarVersion"] = 3.0;
        int state_index = producer.default_state;
        bool used_high_only_edge = false;
        bool used_low_only_edge = false;
        std::set<std::pair<int, bool>> seen;
        const int step_limit = std::max<int>(32,
            static_cast<int>(producer.states.size()) * 4);
        for (int step = 0; step < step_limit; ++step) {
            if (state_index < 0 ||
                state_index >= static_cast<int>(producer.states.size()))
                return std::nullopt;
            const bool contact_high = high_steps < 0 || step < high_steps;
            if (!seen.insert({state_index, contact_high}).second)
                return std::nullopt;
            const auto& state = producer.states[
                static_cast<std::size_t>(state_index)];
            for (const auto& write : state.writes)
                if (write.type == 0) values[write.name] = write.value;

            auto enabled_with_contact = [&](const Transition& transition,
                                             bool high)
                -> std::optional<bool> {
                auto evaluated = values;
                evaluated[contact_parameter] = high ? 1.0 : 0.0;
                for (const auto& condition : transition.conditions) {
                    const auto matches = ConditionMatches(condition, evaluated);
                    if (!matches.has_value()) return std::nullopt;
                    if (!*matches) return false;
                }
                return true;
            };

            const Transition* selected = nullptr;
            bool selected_high_only = false;
            bool selected_low_only = false;
            for (const auto& transition : state.transitions) {
                const auto enabled = enabled_with_contact(
                    transition, contact_high);
                if (!enabled.has_value()) return std::nullopt;
                if (!*enabled) continue;
                const auto opposite = enabled_with_contact(
                    transition, !contact_high);
                if (!opposite.has_value()) return std::nullopt;
                selected = &transition;
                selected_high_only = contact_high && !*opposite;
                selected_low_only = !contact_high && !*opposite;
                break;
            }
            if (!selected)
                return ContactSimulation{state_index, used_high_only_edge,
                    used_low_only_edge};
            if (!concrete_transition(*selected, producer.states.size()))
                return std::nullopt;
            used_high_only_edge |= selected_high_only;
            used_low_only_edge |= selected_low_only;
            state_index = selected->destination;
        }
        return std::nullopt;
    };

    const auto constant_low = simulate_contact(0);
    const auto constant_high = simulate_contact(-1);
    if (!constant_low.has_value() || !constant_high.has_value() ||
        constant_low->sink != producer_failure_state ||
        constant_high->sink != producer_failure_state)
        return std::nullopt;
    bool high_then_low_reaches_ready = false;
    const int pulse_limit = std::max<int>(16,
        static_cast<int>(producer.states.size()) * 2);
    for (int high_steps = 1; high_steps < pulse_limit; ++high_steps) {
        const auto pulse = simulate_contact(high_steps);
        if (pulse.has_value() && pulse->sink == ready_state &&
            pulse->used_high_only_edge && pulse->used_low_only_edge) {
            high_then_low_reaches_ready = true;
            break;
        }
    }
    if (!high_then_low_reaches_ready) return std::nullopt;

    std::vector<DynamicContactTerminalEvidence> matches;
    for (std::size_t success_index = 0;
         success_index < keypad_machine.states.size(); ++success_index) {
        if (static_cast<int>(success_index) == keypad_machine.default_state)
            continue;
        const auto& success = keypad_machine.states[success_index];
        std::map<std::string, double> success_writes;
        bool has_saved_latch = false;
        bool conflicting_success_write = false;
        for (const auto& write : success.writes) {
            if (write.type != 0 ||
                (std::abs(write.value) > 1e-5 &&
                 std::abs(write.value - 1.0) > 1e-5) ||
                snapshot.expression_parameters.count(write.name) == 0)
                continue;
            const auto* runtime_default = EffectiveRuntimeDefault(
                snapshot, controller, write.name);
            if (!runtime_default || runtime_default->type != "bool" ||
                (runtime_default->value > 0.5) == (write.value > 0.5))
                continue;
            const auto inserted = success_writes.emplace(
                write.name, write.value);
            if (!inserted.second &&
                std::abs(inserted.first->second - write.value) > 1e-5)
                conflicting_success_write = true;
            has_saved_latch |= snapshot.saved_expression_parameters.count(
                write.name) != 0;
        }
        if (conflicting_success_write || success_writes.size() < 2 ||
            !has_saved_latch)
            continue;
        bool unsafe_success_writer = false;
        for (const auto& [name, unused] : success_writes) {
            (void)unused;
            unsafe_success_writer |= census.non_set_names.count(name) != 0 ||
                census.animation_names.count(name) != 0 ||
                HasActiveOtherControllerWriter(snapshot, controller, name);
        }
        if (unsafe_success_writer) continue;

        auto writes_complements = [&](const State& state) {
            for (const auto& [name, value] : success_writes) {
                bool complemented = false;
                for (const auto& write : state.writes) {
                    if (write.type == 0 && write.name == name &&
                        std::abs(write.value - (1.0 - value)) <= 1e-5) {
                        complemented = true;
                        break;
                    }
                }
                if (!complemented) return false;
            }
            return true;
        };

        std::vector<int> failure_states;
        for (std::size_t state_index = 0;
             state_index < keypad_machine.states.size(); ++state_index) {
            if (state_index != success_index &&
                writes_complements(keypad_machine.states[state_index]))
                failure_states.push_back(static_cast<int>(state_index));
        }
        if (failure_states.size() != 1 ||
            !writes_complements(producer.states[
                static_cast<std::size_t>(producer_failure_state)]))
            continue;

        bool all_outgoing_blocked = true;
        bool has_own_write_block = false;
        bool has_guard_only_block = false;
        for (const auto& transition : success.transitions) {
            if (!concrete_transition(transition, keypad_machine.states.size())) {
                all_outgoing_blocked = false;
                break;
            }
            bool blocked_by_own_write = false;
            bool blocked_by_ready_guard = false;
            bool conditions_known = true;
            for (const auto& condition : transition.conditions) {
                const auto own = success_writes.find(condition.parameter);
                if (own != success_writes.end()) {
                    const auto condition_match = condition_matches_value(
                        condition, own->second);
                    if (!condition_match.has_value()) conditions_known = false;
                    else blocked_by_own_write |= !*condition_match;
                }
                if (condition.parameter == guard) {
                    const auto condition_match = condition_matches_value(
                        condition, ready_guard_value ? 1.0 : 0.0);
                    if (!condition_match.has_value()) conditions_known = false;
                    else blocked_by_ready_guard |= !*condition_match;
                }
            }
            if (!conditions_known ||
                (!blocked_by_own_write && !blocked_by_ready_guard)) {
                all_outgoing_blocked = false;
                break;
            }
            has_own_write_block |= blocked_by_own_write;
            has_guard_only_block |= blocked_by_ready_guard &&
                !blocked_by_own_write;
        }
        if (!all_outgoing_blocked || !has_own_write_block ||
            !has_guard_only_block)
            continue;

        matches.push_back({static_cast<int>(success_index),
            failure_states.front(), guard, ready_guard_value, producer_index,
            ready_state, producer_failure_state});
    }

    std::sort(matches.begin(), matches.end(),
        [](const DynamicContactTerminalEvidence& left,
           const DynamicContactTerminalEvidence& right) {
            return std::tie(left.success_state, left.failure_state,
                       left.producer_machine, left.producer_ready_state) <
                std::tie(right.success_state, right.failure_state,
                       right.producer_machine, right.producer_ready_state);
        });
    matches.erase(std::unique(matches.begin(), matches.end(),
        [](const DynamicContactTerminalEvidence& left,
           const DynamicContactTerminalEvidence& right) {
            return left.success_state == right.success_state &&
                left.failure_state == right.failure_state &&
                left.guard_parameter == right.guard_parameter &&
                left.ready_guard_value == right.ready_guard_value &&
                left.producer_machine == right.producer_machine &&
                left.producer_ready_state == right.producer_ready_state &&
                left.producer_failure_state == right.producer_failure_state;
        }), matches.end());
    return matches.size() == 1
        ? std::optional<DynamicContactTerminalEvidence>(matches.front())
        : std::nullopt;
}

std::optional<HiddenReceiverPulseEvidence>
HiddenReceiverPulseTerminal(
    const Snapshot& snapshot, const Controller& controller,
    std::size_t keypad_machine_index, const Machine& keypad_machine,
    const std::string& keypad_parameter, int ordinary_success_state,
    bool allow_implicit_blocked_retry) {
    if (keypad_parameter.empty() ||
        keypad_machine_index >= controller.machines.size() ||
        keypad_machine.default_state < 0 ||
        keypad_machine.default_state >= static_cast<int>(keypad_machine.states.size()) ||
        ordinary_success_state < 0 ||
        ordinary_success_state >= static_cast<int>(keypad_machine.states.size()) ||
        ordinary_success_state == keypad_machine.default_state)
        return std::nullopt;

    const auto concrete_transition = [](const Transition& transition,
                                         std::size_t state_count) {
        return transition.destination >= 0 &&
            transition.destination < static_cast<int>(state_count);
    };
    // AnyState edges remain active while the keypad is parked in its claimed
    // terminal.  The detector cannot prove their ordering, so any presence is
    // an unknown path and must fail closed (including non-concrete edges).
    if (!keypad_machine.any_transitions.empty())
        return std::nullopt;

    // This family has an ordinary complementary ParameterDriver terminal.  It
    // differs from DynamicContactStabilizedTerminal in two deliberate ways:
    // the keypad terminal is a true sink, and only one of its two complementary
    // binary ParameterDriver writes needs to be a saved expression Bool.  The
    // generated internal companion is commonly serialized as an Animator
    // Float with values 0/1, so requiring every companion parameter itself to
    // have type Bool would reject the real family.  Re-prove the binary
    // default and complementary writes instead.
    const auto& success = keypad_machine.states[
        static_cast<std::size_t>(ordinary_success_state)];
    // The ordinary subtype requires a literal sink.  An unknown destination
    // is still an outgoing edge, not an empty transition list.
    if (!success.transitions.empty())
        return std::nullopt;

    std::map<std::string, bool> success_writes;
    bool has_changed_saved_latch = false;
    for (const auto& write : success.writes) {
        if (write.type != 0 || write.name.empty() ||
            (std::abs(write.value) > 1e-5 &&
             std::abs(write.value - 1.0) > 1e-5))
            continue;
        const auto* runtime_default = EffectiveRuntimeDefault(
            snapshot, controller, write.name);
        if (!runtime_default ||
            (runtime_default->type != "bool" &&
             runtime_default->type != "float" &&
             runtime_default->type != "int") ||
            (std::abs(runtime_default->value) > 1e-5 &&
             std::abs(runtime_default->value - 1.0) > 1e-5))
            continue;
        const bool value = write.value > 0.5;
        const auto inserted = success_writes.emplace(write.name, value);
        if (!inserted.second && inserted.first->second != value)
            return std::nullopt;
        has_changed_saved_latch |=
            snapshot.saved_expression_parameters.count(write.name) != 0 &&
            runtime_default->type == "bool" &&
            ((runtime_default->value > 0.5) != value);
    }
    if (success_writes.size() < 2 || !has_changed_saved_latch)
        return std::nullopt;

    const auto& census = BuildWriterCensus(controller);
    for (const auto& [name, unused] : success_writes) {
        (void)unused;
        if (census.non_set_names.count(name) != 0 ||
            census.animation_names.count(name) != 0 ||
            HasActiveOtherControllerWriter(snapshot, controller, name))
            return std::nullopt;
    }

    const auto writes_success_complements = [&](const State& state) {
        for (const auto& [name, value] : success_writes) {
            bool complemented = false;
            for (const auto& write : state.writes) {
                if (write.type == 0 && write.name == name &&
                    ((write.value > 0.5) != value) &&
                    (std::abs(write.value) <= 1e-5 ||
                     std::abs(write.value - 1.0) <= 1e-5)) {
                    complemented = true;
                    break;
                }
            }
            if (!complemented) return false;
        }
        return true;
    };
    std::vector<int> failure_states;
    for (std::size_t state_index = 0;
         state_index < keypad_machine.states.size(); ++state_index) {
        if (static_cast<int>(state_index) != ordinary_success_state &&
            writes_success_complements(keypad_machine.states[state_index]))
            failure_states.push_back(static_cast<int>(state_index));
    }
    if (failure_states.size() != 1) return std::nullopt;

    // The guard must be one internal Bool with a single dominant polarity on
    // the actual digit-equality edges.  User/menu/Contact writable guards are
    // rejected because they do not prove a separate hidden producer.
    std::map<std::string, std::array<int, 2>> guard_votes;
    for (const auto& state : keypad_machine.states) {
        for (const auto& transition : state.transitions) {
            int keypad_equalities = 0;
            for (const auto& condition : transition.conditions) {
                if (condition.parameter != keypad_parameter ||
                    condition.mode != 6 || condition.threshold < 0.0 ||
                    condition.threshold > 19.0)
                    continue;
                const int rounded = static_cast<int>(
                    std::llround(condition.threshold));
                if (std::abs(condition.threshold - rounded) <= 1e-5)
                    ++keypad_equalities;
            }
            if (keypad_equalities != 1) continue;
            for (const auto& condition : transition.conditions) {
                if (condition.parameter.empty() ||
                    condition.parameter == keypad_parameter ||
                    (condition.mode != 1 && condition.mode != 2))
                    continue;
                ++guard_votes[condition.parameter][
                    condition.mode == 1 ? 1 : 0];
            }
        }
    }

    std::set<std::string> externally_mutable = snapshot.expression_parameters;
    externally_mutable.insert(snapshot.contact_input_parameters.begin(),
        snapshot.contact_input_parameters.end());
    externally_mutable.insert(snapshot.dynamic_contact_parameters.begin(),
        snapshot.dynamic_contact_parameters.end());
    externally_mutable.insert(snapshot.forced_contact_parameters.begin(),
        snapshot.forced_contact_parameters.end());
    for (const auto& menu : snapshot.menus) {
        for (const auto& control : menu.controls) {
            if (!control.parameter.empty())
                externally_mutable.insert(control.parameter);
            externally_mutable.insert(control.sub_parameters.begin(),
                control.sub_parameters.end());
        }
    }

    std::vector<std::pair<std::string, bool>> dominant_guards;
    for (const auto& [guard, votes] : guard_votes) {
        std::optional<bool> required;
        if (votes[0] >= 3 && votes[0] >= votes[1] * 3)
            required = false;
        else if (votes[1] >= 3 && votes[1] >= votes[0] * 3)
            required = true;
        const auto guard_default = controller.parameter_defaults.find(guard);
        if (!required.has_value() || externally_mutable.count(guard) != 0 ||
            guard_default == controller.parameter_defaults.end() ||
            guard_default->second.type != "bool" ||
            ((guard_default->second.value > 0.5) == *required))
            continue;
        dominant_guards.push_back({guard, *required});
    }
    if (dominant_guards.size() != 1) return std::nullopt;
    const std::string guard = dominant_guards.front().first;
    const bool ready_guard_value = dominant_guards.front().second;

    const auto& writers = census.set_owners;
    const auto guard_writers = writers.find(guard);
    if (guard_writers == writers.end() || guard_writers->second.size() != 1)
        return std::nullopt;
    if (census.non_set_names.count(guard) != 0 ||
        census.animation_names.count(guard) != 0 ||
        HasActiveOtherControllerWriter(snapshot, controller, guard))
        return std::nullopt;
    const std::size_t producer_index = *guard_writers->second.begin();
    if (producer_index == keypad_machine_index ||
        producer_index >= controller.machines.size())
        return std::nullopt;
    const auto& producer = controller.machines[producer_index];
    if (producer.default_state < 0 ||
        producer.default_state >= static_cast<int>(producer.states.size()))
        return std::nullopt;

    std::set<std::string> contact_dependencies;
    bool dynamic_contact_dependency = false;
    bool fixed_contact_dependency = false;
    bool foreign_dependency = false;
    auto scan_dependencies = [&](const std::vector<Transition>& transitions) {
        for (const auto& transition : transitions) {
            for (const auto& condition : transition.conditions) {
                if (snapshot.contact_input_parameters.count(
                        condition.parameter) != 0)
                    contact_dependencies.insert(condition.parameter);
                else if (condition.parameter != "AvatarVersion")
                    foreign_dependency = true;
                if (snapshot.dynamic_contact_parameters.count(
                        condition.parameter) != 0)
                    dynamic_contact_dependency = true;
                if (snapshot.forced_contact_parameters.count(
                        condition.parameter) != 0)
                    fixed_contact_dependency = true;
            }
        }
    };
    scan_dependencies(producer.any_transitions);
    for (const auto& state : producer.states)
        scan_dependencies(state.transitions);
    if (contact_dependencies.size() != 1 || dynamic_contact_dependency ||
        fixed_contact_dependency || foreign_dependency)
        return std::nullopt;
    const std::string contact_parameter = *contact_dependencies.begin();

    if (!producer.any_transitions.empty())
        return std::nullopt;

    const auto stable_sink = [&](const State& state) {
        return state.transitions.empty();
    };
    const auto bool_write = [&](const State& state) -> std::optional<bool> {
        std::optional<bool> value;
        for (const auto& write : state.writes) {
            if (write.type != 0 || write.name != guard ||
                (std::abs(write.value) > 1e-5 &&
                 std::abs(write.value - 1.0) > 1e-5))
                continue;
            const bool current = write.value > 0.5;
            if (value.has_value() && *value != current)
                return std::nullopt;
            value = current;
        }
        return value;
    };

    std::vector<int> ready_states;
    std::vector<int> retry_states;
    for (std::size_t state_index = 0;
         state_index < producer.states.size(); ++state_index) {
        const auto value = bool_write(producer.states[state_index]);
        if (!value.has_value()) continue;
        if (*value == ready_guard_value) {
            if (stable_sink(producer.states[state_index]))
                ready_states.push_back(static_cast<int>(state_index));
        } else {
            retry_states.push_back(static_cast<int>(state_index));
        }
    }
    if (ready_states.size() != 1 || retry_states.size() > 1 ||
        ready_states.front() == producer.default_state)
        return std::nullopt;
    const int ready_state = ready_states.front();
    int retry_state = retry_states.empty() ? -1 : retry_states.front();
    const bool implicit_retry = retry_states.empty();
    if (retry_state == ready_state ||
        (retry_state >= 0 && stable_sink(producer.states[
            static_cast<std::size_t>(retry_state)])))
        return std::nullopt;

    if (!implicit_retry) {
        // An explicit retry state is part of the contact proof, not an
        // arbitrary action state.  Any additional ParameterDriver or
        // animation write could mutate a condition parameter between the
        // sampled contact edges and the keypad terminal.  Treat that shape as
        // unknown instead of silently ignoring the extra operation.
        const auto& retry = producer.states[
            static_cast<std::size_t>(retry_state)];
        int guard_write_count = 0;
        for (const auto& write : retry.writes) {
            if (write.name != guard || write.type != 0 ||
                (std::abs(write.value) > 1e-5 &&
                 std::abs(write.value - 1.0) > 1e-5))
                return std::nullopt;
            ++guard_write_count;
        }
        if (guard_write_count != 1 || !retry.animation_writes.empty())
            return std::nullopt;
    }

    struct ContactTrace {
        int sink = -1;
        std::vector<int> cycle;
        bool used_high_only_edge = false;
        bool used_low_only_edge = false;
        std::set<int> high_only_destinations;
        std::set<int> low_only_destinations;
    };
    const auto simulate_contact = [&](int high_steps)
        -> std::optional<ContactTrace> {
        std::map<std::string, double> values;
        for (const auto& [name, item] : controller.parameter_defaults)
            values[name] = item.value;
        for (const auto& [name, item] : snapshot.expression_parameter_defaults)
            values[name] = item.value;
        values["AvatarVersion"] = 3.0;
        int state_index = producer.default_state;
        bool used_high_only_edge = false;
        bool used_low_only_edge = false;
        std::set<int> high_only_destinations;
        std::set<int> low_only_destinations;
        std::map<std::string, std::size_t> seen;
        std::vector<int> visited;
        const int step_limit = std::max<int>(64,
            static_cast<int>(producer.states.size()) * 8);
        for (int step = 0; step < step_limit; ++step) {
            if (state_index < 0 ||
                state_index >= static_cast<int>(producer.states.size()))
                return std::nullopt;
            const bool contact_high = high_steps < 0 || step < high_steps;
            const auto& state = producer.states[
                static_cast<std::size_t>(state_index)];
            for (const auto& write : state.writes)
                if (write.type == 0) values[write.name] = write.value;
            values[contact_parameter] = contact_high ? 1.0 : 0.0;

            std::ostringstream signature;
            signature << state_index << '|' << (contact_high ? '1' : '0');
            for (const auto& [name, value] : values)
                signature << '|' << name << '=' << std::to_string(value);
            const auto inserted = seen.emplace(signature.str(), visited.size());
            if (!inserted.second) {
                ContactTrace result;
                result.used_high_only_edge = used_high_only_edge;
                result.used_low_only_edge = used_low_only_edge;
                result.high_only_destinations = high_only_destinations;
                result.low_only_destinations = low_only_destinations;
                result.cycle.assign(
                    visited.begin() + static_cast<std::ptrdiff_t>(
                        inserted.first->second), visited.end());
                return result;
            }
            visited.push_back(state_index);

            auto enabled_with_contact = [&](const Transition& transition,
                                             bool high)
                -> std::optional<bool> {
                auto evaluated = values;
                evaluated[contact_parameter] = high ? 1.0 : 0.0;
                for (const auto& condition : transition.conditions) {
                    const auto matches = ConditionMatches(condition, evaluated);
                    if (!matches.has_value()) return std::nullopt;
                    if (!*matches) return false;
                }
                return true;
            };

            const Transition* selected = nullptr;
            bool selected_high_only = false;
            bool selected_low_only = false;
            for (const auto& transition : state.transitions) {
                const auto enabled = enabled_with_contact(
                    transition, contact_high);
                if (!enabled.has_value()) return std::nullopt;
                if (!*enabled) continue;
                const auto opposite = enabled_with_contact(
                    transition, !contact_high);
                if (!opposite.has_value()) return std::nullopt;
                selected = &transition;
                selected_high_only = contact_high && !*opposite;
                selected_low_only = !contact_high && !*opposite;
                break;
            }
            if (!selected) {
                ContactTrace result;
                result.sink = state_index;
                result.used_high_only_edge = used_high_only_edge;
                result.used_low_only_edge = used_low_only_edge;
                result.high_only_destinations = high_only_destinations;
                result.low_only_destinations = low_only_destinations;
                return result;
            }
            if (!concrete_transition(*selected, producer.states.size()))
                return std::nullopt;
            used_high_only_edge |= selected_high_only;
            used_low_only_edge |= selected_low_only;
            if (selected_high_only)
                high_only_destinations.insert(selected->destination);
            if (selected_low_only)
                low_only_destinations.insert(selected->destination);
            state_index = selected->destination;
        }
        return std::nullopt;
    };

    const auto constant_low = simulate_contact(0);
    const auto constant_high = simulate_contact(-1);
    const auto cycle_contains = [](const ContactTrace& trace, int state) {
        return std::find(trace.cycle.begin(), trace.cycle.end(), state) !=
            trace.cycle.end();
    };

    // A sealed-success generator may omit an explicit write of the blocked
    // guard value in its retry state.  That is safe to accept only when the
    // graph itself proves a unique retry state: it must be present in both
    // constant-contact retry cycles, be entered by complementary high-only
    // and low-only contact edges whose other predicates are true at runtime
    // defaults, and have a non-contact return edge into the same cycles.  The
    // ordinary true-sink family deliberately does not enable this branch.
    if (retry_state < 0) {
        if (!allow_implicit_blocked_retry ||
            !constant_low.has_value() || !constant_high.has_value())
            return std::nullopt;

        // In the implicit-retry subtype the ready sink is the sole owner of
        // every guard write.  Writer-machine uniqueness is insufficient: a
        // second state in the same producer could otherwise restore/unseal
        // the guard after the claimed terminal was reached.
        for (std::size_t state_index = 0;
             state_index < producer.states.size(); ++state_index) {
            const auto& state = producer.states[state_index];
            for (const auto& write : state.writes) {
                if (write.name != guard) continue;
                if (static_cast<int>(state_index) != ready_state ||
                    write.type != 0 ||
                    (std::abs(write.value) > 1e-5 &&
                     std::abs(write.value - 1.0) > 1e-5) ||
                    ((write.value > 0.5) != ready_guard_value))
                    return std::nullopt;
            }
            if (std::any_of(state.animation_writes.begin(),
                    state.animation_writes.end(),
                    [&](const AnimationWrite& write) {
                        return write.name == guard;
                    }))
                return std::nullopt;
        }

        std::map<std::string, double> runtime_defaults;
        for (const auto& [name, item] : controller.parameter_defaults)
            runtime_defaults[name] = item.value;
        for (const auto& [name, item] : snapshot.expression_parameter_defaults)
            runtime_defaults[name] = item.value;
        runtime_defaults["AvatarVersion"] = 3.0;

        const auto evaluate_default = [&](const Condition& condition,
                                          double contact_value)
            -> std::optional<bool> {
            auto values = runtime_defaults;
            values[contact_parameter] = contact_value;
            return ConditionMatches(condition, values);
        };

        std::vector<int> implicit_retry_candidates;
        for (std::size_t state_index = 0;
             state_index < producer.states.size(); ++state_index) {
            const int candidate = static_cast<int>(state_index);
            const auto& retry = producer.states[state_index];
            if (candidate == producer.default_state || candidate == ready_state ||
                !cycle_contains(*constant_low, candidate) ||
                !cycle_contains(*constant_high, candidate) ||
                bool_write(retry).has_value() || stable_sink(retry) ||
                !retry.writes.empty() || !retry.animation_writes.empty())
                continue;

            // A malformed/non-binary guard write must not be mistaken for an
            // implicit retry.  Reject every parameter/animation write of the
            // guard name, not just recognized type-0 Boolean writes.
            if (std::any_of(retry.writes.begin(), retry.writes.end(),
                    [&](const ParameterWrite& write) {
                        return write.name == guard;
                    }) ||
                std::any_of(retry.animation_writes.begin(),
                    retry.animation_writes.end(),
                    [&](const AnimationWrite& write) {
                        return write.name == guard;
                    }))
                continue;

            // The sealed subtype has exactly two incoming contact edges: one
            // strict high-only and one strict low-only edge from different
            // source states.  Only the immutable AvatarVersion==3 predicate
            // may accompany that contact condition; external/default-true
            // predicates are intentionally rejected.
            struct IncomingEdge {
                int source = -1;
                bool high_only = false;
                bool low_only = false;
            };
            std::vector<IncomingEdge> incoming;
            bool incoming_shape_ok = true;
            for (std::size_t source_index = 0;
                 source_index < producer.states.size() && incoming_shape_ok;
                 ++source_index) {
                const auto& source = producer.states[source_index];
                for (const auto& transition : source.transitions) {
                    if (!concrete_transition(transition,
                            producer.states.size()) ||
                        transition.destination != candidate)
                        continue;
                    // The retry entry must be an immediate edge.  A timed or
                    // blended edge can fire after the contact polarity has
                    // changed and therefore does not prove the claimed pulse
                    // sequence.  `has_exit_time` is the authoritative bit;
                    // a serialized zero exit_time alone is valid when it is
                    // not marked as present.
                    if (transition.has_exit_time ||
                        !std::isfinite(transition.exit_time) ||
                        !std::isfinite(transition.duration) ||
                        std::abs(transition.duration) > 1e-5) {
                        incoming_shape_ok = false;
                        break;
                    }
                    int contact_conditions = 0;
                    bool strict_contact = false;
                    bool high_enabled = true;
                    bool low_enabled = true;
                    for (const auto& condition : transition.conditions) {
                        if (condition.parameter == contact_parameter) {
                            ++contact_conditions;
                            if ((condition.mode != 3 && condition.mode != 4) ||
                                condition.threshold <= 0.0 ||
                                condition.threshold >= 1.0)
                                incoming_shape_ok = false;
                            const auto high = evaluate_default(condition, 1.0);
                            const auto low = evaluate_default(condition, 0.0);
                            if (!high.has_value() || !low.has_value()) {
                                incoming_shape_ok = false;
                                continue;
                            }
                            high_enabled &= *high;
                            low_enabled &= *low;
                            strict_contact = true;
                        } else if (condition.parameter != "AvatarVersion" ||
                                   condition.mode != 6 ||
                                   std::abs(condition.threshold - 3.0) > 1e-5) {
                            incoming_shape_ok = false;
                        } else {
                            const auto match = evaluate_default(condition, 0.0);
                            if (!match.has_value() || !*match)
                                incoming_shape_ok = false;
                        }
                    }
                    if (!incoming_shape_ok || contact_conditions != 1 ||
                        !strict_contact || high_enabled == low_enabled)
                        incoming_shape_ok = false;
                    incoming.push_back({static_cast<int>(source_index),
                        high_enabled && !low_enabled,
                        low_enabled && !high_enabled});
                }
            }
            if (!incoming_shape_ok || incoming.size() != 2 ||
                incoming[0].source == incoming[1].source ||
                !(incoming[0].high_only != incoming[1].high_only) ||
                !(incoming[0].low_only != incoming[1].low_only) ||
                !(incoming[0].high_only || incoming[1].high_only) ||
                !(incoming[0].low_only || incoming[1].low_only))
                continue;

            // No AnyState edge may feed the implicit retry.  Its only concrete
            // outgoing edge is an unconditional timed return into the proven
            // retry SCC, and it may not directly target itself or the ready
            // sink.  This excludes arbitrary cyclic action buses.
            bool incoming_any_state = false;
            for (const auto& transition : producer.any_transitions)
                incoming_any_state |= concrete_transition(transition,
                    producer.states.size()) && transition.destination == candidate;
            if (incoming_any_state || retry.transitions.size() != 1)
                continue;
            const auto& return_edge = retry.transitions.front();
            if (!concrete_transition(return_edge, producer.states.size()) ||
                !return_edge.conditions.empty() || !return_edge.has_exit_time ||
                !std::isfinite(return_edge.exit_time) ||
                !std::isfinite(return_edge.duration) ||
                return_edge.exit_time <= 0.0 ||
                std::abs(return_edge.duration) > 1e-5 ||
                return_edge.destination == candidate ||
                return_edge.destination == ready_state ||
                (!cycle_contains(*constant_low, return_edge.destination) ||
                 !cycle_contains(*constant_high, return_edge.destination)))
                continue;

            implicit_retry_candidates.push_back(candidate);
        }

        if (implicit_retry_candidates.size() != 1) return std::nullopt;
        retry_state = implicit_retry_candidates.front();
    }

    if (!constant_low.has_value() || !constant_high.has_value() ||
        constant_low->cycle.empty() || constant_high->cycle.empty() ||
        !cycle_contains(*constant_low, retry_state) ||
        !cycle_contains(*constant_high, retry_state) ||
        cycle_contains(*constant_low, ready_state) ||
        cycle_contains(*constant_high, ready_state) ||
        (implicit_retry &&
         (constant_low->low_only_destinations.count(retry_state) == 0 ||
          constant_high->high_only_destinations.count(retry_state) == 0)))
        return std::nullopt;

    bool high_then_low_reaches_ready = false;
    const int pulse_limit = std::max<int>(16,
        static_cast<int>(producer.states.size()) * 3);
    for (int high_steps = 1; high_steps < pulse_limit; ++high_steps) {
        const auto pulse = simulate_contact(high_steps);
        if (pulse.has_value() && pulse->sink == ready_state &&
            pulse->cycle.empty() && pulse->used_high_only_edge &&
            pulse->used_low_only_edge) {
            high_then_low_reaches_ready = true;
            break;
        }
    }
    if (!high_then_low_reaches_ready) return std::nullopt;

    return HiddenReceiverPulseEvidence{producer_index, ready_state,
        retry_state, ordinary_success_state, guard, ready_guard_value};
}

// Variant of the hidden Receiver family whose keypad success state is not a
// graph-theoretic sink.  Its concrete exits are nevertheless impossible after
// combining the values written by the success state with the persistent guard
// value written by the producer ready sink.  Discover the keypad terminal and
// producer together; never assume unrelated controller defaults to seal an
// outgoing edge.
std::optional<HiddenReceiverPulseEvidence>
HiddenReceiverPulseSealedTerminal(
    const Snapshot& snapshot, const Controller& controller,
    std::size_t keypad_machine_index, const Machine& keypad_machine,
    const std::string& keypad_parameter) {
    if (keypad_parameter.empty() ||
        keypad_machine_index >= controller.machines.size())
        return std::nullopt;
    if (!keypad_machine.any_transitions.empty())
        return std::nullopt;

    const auto concrete_transition = [](const Transition& transition,
                                         std::size_t state_count) {
        return transition.destination >= 0 &&
            transition.destination < static_cast<int>(state_count);
    };
    const auto& census = BuildWriterCensus(controller);
    const auto& writers = census.set_owners;

    std::vector<HiddenReceiverPulseEvidence> matches;
    for (std::size_t success_index = 0;
         success_index < keypad_machine.states.size(); ++success_index) {
        if (static_cast<int>(success_index) == keypad_machine.default_state)
            continue;
        const auto& original_success = keypad_machine.states[success_index];
        const bool has_concrete_outgoing = std::any_of(
            original_success.transitions.begin(),
            original_success.transitions.end(),
            [&](const Transition& transition) {
                return concrete_transition(
                    transition, keypad_machine.states.size());
            });
        if (!has_concrete_outgoing) continue;
        if (std::any_of(original_success.transitions.begin(),
                original_success.transitions.end(),
                [&](const Transition& transition) {
                    return !concrete_transition(
                        transition, keypad_machine.states.size());
                }))
            continue;

        std::map<std::string, double> post_values;
        bool changed_saved_latch = false;
        bool conflicting_write = false;
        for (const auto& write : original_success.writes) {
            if (write.type != 0 || write.name.empty() ||
                (std::abs(write.value) > 1e-5 &&
                 std::abs(write.value - 1.0) > 1e-5))
                continue;
            const auto inserted = post_values.emplace(write.name, write.value);
            if (!inserted.second &&
                std::abs(inserted.first->second - write.value) > 1e-5)
                conflicting_write = true;
            const auto* runtime_default = EffectiveRuntimeDefault(
                snapshot, controller, write.name);
            changed_saved_latch |= runtime_default &&
                runtime_default->type == "bool" &&
                snapshot.saved_expression_parameters.count(write.name) != 0 &&
                ((runtime_default->value > 0.5) != (write.value > 0.5));
        }
        if (conflicting_write || post_values.size() < 2 ||
            !changed_saved_latch)
            continue;

        // Temporarily remove only the candidate success outedges and reuse the
        // strict true-sink proof for all remaining keypad/producer predicates.
        Machine assumed_sink = keypad_machine;
        assumed_sink.states[success_index].transitions.clear();
        auto evidence = HiddenReceiverPulseTerminal(snapshot, controller,
            keypad_machine_index, assumed_sink, keypad_parameter,
            static_cast<int>(success_index), true);
        if (!evidence.has_value()) continue;

        // Every success-written value that participates in the terminal must
        // be owned by the keypad machine; an external writer would invalidate
        // the claimed persistent joint post-state.
        bool unique_success_writers = true;
        for (const auto& [name, unused] : post_values) {
            (void)unused;
            const auto found = writers.find(name);
            if (found == writers.end() || found->second.size() != 1 ||
                *found->second.begin() != keypad_machine_index) {
                unique_success_writers = false;
                break;
            }
            if (census.non_set_names.count(name) != 0 ||
                census.animation_names.count(name) != 0 ||
                HasActiveOtherControllerWriter(snapshot, controller, name)) {
                unique_success_writers = false;
                break;
            }
        }
        if (!unique_success_writers) continue;

        post_values[evidence->guard_parameter] =
            evidence->ready_guard_value ? 1.0 : 0.0;
        // AvatarVersion is a recognized immutable runtime discriminator used
        // by generated FX transitions; it is not an external unlock input.
        post_values["AvatarVersion"] = 3.0;
        bool all_outgoing_disabled = true;
        bool has_own_write_block = false;
        bool has_guard_only_block = false;
        for (const auto& transition : original_success.transitions) {
            bool enabled = true;
            bool blocked_by_own_write = false;
            bool blocked_by_ready_guard = false;
            bool conditions_known = true;
            for (const auto& condition : transition.conditions) {
                if (post_values.count(condition.parameter) == 0) {
                    conditions_known = false;
                    continue;
                }
                const auto outcome = ConditionMatches(condition, post_values);
                if (!outcome.has_value()) {
                    conditions_known = false;
                    continue;
                }
                if (!*outcome) {
                    enabled = false;
                    if (post_values.count(condition.parameter) != 0 &&
                        condition.parameter == evidence->guard_parameter)
                        blocked_by_ready_guard = true;
                    if (post_values.count(condition.parameter) != 0 &&
                        condition.parameter != evidence->guard_parameter)
                        blocked_by_own_write = true;
                }
            }
            if (!conditions_known || enabled ||
                (!blocked_by_own_write && !blocked_by_ready_guard)) {
                all_outgoing_disabled = false;
                break;
            }
            has_own_write_block |= blocked_by_own_write;
            has_guard_only_block |= blocked_by_ready_guard &&
                !blocked_by_own_write;
        }
        if (!all_outgoing_disabled || !has_own_write_block ||
            !has_guard_only_block)
            continue;
        evidence->success_state = static_cast<int>(success_index);
        matches.push_back(std::move(*evidence));
    }

    std::sort(matches.begin(), matches.end(),
        [](const HiddenReceiverPulseEvidence& left,
           const HiddenReceiverPulseEvidence& right) {
            return std::tie(left.success_state, left.producer_machine,
                       left.ready_state, left.retry_state) <
                std::tie(right.success_state, right.producer_machine,
                       right.ready_state, right.retry_state);
        });
    matches.erase(std::unique(matches.begin(), matches.end(),
        [](const HiddenReceiverPulseEvidence& left,
           const HiddenReceiverPulseEvidence& right) {
            return left.success_state == right.success_state &&
                left.producer_machine == right.producer_machine &&
                left.ready_state == right.ready_state &&
                left.retry_state == right.retry_state &&
                left.guard_parameter == right.guard_parameter &&
                left.ready_guard_value == right.ready_guard_value;
        }), matches.end());
    return matches.size() == 1
        ? std::optional<HiddenReceiverPulseEvidence>(matches.front())
        : std::nullopt;
}

void DetectParameterDriverKeypad(const Snapshot& snapshot,
    const Controller& controller, std::size_t machine_index,
    const Machine& machine,
    const MenuMaps& menu_maps, std::vector<Candidate>& out) {
    auto ordinary_terminal = ComplementaryParameterDriverTerminal(
        snapshot, controller, machine);
    bool monotonic_saved_terminal = false;
    if (!ordinary_terminal.has_value()) {
        ordinary_terminal = MonotonicSavedUnlockTerminal(
            snapshot, controller, machine);
        monotonic_saved_terminal = ordinary_terminal.has_value();
    }
    if (machine.default_state < 0 ||
        machine.default_state >= static_cast<int>(machine.states.size())) return;

    for (const auto& [parameter, pages] : menu_maps) {
        auto terminal = ordinary_terminal;
        std::optional<DynamicContactTerminalEvidence> contact_evidence;
        std::optional<HiddenReceiverPulseEvidence> hidden_receiver_evidence;
        if (terminal.has_value()) {
            hidden_receiver_evidence = HiddenReceiverPulseTerminal(
                snapshot, controller, machine_index, machine, parameter,
                *terminal, false);
            // ComplementaryParameterDriverTerminal can prove the saved
            // writes while still allowing a concrete, jointly sealed success
            // edge.  Retry the sealed-family proof before falling through to
            // the looser dynamic-contact detector; otherwise the ordinary
            // sink check would mask the stronger self/guard-closure variant.
            if (!hidden_receiver_evidence.has_value()) {
                hidden_receiver_evidence = HiddenReceiverPulseSealedTerminal(
                    snapshot, controller, machine_index, machine, parameter);
                if (hidden_receiver_evidence.has_value())
                    terminal = hidden_receiver_evidence->success_state;
            }
        } else {
            hidden_receiver_evidence = HiddenReceiverPulseSealedTerminal(
                snapshot, controller, machine_index, machine, parameter);
            if (hidden_receiver_evidence.has_value()) {
                terminal = hidden_receiver_evidence->success_state;
            }
        }
        if (!hidden_receiver_evidence.has_value()) {
            // Keep a proven ordinary terminal even when it is not part of a
            // Contact family.  The hidden/dynamic helpers are additional
            // provenance checks, not prerequisites for the ordinary
            // ParameterDriver detector (notably for zero-weight keypads).
            contact_evidence = DynamicContactStabilizedTerminal(
                snapshot, controller, machine_index, machine, parameter);
            if (contact_evidence.has_value()) {
                terminal = contact_evidence->success_state;
            } else if (!terminal.has_value()) {
                continue;
            }
        }
        // Compute the deterministic entry closure with the same runtime values
        // Unity sees on the first frame.  In particular, apply type-0 writes in
        // the default state before evaluating its outgoing guards.  The old
        // state-only closure used controller defaults and could resurrect a
        // keypad whose default state had already written its latch to the
        // unlocked value (the 5B6F false candidate regression).
        std::set<std::string> condition_parameters;
        for (const auto& state : machine.states)
            for (const auto& transition : state.transitions)
                for (const auto& condition : transition.conditions)
                    if (!condition.parameter.empty())
                        condition_parameters.insert(condition.parameter);
        if (!machine.any_transitions.empty()) continue;

        struct RuntimeNode {
            int state = -1;
            std::map<std::string, double> values;
        };
        std::map<std::string, double> initial_values;
        for (const auto& [name, item] : controller.parameter_defaults)
            initial_values[name] = item.value;
        for (const auto& [name, item] : snapshot.expression_parameter_defaults)
            initial_values[name] = item.value;
        initial_values["AvatarVersion"] = 3.0;

        auto runtime_signature = [&](int state,
                                     const std::map<std::string, double>& values) {
            std::ostringstream signature;
            signature << state;
            for (const auto& name : condition_parameters) {
                const auto found = values.find(name);
                if (found != values.end())
                    signature << '|' << name << '=' << std::setprecision(17)
                              << found->second;
            }
            return signature.str();
        };

        std::vector<RuntimeNode> pending;
        pending.push_back({machine.default_state, initial_values});
        std::set<std::string> seen_runtime;
        std::set<int> reachable;
        bool reachability_unknown = false;
        constexpr std::size_t kRuntimeClosureLimit = 512;
        for (std::size_t cursor = 0;
             cursor < pending.size() && cursor < kRuntimeClosureLimit;
             ++cursor) {
            RuntimeNode node = std::move(pending[cursor]);
            if (node.state < 0 ||
                node.state >= static_cast<int>(machine.states.size())) {
                reachability_unknown = true;
                break;
            }
            const auto& state = machine.states[static_cast<std::size_t>(node.state)];
            for (const auto& write : state.writes) {
                if (write.type != 0) {
                    if (condition_parameters.count(write.name) != 0)
                        reachability_unknown = true;
                    continue;
                }
                node.values[write.name] = write.value;
            }
            for (const auto& write : state.animation_writes)
                if (condition_parameters.count(write.name) != 0)
                    reachability_unknown = true;
            if (reachability_unknown) break;

            const auto signature = runtime_signature(node.state, node.values);
            if (!seen_runtime.insert(signature).second) continue;
            reachable.insert(node.state);

            for (const auto& transition : state.transitions) {
                if (transition.destination < 0 ||
                    transition.destination >= static_cast<int>(machine.states.size())) {
                    reachability_unknown = true;
                    break;
                }
                // Numeric input edges are intentionally not followed here;
                // they are enumerated below as candidate user actions.
                if (std::any_of(transition.conditions.begin(),
                        transition.conditions.end(),
                        [&](const Condition& condition) {
                            return condition.parameter == parameter;
                        }))
                    continue;
                bool enabled = true;
                for (const auto& condition : transition.conditions) {
                    const auto match = ConditionMatches(condition, node.values);
                    if (!match.has_value()) {
                        reachability_unknown = true;
                        break;
                    }
                    if (!*match) {
                        enabled = false;
                        break;
                    }
                }
                if (reachability_unknown) break;
                if (enabled)
                    pending.push_back({transition.destination, node.values});
            }
            if (reachability_unknown) break;
        }
        if (pending.size() >= kRuntimeClosureLimit || reachability_unknown)
            continue;

        struct KeyEdge { int value = 0; int destination = -1; };
        std::map<int, std::vector<KeyEdge>> edges;
        for (std::size_t source = 0; source < machine.states.size(); ++source) {
            const auto& source_transitions = machine.states[source].transitions;
            for (std::size_t transition_index = 0;
                 transition_index < source_transitions.size(); ++transition_index) {
                const auto& transition = source_transitions[transition_index];
                if (transition.destination < 0 ||
                    transition.destination >= static_cast<int>(machine.states.size()))
                    continue;
                std::optional<int> value;
                bool clean_input = true;
                for (const auto& condition : transition.conditions) {
                    if (condition.parameter != parameter) continue;
                    if (condition.mode != 6 || value.has_value() ||
                        condition.threshold < 0.0 || condition.threshold > 19.0) {
                        clean_input = false;
                        break;
                    }
                    const int rounded = static_cast<int>(
                        std::llround(condition.threshold));
                    if (std::abs(condition.threshold - rounded) > 1e-5) {
                        clean_input = false;
                        break;
                    }
                    value = rounded;
                }
                if (!clean_input || !value.has_value()) continue;

                // Generated locks may conjoin a temporal Contact/lock guard
                // with the visible key equality.  Keep those non-input guards
                // for the later deterministic/dependency proof instead of
                // discarding the complete password edge here.
                edges[static_cast<int>(source)].push_back(
                    {*value, transition.destination});
            }
        }

        std::set<std::vector<int>> solved;
        std::function<void(int,std::vector<int>&,std::set<int>&)> walk =
            [&](int state, std::vector<int>& values, std::set<int>& visiting) {
                if (state == *terminal) {
                    if (values.size() >= 6) solved.insert(values);
                    return;
                }
                if (values.size() >= 24 || !visiting.insert(state).second) return;
                const auto found = edges.find(state);
                if (found != edges.end()) {
                    for (const auto& edge : found->second) {
                        values.push_back(edge.value);
                        walk(edge.destination, values, visiting);
                        values.pop_back();
                    }
                } else {
                    // A final key may enter a transient state which then falls
                    // through unconditionally to the saved success writer.
                    // Follow only a single concrete unconditional successor;
                    // multiple or guarded successors are ambiguous and remain
                    // fail-closed.
                    const auto& transitions = machine.states[
                        static_cast<std::size_t>(state)].transitions;
                    std::vector<int> silent_successors;
                    for (const auto& transition : transitions)
                        if (transition.destination >= 0 &&
                            transition.destination <
                                static_cast<int>(machine.states.size()) &&
                            transition.conditions.empty())
                            silent_successors.push_back(transition.destination);
                    std::sort(silent_successors.begin(),
                        silent_successors.end());
                    silent_successors.erase(std::unique(
                        silent_successors.begin(), silent_successors.end()),
                        silent_successors.end());
                    if (silent_successors.size() == 1)
                        walk(silent_successors.front(), values, visiting);
                }
                visiting.erase(state);
            };
        for (int start : reachable) {
            std::vector<int> values;
            std::set<int> visiting;
            walk(start, values, visiting);
        }

        // Kanna-style generators enter their keypad chain only after a
        // dynamic Contact has settled a separate Boolean gate.  Controller
        // defaults therefore cannot prove the chain head.  When that exact
        // two-machine dependency is present, inspect every numeric edge source
        // and retain only the unique longest route to the already-proven
        // complementary terminal.  Shorter suffixes are not passwords.
        Candidate guard_probe{"", parameter, "", "", ""};
        if (HasDynamicContactGuardDependency(snapshot, controller,
                machine_index, machine, guard_probe)) {
            const auto default_reachable_solutions = solved;
            solved.clear();
            for (const auto& [start, unused] : edges) {
                (void)unused;
                std::vector<int> values;
                std::set<int> visiting;
                walk(start, values, visiting);
            }
            std::size_t longest = 0;
            for (const auto& values : solved)
                longest = std::max(longest, values.size());
            for (auto it = solved.begin(); it != solved.end();) {
                if (it->size() != longest) it = solved.erase(it);
                else ++it;
            }
            if (solved.size() != 1) solved = default_reachable_solutions;
        }
        if (solved.empty()) continue;
        // Keep up to three longest reverse-derived routes when the graph is
        // ambiguous.  A unique route remains high confidence; ambiguous
        // routes are operator candidates only and can never authorize a
        // rewrite plan (the plan gate below still requires 高).
        std::vector<std::vector<int>> solutions(solved.begin(), solved.end());
        std::sort(solutions.begin(), solutions.end(),
            [](const std::vector<int>& left, const std::vector<int>& right) {
                if (left.size() != right.size()) return left.size() > right.size();
                return left < right;
            });
        if (solutions.size() > 3) solutions.resize(3);
        const std::string confidence = (solved.size() == 1) ? u8"\u9ad8" : u8"\u53c2\u8003";
        for (const auto& solution : solutions) {
            auto raw_values = solution;
            // A settled Kanna gate can enter the chain through the release
            // state immediately preceding the first visible key.  That
            // leading zero is not a user action; later zeros remain required
            // release confirmations.
            std::size_t press_offset = 0;
            if (!raw_values.empty() && raw_values.front() == 0)
                press_offset = 1;
            std::vector<int> press_values;
            bool alternating_release = press_offset < raw_values.size();
            for (std::size_t index = 0; index < raw_values.size(); ++index) {
                if (index >= press_offset &&
                    (index - press_offset) % 2 == 0) {
                    if (raw_values[index] == 0) {
                        alternating_release = false;
                        break;
                    }
                    press_values.push_back(raw_values[index]);
                } else if (raw_values[index] != 0) {
                    alternating_release = false;
                    break;
                }
            }
            if (!alternating_release || press_values.size() < 3) continue;

            for (const auto& [menu_name, mapping] : pages) {
                std::map<int,int> raw_to_logical;
                for (const auto& [logical, entry] : mapping)
                    raw_to_logical[entry.raw_value] = logical;
                std::ostringstream password, raw;
                bool complete = true;
                for (int press_value : press_values) {
                    const auto logical = raw_to_logical.find(press_value);
                    if (logical == raw_to_logical.end()) { complete = false; break; }
                    password << logical->second;
                }
                for (int value : raw_values) raw << value;
                if (!complete) continue;
                out.push_back({controller.name, parameter, raw.str(), password.str(),
                    std::string(monotonic_saved_terminal
                        ? u8"按键/自动回零路径 + 单向保存锁存终点 | 数字菜单「"
                        : u8"按键/自动回零路径 + ParameterDriver 互补终点 | 菜单「") +
                        menu_name + u8"\u300d\u4ea4\u53c9\u9a8c\u8bc1",
                    confidence, *terminal, "native_press_release_semantic_terminal"});
                if (monotonic_saved_terminal)
                    out.back().family =
                        "offset_press_release_monotonic_saved_latch";
                if (contact_evidence.has_value()) {
                    out.back().contact_producer_machine =
                        contact_evidence->producer_machine;
                    out.back().contact_ready_state =
                        contact_evidence->producer_ready_state;
                } else if (hidden_receiver_evidence.has_value()) {
                    out.back().contact_producer_machine =
                        hidden_receiver_evidence->producer_machine;
                    out.back().contact_ready_state =
                        hidden_receiver_evidence->ready_state;
                }
                break;
            }
        }
    }
}

#include "guarded_pair_terminal.inc"
#include "guarded_pair_fallback.inc"

bool StrongPasswordSemantic(const std::string& value) {
    std::string compact;
    for (unsigned char ch : LowerAscii(value))
        if (std::isalnum(ch)) compact.push_back(static_cast<char>(ch));
    static const std::vector<std::string> terms = {
        "passok", "passwordok", "passcodeok", "pincodeok",
        "authok", "authorized", "unlockok", "password"
    };
    return std::any_of(terms.begin(), terms.end(), [&](const std::string& term) {
        return compact.find(term) != std::string::npos;
    });
}

bool HasStrongPasswordSemantics(const Machine& machine,
    const std::string& keypad_parameter) {
    if (StrongPasswordSemantic(keypad_parameter)) return true;
    int semantic_conditions = 0;
    std::set<std::string> semantic_parameters;
    auto scan = [&](const std::vector<Transition>& transitions) {
        for (const auto& transition : transitions) {
            for (const auto& condition : transition.conditions) {
                if (condition.parameter == keypad_parameter ||
                    !StrongPasswordSemantic(condition.parameter)) continue;
                ++semantic_conditions;
                semantic_parameters.insert(condition.parameter);
            }
        }
    };
    for (const auto& state : machine.states) scan(state.transitions);
    scan(machine.any_transitions);
    return semantic_conditions >= 2 && !semantic_parameters.empty();
}

std::optional<int> StrongNamedUnlockWriteTerminal(
    const Controller& controller, const Machine& machine) {
    int numeric_password_edges = 0;
    for (const auto& state : machine.states)
        for (const auto& transition : state.transitions)
            for (const auto& condition : transition.conditions)
                if (condition.mode == 6 &&
                    StrongPasswordSemantic(condition.parameter) &&
                    condition.threshold >= 0.0 && condition.threshold <= 19.0)
                    ++numeric_password_edges;
    if (numeric_password_edges < 3) return std::nullopt;

    std::vector<int> matches;
    for (std::size_t state_index = 0; state_index < machine.states.size();
         ++state_index) {
        const auto& state = machine.states[state_index];
        const std::string name = LowerAscii(Trim(state.name));
        if (name != "unlock" && name != "unlocked") continue;
        const bool concrete_outgoing = std::any_of(
            state.transitions.begin(), state.transitions.end(),
            [&](const Transition& transition) {
                return transition.destination >= 0 &&
                    transition.destination < static_cast<int>(machine.states.size());
            });
        if (concrete_outgoing) continue;
        for (const auto& write : state.writes) {
            const auto found = controller.parameter_defaults.find(write.name);
            const std::string write_name = LowerAscii(Trim(write.name));
            if (write.type == 0 && write.value > 0.5 &&
                (StrongPasswordSemantic(write.name) ||
                 write_name == "unlock" || write_name == "unlocked") &&
                found != controller.parameter_defaults.end() &&
                found->second.type == "bool" && found->second.value <= 0.5) {
                matches.push_back(static_cast<int>(state_index));
                break;
            }
        }
    }
    return matches.size() == 1
        ? std::optional<int>(matches.front()) : std::nullopt;
}

std::optional<int> MultiplexedUnlockTerminal(
    const Controller& controller, const Machine& machine) {
    std::vector<int> matches;
    for (std::size_t state_index = 0; state_index < machine.states.size();
         ++state_index) {
        const auto& state = machine.states[state_index];
        const std::string state_name = LowerAscii(Trim(state.name));
        if (state_name != "unlock" && state_name != "unlocked") continue;
        const bool concrete_outgoing = std::any_of(
            state.transitions.begin(), state.transitions.end(),
            [&](const Transition& transition) {
                return transition.destination >= 0 &&
                    transition.destination < static_cast<int>(machine.states.size());
            });
        if (concrete_outgoing) continue;
        bool semantic_write = false;
        for (const auto& write : state.writes) {
            const auto found = controller.parameter_defaults.find(write.name);
            if (write.type != 0 || found == controller.parameter_defaults.end())
                continue;
            // The state name already supplies the success semantics.  Lock
            // generators are free to obfuscate the bool parameter itself, so
            // accept any explicit bool polarity flip owned by this uniquely
            // named terminal instead of requiring a readable write name.
            const bool flips_default =
                (found->second.value <= 0.5 && write.value > 0.5) ||
                (found->second.value > 0.5 && write.value <= 0.5);
            bool has_opposite_write = false;
            for (std::size_t other_index = 0;
                 other_index < machine.states.size() && !has_opposite_write;
                 ++other_index) {
                if (other_index == state_index) continue;
                for (const auto& other : machine.states[other_index].writes)
                    if (other.type == 0 && other.name == write.name &&
                        std::abs(other.value - (1.0 - write.value)) <= 1e-5) {
                        has_opposite_write = true;
                        break;
                    }
            }
            if (found->second.type == "bool" &&
                (flips_default || has_opposite_write)) {
                semantic_write = true;
                break;
            }
        }
        if (semantic_write) matches.push_back(static_cast<int>(state_index));
    }
    return matches.size() == 1
        ? std::optional<int>(matches.front()) : std::nullopt;
}

void DetectMultiplexedFeatureKeypad(const Controller& controller,
    const Machine& machine, const MenuMaps& menu_maps,
    std::vector<Candidate>& out) {
    const auto terminal = MultiplexedUnlockTerminal(controller, machine);
    if (!terminal.has_value() || machine.default_state < 0 ||
        machine.default_state >= static_cast<int>(machine.states.size())) return;

    auto condition_at_default = [&](const Condition& condition) -> std::optional<bool> {
        double value = 0.0;
        if (condition.parameter == "AvatarVersion") value = 3.0;
        else {
            const auto found = controller.parameter_defaults.find(condition.parameter);
            if (found == controller.parameter_defaults.end()) return std::nullopt;
            value = found->second.value;
        }
        switch (condition.mode) {
        case 1: return value > 0.5;
        case 2: return value <= 0.5;
        case 3: return value > condition.threshold;
        case 4: return value < condition.threshold;
        case 6: return std::abs(value - condition.threshold) <= 1e-5;
        case 7: return std::abs(value - condition.threshold) > 1e-5;
        default: return std::nullopt;
        }
    };

    for (const auto& [parameter, pages] : menu_maps) {
        std::set<int> reachable{machine.default_state};
        bool changed = true;
        while (changed) {
            changed = false;
            for (int source : std::vector<int>(reachable.begin(), reachable.end())) {
                for (const auto& transition : machine.states[source].transitions) {
                    if (transition.destination < 0 ||
                        transition.destination >= static_cast<int>(machine.states.size()))
                        continue;
                    bool enabled = true;
                    for (const auto& condition : transition.conditions) {
                        if (condition.parameter == parameter) {
                            enabled = false;
                            break;
                        }
                        const auto match = condition_at_default(condition);
                        if (!match.has_value() || !*match) {
                            enabled = false;
                            break;
                        }
                    }
                    if (enabled && reachable.insert(transition.destination).second)
                        changed = true;
                }
            }
        }

        struct Edge { int value = 0; int destination = -1; bool mismatch = false; };
        std::map<int, std::vector<Edge>> edges;
        for (std::size_t source = 0; source < machine.states.size(); ++source) {
            bool mismatch_evidence = false;
            for (const auto& transition : machine.states[source].transitions) {
                int not_equal_count = 0;
                bool positive_guard = false;
                for (const auto& condition : transition.conditions) {
                    if (condition.parameter != parameter) continue;
                    if (condition.mode == 7) ++not_equal_count;
                    if (condition.mode == 3 && condition.threshold <= 0.0)
                        positive_guard = true;
                }
                const bool delayed_reject = transition.has_exit_time &&
                    transition.exit_time >= 0.75 &&
                    not_equal_count >= 1 && positive_guard;
                const bool explicit_wrong_set = not_equal_count >= 2;
                mismatch_evidence |= delayed_reject || explicit_wrong_set;
            }
            for (const auto& transition : machine.states[source].transitions) {
                if (transition.has_exit_time || transition.destination < 0 ||
                    transition.destination >= static_cast<int>(machine.states.size()))
                    continue;
                std::optional<int> value;
                bool clean = true;
                for (const auto& condition : transition.conditions) {
                    if (condition.parameter != parameter) continue;
                    if (condition.mode != 6 || value.has_value()) {
                        clean = false;
                        break;
                    }
                    const int rounded = static_cast<int>(
                        std::llround(condition.threshold));
                    if (rounded < 0 || rounded > 19 ||
                        std::abs(condition.threshold - rounded) > 1e-5) {
                        clean = false;
                        break;
                    }
                    value = rounded;
                }
                if (clean && value.has_value())
                    edges[static_cast<int>(source)].push_back(
                        {*value, transition.destination, mismatch_evidence});
            }
        }

        struct Solution { std::vector<int> values; int mismatch_states = 0; };
        std::vector<Solution> solutions;
        std::function<void(int,std::vector<int>&,int,std::set<int>&)> walk =
            [&](int state, std::vector<int>& values, int mismatch_states,
                std::set<int>& visiting) {
                if (state == *terminal) {
                    if (values.size() >= 3 && mismatch_states >= 3)
                        solutions.push_back({values, mismatch_states});
                    return;
                }
                if (values.size() >= 24 || !visiting.insert(state).second) return;
                const auto found = edges.find(state);
                if (found != edges.end()) {
                    for (const auto& edge : found->second) {
                        values.push_back(edge.value);
                        walk(edge.destination, values,
                            mismatch_states + (edge.mismatch ? 1 : 0), visiting);
                        values.pop_back();
                    }
                }
                visiting.erase(state);
            };
        std::set<int> starts = reachable;
        for (const auto& [source, ignored] : edges) {
            (void)ignored;
            starts.insert(source);
        }
        for (int start : starts) {
            std::vector<int> values;
            std::set<int> visiting;
            walk(start, values, 0, visiting);
        }
        std::size_t longest = 0;
        for (const auto& solution : solutions)
            longest = (std::max)(longest, solution.values.size());
        solutions.erase(std::remove_if(solutions.begin(), solutions.end(),
            [&](const Solution& solution) {
                return solution.values.size() != longest;
            }), solutions.end());
        std::sort(solutions.begin(), solutions.end(),
            [](const Solution& left, const Solution& right) {
                return left.values < right.values;
            });
        solutions.erase(std::unique(solutions.begin(), solutions.end(),
            [](const Solution& left, const Solution& right) {
                return left.values == right.values;
            }), solutions.end());
        if (solutions.empty()) continue;
        if (solutions.size() > 3) solutions.resize(3);
        const std::string confidence = solutions.size() == 1 ? u8"\u9ad8" : u8"\u53c2\u8003";
        for (const auto& solution : solutions) {
            for (const auto& [menu_name, mapping] : pages) {
                std::map<int,int> raw_to_logical;
                for (const auto& [logical, entry] : mapping)
                    raw_to_logical[entry.raw_value] = logical;
                std::ostringstream password, raw;
                bool complete = true;
                for (int value : solution.values) {
                    const auto logical = raw_to_logical.find(value);
                    if (logical == raw_to_logical.end()) {
                        complete = false;
                        break;
                    }
                    password << logical->second;
                    raw << value;
                }
                if (!complete) continue;
                out.push_back({controller.name, parameter, raw.str(), password.str(),
                    std::string(u8"\u666e\u901a\u529f\u80fd\u53c2\u6570\u590d\u7528\u6570\u5b57\u94fe + \u5ef6\u65f6\u9519\u8bef\u56de\u9000\u8def\u5f84 | \u83dc\u5355\u300c") +
                        menu_name + u8"\u300d\u4ea4\u53c9\u9a8c\u8bc1",
                    confidence, *terminal,
                    "native_button_pulse_dispatch_terminal"});
                break;
            }
        }
    }
}

PressReleaseDetection DetectPressReleaseKeypad(const Snapshot& snapshot,
    const Controller& controller, const Machine& machine,
    const MenuMaps& menu_maps,
    std::vector<Candidate>& out) {
    struct Step {
        int raw_value = 0;
        int destination = -1;
    };

    PressReleaseDetection detection;
    std::set<std::string> parameters;
    for (const auto& state : machine.states) {
        for (const auto& transition : state.transitions) {
            for (const auto& condition : transition.conditions) {
                if (condition.mode == 6 && !condition.parameter.empty() &&
                    condition.threshold >= 0.0 && condition.threshold <= 19.0)
                    parameters.insert(condition.parameter);
            }
        }
    }

    // A common generated keypad uses two states per digit: INPUT == N enters
    // the pressed state and INPUT != N advances after the button is released.
    // Detect the structure independently of menus. Menus are only required to
    // translate raw values into the buttons users actually see.
    for (const auto& parameter : parameters) {
        std::map<int, std::vector<Step>> steps;
        for (std::size_t source = 0; source < machine.states.size(); ++source) {
            for (const auto& press : machine.states[source].transitions) {
                if (press.destination < 0 ||
                    press.destination >= static_cast<int>(machine.states.size())) continue;
                for (const auto& condition : press.conditions) {
                    if (condition.mode != 6 || condition.parameter != parameter) continue;
                    const int raw_value = static_cast<int>(std::llround(condition.threshold));
                    if (raw_value < 0 || raw_value > 19) continue;

                    const auto& pressed_state =
                        machine.states[static_cast<std::size_t>(press.destination)];
                    for (const auto& release : pressed_state.transitions) {
                        if (release.destination < 0 ||
                            release.destination >= static_cast<int>(machine.states.size()) ||
                            release.destination == static_cast<int>(source)) continue;
                        const bool matching_release = std::any_of(
                            release.conditions.begin(), release.conditions.end(),
                            [&](const Condition& release_condition) {
                                return release_condition.mode == 7 &&
                                    release_condition.parameter == parameter &&
                                    static_cast<int>(std::llround(release_condition.threshold)) == raw_value;
                            });
                        if (matching_release)
                            steps[static_cast<int>(source)].push_back({raw_value, release.destination});
                    }
                }
            }
        }
        if (steps.empty()) continue;

        struct Path {
            std::vector<int> raw_values;
            int terminal = -1;
        };
        if (machine.default_state < 0 ||
            machine.default_state >= static_cast<int>(machine.states.size())) continue;
        std::vector<Path> paths;
        std::vector<int> current;
        std::set<int> visiting;
        std::function<void(int,int)> enumerate = [&](int state, int depth) {
            if (paths.size() >= 64) return;
            if (depth >= 32 || !visiting.insert(state).second) {
                if (current.size() >= 3) paths.push_back({current, state});
                return;
            }
            const auto found = steps.find(state);
            if (found == steps.end() || found->second.empty()) {
                if (current.size() >= 3) paths.push_back({current, state});
            } else {
                for (const auto& step : found->second) {
                    current.push_back(step.raw_value);
                    enumerate(step.destination, depth + 1);
                    current.pop_back();
                    if (paths.size() >= 64) break;
                }
            }
            visiting.erase(state);
        };
        enumerate(machine.default_state, 0);
        if (paths.empty()) continue;
        const std::size_t longest = std::max_element(paths.begin(), paths.end(),
            [](const Path& left, const Path& right) {
                return left.raw_values.size() < right.raw_values.size();
            })->raw_values.size();
        paths.erase(std::remove_if(paths.begin(), paths.end(),
            [&](const Path& path) { return path.raw_values.size() != longest; }),
            paths.end());
        std::sort(paths.begin(), paths.end(),
            [](const Path& left, const Path& right) {
                if (left.raw_values != right.raw_values)
                    return left.raw_values < right.raw_values;
                return left.terminal < right.terminal;
            });
        paths.erase(std::unique(paths.begin(), paths.end(),
            [](const Path& left, const Path& right) {
                return left.raw_values == right.raw_values &&
                    left.terminal == right.terminal;
            }), paths.end());
        const bool unique_path = paths.size() == 1;
        if (paths.size() > 3) paths.resize(3);

        const auto mapped = menu_maps.find(parameter);
        if (mapped == menu_maps.end()) {
            const int terminal = unique_path ? paths.front().terminal : -1;
            const bool terminal_safe = terminal >= 0 &&
                terminal < static_cast<int>(machine.states.size()) &&
                (std::none_of(machine.states[static_cast<std::size_t>(terminal)].transitions.begin(),
                    machine.states[static_cast<std::size_t>(terminal)].transitions.end(),
                    [&](const Transition& transition) {
                        return transition.destination >= 0 &&
                            transition.destination < static_cast<int>(machine.states.size());
                    }) || StrongPressReleaseSemanticTerminal(controller, machine, terminal));
            if (terminal_safe && HasStrongPasswordSemantics(machine, parameter)) {
                if (detection.safe_unlock_state < 0) {
                    detection.safe_unlock_state = terminal;
                    detection.needs_menu_recovery = true;
                } else if (detection.safe_unlock_state != terminal) {
                    // Multiple competing terminals are ambiguous: preserve the
                    // analysis hint but refuse to issue an automatic write plan.
                    detection.safe_unlock_state = -1;
                }
            }
            if (snapshot.expression_parameters.count(parameter) != 0 &&
                HasStrongPasswordSemantics(machine, parameter)) {
                for (const auto& path : paths) {
                    if (path.raw_values.size() < 3 ||
                        path.raw_values.size() > 32)
                        continue;
                    std::ostringstream password;
                    std::ostringstream raw;
                    bool direct_values = true;
                    for (std::size_t index = 0;
                         index < path.raw_values.size(); ++index) {
                        const int value = path.raw_values[index];
                        if (value < 0 || value > 9) {
                            direct_values = false;
                            break;
                        }
                        password << value;
                        if (index) raw << ',';
                        raw << value;
                    }
                    if (!direct_values) continue;
                    Candidate candidate{controller.name, parameter, raw.str(),
                        password.str(),
                        u8"按下/释放双阶段状态链 | 菜单引用缺失，按 OSC 原始整数值输入",
                        u8"参考", terminal_safe ? path.terminal : -1,
                        terminal_safe
                            ? "native_press_release_semantic_terminal" : ""};
                    candidate.input_kind = "osc";
                    candidate.guide_allowed = false;
                    out.push_back(std::move(candidate));
                }
            }
            continue;
        }

        for (const auto& path : paths) {
            if (path.terminal < 0 ||
                path.terminal >= static_cast<int>(machine.states.size())) continue;
            // A recovered sequence can be shown even when its last state has
            // runtime branches, but an automatic bypass remains unique-only.
            const auto& terminal_state =
                machine.states[static_cast<std::size_t>(path.terminal)];
            const bool terminal_is_exit = std::none_of(
                terminal_state.transitions.begin(), terminal_state.transitions.end(),
                [&](const Transition& transition) {
                    return transition.destination >= 0 &&
                        transition.destination < static_cast<int>(machine.states.size());
                });
            const bool terminal_is_semantic = StrongPressReleaseSemanticTerminal(
                controller, machine, path.terminal);
            const bool terminal_is_safe = terminal_is_exit || terminal_is_semantic;
            for (const auto& [menu_name, mapping] : mapped->second) {
                std::map<int,int> raw_to_logical;
                for (const auto& [logical, entry] : mapping)
                    raw_to_logical.emplace(entry.raw_value, logical);
                std::ostringstream password, raw;
                bool complete = true;
                for (int raw_value : path.raw_values) {
                    const auto digit = raw_to_logical.find(raw_value);
                    if (digit == raw_to_logical.end()) {
                        complete = false;
                        break;
                    }
                    password << digit->second;
                    raw << raw_value;
                }
                if (!complete) continue;

                out.push_back({
                    controller.name,
                    parameter,
                    raw.str(),
                    password.str(),
                    std::string(u8"按下/释放双阶段状态链 | 数字菜单「") + menu_name + u8"」交叉验证",
                    unique_path ? u8"高" : u8"参考",
                    terminal_is_safe ? path.terminal : -1,
                    terminal_is_exit ? "native_press_release_terminal" :
                        (terminal_is_semantic
                            ? "native_press_release_semantic_terminal" : "")
                });
                break;
            }
        }
    }
    return detection;
}

void DetectButtonPulseDispatchKeypad(const Controller& controller,
    const Machine& machine, const MenuMaps& menu_maps,
    std::vector<Candidate>& out) {
    if (machine.default_state < 0 ||
        machine.default_state >= static_cast<int>(machine.states.size()))
        return;

    // Some generated locks accept a visible digit immediately, advance a
    // prefix state, then hold the fifth button for one second.  The delayed
    // edge enters a transient dispatch state whose first frame still sees the
    // held menu value.  Unity can therefore select a final digit edge before
    // the dispatch state's unconditional exit transition resets the machine.
    // Recover only the fully evidenced form: numeric menu, unique prefix,
    // delayed dispatch, exactly one semantic unlock destination.
    for (const auto& [parameter, pages] : menu_maps) {
        for (const auto& [menu_name, mapping] : pages) {
            std::map<int, int> raw_to_logical;
            for (const auto& [logical, entry] : mapping)
                raw_to_logical[entry.raw_value] = logical;
            if (raw_to_logical.size() < 4) continue;

            struct Prefix { std::vector<int> raw; int state = -1; };
            std::vector<Prefix> prefixes{{{}, machine.default_state}};
            std::vector<Prefix> dispatch_prefixes;
            for (int depth = 0; depth < 12 && !prefixes.empty(); ++depth) {
                std::vector<Prefix> next;
                for (const auto& prefix : prefixes) {
                    if (prefix.state < 0 ||
                        prefix.state >= static_cast<int>(machine.states.size()))
                        continue;
                    const auto& state = machine.states[
                        static_cast<std::size_t>(prefix.state)];

                    std::set<int> dispatch_destinations;
                    for (const auto& transition : state.transitions) {
                        if (!transition.has_exit_time ||
                            transition.exit_time < 0.75 ||
                            transition.destination < 0 ||
                            transition.destination >= static_cast<int>(machine.states.size()))
                            continue;
                        bool same_parameter = false;
                        for (const auto& condition : transition.conditions)
                            if (condition.parameter == parameter)
                                same_parameter = true;
                        if (same_parameter)
                            dispatch_destinations.insert(transition.destination);
                    }
                    if (dispatch_destinations.size() == 1 &&
                        prefix.raw.size() >= 3)
                        dispatch_prefixes.push_back(
                            {prefix.raw, *dispatch_destinations.begin()});

                    std::map<int, int> advances;
                    for (const auto& transition : state.transitions) {
                        if (transition.has_exit_time ||
                            transition.destination < 0 ||
                            transition.destination >= static_cast<int>(machine.states.size()))
                            continue;
                        std::optional<int> raw;
                        bool clean = true;
                        for (const auto& condition : transition.conditions) {
                            if (condition.parameter == parameter && condition.mode == 6) {
                                const int value = static_cast<int>(
                                    std::llround(condition.threshold));
                                if (raw_to_logical.count(value)) raw = value;
                                else clean = false;
                            } else if (condition.parameter == parameter) {
                                clean = false;
                            }
                        }
                        if (clean && raw.has_value())
                            advances[*raw] = transition.destination;
                    }
                    for (const auto& [raw, destination] : advances) {
                        Prefix child = prefix;
                        child.raw.push_back(raw);
                        child.state = destination;
                        next.push_back(std::move(child));
                    }
                }
                prefixes = std::move(next);
            }

            struct Solved { std::vector<int> raw; int terminal = -1; };
            std::vector<Solved> solved;
            for (const auto& prefix : dispatch_prefixes) {
                const auto& dispatch = machine.states[
                    static_cast<std::size_t>(prefix.state)];
                const bool has_immediate_reset = std::any_of(
                    dispatch.transitions.begin(), dispatch.transitions.end(),
                    [&](const Transition& transition) {
                        return transition.conditions.empty() &&
                            transition.has_exit_time && transition.exit_time <= 0.001;
                    });
                if (!has_immediate_reset) continue;

                std::vector<std::pair<int, int>> terminals;
                for (const auto& transition : dispatch.transitions) {
                    if (transition.destination < 0 ||
                        transition.destination >= static_cast<int>(machine.states.size()))
                        continue;
                    for (const auto& condition : transition.conditions) {
                        if (condition.mode != 6 ||
                            condition.parameter != parameter) continue;
                        const int raw = static_cast<int>(
                            std::llround(condition.threshold));
                        if (!raw_to_logical.count(raw)) continue;
                        const auto& terminal = machine.states[
                            static_cast<std::size_t>(transition.destination)];
                        const bool terminal_state = std::none_of(
                            terminal.transitions.begin(), terminal.transitions.end(),
                            [&](const Transition& outgoing) {
                                return outgoing.destination >= 0 &&
                                    outgoing.destination < static_cast<int>(machine.states.size());
                            });
                        if (!terminal_state || terminal.writes.empty()) continue;
                        terminals.push_back({raw, transition.destination});
                    }
                }

                // The unlock write may be obfuscated, but the dispatch must
                // have exactly one destination carrying this concrete write
                // signature.  If several digits write the same parameter and
                // value, the lock is ambiguous and remains fail-closed.
                for (const auto& [raw, terminal_index] : terminals) {
                    const auto& terminal = machine.states[
                        static_cast<std::size_t>(terminal_index)];
                    bool unique_write_signature = true;
                    for (const auto& [other_raw, other_index] : terminals) {
                        if (other_index == terminal_index) continue;
                        const auto& other = machine.states[
                            static_cast<std::size_t>(other_index)];
                        for (const auto& write : terminal.writes)
                            for (const auto& other_write : other.writes)
                                if (write.name == other_write.name &&
                                    write.type == other_write.type &&
                                    std::abs(write.value - other_write.value) < 1e-5)
                                    unique_write_signature = false;
                    }
                    if (!unique_write_signature) continue;
                    auto sequence = prefix.raw;
                    sequence.push_back(raw);
                    solved.push_back({std::move(sequence), terminal_index});
                }
            }
            if (solved.empty()) continue;
            const auto longest = std::max_element(solved.begin(), solved.end(),
                [](const Solved& left, const Solved& right) {
                    return left.raw.size() < right.raw.size();
                })->raw.size();
            solved.erase(std::remove_if(solved.begin(), solved.end(),
                [&](const Solved& candidate) {
                    return candidate.raw.size() != longest;
                }), solved.end());
            std::sort(solved.begin(), solved.end(),
                [](const Solved& left, const Solved& right) {
                    if (left.raw != right.raw) return left.raw < right.raw;
                    return left.terminal < right.terminal;
                });
            if (solved.size() > 3) solved.resize(3);
            const std::string confidence = solved.size() == 1 ? u8"高" : u8"参考";
            for (const auto& solution : solved) {
                std::ostringstream password, raw;
                bool complete = true;
                for (int value : solution.raw) {
                    const auto logical = raw_to_logical.find(value);
                    if (logical == raw_to_logical.end()) { complete = false; break; }
                    password << logical->second;
                    raw << value;
                }
                if (!complete) continue;
                out.push_back({controller.name, parameter, raw.str(), password.str(),
                    std::string(u8"数字菜单前缀 + 延时按键派发路径 | 菜单「") +
                        menu_name + u8"」交叉验证",
                    confidence, solution.terminal,
                    "native_button_pulse_dispatch_terminal"});
            }
        }
    }
}

bool ConflictsWithNonPasswordMenus(const Snapshot& snapshot, const Candidate& candidate) {
    if (candidate.input_kind == "osc") return false;
    int controls = 0;
    int non_numeric = 0;
    std::set<int> values;
    std::set<std::string> menus;
    for (const auto& menu : snapshot.menus) {
        for (const auto& control : menu.controls) {
            if (control.parameter != candidate.parameter) continue;
            ++controls;
            values.insert(static_cast<int>(std::llround(control.value)));
            menus.insert(menu.id);
            const auto name = Trim(control.name);
            const bool numeric = !name.empty() && name.size() <= 2 &&
                std::all_of(name.begin(), name.end(), [](unsigned char ch) { return std::isdigit(ch); });
            if (!numeric) ++non_numeric;
        }
    }
    return controls >= 3 && non_numeric >= 3 && menus.size() >= 2 && values.size() >= 2;
}

void ApplyMenuMaps(const Snapshot& snapshot, const RuleProfile& rules,
    std::vector<Candidate>& candidates, std::vector<Guide>& guides) {
    const auto maps = BuildMenuMaps(snapshot, rules);
    std::set<std::string> seen;
    for (auto& candidate : candidates) {
        auto found = maps.find(candidate.parameter);

        // Wait_Digit controllers encode the sequence in state names and often
        // use a separate generic menu parameter such as SysActionInt.  Bind it
        // only when the entire snapshot contains exactly one numeric parameter
        // whose merged menu map covers every recovered digit.  Ambiguity remains
        // fail-closed and produces no guide.
        if (found == maps.end() && ContainsI(candidate.parameter, "wait_digit")) {
            auto unique = maps.end();
            for (auto current = maps.begin(); current != maps.end(); ++current) {
                bool covers = false;
                for (const auto& page : current->second) {
                    if (std::all_of(candidate.password.begin(), candidate.password.end(),
                        [&](unsigned char ch) {
                            return std::isdigit(ch) &&
                                page.second.count(ch - '0') != 0;
                        })) {
                        covers = true;
                        break;
                    }
                }
                if (!covers) continue;
                if (unique != maps.end()) {
                    unique = maps.end();
                    break;
                }
                unique = current;
            }
            if (unique != maps.end()) {
                found = unique;
                candidate.parameter = unique->first;
                candidate.note += (candidate.note.empty() ? "" : " | ") +
                    std::string(u8"唯一完整数字菜单参数交叉验证");
            }
        }

        if (found == maps.end() || candidate.password.empty() ||
            !std::all_of(candidate.password.begin(), candidate.password.end(),
                [](unsigned char ch) { return std::isdigit(ch); }))
            continue;

        for (const auto& [menu, mapping] : found->second) {
            std::vector<std::string> keys;
            std::vector<int> values;
            bool ok = true;
            for (char ch : candidate.password) {
                const int logical_digit = ch - '0';
                const auto entry = mapping.find(logical_digit);
                if (entry == mapping.end()) {
                    ok = false;
                    break;
                }
                keys.push_back(entry->second.name);
                values.push_back(entry->second.raw_value);
            }
            if (!ok) continue;

            std::ostringstream visible, route;
            for (std::size_t i = 0; i < keys.size(); ++i) {
                visible << keys[i];
                if (i) route << u8" → ";
                route << keys[i];
            }
            candidate.password = visible.str();
            candidate.note += (candidate.note.empty() ? "" : " | ") +
                std::string(u8"菜单按钮名称与状态机值交叉验证 | 进入菜单「") +
                menu + u8"」后依次点击 " + route.str();
            candidate.menu_mapped = true;
            // Matching menu buttons prove that the raw values are enterable;
            // they do not prove that the sequence reaches an unlock state.
            const std::string key =
                candidate.password + '|' + menu + '|' + candidate.parameter;
            if (candidate.guide_allowed && seen.insert(key).second)
                guides.push_back({
                    candidate.password, menu, candidate.parameter, keys, values
                });
            break;
        }
    }
}

struct ParallelDialSetting {
    std::string menu;
    std::string parent_id;
    std::string parent_menu;
    std::string child_label;
    std::string parameter;
    std::set<int> values;
    int order = -1;
};

struct ParallelDialParentLink {
    std::string parent_id;
    std::string parent_menu;
    std::string child_label;
    int order = -1;
};

void DetectResetGuardedCombination(const std::string& controller,
    const Machine& machine, std::vector<Candidate>& out) {
    if (machine.default_state < 0 ||
        machine.default_state >= static_cast<int>(machine.states.size())) return;

    std::set<int> reset_states;
    for (std::size_t index = 0; index < machine.states.size(); ++index) {
        const auto& state = machine.states[index];
        if (!ContainsI(state.name, "reset")) continue;
        const bool returns_to_default = std::any_of(
            state.transitions.begin(), state.transitions.end(),
            [&](const Transition& transition) {
                return transition.destination == machine.default_state &&
                    transition.conditions.empty();
            });
        if (returns_to_default) reset_states.insert(static_cast<int>(index));
    }
    if (reset_states.empty()) return;

    auto is_unlock = [&](int index) {
        if (index < 0 || index >= static_cast<int>(machine.states.size())) return false;
        const auto& name = machine.states[static_cast<std::size_t>(index)].name;
        return ContainsI(name, "unlock") || ContainsI(name, "authorized") ||
            ContainsI(name, "access granted") || ContainsI(name, u8"解锁成功");
    };

    std::string parameter;
    std::vector<int> digits;
    std::set<int> visited;
    int current = machine.default_state;
    int terminal = -1;
    for (int depth = 0; depth < 10; ++depth) {
        if (!visited.insert(current).second || reset_states.count(current)) return;
        const auto& state = machine.states[static_cast<std::size_t>(current)];
        const Transition* forward = nullptr;
        int forward_digit = -1;
        bool has_guarded_reset = false;

        for (const auto& transition : state.transitions) {
            if (transition.destination < 0 ||
                transition.destination >= static_cast<int>(machine.states.size())) continue;
            if (reset_states.count(transition.destination)) {
                const bool meaningful_guard = !transition.conditions.empty() &&
                    std::any_of(transition.conditions.begin(), transition.conditions.end(),
                        [&](const Condition& condition) {
                            return condition.mode == 7 || condition.mode == 1 ||
                                ContainsI(condition.parameter, "reset");
                        });
                has_guarded_reset |= meaningful_guard;
                continue;
            }

            if (transition.conditions.size() != 1 ||
                transition.conditions.front().mode != 6) return;
            const auto& condition = transition.conditions.front();
            const int digit = static_cast<int>(std::llround(condition.threshold));
            if (std::fabs(condition.threshold - digit) > 0.0001 ||
                digit < 0 || digit > 9 || forward != nullptr) return;
            if (parameter.empty()) parameter = condition.parameter;
            else if (parameter != condition.parameter) return;
            forward = &transition;
            forward_digit = digit;
        }

        if (!forward || !has_guarded_reset || parameter.empty()) return;
        digits.push_back(forward_digit);
        current = forward->destination;
        if (is_unlock(current)) {
            terminal = current;
            break;
        }
    }
    if (terminal < 0 || digits.size() < 3) return;

    std::ostringstream password, detail;
    for (std::size_t index = 0; index < digits.size(); ++index) {
        password << digits[index];
        if (index) detail << u8" → ";
        detail << digits[index];
    }
    out.push_back({controller, parameter, password.str(), password.str(),
        u8"唯一前进输入链 + 每层错误重置 + 明确 Unlock 终点 | " + detail.str(),
        u8"高", terminal, "native_reset_guarded_terminal"});
}

int LastAsciiNumber(const std::string& value) {
    int last = -1;
    int current = -1;
    for (unsigned char ch : value) {
        if (std::isdigit(ch)) {
            if (current < 0) current = 0;
            current = current * 10 + (ch - '0');
        } else if (current >= 0) {
            last = current;
            current = -1;
        }
    }
    return current >= 0 ? current : last;
}

void DetectParallelDialCombination(const std::string& controller,
    const Machine& machine, const Snapshot& snapshot,
    std::vector<Candidate>& out, std::vector<Guide>& guides) {
    std::map<std::string, std::vector<ParallelDialParentLink>> parent_links;
    for (const auto& parent : snapshot.menus) {
        for (std::size_t index = 0; index < parent.controls.size(); ++index) {
            const auto& control = parent.controls[index];
            if (control.submenu.empty()) continue;
            parent_links[control.submenu].push_back({
                parent.id, parent.name, Trim(control.name),
                static_cast<int>(index)});
        }
    }

    std::map<std::string, ParallelDialSetting> dial_settings;
    for (const auto& menu : snapshot.menus) {
        std::optional<ParallelDialParentLink> selected_parent;
        const auto linked = parent_links.find(menu.id);
        if (linked != parent_links.end()) {
            for (const auto& link : linked->second) {
                const bool dial_name = ContainsI(menu.name, u8"拨码") ||
                    ContainsI(menu.name, "dial") || ContainsI(menu.name, "rotary") ||
                    ContainsI(link.child_label, u8"拨码") ||
                    ContainsI(link.child_label, "dial") ||
                    ContainsI(link.child_label, "rotary");
                const bool lock_context = LooksLock(menu.name) ||
                    LooksLock(link.parent_menu) || LooksLock(link.child_label);
                if (!dial_name || !lock_context) continue;
                if (selected_parent && selected_parent->parent_id != link.parent_id) {
                    selected_parent.reset();
                    break;
                }
                selected_parent = link;
            }
        }

        // Some hardened snapshots preserve the breadcrumb in m_Name but lose
        // the parent PPtr.  It remains safe to classify the combination, while
        // the guide is emitted only if the resulting parent menu is reachable.
        if (!selected_parent) {
            const bool dial_name = ContainsI(menu.name, u8"拨码") ||
                ContainsI(menu.name, "dial") || ContainsI(menu.name, "rotary");
            if (!dial_name || !LooksLock(menu.name)) continue;
            const std::string separator = u8" » ";
            const auto split = menu.name.rfind(separator);
            if (split == std::string::npos) continue;
            const std::string parent = menu.name.substr(0, split);
            selected_parent = ParallelDialParentLink{
                "breadcrumb:" + parent, parent,
                menu.name.substr(split + separator.size()),
                LastAsciiNumber(menu.name)};
        }

        std::map<std::string, std::vector<const MenuControl*>> grouped;
        for (const auto& control : menu.controls)
            if (!control.parameter.empty()) grouped[control.parameter].push_back(&control);
        for (const auto& [parameter, controls] : grouped) {
            if (controls.size() < 4 || controls.size() > 10) continue;
            std::set<int> values;
            bool integral_digits = true;
            for (const auto* control : controls) {
                const int value = static_cast<int>(std::llround(control->value));
                if (std::fabs(control->value - value) > 0.0001 || value < 0 || value > 9) {
                    integral_digits = false;
                    break;
                }
                values.insert(value);
            }
            if (!integral_digits || values.size() != controls.size()) continue;
            dial_settings[parameter] = {
                menu.name, selected_parent->parent_id, selected_parent->parent_menu,
                selected_parent->child_label, parameter, std::move(values),
                selected_parent->order >= 0 ? selected_parent->order : LastAsciiNumber(menu.name)};
        }
    }
    if (dial_settings.size() < 3) return;

    std::set<std::pair<std::string, int>> not_equal_guards;
    auto collect_guards = [&](const Transition& transition) {
        for (const auto& condition : transition.conditions) {
            if (condition.mode != 7) continue;
            const int value = static_cast<int>(std::llround(condition.threshold));
            if (std::fabs(condition.threshold - value) <= 0.0001)
                not_equal_guards.insert({condition.parameter, value});
        }
    };
    for (const auto& state : machine.states)
        for (const auto& transition : state.transitions) collect_guards(transition);
    for (const auto& transition : machine.any_transitions) collect_guards(transition);

    struct SelectedDial {
        const ParallelDialSetting* setting;
        int value;
        std::size_t original_order;
    };
    auto inspect = [&](int source, const Transition& transition) {
        if (transition.destination < 0 ||
            transition.destination >= static_cast<int>(machine.states.size()) ||
            transition.destination == source) return;

        std::vector<SelectedDial> selected;
        std::set<std::string> parameters;
        for (const auto& condition : transition.conditions) {
            if (condition.mode != 6) continue;
            const auto found = dial_settings.find(condition.parameter);
            if (found == dial_settings.end()) continue;
            const int value = static_cast<int>(std::llround(condition.threshold));
            if (std::fabs(condition.threshold - value) > 0.0001 ||
                !found->second.values.count(value) ||
                !parameters.insert(condition.parameter).second) continue;
            selected.push_back({&found->second, value, selected.size()});
        }
        if (selected.size() < 3 || selected.size() > 10) return;

        const std::string parent_id = selected.front().setting->parent_id;
        if (parent_id.empty() ||
            !std::all_of(selected.begin(), selected.end(),
                [&](const SelectedDial& item) {
                    return item.setting->parent_id == parent_id;
                })) return;

        std::size_t guarded = 0;
        for (const auto& item : selected)
            if (not_equal_guards.count({item.setting->parameter, item.value})) ++guarded;
        // The paired NotEqual exits prove that the multi-Equals transition is
        // the success combination rather than an ordinary feature blend.
        if (guarded != selected.size()) return;

        bool sortable = std::all_of(selected.begin(), selected.end(),
            [](const SelectedDial& item) { return item.setting->order >= 0; });
        if (sortable) {
            std::set<int> orders;
            for (const auto& item : selected) orders.insert(item.setting->order);
            sortable = orders.size() == selected.size();
        }
        if (sortable)
            std::stable_sort(selected.begin(), selected.end(),
                [](const SelectedDial& left, const SelectedDial& right) {
                    return left.setting->order < right.setting->order;
                });

        std::ostringstream password, parameters_joined, detail;
        for (std::size_t index = 0; index < selected.size(); ++index) {
            const auto& item = selected[index];
            password << item.value;
            if (index) {
                parameters_joined << '+';
                detail << u8" → ";
            }
            parameters_joined << item.setting->parameter;
            detail << (item.setting->child_label.empty()
                ? std::string(u8"拨码盘") + std::to_string(index + 1)
                : item.setting->child_label) << '=' << item.value;
        }
        out.push_back({controller, parameters_joined.str(), password.str(),
            password.str(), u8"多拨码盘组合条件交叉验证 | " + detail.str(),
            u8"高", transition.destination, "native_parallel_dial_terminal"});

        // A joined parameter name is not a real Animator parameter. Preserve
        // an independently mapped manual candidate instead of asking the
        // single-parameter menu mapper to resolve "p1+p2+...". This does not
        // authorize a rewrite or promote the legacy structural proof.
        std::set<std::string> reachable_menus;
        std::deque<std::string> pending_menus(snapshot.active_root_menu_ids.begin(),
            snapshot.active_root_menu_ids.end());
        while (!pending_menus.empty()) {
            const auto id = pending_menus.front(); pending_menus.pop_front();
            if (!reachable_menus.insert(id).second) continue;
            for (const auto& menu : snapshot.menus) {
                if (menu.id != id) continue;
                for (const auto& control : menu.controls)
                    if (control.type == 103 && !control.submenu.empty())
                        pending_menus.push_back(control.submenu);
            }
        }
        bool independently_mapped = reachable_menus.count(parent_id) != 0 &&
            transition.conditions.size() == selected.size();
        for (const auto& item : selected) {
            const auto declared = snapshot.expression_parameter_defaults.find(item.setting->parameter);
            if (declared == snapshot.expression_parameter_defaults.end() ||
                declared->second.type != "int") { independently_mapped = false; break; }
            int matching_pages = 0;
            for (const auto& menu : snapshot.menus) {
                if (menu.id != parent_id) continue;
                for (const auto& branch : menu.controls) {
                    if (branch.type != 103 || !branch.parameter.empty()) continue;
                    for (const auto& page : snapshot.menus) {
                        if (page.id != branch.submenu || !reachable_menus.count(page.id)) continue;
                        int matches = 0;
                        bool consistent = !page.controls.empty();
                        for (const auto& key : page.controls) {
                            consistent = consistent && key.type == 102 &&
                                key.parameter == item.setting->parameter;
                            if (key.value == item.value) ++matches;
                        }
                        if (consistent && matches == 1) ++matching_pages;
                    }
                }
            }
            if (matching_pages != 1) independently_mapped = false;
        }
        if (independently_mapped) {
            Candidate manual = out.back();
            manual.confidence = u8"参考";
            manual.menu_mapped = true;
            manual.guide_allowed = false;
            manual.unlock_state = -1;
            manual.unlock_method.clear();
            manual.family = "parallel_dial_manual_mapping";
            manual.note = std::string(u8"逐盘设置并保持选中（不是连续按键）：") + detail.str() +
                u8" | 按原始菜单值定位；文字重复或图标自定义时请核对对应选项。候选不授权自动移除。";
            out.push_back(std::move(manual));
        }

        // A parallel dial lock spans several sibling submenus.  Represent the
        // route as alternating submenu/value steps so the existing wheel guide
        // can enter a dial, select its raw value, return, and continue with the
        // next sibling without a model-specific UI path.
        std::string parent_menu;
        std::vector<std::string> keys;
        std::vector<int> values;
        bool common_parent = true;
        for (const auto& item : selected) {
            if (parent_menu.empty()) parent_menu = item.setting->parent_menu;
            else if (parent_menu != item.setting->parent_menu) {
                common_parent = false;
                break;
            }
            keys.push_back(item.setting->child_label);
            values.push_back(-99999);  // submenu steps match by unique label
            keys.push_back(std::to_string(item.value));
            values.push_back(item.value);  // icon-only dial keys match by raw value
        }
        if (common_parent && !parent_menu.empty())
            guides.push_back({password.str(), parent_menu,
                parameters_joined.str(), std::move(keys), std::move(values)});
    };

    for (std::size_t source = 0; source < machine.states.size(); ++source)
        for (const auto& transition : machine.states[source].transitions)
            inspect(static_cast<int>(source), transition);
    for (const auto& transition : machine.any_transitions) inspect(-1, transition);
}

// Generated security menus sometimes use ordinary Button controls that write
// one numeric input, then shift values through ordered Parameter Drivers.
// The comparator keeps an exact transition and a matching NotEqual failure
// set.  Prove both halves before exposing the reconstructed menu sequence or
// a state rewrite plan.
void DetectNumericButtonShiftCombination(const Controller& controller,
    const Snapshot& snapshot, std::vector<Candidate>& out,
    std::vector<Guide>& guides, json::Value::Array& state_bypasses,
    std::set<ReversePlanKey>& committed, const RuleProfile& rules) {
    if (snapshot.controller_fail || snapshot.analysis_depth == "fast" ||
        snapshot.active_root_menu_ids.empty() || controller.path_id.empty() ||
        !SafePlanMethodAllowed(rules, "native_parallel_dial_terminal")) return;
    std::map<std::pair<std::string, ReversePlanKey>,
        std::tuple<Candidate, Guide, json::Value>> pending;
    const auto reachable_states = [](const Machine& machine) {
        std::set<int> seen; std::deque<int> work{machine.default_state};
        while (!work.empty()) {
            const int index = work.front(); work.pop_front();
            if (index < 0 || index >= static_cast<int>(machine.states.size()) ||
                !seen.insert(index).second) continue;
            for (const auto& edge : machine.states[index].transitions)
                work.push_back(edge.destination);
        }
        return seen;
    };
    std::map<std::string, const Menu*> menus;
    for (const auto& menu : snapshot.menus) menus[menu.id] = &menu;
    std::set<std::string> reachable;
    std::deque<std::string> queue(snapshot.active_root_menu_ids.begin(),
        snapshot.active_root_menu_ids.end());
    while (!queue.empty()) {
        const auto id = queue.front(); queue.pop_front();
        if (!reachable.insert(id).second || !menus.count(id)) continue;
        for (const auto& control : menus.at(id)->controls)
            if (control.type == 103 && !control.submenu.empty()) queue.push_back(control.submenu);
    }
    std::map<std::string, std::vector<std::pair<int, std::string>>> surfaces;
    for (const auto& menu : snapshot.menus) {
        if (!reachable.count(menu.id)) continue;
        for (const auto& control : menu.controls) {
            if (control.type != 101 || control.parameter.empty()) continue;
            const int value = static_cast<int>(std::llround(control.value));
            if (std::fabs(control.value - value) > 0.0001 || value < 0 || value > 9)
                continue;
            surfaces[control.parameter].push_back({value, menu.name});
        }
    }
    for (auto& [parameter, values] : surfaces) {
        std::sort(values.begin(), values.end());
        values.erase(std::unique(values.begin(), values.end()), values.end());
    }
    for (const auto& [input, buttons] : surfaces) {
        if (buttons.size() < 3) continue;
        const auto input_default = snapshot.expression_parameter_defaults.find(input);
        if (input_default == snapshot.expression_parameter_defaults.end() ||
            input_default->second.type != "int" || input_default->second.value != 0 ||
            !controller.parameter_defaults.count(input)) continue;
        for (std::size_t producer_index = 0;
             producer_index < controller.machines.size(); ++producer_index) {
            const auto& producer = controller.machines[producer_index];
            if (!producer.any_transitions.empty()) continue;
            const auto producer_reachable = reachable_states(producer);
            for (std::size_t writer_index = 0; writer_index < producer.states.size(); ++writer_index) {
            if (!producer_reachable.count(static_cast<int>(writer_index))) continue;
            const auto& writer = producer.states[writer_index];
            std::map<std::string, std::string> copies;
            std::map<std::string, std::size_t> copy_order;
            bool plain_copies = true;
            std::set<std::string> condition_parameters;
            for (const auto& candidate_machine : controller.machines)
                for (const auto& candidate_state : candidate_machine.states)
                    for (const auto& transition : candidate_state.transitions)
                        for (const auto& condition : transition.conditions)
                            condition_parameters.insert(condition.parameter);
            for (std::size_t wi = 0; wi < writer.writes.size(); ++wi) {
                const auto& write = writer.writes[wi];
                    if (write.type == 3 && !write.name.empty() &&
                        !write.source.empty() && condition_parameters.count(write.name)) {
                        const auto convert = write.operation_flags.find("convert_range");
                        const auto local = write.operation_flags.find("local_only");
                        if (convert == write.operation_flags.end() || convert->second ||
                            local == write.operation_flags.end() || local->second ||
                            !copies.emplace(write.name, write.source).second) plain_copies = false;
                        copy_order[write.name] = wi;
                    }
            }
            if (!plain_copies) continue;
            std::vector<std::string> slots{input};
            while (slots.size() < 7) {
                std::string next;
                for (const auto& [destination, source] : copies)
                    if (source == slots.back()) {
                        if (!next.empty()) { next.clear(); break; }
                        next = destination;
                    }
                if (next.empty()) break;
                slots.push_back(next);
            }
            if (slots.size() < 6) continue;
            bool ordered = true;
            for (std::size_t i = 2; i < slots.size(); ++i)
                if (copy_order.at(slots[i]) >= copy_order.at(slots[i - 1])) ordered = false;
            if (!ordered) continue;
            // A slot is private to this ordered writer; a foreign Set/Copy or
            // animation writer invalidates the reconstructed history.
            std::set<std::string> private_slots(slots.begin() + 1, slots.end());
            bool competing = false;
            for (const auto& active_controller : snapshot.controllers) {
                if (!snapshot.active_fx_controller_ids.empty() &&
                    !snapshot.active_fx_controller_ids.count(active_controller.path_id)) continue;
                for (std::size_t mi = 0; mi < active_controller.machines.size(); ++mi)
                    for (std::size_t si = 0; si < active_controller.machines[mi].states.size(); ++si) {
                        const auto& other_state = active_controller.machines[mi].states[si];
                        for (const auto& write : other_state.writes)
                            if (private_slots.count(write.name) &&
                                (active_controller.path_id != controller.path_id ||
                                 mi != producer_index || si != writer_index)) competing = true;
                        for (const auto& effect : other_state.animation_writes)
                            if (private_slots.count(effect.name)) competing = true;
                    }
            }
            if (competing) continue;
            std::vector<int> password_values;
            for (std::size_t comparator_index = 0;
                 comparator_index < controller.machines.size(); ++comparator_index) {
                const auto& comparator = controller.machines[comparator_index];
                const auto comparator_reachable = reachable_states(comparator);
                for (std::size_t state_index = 0;
                     state_index < comparator.states.size(); ++state_index) {
                    const auto& state = comparator.states[state_index];
                    if (!comparator_reachable.count(static_cast<int>(state_index))) continue;
                    for (const auto& exact : state.transitions) {
                        if (exact.destination < 0 ||
                            exact.destination >= static_cast<int>(comparator.states.size())) continue;
                        std::map<std::string, int> expected;
                        bool valid = true;
                        for (const auto& condition : exact.conditions) {
                            const auto slot = std::find(slots.begin(), slots.end(), condition.parameter);
                            const int value = static_cast<int>(std::llround(condition.threshold));
                            if (condition.mode != 6 || slot == slots.end() ||
                                std::fabs(condition.threshold - value) > 0.0001 ||
                                !expected.emplace(condition.parameter, value).second) { valid = false; break; }
                        }
                        if (!valid || expected.size() < 4) continue;
                        // Comparator slots must be the complete newest-first
                        // prefix, and each expected value must have a button.
                        bool complete_prefix = !expected.count(input);
                        for (std::size_t i = 1; i <= expected.size(); ++i) {
                            if (i >= slots.size() || !expected.count(slots[i])) { complete_prefix = false; break; }
                            const int digit = expected.at(slots[i]);
                            if (std::none_of(buttons.begin(), buttons.end(),
                                [&](const auto& button) { return button.first == digit; })) complete_prefix = false;
                        }
                        if (!complete_prefix) continue;
                        const auto& middle = comparator.states[static_cast<std::size_t>(exact.destination)];
                        const Transition* confirm = nullptr;
                        for (const auto& edge : middle.transitions) {
                            std::map<std::string, int> second;
                            bool same = true;
                            for (const auto& condition : edge.conditions) {
                                const int value = static_cast<int>(std::llround(condition.threshold));
                                if (condition.mode != 6 || std::fabs(condition.threshold - value) > 0.0001 ||
                                    !expected.count(condition.parameter) || expected[condition.parameter] != value) {
                                    same = false; break;
                                }
                                second[condition.parameter] = value;
                            }
                            if (same && second == expected) { confirm = &edge; break; }
                        }
                        if (!confirm || confirm->destination < 0 ||
                            confirm->destination >= static_cast<int>(comparator.states.size())) continue;
                        const auto& terminal = comparator.states[static_cast<std::size_t>(confirm->destination)];
                        if (!terminal.transitions.empty() || !comparator.any_transitions.empty()) continue;
                        // Require the same uniquely bound activation target
                        // to be on while locked and off in the stable success
                        // sink. Bool writes alone do not prove visible recovery.
                        if (terminal.animation_writes.size() != 1 ||
                            state.animation_writes.size() != 1) continue;
                        const auto& restored = terminal.animation_writes.front();
                        const auto& locked = state.animation_writes.front();
                        if (restored.name != "m_IsActive" || locked.name != "m_IsActive" ||
                            restored.value != 0 || locked.value != 1 ||
                            restored.binding_status != "unique_serialized_target" ||
                            locked.binding_status != "unique_serialized_target" ||
                            restored.target_type != 1 || restored.target_id.empty() ||
                            restored.target_id != locked.target_id ||
                            restored.attribute_hash != locked.attribute_hash) continue;
                        bool conflicting_effect = false;
                        for (std::size_t other = 0; other < controller.machines.size(); ++other) {
                            if (other == comparator_index) continue;
                            for (const auto& other_state : controller.machines[other].states)
                                for (const auto& effect : other_state.animation_writes)
                                    if (effect.target_id == restored.target_id &&
                                        effect.attribute_hash == restored.attribute_hash)
                                        conflicting_effect = true;
                        }
                        if (conflicting_effect) continue;
                        // Each wrong slot must have its complementary failure
                        // edge in both comparator stages.
                        const auto complementary = [&](const State& owner) {
                            std::set<std::string> rejected;
                            for (const auto& edge : owner.transitions) {
                                if (edge.conditions.size() != 1) continue;
                                const auto& guard = edge.conditions.front();
                                const auto found = expected.find(guard.parameter);
                                if (guard.mode == 7 && found != expected.end() &&
                                    guard.threshold == found->second) rejected.insert(guard.parameter);
                            }
                            return rejected.size() == expected.size();
                        };
                        if (!complementary(state) || !complementary(middle)) continue;
                        bool writes_unlock = false;
                        for (const auto& write : terminal.writes)
                            if (write.type == 0 && std::fabs(write.value - 1.0) < 0.0001)
                                writes_unlock = true;
                        if (!writes_unlock) continue;
                        std::vector<int> values;
                        for (const auto& slot : slots) {
                            const auto found = expected.find(slot);
                            if (found != expected.end()) values.push_back(found->second);
                        }
                        if (values.size() != expected.size() || values.size() < 4) continue;
                        std::reverse(values.begin(), values.end());
                        std::ostringstream password;
                        for (const int value : values) password << value;
                        Candidate candidate{controller.name, input, password.str(), password.str(),
                            u8"普通数字按钮 → 六位移位寄存器 → 双阶段精确比较 → 解锁写入终点",
                            u8"高", confirm->destination,
                            "native_parallel_dial_terminal"};
                        candidate.menu_mapped = true;
                        candidate.analysis_origin = "reverse";
                        candidate.family = "numeric_button_shift_register";
                        candidate.controller_path_id = controller.path_id;
                        candidate.machine_index = comparator_index;
                        json::Value::Object bypass;
                        bypass["path_id"] = controller.path_id;
                        bypass["machine_index"] = static_cast<std::int64_t>(comparator_index);
                        bypass["before"] = comparator.default_state;
                        bypass["unlock_state"] = confirm->destination;
                        bypass["unlock_state_name"] = terminal.name;
                        bypass["method"] = "native_parallel_dial_terminal";
                        bypass["proof_family"] = "numeric_button_shift_register";
                        Guide guide; guide.password = password.str(); guide.menu = buttons.front().second; guide.parameter = input;
                        for (const int value : values) { guide.keys.push_back(std::to_string(value)); guide.values.push_back(value); }
                        const ReversePlanKey key{controller.path_id, comparator_index,
                            confirm->destination, "native_parallel_dial_terminal"};
                        pending.emplace(std::make_pair(password.str(), key),
                            std::make_tuple(std::move(candidate), std::move(guide), json::Value(std::move(bypass))));
                    }
                }
            }
            }
        }
    }
    if (pending.size() != 1) return;
    auto& proof = pending.begin()->second;
    out.push_back(std::move(std::get<0>(proof)));
    guides.push_back(std::move(std::get<1>(proof)));
    state_bypasses.push_back(std::move(std::get<2>(proof)));
    committed.insert(pending.begin()->first.second);
}

void DetectTreeDecoys(const Snapshot& snapshot, const std::map<std::string,std::set<int>>& judged, std::vector<Candidate>& out) {
    std::map<std::string,std::vector<std::tuple<std::string,std::string,int>>> setters;
    for (const auto& menu : snapshot.menus)
        for (const auto& control : menu.controls)
            if (!control.parameter.empty())
                setters[control.parameter].push_back({
                    menu.name, control.name,
                    static_cast<int>(std::llround(control.value))});

    for (const auto& [parameter, values] : judged) {
        const auto it = setters.find(parameter);
        if (it == setters.end() || it->second.size() < 20 ||
            values.empty() || values.size() > 5) continue;

        // A large ordinary selector (expressions, poses, emotes, outfits, and
        // similar feature menus) also has many distinct values and one or two
        // controller equality checks.  The old heuristic promoted any such
        // selector to a high-confidence "tree decoy password", which produced
        // false answers such as a facial-expression menu item.  Require actual
        // password semantics in either the parameter or its menu breadcrumb.
        bool password_semantics = LooksLock(parameter);
        if (!password_semantics) {
            for (const auto& [menu, button, value] : it->second) {
                (void)button;
                (void)value;
                if (LooksLock(menu)) {
                    password_semantics = true;
                    break;
                }
            }
        }
        if (!password_semantics) continue;

        std::set<int> distinct;
        for (const auto& value : it->second) distinct.insert(std::get<2>(value));
        if (distinct.size() < 20) continue;
        for (int target : values) {
            for (const auto& [menu, button, value] : it->second) {
                if (value != target) continue;
                std::string answer = menu + u8" 选第【" + button + u8"】项";
                out.push_back({u8"(菜单树)", u8"树形嵌套诱饵锁",
                    answer, answer, u8"唯一解锁菜单值反查", u8"高"});
            }
        }
    }
}

std::string BreadcrumbDigits(const std::string& value) {
    std::string digits;
    for (unsigned char ch : value) if (std::isdigit(ch)) digits.push_back(static_cast<char>(ch));
    return digits;
}

bool PasswordMenuName(const std::string& value) {
    return ContainsI(value, u8"\u5bc6\u7801") || ContainsI(value, "password") ||
        ContainsI(value, "passcode") || ContainsI(value, "keypad");
}

bool NumericMenuControl(const MenuControl& control, int& digit) {
    const std::string name = Trim(control.name);
    if (name.size() != 1 || !std::isdigit(static_cast<unsigned char>(name[0]))) return false;
    digit = name[0] - '0';
    return true;
}

#include "menu_input_binding.inc"

int CountBooleanNumericPasswordMenus(const Snapshot& snapshot) {
    int count = 0;
    for (const auto& menu : snapshot.menus) {
        if (!PasswordMenuName(menu.name)) continue;
        std::set<int> digits;
        int boolean_buttons = 0;
        for (const auto& control : menu.controls) {
            int digit = 0;
            if (!NumericMenuControl(control, digit)) continue;
            if (control.parameter.empty()) continue;
            if (control.type != 102) continue;
            if (std::fabs(control.value - 1.0) > 0.01) continue;
            digits.insert(digit);
            ++boolean_buttons;
        }
        if (digits.size() >= 5 && boolean_buttons >= 5)
            ++count;
    }
    return count;
}

// Some generators put the semantic label on the parent-menu button (for
// example a root control named "密码") and leave every child submenu
// anonymous.  The older detector only checked the submenu's own name, so it
// missed the entire 8×8 family.  Keep this detector structural and
// name-agnostic for the digit menus: it requires a password-labelled parent
// control, a real submenu reference, and eight independent Bool Toggle
// controls labelled 1..8.  It deliberately reports a feature only; without a
// verified consumer/terminal this shape must never produce a password or a
// removal plan.
int CountBooleanPasswordGridGroups(const Snapshot& snapshot) {
    std::map<std::string, const Menu*> menus;
    for (const auto& menu : snapshot.menus) menus[menu.id] = &menu;

    const auto is_digit_menu = [](const Menu& menu) {
        if (menu.controls.size() != 8) return false;
        std::set<int> digits;
        for (const auto& control : menu.controls) {
            int digit = 0;
            if (!NumericMenuControl(control, digit) || digit < 1 || digit > 8 ||
                control.type != 102 || control.parameter.empty() ||
                std::fabs(control.value - 1.0) > 0.01) return false;
            digits.insert(digit);
        }
        return digits.size() == 8;
    };

    std::set<std::string> roots;
    for (const auto& parent : snapshot.menus) {
        for (const auto& entry : parent.controls) {
            if (PasswordMenuName(entry.name) && !entry.submenu.empty())
                roots.insert(entry.submenu);
        }
        if (PasswordMenuName(parent.name)) roots.insert(parent.id);
    }

    std::set<std::string> matched;
    for (const auto& root_id : roots) {
        const auto target = menus.find(root_id);
        if (target == menus.end()) continue;
            // Support both layouts: Password -> numeric menu, and the more
            // common Password -> group menu (A..H) -> numeric menu.
            if (is_digit_menu(*target->second)) {
                matched.insert(target->first);
                continue;
            }
            for (const auto& group : target->second->controls) {
                if (group.submenu.empty()) continue;
                const auto digits = menus.find(group.submenu);
                if (digits != menus.end() && is_digit_menu(*digits->second))
                    matched.insert(digits->first);
            }
    }
    return static_cast<int>(matched.size());
}

void DetectBooleanToggleCombination(const Snapshot& snapshot,
    const Controller& controller, std::vector<Candidate>& out,
    json::Value::Array& state_bypasses) {
    struct DigitControl { int digit = -1; std::string parameter, menu; };
    std::vector<DigitControl> controls;
    for (const auto& menu : snapshot.menus) {
        if (!PasswordMenuName(menu.name)) continue;
        for (const auto& control : menu.controls) {
            int digit = -1;
            if (control.type != 102 || !NumericMenuControl(control, digit) ||
                control.parameter.empty()) continue;
            controls.push_back({digit, control.parameter, menu.name});
        }
    }
    std::sort(controls.begin(), controls.end(), [](const auto& left, const auto& right) {
        return left.digit < right.digit;
    });
    controls.erase(std::unique(controls.begin(), controls.end(),
        [](const auto& left, const auto& right) { return left.digit == right.digit; }),
        controls.end());
    if (controls.size() != 10) return;

    std::map<std::string,int> parameter_digit;
    for (const auto& control : controls) parameter_digit[control.parameter] = control.digit;
    struct Generator {
        std::string proxy;
        int enabled_digit = -1;
        std::set<int> disabled_digits;
    };
    std::map<std::string,Generator> generators;
    for (const auto& machine : controller.machines) {
        // The legacy label-based rule cannot prove ordered selector dispatch.
        // Those graphs use the source-bound read-only selector proof instead.
        if (machine.has_selector_semantics) continue;
        std::map<std::string,std::map<int,std::set<double>>> evidence;
        for (const auto& state : machine.states) {
            const std::string label = Trim(state.name);
            if (label.size() != 1 ||
                !std::isdigit(static_cast<unsigned char>(label.front()))) continue;
            const int digit = label.front() - '0';
            const auto visible = std::find_if(controls.begin(), controls.end(),
                [&](const auto& item) { return item.digit == digit; });
            if (visible == controls.end()) continue;
            bool reads_visible_parameter = false;
            for (const auto& transition : state.transitions)
                for (const auto& condition : transition.conditions)
                    if (condition.parameter == visible->parameter)
                        reads_visible_parameter = true;
            if (!reads_visible_parameter) continue;
            for (const auto& write : state.animation_writes) {
                if (std::abs(write.value) > 1e-5 &&
                    std::abs(write.value - 1.0) > 1e-5) continue;
                evidence[write.name][digit].insert(write.value > 0.5 ? 1.0 : 0.0);
            }
        }
        for (const auto& [proxy, by_digit] : evidence) {
            std::vector<int> enabled;
            std::set<int> disabled;
            bool contradictory = false;
            for (const auto& [digit, values] : by_digit) {
                if (values.size() != 1) { contradictory = true; break; }
                if (*values.begin() > 0.5) enabled.push_back(digit);
                else disabled.insert(digit);
            }
            if (contradictory || enabled.size() != 1 || disabled.size() < 5 ||
                disabled.count(enabled.front())) continue;
            const auto existing = generators.find(proxy);
            if (existing != generators.end() &&
                existing->second.enabled_digit != enabled.front()) {
                generators.erase(existing);
                continue;
            }
            generators[proxy] = {proxy, enabled.front(), std::move(disabled)};
        }
    }
    if (generators.size() < 2) return;

    std::set<std::string> required_proxies;
    int independent_consumers = 0;
    std::vector<std::pair<std::size_t,int>> consumer_plans;
    for (std::size_t machine_index = 0;
         machine_index < controller.machines.size(); ++machine_index) {
        const auto& machine = controller.machines[machine_index];
        if (machine.has_selector_semantics) continue;
        bool machine_match = false;
        for (const auto& state : machine.states) {
            for (const auto& transition : state.transitions) {
                std::set<std::string> conjunction;
                for (const auto& condition : transition.conditions)
                    if ((condition.mode == 1 || condition.mode == 3) &&
                        generators.count(condition.parameter))
                        conjunction.insert(condition.parameter);
                if (conjunction.size() >= 2) {
                    if (required_proxies.empty()) required_proxies = conjunction;
                    else if (required_proxies != conjunction) continue;
                    machine_match = true;
                    if (transition.destination >= 0 &&
                        transition.destination < static_cast<int>(machine.states.size()) &&
                        transition.destination != machine.default_state)
                        consumer_plans.push_back({machine_index, transition.destination});
                }
            }
        }
        if (machine_match) ++independent_consumers;
    }
    if (required_proxies.size() < 2 || independent_consumers < 2) return;

    std::set<int> enabled_digits;
    std::optional<std::set<int>> common_disabled;
    for (const auto& proxy : required_proxies) {
        const auto found = generators.find(proxy);
        if (found == generators.end()) return;
        if (!enabled_digits.insert(found->second.enabled_digit).second) return;
        if (!common_disabled.has_value()) common_disabled = found->second.disabled_digits;
        else {
            std::set<int> overlap;
            std::set_intersection(common_disabled->begin(), common_disabled->end(),
                found->second.disabled_digits.begin(), found->second.disabled_digits.end(),
                std::inserter(overlap, overlap.begin()));
            common_disabled = std::move(overlap);
        }
    }
    if (!common_disabled.has_value() || common_disabled->size() < 5) return;
    std::set<int> covered = enabled_digits;
    covered.insert(common_disabled->begin(), common_disabled->end());
    for (int digit = 0; digit <= 9; ++digit)
        if (!covered.count(digit)) return;

    std::ostringstream password, raw;
    std::string first_menu;
    for (int digit : enabled_digits) {
        password << digit;
        raw << digit;
        const auto control = std::find_if(controls.begin(), controls.end(),
            [&](const auto& item) { return item.digit == digit; });
        if (control != controls.end() && first_menu.empty()) first_menu = control->menu;
    }
    Candidate candidate{controller.name, u8"\u72ec\u7acb\u5e03\u5c14 Toggle \u7ec4\u5408",
        raw.str(), password.str(),
        u8"\u6bcf\u4f4d AnimationClip \u5e38\u91cf\u5199\u5165 + \u591a\u5c42 AND \u89e3\u9501\u6c47\u603b\u4ea4\u53c9\u9a8c\u8bc1\uff1b\u987a\u5e8f\u65e0\u5173\uff0c\u6700\u7ec8\u4ec5\u4fdd\u6301\u8fd9\u4e9b\u6570\u5b57\u4e3a\u5f00",
        u8"\u9ad8"};
    candidate.menu_mapped = true;
    out.push_back(std::move(candidate));

    std::sort(consumer_plans.begin(), consumer_plans.end());
    consumer_plans.erase(std::unique(consumer_plans.begin(), consumer_plans.end()),
        consumer_plans.end());
    if (consumer_plans.size() < 2 || controller.path_id.empty()) return;
    for (const auto& [machine_index, unlock_state] : consumer_plans) {
        const auto& machine = controller.machines[machine_index];
        json::Value::Object bypass;
        bypass["path_id"] = controller.path_id;
        bypass["machine_index"] = static_cast<std::int64_t>(machine_index);
        bypass["before"] = machine.default_state;
        bypass["unlock_state"] = unlock_state;
        bypass["unlock_state_name"] =
            machine.states[static_cast<std::size_t>(unlock_state)].name;
        bypass["method"] = "native_boolean_toggle_and_terminal";
        state_bypasses.push_back(bypass);
    }
}

bool FunctionalMenu(const Menu& menu) {
    int non_numeric = 0;
    for (const auto& control : menu.controls) {
        int digit = 0;
        if (!NumericMenuControl(control, digit)) ++non_numeric;
    }
    return non_numeric >= 2;
}

void DetectBreadcrumbKeypad(const Snapshot& snapshot, std::vector<Candidate>& out,
    std::vector<Guide>& guides) {
    std::map<std::string,const Menu*> menus;
    for (const auto& menu : snapshot.menus) menus[menu.id] = &menu;

    struct Found {
        std::string password;
        std::string root_name;
        std::vector<std::string> keys;
        std::vector<int> values;
    };
    std::optional<Found> best;

    for (const auto& root : snapshot.menus) {
        if (!PasswordMenuName(root.name)) continue;
        std::string prefix = BreadcrumbDigits(root.name);
        if (prefix.size() > 2) continue;
        const std::string initial_prefix = prefix;
        const Menu* current = &root;
        std::set<std::string> visited;
        std::vector<std::string> keys;
        std::vector<int> values;
        bool unlocked = false;

        for (int depth = 0; depth < 16 && current && visited.insert(current->id).second; ++depth) {
            int numeric_controls = 0;
            struct Next { int digit; int raw_value; const Menu* menu; bool terminal; };
            std::vector<Next> forward;
            for (const auto& control : current->controls) {
                int digit = 0;
                if (!NumericMenuControl(control, digit)) continue;
                ++numeric_controls;
                const auto target = menus.find(control.submenu);
                if (target == menus.end() || target->second->id == current->id) continue;
                const std::string expected = prefix + static_cast<char>('0' + digit);
                const bool breadcrumb = PasswordMenuName(target->second->name) &&
                    BreadcrumbDigits(target->second->name) == expected;
                const bool terminal = !PasswordMenuName(target->second->name) &&
                    prefix.size() >= 3 && FunctionalMenu(*target->second);
                if (breadcrumb || terminal)
                    forward.push_back({
                        digit,
                        static_cast<int>(std::llround(control.value)),
                        target->second,
                        terminal
                    });
            }
            if (numeric_controls < 5 || forward.size() != 1) break;
            const auto next = forward.front();
            prefix.push_back(static_cast<char>('0' + next.digit));
            keys.push_back(std::to_string(next.digit));
            values.push_back(next.raw_value);
            if (next.terminal) {
                unlocked = true;
                break;
            }
            current = next.menu;
        }

        if (!unlocked || prefix.size() < 4 || keys.size() < 2) continue;
        Found found{prefix, root.name, keys, values};
        if (!best || found.password.size() > best->password.size() ||
            (found.password.size() == best->password.size() &&
             initial_prefix.size() < BreadcrumbDigits(best->root_name).size()))
            best = std::move(found);
    }

    if (!best) return;
    out.push_back({
        u8"(\u83dc\u5355\u6811)",
        u8"\u9762\u5305\u5c51\u5bfc\u822a\u5bc6\u7801\u9501",
        best->password,
        best->password,
        u8"\u83dc\u5355\u5c42\u7ea7\u540d\u4e0e\u552f\u4e00\u524d\u8fdb\u5206\u652f\u4ea4\u53c9\u9a8c\u8bc1",
        u8"\u9ad8"
    });
    guides.push_back({
        best->password,
        best->root_name,
        u8"\u9762\u5305\u5c51\u5bfc\u822a\u5bc6\u7801\u9501",
        best->keys,
        best->values
    });
}

bool MenuContainsTerm(const Menu& menu, const std::vector<std::string>& terms) {
    if (std::any_of(terms.begin(), terms.end(),
        [&](const std::string& term) { return ContainsI(menu.name, term); })) return true;
    for (const auto& control : menu.controls)
        if (std::any_of(terms.begin(), terms.end(),
            [&](const std::string& term) { return ContainsI(control.name, term); }))
            return true;
    return false;
}

bool NegativeNavigationTerminal(const Menu& menu) {
    static const std::vector<std::string> terms = {
        "wrong", "failed", "failure", "denied", "invalid", "incorrect",
        "try again", u8"错误", u8"失败", u8"拒绝"
    };
    return MenuContainsTerm(menu, terms);
}

bool PositiveNavigationTerminal(const Menu& menu) {
    static const std::vector<std::string> terms = {
        "access granted", "authorized", "unlocked", "success",
        u8"验证成功", u8"访问许可", u8"已解锁"
    };
    return MenuContainsTerm(menu, terms);
}

bool BreadcrumbContinuation(const Menu& from, const MenuControl& control,
    const Menu& target) {
    if (from.name.empty() || control.name.empty() || target.name.empty()) return false;
    const std::string expected = from.name + u8" » " + Trim(control.name);
    if (target.name.size() < expected.size() ||
        target.name.compare(0, expected.size(), expected) != 0) return false;
    return target.name.size() == expected.size() ||
        target.name.compare(expected.size(), std::string(u8" » ").size(), u8" » ") == 0;
}

struct NavigationMazeStep {
    const MenuControl* control = nullptr;
    const Menu* target = nullptr;
    // Some generators encode the successful write on the same SubMenu edge
    // that returns to the feature/root menu.  Keep that edge terminal instead
    // of treating it as an ordinary navigation hop.
    bool parameter_terminal = false;
    // A name-independent maze step has one structural progress edge and sends
    // every other visible digit to the same failure/retry hub.  Retaining the
    // hub lets the caller prove that the whole route belongs to one generated
    // maze instead of stitching unrelated numeric menus together.
    std::string failure_hub;
    bool structural_progress = false;
    bool legacy_progress = false;
};

bool NumericNavigationMenu(const Menu& menu);

const MenuControl* SingleControlNavigationTerminal(const Snapshot& snapshot,
    const Menu& menu) {
    if (menu.controls.size() != 1) return nullptr;
    const auto& control = menu.controls.front();
    int digit = 0;
    if (NumericMenuControl(control, digit) || control.type == 103 ||
        !control.submenu.empty() || control.parameter.empty() ||
        !control.sub_parameters.empty())
        return nullptr;
    // Button and Toggle are the only scalar expression controls that form a
    // usable one-action terminal.  Radial/two-axis controls need their own
    // value semantics and must not be guessed as a keypad success page.
    if (control.type != 101 && control.type != 102) return nullptr;
    if (snapshot.expression_parameters.count(control.parameter) == 0)
        return nullptr;
    return &control;
}

std::optional<NavigationMazeStep> UniqueNavigationMazeStep(const Menu& menu,
    const std::map<std::string, const Menu*>& menus,
    const Snapshot& snapshot) {
    std::vector<const MenuControl*> numeric;
    std::map<std::string, int> destination_counts;
    std::set<int> visible_digits;
    for (const auto& control : menu.controls) {
        int digit = 0;
        if (!NumericMenuControl(control, digit) || control.submenu.empty() ||
            !menus.count(control.submenu)) continue;
        numeric.push_back(&control);
        visible_digits.insert(digit);
        ++destination_counts[control.submenu];
    }
    if (numeric.size() < 5 || visible_digits.size() != numeric.size())
        return std::nullopt;
    const auto dominant = std::max_element(destination_counts.begin(),
        destination_counts.end(), [](const auto& left, const auto& right) {
            return left.second < right.second;
        });
    const int common = dominant->second;
    if (common < static_cast<int>(numeric.size()) - 2) return std::nullopt;

    std::vector<NavigationMazeStep> forward;
    for (const auto* control : numeric) {
        if (destination_counts[control->submenu] != 1 || control->submenu == menu.id) continue;
        const Menu* target = menus.at(control->submenu);
        if (NegativeNavigationTerminal(*target)) continue;
        // A type-103 control can carry a parameter write.  It is still a
        // SubMenu in the serialized asset, so the old detector discarded it
        // unless the target menu name happened to say "unlocked".  Treat it
        // as a terminal candidate; the caller verifies that the parameter is
        // consumed by the active FX controller before promoting confidence or
        // creating a rewrite plan.
        const bool parameter_terminal = !control->parameter.empty() &&
            control->type == 103;
        const bool structural_progress =
            common == static_cast<int>(numeric.size()) - 1 &&
            (NumericNavigationMenu(*target) ||
             SingleControlNavigationTerminal(snapshot, *target) != nullptr);
        const bool legacy_progress = BreadcrumbContinuation(menu, *control, *target) ||
            PositiveNavigationTerminal(*target) || parameter_terminal;
        if (legacy_progress || structural_progress)
            forward.push_back({control, target, parameter_terminal,
                dominant->first, structural_progress, legacy_progress});
    }
    return forward.size() == 1
        ? std::optional<NavigationMazeStep>(forward.front()) : std::nullopt;
}

bool ActiveControllerConsumesParameter(const Snapshot& snapshot,
    const std::string& parameter) {
    if (parameter.empty()) return false;
    for (const auto& controller : snapshot.controllers) {
        if (!snapshot.active_fx_controller_ids.empty() &&
            !snapshot.active_fx_controller_ids.count(controller.path_id))
            continue;
        auto has_condition = [&](const std::vector<Transition>& transitions) {
            for (const auto& transition : transitions)
                for (const auto& condition : transition.conditions)
                    if (condition.parameter == parameter) return true;
            return false;
        };
        for (const auto& machine : controller.machines) {
            if (has_condition(machine.any_transitions)) return true;
            for (const auto& state : machine.states) {
                if (has_condition(state.transitions)) return true;
                for (const auto& read : state.blend_parameter_reads)
                    if (read.parameter == parameter && read.clip_id >= 0)
                        return true;
            }
        }
    }
    return false;
}

std::set<std::string> ActiveControllerConsumedParameters(
    const Snapshot& snapshot) {
    std::set<std::string> consumed;
    for (const auto& controller : snapshot.controllers) {
        if (!snapshot.active_fx_controller_ids.empty() &&
            !snapshot.active_fx_controller_ids.count(controller.path_id))
            continue;
        const auto collect_conditions = [&](const std::vector<Transition>& transitions) {
            for (const auto& transition : transitions)
                for (const auto& condition : transition.conditions)
                    if (!condition.parameter.empty())
                        consumed.insert(condition.parameter);
        };
        for (const auto& machine : controller.machines) {
            collect_conditions(machine.any_transitions);
            for (const auto& state : machine.states) {
                collect_conditions(state.transitions);
                for (const auto& read : state.blend_parameter_reads)
                    if (!read.parameter.empty() && read.clip_id >= 0)
                        consumed.insert(read.parameter);
            }
        }
    }
    return consumed;
}

// Some menu-only lock generators materialize the complete keypad language as
// an 8-way SubMenu tree.  Wrong prefixes end in empty pages, while exactly one
// leaf exposes a scalar terminal action.  There is no shared failure hub, so
// the ordinary navigation-maze detector cannot recognize this shape.  Prove
// the whole bounded tree instead of matching names, object IDs, or ordering.
void DetectSparseTerminalSubmenuTree(const Snapshot& snapshot,
    std::vector<Candidate>& out, std::vector<Guide>& guides) {
    if (snapshot.active_root_menu_ids.empty()) return;
    std::map<std::string, const Menu*> menus;
    for (const auto& menu : snapshot.menus) menus[menu.id] = &menu;
    std::map<std::string, bool> numeric_menu_cache;
    std::optional<std::set<std::string>> consumed_parameters;
    const auto is_numeric_menu = [&](const std::string& id) {
        const auto cached = numeric_menu_cache.find(id);
        if (cached != numeric_menu_cache.end()) return cached->second;
        const auto found = menus.find(id);
        const bool numeric = found != menus.end() &&
            NumericNavigationMenu(*found->second);
        numeric_menu_cache[id] = numeric;
        return numeric;
    };

    std::set<std::string> numeric_entries;
    std::set<std::string> reached(snapshot.active_root_menu_ids.begin(),
                                  snapshot.active_root_menu_ids.end());
    std::deque<std::string> queue(reached.begin(), reached.end());
    int reach_budget = 10000;
    while (!queue.empty() && reach_budget-- > 0) {
        const auto id = queue.front(); queue.pop_front();
        const auto found = menus.find(id);
        if (found == menus.end()) continue;
        // A keypad may itself be the root. Stop at the first numeric page so
        // suffixes of a password are not mistaken for independent entries.
        if (is_numeric_menu(id)) {
            numeric_entries.insert(id);
            continue;
        }
        for (const auto& control : found->second->controls) {
            if (control.type != 103 || control.submenu.empty())
                continue;
            const auto target = menus.find(control.submenu);
            if (target == menus.end()) continue;
            if (is_numeric_menu(target->first)) {
                numeric_entries.insert(target->first);
            } else if (reached.insert(target->first).second) {
                queue.push_back(target->first);
            }
        }
    }

    for (const auto& start : numeric_entries) {
        struct Pending {
            const Menu* menu;
            std::vector<std::string> keys;
            std::vector<int> values;
            std::set<std::string> path;
        };
        std::deque<Pending> pending;
        pending.push_back({menus.at(start), {}, {}, {start}});
        std::vector<std::pair<std::vector<std::string>,
                              std::vector<int>>> terminal_paths;
        const MenuControl* terminal_control = nullptr;
        std::size_t numeric_pages = 0, dead_leaves = 0;
        bool invalid = false;
        int budget = 10000;
        while (!pending.empty() && budget-- > 0 && !invalid) {
            auto current = std::move(pending.front()); pending.pop_front();
            if (current.keys.size() >= 12 ||
                !is_numeric_menu(current.menu->id)) {
                invalid = true; break;
            }
            ++numeric_pages;
            std::set<int> digits;
            for (const auto& control : current.menu->controls) {
                int digit = 0;
                if (!NumericMenuControl(control, digit) ||
                    control.type != 103 || control.submenu.empty() ||
                    !digits.insert(digit).second) {
                    invalid = true; break;
                }
                const auto target_it = menus.find(control.submenu);
                // Wrong prefixes in this generator are deliberately encoded
                // as unresolved SubMenu PPtrs.  Within a fully numeric,
                // bounded tree these are dead leaves, not malformed evidence.
                if (target_it == menus.end()) {
                    ++dead_leaves;
                    continue;
                }
                if (current.path.count(target_it->first)) {
                    invalid = true; break;
                }
                auto keys = current.keys;
                auto values = current.values;
                keys.push_back(Trim(control.name));
                values.push_back(digit);
                const Menu* target = target_it->second;
                if (is_numeric_menu(target_it->first)) {
                    auto path = current.path;
                    path.insert(target_it->first);
                    pending.push_back({target, std::move(keys),
                                       std::move(values), std::move(path)});
                    continue;
                }
                if (target->controls.empty()) {
                    ++dead_leaves;
                    continue;
                }
                const auto* action =
                    SingleControlNavigationTerminal(snapshot, *target);
                if (!action || !terminal_paths.empty()) {
                    invalid = true; break;
                }
                terminal_control = action;
                terminal_paths.push_back({std::move(keys), std::move(values)});
            }
        }
        if (!pending.empty() || invalid || terminal_paths.size() != 1 ||
            terminal_control == nullptr || numeric_pages < 4 ||
            dead_leaves < 15 || terminal_paths.front().first.size() < 2)
            continue;
        // Controller consumption is the most expensive terminal proof.  Most
        // avatars do not contain this sparse-tree family, so build the shared
        // index lazily only after the complete menu structure has qualified.
        if (!consumed_parameters)
            consumed_parameters = ActiveControllerConsumedParameters(snapshot);
        if (!consumed_parameters->count(terminal_control->parameter)) continue;

        const auto& keys = terminal_paths.front().first;
        const auto& values = terminal_paths.front().second;
        std::ostringstream password, route;
        for (std::size_t i = 0; i < keys.size(); ++i) {
            password << keys[i];
            if (i) route << u8" → ";
            route << keys[i];
        }
        const bool known_active_fx = !snapshot.active_fx_controller_ids.empty();
        Candidate candidate{u8"(菜单树)", terminal_control->parameter,
            password.str(), password.str(),
            std::string(u8"活动根可达 + 完整数字子菜单树 + 唯一可操作终端 + ") +
                (known_active_fx ? u8"活动 FX 消费 | " : u8"控制器消费，活动绑定待确认 | ") +
                route.str(), known_active_fx ? u8"高" : u8"参考", -1, {}, known_active_fx};
        candidate.menu_mapped = true;
        candidate.analysis_origin = "menu_tree";
        candidate.family = "sparse_terminal_submenu_tree";
        out.push_back(std::move(candidate));
        guides.push_back({password.str(), menus.at(start)->name,
            terminal_control->parameter, keys, values});
    }
}

bool NumericNavigationMenu(const Menu& menu) {
    int numeric = 0;
    for (const auto& control : menu.controls) {
        int digit = 0;
        if (NumericMenuControl(control, digit)) ++numeric;
    }
    return numeric >= 5 && numeric == static_cast<int>(menu.controls.size());
}

bool SameMenuControlShape(const MenuControl& left, const MenuControl& right) {
    return left.type == right.type &&
        Trim(left.name) == Trim(right.name) &&
        left.parameter == right.parameter &&
        std::fabs(left.value - right.value) < 0.01;
}

bool VerifiedUnlockedMenuTarget(const Snapshot& snapshot,
    const Menu& locked_root, const std::string& keypad_start,
    const Menu& target) {
    // A parameter-bearing SubMenu edge is not automatically a success edge.
    // Several generated mazes write the same Bool on a short decoy path which
    // simply returns to the still-locked descriptor root.
    if (target.id == locked_root.id ||
        snapshot.active_root_menu_ids.count(target.id) ||
        NumericNavigationMenu(target))
        return false;

    if (PositiveNavigationTerminal(target)) return true;
    if (!FunctionalMenu(target) || target.controls.size() < 4 ||
        locked_root.controls.size() < 4)
        return false;

    bool locked_root_enters_keypad = false;
    for (const auto& control : locked_root.controls) {
        int digit = 0;
        if (control.type == 103 && control.submenu == keypad_start &&
            !NumericMenuControl(control, digit)) {
            locked_root_enters_keypad = true;
            break;
        }
    }
    if (!locked_root_enters_keypad) return false;

    // Generated locks commonly clone the ordinary feature root for the
    // unlocked state and replace only the password entry destination.  Match
    // controls as an unordered set so menu reordering does not break the
    // family rule, while deliberately ignoring the SubMenu destination during
    // shape matching so the changed entry can be detected below.
    std::vector<bool> used(target.controls.size(), false);
    std::size_t matched = 0;
    bool replaced_destination = false;
    for (const auto& source_control : locked_root.controls) {
        for (std::size_t i = 0; i < target.controls.size(); ++i) {
            if (used[i] || !SameMenuControlShape(source_control, target.controls[i]))
                continue;
            used[i] = true;
            ++matched;
            if (source_control.type == 103 &&
                source_control.submenu != target.controls[i].submenu)
                replaced_destination = true;
            break;
        }
    }
    const std::size_t comparable =
        std::min(locked_root.controls.size(), target.controls.size());
    const std::size_t required = std::max<std::size_t>(3, (comparable * 3 + 4) / 5);
    return matched >= required && replaced_destination;
}

// A second navigation form used by generated avatars starts at the active
// descriptor menu, enters one numeric 8-way menu through a non-numeric
// "password" button, and then reuses several numeric menus as a graph.  The
// successful edge is still a SubMenu, but it also writes a Bool parameter and
// returns to the feature/root menu.  The old chain detector required one
// forward edge per menu and therefore missed shared-branch graphs such as
// this.  Search the reachable numeric subgraph directly and keep the shortest
// route for each consumed terminal parameter.
void DetectActiveRootParameterMaze(const Snapshot& snapshot,
    std::vector<Candidate>& out, std::vector<Guide>& guides,
    json::Value::Array& menu_bypasses) {
    if (snapshot.active_root_menu_ids.empty()) return;
    std::map<std::string, const Menu*> menus;
    for (const auto& menu : snapshot.menus) menus[menu.id] = &menu;

    struct Node {
        const Menu* menu = nullptr;
        std::vector<std::string> keys;
        std::vector<int> values;
        std::string numeric_start;
        std::set<std::string> visited;
    };
    struct Found {
        std::string password;
        std::string parameter;
        std::string menu;
        std::string start_menu;
        std::vector<std::string> keys;
        std::vector<int> values;
        const Menu* terminal = nullptr;
    };
    std::map<std::string, Found> best_by_parameter;

    for (const auto& root_id : snapshot.active_root_menu_ids) {
        const auto root_it = menus.find(root_id);
        if (root_it == menus.end()) continue;
        std::deque<Node> queue;
        Node initial; initial.menu = root_it->second; initial.visited.insert(root_id);
        queue.push_back(std::move(initial));
        int expanded = 0;
        while (!queue.empty() && expanded++ < 10000) {
            Node node = std::move(queue.front()); queue.pop_front();
            const bool started = !node.numeric_start.empty();
            for (const auto& control : node.menu->controls) {
                if (control.type != 103 || control.submenu.empty()) continue;
                const auto target_it = menus.find(control.submenu);
                if (target_it == menus.end()) continue;
                int digit = 0;
                const bool is_digit = NumericMenuControl(control, digit);
                if (!started) {
                    // Only use a non-numeric submenu as the entry into a
                    // keypad-shaped menu; do not crawl the avatar's ordinary
                    // feature tree and manufacture a password from it.
                    if (is_digit || !NumericNavigationMenu(*target_it->second)) continue;
                    Node next = node;
                    next.menu = target_it->second;
                    next.numeric_start = target_it->second->id;
                    if (next.visited.count(next.menu->id)) continue;
                    next.visited.insert(next.menu->id);
                    queue.push_back(std::move(next));
                    continue;
                }
                if (!is_digit) continue;
                Node next = node;
                next.keys.push_back(std::to_string(digit));
                next.values.push_back(static_cast<int>(std::llround(control.value)));
                if (!control.parameter.empty() &&
                    std::fabs(control.value - 1.0) < 0.01 &&
                    next.keys.size() >= 3 &&
                    ActiveControllerConsumesParameter(snapshot, control.parameter) &&
                    VerifiedUnlockedMenuTarget(snapshot, *root_it->second,
                        next.numeric_start, *target_it->second)) {
                    std::string password;
                    for (const auto& key : next.keys) password += key;
                    auto found = best_by_parameter.find(control.parameter);
                    if (found == best_by_parameter.end() ||
                        next.keys.size() < found->second.keys.size()) {
                        best_by_parameter[control.parameter] = {
                            password, control.parameter, node.menu->name,
                            next.numeric_start, next.keys, next.values,
                            target_it->second
                        };
                    }
                    // The terminal edge itself is allowed to return to an
                    // already visited root/menu; do not enqueue it as a loop.
                    continue;
                }
                if (next.keys.size() >= 12 || next.visited.count(target_it->second->id))
                    continue;
                next.menu = target_it->second;
                next.visited.insert(next.menu->id);
                queue.push_back(std::move(next));
            }
        }
    }

    for (const auto& [parameter, found] : best_by_parameter) {
        std::ostringstream route, password;
        for (std::size_t i = 0; i < found.keys.size(); ++i) {
            if (i) route << u8" → ";
            route << found.keys[i]; password << found.keys[i];
        }
        out.push_back({u8"(菜单树)", parameter, password.str(), password.str(),
            u8"活动根菜单可达 + 带参数 SubMenu 成功终点 + 活动 FX 消费 | " + route.str(),
            u8"高", -1, "active_fx_parameter_terminal", true});
        guides.push_back({password.str(), found.start_menu, parameter,
            found.keys, found.values});

        // Only create a bypass when the password entry is uniquely reachable
        // from a non-numeric parent.  This keeps ordinary shared feature links
        // fail-closed while allowing the verified lock entry to skip the maze.
        std::vector<std::pair<const Menu*, int>> parents;
        for (const auto& parent : snapshot.menus) {
            for (std::size_t i = 0; i < parent.controls.size(); ++i) {
                const auto& control = parent.controls[i];
                int parent_digit = 0;
                if (control.type == 103 && control.submenu == found.start_menu &&
                    !NumericMenuControl(control, parent_digit))
                    parents.push_back({&parent, static_cast<int>(i)});
            }
        }
        // A parameter-bearing terminal needs an explicit parameter/default
        // rewrite; merely redirecting the parent SubMenu back to the root
        // would skip the write and can create a self-loop.  Until the writer
        // has a dedicated parameter-bypass record, keep this as a password
        // guide only and fail closed on removal planning.
        if (parents.size() == 1 && parameter.empty() &&
            found.terminal && found.terminal->id != parents.front().first->id) {
            json::Value::Object bypass;
            bypass["path_id"] = parents.front().first->id;
            bypass["control_index"] = parents.front().second;
            bypass["before_submenu"] = found.start_menu;
            bypass["after_submenu"] = found.terminal ? found.terminal->id : "";
            bypass["method"] = "native_active_root_parameter_maze";
            bypass["terminal_parameter"] = parameter;
            bypass["terminal_parameter_consumed"] = true;
            menu_bypasses.push_back(bypass);
        }
    }
}

void DetectNavigationMaze(const Snapshot& snapshot, std::vector<Candidate>& out,
    std::vector<Guide>& guides, json::Value::Array& menu_bypasses) {
    std::map<std::string, const Menu*> menus;
    for (const auto& menu : snapshot.menus) menus[menu.id] = &menu;

    struct IncomingMenuLink {
        const Menu* parent = nullptr;
        const MenuControl* control = nullptr;
        int control_index = -1;
    };
    std::map<std::string, std::vector<IncomingMenuLink>> incoming;
    for (const auto& parent : snapshot.menus) {
        for (std::size_t index = 0; index < parent.controls.size(); ++index) {
            const auto& control = parent.controls[index];
            int digit = 0;
            if (control.submenu.empty() || NumericMenuControl(control, digit)) continue;
            incoming[control.submenu].push_back({
                &parent, &control, static_cast<int>(index)});
        }
    }

    // Discover keypad entries from the active descriptor root without using
    // menu/control labels.  Ordinary non-numeric SubMenu links may be nested,
    // but traversal stops when it reaches a complete numeric page so a maze
    // hidden several feature pages deep remains identifiable.
    std::set<std::string> active_numeric_entries;
    std::deque<const Menu*> reachable_queue;
    std::set<std::string> reachable_non_numeric;
    for (const auto& root_id : snapshot.active_root_menu_ids) {
        const auto found = menus.find(root_id);
        if (found == menus.end()) continue;
        reachable_queue.push_back(found->second);
        reachable_non_numeric.insert(root_id);
    }
    int reachable_expanded = 0;
    while (!reachable_queue.empty() && reachable_expanded++ < 10000) {
        const Menu* current = reachable_queue.front();
        reachable_queue.pop_front();
        for (const auto& control : current->controls) {
            int digit = 0;
            if (control.type != 103 || control.submenu.empty() ||
                NumericMenuControl(control, digit))
                continue;
            const auto target = menus.find(control.submenu);
            if (target == menus.end()) continue;
            if (NumericNavigationMenu(*target->second)) {
                active_numeric_entries.insert(target->first);
                continue;
            }
            if (reachable_non_numeric.insert(target->first).second)
                reachable_queue.push_back(target->second);
        }
    }

    std::map<std::string, NavigationMazeStep> steps;
    std::set<std::string> progress_targets;
    for (const auto& [id, menu] : menus) {
        const auto step = UniqueNavigationMazeStep(*menu, menus, snapshot);
        if (!step) continue;
        steps[id] = *step;
        if (steps.count(step->target->id) ||
            UniqueNavigationMazeStep(*step->target, menus, snapshot))
            progress_targets.insert(step->target->id);
    }

    for (const auto& [start_id, first] : steps) {
        if (progress_targets.count(start_id)) continue;
        const Menu* current = menus.at(start_id);
        std::set<std::string> visited;
        std::vector<std::string> keys;
        std::vector<int> values;
        const Menu* terminal = nullptr;
        const MenuControl* single_terminal_control = nullptr;
        std::string terminal_parameter;
        bool verified_parameter_terminal = false;
        std::string structural_failure_hub;
        bool structural_chain = true;
        bool legacy_chain = true;
        bool consistent_failure_hub = true;

        while (current && visited.insert(current->id).second && keys.size() < 12) {
            const auto found = steps.find(current->id);
            if (found == steps.end()) break;
            const auto& step = found->second;
            keys.push_back(Trim(step.control->name));
            values.push_back(static_cast<int>(std::llround(step.control->value)));
            structural_chain = structural_chain && step.structural_progress;
            legacy_chain = legacy_chain && step.legacy_progress;
            if (step.structural_progress) {
                if (structural_failure_hub.empty())
                    structural_failure_hub = step.failure_hub;
                else if (structural_failure_hub != step.failure_hub)
                    consistent_failure_hub = false;
            }
            if (step.parameter_terminal) {
                terminal = step.target;
                terminal_parameter = step.control->parameter;
                verified_parameter_terminal = ActiveControllerConsumesParameter(
                    snapshot, terminal_parameter);
                break;
            }
            if (PositiveNavigationTerminal(*step.target)) {
                terminal = step.target;
                break;
            }
            if (!steps.count(step.target->id)) {
                single_terminal_control =
                    SingleControlNavigationTerminal(snapshot, *step.target);
                if (keys.size() >= 3 &&
                    ((FunctionalMenu(*step.target) &&
                      !NegativeNavigationTerminal(*step.target)) ||
                     single_terminal_control != nullptr))
                    terminal = step.target;
                break;
            }
            current = step.target;
        }
        if (!terminal || keys.size() < 3) continue;
        const bool single_control_terminal = single_terminal_control != nullptr;
        const bool requires_structural_entry_proof =
            single_control_terminal || !legacy_chain;
        if (requires_structural_entry_proof &&
            (!structural_chain || !consistent_failure_hub ||
             structural_failure_hub.empty() ||
             active_numeric_entries.count(start_id) == 0))
            continue;

        std::ostringstream password, route;
        for (std::size_t index = 0; index < keys.size(); ++index) {
            password << keys[index];
            if (index) route << u8" → ";
            route << keys[index];
        }
        // Use one identity for the candidate and its click guide. A terminal
        // SubMenu may also write a real parameter; its guide must not retain
        // the navigation-only placeholder and fail the exact-parameter gate.
        const std::string parameter = terminal_parameter.empty()
            ? "navigation:" + start_id : terminal_parameter;
        const bool proven_terminal = terminal_parameter.empty() ||
            verified_parameter_terminal;
        Candidate maze_candidate{u8"(菜单树)", parameter,
            password.str(), password.str(),
            single_control_terminal
                ? u8"活动根可达 + 完整数字面板 + 统一失败汇聚 + 唯一前进路径 + 单控件终端 | " +
                    route.str()
                : u8"唯一前进分支 + 多数失败汇聚 + 成功功能页 | " + route.str(),
            proven_terminal ? u8"高" : u8"参考", -1,
            terminal_parameter.empty() ? std::string{} :
                "menu_parameter_terminal", true};
        maze_candidate.menu_mapped = true;
        maze_candidate.analysis_origin = "menu_tree";
        maze_candidate.family = single_control_terminal
            ? "single_terminal_submenu_maze"
            : "navigation_submenu_maze";
        if (single_terminal_control)
            maze_candidate.menu_terminal_parameter = single_terminal_control->parameter;
        out.push_back(std::move(maze_candidate));
        guides.push_back({password.str(), menus.at(start_id)->name, parameter,
            keys, values});

        // Rewire only a unique non-numeric entry into this validated keypad.
        // This preserves the unlocked feature page and removes the navigation
        // maze itself. A parameter-bearing terminal also performs a runtime
        // write: redirecting its parent skips that write. As in
        // DetectActiveRootParameterMaze, retain the input guide but require a
        // separately proved parameter/effect plan, never a pointer-only plan.
        // Multiple parents and self-links cannot authorize a menu rewrite.
        const auto parents = incoming.find(start_id);
        if (!single_control_terminal && terminal_parameter.empty() &&
            parents != incoming.end() && parents->second.size() == 1 &&
            terminal->id != parents->second.front().parent->id &&
            parents->second.front().control->type == 103 &&
            parents->second.front().control->parameter.empty() &&
            parents->second.front().control->sub_parameters.empty()) {
            const auto& link = parents->second.front();
            json::Value::Object bypass;
            bypass["path_id"] = link.parent->id;
            bypass["control_index"] = link.control_index;
            bypass["before_submenu"] = start_id;
            bypass["after_submenu"] = terminal->id;
            bypass["control_name"] = link.control->name;
            bypass["before_menu_name"] = menus.at(start_id)->name;
            bypass["after_menu_name"] = terminal->name;
            bypass["method"] = "native_navigation_menu_terminal";
            if (!terminal_parameter.empty()) {
                bypass["terminal_parameter"] = terminal_parameter;
                bypass["terminal_parameter_consumed"] = verified_parameter_terminal;
            }
            menu_bypasses.push_back(bypass);
        }
    }
}

#include "split_button_detector.inc"
#include "random_boolean_restore.inc"
#include "compound_restriction_restore.inc"
#include "float_range_gate_restore.inc"
#include "manual_boolean_effect.inc"
#include "selector_proxy_effect.inc"
#include "osc_shift_restore.inc"
#include "osc_suffix_trace.inc"
#include "osc_shift_suffix.inc"
#include "ajisai_osc_feature.inc"
#include "osc_streamed_redirect.inc"

#if defined(__GNUC__)
__attribute__((noinline))
#elif defined(_MSC_VER)
__declspec(noinline)
#endif
void ValidateProtectedFinalDecision(const RuleProfile& rules,
    const std::vector<Candidate>& candidates,
    const json::Value::Array& state_bypasses,
    const json::Value::Array& menu_bypasses,
    const json::Value::Array& condition_rewrites) {
    VRC_VMP_BEGIN_LOCKED("analyze_graph_finalize");
    std::string failure;
    failure.clear();
    for (const auto& candidate : candidates) {
        if (candidate.confidence != u8"高") continue;
        if (!rules.high_enabled ||
                static_cast<int>(candidate.password.size()) < rules.min_password_length ||
                static_cast<int>(candidate.password.size()) > rules.max_password_length) {
            failure = "high confidence candidate rejected by local rule profile";
            break;
        }
    }
    auto validate_methods = [&](const json::Value::Array& values) {
        for (const auto& value : values) {
            const std::string method = String(value, "method");
            if (method.empty() || !SafePlanMethodAllowed(rules, method)) {
                failure = "safe plan method rejected by local rule profile";
                return;
            }
            if (const auto* proofs = value.find("equivalent_proofs")) {
                if (!proofs->is_array() || proofs->array().size() < 2) {
                    failure = "invalid equivalent state plan proofs";
                    return;
                }
                for (const auto& proof : proofs->array()) {
                    if (!SafePlanMethodAllowed(rules, String(proof, "method"))) {
                        failure = "equivalent plan method rejected by local rule profile";
                        return;
                    }
                }
            }
        }
    };
    if (failure.empty()) validate_methods(state_bypasses);
    if (failure.empty()) validate_methods(menu_bypasses);
    if (failure.empty()) validate_methods(condition_rewrites);
    VRC_VMP_END();
    if (!failure.empty())
        throw std::runtime_error("protected final decision rejected: " + failure);
}

json::Value CandidateJson(const Candidate& c) {
    json::Value::Object o;
    o["controller"] = c.controller;
    o["parameter"] = c.parameter;
    o["raw"] = c.raw;
    o["password"] = c.password;
    o["note"] = c.note;
    o["confidence"] = c.confidence;
    o["analysis_origin"] = c.analysis_origin;
    o["input_kind"] = c.input_kind;
    o["runtime_status"] = c.confidence == u8"高"
        ? "runtime_verified" : c.runtime_status;
    if (!c.family.empty()) o["family"] = c.family;
    o["controller_path_id"] = c.controller_path_id;
    o["machine_index"] = static_cast<std::int64_t>(c.machine_index);
    o["terminal_state"] = c.unlock_state;
    return o;
}
json::Value GuideJson(const Guide& g) { json::Value::Object o;o["password"]=g.password;o["menu"]=g.menu;o["parameter"]=g.parameter;json::Value::Array keys,values,parameters;for(const auto&k:g.keys)keys.push_back(k);for(int v:g.values)values.push_back(v);for(const auto&p:g.parameters)parameters.push_back(p);o["keys"]=keys;o["values"]=values;if(!parameters.empty())o["parameters"]=parameters;return o; }

} // namespace

json::Value AnalyzeNormalizedGraph(const fs::path& graph_path) {
    // The public analyzer uses a fixed local policy. There is no online
    // permit, account, device binding, or encrypted rule download.
    const RuleProfile rules = LocalRuleProfile();
    const json::Value graph_input = json::Parse(ReadUtf8File(graph_path));
    const Snapshot snapshot=ParseSnapshot(graph_input);
    const auto menu_maps = BuildMenuMaps(snapshot, rules);
    const auto semantic_ir = AnalyzeSemanticIr(snapshot, menu_maps);
    // Menu reachability and visible/raw mappings are snapshot-wide facts.
    // Building them once avoids repeating the same menu traversal for every
    // Animator state machine in large FX controllers.
    const auto no_reset_numeric_pages =
        DetectorEnabled(rules, detector_parameter_driver)
        ? ReachableNumericPages(snapshot, rules)
        : std::vector<ReachableNumericPageEvidence>{};
    const auto radial_groups = CollectRadialGroups(snapshot);
    const auto avacrypt_v1_menu = DetectorEnabled(rules, detector_avacrypt)
        ? DetectAvaCryptV1Menu(snapshot) : std::optional<AvaCryptV1MenuEvidence>{};
    const auto avacrypt_v1_mesh_solution = DetectorEnabled(rules, detector_avacrypt)
        ? SolveAvaCryptV1MeshKeys(snapshot.avacrypt_v1_mesh_probes)
        : AvaCryptV1SolveResult{};
    auto native_confident = [&](const Candidate& candidate) {
        // Only a detector that explicitly proved its terminal may authorize a
        // native rewrite.  Menu coverage is input evidence, not unlock evidence.
        return rules.high_enabled && candidate.confidence == u8"高" &&
            (!rules.require_verified_terminal_for_bypass ||
                (candidate.unlock_state >= 0 &&
                 !candidate.unlock_method.empty()));
    };
    std::vector<Candidate>candidates;std::vector<Guide>guides;std::map<std::string,std::set<int>>judged;json::Value::Array state_bypasses;json::Value::Array menu_bypasses;json::Value::Array condition_rewrites;
    int menu_recovery_locks = 0;
    int dead_guard_candidates = 0;
    int fixed_contact_candidates = 0;
    std::set<std::pair<std::string, std::size_t>> fixed_contact_plans;
    int dynamic_contact_candidates = 0;
    std::map<DynamicPairKey, StagedDynamicContactPlan>
        staged_dynamic_contact_plans;
    int named_unlock_terminals = 0;
    int random_boolean_restore_count = 0;
    int compound_restriction_restore_count = 0;
    int float_range_gate_restore_count = 0;
    std::set<std::pair<std::string, std::size_t>> named_unlock_plans;
    std::set<ReversePlanKey> committed_reverse_plans;
    std::map<ReversePlanKey, DynamicProducerKey>
        committed_dynamic_producers;
    bool reverse_first_used = false;
    bool legacy_fallback_used = false;
    int legacy_fallback_machine_count = 0;
    std::set<std::string> reverse_verified_controllers;
    std::set<std::string> reverse_verified_parameters;
    for (const auto& controller : snapshot.controllers) {
        // When the AvatarDescriptor was parsed successfully, only its actual FX
        // controller is runtime-active. Package-internal generated copies must
        // not duplicate passwords or receive rewrite plans.
        if (!snapshot.active_fx_controller_ids.empty() &&
            snapshot.active_fx_controller_ids.count(controller.path_id) == 0)
            continue;
        if (DetectorEnabled(rules, detector_parameter_driver)) {
            const auto osc_restore = DetectOscShiftRestore(
                snapshot, controller);
            if (osc_restore.has_value() &&
                osc_restore->machine_index < controller.machines.size()) {
                const auto& machine = controller.machines[
                    osc_restore->machine_index];
                std::ostringstream password;
                for (int digit : osc_restore->password) password << digit;
                Candidate candidate{controller.name,
                    osc_restore->input_parameter, password.str(),
                    password.str(),
                    std::string(u8"OSC 移位寄存器数字锁：完整比较器 → 成功锁存器 → Direct Blend Tree → ") +
                        std::to_string(osc_restore->restored_effects) +
                        u8" 个精确恢复对象",
                    u8"高", osc_restore->success_state,
                    "native_osc_shift_restore_terminal"};
                candidate.input_kind = "osc";
                candidate.analysis_origin = "reverse";
                candidate.family = "osc_shift_register_direct_blend_restore";
                candidate.controller_path_id = controller.path_id;
                candidate.machine_index = osc_restore->machine_index;
                candidates.push_back(std::move(candidate));
                if (SafePlanMethodAllowed(rules,
                        "native_osc_shift_restore_terminal") &&
                    osc_restore->success_state != machine.default_state) {
                    json::Value::Object plan;
                    plan["path_id"] = controller.path_id;
                    plan["machine_index"] = static_cast<std::int64_t>(
                        osc_restore->machine_index);
                    plan["before"] = machine.default_state;
                    plan["unlock_state"] = osc_restore->success_state;
                    plan["unlock_state_name"] = machine.states[
                        static_cast<std::size_t>(
                            osc_restore->success_state)].name;
                    plan["method"] = "native_osc_shift_restore_terminal";
                    plan["proof_family"] =
                        "osc_shift_register_direct_blend_restore_v1";
                    state_bypasses.push_back(std::move(plan));
                    committed_reverse_plans.emplace(controller.path_id,
                        osc_restore->machine_index,
                        osc_restore->success_state,
                        "native_osc_shift_restore_terminal");
                    reverse_first_used = true;
                    reverse_verified_controllers.insert(controller.path_id);
                    reverse_verified_parameters.insert(
                        osc_restore->input_parameter);
                }
            }
        }
        // A narrow binary32 interval gate is a cross-machine family: the
        // producer carries the interval/latch proof while a separate effect
        // machine latches the successful gate pulse.  Keep this detector
        // before per-machine fallback so a generic numeric chain cannot steal
        // the same controller and produce an unsafe plan.
        if (DetectorEnabled(rules, detector_parameter_driver) &&
            SafePlanMethodAllowed(rules, "native_float_range_gate_terminal")) {
            const auto float_gate = DetectFloatRangeGateRestore(
                snapshot, controller);
            if (float_gate.has_value() &&
                float_gate->success_state != float_gate->locked_state &&
                float_gate->producer_machine < controller.machines.size()) {
                const auto& producer = controller.machines[
                    float_gate->producer_machine];
                json::Value::Object plan;
                plan["path_id"] = controller.path_id;
                plan["machine_index"] = static_cast<std::int64_t>(
                    float_gate->producer_machine);
                plan["before"] = producer.default_state;
                plan["unlock_state"] = float_gate->success_state;
                plan["unlock_state_name"] = producer.states[
                    static_cast<std::size_t>(float_gate->success_state)].name;
                plan["method"] = "native_float_range_gate_terminal";
                plan["proof_family"] = "float_range_gate_latched_effect_v1";
                plan["effect_machine_index"] = static_cast<std::int64_t>(
                    float_gate->effect_machine);
                plan["effect_locked_state"] = float_gate->effect_locked_state;
                plan["effect_success_state"] = float_gate->effect_success_state;
                plan["float_parameter"] = float_gate->float_parameter;
                plan["latch_parameter"] = float_gate->latch_parameter;
                plan["gate_parameter"] = float_gate->gate_parameter;
                plan["interval_lower"] = float_gate->lower;
                plan["interval_upper"] = float_gate->upper;
                plan["restored_effect_count"] = static_cast<std::int64_t>(
                    float_gate->restored_effects);
                state_bypasses.push_back(std::move(plan));
                ++float_range_gate_restore_count;
                reverse_first_used = true;
                reverse_verified_controllers.insert(controller.path_id);
            }
        }
        for (std::size_t machine_index = 0;
             machine_index < controller.machines.size(); ++machine_index) {
            const auto& machine = controller.machines[machine_index];
            const std::size_t before = candidates.size();
            if (DetectorEnabled(rules, detector_parameter_driver) &&
                SafePlanMethodAllowed(rules, "native_random_boolean_restore_terminal")) {
                const auto restored = RandomBooleanRestoreTerminal(snapshot, controller, machine_index);
                if (restored) {
                    json::Value::Object plan;
                    plan["path_id"]=controller.path_id;
                    plan["machine_index"]=static_cast<std::int64_t>(machine_index);
                    plan["before"]=machine.default_state;
                    plan["unlock_state"]=*restored;
                    plan["unlock_state_name"]=machine.states[static_cast<std::size_t>(*restored)].name;
                    plan["method"]="native_random_boolean_restore_terminal";
                    plan["proof_family"]="random_boolean_complementary_restore_v1";
                    state_bypasses.push_back(plan); ++random_boolean_restore_count;
                }
            }
            if (DetectorEnabled(rules, detector_parameter_driver) &&
                SafePlanMethodAllowed(rules, "native_compound_restriction_terminal")) {
                const auto restored = CompoundRestrictionTerminal(
                    snapshot, controller, machine_index);
                if (restored) {
                    json::Value::Object plan;
                    plan["path_id"] = controller.path_id;
                    plan["machine_index"] = static_cast<std::int64_t>(machine_index);
                    plan["before"] = machine.default_state;
                    plan["unlock_state"] = *restored;
                    plan["unlock_state_name"] = machine.states[
                        static_cast<std::size_t>(*restored)].name;
                    plan["method"] = "native_compound_restriction_terminal";
                    plan["proof_family"] = "compound_latch_restriction_v1";
                    state_bypasses.push_back(std::move(plan));
                    ++compound_restriction_restore_count;
                }
            }
            // Reverse-first path: recover a concrete success terminal and
            // walk backwards through the executable keypad transitions before
            // consulting any heuristic/legacy detector.  The reverse path is
            // intentionally limited to detectors that emit a complete,
            // semantically-validated candidate; a mere numeric chain is not a
            // success signal.
            PressReleaseDetection press_release;
            const auto fail_stop_dual_latch =
                DetectorEnabled(rules, detector_parameter_driver)
                ? DetectFailStopDualSavedLatch(snapshot, controller,
                    machine_index, machine, menu_maps)
                : std::optional<FailStopDualLatchEvidence>{};
            const auto no_reset_sync =
                !fail_stop_dual_latch.has_value() &&
                    DetectorEnabled(rules, detector_parameter_driver)
                ? DetectNoResetSynchronizingLatch(snapshot, controller,
                    machine_index, machine, rules, no_reset_numeric_pages)
                : std::optional<NoResetSynchronizingEvidence>{};
            if (fail_stop_dual_latch.has_value()) {
                std::ostringstream password;
                std::ostringstream raw;
                for (int value : fail_stop_dual_latch->visible_spine)
                    password << value;
                for (int value : fail_stop_dual_latch->raw_spine)
                    raw << value;
                Candidate candidate{controller.name,
                    fail_stop_dual_latch->parameter, raw.str(),
                    password.str(),
                    std::string(u8"错误终止双锁存器：有序 Equality 主链 + 每层统一失败终点 + 保存型成功终点 | ") +
                        u8"该结构可能允许无害等待输入，输出为最短规范解锁序列",
                    u8"高", fail_stop_dual_latch->success_state,
                    "native_fail_stop_dual_saved_latch_terminal"};
                candidate.menu_mapped = true;
                candidate.family =
                    "menu_backed_fail_stop_dual_saved_latch";
                candidates.push_back(std::move(candidate));
            } else if (no_reset_sync.has_value()) {
                std::ostringstream password;
                std::ostringstream raw;
                for (int value : no_reset_sync->visible_spine)
                    password << value;
                for (int value : no_reset_sync->raw_spine)
                    raw << value;
                Candidate candidate{controller.name, no_reset_sync->parameter,
                    raw.str(), password.str(),
                    std::string(u8"无回零同步锁存器：规范 Equality spine / 已验证工作序列 | ") +
                        u8"该同步 DFA 可能存在其他工作词，本序列不代表唯一可接受序列 | 菜单「" +
                        no_reset_sync->menu_name + u8"」交叉验证",
                    u8"高", no_reset_sync->success_state,
                    "native_no_reset_sync_latch_terminal"};
                candidate.menu_mapped = true;
                candidate.family = "menu_backed_noreset_sync_latch";
                candidates.push_back(std::move(candidate));
            } else {
                press_release = DetectorEnabled(rules, detector_press_release)
                    ? DetectPressReleaseKeypad(
                        snapshot, controller, machine, menu_maps, candidates)
                    : PressReleaseDetection{};
                if (DetectorEnabled(rules, detector_parameter_driver))
                    DetectParameterDriverKeypad(
                        snapshot, controller, machine_index, machine,
                        menu_maps, candidates);
                if (DetectorEnabled(rules, detector_button_pulse))
                    DetectButtonPulseDispatchKeypad(
                        controller, machine, menu_maps, candidates);
                if (DetectorEnabled(rules, detector_button_pulse))
                    DetectMultiplexedFeatureKeypad(
                        controller, machine, menu_maps, candidates);
            }
            const auto reverse_candidate_begin =
                candidates.begin() + static_cast<std::ptrdiff_t>(before);
            for (auto it = reverse_candidate_begin; it != candidates.end(); ++it) {
                it->analysis_origin = "reverse";
                it->controller_path_id = controller.path_id;
                it->machine_index = machine_index;
                it->guide_allowed = false;
            }
            const bool reverse_verified = std::any_of(
                reverse_candidate_begin, candidates.end(),
                [](const Candidate& candidate) {
                    return candidate.confidence == u8"高" &&
                        candidate.unlock_state >= 0 &&
                        !candidate.unlock_method.empty() &&
                        !candidate.password.empty();
                });
            if (reverse_verified) {
                reverse_first_used = true;
                for (auto it = reverse_candidate_begin;
                     it != candidates.end(); ++it)
                    if (it->confidence == u8"高")
                        reverse_verified_parameters.insert(it->parameter);
                if (!controller.path_id.empty())
                    reverse_verified_controllers.insert(controller.path_id);
            } else {
                // Specialized compatibility detectors remain available for
                // non-reverse families (AvaCrypt/radial/boolean/menu layouts).
                // They are never included in the reverse candidate pool.
                legacy_fallback_used = true;
                ++legacy_fallback_machine_count;
                if (DetectorEnabled(rules, detector_reset_guarded))
                    DetectResetGuardedCombination(controller.name, machine, candidates);
                if (DetectorEnabled(rules, detector_legacy_state))
                    AnalyzeMachine(controller.name, machine, candidates);
                if (DetectorEnabled(rules, detector_radial))
                    DetectRadialDial(controller.name, machine, radial_groups, candidates);
                if (DetectorEnabled(rules, detector_parallel_dial)) {
                    DetectParallelDialCombination(controller.name, machine, snapshot, candidates, guides);
                }

                // Legacy detectors predate the reverse-first provenance fields
                // and therefore only receive the display controller name.  Bind
                // every row emitted by this machine to its immutable snapshot
                // coordinates before any later arbitration/deduplication.  The
                // binding is provenance only: legacy rows remain reference
                // candidates and do not gain a terminal or a write plan from
                // this assignment.
                for (std::size_t index = before; index < candidates.size(); ++index) {
                    auto& candidate = candidates[index];
                    if (candidate.controller_path_id.empty())
                        candidate.controller_path_id = controller.path_id;
                    if (candidate.machine_index == static_cast<std::size_t>(-1))
                        candidate.machine_index = machine_index;
                }
            }
            // Cross-menu guarded candidates are not emitted until the complete
            // runtime input path has been proven.  Partial digit prefixes must
            // never be presented as passwords or authorize a rewrite.
            const auto named_unlock = DetectorEnabled(rules, detector_named_unlock)
                ? StrongNamedUnlockWriteTerminal(controller, machine)
                : std::optional<int>{};
            if (named_unlock.has_value()) {
                if (!controller.path_id.empty() &&
                    *named_unlock != machine.default_state &&
                    named_unlock_plans.insert(
                        {controller.path_id, machine_index}).second) {
                    json::Value::Object bypass;
                    bypass["path_id"] = controller.path_id;
                    bypass["machine_index"] =
                        static_cast<std::int64_t>(machine_index);
                    bypass["before"] = machine.default_state;
                    bypass["unlock_state"] = *named_unlock;
                    bypass["unlock_state_name"] =
                        machine.states[static_cast<std::size_t>(*named_unlock)].name;
                    bypass["method"] =
                        "native_named_unlock_semantic_terminal";
                    if (SafePlanMethodAllowed(rules,
                            "native_named_unlock_semantic_terminal")) {
                        state_bypasses.push_back(bypass);
                        ++named_unlock_terminals;
                    }
                }
            }
            for (std::size_t index = before; index < candidates.size(); ++index) {
                if (!DetectorEnabled(rules, detector_fixed_contact)) continue;
                const auto blocked_guard = FixedContactBlockedGuard(
                    snapshot, controller, machine_index, machine,
                    candidates[index]);
                if (!blocked_guard.has_value()) continue;
                ++fixed_contact_candidates;
                const auto terminal = SemanticUnlockedTerminal(controller, machine);
                if (!terminal.has_value() || controller.path_id.empty() ||
                    *terminal == machine.default_state ||
                    !fixed_contact_plans.insert(
                        {controller.path_id, machine_index}).second)
                    continue;
                json::Value::Object bypass;
                bypass["path_id"] = controller.path_id;
                bypass["machine_index"] =
                    static_cast<std::int64_t>(machine_index);
                bypass["before"] = machine.default_state;
                bypass["unlock_state"] = *terminal;
                bypass["unlock_state_name"] =
                    machine.states[static_cast<std::size_t>(*terminal)].name;
                bypass["method"] =
                    "native_contact_guarded_semantic_terminal";
                if (SafePlanMethodAllowed(rules,
                        "native_contact_guarded_semantic_terminal"))
                    state_bypasses.push_back(bypass);
            }
            for (std::size_t index = before; index < candidates.size(); ++index) {
                const auto guard_status = CandidateHasDeterministicallyBlockedGuard(
                    snapshot, controller, machine_index, machine,
                    candidates[index]);
                if (guard_status == GuardReachability::ProvenBlocked) {
                    ++dead_guard_candidates;
                } else if (guard_status == GuardReachability::Unknown) {
                    // Unknown guard reachability is not evidence of a live
                    // password.  Keep the sequence only as a reference and
                    // make sure it cannot authorize a guide or rewrite plan.
                    candidates[index].confidence = u8"参考";
                    candidates[index].guide_allowed = false;
                    candidates[index].note +=
                        (candidates[index].note.empty() ? " | " : " | ") +
                        std::string(u8"门控可达性未知，已降级为参考候选");
                    if (HasUnprovenContactInputDependency(snapshot, controller,
                            machine_index, machine, candidates[index])) {
                        candidates[index].runtime_status = "runtime_incomplete";
                        candidates[index].note += u8" | Contact 前置复位未证实，数字路径不等于游戏内可用密码";
                    }
                }
            }
            candidates.erase(std::remove_if(
                candidates.begin() + static_cast<std::ptrdiff_t>(before),
                candidates.end(),
                [&](const Candidate& candidate) {
                    return CandidateHasDeterministicallyBlockedGuard(
                        snapshot, controller, machine_index, machine, candidate) ==
                        GuardReachability::ProvenBlocked;
                }), candidates.end());
            // A contact-input-only gate has no extracted sender polarity or
            // physical trigger path. Preserve its inferred digits for the
            // operator, but fail closed until runtime evidence is available.
            for (std::size_t index = before; index < candidates.size(); ++index) {
                if (candidates[index].confidence != u8"高" ||
                    !HasUnprovenContactInputDependency(
                        snapshot, controller, machine_index, machine,
                        candidates[index]))
                    continue;
                candidates[index].confidence = u8"参考";
                candidates[index].guide_allowed = false;
                candidates[index].runtime_status = "runtime_incomplete";
                candidates[index].note += u8" | 前置条件未证实：需先触发隐藏 Contact 输入";
            }
            // Unity 2022.3.22f1 + Avatar SDK 3.10.4 runtime probes show that
            // zero-weight Animator layers still advance their state machines
            // and invoke the SDK's VRCAvatarParameterDriver apply delegate.
            // Weight therefore cannot suppress a menu-mapped keypad.  Keep the
            // exposed-input gate for zero-weight anonymous chains, however: an
            // executable state machine whose parameter has no reachable menu is
            // not a password the user can enter and must remain audit-only.
            const bool serialized_weight_positive = machine_index == 0 ||
                (machine.default_weight_known && machine.default_weight > 0.0001);
            const auto has_numeric_menu_mapping = [&](const Candidate& candidate) {
                const auto mapping = menu_maps.find(candidate.parameter);
                return mapping != menu_maps.end() && !mapping->second.empty();
            };
            const auto has_direct_osc_input = [&](const Candidate& candidate) {
                return candidate.input_kind == "osc" &&
                    snapshot.expression_parameters.count(candidate.parameter) != 0;
            };
            for (std::size_t index = before; index < candidates.size(); ++index) {
                if (serialized_weight_positive ||
                    has_numeric_menu_mapping(candidates[index]) ||
                    has_direct_osc_input(candidates[index]))
                    continue;
                candidates[index].confidence = u8"参考";
                candidates[index].note +=
                    (candidates[index].note.empty() ? "" : " | ") +
                    std::string(u8"零权重层可执行，但缺少可达菜单输入映射");
            }
            candidates.erase(
                std::remove_if(
                    candidates.begin() + static_cast<std::ptrdiff_t>(before),
                    candidates.end(),
                    [&](const Candidate& candidate) {
                        if (candidate.unlock_method ==
                            "native_button_pulse_dispatch_terminal")
                            return false;
                        // A strict explicit or anonymous multi-page keypad map
                        // is positive input evidence.  Invisible labels alone
                        // must not reclassify that same mapped parameter as a
                        // non-password feature menu.
                        if (has_numeric_menu_mapping(candidate) ||
                            has_direct_osc_input(candidate)) return false;
                        return ConflictsWithNonPasswordMenus(snapshot, candidate);
                    }),
                candidates.end());

            const auto first_new =
                candidates.begin() + static_cast<std::ptrdiff_t>(before);
            const auto high_it = std::find_if(first_new, candidates.end(), native_confident);
            const auto explicit_unlock_it = std::find_if(
                first_new, candidates.end(),
                [&](const Candidate& candidate) {
                    return native_confident(candidate) &&
                        candidate.unlock_state >= 0 &&
                        !candidate.unlock_method.empty();
                });
            const bool has_exposed_candidate = std::any_of(
                first_new, candidates.end(),
                [&](const Candidate& candidate) {
                    return has_numeric_menu_mapping(candidate) ||
                        has_direct_osc_input(candidate);
                });
            const bool machine_high = high_it != candidates.end() ||
                (press_release.safe_unlock_state >= 0 &&
                    (serialized_weight_positive || has_exposed_candidate));

            // Select one exact Contact-aware candidate.  The producer and the
            // keypad terminal must come from this same proof; independently
            // selecting a generic high candidate and a later terminal can
            // splice two unrelated paths in a large generated controller.
            const auto contact_candidate = [&](const Candidate& candidate) {
                return native_confident(candidate) &&
                    HasDynamicContactGuardDependency(snapshot, controller,
                        machine_index, machine, candidate);
            };
            const auto exact_contact_candidate = [&](const Candidate& candidate) {
                return contact_candidate(candidate) &&
                    candidate.unlock_state >= 0 &&
                    !candidate.unlock_method.empty();
            };
            const auto contact_candidate_count = static_cast<std::size_t>(
                std::count_if(first_new, candidates.end(), contact_candidate));
            const auto exact_contact_candidate_count = static_cast<std::size_t>(
                std::count_if(first_new, candidates.end(), exact_contact_candidate));
            const auto exact_contact_it = std::find_if(
                first_new, candidates.end(), exact_contact_candidate);
            const bool has_dynamic_contact_dependency =
                machine_high && contact_candidate_count != 0;
            const bool dynamic_contact_guarded =
                has_dynamic_contact_dependency && contact_candidate_count == 1 &&
                exact_contact_candidate_count == 1 &&
                exact_contact_it != candidates.end();
            std::optional<json::Value::Object> dynamic_contact_bypass;
            std::optional<DynamicProducerKey> dynamic_contact_producer_key;
            if (dynamic_contact_guarded) {
                const auto settlement = DynamicContactSettlementState(
                    snapshot, controller, machine_index, machine,
                    *exact_contact_it);
                if (settlement.has_value() && !controller.path_id.empty()) {
                    const auto [settlement_machine, settlement_state] = *settlement;
                    if (settlement_machine < controller.machines.size()) {
                        const auto& gate_machine =
                            controller.machines[settlement_machine];
                        if (settlement_state >= 0 &&
                            settlement_state < static_cast<int>(gate_machine.states.size()) &&
                            settlement_state != gate_machine.default_state) {
                            json::Value::Object bypass;
                            bypass["path_id"] = controller.path_id;
                            bypass["machine_index"] =
                                static_cast<std::int64_t>(settlement_machine);
                            bypass["before"] = gate_machine.default_state;
                            bypass["unlock_state"] = settlement_state;
                            bypass["unlock_state_name"] = gate_machine.states[
                                static_cast<std::size_t>(settlement_state)].name;
                            bypass["method"] =
                                "native_contact_guarded_semantic_terminal";
                            dynamic_contact_bypass = std::move(bypass);
                            dynamic_contact_producer_key =
                                DynamicProducerKey{controller.path_id,
                                    settlement_machine, settlement_state,
                                    "native_contact_guarded_semantic_terminal"};
                        }
                    }
                }
            }
            int unlock = -1;
            std::string plan_method;
            if (dynamic_contact_guarded) {
                unlock = exact_contact_it->unlock_state;
                plan_method = exact_contact_it->unlock_method;
            } else if (!has_dynamic_contact_dependency && machine_high &&
                explicit_unlock_it != candidates.end()) {
                unlock = explicit_unlock_it->unlock_state;
                plan_method = explicit_unlock_it->unlock_method;
            }
            if (!has_dynamic_contact_dependency && machine_high && unlock < 0 &&
                press_release.safe_unlock_state >= 0) {
                unlock = press_release.safe_unlock_state;
                plan_method = "native_press_release_semantic_terminal";
            }
            if (!has_dynamic_contact_dependency && machine_high && unlock < 0) {
                unlock = NamedUnlockState(machine);
                plan_method = "native_named_unlock";
            }
            std::optional<json::Value::Object> password_bypass;
            // Never install the end of an anonymous longest chain as the default
            // state.  The terminal may be failure, reset, or obfuscation logic.
            if (machine_high && unlock >= 0 &&
                unlock < static_cast<int>(machine.states.size()) &&
                !controller.path_id.empty() &&
                unlock != machine.default_state) {
                json::Value::Object bypass;
                bypass["path_id"] = controller.path_id;
                bypass["machine_index"] = static_cast<std::int64_t>(machine_index);
                bypass["before"] = machine.default_state;
                bypass["unlock_state"] = unlock;
                bypass["unlock_state_name"] =
                    machine.states[static_cast<std::size_t>(unlock)].name;
                bypass["method"] = plan_method;
                password_bypass = std::move(bypass);
            }
            if (has_dynamic_contact_dependency) {
                // A dynamic Contact keypad is a two-machine lock.  Installing
                // only the Contact producer terminal or only the password
                // terminal can leave the avatar in a transient/locked state.
                // Stage the complete pair.  Global one-to-one conflict checks
                // run after every controller/machine has been inspected, so a
                // later competing keypad cannot leave an earlier first-wins
                // pair in the output.
                if (dynamic_contact_guarded &&
                    dynamic_contact_bypass.has_value() &&
                    dynamic_contact_producer_key.has_value() &&
                    password_bypass.has_value() &&
                    SafePlanMethodAllowed(rules,
                        "native_contact_guarded_semantic_terminal") &&
                    SafePlanMethodAllowed(rules, plan_method) &&
                    std::get<1>(*dynamic_contact_producer_key) != machine_index) {
                    const DynamicKeypadKey keypad_key{controller.path_id,
                        machine_index, unlock, plan_method};
                    const DynamicPairKey pair_key{
                        *dynamic_contact_producer_key, keypad_key};
                    StagedDynamicContactPlan staged;
                    staged.key = pair_key;
                    staged.producer_before = static_cast<int>(
                        dynamic_contact_bypass->at("before").number());
                    staged.keypad_before = static_cast<int>(
                        password_bypass->at("before").number());
                    staged.producer_bypass = *dynamic_contact_bypass;
                    staged.keypad_bypass = *password_bypass;
                    const auto [staged_it, inserted] =
                        staged_dynamic_contact_plans.emplace(
                            pair_key, std::move(staged));
                    if (!inserted &&
                        (staged_it->second.producer_before != static_cast<int>(
                             dynamic_contact_bypass->at("before").number()) ||
                         staged_it->second.keypad_before != static_cast<int>(
                             password_bypass->at("before").number())))
                        staged_it->second.inconsistent_duplicate = true;
                }
            } else if (password_bypass.has_value()) {
                if (SafePlanMethodAllowed(rules, plan_method)) {
                    state_bypasses.push_back(*password_bypass);
                    committed_reverse_plans.emplace(controller.path_id,
                        machine_index, unlock, plan_method);
                    // Bind guide eligibility to the exact terminal plan.  A
                    // reverse candidate that later loses this plan must remain
                    // reference-only; it must not leave a stale GUIDE row.
                    for (auto it = first_new; it != candidates.end(); ++it) {
                        if (it->analysis_origin == "reverse" &&
                            it->unlock_state == unlock &&
                            it->unlock_method == plan_method)
                            it->guide_allowed = true;
                    }
                }
            }
            if (press_release.needs_menu_recovery &&
                press_release.safe_unlock_state >= 0) ++menu_recovery_locks;
            for (const auto& state : machine.states)
                for (const auto& transition : state.transitions)
                    for (const auto& condition : transition.conditions)
                        if (condition.mode == 6)
                            judged[condition.parameter].insert(
                                static_cast<int>(std::llround(condition.threshold)));
        }

        // This generator family separates icon-only Bool buttons, a temporary
        // digit bus, an ordered sentinel buffer and the obfuscated comparator
        // into different machines.  Per-machine detectors cannot close that
        // path, so run the structural cross-machine proof once per active FX.
        if (DetectorEnabled(rules, detector_parameter_driver)) {
            DetectNumericButtonShiftCombination(controller, snapshot,
                candidates, guides, state_bypasses, committed_reverse_plans, rules);
            const auto split =
                DetectSplitButtonSentinelBuffer(snapshot, controller);
            if (split.has_value() && !controller.path_id.empty() &&
                split->comparator_machine < controller.machines.size()) {
                const ReversePlanKey key{controller.path_id,
                    split->comparator_machine, split->unlock_state,
                    "native_split_button_sentinel_buffer_terminal"};
                const bool physical_plan_conflict = std::any_of(
                    state_bypasses.begin(), state_bypasses.end(),
                    [&](const json::Value& value) {
                        if (!value.is_object()) return false;
                        const auto* path = value.find("path_id");
                        const auto* machine = value.find("machine_index");
                        return path && path->is_string() &&
                            machine && machine->is_number() &&
                            path->string() == controller.path_id &&
                            static_cast<std::size_t>(std::llround(
                                machine->number())) ==
                                split->comparator_machine;
                    });
                if (!physical_plan_conflict &&
                    SafePlanMethodAllowed(rules,
                        "native_split_button_sentinel_buffer_terminal")) {
                    std::ostringstream password;
                    for (int digit : split->digits) password << digit;
                    Candidate candidate{controller.name, split->digit_bus,
                        password.str(), password.str(),
                        std::string(u8"图标式分离按钮密码锁：独立 Bool 按钮 → 数字总线 → 哨兵缓冲区 → 混淆比较器 → 可见锁定效果 | ") +
                            u8"按 Animator 首条可用转移逐槽反推唯一规范序列",
                        u8"高", split->unlock_state,
                        "native_split_button_sentinel_buffer_terminal"};
                    candidate.menu_mapped = true;
                    candidate.analysis_origin = "reverse";
                    candidate.family =
                        "split_button_sentinel_buffer_comparator";
                    candidate.controller_path_id = controller.path_id;
                    candidate.machine_index = split->comparator_machine;
                    candidate.guide_allowed = true;
                    candidates.push_back(std::move(candidate));

                    const auto& comparator = controller.machines[
                        split->comparator_machine];
                    json::Value::Object bypass;
                    bypass["path_id"] = controller.path_id;
                    bypass["machine_index"] = static_cast<std::int64_t>(
                        split->comparator_machine);
                    bypass["before"] = comparator.default_state;
                    bypass["unlock_state"] = split->unlock_state;
                    bypass["unlock_state_name"] = comparator.states[
                        static_cast<std::size_t>(split->unlock_state)].name;
                    bypass["method"] =
                        "native_split_button_sentinel_buffer_terminal";
                    state_bypasses.push_back(std::move(bypass));
                    committed_reverse_plans.insert(key);

                    Guide guide;
                    guide.password = password.str();
                    guide.menu = split->menu_name;
                    guide.parameter = split->digit_bus;
                    guide.parameters = split->button_parameters;
                    for (int digit : split->digits) {
                        guide.keys.push_back(std::to_string(digit));
                        guide.values.push_back(1);
                    }
                    guides.push_back(std::move(guide));
                    reverse_first_used = true;
                    reverse_verified_controllers.insert(controller.path_id);
                    reverse_verified_parameters.insert(split->digit_bus);
                } else if (!physical_plan_conflict) {
                    // A signed policy may disable rewriting without disabling
                    // analysis. Preserve the independently solved input as a
                    // display-only candidate; never create a plan or guide.
                    std::ostringstream password;
                    for (int digit : split->digits) password << digit;
                    Candidate candidate{controller.name, split->digit_bus,
                        password.str(), password.str(),
                        u8"图标式分离按钮比较器已完成结构推导；当前规则未开放自动移除，仅供手动输入。", u8"参考"};
                    candidate.menu_mapped = true;
                    candidate.guide_allowed = false;
                    candidate.analysis_origin = "reverse";
                    candidate.family = "split_button_sentinel_buffer_comparator";
                    candidates.push_back(std::move(candidate));
                    reverse_first_used = true;
                }
            }
        }
    }

    // Contact-gated password plans are committed only after the complete scan
    // proves a one-to-one producer/keypad relationship in both directions.
    // This makes the result independent of controller iteration order and
    // prevents a later conflict from leaving an earlier half-proven pair.
    std::map<DynamicProducerKey, std::set<DynamicKeypadKey>>
        producer_to_keypads;
    std::map<DynamicKeypadKey, std::set<DynamicProducerKey>>
        keypad_to_producers;
    using PhysicalMachineKey = std::pair<std::string, std::size_t>;
    using PhysicalTarget = std::pair<int, std::string>;
    std::map<PhysicalMachineKey, std::set<PhysicalTarget>> physical_targets;
    for (const auto& [pair_key, staged] : staged_dynamic_contact_plans) {
        if (staged.inconsistent_duplicate) continue;
        const auto& producer_key = pair_key.first;
        const auto& keypad_key = pair_key.second;
        producer_to_keypads[producer_key].insert(keypad_key);
        keypad_to_producers[keypad_key].insert(producer_key);
        physical_targets[{std::get<0>(producer_key),
            std::get<1>(producer_key)}].insert(
                {std::get<2>(producer_key), std::get<3>(producer_key)});
        physical_targets[{std::get<0>(keypad_key),
            std::get<1>(keypad_key)}].insert(
                {std::get<2>(keypad_key), std::get<3>(keypad_key)});
    }

    // -1 = conflicting plan already exists for this physical machine,
    //  0 = no plan exists, 1 = the exact plan is already present.
    const auto existing_plan_relation =
        [&](const json::Value::Object& wanted) {
            const auto wanted_path = wanted.at("path_id").string();
            const auto wanted_machine = static_cast<std::size_t>(
                std::llround(wanted.at("machine_index").number()));
            const auto wanted_before = static_cast<int>(
                std::llround(wanted.at("before").number()));
            const auto wanted_state = static_cast<int>(
                std::llround(wanted.at("unlock_state").number()));
            const auto wanted_method = wanted.at("method").string();
            bool identical = false;
            for (const auto& value : state_bypasses) {
                if (!value.is_object()) continue;
                const auto& object = value.object();
                const auto path = object.find("path_id");
                const auto machine = object.find("machine_index");
                if (path == object.end() || !path->second.is_string() ||
                    machine == object.end() || !machine->second.is_number() ||
                    path->second.string() != wanted_path ||
                    static_cast<std::size_t>(std::llround(
                        machine->second.number())) != wanted_machine)
                    continue;
                const auto before = object.find("before");
                const auto state = object.find("unlock_state");
                const auto method = object.find("method");
                if (before == object.end() || !before->second.is_number() ||
                    state == object.end() || !state->second.is_number() ||
                    method == object.end() || !method->second.is_string() ||
                    static_cast<int>(std::llround(before->second.number())) !=
                        wanted_before ||
                    static_cast<int>(std::llround(state->second.number())) !=
                        wanted_state ||
                    method->second.string() != wanted_method)
                    return -1;
                identical = true;
            }
            return identical ? 1 : 0;
        };

    for (const auto& [pair_key, staged] : staged_dynamic_contact_plans) {
        if (staged.inconsistent_duplicate) continue;
        const auto& producer_key = pair_key.first;
        const auto& keypad_key = pair_key.second;
        const auto producer_links = producer_to_keypads.find(producer_key);
        const auto keypad_links = keypad_to_producers.find(keypad_key);
        if (producer_links == producer_to_keypads.end() ||
            producer_links->second.size() != 1 ||
            keypad_links == keypad_to_producers.end() ||
            keypad_links->second.size() != 1)
            continue;
        const PhysicalMachineKey producer_machine{
            std::get<0>(producer_key), std::get<1>(producer_key)};
        const PhysicalMachineKey keypad_machine{
            std::get<0>(keypad_key), std::get<1>(keypad_key)};
        if (producer_machine == keypad_machine ||
            physical_targets[producer_machine].size() != 1 ||
            physical_targets[keypad_machine].size() != 1)
            continue;
        const int producer_relation =
            existing_plan_relation(staged.producer_bypass);
        const int keypad_relation =
            existing_plan_relation(staged.keypad_bypass);
        if (producer_relation < 0 || keypad_relation < 0) continue;

        if (producer_relation == 0)
            state_bypasses.push_back(staged.producer_bypass);
        if (keypad_relation == 0)
            state_bypasses.push_back(staged.keypad_bypass);
        if (existing_plan_relation(staged.producer_bypass) != 1 ||
            existing_plan_relation(staged.keypad_bypass) != 1)
            continue;

        committed_reverse_plans.insert(keypad_key);
        committed_dynamic_producers[keypad_key] = producer_key;
        for (auto& candidate : candidates) {
            if (candidate.analysis_origin != "reverse" ||
                candidate.controller_path_id != std::get<0>(keypad_key) ||
                candidate.machine_index != std::get<1>(keypad_key) ||
                candidate.unlock_state != std::get<2>(keypad_key) ||
                candidate.unlock_method != std::get<3>(keypad_key))
                continue;
            candidate.guide_allowed = true;
        }
        ++dynamic_contact_candidates;
    }

    // Merge the effect-driven semantic pass after the specialized reverse
    // detectors.  Existing answers always win; this pass can only add a new
    // candidate or a new independently proven terminal plan.
    for (const auto& semantic : semantic_ir.candidates) {
        const bool parameter_already_covered = !semantic.strict_terminal &&
            semantic.family.rfind("local_smt_integer_", 0) != 0 &&
            std::any_of(candidates.begin(), candidates.end(),
                [&](const Candidate& existing) {
                    if (existing.parameter != semantic.parameter) return false;
                    if (!semantic.controller_path_id.empty() &&
                        !existing.controller_path_id.empty())
                        return existing.controller_path_id ==
                            semantic.controller_path_id;
                    return existing.controller == semantic.controller;
                });
        if (parameter_already_covered) continue;
        const bool covered_by_specialized = std::any_of(
            candidates.begin(), candidates.end(), [&](const Candidate& existing) {
                return existing.analysis_origin == "reverse" &&
                    existing.confidence == u8"高" &&
                    existing.parameter == semantic.parameter &&
                    existing.controller_path_id == semantic.controller_path_id &&
                    existing.machine_index == semantic.machine_index &&
                    existing.unlock_state >= 0 &&
                    !existing.unlock_method.empty();
            });
        if (covered_by_specialized) continue;
        const bool duplicate = std::any_of(candidates.begin(), candidates.end(),
            [&](const Candidate& existing) {
                return existing.password == semantic.password &&
                    existing.parameter == semantic.parameter;
            });
        if (duplicate) continue;

        bool strict = semantic.strict_terminal &&
            !semantic.controller_path_id.empty() &&
            semantic.machine_index != static_cast<std::size_t>(-1) &&
            semantic.terminal_state >= 0 &&
            SafePlanMethodAllowed(rules, "native_semantic_ir_terminal");
        if (strict) {
            for (const auto& value : state_bypasses) {
                if (!value.is_object()) continue;
                const auto* path = value.find("path_id");
                const auto* machine = value.find("machine_index");
                if (path && path->is_string() && machine && machine->is_number() &&
                    path->string() == semantic.controller_path_id &&
                    static_cast<std::size_t>(std::llround(machine->number())) ==
                        semantic.machine_index) {
                    strict = false;
                    break;
                }
            }
        }

        Candidate candidate{semantic.controller, semantic.parameter,
            semantic.raw, semantic.password,
            semantic.input_kind == "osc"
                ? std::string(u8"语义 IR：从模型恢复效果反向切片并按 Animator 顺序逐帧复放 | OSC 原始值输入 | 家族 ") +
                    semantic.family
                : std::string(u8"语义 IR：从模型恢复效果反向切片并按 Animator 顺序逐帧复放 | 菜单「") +
                    semantic.menu + u8"」交叉验证 | 家族 " + semantic.family,
            strict ? u8"高" : u8"参考", semantic.terminal_state,
            strict ? "native_semantic_ir_terminal" : ""};
        candidate.input_kind = semantic.input_kind;
        candidate.menu_mapped = semantic.input_kind == "menu";
        candidate.guide_allowed = false;
        candidate.analysis_origin = "reverse";
        candidate.family = semantic.family;
        candidate.runtime_status = strict ? "runtime_verified" :
            (semantic.replay_verified ? "runtime_possible" :
                "runtime_incomplete");
        candidate.controller_path_id = semantic.controller_path_id;
        candidate.machine_index = semantic.machine_index;

        if (strict) {
            const auto& machine = [&]() -> const Machine& {
                for (const auto& controller : snapshot.controllers)
                    if (controller.path_id == semantic.controller_path_id)
                        return controller.machines[semantic.machine_index];
                throw std::runtime_error("semantic IR controller vanished");
            }();
            json::Value::Object bypass;
            bypass["path_id"] = semantic.controller_path_id;
            bypass["machine_index"] =
                static_cast<std::int64_t>(semantic.machine_index);
            bypass["before"] = machine.default_state;
            bypass["unlock_state"] = semantic.terminal_state;
            bypass["unlock_state_name"] = machine.states[
                static_cast<std::size_t>(semantic.terminal_state)].name;
            bypass["method"] = "native_semantic_ir_terminal";
            state_bypasses.push_back(bypass);
            committed_reverse_plans.emplace(semantic.controller_path_id,
                semantic.machine_index, semantic.terminal_state,
                "native_semantic_ir_terminal");
            candidate.guide_allowed = true;
            reverse_first_used = true;
            reverse_verified_controllers.insert(semantic.controller_path_id);
            reverse_verified_parameters.insert(semantic.parameter);

            if (semantic.input_kind == "menu") {
                Guide guide;
                guide.password = semantic.password;
                guide.menu = semantic.menu;
                guide.parameter = semantic.parameter;
                for (int value : semantic.visible_values)
                    guide.keys.push_back(std::to_string(value));
                guide.values = semantic.raw_values;
                guides.push_back(std::move(guide));
            }
        }
        candidates.push_back(std::move(candidate));
    }

    for (const auto& controller : snapshot.controllers) {
        if (!snapshot.active_fx_controller_ids.empty() &&
            snapshot.active_fx_controller_ids.count(controller.path_id) == 0)
            continue;
        if (DetectorEnabled(rules, detector_boolean_toggle) &&
            reverse_verified_controllers.count(controller.path_id) == 0) {
            legacy_fallback_used = true;
            DetectBooleanToggleCombination(
                snapshot, controller, candidates, state_bypasses);
        }
    }
    if (DetectorEnabled(rules, detector_menu_tree)) {
        legacy_fallback_used = true;
        DetectTreeDecoys(snapshot,judged,candidates);
        DetectBreadcrumbKeypad(snapshot,candidates,guides);
        DetectNavigationMaze(snapshot,candidates,guides,menu_bypasses);
        DetectSparseTerminalSubmenuTree(snapshot,candidates,guides);
            DetectActiveRootParameterMaze(snapshot,candidates,guides,menu_bypasses);
    }

    // A menu terminal that gates a feature transition with one Boolean and one
    // numeric selector is not a pointer-only menu bypass.  Prove the bounded
    // AND-idempotence substitution against the complete targeted-deep graph;
    // only then expose same-size condition records for the server writer.
    for (auto& candidate : candidates) {
        if (candidate.family != "navigation_submenu_maze" ||
                candidate.input_kind != "menu" || candidate.parameter.empty() ||
                candidate.parameter.rfind("navigation:", 0) == 0) continue;
        const auto proof = ProveMenuBooleanConditionSubstitution(
            graph_input, candidate.parameter);
        if (!proof.accepted) {
            // A missing permanent rewrite proof does not invalidate the
            // independently established menu route/consumer evidence. Keep
            // its original confidence, runtime status and guide provenance;
            // the absent condition plan remains a visible removal blocker.
            continue;
        }
        // This proof establishes an equivalent condition rewrite, not a new
        // password or an Animator terminal. Keep the menu detector's original
        // evidence; changing its origin to reverse would misroute it into the
        // state-only arbiter below. Plan authorization remains independent.
        for (auto rewrite : proof.rewrites) {
            rewrite["input_parameter"] = candidate.parameter;
            rewrite["input_password"] = candidate.password;
            rewrite["proof_family"] = "menu_boolean_guard_substitution_v1";
            condition_rewrites.push_back(std::move(rewrite));
        }
    }

    // Close a proven two-stage numeric lock before the generic candidate
    // arbiter runs.  The first stage writes a Boolean latch; the second stage
    // is a separately guarded numeric chain whose terminal drives an actual
    // blend/animation effect.  This pass is intentionally conservative: a
    // common gate without a unique producer, a competing terminal, or an
    // unknown terminal branch remains a reference candidate.
    if (DetectorEnabled(rules, detector_parameter_driver) &&
        SafePlanMethodAllowed(rules,
            "native_guarded_numeric_dependency_terminal")) {
        const auto mapped_path = [&](const GuardedNumericPathProof& proof)
            -> std::optional<std::tuple<std::string, std::string, std::string,
                std::string>> {
            const auto pages = menu_maps.find(proof.parameter);
            if (pages != menu_maps.end()) for (const auto& [menu_name, mapping] : pages->second) {
                std::map<int, int> raw_to_visible;
                for (const auto& [visible, entry] : mapping)
                    raw_to_visible[entry.raw_value] = visible;
                std::ostringstream password, raw;
                bool complete = true;
                for (std::size_t index = 0; index < proof.raw_values.size(); ++index) {
                    const auto found = raw_to_visible.find(proof.raw_values[index]);
                    if (found == raw_to_visible.end() || found->second < 0 ||
                        found->second > 9) { complete = false; break; }
                    password << found->second;
                    if (index) raw << ',';
                    raw << proof.raw_values[index];
                }
                if (complete)
                    return std::make_tuple(password.str(), raw.str(), menu_name,
                        std::string("menu"));
            }
            // Direct expression parameters are valid input even when the menu
            // reference is absent.  Do not present arbitrary internal floats as
            // a password: every chain value must still be a visible digit.
            if (snapshot.expression_parameters.count(proof.parameter) != 0) {
                std::ostringstream password, raw;
                for (std::size_t index = 0; index < proof.raw_values.size(); ++index) {
                    const int value = proof.raw_values[index];
                    if (value < 0 || value > 9) return std::nullopt;
                    password << value;
                    if (index) raw << ',';
                    raw << value;
                }
                return std::make_tuple(password.str(), raw.str(), std::string{},
                    std::string("osc"));
            }
            return std::nullopt;
        };
        const auto find_plan = [&](const std::string& path,
            std::size_t machine_index) -> const json::Value* {
            for (const auto& value : state_bypasses) {
                if (!value.is_object()) continue;
                const auto* p = value.find("path_id");
                const auto* m = value.find("machine_index");
                if (!p || !m || !p->is_string() || !m->is_number())
                    continue;
                if (p->string() == path &&
                    static_cast<std::size_t>(std::llround(m->number())) ==
                        machine_index)
                    return &value;
            }
            return nullptr;
        };
        const auto find_plan_method = [&](const std::string& path,
            std::size_t machine_index, int state) -> std::string {
            const auto* value = find_plan(path, machine_index);
            if (!value) return {};
            const auto* target = value->find("unlock_state");
            const auto* method = value->find("method");
            if (target && target->is_number() && method && method->is_string() &&
                static_cast<int>(std::llround(target->number())) == state)
                return method->string();
            return {};
        };
        const auto ensure_plan = [&](const Controller& controller,
            std::size_t machine_index, int state, const std::string& method,
            const std::string& family, const json::Value::Object* dependency) {
            if (controller.path_id.empty() || machine_index >= controller.machines.size() ||
                state < 0 || state >= static_cast<int>(controller.machines[machine_index].states.size()) ||
                !SafePlanMethodAllowed(rules, method)) return false;
            const auto& machine = controller.machines[machine_index];
            const auto* existing = find_plan(controller.path_id, machine_index);
            if (existing) {
                const auto* before = existing->find("before");
                const auto* target = existing->find("unlock_state");
                const auto* existing_method = existing->find("method");
                // A physical rewrite coordinate may already have a plan from
                // another detector.  Accept it only when the entire physical
                // mutation and its proof method are identical.
                return before && before->is_number() && target &&
                    target->is_number() && existing_method &&
                    existing_method->is_string() &&
                    static_cast<int>(std::llround(before->number())) ==
                        machine.default_state &&
                    static_cast<int>(std::llround(target->number())) == state &&
                    existing_method->string() == method;
            }
            json::Value::Object plan;
            plan["path_id"] = controller.path_id;
            plan["machine_index"] = static_cast<std::int64_t>(machine_index);
            plan["before"] = machine.default_state;
            plan["unlock_state"] = state;
            plan["unlock_state_name"] = machine.states[static_cast<std::size_t>(state)].name;
            plan["method"] = method;
            plan["proof_family"] = family;
            if (dependency) plan["depends_on"] = *dependency;
            state_bypasses.push_back(std::move(plan));
            return true;
        };
        const auto reviewed_producer_method = [&](const std::string& path,
            std::size_t machine_index, int state) -> std::string {
            const auto* committed = find_plan(path, machine_index);
            if (!committed) return {};
            const auto* target = committed->find("unlock_state");
            const auto* method = committed->find("method");
            if (!target || !target->is_number() || !method ||
                !method->is_string() ||
                static_cast<int>(std::llround(target->number())) != state)
                return {};
            if (method->string() ==
                "native_contact_guarded_semantic_terminal")
                return method->string();
            if (method->string() !=
                "native_guarded_numeric_dependency_terminal")
                return {};
            const auto* family = committed->find("proof_family");
            return family && family->is_string() &&
                family->string() == "guarded_numeric_gate_producer_v1"
                    ? method->string() : std::string{};
        };
        std::set<std::tuple<std::string, std::size_t, int, std::size_t, int>>
            committed_guarded_pairs;
        for (const auto& controller : snapshot.controllers) {
            if (!snapshot.active_fx_controller_ids.empty() &&
                snapshot.active_fx_controller_ids.count(controller.path_id) == 0)
                continue;
            std::vector<std::pair<std::size_t, GuardedNumericPathProof>> paths;
            for (std::size_t machine_index = 0;
                 machine_index < controller.machines.size(); ++machine_index) {
                for (auto& proof : EnumerateGuardedNumericPaths(snapshot,
                         controller, controller.machines[machine_index]))
                    paths.push_back({machine_index, std::move(proof)});
            }
            using GuardedCoordinate = std::pair<std::size_t, int>;
            std::map<GuardedCoordinate, std::set<GuardedCoordinate>>
                producer_effects;
            for (const auto& [effect_machine_index, effect_path] : paths) {
                if (!HasNumericEffectTerminal(snapshot, controller,
                        controller.machines[effect_machine_index],
                        effect_path.terminal_state) ||
                    !mapped_path(effect_path).has_value())
                    continue;
                std::set<GuardedCoordinate> producer_coordinates;
                for (const auto& candidate : candidates) {
                    if (candidate.controller_path_id != controller.path_id ||
                        candidate.machine_index == static_cast<std::size_t>(-1) ||
                        candidate.machine_index == effect_machine_index ||
                        candidate.unlock_state < 0 ||
                        candidate.machine_index >= controller.machines.size() ||
                        reviewed_producer_method(controller.path_id,
                            candidate.machine_index,
                            candidate.unlock_state).empty())
                        continue;
                    const auto& machine =
                        controller.machines[candidate.machine_index];
                    if (candidate.unlock_state < static_cast<int>(
                            machine.states.size()) &&
                        IsGateProducerTerminal(snapshot, controller, machine,
                            candidate.unlock_state,
                            effect_path.gate_parameter,
                            effect_path.gate_mode))
                        producer_coordinates.insert({candidate.machine_index,
                            candidate.unlock_state});
                }
                if (producer_coordinates.empty()) {
                    for (const auto& [machine_index, proof] : paths) {
                        if (machine_index == effect_machine_index ||
                            proof.terminal_state < 0 ||
                            !mapped_path(proof).has_value() ||
                            !IsGateProducerTerminal(snapshot, controller,
                                controller.machines[machine_index],
                                proof.terminal_state,
                                effect_path.gate_parameter,
                                effect_path.gate_mode))
                            continue;
                        producer_coordinates.insert({machine_index,
                            proof.terminal_state});
                    }
                }
                if (producer_coordinates.size() == 1)
                    producer_effects[*producer_coordinates.begin()].insert(
                        {effect_machine_index, effect_path.terminal_state});
            }
            for (const auto& [effect_machine_index, effect_path] : paths) {
                if (!HasNumericEffectTerminal(snapshot, controller,
                        controller.machines[effect_machine_index],
                        effect_path.terminal_state))
                    continue;
                // A guarded numeric path is only a lock when exactly one
                // terminal producer writes the same gate polarity.  Prefer an
                // already detected candidate because encoded press/release
                // chains may not be representable as one raw digit per edge.
                struct Producer {
                    std::size_t machine_index = static_cast<std::size_t>(-1);
                    int state = -1;
                    std::string password, raw, menu, input_kind;
                    Candidate* candidate = nullptr;
                    std::string method;
                };
                std::vector<Producer> producers;
                for (auto& candidate : candidates) {
                    if (candidate.controller_path_id != controller.path_id ||
                        candidate.machine_index == static_cast<std::size_t>(-1) ||
                        candidate.machine_index == effect_machine_index ||
                        candidate.unlock_state < 0 ||
                        candidate.machine_index >= controller.machines.size())
                        continue;
                    const auto& machine = controller.machines[candidate.machine_index];
                    if (candidate.unlock_state >= static_cast<int>(machine.states.size()) ||
                        !IsGateProducerTerminal(snapshot, controller, machine,
                            candidate.unlock_state, effect_path.gate_parameter,
                            effect_path.gate_mode))
                        continue;
                    const std::string committed_method = reviewed_producer_method(
                        controller.path_id, candidate.machine_index,
                        candidate.unlock_state);
                    if (committed_method.empty()) continue;
                    producers.push_back({candidate.machine_index, candidate.unlock_state,
                        candidate.password, candidate.raw, {}, candidate.input_kind,
                        &candidate, committed_method});
                }
                // If no existing row carries the producer coordinates, recover
                // a direct numeric path with the same structural proof.
                if (producers.empty()) {
                    for (const auto& [machine_index, proof] : paths) {
                        if (machine_index == effect_machine_index ||
                            proof.terminal_state < 0 ||
                            !IsGateProducerTerminal(snapshot, controller,
                                controller.machines[machine_index],
                                proof.terminal_state, effect_path.gate_parameter,
                                effect_path.gate_mode))
                            continue;
                        const auto mapped = mapped_path(proof);
                        if (!mapped.has_value()) continue;
                        producers.push_back({machine_index, proof.terminal_state,
                            std::get<0>(*mapped), std::get<1>(*mapped),
                            std::get<2>(*mapped), std::get<3>(*mapped), nullptr,
                            find_plan_method(controller.path_id, machine_index,
                                proof.terminal_state)});
                    }
                }
                std::sort(producers.begin(), producers.end(),
                    [](const Producer& left, const Producer& right) {
                        return std::tie(left.machine_index, left.state,
                            left.password) < std::tie(right.machine_index,
                                right.state, right.password);
                    });
                producers.erase(std::unique(producers.begin(), producers.end(),
                    [](const Producer& left, const Producer& right) {
                        return left.machine_index == right.machine_index &&
                            left.state == right.state;
                    }), producers.end());
                if (producers.size() != 1) continue;
                auto producer = producers.front();
                const auto producer_effect = producer_effects.find(
                    {producer.machine_index, producer.state});
                if (producer_effect == producer_effects.end() ||
                    producer_effect->second.size() != 1 ||
                    producer_effect->second.count({effect_machine_index,
                        effect_path.terminal_state}) == 0)
                    continue;
                auto effect_mapping = mapped_path(effect_path);
                if (!effect_mapping.has_value()) continue;
                Candidate* effect_candidate = nullptr;
                for (auto& candidate : candidates) {
                    if (candidate.controller_path_id == controller.path_id &&
                        candidate.machine_index == effect_machine_index &&
                        candidate.parameter == effect_path.parameter &&
                        candidate.password == std::get<0>(*effect_mapping)) {
                        effect_candidate = &candidate;
                        break;
                    }
                }
                if (!effect_candidate) {
                    Candidate candidate{controller.name, effect_path.parameter,
                        std::get<1>(*effect_mapping), std::get<0>(*effect_mapping),
                        std::string(u8"共同布尔门控数字链 → 唯一效果终点 | 菜单「") +
                            std::get<2>(*effect_mapping) + u8"」交叉验证",
                        u8"高", effect_path.terminal_state,
                        "native_guarded_numeric_dependency_terminal"};
                    candidate.controller_path_id = controller.path_id;
                    candidate.machine_index = effect_machine_index;
                    candidate.analysis_origin = "reverse";
                    candidate.family = "guarded_numeric_effect_terminal_v1";
                    candidate.input_kind = std::get<3>(*effect_mapping);
                    candidate.menu_mapped = candidate.input_kind == "menu";
                    candidate.guide_allowed = false;
                    candidates.push_back(std::move(candidate));
                    effect_candidate = &candidates.back();
                }
                if (!producer.candidate) {
                    Candidate candidate{controller.name, "", producer.raw,
                        producer.password,
                        u8"前置门闩生产链：唯一稳定终点写入第二锁共同门",
                        u8"高", producer.state,
                        "native_guarded_numeric_dependency_terminal"};
                    candidate.controller_path_id = controller.path_id;
                    candidate.machine_index = producer.machine_index;
                    candidate.analysis_origin = "reverse";
                    candidate.family = "guarded_numeric_gate_producer_v1";
                    candidate.input_kind = producer.input_kind;
                    candidate.menu_mapped = producer.input_kind == "menu";
                    candidate.guide_allowed = false;
                    candidates.push_back(std::move(candidate));
                    producer.candidate = &candidates.back();
                    producer.method =
                        "native_guarded_numeric_dependency_terminal";
                }
                // Adding a candidate can reallocate the vector.  Rebind both
                // pointers by immutable coordinates before mutating them.
                for (auto& candidate : candidates) {
                    if (candidate.controller_path_id == controller.path_id &&
                        candidate.machine_index == effect_machine_index &&
                        candidate.parameter == effect_path.parameter &&
                        candidate.password == std::get<0>(*effect_mapping))
                        effect_candidate = &candidate;
                    if (candidate.controller_path_id == controller.path_id &&
                        candidate.machine_index == producer.machine_index &&
                        candidate.unlock_state == producer.state &&
                        candidate.password == producer.password)
                        producer.candidate = &candidate;
                }
                if (!effect_candidate || !producer.candidate) continue;
                const std::string producer_method = producer.method.empty()
                    ? "native_guarded_numeric_dependency_terminal" :
                        producer.method;
                json::Value::Object dependency;
                dependency["path_id"] = controller.path_id;
                dependency["machine_index"] = static_cast<std::int64_t>(
                    producer.machine_index);
                dependency["unlock_state"] = producer.state;
                const auto pair_key = std::make_tuple(controller.path_id,
                    producer.machine_index, producer.state, effect_machine_index,
                    effect_path.terminal_state);
                if (committed_guarded_pairs.count(pair_key) != 0) continue;
                // The two rewrites are one logical transaction.  If the
                // second coordinate conflicts with an existing plan/method,
                // roll back any plan appended by the first ensure_plan call;
                // never leave an orphan producer bypass that can be applied
                // without its dependent effect rewrite.
                const std::size_t plan_count_before = state_bypasses.size();
                if (!ensure_plan(controller, producer.machine_index, producer.state,
                        producer_method, "guarded_numeric_gate_producer_v1", nullptr) ||
                    !ensure_plan(controller, effect_machine_index,
                        effect_path.terminal_state,
                        "native_guarded_numeric_dependency_terminal",
                        "guarded_numeric_effect_terminal_v1", &dependency)) {
                    state_bypasses.resize(plan_count_before);
                    continue;
                }
                committed_guarded_pairs.insert(pair_key);
                producer.candidate->analysis_origin = "reverse";
                producer.candidate->confidence = u8"高";
                producer.candidate->unlock_method = producer_method;
                producer.candidate->family = "guarded_numeric_gate_producer_v1";
                producer.candidate->guide_allowed = true;
                producer.candidate->runtime_status = "runtime_verified";
                effect_candidate->analysis_origin = "reverse";
                effect_candidate->confidence = u8"高";
                effect_candidate->unlock_method =
                    "native_guarded_numeric_dependency_terminal";
                effect_candidate->guide_allowed = true;
                effect_candidate->runtime_status = "runtime_verified";
                effect_candidate->unlock_state = effect_path.terminal_state;
                effect_candidate->unlock_method =
                    "native_guarded_numeric_dependency_terminal";
                effect_candidate->family = "guarded_numeric_effect_terminal_v1";
                reverse_first_used = true;
                reverse_verified_controllers.insert(controller.path_id);
                reverse_verified_parameters.insert(effect_path.parameter);
                committed_reverse_plans.emplace(controller.path_id,
                    producer.machine_index, producer.state, producer_method);
                committed_reverse_plans.emplace(controller.path_id,
                    effect_machine_index, effect_path.terminal_state,
                    "native_guarded_numeric_dependency_terminal");
            }
        }
    }
    reverse_first_used |= AppendStableGuardedPairPlans(snapshot, rules, menu_maps, candidates, state_bypasses);
    candidates.erase(std::remove_if(candidates.begin(), candidates.end(),
        [&](const Candidate& candidate) {
            return candidate.analysis_origin != "reverse" &&
                reverse_verified_parameters.count(candidate.parameter) != 0;
        }), candidates.end());
    ApplyMenuMaps(snapshot, rules, candidates, guides);

    // Perform the safe-method scrub before reverse candidates are promoted.
    // The final arbiter also verifies that every committed key still has its
    // exact emitted bypass (and, for Contact pairs, its producer half).
    const auto safe_plan_method = [&](const json::Value& bypass) {
        const auto* method = bypass.find("method");
        return method && method->is_string() &&
            SafePlanMethodAllowed(rules, method->string());
    };
    state_bypasses.erase(std::remove_if(
        state_bypasses.begin(), state_bypasses.end(),
        [&](const json::Value& bypass) {
            return !safe_plan_method(bypass);
        }), state_bypasses.end());
    menu_bypasses.erase(std::remove_if(
        menu_bypasses.begin(), menu_bypasses.end(),
        [&](const json::Value& bypass) {
            return !safe_plan_method(bypass);
        }), menu_bypasses.end());
    const auto has_exact_state_plan = [&](const ReversePlanKey& key) {
        for (const auto& value : state_bypasses) {
            if (!value.is_object()) continue;
            const auto& object = value.object();
            const auto path = object.find("path_id");
            const auto machine = object.find("machine_index");
            const auto state = object.find("unlock_state");
            const auto method = object.find("method");
            if (path == object.end() || !path->second.is_string() ||
                machine == object.end() || !machine->second.is_number() ||
                state == object.end() || !state->second.is_number() ||
                method == object.end() || !method->second.is_string())
                continue;
            if (path->second.string() == std::get<0>(key) &&
                static_cast<std::size_t>(std::llround(
                    machine->second.number())) == std::get<1>(key) &&
                static_cast<int>(std::llround(state->second.number())) ==
                    std::get<2>(key) &&
                method->second.string() == std::get<3>(key))
                return true;
        }
        return false;
    };
    // A reverse-derived state-machine password and its permanent-unlock plan
    // are two views of the same proof.  If the exact controller/machine/state
    // plan was not emitted (for example, one half of a dynamic Contact pair is
    // missing), the sequence remains useful to an operator but is not a
    // runtime-verified result.  Matching only by method or state index is not
    // sufficient because large generated controllers reuse both extensively.
    for (auto& candidate : candidates) {
        if (candidate.analysis_origin != "reverse" ||
            candidate.confidence != u8"高")
            continue;
        if (candidate.unlock_state < 0 || candidate.unlock_method.empty()) {
            candidate.confidence = u8"参考";
            candidate.note += (candidate.note.empty() ? "" : " | ") +
                std::string(u8"未证明唯一稳定成功终点，已降级待进一步闭环");
            continue;
        }
        const ReversePlanKey key = std::make_tuple(candidate.controller_path_id,
            candidate.machine_index, candidate.unlock_state,
            candidate.unlock_method);
        bool committed = committed_reverse_plans.count(key) != 0 &&
            has_exact_state_plan(key);
        const auto producer = committed_dynamic_producers.find(key);
        if (producer != committed_dynamic_producers.end())
            committed = committed && has_exact_state_plan(producer->second);
        if (committed) continue;
        candidate.confidence = u8"参考";
        candidate.note += (candidate.note.empty() ? "" : " | ") +
            std::string(u8"安全终点计划未形成，已降级待进一步闭环");
    }
    const auto reverse_plan_committed = [&](const Candidate& candidate) {
        if (candidate.analysis_origin != "reverse" ||
            candidate.confidence != u8"高" ||
            candidate.controller_path_id.empty() ||
            candidate.machine_index == static_cast<std::size_t>(-1) ||
            candidate.unlock_state < 0 || candidate.unlock_method.empty())
            return false;
        const ReversePlanKey key{candidate.controller_path_id,
            candidate.machine_index, candidate.unlock_state,
            candidate.unlock_method};
        if (committed_reverse_plans.count(key) == 0 ||
            !has_exact_state_plan(key))
            return false;
        const auto producer = committed_dynamic_producers.find(key);
        return producer == committed_dynamic_producers.end() ||
            has_exact_state_plan(producer->second);
    };
    if (avacrypt_v1_mesh_solution.accepted) {
        std::ostringstream password;
        std::ostringstream raw;
        for (std::size_t i = 0; i < avacrypt_v1_mesh_solution.keys.size(); ++i) {
            if (i) { password << " / "; raw << '/'; }
            password << avacrypt_v1_mesh_solution.keys[i] << '%';
            raw << avacrypt_v1_mesh_solution.keys[i];
        }
        std::ostringstream note;
        note << u8"AvaCrypt V1 网格训练/复核残差一致；恢复的是可正确解密的等效四轮值，不保证与作者最初四值相同（该等价类 "
             << avacrypt_v1_mesh_solution.equivalent_key_count
             << u8" 组）";
        candidates.push_back({u8"(AvaCrypt V1 网格)", "AvaCryptKey0~3",
            raw.str(), password.str(), note.str(), u8"高"});
    }
    auto confidence_rank = [](const std::string& confidence) {
        if (confidence == u8"高") return 3;
        if (confidence == u8"参考") return 2;
        return 1;
    };
    // A reference-only sequence without a proven user input mapping is not a
    // password.  This also catches named/decorated decoy machines whose state
    // graph looks convincing but whose parameter cannot be entered in VRChat.
    for (auto& candidate : candidates) {
        const bool numeric = !candidate.password.empty() &&
            std::all_of(candidate.password.begin(), candidate.password.end(),
                [](unsigned char ch) { return std::isdigit(ch); });
        const bool direct_osc_input = candidate.input_kind == "osc" &&
            candidate.analysis_origin == "reverse";
        if (!rules.high_enabled ||
                (rules.require_menu_mapping_for_numeric && numeric &&
                 !candidate.menu_mapped && !direct_osc_input) ||
                candidate.password.size() < static_cast<std::size_t>(rules.min_password_length) ||
                candidate.password.size() > static_cast<std::size_t>(rules.max_password_length))
            if (candidate.confidence == u8"高") candidate.confidence = u8"参考";
    }
    // Keep a bounded operator-visible pool before strict result filtering.
    // This is a separate, display-only channel: a complete menu-backed numeric
    // path may be useful for manual attempts even when its semantic success
    // terminal is not closed strongly enough for an automatic rewrite.
    std::vector<Candidate> manual_candidate_pool;
    const auto distributed_candidates = DetectorEnabled(rules, detector_parameter_driver)
        ? DetectDistributedIntegerKeypads(snapshot) : std::vector<Candidate>{};
    manual_candidate_pool.insert(manual_candidate_pool.end(), distributed_candidates.begin(), distributed_candidates.end());
    if (DetectorEnabled(rules, detector_parameter_driver)) {
        const auto rolling_candidates = osc_suffix_detail::Detect(snapshot, graph_input);
        manual_candidate_pool.insert(manual_candidate_pool.end(), rolling_candidates.begin(), rolling_candidates.end());
    }
    const auto manual_candidate_eligible = [&](const Candidate& candidate) {
        const bool direct_osc_input = candidate.input_kind == "osc" &&
            candidate.analysis_origin == "reverse";
        if (candidate.password.empty() ||
            (!candidate.menu_mapped && !direct_osc_input)) return false;
        const bool numeric = std::all_of(candidate.password.begin(),
            candidate.password.end(),
            [](unsigned char ch) { return std::isdigit(ch); });
        if (!numeric || candidate.password.size() < 2 ||
            candidate.password.size() > 32) return false;
        // Deterministically blocked paths are removed before this point. The
        // real visible->raw menu mapping also excludes ordinary action buses,
        // transport-only 8x8 panels and non-enterable numeric state chains.
        return true;
    };
    for (const auto& candidate : candidates) {
        if (manual_candidate_eligible(candidate))
            manual_candidate_pool.push_back(candidate);
    }
    candidates.erase(std::remove_if(candidates.begin(), candidates.end(),
        [](const Candidate& candidate) {
            return candidate.confidence != u8"高" && !candidate.menu_mapped;
        }), candidates.end());
    std::map<std::string, std::size_t> unique_positions;
    std::vector<Candidate> unique;
    for (const auto& candidate : candidates) {
        const std::string key = candidate.password + '|' + candidate.parameter;
        const auto found = unique_positions.find(key);
        if (found == unique_positions.end()) {
            unique_positions[key] = unique.size();
            unique.push_back(candidate);
        } else if (confidence_rank(candidate.confidence) >
                   confidence_rank(unique[found->second].confidence)) {
            unique[found->second] = candidate;
        }
    }
    std::vector<Candidate> reference_sequences;
    for (const auto& candidate : unique)
        if (candidate.confidence != u8"高") reference_sequences.push_back(candidate);
    unique.erase(std::remove_if(unique.begin(), unique.end(),
        [](const auto& candidate) { return candidate.confidence != u8"高"; }),
        unique.end());
    for (const auto& candidate : unique)
        if (manual_candidate_eligible(candidate))
            manual_candidate_pool.push_back(candidate);
    std::map<std::string, std::size_t> pool_positions;
    std::vector<Candidate> bounded_reverse_pool;
    const auto pool_score = [&](const Candidate& item) {
        int score = item.confidence == u8"高" ? 1000 : 0;
        score += item.menu_mapped ? 160 : 0;
        score += item.input_kind == "osc" ? 120 : 0;
        score += item.analysis_origin == "reverse" ? 120 : 0;
        score += item.unlock_state >= 0 ? 80 : 0;
        score += !item.unlock_method.empty() ? 80 : 0;
        score += item.generic_chain ? 10 : 30;
        if (item.note.find(u8"保存型") != std::string::npos) score += 30;
        if (item.note.find(u8"成功终点") != std::string::npos) score += 25;
        if (item.note.find(u8"菜单按钮名称与状态机值交叉验证") !=
            std::string::npos) score += 20;
        // Compatibility is a hard release invariant: a new generic semantic
        // hypothesis may fill unused candidate slots, but it must never push
        // a previously visible specialized result out of the bounded list.
        if (item.family.rfind("semantic_effect_slice_v2_", 0) == 0 &&
            item.confidence != u8"高")
            score -= 300;
        if (item.family.rfind("local_smt_integer_", 0) == 0)
            score -= 600; // fill unused slots; never displace existing hypotheses
        if (item.family == "distributed_integer_dispatch_v1") score -= 900;
        if (item.family == "osc_rolling_suffix_comparator_v1") score -= 1500;
        return score;
    };
    for (const auto& candidate : manual_candidate_pool) {
        // The same numeric sequence only needs to be tried once. Keep its best
        // provenance instead of repeating generated controller copies.
        const std::string key = candidate.password;
        const auto found = pool_positions.find(key);
        if (found == pool_positions.end()) {
            pool_positions[key] = bounded_reverse_pool.size();
            bounded_reverse_pool.push_back(candidate);
        } else if (pool_score(candidate) >
                   pool_score(bounded_reverse_pool[found->second])) {
            bounded_reverse_pool[found->second] = candidate;
        }
    }
    std::sort(bounded_reverse_pool.begin(), bounded_reverse_pool.end(),
        [&](const Candidate& left, const Candidate& right) {
            if (pool_score(left) != pool_score(right))
                return pool_score(left) > pool_score(right);
            if (left.password != right.password) return left.password < right.password;
            return left.parameter < right.parameter;
        });
    // Normally show three choices. If fourth/fifth have nearly identical
    // evidence to the third, retain them rather than hiding an arbitrary tie.
    std::size_t visible_candidate_limit =
        std::min<std::size_t>(3, bounded_reverse_pool.size());
    if (bounded_reverse_pool.size() > 3) {
        const int third_score = pool_score(bounded_reverse_pool[2]);
        while (visible_candidate_limit < bounded_reverse_pool.size() &&
               visible_candidate_limit < 5 &&
               pool_score(bounded_reverse_pool[visible_candidate_limit]) >=
                   third_score - 20)
            ++visible_candidate_limit;
    }
    if (bounded_reverse_pool.size() > visible_candidate_limit)
        bounded_reverse_pool.erase(
            bounded_reverse_pool.begin() + visible_candidate_limit,
            bounded_reverse_pool.end());
    const bool high = !unique.empty();
    const auto safe_method = [&](const json::Value& bypass) {
        const auto* method = bypass.find("method");
        return method && method->is_string() &&
            SafePlanMethodAllowed(rules, method->string());
    };
    state_bypasses.erase(std::remove_if(state_bypasses.begin(), state_bypasses.end(),
        [&](const json::Value& bypass) { return !safe_method(bypass); }),
        state_bypasses.end());
    menu_bypasses.erase(std::remove_if(menu_bypasses.begin(), menu_bypasses.end(),
        [&](const json::Value& bypass) { return !safe_method(bypass); }),
        menu_bypasses.end());
    condition_rewrites.erase(std::remove_if(condition_rewrites.begin(), condition_rewrites.end(),
        [&](const json::Value& rewrite) { return !safe_method(rewrite); }),
        condition_rewrites.end());
    guides.erase(std::remove_if(guides.begin(), guides.end(),
        [&](const Guide& guide) {
            const auto matches = [&](const Candidate& candidate) {
                    return candidate.password == guide.password &&
                        candidate.parameter == guide.parameter &&
                        candidate.guide_allowed;
                };
            // Menu highlighting is authoritative behavior. A display-only
            // candidate must never lock the wheel to an unverified route.
            return std::none_of(unique.begin(), unique.end(), matches);
        }), guides.end());
    const auto candidate_id = [&](const Candidate& candidate) {
        std::ostringstream identity;
        identity << "VPF-CANDIDATE-2|" << snapshot.source_sha256 << '|'
                 << rules.policy_hash << '|' << candidate.controller_path_id
                 << '|' << candidate.machine_index << '|'
                 << candidate.unlock_state << '|' << candidate.input_kind
                 << '|' << candidate.parameter.size() << ':'
                 << candidate.parameter << '|' << candidate.raw << '|'
                 << candidate.family;
        return Sha256Hex(identity.str(), true);
    };
    json::Value::Array results;
    for(const auto&c:unique) { auto item=CandidateJson(c); item["candidate_id"]=candidate_id(c); results.push_back(std::move(item)); }
    json::Value::Array reference_json;
    for(const auto&c:reference_sequences) { auto item=CandidateJson(c); item["candidate_id"]=candidate_id(c); reference_json.push_back(std::move(item)); }
    json::Value::Array candidate_json;
    for (const auto& c : bounded_reverse_pool) {
        auto item = CandidateJson(c);
        item["candidate_id"] = candidate_id(c);
        item["display_only"] = true;
        item["automatic_unlock_eligible"] = false;
        // A confirmed input is a request for more evidence, never a bypass.
        // Read all layers of its active FX controller so effect consumers and
        // competing writers are not lost by the fast extractor's filters.
        for (const auto& controller : snapshot.controllers) {
            if (controller.path_id != c.controller_path_id ||
                snapshot.active_fx_controller_ids.count(controller.path_id) == 0 ||
                c.machine_index == static_cast<std::size_t>(-1) ||
                c.machine_index >= controller.machines.size()) continue;
            json::Value::Array owners;
            std::int64_t count = 0;
            for (const auto& active : snapshot.controllers) {
                if (snapshot.active_fx_controller_ids.count(active.path_id) == 0)
                    continue;
                json::Value::Object owner;
                owner["path_id"] = active.path_id;
                json::Value::Array indices;
                for (std::size_t i = 0; i < active.machines.size(); ++i) {
                    indices.push_back(static_cast<std::int64_t>(i));
                    ++count;
                }
                owner["machine_indices"] = std::move(indices);
                owners.push_back(std::move(owner));
            }
            if (count > 0 && count <= 512 && owners.size() <= 64) {
                json::Value::Object request;
                request["schema"] = 1;
                request["source_sha256"] = snapshot.source_sha256;
                request["candidate_id"] = candidate_id(c);
                request["reason"] = "confirmed_candidate_effect_closure";
                // A legacy candidate may identify the input chain but not yet
                // prove a unique terminal.  The request is deliberately
                // read-only evidence collection; native/C# strict-plan
                // arbitration must re-prove the terminal before any write.
                request["candidate_terminal_state"] = c.unlock_state;
                request["candidate_terminal_state_proven"] =
                    c.unlock_state >= 0;
                request["requires_strict_reproof"] = true;
                request["machine_count"] = count;
                request["controllers"] = std::move(owners);
                item["confirmation_deep_scan_request"] = std::move(request);
            }
            break;
        }
        candidate_json.push_back(std::move(item));
    }
    json::Value::Array guide_json;for(const auto&g:guides)guide_json.push_back(GuideJson(g));json::Value::Array features;
    auto feature=[&](std::string name,std::string evidence,std::string note){json::Value::Object f;f["name"]=std::move(name);f["evidence"]=std::move(evidence);f["note"]=std::move(note);features.push_back(f);};
    // APS GhostBody is a serialized body visibility controller.  It is not a
    // password candidate and it is not an OSC transport proof: recognize it
    // as a bounded feature only when the exact BodyModel path, a unique
    // m_IsActive writer, complementary 0/1 writes, Hide/Show state names and
    // the APS_HideBody gate all agree in the same active machine.
    struct BodyHiddenTargetEvidence {
        std::string controller_path_id, target_path, target_id;
        std::size_t machine_index = static_cast<std::size_t>(-1);
        std::set<double> values;
        bool hide_state = false, show_state = false;
        bool hide_parameter = false, fix_parameter = false;
        std::set<std::size_t> writers;
    };
    std::map<std::pair<std::string, std::string>, BodyHiddenTargetEvidence>
        body_hidden_targets;
    for (const auto& controller : snapshot.controllers) {
        if (!snapshot.active_fx_controller_ids.empty() &&
            !snapshot.active_fx_controller_ids.count(controller.path_id))
            continue;
        for (std::size_t machine_index = 0;
             machine_index < controller.machines.size(); ++machine_index) {
            const auto& machine = controller.machines[machine_index];
            BodyHiddenTargetEvidence evidence;
            evidence.controller_path_id = controller.path_id;
            evidence.machine_index = machine_index;
            bool has_body_write = false;
            auto inspect_transition = [&](const Transition& transition) {
                for (const auto& condition : transition.conditions) {
                    evidence.hide_parameter = evidence.hide_parameter ||
                        condition.parameter == "APS_HideBody";
                    evidence.fix_parameter = evidence.fix_parameter ||
                        condition.parameter == "APS_FixBody";
                }
            };
            for (std::size_t state_index = 0; state_index < machine.states.size();
                 ++state_index) {
                const auto& state = machine.states[state_index];
                evidence.hide_state = evidence.hide_state ||
                    ContainsI(state.name, "hide");
                evidence.show_state = evidence.show_state ||
                    ContainsI(state.name, "show");
                for (const auto& transition : state.transitions)
                    inspect_transition(transition);
                for (const auto& write : state.animation_writes) {
                    if (write.name != "m_IsActive" ||
                        write.target_type != 1 ||
                        write.binding_status != "unique_serialized_target" ||
                        !ContainsI(write.target_path,
                            "aps_ghost_hips_proxy$aps_body$bodymodel$"))
                        continue;
                    if (!std::isfinite(write.value) ||
                        (write.value != 0.0 && write.value != 1.0))
                        continue;
                    has_body_write = true;
                    evidence.target_path = write.target_path;
                    evidence.target_id = write.target_id;
                    evidence.values.insert(write.value);
                    evidence.writers.insert(machine_index);
                }
            }
            for (const auto& transition : machine.any_transitions)
                inspect_transition(transition);
            if (!has_body_write || evidence.target_path.empty()) continue;
            auto& slot = body_hidden_targets[{controller.path_id,
                evidence.target_path}];
            if (slot.target_path.empty()) slot = evidence;
            slot.values.insert(evidence.values.begin(), evidence.values.end());
            slot.writers.insert(evidence.writers.begin(), evidence.writers.end());
            slot.hide_state = slot.hide_state || evidence.hide_state;
            slot.show_state = slot.show_state || evidence.show_state;
            slot.hide_parameter = slot.hide_parameter || evidence.hide_parameter;
            slot.fix_parameter = slot.fix_parameter || evidence.fix_parameter;
        }
    }
    std::size_t body_hidden_verified_count = 0;
    for (const auto& [key, evidence] : body_hidden_targets) {
        if (evidence.values.size() != 2 || !evidence.values.count(0.0) ||
            !evidence.values.count(1.0) || !evidence.hide_state ||
            !evidence.show_state || !evidence.hide_parameter ||
            !evidence.fix_parameter || evidence.writers.size() != 1)
            continue;
        ++body_hidden_verified_count;
    }
    if (body_hidden_verified_count) {
        feature(u8"APS BodyModel 主体隐藏特征",
            std::to_string(body_hidden_verified_count) +
                u8" 个主体目标具备唯一 m_IsActive 写入者、Hide/Show 两态和 APS_HideBody/APS_FixBody 门控",
            u8"已识别主体隐藏链；这是静态特征标注，不冒充 OSC 传输或密码终点。永久写回需在隔离副本中使用经过复解析的 AnimationClip 写回流程。"
        );
    }
    auto manual_boolean_routes = FindManualBooleanEffectRoutes(snapshot);
    const auto selector_proxy_routes = selector_proxy_detail::Find(snapshot, graph_input);
    manual_boolean_routes.insert(manual_boolean_routes.end(),
        selector_proxy_routes.begin(), selector_proxy_routes.end());
    for (const auto& route : manual_boolean_routes)
        feature(u8"组合开关解锁候选", String(route, "instructions"),
            String(route, "note"));
    const auto input_binding_diagnostics = DiagnoseUnboundMenuGrids(snapshot);
    // External Contact receiver parameters are an input surface that may be
    // driven by OSC at runtime.  Keep this evidence separate from password
    // candidates: a receiver condition alone does not prove a lock terminal
    // or authorize a permanent rewrite.
    std::size_t contact_receivers = 0;
    std::size_t contact_senders = 0;
    std::set<std::string> contact_condition_parameters;
    for (const auto& contact : snapshot.raw_contact_components) {
        if (contact.kind == "receiver") ++contact_receivers;
        if (contact.kind == "sender") ++contact_senders;
    }
    for (const auto& controller : snapshot.controllers) {
        if (!snapshot.active_fx_controller_ids.empty() &&
            !snapshot.active_fx_controller_ids.count(controller.path_id))
            continue;
        for (const auto& machine : controller.machines) {
            for (const auto& transition : machine.any_transitions)
                for (const auto& condition : transition.conditions)
                    if (snapshot.contact_input_parameters.count(condition.parameter))
                        contact_condition_parameters.insert(condition.parameter);
            for (const auto& state : machine.states)
                for (const auto& transition : state.transitions)
                    for (const auto& condition : transition.conditions)
                        if (snapshot.contact_input_parameters.count(condition.parameter))
                            contact_condition_parameters.insert(condition.parameter);
        }
    }
    if (random_boolean_restore_count)
        feature(u8"可永久解锁的随机布尔校验锁",std::to_string(random_boolean_restore_count),
            u8"已验证稳定通过状态及互补恢复动画，无需数字密码；点击移除密码锁生成新副本。");
    if (compound_restriction_restore_count)
        feature(u8"可永久解锁的复合输入限制锁",
            std::to_string(compound_restriction_restore_count),
            u8"已验证多输入门控、唯一保存型通过锁存器和独立限制效果；无需数字密码，点击移除密码锁生成新副本。");
    if (float_range_gate_restore_count)
        feature(u8"可永久解锁的浮点区间门锁",
            std::to_string(float_range_gate_restore_count),
            u8"已验证窄区间判定、互补门闩和单向恢复效果闭环；无需数字密码，点击移除密码锁生成新副本。");
    if (!input_binding_diagnostics.empty())
        feature(u8"8×8 菜单输入链未接通",
            u8"64 个菜单 Bool 输入未在已提取的 Animator 参数表中找到对应声明",
            u8"已识别输入结构，但尚未闭合本地密码校验链；同步复制不等于解锁。不会凭菜单外形生成密码或安全移除计划。");
    if (!contact_condition_parameters.empty()) {
        std::ostringstream evidence;
        evidence << contact_receivers << u8" 个 Contact Receiver、" << contact_senders
                 << u8" 个 Sender；" << contact_condition_parameters.size()
                 << u8" 个 Receiver 参数进入活动 FX 条件";
        feature(u8"Contact 参数输入",
            evidence.str(),
            u8"已核对 Contact 接收参数在活动 FX 中的引用；这是输入组件证据，不能单独认定为 OSC 锁。");
    }
    const int boolean_numeric_password_menus =
        CountBooleanNumericPasswordMenus(snapshot);
    const int boolean_password_grid_groups =
        CountBooleanPasswordGridGroups(snapshot);
    if (!high && state_bypasses.empty() && boolean_password_grid_groups >= 2)
        feature(u8"VRCFury 8×8 并行布尔密码锁",
            std::to_string(boolean_password_grid_groups) +
                u8" 组子菜单，每组 1-8 共 " +
                std::to_string(boolean_password_grid_groups * 8) +
                u8" 个 Bool Toggle；入口标签位于父菜单按钮",
            u8"已识别菜单结构和 VRCFury 参数压缩/同步形态；当前图谱未找到可验证的成功消费终点，不能编造密码，也不会生成安全移除计划。"
        );
    if (!high && state_bypasses.empty() && boolean_numeric_password_menus > 0 && manual_boolean_routes.empty())
        feature(u8"布尔数字按钮密码锁",
            std::to_string(boolean_numeric_password_menus) + u8" 个密码菜单使用 0-9 独立 Toggle 按钮",
            u8"这是组合式/生成式密码锁，不是单一路径数字链；当前未找到可验证成功终点，不能编造密码，也不会生成安全移除计划。");
    if (dead_guard_candidates > 0)
        feature(u8"死分支数字链已拦截",
            std::to_string(dead_guard_candidates) + u8" 条候选被确定性门控阻断",
            u8"这些数字序列无法从模型默认运行路径进入，不会再作为密码展示。");
    if (fixed_contact_candidates > 0)
        feature(u8"固定接触门阻断数字密码",
            std::to_string(fixed_contact_candidates) +
                u8" 条数字链被零偏移 Contact Sender/Receiver 强制阻断",
            u8"数字序列只存在于控制器中，运行时不会成功；仅在成功终点语义唯一时生成永久解锁计划。"
        );
    if (dynamic_contact_candidates > 0)
        feature(u8"\u52a8\u6001 Contact \u95e8\u63a7\u6570\u5b57\u5bc6\u7801\u9501",
            std::to_string(dynamic_contact_candidates) +
                u8" \u7ec4\u52a8\u753b\u542f\u505c Contact \u8109\u51b2\u4e0e\u5bc6\u7801\u6210\u529f\u7ec8\u70b9\u5df2\u95ed\u73af",
            u8"\u5b89\u5168\u79fb\u9664\u8ba1\u5212\u540c\u65f6\u9501\u5b9a Contact \u7a33\u6001\u7ec8\u70b9\u548c\u5bc6\u7801\u89e3\u9501\u7ec8\u70b9\uff0c\u4e0d\u4f9d\u8d56\u53c2\u6570\u540d\u6216\u6a21\u578b\u540d\u3002");
    if (named_unlock_terminals > 0)
        feature(u8"命名解锁终点已验证",
            std::to_string(named_unlock_terminals) +
                u8" 个密码状态机含唯一 Unlock 写入终点",
            u8"即使菜单输入路径缺失，也可通过已验证的解锁参数写入终点生成永久解锁计划。"
        );
    if (!bounded_reverse_pool.empty())
        feature(u8"逆向候选密码",
            std::to_string(bounded_reverse_pool.size()) + u8" 条候选（通常 3 条，同分时最多 5 条）",
            u8"建议按顺序依次尝试；实测成功后可在移除流程中勾选该候选，进入严格复核并生成永久解锁计划；未经复核不会自动写入。");
    if(snapshot.md5_parameters>=20)feature(u8"d4rkpl4y3r 混淆",std::to_string(snapshot.md5_parameters)+u8" 个参数名为 32 位 MD5 哈希",u8"参数名不可读，但原生核心仍分析结构和值。");
    if(snapshot.controller_fail>0)feature(u8"TypeTree 加固",std::to_string(snapshot.controller_fail)+u8" 个控制器无法规范化",u8"可转 AssetRipper 导出后交给同一原生核心分析。");
    if(snapshot.unicode_obfuscated>=10)feature(u8"Unicode 参数名混淆",std::to_string(snapshot.unicode_obfuscated)+u8" 个参数名含不可见字符",u8"参数名不可读，但状态机结构仍可分析。");
    if (avacrypt_v1_menu || !snapshot.avacrypt_v1_parameters.empty() ||
        snapshot.avacrypt_v1_materials > 0) {
        std::ostringstream evidence;
        evidence << snapshot.avacrypt_v1_materials
                 << u8" 个材质含 _Key0~_Key3";
        if (avacrypt_v1_menu)
            evidence << u8"；菜单「" << avacrypt_v1_menu->menu
                     << u8"」含 4 个 Radial 钥匙参数";
        else if (!snapshot.avacrypt_v1_parameters.empty())
            evidence << u8"；发现 " << snapshot.avacrypt_v1_parameters.size()
                     << u8" 个 AvaCryptKey 参数";
        if (!snapshot.avacrypt_v1_mesh_probes.empty())
            evidence << u8"；" << snapshot.avacrypt_v1_mesh_probes.size()
                     << u8" 个网格通过 UV7/UV8 双样本复核";
        feature(u8"AvaCrypt V1 百分比轮盘网格锁", evidence.str(),
            avacrypt_v1_mesh_solution.accepted
                ? u8"已从加密网格恢复可正确解密的等效四轮百分比；结果不冒充作者原始四值。"
                : snapshot.avacrypt_leaked
                ? u8"发现可能的密钥残留，需由专用网格恢复路径复核。"
                : u8"需依次输入 4 个百分比；网格证据不足或存在歧义时不会编造密钥。");
    }
    if (!snapshot.avacrypt_v2_parameters.empty() ||
        snapshot.avacrypt_v2_mesh_offset_signatures > 0) {
        std::ostringstream evidence;
        evidence << snapshot.avacrypt_v2_materials
                 << u8" 个材质含 _BitKey";
        if (!snapshot.avacrypt_v2_parameters.empty())
            evidence << u8"；发现 " << snapshot.avacrypt_v2_parameters.size()
                     << u8" 个 BitKey 参数";
        if (!snapshot.avacrypt_v2_bit_indices.empty())
            evidence << u8"；密钥宽度 " << snapshot.avacrypt_v2_bit_indices.size()
                     << u8" 位";
        if (snapshot.avacrypt_v2_mesh_offset_signatures > 0)
            evidence << u8"；" << snapshot.avacrypt_v2_mesh_offset_signatures
                     << u8" 个网格通过负 UV6/UV7 扰动签名复核";
        feature(u8"AvaCrypt V2 布尔位网格加密", evidence.str(),
            u8"V2 使用多个布尔 BitKey，不是 V1 的四轮百分比密码。");
    }
    bool shell_direct_keys_contiguous =
        snapshot.shell_protector_direct_key_indices.size() >= 4;
    if (shell_direct_keys_contiguous) {
        int expected = 0;
        for (int index : snapshot.shell_protector_direct_key_indices) {
            if (index != expected++) {
                shell_direct_keys_contiguous = false;
                break;
            }
        }
    }
    const bool external_shell_texture_lock =
        snapshot.shell_protector_multiplexed || shell_direct_keys_contiguous;
    const bool ajisai_osc_lock = ajisai_osc_detail::Detect(snapshot, graph_input);
    if (ajisai_osc_lock) {
        feature(u8"AjisaiFlow 本地 OSC 网格/着色器锁",
            u8"8 个本地浮点输入经 BlendTree 汇总分数，区间比较驱动广播锁存器；独立复核网格恢复和四通道材质解码曲线。",
            u8"这是外部 OSC 密钥锁，不是轮盘数字密码。已识别保护结构；贴图密钥、心跳及永久恢复效果尚未完整验证，当前不支持安全永久移除。");
    }
    if (const auto streamed = osc_streamed_redirect_detail::Detect(snapshot)) {
        std::ostringstream evidence;
        evidence << u8"数字菜单组 " << streamed->menu_groups
                 << u8" 组、按钮 " << streamed->digit_controls
                 << u8" 个；流式曲线状态 " << streamed->streamed_states
                 << u8" 个，其中带条件跳转 " << streamed->redirect_states
                 << u8" 个；checker 机器 " << streamed->checker_machines
                 << u8" 个";
        feature(u8"流式曲线重定向数字锁家族",
            evidence.str(),
            u8"识别到 cycle offset 驱动的 StreamedClip 输出与后续校验机交接。该特征只用于家族标注；当前不输出密码、不生成永久解锁计划，待独立样本闭环验证后再考虑增加受控分析。"
        );
    }
    if (external_shell_texture_lock) {
        std::ostringstream evidence;
        if (snapshot.shell_protector_multiplexed)
            evidence << u8"发现 encrypt_lock、encrypt_switch0~3 与 pkey 多路复用参数";
        if (shell_direct_keys_contiguous) {
            if (snapshot.shell_protector_multiplexed) evidence << u8"；";
            evidence << u8"发现从 pkey0 开始连续的 "
                     << snapshot.shell_protector_direct_key_indices.size()
                     << u8" 个直接密钥参数";
        }
        feature(u8"ShellProtector OSC 纹理加密锁", evidence.str(),
            u8"该锁通过 OSC 输入经 SHA-256 派生的用户密钥，再由着色器解密 XXTEA/ChaCha8 纹理；不是轮盘数字状态机密码锁，不会编造数字密码或自动写入普通解锁状态。");
    }
    const bool detached_avatar_controls =
        snapshot.avatar_descriptor_count > 0 &&
        snapshot.custom_expressions_count > 0 &&
        snapshot.missing_expression_parameters_count > 0 &&
        snapshot.missing_expression_menu_count > 0 &&
        snapshot.custom_fx_count > 0 &&
        snapshot.missing_fx_controller_count > 0 &&
        snapshot.active_fx_controller_ids.empty() &&
        snapshot.active_root_menu_ids.empty() &&
        snapshot.expression_parameters.empty() &&
        snapshot.menus.empty();
    const bool detached_runtime_control_chain =
        detached_avatar_controls && snapshot.animation_hash_count > 0;
    if (detached_runtime_control_chain) {
        std::ostringstream evidence;
        evidence << snapshot.animation_hash_count
                 << u8" \u6761\u6784\u5efa\u65f6\u72b6\u6001\u54c8\u5e0c\u6b8b\u7559\uff08"
                 << snapshot.animation_hash_unique_count
                 << u8" \u4e2a\u552f\u4e00\u72b6\u6001\u540d\uff09\uff1bMenu\u3001Expression Parameters \u548c FX Controller \u5747\u672a\u5185\u5d4c";
        feature(u8"\u8fd0\u884c\u63a7\u5236\u94fe\u7f3a\u5931", evidence.str(),
            u8"\u72b6\u6001\u540d\u548c\u54c8\u5e0c\u4e0d\u5305\u542b Transition \u6761\u4ef6\u3001\u9ed8\u8ba4\u72b6\u6001\u6216 AnimationClip \u66f2\u7ebf\uff1b\u53ef\u7528\u4e8e\u786e\u8ba4\u539f\u5de5\u7a0b\u66fe\u6709\u63a7\u5236\u5668\uff0c\u4f46\u4e0d\u80fd\u636e\u6b64\u4f2a\u9020\u5bc6\u7801\u6216\u5b89\u5168\u5199\u5165\u6c38\u4e45\u89e3\u9501\u3002");
    }
    const bool external_osc_mesh_lock =
        detached_avatar_controls &&
        snapshot.avacrypt_v2_materials >= 4 &&
        snapshot.avacrypt_v2_bit_indices.size() >= 16 &&
        snapshot.avacrypt_v2_mesh_offset_signatures > 0;
    if (external_osc_mesh_lock) {
        std::ostringstream evidence;
        evidence << snapshot.avacrypt_v2_materials << u8" 个网格材质共享 "
                 << snapshot.avacrypt_v2_bit_indices.size()
                 << u8" 位 BitKey；" << snapshot.avacrypt_v2_mesh_offset_signatures
                 << u8" 个网格存在负 UV6/UV7 扰动；AvatarDescriptor 的菜单、参数表和 FX 控制器均未内嵌";
        feature(u8"OSC 外部输入型网格锁", evidence.str(),
            u8"当前模型不是轮盘数字密码锁。请使用“移除密码锁”处理；工具会先验证能否永久固化，证据不足时不会写坏模型。");
    }
    if(menu_recovery_locks>0)feature(u8"数字密码锁结构（菜单待恢复）",std::to_string(menu_recovery_locks)+u8" 个按下/释放状态链具有强密码语义和安全退出终点",u8"已生成安全移除计划；缺少菜单映射时不会编造可见密码或点击引导。");
    json::Value mesh_solution_json = nullptr;
    if (!snapshot.avacrypt_v1_mesh_probes.empty()) {
        json::Value::Object solution;
        solution["accepted"] = avacrypt_v1_mesh_solution.accepted;
        solution["reason"] = avacrypt_v1_mesh_solution.reason;
        solution["equivalent"] = true;
        solution["probe_count"] = static_cast<std::int64_t>(
            avacrypt_v1_mesh_solution.probe_count);
        solution["train_score"] = avacrypt_v1_mesh_solution.train_score;
        solution["validation_score"] =
            avacrypt_v1_mesh_solution.validation_score;
        solution["train_margin"] = avacrypt_v1_mesh_solution.train_margin;
        solution["validation_margin"] =
            avacrypt_v1_mesh_solution.validation_margin;
        if (avacrypt_v1_mesh_solution.accepted) {
            json::Value::Array keys;
            json::Value::Array coefficients;
            for (int key : avacrypt_v1_mesh_solution.keys) keys.push_back(key);
            for (double coefficient : avacrypt_v1_mesh_solution.coefficients)
                coefficients.push_back(coefficient);
            solution["keys"] = keys;
            solution["coefficients"] = coefficients;
            solution["combination_a"] = avacrypt_v1_mesh_solution.combination_a;
            solution["combination_b"] = avacrypt_v1_mesh_solution.combination_b;
            solution["equivalent_key_count"] = static_cast<std::int64_t>(
                avacrypt_v1_mesh_solution.equivalent_key_count);
        }
        mesh_solution_json = solution;
    }
    const auto record = DetectRecordKeypad(snapshot, menu_maps);
    // Keep method-specific proof keys until promotion and Contact-pair
    // arbitration are finished. The writer receives each physical edit once;
    // all detector evidence remains inside the subsequently sealed payload.
    state_bypasses = CanonicalizeStatePlans(state_bypasses);
    ValidateProtectedFinalDecision(rules, unique, state_bypasses, menu_bypasses,
        condition_rewrites);
    json::Value::Object report;
    report["schema"] = 1;
    report["engine"] = "VrcNativeCore/cpp";
    report["analysis_mode"] = "reverse_first";
    report["semantic_pipeline"] =
        "layered_effect_slice_exact_state_witness_replay_v2";
    report["causal_trace"] = BuildCausalTrace(snapshot);
    report["candidate_policy"] = "relaxed_display_strict_rewrite_v1";
    report["automatic_unlock_policy"] = "strict_verified_plan_only";
    report["analysis_depth"] = snapshot.analysis_depth;
    report["deep_scan_machine_count"] = snapshot.deep_scan_machine_count;
    // The generic semantic slice only sees machines whose currently loaded
    // evidence already exposes an effect terminal.  A fast remote graph omits
    // animation curves, so a structurally complete float-range producer can
    // otherwise fail to request the separate effect machine that the strict
    // detector needs.  Merge the bounded, structure-only selector here; it
    // requests evidence only and never authorizes a rewrite by itself.
    auto deep_scan_machines = semantic_ir.deep_scan_machines;
    // A targeted graph may predate menu-terminal evidence selection. Do not
    // resend its generic slice when asking only for missing menu consumers.
    if (snapshot.analysis_depth != "fast") deep_scan_machines.clear();
    if (snapshot.analysis_depth == "fast") {
        for (const auto& [owner, indices] : selector_proxy_detail::SelectDeep(snapshot, graph_input))
            deep_scan_machines[owner].insert(indices.begin(), indices.end());
        for (const auto& [owner, indices] : ajisai_osc_detail::SelectDeep(snapshot, graph_input))
            deep_scan_machines[owner].insert(indices.begin(), indices.end());
    }
    // A menu-only proof has no Animator terminal coordinates. It can still
    // identify the exact scalar written by the terminal menu control. Request
    // the active consumers of that scalar before concluding that no permanent
    // plan exists; menu reachability alone never authorizes any rewrite.
    std::map<std::string, std::set<std::size_t>> menu_evidence_machines;
    std::set<std::string> menu_terminal_parameters;
    if ((snapshot.analysis_depth == "fast" || snapshot.analysis_depth == "targeted_deep") &&
        DetectorEnabled(rules, detector_menu_tree) &&
        !snapshot.active_fx_controller_ids.empty()) {
        for (const auto& candidate : candidates) {
            if (candidate.analysis_origin == "menu_tree" && candidate.menu_mapped &&
                candidate.input_kind == "menu" && candidate.unlock_state < 0) {
                // Preserve the existing targeted-deep termination rule for
                // other families. This bounded supplement is for an actual
                // one-action terminal whose public navigation identity did
                // not previously identify its scalar consumers.
                if (snapshot.analysis_depth == "targeted_deep" &&
                    candidate.menu_terminal_parameter.empty()) continue;
                const auto& parameter = candidate.menu_terminal_parameter.empty()
                    ? candidate.parameter : candidate.menu_terminal_parameter;
                if (!parameter.empty() && parameter.rfind("navigation:", 0) != 0)
                    menu_terminal_parameters.insert(parameter);
            }
        }
        const auto reads_terminal = [&](const std::vector<Transition>& transitions) {
            for (const auto& transition : transitions)
                for (const auto& condition : transition.conditions)
                    if (menu_terminal_parameters.count(condition.parameter)) return true;
            return false;
        };
        std::size_t count = 0;
        for (const auto& controller : snapshot.controllers) {
            if (!snapshot.active_fx_controller_ids.count(controller.path_id)) continue;
            std::set<std::size_t> visited_deep_machines;
            if (snapshot.analysis_depth == "targeted_deep") {
                const json::Value* owner = nullptr;
                for (const auto& raw : Array(graph_input, "controllers")) {
                    if (String(raw, "path_id") != controller.path_id) continue;
                    if (owner) throw std::runtime_error("ambiguous deep coverage owner");
                    owner = &raw;
                }
                const auto* coverage = owner ? owner->find("deep_scan_machine_indices") : nullptr;
                if (coverage) {
                    if (!coverage->is_array() || coverage->array().size() > controller.machines.size())
                        throw std::runtime_error("invalid deep machine coverage");
                    double previous = -1;
                    for (const auto& value : coverage->array()) {
                        const double index = value.is_number() ? value.number() : -1;
                        if (!value.is_number() || !std::isfinite(index) || index < 0 ||
                            std::floor(index) != index || index >= controller.machines.size() ||
                            index <= previous)
                            throw std::runtime_error("invalid deep machine coverage");
                        previous = index;
                        visited_deep_machines.insert(static_cast<std::size_t>(index));
                    }
                }
            }
            for (std::size_t mi = 0; mi < controller.machines.size(); ++mi) {
                const auto& machine = controller.machines[mi];
                bool consumes = reads_terminal(machine.any_transitions);
                for (const auto& state : machine.states) {
                    consumes = consumes || reads_terminal(state.transitions);
                    for (const auto& read : state.blend_parameter_reads)
                        consumes = consumes || menu_terminal_parameters.count(read.parameter) != 0;
                }
                if (consumes && !visited_deep_machines.count(mi)) {
                    menu_evidence_machines[controller.path_id].insert(mi);
                    ++count;
                }
            }
        }
        if (count > 512 || menu_evidence_machines.size() > 64)
            menu_evidence_machines.clear();
        for (const auto& [path, indices] : menu_evidence_machines)
            deep_scan_machines[path].insert(indices.begin(), indices.end());
    }
    if (snapshot.analysis_depth == "fast" &&
        DetectorEnabled(rules, detector_parameter_driver) &&
        SafePlanMethodAllowed(rules, "native_float_range_gate_terminal")) {
        for (const auto& controller : snapshot.controllers) {
            if (!snapshot.active_fx_controller_ids.empty() &&
                snapshot.active_fx_controller_ids.count(
                    controller.path_id) == 0)
                continue;
            const auto requested =
                float_range_gate_detail::SelectFloatRangeGateDeepMachines(
                    snapshot, controller);
            auto& merged = deep_scan_machines[controller.path_id];
            merged.insert(requested.begin(), requested.end());
            if (merged.empty()) deep_scan_machines.erase(controller.path_id);
        }
    }
    if (snapshot.analysis_depth == "fast" &&
        DetectorEnabled(rules, detector_parameter_driver) &&
        SafePlanMethodAllowed(rules, "native_random_boolean_restore_terminal")) {
        for (const auto& controller : snapshot.controllers) {
            if (!float_range_gate_detail::ActiveController(snapshot, controller))
                continue;
            const auto requested = SelectRandomBooleanRestoreDeepMachines(controller);
            if (requested.empty()) continue;
            auto& merged = deep_scan_machines[controller.path_id];
            merged.insert(requested.begin(), requested.end());
        }
    }
    const bool semantic_deep_scan_needed = state_bypasses.empty() &&
        !deep_scan_machines.empty();
    const bool deep_scan_needed =
        (snapshot.analysis_depth == "fast" &&
            (semantic_deep_scan_needed || !menu_evidence_machines.empty() ||
             snapshot.raw_contact_effects_pending)) ||
        (snapshot.analysis_depth == "targeted_deep" && !menu_evidence_machines.empty());
    if (deep_scan_needed) {
        json::Value::Object request;
        request["schema"] = 1;
        request["source_sha256"] = snapshot.source_sha256;
        request["reason"] = snapshot.analysis_depth == "targeted_deep"
            ? "menu_terminal_effect_semantics_missing" : "effect_semantics_missing";
        json::Value::Array controllers;
        std::int64_t requested_count = 0;
        for (const auto& [path_id, machine_indices] :
             deep_scan_machines) {
            json::Value::Object controller;
            controller["path_id"] = path_id;
            json::Value::Array indices;
            for (std::size_t index : machine_indices) {
                indices.push_back(static_cast<std::int64_t>(index));
                ++requested_count;
            }
            controller["machine_indices"] = std::move(indices);
            controllers.push_back(std::move(controller));
        }
        if (snapshot.analysis_depth == "fast" && snapshot.raw_contact_effects_pending) {
            std::map<std::string, std::set<std::size_t>> merged;
            for (const auto& item : controllers) {
                const std::string path_id = String(item, "path_id");
                for (const auto& index : Array(item, "machine_indices"))
                    if (index.is_number()) merged[path_id].insert(
                        static_cast<std::size_t>(index.number()));
            }
            for (const auto& controller : snapshot.controllers) {
                if (!snapshot.active_fx_controller_ids.empty() &&
                        snapshot.active_fx_controller_ids.count(
                            controller.path_id) == 0) continue;
                for (std::size_t index = 0;
                        index < controller.machines.size(); ++index)
                    merged[controller.path_id].insert(index);
            }
            controllers.clear();
            requested_count = 0;
            for (const auto& [path_id, indices_set] : merged) {
                if (path_id.empty()) continue;
                json::Value::Object controller;
                controller["path_id"] = path_id;
                json::Value::Array indices;
                for (const auto index : indices_set) {
                    indices.push_back(static_cast<std::int64_t>(index));
                    ++requested_count;
                }
                controller["machine_indices"] = std::move(indices);
                controllers.push_back(std::move(controller));
            }
            request["reason"] = "contact_animation_semantics_missing";
        }
        request["controllers"] = std::move(controllers);
        request["machine_count"] = requested_count;
        report["deep_scan_request"] = std::move(request);
        report["deep_analysis_request"] = report["deep_scan_request"];
        report["deep_scan_reason"] = "检测到真实输入链，但快速图谱缺少恢复效果；正在定向读取相关控制器。";
    }
    {
        json::Value::Object semantic;
        semantic["machine_count"] =
            static_cast<std::int64_t>(semantic_ir.machine_count);
        semantic["expanded_configurations"] = static_cast<std::int64_t>(semantic_ir.expanded_configurations);
        semantic["sliced_states"] = static_cast<std::int64_t>(semantic_ir.sliced_states);
        semantic["pruned_states"] = static_cast<std::int64_t>(semantic_ir.pruned_states);
        semantic["dependency_machines"] = static_cast<std::int64_t>(semantic_ir.dependency_machines);
        semantic["budget_exhausted_count"] = semantic_ir.budget_exhausted_count;
        semantic["unsupported_semantics_count"] = semantic_ir.unsupported_semantics_count;
        semantic["independent_replay_count"] = semantic_ir.independent_replay_count;
        semantic["smt_attempt_count"] = semantic_ir.smt_attempt_count;
        semantic["smt_candidate_count"] = semantic_ir.smt_candidate_count;
        semantic["smt_unknown_count"] = semantic_ir.smt_unknown_count;
        semantic["smt_unsupported_count"] = semantic_ir.smt_unsupported_count;
        semantic["smt_skipped_verified"] = semantic_ir.smt_skipped_verified;
        semantic["smt_skipped_no_arithmetic"] = semantic_ir.smt_skipped_no_arithmetic;
        json::Value::Object rejections;
        for (const auto& [reason, count] : semantic_ir.smt_rejection_reasons)
            rejections[reason] = count;
        semantic["smt_rejection_reasons"] = rejections;
#if defined(VRC_ENABLE_LOCAL_SMT)
        semantic["smt_backend"] = "z3_integer_development";
#else
        semantic["smt_backend"] = "disabled";
#endif
        semantic["search_complete"] = semantic_ir.budget_exhausted_count == 0 &&
            semantic_ir.unsupported_semantics_count == 0;
        semantic["effect_terminal_count"] =
            static_cast<std::int64_t>(semantic_ir.effect_terminal_count);
        semantic["sliced_machine_count"] =
            static_cast<std::int64_t>(semantic_ir.sliced_machine_count);
        semantic["replayed_path_count"] =
            static_cast<std::int64_t>(semantic_ir.replayed_path_count);
        semantic["candidate_count"] =
            static_cast<std::int64_t>(semantic_ir.candidates.size());
        semantic["strict_candidate_count"] =
            static_cast<std::int64_t>(std::count_if(
                semantic_ir.candidates.begin(), semantic_ir.candidates.end(),
                [](const auto& item) { return item.strict_terminal; }));
        report["semantic_ir"] = semantic;
    }
    report["reverse_first_used"] = reverse_first_used;
    report["unsupported_condition_thresholds"] = snapshot.nonfinite_condition_count;
    report["analysis_incomplete"] = deep_scan_needed ||
        snapshot.nonfinite_condition_count != 0 || semantic_ir.budget_exhausted_count != 0 ||
        semantic_ir.unsupported_semantics_count != 0 || !input_binding_diagnostics.empty();
    report["analysis_complete"] = !Boolean(report, "analysis_incomplete");
    report["input_binding_diagnostics"] = input_binding_diagnostics;
    report["external_input_summary"] = json::Value::Object{
        {"contact_receivers", static_cast<std::int64_t>(contact_receivers)},
        {"contact_senders", static_cast<std::int64_t>(contact_senders)},
        {"receiver_parameters_in_active_conditions",
            static_cast<std::int64_t>(contact_condition_parameters.size())},
        {"osc_transport_proven", false},
        {"unlock_terminal_proven", false}
    };
    report["legacy_fallback_used"] = legacy_fallback_used;
    std::set<std::pair<std::string, std::size_t>>
        final_reverse_verified_machines;
    for (const auto& candidate : unique)
        if (reverse_plan_committed(candidate))
            final_reverse_verified_machines.insert({
                candidate.controller_path_id, candidate.machine_index});
    report["reverse_verified_machine_count"] =
        static_cast<std::int64_t>(final_reverse_verified_machines.size());
    report["legacy_fallback_machine_count"] =
        static_cast<std::int64_t>(legacy_fallback_machine_count);
    report["legacy_fallback_scope"] =
        "specialized_compatibility_only";
    const bool final_reverse_high = std::any_of(
        unique.begin(), unique.end(), [&](const Candidate& candidate) {
            return reverse_plan_committed(candidate);
        });
    report["reverse_status"] = final_reverse_high
        ? "runtime_verified_password"
        : (high ? "legacy_verified_password" :
            "unsupported_or_no_closed_path");
    report["policy_hash"] = rules.policy_hash;
    report["policy_version"] = rules.policy_version;
    report["source_sha256"] = snapshot.source_sha256;
    report["results"] = results;
    report["password_candidates"] = candidate_json;
    report["password_candidate_count"] =
        static_cast<std::int64_t>(bounded_reverse_pool.size());
    report["reference_sequences"] = reference_json;
    report["guides"] = guide_json;
    report["features"] = features;
    report["body_hidden_target"] = json::Value::Object{
        {"detected", body_hidden_verified_count != 0},
        {"count", static_cast<std::int64_t>(body_hidden_verified_count)},
        {"safe_permanent_rewrite_supported", false}
    };
    report["manual_unlock_candidates"] = manual_boolean_routes;
    report["state_bypasses"] = state_bypasses;
    report["menu_bypasses"] = menu_bypasses;
    report["condition_rewrites"] = condition_rewrites;
    report["menu_recovery_needed"] = menu_recovery_locks > 0;
    report["controller_ok"] = snapshot.controller_ok;
    report["controller_fail"] = snapshot.controller_fail;
    report["avacrypt_v1_mesh_solution"] = mesh_solution_json;
    {
        json::Value::Object control_chain;
        control_chain["status"] = detached_runtime_control_chain
            ? "detached" : "available_or_not_custom";
        control_chain["animation_hash_count"] =
            static_cast<std::int64_t>(snapshot.animation_hash_count);
        control_chain["animation_hash_unique_count"] =
            static_cast<std::int64_t>(snapshot.animation_hash_unique_count);
        control_chain["safe_permanent_rewrite_supported"] =
            !state_bypasses.empty();
        control_chain["reason"] = detached_runtime_control_chain
            ? "fx_controller_and_clips_missing" : "";
        report["runtime_control_chain"] = control_chain;
    }
    if (ajisai_osc_lock) {
        json::Value::Object external;
        external["detected"] = true;
        external["kind"] = "ajisaiflow_local_osc_mesh_shader_lock";
        external["confidence"] = u8"高";
        external["safe_removal_supported"] = false;
        external["reason"] = "unsupported_no_safe_plan";
        report["external_input_lock"] = external;
    } else if (external_shell_texture_lock) {
        json::Value::Object external;
        external["detected"] = true;
        external["kind"] = "shellprotector_osc_texture_lock";
        external["confidence"] = u8"高";
        external["safe_removal_supported"] = false;
        external["reason"] = "external_password_required_for_shader_decryption";
        report["external_input_lock"] = external;
    } else if (external_osc_mesh_lock) {
        json::Value::Object external;
        external["detected"] = true;
        external["kind"] = "vrchat_osc_external_mesh_lock";
        external["confidence"] = u8"高";
        external["safe_removal_supported"] = false;
        external["reason"] = "external_key_not_embedded";
        report["external_input_lock"] = external;
    } else {
        report["external_input_lock"] = nullptr;
    }
    if (record && !high) report["record_keypad"] = *record;
    else report["record_keypad"] = nullptr;
    return report;
}

std::string RenderAnalysisProtocol(const json::Value& report) {
    int manual_index = 0;
    std::ostringstream out;int index=0;for(const auto&g:Array(report,"guides")){out<<"GUIDE|"<<SafeProtocol(String(g,"password"))<<'|'<<SafeProtocol(String(g,"menu"))<<'|';const auto&keys=Array(g,"keys");for(std::size_t i=0;i<keys.size();++i){if(i)out<<'>';if(keys[i].is_string())out<<SafeProtocol(keys[i].string());}out<<'|';const auto&values=Array(g,"values");for(std::size_t i=0;i<values.size();++i){if(i)out<<'>';out<<static_cast<int>(std::llround(values[i].number()));}out<<'|'<<SafeProtocol(String(g,"parameter"))<<'|';const auto&parameters=Array(g,"parameters");for(std::size_t i=0;i<parameters.size();++i){if(i)out<<'>';if(parameters[i].is_string())out<<SafeProtocol(parameters[i].string());}out<<'\n';}
    for(const auto&f:Array(report,"features"))out<<"FEATURE|"<<SafeProtocol(String(f,"name"))<<'|'<<SafeProtocol(String(f,"evidence"))<<'|'<<SafeProtocol(String(f,"note"))<<'\n';
    const auto* external=Field(report,"external_input_lock");if(external&&external->is_object()&&Boolean(*external,"detected"))out<<"OSCLOCK|"<<SafeProtocol(String(*external,"confidence"))<<'|'<<(Boolean(*external,"safe_removal_supported")?1:0)<<'|'<<SafeProtocol(String(*external,"reason"))<<'\n';
    const auto* chain=Field(report,"runtime_control_chain");if(chain&&chain->is_object()&&String(*chain,"status")=="detached")out<<"CONTROLCHAIN|detached|"<<Integer(*chain,"animation_hash_count")<<'|'<<Integer(*chain,"animation_hash_unique_count")<<"|fx_controller_and_clips_missing\n";
    const auto* record=Field(report,"record_keypad");if(record&&record->is_string())out<<"LOCK|"<<u8"检测到【键盘记录式加密锁】：数字键盘每位接受全部数字，明文不在逐位状态链中。"<<'\n';
    for(const auto&b:Array(report,"state_bypasses"))out<<"BYPASS|"<<SafeProtocol(String(b,"method"))<<'|'<<Integer(b,"machine_index")<<'|'<<Integer(b,"unlock_state")<<'|'<<SafeProtocol(String(b,"unlock_state_name"))<<'\n';
    for (const auto& manual : Array(report, "manual_unlock_candidates")) {
        const auto instructions = String(manual, "instructions");
        const auto note = String(manual, "note");
        if (!instructions.empty() && !note.empty())
            out << "MANUAL|" << ++manual_index << '|' << SafeProtocol(instructions)
                << '|' << SafeProtocol(note) << '\n';
    }
    if (Boolean(report, "analysis_incomplete"))
        out << "INCOMPLETE|" << u8"部分分支达到搜索上限或包含尚未支持的运行时语义，不能判定为无锁" << '\n';
    const auto* visible_candidates = Field(report, "password_candidates");
    const auto& password_rows = (visible_candidates && visible_candidates->is_array() &&
        !visible_candidates->array().empty()) ? visible_candidates->array() : Array(report, "results");
    for(const auto&r:password_rows)out<<"PWD|"<<++index<<'|'<<SafeProtocol(String(r,"password"))<<'|'<<SafeProtocol(String(r,"parameter"))<<'|'<<SafeProtocol(String(r,"raw"))<<'|'<<SafeProtocol(String(r,"note"))<<'|'<<SafeProtocol(String(r,"confidence"))<<'\n';
    const int fail=Integer(report,"controller_fail"),ok=Integer(report,"controller_ok");if(fail>0||ok==0)out<<"PARSEFAIL|"<<(fail?fail:999)<<'\n';if(index==0 && manual_index==0)out<<"NONE|"<<u8"未找到可还原的数字密码链"<<'\n';return out.str();
}

} // namespace vrc
