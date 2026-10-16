// Display-only, source-independent rolling-buffer comparison witnesses.
// This deliberately cannot emit a writer plan or claim runtime acceptance.
namespace osc_suffix_detail {

bool PlainSelectors(const json::Value& machine) {
    const auto& selectors = Array(machine, "selector_states");
    if (selectors.empty()) return true;
    if (selectors.size() != 2 || !Boolean(selectors[0], "is_entry") ||
        Boolean(selectors[1], "is_entry")) return false;
    for (std::size_t i = 0; i < selectors.size(); ++i) {
        const auto& edges = Array(selectors[i], "transitions");
        if (edges.size() != 1 || !Array(edges[0], "conditions").empty() ||
            Integer(edges[0], "raw_condition_count", -1) != 0 ||
            Boolean(edges[0], "has_exit_time") ||
            Number(edges[0], "duration", -1) != 0) return false;
        if (i == 0 && (edges[0].find("selector_destination") ||
            Integer(edges[0], "destination", -1) != Integer(machine, "default_state", -2))) return false;
        if (i == 1 && Integer(edges[0], "selector_destination", -1) != 0) return false;
    }
    return true;
}

bool RawEdgesValid(const json::Value& machine) {
    if (!PlainSelectors(machine)) return false;
    for (const auto& state : Array(machine, "states")) {
        if (!Array(state, "runtime_behaviours").empty()) return false;
        // An explicitly present manual/object activation layer can override a
        // serialized constant clip.  It must be proved empty before this
        // display-only witness is emitted.
        if (!Array(state, "manual_activation_writes").empty() ||
            !Array(state, "animation_object_writes").empty()) return false;
        for (const auto& write : Array(state, "parameter_writes")) {
            if (Integer(write, "type", -1) != 3) continue;
            const auto* metadata = write.find("operation_metadata");
            if (!metadata || !metadata->is_object()) return false;
            for (const auto& [key, value] : metadata->object()) {
                if (key == "convert_range" || key == "local_only" || key == "prevent_repeats") {
                    if (!value.is_bool()) return false;
                    if ((key == "convert_range" || key == "prevent_repeats") && value.boolean()) return false;
                } else if (key == "chance" || key == "dest_max" || key == "dest_min" ||
                           key == "source_max" || key == "source_min" ||
                           key == "value_max" || key == "value_min") {
                    if (!value.is_number() || !std::isfinite(value.number())) return false;
                } else return false;
            }
            const auto* convert = metadata->find("convert_range");
            if (!convert || !convert->is_bool() || convert->boolean()) return false;
        }
        for (const auto& edge : Array(state, "transitions")) {
            if (edge.find("selector_destination") ||
                Integer(edge, "raw_condition_count", -1) !=
                    static_cast<int>(Array(edge, "conditions").size())) return false;
            for (const auto& condition : Array(edge, "conditions")) {
                const auto* threshold = condition.find("threshold");
                if (!threshold || !threshold->is_number() ||
                    !std::isfinite(threshold->number()) ||
                    condition.find("threshold_encoding")) return false;
            }
        }
    }
    return true;
}

bool RawControllerEvidenceValid(const json::Value& controller) {
    const auto* diagnostics = controller.find("behaviour_diagnostics");
    const auto* reads = controller.find("parameter_read_evidence");
    if (!diagnostics || !diagnostics->is_object() || !reads || !reads->is_object()) return false;
    // The extractor exposes behaviour completeness as mapping_complete plus
    // an explicit error_count.  Do not treat a missing field as false/known;
    // require the complete schema and zero unresolved mappings.  Parameter
    // read evidence has its own independent completeness flags.
    const auto* mapping_complete = diagnostics->find("mapping_complete");
    const auto* error_count = diagnostics->find("error_count");
    if (!mapping_complete || !mapping_complete->is_bool() ||
        !mapping_complete->boolean() || !error_count ||
        !error_count->is_number() || error_count->number() != 0) return false;
    return Boolean(*reads, "state_fields_complete") &&
        Boolean(*reads, "driver_mapping_complete");
}

bool ExactShieldPair(const State& before, const State& after) {
    if (before.animation_writes.size() != 1 || after.animation_writes.size() != 1)
        return false;
    const auto& a = before.animation_writes.front();
    const auto& b = after.animation_writes.front();
    return a.name == "m_IsActive" && b.name == a.name && a.value == 1 && b.value == 0 &&
        a.binding_status == "unique_serialized_target" && b.binding_status == a.binding_status &&
        a.target_type == 1 && b.target_type == 1 && !a.target_id.empty() &&
        a.target_id == b.target_id && a.path_hash == b.path_hash;
}

struct Match { std::string input; std::vector<int> sequence; };

bool EffectWritesParameter(const State& state, const std::string& parameter) {
    for (const auto& w : state.animation_writes) if (w.name == parameter) return true;
    for (const auto& w : state.manual_activation_writes) if (w.name == parameter) return true;
    return false;
}

bool OtherActiveEffectWriter(const Snapshot& snapshot, const Controller& controller,
    const std::string& parameter) {
    for (const auto& other : snapshot.controllers) {
        if (other.path_id == controller.path_id ||
            !snapshot.active_fx_controller_ids.count(other.path_id)) continue;
        for (const auto& m : other.machines) for (const auto& s : m.states)
            if (EffectWritesParameter(s, parameter)) return true;
    }
    return false;
}

std::optional<Match> Producer(const Snapshot& snapshot, const Controller& controller,
    const json::Value& raw_controller, const std::map<std::string, int>& expected) {
    std::vector<Match> matches;
    const auto& raw_machines = Array(raw_controller, "machines");
    if (raw_machines.size() != controller.machines.size() || !RawControllerEvidenceValid(raw_controller)) return std::nullopt;
    for (std::size_t mi = 0; mi < controller.machines.size(); ++mi) {
        const auto& machine = controller.machines[mi];
        if (!machine.any_transitions.empty() || !RawEdgesValid(raw_machines[mi])) continue;
        for (std::size_t si = 0; si < machine.states.size(); ++si) {
            const auto& state = machine.states[si];
            if (state.writes.size() < expected.size() || state.writes.size() > 17 ||
                !state.animation_writes.empty() || !state.blend_parameter_reads.empty()) continue;
            std::map<std::string, std::string> copies;
            std::set<std::string> already_written;
            bool valid = true;
            for (const auto& w : state.writes) {
                const auto conversion = w.operation_flags.find("convert_range");
                if (w.type != 3 || w.name.empty() || w.source.empty() ||
                    conversion == w.operation_flags.end() || conversion->second ||
                    w.name == w.source || already_written.count(w.source) ||
                    !copies.emplace(w.name, w.source).second) { valid = false; break; }
                already_written.insert(w.name);
            }
            if (!valid) continue;
            bool default_ok = false;
            const auto default_state = static_cast<int>(Integer(raw_machines[mi], "default_state", -1));
            if (default_state >= 0 && default_state < static_cast<int>(machine.states.size()) &&
                default_state != static_cast<int>(si)) {
                std::set<int> reached{default_state}; std::deque<int> pending{default_state};
                while (!pending.empty()) {
                    const int current = pending.front(); pending.pop_front();
                    if (current == static_cast<int>(si)) { default_ok = true; break; }
                    for (const auto& t : machine.states[static_cast<std::size_t>(current)].transitions)
                        if (!t.has_exit_time && t.duration == 0 && t.destination >= 0 &&
                            t.destination < static_cast<int>(machine.states.size()) && reached.insert(t.destination).second)
                            pending.push_back(t.destination);
                }
            }
            if (!default_ok) continue;
            bool copy_state_has_exit = false;
            for (const auto& t : state.transitions)
                if (!t.has_exit_time && t.duration == 0 && t.destination >= 0 &&
                    t.destination != static_cast<int>(si)) copy_state_has_exit = true;
            if (!copy_state_has_exit) continue;
            for (const auto& [newest, input] : copies) {
                if (copies.count(input) || !snapshot.expression_parameters.count(input) ||
                    HasActiveOtherControllerWriter(snapshot, controller, input) ||
                    OtherActiveEffectWriter(snapshot, controller, input)) continue;
                const auto pd = controller.parameter_defaults.find(input);
                if (pd == controller.parameter_defaults.end() || pd->second.type != "int" ||
                    pd->second.value != 0) continue;
                const auto expr = snapshot.expression_parameter_defaults.find(input);
                if (expr == snapshot.expression_parameter_defaults.end() || expr->second.type != "int" ||
                    expr->second.value != 0) continue;
                bool writers_ok = true;
                for (const auto& [name, unused] : copies) {
                    const auto slot_default = controller.parameter_defaults.find(name);
                    if (slot_default == controller.parameter_defaults.end() ||
                        slot_default->second.type != "int" || slot_default->second.value != 0) { writers_ok = false; break; }
                    if (HasActiveOtherControllerWriter(snapshot, controller, name)) { writers_ok = false; break; }
                    if (OtherActiveEffectWriter(snapshot, controller, name)) { writers_ok = false; break; }
                    const auto expr_slot = snapshot.expression_parameter_defaults.find(name);
                    if (expr_slot != snapshot.expression_parameter_defaults.end() &&
                        (expr_slot->second.type != "int" || expr_slot->second.value != 0)) { writers_ok = false; break; }
                }
                for (std::size_t other_machine = 0; other_machine < controller.machines.size() && writers_ok; ++other_machine)
                    for (std::size_t other_state = 0; other_state < controller.machines[other_machine].states.size(); ++other_state) {
                        if (other_machine == mi && other_state == si) continue;
                        for (const auto& w : controller.machines[other_machine].states[other_state].writes)
                            if (w.name == input || copies.count(w.name)) { writers_ok = false; break; }
                        const auto& other = controller.machines[other_machine].states[other_state];
                        if (EffectWritesParameter(other, input)) writers_ok = false;
                        for (const auto& [name, unused] : copies)
                            if (EffectWritesParameter(other, name)) writers_ok = false;
                    }
                if (!writers_ok) continue;
                bool has_input_guard = false;
                for (const auto& owner : machine.states) for (const auto& edge : owner.transitions) {
                    if (edge.destination != static_cast<int>(si) || edge.has_exit_time ||
                        edge.duration != 0 || edge.conditions.size() != 2) continue;
                    bool guarded = true;
                    for (int digit = 0; digit <= 9; ++digit) {
                        bool enabled = true;
                        for (const auto& condition : edge.conditions) {
                            const auto result = ConditionMatches(condition, {{input, static_cast<double>(digit)}});
                            if (!result.has_value()) { guarded = false; break; }
                            enabled &= *result;
                        }
                        if (enabled != (digit >= 1 && digit <= 7)) guarded = false;
                    }
                    has_input_guard |= guarded;
                }
                if (!has_input_guard) continue;
                std::vector<std::string> slots{newest};
                std::set<std::string> seen{newest};
                bool ambiguous = false;
                while (slots.size() < copies.size()) {
                    std::vector<std::string> next;
                    for (const auto& [dst, src] : copies) if (src == slots.back()) next.push_back(dst);
                    if (next.empty()) break;
                    if (next.size() != 1 || !seen.insert(next.front()).second) { ambiguous = true; break; }
                    slots.push_back(next.front());
                }
                if (ambiguous || slots.size() < expected.size()) continue;
                std::vector<int> sequence;
                for (std::size_t i = 0; i < expected.size(); ++i) {
                    const auto e = expected.find(slots[i]);
                    if (e == expected.end() || e->second < 1 || e->second > 7) { sequence.clear(); break; }
                    sequence.push_back(e->second);
                }
                if (sequence.size() != expected.size()) continue;
                std::reverse(sequence.begin(), sequence.end());
                if (!osc_suffix_trace_detail::Verify(snapshot, controller, machine,
                    si, input, expected, sequence)) continue;
                matches.push_back({input, std::move(sequence)});
            }
        }
    }
    if (matches.size() != 1) return std::nullopt;
    return matches.front();
}

std::vector<Candidate> Detect(const Snapshot& snapshot, const json::Value& graph) {
    std::vector<Candidate> output;
    for (const auto& controller : snapshot.controllers) {
        if (!snapshot.active_fx_controller_ids.count(controller.path_id)) continue;
        const json::Value* raw_controller = nullptr;
        for (const auto& raw : Array(graph, "controllers"))
            if (String(raw, "path_id") == controller.path_id) raw_controller = &raw;
        if (!raw_controller) continue;
        if (!RawControllerEvidenceValid(*raw_controller)) continue;
        const auto& raw_machines = Array(*raw_controller, "machines");
        if (raw_machines.size() != controller.machines.size()) continue;
        std::set<std::string> emitted;
        for (std::size_t mi = 0; mi < controller.machines.size(); ++mi) {
            const auto& machine = controller.machines[mi];
            if (machine.states.size() < 4 || machine.states.size() > 32 ||
                !machine.any_transitions.empty() || !machine.default_weight_known ||
                machine.default_weight <= 0 || !RawEdgesValid(raw_machines[mi])) continue;
            for (std::size_t ti = 0; ti < machine.states.size(); ++ti) {
                const auto& terminal = machine.states[ti];
                if (!terminal.transitions.empty() || terminal.writes.empty() ||
                    static_cast<int>(ti) == Integer(raw_machines[mi], "default_state", -1)) continue;
                bool simple_terminal = true;
                for (const auto& w : terminal.writes)
                    if (w.type != 0 || !w.source.empty()) simple_terminal = false;
                if (!simple_terminal) continue;
                for (std::size_t before_index = 0; before_index < machine.states.size(); ++before_index)
                for (const auto& edge : machine.states[before_index].transitions) {
                    if (edge.destination != static_cast<int>(ti) || edge.has_exit_time || edge.duration != 0 ||
                        edge.conditions.size() < 4 || edge.conditions.size() > 12 ||
                        !ExactShieldPair(machine.states[before_index], terminal)) continue;
                    std::map<std::string, int> expected;
                    bool valid = true;
                    for (const auto& condition : edge.conditions) {
                        int digit = 0;
                        if (condition.mode != 6 || !SplitIntegral(condition.threshold, digit) ||
                            digit < 1 || digit > 7 || condition.parameter.empty() ||
                            !expected.emplace(condition.parameter, digit).second) valid = false;
                    }
                    if (!valid) continue;
                    int latches = 0;
                    for (const auto& w : terminal.writes) {
                        const auto* initial = EffectiveRuntimeDefault(snapshot, controller, w.name);
                        if (w.value == 1 && initial && initial->type == "bool" && initial->value == 0 &&
                            std::any_of(machine.states[before_index].writes.begin(), machine.states[before_index].writes.end(), [&](const auto& p) {
                                return p.name == w.name && p.type == 0 && p.value == 0;
                            })) ++latches;
                    }
                    if (latches != 1) continue;
                    bool before_reachable = false;
                    const int machine_default = Integer(raw_machines[mi], "default_state", -1);
                    if (machine_default >= 0 && machine_default < static_cast<int>(machine.states.size())) {
                        std::set<int> reached{machine_default}; std::deque<int> pending{machine_default};
                        while (!pending.empty()) {
                            const int current = pending.front(); pending.pop_front();
                            if (current == static_cast<int>(before_index)) { before_reachable = true; break; }
                            for (const auto& candidate_edge : machine.states[static_cast<std::size_t>(current)].transitions)
                                // Comparator startup may contain a timed clip
                                // handoff. This is only structural reachability,
                                // not a runtime timing proof or writer authority.
                                if (std::isfinite(candidate_edge.duration) && candidate_edge.duration >= 0 &&
                                    candidate_edge.destination >= 0 && candidate_edge.destination < static_cast<int>(machine.states.size()) &&
                                    reached.insert(candidate_edge.destination).second) pending.push_back(candidate_edge.destination);
                        }
                    }
                    if (!before_reachable) continue;
                    // This narrow family currently proves one comparison
                    // edge only. Conditional priority alternatives are not
                    // silently assumed disjoint.
                    if (machine.states[before_index].transitions.size() != 1) continue;
                    bool competing_unconditional = false;
                    for (const auto& competing : machine.states[before_index].transitions)
                        if (&competing != &edge && competing.conditions.empty() && !competing.has_exit_time && competing.duration == 0)
                            competing_unconditional = true;
                    if (competing_unconditional) continue;
                    const auto producer = Producer(snapshot, controller, *raw_controller, expected);
                    if (!producer) continue;
                    std::string password;
                    for (int digit : producer->sequence) password += std::to_string(digit);
                    if (!emitted.insert(producer->input + "|" + password).second) continue;
                    Candidate candidate(controller.name, producer->input, password, password,
                        u8"OSC 滚动缓存参考序列：已沿复制顺序反推并对齐多位比较与解锁终态；请使用原 OSC 输入方式，每位输入后回零再发送下一位，完成后等待比较动画结束。未进行游戏运行验证，不提供自动永久移除。", u8"参考");
                    candidate.family = "osc_rolling_suffix_comparator_v1";
                    candidate.analysis_origin = "reverse";
                    candidate.input_kind = "osc";
                    candidate.runtime_status = "runtime_possible";
                    candidate.guide_allowed = false;
                    candidate.controller_path_id = controller.path_id;
                    candidate.machine_index = mi;
                    output.push_back(std::move(candidate));
                    if (output.size() >= 3) return output;
                }
            }
        }
    }
    return output;
}
} // namespace osc_suffix_detail
