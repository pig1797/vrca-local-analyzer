// Structural proof for a narrow floating-point interval gate.
//
// The extractor only selects likely effect machines.  This native detector is
// the final arbiter: it proves the three-state producer, the binary latch
// polarity, the reverse/out-of-range edges and a one-way effect consumer.  It
// deliberately does not use model, author, state, parameter or PathID names.

struct FloatRangeGateRestoreEvidence {
    std::size_t producer_machine = static_cast<std::size_t>(-1);
    int locked_state = -1;
    int success_state = -1;
    std::size_t effect_machine = static_cast<std::size_t>(-1);
    int effect_locked_state = -1;
    int effect_success_state = -1;
    std::string float_parameter;
    std::string latch_parameter;
    std::string gate_parameter;
    double lower = 0.0;
    double upper = 0.0;
    int success_latch_mode = 0;
    int locked_gate_value = 0;
    int success_gate_value = 1;
    std::size_t restored_effects = 0;
};

namespace float_range_gate_detail {

using EffectKey = std::tuple<std::string, int, std::uint32_t>;

std::uint32_t OrderedFloatBits(const double value, bool& ok) {
    ok = false;
    if (!std::isfinite(value) ||
        value > static_cast<double>(std::numeric_limits<float>::max()) ||
        value < -static_cast<double>(std::numeric_limits<float>::max()))
        return 0;
    const float narrowed = static_cast<float>(value);
    if (!std::isfinite(narrowed)) return 0;
    std::uint32_t bits = 0;
    static_assert(sizeof(bits) == sizeof(narrowed), "float must be binary32");
    std::memcpy(&bits, &narrowed, sizeof(bits));
    // IEEE-754 total-order key for finite binary32 values. Keep negative and
    // positive ranges disjoint: subtracting the signless magnitude from
    // 0x80000000 alone collides (-1 and +4 used to share 0x40800000).
    // Unity comparisons regard both signed zeros as the same threshold.
    if ((bits & 0x7fffffffu) == 0) bits = 0;
    bits = (bits & 0x80000000u) ? ~bits : (bits ^ 0x80000000u);
    ok = true;
    return bits;
}

bool SameFloat32(const double left, const double right) {
    bool left_ok = false, right_ok = false;
    const auto a = OrderedFloatBits(left, left_ok);
    const auto b = OrderedFloatBits(right, right_ok);
    return left_ok && right_ok && a == b;
}

bool NarrowInterval(const double lower, const double upper) {
    if (!std::isfinite(lower) || !std::isfinite(upper) || upper <= lower)
        return false;
    const double width = upper - lower;
    const double scale = (std::max)(1.0, (std::max)(std::abs(lower),
        std::abs(upper)));
    if (width > 1e-3 || width / scale > 1e-5) return false;
    bool lower_ok = false, upper_ok = false;
    const auto low_bits = OrderedFloatBits(lower, lower_ok);
    const auto high_bits = OrderedFloatBits(upper, upper_ok);
    if (!lower_ok || !upper_ok || high_bits <= low_bits) return false;
    // A normal feature slider may have a small decimal window, but a lock
    // interval is encoded in adjacent/near-adjacent binary32 values.  Keep a
    // generous bound for compiler/JSON round trips while rejecting ordinary
    // numeric ranges.
    return static_cast<std::uint64_t>(high_bits - low_bits) <= 256u;
}

bool BinaryValue(const double value, int& output) {
    if (!std::isfinite(value) ||
        (std::abs(value) > 1e-6 && std::abs(value - 1.0) > 1e-6))
        return false;
    output = std::abs(value - 1.0) <= 1e-6 ? 1 : 0;
    return true;
}

bool IsBoolDefault(const Controller& controller, const std::string& name) {
    const auto found = controller.parameter_defaults.find(name);
    return found != controller.parameter_defaults.end() &&
        found->second.type == "bool";
}

bool IsFloatDefault(const Controller& controller, const std::string& name) {
    const auto found = controller.parameter_defaults.find(name);
    return found != controller.parameter_defaults.end() &&
        found->second.type == "float";
}

bool IsActivationWrite(const AnimationWrite& write) {
    // Identify the property independently from its value.  Filtering a
    // malformed/non-binary value here would hide it from the proof and from
    // competing-writer checks.
    if (write.target_type == 1 && write.attribute_hash == 2086281974u)
        return write.name == "m_IsActive";
    if ((write.target_type == 23 || write.target_type == 137) &&
        write.attribute_hash == 3305885265u)
        return write.name == "m_Enabled";
    return false;
}

std::optional<EffectKey> EffectIdentity(const AnimationWrite& write) {
    if (!IsActivationWrite(write)) return {};
    std::string identity;
    if (write.binding_status == "unique_serialized_target" &&
        !write.target_id.empty()) {
        identity = "id:" + write.target_id;
    } else if (write.binding_status == "incomplete_hierarchy" &&
               write.path_hash != 0) {
        identity = "hash:" + std::to_string(write.path_hash);
    } else {
        return {};
    }
    return EffectKey{std::move(identity), write.target_type,
        write.attribute_hash};
}

using EffectMap = std::map<EffectKey, int>;

std::optional<EffectMap> ActivationEffects(const State& state) {
    EffectMap result;
    for (const auto& write : state.animation_writes) {
        // Effect clips commonly carry transform/material curves alongside the
        // activation curves.  Those curves are not part of the lock witness;
        // ignore them, while still failing closed for malformed activation
        // bindings or non-binary activation values.
        if (!IsActivationWrite(write)) continue;
        if (write.value != 0.0 && write.value != 1.0) return {};
        int value = 0;
        if (!BinaryValue(write.value, value)) return {};
        const auto key = EffectIdentity(write);
        if (!key.has_value()) return {};
        const auto inserted = result.emplace(*key, value);
        if (!inserted.second && inserted.first->second != value) return {};
    }
    return result;
}

bool HasOnlySelfTransitions(const Machine& machine, const int state) {
    if (state < 0 || state >= static_cast<int>(machine.states.size()))
        return false;
    for (const auto& edge : machine.states[static_cast<std::size_t>(state)].transitions)
        if (edge.destination != state) return false;
    return true;
}

bool ActiveController(const Snapshot& snapshot, const Controller& controller) {
    if (!snapshot.active_fx_controller_ids.empty())
        return snapshot.active_fx_controller_ids.count(controller.path_id) != 0;
    if (!snapshot.selected_controller_ids.empty())
        return snapshot.selected_controller_ids.count(controller.path_id) != 0;
    return true;
}

bool ImmediateTransition(const Transition& edge) {
    return !edge.has_exit_time && std::isfinite(edge.duration) &&
        edge.duration == 0.0 && edge.interruption_source == 0;
}

bool ImmediateMachine(const Machine& machine) {
    for (const auto& state : machine.states)
        for (const auto& edge : state.transitions)
            if (!ImmediateTransition(edge)) return false;
    return true;
}

// Some generated avatars use IsLocal > 0 and IsLocal < 0 edges to the same
// locked state.  These predicates are NOT complementary: IsLocal == 0 stays
// in the idle state.  This recognizes only the entry shape, not universal
// reachability; the independent float/latch/one-way effect proof is required.
bool FindEnvironmentLockedState(const Controller& controller,
    const Machine& producer, const int idle, int& locked) {
    if (idle < 0 || idle >= static_cast<int>(producer.states.size())) return false;
    const auto& entry = producer.states[static_cast<std::size_t>(idle)].transitions;
    if (entry.size() == 1) {
        const auto& edge = entry.front();
        if (ImmediateTransition(edge) && edge.conditions.size() == 1 && edge.destination >= 0 &&
            edge.destination < static_cast<int>(producer.states.size()) &&
            edge.destination != idle && edge.conditions.front().mode == 1 &&
            IsBoolDefault(controller, edge.conditions.front().parameter)) {
            locked = edge.destination;
            return true;
        }
        return false;
    }
    if (entry.size() != 2 || !IsFloatDefault(controller, "IsLocal")) return false;
    int candidate = -1;
    bool saw_less = false, saw_greater = false;
    for (const auto& edge : entry) {
        if (!ImmediateTransition(edge) || edge.conditions.size() != 1 || edge.destination < 0 ||
            edge.destination >= static_cast<int>(producer.states.size()) ||
            edge.destination == idle) return false;
        const auto& condition = edge.conditions.front();
        if (condition.parameter != "IsLocal" ||
            (condition.mode != 3 && condition.mode != 4) ||
            !std::isfinite(condition.threshold) ||
            !SameFloat32(condition.threshold, 0.0)) return false;
        if (candidate < 0) candidate = edge.destination;
        if (candidate != edge.destination) return false;
        saw_less = saw_less || condition.mode == 4;
        saw_greater = saw_greater || condition.mode == 3;
    }
    if (candidate < 0 || !saw_less || !saw_greater) return false;
    locked = candidate;
    return true;
}

// Fast remote graphs intentionally omit most animation curves.  Identify the
// bounded set of effect machines whose curves are required by the strict
// detector, without making an unlock decision.  This is the server-side
// equivalent of the old local extraction hint: names and sample identifiers
// are never consulted, and a safe plan is still emitted only after
// DetectFloatRangeGateRestore proves the returned animation evidence.
std::set<std::size_t> SelectFloatRangeGateDeepMachines(
    const Snapshot& snapshot, const Controller& controller) {
    std::set<std::size_t> selected;
    for (std::size_t producer_index = 0;
         producer_index < controller.machines.size(); ++producer_index) {
        const auto& producer = controller.machines[producer_index];
        if (producer.states.size() != 3 || !producer.any_transitions.empty() ||
            !ImmediateMachine(producer) ||
            producer.default_state < 0 || producer.default_state >= 3)
            continue;
        const int idle = producer.default_state;
        int locked = -1;
        if (!FindEnvironmentLockedState(controller, producer, idle, locked))
            continue;

        for (int success = 0; success < 3; ++success) {
            if (success == idle || success == locked) continue;
            const auto& locked_state = producer.states[
                static_cast<std::size_t>(locked)];
            const auto& success_state = producer.states[
                static_cast<std::size_t>(success)];
            std::vector<const Transition*> success_edges;
            for (const auto& edge : locked_state.transitions)
                if (edge.destination == success) success_edges.push_back(&edge);
            if (locked_state.transitions.size() != 1 || success_edges.size() != 1 ||
                success_edges.front()->conditions.size() != 3)
                continue;

            const auto& unlock_edge = *success_edges.front();
            std::string float_parameter, latch_parameter;
            double lower = 0.0, upper = 0.0;
            int latch_mode = 0;
            bool have_gt = false, have_lt = false, malformed = false;
            for (const auto& condition : unlock_edge.conditions) {
                if (condition.parameter.empty() ||
                    !std::isfinite(condition.threshold)) {
                    malformed = true; break;
                }
                if (condition.mode == 3 || condition.mode == 4) {
                    if (!float_parameter.empty() &&
                        float_parameter != condition.parameter) {
                        malformed = true; break;
                    }
                    float_parameter = condition.parameter;
                    if (condition.mode == 3) {
                        if (have_gt) { malformed = true; break; }
                        lower = condition.threshold; have_gt = true;
                    } else {
                        if (have_lt) { malformed = true; break; }
                        upper = condition.threshold; have_lt = true;
                    }
                } else if (condition.mode == 1 || condition.mode == 2) {
                    if (!latch_parameter.empty() ||
                        condition.parameter == float_parameter) {
                        malformed = true; break;
                    }
                    latch_parameter = condition.parameter;
                    latch_mode = condition.mode;
                } else {
                    malformed = true; break;
                }
            }
            if (malformed || !have_gt || !have_lt ||
                float_parameter.empty() || latch_parameter.empty() ||
                !NarrowInterval(lower, upper) ||
                !IsFloatDefault(controller, float_parameter) ||
                !IsBoolDefault(controller, latch_parameter) ||
                snapshot.expression_parameters.count(float_parameter) == 0 ||
                snapshot.expression_parameters.count(latch_parameter) == 0)
                continue;
            const auto float_default = controller.parameter_defaults.find(
                float_parameter);
            const auto latch_default = controller.parameter_defaults.find(
                latch_parameter);
            if (float_default == controller.parameter_defaults.end() ||
                latch_default == controller.parameter_defaults.end() ||
                (float_default->second.value > lower &&
                 float_default->second.value < upper))
                continue;
            const int expected_latch = latch_mode == 1 ? 1 : 0;
            if ((latch_default->second.value > 0.5) != expected_latch)
                continue;

            bool reverse_low = false, reverse_high = false,
                reverse_latch = false;
            if (success_state.transitions.size() != 3) continue;
            for (const auto& edge : success_state.transitions) {
                if (edge.destination != locked || edge.conditions.size() != 1) {
                    malformed = true; break;
                }
                const auto& condition = edge.conditions.front();
                if (condition.parameter == float_parameter &&
                    condition.mode == 4 &&
                    SameFloat32(condition.threshold, lower)) reverse_low = true;
                if (condition.parameter == float_parameter &&
                    condition.mode == 3 &&
                    SameFloat32(condition.threshold, upper)) reverse_high = true;
                if (condition.parameter == latch_parameter &&
                    condition.mode != latch_mode &&
                    (condition.mode == 1 || condition.mode == 2))
                    reverse_latch = true;
            }
            if (malformed || !reverse_low || !reverse_high || !reverse_latch)
                continue;

            std::string gate;
            int locked_gate = -1, success_gate = -1;
            bool ambiguous_gate = false;
            for (const auto& write : locked_state.writes) {
                int value = 0;
                if (write.type != 0 || !write.source.empty() ||
                    !BinaryValue(write.value, value)) continue;
                for (const auto& other : success_state.writes) {
                    int other_value = 0;
                    if (other.type != 0 || !other.source.empty() ||
                        write.name != other.name ||
                        !BinaryValue(other.value, other_value) ||
                        value == other_value) continue;
                    if (!gate.empty() && gate != write.name) {
                        ambiguous_gate = true; break;
                    }
                    gate = write.name;
                    locked_gate = value;
                    success_gate = other_value;
                }
                if (ambiguous_gate) break;
            }
            if (ambiguous_gate || gate.empty() || locked_gate < 0 ||
                success_gate < 0 ||
                !IsFloatDefault(controller, gate))
                continue;
            int gate_default = 0;
            if (!BinaryValue(controller.parameter_defaults.at(gate).value,
                    gate_default))
                continue;
            int gate_writes = 0;
            bool gate_conflict = false;
            for (const auto& candidate_controller : snapshot.controllers) {
                if (!ActiveController(snapshot, candidate_controller)) continue;
                for (const auto& machine : candidate_controller.machines)
                    for (const auto& state : machine.states) {
                        for (const auto& write : state.writes)
                            if (write.name == gate) {
                                int value = 0;
                                if (write.type != 0 || !write.source.empty() ||
                                    !BinaryValue(write.value, value))
                                    gate_conflict = true;
                                else ++gate_writes;
                            }
                        for (const auto& write : state.animation_writes)
                            if (write.name == gate) gate_conflict = true;
                    }
            }
            if (gate_conflict || gate_writes != 2) continue;

            const bool gate_rise = success_gate > locked_gate;
            const int enter_mode = gate_rise ? 3 : 4;
            const int hold_mode = gate_rise ? 4 : 3;
            for (std::size_t effect_index = 0;
                 effect_index < controller.machines.size(); ++effect_index) {
                if (effect_index == producer_index) continue;
                const auto& effect = controller.machines[effect_index];
                if (effect.states.size() != 2 || !ImmediateMachine(effect) ||
                    !effect.any_transitions.empty() ||
                    !effect.default_weight_known || effect.default_weight <= 1e-5)
                    continue;
                const int effect_locked = effect.default_state;
                const int effect_success = effect_locked == 0 ? 1 :
                    (effect_locked == 1 ? 0 : -1);
                if (effect_success < 0 ||
                    effect.states[static_cast<std::size_t>(effect_locked)]
                        .transitions.size() != 1 ||
                    !HasOnlySelfTransitions(effect, effect_success))
                    continue;
                const auto& enter = effect.states[
                    static_cast<std::size_t>(effect_locked)].transitions.front();
                if (enter.destination != effect_success ||
                    enter.conditions.size() != 1 ||
                    enter.conditions.front().parameter != gate ||
                    enter.conditions.front().mode != enter_mode ||
                    !std::isfinite(enter.conditions.front().threshold) ||
                    enter.conditions.front().threshold <= 0.0 ||
                    enter.conditions.front().threshold >= 1.0)
                    continue;
                bool held = false;
                for (const auto& edge : effect.states[
                         static_cast<std::size_t>(effect_success)].transitions)
                    if (edge.destination == effect_success &&
                        edge.conditions.size() == 1 &&
                        edge.conditions.front().parameter == gate &&
                        edge.conditions.front().mode == hold_mode &&
                        SameFloat32(edge.conditions.front().threshold,
                            enter.conditions.front().threshold))
                        held = true;
                if (held) selected.insert(effect_index);
            }
        }
    }
    return selected;
}

}  // namespace float_range_gate_detail

std::optional<FloatRangeGateRestoreEvidence> DetectFloatRangeGateRestore(
    const Snapshot& snapshot, const Controller& controller) {
    using namespace float_range_gate_detail;
    std::vector<FloatRangeGateRestoreEvidence> matches;

    for (std::size_t producer_index = 0;
         producer_index < controller.machines.size(); ++producer_index) {
        const auto& producer = controller.machines[producer_index];
        if (producer.states.size() != 3 || !producer.any_transitions.empty() ||
            !ImmediateMachine(producer) ||
            producer.default_state < 0 || producer.default_state >= 3)
            continue;
        const int idle = producer.default_state;

        int locked = -1;
        if (!FindEnvironmentLockedState(controller, producer, idle, locked))
            continue;

        for (int success = 0; success < 3; ++success) {
            if (success == idle || success == locked) continue;
            const auto& locked_state = producer.states[static_cast<std::size_t>(locked)];
            const auto& success_state = producer.states[static_cast<std::size_t>(success)];
            std::vector<const Transition*> success_edges;
            for (const auto& edge : locked_state.transitions)
                if (edge.destination == success) success_edges.push_back(&edge);
            if (locked_state.transitions.size() != 1 || success_edges.size() != 1) continue;
            const auto& entry = *success_edges.front();
            if (entry.conditions.size() != 3) continue;

            std::string float_parameter, latch_parameter;
            double lower = 0.0, upper = 0.0;
            int latch_mode = 0;
            bool have_gt = false, have_lt = false;
            bool malformed = false;
            for (const auto& condition : entry.conditions) {
                if (condition.parameter.empty() || !std::isfinite(condition.threshold)) {
                    malformed = true; break;
                }
                if (condition.mode == 3 || condition.mode == 4) {
                    if (!float_parameter.empty() && float_parameter != condition.parameter) {
                        malformed = true; break;
                    }
                    float_parameter = condition.parameter;
                    if (condition.mode == 3) {
                        if (have_gt) { malformed = true; break; }
                        lower = condition.threshold; have_gt = true;
                    } else {
                        if (have_lt) { malformed = true; break; }
                        upper = condition.threshold; have_lt = true;
                    }
                } else if (condition.mode == 1 || condition.mode == 2) {
                    if (!latch_parameter.empty() ||
                        condition.parameter == float_parameter) {
                        malformed = true; break;
                    }
                    latch_parameter = condition.parameter;
                    latch_mode = condition.mode;
                } else {
                    malformed = true; break;
                }
            }
            if (malformed || !have_gt || !have_lt || float_parameter.empty() ||
                latch_parameter.empty() || !NarrowInterval(lower, upper) ||
                !IsFloatDefault(controller, float_parameter) ||
                !IsBoolDefault(controller, latch_parameter))
                continue;
            const auto float_default = controller.parameter_defaults.find(float_parameter);
            const auto latch_default = controller.parameter_defaults.find(latch_parameter);
            if (float_default == controller.parameter_defaults.end() ||
                (float_default->second.value > lower &&
                    float_default->second.value < upper))
                continue;  // the default must be outside the success interval
            const int expected_latch = latch_mode == 1 ? 1 : 0;
            if ((latch_default->second.value > 0.5) != expected_latch)
                continue;
            if (snapshot.expression_parameters.count(float_parameter) == 0 ||
                snapshot.expression_parameters.count(latch_parameter) == 0)
                continue;

            // The reverse path must cover both interval boundaries and the
            // opposite latch polarity.  Every outgoing edge is explicit and
            // single-condition, preventing an unknown competing branch.
            bool reverse_low = false, reverse_high = false, reverse_latch = false;
            if (success_state.transitions.empty()) continue;
            for (const auto& edge : success_state.transitions) {
                if (edge.destination != locked || edge.conditions.size() != 1)
                    continue;
                const auto& condition = edge.conditions.front();
                if (condition.parameter == float_parameter && condition.mode == 4 &&
                    SameFloat32(condition.threshold, lower)) reverse_low = true;
                if (condition.parameter == float_parameter && condition.mode == 3 &&
                    SameFloat32(condition.threshold, upper)) reverse_high = true;
                if (condition.parameter == latch_parameter &&
                    condition.mode != latch_mode &&
                    (condition.mode == 1 || condition.mode == 2)) reverse_latch = true;
            }
            if (!reverse_low || !reverse_high || !reverse_latch) continue;
            bool reverse_shape = success_state.transitions.size() == 3;
            for (const auto& edge : success_state.transitions)
                if (edge.destination != locked || edge.conditions.size() != 1)
                    reverse_shape = false;
            if (!reverse_shape) continue;

            // Exactly one binary gate is written in the two producer states.
            std::string gate;
            int locked_gate = -1, success_gate = -1;
            for (const auto& write : locked_state.writes) {
                int value = 0;
                if (write.type != 0 || write.source.size() != 0 ||
                    !BinaryValue(write.value, value)) continue;
                for (const auto& other : success_state.writes) {
                    int other_value = 0;
                    if (other.type == 0 && other.source.empty() &&
                        write.name == other.name && BinaryValue(other.value, other_value) &&
                        value != other_value) {
                        if (!gate.empty() && gate != write.name) { gate.clear(); break; }
                        gate = write.name; locked_gate = value; success_gate = other_value;
                    }
                }
                if (gate.empty() && locked_gate >= 0) break;
            }
            if (gate.empty() || locked_gate < 0 || success_gate < 0 ||
                !IsFloatDefault(controller, gate))
                continue;
            int gate_default = 0;
            if (!BinaryValue(controller.parameter_defaults.at(gate).value,
                    gate_default))
                continue;
            int gate_writes = 0;
            bool gate_conflict = false;
            for (const auto& candidate_controller : snapshot.controllers) {
                if (!ActiveController(snapshot, candidate_controller)) continue;
                for (const auto& machine : candidate_controller.machines)
                    for (const auto& state : machine.states) {
                        for (const auto& write : state.writes)
                            if (write.name == gate) {
                                int value = 0;
                                if (write.type != 0 || !write.source.empty() ||
                                    !BinaryValue(write.value, value))
                                    gate_conflict = true;
                                else ++gate_writes;
                            }
                        for (const auto& write : state.animation_writes)
                            if (write.name == gate) gate_conflict = true;
                    }
            }
            if (gate_conflict || gate_writes != 2) continue;

            // Locate one effect machine that latches the successful gate pulse.
            std::vector<FloatRangeGateRestoreEvidence> effect_matches;
            for (std::size_t effect_index = 0;
                 effect_index < controller.machines.size(); ++effect_index) {
                if (effect_index == producer_index) continue;
                const auto& effect = controller.machines[effect_index];
                if (effect.states.size() != 2 || !effect.any_transitions.empty() ||
                    !ImmediateMachine(effect) ||
                    !effect.default_weight_known || effect.default_weight <= 1e-5)
                    continue;
                const int effect_locked = effect.default_state;
                const int effect_success = effect_locked == 0 ? 1 :
                    (effect_locked == 1 ? 0 : -1);
                if (effect_success < 0) continue;
                const auto off = ActivationEffects(effect.states[
                    static_cast<std::size_t>(effect_locked)]);
                const auto on = ActivationEffects(effect.states[
                    static_cast<std::size_t>(effect_success)]);
                if (!off || !on || off->size() < 2 || off->size() != on->size())
                    continue;
                bool complementary = true;
                int renderer_count = 0;
                std::set<EffectKey> restored;
                for (const auto& [key, value] : *off) {
                    const auto found = on->find(key);
                    if (found == on->end()) {
                        complementary = false; break;
                    }
                    if (value == found->second) continue;
                    if (value != 0 || found->second != 1) {
                        complementary = false; break;
                    }
                    restored.insert(key);
                    if (std::get<1>(key) == 23 || std::get<1>(key) == 137)
                        ++renderer_count;
                }
                if (!complementary || restored.size() < 2 || renderer_count < 2)
                    continue;

                bool gate_rise = success_gate > locked_gate;
                int enter_mode = gate_rise ? 3 : 4;
                int hold_mode = gate_rise ? 4 : 3;
                double gate_threshold = 0.5;
                bool entered = false, held = false;
                if (effect.states[static_cast<std::size_t>(effect_locked)]
                        .transitions.size() != 1)
                    continue;
                for (const auto& edge : effect.states[static_cast<std::size_t>(effect_locked)].transitions)
                    if (edge.destination == effect_success && edge.conditions.size() == 1 &&
                        edge.conditions.front().parameter == gate &&
                        edge.conditions.front().mode == enter_mode &&
                        std::isfinite(edge.conditions.front().threshold) &&
                        edge.conditions.front().threshold > 0.0 &&
                        edge.conditions.front().threshold < 1.0) {
                        gate_threshold = edge.conditions.front().threshold;
                        entered = true;
                    }
                for (const auto& edge : effect.states[static_cast<std::size_t>(effect_success)].transitions)
                    if (edge.destination == effect_success && edge.conditions.size() == 1 &&
                        edge.conditions.front().parameter == gate &&
                        edge.conditions.front().mode == hold_mode &&
                        SameFloat32(edge.conditions.front().threshold, gate_threshold))
                        held = true;
                if (!entered || !held || !HasOnlySelfTransitions(effect, effect_success))
                    continue;

                // No other active machine may write the same visual targets.
                bool competing = false;
                for (const auto& candidate_controller : snapshot.controllers) {
                    if (!ActiveController(snapshot, candidate_controller)) continue;
                    for (std::size_t mi = 0; mi < candidate_controller.machines.size(); ++mi)
                        for (std::size_t si = 0; si < candidate_controller.machines[mi].states.size(); ++si) {
                            if (&candidate_controller == &controller && mi == effect_index &&
                                (si == static_cast<std::size_t>(effect_locked) ||
                                 si == static_cast<std::size_t>(effect_success))) continue;
                            for (const auto& write : candidate_controller.machines[mi].states[si].animation_writes) {
                                const auto key = EffectIdentity(write);
                                if (key && restored.count(*key)) {
                                    competing = true; break;
                                }
                            }
                            if (competing) break;
                        }
                    if (competing) break;
                }
                if (competing) continue;

                FloatRangeGateRestoreEvidence evidence;
                evidence.producer_machine = producer_index;
                evidence.locked_state = locked;
                evidence.success_state = success;
                evidence.effect_machine = effect_index;
                evidence.effect_locked_state = effect_locked;
                evidence.effect_success_state = effect_success;
                evidence.float_parameter = float_parameter;
                evidence.latch_parameter = latch_parameter;
                evidence.gate_parameter = gate;
                evidence.lower = lower;
                evidence.upper = upper;
                evidence.success_latch_mode = latch_mode;
                evidence.locked_gate_value = locked_gate;
                evidence.success_gate_value = success_gate;
                evidence.restored_effects = restored.size();
                effect_matches.push_back(std::move(evidence));
            }
            if (effect_matches.size() == 1)
                matches.push_back(std::move(effect_matches.front()));
        }
    }
    return matches.size() == 1
        ? std::optional<FloatRangeGateRestoreEvidence>(std::move(matches.front()))
        : std::nullopt;
}
