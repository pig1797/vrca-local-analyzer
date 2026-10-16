// Post-rewrite fixed-point proof, deliberately separate from password entry
// reachability. Not an input witness and never a reason to promote a password.
struct GuardedPairTerminalProof {
    bool accepted = false;
    std::string reason;
};

GuardedPairTerminalProof ProveGuardedPairTerminalWrites(
    const Snapshot& snapshot, const Controller& controller,
    std::size_t producer_index, int producer_state,
    std::size_t effect_index, int effect_state,
    const std::string& gate, int gate_mode) {
    const auto reject = [](const char* reason) { return GuardedPairTerminalProof{false, reason}; };
    if (producer_index == effect_index || producer_index >= controller.machines.size() ||
        effect_index >= controller.machines.size() || (gate_mode != 1 && gate_mode != 2))
        return reject("invalid_coordinates");
    if (snapshot.active_fx_controller_ids.empty() ||
        !snapshot.active_fx_controller_ids.count(controller.path_id))
        return reject("active_fx_not_proven");
    std::size_t active_count = 0, active_machines = 0;
    for (const auto& active : snapshot.controllers) {
        if (!snapshot.active_fx_controller_ids.count(active.path_id)) continue;
        ++active_count;
        active_machines += active.machines.size();
    }
    // Fast/partial animation selection cannot rule out another FX layer
    // overwriting a latch. Require the full active-FX evidence request.
    if (snapshot.analysis_depth != "targeted_deep" ||
        active_count != snapshot.active_fx_controller_ids.size() ||
        active_machines == 0 || active_machines > 512 ||
        snapshot.deep_scan_machine_count != static_cast<int>(active_machines))
        return reject("full_active_fx_evidence_missing");
    const auto& producer = controller.machines[producer_index];
    const auto& effect = controller.machines[effect_index];
    if (producer_state < 0 || effect_state < 0 ||
        producer_state >= static_cast<int>(producer.states.size()) ||
        effect_state >= static_cast<int>(effect.states.size()))
        return reject("invalid_terminal");
    const auto complementary = ComplementaryParameterDriverTerminal(snapshot, controller, producer);
    if (!complementary || *complementary != producer_state ||
        !IsGateProducerTerminal(snapshot, controller, producer, producer_state, gate, gate_mode) ||
        !HasNumericEffectTerminal(snapshot, controller, effect, effect_state))
        return reject("terminal_semantics_unproven");

    const auto evaluate = [](const State& first, const State& second,
                             std::map<std::string, double>& values) {
        for (const State* terminal : {&first, &second}) {
            for (const auto& write : terminal->writes) {
                if (write.name.empty()) return false;
                const auto local = write.operation_flags.find("local_only");
                if (local != write.operation_flags.end() && local->second) return false;
                double value;
                if (write.type == 0) value = write.value;
                else if (write.type == 3) {
                    const auto convert = write.operation_flags.find("convert_range");
                    const auto source = values.find(write.source);
                    if (convert == write.operation_flags.end() || convert->second || source == values.end())
                        return false;
                    value = source->second;
                } else return false;
                // Binary latch values are represented exactly for Bool/Int/Float.
                // Range conversion, arithmetic, randomness and unknown reads are
                // outside this deliberately narrow proof.
                if (!std::isfinite(value) || (value != 0.0 && value != 1.0)) return false;
                const auto old = values.find(write.name);
                if (old != values.end() && old->second != value) return false;
                values[write.name] = value;
            }
        }
        return true;
    };
    std::map<std::string, double> values, reversed;
    if (!evaluate(producer.states[producer_state], effect.states[effect_state], values) ||
        !evaluate(effect.states[effect_state], producer.states[producer_state], reversed) ||
        values != reversed)
        return reject("terminal_writes_unknown_or_order_dependent");
    const auto gate_value = values.find(gate);
    if (gate_value == values.end() || (gate_value->second > 0.5) != (gate_mode == 1))
        return reject("gate_polarity_mismatch");
    // ParameterDriver runs on entry; a clip can keep writing every frame.
    // Do not assume the driver's constants dominate either terminal's clips.
    for (const State* terminal : {&producer.states[producer_state], &effect.states[effect_state]}) {
        for (const auto& write : terminal->animation_writes)
            if (values.count(write.name)) return reject("terminal_animation_can_overwrite_latch");
        for (const auto& write : terminal->manual_activation_writes)
            if (values.count(write.name)) return reject("terminal_animation_can_overwrite_latch");
    }

    const auto closed = [&](const Machine& machine, int terminal) {
        const auto edges_blocked = [&](const std::vector<Transition>& transitions) {
            for (const auto& transition : transitions) {
                if (transition.destination < 0 || transition.destination >= static_cast<int>(machine.states.size()))
                    return false;
                if (transition.destination == terminal) continue;
                bool blocked = false;
                for (const auto& condition : transition.conditions) {
                    const auto outcome = ConditionMatches(condition, values);
                    blocked |= outcome.has_value() && !*outcome;
                }
                if (!blocked) return false;
            }
            return true;
        };
        return edges_blocked(machine.any_transitions) && edges_blocked(machine.states[terminal].transitions);
    };
    if (!closed(producer, producer_state) || !closed(effect, effect_state))
        return reject("terminal_can_leave");
    for (const auto& other : snapshot.controllers) {
        if (!snapshot.active_fx_controller_ids.count(other.path_id)) continue;
        for (std::size_t index = 0; index < other.machines.size(); ++index) {
            if (other.path_id == controller.path_id && (index == producer_index || index == effect_index)) continue;
            for (const auto& state : other.machines[index].states) {
                for (const auto& write : state.writes)
                    if (values.count(write.name)) return reject("competing_parameter_writer");
                for (const auto& write : state.animation_writes)
                    if (values.count(write.name)) return reject("competing_animation_writer");
            }
        }
    }
    for (const auto& contact : snapshot.contact_input_parameters)
        if (values.count(contact)) return reject("contact_can_overwrite_latch");
    return {true, "binary_latch_pair_fixed_point"};
}
