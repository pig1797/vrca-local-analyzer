struct OscShiftRestoreEvidence {
    std::size_t machine_index = static_cast<std::size_t>(-1);
    int success_state = -1;
    std::string input_parameter;
    std::string latch_parameter;
    std::vector<int> password;
    std::size_t consumer_machine = static_cast<std::size_t>(-1);
    int restored_effects = 0;
};

std::optional<OscShiftRestoreEvidence> DetectOscShiftRestore(
    const Snapshot& snapshot, const Controller& controller) {
    std::vector<OscShiftRestoreEvidence> matches;
    for (std::size_t machine_index = 0;
         machine_index < controller.machines.size(); ++machine_index) {
        const auto& machine = controller.machines[machine_index];
        if (machine.states.size() < 4 || machine.states.size() > 12 ||
            !machine.any_transitions.empty()) continue;

        for (std::size_t success_index = 0;
             success_index < machine.states.size(); ++success_index) {
            const auto& success = machine.states[success_index];
            std::vector<const ParameterWrite*> changed_bool_writes;
            std::map<std::string, double> success_values;
            for (const auto& write : success.writes) {
                if (write.type != 0 || write.name.empty()) continue;
                success_values[write.name] = write.value;
                const auto* initial = EffectiveRuntimeDefault(
                    snapshot, controller, write.name);
                if (initial && initial->type == "bool" &&
                    std::abs(initial->value - write.value) > 1e-5)
                    changed_bool_writes.push_back(&write);
            }
            if (changed_bool_writes.size() != 1) continue;
            const auto& latch = *changed_bool_writes.front();

            // The terminal may have a re-lock edge, but its own entry writes
            // must seal every concrete edge immediately.
            bool sealed = true;
            for (const auto& transition : success.transitions) {
                if (transition.destination < 0 || transition.destination >=
                    static_cast<int>(machine.states.size())) continue;
                bool enabled = true;
                for (const auto& condition : transition.conditions) {
                    const auto match = ConditionMatches(
                        condition, success_values);
                    if (!match.has_value()) { sealed = false; enabled = false; break; }
                    if (!*match) { enabled = false; break; }
                }
                if (enabled) sealed = false;
            }
            if (!sealed) continue;

            int opposite_writers = 0;
            for (const auto& candidate_machine : controller.machines)
                for (const auto& state : candidate_machine.states)
                    for (const auto& write : state.writes)
                        if (write.type == 0 && write.name == latch.name &&
                            std::abs(write.value - latch.value) > 0.5)
                            ++opposite_writers;
            if (opposite_writers != 1) continue;

            // Recover the unique comparator edge entering this terminal.
            const Transition* comparator = nullptr;
            bool ambiguous_comparator = false;
            for (const auto& state : machine.states)
                for (const auto& transition : state.transitions)
                    if (transition.destination == static_cast<int>(success_index) &&
                        transition.conditions.size() >= 3 &&
                        transition.conditions.size() <= 12) {
                        if (comparator) { ambiguous_comparator = true; continue; }
                        comparator = &transition;
                    }
            if (!comparator || ambiguous_comparator) continue;
            std::map<std::string, int> expected;
            for (const auto& condition : comparator->conditions) {
                if (condition.mode != 6 || condition.parameter.empty() ||
                    !std::isfinite(condition.threshold) ||
                    std::abs(condition.threshold -
                        std::round(condition.threshold)) > 1e-5)
                    { expected.clear(); break; }
                const int digit = static_cast<int>(
                    std::llround(condition.threshold));
                if (digit < 0 || digit > 9 ||
                    !expected.emplace(condition.parameter, digit).second)
                    { expected.clear(); break; }
            }
            if (expected.size() != comparator->conditions.size()) continue;

            // Locate one shift operation: slot0 <- external input, each later
            // slot <- previous slot.  Names and state labels are irrelevant.
            std::string input;
            std::vector<std::string> slots;
            int shift_states = 0;
            for (const auto& state : machine.states) {
                std::map<std::string, std::string> copies;
                for (const auto& write : state.writes)
                    if (write.type == 3 && !write.name.empty() &&
                        !write.source.empty()) copies[write.name] = write.source;
                if (copies.size() < expected.size()) continue;
                for (const auto& [destination, source] : copies) {
                    if (copies.count(source) != 0 ||
                        snapshot.expression_parameters.count(source) == 0)
                        continue;
                    std::vector<std::string> chain{destination};
                    while (chain.size() < copies.size()) {
                        const auto next = std::find_if(copies.begin(), copies.end(),
                            [&](const auto& item) {
                                return item.second == chain.back();
                            });
                        if (next == copies.end()) break;
                        chain.push_back(next->first);
                    }
                    if (chain.size() >= expected.size()) {
                        input = source;
                        slots = std::move(chain);
                        ++shift_states;
                    }
                }
            }
            if (shift_states != 1 || input.empty()) continue;
            std::vector<int> password;
            for (std::size_t index = 0; index < expected.size(); ++index) {
                const auto found = expected.find(slots[index]);
                if (found == expected.end()) { password.clear(); break; }
                password.push_back(found->second);
            }
            if (password.size() != expected.size()) continue;

            // The latch must weight a real Direct Blend Tree child whose
            // exact animation targets are inactive by default and restored by
            // the weighted clip.  This proves the final visible effect.
            std::size_t consumer_machine = static_cast<std::size_t>(-1);
            int restored_effects = 0;
            int consumer_count = 0;
            for (std::size_t other = 0;
                 other < controller.machines.size(); ++other) {
                const auto& consumer = controller.machines[other];
                if (!consumer.default_weight_known ||
                    consumer.default_weight <= 1e-5) continue;
                for (const auto& state : consumer.states) {
                    std::set<int> weighted_clips;
                    for (const auto& read : state.blend_parameter_reads)
                        if (read.parameter == latch.name && read.clip_id >= 0)
                            weighted_clips.insert(read.clip_id);
                    if (weighted_clips.size() != 1) continue;
                    int effects = 0;
                    bool all_restore = true;
                    std::set<std::string> targets;
                    for (const auto& effect : state.animation_writes) {
                        if (effect.clip_index != *weighted_clips.begin()) continue;
                        if ((effect.name != "m_IsActive" &&
                             effect.name != "m_Enabled") ||
                            std::abs(effect.value - 1.0) > 1e-5 ||
                            effect.binding_status != "unique_serialized_target" ||
                            !effect.serialized_active_known ||
                            effect.serialized_active || effect.target_id.empty() ||
                            !targets.insert(effect.target_id).second) {
                            all_restore = false;
                            break;
                        }
                        ++effects;
                    }
                    if (!all_restore || effects < 1) continue;
                    ++consumer_count;
                    consumer_machine = other;
                    restored_effects = effects;
                }
            }
            if (consumer_count != 1) continue;
            matches.push_back({machine_index,
                static_cast<int>(success_index), input, latch.name,
                password, consumer_machine, restored_effects});
        }
    }
    return matches.size() == 1
        ? std::optional<OscShiftRestoreEvidence>(matches.front())
        : std::nullopt;
}
