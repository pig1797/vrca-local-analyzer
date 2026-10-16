// Effect-driven proof for a compound-input latch whose consumer's default
// clip disables serialized-active avatar objects.  No object, parameter,
// state, author, or model names participate in the decision.
std::optional<int> CompoundRestrictionTerminal(const Snapshot& snapshot,
    const Controller& controller, std::size_t consumer_index) {
    if (consumer_index >= controller.machines.size()) return {};
    const auto& consumer = controller.machines[consumer_index];
    if (!consumer.default_weight_known || consumer.default_weight != 1.0 ||
        !consumer.any_transitions.empty() || consumer.states.size() != 2 ||
        consumer.default_state < 0 || consumer.default_state > 1) return {};
    const auto& restricted = consumer.states[
        static_cast<std::size_t>(consumer.default_state)];
    if (restricted.transitions.size() != 1) return {};
    const auto& edge = restricted.transitions.front();
    if (edge.destination < 0 || edge.destination > 1 ||
        edge.destination == consumer.default_state || edge.conditions.size() != 1 ||
        (edge.conditions[0].mode != 1 && edge.conditions[0].mode != 2) ||
        !consumer.states[static_cast<std::size_t>(edge.destination)].transitions.empty())
        return {};
    const auto& latch = edge.conditions[0].parameter;
    const int wanted = edge.conditions[0].mode == 1 ? 1 : 0;
    const auto latch_default = controller.parameter_defaults.find(latch);
    if (latch.empty() || latch_default == controller.parameter_defaults.end() ||
        latch_default->second.type != "bool" ||
        static_cast<int>(latch_default->second.value > 0.5) == wanted ||
        !snapshot.saved_expression_parameters.count(latch)) return {};

    std::set<std::string> restricted_targets;
    for (const auto& write : restricted.animation_writes) {
        if (write.target_type == 1 && write.attribute_hash == 2086281974U &&
            write.value == 0 && write.binding_status == "unique_serialized_target" &&
            !write.target_id.empty() && write.serialized_active_known &&
            write.serialized_active)
            restricted_targets.insert(write.target_id);
    }
    if (restricted_targets.size() < 2) return {};
    const auto& restored = consumer.states[static_cast<std::size_t>(edge.destination)];
    for (const auto& write : restored.animation_writes)
        if (restricted_targets.count(write.target_id) && write.value == 0)
            return {};

    int writer_count = 0;
    std::size_t producer_index = 0, success_state = 0;
    for (std::size_t mi = 0; mi < controller.machines.size(); ++mi)
        for (std::size_t si = 0; si < controller.machines[mi].states.size(); ++si)
            for (const auto& write : controller.machines[mi].states[si].writes)
                if (write.name == latch) {
                    if (write.type != 0 || static_cast<int>(write.value > 0.5) != wanted)
                        return {};
                    ++writer_count; producer_index = mi; success_state = si;
                }
    if (writer_count != 1 || producer_index == consumer_index) return {};
    const auto& producer = controller.machines[producer_index];
    if (!producer.default_weight_known || producer.default_weight != 1.0 ||
        !producer.any_transitions.empty() || producer.default_state < 0 ||
        producer.default_state >= static_cast<int>(producer.states.size()) ||
        success_state >= producer.states.size() ||
        !producer.states[success_state].transitions.empty()) return {};
    int matching_gates = 0;
    for (const auto& transition : producer.states[
             static_cast<std::size_t>(producer.default_state)].transitions) {
        if (transition.destination != static_cast<int>(success_state)) continue;
        if (transition.conditions.size() < 3 || transition.conditions.size() > 8)
            return {};
        int bool_conditions = 0;
        std::map<std::string, std::set<int>> range_modes;
        for (const auto& condition : transition.conditions) {
            if (condition.parameter.empty() || condition.mode < 1 || condition.mode > 6 ||
                !std::isfinite(condition.threshold)) return {};
            if (condition.mode == 1 || condition.mode == 2) ++bool_conditions;
            if (condition.mode == 3 || condition.mode == 4)
                range_modes[condition.parameter].insert(condition.mode);
        }
        const bool has_window = std::any_of(range_modes.begin(), range_modes.end(),
            [](const auto& item) { return item.second.count(3) && item.second.count(4); });
        if (bool_conditions < 2 || !has_window) return {};
        ++matching_gates;
    }
    if (matching_gates != 1) return {};

    // The restriction targets must be exclusive to this consumer among all
    // extracted effect states.  A competing writer would make a one-machine
    // default-state rewrite unsafe.
    for (std::size_t mi = 0; mi < controller.machines.size(); ++mi)
        for (std::size_t si = 0; si < controller.machines[mi].states.size(); ++si) {
            if (mi == consumer_index && si == static_cast<std::size_t>(consumer.default_state))
                continue;
            for (const auto& write : controller.machines[mi].states[si].animation_writes)
                if (restricted_targets.count(write.target_id)) return {};
        }
    return edge.destination;
}
