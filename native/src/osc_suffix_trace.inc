// Bounded, pure-memory normalized-graph contract. This is not SDK execution
// or a runtime acceptance proof, and must never authorize a writer plan.
namespace osc_suffix_trace_detail {

bool MetadataKnown(const ParameterWrite& write) {
    for (const auto& [name, value] : write.operation_flags) {
        if (name != "convert_range" && name != "local_only" &&
            name != "prevent_repeats") return false;
        if ((name == "convert_range" || name == "prevent_repeats") && value)
            return false;
    }
    for (const auto& [name, value] : write.operation_numbers) {
        if (!std::isfinite(value) || (name != "source_min" &&
            name != "source_max" && name != "dest_min" &&
            name != "dest_max" && name != "value_min" &&
            name != "value_max" && name != "chance")) return false;
    }
    const auto convert = write.operation_flags.find("convert_range");
    return write.type == 0 || (write.type == 3 &&
        convert != write.operation_flags.end() && !convert->second);
}

bool Representable(const ParameterDefault& definition, double value) {
    if (!std::isfinite(value)) return false;
    if (definition.type == "int") return std::floor(value) == value &&
        value >= -2147483648.0 && value <= 2147483647.0;
    if (definition.type == "bool") return value == 0 || value == 1;
    return definition.type == "float";
}

bool Verify(const Snapshot& snapshot, const Controller& controller,
    const Machine& machine, std::size_t copy_state_index,
    const std::string& input, const std::map<std::string, int>& expected,
    const std::vector<int>& sequence) {
    constexpr std::size_t max_states = 64;
    constexpr std::size_t max_transitions = 256;
    constexpr std::size_t max_names = 128;
    constexpr std::size_t max_steps = 4096;
    if (input.empty() || input == "IsLocal" || expected.size() < 4 ||
        expected.size() > 12 || sequence.size() != expected.size() ||
        machine.states.empty() || machine.states.size() > max_states ||
        copy_state_index >= machine.states.size() ||
        machine.default_state < 0 || machine.default_state >=
            static_cast<int>(machine.states.size()) ||
        !machine.any_transitions.empty()) return false;
    for (int digit : sequence) if (digit < 1 || digit > 7) return false;

    std::set<std::string> names{input};
    std::set<std::string> buffers;
    for (const auto& write : machine.states[copy_state_index].writes) {
        if (write.type != 3 || write.name.empty() || write.name == input ||
            !buffers.insert(write.name).second) return false;
    }
    if (buffers.size() < expected.size() || buffers.size() > 17) return false;
    for (const auto& [name, value] : expected)
        if (!buffers.count(name) || value < 1 || value > 7) return false;
    std::size_t edge_count = 0;
    for (std::size_t index = 0; index < machine.states.size(); ++index) {
        const auto& state = machine.states[index];
        if (!state.animation_writes.empty() ||
            !state.manual_activation_writes.empty() ||
            !state.blend_parameter_reads.empty() || state.writes.size() > 32)
            return false;
        edge_count += state.transitions.size();
        if (edge_count > max_transitions) return false;
        for (const auto& write : state.writes) {
            if (!MetadataKnown(write) || write.name.empty() ||
                write.name == input || write.name == "IsLocal" ||
                (write.type == 0 && !write.source.empty()) ||
                (write.type == 3 && write.source.empty()) ||
                (index != copy_state_index && buffers.count(write.name)))
                return false;
            names.insert(write.name);
            if (!write.source.empty()) names.insert(write.source);
        }
        for (const auto& edge : state.transitions) {
            if (edge.destination < 0 || edge.destination >=
                static_cast<int>(machine.states.size()) ||
                edge.conditions.size() > 16) return false;
            for (const auto& condition : edge.conditions) {
                if (condition.parameter.empty() ||
                    !std::isfinite(condition.threshold)) return false;
                names.insert(condition.parameter);
            }
        }
        if (names.size() > max_names) return false;
    }

    std::map<std::string, ParameterDefault> definitions;
    std::map<std::string, double> values;
    for (const auto& name : names) {
        if (name == "IsLocal") {
            // Explicit local-only model context, not an inferred OSC input.
            definitions[name] = {"bool", 1};
            values[name] = 1;
            continue;
        }
        const auto* definition = EffectiveRuntimeDefault(snapshot, controller, name);
        if (!definition || !Representable(*definition, definition->value))
            return false;
        if ((name == input || buffers.count(name)) &&
            (definition->type != "int" || definition->value != 0)) return false;
        definitions.emplace(name, *definition);
        values.emplace(name, definition->value);
    }
    int current = machine.default_state;
    std::size_t total_steps = 0;
    std::size_t copy_entries = 0;
    const auto enter = [&]() -> bool {
        if (++total_steps > max_steps) return false;
        if (current == static_cast<int>(copy_state_index)) ++copy_entries;
        for (const auto& write : machine.states[static_cast<std::size_t>(current)].writes) {
            const auto definition = definitions.find(write.name);
            if (definition == definitions.end()) return false;
            double value = write.value;
            if (write.type == 3) {
                const auto source = values.find(write.source);
                const auto source_definition = definitions.find(write.source);
                if (source == values.end() || source_definition == definitions.end() ||
                    source_definition->second.type != definition->second.type)
                    return false;
                value = source->second;
            }
            if (!Representable(definition->second, value)) return false;
            values[write.name] = value;
        }
        return true;
    };
    const auto settle = [&]() -> bool {
        // A state visited twice under an unchanged external input is a loop,
        // not evidence of a converged Animator state. Reject even if a write
        // might make it terminate later: this contract is intentionally small.
        std::set<int> visited;
        while (visited.insert(current).second) {
            if (++total_steps > max_steps) return false;
            const Transition* selected = nullptr;
            for (const auto& edge : machine.states[static_cast<std::size_t>(current)].transitions) {
                bool enabled = true;
                for (const auto& condition : edge.conditions) {
                    // A serialized default is not evidence that an external
                    // expression guard remains immutable. Apply this gate to
                    // every guard on a state actually visited by the trace;
                    // unreachable/invalid-alphabet failure states may exist.
                    if (condition.parameter != input &&
                        condition.parameter != "IsLocal" &&
                        snapshot.expression_parameters.count(condition.parameter))
                        return false;
                    const auto match = ConditionMatches(condition, values);
                    if (!match.has_value()) return false;
                    enabled = enabled && *match;
                }
                // Time-dependent edges are outside this zero-time contract.
                // Even a currently false predicate cannot prove it stays false.
                if (edge.has_exit_time || edge.duration != 0 ||
                    !std::isfinite(edge.duration)) return false;
                if (enabled && !selected) selected = &edge;
            }
            if (!selected) return true;
            current = selected->destination;
            if (!enter()) return false;
        }
        return false;
    };
    if (!enter() || !settle() || copy_entries != 0) return false;
    for (const auto& name : buffers) if (values.at(name) != 0) return false;
    const auto cycle = [&](int digit) -> bool {
        const auto previous_copies = copy_entries;
        values[input] = digit;
        if (!settle() || copy_entries != previous_copies + 1 ||
            values.at(input) != digit) return false;
        std::map<std::string, double> before_reset;
        for (const auto& name : buffers) before_reset.emplace(name, values.at(name));
        values[input] = 0;
        if (!settle() || copy_entries != previous_copies + 1 ||
            current == static_cast<int>(copy_state_index) || values.at(input) != 0)
            return false;
        for (const auto& [name, value] : before_reset)
            if (values.at(name) != value) return false;
        return true;
    };
    const auto armed = [&]() -> bool {
        if (current == static_cast<int>(copy_state_index) || values.at(input) != 0)
            return false;
        const auto saved_values = values;
        const int saved_current = current;
        const auto saved_copies = copy_entries;
        const auto restore = [&]() {
            values = saved_values;
            current = saved_current;
            copy_entries = saved_copies;
        };
        // Dispatch-style producers may wait in a state selected by their
        // newest cached digit rather than returning to one common Idle index.
        // Prove each stable reset state can accept every public digit, twice:
        // this also verifies repeated equal digits cause distinct Copy entries.
        // Probes are transactional memory clones; total_steps is not restored.
        for (int digit = 1; digit <= 7; ++digit) {
            restore();
            if (!cycle(digit) || !cycle(digit)) { restore(); return false; }
        }
        restore();
        return true;
    };
    if (!armed()) return false;
    for (int digit : sequence) {
        if (!cycle(digit) || !armed()) return false;
    }
    for (const auto& [name, value] : expected)
        if (values.at(name) != value) return false;
    return true;
}
} // namespace osc_suffix_trace_detail
