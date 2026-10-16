// Internal effect-directed slice. State IDs are retained for plans and replay.
// Rejecting/priority edges are NEVER removed from execution: the slice only
// prunes a configuration after its ordered transition has been evaluated.
struct SemanticSlice {
    std::set<int> states;
    std::set<std::string> parameters;
    std::set<std::pair<std::string, std::size_t>> dependencies;
    bool competing_writers = false;
};

SemanticSlice BuildSemanticSlice(const SemanticUsage& usage,
    const Controller& controller, std::size_t machine_index,
    const Machine& machine, const std::string& input,
    const std::set<int>& terminals) {
    SemanticSlice slice;
    slice.parameters.insert(input);
    std::vector<std::vector<int>> predecessors(machine.states.size());
    const auto edge = [&](int from, const Transition& tr) {
        if (tr.destination >= 0 &&
            tr.destination < static_cast<int>(machine.states.size()))
            predecessors[static_cast<std::size_t>(tr.destination)].push_back(from);
    };
    for (std::size_t i = 0; i < machine.states.size(); ++i) {
        for (const auto& tr : machine.states[i].transitions)
            edge(static_cast<int>(i), tr);
        for (const auto& tr : machine.any_transitions)
            edge(static_cast<int>(i), tr);
    }
    slice.states = terminals;
    std::deque<int> queue(terminals.begin(), terminals.end());
    while (!queue.empty()) {
        int state = queue.front(); queue.pop_front();
        for (int predecessor : predecessors[static_cast<std::size_t>(state)])
            if (slice.states.insert(predecessor).second)
                queue.push_back(predecessor);
    }
    const auto collect = [&](const std::vector<Transition>& transitions) {
        for (const auto& tr : transitions)
            for (const auto& condition : tr.conditions)
                slice.parameters.insert(condition.parameter);
    };
    collect(machine.any_transitions);
    for (int state : slice.states)
        collect(machine.states[static_cast<std::size_t>(state)].transitions);

    // Include transitive writer inputs and owning layers. A writer in another
    // layer is a dependency, not a constant default or a proven local replay.
    bool changed = true;
    while (changed) {
        changed = false;
        const auto current = slice.parameters;
        for (const auto& parameter : current) {
            // Copy reads must remain in the slice even though the old writer
            // census intentionally treats every non-Set operation as unsafe.
            const auto sources = usage.read_sources.find(parameter);
            if (sources != usage.read_sources.end())
                for (const auto& source : sources->second)
                    changed |= slice.parameters.insert(source).second;
            const auto owners = usage.all_writer_machines.find(parameter);
            if (owners == usage.all_writer_machines.end()) continue;
            for (const auto& owner : owners->second) {
                slice.dependencies.insert(owner);
                if (owner != std::make_pair(controller.path_id, machine_index))
                    slice.competing_writers = true;
            }
        }
    }
    return slice;
}

// Predicate partition representatives for an unbound local guard. Assign once
// and retain the witness throughout the path, so x>t and x<t cannot both be
// assumed on successive edges. Assumed values NEVER authorize a rewrite.
std::vector<double> SemanticGuardDomain(const Machine& machine,
    const std::string& parameter) {
    std::set<double> boundaries{0.0, 0.5, 1.0};
    const auto collect = [&](const std::vector<Transition>& transitions) {
        for (const auto& tr : transitions)
            for (const auto& c : tr.conditions) {
                if (c.parameter != parameter || !std::isfinite(c.threshold)) continue;
                boundaries.insert(c.threshold);
                if (c.mode == 6 || c.mode == 7) {
                    boundaries.insert(c.threshold - 1e-5);
                    boundaries.insert(c.threshold + 1e-5);
                }
            }
    };
    collect(machine.any_transitions);
    for (const auto& state : machine.states) collect(state.transitions);
    std::set<double> values = boundaries;
    for (double value : boundaries) {
        const double before = std::nextafter(value, -INFINITY);
        const double after = std::nextafter(value, INFINITY);
        if (std::isfinite(before)) values.insert(before);
        if (std::isfinite(after)) values.insert(after);
    }
    // Equivalent predicate signatures need only one witness for Set-only
    // machines. Keep every numeric representative if arithmetic consumes it.
    bool arithmetic = false;
    for (const auto& state : machine.states)
        for (const auto& write : state.writes)
            if ((write.name == parameter || write.source == parameter) &&
                write.type != 0) arithmetic = true;
    if (arithmetic) return {values.begin(), values.end()};
    std::set<std::string> seen;
    std::vector<double> representatives;
    for (double value : values) {
        std::string key;
        const auto append = [&](const std::vector<Transition>& transitions) {
            for (const auto& tr : transitions)
                for (const auto& c : tr.conditions)
                    if (c.parameter == parameter) {
                        auto result = ConditionMatches(c, {{parameter, value}});
                        key += !result ? '?' : (*result ? '1' : '0');
                    }
        };
        append(machine.any_transitions);
        for (const auto& state : machine.states) append(state.transitions);
        if (seen.insert(key).second) representatives.push_back(value);
    }
    return representatives;
}

struct SemanticExecution {
    SemanticRuntimeNode node;
    std::set<int> touched;
};

// Deliberately small arithmetic subset. SDK-synced values are clipped and
// mixed-type Copy has conversion semantics; neither is guessed here. Only
// internal Int -> Int and exact float-representable integer Add are evaluated.
// These witnesses remain MANUAL until cross-layer runtime validation exists.
bool ApplySemanticIntegerWrite(const Snapshot& snapshot, const Controller& controller,
    const ParameterWrite& write, std::map<std::string,double>& values) {
    if (write.type != 1 && write.type != 3) return false;
    if (!write.operation_flags.count("local_only")) return false;
    if (snapshot.expression_parameters.count(write.name)) return false;
    const auto target = controller.parameter_defaults.find(write.name);
    if (target == controller.parameter_defaults.end() || target->second.type != "int") return false;
    const auto exact_int = [](double value) {
        return std::isfinite(value) && value == std::trunc(value) && std::abs(value) <= 16777216.0;
    };
    double result = 0;
    if (write.type == 1) {
        const auto old = values.find(write.name);
        if (old == values.end() || !exact_int(old->second) || !exact_int(write.value)) return false;
        result = old->second + write.value;
    } else {
        const auto convert = write.operation_flags.find("convert_range");
        if (convert == write.operation_flags.end() || convert->second) return false;
        const auto source_type = controller.parameter_defaults.find(write.source);
        const auto source = values.find(write.source);
        if (source_type == controller.parameter_defaults.end() || source_type->second.type != "int" ||
            source == values.end() || !exact_int(source->second)) return false;
        result = source->second;
    }
    if (!exact_int(result)) return false;
    values[write.name] = result;
    return true;
}

std::vector<SemanticExecution> NormalizeSemanticBranches(const Snapshot& snapshot,
    const Controller& controller, const Machine& machine,
    const SemanticInputSpec& input, SemanticRuntimeNode initial,
    const std::set<int>& terminals, const SemanticSlice& slice,
    SemanticIrResult& diagnostics) {
    struct Pending {
        SemanticExecution run;
        std::set<std::string> seen;
        int steps = 0;
    };
    std::vector<SemanticExecution> stable;
    std::deque<Pending> queue;
    queue.push_back({{std::move(initial), {}}, {}, 0});
    std::size_t expanded = 0;
    while (!queue.empty()) {
        if (++expanded > 512) { ++diagnostics.budget_exhausted_count; break; }
        Pending item = std::move(queue.front()); queue.pop_front();
        auto& node = item.run.node;
        if (node.state < 0 || node.state >= static_cast<int>(machine.states.size()))
            continue;
        if (!slice.states.count(node.state)) continue;
        if (++item.steps > 128) { ++diagnostics.budget_exhausted_count; continue; }
        const auto& state = machine.states[static_cast<std::size_t>(node.state)];
        bool unsupported_write = false;
        if (node.entry_pending) {
            for (const auto& write : state.writes) {
                if (!slice.parameters.count(write.name)) continue;
                if (write.type == 0) node.values[write.name] = write.value;
                else if (ApplySemanticIntegerWrite(snapshot, controller, write, node.values)) {
                    node.deterministic = false; // arithmetic candidates never acquire a safe plan here
                }
                else {
                    // Non-Set semantics may include conversion/clamping not
                    // present in schema 1. Do not silently keep the old value.
                    node.values.erase(write.name);
                    node.deterministic = false;
                    ++diagnostics.unsupported_semantics_count;
                    unsupported_write = true;
                }
            }
            for (const auto& write : state.animation_writes)
                if (slice.parameters.count(write.name)) {
                    node.values.erase(write.name);
                    node.deterministic = false;
                    ++diagnostics.unsupported_semantics_count;
                    unsupported_write = true;
                }
            node.entry_pending = false;
            if (terminals.count(node.state)) item.run.touched.insert(node.state);
        }
        if (unsupported_write) continue;
        std::ostringstream signature;
        signature << node.state << '|' << node.deterministic;
        for (const auto& [name, value] : node.values)
            signature << '|' << name.size() << ':' << name << '=' << SemanticExactBits(value);
        if (!item.seen.insert(signature.str()).second) continue;

        // A missing value is expanded before first-eligible arbitration. The
        // false branch therefore naturally reaches the later serialized edge.
        std::string missing;
        bool unsupported_condition = false;
        const auto inspect = [&](const std::vector<Transition>& transitions) {
            for (const auto& tr : transitions) {
                if (SemanticTransitionEnabled(tr, node.values).has_value()) continue;
                for (const auto& c : tr.conditions) {
                    if (c.mode != 1 && c.mode != 2 && c.mode != 3 &&
                        c.mode != 4 && c.mode != 6 && c.mode != 7)
                        unsupported_condition = true;
                    if (!node.values.count(c.parameter) && missing.empty()) missing = c.parameter;
                }
            }
        };
        inspect(machine.any_transitions); inspect(state.transitions);
        if (!missing.empty()) {
            const auto domain = SemanticGuardDomain(machine, missing);
            if (domain.size() > 96) { ++diagnostics.budget_exhausted_count; continue; }
            for (double value : domain) {
                Pending fork = item;
                fork.run.node.values[missing] = value;
                fork.run.node.deterministic = false;
                queue.push_back(std::move(fork));
            }
            continue;
        }
        if (unsupported_condition) {
            ++diagnostics.unsupported_semantics_count;
            continue;
        }
        std::size_t order = 0; bool any = false, known = true;
        const auto* tr = SelectSemanticTransition(machine, node, false, order, any, known);
        if (!tr) { stable.push_back(std::move(item.run)); continue; }
        if (!known) { ++diagnostics.unsupported_semantics_count; continue; }
        if (std::abs(tr->duration) > 1e-9 || tr->interruption_source != 0) {
            node.deterministic = false;
            ++diagnostics.unsupported_semantics_count;
        }
        AppendSemanticTransitionShape(node.trace, machine, node.state, *tr,
            order, any, false, input.parameter);
        node.state = tr->destination; node.entry_pending = true;
        queue.push_back(std::move(item));
    }
    return stable;
}

// Independent concrete interpreter over the ORIGINAL unsliced machine.
// Does not use NormalizeSemanticBranches, the search queue or its visited set.
// It verifies a fixed action witness only; unknown/unsupported paths stay manual.
bool ReplaySemanticWitness(const Snapshot& snapshot, const Controller& controller,
    const Machine& machine, const SemanticInputSpec& input,
    const std::vector<std::pair<int,int>>& actions, int terminal) {
    auto values = SemanticInitialValues(snapshot, controller);
    values[input.parameter] = input.released_value;
    int current = machine.default_state;
    bool entry = true;
    const auto choose = [&](bool timed, bool& valid) -> const Transition* {
        const auto scan = [&](const std::vector<Transition>& transitions) -> const Transition* {
            for (const auto& tr : transitions) {
                if (tr.has_exit_time != timed) continue;
                bool pass = true;
                for (const auto& c : tr.conditions) {
                    auto value = values.find(c.parameter);
                    if (value == values.end()) { valid = false; return nullptr; }
                    const double v = value->second;
                    bool match = false;
                    switch (c.mode) {
                    case 1: match = v > 0.5; break;
                    case 2: match = v <= 0.5; break;
                    case 3: match = v > c.threshold; break;
                    case 4: match = v < c.threshold; break;
                    case 6: match = std::abs(v-c.threshold) <= 1e-5; break;
                    case 7: match = std::abs(v-c.threshold) > 1e-5; break;
                    default: valid = false; return nullptr;
                    }
                    pass &= match;
                }
                if (pass) {
                    // A blend can be interrupted according to source/destination
                    // normalized time and ordered interruption rules.  Until
                    // those clip clocks are present in the graph, it is a
                    // possible witness, never an exact runtime proof.
                    if (std::abs(tr.duration) > 1e-9 ||
                        tr.interruption_source != 0)
                        valid = false;
                    return &tr;
                }
            }
            return nullptr;
        };
        auto* tr = scan(machine.any_transitions);
        return tr || !valid ? tr : scan(machine.states[static_cast<std::size_t>(current)].transitions);
    };
    const auto settle = [&]() {
        for (int frame = 0; frame < 128; ++frame) {
            if (current < 0 || current >= static_cast<int>(machine.states.size())) return false;
            const auto& state = machine.states[static_cast<std::size_t>(current)];
            if (entry) {
                for (const auto& write : state.writes) {
                    if (write.type == 0) values[write.name] = write.value;
                    else if (!ApplySemanticIntegerWrite(snapshot, controller,
                                 write, values))
                        return false;
                }
                entry = false;
            }
            bool valid = true;
            auto* tr = choose(false, valid);
            if (!valid) return false;
            if (!tr) return true;
            current = tr->destination; entry = true;
        }
        return false;
    };
    if (!settle()) return false;
    for (const auto& [kind, value] : actions) {
        if (kind == 2) {
            bool valid = true; auto* tr = choose(true, valid);
            if (!valid || !tr) return false;
            current = tr->destination; entry = true;
        } else values[input.parameter] = kind == 0 ? value : input.released_value;
        if (!settle()) return false;
    }
    return current == terminal;
}
