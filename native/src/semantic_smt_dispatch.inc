#if defined(VRC_ENABLE_LOCAL_SMT)
// Model conversion is the semantic boundary, not just JSON reshaping. Keep
// every state and ordered rejection edge; reject any omitted runtime feature.
std::optional<SemanticIrCandidate> SolveLocalSmtSlice(const Snapshot& snapshot,
    const SemanticUsage& usage, const Controller& controller, std::size_t machine_index,
    const Machine& machine, const SemanticInputSpec& input,
    const std::vector<std::pair<int,int>>& terminals, SemanticIrResult& diagnostics) {
    bool arithmetic = false;
    for (const auto& state : machine.states)
        for (const auto& w : state.writes) arithmetic |= w.type == 1 || w.type == 3;
    if (!arithmetic) { ++diagnostics.smt_skipped_no_arithmetic; return std::nullopt; }
    const auto reject = [&](const char* reason = "unsupported_model") -> std::optional<SemanticIrCandidate> {
        ++diagnostics.smt_unsupported_count;
        ++diagnostics.smt_rejection_reasons[reason];
        return std::nullopt;
    };
    if (machine.states.size() > 128) return reject("machine_size");
    if (!machine.any_transitions.empty()) return reject("any_state");
    if (input.released_value != 0.0 || input.input_kind != "menu") return reject("input_kind_or_release");
    const auto exact = [](double v) {
        return std::isfinite(v) && v == std::trunc(v) && std::abs(v) <= 16777216.0;
    };
    std::set<std::string> parameters{input.parameter};
    for (const auto& state : machine.states) {
        if (!state.animation_writes.empty()) return reject("animation_feedback");
        for (const auto& w : state.writes) {
            if (w.type != 0 && w.type != 1 && w.type != 3) return reject("write_kind");
            if (w.name == input.parameter || !exact(w.value)) return reject("input_writer_or_noninteger");
            parameters.insert(w.name);
            if (w.type == 3) parameters.insert(w.source);
        }
        for (const auto& edge : state.transitions) {
            if (edge.has_exit_time || edge.duration != 0.0) return reject("timing_or_blend");
            for (const auto& c : edge.conditions) {
                if (!exact(c.threshold)) return reject("noninteger_condition");
                parameters.insert(c.parameter);
            }
        }
    }
    if (parameters.size() > 32) return reject("parameter_budget");
    smt_experiment::Model model;
    std::map<std::string,int> ids;
    std::map<std::string,std::string> types;
    for (const auto& parameter : parameters) {
        const auto* def = EffectiveRuntimeDefault(snapshot, controller, parameter);
        if (!def || !exact(def->value) || (def->type != "int" && def->type != "bool")) return reject("parameter_type_or_default");
        if (def->type == "bool" && def->value != 0 && def->value != 1) return reject();
        if (snapshot.contact_input_parameters.count(parameter) || snapshot.dynamic_contact_parameters.count(parameter) ||
            snapshot.forced_contact_parameters.count(parameter)) return reject("contact_input");
        const auto owners = usage.all_writer_machines.find(parameter);
        if (owners != usage.all_writer_machines.end())
            for (const auto& owner : owners->second)
                if (owner != std::make_pair(controller.path_id, machine_index)) return reject("foreign_writer");
        if (parameter != input.parameter) {
            for (const auto& menu : snapshot.menus) for (const auto& control : menu.controls)
                if (control.parameter == parameter ||
                    std::find(control.sub_parameters.begin(), control.sub_parameters.end(), parameter) != control.sub_parameters.end()) return reject();
        }
        ids[parameter] = static_cast<int>(model.defaults.size());
        types[parameter] = def->type;
        model.defaults.push_back(static_cast<int>(def->value));
    }
    if (types[input.parameter] != "int") return reject();
    model.input = ids.at(input.parameter); model.initial = machine.default_state;
    for (const auto& [raw, visible] : input.raw_to_visible) {
        if (raw == 0 || visible < 0 || visible > 9) return reject();
        model.alphabet.push_back(raw);
    }
    for (const auto& state : machine.states) {
        smt_experiment::State converted;
        for (const auto& w : state.writes) {
            smt_experiment::Write write{ids.at(w.name), w.type, static_cast<int>(w.value)};
            if (types[w.name] == "bool" && (w.type != 0 || (w.value != 0 && w.value != 1))) return reject();
            if (w.type != 0) {
                if (!w.operation_flags.count("local_only")) return reject("missing_operation_context");
                if (snapshot.expression_parameters.count(w.name)) return reject("expression_arithmetic_clamping");
                write.context_known = true;
            }
            if (w.type == 3) {
                const auto conversion = w.operation_flags.find("convert_range");
                if (conversion == w.operation_flags.end()) return reject("missing_copy_context");
                if (conversion->second || types[w.source] != types[w.name]) return reject("copy_range_or_type_conversion");
                write.source = ids.at(w.source);
            }
            converted.writes.push_back(write);
        }
        for (const auto& edge : state.transitions) {
            smt_experiment::Edge converted_edge{edge.destination, {}};
            for (const auto& c : edge.conditions) {
                if ((c.mode == 1 || c.mode == 2) && types[c.parameter] != "bool") return reject();
                converted_edge.conditions.push_back({ids.at(c.parameter), c.mode, static_cast<int>(c.threshold)});
            }
            converted.edges.push_back(std::move(converted_edge));
        }
        model.states.push_back(std::move(converted));
    }
    for (const auto& [terminal, score] : terminals) {
        if (score < 85 || terminal < 0 || terminal >= static_cast<int>(machine.states.size()) ||
            !SemanticStrictTerminalEffectProof(snapshot, usage, controller, machine_index,
                machine.states[static_cast<std::size_t>(terminal)])) continue;
        if (diagnostics.smt_attempt_count >= 2) { ++diagnostics.budget_exhausted_count; break; }
        ++diagnostics.smt_attempt_count;
        model.terminal = terminal;
        const auto result = smt_experiment::Solve(model, 64, 500);
        if (result.status == "solver_unknown" || result.status == "solver_error") {
            ++diagnostics.smt_unknown_count; ++diagnostics.budget_exhausted_count; continue;
        }
        if (result.status == "bound_exhausted") { ++diagnostics.budget_exhausted_count; continue; }
        if (result.status != "candidate_replayed") { ++diagnostics.smt_unsupported_count; continue; }
        if (result.presses.size() < 2 || result.presses.size() > 32) continue;
        SemanticIrCandidate candidate;
        candidate.controller = controller.name; candidate.controller_path_id = controller.path_id;
        candidate.machine_index = machine_index; candidate.terminal_state = terminal;
        candidate.parameter = input.parameter; candidate.menu = input.menu;
        candidate.input_kind = input.input_kind; candidate.raw_values = result.presses;
        std::ostringstream password, raw, shape;
        for (int value : result.presses) {
            const int visible = input.raw_to_visible.at(value);
            candidate.visible_values.push_back(visible); password << visible;
            if (raw.tellp() > 0) raw << ',';
            raw << value;
        }
        shape << model.states.size() << ':' << model.defaults.size() << ':' << model.alphabet.size();
        candidate.password = password.str(); candidate.raw = raw.str();
        candidate.family = "local_smt_integer_" + SemanticHashText(shape.str());
        candidate.effect_score = score; candidate.replay_verified = true;
        candidate.strict_terminal = false; // no automatic rewrite from this experimental semantics
        candidate.terminal_stable_shape = true;
        ++diagnostics.smt_candidate_count; ++diagnostics.replayed_path_count;
        return candidate;
    }
    return std::nullopt;
}
#endif
