// Recover a paired write plan when input reachability remains a reference.
// Never changes a reference into a verified password and never uses names.
bool AppendStableGuardedPairPlans(const Snapshot& snapshot, const RuleProfile& rules,
    const MenuMaps& menus, std::vector<Candidate>& candidates,
    json::Value::Array& plans) {
    const std::string method = "native_guarded_numeric_dependency_terminal";
    if (candidates.empty() || snapshot.analysis_depth == "fast" || !DetectorEnabled(rules, detector_parameter_driver) ||
        !SafePlanMethodAllowed(rules, method)) return false;
    struct Proposal {
        const Controller* controller;
        std::size_t producer_candidate, effect_candidate;
        std::size_t producer_machine, effect_machine;
        int producer_state, effect_state;
    };
    std::vector<Proposal> proposals;
    for (const auto& controller : snapshot.controllers) {
        if (!snapshot.active_fx_controller_ids.count(controller.path_id)) continue;
        const bool needs_pair = std::any_of(candidates.begin(), candidates.end(), [&](const Candidate& candidate) {
            if (candidate.controller_path_id != controller.path_id || candidate.machine_index >= controller.machines.size() ||
                candidate.unlock_state < 0 || candidate.analysis_origin != "reverse" ||
                candidate.unlock_method != "native_press_release_semantic_terminal" || !menus.count(candidate.parameter)) return false;
            return std::none_of(plans.begin(), plans.end(), [&](const json::Value& plan) {
                const auto* id = plan.find("path_id"); const auto* machine = plan.find("machine_index");
                return id && id->is_string() && id->string() == controller.path_id && machine && machine->is_number() &&
                    machine->number() == candidate.machine_index;
            });
        });
        if (!needs_pair) continue;
        for (std::size_t mi = 0; mi < controller.machines.size(); ++mi) {
            for (const auto& path : EnumerateGuardedNumericPaths(snapshot, controller, controller.machines[mi])) {
                if (!HasNumericEffectTerminal(snapshot, controller, controller.machines[mi], path.terminal_state)) continue;
                std::set<std::string> passwords;
                const auto pages = menus.find(path.parameter);
                if (pages == menus.end()) continue;
                for (const auto& page : pages->second) {
                    std::map<int, int> raw_to_visible;
                    bool ambiguous = false;
                    for (const auto& entry : page.second) {
                        const auto added = raw_to_visible.emplace(entry.second.raw_value, entry.first);
                        if (!added.second && added.first->second != entry.first) ambiguous = true;
                    }
                    std::string password;
                    for (int raw : path.raw_values) {
                        const auto found = raw_to_visible.find(raw);
                        if (found == raw_to_visible.end() || found->second < 0 || found->second > 9) { ambiguous = true; break; }
                        password += static_cast<char>('0' + found->second);
                    }
                    if (!ambiguous && !password.empty()) passwords.insert(password);
                }
                if (passwords.size() != 1) continue;
                std::vector<std::size_t> effects, producers;
                for (std::size_t ci = 0; ci < candidates.size(); ++ci) {
                    const auto& candidate = candidates[ci];
                    if (candidate.controller_path_id != controller.path_id) continue;
                    if (candidate.machine_index == mi && candidate.parameter == path.parameter &&
                        candidate.password == *passwords.begin() &&
                        (candidate.unlock_state < 0 || candidate.unlock_state == path.terminal_state)) effects.push_back(ci);
                    if (candidate.machine_index == mi || candidate.machine_index >= controller.machines.size() ||
                        candidate.unlock_state < 0 || candidate.analysis_origin != "reverse" ||
                        candidate.unlock_method != "native_press_release_semantic_terminal" ||
                        !menus.count(candidate.parameter)) continue;
                    if (ProveGuardedPairTerminalWrites(snapshot, controller, candidate.machine_index,
                            candidate.unlock_state, mi, path.terminal_state, path.gate_parameter, path.gate_mode).accepted)
                        producers.push_back(ci);
                }
                if (effects.size() != 1 || producers.size() != 1) continue;
                const auto& producer = candidates[producers.front()];
                if (controller.machines[producer.machine_index].default_state == producer.unlock_state ||
                    controller.machines[mi].default_state == path.terminal_state) continue;
                proposals.push_back({&controller, producers.front(), effects.front(),
                    producer.machine_index, mi, producer.unlock_state, path.terminal_state});
            }
        }
    }
    bool added = false;
    for (const auto& proposal : proposals) {
        const auto& controller = *proposal.controller;
        const auto collisions = std::count_if(proposals.begin(), proposals.end(), [&](const Proposal& other) {
            return other.controller->path_id == controller.path_id &&
                (other.producer_machine == proposal.producer_machine || other.effect_machine == proposal.effect_machine ||
                 other.effect_machine == proposal.producer_machine || other.producer_machine == proposal.effect_machine);
        });
        if (collisions != 1) continue;
        bool occupied = false;
        for (const auto& plan : plans) {
            const auto* id = plan.find("path_id"); const auto* machine = plan.find("machine_index");
            if (id && id->is_string() && id->string() == controller.path_id && machine && machine->is_number() &&
                (machine->number() == proposal.producer_machine || machine->number() == proposal.effect_machine)) occupied = true;
        }
        if (occupied) continue;
        const auto make_plan = [&](std::size_t machine, int state, const char* family) {
            json::Value::Object row;
            row["path_id"] = controller.path_id;
            row["machine_index"] = static_cast<std::int64_t>(machine);
            row["before"] = controller.machines[machine].default_state;
            row["unlock_state"] = state;
            row["unlock_state_name"] = controller.machines[machine].states[state].name;
            row["method"] = method; row["proof_family"] = family;
            return row;
        };
        auto producer_plan = make_plan(proposal.producer_machine, proposal.producer_state, "guarded_numeric_gate_producer_v1");
        auto effect_plan = make_plan(proposal.effect_machine, proposal.effect_state, "guarded_numeric_effect_terminal_v1");
        json::Value::Object dependency;
        dependency["path_id"] = controller.path_id;
        dependency["machine_index"] = static_cast<std::int64_t>(proposal.producer_machine);
        dependency["unlock_state"] = proposal.producer_state;
        effect_plan["depends_on"] = std::move(dependency);
        plans.push_back(std::move(producer_plan)); plans.push_back(std::move(effect_plan));
        for (const auto& item : {std::make_pair(proposal.producer_candidate, proposal.producer_state),
                                std::make_pair(proposal.effect_candidate, proposal.effect_state)}) {
            auto& candidate = candidates[item.first];
            candidate.analysis_origin = "reverse";
            candidate.confidence = u8"参考";
            candidate.runtime_status = "runtime_possible";
            candidate.guide_allowed = false;
            candidate.unlock_state = item.second;
            candidate.unlock_method = method;
            candidate.menu_mapped = true;
            candidate.note += u8" | 成对稳定解锁终点已验证；输入前置仍为参考";
        }
        added = true;
    }
    return added;
}
