// May-dependency graph, NOT a runtime proof or a lock detector. Parameter
// equality connects reads/writes; names are never matched against keywords.
// Physical Contact/Shader evaluation requires metadata not present here.
json::Value BuildCausalTrace(const Snapshot& snapshot) {
    constexpr std::size_t max_nodes = 100000;
    constexpr std::size_t max_edges = 400000;
    std::map<std::string, std::size_t> ids;
    std::vector<std::vector<std::size_t>> parents;
    std::vector<std::string> kinds;
    std::vector<std::string> keys;
    std::vector<std::size_t> effects;
    std::map<std::uint32_t, std::vector<std::size_t>> activation_effects;
    std::map<std::size_t, const AnimationWrite*> effect_bindings;
    std::size_t edges = 0;
    bool truncated = false;
    const auto node = [&](const std::string& key, const std::string& kind) {
        auto found = ids.find(key);
        if (found != ids.end()) return found->second;
        if (ids.size() >= max_nodes) { truncated = true; return max_nodes; }
        const auto id = ids.size();
        ids.emplace(key, id); parents.emplace_back(); kinds.push_back(kind); keys.push_back(key);
        return id;
    };
    const auto link = [&](std::size_t from, std::size_t to) {
        if (from == max_nodes || to == max_nodes) return;
        if (edges >= max_edges) { truncated = true; return; }
        parents[to].push_back(from); ++edges;
    };
    const auto parameter = [&](const std::string& name) {
        return node("p:" + name, "parameter");
    };
    // Controller position prevents accidental identity collision when malformed
    // or old snapshots contain duplicate/empty path IDs. All controllers are
    // retained as possible dependencies: active_fx alone excludes Base/Action.
    for (std::size_t ci = 0; ci < snapshot.controllers.size(); ++ci) {
        const auto& controller = snapshot.controllers[ci];
        for (std::size_t mi = 0; mi < controller.machines.size(); ++mi) {
            if (truncated) break;
            const auto& machine = controller.machines[mi];
            const auto prefix = "s:" + std::to_string(ci) + ":" + std::to_string(mi) + ":";
            const auto state_id = [&](int si) {
                return node(prefix + std::to_string(si), "state");
            };
            const auto transitions = [&](int source, const std::vector<Transition>& ts) {
                for (std::size_t ti = 0; ti < ts.size() && !truncated; ++ti) {
                    const auto& tr = ts[ti];
                    if (tr.destination < 0 || tr.destination >= static_cast<int>(machine.states.size())) continue;
                    const auto tn = node(prefix + "edge:" + std::to_string(source) + ":" + std::to_string(ti), "transition");
                    if (source >= 0) link(state_id(source), tn);
                    for (const auto& c : tr.conditions)
                        if (!c.parameter.empty()) link(parameter(c.parameter), tn);
                    link(tn, state_id(tr.destination));
                }
            };
            transitions(-1, machine.any_transitions);
            for (std::size_t si = 0; si < machine.states.size() && !truncated; ++si) {
                const auto sn = state_id(static_cast<int>(si));
                const auto& state = machine.states[si];
                std::map<int, std::vector<std::size_t>> clip_effects;
                transitions(static_cast<int>(si), state.transitions);
                for (std::size_t wi = 0; wi < state.writes.size() && !truncated; ++wi) {
                    const auto& w = state.writes[wi];
                    if (w.name.empty()) continue;
                    const auto wn = node(prefix + std::to_string(si) + ":write:" + std::to_string(wi), "driver_write");
                    link(sn, wn);
                    if (!w.source.empty()) link(parameter(w.source), wn);
                    link(wn, parameter(w.name));
                }
                for (std::size_t ai = 0; ai < state.animation_writes.size() && !truncated; ++ai) {
                    const auto an = node(prefix + std::to_string(si) + ":animation:" + std::to_string(ai), "animation_effect");
                    link(sn, an);
                    if (an != max_nodes) effects.push_back(an);
                    const auto& write = state.animation_writes[ai];
                    if (an != max_nodes && write.clip_index >= 0)
                        clip_effects[write.clip_index].push_back(an);
                    if (an != max_nodes) effect_bindings[an] = &write;
                    if (an != max_nodes && (write.name == "m_Enabled" || write.name == "m_IsActive"))
                        activation_effects[write.path_hash].push_back(an);
                }
                for (const auto& read : state.blend_parameter_reads) {
                    if (read.parameter.empty() || read.clip_id < 0) continue;
                    const auto found = clip_effects.find(read.clip_id);
                    if (found == clip_effects.end()) continue;
                    for (const auto effect : found->second)
                        link(parameter(read.parameter), effect);
                }
            }
        }
    }
    for (const auto& p : snapshot.contact_input_parameters) {
        if (truncated) break;
        link(node("contact:" + p, "contact_input_unresolved"), parameter(p));
    }
    // A suffix hash is a MAY binding, never a unique component binding. Keep
    // all aliases/collisions as unresolved rather than choosing first-wins.
    std::size_t binding_edges = 0;
    std::size_t exact_sender_edges = 0;
    for (std::size_t bi = 0; bi < snapshot.contact_binding_candidates.size() && !truncated; ++bi) {
        const auto& binding = snapshot.contact_binding_candidates[bi];
        const auto sender = node("sender_candidate:" + std::to_string(bi), "sender_binding_unresolved");
        link(sender, node("contact:" + binding.parameter, "contact_input_unresolved"));
        for (const auto hash : binding.path_hashes) {
            const auto found = activation_effects.find(hash);
            if (found == activation_effects.end()) continue;
            for (const auto effect : found->second) {
                if (truncated) break;
                const auto& write = *effect_bindings.at(effect);
                if (!write.binding_status.empty()) {
                    // If exact resolution was attempted, a failed or different
                    // target must not fall back to a suffix match.
                    if (write.binding_status != "unique_serialized_target" ||
                        write.target_type != 114 || write.target_id != binding.sender)
                        continue;
                    ++exact_sender_edges;
                }
                link(effect, sender); ++binding_edges;
            }
            if (truncated) break;
        }
    }
    // Only reachable menus count as menu inputs. Empty roots do not imply all.
    std::set<std::string> reached = snapshot.active_root_menu_ids;
    std::map<std::string, std::vector<const Menu*>> menu_index;
    for (const auto& menu : snapshot.menus) menu_index[menu.id].push_back(&menu);
    std::deque<std::string> menu_queue(reached.begin(), reached.end());
    while (!menu_queue.empty() && !truncated) {
        const auto id = menu_queue.front(); menu_queue.pop_front();
        const auto found = menu_index.find(id);
        if (found == menu_index.end()) continue;
        for (const auto* menu : found->second)
            for (const auto& control : menu->controls)
                if (!control.submenu.empty() && reached.insert(control.submenu).second)
                    menu_queue.push_back(control.submenu);
    }
    for (std::size_t mi = 0; mi < snapshot.menus.size() && !truncated; ++mi) {
        const auto& menu = snapshot.menus[mi];
        if (!reached.count(menu.id)) continue;
        for (std::size_t xi = 0; xi < menu.controls.size() && !truncated; ++xi) {
            const auto& control = menu.controls[xi];
            const auto mn = node("menu:" + std::to_string(mi) + ":" + std::to_string(xi), "menu_input");
            if (!control.parameter.empty()) link(mn, parameter(control.parameter));
            for (const auto& p : control.sub_parameters) if (!p.empty()) link(mn, parameter(p));
        }
    }
    std::vector<bool> visited(parents.size(), false);
    std::vector<std::size_t> successor(parents.size(), max_nodes);
    std::deque<std::size_t> pending;
    for (auto effect : effects) { visited[effect] = true; pending.push_back(effect); }
    while (!pending.empty()) {
        const auto id = pending.front(); pending.pop_front();
        for (auto predecessor : parents[id]) if (!visited[predecessor]) {
            visited[predecessor] = true; successor[predecessor] = id; pending.push_back(predecessor);
        }
    }
    json::Value::Array paths;
    bool paths_truncated = false;
    for (std::size_t i = 0; i < visited.size(); ++i) {
        if (!visited[i] || (kinds[i] != "menu_input" && kinds[i] != "contact_input_unresolved")) continue;
        if (paths.size() >= 16) { paths_truncated = true; continue; }
        json::Value::Array steps;
        auto current = i;
        while (current != max_nodes && steps.size() < 128) {
            json::Value::Object step;
            step["kind"] = kinds[current]; step["identity"] = keys[current];
            steps.push_back(step); current = successor[current];
        }
        json::Value::Object path;
        path["steps"] = steps;
        path["complete"] = current == max_nodes;
        path["runtime_verified"] = false;
        paths.push_back(path);
    }
    json::Value::Object counts;
    std::map<std::string, std::int64_t> tally;
    for (std::size_t i = 0; i < visited.size(); ++i) if (visited[i]) ++tally[kinds[i]];
    for (const auto& [kind, count] : tally) counts[kind] = count;
    json::Value::Object result;
    result["schema"] = 1;
    result["mode"] = "conservative_effect_dependency_slice";
    result["runtime_verified"] = false;
    result["automatic_unlock_eligible"] = false;
    result["complete"] = !truncated;
    result["node_count"] = static_cast<std::int64_t>(parents.size());
    result["edge_count"] = static_cast<std::int64_t>(edges);
    result["contact_animation_candidate_edges"] = static_cast<std::int64_t>(binding_edges);
    result["exact_serialized_sender_edges"] = static_cast<std::int64_t>(exact_sender_edges);
    result["effect_slice_counts"] = counts;
    result["example_dependency_paths"] = paths;
    result["example_paths_truncated"] = paths_truncated;
    result["scope"] = "all_serialized_controllers_activity_unproven";
    result["limitations"] = "may_dependencies_only;no_transition_feasibility;no_physical_or_shader_replay";
    return result;
}
