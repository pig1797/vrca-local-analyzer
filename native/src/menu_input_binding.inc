// An input-surface diagnostic, never a password or rewrite detector.
// Require a reachable complete 8x8 grid and independently typed Expression
// inputs. Labels and object names do not identify a generator or password.
json::Value::Array DiagnoseUnboundMenuGrids(const Snapshot& snapshot) {
    json::Value::Array diagnostics;
    if (snapshot.controller_fail != 0 || snapshot.active_root_menu_ids.empty() ||
        snapshot.active_fx_controller_ids.empty()) return diagnostics;
    std::map<std::string, const Menu*> menus;
    for (const auto& m : snapshot.menus) menus[m.id] = &m;
    std::set<std::string> reachable;
    std::deque<std::string> todo(snapshot.active_root_menu_ids.begin(),
        snapshot.active_root_menu_ids.end());
    while (!todo.empty()) {
        const auto id = todo.front(); todo.pop_front();
        if (!reachable.insert(id).second) continue;
        const auto it = menus.find(id);
        if (it == menus.end()) continue;
        for (const auto& c : it->second->controls)
            if (c.type == 103 && !c.submenu.empty()) todo.push_back(c.submenu);
    }
    std::set<std::string> declared, readers, copied;
    bool active_table_available = false;
    for (const auto& c : snapshot.controllers) {
        if (snapshot.active_fx_controller_ids.count(c.path_id) &&
            !c.parameter_defaults.empty()) active_table_available = true;
        for (const auto& [name, ignored] : c.parameter_defaults) declared.insert(name);
        for (const auto& m : c.machines) {
            for (const auto& t : m.any_transitions)
                for (const auto& guard : t.conditions) readers.insert(guard.parameter);
            for (const auto& s : m.states) {
                for (const auto& t : s.transitions)
                    for (const auto& guard : t.conditions) readers.insert(guard.parameter);
                for (const auto& w : s.writes)
                    if (w.type == 3 && !w.source.empty()) copied.insert(w.source);
            }
        }
    }
    if (!active_table_available) return diagnostics;
    for (const auto& group : snapshot.menus) {
        if (!reachable.count(group.id) || group.controls.size() != 8) continue;
        std::set<std::string> leaves, parameters;
        bool complete = true;
        for (const auto& branch : group.controls) {
            const auto it = menus.find(branch.submenu);
            if (branch.type != 103 || it == menus.end() ||
                !leaves.insert(branch.submenu).second || it->second->controls.size() != 8) {
                complete = false; break;
            }
            for (const auto& key : it->second->controls) {
                const auto p = snapshot.expression_parameter_defaults.find(key.parameter);
                if (key.type != 102 || key.value != 1.0 || key.parameter.empty() ||
                    p == snapshot.expression_parameter_defaults.end() || p->second.type != "bool" ||
                    !parameters.insert(key.parameter).second) { complete = false; break; }
            }
            if (!complete) break;
        }
        if (!complete || parameters.size() != 64) continue;
        int missing = 0, direct_reads = 0, copy_sources = 0;
        for (const auto& p : parameters) {
            missing += declared.count(p) == 0;
            direct_reads += readers.count(p) != 0;
            copy_sources += copied.count(p) != 0;
        }
        if (missing != 64 || direct_reads != 0) continue;
        json::Value::Object row;
        row["family"] = "parallel_bool_grid_unbound_animator_inputs";
        row["status"] = "input_binding_unresolved";
        row["menu_id"] = group.id;
        row["input_count"] = 64;
        row["missing_controller_declarations"] = missing;
        row["direct_condition_inputs"] = direct_reads;
        row["copy_source_inputs"] = copy_sources;
        row["automatic_unlock_eligible"] = false;
        diagnostics.push_back(row);
    }
    return diagnostics;
}
