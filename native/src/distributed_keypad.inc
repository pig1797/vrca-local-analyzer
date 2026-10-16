// Conditional, menu-backed cross-layer integer dispatch. No runtime proof,
// no state rewrite, no names/PathIDs/constants identifying a particular lock.
std::vector<Candidate> DetectDistributedIntegerKeypads(const Snapshot& snapshot) {
    std::vector<Candidate> output;
    std::map<std::string, const Menu*> menus;
    for (const auto& menu : snapshot.menus) menus[menu.id] = &menu;
    std::set<std::string> reachable;
    std::deque<std::string> todo(snapshot.active_root_menu_ids.begin(), snapshot.active_root_menu_ids.end());
    while (!todo.empty()) {
        auto id = todo.front(); todo.pop_front();
        if (!reachable.insert(id).second || !menus.count(id)) continue;
        for (const auto& x : menus.at(id)->controls) if (!x.submenu.empty()) todo.push_back(x.submenu);
    }
    struct Key { char digit; std::string parameter; double value; };
    const auto page_keys = [](const Menu& menu) {
        std::vector<Key> keys;
        for (const auto& x : menu.controls) {
            if (!x.submenu.empty()) continue;
            if (x.name.size() != 1 || x.name[0] < '0' || x.name[0] > '9' ||
                (x.type != 101 && x.type != 102) || x.parameter.empty() || x.value != 1.0) return std::vector<Key>{};
            keys.push_back({x.name[0], x.parameter, x.value});
        }
        return keys.size() >= 3 ? keys : std::vector<Key>{};
    };
    std::set<std::string> emitted;
    std::size_t inspected = 0;
    for (const auto& start : snapshot.menus) {
        if (!reachable.count(start.id) || page_keys(start).empty()) continue;
        std::map<char, Key> keys;
        std::set<std::string> pages, parameters;
        todo = {start.id}; bool ambiguous = false;
        while (!todo.empty() && pages.size() <= 10) {
            auto id = todo.front(); todo.pop_front();
            if (!pages.insert(id).second || !menus.count(id)) continue;
            const auto found = page_keys(*menus.at(id));
            if (found.empty()) continue;
            for (const auto& k : found) {
                if (keys.count(k.digit) || !parameters.insert(k.parameter).second) ambiguous = true;
                keys.insert({k.digit, k});
            }
            for (const auto& x : menus.at(id)->controls) if (!x.submenu.empty()) todo.push_back(x.submenu);
        }
        if (ambiguous || keys.size() < 6 || keys.size() > 10 || pages.size() > 10) continue;
        for (const auto& controller : snapshot.controllers) {
            if (!snapshot.active_fx_controller_ids.count(controller.path_id)) continue;
            struct Edge { double from, to; char digit; std::size_t machine; int state; std::vector<std::string> flags; };
            std::map<std::string, std::vector<Edge>> by_memory;
            for (std::size_t mi = 0; mi < controller.machines.size(); ++mi) {
                const auto& machine = controller.machines[mi];
                for (std::size_t ti = 0; ti < machine.any_transitions.size(); ++ti) {
                    if (++inspected > 200000) return output;
                    const auto& tr = machine.any_transitions[ti];
                    if (tr.destination < 0 || tr.destination >= static_cast<int>(machine.states.size()) ||
                        tr.has_exit_time || tr.duration != 0.0) continue;
                    const auto& state = machine.states[static_cast<std::size_t>(tr.destination)];
                    for (const auto& [digit, key] : keys) {
                        if (std::none_of(tr.conditions.begin(), tr.conditions.end(), [&](const auto& x) { return x.parameter == key.parameter; })) continue;
                        for (const auto& guard : tr.conditions) {
                            if (guard.mode != 6 || parameters.count(guard.parameter) || !std::isfinite(guard.threshold)) continue;
                            const auto pd = controller.parameter_defaults.find(guard.parameter);
                            if (pd == controller.parameter_defaults.end() || pd->second.type != "int" ||
                                std::floor(guard.threshold) != guard.threshold) continue;
                            const auto& memory = guard.parameter;
                            std::map<std::string,double> values;
                            for (const auto& [unused,k] : keys) { (void)unused; values[k.parameter] = 0; }
                            values[key.parameter] = key.value; values[memory] = guard.threshold;
                            bool supported = true;
                            for (const auto& condition : tr.conditions) {
                                if (values.count(condition.parameter)) continue;
                                auto d = controller.parameter_defaults.find(condition.parameter);
                                if ((condition.mode != 1 && condition.mode != 2) || d == controller.parameter_defaults.end() || d->second.type != "bool") { supported = false; break; }
                                values[condition.parameter] = d->second.value;
                            }
                            const auto eligible = [&](const Transition& t, bool initial_context = false) -> std::optional<bool> {
                                bool unknown = false;
                                for (const auto& x : t.conditions) {
                                    auto value = ConditionMatches(x,values);
                                    if (!value && initial_context) {
                                        const auto initial = controller.parameter_defaults.find(x.parameter);
                                        if (initial != controller.parameter_defaults.end())
                                            value = ConditionMatches(x, {{x.parameter, initial->second.value}});
                                    }
                                    if (value && !*value) return false;
                                    if (!value) unknown = true;
                                }
                                return unknown ? std::optional<bool>{} : std::optional<bool>{true};
                            };
                            if (!supported || eligible(tr) != std::optional<bool>{true}) continue;
                            for (std::size_t prior = 0; prior < ti; ++prior)
                                if (eligible(machine.any_transitions[prior], true) != std::optional<bool>{false}) supported = false;
                            if (!supported) continue;
                            std::vector<const ParameterWrite*> writes;
                            for (const auto& w : state.writes) if (w.name == memory) writes.push_back(&w);
                            if (writes.size()!=1 || writes[0]->type!=0 || !std::isfinite(writes[0]->value) || std::floor(writes[0]->value)!=writes[0]->value) continue;
                            std::vector<std::string> flags;
                            for (const auto& w : state.writes) {
                                auto d = snapshot.expression_parameter_defaults.find(w.name);
                                if (w.type==0 && w.value==1 && d!=snapshot.expression_parameter_defaults.end() &&
                                    d->second.type=="bool" && d->second.value==0 && !parameters.count(w.name)) flags.push_back(w.name);
                            }
                            std::sort(flags.begin(),flags.end()); flags.erase(std::unique(flags.begin(),flags.end()),flags.end());
                            by_memory[memory].push_back({guard.threshold,writes[0]->value,digit,mi,tr.destination,flags});
                        }
                    }
                }
            }
            for (const auto& [memory, edges] : by_memory) {
                if (edges.size()<4 || edges.size()>256) continue;
                const auto initial = controller.parameter_defaults.at(memory).value;
                for (std::size_t gi=0;gi<edges.size();++gi) {
                    const auto& goal=edges[gi];
                    if (goal.flags.size()<2) continue;
                    bool converges=false;
                    const auto consume=[&](const Transition& tr) {
                        return std::all_of(goal.flags.begin(),goal.flags.end(),[&](const auto& p) {
                            return std::any_of(tr.conditions.begin(),tr.conditions.end(),[&](const auto& x) {return x.parameter==p && x.mode==1;});
                        });
                    };
                    for (const auto& m : controller.machines) {
                        for (const auto& t:m.any_transitions) converges |= consume(t);
                        for (const auto& s:m.states) for (const auto& t:s.transitions) converges |= consume(t);
                    }
                    if (!converges) continue;
                    std::vector<std::vector<std::size_t>> paths;
                    std::vector<std::size_t> path{gi}; std::set<double> visiting;
                    std::size_t expansions=0;
                    std::function<void(double)> reverse=[&](double value) {
                        if (++expansions>2048 || paths.size()>1 || path.size()>16) return;
                        if (value==initial) {paths.push_back(path);return;}
                        if (!visiting.insert(value).second) return;
                        for (std::size_t ei=0;ei<edges.size();++ei) if (edges[ei].to==value && ei!=gi) {
                            path.push_back(ei);reverse(edges[ei].from);path.pop_back();
                        }
                        visiting.erase(value);
                    };
                    reverse(goal.from);
                    if (expansions>2048 || paths.size()!=1 || paths[0].size()<4) continue;
                    std::string word;std::set<std::size_t> owners;
                    for (auto it=paths[0].rbegin();it!=paths[0].rend();++it) {word+=edges[*it].digit;owners.insert(edges[*it].machine);}
                    if (owners.size()<3 || !emitted.insert(controller.path_id+"|"+memory+"|"+word).second) continue;
                    Candidate result(controller.name,memory,word,word,
                        u8"跨层整数进度链参考（初始参数条件）；忙碌/回零和启动门控未完成运行时验证，仅供手动尝试，不用于自动移除。",u8"参考");
                    result.family="distributed_integer_dispatch_v1";
                    result.analysis_origin="reverse";result.menu_mapped=true;result.guide_allowed=false;
                    output.push_back(std::move(result));
                    if (output.size()>=3) return output;
                }
            }
        }
    }
    return output;
}
