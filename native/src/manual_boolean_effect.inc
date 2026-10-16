// Display-only structural witnesses; never used to authorize rewriting.
json::Value::Array FindManualBooleanEffectRoutes(const Snapshot& snapshot) {
    json::Value::Array result;
    if (snapshot.controller_fail || snapshot.active_fx_controller_ids.empty()) return result;
    std::map<std::string, const Menu*> menus;
    auto visible=[](const std::string& text) {
        std::string out; bool tag=false;
        for(unsigned char ch:text) {
            if(ch=='<') {tag=true;continue;}
            if(tag) {if(ch=='>')tag=false;continue;}
            if(ch<32 || ch=='|') {if(!out.empty() && out.back()!=' ')out+=' ';}
            else out+=static_cast<char>(ch);
        }
        while(!out.empty() && out.back()==' ')out.pop_back();
        const auto first=out.find_first_not_of(' ');
        return first==std::string::npos ? std::string() : out.substr(first);
    };
    for (const auto& m : snapshot.menus) menus[m.id] = &m;
    std::map<std::string, std::string> routes;
    std::deque<std::pair<std::string,std::string>> queue;
    for (const auto& id : snapshot.active_root_menu_ids) queue.push_back({id,u8"主菜单"});
    std::map<std::string, std::pair<std::string,const MenuControl*>> controls;
    std::set<std::string> ambiguous;
    while (!queue.empty()) {
        const auto entry=queue.front(); queue.pop_front();
        if (routes.count(entry.first) || !menus.count(entry.first)) continue;
        routes[entry.first]=entry.second;
        const auto& menu=*menus[entry.first];
        for (std::size_t i=0;i<menu.controls.size();++i) {
            const auto& c=menu.controls[i];
            // Names are presentation only, never matching evidence.
            const auto cleaned=visible(c.name);
            const auto label=cleaned.empty() ? u8"第"+std::to_string(i+1)+u8"项" : cleaned;
            const auto path=entry.second+" > "+label;
            if (c.type==103 && !c.submenu.empty()) queue.push_back({c.submenu,path});
            if (c.type==102 && c.value==1.0 && !c.parameter.empty()) {
                if (controls.count(c.parameter)) ambiguous.insert(c.parameter);
                else controls[c.parameter]={path,&c};
            }
        }
    }
    for (const auto& controller : snapshot.controllers) {
        if (!snapshot.active_fx_controller_ids.count(controller.path_id)) continue;
        for (std::size_t mi=0;mi<controller.machines.size();++mi) {
            const auto& m=controller.machines[mi]; const int count=static_cast<int>(m.states.size());
            if (count<3 || count>16 || !m.any_transitions.empty() ||
                !m.default_weight_known || m.default_weight!=1.0 || m.default_state<0 || m.default_state>=count) continue;
            for (int end=0;end<count;++end) {
                if (!m.states[end].transitions.empty() || end==m.default_state) continue;
                std::map<std::string,bool> required; bool valid=true, found=false;
                for (const auto& s:m.states) for (const auto& t:s.transitions) if(t.destination==end) {
                    std::map<std::string,bool> edge;
                    if (t.conditions.size()<2 || t.conditions.size()>8) {valid=false;continue;}
                    for (const auto& cond:t.conditions) {
                        if ((cond.mode!=1 && cond.mode!=2) || !edge.emplace(cond.parameter,cond.mode==1).second) valid=false;
                    }
                    if (found && edge!=required) valid=false;
                    required=edge;found=true;
                }
                if (!valid || !found) continue;
                bool saved=true;
                for (const auto& [p,v]:required) {
                    const auto d=controller.parameter_defaults.find(p);
                    const auto e=snapshot.expression_parameter_defaults.find(p);
                    if (d==controller.parameter_defaults.end() || d->second.type!="bool" ||
                        e==snapshot.expression_parameter_defaults.end() || e->second.type!="bool" ||
                        !controls.count(p) || ambiguous.count(p) || snapshot.contact_input_parameters.count(p)) valid=false;
                    saved &= snapshot.saved_expression_parameters.count(p)!=0;
                }
                if (!valid) continue;
                std::set<int> reachable; std::deque<int> todo{m.default_state};
                while(!todo.empty()) {int s=todo.front();todo.pop_front();if(!reachable.insert(s).second)continue;
                    for(const auto& t:m.states[s].transitions)if(t.destination>=0 && t.destination<count)todo.push_back(t.destination);}
                if(!reachable.count(end))continue;
                // Require one exact object with complementary stable off/on effects.
                std::set<std::string> targets;
                for(const auto& w:m.states[end].manual_activation_writes)
                    if(w.binding_status=="unique_serialized_target" && w.target_type==1 &&
                        w.attribute_hash==2086281974U && w.value==0 && !w.target_id.empty()) targets.insert(w.target_id);
                if(targets.size()!=1)continue;
                const auto target=*targets.begin(); bool on=false, failed_sink=false, fallback=false, conflict=false;
                for(int si=0;si<count;++si) {
                    const auto& s=m.states[si];
                    for(const auto& w:s.manual_activation_writes)if(w.target_id==target && w.attribute_hash==2086281974U) {
                        if(si==end && w.value!=0)conflict=true;
                        if(si!=end && reachable.count(si) && w.value==1) {
                            on=true;failed_sink |= s.transitions.empty();
                        }
                    }
                    for(const auto& t:s.transitions)if(t.conditions.empty() && t.destination>=0 && t.destination<count && t.destination!=end)fallback=true;
                    // Direct state-side writes make the menu assignment unstable.
                    for(const auto& w:s.writes)if(required.count(w.name))conflict=true;
                }
                if(!on || !fallback || conflict || (failed_sink && !saved))continue;
                json::Value::Object row;json::Value::Array inputs;std::string instructions;
                for(const auto& [p,v]:required) {
                    json::Value::Object item;item["parameter"]=p;item["value"]=v;
                    item["menu_path"]=controls[p].first;inputs.push_back(item);
                    if(!instructions.empty())instructions+=u8"；";
                    instructions+=controls[p].first+(v?u8"：开启":u8"：关闭");
                }
                row["family"]="menu_boolean_conjunction_activation_terminal";
                row["controller"]=controller.path_id;row["machine"]=static_cast<std::int64_t>(mi);
                row["terminal_state"]=end;row["target_id"]=target;row["inputs"]=inputs;
                row["requires_reload_after_failure"]=failed_sink;
                row["runtime_verified"]=false;row["automatic_unlock_eligible"]=false;
                row["instructions"]=instructions;
                row["note"]=failed_sink ? u8"同时保持上述开关状态；若已进入失败态，需保留设置并切换头像后切回验证。结构候选，尚未游戏验证，不用于自动移除。" :
                    u8"同时保持上述开关状态并等待动画过渡。结构候选，尚未游戏验证，不用于自动移除。";
                result.push_back(row);
            }
        }
    }
    return result;
}
