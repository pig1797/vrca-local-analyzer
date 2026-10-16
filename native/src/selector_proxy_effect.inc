// Read-only selector/animation proxy witnesses. No candidate promotion or plans.
namespace selector_proxy_detail {
using Values = std::map<std::string, double>;
using Controls = std::map<std::string, std::string>;

Controls ReachableControls(const Snapshot& snapshot) {
    std::map<std::string, const Menu*> menus;
    for (const auto& m : snapshot.menus) menus[m.id] = &m;
    std::deque<std::pair<std::string,std::string>> todo;
    for (const auto& id : snapshot.active_root_menu_ids) todo.push_back({id,u8"主菜单"});
    std::set<std::string> visited, duplicate;
    Controls controls;
    while (!todo.empty() && visited.size() < 512) {
        const auto [id,path] = todo.front(); todo.pop_front();
        if (!menus.count(id) || !visited.insert(id).second) continue;
        for (const auto& c : menus.at(id)->controls) {
            std::string label; bool tag=false;
            for (unsigned char ch : c.name) {
                if (ch=='<') {tag=true;continue;}
                if (tag) {if(ch=='>')tag=false;continue;}
                if(ch>=32 && ch!='|')label+=static_cast<char>(ch);
            }
            if(label.empty() || label.size()>120) continue;
            const auto next=path+" > "+label;
            if(c.type==103 && !c.submenu.empty()) todo.push_back({c.submenu,next});
            if(c.type==102 && c.value==1 && !c.parameter.empty()) {
                if(!controls.emplace(c.parameter,next).second)duplicate.insert(c.parameter);
            }
        }
    }
    for(const auto& p:duplicate)controls.erase(p);
    return controls;
}

bool Guard(const json::Value& edge, const Values& values, bool& valid) {
    const auto& cs=Array(edge,"conditions");
    if(Integer(edge,"raw_condition_count",-1)!=static_cast<int>(cs.size()))valid=false;
    bool pass=true;
    for(const auto& c:cs) {
        const auto it=values.find(String(c,"parameter"));
        const auto* threshold=c.find("threshold");
        if(it==values.end() || !threshold || !threshold->is_number() ||
            !std::isfinite(threshold->number())) {valid=false;continue;}
        const double v=it->second, t=threshold->number();
        switch(Integer(c,"mode")) {
        case 1:pass &= v!=0;break;case 2:pass &= v==0;break;
        case 3:pass &= v>t;break;case 4:pass &= v<t;break;
        case 6:pass &= v==t;break;case 7:pass &= v!=t;break;
        default:valid=false;
        }
    }
    return pass && valid;
}

bool Shape(const json::Value& m) {
    const auto& sels=Array(m,"selector_states"); const auto& states=Array(m,"states");
    if(sels.size()!=2 || states.size()<2 || states.size()>16 ||
        Number(m,"default_weight",-1)!=1 || Integer(m,"default_state",-1)!=0 ||
        !Array(m,"any_transitions").empty() || !Boolean(sels[0],"is_entry") ||
        Boolean(sels[1],"is_entry")) return false;
    const auto& loop=Array(sels[1],"transitions");
    if(loop.size()!=1 || Integer(loop[0],"selector_destination",-1)!=0 ||
        !Array(loop[0],"conditions").empty())return false;
    const auto& entry=Array(sels[0],"transitions");
    if(entry.size()<2 || entry.size()>16 || !Array(entry.back(),"conditions").empty() ||
        Integer(entry.back(),"destination",-1)!=0)return false;
    for(const auto& e:entry) {
        const int d=Integer(e,"destination",-1);
        if(d<0 || d>=static_cast<int>(states.size()) || e.find("selector_destination"))return false;
    }
    for(const auto& s:states) {
        if(!Boolean(s,"single_clip_motion") || !Boolean(s,"write_defaults") ||
            !Array(s,"parameter_writes").empty() || !Array(s,"runtime_behaviours").empty() ||
            !Array(s,"blend_parameter_reads").empty())return false;
        for(const auto& e:Array(s,"transitions"))
            if(Integer(e,"selector_destination",-1)!=1 || Boolean(e,"has_exit_time") ||
                Number(e,"duration",-1)!=0 || Integer(e,"interruption_source",-1)!=0)return false;
    }
    return true;
}

std::set<std::string> Reads(const json::Value& m) {
    std::set<std::string> result;
    auto edges=[&](const json::Value& owner) {
        for(const auto& e:Array(owner,"transitions"))for(const auto& c:Array(e,"conditions"))
            result.insert(String(c,"parameter"));
    };
    for(const auto& s:Array(m,"states"))edges(s);
    for(const auto& s:Array(m,"selector_states"))edges(s);
    return result;
}

// Convergence from every serialized state, not just the entry selector.
int StableState(const json::Value& m, const Values& values, std::size_t& budget) {
    const auto& states=Array(m,"states");
    const auto& entry=Array(Array(m,"selector_states")[0],"transitions");
    bool valid=true;int selected=-1;
    const auto guard=[&](const json::Value& edge) {
        if(!budget){valid=false;return false;}--budget;
        return Guard(edge,values,valid);
    };
    for(const auto& e:entry)if(guard(e)){selected=Integer(e,"destination",-1);break;}
    if(!valid || selected<0)return -1;
    for(std::size_t initial=0;initial<states.size();++initial) {
        int current=static_cast<int>(initial);bool stable=false;
        for(std::size_t step=0;step<=states.size();++step) {
            bool fired=false;
            for(const auto& e:Array(states[current],"transitions"))
                if(guard(e)){fired=true;break;}
            if(!valid)return -1;
            if(!fired) {stable=current==selected;break;}
            if(current==selected)return -1; // perpetual self re-entry is not stability
            current=selected;
        }
        if(!stable)return -1;
    }
    return selected;
}

std::map<std::string,std::set<std::size_t>> SelectDeep(const Snapshot& snapshot,
    const json::Value& graph) {
    std::map<std::string,std::set<std::size_t>> result;
    const auto controls=ReachableControls(snapshot);
    for(const auto& c:Array(graph,"controllers")) {
        const auto id=String(c,"path_id");
        if(!snapshot.active_fx_controller_ids.count(id))continue;
        const auto& machines=Array(c,"machines");
        bool producer=false;
        for(std::size_t i=0;i<machines.size();++i) {
            const auto& m=machines[i];if(!Shape(m))continue;
            const auto reads=Reads(m);
            if(reads.size()>=4 && reads.size()<=12 &&
                std::all_of(reads.begin(),reads.end(),[&](const auto& p){return controls.count(p);})) {
                result[id].insert(i);producer=true;
            }
        }
        if(!producer)continue;
        for(std::size_t i=0;i<machines.size();++i) {
            const auto& m=machines[i];if(!Shape(m) || Array(m,"states").size()!=2)continue;
            const auto reads=Reads(m);
            if(reads.size()>=2 && reads.size()<=8 &&
                std::none_of(reads.begin(),reads.end(),[&](const auto& p){return controls.count(p);}))
                result[id].insert(i);
        }
        if(result[id].size()>128)result.erase(id);
    }
    return result;
}

json::Value::Array Find(const Snapshot& snapshot,const json::Value& graph) {
    json::Value::Array result;
    if(snapshot.controller_fail || snapshot.analysis_depth=="fast")return result;
    const auto controls=ReachableControls(snapshot);
    const auto selected=SelectDeep(snapshot,graph);
    std::size_t budget=8000000; // whole-report deterministic work ceiling
    for(const auto& c:Array(graph,"controllers")) {
        const auto id=String(c,"path_id");if(!selected.count(id))continue;
        const auto& machines=Array(c,"machines");
        std::set<int> covered;
        for(const auto& i:Array(c,"deep_scan_machine_indices"))if(i.is_number())covered.insert(static_cast<int>(i.number()));
        Values defaults;
        for(const auto& d:Array(c,"parameter_defaults"))
            if(String(d,"type")=="float" || String(d,"type")=="bool")
                defaults[String(d,"name")]=Number(d,"default");
        struct Producer {std::size_t index;std::set<std::string> inputs;std::vector<double> values;};
        std::map<std::string,Producer> producers;std::set<std::string> ambiguous;
        for(auto mi:selected.at(id)) {
            if(!covered.count(static_cast<int>(mi)))continue;
            const auto& m=machines[mi];const auto inputs=Reads(m);
            if(inputs.size()<4 || inputs.size()>12 ||
                !std::all_of(inputs.begin(),inputs.end(),[&](const auto& p){return controls.count(p) && !snapshot.contact_input_parameters.count(p);}))continue;
            std::string proxy;std::vector<double> values;bool good=true,on=false,off=false;
            for(std::size_t si=0;si<Array(m,"states").size();++si) {
                const auto& s=Array(m,"states")[si];const auto& writes=Array(s,"animation_constant_writes");
                if(si==0 && writes.empty()){values.push_back(0);continue;}
                if(writes.size()!=1){good=false;break;}
                const auto& w=writes[0];const auto* binding=w.find("component_binding");
                const auto name=String(w,"name");const auto v=Number(w,"value",-1);
                if(!binding || String(*binding,"status")!="unique_serialized_target" ||
                    Integer(*binding,"type_id")!=95 || Integer(w,"type_id")!=95 ||
                    Number(w,"path_hash",-1)!=0 || Integer(w,"custom_type",-1)!=0 ||
                    name.empty() || (v!=0 && v!=1) || (!proxy.empty() && proxy!=name)) {good=false;break;}
                proxy=name;values.push_back(v);on|=v==1;off|=v==0;
            }
            if(!good || !on || !off || !defaults.count(proxy) || defaults.at(proxy)!=0 || controls.count(proxy))continue;
            if(!producers.emplace(proxy,Producer{mi,inputs,values}).second)ambiguous.insert(proxy);
        }
        for(const auto& p:ambiguous)producers.erase(p);
        std::set<std::string> emitted;
        for(auto mi:selected.at(id)) {
            const auto& m=machines[mi];if(Array(m,"states").size()!=2 || !covered.count(static_cast<int>(mi)))continue;
            const auto gates=Reads(m);
            if(gates.size()<2 || gates.size()>8 ||
                !std::all_of(gates.begin(),gates.end(),[&](const auto& p){return producers.count(p);}))continue;
            const auto& effects=Array(Array(m,"states")[1],"animation_object_writes");
            if(effects.size()!=1 || !Array(Array(m,"states")[0],"animation_object_writes").empty())continue;
            const auto& effect=effects[0];const auto* binding=effect.find("component_binding");
            if(String(effect,"source")!="stable_material_pptr" || !binding ||
                String(*binding,"status")!="unique_serialized_target" ||
                (Integer(*binding,"type_id")!=137 && Integer(*binding,"type_id")!=23) ||
                String(effect,"material_path_id").empty())continue;
            std::set<std::string> input_set;
            for(const auto& p:gates)input_set.insert(producers.at(p).inputs.begin(),producers.at(p).inputs.end());
            if(input_set.size()<4 || input_set.size()>12)continue;
            std::vector<std::string> inputs(input_set.begin(),input_set.end());
            int solution=-1;unsigned count=0;bool valid=true;
            for(unsigned mask=0;mask<(1u<<inputs.size());++mask) {
                Values v;for(std::size_t n=0;n<inputs.size();++n)v[inputs[n]]=(mask>>n)&1;
                for(const auto& p:gates) {
                    const auto& producer=producers.at(p);
                    const int state=StableState(machines[producer.index],v,budget);
                    if(state<0){valid=false;break;}v[p]=producer.values[state];
                }
                if(!valid)break;
                const int end=StableState(m,v,budget);if(end<0){valid=false;break;}
                if(end==1){solution=static_cast<int>(mask);++count;}
            }
            if(!valid || count!=1 || solution<=0)continue;
            json::Value::Array rows;std::string instructions,key;
            std::vector<std::pair<std::string,std::pair<std::string,bool>>> ordered;
            for(std::size_t n=0;n<inputs.size();++n) {
                const bool on=(solution>>n)&1;const auto& p=inputs[n];
                ordered.push_back({controls.at(p),{p,on}});key+=p+(on?"=1;":"=0;");
            }
            if(!emitted.insert(key).second)continue;
            std::sort(ordered.begin(),ordered.end());
            for(const auto& item:ordered) {
                const auto& p=item.second.first;const bool on=item.second.second;
                json::Value::Object row;row["parameter"]=p;row["value"]=on;row["menu_path"]=item.first;rows.push_back(row);
                if(!instructions.empty())instructions+=u8"；";
                instructions+=item.first+(on?u8"：开启":u8"：关闭");
            }
            json::Value::Object row;
            row["family"]="selector_proxy_material_conjunction";row["controller"]=id;
            row["machine"]=static_cast<std::int64_t>(mi);row["inputs"]=rows;
            row["assignments_checked"]=static_cast<std::int64_t>(1u<<inputs.size());
            row["matching_assignments"]=1;row["instructions"]=instructions;
            row["runtime_verified"]=false;row["automatic_unlock_eligible"]=false;
            row["requires_reload_after_failure"]=false;
            row["note"]=u8"这是同时保持的开关组合，不是按顺序输入。可先关闭这些开关，再开启指定项并等待过渡。已核对选择器、参数动画与材质切换链，仍需在游戏中确认外观；此候选不授权自动移除。";
            result.push_back(row);
        }
    }
    return result;
}
} // namespace selector_proxy_detail
