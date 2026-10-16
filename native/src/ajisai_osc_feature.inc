// Identification only. A serialized score witness never authorizes writeback.
namespace ajisai_osc_detail {
struct Shape {
    std::string controller, score, gate, force_lock;
    std::size_t logic = 0, compute = 0;
    int locked = -1, unlocked = -1;
    std::set<std::string> inputs;
};

bool Active(const Snapshot& s, const Controller& c) {
    return !c.path_id.empty() && s.active_fx_controller_ids.count(c.path_id);
}
bool Plain(const Machine& m, std::size_t count) {
    return m.states.size() == count && !m.has_selector_semantics &&
        m.any_transitions.empty() && m.default_weight_known &&
        std::isfinite(m.default_weight) && m.default_weight == 1 &&
        m.default_state >= 0 && m.default_state < static_cast<int>(count);
}
bool Edge(const Transition& t, int destination) {
    return t.destination == destination && !t.has_exit_time &&
        t.duration == 0 && t.interruption_source == 0;
}
bool Set(const State& s, const std::string& p, double v) {
    return s.writes.size() == 1 && s.writes[0].name == p &&
        s.writes[0].type == 0 && s.writes[0].source.empty() &&
        s.writes[0].value == v;
}
const json::Value* RawController(const json::Value& root, const std::string& id) {
    const json::Value* result = nullptr;
    for (const auto& c : Array(root, "controllers")) {
        if (String(c, "path_id") != id) continue;
        if (result) return nullptr;
        result = &c;
    }
    return result;
}
bool DefaultEntrySelectors(const json::Value& raw, int default_state) {
    const auto& selectors=Array(raw,"selector_states");
    if(selectors.size()!=2 || Integer(selectors[0],"index",-1)!=0 ||
        Integer(selectors[1],"index",-1)!=1 ||
        !Boolean(selectors[0],"is_entry") || Boolean(selectors[1],"is_entry")) return false;
    for(std::size_t i=0;i<2;++i) {
        const auto& edges=Array(selectors[i],"transitions");
        if(edges.size()!=1) return false;
        const auto& e=edges[0];
        if(Integer(e,"raw_condition_count",-1)!=0 || !Array(e,"conditions").empty() ||
            Boolean(e,"has_exit_time") || Number(e,"duration",-1)!=0 ||
            Integer(e,"interruption_source",-1)!=0) return false;
        if(i==0) {
            if(Integer(e,"destination",-1)!=default_state ||
                Field(e,"selector_destination")) return false;
        } else if(Integer(e,"destination",0)!=-1 ||
            Integer(e,"selector_destination",-1)!=0) return false;
    }
    for(const auto& s:Array(raw,"states"))
        for(const auto& e:Array(s,"transitions"))
            if(Field(e,"selector_destination")) return false;
    return true;
}
Snapshot SignatureView(const Snapshot& snapshot, const json::Value& root) {
    // Standard serialized Entry -> default and Exit -> Entry records do not
    // add a conditional selector branch. Normalize only a private read-only
    // signature view; retain the original graph and global analysis semantics.
    Snapshot view=snapshot;
    for(auto& c:view.controllers) {
        if(!Active(view,c)) continue;
        const auto* raw=RawController(root,c.path_id);
        if(!raw) continue;
        const auto& machines=Array(*raw,"machines");
        for(std::size_t i=0;i<c.machines.size() && i<machines.size();++i)
            if(c.machines[i].has_selector_semantics &&
                DefaultEntrySelectors(machines[i],c.machines[i].default_state))
                c.machines[i].has_selector_semantics=false;
    }
    return view;
}
bool LocalFloat(const json::Value& root, const std::string& p) {
    int count = 0;
    for (const auto& item : Array(root, "expression_parameters")) {
        if (String(item, "name") != p) continue;
        if (Integer(item, "value_type", -1) != 1 ||
            Number(item, "default", -1) != 0 ||
            !Field(item, "network_synced") || Boolean(item, "network_synced"))
            return false;
        ++count;
    }
    return count == 1;
}
bool InternalByte(const json::Value& root, const std::string& p) {
    int count = 0;
    for (const auto& item : Array(root, "expression_parameters")) {
        if (String(item, "name") != p) continue;
        if (Integer(item, "value_type", -1) != 0 ||
            Number(item, "default", -1) != 0 ||
            !Field(item, "saved") || Boolean(item, "saved") ||
            !Field(item, "network_synced") || !Boolean(item, "network_synced"))
            return false;
        ++count;
    }
    return count == 1;
}
bool FloatDefault(const Controller& c, const std::string& p, double v) {
    const auto it = c.parameter_defaults.find(p);
    return it != c.parameter_defaults.end() &&
        it->second.type == "float" && it->second.value == v;
}

// Match the randomized eight local byte-input -> weighted AAP score topology.
// Names (including package/state/menu names) are deliberately not a signature.
std::vector<Shape> Shapes(const Snapshot& snapshot, const json::Value& root) {
    std::vector<Shape> result;
    if (snapshot.nonfinite_condition_count != 0) return result;
    for (const auto& c : snapshot.controllers) {
        if (!Active(snapshot, c) || c.machines.size() > 512) continue;
        const auto* raw = RawController(root, c.path_id);
        if (!raw) continue;
        const auto& raw_machines = Array(*raw, "machines");
        for (std::size_t li = 0; li < c.machines.size(); ++li) {
            const auto& logic = c.machines[li];
            if (!Plain(logic, 3) || li >= raw_machines.size()) continue;
            bool complete_conditions = true;
            for (const auto& state : Array(raw_machines[li], "states")) {
                for (const auto& edge : Array(state, "transitions"))
                    if (Integer(edge, "raw_condition_count", -1) !=
                        static_cast<int>(Array(edge,"conditions").size()))
                        complete_conditions = false;
            }
            if (!complete_conditions) continue;
            const auto& idle = logic.states[logic.default_state];
            if (!idle.writes.empty() || idle.transitions.size() != 1) continue;
            const auto& enter = idle.transitions[0];
            const int locked = enter.destination;
            if (locked < 0 || locked >= 3 || locked == logic.default_state ||
                !Edge(enter, locked) || enter.conditions.size() != 1 ||
                enter.conditions[0].parameter != "IsLocal" ||
                enter.conditions[0].mode != 1) continue;
            const auto& from = logic.states[locked];
            if (from.transitions.size() != 1 || from.writes.size() != 1) continue;
            const auto& accept = from.transitions[0];
            const int unlocked = accept.destination;
            if (unlocked < 0 || unlocked >= 3 || unlocked == locked ||
                unlocked == logic.default_state || !Edge(accept, unlocked) ||
                accept.conditions.size() != 3) continue;
            const auto& to = logic.states[unlocked];
            const auto gate = from.writes[0].name;
            if (gate.empty() || !Set(from, gate, 0) || !Set(to, gate, 1) ||
                !FloatDefault(c, gate, 0) || to.transitions.size() != 3) continue;
            Shape shape;
            shape.controller = c.path_id; shape.logic = li;
            shape.gate = gate; shape.locked = locked; shape.unlocked = unlocked;
            double low = 0, high = 0;
            int lows = 0, highs = 0, locks = 0;
            for (const auto& cond : accept.conditions) {
                if (cond.mode == 3) {shape.score = cond.parameter; low = cond.threshold; ++lows;}
                else if (cond.mode == 4) {high = cond.threshold; ++highs;}
                else if (cond.mode == 2) {shape.force_lock = cond.parameter; ++locks;}
            }
            if (lows != 1 || highs != 1 || locks != 1 || shape.score.empty() ||
                shape.force_lock.empty() || !std::isfinite(low) || !std::isfinite(high) ||
                low < 0 || high > 2040.01 || high <= low || high - low > 0.002 ||
                !FloatDefault(c, shape.score, 0)) continue;
            bool score_pair = true;
            for (const auto& cond : accept.conditions)
                if ((cond.mode == 3 || cond.mode == 4) && cond.parameter != shape.score)
                    score_pair = false;
            const auto force = c.parameter_defaults.find(shape.force_lock);
            if (!score_pair || force == c.parameter_defaults.end() ||
                force->second.type != "bool" || force->second.value != 0) continue;
            std::set<int> resets;
            for (const auto& edge : to.transitions) {
                if (!Edge(edge, locked) || edge.conditions.size() != 1) continue;
                const auto& cond = edge.conditions[0];
                if (cond.parameter == shape.score && cond.mode == 4 && cond.threshold == low)
                    resets.insert(4);
                if (cond.parameter == shape.score && cond.mode == 3 && cond.threshold == high)
                    resets.insert(3);
                if (cond.parameter == shape.force_lock && cond.mode == 1) resets.insert(1);
            }
            if (resets != std::set<int>{1,3,4}) continue;
            for (std::size_t ci = 0; ci < c.machines.size() && ci < raw_machines.size(); ++ci) {
                if (!Plain(c.machines[ci], 1) || !c.machines[ci].states[0].transitions.empty()) continue;
                const auto& states = Array(raw_machines[ci], "states");
                if (states.size() != 1) continue;
                const auto& reads = Array(states[0], "blend_parameter_reads");
                if (reads.size() != 24) continue; // eight Direct children, sixteen 1D leaves
                std::map<std::string, std::set<double>> ranges;
                std::set<int> direct_children, input_nodes;
                std::set<std::string> ones;
                bool valid = true;
                for (const auto& read : reads) {
                    const auto p = String(read, "parameter");
                    if (p.empty() || Integer(read,"tree_index",-1) != 0) {valid = false; break;}
                    if (String(read,"blend_type") == "1d") {
                        const auto* value = Field(read,"threshold");
                        if (!value || !value->is_number() || !std::isfinite(value->number()) ||
                            Integer(read,"clip_id",-1) < 0 ||
                            Integer(read,"node_index",-1) < 0 ||
                            Integer(read,"child_node_index",-1) < 0) {valid = false; break;}
                        ranges[p].insert(value->number());
                        input_nodes.insert(Integer(read,"node_index",-1));
                    } else {
                        if (Integer(read,"node_index",-1) != 0 ||
                            !direct_children.insert(Integer(read,"child_node_index",-1)).second)
                            valid = false;
                        ones.insert(p);
                    }
                }
                if (!valid || ranges.size() != 8 || ones.size() != 1 ||
                    !FloatDefault(c, *ones.begin(), 1) || direct_children != input_nodes) continue;
                shape.inputs.clear();
                for (const auto& [p, values] : ranges)
                    if (values == std::set<double>{0,255} && FloatDefault(c,p,0) &&
                        LocalFloat(root,p)) shape.inputs.insert(p);
                if (shape.inputs.size() != 8) continue;
                shape.compute = ci;
                result.push_back(shape);
            }
        }
    }
    return result;
}

std::map<std::string,std::set<std::size_t>> SelectDeep(
    const Snapshot& snapshot, const json::Value& root) {
    const auto view=SignatureView(snapshot,root);
    std::map<std::string,std::set<std::size_t>> result;
    for (const auto& shape : Shapes(view,root)) {
        for (const auto& c : view.controllers) {
            if (c.path_id != shape.controller) continue;
            auto& indices = result[c.path_id];
            indices.insert(shape.logic); indices.insert(shape.compute);
            for (std::size_t mi = 0; mi < c.machines.size(); ++mi) {
                for (const auto& state : c.machines[mi].states) {
                    bool depends = false;
                    for (const auto& edge : state.transitions)
                        for (const auto& cond : edge.conditions)
                            depends |= cond.parameter == shape.gate;
                    for (const auto& read : state.blend_parameter_reads)
                        depends |= read.parameter == shape.gate;
                    // Include the independent four-byte texture-key copier.
                    depends |= state.blend_parameter_reads.size() == 12;
                    if (depends) indices.insert(mi);
                }
            }
            if (indices.size() > 32) result.erase(c.path_id);
        }
    }
    return result;
}

bool Exact(const AnimationWrite& w) {
    return w.binding_status == "unique_serialized_target" && !w.target_id.empty();
}
bool ScoreEvidence(const Controller& c, const json::Value& raw, const Shape& shape) {
    const auto& state = c.machines[shape.compute].states[0];
    if (!state.writes.empty()) return false;
    const auto& reads = Array(Array(Array(raw,"machines")[shape.compute],"states")[0],
                              "blend_parameter_reads");
    for (const auto& p : shape.inputs) {
        int count = 0;
        for (const auto& read : reads) {
            if (String(read,"blend_type") != "1d" || String(read,"parameter") != p) continue;
            const int clip = Integer(read,"clip_id",-1);
            const auto values = std::count_if(state.animation_writes.begin(), state.animation_writes.end(),
                [&](const auto& w) {return w.clip_index == clip && w.name == shape.score &&
                    w.target_type == 95 && w.path_hash == 0 &&
                    (Number(read,"threshold",-1) == 0 ? w.value == 0 :
                        w.value >= 1 && w.value <= 255 && std::floor(w.value) == w.value);});
            if (values != 1) return false;
            ++count;
        }
        if (count != 2) return false;
    }
    return true;
}
bool DisplayEvidence(const Controller& c, const Shape& shape) {
    for (const auto& m : c.machines) {
        if (!Plain(m,2)) continue;
        const auto& locked = m.states[m.default_state];
        const auto& restored = m.states[1-m.default_state];
        if (locked.transitions.size()!=1 || restored.transitions.size()!=1 ||
            !Edge(locked.transitions[0],1-m.default_state) ||
            !Edge(restored.transitions[0],m.default_state)) continue;
        const auto& a=locked.transitions[0].conditions;
        const auto& b=restored.transitions[0].conditions;
        if(a.size()!=1 || b.size()!=1 || a[0].parameter!=shape.gate ||
            b[0].parameter!=shape.gate || a[0].mode!=3 || b[0].mode!=4 ||
            a[0].threshold!=0.5 || b[0].threshold!=0.5) continue;
        for(const auto& w:restored.animation_writes) {
            if (!Exact(w) || w.target_type!=137 || w.value!=100 ||
                (w.name.rfind("blendShape.",0)!=0 &&
                 w.name.rfind("m_BlendShapeWeights.Array.data[",0)!=0)) continue;
            for(const auto& before:locked.animation_writes)
                if(Exact(before) && before.target_id==w.target_id && before.name==w.name &&
                    before.path_hash==w.path_hash && before.value==0) return true;
        }
    }
    return false;
}
bool ShaderEvidence(const Controller& c, const json::Value& raw,
                    const json::Value& root, const Shape& shape) {
    const auto& machines = Array(raw,"machines");
    for(std::size_t mi=0;mi<c.machines.size() && mi<machines.size();++mi) {
        if (!Plain(c.machines[mi],1)) continue;
        const auto& state=c.machines[mi].states[0];
        const auto& states=Array(machines[mi],"states");
        if(states.size()!=1) continue;
        std::map<double,int> clips;
        for(const auto& r:Array(states[0],"blend_parameter_reads"))
            if(String(r,"parameter")==shape.gate && String(r,"blend_type")=="1d" &&
                Integer(r,"clip_id",-1)>=0) clips.emplace(Number(r,"threshold",-1),Integer(r,"clip_id"));
        if(clips.size()!=2 || !clips.count(0) || !clips.count(1)) continue;
        std::map<std::pair<std::string,std::uint32_t>,std::set<int>> channels;
        for(const auto& after:state.animation_writes) {
            const bool is_mask_channel = after.name.size()==15 &&
                after.name.rfind("material._AR_K",0)==0;
            if(after.clip_index!=clips.at(1) || !Exact(after) || after.target_type!=137 ||
                !is_mask_channel ||
                after.name.back()<'0' || after.name.back()>'3' || after.value<0 ||
                after.value>255 || std::floor(after.value)!=after.value) continue;
            int matching=0;
            for(const auto& before:state.animation_writes)
                if(before.clip_index==clips.at(0) && Exact(before) && before.target_id==after.target_id &&
                    before.path_hash==after.path_hash && before.name==after.name && before.value==0) ++matching;
            if(matching==1) channels[{after.target_id,after.path_hash}].insert(after.name.back()-'0');
        }
        for(const auto& [target,indices]:channels) if(indices.size()==4) {
            const bool nonzero = std::any_of(state.animation_writes.begin(),state.animation_writes.end(),
                [&](const auto& w) {return w.clip_index==clips.at(1) && Exact(w) &&
                    w.target_id==target.first && w.path_hash==target.second &&
                    w.name.size()==15 && w.name.rfind("material._AR_K",0)==0 &&
                    w.name.back()>='0' && w.name.back()<='3' && w.value>0;});
            if(nonzero) return true;
        }
    }

    // AjisaiFlow's independent texture-key copier is not driven by the score
    // gate.  It contains four local 0/255 input pairs and writes a complete
    // TK0..TK3 quartet to one exact serialized renderer target. Keep this
    // path separate from the score-gated mask path so a zero-valued _AR_K
    // pair does not hide a valid TK copier, while still requiring exact
    // bindings and all four channels.
    for(std::size_t mi=0;mi<c.machines.size() && mi<machines.size();++mi) {
        if (!Plain(c.machines[mi],1)) continue;
        const auto& state=c.machines[mi].states[0];
        const auto& states=Array(machines[mi],"states");
        if(states.size()!=1 || !state.transitions.empty()) continue;
        struct ByteInput { int low=-1, high=-1, node=-1; };
        std::map<std::string,ByteInput> input_clips;
        std::string direct_parameter;
        std::set<int> direct_children, input_nodes, clip_ids;
        const auto& reads=Array(states[0],"blend_parameter_reads");
        if(reads.size()!=12) continue;
        bool valid=true;
        for(const auto& r:reads) {
            const auto p=String(r,"parameter");
            if(p.empty() || Integer(r,"tree_index",-1)!=0) {valid=false; break;}
            if(String(r,"blend_type")=="1d") {
                const int clip=Integer(r,"clip_id",-1);
                const double threshold=Number(r,"threshold",-1);
                const int node=Integer(r,"node_index",-1);
                const auto def=c.parameter_defaults.find(p);
                if(clip<0 || node<=0 || Integer(r,"child_node_index",-1)<=0 ||
                    (threshold!=0 && threshold!=255) || !InternalByte(root,p) ||
                    def==c.parameter_defaults.end() || def->second.type!="float" ||
                    def->second.value!=0 || !clip_ids.insert(clip).second) {valid=false; break;}
                auto& pair=input_clips[p];
                if(pair.node!=-1 && pair.node!=node) {valid=false; break;}
                pair.node=node; input_nodes.insert(node);
                int& destination=threshold==0 ? pair.low : pair.high;
                if(destination!=-1) {valid=false; break;}
                destination=clip;
            } else {
                if(Integer(r,"node_index",-1)!=0 || Integer(r,"child_node_index",-1)<0) {
                    valid=false; break;
                }
                if(direct_parameter.empty()) direct_parameter=p;
                if(p!=direct_parameter ||
                    !direct_children.insert(Integer(r,"child_node_index",-1)).second) {valid=false; break;}
            }
        }
        if(!valid || input_clips.size()!=4 || direct_children.size()!=4 ||
            input_nodes!=direct_children || !FloatDefault(c,direct_parameter,1)) continue;
        for(const auto& [parameter,clips]:input_clips)
            if(clips.low<0 || clips.high<0) {valid=false; break;}
        if(!valid) continue;
        using Target=std::pair<std::string,std::uint32_t>;
        std::map<Target,std::map<int,std::set<std::string>>> channels;
        for(const auto& after:state.animation_writes) {
            if(!Exact(after) || after.target_type!=137 || after.name.size()!=16 ||
                after.name.rfind("material._AR_TK",0)!=0 || after.name.back()<'0' ||
                after.name.back()>'3' || after.value!=255) continue;
            const int channel=after.name.back()-'0';
            for(const auto& [parameter,clips]:input_clips) {
                if(after.clip_index!=clips.high) continue;
                int matching=0, after_count=0;
                for(const auto& before:state.animation_writes)
                    if(before.clip_index==clips.low && Exact(before) &&
                       before.target_type==137 && before.target_id==after.target_id &&
                       before.path_hash==after.path_hash && before.name==after.name &&
                       before.value==0) ++matching;
                for(const auto& other:state.animation_writes)
                    if(other.clip_index==clips.high && Exact(other) && other.target_type==137 &&
                       other.target_id==after.target_id && other.path_hash==after.path_hash &&
                       other.name==after.name) ++after_count;
                if(matching==1 && after_count==1)
                    channels[{after.target_id,after.path_hash}][channel].insert(parameter);
            }
        }
        for(const auto& [target,indices]:channels) {
            if(indices.size()!=4) continue;
            std::set<std::string> parameters;
            bool complete=true;
            for(const auto& [channel,owners]:indices) {
                if(owners.size()!=1) {complete=false; break;}
                parameters.insert(*owners.begin());
            }
            if(complete && parameters.size()==4) return true;
        }
    }
    return false;
}
bool Detect(const Snapshot& snapshot, const json::Value& root) {
    const auto view=SignatureView(snapshot,root);
    for(const auto& shape:Shapes(view,root))
        for(const auto& c:view.controllers) if(c.path_id==shape.controller) {
            const auto* raw=RawController(root,c.path_id);
            if(raw && ScoreEvidence(c,*raw,shape) && DisplayEvidence(c,shape) &&
                ShaderEvidence(c,*raw,root,shape)) return true;
        }
    return false;
}
} // namespace ajisai_osc_detail
