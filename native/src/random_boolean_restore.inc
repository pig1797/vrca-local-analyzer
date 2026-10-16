// Effect-driven terminal proof for randomized pairwise Boolean check networks.
// No model names, parameter prefixes, exact state counts or target state IDs.
// Fast remote graphs intentionally contain no client-derived effect selection.
// Select the bounded Boolean network on the server, then leave all binding,
// complementary-effect and competing-writer checks to the strict terminal proof.
bool RandomBooleanRestoreStructure(const Controller& controller,
    const Machine& machine) {
    if (!machine.default_weight_known || machine.default_weight != 1.0 ||
        !machine.any_transitions.empty() || machine.states.size() > 4096 ||
        machine.default_state < 0 ||
        machine.default_state >= static_cast<int>(machine.states.size())) return false;
    std::set<std::string> randoms;
    for (const auto& state : machine.states) for (const auto& write : state.writes) {
        const auto declared = controller.parameter_defaults.find(write.name);
        if (write.type == 2 && declared != controller.parameter_defaults.end() &&
            declared->second.type == "bool") randoms.insert(write.name);
    }
    if (randoms.size() < 8) return false;
    int pair_states = 0;
    for (const auto& state : machine.states) {
        std::map<std::pair<std::string, std::string>, std::set<std::pair<int, int>>> pairs;
        for (const auto& transition : state.transitions) {
            if (transition.conditions.size() != 2) continue;
            auto a = transition.conditions[0], b = transition.conditions[1];
            if (a.parameter == b.parameter || !randoms.count(a.parameter) ||
                !randoms.count(b.parameter) || (a.mode != 1 && a.mode != 2) ||
                (b.mode != 1 && b.mode != 2)) continue;
            if (a.parameter > b.parameter) std::swap(a, b);
            pairs[{a.parameter, b.parameter}].insert({a.mode, b.mode});
        }
        if (std::any_of(pairs.begin(), pairs.end(), [](const auto& pair) {
                return pair.second.size() == 4;
            })) ++pair_states;
    }
    return pair_states >= 8;
}

std::set<std::size_t> SelectRandomBooleanRestoreDeepMachines(
    const Controller& controller) {
    std::set<std::size_t> requested;
    for (std::size_t mi = 0; mi < controller.machines.size(); ++mi) {
        const auto& machine = controller.machines[mi];
        if (RandomBooleanRestoreStructure(controller, machine)) requested.insert(mi);
    }
    return requested;
}

std::optional<int> RandomBooleanRestoreTerminal(const Snapshot& snapshot,
    const Controller& controller, std::size_t mi) {
    const auto& machine = controller.machines[mi];
    if (!RandomBooleanRestoreStructure(controller, machine)) return {};
    std::set<int> reachable;
    std::deque<int> pending{machine.default_state};
    while (!pending.empty()) {
        int current=pending.front();pending.pop_front();
        if (!reachable.insert(current).second) continue;
        for (const auto& t:machine.states[static_cast<std::size_t>(current)].transitions) {
            if (t.destination<0 || t.destination>=static_cast<int>(machine.states.size())) return {};
            pending.push_back(t.destination);
        }
    }
    // Prefer the resolved serialized component identity.  Some generated
    // avatars intentionally omit enough hierarchy metadata that the extractor
    // cannot recover a concrete object, even though the Animator binding still
    // contains Unity's serialized path hash.  For that case, keep a strictly
    // local fallback identity: path hash + component type + built-in property.
    // This is only used to prove exact complementary clips in this machine;
    // it is never exposed as a writable object reference.
    using Binding=std::tuple<std::string,int,std::uint32_t>;
    const auto effects=[](const State& s) {
        std::map<Binding,double> result;
        for (const auto& w:s.animation_writes) {
            // Unity renderers that can carry the protected visual are split
            // between MeshRenderer (23) and SkinnedMeshRenderer (137).
            // Treat both as renderer enable effects; requiring only 137 made
            // the proof disappear as soon as an otherwise identical avatar
            // also restored a regular MeshRenderer.
            if ((w.target_type!=1 && w.target_type!=23 &&
                 w.target_type!=137 && w.target_type!=114) ||
                (w.value!=0 && w.value!=1)) return std::map<Binding,double>{};
            // Attribute hashes are Unity built-in property identities, not
            // model-specific names or lock fingerprints.
            if ((w.target_type==1 && w.attribute_hash!=2086281974u) ||
                ((w.target_type==23 || w.target_type==137 || w.target_type==114) &&
                 w.attribute_hash!=3305885265u)) return std::map<Binding,double>{};
            std::string identity;
            if (w.binding_status=="unique_serialized_target" && !w.target_id.empty()) {
                identity="id:"+w.target_id;
            } else if (w.binding_status=="incomplete_hierarchy" &&
                       w.path_hash!=0) {
                identity="hash:"+std::to_string(w.path_hash);
            } else {
                return std::map<Binding,double>{};
            }
            Binding key{identity,w.target_type,w.attribute_hash};
            if (result.count(key) && result[key]!=w.value) return std::map<Binding,double>{};
            result[key]=w.value;
        }
        return result;
    };
    std::vector<int> accepted;
    for (std::size_t si=0;si<machine.states.size();++si) {
        const auto& s=machine.states[si];
        if (!reachable.count(static_cast<int>(si))) continue;
        if (!s.transitions.empty() || s.writes.size()!=1 || s.writes[0].type!=0 || s.writes[0].value!=1) continue;
        const auto& latch=s.writes[0].name;
        const auto latch_default=controller.parameter_defaults.find(latch);
        if (latch_default==controller.parameter_defaults.end() || latch_default->second.type!="bool") continue;
        auto pass=effects(s);
        if (pass.size()<3 || std::count_if(pass.begin(),pass.end(),[](const auto& p){return std::get<1>(p.first)==137 && p.second==1;})<2) continue;
        bool competing=false;
        for (const auto& c:snapshot.controllers) {
            // Descriptor-resolved active FX controllers are the strongest
            // runtime scope.  Generated packages may retain inactive copies
            // of the same controller; writers in those copies cannot relock
            // the live avatar and must not veto an otherwise closed proof.
            if (!snapshot.active_fx_controller_ids.empty()) {
                if (!snapshot.active_fx_controller_ids.count(c.path_id)) continue;
            } else if (!snapshot.selected_controller_ids.empty() &&
                       !snapshot.selected_controller_ids.count(c.path_id)) {
                continue;
            }
            for (std::size_t i=0;i<c.machines.size();++i) {
                if (&c==&controller && i==mi) continue;
                for (const auto& other:c.machines[i].states) {
                    for (const auto& w:other.writes) if (w.name==latch) competing=true;
                    for (const auto& w:other.animation_writes)
                        if (w.name==latch) competing=true;
                }
            }
        }
        if (competing) continue;
        bool inverse=false;
        for (const auto& fail:machine.states) {
            if (fail.writes.empty() || fail.writes.size()>16 ||
                !std::all_of(fail.writes.begin(),fail.writes.end(),[](const auto& w){return w.type==0 && w.value==0;}) ||
                std::none_of(fail.writes.begin(),fail.writes.end(),[&](const auto& w){return w.name==latch;})) continue;
            auto off=effects(fail);
            if (off.size()!=pass.size()) continue;
            inverse=std::all_of(pass.begin(),pass.end(),[&](const auto& p){return off.count(p.first) && off.at(p.first)==1-p.second;});
            if (inverse) break;
        }
        if (inverse) accepted.push_back(static_cast<int>(si));
    }
    if (accepted.size()!=1 || accepted[0]==machine.default_state) return {};
    return accepted[0];
}
