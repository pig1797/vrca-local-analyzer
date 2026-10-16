// Structural detector for icon-only split Bool keypads backed by a temporary
// digit bus, an ordered sentinel buffer, an obfuscated comparator and a
// visible binary lock-effect consumer. Included inside analysis.cpp's
// anonymous namespace so it can reuse the normalized graph types/helpers.

struct SplitButtonSentinelEvidence {
    std::size_t comparator_machine = static_cast<std::size_t>(-1);
    std::size_t effect_machine = static_cast<std::size_t>(-1);
    int unlock_state = -1;
    int sentinel = 0;
    std::string digit_bus;
    std::string gate_parameter;
    std::string menu_name;
    std::vector<std::string> slots;
    std::vector<int> digits;
    std::vector<std::string> button_parameters;
};

bool SplitIntegral(double value, int& out) {
    if (!std::isfinite(value)) return false;
    const int rounded = static_cast<int>(std::llround(value));
    if (std::abs(value - rounded) > 1e-5) return false;
    out = rounded;
    return true;
}

bool SplitBoolConditionPolarity(const Condition& condition, bool& positive) {
    std::map<std::string, double> values{{condition.parameter, 0.0}};
    const auto zero = ConditionMatches(condition, values);
    values[condition.parameter] = 1.0;
    const auto one = ConditionMatches(condition, values);
    if (!zero.has_value() || !one.has_value() || *zero == *one) return false;
    positive = *one && !*zero;
    return true;
}

struct SplitReachableButtons {
    std::set<std::string> parameters;
    std::map<std::string, int> depths;
    std::map<std::string, const Menu*> menus;
};

SplitReachableButtons SplitCollectReachableButtons(const Snapshot& snapshot) {
    SplitReachableButtons result;
    std::map<std::string, const Menu*> by_id;
    for (const auto& menu : snapshot.menus) by_id[menu.id] = &menu;
    std::deque<std::pair<std::string, int>> queue;
    if (snapshot.active_root_menu_ids.empty()) {
        for (const auto& menu : snapshot.menus) queue.emplace_back(menu.id, 0);
    } else {
        for (const auto& id : snapshot.active_root_menu_ids)
            queue.emplace_back(id, 0);
    }
    while (!queue.empty()) {
        const auto [id, depth] = queue.front();
        queue.pop_front();
        const auto found = by_id.find(id);
        if (found == by_id.end()) continue;
        const auto old = result.depths.find(id);
        if (old != result.depths.end() && old->second <= depth) continue;
        result.depths[id] = depth;
        result.menus[id] = found->second;
        for (const auto& control : found->second->controls) {
            if (control.type == 101 && control.has_icon &&
                !control.parameter.empty())
                result.parameters.insert(control.parameter);
            if (control.type == 103 && !control.submenu.empty())
                queue.emplace_back(control.submenu, depth + 1);
        }
    }
    return result;
}

struct SplitDigitMap {
    std::string bus;
    std::map<int, std::string> digit_to_button;
};

std::optional<SplitDigitMap> SplitDetectDigitMap(
    const Controller& controller, const SplitReachableButtons& buttons) {
    struct Accumulator {
        bool conflict = false;
        std::map<std::string, int> button_to_digit;
        std::map<int, std::string> digit_to_button;
    };
    std::map<std::string, Accumulator> buses;
    for (const auto& machine : controller.machines) {
        for (const auto& transition : machine.any_transitions) {
            if (transition.destination < 0 || transition.destination >=
                    static_cast<int>(machine.states.size()))
                continue;
            std::string pressed;
            bool ambiguous = false;
            for (const auto& condition : transition.conditions) {
                if (!buttons.parameters.count(condition.parameter)) continue;
                bool positive = false;
                if (!SplitBoolConditionPolarity(condition, positive) || !positive)
                    continue;
                if (!pressed.empty() && pressed != condition.parameter) {
                    ambiguous = true;
                    break;
                }
                pressed = condition.parameter;
            }
            if (ambiguous || pressed.empty()) continue;
            const auto& destination = machine.states[
                static_cast<std::size_t>(transition.destination)];
            for (const auto& write : destination.writes) {
                int digit = 0;
                if (write.type != 0 || !write.source.empty() ||
                    !SplitIntegral(write.value, digit) || digit < 0 || digit > 9)
                    continue;
                auto& bus = buses[write.name];
                const auto old_button = bus.button_to_digit.find(pressed);
                const auto old_digit = bus.digit_to_button.find(digit);
                if ((old_button != bus.button_to_digit.end() &&
                     old_button->second != digit) ||
                    (old_digit != bus.digit_to_button.end() &&
                     old_digit->second != pressed))
                    bus.conflict = true;
                bus.button_to_digit[pressed] = digit;
                bus.digit_to_button[digit] = pressed;
            }
        }
    }
    std::vector<SplitDigitMap> matches;
    for (const auto& [name, bus] : buses) {
        if (bus.conflict || bus.digit_to_button.size() < 8 ||
            bus.digit_to_button.size() != bus.button_to_digit.size())
            continue;
        matches.push_back({name, bus.digit_to_button});
    }
    if (matches.size() != 1) return std::nullopt;
    return matches.front();
}

struct SplitBufferLayout {
    int sentinel = 0;
    std::vector<std::string> slots;
};

std::set<int> SplitSelectorDomain(const Transition& transition,
    const std::string& parameter) {
    std::set<int> domain;
    for (int value = -2; value <= 32; ++value) domain.insert(value);
    bool seen = false;
    for (const auto& condition : transition.conditions) {
        if (condition.parameter != parameter) continue;
        seen = true;
        std::map<std::string, double> values;
        for (auto it = domain.begin(); it != domain.end();) {
            values[parameter] = *it;
            const auto matched = ConditionMatches(condition, values);
            if (!matched.has_value() || !*matched) it = domain.erase(it);
            else ++it;
        }
    }
    return seen ? domain : std::set<int>{};
}

std::optional<std::vector<std::string>> SplitDispatcherOrder(
    const Machine& machine, const std::map<int, std::string>& copy_states,
    const std::set<std::string>& clear_slots) {
    std::vector<std::vector<std::string>> orders;
    for (const auto& dispatcher : machine.states) {
        std::map<std::string,
            std::vector<std::pair<std::set<int>, std::string>>> selectors;
        for (const auto& transition : dispatcher.transitions) {
            const auto copied = copy_states.find(transition.destination);
            if (copied == copy_states.end()) continue;
            std::set<std::string> parameters;
            for (const auto& condition : transition.conditions)
                parameters.insert(condition.parameter);
            for (const auto& parameter : parameters) {
                auto domain = SplitSelectorDomain(transition, parameter);
                if (!domain.empty())
                    selectors[parameter].push_back({std::move(domain), copied->second});
            }
        }
        for (auto& [parameter, entries] : selectors) {
            if (entries.size() != clear_slots.size()) continue;
            bool disjoint = true;
            std::set<std::string> seen;
            for (std::size_t i = 0; i < entries.size(); ++i) {
                seen.insert(entries[i].second);
                for (std::size_t j = i + 1; j < entries.size(); ++j) {
                    std::vector<int> overlap;
                    std::set_intersection(entries[i].first.begin(), entries[i].first.end(),
                        entries[j].first.begin(), entries[j].first.end(),
                        std::back_inserter(overlap));
                    if (!overlap.empty()) disjoint = false;
                }
            }
            if (!disjoint || seen != clear_slots) continue;
            std::sort(entries.begin(), entries.end(),
                [](const auto& left, const auto& right) {
                    return *left.first.begin() < *right.first.begin();
                });
            std::vector<std::string> order;
            for (const auto& entry : entries) order.push_back(entry.second);
            orders.push_back(std::move(order));
        }
    }
    std::sort(orders.begin(), orders.end());
    orders.erase(std::unique(orders.begin(), orders.end()), orders.end());
    if (orders.size() != 1) return std::nullopt;
    return orders.front();
}

std::optional<std::vector<std::string>> SplitSequentialOrder(
    const Machine& machine, const std::map<int, std::string>& copy_states,
    const std::set<std::string>& clear_slots) {
    if (machine.default_state < 0 || machine.default_state >=
            static_cast<int>(machine.states.size()))
        return std::nullopt;
    std::vector<int> distance(machine.states.size(), -1);
    std::deque<int> queue{machine.default_state};
    distance[static_cast<std::size_t>(machine.default_state)] = 0;
    while (!queue.empty()) {
        const int source = queue.front();
        queue.pop_front();
        for (const auto& transition : machine.states[
                 static_cast<std::size_t>(source)].transitions) {
            if (transition.destination < 0 || transition.destination >=
                    static_cast<int>(machine.states.size()))
                continue;
            auto& target = distance[static_cast<std::size_t>(transition.destination)];
            if (target >= 0) continue;
            target = distance[static_cast<std::size_t>(source)] + 1;
            queue.push_back(transition.destination);
        }
    }
    std::vector<std::pair<int, std::string>> ordered;
    std::set<int> used_distances;
    for (const auto& [state, slot] : copy_states) {
        const int d = distance[static_cast<std::size_t>(state)];
        if (d < 0 || !used_distances.insert(d).second) return std::nullopt;
        ordered.push_back({d, slot});
    }
    std::sort(ordered.begin(), ordered.end());
    std::vector<std::string> result;
    for (const auto& item : ordered) result.push_back(item.second);
    std::set<std::string> seen(result.begin(), result.end());
    if (seen != clear_slots) return std::nullopt;
    return result;
}

std::optional<SplitBufferLayout> SplitDetectBuffer(
    const Controller& controller, const std::string& digit_bus) {
    std::vector<SplitBufferLayout> matches;
    for (const auto& machine : controller.machines) {
        for (const auto& state : machine.states) {
            std::map<int, std::set<std::string>> sentinel_groups;
            for (const auto& write : state.writes) {
                int value = 0;
                if (write.type == 0 && write.source.empty() &&
                    write.name != digit_bus &&
                    SplitIntegral(write.value, value) && (value < 0 || value > 9))
                    sentinel_groups[value].insert(write.name);
            }
            for (const auto& [sentinel, clear_slots] : sentinel_groups) {
                if (clear_slots.size() < 4 || clear_slots.size() > 16) continue;
                std::map<int, std::string> copy_states;
                bool ambiguous = false;
                for (std::size_t index = 0; index < machine.states.size(); ++index) {
                    std::set<std::string> copied;
                    for (const auto& write : machine.states[index].writes) {
                        if (write.type == 3 && write.source == digit_bus &&
                            clear_slots.count(write.name)) {
                            const auto conversion = write.operation_flags.find("convert_range");
                            if (conversion != write.operation_flags.end() && conversion->second)
                                ambiguous = true;
                            copied.insert(write.name);
                        }
                    }
                    if (copied.size() > 1) ambiguous = true;
                    else if (copied.size() == 1)
                        copy_states[static_cast<int>(index)] = *copied.begin();
                }
                if (ambiguous || copy_states.size() != clear_slots.size()) continue;
                auto order = SplitDispatcherOrder(machine, copy_states, clear_slots);
                if (!order.has_value())
                    order = SplitSequentialOrder(machine, copy_states, clear_slots);
                if (order.has_value()) matches.push_back({sentinel, *order});
            }
        }
    }
    std::sort(matches.begin(), matches.end(), [](const auto& left, const auto& right) {
        return std::tie(left.sentinel, left.slots) < std::tie(right.sentinel, right.slots);
    });
    matches.erase(std::unique(matches.begin(), matches.end(),
        [](const auto& left, const auto& right) {
            return left.sentinel == right.sentinel && left.slots == right.slots;
        }), matches.end());
    if (matches.size() != 1) return std::nullopt;
    return matches.front();
}

using SplitBox = std::vector<std::set<int>>;
struct SplitRegion {
    int state = -1;
    SplitBox box;
    std::map<std::string, double> globals;
};

std::string SplitRegionKey(const SplitRegion& region) {
    std::ostringstream out;
    out << region.state << '|';
    for (const auto& domain : region.box) {
        for (int value : domain) out << value << ',';
        out << ';';
    }
    out << '|';
    for (const auto& [name, value] : region.globals)
        out << name.size() << ':' << name << '=' << std::setprecision(17)
            << value << ';';
    return out.str();
}

bool SplitTransitionWanted(const Transition& transition,
    const std::map<std::string, std::size_t>& slot_indexes,
    const SplitRegion& region, SplitBox& wanted, bool& unknown) {
    wanted = region.box;
    for (const auto& condition : transition.conditions) {
        const auto slot = slot_indexes.find(condition.parameter);
        if (slot != slot_indexes.end()) {
            auto& domain = wanted[slot->second];
            std::map<std::string, double> value;
            for (auto it = domain.begin(); it != domain.end();) {
                value[condition.parameter] = *it;
                const auto matched = ConditionMatches(condition, value);
                if (!matched.has_value()) {
                    unknown = true;
                    return false;
                }
                if (!*matched) it = domain.erase(it);
                else ++it;
            }
            if (domain.empty()) return false;
            continue;
        }
        const auto found = region.globals.find(condition.parameter);
        if (found == region.globals.end()) {
            unknown = true;
            return false;
        }
        const auto matched = ConditionMatches(condition, region.globals);
        if (!matched.has_value()) {
            unknown = true;
            return false;
        }
        if (!*matched) return false;
    }
    return true;
}

void SplitBoxByWanted(const SplitBox& source, const SplitBox& wanted,
    std::optional<SplitBox>& matched, std::vector<SplitBox>& residual) {
    SplitBox intersection = source;
    for (std::size_t i = 0; i < source.size(); ++i) {
        std::set<int> values;
        std::set_intersection(source[i].begin(), source[i].end(),
            wanted[i].begin(), wanted[i].end(),
            std::inserter(values, values.begin()));
        if (values.empty()) {
            residual.push_back(source);
            matched.reset();
            return;
        }
        intersection[i] = std::move(values);
    }
    matched = intersection;
    SplitBox prefix = source;
    for (std::size_t i = 0; i < source.size(); ++i) {
        std::set<int> outside;
        std::set_difference(prefix[i].begin(), prefix[i].end(),
            wanted[i].begin(), wanted[i].end(),
            std::inserter(outside, outside.begin()));
        if (!outside.empty()) {
            SplitBox branch = prefix;
            branch[i] = std::move(outside);
            residual.push_back(std::move(branch));
        }
        std::set<int> inside;
        std::set_intersection(prefix[i].begin(), prefix[i].end(),
            wanted[i].begin(), wanted[i].end(),
            std::inserter(inside, inside.begin()));
        prefix[i] = std::move(inside);
    }
}

std::optional<std::vector<SplitRegion>> SplitSettleComparator(
    const Machine& machine, const std::vector<std::string>& slots,
    std::vector<SplitRegion> initial) {
    std::map<std::string, std::size_t> slot_indexes;
    for (std::size_t i = 0; i < slots.size(); ++i)
        slot_indexes[slots[i]] = i;
    std::deque<SplitRegion> queue(initial.begin(), initial.end());
    std::vector<SplitRegion> stable;
    std::set<std::string> visited;
    std::size_t expanded = 0;
    while (!queue.empty()) {
        SplitRegion region = std::move(queue.front());
        queue.pop_front();
        if (region.state < 0 || region.state >=
                static_cast<int>(machine.states.size()))
            return std::nullopt;
        const auto& state = machine.states[static_cast<std::size_t>(region.state)];
        for (const auto& write : state.writes)
            if (write.type == 0 && !slot_indexes.count(write.name))
                region.globals[write.name] = write.value;
        // Obfuscators may route several syntactically different edges into the
        // same semantic region.  First-eligible splitting has already removed
        // every shadowed part of those edges, so a repeated region is a proven
        // convergence rather than an ambiguity.
        if (!visited.insert(SplitRegionKey(region)).second) continue;
        if (++expanded > 50000) return std::nullopt;

        std::vector<SplitBox> remaining{region.box};
        for (const auto& transition : state.transitions) {
            std::vector<SplitBox> next_remaining;
            for (const auto& box : remaining) {
                SplitRegion branch = region;
                branch.box = box;
                SplitBox wanted;
                bool unknown = false;
                if (!SplitTransitionWanted(transition, slot_indexes, branch,
                        wanted, unknown)) {
                    if (unknown) return std::nullopt;
                    next_remaining.push_back(box);
                    continue;
                }
                std::optional<SplitBox> matched;
                std::vector<SplitBox> residual;
                SplitBoxByWanted(box, wanted, matched, residual);
                if (matched.has_value()) {
                    SplitRegion child = region;
                    child.state = transition.destination;
                    child.box = std::move(*matched);
                    queue.push_back(std::move(child));
                }
                next_remaining.insert(next_remaining.end(),
                    std::make_move_iterator(residual.begin()),
                    std::make_move_iterator(residual.end()));
            }
            remaining = std::move(next_remaining);
            if (remaining.empty()) break;
        }
        for (auto& box : remaining) {
            SplitRegion settled = region;
            settled.box = std::move(box);
            stable.push_back(std::move(settled));
        }
    }
    return stable;
}

std::string SplitAnimationIdentity(const AnimationWrite& write) {
    std::ostringstream out;
    if (!write.path.empty()) out << "p:" << write.path;
    else out << "h:" << write.path_hash;
    out << "|a:" << (write.attribute_hash
        ? std::to_string(write.attribute_hash) : write.name);
    return out.str();
}

std::optional<int> SplitEffectStateForGate(const Machine& machine,
    const std::string& gate, double gate_value,
    const std::map<std::string, double>& defaults) {
    int state_index = machine.default_state;
    std::set<int> visited;
    for (int hop = 0; hop < 32; ++hop) {
        if (state_index < 0 || state_index >= static_cast<int>(machine.states.size()))
            return std::nullopt;
        if (!visited.insert(state_index).second) return state_index;
        const auto& state = machine.states[static_cast<std::size_t>(state_index)];
        std::map<std::string, double> values = defaults;
        values[gate] = gate_value;
        bool moved = false;
        for (const auto& transition : state.transitions) {
            bool eligible = true;
            for (const auto& condition : transition.conditions) {
                const auto matched = ConditionMatches(condition, values);
                if (!matched.has_value()) return std::nullopt;
                if (!*matched) { eligible = false; break; }
            }
            if (!eligible) continue;
            if (transition.destination == state_index) return state_index;
            state_index = transition.destination;
            moved = true;
            break;
        }
        if (!moved) return state_index;
    }
    return std::nullopt;
}

bool SplitVisibleGateConsumer(const Controller& controller,
    const std::string& gate, int locked_value, int unlocked_value,
    std::size_t& effect_machine) {
    std::map<std::string, double> defaults;
    for (const auto& [name, value] : controller.parameter_defaults)
        defaults[name] = value.value;
    for (std::size_t index = 0; index < controller.machines.size(); ++index) {
        const auto& machine = controller.machines[index];
        const auto locked = SplitEffectStateForGate(machine, gate,
            locked_value, defaults);
        const auto unlocked = SplitEffectStateForGate(machine, gate,
            unlocked_value, defaults);
        if (!locked.has_value() || !unlocked.has_value() || *locked == *unlocked)
            continue;
        const auto binary_writes = [](const State& state) {
            std::map<std::string, int> writes;
            bool invalid = false;
            for (const auto& write : state.animation_writes) {
                if (write.name != "m_IsActive" && write.name != "m_Enabled")
                    continue;
                int value = 0;
                if (!SplitIntegral(write.value, value) || (value != 0 && value != 1)) {
                    invalid = true;
                    break;
                }
                const std::string identity = SplitAnimationIdentity(write);
                const auto old = writes.find(identity);
                if (old != writes.end() && old->second != value) {
                    invalid = true;
                    break;
                }
                writes[identity] = value;
            }
            return std::make_pair(std::move(writes), invalid);
        };
        const auto locked_writes = binary_writes(
            machine.states[static_cast<std::size_t>(*locked)]);
        const auto unlocked_writes = binary_writes(
            machine.states[static_cast<std::size_t>(*unlocked)]);
        if (locked_writes.second || unlocked_writes.second ||
            locked_writes.first.size() < 2 ||
            locked_writes.first.size() != unlocked_writes.first.size())
            continue;
        bool exact = true;
        for (const auto& [identity, value] : locked_writes.first) {
            const auto other = unlocked_writes.first.find(identity);
            if (value != 1 || other == unlocked_writes.first.end() ||
                other->second != 0) {
                exact = false;
                break;
            }
        }
        if (!exact) continue;
        if (effect_machine != static_cast<std::size_t>(-1) &&
            effect_machine != index)
            return false;
        effect_machine = index;
    }
    return effect_machine != static_cast<std::size_t>(-1);
}

bool SplitComparatorShape(const Snapshot& snapshot,
    const Controller& controller, std::size_t machine_index,
    const std::vector<std::string>& slots,
    std::map<std::string, double>& initial_globals) {
    if (machine_index >= controller.machines.size()) return false;
    const auto& machine = controller.machines[machine_index];
    if (machine.default_state < 0 || machine.default_state >=
            static_cast<int>(machine.states.size()) ||
        !machine.any_transitions.empty())
        return false;

    std::set<std::string> slot_names(slots.begin(), slots.end());
    const auto& controller_census = BuildWriterCensus(controller);
    std::set<std::string> internally_written;
    std::set<std::string> referenced_slots;
    std::size_t transition_count = 0;
    // Build the complete write set before classifying any condition.  A gate
    // is commonly first read by the default state and only written by later
    // states; a single interleaved pass would misclassify it as an external
    // guard merely because of serialization order.
    for (const auto& state : machine.states) {
        if (!state.animation_writes.empty()) return false;
        for (const auto& write : state.writes) {
            // The comparison machine is a pure predicate/state-signature
            // machine.  Copy/add/random operations or writes into the input
            // buffer would make a forced terminal unsafe.
            if (write.type != 0 || !write.source.empty() ||
                slot_names.count(write.name))
                return false;
            internally_written.insert(write.name);
        }
    }
    for (const auto& state : machine.states) {
        for (const auto& transition : state.transitions) {
            if (transition.destination < 0 || transition.destination >=
                    static_cast<int>(machine.states.size()) ||
                transition.has_exit_time || std::abs(transition.duration) > 1e-9)
                return false;
            ++transition_count;
            for (const auto& condition : transition.conditions)
                if (slot_names.count(condition.parameter))
                    referenced_slots.insert(condition.parameter);
        }
    }
    if (transition_count == 0 || referenced_slots != slot_names) return false;

    for (const auto& [name, value] : controller.parameter_defaults)
        initial_globals[name] = value.value;

    // A runtime environment guard (for example, a local-instance predicate)
    // is safe to strip from the symbolic comparison only when every edge has
    // the exact same condition and the parameter is not user-controlled or
    // written anywhere.  This is structural and intentionally does not depend
    // on the guard's name.
    std::map<std::string, std::vector<Condition>> external_by_transition;
    std::size_t processed_transitions = 0;
    for (const auto& state : machine.states) {
        for (const auto& transition : state.transitions) {
            std::map<std::string, std::vector<Condition>> on_edge;
            for (const auto& condition : transition.conditions) {
                if (slot_names.count(condition.parameter) ||
                    internally_written.count(condition.parameter))
                    continue;
                on_edge[condition.parameter].push_back(condition);
            }
            for (const auto& [name, conditions] : on_edge)
                if (conditions.size() != 1)
                    return false;

            // Keep one row per serialized transition.  The former code used
            // the already-final total transition count while processing the
            // first edge, which prefixed almost a full machine of placeholders
            // and then overran the row count on the second edge.  Real VRCFury
            // comparators commonly carry the same local-instance predicate on
            // every edge, so that bookkeeping error rejected the whole family
            // before symbolic solving even started.
            for (auto& [name, rows] : external_by_transition) {
                const auto found = on_edge.find(name);
                rows.push_back(found == on_edge.end()
                    ? Condition{-1, {}, 0}
                    : found->second.front());
            }
            for (const auto& [name, conditions] : on_edge) {
                if (external_by_transition.count(name)) continue;
                auto& rows = external_by_transition[name];
                rows.assign(processed_transitions, Condition{-1, {}, 0});
                rows.push_back(conditions.front());
            }
            ++processed_transitions;
        }
    }
    for (const auto& [name, conditions] : external_by_transition) {
        if (conditions.size() != transition_count || conditions.empty() ||
            conditions.front().mode < 0 ||
            snapshot.expression_parameters.count(name) ||
            snapshot.contact_input_parameters.count(name) ||
            snapshot.dynamic_contact_parameters.count(name) ||
            snapshot.forced_contact_parameters.count(name) ||
            controller_census.set_owners.count(name) ||
            controller_census.non_set_names.count(name) ||
            controller_census.animation_names.count(name) ||
            HasActiveOtherControllerWriter(snapshot, controller, name))
            return false;
        const auto& first = conditions.front();
        if (!std::all_of(conditions.begin(), conditions.end(),
                [&](const Condition& condition) {
                    return condition.mode == first.mode &&
                        condition.parameter == first.parameter &&
                        std::abs(condition.threshold - first.threshold) <= 1e-9;
                }))
            return false;
        bool zero = false, one = false;
        std::map<std::string, double> value{{name, 0.0}};
        const auto zero_match = ConditionMatches(first, value);
        value[name] = 1.0;
        const auto one_match = ConditionMatches(first, value);
        if (!zero_match.has_value() || !one_match.has_value() ||
            *zero_match == *one_match)
            return false;
        zero = *zero_match;
        one = *one_match;
        initial_globals[name] = one && !zero ? 1.0 : 0.0;
    }
    return true;
}

std::optional<std::vector<int>> SplitCanonicalSequentialPassword(
    const Machine& machine, const std::vector<std::string>& slots,
    int sentinel, const std::set<int>& alphabet,
    const std::string& gate, int unlocked_value, int unlock_state,
    const std::map<std::string, double>& initial_globals) {
    SplitRegion initial;
    initial.state = machine.default_state;
    initial.globals = initial_globals;
    initial.box.assign(slots.size(), std::set<int>{sentinel});
    auto stable = SplitSettleComparator(machine, slots, {initial});
    if (!stable.has_value() || stable->empty()) return std::nullopt;
    const auto is_unlock = [&](const SplitRegion& region) {
        const auto found = region.globals.find(gate);
        return region.state == unlock_state && found != region.globals.end() &&
            std::abs(found->second - unlocked_value) <= 1e-9;
    };
    if (std::any_of(stable->begin(), stable->end(), is_unlock))
        return std::nullopt;

    std::vector<std::vector<int>> canonical_lengths;
    for (std::size_t index = 0; index < slots.size(); ++index) {
        std::vector<SplitRegion> expanded;
        for (const auto& region : *stable) {
            if (region.box.size() != slots.size() ||
                region.box[index] != std::set<int>{sentinel})
                return std::nullopt;
            SplitRegion next = region;
            next.box[index] = alphabet;
            expanded.push_back(std::move(next));
        }
        stable = SplitSettleComparator(machine, slots, std::move(expanded));
        if (!stable.has_value() || stable->empty()) return std::nullopt;

        std::set<std::vector<int>> exact_successes;
        for (const auto& region : *stable) {
            if (!is_unlock(region)) continue;
            std::vector<int> password;
            bool exact = true;
            for (std::size_t slot = 0; slot < slots.size(); ++slot) {
                if (slot <= index) {
                    if (region.box[slot].size() != 1 ||
                        !alphabet.count(*region.box[slot].begin())) {
                        exact = false;
                        break;
                    }
                    password.push_back(*region.box[slot].begin());
                } else if (region.box[slot] != std::set<int>{sentinel}) {
                    exact = false;
                    break;
                }
            }
            if (exact) exact_successes.insert(std::move(password));
        }
        // A canonical generator branch is the only fully specified success at
        // its length.  Collision shortcuts leave several exact assignments or
        // a wildcard prefix and are therefore never promoted.
        if (exact_successes.size() == 1)
            canonical_lengths.push_back(*exact_successes.begin());
    }
    if (canonical_lengths.size() != 1) return std::nullopt;
    return canonical_lengths.front();
}

bool SplitForcedTerminalStable(const Machine& machine,
    const std::vector<std::string>& slots, int sentinel,
    const std::string& gate, int unlocked_value, int unlock_state,
    const std::map<std::string, double>& initial_globals) {
    SplitRegion forced;
    forced.state = unlock_state;
    forced.globals = initial_globals;
    forced.box.assign(slots.size(), std::set<int>{sentinel});
    const auto stable = SplitSettleComparator(machine, slots, {forced});
    if (!stable.has_value() || stable->size() != 1) return false;
    const auto found = stable->front().globals.find(gate);
    return stable->front().state == unlock_state &&
        found != stable->front().globals.end() &&
        std::abs(found->second - unlocked_value) <= 1e-9;
}

std::optional<SplitButtonSentinelEvidence> DetectSplitButtonSentinelBuffer(
    const Snapshot& snapshot, const Controller& controller) {
    const auto buttons = SplitCollectReachableButtons(snapshot);
    const auto digit_map = SplitDetectDigitMap(controller, buttons);
    if (!digit_map.has_value()) return std::nullopt;
    const auto buffer = SplitDetectBuffer(controller, digit_map->bus);
    if (!buffer.has_value()) return std::nullopt;

    std::set<int> alphabet;
    for (const auto& [digit, ignored] : digit_map->digit_to_button)
        alphabet.insert(digit);
    const auto& census = BuildWriterCensus(controller);
    std::vector<SplitButtonSentinelEvidence> matches;
    for (std::size_t machine_index = 0;
         machine_index < controller.machines.size(); ++machine_index) {
        std::map<std::string, double> initial_globals;
        if (!SplitComparatorShape(snapshot, controller, machine_index,
                buffer->slots, initial_globals))
            continue;
        const auto& machine = controller.machines[machine_index];
        for (const auto& [gate, parameter_default] :
             controller.parameter_defaults) {
            int locked_value = 0;
            if (!SplitIntegral(parameter_default.value, locked_value) ||
                (locked_value != 0 && locked_value != 1))
                continue;
            const int unlocked_value = 1 - locked_value;
            std::set<int> unlock_states;
            bool invalid_writer = false;
            for (std::size_t state_index = 0;
                 state_index < machine.states.size(); ++state_index) {
                std::optional<int> state_value;
                for (const auto& write : machine.states[state_index].writes) {
                    if (write.name != gate) continue;
                    int value = 0;
                    if (write.type != 0 || !write.source.empty() ||
                        !SplitIntegral(write.value, value) ||
                        (value != 0 && value != 1) ||
                        (state_value.has_value() && *state_value != value)) {
                        invalid_writer = true;
                        break;
                    }
                    state_value = value;
                }
                if (state_value.has_value() && *state_value == unlocked_value)
                    unlock_states.insert(static_cast<int>(state_index));
            }
            if (invalid_writer || unlock_states.size() != 1) continue;
            const auto owners = census.set_owners.find(gate);
            if (owners == census.set_owners.end() || owners->second.size() != 1 ||
                !owners->second.count(machine_index) ||
                census.non_set_names.count(gate) ||
                census.animation_names.count(gate) ||
                HasActiveOtherControllerWriter(snapshot, controller, gate))
                continue;
            const int unlock_state = *unlock_states.begin();
            if (unlock_state == machine.default_state) continue;
            std::size_t effect_machine = static_cast<std::size_t>(-1);
            if (!SplitVisibleGateConsumer(controller, gate, locked_value,
                    unlocked_value, effect_machine) ||
                effect_machine == machine_index)
                continue;
            const auto password = SplitCanonicalSequentialPassword(machine,
                buffer->slots, buffer->sentinel, alphabet, gate,
                unlocked_value, unlock_state, initial_globals);
            if (!password.has_value() || password->size() < 2) continue;
            if (!std::all_of(password->begin(), password->end(),
                    [&](int digit) {
                        return digit_map->digit_to_button.count(digit) != 0;
                    }))
                continue;
            if (!SplitForcedTerminalStable(machine, buffer->slots,
                    buffer->sentinel, gate, unlocked_value, unlock_state,
                    initial_globals))
                continue;

            std::string menu_name;
            int best_depth = (std::numeric_limits<int>::max)();
            for (const auto& [menu_id, menu] : buttons.menus) {
                bool contains = false;
                for (const auto& control : menu->controls)
                    if (std::any_of(password->begin(), password->end(),
                            [&](int digit) {
                                return control.parameter ==
                                    digit_map->digit_to_button.at(digit);
                            })) {
                        contains = true;
                        break;
                    }
                if (!contains) continue;
                const int depth = buttons.depths.at(menu_id);
                if (depth < best_depth ||
                    (depth == best_depth && menu->name < menu_name)) {
                    best_depth = depth;
                    menu_name = menu->name;
                }
            }
            SplitButtonSentinelEvidence evidence;
            evidence.comparator_machine = machine_index;
            evidence.effect_machine = effect_machine;
            evidence.unlock_state = unlock_state;
            evidence.sentinel = buffer->sentinel;
            evidence.digit_bus = digit_map->bus;
            evidence.gate_parameter = gate;
            evidence.menu_name = menu_name;
            evidence.slots = buffer->slots;
            evidence.digits = *password;
            for (int digit : *password)
                evidence.button_parameters.push_back(
                    digit_map->digit_to_button.at(digit));
            matches.push_back(std::move(evidence));
        }
    }
    if (matches.size() != 1) return std::nullopt;
    return matches.front();
}
