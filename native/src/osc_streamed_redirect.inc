// Read-only classifier for the streamed-curve redirect/keypad family.
//
// This detector intentionally does not recover a password and never emits a
// state-bypass plan.  It only records a bounded structural feature so the
// caller can distinguish this family from ordinary numeric state machines.
// Any ambiguous or incomplete evidence fails closed.

namespace osc_streamed_redirect_detail {

struct Evidence {
    std::size_t menu_groups = 0;
    std::size_t digit_controls = 0;
    std::size_t controllers = 0;
    std::size_t streamed_states = 0;
    std::size_t redirect_states = 0;
    std::size_t checker_machines = 0;
    bool has_cycle_parameter = false;
    bool has_checker_handoff = false;
};

static bool Near(double left, double right, double epsilon = 1e-6) {
    return std::isfinite(left) && std::isfinite(right) &&
        std::abs(left - right) <= epsilon;
}

static bool IsVisibleDigit(const std::string& text) {
    const auto trimmed = Trim(text);
    return trimmed.size() == 1 && trimmed[0] >= '0' && trimmed[0] <= '9';
}

static bool IsStrictStreamedClip(const StreamedClipEvidence& clip) {
    if (clip.clip_index < 0 || !std::isfinite(clip.start_time) ||
        !std::isfinite(clip.stop_time) || clip.stop_time <= clip.start_time ||
        clip.curves.size() != 1)
        return false;
    const auto& curve = clip.curves.front();
    if (curve.type_id != 95 || curve.keys.size() < 3 ||
        curve.attribute.empty())
        return false;
    bool has_finite_value = false;
    bool has_terminal = false;
    double previous_time = -std::numeric_limits<double>::infinity();
    for (const auto& key : curve.keys) {
        if (!std::isfinite(key.time) || key.time < previous_time)
            return false;
        previous_time = key.time;
        if (!Near(key.coefficients[0], 0.0) ||
            !Near(key.coefficients[1], 0.0) ||
            !Near(key.coefficients[2], 0.0) ||
            !std::isfinite(key.coefficients[3]))
            return false;
        if (key.time >= clip.start_time && key.time <= clip.stop_time)
            has_finite_value = true;
        if (key.time >= clip.stop_time && std::isfinite(key.coefficients[3]))
            has_terminal = true;
    }
    return has_finite_value && has_terminal;
}

static bool HasRedirectTransition(const State& state) {
    // A redirect state must have a real transition.  Timed-only transitions
    // are insufficient because they can be ordinary animation playback.
    for (const auto& transition : state.transitions) {
        if (!transition.conditions.empty() &&
            transition.destination >= 0)
            return true;
    }
    return false;
}

static bool HasCheckerShape(const Machine& machine) {
    if (machine.states.size() < 2) return false;
    bool has_boolean_write = false;
    bool has_terminal = false;
    for (const auto& state : machine.states) {
        for (const auto& write : state.writes) {
            // A normalized bool write is represented by a bounded 0/1 value;
            // accepting only type-0 writes avoids treating arithmetic/Copy
            // drivers as a checker proof.
            if (write.type == 0 &&
                (Near(write.value, 0.0) || Near(write.value, 1.0)))
                has_boolean_write = true;
        }
        if (state.transitions.empty()) has_terminal = true;
    }
    return has_boolean_write && has_terminal;
}

static std::optional<Evidence> Detect(const Snapshot& snapshot) {
    std::map<std::string, std::set<int>> menu_digits;
    std::map<std::string, std::set<int>> menu_raw_values;
    for (const auto& menu : snapshot.menus) {
        for (const auto& control : menu.controls) {
            if (control.type != 102 || control.parameter.empty() ||
                !IsVisibleDigit(control.name) ||
                !std::isfinite(control.value) ||
                std::abs(control.value - std::round(control.value)) > 1e-6)
                continue;
            const auto label = Trim(control.name);
            const int digit = label[0] - '0';
            const int raw = static_cast<int>(std::llround(control.value));
            menu_digits[control.parameter].insert(digit);
            menu_raw_values[control.parameter].insert(raw);
        }
    }
    Evidence evidence;
    for (const auto& [parameter, digits] : menu_digits) {
        const auto raw = menu_raw_values.find(parameter);
        if (digits.size() >= 4 && raw != menu_raw_values.end() &&
            raw->second.size() == digits.size()) {
            ++evidence.menu_groups;
            evidence.digit_controls += digits.size();
        }
    }
    if (evidence.menu_groups == 0) return std::nullopt;

    for (const auto& controller : snapshot.controllers) {
        if (!snapshot.active_fx_controller_ids.empty() &&
            snapshot.active_fx_controller_ids.count(controller.path_id) == 0)
            continue;
        std::size_t streamed_states = 0;
        std::size_t redirect_states = 0;
        bool cycle_parameter = false;
        for (const auto& machine : controller.machines) {
            for (const auto& state : machine.states) {
                bool strict = !state.motion.streamed_clips.empty();
                if (strict) {
                    for (const auto& clip : state.motion.streamed_clips)
                        strict = strict && IsStrictStreamedClip(clip);
                    cycle_parameter = cycle_parameter ||
                        !state.motion.cycle_offset_parameter.empty();
                }
                if (!strict) continue;
                ++streamed_states;
                if (HasRedirectTransition(state)) ++redirect_states;
            }
        }
        if (streamed_states < 4 || redirect_states < 4 || !cycle_parameter)
            continue;
        ++evidence.controllers;
        evidence.streamed_states += streamed_states;
        evidence.redirect_states += redirect_states;
        evidence.has_cycle_parameter = true;
        for (const auto& machine : controller.machines)
            if (HasCheckerShape(machine)) ++evidence.checker_machines;
    }
    if (evidence.controllers == 0 || evidence.checker_machines == 0)
        return std::nullopt;
    evidence.has_checker_handoff = true;
    return evidence;
}

} // namespace osc_streamed_redirect_detail
