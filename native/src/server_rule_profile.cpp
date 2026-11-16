#include "rule_profile.hpp"

#include "common.hpp"

#include <algorithm>

namespace vrc {
namespace {

#ifndef VRC_LOCAL_POLICY_BUILD
#define VRC_LOCAL_POLICY_BUILD 43
#endif

#if VRC_LOCAL_POLICY_BUILD >= 46
constexpr char kLocalPolicyHash[] =
    "6e78a8dcd461cd025c9f38716dd4245bcfe6083f765aaee5815009b4bf5142aa";
constexpr char kLocalPolicyDigest[] = "vpf-build46-local-policy-3";
#elif VRC_LOCAL_POLICY_BUILD >= 44
constexpr char kLocalPolicyHash[] =
    "9bbac923519d3d764625fc93f65d642b4297d5b1198cb6accfc4f10e3360437e";
constexpr char kLocalPolicyDigest[] = "vpf-build45-local-policy-2";
#else
constexpr char kLocalPolicyHash[] =
    "f6da0cb028cb409f1521607bca8fc97ed7173844277c372e191f586a389e17c4";
constexpr char kLocalPolicyDigest[] = "vpf-build43-local-policy-2";
#endif

const std::set<std::string>& LocalSafeMethods() {
    static const std::set<std::string> methods = {
        "native_named_unlock",
        "native_named_unlock_semantic_terminal",
        "native_press_release_terminal",
        "native_press_release_semantic_terminal",
        "native_radial_window_terminal",
        "native_parallel_dial_terminal",
        "native_reset_guarded_terminal",
        "native_contact_guarded_semantic_terminal",
        "native_button_pulse_dispatch_terminal",
        "native_boolean_toggle_and_terminal",
        "native_navigation_menu_terminal",
        "native_random_boolean_restore_terminal",
        "native_split_button_sentinel_buffer_terminal",
        "native_compound_restriction_terminal",
        "native_guarded_numeric_dependency_terminal",
        "native_float_range_gate_terminal",
#if VRC_LOCAL_POLICY_BUILD >= 44
        "native_no_reset_sync_latch_terminal",
        "native_fail_stop_dual_saved_latch_terminal",
        "native_semantic_ir_terminal",
        "native_osc_shift_restore_terminal",
        "native_active_root_parameter_maze",
#endif
#if VRC_LOCAL_POLICY_BUILD >= 46
        "native_menu_boolean_guard_substitution",
#endif
    };
    return methods;
}

}  // namespace

bool DetectorEnabled(const RuleProfile& profile, const DetectorRule detector) {
    return (profile.detector_mask & static_cast<std::uint32_t>(detector)) != 0;
}

bool SafePlanMethodAllowed(const RuleProfile& profile,
    const std::string& method) {
    return profile.safe_plan_methods.count(method) != 0;
}

RuleProfile LocalRuleProfile() {
    RuleProfile profile;
    profile.version = 2;
    profile.policy_version = "2";
    profile.policy_hash = kLocalPolicyHash;
    profile.digest = Sha256Hex(std::string(kLocalPolicyDigest), false);
    profile.capabilities = 0x1Fu;
    profile.detector_mask = detector_all;
    profile.allowed_condition_modes = 0xFFFFu;
    profile.max_path_depth = 128;
    profile.min_password_length = 1;
    profile.max_password_length = 128;
    profile.menu_min_numeric_keys = 3;
    profile.menu_max_digit = 9;
    profile.zero_raw_values = {0, 8, 10};
    profile.require_parameter_match = true;
    profile.high_enabled = true;
    profile.require_menu_mapping_for_numeric = false;
    profile.require_verified_terminal_for_bypass = true;
    profile.min_high_evidence = 3;
    profile.safe_plan_methods = LocalSafeMethods();
    return profile;
}

void SecureClearRuleProfile(RuleProfile& profile) {
    const auto clear = [](std::string& value) {
        std::fill(value.begin(), value.end(), '\0');
        value.clear();
    };
    for (auto& rule : profile.yaml_rules) clear(rule.parameter);
    clear(profile.policy_version);
    clear(profile.policy_hash);
    clear(profile.digest);
    profile = RuleProfile{};
}

}  // namespace vrc
