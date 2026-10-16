#pragma once

#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace vrc {

enum DetectorRule : std::uint32_t {
    detector_legacy_state = 1u << 0,
    detector_radial = 1u << 1,
    detector_press_release = 1u << 2,
    detector_parameter_driver = 1u << 3,
    detector_button_pulse = 1u << 4,
    detector_parallel_dial = 1u << 5,
    detector_reset_guarded = 1u << 6,
    detector_boolean_toggle = 1u << 7,
    detector_menu_tree = 1u << 8,
    detector_avacrypt = 1u << 9,
    detector_named_unlock = 1u << 10,
    detector_fixed_contact = 1u << 11,
    detector_all = (1u << 12) - 1u,
};

struct YamlParameterRule {
    std::string parameter;
    double unlock_value = 0.0;
};

struct RuleProfile {
    int version = 0;
    std::string policy_version;
    std::string policy_hash;
    std::string digest;
    std::uint32_t capabilities = 0;
    std::uint32_t detector_mask = 0;
    std::uint32_t allowed_condition_modes = 0;
    int max_path_depth = 0;
    int min_password_length = 0;
    int max_password_length = 0;
    int menu_min_numeric_keys = 0;
    int menu_max_digit = 0;
    std::vector<int> zero_raw_values;
    bool require_parameter_match = true;
    bool high_enabled = false;
    bool require_menu_mapping_for_numeric = true;
    bool require_verified_terminal_for_bypass = true;
    int min_high_evidence = 0;
    std::set<std::string> safe_plan_methods;
    std::vector<YamlParameterRule> yaml_rules;
};

struct RuleCapsuleBinding {
    std::string app;
    int build = 0;
    std::string action;
    std::string input_hash;
    std::string device_key_hash;
    std::string vmp_hwid_hash;
    std::string jti;
    std::string policy_hash;
    std::string rule_key_commitment;
};

std::string RuleCapsuleAad(const RuleCapsuleBinding& binding);
std::string RuleProfileFingerprint(const RuleProfile& profile);
bool ParseRulePackV2(const std::string& plaintext,
    const RuleCapsuleBinding& expected,
    const std::vector<unsigned char>& rule_key,
    RuleProfile& profile,
    std::string& reason);
bool DetectorEnabled(const RuleProfile& profile, DetectorRule detector);
bool SafePlanMethodAllowed(const RuleProfile& profile, const std::string& method);
RuleProfile DevelopmentRuleProfile();
#if defined(VRC_SERVER_WORKER)
// Fixed, compile-time policy used only by the private Linux analysis worker.
// It deliberately has no client license, VMProtect or encrypted rule-pack
// dependency because the service boundary authenticates the request before
// spawning this process.
RuleProfile ServerRuleProfile();
#endif
void SecureClearRuleProfile(RuleProfile& profile);

}  // namespace vrc
