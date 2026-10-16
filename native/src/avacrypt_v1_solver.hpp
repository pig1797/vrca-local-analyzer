#pragma once

#include <array>
#include <cstddef>
#include <string>
#include <vector>

namespace vrc {

struct AvaCryptV1Quadratic {
    std::array<std::array<double, 4>, 4> q{};
    std::array<double, 4> p{};
    double r = 0.0;
    std::size_t count = 0;
};

struct AvaCryptV1MeshProbe {
    std::string name;
    std::size_t vertex_count = 0;
    AvaCryptV1Quadratic train;
    AvaCryptV1Quadratic validation;
};

struct AvaCryptV1SolveResult {
    bool accepted = false;
    std::string reason;
    std::array<int, 4> keys{};
    std::array<double, 4> coefficients{};
    int combination_a = 0;
    int combination_b = 0;
    std::size_t equivalent_key_count = 0;
    std::size_t probe_count = 0;
    std::size_t train_equations = 0;
    std::size_t validation_equations = 0;
    double train_score = 1.0;
    double validation_score = 1.0;
    double train_margin = 0.0;
    double validation_margin = 0.0;
};

AvaCryptV1SolveResult SolveAvaCryptV1MeshKeys(
    const std::vector<AvaCryptV1MeshProbe>& probes);

}  // namespace vrc
