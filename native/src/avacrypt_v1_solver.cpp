#include "avacrypt_v1_solver.hpp"

#include "vmp_bridge.hpp"

#include <algorithm>
#include <cmath>
#include <limits>
#include <map>
#include <tuple>

namespace vrc {
namespace {

using Vec4 = std::array<double, 4>;
using Mat4 = std::array<std::array<double, 4>, 4>;

struct PairChoice {
    int first = 0;
    int second = 0;
    int cost = std::numeric_limits<int>::max();
    std::size_t count = 0;
};

struct RankedCandidate {
    double best = std::numeric_limits<double>::infinity();
    double second = std::numeric_limits<double>::infinity();
    int best_a = 0;
    int best_b = 0;
    Vec4 best_coefficients{};
};

std::vector<int> LegalKeys() {
    std::vector<int> keys;
    for (int value = 4; value <= 100; value += 3) {
        if (value != 76) keys.push_back(value);
    }
    return keys;
}

void AddPair(std::map<int, PairChoice>& choices, int combination,
             int first, int second) {
    auto& choice = choices[combination];
    ++choice.count;
    // Equivalent keys render identically.  Prefer values near the middle of
    // the radial dial, where VRChat's pointer is easier to place accurately.
    const int cost = (first - 52) * (first - 52) +
                     (second - 52) * (second - 52);
    if (cost < choice.cost ||
        (cost == choice.cost && std::tie(first, second) <
                                    std::tie(choice.first, choice.second))) {
        choice.first = first;
        choice.second = second;
        choice.cost = cost;
    }
}

Vec4 Coefficients(int a, int b) {
    // Match the single-precision Unity/HLSL path used by GTAvaCrypt V1.
    const float fa = static_cast<float>(a);
    const float fb = static_cast<float>(b);
    return {
        static_cast<double>(std::sin(2.0f * fa) * std::cos(fb)),
        static_cast<double>(std::sin(3.0f * fb) * std::cos(fa)),
        static_cast<double>(-std::sin(4.0f * fb) * std::cos(fa)),
        static_cast<double>(-std::sin(5.0f * fa) * std::cos(fb)),
    };
}

bool Usable(const AvaCryptV1Quadratic& quadratic) {
    if (quadratic.count == 0 || !std::isfinite(quadratic.r) ||
        quadratic.r <= 1e-18) return false;
    for (std::size_t i = 0; i < 4; ++i) {
        if (!std::isfinite(quadratic.p[i])) return false;
        for (std::size_t j = 0; j < 4; ++j)
            if (!std::isfinite(quadratic.q[i][j])) return false;
    }
    return true;
}

double RawScore(const AvaCryptV1Quadratic& quadratic, const Vec4& c) {
    double score = quadratic.r;
    for (std::size_t i = 0; i < 4; ++i) {
        score -= 2.0 * quadratic.p[i] * c[i];
        for (std::size_t j = 0; j < 4; ++j)
            score += c[i] * quadratic.q[i][j] * c[j];
    }
    // Roundoff can make a mathematically zero residual slightly negative.
    return std::max(0.0, score);
}

double NormalizedScore(const std::vector<AvaCryptV1MeshProbe>& probes,
                       bool validation, const Vec4& c) {
    double score = 0.0;
    std::size_t used = 0;
    for (const auto& probe : probes) {
        const auto& quadratic = validation ? probe.validation : probe.train;
        if (!Usable(quadratic)) continue;
        score += RawScore(quadratic, c) / quadratic.r;
        ++used;
    }
    return used ? score / static_cast<double>(used)
                : std::numeric_limits<double>::infinity();
}

void UpdateRanking(RankedCandidate& ranking, double score, int a, int b,
                   const Vec4& coefficients) {
    if (score < ranking.best) {
        ranking.second = ranking.best;
        ranking.best = score;
        ranking.best_a = a;
        ranking.best_b = b;
        ranking.best_coefficients = coefficients;
    } else if (score < ranking.second) {
        ranking.second = score;
    }
}

int AggregateRank(const std::vector<AvaCryptV1MeshProbe>& probes,
                  bool validation) {
    Mat4 matrix{};
    for (const auto& probe : probes) {
        const auto& quadratic = validation ? probe.validation : probe.train;
        if (!Usable(quadratic)) continue;
        for (std::size_t i = 0; i < 4; ++i)
            for (std::size_t j = 0; j < 4; ++j)
                matrix[i][j] += quadratic.q[i][j] / quadratic.r;
    }
    double scale = 0.0;
    for (const auto& row : matrix)
        for (double value : row) scale = std::max(scale, std::abs(value));
    if (scale <= 1e-18) return 0;
    int rank = 0;
    for (std::size_t column = 0; column < 4; ++column) {
        std::size_t pivot = static_cast<std::size_t>(rank);
        for (std::size_t row = pivot; row < 4; ++row)
            if (std::abs(matrix[row][column]) >
                std::abs(matrix[pivot][column])) pivot = row;
        if (std::abs(matrix[pivot][column]) <= scale * 1e-8) continue;
        std::swap(matrix[pivot], matrix[static_cast<std::size_t>(rank)]);
        const double divisor = matrix[static_cast<std::size_t>(rank)][column];
        for (std::size_t c = column; c < 4; ++c)
            matrix[static_cast<std::size_t>(rank)][c] /= divisor;
        for (std::size_t row = 0; row < 4; ++row) {
            if (row == static_cast<std::size_t>(rank)) continue;
            const double factor = matrix[row][column];
            for (std::size_t c = column; c < 4; ++c)
                matrix[row][c] -= factor *
                    matrix[static_cast<std::size_t>(rank)][c];
        }
        ++rank;
        if (rank == 4) break;
    }
    return rank;
}

}  // namespace

AvaCryptV1SolveResult SolveAvaCryptV1MeshKeys(
    const std::vector<AvaCryptV1MeshProbe>& probes) {
    // This routine evaluates tens of thousands of official key classes.
    // VMProtect Ultra on the entire hot loop makes a normal analysis exceed
    // the UI timeout. Mutation still protects the compiled search/math while
    // the caller's classification and acceptance policy remain inside the
    // Ultra-protected analyze_normalized_graph region.
    VRC_VMP_BEGIN_MUTATION("avacrypt_v1_mesh_solver");
    AvaCryptV1SolveResult result;
    for (const auto& probe : probes) {
        if (Usable(probe.train) && Usable(probe.validation)) {
            ++result.probe_count;
            result.train_equations += probe.train.count;
            result.validation_equations += probe.validation.count;
        }
    }

    if (result.probe_count == 0) {
        result.reason = "no_valid_mesh_probe";
        VRC_VMP_END();
        return result;
    }
    if (result.train_equations < 128 || result.validation_equations < 128) {
        result.reason = "insufficient_mesh_equations";
        VRC_VMP_END();
        return result;
    }
    if (AggregateRank(probes, false) < 4 || AggregateRank(probes, true) < 4) {
        result.reason = "rank_deficient_mesh_probe";
        VRC_VMP_END();
        return result;
    }

    const auto keys = LegalKeys();
    std::map<int, PairChoice> a_pairs;
    std::map<int, PairChoice> b_pairs;
    for (int k1 : keys)
        for (int k2 : keys) AddPair(a_pairs, 3 * k2 - 2 * k1, k1, k2);
    for (int k0 : keys)
        for (int k3 : keys) AddPair(b_pairs, 4 * k3 - k0, k0, k3);

    RankedCandidate train;
    RankedCandidate validation;
    for (const auto& [a, unused_a] : a_pairs) {
        (void)unused_a;
        for (const auto& [b, unused_b] : b_pairs) {
            (void)unused_b;
            const Vec4 coefficients = Coefficients(a, b);
            UpdateRanking(train, NormalizedScore(probes, false, coefficients),
                          a, b, coefficients);
            UpdateRanking(validation,
                          NormalizedScore(probes, true, coefficients),
                          a, b, coefficients);
        }
    }

    result.train_score = train.best;
    result.validation_score = validation.best;
    result.train_margin = train.second - train.best;
    result.validation_margin = validation.second - validation.best;
    if (train.best_a != validation.best_a || train.best_b != validation.best_b) {
        result.reason = "train_validation_disagree";
        VRC_VMP_END();
        return result;
    }
    if (!std::isfinite(train.best) || !std::isfinite(validation.best) ||
        train.best > 0.85 || validation.best > 0.85) {
        result.reason = "insufficient_decryption_improvement";
        VRC_VMP_END();
        return result;
    }
    if (!std::isfinite(result.train_margin) ||
        !std::isfinite(result.validation_margin) ||
        result.train_margin < 1e-4 || result.validation_margin < 1e-4) {
        result.reason = "ambiguous_equivalent_class";
        VRC_VMP_END();
        return result;
    }

    const auto& a_choice = a_pairs.at(train.best_a);
    const auto& b_choice = b_pairs.at(train.best_b);
    result.accepted = true;
    result.reason = "accepted_equivalent_key";
    result.keys = {b_choice.first, a_choice.first,
                   a_choice.second, b_choice.second};
    result.coefficients = train.best_coefficients;
    result.combination_a = train.best_a;
    result.combination_b = train.best_b;
    result.equivalent_key_count = a_choice.count * b_choice.count;
    VRC_VMP_END();
    return result;
}

}  // namespace vrc
