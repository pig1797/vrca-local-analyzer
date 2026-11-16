#include "analysis.hpp"
#include "common.hpp"
#include "mini_json.hpp"
#include "server_plan_scope.hpp"

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>

#if defined(__linux__)
#include <sys/resource.h>
#endif

namespace fs = std::filesystem;

namespace {

constexpr std::uintmax_t kMaximumInputBytes = 64ull * 1024ull * 1024ull;
constexpr std::size_t kMaximumOutputBytes = 16ull * 1024ull * 1024ull;

void ApplyWorkerLimits() {
#if defined(__linux__)
    // Keep the native hard ceiling aligned with the local worker's 256 MiB
    // address-space budget so a direct invocation cannot escape its capacity.
    const rlimit address{256ull * 1024ull * 1024ull,
        256ull * 1024ull * 1024ull};
    const rlimit cpu{180, 180};
    const rlimit core{0, 0};
    if (setrlimit(RLIMIT_AS, &address) != 0 ||
            setrlimit(RLIMIT_CPU, &cpu) != 0 ||
            setrlimit(RLIMIT_CORE, &core) != 0)
        throw std::runtime_error("unable to establish worker resource limits");
#endif
}

fs::path CheckedInput(const char* raw) {
    fs::path path = fs::u8path(raw ? raw : "");
    if (path.empty() || !path.is_absolute())
        throw std::runtime_error("worker input path must be absolute");
    const auto status = fs::symlink_status(path);
    if (!fs::is_regular_file(status) || fs::is_symlink(status))
        throw std::runtime_error("worker input must be a regular non-symlink file");
    const auto size = fs::file_size(path);
    if (size == 0 || size > kMaximumInputBytes)
        throw std::runtime_error("worker input size rejected");
    return path.lexically_normal();
}

int Emit(vrc::json::Value value) {
    const std::string output = value.dump(0);
    if (output.size() > kMaximumOutputBytes)
        throw std::runtime_error("worker output size rejected");
    std::cout << output << '\n';
    return 0;
}

int Usage() {
    std::cerr << "WORKER_FAIL|usage\n";
    return 64;
}

}  // namespace

int WorkerMain(int argc, char** argv) {
    try {
        ApplyWorkerLimits();
        if (argc == 4 && std::string(argv[1]) == "analyze-graph" &&
                std::string(argv[3]) == "--json") {
            const fs::path graph = CheckedInput(argv[2]);
            vrc::json::Value report = vrc::AnalyzeNormalizedGraph(graph);
            report["graph_sha256"] = vrc::Sha256File(graph, false);
            report["graph_schema_version"] = "vpf-structural-graph/1";
            vrc::AttachServerPlanOptions(report);
            return Emit(std::move(report));
        }
        if (argc == 5 && std::string(argv[1]) == "scope-plan" &&
                std::string(argv[4]) == "--json") {
            const fs::path report = CheckedInput(argv[2]);
            const fs::path selection = CheckedInput(argv[3]);
            return Emit(vrc::ScopeServerPlan(report, selection));
        }
        return Usage();
    } catch (const std::exception& error) {
        std::cerr << "WORKER_FAIL|" << error.what() << '\n';
        return 65;
    }
}

#if defined(_WIN32)
int wmain(int argc, wchar_t** argv) {
    std::vector<std::string> utf8;
    utf8.reserve(static_cast<std::size_t>(argc));
    for (int i = 0; i < argc; ++i) utf8.push_back(vrc::WideToUtf8(argv[i]));
    std::vector<char*> arguments;
    for (auto& value : utf8) arguments.push_back(value.data());
    return WorkerMain(argc, arguments.data());
}
#else
int main(int argc, char** argv) { return WorkerMain(argc, argv); }
#endif
