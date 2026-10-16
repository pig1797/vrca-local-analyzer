# VRCA 本地密码锁分析核心（发布候选）

把 VRCA 结构提取与 C++ 分析核心放在自己的电脑上运行，不需要卡密、登录或分析服务器。模型不上传，原文件不写回。

**这是本地命令行核心候选，不是原商业工具全套功能的开源完成版。项目源码使用 AGPL-3.0-only，仍处于首版发布准备阶段。**

## 当前范围

- 本地提取菜单、控制器、状态机及相关结构，运行现有密码候选与终态分析规则。
- 输出 JSON，保留结果、参考候选、置信度、证据不足与补读请求的区分。
- 必要时执行一次定向深读；深读后仍不完整的结果保持不完整，不自动提升为可用密码。
- 不依赖旧授权服务、账号、卡密、规则下载或 VMProtect SDK。

尚未迁入：桌面图形界面、模型永久移除/写回执行器、工程导出、商业网站和合作商接口。报告中的终态/写回计划只是分析数据，**本版本不执行计划、不生成解锁模型**。也不声称支持全部锁型，不能恢复所有加密素材。

## 环境

- Python 3.10 或以上；本机验证使用 CPython 3.12.7、UnityPy 1.25.0。
- CMake 3.20 或以上、C++17 编译器。
- Windows：Visual Studio 2022 C++ 工具链，或带 Ninja 的 MinGW-w64。
- Linux：GCC/Clang 和 Ninja。Windows/MSVC 与 Linux/GCC 的干净环境构建和回归见 [GitHub Actions](https://github.com/pig1797/vrca-local-analyzer/actions)，以相应提交的实际运行结果为准。

依赖首次安装需要网络；安装后，所提供的分析代码没有上传、遥测或授权请求。依赖安装器与自选外部组件的行为不属于离线运行保证。

## 快速开始：Windows

在仓库目录使用 PowerShell：

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
cmake -S . -B build -DPython3_EXECUTABLE="$PWD/.venv/Scripts/python.exe"
cmake --build build --config Release --parallel 2
.\.venv\Scripts\python.exe analyze.py "D:\Models\自己的模型.vrca" --output "result.report.json"
```

已安装 MinGW/Ninja 时，首次配置可改为：

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DPython3_EXECUTABLE="$PWD/.venv/Scripts/python.exe"
```

不要在同一个 build 目录混用 Visual Studio 与 Ninja；换生成器时使用另一个构建目录并通过 `--worker` 指定产物。

## 快速开始：Linux

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DPython3_EXECUTABLE="$PWD/.venv/bin/python"
cmake --build build --parallel 2
.venv/bin/python analyze.py "/path/to/owned-model.vrca" --output result.report.json
```

如构建在其他目录，传入 `--worker /absolute/path/to/VrcAnalysisWorker`；Windows 的文件名带 `.exe`。

不传 `--output` 时，JSON 写到标准输出。输出可能包含模型名称、结构信息和候选密码，请作为私人数据保存，不要提交到公开仓库或 Issue。已有输出文件不会覆盖。每个子进程默认超时 180 秒，可用 `--timeout` 设置 1–600 秒；最多四个串行子进程，因此该值不是整次分析的总时长。

## 怎么看结果

- `results`：核心规则认可的结果；仍然是静态/离线分析，不等于 VRChat 实测。
- `password_candidates`：包括可能未验证的参考候选；不要只取这里的字符串就宣称密码有效。
- `analysis_incomplete`、`runtime_status`、`deep_scan_request`：说明证据与补读状态，保留这些字段供排查。
- `local_execution`：本地执行信息；`runtime_tested` 与 `model_writeback_supported` 均为 `false`。

原始 worker 也可单独接受绝对路径结构图：

```bash
build/VrcAnalysisWorker analyze-graph /absolute/path/to/input.graph.json --json
```

`python/vrca_extract_graph.py` 的历史参数 `--remote-graph` / `--remote-deep-from-fast` 只代表结构图格式，**不会联网**。通常不需要直接调用它们。

## 测试

```bash
ctest --test-dir build -C Release --output-on-failure
```

包含 60 个随机化合成状态机回归、13 项本地编排单元测试，以及 worker 的中文路径与错误输入集成检查。测试输入不包含客户模型、客户密码或历史实验素材。通过这些测试不代表所有真实模型都能解锁。

## 安全与资源边界

只分析自己拥有或获得授权的文件，不运行 Unity、VRChat 或模型脚本。解析恶意/畸形包仍有风险；建议在低权限隔离环境中处理不受信任的输入。

Windows 提取进程使用现有 Job Object 内存门禁，默认上限 2 GiB；MSVC 构建的原生 worker 固定预留 8 MiB 栈，避免默认 1 MiB 栈在分析中溢出。Linux 原生 worker 保留 256 MiB 地址空间、180 秒 CPU 和禁用 core dump 的限制。Python 提取器在 Linux 上没有同等内存门禁，应另用容器或系统资源限制。该项目不是恶意文件安全沙箱。

## 发布与许可证

项目自有源码采用 [GNU AGPL v3](LICENSE)（SPDX: `AGPL-3.0-only`）。允许商业使用，修改、分发和提供网络服务时须遵守对应条款；不提供任何保证。详见 [LICENSING.md](LICENSING.md)、[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) 与 [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md)。客户模型、卡密数据库、密钥、服务配置、历史日志与生产备份不属于发布内容。
