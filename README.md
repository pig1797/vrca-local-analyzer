# VRCA 本地网页分析工具（发布候选）

把 VRCA 结构提取与 C++ 分析核心放在自己的电脑上运行，不需要卡密、登录或分析服务器。模型不上传，原文件不修改，永久移除只生成另存副本。

双击 `Start-VRCA.cmd`，自动启动本机服务并打开浏览器；选择模型、查看处理进度、密码候选和轮盘、保存报告都在本机完成。不需要卡密或登录。网页布局、样式和轮盘组件复用原有网页端，资源随源码提供，不加载在线字体或 CDN。

**这是本地网页分析版，不是原商业工具全套功能的开源完成版。项目源码使用 AGPL-3.0-only。**

## 普通用户：Windows 便携包

将完整便携包解压到一个目录，双击 `VRCA-Local.exe`（备用入口为 `Start-VRCA.cmd`）。请不要在 ZIP 内直接运行，也不要只复制启动文件；旁边的 `runtime`、`bin`、`python`、`web` 文件夹需要一起保留。完整包自带 Python 和已编译核心，不需要另装 Python 或 C++ 编译器。

浏览器会打开 `http://127.0.0.1:随机端口/`。选择或拖入 `.vrca` → “开始本地分析” → 查看候选/轮盘或保存报告。上传进度是传入**本机临时目录**的进度，不是上传互联网。

点击“取消并清理”可停止本次分析或模型处理；完成后用“清理本次结果”删除临时文件。退出时点击网页右上角“退出本地服务”，或在启动窗口按 `Ctrl+C`。仅关闭浏览器标签页不会停止服务。模型、结构图和结果仅在本机临时保留，最后一次处理完成后 10 分钟自动清理。正在处理时不会到期删除。退出清理临时目录；断电或强制结束进程可能留下系统临时文件，此时不能保证清理已执行。

源码 ZIP/Git checkout **不包含**运行环境和 worker，需要先完成下方开发者安装/编译步骤，再双击入口。不要把源码包误当作免安装便携包。

## 当前范围

- 本地提取菜单、控制器、状态机及相关结构，运行现有密码候选与终态分析规则。
- 输出 JSON，保留结果、参考候选、置信度、证据不足与补读请求的区分。
- 必要时执行一次定向深读；深读后仍不完整的结果保持不完整，不自动提升为可用密码。
- 不依赖旧授权服务、账号、卡密、规则下载或 VMProtect SDK。

本地网页已迁入：上传/拖放、真实阶段进度、密码候选分级、结构说明、完整报告下载、无图标轮盘预览、取消和退出。原页面的卡密、聊天与客户数据不迁入。

已额外迁入以下两个功能，其他功能不迁移：

- **永久移除**：分析完成后，在“模型处理”勾选确认并生成副本。仅接受核心范围解析通过的单状态/明确依赖双状态计划；绑定原文件与图谱 SHA，保持原压缩类型，独立进程重新解析并检查对象集、目标字段和非目标资源字节。复验通过后才提供下载。没有安全计划时明确拒绝，不通过强改置信度开放按钮。
- **工程导出**：选择原始模型，或已通过复验的移除副本，点击开始。提供 Unity 工程 ZIP 和不重复捆绑 SDK 的 unitypackage。恢复器隔离生成脚本、修正已知 SDK 引用，保留缺失引用/近似 Shader 报告。导出成功不是原作者完整源工程，也不是已在 Unity/VRChat 实测成功。

未迁入：3D 预览、聊天、卡密/后台、商业合作商接口。不能保证全部锁型可移除或所有加密素材可恢复。移除仅改已证明的状态字段，不保证清理轮盘专用控件。

### 导出组件与写回依赖（源码运行）

便携包包含经过固定摘要检查的导出组件。源码仓库不提交第三方二进制或 VRChat SDK 包：

1. CMake 同时构建 `vrca_lzma1ext`，产物自动放入 `bin`。Windows 还需要将可信 XZ Utils 的 `liblzma-5.dll` 放在 `bin`（本机验证为 Git for Windows 所带 XZ 5.8.3）；Linux 安装 `liblzma-dev` 后编译并链接系统 liblzma。
2. 下载 [AssetRipper 2.0.0](https://github.com/AssetRipper/AssetRipper/releases/tag/2.0.0)，将 Windows x64 官方 ZIP 的 `AssetRipper.GUI.Free.exe` 与 `capstone.dll` 解压到 `tools/AssetRipper/`。官方 ZIP SHA256：`9a7ef0e7c5c3ea5b90b4e6d855e2d98d5f7ec8c3f9e26fccbc194c6a7b01baf7`。Linux x64 使用同版本的官方构建。本地恢复器会核对可执行文件摘要。
3. 通过 VRChat 官方工具取得 SDK 3.10.4，将 `com.vrchat.base` 与 `com.vrchat.avatars` 两个完整包放到 `tools/sdk/`，保留各自许可证。SDK 属于其自己的使用条款，不适用本项目 AGPL，不要将其上传到源码仓库。

AssetRipper 通过临时本机 HTTP 完成一次离线导出，不打开 Unity/VRChat，也不执行模型生成代码。恢复后的工程首次在 Unity 打开时，Unity 可能需要自行下载依赖；此行为不属于本地分析服务。

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
.\.venv\Scripts\python.exe local_web.py
# 或双击 Start-VRCA.cmd。命令行分析仍可用：
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
.venv/bin/python local_web.py
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

包含 60 个随机化合成状态机回归、13 项本地编排单元测试、13 项本地 HTTP/清理/进程取消检查，以及 worker 的中文路径与错误输入集成检查。测试输入不包含客户模型、客户密码或历史实验素材。通过这些测试不代表所有真实模型都能解锁。

## 本地网页安全边界

仅监听 `127.0.0.1`，不监听局域网或公网。服务拒绝不匹配的 Host、跨站 Origin/Fetch 请求，API 需要自定义同源请求头，不开放 CORS；静态资源使用固定白名单，不接受任意磁盘路径。一次仅处理一个模型，最多 450 MiB；提取/分析不显示伪造百分比。服务会在取消时结束自己派生的分析进程树，不终止其他软件。

这不是用于公网部署的通用 Web 服务，也不是同一操作系统用户之间的权限隔离；同用户恶意程序可以访问本机进程和文件。恶意文件解析风险依然存在。默认使用空闲随机端口；可通过 `local_web.py --port 端口号 --no-browser --worker 路径` 调试，绑定地址不可改为公网地址。

## 便携包构建（维护者）

使用 64 位 CPython 3.12，准备官方 Python 3.12 Windows embeddable ZIP（验证官方来源、摘要和 PSF 签名）、已审阅的 Windows wheelhouse、MSVC Release worker，然后运行：

```powershell
python tools/package_windows.py --python-zip python-3.12.x-embed-amd64.zip --python-sha256 <已验证的SHA256> --worker build/Release/VrcAnalysisWorker.exe --launcher build/Release/VrcaLocalLauncher.exe --wheelhouse wheels --output portable-new
```

只向全新目录打包，不覆盖旧包，不复制开发者环境。分析专用依赖清单有意不捆绑音频转换所需的 FMOD；不用本包执行 UnityPy 的通用媒体导出。脚本保留 CPython 的 `LICENSE.txt`、每个包含依赖的许可证和完整对应项目源码，并生成 `BUNDLE-MANIFEST.json`（包版本、wheel/worker/文件摘要和许可证路径）。需人工核对组件许可与原生依赖；不会自动给第三方代码改成 AGPL。该命令不会下载/发布 GitHub release 或改仓库可见性。

## 安全与资源边界

只分析自己拥有或获得授权的文件，不运行 Unity、VRChat 或模型脚本。解析恶意/畸形包仍有风险；建议在低权限隔离环境中处理不受信任的输入。

Windows 提取进程使用现有 Job Object 内存门禁，默认上限 2 GiB；MSVC 构建的原生 worker 固定预留 8 MiB 栈，避免默认 1 MiB 栈在分析中溢出。Linux 原生 worker 保留 256 MiB 地址空间、180 秒 CPU 和禁用 core dump 的限制。Python 提取器在 Linux 上没有同等内存门禁，应另用容器或系统资源限制。该项目不是恶意文件安全沙箱。

## 发布与许可证

项目自有源码采用 [GNU AGPL v3](LICENSE)（SPDX: `AGPL-3.0-only`）。允许商业使用，修改、分发和提供网络服务时须遵守对应条款；不提供任何保证。详见 [LICENSING.md](LICENSING.md)、[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) 与 [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md)。客户模型、卡密数据库、密钥、服务配置、历史日志与生产备份不属于发布内容。
