// Owned thin Windows launcher. The service/engine remain ordinary local source.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>

namespace {
bool Exists(const std::wstring& path) {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
}
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    wchar_t module[32768]{};
    const DWORD size = GetModuleFileNameW(nullptr, module, 32768);
    if (!size || size >= 32768) return 1;
    const std::wstring executable(module, size);
    const auto slash = executable.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return 1;
    const std::wstring root = executable.substr(0, slash);
    std::wstring python = root + L"\\runtime\\python.exe";
    if (!Exists(python)) python = root + L"\\.venv\\Scripts\\python.exe";
    const std::wstring script = root + L"\\local_web.py";
    if (!Exists(python) || !Exists(script)) {
        MessageBoxW(nullptr, L"请先完整解压便携包，并保留 runtime、bin、python、web 文件夹。\n源码版请按 README 安装和编译后启动。",
                    L"VRCA 本地分析", MB_OK | MB_ICONERROR);
        return 1;
    }
    std::wstring command = L"\"" + python + L"\" \"" + script + L"\"";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(python.c_str(), command.data(), nullptr, nullptr, FALSE,
                        CREATE_NEW_CONSOLE, nullptr, root.c_str(), &startup, &process)) {
        MessageBoxW(nullptr, L"无法启动本地服务，请检查目录权限与完整性。", L"VRCA 本地分析", MB_OK | MB_ICONERROR);
        return 1;
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return 0;
}
