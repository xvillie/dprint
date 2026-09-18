#include "dumper.hpp"
#include "injector.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>

namespace {

constexpr const wchar_t* kDefaultProcess = L"RobloxPlayerBeta.exe";
constexpr const char*    kDefaultAnchor  =
    "SetRoll can only be used on Camera objects with a CameraType of Scriptable";

std::wstring Widen(std::string_view s)
{
    std::wstring w;
    w.reserve(s.size());
    for (char c : s) w.push_back(static_cast<wchar_t>(static_cast<unsigned char>(c)));
    return w;
}

rbx::Level ParseLevel(std::string_view s)
{
    if (s == "print"   || s == "0") return rbx::Level::Print;
    if (s == "info"    || s == "1") return rbx::Level::Info;
    if (s == "warning" || s == "warn" || s == "2") return rbx::Level::Warning;
    if (s == "error"   || s == "err"  || s == "3") return rbx::Level::Error;
    return rbx::Level::Print;
}

void Usage()
{
    std::puts("usage:");
    std::puts("  dprint dump  [--process EXE] [--anchor STRING]");
    std::puts("  dprint print MESSAGE [--level {print|info|warning|error}]");
    std::puts("                    [--offset 0x...] [--process EXE] [--anchor STRING]");
}

int RunDump(std::wstring_view exe, std::string_view anchor)
{
    DWORD pid = rbx::FindProcessId(exe);
    if (!pid) { std::printf("process not found\n"); return 1; }
    auto proc = rbx::OpenProcessByPid(pid, rbx::kReadOnlyRights);
    if (!proc) { std::printf("OpenProcess failed (0x%lX)\n", GetLastError()); return 1; }

    auto base = rbx::GetImageBase(proc.get());
    if (!base) { std::printf("failed to read image base\n"); return 1; }
    std::printf("module base : 0x%llX\n", (unsigned long long)base);

    auto res = rbx::FindFunctionByAnchor(proc.get(), base, anchor);
    std::printf("anchor hits : %zu\n", res.stringHits);
    std::printf("xrefs       : %zu\n", res.xrefCount);
    if (res.candidates.empty()) { std::printf("no candidates\n"); return 1; }

    std::printf("candidates (ranked):\n");
    for (auto& c : res.candidates)
        std::printf("  RVA 0x%08llX   VA 0x%016llX   votes=%d\n",
                    (unsigned long long)c.rva,
                    (unsigned long long)(base + c.rva),
                    c.votes);

    auto best = res.candidates.front().rva;
    std::printf("\nsuggested --offset 0x%llX\n", (unsigned long long)best);
    return 0;
}

int RunPrint(std::wstring_view exe, std::string_view anchor,
             std::string_view message, rbx::Level level,
             std::uintptr_t explicitOffset)
{
    (void)rbx::EnableDebugPrivilege();

    std::uintptr_t rva = explicitOffset;
    if (!rva)
    {
        DWORD pid = rbx::FindProcessId(exe);
        if (!pid) { std::printf("process not found\n"); return 1; }
        auto proc = rbx::OpenProcessByPid(pid, rbx::kReadOnlyRights);
        if (!proc) { std::printf("OpenProcess(read) failed (0x%lX)\n", GetLastError()); return 1; }
        auto base = rbx::GetImageBase(proc.get());
        if (!base) { std::printf("failed to read image base\n"); return 1; }
        auto res = rbx::FindFunctionByAnchor(proc.get(), base, anchor);
        if (res.candidates.empty())
        {
            std::printf("auto-dump failed; pass --offset explicitly\n");
            return 1;
        }
        rva = res.candidates.front().rva;
        std::printf("auto-dumped offset : 0x%llX (%d vote(s))\n",
                    (unsigned long long)rva, res.candidates.front().votes);
    }

    auto r = rbx::CallRemote(exe, rva, level, message);
    if (!r.success)
    {
        std::printf("inject failed: %s\n", r.error ? r.error : "(unknown)");
        return 1;
    }
    std::printf("ok: shellcode @ 0x%llX, cave @ 0x%llX, message = %.*s\n",
                (unsigned long long)r.shellcodeAddr,
                (unsigned long long)r.codecaveAddr,
                static_cast<int>(message.size()), message.data());
    return 0;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc < 2) { Usage(); return 1; }
    std::string_view cmd = argv[1];

    std::wstring processName = kDefaultProcess;
    std::string  anchor      = kDefaultAnchor;
    rbx::Level   level       = rbx::Level::Print;
    std::uintptr_t offset    = 0;
    std::string  message;

    for (int i = 2; i < argc; ++i)
    {
        std::string_view a = argv[i];
        auto need = [&](const char* name) -> const char* {
            if (i + 1 >= argc) { std::fprintf(stderr, "%s needs an argument\n", name); std::exit(1); }
            return argv[++i];
        };
        if (a == "--process") processName = Widen(need("--process"));
        else if (a == "--anchor") anchor  = need("--anchor");
        else if (a == "--level" || a == "-l") level = ParseLevel(need("--level"));
        else if (a == "--offset" || a == "-o") offset = std::strtoull(need("--offset"), nullptr, 0);
        else if (cmd == "print" && message.empty()) message = a;
        else { std::fprintf(stderr, "unrecognised: %.*s\n", (int)a.size(), a.data()); return 1; }
    }

    if (cmd == "dump")  return RunDump(processName, anchor);
    if (cmd == "print")
    {
        if (message.empty()) { std::puts("print needs a MESSAGE argument"); Usage(); return 1; }
        return RunPrint(processName, anchor, message, level, offset);
    }
    Usage();
    return 1;
}