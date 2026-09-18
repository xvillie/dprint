#define NOMINMAX

#include "injector.hpp"

#include <winternl.h>
#include <TlHelp32.h>
#include <cstring>
#include <vector>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")
extern "C" NTSTATUS NTAPI NtSetIoCompletion(HANDLE, PVOID, PVOID, NTSTATUS, ULONG_PTR);

namespace rbx {

namespace {
constexpr std::size_t kTpDirectSize             = 72;
constexpr std::size_t kTpDirectCallbackOffset   = 56;

constexpr int kHandleScanStart = 4;
constexpr int kHandleScanEnd   = 8192;
constexpr int kHandleScanStep  = 4;

constexpr std::size_t kObjectTypeInfoSize = 10000;
constexpr std::size_t kCaveScanChunk      = 0x100000;
constexpr std::uintptr_t kMaxUserAddress  = 0x00007FFFFFFFFFFFull;

std::vector<std::uint8_t> BuildShellcode(std::string_view message,
                                          Level level,
                                          std::uintptr_t functionRva)
{
    auto getModuleHandleA = reinterpret_cast<std::uintptr_t>(
        &GetModuleHandleA);

    std::vector<std::uint8_t> code;
    auto emit = [&](std::initializer_list<std::uint8_t> bytes) {
        code.insert(code.end(), bytes.begin(), bytes.end());
    };
    auto emitPtr = [&](std::uintptr_t v) {
        for (int i = 0; i < 8; ++i) code.push_back(static_cast<std::uint8_t>(v >> (i * 8)));
    };
    auto emit32 = [&](std::uint32_t v) {
        for (int i = 0; i < 4; ++i) code.push_back(static_cast<std::uint8_t>(v >> (i * 8)));
    };

    // sub rsp, 0x28   — shadow space + alignment
    emit({0x48, 0x83, 0xEC, 0x28});
    // xor ecx, ecx
    emit({0x33, 0xC9});
    // mov rax, GetModuleHandleA
    emit({0x48, 0xB8});  emitPtr(getModuleHandleA);
    // call rax        — returns the target's own module base in rax
    emit({0xFF, 0xD0});
    // add rax, functionRva
    emit({0x48, 0x05});  emit32(static_cast<std::uint32_t>(functionRva));
    // mov r10, rax    — stash callee
    emit({0x49, 0x89, 0xC2});
    // mov ecx, level
    emit({0xB9});        emit32(static_cast<std::uint32_t>(level));
    // lea rdx, [rip+0x8] — message starts right after the ret
    emit({0x48, 0x8D, 0x15, 0x08, 0x00, 0x00, 0x00});
    // call r10
    emit({0x41, 0xFF, 0xD2});
    // add rsp, 0x28
    emit({0x48, 0x83, 0xC4, 0x28});
    // ret
    emit({0xC3});
    // inline C-string payload
    for (char c : message) code.push_back(static_cast<std::uint8_t>(c));
    code.push_back(0);
    return code;
}

HANDLE FindIoCompletion(HANDLE process)
{
    std::vector<std::uint8_t> buf(kObjectTypeInfoSize);
    for (int raw = kHandleScanStart; raw < kHandleScanEnd; raw += kHandleScanStep)
    {
        HANDLE dup = nullptr;
        if (!DuplicateHandle(process, reinterpret_cast<HANDLE>(static_cast<LONG_PTR>(raw)),
                             GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS))
            continue;

        ULONG returned = 0;
        NTSTATUS status = NtQueryObject(dup,
            static_cast<OBJECT_INFORMATION_CLASS>(2), buf.data(),
            static_cast<ULONG>(buf.size()), &returned);
        bool matched = false;
        if (status >= 0)
        {
            std::uint16_t length = 0;
            std::uintptr_t namePtr = 0;
            std::memcpy(&length,  buf.data() + 0, sizeof(length));
            std::memcpy(&namePtr, buf.data() + 8, sizeof(namePtr));
            auto typeInfoBase = reinterpret_cast<std::uintptr_t>(buf.data());
            std::uintptr_t offset = namePtr - typeInfoBase;
            if (namePtr && length >= 2 && offset + length <= buf.size())
            {
                std::wstring name(reinterpret_cast<const wchar_t*>(buf.data() + offset),
                                  length / sizeof(wchar_t));
                matched = (name == L"IoCompletion");
            }
        }
        if (matched) return dup;
        CloseHandle(dup);
    }
    return nullptr;
}
std::uintptr_t FindCodeCave(HANDLE process, std::size_t caveSize)
{
    std::vector<std::uint8_t> zeros(caveSize, 0);
    std::vector<std::uint8_t> buf(kCaveScanChunk);
    MEMORY_BASIC_INFORMATION mbi{};
    std::uintptr_t addr = 0;
    while (addr < kMaxUserAddress)
    {
        if (!VirtualQueryEx(process, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)))
            break;
        auto base = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
        std::size_t regionSize = mbi.RegionSize;
        bool okRegion = mbi.State == MEM_COMMIT && mbi.Protect == PAGE_READWRITE;
        if (okRegion && regionSize >= caveSize)
        {
            std::size_t offset = 0;
            while (offset + caveSize <= regionSize)
            {
                std::size_t want = std::min(buf.size(), regionSize - offset);
                SIZE_T got = 0;
                if (!ReadProcessMemory(process,
                        reinterpret_cast<LPCVOID>(base + offset),
                        buf.data(), want, &got) || got < caveSize)
                    break;
                // Search for the run of zeros inside the chunk.
                for (std::size_t i = 0; i + caveSize <= got; ++i)
                {
                    if (std::memcmp(buf.data() + i, zeros.data(), caveSize) == 0)
                        return base + offset + i;
                }
                std::size_t step = got > caveSize - 1 ? got - (caveSize - 1) : 1;
                offset += step;
            }
        }
        std::uintptr_t next = base + regionSize;
        if (next <= addr) break;
        addr = next;
    }
    return 0;
}

} // namespace

bool EnableDebugPrivilege()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &token))
        return false;

    LUID luid{};
    bool ok = false;
    if (LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid))
    {
        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr)
             && GetLastError() != ERROR_NOT_ALL_ASSIGNED;
    }
    CloseHandle(token);
    return ok;
}

InjectResult CallRemote(std::wstring_view exeName,
                        std::uintptr_t functionRva,
                        Level level,
                        std::string_view message)
{
    InjectResult r{};

    DWORD pid = FindProcessId(exeName);
    if (!pid) { r.error = "process not found"; return r; }

    ProcessHandle proc = OpenProcessByPid(pid, kInjectRights);
    if (!proc) { r.error = "OpenProcess failed (try running as admin / enable SeDebugPrivilege)"; return r; }

    auto shellcode = BuildShellcode(message, level, functionRva);
    LPVOID remote = VirtualAllocEx(proc.get(), nullptr, shellcode.size(),
                                   MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote) { r.error = "VirtualAllocEx failed"; return r; }
    r.shellcodeAddr = reinterpret_cast<std::uintptr_t>(remote);

    SIZE_T written = 0;
    if (!WriteProcessMemory(proc.get(), remote, shellcode.data(), shellcode.size(), &written)
        || written != shellcode.size())
    {
        VirtualFreeEx(proc.get(), remote, 0, MEM_RELEASE);
        r.error = "WriteProcessMemory failed";
        return r;
    }
    HANDLE completion = FindIoCompletion(proc.get());
    if (!completion) {
        VirtualFreeEx(proc.get(), remote, 0, MEM_RELEASE);
        r.error = "no IoCompletion handle found";
        return r;
    }

    std::uintptr_t cave = FindCodeCave(proc.get(), kTpDirectSize);
    if (!cave) {
        CloseHandle(completion);
        VirtualFreeEx(proc.get(), remote, 0, MEM_RELEASE);
        r.error = "no suitable codecave found";
        return r;
    }
    r.codecaveAddr = cave;

    std::vector<std::uint8_t> direct(kTpDirectSize, 0);
    auto cb = reinterpret_cast<std::uintptr_t>(remote);
    std::memcpy(direct.data() + kTpDirectCallbackOffset, &cb, sizeof(cb));

    SIZE_T dw = 0;
    if (!WriteProcessMemory(proc.get(), reinterpret_cast<LPVOID>(cave),
                             direct.data(), direct.size(), &dw) || dw != direct.size())
    {
        CloseHandle(completion);
        VirtualFreeEx(proc.get(), remote, 0, MEM_RELEASE);
        r.error = "WriteProcessMemory(TP_DIRECT) failed";
        return r;
    }

    NTSTATUS status = NtSetIoCompletion(completion,
                                        reinterpret_cast<PVOID>(cave),
                                        nullptr, 0, 0);
    CloseHandle(completion);
    if (status < 0)
    {
        VirtualFreeEx(proc.get(), remote, 0, MEM_RELEASE);
        r.error = "NtSetIoCompletion failed";
        return r;
    }
    r.success = true;
    return r;
}

} // namespace rbx
