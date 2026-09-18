#define NOMINMAX

#include "process.hpp"

#include <TlHelp32.h>
#include <winternl.h>
#include <algorithm>
#include <cstring>

#pragma comment(lib, "ntdll.lib")

// Fallback prototype in case winternl.h on the SDK version doesn't publish it.
extern "C" NTSTATUS NTAPI NtQueryInformationProcess(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

namespace rbx {

ProcessHandle::~ProcessHandle()
{
    if (valid()) CloseHandle(handle_);
}

ProcessHandle& ProcessHandle::operator=(ProcessHandle&& other) noexcept
{
    if (this != &other)
    {
        if (valid()) CloseHandle(handle_);
        handle_ = other.handle_;
        other.handle_ = nullptr;
    }
    return *this;
}

DWORD FindProcessId(std::wstring_view exeName)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W entry{ sizeof(entry) };
    DWORD pid = 0;
    std::wstring wanted(exeName);
    std::transform(wanted.begin(), wanted.end(), wanted.begin(),
                   [](wchar_t c){ return static_cast<wchar_t>(towlower(c)); });

    if (Process32FirstW(snap, &entry))
    {
        do {
            std::wstring name(entry.szExeFile);
            std::transform(name.begin(), name.end(), name.begin(),
                           [](wchar_t c){ return static_cast<wchar_t>(towlower(c)); });
            if (name == wanted) { pid = entry.th32ProcessID; break; }
        } while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return pid;
}

ProcessHandle OpenProcessByPid(DWORD pid, DWORD rights)
{
    HANDLE h = OpenProcess(rights, FALSE, pid);
    return ProcessHandle(h);
}

std::uintptr_t GetImageBase(HANDLE process)
{
    PROCESS_BASIC_INFORMATION pbi{};
    ULONG returned = 0;
    NTSTATUS status = NtQueryInformationProcess(
        process, ProcessBasicInformation, &pbi, sizeof(pbi), &returned);
    if (status < 0 || !pbi.PebBaseAddress) return 0;

    // The PEB layout has ImageBaseAddress at +0x10 on x64.
    auto peb = reinterpret_cast<std::uintptr_t>(pbi.PebBaseAddress);
    auto bytes = ReadBytes(process, peb + 0x10, sizeof(std::uintptr_t));
    if (bytes.size() < sizeof(std::uintptr_t)) return 0;
    std::uintptr_t base = 0;
    std::memcpy(&base, bytes.data(), sizeof(base));
    return base;
}

std::vector<std::uint8_t> ReadBytes(HANDLE process, std::uintptr_t address, std::size_t size)
{
    constexpr std::size_t kChunk = 0x400000;
    std::vector<std::uint8_t> out;
    out.reserve(size);
    std::size_t remaining = size;
    std::uintptr_t cursor = address;

    while (remaining > 0)
    {
        std::size_t want = std::min(kChunk, remaining);
        std::size_t before = out.size();
        out.resize(before + want);
        SIZE_T got = 0;
        BOOL ok = ReadProcessMemory(process, reinterpret_cast<LPCVOID>(cursor),
                                    out.data() + before, want, &got);
        out.resize(before + got);
        if (!ok || got == 0) break;
        cursor    += got;
        remaining -= got;
    }
    return out;
}

std::size_t WriteBytes(HANDLE process, std::uintptr_t address,
                       const void* data, std::size_t size)
{
    SIZE_T written = 0;
    WriteProcessMemory(process, reinterpret_cast<LPVOID>(address),
                       data, size, &written);
    return written;
}

std::unordered_map<std::string, Section>
ParseSections(HANDLE process, std::uintptr_t base)
{
    std::unordered_map<std::string, Section> result;
    auto headers = ReadBytes(process, base, 0x800);
    if (headers.size() < 0x200 || headers[0] != 'M' || headers[1] != 'Z')
        return result;

    std::uint32_t elfanew = 0;
    std::memcpy(&elfanew, headers.data() + 0x3C, sizeof(elfanew));
    if (elfanew + 4 > headers.size()) return result;
    if (headers[elfanew] != 'P' || headers[elfanew + 1] != 'E') return result;

    std::uint16_t numSections = 0, sizeOfOptional = 0;
    std::memcpy(&numSections,    headers.data() + elfanew + 6,  sizeof(numSections));
    std::memcpy(&sizeOfOptional, headers.data() + elfanew + 20, sizeof(sizeOfOptional));
    std::size_t tableOffset = static_cast<std::size_t>(elfanew) + 4 + 20 + sizeOfOptional;

    for (std::uint16_t i = 0; i < numSections; ++i)
    {
        std::size_t entry = tableOffset + i * 40;
        if (entry + 40 > headers.size()) break;
        char name[9]{};
        std::memcpy(name, headers.data() + entry, 8);
        std::uint32_t vsize = 0, vaddr = 0;
        std::memcpy(&vsize, headers.data() + entry + 8,  sizeof(vsize));
        std::memcpy(&vaddr, headers.data() + entry + 12, sizeof(vaddr));
        result.emplace(std::string(name),
                       Section{ std::string(name), base + vaddr, vsize });
    }
    return result;
}

std::vector<Region> AccessibleRegions(HANDLE process,
                                      std::uintptr_t start, std::uintptr_t end)
{
    std::vector<Region> out;
    MEMORY_BASIC_INFORMATION mbi{};
    std::uintptr_t cursor = start;
    while (cursor < end)
    {
        if (!VirtualQueryEx(process, reinterpret_cast<LPCVOID>(cursor),
                             &mbi, sizeof(mbi)))
            break;
        auto regionStart = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
        auto regionEnd   = regionStart + mbi.RegionSize;
        bool accessible  = mbi.State == MEM_COMMIT &&
                           !(mbi.Protect & PAGE_GUARD) &&
                           !(mbi.Protect & PAGE_NOACCESS);
        auto clippedStart = std::max(regionStart, start);
        auto clippedEnd   = std::min(regionEnd,   end);
        if (accessible && clippedEnd > clippedStart)
            out.push_back({ clippedStart, clippedEnd });
        std::uintptr_t next = std::max(regionEnd, cursor + 1);
        if (next <= cursor) break;
        cursor = next;
    }
    return out;
}

} // namespace rbx
