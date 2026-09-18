#pragma once

#include <windows.h>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace rbx {
constexpr DWORD kReadOnlyRights =
    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
constexpr DWORD kInjectRights =
    PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
    PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE;

struct Section
{
    std::string name;
    std::uintptr_t base;
    std::size_t    size;
};

class ProcessHandle
{
public:
    ProcessHandle() = default;
    explicit ProcessHandle(HANDLE h) : handle_(h) {}
    ~ProcessHandle();
    ProcessHandle(const ProcessHandle&) = delete;
    ProcessHandle& operator=(const ProcessHandle&) = delete;
    ProcessHandle(ProcessHandle&& other) noexcept : handle_(other.handle_) { other.handle_ = nullptr; }
    ProcessHandle& operator=(ProcessHandle&& other) noexcept;

    HANDLE  get() const noexcept { return handle_; }
    bool    valid() const noexcept { return handle_ && handle_ != INVALID_HANDLE_VALUE; }
    explicit operator bool() const noexcept { return valid(); }

private:
    HANDLE handle_ = nullptr;
};
DWORD FindProcessId(std::wstring_view exeName);
ProcessHandle OpenProcessByPid(DWORD pid, DWORD rights);
std::uintptr_t GetImageBase(HANDLE process);
std::vector<std::uint8_t> ReadBytes(HANDLE process, std::uintptr_t address, std::size_t size);
std::size_t WriteBytes(HANDLE process, std::uintptr_t address, const void* data, std::size_t size);
std::unordered_map<std::string, Section> ParseSections(HANDLE process, std::uintptr_t base);
struct Region { std::uintptr_t base, end; };
std::vector<Region> AccessibleRegions(HANDLE process, std::uintptr_t start, std::uintptr_t end);

} // namespace rbx
