#pragma once

#include "process.hpp"
#include <cstdint>
#include <string_view>

namespace rbx {
enum class Level : int
{
    Print   = 0,
    Info    = 1,
    Warning = 2,
    Error   = 3,
};
bool EnableDebugPrivilege();
struct InjectResult
{
    bool           success       = false;
    std::uintptr_t shellcodeAddr = 0;
    std::uintptr_t codecaveAddr  = 0;
    const char*    error         = nullptr;
};

InjectResult CallRemote(
    std::wstring_view exeName,
    std::uintptr_t    functionRva,
    Level             level,
    std::string_view  message);

} // namespace rbx
