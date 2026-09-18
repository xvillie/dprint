#pragma once

#include "process.hpp"
#include <cstdint>
#include <string_view>
#include <vector>

namespace rbx {

struct DumpCandidate
{
    std::uintptr_t rva;
    int            votes;
};

struct DumpResult
{
    std::uintptr_t base = 0;
    std::vector<DumpCandidate> candidates;
    std::size_t xrefCount   = 0;
    std::size_t stringHits  = 0;
};

DumpResult FindFunctionByAnchor(
    HANDLE process,
    std::uintptr_t base,
    std::string_view needle);

} // namespace rbx
