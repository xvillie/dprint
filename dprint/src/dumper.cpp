#include "dumper.hpp"

extern "C" {
#include "../external/hde64/hde64.h"
}

#include <algorithm>
#include <cstring>
#include <unordered_map>

namespace rbx {

namespace {
std::vector<std::uintptr_t> ScanForNeedle(
    const std::vector<std::uint8_t>& haystack,
    std::uintptr_t regionVa,
    std::string_view needle)
{
    std::vector<std::uintptr_t> hits;
    if (needle.empty() || haystack.size() < needle.size()) return hits;
    const auto* base = haystack.data();
    const auto* npat = reinterpret_cast<const std::uint8_t*>(needle.data());
    const std::size_t limit = haystack.size() - needle.size();
    for (std::size_t i = 0; i <= limit; ++i)
    {
        if (base[i] == npat[0] && std::memcmp(base + i, npat, needle.size()) == 0)
            hits.push_back(regionVa + i);
    }
    return hits;
}

bool IsRefOpcode(std::uint8_t byte)
{
    switch (byte)
    {
        case 0x03: case 0x2B: case 0x39: case 0x3B: case 0x63:
        case 0x80: case 0x81: case 0x83: case 0x85: case 0x87:
        case 0x88: case 0x89: case 0x8A: case 0x8B: case 0x8D:
        case 0xC6: case 0xC7: case 0xF6: case 0xF7:
            return true;
        default:
            return false;
    }
}

std::ptrdiff_t ValidateInstructionStart(
    const std::vector<std::uint8_t>& data, std::ptrdiff_t dispIndex)
{
    if (dispIndex < 4 || dispIndex + 4 > static_cast<std::ptrdiff_t>(data.size()))
        return -1;
    std::uint8_t modrm = data[dispIndex - 1];
    if ((modrm & 0xC7) != 0x05) return -1;
    std::uint8_t op = data[dispIndex - 2];
    if (IsRefOpcode(op)) return dispIndex - 2;
    if (dispIndex >= 3 && data[dispIndex - 3] == 0x0F) return dispIndex - 3;
    return -1;
}

std::vector<std::uintptr_t> FindXrefs(
    HANDLE process,
    std::uintptr_t start, std::uintptr_t end,
    std::uintptr_t targetVa)
{
    std::vector<std::uintptr_t> xrefs;
    for (auto region : AccessibleRegions(process, start, end))
    {
        auto bytes = ReadBytes(process, region.base, region.end - region.base);
        if (bytes.size() < 4) continue;
        const std::int64_t constant =
            static_cast<std::int64_t>(targetVa) -
            static_cast<std::int64_t>(region.base) - 4;

        const std::size_t limit = bytes.size() - 4;
        for (std::size_t i = 0; i <= limit; ++i)
        {
            std::int32_t disp = 0;
            std::memcpy(&disp, bytes.data() + i, sizeof(disp));
            if (static_cast<std::int64_t>(disp) + static_cast<std::int64_t>(i) != constant)
                continue;
            auto start = ValidateInstructionStart(bytes, static_cast<std::ptrdiff_t>(i));
            if (start >= 0)
                xrefs.push_back(region.base + static_cast<std::uintptr_t>(start));
        }
    }
    return xrefs;
}
std::uintptr_t FirstCallAfter(
    HANDLE process,
    std::uintptr_t xrefVa,
    std::uintptr_t textStart, std::uintptr_t textEnd)
{
    constexpr std::size_t kWindow = 0x40;
    auto bytes = ReadBytes(process, xrefVa, kWindow);
    if (bytes.empty()) return 0;

    std::size_t offset = 0;
    while (offset < bytes.size())
    {
        hde64s ins{};
        unsigned len = hde64_disasm(bytes.data() + offset, &ins);
        if (!len || (ins.flags & F_ERROR)) break;

        if (ins.opcode == 0xE8)
        {
            std::uintptr_t nextIp = xrefVa + offset + len;
            std::uintptr_t target = static_cast<std::uintptr_t>(
                static_cast<std::int64_t>(nextIp) +
                static_cast<std::int32_t>(ins.imm.imm32));
            if (target >= textStart && target < textEnd)
                return target;
        }
        offset += len;
    }
    return 0;
}

} // namespace

DumpResult FindFunctionByAnchor(
    HANDLE process, std::uintptr_t base, std::string_view needle)
{
    DumpResult out;
    out.base = base;

    auto sections = ParseSections(process, base);
    auto itRdata = sections.find(".rdata");
    auto itText  = sections.find(".text");
    if (itRdata == sections.end() || itText == sections.end())
        return out;

    auto rdata = ReadBytes(process, itRdata->second.base, itRdata->second.size);
    auto hits  = ScanForNeedle(rdata, itRdata->second.base, needle);
    out.stringHits = hits.size();
    if (hits.empty()) return out;

    auto xrefs = FindXrefs(process,
        itText->second.base,
        itText->second.base + itText->second.size,
        hits.front());
    out.xrefCount = xrefs.size();
    if (xrefs.empty()) return out;

    std::unordered_map<std::uintptr_t, int> votes;
    for (auto xref : xrefs)
    {
        auto callee = FirstCallAfter(process, xref,
            itText->second.base,
            itText->second.base + itText->second.size);
        if (callee)
            votes[callee - base]++;
    }
    out.candidates.reserve(votes.size());
    for (auto& [rva, count] : votes)
        out.candidates.push_back({ rva, count });
    std::sort(out.candidates.begin(), out.candidates.end(),
              [](const DumpCandidate& a, const DumpCandidate& b) { return a.votes > b.votes; });
    return out;
}

} // namespace rbx
