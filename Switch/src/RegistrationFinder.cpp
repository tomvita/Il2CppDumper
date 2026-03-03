#include "SwitchPort/RegistrationFinder.h"

#include <algorithm>
#include <array>
#include <vector>

namespace SwitchPort {

namespace {

constexpr uint32_t kPfX = 1u;
constexpr std::array<uint8_t, 13> kFeatureBytes = {'m', 's', 'c', 'o', 'r', 'l', 'i', 'b', '.', 'd', 'l', 'l', 0};
constexpr uint64_t kPtrSize = 8;

std::vector<size_t> SearchPattern(const std::vector<uint8_t>& haystack, const std::array<uint8_t, 13>& needle) {
    std::vector<size_t> results;
    if (haystack.size() < needle.size()) {
        return results;
    }
    for (size_t i = 0; i + needle.size() <= haystack.size(); ++i) {
        if (std::equal(needle.begin(), needle.end(), haystack.begin() + static_cast<ptrdiff_t>(i))) {
            results.push_back(i);
        }
    }
    return results;
}

} // namespace

RegistrationResult RegistrationFinder::Find(double il2cppVersion, int typeDefinitionsCount, int imageCount) const {
    RegistrationResult result{};
    result.codeRegistration = FindCodeRegistration(il2cppVersion, imageCount, &result.pointerInExec);
    if (il2cppVersion >= 27.0) {
        result.metadataRegistration = FindMetadataRegistrationV21(typeDefinitionsCount, result.pointerInExec);
        if (result.metadataRegistration == 0) {
            // Fallback: some binaries place type pointers outside the expected section class.
            result.metadataRegistration = FindMetadataRegistrationV21(typeDefinitionsCount, !result.pointerInExec);
        }
        if (result.metadataRegistration == 0) {
            result.metadataRegistration = FindMetadataRegistrationHeuristic(typeDefinitionsCount);
        }
        if (result.metadataRegistration != 0) {
            const uint64_t refined = RefineMetadataRegistrationAround(result.metadataRegistration, typeDefinitionsCount);
            if (refined != 0) {
                result.metadataRegistration = refined;
            }
        }
    }
    uint64_t symbolValue = 0;
    if (result.codeRegistration == 0 && elf_.FindDynamicSymbolVaddr("g_CodeRegistration", &symbolValue)) {
        result.codeRegistration = symbolValue;
    }
    if (result.metadataRegistration == 0 && elf_.FindDynamicSymbolVaddr("g_MetadataRegistration", &symbolValue)) {
        result.metadataRegistration = symbolValue;
    }
    return result;
}

bool RegistrationFinder::IsInDataOffset(uint64_t offset) const {
    for (const auto& seg : elf_.Segments()) {
        if ((seg.flags & kPfX) != 0) {
            continue;
        }
        if (offset >= seg.fileOffset && offset <= seg.fileOffset + seg.filesz) {
            return true;
        }
    }
    return false;
}

bool RegistrationFinder::IsInExecVaddr(uint64_t addr) const {
    for (const auto& seg : elf_.Segments()) {
        if ((seg.flags & kPfX) == 0) {
            continue;
        }
        if (addr >= seg.vaddr && addr <= seg.vaddr + seg.memsz) {
            return true;
        }
    }
    return false;
}

bool RegistrationFinder::IsInDataVaddr(uint64_t addr) const {
    for (const auto& seg : elf_.Segments()) {
        if ((seg.flags & kPfX) != 0) {
            continue;
        }
        if (addr >= seg.vaddr && addr <= seg.vaddr + seg.memsz) {
            return true;
        }
    }
    return false;
}

std::vector<uint64_t> RegistrationFinder::FindReferencesInData(uint64_t addr) const {
    std::vector<uint64_t> refs;
    for (const auto& seg : elf_.Segments()) {
        if ((seg.flags & kPfX) != 0 || seg.filesz < kPtrSize) {
            continue;
        }
        const uint64_t end = seg.fileOffset + seg.filesz - kPtrSize;
        for (uint64_t off = seg.fileOffset; off <= end; off += kPtrSize) {
            uint64_t value = 0;
            if (!elf_.ReadU64AtOffset(off, &value)) {
                break;
            }
            if (value == addr) {
                uint64_t va = 0;
                if (elf_.TryMapOffsetToVaddr(off, &va)) {
                    refs.push_back(va);
                }
            }
        }
    }
    return refs;
}

uint64_t RegistrationFinder::FindCodeRegistration(double il2cppVersion, int imageCount, bool* pointerInExec) const {
    if (il2cppVersion < 24.2) {
        return 0;
    }
    uint64_t codeReg = FindCodeRegistrationInSegments(il2cppVersion, imageCount, true);
    if (codeReg != 0) {
        *pointerInExec = true;
        return codeReg;
    }
    codeReg = FindCodeRegistrationInSegments(il2cppVersion, imageCount, false);
    *pointerInExec = false;
    return codeReg;
}

uint64_t RegistrationFinder::FindCodeRegistrationInSegments(double il2cppVersion, int imageCount, bool executableSegments) const {
    for (const auto& seg : elf_.Segments()) {
        const bool isExec = (seg.flags & kPfX) != 0;
        if (isExec != executableSegments || seg.filesz < kFeatureBytes.size()) {
            continue;
        }
        std::vector<uint8_t> bytes;
        if (!elf_.ReadBytesAtOffset(seg.fileOffset, static_cast<size_t>(seg.filesz), &bytes)) {
            continue;
        }
        const auto hits = SearchPattern(bytes, kFeatureBytes);
        for (size_t hit : hits) {
            const uint64_t dllva = seg.vaddr + hit;
            const auto ref1 = FindReferencesInData(dllva);
            for (uint64_t refva : ref1) {
                const auto ref2 = FindReferencesInData(refva);
                for (uint64_t refva2 : ref2) {
                    if (il2cppVersion >= 27.0) {
                        for (int i = imageCount - 1; i >= 0; --i) {
                            const uint64_t candidate = refva2 - static_cast<uint64_t>(i) * kPtrSize;
                            const auto ref3 = FindReferencesInData(candidate);
                            for (uint64_t refva3 : ref3) {
                                uint64_t checkOffset = 0;
                                if (!elf_.TryMapVaddrToOffset(refva3 - kPtrSize, &checkOffset)) {
                                    continue;
                                }
                                uint64_t countValue = 0;
                                if (!elf_.ReadU64AtOffset(checkOffset, &countValue)) {
                                    continue;
                                }
                                if (countValue == static_cast<uint64_t>(imageCount)) {
                                    return refva3 - ((il2cppVersion >= 29.0) ? (kPtrSize * 14) : (kPtrSize * 13));
                                }
                            }
                        }
                    } else {
                        for (int i = 0; i < imageCount; ++i) {
                            const uint64_t candidate = refva2 - static_cast<uint64_t>(i) * kPtrSize;
                            const auto ref3 = FindReferencesInData(candidate);
                            for (uint64_t refva3 : ref3) {
                                return refva3 - kPtrSize * 13;
                            }
                        }
                    }
                }
            }
        }
    }
    return 0;
}

uint64_t RegistrationFinder::FindMetadataRegistrationV21(int typeDefinitionsCount, bool pointerInExec) const {
    for (const auto& seg : elf_.Segments()) {
        if ((seg.flags & kPfX) != 0 || seg.filesz < (kPtrSize * 3)) {
            continue;
        }
        const uint64_t end = seg.fileOffset + seg.filesz - kPtrSize;
        for (uint64_t off = seg.fileOffset; off <= end; off += kPtrSize) {
            uint64_t a = 0;
            if (!elf_.ReadU64AtOffset(off, &a)) {
                break;
            }
            if (a != static_cast<uint64_t>(typeDefinitionsCount)) {
                continue;
            }

            uint64_t b = 0;
            if (!elf_.ReadU64AtOffset(off + kPtrSize, &b) || b != static_cast<uint64_t>(typeDefinitionsCount)) {
                continue;
            }

            uint64_t pointerVa = 0;
            if (!elf_.ReadU64AtOffset(off + kPtrSize * 2, &pointerVa)) {
                continue;
            }
            uint64_t pointerOffset = 0;
            if (!elf_.TryMapVaddrToOffset(pointerVa, &pointerOffset) || !IsInDataOffset(pointerOffset)) {
                continue;
            }

            bool ok = true;
            for (int i = 0; i < typeDefinitionsCount; ++i) {
                uint64_t typeVa = 0;
                if (!elf_.ReadU64AtOffset(pointerOffset + static_cast<uint64_t>(i) * kPtrSize, &typeVa)) {
                    ok = false;
                    break;
                }
                if (pointerInExec) {
                    if (!IsInExecVaddr(typeVa)) {
                        ok = false;
                        break;
                    }
                } else {
                    if (!IsInDataVaddr(typeVa)) {
                        ok = false;
                        break;
                    }
                }
            }
            if (!ok) {
                continue;
            }

            uint64_t addrVa = 0;
            if (!elf_.TryMapOffsetToVaddr(off, &addrVa)) {
                continue;
            }
            return addrVa - kPtrSize * 10;
        }
    }
    return 0;
}

uint64_t RegistrationFinder::FindMetadataRegistrationHeuristic(int typeDefinitionsCount) const {
    constexpr uint64_t kFieldsToCheck = 16; // room for safe reads
    for (const auto& seg : elf_.Segments()) {
        if ((seg.flags & kPfX) != 0 || seg.filesz < kPtrSize * (kFieldsToCheck + 1)) {
            continue;
        }
        const uint64_t end = seg.fileOffset + seg.filesz - kPtrSize * kFieldsToCheck;
        for (uint64_t off = seg.fileOffset; off <= end; off += kPtrSize) {
            uint64_t typesCount = 0;
            if (!elf_.ReadU64AtOffset(off + kPtrSize * 6, &typesCount) || typesCount != static_cast<uint64_t>(typeDefinitionsCount)) {
                continue;
            }

            uint64_t typesPtr = 0;
            uint64_t typesPtrOff = 0;
            if (!elf_.ReadU64AtOffset(off + kPtrSize * 7, &typesPtr) || !elf_.TryMapVaddrToOffset(typesPtr, &typesPtrOff)) {
                continue;
            }
            bool typesTableLooksValid = true;
            const int sample = std::min(typeDefinitionsCount, 32);
            for (int i = 0; i < sample; ++i) {
                uint64_t p = 0;
                if (!elf_.ReadU64AtOffset(typesPtrOff + static_cast<uint64_t>(i) * kPtrSize, &p) ||
                    !(IsInDataVaddr(p) || IsInExecVaddr(p))) {
                    typesTableLooksValid = false;
                    break;
                }
            }
            if (!typesTableLooksValid) {
                continue;
            }

            uint64_t va = 0;
            if (elf_.TryMapOffsetToVaddr(off, &va)) {
                return va;
            }
        }
    }
    return 0;
}

uint64_t RegistrationFinder::RefineMetadataRegistrationAround(uint64_t candidate, int typeDefinitionsCount) const {
    const uint64_t window = 0x100;
    const uint64_t start = (candidate > window) ? (candidate - window) : 0;
    const uint64_t end = candidate + window;
    for (uint64_t m = start; m <= end; m += kPtrSize) {
        uint64_t mOff = 0;
        if (!elf_.TryMapVaddrToOffset(m, &mOff)) {
            continue;
        }
        uint64_t c1 = 0;
        uint64_t c2 = 0;
        uint64_t ptr = 0;
        if (!elf_.ReadU64AtOffset(mOff + kPtrSize * 10, &c1) || !elf_.ReadU64AtOffset(mOff + kPtrSize * 12, &c2) ||
            !elf_.ReadU64AtOffset(mOff + kPtrSize * 13, &ptr)) {
            continue;
        }
        if (c1 != static_cast<uint64_t>(typeDefinitionsCount) || c2 != static_cast<uint64_t>(typeDefinitionsCount)) {
            continue;
        }
        uint64_t ptrOff = 0;
        if (!elf_.TryMapVaddrToOffset(ptr, &ptrOff)) {
            continue;
        }
        bool valid = true;
        const int sample = std::min(typeDefinitionsCount, 32);
        for (int i = 0; i < sample; ++i) {
            uint64_t p = 0;
            if (!elf_.ReadU64AtOffset(ptrOff + static_cast<uint64_t>(i) * kPtrSize, &p) ||
                !(IsInDataVaddr(p) || IsInExecVaddr(p))) {
                valid = false;
                break;
            }
        }
        if (valid) {
            return m;
        }
    }
    return 0;
}

} // namespace SwitchPort
