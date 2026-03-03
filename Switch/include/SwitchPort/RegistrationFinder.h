#pragma once

#include <cstdint>

#include "SwitchPort/ElfImage.h"

namespace SwitchPort {

struct RegistrationResult {
    uint64_t codeRegistration = 0;
    uint64_t metadataRegistration = 0;
    bool pointerInExec = false;
};

class RegistrationFinder {
public:
    explicit RegistrationFinder(const ElfImage& elf) : elf_(elf) {}

    RegistrationResult Find(double il2cppVersion, int typeDefinitionsCount, int imageCount) const;

private:
    bool IsInDataOffset(uint64_t offset) const;
    bool IsInExecVaddr(uint64_t addr) const;
    bool IsInDataVaddr(uint64_t addr) const;

    uint64_t FindCodeRegistration(double il2cppVersion, int imageCount, bool* pointerInExec) const;
    uint64_t FindCodeRegistrationInSegments(double il2cppVersion, int imageCount, bool executableSegments) const;
    uint64_t FindMetadataRegistrationV21(int typeDefinitionsCount, bool pointerInExec) const;
    uint64_t FindMetadataRegistrationHeuristic(int typeDefinitionsCount) const;
    uint64_t RefineMetadataRegistrationAround(uint64_t candidate, int typeDefinitionsCount) const;

    std::vector<uint64_t> FindReferencesInData(uint64_t addr) const;

    const ElfImage& elf_;
};

} // namespace SwitchPort
