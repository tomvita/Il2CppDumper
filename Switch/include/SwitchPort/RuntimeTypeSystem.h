#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "SwitchPort/ElfImage.h"

namespace SwitchPort {

struct RuntimeType {
    uint64_t pointer = 0;
    uint64_t data = 0;
    uint32_t bits = 0;
    uint16_t attrs = 0;
    uint8_t type = 0;
    uint8_t byref = 0;
};

struct MetadataRegistration {
    uint64_t genericClassesCount = 0;
    uint64_t genericClasses = 0;
    uint64_t genericInstsCount = 0;
    uint64_t genericInsts = 0;
    uint64_t genericMethodTableCount = 0;
    uint64_t genericMethodTable = 0;
    uint64_t typesCount = 0;
    uint64_t types = 0;
    uint64_t methodSpecsCount = 0;
    uint64_t methodSpecs = 0;
    uint64_t fieldOffsetsCount = 0;
    uint64_t fieldOffsets = 0;
    uint64_t typeDefinitionsSizesCount = 0;
    uint64_t typeDefinitionsSizes = 0;
    uint64_t metadataUsagesCount = 0;
    uint64_t metadataUsages = 0;
};

struct MethodSpec {
    int32_t methodDefinitionIndex = -1;
    int32_t classIndexIndex = -1;
    int32_t methodIndexIndex = -1;
};

struct GenericMethodTableEntry {
    int32_t genericMethodIndex = -1;
    int32_t methodIndex = -1;
};

class RuntimeTypeSystem {
public:
    bool Load(const ElfImage& elf, uint64_t metadataRegistrationVa, double metadataVersion, std::string* error);

    const RuntimeType* GetTypeByIndex(int32_t index) const;
    const RuntimeType* GetTypeByPointer(uint64_t pointer) const;
    int32_t FindTypeIndexByPointer(uint64_t pointer) const;
    bool HasTypes() const { return !types_.empty(); }
    const MetadataRegistration& Registration() const { return metadataRegistration_; }
    const std::vector<uint64_t>& GenericInstPointers() const { return genericInstPointers_; }
    const std::vector<MethodSpec>& MethodSpecs() const { return methodSpecs_; }
    const std::vector<GenericMethodTableEntry>& GenericMethodTable() const { return genericMethodTable_; }
    bool GetGenericInstArgTypePointers(const ElfImage& elf, int32_t genericInstIndex, std::vector<uint64_t>* out) const;
    int32_t GetFieldOffsetFromIndex(const ElfImage& elf, double metadataVersion, int32_t typeIndex, int32_t fieldIndexInType,
                                    int32_t fieldIndex, bool isValueType, bool isStatic) const;

private:
    const ElfImage* elf_ = nullptr;
    bool fieldOffsetsArePointers_ = false;
    std::vector<uint64_t> fieldOffsets_;
    MetadataRegistration metadataRegistration_;
    std::vector<uint64_t> typePointers_;
    std::vector<RuntimeType> types_;
    std::vector<uint64_t> genericInstPointers_;
    std::vector<MethodSpec> methodSpecs_;
    std::vector<GenericMethodTableEntry> genericMethodTable_;
    std::unordered_map<uint64_t, int32_t> pointerToIndex_;
    mutable std::unordered_map<uint64_t, RuntimeType> pointerTypeCache_;
};

} // namespace SwitchPort
