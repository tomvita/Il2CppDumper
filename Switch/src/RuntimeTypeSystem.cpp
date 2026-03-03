#include "SwitchPort/RuntimeTypeSystem.h"

namespace SwitchPort {

bool RuntimeTypeSystem::Load(const ElfImage& elf, uint64_t metadataRegistrationVa, double metadataVersion, std::string* error) {
    elf_ = &elf;
    types_.clear();
    typePointers_.clear();
    pointerToIndex_.clear();
    genericInstPointers_.clear();
    methodSpecs_.clear();
    genericMethodTable_.clear();
    fieldOffsets_.clear();
    fieldOffsetsArePointers_ = false;
    pointerTypeCache_.clear();
    metadataRegistration_ = {};

    if (metadataRegistrationVa == 0) {
        if (error) {
            *error = "MetadataRegistration VA is zero";
        }
        return false;
    }

    uint64_t values[16]{};
    for (int i = 0; i < 16; ++i) {
        if (!elf.ReadU64AtVaddr(metadataRegistrationVa + static_cast<uint64_t>(i) * 8, &values[i])) {
            if (error) {
                *error = "Failed reading MetadataRegistration field at index " + std::to_string(i);
            }
            return false;
        }
    }

    metadataRegistration_.genericClassesCount = values[0];
    metadataRegistration_.genericClasses = values[1];
    metadataRegistration_.genericInstsCount = values[2];
    metadataRegistration_.genericInsts = values[3];
    metadataRegistration_.genericMethodTableCount = values[4];
    metadataRegistration_.genericMethodTable = values[5];
    metadataRegistration_.typesCount = values[6];
    metadataRegistration_.types = values[7];
    metadataRegistration_.methodSpecsCount = values[8];
    metadataRegistration_.methodSpecs = values[9];
    metadataRegistration_.fieldOffsetsCount = values[10];
    metadataRegistration_.fieldOffsets = values[11];
    metadataRegistration_.typeDefinitionsSizesCount = values[12];
    metadataRegistration_.typeDefinitionsSizes = values[13];
    metadataRegistration_.metadataUsagesCount = values[14];
    metadataRegistration_.metadataUsages = values[15];

    if (metadataRegistration_.fieldOffsetsCount > 0 && metadataRegistration_.fieldOffsets != 0) {
        fieldOffsetsArePointers_ = true; // true for modern metadata versions used by Switch targets.
        fieldOffsets_.resize(static_cast<size_t>(metadataRegistration_.fieldOffsetsCount));
        for (size_t i = 0; i < fieldOffsets_.size(); ++i) {
            if (fieldOffsetsArePointers_) {
                if (!elf.ReadU64AtVaddr(metadataRegistration_.fieldOffsets + static_cast<uint64_t>(i) * 8, &fieldOffsets_[i])) {
                    if (error) {
                        *error = "Failed reading field offsets pointer table";
                    }
                    return false;
                }
            } else {
                int32_t off = -1;
                if (!elf.ReadI32AtVaddr(metadataRegistration_.fieldOffsets + static_cast<uint64_t>(i) * 4, &off)) {
                    if (error) {
                        *error = "Failed reading field offsets table";
                    }
                    return false;
                }
                fieldOffsets_[i] = static_cast<uint64_t>(static_cast<int64_t>(off));
            }
        }
    }

    if (metadataRegistration_.typesCount == 0 || metadataRegistration_.types == 0) {
        if (error) {
            *error = "MetadataRegistration has empty types table";
        }
        return false;
    }

    typePointers_.resize(static_cast<size_t>(metadataRegistration_.typesCount));
    for (size_t i = 0; i < typePointers_.size(); ++i) {
        if (!elf.ReadU64AtVaddr(metadataRegistration_.types + static_cast<uint64_t>(i) * 8, &typePointers_[i])) {
            if (error) {
                *error = "Failed reading type pointer array entry";
            }
            return false;
        }
    }

    types_.resize(typePointers_.size());
    for (size_t i = 0; i < typePointers_.size(); ++i) {
        const uint64_t p = typePointers_[i];
        RuntimeType t{};
        t.pointer = p;
        if (!elf.ReadU64AtVaddr(p + 0, &t.data) || !elf.ReadU32AtVaddr(p + 8, &t.bits)) {
            if (error) {
                *error = "Failed reading Il2CppType at pointer 0x" + std::to_string(p);
            }
            return false;
        }
        t.attrs = static_cast<uint16_t>(t.bits & 0xffffu);
        t.type = static_cast<uint8_t>((t.bits >> 16) & 0xffu);
        t.byref = static_cast<uint8_t>((t.bits >> 29) & 1u);
        types_[i] = t;
        pointerToIndex_[p] = static_cast<int32_t>(i);
    }

    if (metadataRegistration_.genericInstsCount > 0 && metadataRegistration_.genericInsts != 0) {
        genericInstPointers_.resize(static_cast<size_t>(metadataRegistration_.genericInstsCount), 0);
        for (size_t i = 0; i < genericInstPointers_.size(); ++i) {
            if (!elf.ReadU64AtVaddr(metadataRegistration_.genericInsts + static_cast<uint64_t>(i) * 8, &genericInstPointers_[i])) {
                if (error) {
                    *error = "Failed reading genericInst pointer array";
                }
                return false;
            }
        }
    }

    if (metadataRegistration_.methodSpecsCount > 0 && metadataRegistration_.methodSpecs != 0) {
        methodSpecs_.resize(static_cast<size_t>(metadataRegistration_.methodSpecsCount));
        for (size_t i = 0; i < methodSpecs_.size(); ++i) {
            MethodSpec s{};
            if (!elf.ReadI32AtVaddr(metadataRegistration_.methodSpecs + static_cast<uint64_t>(i) * 12 + 0, &s.methodDefinitionIndex) ||
                !elf.ReadI32AtVaddr(metadataRegistration_.methodSpecs + static_cast<uint64_t>(i) * 12 + 4, &s.classIndexIndex) ||
                !elf.ReadI32AtVaddr(metadataRegistration_.methodSpecs + static_cast<uint64_t>(i) * 12 + 8, &s.methodIndexIndex)) {
                if (error) {
                    *error = "Failed reading methodSpecs";
                }
                return false;
            }
            methodSpecs_[i] = s;
        }
    }

    if (metadataRegistration_.genericMethodTableCount > 0 && metadataRegistration_.genericMethodTable != 0) {
        const uint64_t entrySize = (metadataVersion >= 27.1) ? 16 : 12;
        genericMethodTable_.resize(static_cast<size_t>(metadataRegistration_.genericMethodTableCount));
        for (size_t i = 0; i < genericMethodTable_.size(); ++i) {
            GenericMethodTableEntry e{};
            const uint64_t base = metadataRegistration_.genericMethodTable + static_cast<uint64_t>(i) * entrySize;
            if (!elf.ReadI32AtVaddr(base + 0, &e.genericMethodIndex) || !elf.ReadI32AtVaddr(base + 4, &e.methodIndex)) {
                if (error) {
                    *error = "Failed reading genericMethodTable";
                }
                return false;
            }
            genericMethodTable_[i] = e;
        }
    }

    return true;
}

const RuntimeType* RuntimeTypeSystem::GetTypeByIndex(int32_t index) const {
    if (index < 0 || static_cast<size_t>(index) >= types_.size()) {
        return nullptr;
    }
    return &types_[static_cast<size_t>(index)];
}

const RuntimeType* RuntimeTypeSystem::GetTypeByPointer(uint64_t pointer) const {
    const int32_t index = FindTypeIndexByPointer(pointer);
    if (index >= 0) {
        return &types_[static_cast<size_t>(index)];
    }
    const auto cacheIt = pointerTypeCache_.find(pointer);
    if (cacheIt != pointerTypeCache_.end()) {
        return &cacheIt->second;
    }
    if (pointer == 0 || elf_ == nullptr) {
        return nullptr;
    }
    RuntimeType t{};
    t.pointer = pointer;
    if (!elf_->ReadU64AtVaddr(pointer + 0, &t.data) || !elf_->ReadU32AtVaddr(pointer + 8, &t.bits)) {
        return nullptr;
    }
    t.attrs = static_cast<uint16_t>(t.bits & 0xffffu);
    t.type = static_cast<uint8_t>((t.bits >> 16) & 0xffu);
    t.byref = static_cast<uint8_t>((t.bits >> 29) & 1u);
    const auto [it, inserted] = pointerTypeCache_.emplace(pointer, t);
    (void)inserted;
    return &it->second;
}

int32_t RuntimeTypeSystem::FindTypeIndexByPointer(uint64_t pointer) const {
    const auto it = pointerToIndex_.find(pointer);
    if (it == pointerToIndex_.end()) {
        return -1;
    }
    return it->second;
}

bool RuntimeTypeSystem::GetGenericInstArgTypePointers(const ElfImage& elf, int32_t genericInstIndex, std::vector<uint64_t>* out) const {
    out->clear();
    if (genericInstIndex < 0 || static_cast<size_t>(genericInstIndex) >= genericInstPointers_.size()) {
        return false;
    }
    const uint64_t p = genericInstPointers_[static_cast<size_t>(genericInstIndex)];
    if (p == 0) {
        return false;
    }
    uint64_t argc = 0;
    uint64_t argv = 0;
    if (!elf.ReadU64AtVaddr(p + 0, &argc) || !elf.ReadU64AtVaddr(p + 8, &argv)) {
        return false;
    }
    if (argc > 1024) {
        return false;
    }
    out->resize(static_cast<size_t>(argc), 0);
    for (size_t i = 0; i < out->size(); ++i) {
        if (!elf.ReadU64AtVaddr(argv + static_cast<uint64_t>(i) * 8, &(*out)[i])) {
            out->resize(i);
            return false;
        }
    }
    return true;
}

int32_t RuntimeTypeSystem::GetFieldOffsetFromIndex(const ElfImage& elf, double metadataVersion, int32_t typeIndex, int32_t fieldIndexInType,
                                                   int32_t fieldIndex, bool isValueType, bool isStatic) const {
    (void)metadataVersion;
    try {
        int32_t offset = -1;
        if (fieldOffsetsArePointers_) {
            if (typeIndex < 0 || static_cast<size_t>(typeIndex) >= fieldOffsets_.size()) {
                return -1;
            }
            const uint64_t ptr = fieldOffsets_[static_cast<size_t>(typeIndex)];
            if (ptr > 0) {
                if (!elf.ReadI32AtVaddr(ptr + static_cast<uint64_t>(fieldIndexInType) * 4, &offset)) {
                    return -1;
                }
            }
        } else {
            if (fieldIndex < 0 || static_cast<size_t>(fieldIndex) >= fieldOffsets_.size()) {
                return -1;
            }
            offset = static_cast<int32_t>(fieldOffsets_[static_cast<size_t>(fieldIndex)]);
        }
        if (offset > 0 && isValueType && !isStatic) {
            offset -= 16; // 64-bit object header adjustment.
        }
        return offset;
    } catch (...) {
        return -1;
    }
}

} // namespace SwitchPort
