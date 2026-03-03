#include <cstddef>
#include <chrono>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>
#include <cstdarg>
#include <cstdio>
#include <sys/stat.h>

#ifdef __SWITCH__
#include <switch.h>
#endif

#include "SwitchPort/ElfImage.h"
#include "SwitchPort/MetadataFile.h"
#include "SwitchPort/Nx2ElfLite.h"
#include "SwitchPort/RegistrationFinder.h"
#include "SwitchPort/RuntimeTypeSystem.h"

namespace {
namespace fs = std::filesystem;

constexpr uint32_t kTypeVisibilityMask = 0x00000007u;
constexpr uint32_t kTypeNotPublic = 0x00000000u;
constexpr uint32_t kTypePublic = 0x00000001u;
constexpr uint32_t kTypeNestedPublic = 0x00000002u;
constexpr uint32_t kTypeNestedPrivate = 0x00000003u;
constexpr uint32_t kTypeNestedFamily = 0x00000004u;
constexpr uint32_t kTypeNestedAssembly = 0x00000005u;
constexpr uint32_t kTypeNestedFamAndAssem = 0x00000006u;
constexpr uint32_t kTypeNestedFamOrAssem = 0x00000007u;
constexpr uint32_t kTypeInterface = 0x00000020u;
constexpr uint32_t kTypeAbstract = 0x00000080u;
constexpr uint32_t kTypeSealed = 0x00000100u;
constexpr uint32_t kTypeSerializable = 0x00002000u;

constexpr uint16_t kMethodMemberAccessMask = 0x0007u;
constexpr uint16_t kMethodPrivate = 0x0001u;
constexpr uint16_t kMethodFamAndAssem = 0x0002u;
constexpr uint16_t kMethodAssembly = 0x0003u;
constexpr uint16_t kMethodFamily = 0x0004u;
constexpr uint16_t kMethodFamOrAssem = 0x0005u;
constexpr uint16_t kMethodPublic = 0x0006u;
constexpr uint16_t kMethodStatic = 0x0010u;
constexpr uint16_t kMethodFinal = 0x0020u;
constexpr uint16_t kMethodVirtual = 0x0040u;
constexpr uint16_t kMethodVtableLayoutMask = 0x0100u;
constexpr uint16_t kMethodReuseSlot = 0x0000u;
constexpr uint16_t kMethodNewSlot = 0x0100u;
constexpr uint16_t kMethodAbstract = 0x0400u;
constexpr uint16_t kMethodPInvokeImpl = 0x2000u;

constexpr uint16_t kParamAttributeIn = 0x0001u;
constexpr uint16_t kParamAttributeOut = 0x0002u;

constexpr uint16_t kFieldAccessMask = 0x0007u;
constexpr uint16_t kFieldPrivate = 0x0001u;
constexpr uint16_t kFieldFamAndAssem = 0x0002u;
constexpr uint16_t kFieldAssembly = 0x0003u;
constexpr uint16_t kFieldFamily = 0x0004u;
constexpr uint16_t kFieldFamOrAssem = 0x0005u;
constexpr uint16_t kFieldPublic = 0x0006u;
constexpr uint16_t kFieldStatic = 0x0010u;
constexpr uint16_t kFieldInitOnly = 0x0020u;
constexpr uint16_t kFieldLiteral = 0x0040u;

constexpr uint8_t kIl2CppTypeVoid = 0x01;
constexpr uint8_t kIl2CppTypeBoolean = 0x02;
constexpr uint8_t kIl2CppTypeChar = 0x03;
constexpr uint8_t kIl2CppTypeI1 = 0x04;
constexpr uint8_t kIl2CppTypeU1 = 0x05;
constexpr uint8_t kIl2CppTypeI2 = 0x06;
constexpr uint8_t kIl2CppTypeU2 = 0x07;
constexpr uint8_t kIl2CppTypeI4 = 0x08;
constexpr uint8_t kIl2CppTypeU4 = 0x09;
constexpr uint8_t kIl2CppTypeI8 = 0x0a;
constexpr uint8_t kIl2CppTypeU8 = 0x0b;
constexpr uint8_t kIl2CppTypeR4 = 0x0c;
constexpr uint8_t kIl2CppTypeR8 = 0x0d;
constexpr uint8_t kIl2CppTypeString = 0x0e;
constexpr uint8_t kIl2CppTypePtr = 0x0f;
constexpr uint8_t kIl2CppTypeValueType = 0x11;
constexpr uint8_t kIl2CppTypeClass = 0x12;
constexpr uint8_t kIl2CppTypeVar = 0x13;
constexpr uint8_t kIl2CppTypeArray = 0x14;
constexpr uint8_t kIl2CppTypeGenericInst = 0x15;
constexpr uint8_t kIl2CppTypeTypedByRef = 0x16;
constexpr uint8_t kIl2CppTypeI = 0x18;
constexpr uint8_t kIl2CppTypeU = 0x19;
constexpr uint8_t kIl2CppTypeObject = 0x1c;
constexpr uint8_t kIl2CppTypeSzArray = 0x1d;
constexpr uint8_t kIl2CppTypeMVar = 0x1e;
constexpr uint8_t kIl2CppTypeEnumSentinel = 0x55;
constexpr uint8_t kIl2CppTypeIl2CppTypeIndex = 0xff;

std::string TypeKeyword(const SwitchPort::TypeDefinition& type) {
    if ((type.flags & kTypeInterface) != 0) {
        return "interface";
    }
    if (type.IsEnum()) {
        return "enum";
    }
    if (type.IsValueType()) {
        return "struct";
    }
    return "class";
}

std::string TypeVisibility(uint32_t flags) {
    switch (flags & kTypeVisibilityMask) {
        case kTypePublic:
        case kTypeNestedPublic:
            return "public";
        case kTypeNestedPrivate:
            return "private";
        case kTypeNestedFamily:
            return "protected";
        case kTypeNestedFamOrAssem:
            return "protected internal";
        case kTypeNestedAssembly:
        case kTypeNestedFamAndAssem:
        case kTypeNotPublic:
        default:
            return "internal";
    }
}

std::string TypeModifiers(const SwitchPort::TypeDefinition& type) {
    if ((type.flags & kTypeInterface) != 0) {
        return "";
    }
    if ((type.flags & kTypeAbstract) != 0 && (type.flags & kTypeSealed) != 0) {
        return " static";
    }
    if ((type.flags & kTypeAbstract) != 0 && !type.IsEnum() && !type.IsValueType()) {
        return " abstract";
    }
    if ((type.flags & kTypeSealed) != 0 && !type.IsEnum() && !type.IsValueType()) {
        return " sealed";
    }
    return "";
}

std::string MethodModifiers(uint16_t flags) {
    std::string out;
    switch (flags & kMethodMemberAccessMask) {
        case kMethodPublic:
            out = "public";
            break;
        case kMethodPrivate:
            out = "private";
            break;
        case kMethodFamily:
            out = "protected";
            break;
        case kMethodFamOrAssem:
            out = "protected internal";
            break;
        case kMethodAssembly:
        case kMethodFamAndAssem:
        default:
            out = "internal";
            break;
    }
    if ((flags & kMethodStatic) != 0) {
        out += " static";
    }
    if ((flags & kMethodAbstract) != 0) {
        out += " abstract";
        if ((flags & kMethodVtableLayoutMask) == kMethodReuseSlot) {
            out += " override";
        }
    } else if ((flags & kMethodFinal) != 0) {
        if ((flags & kMethodVtableLayoutMask) == kMethodReuseSlot) {
            out += " sealed override";
        }
    } else if ((flags & kMethodVirtual) != 0) {
        if ((flags & kMethodVtableLayoutMask) == kMethodNewSlot) {
            out += " virtual";
        } else {
            out += " override";
        }
    }
    if ((flags & kMethodPInvokeImpl) != 0) {
        out += " extern";
    }
    return out;
}

std::string PseudoTypeName(int32_t typeIndex) {
    return "Il2CppType_" + std::to_string(typeIndex);
}

std::string FieldModifiers(uint16_t attrs) {
    std::string out;
    switch (attrs & kFieldAccessMask) {
        case kFieldPublic:
            out = "public";
            break;
        case kFieldPrivate:
            out = "private";
            break;
        case kFieldFamily:
            out = "protected";
            break;
        case kFieldFamOrAssem:
            out = "protected internal";
            break;
        case kFieldAssembly:
        case kFieldFamAndAssem:
        default:
            out = "internal";
            break;
    }
    if ((attrs & kFieldLiteral) != 0) {
        out += " const";
    } else {
        if ((attrs & kFieldStatic) != 0) {
            out += " static";
        }
        if ((attrs & kFieldInitOnly) != 0) {
            out += " readonly";
        }
    }
    return out;
}

std::string StripGenericArity(const std::string& name);

std::string BuildTypeDefName(const SwitchPort::MetadataFile& metadata, size_t typeIndex,
                             const std::unordered_map<size_t, size_t>& nestedParents,
                             std::unordered_map<size_t, std::string>& cache) {
    const auto found = cache.find(typeIndex);
    if (found != cache.end()) {
        return found->second;
    }

    const auto& types = metadata.Types();
    if (typeIndex >= types.size()) {
        return "Type_" + std::to_string(typeIndex);
    }

    const auto& type = types[typeIndex];
    std::string name = StripGenericArity(metadata.GetString(type.nameIndex));
    if (name.empty()) {
        name = "Type_" + std::to_string(typeIndex);
    }
    const auto parentIt = nestedParents.find(typeIndex);
    if (parentIt != nestedParents.end()) {
        name = BuildTypeDefName(metadata, parentIt->second, nestedParents, cache) + "." + name;
    }
    if (type.genericContainerIndex >= 0 && static_cast<size_t>(type.genericContainerIndex) < metadata.GenericContainers().size()) {
        const auto& gc = metadata.GenericContainers()[static_cast<size_t>(type.genericContainerIndex)];
        if (gc.typeArgc > 0 && gc.genericParameterStart >= 0) {
            name += "<";
            bool first = true;
            for (int32_t i = 0; i < gc.typeArgc; ++i) {
                if (!first) {
                    name += ", ";
                }
                first = false;
                const int32_t gpIndex = gc.genericParameterStart + i;
                std::string gpName = "T" + std::to_string(i);
                if (gpIndex >= 0 && static_cast<size_t>(gpIndex) < metadata.GenericParameters().size()) {
                    const auto& gp = metadata.GenericParameters()[static_cast<size_t>(gpIndex)];
                    const std::string n = metadata.GetString(gp.nameIndex);
                    if (!n.empty()) {
                        gpName = n;
                    }
                }
                name += gpName;
            }
            name += ">";
        }
    }

    cache[typeIndex] = name;
    return name;
}

std::string StripGenericArity(const std::string& name) {
    std::string out = name;
    const size_t tick = out.find('`');
    if (tick == std::string::npos) {
        return out;
    }
    size_t end = tick + 1;
    while (end < out.size() && out[end] >= '0' && out[end] <= '9') {
        ++end;
    }
    out.erase(tick, end - tick);
    return out;
}

std::string StripGenericParams(const std::string& name) {
    std::string out;
    out.reserve(name.size());
    int depth = 0;
    for (char c : name) {
        if (c == '<') {
            ++depth;
            continue;
        }
        if (c == '>') {
            if (depth > 0) {
                --depth;
            }
            continue;
        }
        if (depth == 0) {
            out.push_back(c);
        }
    }
    return out;
}

std::string PrimitiveTypeName(uint8_t type) {
    switch (type) {
        case kIl2CppTypeVoid:
            return "void";
        case kIl2CppTypeBoolean:
            return "bool";
        case kIl2CppTypeChar:
            return "char";
        case kIl2CppTypeI1:
            return "sbyte";
        case kIl2CppTypeU1:
            return "byte";
        case kIl2CppTypeI2:
            return "short";
        case kIl2CppTypeU2:
            return "ushort";
        case kIl2CppTypeI4:
            return "int";
        case kIl2CppTypeU4:
            return "uint";
        case kIl2CppTypeI8:
            return "long";
        case kIl2CppTypeU8:
            return "ulong";
        case kIl2CppTypeR4:
            return "float";
        case kIl2CppTypeR8:
            return "double";
        case kIl2CppTypeString:
            return "string";
        case kIl2CppTypeTypedByRef:
            return "TypedReference";
        case kIl2CppTypeI:
            return "IntPtr";
        case kIl2CppTypeU:
            return "UIntPtr";
        case kIl2CppTypeObject:
            return "object";
        default:
            return "";
    }
}

std::string ResolveTypeName(const SwitchPort::MetadataFile& metadata, const SwitchPort::RuntimeTypeSystem* runtimeTypes,
                            const SwitchPort::ElfImage* elfImage, int32_t typeIndex,
                            const std::unordered_map<size_t, size_t>& nestedParents,
                            std::unordered_map<size_t, std::string>& typeDefNameCache, int depth = 0);

std::string ResolveRuntimeType(const SwitchPort::MetadataFile& metadata, const SwitchPort::RuntimeTypeSystem* runtimeTypes,
                               const SwitchPort::ElfImage* elfImage, const SwitchPort::RuntimeType& rt,
                               const std::unordered_map<size_t, size_t>& nestedParents,
                               std::unordered_map<size_t, std::string>& typeDefNameCache, int depth = 0) {
    if (depth > 12) {
        return "";
    }
    if (const std::string primitive = PrimitiveTypeName(rt.type); !primitive.empty()) {
        return primitive;
    }
    if (rt.type == kIl2CppTypeClass || rt.type == kIl2CppTypeValueType) {
        const uint64_t klassIndex = rt.data;
        if (klassIndex < metadata.Types().size()) {
            return BuildTypeDefName(metadata, static_cast<size_t>(klassIndex), nestedParents, typeDefNameCache);
        }
    }
    if (rt.type == kIl2CppTypeVar) {
        if (rt.data < metadata.GenericParameters().size()) {
            const auto& gp = metadata.GenericParameters()[static_cast<size_t>(rt.data)];
            const std::string n = metadata.GetString(gp.nameIndex);
            if (!n.empty()) {
                return n;
            }
        }
        return "T" + std::to_string(rt.data);
    }
    if (rt.type == kIl2CppTypeMVar) {
        if (rt.data < metadata.GenericParameters().size()) {
            const auto& gp = metadata.GenericParameters()[static_cast<size_t>(rt.data)];
            const std::string n = metadata.GetString(gp.nameIndex);
            if (!n.empty()) {
                return n;
            }
        }
        return "M" + std::to_string(rt.data);
    }
    if (rt.type == kIl2CppTypePtr || rt.type == kIl2CppTypeSzArray) {
        const auto* elemRt = runtimeTypes ? runtimeTypes->GetTypeByPointer(rt.data) : nullptr;
        const std::string elemName =
            (elemRt != nullptr) ? ResolveRuntimeType(metadata, runtimeTypes, elfImage, *elemRt, nestedParents, typeDefNameCache, depth + 1)
                                : PseudoTypeName(-1);
        if (rt.type == kIl2CppTypePtr) {
            return elemName + "*";
        }
        return elemName + "[]";
    }
    if (rt.type == kIl2CppTypeArray && elfImage != nullptr) {
        uint64_t elemTypePtr = 0;
        uint8_t rank = 1;
        if (elfImage->ReadU64AtVaddr(rt.data + 0, &elemTypePtr)) {
            (void)elfImage->ReadU8AtVaddr(rt.data + 8, &rank);
            const auto* elemRt = runtimeTypes ? runtimeTypes->GetTypeByPointer(elemTypePtr) : nullptr;
            std::string elemName = (elemRt != nullptr)
                                       ? ResolveRuntimeType(metadata, runtimeTypes, elfImage, *elemRt, nestedParents, typeDefNameCache,
                                                            depth + 1)
                                       : PseudoTypeName(-1);
            if (rank <= 1) {
                return elemName + "[]";
            }
            return elemName + "[" + std::string(static_cast<size_t>(rank - 1), ',') + "]";
        }
    }
    if (rt.type == kIl2CppTypeGenericInst && elfImage != nullptr && runtimeTypes != nullptr) {
        uint64_t genericTypePtr = 0;
        uint64_t classInst = 0;
        if (elfImage->ReadU64AtVaddr(rt.data + 0, &genericTypePtr) && elfImage->ReadU64AtVaddr(rt.data + 8, &classInst)) {
            std::string baseName;
            if (const auto* baseRt = runtimeTypes->GetTypeByPointer(genericTypePtr); baseRt != nullptr) {
                baseName = ResolveRuntimeType(metadata, runtimeTypes, elfImage, *baseRt, nestedParents, typeDefNameCache, depth + 1);
            }
            if (baseName.empty()) {
                baseName = "Il2CppType_" + std::to_string(static_cast<unsigned long long>(genericTypePtr));
            }
            baseName = StripGenericArity(baseName);
            baseName = StripGenericParams(baseName);
            if (classInst != 0) {
                uint64_t argcRaw = 0;
                uint64_t argv = 0;
                if (elfImage->ReadU64AtVaddr(classInst + 0, &argcRaw) && elfImage->ReadU64AtVaddr(classInst + 8, &argv) &&
                    argcRaw > 0 && argcRaw <= 64) {
                    std::vector<std::string> args;
                    args.reserve(static_cast<size_t>(argcRaw));
                    for (uint64_t ai = 0; ai < argcRaw; ++ai) {
                        uint64_t argTypePtr = 0;
                        if (!elfImage->ReadU64AtVaddr(argv + ai * 8, &argTypePtr)) {
                            break;
                        }
                        if (const auto* argRt = runtimeTypes->GetTypeByPointer(argTypePtr); argRt != nullptr) {
                            args.push_back(ResolveRuntimeType(metadata, runtimeTypes, elfImage, *argRt, nestedParents,
                                                              typeDefNameCache, depth + 1));
                        } else {
                            args.push_back("Il2CppType_" + std::to_string(static_cast<unsigned long long>(argTypePtr)));
                        }
                    }
                    if (!args.empty()) {
                        std::string rendered = baseName + "<";
                        for (size_t i = 0; i < args.size(); ++i) {
                            if (i != 0) {
                                rendered += ", ";
                            }
                            rendered += args[i];
                        }
                        rendered += ">";
                        return rendered;
                    }
                }
            }
            return baseName;
        }
    }
    return "";
}

std::string ResolveTypeName(const SwitchPort::MetadataFile& metadata, const SwitchPort::RuntimeTypeSystem* runtimeTypes,
                            const SwitchPort::ElfImage* elfImage, int32_t typeIndex,
                            const std::unordered_map<size_t, size_t>& nestedParents,
                            std::unordered_map<size_t, std::string>& typeDefNameCache, int depth) {
    if (runtimeTypes == nullptr) {
        return PseudoTypeName(typeIndex);
    }
    const auto* rt = runtimeTypes->GetTypeByIndex(typeIndex);
    if (rt == nullptr) {
        return PseudoTypeName(typeIndex);
    }
    const std::string resolved = ResolveRuntimeType(metadata, runtimeTypes, elfImage, *rt, nestedParents, typeDefNameCache, depth);
    if (!resolved.empty()) {
        return resolved;
    }
    return PseudoTypeName(typeIndex);
}

std::string FormatFieldDefaultValue(const SwitchPort::MetadataFile& metadata, const SwitchPort::RuntimeTypeSystem* runtimeTypes,
                                    const SwitchPort::FieldDefaultValue& fdv) {
    auto readCompressedUInt32 = [&](uint32_t absOffset, uint32_t* out, uint32_t* bytesRead) -> bool {
        uint8_t first = 0;
        if (!metadata.ReadU8AtMetadataOffset(absOffset, &first)) {
            return false;
        }
        if ((first & 0x80u) == 0) {
            *out = first;
            *bytesRead = 1;
            return true;
        }
        if ((first & 0xC0u) == 0x80u) {
            uint8_t b1 = 0;
            if (!metadata.ReadU8AtMetadataOffset(absOffset + 1, &b1)) {
                return false;
            }
            *out = ((first & ~0x80u) << 8) | b1;
            *bytesRead = 2;
            return true;
        }
        if ((first & 0xE0u) == 0xC0u) {
            uint8_t b1 = 0, b2 = 0, b3 = 0;
            if (!metadata.ReadU8AtMetadataOffset(absOffset + 1, &b1) || !metadata.ReadU8AtMetadataOffset(absOffset + 2, &b2) ||
                !metadata.ReadU8AtMetadataOffset(absOffset + 3, &b3)) {
                return false;
            }
            *out = ((first & ~0xC0u) << 24) | (static_cast<uint32_t>(b1) << 16) | (static_cast<uint32_t>(b2) << 8) |
                   static_cast<uint32_t>(b3);
            *bytesRead = 4;
            return true;
        }
        if (first == 0xF0u) {
            if (!metadata.ReadU32AtMetadataOffset(absOffset + 1, out)) {
                return false;
            }
            *bytesRead = 5;
            return true;
        }
        if (first == 0xFEu) {
            *out = 0xFFFFFFFEu;
            *bytesRead = 1;
            return true;
        }
        if (first == 0xFFu) {
            *out = 0xFFFFFFFFu;
            *bytesRead = 1;
            return true;
        }
        return false;
    };

    auto readCompressedInt32 = [&](uint32_t absOffset, int32_t* out, uint32_t* bytesRead) -> bool {
        uint32_t encoded = 0;
        if (!readCompressedUInt32(absOffset, &encoded, bytesRead)) {
            return false;
        }
        if (encoded == 0xFFFFFFFFu) {
            *out = static_cast<int32_t>(0x80000000u);
            return true;
        }
        const bool isNegative = (encoded & 1u) != 0;
        encoded >>= 1;
        if (isNegative) {
            *out = -static_cast<int32_t>(encoded + 1);
        } else {
            *out = static_cast<int32_t>(encoded);
        }
        return true;
    };

    const uint32_t abs = metadata.Header().fieldAndParameterDefaultValueDataOffset + static_cast<uint32_t>(fdv.dataIndex);
    const auto* rt = runtimeTypes ? runtimeTypes->GetTypeByIndex(fdv.typeIndex) : nullptr;
    const uint8_t type = rt ? rt->type : 0;
    if (type == kIl2CppTypeBoolean) {
        uint8_t v = 0;
        if (metadata.ReadU8AtMetadataOffset(abs, &v)) {
            return v ? "True" : "False";
        }
    } else if (type == kIl2CppTypeI1) {
        int8_t v = 0;
        if (metadata.ReadI8AtMetadataOffset(abs, &v)) {
            return std::to_string(static_cast<int>(v));
        }
    } else if (type == kIl2CppTypeU1) {
        uint8_t v = 0;
        if (metadata.ReadU8AtMetadataOffset(abs, &v)) {
            return std::to_string(static_cast<unsigned int>(v));
        }
    } else if (type == kIl2CppTypeI2) {
        int16_t v = 0;
        if (metadata.ReadI16AtMetadataOffset(abs, &v)) {
            return std::to_string(v);
        }
    } else if (type == kIl2CppTypeU2) {
        uint16_t v = 0;
        if (metadata.ReadU16AtMetadataOffset(abs, &v)) {
            return std::to_string(v);
        }
    } else if (type == kIl2CppTypeI4) {
        int32_t v = 0;
        uint32_t bytesRead = 0;
        if (metadata.Header().version >= 29 ? readCompressedInt32(abs, &v, &bytesRead) : metadata.ReadI32AtMetadataOffset(abs, &v)) {
            return std::to_string(v);
        }
    } else if (type == kIl2CppTypeU4) {
        uint32_t v = 0;
        uint32_t bytesRead = 0;
        if (metadata.Header().version >= 29 ? readCompressedUInt32(abs, &v, &bytesRead) : metadata.ReadU32AtMetadataOffset(abs, &v)) {
            return std::to_string(v);
        }
    } else if (type == kIl2CppTypeI8) {
        int64_t v = 0;
        if (metadata.ReadI64AtMetadataOffset(abs, &v)) {
            return std::to_string(v);
        }
    } else if (type == kIl2CppTypeU8) {
        uint64_t v = 0;
        if (metadata.ReadU64AtMetadataOffset(abs, &v)) {
            return std::to_string(v);
        }
    } else if (type == kIl2CppTypeR4) {
        float v = 0;
        if (metadata.ReadF32AtMetadataOffset(abs, &v)) {
            return std::to_string(v) + "f";
        }
    } else if (type == kIl2CppTypeR8) {
        double v = 0;
        if (metadata.ReadF64AtMetadataOffset(abs, &v)) {
            return std::to_string(v);
        }
    } else if (type == kIl2CppTypeString) {
        std::string s;
        if (metadata.Header().version >= 29) {
            int32_t length = 0;
            uint32_t bytesRead = 0;
            if (!readCompressedInt32(abs, &length, &bytesRead)) {
                return "";
            }
            if (length < 0) {
                return "null";
            }
            uint32_t dataOff = abs + bytesRead;
            uint8_t ch = 0;
            s.clear();
            s.reserve(static_cast<size_t>(length));
            for (int32_t i = 0; i < length; ++i) {
                if (!metadata.ReadU8AtMetadataOffset(dataOff + static_cast<uint32_t>(i), &ch)) {
                    return "";
                }
                s.push_back(static_cast<char>(ch));
            }
        } else if (metadata.ReadStringBlobAtMetadataOffset(abs, &s)) {
        } else {
            return "";
        }
        std::string escaped;
        escaped.reserve(s.size());
        for (char c : s) {
            if (c == '\\' || c == '"') {
                escaped.push_back('\\');
            }
            escaped.push_back(c);
        }
        return "\"" + escaped + "\"";
    }
    return "";
}

std::string FormatDefaultValue(const SwitchPort::MetadataFile& metadata, const SwitchPort::RuntimeTypeSystem* runtimeTypes, int32_t typeIndex,
                               int32_t dataIndex) {
    SwitchPort::FieldDefaultValue fdv{};
    fdv.typeIndex = typeIndex;
    fdv.dataIndex = dataIndex;
    return FormatFieldDefaultValue(metadata, runtimeTypes, fdv);
}

bool ReadCompressedUInt32At(const SwitchPort::MetadataFile& metadata, uint32_t absOffset, uint32_t* out, uint32_t* bytesRead) {
    uint8_t first = 0;
    if (!metadata.ReadU8AtMetadataOffset(absOffset, &first)) {
        return false;
    }
    if ((first & 0x80u) == 0) {
        *out = first;
        *bytesRead = 1;
        return true;
    }
    if ((first & 0xC0u) == 0x80u) {
        uint8_t b1 = 0;
        if (!metadata.ReadU8AtMetadataOffset(absOffset + 1, &b1)) {
            return false;
        }
        *out = ((first & ~0x80u) << 8) | b1;
        *bytesRead = 2;
        return true;
    }
    if ((first & 0xE0u) == 0xC0u) {
        uint8_t b1 = 0, b2 = 0, b3 = 0;
        if (!metadata.ReadU8AtMetadataOffset(absOffset + 1, &b1) || !metadata.ReadU8AtMetadataOffset(absOffset + 2, &b2) ||
            !metadata.ReadU8AtMetadataOffset(absOffset + 3, &b3)) {
            return false;
        }
        *out = ((first & ~0xC0u) << 24) | (static_cast<uint32_t>(b1) << 16) | (static_cast<uint32_t>(b2) << 8) |
               static_cast<uint32_t>(b3);
        *bytesRead = 4;
        return true;
    }
    if (first == 0xF0u) {
        if (!metadata.ReadU32AtMetadataOffset(absOffset + 1, out)) {
            return false;
        }
        *bytesRead = 5;
        return true;
    }
    if (first == 0xFEu) {
        *out = 0xFFFFFFFEu;
        *bytesRead = 1;
        return true;
    }
    if (first == 0xFFu) {
        *out = 0xFFFFFFFFu;
        *bytesRead = 1;
        return true;
    }
    return false;
}

bool ReadCompressedInt32At(const SwitchPort::MetadataFile& metadata, uint32_t absOffset, int32_t* out, uint32_t* bytesRead) {
    uint32_t encoded = 0;
    if (!ReadCompressedUInt32At(metadata, absOffset, &encoded, bytesRead)) {
        return false;
    }
    if (encoded == 0xFFFFFFFFu) {
        *out = static_cast<int32_t>(0x80000000u);
        return true;
    }
    const bool isNegative = (encoded & 1u) != 0;
    encoded >>= 1;
    if (isNegative) {
        *out = -static_cast<int32_t>(encoded + 1);
    } else {
        *out = static_cast<int32_t>(encoded);
    }
    return true;
}

std::string StripAttributeSuffix(const std::string& name) {
    std::string out = name;
    const std::string needle = "Attribute";
    size_t pos = 0;
    while ((pos = out.find(needle, pos)) != std::string::npos) {
        out.erase(pos, needle.size());
    }
    return out;
}

std::string DecodeAttributeValueToString(const SwitchPort::MetadataFile& metadata, const SwitchPort::RuntimeTypeSystem* runtimeTypes,
                                         const SwitchPort::ElfImage* elfImage,
                                         const std::unordered_map<size_t, size_t>& nestedParents,
                                         std::unordered_map<size_t, std::string>& typeDefNameCache, uint8_t valueType, uint32_t* cursor,
                                         int depth) {
    if (depth > 16) {
        return "null";
    }
    if (valueType == kIl2CppTypeBoolean) {
        uint8_t v = 0;
        if (!metadata.ReadU8AtMetadataOffset(*cursor, &v)) {
            return "null";
        }
        *cursor += 1;
        return v ? "True" : "False";
    }
    if (valueType == kIl2CppTypeI1) {
        int8_t v = 0;
        if (!metadata.ReadI8AtMetadataOffset(*cursor, &v)) {
            return "null";
        }
        *cursor += 1;
        return std::to_string(static_cast<int>(v));
    }
    if (valueType == kIl2CppTypeU1) {
        uint8_t v = 0;
        if (!metadata.ReadU8AtMetadataOffset(*cursor, &v)) {
            return "null";
        }
        *cursor += 1;
        return std::to_string(static_cast<unsigned int>(v));
    }
    if (valueType == kIl2CppTypeI2 || valueType == kIl2CppTypeChar) {
        int16_t v = 0;
        if (!metadata.ReadI16AtMetadataOffset(*cursor, &v)) {
            return "null";
        }
        *cursor += 2;
        return std::to_string(v);
    }
    if (valueType == kIl2CppTypeU2) {
        uint16_t v = 0;
        if (!metadata.ReadU16AtMetadataOffset(*cursor, &v)) {
            return "null";
        }
        *cursor += 2;
        return std::to_string(v);
    }
    if (valueType == kIl2CppTypeI4) {
        int32_t v = 0;
        uint32_t br = 0;
        if (!ReadCompressedInt32At(metadata, *cursor, &v, &br)) {
            return "null";
        }
        *cursor += br;
        return std::to_string(v);
    }
    if (valueType == kIl2CppTypeU4) {
        uint32_t v = 0;
        uint32_t br = 0;
        if (!ReadCompressedUInt32At(metadata, *cursor, &v, &br)) {
            return "null";
        }
        *cursor += br;
        return std::to_string(v);
    }
    if (valueType == kIl2CppTypeI8) {
        int64_t v = 0;
        if (!metadata.ReadI64AtMetadataOffset(*cursor, &v)) {
            return "null";
        }
        *cursor += 8;
        return std::to_string(v);
    }
    if (valueType == kIl2CppTypeU8) {
        uint64_t v = 0;
        if (!metadata.ReadU64AtMetadataOffset(*cursor, &v)) {
            return "null";
        }
        *cursor += 8;
        return std::to_string(v);
    }
    if (valueType == kIl2CppTypeR4) {
        float v = 0;
        if (!metadata.ReadF32AtMetadataOffset(*cursor, &v)) {
            return "null";
        }
        *cursor += 4;
        return std::to_string(v) + "f";
    }
    if (valueType == kIl2CppTypeR8) {
        double v = 0;
        if (!metadata.ReadF64AtMetadataOffset(*cursor, &v)) {
            return "null";
        }
        *cursor += 8;
        return std::to_string(v);
    }
    if (valueType == kIl2CppTypeString) {
        int32_t len = 0;
        uint32_t br = 0;
        if (!ReadCompressedInt32At(metadata, *cursor, &len, &br)) {
            return "null";
        }
        *cursor += br;
        if (len < 0) {
            return "null";
        }
        std::string s;
        s.reserve(static_cast<size_t>(len));
        for (int32_t i = 0; i < len; ++i) {
            uint8_t ch = 0;
            if (!metadata.ReadU8AtMetadataOffset(*cursor + static_cast<uint32_t>(i), &ch)) {
                return "null";
            }
            s.push_back(static_cast<char>(ch));
        }
        *cursor += static_cast<uint32_t>(len);
        std::string escaped;
        for (char c : s) {
            if (c == '\\' || c == '"') {
                escaped.push_back('\\');
            }
            escaped.push_back(c);
        }
        return "\"" + escaped + "\"";
    }
    if (valueType == kIl2CppTypeIl2CppTypeIndex) {
        int32_t tIndex = -1;
        uint32_t br = 0;
        if (!ReadCompressedInt32At(metadata, *cursor, &tIndex, &br)) {
            return "null";
        }
        *cursor += br;
        if (tIndex < 0) {
            return "null";
        }
        return "typeof(" + ResolveTypeName(metadata, runtimeTypes, elfImage, tIndex, nestedParents, typeDefNameCache) + ")";
    }
    if (valueType == kIl2CppTypeSzArray) {
        int32_t arrayLen = -1;
        uint32_t br = 0;
        if (!ReadCompressedInt32At(metadata, *cursor, &arrayLen, &br)) {
            return "null";
        }
        *cursor += br;
        if (arrayLen < 0) {
            return "null";
        }
        uint8_t elemType = 0;
        if (!metadata.ReadU8AtMetadataOffset(*cursor, &elemType)) {
            return "null";
        }
        *cursor += 1;
        if (elemType == kIl2CppTypeEnumSentinel) {
            int32_t enumTypeIndex = -1;
            if (!ReadCompressedInt32At(metadata, *cursor, &enumTypeIndex, &br)) {
                return "null";
            }
            *cursor += br;
            const auto* enumRt = runtimeTypes ? runtimeTypes->GetTypeByIndex(enumTypeIndex) : nullptr;
            if (enumRt != nullptr && enumRt->data < metadata.Types().size()) {
                const auto& td = metadata.Types()[static_cast<size_t>(enumRt->data)];
                if (td.elementTypeIndex >= 0) {
                    const auto* underRt = runtimeTypes->GetTypeByIndex(td.elementTypeIndex);
                    if (underRt != nullptr) {
                        elemType = underRt->type;
                    }
                }
            }
        }
        uint8_t varied = 0;
        if (!metadata.ReadU8AtMetadataOffset(*cursor, &varied)) {
            return "null";
        }
        *cursor += 1;
        std::string out = "new[] { ";
        for (int32_t i = 0; i < arrayLen; ++i) {
            uint8_t current = elemType;
            if (varied == 1) {
                if (!metadata.ReadU8AtMetadataOffset(*cursor, &current)) {
                    return "null";
                }
                *cursor += 1;
            }
            if (i != 0) {
                out += ", ";
            }
            out += DecodeAttributeValueToString(metadata, runtimeTypes, elfImage, nestedParents, typeDefNameCache, current, cursor,
                                                depth + 1);
        }
        out += " }";
        return out;
    }
    return "null";
}

std::vector<std::string> GetCustomAttributesForToken(const SwitchPort::MetadataFile& metadata, const SwitchPort::RuntimeTypeSystem* runtimeTypes,
                                                     const SwitchPort::ElfImage* elfImage,
                                                     const std::unordered_map<size_t, size_t>& nestedParents,
                                                     std::unordered_map<size_t, std::string>& typeDefNameCache,
                                                     const SwitchPort::ImageDefinition& image, uint32_t token) {
    std::vector<std::string> out;
    const auto& header = metadata.Header();
    if (header.version < 29 || token == 0 || image.customAttributeStart < 0 || image.customAttributeCount == 0) {
        return out;
    }
    const auto& ranges = metadata.AttributeDataRanges();
    const size_t start = static_cast<size_t>(image.customAttributeStart);
    const size_t end = start + static_cast<size_t>(image.customAttributeCount);
    if (start >= ranges.size()) {
        return out;
    }
    size_t hit = static_cast<size_t>(-1);
    for (size_t i = start; i < end && i < ranges.size(); ++i) {
        if (ranges[i].token == token) {
            hit = i;
            break;
        }
    }
    if (hit == static_cast<size_t>(-1)) {
        return out;
    }
    const uint32_t startOff = ranges[hit].startOffset;
    const uint32_t endOff = (hit + 1 < ranges.size()) ? ranges[hit + 1].startOffset : static_cast<uint32_t>(header.attributeDataSize);
    if (endOff <= startOff) {
        return out;
    }
    const uint32_t abs = header.attributeDataOffset + startOff;
    uint32_t count = 0;
    uint32_t countBytes = 0;
    if (!ReadCompressedUInt32At(metadata, abs, &count, &countBytes)) {
        return out;
    }
    const uint32_t ctorListAbs = abs + countBytes;
    const uint32_t localDataSize = endOff - startOff;
    if (count > localDataSize / 4) {
        return out;
    }
    const auto& methods = metadata.Methods();
    const auto& types = metadata.Types();
    for (uint32_t i = 0; i < count; ++i) {
        int32_t ctorIndex = -1;
        if (!metadata.ReadI32AtMetadataOffset(ctorListAbs + i * 4, &ctorIndex)) {
            break;
        }
        if (ctorIndex < 0 || static_cast<size_t>(ctorIndex) >= methods.size()) {
            continue;
        }
        const int32_t decl = methods[static_cast<size_t>(ctorIndex)].declaringType;
        if (decl < 0 || static_cast<size_t>(decl) >= types.size()) {
            continue;
        }
        std::string attr = metadata.GetString(types[static_cast<size_t>(decl)].nameIndex);
        attr = StripGenericArity(attr);
        attr = StripAttributeSuffix(attr);
        if (attr.empty()) {
            continue;
        }
        uint32_t dataPos = ctorListAbs + count * 4;
        for (uint32_t j = 0; j < i; ++j) {
            uint32_t c = 0, b0 = 0, f = 0, b1 = 0, p = 0, b2 = 0;
            if (!ReadCompressedUInt32At(metadata, dataPos, &c, &b0)) break;
            dataPos += b0;
            if (!ReadCompressedUInt32At(metadata, dataPos, &f, &b1)) break;
            dataPos += b1;
            if (!ReadCompressedUInt32At(metadata, dataPos, &p, &b2)) break;
            dataPos += b2;
            for (uint32_t k = 0; k < c + f + p; ++k) {
                uint8_t t = 0;
                if (!metadata.ReadU8AtMetadataOffset(dataPos, &t)) break;
                dataPos += 1;
                if (t == kIl2CppTypeEnumSentinel) {
                    int32_t dummy = 0;
                    uint32_t br = 0;
                    if (!ReadCompressedInt32At(metadata, dataPos, &dummy, &br)) break;
                    dataPos += br;
                    t = kIl2CppTypeI4;
                }
                (void)DecodeAttributeValueToString(metadata, runtimeTypes, elfImage, nestedParents, typeDefNameCache, t, &dataPos, 0);
                if (k >= c) {
                    int32_t memberIndex = 0;
                    uint32_t br = 0;
                    if (!ReadCompressedInt32At(metadata, dataPos, &memberIndex, &br)) break;
                    dataPos += br;
                    if (memberIndex < 0) {
                        uint32_t dummyType = 0;
                        if (!ReadCompressedUInt32At(metadata, dataPos, &dummyType, &br)) break;
                        dataPos += br;
                    }
                }
            }
        }
        uint32_t argCount = 0, bArg = 0, fieldCount = 0, bField = 0, propCount = 0, bProp = 0;
        if (!ReadCompressedUInt32At(metadata, dataPos, &argCount, &bArg)) {
            out.push_back("[" + attr + "]");
            continue;
        }
        dataPos += bArg;
        if (!ReadCompressedUInt32At(metadata, dataPos, &fieldCount, &bField)) {
            out.push_back("[" + attr + "]");
            continue;
        }
        dataPos += bField;
        if (!ReadCompressedUInt32At(metadata, dataPos, &propCount, &bProp)) {
            out.push_back("[" + attr + "]");
            continue;
        }
        dataPos += bProp;

        std::vector<std::string> args;
        for (uint32_t ai = 0; ai < argCount; ++ai) {
            uint8_t t = 0;
            if (!metadata.ReadU8AtMetadataOffset(dataPos, &t)) {
                break;
            }
            dataPos += 1;
            if (t == kIl2CppTypeEnumSentinel) {
                int32_t enumTypeIndex = -1;
                uint32_t br = 0;
                if (!ReadCompressedInt32At(metadata, dataPos, &enumTypeIndex, &br)) {
                    break;
                }
                dataPos += br;
                const auto* enumRt = runtimeTypes ? runtimeTypes->GetTypeByIndex(enumTypeIndex) : nullptr;
                if (enumRt != nullptr && enumRt->data < metadata.Types().size()) {
                    const auto& td = metadata.Types()[static_cast<size_t>(enumRt->data)];
                    if (td.elementTypeIndex >= 0) {
                        const auto* underRt = runtimeTypes->GetTypeByIndex(td.elementTypeIndex);
                        if (underRt != nullptr) {
                            t = underRt->type;
                        }
                    }
                } else {
                    t = kIl2CppTypeI4;
                }
            }
            args.push_back(DecodeAttributeValueToString(metadata, runtimeTypes, elfImage, nestedParents, typeDefNameCache, t, &dataPos, 0));
        }
        auto readNamedArg = [&](bool isField) {
            uint8_t t = 0;
            if (!metadata.ReadU8AtMetadataOffset(dataPos, &t)) {
                return;
            }
            dataPos += 1;
            if (t == kIl2CppTypeEnumSentinel) {
                int32_t dummy = -1;
                uint32_t br = 0;
                if (!ReadCompressedInt32At(metadata, dataPos, &dummy, &br)) {
                    return;
                }
                dataPos += br;
                t = kIl2CppTypeI4;
            }
            std::string value =
                DecodeAttributeValueToString(metadata, runtimeTypes, elfImage, nestedParents, typeDefNameCache, t, &dataPos, 0);
            int32_t memberIndex = 0;
            uint32_t br = 0;
            if (!ReadCompressedInt32At(metadata, dataPos, &memberIndex, &br)) {
                return;
            }
            dataPos += br;
            int32_t ownerTypeIndex = decl;
            if (memberIndex < 0) {
                memberIndex = -(memberIndex + 1);
                uint32_t otherType = 0;
                if (!ReadCompressedUInt32At(metadata, dataPos, &otherType, &br)) {
                    return;
                }
                dataPos += br;
                ownerTypeIndex = static_cast<int32_t>(otherType);
            }
            std::string memberName = isField ? ("field_" + std::to_string(memberIndex)) : ("prop_" + std::to_string(memberIndex));
            if (ownerTypeIndex >= 0 && static_cast<size_t>(ownerTypeIndex) < types.size()) {
                const auto& owner = types[static_cast<size_t>(ownerTypeIndex)];
                if (isField) {
                    const int32_t idx = owner.fieldStart + memberIndex;
                    if (idx >= 0 && static_cast<size_t>(idx) < metadata.Fields().size()) {
                        memberName = metadata.GetString(metadata.Fields()[static_cast<size_t>(idx)].nameIndex);
                    }
                } else {
                    const int32_t idx = owner.propertyStart + memberIndex;
                    if (idx >= 0 && static_cast<size_t>(idx) < metadata.Properties().size()) {
                        memberName = metadata.GetString(metadata.Properties()[static_cast<size_t>(idx)].nameIndex);
                    }
                }
            }
            args.push_back(memberName + " = " + value);
        };
        for (uint32_t fi = 0; fi < fieldCount; ++fi) {
            readNamedArg(true);
        }
        for (uint32_t pi = 0; pi < propCount; ++pi) {
            readNamedArg(false);
        }
        if (args.empty()) {
            out.push_back("[" + attr + "]");
        } else {
            std::string line = "[" + attr + "(";
            for (size_t ai = 0; ai < args.size(); ++ai) {
                if (ai != 0) {
                    line += ", ";
                }
                line += args[ai];
            }
            line += ")]";
            out.push_back(line);
        }
    }
    return out;
}

uint64_t NormalizeCodeRegistration(double metadataVersion, uint64_t codeRegistration) {
    if (codeRegistration == 0) {
        return 0;
    }
    // Matches the high-version correction path used by Il2CppDumper for v31 targets.
    if (metadataVersion >= 31.0 && codeRegistration >= 16) {
        return codeRegistration - 16;
    }
    return codeRegistration;
}

class MethodPointerResolver {
public:
    bool Initialize(const SwitchPort::ElfImage& elf, double metadataVersion, uint64_t codeRegistrationVa) {
        moduleMethodPointers_.clear();
        genericMethodPointers_.clear();
        if (codeRegistrationVa == 0 || metadataVersion < 24.2) {
            return false;
        }

        uint64_t cursor = codeRegistrationVa;
        std::unordered_map<std::string, uint64_t> fields;
        auto readField = [&](const std::string& name, bool enabled) -> bool {
            if (!enabled) {
                return true;
            }
            uint64_t value = 0;
            if (!elf.ReadU64AtVaddr(cursor, &value)) {
                return false;
            }
            fields[name] = value;
            cursor += 8;
            return true;
        };

        if (!readField("methodPointersCount", metadataVersion <= 24.1) ||
            !readField("methodPointers", metadataVersion <= 24.1) ||
            !readField("delegateWrappersFromNativeToManagedCount", metadataVersion <= 21.0) ||
            !readField("delegateWrappersFromNativeToManaged", metadataVersion <= 21.0) ||
            !readField("reversePInvokeWrapperCount", metadataVersion >= 22.0) ||
            !readField("reversePInvokeWrappers", metadataVersion >= 22.0) ||
            !readField("delegateWrappersFromManagedToNativeCount", metadataVersion <= 22.0) ||
            !readField("delegateWrappersFromManagedToNative", metadataVersion <= 22.0) ||
            !readField("marshalingFunctionsCount", metadataVersion <= 22.0) ||
            !readField("marshalingFunctions", metadataVersion <= 22.0) ||
            !readField("ccwMarshalingFunctionsCount", metadataVersion >= 21.0 && metadataVersion <= 22.0) ||
            !readField("ccwMarshalingFunctions", metadataVersion >= 21.0 && metadataVersion <= 22.0) ||
            !readField("genericMethodPointersCount", true) || !readField("genericMethodPointers", true) ||
            !readField("genericAdjustorThunks", metadataVersion >= 27.1) ||
            !readField("invokerPointersCount", true) || !readField("invokerPointers", true) ||
            !readField("customAttributeCount", metadataVersion <= 24.5) ||
            !readField("customAttributeGenerators", metadataVersion <= 24.5) ||
            !readField("guidCount", metadataVersion >= 21.0 && metadataVersion <= 22.0) ||
            !readField("guids", metadataVersion >= 21.0 && metadataVersion <= 22.0) ||
            !readField("unresolvedVirtualCallCount", metadataVersion >= 22.0) ||
            !readField("unresolvedVirtualCallPointers", metadataVersion >= 22.0) ||
            !readField("unresolvedInstanceCallPointers", metadataVersion >= 29.1) ||
            !readField("unresolvedStaticCallPointers", metadataVersion >= 29.1) ||
            !readField("interopDataCount", metadataVersion >= 23.0) || !readField("interopData", metadataVersion >= 23.0) ||
            !readField("windowsRuntimeFactoryCount", metadataVersion >= 24.3) ||
            !readField("windowsRuntimeFactoryTable", metadataVersion >= 24.3) ||
            !readField("codeGenModulesCount", metadataVersion >= 24.2) || !readField("codeGenModules", metadataVersion >= 24.2)) {
            return false;
        }

        const uint64_t moduleCount = fields["codeGenModulesCount"];
        const uint64_t moduleTable = fields["codeGenModules"];
        const uint64_t genericMethodPointerCount = fields["genericMethodPointersCount"];
        const uint64_t genericMethodPointersVa = fields["genericMethodPointers"];
        if (genericMethodPointerCount > 0 && genericMethodPointersVa != 0) {
            genericMethodPointers_.resize(static_cast<size_t>(genericMethodPointerCount), 0);
            for (size_t i = 0; i < genericMethodPointers_.size(); ++i) {
                (void)elf.ReadU64AtVaddr(genericMethodPointersVa + static_cast<uint64_t>(i) * 8, &genericMethodPointers_[i]);
            }
        }
        if (moduleCount == 0 || moduleTable == 0) {
            return false;
        }

        for (uint64_t i = 0; i < moduleCount; ++i) {
            uint64_t moduleVa = 0;
            if (!elf.ReadU64AtVaddr(moduleTable + i * 8, &moduleVa) || moduleVa == 0) {
                continue;
            }
            uint64_t moduleNameVa = 0;
            uint64_t methodPointerCount = 0;
            uint64_t methodPointersVa = 0;
            if (!elf.ReadU64AtVaddr(moduleVa, &moduleNameVa) || !elf.ReadU64AtVaddr(moduleVa + 8, &methodPointerCount) ||
                !elf.ReadU64AtVaddr(moduleVa + 16, &methodPointersVa)) {
                continue;
            }
            std::string moduleName;
            if (!elf.ReadCStringAtVaddr(moduleNameVa, &moduleName) || moduleName.empty()) {
                continue;
            }
            std::vector<uint64_t> methodPointers;
            methodPointers.resize(static_cast<size_t>(methodPointerCount), 0);
            for (size_t mi = 0; mi < methodPointers.size(); ++mi) {
                (void)elf.ReadU64AtVaddr(methodPointersVa + static_cast<uint64_t>(mi) * 8, &methodPointers[mi]);
            }
            moduleMethodPointers_.emplace(moduleName, std::move(methodPointers));
        }
        return !moduleMethodPointers_.empty();
    }

    uint64_t GetMethodPointer(const std::string& imageName, uint32_t methodToken) const {
        const auto it = moduleMethodPointers_.find(imageName);
        if (it == moduleMethodPointers_.end()) {
            return 0;
        }
        const uint32_t methodPointerIndex = methodToken & 0x00FFFFFFu;
        if (methodPointerIndex == 0) {
            return 0;
        }
        const size_t idx = static_cast<size_t>(methodPointerIndex - 1);
        if (idx >= it->second.size()) {
            return 0;
        }
        return it->second[idx];
    }

    uint64_t GetGenericMethodPointer(int32_t methodIndex) const {
        if (methodIndex < 0 || static_cast<size_t>(methodIndex) >= genericMethodPointers_.size()) {
            return 0;
        }
        return genericMethodPointers_[static_cast<size_t>(methodIndex)];
    }

private:
    std::unordered_map<std::string, std::vector<uint64_t>> moduleMethodPointers_;
    std::vector<uint64_t> genericMethodPointers_;
};

using DumpProgressCallback = void (*)(const char* phase, size_t done, size_t total, void* user);

bool UserRequestedAbort() {
#ifdef __SWITCH__
    hidScanInput();
    return (hidKeysDown(CONTROLLER_P1_AUTO) & KEY_MINUS) != 0;
#else
    return false;
#endif
}

std::string BuildGenericInstParams(const SwitchPort::MetadataFile& metadata, const SwitchPort::RuntimeTypeSystem* runtimeTypes,
                                   const SwitchPort::ElfImage* elfImage,
                                   const std::unordered_map<size_t, size_t>& nestedParents,
                                   std::unordered_map<size_t, std::string>& typeDefNameCache, int32_t genericInstIndex) {
    if (runtimeTypes == nullptr || elfImage == nullptr || genericInstIndex < 0) {
        return "";
    }
    std::vector<uint64_t> argPtrs;
    if (!runtimeTypes->GetGenericInstArgTypePointers(*elfImage, genericInstIndex, &argPtrs) || argPtrs.empty()) {
        return "";
    }
    std::string out = "<";
    for (size_t i = 0; i < argPtrs.size(); ++i) {
        if (i != 0) {
            out += ", ";
        }
        const auto* argRt = runtimeTypes->GetTypeByPointer(argPtrs[i]);
        if (argRt != nullptr) {
            out += ResolveRuntimeType(metadata, runtimeTypes, elfImage, *argRt, nestedParents, typeDefNameCache, 0);
        } else {
            out += "Il2CppType_" + std::to_string(static_cast<unsigned long long>(argPtrs[i]));
        }
    }
    out += ">";
    return out;
}

bool WriteDumpCs(const SwitchPort::MetadataFile& metadata, const SwitchPort::RuntimeTypeSystem* runtimeTypes,
                 const SwitchPort::ElfImage* elfImage, uint64_t codeRegistration, const std::string& outputPath,
                 DumpProgressCallback progressCb, void* progressUser, std::string* error) {
    if (UserRequestedAbort()) {
        if (error != nullptr) {
            *error = "Aborted by user (MINUS).";
        }
        return false;
    }

    std::ofstream out(outputPath, std::ios::binary);
    if (!out) {
        if (error != nullptr) {
            *error = "Failed to open output file: " + outputPath;
        }
        return false;
    }

    const auto& images = metadata.Images();
    const auto& types = metadata.Types();
    const auto& fields = metadata.Fields();
    const auto& methods = metadata.Methods();
    const auto& parameters = metadata.Parameters();
    const auto& properties = metadata.Properties();
    const auto& nestedTypeIndices = metadata.NestedTypeIndices();
    const auto& interfaceIndices = metadata.InterfaceIndices();
    MethodPointerResolver methodResolver;
    const bool hasMethodPointers =
        (elfImage != nullptr) && methodResolver.Initialize(*elfImage, static_cast<double>(metadata.Header().version), codeRegistration);
    std::unordered_map<size_t, std::string> typeNameCache;
    std::unordered_map<size_t, size_t> nestedParents;
    std::unordered_map<int32_t, std::vector<std::pair<uint64_t, std::string>>> genericInstMethodLines;
    const size_t totalTypes = types.size();
    size_t writtenTypes = 0;

    if (progressCb != nullptr) {
        progressCb("write dump.cs", 0, totalTypes, progressUser);
    }

    for (size_t parentIndex = 0; parentIndex < types.size(); ++parentIndex) {
        const auto& type = types[parentIndex];
        if (type.nestedTypeCount == 0 || type.nestedTypesStart < 0) {
            continue;
        }
        const size_t start = static_cast<size_t>(type.nestedTypesStart);
        const size_t end = start + static_cast<size_t>(type.nestedTypeCount);
        for (size_t i = start; i < end && i < nestedTypeIndices.size(); ++i) {
            const int32_t child = nestedTypeIndices[i];
            if (child >= 0 && static_cast<size_t>(child) < types.size()) {
                nestedParents[static_cast<size_t>(child)] = parentIndex;
            }
        }
    }

    for (size_t imageIndex = 0; imageIndex < images.size(); ++imageIndex) {
        const auto& image = images[imageIndex];
        out << "// Image " << imageIndex << ": " << metadata.GetString(image.nameIndex) << " - " << image.typeStart << "\n";
    }

    if (runtimeTypes != nullptr && elfImage != nullptr) {
        const auto& specs = runtimeTypes->MethodSpecs();
        const auto& gmt = runtimeTypes->GenericMethodTable();
        for (const auto& e : gmt) {
            if (e.genericMethodIndex < 0 || static_cast<size_t>(e.genericMethodIndex) >= specs.size()) {
                continue;
            }
            const auto& ms = specs[static_cast<size_t>(e.genericMethodIndex)];
            if (ms.methodDefinitionIndex < 0 || static_cast<size_t>(ms.methodDefinitionIndex) >= methods.size()) {
                continue;
            }
            const auto& methodDef = methods[static_cast<size_t>(ms.methodDefinitionIndex)];
            if (methodDef.declaringType < 0 || static_cast<size_t>(methodDef.declaringType) >= types.size()) {
                continue;
            }
            std::string typeName = BuildTypeDefName(metadata, static_cast<size_t>(methodDef.declaringType), nestedParents, typeNameCache);
            if (ms.classIndexIndex >= 0) {
                typeName += BuildGenericInstParams(metadata, runtimeTypes, elfImage, nestedParents, typeNameCache, ms.classIndexIndex);
            }
            std::string methodName = metadata.GetString(methodDef.nameIndex);
            if (ms.methodIndexIndex >= 0) {
                methodName += BuildGenericInstParams(metadata, runtimeTypes, elfImage, nestedParents, typeNameCache, ms.methodIndexIndex);
            }
            const uint64_t ptr = methodResolver.GetGenericMethodPointer(e.methodIndex);
            genericInstMethodLines[ms.methodDefinitionIndex].push_back({ptr, typeName + "." + methodName});
        }
    }

    for (const auto& image : images) {
        if (UserRequestedAbort()) {
            if (error != nullptr) {
                *error = "Aborted by user (MINUS).";
            }
            return false;
        }

        const std::string imageName = metadata.GetString(image.nameIndex);
        const size_t typeStart = static_cast<size_t>(image.typeStart);
        const size_t typeEnd = typeStart + static_cast<size_t>(image.typeCount);

        for (size_t typeIndex = typeStart; typeIndex < typeEnd; ++typeIndex) {
            if (UserRequestedAbort()) {
                if (error != nullptr) {
                    *error = "Aborted by user (MINUS).";
                }
                return false;
            }

            const auto& type = types[typeIndex];
            const std::string ns = metadata.GetString(type.namespaceIndex);
            const std::string typeName = BuildTypeDefName(metadata, typeIndex, nestedParents, typeNameCache);
            std::vector<std::string> extends;
            if (type.parentIndex >= 0) {
                const std::string parentName =
                    ResolveTypeName(metadata, runtimeTypes, elfImage, type.parentIndex, nestedParents, typeNameCache);
                if (!type.IsValueType() && !type.IsEnum() && parentName != "object" && !parentName.empty()) {
                    extends.push_back(parentName);
                }
            }
            if (type.interfacesCount > 0 && type.interfacesStart >= 0) {
                const size_t ifaceStart = static_cast<size_t>(type.interfacesStart);
                const size_t ifaceEnd = ifaceStart + static_cast<size_t>(type.interfacesCount);
                for (size_t ii = ifaceStart; ii < ifaceEnd && ii < interfaceIndices.size(); ++ii) {
                    const int32_t ifaceTypeIndex = interfaceIndices[ii];
                    if (ifaceTypeIndex >= 0) {
                        extends.push_back(
                            ResolveTypeName(metadata, runtimeTypes, elfImage, ifaceTypeIndex, nestedParents, typeNameCache));
                    }
                }
            }

            out << "\n// Namespace: " << ns << "\n";
            for (const auto& attr :
                 GetCustomAttributesForToken(metadata, runtimeTypes, elfImage, nestedParents, typeNameCache, image, type.token)) {
                out << attr << "\n";
            }
            if ((type.flags & kTypeSerializable) != 0) {
                out << "[Serializable]\n";
            }
            out << TypeVisibility(type.flags) << TypeModifiers(type) << " " << TypeKeyword(type) << " " << typeName
                << (extends.empty() ? "" : " : ");
            if (!extends.empty()) {
                for (size_t ei = 0; ei < extends.size(); ++ei) {
                    if (ei != 0) {
                        out << ", ";
                    }
                    out << extends[ei];
                }
            }
            out << " // TypeDefIndex: " << typeIndex << "\n";
            out << "{\n";

            if (type.fieldCount > 0 && type.fieldStart >= 0) {
                out << "\t// Fields\n";
                const size_t fieldStart = static_cast<size_t>(type.fieldStart);
                const size_t fieldEnd = fieldStart + static_cast<size_t>(type.fieldCount);
                for (size_t i = fieldStart; i < fieldEnd && i < fields.size(); ++i) {
                    const auto& field = fields[i];
                    for (const auto& attr : GetCustomAttributesForToken(metadata, runtimeTypes, elfImage, nestedParents,
                                                                         typeNameCache, image, field.token)) {
                        out << "\t" << attr << "\n";
                    }
                    const std::string fieldName = metadata.GetString(field.nameIndex);
                    const auto* fieldRt = runtimeTypes ? runtimeTypes->GetTypeByIndex(field.typeIndex) : nullptr;
                    const uint16_t fieldAttrs = fieldRt ? fieldRt->attrs : 0;
                    const bool isConst = (fieldAttrs & kFieldLiteral) != 0;
                    const bool isStatic = (fieldAttrs & kFieldStatic) != 0;
                    out << "\t" << FieldModifiers(fieldAttrs) << " "
                        << ResolveTypeName(metadata, runtimeTypes, elfImage, field.typeIndex, nestedParents, typeNameCache) << " "
                        << fieldName;
                    SwitchPort::FieldDefaultValue fdv{};
                    if (metadata.TryGetFieldDefaultValue(static_cast<int32_t>(i), &fdv) && fdv.dataIndex >= 0) {
                        const std::string value = FormatFieldDefaultValue(metadata, runtimeTypes, fdv);
                        if (!value.empty()) {
                            out << " = " << value;
                        }
                    }
                    out << ";";
                    if (runtimeTypes != nullptr && elfImage != nullptr && !isConst) {
                        const int32_t fieldOffset =
                            runtimeTypes->GetFieldOffsetFromIndex(*elfImage, static_cast<double>(metadata.Header().version),
                                                                  static_cast<int32_t>(typeIndex),
                                                                  static_cast<int32_t>(i - fieldStart), static_cast<int32_t>(i),
                                                                  type.IsValueType(), isStatic);
                        out << " // 0x" << std::uppercase << std::hex << static_cast<uint32_t>(fieldOffset) << std::nouppercase
                            << std::dec;
                    }
                    out << "\n";
                }
            }

            if (type.propertyCount > 0 && type.propertyStart >= 0) {
                out << "\t// Properties\n";
                const size_t propertyStart = static_cast<size_t>(type.propertyStart);
                const size_t propertyEnd = propertyStart + static_cast<size_t>(type.propertyCount);
                for (size_t i = propertyStart; i < propertyEnd && i < properties.size(); ++i) {
                    const auto& property = properties[i];
                    for (const auto& attr : GetCustomAttributesForToken(metadata, runtimeTypes, elfImage, nestedParents,
                                                                         typeNameCache, image, property.token)) {
                        out << "\t" << attr << "\n";
                    }
                    int32_t propertyTypeIndex = -1;
                    uint16_t propertyFlags = 0;
                    bool hasAccessor = false;
                    if (property.get >= 0 && type.methodStart >= 0) {
                        const size_t methodIndex = static_cast<size_t>(type.methodStart + property.get);
                        if (methodIndex < methods.size()) {
                            propertyTypeIndex = methods[methodIndex].returnType;
                            propertyFlags = methods[methodIndex].flags;
                            hasAccessor = true;
                        }
                    } else if (property.set >= 0 && type.methodStart >= 0) {
                        const size_t methodIndex = static_cast<size_t>(type.methodStart + property.set);
                        if (methodIndex < methods.size()) {
                            const auto& method = methods[methodIndex];
                            propertyFlags = method.flags;
                            if (method.parameterStart >= 0 && static_cast<size_t>(method.parameterStart) < parameters.size()) {
                                propertyTypeIndex = parameters[static_cast<size_t>(method.parameterStart)].typeIndex;
                            }
                            hasAccessor = true;
                        }
                    }
                    out << "\t";
                    if (hasAccessor) {
                        out << MethodModifiers(propertyFlags) << " ";
                    } else {
                        out << "public ";
                    }
                    out << ResolveTypeName(metadata, runtimeTypes, elfImage, propertyTypeIndex, nestedParents, typeNameCache) << " "
                        << metadata.GetString(property.nameIndex) << " { ";
                    if (property.get >= 0) {
                        out << "get; ";
                    }
                    if (property.set >= 0) {
                        out << "set; ";
                    }
                    out << "}\n";
                }
            }

            if (type.methodCount > 0 && type.methodStart >= 0) {
                out << "\t// Methods\n";
                const size_t methodStart = static_cast<size_t>(type.methodStart);
                const size_t methodEnd = methodStart + static_cast<size_t>(type.methodCount);
                for (size_t i = methodStart; i < methodEnd && i < methods.size(); ++i) {
                    const auto& method = methods[i];
                    std::string methodName = metadata.GetString(method.nameIndex);
                    if (method.genericContainerIndex >= 0 &&
                        static_cast<size_t>(method.genericContainerIndex) < metadata.GenericContainers().size()) {
                        const auto& gc = metadata.GenericContainers()[static_cast<size_t>(method.genericContainerIndex)];
                        if (gc.typeArgc > 0 && gc.genericParameterStart >= 0) {
                            methodName += "<";
                            bool firstGp = true;
                            for (int32_t gpNum = 0; gpNum < gc.typeArgc; ++gpNum) {
                                if (!firstGp) {
                                    methodName += ", ";
                                }
                                firstGp = false;
                                const int32_t gpIndex = gc.genericParameterStart + gpNum;
                                std::string gpName = "T" + std::to_string(gpNum);
                                if (gpIndex >= 0 && static_cast<size_t>(gpIndex) < metadata.GenericParameters().size()) {
                                    const auto& gp = metadata.GenericParameters()[static_cast<size_t>(gpIndex)];
                                    const std::string n = metadata.GetString(gp.nameIndex);
                                    if (!n.empty()) {
                                        gpName = n;
                                    }
                                }
                                methodName += gpName;
                            }
                            methodName += ">";
                        }
                    }
                    const bool isAbstract = (method.flags & kMethodAbstract) != 0;
                    out << "\n";
                    for (const auto& attr : GetCustomAttributesForToken(metadata, runtimeTypes, elfImage, nestedParents,
                                                                         typeNameCache, image, method.token)) {
                        out << "\t" << attr << "\n";
                    }
                    if (hasMethodPointers) {
                        const uint64_t methodPointer = methodResolver.GetMethodPointer(imageName, method.token);
                        if (!isAbstract && methodPointer > 0) {
                            uint64_t methodOffset = 0;
                            if (elfImage->TryMapVaddrToOffset(methodPointer, &methodOffset)) {
                                out << "\t// RVA: 0x" << std::uppercase << std::hex << methodPointer << " Offset: 0x" << methodOffset
                                    << " VA: 0x" << methodPointer << std::nouppercase << std::dec;
                            } else {
                                out << "\t// RVA: -1 Offset: -1";
                            }
                        } else {
                            out << "\t// RVA: -1 Offset: -1";
                        }
                        if (method.slot != 0xFFFFu) {
                            out << " Slot: " << method.slot;
                        }
                        out << "\n";
                    }
                    out << "\t" << MethodModifiers(method.flags) << " "
                        << ((runtimeTypes != nullptr && runtimeTypes->GetTypeByIndex(method.returnType) != nullptr &&
                             runtimeTypes->GetTypeByIndex(method.returnType)->byref == 1)
                                ? "ref "
                                : "")
                        << ResolveTypeName(metadata, runtimeTypes, elfImage, method.returnType, nestedParents, typeNameCache) << " "
                        << methodName
                        << "(";

                    bool first = true;
                    if (method.parameterStart >= 0) {
                        const size_t paramStart = static_cast<size_t>(method.parameterStart);
                        const size_t paramEnd = paramStart + static_cast<size_t>(method.parameterCount);
                        for (size_t p = paramStart; p < paramEnd && p < parameters.size(); ++p) {
                            const auto& param = parameters[p];
                            if (!first) {
                                out << ", ";
                            }
                            first = false;
                            std::string parameterName = metadata.GetString(param.nameIndex);
                            if (parameterName.empty()) {
                                parameterName = "param_" + std::to_string(p);
                            }
                            const auto* paramRt = runtimeTypes ? runtimeTypes->GetTypeByIndex(param.typeIndex) : nullptr;
                            if (paramRt != nullptr && paramRt->byref == 1) {
                                const bool hasOut = (paramRt->attrs & kParamAttributeOut) != 0;
                                const bool hasIn = (paramRt->attrs & kParamAttributeIn) != 0;
                                if (hasOut && !hasIn) {
                                    out << "out ";
                                } else if (!hasOut && hasIn) {
                                    out << "in ";
                                } else {
                                    out << "ref ";
                                }
                            } else if (paramRt != nullptr) {
                                if ((paramRt->attrs & kParamAttributeIn) != 0) {
                                    out << "[In] ";
                                }
                                if ((paramRt->attrs & kParamAttributeOut) != 0) {
                                    out << "[Out] ";
                                }
                            }
                            out << ResolveTypeName(metadata, runtimeTypes, elfImage, param.typeIndex, nestedParents, typeNameCache)
                                << " " << parameterName;
                            SwitchPort::ParameterDefaultValue pdv{};
                            if (metadata.TryGetParameterDefaultValue(static_cast<int32_t>(p), &pdv) && pdv.dataIndex >= 0) {
                                const std::string value = FormatDefaultValue(metadata, runtimeTypes, pdv.typeIndex, pdv.dataIndex);
                                if (!value.empty()) {
                                    out << " = " << value;
                                }
                            }
                        }
                    }

                    if (isAbstract) {
                        out << ");\n";
                    } else {
                        out << ") { }\n";
                    }

                    const auto gmIt = genericInstMethodLines.find(static_cast<int32_t>(i));
                    if (gmIt != genericInstMethodLines.end() && !gmIt->second.empty()) {
                        struct Group {
                            uint64_t ptr = 0;
                            std::vector<std::string> lines;
                        };
                        std::vector<Group> groups;
                        for (const auto& item : gmIt->second) {
                            bool found = false;
                            for (auto& g : groups) {
                                if (g.ptr == item.first) {
                                    g.lines.push_back(item.second);
                                    found = true;
                                    break;
                                }
                            }
                            if (!found) {
                                Group g{};
                                g.ptr = item.first;
                                g.lines.push_back(item.second);
                                groups.push_back(std::move(g));
                            }
                        }
                        out << "\t/* GenericInstMethod :\n";
                        for (const auto& g : groups) {
                            out << "\t|\n";
                            if (g.ptr > 0 && elfImage != nullptr) {
                                uint64_t methodOffset = 0;
                                if (elfImage->TryMapVaddrToOffset(g.ptr, &methodOffset)) {
                                    out << "\t|-RVA: 0x" << std::uppercase << std::hex << g.ptr << " Offset: 0x" << methodOffset
                                        << " VA: 0x" << g.ptr << std::nouppercase << std::dec << "\n";
                                } else {
                                    out << "\t|-RVA: -1 Offset: -1\n";
                                }
                            } else {
                                out << "\t|-RVA: -1 Offset: -1\n";
                            }
                            for (const auto& l : g.lines) {
                                out << "\t|-" << l << "\n";
                            }
                        }
                        out << "\t*/\n";
                    }
                }
            }

            out << "}\n";
            ++writtenTypes;
            if (progressCb != nullptr && ((writtenTypes & 0x3ffu) == 0 || writtenTypes == totalTypes)) {
                progressCb("write dump.cs", writtenTypes, totalTypes, progressUser);
            }
        }
    }

    return true;
}

struct DumpSignature {
    uint64_t size = 0;
    uint64_t mtime = 0;
};

DumpSignature GetDumpSignature(const std::string& dumpPath) {
    DumpSignature sig{};
    struct stat st {};
    if (stat(dumpPath.c_str(), &st) == 0) {
        if (st.st_size > 0) {
            sig.size = static_cast<uint64_t>(st.st_size);
        }
        if (st.st_mtime > 0) {
            sig.mtime = static_cast<uint64_t>(st.st_mtime);
        }
    }
    return sig;
}

bool IsNameChar(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_' || c == '.' || c == ':' || c == '<' || c == '>' ||
           c == '`';
}

std::string Trim(const std::string& input) {
    size_t start = 0;
    while (start < input.size() && std::isspace(static_cast<unsigned char>(input[start])) != 0) {
        ++start;
    }
    size_t end = input.size();
    while (end > start && std::isspace(static_cast<unsigned char>(input[end - 1])) != 0) {
        --end;
    }
    return input.substr(start, end - start);
}

std::string NormalizeSymbolWord(const std::string& input) {
    if (input.empty()) {
        return "";
    }
    size_t start = 0;
    while (start < input.size() && !IsNameChar(input[start])) {
        ++start;
    }
    size_t end = input.size();
    while (end > start && !IsNameChar(input[end - 1])) {
        --end;
    }
    if (end <= start) {
        return "";
    }
    return input.substr(start, end - start);
}

std::string NormalizeTypeNameForLookup(std::string name) {
    name = Trim(name);
    if (name.empty()) {
        return "";
    }

    uint32_t arrayDims = 0;
    while (name.size() >= 2 && name.compare(name.size() - 2, 2, "[]") == 0) {
        name = Trim(name.substr(0, name.size() - 2));
        ++arrayDims;
    }

    name = NormalizeSymbolWord(name);
    if (name.empty()) {
        return "";
    }

    constexpr const char* kGlobalPrefix = "global::";
    if (name.rfind(kGlobalPrefix, 0) == 0) {
        name = name.substr(std::char_traits<char>::length(kGlobalPrefix));
    }

    while (!name.empty() && (name.back() == ',' || name.back() == ';')) {
        name.pop_back();
    }
    name = Trim(name);
    if (name.empty()) {
        return "";
    }

    while (arrayDims-- > 0) {
        name += "[]";
    }
    return name;
}

bool TryExtractNameToken(const std::string& value, size_t start, std::string* normalized) {
    size_t end = start;
    while (end < value.size() && IsNameChar(value[end])) {
        ++end;
    }
    if (end <= start) {
        return false;
    }
    if (normalized != nullptr) {
        *normalized = NormalizeSymbolWord(value.substr(start, end - start));
    }
    return normalized != nullptr && !normalized->empty();
}

bool TryExtractPublicDefinitionWord(const std::string& line, std::string* outWord) {
    constexpr const char* kPublicClass = "public class ";
    constexpr const char* kPublicStruct = "public struct ";
    constexpr const char* kPublicEnum = "public enum ";
    if (line.rfind(kPublicClass, 0) == 0) {
        return TryExtractNameToken(line, std::char_traits<char>::length(kPublicClass), outWord);
    }
    if (line.rfind(kPublicStruct, 0) == 0) {
        return TryExtractNameToken(line, std::char_traits<char>::length(kPublicStruct), outWord);
    }
    if (line.rfind(kPublicEnum, 0) == 0) {
        return TryExtractNameToken(line, std::char_traits<char>::length(kPublicEnum), outWord);
    }
    return false;
}

struct TypeInfoRecord {
    uint64_t offset = 0;
    std::string typeName;
    std::string fullName;
    std::string baseName;
    std::string namespaceName;
};

bool TryExtractTypeInfo(const std::string& line, const std::string& namespaceName, TypeInfoRecord* outRecord) {
    if (line.find("TypeDefIndex:") == std::string::npos) {
        return false;
    }

    size_t commentIndex = line.find("// TypeDefIndex:");
    const std::string header = Trim(commentIndex == std::string::npos ? line : line.substr(0, commentIndex));
    if (header.empty()) {
        return false;
    }

    struct KeywordEntry {
        const char* keyword;
        bool isStruct;
        bool isEnum;
    };
    constexpr KeywordEntry kKeywords[] = {
        {" class ", false, false},
        {" struct ", true, false},
        {" enum ", false, true},
        {" interface ", false, false},
    };

    size_t keywordIndex = std::string::npos;
    size_t keywordLength = 0;
    bool isStruct = false;
    bool isEnum = false;
    for (const auto& k : kKeywords) {
        const size_t idx = header.find(k.keyword);
        if (idx == std::string::npos) {
            continue;
        }
        keywordIndex = idx;
        keywordLength = std::char_traits<char>::length(k.keyword);
        isStruct = k.isStruct;
        isEnum = k.isEnum;
        break;
    }
    if (keywordIndex == std::string::npos) {
        return false;
    }

    size_t typeStart = keywordIndex + keywordLength;
    while (typeStart < header.size() && std::isspace(static_cast<unsigned char>(header[typeStart])) != 0) {
        ++typeStart;
    }

    size_t typeEnd = typeStart;
    while (typeEnd < header.size() && IsNameChar(header[typeEnd])) {
        ++typeEnd;
    }
    if (typeEnd <= typeStart) {
        return false;
    }

    TypeInfoRecord rec{};
    rec.typeName = NormalizeTypeNameForLookup(header.substr(typeStart, typeEnd - typeStart));
    if (rec.typeName.empty()) {
        return false;
    }

    const size_t colonIndex = header.find(':', typeEnd);
    if (colonIndex != std::string::npos) {
        size_t baseStart = colonIndex + 1;
        while (baseStart < header.size() && std::isspace(static_cast<unsigned char>(header[baseStart])) != 0) {
            ++baseStart;
        }
        size_t baseEnd = baseStart;
        while (baseEnd < header.size() && header[baseEnd] != ',' && header[baseEnd] != '{') {
            ++baseEnd;
        }
        rec.baseName = NormalizeTypeNameForLookup(header.substr(baseStart, baseEnd - baseStart));
    } else if (isStruct) {
        rec.baseName = "System.ValueType";
    } else if (isEnum) {
        rec.baseName = "System.Enum";
    }

    rec.namespaceName = Trim(namespaceName);
    if (rec.namespaceName.empty()) {
        rec.fullName = rec.typeName;
    } else {
        rec.fullName = rec.namespaceName + "." + rec.typeName;
    }

    if (outRecord != nullptr) {
        *outRecord = std::move(rec);
    }
    return true;
}

bool TryParseHexAfterPrefix(const std::string& line, const char* prefix, uint64_t* value) {
    if (line.rfind(prefix, 0) != 0) {
        return false;
    }
    const size_t start = std::char_traits<char>::length(prefix);
    size_t end = start;
    while (end < line.size() && std::isxdigit(static_cast<unsigned char>(line[end])) != 0) {
        ++end;
    }
    if (end <= start) {
        return false;
    }
    const std::string hex = line.substr(start, end - start);
    try {
        if (value != nullptr) {
            *value = std::stoull(hex, nullptr, 16);
        }
        return true;
    } catch (...) {
        return false;
    }
}

template <typename T>
void WriteBinary(std::ofstream& out, const T& value) {
    out.write(reinterpret_cast<const char*>(&value), sizeof(T));
}

void WriteLengthPrefixedString(std::ofstream& out, const std::string& value) {
    const uint32_t size = static_cast<uint32_t>(value.size());
    WriteBinary(out, size);
    if (!value.empty()) {
        out.write(value.data(), static_cast<std::streamsize>(value.size()));
    }
}

struct RvaRecord {
    uint64_t rva = 0;
    uint32_t dumpOffset = 0;
};

bool BuildDumpAuxiliaryFiles(const std::string& dumpPath, const std::string& index1Path, const std::string& index2Path,
                             const std::string& definitionCachePath, const std::string& namespaceOffsetsPath,
                             const std::string& typeIndexPath, std::string* error) {
    std::ifstream in(dumpPath, std::ios::binary);
    if (!in) {
        if (error != nullptr) {
            *error = "Failed to open dump.cs for indexing: " + dumpPath;
        }
        return false;
    }

    std::map<std::string, std::set<uint64_t>> definitionOffsets;
    std::vector<uint32_t> namespaceOffsets;
    std::vector<TypeInfoRecord> typeInfos;
    std::vector<RvaRecord> rvaRecords;
    std::string currentNamespace;

    std::vector<char> lineBytes;
    lineBytes.reserve(256);
    uint64_t lineStartOffset = 0;
    uint32_t totalDumpLines = 0;

    auto processLine = [&](const std::vector<char>& bytes, uint64_t offset) -> bool {
        ++totalDumpLines;
        std::string line(bytes.begin(), bytes.end());
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        const std::string trimmed = Trim(line);

        constexpr const char* kNamespacePrefix = "// Namespace:";
        if (trimmed.rfind(kNamespacePrefix, 0) == 0) {
            if (offset <= std::numeric_limits<uint32_t>::max()) {
                namespaceOffsets.push_back(static_cast<uint32_t>(offset));
            }
            currentNamespace = Trim(trimmed.substr(std::char_traits<char>::length(kNamespacePrefix)));
        }

        std::string word;
        if (TryExtractPublicDefinitionWord(trimmed, &word)) {
            definitionOffsets[word].insert(offset);
        }

        TypeInfoRecord typeInfo{};
        if (TryExtractTypeInfo(trimmed, currentNamespace, &typeInfo)) {
            typeInfo.offset = offset;
            typeInfos.push_back(std::move(typeInfo));
        }

        uint64_t rva = 0;
        if (TryParseHexAfterPrefix(line, "\t// RVA: 0x", &rva) || TryParseHexAfterPrefix(line, "\t|-RVA: 0x", &rva)) {
            if (offset > std::numeric_limits<uint32_t>::max()) {
                if (error != nullptr) {
                    *error = "dump.cs is larger than supported 32-bit offset range";
                }
                return false;
            }
            rvaRecords.push_back({rva, static_cast<uint32_t>(offset)});
        }

        return true;
    };

    for (;;) {
        const int byte = in.get();
        if (byte == EOF) {
            break;
        }
        if (byte == '\n') {
            if (!processLine(lineBytes, lineStartOffset)) {
                return false;
            }
            lineStartOffset = static_cast<uint64_t>(in.tellg());
            lineBytes.clear();
            if (UserRequestedAbort()) {
                if (error != nullptr) {
                    *error = "Aborted by user (MINUS).";
                }
                return false;
            }
        } else {
            lineBytes.push_back(static_cast<char>(byte));
        }
    }
    if (!lineBytes.empty()) {
        if (!processLine(lineBytes, lineStartOffset)) {
            return false;
        }
    }

    std::sort(namespaceOffsets.begin(), namespaceOffsets.end());
    namespaceOffsets.erase(std::unique(namespaceOffsets.begin(), namespaceOffsets.end()), namespaceOffsets.end());

    std::sort(typeInfos.begin(), typeInfos.end(), [](const TypeInfoRecord& a, const TypeInfoRecord& b) { return a.offset < b.offset; });

    const DumpSignature sig = GetDumpSignature(dumpPath);

    {
        std::ofstream out(definitionCachePath, std::ios::binary | std::ios::trunc);
        if (!out) {
            if (error != nullptr) {
                *error = "Failed to write " + definitionCachePath;
            }
            return false;
        }
        out << "v2\t" << std::uppercase << std::hex << sig.size << "\t" << sig.mtime << std::nouppercase << std::dec << "\n";
        for (const auto& [name, offsets] : definitionOffsets) {
            for (uint64_t off : offsets) {
                out << "D\t" << name << "\t" << std::uppercase << std::hex << off << std::nouppercase << std::dec << "\n";
            }
        }
    }

    {
        constexpr uint32_t kNamespaceIndexMagic = 0x3153494Eu; // "NIS1"
        std::ofstream out(namespaceOffsetsPath, std::ios::binary | std::ios::trunc);
        if (!out) {
            if (error != nullptr) {
                *error = "Failed to write " + namespaceOffsetsPath;
            }
            return false;
        }
        const uint32_t dumpSize32 = static_cast<uint32_t>(std::min<uint64_t>(sig.size, std::numeric_limits<uint32_t>::max()));
        const uint32_t dumpMtime32 = static_cast<uint32_t>(std::min<uint64_t>(sig.mtime, std::numeric_limits<uint32_t>::max()));
        const uint32_t count = static_cast<uint32_t>(namespaceOffsets.size());
        WriteBinary(out, kNamespaceIndexMagic);
        WriteBinary(out, dumpSize32);
        WriteBinary(out, dumpMtime32);
        WriteBinary(out, count);
        for (uint32_t off : namespaceOffsets) {
            WriteBinary(out, off);
        }
    }

    {
        constexpr uint32_t kTypeIndexMagic = 0x32595054u; // "TYP2"
        std::ofstream out(typeIndexPath, std::ios::binary | std::ios::trunc);
        if (!out) {
            if (error != nullptr) {
                *error = "Failed to write " + typeIndexPath;
            }
            return false;
        }
        const uint32_t dumpSize32 = static_cast<uint32_t>(std::min<uint64_t>(sig.size, std::numeric_limits<uint32_t>::max()));
        const uint32_t dumpMtime32 = static_cast<uint32_t>(std::min<uint64_t>(sig.mtime, std::numeric_limits<uint32_t>::max()));
        const uint32_t count = static_cast<uint32_t>(typeInfos.size());
        WriteBinary(out, kTypeIndexMagic);
        WriteBinary(out, dumpSize32);
        WriteBinary(out, dumpMtime32);
        WriteBinary(out, count);
        for (const auto& t : typeInfos) {
            const uint32_t off32 = static_cast<uint32_t>(std::min<uint64_t>(t.offset, std::numeric_limits<uint32_t>::max()));
            WriteBinary(out, off32);
            WriteLengthPrefixedString(out, t.typeName);
            WriteLengthPrefixedString(out, t.fullName);
            WriteLengthPrefixedString(out, t.baseName);
            WriteLengthPrefixedString(out, t.namespaceName);
        }
    }

    std::sort(rvaRecords.begin(), rvaRecords.end(), [](const RvaRecord& a, const RvaRecord& b) {
        if (a.rva != b.rva) {
            return a.rva < b.rva;
        }
        return a.dumpOffset < b.dumpOffset;
    });

    constexpr uint16_t kIndexVersion = 3;

    struct Index2BlockRecord {
        uint32_t addrDelta = 0;
        uint32_t dumpOffset = 0;
    };
    struct Index2Block {
        uint64_t startRva = 0;
        uint32_t startDumpOffset = 0;
        std::vector<Index2BlockRecord> records;
    };
    std::vector<Index2Block> blocks;
    blocks.reserve((rvaRecords.size() / 1024u) + 1u);

    size_t i = 0;
    while (i < rvaRecords.size()) {
        Index2Block block{};
        block.startRva = rvaRecords[i].rva;
        block.startDumpOffset = rvaRecords[i].dumpOffset;
        block.records.push_back({0, rvaRecords[i].dumpOffset});
        ++i;
        uint64_t prevRva = block.startRva;
        while (i < rvaRecords.size() && block.records.size() < 1024u) {
            const uint64_t delta64 = rvaRecords[i].rva - prevRva;
            if (delta64 > std::numeric_limits<uint32_t>::max()) {
                break;
            }
            block.records.push_back({static_cast<uint32_t>(delta64), rvaRecords[i].dumpOffset});
            prevRva = rvaRecords[i].rva;
            ++i;
        }
        blocks.push_back(std::move(block));
    }

    struct Index1Entry {
        uint64_t startRva = 0;
        uint64_t index2Offset = 0;
        uint32_t index2Size = 0;
    };
    std::vector<Index1Entry> index1Entries;
    index1Entries.reserve(blocks.size());

    {
        std::ofstream out(index2Path, std::ios::binary | std::ios::trunc);
        if (!out) {
            if (error != nullptr) {
                *error = "Failed to write " + index2Path;
            }
            return false;
        }
        out.write("IDX2", 4);
        WriteBinary(out, kIndexVersion);
        WriteBinary(out, static_cast<uint16_t>(0));
        WriteBinary(out, static_cast<uint32_t>(blocks.size()));
        WriteBinary(out, totalDumpLines);
        for (const auto& block : blocks) {
            const uint64_t blockOffset = static_cast<uint64_t>(out.tellp());
            WriteBinary(out, block.startRva);
            WriteBinary(out, block.startDumpOffset);
            WriteBinary(out, static_cast<uint32_t>(block.records.size()));
            for (const auto& rec : block.records) {
                WriteBinary(out, rec.addrDelta);
                WriteBinary(out, rec.dumpOffset);
            }
            const uint64_t blockEnd = static_cast<uint64_t>(out.tellp());
            Index1Entry e{};
            e.startRva = block.startRva;
            e.index2Offset = blockOffset;
            e.index2Size = static_cast<uint32_t>(blockEnd - blockOffset);
            index1Entries.push_back(e);
        }
    }

    {
        std::ofstream out(index1Path, std::ios::binary | std::ios::trunc);
        if (!out) {
            if (error != nullptr) {
                *error = "Failed to write " + index1Path;
            }
            return false;
        }
        out.write("IDX1", 4);
        WriteBinary(out, kIndexVersion);
        WriteBinary(out, static_cast<uint16_t>(0));
        WriteBinary(out, static_cast<uint32_t>(index1Entries.size()));
        for (const auto& e : index1Entries) {
            WriteBinary(out, e.startRva);
            WriteBinary(out, e.index2Offset);
            WriteBinary(out, e.index2Size);
            WriteBinary(out, static_cast<uint32_t>(0));
        }
    }

    return true;
}

std::optional<uint32_t> ReadMagic(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return std::nullopt;
    }
    uint32_t magic = 0;
    in.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    if (!in) {
        return std::nullopt;
    }
    return magic;
}

bool IsMetadataFile(const fs::path& path) {
    const auto magic = ReadMagic(path);
    return magic.has_value() && (*magic == 0xFAB11BAFu);
}

bool DirectoryHasMainAndMetadata(const fs::path& dir, fs::path* mainPath, fs::path* metadataPath) {
    const fs::path candidateMainElf = dir / "main.elf";
    const fs::path candidateMain = dir / "main";
    const fs::path candidateMetadata = dir / "global-metadata.dat";
    const bool hasMetadata = fs::exists(candidateMetadata) && fs::is_regular_file(candidateMetadata);
    const bool hasMainElf = fs::exists(candidateMainElf) && fs::is_regular_file(candidateMainElf);
    const bool hasMain = fs::exists(candidateMain) && fs::is_regular_file(candidateMain);
    if (hasMetadata && (hasMainElf || hasMain)) {
        if (mainPath) {
            // Prefer converted ELF when present; fallback to raw "main".
            *mainPath = hasMainElf ? candidateMainElf : candidateMain;
        }
        if (metadataPath) {
            *metadataPath = candidateMetadata;
        }
        return true;
    }
    return false;
}

bool FindExtractedPairInRoot(const fs::path& root, fs::path* mainPath, fs::path* metadataPath) {
    std::error_code ec;
    if (!fs::exists(root, ec) || !fs::is_directory(root, ec)) {
        return false;
    }

    bool found = false;
    fs::path bestMain;
    fs::path bestMetadata;
    fs::file_time_type bestTime{};

    if (DirectoryHasMainAndMetadata(root, &bestMain, &bestMetadata)) {
        found = true;
        bestTime = fs::last_write_time(bestMetadata, ec);
    }

    for (fs::directory_iterator it(root, fs::directory_options::skip_permission_denied, ec), end; it != end; it.increment(ec)) {
        if (ec) {
            ec.clear();
            continue;
        }
        const auto& entry = *it;
        if (!entry.is_directory()) {
            continue;
        }
        fs::path curMain;
        fs::path curMetadata;
        if (!DirectoryHasMainAndMetadata(entry.path(), &curMain, &curMetadata)) {
            continue;
        }
        const auto t = fs::last_write_time(curMetadata, ec);
        if (!found || (!ec && t > bestTime)) {
            found = true;
            bestMain = curMain;
            bestMetadata = curMetadata;
            if (!ec) {
                bestTime = t;
            }
        }
    }

    if (!found) {
        return false;
    }
    if (mainPath) {
        *mainPath = bestMain;
    }
    if (metadataPath) {
        *metadataPath = bestMetadata;
    }
    return true;
}

bool FindExtractedPairRecursively(const fs::path& root, int maxDepth, fs::path* mainPath, fs::path* metadataPath) {
    std::error_code ec;
    if (!fs::exists(root, ec) || !fs::is_directory(root, ec)) {
        return false;
    }

    bool found = false;
    fs::path bestMain;
    fs::path bestMetadata;
    fs::file_time_type bestTime{};

    for (fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec), end; it != end;
         it.increment(ec)) {
        if (ec) {
            ec.clear();
            continue;
        }
        if (maxDepth >= 0 && it.depth() > maxDepth) {
            it.disable_recursion_pending();
            continue;
        }
        if (!it->is_regular_file()) {
            continue;
        }
        if (it->path().filename() != "global-metadata.dat") {
            continue;
        }
        const fs::path candidateDir = it->path().parent_path();
        fs::path curMain;
        fs::path curMetadata;
        if (!DirectoryHasMainAndMetadata(candidateDir, &curMain, &curMetadata)) {
            continue;
        }
        const auto t = fs::last_write_time(curMetadata, ec);
        if (!found || (!ec && t > bestTime)) {
            found = true;
            bestMain = curMain;
            bestMetadata = curMetadata;
            if (!ec) {
                bestTime = t;
            }
        }
    }

    if (!found) {
        return false;
    }
    if (mainPath) {
        *mainPath = bestMain;
    }
    if (metadataPath) {
        *metadataPath = bestMetadata;
    }
    return true;
}

bool AutoDetectNxdumptoolExtractedFiles(fs::path* mainPath, fs::path* metadataPath) {
    const std::vector<fs::path> knownRoots = {
        "sdmc:/switch/Breezehelper/extracted",
        "sdmc:/switch/nxdumptool/extracted",
        "sdmc:/switch/breezehelper/extracted",
    };
    for (const auto& root : knownRoots) {
        if (FindExtractedPairInRoot(root, mainPath, metadataPath)) {
            return true;
        }
    }

    const fs::path switchRoot = "sdmc:/switch";
    std::error_code ec;
    if (!fs::exists(switchRoot, ec) || !fs::is_directory(switchRoot, ec)) {
        return false;
    }
    for (fs::directory_iterator it(switchRoot, fs::directory_options::skip_permission_denied, ec), end; it != end; it.increment(ec)) {
        if (ec) {
            ec.clear();
            continue;
        }
        const auto& appDir = *it;
        if (!appDir.is_directory()) {
            continue;
        }
        const fs::path extractedRoot = appDir.path() / "extracted";
        if (FindExtractedPairInRoot(extractedRoot, mainPath, metadataPath)) {
            return true;
        }
    }

    // Fallback: broad scan under sdmc:/switch for any directory containing both files.
    if (FindExtractedPairRecursively(switchRoot, 6, mainPath, metadataPath)) {
        return true;
    }

    return false;
}

void AppendRunLog(const std::string& line) {
    const fs::path logDir = "sdmc:/switch/switch_il2cpp_metadata";
    std::error_code ec;
    fs::create_directories(logDir, ec);
    std::ofstream log(logDir / "run.log", std::ios::app);
    if (log) {
        log << line << "\n";
    }
}

void PrintInfo(const std::string& line);
void PrintError(const std::string& line);

fs::path PreferSiblingMainElf(const fs::path& il2cppPath) {
    if (il2cppPath.filename() == "main.elf") {
        return il2cppPath;
    }
    const fs::path siblingMainElf = il2cppPath.parent_path() / "main.elf";
    std::error_code ec;
    if (fs::exists(siblingMainElf, ec) && fs::is_regular_file(siblingMainElf, ec)) {
        return siblingMainElf;
    }

    if (il2cppPath.filename() == "main") {
        std::string convertError;
        if (SwitchPort::ConvertNsoLikeToElf(il2cppPath.string(), siblingMainElf.string(), &convertError)) {
            AppendRunLog("auto-converted main -> main.elf: " + siblingMainElf.string());
            PrintInfo("Converted main to ELF: " + siblingMainElf.string());
            return siblingMainElf;
        }
        AppendRunLog("main -> main.elf conversion failed: " + convertError);
        PrintError("main.elf not found and conversion failed: " + convertError);
    }
    return il2cppPath;
}

void RefreshConsole() {
#ifdef __SWITCH__
    consoleUpdate(nullptr);
#endif
}

void PrintInfo(const std::string& line) {
    std::fprintf(stdout, "%s\n", line.c_str());
    RefreshConsole();
}

void PrintError(const std::string& line) {
#ifdef __SWITCH__
    std::fprintf(stdout, "%s\n", line.c_str());
#else
    std::fprintf(stderr, "%s\n", line.c_str());
#endif
    RefreshConsole();
}

void PrintInfof(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    std::vfprintf(stdout, fmt, args);
    va_end(args);
    std::fputc('\n', stdout);
    RefreshConsole();
}

class ProgressReporter {
public:
    ProgressReporter() : start_(std::chrono::steady_clock::now()), lastEmit_(start_), lastPercent_(-1) {}

    void Emit(const std::string& phase, size_t done, size_t total, bool force = false) {
        const auto now = std::chrono::steady_clock::now();
        const auto sinceLast = now - lastEmit_;
        int percent = -1;
        if (total > 0) {
            percent = static_cast<int>((done * 100u) / total);
            if (percent > 100) {
                percent = 100;
            }
        }
        const bool timeDue = sinceLast >= std::chrono::seconds(2);
        const bool progressDue = (percent >= 0) && (percent >= lastPercent_ + 5);
        if (!force && !timeDue && !progressDue) {
            return;
        }

        std::string msg = "[progress] " + phase;
        if (percent >= 0) {
            msg += " " + std::to_string(percent) + "% (" + std::to_string(done) + "/" + std::to_string(total) + ")";
        }
        const auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_).count();
        msg += " elapsed=" + std::to_string(elapsedMs) + "ms";
        PrintInfo(msg);
        AppendRunLog(msg);

        lastEmit_ = now;
        if (percent >= 0) {
            lastPercent_ = percent;
        }
    }

private:
    std::chrono::steady_clock::time_point start_;
    std::chrono::steady_clock::time_point lastEmit_;
    int lastPercent_;
};

void DumpProgressBridge(const char* phase, size_t done, size_t total, void* user) {
    if (user == nullptr || phase == nullptr) {
        return;
    }
    static_cast<ProgressReporter*>(user)->Emit(phase, done, total, false);
}

#ifdef __SWITCH__
void WaitForUserOnExit(bool hadError) {
    if (!hadError) {
        return;
    }
    PrintError("");
    PrintError("Run failed.");
    PrintError("");
    PrintError("Press any key to continue. (MINUS aborts during run)");
    while (appletMainLoop()) {
        hidScanInput();
        const u64 kDown = hidKeysDown(CONTROLLER_P1_AUTO);
        if (kDown != 0) {
            break;
        }
        consoleUpdate(nullptr);
    }
}

void ConfigureReturnToBreeze() {
    static const std::vector<fs::path> candidates = {
        "sdmc:/switch/Breeze/Breeze.nro",
        "sdmc:/switch/Breeze.nro",
    };

    std::error_code ec;
    for (const auto& p : candidates) {
        if (!fs::exists(p, ec) || !fs::is_regular_file(p, ec)) {
            ec.clear();
            continue;
        }
        envSetNextLoad(p.string().c_str(), p.string().c_str());
        AppendRunLog("next load set to Breeze: " + p.string());
        return;
    }
    AppendRunLog("Breeze not found; keeping default return target.");
}
#endif

int Run(int argc, char** argv) {
    const auto runStart = std::chrono::steady_clock::now();
    auto MillisecondsSince = [](std::chrono::steady_clock::time_point start) -> long long {
        return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    };
    ProgressReporter progress;

    AppendRunLog("----- run start -----");
    AppendRunLog("argc=" + std::to_string(argc));
    progress.Emit("startup", 0, 0, true);
    PrintInfo("Tip: press MINUS any time to abort.");

    if (argc < 1 || argc > 4) {
        AppendRunLog("invalid argc");
        PrintError("Usage:");
        PrintError("  switch_il2cpp_metadata  (auto-detects sdmc:/switch/*/extracted/<titleid>/main + global-metadata.dat)");
        PrintError("  switch_il2cpp_metadata <global-metadata.dat> [dump.cs output]");
        PrintError("  switch_il2cpp_metadata <il2cpp-binary> <global-metadata.dat> [dump.cs output]");
        return 2;
    }

    fs::path il2cppPath;
    fs::path metadataPath;
    fs::path outputPath = "dump.cs";
    bool fullMode = false;

    if (argc == 1) {
        fs::path autoMain;
        fs::path autoMetadata;
        if (!AutoDetectNxdumptoolExtractedFiles(&autoMain, &autoMetadata)) {
            AppendRunLog("auto-detect failed");
            PrintError("Failed to auto-detect nxdumptool extracted files.");
            PrintError("Expected paths like: sdmc:/switch/<app>/extracted/<titleid>/main + global-metadata.dat");
            return 1;
        }
        il2cppPath = autoMain;
        metadataPath = autoMetadata;
        outputPath = metadataPath.parent_path() / "dump.cs";
        fullMode = true;
        PrintInfo("Auto-detected main: " + il2cppPath.string());
        PrintInfo("Auto-detected metadata: " + metadataPath.string());
        PrintInfo("Output dump.cs: " + outputPath.string());
    } else if (argc == 2) {
        metadataPath = argv[1];
        outputPath = metadataPath.parent_path() / "dump.cs";
    } else if (argc == 3) {
        if (IsMetadataFile(argv[1])) {
            metadataPath = argv[1];
            outputPath = argv[2];
        } else {
            il2cppPath = argv[1];
            metadataPath = argv[2];
            outputPath = metadataPath.parent_path() / "dump.cs";
            fullMode = true;
        }
    } else {
        il2cppPath = argv[1];
        metadataPath = argv[2];
        outputPath = argv[3];
        fullMode = true;
    }

    AppendRunLog("main path: " + il2cppPath.string());
    AppendRunLog("metadata path: " + metadataPath.string());
    AppendRunLog("output path: " + outputPath.string());
    AppendRunLog(std::string("full mode: ") + (fullMode ? "true" : "false"));

    std::unique_ptr<SwitchPort::ElfImage> elfImage;
    std::unique_ptr<SwitchPort::RuntimeTypeSystem> runtimeTypes;
    uint64_t codeRegistration = 0;
    uint64_t metadataRegistration = 0;
    bool pointerInExec = false;
    if (fullMode) {
        const auto elfLoadStart = std::chrono::steady_clock::now();
        progress.Emit("load il2cpp elf", 0, 0, true);
        il2cppPath = PreferSiblingMainElf(il2cppPath);
        elfImage = std::make_unique<SwitchPort::ElfImage>();
        std::string elfError;
        if (!elfImage->Load(il2cppPath.string(), &elfError)) {
            AppendRunLog("initial IL2CPP load failed: " + elfError);
            // If "main" isn't ELF, retry sibling main.elf automatically.
            if (il2cppPath.filename() != "main.elf") {
                const fs::path mainElfPath = il2cppPath.parent_path() / "main.elf";
                std::error_code ec;
                if (fs::exists(mainElfPath, ec) && fs::is_regular_file(mainElfPath, ec)) {
                    AppendRunLog("retrying with main.elf: " + mainElfPath.string());
                    il2cppPath = mainElfPath;
                    elfError.clear();
                    if (elfImage->Load(il2cppPath.string(), &elfError)) {
                        goto il2cpp_loaded;
                    }
                    AppendRunLog("main.elf retry failed: " + elfError);
                }
            }
            AppendRunLog("failed to load IL2CPP ELF: " + elfError);
            PrintError("Failed to load IL2CPP ELF: " + elfError);
            return 1;
        }
il2cpp_loaded:
        PrintInfo("Loaded IL2CPP ELF (native mode): " + il2cppPath.string());
        PrintInfo("PT_LOAD segments: " + std::to_string(elfImage->LoadSegmentCount()));
        PrintInfo("ELF load time: " + std::to_string(MillisecondsSince(elfLoadStart)) + " ms");
    }

    const auto metadataLoadStart = std::chrono::steady_clock::now();
    progress.Emit("load metadata", 0, 0, true);
    SwitchPort::MetadataFile metadata;
    std::string error;
    if (!metadata.Load(metadataPath.string(), &error)) {
        AppendRunLog("failed to load metadata: " + error);
        PrintError("Failed to load metadata: " + error);
        return 1;
    }
    PrintInfo("Metadata load time: " + std::to_string(MillisecondsSince(metadataLoadStart)) + " ms");

    const auto& header = metadata.Header();
    const auto& images = metadata.Images();
    if (fullMode && elfImage != nullptr) {
        const auto registrationStart = std::chrono::steady_clock::now();
        progress.Emit("find registrations", 0, 0, true);
        SwitchPort::RegistrationFinder finder(*elfImage);
        const auto regs = finder.Find(static_cast<double>(header.version), static_cast<int>(metadata.Types().size()),
                                      static_cast<int>(images.size()));
        codeRegistration = NormalizeCodeRegistration(static_cast<double>(header.version), regs.codeRegistration);
        metadataRegistration = regs.metadataRegistration;
        pointerInExec = regs.pointerInExec;
        PrintInfof("CodeRegistration: 0x%llX", static_cast<unsigned long long>(codeRegistration));
        PrintInfof("MetadataRegistration: 0x%llX", static_cast<unsigned long long>(metadataRegistration));
        PrintInfo(std::string("PointerInExec: ") + (pointerInExec ? "true" : "false"));
        PrintInfo("Registration search time: " + std::to_string(MillisecondsSince(registrationStart)) + " ms");
        if (metadataRegistration != 0) {
            const auto runtimeTypeStart = std::chrono::steady_clock::now();
            progress.Emit("load runtime types", 0, 0, true);
            runtimeTypes = std::make_unique<SwitchPort::RuntimeTypeSystem>();
            std::string runtimeError;
            if (!runtimeTypes->Load(*elfImage, metadataRegistration, static_cast<double>(header.version), &runtimeError)) {
                PrintError("Runtime type system load failed: " + runtimeError);
                runtimeTypes.reset();
            } else {
                PrintInfo("Runtime type table loaded");
            }
            PrintInfo("Runtime type load time: " + std::to_string(MillisecondsSince(runtimeTypeStart)) + " ms");
        }
    }
    const auto dumpWriteStart = std::chrono::steady_clock::now();
    progress.Emit("write dump.cs", 0, metadata.Types().size(), true);
    std::string writeError;
    if (!WriteDumpCs(metadata, runtimeTypes.get(), elfImage.get(), codeRegistration, outputPath.string(), &DumpProgressBridge,
                     &progress, &writeError)) {
        AppendRunLog("failed to write dump.cs: " + writeError);
        PrintError("Failed to write dump.cs: " + writeError);
        return 1;
    }
    AppendRunLog("dump.cs written: " + outputPath.string());
    progress.Emit("write dump.cs", metadata.Types().size(), metadata.Types().size(), true);
    PrintInfo("dump.cs write time: " + std::to_string(MillisecondsSince(dumpWriteStart)) + " ms");

    const auto auxWriteStart = std::chrono::steady_clock::now();
    progress.Emit("write indexes", 0, 0, true);
    const fs::path outputDir = outputPath.has_parent_path() ? outputPath.parent_path() : fs::current_path();
    const fs::path index1Path = outputDir / "index1.bin";
    const fs::path index2Path = outputDir / "index2.bin";
    const fs::path definitionCachePath = outputDir / "dumpcs_definition_cache.txt";
    const fs::path namespaceOffsetsPath = outputDir / "dumpcs_namespace_offsets.bin";
    const fs::path typeIndexPath = outputDir / "dumpcs_type_index.bin";
    std::string auxError;
    if (!BuildDumpAuxiliaryFiles(outputPath.string(), index1Path.string(), index2Path.string(), definitionCachePath.string(),
                                 namespaceOffsetsPath.string(), typeIndexPath.string(), &auxError)) {
        AppendRunLog("failed to write dump indexes: " + auxError);
        PrintError("Failed to write dump indexes: " + auxError);
        return 1;
    }
    AppendRunLog("index1.bin written: " + index1Path.string());
    AppendRunLog("index2.bin written: " + index2Path.string());
    AppendRunLog("dumpcs_definition_cache.txt written: " + definitionCachePath.string());
    AppendRunLog("dumpcs_namespace_offsets.bin written: " + namespaceOffsetsPath.string());
    AppendRunLog("dumpcs_type_index.bin written: " + typeIndexPath.string());
    PrintInfo("Aux index write time: " + std::to_string(MillisecondsSince(auxWriteStart)) + " ms");
    PrintInfo("index1.bin written to: " + index1Path.string());
    PrintInfo("index2.bin written to: " + index2Path.string());
    PrintInfo("dumpcs_definition_cache.txt written to: " + definitionCachePath.string());
    PrintInfo("dumpcs_namespace_offsets.bin written to: " + namespaceOffsetsPath.string());
    PrintInfo("dumpcs_type_index.bin written to: " + typeIndexPath.string());

    PrintInfo("Metadata version: " + std::to_string(header.version));
    PrintInfo("Images: " + std::to_string(images.size()));
    PrintInfo("Types: " + std::to_string(metadata.Types().size()));
    PrintInfo("Methods: " + std::to_string(metadata.Methods().size()));
    PrintInfo("Fields: " + std::to_string(metadata.Fields().size()));
    PrintInfo("Parameters: " + std::to_string(metadata.Parameters().size()));
    PrintInfo("dump.cs written to: " + outputPath.string());
    PrintInfo("Total time: " + std::to_string(MillisecondsSince(runStart)) + " ms");

    return 0;
}

} // namespace

int main(int argc, char** argv) {
#ifdef __SWITCH__
    consoleInit(nullptr);
    std::printf("iL2CPPdumper Switch version\nPress MINUS to abort run.\n");
#endif
    try {
        const int rc = Run(argc, argv);
#ifdef __SWITCH__
        AppendRunLog("rc=" + std::to_string(rc));
        WaitForUserOnExit(rc != 0);
        ConfigureReturnToBreeze();
        consoleExit(nullptr);
#endif
        return rc;
    } catch (const std::exception& ex) {
        PrintError(std::string("Fatal error: ") + ex.what());
#ifdef __SWITCH__
        AppendRunLog(std::string("fatal exception: ") + ex.what());
        WaitForUserOnExit(true);
        ConfigureReturnToBreeze();
        consoleExit(nullptr);
#endif
        return 1;
    }
}
