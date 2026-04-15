#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>

namespace SwitchPort {

constexpr uint32_t kMetadataMagic = 0xFAB11BAF;

struct Il2CppSectionMetadata {
    uint32_t offset = 0;
    uint32_t size = 0;
    uint32_t count = 0;
};

struct MetadataHeader {
    int version = 0;

    uint32_t stringOffset = 0;
    int32_t stringSize = 0;

    uint32_t methodsOffset = 0;
    int32_t methodsSize = 0;

    uint32_t parameterDefaultValuesOffset = 0;
    int32_t parameterDefaultValuesSize = 0;

    uint32_t fieldDefaultValuesOffset = 0;
    int32_t fieldDefaultValuesSize = 0;
    uint32_t fieldAndParameterDefaultValueDataOffset = 0;
    int32_t fieldAndParameterDefaultValueDataSize = 0;

    uint32_t propertiesOffset = 0;
    int32_t propertiesSize = 0;

    uint32_t eventsOffset = 0;
    int32_t eventsSize = 0;

    uint32_t parametersOffset = 0;
    int32_t parametersSize = 0;

    uint32_t fieldsOffset = 0;
    int32_t fieldsSize = 0;

    uint32_t genericParametersOffset = 0;
    int32_t genericParametersSize = 0;

    uint32_t genericContainersOffset = 0;
    int32_t genericContainersSize = 0;

    uint32_t nestedTypesOffset = 0;
    int32_t nestedTypesSize = 0;
    uint32_t interfacesOffset = 0;
    int32_t interfacesSize = 0;

    uint32_t typeDefinitionsOffset = 0;
    int32_t typeDefinitionsSize = 0;

    uint32_t imagesOffset = 0;
    int32_t imagesSize = 0;

    uint32_t attributeDataOffset = 0;
    int32_t attributeDataSize = 0;
    uint32_t attributeDataRangeOffset = 0;
    int32_t attributeDataRangeSize = 0;

    // v38+ section metadata (offset/size/count triplets)
    Il2CppSectionMetadata sec_stringLiterals;
    Il2CppSectionMetadata sec_stringLiteralData;
    Il2CppSectionMetadata sec_strings;
    Il2CppSectionMetadata sec_events;
    Il2CppSectionMetadata sec_properties;
    Il2CppSectionMetadata sec_methods;
    Il2CppSectionMetadata sec_parameterDefaultValues;
    Il2CppSectionMetadata sec_fieldDefaultValues;
    Il2CppSectionMetadata sec_fieldAndParameterDefaultValueData;
    Il2CppSectionMetadata sec_fieldMarshaledSizes;
    Il2CppSectionMetadata sec_parameters;
    Il2CppSectionMetadata sec_fields;
    Il2CppSectionMetadata sec_genericParameters;
    Il2CppSectionMetadata sec_genericParameterConstraints;
    Il2CppSectionMetadata sec_genericContainers;
    Il2CppSectionMetadata sec_nestedTypes;
    Il2CppSectionMetadata sec_interfaces;
    Il2CppSectionMetadata sec_vtableMethods;
    Il2CppSectionMetadata sec_interfaceOffsets;
    Il2CppSectionMetadata sec_typeDefinitions;
    Il2CppSectionMetadata sec_images;
    Il2CppSectionMetadata sec_assemblies;
    Il2CppSectionMetadata sec_fieldRefs;
    Il2CppSectionMetadata sec_referencedAssemblies;
    Il2CppSectionMetadata sec_attributeData;
    Il2CppSectionMetadata sec_attributeDataRanges;
    Il2CppSectionMetadata sec_unresolvedIndirectCallParameterTypes;
    Il2CppSectionMetadata sec_unresolvedIndirectCallParameterRanges;
    Il2CppSectionMetadata sec_windowsRuntimeTypeNames;
    Il2CppSectionMetadata sec_windowsRuntimeStrings;
    Il2CppSectionMetadata sec_exportedTypeDefinitions;
};

struct ImageDefinition {
    uint32_t nameIndex = 0;
    int32_t assemblyIndex = -1;

    int32_t typeStart = 0;
    uint32_t typeCount = 0;

    int32_t entryPointIndex = -1;
    int32_t customAttributeStart = -1;
    uint32_t customAttributeCount = 0;
};

struct TypeDefinition {
    uint32_t nameIndex = 0;
    uint32_t namespaceIndex = 0;

    int32_t declaringTypeIndex = -1;
    int32_t parentIndex = -1;
    int32_t elementTypeIndex = -1;
    int32_t genericContainerIndex = -1;

    uint32_t flags = 0;

    int32_t fieldStart = 0;
    int32_t methodStart = 0;
    int32_t eventStart = 0;
    int32_t propertyStart = 0;
    int32_t nestedTypesStart = 0;
    int32_t interfacesStart = 0;

    uint16_t methodCount = 0;
    uint16_t propertyCount = 0;
    uint16_t fieldCount = 0;
    uint16_t eventCount = 0;
    uint16_t nestedTypeCount = 0;
    uint16_t interfacesCount = 0;

    uint32_t bitfield = 0;
    uint32_t token = 0;

    bool IsValueType() const { return (bitfield & 0x1u) == 1u; }
    bool IsEnum() const { return ((bitfield >> 1) & 0x1u) == 1u; }
};

struct MethodDefinition {
    uint32_t nameIndex = 0;
    int32_t declaringType = -1;
    int32_t returnType = -1;
    int32_t parameterStart = -1;
    int32_t genericContainerIndex = -1;
    uint32_t token = 0;
    uint16_t flags = 0;
    uint16_t slot = 0;
    uint16_t parameterCount = 0;
};

struct ParameterDefinition {
    uint32_t nameIndex = 0;
    int32_t typeIndex = -1;
};

struct FieldDefinition {
    uint32_t nameIndex = 0;
    int32_t typeIndex = -1;
    uint32_t token = 0;
};

struct FieldDefaultValue {
    int32_t fieldIndex = -1;
    int32_t typeIndex = -1;
    int32_t dataIndex = -1;
};

struct ParameterDefaultValue {
    int32_t parameterIndex = -1;
    int32_t typeIndex = -1;
    int32_t dataIndex = -1;
};

struct PropertyDefinition {
    uint32_t nameIndex = 0;
    int32_t get = -1;
    int32_t set = -1;
    uint32_t attrs = 0;
    uint32_t token = 0;
};

struct EventDefinition {
    uint32_t nameIndex = 0;
    int32_t typeIndex = -1;
    int32_t add = -1;
    int32_t remove = -1;
    int32_t raise = -1;
    uint32_t token = 0;
};

struct CustomAttributeDataRange {
    uint32_t token = 0;
    uint32_t startOffset = 0;
};

struct GenericContainer {
    int32_t ownerIndex = -1;
    int32_t typeArgc = 0;
    int32_t isMethod = 0;
    int32_t genericParameterStart = 0;
};

struct GenericParameter {
    int32_t ownerIndex = -1;
    uint32_t nameIndex = 0;
    int16_t constraintsStart = 0;
    int16_t constraintsCount = 0;
    uint16_t num = 0;
    uint16_t flags = 0;
};

inline int GetIndexSize(int count) {
    if (count <= 0xFF) return 1;
    if (count <= 0xFFFF) return 2;
    return 4;
}

inline size_t GetImageDefinitionSize(double version, int typeDefinitionIndexSize = 4) {
    size_t size = 0;
    size += 4; // nameIndex
    size += 4; // assemblyIndex
    size += (version >= 38.0) ? static_cast<size_t>(typeDefinitionIndexSize) : 4; // typeStart (TypeDefinitionIndex)
    size += 4; // typeCount
    if (version >= 24.0) {
        size += (version >= 38.0) ? static_cast<size_t>(typeDefinitionIndexSize) : 4; // exportedTypeStart (TypeDefinitionIndex)
        size += 4; // exportedTypeCount
    }
    size += 4; // entryPointIndex
    if (version >= 19.0) {
        size += 4; // token
    }
    if (version >= 24.1) {
        size += 4; // customAttributeStart
        size += 4; // customAttributeCount
    }
    return size;
}

inline size_t GetTypeDefinitionSize(double version, int genericContainerIndexSize = 4, int typeIndexSize = 4) {
    size_t size = 0;
    size += 4; // nameIndex
    size += 4; // namespaceIndex
    if (version <= 24.0) {
        size += 4; // customAttributeIndex
    }
    size += (version >= 38.0) ? static_cast<size_t>(typeIndexSize) : 4; // byvalTypeIndex (TypeIndex)
    if (version <= 24.5) {
        size += 4; // byrefTypeIndex
    }
    size += (version >= 38.0) ? static_cast<size_t>(typeIndexSize) : 4; // declaringTypeIndex (TypeIndex)
    size += (version >= 38.0) ? static_cast<size_t>(typeIndexSize) : 4; // parentIndex (TypeIndex)
    if (version < 35.0) {
        size += 4; // elementTypeIndex (removed in v35)
    }
    if (version <= 24.1) {
        size += 4; // rgctxStartIndex
        size += 4; // rgctxCount
    }
    size += (version >= 38.0) ? static_cast<size_t>(genericContainerIndexSize) : 4; // genericContainerIndex
    if (version <= 22.0) {
        size += 4; // delegateWrapperFromManagedToNativeIndex
        size += 4; // marshalingFunctionsIndex
    }
    if (version >= 21.0 && version <= 22.0) {
        size += 4; // ccwFunctionIndex
        size += 4; // guidIndex
    }
    size += 4; // flags
    size += 4 * 8; // starts
    size += 2 * 8; // counts
    size += 4; // bitfield
    if (version >= 19.0) {
        size += 4; // token
    }
    return size;
}

inline size_t GetMethodDefinitionSize(double version, int typeIndexSize = 4, int genericContainerIndexSize = 4, int parameterIndexSize = 4, int typeDefinitionIndexSize = 4) {
    size_t size = 0;
    size += 4; // nameIndex
    size += (version >= 38.0) ? static_cast<size_t>(typeDefinitionIndexSize) : 4; // declaringType (TypeDefinitionIndex)
    size += (version >= 38.0) ? static_cast<size_t>(typeIndexSize) : 4; // returnType (TypeIndex)
    if (version >= 31.0) {
        size += 4; // returnParameterToken
    }
    size += (version >= 39.0) ? static_cast<size_t>(parameterIndexSize) : 4; // parameterStart (ParameterIndex in v39+)
    if (version <= 24.0) {
        size += 4; // customAttributeIndex
    }
    size += (version >= 38.0) ? static_cast<size_t>(genericContainerIndexSize) : 4; // genericContainerIndex
    if (version <= 24.1) {
        size += 4; // methodIndex
        size += 4; // invokerIndex
        size += 4; // delegateWrapperIndex
        size += 4; // rgctxStartIndex
        size += 4; // rgctxCount
    }
    size += 4; // token
    size += 2; // flags
    size += 2; // iflags
    size += 2; // slot
    size += 2; // parameterCount
    return size;
}

inline size_t GetParameterDefinitionSize(double version, int typeIndexSize = 4) {
    size_t size = 0;
    size += 4; // nameIndex
    size += 4; // token
    if (version <= 24.0) {
        size += 4; // customAttributeIndex
    }
    size += (version >= 38.0) ? static_cast<size_t>(typeIndexSize) : 4; // typeIndex (TypeIndex)
    return size;
}

inline size_t GetFieldDefinitionSize(double version, int typeIndexSize = 4) {
    size_t size = 0;
    size += 4; // nameIndex
    size += (version >= 38.0) ? static_cast<size_t>(typeIndexSize) : 4; // typeIndex (TypeIndex)
    if (version <= 24.0) {
        size += 4; // customAttributeIndex
    }
    if (version >= 19.0) {
        size += 4; // token
    }
    return size;
}

inline size_t GetGenericContainerSize() {
    return 16;
}

inline size_t GetGenericParameterSize(double version = 0, int genericContainerIndexSize = 4) {
    size_t size = 0;
    size += (version >= 38.0) ? static_cast<size_t>(genericContainerIndexSize) : 4; // ownerIndex (GenericContainerIndex)
    size += 4; // nameIndex
    size += 2; // constraintsStart
    size += 2; // constraintsCount
    size += 2; // num
    size += 2; // flags
    return size;
}

inline size_t GetCustomAttributeDataRangeSize() {
    return 8;
}

inline size_t GetFieldDefaultValueSize(double version = 0, int typeIndexSize = 4) {
    size_t size = 0;
    size += 4; // fieldIndex
    size += (version >= 38.0) ? static_cast<size_t>(typeIndexSize) : 4; // typeIndex (TypeIndex)
    size += 4; // dataIndex
    return size;
}

inline size_t GetParameterDefaultValueSize(double version = 0, int typeIndexSize = 4, int parameterIndexSize = 4) {
    size_t size = 0;
    size += (version >= 38.0) ? static_cast<size_t>(parameterIndexSize) : 4; // parameterIndex (ParameterIndex)
    size += (version >= 38.0) ? static_cast<size_t>(typeIndexSize) : 4; // typeIndex (TypeIndex)
    size += 4; // dataIndex
    return size;
}

inline size_t GetPropertyDefinitionSize(double version) {
    size_t size = 0;
    size += 4; // nameIndex
    size += 4; // get
    size += 4; // set
    size += 4; // attrs
    if (version <= 24.0) {
        size += 4; // customAttributeIndex
    }
    if (version >= 19.0) {
        size += 4; // token
    }
    return size;
}

inline size_t GetEventDefinitionSize(double version, int typeIndexSize = 4) {
    size_t size = 0;
    size += 4; // nameIndex
    size += (version >= 38.0) ? static_cast<size_t>(typeIndexSize) : 4; // typeIndex (TypeIndex)
    size += 4; // add
    size += 4; // remove
    size += 4; // raise
    if (version <= 24.0) {
        size += 4; // customAttributeIndex
    }
    if (version >= 19.0) {
        size += 4; // token
    }
    return size;
}

} // namespace SwitchPort
