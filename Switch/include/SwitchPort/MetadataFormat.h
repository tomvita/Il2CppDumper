#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>

namespace SwitchPort {

constexpr uint32_t kMetadataMagic = 0xFAB11BAF;

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

inline size_t GetImageDefinitionSize(double version) {
    size_t size = 0;
    size += 4; // nameIndex
    size += 4; // assemblyIndex
    size += 4; // typeStart
    size += 4; // typeCount
    if (version >= 24.0) {
        size += 4; // exportedTypeStart
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

inline size_t GetTypeDefinitionSize(double version) {
    size_t size = 0;
    size += 4; // nameIndex
    size += 4; // namespaceIndex
    if (version <= 24.0) {
        size += 4; // customAttributeIndex
    }
    size += 4; // byvalTypeIndex
    if (version <= 24.5) {
        size += 4; // byrefTypeIndex
    }
    size += 4; // declaringTypeIndex
    size += 4; // parentIndex
    size += 4; // elementTypeIndex
    if (version <= 24.1) {
        size += 4; // rgctxStartIndex
        size += 4; // rgctxCount
    }
    size += 4; // genericContainerIndex
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

inline size_t GetMethodDefinitionSize(double version) {
    size_t size = 0;
    size += 4; // nameIndex
    size += 4; // declaringType
    size += 4; // returnType
    if (version >= 31.0) {
        size += 4; // returnParameterToken
    }
    size += 4; // parameterStart
    if (version <= 24.0) {
        size += 4; // customAttributeIndex
    }
    size += 4; // genericContainerIndex
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

inline size_t GetParameterDefinitionSize(double version) {
    size_t size = 0;
    size += 4; // nameIndex
    size += 4; // token
    if (version <= 24.0) {
        size += 4; // customAttributeIndex
    }
    size += 4; // typeIndex
    return size;
}

inline size_t GetFieldDefinitionSize(double version) {
    size_t size = 0;
    size += 4; // nameIndex
    size += 4; // typeIndex
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

inline size_t GetGenericParameterSize() {
    return 16;
}

inline size_t GetCustomAttributeDataRangeSize() {
    return 8;
}

inline size_t GetFieldDefaultValueSize() {
    return 12;
}

inline size_t GetParameterDefaultValueSize() {
    return 12;
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

inline size_t GetEventDefinitionSize(double version) {
    size_t size = 0;
    size += 4; // nameIndex
    size += 4; // typeIndex
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
