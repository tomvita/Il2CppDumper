#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "SwitchPort/MetadataFormat.h"

namespace SwitchPort {

class MetadataFile {
public:
    bool Load(const std::string& path, std::string* error);

    const MetadataHeader& Header() const { return header_; }

    // Variable-width index sizes (1, 2, or 4 bytes; always 4 for versions < 38)
    int TypeIndexSize() const { return typeIndexSize_; }
    int TypeDefinitionIndexSize() const { return typeDefinitionIndexSize_; }
    int GenericContainerIndexSize() const { return genericContainerIndexSize_; }
    int ParameterIndexSize() const { return parameterIndexSize_; }

    // Accessors that return the correct offset/size regardless of header version
    uint32_t GetFieldAndParameterDefaultValueDataOffset() const {
        return (header_.version >= 38) ? header_.sec_fieldAndParameterDefaultValueData.offset
                                       : header_.fieldAndParameterDefaultValueDataOffset;
    }
    uint32_t GetAttributeDataOffset() const {
        return (header_.version >= 38) ? header_.sec_attributeData.offset : header_.attributeDataOffset;
    }
    int32_t GetAttributeDataSize() const {
        return (header_.version >= 38) ? static_cast<int32_t>(header_.sec_attributeData.size)
                                       : header_.attributeDataSize;
    }

    const std::vector<ImageDefinition>& Images() const { return images_; }
    const std::vector<TypeDefinition>& Types() const { return types_; }
    const std::vector<MethodDefinition>& Methods() const { return methods_; }
    const std::vector<FieldDefinition>& Fields() const { return fields_; }
    const std::vector<ParameterDefinition>& Parameters() const { return parameters_; }
    const std::vector<GenericContainer>& GenericContainers() const { return genericContainers_; }
    const std::vector<GenericParameter>& GenericParameters() const { return genericParameters_; }
    const std::vector<PropertyDefinition>& Properties() const { return properties_; }
    const std::vector<EventDefinition>& Events() const { return events_; }
    const std::vector<CustomAttributeDataRange>& AttributeDataRanges() const { return attributeDataRanges_; }
    const std::vector<int32_t>& NestedTypeIndices() const { return nestedTypeIndices_; }
    const std::vector<int32_t>& InterfaceIndices() const { return interfaceIndices_; }
    bool TryGetFieldDefaultValue(int32_t fieldIndex, FieldDefaultValue* out) const;
    bool TryGetParameterDefaultValue(int32_t parameterIndex, ParameterDefaultValue* out) const;

    bool ReadU8AtMetadataOffset(uint32_t absOffset, uint8_t* out) const;
    bool ReadI8AtMetadataOffset(uint32_t absOffset, int8_t* out) const;
    bool ReadU16AtMetadataOffset(uint32_t absOffset, uint16_t* out) const;
    bool ReadI16AtMetadataOffset(uint32_t absOffset, int16_t* out) const;
    bool ReadU32AtMetadataOffset(uint32_t absOffset, uint32_t* out) const;
    bool ReadI32AtMetadataOffset(uint32_t absOffset, int32_t* out) const;
    bool ReadU64AtMetadataOffset(uint32_t absOffset, uint64_t* out) const;
    bool ReadI64AtMetadataOffset(uint32_t absOffset, int64_t* out) const;
    bool ReadF32AtMetadataOffset(uint32_t absOffset, float* out) const;
    bool ReadF64AtMetadataOffset(uint32_t absOffset, double* out) const;
    bool ReadStringBlobAtMetadataOffset(uint32_t absOffset, std::string* out) const;

    std::string GetString(uint32_t index) const;

private:
    bool ParseHeader(std::string* error);
    bool ParseImages(std::string* error);
    bool ParseTypes(std::string* error);
    bool ParseMethods(std::string* error);
    bool ParseFields(std::string* error);
    bool ParseParameters(std::string* error);
    bool ParseGenericParameters(std::string* error);
    bool ParseGenericContainers(std::string* error);
    bool ParseProperties(std::string* error);
    bool ParseEvents(std::string* error);
    bool ParseNestedTypes(std::string* error);
    bool ParseInterfaces(std::string* error);
    bool ParseFieldDefaultValues(std::string* error);
    bool ParseParameterDefaultValues(std::string* error);
    bool ParseAttributeDataRanges(std::string* error);

    void SetError(std::string* error, const std::string& message) const;

    std::vector<uint8_t> data_;
    MetadataHeader header_;
    int typeIndexSize_ = 4;
    int typeDefinitionIndexSize_ = 4;
    int genericContainerIndexSize_ = 4;
    int parameterIndexSize_ = 4;
    std::vector<ImageDefinition> images_;
    std::vector<TypeDefinition> types_;
    std::vector<MethodDefinition> methods_;
    std::vector<FieldDefinition> fields_;
    std::vector<ParameterDefinition> parameters_;
    std::vector<GenericContainer> genericContainers_;
    std::vector<GenericParameter> genericParameters_;
    std::vector<PropertyDefinition> properties_;
    std::vector<EventDefinition> events_;
    std::vector<CustomAttributeDataRange> attributeDataRanges_;
    std::vector<int32_t> nestedTypeIndices_;
    std::vector<int32_t> interfaceIndices_;
    std::unordered_map<int32_t, FieldDefaultValue> fieldDefaultValues_;
    std::unordered_map<int32_t, ParameterDefaultValue> parameterDefaultValues_;
};

} // namespace SwitchPort
