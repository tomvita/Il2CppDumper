#include "SwitchPort/MetadataFile.h"

#include <cstring>
#include <fstream>
#include <sstream>

#include "SwitchPort/BinaryReader.h"

namespace SwitchPort {

namespace {

bool ReadFile(const std::string& path, std::vector<uint8_t>* out) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return false;
    }
    file.seekg(0, std::ios::end);
    const std::streamoff size = file.tellg();
    if (size < 0) {
        return false;
    }
    file.seekg(0, std::ios::beg);

    out->resize(static_cast<size_t>(size));
    if (size == 0) {
        return true;
    }

    file.read(reinterpret_cast<char*>(out->data()), size);
    return file.good();
}

bool ValidateArrayBounds(uint32_t offset, int32_t size, size_t elemSize, std::string* error, const char* name, size_t fileSize) {
    if (size < 0) {
        if (error != nullptr) {
            *error = std::string(name) + " size is negative";
        }
        return false;
    }
    const uint64_t end = static_cast<uint64_t>(offset) + static_cast<uint64_t>(size);
    if (end > fileSize) {
        if (error != nullptr) {
            *error = std::string(name) + " exceeds file size";
        }
        return false;
    }
    if (elemSize != 0 && static_cast<size_t>(size) % elemSize != 0) {
        if (error != nullptr) {
            *error = std::string(name) + " size is not aligned to element size";
        }
        return false;
    }
    return true;
}

} // namespace

bool MetadataFile::Load(const std::string& path, std::string* error) {
    images_.clear();
    types_.clear();
    methods_.clear();
    fields_.clear();
    parameters_.clear();
    genericContainers_.clear();
    genericParameters_.clear();
    properties_.clear();
    events_.clear();
    attributeDataRanges_.clear();
    nestedTypeIndices_.clear();
    interfaceIndices_.clear();
    fieldDefaultValues_.clear();
    parameterDefaultValues_.clear();
    header_ = {};

    if (!ReadFile(path, &data_)) {
        SetError(error, "Failed to read file: " + path);
        return false;
    }

    if (!ParseHeader(error)) {
        return false;
    }
    if (!ParseImages(error)) {
        return false;
    }
    if (!ParseTypes(error)) {
        return false;
    }
    if (!ParseMethods(error)) {
        return false;
    }
    if (!ParseFields(error)) {
        return false;
    }
    if (!ParseParameters(error)) {
        return false;
    }
    if (!ParseGenericParameters(error)) {
        return false;
    }
    if (!ParseGenericContainers(error)) {
        return false;
    }
    if (!ParseNestedTypes(error)) {
        return false;
    }
    if (!ParseInterfaces(error)) {
        return false;
    }
    if (!ParseFieldDefaultValues(error)) {
        return false;
    }
    if (!ParseParameterDefaultValues(error)) {
        return false;
    }
    if (!ParseProperties(error)) {
        return false;
    }
    if (!ParseEvents(error)) {
        return false;
    }
    if (!ParseAttributeDataRanges(error)) {
        return false;
    }

    return true;
}

std::string MetadataFile::GetString(uint32_t index) const {
    BinaryReader reader(data_);
    const uint64_t absOffset = static_cast<uint64_t>(header_.stringOffset) + static_cast<uint64_t>(index);
    return reader.ReadCStringAt(static_cast<size_t>(absOffset));
}

bool MetadataFile::ParseHeader(std::string* error) {
    try {
        BinaryReader reader(data_);

        const uint32_t sanity = reader.ReadU32();
        if (sanity != kMetadataMagic) {
            SetError(error, "Invalid metadata magic");
            return false;
        }

        const int32_t version = reader.ReadI32();
        if (version < 16 || version > 31) {
            SetError(error, "Unsupported metadata version: " + std::to_string(version));
            return false;
        }
        header_.version = version;

        (void)reader.ReadU32(); // stringLiteralOffset
        (void)reader.ReadI32(); // stringLiteralSize
        (void)reader.ReadU32(); // stringLiteralDataOffset
        (void)reader.ReadI32(); // stringLiteralDataSize

        header_.stringOffset = reader.ReadU32();
        header_.stringSize = reader.ReadI32();

        header_.eventsOffset = reader.ReadU32();
        header_.eventsSize = reader.ReadI32();
        header_.propertiesOffset = reader.ReadU32();
        header_.propertiesSize = reader.ReadI32();
        header_.methodsOffset = reader.ReadU32();
        header_.methodsSize = reader.ReadI32();
        header_.parameterDefaultValuesOffset = reader.ReadU32();
        header_.parameterDefaultValuesSize = reader.ReadI32();
        header_.fieldDefaultValuesOffset = reader.ReadU32();
        header_.fieldDefaultValuesSize = reader.ReadI32();
        header_.fieldAndParameterDefaultValueDataOffset = reader.ReadU32();
        header_.fieldAndParameterDefaultValueDataSize = reader.ReadI32();
        (void)reader.ReadI32(); // fieldMarshaledSizesOffset
        (void)reader.ReadI32(); // fieldMarshaledSizesSize
        header_.parametersOffset = reader.ReadU32();
        header_.parametersSize = reader.ReadI32();
        header_.fieldsOffset = reader.ReadU32();
        header_.fieldsSize = reader.ReadI32();
        header_.genericParametersOffset = reader.ReadU32();
        header_.genericParametersSize = reader.ReadI32();
        (void)reader.ReadU32(); // genericParameterConstraintsOffset
        (void)reader.ReadI32(); // genericParameterConstraintsSize
        header_.genericContainersOffset = reader.ReadU32();
        header_.genericContainersSize = reader.ReadI32();
        header_.nestedTypesOffset = reader.ReadU32();
        header_.nestedTypesSize = reader.ReadI32();
        header_.interfacesOffset = reader.ReadU32();
        header_.interfacesSize = reader.ReadI32();
        (void)reader.ReadU32(); // vtableMethodsOffset
        (void)reader.ReadI32(); // vtableMethodsSize
        (void)reader.ReadI32(); // interfaceOffsetsOffset
        (void)reader.ReadI32(); // interfaceOffsetsSize

        header_.typeDefinitionsOffset = reader.ReadU32();
        header_.typeDefinitionsSize = reader.ReadI32();

        if (header_.version <= 24) {
            (void)reader.ReadU32(); // rgctxEntriesOffset
            (void)reader.ReadI32(); // rgctxEntriesCount
        }

        header_.imagesOffset = reader.ReadU32();
        header_.imagesSize = reader.ReadI32();

        (void)reader.ReadU32(); // assembliesOffset
        (void)reader.ReadI32(); // assembliesSize

        if (header_.version >= 29) {
            (void)reader.ReadU32(); // fieldRefsOffset
            (void)reader.ReadI32(); // fieldRefsSize
            (void)reader.ReadI32(); // referencedAssembliesOffset
            (void)reader.ReadI32(); // referencedAssembliesSize
            header_.attributeDataOffset = reader.ReadU32();
            header_.attributeDataSize = reader.ReadI32();
            header_.attributeDataRangeOffset = reader.ReadU32();
            header_.attributeDataRangeSize = reader.ReadI32();
        }

        if (!ValidateArrayBounds(header_.stringOffset, header_.stringSize, 1, error, "string table", data_.size())) {
            return false;
        }
        if (!ValidateArrayBounds(header_.imagesOffset, header_.imagesSize, GetImageDefinitionSize(header_.version), error,
                                 "image table", data_.size())) {
            return false;
        }
        if (!ValidateArrayBounds(header_.typeDefinitionsOffset, header_.typeDefinitionsSize, GetTypeDefinitionSize(header_.version),
                                 error, "type table", data_.size())) {
            return false;
        }
        if (!ValidateArrayBounds(header_.methodsOffset, header_.methodsSize, GetMethodDefinitionSize(header_.version), error,
                                 "method table", data_.size())) {
            return false;
        }
        if (!ValidateArrayBounds(header_.fieldsOffset, header_.fieldsSize, GetFieldDefinitionSize(header_.version), error,
                                 "field table", data_.size())) {
            return false;
        }
        if (!ValidateArrayBounds(header_.parametersOffset, header_.parametersSize, GetParameterDefinitionSize(header_.version),
                                 error, "parameter table", data_.size())) {
            return false;
        }
        if (!ValidateArrayBounds(header_.genericParametersOffset, header_.genericParametersSize, GetGenericParameterSize(), error,
                                 "generic parameter table", data_.size())) {
            return false;
        }
        if (!ValidateArrayBounds(header_.genericContainersOffset, header_.genericContainersSize, GetGenericContainerSize(), error,
                                 "generic container table", data_.size())) {
            return false;
        }
        if (!ValidateArrayBounds(header_.nestedTypesOffset, header_.nestedTypesSize, 4, error, "nested type index table",
                                 data_.size())) {
            return false;
        }
        if (!ValidateArrayBounds(header_.interfacesOffset, header_.interfacesSize, 4, error, "interface index table",
                                 data_.size())) {
            return false;
        }
        if (!ValidateArrayBounds(header_.fieldDefaultValuesOffset, header_.fieldDefaultValuesSize, GetFieldDefaultValueSize(),
                                 error, "field default value table", data_.size())) {
            return false;
        }
        if (!ValidateArrayBounds(header_.parameterDefaultValuesOffset, header_.parameterDefaultValuesSize,
                                 GetParameterDefaultValueSize(), error, "parameter default value table", data_.size())) {
            return false;
        }
        if (!ValidateArrayBounds(header_.fieldAndParameterDefaultValueDataOffset, header_.fieldAndParameterDefaultValueDataSize, 1,
                                 error, "default value blob", data_.size())) {
            return false;
        }
        if (!ValidateArrayBounds(header_.propertiesOffset, header_.propertiesSize, GetPropertyDefinitionSize(header_.version),
                                 error, "property table", data_.size())) {
            return false;
        }
        if (!ValidateArrayBounds(header_.eventsOffset, header_.eventsSize, GetEventDefinitionSize(header_.version), error,
                                 "event table", data_.size())) {
            return false;
        }
        if (header_.version >= 29) {
            if (!ValidateArrayBounds(header_.attributeDataOffset, header_.attributeDataSize, 1, error, "attribute data blob",
                                     data_.size())) {
                return false;
            }
            if (!ValidateArrayBounds(header_.attributeDataRangeOffset, header_.attributeDataRangeSize,
                                     GetCustomAttributeDataRangeSize(), error, "attribute data range table", data_.size())) {
                return false;
            }
        }
    } catch (const std::exception& ex) {
        SetError(error, std::string("Failed to parse header: ") + ex.what());
        return false;
    }

    return true;
}

bool MetadataFile::ParseImages(std::string* error) {
    try {
        BinaryReader reader(data_, header_.imagesOffset);
        const size_t imageCount = static_cast<size_t>(header_.imagesSize) / GetImageDefinitionSize(header_.version);

        images_.reserve(imageCount);
        for (size_t i = 0; i < imageCount; ++i) {
            ImageDefinition image{};
            image.nameIndex = reader.ReadU32();
            image.assemblyIndex = reader.ReadI32();
            image.typeStart = reader.ReadI32();
            image.typeCount = reader.ReadU32();

            if (header_.version >= 24) {
                (void)reader.ReadI32(); // exportedTypeStart
                (void)reader.ReadU32(); // exportedTypeCount
            }

            image.entryPointIndex = reader.ReadI32();

            if (header_.version >= 19) {
                (void)reader.ReadU32(); // token
            }
            if (header_.version >= 24.1) {
                image.customAttributeStart = reader.ReadI32();
                image.customAttributeCount = reader.ReadU32();
            }

            images_.push_back(image);
        }
    } catch (const std::exception& ex) {
        SetError(error, std::string("Failed to parse image table: ") + ex.what());
        return false;
    }
    return true;
}

bool MetadataFile::ParseTypes(std::string* error) {
    try {
        BinaryReader reader(data_, header_.typeDefinitionsOffset);
        const size_t typeCount = static_cast<size_t>(header_.typeDefinitionsSize) / GetTypeDefinitionSize(header_.version);

        types_.reserve(typeCount);
        for (size_t i = 0; i < typeCount; ++i) {
            TypeDefinition type{};
            type.nameIndex = reader.ReadU32();
            type.namespaceIndex = reader.ReadU32();

            if (header_.version <= 24) {
                (void)reader.ReadI32(); // customAttributeIndex
            }
            (void)reader.ReadI32(); // byvalTypeIndex
            if (header_.version <= 24.5) {
                (void)reader.ReadI32(); // byrefTypeIndex
            }

            type.declaringTypeIndex = reader.ReadI32();
            type.parentIndex = reader.ReadI32();
            type.elementTypeIndex = reader.ReadI32();

            if (header_.version <= 24.1) {
                (void)reader.ReadI32(); // rgctxStartIndex
                (void)reader.ReadI32(); // rgctxCount
            }

            type.genericContainerIndex = reader.ReadI32();

            if (header_.version <= 22) {
                (void)reader.ReadI32(); // delegateWrapperFromManagedToNativeIndex
                (void)reader.ReadI32(); // marshalingFunctionsIndex
            }
            if (header_.version >= 21 && header_.version <= 22) {
                (void)reader.ReadI32(); // ccwFunctionIndex
                (void)reader.ReadI32(); // guidIndex
            }

            type.flags = reader.ReadU32();

            type.fieldStart = reader.ReadI32();
            type.methodStart = reader.ReadI32();
            type.eventStart = reader.ReadI32();
            type.propertyStart = reader.ReadI32();
            type.nestedTypesStart = reader.ReadI32();
            type.interfacesStart = reader.ReadI32();
            (void)reader.ReadI32(); // vtableStart
            (void)reader.ReadI32(); // interfaceOffsetsStart

            type.methodCount = reader.ReadU16();
            type.propertyCount = reader.ReadU16();
            type.fieldCount = reader.ReadU16();
            type.eventCount = reader.ReadU16();
            type.nestedTypeCount = reader.ReadU16();
            (void)reader.ReadU16(); // vtable_count
            type.interfacesCount = reader.ReadU16();
            (void)reader.ReadU16(); // interface_offsets_count

            type.bitfield = reader.ReadU32();
            if (header_.version >= 19) {
                type.token = reader.ReadU32();
            }

            types_.push_back(type);
        }

        for (const auto& image : images_) {
            const uint64_t end = static_cast<uint64_t>(image.typeStart) + static_cast<uint64_t>(image.typeCount);
            if (image.typeStart < 0 || end > types_.size()) {
                std::ostringstream oss;
                oss << "Image type range out of bounds: start=" << image.typeStart << " count=" << image.typeCount;
                SetError(error, oss.str());
                return false;
            }
        }
    } catch (const std::exception& ex) {
        SetError(error, std::string("Failed to parse type table: ") + ex.what());
        return false;
    }
    return true;
}

bool MetadataFile::ParseMethods(std::string* error) {
    try {
        BinaryReader reader(data_, header_.methodsOffset);
        const size_t methodCount = static_cast<size_t>(header_.methodsSize) / GetMethodDefinitionSize(header_.version);
        methods_.reserve(methodCount);

        for (size_t i = 0; i < methodCount; ++i) {
            MethodDefinition method{};
            method.nameIndex = reader.ReadU32();
            method.declaringType = reader.ReadI32();
            method.returnType = reader.ReadI32();
            if (header_.version >= 31) {
                (void)reader.ReadI32(); // returnParameterToken
            }
            method.parameterStart = reader.ReadI32();
            if (header_.version <= 24) {
                (void)reader.ReadI32(); // customAttributeIndex
            }
            method.genericContainerIndex = reader.ReadI32();
            if (header_.version <= 24) {
                (void)reader.ReadI32(); // methodIndex
                (void)reader.ReadI32(); // invokerIndex
                (void)reader.ReadI32(); // delegateWrapperIndex
                (void)reader.ReadI32(); // rgctxStartIndex
                (void)reader.ReadI32(); // rgctxCount
            }
            method.token = reader.ReadU32();
            method.flags = reader.ReadU16();
            (void)reader.ReadU16(); // iflags
            method.slot = reader.ReadU16();
            method.parameterCount = reader.ReadU16();
            methods_.push_back(method);
        }
    } catch (const std::exception& ex) {
        SetError(error, std::string("Failed to parse method table: ") + ex.what());
        return false;
    }
    return true;
}

bool MetadataFile::ParseFields(std::string* error) {
    try {
        BinaryReader reader(data_, header_.fieldsOffset);
        const size_t fieldCount = static_cast<size_t>(header_.fieldsSize) / GetFieldDefinitionSize(header_.version);
        fields_.reserve(fieldCount);

        for (size_t i = 0; i < fieldCount; ++i) {
            FieldDefinition field{};
            field.nameIndex = reader.ReadU32();
            field.typeIndex = reader.ReadI32();
            if (header_.version <= 24) {
                (void)reader.ReadI32(); // customAttributeIndex
            }
            if (header_.version >= 19) {
                field.token = reader.ReadU32();
            }
            fields_.push_back(field);
        }
    } catch (const std::exception& ex) {
        SetError(error, std::string("Failed to parse field table: ") + ex.what());
        return false;
    }
    return true;
}

bool MetadataFile::ParseParameters(std::string* error) {
    try {
        BinaryReader reader(data_, header_.parametersOffset);
        const size_t parameterCount = static_cast<size_t>(header_.parametersSize) / GetParameterDefinitionSize(header_.version);
        parameters_.reserve(parameterCount);

        for (size_t i = 0; i < parameterCount; ++i) {
            ParameterDefinition parameter{};
            parameter.nameIndex = reader.ReadU32();
            (void)reader.ReadU32(); // token
            if (header_.version <= 24) {
                (void)reader.ReadI32(); // customAttributeIndex
            }
            parameter.typeIndex = reader.ReadI32();
            parameters_.push_back(parameter);
        }
    } catch (const std::exception& ex) {
        SetError(error, std::string("Failed to parse parameter table: ") + ex.what());
        return false;
    }
    return true;
}

bool MetadataFile::ParseGenericParameters(std::string* error) {
    try {
        BinaryReader reader(data_, header_.genericParametersOffset);
        const size_t count = static_cast<size_t>(header_.genericParametersSize) / GetGenericParameterSize();
        genericParameters_.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            GenericParameter gp{};
            gp.ownerIndex = reader.ReadI32();
            gp.nameIndex = reader.ReadU32();
            gp.constraintsStart = static_cast<int16_t>(reader.ReadU16());
            gp.constraintsCount = static_cast<int16_t>(reader.ReadU16());
            gp.num = reader.ReadU16();
            gp.flags = reader.ReadU16();
            genericParameters_.push_back(gp);
        }
    } catch (const std::exception& ex) {
        SetError(error, std::string("Failed to parse generic parameter table: ") + ex.what());
        return false;
    }
    return true;
}

bool MetadataFile::ParseGenericContainers(std::string* error) {
    try {
        BinaryReader reader(data_, header_.genericContainersOffset);
        const size_t count = static_cast<size_t>(header_.genericContainersSize) / GetGenericContainerSize();
        genericContainers_.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            GenericContainer gc{};
            gc.ownerIndex = reader.ReadI32();
            gc.typeArgc = reader.ReadI32();
            gc.isMethod = reader.ReadI32();
            gc.genericParameterStart = reader.ReadI32();
            genericContainers_.push_back(gc);
        }
    } catch (const std::exception& ex) {
        SetError(error, std::string("Failed to parse generic container table: ") + ex.what());
        return false;
    }
    return true;
}

bool MetadataFile::ParseNestedTypes(std::string* error) {
    try {
        BinaryReader reader(data_, header_.nestedTypesOffset);
        const size_t count = static_cast<size_t>(header_.nestedTypesSize) / 4;
        nestedTypeIndices_.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            nestedTypeIndices_.push_back(reader.ReadI32());
        }
    } catch (const std::exception& ex) {
        SetError(error, std::string("Failed to parse nested type index table: ") + ex.what());
        return false;
    }
    return true;
}

bool MetadataFile::ParseInterfaces(std::string* error) {
    try {
        BinaryReader reader(data_, header_.interfacesOffset);
        const size_t count = static_cast<size_t>(header_.interfacesSize) / 4;
        interfaceIndices_.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            interfaceIndices_.push_back(reader.ReadI32());
        }
    } catch (const std::exception& ex) {
        SetError(error, std::string("Failed to parse interface index table: ") + ex.what());
        return false;
    }
    return true;
}

bool MetadataFile::ParseFieldDefaultValues(std::string* error) {
    try {
        BinaryReader reader(data_, header_.fieldDefaultValuesOffset);
        const size_t count = static_cast<size_t>(header_.fieldDefaultValuesSize) / GetFieldDefaultValueSize();
        for (size_t i = 0; i < count; ++i) {
            FieldDefaultValue value{};
            value.fieldIndex = reader.ReadI32();
            value.typeIndex = reader.ReadI32();
            value.dataIndex = reader.ReadI32();
            fieldDefaultValues_[value.fieldIndex] = value;
        }
    } catch (const std::exception& ex) {
        SetError(error, std::string("Failed to parse field default value table: ") + ex.what());
        return false;
    }
    return true;
}

bool MetadataFile::ParseParameterDefaultValues(std::string* error) {
    try {
        BinaryReader reader(data_, header_.parameterDefaultValuesOffset);
        const size_t count = static_cast<size_t>(header_.parameterDefaultValuesSize) / GetParameterDefaultValueSize();
        for (size_t i = 0; i < count; ++i) {
            ParameterDefaultValue value{};
            value.parameterIndex = reader.ReadI32();
            value.typeIndex = reader.ReadI32();
            value.dataIndex = reader.ReadI32();
            parameterDefaultValues_[value.parameterIndex] = value;
        }
    } catch (const std::exception& ex) {
        SetError(error, std::string("Failed to parse parameter default value table: ") + ex.what());
        return false;
    }
    return true;
}

bool MetadataFile::ParseProperties(std::string* error) {
    try {
        BinaryReader reader(data_, header_.propertiesOffset);
        const size_t propertyCount = static_cast<size_t>(header_.propertiesSize) / GetPropertyDefinitionSize(header_.version);
        properties_.reserve(propertyCount);

        for (size_t i = 0; i < propertyCount; ++i) {
            PropertyDefinition property{};
            property.nameIndex = reader.ReadU32();
            property.get = reader.ReadI32();
            property.set = reader.ReadI32();
            property.attrs = reader.ReadU32();
            if (header_.version <= 24) {
                (void)reader.ReadI32(); // customAttributeIndex
            }
            if (header_.version >= 19) {
                property.token = reader.ReadU32();
            }
            properties_.push_back(property);
        }
    } catch (const std::exception& ex) {
        SetError(error, std::string("Failed to parse property table: ") + ex.what());
        return false;
    }
    return true;
}

bool MetadataFile::ParseEvents(std::string* error) {
    try {
        BinaryReader reader(data_, header_.eventsOffset);
        const size_t eventCount = static_cast<size_t>(header_.eventsSize) / GetEventDefinitionSize(header_.version);
        events_.reserve(eventCount);

        for (size_t i = 0; i < eventCount; ++i) {
            EventDefinition eventDef{};
            eventDef.nameIndex = reader.ReadU32();
            eventDef.typeIndex = reader.ReadI32();
            eventDef.add = reader.ReadI32();
            eventDef.remove = reader.ReadI32();
            eventDef.raise = reader.ReadI32();
            if (header_.version <= 24) {
                (void)reader.ReadI32(); // customAttributeIndex
            }
            if (header_.version >= 19) {
                eventDef.token = reader.ReadU32();
            }
            events_.push_back(eventDef);
        }
    } catch (const std::exception& ex) {
        SetError(error, std::string("Failed to parse event table: ") + ex.what());
        return false;
    }
    return true;
}

bool MetadataFile::ParseAttributeDataRanges(std::string* error) {
    if (header_.version < 29) {
        return true;
    }
    try {
        BinaryReader reader(data_, header_.attributeDataRangeOffset);
        const size_t count = static_cast<size_t>(header_.attributeDataRangeSize) / GetCustomAttributeDataRangeSize();
        attributeDataRanges_.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            CustomAttributeDataRange r{};
            r.token = reader.ReadU32();
            r.startOffset = reader.ReadU32();
            attributeDataRanges_.push_back(r);
        }
    } catch (const std::exception& ex) {
        SetError(error, std::string("Failed to parse attribute data range table: ") + ex.what());
        return false;
    }
    return true;
}

void MetadataFile::SetError(std::string* error, const std::string& message) const {
    if (error != nullptr) {
        *error = message;
    }
}

bool MetadataFile::TryGetFieldDefaultValue(int32_t fieldIndex, FieldDefaultValue* out) const {
    const auto it = fieldDefaultValues_.find(fieldIndex);
    if (it == fieldDefaultValues_.end()) {
        return false;
    }
    if (out != nullptr) {
        *out = it->second;
    }
    return true;
}

bool MetadataFile::TryGetParameterDefaultValue(int32_t parameterIndex, ParameterDefaultValue* out) const {
    const auto it = parameterDefaultValues_.find(parameterIndex);
    if (it == parameterDefaultValues_.end()) {
        return false;
    }
    if (out != nullptr) {
        *out = it->second;
    }
    return true;
}

bool MetadataFile::ReadU8AtMetadataOffset(uint32_t absOffset, uint8_t* out) const {
    if (absOffset >= data_.size()) {
        return false;
    }
    *out = data_[absOffset];
    return true;
}

bool MetadataFile::ReadI8AtMetadataOffset(uint32_t absOffset, int8_t* out) const {
    uint8_t v = 0;
    if (!ReadU8AtMetadataOffset(absOffset, &v)) {
        return false;
    }
    *out = static_cast<int8_t>(v);
    return true;
}

bool MetadataFile::ReadU16AtMetadataOffset(uint32_t absOffset, uint16_t* out) const {
    if (absOffset + 2 > data_.size()) {
        return false;
    }
    std::memcpy(out, data_.data() + absOffset, 2);
    return true;
}

bool MetadataFile::ReadI16AtMetadataOffset(uint32_t absOffset, int16_t* out) const {
    return ReadU16AtMetadataOffset(absOffset, reinterpret_cast<uint16_t*>(out));
}

bool MetadataFile::ReadU32AtMetadataOffset(uint32_t absOffset, uint32_t* out) const {
    if (absOffset + 4 > data_.size()) {
        return false;
    }
    std::memcpy(out, data_.data() + absOffset, 4);
    return true;
}

bool MetadataFile::ReadI32AtMetadataOffset(uint32_t absOffset, int32_t* out) const {
    return ReadU32AtMetadataOffset(absOffset, reinterpret_cast<uint32_t*>(out));
}

bool MetadataFile::ReadU64AtMetadataOffset(uint32_t absOffset, uint64_t* out) const {
    if (absOffset + 8 > data_.size()) {
        return false;
    }
    std::memcpy(out, data_.data() + absOffset, 8);
    return true;
}

bool MetadataFile::ReadI64AtMetadataOffset(uint32_t absOffset, int64_t* out) const {
    return ReadU64AtMetadataOffset(absOffset, reinterpret_cast<uint64_t*>(out));
}

bool MetadataFile::ReadF32AtMetadataOffset(uint32_t absOffset, float* out) const {
    if (absOffset + 4 > data_.size()) {
        return false;
    }
    std::memcpy(out, data_.data() + absOffset, 4);
    return true;
}

bool MetadataFile::ReadF64AtMetadataOffset(uint32_t absOffset, double* out) const {
    if (absOffset + 8 > data_.size()) {
        return false;
    }
    std::memcpy(out, data_.data() + absOffset, 8);
    return true;
}

bool MetadataFile::ReadStringBlobAtMetadataOffset(uint32_t absOffset, std::string* out) const {
    int32_t length = 0;
    if (!ReadI32AtMetadataOffset(absOffset, &length) || length < 0) {
        return false;
    }
    const uint32_t dataOff = absOffset + 4;
    if (dataOff + static_cast<uint32_t>(length) > data_.size()) {
        return false;
    }
    out->assign(reinterpret_cast<const char*>(data_.data() + dataOff), static_cast<size_t>(length));
    return true;
}

} // namespace SwitchPort
