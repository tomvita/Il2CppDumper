#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace SwitchPort {

class ElfImage {
public:
    struct Segment {
        uint64_t vaddr = 0;
        uint64_t memsz = 0;
        uint64_t fileOffset = 0;
        uint64_t filesz = 0;
        uint32_t flags = 0;
    };

    bool Load(const std::string& path, std::string* error);

    // Map a virtual address to file offset. Returns false when unmapped.
    bool TryMapVaddrToOffset(uint64_t vaddr, uint64_t* outOffset) const;
    bool TryMapOffsetToVaddr(uint64_t offset, uint64_t* outVaddr) const;

    bool ReadBytesAtVaddr(uint64_t vaddr, size_t size, std::vector<uint8_t>* out) const;
    bool ReadBytesAtOffset(uint64_t offset, size_t size, std::vector<uint8_t>* out) const;
    bool ReadU8AtVaddr(uint64_t vaddr, uint8_t* out) const;
    bool ReadI32AtVaddr(uint64_t vaddr, int32_t* out) const;
    bool ReadU64AtOffset(uint64_t offset, uint64_t* out) const;
    bool ReadU32AtVaddr(uint64_t vaddr, uint32_t* out) const;
    bool ReadU64AtVaddr(uint64_t vaddr, uint64_t* out) const;
    bool ReadCStringAtVaddr(uint64_t vaddr, std::string* out) const;
    bool FindDynamicSymbolVaddr(const std::string& symbolName, uint64_t* outVaddr) const;

    bool Is64Bit() const { return is64Bit_; }
    bool IsLittleEndian() const { return isLittleEndian_; }
    size_t LoadSegmentCount() const { return segments_.size(); }
    const std::vector<Segment>& Segments() const { return segments_; }

private:
    bool is64Bit_ = false;
    bool isLittleEndian_ = false;
    std::vector<uint8_t> data_;
    std::vector<Segment> segments_;
};

} // namespace SwitchPort
