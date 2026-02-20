#pragma once

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

namespace Il2CppDumper {

class RvaIndexLookup {
public:
    // Load index1/index2 files and prepare in-memory routing table from index1.
    bool Load(const std::string& index1Path, const std::string& index2Path, std::string* error = nullptr);

    // Finds the mapped value whose RVA is the greatest RVA <= queryRva.
    // v1/v2 indexes map to dump.cs line numbers, v3+ maps to dump.cs byte offsets.
    // Returns false if no such line exists.
    bool FindClosestLowerOrEqualLine(uint64_t queryRva, uint32_t* outLine) const;
    uint32_t GetTotalDumpLines() const { return totalDumpLines_; }

private:
    struct Index1Entry {
        uint64_t startRva = 0;
        uint64_t index2Offset = 0;
        uint32_t index2Size = 0;
    };

    struct DecodedBlock {
        std::vector<uint64_t> rvas;
        std::vector<uint32_t> lines;
    };

    bool EnsureIndex2Open(std::string* error) const;
    bool LoadDecodedBlock(size_t blockIndex, DecodedBlock* outBlock, std::string* error) const;

    static uint16_t ReadLe16(const uint8_t* p);
    static uint32_t ReadLe32(const uint8_t* p);
    static uint64_t ReadLe64(const uint8_t* p);

    static bool ReadFully(std::ifstream& stream, uint8_t* dst, size_t size);
    static void SetError(std::string* error, const std::string& value);

    std::vector<Index1Entry> index1Entries_;
    std::string index2Path_;
    uint32_t totalDumpLines_ = 0;

    // Mutable for cheap repeated lookups from a const query API.
    mutable std::ifstream index2Stream_;
    mutable bool index2OpenAttempted_ = false;
    mutable std::string lastError_;

    // Single-block cache keeps hot queries fast with minimal memory.
    mutable size_t cachedBlockIndex_ = static_cast<size_t>(-1);
    mutable DecodedBlock cachedBlock_;
};

} // namespace Il2CppDumper
