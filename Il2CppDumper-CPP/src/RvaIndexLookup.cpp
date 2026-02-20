#include "Il2CppDumper/RvaIndexLookup.h"

#include <algorithm>
#include <array>
#include <limits>

namespace Il2CppDumper {

namespace {

constexpr std::array<uint8_t, 4> kIndex1Magic = {'I', 'D', 'X', '1'};
constexpr std::array<uint8_t, 4> kIndex2Magic = {'I', 'D', 'X', '2'};
constexpr uint16_t kVersion1 = 1;
constexpr uint16_t kVersion2 = 2;
constexpr uint16_t kVersion3 = 3;

} // namespace

bool RvaIndexLookup::Load(const std::string& index1Path, const std::string& index2Path, std::string* error) {
    index1Entries_.clear();
    index2Path_.clear();
    if (index2Stream_.is_open()) {
        index2Stream_.close();
    }
    index2OpenAttempted_ = false;
    lastError_.clear();
    totalDumpLines_ = 0;
    cachedBlockIndex_ = static_cast<size_t>(-1);
    cachedBlock_ = {};

    std::ifstream f(index1Path, std::ios::binary);
    if (!f) {
        SetError(error, "Failed to open index1 file: " + index1Path);
        return false;
    }

    std::array<uint8_t, 12> header{};
    if (!ReadFully(f, header.data(), header.size())) {
        SetError(error, "Failed to read index1 header");
        return false;
    }
    if (!std::equal(kIndex1Magic.begin(), kIndex1Magic.end(), header.begin())) {
        SetError(error, "index1 magic mismatch (expected IDX1)");
        return false;
    }

    const uint16_t version = ReadLe16(header.data() + 4);
    if (version != kVersion1 && version != kVersion2 && version != kVersion3) {
        SetError(error, "Unsupported index1 version");
        return false;
    }

    const uint32_t entryCount = ReadLe32(header.data() + 8);
    index1Entries_.reserve(entryCount);

    std::array<uint8_t, 24> entryBuf{};
    for (uint32_t i = 0; i < entryCount; ++i) {
        if (!ReadFully(f, entryBuf.data(), entryBuf.size())) {
            SetError(error, "Failed to read index1 entry");
            index1Entries_.clear();
            return false;
        }

        Index1Entry entry{};
        entry.startRva = ReadLe64(entryBuf.data());
        entry.index2Offset = ReadLe64(entryBuf.data() + 8);
        entry.index2Size = ReadLe32(entryBuf.data() + 16);
        index1Entries_.push_back(entry);
    }

    if (index1Entries_.empty()) {
        SetError(error, "index1 has no entries");
        return false;
    }

    if (!std::is_sorted(index1Entries_.begin(), index1Entries_.end(),
                        [](const Index1Entry& a, const Index1Entry& b) { return a.startRva < b.startRva; })) {
        SetError(error, "index1 entries are not sorted by startRva");
        index1Entries_.clear();
        return false;
    }

    index2Path_ = index2Path;
    if (!EnsureIndex2Open(error)) {
        index1Entries_.clear();
        index2Path_.clear();
        return false;
    }

    std::array<uint8_t, 12> idx2HeaderBase{};
    index2Stream_.seekg(0, std::ios::beg);
    if (!ReadFully(index2Stream_, idx2HeaderBase.data(), idx2HeaderBase.size())) {
        SetError(error, "Failed to read index2 header");
        index1Entries_.clear();
        index2Path_.clear();
        return false;
    }
    if (!std::equal(kIndex2Magic.begin(), kIndex2Magic.end(), idx2HeaderBase.begin())) {
        SetError(error, "index2 magic mismatch (expected IDX2)");
        index1Entries_.clear();
        index2Path_.clear();
        return false;
    }

    const uint16_t idx2Version = ReadLe16(idx2HeaderBase.data() + 4);
    const uint32_t blockCount = ReadLe32(idx2HeaderBase.data() + 8);
    if (idx2Version != kVersion1 && idx2Version != kVersion2 && idx2Version != kVersion3) {
        SetError(error, "Unsupported index2 version");
        index1Entries_.clear();
        index2Path_.clear();
        return false;
    }
    if (idx2Version >= kVersion2) {
        std::array<uint8_t, 4> totalLinesBuf{};
        if (!ReadFully(index2Stream_, totalLinesBuf.data(), totalLinesBuf.size())) {
            SetError(error, "Failed to read index2 total_dump_lines");
            index1Entries_.clear();
            index2Path_.clear();
            return false;
        }
        totalDumpLines_ = ReadLe32(totalLinesBuf.data());
    }
    if (blockCount != index1Entries_.size()) {
        SetError(error, "index1 entry count does not match index2 block count");
        index1Entries_.clear();
        index2Path_.clear();
        return false;
    }

    return true;
}

bool RvaIndexLookup::FindClosestLowerOrEqualLine(uint64_t queryRva, uint32_t* outLine) const {
    if (outLine == nullptr || index1Entries_.empty()) {
        return false;
    }
    if (queryRva < index1Entries_.front().startRva) {
        return false;
    }

    const auto it = std::upper_bound(
        index1Entries_.begin(), index1Entries_.end(), queryRva,
        [](uint64_t value, const Index1Entry& entry) { return value < entry.startRva; });
    if (it == index1Entries_.begin()) {
        return false;
    }

    size_t blockIndex = static_cast<size_t>(std::distance(index1Entries_.begin(), it) - 1);

    std::string error;
    DecodedBlock block;
    if (!LoadDecodedBlock(blockIndex, &block, &error)) {
        return false;
    }

    auto floorInBlock = [&](const DecodedBlock& b, uint32_t* out) -> bool {
        if (b.rvas.empty()) {
            return false;
        }
        const auto bit = std::upper_bound(b.rvas.begin(), b.rvas.end(), queryRva);
        if (bit == b.rvas.begin()) {
            return false;
        }
        const size_t i = static_cast<size_t>(std::distance(b.rvas.begin(), bit) - 1);
        *out = b.lines[i];
        return true;
    };

    if (floorInBlock(block, outLine)) {
        return true;
    }

    // Boundary fallback: if a block starts above query but was selected by routing,
    // the previous block's last record is the closest lower RVA.
    if (blockIndex == 0) {
        return false;
    }

    DecodedBlock prevBlock;
    if (!LoadDecodedBlock(blockIndex - 1, &prevBlock, &error)) {
        return false;
    }
    if (prevBlock.lines.empty()) {
        return false;
    }

    *outLine = prevBlock.lines.back();
    return true;
}

bool RvaIndexLookup::EnsureIndex2Open(std::string* error) const {
    if (index2Stream_.is_open()) {
        return true;
    }
    if (index2OpenAttempted_) {
        SetError(error, lastError_);
        return false;
    }

    index2OpenAttempted_ = true;
    index2Stream_.open(index2Path_, std::ios::binary);
    if (!index2Stream_) {
        lastError_ = "Failed to open index2 file: " + index2Path_;
        SetError(error, lastError_);
        return false;
    }

    return true;
}

bool RvaIndexLookup::LoadDecodedBlock(size_t blockIndex, DecodedBlock* outBlock, std::string* error) const {
    if (outBlock == nullptr) {
        SetError(error, "Internal error: outBlock is null");
        return false;
    }
    if (blockIndex >= index1Entries_.size()) {
        SetError(error, "Block index out of range");
        return false;
    }
    if (!EnsureIndex2Open(error)) {
        return false;
    }

    if (cachedBlockIndex_ == blockIndex) {
        *outBlock = cachedBlock_;
        return true;
    }

    const Index1Entry& e = index1Entries_[blockIndex];
    if (e.index2Size < 16) {
        SetError(error, "Corrupt block: size smaller than block header");
        return false;
    }

    std::vector<uint8_t> buf(e.index2Size);
    index2Stream_.clear();
    index2Stream_.seekg(static_cast<std::streamoff>(e.index2Offset), std::ios::beg);
    if (!ReadFully(index2Stream_, buf.data(), buf.size())) {
        SetError(error, "Failed reading index2 block");
        return false;
    }

    const uint64_t startRva = ReadLe64(buf.data());
    uint64_t currentRva = startRva;
    const uint32_t startLine = ReadLe32(buf.data() + 8);
    const uint32_t recordCount = ReadLe32(buf.data() + 12);

    const uint64_t expected = 16ull + static_cast<uint64_t>(recordCount) * 8ull;
    if (expected != e.index2Size) {
        SetError(error, "Corrupt block: record count does not match block size");
        return false;
    }

    DecodedBlock decoded;
    decoded.rvas.reserve(recordCount);
    decoded.lines.reserve(recordCount);

    size_t off = 16;
    for (uint32_t i = 0; i < recordCount; ++i, off += 8) {
        const uint32_t addrDelta = ReadLe32(buf.data() + off);
        const uint32_t absoluteLine = ReadLe32(buf.data() + off + 4);

        if (i == 0) {
            currentRva = startRva + addrDelta;
            // first record line can be written either as startLine or absolute value
            decoded.lines.push_back(absoluteLine == 0 ? startLine : absoluteLine);
        } else {
            currentRva += addrDelta;
            decoded.lines.push_back(absoluteLine);
        }

        decoded.rvas.push_back(currentRva);
    }

    if (!decoded.rvas.empty() && !std::is_sorted(decoded.rvas.begin(), decoded.rvas.end())) {
        SetError(error, "Corrupt block: RVAs are not sorted");
        return false;
    }

    cachedBlockIndex_ = blockIndex;
    cachedBlock_ = decoded;
    *outBlock = decoded;
    return true;
}

uint16_t RvaIndexLookup::ReadLe16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0] | (static_cast<uint16_t>(p[1]) << 8));
}

uint32_t RvaIndexLookup::ReadLe32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t RvaIndexLookup::ReadLe64(const uint8_t* p) {
    return static_cast<uint64_t>(ReadLe32(p)) | (static_cast<uint64_t>(ReadLe32(p + 4)) << 32);
}

bool RvaIndexLookup::ReadFully(std::ifstream& stream, uint8_t* dst, size_t size) {
    stream.read(reinterpret_cast<char*>(dst), static_cast<std::streamsize>(size));
    return !stream.fail() && static_cast<size_t>(stream.gcount()) == size;
}

void RvaIndexLookup::SetError(std::string* error, const std::string& value) {
    if (error != nullptr) {
        *error = value;
    }
}

} // namespace Il2CppDumper
