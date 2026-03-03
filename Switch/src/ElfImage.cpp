#include "SwitchPort/ElfImage.h"

#include <algorithm>
#include <fstream>
#include <limits>
#include <new>
#include <string>

namespace SwitchPort {

namespace {
constexpr uint32_t kPtLoad = 1;
constexpr uint32_t kPtDynamic = 2;
constexpr int64_t kDtNull = 0;
constexpr int64_t kDtHash = 4;
constexpr int64_t kDtStrTab = 5;
constexpr int64_t kDtSymTab = 6;
constexpr int64_t kDtRela = 7;
constexpr int64_t kDtRelaSz = 8;
constexpr int64_t kDtGnuHash = 0x6ffffef5;
constexpr uint16_t kEmX86_64 = 62;
constexpr uint16_t kEmAarch64 = 183;
constexpr uint32_t kR_X86_64_64 = 1;
constexpr uint32_t kR_X86_64_RELATIVE = 8;
constexpr uint32_t kR_AARCH64_ABS64 = 257;
constexpr uint32_t kR_AARCH64_RELATIVE = 1027;
constexpr uint64_t kMaxElfFileBytes = 1024ull * 1024ull * 1024ull; // 1 GiB hard cap for malformed inputs.
constexpr uint32_t kMaxDynamicSymbolCount = 4u * 1024u * 1024u;

uint16_t ReadLe16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) | static_cast<uint16_t>(p[1] << 8);
}

uint32_t ReadLe32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) | (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t ReadLe64(const uint8_t* p) {
    return static_cast<uint64_t>(ReadLe32(p)) | (static_cast<uint64_t>(ReadLe32(p + 4)) << 32);
}

void WriteLe64(uint8_t* p, uint64_t v) {
    p[0] = static_cast<uint8_t>(v & 0xff);
    p[1] = static_cast<uint8_t>((v >> 8) & 0xff);
    p[2] = static_cast<uint8_t>((v >> 16) & 0xff);
    p[3] = static_cast<uint8_t>((v >> 24) & 0xff);
    p[4] = static_cast<uint8_t>((v >> 32) & 0xff);
    p[5] = static_cast<uint8_t>((v >> 40) & 0xff);
    p[6] = static_cast<uint8_t>((v >> 48) & 0xff);
    p[7] = static_cast<uint8_t>((v >> 56) & 0xff);
}

bool AddOverflowU64(uint64_t a, uint64_t b, uint64_t* out) {
    if (a > std::numeric_limits<uint64_t>::max() - b) {
        return true;
    }
    *out = a + b;
    return false;
}

bool ReadFile(const std::string& path, std::vector<uint8_t>* out, std::string* error) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        if (error != nullptr) {
            *error = "Failed to open ELF file: " + path;
        }
        return false;
    }
    in.seekg(0, std::ios::end);
    const std::streamoff size = in.tellg();
    if (size < 0) {
        if (error != nullptr) {
            *error = "Failed to query ELF file size: " + path;
        }
        return false;
    }
    if (static_cast<uint64_t>(size) > kMaxElfFileBytes) {
        if (error != nullptr) {
            *error = "ELF file is too large: " + std::to_string(static_cast<unsigned long long>(size)) + " bytes";
        }
        return false;
    }
    in.seekg(0, std::ios::beg);
    try {
        out->resize(static_cast<size_t>(size));
    } catch (const std::bad_alloc&) {
        if (error != nullptr) {
            *error = "Out of memory while reading ELF file";
        }
        return false;
    }
    if (size == 0) {
        return true;
    }
    in.read(reinterpret_cast<char*>(out->data()), size);
    if (!in.good()) {
        if (error != nullptr) {
            *error = "Failed to read ELF file contents: " + path;
        }
        return false;
    }
    return true;
}

} // namespace

bool ElfImage::Load(const std::string& path, std::string* error) {
    segments_.clear();
    data_.clear();
    is64Bit_ = false;
    isLittleEndian_ = false;

    try {
        if (!ReadFile(path, &data_, error)) {
            return false;
        }
    if (data_.size() < 64) {
        if (error) {
            *error = "ELF file is too small";
        }
        return false;
    }

    if (!(data_[0] == 0x7f && data_[1] == 'E' && data_[2] == 'L' && data_[3] == 'F')) {
        if (error) {
            *error = "Invalid ELF magic";
        }
        return false;
    }

    is64Bit_ = (data_[4] == 2);
    isLittleEndian_ = (data_[5] == 1);
    if (!is64Bit_) {
        if (error) {
            *error = "Only ELF64 is supported currently";
        }
        return false;
    }
    if (!isLittleEndian_) {
        if (error) {
            *error = "Only little-endian ELF is supported currently";
        }
        return false;
    }

    const uint64_t e_phoff = ReadLe64(data_.data() + 32);
    const uint16_t e_machine = ReadLe16(data_.data() + 18);
    const uint16_t e_phentsize = ReadLe16(data_.data() + 54);
    const uint16_t e_phnum = ReadLe16(data_.data() + 56);
    if (e_phentsize < 56) {
        if (error) {
            *error = "Invalid ELF program header entry size";
        }
        return false;
    }

    const uint64_t phBytes = static_cast<uint64_t>(e_phentsize) * e_phnum;
    uint64_t phTableEnd = 0;
    if (AddOverflowU64(e_phoff, phBytes, &phTableEnd) || phTableEnd > data_.size()) {
        if (error) {
            *error = "ELF program header table out of bounds";
        }
        return false;
    }

    uint64_t dynamicOffset = 0;
    uint64_t dynamicSize = 0;
    for (uint16_t i = 0; i < e_phnum; ++i) {
        const uint64_t off = e_phoff + static_cast<uint64_t>(i) * e_phentsize;
        const uint8_t* ph = data_.data() + off;
        const uint32_t p_type = ReadLe32(ph + 0);
        if (p_type == kPtDynamic) {
            dynamicOffset = ReadLe64(ph + 8);
            dynamicSize = ReadLe64(ph + 32);
        }
        if (p_type != kPtLoad) {
            continue;
        }

        Segment seg{};
        seg.fileOffset = ReadLe64(ph + 8);
        seg.vaddr = ReadLe64(ph + 16);
        seg.filesz = ReadLe64(ph + 32);
        seg.memsz = ReadLe64(ph + 40);
        seg.flags = ReadLe32(ph + 4);
        uint64_t segEnd = 0;
        if (AddOverflowU64(seg.fileOffset, seg.filesz, &segEnd) || segEnd > data_.size()) {
            if (error) {
                *error = "ELF PT_LOAD segment out of file bounds";
            }
            return false;
        }
        segments_.push_back(seg);
    }

    if (segments_.empty()) {
        if (error) {
            *error = "No PT_LOAD segments found in ELF";
        }
        return false;
    }

    uint64_t dynamicEnd = 0;
    if (dynamicSize >= 16 && !AddOverflowU64(dynamicOffset, dynamicSize, &dynamicEnd) && dynamicEnd <= data_.size()) {
        uint64_t relaVa = 0;
        uint64_t relaSz = 0;
        for (uint64_t off = dynamicOffset; off + 16 <= dynamicEnd; off += 16) {
            const int64_t tag = static_cast<int64_t>(ReadLe64(data_.data() + off));
            const uint64_t value = ReadLe64(data_.data() + off + 8);
            if (tag == kDtNull) {
                break;
            }
            if (tag == kDtRela) {
                relaVa = value;
            } else if (tag == kDtRelaSz) {
                relaSz = value;
            }
        }

        if (relaVa != 0 && relaSz >= 24) {
            uint64_t symtabVa = 0;
            uint64_t hashVa = 0;
            uint64_t gnuHashVa = 0;
            for (uint64_t off = dynamicOffset; off + 16 <= dynamicEnd; off += 16) {
                const int64_t tag = static_cast<int64_t>(ReadLe64(data_.data() + off));
                const uint64_t value = ReadLe64(data_.data() + off + 8);
                if (tag == kDtNull) {
                    break;
                }
                if (tag == kDtSymTab) {
                    symtabVa = value;
                } else if (tag == kDtHash) {
                    hashVa = value;
                } else if (tag == kDtGnuHash) {
                    gnuHashVa = value;
                }
            }

            std::vector<uint64_t> symbolValues;
            if (symtabVa != 0) {
                uint32_t symbolCount = 0;
                if (hashVa != 0) {
                    uint64_t hashOff = 0;
                    if (TryMapVaddrToOffset(hashVa, &hashOff) && hashOff + 8 <= data_.size()) {
                        symbolCount = ReadLe32(data_.data() + hashOff + 4);
                    }
                } else if (gnuHashVa != 0) {
                    uint64_t hashOff = 0;
                    if (TryMapVaddrToOffset(gnuHashVa, &hashOff) && hashOff + 16 <= data_.size()) {
                        const uint32_t nbuckets = ReadLe32(data_.data() + hashOff);
                        const uint32_t symoffset = ReadLe32(data_.data() + hashOff + 4);
                        const uint32_t bloomSize = ReadLe32(data_.data() + hashOff + 8);
                        const uint64_t bucketsOff = hashOff + 16 + 8ull * bloomSize;
                        if (bucketsOff + 4ull * nbuckets <= data_.size()) {
                            uint32_t lastSymbol = 0;
                            for (uint32_t i = 0; i < nbuckets; ++i) {
                                lastSymbol = std::max(lastSymbol, ReadLe32(data_.data() + bucketsOff + 4ull * i));
                            }
                            if (lastSymbol < symoffset) {
                                symbolCount = symoffset;
                            } else {
                                const uint64_t chainsBase = bucketsOff + 4ull * nbuckets;
                                uint64_t chainOff = chainsBase + 4ull * (lastSymbol - symoffset);
                                while (chainOff + 4 <= data_.size()) {
                                    const uint32_t entry = ReadLe32(data_.data() + chainOff);
                                    ++lastSymbol;
                                    chainOff += 4;
                                    if ((entry & 1u) != 0) {
                                        break;
                                    }
                                }
                                symbolCount = lastSymbol;
                            }
                        }
                    }
                }
                if (symbolCount > 0) {
                    if (symbolCount > kMaxDynamicSymbolCount) {
                        if (error != nullptr) {
                            *error = "ELF dynamic symbol count is unreasonable: " +
                                     std::to_string(static_cast<unsigned long long>(symbolCount));
                        }
                        return false;
                    }
                    uint64_t symtabOff = 0;
                    if (TryMapVaddrToOffset(symtabVa, &symtabOff)) {
                        constexpr uint64_t kSymEntSize = 24;
                        uint64_t symBytes = 0;
                        uint64_t symEnd = 0;
                        if (!AddOverflowU64(0, kSymEntSize * static_cast<uint64_t>(symbolCount), &symBytes) &&
                            !AddOverflowU64(symtabOff, symBytes, &symEnd) && symEnd <= data_.size()) {
                            symbolValues.resize(symbolCount);
                            for (uint32_t i = 0; i < symbolCount; ++i) {
                                const uint64_t symOff = symtabOff + kSymEntSize * i;
                                symbolValues[i] = ReadLe64(data_.data() + symOff + 8);
                            }
                        }
                    }
                }
            }

            uint64_t relaOff = 0;
            uint64_t relaEnd = 0;
            if (TryMapVaddrToOffset(relaVa, &relaOff) && !AddOverflowU64(relaOff, relaSz, &relaEnd) &&
                relaEnd <= data_.size()) {
                for (uint64_t off = relaOff; off + 24 <= relaEnd; off += 24) {
                    const uint64_t r_offset = ReadLe64(data_.data() + off);
                    const uint64_t r_info = ReadLe64(data_.data() + off + 8);
                    const uint64_t r_addend = ReadLe64(data_.data() + off + 16);
                    const uint32_t type = static_cast<uint32_t>(r_info & 0xffffffffu);
                    const uint32_t sym = static_cast<uint32_t>(r_info >> 32);

                    uint64_t value = 0;
                    bool recognized = false;
                    if (e_machine == kEmAarch64 && type == kR_AARCH64_RELATIVE) {
                        value = r_addend;
                        recognized = true;
                    } else if (e_machine == kEmX86_64 && type == kR_X86_64_RELATIVE) {
                        value = r_addend;
                        recognized = true;
                    } else if (e_machine == kEmAarch64 && type == kR_AARCH64_ABS64) {
                        if (sym < symbolValues.size()) {
                            value = symbolValues[sym] + r_addend;
                            recognized = true;
                        }
                    } else if (e_machine == kEmX86_64 && type == kR_X86_64_64) {
                        if (sym < symbolValues.size()) {
                            value = symbolValues[sym] + r_addend;
                            recognized = true;
                        }
                    }
                    if (!recognized) {
                        continue;
                    }

                    uint64_t writeOff = 0;
                    if (!TryMapVaddrToOffset(r_offset, &writeOff) || writeOff + 8 > data_.size()) {
                        continue;
                    }
                    WriteLe64(data_.data() + writeOff, value);
                }
            }
        }
    }

    return true;
    } catch (const std::bad_alloc&) {
        if (error != nullptr) {
            *error = "Out of memory while parsing ELF (possibly malformed)";
        }
        return false;
    }
}

bool ElfImage::TryMapVaddrToOffset(uint64_t vaddr, uint64_t* outOffset) const {
    for (const auto& seg : segments_) {
        if (vaddr < seg.vaddr || vaddr >= seg.vaddr + seg.memsz) {
            continue;
        }
        const uint64_t delta = vaddr - seg.vaddr;
        if (delta >= seg.filesz) {
            return false;
        }
        *outOffset = seg.fileOffset + delta;
        return true;
    }
    return false;
}

bool ElfImage::TryMapOffsetToVaddr(uint64_t offset, uint64_t* outVaddr) const {
    for (const auto& seg : segments_) {
        if (offset < seg.fileOffset || offset >= seg.fileOffset + seg.filesz) {
            continue;
        }
        *outVaddr = seg.vaddr + (offset - seg.fileOffset);
        return true;
    }
    return false;
}

bool ElfImage::ReadBytesAtVaddr(uint64_t vaddr, size_t size, std::vector<uint8_t>* out) const {
    uint64_t fileOffset = 0;
    if (!TryMapVaddrToOffset(vaddr, &fileOffset)) {
        return false;
    }
    if (fileOffset + size > data_.size()) {
        return false;
    }
    out->assign(data_.begin() + static_cast<ptrdiff_t>(fileOffset),
                data_.begin() + static_cast<ptrdiff_t>(fileOffset + size));
    return true;
}

bool ElfImage::ReadBytesAtOffset(uint64_t offset, size_t size, std::vector<uint8_t>* out) const {
    if (offset + size > data_.size()) {
        return false;
    }
    out->assign(data_.begin() + static_cast<ptrdiff_t>(offset), data_.begin() + static_cast<ptrdiff_t>(offset + size));
    return true;
}

bool ElfImage::ReadU8AtVaddr(uint64_t vaddr, uint8_t* out) const {
    std::vector<uint8_t> tmp;
    if (!ReadBytesAtVaddr(vaddr, 1, &tmp)) {
        return false;
    }
    *out = tmp[0];
    return true;
}

bool ElfImage::ReadI32AtVaddr(uint64_t vaddr, int32_t* out) const {
    std::vector<uint8_t> tmp;
    if (!ReadBytesAtVaddr(vaddr, 4, &tmp)) {
        return false;
    }
    *out = static_cast<int32_t>(ReadLe32(tmp.data()));
    return true;
}

bool ElfImage::ReadU64AtOffset(uint64_t offset, uint64_t* out) const {
    std::vector<uint8_t> tmp;
    if (!ReadBytesAtOffset(offset, 8, &tmp)) {
        return false;
    }
    *out = ReadLe64(tmp.data());
    return true;
}

bool ElfImage::FindDynamicSymbolVaddr(const std::string& symbolName, uint64_t* outVaddr) const {
    if (!is64Bit_ || !isLittleEndian_ || data_.size() < 64) {
        return false;
    }
    const uint64_t e_phoff = ReadLe64(data_.data() + 32);
    const uint16_t e_phentsize = ReadLe16(data_.data() + 54);
    const uint16_t e_phnum = ReadLe16(data_.data() + 56);
    if (e_phoff + static_cast<uint64_t>(e_phentsize) * e_phnum > data_.size()) {
        return false;
    }

    uint64_t dynamicOffset = 0;
    uint64_t dynamicSize = 0;
    for (uint16_t i = 0; i < e_phnum; ++i) {
        const uint64_t off = e_phoff + static_cast<uint64_t>(i) * e_phentsize;
        const uint8_t* ph = data_.data() + off;
        const uint32_t p_type = ReadLe32(ph + 0);
        if (p_type == kPtDynamic) {
            dynamicOffset = ReadLe64(ph + 8);
            dynamicSize = ReadLe64(ph + 32);
            break;
        }
    }
    if (dynamicSize < 16 || dynamicOffset + dynamicSize > data_.size()) {
        return false;
    }

    uint64_t strtabVa = 0;
    uint64_t symtabVa = 0;
    uint64_t hashVa = 0;
    uint64_t gnuHashVa = 0;
    for (uint64_t off = dynamicOffset; off + 16 <= dynamicOffset + dynamicSize; off += 16) {
        const int64_t tag = static_cast<int64_t>(ReadLe64(data_.data() + off));
        const uint64_t value = ReadLe64(data_.data() + off + 8);
        if (tag == kDtNull) {
            break;
        }
        if (tag == kDtStrTab) {
            strtabVa = value;
        } else if (tag == kDtSymTab) {
            symtabVa = value;
        } else if (tag == kDtHash) {
            hashVa = value;
        } else if (tag == kDtGnuHash) {
            gnuHashVa = value;
        }
    }
    if (strtabVa == 0 || symtabVa == 0) {
        return false;
    }

    uint64_t strtabOff = 0;
    uint64_t symtabOff = 0;
    if (!TryMapVaddrToOffset(strtabVa, &strtabOff) || !TryMapVaddrToOffset(symtabVa, &symtabOff)) {
        return false;
    }

    uint32_t symbolCount = 0;
    if (hashVa != 0) {
        uint64_t hashOff = 0;
        if (!TryMapVaddrToOffset(hashVa, &hashOff) || hashOff + 8 > data_.size()) {
            return false;
        }
        const uint32_t nchain = ReadLe32(data_.data() + hashOff + 4);
        symbolCount = nchain;
    } else if (gnuHashVa != 0) {
        uint64_t hashOff = 0;
        if (!TryMapVaddrToOffset(gnuHashVa, &hashOff) || hashOff + 16 > data_.size()) {
            return false;
        }
        const uint32_t nbuckets = ReadLe32(data_.data() + hashOff);
        const uint32_t symoffset = ReadLe32(data_.data() + hashOff + 4);
        const uint32_t bloomSize = ReadLe32(data_.data() + hashOff + 8);
        const uint64_t bucketsOff = hashOff + 16 + 8ull * bloomSize;
        if (bucketsOff + 4ull * nbuckets > data_.size()) {
            return false;
        }
        uint32_t lastSymbol = 0;
        for (uint32_t i = 0; i < nbuckets; ++i) {
            lastSymbol = std::max(lastSymbol, ReadLe32(data_.data() + bucketsOff + 4ull * i));
        }
        if (lastSymbol < symoffset) {
            symbolCount = symoffset;
        } else {
            const uint64_t chainsBase = bucketsOff + 4ull * nbuckets;
            uint64_t chainOff = chainsBase + 4ull * (lastSymbol - symoffset);
            if (chainOff + 4 > data_.size()) {
                return false;
            }
            while (chainOff + 4 <= data_.size()) {
                const uint32_t entry = ReadLe32(data_.data() + chainOff);
                ++lastSymbol;
                chainOff += 4;
                if ((entry & 1u) != 0) {
                    break;
                }
            }
            symbolCount = lastSymbol;
        }
    } else {
        return false;
    }

    constexpr uint64_t symEntSize = 24;
    if (symtabOff + symEntSize * symbolCount > data_.size()) {
        return false;
    }

    for (uint32_t i = 0; i < symbolCount; ++i) {
        const uint64_t symOff = symtabOff + symEntSize * i;
        const uint32_t st_name = ReadLe32(data_.data() + symOff + 0);
        const uint64_t st_value = ReadLe64(data_.data() + symOff + 8);
        if (st_name == 0) {
            continue;
        }
        const uint64_t nameOff = strtabOff + st_name;
        if (nameOff >= data_.size()) {
            continue;
        }
        std::string name;
        for (uint64_t p = nameOff; p < data_.size() && data_[p] != 0; ++p) {
            name.push_back(static_cast<char>(data_[p]));
        }
        if (name == symbolName) {
            *outVaddr = st_value;
            return true;
        }
    }
    return false;
}

bool ElfImage::ReadU32AtVaddr(uint64_t vaddr, uint32_t* out) const {
    std::vector<uint8_t> tmp;
    if (!ReadBytesAtVaddr(vaddr, 4, &tmp)) {
        return false;
    }
    *out = ReadLe32(tmp.data());
    return true;
}

bool ElfImage::ReadU64AtVaddr(uint64_t vaddr, uint64_t* out) const {
    std::vector<uint8_t> tmp;
    if (!ReadBytesAtVaddr(vaddr, 8, &tmp)) {
        return false;
    }
    *out = ReadLe64(tmp.data());
    return true;
}

bool ElfImage::ReadCStringAtVaddr(uint64_t vaddr, std::string* out) const {
    out->clear();
    for (size_t i = 0; i < 4096; ++i) {
        uint8_t c = 0;
        if (!ReadU8AtVaddr(vaddr + static_cast<uint64_t>(i), &c)) {
            return false;
        }
        if (c == 0) {
            return true;
        }
        out->push_back(static_cast<char>(c));
    }
    return false;
}

} // namespace SwitchPort
