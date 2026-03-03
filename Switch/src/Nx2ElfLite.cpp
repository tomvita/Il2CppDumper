#include "SwitchPort/Nx2ElfLite.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include "lz4.h"

namespace SwitchPort {
namespace {

constexpr uint32_t kPtLoad = 1;
constexpr uint32_t kPtDynamic = 2;
constexpr uint32_t kPfX = 1;
constexpr uint32_t kPfW = 2;
constexpr uint32_t kPfR = 4;
constexpr uint16_t kEmAarch64 = 183;
constexpr uint32_t kEvCurrent = 1;
constexpr uint32_t kNsoMagic = 0x304f534e; // NSO0
constexpr uint32_t kNroMagic = 0x304f524e; // NRO0
constexpr uint32_t kModMagic = 0x30444f4d; // MOD0
constexpr uint64_t kDtNull = 0;

constexpr size_t AlignUp(size_t value, size_t align) {
    return (value + align - 1) & ~(align - 1);
}

uint32_t ReadLe32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) | (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t ReadLe64(const uint8_t* p) {
    return static_cast<uint64_t>(ReadLe32(p)) | (static_cast<uint64_t>(ReadLe32(p + 4)) << 32);
}

void WriteLe16(uint8_t* p, uint16_t v) {
    p[0] = static_cast<uint8_t>(v & 0xff);
    p[1] = static_cast<uint8_t>((v >> 8) & 0xff);
}

void WriteLe32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v & 0xff);
    p[1] = static_cast<uint8_t>((v >> 8) & 0xff);
    p[2] = static_cast<uint8_t>((v >> 16) & 0xff);
    p[3] = static_cast<uint8_t>((v >> 24) & 0xff);
}

void WriteLe64(uint8_t* p, uint64_t v) {
    WriteLe32(p, static_cast<uint32_t>(v & 0xffffffffu));
    WriteLe32(p + 4, static_cast<uint32_t>((v >> 32) & 0xffffffffu));
}

bool ReadFile(const std::string& path, std::vector<uint8_t>* out) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return false;
    }
    in.seekg(0, std::ios::end);
    const std::streamoff size = in.tellg();
    if (size < 0) {
        return false;
    }
    in.seekg(0, std::ios::beg);
    out->resize(static_cast<size_t>(size));
    if (size == 0) {
        return true;
    }
    in.read(reinterpret_cast<char*>(out->data()), size);
    return in.good();
}

bool WriteFile(const std::string& path, const std::vector<uint8_t>& bytes) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        return false;
    }
    if (!bytes.empty()) {
        out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    }
    return static_cast<bool>(out);
}

struct SegmentInfo {
    uint32_t fileOffset = 0;
    uint32_t memOffset = 0;
    uint32_t memSize = 0;
    uint32_t bssAlign = 0;
};

struct ModHeader {
    uint32_t magic;
    int32_t dynamicOffset;
    int32_t bssStartOffset;
    int32_t bssEndOffset;
    int32_t ehStartOffset;
    int32_t ehEndOffset;
    int32_t moduleObjectOffset;
};

bool ComputeDynamicSize(const std::vector<uint8_t>& image, uint32_t dynamicVaddr, uint64_t* dynamicSize) {
    if (dynamicVaddr + 16 > image.size()) {
        return false;
    }
    uint64_t size = 0;
    for (size_t off = dynamicVaddr; off + 16 <= image.size(); off += 16) {
        const uint64_t tag = ReadLe64(image.data() + off);
        size += 16;
        if (tag == kDtNull) {
            *dynamicSize = size;
            return true;
        }
        if (size > (1u << 20)) {
            return false;
        }
    }
    return false;
}

bool BuildMinimalElf(const std::vector<uint8_t>& image, const std::array<SegmentInfo, 3>& segs, uint32_t dynamicVaddr,
                     std::vector<uint8_t>* outElf, std::string* error) {
    uint64_t dynamicSize = 0;
    if (!ComputeDynamicSize(image, dynamicVaddr, &dynamicSize)) {
        if (error) {
            *error = "Failed to parse .dynamic table from MOD header";
        }
        return false;
    }

    constexpr size_t kEhdrSize = 64;
    constexpr size_t kPhdrSize = 56;
    constexpr size_t kPhnum = 4;
    size_t cursor = kEhdrSize + kPhdrSize * kPhnum;

    struct SegMap {
        uint32_t vaddr = 0;
        uint32_t memSize = 0;
        size_t fileOffset = 0;
    } maps[3]{};

    for (size_t i = 0; i < 3; ++i) {
        cursor = AlignUp(cursor, 0x1000);
        maps[i].vaddr = segs[i].memOffset;
        maps[i].memSize = segs[i].memSize;
        maps[i].fileOffset = cursor;
        cursor += segs[i].memSize;
    }

    size_t dynamicFileOffset = 0;
    bool dynamicMapped = false;
    for (size_t i = 0; i < 3; ++i) {
        const uint64_t segStart = maps[i].vaddr;
        const uint64_t segEnd = segStart + maps[i].memSize;
        if (dynamicVaddr >= segStart && dynamicVaddr < segEnd) {
            dynamicFileOffset = maps[i].fileOffset + (dynamicVaddr - segStart);
            dynamicMapped = true;
            break;
        }
    }
    if (!dynamicMapped) {
        if (error) {
            *error = "Failed to map .dynamic virtual address into PT_LOAD range";
        }
        return false;
    }

    outElf->assign(cursor, 0);
    uint8_t* elf = outElf->data();

    elf[0] = 0x7f;
    elf[1] = 'E';
    elf[2] = 'L';
    elf[3] = 'F';
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    WriteLe16(elf + 16, 3); // ET_DYN
    WriteLe16(elf + 18, kEmAarch64);
    WriteLe32(elf + 20, kEvCurrent);
    WriteLe64(elf + 24, segs[0].memOffset);
    WriteLe64(elf + 32, kEhdrSize);
    WriteLe64(elf + 40, 0);
    WriteLe32(elf + 48, 0);
    WriteLe16(elf + 52, kEhdrSize);
    WriteLe16(elf + 54, kPhdrSize);
    WriteLe16(elf + 56, kPhnum);
    WriteLe16(elf + 58, 0);
    WriteLe16(elf + 60, 0);
    WriteLe16(elf + 62, 0);

    auto writePhdr = [&](size_t index, uint32_t type, uint32_t flags, uint64_t offset, uint64_t vaddr, uint64_t filesz,
                         uint64_t memsz, uint64_t align) {
        uint8_t* ph = elf + kEhdrSize + index * kPhdrSize;
        WriteLe32(ph + 0, type);
        WriteLe32(ph + 4, flags);
        WriteLe64(ph + 8, offset);
        WriteLe64(ph + 16, vaddr);
        WriteLe64(ph + 24, vaddr);
        WriteLe64(ph + 32, filesz);
        WriteLe64(ph + 40, memsz);
        WriteLe64(ph + 48, align);
    };

    writePhdr(0, kPtLoad, kPfR | kPfX, maps[0].fileOffset, segs[0].memOffset, segs[0].memSize, segs[0].memSize,
              std::max<uint32_t>(segs[0].bssAlign, 1));
    writePhdr(1, kPtLoad, kPfR, maps[1].fileOffset, segs[1].memOffset, segs[1].memSize, segs[1].memSize,
              std::max<uint32_t>(segs[1].bssAlign, 1));
    writePhdr(2, kPtLoad, kPfR | kPfW, maps[2].fileOffset, segs[2].memOffset, segs[2].memSize,
              static_cast<uint64_t>(segs[2].memSize) + segs[2].bssAlign, 1);
    writePhdr(3, kPtDynamic, kPfR | kPfW, dynamicFileOffset, dynamicVaddr, dynamicSize, dynamicSize, 8);

    for (size_t i = 0; i < 3; ++i) {
        const uint64_t srcOff = segs[i].memOffset;
        const uint64_t srcEnd = srcOff + segs[i].memSize;
        if (srcEnd > image.size()) {
            if (error) {
                *error = "Segment out of decompressed image bounds";
            }
            return false;
        }
        std::memcpy(elf + maps[i].fileOffset, image.data() + srcOff, segs[i].memSize);
    }

    return true;
}

} // namespace

bool ConvertNsoLikeToElf(const std::string& inputPath, const std::string& outputElfPath, std::string* error) {
    std::vector<uint8_t> file;
    if (!ReadFile(inputPath, &file)) {
        if (error) {
            *error = "Failed to read input file";
        }
        return false;
    }

    if (file.size() < 0x20) {
        if (error) {
            *error = "Input file too small";
        }
        return false;
    }

    std::array<SegmentInfo, 3> segs{};
    std::vector<uint8_t> image;
    bool recognized = false;

    if (file.size() >= 0x100 && ReadLe32(file.data()) == kNsoMagic) {
        const uint32_t segFileOffBase = 0x10;
        const uint32_t segMemOffBase = 0x14;
        const uint32_t segMemSizeBase = 0x18;
        const uint32_t segBssAlignBase = 0x1c;
        const uint32_t segFileSizeBase = 0x60;

        for (size_t i = 0; i < 3; ++i) {
            segs[i].fileOffset = ReadLe32(file.data() + segFileOffBase + i * 0x10);
            segs[i].memOffset = ReadLe32(file.data() + segMemOffBase + i * 0x10);
            segs[i].memSize = ReadLe32(file.data() + segMemSizeBase + i * 0x10);
            segs[i].bssAlign = ReadLe32(file.data() + segBssAlignBase + i * 0x10);
        }

        const uint32_t dataEnd = segs[2].memOffset + segs[2].memSize + segs[2].bssAlign;
        image.assign(dataEnd, 0);

        for (size_t i = 0; i < 3; ++i) {
            const uint32_t compSize = ReadLe32(file.data() + segFileSizeBase + i * 4);
            if (segs[i].fileOffset + compSize > file.size() || segs[i].memOffset + segs[i].memSize > image.size()) {
                if (error) {
                    *error = "NSO segment bounds are invalid";
                }
                return false;
            }
            if (compSize == segs[i].memSize) {
                std::memcpy(image.data() + segs[i].memOffset, file.data() + segs[i].fileOffset, segs[i].memSize);
            } else {
                const int outLen = LZ4_decompress_safe(reinterpret_cast<const char*>(file.data() + segs[i].fileOffset),
                                                       reinterpret_cast<char*>(image.data() + segs[i].memOffset), compSize,
                                                       segs[i].memSize);
                if (outLen != static_cast<int>(segs[i].memSize)) {
                    if (error) {
                        *error = "NSO LZ4 decompression failed";
                    }
                    return false;
                }
            }
        }
        recognized = true;
    } else {
        constexpr uint32_t kNroOffset = 0x10;
        if (file.size() >= kNroOffset + 0x80 && ReadLe32(file.data() + kNroOffset) == kNroMagic) {
            const uint32_t fileSize = ReadLe32(file.data() + kNroOffset + 8);
            if (fileSize != file.size()) {
                if (error) {
                    *error = "Invalid NRO file size";
                }
                return false;
            }
            for (size_t i = 0; i < 3; ++i) {
                segs[i].fileOffset = ReadLe32(file.data() + kNroOffset + 0x10 + i * 8);
                segs[i].memOffset = segs[i].fileOffset;
                segs[i].memSize = ReadLe32(file.data() + kNroOffset + 0x14 + i * 8);
                segs[i].bssAlign = (i == 0) ? 0x100u : (i == 1 ? 1u : ReadLe32(file.data() + kNroOffset + 0x28));
            }
            image = file;
            recognized = true;
        }
    }

    if (!recognized) {
        if (error) {
            *error = "Unsupported input format (expected NSO/NRO)";
        }
        return false;
    }

    if (image.size() < 8) {
        if (error) {
            *error = "Image too small for MOD pointer";
        }
        return false;
    }

    const uint32_t modMagicOffset = ReadLe32(image.data() + 4);
    if (modMagicOffset + sizeof(ModHeader) > image.size()) {
        if (error) {
            *error = "MOD header out of range";
        }
        return false;
    }

    const ModHeader* mod = reinterpret_cast<const ModHeader*>(image.data() + modMagicOffset);
    if (mod->magic != kModMagic) {
        if (error) {
            *error = "MOD0 header not found in image";
        }
        return false;
    }

    const int64_t dynamicRelative = mod->dynamicOffset;
    const int64_t dynamicVaddr64 = static_cast<int64_t>(modMagicOffset) + dynamicRelative;
    if (dynamicVaddr64 < 0 || static_cast<size_t>(dynamicVaddr64 + 16) > image.size()) {
        if (error) {
            *error = "Invalid MOD dynamic offset";
        }
        return false;
    }
    const uint32_t dynamicVaddr = static_cast<uint32_t>(dynamicVaddr64);

    std::vector<uint8_t> elf;
    if (!BuildMinimalElf(image, segs, dynamicVaddr, &elf, error)) {
        return false;
    }

    if (!WriteFile(outputElfPath, elf)) {
        if (error) {
            *error = "Failed to write converted ELF";
        }
        return false;
    }
    return true;
}

} // namespace SwitchPort
