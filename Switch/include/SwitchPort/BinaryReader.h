#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace SwitchPort {

class BinaryReader {
public:
    explicit BinaryReader(const std::vector<uint8_t>& data, size_t pos = 0) : data_(data), pos_(pos) {}

    void Seek(size_t pos) {
        if (pos > data_.size()) {
            throw std::out_of_range("Seek out of range");
        }
        pos_ = pos;
    }

    size_t Position() const { return pos_; }

    uint8_t ReadU8() {
        EnsureAvailable(1);
        return data_[pos_++];
    }

    int32_t ReadIndexValue(int byteWidth) {
        switch (byteWidth) {
        case 1: {
            uint8_t v = ReadU8();
            return (v == 0xFF) ? -1 : static_cast<int32_t>(v);
        }
        case 2: {
            uint16_t v = ReadU16();
            return (v == 0xFFFF) ? -1 : static_cast<int32_t>(v);
        }
        case 4:
        default:
            return ReadI32();
        }
    }

    uint16_t ReadU16() {
        EnsureAvailable(2);
        const uint16_t value = static_cast<uint16_t>(data_[pos_]) |
                               static_cast<uint16_t>(data_[pos_ + 1] << 8);
        pos_ += 2;
        return value;
    }

    uint32_t ReadU32() {
        EnsureAvailable(4);
        const uint32_t value = static_cast<uint32_t>(data_[pos_]) |
                               (static_cast<uint32_t>(data_[pos_ + 1]) << 8) |
                               (static_cast<uint32_t>(data_[pos_ + 2]) << 16) |
                               (static_cast<uint32_t>(data_[pos_ + 3]) << 24);
        pos_ += 4;
        return value;
    }

    int32_t ReadI32() {
        return static_cast<int32_t>(ReadU32());
    }

    std::string ReadCStringAt(size_t absOffset) const {
        if (absOffset >= data_.size()) {
            throw std::out_of_range("String offset out of range");
        }
        std::string out;
        size_t cursor = absOffset;
        while (cursor < data_.size() && data_[cursor] != 0) {
            out.push_back(static_cast<char>(data_[cursor]));
            ++cursor;
        }
        return out;
    }

private:
    void EnsureAvailable(size_t n) const {
        if (pos_ + n > data_.size()) {
            throw std::out_of_range("Read past end of buffer");
        }
    }

    const std::vector<uint8_t>& data_;
    size_t pos_;
};

} // namespace SwitchPort
