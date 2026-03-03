#pragma once

#include <string>

namespace SwitchPort {

// Converts NSO/NRO-style Nintendo Switch main binaries into a minimal ELF64
// containing PT_LOAD + PT_DYNAMIC program headers.
bool ConvertNsoLikeToElf(const std::string& inputPath, const std::string& outputElfPath, std::string* error);

} // namespace SwitchPort
