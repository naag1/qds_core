#pragma once
#include <cstdint>
#include <iostream>
#include <string>

namespace qds {
inline void write_frame(const std::string& payload) {
    const auto size = static_cast<std::uint32_t>(payload.size());
    std::cout.write(reinterpret_cast<const char*>(&size), sizeof(size));
    std::cout.write(payload.data(), static_cast<std::streamsize>(payload.size()));
    std::cout.flush();
}
}
