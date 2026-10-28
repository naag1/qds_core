#include "pcap_reader.hpp"
#include <array>
#include <cstring>
#include <intrin.h>
namespace qds {
static std::uint32_t swap32(std::uint32_t v) { return _byteswap_ulong(v); }
PcapReader::PcapReader(const std::string& path) : input_(path, std::ios::binary) {
    std::array<std::uint32_t, 6> h{}; input_.read(reinterpret_cast<char*>(h.data()), 24);
    if (!input_) { error_ = "cannot read pcap header"; return; }
    const auto magic = h[0];
    if (magic == 0xa1b2c3d4 || magic == 0xa1b23c4d) { nano_ = magic == 0xa1b23c4d; }
    else if (magic == 0xd4c3b2a1 || magic == 0x4d3cb2a1) { swap_ = true; nano_ = magic == 0x4d3cb2a1; }
    else { error_ = "pcapng or unsupported pcap format"; return; }
    valid_ = true;
}
bool PcapReader::next_batch(CaptureBatch& b, std::size_t max_packets, std::size_t max_bytes) {
    b = {}; std::array<std::uint32_t, 4> h{};
    while (b.packets.size() < max_packets && b.bytes < max_bytes && input_.read(reinterpret_cast<char*>(h.data()), 16)) {
        if (swap_) for (auto& x : h) x = swap32(x);
        if (!h[2] || h[2] > max_bytes) { input_.seekg(h[2], std::ios::cur); continue; }
        std::vector<std::uint8_t> data(h[2]); input_.read(reinterpret_cast<char*>(data.data()), h[2]); if (!input_) break;
        const auto offset = static_cast<std::uint32_t>(b.words.size() * 4);
        const auto old_words = b.words.size();
        b.words.resize(old_words + (data.size() + 3) / 4, 0);
        std::memcpy(reinterpret_cast<std::uint8_t*>(b.words.data()) + offset, data.data(), data.size());
        b.packets.push_back({offset, h[2], h[0], h[1]}); b.bytes += h[2];
    }
    return !b.packets.empty();
}
}
