#pragma once
#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

namespace qds {
struct PacketDesc { std::uint32_t byte_offset, captured_length, ts_seconds, ts_fraction; };
struct CaptureBatch { std::vector<std::uint32_t> words; std::vector<PacketDesc> packets; std::uint64_t bytes = 0; };
class PcapReader {
public:
    explicit PcapReader(const std::string& path);
    bool next_batch(CaptureBatch& batch, std::size_t max_packets, std::size_t max_bytes);
    bool valid() const { return valid_; }
    const std::string& error() const { return error_; }
private:
    std::ifstream input_; bool valid_ = false; bool swap_ = false; bool nano_ = false; std::string error_;
};
}
