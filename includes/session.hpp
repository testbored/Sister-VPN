#pragma once

#include "crypto.hpp"

#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <stdexcept>

constexpr std::uint32_t VPN_PACKET_MAGIC = 0x5356504e;
constexpr std::uint8_t VPN_PACKET_VERSION = 1;

#pragma pack(push, 1)
struct PacketHeader {
    std::uint32_t magic;
    std::uint8_t version;
    std::uint8_t flags;
    std::uint16_t reserved;
    std::uint32_t sessionId;
    std::uint64_t sequence;
};
#pragma pack(pop)
static_assert(sizeof(PacketHeader) == 20, "unexpected tunnel header size");

inline std::uint64_t hostToBigEndian64(std::uint64_t value) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap64(value);
#else
    return value;
#endif
}

inline std::uint64_t bigEndianToHost64(std::uint64_t value) {
    return hostToBigEndian64(value);
}

inline crypto::Nonce nonceFromHeader(const PacketHeader& header) {
    crypto::Nonce nonce{};
    std::memcpy(nonce.data(), &header.sessionId, sizeof(header.sessionId));
    std::memcpy(nonce.data() + sizeof(header.sessionId), &header.sequence,
                sizeof(header.sequence));
    return nonce;
}


inline void validateHeader(const PacketHeader& header) {
    if (ntohl(header.magic) != VPN_PACKET_MAGIC || header.version != VPN_PACKET_VERSION ||
        header.flags != 0 || header.reserved != 0) {
        throw std::runtime_error("invalid VPN packet header");
    }
}

class ReplayWindow {
public:
    bool accept(std::uint32_t sessionId, std::uint64_t sequence) {
        if (!initialized_ || sessionId != sessionId_) {
            initialized_ = true;
            sessionId_ = sessionId;
            highest_ = sequence;
            bitmap_ = 1;
            return true;
        }
        if (sequence > highest_) {
            const auto shift = sequence - highest_;
            bitmap_ = shift >= 64 ? 1 : (bitmap_ << shift) | 1;
            highest_ = sequence;
            return true;
        }
        const auto distance = highest_ - sequence;
        if (distance >= 64 || ((bitmap_ >> distance) & 1U) != 0) return false;
        bitmap_ |= (std::uint64_t{1} << distance);
        return true;
    }

private:
    bool initialized_{false};
    std::uint32_t sessionId_{0};
    std::uint64_t highest_{0};
    std::uint64_t bitmap_{0};
};
