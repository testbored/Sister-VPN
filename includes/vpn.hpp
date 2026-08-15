#pragma once

#include "crypto.hpp"
#include "session.hpp"
#include "tun.hpp"
#include "udp.hpp"

#include <cstdint>
#include <string>

enum class Role { Initiator, Responder };

struct VPNConfig {
    std::string tunName;
    std::uint16_t localPort;
    std::string peerAddress;
    std::uint16_t peerPort;
    crypto::Key preSharedKey;
    Role role;
    std::uint32_t mtu{1400};
};

class VPN {
public:
    explicit VPN(const VPNConfig& config);
    void run();
    const std::string& tunName() const;
private:
    void forwardTunToUdp();
    void forwardUdpToTun();
    VPNConfig config_;
    UDP socket_;
    TUN tunnel_;
    crypto::Key transmitKey_;
    crypto::Key receiveKey_;
    std::uint32_t sessionId_;
    std::uint64_t nextSequence_{0};
    ReplayWindow replayWindow_;
};
