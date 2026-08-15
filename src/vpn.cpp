#include "vpn.hpp"

#include <arpa/inet.h>
#include <poll.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <vector>

VPN::VPN(const VPNConfig& config)
    : config_(config),
      socket_(config.localPort, config.peerAddress, config.peerPort),
      tunnel_(config.tunName),
      transmitKey_(crypto::deriveDirectionalKey(
          config.preSharedKey, config.role == Role::Initiator
              ? "sister-vpn/v1/init-to-resp" : "sister-vpn/v1/resp-to-init")),
      receiveKey_(crypto::deriveDirectionalKey(
          config.preSharedKey, config.role == Role::Initiator
              ? "sister-vpn/v1/resp-to-init" : "sister-vpn/v1/init-to-resp")),
      sessionId_(crypto::randomSessionId()) {
    if (config.mtu < 576 || config.mtu > 65507) {
        throw std::invalid_argument("MTU must be 576..65507");
    }
}

const std::string& VPN::tunName() const { return tunnel_.name(); }

void VPN::run() {
    std::cerr << "VPN running: TUN " << tunnel_.name() << ", UDP " << config_.localPort
              << " -> " << config_.peerAddress << ':' << config_.peerPort << '\n';
    std::array<pollfd, 2> descriptors{{
        {tunnel_.getFd(), POLLIN, 0},
        {socket_.getFd(), POLLIN, 0},
    }};
    while (true) {
        const int result = poll(descriptors.data(), descriptors.size(), -1);
        if (result < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error("poll failed");
        }
        if (descriptors[0].revents & POLLIN) forwardTunToUdp();
        if (descriptors[1].revents & POLLIN) forwardUdpToTun();
        if ((descriptors[0].revents | descriptors[1].revents) & (POLLERR | POLLHUP | POLLNVAL)) {
            throw std::runtime_error("descriptor error");
        }
    }
}

void VPN::forwardTunToUdp() {
    std::vector<std::uint8_t> packet(config_.mtu);
    const auto plainLength = tunnel_.readPacket(
        packet.data() + sizeof(PacketHeader), config_.mtu - sizeof(PacketHeader) - crypto::TAG_BYTES);
    PacketHeader header{htonl(VPN_PACKET_MAGIC), VPN_PACKET_VERSION, 0, 0,
                        htonl(sessionId_), hostToBigEndian64(nextSequence_++)};
    std::memcpy(packet.data(), &header, sizeof(header));
    const auto encryptedLength = crypto::encrypt(
        transmitKey_, nonceFromHeader(header), packet.data(), sizeof(header),
        packet.data() + sizeof(header), plainLength, packet.data() + sizeof(header),
        packet.size() - sizeof(header));
    socket_.send(packet.data(), sizeof(header) + encryptedLength);
}

void VPN::forwardUdpToTun() {
    std::vector<std::uint8_t> packet(config_.mtu);
    const auto received = socket_.receive(packet.data(), packet.size());
    if (received < sizeof(PacketHeader) + crypto::TAG_BYTES) return;

    PacketHeader header{};
    std::memcpy(&header, packet.data(), sizeof(header));
    try {
        validateHeader(header);
        const auto plainLength = crypto::decrypt(
            receiveKey_, nonceFromHeader(header), packet.data(), sizeof(header),
            packet.data() + sizeof(header), received - sizeof(header),
            packet.data() + sizeof(header), packet.size() - sizeof(header));
        if (replayWindow_.accept(ntohl(header.sessionId), bigEndianToHost64(header.sequence))) {
            tunnel_.writePacket(packet.data() + sizeof(header), plainLength);
        }
    } catch (const std::exception& error) {
        std::cerr << "Dropped UDP packet: " << error.what() << '\n';
    }
}
