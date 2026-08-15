#include "udp.hpp"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <stdexcept>
#include <system_error>

UDP::UDP(std::uint16_t localPort, const std::string& peerAddress, std::uint16_t peerPort) {
    sockFd_ = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sockFd_ < 0) throw std::system_error(errno, std::generic_category(), "create UDP socket");
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(localPort);
    
    if (bind(sockFd_, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) < 0) {
        const int error = errno;
        close(sockFd_);
        sockFd_ = -1;
        throw std::system_error(error, std::generic_category(), "bind UDP socket");
    }

    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    peer.sin_port = htons(peerPort);
    if (inet_pton(AF_INET, peerAddress.c_str(), &peer.sin_addr) != 1) {
        close(sockFd_);
        sockFd_ = -1;
        throw std::invalid_argument("peer must be an IPv4 address");
    }

    if (connect(sockFd_, reinterpret_cast<const sockaddr*>(&peer), sizeof(peer)) < 0) {
        const int error = errno;
        close(sockFd_);
        sockFd_ = -1;
        throw std::system_error(error, std::generic_category(), "connect UDP peer");
    }

}


UDP::~UDP() {
    if (sockFd_ >= 0) close(sockFd_);
}

int UDP::getFd() const { return sockFd_; }

void UDP::send(const std::uint8_t* data, std::size_t length) const {
    const auto result = ::send(sockFd_, data, length, 0);
    if (result < 0 || static_cast<std::size_t>(result) != length) {
        throw std::system_error(result < 0 ? errno : EIO, std::generic_category(), "send UDP datagram");
    }
}

std::size_t UDP::receive(std::uint8_t* data, std::size_t capacity) const {
    const auto result = recv(sockFd_, data, capacity, 0);
    if (result < 0) throw std::system_error(errno, std::generic_category(), "receive UDP datagram");
    return static_cast<std::size_t>(result);
}
