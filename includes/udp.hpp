#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

class UDP {
public:
    UDP(std::uint16_t localPort, const std::string& peerAddress,
        std::uint16_t peerPort);
    ~UDP();
    UDP(const UDP&) = delete;
    UDP& operator=(const UDP&) = delete;

    int getFd() const;
    void send(const std::uint8_t* data, std::size_t length) const;
    std::size_t receive(std::uint8_t* data, std::size_t capacity) const;

private:
    int sockFd_{-1};
};
