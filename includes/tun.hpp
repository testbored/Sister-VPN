#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

// TUN carries raw layer-3 IP packets; IFF_NO_PI omits Linux metadata.
class TUN {
public:
    explicit TUN(const std::string& requestedName);
    ~TUN();
    TUN(const TUN&) = delete;
    TUN& operator=(const TUN&) = delete;

    int getFd() const;
    const std::string& name() const;
    std::size_t readPacket(std::uint8_t* data, std::size_t capacity) const;
    void writePacket(const std::uint8_t* data, std::size_t length) const;

private:
    int fd_{-1};
    std::string name_;
};
