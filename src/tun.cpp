#include "tun.hpp"

#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <system_error>

TUN::TUN(const std::string& requestedName) {
    fd_ = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    
    if (fd_ < 0) throw std::system_error(errno, std::generic_category(), "open /dev/net/tun");
    if (requestedName.size() >= IFNAMSIZ) {
        throw std::invalid_argument("TUN interface name is too long");
    }

    ifreq ifr{};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    std::strncpy(ifr.ifr_name, requestedName.c_str(), IFNAMSIZ - 1);
    if (ioctl(fd_, TUNSETIFF, &ifr) < 0) {
        const int error = errno;
        close(fd_);
        fd_ = -1;
        throw std::system_error(error, std::generic_category(), "ioctl TUNSETIFF");
    }

    name_ = ifr.ifr_name;
}
TUN::~TUN() {
    if (fd_ >= 0) close(fd_);
}

int TUN::getFd() const { return fd_; }

const std::string& TUN::name() const { return name_; }

std::size_t TUN::readPacket(std::uint8_t* data, std::size_t capacity) const {
    const auto result = read(fd_, data, capacity);
    
    if (result < 0) throw std::system_error(errno, std::generic_category(), "read TUN");
    return static_cast<std::size_t>(result);
}


void TUN::writePacket(const std::uint8_t* data, std::size_t length) const {
    const auto result = write(fd_, data, length);
    if (result < 0 || static_cast<std::size_t>(result) != length) {
        throw std::system_error(result < 0 ? errno : EIO, std::generic_category(), "write TUN");
    }
}
