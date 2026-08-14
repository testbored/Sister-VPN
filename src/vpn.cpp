#include "vpn.hpp"


void VPN::openTUN(const char* dev_name){
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) { perror("open tun"); exit(1); }

    ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, dev_name, IFNAMSIZ);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        perror("ioctl TUNSETIFF"); exit(1);
    }

    this->fd = fd;
}

void VPN::setUpUDP(int localPort){
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(localPort);

    bind(fd, (struct sockaddr*)&addr, sizeof(addr));
    this->sockFd = fd;
}




VPN::VPN(const std::string& ipAddress, const std::string& subnetMask){
    
}