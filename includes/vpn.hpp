#pragma once

#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <cstring>
#include <string>

class VPN{
private:
    int fd;
    int sockFd;
    
    void openTUN(const char* dev_name);
    void setUpUDP(int localPort);

public:
    VPN(const std::string& ipAddress, const std::string& subnetMask);
    void send();
    void receive();
};