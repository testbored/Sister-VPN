#include "crypto.hpp"
#include "vpn.hpp"

#include <charconv>
#include <cstdlib>
#include <iostream>
#include <stdexcept>

namespace {

[[noreturn]] void usage() {
    std::cerr << "Usage: sister-vpn --tun NAME --listen PORT --peer IPV4:PORT "
                 "--key HEX64 --role initiator|responder [--mtu N]\n";
    std::exit(2);
}

std::uint16_t parsePort(const std::string& value) {
    unsigned port{};
    const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), port);
    if (error != std::errc{} || end != value.data() + value.size() || port > 65535) {
        throw std::invalid_argument("invalid port");
    }
    return static_cast<std::uint16_t>(port);
}

}  // namespace

int main(int argc, char** argv) {
    try {
        VPNConfig config{};
        bool gotTun = false;
        bool gotListen = false;
        bool gotPeer = false;
        bool gotKey = false;
        bool gotRole = false;

        for (int index = 1; index < argc; ++index) {
            const std::string argument = argv[index];
            if (argument == "--help") usage();
            if (++index >= argc) usage();
            const std::string value = argv[index];

            if (argument == "--tun") {
                config.tunName = value;
                gotTun = true;
            } else if (argument == "--listen") {
                config.localPort = parsePort(value);
                gotListen = true;
            } else if (argument == "--peer") {
                const auto separator = value.rfind(':');
                if (separator == std::string::npos) throw std::invalid_argument("peer must be IPV4:PORT");
                config.peerAddress = value.substr(0, separator);
                config.peerPort = parsePort(value.substr(separator + 1));
                gotPeer = true;
            } else if (argument == "--key") {
                config.preSharedKey = crypto::keyFromHex(value);
                gotKey = true;
            } else if (argument == "--role") {
                if (value == "initiator") config.role = Role::Initiator;
                else if (value == "responder") config.role = Role::Responder;
                else throw std::invalid_argument("role must be initiator or responder");
                gotRole = true;
            } else if (argument == "--mtu") {
                unsigned mtu{};
                const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), mtu);
                if (error != std::errc{} || end != value.data() + value.size()) {
                    throw std::invalid_argument("invalid MTU");
                }
                config.mtu = mtu;
            } else {
                usage();
            }
        }
        if (!gotTun || !gotListen || !gotPeer || !gotKey || !gotRole) usage();
        VPN(config).run();
    } catch (const std::exception& error) {
        std::cerr << "sister-vpn: " << error.what() << '\n';
        return 1;
    }
}
