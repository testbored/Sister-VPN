#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace crypto {
constexpr std::size_t KEY_BYTES = 32;
constexpr std::size_t NONCE_BYTES = 12;
constexpr std::size_t TAG_BYTES = 16;
using Key = std::array<std::uint8_t, KEY_BYTES>;
using Nonce = std::array<std::uint8_t, NONCE_BYTES>;

Key keyFromHex(const std::string& hex);
Key deriveDirectionalKey(const Key& preSharedKey, const std::string& label);
std::uint32_t randomSessionId();
std::size_t encrypt(const Key& key, const Nonce& nonce,
                    const std::uint8_t* aad, std::size_t aadLength,
                    const std::uint8_t* plaintext, std::size_t plaintextLength,
                    std::uint8_t* output, std::size_t outputCapacity);
std::size_t decrypt(const Key& key, const Nonce& nonce,
                    const std::uint8_t* aad, std::size_t aadLength,
                    const std::uint8_t* ciphertextAndTag, std::size_t inputLength,
                    std::uint8_t* output, std::size_t outputCapacity);
}  // namespace crypto
