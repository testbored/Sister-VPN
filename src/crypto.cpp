#include "crypto.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <stdexcept>

namespace crypto {
namespace {

int hexValue(char character) {
    if (character >= '0' && character <= '9') return character - '0';
    if (character >= 'a' && character <= 'f') return character - 'a' + 10;
    if (character >= 'A' && character <= 'F') return character - 'A' + 10;
    return -1;
}

void check(bool succeeded, const char* operation) {
    if (!succeeded) throw std::runtime_error(operation);
}

}  // namespace

Key keyFromHex(const std::string& hex) {
    if (hex.size() != KEY_BYTES * 2) {
        throw std::invalid_argument("key must be 64 hexadecimal characters");
    }
    Key key{};
    for (std::size_t index = 0; index < key.size(); ++index) {
        const int high = hexValue(hex[index * 2]);
        const int low = hexValue(hex[index * 2 + 1]);
        if (high < 0 || low < 0) throw std::invalid_argument("invalid hexadecimal key");
        key[index] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return key;
}

Key deriveDirectionalKey(const Key& preSharedKey, const std::string& label) {
    Key key{};
    unsigned int outputLength = 0;
    const auto* result = HMAC(
        EVP_sha256(), preSharedKey.data(), preSharedKey.size(),
        reinterpret_cast<const unsigned char*>(label.data()), label.size(), key.data(), &outputLength);
    if (result == nullptr || outputLength != key.size()) {
        throw std::runtime_error("derive directional key");
    }
    return key;
}

std::uint32_t randomSessionId() {
    std::uint32_t value{};
    check(RAND_bytes(reinterpret_cast<unsigned char*>(&value), sizeof(value)) == 1, "random session id");
    return value;
}

std::size_t encrypt(const Key& key, const Nonce& nonce, const std::uint8_t* aad,
                    std::size_t aadLength, const std::uint8_t* plaintext,
                    std::size_t plaintextLength, std::uint8_t* output,
                    std::size_t outputCapacity) {
    if (outputCapacity < plaintextLength + TAG_BYTES) {
        throw std::invalid_argument("output buffer too small");
    }
    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    if (context == nullptr) throw std::runtime_error("cipher context");
    int length = 0;
    int produced = 0;
    try {
        check(EVP_EncryptInit_ex(context, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) == 1, "cipher init");
        check(EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_IVLEN, NONCE_BYTES, nullptr) == 1, "nonce length");
        check(EVP_EncryptInit_ex(context, nullptr, nullptr, key.data(), nonce.data()) == 1, "cipher key");
        if (aadLength) check(EVP_EncryptUpdate(context, nullptr, &length, aad, aadLength) == 1, "header auth");
        if (plaintextLength) {
            check(EVP_EncryptUpdate(context, output, &length, plaintext, plaintextLength) == 1, "encrypt");
            produced = length;
        }
        check(EVP_EncryptFinal_ex(context, output + produced, &length) == 1, "encrypt final");
        produced += length;
        check(EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_GET_TAG, TAG_BYTES, output + produced) == 1, "auth tag");
        EVP_CIPHER_CTX_free(context);
        return static_cast<std::size_t>(produced) + TAG_BYTES;
    } catch (...) {
        EVP_CIPHER_CTX_free(context);
        throw;
    }
}

std::size_t decrypt(const Key& key, const Nonce& nonce, const std::uint8_t* aad,
                    std::size_t aadLength, const std::uint8_t* input,
                    std::size_t inputLength, std::uint8_t* output,
                    std::size_t outputCapacity) {
    if (inputLength < TAG_BYTES || outputCapacity < inputLength - TAG_BYTES) {
        throw std::invalid_argument("invalid encrypted packet size");
    }
    const std::size_t ciphertextLength = inputLength - TAG_BYTES;
    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    if (context == nullptr) throw std::runtime_error("cipher context");
    int length = 0;
    int produced = 0;
    try {
        check(EVP_DecryptInit_ex(context, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) == 1, "cipher init");
        check(EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_IVLEN, NONCE_BYTES, nullptr) == 1, "nonce length");
        check(EVP_DecryptInit_ex(context, nullptr, nullptr, key.data(), nonce.data()) == 1, "cipher key");
        if (aadLength) check(EVP_DecryptUpdate(context, nullptr, &length, aad, aadLength) == 1, "header auth");
        if (ciphertextLength) {
            check(EVP_DecryptUpdate(context, output, &length, input, ciphertextLength) == 1, "decrypt");
            produced = length;
        }
        check(EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_TAG, TAG_BYTES,
                                  const_cast<std::uint8_t*>(input + ciphertextLength)) == 1, "auth tag");
        if (EVP_DecryptFinal_ex(context, output + produced, &length) != 1) {
            throw std::runtime_error("packet authentication failed");
        }
        produced += length;
        EVP_CIPHER_CTX_free(context);
        return static_cast<std::size_t>(produced);
    } catch (...) {
        EVP_CIPHER_CTX_free(context);
        throw;
    }
}

}  // namespace crypto
