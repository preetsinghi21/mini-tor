#pragma once

#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <memory>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>

namespace minitor {
namespace crypto {

// Helper: Convert binary vector to hex string
inline std::string to_hex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    return oss.str();
}

inline std::string to_hex(const std::vector<uint8_t>& data) {
    return to_hex(data.data(), data.size());
}

// Helper: Convert hex string to binary vector
inline std::vector<uint8_t> from_hex(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// Generates random bytes
inline std::vector<uint8_t> random_bytes(size_t len) {
    std::vector<uint8_t> buf(len);
    if (RAND_bytes(buf.data(), static_cast<int>(len)) != 1) {
        // Fallback if RAND_bytes fails
        for (size_t i = 0; i < len; ++i) buf[i] = static_cast<uint8_t>(rand() % 256);
    }
    return buf;
}

// X25519 KeyPair for ECDH
class KeyPair {
public:
    EVP_PKEY* pkey;
    std::vector<uint8_t> public_key; // 32 bytes

    KeyPair() : pkey(nullptr) {
        generate();
    }

    ~KeyPair() {
        if (pkey) {
            EVP_PKEY_free(pkey);
            pkey = nullptr;
        }
    }

    // Disable copy to avoid double-free
    KeyPair(const KeyPair&) = delete;
    KeyPair& operator=(const KeyPair&) = delete;

    // Allow move
    KeyPair(KeyPair&& other) noexcept : pkey(other.pkey), public_key(std::move(other.public_key)) {
        other.pkey = nullptr;
    }

    KeyPair& operator=(KeyPair&& other) noexcept {
        if (this != &other) {
            if (pkey) EVP_PKEY_free(pkey);
            pkey = other.pkey;
            public_key = std::move(other.public_key);
            other.pkey = nullptr;
        }
        return *this;
    }

    bool generate() {
        if (pkey) {
            EVP_PKEY_free(pkey);
            pkey = nullptr;
        }
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
        if (!pctx) return false;

        if (EVP_PKEY_keygen_init(pctx) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            return false;
        }

        if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            return false;
        }
        EVP_PKEY_CTX_free(pctx);

        public_key.resize(32);
        size_t len = 32;
        if (EVP_PKEY_get_raw_public_key(pkey, public_key.data(), &len) <= 0) {
            return false;
        }
        return true;
    }

    std::string get_public_hex() const {
        return to_hex(public_key);
    }
};

// Compute X25519 ECDH Shared Secret (32 bytes)
inline bool derive_shared_secret(const KeyPair& my_key, const std::vector<uint8_t>& peer_pubkey, std::vector<uint8_t>& out_secret) {
    if (peer_pubkey.size() != 32 || !my_key.pkey) return false;

    EVP_PKEY* peer_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_pubkey.data(), 32);
    if (!peer_pkey) return false;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(my_key.pkey, nullptr);
    if (!ctx) {
        EVP_PKEY_free(peer_pkey);
        return false;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0 || EVP_PKEY_derive_set_peer(ctx, peer_pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_pkey);
        return false;
    }

    size_t secret_len = 0;
    if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_pkey);
        return false;
    }

    out_secret.resize(secret_len);
    if (EVP_PKEY_derive(ctx, out_secret.data(), &secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_pkey);
        return false;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_pkey);
    return true;
}

// HKDF-SHA256 Key Derivation
inline bool hkdf_sha256(const std::vector<uint8_t>& secret, const std::string& info, size_t key_len, std::vector<uint8_t>& out_key) {
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf) return false;
    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx) return false;

    OSSL_PARAM params[4];
    char digest[] = "SHA256";
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, sizeof(digest));
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void*)secret.data(), secret.size());
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void*)info.data(), info.size());
    params[3] = OSSL_PARAM_construct_end();

    out_key.resize(key_len);
    int res = EVP_KDF_derive(kctx, out_key.data(), out_key.size(), params);
    EVP_KDF_CTX_free(kctx);
    return res > 0;
}

// AES-256-GCM Encrypt:
// Result format: [12 bytes IV] + [16 bytes TAG] + [Ciphertext]
inline bool aes_gcm_encrypt(const std::vector<uint8_t>& key,
                            const std::vector<uint8_t>& plaintext,
                            std::vector<uint8_t>& out_packet) {
    if (key.size() != 32) return false;

    std::vector<uint8_t> iv = random_bytes(12);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    std::vector<uint8_t> ciphertext(plaintext.size());
    int len = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int total_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    total_len += len;
    ciphertext.resize(total_len);

    std::vector<uint8_t> tag(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    EVP_CIPHER_CTX_free(ctx);

    // Pack into out_packet: [12-byte IV] + [16-byte TAG] + [Ciphertext]
    out_packet.clear();
    out_packet.reserve(12 + 16 + ciphertext.size());
    out_packet.insert(out_packet.end(), iv.begin(), iv.end());
    out_packet.insert(out_packet.end(), tag.begin(), tag.end());
    out_packet.insert(out_packet.end(), ciphertext.begin(), ciphertext.end());
    return true;
}

// AES-256-GCM Decrypt:
// Expects: [12 bytes IV] + [16 bytes TAG] + [Ciphertext]
inline bool aes_gcm_decrypt(const std::vector<uint8_t>& key,
                            const std::vector<uint8_t>& in_packet,
                            std::vector<uint8_t>& out_plaintext) {
    if (key.size() != 32 || in_packet.size() < (12 + 16)) return false;

    const uint8_t* iv = in_packet.data();
    const uint8_t* tag = in_packet.data() + 12;
    const uint8_t* ciphertext = in_packet.data() + 28;
    size_t ciphertext_len = in_packet.size() - 28;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    out_plaintext.resize(ciphertext_len);
    int len = 0;
    if (EVP_DecryptUpdate(ctx, out_plaintext.data(), &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int total_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int ret = EVP_DecryptFinal_ex(ctx, out_plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    if (ret > 0) {
        total_len += len;
        out_plaintext.resize(total_len);
        return true;
    }
    return false;
}

} // namespace crypto
} // namespace minitor
