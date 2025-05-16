#include "pqc_service.h"
#include <oqs/kem.h>
#include <sstream>
#include <iomanip>
#include <oqs/oqs.h>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <vector>
#include <nlohmann/json.hpp>
#include <fstream>

using json = nlohmann::json;

std::pair<std::string, std::string> PQCService::generate_keypair() {
    OQS_KEM* kem = OQS_KEM_new("Kyber512");
    if (!kem) throw std::runtime_error("Failed to initialize Kyber512");

    std::vector<uint8_t> pub_key(kem->length_public_key);
    std::vector<uint8_t> secret_key(kem->length_secret_key);
    //secret_key.resize(kem->length_secret_key);

    if (OQS_KEM_keypair(kem, pub_key.data(), secret_key.data()) != OQS_SUCCESS)
        throw std::runtime_error("KEM keypair generation failed");

    OQS_KEM_free(kem);

    return {
        bytes_to_hex(pub_key.data(), pub_key.size()),
        bytes_to_hex(secret_key.data(), secret_key.size())
    };
}

std::string PQCService::bytes_to_hex(const uint8_t* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

// Utility: Convert hex string to bytes
std::vector<uint8_t> PQCService::hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::string PQCService::encrypt(const std::string& plaintext) {
    (void) plaintext;  // Ignored for KEM

    OQS_KEM *kem = OQS_KEM_new("Kyber512");
    if (kem == nullptr) {
        return "Error initializing Kyber KEM";
    }

    uint8_t public_key[kem->length_public_key];
    uint8_t secret_key[kem->length_secret_key];
    uint8_t ciphertext[kem->length_ciphertext];
    uint8_t shared_secret[kem->length_shared_secret];

    if (OQS_KEM_keypair(kem, public_key, secret_key) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        return "Error generating keypair";
    }

    if (OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        return "Error during encapsulation";
    }

    OQS_KEM_free(kem);

    return bytes_to_hex(ciphertext, sizeof(ciphertext));
}

// Encrypt file contents with AES-GCM, AES key encapsulated via recipient's Kyber512 public key
std::string PQCService::encrypt_data(const std::string& body) {
    try {
        // Parse incoming JSON
        json input = json::parse(body);
        if (!input.contains("public_key") || !input.contains("data")) {
            throw std::runtime_error("Missing required fields in body");
        }

        // Extract public key
        std::string pubkey_hex = input["public_key"];
        std::vector<uint8_t> pubkey(pubkey_hex.length() / 2);
        for (size_t i = 0; i < pubkey.size(); i++) {
            std::stringstream ss;
            ss << std::hex << pubkey_hex.substr(i * 2, 2);
            int val;
            ss >> val;
            pubkey[i] = static_cast<uint8_t>(val);
        }

        // Save data to temp file
        std::string filename = "/mnt/c/Users/Atharva/pistache/pqc_microservice/data_to_encrypt.json";
        //std::string filename = "/app/data_to_encrypt.json";
        std::ofstream outfile(filename);
        outfile << input["data"].dump(4);
        outfile.close();

        // Read back the file as string for AES encryption
        std::ifstream infile(filename);
        std::stringstream buffer;
        buffer << infile.rdbuf();
        std::string file_content = buffer.str();
        infile.close();

        // PQC encapsulation with public key
        OQS_KEM* kem = OQS_KEM_new("Kyber512");
        if (!kem) throw std::runtime_error("Failed to init KEM");

        std::vector<uint8_t> kem_ciphertext(kem->length_ciphertext);
        std::vector<uint8_t> shared_secret(kem->length_shared_secret);
        if (OQS_KEM_encaps(kem, kem_ciphertext.data(), shared_secret.data(), pubkey.data()) != OQS_SUCCESS)
            throw std::runtime_error("KEM encapsulation failed");

        OQS_KEM_free(kem);

        // Generate AES key & IV
        uint8_t aes_key[32], aes_iv[12], aes_tag[16];
        //RAND_bytes(aes_key, sizeof(aes_key));
        RAND_bytes(aes_iv, sizeof(aes_iv));

        std::vector<uint8_t> ciphertext(file_content.size() + 16); // AES-GCM tag

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        int len;
        int ciphertext_len;

        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, shared_secret.data(), aes_iv);

        EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                          reinterpret_cast<const uint8_t*>(file_content.data()),
                          file_content.size());
        ciphertext_len = len;

        EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
        ciphertext_len += len;

        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, aes_tag);
        EVP_CIPHER_CTX_free(ctx);

        // Save encrypted data
        std::ofstream enc_file("/mnt/c/Users/Atharva/pistache/pqc_microservice/data_encrypted.bin", std::ios::binary);
        //std::ofstream enc_file("/app/data_encrypted.bin", std::ios::binary);
        enc_file.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext_len);
        enc_file.close();

        // Return metadata JSON
        json out;
        out["aes_iv"] = bytes_to_hex(aes_iv, sizeof(aes_iv));
        out["aes_tag"] = bytes_to_hex(aes_tag, sizeof(aes_tag));
        out["kem_ciphertext"] = bytes_to_hex(kem_ciphertext.data(), kem_ciphertext.size());
        return out.dump();

    } catch (const std::exception& e) {
        return std::string("Encryption failed: ") + e.what();
    }
}

nlohmann::json PQCService::decrypt_data(const std::string& body) {
    try {
        auto json_body = nlohmann::json::parse(body);
        std::string private_key_hex = json_body["private_key"];
        std::string kem_ciphertext_hex = json_body["kem_ciphertext"];
        std::string aes_iv_hex = json_body["aes_iv"];
        std::string aes_tag_hex = json_body["aes_tag"];
        std::string encrypted_filename = json_body["encrypted_file"];

        OQS_KEM* kem = OQS_KEM_new("Kyber512");
        if (!kem) return "Failed to initialize Kyber512";

        std::vector<uint8_t> priv_key = hex_to_bytes(private_key_hex);
        std::vector<uint8_t> kem_ct = hex_to_bytes(kem_ciphertext_hex);
        std::vector<uint8_t> aes_iv = hex_to_bytes(aes_iv_hex);
        std::vector<uint8_t> aes_tag = hex_to_bytes(aes_tag_hex);
        std::vector<uint8_t> shared_secret(kem->length_shared_secret);

        if (OQS_KEM_decaps(kem, shared_secret.data(), kem_ct.data(), priv_key.data()) != OQS_SUCCESS) {
            OQS_KEM_free(kem);
            return "KEM decapsulation failed";
        }

        // Read ciphertext from file
        std::ifstream file_in(encrypted_filename, std::ios::binary);
        if (!file_in) {
            OQS_KEM_free(kem);
            return "Encrypted file not found";
        }
        std::vector<uint8_t> ciphertext((std::istreambuf_iterator<char>(file_in)), std::istreambuf_iterator<char>());
        file_in.close();

        std::vector<uint8_t> decrypted(ciphertext.size());

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            OQS_KEM_free(kem);
            return "Failed to create EVP context";
        }

        if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, shared_secret.data(), aes_iv.data())) {
            EVP_CIPHER_CTX_free(ctx);
            OQS_KEM_free(kem);
            return "EVP_DecryptInit failed";
        }

        int len;
        if (!EVP_DecryptUpdate(ctx, decrypted.data(), &len, ciphertext.data(), ciphertext.size())) {
            EVP_CIPHER_CTX_free(ctx);
            OQS_KEM_free(kem);
            return "EVP_DecryptUpdate failed";
        }

        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, aes_tag.size(), aes_tag.data())) {
            EVP_CIPHER_CTX_free(ctx);
            OQS_KEM_free(kem);
            return "Failed to set GCM tag";
        }

        int final_len = 0;
        if (EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &final_len) <= 0) {
            EVP_CIPHER_CTX_free(ctx);
            OQS_KEM_free(kem);
            return "Decryption failed: tag mismatch";
        }

        EVP_CIPHER_CTX_free(ctx);
        OQS_KEM_free(kem);

        // Return decrypted data as string (assumes UTF-8 JSON)
        //return std::string(decrypted.begin(), decrypted.begin() + len + final_len);
        std::string decrypted_str(decrypted.begin(), decrypted.begin() + len + final_len);
        nlohmann::json parsed = nlohmann::json::parse(decrypted_str);
        return parsed;

    } catch (const std::exception& e) {
        return std::string("Decryption error: ") + e.what();
    }
}