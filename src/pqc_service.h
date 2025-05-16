#pragma once
#include <string>
#include <oqs/oqs.h>
#include <vector>
#include <nlohmann/json.hpp>

class PQCService {
public:
    std::string encrypt(const std::string& plaintext);
    std::pair<std::string, std::string> generate_keypair(); // pub, priv
    std::string encrypt_data(const std::string& body);
    nlohmann::json decrypt_data(const std::string& body);

private:
    std::string bytes_to_hex(const uint8_t* data, size_t len);
    std::vector<uint8_t> hex_to_bytes(const std::string& hex);
};