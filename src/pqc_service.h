#pragma once
#include <string>
#include <oqs/oqs.h>
#include <vector>

class PQCService {
public:
    std::string encrypt(const std::string& plaintext);
    std::pair<std::string, std::string> generate_keypair(); // pub, priv
private:
    std::string bytes_to_hex(const uint8_t* data, size_t len);

};