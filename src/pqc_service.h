#pragma once
#include <string>
#include <oqs/oqs.h>

class PQCService {
public:
    std::string encrypt(const std::string& plaintext);

private:
    std::string bytes_to_hex(const uint8_t* data, size_t len);

};