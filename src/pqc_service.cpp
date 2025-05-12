#include "pqc_service.h"
#include <oqs/kem.h>
#include <sstream>
#include <iomanip>
#include <oqs/oqs.h>


std::string PQCService::bytes_to_hex(const uint8_t* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
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