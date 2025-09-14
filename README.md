
PQC Microservice – C++ Hybrid Encryption Service
================================================

A C++ microservice using Pistache REST framework to perform hybrid post-quantum encryption with Kyber512 (from liboqs), AES-GCM, and JSON APIs. It supports file encryption, IPFS storage, and AES key encapsulation using Kyber KEM.

Features
--------
- REST API (Pistache-based)
- Hybrid encryption using:
  - Kyber512 (Post-Quantum KEM)
  - AES-GCM (symmetric encryption)
- IPFS integration for storing encrypted files
- Docker and Docker Compose ready

Prerequisites
-------------
**Local System (Ubuntu 22.04 or WSL):**
- CMake ≥ 3.10
- C++17 compiler
- Git, Curl
- libssl-dev, libevent-dev, libcurl4-openssl-dev
- nlohmann-json3-dev
- Docker (optional)

**Installed Libraries:**
- liboqs (Open Quantum Safe)
- Pistache (REST server)
- nlohmann/json

Build Instructions (Locally)
----------------------------
1. Clone the project
    git clone https://github.com/yourname/pqc_microservice.git
    cd pqc_microservice

2. Install dependencies
    sudo apt update && sudo apt install -y \
        build-essential cmake git libssl-dev curl libevent-dev \
        libcurl4-openssl-dev ninja-build nlohmann-json3-dev

3. Build liboqs
    git clone --recursive https://github.com/open-quantum-safe/liboqs.git
    cd liboqs && mkdir build && cd build
    cmake -DBUILD_SHARED_LIBS=ON ..
    make -j$(nproc) && sudo make install
    sudo ldconfig
    cd ../..

4. Build Pistache (static)
    git clone https://github.com/pistacheio/pistache.git
    cd pistache && mkdir build && cd build
    cmake -DPISTACHE_BUILD_TESTS=OFF -DPISTACHE_BUILD_EXAMPLES=OFF ..
    make -j$(nproc)
    cd ../..

5. Build your microservice
    mkdir build && cd build
    cmake ..
    make -j$(nproc)

Docker Setup
------------
1. Build Docker image
    docker build -t pqc-microservice .

2. Run container
    docker run -p 9000:9000 pqc-microservice

Docker Compose (Optional + IPFS)
    docker compose up --build

API Endpoints
-------------
**POST /encrypt_data** - Encrypts data using hybrid Kyber512 + AES-GCM.

curl -X POST http://localhost:9000/encrypt_data \
  -H "Content-Type: application/json" \
  -d '{"file_path": "data.txt", "receiver_public_key": "..." }'

Sample Response:
{
  "aes_iv": "...",
  "aes_tag": "...",
  "ciphertext": "...",
  "kem_ciphertext": "...",
  "cid": "Qm..."  // (if stored on IPFS)
}

IPFS Integration
----------------
- Store encrypted files using `ipfs add`
- Retrieve files using `ipfs cat` or `http://localhost:8080/ipfs/<CID>`

Security Notes
--------------
- Kyber512 is used to securely exchange AES key (KEM).
- AES-GCM provides confidentiality and integrity.
- IPFS stores ciphertext, blockchain can store hash/metadata (optional).
- CORS headers are enabled for local development.

Tech Stack
----------
- REST API: Pistache
- PQ Encryption: liboqs (Kyber512)
- Symmetric: AES-GCM (OpenSSL)
- JSON Parsing: nlohmann/json
- IPFS: Kubo (Go-IPFS)
- Docker: Multi-stage image
- Blockchain (optional): CID storage only

Credits
-------
- Open Quantum Safe
- Kyber PQC Algorithm
- Pistache REST Framework

License
-------
MIT License – free to use, modify, and distribute.
