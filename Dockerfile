FROM ubuntu:22.04

# Install dependencies
RUN apt update && apt install -y \
    build-essential cmake git libssl-dev curl libevent-dev \
    libcurl4-openssl-dev ninja-build

# Install IPFS (Kubo)
RUN curl -O https://dist.ipfs.tech/kubo/v0.24.0/kubo_v0.24.0_linux-amd64.tar.gz && \
    tar -xvzf kubo_v0.24.0_linux-amd64.tar.gz && \
    cd kubo && \
    bash install.sh && \
    ipfs init    

# Install liboqs
RUN git clone --recursive https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && mkdir build && cd build && \
    cmake -DBUILD_SHARED_LIBS=ON .. && \
    make -j$(nproc) && \
    make install && ldconfig

# Install dependencies (including nlohmann JSON)
RUN apt update && apt install -y \
    build-essential cmake git libssl-dev curl libevent-dev \
    libcurl4-openssl-dev ninja-build nlohmann-json3-dev

RUN apt install -y python3-pip && pip3 install meson ninja
   
# Build Pistache & install it system-wide
# Build Pistache (no install)
RUN git clone https://github.com/pistacheio/pistache.git && \
    cd pistache && mkdir build && cd build && \
    cmake -DPISTACHE_BUILD_TESTS=OFF -DPISTACHE_BUILD_EXAMPLES=OFF .. && \
    make -j$(nproc)


# Build PQC Microservice (using Pistache static lib)
WORKDIR /app
COPY . /app

RUN echo $(realpath data_encrypted.bin)

RUN mkdir build && cd build && \
    cmake .. && \
    make -j$(nproc)


# Expose port
EXPOSE 9000

# Run microservice
CMD ["./build/pqc_microservice"]
