cmake_minimum_required(VERSION 3.10)
project(PQCMicroservice)

set(CMAKE_CXX_STANDARD 17)

# Find liboqs (already built in Docker)
find_library(OQS_LIB oqs REQUIRED)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Include Pistache headers from its build
include_directories(/pistache/include)

# Add your project source files
add_executable(pqc_microservice
    src/main.cpp
    src/pqc_service.cpp
)

# Include header paths manually
target_include_directories(pqc_microservice PRIVATE
    /usr/local/include          # for liboqs
    /usr/include/nlohmann       # for json.hpp (from apt install nlohmann-json)
    /pistache/include           # for pistache (from build)
)
# Link Pistache static lib manually
target_link_libraries(pqc_microservice
    ${OQS_LIB}
    /pistache/build/src/libpistache.a
    pthread
)

# Link static Pistache library and other dependencies
target_link_libraries(pqc_microservice
    ${OQS_LIB}
    OpenSSL::Crypto
    pthread
    /pistache/build/src/libpistache.a
)