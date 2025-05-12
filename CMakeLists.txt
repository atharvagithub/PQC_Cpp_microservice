cmake_minimum_required(VERSION 3.10)
project(PQCMicroservice)

set(CMAKE_CXX_STANDARD 17)

# Find liboqs library
find_library(OQS_LIB oqs PATHS /usr/local/lib REQUIRED)

# Define executable target first
add_executable(pqc_microservice
    src/main.cpp
    src/pqc_service.cpp
)

# Include Pistache & liboqs headers
target_include_directories(pqc_microservice PRIVATE
    ${CMAKE_SOURCE_DIR}/../include
    ${CMAKE_SOURCE_DIR}/../build/include
    /usr/local/include
)

# Link Pistache static lib & liboqs
target_link_libraries(pqc_microservice
    ${OQS_LIB}
    ${CMAKE_SOURCE_DIR}/../build/src/libpistache.a
    pthread
)
