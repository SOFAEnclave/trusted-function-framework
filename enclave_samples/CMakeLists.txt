list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
find_package(SGX REQUIRED)

add_subdirectory(protobuf_functions)
add_subdirectory(remote_attestation)
