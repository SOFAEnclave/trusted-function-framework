list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
find_package(Protobuf REQUIRED)

file(GLOB COMMON_SRCS ${TOP_SRC_DIR}/common/*.cpp)
file(GLOB UTILS_SRCS ${TOP_SRC_DIR}/untrusted/utils/*.cpp)
file(GLOB CHALLENGER_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)
file(GLOB PROTO_FILES ${TEE_TOP_DIR}/proto/*.proto)
PROTOBUF_GENERATE_CPP(PROTO_SRCS PROTO_HDRS ${CMAKE_BINARY_DIR} ${PROTO_FILES})

set(C_SRCS
    ${COMMON_SRCS}
    ${UTILS_SRCS}
    ${CHALLENGER_SRCS}
    ${TOP_SRC_DIR/untrusted/ra/untrusted_config.cpp}
    ${PROTO_SRCS}
)

add_library(challenger SHARED ${C_SRCS})
target_include_directories(
    challenger PUBLIC
    ${TOP_SRC_DIR}
    ${TOP_SRC_DIR}/include
    ${TOP_SRC_DIR}/include/tee
    ${CMAKE_BINARY_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${SGX_INCLUDE_DIR}
    /usr/include/openssl/../
    ${TEE_TOP_DIR}/third_party/cppcodec
    ${TEE_TOP_DIR}/third_party/rapidjson/include
)
