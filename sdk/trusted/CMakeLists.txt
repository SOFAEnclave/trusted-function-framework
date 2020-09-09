set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SGXSSL_INC /opt/intel/sgxssl/include)

find_package(Protobuf REQUIRED)
set(TEE_PROTO_FILES
    ${TEE_TOP_DIR}/proto/kubetee.proto
)
PROTOBUF_GENERATE_CPP(
    TEE_PROTO_SRCS
    TEE_PROTO_HDRS
    ${CMAKE_BINARY_DIR}
    ${TEE_PROTO_FILES}
)

file(GLOB COMMON_SRCS ${TOP_SRC_DIR}/common/*.cpp)
file(GLOB TRUSTED_RA_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/ra/*.cpp)
file(GLOB TRUSTED_UTILS_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/utils/*.cpp)
file(GLOB TRUSTED_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)

set(EDL_FILE ${TOP_SRC_DIR}/edl/kubetee.edl)
set(T_SRCS
    ${COMMON_SRCS}
    ${TRUSTED_SRCS}
    ${TRUSTED_RA_SRCS}
    ${TRUSTED_UTILS_SRCS}
    ${TEE_PROTO_SRCS}
)

include_directories(
    ${TOP_SRC_DIR}
    ${TOP_SRC_DIR}/include
    ${TOP_SRC_DIR}/include/tee
    ${CMAKE_BINARY_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${SGXSSL_INC}
    ${TEE_TOP_DIR}/third_party/cppcodec
    ${TEE_TOP_DIR}/third_party/protobuf-cpp/src/
)

set(TRUSTED_LIB tkubetee)
add_trusted_library(
    ${TRUSTED_LIB}
    SRCS ${T_SRCS}
    EDL ${EDL_FILE}
    EDL_SEARCH_PATHS ${TOP_SRC_DIR}/edl
)

target_link_libraries(
    ${TRUSTED_LIB}
    -ltprotobuf
)

add_dependencies(${TRUSTED_LIB} tprotobuf)
