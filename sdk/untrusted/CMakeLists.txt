list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
find_package(SGX REQUIRED)
find_package(Protobuf REQUIRED)
find_package(GRPC REQUIRED)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

file(GLOB COMMON_SRCS ${TOP_SRC_DIR}/common/*.cpp)
file(GLOB UNTRUSTED_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)
file(GLOB UNTRUSTED_ENCLAVE_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/enclave/*.cpp)
file(GLOB UNTRUSTED_RA_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/ra/*.cpp)
file(GLOB UNTRUSTED_UTILS_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/utils/*.cpp)
file(GLOB PROTO_FILES ${TEE_TOP_DIR}/proto/*.proto)
PROTOBUF_GENERATE_CPP(PROTO_SRCS PROTO_HDRS ${CMAKE_BINARY_DIR} ${PROTO_FILES})

set(EDL_SEARCH_PATHS ${TOP_SRC_DIR}/edl)
set(EDL_FILE ${TOP_SRC_DIR}/edl/kubetee.edl)
set(U_SRCS
    ${COMMON_SRCS}
    ${UNTRUSTED_SRCS}
    ${UNTRUSTED_ENCLAVE_SRCS}
    ${UNTRUSTED_RA_SRCS}
    ${UNTRUSTED_UTILS_SRCS}
    ${PROTO_SRCS}
)

set(UNTRUSTED_LIB ukubetee)
add_untrusted_library(
    ${UNTRUSTED_LIB} SHARED
    SRCS ${U_SRCS}
    EDL ${EDL_FILE}
    EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS}
)
target_include_directories(
    ${UNTRUSTED_LIB} PUBLIC
    ${TOP_SRC_DIR}
    ${TOP_SRC_DIR}/include
    ${TOP_SRC_DIR}/include/tee
    ${CMAKE_BINARY_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    /usr/include/openssl/../
    ${TEE_TOP_DIR}/third_party/cppcodec
    ${TEE_TOP_DIR}/third_party/rapidjson/include
)
target_link_libraries(
    ${UNTRUSTED_LIB}
    -lcurl -lprotobuf
    -Wl,-rpath=.:/lib64:/usr/local/lib:/usr/local/lib64:${SGX_LIBRARY_DIR}
)
