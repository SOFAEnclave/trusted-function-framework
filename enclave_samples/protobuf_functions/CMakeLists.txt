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

set(INC_EX ${TEE_TOP_DIR}/sdk/include)
set(SGXSSL_LIB /opt/intel/sgxssl/lib64)
set(SGXSSL_INC /opt/intel/sgxssl/include)
set(EX_EDL_SEARCH_PATHS
    ${CMAKE_CURRENT_SOURCE_DIR}/enclave
    ${TEE_TOP_DIR}/sdk/edl
    ${SGXSSL_INC}
    ${INC_EX}
)
set(E_SRCS
    ${TEE_PROTO_SRCS}
    ${CMAKE_CURRENT_SOURCE_DIR}/enclave/enclave.cpp
)
set(LDS ${CMAKE_CURRENT_SOURCE_DIR}/enclave/enclave.lds)
set(EDL ${CMAKE_CURRENT_SOURCE_DIR}/enclave/enclave.edl)
set(KEY ${CMAKE_CURRENT_SOURCE_DIR}/enclave/enclave_private.pem)
set(XML ${CMAKE_CURRENT_SOURCE_DIR}/enclave/enclave.config.xml)
set(TLIBS tkubetee tprotobuf)
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_BINARY_DIR}
    ${TEE_TOP_DIR}/sdk
    ${TEE_TOP_DIR}/third_party/protobuf-cpp/src/
)

set(SAMPLEENCLAVE enclave_protobuf_functions)
add_enclave_library(
    ${SAMPLEENCLAVE}
    SRCS ${E_SRCS}
    TRUSTED_LIBS ${TLIBS}
    EDL ${EDL}
    EDL_SEARCH_PATHS ${EX_EDL_SEARCH_PATHS}
    LDSCRIPT ${LDS}
)
enclave_sign(
    ${SAMPLEENCLAVE}
    KEY ${KEY}
    CONFIG ${XML}
)

set(SAMPLEAPP sample_protobuf_functions)
set(SRCS
    ${TEE_PROTO_SRCS}
    ${CMAKE_CURRENT_SOURCE_DIR}/app/app.cpp
)
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_BINARY_DIR}
    ${TEE_TOP_DIR}/sdk
    ${TEE_TOP_DIR}/sdk/include
)
add_untrusted_executable(
    ${SAMPLEAPP}
    SRCS ${SRCS}
    EDL ${EDL}
    EDL_SEARCH_PATHS ${EX_EDL_SEARCH_PATHS}
)
target_link_libraries(
    ${SAMPLEAPP}
    -L${LIBRARY_OUTPUT_PATH} -L${SGX_LIBRARY_DIR} -L${SGXSSL_LIB} -L/usr/lib64
    -lprotobuf
    -Wl,--start-group -lukubetee -lchallenger -lsgx_usgxssl -lcrypto -Wl,--end-group
    -Wl,-rpath=.:/lib64:/usr/lib:/usr/local/lib
)
add_dependencies(${SAMPLEAPP} ukubetee challenger)
