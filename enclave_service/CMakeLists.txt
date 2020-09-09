set(SGXSSL_LIB /opt/intel/sgxssl/lib64)
set(SGXSSL_INC /opt/intel/sgxssl/include)

# Generate the protobuf and grpc source and header files
find_package(Protobuf REQUIRED)
find_package(GRPC REQUIRED)
set(ES_PROTO_FILES
    ${TEE_TOP_DIR}/proto/kubetee.proto
    ${CMAKE_CURRENT_SOURCE_DIR}/proto/enclave_service.proto
)
PROTOBUF_GENERATE_CPP(
    ES_PROTO_SRCS
    ES_PROTO_HDRS
    ${CMAKE_BINARY_DIR}
    ${ES_PROTO_FILES}
)
GRPC_GENERATE_CPP(
    ES_GRPC_SRCS
    ES_GRPC_HDRS
    ${CMAKE_BINARY_DIR}
    ${ES_PROTO_FILES}
)

set(ES_EDL ${CMAKE_CURRENT_SOURCE_DIR}/trusted/enclave_service.edl)
set(EX_EDL_SEARCH_PATHS
    ${CMAKE_CURRENT_SOURCE_DIR}/trusted
    ${TEE_TOP_DIR}/sdk/edl
    ${TEE_TOP_DIR}/sdk/include
    ${SGXSSL_INC}
)

# Generate the trusted targets
file(GLOB ES_TRUSTED_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/trusted/*.cpp)
set(ES_LDS ${CMAKE_CURRENT_SOURCE_DIR}/trusted/enclave_service.lds)
set(ES_KEY ${CMAKE_CURRENT_SOURCE_DIR}/trusted/enclave_private.pem)
set(ES_XML ${CMAKE_CURRENT_SOURCE_DIR}/trusted/enclave.config.xml)
set(ES_TLIBS tkubetee tprotobuf)
set(ES_TSRCS
    ${ES_TRUSTED_SRCS}
    ${CMAKE_BINARY_DIR}/enclave_service.pb.cc
)
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_BINARY_DIR}
    ${TEE_TOP_DIR}/sdk
    ${TEE_TOP_DIR}/sdk/include
    ${TEE_TOP_DIR}/third_party/protobuf-cpp/src/
)

set(ESENCLAVE enclave_service)
add_enclave_library(
    ${ESENCLAVE}
    SRCS ${ES_TSRCS}
    TRUSTED_LIBS ${ES_TLIBS}
    EDL ${ES_EDL}
    EDL_SEARCH_PATHS ${EX_EDL_SEARCH_PATHS}
    LDSCRIPT ${ES_LDS}
)
target_include_directories(
    ${ESENCLAVE} PRIVATE
    ${SGXSSL_INC}
)
enclave_sign(
    ${ESENCLAVE}
    KEY ${ES_KEY}
    CONFIG ${ES_XML}
)

# common untrusted files
file(GLOB ES_CPPSRCS ${CMAKE_CURRENT_SOURCE_DIR}/untrusted/*.cpp)
file(GLOB ES_SERVER_CPPSRCS ${CMAKE_CURRENT_SOURCE_DIR}/server/*.cpp)

# Generate the untrusted targets
set(ES_SERVER_USRCS ${ES_CPPSRCS} ${ES_SERVER_CPPSRCS} ${ES_PROTO_SRCS} ${ES_GRPC_SRCS})
include_directories(
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_BINARY_DIR}
    ${TEE_TOP_DIR}/sdk
    ${TEE_TOP_DIR}/sdk/include
    ${TEE_TOP_DIR}/third_party/rapidjson/include
)
set(ES_SERVER_APP enclave_service_server)
add_untrusted_executable(
    ${ES_SERVER_APP}
    SRCS ${ES_SERVER_USRCS}
    EDL ${ES_EDL}
    EDL_SEARCH_PATHS ${EX_EDL_SEARCH_PATHS}
)
target_link_libraries(
    ${ES_SERVER_APP}
    -L${LIBRARY_OUTPUT_PATH} -L${SGX_LIBRARY_DIR} -L${SGXSSL_LIB}
    -L/usr/lib64 -L/usr/local/lib64
    -lprotobuf
    gRPC::grpc++_reflection
    -Wl,--start-group -lukubetee -lchallenger -lsgx_usgxssl -lcrypto -Wl,--end-group
    -Wl,-rpath=.:/lib64:/usr/lib:/usr/local/lib:/usr/local/lib64:${SGX_LIBRARY_DIR}
)
add_dependencies(${ES_SERVER_APP} ukubetee challenger)

# Generate the untrusted cli test targets
file(GLOB ES_CLIENT_CPPSRCS ${CMAKE_CURRENT_SOURCE_DIR}/client/*.cpp)
set(ES_CLIENT_USRCS ${ES_CPPSRCS} ${ES_CLIENT_CPPSRCS} ${ES_PROTO_SRCS} ${ES_GRPC_SRCS})
include_directories(
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_BINARY_DIR}
    ${TEE_TOP_DIR}/sdk
    ${TEE_TOP_DIR}/sdk/include
    ${TEE_TOP_DIR}/third_party/rapidjson/include
)
set(ES_CLIENT_APP enclave_service_client)
add_untrusted_executable(
    ${ES_CLIENT_APP}
    SRCS ${ES_CLIENT_USRCS}
    EDL ${ES_EDL}
    EDL_SEARCH_PATHS ${EX_EDL_SEARCH_PATHS}
)
target_link_libraries(
    ${ES_CLIENT_APP}
    -L${LIBRARY_OUTPUT_PATH} -L${SGX_LIBRARY_DIR} -L${SGXSSL_LIB}
    -L/usr/lib64 -L/usr/local/lib64
    -lprotobuf
    gRPC::grpc++_reflection
    -Wl,--start-group -lukubetee -lchallenger -lsgx_usgxssl -lcrypto -Wl,--end-group
    -Wl,-rpath=.:/lib64:/usr/lib:/usr/local/lib:/usr/local/lib64:${SGX_LIBRARY_DIR}
)
add_dependencies(${ES_CLIENT_APP} ukubetee challenger)
