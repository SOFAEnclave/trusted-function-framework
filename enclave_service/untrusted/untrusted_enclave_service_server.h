#ifndef ENCLAVE_SERVICE_UNTRUSTED_UNTRUSTED_ENCLAVE_SERVICE_SERVER_H_
#define ENCLAVE_SERVICE_UNTRUSTED_UNTRUSTED_ENCLAVE_SERVICE_SERVER_H_

#include <string>

#include "tee/common/error.h"
#include "tee/common/type.h"
#include "tee/untrusted/enclave/untrusted_enclave.h"

#include "grpcpp/grpcpp.h"

#include "./enclave_service.grpc.pb.h"
#include "./enclave_service.pb.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::SslServerCredentialsOptions;
using grpc::Status;

using tee::EnclaveService;

#define RETURN_ERROR(msg)                           \
  do {                                              \
    TEE_LOG_ERROR(msg);                             \
    return Status(grpc::StatusCode::INTERNAL, msg); \
  } while (0)

#define GRPC_INTERFACE_ENTER_DEBUG() \
  TEE_LOG_DEBUG("GRPC SERVER INTERFACE:%s", __FUNCTION__)

namespace tee {
namespace untrusted {

class EnclaveServiceServerImpl final : public EnclaveService::Service {
 public:
  TeeErrorCode Initialize(EnclaveInstance* enclave);

  Status TeeRunRemote(ServerContext* context,
                      const PbTeeRunRemoteRequest* request,
                      PbTeeRunRemoteResponse* response);
  TeeErrorCode GetServerRaAuthentication(RaReportAuthentication* auth);

 private:
  TeeErrorCode CheckRaAuthentication(const RaReportAuthentication& auth);
  TeeErrorCode CheckSignatureAuthentication(const std::string& data,
                                            const std::string& signature);

  EnclaveInstance* enclave_;
  IasReport server_ias_report_;
};

class EnclaveServiceServer {
 public:
  EnclaveServiceServer() : enclave_(nullptr) {}

  TeeErrorCode InitServer(EnclaveInstance* enclave);
  TeeErrorCode RunServer();

 private:
  EnclaveServiceServerImpl service_impl_;
  EnclaveInstance* enclave_;
  std::string rpc_server_;
  std::string rpc_port_;
  std::string ssl_cert_;
  std::string ssl_key_;
  std::string ssl_ca_;
};

}  // namespace untrusted
}  // namespace tee

#endif  // ENCLAVE_SERVICE_UNTRUSTED_UNTRUSTED_ENCLAVE_SERVICE_SERVER_H_
