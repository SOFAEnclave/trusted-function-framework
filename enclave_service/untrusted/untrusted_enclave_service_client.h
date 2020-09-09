#ifndef ENCLAVE_SERVICE_UNTRUSTED_UNTRUSTED_ENCLAVE_SERVICE_CLIENT_H_
#define ENCLAVE_SERVICE_UNTRUSTED_UNTRUSTED_ENCLAVE_SERVICE_CLIENT_H_

#include <grpcpp/grpcpp.h>

#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#include "tee/common/error.h"
#include "tee/common/log.h"
#include "tee/common/type.h"
#include "tee/untrusted/enclave/untrusted_enclave.h"

#include "./enclave_service.grpc.pb.h"
#include "./enclave_service.pb.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

using tee::EnclaveService;
using tee::IasReport;
using tee::PbGenericRequest;
using tee::PbGenericResponse;
using tee::PbTeeRunRemoteRequest;
using tee::PbTeeRunRemoteResponse;
using tee::RaReportAuthentication;

namespace tee {
namespace untrusted {

constexpr int kTimeoutMs = 4000;

class EnclaveServiceClient {
 public:
  explicit EnclaveServiceClient(EnclaveInstance* enclave);
  ~EnclaveServiceClient() {}

  std::unique_ptr<EnclaveService::Stub> PrepareSecureStub(
      const std::string& ep, const std::string& ca, const std::string& key,
      const std::string& cert);

  TeeErrorCode TeeRunRemote(PbTeeRunRemoteRequest* request,
                            PbTeeRunRemoteResponse* response);

 private:
  TeeErrorCode GetClientRaAuthentication(RaReportAuthentication* auth);
  bool WaitForChannelReady(std::shared_ptr<Channel> channel);
  TeeErrorCode CheckStatusCode(const Status& status);

  EnclaveInstance* enclave_;
  std::unique_ptr<EnclaveService::Stub> stub_;
};

}  // namespace untrusted
}  // namespace tee

#endif  // ENCLAVE_SERVICE_UNTRUSTED_UNTRUSTED_ENCLAVE_SERVICE_CLIENT_H_
