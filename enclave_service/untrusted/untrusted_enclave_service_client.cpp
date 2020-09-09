#include <grpcpp/grpcpp.h>

#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#include "tee/common/error.h"
#include "tee/common/log.h"
#include "tee/common/type.h"
#include "tee/untrusted/untrusted_config.h"
#include "tee/untrusted/utils/untrusted_fs.h"

#include "untrusted/untrusted_enclave_service_client.h"

namespace tee {
namespace untrusted {

EnclaveServiceClient::EnclaveServiceClient(EnclaveInstance* enclave) {
  // Prepare the client stub based on secure channel
  std::string server = GET_CONF_STR(kConfRpcServer);
  std::string port = GET_CONF_STR(kConfRpcPort);
  std::string ca = GetFsString(GET_CONF_STR(kConfRpcCaPath));
  std::string key = GetFsString(GET_CONF_STR(kConfRpcKeyPath));
  std::string cert = GetFsString(GET_CONF_STR(kConfRpcCertPath));
  std::string endpoint = server + ":" + port;
  stub_ = PrepareSecureStub(endpoint, ca, key, cert);

  // Initialize the enclave IAS report if it's not ready
  enclave_ = enclave;
  if (enclave_->GetLocalIasReport().b64_signature().empty()) {
    TEE_LOG_INFO("Fetch IAS report when initialize enclave service client");
    enclave_->FetchIasReport();
  }
}

bool EnclaveServiceClient::WaitForChannelReady(
    std::shared_ptr<grpc::Channel> channel) {
  using std::chrono::system_clock;
  grpc_connectivity_state state;
  while ((state = channel->GetState(true)) != GRPC_CHANNEL_READY) {
    system_clock::time_point now = system_clock::now();
    system_clock::time_point end = now + std::chrono::milliseconds(kTimeoutMs);
    if (!channel->WaitForStateChange(state, end)) {
      return false;
    }
  }
  return true;
}

std::unique_ptr<EnclaveService::Stub> EnclaveServiceClient::PrepareSecureStub(
    const std::string& ep, const std::string& ca, const std::string& key,
    const std::string& cert) {
  grpc::SslCredentialsOptions ssl_opts;
  ssl_opts.pem_root_certs = ca;
  ssl_opts.pem_private_key = key;
  ssl_opts.pem_cert_chain = cert;

  auto ssl_creds = grpc::SslCredentials(ssl_opts);
  auto channel_args = grpc::ChannelArguments();

  // For our generated certificates CN.
  constexpr char kSelfSignedCN[] = "enclave-service";
  channel_args.SetSslTargetNameOverride(kSelfSignedCN);

  // Return a channel using the credentials created in the previous step.
  auto channel = grpc::CreateCustomChannel(ep, ssl_creds, channel_args);

  if (!WaitForChannelReady(channel))
    throw std::runtime_error("Secure channel not ready.");

  return EnclaveService::NewStub(channel);
}

TeeErrorCode EnclaveServiceClient::CheckStatusCode(const Status& status) {
  if (!status.ok()) {
    TEE_LOG_ERROR("Status Code: %d", status.error_code());
    TEE_LOG_ERROR("Error Message: %s", status.error_message().c_str());
    return TEE_ERROR_UNEXPECTED;
  }
  return TEE_SUCCESS;
}

TeeErrorCode EnclaveServiceClient::GetClientRaAuthentication(
    RaReportAuthentication* auth) {
  auth->mutable_ias_report()->CopyFrom(enclave_->GetLocalIasReport());
  auth->set_public_key(enclave_->GetPublicKey());
  return TEE_SUCCESS;
}

TeeErrorCode EnclaveServiceClient::TeeRunRemote(
    PbTeeRunRemoteRequest* request, PbTeeRunRemoteResponse* response) {
  ClientContext context;
  context.set_deadline(std::chrono::system_clock::now() +
                       std::chrono::milliseconds(kTimeoutMs));

  TEE_CHECK_RETURN(GetClientRaAuthentication(request->mutable_ra_auth()));
  Status status = stub_->TeeRunRemote(&context, *request, response);

  return CheckStatusCode(status);
}

}  // namespace untrusted
}  // namespace tee
