#include <memory>
#include <string>
#include <vector>

#include "tee/common/aes.h"
#include "tee/common/challenger.h"
#include "tee/common/protobuf.h"
#include "tee/common/rsa.h"

#include "tee/untrusted/enclave/untrusted_enclave.h"
#include "tee/untrusted/ra/untrusted_challenger.h"
#include "tee/untrusted/ra/untrusted_ias.h"
#include "tee/untrusted/untrusted_config.h"
#include "tee/untrusted/untrusted_pbcall.h"
#include "tee/untrusted/utils/untrusted_fs.h"
#include "tee/untrusted/utils/untrusted_json.h"

#include "untrusted/untrusted_enclave_service_client.h"
#include "untrusted/untrusted_enclave_service_server.h"

#include "./enclave_service_u.h"

namespace tee {
namespace untrusted {

TeeErrorCode EnclaveServiceServerImpl::CheckRaAuthentication(
    const RaReportAuthentication& auth) {
  TEE_CHECK_RETURN(VerifyRaReport(auth.public_key(), auth.ias_report()));
  return TEE_SUCCESS;
}

TeeErrorCode EnclaveServiceServerImpl::GetServerRaAuthentication(
    RaReportAuthentication* auth) {
  auth->mutable_ias_report()->CopyFrom(enclave_->GetLocalIasReport());
  auth->set_public_key(enclave_->GetPublicKey());
  return TEE_SUCCESS;
}

Status EnclaveServiceServerImpl::TeeRunRemote(
    ServerContext* context, const PbTeeRunRemoteRequest* request,
    PbTeeRunRemoteResponse* response) {
  GRPC_INTERFACE_ENTER_DEBUG();

  // Check the RA report or signature authentication
  if (CheckRaAuthentication(request->ra_auth()) != TEE_SUCCESS) {
    RETURN_ERROR("Fail to verify the authentication");
  }

  // Call the trusted function
  TeeErrorCode ret = enclave_->TeeRun(request->function_name(), *request,
                                      response->mutable_result());
  if (ret != TEE_SUCCESS) {
    RETURN_ERROR("Fail to run trusted function");
  }

  // Prepare response with server's RA report and public key
  RaReportAuthentication* server_ra_auth = response->mutable_ra_auth();
  if (GetServerRaAuthentication(server_ra_auth) != TEE_SUCCESS) {
    RETURN_ERROR("Fail to load server RA report");
  }

  return Status::OK;
}

TeeErrorCode EnclaveServiceServerImpl::Initialize(EnclaveInstance* enclave) {
  enclave_ = enclave;

  // Check the server IAS report
  if (enclave_->GetLocalIasReport().b64_signature().empty()) {
    TEE_LOG_ERROR("Invalid server enclave identity public key");
    return TEE_ERROR_ENCLAVE_NOTINITIALIZED;
  }

  // Check the server identity publick key
  if (enclave_->GetPublicKey().empty()) {
    TEE_LOG_ERROR("Invalid server enclave identity public key");
    return TEE_ERROR_ENCLAVE_NOTINITIALIZED;
  }
  return TEE_SUCCESS;
}

TeeErrorCode EnclaveServiceServer::InitServer(EnclaveInstance* enclave) {
  // Set and check the enclave instance
  enclave_ = enclave;
  if (enclave_ == 0) {
    TEE_LOG_ERROR("Invalid enclave ID on which to run RPC server");
    return TEE_ERROR_PARAMETERS;
  }

  // Load configurations
  rpc_port_ = GET_CONF_STR(kConfRpcPort);

  std::string cert = GET_CONF_STR(kConfRpcCertPath);
  std::string key = GET_CONF_STR(kConfRpcKeyPath);
  std::string ca = GET_CONF_STR(kConfRpcCaPath);

  TeeErrorCode ret = tee::untrusted::FsReadString(cert, &ssl_cert_);
  if (ret != TEE_SUCCESS) {
    TEE_LOG_ERROR("Fail to load ssl cert file: %s", cert.c_str());
    return ret;
  }
  ret = tee::untrusted::FsReadString(key, &ssl_key_);
  if (ret != TEE_SUCCESS) {
    TEE_LOG_ERROR("Fail to load ssl key file: %s", key.c_str());
    return ret;
  }
  ret = tee::untrusted::FsReadString(ca, &ssl_ca_);
  if (ret != TEE_SUCCESS) {
    TEE_LOG_ERROR("Fail to load ssl ca file: %s", ca.c_str());
    return ret;
  }

  // Always generate new IAS report when start the service
  ret = enclave_->FetchIasReport(false);
  if (ret != TEE_SUCCESS) {
    TEE_LOG_ERROR("Fail to initialize the local RA report: 0x%x", ret);
    return ret;
  }

  // Try to initialize the rpc server implement instance.
  // Must before SyncIdentity because we will use the server ias_report
  // which is initialized in this process.
  ret = service_impl_.Initialize(enclave_);
  if (ret != TEE_SUCCESS) {
    TEE_LOG_ERROR("Fail to initialize the RPC server implement instance");
    return ret;
  }

  return TEE_SUCCESS;
}

TeeErrorCode EnclaveServiceServer::RunServer() {
  // Listen on the given address with authentication mechanism.
  SslServerCredentialsOptions::PemKeyCertPair keycert{ssl_key_, ssl_cert_};
  grpc::SslServerCredentialsOptions ssl_opts;
  ssl_opts.pem_root_certs = ssl_ca_;
  ssl_opts.pem_key_cert_pairs.push_back(keycert);
  ssl_opts.client_certificate_request =
      GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY;

  ServerBuilder builder;
  std::string server_addr = "0.0.0.0:" + rpc_port_;
  builder.AddListeningPort(server_addr, grpc::SslServerCredentials(ssl_opts));
  // Register "EnclaveServiceServerImpl" as the instance through which we'll
  // communicate with clients. In this case it corresponds to an
  // *synchronous* service.
  builder.RegisterService(&service_impl_);
  // Finally assemble the server.
  std::unique_ptr<Server> server(builder.BuildAndStart());
  TEE_LOG_INFO("Server listening on %s", server_addr.c_str());

  // Wait for the server to shutdown. Note that some other thread must be
  // responsible for shutting down the server for this call to ever return.
  server->Wait();
  return TEE_SUCCESS;
}

}  // namespace untrusted
}  // namespace tee
