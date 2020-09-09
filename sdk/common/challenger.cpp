#include <cstring>
#include <string>
#include <vector>

#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/pem.h"

#include "tee/common/bytes.h"
#include "tee/common/challenger.h"
#include "tee/common/error.h"
#include "tee/common/log.h"
#include "tee/common/rsa.h"
#include "tee/common/scope.h"
#include "tee/common/type.h"

#define CHECK_PARAM_NULL(p)             \
  do {                                  \
    if ((p) == nullptr || ((p) == 0)) { \
      TEE_LOG_ERROR("NULL pointer");    \
      return TEE_ERROR_PARAMETERS;      \
    }                                   \
  } while (0)

namespace tee {
namespace common {

// Intel official IAS CA
static const char* kAttestationSigningCACert = R"(
-----BEGIN CERTIFICATE-----
MIIFSzCCA7OgAwIBAgIJANEHdl0yo7CUMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV
BAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV
BAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0
YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwIBcNMTYxMTE0MTUzNzMxWhgPMjA0OTEy
MzEyMzU5NTlaMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwL
U2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQD
DCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwggGiMA0G
CSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCfPGR+tXc8u1EtJzLA10Feu1Wg+p7e
LmSRmeaCHbkQ1TF3Nwl3RmpqXkeGzNLd69QUnWovYyVSndEMyYc3sHecGgfinEeh
rgBJSEdsSJ9FpaFdesjsxqzGRa20PYdnnfWcCTvFoulpbFR4VBuXnnVLVzkUvlXT
L/TAnd8nIZk0zZkFJ7P5LtePvykkar7LcSQO85wtcQe0R1Raf/sQ6wYKaKmFgCGe
NpEJUmg4ktal4qgIAxk+QHUxQE42sxViN5mqglB0QJdUot/o9a/V/mMeH8KvOAiQ
byinkNndn+Bgk5sSV5DFgF0DffVqmVMblt5p3jPtImzBIH0QQrXJq39AT8cRwP5H
afuVeLHcDsRp6hol4P+ZFIhu8mmbI1u0hH3W/0C2BuYXB5PC+5izFFh/nP0lc2Lf
6rELO9LZdnOhpL1ExFOq9H/B8tPQ84T3Sgb4nAifDabNt/zu6MmCGo5U8lwEFtGM
RoOaX4AS+909x00lYnmtwsDVWv9vBiJCXRsCAwEAAaOByTCBxjBgBgNVHR8EWTBX
MFWgU6BRhk9odHRwOi8vdHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9jb250ZW50
L0NSTC9TR1gvQXR0ZXN0YXRpb25SZXBvcnRTaWduaW5nQ0EuY3JsMB0GA1UdDgQW
BBR4Q3t2pn680K9+QjfrNXw7hwFRPDAfBgNVHSMEGDAWgBR4Q3t2pn680K9+Qjfr
NXw7hwFRPDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADANBgkq
hkiG9w0BAQsFAAOCAYEAeF8tYMXICvQqeXYQITkV2oLJsp6J4JAqJabHWxYJHGir
IEqucRiJSSx+HjIJEUVaj8E0QjEud6Y5lNmXlcjqRXaCPOqK0eGRz6hi+ripMtPZ
sFNaBwLQVV905SDjAzDzNIDnrcnXyB4gcDFCvwDFKKgLRjOB/WAqgscDUoGq5ZVi
zLUzTqiQPmULAQaB9c6Oti6snEFJiCQ67JLyW/E83/frzCmO5Ru6WjU4tmsmy8Ra
Ud4APK0wZTGtfPXU7w+IBdG5Ez0kE1qzxGQaL4gINJ1zMyleDnbuS8UicjJijvqA
152Sq049ESDz+1rRGc2NVEqh1KaGXmtXvqxXcTB+Ljy5Bw2ke0v8iGngFBPqCTVB
3op5KBG3RjbF6RRSzwzuWfL7QErNC8WEy5yDVARzTA5+xmBc388v9Dm21HGfcC8O
DD+gT9sSpssq0ascmvH49MOgjt1yoysLtdCtJW/9FZpoOypaHx0R+mJTLwPXVMrv
DaVzWh5aiEx+idkSGMnX
-----END CERTIFICATE-----
)";

constexpr char kQuoteStatusOK[] = "OK";
constexpr char kQuoteStatusConfigurationNeeded[] = "CONFIGURATION_NEEDED";
constexpr char kQuoteStatusOutOfDate[] = "GROUP_OUT_OF_DATE";

RaChallenger::RaChallenger(const std::string& public_key,
                           const tee::EnclaveMatchRules& verify_rules)
    : public_key_(public_key), rules_(verify_rules), enclave_(nullptr) {}

// The report response check
TeeErrorCode RaChallenger::VerifyReport(const tee::IasReport& ias_report) {
  TEE_CHECK_RETURN(CheckReportSignature(ias_report));
  TEE_CHECK_RETURN(CheckReportQuoteStatus(ias_report));

  // If match any rule entry, return success.
  TeeErrorCode ret = TEE_ERROR_GENERIC;
  for (int i = 0; i < rules_.entries_size(); i++) {
    ELOG_INFO("Verify RA report quote by rule entry [%d]", i);
    enclave_ = CCAST(tee::EnclaveInformation*, &rules_.entries()[i]);
    if ((ret = CheckReportQuote(ias_report)) == TEE_SUCCESS) {
      return TEE_SUCCESS;
    }
  }
  return ret;
}

TeeErrorCode RaChallenger::CheckReportSignature(
    const tee::IasReport& ias_report) {
  std::string b64_sig = ias_report.b64_signature();
  std::string cert = ias_report.signing_cert();
  std::string body = ias_report.response_body();

  ELOG_BUFFER("[b64sig]", b64_sig.data(), b64_sig.length());
  if (b64_sig.empty() || cert.empty() || body.empty()) {
    ELOG_ERROR("Invalid IAS report response content!");
    return TEE_ERROR_PARAMETERS;
  }

  BIO* root_cert = BIO_new(BIO_s_mem());
  BIO_puts(root_cert, kAttestationSigningCACert);
  ON_SCOPE_EXIT([&root_cert] { BIO_free(root_cert); });

  // Load intel CA
  X509* cert_ra = PEM_read_bio_X509(root_cert, NULL, NULL, NULL);
  if (cert_ra == NULL) {
    ELOG_ERROR("Fail to read Intel X509 CA pem certificate");
    return TEE_ERROR_RA_LOAD_CA_CERT;
  }
  ON_SCOPE_EXIT([&cert_ra] { X509_free(cert_ra); });

  // Build Cert-Chain
  const char* certchain = cert.c_str();
  uint32_t certchain_len = SCAST(uint32_t, strlen(certchain));
  X509_STORE* store = X509_STORE_new();
  X509_STORE_CTX* ctx = X509_STORE_CTX_new();
  X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK_ALL);
  BIO* bio_cert_chain = BIO_new_mem_buf(certchain, certchain_len);
  STACK_OF(X509)* recips = sk_X509_new_null();
  STACK_OF(X509_INFO)* inf =
      PEM_X509_INFO_read_bio(bio_cert_chain, NULL, NULL, NULL);
  ON_SCOPE_EXIT([&inf, &recips, &ctx, &store, &bio_cert_chain] {
    if (inf) {
      sk_X509_INFO_pop_free(inf, X509_INFO_free);
    }
    if (recips) {
      sk_X509_free(recips);
    }
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    BIO_free(bio_cert_chain);
  });

  if (inf == NULL || recips == NULL) {
    ELOG_ERROR("bad bio cert chain info");
    return TEE_ERROR_RA_INVALID_AS_CERTS;
  }

  // STEP: verify signing cert via intel CA
  if (X509_STORE_CTX_init(ctx, store, cert_ra, NULL) != 1) {
    ELOG_ERROR("init store ctx fail");
    return TEE_ERROR_RA_VERIFY_SIG_INIT;
  }

  for (int i = 0; i < sk_X509_INFO_num(inf); i++) {
    X509_INFO* info = sk_X509_INFO_value(inf, i);
    if (info && info->x509) {
      sk_X509_push(recips, info->x509);
    }
  }

  X509_STORE_CTX_trusted_stack(ctx, recips);

  if (X509_verify_cert(ctx) != 1) {
    ELOG_ERROR("Fail to verify IAS_signing certificate");
    return TEE_ERROR_RA_VERIFY_CERT_DENIED;
  }

  // STEP: verify signature on response via signing cert
  BIO* bio_sp = BIO_new(BIO_s_mem());
  BIO_write(bio_sp, certchain, certchain_len);
  ON_SCOPE_EXIT([&bio_sp] { BIO_free_all(bio_sp); });

  X509* cert_sp = PEM_read_bio_X509(bio_sp, NULL, NULL, NULL);
  if (cert_sp == NULL) {
    ELOG_ERROR("Cannot read x509 from signing cert");
    return TEE_ERROR_RA_VERIFY_LOAD_CERT;
  }
  ON_SCOPE_EXIT([&cert_sp] { X509_free(cert_sp); });

  EVP_PKEY* pubkey_sp = X509_get_pubkey(cert_sp);
  if (pubkey_sp == NULL) {
    ELOG_ERROR("Cannot get EVP_PKEY from ias_signing_cert");
    return TEE_ERROR_RA_VERIFY_GET_PUBKEY;
  }
  ON_SCOPE_EXIT([&pubkey_sp] { EVP_PKEY_free(pubkey_sp); });

  RSA* rsa = EVP_PKEY_get1_RSA(pubkey_sp);
  if (rsa == NULL) {
    ELOG_ERROR("Cannot get RSA from EVP_PKEY");
    return TEE_ERROR_RA_VERIFY_GET_RSAKEY;
  }
  ON_SCOPE_EXIT([&rsa] { RSA_free(rsa); });

  // STEP: begin verify response body
  tee::common::DataBytes body_hash(body);
  if (body_hash.ToSHA256().empty()) {
    ELOG_ERROR("Fail to compute SHA256 for response");
    return TEE_ERROR_CRYPTO_SHA256;
  }
  ELOG_BUFFER("ReportResponse HASH", body_hash.data(), body_hash.size());

  tee::common::DataBytes signature(b64_sig);
  signature.FromBase64().Void();
  ELOG_BUFFER("SIGNATURE", signature.data(), signature.size());

  if (OPENSSL_SUCCESS != RSA_verify(NID_sha256, body_hash.data(),
                                    body_hash.size(), signature.data(),
                                    SCAST(uint32_t, signature.size()), rsa)) {
    ELOG_ERROR("Signature verification failed: 0x%x", ERR_get_error());
    return TEE_ERROR_RA_VERIFY_SIGNATURE;
  }

  ELOG_DEBUG("Verify Signature Successfully!");
  return TEE_SUCCESS;
}

TeeErrorCode RaChallenger::CheckReportQuoteStatus(
    const tee::IasReport& ias_report) {
  std::string quote_status = ias_report.quote_status();
  std::string advisory_url = ias_report.advisory_url();
  std::string advisory_ids = ias_report.advisory_ids();
  if (quote_status.empty()) {
    ELOG_ERROR("No quote status in IAS report reponse!");
    return TEE_ERROR_PARAMETERS;
  }

  if (quote_status == kQuoteStatusOK) {
    ELOG_DEBUG("Verify quote status: OK");
  } else if ((quote_status == kQuoteStatusConfigurationNeeded) ||
             (quote_status == kQuoteStatusOutOfDate)) {
    ELOG_WARN("Verify quote status: %s", quote_status.c_str());
    if (!advisory_url.empty()) {
      ELOG_WARN("AdvisoryUrl: %s", advisory_url.c_str());
    }
    if (!advisory_ids.empty()) {
      ELOG_WARN("AdvisoryIDs: %s", advisory_ids.c_str());
    }
  } else {
    ELOG_ERROR("Verify quote status: %s", quote_status.c_str());
    return TEE_ERROR_RA_VERIFY_QUOTE_STATUS;
  }
  return TEE_SUCCESS;
}

TeeErrorCode RaChallenger::CheckReportQuote(const tee::IasReport& ias_report) {
  std::string quote_b64 = ias_report.b64_quote_body();
  ELOG_DEBUG("Quote: %s", quote_b64.c_str());
  if (quote_b64.empty()) {
    ELOG_ERROR("No quote body in IAS report response!");
    return TEE_ERROR_PARAMETERS;
  }

  tee::common::DataBytes quote(quote_b64);
  quote.FromBase64().Void();
  ELOG_BUFFER("QUOTE", quote.data(), quote.size());

  TeeErrorCode ret = TEE_ERROR_GENERIC;
  sgx_quote_t* pquote = RCAST(sgx_quote_t*, quote.data());
  if ((ret = CheckQuoteSignType(pquote)) != TEE_SUCCESS) {
    return ret;
  }
  if ((ret = CheckQuoteSPID(pquote)) != TEE_SUCCESS) {
    return ret;
  }
  if ((ret = CheckQuoteReportBody(pquote)) != TEE_SUCCESS) {
    return ret;
  }
  return TEE_SUCCESS;
}

// The quote in response check:
//    typedef struct _quote_t {
//        uint16_t            version;
//        uint16_t            sign_type;
//        sgx_epid_group_id_t epid_group_id;
//        sgx_isv_svn_t       qe_svn;
//        sgx_isv_svn_t       pce_svn;
//        uint32_t            xeid;
//        sgx_basename_t      basename;
//        sgx_report_body_t   report_body;
//        uint32_t            signature_len;
//        uint8_t             signature[];
//    } sgx_quote_t;
TeeErrorCode RaChallenger::CheckQuoteSignType(sgx_quote_t* pquote) {
  CHECK_PARAM_NULL(pquote);

  constexpr uint16_t type = SGX_LINKABLE_SIGNATURE;
  if (pquote->sign_type != type) {
    ELOG_ERROR("Unexpected sign type %d", pquote->sign_type);
    return TEE_ERROR_RA_VERIFY_SIGNING_TYPE;
  }
  return TEE_SUCCESS;
}

TeeErrorCode RaChallenger::CheckQuoteSPID(sgx_quote_t* pquote) {
  CHECK_PARAM_NULL(pquote);

  if (enclave_->hex_spid().empty()) {
    ELOG_WARN("No SPID is specified to be verified, be careful!");
    return TEE_SUCCESS;
  }

  tee::common::DataBytes spid(enclave_->hex_spid());
  if (!spid.FromHexStr().Compare(pquote->basename.name, sizeof(sgx_spid_t))) {
    ELOG_ERROR("Unexpected SPID name!");
    return TEE_ERROR_RA_VERIFY_SPID_NAME;
  }
  ELOG_DEBUG("Verify the SPID successfully");
  return TEE_SUCCESS;
}

TeeErrorCode RaChallenger::CheckQuoteReportBody(sgx_quote_t* pquote) {
  CHECK_PARAM_NULL(pquote);

  TeeErrorCode ret = TEE_ERROR_GENERIC;
  sgx_report_body_t* report_body = &(pquote->report_body);

  if ((ret = CheckReportBodyMRSIGNER(report_body)) != TEE_SUCCESS) {
    return ret;
  }
  if ((ret = CheckReportBodyMRENCLAVE(report_body)) != TEE_SUCCESS) {
    return ret;
  }
  if ((ret = CheckReportBodyAttributes(report_body)) != TEE_SUCCESS) {
    return ret;
  }
  if ((ret = CheckReportBodyIsvProd(report_body)) != TEE_SUCCESS) {
    return ret;
  }
  if ((ret = CheckReportBodyIsvSvn(report_body)) != TEE_SUCCESS) {
    return ret;
  }
  if ((ret = CheckReportBodyUserData(report_body)) != TEE_SUCCESS) {
    return ret;
  }

  return TEE_SUCCESS;
}

// The report_body in quote check:
//    typedef struct _report_body_t {
//        sgx_cpu_svn_t           cpu_svn;
//        sgx_misc_select_t       misc_select;
//        uint8_t                 reserved1[28];
//        sgx_attributes_t        attributes;
//        sgx_measurement_t       mr_enclave;
//        uint8_t                 reserved2[32];
//        sgx_measurement_t       mr_signer;
//        uint8_t                 reserved3[96];
//        sgx_prod_id_t           isv_prod_id;
//        sgx_isv_svn_t           isv_svn;
//        uint8_t                 reserved4[60];
//        sgx_report_data_t       report_data;
//    } sgx_report_body_t;
TeeErrorCode RaChallenger::CheckReportBodyMRENCLAVE(
    sgx_report_body_t* report_body) {
  CHECK_PARAM_NULL(report_body);
  if (enclave_->hex_mrenclave().empty()) {
    ELOG_WARN("No MRENCLAVE is specified to be verified, be careful!");
    return TEE_SUCCESS;
  }

  tee::common::DataBytes mrenclave(RCAST(uint8_t*, &(report_body->mr_enclave)),
                                   sizeof(sgx_measurement_t));
  if (!mrenclave.ToHexStr().Compare(enclave_->hex_mrenclave())) {
    ELOG_ERROR("Fail to verify the MRENCLAVE, be careful!");
    ELOG_ERROR("Actual   MRENCLAVE: %s", mrenclave.GetStr().c_str());
    ELOG_DEBUG("Expected MRENCLAVE: %s", enclave_->hex_mrenclave().c_str());
    return TEE_ERROR_RA_VERIFY_MRENCLAVE;
  }
  ELOG_DEBUG("Verify the MRENCLAVE successfully");
  return TEE_SUCCESS;
}

TeeErrorCode RaChallenger::CheckReportBodyMRSIGNER(
    sgx_report_body_t* report_body) {
  CHECK_PARAM_NULL(report_body);

  tee::common::DataBytes mrsigner(RCAST(uint8_t*, &(report_body->mr_signer)),
                                  sizeof(sgx_measurement_t));
  if (!mrsigner.ToHexStr().Compare(enclave_->hex_mrsigner())) {
    ELOG_ERROR("Fail to verify the MRSIGNER, be careful!");
    ELOG_ERROR("Actual   MRSIGNER: %s", mrsigner.GetStr().c_str());
    ELOG_DEBUG("Expected MRSIGNER: %s", enclave_->hex_mrsigner().c_str());
    return TEE_ERROR_RA_VERIFY_MRSIGNER;
  }
  ELOG_DEBUG("Verify the MRSIGNER successfully");
  return TEE_SUCCESS;
}

TeeErrorCode RaChallenger::CheckReportBodyAttributes(
    sgx_report_body_t* report_body) {
  CHECK_PARAM_NULL(report_body);
#if !defined(NOLOG) && defined(DEBUG)
  uint64_t flags = report_body->attributes.flags;
  uint64_t xfrm = report_body->attributes.xfrm;
  ELOG_DEBUG("Verify the Quote attribute: %lx/%lx[ignored]", flags, xfrm);
#endif
  return TEE_SUCCESS;
}

TeeErrorCode RaChallenger::CheckReportBodyIsvProd(
    sgx_report_body_t* report_body) {
  CHECK_PARAM_NULL(report_body);
  if (enclave_->hex_prod_id().empty()) {
    ELOG_WARN("No ProdID is specified to be verified, be careful");
    return TEE_SUCCESS;
  }

  // Need to verify the ProdID if it's not empty.
  int prodid = report_body->isv_prod_id;
  int prodid_expected = std::stoi(enclave_->hex_prod_id());
  if (prodid_expected != prodid) {
    ELOG_ERROR("Fail to verify the ISV ProdID");
    ELOG_ERROR("Actual   ProdID: %d", prodid);
    ELOG_DEBUG("Expected ProdID: %d", prodid_expected);
    return TEE_ERROR_RA_VERIFY_ISV_PORDID;
  }
  ELOG_DEBUG("Verify the ProdID successfully");
  return TEE_SUCCESS;
}

TeeErrorCode RaChallenger::CheckReportBodyIsvSvn(
    sgx_report_body_t* report_body) {
  CHECK_PARAM_NULL(report_body);
  if (enclave_->hex_min_isvsvn().empty()) {
    ELOG_WARN("No SVN is specified to be verified, be careful");
    return TEE_SUCCESS;
  }

  // Need to verify the SVN if it's not empty.
  int svn = report_body->isv_svn;
  int svn_min = std::stoi(enclave_->hex_min_isvsvn());
  if (svn < svn_min) {
    ELOG_ERROR("Fail to verify the ISV SVN");
    ELOG_ERROR("Actual  ISVSVN: %d", svn);
    ELOG_DEBUG("Minimal ISVSVN: %d", svn_min);
    return TEE_ERROR_RA_VERIFY_ISV_SVN;
  }
  ELOG_DEBUG("Verify the ISV SVN successfully");
  return TEE_SUCCESS;
}

TeeErrorCode RaChallenger::CheckReportBodyUserData(
    sgx_report_body_t* report_body) {
  CHECK_PARAM_NULL(report_body);

  if (public_key_.empty()) {
    ELOG_ERROR("Invalid public key to verify report");
    return TEE_ERROR_PARAMETERS;
  }

  // Get public key SHA256 hash value
  size_t report_data_len = sizeof(sgx_report_data_t);
  tee::common::DataBytes report_data(public_key_);
  if (report_data.ToSHA256().empty()) {
    return report_data.GetError();
  }

  // Extern the data buffer with user data or zero
  std::string userdata = enclave_->hex_user_data();
  if (!userdata.empty()) {
    report_data.insert(report_data.end(), userdata.begin(), userdata.end());
  }
  report_data.resize(report_data_len, 0);

  // Compare with the total report data buffer
  if (!report_data.Compare(report_body->report_data.d, report_data_len)) {
    ELOG_BUFFER("ReportDataActual", report_body->report_data.d,
                report_data_len);
    ELOG_BUFFER("ReportDataExpected", report_data.data(), report_data.size());
    ELOG_ERROR("Fail to verify the report data, be careful!");
    return TEE_ERROR_RA_VERIFY_USER_DATA;
  }

  ELOG_DEBUG("Verify the report data successfully");
  return TEE_SUCCESS;
}

TeeErrorCode RaChallenger::GetEnclaveInfo(const tee::IasReport& ias_report,
                                          tee::EnclaveInformation* info) {
  ELOG_DEBUG("Get enclave information from RA report ...");
  std::string quote_b64 = ias_report.b64_quote_body();
  if (quote_b64.empty()) {
    ELOG_ERROR("No quote body in IAS report response!");
    return TEE_ERROR_PARAMETERS;
  }

  tee::common::DataBytes quote(quote_b64);
  if (quote.FromBase64().size() == 0) {
    ELOG_ERROR("Fail to decrypt the base64 quote");
    return TEE_ERROR_PARAMETERS;
  }

  sgx_quote_t* pquote = RCAST(sgx_quote_t*, quote.data());
  sgx_report_body_t* report_body = &(pquote->report_body);
  tee::common::DataBytes spid(RCAST(uint8_t*, pquote->basename.name),
                              sizeof(sgx_spid_t));
  tee::common::DataBytes userdata(RCAST(uint8_t*, report_body->report_data.d),
                                  sizeof(sgx_report_data_t));
  tee::common::DataBytes mrsigner(RCAST(uint8_t*, report_body->mr_signer.m),
                                  sizeof(sgx_measurement_t));
  tee::common::DataBytes mrenclave(RCAST(uint8_t*, report_body->mr_enclave.m),
                                   sizeof(sgx_measurement_t));
  int prodid = report_body->isv_prod_id;
  int svn = report_body->isv_svn;

  info->set_hex_spid(spid.ToHexStr().GetStr());
  info->set_hex_user_data(userdata.ToHexStr().GetStr());
  info->set_hex_mrsigner(mrsigner.ToHexStr().GetStr());
  info->set_hex_mrenclave(mrenclave.ToHexStr().GetStr());
  info->set_hex_prod_id(std::to_string(prodid));
  info->set_hex_min_isvsvn(std::to_string(svn));
  return TEE_SUCCESS;
}

}  // namespace common
}  // namespace tee
