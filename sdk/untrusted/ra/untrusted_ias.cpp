#include <string>
#include <vector>

#include "tee/common/bytes.h"
#include "tee/common/error.h"
#include "tee/common/log.h"
#include "tee/common/type.h"

#include "tee/untrusted/ra/untrusted_ias.h"
#include "tee/untrusted/untrusted_config.h"
#include "tee/untrusted/utils/untrusted_fs.h"

#include "untrusted/utils/untrusted_json_internal.h"

namespace tee {
namespace untrusted {

constexpr char kStrEpidPseudonym[] = "epidPseudonym";
constexpr char kStrQuoteStatus[] = "isvEnclaveQuoteStatus";
constexpr char kStrPlatform[] = "platformInfoBlob";
constexpr char kStrQuoteBody[] = "isvEnclaveQuoteBody";
constexpr char kStrHeaderSig[] = "x-iasreport-signature:";
constexpr char kStrHeaderSigAk[] = "X-IASReport-Signature:";
constexpr char kStrHeaderCa[] = "x-iasreport-signing-certificate:";
constexpr char kStrHeaderCaAk[] = "X-IASReport-Signing-Certificate:";
constexpr char kStrHeaderAdvisoryURL[] = "advisory-url:";
constexpr char kStrHeaderAdvisoryIDs[] = "advisory-ids:";

typedef struct {
  std::string b64_sigrl;
} IasSigrl;

std::string RaIasClient::GetIasUrl() {
  std::string url = GET_CONF_STR(kConfIasURL);
  if (url.empty()) {
    const char* purl = getenv("AECS_IAS_URL");
    if (purl) {
      url.assign(purl);
    }
  }
  return url;
}

std::string RaIasClient::GetHeaderValue(const std::string& header) {
  // Name: value\r\n
  std::size_t pos_start = header.find_first_of(" ");
  std::size_t pos_end = header.find_first_of("\r\n");
  if ((pos_start != std::string::npos) && (pos_end != std::string::npos)) {
    return header.substr(pos_start + 1, pos_end - pos_start - 1);
  } else {
    return std::string("");
  }
}

size_t RaIasClient::ParseSigrlResponseBody(const char* contents, size_t size,
                                           size_t nmemb, void* response) {
  size_t content_length = size * nmemb;
  IasSigrl* sigrl = RCAST(IasSigrl*, response);

  if (content_length == 0) {
    sigrl->b64_sigrl.clear();
    TEE_LOG_DEBUG("GetSigRL: Empty");
  } else {
    sigrl->b64_sigrl.assign(contents, content_length);
    TEE_LOG_DEBUG("GetSigRL: %s", sigrl->b64_sigrl.c_str());
  }
  return content_length;
}

size_t RaIasClient::ParseSigrlResponseHeader(const char* contents, size_t size,
                                             size_t nmemb, void* response) {
  size_t len = size * nmemb;
  TEE_UNREFERENCED_PARAMETER(response);
  TEE_UNREFERENCED_PARAMETER(contents);
#if !defined(NOLOG) && defined(DEBUG)
  const char* header = contents;
  TEE_LOG_DEBUG("IAS Get SigRL %s", header);
#endif
  return len;
}

size_t RaIasClient::ParseReportResponseBody(const char* contents, size_t size,
                                            size_t nmemb, void* response) {
  const char* body = contents;
  size_t content_length = size * nmemb;
  IasReport* report = RCAST(IasReport*, response);

  // The JSON response body maybe will be split into multi times
  report->mutable_response_body()->append(body, content_length);
  TEE_LOG_DEBUG("IAS response body: %s", report->response_body().c_str());

  rapidjson::Document doc;
  if (!doc.Parse(report->response_body().data()).HasParseError()) {
    report->set_epid_pseudonym(JsonConfig::GetStr(doc, kStrEpidPseudonym));
    report->set_quote_status(JsonConfig::GetStr(doc, kStrQuoteStatus));
    report->set_b16_platform_info_blob(JsonConfig::GetStr(doc, kStrPlatform));
    report->set_b64_quote_body(JsonConfig::GetStr(doc, kStrQuoteBody));
  } else if (body[content_length - 1] == '}') {
    TEE_LOG_ERROR("Fail to parse report response body");
  }

  return content_length;
}

size_t RaIasClient::ParseReportResponseHeader(const char* contents, size_t size,
                                              size_t nmemb, void* response) {
  size_t len = size * nmemb;
  const char* header = contents;
  IasReport* report = RCAST(IasReport*, response);

  if (!strncmp(header, kStrHeaderSig, strlen(kStrHeaderSig))) {
    report->set_b64_signature(GetHeaderValue(header));
  } else if (!strncmp(header, kStrHeaderSigAk, strlen(kStrHeaderSigAk))) {
    report->set_b64_signature(GetHeaderValue(header));
  } else if (!strncmp(header, kStrHeaderCa, strlen(kStrHeaderCa))) {
    report->set_signing_cert(GetHeaderValue(header));
  } else if (!strncmp(header, kStrHeaderCaAk, strlen(kStrHeaderCaAk))) {
    report->set_signing_cert(GetHeaderValue(header));
  } else if (!strncmp(header, kStrHeaderAdvisoryURL,
                      strlen(kStrHeaderAdvisoryURL))) {
    report->set_advisory_url(GetHeaderValue(header));
  } else if (!strncmp(header, kStrHeaderAdvisoryIDs,
                      strlen(kStrHeaderAdvisoryIDs))) {
    report->set_advisory_ids(GetHeaderValue(header));
  }
  return len;
}

// Define the static member for per-thread lock
std::mutex RaIasClient::init_mutex_;

RaIasClient::RaIasClient() {
  // curl_global_init is not multithreads safe function. It's suggested to
  // call it in main thread. Here we just add lock to make sure safety, but
  // don't consider the performance, as multithreads is not common usecase.
  {
    std::lock_guard<std::mutex> lock(init_mutex_);
    curl_global_init(CURL_GLOBAL_ALL);
  }

  curl_ = curl_easy_init();
  if (!curl_) {
    return;
  }

#if !defined(NOLOG) && defined(DEBUG)
  // set libcurl verbose
  curl_easy_setopt(curl_, CURLOPT_VERBOSE, 1L);
#endif

  // set the common header
  headers_ = curl_slist_append(NULL, "Accept: application/json");
  headers_ = curl_slist_append(headers_, "Content-Type: application/json");
  curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, headers_);
  curl_easy_setopt(curl_, CURLOPT_USERAGENT, "sgx-sp/1.0");

  std::string header_access_key = "Ocp-Apim-Subscription-Key: ";
  std::string ias_access_key = GET_CONF_STR(kConfIasAccessKey);
  if (!ias_access_key.empty()) {
    header_access_key += ias_access_key;
    headers_ = curl_slist_append(headers_, header_access_key.c_str());
  }

  // set commom option
  curl_easy_setopt(curl_, CURLOPT_FORBID_REUSE, 1L);
  curl_easy_setopt(curl_, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(curl_, CURLOPT_TIMEOUT, 60L);
  curl_easy_setopt(curl_, CURLOPT_CONNECTTIMEOUT, 10L);
  curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYPEER, 0L);
  curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYHOST, 0L);
}

RaIasClient::~RaIasClient() {
  if (headers_) {
    curl_slist_free_all(headers_);
  }
  if (curl_) {
    curl_easy_cleanup(curl_);
  }
  // add lock for multi-threads safety
  {
    std::lock_guard<std::mutex> lock(init_mutex_);
    curl_global_cleanup();
  }
}

TeeErrorCode RaIasClient::GetSigRL(const sgx_epid_group_id_t* gid,
                                   DataBytes* sigrl) {
  if (!curl_) {
    TEE_LOG_ERROR("IAS client is not initialized");
    return TEE_ERROR_IAS_CLIENT_INIT;
  }

  // Set the URL
  tee::common::DataBytes gid_hex(RCAST(const uint8_t*, gid),
                                 sizeof(sgx_epid_group_id_t));
  std::string url = GetIasUrl() + "/sigrl/" + gid_hex.ToHexStr(true).GetStr();
  TEE_LOG_DEBUG("URL: %s", url.c_str());
  curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());

  // Set the sigrl request header and body handler function and data
  IasSigrl ias_sigrl;
  curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, ParseSigrlResponseBody);
  curl_easy_setopt(curl_, CURLOPT_HEADERFUNCTION, ParseSigrlResponseHeader);
  curl_easy_setopt(curl_, CURLOPT_WRITEDATA, RCAST(void*, &ias_sigrl));
  curl_easy_setopt(curl_, CURLOPT_WRITEHEADER, RCAST(void*, &ias_sigrl));

  CURLcode rc = curl_easy_perform(curl_);
  if (rc != CURLE_OK) {
    TEE_LOG_ERROR("Fail to connect server: %s\n", curl_easy_strerror(rc));
    return TEE_ERROR_IAS_CLIENT_CONNECT;
  }

  if (!ias_sigrl.b64_sigrl.empty()) {
    sigrl->SetValue(ias_sigrl.b64_sigrl);
  }
  return TEE_SUCCESS;
}

TeeErrorCode RaIasClient::FetchReport(const std::string& b64_quote,
                                      tee::IasReport* ias_report) {
  // should not be empty is not to use cache
  if (b64_quote.empty()) {
    TEE_LOG_ERROR("Invalid base64 quote value");
    return TEE_ERROR_PARAMETERS;
  }

  if (!curl_) {
    TEE_LOG_ERROR("IAS client is not initialized!");
    return TEE_ERROR_IAS_CLIENT_INIT;
  }

  // Set the report url
  std::string url = GetIasUrl() + "/report";
  TEE_LOG_DEBUG("URL: %s", url.c_str());
  curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());

  // Set the post data
  std::string post_data = "{\"isvEnclaveQuote\": \"";
  post_data += b64_quote;
  post_data += "\"}";
  curl_easy_setopt(curl_, CURLOPT_POSTFIELDS, post_data.c_str());

  // Set the report request header and body handler function and data;
  // Clear the ias_report in case it's dirty
  ias_report->clear_b64_signature();
  ias_report->clear_signing_cert();
  ias_report->clear_advisory_url();
  ias_report->clear_advisory_ids();
  ias_report->clear_response_body();
  ias_report->clear_epid_pseudonym();
  ias_report->clear_quote_status();
  ias_report->clear_b16_platform_info_blob();
  ias_report->clear_b64_quote_body();
  curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, ParseReportResponseBody);
  curl_easy_setopt(curl_, CURLOPT_HEADERFUNCTION, ParseReportResponseHeader);
  curl_easy_setopt(curl_, CURLOPT_WRITEDATA, RCAST(void*, ias_report));
  curl_easy_setopt(curl_, CURLOPT_WRITEHEADER, RCAST(void*, ias_report));

  CURLcode rc = curl_easy_perform(curl_);
  if (rc != CURLE_OK) {
    TEE_LOG_ERROR("Fail to connect server: %s\n", curl_easy_strerror(rc));
    return TEE_ERROR_IAS_CLIENT_CONNECT;
  }

  // deal with the escaped certificates
  std::string signing_cert = ias_report->signing_cert();
  if (!signing_cert.empty()) {
    int unescape_len = 0;
    char* unescape = curl_easy_unescape(curl_, signing_cert.data(),
                                        signing_cert.length(), &unescape_len);
    if (unescape && unescape_len) {
      ias_report->set_signing_cert(unescape, unescape_len);
      curl_free(unescape);
    } else {
      TEE_LOG_ERROR("Fail to convert the escaped certificate in response.");
      return TEE_ERROR_IAS_CLIENT_UNESCAPE;
    }
  } else {
    TEE_LOG_ERROR("Fail to get quote report from IAS");
    return TEE_ERROR_IAS_CLIENT_GETREPORT;
  }

  TEE_LOG_INFO("Get IAS report successfully");
  return TEE_SUCCESS;
}

}  // namespace untrusted
}  // namespace tee
