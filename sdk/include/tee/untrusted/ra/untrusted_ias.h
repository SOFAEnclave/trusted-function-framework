#ifndef SDK_INCLUDE_TEE_UNTRUSTED_RA_UNTRUSTED_IAS_H_
#define SDK_INCLUDE_TEE_UNTRUSTED_RA_UNTRUSTED_IAS_H_

#include <mutex>
#include <string>

#include "./sgx_quote.h"
#include "./sgx_urts.h"
#include "./sgx_utils.h"

#include "curl/curl.h"

#include "tee/common/bytes.h"
#include "tee/common/error.h"
#include "tee/common/type.h"

#include "./kubetee.pb.h"

namespace tee {
namespace untrusted {

class RaIasClient {
 public:
  RaIasClient();
  ~RaIasClient();

  TeeErrorCode GetSigRL(const sgx_epid_group_id_t* gid, DataBytes* sigrl);
  TeeErrorCode FetchReport(const std::string& b64_quote,
                           tee::IasReport* ias_report);

 private:
  static std::string GetIasUrl();
  static std::string GetHeaderValue(const std::string& header);
  static size_t ParseSigrlResponseBody(const char* contents, size_t size,
                                       size_t nmemb, void* response);
  static size_t ParseSigrlResponseHeader(const char* contents, size_t size,
                                         size_t nmemb, void* response);
  static size_t ParseReportResponseBody(const char* contents, size_t size,
                                        size_t nmemb, void* response);
  static size_t ParseReportResponseHeader(const char* contents, size_t size,
                                          size_t nmemb, void* response);

  CURL* curl_ = NULL;
  curl_slist* headers_ = NULL;

  static std::mutex init_mutex_;
};

}  // namespace untrusted
}  // namespace tee

#endif  // SDK_INCLUDE_TEE_UNTRUSTED_RA_UNTRUSTED_IAS_H_
