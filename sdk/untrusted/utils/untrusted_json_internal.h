#ifndef SDK_UNTRUSTED_UTILS_UNTRUSTED_JSON_INTERNAL_H_
#define SDK_UNTRUSTED_UTILS_UNTRUSTED_JSON_INTERNAL_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "rapidjson/document.h"

#include "tee/common/error.h"
#include "tee/common/log.h"
#include "tee/common/type.h"

namespace tee {
namespace untrusted {

constexpr char kConfSignedCheck[] = "configurations_is_signed";
constexpr char kConfSignedConf[] = "configurations";
constexpr char kConfSignedHash[] = "hash";
constexpr char kConfSignedSig[] = "signature";

typedef std::shared_ptr<rapidjson::Document> JsonDocumentPtr;
typedef std::map<std::string, JsonDocumentPtr> JsonConfigurationsMap;

class JsonConfig {
 public:
  // Gets the singleton UnitTest object.
  static JsonConfig* GetInstance();

  // To support both rapidjson::Document and rapidjson::Value
  static bool CheckString(const rapidjson::Document& conf, const char* name);
  static bool CheckString(const rapidjson::Value& conf, const char* name);
  static bool CheckArray(const rapidjson::Document& conf, const char* name);
  static bool CheckArray(const rapidjson::Value& conf, const char* name);
  static bool CheckInt(const rapidjson::Document& conf, const char* name);
  static bool CheckInt(const rapidjson::Value& conf, const char* name);
  static bool CheckObj(const rapidjson::Document& conf, const char* name);
  static bool CheckObj(const rapidjson::Value& conf, const char* name);
  static std::string GetStr(const rapidjson::Document& conf, const char* name,
                            const std::string& default_val = "");
  static std::string GetStr(const rapidjson::Value& conf, const char* name,
                            const std::string& default_val = "");
  static TeeErrorCode GetStrArray(const rapidjson::Document& conf,
                                  const char* name,
                                  std::vector<std::string>* values);
  static TeeErrorCode GetStrArray(const rapidjson::Value& conf,
                                  const char* name,
                                  std::vector<std::string>* values);
  static TeeErrorCode GetInt(const rapidjson::Document& conf, const char* name,
                             int* value);
  static TeeErrorCode GetInt(const rapidjson::Value& conf, const char* name,
                             int* value);

  // Load configuration files and then parse and get value(s)
  std::string ConfGetStr(const std::string& conf_file, const char* name,
                         const std::string& default_val = "");
  TeeErrorCode ConfGetStrArray(const std::string& conf_file, const char* name,
                               std::vector<std::string>* values);
  TeeErrorCode ConfGetInt(const std::string& conf_file, const char* name,
                          int* value);
  rapidjson::Document* GetJsonConf(const std::string& conf_file);

 private:
  // Hide construction functions
  JsonConfig() {}
  JsonConfig(const JsonConfig&);
  void operator=(JsonConfig const&);

  std::string GetConfigFilename(const std::string& filename);
  TeeErrorCode LoadConfiguration(const std::string& filename);
  std::string ParseSignedConfiguration(const JsonDocumentPtr& doc);

  JsonConfigurationsMap cfgs_;
};

}  // namespace untrusted
}  // namespace tee

#endif  // SDK_UNTRUSTED_UTILS_UNTRUSTED_JSON_INTERNAL_H_
