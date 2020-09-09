#ifndef SDK_INCLUDE_TEE_UNTRUSTED_UTILS_UNTRUSTED_JSON_H_
#define SDK_INCLUDE_TEE_UNTRUSTED_UTILS_UNTRUSTED_JSON_H_

#include <string>
#include <vector>

#include "tee/common/error.h"
#include "tee/common/log.h"
#include "tee/common/type.h"

#define JSON_CONF_STR(filename, name) GetConfStr((filename), (name))
#define JSON_CONF_ARRAY(filename, name, value) \
  GetConfStrArray((filename), (name), (value))
#define JSON_CONF_INT(filename, name, value) \
  GetConfInt((filename), (name), (value))

constexpr char kConfValueEnable[] = "enable";
constexpr char kConfValueDisable[] = "disable";
constexpr char kConfValueTrue[] = "true";
constexpr char kConfValueFalse[] = "false";

std::string GetConfStr(const std::string& conf_file, const char* name,
                       const std::string& default_value = "");
TeeErrorCode GetConfStrArray(const std::string& conf_file, const char* name,
                             std::vector<std::string>* values);
TeeErrorCode GetConfInt(const std::string& conf_file, const char* name,
                        int* value);

#endif  // SDK_INCLUDE_TEE_UNTRUSTED_UTILS_UNTRUSTED_JSON_H_
