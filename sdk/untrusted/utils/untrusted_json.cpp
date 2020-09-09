#include <string>
#include <vector>

#include "tee/common/bytes.h"
#include "tee/common/log.h"
#include "tee/common/rsa.h"
#include "tee/untrusted/utils/untrusted_fs.h"

#include "untrusted/utils/untrusted_json_internal.h"

namespace tee {
namespace untrusted {

#if defined(DEBUG) || defined(EDEBUG)
// The public key of intel SDK sample code default privite key
static const char* kConfSignedPublicKey = R"(
-----BEGIN RSA PUBLIC KEY-----
MIIBiAKCAYEAroOogvsj/fZDZY8XFdkl6dJmky0lRvnWMmpeH41Bla6U1qLZAmZu
yIF+mQC/cgojIsrBMzBxb1kKqzATF4+XwPwgKz7fmiddmHyYz2WDJfAjIveJZjdM
jM4+EytGlkkJ52T8V8ds0/L2qKexJ+NBLxkeQLfV8n1mIk7zX7jguwbCG1PrnEMd
J3Sew20vnje+RsngAzdPChoJpVsWi/K7cettX/tbnre1DL02GXc5qJoQYk7b3zkm
hz31TgFrd9VVtmUGyFXAysuSAb3EN+5VnHGr0xKkeg8utErea2FNtNIgua8HONfm
9Eiyaav1SVKzPHlyqLtcdxH3I8Wg7yqMsaprZ1n5A1v/levxnL8+It02KseD5HqV
4rf/cImSlCt3lpRg8U5E1pyFQ2IVEC/XTDMiI3c+AR+w2jSRB3Bwn9zJtFlWKHG3
m1xGI4ck+Lci1JvWWLXQagQSPtZTsubxTQNx1gsgZhgv1JHVZMdbVlAbbRMC1nSu
JNl7KPAS/VfzAgED
-----END RSA PUBLIC KEY-----
)";
#else
// Empty public key of release mode signing key
// Please add this in your formal product code.
static const char* kConfSignedPublicKey = R"(
)";
#endif

JsonConfig* JsonConfig::GetInstance() {
  static JsonConfig instance;
  return &instance;
}

bool JsonConfig::CheckString(const rapidjson::Value& conf, const char* name) {
  if (!conf.HasMember(name) || !conf[name].IsString()) {
    TEE_LOG_INFO("%s is missed or not string in config file", name);
    return false;
  }
  return true;
}

bool JsonConfig::CheckString(const rapidjson::Document& conf,
                             const char* name) {
  if (!conf.HasMember(name) || !conf[name].IsString()) {
    TEE_LOG_INFO("%s is missed or not string in config file", name);
    return false;
  }
  return true;
}

bool JsonConfig::CheckArray(const rapidjson::Document& conf, const char* name) {
  if (!conf.HasMember(name) || !conf[name].IsArray()) {
    TEE_LOG_INFO("%s is missed or not array in config file", name);
    return false;
  }
  return true;
}

bool JsonConfig::CheckArray(const rapidjson::Value& conf, const char* name) {
  if (!conf.HasMember(name) || !conf[name].IsArray()) {
    TEE_LOG_INFO("%s is missed or not array in config file", name);
    return false;
  }
  return true;
}

bool JsonConfig::CheckInt(const rapidjson::Document& conf, const char* name) {
  if (!conf.HasMember(name) || !conf[name].IsInt()) {
    TEE_LOG_INFO("%s is missed or not integer in config file", name);
    return false;
  }
  return true;
}

bool JsonConfig::CheckInt(const rapidjson::Value& conf, const char* name) {
  if (!conf.HasMember(name) || !conf[name].IsInt()) {
    TEE_LOG_INFO("%s is missed or not integer in config file", name);
    return false;
  }
  return true;
}

bool JsonConfig::CheckObj(const rapidjson::Document& conf, const char* name) {
  if (!conf.HasMember(name) || !conf[name].IsObject()) {
    TEE_LOG_ERROR("%s is missed or not object in config file", name);
    return false;
  }
  return true;
}

bool JsonConfig::CheckObj(const rapidjson::Value& conf, const char* name) {
  if (!conf.HasMember(name) || !conf[name].IsObject()) {
    TEE_LOG_ERROR("%s is missed or not object in config file", name);
    return false;
  }
  return true;
}

std::string JsonConfig::GetStr(const rapidjson::Document& conf,
                               const char* name,
                               const std::string& default_val) {
  if (CheckString(conf, name)) {
    std::string value = conf[name].GetString();
    TEE_LOG_DEBUG("%s=%s", name, value.c_str());
    return value;
  } else {
    TEE_LOG_DEBUG("%s is not string type", name);
    return default_val;
  }
}

std::string JsonConfig::GetStr(const rapidjson::Value& conf, const char* name,
                               const std::string& default_val) {
  if (CheckString(conf, name)) {
    std::string value = conf[name].GetString();
    TEE_LOG_DEBUG("%s=%s", name, value.c_str());
    return value;
  } else {
    TEE_LOG_DEBUG("%s is not string type", name);
    return default_val;
  }
}

TeeErrorCode JsonConfig::GetStrArray(const rapidjson::Document& conf,
                                     const char* name,
                                     std::vector<std::string>* values) {
  if (CheckArray(conf, name)) {
    const rapidjson::Value& val_array = conf[name];
    size_t count = val_array.Size();
    for (size_t i = 0; i < count; i++) {
      if (val_array[i].IsString()) {
        std::string val_str = val_array[i].GetString();
        TEE_LOG_DEBUG("%s[%ld]=%s", name, i, val_str.c_str());
        values->push_back(val_str);
      } else {
        TEE_LOG_ERROR("Invalid string type in Array");
        return TEE_ERROR_PARSE_CONFIGURATIONS;
      }
    }
  } else {
    TEE_LOG_DEBUG("Invalid Array type");
    return TEE_ERROR_PARSE_CONFIGURATIONS;
  }
  return TEE_SUCCESS;
}

TeeErrorCode JsonConfig::GetStrArray(const rapidjson::Value& conf,
                                     const char* name,
                                     std::vector<std::string>* values) {
  if (CheckArray(conf, name)) {
    const rapidjson::Value& val_array = conf[name];
    size_t count = val_array.Size();
    for (size_t i = 0; i < count; i++) {
      if (val_array[i].IsString()) {
        std::string val_str = val_array[i].GetString();
        TEE_LOG_DEBUG("%s[%ld]=%s", name, i, val_str.c_str());
        values->push_back(val_str);
      } else {
        TEE_LOG_ERROR("Invalid string type in Array");
        return TEE_ERROR_PARSE_CONFIGURATIONS;
      }
    }
  } else {
    TEE_LOG_DEBUG("Invalid Array type");
    return TEE_ERROR_PARSE_CONFIGURATIONS;
  }
  return TEE_SUCCESS;
}

TeeErrorCode JsonConfig::GetInt(const rapidjson::Document& conf,
                                const char* name, int* value) {
  if (!CheckInt(conf, name)) {
    TEE_LOG_ERROR("Not integer type: %s", name);
    return TEE_ERROR_PARSE_CONFIGURATIONS;
  }

  *value = conf[name].GetInt();
  TEE_LOG_DEBUG("%s=%d", name, *value);
  return TEE_SUCCESS;
}

TeeErrorCode JsonConfig::GetInt(const rapidjson::Value& conf, const char* name,
                                int* value) {
  if (!CheckInt(conf, name)) {
    TEE_LOG_ERROR("Not integer type: %s", name);
    return TEE_ERROR_PARSE_CONFIGURATIONS;
  }

  *value = conf[name].GetInt();
  TEE_LOG_DEBUG("%s=%d", name, *value);
  return TEE_SUCCESS;
}

std::string JsonConfig::GetConfigFilename(const std::string& filename) {
  // First priority, the absolute path filename or file in current directory
  if (FsFileExists(filename)) {
    TEE_LOG_DEBUG("Configuration file: %s", filename.c_str());
    return filename;
  }

  // Then find configuration file in HOME directory
  std::string homepath = getenv("HOME");
  homepath = homepath + "/" + filename;
  if (FsFileExists(homepath)) {
    TEE_LOG_DEBUG("Configuration file: %s", homepath.c_str());
    return homepath;
  }

  // Finally, try to find configuration file in /etc directory
  std::string etcpath = "/etc/kubetee/";
  etcpath += filename;
  if (FsFileExists(etcpath)) {
    TEE_LOG_DEBUG("Configuration file: %s", etcpath.c_str());
    return etcpath;
  }

  // If cannot find configuration file, return empty string
  TEE_LOG_ERROR("Cannot find configuration file: %s", filename.c_str());
  return "";
}

std::string JsonConfig::ParseSignedConfiguration(const JsonDocumentPtr& doc) {
  rapidjson::Document* conf = doc.get();
  const std::string config_empty = "";

  // Firstly, try to get each section
  std::string config_b64 = GetStr(*conf, kConfSignedConf);
  if (config_b64.empty()) {
    TEE_LOG_ERROR("Fail to read configuration section");
    return config_empty;
  }
  std::string hash_hex = GetStr(*conf, kConfSignedHash);
  if (hash_hex.empty()) {
    TEE_LOG_ERROR("Fail to read hash section");
    return config_empty;
  }
  std::string sig_b64 = GetStr(*conf, kConfSignedSig);
  if (sig_b64.empty()) {
    TEE_LOG_ERROR("Fail to read signature section");
    return config_empty;
  }

  // parse the configuration section
  tee::common::DataBytes config(config_b64);
  std::string config_str = config.FromBase64().GetStr();
  TEE_LOG_DEBUG("configurations: %s", config_str.c_str());

  // Generate the hash and check the signature and value
  if (!config.ToSHA256().ToHexStr().Compare(hash_hex)) {
    TEE_LOG_DEBUG("Calculated Hash value: %s", config.GetStr().c_str());
    TEE_LOG_ERROR("Mismatch between calculated hash value and given one");
    return config_empty;
  }

  using RsaCrypto = tee::common::RsaCrypto;
  tee::common::DataBytes sig_vec(sig_b64);
  std::string sig = sig_vec.FromBase64().GetStr();
  TeeErrorCode ret = RsaCrypto::Verify(kConfSignedPublicKey, hash_hex, sig);
  if (ret != TEE_SUCCESS) {
    TEE_LOG_ERROR("Fail to verify hash value signature");
    return config_empty;
  }

  return config_str;
}

TeeErrorCode JsonConfig::LoadConfiguration(const std::string& filename) {
  if (filename.empty()) {
    TEE_LOG_ERROR("Empty configuration file name");
    return TEE_ERROR_CONF_NOTEXIST;
  }

  std::string config_file = GetConfigFilename(filename);
  if (config_file.empty()) {
    TEE_LOG_ERROR("Fail to find configuration file");
    return TEE_ERROR_CONF_NOTEXIST;
  }

  std::string config_str;
  if (FsReadString(config_file, &config_str) != TEE_SUCCESS) {
    TEE_LOG_ERROR("Fail to read configuration file");
    return TEE_ERROR_PARSE_CONFIGURATIONS;
  }

  JsonDocumentPtr doc(new rapidjson::Document);
  if (doc.get()->Parse(config_str.data()).HasParseError()) {
    TEE_LOG_ERROR("Fail to parse json configration file");
    return TEE_ERROR_PARSE_CONFIGURATIONS;
  }

  std::string is_signed = GetStr(*doc.get(), kConfSignedCheck, "false");
  if (is_signed == "true") {
    TEE_LOG_INFO("Parsing the signed configurations file ...");
    std::string config_str_signed = ParseSignedConfiguration(doc);
    JsonDocumentPtr doc_signed(new rapidjson::Document);
    if (doc_signed.get()->Parse(config_str_signed.data()).HasParseError()) {
      TEE_LOG_ERROR("Fail to parse signed configration file");
      return TEE_ERROR_PARSE_CONFIGURATIONS;
    }
    cfgs_.emplace(filename, doc_signed);
  } else {
    // Support both signed and unsigned configurations, but only signed
    // configurations in release mode.
#if defined(DEBUG) || defined(EDEBUG)
    cfgs_.emplace(filename, doc);
#else
    TEE_LOG_WARN("Please use signed configuration file in release mode");
    cfgs_.emplace(filename, doc);
    // return TEE_ERROR_PARSE_CONFIGURATIONS;
    // TEE_LOG_ERROR("Please use signed configuration file in release mode");
    // return TEE_ERROR_PARSE_CONFIGURATIONS;
#endif
  }

  TEE_LOG_INFO("Load configuration file %s successfully", filename.c_str());
  return TEE_SUCCESS;
}

std::string JsonConfig::ConfGetStr(const std::string& conf_file,
                                   const char* name,
                                   const std::string& default_val) {
  TEE_LOG_DEBUG("Get %s from %s", name, conf_file.c_str());

  if (cfgs_.find(conf_file) == cfgs_.end()) {
    if (LoadConfiguration(conf_file) != TEE_SUCCESS) {
      TEE_LOG_DEBUG("Load config failed, set %s to default value", name);
      return default_val;
    }
  }

  return GetStr(*cfgs_[conf_file].get(), name, default_val);
}

TeeErrorCode JsonConfig::ConfGetStrArray(const std::string& conf_file,
                                         const char* name,
                                         std::vector<std::string>* values) {
  TEE_LOG_DEBUG("Get %s from %s", name, conf_file.c_str());

  if (cfgs_.find(conf_file) == cfgs_.end()) {
    if (LoadConfiguration(conf_file) != TEE_SUCCESS) {
      TEE_LOG_DEBUG("Fail to load configuration file");
      return TEE_ERROR_PARSE_CONFIGURATIONS;
    }
  }

  return GetStrArray(*cfgs_[conf_file].get(), name, values);
}

TeeErrorCode JsonConfig::ConfGetInt(const std::string& conf_file,
                                    const char* name, int* value) {
  TEE_LOG_DEBUG("Get %s from %s", name, conf_file.c_str());

  if (cfgs_.find(conf_file) == cfgs_.end()) {
    if (LoadConfiguration(conf_file) != TEE_SUCCESS) {
      TEE_LOG_ERROR("Fail to load configuration file");
      return TEE_ERROR_PARSE_CONFIGURATIONS;
    }
  }

  return GetInt(*cfgs_[conf_file].get(), name, value);
}

rapidjson::Document* JsonConfig::GetJsonConf(const std::string& conf_file) {
  TEE_LOG_DEBUG("Get json configuration %s", conf_file.c_str());

  if (cfgs_.find(conf_file) == cfgs_.end()) {
    if (LoadConfiguration(conf_file) != TEE_SUCCESS) {
      TEE_LOG_ERROR("Fail to load configuration file");
      return nullptr;
    }
  }

  return cfgs_[conf_file].get();
}

}  // namespace untrusted
}  // namespace tee

std::string GetConfStr(const std::string& conf_file, const char* name,
                       const std::string& default_val) {
  return tee::untrusted::JsonConfig::GetInstance()->ConfGetStr(conf_file, name,
                                                               default_val);
}

TeeErrorCode GetConfStrArray(const std::string& conf_file, const char* name,
                             std::vector<std::string>* values) {
  return tee::untrusted::JsonConfig::GetInstance()->ConfGetStrArray(
      conf_file, name, values);
}

TeeErrorCode GetConfInt(const std::string& conf_file, const char* name,
                        int* value) {
  return tee::untrusted::JsonConfig::GetInstance()->ConfGetInt(conf_file, name,
                                                               value);
}
