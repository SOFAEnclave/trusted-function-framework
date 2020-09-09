#ifndef SDK_INCLUDE_TEE_COMMON_TABLE_H_
#define SDK_INCLUDE_TEE_COMMON_TABLE_H_

#include <map>
#include <string>

#include "tee/common/error.h"
#include "tee/common/log.h"

namespace tee {
namespace common {

template <class T>
class DataTable {
 public:
  DataTable() {}
  ~DataTable() {}

  bool Exist(const std::string& key_name) {
    return (table_.find(key_name) != table_.end()) ? true : false;
  }

  T Get(const std::string& key_name) {
    return Exist(key_name) ? table_[key_name] : nullptr;
  }

  TeeErrorCode Add(const std::string& key_name, T value) {
    if (table_[key_name]) {
      ELOG_ERROR("Conflict name: %s", key_name.c_str());
      return TEE_ERROR_PARAMETERS;
    }
    ELOG_DEBUG("Add: %s", key_name.c_str());
    table_[key_name] = value;
    return TEE_SUCCESS;
  }

 private:
  std::map<std::string, T> table_;
};

}  // namespace common
}  // namespace tee

#endif  // SDK_INCLUDE_TEE_COMMON_TABLE_H_
