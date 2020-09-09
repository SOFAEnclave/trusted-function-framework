#ifndef SDK_INCLUDE_TEE_COMMON_SCOPE_H_
#define SDK_INCLUDE_TEE_COMMON_SCOPE_H_

#include <functional>
#include <utility>

namespace tee {
namespace common {

class ScopeGuard {
 public:
  explicit ScopeGuard(std::function<void()>&& f) : f_(std::move(f)) {}
  ScopeGuard(const ScopeGuard&) = delete;
  ScopeGuard& operator=(const ScopeGuard&) = delete;
  ~ScopeGuard() {
    if (f_) {
      f_();
    }
  }

  void release() {
    f_ = nullptr;
  }

 private:
  std::function<void()> f_;
};

}  // namespace common
}  // namespace tee

#define SCOPEGUARD_LINENAME_CAT(name, line) name##line
#define SCOPEGUARD_LINENAME(name, line) SCOPEGUARD_LINENAME_CAT(name, line)
#define ON_SCOPE_EXIT(...) \
  tee::common::ScopeGuard SCOPEGUARD_LINENAME(EXIT, __LINE__)(__VA_ARGS__)

#endif  // SDK_INCLUDE_TEE_COMMON_SCOPE_H_
