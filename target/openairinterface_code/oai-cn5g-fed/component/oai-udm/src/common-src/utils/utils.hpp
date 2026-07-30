/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_UTILS_HPP_SEEN
#define FILE_UTILS_HPP_SEEN

#include <boost/thread.hpp>
#include <boost/thread/future.hpp>
#include <sstream>
#include <string>

#include "bstrlib.h"

namespace oai::utils {

constexpr uint8_t kMccMncLength           = 3;
constexpr uint32_t KFutureStatusTimeoutMs = 1000;

class utils {
 public:
  template<class T>
  static inline T fromString(const std::string& str) {
    std::istringstream is(str);
    T v;
    is >> v;
    return v;
  }

  // For Boost
  template<typename T>
  static void wait_for_result(
      boost::shared_future<T>& f, std::optional<T>& result) {
    boost::future_status status;
    // wait for timeout or ready
    status = f.wait_for(boost::chrono::milliseconds(KFutureStatusTimeoutMs));
    if (status == boost::future_status::ready) {
      assert(f.is_ready());
      assert(f.has_value());
      assert(!f.has_exception());
      // return the result when available
      result = std::make_optional<T>(f.get());
      return;
    } else {
      result = std::nullopt;
      return;
    }
  }

  static void free_wrapper(void** ptr) __attribute__((hot));
  static void bdestroy_wrapper(bstring* b);
};
}  // namespace oai::utils
#endif /* FILE_UTILS_HPP_SEEN */
