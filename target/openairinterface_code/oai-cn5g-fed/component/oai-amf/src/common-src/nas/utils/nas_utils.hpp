/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_NAS_UTILS_HPP_SEEN
#define FILE_NAS_UTILS_HPP_SEEN

#include <boost/thread.hpp>
#include <boost/thread/future.hpp>
#include <sstream>
#include <string>

#include "bstrlib.h"

namespace oai::nas {

constexpr uint8_t kMccMncLength = 3;

class nas_utils {
 public:
  static int encodeMccMnc2Buffer(
      const std::string& mcc_str, const std::string& mnc_str, uint8_t* buf,
      int len);
  static int decodeMccMncFromBuffer(
      std::string& mcc_str, std::string& mnc_str, const uint8_t* const buf,
      int len);
};
}  // namespace oai::nas

#endif /* FILE_UTILS_HPP_SEEN */
