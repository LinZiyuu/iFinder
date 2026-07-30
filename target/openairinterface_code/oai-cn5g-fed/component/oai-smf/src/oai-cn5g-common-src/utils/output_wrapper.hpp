/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _OUTPUT_WRAPPER_H
#define _OUTPUT_WRAPPER_H

#include <string>

namespace oai::utils {
class output_wrapper {
 public:
  static void print_buffer(
      const std::string app, const std::string sink, const uint8_t* buf,
      int len);
};
}  // namespace oai::utils
#endif
