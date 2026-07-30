/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _IMEISV_REQUEST_H_
#define _IMEISV_REQUEST_H_

#include "Type1NasIeFormatTv.hpp"

constexpr auto kImeisvRequestIeName = "IMEISV Request";

namespace oai::nas {

class ImeisvRequest : public Type1NasIeFormatTv {
 public:
  ImeisvRequest();
  ImeisvRequest(uint8_t value);
  virtual ~ImeisvRequest();

  static std::string GetIeName() { return kImeisvRequestIeName; }

  void Set(uint8_t value);
  uint8_t Get() const;

 private:
};
}  // namespace oai::nas

#endif
