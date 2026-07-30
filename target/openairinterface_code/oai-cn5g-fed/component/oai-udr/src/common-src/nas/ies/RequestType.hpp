/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _REQUEST_TYPE_H_
#define _REQUEST_TYPE_H_

#include "NasIe.hpp"
#include "Type1NasIeFormatTv.hpp"

constexpr auto kRequestTypeIeName = "Request Type";

namespace oai::nas {

class RequestType : public Type1NasIeFormatTv {
 public:
  RequestType();
  RequestType(uint8_t value);
  virtual ~RequestType();

  static std::string GetIeName() { return kRequestTypeIeName; }

  void SetValue(uint8_t value);
  uint8_t GetValue() const;

 private:
};
}  // namespace oai::nas

#endif
