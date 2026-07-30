/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PAYLOAD_CONTAINER_TYPE_H
#define _PAYLOAD_CONTAINER_TYPE_H

#include "Type1NasIeFormatTv.hpp"

constexpr uint8_t kPayloadContainerTypeLength = 1;
constexpr auto kPayloadContainerTypeIeName    = "Payload Container Type";

namespace oai::nas {

class PayloadContainerType : public Type1NasIeFormatTv {
 public:
  PayloadContainerType();
  PayloadContainerType(uint8_t value);
  PayloadContainerType(uint8_t iei, uint8_t value);
  virtual ~PayloadContainerType();

  static std::string GetIeName() { return kPayloadContainerTypeIeName; }

 private:
};

}  // namespace oai::nas

#endif
