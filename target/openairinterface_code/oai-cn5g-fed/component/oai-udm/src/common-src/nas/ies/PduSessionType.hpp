/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_TYPE_H_
#define _PDU_SESSION_TYPE_H_

#include "Type1NasIeFormatTv.hpp"

constexpr auto kPduSessionTypeName = "PDU Session Type";

namespace oai::nas {

class PduSessionType : public Type1NasIeFormatTv {
 public:
  PduSessionType();
  PduSessionType(uint8_t type);
  PduSessionType(uint8_t iei, uint8_t type);
  virtual ~PduSessionType();

  static std::string GetIeName() { return kPduSessionTypeName; }

  void SetValue(uint8_t value);
  uint8_t GetValue() const;
};

}  // namespace oai::nas

#endif
