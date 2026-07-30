/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_STATUS_H_
#define _PDU_SESSION_STATUS_H_

#include "Type4NasIe.hpp"

constexpr uint8_t kPduSessionStatusMinimumLength = 4;
constexpr uint8_t kPduSessionStatusContentMinimumLength =
    kPduSessionStatusMinimumLength -
    2;  // Minimum length - 2 octets for IEI/Length
constexpr uint8_t kPduSessionStatusMaximumLength = 34;
constexpr auto kPduSessionStatusIeName           = "PDU Session Status";

namespace oai::nas {

class PduSessionStatus : public Type4NasIe {
 public:
  PduSessionStatus();
  PduSessionStatus(uint16_t value);
  virtual ~PduSessionStatus() = default;

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kPduSessionStatusIeName; }

  void SetValue(uint16_t value);
  uint16_t GetValue() const;

 private:
  uint16_t value_;
  // TODO: spare
};

}  // namespace oai::nas

#endif
