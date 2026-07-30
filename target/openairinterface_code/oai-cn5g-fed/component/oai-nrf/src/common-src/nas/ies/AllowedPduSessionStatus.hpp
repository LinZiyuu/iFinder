/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _ALLOWED_PDU_SESSION_STATUS_H_
#define _ALLOWED_PDU_SESSION_STATUS_H_

#include "Type4NasIe.hpp"

constexpr uint8_t kAllowedPduSessionStatusMinimumLength = 4;
constexpr uint8_t kAllowedPduSessionStatusContentMinimumLength =
    kAllowedPduSessionStatusMinimumLength -
    2;  // Minimum length - 2 octets for IEI/Length
constexpr uint8_t kAllowedPduSessionStatusMaximumLength = 34;
constexpr auto kAllowedPduSessionStatusIeName = "Allowed PDU Session Status";

namespace oai::nas {

class AllowedPduSessionStatus : public Type4NasIe {
 public:
  AllowedPduSessionStatus();
  AllowedPduSessionStatus(uint16_t value);
  virtual ~AllowedPduSessionStatus();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kAllowedPduSessionStatusIeName; }

  void SetValue(uint16_t value);
  uint16_t GetValue() const;

 private:
  uint16_t value_;
  // TODO: spare
};

}  // namespace oai::nas

#endif
