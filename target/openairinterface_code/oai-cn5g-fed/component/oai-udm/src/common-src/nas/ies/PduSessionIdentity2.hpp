/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_IDENTITY_2_H_
#define _PDU_SESSION_IDENTITY_2_H_

#include "Type3NasIe.hpp"

constexpr uint8_t kPduSessionIdentity2Length = 2;
constexpr auto kPduSessionIdentity2IeName    = "PDU Session Identity 2";

namespace oai::nas {

class PduSessionIdentity2 : public Type3NasIe {
 public:
  PduSessionIdentity2();
  PduSessionIdentity2(uint8_t iei);
  PduSessionIdentity2(uint8_t iei, uint8_t value);
  virtual ~PduSessionIdentity2();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kPduSessionIdentity2IeName; }
  uint32_t GetIeLength() const override;

  void SetValue(uint8_t value);
  uint8_t GetValue() const;

 private:
  uint8_t value_;
};
}  // namespace oai::nas

#endif
