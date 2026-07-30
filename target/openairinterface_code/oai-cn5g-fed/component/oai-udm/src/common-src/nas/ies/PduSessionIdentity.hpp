/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_IDENTITY_H_
#define _PDU_SESSION_IDENTITY_H_

#include "Type3NasIe.hpp"

constexpr uint8_t kPduSessionIdentityLength = 1;
constexpr auto kPduSessionIdentityIeName    = "PDU Session Identity";

namespace oai::nas {

class PduSessionIdentity : public NasIe {
 public:
  PduSessionIdentity();
  PduSessionIdentity(uint8_t value);
  virtual ~PduSessionIdentity();

  bool Validate(int len) const override;

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kPduSessionIdentityIeName; }
  uint32_t GetIeLength() const override;

  void Set(uint8_t value);
  uint8_t Get() const;

 private:
  uint8_t value_;
};
}  // namespace oai::nas

#endif
