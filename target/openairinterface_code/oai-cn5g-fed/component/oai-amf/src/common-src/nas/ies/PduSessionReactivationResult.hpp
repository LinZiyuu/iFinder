/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */
#ifndef _PDU_SESSION_REACTIVATION_RESULT_H_
#define _PDU_SESSION_REACTIVATION_RESULT_H_

#include "Type4NasIe.hpp"

constexpr uint8_t kPduSessionReactivationResultMinimumLength = 4;
constexpr uint8_t kPduSessionReactivationResultContentMinimumLength =
    kPduSessionReactivationResultMinimumLength -
    2;  // Minimum length - 2 octets for IEI/Length
constexpr uint8_t kPduSessionReactivationResultMaximumLength = 34;
constexpr auto kPduSessionReactivationResultIeName =
    "PDU Session Reactivation Result";

namespace oai::nas {

class PduSessionReactivationResult : public Type4NasIe {
 public:
  PduSessionReactivationResult();
  PduSessionReactivationResult(uint16_t value);
  virtual ~PduSessionReactivationResult() = default;

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kPduSessionReactivationResultIeName; }

  void SetValue(uint16_t value);
  uint16_t GetValue() const;

 private:
  uint16_t value_;
  // Spare
};

}  // namespace oai::nas

#endif
