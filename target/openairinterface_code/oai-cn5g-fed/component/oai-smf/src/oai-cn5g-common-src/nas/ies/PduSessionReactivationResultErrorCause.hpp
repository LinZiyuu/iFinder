/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_REACTIVATION_RESULT_ERROR_CAUSE_HPP_
#define _PDU_SESSION_REACTIVATION_RESULT_ERROR_CAUSE_HPP_

#include "Type6NasIe.hpp"

constexpr uint8_t kPduSessionReactivationResultErrorCauseMinimumLength = 5;
constexpr uint8_t kPduSessionReactivationResultErrorCauseContentMinimumLength =
    kPduSessionReactivationResultErrorCauseMinimumLength -
    3;  // Minimum length - 3 octets for IEI/Length
constexpr uint32_t kPduSessionReactivationResultErrorCauseMaximumLength = 515;
constexpr auto kPduSessionReactivationResultErrorCauseIeName =
    "PDU Session Reactivation Result Error Cause";

namespace oai::nas {

class PduSessionReactivationResultErrorCause : public Type6NasIe {
 public:
  PduSessionReactivationResultErrorCause();
  PduSessionReactivationResultErrorCause(uint8_t session_id, uint8_t value);
  virtual ~PduSessionReactivationResultErrorCause() = default;

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() {
    return kPduSessionReactivationResultErrorCauseIeName;
  }

  void SetValue(uint8_t session_id, uint8_t cause);
  std::pair<uint8_t, uint8_t> GetValue() const;

  void SetValue(const std::vector<std::pair<uint8_t, uint8_t>>& value);
  void GetValue(std::vector<std::pair<uint8_t, uint8_t>>& value) const;

 private:
  std::vector<std::pair<uint8_t, uint8_t>> pdu_session_id_cause_value_pair_;
};

}  // namespace oai::nas

#endif
