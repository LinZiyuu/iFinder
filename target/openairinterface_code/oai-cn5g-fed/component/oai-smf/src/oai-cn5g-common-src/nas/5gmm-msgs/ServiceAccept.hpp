/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _SERVICE_ACCEPT_H_
#define _SERVICE_ACCEPT_H_

#include "NasIeHeader.hpp"
#include "NasMmPlainHeader.hpp"

namespace oai::nas {
using namespace oai::nas;

class ServiceAccept : public Nas5gmmMessage {
 public:
  ServiceAccept();
  virtual ~ServiceAccept() = default;

  void SetHeader(uint8_t security_header_type);

  int Encode(uint8_t* buf, int len) override;
  int Decode(uint8_t* buf, int len) override;

  uint32_t GetLength() const override;

  void SetPduSessionStatus(uint16_t value);
  // TODO: Get

  void SetPduSessionReactivationResult(uint16_t value);
  // TODO: Get

  void SetPduSessionReactivationResultErrorCause(
      uint8_t session_id, uint8_t value);
  // TODO: Get

  void SetEapMessage(const bstring& eap);
  // TODO: Get

  void SetT3448Value(uint8_t unit, uint8_t value);
  // TODO: Get

 private:
  NasMmPlainHeader ie_header_;                             // Mandatory
  std::optional<PduSessionStatus> ie_pdu_session_status_;  // Optional
  std::optional<PduSessionReactivationResult>
      ie_pdu_session_reactivation_result_;  // Optional
  std::optional<PduSessionReactivationResultErrorCause>
      ie_pdu_session_reactivation_result_error_cause_;  // Optional
  std::optional<EapMessage> ie_eap_message_;            // Optional
  std::optional<GprsTimer3> ie_t3448_value_;            // Optional
};

}  // namespace oai::nas

#endif
