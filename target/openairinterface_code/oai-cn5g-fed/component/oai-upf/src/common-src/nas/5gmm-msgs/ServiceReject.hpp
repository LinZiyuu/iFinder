/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _SERVICE_REJECT_H_
#define _SERVICE_REJECT_H_

#include "NasIeHeader.hpp"
#include "NasMmPlainHeader.hpp"

namespace oai::nas {

class ServiceReject : public Nas5gmmMessage {
 public:
  ServiceReject();
  ~ServiceReject();

  void SetHeader(uint8_t security_header_type);

  int Encode(uint8_t* buf, int len) override;
  int Decode(uint8_t* buf, int len) override;

  uint32_t GetLength() const override;

  void Set5gmmCause(uint8_t value);
  uint8_t Get5GMmCause();

  void SetPduSessionStatus(uint16_t value);
  // TODO: Get

  void SetT3346Value(uint8_t value);
  // TODO: Get

  void SetEapMessage(const bstring& eap);
  // TODO: Get

  void SetT3448Value(uint8_t unit, uint8_t value);
  // TODO: Get

 private:
  NasMmPlainHeader ie_header_;  // Mandatory
  _5gmmCause ie_5gmm_cause_;    // Mandatory

  std::optional<PduSessionStatus> ie_pdu_session_status_;  // Optional
  std::optional<GprsTimer2> ie_t3346_value_;               // Optional
  std::optional<EapMessage> ie_eap_message_;               // Optional
  std::optional<GprsTimer3> ie_t3448_value_;               // Optional
  // TODO: CAG information list (Rel 16.14.0, Optional)
};

}  // namespace oai::nas

#endif
