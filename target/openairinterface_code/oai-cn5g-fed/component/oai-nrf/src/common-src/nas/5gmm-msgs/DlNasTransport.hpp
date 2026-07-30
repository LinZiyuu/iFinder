/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _DL_NAS_TRANSPORT_H_
#define _DL_NAS_TRANSPORT_H_

#include "NasIeHeader.hpp"
#include "NasMmPlainHeader.hpp"

namespace oai::nas {
using namespace oai::nas;

class DlNasTransport : public Nas5gmmMessage {
 public:
  DlNasTransport();
  ~DlNasTransport();

  void SetHeader(uint8_t security_header_type);

  int Encode(uint8_t* buf, int len) override;
  int Decode(uint8_t* buf, int len) override;

  uint32_t GetLength() const override;

  void SetPayloadContainerType(uint8_t value);

  void SetPayloadContainer(const std::vector<PayloadContainerEntry>& content);
  void SetPayloadContainer(uint8_t* buf, int len);

  void SetPduSessionId(uint8_t value);
  // TODO: Get

  void SetAdditionalInformation(const bstring& value);
  // TODO: Get

  void Set5gmmCause(uint8_t value);
  // TODO: Get

  void SetBackOffTimerValue(uint8_t unit, uint8_t value);
  // TODO: Get

 private:
  NasMmPlainHeader ie_header_;                                      // Mandatory
  PayloadContainerType ie_payload_container_type_;                  // Mandatory
  PayloadContainer ie_payload_container_;                           // Mandatory
  std::optional<PduSessionIdentity2> ie_pdu_session_identity_2_;    // Optional
  std::optional<AdditionalInformation> ie_additional_information_;  // Optional
  std::optional<_5gmmCause> ie_5gmm_cause_;                         // Optional
  std::optional<GprsTimer3> ie_back_off_timer_value_;               // Optional
};

}  // namespace oai::nas

#endif
