/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _REGISTRATION_REJECT_H_
#define _REGISTRATION_REJECT_H_

#include "NasIeHeader.hpp"
#include "NasMmPlainHeader.hpp"

namespace oai::nas {

class RegistrationReject : public Nas5gmmMessage {
 public:
  RegistrationReject();
  virtual ~RegistrationReject();

  int Encode(uint8_t* buf, int len) override;
  int Decode(uint8_t* buf, int len) override;

  uint32_t GetLength() const override;

  void SetHeader(uint8_t security_header_type);
  void GetSecurityHeaderType(uint8_t security_header_type);
  bool VerifyHeader();

  void Set5gmmCause(uint8_t value);
  // TODO: Get

  void SetT3346(uint8_t value);
  // TODO: Get

  void SetT3502(uint8_t value);
  // TOGO: Get

  void SetEapMessage(const bstring& eap);
  // TODO: Get

  void SetRejectedNssai(const std::vector<RejectedSNssai>& nssai);
  // TODO: Get

 private:
  NasMmPlainHeader ie_header_;                      // Mandatory
  _5gmmCause ie_5gmm_cause_;                        // Mandatory
  std::optional<GprsTimer2> ie_t3346_value_;        // Optional
  std::optional<GprsTimer2> ie_t3502_value_;        // Optional
  std::optional<EapMessage> ie_eap_message_;        // Optional
  std::optional<RejectedNssai> ie_rejected_nssai_;  // Release 16.4.1
  // TODO: CAG information list (Release 16.14.0)
};

}  // namespace oai::nas

#endif
