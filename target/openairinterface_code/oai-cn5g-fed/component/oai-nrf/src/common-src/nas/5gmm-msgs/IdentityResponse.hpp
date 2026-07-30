/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _IDENTITY_RESPONSE_H_
#define _IDENTITY_RESPONSE_H_

#include "NasIeHeader.hpp"
#include "NasMmPlainHeader.hpp"

namespace oai::nas {
using namespace oai::nas;

class IdentityResponse : public Nas5gmmMessage {
 public:
  IdentityResponse();
  ~IdentityResponse();

  int Encode(uint8_t* buf, int len) override;
  int Decode(uint8_t* buf, int len) override;

  uint32_t GetLength() const override;

  void SetHeader(uint8_t security_header_type);

  void Get5gsMobileIdentity(_5gsMobileIdentity& mobile_identity) const;
  _5gsMobileIdentity Get5gsMobileIdentity() const;

  void SetSuciSupiFormatImsi(
      const std::string& mcc, const std::string& mnc,
      const std::string& routing_ind, uint8_t protection_sch_id,
      const std::string& msin);
  void SetSuciSupiFormatImsi(
      const std::string& mcc, const std::string& mnc,
      const std::string& routing_ind, uint8_t protection_sch_id, uint8_t hnpki,
      const std::string& msin);

  void Set5gGuti();
  void SetImeiImeisv();
  void Set5gSTmsi();

 private:
  NasMmPlainHeader ie_header_;             // Mandatory
  _5gsMobileIdentity ie_mobile_identity_;  // Mandatory
};

}  // namespace oai::nas

#endif
