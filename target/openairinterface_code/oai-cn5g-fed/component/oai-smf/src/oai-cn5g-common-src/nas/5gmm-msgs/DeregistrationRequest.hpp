/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _DEREGISTRATION_REQUEST_H_
#define _DEREGISTRATION_REQUEST_H_

#include "NasIeHeader.hpp"
#include "NasMmPlainHeader.hpp"

namespace oai::nas {
using namespace oai::nas;

class DeregistrationRequest : public Nas5gmmMessage {
 public:
  DeregistrationRequest();
  ~DeregistrationRequest();

  int Encode(uint8_t* buf, int len) override;
  int Decode(uint8_t* buf, int len) override;

  uint32_t GetLength() const override;

  void SetHeader(uint8_t security_header_type);

  void SetDeregistrationType(uint8_t dereg_type);
  void GetDeregistrationType(uint8_t& dereg_type) const;

  void SetDeregistrationType(const _5gs_deregistration_type_t& type);
  void GetDeregistrationType(_5gs_deregistration_type_t& type) const;

  void SetNgKsi(uint8_t tsc, uint8_t key_set_id);
  bool GetNgKsi(uint8_t& ng_ksi) const;

  void SetMobilityIdentityType(uint8_t type);
  void GetMobilityIdentityType(uint8_t& type) const;

  void SetSuciSupiFormatImsi(
      const std::string& mcc, const std::string& mnc,
      const std::string& routing_ind, uint8_t protection_sch_id,
      const std::string& msin);
  void SetSuciSupiFormatImsi(
      const std::string& mcc, const std::string& mnc,
      const std::string& routing_ind, uint8_t protection_sch_id, uint8_t hnpki,
      const std::string& msin);
  bool GetSuciSupiFormatImsi(SUCI_imsi_t& imsi) const;

  void Set5gGuti();
  std::string Get5gGuti() const;

  void SetImeiImeisv();
  // TODO: Get

  void Set5gSTmsi();
  // TODO: Get

 private:
  NasMmPlainHeader ie_header_;                     // Mandatory
  _5gsDeregistrationType ie_deregistration_type_;  // Mandatory
  NasKeySetIdentifier ie_ng_ksi_;                  // Mandatory
  _5gsMobileIdentity ie_5gs_mobility_id_;          // Mandatory
};

}  // namespace oai::nas

#endif
