/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _SERVICE_REQUEST_H_
#define _SERVICE_REQUEST_H_

#include "NasIeHeader.hpp"
#include "bstrlib.h"
#include "NasMmPlainHeader.hpp"

namespace oai::nas {

class ServiceRequest : public Nas5gmmMessage {
 public:
  ServiceRequest();
  ~ServiceRequest();

  void SetHeader(uint8_t security_header_type);

  int Encode(uint8_t* buf, int len) override;
  int Decode(uint8_t* buf, int len) override;

  uint32_t GetLength() const override;

  void SetNgKsi(uint8_t tsc, uint8_t key_set_id);
  void GetNgKsi(uint8_t& ng_ksi) const;

  void SetServiceType(uint8_t value);
  void GetServiceType(uint8_t& value) const;

  void Set5gSTmsi(
      uint16_t amf_set_id, uint8_t amf_pointer, const std::string& tmsi);
  bool Get5gSTmsi(
      uint16_t& amf_set_id, uint8_t& amf_pointer, std::string& tmsi) const;

  void SetUplinkDataStatus(uint16_t value);
  bool GetUplinkDataStatus(uint16_t& value) const;
  std::optional<uint16_t> GetUplinkDataStatus() const;

  void SetPduSessionStatus(uint16_t value);
  bool GetPduSessionStatus(uint16_t& value) const;
  std::optional<uint16_t> GetPduSessionStatus() const;

  void SetAllowedPduSessionStatus(uint16_t value);
  bool GetAllowedPduSessionStatus(uint16_t& value) const;
  std::optional<uint16_t> GetAllowedPduSessionStatus() const;

  void SetNasMessageContainer(const bstring& value);
  bool GetNasMessageContainer(bstring& nas) const;

 private:
  NasMmPlainHeader ie_header_;       // Mandatory
  NasKeySetIdentifier ie_ng_ksi_;    // Mandatory
  ServiceType ie_service_type_;      // Mandatory
  _5gsMobileIdentity ie_5g_s_tmsi_;  // Mandatory

  std::optional<UplinkDataStatus> ie_uplink_data_status_;  // Optional
  std::optional<PduSessionStatus> ie_pdu_session_status_;  // Optional
  std::optional<AllowedPduSessionStatus>
      ie_allowed_pdu_session_status_;                            // Optional
  std::optional<NasMessageContainer> ie_nas_message_container_;  // Optional
};

}  // namespace oai::nas

#endif
