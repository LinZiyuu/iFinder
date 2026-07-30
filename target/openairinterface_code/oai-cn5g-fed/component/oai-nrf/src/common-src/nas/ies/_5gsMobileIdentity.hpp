/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _5GS_MOBILE_IDENTITY_H_
#define _5GS_MOBILE_IDENTITY_H_

#include "Struct.hpp"
#include "Type6NasIe.hpp"

constexpr uint8_t k5gsMobileIdentityMinimumLength = 4;
constexpr uint8_t k5gsMobileIdentityContentMinimumLength =
    k5gsMobileIdentityMinimumLength -
    3;  // Minimum length - 3 octets for IEI/Length
constexpr uint8_t k5gsMobileIdentityIe5gGutiLength  = 11;
constexpr uint8_t k5gsMobileIdentityIe5gSTmsiLength = 7;
constexpr auto k5gsMobileIdentityIeName             = "5GS Mobile Identity";

namespace oai::nas {

// TODO: 5GS mobile identity information element for type of identity "MAC
// address"

class _5gsMobileIdentity : public Type6NasIe {
 public:
  _5gsMobileIdentity();
  _5gsMobileIdentity(uint8_t iei);
  virtual ~_5gsMobileIdentity();

  // Common
  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return k5gsMobileIdentityIeName; }
  void ClearIe();
  uint8_t GetTypeOfIdentity() const { return type_of_identity_; };

  // 5G GUTI
  int Encode5gGuti(uint8_t* buf, int len) const;
  int Decode5gGuti(const uint8_t* const buf, int len);
  void Set5gGuti(
      const std::string& mcc, const std::string& mnc, uint8_t amf_region_id,
      uint16_t amf_set_id, uint8_t amf_pointer, uint32_t _5g_tmsi);
  void Get5gGuti(std::optional<_5G_GUTI_t>&) const;

  // SUCI
  int EncodeSuci(uint8_t* buf, int len) const;
  int DecodeSuci(const uint8_t* const buf, int len, int length);
  void SetSuciWithSupiImsi(
      const std::string& mcc, const std::string& mnc,
      const std::string& routing_ind, uint8_t protection_sch_id,
      const std::string& msin);  // TODO: SetSUCI, SUCI and SUPI format IMSI
  void SetSuciWithSupiImsi(
      const std::string& mcc, const std::string& mnc,
      const std::string& routing_ind, uint8_t protection_sch_id,
      uint8_t home_pki, const std::string& msin_digits);
  bool GetSuciWithSupiImsi(SUCI_imsi_t& suci) const;

  int EncodeRoutingIndicator(
      std::optional<std::string> routing_indicator, uint8_t* buf,
      int len) const;
  int EncodeMsin(const std::string& msin_str, uint8_t* buf, int len) const;

  // TMSI
  int Encode5gSTmsi(uint8_t* buf, int len) const;
  int Decode5gSTmsi(const uint8_t* const buf, int len);

  void Set5gSTmsi(
      uint16_t amf_set_id, uint8_t amf_pointer, const std::string& tmsi);
  bool Get5gSTmsi(
      uint16_t& amf_set_id, uint8_t& amf_pointer, std::string& tmsi) const;

  // IMEI/IMEISV
  int EncodeImeisv(uint8_t* buf, int len) const;
  int DecodeImeisv(const uint8_t* const buf, int len);

  void SetImeisv(const IMEI_IMEISV_t& imeisv);
  bool GetImeisv(IMEI_IMEISV_t& imeisv) const;

 private:
  uint8_t type_of_identity_ : 3;

  std::optional<SUCI_imsi_t> supi_format_imsi_;
  std::optional<_5G_GUTI_t> _5g_guti_;
  // std::optional<IMEI_IMEISV_t> imei_;  // TODO:
  std::optional<IMEI_IMEISV_t> imeisv_;
  std::optional<_5G_S_TMSI_t> _5g_s_tmsi_;
};

}  // namespace oai::nas

#endif
