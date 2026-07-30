/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _SESSION_AMBR_H_
#define _SESSION_AMBR_H_

#include "Type4NasIe.hpp"

constexpr uint8_t kSessionAmbrLength = 8;
constexpr uint8_t kSessionAmbrContentLength =
    kSessionAmbrLength - 2;  // length - 2 octets for IEI/Length
constexpr auto kSessionAmbrIeName = "Session-AMBR";

namespace oai::nas {

class SessionAmbr : public Type4NasIe {
 public:
  SessionAmbr();
  SessionAmbr(uint8_t iei);
  SessionAmbr(
      uint8_t unit_for_downlink, uint16_t session_ambr_for_downlink,
      uint8_t unit_for_uplink, uint16_t session_ambr_for_uplink);
  SessionAmbr(
      uint8_t iei, uint8_t unit_for_downlink,
      uint16_t session_ambr_for_downlink, uint8_t unit_for_uplink,
      uint16_t session_ambr_for_uplink);
  virtual ~SessionAmbr();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = true) override;

  static std::string GetIeName() { return kSessionAmbrIeName; }

  void SetUnitForDownlink(uint8_t unit_for_downlink);
  uint8_t GetUnitForDownlink() const;

  void SetSessionAmbrForDownlink(uint16_t session_ambr_for_downlink);
  uint16_t GetSessionAmbrForDownlink() const;

  void SetUnitForUplink(uint8_t unit_for_uplink);
  uint8_t GetUnitForUplink() const;

  void SetSessionAmbrForUplink(uint16_t session_ambr_for_uplink);
  uint16_t GetSessionAmbrForUplink() const;

 private:
  uint8_t unit_for_downlink_;
  uint16_t session_ambr_for_downlink_;
  uint8_t unit_for_uplink_;
  uint16_t session_ambr_for_uplink_;
};

}  // namespace oai::nas

#endif
