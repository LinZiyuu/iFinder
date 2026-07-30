/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef __5GS_TRACKING_AREA_IDENTITY_H_
#define __5GS_TRACKING_AREA_IDENTITY_H_

#include "Type3NasIe.hpp"

constexpr uint8_t k5gsTrackingAreaIdentityLength = 7;
constexpr auto k5gsTrackingAreaIdentityIeName    = "5GS Tracking Area Identity";

namespace oai::nas {

class _5gsTrackingAreaIdentity : public Type3NasIe {
 public:
  _5gsTrackingAreaIdentity();
  _5gsTrackingAreaIdentity(uint8_t iei) = delete;
  _5gsTrackingAreaIdentity(
      const std::string& mcc, const std::string& mnc, uint32_t tac);
  virtual ~_5gsTrackingAreaIdentity();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = true);

  static std::string GetIeName() { return k5gsTrackingAreaIdentityIeName; }
  uint32_t GetIeLength() const override;

  void SetTac(uint32_t value);
  uint32_t GetTac() const;
  void GetTac(uint32_t& value) const;

  void SetMcc(const std::string& mcc);
  void GetMcc(std::string& mcc) const;

  void SetMnc(const std::string& mnc);
  void GetMnc(std::string& mnc) const;

 private:
  std::string mcc_;
  std::string mnc_;
  uint32_t tac_;
};
}  // namespace oai::nas

#endif
