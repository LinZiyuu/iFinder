/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UE_RADIO_CAPABILITY_ID_H_
#define _UE_RADIO_CAPABILITY_ID_H_

#include "Type4NasIe.hpp"

constexpr uint8_t kUeRadioCapabilityIdMinimumLength = 4;
constexpr uint8_t kUeRadioCapabilityIdContentMinimumLength =
    kUeRadioCapabilityIdMinimumLength -
    2;  // Minimum length - 2 octets for IEI/Length
constexpr auto kUeRadioCapabilityIdIeName = "UE Radio Capability ID";

namespace oai::nas {

class UeRadioCapabilityId : public Type4NasIe {
 public:
  UeRadioCapabilityId();
  UeRadioCapabilityId(const bstring& value);
  virtual ~UeRadioCapabilityId();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kUeRadioCapabilityIdIeName; }

  void SetValue(const bstring& value);
  void GetValue(bstring& value) const;

 private:
  bstring value_;
};
}  // namespace oai::nas

#endif
