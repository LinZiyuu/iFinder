/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UES_USAGE_SETTING_H_
#define _UES_USAGE_SETTING_H_

#include "Type4NasIe.hpp"

constexpr uint8_t kUeUsageSettingLength = 3;
constexpr uint8_t kUeUsageSettingContentLength =
    kUeUsageSettingLength - 2;  // IE length - 2 octets for IEI/Length
constexpr auto kUeUsageSettingIeName = "UE's Usage Setting";

namespace oai::nas {

class UeUsageSetting : public Type4NasIe {
 public:
  UeUsageSetting();
  UeUsageSetting(bool ues_usage_setting);
  virtual ~UeUsageSetting();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = true) override;

  static std::string GetIeName() { return kUeUsageSettingIeName; }

  void SetValue(bool value);
  bool GetValue() const;

 private:
  bool ues_usage_setting_;
};
}  // namespace oai::nas

#endif
