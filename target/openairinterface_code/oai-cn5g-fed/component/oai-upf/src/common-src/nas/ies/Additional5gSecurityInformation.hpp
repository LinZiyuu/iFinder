/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _ADDITIONAL_5G_SECURITY_INFORMATION_H_
#define _ADDITIONAL_5G_SECURITY_INFORMATION_H_

#include "Type4NasIe.hpp"

constexpr uint8_t kAdditional5gSecurityInformationLength = 3;
constexpr uint8_t kAdditional5gSecurityInformationContentLength =
    kAdditional5gSecurityInformationLength -
    2;  // Minimum length - 2 octets for IEI/Length
constexpr auto kAdditional5gSecurityInformationIeName =
    "Additional 5G Security Information";

namespace oai::nas {

class Additional5gSecurityInformation : public Type4NasIe {
 public:
  Additional5gSecurityInformation();
  Additional5gSecurityInformation(bool RINMR, bool HDP);
  virtual ~Additional5gSecurityInformation();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() {
    return kAdditional5gSecurityInformationIeName;
  }

  void SetRinmr(bool value);
  bool GetRinmr() const;

  void SetHdp(bool value);
  bool GetHdp() const;

 private:
  bool rinmr_;
  bool hdp_;
};
}  // namespace oai::nas

#endif
