/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _LADN_Indication_H_
#define _LADN_Indication_H_

#include "Type6NasIe.hpp"

constexpr uint8_t kLadnIndicationMinimumLength = 3;
constexpr uint8_t kLadnIndicationContentMinimumLength =
    kLadnIndicationMinimumLength -
    3;  // Minimum length - 3 octets for IEI/Length
constexpr uint16_t kLadnIndicationMaximumLength        = 811;
constexpr uint8_t kLadnIndicationMaximumSupportedLadns = 8;
constexpr auto kLadnIndicationIeName                   = "LADN Indication";

namespace oai::nas {

class LadnIndication : public Type6NasIe {
 public:
  LadnIndication();
  LadnIndication(const std::vector<bstring>& ladn);
  virtual ~LadnIndication();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kLadnIndicationIeName; }

  // void SetValue(const std::vector<bstring>& ladn);
  void GetValue(std::vector<bstring>& ladn) const;

 private:
  std::vector<bstring> ladn_;
};

}  // namespace oai::nas

#endif
