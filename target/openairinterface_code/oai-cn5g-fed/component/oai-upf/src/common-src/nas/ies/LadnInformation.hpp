/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _LADN_INFORMATION_H_
#define _LADN_INFORMATION_H_

#include "Dnn.hpp"
#include "Ladn.hpp"
#include "Type6NasIe.hpp"
#include "_5gsTrackingAreaIdList.hpp"

constexpr uint8_t kLadnInformationMinimumLength = 3;
constexpr uint8_t kLadnInformationContentMinimumLength =
    kLadnInformationMinimumLength -
    3;  // Minimum length - 3 octets for IEI/Length
constexpr uint16_t kLadnInformationMaximumLength        = 1715;
constexpr uint8_t kLadnInformationMaximumSupportedLadns = 8;
constexpr auto kLadnInformationIeName                   = "LADN Information";

namespace oai::nas {

class LadnInformation : public Type6NasIe {
 public:
  LadnInformation();
  virtual ~LadnInformation();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kLadnInformationIeName; }

  void Set(const std::vector<Ladn>& value);
  void Add(const Ladn& value);

 private:
  std::vector<Ladn> ladn_list_;
};

}  // namespace oai::nas

#endif
