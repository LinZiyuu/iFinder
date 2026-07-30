/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _ADDITIONAL_INFORMATION_H_
#define _ADDITIONAL_INFORMATION_H_

extern "C" {
#include "TLVDecoder.h"
#include "TLVEncoder.h"
#include "bstrlib.h"
}

#include "Type4NasIe.hpp"

constexpr uint8_t kAdditionalInformationMinimumLength = 3;
constexpr uint8_t kAdditionalInformationContentMinimumLength =
    kAdditionalInformationMinimumLength -
    2;  // Minimum length - 2 octets for IEI/Length
constexpr uint16_t kAdditionalInformationMaximumLength = 257;
constexpr auto kAdditionalInformationIeName = "Additional Information";

namespace oai::nas {

class AdditionalInformation : public Type4NasIe {
 public:
  AdditionalInformation();
  AdditionalInformation(const bstring& value);
  virtual ~AdditionalInformation();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kAdditionalInformationIeName; }

  void SetValue(const bstring& dnn);
  void GetValue(bstring& dnn) const;

 private:
  bstring value_;
};

}  // namespace oai::nas

#endif
