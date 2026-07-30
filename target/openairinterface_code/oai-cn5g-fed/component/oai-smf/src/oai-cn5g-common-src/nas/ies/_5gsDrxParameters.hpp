/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _5GS_DRX_PARAMETERS_H_
#define _5GS_DRX_PARAMETERS_H_

#include "Type4NasIe.hpp"

constexpr uint8_t k5gsDrxParametersLength = 3;
constexpr uint8_t k5gsDrxParametersContentLength =
    k5gsDrxParametersLength - 2;  // Length - 2 octets for IEI/Length
constexpr auto k5gsDrxParametersIeName = "5GS DRX Parameters";

namespace oai::nas {

class _5gsDrxParameters : public Type4NasIe {
 public:
  _5gsDrxParameters();
  _5gsDrxParameters(uint8_t value);
  virtual ~_5gsDrxParameters();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return k5gsDrxParametersIeName; }

  void SetValue(uint8_t value);
  uint8_t GetValue() const;

 private:
  uint8_t value_;
};
}  // namespace oai::nas

#endif
