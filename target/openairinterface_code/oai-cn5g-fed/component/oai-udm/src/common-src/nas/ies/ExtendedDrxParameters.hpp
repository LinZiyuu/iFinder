/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _EXTENDED_DRX_PARAMETERS_H_
#define _EXTENDED_DRX_PARAMETERS_H_

#include "Type4NasIe.hpp"

constexpr uint8_t kExtendedDrxParametersLength = 3;
constexpr uint8_t kExtendedDrxParametersContentLength =
    kExtendedDrxParametersLength -
    2;  // Minimum length - 2 octets for IEI/Length
constexpr auto kExtendedDrxParametersIeName = "Extended DRX Parameters";

namespace oai::nas {

class ExtendedDrxParameters : public Type4NasIe {
 public:
  ExtendedDrxParameters();
  ExtendedDrxParameters(uint8_t paging_time, uint8_t value);
  virtual ~ExtendedDrxParameters();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kExtendedDrxParametersIeName; }

  void SetValue(uint8_t value);
  uint8_t GetValue() const;

  void SetPagingTime(uint8_t value);
  uint8_t GetPagingTime() const;

 private:
  uint8_t paging_time_;
  uint8_t e_drx_value_;
};
}  // namespace oai::nas

#endif
