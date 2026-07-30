/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _GPRS_TIMER_3_H_
#define _GPRS_TIMER_3_H_

#include "Type4NasIe.hpp"

constexpr uint8_t kGprsTimer3Length = 3;
constexpr uint8_t kGprsTimer3ContentLength =
    kGprsTimer3Length - 2;  // Length - 2 octets for IEI/Length
constexpr auto kGprsTimer3IeName = "GPRS Timer 3";

namespace oai::nas {

class GprsTimer3 : public Type4NasIe {
 public:
  GprsTimer3(){};
  GprsTimer3(uint8_t iei);
  GprsTimer3(uint8_t iei, uint8_t unit, uint8_t value);
  virtual ~GprsTimer3() = default;

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kGprsTimer3IeName; }

  void SetValue(uint8_t unit, uint8_t value);
  uint8_t GetValue() const;

  uint8_t getUnit() const;

 private:
  uint8_t unit_;
  uint8_t value_;
};
}  // namespace oai::nas

#endif
