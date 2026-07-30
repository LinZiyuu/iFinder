/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _GPRS_TIMER_2_H_
#define _GPRS_TIMER_2_H_

#include "Type4NasIe.hpp"

constexpr uint8_t kGprsTimer2Length = 3;
constexpr uint8_t kGprsTimer2ContentLength =
    kGprsTimer2Length - 2;  // Length - 2 octets for IEI/Length
constexpr auto kGprsTimer2IeName = "GPRS Timer 2";

namespace oai::nas {

class GprsTimer2 : public Type4NasIe {
 public:
  GprsTimer2(uint8_t iei);
  GprsTimer2(uint8_t iei, uint8_t value);
  virtual ~GprsTimer2() = default;

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kGprsTimer2IeName; }

  void SetValue(uint8_t value);
  uint8_t GetValue() const;

 private:
  uint8_t value_;
};
}  // namespace oai::nas

#endif
