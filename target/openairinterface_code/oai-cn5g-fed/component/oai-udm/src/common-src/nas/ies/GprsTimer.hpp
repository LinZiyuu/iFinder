/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _GPRS_TIMER_H_
#define _GPRS_TIMER_H_

#include "Type3NasIe.hpp"

constexpr uint8_t kGprsTimerLength = 2;
constexpr uint8_t kGprsTimerContentLength =
    kGprsTimerLength - 1;  // Length - 1 octets for IEI
constexpr auto kGprsTimerIeName = "GPRS Timer";

namespace oai::nas {
constexpr uint8_t kGprsTimerUnitValueIsIncrementedInMultiplesOf2Seconds = 0b000;
constexpr uint8_t kGprsTimerUnitValueIsIncrementedInMultiplesOf1Minute  = 0b001;
constexpr uint8_t kGprsTimerUnitValueIsIncrementedInMultiplesOfDecihours =
    0b010;
constexpr uint8_t kGprsTimerUnitValueIndicatesThatTheTimerIsDeactivated = 0b111;

class GprsTimer : public Type3NasIe {
 public:
  GprsTimer(uint8_t iei);
  GprsTimer(uint8_t iei, uint8_t unit, uint8_t value);

  virtual ~GprsTimer();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kGprsTimerIeName; }
  uint32_t GetIeLength() const override;

  void Set(uint8_t _iei, uint8_t unit, uint8_t value);

  void SetUnit(uint8_t unit);
  uint8_t GetUnit() const;

  void SetValue(uint8_t value);
  uint8_t GetValue() const;

 private:
  uint8_t unit_;   // 3 bits
  uint8_t value_;  // 5 bits
};
}  // namespace oai::nas

#endif
