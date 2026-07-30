/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UPLINK_DATA_STATUS_H_
#define _UPLINK_DATA_STATUS_H_

#include "Type4NasIe.hpp"

constexpr uint8_t kUplinkDataStatusMinimumLength = 4;
constexpr uint8_t kUplinkDataStatusContentMinimumLength =
    kUplinkDataStatusMinimumLength -
    2;  // Minimum length - 2 octets for IEI/Length
constexpr uint8_t kUplinkDataStatusMaximumLength = 34;
constexpr auto kUplinkDataStatusIeName           = "Uplink Data Status";

namespace oai::nas {

class UplinkDataStatus : public Type4NasIe {
 public:
  UplinkDataStatus();
  UplinkDataStatus(uint16_t value);
  virtual ~UplinkDataStatus();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kUplinkDataStatusIeName; }

  void SetValue(uint16_t value);
  uint16_t GetValue() const;

 private:
  uint16_t value_;
  // TODO: spare
};

}  // namespace oai::nas

#endif
