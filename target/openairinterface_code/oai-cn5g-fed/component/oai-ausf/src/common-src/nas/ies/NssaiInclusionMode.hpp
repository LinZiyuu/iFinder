/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _NSSAI_INCLUSION_MODE_H
#define _NSSAI_INCLUSION_MODE_H

#include "Type1NasIeFormatTv.hpp"

constexpr uint8_t kNssaiInclusionModeLength = 1;
constexpr auto kNssaiInclusionModeIeName    = "NSSAI Inclusion Mode";

namespace oai::nas {

class NssaiInclusionMode : public Type1NasIeFormatTv {
 public:
  NssaiInclusionMode();
  NssaiInclusionMode(uint8_t value);
  virtual ~NssaiInclusionMode();

  static std::string GetIeName() { return kNssaiInclusionModeIeName; }

  void SetValue(uint8_t value);
  uint8_t GetValue() const;

 private:
};

}  // namespace oai::nas

#endif
