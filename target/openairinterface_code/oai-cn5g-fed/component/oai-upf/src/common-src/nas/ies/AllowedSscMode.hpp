/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _ALLOWED_SSC_MODE_H_
#define _ALLOWED_SSC_MODE_H_

#include "Type1NasIeFormatTv.hpp"

constexpr auto kAllowedSscModeName = "Allowed SSC Mode";

namespace oai::nas {

class AllowedSscMode : public Type1NasIeFormatTv {
 public:
  AllowedSscMode();
  AllowedSscMode(uint8_t type);
  AllowedSscMode(uint8_t iei, uint8_t type);
  virtual ~AllowedSscMode();

  static std::string GetIeName() { return kAllowedSscModeName; }

  void SetValue(uint8_t value);
  uint8_t GetValue() const;

  bool IsSscMode1Allowed() const;
  bool IsSscMode2Allowed() const;
  bool IsSscMode3Allowed() const;
};

}  // namespace oai::nas

#endif
