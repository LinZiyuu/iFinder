/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _5GS_IDENTITY_TYPE_H_
#define _5GS_IDENTITY_TYPE_H_

#include "Type1NasIeFormatTv.hpp"

constexpr auto k5gsIdentityTypeIeName = "5GS Identity Type";

namespace oai::nas {

class _5gsIdentityType : public Type1NasIeFormatTv {
 public:
  _5gsIdentityType();
  _5gsIdentityType(uint8_t iei);
  _5gsIdentityType(uint8_t iei, uint8_t value);
  virtual ~_5gsIdentityType();

  static std::string GetIeName() { return k5gsIdentityTypeIeName; }

  void SetValue(uint8_t value);
  uint8_t GetValue() const;

 private:
};
}  // namespace oai::nas

#endif
