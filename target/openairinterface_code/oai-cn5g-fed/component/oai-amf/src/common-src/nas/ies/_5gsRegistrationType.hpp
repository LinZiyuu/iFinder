/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _5GS_REGISTRATION_TYPE_H_
#define _5GS_REGISTRATION_TYPE_H_

#include "Type1NasIeFormatTv.hpp"

constexpr auto k5gsRegistrationTypeName = "5GS Registration Type";

namespace oai::nas {

class _5gsRegistrationType : public Type1NasIeFormatTv {
 public:
  _5gsRegistrationType();
  _5gsRegistrationType(bool follow_on_req, uint8_t type);
  _5gsRegistrationType(uint8_t iei, bool follow_on_req, uint8_t type);
  virtual ~_5gsRegistrationType();

  static std::string GetIeName() { return k5gsRegistrationTypeName; }

  void SetValue();
  void GetValue();

  bool ValidateValue(bool follow_on_req, uint8_t type);

  void Set(bool follow_on_req, uint8_t type, uint8_t iei);
  void Set(bool follow_on_req, uint8_t type);

  void SetFollowOnReq(bool is);
  bool IsFollowOnReq();

  void SetRegType(uint8_t type);
  uint8_t GetRegType();

 private:
  bool follow_on_req_;
  uint8_t reg_type_ : 3;
};

}  // namespace oai::nas

#endif
