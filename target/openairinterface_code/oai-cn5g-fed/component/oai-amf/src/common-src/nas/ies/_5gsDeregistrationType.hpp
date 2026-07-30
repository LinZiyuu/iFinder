/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _5GS_DEREGISTRATION_TYPE_H_
#define _5GS_DEREGISTRATION_TYPE_H_

#include "Type1NasIeFormatTv.hpp"

namespace oai::nas {
typedef struct _5gs_deregistration_type_s {
  uint8_t iei : 4;
  uint8_t switch_off : 1;
  uint8_t re_registration_required : 1;
  uint8_t access_type : 2;
} _5gs_deregistration_type_t;

constexpr auto k5gsDeregistrationTypeIeName = "5GS De-registration Type";

class _5gsDeregistrationType : public Type1NasIeFormatTv {
 public:
  _5gsDeregistrationType();
  _5gsDeregistrationType(uint8_t iei);
  _5gsDeregistrationType(uint8_t iei, uint8_t value);
  _5gsDeregistrationType(_5gs_deregistration_type_t type);
  virtual ~_5gsDeregistrationType();

  static std::string GetIeName() { return k5gsDeregistrationTypeIeName; }

  void Set(const _5gs_deregistration_type_t& type);
  void Get(_5gs_deregistration_type_t& type) const;

  void Set(uint8_t value);
  void Get(uint8_t& value) const;

  void Set(uint8_t iei, uint8_t value);
  void Get(uint8_t& iei, uint8_t& value) const;

 private:
  void SetValue();
  void GetValue();

  union {
    struct {
      uint8_t iei : 4;
      uint8_t switch_off : 1;
      uint8_t re_registration_required : 1;
      uint8_t access_type : 2;
    } bf;
    uint8_t b;
  } u1;
};

}  // namespace oai::nas

#endif
