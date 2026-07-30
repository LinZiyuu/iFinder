/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _5GS_REGISTRATION_RESULT_H_
#define _5GS_REGISTRATION_RESULT_H_

#include "Type4NasIe.hpp"

constexpr uint8_t k5gsRegistrationResultLength = 3;
constexpr uint8_t k5gsRegistrationResultContentLength =
    k5gsRegistrationResultLength -
    2;  // Minimum length - 2 bytes for IEI/Length
constexpr auto k5gsRegistrationResultIeName = "5GS Registration Result";

namespace oai::nas {

class _5gsRegistrationResult : public Type4NasIe {
 public:
  _5gsRegistrationResult();
  _5gsRegistrationResult(uint8_t iei);
  _5gsRegistrationResult(bool emergency, bool nssaa, bool sms, uint8_t value);
  _5gsRegistrationResult(
      uint8_t iei, bool emergency, bool nssaa, bool sms, uint8_t value);
  virtual ~_5gsRegistrationResult();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return k5gsRegistrationResultIeName; }

  void SetValue(uint8_t value);
  uint8_t GetValue() const;

  void Set(uint8_t iei, bool emergency, bool nssaa, bool sms, uint8_t value);
  void Set(bool emergency, bool nssaa, bool sms, uint8_t value);

 private:
  bool emergency_registered_;
  bool nssaa_performed_;
  bool sms_allowed_;
  uint8_t value_;
};
}  // namespace oai::nas

#endif
