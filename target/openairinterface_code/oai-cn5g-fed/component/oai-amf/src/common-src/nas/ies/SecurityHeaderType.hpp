/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _SECURITY_HEADER_TYPE_H_
#define _SECURITY_HEADER_TYPE_H_

#include "NasIe.hpp"

constexpr uint8_t kSecurityHeaderTypeLength = 1;
constexpr auto kSecurityHeaderTypeIeName    = "Security Header Type";

namespace oai::nas {

class SecurityHeaderType : public NasIe {
 public:
  SecurityHeaderType(uint8_t secu_header_type);
  SecurityHeaderType();
  virtual ~SecurityHeaderType() = default;

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kSecurityHeaderTypeIeName; }

  bool Validate(int len) const override;
  uint32_t GetIeLength() const override;

  void Set(uint8_t secu_header_type, uint8_t spare = 0);
  void Get(uint8_t& secu_header_type) const;
  uint8_t Get() const;

 private:
  uint8_t spare_ : 4;
  uint8_t secu_header_type_ : 4;
};

}  // namespace oai::nas

#endif
