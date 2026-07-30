/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _ABBA_H_
#define _ABBA_H_

#include "Type4NasIe.hpp"

constexpr uint8_t kAbbaMinimumLength = 4;
constexpr uint8_t kAbbaContentMinimumLength =
    kAbbaMinimumLength - 2;  // Minimum length - 2 octets for IEI/Length
constexpr auto kAbbaIeName = "Abba";

namespace oai::nas {

class Abba : public Type4NasIe {
 public:
  Abba();
  Abba(uint8_t iei);
  Abba(uint8_t length, uint8_t* value);
  Abba(uint8_t iei, uint8_t length, uint8_t* value);
  virtual ~Abba();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kAbbaIeName; }

  void Set(uint8_t length, const uint8_t* value);
  void Set(uint8_t iei, uint8_t length, const uint8_t* value);

 private:
  uint8_t value_[256];  // TODO:
};

}  // namespace oai::nas

#endif
