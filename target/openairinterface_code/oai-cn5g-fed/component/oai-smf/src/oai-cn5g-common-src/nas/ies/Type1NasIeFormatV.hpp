/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _TYPE1_NAS_IE_FORMAT_V_H_
#define _TYPE1_NAS_IE_FORMAT_V_H_

#include "NasIe.hpp"

constexpr uint8_t kType1NasIeFormatVLength = 1;
namespace oai::nas {

class Type1NasIeFormatV : public NasIe {
 public:
  Type1NasIeFormatV();
  Type1NasIeFormatV(bool high_pos);
  Type1NasIeFormatV(bool high_pos, uint8_t value);
  virtual ~Type1NasIeFormatV();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool high_pos = false) override;

  uint32_t GetIeLength() const override;
  bool Validate(int len) const override;

  void Set(bool high_pos, uint8_t value);
  void Set(uint8_t value);

 protected:
  bool high_pos_;
  uint8_t value_;  // only for value in bit positions 8, 7, 6, 5 of an octet
                   // in case of value in bit positions 4, 3, 2, 1 of an octet,
                   // use Type1NasIeFormatTV instead)
};

}  // namespace oai::nas

#endif
