/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _TYPE2_NAS_IE_FORMAT_T_H_
#define _TYPE2_NAS_IE_FORMAT_T_H_

#include "NasIe.hpp"

constexpr uint8_t kType2NasIeFormatTLength = 1;
namespace oai::nas {

class Type2NasIeFormatT : public NasIe {
 public:
  Type2NasIeFormatT();
  Type2NasIeFormatT(uint8_t iei);
  virtual ~Type2NasIeFormatT();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = true) override;

  uint32_t GetIeLength() const override;

  bool Validate(int len) const override;

 protected:
  uint8_t iei_;  // 1 byte
};

}  // namespace oai::nas

#endif
