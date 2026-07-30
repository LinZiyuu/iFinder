/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _TYPE1_NAS_IE_FORMAT_TV_H_
#define _TYPE1_NAS_IE_FORMAT_TV_H_

#include "NasIe.hpp"

constexpr uint8_t kType1NasIeFormatTvLength = 1;
namespace oai::nas {

class Type1NasIeFormatTv : public NasIe {
 public:
  Type1NasIeFormatTv();
  Type1NasIeFormatTv(uint8_t iei);
  virtual ~Type1NasIeFormatTv();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = true) override;

  uint32_t GetIeLength() const override;
  bool Validate(int len) const override;

  void SetIei(uint8_t iei);

  void SetValue(uint8_t value);
  uint8_t GetValue() const;

 protected:
  std::optional<uint8_t> iei_;  // in bit position 5,6,7,8 of an octet
  uint8_t value_;               // value in bit positions 4, 3, 2, 1 of an octet
};

}  // namespace oai::nas

#endif
