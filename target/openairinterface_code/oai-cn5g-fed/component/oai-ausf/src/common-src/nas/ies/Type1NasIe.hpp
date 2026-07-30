/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _TYPE1_NAS_IE_H_
#define _TYPE1_NAS_IE_H_

#include <optional>

#include "NasIe.hpp"

constexpr uint8_t kType1NasIeLength = 1;
namespace oai::nas {

class Type1NasIe : public NasIe {
 public:
  Type1NasIe();
  Type1NasIe(bool high_pos, uint8_t value);
  Type1NasIe(bool high_pos);
  Type1NasIe(uint8_t iei, uint8_t value);
  Type1NasIe(uint8_t iei);
  virtual ~Type1NasIe();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = true) override;
  int Decode(const uint8_t* const buf, int len, bool high_pos, bool is_iei);

  uint32_t GetIeLength() const override;
  bool Validate(int len) const override;

  void Set(bool high_pos, uint8_t value);
  void Set(bool high_pos);

 protected:
  void SetValue(uint8_t value);
  virtual void SetValue() = 0;
  virtual void GetValue() = 0;

  std::optional<uint8_t>
      iei_;        // IEI present in Format TV (in bit position 8,7,6,5)
  bool high_pos_;  // choose bit position for Format V
  uint8_t value_;  // value (in bit positions 4,3,2,1 or 8,7,6,5)
};

}  // namespace oai::nas

#endif
