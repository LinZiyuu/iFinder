/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _TYPE3_NAS_IE_H_
#define _TYPE3_NAS_IE_H_

#include <optional>

#include "NasIe.hpp"

constexpr uint8_t kType3NasIeFormatTvLength = 1;
namespace oai::nas {

class Type3NasIe : public NasIe {
 public:
  Type3NasIe();
  Type3NasIe(uint8_t iei);
  virtual ~Type3NasIe() = default;

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  uint32_t GetIeLength() const override;
  bool Validate(int len) const override;

  void SetIei(uint8_t iei);

 protected:
  std::optional<uint8_t> iei_;  // IEI present format TV
};

}  // namespace oai::nas

#endif
