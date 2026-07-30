/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _TYPE6_NAS_IE_H_
#define _TYPE6_NAS_IE_H_

#include <optional>

#include "NasIe.hpp"

namespace oai::nas {

class Type6NasIe : public NasIe {
 public:
  Type6NasIe();
  Type6NasIe(uint8_t iei);
  virtual ~Type6NasIe() = default;

  int Encode(uint8_t* buf, int len) const override;
  int Encode(
      uint8_t* buf, int len,
      int& len_pos) const;  // Use this function to encode IE lengh later
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  uint32_t GetIeLength() const override;
  bool Validate(int len) const override;
  bool ValidateHeader(int len) const;

  void SetIei(uint8_t iei);

  void SetLengthIndicator(uint16_t li);
  void GetLengthIndicator(uint16_t& li) const;
  uint16_t GetLengthIndicator() const;

  uint8_t GetHeaderLength() const;

 protected:
  std::optional<uint8_t> iei_;  // IEI present in format TLV-E
  uint16_t li_;                 // length indicator, 2 bytes
};

}  // namespace oai::nas

#endif
