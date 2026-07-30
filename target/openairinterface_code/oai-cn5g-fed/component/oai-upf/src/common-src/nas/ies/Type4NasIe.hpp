/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _TYPE4_NAS_IE_H_
#define _TYPE4_NAS_IE_H_

#include <optional>

#include "NasIe.hpp"

namespace oai::nas {

class Type4NasIe : public NasIe {
 public:
  Type4NasIe();
  Type4NasIe(uint8_t iei);
  virtual ~Type4NasIe() = default;

  int Encode(uint8_t* buf, int len) const override;
  int Encode(
      uint8_t* buf, int len,
      int& len_pos) const;  // Use this function to encode IE length later
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  uint32_t GetIeLength() const override;
  bool Validate(int len) const override;
  bool ValidateHeader(int len) const;

  void SetIei(uint8_t iei);
  void GetIei(std::optional<uint8_t>& iei) const;

  void SetLengthIndicator(uint8_t li);
  void GetLengthIndicator(uint8_t& li) const;
  uint8_t GetLengthIndicator() const;

  uint8_t GetHeaderLength() const;

 protected:
  std::optional<uint8_t> iei_;  // IEI present in format TLV
  uint8_t li_;                  // length indicator, 1 byte
};

}  // namespace oai::nas

#endif
