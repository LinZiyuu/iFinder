/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _S_NSSAI_NAS_H_
#define _S_NSSAI_NAS_H_

#include "Struct.hpp"
#include "Type4NasIe.hpp"

constexpr uint8_t kSNssaiMinimumLength = 3;
constexpr uint8_t kSNssaiContentMinimumLength =
    kSNssaiMinimumLength - 2;  // Minimum length - 2 octets for IEI/Length
constexpr uint8_t kSNssaiMaximumLength = 10;
constexpr auto kSNssaiIeName           = "S-NSSAI";

namespace oai::nas {

class SNssai : public Type4NasIe {
 public:
  SNssai(uint8_t iei);
  SNssai(std::optional<uint8_t> iei);
  SNssai(std::optional<uint8_t> iei, SNSSAI_s snssai);
  virtual ~SNssai();

  void Clear();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(uint8_t* buf, int len, const bool is_option = true);

  static std::string GetIeName() { return kSNssaiIeName; }

  void GetValue(SNSSAI_t& snssai) const;

  void SetSNSSAI(
      uint8_t sst, uint32_t sd, uint8_t mapped_hplmn_sst = 0,
      uint32_t mapped_hplmn_sd = SD_NO_VALUE);
  void SetSNSSAI(
      std::optional<int8_t> iei, uint8_t sst, uint32_t sd,
      uint8_t mapped_hplmn_sst = 0, uint32_t mapped_hplmn_sd = SD_NO_VALUE);

  std::string ToString() const;

 private:
  uint8_t sst_;
  uint32_t sd_;
  uint8_t mapped_hplmn_sst_;
  uint32_t mapped_hplmn_sd_;
};

}  // namespace oai::nas

#endif
