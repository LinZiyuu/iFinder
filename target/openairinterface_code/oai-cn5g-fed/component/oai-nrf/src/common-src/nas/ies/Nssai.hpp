/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _NSSAI_HPP_
#define _NSSAI_HPP_

#include "NasIeHeader.hpp"
#include "Type4NasIe.hpp"

constexpr uint8_t kNssaiMinimumLength = 4;
constexpr uint8_t kNssaiContentMinimumLength =
    kNssaiMinimumLength - 2;  // Minimum length - 2 octets for IEI/Length
constexpr uint8_t kNssaiMaximumLength = 146;
constexpr auto kNssaiIeName           = "NSSAI";

namespace oai::nas {

class Nssai : public Type4NasIe {
 public:
  Nssai();
  Nssai(uint8_t iei);
  Nssai(uint8_t iei, const std::vector<struct SNSSAI_s>& nssai);
  virtual ~Nssai();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kNssaiIeName; }

  void GetValue(std::vector<struct SNSSAI_s>& nssai) const;

 private:
  std::vector<struct SNSSAI_s>
      s_nssais_;  // TODO: use class S-NSSAI instead of struct SNSSAI_s
};

}  // namespace oai::nas

#endif
