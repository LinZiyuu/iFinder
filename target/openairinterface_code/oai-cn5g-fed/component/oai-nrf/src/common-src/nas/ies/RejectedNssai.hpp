/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _REJECTED_NSSAI_H_
#define _REJECTED_NSSAI_H_

#include <RejectedSNssai.hpp>

#include "Type4NasIe.hpp"

constexpr uint8_t kRejectedNssaiMinimumLength = 4;
constexpr uint8_t kRejectedNssaiContentMinimumLength =
    kRejectedNssaiMinimumLength -
    2;  // Minimum length - 2 octets for IEI/Length
constexpr uint8_t kRejectedNssaiMaximumLength = 42;
constexpr auto kRejectedNssaiIeName           = "Rejected NSSAI";

namespace oai::nas {

class RejectedNssai : public Type4NasIe {
 public:
  RejectedNssai();
  RejectedNssai(uint8_t iei);
  virtual ~RejectedNssai();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kRejectedNssaiIeName; }

  void SetRejectedSNssais(const std::vector<RejectedSNssai>& nssais);
  void GetRejectedSNssais(std::vector<RejectedSNssai>& nssais) const;

 private:
  std::vector<RejectedSNssai> rejected_nssais_;
};

}  // namespace oai::nas

#endif
