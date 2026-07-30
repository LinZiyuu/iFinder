/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _5GSM_CONGESTION_RE_ATTEMPT_INDICATOR_H_
#define _5GSM_CONGESTION_RE_ATTEMPT_INDICATOR_H_

#include "Type4NasIe.hpp"

constexpr uint8_t k5gsmCongestionReAttemptIndicatorLength = 3;
constexpr uint8_t k5gsmCongestionReAttemptIndicatorContentLength =
    k5gsmCongestionReAttemptIndicatorLength -
    2;  // Minimum length - 2 octets for IEI/Length
constexpr auto k5gsmCongestionReAttemptIndicatorIeName =
    "5GSM congestion re-attempt indicator";

namespace oai::nas {

class _5gsmCongestionReAttemptIndicator : public Type4NasIe {
 public:
  _5gsmCongestionReAttemptIndicator();
  _5gsmCongestionReAttemptIndicator(bool abo);
  virtual ~_5gsmCongestionReAttemptIndicator();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = true) override;

  static std::string GetIeName() {
    return k5gsmCongestionReAttemptIndicatorIeName;
  }

  void SetAbo(bool abo);
  bool GetAbo() const;

 private:
  bool abo_;
};

}  // namespace oai::nas

#endif
