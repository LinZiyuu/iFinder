/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _RE_ATTEMPT_INDICATOR_H_
#define _RE_ATTEMPT_INDICATOR_H_

#include "Type4NasIe.hpp"

constexpr uint8_t kReAttemptIndicatorLength = 3;
constexpr uint8_t kReAttemptIndicatorContentLength =
    kReAttemptIndicatorLength - 2;  // Minimum length - 2 octets for IEI/Length
constexpr auto kReAttemptIndicatorIeName = "Re-attempt indicator";

namespace oai::nas {

class ReAttemptIndicator : public Type4NasIe {
 public:
  ReAttemptIndicator();
  ReAttemptIndicator(bool eplmnc, bool ratc);
  virtual ~ReAttemptIndicator();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = true) override;

  static std::string GetIeName() { return kReAttemptIndicatorIeName; }

  void SetEplmnc(bool abo);
  bool GetEplmnc() const;

  void SetRatc(bool abo);
  bool GetRatc() const;

 private:
  bool eplmnc_;
  bool ratc_;
};

}  // namespace oai::nas

#endif
