/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _EPS_BEARER_CONTEXT_STATUS_H_
#define _EPS_BEARER_CONTEXT_STATUS_H_

#include "Type4NasIe.hpp"

constexpr uint8_t kEpsBearerContextStatusLength = 4;
constexpr uint8_t kEpsBearerContextStatusContentLength =
    kEpsBearerContextStatusLength - 2;  // Length - 2 octets for IEI/Length
constexpr auto kEpsBearerContextStatusIeName = "EPS Bearer Context Status";

namespace oai::nas {

class EpsBearerContextStatus : public Type4NasIe {
 public:
  EpsBearerContextStatus();
  EpsBearerContextStatus(uint16_t value);
  virtual ~EpsBearerContextStatus();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kEpsBearerContextStatusIeName; }

  void SetValue(uint16_t value);
  uint16_t GetValue() const;

 private:
  uint16_t value_;
};

}  // namespace oai::nas

#endif
