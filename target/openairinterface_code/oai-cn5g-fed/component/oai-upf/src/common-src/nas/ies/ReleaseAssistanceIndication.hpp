/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _RELEASE_ASSISTANCE_INDICATION_H_
#define _RELEASE_ASSISTANCE_INDICATION_H_

#include "Type1NasIeFormatTv.hpp"

constexpr auto kReleaseAssistanceIndicationIeName =
    "Release Assistance Indication";

namespace oai::nas {

class ReleaseAssistanceIndication : public Type1NasIeFormatTv {
 public:
  ReleaseAssistanceIndication();
  ReleaseAssistanceIndication(uint8_t value);
  virtual ~ReleaseAssistanceIndication();

  static std::string GetIeName() { return kReleaseAssistanceIndicationIeName; }

  void Set(uint8_t value);
  uint8_t Get() const;

 private:
  // uint8_t ddx_;
};
}  // namespace oai::nas

#endif
