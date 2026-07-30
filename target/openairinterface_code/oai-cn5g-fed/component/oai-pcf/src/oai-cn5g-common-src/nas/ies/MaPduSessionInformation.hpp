/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _MA_PDU_SESSION_INFORMATION_H_
#define _MA_PDU_SESSION_INFORMATION_H_

#include "Type1NasIeFormatTv.hpp"

constexpr auto kMaPduSessionInformationIeName = "MA PDU Session Information";

namespace oai::nas {

class MaPduSessionInformation : public Type1NasIeFormatTv {
 public:
  MaPduSessionInformation();
  MaPduSessionInformation(uint8_t value);
  virtual ~MaPduSessionInformation();

  static std::string GetIeName() { return kMaPduSessionInformationIeName; }

  void Set(uint8_t value);
  uint8_t Get() const;

 private:
};
}  // namespace oai::nas

#endif
