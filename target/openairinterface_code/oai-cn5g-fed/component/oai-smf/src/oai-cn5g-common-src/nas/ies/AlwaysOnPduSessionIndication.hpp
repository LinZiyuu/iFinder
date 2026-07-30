/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _ALWAYS_ON_PDU_SESSION_INDICATION_H_
#define _ALWAYS_ON_PDU_SESSION_INDICATION_H_

#include "Type1NasIeFormatTv.hpp"

namespace oai::nas {

constexpr auto kAlwaysOnPduSessionIndicationIeName =
    "Always-on PDU Session Indication";
constexpr uint8_t kAlwaysOnPduSessionNotAllowed = 0;
constexpr uint8_t kAlwaysOnPduSessionRequired   = 1;

class AlwaysOnPduSessionIndication : public Type1NasIeFormatTv {
 public:
  AlwaysOnPduSessionIndication();
  AlwaysOnPduSessionIndication(uint8_t iei);
  AlwaysOnPduSessionIndication(uint8_t iei, uint8_t type);
  virtual ~AlwaysOnPduSessionIndication();

  static std::string GetIeName() { return kAlwaysOnPduSessionIndicationIeName; }

  void SetValue();
  void GetValue();

  void Set(uint8_t iei, bool apsi);

  void SetApsi(bool apsi);
  bool IsApsi();

 private:
  bool apsi_;
};

}  // namespace oai::nas

#endif
