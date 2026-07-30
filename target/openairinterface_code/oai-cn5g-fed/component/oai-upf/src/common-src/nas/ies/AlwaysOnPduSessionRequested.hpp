/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _ALWAYS_ON_PDU_SESSION_REQUESTED_H_
#define _ALWAYS_ON_PDU_SESSION_REQUESTED_H_

#include "Type1NasIeFormatTv.hpp"

constexpr auto kAlwaysOnPduSessionRequestedIeName =
    "AlwaysOnPduSessionRequested";

namespace oai::nas {

class AlwaysOnPduSessionRequested : public Type1NasIeFormatTv {
 public:
  AlwaysOnPduSessionRequested();
  AlwaysOnPduSessionRequested(uint8_t type);
  AlwaysOnPduSessionRequested(uint8_t iei, uint8_t type);
  virtual ~AlwaysOnPduSessionRequested();

  static std::string GetIeName() { return kAlwaysOnPduSessionRequestedIeName; }

  void SetValue();
  void GetValue();

  void Set(uint8_t iei, bool apsr);

  void SetApsr(bool apsr);
  bool IsApsr();

 private:
  bool apsr_;
};

}  // namespace oai::nas

#endif
