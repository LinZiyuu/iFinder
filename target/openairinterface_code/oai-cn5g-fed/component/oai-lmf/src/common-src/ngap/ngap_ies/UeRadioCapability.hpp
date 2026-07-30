/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UE_RADIO_CAPABILITY_H_
#define _UE_RADIO_CAPABILITY_H_

#include "bstrlib.h"

extern "C" {
#include "Ngap_UERadioCapability.h"
}

namespace oai::ngap {

class UeRadioCapability {
 public:
  UeRadioCapability();
  // UeRadioCapability(const OCTET_STRING_t& capability);
  // UeRadioCapability(const bstring& capability);
  virtual ~UeRadioCapability();

  bool set(const OCTET_STRING_t& capability);
  bool get(OCTET_STRING_t& capability) const;

  bool set(const bstring& capability);
  bool get(bstring& capability) const;

  bool encode(Ngap_UERadioCapability_t& ueRadioCapability) const;
  bool decode(const Ngap_UERadioCapability_t& ueRadioCapability);

 private:
  bstring m_UeRadioCapability;
};

}  // namespace oai::ngap

#endif
