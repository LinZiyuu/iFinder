/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UE_RADIO_CAPABILITY_FOR_PAGING_OF_NR_H_
#define _UE_RADIO_CAPABILITY_FOR_PAGING_OF_NR_H_

#include "bstrlib.h"

extern "C" {
#include "Ngap_UERadioCapabilityForPagingOfNR.h"
}

namespace oai::ngap {

class UeRadioCapabilityForPagingOfNr {
 public:
  UeRadioCapabilityForPagingOfNr();
  virtual ~UeRadioCapabilityForPagingOfNr();

  bool set(const OCTET_STRING_t& capability);
  bool get(OCTET_STRING_t& capability) const;

  bool set(const bstring& capability);
  bool get(bstring& capability) const;

  bool encode(Ngap_UERadioCapabilityForPagingOfNR_t&
                  ueRadioCapabilityForPagingOfNr) const;
  bool decode(const Ngap_UERadioCapabilityForPagingOfNR_t&
                  ueRadioCapabilityForPagingOfNr);

 private:
  OCTET_STRING_t m_UeRadioCapability;
};

}  // namespace oai::ngap

#endif
