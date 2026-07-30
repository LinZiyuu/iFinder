/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UE_RADIO_CAPABILITY_FOR_PAGING_OF_EUTRA_H_
#define _UE_RADIO_CAPABILITY_FOR_PAGING_OF_EUTRA_H_

#include "bstrlib.h"

extern "C" {
#include "Ngap_UERadioCapabilityForPagingOfEUTRA.h"
}

namespace oai::ngap {

class UeRadioCapabilityForPagingOfEutra {
 public:
  UeRadioCapabilityForPagingOfEutra();
  virtual ~UeRadioCapabilityForPagingOfEutra();

  bool set(const OCTET_STRING_t& capability);
  bool get(OCTET_STRING_t& capability) const;

  bool set(const bstring& capability);
  bool get(bstring& capability) const;

  bool encode(Ngap_UERadioCapabilityForPagingOfEUTRA_t&
                  ueRadioCapabilityForPagingOfEutra) const;
  bool decode(const Ngap_UERadioCapabilityForPagingOfEUTRA_t&
                  ueRadioCapabilityForPagingOfEutra);

 private:
  OCTET_STRING_t m_UeRadioCapability;
};

}  // namespace oai::ngap

#endif
