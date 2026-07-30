/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UE_RADIO_CAPABILITY_FOR_PAGING_H_
#define _UE_RADIO_CAPABILITY_FOR_PAGING_H_

#include <optional>

#include "UeRadioCapabilityForPagingOfEutra.hpp"
#include "UeRadioCapabilityForPagingOfNr.hpp"

extern "C" {
#include "Ngap_UERadioCapabilityForPaging.h"
}

namespace oai::ngap {

class UeRadioCapabilityForPaging {
 public:
  UeRadioCapabilityForPaging();
  virtual ~UeRadioCapabilityForPaging();

  void setUeRadioCapabilityForPagingOfNr(const OCTET_STRING_t& capability);
  bool getUeRadioCapabilityForPagingOfNr(OCTET_STRING_t& capability) const;

  void setUeRadioCapabilityForPagingOfEutra(const OCTET_STRING_t& capability);
  bool getUeRadioCapabilityForPagingOfEutra(OCTET_STRING_t& capability) const;

  bool encode(
      Ngap_UERadioCapabilityForPaging_t& ueRadioCapabilityForPaging) const;
  bool decode(
      const Ngap_UERadioCapabilityForPaging_t& ueRadioCapabilityForPaging);

 private:
  std::optional<UeRadioCapabilityForPagingOfNr>
      m_UeRadioCapabilityForPagingOfNr;  // Optional
  std::optional<UeRadioCapabilityForPagingOfEutra>
      m_UeRadioCapabilityForPagingOfEutra;  // Optional
};

}  // namespace oai::ngap

#endif
