/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _CORE_NETWORK_ASSISTANCE_INFORMATION_FOR_INACTIVE_H_
#define _CORE_NETWORK_ASSISTANCE_INFORMATION_FOR_INACTIVE_H_

#include <optional>

#include "DefaultPagingDrx.hpp"
#include "MicoModeIndication.hpp"
#include "PeriodicRegistrationUpdateTimer.hpp"
#include "Tai.hpp"
#include "UeIdentityIndexValue.hpp"

extern "C" {
#include "Ngap_CoreNetworkAssistanceInformationForInactive.h"
}

namespace oai::ngap {

class CoreNetworkAssistanceInformationForInactive {
 public:
  CoreNetworkAssistanceInformationForInactive();
  virtual ~CoreNetworkAssistanceInformationForInactive(){};

  void set(
      const UeIdentityIndexValue& ueIdentityIndexValue,
      const DefaultPagingDrx& pagingDrx,
      const PeriodicRegistrationUpdateTimer& periodicRegistrationUpdateTimer,
      bool micoModeIndication, const std::vector<Tai>& tai);

  void get(
      UeIdentityIndexValue& ueIdentityIndexValue,
      std::optional<DefaultPagingDrx>& pagingDrx,
      PeriodicRegistrationUpdateTimer& periodicRegistrationUpdateTimer,
      bool& micoModeIndication, std::vector<Tai>& tai) const;

  bool encode(Ngap_CoreNetworkAssistanceInformationForInactive_t&
                  coreNetworkAssistanceInformation) const;
  bool decode(const Ngap_CoreNetworkAssistanceInformationForInactive_t&
                  coreNetworkAssistanceInformation);

 private:
  UeIdentityIndexValue m_UeIdentityIndexValue;  // Mandatory
  std::optional<DefaultPagingDrx> m_PagingDRX;  // UE Specific DRX, Optional
  PeriodicRegistrationUpdateTimer m_PeriodicRegUpdateTimer;  // Mandatory
  std::optional<MicoModeIndication> m_MicoModeInd;           // Optional
  std::vector<Tai> m_TaiList;  // Tai List for RRC Inactive, Mandatory
  // TODO: Expected UE Behaviour (Optional)
  // TODO: Paging eDRX Information (Optional)
  // TODO: Extended UE Identity Index Value (Optional)
  // TODO:UE Radio Capability for Paging (Optional)
  // TODO:MICO All PLMN (Optional)
  // TODO:Hashed UE Identity Index Value (Optional)
};

}  // namespace oai::ngap

#endif
