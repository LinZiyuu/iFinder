/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PAGING_H_
#define _PAGING_H_

#include "NgapMessage.hpp"
#include "TaiListforPaging.hpp"
#include "UePagingIdentity.hpp"

extern "C" {
#include "Ngap_NGAP-PDU.h"
#include "Ngap_Paging.h"
#include "Ngap_ProtocolIE-Field.h"
}

namespace oai::ngap {

class PagingMsg : public NgapMessage {
 public:
  PagingMsg();
  virtual ~PagingMsg();

  void initialize();
  bool decode(Ngap_NGAP_PDU_t* ngap_msg_pdu) override;

  void setUePagingIdentity(
      const std::string& setId, const std::string& pointer,
      const std::string tmsi);
  void getUePagingIdentity(std::string& _5g_s_tmsi) const;
  void getUePagingIdentity(
      std::string& setId, std::string& pointer, std::string& tmsi) const;

  void setTaiListForPaging(const std::vector<Tai_t>& list);
  void getTaiListForPaging(std::vector<Tai_t>& list) const;

 private:
  Ngap_Paging_t* m_PagingIes;

  UePagingIdentity m_UePagingIdentity;  // Mandatory
  // TODO: Paging DRX (Optional)
  TaiListForPaging m_TaiListForPaging;  // Mandatory
  // TODO: Paging Priority (Optional)
  // TODO: UE Radio Capability for Paging (Optional)
  // TODO: Paging Origin (Optional)
  // TODO: Assistance Data for Paging (Optional)
  // TODO: NB-IoT Paging eDRX Information (Optional, Rel 16.14.0)
  // TODO: NB-IoT Paging DRX (Optional, Rel 16.14.0)
  // TODO: Enhanced Coverage Restriction (Optional, Rel 16.14.0)
  // TODO: WUS Assistance Information (Optional, Rel 16.14.0)
  // TODO: Paging eDRX Information (Optional, Rel 16.14.0)
  // TODO: CE-mode-B Restricted (Optional, Rel 16.14.0)
};

}  // namespace oai::ngap

#endif
