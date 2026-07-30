/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_TO_RELEASE_LIST_HO_CMD_H_
#define _PDU_SESSION_RESOURCE_TO_RELEASE_LIST_HO_CMD_H_

#include <vector>

#include "PduSessionResourceItem.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceToReleaseListHOCmd.h"
}

namespace oai::ngap {

class PduSessionResourceToReleaseListHandoverCmd {
 public:
  PduSessionResourceToReleaseListHandoverCmd();
  virtual ~PduSessionResourceToReleaseListHandoverCmd();

  void set(const std::vector<PduSessionResourceItem>& list);
  void get(std::vector<PduSessionResourceItem>& list) const;

  bool encode(Ngap_PDUSessionResourceToReleaseListHOCmd_t& list) const;
  bool decode(const Ngap_PDUSessionResourceToReleaseListHOCmd_t& list);

 private:
  std::vector<PduSessionResourceItem> m_ItemList;
};

}  // namespace oai::ngap

#endif
