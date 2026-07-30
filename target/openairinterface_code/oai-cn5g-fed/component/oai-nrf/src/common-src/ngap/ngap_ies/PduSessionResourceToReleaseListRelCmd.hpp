/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_TO_RELEASE_LIST_REL_CMD_H_
#define _PDU_SESSION_RESOURCE_TO_RELEASE_LIST_REL_CMD_H_

#include <vector>

#include "PduSessionResourceToReleaseItemRelCmd.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceToReleaseItemRelCmd.h"
#include "Ngap_PDUSessionResourceToReleaseListRelCmd.h"
}

namespace oai::ngap {

class PduSessionResourceToReleaseListRelCmd {
 public:
  PduSessionResourceToReleaseListRelCmd();
  virtual ~PduSessionResourceToReleaseListRelCmd();

  void set(const std::vector<PduSessionResourceToReleaseItemRelCmd>& list);
  void get(std::vector<PduSessionResourceToReleaseItemRelCmd>& list) const;

  bool encode(Ngap_PDUSessionResourceToReleaseListRelCmd_t&
                  pduSessionResourceToReleaseListRelCmd) const;
  bool decode(const Ngap_PDUSessionResourceToReleaseListRelCmd_t&
                  pduSessionResourceToReleaseListRelCmd);

 private:
  std::vector<PduSessionResourceToReleaseItemRelCmd> m_ItemList;
};

}  // namespace oai::ngap

#endif
