/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_RELEASE_LIST_CMD_H_
#define _PDU_SESSION_RESOURCE_RELEASE_LIST_CMD_H_

#include <vector>

#include "PduSessionResourceReleaseItemCmd.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceToReleaseListRelCmd.h"
}

constexpr uint16_t kMaxNoOfPduSessions = 256;

namespace oai::ngap {

class PduSessionResourceReleaseListCmd {
 public:
  PduSessionResourceReleaseListCmd();
  virtual ~PduSessionResourceReleaseListCmd();

  void set(const std::vector<PduSessionResourceReleaseItemCmd>& itemList);
  void get(std::vector<PduSessionResourceReleaseItemCmd>& itemList) const;

  bool encode(Ngap_PDUSessionResourceToReleaseListRelCmd_t&
                  pduSessionResourceReleaseListCmd) const;
  bool decode(const Ngap_PDUSessionResourceToReleaseListRelCmd_t&
                  pduSessionResourceReleaseListCmd);

 private:
  std::vector<PduSessionResourceReleaseItemCmd> m_ItemList;
};

}  // namespace oai::ngap

#endif
