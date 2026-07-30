/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef PDU_SESSION_RESOURCE_FAILED_TO_SETUP_LIST_HO_ACK_H_
#define PDU_SESSION_RESOURCE_FAILED_TO_SETUP_LIST_HO_ACK_H_

#include <vector>

#include "PduSessionResourceItem.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceFailedToSetupListHOAck.h"
}

namespace oai::ngap {

class PduSessionResourceFailedToSetupListHoAck {
 public:
  PduSessionResourceFailedToSetupListHoAck();
  virtual ~PduSessionResourceFailedToSetupListHoAck();

  void set(const std::vector<PduSessionResourceItem>& list);
  void get(std::vector<PduSessionResourceItem>& list) const;

  bool encode(Ngap_PDUSessionResourceFailedToSetupListHOAck_t& list) const;
  bool decode(const Ngap_PDUSessionResourceFailedToSetupListHOAck_t& list);

 private:
  std::vector<PduSessionResourceItem> m_ItemList;
};

}  // namespace oai::ngap

#endif
