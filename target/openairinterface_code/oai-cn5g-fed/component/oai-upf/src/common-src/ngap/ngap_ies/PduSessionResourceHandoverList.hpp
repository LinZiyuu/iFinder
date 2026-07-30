/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_HANDOVER_LIST_H_
#define _PDU_SESSION_RESOURCE_HANDOVER_LIST_H_

#include "PduSessionResourceItem.hpp"
#include "vector"

extern "C" {
#include "Ngap_PDUSessionResourceHandoverList.h"
}

namespace oai::ngap {

class PduSessionResourceHandoverList {
 public:
  PduSessionResourceHandoverList();
  virtual ~PduSessionResourceHandoverList();

  void set(const std::vector<PduSessionResourceItem>& list);
  void get(std::vector<PduSessionResourceItem>& list) const;

  bool encode(Ngap_PDUSessionResourceHandoverList_t& list) const;
  bool decode(const Ngap_PDUSessionResourceHandoverList_t& list);

 private:
  std::vector<PduSessionResourceItem> m_ItemList;
};

}  // namespace oai::ngap

#endif
