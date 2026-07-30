/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_LIST_HO_RQD_H_
#define _PDU_SESSION_RESOURCE_LIST_HO_RQD_H_

#include <vector>

#include "PduSessionResourceItem.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceListHORqd.h"
}

namespace oai::ngap {

class PduSessionResourceListHandoverRqd {
 public:
  PduSessionResourceListHandoverRqd();
  virtual ~PduSessionResourceListHandoverRqd();

  void set(const std::vector<PduSessionResourceItem>& list);
  void get(std::vector<PduSessionResourceItem>& list) const;

  bool encode(Ngap_PDUSessionResourceListHORqd_t& list) const;
  bool decode(const Ngap_PDUSessionResourceListHORqd_t& list);

 private:
  std::vector<PduSessionResourceItem> m_ItemList;
};

}  // namespace oai::ngap

#endif
