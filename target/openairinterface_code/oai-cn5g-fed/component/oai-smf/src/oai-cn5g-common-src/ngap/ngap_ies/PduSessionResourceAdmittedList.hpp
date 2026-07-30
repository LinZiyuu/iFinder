/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef PDU_SESSION_RESOURCE_ADMITTED_LIST_H_
#define PDU_SESSION_RESOURCE_ADMITTED_LIST_H_

#include <vector>

#include "PduSessionResourceItem.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceAdmittedList.h"
}

namespace oai::ngap {

class PduSessionResourceAdmittedList {
 public:
  PduSessionResourceAdmittedList();
  virtual ~PduSessionResourceAdmittedList();

  void set(const std::vector<PduSessionResourceItem>& list);
  void get(std::vector<PduSessionResourceItem>& list) const;

  bool encode(Ngap_PDUSessionResourceAdmittedList_t& list) const;
  bool decode(const Ngap_PDUSessionResourceAdmittedList_t& List);

 private:
  std::vector<PduSessionResourceItem> m_ItemList;
};

}  // namespace oai::ngap

#endif
