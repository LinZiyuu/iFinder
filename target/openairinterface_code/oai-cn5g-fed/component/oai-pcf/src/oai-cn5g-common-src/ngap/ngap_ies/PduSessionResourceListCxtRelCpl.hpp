/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_LIST_CXT_REL_CPL_H_
#define _PDU_SESSION_RESOURCE_LIST_CXT_REL_CPL_H_

#include <vector>

#include "PduSessionResourceItemCxtRelCpl.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceItemCxtRelCpl.h"
#include "Ngap_PDUSessionResourceListCxtRelCpl.h"
}

namespace oai::ngap {

class PduSessionResourceListCxtRelCpl {
 public:
  PduSessionResourceListCxtRelCpl();
  virtual ~PduSessionResourceListCxtRelCpl();

  void set(const std::vector<PduSessionResourceItemCxtRelCpl>& list);
  void get(std::vector<PduSessionResourceItemCxtRelCpl>& list) const;

  bool encode(Ngap_PDUSessionResourceListCxtRelCpl_t&
                  pduSessionResourceListCxtRelCpl) const;
  bool decode(const Ngap_PDUSessionResourceListCxtRelCpl_t&
                  pduSessionResourceListCxtRelCpl);

 private:
  std::vector<PduSessionResourceItemCxtRelCpl> m_ItemList;
};

}  // namespace oai::ngap

#endif
