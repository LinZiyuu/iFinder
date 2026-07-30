/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_RELEASED_LIST_REL_RES_H_
#define _PDU_SESSION_RESOURCE_RELEASED_LIST_REL_RES_H_

#include <vector>

#include "PduSessionResourceReleasedItemRelRes.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceReleasedItemRelRes.h"
#include "Ngap_PDUSessionResourceReleasedListRelRes.h"
}

namespace oai::ngap {

class PduSessionResourceReleasedListRelRes {
 public:
  PduSessionResourceReleasedListRelRes();
  virtual ~PduSessionResourceReleasedListRelRes();

  void set(const std::vector<PduSessionResourceReleasedItemRelRes>& list);
  void get(std::vector<PduSessionResourceReleasedItemRelRes>& list) const;

  bool encode(Ngap_PDUSessionResourceReleasedListRelRes_t&
                  pduSessionResourceList) const;
  bool decode(const Ngap_PDUSessionResourceReleasedListRelRes_t&
                  pduSessionResourceList);

 private:
  std::vector<PduSessionResourceReleasedItemRelRes> m_ItemList;
};

}  // namespace oai::ngap

#endif
