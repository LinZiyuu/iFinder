/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_MODIFY_LIST_MOD_REQ_H_
#define _PDU_SESSION_RESOURCE_MODIFY_LIST_MOD_REQ_H_

#include <vector>

#include "PduSessionResourceModifyItemModReq.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceModifyListModReq.h"
}

namespace oai::ngap {

class PduSessionResourceModifyListModReq {
 public:
  PduSessionResourceModifyListModReq();
  virtual ~PduSessionResourceModifyListModReq();

  void set(const std::vector<PduSessionResourceModifyItemModReq>& list);
  void get(std::vector<PduSessionResourceModifyItemModReq>& list) const;

  bool encode(
      Ngap_PDUSessionResourceModifyListModReq_t& pduSessionResourceList) const;
  bool decode(
      const Ngap_PDUSessionResourceModifyListModReq_t& pduSessionResourceList);

 private:
  std::vector<PduSessionResourceModifyItemModReq> m_ItemList;
};

}  // namespace oai::ngap

#endif
