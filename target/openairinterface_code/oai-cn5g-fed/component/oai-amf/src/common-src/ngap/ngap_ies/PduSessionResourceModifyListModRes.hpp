/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_MODIFY_LIST_MOD_RES_H_
#define _PDU_SESSION_RESOURCE_MODIFY_LIST_MOD_RES_H_

#include <vector>

#include "PduSessionResourceModifyItemModRes.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceModifyListModRes.h"
}

namespace oai::ngap {

class PduSessionResourceModifyListModRes {
 public:
  PduSessionResourceModifyListModRes();
  virtual ~PduSessionResourceModifyListModRes();

  void set(const std::vector<PduSessionResourceModifyItemModRes>&
               pduSessionResourceModifyListModRes);
  void get(std::vector<PduSessionResourceModifyItemModRes>&
               pduSessionResourceModifyListModRes) const;

  bool encode(Ngap_PDUSessionResourceModifyListModRes_t&
                  pduSessionResourceModifyListModRes) const;
  bool decode(const Ngap_PDUSessionResourceModifyListModRes_t&
                  pduSessionResourceModifyListModRes);

 private:
  std::vector<PduSessionResourceModifyItemModRes> m_ItemList;
};

}  // namespace oai::ngap

#endif
