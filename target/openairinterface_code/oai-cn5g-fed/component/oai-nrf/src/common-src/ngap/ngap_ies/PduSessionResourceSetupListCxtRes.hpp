/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_SETUP_LIST_CXT_RES_H_
#define _PDU_SESSION_RESOURCE_SETUP_LIST_CXT_RES_H_

#include <vector>

#include "PduSessionResourceSetupItemCxtRes.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceSetupListCxtRes.h"
}

namespace oai::ngap {

class PduSessionResourceSetupListCxtRes {
 public:
  PduSessionResourceSetupListCxtRes();
  virtual ~PduSessionResourceSetupListCxtRes();

  void set(const std::vector<PduSessionResourceSetupItemCxtRes>& list);
  void get(std::vector<PduSessionResourceSetupItemCxtRes>& list) const;

  bool encode(Ngap_PDUSessionResourceSetupListCxtRes_t&
                  pduSessionResourceSetupListCxtRes) const;
  bool decode(const Ngap_PDUSessionResourceSetupListCxtRes_t&
                  pduSessionResourceSetupListCxtRes);

 private:
  std::vector<PduSessionResourceSetupItemCxtRes> m_ItemList;
};

}  // namespace oai::ngap

#endif
