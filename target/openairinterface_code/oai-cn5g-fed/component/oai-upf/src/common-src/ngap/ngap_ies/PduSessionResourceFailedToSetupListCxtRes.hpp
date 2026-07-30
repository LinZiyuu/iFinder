/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_FAILED_TO_SETUP_LIST_CXT_RES_H_
#define _PDU_SESSION_RESOURCE_FAILED_TO_SETUP_LIST_CXT_RES_H_

#include <vector>

#include "PduSessionResourceFailedToSetupItemCxtRes.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceFailedToSetupListCxtRes.h"
}

namespace oai::ngap {

class PduSessionResourceFailedToSetupListCxtRes {
 public:
  PduSessionResourceFailedToSetupListCxtRes();
  virtual ~PduSessionResourceFailedToSetupListCxtRes();

  void set(const std::vector<PduSessionResourceFailedToSetupItemCxtRes>& list);
  void get(std::vector<PduSessionResourceFailedToSetupItemCxtRes>& list) const;

  bool encode(Ngap_PDUSessionResourceFailedToSetupListCxtRes_t&
                  pduSessionResourceFailedToSetupListCxtRes) const;
  bool decode(const Ngap_PDUSessionResourceFailedToSetupListCxtRes_t&
                  pduSessionResourceFailedToSetupListCxtRes);

 private:
  std::vector<PduSessionResourceFailedToSetupItemCxtRes> m_ItemList;
};

}  // namespace oai::ngap

#endif
