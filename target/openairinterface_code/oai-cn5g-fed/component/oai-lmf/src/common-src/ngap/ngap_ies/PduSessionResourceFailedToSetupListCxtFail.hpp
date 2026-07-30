/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_FAILED_TO_SETUP_LIST_CXT_FAIL_H_
#define _PDU_SESSION_RESOURCE_FAILED_TO_SETUP_LIST_CXT_FAIL_H_

#include <vector>

#include "PduSessionResourceFailedToSetupItemCxtFail.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceFailedToSetupListCxtFail.h"
}

namespace oai::ngap {

class PduSessionResourceFailedToSetupListCxtFail {
 public:
  PduSessionResourceFailedToSetupListCxtFail();
  virtual ~PduSessionResourceFailedToSetupListCxtFail();

  void set(const std::vector<PduSessionResourceFailedToSetupItemCxtFail>& list);
  void get(std::vector<PduSessionResourceFailedToSetupItemCxtFail>& list) const;

  bool encode(Ngap_PDUSessionResourceFailedToSetupListCxtFail_t&
                  pduSessionResourceFailedToSetupListCxtFail) const;
  bool decode(const Ngap_PDUSessionResourceFailedToSetupListCxtFail_t&
                  pduSessionResourceFailedToSetupListCxtFail);

 private:
  std::vector<PduSessionResourceFailedToSetupItemCxtFail> m_ItemList;
};

}  // namespace oai::ngap

#endif
