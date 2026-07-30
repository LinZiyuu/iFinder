/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_FAILED_TO_SETUP_LIST_SU_RES_H_
#define _PDU_SESSION_RESOURCE_FAILED_TO_SETUP_LIST_SU_RES_H_

#include <vector>

#include "PduSessionResourceFailedToSetupItemSURes.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceFailedToSetupListSURes.h"
}

namespace oai::ngap {

class PduSessionResourceFailedToSetupListSURes {
 public:
  PduSessionResourceFailedToSetupListSURes();
  virtual ~PduSessionResourceFailedToSetupListSURes();

  void set(const std::vector<PduSessionResourceFailedToSetupItemSURes>& item);
  void get(std::vector<PduSessionResourceFailedToSetupItemSURes>& item) const;

  bool encode(Ngap_PDUSessionResourceFailedToSetupListSURes_t&
                  pduSessionResourceRes) const;
  bool decode(const Ngap_PDUSessionResourceFailedToSetupListSURes_t&
                  pduSessionResourceRes);

 private:
  std::vector<PduSessionResourceFailedToSetupItemSURes> m_ItemList;
};

}  // namespace oai::ngap

#endif
