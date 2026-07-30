/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_SETUP_LIST_SU_RES_H_
#define _PDU_SESSION_RESOURCE_SETUP_LIST_SU_RES_H_

#include <vector>

#include "PduSessionResourceSetupItemSURes.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceSetupListSURes.h"
}

namespace oai::ngap {

class PduSessionResourceSetupListSURes {
 public:
  PduSessionResourceSetupListSURes();
  virtual ~PduSessionResourceSetupListSURes();

  void set(const std::vector<PduSessionResourceSetupItemSURes>& list);
  void get(std::vector<PduSessionResourceSetupItemSURes>& list) const;

  bool encode(
      Ngap_PDUSessionResourceSetupListSURes_t& pduSessionResourceList) const;
  bool decode(
      const Ngap_PDUSessionResourceSetupListSURes_t& pduSessionResourceList);

 private:
  std::vector<PduSessionResourceSetupItemSURes> m_ItemList;
};

}  // namespace oai::ngap

#endif
