/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _INITIAL_CONTEXT_SETUP_FAILURE_H_
#define _INITIAL_CONTEXT_SETUP_FAILURE_H_

#include <optional>

#include "Cause.hpp"
#include "NgapUeMessage.hpp"
#include "PduSessionResourceFailedToSetupListCxtFail.hpp"

extern "C" {
#include "Ngap_InitialContextSetupFailure.h"
}

namespace oai::ngap {

class InitialContextSetupFailureMsg : public NgapUeMessage {
 public:
  InitialContextSetupFailureMsg();
  virtual ~InitialContextSetupFailureMsg();

  void initialize();
  void setAmfUeNgapId(const uint64_t& id) override;
  void setRanUeNgapId(const uint32_t& id) override;
  bool decode(Ngap_NGAP_PDU_t* ngapMsgPdu) override;

  void setPduSessionResourceFailedToSetupList(
      const std::vector<PDUSessionResourceFailedToSetupItem_t>& list);
  bool getPduSessionResourceFailedToSetupList(
      std::vector<PDUSessionResourceFailedToSetupItem_t>& list) const;

  void setCause(const long& cause, const Ngap_Cause_PR& cause_present);
  void setCause(const Cause& cause);
  void getCause(Cause& cause) const;

 private:
  Ngap_InitialContextSetupFailure_t* m_InitialContextSetupFailureIes;

  std::optional<PduSessionResourceFailedToSetupListCxtFail>
      m_PduSessionResourceFailedToSetupFailureList;  // Optional
  Cause m_Cause;                                     // Mandatory
  // TODO: Criticality Diagnostics //Optional
};

}  // namespace oai::ngap
#endif
