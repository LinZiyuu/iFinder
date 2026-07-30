/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _HANDOVER_COMMAND_H_
#define _HANDOVER_COMMAND_H_

#include <optional>

#include "NgapUeMessage.hpp"
#include "PduSessionResourceHandoverList.hpp"
#include "PduSessionResourceToReleaseListHandoverCmd.hpp"

extern "C" {
#include "Ngap_HandoverCommand.h"
#include "Ngap_NGAP-PDU.h"
}

namespace oai::ngap {

class HandoverCommandMsg : public NgapUeMessage {
 public:
  HandoverCommandMsg();
  virtual ~HandoverCommandMsg();

  void initialize();
  void setAmfUeNgapId(const uint64_t& id) override;
  void setRanUeNgapId(const uint32_t& id) override;
  bool decode(Ngap_NGAP_PDU_t* ngapMsgPdu) override;

  void setHandoverType(const long& type);
  // void getHandoverType(Ngap_HandoverType_t &type);

  void setNasSecurityParametersFromNgRan(
      const OCTET_STRING_t& nasSecurityParameters);
  bool getNasSecurityParametersFromNgRan(
      OCTET_STRING_t& nasSecurityParameters) const;

  void setPduSessionResourceHandoverList(
      const PduSessionResourceHandoverList& list);
  bool getPduSessionResourceHandoverList(
      PduSessionResourceHandoverList& list) const;

  void setPduSessionResourceToReleaseListHOCmd(
      const PduSessionResourceToReleaseListHandoverCmd& list);
  bool getPduSessionResourceToReleaseListHOCmd(
      PduSessionResourceToReleaseListHandoverCmd& list) const;

  void setTargetToSourceTransparentContainer(
      const OCTET_STRING_t& targetTosource);
  void getTargetToSourceTransparentContainer(
      OCTET_STRING_t& targetTosource) const;

 private:
  Ngap_HandoverCommand_t* m_HandoverCommandIes;

  // AMF_UE_NGAP_ID (Mandatory)
  // RAN_UE_NGAP_ID (Mandatory)
  Ngap_HandoverType_t m_HandoverType;  // Mandatory
  std::optional<Ngap_NASSecurityParametersFromNGRAN_t>
      m_NasSecurityParametersFromNgRan;  // TODO: Conditional
  std::optional<PduSessionResourceHandoverList>
      m_PduSessionResourceHandoverList;  // Optional
  std::optional<PduSessionResourceToReleaseListHandoverCmd>
      m_PduSessionResourceToReleaseListHOCmd;
  Ngap_TargetToSource_TransparentContainer_t
      m_TargetToSourceTransparentContainer;                 // TODO: Mandatory
  Ngap_CriticalityDiagnostics_t* m_CriticalityDiagnostics;  // TODO: Optional
};

}  // namespace oai::ngap

#endif
