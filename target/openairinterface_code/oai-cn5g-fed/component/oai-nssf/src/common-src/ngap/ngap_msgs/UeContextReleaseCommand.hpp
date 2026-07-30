/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UE_CONTEXT_RELEASE_COMMAND_H_
#define _UE_CONTEXT_RELEASE_COMMAND_H_

#include "AmfUeNgapId.hpp"
#include "Cause.hpp"
#include "NgapUeMessage.hpp"
#include "RanUeNgapId.hpp"

extern "C" {
#include "Ngap_UEContextReleaseCommand.h"
}

namespace oai::ngap {

class UeContextReleaseCommandMsg : public NgapMessage {
 public:
  UeContextReleaseCommandMsg();
  ~UeContextReleaseCommandMsg();

  void initialize();

  bool decode(Ngap_NGAP_PDU_t* ngapMsgPdu) override;

  void setAmfUeNgapId(const uint64_t& id);
  bool getAmfUeNgapId(uint64_t& id) const;

  void setUeNgapIdPair(const uint64_t& amfId, const uint32_t& ranId);
  bool getUeNgapIdPair(uint64_t& amfId, uint32_t& ranId) const;

  void addCauseIe();
  void setCauseRadioNetwork(const e_Ngap_CauseRadioNetwork& cause);
  void setCauseNas(const e_Ngap_CauseNas& cause);

 private:
  Ngap_UEContextReleaseCommand_t* m_UEContextReleaseCommandIes;
  AmfUeNgapId m_AmfUeNgapId;
  std::optional<RanUeNgapId>
      m_RanUeNgapId;   // CHOICE UE NGAP IDs: AMF UE NGAP ID
  Cause m_CauseValue;  // Mandatory
};

}  // namespace oai::ngap

#endif
