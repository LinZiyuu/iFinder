/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _NG_RESET_ACK_H_
#define _NG_RESET_ACK_H_

#include <optional>

#include "NgapIesStruct.hpp"
#include "NgapMessage.hpp"
#include "UeAssociatedLogicalNgConnectionItem.hpp"
#include "UeAssociatedLogicalNgConnectionList.hpp"

namespace oai::ngap {

class NgResetAckMsg : public NgapMessage {
 public:
  NgResetAckMsg();
  virtual ~NgResetAckMsg();

  void initialize();

  void setUeAssociatedLogicalNgConnectionList(
      const std::vector<UeAssociatedLogicalNgConnectionItem>& list);
  void getUeAssociatedLogicalNgConnectionList(
      std::vector<UeAssociatedLogicalNgConnectionItem>& list) const;

  void addUeAssociatedLogicalNgConnectionList();

  bool decode(Ngap_NGAP_PDU_t* ngapMsgPdu) override;
  // TODO: CriticalityDiagnostics

 private:
  Ngap_NGResetAcknowledge_t* m_NgResetAckIes;

  std::optional<UeAssociatedLogicalNgConnectionList>
      m_UeAssociatedLogicalNgConnectionList;                // Optional
  Ngap_CriticalityDiagnostics_t* m_CriticalityDiagnostics;  // TODO: Optional
};

}  // namespace oai::ngap

#endif
