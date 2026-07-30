/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _NG_RESET_H_
#define _NG_RESET_H_

#include "Cause.hpp"
#include "NgapIesStruct.hpp"
#include "NgapMessage.hpp"
#include "ResetType.hpp"

namespace oai::ngap {

class NgResetMsg : public NgapMessage {
 public:
  NgResetMsg();
  virtual ~NgResetMsg();

  void initialize();

  void setCause(const Cause&);
  void getCause(Cause&) const;

  void setResetType(const ResetType&);
  bool getResetType(ResetType&) const;

  bool decode(Ngap_NGAP_PDU_t* ngapMsgPdu) override;

 private:
  Ngap_NGReset_t* m_NgResetIes;

  Cause m_Cause;          // Mandatory
  ResetType m_ResetType;  // Mandatory
};

}  // namespace oai::ngap

#endif
