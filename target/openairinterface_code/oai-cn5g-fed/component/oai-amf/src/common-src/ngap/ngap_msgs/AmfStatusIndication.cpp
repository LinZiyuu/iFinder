/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "AmfStatusIndication.hpp"

#include "logger_base.hpp"
#include "utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
AmfStatusIndication::AmfStatusIndication() : NgapMessage() {
  m_AmfStatusIndicationIEs = nullptr;
  NgapMessage::setMessageType(NgapMessageType::AMF_STATUS_INDICATION);
  initialize();
}

//------------------------------------------------------------------------------
AmfStatusIndication::~AmfStatusIndication() {}

//------------------------------------------------------------------------------
void AmfStatusIndication::initialize() {
  m_AmfStatusIndicationIEs =
      &(ngapPdu->choice.initiatingMessage->value.choice.AMFStatusIndication);
}

//------------------------------------------------------------------------------
void AmfStatusIndication::setUnavailableGuamiList(
    const UnavailableGuamiList& list) {
  m_UnavailableGuamiList = list;
}

//------------------------------------------------------------------------------
void AmfStatusIndication::getUnavailableGuamiList(
    UnavailableGuamiList& list) const {
  list = m_UnavailableGuamiList;
}

//------------------------------------------------------------------------------
bool AmfStatusIndication::decode(Ngap_NGAP_PDU_t* ngapMsgPdu) {
  ngapPdu = ngapMsgPdu;

  if (ngapPdu->present == Ngap_NGAP_PDU_PR_initiatingMessage) {
    if (ngapPdu->choice.initiatingMessage &&
        ngapPdu->choice.initiatingMessage->procedureCode ==
            Ngap_ProcedureCode_id_AMFStatusIndication &&
        ngapPdu->choice.initiatingMessage->criticality ==
            Ngap_Criticality_ignore &&
        ngapPdu->choice.initiatingMessage->value.present ==
            Ngap_InitiatingMessage__value_PR_AMFStatusIndication) {
      m_AmfStatusIndicationIEs =
          &ngapPdu->choice.initiatingMessage->value.choice.AMFStatusIndication;
    } else {
      oai::logger::logger_common::ngap().error(
          "Check AMFStatusIndication message error");
      return false;
    }
  } else {
    oai::logger::logger_common::ngap().error(
        "MessageType error, ngapPdu->present %d", ngapPdu->present);
    return false;
  }

  for (int i = 0; i < m_AmfStatusIndicationIEs->protocolIEs.list.count; i++) {
    switch (m_AmfStatusIndicationIEs->protocolIEs.list.array[i]->id) {
      case Ngap_ProtocolIE_ID_id_UnavailableGUAMIList: {
        if (m_AmfStatusIndicationIEs->protocolIEs.list.array[i]->criticality ==
                Ngap_Criticality_reject &&
            m_AmfStatusIndicationIEs->protocolIEs.list.array[i]
                    ->value.present ==
                Ngap_AMFStatusIndicationIEs__value_PR_UnavailableGUAMIList) {
          if (!m_UnavailableGuamiList.decode(
                  m_AmfStatusIndicationIEs->protocolIEs.list.array[i]
                      ->value.choice.UnavailableGUAMIList)) {
            oai::logger::logger_common::ngap().error(
                "Decoded NGAP UnavailableGUAMIList error");
            return false;
          }
        } else {
          oai::logger::logger_common::ngap().error(
              "Decoded NGAP UnavailableGUAMIList error");
          return false;
        }
      } break;
      default: {
        oai::logger::logger_common::ngap().error(
            "Decoded NGAP Message PDU error");
        return false;
      }
    }
  }

  return true;
}

}  // namespace oai::ngap
