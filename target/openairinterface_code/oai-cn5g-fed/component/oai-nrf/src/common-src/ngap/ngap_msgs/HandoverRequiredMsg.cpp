/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "HandoverRequiredMsg.hpp"

#include "logger_base.hpp"
#include "ngap_utils.hpp"
#include "utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
HandoverRequiredMsg::HandoverRequiredMsg() : NgapUeMessage() {
  m_DirectForwardingPathAvailability = std::nullopt;
  m_HandoverRequiredIes              = nullptr;

  setMessageType(NgapMessageType::HANDOVER_REQUIRED);
  initialize();
}

//------------------------------------------------------------------------------
HandoverRequiredMsg::~HandoverRequiredMsg() {}

//------------------------------------------------------------------------------
void HandoverRequiredMsg::initialize() {
  m_HandoverRequiredIes =
      &ngapPdu->choice.initiatingMessage->value.choice.HandoverRequired;
}

//------------------------------------------------------------------------------
void HandoverRequiredMsg::setAmfUeNgapId(const uint64_t& id) {
  NgapUeMessage::m_AmfUeNgapId.set(id);

  Ngap_HandoverRequiredIEs_t* ie = (Ngap_HandoverRequiredIEs_t*) calloc(
      1, sizeof(Ngap_HandoverRequiredIEs_t));
  ie->id            = Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID;
  ie->criticality   = Ngap_Criticality_reject;
  ie->value.present = Ngap_HandoverRequiredIEs__value_PR_AMF_UE_NGAP_ID;

  int ret =
      NgapUeMessage::m_AmfUeNgapId.encode(ie->value.choice.AMF_UE_NGAP_ID);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode AMF_UE_NGAP_ID IE error!");
    oai::utils::utils::free_wrapper((void**) &ie);
    return;
  }

  ret = ASN_SEQUENCE_ADD(&m_HandoverRequiredIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error("Encode AMF_UE_NGAP_ID IE error!");
}

//------------------------------------------------------------------------------
void HandoverRequiredMsg::setRanUeNgapId(const uint32_t& ranUeNgapId) {
  NgapUeMessage::m_RanUeNgapId.set(ranUeNgapId);

  Ngap_HandoverRequiredIEs_t* ie = (Ngap_HandoverRequiredIEs_t*) calloc(
      1, sizeof(Ngap_HandoverRequiredIEs_t));
  ie->id            = Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID;
  ie->criticality   = Ngap_Criticality_reject;
  ie->value.present = Ngap_HandoverRequiredIEs__value_PR_RAN_UE_NGAP_ID;

  int ret =
      NgapUeMessage::m_RanUeNgapId.encode(ie->value.choice.RAN_UE_NGAP_ID);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode RAN_UE_NGAP_ID IE error!");
    oai::utils::utils::free_wrapper((void**) &ie);
    return;
  }

  ret = ASN_SEQUENCE_ADD(&m_HandoverRequiredIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error("Encode RAN_UE_NGAP_ID IE error!");
}

//------------------------------------------------------------------------------
Ngap_HandoverType_t HandoverRequiredMsg::getHandoverType() const {
  return m_HandoverType;
}

//------------------------------------------------------------------------------
Ngap_Cause_PR HandoverRequiredMsg::getChoiceOfCause() const {
  return m_Cause.getChoiceOfCause();
}

//------------------------------------------------------------------------------
long HandoverRequiredMsg::getCauseValue() const {
  return m_Cause.get();
}

bool HandoverRequiredMsg::getTargetId(GlobalGnbId& gnbId, Tai& tai) const {
  if (m_TargetId.present == Ngap_TargetID_PR_targetRANNodeID) {
    if (m_TargetId.choice.targetRANNodeID->globalRANNodeID.present ==
        Ngap_GlobalRANNodeID_PR_globalGNB_ID) {
      gnbId.decode(*m_TargetId.choice.targetRANNodeID->globalRANNodeID.choice
                        .globalGNB_ID);
      tai.decode(m_TargetId.choice.targetRANNodeID->selectedTAI);
      return true;
    }
  }
  return false;
}

//------------------------------------------------------------------------------
OCTET_STRING_t HandoverRequiredMsg::getSourceToTargetTransparentContainer()
    const {
  return m_SourceToTargetTransparentContainer;
}

//------------------------------------------------------------------------------
bool HandoverRequiredMsg::getPduSessionResourceList(
    PduSessionResourceListHandoverRqd& list) const {
  list = m_PduSessionResourceList;
  return true;
}

//------------------------------------------------------------------------------
bool HandoverRequiredMsg::getDirectForwardingPathAvailability(
    long& value) const {
  if (!m_DirectForwardingPathAvailability.has_value()) return false;
  value = m_DirectForwardingPathAvailability.value();
  return true;
}

//------------------------------------------------------------------------------
bool HandoverRequiredMsg::decode(Ngap_NGAP_PDU_t* ngapMsgPdu) {
  ngapPdu = ngapMsgPdu;

  if (ngapPdu->present == Ngap_NGAP_PDU_PR_initiatingMessage) {
    if (ngapPdu->choice.initiatingMessage &&
        ngapPdu->choice.initiatingMessage->procedureCode ==
            Ngap_ProcedureCode_id_HandoverPreparation &&
        ngapPdu->choice.initiatingMessage->criticality ==
            Ngap_Criticality_reject &&
        ngapPdu->choice.initiatingMessage->value.present ==
            Ngap_InitiatingMessage__value_PR_HandoverRequired) {
      m_HandoverRequiredIes =
          &ngapPdu->choice.initiatingMessage->value.choice.HandoverRequired;
    } else {
      oai::logger::logger_common::ngap().error(
          "Check HandoverRequired message error!");
      return false;
    }
  } else {
    oai::logger::logger_common::ngap().error(
        "HandoverRequired MessageType error!");
    return false;
  }
  for (int i = 0; i < m_HandoverRequiredIes->protocolIEs.list.count; i++) {
    switch (m_HandoverRequiredIes->protocolIEs.list.array[i]->id) {
      case Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID: {
        if (m_HandoverRequiredIes->protocolIEs.list.array[i]->criticality ==
                Ngap_Criticality_reject &&
            m_HandoverRequiredIes->protocolIEs.list.array[i]->value.present ==
                Ngap_HandoverRequiredIEs__value_PR_AMF_UE_NGAP_ID) {
          if (!NgapUeMessage::m_AmfUeNgapId.decode(
                  m_HandoverRequiredIes->protocolIEs.list.array[i]
                      ->value.choice.AMF_UE_NGAP_ID)) {
            oai::logger::logger_common::ngap().error(
                "Decoded NGAP AMF_UE_NGAP_ID IE error");
            return false;
          }
        } else {
          oai::logger::logger_common::ngap().error(
              "Decoded NGAP AMF_UE_NGAP_ID IE error");
          return false;
        }
      } break;
      case Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID: {
        if (m_HandoverRequiredIes->protocolIEs.list.array[i]->criticality ==
                Ngap_Criticality_reject &&
            m_HandoverRequiredIes->protocolIEs.list.array[i]->value.present ==
                Ngap_HandoverRequiredIEs__value_PR_RAN_UE_NGAP_ID) {
          if (!NgapUeMessage::m_RanUeNgapId.decode(
                  m_HandoverRequiredIes->protocolIEs.list.array[i]
                      ->value.choice.RAN_UE_NGAP_ID)) {
            oai::logger::logger_common::ngap().error(
                "Decoded NGAP RAN_UE_NGAP_ID IE error");
            return false;
          }
        } else {
          oai::logger::logger_common::ngap().error(
              "Decoded NGAP RAN_UE_NGAP_ID IE error");
          return false;
        }
      } break;
      case Ngap_ProtocolIE_ID_id_HandoverType: {
        if (m_HandoverRequiredIes->protocolIEs.list.array[i]->criticality ==
                Ngap_Criticality_reject &&
            m_HandoverRequiredIes->protocolIEs.list.array[i]->value.present ==
                Ngap_HandoverRequiredIEs__value_PR_HandoverType) {
          m_HandoverType = m_HandoverRequiredIes->protocolIEs.list.array[i]
                               ->value.choice.HandoverType;
        } else {
          oai::logger::logger_common::ngap().error(
              "Decoded NGAP Handover Type error");
          return false;
        }
      } break;
      case Ngap_ProtocolIE_ID_id_Cause: {
        if (m_HandoverRequiredIes->protocolIEs.list.array[i]->criticality ==
                Ngap_Criticality_ignore &&
            m_HandoverRequiredIes->protocolIEs.list.array[i]->value.present ==
                Ngap_HandoverRequiredIEs__value_PR_Cause) {
          if (!m_Cause.decode(m_HandoverRequiredIes->protocolIEs.list.array[i]
                                  ->value.choice.Cause)) {
            oai::logger::logger_common::ngap().error(
                "Decoded NGAP Cause IE error");
            return false;
          }
        } else {
          oai::logger::logger_common::ngap().error(
              "Decoded NGAP Cause IE error");
          return false;
        }
      } break;
      case Ngap_ProtocolIE_ID_id_TargetID: {
        if (m_HandoverRequiredIes->protocolIEs.list.array[i]->criticality ==
                Ngap_Criticality_reject &&
            m_HandoverRequiredIes->protocolIEs.list.array[i]->value.present ==
                Ngap_HandoverRequiredIEs__value_PR_TargetID) {
          m_TargetId = m_HandoverRequiredIes->protocolIEs.list.array[i]
                           ->value.choice.TargetID;
        } else {
          oai::logger::logger_common::ngap().error(
              "Decoded NGAP TargetID IE error");
          return false;
        }
      } break;
      case Ngap_ProtocolIE_ID_id_DirectForwardingPathAvailability: {
        if (m_HandoverRequiredIes->protocolIEs.list.array[i]->criticality ==
                Ngap_Criticality_ignore &&
            m_HandoverRequiredIes->protocolIEs.list.array[i]->value.present ==
                Ngap_HandoverRequiredIEs__value_PR_DirectForwardingPathAvailability) {
          m_DirectForwardingPathAvailability =
              std::optional<Ngap_DirectForwardingPathAvailability_t>(
                  m_HandoverRequiredIes->protocolIEs.list.array[i]
                      ->value.choice.DirectForwardingPathAvailability);
        } else {
          oai::logger::logger_common::ngap().error(
              "Decoded NGAP DirectForwardingPathAvailability IE error");
          return false;
        }
      } break;
      case Ngap_ProtocolIE_ID_id_PDUSessionResourceListHORqd: {
        if (m_HandoverRequiredIes->protocolIEs.list.array[i]->criticality ==
                Ngap_Criticality_reject &&
            m_HandoverRequiredIes->protocolIEs.list.array[i]->value.present ==
                Ngap_HandoverRequiredIEs__value_PR_PDUSessionResourceListHORqd) {
          if (!m_PduSessionResourceList.decode(
                  m_HandoverRequiredIes->protocolIEs.list.array[i]
                      ->value.choice.PDUSessionResourceListHORqd)) {
            oai::logger::logger_common::ngap().error(
                "Decoded NGAP PDUSessionResourceSetupListCxtRes IE error");
            return false;
          }
        } else {
          oai::logger::logger_common::ngap().error(
              "Decoded NGAP PDUSessionResourceSetupListCxtRes IE error");
          return false;
        }
      } break;
      case Ngap_ProtocolIE_ID_id_SourceToTarget_TransparentContainer: {
        if (m_HandoverRequiredIes->protocolIEs.list.array[i]->criticality ==
                Ngap_Criticality_reject &&
            m_HandoverRequiredIes->protocolIEs.list.array[i]->value.present ==
                Ngap_HandoverRequiredIEs__value_PR_SourceToTarget_TransparentContainer) {
          ngap_utils::octet_string_copy(
              m_SourceToTargetTransparentContainer,
              m_HandoverRequiredIes->protocolIEs.list.array[i]
                  ->value.choice.SourceToTarget_TransparentContainer);
        } else {
          oai::logger::logger_common::ngap().error(
              "Decoded NGAP SourceToTarget_TransparentContainer IE error");
          return false;
        }
      } break;
      default: {
        oai::logger::logger_common::ngap().error(
            "Decoded NGAP message PDU error");
        return false;
      }
    }
  }

  return true;
}

}  // namespace oai::ngap
