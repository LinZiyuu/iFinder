/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "HandoverRequestAck.hpp"

#include "logger_base.hpp"
#include "ngap_utils.hpp"
#include "utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
HandoverRequestAck::HandoverRequestAck() : NgapUeMessage() {
  m_PduSessionResourceFailedToSetupList = std::nullopt;
  m_CriticalityDiagnostics              = nullptr;
  m_HandoverRequestAckIes               = nullptr;
  setMessageType(NgapMessageType::HANDOVER_REQUEST_ACKNOWLEDGE);
  initialize();
}

//------------------------------------------------------------------------------
HandoverRequestAck::~HandoverRequestAck() {}

//------------------------------------------------------------------------------
void HandoverRequestAck::initialize() {
  m_HandoverRequestAckIes = &(ngapPdu->choice.successfulOutcome->value.choice
                                  .HandoverRequestAcknowledge);
}

//------------------------------------------------------------------------------
void HandoverRequestAck::setAmfUeNgapId(const uint64_t& id) {
  NgapUeMessage::m_AmfUeNgapId.set(id);

  Ngap_HandoverRequestAcknowledgeIEs_t* ie =
      (Ngap_HandoverRequestAcknowledgeIEs_t*) calloc(
          1, sizeof(Ngap_HandoverRequestAcknowledgeIEs_t));
  ie->id          = Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID;
  ie->criticality = Ngap_Criticality_reject;
  ie->value.present =
      Ngap_HandoverRequestAcknowledgeIEs__value_PR_AMF_UE_NGAP_ID;

  int ret =
      NgapUeMessage::m_AmfUeNgapId.encode(ie->value.choice.AMF_UE_NGAP_ID);
  if (!ret) {
    oai::logger::logger_common::ngap().error(
        "Encode NGAP AMF_UE_NGAP_ID IE error");
    oai::utils::utils::free_wrapper((void**) &ie);
    return;
  }

  ret = ASN_SEQUENCE_ADD(&m_HandoverRequestAckIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error(
        "Encode NGAP AMF_UE_NGAP_ID IE error");
}

//------------------------------------------------------------------------------
void HandoverRequestAck::setRanUeNgapId(const uint32_t& ranUeNgapId) {
  NgapUeMessage::m_RanUeNgapId.set(ranUeNgapId);

  Ngap_HandoverRequestAcknowledgeIEs_t* ie =
      (Ngap_HandoverRequestAcknowledgeIEs_t*) calloc(
          1, sizeof(Ngap_HandoverRequestAcknowledgeIEs_t));
  ie->id          = Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID;
  ie->criticality = Ngap_Criticality_reject;
  ie->value.present =
      Ngap_HandoverRequestAcknowledgeIEs__value_PR_RAN_UE_NGAP_ID;

  int ret =
      NgapUeMessage::m_RanUeNgapId.encode(ie->value.choice.RAN_UE_NGAP_ID);
  if (!ret) {
    oai::logger::logger_common::ngap().error(
        "Encode NGAP RAN_UE_NGAP_ID IE error");
    oai::utils::utils::free_wrapper((void**) &ie);
    return;
  }

  ret = ASN_SEQUENCE_ADD(&m_HandoverRequestAckIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error(
        "Encode NGAP RAN_UE_NGAP_ID IE error");
}

//------------------------------------------------------------------------------
OCTET_STRING_t HandoverRequestAck::getTargetToSourceTransparentContainer()
    const {
  return m_TargetToSourceTransparentContainer;
}

void HandoverRequestAck::setTargetToSourceTransparentContainer(
    const OCTET_STRING_t& targetTosource) {
  Ngap_HandoverRequestAcknowledgeIEs_t* ie =
      (Ngap_HandoverRequestAcknowledgeIEs_t*) calloc(
          1, sizeof(Ngap_HandoverRequestAcknowledgeIEs_t));
  ie->id          = Ngap_ProtocolIE_ID_id_TargetToSource_TransparentContainer;
  ie->criticality = Ngap_Criticality_reject;
  ie->value.present =
      Ngap_HandoverRequestAcknowledgeIEs__value_PR_TargetToSource_TransparentContainer;
  ngap_utils::octet_string_copy(
      ie->value.choice.TargetToSource_TransparentContainer, targetTosource);
  int ret = ASN_SEQUENCE_ADD(&m_HandoverRequestAckIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error(
        "Encode NGAP TargetToSourceTransparentContainer IE error");
}

//------------------------------------------------------------------------------
bool HandoverRequestAck::getPduSessionResourceAdmittedList(
    std::vector<PDUSessionResourceAdmittedItem_t>& list) const {
  std::vector<PduSessionResourceItem> admittedItemList;
  m_PduSessionResourceAdmittedList.get(admittedItemList);

  for (auto& item : admittedItemList) {
    PDUSessionResourceAdmittedItem_t response = {};
    PduSessionId pDUSessionID                 = {};
    item.get(pDUSessionID, response.handoverRequestAcknowledgeTransfer);
    pDUSessionID.get(response.pduSessionId);
    list.push_back(response);
  }

  return true;
}

//------------------------------------------------------------------------------
void HandoverRequestAck::setPduSessionResourceAdmittedList(
    const PduSessionResourceAdmittedList& admittedList) {
  m_PduSessionResourceAdmittedList = admittedList;
  Ngap_HandoverRequestAcknowledgeIEs_t* ie =
      (Ngap_HandoverRequestAcknowledgeIEs_t*) calloc(
          1, sizeof(Ngap_HandoverRequestAcknowledgeIEs_t));

  ie->id          = Ngap_ProtocolIE_ID_id_PDUSessionResourceAdmittedList;
  ie->criticality = Ngap_Criticality_ignore;
  ie->value.present =
      Ngap_HandoverRequestAcknowledgeIEs__value_PR_PDUSessionResourceAdmittedList;

  m_PduSessionResourceAdmittedList.encode(
      ie->value.choice.PDUSessionResourceAdmittedList);

  int ret = ASN_SEQUENCE_ADD(&m_HandoverRequestAckIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error(
        "Encode NGAP PDUSessionResourceAdmittedList IE error");
}

//------------------------------------------------------------------------------
void HandoverRequestAck::setPduSessionResourceFailedToSetupListHOAck(
    const PduSessionResourceFailedToSetupListHoAck& list) {
  m_PduSessionResourceFailedToSetupList =
      std::optional<PduSessionResourceFailedToSetupListHoAck>(list);

  Ngap_HandoverRequestAcknowledgeIEs_t* ie =
      (Ngap_HandoverRequestAcknowledgeIEs_t*) calloc(
          1, sizeof(Ngap_HandoverRequestAcknowledgeIEs_t));

  ie->id = Ngap_ProtocolIE_ID_id_PDUSessionResourceFailedToSetupListHOAck;
  ie->criticality = Ngap_Criticality_ignore;
  ie->value.present =
      Ngap_HandoverRequestAcknowledgeIEs__value_PR_PDUSessionResourceFailedToSetupListHOAck;

  m_PduSessionResourceFailedToSetupList.value().encode(
      ie->value.choice.PDUSessionResourceFailedToSetupListHOAck);

  int ret = ASN_SEQUENCE_ADD(&m_HandoverRequestAckIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error(
        "Encode NGAP PDUSessionResourceFailedToSetupListHOAck IE error");
}

//------------------------------------------------------------------------------
void HandoverRequestAck::setPduSessionResourceFailedToSetupListHOAck(
    const std::vector<PduSessionResourceItem>& list) {
  PduSessionResourceFailedToSetupListHoAck tmp = {};
  tmp.set(list);
  m_PduSessionResourceFailedToSetupList =
      std::optional<PduSessionResourceFailedToSetupListHoAck>(tmp);

  Ngap_HandoverRequestAcknowledgeIEs_t* ie =
      (Ngap_HandoverRequestAcknowledgeIEs_t*) calloc(
          1, sizeof(Ngap_HandoverRequestAcknowledgeIEs_t));

  ie->id = Ngap_ProtocolIE_ID_id_PDUSessionResourceFailedToSetupListHOAck;
  ie->criticality = Ngap_Criticality_ignore;
  ie->value.present =
      Ngap_HandoverRequestAcknowledgeIEs__value_PR_PDUSessionResourceFailedToSetupListHOAck;

  m_PduSessionResourceFailedToSetupList.value().encode(
      ie->value.choice.PDUSessionResourceFailedToSetupListHOAck);

  int ret = ASN_SEQUENCE_ADD(&m_HandoverRequestAckIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error(
        "Encode NGAP PDUSessionResourceFailedToSetupListHOAck IE error");
}

//------------------------------------------------------------------------------
bool HandoverRequestAck::getPduSessionResourceFailedToSetupListHOAck(
    std::vector<PduSessionResourceItem>& list) const {
  if (!m_PduSessionResourceFailedToSetupList.has_value()) return false;
  m_PduSessionResourceFailedToSetupList.value().get(list);
  return true;
}

//------------------------------------------------------------------------------
bool HandoverRequestAck::decode(Ngap_NGAP_PDU_t* ngapMsgPdu) {
  if (!ngapMsgPdu) return false;
  ngapPdu = ngapMsgPdu;

  if (ngapPdu->present == Ngap_NGAP_PDU_PR_successfulOutcome) {
    if (ngapPdu->choice.successfulOutcome &&
        ngapPdu->choice.successfulOutcome->procedureCode ==
            Ngap_ProcedureCode_id_HandoverResourceAllocation &&
        ngapPdu->choice.successfulOutcome->criticality ==
            Ngap_Criticality_reject &&
        ngapPdu->choice.successfulOutcome->value.present ==
            Ngap_SuccessfulOutcome__value_PR_HandoverRequestAcknowledge) {
      m_HandoverRequestAckIes = &ngapPdu->choice.successfulOutcome->value.choice
                                     .HandoverRequestAcknowledge;
    } else {
      oai::logger::logger_common::ngap().error(
          "Check handoverRequestAck message error");
      return false;
    }
  } else {
    oai::logger::logger_common::ngap().error(
        "handoverRequestAck MessageType error");
    return false;
  }
  for (int i = 0; i < m_HandoverRequestAckIes->protocolIEs.list.count; i++) {
    switch (m_HandoverRequestAckIes->protocolIEs.list.array[i]->id) {
      case Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID: {
        if (m_HandoverRequestAckIes->protocolIEs.list.array[i]->criticality ==
                Ngap_Criticality_ignore &&
            m_HandoverRequestAckIes->protocolIEs.list.array[i]->value.present ==
                Ngap_HandoverRequestAcknowledgeIEs__value_PR_AMF_UE_NGAP_ID) {
          if (!NgapUeMessage::m_AmfUeNgapId.decode(
                  m_HandoverRequestAckIes->protocolIEs.list.array[i]
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
        if (m_HandoverRequestAckIes->protocolIEs.list.array[i]->criticality ==
                Ngap_Criticality_ignore &&
            m_HandoverRequestAckIes->protocolIEs.list.array[i]->value.present ==
                Ngap_HandoverRequestAcknowledgeIEs__value_PR_RAN_UE_NGAP_ID) {
          if (!NgapUeMessage::m_RanUeNgapId.decode(
                  m_HandoverRequestAckIes->protocolIEs.list.array[i]
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
      case Ngap_ProtocolIE_ID_id_PDUSessionResourceAdmittedList: {
        if (m_HandoverRequestAckIes->protocolIEs.list.array[i]->criticality ==
                Ngap_Criticality_ignore &&
            m_HandoverRequestAckIes->protocolIEs.list.array[i]->value.present ==
                Ngap_HandoverRequestAcknowledgeIEs__value_PR_PDUSessionResourceAdmittedList) {
          if (!m_PduSessionResourceAdmittedList.decode(
                  m_HandoverRequestAckIes->protocolIEs.list.array[i]
                      ->value.choice.PDUSessionResourceAdmittedList)) {
            oai::logger::logger_common::ngap().error(
                "Decoded NGAP PDUSessionResourceAdmittedList IE error");
            return false;
          }
        } else {
          oai::logger::logger_common::ngap().error(
              "Decoded NGAP PDUSessionResourceAdmittedList IE error");
          return false;
        }
      } break;

      case Ngap_ProtocolIE_ID_id_PDUSessionResourceFailedToSetupListHOAck: {
        if (m_HandoverRequestAckIes->protocolIEs.list.array[i]->criticality ==
                Ngap_Criticality_ignore &&
            m_HandoverRequestAckIes->protocolIEs.list.array[i]->value.present ==
                Ngap_HandoverRequestAcknowledgeIEs__value_PR_PDUSessionResourceFailedToSetupListHOAck) {
          PduSessionResourceFailedToSetupListHoAck tmp = {};
          if (!tmp.decode(m_HandoverRequestAckIes->protocolIEs.list.array[i]
                              ->value.choice
                              .PDUSessionResourceFailedToSetupListHOAck)) {
            oai::logger::logger_common::ngap().error(
                "Decoded NGAP PDUSessionResourceFailedToSetupListHOAck IE "
                "error");
            return false;
          }
          m_PduSessionResourceFailedToSetupList =
              std::optional<PduSessionResourceFailedToSetupListHoAck>(tmp);
        } else {
          oai::logger::logger_common::ngap().error(
              "Decoded NGAP PDUSessionResourceFailedToSetupListHOAck IE "
              "error");
          return false;
        }
      } break;
      case Ngap_ProtocolIE_ID_id_TargetToSource_TransparentContainer: {
        if (m_HandoverRequestAckIes->protocolIEs.list.array[i]->criticality ==
                Ngap_Criticality_reject &&
            m_HandoverRequestAckIes->protocolIEs.list.array[i]->value.present ==
                Ngap_HandoverRequestAcknowledgeIEs__value_PR_TargetToSource_TransparentContainer) {
          ngap_utils::octet_string_copy(
              m_TargetToSourceTransparentContainer,
              m_HandoverRequestAckIes->protocolIEs.list.array[i]
                  ->value.choice.TargetToSource_TransparentContainer);
        } else {
          oai::logger::logger_common::ngap().error(
              "Decoded NGAP m_TargetToSourceTransparentContainer IE error");

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
