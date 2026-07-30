/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "HandoverPreparationFailure.hpp"

#include "logger_base.hpp"
#include "utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
HandoverPreparationFailure::HandoverPreparationFailure() : NgapUeMessage() {
  m_HOPreparationFailureIes = nullptr;
  m_CriticalityDiagnostics  = nullptr;

  setMessageType(NgapMessageType::HANDOVER_PREPARATION_FAILURE);
  initialize();
}

//------------------------------------------------------------------------------
HandoverPreparationFailure::~HandoverPreparationFailure() {}

//------------------------------------------------------------------------------
void HandoverPreparationFailure::initialize() {
  m_HOPreparationFailureIes = &(ngapPdu->choice.unsuccessfulOutcome->value
                                    .choice.HandoverPreparationFailure);
}

//------------------------------------------------------------------------------
void HandoverPreparationFailure::setAmfUeNgapId(const uint64_t& id) {
  NgapUeMessage::m_AmfUeNgapId.set(id);

  Ngap_HandoverPreparationFailureIEs_t* ie =
      (Ngap_HandoverPreparationFailureIEs_t*) calloc(
          1, sizeof(Ngap_HandoverPreparationFailureIEs_t));
  ie->id          = Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID;
  ie->criticality = Ngap_Criticality_ignore;
  ie->value.present =
      Ngap_HandoverPreparationFailureIEs__value_PR_AMF_UE_NGAP_ID;

  int ret =
      NgapUeMessage::m_AmfUeNgapId.encode(ie->value.choice.AMF_UE_NGAP_ID);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode AMF_UE_NGAP_ID IE error");
    oai::utils::utils::free_wrapper((void**) &ie);
    return;
  }

  ret = ASN_SEQUENCE_ADD(&m_HOPreparationFailureIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error("Encode AMF_UE_NGAP_ID IE error");
}

//------------------------------------------------------------------------------
void HandoverPreparationFailure::setRanUeNgapId(const uint32_t& ranUeNgapId) {
  NgapUeMessage::m_RanUeNgapId.set(ranUeNgapId);

  Ngap_HandoverPreparationFailureIEs_t* ie =
      (Ngap_HandoverPreparationFailureIEs_t*) calloc(
          1, sizeof(Ngap_HandoverPreparationFailureIEs_t));
  ie->id          = Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID;
  ie->criticality = Ngap_Criticality_reject;
  ie->value.present =
      Ngap_HandoverPreparationFailureIEs__value_PR_RAN_UE_NGAP_ID;

  int ret =
      NgapUeMessage::m_RanUeNgapId.encode(ie->value.choice.RAN_UE_NGAP_ID);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode RAN_UE_NGAP_ID IE error");
    oai::utils::utils::free_wrapper((void**) &ie);
    return;
  }

  ret = ASN_SEQUENCE_ADD(&m_HOPreparationFailureIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error("Encode RAN_UE_NGAP_ID IE error");
}

//------------------------------------------------------------------------------
void HandoverPreparationFailure::setCause(
    const Ngap_Cause_PR& causePresent,
    const long& value)  //
{
  Ngap_HandoverPreparationFailureIEs_t* ie =
      (Ngap_HandoverPreparationFailureIEs_t*) calloc(
          1, sizeof(Ngap_HandoverPreparationFailureIEs_t));
  ie->id            = Ngap_ProtocolIE_ID_id_Cause;
  ie->criticality   = Ngap_Criticality_ignore;
  ie->value.present = Ngap_HandoverPreparationFailureIEs__value_PR_Cause;

  m_Cause.setChoiceOfCause(causePresent);
  if (causePresent != Ngap_Cause_PR_NOTHING) m_Cause.set(value);
  m_Cause.encode(ie->value.choice.Cause);
  int ret = ASN_SEQUENCE_ADD(&m_HOPreparationFailureIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error("Encode Cause IE error");
}

//------------------------------------------------------------------------------
Ngap_Cause_PR HandoverPreparationFailure::getChoiceOfCause() const {
  return m_Cause.getChoiceOfCause();
}

//------------------------------------------------------------------------------
bool HandoverPreparationFailure::decode(Ngap_NGAP_PDU_t* ngapMsgPdu) {
  if (!ngapMsgPdu) return false;
  ngapPdu = ngapMsgPdu;

  if (ngapPdu->present == Ngap_NGAP_PDU_PR_unsuccessfulOutcome) {
    if (ngapPdu->choice.unsuccessfulOutcome &&
        ngapPdu->choice.unsuccessfulOutcome->procedureCode ==
            Ngap_ProcedureCode_id_HandoverPreparation &&
        ngapPdu->choice.unsuccessfulOutcome->criticality ==
            Ngap_Criticality_reject &&
        ngapPdu->choice.unsuccessfulOutcome->value.present ==
            Ngap_UnsuccessfulOutcome__value_PR_HandoverPreparationFailure) {
      m_HOPreparationFailureIes = &ngapPdu->choice.unsuccessfulOutcome->value
                                       .choice.HandoverPreparationFailure;
    } else {
      oai::logger::logger_common::ngap().error(
          "Check HandoverPreparationFailure message error");
      return false;
    }
  } else {
    oai::logger::logger_common::ngap().error(
        "HandoverPreparationFailure MessageType error");
    return false;
  }

  for (int i = 0; i < m_HOPreparationFailureIes->protocolIEs.list.count; i++) {
    switch (m_HOPreparationFailureIes->protocolIEs.list.array[i]->id) {
      case Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID: {
        if (m_HOPreparationFailureIes->protocolIEs.list.array[i]->criticality ==
                Ngap_Criticality_ignore &&
            m_HOPreparationFailureIes->protocolIEs.list.array[i]
                    ->value.present ==
                Ngap_HandoverPreparationFailureIEs__value_PR_AMF_UE_NGAP_ID) {
          if (!NgapUeMessage::m_AmfUeNgapId.decode(
                  m_HOPreparationFailureIes->protocolIEs.list.array[i]
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
        if (m_HOPreparationFailureIes->protocolIEs.list.array[i]->criticality ==
                Ngap_Criticality_ignore &&
            m_HOPreparationFailureIes->protocolIEs.list.array[i]
                    ->value.present ==
                Ngap_HandoverPreparationFailureIEs__value_PR_RAN_UE_NGAP_ID) {
          if (!NgapUeMessage::m_RanUeNgapId.decode(
                  m_HOPreparationFailureIes->protocolIEs.list.array[i]
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
      case Ngap_ProtocolIE_ID_id_Cause: {
        if (m_HOPreparationFailureIes->protocolIEs.list.array[i]->criticality ==
                Ngap_Criticality_ignore &&
            m_HOPreparationFailureIes->protocolIEs.list.array[i]
                    ->value.present ==
                Ngap_HandoverPreparationFailureIEs__value_PR_Cause) {
          if (!m_Cause.decode(
                  m_HOPreparationFailureIes->protocolIEs.list.array[i]
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
      case Ngap_ProtocolIE_ID_id_CriticalityDiagnostics: {
        if (m_HOPreparationFailureIes->protocolIEs.list.array[i]->criticality ==
                Ngap_Criticality_ignore &&
            m_HOPreparationFailureIes->protocolIEs.list.array[i]
                    ->value.present ==
                Ngap_HandoverPreparationFailureIEs__value_PR_CriticalityDiagnostics) {
          // TODO:
        } else {
          oai::logger::logger_common::ngap().error(
              "Decoded NGAP CriticalityDiagnostics IE error");
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
