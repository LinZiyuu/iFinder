/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "InitialContextSetupFailure.hpp"

#include "logger_base.hpp"
#include "utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
InitialContextSetupFailureMsg::InitialContextSetupFailureMsg() {
  m_InitialContextSetupFailureIes              = nullptr;
  m_PduSessionResourceFailedToSetupFailureList = std::nullopt;

  setMessageType(NgapMessageType::INITIAL_CONTEXT_SETUP_FAILURE);
  initialize();
}

//------------------------------------------------------------------------------
InitialContextSetupFailureMsg::~InitialContextSetupFailureMsg() {
  if (m_InitialContextSetupFailureIes) free(m_InitialContextSetupFailureIes);
}

//------------------------------------------------------------------------------
void InitialContextSetupFailureMsg::initialize() {
  m_InitialContextSetupFailureIes = &(ngapPdu->choice.unsuccessfulOutcome->value
                                          .choice.InitialContextSetupFailure);
}

//------------------------------------------------------------------------------
void InitialContextSetupFailureMsg::setAmfUeNgapId(const uint64_t& id) {
  NgapUeMessage::m_AmfUeNgapId.set(id);

  Ngap_InitialContextSetupFailureIEs_t* ie =
      (Ngap_InitialContextSetupFailureIEs_t*) calloc(
          1, sizeof(Ngap_InitialContextSetupFailureIEs_t));
  ie->id          = Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID;
  ie->criticality = Ngap_Criticality_ignore;
  ie->value.present =
      Ngap_InitialContextSetupFailureIEs__value_PR_AMF_UE_NGAP_ID;

  int ret =
      NgapUeMessage::m_AmfUeNgapId.encode(ie->value.choice.AMF_UE_NGAP_ID);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode AMF_UE_NGAP_ID IE error");
    oai::utils::utils::free_wrapper((void**) &ie);
    return;
  }

  ret =
      ASN_SEQUENCE_ADD(&m_InitialContextSetupFailureIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error("Encode AMF_UE_NGAP_ID IE error");
}

//------------------------------------------------------------------------------
void InitialContextSetupFailureMsg::setRanUeNgapId(
    const uint32_t& ranUeNgapId) {
  NgapUeMessage::m_RanUeNgapId.set(ranUeNgapId);

  Ngap_InitialContextSetupFailureIEs_t* ie =
      (Ngap_InitialContextSetupFailureIEs_t*) calloc(
          1, sizeof(Ngap_InitialContextSetupFailureIEs_t));
  ie->id          = Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID;
  ie->criticality = Ngap_Criticality_ignore;
  ie->value.present =
      Ngap_InitialContextSetupFailureIEs__value_PR_RAN_UE_NGAP_ID;

  int ret =
      NgapUeMessage::m_RanUeNgapId.encode(ie->value.choice.RAN_UE_NGAP_ID);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode RAN_UE_NGAP_ID IE error");
    oai::utils::utils::free_wrapper((void**) &ie);
    return;
  }

  ret =
      ASN_SEQUENCE_ADD(&m_InitialContextSetupFailureIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error("Encode RAN_UE_NGAP_ID IE error");
}

//------------------------------------------------------------------------------
void InitialContextSetupFailureMsg::setPduSessionResourceFailedToSetupList(
    const std::vector<PDUSessionResourceFailedToSetupItem_t>& list) {
  m_PduSessionResourceFailedToSetupFailureList =
      std::make_optional<PduSessionResourceFailedToSetupListCxtFail>();

  std::vector<PduSessionResourceFailedToSetupItemCxtFail> cxt_fail_list;
  cxt_fail_list.reserve(list.size());

  for (int i = 0; i < list.size(); i++) {
    PduSessionResourceFailedToSetupItemCxtFail item_cxt_fail = {};
    PduSessionId pdu_session_id                              = {};
    pdu_session_id.set(list[i].pduSessionId);

    item_cxt_fail.set(
        pdu_session_id, list[i].pduSessionResourceSetupUnsuccessfulTransfer);
    cxt_fail_list.push_back(item_cxt_fail);
  }

  m_PduSessionResourceFailedToSetupFailureList.value().set(cxt_fail_list);

  Ngap_InitialContextSetupFailureIEs_t* ie =
      (Ngap_InitialContextSetupFailureIEs_t*) calloc(
          1, sizeof(Ngap_InitialContextSetupFailureIEs_t));
  ie->id = Ngap_ProtocolIE_ID_id_PDUSessionResourceFailedToSetupListCxtFail;
  ie->criticality = Ngap_Criticality_ignore;
  ie->value.present =
      Ngap_InitialContextSetupFailureIEs__value_PR_PDUSessionResourceFailedToSetupListCxtFail;

  int ret = m_PduSessionResourceFailedToSetupFailureList.value().encode(
      ie->value.choice.PDUSessionResourceFailedToSetupListCxtFail);
  if (!ret) {
    oai::logger::logger_common::ngap().error(
        "Encode PDUSessionResourceFailedToSetupListCxtFail IE error");
    return;
  }

  ret =
      ASN_SEQUENCE_ADD(&m_InitialContextSetupFailureIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error(
        "Encode PDUSessionResourceFailedToSetupListCxtFail IE error");
}

//------------------------------------------------------------------------------
bool InitialContextSetupFailureMsg::decode(Ngap_NGAP_PDU_t* ngapMsgPdu) {
  ngapPdu = ngapMsgPdu;

  if (ngapPdu->present == Ngap_NGAP_PDU_PR_unsuccessfulOutcome) {
    if (ngapPdu->choice.unsuccessfulOutcome &&
        ngapPdu->choice.unsuccessfulOutcome->procedureCode ==
            Ngap_ProcedureCode_id_InitialContextSetup &&
        ngapPdu->choice.unsuccessfulOutcome->criticality ==
            Ngap_Criticality_reject &&
        ngapPdu->choice.unsuccessfulOutcome->value.present ==
            Ngap_UnsuccessfulOutcome__value_PR_InitialContextSetupFailure) {
      m_InitialContextSetupFailureIes =
          &ngapPdu->choice.unsuccessfulOutcome->value.choice
               .InitialContextSetupFailure;
    } else {
      oai::logger::logger_common::ngap().error(
          "Check InitialContextSetupFailure message error!");
      return false;
    }
  } else {
    oai::logger::logger_common::ngap().error("MessageType error!");
    return false;
  }
  for (int i = 0; i < m_InitialContextSetupFailureIes->protocolIEs.list.count;
       i++) {
    switch (m_InitialContextSetupFailureIes->protocolIEs.list.array[i]->id) {
      case Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID: {
        if (m_InitialContextSetupFailureIes->protocolIEs.list.array[i]
                    ->criticality == Ngap_Criticality_ignore &&
            m_InitialContextSetupFailureIes->protocolIEs.list.array[i]
                    ->value.present ==
                Ngap_InitialContextSetupFailureIEs__value_PR_AMF_UE_NGAP_ID) {
          if (!NgapUeMessage::m_AmfUeNgapId.decode(
                  m_InitialContextSetupFailureIes->protocolIEs.list.array[i]
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
        if (m_InitialContextSetupFailureIes->protocolIEs.list.array[i]
                    ->criticality == Ngap_Criticality_ignore &&
            m_InitialContextSetupFailureIes->protocolIEs.list.array[i]
                    ->value.present ==
                Ngap_InitialContextSetupFailureIEs__value_PR_RAN_UE_NGAP_ID) {
          if (!NgapUeMessage::m_RanUeNgapId.decode(
                  m_InitialContextSetupFailureIes->protocolIEs.list.array[i]
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
      case Ngap_ProtocolIE_ID_id_PDUSessionResourceFailedToSetupListCxtFail: {
        if (m_InitialContextSetupFailureIes->protocolIEs.list.array[i]
                    ->criticality == Ngap_Criticality_ignore &&
            m_InitialContextSetupFailureIes->protocolIEs.list.array[i]
                    ->value.present ==
                Ngap_InitialContextSetupFailureIEs__value_PR_PDUSessionResourceFailedToSetupListCxtFail) {
          PduSessionResourceFailedToSetupListCxtFail tmp = {};
          if (!tmp.decode(
                  m_InitialContextSetupFailureIes->protocolIEs.list.array[i]
                      ->value.choice
                      .PDUSessionResourceFailedToSetupListCxtFail)) {
            oai::logger::logger_common::ngap().error(
                "Decoded NGAP PDUSessionResourceFailedToSetupListCxtFail "
                "IE "
                "error");
            return false;
          }
          m_PduSessionResourceFailedToSetupFailureList =
              std::optional<PduSessionResourceFailedToSetupListCxtFail>(tmp);

        } else {
          oai::logger::logger_common::ngap().error(
              "Decoded NGAP PDUSessionResourceFailedToSetupListCxtFail IE "
              "error");
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

//------------------------------------------------------------------------------
bool InitialContextSetupFailureMsg::getPduSessionResourceFailedToSetupList(
    std::vector<PDUSessionResourceFailedToSetupItem_t>& list) const {
  if (!m_PduSessionResourceFailedToSetupFailureList.has_value()) return false;

  std::vector<PduSessionResourceFailedToSetupItemCxtFail> cxt_fail_list;

  m_PduSessionResourceFailedToSetupFailureList.value().get(cxt_fail_list);

  for (std::vector<PduSessionResourceFailedToSetupItemCxtFail>::iterator it =
           std::begin(cxt_fail_list);
       it < std::end(cxt_fail_list); ++it) {
    PDUSessionResourceFailedToSetupItem_t failedToFailure = {};

    PduSessionId pdu_session_id = {};
    it->get(
        pdu_session_id,
        failedToFailure.pduSessionResourceSetupUnsuccessfulTransfer);
    pdu_session_id.get(failedToFailure.pduSessionId);

    list.push_back(failedToFailure);
  }

  return true;
}

//------------------------------------------------------------------------------
void InitialContextSetupFailureMsg::setCause(
    const long& cause, const Ngap_Cause_PR& cause_present) {
  m_Cause.set(cause, cause_present);
}

//------------------------------------------------------------------------------
void InitialContextSetupFailureMsg::setCause(const Cause& cause) {
  m_Cause.set(cause.get(), cause.getChoiceOfCause());
}

//------------------------------------------------------------------------------
void InitialContextSetupFailureMsg::getCause(Cause& cause) const {
  cause.set(m_Cause.get(), m_Cause.getChoiceOfCause());
}

}  // namespace oai::ngap
