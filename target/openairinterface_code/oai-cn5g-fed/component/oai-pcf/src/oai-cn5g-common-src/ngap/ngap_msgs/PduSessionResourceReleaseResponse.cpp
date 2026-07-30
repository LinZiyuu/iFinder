/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceReleaseResponse.hpp"

#include "logger_base.hpp"
#include "utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceReleaseResponseMsg::PduSessionResourceReleaseResponseMsg()
    : NgapUeMessage() {
  m_PduSessionResourceReleaseResponseIes = nullptr;
  m_UserLocationInformation              = std::nullopt;

  setMessageType(NgapMessageType::PDU_SESSION_RESOURCE_RELEASE_RESPONSE);
  initialize();
}

//------------------------------------------------------------------------------
PduSessionResourceReleaseResponseMsg::~PduSessionResourceReleaseResponseMsg() {}

//------------------------------------------------------------------------------
void PduSessionResourceReleaseResponseMsg::initialize() {
  m_PduSessionResourceReleaseResponseIes =
      &(ngapPdu->choice.successfulOutcome->value.choice
            .PDUSessionResourceReleaseResponse);
}

//------------------------------------------------------------------------------
void PduSessionResourceReleaseResponseMsg::setAmfUeNgapId(const uint64_t& id) {
  NgapUeMessage::m_AmfUeNgapId.set(id);

  Ngap_PDUSessionResourceReleaseResponseIEs_t* ie =
      (Ngap_PDUSessionResourceReleaseResponseIEs_t*) calloc(
          1, sizeof(Ngap_PDUSessionResourceReleaseResponseIEs_t));

  ie->id          = Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID;
  ie->criticality = Ngap_Criticality_reject;
  ie->value.present =
      Ngap_PDUSessionResourceReleaseResponseIEs__value_PR_AMF_UE_NGAP_ID;

  int ret =
      NgapUeMessage::m_AmfUeNgapId.encode(ie->value.choice.AMF_UE_NGAP_ID);
  if (!ret) {
    oai::logger::logger_common::ngap().warn("Encode AMF_UE_NGAP_ID IE error");
    oai::utils::utils::free_wrapper((void**) &ie);
    return;
  }

  ret = ASN_SEQUENCE_ADD(
      &m_PduSessionResourceReleaseResponseIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().warn("Encode AMF_UE_NGAP_ID IE error");
}

//------------------------------------------------------------------------------
void PduSessionResourceReleaseResponseMsg::setRanUeNgapId(
    const uint32_t& ranUeNgapId) {
  NgapUeMessage::m_RanUeNgapId.set(ranUeNgapId);

  Ngap_PDUSessionResourceReleaseResponseIEs_t* ie =
      (Ngap_PDUSessionResourceReleaseResponseIEs_t*) calloc(
          1, sizeof(Ngap_PDUSessionResourceReleaseResponseIEs_t));
  ie->id          = Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID;
  ie->criticality = Ngap_Criticality_reject;
  ie->value.present =
      Ngap_PDUSessionResourceReleaseResponseIEs__value_PR_RAN_UE_NGAP_ID;

  int ret =
      NgapUeMessage::m_RanUeNgapId.encode(ie->value.choice.RAN_UE_NGAP_ID);
  if (!ret) {
    oai::logger::logger_common::ngap().warn("Encode RAN_UE_NGAP_ID IE error");
    oai::utils::utils::free_wrapper((void**) &ie);
    return;
  }

  ret = ASN_SEQUENCE_ADD(
      &m_PduSessionResourceReleaseResponseIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().warn("Encode RAN_UE_NGAP_ID IE error");
}

//------------------------------------------------------------------------------
void PduSessionResourceReleaseResponseMsg::setPduSessionResourceReleasedList(
    const std::vector<PDUSessionResourceReleasedItem_t>& list) {
  std::vector<PduSessionResourceReleasedItemRelRes> itemRelResList;
  for (int i = 0; i < list.size(); i++) {
    PduSessionResourceReleasedItemRelRes itemRelRes = {};
    PduSessionId pduSessionId                       = {};
    pduSessionId.set(list[i].pduSessionId);

    itemRelRes.set(
        pduSessionId, list[i].pduSessionResourceReleaseResponseTransfer);
    itemRelResList.push_back(itemRelRes);
  }

  m_PduSessionResourceReleasedList.set(itemRelResList);

  Ngap_PDUSessionResourceReleaseResponseIEs_t* ie =
      (Ngap_PDUSessionResourceReleaseResponseIEs_t*) calloc(
          1, sizeof(Ngap_PDUSessionResourceReleaseResponseIEs_t));

  ie->id          = Ngap_ProtocolIE_ID_id_PDUSessionResourceReleasedListRelRes;
  ie->criticality = Ngap_Criticality_reject;
  ie->value.present =
      Ngap_PDUSessionResourceReleaseResponseIEs__value_PR_PDUSessionResourceReleasedListRelRes;

  int ret = m_PduSessionResourceReleasedList.encode(
      ie->value.choice.PDUSessionResourceReleasedListRelRes);
  if (!ret) {
    oai::logger::logger_common::ngap().warn(
        "Encode PDUSessionResourceReleasedListRelRes IE error");
    oai::utils::utils::free_wrapper((void**) &ie);
    return;
  }

  ret = ASN_SEQUENCE_ADD(
      &m_PduSessionResourceReleaseResponseIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().warn(
        "Encode PDUSessionResourceReleasedListRelRes IE error");
}

//------------------------------------------------------------------------------
bool PduSessionResourceReleaseResponseMsg::getPduSessionResourceReleasedList(
    std::vector<PDUSessionResourceReleasedItem_t>& list) const {
  std::vector<PduSessionResourceReleasedItemRelRes> itemRelResList;
  m_PduSessionResourceReleasedList.get(itemRelResList);

  for (auto& item : itemRelResList) {
    PDUSessionResourceReleasedItem_t rel = {};
    PduSessionId pduSessionId            = {};

    item.get(pduSessionId, rel.pduSessionResourceReleaseResponseTransfer);
    pduSessionId.get(rel.pduSessionId);

    list.push_back(rel);
  }

  return true;
}

//------------------------------------------------------------------------------
void PduSessionResourceReleaseResponseMsg::setUserLocationInfoNr(
    const NrCgi_t& cig, const Tai_t& tai) {
  UserLocationInformation tmp = {};

  UserLocationInformationNr userLocationInformationNR = {};
  NrCgi nrCgi                                         = {};
  Tai taiNr                                           = {};
  nrCgi.set(cig.mcc, cig.mnc, cig.nrCellId);
  taiNr.set(tai);
  userLocationInformationNR.set(nrCgi, taiNr);
  tmp.set(userLocationInformationNR);
  m_UserLocationInformation = std::optional<UserLocationInformation>(tmp);

  Ngap_PDUSessionResourceReleaseResponseIEs_t* ie =
      (Ngap_PDUSessionResourceReleaseResponseIEs_t*) calloc(
          1, sizeof(Ngap_PDUSessionResourceReleaseResponseIEs_t));
  ie->id          = Ngap_ProtocolIE_ID_id_UserLocationInformation;
  ie->criticality = Ngap_Criticality_reject;
  ie->value.present =
      Ngap_PDUSessionResourceReleaseResponseIEs__value_PR_UserLocationInformation;

  int ret = m_UserLocationInformation.value().encode(
      ie->value.choice.UserLocationInformation);
  if (!ret) {
    oai::logger::logger_common::ngap().warn(
        "Encode UserLocationInformation IE error");
    oai::utils::utils::free_wrapper((void**) &ie);
    return;
  }

  ret = ASN_SEQUENCE_ADD(
      &m_PduSessionResourceReleaseResponseIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().warn(
        "Encode UserLocationInformation IE error");
  // oai::utils::utils::free_wrapper((void**) &ie);
}

//------------------------------------------------------------------------------
bool PduSessionResourceReleaseResponseMsg::getUserLocationInfoNr(
    NrCgi_t& cgi, Tai_t& tai) const {
  if (!m_UserLocationInformation.has_value()) return false;

  UserLocationInformationNr userLocationInformationNR = {};
  if (!m_UserLocationInformation.value().get(userLocationInformationNR))
    return false;

  if (m_UserLocationInformation.value().getChoiceOfUserLocationInformation() !=
      Ngap_UserLocationInformation_PR_userLocationInformationNR)
    return false;
  NrCgi nrCgi = {};
  Tai taiNr   = {};
  userLocationInformationNR.get(nrCgi, taiNr);
  nrCgi.get(cgi);
  taiNr.get(tai);

  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceReleaseResponseMsg::decode(Ngap_NGAP_PDU_t* ngapMsgPdu) {
  ngapPdu = ngapMsgPdu;

  if (ngapPdu->present == Ngap_NGAP_PDU_PR_successfulOutcome) {
    if (ngapPdu->choice.successfulOutcome &&
        ngapPdu->choice.successfulOutcome->procedureCode ==
            Ngap_ProcedureCode_id_PDUSessionResourceRelease &&
        ngapPdu->choice.successfulOutcome->criticality ==
            Ngap_Criticality_reject &&
        ngapPdu->choice.successfulOutcome->value.present ==
            Ngap_SuccessfulOutcome__value_PR_PDUSessionResourceReleaseResponse) {
      m_PduSessionResourceReleaseResponseIes =
          &ngapPdu->choice.successfulOutcome->value.choice
               .PDUSessionResourceReleaseResponse;
    } else {
      oai::logger::logger_common::ngap().warn(
          "Check PDUSessionResourceReleaseResponse message error");
      return false;
    }
  } else {
    oai::logger::logger_common::ngap().warn("MessageType error");
    return false;
  }

  for (int i = 0;
       i < m_PduSessionResourceReleaseResponseIes->protocolIEs.list.count;
       i++) {
    switch (
        m_PduSessionResourceReleaseResponseIes->protocolIEs.list.array[i]->id) {
      case Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID: {
        if (m_PduSessionResourceReleaseResponseIes->protocolIEs.list.array[i]
                    ->criticality == Ngap_Criticality_ignore &&
            m_PduSessionResourceReleaseResponseIes->protocolIEs.list.array[i]
                    ->value.present ==
                Ngap_PDUSessionResourceReleaseResponseIEs__value_PR_AMF_UE_NGAP_ID) {
          if (!NgapUeMessage::m_AmfUeNgapId.decode(
                  m_PduSessionResourceReleaseResponseIes->protocolIEs.list
                      .array[i]
                      ->value.choice.AMF_UE_NGAP_ID)) {
            oai::logger::logger_common::ngap().warn(
                "Decoded NGAP AMF_UE_NGAP_ID IE error");
            return false;
          }
        } else {
          oai::logger::logger_common::ngap().warn(
              "Decoded NGAP AMF_UE_NGAP_ID IE error");
          return false;
        }
      } break;

      case Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID: {
        if (m_PduSessionResourceReleaseResponseIes->protocolIEs.list.array[i]
                    ->criticality == Ngap_Criticality_ignore &&
            m_PduSessionResourceReleaseResponseIes->protocolIEs.list.array[i]
                    ->value.present ==
                Ngap_PDUSessionResourceReleaseResponseIEs__value_PR_RAN_UE_NGAP_ID) {
          if (!NgapUeMessage::m_RanUeNgapId.decode(
                  m_PduSessionResourceReleaseResponseIes->protocolIEs.list
                      .array[i]
                      ->value.choice.RAN_UE_NGAP_ID)) {
            oai::logger::logger_common::ngap().warn(
                "Decoded NGAP RAN_UE_NGAP_ID IE error");
            return false;
          }
        } else {
          oai::logger::logger_common::ngap().warn(
              "Decoded NGAP RAN_UE_NGAP_ID IE error");
          return false;
        }
      } break;

      case Ngap_ProtocolIE_ID_id_PDUSessionResourceReleasedListRelRes: {
        if (m_PduSessionResourceReleaseResponseIes->protocolIEs.list.array[i]
                    ->criticality == Ngap_Criticality_ignore &&
            m_PduSessionResourceReleaseResponseIes->protocolIEs.list.array[i]
                    ->value.present ==
                Ngap_PDUSessionResourceReleaseResponseIEs__value_PR_PDUSessionResourceReleasedListRelRes) {
          if (!m_PduSessionResourceReleasedList.decode(
                  m_PduSessionResourceReleaseResponseIes->protocolIEs.list
                      .array[i]
                      ->value.choice.PDUSessionResourceReleasedListRelRes)) {
            oai::logger::logger_common::ngap().warn(
                "Decoded NGAP PDUSessionResourceReleasedListRelRes IE "
                "error");
            return false;
          }
        } else {
          oai::logger::logger_common::ngap().warn(
              "Decoded NGAP PDUSessionResourceReleasedListRelRes IE error");
          return false;
        }
      } break;
      default: {
        oai::logger::logger_common::ngap().warn(
            "Decoded NGAP message PDU error");
        return false;
      }
    }
  }

  return true;
}

}  // namespace oai::ngap
