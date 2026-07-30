/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceModifyResponse.hpp"

#include "logger_base.hpp"
#include "utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceModifyResponseMsg::PduSessionResourceModifyResponseMsg()
    : NgapUeMessage() {
  m_PduSessionResourceModifyList = std::nullopt;
  setMessageType(NgapMessageType::PDU_SESSION_RESOURCE_MODIFY_RESPONSE);
  initialize();
}

//------------------------------------------------------------------------------
PduSessionResourceModifyResponseMsg::~PduSessionResourceModifyResponseMsg() {
  // TODO:
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyResponseMsg::initialize() {
  pduSessionResourceModifyResponseIes =
      &(ngapPdu->choice.successfulOutcome->value.choice
            .PDUSessionResourceModifyResponse);
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyResponseMsg::setAmfUeNgapId(const uint64_t& id) {
  NgapUeMessage::m_AmfUeNgapId.set(id);

  Ngap_PDUSessionResourceModifyResponseIEs_t* ie =
      (Ngap_PDUSessionResourceModifyResponseIEs_t*) calloc(
          1, sizeof(Ngap_PDUSessionResourceModifyResponseIEs_t));
  ie->id          = Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID;
  ie->criticality = Ngap_Criticality_ignore;
  ie->value.present =
      Ngap_PDUSessionResourceModifyResponseIEs__value_PR_AMF_UE_NGAP_ID;

  int ret =
      NgapUeMessage::m_AmfUeNgapId.encode(ie->value.choice.AMF_UE_NGAP_ID);
  if (!ret) {
    oai::logger::logger_common::ngap().error(
        "Encode NGAP AMF_UE_NGAP_ID IE error");
    oai::utils::utils::free_wrapper((void**) &ie);
    return;
  }

  ret = ASN_SEQUENCE_ADD(
      &pduSessionResourceModifyResponseIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error(
        "Encode NGAP AMF_UE_NGAP_ID IE error");
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyResponseMsg::setRanUeNgapId(
    const uint32_t& ranUeNgapId) {
  NgapUeMessage::m_RanUeNgapId.set(ranUeNgapId);

  Ngap_PDUSessionResourceModifyResponseIEs_t* ie =
      (Ngap_PDUSessionResourceModifyResponseIEs_t*) calloc(
          1, sizeof(Ngap_PDUSessionResourceModifyResponseIEs_t));
  ie->id          = Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID;
  ie->criticality = Ngap_Criticality_ignore;
  ie->value.present =
      Ngap_PDUSessionResourceModifyResponseIEs__value_PR_RAN_UE_NGAP_ID;

  int ret =
      NgapUeMessage::m_RanUeNgapId.encode(ie->value.choice.RAN_UE_NGAP_ID);
  if (!ret) {
    oai::logger::logger_common::ngap().error(
        "Encode NGAP RAN_UE_NGAP_ID IE error");
    oai::utils::utils::free_wrapper((void**) &ie);
    return;
  }

  ret = ASN_SEQUENCE_ADD(
      &pduSessionResourceModifyResponseIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error(
        "Encode NGAP RAN_UE_NGAP_ID IE error");
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyResponseMsg::
    setPduSessionResourceModifyResponseList(
        const std::vector<PDUSessionResourceModifyResponseItem_t>& list) {
  std::vector<PduSessionResourceModifyItemModRes> itemModResList;
  // itemModResList.reserve(list.size());

  for (int i = 0; i < list.size(); i++) {
    PduSessionId pduSessionId               = {};
    PduSessionResourceModifyItemModRes item = {};

    pduSessionId.set(list[i].pduSessionId);
    item.set(pduSessionId, list[i].pduSessionResourceModifyResponseTransfer);
    itemModResList.push_back(item);
  }

  PduSessionResourceModifyListModRes item_list = {};
  item_list.set(itemModResList);
  m_PduSessionResourceModifyList =
      std::optional<PduSessionResourceModifyListModRes>(item_list);

  Ngap_PDUSessionResourceModifyResponseIEs_t* ie =
      (Ngap_PDUSessionResourceModifyResponseIEs_t*) calloc(
          1, sizeof(Ngap_PDUSessionResourceModifyResponseIEs_t));
  ie->id          = Ngap_ProtocolIE_ID_id_PDUSessionResourceModifyListModRes;
  ie->criticality = Ngap_Criticality_reject;
  ie->value.present =
      Ngap_PDUSessionResourceModifyResponseIEs__value_PR_PDUSessionResourceModifyListModRes;

  int ret = m_PduSessionResourceModifyList.value().encode(
      ie->value.choice.PDUSessionResourceModifyListModRes);
  if (!ret) {
    oai::logger::logger_common::ngap().error(
        "Encode NGAP PDUSessionResourceModifyListModRes IE error");
    oai::utils::utils::free_wrapper((void**) &ie);
    return;
  }

  ret = ASN_SEQUENCE_ADD(
      &pduSessionResourceModifyResponseIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error(
        "Encode NGAP PDUSessionResourceSetupListSUReq IE error");
}

//------------------------------------------------------------------------------
bool PduSessionResourceModifyResponseMsg::
    getPduSessionResourceModifyResponseList(
        std::vector<PDUSessionResourceModifyResponseItem_t>& list) const {
  if (!m_PduSessionResourceModifyList.has_value()) return false;

  std::vector<PduSessionResourceModifyItemModRes> itemModResList;
  m_PduSessionResourceModifyList.value().get(itemModResList);

  for (auto& it : itemModResList) {
    PDUSessionResourceModifyResponseItem_t response = {};
    PduSessionId pduSessionId                       = {};
    it.get(pduSessionId, response.pduSessionResourceModifyResponseTransfer);
    pduSessionId.get(response.pduSessionId);
    list.push_back(response);
  }

  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceModifyResponseMsg::decode(Ngap_NGAP_PDU_t* ngapMsgPdu) {
  ngapPdu = ngapMsgPdu;

  if (ngapPdu->present == Ngap_NGAP_PDU_PR_successfulOutcome) {
    if (ngapPdu->choice.successfulOutcome &&
        ngapPdu->choice.successfulOutcome->procedureCode ==
            Ngap_ProcedureCode_id_PDUSessionResourceModify &&
        ngapPdu->choice.successfulOutcome->criticality ==
            Ngap_Criticality_reject &&
        ngapPdu->choice.successfulOutcome->value.present ==
            Ngap_SuccessfulOutcome__value_PR_PDUSessionResourceModifyResponse) {
      pduSessionResourceModifyResponseIes =
          &ngapPdu->choice.successfulOutcome->value.choice
               .PDUSessionResourceModifyResponse;
    } else {
      oai::logger::logger_common::ngap().error(
          "Check PDUSessionResourceModifyResponse message error!");

      return false;
    }
  } else {
    oai::logger::logger_common::ngap().error("MessageType error!");
    return false;
  }

  for (int i = 0;
       i < pduSessionResourceModifyResponseIes->protocolIEs.list.count; i++) {
    switch (
        pduSessionResourceModifyResponseIes->protocolIEs.list.array[i]->id) {
      case Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID: {
        if (pduSessionResourceModifyResponseIes->protocolIEs.list.array[i]
                    ->criticality == Ngap_Criticality_ignore &&
            pduSessionResourceModifyResponseIes->protocolIEs.list.array[i]
                    ->value.present ==
                Ngap_PDUSessionResourceModifyResponseIEs__value_PR_AMF_UE_NGAP_ID) {
          if (!NgapUeMessage::m_AmfUeNgapId.decode(
                  pduSessionResourceModifyResponseIes->protocolIEs.list
                      .array[i]
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
        if (pduSessionResourceModifyResponseIes->protocolIEs.list.array[i]
                    ->criticality == Ngap_Criticality_reject &&
            pduSessionResourceModifyResponseIes->protocolIEs.list.array[i]
                    ->value.present ==
                Ngap_PDUSessionResourceModifyResponseIEs__value_PR_RAN_UE_NGAP_ID) {
          if (!NgapUeMessage::m_RanUeNgapId.decode(
                  pduSessionResourceModifyResponseIes->protocolIEs.list
                      .array[i]
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
      case Ngap_ProtocolIE_ID_id_PDUSessionResourceModifyListModRes: {
        if (pduSessionResourceModifyResponseIes->protocolIEs.list.array[i]
                    ->criticality == Ngap_Criticality_ignore &&
            pduSessionResourceModifyResponseIes->protocolIEs.list.array[i]
                    ->value.present ==
                Ngap_PDUSessionResourceModifyResponseIEs__value_PR_PDUSessionResourceModifyListModRes) {
          PduSessionResourceModifyListModRes item_list = {};
          if (!item_list.decode(
                  pduSessionResourceModifyResponseIes->protocolIEs.list
                      .array[i]
                      ->value.choice.PDUSessionResourceModifyListModRes)) {
            oai::logger::logger_common::ngap().error(
                "Decoded NGAP PDUSessionResourceModifyListModRes IE error");
            return false;
          }
          m_PduSessionResourceModifyList =
              std::optional<PduSessionResourceModifyListModRes>(item_list);

        } else {
          oai::logger::logger_common::ngap().error(
              "Decoded NGAP PDUSessionResourceModifyListModRes IE error");

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
