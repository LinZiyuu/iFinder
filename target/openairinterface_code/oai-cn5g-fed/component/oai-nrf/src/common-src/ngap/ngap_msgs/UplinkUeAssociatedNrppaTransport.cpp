/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "UplinkUeAssociatedNrppaTransport.hpp"

#include "logger_base.hpp"
#include "utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
UplinkUeAssociatedNrppaTransportMsg::UplinkUeAssociatedNrppaTransportMsg()
    : NgapUeMessage() {
  m_UplinkUeAssociatedNrppaTransportIes = nullptr;

  setMessageType(NgapMessageType::UPLINK_UE_ASSOCIATED_NRPPA_TRANSPORT);
  initialize();
}

//------------------------------------------------------------------------------
UplinkUeAssociatedNrppaTransportMsg::~UplinkUeAssociatedNrppaTransportMsg() {}

//------------------------------------------------------------------------------
void UplinkUeAssociatedNrppaTransportMsg::initialize() {
  m_UplinkUeAssociatedNrppaTransportIes =
      &(ngapPdu->choice.initiatingMessage->value.choice
            .UplinkUEAssociatedNRPPaTransport);
}

//------------------------------------------------------------------------------
void UplinkUeAssociatedNrppaTransportMsg::setAmfUeNgapId(const uint64_t& id) {
  NgapUeMessage::m_AmfUeNgapId.set(id);

  Ngap_UplinkUEAssociatedNRPPaTransportIEs_t* ie =
      (Ngap_UplinkUEAssociatedNRPPaTransportIEs_t*) calloc(
          1, sizeof(Ngap_UplinkUEAssociatedNRPPaTransportIEs_t));
  ie->id          = Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID;
  ie->criticality = Ngap_Criticality_reject;
  ie->value.present =
      Ngap_UplinkUEAssociatedNRPPaTransportIEs__value_PR_AMF_UE_NGAP_ID;

  int ret =
      NgapUeMessage::m_AmfUeNgapId.encode(ie->value.choice.AMF_UE_NGAP_ID);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode AMF_UE_NGAP_ID IE error");
    oai::utils::utils::free_wrapper((void**) &ie);
    return;
  }

  ret = ASN_SEQUENCE_ADD(
      &m_UplinkUeAssociatedNrppaTransportIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error("Encode AMF_UE_NGAP_ID IE error");
}

//------------------------------------------------------------------------------
void UplinkUeAssociatedNrppaTransportMsg::setRanUeNgapId(
    const uint32_t& ranUeNgapId) {
  NgapUeMessage::m_RanUeNgapId.set(ranUeNgapId);

  Ngap_UplinkUEAssociatedNRPPaTransportIEs_t* ie =
      (Ngap_UplinkUEAssociatedNRPPaTransportIEs_t*) calloc(
          1, sizeof(Ngap_UplinkUEAssociatedNRPPaTransportIEs_t));
  ie->id          = Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID;
  ie->criticality = Ngap_Criticality_reject;
  ie->value.present =
      Ngap_UplinkUEAssociatedNRPPaTransportIEs__value_PR_RAN_UE_NGAP_ID;

  int ret =
      NgapUeMessage::m_RanUeNgapId.encode(ie->value.choice.RAN_UE_NGAP_ID);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode RAN_UE_NGAP_ID IE error");
    oai::utils::utils::free_wrapper((void**) &ie);
    return;
  }

  ret = ASN_SEQUENCE_ADD(
      &m_UplinkUeAssociatedNrppaTransportIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error("Encode RAN_UE_NGAP_ID IE error");
}

//------------------------------------------------------------------------------
bool UplinkUeAssociatedNrppaTransportMsg::decode(Ngap_NGAP_PDU_t* ngapMsgPdu) {
  ngapPdu = ngapMsgPdu;

  if (ngapPdu->present == Ngap_NGAP_PDU_PR_initiatingMessage) {
    if (ngapPdu->choice.initiatingMessage &&
        ngapPdu->choice.initiatingMessage->procedureCode ==
            Ngap_ProcedureCode_id_UplinkUEAssociatedNRPPaTransport &&
        ngapPdu->choice.initiatingMessage->criticality ==
            Ngap_Criticality_ignore &&
        ngapPdu->choice.initiatingMessage->value.present ==
            Ngap_InitiatingMessage__value_PR_UplinkUEAssociatedNRPPaTransport) {
      m_UplinkUeAssociatedNrppaTransportIes =
          &ngapPdu->choice.initiatingMessage->value.choice
               .UplinkUEAssociatedNRPPaTransport;
    } else {
      oai::logger::logger_common::ngap().error(
          "Decode NGAP UplinkUEAssociatedNRPPaTransport error");
      return false;
    }
  } else {
    oai::logger::logger_common::ngap().error(
        "Decode NGAP MessageType IE error");
    return false;
  }

  for (int i = 0;
       i < m_UplinkUeAssociatedNrppaTransportIes->protocolIEs.list.count; i++) {
    switch (
        m_UplinkUeAssociatedNrppaTransportIes->protocolIEs.list.array[i]->id) {
      case Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID: {
        if (m_UplinkUeAssociatedNrppaTransportIes->protocolIEs.list.array[i]
                    ->criticality == Ngap_Criticality_reject &&
            m_UplinkUeAssociatedNrppaTransportIes->protocolIEs.list.array[i]
                    ->value.present ==
                Ngap_UplinkUEAssociatedNRPPaTransportIEs__value_PR_AMF_UE_NGAP_ID) {
          if (!NgapUeMessage::m_AmfUeNgapId.decode(
                  m_UplinkUeAssociatedNrppaTransportIes->protocolIEs.list
                      .array[i]
                      ->value.choice.AMF_UE_NGAP_ID)) {
            oai::logger::logger_common::ngap().error(
                "Decode NGAP AMF_UE_NGAP_ID IE error");
            return false;
          }
        } else {
          oai::logger::logger_common::ngap().error(
              "Decode NGAP AMF_UE_NGAP_ID IE error");
          return false;
        }
      } break;
      case Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID: {
        if (m_UplinkUeAssociatedNrppaTransportIes->protocolIEs.list.array[i]
                    ->criticality == Ngap_Criticality_reject &&
            m_UplinkUeAssociatedNrppaTransportIes->protocolIEs.list.array[i]
                    ->value.present ==
                Ngap_UplinkUEAssociatedNRPPaTransportIEs__value_PR_RAN_UE_NGAP_ID) {
          if (!NgapUeMessage::m_RanUeNgapId.decode(
                  m_UplinkUeAssociatedNrppaTransportIes->protocolIEs.list
                      .array[i]
                      ->value.choice.RAN_UE_NGAP_ID)) {
            oai::logger::logger_common::ngap().error(
                "Decode NGAP RAN_UE_NGAP_ID IE error");
            return false;
          }
        } else {
          oai::logger::logger_common::ngap().error(
              "Decode NGAP RAN_UE_NGAP_ID IE error");
          return false;
        }
      } break;

      case Ngap_ProtocolIE_ID_id_RoutingID: {
        if (m_UplinkUeAssociatedNrppaTransportIes->protocolIEs.list.array[i]
                    ->criticality == Ngap_Criticality_reject &&
            m_UplinkUeAssociatedNrppaTransportIes->protocolIEs.list.array[i]
                    ->value.present ==
                Ngap_UplinkUEAssociatedNRPPaTransportIEs__value_PR_RoutingID) {
          m_RoutingId =
              m_UplinkUeAssociatedNrppaTransportIes->protocolIEs.list.array[i]
                  ->value.choice.RoutingID;
        } else {
          oai::logger::logger_common::ngap().error(
              "Decode NGAP RoutingID IE error");
          return false;
        }

      } break;
      case Ngap_ProtocolIE_ID_id_NRPPa_PDU: {
        if (m_UplinkUeAssociatedNrppaTransportIes->protocolIEs.list.array[i]
                    ->criticality == Ngap_Criticality_reject &&
            m_UplinkUeAssociatedNrppaTransportIes->protocolIEs.list.array[i]
                    ->value.present ==
                Ngap_UplinkUEAssociatedNRPPaTransportIEs__value_PR_NRPPa_PDU) {
          m_NrppaPdu =
              m_UplinkUeAssociatedNrppaTransportIes->protocolIEs.list.array[i]
                  ->value.choice.NRPPa_PDU;
        } else {
          oai::logger::logger_common::ngap().error(
              "Decode NGAP NRPPa PDU IE error");
          return false;
        }
      } break;

      default: {
        oai::logger::logger_common::ngap().error(
            "Decode NGAP message PDU error");
        return false;
      }
    }
  }

  return true;
}

//------------------------------------------------------------------------------
void UplinkUeAssociatedNrppaTransportMsg::setRoutingId(
    const OCTET_STRING_t& id) {
  m_RoutingId = id;
  Ngap_UplinkUEAssociatedNRPPaTransportIEs_t* ie =
      (Ngap_UplinkUEAssociatedNRPPaTransportIEs_t*) calloc(
          1, sizeof(Ngap_UplinkUEAssociatedNRPPaTransportIEs_t));
  ie->id          = Ngap_ProtocolIE_ID_id_RoutingID;
  ie->criticality = Ngap_Criticality_reject;
  ie->value.present =
      Ngap_UplinkUEAssociatedNRPPaTransportIEs__value_PR_RoutingID;

  ie->value.choice.RoutingID = m_RoutingId;

  int ret = ASN_SEQUENCE_ADD(
      &m_UplinkUeAssociatedNrppaTransportIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error("Encode RoutingID IE error");
}

//------------------------------------------------------------------------------
void UplinkUeAssociatedNrppaTransportMsg::getRoutingId(
    OCTET_STRING_t& id) const {
  id = m_RoutingId;
}

//------------------------------------------------------------------------------
OCTET_STRING_t UplinkUeAssociatedNrppaTransportMsg::getRoutingId() const {
  return m_RoutingId;
}

//------------------------------------------------------------------------------
void UplinkUeAssociatedNrppaTransportMsg::setNrppaPdu(
    const OCTET_STRING_t& pdu) {
  m_NrppaPdu = pdu;

  Ngap_UplinkUEAssociatedNRPPaTransportIEs_t* ie =
      (Ngap_UplinkUEAssociatedNRPPaTransportIEs_t*) calloc(
          1, sizeof(Ngap_UplinkUEAssociatedNRPPaTransportIEs_t));
  ie->id          = Ngap_ProtocolIE_ID_id_NRPPa_PDU;
  ie->criticality = Ngap_Criticality_reject;
  ie->value.present =
      Ngap_UplinkUEAssociatedNRPPaTransportIEs__value_PR_NRPPa_PDU;

  ie->value.choice.NRPPa_PDU = m_NrppaPdu;

  int ret = ASN_SEQUENCE_ADD(
      &m_UplinkUeAssociatedNrppaTransportIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error("Encode NRPPa_PDU IE error");
}

//------------------------------------------------------------------------------
void UplinkUeAssociatedNrppaTransportMsg::getNrppaPdu(
    OCTET_STRING_t& pdu) const {
  pdu = m_NrppaPdu;
}

//------------------------------------------------------------------------------
OCTET_STRING_t UplinkUeAssociatedNrppaTransportMsg::getNrppaPdu() const {
  return m_NrppaPdu;
}

}  // namespace oai::ngap
