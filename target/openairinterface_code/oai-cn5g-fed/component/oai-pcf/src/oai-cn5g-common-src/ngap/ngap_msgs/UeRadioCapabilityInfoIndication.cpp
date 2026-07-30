/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "UeRadioCapabilityInfoIndication.hpp"

#include "logger_base.hpp"
#include "ngap_utils.hpp"
#include "utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
UeRadioCapabilityInfoIndicationMsg::UeRadioCapabilityInfoIndicationMsg()
    : NgapUeMessage() {
  m_UeRadioCapabilityInfoIndicationIes = nullptr;
  m_UeRadioCapabilityForPaging         = std::nullopt;

  setMessageType(NgapMessageType::UE_RADIO_CAPABILITY_INFO_INDICATION);
  initialize();
}

//------------------------------------------------------------------------------
UeRadioCapabilityInfoIndicationMsg::~UeRadioCapabilityInfoIndicationMsg() {}

//------------------------------------------------------------------------------
void UeRadioCapabilityInfoIndicationMsg::initialize() {
  m_UeRadioCapabilityInfoIndicationIes =
      &(ngapPdu->choice.initiatingMessage->value.choice
            .UERadioCapabilityInfoIndication);
}

//------------------------------------------------------------------------------
void UeRadioCapabilityInfoIndicationMsg::setAmfUeNgapId(const uint64_t& id) {
  NgapUeMessage::m_AmfUeNgapId.set(id);

  Ngap_UERadioCapabilityInfoIndicationIEs_t* ie =
      (Ngap_UERadioCapabilityInfoIndicationIEs_t*) calloc(
          1, sizeof(Ngap_UERadioCapabilityInfoIndicationIEs_t));
  ie->id          = Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID;
  ie->criticality = Ngap_Criticality_reject;
  ie->value.present =
      Ngap_UERadioCapabilityInfoIndicationIEs__value_PR_AMF_UE_NGAP_ID;

  int ret =
      NgapUeMessage::m_AmfUeNgapId.encode(ie->value.choice.AMF_UE_NGAP_ID);
  if (!ret) {
    oai::logger::logger_common::ngap().error(
        "Encode NGAP AMF_UE_NGAP_ID IE error");
    oai::utils::utils::free_wrapper((void**) &ie);
    return;
  }

  ret = ASN_SEQUENCE_ADD(
      &m_UeRadioCapabilityInfoIndicationIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error(
        "Encode NGAP AMF_UE_NGAP_ID IE error");
}

//------------------------------------------------------------------------------
void UeRadioCapabilityInfoIndicationMsg::setRanUeNgapId(
    const uint32_t& ranUeNgapId) {
  NgapUeMessage::m_RanUeNgapId.set(ranUeNgapId);

  Ngap_UERadioCapabilityInfoIndicationIEs_t* ie =
      (Ngap_UERadioCapabilityInfoIndicationIEs_t*) calloc(
          1, sizeof(Ngap_UERadioCapabilityInfoIndicationIEs_t));
  ie->id          = Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID;
  ie->criticality = Ngap_Criticality_reject;
  ie->value.present =
      Ngap_UERadioCapabilityInfoIndicationIEs__value_PR_RAN_UE_NGAP_ID;

  int ret =
      NgapUeMessage::m_RanUeNgapId.encode(ie->value.choice.RAN_UE_NGAP_ID);
  if (!ret) {
    oai::logger::logger_common::ngap().error(
        "Encode NGAP RAN_UE_NGAP_ID IE error");
    oai::utils::utils::free_wrapper((void**) &ie);
    return;
  }

  ret = ASN_SEQUENCE_ADD(
      &m_UeRadioCapabilityInfoIndicationIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error(
        "Encode NGAP RAN_UE_NGAP_ID IE error");
}

//------------------------------------------------------------------------------
void UeRadioCapabilityInfoIndicationMsg::setUeRadioCapability(
    const OCTET_STRING_t& capability) {
  m_UeRadioCapability.set(capability);

  Ngap_UERadioCapabilityInfoIndicationIEs_t* ie =
      (Ngap_UERadioCapabilityInfoIndicationIEs_t*) calloc(
          1, sizeof(Ngap_PDUSessionResourceSetupRequestIEs_t));
  ie->id          = Ngap_ProtocolIE_ID_id_UERadioCapability;
  ie->criticality = Ngap_Criticality_ignore;
  ie->value.present =
      Ngap_UERadioCapabilityInfoIndicationIEs__value_PR_UERadioCapability;

  if (!m_UeRadioCapability.encode(ie->value.choice.UERadioCapability)) {
    oai::logger::logger_common::ngap().error(
        "Encode NGAP UERadioCapability IE error");
    oai::utils::utils::free_wrapper((void**) &ie);
    return;
  }

  int ret = ASN_SEQUENCE_ADD(
      &m_UeRadioCapabilityInfoIndicationIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error(
        "Encode NGAP UERadioCapability IE error");
}

//------------------------------------------------------------------------------
void UeRadioCapabilityInfoIndicationMsg::getUeRadioCapability(
    OCTET_STRING_t& capability) const {
  m_UeRadioCapability.get(capability);
}

//------------------------------------------------------------------------------
void UeRadioCapabilityInfoIndicationMsg::setUeRadioCapabilityForPaging(
    const OCTET_STRING_t& ueRadioCapabilityForPagingOfNr,
    const OCTET_STRING_t& ueRadioCapabilityForPagingOfEutra) {
  if (!(ngap_utils::check_octet_string(ueRadioCapabilityForPagingOfNr) or
        ngap_utils::check_octet_string(ueRadioCapabilityForPagingOfEutra))) {
    return;
  }
  UeRadioCapabilityForPaging tmp = {};

  if (ngap_utils::check_octet_string(ueRadioCapabilityForPagingOfNr)) {
    tmp.setUeRadioCapabilityForPagingOfNr(ueRadioCapabilityForPagingOfNr);
  }
  if (ngap_utils::check_octet_string(ueRadioCapabilityForPagingOfEutra)) {
    tmp.setUeRadioCapabilityForPagingOfEutra(ueRadioCapabilityForPagingOfEutra);
  }
  m_UeRadioCapabilityForPaging = std::optional<UeRadioCapabilityForPaging>(tmp);

  Ngap_UERadioCapabilityInfoIndicationIEs_t* ie =
      (Ngap_UERadioCapabilityInfoIndicationIEs_t*) calloc(
          1, sizeof(Ngap_UERadioCapabilityInfoIndicationIEs_t));
  ie->id          = Ngap_ProtocolIE_ID_id_UERadioCapabilityForPaging;
  ie->criticality = Ngap_Criticality_ignore;
  ie->value.present =
      Ngap_UERadioCapabilityInfoIndicationIEs__value_PR_UERadioCapabilityForPaging;

  int ret = m_UeRadioCapabilityForPaging.value().encode(
      ie->value.choice.UERadioCapabilityForPaging);
  if (!ret) {
    oai::logger::logger_common::ngap().error(
        "Encode NGAP UERadioCapabilityForPaging IE error");
    oai::utils::utils::free_wrapper((void**) &ie);
    return;
  }

  ret = ASN_SEQUENCE_ADD(
      &m_UeRadioCapabilityInfoIndicationIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error(
        "Encode NGAP UERadioCapabilityForPaging IE error");
}

//------------------------------------------------------------------------------
bool UeRadioCapabilityInfoIndicationMsg::getUeRadioCapabilityForPaging(
    OCTET_STRING_t& ueRadioCapabilityForPagingOfNr,
    OCTET_STRING_t& ueRadioCapabilityForPagingOfEutra) const {
  if (!m_UeRadioCapabilityForPaging.has_value()) return false;
  m_UeRadioCapabilityForPaging.value().getUeRadioCapabilityForPagingOfNr(
      ueRadioCapabilityForPagingOfNr);
  m_UeRadioCapabilityForPaging.value().getUeRadioCapabilityForPagingOfEutra(
      ueRadioCapabilityForPagingOfEutra);
  return true;
}

//------------------------------------------------------------------------------
bool UeRadioCapabilityInfoIndicationMsg::decode(Ngap_NGAP_PDU_t* ngapMsgPdu) {
  ngapPdu = ngapMsgPdu;

  if (ngapPdu->present == Ngap_NGAP_PDU_PR_initiatingMessage) {
    if (ngapPdu->choice.initiatingMessage &&
        ngapPdu->choice.initiatingMessage->procedureCode ==
            Ngap_ProcedureCode_id_UERadioCapabilityInfoIndication &&
        ngapPdu->choice.initiatingMessage->criticality ==
            Ngap_Criticality_ignore &&
        ngapPdu->choice.initiatingMessage->value.present ==
            Ngap_InitiatingMessage__value_PR_UERadioCapabilityInfoIndication) {
      m_UeRadioCapabilityInfoIndicationIes =
          &ngapPdu->choice.initiatingMessage->value.choice
               .UERadioCapabilityInfoIndication;
    } else {
      oai::logger::logger_common::ngap().error(
          "Check UERadioCapabilityInfoIndication message error!");
      return false;
    }
  } else {
    oai::logger::logger_common::ngap().error("MessageType error!");
    return false;
  }
  for (int i = 0;
       i < m_UeRadioCapabilityInfoIndicationIes->protocolIEs.list.count; i++) {
    switch (
        m_UeRadioCapabilityInfoIndicationIes->protocolIEs.list.array[i]->id) {
      case Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID: {
        if (m_UeRadioCapabilityInfoIndicationIes->protocolIEs.list.array[i]
                    ->criticality == Ngap_Criticality_reject &&
            m_UeRadioCapabilityInfoIndicationIes->protocolIEs.list.array[i]
                    ->value.present ==
                Ngap_UERadioCapabilityInfoIndicationIEs__value_PR_AMF_UE_NGAP_ID) {
          if (!NgapUeMessage::m_AmfUeNgapId.decode(
                  m_UeRadioCapabilityInfoIndicationIes->protocolIEs.list
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
        if (m_UeRadioCapabilityInfoIndicationIes->protocolIEs.list.array[i]
                    ->criticality == Ngap_Criticality_reject &&
            m_UeRadioCapabilityInfoIndicationIes->protocolIEs.list.array[i]
                    ->value.present ==
                Ngap_UERadioCapabilityInfoIndicationIEs__value_PR_RAN_UE_NGAP_ID) {
          if (!NgapUeMessage::m_RanUeNgapId.decode(
                  m_UeRadioCapabilityInfoIndicationIes->protocolIEs.list
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
      case Ngap_ProtocolIE_ID_id_UERadioCapability: {
        if (m_UeRadioCapabilityInfoIndicationIes->protocolIEs.list.array[i]
                    ->criticality == Ngap_Criticality_ignore &&
            m_UeRadioCapabilityInfoIndicationIes->protocolIEs.list.array[i]
                    ->value.present ==
                Ngap_UERadioCapabilityInfoIndicationIEs__value_PR_UERadioCapability) {
          m_UeRadioCapability.set(
              m_UeRadioCapabilityInfoIndicationIes->protocolIEs.list.array[i]
                  ->value.choice.UERadioCapability);
        } else {
          oai::logger::logger_common::ngap().error(
              "Decoded NGAP UERadioCapability IE error");
          return false;
        }
      } break;
      case Ngap_ProtocolIE_ID_id_UERadioCapabilityForPaging: {
        if (m_UeRadioCapabilityInfoIndicationIes->protocolIEs.list.array[i]
                    ->criticality == Ngap_Criticality_ignore &&
            m_UeRadioCapabilityInfoIndicationIes->protocolIEs.list.array[i]
                    ->value.present ==
                Ngap_UERadioCapabilityInfoIndicationIEs__value_PR_UERadioCapabilityForPaging) {
          UeRadioCapabilityForPaging tmp = {};
          if (!tmp.decode(m_UeRadioCapabilityInfoIndicationIes->protocolIEs.list
                              .array[i]
                              ->value.choice.UERadioCapabilityForPaging)) {
            oai::logger::logger_common::ngap().error(
                "Decoded NGAP UERadioCapabilityForPaging IE error");
            return false;
          }
          m_UeRadioCapabilityForPaging =
              std::optional<UeRadioCapabilityForPaging>(tmp);
        } else {
          oai::logger::logger_common::ngap().error(
              "Decoded NGAP UERadioCapabilityForPaging IE error");
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
