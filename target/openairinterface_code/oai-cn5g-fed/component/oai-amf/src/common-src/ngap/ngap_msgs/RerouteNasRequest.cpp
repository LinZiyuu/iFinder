/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "RerouteNasRequest.hpp"

#include "3gpp_23.003.h"
#include "common_defs.hpp"
#include "logger_base.hpp"
#include "utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
RerouteNasRequest::RerouteNasRequest() : NgapMessage() {
  m_RerouteNASRequestIes = nullptr;
  m_AmfUeNgapId          = std::nullopt;
  m_AllowedNssai         = std::nullopt;

  NgapMessage::setMessageType(NgapMessageType::REROUTE_NAS_REQUEST);
  initialize();
}

//------------------------------------------------------------------------------
RerouteNasRequest::~RerouteNasRequest() {}

//------------------------------------------------------------------------------
void RerouteNasRequest::initialize() {
  m_RerouteNASRequestIes =
      &(ngapPdu->choice.initiatingMessage->value.choice.RerouteNASRequest);
}

//------------------------------------------------------------------------------
void RerouteNasRequest::setAmfUeNgapId(const uint64_t& id) {
  AmfUeNgapId tmp = {};
  tmp.set(id);
  m_AmfUeNgapId = std::optional<AmfUeNgapId>(tmp);

  Ngap_RerouteNASRequest_IEs_t* ie = (Ngap_RerouteNASRequest_IEs_t*) calloc(
      1, sizeof(Ngap_RerouteNASRequest_IEs_t));
  ie->id            = Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID;
  ie->criticality   = Ngap_Criticality_ignore;
  ie->value.present = Ngap_RerouteNASRequest_IEs__value_PR_AMF_UE_NGAP_ID;

  int ret = m_AmfUeNgapId.value().encode(ie->value.choice.AMF_UE_NGAP_ID);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode AMF_UE_NGAP_ID IE error!");
    oai::utils::utils::free_wrapper((void**) &ie);
    return;
  }

  ret = ASN_SEQUENCE_ADD(&m_RerouteNASRequestIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error("Encode AMF_UE_NGAP_ID IE error!");
}

//------------------------------------------------------------------------------
bool RerouteNasRequest::getAmfUeNgapId(uint64_t& id) const {
  if (!m_AmfUeNgapId.has_value()) return false;
  id = m_AmfUeNgapId->get();
  return true;
}

//------------------------------------------------------------------------------
void RerouteNasRequest::setRanUeNgapId(const uint32_t& ranUeNgapId) {
  m_RanUeNgapId.set(ranUeNgapId);

  Ngap_RerouteNASRequest_IEs_t* ie = (Ngap_RerouteNASRequest_IEs_t*) calloc(
      1, sizeof(Ngap_RerouteNASRequest_IEs_t));
  ie->id            = Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID;
  ie->criticality   = Ngap_Criticality_reject;
  ie->value.present = Ngap_RerouteNASRequest_IEs__value_PR_RAN_UE_NGAP_ID;

  int ret = m_RanUeNgapId.encode(ie->value.choice.RAN_UE_NGAP_ID);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode RAN_UE_NGAP_ID IE error!");
    oai::utils::utils::free_wrapper((void**) &ie);
    return;
  }

  ret = ASN_SEQUENCE_ADD(&m_RerouteNASRequestIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error("Encode RAN_UE_NGAP_ID IE error!");
}

//------------------------------------------------------------------------------
uint32_t RerouteNasRequest::getRanUeNgapId() const {
  return m_RanUeNgapId.get();
}

//------------------------------------------------------------------------------
void RerouteNasRequest::setAllowedNssai(const std::vector<S_Nssai>& list) {
  AllowedNSSAI tmp = {};

  std::vector<SNssai> sNssaiList;
  for (int i = 0; i < list.size(); i++) {
    SNssai sNssai = {};
    sNssai.setSst(list[i].sst);

    if (!list[i].sd.empty()) {
      sNssai.setSd(list[i].sd);
    } else {
      sNssai.setSd(SD_NO_VALUE);
    }
    sNssaiList.push_back(sNssai);
  }
  tmp.set(sNssaiList);
  m_AllowedNssai = std::optional<AllowedNSSAI>(tmp);

  Ngap_RerouteNASRequest_IEs_t* ie = (Ngap_RerouteNASRequest_IEs_t*) calloc(
      1, sizeof(Ngap_RerouteNASRequest_IEs_t));
  ie->id            = Ngap_ProtocolIE_ID_id_AllowedNSSAI;
  ie->criticality   = Ngap_Criticality_reject;
  ie->value.present = Ngap_RerouteNASRequest_IEs__value_PR_AllowedNSSAI;

  int ret = m_AllowedNssai.value().encode(ie->value.choice.AllowedNSSAI);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode AllowedNSSAI IE error!");
    oai::utils::utils::free_wrapper((void**) &ie);
    return;
  }

  ret = ASN_SEQUENCE_ADD(&m_RerouteNASRequestIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error("Encode AllowedNSSAI IE error!");
}

//------------------------------------------------------------------------------
bool RerouteNasRequest::getAllowedNssai(std::vector<S_Nssai>& list) const {
  if (!m_AllowedNssai.has_value()) return false;

  std::vector<SNssai> sNssaiList;
  m_AllowedNssai.value().get(sNssaiList);
  for (std::vector<SNssai>::iterator it = std::begin(sNssaiList);
       it < std::end(sNssaiList); ++it) {
    S_Nssai sNssai = {};
    it->getSst(sNssai.sst);
    it->getSd(sNssai.sd);
    list.push_back(sNssai);
  }
  return true;
}

//------------------------------------------------------------------------------
void RerouteNasRequest::setNgapMessage(const OCTET_STRING_t& message) {
  Ngap_RerouteNASRequest_IEs_t* ie = (Ngap_RerouteNASRequest_IEs_t*) calloc(
      1, sizeof(Ngap_RerouteNASRequest_IEs_t));
  ie->id            = Ngap_ProtocolIE_ID_id_NGAP_Message;
  ie->criticality   = Ngap_Criticality_reject;
  ie->value.present = Ngap_RerouteNASRequest_IEs__value_PR_OCTET_STRING;
  ie->value.choice.OCTET_STRING = message;

  int ret = ASN_SEQUENCE_ADD(&m_RerouteNASRequestIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error("Encode NGAP Message IE error!");
}

//------------------------------------------------------------------------------
bool RerouteNasRequest::getNgapMessage(OCTET_STRING_t& message) const {
  message = m_NgapMessage;
  return true;
}

//------------------------------------------------------------------------------
bool RerouteNasRequest::setAmfSetId(const uint16_t& amfSetId) {
  if (!m_AmfSetId.set(amfSetId)) return false;

  Ngap_RerouteNASRequest_IEs_t* ie = (Ngap_RerouteNASRequest_IEs_t*) calloc(
      1, sizeof(Ngap_RerouteNASRequest_IEs_t));
  ie->id            = Ngap_ProtocolIE_ID_id_AMFSetID;
  ie->criticality   = Ngap_Criticality_reject;
  ie->value.present = Ngap_RerouteNASRequest_IEs__value_PR_AMFSetID;

  int ret = m_AmfSetId.encode(ie->value.choice.AMFSetID);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode AMFSetID IE error!");
    oai::utils::utils::free_wrapper((void**) &ie);
    return false;
  }

  ret = ASN_SEQUENCE_ADD(&m_RerouteNASRequestIes->protocolIEs.list, ie);
  if (ret != 0) {
    oai::logger::logger_common::ngap().error("Encode AMFSetID IE error!");
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
void RerouteNasRequest::getAmfSetId(std::string& amfSetId) const {
  m_AmfSetId.get(amfSetId);
}

//------------------------------------------------------------------------------
bool RerouteNasRequest::decode(Ngap_NGAP_PDU_t* ngapMsgPdu) {
  ngapPdu = ngapMsgPdu;

  if (ngapPdu->present == Ngap_NGAP_PDU_PR_initiatingMessage) {
    if (ngapPdu->choice.initiatingMessage &&
        ngapPdu->choice.initiatingMessage->procedureCode ==
            Ngap_ProcedureCode_id_RerouteNASRequest &&
        ngapPdu->choice.initiatingMessage->criticality ==
            Ngap_Criticality_reject &&
        ngapPdu->choice.initiatingMessage->value.present ==
            Ngap_InitiatingMessage__value_PR_RerouteNASRequest) {
      m_RerouteNASRequestIes =
          &ngapPdu->choice.initiatingMessage->value.choice.RerouteNASRequest;
    } else {
      oai::logger::logger_common::ngap().error(
          "Check RerouteNASRequest message error!");
      return false;
    }
  } else {
    oai::logger::logger_common::ngap().error("MessageType error!");
    return false;
  }
  for (int i = 0; i < m_RerouteNASRequestIes->protocolIEs.list.count; i++) {
    switch (m_RerouteNASRequestIes->protocolIEs.list.array[i]->id) {
      case Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID: {
        if (m_RerouteNASRequestIes->protocolIEs.list.array[i]->criticality ==
                Ngap_Criticality_ignore &&
            m_RerouteNASRequestIes->protocolIEs.list.array[i]->value.present ==
                Ngap_RerouteNASRequest_IEs__value_PR_AMF_UE_NGAP_ID) {
          AmfUeNgapId tmp = {};
          if (!tmp.decode(m_RerouteNASRequestIes->protocolIEs.list.array[i]
                              ->value.choice.AMF_UE_NGAP_ID)) {
            oai::logger::logger_common::ngap().error(
                "Decoded NGAP AMF_UE_NGAP_ID IE error");
            return false;
          }
          m_AmfUeNgapId = std::optional<AmfUeNgapId>(tmp);
        } else {
          oai::logger::logger_common::ngap().error(
              "Decoded NGAP AMF_UE_NGAP_ID IE error");
          return false;
        }
      } break;
      case Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID: {
        if (m_RerouteNASRequestIes->protocolIEs.list.array[i]->criticality ==
                Ngap_Criticality_reject &&
            m_RerouteNASRequestIes->protocolIEs.list.array[i]->value.present ==
                Ngap_RerouteNASRequest_IEs__value_PR_RAN_UE_NGAP_ID) {
          if (!m_RanUeNgapId.decode(
                  m_RerouteNASRequestIes->protocolIEs.list.array[i]
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

      case Ngap_ProtocolIE_ID_id_NGAP_Message: {
        if (m_RerouteNASRequestIes->protocolIEs.list.array[i]->criticality ==
                Ngap_Criticality_reject &&
            m_RerouteNASRequestIes->protocolIEs.list.array[i]->value.present ==
                Ngap_RerouteNASRequest_IEs__value_PR_OCTET_STRING) {
          m_NgapMessage = m_RerouteNASRequestIes->protocolIEs.list.array[i]
                              ->value.choice.OCTET_STRING;
          oai::logger::logger_common::ngap().error(
              "Decoded NGAP Message IE error");
        }
      } break;

      case Ngap_ProtocolIE_ID_id_AMFSetID: {
        if (m_RerouteNASRequestIes->protocolIEs.list.array[i]->criticality ==
                Ngap_Criticality_reject &&
            m_RerouteNASRequestIes->protocolIEs.list.array[i]->value.present ==
                Ngap_RerouteNASRequest_IEs__value_PR_AMFSetID) {
          if (!m_AmfSetId.decode(
                  m_RerouteNASRequestIes->protocolIEs.list.array[i]
                      ->value.choice.AMFSetID)) {
            oai::logger::logger_common::ngap().error(
                "Decoded NGAP AMFSetID error");
            return false;
          }
        } else {
          oai::logger::logger_common::ngap().error(
              "Decoded NGAP AMFSetID IE error");
          return false;
        }
      } break;

      case Ngap_ProtocolIE_ID_id_AllowedNSSAI: {
        if (m_RerouteNASRequestIes->protocolIEs.list.array[i]->criticality ==
                Ngap_Criticality_reject &&
            m_RerouteNASRequestIes->protocolIEs.list.array[i]->value.present ==
                Ngap_RerouteNASRequest_IEs__value_PR_AllowedNSSAI) {
          AllowedNSSAI tmp = {};
          if (!m_AllowedNssai->decode(
                  m_RerouteNASRequestIes->protocolIEs.list.array[i]
                      ->value.choice.AllowedNSSAI)) {
            oai::logger::logger_common::ngap().error(
                "Decoded NGAP AllowedNSSAI IE error");
            return false;
          }
          m_AllowedNssai = std::optional<AllowedNSSAI>(tmp);
        } else {
          oai::logger::logger_common::ngap().error(
              "Decoded NGAP AllowedNSSAI IE error");
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
