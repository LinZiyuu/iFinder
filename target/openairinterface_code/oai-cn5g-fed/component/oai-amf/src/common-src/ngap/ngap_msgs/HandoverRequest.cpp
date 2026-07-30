/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "HandoverRequest.hpp"

#include "logger_base.hpp"
#include "ngap_utils.hpp"
#include "utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
HandoverRequest::HandoverRequest() : NgapMessage() {
  m_MobilityRestrictionList = std::nullopt;
  m_HandoverRequestIes      = nullptr;

  m_AmfUeNgapId                        = {};
  m_HandoverType                       = {};
  m_Cause                              = {};
  m_UeAggregateMaximumBitRate          = {};
  m_UeSecurityCapabilities             = {};
  m_SecurityContext                    = {};
  m_PduSessionResourceSetupList        = {};
  m_AllowedNssai                       = {};
  m_SourceToTargetTransparentContainer = {};
  m_Guami                              = {};

  setMessageType(NgapMessageType::HANDOVER_REQUEST);
  initialize();
}

//------------------------------------------------------------------------------
HandoverRequest::~HandoverRequest() {}

//------------------------------------------------------------------------------
void HandoverRequest::initialize() {
  m_HandoverRequestIes =
      &(ngapPdu->choice.initiatingMessage->value.choice.HandoverRequest);
}

//------------------------------------------------------------------------------
uint64_t HandoverRequest::getAmfUeNgapId() const {
  return m_AmfUeNgapId.get();
}

//------------------------------------------------------------------------------
bool HandoverRequest::decode(Ngap_NGAP_PDU_t* ngapMsgPdu) {
  ngapPdu = ngapMsgPdu;

  if (ngapPdu->present == Ngap_NGAP_PDU_PR_initiatingMessage) {
    if (ngapPdu->choice.initiatingMessage &&
        ngapPdu->choice.initiatingMessage->procedureCode ==
            Ngap_ProcedureCode_id_HandoverResourceAllocation &&
        ngapPdu->choice.initiatingMessage->criticality ==
            Ngap_Criticality_reject &&
        ngapPdu->choice.initiatingMessage->value.present ==
            Ngap_InitiatingMessage__value_PR_HandoverRequest) {
      m_HandoverRequestIes =
          &ngapPdu->choice.initiatingMessage->value.choice.HandoverRequest;
    } else {
      oai::logger::logger_common::ngap().error("Check HandoverRequest error");
      return false;
    }
  } else {
    oai::logger::logger_common::ngap().error(
        "HandoverRequest MessageType error");
    return false;
  }
  for (int i = 0; i < m_HandoverRequestIes->protocolIEs.list.count; i++) {
    switch (m_HandoverRequestIes->protocolIEs.list.array[i]->id) {
      case Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID: {
        if (m_HandoverRequestIes->protocolIEs.list.array[i]->criticality ==
                Ngap_Criticality_reject &&
            m_HandoverRequestIes->protocolIEs.list.array[i]->value.present ==
                Ngap_HandoverRequestIEs__value_PR_AMF_UE_NGAP_ID) {
          if (!m_AmfUeNgapId.decode(
                  m_HandoverRequestIes->protocolIEs.list.array[i]
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
      case Ngap_ProtocolIE_ID_id_HandoverType: {
        if (m_HandoverRequestIes->protocolIEs.list.array[i]->criticality ==
                Ngap_Criticality_reject &&
            m_HandoverRequestIes->protocolIEs.list.array[i]->value.present ==
                Ngap_HandoverRequestIEs__value_PR_HandoverType) {
          m_HandoverType = m_HandoverRequestIes->protocolIEs.list.array[i]
                               ->value.choice.HandoverType;
        } else {
          oai::logger::logger_common::ngap().error(
              "Decode NGAP Handover Type IE error");
          return false;
        }
      } break;
        // TODO: Cause
        // TODO: UeAggregateMaxBitRate
        // TODO: Core Network Assistance Information for RRC INACTIVE
        // TODO:  UeSecurityCapabilities UeSecurityCapabilities
        // TODO: Ngap_SecurityContext_t SecurityContext
        // TODO: New Security Context Indicator
        // TODO: NASC - NAS-PDU
        // TODO: PduSessionResourceSetupListHoReq
        // TODO: AllowedNSSAI
        // TODO: Trace Activation
        // TODO: Masked IMEISV
        // TODO: SourceToTargetTransparentContainer
        // TODO: MobilityRestrictionList
        // TODO: Location Reporting Request Type
        // TODO: RRC Inactive Transition Report Request
        // TODO: Guami
        // TODO: Redirection for Voice EPS Fallback
        // TODO: CN Assisted RAN Parameters Tuning
      default: {
        oai::logger::logger_common::ngap().error(
            "Decode NGAP HandoverRequest PDU error");
        return false;
      }
    }
  }

  return true;
}

//------------------------------------------------------------------------------
void HandoverRequest::setAmfUeNgapId(const uint64_t& id) {
  m_AmfUeNgapId.set(id);

  Ngap_HandoverRequestIEs_t* ie =
      (Ngap_HandoverRequestIEs_t*) calloc(1, sizeof(Ngap_HandoverRequestIEs_t));
  ie->id            = Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID;
  ie->criticality   = Ngap_Criticality_reject;
  ie->value.present = Ngap_HandoverRequestIEs__value_PR_AMF_UE_NGAP_ID;

  int ret = m_AmfUeNgapId.encode(ie->value.choice.AMF_UE_NGAP_ID);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode AMF_UE_NGAP_ID IE error");
    oai::utils::utils::free_wrapper((void**) &ie);
    return;
  }

  ret = ASN_SEQUENCE_ADD(&m_HandoverRequestIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error("Encode AMF_UE_NGAP_ID IE error");
}

//------------------------------------------------------------------------------
void HandoverRequest::setHandoverType(const long& type)  // 0--intra5gs
{
  Ngap_HandoverRequestIEs_t* ie =
      (Ngap_HandoverRequestIEs_t*) calloc(1, sizeof(Ngap_HandoverRequestIEs_t));
  ie->id            = Ngap_ProtocolIE_ID_id_HandoverType;
  ie->criticality   = Ngap_Criticality_reject;
  ie->value.present = Ngap_HandoverRequestIEs__value_PR_HandoverType;
  ie->value.choice.HandoverType = type;
  int ret = ASN_SEQUENCE_ADD(&m_HandoverRequestIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error("Encode HandoverType IE error");
}

//------------------------------------------------------------------------------
void HandoverRequest::setCause(
    const Ngap_Cause_PR& causePresent, const long& value) {
  Ngap_HandoverRequestIEs_t* ie =
      (Ngap_HandoverRequestIEs_t*) calloc(1, sizeof(Ngap_HandoverRequestIEs_t));
  ie->id            = Ngap_ProtocolIE_ID_id_Cause;
  ie->criticality   = Ngap_Criticality_ignore;
  ie->value.present = Ngap_HandoverRequestIEs__value_PR_Cause;

  m_Cause.setChoiceOfCause(causePresent);
  m_Cause.set(value);
  m_Cause.encode(ie->value.choice.Cause);
  int ret = ASN_SEQUENCE_ADD(&m_HandoverRequestIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error("Encode Cause IE error");
}

//------------------------------------------------------------------------------
void HandoverRequest::setUeAggregateMaximumBitRate(
    const long& bitRateDl, const long& bitRateUl) {
  m_UeAggregateMaximumBitRate.set(bitRateDl, bitRateUl);

  Ngap_HandoverRequestIEs_t* ie =
      (Ngap_HandoverRequestIEs_t*) calloc(1, sizeof(Ngap_HandoverRequestIEs_t));
  ie->id          = Ngap_ProtocolIE_ID_id_UEAggregateMaximumBitRate;
  ie->criticality = Ngap_Criticality_reject;
  ie->value.present =
      Ngap_HandoverRequestIEs__value_PR_UEAggregateMaximumBitRate;
  m_UeAggregateMaximumBitRate.encode(
      ie->value.choice.UEAggregateMaximumBitRate);

  int ret = ASN_SEQUENCE_ADD(&m_HandoverRequestIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error(
        "Encode UEAggregateMaximumBitRate IE error");
}

//------------------------------------------------------------------------------
void HandoverRequest::setUeSecurityCapabilities(
    uint16_t nrEncryptionAlgs, uint16_t nrIntegrityProtectionAlgs,
    uint16_t eutraEncryptionAlgs, uint16_t eutraIntegrityProtectionAlgs) {
  Ngap_HandoverRequestIEs_t* ie =
      (Ngap_HandoverRequestIEs_t*) calloc(1, sizeof(Ngap_HandoverRequestIEs_t));
  ie->id            = Ngap_ProtocolIE_ID_id_UESecurityCapabilities;
  ie->criticality   = Ngap_Criticality_reject;
  ie->value.present = Ngap_HandoverRequestIEs__value_PR_UESecurityCapabilities;
  m_UeSecurityCapabilities.set(
      nrEncryptionAlgs, nrIntegrityProtectionAlgs, eutraEncryptionAlgs,
      eutraIntegrityProtectionAlgs);
  m_UeSecurityCapabilities.encode((ie->value.choice.UESecurityCapabilities));

  int ret = ASN_SEQUENCE_ADD(&m_HandoverRequestIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error(
        "Encode UESecurityCapabilities IE error");
}

//------------------------------------------------------------------------------
void HandoverRequest::setGuami(
    const PlmnId& plmnId, const AmfRegionId& amfRegionId,
    const AmfSetId& amfSetId, const AmfPointer& amfPointer) {
  Ngap_HandoverRequestIEs_t* ie =
      (Ngap_HandoverRequestIEs_t*) calloc(1, sizeof(Ngap_HandoverRequestIEs_t));
  ie->id            = Ngap_ProtocolIE_ID_id_GUAMI;
  ie->criticality   = Ngap_Criticality_reject;
  ie->value.present = Ngap_HandoverRequestIEs__value_PR_GUAMI;
  m_Guami.set(plmnId, amfRegionId, amfSetId, amfPointer);
  m_Guami.encode(ie->value.choice.GUAMI);

  int ret = ASN_SEQUENCE_ADD(&m_HandoverRequestIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error("Encode GUAMI IE error");
}

//------------------------------------------------------------------------------
void HandoverRequest::setGuami(
    const std::string& mcc, const std::string& mnc, const std::string& regionId,
    const std::string& setId, const std::string& pointer) {
  Ngap_HandoverRequestIEs_t* ie =
      (Ngap_HandoverRequestIEs_t*) calloc(1, sizeof(Ngap_HandoverRequestIEs_t));
  ie->id            = Ngap_ProtocolIE_ID_id_GUAMI;
  ie->criticality   = Ngap_Criticality_reject;
  ie->value.present = Ngap_HandoverRequestIEs__value_PR_GUAMI;
  m_Guami.set(mcc, mnc, regionId, setId, pointer);
  m_Guami.encode(ie->value.choice.GUAMI);

  int ret = ASN_SEQUENCE_ADD(&m_HandoverRequestIes->protocolIEs.list, ie);

  if (ret != 0)
    oai::logger::logger_common::ngap().error("Encode GUAMI IE error");
}

//------------------------------------------------------------------------------
void HandoverRequest::setGuami(
    const std::string& mcc, const std::string& mnc, uint8_t regionId,
    uint16_t setId, uint8_t pointer) {
  Ngap_HandoverRequestIEs_t* ie =
      (Ngap_HandoverRequestIEs_t*) calloc(1, sizeof(Ngap_HandoverRequestIEs_t));
  ie->id            = Ngap_ProtocolIE_ID_id_GUAMI;
  ie->criticality   = Ngap_Criticality_reject;
  ie->value.present = Ngap_HandoverRequestIEs__value_PR_GUAMI;
  m_Guami.set(mcc, mnc, regionId, setId, pointer);
  m_Guami.encode(ie->value.choice.GUAMI);

  int ret = ASN_SEQUENCE_ADD(&m_HandoverRequestIes->protocolIEs.list, ie);

  if (ret != 0)
    oai::logger::logger_common::ngap().error("Encode GUAMI IE error");
}

//------------------------------------------------------------------------------
void HandoverRequest::setAllowedNssai(const std::vector<SNssai>& list) {
  for (auto& it : list) {
    Ngap_AllowedNSSAI_Item_t* item =
        (Ngap_AllowedNSSAI_Item_t*) calloc(1, sizeof(Ngap_AllowedNSSAI_Item_t));
    it.encode(item->s_NSSAI);
    int ret = ASN_SEQUENCE_ADD(&m_AllowedNssai.list, item);
    if (ret != 0)
      oai::logger::logger_common::ngap().error(
          "Encode PDUSessionResourceHandoverListItem IE error");
  }
  ngap_utils::print_asn_msg(&asn_DEF_Ngap_AllowedNSSAI, &m_AllowedNssai);
  Ngap_HandoverRequestIEs_t* ie =
      (Ngap_HandoverRequestIEs_t*) calloc(1, sizeof(Ngap_HandoverRequestIEs_t));
  ie->id            = Ngap_ProtocolIE_ID_id_AllowedNSSAI;
  ie->criticality   = Ngap_Criticality_reject;
  ie->value.present = Ngap_HandoverRequestIEs__value_PR_AllowedNSSAI;
  ie->value.choice.AllowedNSSAI = m_AllowedNssai;
  int ret = ASN_SEQUENCE_ADD(&m_HandoverRequestIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error("Encode AllowedNSSAI IE error");
}

//------------------------------------------------------------------------------
void HandoverRequest::setSecurityContext(const long& count, const bstring& nh) {
  ngap_utils::bstring_2_bit_string(nh, m_SecurityContext.nextHopNH);
  m_SecurityContext.nextHopChainingCount = count;

  Ngap_HandoverRequestIEs_t* ie =
      (Ngap_HandoverRequestIEs_t*) calloc(1, sizeof(Ngap_HandoverRequestIEs_t));
  ie->id            = Ngap_ProtocolIE_ID_id_SecurityContext;
  ie->criticality   = Ngap_Criticality_reject;
  ie->value.present = Ngap_HandoverRequestIEs__value_PR_SecurityContext;
  ie->value.choice.SecurityContext = m_SecurityContext;
  int ret = ASN_SEQUENCE_ADD(&m_HandoverRequestIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error("Encode SecurityContext IE error");
}

//------------------------------------------------------------------------------
void HandoverRequest::setPduSessionResourceSetupList(
    const std::vector<PDUSessionResourceSetupRequestItem_t>& list) {
  std::vector<PduSessionResourceSetupItemHoReq> resource_setup_list;

  for (int i = 0; i < list.size(); i++) {
    PduSessionResourceSetupItemHoReq resource_setup_item = {};
    PduSessionId pdu_session_id                          = {};
    pdu_session_id.set(list[i].pduSessionId);
    SNssai s_nssai = {};
    s_nssai.setSst(list[i].sNssai.sst);
    if (list[i].sNssai.sd.size()) s_nssai.setSd(list[i].sNssai.sd);
    resource_setup_item.set(
        pdu_session_id, s_nssai,
        list[i].pduSessionResourceSetupRequestTransfer);
    resource_setup_list.push_back(resource_setup_item);
  }

  m_PduSessionResourceSetupList.set(resource_setup_list);

  Ngap_HandoverRequestIEs_t* ie =
      (Ngap_HandoverRequestIEs_t*) calloc(1, sizeof(Ngap_HandoverRequestIEs_t));
  ie->id          = Ngap_ProtocolIE_ID_id_PDUSessionResourceSetupListHOReq;
  ie->criticality = Ngap_Criticality_reject;
  ie->value.present =
      Ngap_HandoverRequestIEs__value_PR_PDUSessionResourceSetupListHOReq;

  int ret = m_PduSessionResourceSetupList.encode(
      ie->value.choice.PDUSessionResourceSetupListHOReq);
  if (!ret) {
    oai::logger::logger_common::ngap().error(
        "Encode PDUSessionResourceSetupListSUReq IE error");
    oai::utils::utils::free_wrapper((void**) &ie);
    return;
  }

  ret = ASN_SEQUENCE_ADD(&m_HandoverRequestIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error(
        "Encode PDUSessionResourceSetupListSUReq IE error");
}

//------------------------------------------------------------------------------
void HandoverRequest::setSourceToTargetTransparentContainer(
    const OCTET_STRING_t& sourceTotarget) {
  ngap_utils::octet_string_copy(
      m_SourceToTargetTransparentContainer, sourceTotarget);
  Ngap_HandoverRequestIEs_t* ie =
      (Ngap_HandoverRequestIEs_t*) calloc(1, sizeof(Ngap_HandoverRequestIEs_t));
  ie->id          = Ngap_ProtocolIE_ID_id_SourceToTarget_TransparentContainer;
  ie->criticality = Ngap_Criticality_reject;
  ie->value.present =
      Ngap_HandoverRequestIEs__value_PR_SourceToTarget_TransparentContainer;

  ngap_utils::octet_string_copy(
      ie->value.choice.SourceToTarget_TransparentContainer, sourceTotarget);
  int ret = ASN_SEQUENCE_ADD(&m_HandoverRequestIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error(
        "Encode m_SourceToTargetTransparentContainer IE error");
}

//------------------------------------------------------------------------------
void HandoverRequest::setMobilityRestrictionList(const PlmnId& plmn_id) {
  MobilityRestrictionList tmp = {};
  tmp.setPlmn(plmn_id);
  m_MobilityRestrictionList = std::optional<MobilityRestrictionList>(tmp);

  Ngap_HandoverRequestIEs_t* ie =
      (Ngap_HandoverRequestIEs_t*) calloc(1, sizeof(Ngap_HandoverRequestIEs_t));
  ie->id            = Ngap_ProtocolIE_ID_id_MobilityRestrictionList;
  ie->criticality   = Ngap_Criticality_ignore;
  ie->value.present = Ngap_HandoverRequestIEs__value_PR_MobilityRestrictionList;

  m_MobilityRestrictionList.value().encode(
      ie->value.choice.MobilityRestrictionList);
  int ret = ASN_SEQUENCE_ADD(&m_HandoverRequestIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error(
        "Encode MobilityRestrictionList IE error");
}

}  // namespace oai::ngap
